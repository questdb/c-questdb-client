/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2025 QuestDB
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

//! C ABI for the column-major sender.
//!
//! Mirrors `doc/COLUMN_SENDER_FFI_ABI.md`. The ABI re-uses
//! `line_sender_error*` for fallible-call error reporting; opaque types
//! (`questdb_db`, `qwpws_conn`, `column_sender_chunk`) are heap-allocated
//! and freed through their dedicated `_close` / `_free` / `_return_conn`
//! entry points.

use libc::{c_char, size_t};
use std::slice;
use std::str;

use questdb::ingress::MAX_ARRAY_DIMS;
use questdb::ingress::column_sender::{
    AckLevel, Chunk, NumpyDtype, OwnedSender, QuestDb, Validity,
};
use questdb::{Error, ErrorCode};

#[cfg(feature = "arrow")]
use crate::{line_sender_column_name, line_sender_table_name};
use crate::{line_sender_error, set_err_out_from_error};

// ===========================================================================
// Opaque handles
// ===========================================================================

/// Connection pool. Thread-safe; share across threads.
pub struct questdb_db(pub(crate) QuestDb);

/// Borrowed QWP/WS connection. Owns a pool slot until
/// `questdb_db_return_conn` is called. Not thread-safe. Bundles the
/// per-connection schema registry and symbol-dict state used by all
/// writer modes (column-sender chunks, future Arrow / NumPy appenders,
/// future egress readers).
pub struct qwpws_conn(OwnedSender);

/// One DataFrame's worth of column buffers destined for one QuestDB table.
/// Owned by the caller; not bound to a connection.
///
/// Holds raw pointers into caller buffers (no copy). Per the FFI ABI
/// doc §2.3, the caller MUST keep every column buffer passed in via
/// `column_sender_chunk_column_*` / `column_sender_chunk_append_*`
/// alive until the next `column_sender_flush` call returns. We hide the
/// chunk's lifetime by promoting its inner type to `'static`; the lifetime
/// is enforced by the caller, not the borrow checker.
pub struct column_sender_chunk(Chunk<'static>);

// ===========================================================================
// Validity bitmap (Arrow shape: bit = 1 means valid, LSB-first).
// ===========================================================================

#[repr(C)]
#[derive(Copy, Clone)]
pub struct column_sender_validity {
    pub bits: *const u8,
    pub bit_len: size_t,
}

unsafe fn as_validity<'a>(
    v: *const column_sender_validity,
    err_out: *mut *mut line_sender_error,
) -> Option<Option<Validity<'a>>> {
    if v.is_null() {
        return Some(None);
    }
    let v = unsafe { &*v };
    let required = v.bit_len.div_ceil(8);
    if v.bits.is_null() && v.bit_len != 0 {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    "column_sender_validity has null bits but bit_len != 0".to_string(),
                ),
            );
        }
        return None;
    }
    let bytes: &[u8] = if v.bit_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(v.bits, required) }
    };
    match Validity::from_bitmap(bytes, v.bit_len) {
        Ok(parsed) => Some(Some(parsed)),
        Err(err) => {
            unsafe { set_err_out_from_error(err_out, err) };
            None
        }
    }
}

// ===========================================================================
// Ack level
// ===========================================================================

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum column_sender_ack_level {
    column_sender_ack_level_ok = 0,
    column_sender_ack_level_durable = 1,
}

impl From<column_sender_ack_level> for AckLevel {
    fn from(value: column_sender_ack_level) -> Self {
        match value {
            column_sender_ack_level::column_sender_ack_level_ok => AckLevel::Ok,
            column_sender_ack_level::column_sender_ack_level_durable => AckLevel::Durable,
        }
    }
}

// ===========================================================================
// Conversion helpers
// ===========================================================================

unsafe fn name_str<'a>(
    name: *const c_char,
    name_len: size_t,
    err_out: *mut *mut line_sender_error,
) -> Option<&'a str> {
    if name.is_null() && name_len != 0 {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    "name pointer is NULL with non-zero length".to_string(),
                ),
            );
        }
        return None;
    }
    let slice = if name_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(name as *const u8, name_len) }
    };
    match str::from_utf8(slice) {
        Ok(s) => Some(s),
        Err(_) => {
            unsafe {
                set_err_out_from_error(
                    err_out,
                    Error::new(
                        ErrorCode::InvalidUtf8,
                        "name is not valid UTF-8".to_string(),
                    ),
                );
            }
            None
        }
    }
}

unsafe fn typed_slice<'a, T>(
    data: *const T,
    len: size_t,
    err_out: *mut *mut line_sender_error,
    what: &'static str,
) -> Option<&'a [T]> {
    if data.is_null() && len != 0 {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    format!("{what} pointer is NULL with non-zero length"),
                ),
            );
        }
        return None;
    }
    if len == 0 {
        return Some(&[]);
    }
    Some(unsafe { slice::from_raw_parts(data, len) })
}

macro_rules! bubble {
    ($err_out:expr, $expr:expr) => {
        match $expr {
            Ok(value) => value,
            Err(err) => {
                unsafe { set_err_out_from_error($err_out, err) };
                return false;
            }
        }
    };
}

// ===========================================================================
// Pool
// ===========================================================================

/// Open a connection pool. Eagerly opens `pool_size` connections; any
/// server/auth/TLS error during those opens fails the call. `conf` is a
/// NUL-terminated UTF-8 string.
///
/// Returns NULL on failure. When `err_out != NULL`, the error is placed
/// in `*err_out` and ownership transfers to the caller (release with
/// `line_sender_error_free`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_db_connect(
    conf: *const c_char,
    conf_len: size_t,
    err_out: *mut *mut line_sender_error,
) -> *mut questdb_db {
    let conf = match unsafe { name_str(conf, conf_len, err_out) } {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    match QuestDb::connect(conf) {
        Ok(db) => Box::into_raw(Box::new(questdb_db(db))),
        Err(err) => {
            unsafe { set_err_out_from_error(err_out, err) };
            std::ptr::null_mut()
        }
    }
}

/// Close the pool and all its connections. Accepts NULL and no-ops.
///
/// Outstanding `qwpws_conn` handles remain valid (they hold an
/// internal reference to the pool's state) and return themselves on
/// `questdb_db_return_conn`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_db_close(db: *mut questdb_db) {
    if !db.is_null() {
        unsafe { drop(Box::from_raw(db)) };
    }
}

/// Borrow a QWP/WS connection from the pool. See
/// `doc/COLUMN_SENDER_FFI_ABI.md` §4.3 for the selection rules. Returns
/// NULL on failure; sets `*err_out` if provided.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_db_borrow_conn(
    db: *mut questdb_db,
    err_out: *mut *mut line_sender_error,
) -> *mut qwpws_conn {
    if db.is_null() {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    "questdb_db_borrow_conn: db pointer is NULL".to_string(),
                ),
            );
        }
        return std::ptr::null_mut();
    }
    let db_ref = unsafe { &*db };
    match db_ref.0.borrow_sender_owned() {
        Ok(owned) => Box::into_raw(Box::new(qwpws_conn(owned))),
        Err(err) => {
            unsafe { set_err_out_from_error(err_out, err) };
            std::ptr::null_mut()
        }
    }
}

/// Return a borrowed conn to the pool. Invalidates `conn`. Accepts
/// NULL `conn` and no-ops. `db` is ignored — the conn carries its own
/// reference to the pool — but kept in the ABI for symmetry with the
/// borrow call and to allow future runtime checks.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_db_return_conn(_db: *mut questdb_db, conn: *mut qwpws_conn) {
    if !conn.is_null() {
        unsafe { drop(Box::from_raw(conn)) };
    }
}

/// Force-drop a borrowed conn instead of recycling it. The conn is
/// marked terminal (`qwpws_conn_must_close` becomes `true`) before
/// the usual pool-return path runs, so the underlying connection is
/// closed and dropped from the pool. Invalidates `conn`. Accepts
/// NULL `conn` and no-ops.
///
/// Use this in error-recovery paths where the conn may hold
/// in-flight uncommitted frames that the next borrower would otherwise
/// commit alongside their own. Equivalent to "mark must_close, then
/// return" but in a single atomic step from the caller's perspective.
///
/// `db` is ignored, kept for symmetry with the other pool entry
/// points.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_db_drop_conn(_db: *mut questdb_db, conn: *mut qwpws_conn) {
    if !conn.is_null() {
        // SAFETY: caller guarantees `conn` is a live qwpws_conn handle
        // (NULL handled above).
        let owned = unsafe { &mut *conn };
        owned.0.get_mut().mark_must_close();
        unsafe { drop(Box::from_raw(conn)) };
    }
}

/// Manually reap idle connections. Returns the number of connections
/// closed by this invocation. `db` must be non-NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_db_reap_idle(db: *mut questdb_db) -> size_t {
    if db.is_null() {
        return 0;
    }
    let db_ref = unsafe { &*db };
    db_ref.0.reap_idle()
}

// ===========================================================================
// Connection state
// ===========================================================================

/// `true` if the connection is in a permanently-unusable state.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwpws_conn_must_close(conn: *const qwpws_conn) -> bool {
    if conn.is_null() {
        return true;
    }
    unsafe { (*conn).0.get().must_close() }
}

// ===========================================================================
// Arrow C Data Interface mirror types
//
// We read these but never construct or release them — that's the
// producer's responsibility. The fields below mirror the layout from
// the Apache Arrow C Data Interface spec
// (https://arrow.apache.org/docs/format/CDataInterface.html) so the
// pointer the caller passes in points at a compatible memory layout.
// ===========================================================================

// Field types mirror the Apache Arrow C Data Interface declarations
// (`struct ArrowArray**` etc.). We never mutate the structs, but the
// inner pointer type matches the spec so the layout description reads
// the same on both sides.
#[repr(C)]
pub struct ArrowArray {
    pub length: i64,
    pub null_count: i64,
    pub offset: i64,
    pub n_buffers: i64,
    pub n_children: i64,
    pub buffers: *const *const std::ffi::c_void,
    pub children: *const *mut ArrowArray,
    pub dictionary: *mut ArrowArray,
    pub release: Option<unsafe extern "C" fn(*mut ArrowArray)>,
    pub private_data: *mut std::ffi::c_void,
}

#[repr(C)]
pub struct ArrowSchema {
    pub format: *const c_char,
    pub name: *const c_char,
    pub metadata: *const c_char,
    pub flags: i64,
    pub n_children: i64,
    pub children: *const *mut ArrowSchema,
    pub dictionary: *mut ArrowSchema,
    pub release: Option<unsafe extern "C" fn(*mut ArrowSchema)>,
    pub private_data: *mut std::ffi::c_void,
}

// ===========================================================================
// Chunk lifecycle
// ===========================================================================

/// Create an empty chunk for `table_name` (validated UTF-8, ≤ 127 bytes).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn column_sender_chunk_new(
    table_name: *const c_char,
    table_name_len: size_t,
    err_out: *mut *mut line_sender_error,
) -> *mut column_sender_chunk {
    let table = match unsafe { name_str(table_name, table_name_len, err_out) } {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    Box::into_raw(Box::new(column_sender_chunk(Chunk::new(table))))
}

/// Free a chunk. Accepts NULL and no-ops.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn column_sender_chunk_free(chunk: *mut column_sender_chunk) {
    if !chunk.is_null() {
        unsafe { drop(Box::from_raw(chunk)) };
    }
}

/// Clear a chunk's content, keeping its retained capacity for reuse.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn column_sender_chunk_clear(chunk: *mut column_sender_chunk) {
    if !chunk.is_null() {
        unsafe { (*chunk).0.clear() };
    }
}

/// Current row count of the chunk; 0 if no column has been appended.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn column_sender_chunk_row_count(
    chunk: *const column_sender_chunk,
) -> size_t {
    if chunk.is_null() {
        return 0;
    }
    unsafe { (*chunk).0.row_count() }
}

// ===========================================================================
// Numeric / fixed-width column appends
// ===========================================================================

macro_rules! column_fn {
    ($fn_name:ident, $c_ty:ty, $rust_method:ident, $what:literal) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $fn_name(
            chunk: *mut column_sender_chunk,
            name: *const c_char,
            name_len: size_t,
            data: *const $c_ty,
            row_count: size_t,
            validity: *const column_sender_validity,
            err_out: *mut *mut line_sender_error,
        ) -> bool {
            let chunk = match unsafe { chunk.as_mut() } {
                Some(c) => &mut c.0,
                None => return reject_null_chunk(err_out),
            };
            let name = match unsafe { name_str(name, name_len, err_out) } {
                Some(s) => s,
                None => return false,
            };
            let data = match unsafe { typed_slice(data, row_count, err_out, $what) } {
                Some(s) => s,
                None => return false,
            };
            let validity = match unsafe { as_validity(validity, err_out) } {
                Some(v) => v,
                None => return false,
            };
            bubble!(err_out, chunk.$rust_method(name, data, validity.as_ref()));
            true
        }
    };
}

column_fn!(
    column_sender_chunk_column_i8,
    i8,
    column_i8,
    "i8 column data"
);
column_fn!(
    column_sender_chunk_column_i16,
    i16,
    column_i16,
    "i16 column data"
);
column_fn!(
    column_sender_chunk_column_i32,
    i32,
    column_i32,
    "i32 column data"
);
column_fn!(
    column_sender_chunk_column_i64,
    i64,
    column_i64,
    "i64 column data"
);
column_fn!(
    column_sender_chunk_column_f32,
    f32,
    column_f32,
    "f32 column data"
);
column_fn!(
    column_sender_chunk_column_f64,
    f64,
    column_f64,
    "f64 column data"
);
column_fn!(
    column_sender_chunk_column_ipv4,
    u32,
    column_ipv4,
    "ipv4 column data"
);
column_fn!(
    column_sender_chunk_column_ts_nanos,
    i64,
    column_ts_nanos,
    "ts_nanos column data"
);
column_fn!(
    column_sender_chunk_column_ts_micros,
    i64,
    column_ts_micros,
    "ts_micros column data"
);
column_fn!(
    column_sender_chunk_column_date_millis,
    i64,
    column_date_millis,
    "date_millis column data"
);

/// `BOOLEAN` column. `data` is an Arrow-style LSB-first packed bitmap;
/// must be at least `ceil(row_count / 8)` bytes long.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn column_sender_chunk_column_bool(
    chunk: *mut column_sender_chunk,
    name: *const c_char,
    name_len: size_t,
    data: *const u8,
    row_count: size_t,
    validity: *const column_sender_validity,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let chunk = match unsafe { chunk.as_mut() } {
        Some(c) => &mut c.0,
        None => return reject_null_chunk(err_out),
    };
    let name = match unsafe { name_str(name, name_len, err_out) } {
        Some(s) => s,
        None => return false,
    };
    let bytes_required = row_count.div_ceil(8);
    let data_slice = match unsafe { typed_slice(data, bytes_required, err_out, "bool column data") }
    {
        Some(s) => s,
        None => return false,
    };
    let validity = match unsafe { as_validity(validity, err_out) } {
        Some(v) => v,
        None => return false,
    };
    bubble!(
        err_out,
        chunk.column_bool(name, data_slice, row_count, validity.as_ref())
    );
    true
}

macro_rules! fixed_width_byte_column_fn {
    ($fn_name:ident, $n:literal, $rust_method:ident, $what:literal) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $fn_name(
            chunk: *mut column_sender_chunk,
            name: *const c_char,
            name_len: size_t,
            data: *const u8,
            row_count: size_t,
            validity: *const column_sender_validity,
            err_out: *mut *mut line_sender_error,
        ) -> bool {
            let chunk = match unsafe { chunk.as_mut() } {
                Some(c) => &mut c.0,
                None => return reject_null_chunk(err_out),
            };
            let name = match unsafe { name_str(name, name_len, err_out) } {
                Some(s) => s,
                None => return false,
            };
            if data.is_null() && row_count != 0 {
                unsafe {
                    set_err_out_from_error(
                        err_out,
                        Error::new(
                            ErrorCode::InvalidApiCall,
                            format!(
                                "{} column data pointer is NULL with non-zero row_count",
                                $what
                            ),
                        ),
                    );
                }
                return false;
            }
            let data_slice: &[[u8; $n]] = if row_count == 0 {
                &[]
            } else {
                unsafe { slice::from_raw_parts(data as *const [u8; $n], row_count) }
            };
            let validity = match unsafe { as_validity(validity, err_out) } {
                Some(v) => v,
                None => return false,
            };
            bubble!(
                err_out,
                chunk.$rust_method(name, data_slice, validity.as_ref())
            );
            true
        }
    };
}

fixed_width_byte_column_fn!(column_sender_chunk_column_uuid, 16, column_uuid, "uuid");
fixed_width_byte_column_fn!(
    column_sender_chunk_column_long256,
    32,
    column_long256,
    "long256"
);

// ===========================================================================
// VARCHAR (variable-width text)
// ===========================================================================

/// `BINARY` column. Same `offsets` + `bytes` layout as
/// `column_sender_chunk_column_varchar`; wire type byte differs so the
/// server creates a BINARY column. No UTF-8 validation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn column_sender_chunk_column_binary(
    chunk: *mut column_sender_chunk,
    name: *const c_char,
    name_len: size_t,
    offsets: *const i32,
    bytes: *const u8,
    bytes_len: size_t,
    row_count: size_t,
    validity: *const column_sender_validity,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let chunk = match unsafe { chunk.as_mut() } {
        Some(c) => &mut c.0,
        None => return reject_null_chunk(err_out),
    };
    let name = match unsafe { name_str(name, name_len, err_out) } {
        Some(s) => s,
        None => return false,
    };
    let offsets_len = match row_count.checked_add(1) {
        Some(n) => n,
        None => {
            unsafe {
                set_err_out_from_error(
                    err_out,
                    Error::new(
                        ErrorCode::InvalidApiCall,
                        "row_count overflow when computing offsets length".to_string(),
                    ),
                );
            }
            return false;
        }
    };
    let offsets = match unsafe { typed_slice(offsets, offsets_len, err_out, "binary offsets") } {
        Some(s) => s,
        None => return false,
    };
    let bytes = match unsafe { typed_slice(bytes, bytes_len, err_out, "binary bytes") } {
        Some(s) => s,
        None => return false,
    };
    let validity = match unsafe { as_validity(validity, err_out) } {
        Some(v) => v,
        None => return false,
    };
    bubble!(
        err_out,
        chunk.column_binary(name, offsets, bytes, validity.as_ref())
    );
    true
}

/// `VARCHAR` column. Inputs are Arrow Utf8 shape: `offsets` length
/// `row_count + 1`, monotonically non-decreasing; `bytes` is the
/// concatenated UTF-8 buffer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn column_sender_chunk_column_varchar(
    chunk: *mut column_sender_chunk,
    name: *const c_char,
    name_len: size_t,
    offsets: *const i32,
    bytes: *const u8,
    bytes_len: size_t,
    row_count: size_t,
    validity: *const column_sender_validity,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let chunk = match unsafe { chunk.as_mut() } {
        Some(c) => &mut c.0,
        None => return reject_null_chunk(err_out),
    };
    let name = match unsafe { name_str(name, name_len, err_out) } {
        Some(s) => s,
        None => return false,
    };
    let offsets_len = match row_count.checked_add(1) {
        Some(n) => n,
        None => {
            unsafe {
                set_err_out_from_error(
                    err_out,
                    Error::new(
                        ErrorCode::InvalidApiCall,
                        "row_count overflow when computing offsets length".to_string(),
                    ),
                );
            }
            return false;
        }
    };
    let offsets = match unsafe { typed_slice(offsets, offsets_len, err_out, "varchar offsets") } {
        Some(s) => s,
        None => return false,
    };
    let bytes = match unsafe { typed_slice(bytes, bytes_len, err_out, "varchar bytes") } {
        Some(s) => s,
        None => return false,
    };
    let validity = match unsafe { as_validity(validity, err_out) } {
        Some(v) => v,
        None => return false,
    };
    bubble!(
        err_out,
        chunk.column_varchar(name, offsets, bytes, validity.as_ref())
    );
    true
}

// ===========================================================================
// Symbol dictionary columns
// ===========================================================================

macro_rules! symbol_fn {
    ($fn_name:ident, $code_ty:ty, $rust_method:ident, $what:literal) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $fn_name(
            chunk: *mut column_sender_chunk,
            name: *const c_char,
            name_len: size_t,
            codes: *const $code_ty,
            row_count: size_t,
            dict_offsets: *const i32,
            dict_offsets_len: size_t,
            dict_bytes: *const u8,
            dict_bytes_len: size_t,
            validity: *const column_sender_validity,
            err_out: *mut *mut line_sender_error,
        ) -> bool {
            let chunk = match unsafe { chunk.as_mut() } {
                Some(c) => &mut c.0,
                None => return reject_null_chunk(err_out),
            };
            let name = match unsafe { name_str(name, name_len, err_out) } {
                Some(s) => s,
                None => return false,
            };
            let codes = match unsafe { typed_slice(codes, row_count, err_out, $what) } {
                Some(s) => s,
                None => return false,
            };
            let dict_offsets = match unsafe {
                typed_slice(
                    dict_offsets,
                    dict_offsets_len,
                    err_out,
                    "symbol dict offsets",
                )
            } {
                Some(s) => s,
                None => return false,
            };
            let dict_bytes = match unsafe {
                typed_slice(dict_bytes, dict_bytes_len, err_out, "symbol dict bytes")
            } {
                Some(s) => s,
                None => return false,
            };
            let validity = match unsafe { as_validity(validity, err_out) } {
                Some(v) => v,
                None => return false,
            };
            bubble!(
                err_out,
                chunk.$rust_method(name, codes, dict_offsets, dict_bytes, validity.as_ref())
            );
            true
        }
    };
}

symbol_fn!(
    column_sender_chunk_symbol_dict_i8,
    i8,
    symbol_dict_i8,
    "symbol codes (i8)"
);
symbol_fn!(
    column_sender_chunk_symbol_dict_i16,
    i16,
    symbol_dict_i16,
    "symbol codes (i16)"
);
symbol_fn!(
    column_sender_chunk_symbol_dict_i32,
    i32,
    symbol_dict_i32,
    "symbol codes (i32)"
);

// ===========================================================================
// Generic Arrow column appender
// ===========================================================================

/// Append a slice of one column from an Arrow C Data Interface array.
/// Routes through the same encoding infrastructure as
/// `column_sender_flush_arrow_batch`; supports the full 43-variant
/// Arrow type matrix (`arrow_batch::classify`).
///
/// `row_offset` and `row_count` describe the slice of the array to
/// append; pass `row_offset=0, row_count=array->length` for the whole
/// array.
///
/// Ownership: on success, `array->release` is consumed (set to NULL);
/// the chunk holds the underlying buffers via an internal Arc until
/// `column_sender_flush` returns. On failure, `array->release` may
/// also have been consumed if the call reached the Arrow import step
/// before failing — callers MUST check `array->release != NULL` before
/// invoking it on the failure path. Early-fail paths (NULL pointer,
/// depth-cap rejection) leave it intact. `schema` is borrowed in all
/// cases.
///
/// `array->offset` is honored (the Arrow C Data Interface logical
/// offset); `row_offset` further sub-slices within the call.
#[cfg(feature = "arrow")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn column_sender_chunk_append_arrow_column(
    chunk: *mut column_sender_chunk,
    name: *const c_char,
    name_len: size_t,
    array: *mut ArrowArray,
    schema: *const ArrowSchema,
    row_offset: size_t,
    row_count: size_t,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let chunk = match unsafe { chunk.as_mut() } {
        Some(c) => &mut c.0,
        None => return reject_null_chunk(err_out),
    };
    let name = match unsafe { name_str(name, name_len, err_out) } {
        Some(s) => s,
        None => return false,
    };
    let ffi_array = array as *mut arrow::ffi::FFI_ArrowArray;
    let ffi_schema = schema as *const arrow::ffi::FFI_ArrowSchema;
    let arr_ref = match unsafe {
        crate::arrow_ffi_import_array_sliced(
            ffi_array,
            ffi_schema,
            row_offset,
            row_count,
            "column_sender_chunk_append_arrow_column",
            err_out,
        )
    } {
        Some(a) => a,
        None => return false,
    };
    let field = match arrow::datatypes::Field::try_from(unsafe { &*ffi_schema }) {
        Ok(f) => f,
        Err(e) => {
            unsafe {
                set_err_out_from_error(
                    err_out,
                    Error::new(
                        ErrorCode::ArrowIngest,
                        format!("schema conversion failed: {e}"),
                    ),
                );
            }
            return false;
        }
    };
    bubble!(err_out, chunk.push_arrow_column(name, &field, arr_ref));
    true
}

// ===========================================================================
// NumPy column appender
//
// Companion to `column_sender_chunk_append_arrow_column` that takes a
// raw contiguous NumPy buffer + a dtype tag. Widening / packing happens
// in Rust at append time into a chunk-owned scratch arena, so callers
// don't allocate a widened buffer themselves.
//
// Stride and non-native-endian are not supported; the caller (Python
// client) consolidates upstream.
// ===========================================================================

/// NumPy source dtype tag. Mirrored to the C ABI as a 32-bit enum; the
/// discriminants and order must match `column_sender_numpy_dtype` in the
/// C header. The dtype tells the encoder how to walk `data` at flush and
/// which QWP wire kind to emit; for `decimal_*` and `geohash_*`, the
/// per-call parameter rides on `column_sender_numpy_extras`.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum column_sender_numpy_dtype {
    column_sender_numpy_i8 = 0,
    column_sender_numpy_i16 = 1,
    column_sender_numpy_i32 = 2,
    column_sender_numpy_i64 = 3,
    column_sender_numpy_u8 = 4,
    column_sender_numpy_u16 = 5,
    column_sender_numpy_u32 = 6,
    column_sender_numpy_u64 = 7,
    column_sender_numpy_f32 = 8,
    column_sender_numpy_f64 = 9,
    column_sender_numpy_bool = 10,

    column_sender_numpy_f16 = 11,
    column_sender_numpy_datetime64_s = 12,
    column_sender_numpy_datetime64_ms = 13,
    column_sender_numpy_datetime64_us = 14,
    column_sender_numpy_datetime64_ns = 15,
    column_sender_numpy_timedelta64_s = 16,
    column_sender_numpy_timedelta64_ms = 17,
    column_sender_numpy_timedelta64_us = 18,
    column_sender_numpy_timedelta64_ns = 19,

    column_sender_numpy_s16 = 20,
    column_sender_numpy_s32 = 21,

    column_sender_numpy_decimal_s8 = 22,
    column_sender_numpy_decimal_s16 = 23,
    column_sender_numpy_decimal_s32 = 24,

    column_sender_numpy_u32_ipv4 = 25,
    column_sender_numpy_u16_char = 26,

    column_sender_numpy_geohash_i8 = 27,
    column_sender_numpy_geohash_i16 = 28,
    column_sender_numpy_geohash_i32 = 29,
    column_sender_numpy_geohash_i64 = 30,

    column_sender_numpy_f64_ndarray = 31,

    column_sender_numpy_datetime64_m = 32,
    column_sender_numpy_datetime64_h = 33,
    column_sender_numpy_datetime64_D = 34,
    column_sender_numpy_datetime64_M = 35,
    column_sender_numpy_datetime64_Y = 36,
}

/// Companion to [`column_sender_chunk_append_numpy_column`] carrying
/// dtype-specific parameters. Pass NULL unless the chosen dtype reads
/// from a field (decimal scale, geohash bits).
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct column_sender_numpy_extras {
    pub decimal_scale: i8,
    pub geohash_bits: u8,
    /// Number of dimensions per row for `column_sender_numpy_f64_ndarray`.
    /// Must be in `1..=MAX_ARRAY_DIMS` (`32`).
    pub array_ndim: u8,
    /// Per-row shape (length = `array_ndim`). Each dim must be >= 1. The
    /// pointer is borrowed for the duration of the FFI call only.
    pub array_shape: *const u32,
}

unsafe fn validate_decimal_scale(
    extras: Option<&column_sender_numpy_extras>,
    max_scale: i8,
    label: &str,
    err_out: *mut *mut line_sender_error,
) -> Option<u8> {
    let Some(extras) = extras else {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    format!(
                        "{label} column requires non-NULL column_sender_numpy_extras with decimal_scale set"
                    ),
                ),
            );
        }
        return None;
    };
    let scale = extras.decimal_scale;
    if scale < 0 {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    format!("decimal_scale must be >= 0, got {scale}"),
                ),
            );
        }
        return None;
    }
    if scale > max_scale {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    format!("decimal_scale must be <= {max_scale} for {label}, got {scale}"),
                ),
            );
        }
        return None;
    }
    Some(scale as u8)
}

unsafe fn validate_geohash_bits(
    extras: Option<&column_sender_numpy_extras>,
    max_bits: u8,
    err_out: *mut *mut line_sender_error,
) -> Option<u8> {
    let Some(extras) = extras else {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    "GEOHASH iN column requires non-NULL column_sender_numpy_extras with geohash_bits set".to_string(),
                ),
            );
        }
        return None;
    };
    let bits = extras.geohash_bits;
    if bits == 0 {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    "geohash_bits must be >= 1, got 0".to_string(),
                ),
            );
        }
        return None;
    }
    if bits > max_bits {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    format!("geohash_bits must be <= {max_bits} for GEOHASH iN, got {bits}"),
                ),
            );
        }
        return None;
    }
    Some(bits)
}

unsafe fn validate_f64_ndarray(
    extras: Option<&column_sender_numpy_extras>,
    err_out: *mut *mut line_sender_error,
) -> Option<(u8, [u32; MAX_ARRAY_DIMS])> {
    let Some(extras) = extras else {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    "f64_ndarray column requires non-NULL column_sender_numpy_extras with array_ndim and array_shape set".to_string(),
                ),
            );
        }
        return None;
    };
    let ndim = extras.array_ndim;
    if ndim == 0 {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    "array_ndim must be >= 1, got 0".to_string(),
                ),
            );
        }
        return None;
    }
    if (ndim as usize) > MAX_ARRAY_DIMS {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    format!("array_ndim must be <= {MAX_ARRAY_DIMS} (MAX_ARRAY_DIMS), got {ndim}"),
                ),
            );
        }
        return None;
    }
    if extras.array_shape.is_null() {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    "f64_ndarray column requires non-NULL array_shape".to_string(),
                ),
            );
        }
        return None;
    }
    let mut shape = [0u32; MAX_ARRAY_DIMS];
    for (i, slot) in shape.iter_mut().take(ndim as usize).enumerate() {
        let dim = unsafe { *extras.array_shape.add(i) };
        if dim == 0 {
            unsafe {
                set_err_out_from_error(
                    err_out,
                    Error::new(
                        ErrorCode::InvalidApiCall,
                        format!("array_shape[{i}] must be >= 1, got 0"),
                    ),
                );
            }
            return None;
        }
        *slot = dim;
    }
    Some((ndim, shape))
}

unsafe fn resolve_numpy_dtype(
    dtype: column_sender_numpy_dtype,
    extras: *const column_sender_numpy_extras,
    err_out: *mut *mut line_sender_error,
) -> Option<NumpyDtype> {
    use column_sender_numpy_dtype as D;
    let extras = unsafe { extras.as_ref() };
    Some(match dtype {
        D::column_sender_numpy_i64 => NumpyDtype::I64Direct,
        D::column_sender_numpy_f64 => NumpyDtype::F64Direct,
        D::column_sender_numpy_datetime64_ms => NumpyDtype::DateI64Direct,
        D::column_sender_numpy_datetime64_us => NumpyDtype::TimestampMicrosDirect,
        D::column_sender_numpy_datetime64_ns => NumpyDtype::TimestampNanosDirect,
        D::column_sender_numpy_timedelta64_s
        | D::column_sender_numpy_timedelta64_ms
        | D::column_sender_numpy_timedelta64_us
        | D::column_sender_numpy_timedelta64_ns => NumpyDtype::LongDirect,
        D::column_sender_numpy_s16 => NumpyDtype::UuidDirect,
        D::column_sender_numpy_s32 => NumpyDtype::Long256Direct,
        D::column_sender_numpy_u32_ipv4 => NumpyDtype::Ipv4Direct,
        D::column_sender_numpy_u16_char => NumpyDtype::CharDirect,

        D::column_sender_numpy_i8 => NumpyDtype::I8Direct,
        D::column_sender_numpy_i16 => NumpyDtype::I16Direct,
        D::column_sender_numpy_i32 => NumpyDtype::I32Direct,
        D::column_sender_numpy_u8 => NumpyDtype::U8WidenToI32,
        D::column_sender_numpy_u16 => NumpyDtype::U16WidenToI32,
        D::column_sender_numpy_u32 => NumpyDtype::U32WidenToI64,
        D::column_sender_numpy_u64 => NumpyDtype::U64WidenToI64,
        D::column_sender_numpy_f32 => NumpyDtype::F32Widen,
        D::column_sender_numpy_f16 => NumpyDtype::F16Widen,
        D::column_sender_numpy_bool => NumpyDtype::Bool,
        D::column_sender_numpy_datetime64_s => NumpyDtype::DatetimeSecToMicros,
        D::column_sender_numpy_datetime64_m => NumpyDtype::DatetimeMinuteToMicros,
        D::column_sender_numpy_datetime64_h => NumpyDtype::DatetimeHourToMicros,
        D::column_sender_numpy_datetime64_D => NumpyDtype::DatetimeDayToMicros,
        D::column_sender_numpy_datetime64_M => NumpyDtype::DatetimeMonthToMicros,
        D::column_sender_numpy_datetime64_Y => NumpyDtype::DatetimeYearToMicros,

        D::column_sender_numpy_decimal_s8 => NumpyDtype::Decimal64 {
            scale: unsafe { validate_decimal_scale(extras, 18, "DECIMAL64", err_out)? },
        },
        D::column_sender_numpy_decimal_s16 => NumpyDtype::Decimal128 {
            scale: unsafe { validate_decimal_scale(extras, 38, "DECIMAL128", err_out)? },
        },
        D::column_sender_numpy_decimal_s32 => NumpyDtype::Decimal256 {
            scale: unsafe { validate_decimal_scale(extras, 76, "DECIMAL256", err_out)? },
        },

        D::column_sender_numpy_geohash_i8 => NumpyDtype::GeohashI8 {
            bits: unsafe { validate_geohash_bits(extras, 8, err_out)? },
        },
        D::column_sender_numpy_geohash_i16 => NumpyDtype::GeohashI16 {
            bits: unsafe { validate_geohash_bits(extras, 16, err_out)? },
        },
        D::column_sender_numpy_geohash_i32 => NumpyDtype::GeohashI32 {
            bits: unsafe { validate_geohash_bits(extras, 32, err_out)? },
        },
        D::column_sender_numpy_geohash_i64 => NumpyDtype::GeohashI64 {
            bits: unsafe { validate_geohash_bits(extras, 60, err_out)? },
        },

        D::column_sender_numpy_f64_ndarray => {
            let (ndim, shape) = unsafe { validate_f64_ndarray(extras, err_out)? };
            NumpyDtype::F64Ndarray { ndim, shape }
        }
    })
}

/// Append one column from a contiguous, native-endian NumPy buffer.
/// The buffer is walked at flush time straight into the outbound frame;
/// no per-column copy is taken at append. Caller MUST keep `data` (and
/// `validity->bits`, if any) alive until the next
/// `column_sender_flush` / `column_sender_sync` returns.
///
/// `dtype` selects from 31 supported NumPy → QuestDB wire mappings (see
/// the C header for the full coverage matrix). For `decimal_*`,
/// `geohash_*`, and `f64_ndarray` dtypes, `extras` must be non-NULL and
/// supply the corresponding fields (`decimal_scale` 0..=18/38/76;
/// `geohash_bits` 1..=8/16/32/60; `array_ndim` 1..=32 with `array_shape`
/// pointing at `array_ndim` per-dim u32 sizes, each >= 1). For every
/// other dtype, `extras` is ignored and may be NULL.
///
/// Strided and non-native-endian arrays are not supported; consolidate
/// upstream.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn column_sender_chunk_append_numpy_column(
    chunk: *mut column_sender_chunk,
    name: *const c_char,
    name_len: size_t,
    dtype: column_sender_numpy_dtype,
    data: *const u8,
    row_count: size_t,
    validity: *const column_sender_validity,
    extras: *const column_sender_numpy_extras,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let chunk = match unsafe { chunk.as_mut() } {
        Some(c) => &mut c.0,
        None => return reject_null_chunk(err_out),
    };
    let name = match unsafe { name_str(name, name_len, err_out) } {
        Some(s) => s,
        None => return false,
    };
    let validity = match unsafe { as_validity(validity, err_out) } {
        Some(v) => v,
        None => return false,
    };
    let dtype = match unsafe { resolve_numpy_dtype(dtype, extras, err_out) } {
        Some(d) => d,
        None => return false,
    };
    bubble!(err_out, unsafe {
        chunk.push_numpy_deferred(name, dtype, data, row_count, validity.as_ref())
    });
    true
}

// ===========================================================================
// Designated timestamp
// ===========================================================================

#[unsafe(no_mangle)]
pub unsafe extern "C" fn column_sender_chunk_designated_timestamp_micros(
    chunk: *mut column_sender_chunk,
    data: *const i64,
    row_count: size_t,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let chunk = match unsafe { chunk.as_mut() } {
        Some(c) => &mut c.0,
        None => return reject_null_chunk(err_out),
    };
    let data = match unsafe { typed_slice(data, row_count, err_out, "designated_ts micros") } {
        Some(s) => s,
        None => return false,
    };
    bubble!(err_out, chunk.designated_timestamp_micros(data));
    true
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn column_sender_chunk_designated_timestamp_nanos(
    chunk: *mut column_sender_chunk,
    data: *const i64,
    row_count: size_t,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let chunk = match unsafe { chunk.as_mut() } {
        Some(c) => &mut c.0,
        None => return reject_null_chunk(err_out),
    };
    let data = match unsafe { typed_slice(data, row_count, err_out, "designated_ts nanos") } {
        Some(s) => s,
        None => return false,
    };
    bubble!(err_out, chunk.designated_timestamp_nanos(data));
    true
}

// ===========================================================================
// Flush
// ===========================================================================

/// Encode `chunk` into a QWP/WebSocket frame, write it to the socket,
/// and return immediately — without waiting for the server's ack.
///
/// Ready acks are drained non-blocking before the write. Deferred
/// flushes keep one in-flight slot reserved for the later
/// `column_sender_sync` commit frame; if that reserve would be
/// consumed, the call fails and the caller must sync before flushing
/// more chunks.
///
/// On success, `chunk` is cleared and the call returns `true`. On
/// failure, `chunk` is left untouched and `false` is returned (with
/// `*err_out` set if provided).
///
/// Call [`column_sender_sync`] after the last flush to drain all
/// remaining in-flight acks.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn column_sender_flush(
    conn: *mut qwpws_conn,
    chunk: *mut column_sender_chunk,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let sender = match unsafe { conn.as_mut() } {
        Some(c) => c.0.get_mut(),
        None => {
            unsafe {
                set_err_out_from_error(
                    err_out,
                    Error::new(
                        ErrorCode::InvalidApiCall,
                        "column_sender_flush: conn pointer is NULL".to_string(),
                    ),
                );
            }
            return false;
        }
    };
    let chunk = match unsafe { chunk.as_mut() } {
        Some(c) => &mut c.0,
        None => return reject_null_chunk(err_out),
    };
    bubble!(err_out, sender.flush(chunk));
    true
}

/// Encode an Apache Arrow `RecordBatch` (Arrow C Data Interface) as a
/// single QWP/WebSocket frame for `table` and publish it through `conn`
/// in one pass — no intermediate buffer staging, no per-column copy.
///
/// `array` may be either a Struct array (one child per column, standard
/// RecordBatch shape) or a non-Struct single-column array whose
/// `schema->name` becomes the column name.
///
/// The per-row designated timestamp is omitted; the server stamps each
/// row on arrival. Use [`column_sender_flush_arrow_batch_at_column`] to
/// source the timestamp from a `Timestamp(_)` column inside the batch.
///
/// Ownership: on success, `array->release` is consumed (set to NULL)
/// and the function has invoked it internally. On failure, `array->release`
/// may also have been consumed if the call reached the Arrow import
/// step before failing — callers MUST check `array->release != NULL`
/// before invoking it on the failure path. `schema` is always
/// borrowed.
///
/// Returns `true` on success, `false` on error (with `*err_out` set).
#[cfg(feature = "arrow")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn column_sender_flush_arrow_batch(
    conn: *mut qwpws_conn,
    table: line_sender_table_name,
    array: *mut arrow::ffi::FFI_ArrowArray,
    schema: *const arrow::ffi::FFI_ArrowSchema,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe { arrow_batch_impl(conn, table, array, schema, None, err_out) }
}

/// Variant of [`column_sender_flush_arrow_batch`] that sources each
/// row's designated timestamp from a named `Timestamp(_)` column inside
/// the batch. The column must be `Timestamp(Microsecond | Nanosecond |
/// Millisecond, _)` with no null rows and no values before the Unix
/// epoch. Same ownership contract.
#[cfg(feature = "arrow")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn column_sender_flush_arrow_batch_at_column(
    conn: *mut qwpws_conn,
    table: line_sender_table_name,
    array: *mut arrow::ffi::FFI_ArrowArray,
    schema: *const arrow::ffi::FFI_ArrowSchema,
    ts_column: line_sender_column_name,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe { arrow_batch_impl(conn, table, array, schema, Some(ts_column), err_out) }
}

#[cfg(feature = "arrow")]
unsafe fn arrow_batch_impl(
    conn: *mut qwpws_conn,
    table: line_sender_table_name,
    array: *mut arrow::ffi::FFI_ArrowArray,
    schema: *const arrow::ffi::FFI_ArrowSchema,
    ts_column: Option<line_sender_column_name>,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let sender = match unsafe { conn.as_mut() } {
        Some(c) => c.0.get_mut(),
        None => {
            crate::arrow_err_to_c_box(
                err_out,
                ErrorCode::InvalidApiCall,
                "column_sender_flush_arrow_batch: conn pointer is NULL".to_string(),
            );
            return false;
        }
    };
    let rb = match unsafe {
        crate::arrow_ffi_import_record_batch(
            array,
            schema,
            "column_sender_flush_arrow_batch",
            err_out,
        )
    } {
        Some(rb) => rb,
        None => return false,
    };
    let table_name = unsafe { table.as_name() };
    let result = match ts_column {
        Some(ts) => sender.flush_arrow_batch_at_column(table_name, &rb, ts.as_name()),
        None => sender.flush_arrow_batch(table_name, &rb),
    };
    bubble!(err_out, result);
    true
}

/// Block until all in-flight frames are acknowledged at the requested
/// `ack_level`.
///
/// `column_sender_ack_level_ok` waits for every in-flight frame's
/// WAL-commit ack. `column_sender_ack_level_durable` additionally waits
/// for the server's object-store durability watermarks.
///
/// Returns `true` on success, `false` on error (with `*err_out` set).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn column_sender_sync(
    conn: *mut qwpws_conn,
    ack_level: column_sender_ack_level,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let sender = match unsafe { conn.as_mut() } {
        Some(c) => c.0.get_mut(),
        None => {
            unsafe {
                set_err_out_from_error(
                    err_out,
                    Error::new(
                        ErrorCode::InvalidApiCall,
                        "column_sender_sync: conn pointer is NULL".to_string(),
                    ),
                );
            }
            return false;
        }
    };
    bubble!(err_out, sender.sync(ack_level.into()));
    true
}

// ===========================================================================
// Helpers
// ===========================================================================

fn reject_null_chunk(err_out: *mut *mut line_sender_error) -> bool {
    unsafe {
        set_err_out_from_error(
            err_out,
            Error::new(
                ErrorCode::InvalidApiCall,
                "column_sender_chunk pointer is NULL".to_string(),
            ),
        );
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::line_sender_error_free;
    #[cfg(feature = "arrow")]
    use std::ffi::c_void;

    // Most behaviour is already covered by the questdb-rs lib tests; this
    // module's tests focus on the FFI surface — pointer handling, NULL
    // guards, lifetime of error objects, etc.

    #[test]
    fn connect_rejects_non_qwp_ws_schema() {
        let conf = b"http::addr=localhost:9000;";
        let mut err: *mut line_sender_error = std::ptr::null_mut();
        let db =
            unsafe { questdb_db_connect(conf.as_ptr() as *const c_char, conf.len(), &mut err) };
        assert!(db.is_null());
        assert!(!err.is_null());
        unsafe { line_sender_error_free(err) };
    }

    #[test]
    fn chunk_new_validates_table_name() {
        let mut err: *mut line_sender_error = std::ptr::null_mut();
        // 128-byte name: exceeds the 127-byte QWP cap, but the public
        // `Chunk::new` does not validate eagerly — validation happens at
        // flush time. So this constructor succeeds.
        let table = "x".repeat(128);
        let chunk = unsafe {
            column_sender_chunk_new(table.as_ptr() as *const c_char, table.len(), &mut err)
        };
        assert!(!chunk.is_null());
        assert!(err.is_null());
        unsafe { column_sender_chunk_free(chunk) };
    }

    #[test]
    fn chunk_new_rejects_invalid_utf8() {
        let bad: [u8; 3] = [0xFF, 0xFE, 0xFD];
        let mut err: *mut line_sender_error = std::ptr::null_mut();
        let chunk =
            unsafe { column_sender_chunk_new(bad.as_ptr() as *const c_char, bad.len(), &mut err) };
        assert!(chunk.is_null());
        assert!(!err.is_null());
        unsafe { line_sender_error_free(err) };
    }

    #[test]
    fn column_i64_round_trip_on_pure_data_path() {
        let table = b"trades";
        let mut err: *mut line_sender_error = std::ptr::null_mut();
        let chunk = unsafe {
            column_sender_chunk_new(table.as_ptr() as *const c_char, table.len(), &mut err)
        };
        assert!(!chunk.is_null());

        let name = b"price";
        let data: [i64; 3] = [1, 2, 3];
        let ok = unsafe {
            column_sender_chunk_column_i64(
                chunk,
                name.as_ptr() as *const c_char,
                name.len(),
                data.as_ptr(),
                data.len(),
                std::ptr::null(),
                &mut err,
            )
        };
        assert!(ok, "column_i64 should succeed");
        assert_eq!(unsafe { column_sender_chunk_row_count(chunk) }, 3);
        unsafe { column_sender_chunk_free(chunk) };
    }

    #[test]
    fn column_i64_rejects_row_count_mismatch() {
        let table = b"trades";
        let mut err: *mut line_sender_error = std::ptr::null_mut();
        let chunk = unsafe {
            column_sender_chunk_new(table.as_ptr() as *const c_char, table.len(), &mut err)
        };
        let name_a = b"a";
        let name_b = b"b";
        let data_a: [i64; 3] = [1, 2, 3];
        let data_b: [i64; 2] = [4, 5];
        assert!(unsafe {
            column_sender_chunk_column_i64(
                chunk,
                name_a.as_ptr() as *const c_char,
                name_a.len(),
                data_a.as_ptr(),
                data_a.len(),
                std::ptr::null(),
                &mut err,
            )
        });
        let ok = unsafe {
            column_sender_chunk_column_i64(
                chunk,
                name_b.as_ptr() as *const c_char,
                name_b.len(),
                data_b.as_ptr(),
                data_b.len(),
                std::ptr::null(),
                &mut err,
            )
        };
        assert!(!ok);
        assert!(!err.is_null());
        unsafe { line_sender_error_free(err) };
        unsafe { column_sender_chunk_free(chunk) };
    }

    #[test]
    fn validity_null_bits_with_nonzero_len_errors() {
        let table = b"trades";
        let mut err: *mut line_sender_error = std::ptr::null_mut();
        let chunk = unsafe {
            column_sender_chunk_new(table.as_ptr() as *const c_char, table.len(), &mut err)
        };
        let name = b"a";
        let data: [i64; 2] = [1, 2];
        let v = column_sender_validity {
            bits: std::ptr::null(),
            bit_len: 2,
        };
        let ok = unsafe {
            column_sender_chunk_column_i64(
                chunk,
                name.as_ptr() as *const c_char,
                name.len(),
                data.as_ptr(),
                data.len(),
                &v,
                &mut err,
            )
        };
        assert!(!ok);
        assert!(!err.is_null());
        unsafe { line_sender_error_free(err) };
        unsafe { column_sender_chunk_free(chunk) };
    }

    #[cfg(feature = "arrow")]
    #[test]
    fn append_arrow_dictionary_accepts_large_utf8_values() {
        let table = b"trades";
        let mut err: *mut line_sender_error = std::ptr::null_mut();
        let chunk = unsafe {
            column_sender_chunk_new(table.as_ptr() as *const c_char, table.len(), &mut err)
        };
        assert!(!chunk.is_null());

        let index_format = b"i\0";
        let value_format = b"U\0";
        let mut dict_schema = ArrowSchema {
            format: value_format.as_ptr() as *const c_char,
            name: std::ptr::null(),
            metadata: std::ptr::null(),
            flags: 0,
            n_children: 0,
            children: std::ptr::null(),
            dictionary: std::ptr::null_mut(),
            release: None,
            private_data: std::ptr::null_mut(),
        };
        let schema = ArrowSchema {
            format: index_format.as_ptr() as *const c_char,
            name: std::ptr::null(),
            metadata: std::ptr::null(),
            flags: 0,
            n_children: 0,
            children: std::ptr::null(),
            dictionary: &mut dict_schema,
            release: None,
            private_data: std::ptr::null_mut(),
        };

        let codes = [0i32, 1, 0];
        let dict_offsets = [0i64, 5, 9];
        let dict_bytes = b"alphabeta";
        let array_buffers = [std::ptr::null(), codes.as_ptr() as *const c_void];
        let dict_buffers = [
            std::ptr::null(),
            dict_offsets.as_ptr() as *const c_void,
            dict_bytes.as_ptr() as *const c_void,
        ];
        let mut dict_array = ArrowArray {
            length: 2,
            null_count: 0,
            offset: 0,
            n_buffers: 3,
            n_children: 0,
            buffers: dict_buffers.as_ptr(),
            children: std::ptr::null(),
            dictionary: std::ptr::null_mut(),
            release: None,
            private_data: std::ptr::null_mut(),
        };
        let mut array = ArrowArray {
            length: 3,
            null_count: 0,
            offset: 0,
            n_buffers: 2,
            n_children: 0,
            buffers: array_buffers.as_ptr(),
            children: std::ptr::null(),
            dictionary: &mut dict_array,
            release: None,
            private_data: std::ptr::null_mut(),
        };

        let name = b"sym";
        let ok = unsafe {
            column_sender_chunk_append_arrow_column(
                chunk,
                name.as_ptr() as *const c_char,
                name.len(),
                &mut array,
                &schema,
                0,
                codes.len(),
                &mut err,
            )
        };
        assert!(ok, "LargeUtf8 dictionary values should be accepted");
        assert!(err.is_null());
        assert_eq!(unsafe { column_sender_chunk_row_count(chunk) }, codes.len());
        unsafe { column_sender_chunk_free(chunk) };
    }

    #[test]
    fn null_chunk_pointer_is_handled() {
        let mut err: *mut line_sender_error = std::ptr::null_mut();
        let name = b"a";
        let data: [i64; 1] = [1];
        let ok = unsafe {
            column_sender_chunk_column_i64(
                std::ptr::null_mut(),
                name.as_ptr() as *const c_char,
                name.len(),
                data.as_ptr(),
                data.len(),
                std::ptr::null(),
                &mut err,
            )
        };
        assert!(!ok);
        assert!(!err.is_null());
        unsafe { line_sender_error_free(err) };
    }

    #[test]
    fn ack_level_enum_maps_correctly() {
        assert_eq!(
            AckLevel::from(column_sender_ack_level::column_sender_ack_level_ok),
            AckLevel::Ok
        );
        assert_eq!(
            AckLevel::from(column_sender_ack_level::column_sender_ack_level_durable),
            AckLevel::Durable
        );
    }
}
