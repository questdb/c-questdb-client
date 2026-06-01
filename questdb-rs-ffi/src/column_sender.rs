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

use questdb::ingress::column_sender::{
    AckLevel, Chunk, NumpyDtype, OwnedSender, QuestDb, Validity,
};
use questdb::{Error, ErrorCode};

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
/// `column_sender_chunk_column_*` / `column_sender_chunk_symbol_dict_*`
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
            // SAFETY: the caller promises `data` points to `row_count *
            // N` bytes (FFI-ABI §6) and that the buffer outlives the call.
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

// `UUID` column. `data` is `row_count * 16` bytes; the FFI takes a
// `uint8_t*` and slices it into 16-byte rows.
fixed_width_byte_column_fn!(column_sender_chunk_column_uuid, 16, column_uuid, "uuid");

// `LONG256` column. `data` is `row_count * 32` bytes.
fixed_width_byte_column_fn!(
    column_sender_chunk_column_long256,
    32,
    column_long256,
    "long256"
);

// ===========================================================================
// VARCHAR (variable-width text)
// ===========================================================================

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

/// Read the Arrow schema's format string. Returns `None` on a NULL ptr
/// or invalid UTF-8.
unsafe fn arrow_format_str(
    schema: &ArrowSchema,
    err_out: *mut *mut line_sender_error,
) -> Option<&str> {
    if schema.format.is_null() {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    "ArrowSchema.format is NULL".to_string(),
                ),
            );
        }
        return None;
    }
    let bytes = unsafe { std::ffi::CStr::from_ptr(schema.format) }.to_bytes();
    match str::from_utf8(bytes) {
        Ok(s) => Some(s),
        Err(_) => {
            unsafe {
                set_err_out_from_error(
                    err_out,
                    Error::new(
                        ErrorCode::InvalidUtf8,
                        "ArrowSchema.format is not valid UTF-8".to_string(),
                    ),
                );
            }
            None
        }
    }
}

/// Reject Arrow arrays with a non-zero logical offset — the current
/// validity / offset slicing logic assumes the array starts at bit 0
/// of buffers[0] and offset 0 of buffers[1]. Sliced arrays must be
/// consolidated by the caller.
unsafe fn arrow_check_offset(array: &ArrowArray, err_out: *mut *mut line_sender_error) -> bool {
    if array.offset != 0 {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    format!(
                        "ArrowArray.offset is {} (only 0 is supported); \
                         consolidate the array before passing it in.",
                        array.offset
                    ),
                ),
            );
        }
        return false;
    }
    true
}

/// Build a Validity from the slice `[row_offset .. row_offset + row_count)`
/// of the array's validity buffer (buffers[0]). Returns `Some(None)` when
/// the array has no nulls (so no validity is passed to the column writer),
/// `Some(Some(_))` when validity is present, and `None` on error.
///
/// `row_offset` must be a multiple of 8 when validity is present, because
/// the QWP encoder reads the bitmap byte-aligned. Callers planning
/// non-aligned chunk boundaries must either align them or rebuild the
/// bitmap.
unsafe fn arrow_validity<'a>(
    array: &ArrowArray,
    row_offset: usize,
    row_count: usize,
    err_out: *mut *mut line_sender_error,
) -> Option<Option<Validity<'a>>> {
    if array.null_count == 0 {
        return Some(None);
    }
    if array.n_buffers < 1 || array.buffers.is_null() {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    "ArrowArray has nulls but no buffers".to_string(),
                ),
            );
        }
        return None;
    }
    let validity_buf = unsafe { *array.buffers.add(0) } as *const u8;
    if validity_buf.is_null() {
        // Arrow spec: `null_count = -1` means "unknown". When the
        // bitmap pointer is also NULL the producer is signalling "I
        // don't know how many nulls there are, and I'm not exposing a
        // bitmap" — most producers (pyarrow, polars) only emit this
        // shape when the column has no nulls. Treat it as no-nulls
        // here; downstream encoders read the data buffer densely.
        if array.null_count < 0 {
            return Some(None);
        }
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    "ArrowArray.null_count > 0 but validity buffer is NULL".to_string(),
                ),
            );
        }
        return None;
    }
    if !row_offset.is_multiple_of(8) {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    format!(
                        "ArrowArray validity slice requires row_offset to be a \
                         multiple of 8 (got {row_offset}); align chunk \
                         boundaries or rebuild the bitmap."
                    ),
                ),
            );
        }
        return None;
    }
    let shifted = unsafe { validity_buf.add(row_offset / 8) };
    let required = row_count.div_ceil(8);
    let bytes = unsafe { slice::from_raw_parts(shifted, required) };
    match Validity::from_bitmap(bytes, row_count) {
        Ok(v) => Some(Some(v)),
        Err(err) => {
            unsafe { set_err_out_from_error(err_out, err) };
            None
        }
    }
}

/// Read the i-th buffer pointer from `array.buffers`, cast to `*const T`.
///
/// `allow_null` lets caller opt in to a NULL buffer pointer (only the
/// bytes buffer of an empty varchar/symbol-dict array does this). All
/// other call sites must pass `allow_null = false` so a malformed Arrow
/// array (length > 0 with a NULL data buffer) is rejected with an
/// `InvalidApiCall` rather than dereferenced.
unsafe fn arrow_buffer<T>(
    array: &ArrowArray,
    idx: i64,
    allow_null: bool,
    err_out: *mut *mut line_sender_error,
    what: &'static str,
) -> Option<*const T> {
    if array.n_buffers <= idx || array.buffers.is_null() {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    format!(
                        "ArrowArray missing buffer #{idx} for {what} \
                         (n_buffers={})",
                        array.n_buffers
                    ),
                ),
            );
        }
        return None;
    }
    let p = unsafe { *array.buffers.add(idx as usize) } as *const T;
    if !allow_null && p.is_null() {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    format!("ArrowArray buffer #{idx} for {what} is NULL"),
                ),
            );
        }
        return None;
    }
    Some(p)
}

#[derive(Clone, Copy)]
enum ArrowDictionaryOffsets<'a> {
    Utf8(&'a [i32]),
    LargeUtf8(&'a [i64]),
}

unsafe fn arrow_bytes_len_from_last_offset(
    last_offset: i64,
    err_out: *mut *mut line_sender_error,
    what: &str,
) -> Option<usize> {
    if last_offset < 0 {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    format!("{what} last offset must be non-negative: {last_offset}"),
                ),
            );
        }
        return None;
    }
    match usize::try_from(last_offset) {
        Ok(v) => Some(v),
        Err(_) => {
            unsafe {
                set_err_out_from_error(
                    err_out,
                    Error::new(
                        ErrorCode::InvalidApiCall,
                        format!("{what} last offset does not fit usize: {last_offset}"),
                    ),
                );
            }
            None
        }
    }
}

/// Inspect the Arrow dictionary subtree for a Categorical-style column.
/// Returns the dictionary offsets and bytes ready to feed into
/// `Chunk::symbol_dict_i*` / `Chunk::symbol_dict_large_i*`. Rejects any
/// dict value type other than UTF-8 (`u`) or LargeUtf8 (`U`).
unsafe fn arrow_dictionary_utf8<'a>(
    schema: &ArrowSchema,
    array: &ArrowArray,
    err_out: *mut *mut line_sender_error,
) -> Option<(ArrowDictionaryOffsets<'a>, &'a [u8])> {
    if schema.dictionary.is_null() || array.dictionary.is_null() {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    "dictionary type missing dictionary array or schema".to_string(),
                ),
            );
        }
        return None;
    }
    let dict_schema = unsafe { &*schema.dictionary };
    let dict_array = unsafe { &*array.dictionary };
    if !unsafe { arrow_check_offset(dict_array, err_out) } {
        return None;
    }
    let dict_format = unsafe { arrow_format_str(dict_schema, err_out) }?;
    if dict_format != "u" && dict_format != "U" {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    format!(
                        "dictionary value type {dict_format:?} is not \
                         supported (only UTF-8 'u' or LargeUtf8 'U')"
                    ),
                ),
            );
        }
        return None;
    }
    if dict_array.length < 0 {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    format!(
                        "ArrowArray dictionary length is negative: {}",
                        dict_array.length
                    ),
                ),
            );
        }
        return None;
    }
    let dict_len = dict_array.length as usize;
    let bytes_ptr = unsafe {
        arrow_buffer::<u8>(
            dict_array,
            2,
            /* allow_null = */ true,
            err_out,
            "dict bytes",
        )
    }?;
    let (offsets, bytes_len) = if dict_format == "u" {
        let offsets_ptr = unsafe {
            arrow_buffer::<i32>(
                dict_array,
                1,
                /* allow_null = */ false,
                err_out,
                "dict offsets",
            )
        }?;
        let offsets = unsafe { slice::from_raw_parts(offsets_ptr, dict_len + 1) };
        let bytes_len = if dict_len == 0 {
            0
        } else {
            unsafe {
                arrow_bytes_len_from_last_offset(
                    offsets[dict_len] as i64,
                    err_out,
                    "dictionary UTF-8",
                )
            }?
        };
        (ArrowDictionaryOffsets::Utf8(offsets), bytes_len)
    } else {
        let offsets_ptr = unsafe {
            arrow_buffer::<i64>(
                dict_array,
                1,
                /* allow_null = */ false,
                err_out,
                "dict offsets",
            )
        }?;
        let offsets = unsafe { slice::from_raw_parts(offsets_ptr, dict_len + 1) };
        let bytes_len = if dict_len == 0 {
            0
        } else {
            unsafe {
                arrow_bytes_len_from_last_offset(offsets[dict_len], err_out, "dictionary LargeUtf8")
            }?
        };
        (ArrowDictionaryOffsets::LargeUtf8(offsets), bytes_len)
    };
    let bytes = if bytes_len == 0 || bytes_ptr.is_null() {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(bytes_ptr, bytes_len) }
    };
    Some((offsets, bytes))
}

/// Append a slice of one column from an Arrow C Data interface array.
/// Delegates to the appropriate `column_sender_chunk_column_*` /
/// `_symbol_dict_*` path based on the schema's format string.
///
/// `row_offset` and `row_count` describe the slice of the array to
/// append; pass `row_offset=0, row_count=array->length` to send the
/// whole array. When the array has nulls, `row_offset` must be a
/// multiple of 8 (the QWP encoder reads the validity bitmap
/// byte-aligned).
///
/// Supported formats (see Apache Arrow C Data Interface spec):
///   - `c`, `s`, `i`, `l`          int8 / int16 / int32 / int64
///   - `f`, `g`                    float32 / float64
///   - `b`                         bool (LSB-first bitmap)
///   - `u`                         UTF-8 string (int32 offsets)
///   - `U`                         LargeUtf8 string (int64 offsets;
///     narrowed to u32 at encode time)
///   - `tsn:...`                   timestamp nanos (timezone ignored)
///   - `tsu:...`                   timestamp micros (timezone ignored)
///   - dictionary-typed schema with the index format above and a
///     UTF-8 `u` or LargeUtf8 `U` value type → routes to
///     `symbol_dict_i*`.
///
/// Other formats return `line_sender_error_invalid_api_call`.
///
/// The array must have `offset == 0` (consolidate slices upstream of
/// this call).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn column_sender_chunk_append_arrow_column(
    chunk: *mut column_sender_chunk,
    name: *const c_char,
    name_len: size_t,
    array: *const ArrowArray,
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
    if array.is_null() || schema.is_null() {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    "ArrowArray and ArrowSchema must be non-NULL".to_string(),
                ),
            );
        }
        return false;
    }
    let array_ref = unsafe { &*array };
    let schema_ref = unsafe { &*schema };
    if !unsafe { arrow_check_offset(array_ref, err_out) } {
        return false;
    }
    if array_ref.length < 0 {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    format!("ArrowArray.length is negative: {}", array_ref.length),
                ),
            );
        }
        return false;
    }
    let array_total_len = array_ref.length as usize;
    if row_offset > array_total_len || row_count > array_total_len - row_offset {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    format!(
                        "slice [{row_offset}, {row_offset}+{row_count}) \
                         out of range for ArrowArray.length={array_total_len}"
                    ),
                ),
            );
        }
        return false;
    }

    let format = match unsafe { arrow_format_str(schema_ref, err_out) } {
        Some(s) => s,
        None => return false,
    };
    let validity = match unsafe { arrow_validity(array_ref, row_offset, row_count, err_out) } {
        Some(v) => v,
        None => return false,
    };

    // Dictionary types dispatch to symbol_dict_*; the outer format is
    // the index width. The dictionary array is shared across chunks;
    // only the per-row codes are sliced by row_offset.
    if !schema_ref.dictionary.is_null() {
        let (dict_offsets, dict_bytes) =
            match unsafe { arrow_dictionary_utf8(schema_ref, array_ref, err_out) } {
                Some(t) => t,
                None => return false,
            };
        match format {
            "c" => {
                let codes_ptr =
                    match unsafe { arrow_buffer::<i8>(array_ref, 1, false, err_out, "dict codes") }
                    {
                        Some(p) => p,
                        None => return false,
                    };
                let codes = unsafe { slice::from_raw_parts(codes_ptr.add(row_offset), row_count) };
                match dict_offsets {
                    ArrowDictionaryOffsets::Utf8(dict_offsets) => bubble!(
                        err_out,
                        chunk.symbol_dict_i8(
                            name,
                            codes,
                            dict_offsets,
                            dict_bytes,
                            validity.as_ref()
                        )
                    ),
                    ArrowDictionaryOffsets::LargeUtf8(dict_offsets) => bubble!(
                        err_out,
                        chunk.symbol_dict_large_i8(
                            name,
                            codes,
                            dict_offsets,
                            dict_bytes,
                            validity.as_ref()
                        )
                    ),
                };
            }
            "s" => {
                let codes_ptr = match unsafe {
                    arrow_buffer::<i16>(array_ref, 1, false, err_out, "dict codes")
                } {
                    Some(p) => p,
                    None => return false,
                };
                let codes = unsafe { slice::from_raw_parts(codes_ptr.add(row_offset), row_count) };
                match dict_offsets {
                    ArrowDictionaryOffsets::Utf8(dict_offsets) => bubble!(
                        err_out,
                        chunk.symbol_dict_i16(
                            name,
                            codes,
                            dict_offsets,
                            dict_bytes,
                            validity.as_ref()
                        )
                    ),
                    ArrowDictionaryOffsets::LargeUtf8(dict_offsets) => bubble!(
                        err_out,
                        chunk.symbol_dict_large_i16(
                            name,
                            codes,
                            dict_offsets,
                            dict_bytes,
                            validity.as_ref()
                        )
                    ),
                };
            }
            "i" => {
                let codes_ptr = match unsafe {
                    arrow_buffer::<i32>(array_ref, 1, false, err_out, "dict codes")
                } {
                    Some(p) => p,
                    None => return false,
                };
                let codes = unsafe { slice::from_raw_parts(codes_ptr.add(row_offset), row_count) };
                match dict_offsets {
                    ArrowDictionaryOffsets::Utf8(dict_offsets) => bubble!(
                        err_out,
                        chunk.symbol_dict_i32(
                            name,
                            codes,
                            dict_offsets,
                            dict_bytes,
                            validity.as_ref()
                        )
                    ),
                    ArrowDictionaryOffsets::LargeUtf8(dict_offsets) => bubble!(
                        err_out,
                        chunk.symbol_dict_large_i32(
                            name,
                            codes,
                            dict_offsets,
                            dict_bytes,
                            validity.as_ref()
                        )
                    ),
                };
            }
            other => {
                unsafe {
                    set_err_out_from_error(
                        err_out,
                        Error::new(
                            ErrorCode::InvalidApiCall,
                            format!(
                                "dictionary index type {other:?} is not \
                                 supported (only c / s / i for now)"
                            ),
                        ),
                    );
                }
                return false;
            }
        }
        return true;
    }

    // Plain (non-dictionary) types. Data lives in buffers[1] for fixed-
    // width primitives; varchar additionally uses buffers[2] for bytes.
    //
    // The Arrow C Data Interface puts a `:`-prefixed parameter (e.g.
    // timezone) only on timestamp / date / time formats. For everything
    // else we exact-match the format string so e.g. a malformed `"u:foo"`
    // doesn't spuriously dispatch to the varchar arm.
    macro_rules! primitive {
        ($ty:ty, $method:ident, $what:literal) => {{
            let ptr = match unsafe { arrow_buffer::<$ty>(array_ref, 1, false, err_out, $what) } {
                Some(p) => p,
                None => return false,
            };
            let data = unsafe { slice::from_raw_parts(ptr.add(row_offset), row_count) };
            bubble!(err_out, chunk.$method(name, data, validity.as_ref()));
        }};
    }
    match format {
        "c" => primitive!(i8, column_i8, "i8 column data"),
        "s" => primitive!(i16, column_i16, "i16 column data"),
        "i" => primitive!(i32, column_i32, "i32 column data"),
        "l" => primitive!(i64, column_i64, "i64 column data"),
        "f" => primitive!(f32, column_f32, "f32 column data"),
        "g" => primitive!(f64, column_f64, "f64 column data"),
        "b" => {
            // Bool bitmap: callers using row_offset on a packed bitmap
            // must align by 8 just like validity. Rust crate's
            // column_bool reads bit-shifted only off the byte boundary.
            if !row_offset.is_multiple_of(8) {
                unsafe {
                    set_err_out_from_error(
                        err_out,
                        Error::new(
                            ErrorCode::InvalidApiCall,
                            format!(
                                "Arrow bool column slice requires row_offset \
                                 to be a multiple of 8 (got {row_offset})."
                            ),
                        ),
                    );
                }
                return false;
            }
            let ptr =
                match unsafe { arrow_buffer::<u8>(array_ref, 1, false, err_out, "bool bitmap") } {
                    Some(p) => p,
                    None => return false,
                };
            let shifted = unsafe { ptr.add(row_offset / 8) };
            let len = row_count.div_ceil(8);
            let bits = unsafe { slice::from_raw_parts(shifted, len) };
            bubble!(
                err_out,
                chunk.column_bool(name, bits, row_count, validity.as_ref())
            );
        }
        // Timestamp formats carry a `:<tz>` (or `:`) suffix per the
        // Arrow C Data Interface. We ignore the timezone — the QWP
        // wire stores absolute instants, and Pandas / Polars give us
        // UTC-normalised values by convention.
        f if f.starts_with("tsn:") => {
            primitive!(i64, column_ts_nanos, "ts_nanos column data")
        }
        f if f.starts_with("tsu:") => {
            primitive!(i64, column_ts_micros, "ts_micros column data")
        }
        "u" => {
            // UTF-8 string column with int32 offsets. buffers[1] = offsets,
            // buffers[2] = bytes. The offsets array has length array.length
            // + 1; slicing means starting at offsets[row_offset] and
            // reading row_count + 1 entries.
            let offsets_ptr = match unsafe {
                arrow_buffer::<i32>(array_ref, 1, false, err_out, "varchar offsets")
            } {
                Some(p) => p,
                None => return false,
            };
            let bytes_ptr =
                match unsafe { arrow_buffer::<u8>(array_ref, 2, true, err_out, "varchar bytes") } {
                    Some(p) => p,
                    None => return false,
                };
            let offsets =
                unsafe { slice::from_raw_parts(offsets_ptr.add(row_offset), row_count + 1) };
            // bytes_len passed to Chunk::column_varchar is the high-water
            // mark of the slice — the Rust encoder reads bytes in the
            // range [offsets[0], offsets[row_count]); pass the full
            // original bytes buffer length so validate_varchar_offsets
            // doesn't complain.
            let bytes_len = if array_total_len == 0 {
                0
            } else {
                // Read original offsets[array_total_len] as the bytes-buffer
                // upper bound. Avoids slicing the bytes; the encoder
                // does its own rebase.
                unsafe { *offsets_ptr.add(array_total_len) as usize }
            };
            let bytes = if bytes_len == 0 || bytes_ptr.is_null() {
                &[][..]
            } else {
                unsafe { slice::from_raw_parts(bytes_ptr, bytes_len) }
            };
            bubble!(
                err_out,
                chunk.column_varchar(name, offsets, bytes, validity.as_ref())
            );
        }
        "U" => {
            // LargeUtf8 column with int64 offsets. Same shape as `u`
            // but offsets are i64.
            let offsets_ptr = match unsafe {
                arrow_buffer::<i64>(array_ref, 1, false, err_out, "large_varchar offsets")
            } {
                Some(p) => p,
                None => return false,
            };
            let bytes_ptr = match unsafe {
                arrow_buffer::<u8>(array_ref, 2, true, err_out, "large_varchar bytes")
            } {
                Some(p) => p,
                None => return false,
            };
            let offsets =
                unsafe { slice::from_raw_parts(offsets_ptr.add(row_offset), row_count + 1) };
            let bytes_len = if array_total_len == 0 {
                0
            } else {
                unsafe { *offsets_ptr.add(array_total_len) as usize }
            };
            let bytes = if bytes_len == 0 || bytes_ptr.is_null() {
                &[][..]
            } else {
                unsafe { slice::from_raw_parts(bytes_ptr, bytes_len) }
            };
            bubble!(
                err_out,
                chunk.column_varchar_large(name, offsets, bytes, validity.as_ref())
            );
        }
        other => {
            unsafe {
                set_err_out_from_error(
                    err_out,
                    Error::new(
                        ErrorCode::InvalidApiCall,
                        format!(
                            "Arrow column format {other:?} (full: {format:?}) \
                             is not yet supported by \
                             column_sender_chunk_append_arrow_column"
                        ),
                    ),
                );
            }
            return false;
        }
    }
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

/// NumPy source dtype, mirrored to the C ABI as `int32` values. Keep
/// in sync with the Cython `cdef enum column_sender_numpy_dtype` and
/// the Rust [`NumpyDtype`] enum (see `Chunk::column_numpy` for the
/// widening / packing rules).
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
}

impl From<column_sender_numpy_dtype> for NumpyDtype {
    fn from(value: column_sender_numpy_dtype) -> Self {
        match value {
            column_sender_numpy_dtype::column_sender_numpy_i8 => NumpyDtype::I8,
            column_sender_numpy_dtype::column_sender_numpy_i16 => NumpyDtype::I16,
            column_sender_numpy_dtype::column_sender_numpy_i32 => NumpyDtype::I32,
            column_sender_numpy_dtype::column_sender_numpy_i64 => NumpyDtype::I64,
            column_sender_numpy_dtype::column_sender_numpy_u8 => NumpyDtype::U8,
            column_sender_numpy_dtype::column_sender_numpy_u16 => NumpyDtype::U16,
            column_sender_numpy_dtype::column_sender_numpy_u32 => NumpyDtype::U32,
            column_sender_numpy_dtype::column_sender_numpy_u64 => NumpyDtype::U64,
            column_sender_numpy_dtype::column_sender_numpy_f32 => NumpyDtype::F32,
            column_sender_numpy_dtype::column_sender_numpy_f64 => NumpyDtype::F64,
            column_sender_numpy_dtype::column_sender_numpy_bool => NumpyDtype::Bool,
        }
    }
}

/// Append one column from a contiguous, native-endian NumPy buffer.
/// Widening (narrower int / float → wire type) and NumPy bool packing
/// (byte-per-row → LSB-bitmap) happen inside Rust at append time; the
/// caller's `data` buffer is read once and not retained.
///
/// `data` must point to at least `row_count * sizeof(dtype)` bytes
/// (for `column_sender_numpy_bool`: `row_count` bytes, one byte per
/// row, NumPy native layout). Strided / non-native-endian arrays are
/// rejected by convention — the caller consolidates upstream.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn column_sender_chunk_append_numpy_column(
    chunk: *mut column_sender_chunk,
    name: *const c_char,
    name_len: size_t,
    dtype: column_sender_numpy_dtype,
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
    let validity = match unsafe { as_validity(validity, err_out) } {
        Some(v) => v,
        None => return false,
    };
    let dtype: NumpyDtype = dtype.into();
    bubble!(err_out, unsafe {
        chunk.column_numpy(name, dtype, data, row_count, validity.as_ref())
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
        let array = ArrowArray {
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
                &array,
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
