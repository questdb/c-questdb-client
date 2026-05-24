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
//! (`questdb_db`, `column_sender`, `column_sender_chunk`) are heap-allocated
//! and freed through their dedicated `_close` / `_free` / `_return_sender`
//! entry points.

use libc::{c_char, size_t};
use std::slice;
use std::str;

use questdb::ingress::column_sender::{AckLevel, Chunk, OwnedSender, QuestDb, Validity};
use questdb::{Error, ErrorCode};

use crate::{line_sender_error, set_err_out_from_error};

// ===========================================================================
// Opaque handles
// ===========================================================================

/// Connection pool. Thread-safe; share across threads.
pub struct questdb_db(QuestDb);

/// Borrowed sender. Owns a pool slot until `questdb_db_return_sender` is
/// called. Not thread-safe.
pub struct column_sender(OwnedSender);

/// One DataFrame's worth of column buffers destined for one QuestDB table.
/// Owned by the caller; not bound to a sender.
pub struct column_sender_chunk(Chunk);

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
/// Outstanding `column_sender` handles remain valid (they hold an
/// internal reference to the pool's state) and return themselves on
/// `questdb_db_return_sender`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_db_close(db: *mut questdb_db) {
    if !db.is_null() {
        unsafe { drop(Box::from_raw(db)) };
    }
}

/// Borrow a sender from the pool. See
/// `doc/COLUMN_SENDER_FFI_ABI.md` §4.3 for the selection rules. Returns
/// NULL on failure; sets `*err_out` if provided.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_db_borrow_sender(
    db: *mut questdb_db,
    err_out: *mut *mut line_sender_error,
) -> *mut column_sender {
    if db.is_null() {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    "questdb_db_borrow_sender: db pointer is NULL".to_string(),
                ),
            );
        }
        return std::ptr::null_mut();
    }
    let db_ref = unsafe { &*db };
    match db_ref.0.borrow_sender_owned() {
        Ok(owned) => Box::into_raw(Box::new(column_sender(owned))),
        Err(err) => {
            unsafe { set_err_out_from_error(err_out, err) };
            std::ptr::null_mut()
        }
    }
}

/// Return a borrowed sender to the pool. Invalidates `sender`. Accepts
/// NULL `sender` and no-ops. `db` is ignored — the sender carries its
/// own reference to the pool — but kept in the ABI for symmetry with the
/// borrow call and to allow future runtime checks.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_db_return_sender(
    _db: *mut questdb_db,
    sender: *mut column_sender,
) {
    if !sender.is_null() {
        unsafe { drop(Box::from_raw(sender)) };
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
// Sender state
// ===========================================================================

/// `true` if the sender's underlying connection is in a permanently-
/// unusable state.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn column_sender_must_close(sender: *const column_sender) -> bool {
    if sender.is_null() {
        return true;
    }
    unsafe { (*sender).0.get().must_close() }
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

/// Encode `chunk` into a QWP/WebSocket frame, publish it, and block
/// until the server acknowledges at the requested `ack_level`.
///
/// On success, `chunk` is cleared and the call returns `true`. On
/// failure, `chunk` is left untouched and `false` is returned (with
/// `*err_out` set if provided).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn column_sender_flush(
    sender: *mut column_sender,
    chunk: *mut column_sender_chunk,
    ack_level: column_sender_ack_level,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let sender = match unsafe { sender.as_mut() } {
        Some(s) => s.0.get_mut(),
        None => {
            unsafe {
                set_err_out_from_error(
                    err_out,
                    Error::new(
                        ErrorCode::InvalidApiCall,
                        "column_sender_flush: sender pointer is NULL".to_string(),
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
    bubble!(err_out, sender.flush(chunk, ack_level.into()));
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
