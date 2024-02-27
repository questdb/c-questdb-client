/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2024 QuestDB
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

#![allow(non_camel_case_types, clippy::missing_safety_doc)]

use libc::{c_char, size_t};
use std::ascii;
use std::boxed::Box;
use std::convert::{From, Into};
use std::path::PathBuf;
use std::ptr;
use std::slice;
use std::str;

use questdb::{
    ingress::{
        Buffer, CertificateAuthority, ColumnName, Sender, SenderBuilder, TableName,
        TimestampMicros, TimestampNanos,
    },
    Error, ErrorCode,
};

macro_rules! bubble_err_to_c {
    ($err_out:expr, $expression:expr) => {
        bubble_err_to_c!($err_out, $expression, false)
    };
    ($err_out:expr, $expression:expr, $sentinel:expr) => {
        match $expression {
            Ok(value) => value,
            Err(err) => {
                let err_ptr = Box::into_raw(Box::new(line_sender_error(err)));
                *$err_out = err_ptr;
                return $sentinel;
            }
        }
    };
}

/*

    // This is square-peg-round-hole code.
    // The C API is not designed to handle Rust's ownership semantics.
    // So we're going to do some very unsafe things here.
    // We need to extract a `T` from a `*mut T` and then replace it with
    // another `T` in situ.
    let dest = &mut (*opts).0;
    let forced_builder = ptr::read(&(*opts).0);
    let new_builder = match forced_builder.tls_roots(path) {
        Ok(builder) => builder,
        Err(err) => {
            let err_ptr = Box::into_raw(Box::new(line_sender_error(err)));
            *err_out = err_ptr;

            // We're really messing the borrow-checker here.
            // We've moved ownership of `forced_builder` (which is actually
            // just an alias of the real `SenderBuilder` owned by the caller
            // via a pointer - but the Rust compiler doesn't know that)
            // into `tls_roots`.
            // This leaves the original caller holding a pointer to an
            // already cleaned up object.
            // To avoid double-freeing, we need to construct a valid "dummy"
            // object on top of the memory that is still owned by the caller.
            let dummy = SenderBuilder::new_tcp("localhost", 1);
            ptr::write(dest, dummy);
            return false;
        }
    };
    ptr::write(dest, new_builder);
    true

*/

/// Update the Rust builder inside the C opts object
/// after calling a method that takes ownership of the builder.
macro_rules! upd_opts {
    // This is square-peg-round-hole code.
    // The C API is not designed to handle Rust's move semantics.
    // So we're going to do some very unsafe things here.
    // We need to extract a `T` from a `*mut T` and then replace it with
    // another `T` in situ.
    ($opts:expr, $err_out:expr, $func:ident $(, $($args:expr),*)?) => {
        {
            let builder_ref: *mut SenderBuilder = &mut (*$opts).0;
            let forced_builder = ptr::read(&(*$opts).0);
            let new_builder_or_err = forced_builder.$func($($($args),*)?);
            let new_builder = match new_builder_or_err {
                Ok(builder) => builder,
                Err(err) => {
                    *$err_out = Box::into_raw(Box::new(line_sender_error(err)));
                    // We're really messing the borrow-checker here.
                    // We've moved ownership of `forced_builder` (which is actually
                    // just an alias of the real `SenderBuilder` owned by the caller
                    // via a pointer - but the Rust compiler doesn't know that)
                    // into `tls_roots`.
                    // This leaves the original caller holding a pointer to an
                    // already cleaned up object.
                    // To avoid double-freeing, we need to construct a valid "dummy"
                    // object on top of the memory that is still owned by the caller.
                    let dummy = SenderBuilder::new_tcp("localhost", 1);
                    ptr::write(builder_ref, dummy);
                    return false;
                }
            };

            // Overwrite the original builder with the new one.
            ptr::write(builder_ref, new_builder);
            true
        }
    };
}

/// An error that occurred when using the line sender.
pub struct line_sender_error(Error);

/// Category of error.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum line_sender_error_code {
    /// The host, port, or interface was incorrect.
    line_sender_error_could_not_resolve_addr,

    /// Called methods in the wrong order. E.g. `symbol` after `column`.
    line_sender_error_invalid_api_call,

    /// A network error connecting or flushing data out.
    line_sender_error_socket_error,

    /// The string or symbol field is not encoded in valid UTF-8.
    line_sender_error_invalid_utf8,

    /// The table name or column name contains bad characters.
    line_sender_error_invalid_name,

    /// The supplied timestamp is invalid.
    line_sender_error_invalid_timestamp,

    /// Error during the authentication process.
    line_sender_error_auth_error,

    /// Error during TLS handshake.
    line_sender_error_tls_error,

    /// The server does not support ILP over HTTP.
    line_sender_error_http_not_supported,

    /// Error sent back from the server during flush.
    line_sender_error_server_flush_error,

    /// Bad configuration.
    line_sender_error_config_error,
}

impl From<ErrorCode> for line_sender_error_code {
    fn from(code: ErrorCode) -> Self {
        match code {
            ErrorCode::CouldNotResolveAddr => {
                line_sender_error_code::line_sender_error_could_not_resolve_addr
            }
            ErrorCode::InvalidApiCall => line_sender_error_code::line_sender_error_invalid_api_call,
            ErrorCode::SocketError => line_sender_error_code::line_sender_error_socket_error,
            ErrorCode::InvalidUtf8 => line_sender_error_code::line_sender_error_invalid_utf8,
            ErrorCode::InvalidName => line_sender_error_code::line_sender_error_invalid_name,
            ErrorCode::InvalidTimestamp => {
                line_sender_error_code::line_sender_error_invalid_timestamp
            }
            ErrorCode::AuthError => line_sender_error_code::line_sender_error_auth_error,
            ErrorCode::TlsError => line_sender_error_code::line_sender_error_tls_error,
            ErrorCode::HttpNotSupported => {
                line_sender_error_code::line_sender_error_http_not_supported
            }
            ErrorCode::ServerFlushError => {
                line_sender_error_code::line_sender_error_server_flush_error
            }
            ErrorCode::ConfigError => line_sender_error_code::line_sender_error_config_error,
        }
    }
}

/// Certificate authority used to determine how to validate the server's TLS certificate.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum line_sender_ca {
    /// Use the set of root certificates provided by the `webpki` crate.
    line_sender_ca_webpki_roots,

    /// Use the set of root certificates provided by the operating system.
    line_sender_ca_os_roots,

    /// Use the set of root certificates provided by both the `webpki` crate and the operating system.
    line_sender_ca_webpki_and_os_roots,

    /// Use a custom root certificate `.pem` file.
    line_sender_ca_pem_file,
}

impl From<CertificateAuthority> for line_sender_ca {
    fn from(ca: CertificateAuthority) -> Self {
        match ca {
            CertificateAuthority::WebpkiRoots => line_sender_ca::line_sender_ca_webpki_roots,
            CertificateAuthority::OsRoots => line_sender_ca::line_sender_ca_os_roots,
            CertificateAuthority::WebpkiAndOsRoots => {
                line_sender_ca::line_sender_ca_webpki_and_os_roots
            }
            CertificateAuthority::PemFile => line_sender_ca::line_sender_ca_pem_file,
        }
    }
}

impl From<line_sender_ca> for CertificateAuthority {
    fn from(ca: line_sender_ca) -> Self {
        match ca {
            line_sender_ca::line_sender_ca_webpki_roots => CertificateAuthority::WebpkiRoots,
            line_sender_ca::line_sender_ca_os_roots => CertificateAuthority::OsRoots,
            line_sender_ca::line_sender_ca_webpki_and_os_roots => {
                CertificateAuthority::WebpkiAndOsRoots
            }
            line_sender_ca::line_sender_ca_pem_file => CertificateAuthority::PemFile,
        }
    }
}

/** Error code categorizing the error. */
#[no_mangle]
pub unsafe extern "C" fn line_sender_error_get_code(
    error: *const line_sender_error,
) -> line_sender_error_code {
    (*error).0.code().into()
}

/// UTF-8 encoded error message. Never returns NULL.
/// The `len_out` argument is set to the number of bytes in the string.
/// The string is NOT null-terminated.
#[no_mangle]
pub unsafe extern "C" fn line_sender_error_msg(
    error: *const line_sender_error,
    len_out: *mut size_t,
) -> *const c_char {
    let msg: &str = (*error).0.msg();
    *len_out = msg.len();
    msg.as_ptr() as *mut c_char
}

/// Clean up the error.
#[no_mangle]
pub unsafe extern "C" fn line_sender_error_free(error: *mut line_sender_error) {
    if !error.is_null() {
        drop(Box::from_raw(error));
    }
}

/// Non-owning validated UTF-8 encoded string.
/// The string need not be null-terminated.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct line_sender_utf8 {
    /// Don't initialize fields directly.
    /// Call `line_sender_utf8_init` instead.
    len: size_t,
    buf: *const c_char,
}

impl line_sender_utf8 {
    fn as_str(&self) -> &str {
        unsafe { str::from_utf8_unchecked(slice::from_raw_parts(self.buf as *const u8, self.len)) }
    }
}

/// An ASCII-safe description of a binary buffer. Trimmed if too long.
fn describe_buf(buf: &[u8]) -> String {
    let max_len = 100usize;
    let trim = buf.len() >= max_len;
    let working_len = if trim {
        max_len - 3 // 3 here for trailing "..."
    } else {
        buf.len()
    };
    let sliced = &buf[0..working_len];
    // If every byte needs escaping we'll need to 4 times as many bytes,
    // + 1 for trailing \0 added by printf functions.
    let mut output = String::with_capacity(working_len * 4 + 1);

    for &c in sliced.iter() {
        for esc in ascii::escape_default(c) {
            output.push(esc as char);
        }
    }

    if trim {
        output.push_str("...");
    }

    output
}

unsafe fn set_err_out(err_out: *mut *mut line_sender_error, code: ErrorCode, msg: String) {
    let err = line_sender_error(Error::new(code, msg));
    let err_ptr = Box::into_raw(Box::new(err));
    *err_out = err_ptr;
}

unsafe fn unwrap_utf8_or_str(buf: &[u8]) -> Result<&str, String> {
    match str::from_utf8(buf) {
        Ok(str_ref) => Ok(str_ref),
        Err(u8err) => {
            let buf_descr = describe_buf(buf);
            let msg = if let Some(_err_len) = u8err.error_len() {
                format!(
                    concat!(
                        "Bad string \"{}\": Invalid UTF-8. ",
                        "Illegal codepoint starting at byte index {}."
                    ),
                    buf_descr,
                    u8err.valid_up_to()
                )
            } else {
                // needs more input
                format!(
                    concat!(
                        "Bad string \"{}\": Invalid UTF-8. Incomplete ",
                        "multi-byte codepoint at end of string. ",
                        "Bad codepoint starting at byte index {}."
                    ),
                    buf_descr,
                    u8err.valid_up_to()
                )
            };
            Err(msg)
        }
    }
}

unsafe fn unwrap_utf8(buf: &[u8], err_out: *mut *mut line_sender_error) -> Option<&str> {
    match unwrap_utf8_or_str(buf) {
        Ok(str_ref) => Some(str_ref),
        Err(msg) => {
            set_err_out(err_out, ErrorCode::InvalidUtf8, msg);
            None
        }
    }
}

/// Check the provided buffer is a valid UTF-8 encoded string.
///
/// @param[out] str The object to be initialized.
/// @param[in] len Length in bytes of the buffer.
/// @param[in] buf UTF-8 encoded buffer. Need not be null-terminated.
/// @param[out] err_out Set on error.
/// @return true on success, false on error.
#[no_mangle]
pub unsafe extern "C" fn line_sender_utf8_init(
    string: *mut line_sender_utf8,
    len: size_t,
    buf: *const c_char,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let slice = slice::from_raw_parts(buf as *const u8, len);
    if let Some(str_ref) = unwrap_utf8(slice, err_out) {
        (*string).len = str_ref.len();
        (*string).buf = str_ref.as_ptr() as *const c_char;
        true
    } else {
        false
    }
}

#[no_mangle]
pub unsafe extern "C" fn line_sender_utf8_assert(
    len: size_t,
    buf: *const c_char,
) -> line_sender_utf8 {
    let slice = slice::from_raw_parts(buf as *const u8, len);
    match unwrap_utf8_or_str(slice) {
        Ok(str_ref) => line_sender_utf8 {
            len: str_ref.len(),
            buf: str_ref.as_ptr() as *const c_char,
        },
        Err(msg) => {
            panic!("{}", msg);
        }
    }
}

/// Non-owning validated table name. UTF-8 encoded.
/// Need not be null-terminated.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct line_sender_table_name {
    /// Don't initialize fields directly.
    /// Call `line_sender_table_name_init` instead.
    len: size_t,
    buf: *const c_char,
}

impl line_sender_table_name {
    unsafe fn as_name<'a>(&self) -> TableName<'a> {
        let str_name =
            str::from_utf8_unchecked(slice::from_raw_parts(self.buf as *const u8, self.len));
        TableName::new_unchecked(str_name)
    }
}

/// Non-owning validated symbol or column name. UTF-8 encoded.
/// Need not be null-terminated.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct line_sender_column_name {
    /// Don't initialize fields directly.
    /// Call `line_sender_column_name_init` instead.
    len: size_t,
    buf: *const c_char,
}

impl line_sender_column_name {
    unsafe fn as_name<'a>(&self) -> ColumnName<'a> {
        let str_name =
            str::from_utf8_unchecked(slice::from_raw_parts(self.buf as *const u8, self.len));
        ColumnName::new_unchecked(str_name)
    }
}

/// Check the provided buffer is a valid UTF-8 encoded string that can be
/// used as a table name.
///
/// @param[out] name The object to be initialized.
/// @param[in] len Length in bytes of the buffer.
/// @param[in] buf UTF-8 encoded buffer. Need not be null-terminated.
/// @param[out] err_out Set on error.
/// @return true on success, false on error.
#[no_mangle]
pub unsafe extern "C" fn line_sender_table_name_init(
    name: *mut line_sender_table_name,
    len: size_t,
    buf: *const c_char,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let mut u8str = line_sender_utf8 {
        len: 0usize,
        buf: ptr::null_mut(),
    };
    if !line_sender_utf8_init(&mut u8str, len, buf, err_out) {
        return false;
    }

    let str_name = str::from_utf8_unchecked(slice::from_raw_parts(buf as *const u8, len));

    bubble_err_to_c!(err_out, TableName::new(str_name));

    (*name).len = len;
    (*name).buf = buf;
    true
}

#[no_mangle]
pub unsafe extern "C" fn line_sender_table_name_assert(
    len: size_t,
    buf: *const c_char,
) -> line_sender_table_name {
    let u8str = line_sender_utf8_assert(len, buf);
    match TableName::new(u8str.as_str()) {
        Ok(_) => line_sender_table_name { len, buf },
        Err(msg) => {
            panic!("{}", msg);
        }
    }
}

/// Check the provided buffer is a valid UTF-8 encoded string that can be
/// used as a symbol or column name.
///
/// @param[out] name The object to be initialized.
/// @param[in] len Length in bytes of the buffer.
/// @param[in] buf UTF-8 encoded buffer. Need not be null-terminated.
/// @param[out] err_out Set on error.
/// @return true on success, false on error.
#[no_mangle]
pub unsafe extern "C" fn line_sender_column_name_init(
    name: *mut line_sender_column_name,
    len: size_t,
    buf: *const c_char,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let mut u8str = line_sender_utf8 {
        len: 0usize,
        buf: ptr::null_mut(),
    };
    if !line_sender_utf8_init(&mut u8str, len, buf, err_out) {
        return false;
    }

    let str_name = str::from_utf8_unchecked(slice::from_raw_parts(buf as *const u8, len));

    bubble_err_to_c!(err_out, ColumnName::new(str_name));

    (*name).len = len;
    (*name).buf = buf;
    true
}

#[no_mangle]
pub unsafe extern "C" fn line_sender_column_name_assert(
    len: size_t,
    buf: *const c_char,
) -> line_sender_table_name {
    let u8str = line_sender_utf8_assert(len, buf);
    match ColumnName::new(u8str.as_str()) {
        Ok(_) => line_sender_table_name { len, buf },
        Err(msg) => {
            panic!("{}", msg);
        }
    }
}

/// Prepare rows for sending via the line sender's `flush` function.
/// Buffer objects are re-usable and cleared automatically when flushing.
pub struct line_sender_buffer(Buffer);

/// Create a buffer for serializing ILP messages.
#[no_mangle]
pub unsafe extern "C" fn line_sender_buffer_new() -> *mut line_sender_buffer {
    let buffer = Buffer::new();
    Box::into_raw(Box::new(line_sender_buffer(buffer)))
}

/// Create a buffer for serializing ILP messages.
#[no_mangle]
pub unsafe extern "C" fn line_sender_buffer_with_max_name_len(
    max_name_len: size_t,
) -> *mut line_sender_buffer {
    let buffer = Buffer::with_max_name_len(max_name_len);
    Box::into_raw(Box::new(line_sender_buffer(buffer)))
}

/// Release the buffer object.
#[no_mangle]
pub unsafe extern "C" fn line_sender_buffer_free(buffer: *mut line_sender_buffer) {
    if !buffer.is_null() {
        drop(Box::from_raw(buffer));
    }
}

unsafe fn unwrap_buffer<'a>(buffer: *const line_sender_buffer) -> &'a Buffer {
    &(*buffer).0
}

unsafe fn unwrap_buffer_mut<'a>(buffer: *mut line_sender_buffer) -> &'a mut Buffer {
    &mut (*buffer).0
}

/// Create a new copy of the buffer.
#[no_mangle]
pub unsafe extern "C" fn line_sender_buffer_clone(
    buffer: *const line_sender_buffer,
) -> *mut line_sender_buffer {
    let new_buffer = unwrap_buffer(buffer).clone();
    Box::into_raw(Box::new(line_sender_buffer(new_buffer)))
}

/// Pre-allocate to ensure the buffer has enough capacity for at least the
/// specified additional byte count. This may be rounded up.
/// See: `capacity`.
#[no_mangle]
pub unsafe extern "C" fn line_sender_buffer_reserve(
    buffer: *mut line_sender_buffer,
    additional: size_t,
) {
    let buffer = unwrap_buffer_mut(buffer);
    buffer.reserve(additional);
}

/// Get the current capacity of the buffer.
#[no_mangle]
pub unsafe extern "C" fn line_sender_buffer_capacity(buffer: *const line_sender_buffer) -> size_t {
    unwrap_buffer(buffer).capacity()
}

/// Mark a rewind point.
/// This allows undoing accumulated changes to the buffer for one or more
/// rows by calling `rewind_to_marker`.
/// Any previous marker will be discarded.
/// Once the marker is no longer needed, call `clear_marker`.
#[no_mangle]
pub unsafe extern "C" fn line_sender_buffer_set_marker(
    buffer: *mut line_sender_buffer,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let buffer = unwrap_buffer_mut(buffer);
    bubble_err_to_c!(err_out, buffer.set_marker());
    true
}

/// Undo all changes since the last `set_marker` call.
/// As a side-effect, this also clears the marker.
#[no_mangle]
pub unsafe extern "C" fn line_sender_buffer_rewind_to_marker(
    buffer: *mut line_sender_buffer,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let buffer = unwrap_buffer_mut(buffer);
    bubble_err_to_c!(err_out, buffer.rewind_to_marker());
    true
}

/// Discard the marker.
#[no_mangle]
pub unsafe extern "C" fn line_sender_buffer_clear_marker(buffer: *mut line_sender_buffer) {
    let buffer = unwrap_buffer_mut(buffer);
    buffer.clear_marker();
}

/// Remove all accumulated data and prepare the buffer for new lines.
/// This does not affect the buffer's capacity.
#[no_mangle]
pub unsafe extern "C" fn line_sender_buffer_clear(buffer: *mut line_sender_buffer) {
    let buffer = unwrap_buffer_mut(buffer);
    buffer.clear();
}

/// Number of bytes in the accumulated buffer.
#[no_mangle]
pub unsafe extern "C" fn line_sender_buffer_size(buffer: *const line_sender_buffer) -> size_t {
    let buffer = unwrap_buffer(buffer);
    buffer.len()
}

/// The number of rows accumulated in the buffer.
#[no_mangle]
pub unsafe extern "C" fn line_sender_buffer_row_count(buffer: *const line_sender_buffer) -> size_t {
    let buffer = unwrap_buffer(buffer);
    buffer.row_count()
}

/// The buffer is transactional if sent over HTTP.
/// A buffer stops being transactional if it contains rows for multiple tables.
#[no_mangle]
pub unsafe extern "C" fn line_sender_buffer_transactional(
    buffer: *const line_sender_buffer,
) -> bool {
    let buffer = unwrap_buffer(buffer);
    buffer.transactional()
}

/// Peek into the accumulated buffer that is to be sent out at the next `flush`.
///
/// @param[in] buffer Line buffer object.
/// @param[out] len_out The length in bytes of the accumulated buffer.
/// @return UTF-8 encoded buffer. The buffer is not nul-terminated.
#[no_mangle]
pub unsafe extern "C" fn line_sender_buffer_peek(
    buffer: *const line_sender_buffer,
    len_out: *mut size_t,
) -> *const c_char {
    let buffer = unwrap_buffer(buffer);
    let buf: &[u8] = buffer.as_str().as_bytes();
    *len_out = buf.len();
    buf.as_ptr() as *const c_char
}

/// Start batching the next row of input for the named table.
/// @param[in] buffer Line buffer object.
/// @param[in] name Table name.
#[no_mangle]
pub unsafe extern "C" fn line_sender_buffer_table(
    buffer: *mut line_sender_buffer,
    name: line_sender_table_name,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let buffer = unwrap_buffer_mut(buffer);
    bubble_err_to_c!(err_out, buffer.table(name.as_name()));
    true
}

/// Append a value for a SYMBOL column.
/// Symbol columns must always be written before other columns for any given
/// row.
/// @param[in] buffer Line buffer object.
/// @param[in] name Column name.
/// @param[in] value Column value.
/// @param[out] err_out Set on error.
/// @return true on success, false on error.
#[no_mangle]
pub unsafe extern "C" fn line_sender_buffer_symbol(
    buffer: *mut line_sender_buffer,
    name: line_sender_column_name,
    value: line_sender_utf8,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let buffer = unwrap_buffer_mut(buffer);
    bubble_err_to_c!(err_out, buffer.symbol(name.as_name(), value.as_str()));
    true
}

/// Append a value for a BOOLEAN column.
/// @param[in] buffer Line buffer object.
/// @param[in] name Column name.
/// @param[in] value Column value.
/// @param[out] err_out Set on error.
/// @return true on success, false on error.
#[no_mangle]
pub unsafe extern "C" fn line_sender_buffer_column_bool(
    buffer: *mut line_sender_buffer,
    name: line_sender_column_name,
    value: bool,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let buffer = unwrap_buffer_mut(buffer);
    bubble_err_to_c!(err_out, buffer.column_bool(name.as_name(), value));
    true
}

/// Append a value for a LONG column.
/// @param[in] buffer Line buffer object.
/// @param[in] name Column name.
/// @param[in] value Column value.
/// @param[out] err_out Set on error.
/// @return true on success, false on error.
#[no_mangle]
pub unsafe extern "C" fn line_sender_buffer_column_i64(
    buffer: *mut line_sender_buffer,
    name: line_sender_column_name,
    value: i64,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let buffer = unwrap_buffer_mut(buffer);
    bubble_err_to_c!(err_out, buffer.column_i64(name.as_name(), value));
    true
}

/// Append a value for a DOUBLE column.
/// @param[in] buffer Line buffer object.
/// @param[in] name Column name.
/// @param[in] value Column value.
/// @param[out] err_out Set on error.
/// @return true on success, false on error.
#[no_mangle]
pub unsafe extern "C" fn line_sender_buffer_column_f64(
    buffer: *mut line_sender_buffer,
    name: line_sender_column_name,
    value: f64,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let buffer = unwrap_buffer_mut(buffer);
    bubble_err_to_c!(err_out, buffer.column_f64(name.as_name(), value));
    true
}

/// Append a value for a STRING column.
/// @param[in] buffer Line buffer object.
/// @param[in] name Column name.
/// @param[in] value Column value.
/// @param[out] err_out Set on error.
/// @return true on success, false on error.
#[no_mangle]
pub unsafe extern "C" fn line_sender_buffer_column_str(
    buffer: *mut line_sender_buffer,
    name: line_sender_column_name,
    value: line_sender_utf8,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let buffer = unwrap_buffer_mut(buffer);
    let name = name.as_name();
    let value = value.as_str();
    bubble_err_to_c!(err_out, buffer.column_str(name, value));
    true
}

/// Append a value for a TIMESTAMP column from nanoseconds.
/// @param[in] buffer Line buffer object.
/// @param[in] name Column name.
/// @param[in] nanos The timestamp in nanoseconds before or since the unix epoch.
/// @param[out] err_out Set on error.
/// @return true on success, false on error.
#[no_mangle]
pub unsafe extern "C" fn line_sender_buffer_column_ts_nanos(
    buffer: *mut line_sender_buffer,
    name: line_sender_column_name,
    nanos: i64,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let buffer = unwrap_buffer_mut(buffer);
    let timestamp = TimestampNanos::new(nanos);
    bubble_err_to_c!(err_out, buffer.column_ts(name.as_name(), timestamp));
    true
}

/// Append a value for a TIMESTAMP column from microseconds.
/// @param[in] buffer Line buffer object.
/// @param[in] name Column name.
/// @param[in] micros The timestamp in microseconds before or since the unix epoch.
/// @param[out] err_out Set on error.
/// @return true on success, false on error.
#[no_mangle]
pub unsafe extern "C" fn line_sender_buffer_column_ts_micros(
    buffer: *mut line_sender_buffer,
    name: line_sender_column_name,
    micros: i64,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let buffer = unwrap_buffer_mut(buffer);
    let timestamp = TimestampMicros::new(micros);
    bubble_err_to_c!(err_out, buffer.column_ts(name.as_name(), timestamp));
    true
}

/// Complete the row with a timestamp specified as nanoseconds.
///
/// After this call, you can start batching the next row by calling
/// `table` again, or you can send the accumulated batch by
/// calling `flush`.
///
/// @param[in] buffer Line buffer object.
/// @param[in] epoch_nanos Number of nanoseconds since 1st Jan 1970 UTC.
/// @param[out] err_out Set on error.
/// @return true on success, false on error.
#[no_mangle]
pub unsafe extern "C" fn line_sender_buffer_at_nanos(
    buffer: *mut line_sender_buffer,
    epoch_nanos: i64,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let buffer = unwrap_buffer_mut(buffer);
    let timestamp = TimestampNanos::new(epoch_nanos);
    bubble_err_to_c!(err_out, buffer.at(timestamp));
    true
}

/// Complete the row with a timestamp specified as microseconds.
///
/// After this call, you can start batching the next row by calling
/// `table` again, or you can send the accumulated batch by
/// calling `flush`.
///
/// @param[in] buffer Line buffer object.
/// @param[in] epoch_micros Number of microseconds since 1st Jan 1970 UTC.
/// @param[out] err_out Set on error.
/// @return true on success, false on error.
#[no_mangle]
pub unsafe extern "C" fn line_sender_buffer_at_micros(
    buffer: *mut line_sender_buffer,
    epoch_micros: i64,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let buffer = unwrap_buffer_mut(buffer);
    let timestamp = TimestampMicros::new(epoch_micros);
    bubble_err_to_c!(err_out, buffer.at(timestamp));
    true
}

/// Complete the row without providing a timestamp.
/// The QuestDB instance will insert its own timestamp.
///
/// After this call, you can start batching the next row by calling
/// `table` again, or you can send the accumulated batch by
/// calling `flush`.
///
/// @param[in] buffer Line buffer object.
/// @param[out] err_out Set on error.
/// @return true on success, false on error.
#[no_mangle]
pub unsafe extern "C" fn line_sender_buffer_at_now(
    buffer: *mut line_sender_buffer,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let buffer = unwrap_buffer_mut(buffer);
    bubble_err_to_c!(err_out, buffer.at_now());
    true
}

/// Accumulates parameters for creating a line sender connection.
pub struct line_sender_opts(SenderBuilder);

/// Create a new `ops` instance from configuration string.
/// The format of the string is: "tcp::addr=host:port;ket=value;...;"
/// Alongside "tcp" you can also specify "tcps", "http", and "https".
/// The accepted set of keys and values is the same as for the opt's API.
/// E.g. "tcp::addr=host:port;user=alice;password=secret;tls_ca=os_roots;"
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_from_conf(
    config: line_sender_utf8,
    err_out: *mut *mut line_sender_error,
) -> *mut line_sender_opts {
    let config = config.as_str();
    let builder = bubble_err_to_c!(err_out, SenderBuilder::from_conf(config), ptr::null_mut());
    Box::into_raw(Box::new(line_sender_opts(builder)))
}

/// Create a new `ops` instance from configuration string read from the
/// `QDB_CLIENT_CONF` environment variable.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_from_env(
    err_out: *mut *mut line_sender_error,
) -> *mut line_sender_opts {
    let builder = bubble_err_to_c!(err_out, SenderBuilder::from_env(), ptr::null_mut());
    Box::into_raw(Box::new(line_sender_opts(builder)))
}

/// A new set of options for a line sender connection for ILP/TCP.
/// @param[in] host The QuestDB database host.
/// @param[in] port The QuestDB ILP TCP port.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_new_tcp(
    host: line_sender_utf8,
    port: u16,
) -> *mut line_sender_opts {
    let builder = SenderBuilder::new_tcp(host.as_str(), port);
    Box::into_raw(Box::new(line_sender_opts(builder)))
}

/// Variant of line_sender_opts_new_tcp that takes a service name for port.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_new_tcp_service(
    host: line_sender_utf8,
    port: line_sender_utf8,
) -> *mut line_sender_opts {
    let builder = SenderBuilder::new_tcp(host.as_str(), port.as_str());
    Box::into_raw(Box::new(line_sender_opts(builder)))
}

/// A new set of options for a line sender connection for ILP/HTTP.
/// @param[in] host The QuestDB database host.
/// @param[in] port The QuestDB HTTP port.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_new_http(
    host: line_sender_utf8,
    port: u16,
) -> *mut line_sender_opts {
    let builder = SenderBuilder::new_http(host.as_str(), port);
    Box::into_raw(Box::new(line_sender_opts(builder)))
}

/// Variant of line_sender_opts_new_http that takes a service name for port.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_new_http_service(
    host: line_sender_utf8,
    port: line_sender_utf8,
) -> *mut line_sender_opts {
    let builder = SenderBuilder::new_http(host.as_str(), port.as_str());
    Box::into_raw(Box::new(line_sender_opts(builder)))
}

/// Select local outbound network "bind" interface.
///
/// This may be relevant if your machine has multiple network interfaces.
///
/// The default is `0.0.0.0``.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_bind_interface(
    opts: *mut line_sender_opts,
    bind_interface: line_sender_utf8,
    err_out: *mut *mut line_sender_error,
) -> bool {
    upd_opts!(opts, err_out, bind_interface, bind_interface.as_str())
}

/// Set the username for authentication.
///
/// For TCP this is the `kid` part of the ECDSA key set.
/// The other fields are `token` `token_x` and `token_y`.
///
/// For HTTP this is part of basic authentication.
/// Also see `pass`.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_user(
    opts: *mut line_sender_opts,
    user: line_sender_utf8,
    err_out: *mut *mut line_sender_error,
) -> bool {
    upd_opts!(opts, err_out, user, user.as_str())
}

/// Set the password for basic HTTP authentication.
/// Also see `user`.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_pass(
    opts: *mut line_sender_opts,
    pass: line_sender_utf8,
    err_out: *mut *mut line_sender_error,
) -> bool {
    upd_opts!(opts, err_out, pass, pass.as_str())
}

/// Token (Bearer) Authentication Parameters for ILP over HTTP,
/// or the ECDSA private key for ILP over TCP authentication.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_token(
    opts: *mut line_sender_opts,
    token: line_sender_utf8,
    err_out: *mut *mut line_sender_error,
) -> bool {
    upd_opts!(opts, err_out, token, token.as_str())
}

/// The ECDSA public key X for ILP over TCP authentication.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_token_x(
    opts: *mut line_sender_opts,
    token_x: line_sender_utf8,
    err_out: *mut *mut line_sender_error,
) -> bool {
    upd_opts!(opts, err_out, token_x, token_x.as_str())
}

/// The ECDSA public key Y for ILP over TCP authentication.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_token_y(
    opts: *mut line_sender_opts,
    token_y: line_sender_utf8,
    err_out: *mut *mut line_sender_error,
) -> bool {
    upd_opts!(opts, err_out, token_y, token_y.as_str())
}

/// Configure how long to wait for messages from the QuestDB server during
/// the TLS handshake and authentication process.
/// The default is 15000 milliseconds.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_auth_timeout(
    opts: *mut line_sender_opts,
    timeout_millis: u64,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let timeout = std::time::Duration::from_millis(timeout_millis);
    upd_opts!(opts, err_out, auth_timeout, timeout)
}

/// Enable or disable TLS.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_tls_enabled(
    opts: *mut line_sender_opts,
    enabled: bool,
    err_out: *mut *mut line_sender_error,
) -> bool {
    upd_opts!(opts, err_out, tls_enabled, enabled)
}

/// Set to `false` to disable TLS certificate verification.
/// This should only be used for debugging purposes as it reduces security.
///
/// For testing consider specifying a path to a `.pem` file instead via
/// the `tls_roots` setting.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_tls_verify(
    opts: *mut line_sender_opts,
    verify: bool,
    err_out: *mut *mut line_sender_error,
) -> bool {
    upd_opts!(opts, err_out, tls_verify, verify)
}

/// Set the certificate authority used to determine how to validate the server's TLS certificate.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_tls_ca(
    opts: *mut line_sender_opts,
    ca: line_sender_ca,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let ca: CertificateAuthority = ca.into();
    upd_opts!(opts, err_out, tls_ca, ca)
}

/// Set the path to a custom root certificate `.pem` file.
/// This is used to validate the server's certificate during the TLS handshake.
/// The file may be password-protected, if so, also specify the password.
/// via the `tls_roots_password` method.
///
/// See notes on how to test with [self-signed certificates](https://github.com/questdb/c-questdb-client/tree/main/tls_certs).
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_tls_roots(
    opts: *mut line_sender_opts,
    path: line_sender_utf8,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let path = PathBuf::from(path.as_str());
    upd_opts!(opts, err_out, tls_roots, path)
}

/// The maximum buffer size that the client will flush to the server.
/// The default is 100 MiB.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_max_buf_size(
    opts: *mut line_sender_opts,
    max_buf_size: size_t,
    err_out: *mut *mut line_sender_error,
) -> bool {
    upd_opts!(opts, err_out, max_buf_size, max_buf_size)
}

/// Cumulative duration spent in retries.
/// Default is 10 seconds.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_retry_timeout(
    opts: *mut line_sender_opts,
    millis: u64,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let retry_timeout = std::time::Duration::from_millis(millis);
    upd_opts!(opts, err_out, retry_timeout, retry_timeout)
}

/// Minimum expected throughput in bytes per second for HTTP requests.
/// If the throughput is lower than this value, the connection will time out.
/// The default is 100 KiB/s.
/// The value is expressed as a number of bytes per second.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_min_throughput(
    opts: *mut line_sender_opts,
    bytes_per_sec: u64,
    err_out: *mut *mut line_sender_error,
) -> bool {
    upd_opts!(opts, err_out, min_throughput, bytes_per_sec)
}

/// Grace request timeout before relying on the minimum throughput logic.
/// The default is 5 seconds.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_grace_timeout(
    opts: *mut line_sender_opts,
    millis: u64,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let grace_timeout = std::time::Duration::from_millis(millis);
    upd_opts!(opts, err_out, grace_timeout, grace_timeout)
}

/// Set the HTTP user agent. Internal API. Do not use.
#[doc(hidden)]
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_user_agent(
    opts: *mut line_sender_opts,
    user_agent: line_sender_utf8,
    err_out: *mut *mut line_sender_error,
) -> bool {
    upd_opts!(opts, err_out, user_agent, user_agent.as_str())
}

/// Duplicate the opts object.
/// Both old and new objects will have to be freed.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_clone(
    opts: *const line_sender_opts,
) -> *mut line_sender_opts {
    let builder = &(*opts).0;
    let new_builder = builder.clone();
    Box::into_raw(Box::new(line_sender_opts(new_builder)))
}

/// Release the opts object.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_free(opts: *mut line_sender_opts) {
    if !opts.is_null() {
        drop(Box::from_raw(opts));
    }
}

/// Insert data into QuestDB via the InfluxDB Line Protocol.
///
/// Batch up rows in `buffer` objects, then call `flush` to send them.
pub struct line_sender(Sender);

/// Build the line sender.
///
/// In case of TCP, this synchronously establishes the TCP connection, and
/// returns once the connection is fully established. If the connection
/// requires authentication or TLS, these will also be completed before
/// returning.
///
/// The connection should be accessed by only a single thread a time.
///
/// @param[in] opts Options for the connection.
#[no_mangle]
pub unsafe extern "C" fn line_sender_build(
    opts: *const line_sender_opts,
    err_out: *mut *mut line_sender_error,
) -> *mut line_sender {
    let builder = &(*opts).0;
    let sender = bubble_err_to_c!(err_out, builder.build(), ptr::null_mut());
    Box::into_raw(Box::new(line_sender(sender)))
}

/// Create a new `line_sender` instance from configuration string.
/// The format of the string is: "tcp::addr=host:port;key=value;...;"
/// Alongside "tcp" you can also specify "tcps", "http", and "https".
/// The accepted set of keys and values is the same as for the opt's API.
/// E.g. "tcp::addr=host:port;user=alice;password=secret;tls_ca=os_roots;"
///
/// For full list of options, search this header for `bool line_sender_opts_`.
#[no_mangle]
pub unsafe extern "C" fn line_sender_from_conf(
    config: line_sender_utf8,
    err_out: *mut *mut line_sender_error,
) -> *mut line_sender {
    let config = config.as_str();
    let sender = bubble_err_to_c!(err_out, Sender::from_conf(config), ptr::null_mut());
    Box::into_raw(Box::new(line_sender(sender)))
}

/// Create a new `line_sender` instance from configuration string read from the
/// `QDB_CLIENT_CONF` environment variable.
#[no_mangle]
pub unsafe extern "C" fn line_sender_from_env(
    err_out: *mut *mut line_sender_error,
) -> *mut line_sender {
    let sender = bubble_err_to_c!(err_out, Sender::from_env(), ptr::null_mut());
    Box::into_raw(Box::new(line_sender(sender)))
}

unsafe fn unwrap_sender<'a>(sender: *const line_sender) -> &'a Sender {
    &(*sender).0
}

unsafe fn unwrap_sender_mut<'a>(sender: *mut line_sender) -> &'a mut Sender {
    &mut (*sender).0
}

/// Check if an error occurred previously and the sender must be closed.
/// @param[in] sender Line sender object.
/// @return true if an error occurred with a sender and it must be closed.
#[no_mangle]
pub unsafe extern "C" fn line_sender_must_close(sender: *const line_sender) -> bool {
    unwrap_sender(sender).must_close()
}

/// Close the connection. Does not flush. Non-idempotent.
/// @param[in] sender Line sender object.
#[no_mangle]
pub unsafe extern "C" fn line_sender_close(sender: *mut line_sender) {
    if !sender.is_null() {
        drop(Box::from_raw(sender));
    }
}

/// Send buffer of rows to the QuestDB server.
///
/// The buffer will be automatically cleared, ready for re-use.
/// If instead you want to preserve the buffer contents, call `flush_and_keep`.
///
/// @param[in] sender Line sender object.
/// @param[in] buffer Line buffer object.
/// @return true on success, false on error.
#[no_mangle]
pub unsafe extern "C" fn line_sender_flush(
    sender: *mut line_sender,
    buffer: *mut line_sender_buffer,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let sender = unwrap_sender_mut(sender);
    let buffer = unwrap_buffer_mut(buffer);
    bubble_err_to_c!(err_out, sender.flush(buffer));
    true
}

/// Send buffer of rows to the QuestDB server.
///
/// The buffer will left untouched and must be cleared before re-use.
/// To send and clear in one single step, `flush` instead.
/// @param[in] sender Line sender object.
/// @param[in] buffer Line buffer object.
/// @return true on success, false on error.
#[no_mangle]
pub unsafe extern "C" fn line_sender_flush_and_keep(
    sender: *mut line_sender,
    buffer: *const line_sender_buffer,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let sender = unwrap_sender_mut(sender);
    let buffer = unwrap_buffer(buffer);
    bubble_err_to_c!(err_out, sender.flush_and_keep(buffer));
    true
}

/// Variant of `.flush()` that does not clear the buffer and allows for
/// transactional flushes.
///
/// A transactional flush is simply a flush that ensures that all rows in
/// the ILP buffer refer to the same table, thus allowing the server to
/// treat the flush request as a single transaction.
///
/// This is because QuestDB does not support transactions spanning multiple
/// tables.
#[no_mangle]
pub unsafe extern "C" fn line_sender_flush_and_keep_with_flags(
    sender: *mut line_sender,
    buffer: *const line_sender_buffer,
    transactional: bool,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let sender = unwrap_sender_mut(sender);
    let buffer = unwrap_buffer(buffer);
    bubble_err_to_c!(
        err_out,
        sender.flush_and_keep_with_flags(buffer, transactional)
    );
    true
}

/// Get the current time in nanoseconds since the unix epoch (UTC).
#[no_mangle]
pub unsafe extern "C" fn line_sender_now_nanos() -> i64 {
    TimestampNanos::now().as_i64()
}

/// Get the current time in microseconds since the unix epoch (UTC).
#[no_mangle]
pub unsafe extern "C" fn line_sender_now_micros() -> i64 {
    TimestampMicros::now().as_i64()
}

#[cfg(feature = "confstr-ffi")]
use questdb_confstr_ffi::questdb_conf_str_parse_err;

#[cfg(feature = "confstr-ffi")]
/// A build system hack.
/// Without this, the `questdb-confstr-ffi` crate dependency is not
/// included in the final binary.
/// This is because otherwise `cargo` will optimise out the dependency.
pub unsafe fn _build_system_hack(err: *mut questdb_conf_str_parse_err) {
    use questdb_confstr_ffi::questdb_conf_str_parse_err_free;
    questdb_conf_str_parse_err_free(err);
}
