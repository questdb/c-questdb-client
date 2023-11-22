/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2023 QuestDB
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
        TimestampMicros, TimestampNanos, Tls,
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

/// Update the Rust builder inside the C opts object
/// after calling a method that takes ownership of the builder.
macro_rules! upd_opts {
    ($opts:expr, $func:ident, $($args:expr),*) => {
        ptr::write(
            &mut (*$opts).0,
            ptr::read(&(*$opts).0).$func($($args),*));
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

/// Accumulates parameters for creating a line sender connection.
pub struct line_sender_opts(SenderBuilder);

/// A new set of options for a line sender connection.
/// @param[in] host The QuestDB database host.
/// @param[in] port The QuestDB database port.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_new(
    host: line_sender_utf8,
    port: u16,
) -> *mut line_sender_opts {
    let builder = SenderBuilder::new(host.as_str(), port);
    Box::into_raw(Box::new(line_sender_opts(builder)))
}

/// A new set of options for a line sender connection.
/// @param[in] host The QuestDB database host.
/// @param[in] port The QuestDB database port as service name.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_new_service(
    host: line_sender_utf8,
    port: line_sender_utf8,
) -> *mut line_sender_opts {
    let builder = SenderBuilder::new(host.as_str(), port.as_str());
    Box::into_raw(Box::new(line_sender_opts(builder)))
}

/// Select local outbound interface.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_net_interface(
    opts: *mut line_sender_opts,
    net_interface: line_sender_utf8,
) {
    upd_opts!(opts, net_interface, net_interface.as_str());
}

/// Authentication Parameters.
/// @param[in] key_id Key id. AKA "kid"
/// @param[in] priv_key Private key. AKA "d".
/// @param[in] pub_key_x Public key X coordinate. AKA "x".
/// @param[in] pub_key_y Public key Y coordinate. AKA "y".
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_auth(
    opts: *mut line_sender_opts,
    key_id: line_sender_utf8,
    priv_key: line_sender_utf8,
    pub_key_x: line_sender_utf8,
    pub_key_y: line_sender_utf8,
) {
    upd_opts!(
        opts,
        auth,
        key_id.as_str(),
        priv_key.as_str(),
        pub_key_x.as_str(),
        pub_key_y.as_str()
    );
}

/// Enable full connection encryption via TLS.
/// The connection will accept certificates by well-known certificate
/// authorities as per the "webpki-roots" Rust crate.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_tls(opts: *mut line_sender_opts) {
    upd_opts!(opts, tls, Tls::Enabled(CertificateAuthority::WebpkiRoots));
}

/// Enable full connection encryption via TLS, using OS-provided certificate roots.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_tls_os_roots(opts: *mut line_sender_opts) {
    upd_opts!(opts, tls, Tls::Enabled(CertificateAuthority::OsRoots));
}

/// Enable full connection encryption via TLS, accepting certificates signed by either
/// the OS-provided certificate roots or well-known certificate authorities as per
/// the "webpki-roots" Rust crate.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_tls_webpki_and_os_roots(opts: *mut line_sender_opts) {
    upd_opts!(
        opts,
        tls,
        Tls::Enabled(CertificateAuthority::WebpkiAndOsRoots)
    );
}

/// Enable full connection encryption via TLS.
/// The connection will accept certificates by the specified certificate
/// authority file.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_tls_ca(
    opts: *mut line_sender_opts,
    ca_path: line_sender_utf8,
) {
    let ca_path = PathBuf::from(ca_path.as_str());
    upd_opts!(opts, tls, Tls::Enabled(CertificateAuthority::File(ca_path)));
}

/// Enable TLS whilst dangerously accepting any certificate as valid.
/// This should only be used for debugging.
/// Consider using calling "tls_ca" instead.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_tls_insecure_skip_verify(opts: *mut line_sender_opts) {
    upd_opts!(opts, tls, Tls::InsecureSkipVerify);
}

/// Configure how long to wait for messages from the QuestDB server during
/// the TLS handshake and authentication process.
/// The default is 15 seconds.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_read_timeout(
    opts: *mut line_sender_opts,
    timeout_millis: u64,
) {
    let timeout = std::time::Duration::from_millis(timeout_millis);
    upd_opts!(opts, read_timeout, timeout);
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

/// Insert data into QuestDB via the InfluxDB Line Protocol.
///
/// Batch up rows in `buffer` objects, then call `flush` to send them.
pub struct line_sender(Sender);

/// Synchronously connect to the QuestDB database.
/// The connection should be accessed by only a single thread a time.
/// @param[in] opts Options for the connection.
#[no_mangle]
pub unsafe extern "C" fn line_sender_connect(
    opts: *const line_sender_opts,
    err_out: *mut *mut line_sender_error,
) -> *mut line_sender {
    let builder = &(*opts).0;
    let sender = bubble_err_to_c!(err_out, builder.connect(), ptr::null_mut());
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
