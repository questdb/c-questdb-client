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
    ingress,
    ingress::{
        Buffer, CertificateAuthority, ColumnName, Protocol, Sender, SenderBuilder, TableName,
        TimestampMicros, TimestampNanos,
    },
    Error, ErrorCode,
};

mod ndarr;
use ndarr::StrideArrayView;

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
                    // We're really messing with the borrow-checker here.
                    // We've moved ownership of `forced_builder` (which is actually
                    // just an alias of the real `SenderBuilder` owned by the caller
                    // via a pointer - but the Rust compiler doesn't know that)
                    // into this function.
                    // This leaves the original caller holding a pointer to an
                    // already cleaned up object.
                    // To avoid double-freeing, we need to construct a valid "dummy"
                    // object on top of the memory that is still owned by the caller.
                    let dummy = SenderBuilder::new(Protocol::Tcp, "127.0.0.1", 1);
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

    /// There was an error serializing an array.
    line_sender_error_array_error,

    /// Line sender protocol version error.
    line_sender_error_protocol_version_error,
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
            ErrorCode::ArrayError => line_sender_error_code::line_sender_error_array_error,
            ErrorCode::ProtocolVersionError => {
                line_sender_error_code::line_sender_error_protocol_version_error
            }
        }
    }
}

/// The protocol used to connect with.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum line_sender_protocol {
    /// InfluxDB Line Protocol over TCP.
    line_sender_protocol_tcp,

    /// InfluxDB Line Protocol over TCP with TLS.
    line_sender_protocol_tcps,

    /// InfluxDB Line Protocol over HTTP.
    line_sender_protocol_http,

    /// InfluxDB Line Protocol over HTTP with TLS.
    line_sender_protocol_https,
}

impl From<Protocol> for line_sender_protocol {
    fn from(protocol: Protocol) -> Self {
        match protocol {
            Protocol::Tcp => line_sender_protocol::line_sender_protocol_tcp,
            Protocol::Tcps => line_sender_protocol::line_sender_protocol_tcps,
            Protocol::Http => line_sender_protocol::line_sender_protocol_http,
            Protocol::Https => line_sender_protocol::line_sender_protocol_https,
        }
    }
}

impl From<line_sender_protocol> for Protocol {
    fn from(protocol: line_sender_protocol) -> Self {
        match protocol {
            line_sender_protocol::line_sender_protocol_tcp => Protocol::Tcp,
            line_sender_protocol::line_sender_protocol_tcps => Protocol::Tcps,
            line_sender_protocol::line_sender_protocol_http => Protocol::Http,
            line_sender_protocol::line_sender_protocol_https => Protocol::Https,
        }
    }
}

/// The version of InfluxDB Line Protocol used to communicate with the server.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum ProtocolVersion {
    /// Version 1 of InfluxDB Line Protocol.
    /// Full-text protocol.
    /// When used over HTTP, it is compatible with the InfluxDB line protocol.
    V1 = 1,

    /// Version 2 of InfluxDB Line Protocol.
    /// Uses binary format serialization for f64, and supports the array data type.
    /// This version is specific to QuestDB and is not compatible with InfluxDB.
    V2 = 2,
}

impl From<ProtocolVersion> for ingress::ProtocolVersion {
    fn from(version: ProtocolVersion) -> Self {
        match version {
            ProtocolVersion::V1 => ingress::ProtocolVersion::V1,
            ProtocolVersion::V2 => ingress::ProtocolVersion::V2,
        }
    }
}

impl From<ingress::ProtocolVersion> for ProtocolVersion {
    fn from(version: ingress::ProtocolVersion) -> Self {
        match version {
            ingress::ProtocolVersion::V1 => ProtocolVersion::V1,
            ingress::ProtocolVersion::V2 => ProtocolVersion::V2,
        }
    }
}

/// Possible sources of the root certificates used to validate the server's TLS certificate.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum line_sender_ca {
    /// Use the root certificates provided by the `webpki` crate.
    line_sender_ca_webpki_roots,

    /// Use the root certificates provided by the operating system.
    line_sender_ca_os_roots,

    /// Combine the root certificates provided by the OS and the `webpki-roots` crate.
    line_sender_ca_webpki_and_os_roots,

    /// Use the root certificates provided in a PEM-encoded file.
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

/// Accumulates a batch of rows to be sent via `line_sender_flush()` or its
/// variants. A buffer object can be reused after flushing and clearing.
pub struct line_sender_buffer(Buffer);

/// Construct a `line_sender_buffer` with a `max_name_len` of `127`, which is the
/// same as the QuestDB server default.
#[no_mangle]
pub unsafe extern "C" fn line_sender_buffer_new(
    version: ProtocolVersion,
) -> *mut line_sender_buffer {
    let buffer = Buffer::new(version.into());
    Box::into_raw(Box::new(line_sender_buffer(buffer)))
}

/// Construct a `line_sender_buffer` with a custom maximum length for table and
/// column names. This should match the `cairo.max.file.name.length` setting of
/// the QuestDB  server you're connecting to.
/// If the server does not configure it, the default is `127`, and you can
/// call `line_sender_buffer_new()` instead.
#[no_mangle]
pub unsafe extern "C" fn line_sender_buffer_with_max_name_len(
    version: ProtocolVersion,
    max_name_len: size_t,
) -> *mut line_sender_buffer {
    let buffer = Buffer::with_max_name_len(version.into(), max_name_len);
    Box::into_raw(Box::new(line_sender_buffer(buffer)))
}

/// Release the `line_sender_buffer` object.
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
/// This does not allocate if such additional capacity is already satisfied.
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

/// The number of bytes accumulated in the buffer.
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

/// Tell whether the buffer is transactional. It is transactional iff it contains
/// data for at most one table. Additionally, you must send the buffer over HTTP to
/// get transactional behavior.
#[no_mangle]
pub unsafe extern "C" fn line_sender_buffer_transactional(
    buffer: *const line_sender_buffer,
) -> bool {
    let buffer = unwrap_buffer(buffer);
    buffer.transactional()
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct line_sender_buffer_view {
    len: size_t,
    buf: *const u8,
}

/// Provides a read-only view into the buffer's bytes content.
///
/// @param[in] buffer Line buffer object.
/// @return A [`line_sender_buffer_view`] struct containing:
/// - `buf`: Immutable pointer to the byte stream
/// - `len`: Exact byte length of the data
#[no_mangle]
pub unsafe extern "C" fn line_sender_buffer_peek(
    buffer: *const line_sender_buffer,
) -> line_sender_buffer_view {
    let buffer = unwrap_buffer(buffer);
    let buf: &[u8] = buffer.as_bytes();
    line_sender_buffer_view {
        len: buf.len(),
        buf: buf.as_ptr(),
    }
}

/// Start recording a new row for the given table.
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

/// Record a symbol value for the given column.
/// Make sure you record all the symbol columns before any other column type.
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

/// Record a boolean value for the given column.
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

/// Record an integer value for the given column.
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

/// Record a floating-point value for the given column.
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

/// Record a string value for the given column.
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

/// Records a float64 multidimensional array with **C-MAJOR memory layout**.
///
/// @param[in] buffer Line buffer object.
/// @param[in] name Column name.
/// @param[in] rank Array dims.
/// @param[in] shape Array shape.
/// @param[in] data_buffer Array **first element** data memory ptr.
/// @param[in] data_buffer_len Array data memory length.
/// @param[out] err_out Set on error.
/// # Safety
/// - All pointer parameters must be valid and non-null
/// - shape must point to an array of `rank` integers
/// - data_buffer must point to a buffer of size `data_buffer_len` bytes
#[no_mangle]
pub unsafe extern "C" fn line_sender_buffer_column_f64_arr_c_major(
    buffer: *mut line_sender_buffer,
    name: line_sender_column_name,
    rank: size_t,
    shape: *const usize,
    data_buffer: *const u8,
    data_buffer_len: size_t,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let buffer = unwrap_buffer_mut(buffer);
    let name = name.as_name();
    let view = match CMajorArrayView::<f64>::new(rank, shape, data_buffer, data_buffer_len) {
        Ok(value) => value,
        Err(err) => {
            let err_ptr = Box::into_raw(Box::new(line_sender_error(err)));
            *err_out = err_ptr;
            return false;
        }
    };
    bubble_err_to_c!(
        err_out,
        buffer.column_arr::<ColumnName<'_>, CMajorArrayView<'_, f64>, f64>(name, &view)
    );
    true
}

/// Records a float64 multidimensional array with **byte-level strides specification**.
///
/// The `strides` represent byte offsets between elements along each dimension.
///
/// @param[in] buffer Line buffer object.
/// @param[in] name Column name.
/// @param[in] rank Array dims.
/// @param[in] shape Array shape.
/// @param[in] strides Array strides, represent byte offsets between elements along each dimension.
/// @param[in] data_buffer Array **first element** data memory ptr.
/// @param[in] data_buffer_len Array data memory length.
/// @param[out] err_out Set on error.
/// # Safety
/// - All pointer parameters must be valid and non-null
/// - shape must point to an array of `rank` integers
/// - data_buffer must point to a buffer of size `data_buffer_len` bytes
#[no_mangle]
pub unsafe extern "C" fn line_sender_buffer_column_f64_arr_byte_strides(
    buffer: *mut line_sender_buffer,
    name: line_sender_column_name,
    rank: size_t,
    shape: *const usize,
    strides: *const isize,
    data_buffer: *const u8,
    data_buffer_len: size_t,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let buffer = unwrap_buffer_mut(buffer);
    let name = name.as_name();
    let view =
        match StrideArrayView::<f64, 1>::new(rank, shape, strides, data_buffer, data_buffer_len) {
            Ok(value) => value,
            Err(err) => {
                let err_ptr = Box::into_raw(Box::new(line_sender_error(err)));
                *err_out = err_ptr;
                return false;
            }
        };
    bubble_err_to_c!(
        err_out,
        buffer.column_arr::<ColumnName<'_>, StrideArrayView<'_, f64, 1>, f64>(name, &view)
    );
    true
}

/// Records a float64 multidimensional array with **element count stride specification**.
///
/// The `strides` represent element counts between elements along each dimension.
///
/// converted to byte strides using f64 size
/// @param[in] buffer Line buffer object.
/// @param[in] name Column name.
/// @param[in] rank Array dims.
/// @param[in] shape Array shape.
/// @param[in] strides Array strides, represent element counts between elements along each dimension.
/// @param[in] data_buffer Array **first element** data memory ptr.
/// @param[in] data_buffer_len Array data memory length.
/// @param[out] err_out Set on error.
/// # Safety
/// - All pointer parameters must be valid and non-null
/// - shape must point to an array of `rank` integers
/// - data_buffer must point to a buffer of size `data_buffer_len` bytes
#[no_mangle]
pub unsafe extern "C" fn line_sender_buffer_column_f64_arr_elem_strides(
    buffer: *mut line_sender_buffer,
    name: line_sender_column_name,
    rank: size_t,
    shape: *const usize,
    strides: *const isize,
    data_buffer: *const u8,
    data_buffer_len: size_t,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let buffer = unwrap_buffer_mut(buffer);
    let name = name.as_name();
    let view = match StrideArrayView::<f64, { std::mem::size_of::<f64>() as isize }>::new(
        rank,
        shape,
        strides,
        data_buffer,
        data_buffer_len,
    ) {
        Ok(value) => value,
        Err(err) => {
            let err_ptr = Box::into_raw(Box::new(line_sender_error(err)));
            *err_out = err_ptr;
            return false;
        }
    };
    bubble_err_to_c!(
            err_out,
            buffer.column_arr::<ColumnName<'_>, StrideArrayView<'_, f64,  { std::mem::size_of::<f64>() as isize }>, f64>(name, &view)
        );
    true
}

/// Record a nanosecond timestamp value for the given column.
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

/// Record a microsecond timestamp value for the given column.
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

/// Complete the current row with the designated timestamp in nanoseconds.
///
/// After this call, you can start recording the next row by calling
/// `line_sender_buffer_table()` again, or you can send the accumulated batch
/// by calling `line_sender_flush()` or one of its variants.
///
/// If you want to pass the current system timestamp, see
/// `line_sender_now_nanos()`.
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

/// Complete the current row with the designated timestamp in microseconds.
///
/// After this call, you can start recording the next row by calling
/// `line_sender_buffer_table()` again, or you can send the accumulated batch
/// by calling `line_sender_flush()` or one of its variants.
///
/// If you want to pass the current system timestamp, see
/// `line_sender_now_micros()`.
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

/// Complete the current row without providing a timestamp. The QuestDB instance
/// will insert its own timestamp.
///
/// Letting the server assign the timestamp can be faster since it a reliable way
/// to avoid out-of-order operations in the database for maximum ingestion
/// throughput. However, it removes the ability to deduplicate rows.
///
/// This is NOT equivalent to calling `line_sender_buffer_at_nanos()` or
/// `line_sender_buffer_at_micros()` with the current time: the QuestDB server
/// will set the timestamp only after receiving the row. If you're flushing
/// infrequently, the server-assigned timestamp may be significantly behind the
/// time the data was recorded in the buffer.
///
/// In almost all cases, you should prefer the `line_sender_buffer_at_*()` functions.
///
/// After this call, you can start recording the next row by calling `table()`
/// again, or you can send the accumulated batch by calling `flush()` or one of
/// its variants.
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

/**
 * Check whether the buffer is ready to be flushed.
 * If this returns false, the buffer is incomplete and cannot be sent,
 * and an error message is set to indicate the problem.
 */
#[no_mangle]
pub unsafe extern "C" fn line_sender_buffer_check_can_flush(
    buffer: *const line_sender_buffer,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let buffer = unwrap_buffer(buffer);
    bubble_err_to_c!(err_out, buffer.check_can_flush());
    true
}

/// Accumulates parameters for a new `line_sender` object.
pub struct line_sender_opts(SenderBuilder);

/// Create a new `line_sender_opts` instance from the given configuration string.
/// The format of the string is: "tcp::addr=host:port;key=value;...;"
/// Instead of "tcp" you can also specify "tcps", "http", and "https".
///
/// The accepted keys match one-for-one with the functions on `line_sender_opts`.
/// For example, this is a valid configuration string:
///
/// "https::addr=host:port;username=alice;password=secret;"
///
/// and there are matching functions `line_sender_opts_username()` and
/// `line_sender_opts_password()`. The value for `addr=` is supplied directly to
/// `line_sender_opts_new`, so there's no function with a matching name.
///
/// For the full list of keys, search this module for `fn line_sender_opts_`.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_from_conf(
    config: line_sender_utf8,
    err_out: *mut *mut line_sender_error,
) -> *mut line_sender_opts {
    let config = config.as_str();
    let builder = bubble_err_to_c!(err_out, SenderBuilder::from_conf(config), ptr::null_mut());
    Box::into_raw(Box::new(line_sender_opts(builder)))
}

/// Create a new `line_sender_opts` instance from the configuration stored in the
/// `QDB_CLIENT_CONF` environment variable.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_from_env(
    err_out: *mut *mut line_sender_error,
) -> *mut line_sender_opts {
    let builder = bubble_err_to_c!(err_out, SenderBuilder::from_env(), ptr::null_mut());
    Box::into_raw(Box::new(line_sender_opts(builder)))
}

/// Create a new `line_sender_opts` instance with the given protocol, hostname and
/// port.
/// @param[in] protocol The protocol to use.
/// @param[in] host The QuestDB database host.
/// @param[in] port The QuestDB ILP TCP port.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_new(
    protocol: line_sender_protocol,
    host: line_sender_utf8,
    port: u16,
) -> *mut line_sender_opts {
    let builder = SenderBuilder::new(protocol.into(), host.as_str(), port);
    let builder = builder
        .user_agent(concat!("questdb/c/", env!("CARGO_PKG_VERSION")))
        .expect("user_agent set");
    Box::into_raw(Box::new(line_sender_opts(builder)))
}

/// Create a new `line_sender_opts` instance with the given protocol, hostname and
/// service name.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_new_service(
    protocol: line_sender_protocol,
    host: line_sender_utf8,
    port: line_sender_utf8,
) -> *mut line_sender_opts {
    let builder = SenderBuilder::new(protocol.into(), host.as_str(), port.as_str());
    let builder = builder
        .user_agent(concat!("questdb/c/", env!("CARGO_PKG_VERSION")))
        .expect("user_agent set");
    Box::into_raw(Box::new(line_sender_opts(builder)))
}

/// Select local outbound network "bind" interface.
///
/// This may be relevant if your machine has multiple network interfaces.
///
/// The default is `0.0.0.0`.
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
/// For TCP, this is the `kid` part of the ECDSA key set.
/// The other fields are `token` `token_x` and `token_y`.
///
/// For HTTP, this is part of basic authentication.
/// See also: `line_sender_opts_password()`.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_username(
    opts: *mut line_sender_opts,
    username: line_sender_utf8,
    err_out: *mut *mut line_sender_error,
) -> bool {
    upd_opts!(opts, err_out, username, username.as_str())
}

/// Set the password for basic HTTP authentication.
/// See also: `line_sender_opts_username()`.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_password(
    opts: *mut line_sender_opts,
    password: line_sender_utf8,
    err_out: *mut *mut line_sender_error,
) -> bool {
    upd_opts!(opts, err_out, password, password.as_str())
}

/// Set the Token (Bearer) Authentication parameter for HTTP,
/// or the ECDSA private key for TCP authentication.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_token(
    opts: *mut line_sender_opts,
    token: line_sender_utf8,
    err_out: *mut *mut line_sender_error,
) -> bool {
    upd_opts!(opts, err_out, token, token.as_str())
}

/// Set the ECDSA public key X for TCP authentication.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_token_x(
    opts: *mut line_sender_opts,
    token_x: line_sender_utf8,
    err_out: *mut *mut line_sender_error,
) -> bool {
    upd_opts!(opts, err_out, token_x, token_x.as_str())
}

/// Set the ECDSA public key Y for TCP authentication.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_token_y(
    opts: *mut line_sender_opts,
    token_y: line_sender_utf8,
    err_out: *mut *mut line_sender_error,
) -> bool {
    upd_opts!(opts, err_out, token_y, token_y.as_str())
}

/// set the line protocol version.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_protocol_version(
    opts: *mut line_sender_opts,
    version: ProtocolVersion,
    err_out: *mut *mut line_sender_error,
) -> bool {
    upd_opts!(opts, err_out, protocol_version, version.into())
}

/// Configure how long to wait for messages from the QuestDB server during
/// the TLS handshake and authentication process.
/// The value is in milliseconds, and the default is 15 seconds.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_auth_timeout(
    opts: *mut line_sender_opts,
    timeout_millis: u64,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let timeout = std::time::Duration::from_millis(timeout_millis);
    upd_opts!(opts, err_out, auth_timeout, timeout)
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

/// Specify where to find the certificate authority used to validate
/// the validate the server's TLS certificate.
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
///
/// See notes on how to test with [self-signed
/// certificates](https://github.com/questdb/c-questdb-client/tree/main/tls_certs).
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_tls_roots(
    opts: *mut line_sender_opts,
    path: line_sender_utf8,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let path = PathBuf::from(path.as_str());
    upd_opts!(opts, err_out, tls_roots, path)
}

/// Set the maximum buffer size in bytes that the client will flush to the server.
/// The default is 100 MiB.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_max_buf_size(
    opts: *mut line_sender_opts,
    max_buf_size: size_t,
    err_out: *mut *mut line_sender_error,
) -> bool {
    upd_opts!(opts, err_out, max_buf_size, max_buf_size)
}

/// Ser the maximum length of a table or column name in bytes.
/// The default is 127 bytes.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_max_name_len(
    opts: *mut line_sender_opts,
    max_name_len: size_t,
    err_out: *mut *mut line_sender_error,
) -> bool {
    upd_opts!(opts, err_out, max_name_len, max_name_len)
}

/// Set the cumulative duration spent in retries.
/// The value is in milliseconds, and the default is 10 seconds.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_retry_timeout(
    opts: *mut line_sender_opts,
    millis: u64,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let retry_timeout = std::time::Duration::from_millis(millis);
    upd_opts!(opts, err_out, retry_timeout, retry_timeout)
}

/// Set the minimum acceptable throughput while sending a buffer to the server.
/// The sender will divide the payload size by this number to determine for how
/// long to keep sending the payload before timing out.
/// The value is in bytes per second, and the default is 100 KiB/s.
/// The timeout calculated from minimum throughput is adedd to the value of
/// `request_timeout`.
///
/// See also: `line_sender_opts_request_timeout()`
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_request_min_throughput(
    opts: *mut line_sender_opts,
    bytes_per_sec: u64,
    err_out: *mut *mut line_sender_error,
) -> bool {
    upd_opts!(opts, err_out, request_min_throughput, bytes_per_sec)
}

/// Set the additional time to wait on top of that calculated from the minimum
/// throughput. This accounts for the fixed latency of the HTTP request-response
/// roundtrip. The value is in milliseconds, and the default is 10 seconds.
///
/// See also: `line_sender_opts_request_min_throughput()`
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_request_timeout(
    opts: *mut line_sender_opts,
    millis: u64,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let request_timeout = std::time::Duration::from_millis(millis);
    upd_opts!(opts, err_out, request_timeout, request_timeout)
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

/// Duplicate the `line_sender_opts` object.
/// Both old and new objects will have to be freed.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_clone(
    opts: *const line_sender_opts,
) -> *mut line_sender_opts {
    let builder = &(*opts).0;
    let new_builder = builder.clone();
    Box::into_raw(Box::new(line_sender_opts(new_builder)))
}

/// Release the `line_sender_opts` object.
#[no_mangle]
pub unsafe extern "C" fn line_sender_opts_free(opts: *mut line_sender_opts) {
    if !opts.is_null() {
        drop(Box::from_raw(opts));
    }
}

/// Inserts data into QuestDB via the InfluxDB Line Protocol.
///
/// Batch up rows in a `line_sender_buffer`, then call `line_sender_flush()` or
/// one of its variants with this object to send them.
pub struct line_sender(Sender);

/// Create a new line sender instance from the given options object.
///
/// In the case of TCP, this synchronously establishes the TCP connection, and
/// returns once the connection is fully established. If the connection
/// requires authentication or TLS, these will also be completed before
/// returning.
///
/// The sender should be accessed by only a single thread a time.
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

/// Create a new line sender instance from the given configuration string.
/// The format of the string is: "tcp::addr=host:port;key=value;...;"
/// Instead of "tcp" you can also specify "tcps", "http", and "https".
///
/// The accepted keys match one-for-one with the functions on `line_sender_opts`.
/// For example, this is a valid configuration string:
///
/// "https::addr=host:port;username=alice;password=secret;"
///
/// and there are matching functions `line_sender_opts_username()` and
/// `line_sender_opts_password()`. The value for `addr=` is supplied directly to
/// `line_sender_opts_new`, so there's no function with a matching name.
///
/// For the full list of keys, search this header for `bool line_sender_opts_`.
///
/// In the case of TCP, this synchronously establishes the TCP connection, and
/// returns once the connection is fully established. If the connection
/// requires authentication or TLS, these will also be completed before
/// returning.
///
/// The sender should be accessed by only a single thread a time.
#[no_mangle]
pub unsafe extern "C" fn line_sender_from_conf(
    config: line_sender_utf8,
    err_out: *mut *mut line_sender_error,
) -> *mut line_sender {
    let config = config.as_str();
    let builder = bubble_err_to_c!(err_out, SenderBuilder::from_conf(config), ptr::null_mut());
    let builder = builder
        .user_agent(concat!("questdb/c/", env!("CARGO_PKG_VERSION")))
        .expect("user_agent set");
    let sender = bubble_err_to_c!(err_out, builder.build(), ptr::null_mut());
    Box::into_raw(Box::new(line_sender(sender)))
}

/// Create a new `line_sender` instance from the configuration stored in the
/// `QDB_CLIENT_CONF` environment variable.
///
/// In the case of TCP, this synchronously establishes the TCP connection, and
/// returns once the connection is fully established. If the connection
/// requires authentication or TLS, these will also be completed before
/// returning.
///
/// The sender should be accessed by only a single thread a time.
#[no_mangle]
pub unsafe extern "C" fn line_sender_from_env(
    err_out: *mut *mut line_sender_error,
) -> *mut line_sender {
    let builder = bubble_err_to_c!(err_out, SenderBuilder::from_env(), ptr::null_mut());
    let builder = builder
        .user_agent(concat!("questdb/c/", env!("CARGO_PKG_VERSION")))
        .expect("user_agent set");
    let sender = bubble_err_to_c!(err_out, builder.build(), ptr::null_mut());
    Box::into_raw(Box::new(line_sender(sender)))
}

unsafe fn unwrap_sender<'a>(sender: *const line_sender) -> &'a Sender {
    &(*sender).0
}

unsafe fn unwrap_sender_mut<'a>(sender: *mut line_sender) -> &'a mut Sender {
    &mut (*sender).0
}

/// Return the sender's protocol version.
/// This is either the protocol version that was set explicitly,
/// or the one that was auto-detected during the connection process.
/// If connecting via TCP and not overridden, the value is V1.
#[no_mangle]
pub unsafe extern "C" fn line_sender_get_protocol_version(
    sender: *const line_sender,
) -> ProtocolVersion {
    unwrap_sender(sender).protocol_version().into()
}

#[no_mangle]
pub unsafe extern "C" fn line_sender_get_max_name_len(sender: *const line_sender) -> size_t {
    unwrap_sender(sender).max_name_len()
}

/// Construct a `line_sender_buffer` with a `max_name_len` of `127` and sender's default protocol version
/// which is the same as the QuestDB server default.
#[no_mangle]
pub unsafe extern "C" fn line_sender_buffer_new_for_sender(
    sender: *const line_sender,
) -> *mut line_sender_buffer {
    let sender = unwrap_sender(sender);
    let buffer = sender.new_buffer();
    Box::into_raw(Box::new(line_sender_buffer(buffer)))
}

/// Tell whether the sender is no longer usable and must be closed.
/// This happens when there was an earlier failure.
/// This fuction is specific to TCP and is not relevant for HTTP.
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

/// Send the given buffer of rows to the QuestDB server, clearing the buffer.
///
/// After this function returns, the buffer is empty and ready for the next batch.
/// If you want to preserve the buffer contents, call `line_sender_flush_and_keep`.
/// If you want to ensure the flush is transactional, call
/// `line_sender_flush_and_keep_with_flags`.
///
/// With ILP-over-HTTP, this function sends an HTTP request and waits for the
/// response. If the server responds with an error, it returns a descriptive error.
/// In the case of a network error, it retries until it has exhausted the retry time
/// budget.
///
/// With ILP-over-TCP, the function blocks only until the buffer is flushed to the
/// underlying OS-level network socket, without waiting to actually send it to the
/// server. In the case of an error, the server will quietly disconnect: consult the
/// server logs for error messages.
///
/// HTTP should be the first choice, but use TCP if you need to continuously send
/// data to the server at a high rate.
///
/// To improve the HTTP performance, send larger buffers (with more rows), and
/// consider parallelizing writes using multiple senders from multiple threads.
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

/// Send the given buffer of rows to the QuestDB server.
///
/// All the data stays in the buffer. Clear the buffer before starting a new batch.
///
/// To send and clear in one step, call `line_sender_flush` instead. Also, see the docs
/// on that function for more important details on flushing.
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

/// Send the batch of rows in the buffer to the QuestDB server, and, if the parameter
/// `transactional` is true, ensure the flush will be transactional.
///
/// A flush is transactional iff all the rows belong to the same table. This allows
/// QuestDB to treat the flush as a single database transaction, because it doesn't
/// support transactions spanning multiple tables. Additionally, only ILP-over-HTTP
/// supports transactional flushes.
///
/// If the flush wouldn't be transactional, this function returns an error and
/// doesn't flush any data.
///
/// The function sends an HTTP request and waits for the response. If the server
/// responds with an error, it returns a descriptive error. In the case of a network
/// error, it retries until it has exhausted the retry time budget.
///
/// All the data stays in the buffer. Clear the buffer before starting a new batch.
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

/// Get the current time in nanoseconds since the Unix epoch (UTC).
#[no_mangle]
pub unsafe extern "C" fn line_sender_now_nanos() -> i64 {
    TimestampNanos::now().as_i64()
}

/// Get the current time in microseconds since the Unix epoch (UTC).
#[no_mangle]
pub unsafe extern "C" fn line_sender_now_micros() -> i64 {
    TimestampMicros::now().as_i64()
}

use crate::ndarr::CMajorArrayView;
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
