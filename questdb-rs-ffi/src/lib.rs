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

use libc::{c_char, c_void, size_t};
use questdb::ingress::DecimalView;
use std::ascii;
use std::boxed::Box;
use std::convert::{From, Into};
use std::io::{self, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::ptr;
use std::slice;
use std::str;

use questdb::{
    Error, ErrorCode, ingress,
    ingress::{
        Buffer, CertificateAuthority, ColumnName, Protocol,
        QwpWsErrorCategory as RustQwpWsErrorCategory, QwpWsErrorPolicy as RustQwpWsErrorPolicy,
        QwpWsProgress as RustQwpWsProgress, QwpWsSenderError, Sender, SenderBuilder, TableName,
        TimestampMicros, TimestampNanos,
    },
};
use std::time::Duration;

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
                set_err_out_from_error($err_out, err);
                return $sentinel;
            }
        }
    };
}

#[macro_export]
macro_rules! fmt_error {
    ($code:ident, $($arg:tt)*) => {
        questdb::Error::new(
            questdb::ErrorCode::$code,
            format!($($arg)*))
    }
}

macro_rules! new_stride_array {
    (
        $rank:expr,
        $m:literal,
        $n:literal,
        $shape:expr,
        $strides:expr,
        $data:expr,
        $data_len:expr,
        $err_out:expr,
        $buffer:expr,
        $name:expr
    ) => {{
        let view = match StrideArrayView::<f64, $m, $n>::new($shape, $strides, $data, $data_len) {
            Ok(value) => value,
            Err(err) => {
                set_err_out_from_error($err_out, err);
                return false;
            }
        };
        bubble_err_to_c!(
            $err_out,
            $buffer
                .column_arr::<ColumnName<'_>, StrideArrayView<'_, f64, $m, $n>, f64>($name, &view)
        );
    }};
}

macro_rules! generate_array_dims_branches {
    ($rank:expr, $m:literal, $shape:expr, $strides:expr, $data:expr, $data_len:expr, $err_out:expr, $buffer:expr, $name:expr => $($n:literal),*) => {
        match $rank {
            0 => {
                if !$err_out.is_null() {
                    let err = fmt_error!(
                        ArrayError,
                        "Zero-dimensional arrays are not supported",
                    );
                    set_err_out_from_error($err_out, err);
                }
                return false;
            }
            $(
                $n => new_stride_array!(
                    $rank,
                    $m,
                    $n,
                    $shape,
                    $strides,
                    $data,
                    $data_len,
                    $err_out,
                    $buffer,
                    $name
                ),
            )*
            other => {
                if !$err_out.is_null() {
                    let err = fmt_error!(
                        ArrayError,
                        "Array dimension mismatch: expected at most {} dimensions, but got {}",
                        32,
                        other
                    );
                    set_err_out_from_error($err_out, err);
                }
                return false;
            }
        }
    };
}

/// Update the Rust builder inside the C opts object
/// after calling a method that takes ownership of the builder.
///
/// The builder setters consume `self` (Rust move semantics), so we
/// clone the current builder, call the setter on the clone, and commit the
/// returned builder only on success.
///
/// This keeps the original object valid on validation errors and during
/// unwinding if a setter panics; the live `line_sender_opts` object never
/// contains duplicated stale owned bits.
///
/// This costs one clone per setter call during one-time setup — acceptable
/// since this path is only hit from C/C++ FFI, never from pure Rust.
///
/// Alternatives considered:
/// - Private `&mut self` helpers on `SenderBuilder` called from FFI
///   directly: eliminates the clone but requires `#[doc(hidden)] pub`
///   visibility leaking across crates, and every new setter needs a
///   companion method (desync risk).
/// - Changing the public Rust API to `&mut self`: removes the problem
///   entirely but is a semver-breaking change affecting all Rust users.
/// - `ManuallyDrop`/`MaybeUninit`: these cannot reconstruct the old
///   builder after a consuming setter drops it on error — a backup
///   copy is still needed.
macro_rules! upd_opts {
    ($opts:expr, $err_out:expr, $func:ident $(, $($args:expr),*)?) => {{
        // catch_unwind makes this macro the single FFI panic boundary for the
        // entire opts-setter family; AssertUnwindSafe is justified by the
        // clone-then-replace dance above keeping the live builder consistent.
        match catch_unwind(AssertUnwindSafe(|| {
            let builder_ref: &mut SenderBuilder = &mut (*$opts).0;
            match builder_ref.clone().$func($($($args),*)?) {
                Ok(builder) => {
                    *builder_ref = builder;
                    true
                }
                Err(err) => {
                    set_err_out_from_error($err_out, err);
                    false
                }
            }
        })) {
            Ok(v) => v,
            Err(_) => {
                set_err_out(
                    $err_out,
                    ErrorCode::InvalidApiCall,
                    concat!(stringify!($func), " panicked").to_string(),
                );
                false
            }
        }
    }};
}

/// An error that occurred when using the line sender.
pub struct line_sender_error {
    error: Error,
    qwp_ws_error: Option<QwpWsSenderError>,
}

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

    /// The supplied decimal is invalid.
    line_sender_error_invalid_decimal,

    /// QWP/WebSocket server rejection or terminal protocol violation.
    line_sender_error_server_rejection,
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
            ErrorCode::ServerRejection => {
                line_sender_error_code::line_sender_error_server_rejection
            }
            ErrorCode::ConfigError => line_sender_error_code::line_sender_error_config_error,
            ErrorCode::ArrayError => line_sender_error_code::line_sender_error_array_error,
            ErrorCode::ProtocolVersionError => {
                line_sender_error_code::line_sender_error_protocol_version_error
            }
            ErrorCode::InvalidDecimal => line_sender_error_code::line_sender_error_invalid_decimal,
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

    /// QuestWire Protocol over UDP.
    line_sender_protocol_qwpudp,

    /// QuestWire Protocol over WebSocket.
    line_sender_protocol_qwpws,

    /// QuestWire Protocol over WebSocket Secure (TLS).
    line_sender_protocol_qwpwss,
}

impl From<Protocol> for line_sender_protocol {
    fn from(protocol: Protocol) -> Self {
        match protocol {
            Protocol::Tcp => line_sender_protocol::line_sender_protocol_tcp,
            Protocol::Tcps => line_sender_protocol::line_sender_protocol_tcps,
            Protocol::Http => line_sender_protocol::line_sender_protocol_http,
            Protocol::Https => line_sender_protocol::line_sender_protocol_https,
            Protocol::QwpUdp => line_sender_protocol::line_sender_protocol_qwpudp,
            Protocol::QwpWs => line_sender_protocol::line_sender_protocol_qwpws,
            Protocol::QwpWss => line_sender_protocol::line_sender_protocol_qwpwss,
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
            line_sender_protocol::line_sender_protocol_qwpudp => Protocol::QwpUdp,
            line_sender_protocol::line_sender_protocol_qwpws => Protocol::QwpWs,
            line_sender_protocol::line_sender_protocol_qwpwss => Protocol::QwpWss,
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
    /// QuestDB server version 9.0.0 or later is required for `V2` support.
    V2 = 2,

    /// Version 3 of InfluxDB Line Protocol.
    /// Supports the decimal data type in text and binary formats.
    /// This version is specific to QuestDB and is not compatible with InfluxDB.
    /// QuestDB server version 9.2.0 or later is required for `V3` support.
    V3 = 3,
}

impl From<ProtocolVersion> for ingress::ProtocolVersion {
    fn from(version: ProtocolVersion) -> Self {
        match version {
            ProtocolVersion::V1 => ingress::ProtocolVersion::V1,
            ProtocolVersion::V2 => ingress::ProtocolVersion::V2,
            ProtocolVersion::V3 => ingress::ProtocolVersion::V3,
        }
    }
}

impl From<ingress::ProtocolVersion> for ProtocolVersion {
    fn from(version: ingress::ProtocolVersion) -> Self {
        match version {
            ingress::ProtocolVersion::V1 => ProtocolVersion::V1,
            ingress::ProtocolVersion::V2 => ProtocolVersion::V2,
            ingress::ProtocolVersion::V3 => ProtocolVersion::V3,
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_error_get_code(
    error: *const line_sender_error,
) -> line_sender_error_code {
    unsafe { (*error).error.code().into() }
}

/// UTF-8 encoded error message. Never returns NULL.
/// The `len_out` argument is set to the number of bytes in the string.
/// The string is NOT null-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_error_msg(
    error: *const line_sender_error,
    len_out: *mut size_t,
) -> *const c_char {
    unsafe {
        let msg: &str = (*error).error.msg();
        *len_out = msg.len();
        msg.as_ptr() as *const c_char
    }
}

/// Clean up the error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_error_free(error: *mut line_sender_error) {
    unsafe {
        if !error.is_null() {
            drop(Box::from_raw(error));
        }
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

#[cold]
unsafe fn set_err_out_from_error(err_out: *mut *mut line_sender_error, err: Error) {
    unsafe { set_err_out_from_error_with_qwpws(err_out, err, None) };
}

#[cold]
unsafe fn set_err_out_from_error_with_qwpws(
    err_out: *mut *mut line_sender_error,
    err: Error,
    qwp_ws_error: Option<QwpWsSenderError>,
) {
    // `err_out` is optional in the C API; avoid allocating when the caller
    // intentionally discards error details.
    if !err_out.is_null() {
        let err_ptr = Box::into_raw(Box::new(line_sender_error {
            error: err,
            qwp_ws_error,
        }));
        unsafe {
            *err_out = err_ptr;
        }
    }
}

#[cold]
unsafe fn set_err_out_from_sender_error(
    err_out: *mut *mut line_sender_error,
    sender: &Sender,
    err: Error,
) {
    if err_out.is_null() {
        return;
    }
    let qwp_ws_error = err
        .qwp_ws_rejection()
        .cloned()
        .or_else(|| sender.qwp_ws_terminal_error().ok().flatten());
    unsafe { set_err_out_from_error_with_qwpws(err_out, err, qwp_ws_error) };
}

#[cold]
unsafe fn set_err_out(err_out: *mut *mut line_sender_error, code: ErrorCode, msg: String) {
    if !err_out.is_null() {
        unsafe { set_err_out_from_error(err_out, Error::new(code, msg)) };
    }
}

fn describe_utf8_error(buf: &[u8], u8err: str::Utf8Error) -> String {
    let buf_descr = describe_buf(buf);
    if let Some(_err_len) = u8err.error_len() {
        format!(
            concat!(
                "Bad string \"{}\": Invalid UTF-8. ",
                "Illegal codepoint starting at byte index {}."
            ),
            buf_descr,
            u8err.valid_up_to()
        )
    } else {
        format!(
            concat!(
                "Bad string \"{}\": Invalid UTF-8. Incomplete ",
                "multi-byte codepoint at end of string. ",
                "Bad codepoint starting at byte index {}."
            ),
            buf_descr,
            u8err.valid_up_to()
        )
    }
}

fn unwrap_utf8_or_str(buf: &[u8]) -> Result<&str, String> {
    str::from_utf8(buf).map_err(|u8err| describe_utf8_error(buf, u8err))
}

unsafe fn unwrap_utf8(buf: &[u8], err_out: *mut *mut line_sender_error) -> Option<&str> {
    match str::from_utf8(buf) {
        Ok(str_ref) => Some(str_ref),
        Err(u8err) => {
            if !err_out.is_null() {
                let msg = describe_utf8_error(buf, u8err);
                unsafe { set_err_out(err_out, ErrorCode::InvalidUtf8, msg) };
            }
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_utf8_init(
    string: *mut line_sender_utf8,
    len: size_t,
    buf: *const c_char,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let slice = slice::from_raw_parts(buf as *const u8, len);
        if let Some(str_ref) = unwrap_utf8(slice, err_out) {
            (*string).len = str_ref.len();
            (*string).buf = str_ref.as_ptr() as *const c_char;
            true
        } else {
            false
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_utf8_assert(
    len: size_t,
    buf: *const c_char,
) -> line_sender_utf8 {
    unsafe {
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
        unsafe {
            let str_name =
                str::from_utf8_unchecked(slice::from_raw_parts(self.buf as *const u8, self.len));
            TableName::new_unchecked(str_name)
        }
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
    fn as_name<'a>(&self) -> ColumnName<'a> {
        unsafe {
            let str_name =
                str::from_utf8_unchecked(slice::from_raw_parts(self.buf as *const u8, self.len));
            ColumnName::new_unchecked(str_name)
        }
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_table_name_init(
    name: *mut line_sender_table_name,
    len: size_t,
    buf: *const c_char,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
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
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_table_name_assert(
    len: size_t,
    buf: *const c_char,
) -> line_sender_table_name {
    unsafe {
        let u8str = line_sender_utf8_assert(len, buf);
        match TableName::new(u8str.as_str()) {
            Ok(_) => line_sender_table_name { len, buf },
            Err(msg) => {
                panic!("{}", msg);
            }
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_column_name_init(
    name: *mut line_sender_column_name,
    len: size_t,
    buf: *const c_char,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
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
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_column_name_assert(
    len: size_t,
    buf: *const c_char,
) -> line_sender_column_name {
    unsafe {
        let u8str = line_sender_utf8_assert(len, buf);
        match ColumnName::new(u8str.as_str()) {
            Ok(_) => line_sender_column_name { len, buf },
            Err(msg) => {
                panic!("{}", msg);
            }
        }
    }
}

/// Accumulates a batch of rows to be sent via `line_sender_flush()` or its
/// variants. A buffer object can be reused after flushing and clearing.
pub struct line_sender_buffer {
    buffer: Buffer,
    empty_peek_buf_is_null: bool,
}

/// Opaque rollback handle captured from a buffer.
///
/// This is the stable C ABI v1 layout. Do not change field order or width
/// without a breaking version bump.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct line_sender_bookmark {
    origin: u64,
    generation: u64,
}

impl From<ingress::Bookmark> for line_sender_bookmark {
    fn from(bookmark: ingress::Bookmark) -> Self {
        Self {
            origin: bookmark.origin(),
            generation: bookmark.generation(),
        }
    }
}

impl From<line_sender_bookmark> for ingress::Bookmark {
    fn from(bookmark: line_sender_bookmark) -> Self {
        ingress::Bookmark::from_raw(bookmark.origin, bookmark.generation)
    }
}

/// Construct an ILP `line_sender_buffer` with a `max_name_len` of `127`, which
/// is the same as the QuestDB server default.
///
/// This constructor is ILP-only. It does not create QWP/UDP buffers.
/// For protocol-neutral construction, prefer `line_sender_buffer_new_for_sender`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_new(
    version: ProtocolVersion,
) -> *mut line_sender_buffer {
    let buffer = Buffer::new(version.into());
    Box::into_raw(Box::new(line_sender_buffer {
        buffer,
        empty_peek_buf_is_null: false,
    }))
}

/// Construct an ILP `line_sender_buffer` with a custom maximum length for table
/// and column names. This should match the `cairo.max.file.name.length`
/// setting of the QuestDB server you're connecting to.
///
/// This constructor is ILP-only. It does not create QWP/UDP buffers.
/// For protocol-neutral construction, prefer `line_sender_buffer_new_for_sender`.
///
/// If the server does not configure it, the default is `127`, and you can
/// call `line_sender_buffer_new()` instead.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_with_max_name_len(
    version: ProtocolVersion,
    max_name_len: size_t,
) -> *mut line_sender_buffer {
    let buffer = Buffer::with_max_name_len(version.into(), max_name_len);
    Box::into_raw(Box::new(line_sender_buffer {
        buffer,
        empty_peek_buf_is_null: false,
    }))
}

/// Construct a QWP/UDP `line_sender_buffer` with a `max_name_len` of `127`,
/// which is the same as the QuestDB server default.
///
/// This constructor is only available when QWP/UDP support is enabled.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_new_qwp() -> *mut line_sender_buffer {
    let buffer = Buffer::new_qwp();
    Box::into_raw(Box::new(line_sender_buffer {
        buffer,
        empty_peek_buf_is_null: true,
    }))
}

/// Construct a QWP/UDP `line_sender_buffer` with a custom maximum length for
/// table and column names.
///
/// This constructor is only available when QWP/UDP support is enabled.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_new_qwp_with_max_name_len(
    max_name_len: size_t,
) -> *mut line_sender_buffer {
    let buffer = Buffer::qwp_with_max_name_len(max_name_len);
    Box::into_raw(Box::new(line_sender_buffer {
        buffer,
        empty_peek_buf_is_null: true,
    }))
}

/// Release the `line_sender_buffer` object.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_free(buffer: *mut line_sender_buffer) {
    unsafe {
        if !buffer.is_null() {
            drop(Box::from_raw(buffer));
        }
    }
}

unsafe fn unwrap_buffer<'a>(buffer: *const line_sender_buffer) -> &'a Buffer {
    unsafe { &(*buffer).buffer }
}

unsafe fn unwrap_buffer_mut<'a>(buffer: *mut line_sender_buffer) -> &'a mut Buffer {
    unsafe { &mut (*buffer).buffer }
}

/// Create a new copy of the buffer.
///
/// Returns NULL and populates `err_out` if `buffer` is NULL or if the
/// underlying clone panics (e.g. allocation failure).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_clone(
    buffer: *const line_sender_buffer,
    err_out: *mut *mut line_sender_error,
) -> *mut line_sender_buffer {
    if buffer.is_null() {
        unsafe {
            set_err_out(
                err_out,
                ErrorCode::InvalidApiCall,
                "line_sender_buffer_clone requires a non-NULL buffer".to_owned(),
            );
        }
        return ptr::null_mut();
    }
    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        let src = &*buffer;
        Box::into_raw(Box::new(line_sender_buffer {
            buffer: src.buffer.clone(),
            empty_peek_buf_is_null: src.empty_peek_buf_is_null,
        }))
    }));
    match result {
        Ok(ptr) => ptr,
        Err(_) => {
            unsafe {
                set_err_out(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    "line_sender_buffer_clone panicked".to_owned(),
                );
            }
            ptr::null_mut()
        }
    }
}

/// Pre-allocate to ensure the buffer has enough capacity for at least the
/// specified additional byte count. This may be rounded up.
/// This does not allocate if such additional capacity is already satisfied.
///
/// For ILP buffers this is expressed in bytes. For QWP buffers this is only a
/// best-effort hint and may be ignored.
///
/// Returns true on success. Returns false and populates `err_out` if `buffer`
/// is NULL or if the underlying allocator panics (e.g. capacity overflow).
///
/// See: `capacity`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_reserve(
    buffer: *mut line_sender_buffer,
    additional: size_t,
    err_out: *mut *mut line_sender_error,
) -> bool {
    if buffer.is_null() {
        unsafe {
            set_err_out(
                err_out,
                ErrorCode::InvalidApiCall,
                "line_sender_buffer_reserve requires a non-NULL buffer".to_owned(),
            );
        }
        return false;
    }
    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        unwrap_buffer_mut(buffer).reserve(additional);
    }));
    match result {
        Ok(()) => true,
        Err(_) => {
            unsafe {
                set_err_out(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    "line_sender_buffer_reserve panicked (likely capacity overflow)".to_owned(),
                );
            }
            false
        }
    }
}

/// Get the current buffer capacity.
///
/// For ILP buffers this is the number of bytes available before reallocation.
/// For QWP buffers this is an implementation-defined capacity hint and should
/// not be interpreted as byte capacity.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_capacity(buffer: *const line_sender_buffer) -> size_t {
    unsafe { unwrap_buffer(buffer).capacity() }
}

/// Capture a bookmark for the current buffer state.
///
/// `buffer` must be non-NULL. `out` must be non-NULL on success; passing NULL
/// returns false and sets `err_out` if provided. `err_out` is optional.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_bookmark(
    buffer: *mut line_sender_buffer,
    out: *mut line_sender_bookmark,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        if out.is_null() {
            set_err_out(
                err_out,
                ErrorCode::InvalidApiCall,
                "line_sender_buffer_bookmark `out` must be non-NULL.".to_owned(),
            );
            return false;
        }
        let buffer = unwrap_buffer_mut(buffer);
        let bookmark = bubble_err_to_c!(err_out, buffer.bookmark());
        *out = bookmark.into();
        true
    }
}

/// Rewind the buffer to a previously captured bookmark.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_rewind_to_bookmark(
    buffer: *mut line_sender_buffer,
    bookmark: line_sender_bookmark,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let buffer = unwrap_buffer_mut(buffer);
        bubble_err_to_c!(err_out, buffer.rewind_to_bookmark(bookmark.into()));
        true
    }
}

/// Clear a previously captured bookmark if it is still current.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_clear_bookmark(
    buffer: *mut line_sender_buffer,
    bookmark: line_sender_bookmark,
) {
    unsafe {
        let buffer = unwrap_buffer_mut(buffer);
        buffer.clear_bookmark(bookmark.into());
    }
}

/// Mark a rewind point.
/// This allows undoing accumulated changes to the buffer for one or more
/// rows by calling `rewind_to_marker`.
/// Any previously stored rewind point will be discarded, including one
/// established by `line_sender_buffer_bookmark`.
/// Once the marker is no longer needed, call `clear_marker`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_set_marker(
    buffer: *mut line_sender_buffer,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let buffer = unwrap_buffer_mut(buffer);
        bubble_err_to_c!(err_out, buffer.set_marker());
        true
    }
}

/// Undo all changes since the currently stored rewind point was captured.
///
/// This may rewind a state established by either `line_sender_buffer_set_marker`
/// or `line_sender_buffer_bookmark`.
///
/// As a side-effect, this also clears the stored rewind point.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_rewind_to_marker(
    buffer: *mut line_sender_buffer,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let buffer = unwrap_buffer_mut(buffer);
        bubble_err_to_c!(err_out, buffer.rewind_to_marker());
        true
    }
}

/// Discard the marker.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_clear_marker(buffer: *mut line_sender_buffer) {
    unsafe {
        let buffer = unwrap_buffer_mut(buffer);
        buffer.clear_marker();
    }
}

/// Remove all accumulated data and prepare the buffer for new lines.
/// This does not affect the buffer's capacity.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_clear(buffer: *mut line_sender_buffer) {
    unsafe {
        let buffer = unwrap_buffer_mut(buffer);
        buffer.clear();
    }
}

/// The current encoded size of the buffered data.
///
/// For ILP buffers this is the exact pending byte length. For QWP buffers this
/// is a buffered size hint, not the exact size of any eventual UDP datagram.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_size(buffer: *const line_sender_buffer) -> size_t {
    unsafe {
        let buffer = unwrap_buffer(buffer);
        buffer.len()
    }
}

/// The number of rows accumulated in the buffer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_row_count(buffer: *const line_sender_buffer) -> size_t {
    unsafe {
        let buffer = unwrap_buffer(buffer);
        buffer.row_count()
    }
}

/// Tell whether the buffer is transactional.
///
/// ILP buffers are transactional iff they contain data for at most one table.
/// QWP/UDP does not support transactional flushes, so QWP buffers always return
/// `false`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_transactional(
    buffer: *const line_sender_buffer,
) -> bool {
    unsafe {
        let buffer = unwrap_buffer(buffer);
        buffer.transactional()
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct line_sender_buffer_view {
    len: size_t,
    buf: *const u8,
}

/// Provides a read-only view into the buffer's bytes content.
///
/// This is only meaningful for ILP buffers, where rows are accumulated in
/// serialized form. For QWP buffers the return value is currently empty because
/// rows are encoded into UDP datagrams only during flush.
///
/// @param[in] buffer Line buffer object.
/// @return A [`line_sender_buffer_view`] struct containing:
/// - `buf`: Immutable pointer to the byte stream
/// - `len`: Exact byte length of the data for ILP, or zero for QWP
///
/// For QWP buffers this returns an empty view with `len == 0` and `buf == NULL`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_peek(
    buffer: *const line_sender_buffer,
) -> line_sender_buffer_view {
    unsafe {
        let buffer = &*buffer;
        let buf: &[u8] = buffer.buffer.as_bytes();
        line_sender_buffer_view {
            len: buf.len(),
            buf: if buf.is_empty() && buffer.empty_peek_buf_is_null {
                ptr::null()
            } else {
                buf.as_ptr()
            },
        }
    }
}

/// Start recording a new row for the given table.
/// @param[in] buffer Line buffer object.
/// @param[in] name Table name.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_table(
    buffer: *mut line_sender_buffer,
    name: line_sender_table_name,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let buffer = unwrap_buffer_mut(buffer);
        bubble_err_to_c!(err_out, buffer.table(name.as_name()));
        true
    }
}

/// Record a symbol value for the given column.
/// Make sure you record all the symbol columns before any other column type.
/// @param[in] buffer Line buffer object.
/// @param[in] name Column name.
/// @param[in] value Column value.
/// @param[out] err_out Set on error.
/// @return true on success, false on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_symbol(
    buffer: *mut line_sender_buffer,
    name: line_sender_column_name,
    value: line_sender_utf8,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let buffer = unwrap_buffer_mut(buffer);
        bubble_err_to_c!(err_out, buffer.symbol(name.as_name(), value.as_str()));
        true
    }
}

/// Record a boolean value for the given column.
/// @param[in] buffer Line buffer object.
/// @param[in] name Column name.
/// @param[in] value Column value.
/// @param[out] err_out Set on error.
/// @return true on success, false on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_column_bool(
    buffer: *mut line_sender_buffer,
    name: line_sender_column_name,
    value: bool,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let buffer = unwrap_buffer_mut(buffer);
        bubble_err_to_c!(err_out, buffer.column_bool(name.as_name(), value));
        true
    }
}

/// Record an integer value for the given column.
/// @param[in] buffer Line buffer object.
/// @param[in] name Column name.
/// @param[in] value Column value.
/// @param[out] err_out Set on error.
/// @return true on success, false on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_column_i64(
    buffer: *mut line_sender_buffer,
    name: line_sender_column_name,
    value: i64,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let buffer = unwrap_buffer_mut(buffer);
        bubble_err_to_c!(err_out, buffer.column_i64(name.as_name(), value));
        true
    }
}

/// Record a floating-point value for the given column.
/// @param[in] buffer Line buffer object.
/// @param[in] name Column name.
/// @param[in] value Column value.
/// @param[out] err_out Set on error.
/// @return true on success, false on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_column_f64(
    buffer: *mut line_sender_buffer,
    name: line_sender_column_name,
    value: f64,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let buffer = unwrap_buffer_mut(buffer);
        bubble_err_to_c!(err_out, buffer.column_f64(name.as_name(), value));
        true
    }
}

/// Record a string value for the given column.
/// @param[in] buffer Line buffer object.
/// @param[in] name Column name.
/// @param[in] value Column value.
/// @param[out] err_out Set on error.
/// @return true on success, false on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_column_str(
    buffer: *mut line_sender_buffer,
    name: line_sender_column_name,
    value: line_sender_utf8,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let buffer = unwrap_buffer_mut(buffer);
        let name = name.as_name();
        let value = value.as_str();
        bubble_err_to_c!(err_out, buffer.column_str(name, value));
        true
    }
}

/// Record a decimal string value for the given column.
///
/// When specifying a decimal as a string, use a '.' to separate the whole from the
/// fractional parts. For example, "12.20".
/// Infinity is encoded as "+Infinity" or "-Infinity", while NaN as "NaN".
/// Note that Infinity and NaN values decay to nulls when stored in the database.
///
/// @param[in] buffer Line buffer object.
/// @param[in] name Column name.
/// @param[in] value Column value.
/// @param[out] err_out Set on error.
/// @return true on success, false on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_column_dec_str(
    buffer: *mut line_sender_buffer,
    name: line_sender_column_name,
    value: *mut c_char,
    value_len: size_t,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let buffer = unsafe { unwrap_buffer_mut(buffer) };
    let name = name.as_name();
    let value = unsafe { slice::from_raw_parts(value as *const u8, value_len) };
    // Basic validation: ensure only numerical characters are present (accepts NaN, Inf[inity], and e-notation)
    for b in value.iter() {
        match b {
            b'0'..=b'9'
            | b'.'
            | b'-'
            | b'+'
            | b'e'
            | b'E'
            | b'N'
            | b'a'
            | b'I'
            | b'n'
            | b'f'
            | b'i'
            | b't'
            | b'y' => {}
            _ => {
                if !err_out.is_null() {
                    unsafe {
                        set_err_out_from_error(
                            err_out,
                            questdb::Error::new(
                                questdb::ErrorCode::InvalidDecimal,
                                format!("Decimal string contains invalid character {:?}", b),
                            ),
                        );
                    }
                }
                return false;
            }
        }
    }
    let value = unsafe { str::from_utf8_unchecked(value) };
    unsafe {
        bubble_err_to_c!(
            err_out,
            buffer.column_dec(name, DecimalView::String { value })
        );
    }
    true
}

/// Record a decimal value for the given column.
///
/// There is no equivalent of NaN or Infinity when specifying decimals in binary format.
/// Those special values have no meaning for decimals and should be encoded as nulls instead.
///
/// @param[in] buffer Line buffer object.
/// @param[in] name Column name.
/// @param[in] scale Number of digits after the decimal point
/// @param[in] data Unscaled value in two's complement format, big-endian
/// @param[in] data_len Length of the unscaled value array
/// @param[out] err_out Set on error.
/// @return true on success, false on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_column_dec(
    buffer: *mut line_sender_buffer,
    name: line_sender_column_name,
    scale: u32,
    data: *const u8,
    data_len: size_t,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let data = if data.is_null() {
            &[]
        } else {
            slice::from_raw_parts(data, data_len)
        };
        let buffer = unwrap_buffer_mut(buffer);
        let name = name.as_name();
        let decimal = bubble_err_to_c!(err_out, DecimalView::try_new_scaled(scale, data));
        bubble_err_to_c!(err_out, buffer.column_dec(name, decimal));
    }
    true
}

/// Records a float64 multidimensional array with **C-MAJOR memory layout**.
///
/// @param[in] buffer Line buffer object.
/// @param[in] name Column name.
/// @param[in] rank Array dims.
/// @param[in] shape Array shape.
/// @param[in] data Array **first element** data memory ptr.
/// @param[in] data_len Array data length.
/// @param[out] err_out Set on error.
/// # Safety
/// - All pointer parameters must be valid and non-null
/// - shape must point to an array of `rank` integers
/// - data must point to a buffer of size `data_len` f64 elements.
/// - QuestDB server version 9.0.0 or later is required for array support.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_column_f64_arr_c_major(
    buffer: *mut line_sender_buffer,
    name: line_sender_column_name,
    rank: size_t,
    shape: *const usize,
    data: *const f64,
    data_len: size_t,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let buffer = unwrap_buffer_mut(buffer);
        let name = name.as_name();
        let view = match CMajorArrayView::<f64>::new(rank, shape, data, data_len) {
            Ok(value) => value,
            Err(err) => {
                set_err_out_from_error(err_out, err);
                return false;
            }
        };
        bubble_err_to_c!(
            err_out,
            buffer.column_arr::<ColumnName<'_>, CMajorArrayView<'_, f64>, f64>(name, &view)
        );
        true
    }
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
/// @param[in] data Array **first element** data memory ptr.
/// @param[in] data_len Array data element length.
/// @param[out] err_out Set on error.
/// # Safety
/// - All pointer parameters must be valid and non-null
/// - shape must point to an array of `rank` integers
/// - data must point to a buffer of size `data_len` f64 elements.
/// - QuestDB server version 9.0.0 or later is required for array support.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_column_f64_arr_byte_strides(
    buffer: *mut line_sender_buffer,
    name: line_sender_column_name,
    rank: size_t,
    shape: *const usize,
    strides: *const isize,
    data: *const f64,
    data_len: size_t,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let buffer = unwrap_buffer_mut(buffer);
        let name = name.as_name();
        generate_array_dims_branches!(
            rank,
            1,
            shape,
            strides,
            data,
            data_len,
            err_out,
            buffer,
            name
            => 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
        );
        true
    }
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
/// @param[in] data Array **first element** data memory ptr.
/// @param[in] data_len Array data element length.
/// @param[out] err_out Set on error.
/// # Safety
/// - All pointer parameters must be valid and non-null
/// - shape must point to an array of `rank` integers
/// - data must point to a buffer of size `data_len` f64 elements.
/// - QuestDB server version 9.0.0 or later is required for array support.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_column_f64_arr_elem_strides(
    buffer: *mut line_sender_buffer,
    name: line_sender_column_name,
    rank: size_t,
    shape: *const usize,
    strides: *const isize,
    data: *const f64,
    data_len: size_t,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let buffer = unwrap_buffer_mut(buffer);
        let name = name.as_name();
        generate_array_dims_branches!(
            rank,
            8,
            shape,
            strides,
            data,
            data_len,
            err_out,
            buffer,
            name
            => 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
        );
        true
    }
}

/// Record a nanosecond timestamp value for the given column.
/// @param[in] buffer Line buffer object.
/// @param[in] name Column name.
/// @param[in] nanos The timestamp in nanoseconds before or since the unix epoch.
/// @param[out] err_out Set on error.
/// @return true on success, false on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_column_ts_nanos(
    buffer: *mut line_sender_buffer,
    name: line_sender_column_name,
    nanos: i64,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let buffer = unwrap_buffer_mut(buffer);
        let timestamp = TimestampNanos::new(nanos);
        bubble_err_to_c!(err_out, buffer.column_ts(name.as_name(), timestamp));
        true
    }
}

/// Record a microsecond timestamp value for the given column.
/// @param[in] buffer Line buffer object.
/// @param[in] name Column name.
/// @param[in] micros The timestamp in microseconds before or since the unix epoch.
/// @param[out] err_out Set on error.
/// @return true on success, false on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_column_ts_micros(
    buffer: *mut line_sender_buffer,
    name: line_sender_column_name,
    micros: i64,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let buffer = unwrap_buffer_mut(buffer);
        let timestamp = TimestampMicros::new(micros);
        bubble_err_to_c!(err_out, buffer.column_ts(name.as_name(), timestamp));
        true
    }
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_at_nanos(
    buffer: *mut line_sender_buffer,
    epoch_nanos: i64,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let buffer = unwrap_buffer_mut(buffer);
        let timestamp = TimestampNanos::new(epoch_nanos);
        bubble_err_to_c!(err_out, buffer.at(timestamp));
        true
    }
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_at_micros(
    buffer: *mut line_sender_buffer,
    epoch_micros: i64,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let buffer = unwrap_buffer_mut(buffer);
        let timestamp = TimestampMicros::new(epoch_micros);
        bubble_err_to_c!(err_out, buffer.at(timestamp));
        true
    }
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_at_now(
    buffer: *mut line_sender_buffer,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let buffer = unwrap_buffer_mut(buffer);
        bubble_err_to_c!(err_out, buffer.at_now());
        true
    }
}

/**
 * Check whether the buffer is ready to be flushed.
 * If this returns false, the buffer is incomplete and cannot be sent,
 * and an error message is set to indicate the problem.
 */
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_check_can_flush(
    buffer: *const line_sender_buffer,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let buffer = unwrap_buffer(buffer);
        bubble_err_to_c!(err_out, buffer.check_can_flush());
        true
    }
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_opts_from_conf(
    config: line_sender_utf8,
    err_out: *mut *mut line_sender_error,
) -> *mut line_sender_opts {
    unsafe {
        let config = config.as_str();
        let builder = bubble_err_to_c!(err_out, SenderBuilder::from_conf(config), ptr::null_mut());
        let builder = with_c_qwp_ws_default_error_handler(builder);
        Box::into_raw(Box::new(line_sender_opts(builder)))
    }
}

/// Create a new `line_sender_opts` instance from the configuration stored in the
/// `QDB_CLIENT_CONF` environment variable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_opts_from_env(
    err_out: *mut *mut line_sender_error,
) -> *mut line_sender_opts {
    unsafe {
        let builder = bubble_err_to_c!(err_out, SenderBuilder::from_env(), ptr::null_mut());
        let builder = with_c_qwp_ws_default_error_handler(builder);
        Box::into_raw(Box::new(line_sender_opts(builder)))
    }
}

/// Create a new `line_sender_opts` instance with the given protocol, hostname and
/// port.
/// @param[in] protocol The protocol to use.
/// @param[in] host The QuestDB database host.
/// @param[in] port The QuestDB ILP TCP port.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_opts_new(
    protocol: line_sender_protocol,
    host: line_sender_utf8,
    port: u16,
) -> *mut line_sender_opts {
    let builder = SenderBuilder::new(protocol.into(), host.as_str(), port);
    let builder = match builder.user_agent(concat!("questdb/c/", env!("CARGO_PKG_VERSION"))) {
        Ok(builder) => builder,
        Err(_) => return ptr::null_mut(),
    };
    let builder = with_c_qwp_ws_default_error_handler(builder);
    Box::into_raw(Box::new(line_sender_opts(builder)))
}

/// Create a new `line_sender_opts` instance with the given protocol, hostname and
/// service name.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_opts_new_service(
    protocol: line_sender_protocol,
    host: line_sender_utf8,
    port: line_sender_utf8,
) -> *mut line_sender_opts {
    let builder = SenderBuilder::new(protocol.into(), host.as_str(), port.as_str());
    let builder = match builder.user_agent(concat!("questdb/c/", env!("CARGO_PKG_VERSION"))) {
        Ok(builder) => builder,
        Err(_) => return ptr::null_mut(),
    };
    let builder = with_c_qwp_ws_default_error_handler(builder);
    Box::into_raw(Box::new(line_sender_opts(builder)))
}

/// Select local outbound network "bind" interface.
///
/// This may be relevant if your machine has multiple network interfaces.
///
/// The default is `0.0.0.0`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_opts_bind_interface(
    opts: *mut line_sender_opts,
    bind_interface: line_sender_utf8,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe { upd_opts!(opts, err_out, bind_interface, bind_interface.as_str()) }
}

/// Set the maximum QWP/UDP datagram size in bytes.
///
/// `max_datagram_size` must be between 1 and 65,507 bytes, inclusive. Values
/// outside this range are rejected. The upper bound is the UDP/IPv4 payload
/// limit, not a recommended operating size. The default is 1,400 bytes, leaving
/// room for IPv4 and UDP headers under a common 1,500-byte Ethernet MTU. If you
/// raise this value, keep it within the effective UDP payload budget for the
/// path MTU. Oversized IPv4 packets may be fragmented when fragmentation is
/// allowed, or dropped when it is not; fragmented UDP is fragile because losing
/// any fragment loses the whole datagram.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_opts_max_datagram_size(
    opts: *mut line_sender_opts,
    max_datagram_size: size_t,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe { upd_opts!(opts, err_out, max_datagram_size, max_datagram_size) }
}

/// Set the multicast TTL used for QWP/UDP sends.
///
/// The default is 1. Use a value greater than 0 when sending to a multicast
/// address. A value of 0 prevents multicast datagrams from leaving the local
/// host.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_opts_multicast_ttl(
    opts: *mut line_sender_opts,
    multicast_ttl: u32,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe { upd_opts!(opts, err_out, multicast_ttl, multicast_ttl) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_opts_qwpws_progress(
    opts: *mut line_sender_opts,
    progress: line_sender_qwpws_progress,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let progress = match progress {
        line_sender_qwpws_progress::LINE_SENDER_QWPWS_PROGRESS_BACKGROUND => {
            RustQwpWsProgress::Background
        }
        line_sender_qwpws_progress::LINE_SENDER_QWPWS_PROGRESS_MANUAL => RustQwpWsProgress::Manual,
    };
    unsafe { upd_opts!(opts, err_out, qwp_ws_progress, progress) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_opts_qwpws_error_handler(
    opts: *mut line_sender_opts,
    cb: line_sender_qwpws_error_cb,
    user_data: *mut c_void,
    err_out: *mut *mut line_sender_error,
) -> bool {
    ffi_catch_bool(err_out, || unsafe {
        if opts.is_null() {
            set_err_out(
                err_out,
                ErrorCode::InvalidApiCall,
                "line_sender_opts_qwpws_error_handler requires non-NULL opts".to_string(),
            );
            return false;
        }
        let builder_ref: &mut SenderBuilder = &mut (*opts).0;
        let current = builder_ref.clone();
        let new_builder = match cb {
            Some(cb) => {
                let user_data = user_data as usize;
                current.qwp_ws_error_handler(move |error| {
                    let view = qwp_ws_sender_error_view(error);
                    ffi_invoke_c_callback("qwp_ws_error_handler", || {
                        cb(user_data as *mut c_void, &view);
                    });
                })
            }
            None => current.qwp_ws_error_handler(c_default_qwp_ws_error_handler),
        };
        match new_builder {
            Ok(new_builder) => {
                *builder_ref = new_builder;
                true
            }
            Err(err) => {
                set_err_out_from_error(err_out, err);
                false
            }
        }
    })
}

/// Set the username for authentication.
///
/// For TCP, this is the `kid` part of the ECDSA key set.
/// The other fields are `token` `token_x` and `token_y`.
///
/// For HTTP, this is part of basic authentication.
/// See also: `line_sender_opts_password()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_opts_username(
    opts: *mut line_sender_opts,
    username: line_sender_utf8,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe { upd_opts!(opts, err_out, username, username.as_str()) }
}

/// Set the password for basic HTTP authentication.
/// See also: `line_sender_opts_username()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_opts_password(
    opts: *mut line_sender_opts,
    password: line_sender_utf8,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe { upd_opts!(opts, err_out, password, password.as_str()) }
}

/// Set the Token (Bearer) Authentication parameter for HTTP,
/// or the ECDSA private key for TCP authentication.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_opts_token(
    opts: *mut line_sender_opts,
    token: line_sender_utf8,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe { upd_opts!(opts, err_out, token, token.as_str()) }
}

/// Set the ECDSA public key X for TCP authentication.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_opts_token_x(
    opts: *mut line_sender_opts,
    token_x: line_sender_utf8,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe { upd_opts!(opts, err_out, token_x, token_x.as_str()) }
}

/// Set the ECDSA public key Y for TCP authentication.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_opts_token_y(
    opts: *mut line_sender_opts,
    token_y: line_sender_utf8,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe { upd_opts!(opts, err_out, token_y, token_y.as_str()) }
}

/// Sets the ingestion protocol version.
/// - HTTP transport automatically negotiates the protocol version by default(unset, **Strong Recommended**).
///   You can explicitly configure the protocol version to avoid the slight latency cost at connection time.
/// - TCP transport does not negotiate the protocol version and uses [`ProtocolVersion::V1`] by
///   default. You must explicitly set [`ProtocolVersion::V2`] in order to ingest
///   arrays.
///
/// QuestDB server version 9.0.0 or later is required for [`ProtocolVersion::V2`] support
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_opts_protocol_version(
    opts: *mut line_sender_opts,
    version: ProtocolVersion,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe { upd_opts!(opts, err_out, protocol_version, version.into()) }
}

/// Configure how long to wait for messages from the QuestDB server during
/// the TLS handshake and authentication process.
/// The value is in milliseconds, and the default is 15 seconds.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_opts_auth_timeout(
    opts: *mut line_sender_opts,
    timeout_millis: u64,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let timeout = std::time::Duration::from_millis(timeout_millis);
        upd_opts!(opts, err_out, auth_timeout, timeout)
    }
}

/// Set to `false` to disable TLS certificate verification.
/// This should only be used for debugging purposes as it reduces security.
///
/// For testing consider specifying a path to a `.pem` file instead via
/// the `tls_roots` setting.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_opts_tls_verify(
    opts: *mut line_sender_opts,
    verify: bool,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe { upd_opts!(opts, err_out, tls_verify, verify) }
}

/// Specify where to find the certificate authority used to validate
/// the validate the server's TLS certificate.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_opts_tls_ca(
    opts: *mut line_sender_opts,
    ca: line_sender_ca,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let ca: CertificateAuthority = ca.into();
        upd_opts!(opts, err_out, tls_ca, ca)
    }
}

/// Set the path to a custom root certificate `.pem` file.
/// This is used to validate the server's certificate during the TLS handshake.
///
/// See notes on how to test with [self-signed
/// certificates](https://github.com/questdb/c-questdb-client/tree/main/tls_certs).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_opts_tls_roots(
    opts: *mut line_sender_opts,
    path: line_sender_utf8,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let path = PathBuf::from(path.as_str());
        upd_opts!(opts, err_out, tls_roots, path)
    }
}

/// Set the maximum buffered size that the client will flush to the server.
/// The default is 100 MiB.
///
/// For ILP this applies to the exact pending byte length.
/// For QWP/UDP this applies to the buffer size hint returned by
/// `line_sender_buffer_size()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_opts_max_buf_size(
    opts: *mut line_sender_opts,
    max_buf_size: size_t,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe { upd_opts!(opts, err_out, max_buf_size, max_buf_size) }
}

/// Ser the maximum length of a table or column name in bytes.
/// The default is 127 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_opts_max_name_len(
    opts: *mut line_sender_opts,
    max_name_len: size_t,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe { upd_opts!(opts, err_out, max_name_len, max_name_len) }
}

/// Set the cumulative duration spent in retries.
/// The value is in milliseconds, and the default is 10 seconds.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_opts_retry_timeout(
    opts: *mut line_sender_opts,
    millis: u64,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let retry_timeout = std::time::Duration::from_millis(millis);
        upd_opts!(opts, err_out, retry_timeout, retry_timeout)
    }
}

/// Set the minimum acceptable throughput while sending a buffer to the server.
/// The sender will divide the payload size by this number to determine for how
/// long to keep sending the payload before timing out.
/// The value is in bytes per second, and the default is 100 KiB/s.
/// The timeout calculated from minimum throughput is adedd to the value of
/// `request_timeout`.
///
/// See also: `line_sender_opts_request_timeout()`
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_opts_request_min_throughput(
    opts: *mut line_sender_opts,
    bytes_per_sec: u64,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe { upd_opts!(opts, err_out, request_min_throughput, bytes_per_sec) }
}

/// Set the additional time to wait on top of that calculated from the minimum
/// throughput. This accounts for the fixed latency of the HTTP request-response
/// roundtrip. The value is in milliseconds, and the default is 10 seconds.
///
/// See also: `line_sender_opts_request_min_throughput()`
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_opts_request_timeout(
    opts: *mut line_sender_opts,
    millis: u64,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let request_timeout = std::time::Duration::from_millis(millis);
        upd_opts!(opts, err_out, request_timeout, request_timeout)
    }
}

/// Set the HTTP user agent. Internal API. Do not use.
#[doc(hidden)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_opts_user_agent(
    opts: *mut line_sender_opts,
    user_agent: line_sender_utf8,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe { upd_opts!(opts, err_out, user_agent, user_agent.as_str()) }
}

/// Duplicate the `line_sender_opts` object.
/// Both old and new objects will have to be freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_opts_clone(
    opts: *const line_sender_opts,
) -> *mut line_sender_opts {
    unsafe {
        if opts.is_null() {
            return ptr::null_mut();
        }
        let builder = &(*opts).0;
        let new_builder = builder.clone();
        Box::into_raw(Box::new(line_sender_opts(new_builder)))
    }
}

/// Release the `line_sender_opts` object.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_opts_free(opts: *mut line_sender_opts) {
    unsafe {
        if !opts.is_null() {
            drop(Box::from_raw(opts));
        }
    }
}

/// Inserts data into QuestDB via the InfluxDB Line Protocol.
///
/// Batch up rows in a `line_sender_buffer`, then call `line_sender_flush()` or
/// one of its variants with this object to send them.
pub struct line_sender(Sender);

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum line_sender_qwpws_progress {
    LINE_SENDER_QWPWS_PROGRESS_BACKGROUND = 0,
    LINE_SENDER_QWPWS_PROGRESS_MANUAL = 1,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct line_sender_qwpws_fsn {
    has_value: bool,
    value: u64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum line_sender_qwpws_error_category {
    LINE_SENDER_QWPWS_ERROR_SCHEMA_MISMATCH = 0,
    LINE_SENDER_QWPWS_ERROR_PARSE_ERROR = 1,
    LINE_SENDER_QWPWS_ERROR_INTERNAL_ERROR = 2,
    LINE_SENDER_QWPWS_ERROR_SECURITY_ERROR = 3,
    LINE_SENDER_QWPWS_ERROR_WRITE_ERROR = 4,
    LINE_SENDER_QWPWS_ERROR_PROTOCOL_VIOLATION = 5,
    LINE_SENDER_QWPWS_ERROR_UNKNOWN = 6,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum line_sender_qwpws_error_policy {
    LINE_SENDER_QWPWS_ERROR_DROP_AND_CONTINUE = 0,
    LINE_SENDER_QWPWS_ERROR_HALT = 1,
}

pub struct line_sender_qwpws_error {
    category: line_sender_qwpws_error_category,
    applied_policy: line_sender_qwpws_error_policy,
    status: Option<u8>,
    message_sequence: Option<u64>,
    from_fsn: u64,
    to_fsn: u64,
    message: Vec<u8>,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct line_sender_qwpws_error_view {
    category: line_sender_qwpws_error_category,
    applied_policy: line_sender_qwpws_error_policy,
    has_status: bool,
    status: u8,
    has_message_sequence: bool,
    message_sequence: u64,
    from_fsn: u64,
    to_fsn: u64,
    message: *const c_char,
    message_len: size_t,
}

impl From<RustQwpWsErrorCategory> for line_sender_qwpws_error_category {
    fn from(category: RustQwpWsErrorCategory) -> Self {
        match category {
            RustQwpWsErrorCategory::SchemaMismatch => {
                line_sender_qwpws_error_category::LINE_SENDER_QWPWS_ERROR_SCHEMA_MISMATCH
            }
            RustQwpWsErrorCategory::ParseError => {
                line_sender_qwpws_error_category::LINE_SENDER_QWPWS_ERROR_PARSE_ERROR
            }
            RustQwpWsErrorCategory::InternalError => {
                line_sender_qwpws_error_category::LINE_SENDER_QWPWS_ERROR_INTERNAL_ERROR
            }
            RustQwpWsErrorCategory::SecurityError => {
                line_sender_qwpws_error_category::LINE_SENDER_QWPWS_ERROR_SECURITY_ERROR
            }
            RustQwpWsErrorCategory::WriteError => {
                line_sender_qwpws_error_category::LINE_SENDER_QWPWS_ERROR_WRITE_ERROR
            }
            RustQwpWsErrorCategory::ProtocolViolation => {
                line_sender_qwpws_error_category::LINE_SENDER_QWPWS_ERROR_PROTOCOL_VIOLATION
            }
            RustQwpWsErrorCategory::Unknown => {
                line_sender_qwpws_error_category::LINE_SENDER_QWPWS_ERROR_UNKNOWN
            }
            _ => line_sender_qwpws_error_category::LINE_SENDER_QWPWS_ERROR_UNKNOWN,
        }
    }
}

impl From<RustQwpWsErrorPolicy> for line_sender_qwpws_error_policy {
    fn from(policy: RustQwpWsErrorPolicy) -> Self {
        match policy {
            RustQwpWsErrorPolicy::DropAndContinue => {
                line_sender_qwpws_error_policy::LINE_SENDER_QWPWS_ERROR_DROP_AND_CONTINUE
            }
            RustQwpWsErrorPolicy::Halt => {
                line_sender_qwpws_error_policy::LINE_SENDER_QWPWS_ERROR_HALT
            }
            _ => line_sender_qwpws_error_policy::LINE_SENDER_QWPWS_ERROR_HALT,
        }
    }
}

impl From<QwpWsSenderError> for line_sender_qwpws_error {
    fn from(error: QwpWsSenderError) -> Self {
        Self {
            category: error.category.into(),
            applied_policy: error.applied_policy.into(),
            status: error.status,
            message_sequence: error.message_sequence,
            from_fsn: error.from_fsn,
            to_fsn: error.to_fsn,
            message: error.message.unwrap_or_default().into_bytes(),
        }
    }
}

impl line_sender_qwpws_error {
    fn view(&self) -> line_sender_qwpws_error_view {
        let message = if self.message.is_empty() {
            ptr::null()
        } else {
            self.message.as_ptr() as *const c_char
        };
        line_sender_qwpws_error_view {
            category: self.category,
            applied_policy: self.applied_policy,
            has_status: self.status.is_some(),
            status: self.status.unwrap_or(0),
            has_message_sequence: self.message_sequence.is_some(),
            message_sequence: self.message_sequence.unwrap_or(0),
            from_fsn: self.from_fsn,
            to_fsn: self.to_fsn,
            message,
            message_len: self.message.len(),
        }
    }
}

fn qwp_ws_sender_error_view(error: &QwpWsSenderError) -> line_sender_qwpws_error_view {
    let message = error.message.as_deref();
    let message_ptr = message.map_or(ptr::null(), |message| {
        if message.is_empty() {
            ptr::null()
        } else {
            message.as_ptr() as *const c_char
        }
    });
    line_sender_qwpws_error_view {
        category: error.category.into(),
        applied_policy: error.applied_policy.into(),
        has_status: error.status.is_some(),
        status: error.status.unwrap_or(0),
        has_message_sequence: error.message_sequence.is_some(),
        message_sequence: error.message_sequence.unwrap_or(0),
        from_fsn: error.from_fsn,
        to_fsn: error.to_fsn,
        message: message_ptr,
        message_len: message.map_or(0, |message| message.len()),
    }
}

fn c_default_qwp_ws_error_handler(error: &QwpWsSenderError) {
    let level = if error.applied_policy == RustQwpWsErrorPolicy::Halt {
        "ERROR"
    } else {
        "WARN"
    };
    let status = error
        .status
        .map(|status| format!("0x{status:02x}"))
        .unwrap_or_else(|| "none".to_string());
    let sequence = error
        .message_sequence
        .map(|sequence| sequence.to_string())
        .unwrap_or_else(|| "none".to_string());
    eprintln!(
        "[questdb {level}] QWP/WebSocket server rejected batch category={:?} policy={:?} status={} fsn=[{},{}] seq={} msg={}",
        error.category,
        error.applied_policy,
        status,
        error.from_fsn,
        error.to_fsn,
        sequence,
        error.message.as_deref().unwrap_or("")
    );
}

fn with_c_qwp_ws_default_error_handler(builder: SenderBuilder) -> SenderBuilder {
    builder
        .qwp_ws_error_handler(c_default_qwp_ws_error_handler)
        .expect("installing C default QWP/WebSocket error handler must not fail")
}

pub type line_sender_qwpws_error_cb =
    Option<unsafe extern "C" fn(*mut c_void, *const line_sender_qwpws_error_view)>;

impl line_sender_qwpws_fsn {
    fn from_option(fsn: Option<u64>) -> Self {
        Self {
            has_value: fsn.is_some(),
            value: fsn.unwrap_or(0),
        }
    }
}

/// Outbound FFI panic boundary for bool-returning extern "C" functions.
///
/// Wraps the body of a `pub extern "C" fn` so a Rust panic surfaces as
/// `false` + `err_out = InvalidApiCall` instead of unwinding across the
/// `extern "C"` boundary (UB on stable rustc, process abort with `panic=abort`).
fn ffi_catch_bool<F>(err_out: *mut *mut line_sender_error, f: F) -> bool
where
    F: FnOnce() -> bool,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(value) => value,
        Err(_) => {
            unsafe {
                set_err_out(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    "FFI call panicked".to_string(),
                );
            }
            false
        }
    }
}

/// Inbound FFI panic boundary for user-supplied callbacks.
///
/// Wraps the invocation of a C callback (the `cb(user_data, …)` step inside a
/// Rust trampoline) so a panic doesn't unwind back across the `extern "C"`
/// boundary into the user's code. Void-returning callbacks have no err_out
/// channel; the panic is logged to stderr and swallowed.
fn ffi_invoke_c_callback<F>(label: &str, f: F)
where
    F: FnOnce(),
{
    if catch_unwind(AssertUnwindSafe(f)).is_err() {
        let _ = writeln!(
            io::stderr(),
            "[questdb ERROR] {label} C callback panicked; panic swallowed at FFI boundary"
        );
    }
}

unsafe fn qwpws_line_sender_ref<'a>(
    sender: *const line_sender,
    err_out: *mut *mut line_sender_error,
    function: &str,
) -> Option<&'a Sender> {
    if sender.is_null() {
        unsafe {
            set_err_out(
                err_out,
                ErrorCode::InvalidApiCall,
                format!("{function} requires a non-NULL sender"),
            );
        }
        return None;
    }
    Some(unsafe { &(*sender).0 })
}

unsafe fn qwpws_line_sender_mut<'a>(
    sender: *mut line_sender,
    err_out: *mut *mut line_sender_error,
    function: &str,
) -> Option<&'a mut Sender> {
    if sender.is_null() {
        unsafe {
            set_err_out(
                err_out,
                ErrorCode::InvalidApiCall,
                format!("{function} requires a non-NULL sender"),
            );
        }
        return None;
    }
    Some(unsafe { &mut (*sender).0 })
}

unsafe fn qwpws_buffer_ptr_ref<'a>(
    buffer: *const line_sender_buffer,
    err_out: *mut *mut line_sender_error,
    function: &str,
) -> Option<&'a Buffer> {
    if buffer.is_null() {
        unsafe {
            set_err_out(
                err_out,
                ErrorCode::InvalidApiCall,
                format!("{function} requires a non-NULL buffer"),
            );
        }
        return None;
    }
    Some(unsafe { &(*buffer).buffer })
}

unsafe fn qwpws_buffer_ptr_mut<'a>(
    buffer: *mut line_sender_buffer,
    err_out: *mut *mut line_sender_error,
    function: &str,
) -> Option<&'a mut Buffer> {
    if buffer.is_null() {
        unsafe {
            set_err_out(
                err_out,
                ErrorCode::InvalidApiCall,
                format!("{function} requires a non-NULL buffer"),
            );
        }
        return None;
    }
    Some(unsafe { &mut (*buffer).buffer })
}

/// Create a new line sender instance from the given options object.
///
/// In the case of TCP, this synchronously establishes the TCP connection, and
/// returns once the connection is fully established. If the connection
/// requires authentication or TLS, these will also be completed before
/// returning.
///
/// The sender should be accessed by only a single thread a time.
///
/// @param[in] opts Options for the connection. Must be non-NULL.
/// The caller retains ownership of `opts` and must release it with
/// `line_sender_opts_free` when it is no longer needed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_build(
    opts: *const line_sender_opts,
    err_out: *mut *mut line_sender_error,
) -> *mut line_sender {
    unsafe {
        let builder = &(*opts).0;
        let sender = bubble_err_to_c!(err_out, builder.build(), ptr::null_mut());
        Box::into_raw(Box::new(line_sender(sender)))
    }
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_from_conf(
    config: line_sender_utf8,
    err_out: *mut *mut line_sender_error,
) -> *mut line_sender {
    unsafe {
        let config = config.as_str();
        let builder = bubble_err_to_c!(err_out, SenderBuilder::from_conf(config), ptr::null_mut());
        let builder = bubble_err_to_c!(
            err_out,
            builder.user_agent(concat!("questdb/c/", env!("CARGO_PKG_VERSION"))),
            ptr::null_mut()
        );
        let builder = with_c_qwp_ws_default_error_handler(builder);
        let sender = bubble_err_to_c!(err_out, builder.build(), ptr::null_mut());
        Box::into_raw(Box::new(line_sender(sender)))
    }
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_from_env(
    err_out: *mut *mut line_sender_error,
) -> *mut line_sender {
    unsafe {
        let builder = bubble_err_to_c!(err_out, SenderBuilder::from_env(), ptr::null_mut());
        let builder = bubble_err_to_c!(
            err_out,
            builder.user_agent(concat!("questdb/c/", env!("CARGO_PKG_VERSION"))),
            ptr::null_mut()
        );
        let builder = with_c_qwp_ws_default_error_handler(builder);
        let sender = bubble_err_to_c!(err_out, builder.build(), ptr::null_mut());
        Box::into_raw(Box::new(line_sender(sender)))
    }
}

unsafe fn unwrap_sender<'a>(sender: *const line_sender) -> &'a Sender {
    unsafe { &(*sender).0 }
}

unsafe fn unwrap_sender_mut<'a>(sender: *mut line_sender) -> &'a mut Sender {
    unsafe { &mut (*sender).0 }
}

/// Return the sender's configured transport protocol.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_get_protocol(
    sender: *const line_sender,
) -> line_sender_protocol {
    unsafe { unwrap_sender(sender).protocol().into() }
}

/// Returns the sender's ILP protocol version
///
/// This is meaningful for ILP senders. For protocol-neutral inspection, use
/// [`line_sender_get_protocol`]. Do not use this value to construct QWP/UDP
/// buffers; use [`line_sender_buffer_new_for_sender`] instead.
/// For QWP/UDP senders this reports the QWP datagram version, currently
/// represented as [`ProtocolVersion::V1`]; it is not an ILP feature version.
///
/// - Explicitly set version, or
/// - Auto-detected during HTTP transport, or
/// - [`ProtocolVersion::V1`] for TCP transport.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_get_protocol_version(
    sender: *const line_sender,
) -> ProtocolVersion {
    unsafe { unwrap_sender(sender).protocol_version().into() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_get_max_name_len(sender: *const line_sender) -> size_t {
    unsafe { unwrap_sender(sender).max_name_len() }
}

/// Construct a [`line_sender_buffer`] using the sender's protocol settings.
///
/// This is the preferred protocol-neutral buffer constructor. It may produce a
/// different buffer implementation than `line_sender_buffer_new(...)`, for
/// example when the sender uses QWP-over-UDP.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_new_for_sender(
    sender: *const line_sender,
) -> *mut line_sender_buffer {
    unsafe {
        let sender = unwrap_sender(sender);
        let buffer = sender.new_buffer();
        let empty_peek_buf_is_null = matches!(
            sender.protocol(),
            Protocol::QwpUdp | Protocol::QwpWs | Protocol::QwpWss
        );
        Box::into_raw(Box::new(line_sender_buffer {
            buffer,
            empty_peek_buf_is_null,
        }))
    }
}

/// Tell whether the sender is no longer usable and must be closed.
/// This happens when there was an earlier failure.
/// This fuction is specific to TCP and is not relevant for HTTP.
/// @param[in] sender Line sender object.
/// @return true if an error occurred with a sender and it must be closed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_must_close(sender: *const line_sender) -> bool {
    unsafe { unwrap_sender(sender).must_close() }
}

/// Close the connection. Does not flush. Non-idempotent.
/// @param[in] sender Line sender object.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_close(sender: *mut line_sender) {
    unsafe {
        if !sender.is_null() {
            drop(Box::from_raw(sender));
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_qwpws_flush_and_get_fsn(
    sender: *mut line_sender,
    buffer: *mut line_sender_buffer,
    fsn_out: *mut line_sender_qwpws_fsn,
    err_out: *mut *mut line_sender_error,
) -> bool {
    ffi_catch_bool(err_out, || unsafe {
        if fsn_out.is_null() {
            set_err_out(
                err_out,
                ErrorCode::InvalidApiCall,
                "line_sender_qwpws_flush_and_get_fsn requires non-NULL fsn_out".to_string(),
            );
            return false;
        }
        let Some(sender) =
            qwpws_line_sender_mut(sender, err_out, "line_sender_qwpws_flush_and_get_fsn")
        else {
            return false;
        };
        let Some(buffer) =
            qwpws_buffer_ptr_mut(buffer, err_out, "line_sender_qwpws_flush_and_get_fsn")
        else {
            return false;
        };
        match sender.flush_and_get_fsn(buffer) {
            Ok(fsn) => {
                *fsn_out = line_sender_qwpws_fsn::from_option(fsn);
                true
            }
            Err(err) => {
                set_err_out_from_sender_error(err_out, sender, err);
                false
            }
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_qwpws_flush_and_keep_and_get_fsn(
    sender: *mut line_sender,
    buffer: *const line_sender_buffer,
    fsn_out: *mut line_sender_qwpws_fsn,
    err_out: *mut *mut line_sender_error,
) -> bool {
    ffi_catch_bool(err_out, || unsafe {
        if fsn_out.is_null() {
            set_err_out(
                err_out,
                ErrorCode::InvalidApiCall,
                "line_sender_qwpws_flush_and_keep_and_get_fsn requires non-NULL fsn_out"
                    .to_string(),
            );
            return false;
        }
        let Some(sender) = qwpws_line_sender_mut(
            sender,
            err_out,
            "line_sender_qwpws_flush_and_keep_and_get_fsn",
        ) else {
            return false;
        };
        let Some(buffer) = qwpws_buffer_ptr_ref(
            buffer,
            err_out,
            "line_sender_qwpws_flush_and_keep_and_get_fsn",
        ) else {
            return false;
        };
        match sender.flush_and_keep_and_get_fsn(buffer) {
            Ok(fsn) => {
                *fsn_out = line_sender_qwpws_fsn::from_option(fsn);
                true
            }
            Err(err) => {
                set_err_out_from_sender_error(err_out, sender, err);
                false
            }
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_qwpws_drive_once(
    sender: *mut line_sender,
    progressed_out: *mut bool,
    err_out: *mut *mut line_sender_error,
) -> bool {
    ffi_catch_bool(err_out, || unsafe {
        if progressed_out.is_null() {
            set_err_out(
                err_out,
                ErrorCode::InvalidApiCall,
                "line_sender_qwpws_drive_once requires non-NULL progressed_out".to_string(),
            );
            return false;
        }
        let Some(sender) = qwpws_line_sender_mut(sender, err_out, "line_sender_qwpws_drive_once")
        else {
            return false;
        };
        match sender.drive_once() {
            Ok(progressed) => {
                *progressed_out = progressed;
                true
            }
            Err(err) => {
                set_err_out_from_sender_error(err_out, sender, err);
                false
            }
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_qwpws_published_fsn(
    sender: *const line_sender,
    fsn_out: *mut line_sender_qwpws_fsn,
    err_out: *mut *mut line_sender_error,
) -> bool {
    ffi_catch_bool(err_out, || unsafe {
        if fsn_out.is_null() {
            set_err_out(
                err_out,
                ErrorCode::InvalidApiCall,
                "line_sender_qwpws_published_fsn requires non-NULL fsn_out".to_string(),
            );
            return false;
        }
        let Some(sender) =
            qwpws_line_sender_ref(sender, err_out, "line_sender_qwpws_published_fsn")
        else {
            return false;
        };
        match sender.published_fsn() {
            Ok(fsn) => {
                *fsn_out = line_sender_qwpws_fsn::from_option(fsn);
                true
            }
            Err(err) => {
                set_err_out_from_sender_error(err_out, sender, err);
                false
            }
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_qwpws_acked_fsn(
    sender: *const line_sender,
    fsn_out: *mut line_sender_qwpws_fsn,
    err_out: *mut *mut line_sender_error,
) -> bool {
    ffi_catch_bool(err_out, || unsafe {
        if fsn_out.is_null() {
            set_err_out(
                err_out,
                ErrorCode::InvalidApiCall,
                "line_sender_qwpws_acked_fsn requires non-NULL fsn_out".to_string(),
            );
            return false;
        }
        let Some(sender) = qwpws_line_sender_ref(sender, err_out, "line_sender_qwpws_acked_fsn")
        else {
            return false;
        };
        match sender.acked_fsn() {
            Ok(fsn) => {
                *fsn_out = line_sender_qwpws_fsn::from_option(fsn);
                true
            }
            Err(err) => {
                set_err_out_from_sender_error(err_out, sender, err);
                false
            }
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_qwpws_await_acked_fsn(
    sender: *mut line_sender,
    fsn: u64,
    timeout_millis: u64,
    reached_out: *mut bool,
    err_out: *mut *mut line_sender_error,
) -> bool {
    ffi_catch_bool(err_out, || unsafe {
        if reached_out.is_null() {
            set_err_out(
                err_out,
                ErrorCode::InvalidApiCall,
                "line_sender_qwpws_await_acked_fsn requires non-NULL reached_out".to_string(),
            );
            return false;
        }
        let Some(sender) =
            qwpws_line_sender_mut(sender, err_out, "line_sender_qwpws_await_acked_fsn")
        else {
            return false;
        };
        match sender.await_acked_fsn(fsn, Duration::from_millis(timeout_millis)) {
            Ok(reached) => {
                *reached_out = reached;
                true
            }
            Err(err) => {
                set_err_out_from_sender_error(err_out, sender, err);
                false
            }
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_qwpws_poll_error(
    sender: *mut line_sender,
    error_out: *mut *mut line_sender_qwpws_error,
    err_out: *mut *mut line_sender_error,
) -> bool {
    ffi_catch_bool(err_out, || unsafe {
        if error_out.is_null() {
            set_err_out(
                err_out,
                ErrorCode::InvalidApiCall,
                "line_sender_qwpws_poll_error requires non-NULL error_out".to_string(),
            );
            return false;
        }
        *error_out = ptr::null_mut();
        let Some(sender) = qwpws_line_sender_mut(sender, err_out, "line_sender_qwpws_poll_error")
        else {
            return false;
        };
        match sender.poll_qwp_ws_error() {
            Ok(Some(error)) => {
                *error_out = Box::into_raw(Box::new(error.into()));
                true
            }
            Ok(None) => true,
            Err(err) => {
                set_err_out_from_sender_error(err_out, sender, err);
                false
            }
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_qwpws_error_get_view(
    error: *const line_sender_qwpws_error,
) -> line_sender_qwpws_error_view {
    let Some(error) = (unsafe { error.as_ref() }) else {
        return line_sender_qwpws_error_view {
            category: line_sender_qwpws_error_category::LINE_SENDER_QWPWS_ERROR_UNKNOWN,
            applied_policy: line_sender_qwpws_error_policy::LINE_SENDER_QWPWS_ERROR_HALT,
            has_status: false,
            status: 0,
            has_message_sequence: false,
            message_sequence: 0,
            from_fsn: 0,
            to_fsn: 0,
            message: ptr::null(),
            message_len: 0,
        };
    };
    error.view()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_error_qwpws_get_view(
    error: *const line_sender_error,
    view_out: *mut line_sender_qwpws_error_view,
) -> bool {
    if error.is_null() || view_out.is_null() {
        return false;
    }
    let Some(qwp_ws_error) = (unsafe { (*error).qwp_ws_error.as_ref() }) else {
        return false;
    };
    unsafe {
        *view_out = qwp_ws_sender_error_view(qwp_ws_error);
    }
    true
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_qwpws_error_free(error: *mut line_sender_qwpws_error) {
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        if !error.is_null() {
            drop(Box::from_raw(error));
        }
    }));
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_qwpws_errors_dropped(
    sender: *const line_sender,
    dropped_out: *mut u64,
    err_out: *mut *mut line_sender_error,
) -> bool {
    ffi_catch_bool(err_out, || unsafe {
        if dropped_out.is_null() {
            set_err_out(
                err_out,
                ErrorCode::InvalidApiCall,
                "line_sender_qwpws_errors_dropped requires non-NULL dropped_out".to_string(),
            );
            return false;
        }
        let Some(sender) =
            qwpws_line_sender_ref(sender, err_out, "line_sender_qwpws_errors_dropped")
        else {
            return false;
        };
        match sender.qwp_ws_errors_dropped() {
            Ok(dropped) => {
                *dropped_out = dropped;
                true
            }
            Err(err) => {
                set_err_out_from_sender_error(err_out, sender, err);
                false
            }
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_qwpws_close_drain(
    sender: *mut line_sender,
    err_out: *mut *mut line_sender_error,
) -> bool {
    ffi_catch_bool(err_out, || unsafe {
        let Some(sender) = qwpws_line_sender_mut(sender, err_out, "line_sender_qwpws_close_drain")
        else {
            return false;
        };
        match sender.close_drain() {
            Ok(()) => true,
            Err(err) => {
                set_err_out_from_sender_error(err_out, sender, err);
                false
            }
        }
    })
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
/// With QWP-over-UDP, the function sends one or more UDP datagrams and returns
/// local socket errors only. A successful return does not guarantee delivery, and
/// when a flush spans multiple datagrams there is no all-or-nothing guarantee for
/// the logical batch.
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_flush(
    sender: *mut line_sender,
    buffer: *mut line_sender_buffer,
    err_out: *mut *mut line_sender_error,
) -> bool {
    ffi_catch_bool(err_out, || unsafe {
        let sender = unwrap_sender_mut(sender);
        let buffer = unwrap_buffer_mut(buffer);
        match sender.flush(buffer) {
            Ok(()) => true,
            Err(err) => {
                set_err_out_from_sender_error(err_out, sender, err);
                false
            }
        }
    })
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_flush_and_keep(
    sender: *mut line_sender,
    buffer: *const line_sender_buffer,
    err_out: *mut *mut line_sender_error,
) -> bool {
    ffi_catch_bool(err_out, || unsafe {
        let sender = unwrap_sender_mut(sender);
        let buffer = unwrap_buffer(buffer);
        match sender.flush_and_keep(buffer) {
            Ok(()) => true,
            Err(err) => {
                set_err_out_from_sender_error(err_out, sender, err);
                false
            }
        }
    })
}

/// Send the batch of rows in the buffer to the QuestDB server, and, if the parameter
/// `transactional` is true, ensure the flush will be transactional.
///
/// A flush is transactional iff all the rows belong to the same table. This allows
/// QuestDB to treat the flush as a single database transaction, because it doesn't
/// support transactions spanning multiple tables. Additionally, only ILP-over-HTTP
/// supports transactional flushes; QWP/UDP is a best-effort datagram transport and
/// has no flush-level atomicity guarantee.
///
/// If the flush wouldn't be transactional, this function returns an error and
/// doesn't flush any data.
///
/// The function sends an HTTP request and waits for the response. If the server
/// responds with an error, it returns a descriptive error. In the case of a network
/// error, it retries until it has exhausted the retry time budget.
///
/// All the data stays in the buffer. Clear the buffer before starting a new batch.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_flush_and_keep_with_flags(
    sender: *mut line_sender,
    buffer: *const line_sender_buffer,
    transactional: bool,
    err_out: *mut *mut line_sender_error,
) -> bool {
    ffi_catch_bool(err_out, || unsafe {
        let sender = unwrap_sender_mut(sender);
        let buffer = unwrap_buffer(buffer);
        match sender.flush_and_keep_with_flags(buffer, transactional) {
            Ok(()) => true,
            Err(err) => {
                set_err_out_from_sender_error(err_out, sender, err);
                false
            }
        }
    })
}

/// Get the current time in nanoseconds since the Unix epoch (UTC).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_now_nanos() -> i64 {
    TimestampNanos::now().as_i64()
}

/// Get the current time in microseconds since the Unix epoch (UTC).
#[unsafe(no_mangle)]
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
    unsafe {
        use questdb_confstr_ffi::questdb_conf_str_parse_err_free;
        questdb_conf_str_parse_err_free(err);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;

    const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    const FIRST_WIRE_SEQUENCE: u64 = 0;
    const QWP_STATUS_PARSE_ERROR: u8 = 0x05;

    fn free_err(err: &mut *mut line_sender_error) {
        unsafe {
            line_sender_error_free(*err);
        }
        *err = ptr::null_mut();
    }

    fn assert_err_code(actual: line_sender_error_code, expected: line_sender_error_code) {
        assert_eq!(actual as u32, expected as u32);
    }

    #[test]
    fn line_sender_error_code_discriminants_are_abi_stable() {
        // Pin numeric values exposed to C/FFI consumers (questdb-py via
        // ctypes/cffi, Go cgo, Java FFM) that cache them. New variants must
        // be appended to preserve the ABI.
        use line_sender_error_code::*;
        let expected: &[(line_sender_error_code, u32)] = &[
            (line_sender_error_could_not_resolve_addr, 0),
            (line_sender_error_invalid_api_call, 1),
            (line_sender_error_socket_error, 2),
            (line_sender_error_invalid_utf8, 3),
            (line_sender_error_invalid_name, 4),
            (line_sender_error_invalid_timestamp, 5),
            (line_sender_error_auth_error, 6),
            (line_sender_error_tls_error, 7),
            (line_sender_error_http_not_supported, 8),
            (line_sender_error_server_flush_error, 9),
            (line_sender_error_config_error, 10),
            (line_sender_error_array_error, 11),
            (line_sender_error_protocol_version_error, 12),
            (line_sender_error_invalid_decimal, 13),
            // New since 6.1.0 — must remain at the tail.
            (line_sender_error_server_rejection, 14),
        ];
        for (variant, want) in expected {
            assert_eq!(
                *variant as u32, *want,
                "{:?} discriminant changed — appended-only ABI broken",
                variant,
            );
        }
    }

    // ---- C5 regression: FFI panic boundaries ----

    /// `ffi_catch_bool` must convert a Rust panic into `false` + `err_out`
    /// rather than unwinding across the `extern "C"` boundary into the C
    /// caller (UB on stable rustc; process abort with `panic=abort`).
    #[test]
    fn ffi_catch_bool_converts_panic_to_err_out() {
        unsafe {
            let mut err: *mut line_sender_error = ptr::null_mut();
            let result = ffi_catch_bool(&mut err, || panic!("simulated panic"));
            assert!(!result, "panicking closure must return false");
            assert!(!err.is_null(), "err_out must be populated");
            assert_err_code(
                line_sender_error_get_code(err),
                line_sender_error_code::line_sender_error_invalid_api_call,
            );
            free_err(&mut err);
        }
    }

    /// `ffi_catch_bool` must be transparent for non-panicking closures —
    /// no spurious err_out, return value preserved.
    #[test]
    fn ffi_catch_bool_is_transparent_when_no_panic() {
        let mut err: *mut line_sender_error = ptr::null_mut();
        let result_true = ffi_catch_bool(&mut err, || true);
        assert!(result_true);
        assert!(err.is_null());

        let result_false = ffi_catch_bool(&mut err, || false);
        assert!(!result_false);
        assert!(err.is_null());
    }

    /// `ffi_invoke_c_callback` must swallow a Rust panic raised inside the
    /// closure rather than letting it unwind back to the trampoline caller.
    /// The void-returning callback contract has no err_out channel; the helper
    /// returns normally and logs to stderr.
    ///
    /// Note: this test exercises panics in *Rust code* invoked from inside the
    /// helper's closure — which is the case that catch_unwind can actually
    /// catch. A panic from inside an `extern "C"` callback aborts the process
    /// at the ABI boundary (stable rustc treats `extern "C"` as nounwind);
    /// `catch_unwind` cannot intervene before that abort, so we don't claim to
    /// test that case here. The genuine protection against a panicking
    /// callback comes from the outer `ffi_catch_bool` on the FFI entry point
    /// (`line_sender_flush*`), which catches Rust-side panics that the closure
    /// caused indirectly without crossing an `extern "C"` frame.
    #[test]
    fn ffi_invoke_c_callback_swallows_panic() {
        ffi_invoke_c_callback("test_callback", || {
            panic!("simulated panic inside trampoline closure");
        });
    }

    fn utf8(bytes: &'static [u8]) -> line_sender_utf8 {
        line_sender_utf8 {
            len: bytes.len(),
            buf: bytes.as_ptr() as *const c_char,
        }
    }

    fn table_name(bytes: &'static [u8]) -> line_sender_table_name {
        unsafe { line_sender_table_name_assert(bytes.len(), bytes.as_ptr() as *const c_char) }
    }

    fn column_name(bytes: &'static [u8]) -> line_sender_column_name {
        unsafe { line_sender_column_name_assert(bytes.len(), bytes.as_ptr() as *const c_char) }
    }

    fn read_view_message(view: line_sender_qwpws_error_view) -> Vec<u8> {
        if view.message.is_null() {
            return Vec::new();
        }
        unsafe { std::slice::from_raw_parts(view.message as *const u8, view.message_len).to_vec() }
    }

    fn read_error_message(err: *const line_sender_error) -> String {
        unsafe {
            let mut len = 0;
            let ptr = line_sender_error_msg(err, &mut len);
            let bytes = std::slice::from_raw_parts(ptr as *const u8, len);
            String::from_utf8_lossy(bytes).into_owned()
        }
    }

    fn blank_qwpws_error_view() -> line_sender_qwpws_error_view {
        line_sender_qwpws_error_view {
            category: line_sender_qwpws_error_category::LINE_SENDER_QWPWS_ERROR_UNKNOWN,
            applied_policy: line_sender_qwpws_error_policy::LINE_SENDER_QWPWS_ERROR_HALT,
            has_status: false,
            status: 0,
            has_message_sequence: false,
            message_sequence: 0,
            from_fsn: 0,
            to_fsn: 0,
            message: ptr::null(),
            message_len: 0,
        }
    }

    fn assert_parse_halt_diagnostic(view: line_sender_qwpws_error_view) {
        assert_eq!(
            view.category,
            line_sender_qwpws_error_category::LINE_SENDER_QWPWS_ERROR_PARSE_ERROR
        );
        assert_eq!(
            view.applied_policy,
            line_sender_qwpws_error_policy::LINE_SENDER_QWPWS_ERROR_HALT
        );
        assert!(view.has_status);
        assert_eq!(view.status, QWP_STATUS_PARSE_ERROR);
        assert!(view.has_message_sequence);
        assert_eq!(view.message_sequence, FIRST_WIRE_SEQUENCE);
        assert_eq!(view.from_fsn, 0);
        assert_eq!(view.to_fsn, 0);
        assert_eq!(read_view_message(view), b"ffi bad line");
    }

    #[derive(Default)]
    struct CallbackState {
        calls: AtomicU64,
        category: AtomicU64,
        policy: AtomicU64,
        from_fsn: AtomicU64,
        to_fsn: AtomicU64,
    }

    unsafe extern "C" fn record_qwpws_error(
        user_data: *mut libc::c_void,
        view: *const line_sender_qwpws_error_view,
    ) {
        let state = unsafe { &*(user_data as *const CallbackState) };
        let view = unsafe { &*view };
        state.calls.fetch_add(1, Ordering::SeqCst);
        state.category.store(view.category as u64, Ordering::SeqCst);
        state
            .policy
            .store(view.applied_policy as u64, Ordering::SeqCst);
        state.from_fsn.store(view.from_fsn, Ordering::SeqCst);
        state.to_fsn.store(view.to_fsn, Ordering::SeqCst);
    }

    fn read_request_until_blank(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 256];
        loop {
            let n = stream.read(&mut tmp)?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        Ok(buf)
    }

    fn parse_header(req: &str, name: &str) -> Option<String> {
        for line in req.split("\r\n").skip(1) {
            if let Some((key, value)) = line.split_once(':')
                && key.trim().eq_ignore_ascii_case(name)
            {
                return Some(value.trim().to_string());
            }
        }
        None
    }

    fn base64_encode(input: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
        for chunk in input.chunks(3) {
            let b0 = chunk[0];
            let b1 = *chunk.get(1).unwrap_or(&0);
            let b2 = *chunk.get(2).unwrap_or(&0);
            out.push(TABLE[(b0 >> 2) as usize] as char);
            out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
            if chunk.len() > 1 {
                out.push(TABLE[(((b1 & 0x0F) << 2) | (b2 >> 6)) as usize] as char);
            } else {
                out.push('=');
            }
            if chunk.len() > 2 {
                out.push(TABLE[(b2 & 0x3F) as usize] as char);
            } else {
                out.push('=');
            }
        }
        out
    }

    fn sha1(input: &[u8]) -> [u8; 20] {
        let (mut h0, mut h1, mut h2, mut h3, mut h4) = (
            0x67452301u32,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0,
        );
        let bit_len = (input.len() as u64).wrapping_mul(8);
        let mut padded = Vec::with_capacity(input.len() + 64);
        padded.extend_from_slice(input);
        padded.push(0x80);
        while padded.len() % 64 != 56 {
            padded.push(0);
        }
        padded.extend_from_slice(&bit_len.to_be_bytes());

        let mut words = [0u32; 80];
        for chunk in padded.chunks_exact(64) {
            for (idx, word) in chunk.chunks_exact(4).enumerate() {
                words[idx] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
            }
            for idx in 16..80 {
                words[idx] = (words[idx - 3] ^ words[idx - 8] ^ words[idx - 14] ^ words[idx - 16])
                    .rotate_left(1);
            }

            let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
            for (idx, &word) in words.iter().enumerate() {
                let (f, k) = match idx {
                    0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                    20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                    40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                    _ => (b ^ c ^ d, 0xCA62C1D6),
                };
                let temp = a
                    .rotate_left(5)
                    .wrapping_add(f)
                    .wrapping_add(e)
                    .wrapping_add(k)
                    .wrapping_add(word);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = temp;
            }
            h0 = h0.wrapping_add(a);
            h1 = h1.wrapping_add(b);
            h2 = h2.wrapping_add(c);
            h3 = h3.wrapping_add(d);
            h4 = h4.wrapping_add(e);
        }

        let mut out = [0u8; 20];
        for (idx, h) in [h0, h1, h2, h3, h4].iter().enumerate() {
            out[idx * 4..idx * 4 + 4].copy_from_slice(&h.to_be_bytes());
        }
        out
    }

    fn compute_accept(key_b64: &str) -> String {
        let combined = format!("{key_b64}{WS_GUID}");
        base64_encode(&sha1(combined.as_bytes()))
    }

    fn upgrade_mock_stream(stream: &mut TcpStream) {
        let req_bytes = read_request_until_blank(stream).unwrap();
        let req = String::from_utf8_lossy(&req_bytes);
        let key = parse_header(&req, "Sec-WebSocket-Key").expect("missing Sec-WebSocket-Key");
        let accept = compute_accept(&key);
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {accept}\r\n\
             X-QWP-Version: 1\r\n\
             \r\n"
        );
        stream.write_all(response.as_bytes()).unwrap();
    }

    fn read_frame(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
        let mut header = [0u8; 2];
        stream.read_exact(&mut header)?;
        let masked = (header[1] & 0x80) != 0;
        let payload_len = match header[1] & 0x7F {
            126 => {
                let mut bytes = [0u8; 2];
                stream.read_exact(&mut bytes)?;
                u16::from_be_bytes(bytes) as usize
            }
            127 => {
                let mut bytes = [0u8; 8];
                stream.read_exact(&mut bytes)?;
                u64::from_be_bytes(bytes) as usize
            }
            len => len as usize,
        };
        let mut mask = [0u8; 4];
        if masked {
            stream.read_exact(&mut mask)?;
        }
        let mut payload = vec![0u8; payload_len];
        stream.read_exact(&mut payload)?;
        if masked {
            for (idx, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[idx & 3];
            }
        }
        Ok(payload)
    }

    fn write_server_binary_frame(stream: &mut TcpStream, payload: &[u8]) -> std::io::Result<()> {
        let mut frame = vec![0x82];
        let payload_len = payload.len();
        if payload_len <= 125 {
            frame.push(payload_len as u8);
        } else if payload_len <= 0xFFFF {
            frame.push(126);
            frame.extend_from_slice(&(payload_len as u16).to_be_bytes());
        } else {
            frame.push(127);
            frame.extend_from_slice(&(payload_len as u64).to_be_bytes());
        }
        frame.extend_from_slice(payload);
        stream.write_all(&frame)
    }

    fn write_qwp_error_response(
        stream: &mut TcpStream,
        status: u8,
        wire_seq: u64,
        message: &[u8],
    ) -> std::io::Result<()> {
        let mut payload = Vec::new();
        payload.push(status);
        payload.extend_from_slice(&wire_seq.to_le_bytes());
        payload.extend_from_slice(&(message.len() as u16).to_le_bytes());
        payload.extend_from_slice(message);
        write_server_binary_frame(stream, &payload)
    }

    fn new_qwpudp_sender(err: &mut *mut line_sender_error) -> *mut line_sender {
        unsafe {
            let opts = line_sender_opts_new(
                line_sender_protocol::line_sender_protocol_qwpudp,
                utf8(b"127.0.0.1"),
                9009,
            );
            assert!(!opts.is_null());
            let sender = line_sender_build(opts, err);
            line_sender_opts_free(opts);
            assert!(!sender.is_null());
            assert!(err.is_null());
            sender
        }
    }

    #[test]
    fn qwpws_progress_opts_reject_non_websocket_protocol() {
        unsafe {
            let mut err = ptr::null_mut();
            let opts = line_sender_opts_new(
                line_sender_protocol::line_sender_protocol_qwpudp,
                utf8(b"127.0.0.1"),
                9009,
            );
            assert!(!opts.is_null());

            assert!(!line_sender_opts_qwpws_progress(
                opts,
                line_sender_qwpws_progress::LINE_SENDER_QWPWS_PROGRESS_MANUAL,
                &mut err
            ));
            assert!(!err.is_null());
            assert_err_code(
                line_sender_error_get_code(err),
                line_sender_error_code::line_sender_error_config_error,
            );

            free_err(&mut err);
            line_sender_opts_free(opts);
        }
    }

    #[test]
    fn qwpws_fsn_outputs_are_required() {
        unsafe {
            let mut err = ptr::null_mut();
            let sender = new_qwpudp_sender(&mut err);

            assert!(!line_sender_qwpws_published_fsn(
                sender,
                ptr::null_mut(),
                &mut err
            ));
            assert!(!err.is_null());
            assert_err_code(
                line_sender_error_get_code(err),
                line_sender_error_code::line_sender_error_invalid_api_call,
            );

            free_err(&mut err);
            line_sender_close(sender);
        }
    }

    #[test]
    fn qwpws_extensions_reject_non_websocket_sender() {
        unsafe {
            let mut err = ptr::null_mut();
            let sender = new_qwpudp_sender(&mut err);
            let mut fsn = line_sender_qwpws_fsn {
                has_value: true,
                value: u64::MAX,
            };

            assert!(!line_sender_qwpws_published_fsn(sender, &mut fsn, &mut err));
            assert!(!err.is_null());
            assert_err_code(
                line_sender_error_get_code(err),
                line_sender_error_code::line_sender_error_invalid_api_call,
            );
            free_err(&mut err);

            let mut progressed = true;
            assert!(!line_sender_qwpws_drive_once(
                sender,
                &mut progressed,
                &mut err
            ));
            assert!(!err.is_null());
            assert_err_code(
                line_sender_error_get_code(err),
                line_sender_error_code::line_sender_error_invalid_api_call,
            );
            free_err(&mut err);

            let mut reached = true;
            assert!(!line_sender_qwpws_await_acked_fsn(
                sender,
                0,
                0,
                &mut reached,
                &mut err
            ));
            assert!(!err.is_null());
            assert_err_code(
                line_sender_error_get_code(err),
                line_sender_error_code::line_sender_error_invalid_api_call,
            );
            free_err(&mut err);

            let mut dropped = u64::MAX;
            assert!(!line_sender_qwpws_errors_dropped(
                sender,
                &mut dropped,
                &mut err
            ));
            assert!(!err.is_null());
            assert_err_code(
                line_sender_error_get_code(err),
                line_sender_error_code::line_sender_error_invalid_api_call,
            );
            free_err(&mut err);

            assert!(!line_sender_qwpws_close_drain(sender, &mut err));
            assert!(!err.is_null());
            assert_err_code(
                line_sender_error_get_code(err),
                line_sender_error_code::line_sender_error_invalid_api_call,
            );
            free_err(&mut err);

            line_sender_close(sender);
        }
    }

    #[test]
    fn qwpws_poll_error_uses_owned_object_view() {
        let owned = Box::new(line_sender_qwpws_error {
            category: line_sender_qwpws_error_category::LINE_SENDER_QWPWS_ERROR_SCHEMA_MISMATCH,
            applied_policy:
                line_sender_qwpws_error_policy::LINE_SENDER_QWPWS_ERROR_DROP_AND_CONTINUE,
            status: Some(3),
            message_sequence: Some(42),
            from_fsn: 7,
            to_fsn: 9,
            message: b"complete diagnostic".to_vec(),
        });
        let raw = Box::into_raw(owned);

        unsafe {
            let view = line_sender_qwpws_error_get_view(raw);
            assert_eq!(
                view.category,
                line_sender_qwpws_error_category::LINE_SENDER_QWPWS_ERROR_SCHEMA_MISMATCH
            );
            assert_eq!(
                view.applied_policy,
                line_sender_qwpws_error_policy::LINE_SENDER_QWPWS_ERROR_DROP_AND_CONTINUE
            );
            assert!(view.has_status);
            assert_eq!(view.status, 3);
            assert!(view.has_message_sequence);
            assert_eq!(view.message_sequence, 42);
            assert_eq!(view.from_fsn, 7);
            assert_eq!(view.to_fsn, 9);
            assert_eq!(view.message_len, "complete diagnostic".len());
            let message = std::slice::from_raw_parts(view.message as *const u8, view.message_len);
            assert_eq!(message, b"complete diagnostic");

            line_sender_qwpws_error_free(raw);
        }
    }

    #[test]
    fn qwpws_terminal_diagnostic_remains_visible_after_poll() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            upgrade_mock_stream(&mut stream);
            let _ = read_frame(&mut stream).unwrap();
            write_qwp_error_response(
                &mut stream,
                QWP_STATUS_PARSE_ERROR,
                FIRST_WIRE_SEQUENCE,
                b"ffi bad line",
            )
            .unwrap();
            thread::sleep(Duration::from_millis(50));
        });

        unsafe {
            let mut err = ptr::null_mut();
            let callback_state = CallbackState::default();
            let opts = line_sender_opts_new(
                line_sender_protocol::line_sender_protocol_qwpws,
                utf8(b"127.0.0.1"),
                port,
            );
            assert!(!opts.is_null());
            assert!(line_sender_opts_qwpws_error_handler(
                opts,
                Some(record_qwpws_error),
                &callback_state as *const CallbackState as *mut libc::c_void,
                &mut err
            ));
            assert!(err.is_null());
            let sender = line_sender_build(opts, &mut err);
            line_sender_opts_free(opts);
            assert!(!sender.is_null());
            assert!(err.is_null());

            let buffer = line_sender_buffer_new_for_sender(sender);
            assert!(!buffer.is_null());
            assert!(line_sender_buffer_table(
                buffer,
                table_name(b"trades"),
                &mut err
            ));
            assert!(err.is_null());
            assert!(line_sender_buffer_column_i64(
                buffer,
                column_name(b"price"),
                42,
                &mut err
            ));
            assert!(err.is_null());
            assert!(line_sender_buffer_at_now(buffer, &mut err));
            assert!(err.is_null());
            assert!(line_sender_flush(sender, buffer, &mut err));
            assert!(err.is_null());

            let mut polled = false;
            for _ in 0..500 {
                let mut qwp_error = ptr::null_mut();
                assert!(line_sender_qwpws_poll_error(
                    sender,
                    &mut qwp_error,
                    &mut err
                ));
                assert!(err.is_null());
                if !qwp_error.is_null() {
                    let view = line_sender_qwpws_error_get_view(qwp_error);
                    assert_parse_halt_diagnostic(view);
                    line_sender_qwpws_error_free(qwp_error);
                    polled = true;
                    break;
                }
                thread::sleep(Duration::from_millis(10));
            }
            assert!(polled);

            assert!(!line_sender_flush(sender, buffer, &mut err));
            assert!(!err.is_null());
            assert_eq!(callback_state.calls.load(Ordering::SeqCst), 1);
            assert_eq!(
                callback_state.category.load(Ordering::SeqCst),
                line_sender_qwpws_error_category::LINE_SENDER_QWPWS_ERROR_PARSE_ERROR as u64
            );
            assert_eq!(
                callback_state.policy.load(Ordering::SeqCst),
                line_sender_qwpws_error_policy::LINE_SENDER_QWPWS_ERROR_HALT as u64
            );
            assert_eq!(callback_state.from_fsn.load(Ordering::SeqCst), 0);
            assert_eq!(callback_state.to_fsn.load(Ordering::SeqCst), 0);
            let mut view = blank_qwpws_error_view();
            assert!(line_sender_error_qwpws_get_view(err, &mut view));
            assert_parse_halt_diagnostic(view);
            free_err(&mut err);

            assert!(line_sender_buffer_table(
                buffer,
                table_name(b"trades"),
                &mut err
            ));
            assert!(err.is_null());
            assert!(line_sender_buffer_column_i64(
                buffer,
                column_name(b"price"),
                43,
                &mut err
            ));
            assert!(err.is_null());
            assert!(!line_sender_flush(sender, buffer, &mut err));
            assert!(!err.is_null());
            let message = read_error_message(err);
            assert!(
                message.contains("ffi bad line"),
                "terminal error should dominate local buffer validation, got: {message}"
            );
            assert!(
                !message.contains("Bad call to `flush`"),
                "local buffer validation should not mask terminal error: {message}"
            );
            let mut view = blank_qwpws_error_view();
            assert!(line_sender_error_qwpws_get_view(err, &mut view));
            assert_parse_halt_diagnostic(view);
            free_err(&mut err);

            line_sender_buffer_free(buffer);
            line_sender_close(sender);
        }

        server.join().unwrap();
    }

    #[test]
    fn qwpws_terminal_diagnostic_view_rejects_plain_error() {
        let owned = Box::new(line_sender_error {
            error: Error::new(ErrorCode::SocketError, "plain error"),
            qwp_ws_error: None,
        });
        let raw = Box::into_raw(owned);

        unsafe {
            let mut view = blank_qwpws_error_view();
            assert!(!line_sender_error_qwpws_get_view(raw, &mut view));
            assert!(!line_sender_error_qwpws_get_view(raw, ptr::null_mut()));

            line_sender_error_free(raw);
        }
    }
}
