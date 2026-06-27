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
// The C-ABI surface documents parameters with doxygen `@param[in]` /
// `@param[out]` annotations, which `cbindgen` (`documentation_style = "doxy"`)
// propagates verbatim into the generated C/C++ headers. rustdoc misreads the
// `[in]` / `[out]` as intra-doc links and warns, but this crate is a
// `publish = false` cdylib whose rustdoc is never built or shipped — and
// escaping the brackets would corrupt the doxygen in the real C/C++ headers.
// Suppress the false positive rather than break the headers.
#![allow(rustdoc::broken_intra_doc_links)]

// ----------------------------------------------------------------------------
// Panic policy
//
// This crate sets `panic = "abort"` in both `[profile.release]` and
// `[profile.dev]` (see `questdb-rs-ffi/Cargo.toml`). Any Rust panic that
// reaches the panic handler — debug assertion, arithmetic overflow, slice
// indexing, allocator overflow, `unwrap()` on `None`, etc. — terminates the
// host process immediately. The unwinder is not linked in, so there is no
// FFI panic boundary: `catch_unwind` would be a no-op even if it were
// installed, and a panic cannot be converted into `false` + `err_out`.
//
// As a result, every `extern "C"` entry point must validate inputs
// upstream — *before* any panic-capable call (`Vec::reserve`, slice
// indexing, `unwrap` on `None`, etc.) is reached. See
// `line_sender_buffer_reserve` for the canonical pattern: it pre-checks
// the would-be capacity against `isize::MAX` and returns `false` +
// `InvalidApiCall` instead of relying on a (dead) panic guard around the
// underlying `Vec::reserve` call.
//
// The `[profile.test]` and `[profile.bench]` profiles are forced to
// `panic = "unwind"` by cargo (the test harness needs to catch panics
// to report them), so any test that panics will *not* abort. Do not let
// this mislead you: in production builds the abort is the contract.
// ----------------------------------------------------------------------------

use libc::{c_char, c_void, size_t};
use questdb::ingress::DecimalView;
use std::ascii;
use std::boxed::Box;
use std::convert::{From, Into};
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

use questdb::ffi_support::OwnedRowSender;

mod ndarr;
use ndarr::StrideArrayView;

#[cfg(feature = "sync-reader-qwp-ws")]
mod egress;

pub mod column_sender;
pub use column_sender::*;

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
        $ty:ty,
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
        let view = match StrideArrayView::<$ty, $m, $n>::new($shape, $strides, $data, $data_len) {
            Ok(value) => value,
            Err(err) => {
                set_err_out_from_error($err_out, err);
                return false;
            }
        };
        bubble_err_to_c!(
            $err_out,
            $buffer
                .column_arr::<ColumnName<'_>, StrideArrayView<'_, $ty, $m, $n>, $ty>($name, &view)
        );
    }};
}

macro_rules! generate_array_dims_branches {
    ($ty:ty, $rank:expr, $m:literal, $shape:expr, $strides:expr, $data:expr, $data_len:expr, $err_out:expr, $buffer:expr, $name:expr => $($n:literal),*) => {
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
                    $ty,
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
/// returned builder only on success. On `Err`, the live `line_sender_opts`
/// keeps its original builder untouched.
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
    }};
}

/// An error that occurred when using the line sender.
pub struct line_sender_error {
    error: Error,
    qwp_ws_error: Option<QwpWsSenderError>,
}

/// Category of error.
///
/// APPEND-ONLY ABI: existing discriminants are pinned (the C header at
/// `include/questdb/ingress/line_sender.h` numbers them explicitly) and
/// new variants must be appended at the end with explicit `= N`.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum line_sender_error_code {
    /// The host, port, or interface was incorrect.
    line_sender_error_could_not_resolve_addr = 0,

    /// Called methods in the wrong order. E.g. `symbol` after `column`.
    line_sender_error_invalid_api_call = 1,

    /// A network error connecting or flushing data out.
    line_sender_error_socket_error = 2,

    /// The string or symbol field is not encoded in valid UTF-8.
    line_sender_error_invalid_utf8 = 3,

    /// The table name or column name contains bad characters.
    line_sender_error_invalid_name = 4,

    /// The supplied timestamp is invalid.
    line_sender_error_invalid_timestamp = 5,

    /// Error during the authentication process.
    line_sender_error_auth_error = 6,

    /// Error during TLS handshake.
    line_sender_error_tls_error = 7,

    /// The server does not support ILP over HTTP.
    line_sender_error_http_not_supported = 8,

    /// Error sent back from the server during flush.
    line_sender_error_server_flush_error = 9,

    /// Bad configuration.
    line_sender_error_config_error = 10,

    /// There was an error serializing an array.
    line_sender_error_array_error = 11,

    /// Line sender protocol version error.
    line_sender_error_protocol_version_error = 12,

    /// The supplied decimal is invalid.
    line_sender_error_invalid_decimal = 13,

    /// QWP/WebSocket server rejection or terminal protocol violation.
    line_sender_error_server_rejection = 14,

    /// `column_sender_flush_arrow_batch_*` was passed a column whose
    /// Arrow / QuestDB kind cannot be persisted to a QuestDB table.
    /// Only emitted with the `arrow` feature enabled.
    line_sender_error_arrow_unsupported_column_kind = 15,

    /// `column_sender_flush_arrow_batch_*` rejected a `RecordBatch` at
    /// client-side structural validation (column count, name encoding,
    /// FFI struct contract). Only emitted with the `arrow` feature
    /// enabled.
    line_sender_error_arrow_ingest = 16,

    /// A reconnectable failure on the column-major sender's flush/sync
    /// path (transport error, EOF, closed connection). The operation has
    /// not committed: drop the connection (`questdb_db_drop_column_sender`),
    /// borrow a fresh one (the pool rotates to a live endpoint), and
    /// re-drive from your source.
    line_sender_error_failover_retry = 17,

    /// Every reachable endpoint handshook but none matched the configured
    /// `target=` role filter (e.g. `target=primary` against an all-replica
    /// address list). Distinct from `socket_error` ("all endpoints
    /// unreachable") so callers can tell "no primary elected" from "all down".
    line_sender_error_role_mismatch = 18,
}

impl From<ErrorCode> for line_sender_error_code {
    fn from(code: ErrorCode) -> Self {
        // `ErrorCode` is `#[non_exhaustive]`; the trailing `_ =>` is
        // mandatory by the Rust language. To stop a future upstream
        // variant from silently downgrading to `invalid_api_call`,
        // the test
        // `line_sender_error_code_covers_every_upstream_variant`
        // exhaustively lists every current variant and fails to
        // compile when a new one is added without an explicit arm
        // below.
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
            ErrorCode::ArrowUnsupportedColumnKind => {
                line_sender_error_code::line_sender_error_arrow_unsupported_column_kind
            }
            ErrorCode::ArrowIngest => line_sender_error_code::line_sender_error_arrow_ingest,
            ErrorCode::FailoverRetry => line_sender_error_code::line_sender_error_failover_retry,
            ErrorCode::RoleMismatch => line_sender_error_code::line_sender_error_role_mismatch,
            _ => line_sender_error_code::line_sender_error_invalid_api_call,
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

    /// Sentinel for a protocol the Rust `Protocol` enum knows about but this
    /// FFI build does not. Returned by `line_sender_get_protocol` for future
    /// `Protocol` variants added after this FFI was compiled; never a valid
    /// input to `line_sender_opts_new` / `line_sender_opts_new_service`
    /// (those return null when passed this value).
    line_sender_protocol_unknown,
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
            _ => line_sender_protocol::line_sender_protocol_unknown,
        }
    }
}

impl TryFrom<line_sender_protocol> for Protocol {
    type Error = ();
    fn try_from(protocol: line_sender_protocol) -> Result<Self, Self::Error> {
        Ok(match protocol {
            line_sender_protocol::line_sender_protocol_tcp => Protocol::Tcp,
            line_sender_protocol::line_sender_protocol_tcps => Protocol::Tcps,
            line_sender_protocol::line_sender_protocol_http => Protocol::Http,
            line_sender_protocol::line_sender_protocol_https => Protocol::Https,
            line_sender_protocol::line_sender_protocol_qwpudp => Protocol::QwpUdp,
            line_sender_protocol::line_sender_protocol_qwpws => Protocol::QwpWs,
            line_sender_protocol::line_sender_protocol_qwpwss => Protocol::QwpWss,
            line_sender_protocol::line_sender_protocol_unknown => return Err(()),
        })
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

/// Error code categorising the error.
///
/// NULL-safe: passing `NULL` returns `line_sender_error_invalid_api_call`
/// (the caller is misusing the accessor) rather than dereferencing.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_error_get_code(
    error: *const line_sender_error,
) -> line_sender_error_code {
    if error.is_null() {
        return line_sender_error_code::line_sender_error_invalid_api_call;
    }
    unsafe { (*error).error.code().into() }
}

/// UTF-8 encoded error message. Never returns NULL.
/// `len_out` is set to the number of bytes; the string is NOT null-terminated.
///
/// NULL-safe on both `error` and `len_out`. A NULL `error` returns a static
/// empty string with `*len_out = 0` (when `len_out` is non-NULL); a NULL
/// `len_out` is silently ignored.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_error_msg(
    error: *const line_sender_error,
    len_out: *mut size_t,
) -> *const c_char {
    unsafe {
        if error.is_null() {
            if !len_out.is_null() {
                *len_out = 0;
            }
            return c"".as_ptr();
        }
        let msg: &str = (*error).error.msg();
        if !len_out.is_null() {
            *len_out = msg.len();
        }
        msg.as_ptr() as *const c_char
    }
}

/// `true` when the failed operation is *delivery-unknown* ("in doubt"): the
/// current input's bytes may already have reached the server even though the
/// call returned an error (e.g. a socket write that failed mid-frame, or a
/// post-publish ACK wait that failed).
///
/// This is independent of `line_sender_error_get_code`: a delivery-unknown
/// failure typically reports `line_sender_error_failover_retry` (the connection
/// may be replaced), yet that code alone does NOT mean the input is safe to
/// resend. When this returns `true`, only replay the same input if table-level
/// dedup/upsert keys make duplicate rows harmless.
///
/// NULL-safe: passing `NULL` returns `false`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_error_in_doubt(error: *const line_sender_error) -> bool {
    if error.is_null() {
        return false;
    }
    unsafe { (*error).error.in_doubt() }
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
    pub(crate) fn as_str(&self) -> &str {
        // `slice::from_raw_parts` requires a non-null, properly aligned
        // pointer even when `len == 0`; a hand-rolled
        // `line_sender_utf8 { buf: NULL, len: 0 }` (legal-looking from C)
        // would otherwise be instant UB. Substitute an empty slice.
        if self.buf.is_null() {
            return "";
        }
        unsafe { str::from_utf8_unchecked(slice::from_raw_parts(self.buf as *const u8, self.len)) }
    }

    /// Re-validate the buffer as UTF-8 and return a borrowed `&str`.
    /// Egress entry points that receive a `line_sender_utf8` from C
    /// MUST consume the parameter via this method (typically through the
    /// `egress::utf8_in` chokepoint) rather than `as_str()`: the public
    /// C struct layout means a misbehaving caller can hand-roll a
    /// `line_sender_utf8` with arbitrary bytes (skipping
    /// `line_sender_utf8_init`'s validation), and `as_str()` would
    /// silently feed those bytes to `from_utf8_unchecked` — instant UB
    /// the moment upstream walks the slice.
    ///
    /// Returning `Result<&str, Utf8Error>` (rather than a raw byte slice
    /// for the caller to re-validate) is deliberate: there is no
    /// `as_bytes()` escape hatch for egress to misuse. The only ways to
    /// extract content from a `line_sender_utf8` are this method
    /// (always validates) and `as_str()` (trusted-caller-only, used by
    /// ingress where the inputs went through `line_sender_utf8_init`).
    #[cfg(feature = "sync-reader-qwp-ws")]
    pub(crate) fn validated_utf8(&self) -> Result<&str, std::str::Utf8Error> {
        // Same NULL-guard as `as_str`: `slice::from_raw_parts` is UB on a
        // null pointer even with `len == 0`. Treat NULL+0 as the empty
        // string (which is valid UTF-8).
        let bytes: &[u8] = if self.buf.is_null() {
            &[]
        } else {
            unsafe { slice::from_raw_parts(self.buf as *const u8, self.len) }
        };
        std::str::from_utf8(bytes)
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
pub(crate) unsafe fn set_err_out_from_error_with_qwpws(
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
        // NULL buf would make `from_raw_parts` UB even at len 0; degrade to
        // the empty name, matching `line_sender_utf8::as_str`.
        if self.buf.is_null() {
            return TableName::new_unchecked("");
        }
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
        // NULL-guard as in `line_sender_table_name::as_name`.
        if self.buf.is_null() {
            return ColumnName::new_unchecked("");
        }
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
/// Returns NULL and populates `err_out` if `buffer` is NULL. If the
/// underlying clone hits an allocator failure, the process aborts per
/// the crate-wide panic policy (see the panic-policy header in
/// `lib.rs`).
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
    unsafe {
        let src = &*buffer;
        Box::into_raw(Box::new(line_sender_buffer {
            buffer: src.buffer.clone(),
            empty_peek_buf_is_null: src.empty_peek_buf_is_null,
        }))
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
    // `Vec::reserve` panics if the resulting capacity exceeds
    // `isize::MAX`, which under the crate-wide `panic = "abort"`
    // policy would abort the host process. Reject the call up front
    // instead. The current capacity is included so we don't accept
    // an `additional` that overflows only because of what's already
    // buffered.
    let current = unsafe { unwrap_buffer(buffer).capacity() };
    if additional > (isize::MAX as usize).saturating_sub(current) {
        unsafe {
            set_err_out(
                err_out,
                ErrorCode::InvalidApiCall,
                "line_sender_buffer_reserve: additional capacity would overflow".to_owned(),
            );
        }
        return false;
    }
    unsafe { unwrap_buffer_mut(buffer).reserve(additional) };
    true
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

/// Record an 8-bit signed integer for the given column. QWP-only.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_column_i8(
    buffer: *mut line_sender_buffer,
    name: line_sender_column_name,
    value: i8,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let buffer = unwrap_buffer_mut(buffer);
        bubble_err_to_c!(err_out, buffer.column_i8(name.as_name(), value));
        true
    }
}

/// Record a 16-bit signed integer for the given column. QWP-only.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_column_i16(
    buffer: *mut line_sender_buffer,
    name: line_sender_column_name,
    value: i16,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let buffer = unwrap_buffer_mut(buffer);
        bubble_err_to_c!(err_out, buffer.column_i16(name.as_name(), value));
        true
    }
}

/// Record a 32-bit signed integer for the given column. QWP-only.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_column_i32(
    buffer: *mut line_sender_buffer,
    name: line_sender_column_name,
    value: i32,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let buffer = unwrap_buffer_mut(buffer);
        bubble_err_to_c!(err_out, buffer.column_i32(name.as_name(), value));
        true
    }
}

/// Record a 32-bit floating-point value for the given column. QWP-only.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_column_f32(
    buffer: *mut line_sender_buffer,
    name: line_sender_column_name,
    value: f32,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let buffer = unwrap_buffer_mut(buffer);
        bubble_err_to_c!(err_out, buffer.column_f32(name.as_name(), value));
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
    if value.is_null() && value_len != 0 {
        if !err_out.is_null() {
            unsafe {
                set_err_out_from_error(
                    err_out,
                    questdb::Error::new(
                        questdb::ErrorCode::InvalidDecimal,
                        "Decimal string pointer is NULL with non-zero length".to_string(),
                    ),
                );
            }
        }
        return false;
    }
    let value: &[u8] = if value_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(value as *const u8, value_len) }
    };
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

/// Record a 64-bit decimal string value for the given column. QWP-only.
/// Same string format as `line_sender_buffer_column_dec_str`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_column_dec64_str(
    buffer: *mut line_sender_buffer,
    name: line_sender_column_name,
    value: *mut c_char,
    value_len: size_t,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let buffer = unsafe { unwrap_buffer_mut(buffer) };
    let name = name.as_name();
    if value.is_null() && value_len != 0 {
        if !err_out.is_null() {
            unsafe {
                set_err_out_from_error(
                    err_out,
                    questdb::Error::new(
                        questdb::ErrorCode::InvalidDecimal,
                        "Decimal string pointer is NULL with non-zero length".to_string(),
                    ),
                );
            }
        }
        return false;
    }
    let value: &[u8] = if value_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(value as *const u8, value_len) }
    };
    let value = match str::from_utf8(value) {
        Ok(value) => value,
        Err(err) => {
            if !err_out.is_null() {
                unsafe {
                    set_err_out_from_error(
                        err_out,
                        questdb::Error::new(
                            questdb::ErrorCode::InvalidDecimal,
                            format!("Decimal string is not valid UTF-8: {err}"),
                        ),
                    );
                }
            }
            return false;
        }
    };
    unsafe {
        bubble_err_to_c!(
            err_out,
            buffer.column_dec64(name, DecimalView::String { value })
        );
    }
    true
}

/// Record a 64-bit decimal value for the given column. QWP-only.
/// Same scaled-int format as `line_sender_buffer_column_dec`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_column_dec64(
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
        bubble_err_to_c!(err_out, buffer.column_dec64(name, decimal));
    }
    true
}

/// Record a 128-bit decimal string value for the given column. QWP-only.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_column_dec128_str(
    buffer: *mut line_sender_buffer,
    name: line_sender_column_name,
    value: *mut c_char,
    value_len: size_t,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let buffer = unsafe { unwrap_buffer_mut(buffer) };
    let name = name.as_name();
    if value.is_null() && value_len != 0 {
        if !err_out.is_null() {
            unsafe {
                set_err_out_from_error(
                    err_out,
                    questdb::Error::new(
                        questdb::ErrorCode::InvalidDecimal,
                        "Decimal string pointer is NULL with non-zero length".to_string(),
                    ),
                );
            }
        }
        return false;
    }
    let value: &[u8] = if value_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(value as *const u8, value_len) }
    };
    let value = match str::from_utf8(value) {
        Ok(value) => value,
        Err(err) => {
            if !err_out.is_null() {
                unsafe {
                    set_err_out_from_error(
                        err_out,
                        questdb::Error::new(
                            questdb::ErrorCode::InvalidDecimal,
                            format!("Decimal string is not valid UTF-8: {err}"),
                        ),
                    );
                }
            }
            return false;
        }
    };
    unsafe {
        bubble_err_to_c!(
            err_out,
            buffer.column_dec128(name, DecimalView::String { value })
        );
    }
    true
}

/// Record a 128-bit decimal value for the given column. QWP-only.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_column_dec128(
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
        bubble_err_to_c!(err_out, buffer.column_dec128(name, decimal));
    }
    true
}

/// Record a UUID column value. QWP-only.
///
/// The wire encoding writes `lo` (8 bytes LE) followed by `hi` (8 bytes LE).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_column_uuid(
    buffer: *mut line_sender_buffer,
    name: line_sender_column_name,
    lo: u64,
    hi: u64,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let buffer = unwrap_buffer_mut(buffer);
        bubble_err_to_c!(err_out, buffer.column_uuid(name.as_name(), lo, hi));
        true
    }
}

/// Record a LONG256 column value. QWP-only.
///
/// `value` must point to exactly 32 bytes: four 64-bit limbs encoded
/// little-endian, least-significant limb first.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_column_long256(
    buffer: *mut line_sender_buffer,
    name: line_sender_column_name,
    value: *const u8,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        if value.is_null() {
            if !err_out.is_null() {
                set_err_out_from_error(
                    err_out,
                    questdb::Error::new(
                        questdb::ErrorCode::InvalidApiCall,
                        "column_long256 value pointer must not be NULL".to_string(),
                    ),
                );
            }
            return false;
        }
        let buffer = unwrap_buffer_mut(buffer);
        let bytes: &[u8; 32] = &*(value as *const [u8; 32]);
        bubble_err_to_c!(err_out, buffer.column_long256(name.as_name(), bytes));
        true
    }
}

/// Record an IPv4 column value. QWP-only.
///
/// `value` is the address packed as a u32 with octet 0 in the high byte:
/// `addr = ((a << 24) | (b << 16) | (c << 8) | d)`. The encoder writes
/// `value.to_le_bytes()` so the wire bytes appear as `[d, c, b, a]`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_column_ipv4(
    buffer: *mut line_sender_buffer,
    name: line_sender_column_name,
    value: u32,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let buffer = unwrap_buffer_mut(buffer);
        let addr = std::net::Ipv4Addr::from(value);
        bubble_err_to_c!(err_out, buffer.column_ipv4(name.as_name(), addr));
        true
    }
}

/// Record a DATE column value (milliseconds since the Unix epoch). QWP-only.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_column_date(
    buffer: *mut line_sender_buffer,
    name: line_sender_column_name,
    millis: i64,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let buffer = unwrap_buffer_mut(buffer);
        bubble_err_to_c!(err_out, buffer.column_date(name.as_name(), millis));
        true
    }
}

/// Record a CHAR column value (single UTF-16 code unit). QWP-only.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_column_char(
    buffer: *mut line_sender_buffer,
    name: line_sender_column_name,
    value: u16,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let buffer = unwrap_buffer_mut(buffer);
        bubble_err_to_c!(err_out, buffer.column_char(name.as_name(), value));
        true
    }
}

/// Record a BINARY column value (opaque byte sequence). QWP-only.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_column_binary(
    buffer: *mut line_sender_buffer,
    name: line_sender_column_name,
    data: *const u8,
    data_len: size_t,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let bytes = if data.is_null() {
            &[]
        } else {
            slice::from_raw_parts(data, data_len)
        };
        let buffer = unwrap_buffer_mut(buffer);
        bubble_err_to_c!(err_out, buffer.column_binary(name.as_name(), bytes));
        true
    }
}

/// Record a GEOHASH column value. QWP-only.
///
/// `precision_bits` must be in `1..=60` and is pinned per column.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_column_geohash(
    buffer: *mut line_sender_buffer,
    name: line_sender_column_name,
    bits: u64,
    precision_bits: u8,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let buffer = unwrap_buffer_mut(buffer);
        bubble_err_to_c!(
            err_out,
            buffer.column_geohash(name.as_name(), bits, precision_bits)
        );
        true
    }
}

/// Records an int64 multidimensional array with C-major memory layout. QWP-only.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_column_i64_arr_c_major(
    buffer: *mut line_sender_buffer,
    name: line_sender_column_name,
    rank: size_t,
    shape: *const usize,
    data: *const i64,
    data_len: size_t,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let buffer = unwrap_buffer_mut(buffer);
        let name = name.as_name();
        let view = match CMajorArrayView::<i64>::new(rank, shape, data, data_len) {
            Ok(value) => value,
            Err(err) => {
                set_err_out_from_error(err_out, err);
                return false;
            }
        };
        bubble_err_to_c!(
            err_out,
            buffer.column_arr::<ColumnName<'_>, CMajorArrayView<'_, i64>, i64>(name, &view)
        );
        true
    }
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
            f64,
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
            f64,
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

/// Records an int64 multidimensional array with **byte stride specification**.
/// QWP-only. See `line_sender_buffer_column_f64_arr_byte_strides` for parameter docs.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_column_i64_arr_byte_strides(
    buffer: *mut line_sender_buffer,
    name: line_sender_column_name,
    rank: size_t,
    shape: *const usize,
    strides: *const isize,
    data: *const i64,
    data_len: size_t,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let buffer = unwrap_buffer_mut(buffer);
        let name = name.as_name();
        generate_array_dims_branches!(
            i64,
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

/// Records an int64 multidimensional array with **element count stride specification**.
/// QWP-only. See `line_sender_buffer_column_f64_arr_elem_strides` for parameter docs.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_buffer_column_i64_arr_elem_strides(
    buffer: *mut line_sender_buffer,
    name: line_sender_column_name,
    rank: size_t,
    shape: *const usize,
    strides: *const isize,
    data: *const i64,
    data_len: size_t,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let buffer = unwrap_buffer_mut(buffer);
        let name = name.as_name();
        generate_array_dims_branches!(
            i64,
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
    let Ok(protocol) = Protocol::try_from(protocol) else {
        return ptr::null_mut();
    };
    let builder = SenderBuilder::new(protocol, host.as_str(), port);
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
    let Ok(protocol) = Protocol::try_from(protocol) else {
        return ptr::null_mut();
    };
    let builder = SenderBuilder::new(protocol, host.as_str(), port.as_str());
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
    unsafe {
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
                    cb(user_data as *mut c_void, &view);
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
    }
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
///
/// On builds without the `insecure-skip-verify` Cargo feature, calling
/// this with `verify=false` returns an `InvalidApiCall` error and leaves
/// the options unchanged. `verify=true` is a no-op (verification is the
/// default).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_opts_tls_verify(
    opts: *mut line_sender_opts,
    verify: bool,
    err_out: *mut *mut line_sender_error,
) -> bool {
    #[cfg(feature = "insecure-skip-verify")]
    {
        unsafe { upd_opts!(opts, err_out, tls_verify, verify) }
    }
    #[cfg(not(feature = "insecure-skip-verify"))]
    {
        let _ = opts;
        if verify {
            true
        } else {
            unsafe {
                set_err_out(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    "tls_verify=false requires the \"insecure-skip-verify\" \
                     Cargo feature, which this build was compiled without"
                        .to_string(),
                );
            }
            false
        }
    }
}

/// Specify where to find the certificate authority used to validate
/// the server's TLS certificate.
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
/// On QWP/WebSocket (`qwpwss::`) the same path may instead point at a JKS
/// or PKCS#12 keystore; pair it with `line_sender_opts_tls_roots_password`
/// to unlock it.
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

/// Set the password unlocking the JKS / PKCS#12 keystore named by
/// `line_sender_opts_tls_roots`.
///
/// QWP/WebSocket only (`qwpwss::`). Setting this on an ILP/TCP or
/// ILP/HTTP sender returns an `InvalidApiCall` error: those transports
/// read unencrypted PEM via rustls and have no keystore concept.
///
/// With this set, the `tls_roots` file is interpreted as a Java
/// KeyStore (auto-detected: JKS magic `0xFEEDFEED`, or PKCS#12
/// ASN.1 SEQUENCE) and its trusted-certificate entries become the
/// rustls root store. Mirrors the Java reference client's
/// `tls_roots_password` connect-string key.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_opts_tls_roots_password(
    opts: *mut line_sender_opts,
    password: line_sender_utf8,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let password = password.as_str().to_string();
        upd_opts!(opts, err_out, tls_roots_password, password)
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

/// Cap on per-attempt backoff in the HTTP retry loop, in milliseconds.
/// Default is 1000 ms. The retry loop starts at 10 ms and doubles each
/// attempt up to this cap; the total retry budget is independently
/// bounded by `line_sender_opts_retry_timeout`. ILP-over-HTTP only.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_opts_retry_max_backoff(
    opts: *mut line_sender_opts,
    millis: u64,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let retry_max_backoff = std::time::Duration::from_millis(millis);
        upd_opts!(opts, err_out, retry_max_backoff, retry_max_backoff)
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
/// Returns true after an unrecoverable failure. For ILP-over-TCP this is any
/// socket error. For QWP/WebSocket this also covers a server rejection or
/// protocol violation that latches the publication lifecycle to its terminal
/// state. ILP-over-HTTP and QWP/UDP never transition into a
/// permanently-unusable state and always return false.
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
    unsafe {
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
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_qwpws_flush_and_keep_and_get_fsn(
    sender: *mut line_sender,
    buffer: *const line_sender_buffer,
    fsn_out: *mut line_sender_qwpws_fsn,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
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
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_qwpws_drive_once(
    sender: *mut line_sender,
    progressed_out: *mut bool,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
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
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_qwpws_published_fsn(
    sender: *const line_sender,
    fsn_out: *mut line_sender_qwpws_fsn,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
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
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_qwpws_acked_fsn(
    sender: *const line_sender,
    fsn_out: *mut line_sender_qwpws_fsn,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
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
    }
}

/// Acknowledgement level for [`line_sender_qwpws_wait`]. These mirror the
/// column-major `column_sender_ack_level_*` values; the FFI takes a `uint32_t`.
#[allow(non_upper_case_globals)]
pub const line_sender_qwpws_ack_level_ok: u32 = 0;
#[allow(non_upper_case_globals)]
pub const line_sender_qwpws_ack_level_durable: u32 = 1;

/// Wait until every QWP/WebSocket frame published so far on `sender` reaches
/// `ack_level` (a `line_sender_qwpws_ack_level_*` value). This is the
/// row-major counterpart to the column-major `sf_column_sender_wait`.
///
/// `timeout_millis` is a no-progress deadline (it fires only if the ack
/// watermark fails to advance for that long); `0` waits indefinitely.
///
/// Returns `true` once the boundary is acknowledged. Returns `false` and sets
/// `err_out` on the no-progress timeout (`line_sender_error_failover_retry`), a
/// server rejection, a transport failure, or an invalid `ack_level`. With
/// nothing published yet it succeeds immediately.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_qwpws_wait(
    sender: *mut line_sender,
    ack_level: u32,
    timeout_millis: u64,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        let ack_level = match ack_level {
            0 => questdb::ingress::AckLevel::Ok,
            1 => questdb::ingress::AckLevel::Durable,
            other => {
                set_err_out(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    format!("line_sender_qwpws_wait: invalid ack_level {other} (expected 0 or 1)"),
                );
                return false;
            }
        };
        let Some(sender) = qwpws_line_sender_mut(sender, err_out, "line_sender_qwpws_wait") else {
            return false;
        };
        match sender.wait(ack_level, Duration::from_millis(timeout_millis)) {
            Ok(()) => true,
            Err(err) => {
                set_err_out_from_sender_error(err_out, sender, err);
                false
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_qwpws_poll_error(
    sender: *mut line_sender,
    error_out: *mut *mut line_sender_qwpws_error,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
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
    }
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
    unsafe {
        if !error.is_null() {
            drop(Box::from_raw(error));
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_qwpws_errors_dropped(
    sender: *const line_sender,
    dropped_out: *mut u64,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
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
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_sender_qwpws_close_drain(
    sender: *mut line_sender,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
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
    unsafe {
        let sender = unwrap_sender_mut(sender);
        let buffer = unwrap_buffer_mut(buffer);
        match sender.flush(buffer) {
            Ok(()) => true,
            Err(err) => {
                set_err_out_from_sender_error(err_out, sender, err);
                false
            }
        }
    }
}

// ===========================================================================
// Row-sender pool borrow (row-major QWP/WS sender)
//
// The pool (`questdb_db`) hands out three kinds of borrow: column-major
// senders (`column_sender`), row-major senders (`row_sender`, below), and
// query readers (`reader`). A `row_sender` builds rows with the ordinary
// `line_sender_buffer` and flushes them with `row_sender_flush`.
// ===========================================================================

/// A row-major QWP/WS sender borrowed from a `questdb_db` pool. Opaque and
/// not thread-safe: it belongs to the borrowing thread until returned with
/// `questdb_db_return_row_sender` (recycle) or `questdb_db_drop_row_sender`
/// (force-close). If the pool has been closed, return closes the sender
/// instead of recycling it. Build rows with a `line_sender_buffer` and send
/// them with `row_sender_flush` / `row_sender_flush_and_keep`.
pub struct row_sender(OwnedRowSender);

unsafe fn reject_closed_pool_row_sender(
    sender: *const row_sender,
    fn_name: &str,
    err_out: *mut *mut line_sender_error,
) -> bool {
    if unsafe { (*sender).0.pool_closed() } {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    format!("{fn_name}: QuestDb pool is closed"),
                ),
            );
        }
        true
    } else {
        false
    }
}

/// Borrow a row-major sender from the pool. Returns NULL on failure and sets
/// `*err_out` if provided. The row-sender pool is lazy and independently
/// capped (shares `pool_max`); a borrow at the cap returns
/// `line_sender_error_invalid_api_call`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_db_borrow_row_sender(
    db: *mut questdb_db,
    err_out: *mut *mut line_sender_error,
) -> *mut row_sender {
    if db.is_null() {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    "questdb_db_borrow_row_sender: db pointer is NULL".to_string(),
                ),
            );
        }
        return ptr::null_mut();
    }
    let db_ref = unsafe { &*db };
    match questdb::ffi_support::borrow_row_sender_owned(&db_ref.0) {
        Ok(owned) => Box::into_raw(Box::new(row_sender(owned))),
        Err(err) => {
            unsafe { set_err_out_from_error(err_out, err) };
            ptr::null_mut()
        }
    }
}

/// Like `questdb_db_borrow_row_sender` but retries the connect within
/// `budget_ms` using the pool's reconnect backoff (auth / protocol-version
/// errors are terminal). `budget_ms == 0` makes a single attempt. Returns
/// NULL on failure; sets `*err_out` if provided.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_db_borrow_row_sender_with_retry(
    db: *mut questdb_db,
    budget_ms: u64,
    err_out: *mut *mut line_sender_error,
) -> *mut row_sender {
    if db.is_null() {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    "questdb_db_borrow_row_sender_with_retry: db pointer is NULL".to_string(),
                ),
            );
        }
        return ptr::null_mut();
    }
    let db_ref = unsafe { &*db };
    match questdb::ffi_support::borrow_row_sender_owned_with_retry(
        &db_ref.0,
        Duration::from_millis(budget_ms),
    ) {
        Ok(owned) => Box::into_raw(Box::new(row_sender(owned))),
        Err(err) => {
            unsafe { set_err_out_from_error(err_out, err) };
            ptr::null_mut()
        }
    }
}

/// Return a borrowed row sender to the pool. Invalidates `sender`. Accepts
/// NULL and no-ops. `db` is ignored (the sender carries its own pool
/// back-reference) but kept in the ABI for symmetry with the borrow call. If
/// the pool has been closed, the sender is closed instead of recycled.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_db_return_row_sender(
    _db: *mut questdb_db,
    sender: *mut row_sender,
) {
    if sender.is_null() {
        return;
    }
    unsafe { drop(Box::from_raw(sender)) };
}

/// Force-drop a borrowed row sender instead of recycling it: the underlying
/// connection is closed and the next borrow opens a fresh one. Invalidates
/// `sender`. Accepts NULL and no-ops.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_db_drop_row_sender(_db: *mut questdb_db, sender: *mut row_sender) {
    if sender.is_null() {
        return;
    }
    unsafe {
        (*sender).0.mark_must_close();
        drop(Box::from_raw(sender));
    }
}

/// `true` if the row sender will be dropped rather than recycled on return
/// (force-marked, a flush left the connection unusable, or the originating
/// pool has been closed), or if `sender` is NULL. `false` only when it is
/// safely reusable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn row_sender_must_close(sender: *const row_sender) -> bool {
    if sender.is_null() {
        return true;
    }
    unsafe { (*sender).0.must_close() }
}

/// Flush the buffer of rows through the borrowed row sender, then clear the
/// buffer. Returns `true` on success; on failure returns `false` and sets
/// `*err_out`. Mirrors `line_sender_flush` for the standalone sender.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn row_sender_flush(
    sender: *mut row_sender,
    buffer: *mut line_sender_buffer,
    err_out: *mut *mut line_sender_error,
) -> bool {
    if sender.is_null() {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    "row_sender_flush: sender pointer is NULL".to_string(),
                ),
            );
        }
        return false;
    }
    if unsafe { reject_closed_pool_row_sender(sender, "row_sender_flush", err_out) } {
        return false;
    }
    unsafe {
        let s = (*sender).0.get_mut();
        let buffer = unwrap_buffer_mut(buffer);
        match s.flush(buffer) {
            Ok(()) => true,
            Err(err) => {
                set_err_out_from_sender_error(err_out, s, err);
                false
            }
        }
    }
}

/// Flush the buffer of rows through the borrowed row sender, keeping the
/// buffer intact (clear it before starting a new batch). Mirrors
/// `line_sender_flush_and_keep`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn row_sender_flush_and_keep(
    sender: *mut row_sender,
    buffer: *const line_sender_buffer,
    err_out: *mut *mut line_sender_error,
) -> bool {
    if sender.is_null() {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    "row_sender_flush_and_keep: sender pointer is NULL".to_string(),
                ),
            );
        }
        return false;
    }
    if unsafe { reject_closed_pool_row_sender(sender, "row_sender_flush_and_keep", err_out) } {
        return false;
    }
    unsafe {
        let s = (*sender).0.get_mut();
        let buffer = unwrap_buffer(buffer);
        match s.flush_and_keep(buffer) {
            Ok(()) => true,
            Err(err) => {
                set_err_out_from_sender_error(err_out, s, err);
                false
            }
        }
    }
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
    unsafe {
        let sender = unwrap_sender_mut(sender);
        let buffer = unwrap_buffer(buffer);
        match sender.flush_and_keep(buffer) {
            Ok(()) => true,
            Err(err) => {
                set_err_out_from_sender_error(err_out, sender, err);
                false
            }
        }
    }
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
    unsafe {
        let sender = unwrap_sender_mut(sender);
        let buffer = unwrap_buffer(buffer);
        match sender.flush_and_keep_with_flags(buffer, transactional) {
            Ok(()) => true,
            Err(err) => {
                set_err_out_from_sender_error(err_out, sender, err);
                false
            }
        }
    }
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

// Crate is `panic = "abort"`; `catch_unwind` would be a no-op in
// shipped builds and harms `cargo test` diagnostics. Validation
// happens up-front in `arrow_ffi_import_record_batch`.

// Bounds for the pre-walk that protects `arrow::ffi::from_ffi` against
// adversarial FFI input. Three independent caps:
//   * `MAX_ARROW_SCHEMA_DEPTH` bounds recursion depth (children + dictionary
//     chain). arrow-rs unrolls both onto the host stack; without this cap
//     a deep schema would stack-overflow inside `from_ffi`.
//   * `MAX_ARROW_SCHEMA_CHILDREN_PER_NODE` bounds breadth per node.
//   * `MAX_ARROW_SCHEMA_TOTAL_NODES` bounds the whole tree (depth × breadth
//     would otherwise be combinatorial under shared children / cyclic DAGs).
#[cfg(feature = "arrow")]
const MAX_ARROW_SCHEMA_DEPTH: usize = 64;
#[cfg(feature = "arrow")]
const MAX_ARROW_SCHEMA_CHILDREN_PER_NODE: i64 = 65_536;
#[cfg(feature = "arrow")]
const MAX_ARROW_SCHEMA_TOTAL_NODES: usize = 4_096;
// Widest Arrow physical layout is dense Union at 3 buffers. Cap above
// that so the validator can't be DoS'd by an inflated `n_buffers`
// independently of whatever arrow-rs's `from_ffi` happens to trust.
#[cfg(feature = "arrow")]
const MAX_ARROW_ARRAY_N_BUFFERS_PER_NODE: i64 = 16;
// `arrow::ffi::from_ffi` reads `(*a).length` as i64 and casts to
// usize before the inner crate gets to check the row cap, so a
// negative or `i64::MAX` length must be rejected here. Anchored on
// the shared `MAX_CHUNK_ROWS` constant so the two crates cannot
// drift.
#[cfg(feature = "arrow")]
const MAX_ARROW_ARRAY_LENGTH: i64 = questdb::ingress::column_sender::MAX_CHUNK_ROWS as i64;
// `FFI_ArrowSchema::metadata()` reads the leading entry count straight from
// the producer blob and feeds it to `HashMap::with_capacity` — an unbounded
// `i32` there is a multi-gigabyte allocation that aborts the `panic = "abort"`
// crate from ~4 bytes of input. Bound it before any node is converted.
#[cfg(feature = "arrow")]
const MAX_ARROW_SCHEMA_METADATA_ENTRIES: i32 = 65_536;

// Residual trust boundary: the Arrow C Data Interface carries no byte length
// for its buffers, so a producer that lies about offset/data buffer sizes or
// about the `metadata` blob's internal lengths can drive arrow-rs into an
// out-of-bounds read no consumer can pre-detect. The pre-walk closes every
// gap that has a checkable invariant (NULL pointers, negative/oversized
// counts, missing children, eagerly-dereferenced slots); the byte-size lies
// remain the producer's responsibility, same as any C Data Interface consumer.
#[cfg(feature = "arrow")]
fn arrow_ingest_err(msg: impl Into<String>) -> Error {
    Error::new(ErrorCode::ArrowIngest, msg.into())
}

// Format strings the Arrow C Data Interface accepts; trusted on a cheap
// prefix match. We do NOT enforce the full grammar — arrow-rs's own
// `DataType::try_from` does the structural parse and returns an Err on
// unknown variants. We only reject the inputs that would panic inside
// `FFI_ArrowSchema::format()` (NULL pointer / non-UTF-8) before reaching
// the parser.
#[cfg(feature = "arrow")]
unsafe fn validate_format_str(s: *const arrow::ffi::FFI_ArrowSchema) -> questdb::Result<()> {
    unsafe {
        let p = (*s).format;
        if p.is_null() {
            return Err(arrow_ingest_err("Arrow schema format pointer is NULL"));
        }
        let cstr = std::ffi::CStr::from_ptr(p);
        cstr.to_str()
            .map_err(|_| arrow_ingest_err("Arrow schema format string is not UTF-8"))?;
        Ok(())
    }
}

// `FFI_ArrowSchema::name()` in arrow-schema-58.x calls `.expect("non-utf8
// as name")` on every import, and `TryFrom<&FFI_ArrowSchema> for Field`
// invokes it unconditionally. Under `panic = "abort"` an invalid byte in
// `name` from an Arrow producer aborts the host. NULL is allowed (treated
// as empty string by arrow-rs); only reject non-UTF-8.
#[cfg(feature = "arrow")]
unsafe fn validate_name_str(s: *const arrow::ffi::FFI_ArrowSchema) -> questdb::Result<()> {
    unsafe {
        let p = (*s).name;
        if p.is_null() {
            return Ok(());
        }
        let cstr = std::ffi::CStr::from_ptr(p);
        cstr.to_str()
            .map_err(|_| arrow_ingest_err("Arrow schema name is not UTF-8"))?;
        Ok(())
    }
}

#[cfg(feature = "arrow")]
unsafe fn try_reserve_one<T>(v: &mut Vec<T>) -> questdb::Result<()> {
    v.try_reserve(1)
        .map_err(|_| arrow_ingest_err("Arrow schema pre-walk: reservation failed"))
}

// Minimum `n_children` a nested Arrow format string requires. arrow-rs's
// `DataType::try_from` calls `FFI_ArrowSchema::child(0)` (plus `child(1)` for
// run-end-encoded) unconditionally for these formats, and `child()` asserts
// `index < n_children`. Under `panic = "abort"` a short child list would abort
// the host inside `try_from` before any of arrow-rs's fallible parsing runs.
// Struct (`+s`) and union (`+ud`/`+us`) use a `0..n_children` iterator instead,
// so they need no floor here.
#[cfg(feature = "arrow")]
fn arrow_format_min_children(format: &str) -> i64 {
    if format.starts_with("+w:") {
        return 1;
    }
    match format {
        "+l" | "+L" | "+vl" | "+vL" | "+m" => 1,
        "+r" => 2,
        _ => 0,
    }
}

#[cfg(feature = "arrow")]
unsafe fn validate_arrow_schema_depth(
    schema: *const arrow::ffi::FFI_ArrowSchema,
) -> questdb::Result<()> {
    // Shared children / dictionaries (a DAG) are legal per the Arrow C
    // Data Interface spec, so we don't use "ever-visited" as a cycle
    // proxy. Cycles are still bounded — both the total-nodes cap and
    // the depth cap below ensure traversal terminates.
    unsafe {
        let mut stack: Vec<(*const arrow::ffi::FFI_ArrowSchema, usize)> = Vec::new();
        let mut total: usize = 0;
        try_reserve_one(&mut stack)?;
        stack.push((schema, 0));
        while let Some((s, depth)) = stack.pop() {
            total += 1;
            if total > MAX_ARROW_SCHEMA_TOTAL_NODES {
                return Err(arrow_ingest_err(format!(
                    "Arrow schema total node count exceeds {}",
                    MAX_ARROW_SCHEMA_TOTAL_NODES
                )));
            }
            if depth >= MAX_ARROW_SCHEMA_DEPTH {
                return Err(arrow_ingest_err(format!(
                    "Arrow schema nesting depth exceeds {}",
                    MAX_ARROW_SCHEMA_DEPTH
                )));
            }
            validate_format_str(s)?;
            validate_name_str(s)?;
            // Bounds the metadata entry *count* (a tiny header could otherwise
            // drive a huge `HashMap::with_capacity` in `metadata()`). Per-entry
            // key/value lengths are intentionally left to the producer-trust
            // contract, like the producer-declared buffer byte-lengths.
            let metadata = (*s).metadata;
            if !metadata.is_null() {
                let header = std::slice::from_raw_parts(metadata as *const u8, 4);
                let num_entries = i32::from_ne_bytes([header[0], header[1], header[2], header[3]]);
                if !(0..=MAX_ARROW_SCHEMA_METADATA_ENTRIES).contains(&num_entries) {
                    return Err(arrow_ingest_err(format!(
                        "Arrow schema metadata declares {} entries (allowed 0..={})",
                        num_entries, MAX_ARROW_SCHEMA_METADATA_ENTRIES
                    )));
                }
            }
            let n = (*s).n_children;
            if n < 0 {
                return Err(arrow_ingest_err(format!(
                    "Arrow schema n_children {} is negative",
                    n
                )));
            }
            // `format` was just confirmed non-NULL and UTF-8 by validate_format_str.
            let format = std::ffi::CStr::from_ptr((*s).format).to_str().unwrap_or("");
            let min_children = arrow_format_min_children(format);
            if n < min_children {
                return Err(arrow_ingest_err(format!(
                    "Arrow schema format '{}' requires at least {} child(ren) but declares {}",
                    format, min_children, n
                )));
            }
            if n > MAX_ARROW_SCHEMA_CHILDREN_PER_NODE {
                return Err(arrow_ingest_err(format!(
                    "Arrow schema n_children {} exceeds per-node cap {}",
                    n, MAX_ARROW_SCHEMA_CHILDREN_PER_NODE
                )));
            }
            let dict = (*s).dictionary;
            if !dict.is_null() {
                try_reserve_one(&mut stack)?;
                stack.push((dict as *const _, depth + 1));
            }
            if n == 0 {
                continue;
            }
            let children = (*s).children;
            if children.is_null() {
                return Err(arrow_ingest_err(
                    "Arrow schema declares children but pointer is NULL",
                ));
            }
            for i in 0..n as usize {
                let child = *children.add(i);
                if child.is_null() {
                    return Err(arrow_ingest_err("Arrow schema child pointer is NULL"));
                }
                try_reserve_one(&mut stack)?;
                stack.push((child as *const _, depth + 1));
            }
        }
        Ok(())
    }
}

// Minimum `n_buffers` arrow-rs's `from_ffi` requires for `dt` before it
// would read an out-of-range / NULL buffer. Mirrors `arrow_data::layout`
// (validity + data buffers; view types add a variadic lengths buffer)
// without calling it — `layout` panics on a negative `FixedSizeBinary`
// width. The catch-all is the validity + single-data-buffer family
// (primitives, decimals, list, map, fixed-size-binary, temporal).
#[cfg(feature = "arrow")]
fn arrow_min_n_buffers(dt: &arrow::datatypes::DataType) -> i64 {
    use arrow::datatypes::{DataType as D, UnionMode};
    match dt {
        D::Null | D::RunEndEncoded(..) => 0,
        D::Struct(_) | D::FixedSizeList(..) => 1,
        D::Union(_, UnionMode::Sparse) => 1,
        D::Union(_, UnionMode::Dense) => 2,
        D::Utf8
        | D::LargeUtf8
        | D::Binary
        | D::LargeBinary
        | D::Utf8View
        | D::BinaryView
        | D::ListView(_)
        | D::LargeListView(_) => 3,
        D::Dictionary(key, _) => arrow_min_n_buffers(key),
        _ => 2,
    }
}

// Reject the parsed Arrow `DataType`s whose declared size arrow-rs's
// `from_ffi` feeds straight into an unchecked `as usize` multiply in
// `arrow_array::ffi::bit_width`:
//
//     FixedSizeBinary(w)  -> w as usize * 8
//     FixedSizeList(_, n) -> child_bits * (n as usize)
//
// A negative size casts to a near-`usize::MAX` factor; a *positive* size nested
// inside another FixedSize* overflows the cumulative product (e.g. two nested
// `FixedSizeList(2^31)` over an Int64 leaf is 2^68). Under `panic = "abort"` +
// overflow-checks (dev/test) either aborts the host before `validate_full`
// runs; in release it wraps to a bogus buffer length. Recompute the cumulative
// bit-width with checked i64 arithmetic — using the widest fixed-width leaf
// (256 bits) as an upper bound — and reject anything that overflows. The caller
// runs this at every schema node, always before `from_ffi`. Keep in sync with
// `bit_width` on arrow upgrades.
#[cfg(feature = "arrow")]
fn reject_overflowing_fixed_size(dt: &arrow::datatypes::DataType) -> questdb::Result<()> {
    use arrow::datatypes::DataType;
    fn cumulative_bit_width_upper(dt: &DataType) -> questdb::Result<i64> {
        match dt {
            DataType::FixedSizeBinary(width) => {
                if *width < 0 {
                    return Err(arrow_ingest_err(format!(
                        "Arrow FixedSizeBinary width {width} is negative"
                    )));
                }
                (*width as i64).checked_mul(8)
            }
            DataType::FixedSizeList(field, size) => {
                if *size < 0 {
                    return Err(arrow_ingest_err(format!(
                        "Arrow FixedSizeList size {size} is negative"
                    )));
                }
                cumulative_bit_width_upper(field.data_type())?.checked_mul(*size as i64)
            }
            _ => Some(256),
        }
        .ok_or_else(|| arrow_ingest_err("Arrow FixedSize element bit-width overflows".to_string()))
    }
    cumulative_bit_width_upper(dt)?;
    Ok(())
}

// Cross-walk schema + array in lockstep. arrow-rs's `from_ffi` asserts on
// mismatches between the two trees (`n_children` agreement for Struct /
// Union, `n_buffers` consistency, etc.); under `panic = "abort"` that
// assert aborts the host. We pre-check everything we can.
#[cfg(feature = "arrow")]
unsafe fn validate_arrow_array_depth(
    array: *const arrow::ffi::FFI_ArrowArray,
    schema: *const arrow::ffi::FFI_ArrowSchema,
) -> questdb::Result<()> {
    // Shared children are legal — see validate_arrow_schema_depth for
    // the same rationale. Cycles are bounded by total + depth caps.
    unsafe {
        // `DataType::try_from` (called per node below) recursively follows
        // the schema's children and `dictionary` pointers, so a cyclic or
        // over-deep schema would overflow the stack before the iterative
        // depth cap here can fire. Bound the schema first with the
        // cycle-safe walker (which never calls `try_from`); afterwards every
        // `try_from` recurses at most `MAX_ARROW_SCHEMA_DEPTH` levels.
        validate_arrow_schema_depth(schema)?;
        let mut stack: Vec<(
            *const arrow::ffi::FFI_ArrowArray,
            *const arrow::ffi::FFI_ArrowSchema,
            usize,
        )> = Vec::new();
        let mut total: usize = 0;
        try_reserve_one(&mut stack)?;
        stack.push((array, schema, 0));
        while let Some((a, s, depth)) = stack.pop() {
            total += 1;
            if total > MAX_ARROW_SCHEMA_TOTAL_NODES {
                return Err(arrow_ingest_err(format!(
                    "Arrow array total node count exceeds {}",
                    MAX_ARROW_SCHEMA_TOTAL_NODES
                )));
            }
            if depth >= MAX_ARROW_SCHEMA_DEPTH {
                return Err(arrow_ingest_err(format!(
                    "Arrow array nesting depth exceeds {}",
                    MAX_ARROW_SCHEMA_DEPTH
                )));
            }
            let length = (*a).length;
            let offset = (*a).offset;
            if length < 0 {
                return Err(arrow_ingest_err(format!(
                    "Arrow array length {} is negative",
                    length
                )));
            }
            if offset < 0 {
                return Err(arrow_ingest_err(format!(
                    "Arrow array offset {} is negative",
                    offset
                )));
            }
            if length > MAX_ARROW_ARRAY_LENGTH {
                return Err(arrow_ingest_err(format!(
                    "Arrow array length {} exceeds {}",
                    length, MAX_ARROW_ARRAY_LENGTH
                )));
            }
            if offset > MAX_ARROW_ARRAY_LENGTH {
                return Err(arrow_ingest_err(format!(
                    "Arrow array offset {} exceeds {}",
                    offset, MAX_ARROW_ARRAY_LENGTH
                )));
            }
            let na = (*a).n_children;
            let ns = (*s).n_children;
            if na < 0 {
                return Err(arrow_ingest_err(format!(
                    "Arrow array n_children {} is negative",
                    na
                )));
            }
            if na != ns {
                return Err(arrow_ingest_err(format!(
                    "Arrow array n_children {} disagrees with schema n_children {}",
                    na, ns
                )));
            }
            if na > MAX_ARROW_SCHEMA_CHILDREN_PER_NODE {
                return Err(arrow_ingest_err(format!(
                    "Arrow array n_children {} exceeds per-node cap {}",
                    na, MAX_ARROW_SCHEMA_CHILDREN_PER_NODE
                )));
            }
            if (*a).n_buffers < 0 {
                return Err(arrow_ingest_err(format!(
                    "Arrow array n_buffers {} is negative",
                    (*a).n_buffers
                )));
            }
            if (*a).n_buffers > MAX_ARROW_ARRAY_N_BUFFERS_PER_NODE {
                return Err(arrow_ingest_err(format!(
                    "Arrow array n_buffers {} exceeds per-node cap {}",
                    (*a).n_buffers,
                    MAX_ARROW_ARRAY_N_BUFFERS_PER_NODE
                )));
            }
            // arrow-rs's `from_ffi` dereferences the buffer array and reads
            // every buffer slot the data type's layout requires *before*
            // `validate_full` runs. A NULL buffer pointer or fewer buffers
            // than the layout demands (a view type with `< 3` buffers
            // underflows `num_buffers - (2 + null_mask)`) each abort the
            // host under `panic = "abort"`. Reject them here; negative
            // fixed-size widths/sizes are handled by
            // `reject_overflowing_fixed_size` below.
            if (*a).n_buffers > 0 && (*a).buffers.is_null() {
                return Err(arrow_ingest_err(
                    "Arrow array declares buffers but the buffer pointer is NULL",
                ));
            }
            if let Ok(dt) = arrow::datatypes::DataType::try_from(&*s) {
                // Reject negative fixed-size widths/sizes that would overflow
                // arrow-rs's `bit_width`. Runs at every schema node, so a
                // negative size nested inside a container is caught when the
                // walk reaches that node, always before `from_ffi` runs.
                reject_overflowing_fixed_size(&dt)?;
                let min_buffers = arrow_min_n_buffers(&dt);
                if (*a).n_buffers < min_buffers {
                    return Err(arrow_ingest_err(format!(
                        "Arrow array declares {} buffers but {:?} requires at least {}",
                        (*a).n_buffers,
                        dt,
                        min_buffers
                    )));
                }
                // arrow-rs `from_ffi` dereferences the offset buffer of a
                // variable-width array (and the variadic-lengths buffer of a
                // view array) to size the data buffer, *before* `validate_full`
                // runs. A NULL pointer in those slots aborts the host under
                // `panic = "abort"`. Other NULL slots (e.g. an empty data
                // buffer, a NULL validity mask) import safely, so only reject
                // the eagerly-dereferenced ones here.
                use arrow::datatypes::DataType;
                let buffers = (*a).buffers;
                // `from_ffi` sizes buffers off a dictionary's key type, not the
                // dictionary itself (arrow `layout(Dictionary(key, _)) =>
                // layout(key)`), so the eager-deref checks below must match on
                // the key type too — otherwise `Dictionary(Utf8View, _)` skips
                // them and `from_ffi` dereferences a NULL variadic slot.
                let buf_dt = match &dt {
                    DataType::Dictionary(key, _) => key.as_ref(),
                    other => other,
                };
                let var_width = matches!(
                    buf_dt,
                    DataType::Utf8 | DataType::LargeUtf8 | DataType::Binary | DataType::LargeBinary
                );
                if var_width && (*a).length > 0 && (*buffers.add(1)).is_null() {
                    return Err(arrow_ingest_err(
                        "Arrow variable-width array offset buffer (slot 1) is NULL",
                    ));
                }
                let view = matches!(buf_dt, DataType::Utf8View | DataType::BinaryView);
                if view
                    && (*a).n_buffers > 3
                    && (*buffers.add(((*a).n_buffers - 1) as usize)).is_null()
                {
                    return Err(arrow_ingest_err(
                        "Arrow view array variadic-lengths buffer is NULL",
                    ));
                }
            }
            let dict_a = (*a).dictionary;
            let dict_s = (*s).dictionary;
            match (dict_a.is_null(), dict_s.is_null()) {
                (true, true) => {}
                (false, false) => {
                    try_reserve_one(&mut stack)?;
                    stack.push((dict_a as *const _, dict_s as *const _, depth + 1));
                }
                _ => {
                    return Err(arrow_ingest_err(
                        "Arrow array / schema disagree on dictionary presence",
                    ));
                }
            }
            if na == 0 {
                continue;
            }
            let a_children = (*a).children;
            let s_children = (*s).children;
            if a_children.is_null() || s_children.is_null() {
                return Err(arrow_ingest_err(
                    "Arrow array or schema declares children but pointer is NULL",
                ));
            }
            for i in 0..na as usize {
                let child_a = *a_children.add(i);
                let child_s = *s_children.add(i);
                if child_a.is_null() || child_s.is_null() {
                    return Err(arrow_ingest_err(
                        "Arrow array or schema child pointer is NULL",
                    ));
                }
                try_reserve_one(&mut stack)?;
                stack.push((child_a as *const _, child_s as *const _, depth + 1));
            }
        }
        Ok(())
    }
}

/// Validate, import (Arrow C Data Interface → arrow-rs), and bundle into
/// a `RecordBatch`. NULL array/schema or any validation failure sets
/// `*err_out` and returns `None`. On `Some`, the caller's
/// `array->release` has been consumed.
///
/// Shared by every FFI entry point that consumes a caller-built Arrow
/// C Data Interface pair (currently
/// `column_sender_flush_arrow_batch_server_stamped` / `_at_column`).
#[cfg(feature = "arrow")]
pub(crate) unsafe fn arrow_ffi_import_record_batch(
    array: *mut arrow::ffi::FFI_ArrowArray,
    schema: *const arrow::ffi::FFI_ArrowSchema,
    fn_name: &str,
    err_out: *mut *mut line_sender_error,
) -> Option<arrow_array::RecordBatch> {
    use arrow::datatypes::{DataType, Field, Schema};
    use arrow_array::{ArrayRef, RecordBatch, StructArray, make_array};
    use std::sync::Arc;
    unsafe {
        if array.is_null() || schema.is_null() {
            arrow_err_to_c_box(
                err_out,
                ErrorCode::InvalidApiCall,
                format!("{fn_name}: NULL array / schema"),
            );
            return None;
        }
        if (*array).release.is_none() {
            arrow_err_to_c_box(
                err_out,
                ErrorCode::InvalidApiCall,
                format!("{fn_name}: ArrowArray already consumed (release is NULL)"),
            );
            return None;
        }
        if let Err(e) = validate_arrow_array_depth(array, schema) {
            arrow_err_to_c_box(err_out, e.code(), e.msg().to_string());
            return None;
        }
        let imported_array = std::ptr::read(array);
        (*array).release = None;
        let array_data = match arrow::ffi::from_ffi(imported_array, &*schema) {
            Ok(d) => d,
            Err(e) => {
                arrow_err_to_c_box(
                    err_out,
                    ErrorCode::ArrowIngest,
                    format!("from_ffi failed: {}", e),
                );
                return None;
            }
        };
        if let Err(e) = array_data.validate_full() {
            arrow_err_to_c_box(
                err_out,
                ErrorCode::ArrowIngest,
                format!("Arrow array validation failed: {}", e),
            );
            return None;
        }
        let rb = if matches!(array_data.data_type(), DataType::Struct(_)) {
            if array_data.nulls().is_some_and(|n| n.null_count() > 0) {
                arrow_err_to_c_box(
                    err_out,
                    ErrorCode::ArrowIngest,
                    "top-level Struct array must have no null rows for RecordBatch ingest"
                        .to_string(),
                );
                return None;
            }
            let struct_arr = StructArray::from(array_data);
            let rb_schema = Arc::new(Schema::new(struct_arr.fields().clone()));
            let columns: Vec<ArrayRef> = struct_arr.columns().to_vec();
            match RecordBatch::try_new(rb_schema, columns) {
                Ok(rb) => rb,
                Err(e) => {
                    arrow_err_to_c_box(
                        err_out,
                        ErrorCode::ArrowIngest,
                        format!("RecordBatch::try_new failed: {}", e),
                    );
                    return None;
                }
            }
        } else {
            let field = match Field::try_from(&*schema) {
                Ok(f) => f,
                Err(e) => {
                    arrow_err_to_c_box(
                        err_out,
                        ErrorCode::ArrowIngest,
                        format!("schema conversion failed: {}", e),
                    );
                    return None;
                }
            };
            let arr_ref: ArrayRef = make_array(array_data);
            let rb_schema = Arc::new(Schema::new(vec![field]));
            match RecordBatch::try_new(rb_schema, vec![arr_ref]) {
                Ok(rb) => rb,
                Err(e) => {
                    arrow_err_to_c_box(
                        err_out,
                        ErrorCode::ArrowIngest,
                        format!("RecordBatch::try_new failed: {}", e),
                    );
                    return None;
                }
            }
        };
        Some(rb)
    }
}

/// Validate, import, and slice a single Arrow C Data Interface array
/// into an `ArrayRef`. `[row_offset, row_offset + row_count)` must lie
/// within the imported array's length. NULL pointers, depth-cap
/// violations, FFI-import failures, and out-of-range slices all set
/// `*err_out` and return `None`. On `Some`, the caller's
/// `array->release` has been consumed and the returned `ArrayRef`'s
/// Arc keeper owns the underlying buffer lifetime.
#[cfg(feature = "arrow")]
pub(crate) unsafe fn arrow_ffi_import_array_sliced(
    array: *mut arrow::ffi::FFI_ArrowArray,
    schema: *const arrow::ffi::FFI_ArrowSchema,
    row_offset: usize,
    row_count: usize,
    fn_name: &str,
    err_out: *mut *mut line_sender_error,
) -> Option<arrow_array::ArrayRef> {
    use arrow_array::make_array;
    unsafe {
        if array.is_null() || schema.is_null() {
            arrow_err_to_c_box(
                err_out,
                ErrorCode::InvalidApiCall,
                format!("{fn_name}: NULL array / schema"),
            );
            return None;
        }
        if (*array).release.is_none() {
            arrow_err_to_c_box(
                err_out,
                ErrorCode::InvalidApiCall,
                format!("{fn_name}: ArrowArray has already been consumed"),
            );
            return None;
        }
        if let Err(e) = validate_arrow_array_depth(array, schema) {
            arrow_err_to_c_box(err_out, e.code(), e.msg().to_string());
            return None;
        }
        let imported_array = std::ptr::read(array);
        (*array).release = None;
        let array_data = match arrow::ffi::from_ffi(imported_array, &*schema) {
            Ok(d) => d,
            Err(e) => {
                arrow_err_to_c_box(
                    err_out,
                    ErrorCode::ArrowIngest,
                    format!("from_ffi failed: {}", e),
                );
                return None;
            }
        };
        if let Err(e) = array_data.validate_full() {
            arrow_err_to_c_box(
                err_out,
                ErrorCode::ArrowIngest,
                format!("Arrow array validation failed: {}", e),
            );
            return None;
        }
        let full = make_array(array_data);
        let array_len = full.len();
        let slice_end = match row_offset.checked_add(row_count) {
            Some(end) => end,
            None => {
                arrow_err_to_c_box(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    format!("{fn_name}: row_offset {row_offset} + row_count {row_count} overflows",),
                );
                return None;
            }
        };
        if slice_end > array_len {
            arrow_err_to_c_box(
                err_out,
                ErrorCode::InvalidApiCall,
                format!(
                    "{fn_name}: slice [{row_offset}, {slice_end}) out of range for array length {array_len}",
                ),
            );
            return None;
        }
        Some(if row_offset == 0 && row_count == array_len {
            full
        } else {
            full.slice(row_offset, row_count)
        })
    }
}

#[cfg(feature = "arrow")]
pub(crate) unsafe fn arrow_ffi_import_column(
    array: *mut arrow::ffi::FFI_ArrowArray,
    schema: *const arrow::ffi::FFI_ArrowSchema,
    symbol: Option<bool>,
    fn_name: &str,
    err_out: *mut *mut line_sender_error,
) -> Option<questdb::ingress::column_sender::ImportedArrowColumn> {
    unsafe {
        if array.is_null() || schema.is_null() {
            arrow_err_to_c_box(
                err_out,
                ErrorCode::InvalidApiCall,
                format!("{fn_name}: NULL array / schema"),
            );
            return None;
        }
        if (*array).release.is_none() {
            arrow_err_to_c_box(
                err_out,
                ErrorCode::InvalidApiCall,
                format!("{fn_name}: ArrowArray has already been consumed"),
            );
            return None;
        }
        if let Err(e) = validate_arrow_array_depth(array, schema) {
            arrow_err_to_c_box(err_out, e.code(), e.msg().to_string());
            return None;
        }
        match questdb::ingress::column_sender::ImportedArrowColumn::import_from_ffi(
            &mut *array,
            &*schema,
            symbol,
        ) {
            Ok(imported) => Some(imported),
            Err(err) => {
                set_err_out_from_error(err_out, err);
                None
            }
        }
    }
}

#[cfg(feature = "arrow")]
pub(crate) fn arrow_err_to_c_box(
    err_out: *mut *mut line_sender_error,
    code: ErrorCode,
    msg: String,
) {
    unsafe {
        if err_out.is_null() {
            return;
        }
        *err_out = Box::into_raw(Box::new(line_sender_error {
            error: Error::new(code, msg),
            qwp_ws_error: None,
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    };
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
    fn line_sender_error_in_doubt_is_null_safe() {
        assert!(!unsafe { line_sender_error_in_doubt(ptr::null()) });
    }

    #[test]
    fn line_sender_error_in_doubt_round_trips_the_flag() {
        use questdb::ingress::column_sender::FlushFailure;

        // A plain error is not in doubt.
        let plain = Box::into_raw(Box::new(line_sender_error {
            error: Error::new(ErrorCode::SocketError, "boom"),
            qwp_ws_error: None,
        }));
        assert!(!unsafe { line_sender_error_in_doubt(plain) });
        unsafe { line_sender_error_free(plain) };

        // A delivery-unknown failure surfaces in_doubt even though it reports
        // FailoverRetry (the publish-only manual-chunk partial-write case).
        let in_doubt_err =
            FlushFailure::DeliveryUnknown(Error::new(ErrorCode::FailoverRetry, "mid-frame"))
                .into_error();
        let in_doubt = Box::into_raw(Box::new(line_sender_error {
            error: in_doubt_err,
            qwp_ws_error: None,
        }));
        assert!(unsafe { line_sender_error_in_doubt(in_doubt) });
        assert_err_code(
            unsafe { line_sender_error_get_code(in_doubt) },
            line_sender_error_code::line_sender_error_failover_retry,
        );
        unsafe { line_sender_error_free(in_doubt) };
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
            // New since 7.0.0 — arrow feature. Append-only.
            (line_sender_error_arrow_unsupported_column_kind, 15),
            (line_sender_error_arrow_ingest, 16),
            // Column-sender failover. Append-only.
            (line_sender_error_failover_retry, 17),
            // Reader/egress role-filter exhaustion. Append-only.
            (line_sender_error_role_mismatch, 18),
        ];
        for (variant, want) in expected {
            assert_eq!(
                *variant as u32, *want,
                "{:?} discriminant changed — appended-only ABI broken",
                variant,
            );
        }
    }

    #[test]
    fn line_sender_error_code_covers_every_upstream_variant() {
        // Tripwire for the `_ =>` arm in `impl From<ErrorCode> for
        // line_sender_error_code`. Whenever a new variant is added
        // upstream, also add it to the iteration below; the runtime
        // assertion catches missing FFI mappings on the next test run.
        fn cover(code: ErrorCode) -> &'static str {
            match code {
                ErrorCode::CouldNotResolveAddr => "CouldNotResolveAddr",
                ErrorCode::InvalidApiCall => "InvalidApiCall",
                ErrorCode::SocketError => "SocketError",
                ErrorCode::InvalidUtf8 => "InvalidUtf8",
                ErrorCode::InvalidName => "InvalidName",
                ErrorCode::InvalidTimestamp => "InvalidTimestamp",
                ErrorCode::AuthError => "AuthError",
                ErrorCode::TlsError => "TlsError",
                ErrorCode::HttpNotSupported => "HttpNotSupported",
                ErrorCode::ServerFlushError => "ServerFlushError",
                ErrorCode::ConfigError => "ConfigError",
                ErrorCode::ArrayError => "ArrayError",
                ErrorCode::ProtocolVersionError => "ProtocolVersionError",
                ErrorCode::InvalidDecimal => "InvalidDecimal",
                ErrorCode::ServerRejection => "ServerRejection",
                ErrorCode::ArrowUnsupportedColumnKind => "ArrowUnsupportedColumnKind",
                ErrorCode::ArrowIngest => "ArrowIngest",
                ErrorCode::FailoverRetry => "FailoverRetry",
                ErrorCode::RoleMismatch => "RoleMismatch",
                _ => "unmapped",
            }
        }
        for code in [
            ErrorCode::CouldNotResolveAddr,
            ErrorCode::InvalidApiCall,
            ErrorCode::SocketError,
            ErrorCode::InvalidUtf8,
            ErrorCode::InvalidName,
            ErrorCode::InvalidTimestamp,
            ErrorCode::AuthError,
            ErrorCode::TlsError,
            ErrorCode::HttpNotSupported,
            ErrorCode::ServerFlushError,
            ErrorCode::ConfigError,
            ErrorCode::ArrayError,
            ErrorCode::ProtocolVersionError,
            ErrorCode::InvalidDecimal,
            ErrorCode::ServerRejection,
            ErrorCode::ArrowUnsupportedColumnKind,
            ErrorCode::ArrowIngest,
            ErrorCode::FailoverRetry,
            ErrorCode::RoleMismatch,
        ] {
            assert_ne!(
                cover(code),
                "unmapped",
                "FFI mapping missing for {:?}",
                code
            );
        }
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
        // The mock server sets a short per-read timeout (~50ms) on accepted
        // sockets so the post-handshake read loop can poll for shutdown. That
        // same timeout applies to this handshake read, so a slow CI agent can
        // surface a transient WouldBlock/TimedOut before the client finishes
        // sending its upgrade request. Tolerate those by retrying until an
        // overall deadline, rather than propagating them (which previously made
        // callers .unwrap() panic and flake the test on macOS).
        let mut buf = Vec::new();
        let mut tmp = [0u8; 256];
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match stream.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&tmp[..n]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                Err(err)
                    if err.kind() == std::io::ErrorKind::WouldBlock
                        || err.kind() == std::io::ErrorKind::TimedOut =>
                {
                    if std::time::Instant::now() >= deadline {
                        return Err(err);
                    }
                }
                Err(err) => return Err(err),
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

    fn upgrade_mock_stream_with_request(stream: &mut TcpStream) -> std::io::Result<String> {
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
        stream.write_all(response.as_bytes())?;
        Ok(req.into_owned())
    }

    fn upgrade_mock_stream(stream: &mut TcpStream) {
        upgrade_mock_stream_with_request(stream).unwrap();
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

    #[cfg(feature = "sync-reader-qwp-ws")]
    fn write_server_info_frame(stream: &mut TcpStream) -> std::io::Result<()> {
        let mut payload = Vec::new();
        payload.push(0x18); // SERVER_INFO
        payload.push(0x00); // role = standalone
        payload.extend_from_slice(&1u64.to_le_bytes()); // epoch
        payload.extend_from_slice(&0u32.to_le_bytes()); // capabilities
        payload.extend_from_slice(&0i64.to_le_bytes()); // server_wall_ns
        payload.extend_from_slice(&0u16.to_le_bytes()); // cluster_id len
        payload.extend_from_slice(&0u16.to_le_bytes()); // node_id len

        let mut frame = Vec::with_capacity(12 + payload.len());
        frame.extend_from_slice(b"QWP1");
        frame.push(1); // version
        frame.push(0); // flags
        frame.extend_from_slice(&0u16.to_le_bytes()); // table_count
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(&payload);
        write_server_binary_frame(stream, &frame)
    }

    struct PooledQwpMock {
        port: u16,
        stop: Arc<AtomicBool>,
        join: Option<thread::JoinHandle<()>>,
    }

    impl PooledQwpMock {
        fn spawn(max_accepts: usize) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let port = listener.local_addr().unwrap().port();
            let stop = Arc::new(AtomicBool::new(false));
            let stop_c = Arc::clone(&stop);

            let join = thread::spawn(move || {
                let mut accepted = 0;
                let mut handlers = Vec::new();
                while accepted < max_accepts && !stop_c.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            accepted += 1;
                            stream
                                .set_read_timeout(Some(Duration::from_millis(50)))
                                .unwrap();
                            stream
                                .set_write_timeout(Some(Duration::from_secs(5)))
                                .unwrap();
                            let stop_h = Arc::clone(&stop_c);
                            handlers.push(thread::spawn(move || {
                                let _request = match upgrade_mock_stream_with_request(&mut stream) {
                                    Ok(request) => request,
                                    Err(_) => return,
                                };
                                #[cfg(feature = "sync-reader-qwp-ws")]
                                if _request.starts_with("GET /read/v1 ") {
                                    let _ = write_server_info_frame(&mut stream);
                                }
                                let mut buf = [0u8; 256];
                                while !stop_h.load(Ordering::SeqCst) {
                                    match stream.read(&mut buf) {
                                        Ok(0) => break,
                                        Ok(_) => {}
                                        Err(err)
                                            if err.kind() == std::io::ErrorKind::WouldBlock
                                                || err.kind() == std::io::ErrorKind::TimedOut => {}
                                        Err(_) => break,
                                    }
                                }
                            }));
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => break,
                    }
                }
                for handler in handlers {
                    let _ = handler.join();
                }
            });

            Self {
                port,
                stop,
                join: Some(join),
            }
        }

        fn conf(&self) -> String {
            format!(
                "qwpws::addr=127.0.0.1:{};pool_size=1;pool_max=2;close_flush_timeout_millis=50;",
                self.port
            )
        }
    }

    impl Drop for PooledQwpMock {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(join) = self.join.take() {
                let _ = join.join();
            }
        }
    }

    fn connect_pool(conf: &str, err: &mut *mut line_sender_error) -> *mut questdb_db {
        let db = unsafe { questdb_db_connect(conf.as_ptr() as *const c_char, conf.len(), err) };
        assert!(!db.is_null(), "pool connect failed");
        assert!(err.is_null(), "pool connect set unexpected error");
        db
    }

    fn assert_line_error_contains(
        err: &mut *mut line_sender_error,
        code: line_sender_error_code,
        needle: &str,
    ) {
        assert!(!err.is_null(), "expected line_sender_error");
        assert_err_code(unsafe { line_sender_error_get_code(*err) }, code);
        let message = read_error_message(*err);
        assert!(
            message.contains(needle),
            "expected error message to contain {needle:?}, got: {message}"
        );
        free_err(err);
    }

    #[cfg(feature = "sync-reader-qwp-ws")]
    fn assert_reader_error_contains(
        err: &mut *mut egress::reader_error,
        code: egress::reader_error_code,
        needle: &str,
    ) {
        assert!(!err.is_null(), "expected reader_error");
        assert_eq!(
            unsafe { egress::reader_error_get_code(*err) } as u32,
            code as u32
        );
        let message = unsafe {
            let mut len = 0;
            let ptr = egress::reader_error_msg(*err, &mut len);
            let bytes = std::slice::from_raw_parts(ptr as *const u8, len);
            String::from_utf8_lossy(bytes).into_owned()
        };
        assert!(
            message.contains(needle),
            "expected reader error message to contain {needle:?}, got: {message}"
        );
        unsafe { egress::reader_error_free(*err) };
        *err = ptr::null_mut();
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
    fn pooled_column_sender_rejects_flush_after_db_close_and_returns_safely() {
        let server = PooledQwpMock::spawn(1);
        unsafe {
            let mut err = ptr::null_mut();
            let conf = server.conf();
            let db = connect_pool(&conf, &mut err);

            let sender = questdb_db_borrow_sf_column_sender(db, &mut err);
            assert!(!sender.is_null());
            assert!(err.is_null());

            let table = b"trades";
            let chunk =
                column_sender_chunk_new(table.as_ptr() as *const c_char, table.len(), &mut err);
            assert!(!chunk.is_null());
            assert!(err.is_null());

            questdb_db_close(db);

            assert!(!sf_column_sender_flush(sender, chunk, &mut err));
            assert_line_error_contains(
                &mut err,
                line_sender_error_code::line_sender_error_invalid_api_call,
                "QuestDb pool is closed",
            );

            questdb_db_return_sf_column_sender(ptr::null_mut(), sender);
            column_sender_chunk_free(chunk);
        }
    }

    #[test]
    fn pooled_row_sender_rejects_flush_after_db_close_and_returns_safely() {
        let server = PooledQwpMock::spawn(2);
        unsafe {
            let mut err = ptr::null_mut();
            let conf = server.conf();
            let db = connect_pool(&conf, &mut err);

            let sender = questdb_db_borrow_row_sender(db, &mut err);
            assert!(!sender.is_null());
            assert!(err.is_null());

            let buffer = line_sender_buffer_new_qwp();
            assert!(!buffer.is_null());

            questdb_db_close(db);

            assert!(!row_sender_flush(sender, buffer, &mut err));
            assert_line_error_contains(
                &mut err,
                line_sender_error_code::line_sender_error_invalid_api_call,
                "QuestDb pool is closed",
            );

            questdb_db_return_row_sender(ptr::null_mut(), sender);
            line_sender_buffer_free(buffer);
        }
    }

    #[cfg(feature = "sync-reader-qwp-ws")]
    #[test]
    fn pooled_reader_rejects_prepare_after_db_close_and_closes_safely() {
        let server = PooledQwpMock::spawn(2);
        unsafe {
            let mut err = ptr::null_mut();
            let conf = server.conf();
            let db = egress::questdb_db_connect_reader(
                conf.as_ptr() as *const c_char,
                conf.len(),
                &mut err,
            );
            assert!(!db.is_null());
            assert!(err.is_null());

            let reader = egress::questdb_db_borrow_reader(db, &mut err);
            assert!(!reader.is_null());
            assert!(err.is_null());

            questdb_db_close(db);

            let query = egress::reader_prepare(reader, utf8(b"select 1"), &mut err);
            assert!(query.is_null());
            assert_reader_error_contains(
                &mut err,
                egress::reader_error_code::reader_error_invalid_api_call,
                "QuestDb pool is closed",
            );

            egress::reader_close(reader);
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

            assert!(!line_sender_qwpws_wait(sender, 0, 0, &mut err));
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

    #[cfg(feature = "arrow")]
    mod arrow_validator_tests {
        use super::super::*;
        use arrow::ffi::{FFI_ArrowArray, FFI_ArrowSchema};
        use std::ffi::CString;

        // Build a chain of FFI_ArrowSchemas via the `dictionary` pointer
        // of length `depth`. Each parent owns one child via a leaked
        // `Box<FFI_ArrowSchema>` so the test can free the chain manually
        // at teardown. The chain reuses the inner `format = "i"` Int32
        // tag — that's all `validate_arrow_schema_depth` reads.
        unsafe fn build_dict_chain(depth: usize) -> *mut FFI_ArrowSchema {
            let format = CString::new("i").unwrap();
            let mut head: *mut FFI_ArrowSchema = std::ptr::null_mut();
            for _ in 0..depth {
                let layout = std::alloc::Layout::new::<FFI_ArrowSchema>();
                let raw = unsafe { std::alloc::alloc_zeroed(layout) } as *mut FFI_ArrowSchema;
                unsafe {
                    (*raw).format = format.as_ptr();
                    (*raw).dictionary = head;
                }
                head = raw;
            }
            std::mem::forget(format);
            head
        }

        unsafe fn drop_dict_chain(mut node: *mut FFI_ArrowSchema) {
            while !node.is_null() {
                let next = unsafe { (*node).dictionary };
                let layout = std::alloc::Layout::new::<FFI_ArrowSchema>();
                unsafe { std::alloc::dealloc(node as *mut u8, layout) };
                node = next;
            }
        }

        #[test]
        fn schema_dictionary_chain_at_depth_cap_succeeds() {
            unsafe {
                let head = build_dict_chain(MAX_ARROW_SCHEMA_DEPTH);
                let res = validate_arrow_schema_depth(head);
                drop_dict_chain(head);
                assert!(res.is_ok(), "depth = cap should be accepted: {:?}", res);
            }
        }

        #[test]
        fn schema_dictionary_chain_above_depth_cap_rejected() {
            unsafe {
                let head = build_dict_chain(MAX_ARROW_SCHEMA_DEPTH + 2);
                let res = validate_arrow_schema_depth(head);
                drop_dict_chain(head);
                let err = res.unwrap_err();
                assert!(
                    err.msg().contains("depth"),
                    "expected depth-cap error, got: {}",
                    err.msg()
                );
            }
        }

        #[test]
        fn schema_null_format_rejected() {
            unsafe {
                let layout = std::alloc::Layout::new::<FFI_ArrowSchema>();
                let raw = std::alloc::alloc_zeroed(layout) as *mut FFI_ArrowSchema;
                let res = validate_arrow_schema_depth(raw);
                std::alloc::dealloc(raw as *mut u8, layout);
                let err = res.unwrap_err();
                assert!(
                    err.msg().contains("format"),
                    "expected format-NULL error, got: {}",
                    err.msg()
                );
            }
        }

        #[test]
        fn schema_negative_n_children_rejected() {
            unsafe {
                let format = CString::new("i").unwrap();
                let layout = std::alloc::Layout::new::<FFI_ArrowSchema>();
                let raw = std::alloc::alloc_zeroed(layout) as *mut FFI_ArrowSchema;
                (*raw).format = format.as_ptr();
                (*raw).n_children = -1;
                let res = validate_arrow_schema_depth(raw);
                std::alloc::dealloc(raw as *mut u8, layout);
                let err = res.unwrap_err();
                assert!(
                    err.msg().contains("negative"),
                    "expected negative-n_children error, got: {}",
                    err.msg()
                );
            }
        }

        #[test]
        fn schema_breadth_above_cap_rejected() {
            unsafe {
                let format = CString::new("i").unwrap();
                let layout = std::alloc::Layout::new::<FFI_ArrowSchema>();
                let raw = std::alloc::alloc_zeroed(layout) as *mut FFI_ArrowSchema;
                (*raw).format = format.as_ptr();
                (*raw).n_children = MAX_ARROW_SCHEMA_CHILDREN_PER_NODE + 1;
                let res = validate_arrow_schema_depth(raw);
                std::alloc::dealloc(raw as *mut u8, layout);
                let err = res.unwrap_err();
                assert!(
                    err.msg().contains("n_children"),
                    "expected n_children-cap error, got: {}",
                    err.msg()
                );
            }
        }

        #[test]
        fn array_n_buffers_negative_rejected() {
            unsafe {
                let format = CString::new("i").unwrap();
                let s_layout = std::alloc::Layout::new::<FFI_ArrowSchema>();
                let s_raw = std::alloc::alloc_zeroed(s_layout) as *mut FFI_ArrowSchema;
                (*s_raw).format = format.as_ptr();
                let a_layout = std::alloc::Layout::new::<FFI_ArrowArray>();
                let a_raw = std::alloc::alloc_zeroed(a_layout) as *mut FFI_ArrowArray;
                (*a_raw).n_buffers = -1;
                let res = validate_arrow_array_depth(a_raw, s_raw);
                std::alloc::dealloc(s_raw as *mut u8, s_layout);
                std::alloc::dealloc(a_raw as *mut u8, a_layout);
                let err = res.unwrap_err();
                assert!(
                    err.msg().contains("n_buffers"),
                    "expected n_buffers-negative error, got: {}",
                    err.msg()
                );
            }
        }

        #[test]
        fn array_n_buffers_above_cap_rejected() {
            unsafe {
                let format = CString::new("i").unwrap();
                let s_layout = std::alloc::Layout::new::<FFI_ArrowSchema>();
                let s_raw = std::alloc::alloc_zeroed(s_layout) as *mut FFI_ArrowSchema;
                (*s_raw).format = format.as_ptr();
                let a_layout = std::alloc::Layout::new::<FFI_ArrowArray>();
                let a_raw = std::alloc::alloc_zeroed(a_layout) as *mut FFI_ArrowArray;
                (*a_raw).n_buffers = MAX_ARROW_ARRAY_N_BUFFERS_PER_NODE + 1;
                let res = validate_arrow_array_depth(a_raw, s_raw);
                std::alloc::dealloc(s_raw as *mut u8, s_layout);
                std::alloc::dealloc(a_raw as *mut u8, a_layout);
                let err = res.unwrap_err();
                assert!(
                    err.msg().contains("n_buffers"),
                    "expected n_buffers-cap error, got: {}",
                    err.msg()
                );
            }
        }

        #[test]
        fn array_null_buffers_pointer_rejected() {
            unsafe {
                let format = CString::new("i").unwrap();
                let s_layout = std::alloc::Layout::new::<FFI_ArrowSchema>();
                let s_raw = std::alloc::alloc_zeroed(s_layout) as *mut FFI_ArrowSchema;
                (*s_raw).format = format.as_ptr();
                let a_layout = std::alloc::Layout::new::<FFI_ArrowArray>();
                let a_raw = std::alloc::alloc_zeroed(a_layout) as *mut FFI_ArrowArray;
                (*a_raw).n_buffers = 2;
                let res = validate_arrow_array_depth(a_raw, s_raw);
                std::alloc::dealloc(s_raw as *mut u8, s_layout);
                std::alloc::dealloc(a_raw as *mut u8, a_layout);
                let err = res.unwrap_err();
                assert!(
                    err.msg().contains("buffer pointer is NULL"),
                    "expected NULL-buffers error, got: {}",
                    err.msg()
                );
            }
        }

        #[test]
        fn array_null_offset_buffer_slot_rejected() {
            // Utf8 with a non-NULL buffers array but a NULL offsets slot
            // (index 1) — the slot arrow-rs `from_ffi` dereferences before
            // `validate_full`, which would abort under `panic = "abort"`.
            unsafe {
                let format = CString::new("u").unwrap();
                let s_layout = std::alloc::Layout::new::<FFI_ArrowSchema>();
                let s_raw = std::alloc::alloc_zeroed(s_layout) as *mut FFI_ArrowSchema;
                (*s_raw).format = format.as_ptr();
                let a_layout = std::alloc::Layout::new::<FFI_ArrowArray>();
                let a_raw = std::alloc::alloc_zeroed(a_layout) as *mut FFI_ArrowArray;
                let validity: u8 = 0;
                let data: u8 = 0;
                let mut slots: [*const std::ffi::c_void; 3] = [
                    &validity as *const u8 as *const std::ffi::c_void,
                    std::ptr::null(),
                    &data as *const u8 as *const std::ffi::c_void,
                ];
                (*a_raw).length = 1;
                (*a_raw).n_buffers = 3;
                (*a_raw).buffers = slots.as_mut_ptr();
                let res = validate_arrow_array_depth(a_raw, s_raw);
                (*a_raw).buffers = std::ptr::null_mut();
                std::alloc::dealloc(s_raw as *mut u8, s_layout);
                std::alloc::dealloc(a_raw as *mut u8, a_layout);
                let err = res.unwrap_err();
                assert!(
                    err.msg().contains("offset buffer"),
                    "expected NULL offset-buffer rejection, got: {}",
                    err.msg()
                );
            }
        }

        #[test]
        fn array_too_few_buffers_for_view_rejected() {
            unsafe {
                let format = CString::new("vu").unwrap();
                let s_layout = std::alloc::Layout::new::<FFI_ArrowSchema>();
                let s_raw = std::alloc::alloc_zeroed(s_layout) as *mut FFI_ArrowSchema;
                (*s_raw).format = format.as_ptr();
                let a_layout = std::alloc::Layout::new::<FFI_ArrowArray>();
                let a_raw = std::alloc::alloc_zeroed(a_layout) as *mut FFI_ArrowArray;
                (*a_raw).n_buffers = 0;
                let res = validate_arrow_array_depth(a_raw, s_raw);
                std::alloc::dealloc(s_raw as *mut u8, s_layout);
                std::alloc::dealloc(a_raw as *mut u8, a_layout);
                let err = res.unwrap_err();
                assert!(
                    err.msg().contains("requires at least"),
                    "expected too-few-buffers error, got: {}",
                    err.msg()
                );
            }
        }

        #[test]
        fn array_dictionary_view_key_null_variadic_buffer_rejected() {
            // A dictionary whose index (key) type is a view ("vu" = Utf8View)
            // is structurally invalid but parses to `Dictionary(Utf8View, _)`.
            // `from_ffi` sizes buffers off the key type, so a NULL
            // variadic-lengths slot would be dereferenced before
            // `validate_full`. The pre-walk must strip the dictionary and
            // reject it here.
            unsafe {
                let key_format = CString::new("vu").unwrap();
                let val_format = CString::new("u").unwrap();
                let v_layout = std::alloc::Layout::new::<FFI_ArrowSchema>();
                let v_raw = std::alloc::alloc_zeroed(v_layout) as *mut FFI_ArrowSchema;
                (*v_raw).format = val_format.as_ptr();
                let s_layout = std::alloc::Layout::new::<FFI_ArrowSchema>();
                let s_raw = std::alloc::alloc_zeroed(s_layout) as *mut FFI_ArrowSchema;
                (*s_raw).format = key_format.as_ptr();
                (*s_raw).dictionary = v_raw;
                let a_layout = std::alloc::Layout::new::<FFI_ArrowArray>();
                let a_raw = std::alloc::alloc_zeroed(a_layout) as *mut FFI_ArrowArray;
                let dummy: u8 = 0;
                let p = &dummy as *const u8 as *const std::ffi::c_void;
                let mut slots: [*const std::ffi::c_void; 4] = [p, p, p, std::ptr::null()];
                (*a_raw).length = 1;
                (*a_raw).n_buffers = 4;
                (*a_raw).buffers = slots.as_mut_ptr();
                let res = validate_arrow_array_depth(a_raw, s_raw);
                (*a_raw).buffers = std::ptr::null_mut();
                (*s_raw).dictionary = std::ptr::null_mut();
                std::alloc::dealloc(v_raw as *mut u8, v_layout);
                std::alloc::dealloc(s_raw as *mut u8, s_layout);
                std::alloc::dealloc(a_raw as *mut u8, a_layout);
                let err = res.unwrap_err();
                assert!(
                    err.msg().contains("variadic-lengths buffer is NULL"),
                    "expected NULL variadic-lengths rejection, got: {}",
                    err.msg()
                );
            }
        }

        #[test]
        fn schema_metadata_entry_count_above_cap_rejected() {
            unsafe {
                let format = CString::new("i").unwrap();
                let blob = (MAX_ARROW_SCHEMA_METADATA_ENTRIES + 1).to_ne_bytes();
                let layout = std::alloc::Layout::new::<FFI_ArrowSchema>();
                let raw = std::alloc::alloc_zeroed(layout) as *mut FFI_ArrowSchema;
                (*raw).format = format.as_ptr();
                (*raw).metadata = blob.as_ptr() as *const std::ffi::c_char;
                let res = validate_arrow_schema_depth(raw);
                (*raw).metadata = std::ptr::null();
                std::alloc::dealloc(raw as *mut u8, layout);
                let err = res.unwrap_err();
                assert!(
                    err.msg().contains("metadata"),
                    "expected metadata entry-count rejection, got: {}",
                    err.msg()
                );
            }
        }

        #[test]
        fn array_negative_fixed_size_binary_width_rejected() {
            unsafe {
                let format = CString::new("w:-4").unwrap();
                let s_layout = std::alloc::Layout::new::<FFI_ArrowSchema>();
                let s_raw = std::alloc::alloc_zeroed(s_layout) as *mut FFI_ArrowSchema;
                (*s_raw).format = format.as_ptr();
                let a_layout = std::alloc::Layout::new::<FFI_ArrowArray>();
                let a_raw = std::alloc::alloc_zeroed(a_layout) as *mut FFI_ArrowArray;
                (*a_raw).n_buffers = 0;
                let res = validate_arrow_array_depth(a_raw, s_raw);
                std::alloc::dealloc(s_raw as *mut u8, s_layout);
                std::alloc::dealloc(a_raw as *mut u8, a_layout);
                let err = res.unwrap_err();
                assert!(
                    err.msg().contains("negative"),
                    "expected negative-width error, got: {}",
                    err.msg()
                );
            }
        }

        #[test]
        fn array_negative_fixed_size_list_size_rejected() {
            unsafe {
                // Child schema Int32 ("i"): DataType::try_from("+w:-1") calls
                // child(0)/Field::try_from, so the parent needs a valid child.
                let child_fmt = CString::new("i").unwrap();
                let cs_layout = std::alloc::Layout::new::<FFI_ArrowSchema>();
                let cs_raw = std::alloc::alloc_zeroed(cs_layout) as *mut FFI_ArrowSchema;
                (*cs_raw).format = child_fmt.as_ptr();

                // Parent schema: FixedSizeList with negative list size.
                let format = CString::new("+w:-1").unwrap();
                let s_layout = std::alloc::Layout::new::<FFI_ArrowSchema>();
                let s_raw = std::alloc::alloc_zeroed(s_layout) as *mut FFI_ArrowSchema;
                (*s_raw).format = format.as_ptr();
                (*s_raw).n_children = 1;
                let mut s_children: [*mut FFI_ArrowSchema; 1] = [cs_raw];
                (*s_raw).children = s_children.as_mut_ptr();

                // Array: n_buffers = 2 (>= the FixedSizeList floor of 1) with a
                // non-NULL buffers array, so the only defect is the negative
                // size. Without a guard, arrow-rs `from_ffi` would compute
                // `child_bits * (size as usize)` with `size == -1`, overflowing
                // and aborting under `panic = "abort"` + overflow-checks.
                let a_layout = std::alloc::Layout::new::<FFI_ArrowArray>();
                let a_raw = std::alloc::alloc_zeroed(a_layout) as *mut FFI_ArrowArray;
                (*a_raw).n_children = 1;
                let b0: u8 = 0;
                let b1: u8 = 0;
                let mut slots: [*const std::ffi::c_void; 2] = [
                    &b0 as *const u8 as *const std::ffi::c_void,
                    &b1 as *const u8 as *const std::ffi::c_void,
                ];
                (*a_raw).n_buffers = 2;
                (*a_raw).buffers = slots.as_mut_ptr();

                let res = validate_arrow_array_depth(a_raw, s_raw);
                (*a_raw).buffers = std::ptr::null_mut();
                (*s_raw).children = std::ptr::null_mut();
                std::alloc::dealloc(cs_raw as *mut u8, cs_layout);
                std::alloc::dealloc(s_raw as *mut u8, s_layout);
                std::alloc::dealloc(a_raw as *mut u8, a_layout);
                let err = res.unwrap_err();
                assert!(
                    err.msg().contains("negative"),
                    "expected negative FixedSizeList size error, got: {}",
                    err.msg()
                );
            }
        }

        #[test]
        fn array_nested_negative_fixed_size_list_size_rejected() {
            // FixedSizeList(FixedSizeList(Int32, -1), 3). arrow-rs would
            // overflow while sizing the *outer* list's buffer (its `bit_width`
            // recurses into the inner type inline). The validator's per-node
            // walk reaches the inner node and `reject_overflowing_fixed_size`
            // rejects it before `from_ffi` is ever called.
            unsafe {
                let leaf_fmt = CString::new("i").unwrap();
                let inner_fmt = CString::new("+w:-1").unwrap();
                let outer_fmt = CString::new("+w:3").unwrap();

                let s_layout = std::alloc::Layout::new::<FFI_ArrowSchema>();
                let leaf_s = std::alloc::alloc_zeroed(s_layout) as *mut FFI_ArrowSchema;
                (*leaf_s).format = leaf_fmt.as_ptr();
                let inner_s = std::alloc::alloc_zeroed(s_layout) as *mut FFI_ArrowSchema;
                (*inner_s).format = inner_fmt.as_ptr();
                (*inner_s).n_children = 1;
                let mut inner_s_children: [*mut FFI_ArrowSchema; 1] = [leaf_s];
                (*inner_s).children = inner_s_children.as_mut_ptr();
                let outer_s = std::alloc::alloc_zeroed(s_layout) as *mut FFI_ArrowSchema;
                (*outer_s).format = outer_fmt.as_ptr();
                (*outer_s).n_children = 1;
                let mut outer_s_children: [*mut FFI_ArrowSchema; 1] = [inner_s];
                (*outer_s).children = outer_s_children.as_mut_ptr();

                let a_layout = std::alloc::Layout::new::<FFI_ArrowArray>();
                // Inner array: only n_children must agree (1); it is rejected
                // before its buffers/children are ever read.
                let inner_a = std::alloc::alloc_zeroed(a_layout) as *mut FFI_ArrowArray;
                (*inner_a).n_children = 1;
                let outer_a = std::alloc::alloc_zeroed(a_layout) as *mut FFI_ArrowArray;
                (*outer_a).n_children = 1;
                let b: u8 = 0;
                let mut outer_slots: [*const std::ffi::c_void; 1] =
                    [&b as *const u8 as *const std::ffi::c_void];
                (*outer_a).n_buffers = 1; // FixedSizeList floor
                (*outer_a).buffers = outer_slots.as_mut_ptr();
                let mut outer_a_children: [*mut FFI_ArrowArray; 1] = [inner_a];
                (*outer_a).children = outer_a_children.as_mut_ptr();

                let res = validate_arrow_array_depth(outer_a, outer_s);

                (*outer_a).buffers = std::ptr::null_mut();
                (*outer_a).children = std::ptr::null_mut();
                (*outer_s).children = std::ptr::null_mut();
                (*inner_s).children = std::ptr::null_mut();
                std::alloc::dealloc(leaf_s as *mut u8, s_layout);
                std::alloc::dealloc(inner_s as *mut u8, s_layout);
                std::alloc::dealloc(outer_s as *mut u8, s_layout);
                std::alloc::dealloc(inner_a as *mut u8, a_layout);
                std::alloc::dealloc(outer_a as *mut u8, a_layout);

                let err = res.unwrap_err();
                assert!(
                    err.msg().contains("FixedSizeList size -1 is negative"),
                    "expected nested negative FixedSizeList rejection, got: {}",
                    err.msg()
                );
            }
        }

        #[test]
        fn array_schema_n_children_mismatch_rejected() {
            unsafe {
                let format = CString::new("+s").unwrap();
                let s_layout = std::alloc::Layout::new::<FFI_ArrowSchema>();
                let s_raw = std::alloc::alloc_zeroed(s_layout) as *mut FFI_ArrowSchema;
                (*s_raw).format = format.as_ptr();
                (*s_raw).n_children = 0;
                let a_layout = std::alloc::Layout::new::<FFI_ArrowArray>();
                let a_raw = std::alloc::alloc_zeroed(a_layout) as *mut FFI_ArrowArray;
                (*a_raw).n_children = 5;
                let res = validate_arrow_array_depth(a_raw, s_raw);
                std::alloc::dealloc(s_raw as *mut u8, s_layout);
                std::alloc::dealloc(a_raw as *mut u8, a_layout);
                let err = res.unwrap_err();
                assert!(
                    err.msg().contains("disagrees"),
                    "expected n_children-disagreement error, got: {}",
                    err.msg()
                );
            }
        }

        #[test]
        fn schema_nested_format_missing_children_rejected() {
            // A nested format (List/LargeList/ListView/Map/FixedSizeList) with
            // too few children must be rejected here; otherwise
            // DataType::try_from would call child(0) and abort the host.
            for (fmt, n_children) in [
                ("+l", 0),
                ("+L", 0),
                ("+vl", 0),
                ("+vL", 0),
                ("+m", 0),
                ("+w:3", 0),
                ("+r", 1),
            ] {
                unsafe {
                    let format = CString::new(fmt).unwrap();
                    let layout = std::alloc::Layout::new::<FFI_ArrowSchema>();
                    let raw = std::alloc::alloc_zeroed(layout) as *mut FFI_ArrowSchema;
                    (*raw).format = format.as_ptr();
                    (*raw).n_children = n_children;
                    let res = validate_arrow_schema_depth(raw);
                    std::alloc::dealloc(raw as *mut u8, layout);
                    let err = res.unwrap_err();
                    assert!(
                        err.msg().contains("requires at least"),
                        "format {fmt} with {n_children} children: expected min-children rejection, got: {}",
                        err.msg()
                    );
                }
            }
        }

        #[test]
        fn schema_self_dictionary_cycle_rejected() {
            // Self-cycles are not flagged by name (DAGs with shared
            // children are legal) but the depth / total-nodes caps
            // make traversal terminate with a bounded-size error.
            unsafe {
                let format = CString::new("i").unwrap();
                let layout = std::alloc::Layout::new::<FFI_ArrowSchema>();
                let raw = std::alloc::alloc_zeroed(layout) as *mut FFI_ArrowSchema;
                (*raw).format = format.as_ptr();
                (*raw).dictionary = raw;
                let res = validate_arrow_schema_depth(raw);
                (*raw).dictionary = std::ptr::null_mut();
                std::alloc::dealloc(raw as *mut u8, layout);
                let err = res.unwrap_err();
                assert!(
                    err.msg().contains("depth") || err.msg().contains("total"),
                    "expected depth/total cap rejection, got: {}",
                    err.msg()
                );
            }
        }

        #[test]
        fn array_self_dictionary_cycle_rejected() {
            unsafe {
                let format = CString::new("i").unwrap();
                let s_layout = std::alloc::Layout::new::<FFI_ArrowSchema>();
                let s_raw = std::alloc::alloc_zeroed(s_layout) as *mut FFI_ArrowSchema;
                (*s_raw).format = format.as_ptr();
                (*s_raw).dictionary = s_raw;
                let a_layout = std::alloc::Layout::new::<FFI_ArrowArray>();
                let a_raw = std::alloc::alloc_zeroed(a_layout) as *mut FFI_ArrowArray;
                (*a_raw).dictionary = a_raw;
                let res = validate_arrow_array_depth(a_raw, s_raw);
                (*s_raw).dictionary = std::ptr::null_mut();
                (*a_raw).dictionary = std::ptr::null_mut();
                std::alloc::dealloc(s_raw as *mut u8, s_layout);
                std::alloc::dealloc(a_raw as *mut u8, a_layout);
                let err = res.unwrap_err();
                assert!(
                    err.msg().contains("depth") || err.msg().contains("total"),
                    "expected depth/total cap rejection, got: {}",
                    err.msg()
                );
            }
        }

        #[test]
        fn array_negative_length_rejected() {
            unsafe {
                let format = CString::new("i").unwrap();
                let s_layout = std::alloc::Layout::new::<FFI_ArrowSchema>();
                let s_raw = std::alloc::alloc_zeroed(s_layout) as *mut FFI_ArrowSchema;
                (*s_raw).format = format.as_ptr();
                let a_layout = std::alloc::Layout::new::<FFI_ArrowArray>();
                let a_raw = std::alloc::alloc_zeroed(a_layout) as *mut FFI_ArrowArray;
                (*a_raw).length = -1;
                let res = validate_arrow_array_depth(a_raw, s_raw);
                std::alloc::dealloc(s_raw as *mut u8, s_layout);
                std::alloc::dealloc(a_raw as *mut u8, a_layout);
                let err = res.unwrap_err();
                assert!(
                    err.msg().contains("length"),
                    "expected negative-length error, got: {}",
                    err.msg()
                );
            }
        }

        #[test]
        fn array_negative_offset_rejected() {
            unsafe {
                let format = CString::new("i").unwrap();
                let s_layout = std::alloc::Layout::new::<FFI_ArrowSchema>();
                let s_raw = std::alloc::alloc_zeroed(s_layout) as *mut FFI_ArrowSchema;
                (*s_raw).format = format.as_ptr();
                let a_layout = std::alloc::Layout::new::<FFI_ArrowArray>();
                let a_raw = std::alloc::alloc_zeroed(a_layout) as *mut FFI_ArrowArray;
                (*a_raw).offset = -1;
                let res = validate_arrow_array_depth(a_raw, s_raw);
                std::alloc::dealloc(s_raw as *mut u8, s_layout);
                std::alloc::dealloc(a_raw as *mut u8, a_layout);
                let err = res.unwrap_err();
                assert!(
                    err.msg().contains("offset"),
                    "expected negative-offset error, got: {}",
                    err.msg()
                );
            }
        }

        #[test]
        fn array_length_above_cap_rejected() {
            unsafe {
                let format = CString::new("i").unwrap();
                let s_layout = std::alloc::Layout::new::<FFI_ArrowSchema>();
                let s_raw = std::alloc::alloc_zeroed(s_layout) as *mut FFI_ArrowSchema;
                (*s_raw).format = format.as_ptr();
                let a_layout = std::alloc::Layout::new::<FFI_ArrowArray>();
                let a_raw = std::alloc::alloc_zeroed(a_layout) as *mut FFI_ArrowArray;
                (*a_raw).length = MAX_ARROW_ARRAY_LENGTH + 1;
                let res = validate_arrow_array_depth(a_raw, s_raw);
                std::alloc::dealloc(s_raw as *mut u8, s_layout);
                std::alloc::dealloc(a_raw as *mut u8, a_layout);
                let err = res.unwrap_err();
                assert!(
                    err.msg().contains("length"),
                    "expected length-cap error, got: {}",
                    err.msg()
                );
            }
        }
    }
}
