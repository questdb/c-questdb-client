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

//! C FFI bindings for the QuestDB Wire Protocol (QWP) egress reader.
//!
//! Surface covered: open `Reader` from config, build a query with bind
//! parameters, advance a `Cursor` batch-by-batch, and read columns by
//! `(col, row)` using per-kind getters. Failover callbacks and array
//! columns (`DOUBLE_ARRAY` / `LONG_ARRAY`) land in follow-up changes.

use std::cell::UnsafeCell;
use std::mem::ManuallyDrop;
use std::net::Ipv4Addr;
use std::ptr;
use std::slice;
use std::sync::atomic::{AtomicBool, Ordering};

use libc::{c_char, c_void, size_t};

use questdb::egress::{
    BatchView, ColumnKind, ColumnView, Cursor, Error, ErrorCode, FailoverEvent, Reader,
    ReaderQuery, ServerInfo, ServerRole, SimpleNullKind, Terminal, Validity,
};

use crate::line_sender_utf8;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// An error that occurred when using the line reader.
pub struct line_reader_error(Error);

/// Category of egress error. Mirrors `questdb::egress::ErrorCode`.
///
/// Discriminants are explicit and append-only — must stay in lockstep
/// with `line_reader_error_code` in `include/questdb/egress/line_reader.h`.
/// Inserting a new variant in the middle would silently renumber later
/// ones across recompiles and break ABI for any shared-library consumer
/// holding a previously-built header.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum line_reader_error_code {
    /// Bad URL, host, or interface in the connect string.
    line_reader_error_could_not_resolve_addr = 0,
    /// Bad configuration string or builder argument.
    line_reader_error_config_error = 1,
    /// Methods called in the wrong order (e.g. `execute` while a cursor is live).
    line_reader_error_invalid_api_call = 2,
    /// Network-level failure (connect, read, write, close).
    line_reader_error_socket_error = 3,
    /// TLS handshake failure.
    line_reader_error_tls_error = 4,
    /// HTTP-upgrade or WebSocket handshake failure.
    line_reader_error_handshake_error = 5,
    /// Authentication or authorization failure.
    line_reader_error_auth_error = 6,
    /// Server returned an unsupported QWP version, encoding, or capability.
    line_reader_error_unsupported_server = 7,
    /// All endpoints connected but none advertised a role matching the
    /// configured `target` filter.
    line_reader_error_role_mismatch = 8,
    /// Wire-format violation: bad magic, truncated frame, unknown
    /// discriminant, invalid varint, schema/symbol-dict reference miss, etc.
    line_reader_error_protocol_error = 9,
    /// String or symbol field was not valid UTF-8.
    line_reader_error_invalid_utf8 = 10,
    /// Bind parameter index, count, or value rejected client-side.
    line_reader_error_invalid_bind = 11,
    /// Invalid timestamp value.
    line_reader_error_invalid_timestamp = 12,
    /// Invalid decimal value.
    line_reader_error_invalid_decimal = 13,
    /// Server-reported QWP `SCHEMA_MISMATCH` (status `0x03`).
    line_reader_error_server_schema_mismatch = 14,
    /// Server-reported QWP `PARSE_ERROR` (status `0x05`).
    line_reader_error_server_parse_error = 15,
    /// Server-reported QWP `INTERNAL_ERROR` (status `0x06`).
    line_reader_error_server_internal_error = 16,
    /// Server-reported QWP `SECURITY_ERROR` (status `0x08`).
    line_reader_error_server_security_error = 17,
    /// Client-side limit hit (e.g. an array row exceeds the configured cap).
    line_reader_error_limit_exceeded = 18,
    /// Server-reported QWP `LIMIT_EXCEEDED` (status `0x0B`).
    line_reader_error_server_limit_exceeded = 19,
    /// Query was cancelled (locally or via server `CANCELLED` status `0x0A`).
    line_reader_error_cancelled = 20,
}

impl From<ErrorCode> for line_reader_error_code {
    fn from(code: ErrorCode) -> Self {
        use line_reader_error_code::*;
        match code {
            ErrorCode::CouldNotResolveAddr => line_reader_error_could_not_resolve_addr,
            ErrorCode::ConfigError => line_reader_error_config_error,
            ErrorCode::InvalidApiCall => line_reader_error_invalid_api_call,
            ErrorCode::SocketError => line_reader_error_socket_error,
            ErrorCode::TlsError => line_reader_error_tls_error,
            ErrorCode::HandshakeError => line_reader_error_handshake_error,
            ErrorCode::AuthError => line_reader_error_auth_error,
            ErrorCode::UnsupportedServer => line_reader_error_unsupported_server,
            ErrorCode::RoleMismatch => line_reader_error_role_mismatch,
            ErrorCode::ProtocolError => line_reader_error_protocol_error,
            ErrorCode::InvalidUtf8 => line_reader_error_invalid_utf8,
            ErrorCode::InvalidBind => line_reader_error_invalid_bind,
            ErrorCode::InvalidTimestamp => line_reader_error_invalid_timestamp,
            ErrorCode::InvalidDecimal => line_reader_error_invalid_decimal,
            ErrorCode::ServerSchemaMismatch => line_reader_error_server_schema_mismatch,
            ErrorCode::ServerParseError => line_reader_error_server_parse_error,
            ErrorCode::ServerInternalError => line_reader_error_server_internal_error,
            ErrorCode::ServerSecurityError => line_reader_error_server_security_error,
            ErrorCode::LimitExceeded => line_reader_error_limit_exceeded,
            ErrorCode::ServerLimitExceeded => line_reader_error_server_limit_exceeded,
            ErrorCode::Cancelled => line_reader_error_cancelled,
            // ErrorCode is `#[non_exhaustive]`. Any future variant added
            // upstream that the C ABI hasn't been taught about falls
            // back to ProtocolError so callers see *something* rather
            // than a build failure when versions skew. Production builds
            // should never hit this — both crates rebuild together
            // in-workspace.
            _ => line_reader_error_protocol_error,
        }
    }
}

/// NULL-handle guard for opaque-handle FFI entry points whose contract
/// disallows NULL. Calls match the policy already established in
/// `mutate_query` (the bind path) — log and abort, rather than silently
/// dereferencing into UB. Reserved for state-mutating cursor / reader
/// operations where a NULL deref would corrupt the FFI lifecycle; cheap
/// read-only stat getters keep the header's "NULL is UB" contract for
/// ergonomics.
macro_rules! null_check_handle {
    ($ptr:expr, $fn_name:literal) => {
        if $ptr.is_null() {
            eprintln!(
                "{}: NULL handle. This is a contract violation; aborting.",
                $fn_name
            );
            std::process::abort();
        }
    };
}

macro_rules! reader_bubble {
    ($err_out:expr, $expression:expr) => {
        reader_bubble!($err_out, $expression, false)
    };
    ($err_out:expr, $expression:expr, $sentinel:expr) => {
        match $expression {
            Ok(value) => value,
            Err(err) => {
                let err_ptr = Box::into_raw(Box::new(line_reader_error(err)));
                *$err_out = err_ptr;
                return $sentinel;
            }
        }
    };
}

unsafe fn set_reader_err(
    err_out: *mut *mut line_reader_error,
    code: ErrorCode,
    msg: impl Into<String>,
) {
    let err = line_reader_error(Error::new(code, msg.into()));
    unsafe {
        *err_out = Box::into_raw(Box::new(err));
    }
}

/// Panic-boundary helper for `extern "C"` entry points. Catches any unwind
/// from `f` and aborts the process — Rust panics escaping into C are UB.
/// Used by every entry point that calls upstream Rust code (decoder, drop
/// chains, allocator paths) where a panic is not currently reachable but a
/// future refactor could newly expose one. Mirrors the inline
/// `catch_unwind(AssertUnwindSafe(...))` pattern already used by
/// `_from_conf`, `_from_env`, `_query_new`, `_query_execute`, `mutate_query`,
/// and `_cursor_next_batch`.
#[inline]
fn panic_guard<R>(f: impl FnOnce() -> R) -> R {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(_) => std::process::abort(),
    }
}

/// Egress-private chokepoint for re-validating C-supplied
/// `line_sender_utf8` payloads.
///
/// Every reader-FFI entry that accepts a `line_sender_utf8` (today
/// `_from_conf`, `_query_new`, `_bind_varchar`; any future bind/builder
/// added here) MUST funnel that payload through this module's
/// `validated_utf8` helper before handing the bytes to upstream code.
///
/// `line_sender_utf8::as_str` uses `from_utf8_unchecked`; its contract
/// is that the caller already validated via `line_sender_utf8_init`.
/// The public C struct layout means a misbehaving C caller can
/// hand-roll the fields and pass arbitrary bytes — re-validating here
/// turns that contract violation into a clean `InvalidUtf8` error
/// instead of UB the moment upstream walks the slice as `&str`.
///
/// Structurally enforced by the type system: `line_sender_utf8` exposes
/// no `as_bytes()` accessor, so egress code that needs a `&str` has
/// only two paths — (a) `as_str()`, which is documented as
/// trusted-caller-only and is wrong for any input that came from the C
/// boundary, or (b) this module's `validated_utf8`, which always
/// re-validates. New egress entry points should reach for (b).
mod utf8_in {
    use super::{Error, ErrorCode, line_sender_utf8};

    pub(super) fn validated_utf8(v: &line_sender_utf8) -> Result<&str, Error> {
        v.validated_utf8().map_err(|e| {
            Error::new(
                ErrorCode::InvalidUtf8,
                format!(
                    "line_sender_utf8 payload is not valid UTF-8: {} (at byte {})",
                    e,
                    e.valid_up_to()
                ),
            )
        })
    }
}

use utf8_in::validated_utf8;

/// Error code categorising the error.
///
/// NULL-safe: passing `NULL` returns `line_reader_error_invalid_api_call`
/// (the caller is misusing the accessor) rather than dereferencing.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_error_get_code(
    error: *const line_reader_error,
) -> line_reader_error_code {
    if error.is_null() {
        return line_reader_error_code::line_reader_error_invalid_api_call;
    }
    unsafe { (*error).0.code().into() }
}

/// UTF-8 encoded error message. Never returns NULL.
/// `len_out` is set to the number of bytes; the string is NOT null-terminated.
///
/// NULL-safe on both `error` and `len_out`. A NULL `error` returns a static
/// empty string with `*len_out = 0` (when `len_out` is non-NULL); a NULL
/// `len_out` is silently ignored. The combination matches `_free`'s NULL-
/// safety, so a defensive caller can write
/// `_msg(err, &len); _free(err);` without first checking `err`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_error_msg(
    error: *const line_reader_error,
    len_out: *mut size_t,
) -> *const c_char {
    unsafe {
        if error.is_null() {
            if !len_out.is_null() {
                *len_out = 0;
            }
            // Static empty string — guaranteed non-NULL, zero-length, and
            // valid for any caller's lifetime.
            return c"".as_ptr();
        }
        let msg: &str = (*error).0.msg();
        if !len_out.is_null() {
            *len_out = msg.len();
        }
        msg.as_ptr() as *const c_char
    }
}

/// Free an error returned via an `err_out` parameter. Idempotent on NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_error_free(error: *mut line_reader_error) {
    unsafe {
        if !error.is_null() {
            drop(Box::from_raw(error));
        }
    }
}

// ---------------------------------------------------------------------------
// Column kind
// ---------------------------------------------------------------------------

/// Column kind discriminant. Mirrors `questdb::egress::ColumnKind`. Numeric
/// values match the QWP wire codes (and `ColumnKind::as_u8()`).
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub enum line_reader_column_kind {
    line_reader_column_kind_boolean = 0x01,
    line_reader_column_kind_byte = 0x02,
    line_reader_column_kind_short = 0x03,
    line_reader_column_kind_int = 0x04,
    line_reader_column_kind_long = 0x05,
    line_reader_column_kind_float = 0x06,
    line_reader_column_kind_double = 0x07,
    line_reader_column_kind_symbol = 0x09,
    line_reader_column_kind_timestamp = 0x0A,
    line_reader_column_kind_date = 0x0B,
    line_reader_column_kind_uuid = 0x0C,
    line_reader_column_kind_long256 = 0x0D,
    line_reader_column_kind_geohash = 0x0E,
    line_reader_column_kind_varchar = 0x0F,
    line_reader_column_kind_timestamp_nanos = 0x10,
    line_reader_column_kind_double_array = 0x11,
    line_reader_column_kind_long_array = 0x12,
    line_reader_column_kind_decimal64 = 0x13,
    line_reader_column_kind_decimal128 = 0x14,
    line_reader_column_kind_decimal256 = 0x15,
    line_reader_column_kind_char = 0x16,
    line_reader_column_kind_binary = 0x17,
    line_reader_column_kind_ipv4 = 0x18,
}

impl From<ColumnKind> for line_reader_column_kind {
    fn from(k: ColumnKind) -> Self {
        use line_reader_column_kind::*;
        match k {
            ColumnKind::Boolean => line_reader_column_kind_boolean,
            ColumnKind::Byte => line_reader_column_kind_byte,
            ColumnKind::Short => line_reader_column_kind_short,
            ColumnKind::Int => line_reader_column_kind_int,
            ColumnKind::Long => line_reader_column_kind_long,
            ColumnKind::Float => line_reader_column_kind_float,
            ColumnKind::Double => line_reader_column_kind_double,
            ColumnKind::Symbol => line_reader_column_kind_symbol,
            ColumnKind::Timestamp => line_reader_column_kind_timestamp,
            ColumnKind::Date => line_reader_column_kind_date,
            ColumnKind::Uuid => line_reader_column_kind_uuid,
            ColumnKind::Geohash => line_reader_column_kind_geohash,
            ColumnKind::Varchar => line_reader_column_kind_varchar,
            ColumnKind::TimestampNanos => line_reader_column_kind_timestamp_nanos,
            ColumnKind::DoubleArray => line_reader_column_kind_double_array,
            ColumnKind::LongArray => line_reader_column_kind_long_array,
            ColumnKind::Decimal64 => line_reader_column_kind_decimal64,
            ColumnKind::Decimal128 => line_reader_column_kind_decimal128,
            ColumnKind::Decimal256 => line_reader_column_kind_decimal256,
            ColumnKind::Char => line_reader_column_kind_char,
            ColumnKind::Binary => line_reader_column_kind_binary,
            ColumnKind::Long256 => line_reader_column_kind_long256,
            ColumnKind::Ipv4 => line_reader_column_kind_ipv4,
            // ColumnKind is `#[non_exhaustive]`. There's no semantic
            // fallback for an unknown wire-type code on the C side —
            // every column kind needs a paired C ABI mapping. This arm
            // is a build-time guard: it fires only on a workspace
            // version skew (a new ColumnKind variant added upstream
            // without updating the FFI translation), which is
            // impossible in same-workspace builds. Aborting is strictly
            // safer than silently mapping to a wrong-typed C variant.
            _ => {
                eprintln!(
                    "ColumnKind→C ABI: unknown variant {:?}; the FFI translation is out of sync \
                     with the upstream enum. Aborting to prevent silent type confusion in the C \
                     caller.",
                    k
                );
                std::process::abort();
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

/// Opaque QWP egress reader.
///
/// The `Reader` lives inside an `UnsafeCell` so that the lifetime-laundered
/// `&mut Reader` held by an in-flight `ReaderQuery<'static>` / `Cursor<'static>`
/// can coexist with shared reborrows synthesised by the read-only stat
/// getters (`_bytes_received`, `_credit_granted_total`, `_read_ns`,
/// `_decode_ns`, `_server_version`, `_current_server_info`,
/// `_current_addr_*`). All references to the inner `Reader` are derived
/// from `UnsafeCell::get()`, so under Stacked/Tree Borrows they receive
/// the `SharedReadWrite` tag rather than `Unique` — making the temporary
/// `&Reader` synthesised by a stat getter compatible with the laundered
/// `&mut Reader` borrow inside the query/cursor. Without the cell, those
/// two would alias the same memory and be instant aliasing UB regardless
/// of the program being single-threaded.
///
/// `active` still tracks whether a `line_reader_query` or `line_reader_cursor`
/// has taken a laundered `&mut Reader` out of the cell. While `active` is
/// true, no new query/cursor may be created against this reader — the FFI
/// rejects `_query_new` / `_execute` to prevent two laundered `&mut Reader`
/// from existing simultaneously (which would be UB even with `UnsafeCell`,
/// since the laundered borrows themselves still need to be unique
/// w.r.t. each other).
///
/// `AtomicBool` (rather than `Cell<bool>`) so that a reader migrated
/// between threads — permitted by the C contract under the user's
/// happens-before edge — sees a consistent view of the flag even on
/// weakly-ordered targets. Access uses `Acquire`/`Release` so the flag's
/// state pairs with the reader-mutating operation that flipped it.
pub struct line_reader(UnsafeCell<Reader>, AtomicBool);

/// Construct a reader from a QuestDB config string.
///
/// The config string follows the same format documented in the Rust
/// `ReaderConfig::from_conf` API (e.g. `"http::addr=localhost:9000;"`).
/// On success returns a non-NULL handle that must be released with
/// `line_reader_close`. On failure returns NULL and sets `*err_out`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_from_conf(
    config: line_sender_utf8,
    err_out: *mut *mut line_reader_error,
) -> *mut line_reader {
    // Wrap the entire body so allocator panics from `Box::into_raw`,
    // `set_reader_err`, or any future fallible step can't unwind across
    // the FFI boundary. Matches the policy used elsewhere in this file
    // (`mutate_query`, `_query_execute`, `_cursor_next_batch`, etc.).
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        // Re-validate UTF-8 (see `validated_utf8` for the rationale).
        let conf = match validated_utf8(&config) {
            Ok(s) => s,
            Err(e) => {
                *err_out = Box::into_raw(Box::new(line_reader_error(e)));
                return ptr::null_mut();
            }
        };
        let reader_result = Reader::from_conf(conf);
        let reader = reader_bubble!(err_out, reader_result, ptr::null_mut());
        Box::into_raw(Box::new(line_reader(
            UnsafeCell::new(reader),
            AtomicBool::new(false),
        )))
    }));
    match result {
        Ok(p) => p,
        Err(_) => std::process::abort(),
    }
}

/// Construct a reader from the configuration stored in the
/// `QDB_CLIENT_CONF` environment variable.
///
/// The variable's value follows the same format as
/// `line_reader_from_conf`. Returns NULL and sets `*err_out` if the
/// variable is unset, not valid UTF-8, or contains an invalid config
/// string. On success returns a non-NULL handle that must be released
/// with `line_reader_close`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_from_env(
    err_out: *mut *mut line_reader_error,
) -> *mut line_reader {
    // See `line_reader_from_conf` for the full-body `catch_unwind`
    // rationale.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        let conf = match std::env::var("QDB_CLIENT_CONF") {
            Ok(s) => s,
            Err(std::env::VarError::NotPresent) => {
                set_reader_err(
                    err_out,
                    ErrorCode::ConfigError,
                    "Environment variable QDB_CLIENT_CONF not set.",
                );
                return ptr::null_mut();
            }
            Err(std::env::VarError::NotUnicode(_)) => {
                set_reader_err(
                    err_out,
                    ErrorCode::InvalidUtf8,
                    "Environment variable QDB_CLIENT_CONF is set but its \
                     value is not valid UTF-8.",
                );
                return ptr::null_mut();
            }
        };
        let reader_result = Reader::from_conf(&conf);
        let reader = reader_bubble!(err_out, reader_result, ptr::null_mut());
        Box::into_raw(Box::new(line_reader(
            UnsafeCell::new(reader),
            AtomicBool::new(false),
        )))
    }));
    match result {
        Ok(p) => p,
        Err(_) => std::process::abort(),
    }
}

/// Close the reader and release all associated resources. Idempotent on NULL.
///
/// Any `line_reader_query` or `line_reader_cursor` obtained from this reader
/// MUST be freed/closed first. Closing the reader while a query or cursor is
/// still live would otherwise be undefined behaviour — the cursor's internal
/// `&mut Reader` (lifetime-laundered to `'static` via `transmute`) becomes a
/// dangling reference and any subsequent operation on it is use-after-free.
///
/// As defense-in-depth against this misuse, the library checks the `active`
/// flag and, if a query/cursor is still outstanding, prints a diagnostic to
/// `stderr` and **leaks the reader** rather than freeing it. Leaking is
/// strictly better than a use-after-free: the leaked storage is finite (one
/// reader) and the live cursor remains valid, while a free here would let
/// the next allocation alias the cursor's `&mut Reader` and produce silent
/// memory corruption.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_close(reader: *mut line_reader) {
    panic_guard(|| unsafe {
        if reader.is_null() {
            return;
        }
        // Compare-and-swap rather than `load`+`free`. The C contract
        // forbids racing `_close` against `_query_new` on the same reader,
        // but `_query_new` already uses CAS as defense-in-depth, so a bare
        // `load` here would leave a window between the read and the free
        // during which a misbehaving caller's concurrent `_query_new`
        // could flip `active` from false to true and end up holding a
        // freed `&mut Reader`. Atomically claim the flag instead: on
        // success no query/cursor exists nor can be created, so the free
        // is sound; on failure (active already true, or another thread
        // racing) we leak — matching the existing leak-on-active policy
        // documented above.
        if (*reader)
            .1
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            // A query or cursor is still live (or a concurrent _query_new
            // raced us); freeing the reader would leave a dangling
            // `&mut Reader` inside it. Leak the reader (and its socket)
            // rather than risk use-after-free.
            eprintln!(
                "line_reader_close: a query or cursor is still live on this \
                 reader. The reader has been LEAKED to avoid use-after-free; \
                 close the cursor / free the query before closing the reader. \
                 This is a contract violation — see the line_reader_close \
                 docstring."
            );
            return;
        }
        // The drop chain runs Reader → Option<WsTransport> → Drop. Wrapped
        // in `panic_guard` because a panic from any allocator/transport
        // Drop would otherwise unwind across the FFI boundary.
        drop(Box::from_raw(reader));
    })
}

/// Cumulative bytes successfully read from the wire across the reader's
/// lifetime (header + payload, before decoding). Returns `0` for a NULL
/// handle (defense-in-depth — passing NULL is a contract violation).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_bytes_received(reader: *const line_reader) -> u64 {
    unsafe {
        if reader.is_null() {
            return 0;
        }
        (*(*reader).0.get()).bytes_received()
    }
}

/// Cumulative bytes of CREDIT this reader has granted the server across
/// every cursor on this connection. Returns `0` for a NULL handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_credit_granted_total(reader: *const line_reader) -> u64 {
    unsafe {
        if reader.is_null() {
            return 0;
        }
        (*(*reader).0.get()).credit_granted_total()
    }
}

/// Cumulative wall-clock nanoseconds spent in `read` calls. Saturates at
/// `u64::MAX` (~584 years). Returns `0` for a NULL handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_read_ns(reader: *const line_reader) -> u64 {
    unsafe {
        if reader.is_null() {
            return 0;
        }
        (*(*reader).0.get()).read_ns()
    }
}

/// Cumulative wall-clock nanoseconds spent decoding frames. Saturates at
/// `u64::MAX`. Returns `0` for a NULL handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_decode_ns(reader: *const line_reader) -> u64 {
    unsafe {
        if reader.is_null() {
            return 0;
        }
        (*(*reader).0.get()).decode_ns()
    }
}

/// Reset the cumulative `read_ns` / `decode_ns` counters to zero. No-op
/// for a NULL handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_reset_timing(reader: *mut line_reader) {
    unsafe {
        if reader.is_null() {
            return;
        }
        (*(*reader).0.get()).reset_timing()
    }
}

/// Get the negotiated QWP server version (1..=`HIGHEST_KNOWN_VERSION`).
/// Returns false and sets `*err_out` if the connection is not established
/// (no `SERVER_INFO` received yet). Returns `false` for a NULL handle
/// (defense-in-depth — passing NULL is a contract violation).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_server_version(
    reader: *const line_reader,
    out_version: *mut u8,
    err_out: *mut *mut line_reader_error,
) -> bool {
    unsafe {
        if reader.is_null() {
            return false;
        }
        match (*(*reader).0.get()).server_version() {
            Ok(v) => {
                *out_version = v;
                true
            }
            Err(e) => {
                *err_out = Box::into_raw(Box::new(line_reader_error(e)));
                false
            }
        }
    }
}

/// Borrowed `SERVER_INFO` of the currently connected endpoint, or NULL when
/// the server hasn't sent one (v1 protocol). The returned pointer is
/// invalidated by any subsequent reader operation that may reconnect or
/// receive a new `SERVER_INFO` (`line_reader_query_execute`,
/// `line_reader_cursor_next_batch`, `line_reader_close`). Returns NULL for
/// a NULL handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_current_server_info(
    reader: *const line_reader,
) -> *const line_reader_server_info {
    unsafe {
        if reader.is_null() {
            return ptr::null();
        }
        match (*(*reader).0.get()).server_info() {
            Some(si) => si as *const ServerInfo as *const line_reader_server_info,
            None => ptr::null(),
        }
    }
}

/// Host of the endpoint the reader is currently connected to. The buffer
/// is borrowed; valid until any reader operation that may reconnect. For a
/// NULL handle, writes an empty `(NULL, 0)` pair.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_current_addr_host(
    reader: *const line_reader,
    out_buf: *mut *const c_char,
    out_len: *mut size_t,
) {
    unsafe {
        if reader.is_null() {
            *out_buf = ptr::null();
            *out_len = 0;
            return;
        }
        let ep = (*(*reader).0.get()).current_addr();
        *out_buf = ep.host.as_ptr() as *const c_char;
        *out_len = ep.host.len();
    }
}

/// Port of the endpoint the reader is currently connected to. Returns `0`
/// for a NULL handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_current_addr_port(reader: *const line_reader) -> u16 {
    unsafe {
        if reader.is_null() {
            return 0;
        }
        (*(*reader).0.get()).current_addr().port
    }
}

#[inline]
fn u128_to_u64_sat(v: u128) -> u64 {
    if v > u64::MAX as u128 {
        u64::MAX
    } else {
        v as u64
    }
}

// ---------------------------------------------------------------------------
// ServerInfo
// ---------------------------------------------------------------------------

/// Opaque borrowed handle to a `SERVER_INFO` body. Returned by
/// `line_reader_server_info` and `line_reader_failover_event_server_info`.
#[repr(C)]
pub struct line_reader_server_info {
    _private: [u8; 0],
}

/// Cluster role advertised by `SERVER_INFO`. Mirrors `egress::ServerRole`,
/// preserving the raw byte for unknown future variants via the `_other`
/// arm — call `line_reader_server_info_role_byte` to recover it.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub enum line_reader_server_role {
    line_reader_server_role_standalone = 0,
    line_reader_server_role_primary = 1,
    line_reader_server_role_replica = 2,
    line_reader_server_role_primary_catchup = 3,
    /// Forward-compat: a server role this client doesn't recognise. The
    /// raw byte is available via `line_reader_server_info_role_byte`.
    line_reader_server_role_other = 0xFF,
}

/// NULL-safe borrow of the opaque `ServerInfo`. Returns `None` when the
/// caller passes a NULL pointer; the per-accessor NULL handling below
/// then substitutes a documented sentinel rather than dereferencing.
unsafe fn server_info_ref<'a>(si: *const line_reader_server_info) -> Option<&'a ServerInfo> {
    if si.is_null() {
        None
    } else {
        Some(unsafe { &*(si as *const ServerInfo) })
    }
}

/// Cluster role advertised by the SERVER_INFO. NULL-safe: returns
/// `line_reader_server_role_other` when `si` is NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_server_info_role(
    si: *const line_reader_server_info,
) -> line_reader_server_role {
    use line_reader_server_role::*;
    unsafe {
        let si = match server_info_ref(si) {
            Some(s) => s,
            None => return line_reader_server_role_other,
        };
        match si.role {
            ServerRole::Standalone => line_reader_server_role_standalone,
            ServerRole::Primary => line_reader_server_role_primary,
            ServerRole::Replica => line_reader_server_role_replica,
            ServerRole::PrimaryCatchup => line_reader_server_role_primary_catchup,
            ServerRole::Other(_) => line_reader_server_role_other,
            // ServerRole is `#[non_exhaustive]`; future named variants
            // not yet wired through to the C ABI surface as `_other`
            // (matching the existing `Other(u8)` semantics).
            _ => line_reader_server_role_other,
        }
    }
}

/// Raw role byte from the wire (useful when `role()` returns `OTHER`).
/// NULL-safe: returns `0xFF` when `si` is NULL (the same sentinel as
/// `ServerRole::Other(0xFF)`'s discriminant).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_server_info_role_byte(
    si: *const line_reader_server_info,
) -> u8 {
    unsafe {
        let si = match server_info_ref(si) {
            Some(s) => s,
            None => return 0xFF,
        };
        match si.role {
            ServerRole::Standalone => 0,
            ServerRole::Primary => 1,
            ServerRole::Replica => 2,
            ServerRole::PrimaryCatchup => 3,
            ServerRole::Other(b) => b,
            // `#[non_exhaustive]` fallback: 0xFF matches the
            // `Other(0xFF)` sentinel used elsewhere for unknown roles.
            _ => 0xFF,
        }
    }
}

/// NULL-safe: returns 0 when `si` is NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_server_info_epoch(si: *const line_reader_server_info) -> u64 {
    unsafe { server_info_ref(si).map(|s| s.epoch).unwrap_or(0) }
}

/// NULL-safe: returns 0 when `si` is NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_server_info_capabilities(
    si: *const line_reader_server_info,
) -> u32 {
    unsafe { server_info_ref(si).map(|s| s.capabilities).unwrap_or(0) }
}

/// NULL-safe: returns 0 when `si` is NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_server_info_server_wall_ns(
    si: *const line_reader_server_info,
) -> i64 {
    unsafe { server_info_ref(si).map(|s| s.server_wall_ns).unwrap_or(0) }
}

/// NULL-safe: writes `*out_buf = NULL` and `*out_len = 0` when `si` is
/// NULL. The `out_*` pointers themselves must be non-NULL — see the
/// per-header NULL-precondition contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_server_info_cluster_id(
    si: *const line_reader_server_info,
    out_buf: *mut *const c_char,
    out_len: *mut size_t,
) {
    unsafe {
        match server_info_ref(si) {
            Some(s) => {
                let cid = s.cluster_id.as_str();
                *out_buf = cid.as_ptr() as *const c_char;
                *out_len = cid.len();
            }
            None => {
                *out_buf = ptr::null();
                *out_len = 0;
            }
        }
    }
}

/// NULL-safe: see `line_reader_server_info_cluster_id`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_server_info_node_id(
    si: *const line_reader_server_info,
    out_buf: *mut *const c_char,
    out_len: *mut size_t,
) {
    unsafe {
        match server_info_ref(si) {
            Some(s) => {
                let nid = s.node_id.as_str();
                *out_buf = nid.as_ptr() as *const c_char;
                *out_len = nid.len();
            }
            None => {
                *out_buf = ptr::null();
                *out_len = 0;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// FailoverEvent + on_failover_reset callback
// ---------------------------------------------------------------------------

/// Opaque borrowed handle to a failover event. The pointer is valid only
/// for the duration of the user's failover callback invocation.
#[repr(C)]
pub struct line_reader_failover_event {
    _private: [u8; 0],
}

/// User callback fired after each successful mid-query failover. The
/// `event` pointer is valid only for the duration of the call.
pub type line_reader_failover_callback =
    Option<unsafe extern "C" fn(event: *const line_reader_failover_event, user_data: *mut c_void)>;

/// NULL-safe borrow of the opaque `FailoverEvent`. Returns `None` when
/// the caller passes a NULL pointer.
unsafe fn ev_ref<'a>(ev: *const line_reader_failover_event) -> Option<&'a FailoverEvent> {
    if ev.is_null() {
        None
    } else {
        Some(unsafe { &*(ev as *const FailoverEvent) })
    }
}

/// NULL-safe: writes empty `(NULL, 0)` when `ev` is NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_failover_event_failed_host(
    ev: *const line_reader_failover_event,
    out_buf: *mut *const c_char,
    out_len: *mut size_t,
) {
    unsafe {
        match ev_ref(ev) {
            Some(e) => {
                let h = e.failed_addr.host.as_str();
                *out_buf = h.as_ptr() as *const c_char;
                *out_len = h.len();
            }
            None => {
                *out_buf = ptr::null();
                *out_len = 0;
            }
        }
    }
}

/// NULL-safe: returns 0 when `ev` is NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_failover_event_failed_port(
    ev: *const line_reader_failover_event,
) -> u16 {
    unsafe { ev_ref(ev).map(|e| e.failed_addr.port).unwrap_or(0) }
}

/// NULL-safe: writes empty `(NULL, 0)` when `ev` is NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_failover_event_new_host(
    ev: *const line_reader_failover_event,
    out_buf: *mut *const c_char,
    out_len: *mut size_t,
) {
    unsafe {
        match ev_ref(ev) {
            Some(e) => {
                let h = e.new_addr.host.as_str();
                *out_buf = h.as_ptr() as *const c_char;
                *out_len = h.len();
            }
            None => {
                *out_buf = ptr::null();
                *out_len = 0;
            }
        }
    }
}

/// NULL-safe: returns 0 when `ev` is NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_failover_event_new_port(
    ev: *const line_reader_failover_event,
) -> u16 {
    unsafe { ev_ref(ev).map(|e| e.new_addr.port).unwrap_or(0) }
}

/// NULL-safe: returns 0 when `ev` is NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_failover_event_new_request_id(
    ev: *const line_reader_failover_event,
) -> i64 {
    unsafe { ev_ref(ev).map(|e| e.new_request_id).unwrap_or(0) }
}

/// NULL-safe: returns 0 when `ev` is NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_failover_event_attempts(
    ev: *const line_reader_failover_event,
) -> u32 {
    unsafe { ev_ref(ev).map(|e| e.attempts).unwrap_or(0) }
}

/// Wall-clock nanoseconds spent reconnecting (sleep + dial + handshake +
/// `SERVER_INFO` read). Saturates at `u64::MAX`. NULL-safe: returns 0
/// when `ev` is NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_failover_event_elapsed_ns(
    ev: *const line_reader_failover_event,
) -> u64 {
    unsafe {
        ev_ref(ev)
            .map(|e| u128_to_u64_sat(e.elapsed.as_nanos()))
            .unwrap_or(0)
    }
}

/// Error code that triggered the failover (the cause-of-death of the
/// previous connection). NULL-safe: returns
/// `line_reader_error_invalid_api_call` when `ev` is NULL (the same
/// sentinel as `line_reader_error_get_code(NULL)`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_failover_event_trigger_code(
    ev: *const line_reader_failover_event,
) -> line_reader_error_code {
    unsafe {
        match ev_ref(ev) {
            Some(e) => e.trigger.code().into(),
            None => line_reader_error_code::line_reader_error_invalid_api_call,
        }
    }
}

/// Trigger error message (UTF-8). Borrowed for the duration of the call.
/// NULL-safe: writes empty `(NULL, 0)` when `ev` is NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_failover_event_trigger_msg(
    ev: *const line_reader_failover_event,
    out_buf: *mut *const c_char,
    out_len: *mut size_t,
) {
    unsafe {
        match ev_ref(ev) {
            Some(e) => {
                let m = e.trigger.msg();
                *out_buf = m.as_ptr() as *const c_char;
                *out_len = m.len();
            }
            None => {
                *out_buf = ptr::null();
                *out_len = 0;
            }
        }
    }
}

/// `SERVER_INFO` for the new endpoint, or NULL for v1 servers. Borrowed
/// for the duration of the call. NULL-safe: returns NULL when `ev` is
/// NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_failover_event_server_info(
    ev: *const line_reader_failover_event,
) -> *const line_reader_server_info {
    unsafe {
        match ev_ref(ev).and_then(|e| e.new_server_info.as_ref()) {
            Some(si) => si as *const ServerInfo as *const line_reader_server_info,
            None => ptr::null(),
        }
    }
}

/// Install a failover-reset callback on the query. Replaces any previously
/// installed callback. `user_data` is opaque to the library; pass NULL if
/// not needed.
///
/// The callback is invoked just before any replayed `RESULT_BATCH` arrives
/// on a new connection. The `event` pointer passed to the callback is
/// valid only for the duration of that call.
///
/// Reentrancy contract — see the corresponding C header docs on
/// `line_reader_failover_callback`. In short: the trampoline runs
/// synchronously inside the in-flight cursor op, so the user callback
/// MUST NOT touch the originating reader, query, or cursor (including
/// read-only stat getters — they would alias the upstream `&mut Reader`
/// borrow), and MUST NOT throw / longjmp / unwind across the C boundary.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_query_on_failover_reset(
    query: *mut line_reader_query,
    callback: line_reader_failover_callback,
    user_data: *mut c_void,
) {
    unsafe {
        // Wrap the C function pointer + user_data in a Rust closure that
        // matches the `FnMut(&FailoverEvent) + 'r` signature `ReaderQuery`
        // expects. The trait bound has no `Send` requirement; the cursor
        // is single-threaded and the trampoline runs on the same thread
        // that drives `next_batch`. The C caller owns `user_data` and is
        // responsible for its lifetime — see the header docs.
        let trampoline = move |event: &FailoverEvent| {
            if let Some(c_cb) = callback {
                let opaque = event as *const FailoverEvent as *const line_reader_failover_event;
                // The user callback is C code; it cannot itself panic, but it
                // may re-enter Rust (e.g. by calling a stat getter — itself a
                // contract violation but still possible) and that re-entrant
                // path may panic. An unwind through this `extern "C"` frame
                // would be UB, so catch and abort. C++ users get the same
                // protection from the wrapper's noexcept trampoline.
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    c_cb(opaque, user_data)
                }));
                if result.is_err() {
                    std::process::abort();
                }
            }
        };
        mutate_query(query, |q| q.on_failover_reset(trampoline));
    }
}

// ---------------------------------------------------------------------------
// Query builder (binds)
// ---------------------------------------------------------------------------

/// Opaque query-builder handle. Holds an in-progress `ReaderQuery` that the
/// caller can append bind parameters to before consuming it via
/// `line_reader_query_execute`. The originating `line_reader` MUST outlive
/// the query.
pub struct line_reader_query {
    /// Lifetime extended to `'static`; bounded by the reader's lifetime.
    /// `ManuallyDrop` lets us move the inner `ReaderQuery` out via
    /// `ptr::read` / `ptr::write` for each builder mutation, and lets
    /// `_execute` consume it without double-dropping.
    inner: ManuallyDrop<ReaderQuery<'static>>,
    /// Backpointer to the originating reader, used to clear its `active`
    /// flag on `_query_free` or `_query_execute` failure. Always non-NULL
    /// for a valid query (the C contract requires the reader to outlive
    /// the query).
    reader: *mut line_reader,
    /// First fatal error detected by an FFI-level bind/builder method
    /// that has no `err_out` slot of its own (currently only
    /// `_bind_varchar`'s UTF-8 re-validation). `_query_execute` checks
    /// this before delegating to upstream `ReaderQuery::execute` and
    /// surfaces the stored error if set, mirroring the deferred-error
    /// pattern upstream uses internally.
    deferred_err: Option<Error>,
}

/// Begin a new query against `reader` for the given SQL.
///
/// Returns NULL and sets `*err_out` if a query or cursor against this
/// reader is already in flight (only one may be live per reader at a time).
/// On success the returned handle must be either consumed by
/// `line_reader_query_execute` (which produces a cursor) or released with
/// `line_reader_query_free`. The reader MUST outlive the query/cursor.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_query_new(
    reader: *mut line_reader,
    sql: line_sender_utf8,
    err_out: *mut *mut line_reader_error,
) -> *mut line_reader_query {
    unsafe {
        // NULL handle is a contract violation, but report it as a clean
        // `InvalidApiCall` rather than SIGSEGV on the CAS deref below.
        // Matches the defensive NULL-tolerance the reader stat getters
        // (`_bytes_received`, `_credit_granted_total`, `_read_ns`,
        // `_decode_ns`, `_reset_timing`, `_close`) already implement.
        if reader.is_null() {
            set_reader_err(
                err_out,
                ErrorCode::InvalidApiCall,
                "line_reader_query_new: NULL reader handle",
            );
            return ptr::null_mut();
        }
        // Compare-and-swap the active flag. The C contract forbids
        // concurrent calls on the same reader, so this is documented
        // user-side UB if it ever races — but a CAS at least gives a
        // deterministic `InvalidApiCall` to the loser of a race rather
        // than silently producing two `&mut Reader` borrows. A bare
        // `load`+`store` pair would let two threads both pass the
        // check.
        //
        // Success ordering is `AcqRel` (matching `_close`'s CAS at line
        // 458): we both `Acquire` any prior writes that the previous
        // owner-thread released via `_query_free` / `_cursor_free`, and
        // `Release` so that the imminent mutations through the
        // laundered `&mut Reader` are properly published to whichever
        // thread next observes `active=false`. `Acquire`-only on the
        // success arm would skip the `Release` half of that handover.
        if (*reader)
            .1
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            set_reader_err(
                err_out,
                ErrorCode::InvalidApiCall,
                "another query or cursor is already in flight on this reader \
                 (only one at a time)",
            );
            return ptr::null_mut();
        }
        // Defensive UTF-8 re-validation. `line_sender_utf8::as_str` uses
        // `from_utf8_unchecked`, trusting that the caller built the
        // struct via `line_sender_utf8_init` (which validates). A C
        // caller that hand-rolls the struct with invalid bytes would
        // otherwise create an invalid `&str`, which is instant UB the
        // moment upstream walks it. Validate here so the error surfaces
        // cleanly via `err_out` instead.
        let sql_str = match validated_utf8(&sql) {
            Ok(s) => s,
            Err(e) => {
                // Release the active flag we just claimed: no query was
                // produced, so the reader must be available again.
                (*reader).1.store(false, Ordering::Release);
                *err_out = Box::into_raw(Box::new(line_reader_error(e)));
                return ptr::null_mut();
            }
        };
        // Derive `&mut Reader` through the `UnsafeCell::get()` raw pointer
        // (rather than `&mut (*reader).0`, which would give the borrow a
        // `Unique` tag under Stacked/Tree Borrows and conflict with the
        // shared reborrows synthesised by the read-only stat getters).
        // Going through the cell's raw pointer tags this borrow as
        // `SharedReadWrite`, compatible with those temporary `&Reader`s.
        let r: &mut Reader = &mut *(*reader).0.get();
        // Defense-in-depth: catch any unwind out of `r.query(sql_str)` and
        // abort, mirroring the policy in `_query_execute` and
        // `mutate_query`. Upstream `Reader::query` is in practice
        // infallible (it just builds a small `ReaderQuery` struct), but a
        // future change or a custom allocator that unwinds on OOM would
        // otherwise (a) propagate a Rust panic across the FFI boundary
        // into C — instant UB — and (b) leave the `active` flag stuck
        // `true` (no query was produced, but the early-claim of the flag
        // wouldn't be undone). Aborting is strictly safer.
        //
        // The lifetime launder happens INSIDE the closure: a `FnMut`
        // closure cannot return a borrow of a variable it captured, so
        // returning `ReaderQuery<'a>` (which borrows `r`) is rejected by
        // the borrow checker. Transmuting to `ReaderQuery<'static>` first
        // detaches the borrow, satisfying the closure's
        // no-references-to-captures rule. SAFETY: the launder is sound
        // because the C caller's contract requires the reader to outlive
        // the query handle and any cursor it produces, and the `active`
        // flag prevents a second laundered borrow from being taken while
        // this one is alive.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let q = r.query(sql_str);
            let q_static: ReaderQuery<'static> = std::mem::transmute(q);
            q_static
        }));
        let q_static = match result {
            Ok(q) => q,
            Err(_) => std::process::abort(),
        };
        Box::into_raw(Box::new(line_reader_query {
            inner: ManuallyDrop::new(q_static),
            reader,
            deferred_err: None,
        }))
    }
}

/// Free a query without executing it. Idempotent on NULL. Use this only on
/// the error path; `line_reader_query_execute` consumes the query and frees
/// the handle on success AND failure (do not call `_query_free` after
/// `_query_execute`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_query_free(query: *mut line_reader_query) {
    panic_guard(|| unsafe {
        if query.is_null() {
            return;
        }
        let mut boxed = Box::from_raw(query);
        ManuallyDrop::drop(&mut boxed.inner);
        // Release the reader's active flag so a new query/cursor can be
        // started.
        if !boxed.reader.is_null() {
            (*boxed.reader).1.store(false, Ordering::Release);
        }
        drop(boxed);
    })
}

/// Consume the query and return a streaming cursor.
///
/// `query_inout` is a pointer to the caller's `line_reader_query*`
/// variable. On entry, `*query_inout` is the query to consume; on exit,
/// `*query_inout` is set to NULL — regardless of success or failure — so
/// a subsequent `line_reader_query_free(*query_inout)` is a safe no-op
/// (the query handle is consumed by this call). Passing NULL for
/// `query_inout` itself, or for `*query_inout`, is a contract violation;
/// the function returns NULL with `InvalidApiCall` set.
///
/// On success, ownership of the query transfers to the returned cursor;
/// on failure `*err_out` is set and NULL is returned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_query_execute(
    query_inout: *mut *mut line_reader_query,
    err_out: *mut *mut line_reader_error,
) -> *mut line_reader_cursor {
    unsafe {
        // Defense-in-depth: `Box::from_raw(null)` is officially UB —
        // strictly worse than a SIGSEGV. Reject NULL early instead.
        if query_inout.is_null() {
            set_reader_err(
                err_out,
                ErrorCode::InvalidApiCall,
                "line_reader_query_execute called with NULL query_inout",
            );
            return ptr::null_mut();
        }
        let query = *query_inout;
        if query.is_null() {
            set_reader_err(
                err_out,
                ErrorCode::InvalidApiCall,
                "line_reader_query_execute called with NULL *query_inout",
            );
            return ptr::null_mut();
        }
        // Null the caller's local now: the query is consumed regardless of
        // outcome. A subsequent `line_reader_query_free(*query_inout)` is
        // then a NULL no-op.
        *query_inout = ptr::null_mut();
        let mut boxed = Box::from_raw(query);
        let q: ReaderQuery<'static> = ManuallyDrop::take(&mut boxed.inner);
        let reader = boxed.reader;
        // boxed is dropped at end of scope; ManuallyDrop's no-op drop is fine
        // since we already moved the inner out via `take`.

        // Surface deferred errors stashed by void-returning bind helpers
        // (see `line_reader_query_bind_varchar`). `q` is consumed and
        // dropped along with `boxed`; the active flag is released so a
        // new query can start.
        if let Some(e) = boxed.deferred_err.take() {
            drop(q);
            if !reader.is_null() {
                (*reader).1.store(false, Ordering::Release);
            }
            *err_out = Box::into_raw(Box::new(line_reader_error(e)));
            return ptr::null_mut();
        }

        // Defense-in-depth: catch any unwind out of `q.execute()` and
        // abort, mirroring the policy in `mutate_query`. `q` was moved
        // out of the now-dead `Box<line_reader_query>` via
        // `ManuallyDrop::take`, so an unwind would otherwise (a) leave
        // the reader's `active` flag stuck `true` (no cursor produced,
        // no Err arm taken to clear it) and (b) propagate a Rust panic
        // across the FFI boundary into C — instant UB. Aborting is
        // strictly safer.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| q.execute()));
        let result = match result {
            Ok(r) => r,
            Err(_) => std::process::abort(),
        };
        match result {
            Ok(cursor) => {
                // Active flag stays set; ownership transfers to the cursor.
                let cursor_static: Cursor<'static> = std::mem::transmute(cursor);
                Box::into_raw(Box::new(line_reader_cursor {
                    cursor: ManuallyDrop::new(cursor_static),
                    current_batch: None,
                    reader,
                }))
            }
            Err(e) => {
                // Query gone, no cursor produced — release the active flag.
                if !reader.is_null() {
                    (*reader).1.store(false, Ordering::Release);
                }
                *err_out = Box::into_raw(Box::new(line_reader_error(e)));
                ptr::null_mut()
            }
        }
    }
}

/// Apply a builder method to the in-place `ReaderQuery`.
///
/// Skips the upstream call entirely if a previous void-return bind has
/// stashed a `deferred_err` on the query. This keeps subsequent bind
/// indices stable: once a bind has failed, the upstream builder is
/// frozen, no further binds are pushed, and `_query_execute` surfaces the
/// stored error before invoking upstream `execute()`. Without this
/// short-circuit, a single failed `_bind_varchar` (UTF-8 reject) would
/// shift every later bind position by one and produce confusing
/// downstream errors.
///
/// `f` is in practice infallible — the upstream `ReaderQuery::bind_*`
/// methods just push into a `Vec`, and allocation failure under the default
/// allocator aborts rather than unwinds. The `catch_unwind` here is
/// defense-in-depth: between `ptr::read(inner_ptr)` and `ptr::write` the
/// slot is logically uninitialised, so an unwind-style panic from a future
/// upstream change (or a custom allocator that unwinds on OOM) would
/// otherwise leak the stale value into `_query_free`'s drop. Aborting on
/// unwind is stricter than the line_sender FFI's default behaviour, but
/// the surface area here (lifetime-laundered `ReaderQuery<'static>`) makes
/// it the safer choice.
unsafe fn mutate_query<F>(query: *mut line_reader_query, f: F)
where
    F: FnOnce(ReaderQuery<'static>) -> ReaderQuery<'static>,
{
    unsafe {
        // NULL handle is a contract violation; defer to the shared
        // `null_check_handle!` policy.
        null_check_handle!(query, "line_reader_query_bind_*");
        if (*query).deferred_err.is_some() {
            return;
        }
        let inner_ptr: *mut ReaderQuery<'static> = &mut *(*query).inner;
        let q = ptr::read(inner_ptr);
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || f(q))) {
            Ok(new_q) => ptr::write(inner_ptr, new_q),
            Err(_) => std::process::abort(),
        }
    }
}

macro_rules! ffi_bind_method {
    ($c_name:ident, $rust_method:ident, $($arg:ident : $ty:ty),*) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $c_name(
            query: *mut line_reader_query,
            $($arg : $ty),*
        ) {
            unsafe { mutate_query(query, |q| q.$rust_method($($arg),*)) }
        }
    };
}

ffi_bind_method!(line_reader_query_bind_bool, bind_bool, v: bool);
ffi_bind_method!(line_reader_query_bind_i8, bind_i8, v: i8);
ffi_bind_method!(line_reader_query_bind_i16, bind_i16, v: i16);
ffi_bind_method!(line_reader_query_bind_i32, bind_i32, v: i32);
ffi_bind_method!(line_reader_query_bind_i64, bind_i64, v: i64);
ffi_bind_method!(line_reader_query_bind_f32, bind_f32, v: f32);
ffi_bind_method!(line_reader_query_bind_f64, bind_f64, v: f64);
ffi_bind_method!(line_reader_query_bind_timestamp_micros, bind_timestamp_micros, v: i64);
ffi_bind_method!(line_reader_query_bind_timestamp_nanos, bind_timestamp_nanos, v: i64);
ffi_bind_method!(line_reader_query_bind_date_millis, bind_date_millis, v: i64);
ffi_bind_method!(line_reader_query_bind_char, bind_char, v: u16);
ffi_bind_method!(line_reader_query_bind_decimal64, bind_decimal64, v: i64, scale: i8);
ffi_bind_method!(line_reader_query_bind_geohash, bind_geohash, v: u64, precision_bits: u8);
ffi_bind_method!(line_reader_query_bind_null_varchar, bind_null_varchar,);
ffi_bind_method!(line_reader_query_bind_null_binary, bind_null_binary,);
ffi_bind_method!(line_reader_query_bind_null_decimal64, bind_null_decimal64, scale: i8);
ffi_bind_method!(line_reader_query_bind_null_decimal128, bind_null_decimal128, scale: i8);
ffi_bind_method!(line_reader_query_bind_null_decimal256, bind_null_decimal256, scale: i8);
ffi_bind_method!(line_reader_query_bind_null_geohash, bind_null_geohash, precision_bits: u8);

/// Bind a UTF-8 VARCHAR value. The bytes are copied; no lifetime requirement.
///
/// The payload is re-validated as UTF-8 on entry. A caller that hand-rolled
/// a `line_sender_utf8` with invalid bytes (bypassing `line_sender_utf8_init`)
/// has the error stored on the query and surfaced from
/// `line_reader_query_execute` with `line_reader_error_invalid_utf8`. This
/// function returns void, so deferred surfacing is the only way to report
/// the error without aborting.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_query_bind_varchar(
    query: *mut line_reader_query,
    v: line_sender_utf8,
) {
    unsafe {
        // NULL handle is a contract violation. Match `mutate_query`'s
        // policy so the success and failure branches behave identically
        // — otherwise a NULL handle paired with malformed UTF-8 would
        // SIGSEGV on the deferred-error deref below instead of aborting
        // cleanly.
        if query.is_null() {
            eprintln!(
                "line_reader_query_bind_varchar: NULL query handle. \
                 This is a contract violation; aborting."
            );
            std::process::abort();
        }
        match validated_utf8(&v) {
            Ok(s) => {
                let owned = s.to_owned();
                mutate_query(query, |q| q.bind_varchar(owned));
            }
            Err(e) => {
                // Don't touch the upstream builder — a partially-applied
                // bind would shift every later bind index. Stash the
                // error so `_query_execute` surfaces it. First-error-
                // wins so the original cause isn't masked.
                if (*query).deferred_err.is_none() {
                    (*query).deferred_err = Some(e);
                }
            }
        }
    }
}

/// Bind a BINARY value. The bytes are copied. `buf` may be NULL only when
/// `len` is 0 (empty value). A NULL `buf` with non-zero `len` aborts the
/// process — the same policy as `line_reader_query_bind_uuid`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_query_bind_binary(
    query: *mut line_reader_query,
    buf: *const u8,
    len: size_t,
) {
    if buf.is_null() && len != 0 {
        eprintln!(
            "line_reader_query_bind_binary: `buf` is NULL but `len` is {} — \
             pass a non-NULL buffer or set `len` to 0. Aborting to avoid \
             undefined behaviour from `slice::from_raw_parts(NULL, len)`.",
            len
        );
        std::process::abort();
    }
    unsafe {
        let bytes: Vec<u8> = if len == 0 {
            Vec::new()
        } else {
            slice::from_raw_parts(buf, len).to_vec()
        };
        mutate_query(query, |q| q.bind_binary(bytes));
    }
}

/// Bind a 16-byte UUID value (raw bytes). `value` MUST be non-NULL and point
/// to at least 16 readable bytes. A NULL `value` aborts the process via
/// `process::abort()` to surface the bug instead of silently substituting
/// zero bytes (which would produce a valid-looking `00000000-0000-0000-
/// 0000-000000000000` UUID and corrupt the query). Use
/// `line_reader_query_bind_null` with `line_reader_column_kind_uuid` to bind
/// SQL NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_query_bind_uuid(
    query: *mut line_reader_query,
    value: *const u8,
) {
    if value.is_null() {
        eprintln!(
            "line_reader_query_bind_uuid: `value` is NULL — \
             pass a non-NULL 16-byte buffer or use \
             line_reader_query_bind_null(query, line_reader_column_kind_uuid). \
             Aborting to avoid silently binding all-zero bytes."
        );
        std::process::abort();
    }
    unsafe {
        let mut buf = [0u8; 16];
        buf.copy_from_slice(slice::from_raw_parts(value, 16));
        mutate_query(query, |q| q.bind_uuid_bytes(buf));
    }
}

/// Bind a 32-byte LONG256 value (raw little-endian bytes). `value` MUST be
/// non-NULL and point to at least 32 readable bytes. A NULL `value` aborts
/// the process — see `line_reader_query_bind_uuid` for the rationale. Use
/// `line_reader_query_bind_null` with `line_reader_column_kind_long256` to
/// bind SQL NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_query_bind_long256(
    query: *mut line_reader_query,
    value: *const u8,
) {
    if value.is_null() {
        eprintln!(
            "line_reader_query_bind_long256: `value` is NULL — \
             pass a non-NULL 32-byte buffer or use \
             line_reader_query_bind_null(query, line_reader_column_kind_long256). \
             Aborting to avoid silently binding all-zero bytes."
        );
        std::process::abort();
    }
    unsafe {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(slice::from_raw_parts(value, 32));
        mutate_query(query, |q| q.bind_long256(buf));
    }
}

/// Bind an IPv4 address as a host-order `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_query_bind_ipv4(
    query: *mut line_reader_query,
    host_order: u32,
) {
    unsafe {
        mutate_query(query, |q| q.bind_ipv4(Ipv4Addr::from(host_order)));
    }
}

/// Bind a DECIMAL128 value as two i64 limbs (low/high) for the i128 mantissa.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_query_bind_decimal128(
    query: *mut line_reader_query,
    value_low: u64,
    value_high: i64,
    scale: i8,
) {
    unsafe {
        let lo = value_low as u128;
        let hi = (value_high as i128) as u128;
        let combined = (hi << 64) | lo;
        let value = combined as i128;
        mutate_query(query, |q| q.bind_decimal128(value, scale));
    }
}

/// Bind a DECIMAL256 value as 32 little-endian raw bytes plus column scale.
/// `value` MUST be non-NULL and point to at least 32 readable bytes. A NULL
/// `value` aborts the process — see `line_reader_query_bind_uuid` for the
/// rationale. Use `line_reader_query_bind_null_decimal256` to bind SQL NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_query_bind_decimal256(
    query: *mut line_reader_query,
    value: *const u8,
    scale: i8,
) {
    if value.is_null() {
        eprintln!(
            "line_reader_query_bind_decimal256: `value` is NULL — \
             pass a non-NULL 32-byte buffer or use \
             line_reader_query_bind_null_decimal256(query, scale). \
             Aborting to avoid silently binding all-zero bytes."
        );
        std::process::abort();
    }
    unsafe {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(slice::from_raw_parts(value, 32));
        mutate_query(query, |q| q.bind_decimal256(buf, scale));
    }
}

/// Bind a typed NULL for one of the simple column kinds (numeric, temporal,
/// UUID, IPv4, LONG256, CHAR). For VARCHAR / BINARY / DECIMAL\* / GEOHASH
/// use the dedicated `_null_*` variants since those carry extra column
/// metadata. Passing a kind not in the simple-null set (e.g. SYMBOL,
/// VARCHAR, DECIMAL64, DOUBLE_ARRAY) stashes an `InvalidBind` deferred
/// error on the query that surfaces from `_query_execute`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_query_bind_null(
    query: *mut line_reader_query,
    kind: line_reader_column_kind,
) {
    unsafe {
        // NULL-handle guard before any deferred_err deref below.
        null_check_handle!(query, "line_reader_query_bind_null");
        let k = column_kind_from_c(kind);
        match SimpleNullKind::try_from(k) {
            Ok(s) => mutate_query(query, |q| q.bind_null(s)),
            Err(invalid) => {
                // Don't touch the upstream builder — leaving the bind
                // unposted keeps later bind indices stable. Stash the
                // error so `_query_execute` surfaces it. First-error-
                // wins so the original cause isn't masked.
                if (*query).deferred_err.is_none() {
                    (*query).deferred_err = Some(Error::new(
                        ErrorCode::InvalidBind,
                        format!(
                            "line_reader_query_bind_null: kind {} is not a simple-null kind; \
                             use the dedicated line_reader_query_bind_null_{{varchar,binary,decimal64,decimal128,decimal256,geohash}} \
                             entry point",
                            invalid.name()
                        ),
                    ));
                }
            }
        }
    }
}

fn column_kind_from_c(k: line_reader_column_kind) -> ColumnKind {
    use line_reader_column_kind::*;
    match k {
        line_reader_column_kind_boolean => ColumnKind::Boolean,
        line_reader_column_kind_byte => ColumnKind::Byte,
        line_reader_column_kind_short => ColumnKind::Short,
        line_reader_column_kind_int => ColumnKind::Int,
        line_reader_column_kind_long => ColumnKind::Long,
        line_reader_column_kind_float => ColumnKind::Float,
        line_reader_column_kind_double => ColumnKind::Double,
        line_reader_column_kind_symbol => ColumnKind::Symbol,
        line_reader_column_kind_timestamp => ColumnKind::Timestamp,
        line_reader_column_kind_date => ColumnKind::Date,
        line_reader_column_kind_uuid => ColumnKind::Uuid,
        line_reader_column_kind_geohash => ColumnKind::Geohash,
        line_reader_column_kind_varchar => ColumnKind::Varchar,
        line_reader_column_kind_timestamp_nanos => ColumnKind::TimestampNanos,
        line_reader_column_kind_double_array => ColumnKind::DoubleArray,
        line_reader_column_kind_long_array => ColumnKind::LongArray,
        line_reader_column_kind_decimal64 => ColumnKind::Decimal64,
        line_reader_column_kind_decimal128 => ColumnKind::Decimal128,
        line_reader_column_kind_decimal256 => ColumnKind::Decimal256,
        line_reader_column_kind_char => ColumnKind::Char,
        line_reader_column_kind_binary => ColumnKind::Binary,
        line_reader_column_kind_long256 => ColumnKind::Long256,
        line_reader_column_kind_ipv4 => ColumnKind::Ipv4,
    }
}

// ---------------------------------------------------------------------------
// Cursor
// ---------------------------------------------------------------------------

/// Opaque cursor handle. Borrows from the originating `line_reader` for its
/// entire lifetime — the reader MUST outlive the cursor. Single-threaded.
///
/// # Self-referential invariant (READ BEFORE EDITING)
///
/// `current_batch: Option<BatchView<'static>>` is laundered to `'static`
/// but in reality borrows from `cursor: ManuallyDrop<Cursor<'static>>`
/// (also laundered). This is a self-referential struct held together
/// purely by convention; the Rust type system cannot enforce the
/// invariant. The convention is:
///
///   *Any code path that takes `&mut self.cursor` MUST first set
///   `self.current_batch = None`, OR be the one final consumer that
///   tears the whole struct down.*
///
/// Violating this aliases the immutable borrow held by the live
/// `BatchView` against the new exclusive borrow on the `Cursor` it came
/// from — instant Rust aliasing UB even though the C caller would see
/// no symptom until later memory corruption.
///
/// To make accidental violation harder, all in-place cursor mutations
/// (`_cursor_cancel`, `_cursor_add_credit`, `_cursor_next_batch`) route
/// through `cursor_for_mut()`, which clears the batch and yields the
/// exclusive borrow in one step. `_cursor_free` is the one teardown
/// path that does not use the helper — it consumes the `Box` and drops
/// the `BatchView` first, then the cursor, then the box.
pub struct line_reader_cursor {
    /// Cursor borrowing from the originating Reader. Lifetime extended to
    /// `'static` via `transmute`; the actual lifetime is bounded by the
    /// reader the C caller holds. ManuallyDrop because the cursor must be
    /// dropped before the surrounding box is freed.
    cursor: ManuallyDrop<Cursor<'static>>,
    /// View over the most recently decoded batch. Re-issued on each
    /// `next_batch`; cleared when the stream terminates. Lifetime extended
    /// for the same reason as `cursor`. See the struct-level safety note —
    /// this field MUST be `None` whenever `&mut self.cursor` is exposed.
    current_batch: Option<BatchView<'static>>,
    /// Backpointer to the originating reader, used to clear its `active`
    /// flag on `_cursor_free`. Always non-NULL for a valid cursor.
    reader: *mut line_reader,
}

impl line_reader_cursor {
    /// Drop any in-flight `BatchView` and yield exclusive access to the
    /// inner `Cursor`. The single chokepoint that maintains the
    /// "no-`current_batch`-while-`&mut cursor`" invariant documented on
    /// `line_reader_cursor`. Mutating cursor ops MUST go through here
    /// instead of taking `&mut self.cursor` directly.
    fn cursor_for_mut(&mut self) -> &mut Cursor<'static> {
        self.current_batch = None;
        debug_assert!(self.current_batch.is_none());
        &mut self.cursor
    }
}

/// Free the cursor and release its resources. Drops any in-flight
/// batch view; if the cursor was abandoned mid-stream, tears down the
/// underlying WebSocket transport (bounded by ~200ms) so the server
/// stops streaming and releases request-scoped state. On a fully-drained
/// cursor the reader's connection is preserved for the next query. No
/// CANCEL frame is sent — the server learns about a mid-stream abort
/// only when the socket goes away. Call `line_reader_cursor_cancel`
/// first if you need a cooperative cancellation handshake before the
/// connection is closed. Idempotent on NULL.
///
/// Naming aligns with `line_reader_query_free` / `line_reader_error_free`
/// (and the ingress `line_sender_buffer_free` / `_opts_free`): the only
/// `_close` in the egress API is `line_reader_close`, which closes the
/// persistent network transport. Every other handle, including this
/// per-query cursor, uses `_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_free(cursor: *mut line_reader_cursor) {
    panic_guard(|| unsafe {
        if cursor.is_null() {
            return;
        }
        let mut boxed = Box::from_raw(cursor);
        // Drop the borrowed BatchView before the cursor it borrows from.
        // Wrapped in `panic_guard` because the cursor's Drop runs
        // `close_in_place` which writes a Close frame and shuts down the
        // TCP socket — any panic there would otherwise cross the FFI
        // boundary.
        boxed.current_batch = None;
        ManuallyDrop::drop(&mut boxed.cursor);
        // Release the reader's active flag so a new query/cursor can be
        // started.
        if !boxed.reader.is_null() {
            (*boxed.reader).1.store(false, Ordering::Release);
        }
        drop(boxed);
    })
}

/// Advance to the next batch.
///
/// Returns:
///   * `1`  — a new batch is available; column accessors are now valid.
///   * `0`  — the stream has terminated normally; no batch is available.
///   * `-1` — an error occurred; `*err_out` is set and the cursor must be closed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_next_batch(
    cursor: *mut line_reader_cursor,
    err_out: *mut *mut line_reader_error,
) -> i32 {
    unsafe {
        null_check_handle!(cursor, "line_reader_cursor_next_batch");
        let c = &mut *cursor;
        // `cursor_for_mut` clears `current_batch` (releasing the prior
        // BatchView's borrow on the cursor) and yields exclusive access
        // to the inner Cursor in one step — see the struct-level safety
        // note. The borrow is released before we re-assign
        // `c.current_batch` below; the explicit binding (`inner`) keeps
        // borrowck happy across the match.
        let inner: &mut Cursor<'static> = c.cursor_for_mut();
        // The decoder pipeline (varint parse, schema/dict bookkeeping,
        // Gorilla decode, validity walks) contains panic sites that an
        // unwind would propagate through this `extern "C"` frame — UB.
        // Catch and abort, matching the policy in `_query_new` and
        // `_query_execute`. The lifetime launder happens INSIDE the
        // closure: `BatchView<'_>` borrows from `inner`, which the
        // closure can't return as a borrow of a captured variable. The
        // launder is sound for the same reason as in `_query_new` —
        // the cursor (and therefore the batch's backing buffers) lives
        // at least as long as the FFI call sequence ends with
        // `_cursor_free`.
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match inner.next_batch() {
                Ok(Some(batch)) => {
                    let batch_static: BatchView<'static> = std::mem::transmute(batch);
                    Ok(Some(batch_static))
                }
                Ok(None) => Ok(None),
                Err(e) => Err(e),
            }));
        let next = match result {
            Ok(r) => r,
            Err(_) => std::process::abort(),
        };
        match next {
            Ok(Some(batch_static)) => {
                c.current_batch = Some(batch_static);
                1
            }
            Ok(None) => 0,
            Err(e) => {
                *err_out = Box::into_raw(Box::new(line_reader_error(e)));
                -1
            }
        }
    }
}

/// Number of rows in the current batch. Returns `0` when no batch is loaded.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_row_count(cursor: *const line_reader_cursor) -> size_t {
    unsafe {
        match (*cursor).current_batch.as_ref() {
            Some(b) => b.row_count(),
            None => 0,
        }
    }
}

/// Number of columns in the current batch. Returns `0` when no batch is loaded.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_column_count(
    cursor: *const line_reader_cursor,
) -> size_t {
    unsafe {
        match (*cursor).current_batch.as_ref() {
            Some(b) => b.column_count(),
            None => 0,
        }
    }
}

/// Get the kind discriminant for a column in the current batch.
/// Returns false and sets `*err_out` if no batch is loaded or `col_idx` is
/// out of range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_column_kind(
    cursor: *const line_reader_cursor,
    col_idx: size_t,
    out_kind: *mut line_reader_column_kind,
    err_out: *mut *mut line_reader_error,
) -> bool {
    panic_guard(|| unsafe {
        let view = match get_column_view(&*cursor, col_idx, err_out) {
            Some(v) => v,
            None => return false,
        };
        *out_kind = view.kind().into();
        true
    })
}

/// Borrowed UTF-8 column name for the column at `col_idx` in the current
/// batch's schema. The string is NOT null-terminated. The pointer is
/// borrowed from the per-connection `SchemaRegistry`; it remains valid for
/// at least as long as the cursor — schemas referenced by RESULT_BATCH
/// frames are pinned for the cursor's lifetime.
///
/// Returns false and sets `*err_out` if no batch is loaded, `col_idx` is
/// out of range, or the cursor's schema lookup fails.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_column_name(
    cursor: *const line_reader_cursor,
    col_idx: size_t,
    out_buf: *mut *const c_char,
    out_len: *mut size_t,
    err_out: *mut *mut line_reader_error,
) -> bool {
    unsafe {
        let batch = match (*cursor).current_batch.as_ref() {
            Some(b) => b,
            None => {
                set_reader_err(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    "no batch loaded; call line_reader_cursor_next_batch first",
                );
                return false;
            }
        };
        let schema = batch.schema();
        match schema.column(col_idx) {
            Some(col) => {
                *out_buf = col.name.as_ptr() as *const c_char;
                *out_len = col.name.len();
                true
            }
            None => {
                set_reader_err(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    format!(
                        "column index {} out of range (column_count={})",
                        col_idx,
                        schema.len()
                    ),
                );
                false
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Per-kind getters (vertical-slice subset: bool / i64 / f64)
// ---------------------------------------------------------------------------

/// Read a `BOOLEAN` value at `(col_idx, row_idx)` in the current batch.
/// On success, `*out_value` is the row's value and `*out_is_null` indicates
/// whether the row is null (in which case `*out_value` is undefined).
/// Returns false and sets `*err_out` on type mismatch, missing batch, or
/// out-of-range indices.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_get_bool(
    cursor: *const line_reader_cursor,
    col_idx: size_t,
    row_idx: size_t,
    out_value: *mut bool,
    out_is_null: *mut bool,
    err_out: *mut *mut line_reader_error,
) -> bool {
    panic_guard(|| unsafe {
        let view = match get_column_view(&*cursor, col_idx, err_out) {
            Some(v) => v,
            None => return false,
        };
        let col = match view {
            ColumnView::Boolean(c) => c,
            other => {
                set_reader_err(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    format!("column {} is {:?}, not BOOLEAN", col_idx, other.kind()),
                );
                return false;
            }
        };
        if !check_row(col_idx, row_idx, col.len(), err_out) {
            return false;
        }
        let is_null = col.validity().is_null(row_idx);
        *out_is_null = is_null;
        *out_value = !is_null && col.value(row_idx) != 0;
        true
    })
}

/// Read an `LONG` / `TIMESTAMP` (μs) / `DATE` (ms) / `TIMESTAMP_NANOS` (ns)
/// value at `(col_idx, row_idx)`. All four kinds are i64-typed under the
/// hood and accepted by this getter — call `line_reader_cursor_column_kind`
/// to disambiguate units.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_get_i64(
    cursor: *const line_reader_cursor,
    col_idx: size_t,
    row_idx: size_t,
    out_value: *mut i64,
    out_is_null: *mut bool,
    err_out: *mut *mut line_reader_error,
) -> bool {
    panic_guard(|| unsafe {
        let view = match get_column_view(&*cursor, col_idx, err_out) {
            Some(v) => v,
            None => return false,
        };
        let col = match view {
            ColumnView::Long(c)
            | ColumnView::Timestamp(c)
            | ColumnView::Date(c)
            | ColumnView::TimestampNanos(c) => c,
            other => {
                set_reader_err(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    format!(
                        "column {} is {:?}, not LONG/TIMESTAMP/DATE/TIMESTAMP_NANOS",
                        col_idx,
                        other.kind()
                    ),
                );
                return false;
            }
        };
        if !check_row(col_idx, row_idx, col.len(), err_out) {
            return false;
        }
        let is_null = col.validity().is_null(row_idx);
        *out_is_null = is_null;
        *out_value = if is_null { 0 } else { col.value(row_idx) };
        true
    })
}

/// Read a `DOUBLE` value at `(col_idx, row_idx)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_get_f64(
    cursor: *const line_reader_cursor,
    col_idx: size_t,
    row_idx: size_t,
    out_value: *mut f64,
    out_is_null: *mut bool,
    err_out: *mut *mut line_reader_error,
) -> bool {
    panic_guard(|| unsafe {
        let view = match get_column_view(&*cursor, col_idx, err_out) {
            Some(v) => v,
            None => return false,
        };
        let col = match view {
            ColumnView::Double(c) => c,
            other => {
                set_reader_err(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    format!("column {} is {:?}, not DOUBLE", col_idx, other.kind()),
                );
                return false;
            }
        };
        if !check_row(col_idx, row_idx, col.len(), err_out) {
            return false;
        }
        let is_null = col.validity().is_null(row_idx);
        *out_is_null = is_null;
        *out_value = if is_null { 0.0 } else { col.value(row_idx) };
        true
    })
}

/// Read a `BYTE` (signed 8-bit) value.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_get_i8(
    cursor: *const line_reader_cursor,
    col_idx: size_t,
    row_idx: size_t,
    out_value: *mut i8,
    out_is_null: *mut bool,
    err_out: *mut *mut line_reader_error,
) -> bool {
    panic_guard(|| unsafe {
        let view = match get_column_view(&*cursor, col_idx, err_out) {
            Some(v) => v,
            None => return false,
        };
        let col = match view {
            ColumnView::Byte(c) => c,
            other => {
                set_reader_err(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    format!("column {} is {:?}, not BYTE", col_idx, other.kind()),
                );
                return false;
            }
        };
        if !check_row(col_idx, row_idx, col.len(), err_out) {
            return false;
        }
        let is_null = col.validity().is_null(row_idx);
        *out_is_null = is_null;
        *out_value = if is_null { 0 } else { col.value(row_idx) };
        true
    })
}

/// Read a `SHORT` (signed 16-bit) value.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_get_i16(
    cursor: *const line_reader_cursor,
    col_idx: size_t,
    row_idx: size_t,
    out_value: *mut i16,
    out_is_null: *mut bool,
    err_out: *mut *mut line_reader_error,
) -> bool {
    panic_guard(|| unsafe {
        let view = match get_column_view(&*cursor, col_idx, err_out) {
            Some(v) => v,
            None => return false,
        };
        let col = match view {
            ColumnView::Short(c) => c,
            other => {
                set_reader_err(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    format!("column {} is {:?}, not SHORT", col_idx, other.kind()),
                );
                return false;
            }
        };
        if !check_row(col_idx, row_idx, col.len(), err_out) {
            return false;
        }
        let is_null = col.validity().is_null(row_idx);
        *out_is_null = is_null;
        *out_value = if is_null { 0 } else { col.value(row_idx) };
        true
    })
}

/// Read an `INT` (signed 32-bit) value. Rejects `IPV4` columns —
/// use `line_reader_cursor_get_ipv4` for those. Reinterpreting an IPv4
/// address through a signed 32-bit getter would silently flip the sign
/// for any address ≥ 128.0.0.0, so the two are kept on separate
/// accessors.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_get_i32(
    cursor: *const line_reader_cursor,
    col_idx: size_t,
    row_idx: size_t,
    out_value: *mut i32,
    out_is_null: *mut bool,
    err_out: *mut *mut line_reader_error,
) -> bool {
    panic_guard(|| unsafe {
        let view = match get_column_view(&*cursor, col_idx, err_out) {
            Some(v) => v,
            None => return false,
        };
        let col = match view {
            ColumnView::Int(c) => c,
            other => {
                set_reader_err(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    format!("column {} is {:?}, not INT", col_idx, other.kind()),
                );
                return false;
            }
        };
        if !check_row(col_idx, row_idx, col.len(), err_out) {
            return false;
        }
        let is_null = col.validity().is_null(row_idx);
        *out_is_null = is_null;
        *out_value = if is_null { 0 } else { col.value(row_idx) };
        true
    })
}

/// Read an `IPV4` value as an unsigned 32-bit integer in the conventional
/// big-endian-packed form: `(a << 24) | (b << 16) | (c << 8) | d` for
/// `a.b.c.d`. This matches `line_reader_query_bind_ipv4`'s parameter
/// (round-trip safe) and avoids the sign-flip that would occur if the
/// value were reinterpreted as `int32_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_get_ipv4(
    cursor: *const line_reader_cursor,
    col_idx: size_t,
    row_idx: size_t,
    out_value: *mut u32,
    out_is_null: *mut bool,
    err_out: *mut *mut line_reader_error,
) -> bool {
    panic_guard(|| unsafe {
        let view = match get_column_view(&*cursor, col_idx, err_out) {
            Some(v) => v,
            None => return false,
        };
        let col = match view {
            ColumnView::Ipv4(c) => c,
            other => {
                set_reader_err(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    format!("column {} is {:?}, not IPV4", col_idx, other.kind()),
                );
                return false;
            }
        };
        if !check_row(col_idx, row_idx, col.len(), err_out) {
            return false;
        }
        let is_null = col.validity().is_null(row_idx);
        *out_is_null = is_null;
        *out_value = if is_null { 0 } else { col.value(row_idx) };
        true
    })
}

/// Read a `FLOAT` (32-bit) value.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_get_f32(
    cursor: *const line_reader_cursor,
    col_idx: size_t,
    row_idx: size_t,
    out_value: *mut f32,
    out_is_null: *mut bool,
    err_out: *mut *mut line_reader_error,
) -> bool {
    panic_guard(|| unsafe {
        let view = match get_column_view(&*cursor, col_idx, err_out) {
            Some(v) => v,
            None => return false,
        };
        let col = match view {
            ColumnView::Float(c) => c,
            other => {
                set_reader_err(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    format!("column {} is {:?}, not FLOAT", col_idx, other.kind()),
                );
                return false;
            }
        };
        if !check_row(col_idx, row_idx, col.len(), err_out) {
            return false;
        }
        let is_null = col.validity().is_null(row_idx);
        *out_is_null = is_null;
        *out_value = if is_null { 0.0 } else { col.value(row_idx) };
        true
    })
}

/// Read a `CHAR` value (a 16-bit UTF-16 code unit, per QuestDB semantics).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_get_char(
    cursor: *const line_reader_cursor,
    col_idx: size_t,
    row_idx: size_t,
    out_value: *mut u16,
    out_is_null: *mut bool,
    err_out: *mut *mut line_reader_error,
) -> bool {
    panic_guard(|| unsafe {
        let view = match get_column_view(&*cursor, col_idx, err_out) {
            Some(v) => v,
            None => return false,
        };
        let col = match view {
            ColumnView::Char(c) => c,
            other => {
                set_reader_err(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    format!("column {} is {:?}, not CHAR", col_idx, other.kind()),
                );
                return false;
            }
        };
        if !check_row(col_idx, row_idx, col.len(), err_out) {
            return false;
        }
        let is_null = col.validity().is_null(row_idx);
        *out_is_null = is_null;
        *out_value = if is_null { 0 } else { col.value(row_idx) };
        true
    })
}

/// Read a `UUID` value as 16 raw bytes. `out_value` must point to at least
/// 16 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_get_uuid(
    cursor: *const line_reader_cursor,
    col_idx: size_t,
    row_idx: size_t,
    out_value: *mut u8,
    out_is_null: *mut bool,
    err_out: *mut *mut line_reader_error,
) -> bool {
    panic_guard(|| unsafe {
        let view = match get_column_view(&*cursor, col_idx, err_out) {
            Some(v) => v,
            None => return false,
        };
        let col = match view {
            ColumnView::Uuid(c) => c,
            other => {
                set_reader_err(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    format!("column {} is {:?}, not UUID", col_idx, other.kind()),
                );
                return false;
            }
        };
        if !check_row(col_idx, row_idx, col.len(), err_out) {
            return false;
        }
        let is_null = col.validity().is_null(row_idx);
        *out_is_null = is_null;
        if is_null {
            ptr::write_bytes(out_value, 0, 16);
        } else {
            ptr::copy_nonoverlapping(col.value(row_idx).as_ptr(), out_value, 16);
        }
        true
    })
}

/// Read a `LONG256` value as 32 raw little-endian bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_get_long256(
    cursor: *const line_reader_cursor,
    col_idx: size_t,
    row_idx: size_t,
    out_value: *mut u8,
    out_is_null: *mut bool,
    err_out: *mut *mut line_reader_error,
) -> bool {
    panic_guard(|| unsafe {
        let view = match get_column_view(&*cursor, col_idx, err_out) {
            Some(v) => v,
            None => return false,
        };
        let col = match view {
            ColumnView::Long256(c) => c,
            other => {
                set_reader_err(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    format!("column {} is {:?}, not LONG256", col_idx, other.kind()),
                );
                return false;
            }
        };
        if !check_row(col_idx, row_idx, col.len(), err_out) {
            return false;
        }
        let is_null = col.validity().is_null(row_idx);
        *out_is_null = is_null;
        if is_null {
            ptr::write_bytes(out_value, 0, 32);
        } else {
            ptr::copy_nonoverlapping(col.value(row_idx).as_ptr(), out_value, 32);
        }
        true
    })
}

/// Read a `VARCHAR` value as a borrowed UTF-8 byte slice. The returned
/// pointer is valid until the next `line_reader_cursor_next_batch` call or
/// until the cursor is closed. `*out_buf` is set to NULL when the row is
/// null. The string is NOT null-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_get_varchar(
    cursor: *const line_reader_cursor,
    col_idx: size_t,
    row_idx: size_t,
    out_buf: *mut *const c_char,
    out_len: *mut size_t,
    out_is_null: *mut bool,
    err_out: *mut *mut line_reader_error,
) -> bool {
    panic_guard(|| unsafe {
        let view = match get_column_view(&*cursor, col_idx, err_out) {
            Some(v) => v,
            None => return false,
        };
        let col = match view {
            ColumnView::Varchar(c) => c,
            other => {
                set_reader_err(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    format!("column {} is {:?}, not VARCHAR", col_idx, other.kind()),
                );
                return false;
            }
        };
        if !check_row(col_idx, row_idx, col.len(), err_out) {
            return false;
        }
        match col.value(row_idx) {
            Some(s) => {
                *out_is_null = false;
                *out_buf = s.as_ptr() as *const c_char;
                *out_len = s.len();
            }
            None => {
                *out_is_null = true;
                *out_buf = ptr::null();
                *out_len = 0;
            }
        }
        true
    })
}

/// Read a `BINARY` value as a borrowed byte slice. Same lifetime contract
/// as `line_reader_cursor_get_varchar`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_get_binary(
    cursor: *const line_reader_cursor,
    col_idx: size_t,
    row_idx: size_t,
    out_buf: *mut *const u8,
    out_len: *mut size_t,
    out_is_null: *mut bool,
    err_out: *mut *mut line_reader_error,
) -> bool {
    panic_guard(|| unsafe {
        let view = match get_column_view(&*cursor, col_idx, err_out) {
            Some(v) => v,
            None => return false,
        };
        let col = match view {
            ColumnView::Binary(c) => c,
            other => {
                set_reader_err(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    format!("column {} is {:?}, not BINARY", col_idx, other.kind()),
                );
                return false;
            }
        };
        if !check_row(col_idx, row_idx, col.len(), err_out) {
            return false;
        }
        match col.value(row_idx) {
            Some(b) => {
                *out_is_null = false;
                *out_buf = b.as_ptr();
                *out_len = b.len();
            }
            None => {
                *out_is_null = true;
                *out_buf = ptr::null();
                *out_len = 0;
            }
        }
        true
    })
}

/// Read a `SYMBOL` value as a UTF-8 byte slice resolved through the
/// connection-scoped symbol dictionary. Same lifetime contract as
/// `line_reader_cursor_get_varchar` (valid until next batch or close).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_get_symbol(
    cursor: *const line_reader_cursor,
    col_idx: size_t,
    row_idx: size_t,
    out_buf: *mut *const c_char,
    out_len: *mut size_t,
    out_is_null: *mut bool,
    err_out: *mut *mut line_reader_error,
) -> bool {
    panic_guard(|| unsafe {
        let view = match get_column_view(&*cursor, col_idx, err_out) {
            Some(v) => v,
            None => return false,
        };
        let col = match view {
            ColumnView::Symbol(c) => c,
            other => {
                set_reader_err(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    format!("column {} is {:?}, not SYMBOL", col_idx, other.kind()),
                );
                return false;
            }
        };
        if !check_row(col_idx, row_idx, col.len(), err_out) {
            return false;
        }
        match col.resolve(row_idx) {
            Some(s) => {
                *out_is_null = false;
                *out_buf = s.as_ptr() as *const c_char;
                *out_len = s.len();
            }
            None => {
                *out_is_null = true;
                *out_buf = ptr::null();
                *out_len = 0;
            }
        }
        true
    })
}

/// Read a `DECIMAL64` mantissa plus the column's scale.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_get_decimal64(
    cursor: *const line_reader_cursor,
    col_idx: size_t,
    row_idx: size_t,
    out_mantissa: *mut i64,
    out_scale: *mut i8,
    out_is_null: *mut bool,
    err_out: *mut *mut line_reader_error,
) -> bool {
    panic_guard(|| unsafe {
        let view = match get_column_view(&*cursor, col_idx, err_out) {
            Some(v) => v,
            None => return false,
        };
        let col = match view {
            ColumnView::Decimal64(c) => c,
            other => {
                set_reader_err(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    format!("column {} is {:?}, not DECIMAL64", col_idx, other.kind()),
                );
                return false;
            }
        };
        if !check_row(col_idx, row_idx, col.len(), err_out) {
            return false;
        }
        let is_null = col.is_null(row_idx);
        *out_is_null = is_null;
        *out_mantissa = if is_null { 0 } else { col.value(row_idx) };
        *out_scale = col.scale();
        true
    })
}

/// Read a `DECIMAL128` mantissa as `u64` low + `i64` high (the upper 64 bits
/// reinterpreted to preserve the i128 sign in the C type), plus column scale.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_get_decimal128(
    cursor: *const line_reader_cursor,
    col_idx: size_t,
    row_idx: size_t,
    out_low: *mut u64,
    out_high: *mut i64,
    out_scale: *mut i8,
    out_is_null: *mut bool,
    err_out: *mut *mut line_reader_error,
) -> bool {
    panic_guard(|| unsafe {
        let view = match get_column_view(&*cursor, col_idx, err_out) {
            Some(v) => v,
            None => return false,
        };
        let col = match view {
            ColumnView::Decimal128(c) => c,
            other => {
                set_reader_err(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    format!("column {} is {:?}, not DECIMAL128", col_idx, other.kind()),
                );
                return false;
            }
        };
        if !check_row(col_idx, row_idx, col.len(), err_out) {
            return false;
        }
        let is_null = col.is_null(row_idx);
        *out_is_null = is_null;
        let value: i128 = if is_null { 0 } else { col.value(row_idx) };
        let bits = value as u128;
        *out_low = bits as u64;
        *out_high = (bits >> 64) as i64;
        *out_scale = col.scale();
        true
    })
}

/// Read a `DECIMAL256` mantissa as 32 raw little-endian bytes plus column scale.
/// `out_value` must point to at least 32 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_get_decimal256(
    cursor: *const line_reader_cursor,
    col_idx: size_t,
    row_idx: size_t,
    out_value: *mut u8,
    out_scale: *mut i8,
    out_is_null: *mut bool,
    err_out: *mut *mut line_reader_error,
) -> bool {
    panic_guard(|| unsafe {
        let view = match get_column_view(&*cursor, col_idx, err_out) {
            Some(v) => v,
            None => return false,
        };
        let col = match view {
            ColumnView::Decimal256(c) => c,
            other => {
                set_reader_err(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    format!("column {} is {:?}, not DECIMAL256", col_idx, other.kind()),
                );
                return false;
            }
        };
        if !check_row(col_idx, row_idx, col.len(), err_out) {
            return false;
        }
        let is_null = col.is_null(row_idx);
        *out_is_null = is_null;
        if is_null {
            ptr::write_bytes(out_value, 0, 32);
        } else {
            ptr::copy_nonoverlapping(col.value(row_idx).as_ptr(), out_value, 32);
        }
        *out_scale = col.scale();
        true
    })
}

/// Borrowed view over a single `DOUBLE_ARRAY` row.
///
/// All pointers are valid until the next `line_reader_cursor_next_batch`
/// call or until the cursor is closed. `shape` is row-major (innermost
/// dimension last). `data` is concatenated little-endian `f64` bytes
/// (`element_count = data_len / 8`).
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct line_reader_double_array_view {
    pub shape: *const u32,
    pub ndim: size_t,
    pub data: *const u8,
    pub data_len: size_t,
    pub element_count: size_t,
}

/// Borrowed view over a single `LONG_ARRAY` row. Same layout as the f64
/// variant; `data` is concatenated little-endian `i64` bytes.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct line_reader_long_array_view {
    pub shape: *const u32,
    pub ndim: size_t,
    pub data: *const u8,
    pub data_len: size_t,
    pub element_count: size_t,
}

unsafe fn empty_array_view_f64(out: *mut line_reader_double_array_view) {
    unsafe {
        (*out).shape = ptr::null();
        (*out).ndim = 0;
        (*out).data = ptr::null();
        (*out).data_len = 0;
        (*out).element_count = 0;
    }
}

unsafe fn empty_array_view_i64(out: *mut line_reader_long_array_view) {
    unsafe {
        (*out).shape = ptr::null();
        (*out).ndim = 0;
        (*out).data = ptr::null();
        (*out).data_len = 0;
        (*out).element_count = 0;
    }
}

/// Read a `DOUBLE_ARRAY` row into a borrowed view. On a NULL row, all
/// view fields are zeroed and `*out_is_null` is true.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_get_double_array(
    cursor: *const line_reader_cursor,
    col_idx: size_t,
    row_idx: size_t,
    out_view: *mut line_reader_double_array_view,
    out_is_null: *mut bool,
    err_out: *mut *mut line_reader_error,
) -> bool {
    panic_guard(|| unsafe {
        let view = match get_column_view(&*cursor, col_idx, err_out) {
            Some(v) => v,
            None => return false,
        };
        let col = match view {
            ColumnView::DoubleArray(c) => c,
            other => {
                set_reader_err(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    format!("column {} is {:?}, not DOUBLE_ARRAY", col_idx, other.kind()),
                );
                return false;
            }
        };
        if !check_row(col_idx, row_idx, col.len(), err_out) {
            return false;
        }
        if col.is_null(row_idx) {
            empty_array_view_f64(out_view);
            *out_is_null = true;
            return true;
        }
        // For a non-null row, `shape`/`raw` returning None indicates a wire
        // invariant violation — surface it rather than fabricate a view
        // with dangling-but-non-null pointers from `(&[]).as_ptr()`.
        let (shape, raw) = match (col.shape(row_idx), col.raw(row_idx)) {
            (Some(s), Some(r)) => (s, r),
            _ => {
                empty_array_view_f64(out_view);
                set_reader_err(
                    err_out,
                    ErrorCode::ProtocolError,
                    format!(
                        "DOUBLE_ARRAY row {} of column {} has no shape/data \
                         despite being non-null",
                        row_idx, col_idx
                    ),
                );
                return false;
            }
        };
        // Defense-in-depth: a `raw` length that isn't a multiple of 8
        // would mean the decoder produced a partial f64 element. Reject
        // before exposing a view where `data_len` and `element_count`
        // would disagree (truncating element_count silently would let
        // the C caller read past the last whole element).
        if !raw.len().is_multiple_of(8) {
            empty_array_view_f64(out_view);
            set_reader_err(
                err_out,
                ErrorCode::ProtocolError,
                format!(
                    "DOUBLE_ARRAY row {} of column {} has data_len {} \
                     (not a multiple of 8 — partial f64 element)",
                    row_idx,
                    col_idx,
                    raw.len()
                ),
            );
            return false;
        }
        // Symmetry: `data_len == 0 ⇒ data == NULL`, `ndim == 0 ⇒ shape ==
        // NULL`. Without these, an array row whose shape produces zero
        // elements (e.g. `[2, 0, 3]`) would expose Rust's
        // `(&[]).as_ptr()` dangling sentinel to C, breaking defensive
        // checks like `if (view.data) { ... }`. `shape.is_empty()` is
        // unreachable today (the decoder rejects `n_dims == 0`) but
        // null-out is symmetric with the data path.
        (*out_view).shape = if shape.is_empty() {
            ptr::null()
        } else {
            shape.as_ptr()
        };
        (*out_view).ndim = shape.len();
        (*out_view).data = if raw.is_empty() {
            ptr::null()
        } else {
            raw.as_ptr()
        };
        (*out_view).data_len = raw.len();
        (*out_view).element_count = raw.len() / 8;
        *out_is_null = false;
        true
    })
}

/// Read a single `f64` element at flat row-major index `flat_idx` of a
/// `DOUBLE_ARRAY` row. Useful for callers that don't want to handle
/// little-endian byte reads themselves.
///
/// On a NULL row sets `*out_is_null = true`, zeroes `*out_value`, and
/// returns true. On a non-null row in range writes `*out_value`, sets
/// `*out_is_null = false`, and returns true. Returns false and sets
/// `*err_out` for type mismatch, out-of-range `row_idx`, or out-of-range
/// `flat_idx`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_get_double_array_element(
    cursor: *const line_reader_cursor,
    col_idx: size_t,
    row_idx: size_t,
    flat_idx: size_t,
    out_value: *mut f64,
    out_is_null: *mut bool,
    err_out: *mut *mut line_reader_error,
) -> bool {
    panic_guard(|| unsafe {
        let view = match get_column_view(&*cursor, col_idx, err_out) {
            Some(v) => v,
            None => return false,
        };
        let col = match view {
            ColumnView::DoubleArray(c) => c,
            other => {
                set_reader_err(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    format!("column {} is {:?}, not DOUBLE_ARRAY", col_idx, other.kind()),
                );
                return false;
            }
        };
        if !check_row(col_idx, row_idx, col.len(), err_out) {
            return false;
        }
        if col.is_null(row_idx) {
            *out_is_null = true;
            *out_value = 0.0;
            return true;
        }
        match col.element(row_idx, flat_idx) {
            Some(v) => {
                *out_is_null = false;
                *out_value = v;
                true
            }
            None => {
                set_reader_err(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    format!(
                        "flat index {} out of range for row {} of column {} \
                         (element_count={})",
                        flat_idx,
                        row_idx,
                        col_idx,
                        col.element_count(row_idx)
                    ),
                );
                false
            }
        }
    })
}

/// Read a `LONG_ARRAY` row into a borrowed view.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_get_long_array(
    cursor: *const line_reader_cursor,
    col_idx: size_t,
    row_idx: size_t,
    out_view: *mut line_reader_long_array_view,
    out_is_null: *mut bool,
    err_out: *mut *mut line_reader_error,
) -> bool {
    panic_guard(|| unsafe {
        let view = match get_column_view(&*cursor, col_idx, err_out) {
            Some(v) => v,
            None => return false,
        };
        let col = match view {
            ColumnView::LongArray(c) => c,
            other => {
                set_reader_err(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    format!("column {} is {:?}, not LONG_ARRAY", col_idx, other.kind()),
                );
                return false;
            }
        };
        if !check_row(col_idx, row_idx, col.len(), err_out) {
            return false;
        }
        if col.is_null(row_idx) {
            empty_array_view_i64(out_view);
            *out_is_null = true;
            return true;
        }
        // For a non-null row, `shape`/`raw` returning None indicates a wire
        // invariant violation — surface it rather than fabricate a view
        // with dangling-but-non-null pointers from `(&[]).as_ptr()`.
        let (shape, raw) = match (col.shape(row_idx), col.raw(row_idx)) {
            (Some(s), Some(r)) => (s, r),
            _ => {
                empty_array_view_i64(out_view);
                set_reader_err(
                    err_out,
                    ErrorCode::ProtocolError,
                    format!(
                        "LONG_ARRAY row {} of column {} has no shape/data \
                         despite being non-null",
                        row_idx, col_idx
                    ),
                );
                return false;
            }
        };
        // Defense-in-depth: see the matching check in
        // `line_reader_cursor_get_double_array`. A `raw` length not
        // divisible by 8 means the decoder produced a partial i64
        // element; surface as ProtocolError rather than silently
        // truncating element_count.
        if !raw.len().is_multiple_of(8) {
            empty_array_view_i64(out_view);
            set_reader_err(
                err_out,
                ErrorCode::ProtocolError,
                format!(
                    "LONG_ARRAY row {} of column {} has data_len {} \
                     (not a multiple of 8 — partial i64 element)",
                    row_idx,
                    col_idx,
                    raw.len()
                ),
            );
            return false;
        }
        // See `line_reader_cursor_get_double_array` for the empty-slice
        // null-out rationale.
        (*out_view).shape = if shape.is_empty() {
            ptr::null()
        } else {
            shape.as_ptr()
        };
        (*out_view).ndim = shape.len();
        (*out_view).data = if raw.is_empty() {
            ptr::null()
        } else {
            raw.as_ptr()
        };
        (*out_view).data_len = raw.len();
        (*out_view).element_count = raw.len() / 8;
        *out_is_null = false;
        true
    })
}

/// Read a single `i64` element of a `LONG_ARRAY` row.
///
/// On a NULL row sets `*out_is_null = true`, zeroes `*out_value`, and
/// returns true. On a non-null row in range writes `*out_value`, sets
/// `*out_is_null = false`, and returns true. Returns false and sets
/// `*err_out` for type mismatch, out-of-range `row_idx`, or out-of-range
/// `flat_idx`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_get_long_array_element(
    cursor: *const line_reader_cursor,
    col_idx: size_t,
    row_idx: size_t,
    flat_idx: size_t,
    out_value: *mut i64,
    out_is_null: *mut bool,
    err_out: *mut *mut line_reader_error,
) -> bool {
    panic_guard(|| unsafe {
        let view = match get_column_view(&*cursor, col_idx, err_out) {
            Some(v) => v,
            None => return false,
        };
        let col = match view {
            ColumnView::LongArray(c) => c,
            other => {
                set_reader_err(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    format!("column {} is {:?}, not LONG_ARRAY", col_idx, other.kind()),
                );
                return false;
            }
        };
        if !check_row(col_idx, row_idx, col.len(), err_out) {
            return false;
        }
        if col.is_null(row_idx) {
            *out_is_null = true;
            *out_value = 0;
            return true;
        }
        match col.element(row_idx, flat_idx) {
            Some(v) => {
                *out_is_null = false;
                *out_value = v;
                true
            }
            None => {
                set_reader_err(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    format!(
                        "flat index {} out of range for row {} of column {} \
                         (element_count={})",
                        flat_idx,
                        row_idx,
                        col_idx,
                        col.element_count(row_idx)
                    ),
                );
                false
            }
        }
    })
}

/// Get the raw validity bitmap for a column in the current batch.
///
/// On success: when the column has any nulls, `*out_buf` is set to a
/// borrowed pointer to the LSB-first bitmap (bit `1` = null) and `*out_len`
/// is its byte length. When the column has no nulls (`Validity::None` on
/// the wire) `*out_buf` is set to NULL and `*out_len` to 0. The pointer is
/// valid until the next `line_reader_cursor_next_batch` call or until the
/// cursor is closed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_column_validity(
    cursor: *const line_reader_cursor,
    col_idx: size_t,
    out_buf: *mut *const u8,
    out_len: *mut size_t,
    err_out: *mut *mut line_reader_error,
) -> bool {
    panic_guard(|| unsafe {
        let view = match get_column_view(&*cursor, col_idx, err_out) {
            Some(v) => v,
            None => return false,
        };
        let validity = column_view_validity(&view);
        // A `Validity::None` wire variant and an empty bitmap both mean
        // "no nulls present"; surface both as a NULL pointer so the
        // documented "out_buf == NULL ⇔ no nulls" contract holds.
        match validity.bytes() {
            Some(bytes) if !bytes.is_empty() => {
                *out_buf = bytes.as_ptr();
                *out_len = bytes.len();
            }
            _ => {
                *out_buf = ptr::null();
                *out_len = 0;
            }
        }
        true
    })
}

fn column_view_validity<'a>(view: &ColumnView<'a>) -> Validity<'a> {
    match view {
        ColumnView::Boolean(c) => c.validity(),
        ColumnView::Byte(c) => c.validity(),
        ColumnView::Short(c) => c.validity(),
        ColumnView::Int(c) => c.validity(),
        ColumnView::Long(c) => c.validity(),
        ColumnView::Float(c) => c.validity(),
        ColumnView::Double(c) => c.validity(),
        ColumnView::Symbol(c) => c.validity(),
        ColumnView::Timestamp(c) => c.validity(),
        ColumnView::Date(c) => c.validity(),
        ColumnView::Uuid(c) => c.validity(),
        ColumnView::Long256(c) => c.validity(),
        ColumnView::TimestampNanos(c) => c.validity(),
        ColumnView::Decimal64(c) => c.validity(),
        ColumnView::Char(c) => c.validity(),
        ColumnView::Ipv4(c) => c.validity(),
        ColumnView::Varchar(c) => c.validity(),
        ColumnView::Binary(c) => c.validity(),
        ColumnView::Geohash(c) => c.validity(),
        ColumnView::Decimal128(c) => c.validity(),
        ColumnView::Decimal256(c) => c.validity(),
        ColumnView::DoubleArray(c) => c.validity(),
        ColumnView::LongArray(c) => c.validity(),
    }
}

// ---------------------------------------------------------------------------
// Cursor introspection
// ---------------------------------------------------------------------------

/// Cursor's request_id (assigned at `execute()` and refreshed on failover).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_request_id(cursor: *const line_reader_cursor) -> i64 {
    unsafe { (*cursor).cursor.request_id() }
}

/// Cumulative bytes of CREDIT this cursor has granted the server. Pulls
/// through to the underlying reader's connection-level counter.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_credit_granted_total(
    cursor: *const line_reader_cursor,
) -> u64 {
    unsafe { (*cursor).cursor.credit_granted_total() }
}

/// Number of successful failover resets observed by this cursor since
/// `execute()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_failover_resets(
    cursor: *const line_reader_cursor,
) -> u32 {
    unsafe { (*cursor).cursor.failover_resets() }
}

/// Host of the endpoint the cursor is currently connected to. Borrowed;
/// invalidated on failover or close.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_current_addr_host(
    cursor: *const line_reader_cursor,
    out_buf: *mut *const c_char,
    out_len: *mut size_t,
) {
    unsafe {
        let ep = (*cursor).cursor.current_addr();
        *out_buf = ep.host.as_ptr() as *const c_char;
        *out_len = ep.host.len();
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_current_addr_port(
    cursor: *const line_reader_cursor,
) -> u16 {
    unsafe { (*cursor).cursor.current_addr().port }
}

/// `request_id` from the most recently decoded batch's frame header. Only
/// meaningful after a successful `next_batch` and before the next call.
///
/// Returns true and writes `*out_request_id` if a batch is currently loaded.
/// Returns false and zeroes the output if no batch is loaded.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_batch_request_id(
    cursor: *const line_reader_cursor,
    out_request_id: *mut i64,
) -> bool {
    unsafe {
        match (*cursor).current_batch.as_ref() {
            Some(b) => {
                *out_request_id = b.request_id();
                true
            }
            None => {
                *out_request_id = 0;
                false
            }
        }
    }
}

/// `batch_seq` of the current batch (0-based, monotonically increasing
/// within a single cursor lifecycle on the same connection).
///
/// Returns true and writes `*out_batch_seq` if a batch is currently loaded.
/// Returns false and zeroes the output if no batch is loaded.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_batch_seq(
    cursor: *const line_reader_cursor,
    out_batch_seq: *mut u64,
) -> bool {
    unsafe {
        match (*cursor).current_batch.as_ref() {
            Some(b) => {
                *out_batch_seq = b.batch_seq();
                true
            }
            None => {
                *out_batch_seq = 0;
                false
            }
        }
    }
}

/// Per-batch wire flags from the current batch's frame header.
///
/// Returns true and writes `*out_flags` if a batch is currently loaded.
/// Returns false and zeroes the output if no batch is loaded.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_batch_flags(
    cursor: *const line_reader_cursor,
    out_flags: *mut u8,
) -> bool {
    unsafe {
        match (*cursor).current_batch.as_ref() {
            Some(b) => {
                *out_flags = b.flags();
                true
            }
            None => {
                *out_flags = 0;
                false
            }
        }
    }
}

/// Terminal kind for the cursor.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub enum line_reader_terminal_kind {
    /// No terminal observed yet (stream is still active or errored out
    /// without a structured terminal).
    line_reader_terminal_kind_none = 0,
    /// `RESULT_END` terminal — see `_terminal_end`.
    line_reader_terminal_kind_end = 1,
    /// `EXEC_DONE` terminal — see `_terminal_exec_done`.
    line_reader_terminal_kind_exec_done = 2,
}

/// Discriminant of the cursor's terminal frame, if observed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_terminal_kind(
    cursor: *const line_reader_cursor,
) -> line_reader_terminal_kind {
    unsafe {
        match (*cursor).cursor.terminal() {
            None => line_reader_terminal_kind::line_reader_terminal_kind_none,
            Some(Terminal::End { .. }) => line_reader_terminal_kind::line_reader_terminal_kind_end,
            Some(Terminal::ExecDone { .. }) => {
                line_reader_terminal_kind::line_reader_terminal_kind_exec_done
            }
            // `Terminal` is `#[non_exhaustive]`. A new variant added
            // upstream that the C ABI hasn't been taught about surfaces
            // as `_none` rather than misrepresenting itself as End or
            // ExecDone — callers reading per-variant fields would then
            // see zeroed values rather than wrong values.
            Some(_) => line_reader_terminal_kind::line_reader_terminal_kind_none,
        }
    }
}

/// If the cursor's terminal is `RESULT_END`, set `*out_final_seq` and
/// `*out_total_rows` and return true. Otherwise zeroes both outputs and
/// returns false.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_terminal_end(
    cursor: *const line_reader_cursor,
    out_final_seq: *mut u64,
    out_total_rows: *mut u64,
) -> bool {
    unsafe {
        match (*cursor).cursor.terminal() {
            Some(Terminal::End {
                final_seq,
                total_rows,
            }) => {
                *out_final_seq = *final_seq;
                *out_total_rows = *total_rows;
                true
            }
            _ => {
                *out_final_seq = 0;
                *out_total_rows = 0;
                false
            }
        }
    }
}

/// If the cursor's terminal is `EXEC_DONE`, set `*out_op_type` and
/// `*out_rows_affected` and return true. Otherwise zeroes both outputs and
/// returns false.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_terminal_exec_done(
    cursor: *const line_reader_cursor,
    out_op_type: *mut u8,
    out_rows_affected: *mut u64,
) -> bool {
    unsafe {
        match (*cursor).cursor.terminal() {
            Some(Terminal::ExecDone {
                op_type,
                rows_affected,
            }) => {
                *out_op_type = *op_type;
                *out_rows_affected = *rows_affected;
                true
            }
            _ => {
                *out_op_type = 0;
                *out_rows_affected = 0;
                false
            }
        }
    }
}

/// Send a `CANCEL` frame and drain the stream until the server's terminal
/// reply. Idempotent once the cursor has reached terminal. Returns false
/// and sets `*err_out` on transport failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_cancel(
    cursor: *mut line_reader_cursor,
    err_out: *mut *mut line_reader_error,
) -> bool {
    unsafe {
        null_check_handle!(cursor, "line_reader_cursor_cancel");
        // Routes through `cursor_for_mut` to maintain the BatchView /
        // &mut Cursor exclusion invariant — see line_reader_cursor docs.
        // `cancel()` runs the drain loop which can panic (decoder paths);
        // catch and abort to keep panics from crossing the FFI boundary.
        let inner = (*cursor).cursor_for_mut();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| inner.cancel()));
        let res = match result {
            Ok(r) => r,
            Err(_) => std::process::abort(),
        };
        match res {
            Ok(()) => true,
            Err(e) => {
                *err_out = Box::into_raw(Box::new(line_reader_error(e)));
                false
            }
        }
    }
}

/// Grant the server an additional CREDIT budget. Only valid for cursors
/// started with `initial_credit > 0`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_add_credit(
    cursor: *mut line_reader_cursor,
    additional_bytes: u64,
    err_out: *mut *mut line_reader_error,
) -> bool {
    unsafe {
        null_check_handle!(cursor, "line_reader_cursor_add_credit");
        // Routes through `cursor_for_mut` — see line_reader_cursor docs.
        // Catch any unwind out of `add_credit` to keep panics from crossing
        // the FFI boundary.
        let inner = (*cursor).cursor_for_mut();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            inner.add_credit(additional_bytes)
        }));
        let res = match result {
            Ok(r) => r,
            Err(_) => std::process::abort(),
        };
        match res {
            Ok(()) => true,
            Err(e) => {
                *err_out = Box::into_raw(Box::new(line_reader_error(e)));
                false
            }
        }
    }
}

/// Set `initial_credit` (in bytes; `0` = unbounded) on the in-progress
/// query. Mirrors `ReaderQuery::initial_credit`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_query_initial_credit(
    query: *mut line_reader_query,
    credit: u64,
) {
    unsafe { mutate_query(query, |q| q.initial_credit(credit)) }
}

/// Read a `GEOHASH` value zero-extended to a `u64`, plus the column's
/// `precision_bits` (in `1..=60`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_get_geohash(
    cursor: *const line_reader_cursor,
    col_idx: size_t,
    row_idx: size_t,
    out_value: *mut u64,
    out_precision_bits: *mut u8,
    out_is_null: *mut bool,
    err_out: *mut *mut line_reader_error,
) -> bool {
    panic_guard(|| unsafe {
        let view = match get_column_view(&*cursor, col_idx, err_out) {
            Some(v) => v,
            None => return false,
        };
        let col = match view {
            ColumnView::Geohash(c) => c,
            other => {
                set_reader_err(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    format!("column {} is {:?}, not GEOHASH", col_idx, other.kind()),
                );
                return false;
            }
        };
        if !check_row(col_idx, row_idx, col.len(), err_out) {
            return false;
        }
        let is_null = col.is_null(row_idx);
        *out_is_null = is_null;
        *out_value = if is_null { 0 } else { col.value(row_idx) };
        *out_precision_bits = col.precision_bits();
        true
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// SAFETY: `cursor` must be a valid, non-null pointer to a `line_reader_cursor`
/// and `err_out` must be a valid pointer. `'a` is bounded by the lifetime of
/// the input reference, which prevents callers from extending the borrow past
/// the cursor's `current_batch`.
unsafe fn get_column_view<'a>(
    cursor: &'a line_reader_cursor,
    col_idx: size_t,
    err_out: *mut *mut line_reader_error,
) -> Option<ColumnView<'a>> {
    unsafe {
        let batch = match cursor.current_batch.as_ref() {
            Some(b) => b,
            None => {
                set_reader_err(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    "no batch loaded; call line_reader_cursor_next_batch first",
                );
                return None;
            }
        };
        if col_idx >= batch.column_count() {
            set_reader_err(
                err_out,
                ErrorCode::InvalidApiCall,
                format!(
                    "column index {} out of range (column_count={})",
                    col_idx,
                    batch.column_count()
                ),
            );
            return None;
        }
        match batch.column(col_idx) {
            Ok(v) => Some(v),
            Err(e) => {
                *err_out = Box::into_raw(Box::new(line_reader_error(e)));
                None
            }
        }
    }
}

unsafe fn check_row(
    col_idx: size_t,
    row_idx: size_t,
    row_count: size_t,
    err_out: *mut *mut line_reader_error,
) -> bool {
    if row_idx >= row_count {
        unsafe {
            set_reader_err(
                err_out,
                ErrorCode::InvalidApiCall,
                format!(
                    "row index {} out of range for column {} (row_count={})",
                    row_idx, col_idx, row_count
                ),
            );
        }
        return false;
    }
    true
}

// ---------------------------------------------------------------------------
// Tests
//
// Coverage of the in-process FFI shim: error packaging, enum mappings, the
// saturating u128→u64 helper, and `_error_free` / `_query_free` /
// `_cursor_free` NULL-idempotency. End-to-end coverage of `Reader`,
// `Cursor`, decoder dispatch, and the failover trampoline requires a live
// QuestDB or a wire-protocol fixture and lives outside this crate.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;
    use std::slice;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn make_error(code: ErrorCode, msg: &str) -> *mut line_reader_error {
        Box::into_raw(Box::new(line_reader_error(Error::new(code, msg))))
    }

    #[test]
    fn error_round_trip_and_free() {
        unsafe {
            let err = make_error(ErrorCode::InvalidApiCall, "boom");
            let got = line_reader_error_get_code(err) as u32;
            let want = line_reader_error_code::line_reader_error_invalid_api_call as u32;
            assert_eq!(got, want);
            let mut len: size_t = 0;
            let p = line_reader_error_msg(err, &mut len);
            assert_eq!(len, 4);
            let s = std::str::from_utf8(slice::from_raw_parts(p as *const u8, len)).unwrap();
            assert_eq!(s, "boom");
            line_reader_error_free(err);
        }
    }

    #[test]
    fn error_free_is_null_idempotent() {
        unsafe {
            line_reader_error_free(ptr::null_mut());
        }
    }

    #[test]
    fn query_free_is_null_idempotent() {
        unsafe {
            line_reader_query_free(ptr::null_mut());
        }
    }

    #[test]
    fn cursor_free_is_null_idempotent() {
        unsafe {
            line_reader_cursor_free(ptr::null_mut());
        }
    }

    #[test]
    fn close_is_null_idempotent() {
        unsafe {
            line_reader_close(ptr::null_mut());
        }
    }

    #[test]
    fn u128_saturating_cast() {
        assert_eq!(u128_to_u64_sat(0u128), 0u64);
        assert_eq!(u128_to_u64_sat(123u128), 123u64);
        assert_eq!(u128_to_u64_sat(u64::MAX as u128), u64::MAX);
        assert_eq!(u128_to_u64_sat(u64::MAX as u128 + 1), u64::MAX);
        assert_eq!(u128_to_u64_sat(u128::MAX), u64::MAX);
    }

    #[test]
    fn error_code_round_trips_for_every_variant() {
        let codes = [
            ErrorCode::CouldNotResolveAddr,
            ErrorCode::ConfigError,
            ErrorCode::InvalidApiCall,
            ErrorCode::SocketError,
            ErrorCode::TlsError,
            ErrorCode::HandshakeError,
            ErrorCode::AuthError,
            ErrorCode::UnsupportedServer,
            ErrorCode::RoleMismatch,
            ErrorCode::ProtocolError,
            ErrorCode::InvalidUtf8,
            ErrorCode::InvalidBind,
            ErrorCode::InvalidTimestamp,
            ErrorCode::InvalidDecimal,
            ErrorCode::ServerSchemaMismatch,
            ErrorCode::ServerParseError,
            ErrorCode::ServerInternalError,
            ErrorCode::ServerSecurityError,
            ErrorCode::LimitExceeded,
            ErrorCode::ServerLimitExceeded,
            ErrorCode::Cancelled,
        ];
        for code in codes {
            let c: line_reader_error_code = code.into();
            // Trip through the public C accessor as well.
            unsafe {
                let err = Box::into_raw(Box::new(line_reader_error(Error::new(code, ""))));
                let got = line_reader_error_get_code(err);
                assert_eq!(c as u32, got as u32, "round-trip mismatch for {:?}", code);
                line_reader_error_free(err);
            }
        }
    }

    #[test]
    fn column_kind_round_trips_for_every_variant() {
        let pairs = [
            (
                ColumnKind::Boolean,
                line_reader_column_kind::line_reader_column_kind_boolean,
            ),
            (
                ColumnKind::Byte,
                line_reader_column_kind::line_reader_column_kind_byte,
            ),
            (
                ColumnKind::Short,
                line_reader_column_kind::line_reader_column_kind_short,
            ),
            (
                ColumnKind::Int,
                line_reader_column_kind::line_reader_column_kind_int,
            ),
            (
                ColumnKind::Long,
                line_reader_column_kind::line_reader_column_kind_long,
            ),
            (
                ColumnKind::Float,
                line_reader_column_kind::line_reader_column_kind_float,
            ),
            (
                ColumnKind::Double,
                line_reader_column_kind::line_reader_column_kind_double,
            ),
            (
                ColumnKind::Symbol,
                line_reader_column_kind::line_reader_column_kind_symbol,
            ),
            (
                ColumnKind::Timestamp,
                line_reader_column_kind::line_reader_column_kind_timestamp,
            ),
            (
                ColumnKind::Date,
                line_reader_column_kind::line_reader_column_kind_date,
            ),
            (
                ColumnKind::Uuid,
                line_reader_column_kind::line_reader_column_kind_uuid,
            ),
            (
                ColumnKind::Geohash,
                line_reader_column_kind::line_reader_column_kind_geohash,
            ),
            (
                ColumnKind::Varchar,
                line_reader_column_kind::line_reader_column_kind_varchar,
            ),
            (
                ColumnKind::TimestampNanos,
                line_reader_column_kind::line_reader_column_kind_timestamp_nanos,
            ),
            (
                ColumnKind::DoubleArray,
                line_reader_column_kind::line_reader_column_kind_double_array,
            ),
            (
                ColumnKind::LongArray,
                line_reader_column_kind::line_reader_column_kind_long_array,
            ),
            (
                ColumnKind::Decimal64,
                line_reader_column_kind::line_reader_column_kind_decimal64,
            ),
            (
                ColumnKind::Decimal128,
                line_reader_column_kind::line_reader_column_kind_decimal128,
            ),
            (
                ColumnKind::Decimal256,
                line_reader_column_kind::line_reader_column_kind_decimal256,
            ),
            (
                ColumnKind::Char,
                line_reader_column_kind::line_reader_column_kind_char,
            ),
            (
                ColumnKind::Binary,
                line_reader_column_kind::line_reader_column_kind_binary,
            ),
            (
                ColumnKind::Long256,
                line_reader_column_kind::line_reader_column_kind_long256,
            ),
            (
                ColumnKind::Ipv4,
                line_reader_column_kind::line_reader_column_kind_ipv4,
            ),
        ];
        for (rust, c) in pairs {
            let mapped: line_reader_column_kind = rust.into();
            assert_eq!(mapped, c, "rust→c mapping for {:?}", rust);
            // Discriminant equals wire byte.
            assert_eq!(
                mapped as u8,
                rust.as_u8(),
                "wire-byte mismatch for {:?}",
                rust
            );
            assert_eq!(column_kind_from_c(c), rust, "c→rust mapping for {:?}", rust);
        }
    }

    #[test]
    fn from_conf_invalid_string_sets_err() {
        // A malformed config string must surface an error and return NULL,
        // not panic and not return a live handle.
        let conf = "this is not a valid config string";
        let utf8 = line_sender_utf8 {
            buf: conf.as_ptr() as *const c_char,
            len: conf.len(),
        };
        let mut err: *mut line_reader_error = ptr::null_mut();
        unsafe {
            let r = line_reader_from_conf(utf8, &mut err);
            assert!(r.is_null());
            assert!(!err.is_null());
            line_reader_error_free(err);
        }
    }

    // -- Failover trampoline shape (no live cursor) --
    //
    // Stand up a single static counter and dispatch through the same
    // closure shape that `line_reader_query_on_failover_reset` installs.
    // This pins the C-callback dispatch behaviour even though we can't
    // exercise the full `ReaderQuery::on_failover_reset` path without a
    // live Reader.
    static CB_HITS: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn test_cb(_ev: *const line_reader_failover_event, user_data: *mut c_void) {
        CB_HITS.fetch_add(1, Ordering::SeqCst);
        // The user_data round-trip must preserve the bit pattern.
        assert_eq!(user_data as usize, 0xdead_beef_usize);
    }

    /// Trampoline shape mirrored from `line_reader_query_on_failover_reset`,
    /// but parameterised over a raw `*const line_reader_failover_event`
    /// instead of `&FailoverEvent`. The real trampoline never dereferences
    /// the event reference — it forwards an opaque pointer to the C
    /// callback — so testing it via raw pointer preserves the dispatch
    /// invariant we care about while sidestepping the validity invariants
    /// of `FailoverEvent` (which would be violated by an all-zeros buffer
    /// transmuted to `&FailoverEvent`).
    fn dispatch_via_trampoline(
        cb: line_reader_failover_callback,
        user_data: *mut c_void,
        ev: *const line_reader_failover_event,
    ) {
        if let Some(c_cb) = cb {
            unsafe { c_cb(ev, user_data) };
        }
    }

    #[test]
    fn failover_trampoline_dispatches_to_c_callback() {
        CB_HITS.store(0, Ordering::SeqCst);
        let cb: line_reader_failover_callback = Some(test_cb);
        let user_data = 0xdead_beef_usize as *mut c_void;
        // The C callback receives the event as an opaque pointer; we never
        // construct a Rust `&FailoverEvent`, so a bogus address is fine.
        let ev = std::ptr::dangling::<line_reader_failover_event>();
        dispatch_via_trampoline(cb, user_data, ev);
        assert_eq!(CB_HITS.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn failover_trampoline_no_op_when_callback_is_null() {
        let cb: line_reader_failover_callback = None;
        let user_data: *mut c_void = ptr::null_mut();
        let ev: *const line_reader_failover_event = ptr::null();
        dispatch_via_trampoline(cb, user_data, ev);
        // No assertion on side-effects: the goal is to confirm dispatch
        // is a no-op when the C callback slot is empty.
    }
}
