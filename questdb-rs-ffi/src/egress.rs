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
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use libc::{c_char, c_void, size_t};

use questdb::egress::{
    BatchView, ColumnKind, ColumnView, Cursor, Error, ErrorCode, FailoverEvent, FailoverPhase,
    FailoverProgressEvent, Reader, ReaderQuery, ReaderStats, ServerInfo, ServerRole,
    SimpleNullKind, SymbolEntry, Terminal, Validity,
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
    /// Bind parameter index, count, or value rejected client-side
    /// (covers timestamp / decimal / geohash range failures too —
    /// see `ErrorCode::InvalidBind` on the Rust side).
    line_reader_error_invalid_bind = 11,
    // Values 12 and 13 are intentionally reserved (formerly
    // `invalid_timestamp` / `invalid_decimal`, removed before
    // release because no egress path ever emitted them). Do not
    // reuse without ABI co-ordination — Cython / external consumers
    // may have cached the prior numbering.
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
    /// Mid-query failover was eligible but at least one batch had already
    /// been delivered to the caller and no `on_failover_reset` callback
    /// was installed; replay would silently double-deliver rows already
    /// consumed, so the cursor was terminated instead. Install
    /// `line_reader_query_on_failover_reset` to opt in to replays, or
    /// re-execute the query from scratch.
    line_reader_error_failover_would_duplicate = 21,
    /// Streaming Arrow adapter saw a mid-stream schema change. The cursor
    /// is still usable; re-wrap with `line_reader_cursor_next_arrow_batch`
    /// after dropping any partial state to snapshot the new schema. Only
    /// emitted with the `arrow` feature enabled.
    line_reader_error_schema_drift = 22,
    /// `line_reader_cursor_next_arrow_batch` was called on a stream that
    /// terminated before any batch was produced — no schema to snapshot.
    /// Only emitted with the `arrow` feature enabled.
    line_reader_error_no_schema = 23,
    /// Arrow C Data Interface export failed (arrow-rs rejected the
    /// produced `ArrayData`'s invariants). Indicates a client bug — not
    /// user-recoverable. Only emitted with the `arrow` feature enabled.
    line_reader_error_arrow_export = 24,
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
            ErrorCode::ServerSchemaMismatch => line_reader_error_server_schema_mismatch,
            ErrorCode::ServerParseError => line_reader_error_server_parse_error,
            ErrorCode::ServerInternalError => line_reader_error_server_internal_error,
            ErrorCode::ServerSecurityError => line_reader_error_server_security_error,
            ErrorCode::LimitExceeded => line_reader_error_limit_exceeded,
            ErrorCode::ServerLimitExceeded => line_reader_error_server_limit_exceeded,
            ErrorCode::Cancelled => line_reader_error_cancelled,
            ErrorCode::FailoverWouldDuplicate => line_reader_error_failover_would_duplicate,
            ErrorCode::SchemaDrift => line_reader_error_schema_drift,
            ErrorCode::NoSchema => line_reader_error_no_schema,
            ErrorCode::ArrowExport => line_reader_error_arrow_export,
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

/// Stash a deferred error on a `line_reader_query` (first-error-wins).
/// NULL-safe: logs and drops the error when `query` is NULL since the
/// bind family has no `err_out` channel.
unsafe fn defer_query_err(query: *mut line_reader_query, fn_name: &str, err: Error) {
    if query.is_null() {
        eprintln!(
            "{fn_name}: NULL query handle; dropping error: {}",
            err.msg()
        );
        return;
    }
    unsafe {
        if (*query).deferred_err.is_none() {
            (*query).deferred_err = Some(err);
        }
    }
}

macro_rules! reader_bubble {
    ($err_out:expr, $expression:expr) => {
        reader_bubble!($err_out, $expression, false)
    };
    ($err_out:expr, $expression:expr, $sentinel:expr) => {
        match $expression {
            Ok(value) => value,
            Err(err) => {
                // Routes through `write_err_box` so a caller passing
                // `err_out == NULL` swallows the report instead of
                // SIGSEGV-ing on the diagnostic write — same NULL
                // contract every fallible entry point already
                // applies via `set_reader_err`.
                write_err_box($err_out, err);
                return $sentinel;
            }
        }
    };
}

/// Write an error envelope through `err_out`, swallowing the report
/// when the caller passed `NULL`.
///
/// The header documents `err_out` as required-non-NULL on every
/// fallible entry point, so a NULL here is technically a contract
/// violation — but the upstream callers reach this helper from their
/// own NULL-handle defensive arms (`reader.is_null()` /
/// `query_inout.is_null()` / `*query_inout.is_null()`), which exist
/// precisely so that callers misusing the API get a clean
/// `InvalidApiCall` error rather than a SIGSEGV. Without the NULL
/// check below, a caller that violated *both* the handle contract
/// AND the err_out contract would lose the defensive recovery and
/// crash on the diagnostic write itself — masking the original
/// violation. Centralising the guard here makes every call site
/// (including the 20+ in the bind-helper macros) safe by
/// construction; future call sites cannot forget it.
unsafe fn write_err_box(err_out: *mut *mut line_reader_error, err: Error) {
    if err_out.is_null() {
        return;
    }
    unsafe {
        *err_out = Box::into_raw(Box::new(line_reader_error(err)));
    }
}

unsafe fn set_reader_err(
    err_out: *mut *mut line_reader_error,
    code: ErrorCode,
    msg: impl Into<String>,
) {
    unsafe { write_err_box(err_out, Error::new(code, msg.into())) }
}

/// Panic-boundary helper for `extern "C"` entry points whose body
/// could plausibly unwind.
///
/// **Status in shipped builds: no-op.** This crate sets
/// `panic = "abort"` in both `[profile.release]` and `[profile.dev]`
/// (see `Cargo.toml`, and the panic-policy note at the top of
/// `lib.rs`). Under that policy the panic runtime aborts the process
/// at the panic site, before `catch_unwind` ever observes anything,
/// so the `Err(_) => abort()` arm here is unreachable in production
/// cdylib / staticlib builds. The wrap is effectively a thin inline
/// pass-through.
///
/// **Where the wrap is live:** cargo forces `[profile.test]` and
/// `[profile.bench]` to `panic = "unwind"` so the test harness can
/// catch panics and report failures. In those builds the guard
/// converts a panic out of `f` into a hard abort, which matches
/// production behaviour and — at the lifetime-launder / `Drop`-chain
/// sites (`_close`, `_query_free`, `_cursor_free`, `mutate_query`) —
/// prevents the harness from "recovering" past a panic that would
/// leak resources or leave a slot in an inconsistent state.
///
/// **Why keep it at all:** (a) the structural barrier survives any
/// future switch of the crate panic policy to `unwind`; (b) it
/// documents at each call site that the body could panic and we want
/// a hard abort if it does; (c) tests that exercise the
/// lifetime-launder windows get production-equivalent abort semantics
/// rather than an unwind that bypasses them. New entry points still
/// earn the wrap when their body genuinely could panic.
///
/// **Scope at the time of writing:** `_from_conf`, `_from_env`,
/// `_query_new`, `_query_execute`, `mutate_query`, `_cursor_next_batch`
/// (inline `catch_unwind` blocks, predate this helper) plus `_close`,
/// `_query_free`, `_cursor_free` (go through this wrapper because
/// their `Drop` chains run `close_in_place` and the tungstenite write
/// paths that can theoretically panic on allocator failure).
///
/// **Explicitly do NOT wrap per-column bulk accessors** —
/// `line_reader_batch_column_data`, `line_reader_batch_array_column_data`,
/// `line_reader_batch_symbol`. Those run pure pointer arithmetic and
/// integer compares against an already-decoded `ColumnView`, are
/// statically panic-free in release for any input that passes their
/// bounds checks, and are called per-column on Cython scan loops where
/// even a no-op `catch_unwind` frame shows up at the top of profiles.
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
    line_reader_column_kind_unknown = 0xFF,
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
            _ => {
                eprintln!(
                    "questdb-rs-ffi: unrecognised ColumnKind variant {k:?}; \
                     surfacing as line_reader_column_kind_unknown"
                );
                line_reader_column_kind_unknown
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
/// can coexist with shared reborrows synthesised by the non-counter
/// stat/info getters (`_server_version`, `_current_server_info`,
/// `_current_addr_*`). All references to the inner `Reader` are derived
/// from `UnsafeCell::get()`, intentionally without ever creating a
/// `&mut Reader` outside the FFI's own laundering path. The non-counter
/// getters are still bound by the one-thread-at-a-time contract, so
/// they cannot race with the laundered `&mut Reader` even in principle.
///
/// The counter getters (`_bytes_received`, `_credit_granted_total`,
/// `_read_ns`, `_decode_ns`, `_reset_timing`) go through a separate
/// `Arc<ReaderStats>` field, NOT through the cell. That decouples the
/// counter accesses from the Reader's borrow stack — a monitoring
/// thread reading the counters never touches the `UnsafeCell`, so the
/// laundered `&mut Reader` inside an in-flight query/cursor is
/// unaffected (no `&Reader` synthesised, no Stacked-Borrows pop). The
/// `Arc` is cloned once at handle construction; both the FFI and the
/// inner `Reader` hold strong references to the same counters.
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
///
/// Field `.2` is a clone of the inner `Reader::stats()` `Arc`. Stat
/// getters read from here and never touch `.0`, so a monitoring
/// thread firing a stat getter while another thread is driving a
/// cursor cannot disturb the cursor's laundered `&mut Reader`.
pub struct line_reader(UnsafeCell<Reader>, AtomicBool, Arc<ReaderStats>);

/// Construct a reader from a QuestDB config string.
///
/// The config string follows the same format documented in the Rust
/// `ReaderConfig::from_conf` API (e.g. `"ws::addr=localhost:9000;"`).
/// On success returns a non-NULL handle that must be released with
/// `line_reader_close`. On failure returns NULL and sets `*err_out`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_from_conf(
    config: line_sender_utf8,
    err_out: *mut *mut line_reader_error,
) -> *mut line_reader {
    // Wrap the entire body to localize any unwind from allocator
    // panics (`Box::into_raw`, `set_reader_err`, or any future
    // fallible step). No-op in shipped cdylib / staticlib builds
    // under `panic = abort`; active in test builds. See `panic_guard`
    // docstring for the full rationale. Matches the wrap used
    // elsewhere in this file (`mutate_query`, `_query_execute`,
    // `_cursor_next_batch`, etc.).
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        // Re-validate UTF-8 (see `validated_utf8` for the rationale).
        let conf = match validated_utf8(&config) {
            Ok(s) => s,
            Err(e) => {
                write_err_box(err_out, e);
                return ptr::null_mut();
            }
        };
        let reader_result = Reader::from_conf(conf);
        let reader = reader_bubble!(err_out, reader_result, ptr::null_mut());
        let stats = Arc::clone(reader.stats());
        Box::into_raw(Box::new(line_reader(
            UnsafeCell::new(reader),
            AtomicBool::new(false),
            stats,
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
        let stats = Arc::clone(reader.stats());
        Box::into_raw(Box::new(line_reader(
            UnsafeCell::new(reader),
            AtomicBool::new(false),
            stats,
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
            // Project to the stats Arc via `addr_of!` so we don't form
            // a `&line_reader` reborrow that would alias the in-flight
            // `&mut Reader` held by the live query/cursor (same pattern
            // as the stat getters below).
            let stats_ptr = std::ptr::addr_of!((*reader).2);
            let bytes_in_flight = (&*stats_ptr).bytes_received.load(Ordering::Relaxed);
            eprintln!(
                "line_reader_close: a query or cursor is still live on this \
                 reader. The reader has been LEAKED (TCP socket + TLS session + \
                 ~{bytes_in_flight} bytes of in-flight buffers + up to the \
                 symbol-dict heap cap) to avoid use-after-free. Close the \
                 cursor / free the query before closing the reader. This is \
                 a contract violation — see the line_reader_close docstring."
            );
            return;
        }
        // The drop chain runs Reader -> Option<WsTransport> -> Drop.
        // Wrapped in `panic_guard` so a panic out of any allocator /
        // transport `Drop` is localized in test builds (and would
        // localize if the crate ever moved off `panic = abort`).
        // No-op in shipped builds; see `panic_guard` docstring.
        drop(Box::from_raw(reader));
    })
}

/// Peek at the reader's active-query flag.
///
/// Returns `1` when a `line_reader_query` or `line_reader_cursor` produced by
/// this reader is still live, `0` otherwise. Returns `0` for a NULL handle.
///
/// Intended for higher-level bindings (e.g. the C++ wrapper) that want to
/// surface "close while a cursor is live" as a programmable error before it
/// silently triggers the leak-on-active branch in `line_reader_close`.
///
/// TOCTOU note: a concurrent `_query_new` / `_query_free` from another thread
/// can flip the flag between this peek and the next call. The C contract
/// already forbids racing `_close` against `_query_new` on the same reader,
/// so callers that observe the flag under that contract get a stable answer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_has_active_query(reader: *const line_reader) -> u8 {
    unsafe {
        if reader.is_null() {
            return 0;
        }
        // Project to the `AtomicBool` field via `addr_of!` so we never
        // synthesise an intermediate `&line_reader` reborrow — doing so
        // would cover the `UnsafeCell<Reader>` field and disturb the
        // laundered `&mut Reader` held by an in-flight query/cursor under
        // Stacked Borrows. Same pattern as the stat getters below.
        let active: &AtomicBool = &*std::ptr::addr_of!((*reader).1);
        // `Acquire` pairs with the `AcqRel` flip in `_query_new` / the
        // `Release` clear in `_query_free` / `_cursor_free`, so observers
        // see a consistent state under the C contract's
        // happens-before edge.
        active.load(Ordering::Acquire) as u8
    }
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
        // Project to the `Arc<ReaderStats>` field via `addr_of!` so we
        // never synthesise an intermediate `&line_reader` reborrow —
        // doing so would cover the `UnsafeCell<Reader>` field and
        // disturb the laundered `&mut Reader` held by any in-flight
        // `ReaderQuery` / `Cursor` under Stacked Borrows. The explicit
        // `&Arc<ReaderStats>` borrow below covers only the Arc field,
        // which lives at a distinct offset and is unrelated to the cell.
        let stats: &Arc<ReaderStats> = &*std::ptr::addr_of!((*reader).2);
        stats.bytes_received.load(Ordering::Relaxed)
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
        let stats: &Arc<ReaderStats> = &*std::ptr::addr_of!((*reader).2);
        stats.credit_granted_total.load(Ordering::Relaxed)
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
        let stats: &Arc<ReaderStats> = &*std::ptr::addr_of!((*reader).2);
        stats.read_ns.load(Ordering::Relaxed)
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
        let stats: &Arc<ReaderStats> = &*std::ptr::addr_of!((*reader).2);
        stats.decode_ns.load(Ordering::Relaxed)
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
        let stats: &Arc<ReaderStats> = &*std::ptr::addr_of!((*reader).2);
        stats.read_ns.store(0, Ordering::Relaxed);
        stats.decode_ns.store(0, Ordering::Relaxed);
    }
}

/// `true` while a `line_reader_query` / `line_reader_cursor` produced by
/// this reader holds a lifetime-laundered `&mut Reader` taken out of the
/// `UnsafeCell`. The connection-metadata getters consult this before
/// synthesising a shared `&Reader`, which would otherwise alias that
/// `&mut` — aliasing UB the `UnsafeCell` does not sanction.
#[inline]
unsafe fn reader_active(reader: *const line_reader) -> bool {
    // `addr_of!` avoids a `&line_reader` reborrow over the cell — see
    // `line_reader_has_active_query`.
    let active: &AtomicBool = unsafe { &*std::ptr::addr_of!((*reader).1) };
    active.load(Ordering::Acquire)
}

/// Get the negotiated QWP server version (1..=`HIGHEST_KNOWN_VERSION`).
///
/// Returns `false` and sets `*err_out` on failure: the connection is not
/// established yet (no `SERVER_INFO` received), the `reader` handle is
/// NULL, or a `line_reader_query` / `line_reader_cursor` produced by this
/// reader is still live — all surfaced as `InvalidApiCall`. The
/// query/cursor rejection prevents the synthesised `&Reader` from aliasing
/// the laundered `&mut Reader` that handle holds.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_server_version(
    reader: *const line_reader,
    out_version: *mut u8,
    err_out: *mut *mut line_reader_error,
) -> bool {
    unsafe {
        if out_version.is_null() {
            // Defensive: a NULL out-param is a contract violation. Report
            // it via `err_out` (if non-NULL) rather than dereferencing.
            if !err_out.is_null() {
                set_reader_err(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    "line_reader_server_version called with NULL out_version",
                );
            }
            return false;
        }
        if reader.is_null() {
            if !err_out.is_null() {
                set_reader_err(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    "line_reader_server_version called with NULL reader handle",
                );
            }
            return false;
        }
        if reader_active(reader) {
            if !err_out.is_null() {
                set_reader_err(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    "line_reader_server_version called while a query or \
                     cursor produced by this reader is still live; release \
                     it before reading connection metadata",
                );
            }
            return false;
        }
        match (*(*reader).0.get()).server_version() {
            Ok(v) => {
                *out_version = v;
                true
            }
            Err(e) => {
                write_err_box(err_out, e);
                false
            }
        }
    }
}

/// Borrowed `SERVER_INFO` of the currently connected endpoint, or NULL when
/// the server hasn't sent one (v1 protocol). The returned pointer is
/// invalidated by any subsequent reader operation that may reconnect or
/// receive a new `SERVER_INFO` (`line_reader_query_execute`,
/// `line_reader_cursor_next_batch`, `line_reader_close`).
///
/// Returns NULL for a NULL handle, and also NULL while a `line_reader_query`
/// / `line_reader_cursor` produced by this reader is still live — reading
/// the metadata then would alias that handle's laundered `&mut Reader`.
/// Release the query/cursor first to read connection metadata.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_current_server_info(
    reader: *const line_reader,
) -> *const line_reader_server_info {
    unsafe {
        if reader.is_null() {
            return ptr::null();
        }
        if reader_active(reader) {
            return ptr::null();
        }
        match (*(*reader).0.get()).server_info() {
            Some(si) => si as *const ServerInfo as *const line_reader_server_info,
            None => ptr::null(),
        }
    }
}

/// Host of the endpoint the reader is currently connected to. The buffer
/// is borrowed; valid until any reader operation that may reconnect.
///
/// Writes an empty `(NULL, 0)` pair for a NULL handle, and also while a
/// `line_reader_query` / `line_reader_cursor` produced by this reader is
/// still live — reading the metadata then would alias that handle's
/// laundered `&mut Reader`. Release the query/cursor first.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_current_addr_host(
    reader: *const line_reader,
    out_buf: *mut *const c_char,
    out_len: *mut size_t,
) {
    unsafe {
        // Defensive: a NULL out-param is a contract violation. Skip the
        // write rather than dereferencing NULL.
        if out_buf.is_null() || out_len.is_null() {
            return;
        }
        if reader.is_null() {
            *out_buf = ptr::null();
            *out_len = 0;
            return;
        }
        if reader_active(reader) {
            *out_buf = ptr::null();
            *out_len = 0;
            return;
        }
        let ep = (*(*reader).0.get()).current_addr();
        *out_buf = ep.host.as_ptr() as *const c_char;
        *out_len = ep.host.len();
    }
}

/// Port of the endpoint the reader is currently connected to.
///
/// Returns `0` for a NULL handle, and also `0` while a `line_reader_query`
/// / `line_reader_cursor` produced by this reader is still live — reading
/// the metadata then would alias that handle's laundered `&mut Reader`.
/// Release the query/cursor first.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_current_addr_port(reader: *const line_reader) -> u16 {
    unsafe {
        if reader.is_null() {
            return 0;
        }
        if reader_active(reader) {
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
        // Defensive: a NULL out-param is a contract violation. Skip the
        // write rather than dereferencing NULL.
        if out_buf.is_null() || out_len.is_null() {
            return;
        }
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
        // Defensive: a NULL out-param is a contract violation. Skip the
        // write rather than dereferencing NULL.
        if out_buf.is_null() || out_len.is_null() {
            return;
        }
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
        // Defensive: a NULL out-param is a contract violation. Skip the
        // write rather than dereferencing NULL.
        if out_buf.is_null() || out_len.is_null() {
            return;
        }
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
        // Defensive: a NULL out-param is a contract violation. Skip the
        // write rather than dereferencing NULL.
        if out_buf.is_null() || out_len.is_null() {
            return;
        }
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
        // Defensive: a NULL out-param is a contract violation. Skip the
        // write rather than dereferencing NULL.
        if out_buf.is_null() || out_len.is_null() {
            return;
        }
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
                // path may panic. The `catch_unwind` + abort below is a
                // no-op under this crate's `panic = abort` policy (see
                // `panic_guard` docstring) and active in test builds; the
                // shipped binary aborts at the panic site directly. C++
                // users get the unwind-into-C protection from the wrapper's
                // noexcept trampoline.
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
// FailoverProgressEvent + on_failover_progress callback
// ---------------------------------------------------------------------------

/// Phase discriminant on `line_reader_failover_progress_event`.
///
/// Numeric values match the Rust [`FailoverPhase`] discriminants and
/// are append-only across releases — inserting a new variant in the
/// middle would silently renumber later ones across recompiles,
/// breaking ABI for shared-library consumers.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
#[allow(clippy::enum_variant_names)]
pub enum line_reader_failover_phase {
    line_reader_failover_phase_disconnected = 0,
    line_reader_failover_phase_retrying = 1,
    line_reader_failover_phase_reset = 2,
    line_reader_failover_phase_gave_up = 3,
    /// Sentinel for variants the FFI build doesn't know.
    line_reader_failover_phase_unknown = 0xFF,
}

impl From<FailoverPhase> for line_reader_failover_phase {
    fn from(p: FailoverPhase) -> Self {
        match p {
            FailoverPhase::Disconnected => {
                line_reader_failover_phase::line_reader_failover_phase_disconnected
            }
            FailoverPhase::Retrying => {
                line_reader_failover_phase::line_reader_failover_phase_retrying
            }
            FailoverPhase::Reset => line_reader_failover_phase::line_reader_failover_phase_reset,
            FailoverPhase::GaveUp => line_reader_failover_phase::line_reader_failover_phase_gave_up,
            _ => {
                eprintln!(
                    "questdb-rs-ffi: unrecognised FailoverPhase variant {p:?}; \
                     surfacing as line_reader_failover_phase_unknown"
                );
                line_reader_failover_phase::line_reader_failover_phase_unknown
            }
        }
    }
}

/// Opaque borrowed handle to a failover-progress event. The pointer is
/// valid only for the duration of the user's progress callback
/// invocation.
#[repr(C)]
pub struct line_reader_failover_progress_event {
    _private: [u8; 0],
}

/// User callback fired at every phase of a mid-query failover
/// lifecycle. The `event` pointer is valid only for the duration of
/// the call.
pub type line_reader_failover_progress_callback = Option<
    unsafe extern "C" fn(event: *const line_reader_failover_progress_event, user_data: *mut c_void),
>;

/// NULL-safe borrow of the opaque `FailoverProgressEvent`. Returns
/// `None` when the caller passes a NULL pointer.
unsafe fn pev_ref<'a>(
    ev: *const line_reader_failover_progress_event,
) -> Option<&'a FailoverProgressEvent> {
    if ev.is_null() {
        None
    } else {
        Some(unsafe { &*(ev as *const FailoverProgressEvent) })
    }
}

/// Phase discriminant. NULL-safe: returns
/// `line_reader_failover_phase_disconnected` (the zero variant) when
/// `ev` is NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_failover_progress_event_phase(
    ev: *const line_reader_failover_progress_event,
) -> line_reader_failover_phase {
    unsafe {
        match pev_ref(ev) {
            Some(e) => e.phase.into(),
            None => line_reader_failover_phase::line_reader_failover_phase_disconnected,
        }
    }
}

/// NULL-safe: writes empty `(NULL, 0)` when `ev` is NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_failover_progress_event_failed_host(
    ev: *const line_reader_failover_progress_event,
    out_buf: *mut *const c_char,
    out_len: *mut size_t,
) {
    unsafe {
        if out_buf.is_null() || out_len.is_null() {
            return;
        }
        match pev_ref(ev) {
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
pub unsafe extern "C" fn line_reader_failover_progress_event_failed_port(
    ev: *const line_reader_failover_progress_event,
) -> u16 {
    unsafe { pev_ref(ev).map(|e| e.failed_addr.port).unwrap_or(0) }
}

/// New-endpoint host (Reset phase only). Writes `(NULL, 0)` outside
/// Reset, or when `ev` is NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_failover_progress_event_new_host(
    ev: *const line_reader_failover_progress_event,
    out_buf: *mut *const c_char,
    out_len: *mut size_t,
) {
    unsafe {
        if out_buf.is_null() || out_len.is_null() {
            return;
        }
        match pev_ref(ev).and_then(|e| e.new_addr.as_ref()) {
            Some(addr) => {
                let h = addr.host.as_str();
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

/// New-endpoint port (Reset phase only). Returns `0` outside Reset, or
/// when `ev` is NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_failover_progress_event_new_port(
    ev: *const line_reader_failover_progress_event,
) -> u16 {
    unsafe {
        pev_ref(ev)
            .and_then(|e| e.new_addr.as_ref())
            .map(|a| a.port)
            .unwrap_or(0)
    }
}

/// New `request_id` (Reset phase only). Returns `true` and writes the
/// id to `*out_request_id` on Reset; returns `false` and writes `0` in
/// every other phase or when `ev`/`out_request_id` is NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_failover_progress_event_new_request_id(
    ev: *const line_reader_failover_progress_event,
    out_request_id: *mut i64,
) -> bool {
    unsafe {
        if out_request_id.is_null() {
            return false;
        }
        match pev_ref(ev).and_then(|e| e.new_request_id) {
            Some(rid) => {
                *out_request_id = rid;
                true
            }
            None => {
                *out_request_id = 0;
                false
            }
        }
    }
}

/// 1-based attempt counter. See the Rust
/// [`FailoverProgressEvent::attempt`] docs for per-phase semantics.
/// NULL-safe: returns 0 when `ev` is NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_failover_progress_event_attempt(
    ev: *const line_reader_failover_progress_event,
) -> u32 {
    unsafe { pev_ref(ev).map(|e| e.attempt).unwrap_or(0) }
}

/// Trigger error code (the cause-of-death of the previous connection).
/// NULL-safe: returns `line_reader_error_invalid_api_call` when `ev`
/// is NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_failover_progress_event_trigger_code(
    ev: *const line_reader_failover_progress_event,
) -> line_reader_error_code {
    unsafe {
        match pev_ref(ev) {
            Some(e) => e.trigger.code().into(),
            None => line_reader_error_code::line_reader_error_invalid_api_call,
        }
    }
}

/// Trigger error message (UTF-8). NULL-safe: writes `(NULL, 0)` when
/// `ev` is NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_failover_progress_event_trigger_msg(
    ev: *const line_reader_failover_progress_event,
    out_buf: *mut *const c_char,
    out_len: *mut size_t,
) {
    unsafe {
        if out_buf.is_null() || out_len.is_null() {
            return;
        }
        match pev_ref(ev) {
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

/// Wall-clock nanoseconds since the disconnect was observed.
/// Saturates at `u64::MAX`. NULL-safe: returns 0 when `ev` is NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_failover_progress_event_elapsed_ns(
    ev: *const line_reader_failover_progress_event,
) -> u64 {
    unsafe {
        pev_ref(ev)
            .map(|e| u128_to_u64_sat(e.elapsed.as_nanos()))
            .unwrap_or(0)
    }
}

/// `SERVER_INFO` for the new endpoint, or NULL outside the Reset phase
/// / on QWP v1 servers. Borrowed for the duration of the call.
/// NULL-safe: returns NULL when `ev` is NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_failover_progress_event_server_info(
    ev: *const line_reader_failover_progress_event,
) -> *const line_reader_server_info {
    unsafe {
        match pev_ref(ev).and_then(|e| e.new_server_info.as_ref()) {
            Some(si) => si as *const ServerInfo as *const line_reader_server_info,
            None => ptr::null(),
        }
    }
}

/// Final error code (GaveUp phase only). Returns `true` and writes the
/// code to `*out_code` on GaveUp; returns `false` and writes
/// `line_reader_error_invalid_api_call` outside GaveUp or when `ev`/
/// `out_code` is NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_failover_progress_event_final_error_code(
    ev: *const line_reader_failover_progress_event,
    out_code: *mut line_reader_error_code,
) -> bool {
    unsafe {
        if out_code.is_null() {
            return false;
        }
        match pev_ref(ev).and_then(|e| e.final_error.as_ref()) {
            Some(e) => {
                *out_code = e.code().into();
                true
            }
            None => {
                *out_code = line_reader_error_code::line_reader_error_invalid_api_call;
                false
            }
        }
    }
}

/// Final error message (GaveUp phase only). Returns `true` and writes
/// the borrowed UTF-8 message on GaveUp; returns `false` and writes
/// `(NULL, 0)` outside GaveUp or when `ev` is NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_failover_progress_event_final_error_msg(
    ev: *const line_reader_failover_progress_event,
    out_buf: *mut *const c_char,
    out_len: *mut size_t,
) -> bool {
    unsafe {
        if out_buf.is_null() || out_len.is_null() {
            return false;
        }
        match pev_ref(ev).and_then(|e| e.final_error.as_ref()) {
            Some(err) => {
                let m = err.msg();
                *out_buf = m.as_ptr() as *const c_char;
                *out_len = m.len();
                true
            }
            None => {
                *out_buf = ptr::null();
                *out_len = 0;
                false
            }
        }
    }
}

/// Install a failover-progress callback on the query. Replaces any
/// previously installed progress callback. `user_data` is opaque to
/// the library; pass NULL if not needed.
///
/// The callback fires at every phase of a mid-query failover — see
/// `line_reader_failover_phase`. Installing this callback also opts
/// the cursor in to "I will handle replay-after-data-delivered
/// correctly," the same way `line_reader_query_on_failover_reset`
/// does — either being installed clears the silent-duplicate guard.
///
/// Reentrancy contract — same as `line_reader_failover_callback`. In
/// short: the trampoline runs synchronously inside the in-flight
/// cursor op, so the user callback MUST NOT touch the originating
/// reader, query, or cursor (including read-only stat getters — they
/// would alias the upstream `&mut Reader` borrow), and MUST NOT throw
/// / longjmp / unwind across the C boundary. The trampoline wraps the
/// callback in `catch_unwind` and aborts on escape; under this crate's
/// `panic = abort` policy that wrap is a no-op in shipped builds and
/// active only in tests (see [`panic_guard`] docstring).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_query_on_failover_progress(
    query: *mut line_reader_query,
    callback: line_reader_failover_progress_callback,
    user_data: *mut c_void,
) {
    unsafe {
        let trampoline = move |event: &FailoverProgressEvent| {
            if let Some(c_cb) = callback {
                let opaque = event as *const FailoverProgressEvent
                    as *const line_reader_failover_progress_event;
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    c_cb(opaque, user_data)
                }));
                if result.is_err() {
                    std::process::abort();
                }
            }
        };
        mutate_query(query, |q| q.on_failover_progress(trampoline));
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
pub unsafe extern "C" fn line_reader_prepare(
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
                "line_reader_prepare: NULL reader handle",
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
                write_err_box(err_out, e);
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
        // Catch any unwind out of `r.prepare(sql_str)` AND the
        // wrapper allocation that publishes the result, then abort.
        // No-op under this crate's `panic = abort` policy (see
        // `panic_guard` docstring); active in test builds.
        // Upstream `Reader::prepare` is in practice infallible (it
        // just builds a small `ReaderQuery` struct) and the default
        // Rust allocator aborts on OOM rather than unwinds — but if
        // the policy ever flipped to `unwind`, or a test panic is
        // injected here, an escape would (a) leave the `active` flag
        // stuck `true` (the early-claim of the flag would not be
        // undone) and (b) violate the FFI no-unwind contract.
        // Including the `Box::into_raw(Box::new(...))` inside the
        // guarded closure closes the allocation gap left by the
        // previous narrower `catch_unwind` that wrapped only the
        // upstream call.
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
            let q = r.prepare(sql_str);
            let q_static: ReaderQuery<'static> = std::mem::transmute(q);
            Box::into_raw(Box::new(line_reader_query {
                inner: ManuallyDrop::new(q_static),
                reader,
                deferred_err: None,
            }))
        }));
        match result {
            Ok(p) => p,
            Err(_) => std::process::abort(),
        }
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
            write_err_box(err_out, e);
            return ptr::null_mut();
        }

        // Catch any unwind out of `q.execute()` AND the wrapper
        // allocations that publish either the cursor handle or the
        // error envelope. No-op under this crate's `panic = abort`
        // policy (see `panic_guard` docstring); active in test
        // builds. `q` was moved out of the now-dead
        // `Box<line_reader_query>` via `ManuallyDrop::take`, so if
        // the policy ever flipped to `unwind`, an escape would (a)
        // leave the reader's `active` flag stuck `true` on the
        // success-arm path (no cursor produced, no Err arm taken to
        // clear it) and (b) violate the FFI no-unwind contract.
        // Including both the success-side
        // `Box::into_raw(Box::new(line_reader_cursor { .. }))` and
        // the error-side
        // `Box::into_raw(Box::new(line_reader_error(..)))` inside
        // the guarded closure closes the two allocation gaps left by
        // the previous narrower `catch_unwind` that wrapped only
        // `q.execute()`.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            match q.execute() {
                Ok(cursor) => {
                    // Active flag stays set; ownership transfers to the cursor.
                    let cursor_static: Cursor<'static> = std::mem::transmute(cursor);
                    Box::into_raw(Box::new(line_reader_cursor {
                        cursor: ManuallyDrop::new(cursor_static),
                        current_batch: None,
                        #[cfg(feature = "arrow")]
                        arrow_schema_pin: None,
                        reader,
                    }))
                }
                Err(e) => {
                    // Query gone, no cursor produced — release the active flag.
                    if !reader.is_null() {
                        (*reader).1.store(false, Ordering::Release);
                    }
                    write_err_box(err_out, e);
                    ptr::null_mut()
                }
            }
        }));
        match result {
            Ok(p) => p,
            Err(_) => std::process::abort(),
        }
    }
}

/// Convenience: prepare + execute in one call, for SQL with no binds.
/// Equivalent to `line_reader_prepare` followed immediately by
/// `line_reader_query_execute` — no query handle is exposed to the
/// caller. Returns NULL and sets `*err_out` on failure (including NULL
/// reader, invalid UTF-8 in `sql`, another query/cursor already in
/// flight, or server-side execution failure).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_execute(
    reader: *mut line_reader,
    sql: line_sender_utf8,
    err_out: *mut *mut line_reader_error,
) -> *mut line_reader_cursor {
    unsafe {
        if reader.is_null() {
            set_reader_err(
                err_out,
                ErrorCode::InvalidApiCall,
                "line_reader_execute: NULL reader handle",
            );
            return ptr::null_mut();
        }
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
        let sql_str = match validated_utf8(&sql) {
            Ok(s) => s,
            Err(e) => {
                (*reader).1.store(false, Ordering::Release);
                write_err_box(err_out, e);
                return ptr::null_mut();
            }
        };
        let r: &mut Reader = &mut *(*reader).0.get();
        // Single guarded closure covers `r.execute(...)`, the lifetime
        // launder, and both success/error Box allocations — same
        // pattern as `_prepare` and `_query_execute`. No-op under this
        // crate's `panic = abort` policy (see `panic_guard`
        // docstring); active in test builds. Active flag is kept
        // claimed on success (transferred to the cursor) and released
        // on the error arm.
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match r.execute(sql_str) {
                Ok(cursor) => {
                    let cursor_static: Cursor<'static> = std::mem::transmute(cursor);
                    Box::into_raw(Box::new(line_reader_cursor {
                        cursor: ManuallyDrop::new(cursor_static),
                        current_batch: None,
                        #[cfg(feature = "arrow")]
                        arrow_schema_pin: None,
                        reader,
                    }))
                }
                Err(e) => {
                    (*reader).1.store(false, Ordering::Release);
                    write_err_box(err_out, e);
                    ptr::null_mut()
                }
            }));
        match result {
            Ok(p) => p,
            Err(_) => std::process::abort(),
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
/// allocator aborts rather than unwinds. The `catch_unwind` here is a
/// no-op under the crate's `panic = abort` policy (see [`panic_guard`])
/// and is kept for two reasons: (a) in test builds, where cargo forces
/// `panic = unwind`, it converts any unwind from `f` between
/// `ptr::read(inner_ptr)` and `ptr::write` — the window during which the
/// slot is logically uninitialised — into a hard abort, instead of
/// letting the test harness recover and leak the stale value into
/// `_query_free`'s drop; (b) it preserves the structural barrier if the
/// crate ever moves off `panic = abort`. The line_sender FFI does not
/// wrap its bind sites; the extra wrap here is justified by the
/// lifetime-laundered `ReaderQuery<'static>` surface area.
unsafe fn mutate_query<F>(query: *mut line_reader_query, f: F)
where
    F: FnOnce(ReaderQuery<'static>) -> ReaderQuery<'static>,
{
    unsafe {
        if query.is_null() {
            eprintln!("line_reader_query_bind_*: NULL query handle; bind dropped");
            return;
        }
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
        if query.is_null() {
            eprintln!("line_reader_query_bind_varchar: NULL query handle; bind dropped");
            return;
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
/// `len` is 0 (empty value). A NULL `buf` with non-zero `len`, or a
/// `len` exceeding `isize::MAX`, stashes a deferred `InvalidBind` error
/// on the query that surfaces from `_query_execute`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_query_bind_binary(
    query: *mut line_reader_query,
    buf: *const u8,
    len: size_t,
) {
    unsafe {
        if buf.is_null() && len != 0 {
            defer_query_err(
                query,
                "line_reader_query_bind_binary",
                Error::new(
                    ErrorCode::InvalidBind,
                    format!("buf is NULL but len is {len}"),
                ),
            );
            return;
        }
        // `slice::from_raw_parts` is UB for `len > isize::MAX`, and
        // `Vec::to_vec` on such a length would trigger an allocator
        // abort under panic=abort. Reject up front.
        if len > isize::MAX as usize {
            defer_query_err(
                query,
                "line_reader_query_bind_binary",
                Error::new(
                    ErrorCode::InvalidBind,
                    format!("len {len} exceeds isize::MAX"),
                ),
            );
            return;
        }
        let bytes: Vec<u8> = if len == 0 {
            Vec::new()
        } else {
            slice::from_raw_parts(buf, len).to_vec()
        };
        mutate_query(query, |q| q.bind_binary(bytes));
    }
}

/// Bind a 16-byte UUID value (raw bytes). `value` MUST be non-NULL and
/// point to at least 16 readable bytes; passing a smaller buffer is a
/// buffer over-read (undefined behaviour) — exactly 16 bytes are read
/// unconditionally. A NULL `value` stashes a deferred `InvalidBind`
/// error on the query that surfaces from `_query_execute`. Use
/// `line_reader_query_bind_null` with `line_reader_column_kind_uuid` to
/// bind SQL NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_query_bind_uuid(
    query: *mut line_reader_query,
    value: *const u8,
) {
    unsafe {
        if value.is_null() {
            defer_query_err(
                query,
                "line_reader_query_bind_uuid",
                Error::new(
                    ErrorCode::InvalidBind,
                    "value is NULL; use _bind_null(_, column_kind_uuid) for SQL NULL",
                ),
            );
            return;
        }
        let mut buf = [0u8; 16];
        buf.copy_from_slice(slice::from_raw_parts(value, 16));
        mutate_query(query, |q| q.bind_uuid(buf));
    }
}

/// Bind a 32-byte LONG256 value (raw little-endian bytes). `value` MUST be
/// non-NULL and point to at least 32 readable bytes; passing a smaller
/// buffer is a buffer over-read (undefined behaviour) — exactly 32 bytes
/// are read unconditionally. A NULL `value` stashes a deferred
/// `InvalidBind` error on the query. Use `line_reader_query_bind_null`
/// with `line_reader_column_kind_long256` to bind SQL NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_query_bind_long256(
    query: *mut line_reader_query,
    value: *const u8,
) {
    unsafe {
        if value.is_null() {
            defer_query_err(
                query,
                "line_reader_query_bind_long256",
                Error::new(
                    ErrorCode::InvalidBind,
                    "value is NULL; use _bind_null(_, column_kind_long256) for SQL NULL",
                ),
            );
            return;
        }
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

/// Bind a DECIMAL128 mantissa as two limbs of the standard two's-complement
/// `i128` representation, plus the column's `scale`.
///
/// `mantissa_lo` is the unsigned low 64 bits; `mantissa_hi` is the **signed**
/// upper 64 bits. The high limb is `i64` so the sign extends naturally into
/// the i128 — `mantissa_lo = UINT64_MAX, mantissa_hi = -1` reconstructs `i128 = -1`.
/// Passing the high limb as a zero-extended `u64` corrupts negative values;
/// always cast through `int64_t` on the caller side.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_query_bind_decimal128(
    query: *mut line_reader_query,
    mantissa_lo: u64,
    mantissa_hi: i64,
    scale: i8,
) {
    unsafe {
        let lo = mantissa_lo as u128;
        let hi = (mantissa_hi as i128) as u128;
        let combined = (hi << 64) | lo;
        let value = combined as i128;
        mutate_query(query, |q| q.bind_decimal128(value, scale));
    }
}

/// Bind a DECIMAL256 value as 32 little-endian raw bytes plus column scale.
/// `value` MUST be non-NULL and point to at least 32 readable bytes;
/// passing a smaller buffer is a buffer over-read (undefined behaviour) —
/// exactly 32 bytes are read unconditionally. A NULL `value` stashes a
/// deferred `InvalidBind` error on the query. Use
/// `line_reader_query_bind_null_decimal256` to bind SQL NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_query_bind_decimal256(
    query: *mut line_reader_query,
    value: *const u8,
    scale: i8,
) {
    unsafe {
        if value.is_null() {
            defer_query_err(
                query,
                "line_reader_query_bind_decimal256",
                Error::new(
                    ErrorCode::InvalidBind,
                    "value is NULL; use _bind_null_decimal256 for SQL NULL",
                ),
            );
            return;
        }
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
///
/// `kind` carries a `line_reader_column_kind_*` discriminant as a raw
/// integer (not the typed enum) so a buggy caller passing an out-of-range
/// value surfaces as a deferred `InvalidBind` error rather than triggering
/// undefined behaviour at the FFI boundary.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_query_bind_null(query: *mut line_reader_query, kind: u32) {
    unsafe {
        if query.is_null() {
            eprintln!("line_reader_query_bind_null: NULL query handle; bind dropped");
            return;
        }
        let k = match column_kind_from_c(kind) {
            Some(k) => k,
            None => {
                if (*query).deferred_err.is_none() {
                    let msg = if kind
                        == line_reader_column_kind::line_reader_column_kind_unknown as u32
                    {
                        "line_reader_query_bind_null: kind is the \
                         line_reader_column_kind_unknown sentinel; pass a \
                         concrete column kind"
                            .to_string()
                    } else {
                        format!(
                            "line_reader_query_bind_null: kind 0x{kind:02X} is not a \
                             recognised line_reader_column_kind discriminant"
                        )
                    };
                    (*query).deferred_err = Some(Error::new(ErrorCode::InvalidBind, msg));
                }
                return;
            }
        };
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

/// Convert a raw C-side `line_reader_column_kind` discriminant into a
/// `ColumnKind`. Accepting `u32` rather than the enum keeps the FFI
/// boundary sound when a C caller hands us a bit pattern outside the
/// declared discriminants (passing such a value as `line_reader_column_kind`
/// is undefined behaviour per the Rust reference). The wire bytes match
/// `ColumnKind::as_u8`, so we delegate to `ColumnKind::from_u8`; both the
/// documented `_unknown` (0xFF) sentinel and arbitrary garbage map to
/// `None`.
fn column_kind_from_c(k: u32) -> Option<ColumnKind> {
    let byte = u8::try_from(k).ok()?;
    ColumnKind::from_u8(byte).ok()
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
    /// Pins the first Arrow batch's schema for mid-stream drift detection.
    #[cfg(feature = "arrow")]
    arrow_schema_pin: Option<arrow::datatypes::SchemaRef>,
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
    ///
    /// Also clears any Arrow schema pin — switching back from the raw
    /// `BatchView` path to `_next_arrow_batch` should re-snapshot the
    /// schema, not compare against a stale one from before the detour.
    fn cursor_for_mut(&mut self) -> &mut Cursor<'static> {
        self.current_batch = None;
        debug_assert!(self.current_batch.is_none());
        #[cfg(feature = "arrow")]
        {
            self.arrow_schema_pin = None;
        }
        &mut self.cursor
    }

    /// Like `cursor_for_mut` but preserves any Arrow schema pin. For
    /// auxiliary cursor ops (`cancel`, `add_credit`) that do not advance
    /// the stream and therefore must not lose the drift-detection
    /// snapshot established by a prior `_next_arrow_batch`.
    fn cursor_for_aux(&mut self) -> &mut Cursor<'static> {
        self.current_batch = None;
        debug_assert!(self.current_batch.is_none());
        &mut self.cursor
    }
}

/// Free the cursor and release its resources. Drops any in-flight
/// batch view; if the cursor was abandoned mid-stream, sends a
/// best-effort CANCEL frame (bounded by the WS write timeout, errors
/// swallowed) and then tears down the underlying WebSocket transport
/// (bounded by ~200ms) so the server promptly stops streaming and
/// releases request-scoped state. On a fully-drained cursor the
/// reader's connection is preserved for the next query and no CANCEL
/// is sent. Call `line_reader_cursor_cancel` first if you need a
/// synchronous cancellation that surfaces errors and drains pending
/// frames before the connection is closed. Idempotent on NULL.
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
        // Drop the BatchView (it borrows from the cursor) before the
        // cursor itself. Wrapped in `panic_guard` because the cursor's
        // `Drop` runs `close_in_place`, which writes a Close frame
        // and shuts down the TCP socket. No-op under this crate's
        // `panic = abort` policy (the panic site aborts directly);
        // active in test builds and a structural barrier if the
        // policy ever moves to `unwind`. See `panic_guard` docstring.
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
///   * Non-NULL borrowed batch handle on success. Invalidated by the next
///     `line_reader_cursor_next_batch`, `line_reader_cursor_cancel`,
///     `line_reader_cursor_free`, or mid-query failover.
///   * NULL with `*err_out` left untouched when the stream has terminated
///     normally (no batch available).
///   * NULL with `*err_out` set on error; the cursor must be freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_next_batch(
    cursor: *mut line_reader_cursor,
    err_out: *mut *mut line_reader_error,
) -> *const line_reader_batch {
    unsafe {
        if cursor.is_null() {
            set_reader_err(
                err_out,
                ErrorCode::InvalidApiCall,
                "line_reader_cursor_next_batch: cursor is NULL",
            );
            return std::ptr::null();
        }
        let c = &mut *cursor;
        // `cursor_for_mut` clears `current_batch` (releasing the prior
        // BatchView's borrow on the cursor) and yields exclusive access
        // to the inner Cursor in one step — see the struct-level safety
        // note. The borrow is released before we re-assign
        // `c.current_batch` below; the explicit binding (`inner`) keeps
        // borrowck happy across the match.
        let inner: &mut Cursor<'static> = c.cursor_for_mut();
        // The decoder pipeline (varint parse, schema/dict bookkeeping,
        // Gorilla decode, validity walks) contains panic sites; under
        // this crate's `panic = abort` policy the panic site aborts
        // directly, so the `catch_unwind` + abort below is a no-op in
        // shipped builds. It is kept active for test builds (cargo
        // forces `panic = unwind`) and to match the wrap pattern used
        // by `_query_new` and `_query_execute`. See `panic_guard`
        // docstring. The lifetime launder happens INSIDE the closure:
        // `BatchView<'_>` borrows from `inner`, which the closure
        // can't return as a borrow of a captured variable. The
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
                // SAFETY: `repr(transparent)` over `BatchView<'static>`; the
                // pointer borrows the cursor's `current_batch` field and is
                // valid until the next `cursor_for_mut` (i.e. next
                // `next_batch` / `cancel` / `free`).
                let bv: &BatchView<'static> = c.current_batch.as_ref().unwrap();
                (bv as *const BatchView<'static>).cast()
            }
            Ok(None) => ptr::null(),
            Err(e) => {
                write_err_box(err_out, e);
                ptr::null()
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Cursor introspection
// ---------------------------------------------------------------------------

/// Cursor's request_id (assigned at `execute()` and refreshed on failover).
/// Returns `0` for a NULL handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_request_id(cursor: *const line_reader_cursor) -> i64 {
    unsafe {
        if cursor.is_null() {
            return 0;
        }
        (*cursor).cursor.request_id()
    }
}

/// Cumulative bytes of CREDIT this cursor has granted the server. Pulls
/// through to the underlying reader's connection-level counter.
///
/// **Single-thread only.** This getter reads the counter through the
/// laundered `Cursor<'static>` and is bound by the cursor's one-thread-at-a-time
/// contract — calling it from a monitoring thread while the cursor's
/// owning thread is inside `next_batch` / `cancel` / `add_credit` is
/// undefined behaviour. For cross-thread monitoring (e.g. a stats
/// dashboard polling from a separate thread), use
/// `line_reader_credit_granted_total` instead — it reads the same
/// connection-level counter through the reader's atomic, which is
/// explicitly cross-thread safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_credit_granted_total(
    cursor: *const line_reader_cursor,
) -> u64 {
    unsafe {
        if cursor.is_null() {
            return 0;
        }
        (*cursor).cursor.credit_granted_total()
    }
}

/// Number of successful failover resets observed by this cursor since
/// `execute()`. Returns `0` for a NULL handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_failover_resets(
    cursor: *const line_reader_cursor,
) -> u32 {
    unsafe {
        if cursor.is_null() {
            return 0;
        }
        (*cursor).cursor.failover_resets()
    }
}

/// Host of the endpoint the cursor is currently connected to. Borrowed;
/// invalidated on failover or close. For a NULL handle, writes an empty
/// `(NULL, 0)` pair.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_current_addr_host(
    cursor: *const line_reader_cursor,
    out_buf: *mut *const c_char,
    out_len: *mut size_t,
) {
    unsafe {
        // Defensive: a NULL out-param is a contract violation. Skip the
        // write rather than dereferencing NULL.
        if out_buf.is_null() || out_len.is_null() {
            return;
        }
        if cursor.is_null() {
            *out_buf = ptr::null();
            *out_len = 0;
            return;
        }
        let ep = (*cursor).cursor.current_addr();
        *out_buf = ep.host.as_ptr() as *const c_char;
        *out_len = ep.host.len();
    }
}

/// Port of the endpoint the cursor is currently connected to. Returns `0`
/// for a NULL handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_current_addr_port(
    cursor: *const line_reader_cursor,
) -> u16 {
    unsafe {
        if cursor.is_null() {
            return 0;
        }
        (*cursor).cursor.current_addr().port
    }
}

/// Negotiated QWP version of the cursor's underlying connection. The
/// in-cursor counterpart to `line_reader_server_version`, which rejects
/// while a cursor is live.
///
/// Returns `false` and sets `*err_out` on failure: the cursor handle is
/// NULL, or the underlying connection is poisoned after a failed
/// mid-query failover. On success returns `true` and writes the version
/// to `*out_version`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_server_version(
    cursor: *const line_reader_cursor,
    out_version: *mut u8,
    err_out: *mut *mut line_reader_error,
) -> bool {
    unsafe {
        if out_version.is_null() {
            // Defensive: a NULL out-param is a contract violation.
            if !err_out.is_null() {
                set_reader_err(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    "line_reader_cursor_server_version called with NULL out_version",
                );
            }
            return false;
        }
        if cursor.is_null() {
            if !err_out.is_null() {
                set_reader_err(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    "line_reader_cursor_server_version called with NULL cursor handle",
                );
            }
            return false;
        }
        match (*cursor).cursor.server_version() {
            Ok(v) => {
                *out_version = v;
                true
            }
            Err(e) => {
                write_err_box(err_out, e);
                false
            }
        }
    }
}

/// Borrowed `SERVER_INFO` of the cursor's currently connected endpoint, or
/// NULL when the server hasn't sent one (v1 protocol). The returned
/// pointer is invalidated by any subsequent cursor operation that may
/// reconnect (`line_reader_cursor_next_batch`, `line_reader_cursor_free`).
/// Returns NULL for a NULL handle.
///
/// The in-cursor counterpart to `line_reader_current_server_info`, which
/// rejects while a cursor is live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_current_server_info(
    cursor: *const line_reader_cursor,
) -> *const line_reader_server_info {
    unsafe {
        if cursor.is_null() {
            return ptr::null();
        }
        match (*cursor).cursor.server_info() {
            Some(si) => si as *const ServerInfo as *const line_reader_server_info,
            None => ptr::null(),
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

/// Discriminant of the cursor's terminal frame, if observed. Returns
/// `_kind_none` for a NULL handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_terminal_kind(
    cursor: *const line_reader_cursor,
) -> line_reader_terminal_kind {
    unsafe {
        if cursor.is_null() {
            return line_reader_terminal_kind::line_reader_terminal_kind_none;
        }
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
/// returns false. NULL handle also zeroes the outputs and returns false.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_terminal_end(
    cursor: *const line_reader_cursor,
    out_final_seq: *mut u64,
    out_total_rows: *mut u64,
) -> bool {
    unsafe {
        // Defensive: a NULL out-param is a contract violation. Skip every
        // write below rather than dereferencing NULL.
        if out_final_seq.is_null() || out_total_rows.is_null() {
            return false;
        }
        if cursor.is_null() {
            *out_final_seq = 0;
            *out_total_rows = 0;
            return false;
        }
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
/// returns false. NULL handle also zeroes the outputs and returns false.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_terminal_exec_done(
    cursor: *const line_reader_cursor,
    out_op_type: *mut u8,
    out_rows_affected: *mut u64,
) -> bool {
    unsafe {
        // Defensive: a NULL out-param is a contract violation. Skip every
        // write below rather than dereferencing NULL.
        if out_op_type.is_null() || out_rows_affected.is_null() {
            return false;
        }
        if cursor.is_null() {
            *out_op_type = 0;
            *out_rows_affected = 0;
            return false;
        }
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
        if cursor.is_null() {
            set_reader_err(
                err_out,
                ErrorCode::InvalidApiCall,
                "line_reader_cursor_cancel: cursor is NULL",
            );
            return false;
        }
        // `cursor_for_aux` keeps the Arrow schema pin intact — `cancel`
        // is a terminal op so the pin is about to be irrelevant, but
        // sharing the helper with `add_credit` keeps the contract uniform.
        let inner = (*cursor).cursor_for_aux();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| inner.cancel()));
        let res = match result {
            Ok(r) => r,
            Err(_) => std::process::abort(),
        };
        match res {
            Ok(()) => true,
            Err(e) => {
                write_err_box(err_out, e);
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
        if cursor.is_null() {
            set_reader_err(
                err_out,
                ErrorCode::InvalidApiCall,
                "line_reader_cursor_add_credit: cursor is NULL",
            );
            return false;
        }
        // `cursor_for_aux` keeps the Arrow schema pin intact across this
        // flow-control call; otherwise a subsequent `_next_arrow_batch`
        // would lose its drift snapshot.
        let inner = (*cursor).cursor_for_aux();
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
                write_err_box(err_out, e);
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

/// Report a NULL out-param contract violation through `err_out`.
#[inline]
unsafe fn null_out_param_err(err_out: *mut *mut line_reader_error, fn_name: &str) {
    unsafe {
        set_reader_err(
            err_out,
            ErrorCode::InvalidApiCall,
            format!("{fn_name} called with a NULL out-param pointer"),
        );
    }
}

// ---------------------------------------------------------------------------
// Batch & column bulk access
// ---------------------------------------------------------------------------

/// Borrowed handle for the batch currently loaded in a cursor. Backed by
/// the cursor's `current_batch`; invalidated by the next
/// `line_reader_cursor_next_batch`, `line_reader_cursor_cancel`,
/// `line_reader_cursor_free`, or mid-query failover. Never freed by the
/// caller.
#[repr(transparent)]
pub struct line_reader_batch(BatchView<'static>);

/// Bulk descriptor for one scalar / variable-width column. Every pointer
/// borrows from the batch and shares its lifetime.
#[repr(C)]
pub struct line_reader_column_data {
    pub kind: line_reader_column_kind,
    pub row_count: size_t,
    /// LSB-first null bitmap, `ceil(row_count / 8)` bytes; NULL if the
    /// column carries no nulls.
    pub validity: *const u8,
    /// Dense little-endian values, `row_count * value_stride` bytes; NULL
    /// for variable-width kinds.
    pub values: *const c_void,
    /// Bytes per fixed-width value; `0` for variable-width kinds.
    pub value_stride: size_t,
    /// VARCHAR / BINARY offset table, `row_count + 1` entries; NULL otherwise.
    pub var_offsets: *const u32,
    /// VARCHAR / BINARY concatenated data blob; NULL otherwise.
    pub var_data: *const u8,
    pub var_data_len: size_t,
    /// SYMBOL per-row dictionary codes, `row_count` entries; NULL otherwise.
    pub symbol_codes: *const u32,
    /// DECIMAL64/128/256 shared scale; `0` otherwise.
    pub decimal_scale: i8,
    /// GEOHASH precision in bits (1..60); `0` otherwise.
    pub geohash_precision_bits: u8,
}

/// Bulk descriptor for a `DOUBLE_ARRAY` / `LONG_ARRAY` column. Four-buffer
/// ragged layout; every pointer borrows from the batch.
#[repr(C)]
pub struct line_reader_array_data {
    pub kind: line_reader_column_kind,
    pub row_count: size_t,
    /// Row-level null bitmap (whole-array NULL); NULL if no row is null.
    pub validity: *const u8,
    /// Flattened row-major little-endian element bytes for every row.
    pub data: *const u8,
    pub data_len: size_t,
    /// Per-row byte offsets into `data`, `row_count + 1` entries.
    pub data_offsets: *const u32,
    /// Concatenated per-row dimension lengths.
    pub shapes: *const u32,
    pub shapes_len: size_t,
    /// Per-row offsets into `shapes`, `row_count + 1` entries.
    pub shape_offsets: *const u32,
}

/// One symbol-dictionary entry: a byte range into `line_reader_symbol_dict::heap`.
#[repr(C)]
pub struct line_reader_symbol_entry {
    pub offset: u32,
    pub length: u32,
}

/// Snapshot of the connection-scoped symbol dictionary.
#[repr(C)]
pub struct line_reader_symbol_dict {
    /// Entry count; an entry's index is its dictionary code.
    pub entry_count: size_t,
    /// Concatenated UTF-8 bytes for every entry.
    pub heap: *const u8,
    pub heap_len: size_t,
    /// `entry_count` entries addressing `heap`.
    pub entries: *const line_reader_symbol_entry,
}

// `line_reader_batch_symbol_dict` hands out `questdb-rs`'s `SymbolEntry`
// slice reinterpreted as `line_reader_symbol_entry`; both are `#[repr(C)]`
// `{ u32, u32 }`, but assert it so a layout change upstream fails the
// build instead of silently corrupting the offset table.
const _: () = assert!(
    std::mem::size_of::<line_reader_symbol_entry>() == std::mem::size_of::<SymbolEntry>()
        && std::mem::align_of::<line_reader_symbol_entry>() == std::mem::align_of::<SymbolEntry>()
);

#[inline]
fn validity_ptr(v: Validity<'_>) -> *const u8 {
    v.bytes().map_or(ptr::null(), <[u8]>::as_ptr)
}

unsafe fn batch_or_err<'a>(
    batch: *const line_reader_batch,
    err_out: *mut *mut line_reader_error,
    fn_name: &str,
) -> Option<&'a BatchView<'static>> {
    if batch.is_null() {
        unsafe {
            set_reader_err(
                err_out,
                ErrorCode::InvalidApiCall,
                format!("{fn_name}: batch handle is NULL"),
            );
        }
        return None;
    }
    Some(unsafe { &(*batch).0 })
}

/// Rows in the batch. `0` on a NULL handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_batch_row_count(batch: *const line_reader_batch) -> size_t {
    unsafe {
        if batch.is_null() {
            return 0;
        }
        (*batch).0.row_count()
    }
}

/// Columns in the batch. `0` on a NULL handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_batch_column_count(batch: *const line_reader_batch) -> size_t {
    unsafe {
        if batch.is_null() {
            return 0;
        }
        (*batch).0.column_count()
    }
}

/// `request_id` echoed from the originating `QUERY_REQUEST`. `0` on a NULL
/// handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_batch_request_id(batch: *const line_reader_batch) -> i64 {
    unsafe {
        if batch.is_null() {
            return 0;
        }
        (*batch).0.request_id()
    }
}

/// Monotonic per-request batch sequence number. `0` on a NULL handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_batch_seq(batch: *const line_reader_batch) -> u64 {
    unsafe {
        if batch.is_null() {
            return 0;
        }
        (*batch).0.batch_seq()
    }
}

/// Per-batch wire flags from the frame header. `0` on a NULL handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_batch_flags(batch: *const line_reader_batch) -> u8 {
    unsafe {
        if batch.is_null() {
            return 0;
        }
        (*batch).0.flags()
    }
}

/// Kind discriminant for `col_idx`. Returns false and sets `*err_out` on a
/// NULL handle, a NULL out-param, or an out-of-range index.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_batch_column_kind(
    batch: *const line_reader_batch,
    col_idx: size_t,
    out_kind: *mut line_reader_column_kind,
    err_out: *mut *mut line_reader_error,
) -> bool {
    unsafe {
        if out_kind.is_null() {
            null_out_param_err(err_out, "line_reader_batch_column_kind");
            return false;
        }
        let Some(batch) = batch_or_err(batch, err_out, "line_reader_batch_column_kind") else {
            return false;
        };
        let Some(view) = column_view_or_err(batch, col_idx, err_out) else {
            return false;
        };
        *out_kind = view.kind().into();
        true
    }
}

/// Borrowed, non-NUL-terminated UTF-8 column name for `col_idx`. The
/// pointer borrows from the batch's schema; see the batch handle's
/// invalidation rules. Returns false and sets `*err_out` on a NULL handle,
/// a NULL out-param, or an out-of-range index.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_batch_column_name(
    batch: *const line_reader_batch,
    col_idx: size_t,
    out_buf: *mut *const c_char,
    out_len: *mut size_t,
    err_out: *mut *mut line_reader_error,
) -> bool {
    unsafe {
        if out_buf.is_null() || out_len.is_null() {
            null_out_param_err(err_out, "line_reader_batch_column_name");
            return false;
        }
        let Some(batch) = batch_or_err(batch, err_out, "line_reader_batch_column_name") else {
            return false;
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

/// Project a scalar / variable-width column into `*out`. Returns false and
/// sets `*err_out` on a NULL handle, a NULL out-param, an out-of-range
/// index, or an array column (use `line_reader_batch_array_column_data`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_batch_column_data(
    batch: *const line_reader_batch,
    col_idx: size_t,
    out: *mut line_reader_column_data,
    err_out: *mut *mut line_reader_error,
) -> bool {
    unsafe {
        if out.is_null() {
            null_out_param_err(err_out, "line_reader_batch_column_data");
            return false;
        }
        let Some(batch) = batch_or_err(batch, err_out, "line_reader_batch_column_data") else {
            return false;
        };
        let Some(view) = column_view_or_err(batch, col_idx, err_out) else {
            return false;
        };
        let mut d = line_reader_column_data {
            kind: view.kind().into(),
            row_count: batch.row_count(),
            validity: ptr::null(),
            values: ptr::null(),
            value_stride: 0,
            var_offsets: ptr::null(),
            var_data: ptr::null(),
            var_data_len: 0,
            symbol_codes: ptr::null(),
            decimal_scale: 0,
            geohash_precision_bits: 0,
        };
        macro_rules! fixed {
            ($c:expr, $stride:expr) => {{
                d.values = $c.raw().as_ptr().cast();
                d.value_stride = $stride;
                d.validity = validity_ptr($c.validity());
            }};
        }
        match &view {
            ColumnView::Boolean(c) => fixed!(c, 1),
            ColumnView::Byte(c) => fixed!(c, 1),
            ColumnView::Short(c) => fixed!(c, 2),
            ColumnView::Char(c) => fixed!(c, 2),
            ColumnView::Int(c) => fixed!(c, 4),
            ColumnView::Float(c) => fixed!(c, 4),
            ColumnView::Ipv4(c) => fixed!(c, 4),
            ColumnView::Long(c) => fixed!(c, 8),
            ColumnView::Double(c) => fixed!(c, 8),
            ColumnView::Timestamp(c) => fixed!(c, 8),
            ColumnView::Date(c) => fixed!(c, 8),
            ColumnView::TimestampNanos(c) => fixed!(c, 8),
            ColumnView::Uuid(c) => fixed!(c, 16),
            ColumnView::Long256(c) => fixed!(c, 32),
            ColumnView::Decimal64(c) => {
                fixed!(c, 8);
                d.decimal_scale = c.scale();
            }
            ColumnView::Decimal128(c) => {
                fixed!(c, 16);
                d.decimal_scale = c.scale();
            }
            ColumnView::Decimal256(c) => {
                fixed!(c, 32);
                d.decimal_scale = c.scale();
            }
            ColumnView::Geohash(c) => {
                d.values = c.raw().as_ptr().cast();
                d.value_stride = c.byte_width() as size_t;
                d.validity = validity_ptr(c.validity());
                d.geohash_precision_bits = c.precision_bits();
            }
            ColumnView::Symbol(c) => {
                d.symbol_codes = c.codes().as_ptr();
                d.validity = validity_ptr(c.validity());
            }
            ColumnView::Varchar(c) => {
                d.var_offsets = c.offsets().as_ptr();
                d.var_data = c.data().as_ptr();
                d.var_data_len = c.data().len();
                d.validity = validity_ptr(c.validity());
            }
            ColumnView::Binary(c) => {
                d.var_offsets = c.offsets().as_ptr();
                d.var_data = c.data().as_ptr();
                d.var_data_len = c.data().len();
                d.validity = validity_ptr(c.validity());
            }
            ColumnView::DoubleArray(_) => {
                set_reader_err(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    format!(
                        "column {col_idx} is a DOUBLE_ARRAY; use line_reader_batch_array_column_data"
                    ),
                );
                return false;
            }
            ColumnView::LongArray(_) => {
                set_reader_err(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    format!(
                        "column {col_idx} is a LONG_ARRAY; LONG_ARRAY is not supported in this revision"
                    ),
                );
                return false;
            }
            _ => {
                set_reader_err(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    format!("column {col_idx} has unsupported kind {:?}", view.kind()),
                );
                return false;
            }
        }
        *out = d;
        true
    }
}

/// Project a `DOUBLE_ARRAY` / `LONG_ARRAY` column into `*out`. Returns
/// false and sets `*err_out` on a NULL handle, a NULL out-param, an
/// out-of-range index, or a non-array column.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_batch_array_column_data(
    batch: *const line_reader_batch,
    col_idx: size_t,
    out: *mut line_reader_array_data,
    err_out: *mut *mut line_reader_error,
) -> bool {
    unsafe {
        if out.is_null() {
            null_out_param_err(err_out, "line_reader_batch_array_column_data");
            return false;
        }
        let Some(batch) = batch_or_err(batch, err_out, "line_reader_batch_array_column_data")
        else {
            return false;
        };
        let Some(view) = column_view_or_err(batch, col_idx, err_out) else {
            return false;
        };
        let mut d = line_reader_array_data {
            kind: view.kind().into(),
            row_count: batch.row_count(),
            validity: ptr::null(),
            data: ptr::null(),
            data_len: 0,
            data_offsets: ptr::null(),
            shapes: ptr::null(),
            shapes_len: 0,
            shape_offsets: ptr::null(),
        };
        macro_rules! array {
            ($c:expr) => {{
                d.validity = validity_ptr($c.validity());
                d.data = $c.data().as_ptr();
                d.data_len = $c.data().len();
                d.data_offsets = $c.data_offsets().as_ptr();
                d.shapes = $c.shapes().as_ptr();
                d.shapes_len = $c.shapes().len();
                d.shape_offsets = $c.shape_offsets().as_ptr();
            }};
        }
        match &view {
            ColumnView::DoubleArray(c) => array!(c),
            ColumnView::LongArray(_) => {
                set_reader_err(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    format!(
                        "column {col_idx} is a LONG_ARRAY; LONG_ARRAY is not supported in this revision"
                    ),
                );
                return false;
            }
            _ => {
                set_reader_err(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    format!(
                        "column {col_idx} is kind {:?}, not a DOUBLE_ARRAY \
                         column; use line_reader_batch_column_data for \
                         scalar / variable-width columns",
                        view.kind()
                    ),
                );
                return false;
            }
        }
        *out = d;
        true
    }
}

/// Resolve a SYMBOL dictionary `code` to its borrowed, non-NUL-terminated
/// UTF-8 bytes. Returns false and sets `*err_out` on a NULL handle, a NULL
/// out-param, a non-SYMBOL column, or a code outside the dictionary.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_batch_symbol(
    batch: *const line_reader_batch,
    col_idx: size_t,
    code: u32,
    out_buf: *mut *const c_char,
    out_len: *mut size_t,
    err_out: *mut *mut line_reader_error,
) -> bool {
    unsafe {
        if out_buf.is_null() || out_len.is_null() {
            null_out_param_err(err_out, "line_reader_batch_symbol");
            return false;
        }
        let Some(batch) = batch_or_err(batch, err_out, "line_reader_batch_symbol") else {
            return false;
        };
        let Some(view) = column_view_or_err(batch, col_idx, err_out) else {
            return false;
        };
        if !matches!(view, ColumnView::Symbol(_)) {
            set_reader_err(
                err_out,
                ErrorCode::InvalidApiCall,
                format!("column {col_idx} is not a SYMBOL column"),
            );
            return false;
        }
        let dict = batch.dict();
        match dict.get(code) {
            Some(s) => {
                *out_buf = s.as_ptr() as *const c_char;
                *out_len = s.len();
                true
            }
            None => {
                set_reader_err(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    format!(
                        "symbol code {code} out of range (dictionary size {})",
                        dict.len()
                    ),
                );
                false
            }
        }
    }
}

/// Snapshot the connection-scoped symbol dictionary into `*out` for bulk
/// (e.g. categorical) construction. Returns false and sets `*err_out` on a
/// NULL handle or a NULL out-param.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_batch_symbol_dict(
    batch: *const line_reader_batch,
    out: *mut line_reader_symbol_dict,
    err_out: *mut *mut line_reader_error,
) -> bool {
    unsafe {
        if out.is_null() {
            null_out_param_err(err_out, "line_reader_batch_symbol_dict");
            return false;
        }
        let Some(batch) = batch_or_err(batch, err_out, "line_reader_batch_symbol_dict") else {
            return false;
        };
        let dict = batch.dict();
        let entries = dict.entries();
        let heap = dict.arena();
        *out = line_reader_symbol_dict {
            entry_count: entries.len(),
            heap: heap.as_ptr(),
            heap_len: heap.len(),
            entries: entries.as_ptr().cast::<line_reader_symbol_entry>(),
        };
        true
    }
}

/// Build a `ColumnView` for `col_idx`, reporting an out-of-range index or a
/// projection failure through `err_out`.
unsafe fn column_view_or_err<'a>(
    batch: &'a BatchView<'a>,
    col_idx: size_t,
    err_out: *mut *mut line_reader_error,
) -> Option<ColumnView<'a>> {
    if col_idx >= batch.column_count() {
        unsafe {
            set_reader_err(
                err_out,
                ErrorCode::InvalidApiCall,
                format!(
                    "column index {} out of range (column_count={})",
                    col_idx,
                    batch.column_count()
                ),
            );
        }
        return None;
    }
    match batch.column(col_idx) {
        Ok(view) => Some(view),
        Err(e) => {
            unsafe { write_err_box(err_out, e) };
            None
        }
    }
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
    fn server_version_null_handle_sets_err_out() {
        unsafe {
            let mut version: u8 = 0xFF;
            let mut err: *mut line_reader_error = ptr::null_mut();
            let ok = line_reader_server_version(ptr::null(), &mut version, &mut err);
            assert!(!ok);
            assert!(!err.is_null(), "err_out must be set on NULL handle");
            let code = line_reader_error_get_code(err) as u32;
            let want = line_reader_error_code::line_reader_error_invalid_api_call as u32;
            assert_eq!(code, want);
            line_reader_error_free(err);
        }
    }

    #[test]
    fn server_version_null_handle_with_null_err_out_does_not_segv() {
        unsafe {
            let mut version: u8 = 0xFF;
            let ok = line_reader_server_version(ptr::null(), &mut version, ptr::null_mut());
            assert!(!ok);
        }
    }

    /// Pure-return cursor getters MUST return a benign sentinel on a
    /// NULL handle — never SIGSEGV inside `(*cursor)`. Each variant
    /// here would have previously dereferenced unconditionally.
    #[test]
    fn cursor_pure_return_getters_tolerate_null_handle() {
        unsafe {
            assert_eq!(line_reader_cursor_request_id(ptr::null()), 0);
            assert_eq!(line_reader_cursor_credit_granted_total(ptr::null()), 0);
            assert_eq!(line_reader_cursor_failover_resets(ptr::null()), 0);
            assert_eq!(line_reader_cursor_current_addr_port(ptr::null()), 0);
            assert_eq!(
                line_reader_cursor_terminal_kind(ptr::null()) as u32,
                line_reader_terminal_kind::line_reader_terminal_kind_none as u32,
            );
        }
    }

    /// `_current_addr_host` writes `(NULL, 0)` to its out-params on a
    /// NULL handle (matching `line_reader_current_addr_host`).
    #[test]
    fn cursor_current_addr_host_null_handle_zeroes_out() {
        unsafe {
            let mut buf: *const c_char = ptr::dangling::<c_char>(); // poison
            let mut len: size_t = 0xDEADBEEF;
            line_reader_cursor_current_addr_host(ptr::null(), &mut buf, &mut len);
            assert!(buf.is_null());
            assert_eq!(len, 0);
        }
    }

    /// `terminal_end` / `terminal_exec_done` return false and zero
    /// every out-param on a NULL handle.
    #[test]
    fn cursor_terminal_getters_null_handle_return_false_and_zero() {
        unsafe {
            let mut a: u64 = 1;
            let mut b: u64 = 2;
            assert!(!line_reader_cursor_terminal_end(
                ptr::null(),
                &mut a,
                &mut b
            ));
            assert_eq!(a, 0);
            assert_eq!(b, 0);

            let mut op: u8 = 0xFF;
            let mut rows: u64 = 0xFEED;
            assert!(!line_reader_cursor_terminal_exec_done(
                ptr::null(),
                &mut op,
                &mut rows
            ));
            assert_eq!(op, 0);
            assert_eq!(rows, 0);
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
            ErrorCode::ServerSchemaMismatch,
            ErrorCode::ServerParseError,
            ErrorCode::ServerInternalError,
            ErrorCode::ServerSecurityError,
            ErrorCode::LimitExceeded,
            ErrorCode::ServerLimitExceeded,
            ErrorCode::Cancelled,
            ErrorCode::FailoverWouldDuplicate,
            ErrorCode::SchemaDrift,
            ErrorCode::NoSchema,
            ErrorCode::ArrowExport,
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
    fn line_reader_error_code_arrow_discriminants_are_abi_stable() {
        // Pin numeric values for the Arrow-related variants exposed to C/FFI
        // consumers. Append-only past the existing tail at 21.
        assert_eq!(
            line_reader_error_code::line_reader_error_schema_drift as u32,
            22
        );
        assert_eq!(
            line_reader_error_code::line_reader_error_no_schema as u32,
            23
        );
        assert_eq!(
            line_reader_error_code::line_reader_error_arrow_export as u32,
            24
        );
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
            assert_eq!(
                column_kind_from_c(c as u32),
                Some(rust),
                "c→rust mapping for {:?}",
                rust
            );
        }
        // Out-of-range / reserved / sentinel discriminants must round-trip
        // to None rather than UB. The FFI parameter is `u32` precisely so
        // these values can be represented and rejected (storing them in a
        // `line_reader_column_kind` value would be UB per the Rust
        // reference).
        assert_eq!(
            column_kind_from_c(line_reader_column_kind::line_reader_column_kind_unknown as u32),
            None,
            "unknown sentinel rejects"
        );
        assert_eq!(
            column_kind_from_c(0x08),
            None,
            "reserved STRING code rejects"
        );
        assert_eq!(column_kind_from_c(0x99), None, "garbage byte rejects");
        assert_eq!(
            column_kind_from_c(0x1_0000),
            None,
            "out-of-byte-range rejects"
        );
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

#[cfg(feature = "arrow")]
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum line_reader_arrow_batch_result {
    line_reader_arrow_batch_ok = 0,
    line_reader_arrow_batch_end = 1,
    line_reader_arrow_batch_error = 2,
}

#[cfg(feature = "arrow")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn line_reader_cursor_next_arrow_batch(
    cursor: *mut line_reader_cursor,
    out_array: *mut arrow::ffi::FFI_ArrowArray,
    out_schema: *mut arrow::ffi::FFI_ArrowSchema,
    err_out: *mut *mut line_reader_error,
) -> line_reader_arrow_batch_result {
    use arrow_array::{Array, StructArray};
    unsafe {
        if cursor.is_null() {
            set_reader_err(
                err_out,
                ErrorCode::InvalidApiCall,
                "line_reader_cursor_next_arrow_batch: cursor is NULL",
            );
            return line_reader_arrow_batch_result::line_reader_arrow_batch_error;
        }
        if out_array.is_null() || out_schema.is_null() {
            set_reader_err(
                err_out,
                ErrorCode::InvalidApiCall,
                "line_reader_cursor_next_arrow_batch: out_array or out_schema is NULL",
            );
            return line_reader_arrow_batch_result::line_reader_arrow_batch_error;
        }
        enum NextArrow {
            Ok(
                arrow::ffi::FFI_ArrowArray,
                arrow::ffi::FFI_ArrowSchema,
                arrow::datatypes::SchemaRef,
            ),
            End,
            Err(Error, Option<arrow::datatypes::SchemaRef>),
        }
        let c = &mut *cursor;
        let pinned = c.arrow_schema_pin.clone();
        let inner: &mut Cursor<'static> = c.cursor_for_mut();
        let outcome = panic_guard(|| -> NextArrow {
            let rb = match inner.next_arrow_batch_inner(pinned.as_ref()) {
                Ok(Some(rb)) => rb,
                Ok(None) => return NextArrow::End,
                Err(e) => return NextArrow::Err(e, None),
            };
            let schema_ref = rb.schema();
            let struct_array: StructArray = rb.into();
            let array_data = struct_array.into_data();
            match arrow::ffi::to_ffi(&array_data) {
                Ok((ffi_array, ffi_schema)) => NextArrow::Ok(ffi_array, ffi_schema, schema_ref),
                Err(e) => NextArrow::Err(
                    Error::new(ErrorCode::ArrowExport, e.to_string()),
                    Some(schema_ref),
                ),
            }
        });
        match outcome {
            NextArrow::Ok(ffi_array, ffi_schema, schema_ref) => {
                c.arrow_schema_pin = Some(schema_ref);
                std::ptr::write(out_array, ffi_array);
                std::ptr::write(out_schema, ffi_schema);
                line_reader_arrow_batch_result::line_reader_arrow_batch_ok
            }
            NextArrow::End => line_reader_arrow_batch_result::line_reader_arrow_batch_end,
            NextArrow::Err(e, pin_to_restore) => {
                if let Some(pin) = pin_to_restore {
                    c.arrow_schema_pin = Some(pin);
                }
                write_err_box(err_out, e);
                line_reader_arrow_batch_result::line_reader_arrow_batch_error
            }
        }
    }
}
