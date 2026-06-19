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

#![allow(non_upper_case_globals)]

use libc::{c_char, size_t};
use std::slice;
use std::str;
use std::sync::atomic::{AtomicU32, Ordering};

use questdb::ingress::column_sender::{
    AckLevel, Chunk, NumpyDtype, OwnedSender, QuestDb, Validity,
};
#[cfg(feature = "arrow")]
use questdb::ingress::column_sender::{ArrowColumnOverride, ImportedArrowColumn};
use questdb::ingress::{MAX_ARRAY_DIMS, MAX_NDARRAY_LEAF_ELEMS};
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
/// `questdb_db_return_conn` is called. Bundles the per-connection
/// schema registry and symbol-dict state used by all writer modes.
///
/// **Not thread-safe.** A `qwpws_conn*` must not be used from more than
/// one thread at a time. The second tuple field is a CAS-checked latch
/// on every FFI entry (mutation, accessor, and free); a non-blocking
/// contending caller observes `line_sender_error_invalid_api_call`
/// instead of a data race. When `questdb_db_return_conn` is observed
/// to interleave with an in-flight call (the latch sees `IN_USE` when
/// the free arrives), the box's drop is deferred to the in-flight
/// call's exit path, preventing UAF for that ordering.
///
/// Callers must still ensure happens-before ordering between the last
/// FFI call on `conn` and `questdb_db_return_conn(conn)` — e.g. by
/// confining `conn` to a single thread, or by an external barrier — so
/// the latch's CAS sees the close intent. A true concurrent free
/// without such ordering is undefined behavior.
pub struct qwpws_conn(OwnedSender, AtomicU32);

/// One DataFrame's worth of column buffers destined for one QuestDB table.
/// Owned by the caller; not bound to a connection.
///
/// Holds raw pointers into caller buffers (no copy). Per the FFI ABI
/// doc §2.3, the caller MUST keep every column buffer passed in via
/// `column_sender_chunk_column_*` / `column_sender_chunk_append_*`
/// alive until the next `column_sender_flush` call returns. We hide the
/// chunk's lifetime by promoting its inner type to `'static`; the lifetime
/// is enforced by the caller, not the borrow checker.
///
/// **Not thread-safe.** Single-threaded by contract; the latch in the
/// second tuple field detects in-thread reentrance and out-of-order
/// free/use sequences, deferring a free observed mid-call until the
/// active call exits. The same caveat as [`qwpws_conn`] applies: the
/// caller must establish happens-before between the last column call
/// on `chunk` and `column_sender_chunk_free(chunk)`.
pub struct column_sender_chunk(Chunk<'static>, AtomicU32);

/// Imported Arrow column for repeated chunk appends.
///
/// **Not thread-safe.** Python owns this per-plan and uses it from one thread.
/// The latch rejects concurrent append/free on the FFI surface.
#[cfg(feature = "arrow")]
pub struct column_sender_arrow_import(ImportedArrowColumn, AtomicU32);

const LATCH_IN_USE: u32 = 1 << 0;
const LATCH_CLOSED: u32 = 1 << 1;
const LATCH_DROP: u32 = 1 << 2;

trait FfiHandle {
    unsafe fn on_deferred_close(handle: *mut Self, latch_prev: u32);
}

impl FfiHandle for column_sender_chunk {
    unsafe fn on_deferred_close(_handle: *mut Self, _latch_prev: u32) {}
}

#[cfg(feature = "arrow")]
impl FfiHandle for column_sender_arrow_import {
    unsafe fn on_deferred_close(_handle: *mut Self, _latch_prev: u32) {}
}

impl FfiHandle for qwpws_conn {
    unsafe fn on_deferred_close(handle: *mut Self, latch_prev: u32) {
        if latch_prev & LATCH_DROP != 0 {
            unsafe { (*handle).0.get_mut().mark_must_close() };
        }
    }
}

struct InUseGuard<T: FfiHandle> {
    handle: *mut T,
    state: *const AtomicU32,
}

impl<T: FfiHandle> InUseGuard<T> {
    unsafe fn acquire(
        handle: *mut T,
        state: *const AtomicU32,
        fn_name: &str,
        what: &str,
        err_out: *mut *mut line_sender_error,
    ) -> Option<Self> {
        let atomic = unsafe { &*state };
        loop {
            let cur = atomic.load(Ordering::Acquire);
            if cur & LATCH_CLOSED != 0 {
                unsafe {
                    set_err_out_from_error(
                        err_out,
                        Error::new(
                            ErrorCode::InvalidApiCall,
                            format!("{fn_name}: {what} has been freed or returned to the pool"),
                        ),
                    );
                }
                return None;
            }
            if cur & LATCH_IN_USE != 0 {
                unsafe {
                    set_err_out_from_error(
                        err_out,
                        Error::new(
                            ErrorCode::InvalidApiCall,
                            format!(
                                "{fn_name}: {what} is already in use by a concurrent call \
                                 (each handle is single-threaded)"
                            ),
                        ),
                    );
                }
                return None;
            }
            if atomic
                .compare_exchange_weak(cur, cur | LATCH_IN_USE, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(Self { handle, state });
            }
        }
    }
}

impl<T: FfiHandle> Drop for InUseGuard<T> {
    fn drop(&mut self) {
        let atomic = unsafe { &*self.state };
        let prev = atomic.fetch_and(!LATCH_IN_USE, Ordering::AcqRel);
        if prev & LATCH_CLOSED != 0 {
            unsafe {
                T::on_deferred_close(self.handle, prev);
                drop(Box::from_raw(self.handle));
            }
        }
    }
}

unsafe fn finalize_or_defer<T: FfiHandle>(handle: *mut T, state: *const AtomicU32, extra: u32) {
    let atomic = unsafe { &*state };
    let prev = atomic.fetch_or(LATCH_CLOSED | extra, Ordering::AcqRel);
    if prev & (LATCH_IN_USE | LATCH_CLOSED) == 0 {
        unsafe {
            T::on_deferred_close(handle, LATCH_CLOSED | extra);
            drop(Box::from_raw(handle));
        }
    }
}

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
    use questdb::ingress::column_sender::MAX_CHUNK_ROWS;
    if v.is_null() {
        return Some(None);
    }
    let v = unsafe { &*v };
    if v.bit_len > MAX_CHUNK_ROWS {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    format!(
                        "column_sender_validity bit_len {} exceeds MAX_CHUNK_ROWS ({MAX_CHUNK_ROWS})",
                        v.bit_len
                    ),
                ),
            );
        }
        return None;
    }
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
//
// The C header exposes named constants (`column_sender_ack_level_ok = 0`,
// `column_sender_ack_level_durable = 1`) but the FFI takes a `uint32_t`
// (not a `#[repr(C)] enum`) so an out-of-range value is a recoverable
// `InvalidApiCall` error instead of immediate Rust UB.
// ===========================================================================

pub const column_sender_ack_level_ok: u32 = 0;
pub const column_sender_ack_level_durable: u32 = 1;

fn ack_level_from_u32(value: u32, err_out: *mut *mut line_sender_error) -> Option<AckLevel> {
    match value {
        0 => Some(AckLevel::Ok),
        1 => Some(AckLevel::Durable),
        other => {
            unsafe {
                set_err_out_from_error(
                    err_out,
                    Error::new(
                        ErrorCode::InvalidApiCall,
                        format!("column_sender_sync: invalid ack_level {other} (expected 0 or 1)"),
                    ),
                );
            }
            None
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

/// Per-column varlen payload cap (~2 GiB). Bounded by `i32::MAX` to
/// match the i32 offset encoding used by varchar/binary/dict-bytes.
pub(crate) const MAX_VARLEN_PAYLOAD_BYTES: usize = i32::MAX as usize;

unsafe fn typed_slice_bounded<'a, T>(
    data: *const T,
    len: size_t,
    max_len: usize,
    max_label: &'static str,
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
    if len > max_len {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    format!("{what} length {len} exceeds {max_label} ({max_len})"),
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

unsafe fn typed_slice<'a, T>(
    data: *const T,
    len: size_t,
    err_out: *mut *mut line_sender_error,
    what: &'static str,
) -> Option<&'a [T]> {
    use questdb::ingress::column_sender::MAX_CHUNK_ROWS;
    unsafe { typed_slice_bounded(data, len, MAX_CHUNK_ROWS, "MAX_CHUNK_ROWS", err_out, what) }
}

unsafe fn typed_offsets_slice<'a, T>(
    data: *const T,
    len: size_t,
    err_out: *mut *mut line_sender_error,
    what: &'static str,
) -> Option<&'a [T]> {
    use questdb::ingress::column_sender::MAX_CHUNK_ROWS;
    let max = MAX_CHUNK_ROWS + 1;
    unsafe { typed_slice_bounded(data, len, max, "MAX_CHUNK_ROWS+1", err_out, what) }
}

unsafe fn typed_bytes_slice<'a>(
    data: *const u8,
    len: size_t,
    err_out: *mut *mut line_sender_error,
    what: &'static str,
) -> Option<&'a [u8]> {
    unsafe {
        typed_slice_bounded(
            data,
            len,
            MAX_VARLEN_PAYLOAD_BYTES,
            "MAX_VARLEN_PAYLOAD_BYTES",
            err_out,
            what,
        )
    }
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
        Ok(owned) => Box::into_raw(Box::new(qwpws_conn(owned, AtomicU32::new(0)))),
        Err(err) => {
            unsafe { set_err_out_from_error(err_out, err) };
            std::ptr::null_mut()
        }
    }
}

/// Like `questdb_db_borrow_conn` but retries the connect within `budget_ms`
/// using the row sender's reconnect backoff (centered-jittered exponential with
/// a role-reject reset; `AuthError` / protocol-version errors are terminal). On
/// a transient `line_sender_error_failover_retry`, drop the dead conn with
/// `questdb_db_drop_conn` then call this to fail over with the same budget and
/// backoff as the row API. `budget_ms == 0` makes a single attempt (no retry).
/// Returns NULL on failure; sets `*err_out` if provided.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_db_borrow_conn_with_retry(
    db: *mut questdb_db,
    budget_ms: u64,
    err_out: *mut *mut line_sender_error,
) -> *mut qwpws_conn {
    if db.is_null() {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    "questdb_db_borrow_conn_with_retry: db pointer is NULL".to_string(),
                ),
            );
        }
        return std::ptr::null_mut();
    }
    let db_ref = unsafe { &*db };
    match db_ref
        .0
        .borrow_sender_owned_with_retry(std::time::Duration::from_millis(budget_ms))
    {
        Ok(owned) => Box::into_raw(Box::new(qwpws_conn(owned, AtomicU32::new(0)))),
        Err(err) => {
            unsafe { set_err_out_from_error(err_out, err) };
            std::ptr::null_mut()
        }
    }
}

/// The pool's failover budget (`reconnect_max_duration`, default 300000 ms).
/// Callers tracking an overall failover deadline pass the remaining budget to
/// `questdb_db_borrow_conn_with_retry`. Returns 0 if `db` is NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_db_reconnect_max_duration_ms(db: *const questdb_db) -> u64 {
    if db.is_null() {
        return 0;
    }
    let db_ref = unsafe { &*db };
    db_ref.0.reconnect_max_duration().as_millis() as u64
}

/// Return a borrowed conn to the pool. Invalidates `conn`. Accepts NULL
/// and no-ops. `db` is ignored — kept in the ABI for symmetry.
///
/// A racing in-flight call on the same handle defers the drop: the
/// in-flight call's exit path performs the actual `Box::from_raw`, so
/// the caller never sees UAF.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_db_return_conn(_db: *mut questdb_db, conn: *mut qwpws_conn) {
    if conn.is_null() {
        return;
    }
    let state: *const AtomicU32 = unsafe { &raw const (*conn).1 };
    unsafe { finalize_or_defer(conn, state, 0) };
}

/// Force-drop a borrowed conn instead of recycling it. Marks the conn terminal
/// (`qwpws_conn_must_close` becomes `true`) so the underlying backend is
/// removed from the pool. In store-and-forward mode unresolved frames remain in
/// the SFA slot for replay by the next owner. Accepts NULL and no-ops. As with
/// `questdb_db_return_conn`, a racing in-flight call defers the drop to that
/// call's exit path.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_db_drop_conn(_db: *mut questdb_db, conn: *mut qwpws_conn) {
    if conn.is_null() {
        return;
    }
    let state: *const AtomicU32 = unsafe { &raw const (*conn).1 };
    unsafe { finalize_or_defer(conn, state, LATCH_DROP) };
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

/// `true` if any of the following hold; `false` only when the conn is
/// safely reusable:
///   * `conn` is NULL,
///   * the conn was already closed / dropped,
///   * the conn is in a permanently-unusable state (e.g. a flush left
///     it with uncommitted in-flight frames),
///   * another FFI call on the same handle is currently in flight on
///     another thread (single-handle contract violation).
///
/// The latch-contention case folds into the same return value because
/// the caller cannot safely act on a contended handle anyway; if you
/// need to distinguish "contended" from "terminal", confine `conn` to
/// one thread so the latch can never be contended at this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwpws_conn_must_close(conn: *const qwpws_conn) -> bool {
    if conn.is_null() {
        return true;
    }
    let state: *const AtomicU32 = unsafe { &raw const (*conn).1 };
    let mut err_box: *mut line_sender_error = std::ptr::null_mut();
    let guard = unsafe {
        InUseGuard::acquire(
            conn as *mut qwpws_conn,
            state,
            "qwpws_conn_must_close",
            "qwpws_conn",
            &mut err_box,
        )
    };
    if guard.is_none() {
        if !err_box.is_null() {
            unsafe { crate::line_sender_error_free(err_box) };
        }
        return true;
    }
    let result = unsafe { (*conn).0.get().must_close() };
    drop(guard);
    result
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

/// Create an empty chunk for `table_name` (validated UTF-8).
///
/// Table name grammar and length validation is deferred to first flush —
/// matches the deferred-validation contract of `Chunk::new` in the Rust
/// API.
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
    Box::into_raw(Box::new(column_sender_chunk(
        Chunk::new(table),
        AtomicU32::new(0),
    )))
}

/// Free a chunk. Accepts NULL and no-ops. A racing in-flight call defers
/// the drop to the in-flight call's exit path.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn column_sender_chunk_free(chunk: *mut column_sender_chunk) {
    if chunk.is_null() {
        return;
    }
    let state: *const AtomicU32 = unsafe { &raw const (*chunk).1 };
    unsafe { finalize_or_defer(chunk, state, 0) };
}

/// Clear a chunk's content, keeping its retained capacity for reuse.
///
/// Returns `true` on success, `false` if `chunk` is NULL, has already
/// been freed, or another FFI call is currently mutating the chunk.
/// On `false`, `*err_out` carries the reason (NULL `err_out` is silently
/// ignored).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn column_sender_chunk_clear(
    chunk: *mut column_sender_chunk,
    err_out: *mut *mut line_sender_error,
) -> bool {
    if chunk.is_null() {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    "column_sender_chunk_clear: chunk is NULL".to_string(),
                ),
            );
        }
        return false;
    }
    let state: *const AtomicU32 = unsafe { &raw const (*chunk).1 };
    let guard = unsafe {
        InUseGuard::acquire(
            chunk,
            state,
            "column_sender_chunk_clear",
            "column_sender_chunk",
            err_out,
        )
    };
    if guard.is_none() {
        return false;
    }
    unsafe { (*chunk).0.clear() };
    drop(guard);
    true
}

/// Current row count of the chunk. Returns `(size_t)-1` (a.k.a.
/// `SIZE_MAX`) on failure (`chunk` is NULL, has been freed, or another
/// FFI call on the same handle is currently in flight) and sets
/// `*err_out`. A NULL `err_out` is silently ignored.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn column_sender_chunk_row_count(
    chunk: *const column_sender_chunk,
    err_out: *mut *mut line_sender_error,
) -> size_t {
    if chunk.is_null() {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    "column_sender_chunk_row_count: chunk is NULL".to_string(),
                ),
            );
        }
        return usize::MAX;
    }
    let state: *const AtomicU32 = unsafe { &raw const (*chunk).1 };
    let guard = unsafe {
        InUseGuard::acquire(
            chunk as *mut column_sender_chunk,
            state,
            "column_sender_chunk_row_count",
            "column_sender_chunk",
            err_out,
        )
    };
    if guard.is_none() {
        return usize::MAX;
    }
    let result = unsafe { (*chunk).0.row_count() };
    drop(guard);
    result
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
            if chunk.is_null() {
                return reject_null_chunk(err_out);
            }
            let _guard = match unsafe {
                InUseGuard::acquire(
                    chunk,
                    &raw const (*chunk).1,
                    stringify!($fn_name),
                    "column_sender_chunk",
                    err_out,
                )
            } {
                Some(g) => g,
                None => return false,
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
            let inner: &mut Chunk = unsafe { &mut (*chunk).0 };
            bubble!(err_out, inner.$rust_method(name, data, validity.as_ref()));
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
    if chunk.is_null() {
        return reject_null_chunk(err_out);
    }
    let _guard = match unsafe {
        InUseGuard::acquire(
            chunk,
            &raw const (*chunk).1,
            "column_sender_chunk_column_bool",
            "column_sender_chunk",
            err_out,
        )
    } {
        Some(g) => g,
        None => return false,
    };
    let name = match unsafe { name_str(name, name_len, err_out) } {
        Some(s) => s,
        None => return false,
    };
    {
        use questdb::ingress::column_sender::MAX_CHUNK_ROWS;
        if row_count > MAX_CHUNK_ROWS {
            unsafe {
                set_err_out_from_error(
                    err_out,
                    Error::new(
                        ErrorCode::InvalidApiCall,
                        format!(
                            "bool column row_count {row_count} exceeds MAX_CHUNK_ROWS ({MAX_CHUNK_ROWS})"
                        ),
                    ),
                );
            }
            return false;
        }
    }
    let bytes_required = row_count.div_ceil(8);
    let bool_bytes_cap = {
        use questdb::ingress::column_sender::MAX_CHUNK_ROWS;
        MAX_CHUNK_ROWS.div_ceil(8)
    };
    let data_slice = match unsafe {
        typed_slice_bounded(
            data,
            bytes_required,
            bool_bytes_cap,
            "ceil(MAX_CHUNK_ROWS / 8)",
            err_out,
            "bool column data",
        )
    } {
        Some(s) => s,
        None => return false,
    };
    let validity = match unsafe { as_validity(validity, err_out) } {
        Some(v) => v,
        None => return false,
    };
    let inner: &mut Chunk = unsafe { &mut (*chunk).0 };
    bubble!(
        err_out,
        inner.column_bool(name, data_slice, row_count, validity.as_ref())
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
            if chunk.is_null() {
                return reject_null_chunk(err_out);
            }
            let _guard = match unsafe {
                InUseGuard::acquire(
                    chunk,
                    &raw const (*chunk).1,
                    stringify!($fn_name),
                    "column_sender_chunk",
                    err_out,
                )
            } {
                Some(g) => g,
                None => return false,
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
            {
                use questdb::ingress::column_sender::MAX_CHUNK_ROWS;
                if row_count > MAX_CHUNK_ROWS {
                    unsafe {
                        set_err_out_from_error(
                            err_out,
                            Error::new(
                                ErrorCode::InvalidApiCall,
                                format!(
                                    "{} column row_count {} exceeds MAX_CHUNK_ROWS ({})",
                                    $what, row_count, MAX_CHUNK_ROWS
                                ),
                            ),
                        );
                    }
                    return false;
                }
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
            let inner: &mut Chunk = unsafe { &mut (*chunk).0 };
            bubble!(
                err_out,
                inner.$rust_method(name, data_slice, validity.as_ref())
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
    if chunk.is_null() {
        return reject_null_chunk(err_out);
    }
    let _guard = match unsafe {
        InUseGuard::acquire(
            chunk,
            &raw const (*chunk).1,
            "column_sender_chunk_column_binary",
            "column_sender_chunk",
            err_out,
        )
    } {
        Some(g) => g,
        None => return false,
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
    let offsets =
        match unsafe { typed_offsets_slice(offsets, offsets_len, err_out, "binary offsets") } {
            Some(s) => s,
            None => return false,
        };
    let bytes = match unsafe { typed_bytes_slice(bytes, bytes_len, err_out, "binary bytes") } {
        Some(s) => s,
        None => return false,
    };
    let validity = match unsafe { as_validity(validity, err_out) } {
        Some(v) => v,
        None => return false,
    };
    let inner: &mut Chunk = unsafe { &mut (*chunk).0 };
    bubble!(
        err_out,
        inner.column_binary(name, offsets, bytes, validity.as_ref())
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
    if chunk.is_null() {
        return reject_null_chunk(err_out);
    }
    let _guard = match unsafe {
        InUseGuard::acquire(
            chunk,
            &raw const (*chunk).1,
            "column_sender_chunk_column_varchar",
            "column_sender_chunk",
            err_out,
        )
    } {
        Some(g) => g,
        None => return false,
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
    let offsets =
        match unsafe { typed_offsets_slice(offsets, offsets_len, err_out, "varchar offsets") } {
            Some(s) => s,
            None => return false,
        };
    let bytes = match unsafe { typed_bytes_slice(bytes, bytes_len, err_out, "varchar bytes") } {
        Some(s) => s,
        None => return false,
    };
    let validity = match unsafe { as_validity(validity, err_out) } {
        Some(v) => v,
        None => return false,
    };
    let inner: &mut Chunk = unsafe { &mut (*chunk).0 };
    bubble!(
        err_out,
        inner.column_varchar(name, offsets, bytes, validity.as_ref())
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
            if chunk.is_null() {
                return reject_null_chunk(err_out);
            }
            let _guard = match unsafe {
                InUseGuard::acquire(
                    chunk,
                    &raw const (*chunk).1,
                    stringify!($fn_name),
                    "column_sender_chunk",
                    err_out,
                )
            } {
                Some(g) => g,
                None => return false,
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
                typed_offsets_slice(
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
                typed_bytes_slice(dict_bytes, dict_bytes_len, err_out, "symbol dict bytes")
            } {
                Some(s) => s,
                None => return false,
            };
            let validity = match unsafe { as_validity(validity, err_out) } {
                Some(v) => v,
                None => return false,
            };
            let inner: &mut Chunk = unsafe { &mut (*chunk).0 };
            bubble!(
                err_out,
                inner.$rust_method(name, codes, dict_offsets, dict_bytes, validity.as_ref())
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

/// Import an Arrow C Data Interface (`ArrowArray` + `ArrowSchema`) pair
/// into an opaque handle that subsequent calls can slice / append from.
///
/// Ownership: on success, `array->release` is consumed (set to NULL);
/// the returned handle owns the underlying buffers and releases them on
/// `column_sender_arrow_import_free`. On failure, `array->release` may
/// also have been consumed if the call reached the Arrow import step
/// before failing — callers MUST check `array->release != NULL` before
/// invoking it on the failure path. Early-fail paths (NULL pointer,
/// depth-cap rejection) leave it intact. `schema` is borrowed in all
/// cases.
///
/// `auto`: Dictionary(*, Utf8/LargeUtf8) -> SYMBOL, plain Utf8 -> VARCHAR.
/// `symbol`: force plain Utf8 -> SYMBOL. `not_symbol`: force Dictionary ->
/// VARCHAR. Used by `column_sender_arrow_import_new`.
#[cfg(feature = "arrow")]
#[repr(u32)]
#[allow(non_camel_case_types)]
pub enum column_sender_symbol_mode {
    column_sender_symbol_mode_auto = 0,
    column_sender_symbol_mode_symbol = 1,
    column_sender_symbol_mode_not_symbol = 2,
}

#[cfg(feature = "arrow")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn column_sender_arrow_import_new(
    array: *mut ArrowArray,
    schema: *const ArrowSchema,
    symbol_mode: column_sender_symbol_mode,
    err_out: *mut *mut line_sender_error,
) -> *mut column_sender_arrow_import {
    let symbol = match symbol_mode {
        column_sender_symbol_mode::column_sender_symbol_mode_symbol => Some(true),
        column_sender_symbol_mode::column_sender_symbol_mode_not_symbol => Some(false),
        column_sender_symbol_mode::column_sender_symbol_mode_auto => None,
    };
    let ffi_array = array as *mut arrow::ffi::FFI_ArrowArray;
    let ffi_schema = schema as *const arrow::ffi::FFI_ArrowSchema;
    let imported = match unsafe {
        crate::arrow_ffi_import_column(
            ffi_array,
            ffi_schema,
            symbol,
            "column_sender_arrow_import_new",
            err_out,
        )
    } {
        Some(imported) => imported,
        None => return std::ptr::null_mut(),
    };
    Box::into_raw(Box::new(column_sender_arrow_import(
        imported,
        AtomicU32::new(0),
    )))
}

#[cfg(feature = "arrow")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn column_sender_arrow_import_free(
    imported: *mut column_sender_arrow_import,
) {
    if imported.is_null() {
        return;
    }
    let state: *const AtomicU32 = unsafe { &raw const (*imported).1 };
    unsafe { finalize_or_defer(imported, state, 0) };
}

/// Number of rows in an imported Arrow column. Returns 0 for a NULL
/// `imported`, for a logically-empty column, and for a handle that has
/// been freed or is in use by a concurrent call. Cheap accessor; the
/// length is stored alongside the buffers.
#[cfg(feature = "arrow")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn column_sender_arrow_import_len(
    imported: *const column_sender_arrow_import,
) -> size_t {
    if imported.is_null() {
        return 0;
    }
    let imported_mut = imported as *mut column_sender_arrow_import;
    let guard = unsafe {
        InUseGuard::acquire(
            imported_mut,
            &raw const (*imported_mut).1,
            "column_sender_arrow_import_len",
            "column_sender_arrow_import",
            std::ptr::null_mut(),
        )
    };
    if guard.is_none() {
        return 0;
    }
    unsafe { (*imported).0.len() }
}

#[cfg(feature = "arrow")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn column_sender_chunk_append_arrow_import(
    chunk: *mut column_sender_chunk,
    name: *const c_char,
    name_len: size_t,
    imported: *const column_sender_arrow_import,
    row_offset: size_t,
    row_count: size_t,
    err_out: *mut *mut line_sender_error,
) -> bool {
    if chunk.is_null() {
        return reject_null_chunk(err_out);
    }
    if imported.is_null() {
        return reject_null_arrow_import(err_out);
    }
    let imported_mut = imported as *mut column_sender_arrow_import;
    let _import_guard = match unsafe {
        InUseGuard::acquire(
            imported_mut,
            &raw const (*imported_mut).1,
            "column_sender_chunk_append_arrow_import",
            "column_sender_arrow_import",
            err_out,
        )
    } {
        Some(g) => g,
        None => return false,
    };
    let _chunk_guard = match unsafe {
        InUseGuard::acquire(
            chunk,
            &raw const (*chunk).1,
            "column_sender_chunk_append_arrow_import",
            "column_sender_chunk",
            err_out,
        )
    } {
        Some(g) => g,
        None => return false,
    };
    let name = match unsafe { name_str(name, name_len, err_out) } {
        Some(s) => s,
        None => return false,
    };
    let inner: &mut Chunk = unsafe { &mut (*chunk).0 };
    let imported_ref = unsafe { &(*imported).0 };
    bubble!(
        err_out,
        inner.push_imported_arrow_slice(name, imported_ref, row_offset, row_count)
    );
    true
}

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
    if chunk.is_null() {
        return reject_null_chunk(err_out);
    }
    let _guard = match unsafe {
        InUseGuard::acquire(
            chunk,
            &raw const (*chunk).1,
            "column_sender_chunk_append_arrow_column",
            "column_sender_chunk",
            err_out,
        )
    } {
        Some(g) => g,
        None => return false,
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
    let inner: &mut Chunk = unsafe { &mut (*chunk).0 };
    bubble!(err_out, inner.push_arrow_column(name, &field, arr_ref));
    true
}

// ===========================================================================
// NumPy column appender
//
// Companion to `column_sender_chunk_append_arrow_column` that takes a
// raw contiguous NumPy buffer + a dtype tag. The buffer is borrowed by
// pointer (not copied) at append time; widening / packing happens at
// flush. The caller must keep `data` alive until the next flush returns.
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
    column_sender_numpy_datetime64_W = 37,

    column_sender_numpy_timedelta64_m = 38,
    column_sender_numpy_timedelta64_h = 39,
    column_sender_numpy_timedelta64_D = 40,
    column_sender_numpy_timedelta64_M = 41,
    column_sender_numpy_timedelta64_Y = 42,
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
    let mut leaf_count: usize = 1;
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
        leaf_count = match leaf_count.checked_mul(dim as usize) {
            Some(v) if v <= MAX_NDARRAY_LEAF_ELEMS => v,
            _ => {
                unsafe {
                    set_err_out_from_error(
                        err_out,
                        Error::new(
                            ErrorCode::InvalidApiCall,
                            format!(
                                "array_shape product exceeds MAX_NDARRAY_LEAF_ELEMS ({MAX_NDARRAY_LEAF_ELEMS}) at dim {i}"
                            ),
                        ),
                    );
                }
                return None;
            }
        };
        *slot = dim;
    }
    Some((ndim, shape))
}

unsafe fn resolve_numpy_dtype(
    dtype: u32,
    extras: *const column_sender_numpy_extras,
    err_out: *mut *mut line_sender_error,
) -> Option<NumpyDtype> {
    let extras = unsafe { extras.as_ref() };
    Some(match dtype {
        d if d == column_sender_numpy_dtype::column_sender_numpy_i8 as u32 => {
            NumpyDtype::I8WidenToI32
        }
        d if d == column_sender_numpy_dtype::column_sender_numpy_i16 as u32 => {
            NumpyDtype::I16WidenToI32
        }
        d if d == column_sender_numpy_dtype::column_sender_numpy_i32 as u32 => {
            NumpyDtype::I32WidenToI64
        }
        d if d == column_sender_numpy_dtype::column_sender_numpy_i64 as u32 => {
            NumpyDtype::I64Direct
        }
        d if d == column_sender_numpy_dtype::column_sender_numpy_u8 as u32 => {
            NumpyDtype::U8WidenToI32
        }
        d if d == column_sender_numpy_dtype::column_sender_numpy_u16 as u32 => {
            NumpyDtype::U16WidenToI32
        }
        d if d == column_sender_numpy_dtype::column_sender_numpy_u32 as u32 => {
            NumpyDtype::U32WidenToI64
        }
        d if d == column_sender_numpy_dtype::column_sender_numpy_u64 as u32 => {
            NumpyDtype::U64WidenToI64
        }
        d if d == column_sender_numpy_dtype::column_sender_numpy_f32 as u32 => {
            NumpyDtype::F32Direct
        }
        d if d == column_sender_numpy_dtype::column_sender_numpy_f64 as u32 => {
            NumpyDtype::F64Direct
        }
        d if d == column_sender_numpy_dtype::column_sender_numpy_bool as u32 => NumpyDtype::Bool,
        d if d == column_sender_numpy_dtype::column_sender_numpy_f16 as u32 => NumpyDtype::F16Widen,
        d if d == column_sender_numpy_dtype::column_sender_numpy_datetime64_s as u32 => {
            NumpyDtype::DatetimeSecToMicros
        }
        d if d == column_sender_numpy_dtype::column_sender_numpy_datetime64_ms as u32 => {
            NumpyDtype::DateI64Direct
        }
        d if d == column_sender_numpy_dtype::column_sender_numpy_datetime64_us as u32 => {
            NumpyDtype::TimestampMicrosDirect
        }
        d if d == column_sender_numpy_dtype::column_sender_numpy_datetime64_ns as u32 => {
            NumpyDtype::TimestampNanosDirect
        }
        d if d == column_sender_numpy_dtype::column_sender_numpy_timedelta64_s as u32
            || d == column_sender_numpy_dtype::column_sender_numpy_timedelta64_ms as u32
            || d == column_sender_numpy_dtype::column_sender_numpy_timedelta64_us as u32
            || d == column_sender_numpy_dtype::column_sender_numpy_timedelta64_ns as u32 =>
        {
            NumpyDtype::LongDirect
        }
        d if d == column_sender_numpy_dtype::column_sender_numpy_s16 as u32 => {
            NumpyDtype::UuidDirect
        }
        d if d == column_sender_numpy_dtype::column_sender_numpy_s32 as u32 => {
            NumpyDtype::Long256Direct
        }
        d if d == column_sender_numpy_dtype::column_sender_numpy_decimal_s8 as u32 => {
            NumpyDtype::Decimal64 {
                scale: unsafe { validate_decimal_scale(extras, 18, "DECIMAL64", err_out)? },
            }
        }
        d if d == column_sender_numpy_dtype::column_sender_numpy_decimal_s16 as u32 => {
            NumpyDtype::Decimal128 {
                scale: unsafe { validate_decimal_scale(extras, 38, "DECIMAL128", err_out)? },
            }
        }
        d if d == column_sender_numpy_dtype::column_sender_numpy_decimal_s32 as u32 => {
            NumpyDtype::Decimal256 {
                scale: unsafe { validate_decimal_scale(extras, 76, "DECIMAL256", err_out)? },
            }
        }
        d if d == column_sender_numpy_dtype::column_sender_numpy_u32_ipv4 as u32 => {
            NumpyDtype::Ipv4Direct
        }
        d if d == column_sender_numpy_dtype::column_sender_numpy_u16_char as u32 => {
            NumpyDtype::CharDirect
        }
        d if d == column_sender_numpy_dtype::column_sender_numpy_geohash_i8 as u32 => {
            NumpyDtype::GeohashI8 {
                bits: unsafe { validate_geohash_bits(extras, 8, err_out)? },
            }
        }
        d if d == column_sender_numpy_dtype::column_sender_numpy_geohash_i16 as u32 => {
            NumpyDtype::GeohashI16 {
                bits: unsafe { validate_geohash_bits(extras, 16, err_out)? },
            }
        }
        d if d == column_sender_numpy_dtype::column_sender_numpy_geohash_i32 as u32 => {
            NumpyDtype::GeohashI32 {
                bits: unsafe { validate_geohash_bits(extras, 32, err_out)? },
            }
        }
        d if d == column_sender_numpy_dtype::column_sender_numpy_geohash_i64 as u32 => {
            NumpyDtype::GeohashI64 {
                bits: unsafe { validate_geohash_bits(extras, 60, err_out)? },
            }
        }
        d if d == column_sender_numpy_dtype::column_sender_numpy_f64_ndarray as u32 => {
            let (ndim, shape) = unsafe { validate_f64_ndarray(extras, err_out)? };
            NumpyDtype::F64Ndarray { ndim, shape }
        }
        d if d == column_sender_numpy_dtype::column_sender_numpy_datetime64_m as u32 => {
            NumpyDtype::DatetimeMinuteToMicros
        }
        d if d == column_sender_numpy_dtype::column_sender_numpy_datetime64_h as u32 => {
            NumpyDtype::DatetimeHourToMicros
        }
        d if d == column_sender_numpy_dtype::column_sender_numpy_datetime64_D as u32 => {
            NumpyDtype::DatetimeDayToMicros
        }
        d if d == column_sender_numpy_dtype::column_sender_numpy_datetime64_M as u32 => {
            NumpyDtype::DatetimeMonthToMicros
        }
        d if d == column_sender_numpy_dtype::column_sender_numpy_datetime64_Y as u32 => {
            NumpyDtype::DatetimeYearToMicros
        }
        d if d == column_sender_numpy_dtype::column_sender_numpy_datetime64_W as u32 => {
            NumpyDtype::DatetimeWeekToMicros
        }
        d if d == column_sender_numpy_dtype::column_sender_numpy_timedelta64_m as u32
            || d == column_sender_numpy_dtype::column_sender_numpy_timedelta64_h as u32
            || d == column_sender_numpy_dtype::column_sender_numpy_timedelta64_D as u32 =>
        {
            NumpyDtype::LongDirect
        }
        d if d == column_sender_numpy_dtype::column_sender_numpy_timedelta64_M as u32
            || d == column_sender_numpy_dtype::column_sender_numpy_timedelta64_Y as u32 =>
        {
            unsafe {
                set_err_out_from_error(
                    err_out,
                    Error::new(
                        ErrorCode::InvalidApiCall,
                        "timedelta64[M] / timedelta64[Y] are not supported as LONG: \
                         calendar units have variable duration (28-31 days / 365-366 days) \
                         and cannot be represented as a scalar integer offset. \
                         Convert to a fixed unit (s / ms / us / ns / m / h / D) upstream."
                            .to_string(),
                    ),
                );
            }
            return None;
        }
        other => {
            unsafe {
                set_err_out_from_error(
                    err_out,
                    Error::new(
                        ErrorCode::InvalidApiCall,
                        format!(
                            "column_sender_chunk_append_numpy_column: invalid dtype {other} \
                             (expected a column_sender_numpy_* constant)"
                        ),
                    ),
                );
            }
            return None;
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
    dtype: u32,
    data: *const u8,
    row_count: size_t,
    validity: *const column_sender_validity,
    extras: *const column_sender_numpy_extras,
    err_out: *mut *mut line_sender_error,
) -> bool {
    if chunk.is_null() {
        return reject_null_chunk(err_out);
    }
    let _guard = match unsafe {
        InUseGuard::acquire(
            chunk,
            &raw const (*chunk).1,
            "column_sender_chunk_append_numpy_column",
            "column_sender_chunk",
            err_out,
        )
    } {
        Some(g) => g,
        None => return false,
    };
    let name = match unsafe { name_str(name, name_len, err_out) } {
        Some(s) => s,
        None => return false,
    };
    {
        use questdb::ingress::column_sender::MAX_CHUNK_ROWS;
        if row_count > MAX_CHUNK_ROWS {
            unsafe {
                set_err_out_from_error(
                    err_out,
                    Error::new(
                        ErrorCode::InvalidApiCall,
                        format!(
                            "numpy column row_count {row_count} exceeds MAX_CHUNK_ROWS ({MAX_CHUNK_ROWS})"
                        ),
                    ),
                );
            }
            return false;
        }
    }
    if data.is_null() && row_count != 0 {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    format!("numpy column data pointer is NULL with row_count = {row_count}"),
                ),
            );
        }
        return false;
    }
    let validity = match unsafe { as_validity(validity, err_out) } {
        Some(v) => v,
        None => return false,
    };
    let dtype = match unsafe { resolve_numpy_dtype(dtype, extras, err_out) } {
        Some(d) => d,
        None => return false,
    };
    let inner: &mut Chunk = unsafe { &mut (*chunk).0 };
    bubble!(err_out, unsafe {
        inner.push_numpy_deferred(name, dtype, data, row_count, validity.as_ref())
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
    if chunk.is_null() {
        return reject_null_chunk(err_out);
    }
    let _guard = match unsafe {
        InUseGuard::acquire(
            chunk,
            &raw const (*chunk).1,
            "column_sender_chunk_designated_timestamp_micros",
            "column_sender_chunk",
            err_out,
        )
    } {
        Some(g) => g,
        None => return false,
    };
    let data = match unsafe { typed_slice(data, row_count, err_out, "designated_ts micros") } {
        Some(s) => s,
        None => return false,
    };
    let inner: &mut Chunk = unsafe { &mut (*chunk).0 };
    bubble!(err_out, inner.designated_timestamp_micros(data));
    true
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn column_sender_chunk_designated_timestamp_nanos(
    chunk: *mut column_sender_chunk,
    data: *const i64,
    row_count: size_t,
    err_out: *mut *mut line_sender_error,
) -> bool {
    if chunk.is_null() {
        return reject_null_chunk(err_out);
    }
    let _guard = match unsafe {
        InUseGuard::acquire(
            chunk,
            &raw const (*chunk).1,
            "column_sender_chunk_designated_timestamp_nanos",
            "column_sender_chunk",
            err_out,
        )
    } {
        Some(g) => g,
        None => return false,
    };
    let data = match unsafe { typed_slice(data, row_count, err_out, "designated_ts nanos") } {
        Some(s) => s,
        None => return false,
    };
    let inner: &mut Chunk = unsafe { &mut (*chunk).0 };
    bubble!(err_out, inner.designated_timestamp_nanos(data));
    true
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn column_sender_chunk_designated_timestamp_millis(
    chunk: *mut column_sender_chunk,
    data: *const i64,
    row_count: size_t,
    err_out: *mut *mut line_sender_error,
) -> bool {
    if chunk.is_null() {
        return reject_null_chunk(err_out);
    }
    let _guard = match unsafe {
        InUseGuard::acquire(
            chunk,
            &raw const (*chunk).1,
            "column_sender_chunk_designated_timestamp_millis",
            "column_sender_chunk",
            err_out,
        )
    } {
        Some(g) => g,
        None => return false,
    };
    let data = match unsafe { typed_slice(data, row_count, err_out, "designated_ts millis") } {
        Some(s) => s,
        None => return false,
    };
    let inner: &mut Chunk = unsafe { &mut (*chunk).0 };
    bubble!(err_out, inner.designated_timestamp_millis(data));
    true
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn column_sender_chunk_designated_timestamp_seconds(
    chunk: *mut column_sender_chunk,
    data: *const i64,
    row_count: size_t,
    err_out: *mut *mut line_sender_error,
) -> bool {
    if chunk.is_null() {
        return reject_null_chunk(err_out);
    }
    let _guard = match unsafe {
        InUseGuard::acquire(
            chunk,
            &raw const (*chunk).1,
            "column_sender_chunk_designated_timestamp_seconds",
            "column_sender_chunk",
            err_out,
        )
    } {
        Some(g) => g,
        None => return false,
    };
    let data = match unsafe { typed_slice(data, row_count, err_out, "designated_ts seconds") } {
        Some(s) => s,
        None => return false,
    };
    let inner: &mut Chunk = unsafe { &mut (*chunk).0 };
    bubble!(err_out, inner.designated_timestamp_seconds(data));
    true
}

// ===========================================================================
// Flush
// ===========================================================================

/// Encode `chunk` into a QWP/WebSocket frame, publish it, and return
/// immediately without waiting for the server's ack. Direct mode writes to the
/// socket. Store-and-forward mode appends to the local SFA queue.
///
/// In direct mode, ready acks are drained non-blocking before the write.
/// Deferred flushes keep one in-flight slot reserved for the later
/// `column_sender_sync` commit frame; if that reserve would be consumed, the
/// call fails and the caller must sync before flushing more chunks. In SFA mode
/// frames are non-deferred and `flush` success means local queue acceptance.
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
    if conn.is_null() {
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
    let _conn_guard = match unsafe {
        InUseGuard::acquire(
            conn,
            &raw const (*conn).1,
            "column_sender_flush",
            "qwpws_conn",
            err_out,
        )
    } {
        Some(g) => g,
        None => return false,
    };
    if chunk.is_null() {
        return reject_null_chunk(err_out);
    }
    let _chunk_guard = match unsafe {
        InUseGuard::acquire(
            chunk,
            &raw const (*chunk).1,
            "column_sender_flush",
            "column_sender_chunk",
            err_out,
        )
    } {
        Some(g) => g,
        None => return false,
    };
    let sender = unsafe { (*conn).0.get_mut() };
    let chunk_inner: &mut Chunk = unsafe { &mut (*chunk).0 };
    bubble!(err_out, sender.flush(chunk_inner));
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
/// and the function has invoked it internally. On a **transient**
/// (`line_sender_error_failover_retry`) failure `array` is left intact
/// (re-exported back into `*array` with a fresh `release`) so the caller
/// can drop+re-borrow a live conn and retry with the same array. On any
/// other failure `array->release` may have been consumed if the call
/// reached the Arrow import step — callers MUST check `array->release != NULL`
/// before invoking it on the failure path. `schema` is always borrowed.
///
/// Returns `true` on success, `false` on error (with `*err_out` set).
///
/// `overrides` (length `overrides_len`) optionally supplies per-column
/// wire-type hints without requiring the caller to attach `questdb.*`
/// Field metadata to the Arrow schema. Pass `NULL, 0` for no overrides.
/// Returns `false` with `line_sender_error_invalid_api_call` if any
/// override targets an unknown column, duplicates another override,
/// carries invalid UTF-8 in `column`, has an unknown `kind`, or — for
/// `_geohash` — carries `arg` outside `1..=60`.
#[cfg(feature = "arrow")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn column_sender_flush_arrow_batch(
    conn: *mut qwpws_conn,
    table: line_sender_table_name,
    array: *mut arrow::ffi::FFI_ArrowArray,
    schema: *const arrow::ffi::FFI_ArrowSchema,
    overrides: *const column_sender_arrow_override,
    overrides_len: size_t,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        arrow_batch_impl(
            conn,
            table,
            array,
            schema,
            None,
            overrides,
            overrides_len,
            err_out,
        )
    }
}

/// Variant of [`column_sender_flush_arrow_batch`] that sources each
/// row's designated timestamp from a named `Timestamp(_)` column inside
/// the batch. The column must be `Timestamp(Microsecond | Nanosecond |
/// Millisecond, _)` with no null rows and no values before the Unix
/// epoch. Same ownership and `overrides` contract.
#[cfg(feature = "arrow")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn column_sender_flush_arrow_batch_at_column(
    conn: *mut qwpws_conn,
    table: line_sender_table_name,
    array: *mut arrow::ffi::FFI_ArrowArray,
    schema: *const arrow::ffi::FFI_ArrowSchema,
    ts_column: line_sender_column_name,
    overrides: *const column_sender_arrow_override,
    overrides_len: size_t,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        arrow_batch_impl(
            conn,
            table,
            array,
            schema,
            Some(ts_column),
            overrides,
            overrides_len,
            err_out,
        )
    }
}

/// Per-column wire-type hint kind passed in
/// [`column_sender_arrow_override::kind`].
#[cfg(feature = "arrow")]
#[repr(u32)]
#[allow(non_camel_case_types)]
pub enum column_sender_arrow_override_kind {
    column_sender_arrow_override_symbol = 0,
    column_sender_arrow_override_ipv4 = 1,
    column_sender_arrow_override_char = 2,
    column_sender_arrow_override_geohash = 3,
}

/// Per-column wire-type hint that overrides what the encoder would
/// otherwise derive from the Arrow `Field`'s data type alone. Caller
/// owns `column`; the bytes are borrowed for the duration of the
/// `column_sender_flush_arrow_batch[_at_column]` call and must outlive
/// it.
#[cfg(feature = "arrow")]
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct column_sender_arrow_override {
    /// UTF-8 column name; not necessarily NUL-terminated.
    pub column: *const c_char,
    pub column_len: size_t,
    /// One of `column_sender_arrow_override_kind` as `u32`.
    pub kind: u32,
    /// Kind-specific argument:
    /// - `_symbol`: 0 = mark column as `SYMBOL` (default), 1 = force
    ///   the column NOT to be SYMBOL (Dictionary columns are decoded
    ///   to VARCHAR on emit; no-op on plain Utf8 which is VARCHAR
    ///   already).
    /// - `_geohash`: precision bits (1..=60).
    /// - other kinds: ignored; pass 0.
    pub arg: u32,
}

#[cfg(feature = "arrow")]
const MAX_ARROW_OVERRIDES: usize = 65_536;
#[cfg(feature = "arrow")]
const MAX_ARROW_OVERRIDE_COLUMN_NAME_LEN: usize = 65_536;

#[cfg(feature = "arrow")]
unsafe fn arrow_overrides_from_c<'a>(
    overrides: *const column_sender_arrow_override,
    overrides_len: size_t,
    err_out: *mut *mut line_sender_error,
) -> Option<Vec<ArrowColumnOverride<'a>>> {
    if overrides_len == 0 {
        return Some(Vec::new());
    }
    if overrides.is_null() {
        crate::arrow_err_to_c_box(
            err_out,
            ErrorCode::InvalidApiCall,
            "column_sender_flush_arrow_batch: overrides pointer is NULL".to_string(),
        );
        return None;
    }
    if overrides_len > MAX_ARROW_OVERRIDES {
        crate::arrow_err_to_c_box(
            err_out,
            ErrorCode::InvalidApiCall,
            format!("arrow overrides_len {overrides_len} exceeds maximum ({MAX_ARROW_OVERRIDES})"),
        );
        return None;
    }
    let raw = unsafe { std::slice::from_raw_parts(overrides, overrides_len) };
    let mut out = Vec::with_capacity(raw.len());
    for ov in raw {
        if ov.column.is_null() || ov.column_len == 0 {
            crate::arrow_err_to_c_box(
                err_out,
                ErrorCode::InvalidApiCall,
                "arrow override has empty column name".to_string(),
            );
            return None;
        }
        if ov.column_len > MAX_ARROW_OVERRIDE_COLUMN_NAME_LEN {
            crate::arrow_err_to_c_box(
                err_out,
                ErrorCode::InvalidApiCall,
                format!(
                    "arrow override column_len {} exceeds maximum ({MAX_ARROW_OVERRIDE_COLUMN_NAME_LEN})",
                    ov.column_len
                ),
            );
            return None;
        }
        let bytes = unsafe { std::slice::from_raw_parts(ov.column as *const u8, ov.column_len) };
        let column = match str::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => {
                crate::arrow_err_to_c_box(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    "arrow override column name is not valid UTF-8".to_string(),
                );
                return None;
            }
        };
        let parsed = match ov.kind {
            x if x
                == column_sender_arrow_override_kind::column_sender_arrow_override_symbol
                    as u32 =>
            {
                if ov.arg == 0 {
                    ArrowColumnOverride::Symbol { column }
                } else {
                    ArrowColumnOverride::NotSymbol { column }
                }
            }
            x if x
                == column_sender_arrow_override_kind::column_sender_arrow_override_ipv4 as u32 =>
            {
                ArrowColumnOverride::Ipv4 { column }
            }
            x if x
                == column_sender_arrow_override_kind::column_sender_arrow_override_char as u32 =>
            {
                ArrowColumnOverride::Char { column }
            }
            x if x
                == column_sender_arrow_override_kind::column_sender_arrow_override_geohash
                    as u32 =>
            {
                if ov.arg == 0 || ov.arg > 60 {
                    crate::arrow_err_to_c_box(
                        err_out,
                        ErrorCode::InvalidApiCall,
                        format!(
                            "arrow override for column '{}' has invalid geohash bits {} \
                             (must be 1..=60)",
                            column, ov.arg
                        ),
                    );
                    return None;
                }
                ArrowColumnOverride::Geohash {
                    column,
                    bits: ov.arg as u8,
                }
            }
            other => {
                crate::arrow_err_to_c_box(
                    err_out,
                    ErrorCode::InvalidApiCall,
                    format!("unknown arrow override kind {}", other),
                );
                return None;
            }
        };
        out.push(parsed);
    }
    Some(out)
}

#[cfg(feature = "arrow")]
#[allow(clippy::too_many_arguments)]
unsafe fn arrow_batch_impl(
    conn: *mut qwpws_conn,
    table: line_sender_table_name,
    array: *mut arrow::ffi::FFI_ArrowArray,
    schema: *const arrow::ffi::FFI_ArrowSchema,
    ts_column: Option<line_sender_column_name>,
    overrides_ptr: *const column_sender_arrow_override,
    overrides_len: size_t,
    err_out: *mut *mut line_sender_error,
) -> bool {
    if conn.is_null() {
        crate::arrow_err_to_c_box(
            err_out,
            ErrorCode::InvalidApiCall,
            "column_sender_flush_arrow_batch: conn pointer is NULL".to_string(),
        );
        return false;
    }
    let _guard = match unsafe {
        InUseGuard::acquire(
            conn,
            &raw const (*conn).1,
            "column_sender_flush_arrow_batch",
            "qwpws_conn",
            err_out,
        )
    } {
        Some(g) => g,
        None => return false,
    };
    let overrides = match unsafe { arrow_overrides_from_c(overrides_ptr, overrides_len, err_out) } {
        Some(v) => v,
        None => return false,
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
    let sender = unsafe { (*conn).0.get_mut() };
    let result = match ts_column {
        Some(ts) => sender.flush_arrow_batch_at_column(table_name, &rb, ts.as_name(), &overrides),
        None => sender.flush_arrow_batch(table_name, &rb, &overrides),
    };
    match result {
        Ok(()) => true,
        Err(err) => {
            // A transient (reconnectable) failure must leave the caller's
            // `array` intact so it can drop+re-borrow a live conn and retry
            // with the same data. The import already consumed `array->release`,
            // so we re-export the still-live `RecordBatch` back into `*array`,
            // restoring a valid release. A terminal error consumes the array
            // as before (the data is unusable on any conn).
            if err.code() == ErrorCode::FailoverRetry {
                unsafe { reexport_record_batch_into(rb, array) };
            }
            unsafe { set_err_out_from_error(err_out, err) };
            false
        }
    }
}

/// Re-export `rb` back into the caller's `*array` (a Struct array, one child
/// per column — the shape `arrow_ffi_import_record_batch` accepts on retry),
/// restoring `array->release` consumed during import. Best-effort: an export
/// failure leaves `array->release == NULL`, which the caller already must
/// tolerate per the documented ownership contract.
#[cfg(feature = "arrow")]
unsafe fn reexport_record_batch_into(
    rb: arrow_array::RecordBatch,
    array: *mut arrow::ffi::FFI_ArrowArray,
) {
    use arrow_array::{Array, StructArray};
    let struct_array = StructArray::from(rb);
    let array_data = struct_array.into_data();
    if let Ok((ffi_array, _ffi_schema)) = arrow::ffi::to_ffi(&array_data) {
        unsafe { std::ptr::write(array, ffi_array) };
    }
}

/// Block until all in-flight frames are acknowledged at the requested
/// `ack_level`. In direct mode this sends a commit-triggering frame first. In
/// store-and-forward mode all data frames are already non-deferred, so sync
/// waits for the local queue boundary published before the call.
///
/// `column_sender_ack_level_ok` waits for every in-flight frame's
/// WAL-commit ack. `column_sender_ack_level_durable` additionally waits
/// for the server's object-store durability watermarks.
///
/// Returns `true` on success, `false` on error (with `*err_out` set).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn column_sender_sync(
    conn: *mut qwpws_conn,
    ack_level: u32,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let ack_level = match ack_level_from_u32(ack_level, err_out) {
        Some(l) => l,
        None => return false,
    };
    if conn.is_null() {
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
    let _guard = match unsafe {
        InUseGuard::acquire(
            conn,
            &raw const (*conn).1,
            "column_sender_sync",
            "qwpws_conn",
            err_out,
        )
    } {
        Some(g) => g,
        None => return false,
    };
    let sender = unsafe { (*conn).0.get_mut() };
    bubble!(err_out, sender.sync(ack_level));
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

#[cfg(feature = "arrow")]
fn reject_null_arrow_import(err_out: *mut *mut line_sender_error) -> bool {
    unsafe {
        set_err_out_from_error(
            err_out,
            Error::new(
                ErrorCode::InvalidApiCall,
                "column_sender_arrow_import pointer is NULL".to_string(),
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

    #[cfg(feature = "arrow")]
    unsafe extern "C" fn noop_release_array(array: *mut ArrowArray) {
        if !array.is_null() {
            unsafe {
                (*array).release = None;
            }
        }
    }

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
    fn chunk_new_defers_table_name_validation() {
        // The 128-byte name exceeds the QWP 127-byte cap and contains
        // grammatically valid characters; both checks are deferred to
        // flush per the documented contract on `Chunk::new`.
        let mut err: *mut line_sender_error = std::ptr::null_mut();
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
        assert_eq!(
            unsafe { column_sender_chunk_row_count(chunk, std::ptr::null_mut()) },
            3
        );
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
            release: Some(noop_release_array),
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
            release: Some(noop_release_array),
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
        assert_eq!(
            unsafe { column_sender_chunk_row_count(chunk, std::ptr::null_mut()) },
            codes.len()
        );
        unsafe { column_sender_chunk_free(chunk) };
    }

    #[cfg(feature = "arrow")]
    #[test]
    fn arrow_import_append_twice_after_clear() {
        let table = b"trades";
        let mut err: *mut line_sender_error = std::ptr::null_mut();
        let chunk = unsafe {
            column_sender_chunk_new(table.as_ptr() as *const c_char, table.len(), &mut err)
        };
        assert!(!chunk.is_null());

        let value_format = b"U\0";
        let schema = ArrowSchema {
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
        let offsets = [0i64, 5, 9, 14];
        let bytes = b"alphabetagamma";
        let buffers = [
            std::ptr::null(),
            offsets.as_ptr() as *const c_void,
            bytes.as_ptr() as *const c_void,
        ];
        let mut array = ArrowArray {
            length: 3,
            null_count: 0,
            offset: 0,
            n_buffers: 3,
            n_children: 0,
            buffers: buffers.as_ptr(),
            children: std::ptr::null(),
            dictionary: std::ptr::null_mut(),
            release: Some(noop_release_array),
            private_data: std::ptr::null_mut(),
        };

        let imported = unsafe {
            column_sender_arrow_import_new(
                &mut array,
                &schema,
                column_sender_symbol_mode::column_sender_symbol_mode_auto,
                &mut err,
            )
        };
        assert!(!imported.is_null());
        assert!(err.is_null());
        assert!(array.release.is_none());

        let name = b"sym";
        let ok = unsafe {
            column_sender_chunk_append_arrow_import(
                chunk,
                name.as_ptr() as *const c_char,
                name.len(),
                imported,
                0,
                2,
                &mut err,
            )
        };
        assert!(ok);
        assert_eq!(
            unsafe { column_sender_chunk_row_count(chunk, std::ptr::null_mut()) },
            2
        );

        unsafe { column_sender_chunk_clear(chunk, std::ptr::null_mut()) };
        let ok = unsafe {
            column_sender_chunk_append_arrow_import(
                chunk,
                name.as_ptr() as *const c_char,
                name.len(),
                imported,
                1,
                2,
                &mut err,
            )
        };
        assert!(ok);
        assert_eq!(
            unsafe { column_sender_chunk_row_count(chunk, std::ptr::null_mut()) },
            2
        );

        unsafe {
            column_sender_arrow_import_free(imported);
            column_sender_chunk_free(chunk);
        }
    }

    #[cfg(feature = "arrow")]
    #[test]
    fn arrow_import_rejects_double_import() {
        let value_format = b"U\0";
        let schema = ArrowSchema {
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
        let offsets = [0i64, 5];
        let bytes = b"alpha";
        let buffers = [
            std::ptr::null(),
            offsets.as_ptr() as *const c_void,
            bytes.as_ptr() as *const c_void,
        ];
        let mut array = ArrowArray {
            length: 1,
            null_count: 0,
            offset: 0,
            n_buffers: 3,
            n_children: 0,
            buffers: buffers.as_ptr(),
            children: std::ptr::null(),
            dictionary: std::ptr::null_mut(),
            release: Some(noop_release_array),
            private_data: std::ptr::null_mut(),
        };

        let mut err: *mut line_sender_error = std::ptr::null_mut();
        let imported = unsafe {
            column_sender_arrow_import_new(
                &mut array,
                &schema,
                column_sender_symbol_mode::column_sender_symbol_mode_auto,
                &mut err,
            )
        };
        assert!(!imported.is_null());
        assert!(err.is_null());
        assert!(array.release.is_none());

        let second = unsafe {
            column_sender_arrow_import_new(
                &mut array,
                &schema,
                column_sender_symbol_mode::column_sender_symbol_mode_auto,
                &mut err,
            )
        };
        assert!(second.is_null());
        assert!(!err.is_null());

        unsafe {
            line_sender_error_free(err);
            column_sender_arrow_import_free(imported);
        }
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
    fn ack_level_constants_map_correctly() {
        let mut err: *mut line_sender_error = std::ptr::null_mut();
        assert_eq!(
            ack_level_from_u32(column_sender_ack_level_ok, &mut err),
            Some(AckLevel::Ok)
        );
        assert!(err.is_null());
        assert_eq!(
            ack_level_from_u32(column_sender_ack_level_durable, &mut err),
            Some(AckLevel::Durable)
        );
        assert!(err.is_null());
    }

    #[test]
    fn ack_level_rejects_out_of_range() {
        let mut err: *mut line_sender_error = std::ptr::null_mut();
        assert_eq!(ack_level_from_u32(99, &mut err), None);
        assert!(!err.is_null());
        unsafe { line_sender_error_free(err) };
    }
}
