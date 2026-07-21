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

//! C ABI for the unified QWP ingress sender and column-shaped payloads.
//!
//! The live contract is declared in `include/questdb/ingress/qwp_sender.h`.
//! The ABI re-uses `line_sender_error*` for fallible-call error reporting; opaque types
//! (`questdb_db`, `qwp_sender`, `qwp_chunk`) are heap-allocated
//! and freed through their dedicated `_close` / `_free` /
//! `_return_sender` entry points.

#![allow(non_upper_case_globals)]

use libc::{c_char, c_void, size_t};
use std::slice;
use std::str;
use std::sync::atomic::{AtomicU32, Ordering};

use questdb::QuestDb;
use questdb::ffi_support::{OwnedDirectColumnSender, OwnedSender};
#[cfg(feature = "arrow")]
use questdb::ingress::column_sender::{ArrowColumnOverride, FlushFailure, ImportedArrowColumn};
use questdb::ingress::column_sender::{Chunk, NumpyDtype, Validity};
use questdb::ingress::{AckLevel, TimestampUnit};
#[cfg(feature = "arrow")]
use questdb::ingress::{ColumnName, TableName};
use questdb::ingress::{MAX_ARRAY_DIMS, MAX_NDARRAY_LEAF_ELEMS};
use questdb::{Error, ErrorCode};

#[cfg(feature = "arrow")]
use crate::line_sender_column_name;
use crate::{
    line_sender_buffer, line_sender_error, line_sender_error_code, line_sender_opts,
    line_sender_qwpws_error_cb, line_sender_qwpws_fsn, line_sender_table_name, questdb_error,
    qwp_ws_sender_error_view, qwpws_ack_level_durable, qwpws_ack_level_ok, qwpws_buffer_ptr_mut,
    qwpws_buffer_ptr_ref, set_err_out_from_error,
};

// ===========================================================================
// Opaque handles
// ===========================================================================

/// Connection pool. Thread-safe for borrow/return/reap operations while the
/// owning handle remains open. `questdb_db_close` is the final owner release
/// and must not race with other operations on the same `db`.
pub struct questdb_db(pub(crate) QuestDb);

/// Borrowed store-and-forward QWP/WS sender. Owns a pool slot until
/// `questdb_db_return_sender` or `questdb_db_drop_sender`
/// is called. Bundles the per-connection schema registry and symbol-dict state
/// used by all writer modes.
///
/// **Not thread-safe.** A `qwp_sender*` or `qwp_direct_sender*`
/// handle must not be used from more than one thread at a time. The second
/// tuple field is a CAS-checked latch on every FFI entry (mutation, accessor,
/// and free); a non-blocking contending caller observes
/// `line_sender_error_invalid_api_call` instead of a data race. When a
/// return/drop entry point is observed to
/// interleave with an in-flight call (the latch sees `IN_USE` when the free
/// arrives), the box's drop is deferred to the in-flight call's exit path.
/// This deferral only protects the concurrent in-flight-call-vs-free race; it
/// does NOT make a free idempotent.
/// Calling a free/return/drop entry point twice on the same handle (or
/// return-then-drop) is undefined behavior — the second call performs a
/// use-after-free atomic op on the freed box before the latch's CLOSED
/// guard can be evaluated.
///
/// Callers must still ensure happens-before ordering between the last
/// FFI call on `sender` and the matching return/drop call - e.g. by confining
/// `sender` to a single thread, or by an external barrier - so the latch's CAS
/// sees the close intent. A true concurrent free without such ordering is
/// undefined behavior.
pub struct qwp_sender(pub(crate) OwnedSender, pub(crate) AtomicU32);

/// Direct (pipelined, non-store-and-forward) sibling of [`qwp_sender`],
/// borrowed from the always-direct pool via
/// `questdb_db_borrow_direct_sender`. Same single-threaded /
/// reentrancy-latch contract as [`qwp_sender`]; it exposes
/// `qwp_direct_sender_flush` + `qwp_direct_sender_flush_and_wait` +
/// `qwp_direct_sender_commit` instead of the store-and-forward queue
/// primitives exposed by [`qwp_sender`].
pub struct qwp_direct_sender(OwnedDirectColumnSender, AtomicU32);

/// Shared accessor over the two structurally-identical sender handle
/// types so the FFI body helpers (`reject_closed_pool_cs`, `arrow_batch_impl`,
/// the flush / wait helpers) are written once and instantiated for each.
trait CsHandle: FfiHandle + Sized {
    type Owned;

    const TYPE_NAME: &'static str;
    /// # Safety
    /// `this` must be a valid, exclusively-borrowed pointer to a live handle.
    unsafe fn owned_mut<'a>(this: *mut Self) -> &'a mut Self::Owned;
    /// # Safety
    /// `this` must be a valid pointer to a live handle.
    unsafe fn owned_ref<'a>(this: *const Self) -> &'a Self::Owned;
    /// # Safety
    /// `this` must be a valid pointer to a live handle.
    unsafe fn latch<'a>(this: *const Self) -> &'a AtomicU32;

    unsafe fn pool_closed(this: *const Self) -> bool;
    unsafe fn flush(this: *mut Self, chunk: &mut Chunk<'_>) -> questdb::Result<()>;
    unsafe fn flush_and_wait(
        this: *mut Self,
        chunk: &mut Chunk<'_>,
        ack_level: AckLevel,
    ) -> questdb::Result<()>;
    unsafe fn wait_or_commit(
        this: *mut Self,
        ack_level: AckLevel,
        timeout: Option<std::time::Duration>,
    ) -> questdb::Result<()>;

    #[cfg(feature = "arrow")]
    unsafe fn validate_ack_level(this: *const Self, ack_level: AckLevel) -> questdb::Result<()>;
    #[cfg(feature = "arrow")]
    unsafe fn flush_arrow_at_now(
        this: *mut Self,
        table: TableName<'_>,
        batch: &arrow::array::RecordBatch,
        overrides: &[ArrowColumnOverride<'_>],
    ) -> questdb::Result<()>;
    #[cfg(feature = "arrow")]
    unsafe fn flush_arrow_at_column(
        this: *mut Self,
        table: TableName<'_>,
        batch: &arrow::array::RecordBatch,
        ts_column: ColumnName<'_>,
        overrides: &[ArrowColumnOverride<'_>],
    ) -> questdb::Result<()>;
    #[cfg(feature = "arrow")]
    unsafe fn flush_arrow_at_scalar_nanos(
        this: *mut Self,
        table: TableName<'_>,
        batch: &arrow::array::RecordBatch,
        nanos: i64,
        overrides: &[ArrowColumnOverride<'_>],
    ) -> questdb::Result<()>;
    #[cfg(feature = "arrow")]
    unsafe fn flush_arrow_at_now_and_wait(
        this: *mut Self,
        table: TableName<'_>,
        batch: &arrow::array::RecordBatch,
        overrides: &[ArrowColumnOverride<'_>],
        ack_level: AckLevel,
    ) -> std::result::Result<(), FlushFailure>;
    #[cfg(feature = "arrow")]
    unsafe fn flush_arrow_at_column_and_wait(
        this: *mut Self,
        table: TableName<'_>,
        batch: &arrow::array::RecordBatch,
        ts_column: ColumnName<'_>,
        overrides: &[ArrowColumnOverride<'_>],
        ack_level: AckLevel,
    ) -> std::result::Result<(), FlushFailure>;
}

impl CsHandle for qwp_sender {
    type Owned = OwnedSender;

    const TYPE_NAME: &'static str = "qwp_sender";
    unsafe fn owned_mut<'a>(this: *mut Self) -> &'a mut OwnedSender {
        unsafe { &mut (*this).0 }
    }
    unsafe fn owned_ref<'a>(this: *const Self) -> &'a OwnedSender {
        unsafe { &(*this).0 }
    }
    unsafe fn latch<'a>(this: *const Self) -> &'a AtomicU32 {
        unsafe { &(*this).1 }
    }

    unsafe fn pool_closed(this: *const Self) -> bool {
        unsafe { Self::owned_ref(this).pool_closed() }
    }

    unsafe fn flush(this: *mut Self, chunk: &mut Chunk<'_>) -> questdb::Result<()> {
        unsafe { Self::owned_mut(this).get_mut().flush(chunk) }
    }

    unsafe fn flush_and_wait(
        this: *mut Self,
        chunk: &mut Chunk<'_>,
        ack_level: AckLevel,
    ) -> questdb::Result<()> {
        unsafe {
            Self::owned_mut(this)
                .get_mut()
                .flush_and_wait(chunk, ack_level)
        }
    }

    unsafe fn wait_or_commit(
        this: *mut Self,
        ack_level: AckLevel,
        timeout: Option<std::time::Duration>,
    ) -> questdb::Result<()> {
        unsafe {
            Self::owned_mut(this)
                .get_mut()
                .wait(ack_level, timeout.unwrap_or(std::time::Duration::ZERO))
        }
    }

    #[cfg(feature = "arrow")]
    unsafe fn validate_ack_level(this: *const Self, ack_level: AckLevel) -> questdb::Result<()> {
        unsafe { Self::owned_ref(this).get().validate_ack_level(ack_level) }
    }

    #[cfg(feature = "arrow")]
    unsafe fn flush_arrow_at_now(
        this: *mut Self,
        table: TableName<'_>,
        batch: &arrow::array::RecordBatch,
        overrides: &[ArrowColumnOverride<'_>],
    ) -> questdb::Result<()> {
        unsafe {
            Self::owned_mut(this)
                .get_mut()
                .flush_arrow_batch_at_now(table, batch, overrides)
        }
    }

    #[cfg(feature = "arrow")]
    unsafe fn flush_arrow_at_column(
        this: *mut Self,
        table: TableName<'_>,
        batch: &arrow::array::RecordBatch,
        ts_column: ColumnName<'_>,
        overrides: &[ArrowColumnOverride<'_>],
    ) -> questdb::Result<()> {
        unsafe {
            Self::owned_mut(this)
                .get_mut()
                .flush_arrow_batch_at_column(table, batch, ts_column, overrides)
        }
    }

    #[cfg(feature = "arrow")]
    unsafe fn flush_arrow_at_scalar_nanos(
        this: *mut Self,
        table: TableName<'_>,
        batch: &arrow::array::RecordBatch,
        nanos: i64,
        overrides: &[ArrowColumnOverride<'_>],
    ) -> questdb::Result<()> {
        unsafe {
            Self::owned_mut(this)
                .get_mut()
                .flush_arrow_batch_at_scalar_nanos(table, batch, nanos, overrides)
        }
    }

    #[cfg(feature = "arrow")]
    unsafe fn flush_arrow_at_now_and_wait(
        this: *mut Self,
        table: TableName<'_>,
        batch: &arrow::array::RecordBatch,
        overrides: &[ArrowColumnOverride<'_>],
        ack_level: AckLevel,
    ) -> std::result::Result<(), FlushFailure> {
        unsafe {
            Self::owned_mut(this)
                .get_mut()
                .flush_arrow_batch_at_now_and_wait_ffi(table, batch, overrides, ack_level)
        }
    }

    #[cfg(feature = "arrow")]
    unsafe fn flush_arrow_at_column_and_wait(
        this: *mut Self,
        table: TableName<'_>,
        batch: &arrow::array::RecordBatch,
        ts_column: ColumnName<'_>,
        overrides: &[ArrowColumnOverride<'_>],
        ack_level: AckLevel,
    ) -> std::result::Result<(), FlushFailure> {
        unsafe {
            Self::owned_mut(this)
                .get_mut()
                .flush_arrow_batch_at_column_and_wait_ffi(
                    table, batch, ts_column, overrides, ack_level,
                )
        }
    }
}

impl CsHandle for qwp_direct_sender {
    type Owned = OwnedDirectColumnSender;

    const TYPE_NAME: &'static str = "qwp_direct_sender";
    unsafe fn owned_mut<'a>(this: *mut Self) -> &'a mut OwnedDirectColumnSender {
        unsafe { &mut (*this).0 }
    }
    unsafe fn owned_ref<'a>(this: *const Self) -> &'a OwnedDirectColumnSender {
        unsafe { &(*this).0 }
    }
    unsafe fn latch<'a>(this: *const Self) -> &'a AtomicU32 {
        unsafe { &(*this).1 }
    }

    unsafe fn pool_closed(this: *const Self) -> bool {
        unsafe { Self::owned_ref(this).pool_closed() }
    }

    unsafe fn flush(this: *mut Self, chunk: &mut Chunk<'_>) -> questdb::Result<()> {
        unsafe { Self::owned_mut(this).get_mut().flush(chunk) }
    }

    unsafe fn flush_and_wait(
        this: *mut Self,
        chunk: &mut Chunk<'_>,
        ack_level: AckLevel,
    ) -> questdb::Result<()> {
        unsafe {
            Self::owned_mut(this)
                .get_mut()
                .flush_and_wait(chunk, ack_level)
        }
    }

    unsafe fn wait_or_commit(
        this: *mut Self,
        ack_level: AckLevel,
        _timeout: Option<std::time::Duration>,
    ) -> questdb::Result<()> {
        unsafe { Self::owned_mut(this).get_mut().sync(ack_level) }
    }

    #[cfg(feature = "arrow")]
    unsafe fn validate_ack_level(this: *const Self, ack_level: AckLevel) -> questdb::Result<()> {
        unsafe { Self::owned_ref(this).get().validate_ack_level(ack_level) }
    }

    #[cfg(feature = "arrow")]
    unsafe fn flush_arrow_at_now(
        this: *mut Self,
        table: TableName<'_>,
        batch: &arrow::array::RecordBatch,
        overrides: &[ArrowColumnOverride<'_>],
    ) -> questdb::Result<()> {
        unsafe {
            Self::owned_mut(this)
                .get_mut()
                .flush_arrow_batch_at_now(table, batch, overrides)
        }
    }

    #[cfg(feature = "arrow")]
    unsafe fn flush_arrow_at_column(
        this: *mut Self,
        table: TableName<'_>,
        batch: &arrow::array::RecordBatch,
        ts_column: ColumnName<'_>,
        overrides: &[ArrowColumnOverride<'_>],
    ) -> questdb::Result<()> {
        unsafe {
            Self::owned_mut(this)
                .get_mut()
                .flush_arrow_batch_at_column(table, batch, ts_column, overrides)
        }
    }

    #[cfg(feature = "arrow")]
    unsafe fn flush_arrow_at_scalar_nanos(
        this: *mut Self,
        table: TableName<'_>,
        batch: &arrow::array::RecordBatch,
        nanos: i64,
        overrides: &[ArrowColumnOverride<'_>],
    ) -> questdb::Result<()> {
        unsafe {
            Self::owned_mut(this)
                .get_mut()
                .flush_arrow_batch_at_scalar_nanos(table, batch, nanos, overrides)
        }
    }

    #[cfg(feature = "arrow")]
    unsafe fn flush_arrow_at_now_and_wait(
        this: *mut Self,
        table: TableName<'_>,
        batch: &arrow::array::RecordBatch,
        overrides: &[ArrowColumnOverride<'_>],
        ack_level: AckLevel,
    ) -> std::result::Result<(), FlushFailure> {
        unsafe {
            Self::owned_mut(this)
                .get_mut()
                .flush_arrow_batch_at_now_and_wait_ffi(table, batch, overrides, ack_level)
        }
    }

    #[cfg(feature = "arrow")]
    unsafe fn flush_arrow_at_column_and_wait(
        this: *mut Self,
        table: TableName<'_>,
        batch: &arrow::array::RecordBatch,
        ts_column: ColumnName<'_>,
        overrides: &[ArrowColumnOverride<'_>],
        ack_level: AckLevel,
    ) -> std::result::Result<(), FlushFailure> {
        unsafe {
            Self::owned_mut(this)
                .get_mut()
                .flush_arrow_batch_at_column_and_wait_ffi(
                    table, batch, ts_column, overrides, ack_level,
                )
        }
    }
}

/// One DataFrame's worth of column buffers destined for one QuestDB table.
/// Owned by the caller; not bound to a connection.
///
/// Holds raw pointers into caller buffers (no copy). Per the FFI ABI
/// doc §2.3, the caller MUST keep every column buffer passed in via
/// `qwp_chunk_column_*` / `qwp_chunk_append_*`
/// alive until the next `qwp_sender_flush_chunk` call returns. We hide the
/// chunk's lifetime by promoting its inner type to `'static`; the lifetime
/// is enforced by the caller, not the borrow checker.
///
/// **Not thread-safe.** Single-threaded by contract; the latch in the
/// second tuple field detects in-thread reentrance and defers a free
/// observed concurrently with an in-flight call until that call exits.
/// This protects only the concurrent in-flight-call-vs-free race; it
/// does not make a free idempotent — calling `qwp_chunk_free`
/// twice on the same handle is undefined behavior. The same caveat as
/// [`qwp_sender`] applies: the caller must establish happens-before
/// between the last column call on `chunk` and
/// `qwp_chunk_free(chunk)`.
pub struct qwp_chunk(Chunk<'static>, AtomicU32);

/// Imported Arrow column for repeated chunk appends.
///
/// **Not thread-safe.** Python owns this per-plan and uses it from one thread.
/// The latch rejects concurrent append/free on the FFI surface.
#[cfg(feature = "arrow")]
pub struct qwp_arrow_import(ImportedArrowColumn, AtomicU32);

const LATCH_IN_USE: u32 = 1 << 0;
const LATCH_CLOSED: u32 = 1 << 1;
const LATCH_DROP: u32 = 1 << 2;

trait FfiHandle {
    unsafe fn on_deferred_close(handle: *mut Self, latch_prev: u32);
}

impl FfiHandle for qwp_chunk {
    unsafe fn on_deferred_close(_handle: *mut Self, _latch_prev: u32) {}
}

#[cfg(feature = "arrow")]
impl FfiHandle for qwp_arrow_import {
    unsafe fn on_deferred_close(_handle: *mut Self, _latch_prev: u32) {}
}

impl FfiHandle for qwp_sender {
    unsafe fn on_deferred_close(handle: *mut Self, latch_prev: u32) {
        if latch_prev & LATCH_DROP != 0 {
            unsafe { (*handle).0.get_mut().mark_must_close() };
        }
    }
}

impl FfiHandle for qwp_direct_sender {
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

unsafe fn reject_closed_pool_cs<T: CsHandle>(
    sender: *const T,
    fn_name: &str,
    err_out: *mut *mut line_sender_error,
) -> bool {
    if unsafe { T::pool_closed(sender) } {
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

unsafe fn reject_null_fsn_out(
    fsn_out: *mut line_sender_qwpws_fsn,
    fn_name: &str,
    err_out: *mut *mut line_sender_error,
) -> bool {
    if fsn_out.is_null() {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    format!("{fn_name} requires non-NULL fsn_out"),
                ),
            );
        }
        true
    } else {
        false
    }
}

// ===========================================================================
// Validity bitmap (Arrow shape: bit = 1 means valid, LSB-first).
// ===========================================================================

#[repr(C)]
#[derive(Copy, Clone)]
pub struct qwp_validity {
    pub bits: *const u8,
    pub bit_len: size_t,
}

unsafe fn as_validity<'a>(
    v: *const qwp_validity,
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
                        "qwp_validity bit_len {} exceeds MAX_CHUNK_ROWS ({MAX_CHUNK_ROWS})",
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
                    "qwp_validity has null bits but bit_len != 0".to_string(),
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
// The C header exposes named constants (`qwpws_ack_level_ok = 0`,
// `qwpws_ack_level_durable = 1`) but the FFI takes a `uint32_t`
// (not a `#[repr(C)] enum`) so an out-of-range value is a recoverable
// `InvalidApiCall` error instead of immediate Rust UB.
// ===========================================================================

fn ack_level_from_u32(value: u32, err_out: *mut *mut line_sender_error) -> Option<AckLevel> {
    match value {
        value if value == qwpws_ack_level_ok => Some(AckLevel::Ok),
        value if value == qwpws_ack_level_durable => Some(AckLevel::Durable),
        other => {
            unsafe {
                set_err_out_from_error(
                    err_out,
                    Error::new(
                        ErrorCode::InvalidApiCall,
                        format!("ws ack_level: invalid value {other} (expected 0 or 1)"),
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
    if name_len > isize::MAX as usize {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    "name length exceeds the maximum addressable size".to_string(),
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

/// Offsets length bound for a symbol/categorical dictionary, whose entry count
/// is independent of the chunk row count (a `Categorical` can have many more
/// distinct values than rows). Bounded by the symbol-dictionary ceiling, not
/// `MAX_CHUNK_ROWS`.
unsafe fn typed_dict_offsets_slice<'a, T>(
    data: *const T,
    len: size_t,
    err_out: *mut *mut line_sender_error,
    what: &'static str,
) -> Option<&'a [T]> {
    use questdb::ingress::column_sender::MAX_SYMBOL_DICT_ENTRIES;
    let max = MAX_SYMBOL_DICT_ENTRIES + 1;
    unsafe { typed_slice_bounded(data, len, max, "MAX_SYMBOL_DICT_ENTRIES+1", err_out, what) }
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

// ===========================================================================
// Pool
// ===========================================================================

/// Open a connection pool. The pool is lazy: this call parses and validates
/// the connect string but opens no connections; the first borrow opens one,
/// so server/auth/TLS errors surface from the borrow, not from here. `conf`
/// is a UTF-8 string of `conf_len` bytes.
///
/// Returns NULL on failure. When `err_out != NULL`, the error is placed
/// in `*err_out` and ownership transfers to the caller (release with
/// `questdb_error_free`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_db_connect(
    conf: *const c_char,
    conf_len: size_t,
    err_out: *mut *mut questdb_error,
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

/// Close the pool. Accepts NULL and no-ops.
///
/// Final owner release: callers must ensure no other thread is concurrently
/// using `db` for borrow/reap/config operations. This invalidates the
/// `questdb_db*` for new borrows and closes idle connections.
/// Outstanding `qwp_sender` handles are independent leases:
/// return/drop remains safe after close, but new operations on them fail with
/// `InvalidApiCall`. A handle returned after close is closed, not recycled.
/// Close also detaches and joins the connection-event and rejection
/// dispatchers; after this function returns no callback can use its
/// `user_data`, including callbacks from an outstanding sender's background
/// runner. Exception: when close is called from a dispatcher thread, that
/// thread is not joined (avoiding a self-join deadlock) and its in-flight
/// callback finishes after close returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_db_close(db: *mut questdb_db) {
    if !db.is_null() {
        unsafe { drop(Box::from_raw(db)) };
    }
}

/// Create a caller-owned QWP/WebSocket row buffer using the pool's configured
/// name limit. The buffer is independent of any sender lease and may be filled
/// before or after `questdb_db_borrow_sender`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_db_new_buffer(
    db: *const questdb_db,
    err_out: *mut *mut line_sender_error,
) -> *mut line_sender_buffer {
    if db.is_null() {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    "questdb_db_new_buffer: db pointer is NULL".to_string(),
                ),
            );
        }
        return std::ptr::null_mut();
    }
    let buffer = unsafe { &*db }.0.new_buffer();
    Box::into_raw(Box::new(line_sender_buffer {
        buffer,
        empty_peek_buf_is_null: true,
    }))
}

/// Return the configured name limit used by `questdb_db_new_buffer`, or zero
/// for a NULL pool pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_db_buffer_max_name_len(db: *const questdb_db) -> size_t {
    if db.is_null() {
        return 0;
    }
    unsafe { &*db }.0.buffer_max_name_len()
}

/// Shared borrow body for both handle flavors: NULL-checks `db`, runs the
/// owned-borrow closure, and boxes the result into the right opaque handle
/// (`make` is the tuple-struct constructor, e.g. `qwp_sender`).
unsafe fn borrow_cs<T, O>(
    db: *mut questdb_db,
    fn_name: &str,
    err_out: *mut *mut line_sender_error,
    do_borrow: impl FnOnce(&questdb::QuestDb) -> questdb::Result<O>,
    make: fn(O, AtomicU32) -> T,
) -> *mut T {
    if db.is_null() {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    format!("{fn_name}: db pointer is NULL"),
                ),
            );
        }
        return std::ptr::null_mut();
    }
    let db_ref = unsafe { &*db };
    match do_borrow(&db_ref.0) {
        Ok(owned) => Box::into_raw(Box::new(make(owned, AtomicU32::new(0)))),
        Err(err) => {
            unsafe { set_err_out_from_error(err_out, err) };
            std::ptr::null_mut()
        }
    }
}

/// Borrow a store-and-forward QWP/WS connection from the unified ingestion
/// pool. Returns NULL on failure; sets `*err_out` if provided.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_db_borrow_sender(
    db: *mut questdb_db,
    err_out: *mut *mut line_sender_error,
) -> *mut qwp_sender {
    unsafe {
        borrow_cs(
            db,
            "questdb_db_borrow_sender",
            err_out,
            questdb::ffi_support::borrow_sender_owned,
            qwp_sender,
        )
    }
}

/// Borrow a direct (pipelined, non-store-and-forward) connection from the
/// always-direct pool. Returns NULL on failure; sets `*err_out` if provided.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_db_borrow_direct_sender(
    db: *mut questdb_db,
    err_out: *mut *mut line_sender_error,
) -> *mut qwp_direct_sender {
    unsafe {
        borrow_cs(
            db,
            "questdb_db_borrow_direct_sender",
            err_out,
            questdb::ffi_support::borrow_direct_column_sender_owned,
            qwp_direct_sender,
        )
    }
}

/// Like `questdb_db_borrow_sender` but retries the connect within
/// `budget_ms` using the pool's reconnect backoff (centered-jittered
/// exponential with a role-reject reset; `AuthError` / protocol-version errors
/// are terminal). `budget_ms == 0` makes a single attempt (no retry). Returns
/// NULL on failure; sets `*err_out` if provided.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_db_borrow_sender_with_retry(
    db: *mut questdb_db,
    budget_ms: u64,
    err_out: *mut *mut line_sender_error,
) -> *mut qwp_sender {
    unsafe {
        borrow_cs(
            db,
            "questdb_db_borrow_sender_with_retry",
            err_out,
            |q| {
                questdb::ffi_support::borrow_sender_owned_with_retry(
                    q,
                    std::time::Duration::from_millis(budget_ms),
                )
            },
            qwp_sender,
        )
    }
}

/// Like `questdb_db_borrow_direct_sender` but retries the connect
/// within `budget_ms` using the same reconnect backoff. `budget_ms == 0`
/// makes a single attempt. Returns NULL on failure; sets `*err_out` if provided.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_db_borrow_direct_sender_with_retry(
    db: *mut questdb_db,
    budget_ms: u64,
    err_out: *mut *mut line_sender_error,
) -> *mut qwp_direct_sender {
    unsafe {
        borrow_cs(
            db,
            "questdb_db_borrow_direct_sender_with_retry",
            err_out,
            |q| {
                questdb::ffi_support::borrow_direct_column_sender_owned_with_retry(
                    q,
                    std::time::Duration::from_millis(budget_ms),
                )
            },
            qwp_direct_sender,
        )
    }
}

/// Build a direct (pipelined, non-store-and-forward) column sender from a
/// QWP/WebSocket config string, owning its own connection with no pool. `conf`
/// is a UTF-8 string of `conf_len` bytes. Free the returned handle with
/// `qwp_direct_sender_free`; there is no pool to return it to. Returns NULL
/// on failure; sets `*err_out` if provided.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_direct_sender_from_conf(
    conf: *const c_char,
    conf_len: size_t,
    err_out: *mut *mut line_sender_error,
) -> *mut qwp_direct_sender {
    let conf = match unsafe { name_str(conf, conf_len, err_out) } {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    match questdb::ffi_support::direct_column_sender_from_conf(conf) {
        Ok(owned) => Box::into_raw(Box::new(qwp_direct_sender(owned, AtomicU32::new(0)))),
        Err(err) => {
            unsafe { set_err_out_from_error(err_out, err) };
            std::ptr::null_mut()
        }
    }
}

/// Build a direct (pipelined, non-store-and-forward) column sender from a
/// configured `line_sender_opts`, owning its own connection with no pool. The
/// opts carry the full auth/TLS configuration (including options set through
/// the `line_sender_opts_*` builder functions rather than a config string), so
/// this works for senders built either way. `opts` is borrowed, not consumed:
/// the caller retains ownership and must still free it. Free the returned
/// handle with `qwp_direct_sender_free`. Returns NULL on failure; sets
/// `*err_out` if provided.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_direct_sender_from_opts(
    opts: *const line_sender_opts,
    err_out: *mut *mut line_sender_error,
) -> *mut qwp_direct_sender {
    if opts.is_null() {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    "qwp_direct_sender_from_opts: opts pointer is NULL".to_string(),
                ),
            );
        }
        return std::ptr::null_mut();
    }
    let builder = unsafe { &*opts }.builder();
    match questdb::ffi_support::direct_column_sender_from_opts(builder) {
        Ok(owned) => Box::into_raw(Box::new(qwp_direct_sender(owned, AtomicU32::new(0)))),
        Err(err) => {
            unsafe { set_err_out_from_error(err_out, err) };
            std::ptr::null_mut()
        }
    }
}

/// The pool's failover budget (`reconnect_max_duration`, default 300000 ms).
/// Callers tracking an overall failover deadline pass the remaining budget to
/// `questdb_db_borrow_sender_with_retry`. Returns 0 if `db` is NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_db_reconnect_max_duration_ms(db: *const questdb_db) -> u64 {
    if db.is_null() {
        return 0;
    }
    let db_ref = unsafe { &*db };
    u64::try_from(questdb::ffi_support::reconnect_max_duration(&db_ref.0).as_millis())
        .unwrap_or(u64::MAX)
}

/// Return a borrowed sender to the pool. Invalidates `sender`. Accepts NULL
/// and no-ops. `db` is ignored — kept in the ABI for symmetry. If the sender
/// has latched terminal state, or if the pool has been closed, the sender is
/// closed instead of recycled.
///
/// A racing in-flight call on the same handle defers the drop to that
/// call's exit path, which performs the actual `Box::from_raw`. This
/// covers only the concurrent in-flight-call-vs-free race. It is NOT a
/// double-free guard: mutually exclusive with the matching drop entry point on
/// the same `sender` - call exactly one of return/drop. Calling both (or either
/// twice) is UB.
unsafe fn return_or_drop_cs<T: CsHandle>(sender: *mut T, extra: u32) {
    if sender.is_null() {
        return;
    }
    let state: *const AtomicU32 = unsafe { T::latch(sender) };
    unsafe { finalize_or_defer(sender, state, extra) };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_db_return_sender(_db: *mut questdb_db, sender: *mut qwp_sender) {
    unsafe { return_or_drop_cs(sender, 0) };
}

/// Direct-handle counterpart of `questdb_db_return_sender`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_db_return_direct_sender(
    _db: *mut questdb_db,
    sender: *mut qwp_direct_sender,
) {
    unsafe { return_or_drop_cs(sender, 0) };
}

/// Force-drop a borrowed sender instead of recycling it. Marks the sender terminal
/// so the underlying backend is removed from the pool. In store-and-forward
/// mode with `sf_dir`, unresolved frames remain in the spool for replay by the
/// next owner; without `sf_dir`, force-dropping may discard undelivered queued
/// frames after the bounded close drain. Call `qwp_sender_wait` before
/// drop if those frames must be delivered. Accepts NULL and no-ops. As with
/// `questdb_db_return_sender`, a racing in-flight call defers the
/// drop to that call's exit path; this covers only the concurrent
/// in-flight-call-vs-free race. Mutually exclusive with
/// `questdb_db_return_sender` on the same `sender` - call exactly one
/// of the two. Calling both (or either twice) is UB.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_db_drop_sender(_db: *mut questdb_db, sender: *mut qwp_sender) {
    unsafe { return_or_drop_cs(sender, LATCH_DROP) };
}

/// Direct-handle counterpart of `questdb_db_drop_sender`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_db_drop_direct_sender(
    _db: *mut questdb_db,
    sender: *mut qwp_direct_sender,
) {
    unsafe { return_or_drop_cs(sender, LATCH_DROP) };
}

/// Free a standalone `qwp_direct_sender_from_conf` handle, committing any
/// un-sync'd deferred frames first (call `qwp_direct_sender_commit` or a
/// waited flush beforehand for delivery certainty). Accepts NULL and no-ops.
/// For a pool-borrowed handle use `questdb_db_return_direct_sender`
/// instead. A racing in-flight call defers the free to that call's exit path.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_direct_sender_free(sender: *mut qwp_direct_sender) {
    unsafe { return_or_drop_cs(sender, 0) };
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

/// Connection lifecycle event kinds. Values mirror
/// `questdb::ingress::ConnectionEventKind`.
pub const questdb_connection_event_connected: u32 = 0;
pub const questdb_connection_event_disconnected: u32 = 1;
pub const questdb_connection_event_reconnected: u32 = 2;
pub const questdb_connection_event_failed_over: u32 = 3;
pub const questdb_connection_event_endpoint_attempt_failed: u32 = 4;
pub const questdb_connection_event_all_endpoints_unreachable: u32 = 5;
pub const questdb_connection_event_auth_failed: u32 = 6;

/// One connection-state transition, delivered to a
/// `questdb_connection_event_cb`. String fields are borrowed UTF-8
/// slices valid only for the duration of the callback; absent strings
/// are `NULL` with length `0`.
#[repr(C)]
pub struct questdb_connection_event {
    /// One of the `questdb_connection_event_*` kind constants.
    pub kind: u32,
    pub host: *const c_char,
    pub host_len: size_t,
    pub port: *const c_char,
    pub port_len: size_t,
    pub previous_host: *const c_char,
    pub previous_host_len: size_t,
    pub previous_port: *const c_char,
    pub previous_port_len: size_t,
    pub has_attempt: bool,
    pub attempt_number: u64,
    pub has_cause: bool,
    pub cause_code: line_sender_error_code,
    pub cause_msg: *const c_char,
    pub cause_msg_len: size_t,
    /// Wall-clock time of the event, milliseconds since the Unix epoch.
    pub timestamp_millis: i64,
}

/// Callback invoked on a dedicated dispatcher thread — never on an I/O
/// or producer thread — once per connection event. Connected, reconnected,
/// and failed-over events are queued only after negotiated connection state,
/// including the server-advertised frame cap, is committed; they are not data
/// delivery or acknowledgement barriers. The `event` pointer
/// (and every string it references) is valid only for the duration of
/// the call. The callback must not unwind.
pub type questdb_connection_event_cb =
    unsafe extern "C" fn(user_data: *mut c_void, event: *const questdb_connection_event);

struct ConnectionEventCbHandle {
    callback: questdb_connection_event_cb,
    user_data: *mut c_void,
}

// The dispatcher thread invokes the callback; the caller promises
// `user_data` is safe to use from that thread (documented contract,
// same as `line_sender_opts_qwpws_error_handler`).
unsafe impl Send for ConnectionEventCbHandle {}
unsafe impl Sync for ConnectionEventCbHandle {}

impl ConnectionEventCbHandle {
    fn invoke(&self, view: &questdb_connection_event) {
        unsafe { (self.callback)(self.user_data, view) };
    }
}

fn str_or_null(value: Option<&str>) -> (*const c_char, size_t) {
    match value {
        Some(s) => (s.as_ptr() as *const c_char, s.len()),
        None => (std::ptr::null(), 0),
    }
}

/// Adapt a C callback + user_data pair into a [`ConnectionListener`].
/// The caller guarantees `user_data` is safe to use from the dispatcher
/// thread.
pub(crate) fn connection_listener_from_c(
    callback: questdb_connection_event_cb,
    user_data: *mut c_void,
) -> questdb::ingress::ConnectionListener {
    let handle = ConnectionEventCbHandle {
        callback,
        user_data,
    };
    std::sync::Arc::new(move |event: &questdb::ingress::ConnectionEvent| {
        let kind = match event.kind {
            questdb::ingress::ConnectionEventKind::Connected => questdb_connection_event_connected,
            questdb::ingress::ConnectionEventKind::Disconnected => {
                questdb_connection_event_disconnected
            }
            questdb::ingress::ConnectionEventKind::Reconnected => {
                questdb_connection_event_reconnected
            }
            questdb::ingress::ConnectionEventKind::FailedOver => {
                questdb_connection_event_failed_over
            }
            questdb::ingress::ConnectionEventKind::EndpointAttemptFailed => {
                questdb_connection_event_endpoint_attempt_failed
            }
            questdb::ingress::ConnectionEventKind::AllEndpointsUnreachable => {
                questdb_connection_event_all_endpoints_unreachable
            }
            questdb::ingress::ConnectionEventKind::AuthFailed => {
                questdb_connection_event_auth_failed
            }
            _ => return,
        };
        let (host, host_len) = str_or_null(event.host.as_deref());
        let (port, port_len) = str_or_null(event.port.as_deref());
        let (previous_host, previous_host_len) = str_or_null(event.previous_host.as_deref());
        let (previous_port, previous_port_len) = str_or_null(event.previous_port.as_deref());
        let (cause_msg, cause_msg_len) = str_or_null(event.cause_msg.as_deref());
        let view = questdb_connection_event {
            kind,
            host,
            host_len,
            port,
            port_len,
            previous_host,
            previous_host_len,
            previous_port,
            previous_port_len,
            has_attempt: event.attempt_number.is_some(),
            attempt_number: event.attempt_number.unwrap_or(0),
            has_cause: event.cause_code.is_some(),
            cause_code: event.cause_code.unwrap_or(ErrorCode::InvalidApiCall).into(),
            cause_msg,
            cause_msg_len,
            timestamp_millis: event.timestamp_millis,
        };
        handle.invoke(&view);
    })
}

/// `questdb_db_connect` with a connection lifecycle listener. Events fire
/// for every ingress pool connect (initial connect, per-endpoint attempt
/// failures, all-endpoints-unreachable sweeps, failover to a different
/// endpoint, terminal auth rejection) and for transport deaths observed
/// when a connection is returned.
///
/// Delivery is via a bounded inbox (`inbox_capacity`; `0` = default 64)
/// drained by a dedicated dispatcher thread: a slow callback cannot
/// stall connects or publishing, and on overflow the oldest undelivered
/// event is dropped. Direct and store-and-forward senders share one source
/// and inbox.
///
/// The handler is registered before the pool opens anything, so it observes
/// every transition — including the initial `connected` of disk recovery
/// senders pre-opened by this call. This is the only way to attach a
/// handler; there is no post-connect registration. The caller guarantees
/// `user_data` is safe to use from the dispatcher thread until
/// `questdb_db_close` returns. On failure (NULL return) the dispatcher is
/// already torn down: no callback runs after this function returns and
/// `user_data` may be released immediately.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_db_connect_with_event_handler(
    conf: *const c_char,
    conf_len: size_t,
    callback: questdb_connection_event_cb,
    user_data: *mut c_void,
    inbox_capacity: size_t,
    err_out: *mut *mut questdb_error,
) -> *mut questdb_db {
    let conf = match unsafe { name_str(conf, conf_len, err_out) } {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    let listener = connection_listener_from_c(callback, user_data);
    match QuestDb::connect_with_listener(conf, listener, inbox_capacity) {
        Ok(db) => Box::into_raw(Box::new(questdb_db(db))),
        Err(err) => {
            unsafe { set_err_out_from_error(err_out, err) };
            std::ptr::null_mut()
        }
    }
}

/// Total connection events discarded by the listener inbox's drop-oldest
/// policy. `0` for a NULL `db` or when no listener is registered.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_db_connection_events_dropped(db: *const questdb_db) -> u64 {
    if db.is_null() {
        return 0;
    }
    let db_ref = unsafe { &*db };
    db_ref.0.connection_events_dropped()
}

/// Total connection events delivered to the listener. `0` for a NULL
/// `db` or when no listener is registered.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_db_connection_events_delivered(db: *const questdb_db) -> u64 {
    if db.is_null() {
        return 0;
    }
    let db_ref = unsafe { &*db };
    db_ref.0.connection_events_delivered()
}

/// Like `questdb_db_connect_with_event_handler`, additionally registering a
/// server-rejection handler. Either callback may be NULL: a NULL
/// `event_callback` disables connection lifecycle events; a NULL
/// `rejection_callback` selects the default behaviour of logging every
/// rejection (warn for retriable policies — the frames are replayed, not
/// lost — error for terminal ones), so silence is never the default.
///
/// The rejection handler receives every server rejection any of the pool's
/// store-and-forward connections records — including rejections for frames
/// whose sender was already returned to the pool — on a dedicated dispatcher
/// thread through a bounded inbox (`rejection_inbox_capacity`; `0` = default
/// 64; overflow drops the oldest event, counted by
/// `questdb_db_rejection_events_dropped`). The caller guarantees each
/// `user_data` is safe to use from its dispatcher thread until
/// `questdb_db_close` returns. A terminal rejection enters the handler inbox
/// only after the connection's terminal latch and pollable diagnostic have
/// been committed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_db_connect_with_handlers(
    conf: *const c_char,
    conf_len: size_t,
    event_callback: Option<questdb_connection_event_cb>,
    event_user_data: *mut c_void,
    event_inbox_capacity: size_t,
    rejection_callback: line_sender_qwpws_error_cb,
    rejection_user_data: *mut c_void,
    rejection_inbox_capacity: size_t,
    err_out: *mut *mut questdb_error,
) -> *mut questdb_db {
    let conf = match unsafe { name_str(conf, conf_len, err_out) } {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    let mut handlers = questdb::ConnectHandlers::default();
    if let Some(cb) = event_callback {
        handlers.connection_listener = Some(connection_listener_from_c(cb, event_user_data));
        handlers.connection_event_inbox_capacity = event_inbox_capacity;
    }
    if let Some(cb) = rejection_callback {
        let user_data = rejection_user_data as usize;
        handlers.error_handler = Some(questdb::ingress::QwpWsErrorHandler::new(
            move |error: &questdb::ingress::QwpWsSenderError| {
                let view = qwp_ws_sender_error_view(error);
                unsafe { cb(user_data as *mut c_void, &view) };
            },
        ));
        handlers.error_inbox_capacity = rejection_inbox_capacity;
    }
    match QuestDb::connect_with_handlers(conf, handlers) {
        Ok(db) => Box::into_raw(Box::new(questdb_db(db))),
        Err(err) => {
            unsafe { set_err_out_from_error(err_out, err) };
            std::ptr::null_mut()
        }
    }
}

/// Total server rejections delivered to the rejection handler (or to the
/// default log handler when none was registered). `0` for a NULL `db`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_db_rejection_events_delivered(db: *const questdb_db) -> u64 {
    if db.is_null() {
        return 0;
    }
    let db_ref = unsafe { &*db };
    db_ref.0.rejection_events_delivered()
}

/// Total server rejections discarded by the rejection handler inbox's
/// drop-oldest policy. Always `0` without a registered handler: the default
/// log handler has no inbox. `0` for a NULL `db`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_db_rejection_events_dropped(db: *const questdb_db) -> u64 {
    if db.is_null() {
        return 0;
    }
    let db_ref = unsafe { &*db };
    db_ref.0.rejection_events_dropped()
}

/// Per-pool connection counts, mirroring `questdb::DbgPoolCount`. Diagnostics
/// only (soak / leak harnesses); the field set is not part of the stable ABI.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct questdb_dbg_pool_count {
    pub free: size_t,
    pub in_use: size_t,
    pub closing: size_t,
}

/// Snapshot of connection counts across all three pools, mirroring
/// `questdb::DbgPoolCounts`. Diagnostics only; not part of the stable ABI.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct questdb_dbg_pool_counts {
    pub ingress: questdb_dbg_pool_count,
    pub column_direct: questdb_dbg_pool_count,
    pub reader: questdb_dbg_pool_count,
}

/// Snapshot per-pool connection counts for diagnostics. Soak / leak harnesses
/// sample this and assert every pool drains back to a steady baseline after
/// load and failover episodes. Returns all-zero for a NULL `db`. Not part of
/// the supported ABI; the field set may change.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn questdb_db_dbg_pool_counts(
    db: *const questdb_db,
) -> questdb_dbg_pool_counts {
    if db.is_null() {
        return questdb_dbg_pool_counts::default();
    }
    let counts = unsafe { &*db }.0.dbg_pool_counts();
    let conv = |p: &questdb::DbgPoolCount| questdb_dbg_pool_count {
        free: p.free,
        in_use: p.in_use,
        closing: p.closing,
    };
    questdb_dbg_pool_counts {
        ingress: conv(&counts.ingress),
        column_direct: conv(&counts.column_direct),
        reader: conv(&counts.reader),
    }
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

/// Create an empty chunk from a raw `table_name` buffer (validated UTF-8
/// only at this point).
///
/// **Name validation timing — read this.** This entrypoint takes the
/// table name as raw `const char*` + length and validates *only* that the
/// bytes are UTF-8 here. Both the name **grammar** (illegal characters
/// such as `?`, `.` placement, BOM) **and** the 127-byte length cap are
/// **deferred to the first flush**, matching the deferred-validation
/// contract of `Chunk::new` in the Rust API: a malformed name is accepted
/// by `qwp_chunk_new` and only surfaces as an error from
/// `qwp_sender_flush_chunk*`.
///
/// If you already hold a pre-validated [`line_sender_table_name`] (for
/// example because you also flush Arrow batches via
/// `qwp_sender_flush_arrow_batch_at_column`, which requires that type),
/// prefer [`qwp_chunk_new_validated`]: it accepts the validated
/// handle directly and reports grammar errors *eagerly* at
/// `line_sender_table_name_init` time — the same type and timing as the
/// Arrow flush entrypoints — so the same bad name doesn't surface at two
/// different points depending on which path you take.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_chunk_new(
    table_name: *const c_char,
    table_name_len: size_t,
    err_out: *mut *mut line_sender_error,
) -> *mut qwp_chunk {
    let table = match unsafe { name_str(table_name, table_name_len, err_out) } {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    Box::into_raw(Box::new(qwp_chunk(Chunk::new(table), AtomicU32::new(0))))
}

/// Create an empty chunk from a pre-validated [`line_sender_table_name`].
///
/// Typed, eager-grammar-validation counterpart to
/// [`qwp_chunk_new`]. The name grammar was already checked when
/// the [`line_sender_table_name`] was built (`line_sender_table_name_init`
/// returns `false` for an illegal name), so this constructor cannot fail
/// on the name and never writes `*err_out`. The 127-byte length cap is
/// still applied at the first flush — identical type *and* validation
/// timing to the Arrow flush entrypoints
/// (`qwp_sender_flush_arrow_batch_at_column` /
/// `_at_now`), which also take a [`line_sender_table_name`].
///
/// Use this when you already validated the table name once (e.g. to share
/// it between the chunk path and an Arrow flush) instead of being forced
/// to re-pass raw `const char*` bytes through [`qwp_chunk_new`].
/// `err_out` is accepted for ABI symmetry with the other constructors but
/// is never set: a [`line_sender_table_name`] is validated by
/// construction.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_chunk_new_validated(
    table: line_sender_table_name,
    _err_out: *mut *mut line_sender_error,
) -> *mut qwp_chunk {
    // The newtype was grammar-validated at `line_sender_table_name_init`
    // time, so `as_name()` is infallible — there is no name failure path.
    // The 127-byte cap is enforced at flush by `validate_table_name`,
    // exactly as it is for the Arrow flush entrypoints.
    let table = unsafe { table.as_name() };
    Box::into_raw(Box::new(qwp_chunk(
        Chunk::new(table.as_ref()),
        AtomicU32::new(0),
    )))
}

/// Free a chunk. Accepts NULL and no-ops. A racing in-flight call defers
/// the drop to the in-flight call's exit path.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_chunk_free(chunk: *mut qwp_chunk) {
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
pub unsafe extern "C" fn qwp_chunk_clear(
    chunk: *mut qwp_chunk,
    err_out: *mut *mut line_sender_error,
) -> bool {
    if chunk.is_null() {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    "qwp_chunk_clear: chunk is NULL".to_string(),
                ),
            );
        }
        return false;
    }
    let state: *const AtomicU32 = unsafe { &raw const (*chunk).1 };
    let guard =
        unsafe { InUseGuard::acquire(chunk, state, "qwp_chunk_clear", "qwp_chunk", err_out) };
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
pub unsafe extern "C" fn qwp_chunk_row_count(
    chunk: *const qwp_chunk,
    err_out: *mut *mut line_sender_error,
) -> size_t {
    if chunk.is_null() {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    "qwp_chunk_row_count: chunk is NULL".to_string(),
                ),
            );
        }
        return usize::MAX;
    }
    let state: *const AtomicU32 = unsafe { &raw const (*chunk).1 };
    let guard = unsafe {
        InUseGuard::acquire(
            chunk as *mut qwp_chunk,
            state,
            "qwp_chunk_row_count",
            "qwp_chunk",
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

// ===========================================================================
// Timestamp unit
//
// Like ack_level, the `qwp_chunk_column_ts` unit crosses the ABI as
// a `uint32_t` (named constants below) rather than a `#[repr(C)] enum`, so an
// out-of-range value is a recoverable `InvalidApiCall` instead of Rust UB.
// ===========================================================================

/// `unit` value selecting `TIMESTAMP` (microseconds) for
/// [`qwp_chunk_column_ts`].
pub const qwp_ts_unit_micros: u32 = 0;

/// `unit` value selecting `TIMESTAMP_NANOS` (nanoseconds) for
/// [`qwp_chunk_column_ts`].
pub const qwp_ts_unit_nanos: u32 = 1;

fn ts_unit_from_u32(value: u32, err_out: *mut *mut line_sender_error) -> Option<TimestampUnit> {
    match value {
        v if v == qwp_ts_unit_micros => Some(TimestampUnit::Micros),
        v if v == qwp_ts_unit_nanos => Some(TimestampUnit::Nanos),
        other => {
            unsafe {
                set_err_out_from_error(
                    err_out,
                    Error::new(
                        ErrorCode::InvalidApiCall,
                        format!("qwp_sender ts unit: invalid value {other} (expected 0 or 1)"),
                    ),
                );
            }
            None
        }
    }
}

macro_rules! column_fn {
    ($fn_name:ident, $c_ty:ty, $rust_method:ident, $what:literal) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $fn_name(
            chunk: *mut qwp_chunk,
            name: *const c_char,
            name_len: size_t,
            data: *const $c_ty,
            row_count: size_t,
            validity: *const qwp_validity,
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
                    "qwp_chunk",
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
            bubble_err_to_c!(err_out, inner.$rust_method(name, data, validity.as_ref()));
            true
        }
    };
}

column_fn!(qwp_chunk_column_i8, i8, column_i8, "i8 column data");
column_fn!(qwp_chunk_column_i16, i16, column_i16, "i16 column data");
column_fn!(qwp_chunk_column_i32, i32, column_i32, "i32 column data");
column_fn!(qwp_chunk_column_i64, i64, column_i64, "i64 column data");
column_fn!(qwp_chunk_column_f32, f32, column_f32, "f32 column data");
column_fn!(qwp_chunk_column_f64, f64, column_f64, "f64 column data");
column_fn!(qwp_chunk_column_ipv4, u32, column_ipv4, "ipv4 column data");
column_fn!(qwp_chunk_column_date, i64, column_date, "date column data");

/// `TIMESTAMP` / `TIMESTAMP_NANOS` column. `unit` selects the precision:
/// `qwp_ts_unit_micros` (0) → `TIMESTAMP`,
/// `qwp_ts_unit_nanos` (1) → `TIMESTAMP_NANOS`. `data` holds
/// `row_count` Unix-epoch values in the chosen unit.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_chunk_column_ts(
    chunk: *mut qwp_chunk,
    name: *const c_char,
    name_len: size_t,
    data: *const i64,
    row_count: size_t,
    unit: u32,
    validity: *const qwp_validity,
    err_out: *mut *mut line_sender_error,
) -> bool {
    if chunk.is_null() {
        return reject_null_chunk(err_out);
    }
    let _guard = match unsafe {
        InUseGuard::acquire(
            chunk,
            &raw const (*chunk).1,
            "qwp_chunk_column_ts",
            "qwp_chunk",
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
    let data = match unsafe { typed_slice(data, row_count, err_out, "timestamp column data") } {
        Some(s) => s,
        None => return false,
    };
    let unit = match ts_unit_from_u32(unit, err_out) {
        Some(u) => u,
        None => return false,
    };
    let validity = match unsafe { as_validity(validity, err_out) } {
        Some(v) => v,
        None => return false,
    };
    let inner: &mut Chunk = unsafe { &mut (*chunk).0 };
    bubble_err_to_c!(
        err_out,
        inner.column_ts(name, data, unit, validity.as_ref())
    );
    true
}

/// `BOOLEAN` column. `data` is an Arrow-style LSB-first packed bitmap;
/// must be at least `ceil(row_count / 8)` bytes long.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_chunk_column_bool(
    chunk: *mut qwp_chunk,
    name: *const c_char,
    name_len: size_t,
    data: *const u8,
    row_count: size_t,
    validity: *const qwp_validity,
    err_out: *mut *mut line_sender_error,
) -> bool {
    if chunk.is_null() {
        return reject_null_chunk(err_out);
    }
    let _guard = match unsafe {
        InUseGuard::acquire(
            chunk,
            &raw const (*chunk).1,
            "qwp_chunk_column_bool",
            "qwp_chunk",
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
    bubble_err_to_c!(
        err_out,
        inner.column_bool(name, data_slice, row_count, validity.as_ref())
    );
    true
}

macro_rules! fixed_width_byte_column_fn {
    ($fn_name:ident, $n:literal, $rust_method:ident, $what:literal) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $fn_name(
            chunk: *mut qwp_chunk,
            name: *const c_char,
            name_len: size_t,
            data: *const u8,
            row_count: size_t,
            validity: *const qwp_validity,
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
                    "qwp_chunk",
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
            bubble_err_to_c!(
                err_out,
                inner.$rust_method(name, data_slice, validity.as_ref())
            );
            true
        }
    };
}

fixed_width_byte_column_fn!(qwp_chunk_column_uuid, 16, column_uuid, "uuid");
fixed_width_byte_column_fn!(qwp_chunk_column_long256, 32, column_long256, "long256");

// ===========================================================================
// VARCHAR (variable-width text)
// ===========================================================================

/// `BINARY` column. Same `offsets` + `bytes` layout as
/// `qwp_chunk_column_str`; wire type byte differs so the
/// server creates a BINARY column. No UTF-8 validation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_chunk_column_binary(
    chunk: *mut qwp_chunk,
    name: *const c_char,
    name_len: size_t,
    offsets: *const i32,
    bytes: *const u8,
    bytes_len: size_t,
    row_count: size_t,
    validity: *const qwp_validity,
    err_out: *mut *mut line_sender_error,
) -> bool {
    if chunk.is_null() {
        return reject_null_chunk(err_out);
    }
    let _guard = match unsafe {
        InUseGuard::acquire(
            chunk,
            &raw const (*chunk).1,
            "qwp_chunk_column_binary",
            "qwp_chunk",
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
    bubble_err_to_c!(
        err_out,
        inner.column_binary(name, offsets, bytes, validity.as_ref())
    );
    true
}

/// `VARCHAR` column. Inputs are Arrow Utf8 shape: `offsets` length
/// `row_count + 1`, monotonically non-decreasing; `bytes` is the
/// concatenated UTF-8 buffer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_chunk_column_str(
    chunk: *mut qwp_chunk,
    name: *const c_char,
    name_len: size_t,
    offsets: *const i32,
    bytes: *const u8,
    bytes_len: size_t,
    row_count: size_t,
    validity: *const qwp_validity,
    err_out: *mut *mut line_sender_error,
) -> bool {
    if chunk.is_null() {
        return reject_null_chunk(err_out);
    }
    let _guard = match unsafe {
        InUseGuard::acquire(
            chunk,
            &raw const (*chunk).1,
            "qwp_chunk_column_str",
            "qwp_chunk",
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
    bubble_err_to_c!(
        err_out,
        inner.column_str(name, offsets, bytes, validity.as_ref())
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
            chunk: *mut qwp_chunk,
            name: *const c_char,
            name_len: size_t,
            codes: *const $code_ty,
            row_count: size_t,
            dict_offsets: *const i32,
            dict_offsets_len: size_t,
            dict_bytes: *const u8,
            dict_bytes_len: size_t,
            validity: *const qwp_validity,
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
                    "qwp_chunk",
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
                typed_dict_offsets_slice(
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
            bubble_err_to_c!(
                err_out,
                inner.$rust_method(name, codes, dict_offsets, dict_bytes, validity.as_ref())
            );
            true
        }
    };
}

symbol_fn!(qwp_chunk_symbol_i8, i8, symbol_i8, "symbol codes (i8)");
symbol_fn!(qwp_chunk_symbol_i16, i16, symbol_i16, "symbol codes (i16)");
symbol_fn!(qwp_chunk_symbol_i32, i32, symbol_i32, "symbol codes (i32)");

// ===========================================================================
// Generic Arrow column appender
// ===========================================================================

/// Import an Arrow C Data Interface (`ArrowArray` + `ArrowSchema`) pair
/// into an opaque handle that subsequent calls can slice / append from.
///
/// Ownership: on success, `array->release` is consumed (set to NULL);
/// the returned handle owns the underlying buffers and releases them on
/// `qwp_arrow_import_free`. On failure, `array->release` may
/// also have been consumed if the call reached the Arrow import step
/// before failing — callers MUST check `array->release != NULL` before
/// invoking it on the failure path. Early-fail paths (NULL pointer,
/// depth-cap rejection) leave it intact. `schema` is borrowed in all
/// cases.
///
/// `auto`: Dictionary(*, Utf8/LargeUtf8) -> SYMBOL, plain Utf8 -> VARCHAR.
/// `symbol`: force plain Utf8 -> SYMBOL. `not_symbol`: force Dictionary ->
/// VARCHAR. Used by `qwp_arrow_import_new`.
//
// The C header exposes named constants (`qwp_symbol_mode_auto = 0`,
// `..._symbol = 1`, `..._not_symbol = 2`) but the FFI takes a `u32` (not a
// `#[repr(u32)]` enum) so an out-of-range value is a recoverable
// `InvalidApiCall` error instead of immediate Rust UB at the language boundary.
#[cfg(feature = "arrow")]
pub const qwp_symbol_mode_auto: u32 = 0;
#[cfg(feature = "arrow")]
pub const qwp_symbol_mode_symbol: u32 = 1;
#[cfg(feature = "arrow")]
pub const qwp_symbol_mode_not_symbol: u32 = 2;

/// Resolve a `qwp_symbol_mode_*` value into the symbol disposition
/// consumed by the Arrow importer: `Some(None)` = auto, `Some(Some(true))` =
/// force SYMBOL, `Some(Some(false))` = force VARCHAR. Returns the outer `None`
/// (after writing `*err_out`) when `value` is out of range.
#[cfg(feature = "arrow")]
fn symbol_mode_from_u32(value: u32, err_out: *mut *mut line_sender_error) -> Option<Option<bool>> {
    match value {
        0 => Some(None),
        1 => Some(Some(true)),
        2 => Some(Some(false)),
        other => {
            unsafe {
                set_err_out_from_error(
                    err_out,
                    Error::new(
                        ErrorCode::InvalidApiCall,
                        format!(
                            "qwp_arrow_import_new: invalid symbol_mode {other} (expected 0, 1, or 2)"
                        ),
                    ),
                );
            }
            None
        }
    }
}

#[cfg(feature = "arrow")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_arrow_import_new(
    array: *mut ArrowArray,
    schema: *const ArrowSchema,
    symbol_mode: u32,
    err_out: *mut *mut line_sender_error,
) -> *mut qwp_arrow_import {
    let symbol = match symbol_mode_from_u32(symbol_mode, err_out) {
        Some(symbol) => symbol,
        None => return std::ptr::null_mut(),
    };
    let ffi_array = array as *mut arrow::ffi::FFI_ArrowArray;
    let ffi_schema = schema as *const arrow::ffi::FFI_ArrowSchema;
    let imported = match unsafe {
        crate::arrow_ffi_import_column(
            ffi_array,
            ffi_schema,
            symbol,
            "qwp_arrow_import_new",
            err_out,
        )
    } {
        Some(imported) => imported,
        None => return std::ptr::null_mut(),
    };
    Box::into_raw(Box::new(qwp_arrow_import(imported, AtomicU32::new(0))))
}

#[cfg(feature = "arrow")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_arrow_import_free(imported: *mut qwp_arrow_import) {
    if imported.is_null() {
        return;
    }
    let state: *const AtomicU32 = unsafe { &raw const (*imported).1 };
    unsafe { finalize_or_defer(imported, state, 0) };
}

/// Number of rows in an imported Arrow column. Returns `(size_t)-1`
/// (a.k.a. `SIZE_MAX`) for a NULL `imported`, a handle that has been
/// freed, or one in use by a concurrent call; `0` is reserved for a
/// genuinely empty (0-row) import. Cheap accessor; the length is stored
/// alongside the buffers.
#[cfg(feature = "arrow")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_arrow_import_len(imported: *const qwp_arrow_import) -> size_t {
    if imported.is_null() {
        return usize::MAX;
    }
    let imported_mut = imported as *mut qwp_arrow_import;
    let guard = unsafe {
        InUseGuard::acquire(
            imported_mut,
            &raw const (*imported_mut).1,
            "qwp_arrow_import_len",
            "qwp_arrow_import",
            std::ptr::null_mut(),
        )
    };
    if guard.is_none() {
        return usize::MAX;
    }
    unsafe { (*imported).0.len() }
}

#[cfg(feature = "arrow")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_chunk_append_arrow_import(
    chunk: *mut qwp_chunk,
    name: *const c_char,
    name_len: size_t,
    imported: *const qwp_arrow_import,
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
    let imported_mut = imported as *mut qwp_arrow_import;
    let _import_guard = match unsafe {
        InUseGuard::acquire(
            imported_mut,
            &raw const (*imported_mut).1,
            "qwp_chunk_append_arrow_import",
            "qwp_arrow_import",
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
            "qwp_chunk_append_arrow_import",
            "qwp_chunk",
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
    bubble_err_to_c!(
        err_out,
        inner.push_imported_arrow_slice(name, imported_ref, row_offset, row_count)
    );
    true
}

/// Append a slice of one column from an Arrow C Data Interface array.
/// Routes through the same encoding infrastructure as
/// `qwp_sender_flush_arrow_batch_at_now`; supports the full
/// 43-variant Arrow type matrix (`arrow_batch::classify`).
///
/// `row_offset` and `row_count` describe the slice of the array to
/// append; pass `row_offset=0, row_count=array->length` for the whole
/// array.
///
/// Ownership: on success, `array->release` is consumed (set to NULL);
/// the chunk holds the underlying buffers via an internal Arc until
/// `qwp_sender_flush_chunk` returns. On failure, `array->release` may
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
pub unsafe extern "C" fn qwp_chunk_append_arrow_column(
    chunk: *mut qwp_chunk,
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
            "qwp_chunk_append_arrow_column",
            "qwp_chunk",
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
            "qwp_chunk_append_arrow_column",
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
    bubble_err_to_c!(err_out, inner.push_arrow_column(name, &field, arr_ref));
    true
}

// ===========================================================================
// NumPy column appender
//
// Companion to `qwp_chunk_append_arrow_column` that takes a
// raw contiguous NumPy buffer + a dtype tag. The buffer is borrowed by
// pointer (not copied) at append time; widening / packing happens at
// flush. The caller must keep `data` alive until the next flush returns.
//
// Stride and non-native-endian are not supported; the caller (Python
// client) consolidates upstream.
// ===========================================================================

/// NumPy source dtype tag. Mirrored to the C ABI as a 32-bit enum; the
/// discriminants and order must match `qwp_numpy_dtype` in the
/// C header. The dtype tells the encoder how to walk `data` at flush and
/// which QWP wire kind to emit; for `decimal_*` and `geohash_*`, the
/// per-call parameter rides on `qwp_numpy_extras`.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum qwp_numpy_dtype {
    qwp_numpy_i8 = 0,
    qwp_numpy_i16 = 1,
    qwp_numpy_i32 = 2,
    qwp_numpy_i64 = 3,
    qwp_numpy_u8 = 4,
    qwp_numpy_u16 = 5,
    qwp_numpy_u32 = 6,
    qwp_numpy_u64 = 7,
    qwp_numpy_f32 = 8,
    qwp_numpy_f64 = 9,
    qwp_numpy_bool = 10,

    qwp_numpy_f16 = 11,
    qwp_numpy_datetime64_s = 12,
    qwp_numpy_datetime64_ms = 13,
    qwp_numpy_datetime64_us = 14,
    qwp_numpy_datetime64_ns = 15,
    qwp_numpy_timedelta64_s = 16,
    qwp_numpy_timedelta64_ms = 17,
    qwp_numpy_timedelta64_us = 18,
    qwp_numpy_timedelta64_ns = 19,

    qwp_numpy_s16 = 20,
    qwp_numpy_s32 = 21,

    qwp_numpy_decimal_s8 = 22,
    qwp_numpy_decimal_s16 = 23,
    qwp_numpy_decimal_s32 = 24,

    qwp_numpy_u32_ipv4 = 25,
    qwp_numpy_u16_char = 26,

    qwp_numpy_geohash_i8 = 27,
    qwp_numpy_geohash_i16 = 28,
    qwp_numpy_geohash_i32 = 29,
    qwp_numpy_geohash_i64 = 30,

    qwp_numpy_f64_ndarray = 31,

    qwp_numpy_datetime64_m = 32,
    qwp_numpy_datetime64_h = 33,
    qwp_numpy_datetime64_D = 34,
    qwp_numpy_datetime64_M = 35,
    qwp_numpy_datetime64_Y = 36,
    qwp_numpy_datetime64_W = 37,

    qwp_numpy_timedelta64_m = 38,
    qwp_numpy_timedelta64_h = 39,
    qwp_numpy_timedelta64_D = 40,
    qwp_numpy_timedelta64_M = 41,
    qwp_numpy_timedelta64_Y = 42,
}

/// Companion to [`qwp_chunk_append_numpy_column`] carrying
/// dtype-specific parameters. Pass NULL unless the chosen dtype reads
/// from a field (decimal scale, geohash bits).
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct qwp_numpy_extras {
    pub decimal_scale: i8,
    pub geohash_bits: u8,
    /// Number of dimensions per row for `qwp_numpy_f64_ndarray`.
    /// Must be in `1..=MAX_ARRAY_DIMS` (`32`).
    pub array_ndim: u8,
    /// Per-row shape (length = `array_ndim`). Each dim must be >= 1. The
    /// pointer is borrowed for the duration of the FFI call only.
    pub array_shape: *const u32,
}

unsafe fn validate_decimal_scale(
    extras: Option<&qwp_numpy_extras>,
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
                        "{label} column requires non-NULL qwp_numpy_extras with decimal_scale set"
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
    extras: Option<&qwp_numpy_extras>,
    max_bits: u8,
    err_out: *mut *mut line_sender_error,
) -> Option<u8> {
    let Some(extras) = extras else {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    "GEOHASH iN column requires non-NULL qwp_numpy_extras with geohash_bits set"
                        .to_string(),
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
    extras: Option<&qwp_numpy_extras>,
    err_out: *mut *mut line_sender_error,
) -> Option<(u8, [u32; MAX_ARRAY_DIMS])> {
    let Some(extras) = extras else {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    "f64_ndarray column requires non-NULL qwp_numpy_extras with array_ndim and array_shape set".to_string(),
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
    extras: *const qwp_numpy_extras,
    err_out: *mut *mut line_sender_error,
) -> Option<NumpyDtype> {
    let extras = unsafe { extras.as_ref() };
    Some(match dtype {
        d if d == qwp_numpy_dtype::qwp_numpy_i8 as u32 => NumpyDtype::I8WidenToI32,
        d if d == qwp_numpy_dtype::qwp_numpy_i16 as u32 => NumpyDtype::I16WidenToI32,
        d if d == qwp_numpy_dtype::qwp_numpy_i32 as u32 => NumpyDtype::I32WidenToI64,
        d if d == qwp_numpy_dtype::qwp_numpy_i64 as u32 => NumpyDtype::I64Direct,
        d if d == qwp_numpy_dtype::qwp_numpy_u8 as u32 => NumpyDtype::U8WidenToI32,
        d if d == qwp_numpy_dtype::qwp_numpy_u16 as u32 => NumpyDtype::U16WidenToI32,
        d if d == qwp_numpy_dtype::qwp_numpy_u32 as u32 => NumpyDtype::U32WidenToI64,
        d if d == qwp_numpy_dtype::qwp_numpy_u64 as u32 => NumpyDtype::U64WidenToI64,
        d if d == qwp_numpy_dtype::qwp_numpy_f32 as u32 => NumpyDtype::F32Direct,
        d if d == qwp_numpy_dtype::qwp_numpy_f64 as u32 => NumpyDtype::F64Direct,
        d if d == qwp_numpy_dtype::qwp_numpy_bool as u32 => NumpyDtype::Bool,
        d if d == qwp_numpy_dtype::qwp_numpy_f16 as u32 => NumpyDtype::F16Widen,
        d if d == qwp_numpy_dtype::qwp_numpy_datetime64_s as u32 => NumpyDtype::DatetimeSecToMicros,
        d if d == qwp_numpy_dtype::qwp_numpy_datetime64_ms as u32 => NumpyDtype::DateI64Direct,
        d if d == qwp_numpy_dtype::qwp_numpy_datetime64_us as u32 => {
            NumpyDtype::TimestampMicrosDirect
        }
        d if d == qwp_numpy_dtype::qwp_numpy_datetime64_ns as u32 => {
            NumpyDtype::TimestampNanosDirect
        }
        d if d == qwp_numpy_dtype::qwp_numpy_timedelta64_s as u32
            || d == qwp_numpy_dtype::qwp_numpy_timedelta64_ms as u32
            || d == qwp_numpy_dtype::qwp_numpy_timedelta64_us as u32
            || d == qwp_numpy_dtype::qwp_numpy_timedelta64_ns as u32 =>
        {
            NumpyDtype::LongDirect
        }
        d if d == qwp_numpy_dtype::qwp_numpy_s16 as u32 => NumpyDtype::UuidDirect,
        d if d == qwp_numpy_dtype::qwp_numpy_s32 as u32 => NumpyDtype::Long256Direct,
        d if d == qwp_numpy_dtype::qwp_numpy_decimal_s8 as u32 => NumpyDtype::Decimal64 {
            scale: unsafe { validate_decimal_scale(extras, 18, "DECIMAL64", err_out)? },
        },
        d if d == qwp_numpy_dtype::qwp_numpy_decimal_s16 as u32 => NumpyDtype::Decimal128 {
            scale: unsafe { validate_decimal_scale(extras, 38, "DECIMAL128", err_out)? },
        },
        d if d == qwp_numpy_dtype::qwp_numpy_decimal_s32 as u32 => NumpyDtype::Decimal256 {
            scale: unsafe { validate_decimal_scale(extras, 76, "DECIMAL256", err_out)? },
        },
        d if d == qwp_numpy_dtype::qwp_numpy_u32_ipv4 as u32 => NumpyDtype::Ipv4Direct,
        d if d == qwp_numpy_dtype::qwp_numpy_u16_char as u32 => NumpyDtype::CharDirect,
        d if d == qwp_numpy_dtype::qwp_numpy_geohash_i8 as u32 => NumpyDtype::GeohashI8 {
            bits: unsafe { validate_geohash_bits(extras, 8, err_out)? },
        },
        d if d == qwp_numpy_dtype::qwp_numpy_geohash_i16 as u32 => NumpyDtype::GeohashI16 {
            bits: unsafe { validate_geohash_bits(extras, 16, err_out)? },
        },
        d if d == qwp_numpy_dtype::qwp_numpy_geohash_i32 as u32 => NumpyDtype::GeohashI32 {
            bits: unsafe { validate_geohash_bits(extras, 32, err_out)? },
        },
        d if d == qwp_numpy_dtype::qwp_numpy_geohash_i64 as u32 => NumpyDtype::GeohashI64 {
            bits: unsafe { validate_geohash_bits(extras, 60, err_out)? },
        },
        d if d == qwp_numpy_dtype::qwp_numpy_f64_ndarray as u32 => {
            let (ndim, shape) = unsafe { validate_f64_ndarray(extras, err_out)? };
            NumpyDtype::F64Ndarray { ndim, shape }
        }
        d if d == qwp_numpy_dtype::qwp_numpy_datetime64_m as u32 => {
            NumpyDtype::DatetimeMinuteToMicros
        }
        d if d == qwp_numpy_dtype::qwp_numpy_datetime64_h as u32 => {
            NumpyDtype::DatetimeHourToMicros
        }
        d if d == qwp_numpy_dtype::qwp_numpy_datetime64_D as u32 => NumpyDtype::DatetimeDayToMicros,
        d if d == qwp_numpy_dtype::qwp_numpy_datetime64_M as u32 => {
            NumpyDtype::DatetimeMonthToMicros
        }
        d if d == qwp_numpy_dtype::qwp_numpy_datetime64_Y as u32 => {
            NumpyDtype::DatetimeYearToMicros
        }
        d if d == qwp_numpy_dtype::qwp_numpy_datetime64_W as u32 => {
            NumpyDtype::DatetimeWeekToMicros
        }
        d if d == qwp_numpy_dtype::qwp_numpy_timedelta64_m as u32
            || d == qwp_numpy_dtype::qwp_numpy_timedelta64_h as u32
            || d == qwp_numpy_dtype::qwp_numpy_timedelta64_D as u32 =>
        {
            NumpyDtype::LongDirect
        }
        d if d == qwp_numpy_dtype::qwp_numpy_timedelta64_M as u32
            || d == qwp_numpy_dtype::qwp_numpy_timedelta64_Y as u32 =>
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
                            "qwp_chunk_append_numpy_column: invalid dtype {other} \
                             (expected a qwp_numpy_* constant)"
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
/// no per-column copy is taken at append.
///
/// # LIFETIME (zero-copy contract) — read this
///
/// This call parks the raw `data` (and `validity->bits`, if any) pointer
/// and walks it later, at flush time. The caller therefore MUST keep the
/// backing buffer **alive and unmodified** until the next
/// `qwp_sender_flush_chunk` / `qwp_sender_wait` on this chunk **returns**.
/// Freeing, reallocating, or letting a GC move the buffer before then is
/// undefined behaviour (use-after-free). No length or liveness can be
/// re-checked at flush time — only at append.
///
/// # BUFFER LENGTH
///
/// `data_len_bytes` is the size in bytes of the buffer `data` points at.
/// It is validated here against the bytes the encoder will read
/// (`row_count * source-stride(dtype)`); if the buffer is too small the
/// call fails with `invalid_api_call` and nothing is appended. This is
/// the only guard against a mis-tagged `dtype` (e.g. an `int8` array
/// tagged `f64`) or an inflated `row_count` walking the pointer off the
/// end of the real allocation and streaming host memory onto the wire.
/// For NumPy callers pass `arr.nbytes`. When `data == NULL` (only legal
/// with `row_count == 0`) pass `0`.
///
/// `dtype` selects from 31 supported NumPy → QuestDB wire mappings (see
/// the C header for the full coverage matrix). For `decimal_*`,
/// `geohash_*`, and `f64_ndarray` dtypes, `extras` must be non-NULL and
/// supply the corresponding fields (`decimal_scale` 0..=18/38/76;
/// `geohash_bits` 1..=8/16/32/60; `array_ndim` 1..=32 with `array_shape`
/// pointing at `array_ndim` per-dim u32 sizes, each >= 1). For every
/// other dtype, `extras` is ignored and may be NULL.
///
/// # CONTIGUITY
///
/// The buffer MUST be C-contiguous and native-endian. The walk reads
/// `row_count` elements forward at the dtype's native stride; NumPy strides
/// are not passed in and cannot be checked, so a non-contiguous view
/// (sliced / transposed / reversed) whose `nbytes` still satisfies the
/// length check is read out of bounds — undefined behaviour. Call
/// `numpy.ascontiguousarray(arr)` upstream before handing the buffer over.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_chunk_append_numpy_column(
    chunk: *mut qwp_chunk,
    name: *const c_char,
    name_len: size_t,
    dtype: u32,
    data: *const u8,
    data_len_bytes: size_t,
    row_count: size_t,
    validity: *const qwp_validity,
    extras: *const qwp_numpy_extras,
    err_out: *mut *mut line_sender_error,
) -> bool {
    if chunk.is_null() {
        return reject_null_chunk(err_out);
    }
    let _guard = match unsafe {
        InUseGuard::acquire(
            chunk,
            &raw const (*chunk).1,
            "qwp_chunk_append_numpy_column",
            "qwp_chunk",
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
    // Bounds-check the caller-supplied buffer length against the bytes the
    // deferred encoder will read (`row_count * source-stride`). This is the
    // only thing standing between a mis-tagged dtype / inflated row_count and
    // an out-of-bounds read at flush time (host-memory info-leak onto the wire
    // or a segfault). `dtype` is fully resolved/validated above, so
    // `source_elem_size` is safe to query here. Guards length, not liveness:
    // the buffer-lifetime requirement is the caller's per the doc above.
    let elem = bubble_err_to_c!(err_out, dtype.source_elem_size());
    match row_count.checked_mul(elem) {
        Some(required) if required <= data_len_bytes => {}
        Some(required) => {
            unsafe {
                set_err_out_from_error(
                    err_out,
                    Error::new(
                        ErrorCode::InvalidApiCall,
                        format!(
                            "numpy column buffer too small: dtype needs {required} bytes \
                             ({row_count} rows * {elem} bytes/row) but data_len_bytes is {data_len_bytes}"
                        ),
                    ),
                );
            }
            return false;
        }
        None => {
            unsafe {
                set_err_out_from_error(
                    err_out,
                    Error::new(
                        ErrorCode::InvalidApiCall,
                        format!(
                            "numpy column size overflows usize: {row_count} rows * {elem} bytes/row"
                        ),
                    ),
                );
            }
            return false;
        }
    }
    let inner: &mut Chunk = unsafe { &mut (*chunk).0 };
    bubble_err_to_c!(err_out, unsafe {
        inner.push_numpy_deferred(name, dtype, data, row_count, validity.as_ref())
    });
    true
}

// ===========================================================================
// Designated timestamp
// ===========================================================================

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_chunk_at_micros(
    chunk: *mut qwp_chunk,
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
            "qwp_chunk_at_micros",
            "qwp_chunk",
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
    bubble_err_to_c!(err_out, inner.at_micros(data));
    true
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_chunk_at_nanos(
    chunk: *mut qwp_chunk,
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
            "qwp_chunk_at_nanos",
            "qwp_chunk",
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
    bubble_err_to_c!(err_out, inner.at_nanos(data));
    true
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_chunk_at_millis(
    chunk: *mut qwp_chunk,
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
            "qwp_chunk_at_millis",
            "qwp_chunk",
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
    bubble_err_to_c!(err_out, inner.at_millis(data));
    true
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_chunk_at_seconds(
    chunk: *mut qwp_chunk,
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
            "qwp_chunk_at_seconds",
            "qwp_chunk",
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
    bubble_err_to_c!(err_out, inner.at_seconds(data));
    true
}

/// Opt the chunk into server-assigned timestamps: the encoded frame
/// carries no designated timestamp column and the server stamps each row
/// on arrival. This is an **explicit opt-in** mirroring
/// `qwp_sender_flush_arrow_batch_at_now` — if your data carries a real
/// event-time column, pin it with `qwp_chunk_at_micros` /
/// `_at_nanos` instead; server-assigned timestamps generate unique rows
/// on resubmission and so defeat `DEDUP UPSERT KEYS`.
///
/// Rejects if a designated timestamp column is already set on this chunk
/// (and the `at_*` setters reject after this call). Cleared by
/// `qwp_chunk_clear` like every other chunk property.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_chunk_at_now(
    chunk: *mut qwp_chunk,
    err_out: *mut *mut line_sender_error,
) -> bool {
    if chunk.is_null() {
        return reject_null_chunk(err_out);
    }
    let _guard = match unsafe {
        InUseGuard::acquire(
            chunk,
            &raw const (*chunk).1,
            "qwp_chunk_at_now",
            "qwp_chunk",
            err_out,
        )
    } {
        Some(g) => g,
        None => return false,
    };
    let inner: &mut Chunk = unsafe { &mut (*chunk).0 };
    bubble_err_to_c!(err_out, inner.at_now());
    true
}

/// Pin one scalar nanosecond-precision Unix epoch timestamp as every
/// row's designated timestamp, encoded as a repeated constant (wire type
/// `TIMESTAMP_NANOS`). Unlike `qwp_chunk_at_now` the value is
/// fixed at the caller, so resubmission is idempotent under
/// `DEDUP UPSERT KEYS`. Rejects negative (pre-epoch) values and any
/// already-set designated timestamp. Cleared by
/// `qwp_chunk_clear` like every other chunk property.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_chunk_at_scalar_nanos(
    chunk: *mut qwp_chunk,
    nanos: i64,
    err_out: *mut *mut line_sender_error,
) -> bool {
    if chunk.is_null() {
        return reject_null_chunk(err_out);
    }
    let _guard = match unsafe {
        InUseGuard::acquire(
            chunk,
            &raw const (*chunk).1,
            "qwp_chunk_at_scalar_nanos",
            "qwp_chunk",
            err_out,
        )
    } {
        Some(g) => g,
        None => return false,
    };
    let inner: &mut Chunk = unsafe { &mut (*chunk).0 };
    bubble_err_to_c!(err_out, inner.at_scalar_nanos(nanos));
    true
}

// ===========================================================================
// Flush
// ===========================================================================

unsafe fn acquire_qwp_sender(
    sender: *mut qwp_sender,
    fn_name: &str,
    err_out: *mut *mut line_sender_error,
) -> Option<InUseGuard<qwp_sender>> {
    if sender.is_null() {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    format!("{fn_name}: sender pointer is NULL"),
                ),
            );
        }
        return None;
    }
    let guard = unsafe {
        InUseGuard::acquire(
            sender,
            qwp_sender::latch(sender),
            fn_name,
            "qwp_sender",
            err_out,
        )
    }?;
    if unsafe { reject_closed_pool_cs(sender, fn_name, err_out) } {
        return None;
    }
    Some(guard)
}

/// Publish a QWP/WebSocket Buffer into the local store-and-forward queue and
/// clear it after local acceptance.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_sender_flush_buffer(
    sender: *mut qwp_sender,
    buffer: *mut line_sender_buffer,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let fn_name = "qwp_sender_flush_buffer";
    let _guard = match unsafe { acquire_qwp_sender(sender, fn_name, err_out) } {
        Some(guard) => guard,
        None => return false,
    };
    let Some(buffer) = (unsafe { qwpws_buffer_ptr_mut(buffer, err_out, fn_name) }) else {
        return false;
    };
    let sender = unsafe { qwp_sender::owned_mut(sender).get_mut() };
    bubble_err_to_c!(err_out, sender.flush_buffer(buffer));
    true
}

/// Publish and clear a Buffer, then wait for every frame published through
/// this sender to reach `ack_level`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_sender_flush_buffer_and_wait(
    sender: *mut qwp_sender,
    buffer: *mut line_sender_buffer,
    ack_level: u32,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let fn_name = "qwp_sender_flush_buffer_and_wait";
    let ack_level = match ack_level_from_u32(ack_level, err_out) {
        Some(level) => level,
        None => return false,
    };
    let _guard = match unsafe { acquire_qwp_sender(sender, fn_name, err_out) } {
        Some(guard) => guard,
        None => return false,
    };
    let Some(buffer) = (unsafe { qwpws_buffer_ptr_mut(buffer, err_out, fn_name) }) else {
        return false;
    };
    let sender = unsafe { qwp_sender::owned_mut(sender).get_mut() };
    bubble_err_to_c!(err_out, sender.flush_buffer_and_wait(buffer, ack_level));
    true
}

/// Publish a QWP/WebSocket Buffer without clearing it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_sender_flush_buffer_and_keep(
    sender: *mut qwp_sender,
    buffer: *const line_sender_buffer,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let fn_name = "qwp_sender_flush_buffer_and_keep";
    let _guard = match unsafe { acquire_qwp_sender(sender, fn_name, err_out) } {
        Some(guard) => guard,
        None => return false,
    };
    let Some(buffer) = (unsafe { qwpws_buffer_ptr_ref(buffer, err_out, fn_name) }) else {
        return false;
    };
    let sender = unsafe { qwp_sender::owned_mut(sender).get_mut() };
    bubble_err_to_c!(err_out, sender.flush_buffer_and_keep(buffer));
    true
}

/// Publish and clear a Buffer, returning its local frame sequence boundary.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_sender_flush_buffer_and_get_fsn(
    sender: *mut qwp_sender,
    buffer: *mut line_sender_buffer,
    fsn_out: *mut line_sender_qwpws_fsn,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let fn_name = "qwp_sender_flush_buffer_and_get_fsn";
    if unsafe { reject_null_fsn_out(fsn_out, fn_name, err_out) } {
        return false;
    }
    let _guard = match unsafe { acquire_qwp_sender(sender, fn_name, err_out) } {
        Some(guard) => guard,
        None => return false,
    };
    let Some(buffer) = (unsafe { qwpws_buffer_ptr_mut(buffer, err_out, fn_name) }) else {
        return false;
    };
    let sender = unsafe { qwp_sender::owned_mut(sender).get_mut() };
    match sender.flush_buffer_and_get_fsn(buffer) {
        Ok(fsn) => {
            unsafe { *fsn_out = line_sender_qwpws_fsn::from_option(fsn) };
            true
        }
        Err(err) => {
            unsafe { set_err_out_from_error(err_out, err) };
            false
        }
    }
}

/// Publish a Buffer without clearing it and return its local frame sequence
/// boundary.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_sender_flush_buffer_and_keep_and_get_fsn(
    sender: *mut qwp_sender,
    buffer: *const line_sender_buffer,
    fsn_out: *mut line_sender_qwpws_fsn,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let fn_name = "qwp_sender_flush_buffer_and_keep_and_get_fsn";
    if unsafe { reject_null_fsn_out(fsn_out, fn_name, err_out) } {
        return false;
    }
    let _guard = match unsafe { acquire_qwp_sender(sender, fn_name, err_out) } {
        Some(guard) => guard,
        None => return false,
    };
    let Some(buffer) = (unsafe { qwpws_buffer_ptr_ref(buffer, err_out, fn_name) }) else {
        return false;
    };
    let sender = unsafe { qwp_sender::owned_mut(sender).get_mut() };
    match sender.flush_buffer_and_keep_and_get_fsn(buffer) {
        Ok(fsn) => {
            unsafe { *fsn_out = line_sender_qwpws_fsn::from_option(fsn) };
            true
        }
        Err(err) => {
            unsafe { set_err_out_from_error(err_out, err) };
            false
        }
    }
}

/// Encode `chunk` into a QWP/WebSocket frame, publish it, and return
/// immediately without waiting for the server's ack. Direct mode writes to the
/// socket. Store-and-forward mode appends to the local SFA queue.
///
/// In direct mode, ready acks are drained non-blocking before the write.
/// Deferred flushes keep one in-flight slot reserved for the later
/// `qwp_direct_sender_commit` frame; if that reserve would be consumed, the
/// call fails and the caller must sync before flushing more chunks. In SFA mode
/// frames are non-deferred and `flush` success means local queue acceptance.
///
/// On success, `chunk` is cleared and the call returns `true`. On failure,
/// `chunk` is left untouched and `false` is returned (with `*err_out` set if
/// provided).
///
/// A `false` return does **not** prove the rows were not sent: a transport
/// error that fails mid-frame may already have put bytes on the wire. Such a
/// failure reports `line_sender_error_failover_retry`, yet re-flushing the
/// retained `chunk` on a fresh connection could duplicate rows. Call
/// [`line_sender_error_in_doubt`](crate::line_sender_error_in_doubt) on
/// `*err_out` to detect this delivery-unknown case before retrying.
///
/// Call `qwp_sender_wait` (store-and-forward) or
/// `qwp_direct_sender_commit` (direct) after the last flush to drain all
/// remaining in-flight acks.
unsafe fn cs_flush_body<T: CsHandle>(
    sender: *mut T,
    chunk: *mut qwp_chunk,
    fn_name: &str,
    err_out: *mut *mut line_sender_error,
) -> bool {
    if sender.is_null() {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    format!("{fn_name}: sender pointer is NULL"),
                ),
            );
        }
        return false;
    }
    let _conn_guard = match unsafe {
        InUseGuard::acquire(sender, T::latch(sender), fn_name, T::TYPE_NAME, err_out)
    } {
        Some(g) => g,
        None => return false,
    };
    if unsafe { reject_closed_pool_cs(sender, fn_name, err_out) } {
        return false;
    }
    if chunk.is_null() {
        return reject_null_chunk(err_out);
    }
    let _chunk_guard = match unsafe {
        InUseGuard::acquire(chunk, &raw const (*chunk).1, fn_name, "qwp_chunk", err_out)
    } {
        Some(g) => g,
        None => return false,
    };
    let chunk_inner: &mut Chunk = unsafe { &mut (*chunk).0 };
    bubble_err_to_c!(err_out, unsafe { T::flush(sender, chunk_inner) });
    true
}

/// Publish-only flush into the store-and-forward queue. Returns as soon as the
/// frame is accepted locally; call `qwp_sender_wait` to block for the
/// server ack.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_sender_flush_chunk(
    sender: *mut qwp_sender,
    chunk: *mut qwp_chunk,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe { cs_flush_body(sender, chunk, "qwp_sender_flush_chunk", err_out) }
}

unsafe fn cs_flush_and_wait_body<T: CsHandle>(
    sender: *mut T,
    chunk: *mut qwp_chunk,
    ack_level: u32,
    fn_name: &str,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let ack_level = match ack_level_from_u32(ack_level, err_out) {
        Some(l) => l,
        None => return false,
    };
    if sender.is_null() {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    format!("{fn_name}: sender pointer is NULL"),
                ),
            );
        }
        return false;
    }
    let _conn_guard = match unsafe {
        InUseGuard::acquire(sender, T::latch(sender), fn_name, T::TYPE_NAME, err_out)
    } {
        Some(g) => g,
        None => return false,
    };
    if unsafe { reject_closed_pool_cs(sender, fn_name, err_out) } {
        return false;
    }
    if chunk.is_null() {
        return reject_null_chunk(err_out);
    }
    let _chunk_guard = match unsafe {
        InUseGuard::acquire(chunk, &raw const (*chunk).1, fn_name, "qwp_chunk", err_out)
    } {
        Some(g) => g,
        None => return false,
    };
    let chunk_inner: &mut Chunk = unsafe { &mut (*chunk).0 };
    bubble_err_to_c!(err_out, unsafe {
        T::flush_and_wait(sender, chunk_inner, ack_level)
    });
    true
}

/// Store-and-forward combined publish+wait. Publishes `chunk` into the local SFA
/// queue as a completion boundary, then waits until every frame published before
/// or by this call reaches `ack_level`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_sender_flush_chunk_and_wait(
    sender: *mut qwp_sender,
    chunk: *mut qwp_chunk,
    ack_level: u32,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        cs_flush_and_wait_body(
            sender,
            chunk,
            ack_level,
            "qwp_sender_flush_chunk_and_wait",
            err_out,
        )
    }
}

/// Publish-only store-and-forward flush that also returns the local frame
/// sequence boundary. If a chunk is split into multiple frames, the returned
/// FSN is the final frame boundary.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_sender_flush_chunk_and_get_fsn(
    sender: *mut qwp_sender,
    chunk: *mut qwp_chunk,
    fsn_out: *mut line_sender_qwpws_fsn,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let fn_name = "qwp_sender_flush_chunk_and_get_fsn";
    if unsafe { reject_null_fsn_out(fsn_out, fn_name, err_out) } {
        return false;
    }
    if sender.is_null() {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    format!("{fn_name}: sender pointer is NULL"),
                ),
            );
        }
        return false;
    }
    let _conn_guard = match unsafe {
        InUseGuard::acquire(
            sender,
            qwp_sender::latch(sender),
            fn_name,
            "qwp_sender",
            err_out,
        )
    } {
        Some(g) => g,
        None => return false,
    };
    if unsafe { reject_closed_pool_cs(sender, fn_name, err_out) } {
        return false;
    }
    if chunk.is_null() {
        return reject_null_chunk(err_out);
    }
    let _chunk_guard = match unsafe {
        InUseGuard::acquire(chunk, &raw const (*chunk).1, fn_name, "qwp_chunk", err_out)
    } {
        Some(g) => g,
        None => return false,
    };
    let sender = unsafe { qwp_sender::owned_mut(sender).get_mut() };
    let chunk_inner: &mut Chunk = unsafe { &mut (*chunk).0 };
    match sender.flush_and_get_fsn(chunk_inner) {
        Ok(fsn) => {
            unsafe {
                *fsn_out = line_sender_qwpws_fsn::from_option(fsn);
            }
            true
        }
        Err(err) => {
            unsafe { set_err_out_from_error(err_out, err) };
            false
        }
    }
}

unsafe fn qwp_sender_fsn_watermark(
    sender: *const qwp_sender,
    fsn_out: *mut line_sender_qwpws_fsn,
    fn_name: &str,
    err_out: *mut *mut line_sender_error,
    read: fn(&questdb::ingress::column_sender::PooledSenderCore) -> questdb::Result<Option<u64>>,
) -> bool {
    if unsafe { reject_null_fsn_out(fsn_out, fn_name, err_out) } {
        return false;
    }
    if sender.is_null() {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    format!("{fn_name}: sender pointer is NULL"),
                ),
            );
        }
        return false;
    }
    let handle = sender as *mut qwp_sender;
    let _guard = match unsafe {
        InUseGuard::acquire(
            handle,
            qwp_sender::latch(sender),
            fn_name,
            "qwp_sender",
            err_out,
        )
    } {
        Some(g) => g,
        None => return false,
    };
    if unsafe { reject_closed_pool_cs(sender, fn_name, err_out) } {
        return false;
    }
    let sender = unsafe { qwp_sender::owned_ref(sender).get() };
    match read(sender) {
        Ok(fsn) => {
            unsafe {
                *fsn_out = line_sender_qwpws_fsn::from_option(fsn);
            }
            true
        }
        Err(err) => {
            unsafe { set_err_out_from_error(err_out, err) };
            false
        }
    }
}

/// Poll the next server-rejection diagnostic recorded on this borrow's
/// connection since it was borrowed. On success, `*error_out` is NULL when
/// no diagnostic is pending, otherwise an owned handle to view via
/// `line_sender_qwpws_error_get_view` and release via
/// `line_sender_qwpws_error_free`. The pool's error handler (see
/// `questdb_db_connect_with_handlers`) independently receives every
/// rejection at record time.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_sender_poll_error(
    sender: *mut qwp_sender,
    error_out: *mut *mut crate::line_sender_qwpws_error,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let fn_name = "qwp_sender_poll_error";
    if error_out.is_null() {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    format!("{fn_name}: error_out pointer is NULL"),
                ),
            );
        }
        return false;
    }
    unsafe {
        *error_out = std::ptr::null_mut();
    }
    if sender.is_null() {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    format!("{fn_name}: sender pointer is NULL"),
                ),
            );
        }
        return false;
    }
    let _guard = match unsafe {
        InUseGuard::acquire(
            sender,
            qwp_sender::latch(sender),
            fn_name,
            "qwp_sender",
            err_out,
        )
    } {
        Some(g) => g,
        None => return false,
    };
    if unsafe { reject_closed_pool_cs(sender, fn_name, err_out) } {
        return false;
    }
    let core = unsafe { qwp_sender::owned_ref(sender).get() };
    match core.poll_error() {
        Ok(Some(error)) => {
            unsafe {
                *error_out = Box::into_raw(Box::new(error.into()));
            }
            true
        }
        Ok(None) => true,
        Err(err) => {
            unsafe { set_err_out_from_error(err_out, err) };
            false
        }
    }
}

/// Diagnostics dropped from this connection's bounded ring
/// (`error_inbox_capacity`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_sender_error_events_dropped(
    sender: *const qwp_sender,
    dropped_out: *mut u64,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let fn_name = "qwp_sender_error_events_dropped";
    if dropped_out.is_null() {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    format!("{fn_name}: dropped_out pointer is NULL"),
                ),
            );
        }
        return false;
    }
    if sender.is_null() {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    format!("{fn_name}: sender pointer is NULL"),
                ),
            );
        }
        return false;
    }
    let handle = sender as *mut qwp_sender;
    let _guard = match unsafe {
        InUseGuard::acquire(
            handle,
            qwp_sender::latch(sender),
            fn_name,
            "qwp_sender",
            err_out,
        )
    } {
        Some(g) => g,
        None => return false,
    };
    if unsafe { reject_closed_pool_cs(sender, fn_name, err_out) } {
        return false;
    }
    let core = unsafe { qwp_sender::owned_ref(sender).get() };
    match core.error_events_dropped() {
        Ok(dropped) => {
            unsafe {
                *dropped_out = dropped;
            }
            true
        }
        Err(err) => {
            unsafe { set_err_out_from_error(err_out, err) };
            false
        }
    }
}

/// Return the current hard payload cap for this store-and-forward sender and
/// whether the current connection advertised `X-QWP-Max-Batch-Size` (whether
/// or not that value is the binding limit). The cap is always bounded by
/// configured `max_buf_size` and the queue's segment payload capacity, and may
/// change after reconnect.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_sender_effective_frame_cap(
    sender: *const qwp_sender,
    cap_out: *mut usize,
    server_cap_known_out: *mut bool,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let fn_name = "qwp_sender_effective_frame_cap";
    if cap_out.is_null() || server_cap_known_out.is_null() {
        let output = if cap_out.is_null() {
            "cap_out"
        } else {
            "server_cap_known_out"
        };
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    format!("{fn_name}: {output} pointer is NULL"),
                ),
            );
        }
        return false;
    }
    if sender.is_null() {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    format!("{fn_name}: sender pointer is NULL"),
                ),
            );
        }
        return false;
    }
    let handle = sender as *mut qwp_sender;
    let _guard = match unsafe {
        InUseGuard::acquire(
            handle,
            qwp_sender::latch(sender),
            fn_name,
            "qwp_sender",
            err_out,
        )
    } {
        Some(g) => g,
        None => return false,
    };
    if unsafe { reject_closed_pool_cs(sender, fn_name, err_out) } {
        return false;
    }
    let (cap, server_cap_known) =
        unsafe { qwp_sender::owned_ref(sender).get() }.effective_frame_cap();
    unsafe {
        *cap_out = cap;
        *server_cap_known_out = server_cap_known;
    }
    true
}

/// Return the highest QWP/WebSocket frame sequence number published locally
/// through this store-and-forward QWP sender, or no value if no frame has
/// been published.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_sender_published_fsn(
    sender: *const qwp_sender,
    fsn_out: *mut line_sender_qwpws_fsn,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        qwp_sender_fsn_watermark(
            sender,
            fsn_out,
            "qwp_sender_published_fsn",
            err_out,
            |sender| sender.published_fsn(),
        )
    }
}

/// Return the highest QWP/WebSocket frame sequence number completed by ACK, or
/// no value if no frame has completed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_sender_acked_fsn(
    sender: *const qwp_sender,
    fsn_out: *mut line_sender_qwpws_fsn,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        qwp_sender_fsn_watermark(sender, fsn_out, "qwp_sender_acked_fsn", err_out, |sender| {
            sender.acked_fsn()
        })
    }
}

/// Pipeline a deferred frame on a direct connection. Not committed until
/// `qwp_direct_sender_commit` / `qwp_direct_sender_flush_and_wait`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_direct_sender_flush(
    sender: *mut qwp_direct_sender,
    chunk: *mut qwp_chunk,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe { cs_flush_body(sender, chunk, "qwp_direct_sender_flush", err_out) }
}

/// Publish `chunk` as a completion boundary, then **wait** until every frame
/// published before or by this call reaches `ack_level` (see
/// `qwp_sender_wait` for the level meanings and the no-progress timeout).
///
/// `ack_level` carries a `qwpws_ack_level_*` constant; an out-of-range value,
/// or the Enterprise-only `qwpws_ack_level_durable` without
/// `request_durable_ack=on`, returns `line_sender_error_invalid_api_call`
/// **before** `chunk` is touched.
///
/// Boundary: a successful return acknowledges all prior no-wait flushes plus
/// this one. An empty `chunk` behaves like `qwp_direct_sender_commit`.
///
/// Failure contract: if the call fails before publication, `chunk` is left
/// untouched and retryable. Once the frame is published `chunk` is cleared even
/// if the ACK wait then fails — delivery of that frame is **unknown** and the
/// sender should be dropped/re-borrowed per the error class. There is no internal
/// failover retry.
///
/// Returns `true` on success, `false` on error (with `*err_out` set).
/// Direct-only combined publish+commit. Publishes `chunk` as a non-deferred
/// commit boundary and waits for `ack_level`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_direct_sender_flush_and_wait(
    sender: *mut qwp_direct_sender,
    chunk: *mut qwp_chunk,
    ack_level: u32,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        cs_flush_and_wait_body(
            sender,
            chunk,
            ack_level,
            "qwp_direct_sender_flush_and_wait",
            err_out,
        )
    }
}

/// Encode an Apache Arrow `RecordBatch` (Arrow C Data Interface) as a
/// single QWP/WebSocket frame for `table` and publish it through `sender`
/// in one pass — no intermediate buffer staging, no per-column copy.
///
/// `array` may be either a Struct array (one child per column, standard
/// RecordBatch shape) or a non-Struct single-column array whose
/// `schema->name` becomes the column name.
///
/// The per-row designated timestamp is omitted; the server stamps each
/// row on arrival. This is an **explicit opt-in**: if your batch carries
/// a real event-time column, use [`qwp_sender_flush_arrow_batch_at_column`]
/// instead to source the timestamp from a `Timestamp(_)` column inside the
/// batch — reaching for this entry point would discard that column's role
/// as the designated timestamp and silently substitute server arrival time.
///
/// Ownership: on success, `array->release` is consumed (set to NULL)
/// and the function has invoked it internally. On a **transient,
/// provably-not-delivered** (`line_sender_error_failover_retry` with
/// `line_sender_error_in_doubt == false`) failure `array` is left intact
/// (re-exported back into `*array` with a fresh `release`) so the caller
/// can drop+re-borrow a live sender and retry with the same array. A
/// delivery-unknown failure (a partial write that fails mid-frame: also
/// `line_sender_error_failover_retry` but with `line_sender_error_in_doubt ==
/// true`) is **not** re-exported, since replaying it could duplicate rows. On
/// any failure `array->release` may have been consumed if the call reached the
/// Arrow import step — callers MUST check `array->release != NULL` before
/// invoking it on the failure path. `schema` is always borrowed.
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
pub unsafe extern "C" fn qwp_sender_flush_arrow_batch_at_now(
    sender: *mut qwp_sender,
    table: line_sender_table_name,
    array: *mut arrow::ffi::FFI_ArrowArray,
    schema: *const arrow::ffi::FFI_ArrowSchema,
    overrides: *const qwp_arrow_override,
    overrides_len: size_t,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        arrow_batch_impl(
            "qwp_sender_flush_arrow_batch_at_now",
            sender,
            table,
            array,
            schema,
            FfiArrowTs::ServerNow,
            overrides,
            overrides_len,
            err_out,
        )
    }
}

/// FSN-returning counterpart of `qwp_sender_flush_arrow_batch_at_now`.
/// Local publication semantics and Arrow ownership are the same as the
/// non-FSN variant.
#[cfg(feature = "arrow")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_sender_flush_arrow_batch_at_now_and_get_fsn(
    sender: *mut qwp_sender,
    table: line_sender_table_name,
    array: *mut arrow::ffi::FFI_ArrowArray,
    schema: *const arrow::ffi::FFI_ArrowSchema,
    overrides: *const qwp_arrow_override,
    overrides_len: size_t,
    fsn_out: *mut line_sender_qwpws_fsn,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        arrow_batch_impl_and_get_fsn(
            "qwp_sender_flush_arrow_batch_at_now_and_get_fsn",
            sender,
            table,
            array,
            schema,
            None,
            overrides,
            overrides_len,
            fsn_out,
            err_out,
        )
    }
}

/// ACKing counterpart of `qwp_sender_flush_arrow_batch_at_now`: publish
/// `array` as a boundary, then wait for `ack_level`.
///
/// Same ACK-validation preflight and phase-aware re-export contract as
/// `qwp_direct_sender_flush_arrow_batch_at_now_and_wait`.
#[cfg(feature = "arrow")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_sender_flush_arrow_batch_at_now_and_wait(
    sender: *mut qwp_sender,
    table: line_sender_table_name,
    array: *mut arrow::ffi::FFI_ArrowArray,
    schema: *const arrow::ffi::FFI_ArrowSchema,
    overrides: *const qwp_arrow_override,
    overrides_len: size_t,
    ack_level: u32,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        arrow_batch_impl_and_wait(
            "qwp_sender_flush_arrow_batch_at_now_and_wait",
            sender,
            table,
            array,
            schema,
            None,
            overrides,
            overrides_len,
            ack_level,
            err_out,
        )
    }
}

/// Direct-handle publish-only Arrow flush (server-stamped). Pair with
/// `qwp_direct_sender_commit`, or use
/// `qwp_direct_sender_flush_arrow_batch_at_now_and_wait`.
#[cfg(feature = "arrow")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_direct_sender_flush_arrow_batch_at_now(
    sender: *mut qwp_direct_sender,
    table: line_sender_table_name,
    array: *mut arrow::ffi::FFI_ArrowArray,
    schema: *const arrow::ffi::FFI_ArrowSchema,
    overrides: *const qwp_arrow_override,
    overrides_len: size_t,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        arrow_batch_impl(
            "qwp_direct_sender_flush_arrow_batch_at_now",
            sender,
            table,
            array,
            schema,
            FfiArrowTs::ServerNow,
            overrides,
            overrides_len,
            err_out,
        )
    }
}

/// Variant of [`qwp_sender_flush_arrow_batch_at_now`] that
/// sources each row's designated timestamp from a named `Timestamp(_)`
/// column inside the batch. The column must be `Timestamp(Microsecond |
/// Nanosecond | Millisecond, _)` with no null rows and no values before
/// the Unix epoch. Same ownership and `overrides` contract.
#[cfg(feature = "arrow")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_sender_flush_arrow_batch_at_column(
    sender: *mut qwp_sender,
    table: line_sender_table_name,
    array: *mut arrow::ffi::FFI_ArrowArray,
    schema: *const arrow::ffi::FFI_ArrowSchema,
    ts_column: line_sender_column_name,
    overrides: *const qwp_arrow_override,
    overrides_len: size_t,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        arrow_batch_impl(
            "qwp_sender_flush_arrow_batch_at_column",
            sender,
            table,
            array,
            schema,
            FfiArrowTs::Column(ts_column),
            overrides,
            overrides_len,
            err_out,
        )
    }
}

/// FSN-returning counterpart of
/// `qwp_sender_flush_arrow_batch_at_column`.
#[cfg(feature = "arrow")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_sender_flush_arrow_batch_at_column_and_get_fsn(
    sender: *mut qwp_sender,
    table: line_sender_table_name,
    array: *mut arrow::ffi::FFI_ArrowArray,
    schema: *const arrow::ffi::FFI_ArrowSchema,
    ts_column: line_sender_column_name,
    overrides: *const qwp_arrow_override,
    overrides_len: size_t,
    fsn_out: *mut line_sender_qwpws_fsn,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        arrow_batch_impl_and_get_fsn(
            "qwp_sender_flush_arrow_batch_at_column_and_get_fsn",
            sender,
            table,
            array,
            schema,
            Some(ts_column),
            overrides,
            overrides_len,
            fsn_out,
            err_out,
        )
    }
}

/// ACKing counterpart of `qwp_sender_flush_arrow_batch_at_column`: publish
/// `array` (timestamp sourced from `ts_column`) as a boundary, then wait for
/// `ack_level`. Same ACK-validation preflight and phase-aware re-export
/// contract as `qwp_sender_flush_arrow_batch_at_now_and_wait`.
#[cfg(feature = "arrow")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_sender_flush_arrow_batch_at_column_and_wait(
    sender: *mut qwp_sender,
    table: line_sender_table_name,
    array: *mut arrow::ffi::FFI_ArrowArray,
    schema: *const arrow::ffi::FFI_ArrowSchema,
    ts_column: line_sender_column_name,
    overrides: *const qwp_arrow_override,
    overrides_len: size_t,
    ack_level: u32,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        arrow_batch_impl_and_wait(
            "qwp_sender_flush_arrow_batch_at_column_and_wait",
            sender,
            table,
            array,
            schema,
            Some(ts_column),
            overrides,
            overrides_len,
            ack_level,
            err_out,
        )
    }
}

/// Direct-handle publish-only Arrow flush (column-stamped). Pair with
/// `qwp_direct_sender_commit`, or use
/// `qwp_direct_sender_flush_arrow_batch_at_column_and_wait`.
#[cfg(feature = "arrow")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_direct_sender_flush_arrow_batch_at_column(
    sender: *mut qwp_direct_sender,
    table: line_sender_table_name,
    array: *mut arrow::ffi::FFI_ArrowArray,
    schema: *const arrow::ffi::FFI_ArrowSchema,
    ts_column: line_sender_column_name,
    overrides: *const qwp_arrow_override,
    overrides_len: size_t,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        arrow_batch_impl(
            "qwp_direct_sender_flush_arrow_batch_at_column",
            sender,
            table,
            array,
            schema,
            FfiArrowTs::Column(ts_column),
            overrides,
            overrides_len,
            err_out,
        )
    }
}

/// Direct-handle publish-only Arrow flush with one scalar
/// nanosecond-precision Unix epoch timestamp as every row's designated
/// timestamp, encoded as a repeated constant. Unlike
/// `qwp_direct_sender_flush_arrow_batch_at_now` the value is fixed at
/// the caller, so resubmission is idempotent under `DEDUP UPSERT KEYS`.
/// Rejects negative (pre-epoch) values. Same ownership and `overrides`
/// contract as `qwp_direct_sender_flush_arrow_batch_at_now`.
#[cfg(feature = "arrow")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_direct_sender_flush_arrow_batch_at_scalar_nanos(
    sender: *mut qwp_direct_sender,
    table: line_sender_table_name,
    array: *mut arrow::ffi::FFI_ArrowArray,
    schema: *const arrow::ffi::FFI_ArrowSchema,
    at_nanos: i64,
    overrides: *const qwp_arrow_override,
    overrides_len: size_t,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        arrow_batch_impl(
            "qwp_direct_sender_flush_arrow_batch_at_scalar_nanos",
            sender,
            table,
            array,
            schema,
            FfiArrowTs::ScalarNanos(at_nanos),
            overrides,
            overrides_len,
            err_out,
        )
    }
}

/// ACKing counterpart of `qwp_sender_flush_arrow_batch_at_now`:
/// publish `array` as a boundary, then wait for `ack_level`.
///
/// `ack_level` carries a `qwpws_ack_level_*` constant. It is validated
/// **before** the Arrow C Data Interface import consumes `array->release`, so a
/// rejected level (out-of-range, or the Enterprise-only `durable` without
/// `request_durable_ack=on`) returns `line_sender_error_invalid_api_call` and
/// leaves `array` untouched.
///
/// Ownership differs from the publish-only flush on the failure path. On a
/// failure that is provably **pre-publication** (validation, encode, size, or a
/// transport error before any byte was written) the batch is re-exported back
/// into `*array` with a fresh `release` so the caller can drop+re-borrow and
/// retry. On any **post-publication** failure — including an ACK-wait or SFA
/// no-progress timeout reported as `line_sender_error_failover_retry` — the
/// batch is **not** re-exported (`array->release` stays NULL): delivery is
/// unknown and a blind replay could duplicate rows. Callers MUST check
/// `array->release != NULL` before invoking it on the failure path.
///
/// Returns `true` on success, `false` on error (with `*err_out` set).
#[cfg(feature = "arrow")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_direct_sender_flush_arrow_batch_at_now_and_wait(
    sender: *mut qwp_direct_sender,
    table: line_sender_table_name,
    array: *mut arrow::ffi::FFI_ArrowArray,
    schema: *const arrow::ffi::FFI_ArrowSchema,
    overrides: *const qwp_arrow_override,
    overrides_len: size_t,
    ack_level: u32,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        arrow_batch_impl_and_wait(
            "qwp_direct_sender_flush_arrow_batch_at_now_and_wait",
            sender,
            table,
            array,
            schema,
            None,
            overrides,
            overrides_len,
            ack_level,
            err_out,
        )
    }
}

/// ACKing counterpart of `qwp_sender_flush_arrow_batch_at_column`: publish
/// `array` (timestamp sourced from `ts_column`) as a boundary, then wait for
/// `ack_level`. Same ACK-validation preflight and phase-aware re-export
/// contract as `qwp_sender_flush_arrow_batch_at_now_and_wait`.
#[cfg(feature = "arrow")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_direct_sender_flush_arrow_batch_at_column_and_wait(
    sender: *mut qwp_direct_sender,
    table: line_sender_table_name,
    array: *mut arrow::ffi::FFI_ArrowArray,
    schema: *const arrow::ffi::FFI_ArrowSchema,
    ts_column: line_sender_column_name,
    overrides: *const qwp_arrow_override,
    overrides_len: size_t,
    ack_level: u32,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        arrow_batch_impl_and_wait(
            "qwp_direct_sender_flush_arrow_batch_at_column_and_wait",
            sender,
            table,
            array,
            schema,
            Some(ts_column),
            overrides,
            overrides_len,
            ack_level,
            err_out,
        )
    }
}

/// Per-column wire-type hint kind passed in
/// [`qwp_arrow_override::kind`].
#[cfg(feature = "arrow")]
#[repr(u32)]
#[allow(non_camel_case_types)]
pub enum qwp_arrow_override_kind {
    qwp_arrow_override_symbol = 0,
    qwp_arrow_override_ipv4 = 1,
    qwp_arrow_override_char = 2,
    qwp_arrow_override_geohash = 3,
    qwp_arrow_override_not_symbol = 4,
}

/// Per-column wire-type hint that overrides what the encoder would
/// otherwise derive from the Arrow `Field`'s data type alone. Caller
/// owns `column`; the bytes are borrowed for the duration of the
/// `qwp_sender_flush_arrow_batch_at_now` / `_at_column` call
/// and must outlive it.
#[cfg(feature = "arrow")]
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct qwp_arrow_override {
    /// UTF-8 column name; not necessarily NUL-terminated.
    pub column: *const c_char,
    pub column_len: size_t,
    /// One of `qwp_arrow_override_kind` as `u32`.
    pub kind: u32,
    /// Kind-specific argument:
    /// - `_geohash`: precision bits (1..=60).
    /// - all other kinds: ignored; pass 0.
    ///
    /// To force a column NOT to be SYMBOL (Dictionary columns decode to
    /// VARCHAR on emit; no-op on plain Utf8) use the dedicated
    /// `_not_symbol` kind, not a non-zero `arg`.
    pub arg: u32,
}

#[cfg(feature = "arrow")]
const MAX_ARROW_OVERRIDES: usize = 65_536;
#[cfg(feature = "arrow")]
const MAX_ARROW_OVERRIDE_COLUMN_NAME_LEN: usize = 65_536;

#[cfg(feature = "arrow")]
unsafe fn arrow_overrides_from_c<'a>(
    fn_name: &str,
    overrides: *const qwp_arrow_override,
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
            format!("{fn_name}: overrides pointer is NULL"),
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
            x if x == qwp_arrow_override_kind::qwp_arrow_override_symbol as u32 => {
                ArrowColumnOverride::Symbol { column }
            }
            x if x == qwp_arrow_override_kind::qwp_arrow_override_not_symbol as u32 => {
                ArrowColumnOverride::NotSymbol { column }
            }
            x if x == qwp_arrow_override_kind::qwp_arrow_override_ipv4 as u32 => {
                ArrowColumnOverride::Ipv4 { column }
            }
            x if x == qwp_arrow_override_kind::qwp_arrow_override_char as u32 => {
                ArrowColumnOverride::Char { column }
            }
            x if x == qwp_arrow_override_kind::qwp_arrow_override_geohash as u32 => {
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

/// Designated timestamp source for the plain (publish-only) Arrow FFI
/// entry points.
#[cfg(feature = "arrow")]
#[derive(Clone, Copy)]
enum FfiArrowTs {
    Column(line_sender_column_name),
    ScalarNanos(i64),
    ServerNow,
}

#[cfg(feature = "arrow")]
#[allow(clippy::too_many_arguments)]
unsafe fn arrow_batch_impl<T: CsHandle>(
    fn_name: &'static str,
    sender: *mut T,
    table: line_sender_table_name,
    array: *mut arrow::ffi::FFI_ArrowArray,
    schema: *const arrow::ffi::FFI_ArrowSchema,
    ts: FfiArrowTs,
    overrides_ptr: *const qwp_arrow_override,
    overrides_len: size_t,
    err_out: *mut *mut line_sender_error,
) -> bool {
    if sender.is_null() {
        crate::arrow_err_to_c_box(
            err_out,
            ErrorCode::InvalidApiCall,
            format!("{fn_name}: sender pointer is NULL"),
        );
        return false;
    }
    let _guard = match unsafe {
        InUseGuard::acquire(sender, T::latch(sender), fn_name, T::TYPE_NAME, err_out)
    } {
        Some(g) => g,
        None => return false,
    };
    if unsafe { reject_closed_pool_cs(sender, fn_name, err_out) } {
        return false;
    }
    let overrides =
        match unsafe { arrow_overrides_from_c(fn_name, overrides_ptr, overrides_len, err_out) } {
            Some(v) => v,
            None => return false,
        };
    let rb = match unsafe { crate::arrow_ffi_import_record_batch(array, schema, fn_name, err_out) }
    {
        Some(rb) => rb,
        None => return false,
    };
    let table_name = unsafe { table.as_name() };
    let result = match ts {
        FfiArrowTs::Column(c) => unsafe {
            T::flush_arrow_at_column(sender, table_name, &rb, c.as_name(), &overrides)
        },
        FfiArrowTs::ScalarNanos(nanos) => unsafe {
            T::flush_arrow_at_scalar_nanos(sender, table_name, &rb, nanos, &overrides)
        },
        FfiArrowTs::ServerNow => unsafe {
            T::flush_arrow_at_now(sender, table_name, &rb, &overrides)
        },
    };
    match result {
        Ok(()) => true,
        Err(err) => {
            // A provably-not-delivered failure must leave the caller's
            // `array` intact so it can retry with the same data (on a fresh
            // sender for a transient error, after a commit for a deferred-
            // capacity error). The import already consumed `array->release`,
            // so we re-export the still-live `RecordBatch` back into `*array`
            // (matching the caller's retained `schema` shape), restoring a
            // valid release.
            //
            // `in_doubt` carries the delivery classification: a direct-mode
            // partial write fails mid-frame delivery-unknown (`in_doubt`),
            // and re-exporting it would invite a duplicate-causing retry —
            // that is the one case that must consume the array.
            if !err.in_doubt() {
                unsafe { reexport_record_batch_into(rb, array, schema) };
            }
            unsafe { set_err_out_from_error(err_out, err) };
            false
        }
    }
}

#[cfg(feature = "arrow")]
#[allow(clippy::too_many_arguments)]
unsafe fn arrow_batch_impl_and_get_fsn(
    fn_name: &'static str,
    sender: *mut qwp_sender,
    table: line_sender_table_name,
    array: *mut arrow::ffi::FFI_ArrowArray,
    schema: *const arrow::ffi::FFI_ArrowSchema,
    ts_column: Option<line_sender_column_name>,
    overrides_ptr: *const qwp_arrow_override,
    overrides_len: size_t,
    fsn_out: *mut line_sender_qwpws_fsn,
    err_out: *mut *mut line_sender_error,
) -> bool {
    if unsafe { reject_null_fsn_out(fsn_out, fn_name, err_out) } {
        return false;
    }
    if sender.is_null() {
        crate::arrow_err_to_c_box(
            err_out,
            ErrorCode::InvalidApiCall,
            format!("{fn_name}: sender pointer is NULL"),
        );
        return false;
    }
    let _guard = match unsafe {
        InUseGuard::acquire(
            sender,
            qwp_sender::latch(sender),
            fn_name,
            "qwp_sender",
            err_out,
        )
    } {
        Some(g) => g,
        None => return false,
    };
    if unsafe { reject_closed_pool_cs(sender, fn_name, err_out) } {
        return false;
    }
    let overrides =
        match unsafe { arrow_overrides_from_c(fn_name, overrides_ptr, overrides_len, err_out) } {
            Some(v) => v,
            None => return false,
        };
    let rb = match unsafe { crate::arrow_ffi_import_record_batch(array, schema, fn_name, err_out) }
    {
        Some(rb) => rb,
        None => return false,
    };
    let table_name = unsafe { table.as_name() };
    let sender = unsafe { qwp_sender::owned_mut(sender).get_mut() };
    let result = match ts_column {
        Some(ts) => sender.flush_arrow_batch_at_column_and_get_fsn(
            table_name,
            &rb,
            ts.as_name(),
            &overrides,
        ),
        None => sender.flush_arrow_batch_at_now_and_get_fsn(table_name, &rb, &overrides),
    };
    match result {
        Ok(fsn) => {
            unsafe {
                *fsn_out = line_sender_qwpws_fsn::from_option(fsn);
            }
            true
        }
        Err(err) => {
            if !err.in_doubt() {
                unsafe { reexport_record_batch_into(rb, array, schema) };
            }
            unsafe { set_err_out_from_error(err_out, err) };
            false
        }
    }
}

/// ACKing variant of [`arrow_batch_impl`]. Validates `ack_level` **before** the
/// Arrow import consumes `array->release`, then publishes and waits.
///
/// The re-export decision is driven by the [`FlushFailure`] delivery
/// classification, **not** by the error code: re-export only when the flush
/// primitive reports `NotDelivered` (the batch was provably not transmitted),
/// never on `DeliveryUnknown` (write succeeded/partial, or the post-publish ACK
/// wait failed) — even when that surfaces as `FailoverRetry`.
#[cfg(feature = "arrow")]
#[allow(clippy::too_many_arguments)]
unsafe fn arrow_batch_impl_and_wait<T: CsHandle>(
    fn_name: &'static str,
    sender: *mut T,
    table: line_sender_table_name,
    array: *mut arrow::ffi::FFI_ArrowArray,
    schema: *const arrow::ffi::FFI_ArrowSchema,
    ts_column: Option<line_sender_column_name>,
    overrides_ptr: *const qwp_arrow_override,
    overrides_len: size_t,
    ack_level: u32,
    err_out: *mut *mut line_sender_error,
) -> bool {
    // ACK-level parse preflight: precedes the guard, the import, and any
    // caller-owned input being consumed.
    let ack_level = match ack_level_from_u32(ack_level, err_out) {
        Some(l) => l,
        None => return false,
    };
    if sender.is_null() {
        crate::arrow_err_to_c_box(
            err_out,
            ErrorCode::InvalidApiCall,
            format!("{fn_name}: sender pointer is NULL"),
        );
        return false;
    }
    let _guard = match unsafe {
        InUseGuard::acquire(sender, T::latch(sender), fn_name, T::TYPE_NAME, err_out)
    } {
        Some(g) => g,
        None => return false,
    };
    if unsafe { reject_closed_pool_cs(sender, fn_name, err_out) } {
        return false;
    }
    let overrides =
        match unsafe { arrow_overrides_from_c(fn_name, overrides_ptr, overrides_len, err_out) } {
            Some(v) => v,
            None => return false,
        };
    // Durable opt-in preflight: reject before the import consumes
    // `array->release`, so a rejected level leaves the caller's array intact.
    if let Err(err) = unsafe { T::validate_ack_level(sender, ack_level) } {
        unsafe { set_err_out_from_error(err_out, err) };
        return false;
    }
    let rb = match unsafe { crate::arrow_ffi_import_record_batch(array, schema, fn_name, err_out) }
    {
        Some(rb) => rb,
        None => return false,
    };
    let table_name = unsafe { table.as_name() };
    let result = match ts_column {
        Some(ts) => unsafe {
            T::flush_arrow_at_column_and_wait(
                sender,
                table_name,
                &rb,
                ts.as_name(),
                &overrides,
                ack_level,
            )
        },
        None => unsafe {
            T::flush_arrow_at_now_and_wait(sender, table_name, &rb, &overrides, ack_level)
        },
    };
    match result {
        Ok(()) => true,
        Err(flush_failure) => {
            // Phase-aware re-export: `NotDelivered` is safe to retry on a fresh
            // sender, so restore the caller's array; `DeliveryUnknown` is not.
            let reexport = flush_failure.is_not_delivered();
            let err = flush_failure.into_error();
            if reexport {
                unsafe { reexport_record_batch_into(rb, array, schema) };
            }
            unsafe { set_err_out_from_error(err_out, err) };
            false
        }
    }
}

/// Re-export `rb` back into the caller's `*array`, restoring the `release`
/// consumed during import so the caller can retry on a fresh sender. The shape
/// must match the caller's **retained** `schema` (which is borrowed and never
/// consumed): a Struct schema → a Struct array (one child per column); a bare
/// single-column non-Struct schema → that one column's array directly.
///
/// This shape match is load-bearing: `arrow_ffi_import_record_batch` wraps a
/// bare single-column input into a one-column `RecordBatch`, so re-exporting it
/// unconditionally as a Struct array would yield an array whose child count (1)
/// disagrees with the still-primitive schema (0 children) and the retry would
/// be rejected by `validate_arrow_array_depth`.
///
/// Best-effort: an export failure leaves `array->release == NULL`, which the
/// caller already must tolerate per the documented ownership contract.
#[cfg(feature = "arrow")]
unsafe fn reexport_record_batch_into(
    rb: arrow::array::RecordBatch,
    array: *mut arrow::ffi::FFI_ArrowArray,
    schema: *const arrow::ffi::FFI_ArrowSchema,
) {
    use arrow::array::{Array, StructArray};
    use arrow::datatypes::DataType;

    // A non-Struct top-level schema means the caller passed a bare
    // single-column array; mirror that shape so the re-exported array pairs
    // with the retained schema. Default to the Struct shape if the schema
    // can't be read (it validated during import, so this should not happen).
    let top_is_struct = unsafe { DataType::try_from(&*schema) }
        .map(|dt| matches!(dt, DataType::Struct(_)))
        .unwrap_or(true);

    let array_data = if !top_is_struct && rb.num_columns() == 1 {
        rb.column(0).to_data()
    } else {
        StructArray::from(rb).into_data()
    };

    if let Ok((ffi_array, _ffi_schema)) = arrow::ffi::to_ffi(&array_data) {
        unsafe { std::ptr::write(array, ffi_array) };
    }
}

/// Block until all in-flight frames are acknowledged at the requested
/// `ack_level`. In direct mode this sends a commit-triggering frame first. In
/// store-and-forward mode all data frames are already non-deferred, so sync
/// waits for the local queue boundary published before the call.
///
/// `qwpws_ack_level_ok` waits for every in-flight frame's WAL-commit ack.
/// `qwpws_ack_level_durable` requires QuestDB Enterprise and additionally
/// waits for the server's object-store durability watermarks.
///
/// No-progress timeout: if the server stays connected but never advances the
/// ack/durable watermark — a back-pressured WAL or stuck commit — the wait
/// returns `line_sender_error_failover_retry`. The deadline resets on every
/// watermark advance, so a slow-but-progressing wait (e.g. a `durable` upload
/// under pressure) is not cut off. The unacked frames are retained: drop the
/// sender and re-borrow to replay (store-and-forward) or re-drive from source
/// (direct).
///
/// `timeout` selects the bound: `Some` is the store-and-forward `wait`'s
/// per-call no-progress deadline (`Duration::ZERO` waits forever); `None` is
/// the direct `commit`, whose bound is the connection `request_timeout`.
///
/// Returns `true` on success, `false` on error (with `*err_out` set).
unsafe fn cs_wait_body<T: CsHandle>(
    sender: *mut T,
    ack_level: u32,
    timeout: Option<std::time::Duration>,
    fn_name: &str,
    err_out: *mut *mut line_sender_error,
) -> bool {
    let ack_level = match ack_level_from_u32(ack_level, err_out) {
        Some(l) => l,
        None => return false,
    };
    if sender.is_null() {
        unsafe {
            set_err_out_from_error(
                err_out,
                Error::new(
                    ErrorCode::InvalidApiCall,
                    format!("{fn_name}: sender pointer is NULL"),
                ),
            );
        }
        return false;
    }
    let _guard = match unsafe {
        InUseGuard::acquire(sender, T::latch(sender), fn_name, T::TYPE_NAME, err_out)
    } {
        Some(g) => g,
        None => return false,
    };
    if unsafe { reject_closed_pool_cs(sender, fn_name, err_out) } {
        return false;
    }
    bubble_err_to_c!(err_out, unsafe {
        T::wait_or_commit(sender, ack_level, timeout)
    });
    true
}

/// Store-and-forward ack barrier: block until every frame published through
/// this borrow of `sender` reaches `ack_level`. The SFA queue owns delivery,
/// so this is needed only to *observe* the ack, never for durability.
///
/// The barrier is a watermark check plus a terminal-latch check: only a
/// terminal connection failure fails it. Server rejections — the borrow's
/// own and earlier borrows' alike — are delivered to the pool's rejection
/// handler (default: logged) rather than raised here; retriable ones are
/// replayed by the queue.
///
/// `timeout_millis` is a no-progress deadline (it fires only if the ack
/// watermark fails to advance for that long); `0` waits indefinitely.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_sender_wait(
    sender: *mut qwp_sender,
    ack_level: u32,
    timeout_millis: u64,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe {
        cs_wait_body(
            sender,
            ack_level,
            Some(std::time::Duration::from_millis(timeout_millis)),
            "qwp_sender_wait",
            err_out,
        )
    }
}

/// Direct commit: send the commit boundary for all pipelined frames and block
/// until they reach `ack_level`. The direct sender's durability checkpoint.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qwp_direct_sender_commit(
    sender: *mut qwp_direct_sender,
    ack_level: u32,
    err_out: *mut *mut line_sender_error,
) -> bool {
    unsafe { cs_wait_body(sender, ack_level, None, "qwp_direct_sender_commit", err_out) }
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
                "qwp_chunk pointer is NULL".to_string(),
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
                "qwp_arrow_import pointer is NULL".to_string(),
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
    fn borrow_sender_with_retry_null_db_is_safe() {
        // The NULL-db guard lives in `borrow_cs`, shared by both retry shims:
        // NULL in → NULL out + a populated error, never a deref/abort.
        for budget in [0u64, 50] {
            let mut err_sf: *mut line_sender_error = std::ptr::null_mut();
            let sf = unsafe {
                questdb_db_borrow_sender_with_retry(std::ptr::null_mut(), budget, &mut err_sf)
            };
            assert!(sf.is_null());
            assert!(!err_sf.is_null());
            unsafe { line_sender_error_free(err_sf) };

            let mut err_direct: *mut line_sender_error = std::ptr::null_mut();
            let direct = unsafe {
                questdb_db_borrow_direct_sender_with_retry(
                    std::ptr::null_mut(),
                    budget,
                    &mut err_direct,
                )
            };
            assert!(direct.is_null());
            assert!(!err_direct.is_null());
            unsafe { line_sender_error_free(err_direct) };
        }
    }

    #[test]
    fn effective_frame_cap_rejects_null_pointers() {
        let mut cap = 0usize;
        let mut known = false;

        let mut err: *mut line_sender_error = std::ptr::null_mut();
        assert!(!unsafe {
            qwp_sender_effective_frame_cap(std::ptr::null(), &mut cap, &mut known, &mut err)
        });
        assert!(!err.is_null());
        unsafe { line_sender_error_free(err) };

        err = std::ptr::null_mut();
        assert!(!unsafe {
            qwp_sender_effective_frame_cap(
                std::ptr::null(),
                std::ptr::null_mut(),
                &mut known,
                &mut err,
            )
        });
        assert!(!err.is_null());
        unsafe { line_sender_error_free(err) };

        err = std::ptr::null_mut();
        assert!(!unsafe {
            qwp_sender_effective_frame_cap(
                std::ptr::null(),
                &mut cap,
                std::ptr::null_mut(),
                &mut err,
            )
        });
        assert!(!err.is_null());
        unsafe { line_sender_error_free(err) };
    }

    #[test]
    fn borrow_direct_column_sender_with_retry_fails_against_dead_endpoint() {
        // Bind then drop to get a definitely-closed local port. The pool is
        // lazy, so the connect only happens on borrow; a closed port refuses
        // immediately, so the Direct retry shim must exhaust its budget and
        // surface NULL + a populated error across the FFI boundary — not panic
        // or abort under the crate's `panic = "abort"` profile.
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1");
            listener.local_addr().expect("local_addr").port()
        };
        let conf = format!(
            "ws::addr=127.0.0.1:{port};auth_timeout=2000;reconnect_max_duration_millis=1000;"
        );
        let mut err: *mut line_sender_error = std::ptr::null_mut();
        let db =
            unsafe { questdb_db_connect(conf.as_ptr() as *const c_char, conf.len(), &mut err) };
        assert!(
            !db.is_null(),
            "lazy connect opens no socket, so it succeeds"
        );
        assert!(err.is_null());

        // Non-zero budget: the retry loop makes a few attempts, then gives up
        // once the budget is spent.
        let sender = unsafe { questdb_db_borrow_direct_sender_with_retry(db, 150, &mut err) };
        assert!(sender.is_null(), "borrow against a closed port must fail");
        assert!(!err.is_null(), "a failed borrow must populate err_out");
        unsafe { line_sender_error_free(err) };

        // Zero budget makes a single attempt; still fails, error reported, no
        // leak or panic.
        let mut err0: *mut line_sender_error = std::ptr::null_mut();
        let conn0 = unsafe { questdb_db_borrow_direct_sender_with_retry(db, 0, &mut err0) };
        assert!(conn0.is_null());
        assert!(!err0.is_null());
        unsafe { line_sender_error_free(err0) };

        unsafe { questdb_db_close(db) };
    }

    #[test]
    fn chunk_new_defers_table_name_validation() {
        // The 128-byte name exceeds the QWP 127-byte cap and contains
        // grammatically valid characters; both checks are deferred to
        // flush per the documented contract on `Chunk::new`.
        let mut err: *mut line_sender_error = std::ptr::null_mut();
        let table = "x".repeat(128);
        let chunk =
            unsafe { qwp_chunk_new(table.as_ptr() as *const c_char, table.len(), &mut err) };
        assert!(!chunk.is_null());
        assert!(err.is_null());
        unsafe { qwp_chunk_free(chunk) };
    }

    #[test]
    fn chunk_new_rejects_invalid_utf8() {
        let bad: [u8; 3] = [0xFF, 0xFE, 0xFD];
        let mut err: *mut line_sender_error = std::ptr::null_mut();
        let chunk = unsafe { qwp_chunk_new(bad.as_ptr() as *const c_char, bad.len(), &mut err) };
        assert!(chunk.is_null());
        assert!(!err.is_null());
        unsafe { line_sender_error_free(err) };
    }

    #[test]
    fn chunk_at_now_null_guard_happy_path_and_ts_conflict() {
        let mut err: *mut line_sender_error = std::ptr::null_mut();

        // NULL chunk rejects without touching err-free invariants.
        let ok = unsafe { qwp_chunk_at_now(std::ptr::null_mut(), &mut err) };
        assert!(!ok);
        assert!(!err.is_null());
        unsafe { line_sender_error_free(err) };
        err = std::ptr::null_mut();

        let table = b"trades";
        let chunk =
            unsafe { qwp_chunk_new(table.as_ptr() as *const c_char, table.len(), &mut err) };
        assert!(!chunk.is_null());

        assert!(unsafe { qwp_chunk_at_now(chunk, &mut err) });
        assert!(err.is_null());

        // A designated ts column now conflicts with the at_now opt-in.
        let ts = [1i64, 2, 3];
        let ok = unsafe { qwp_chunk_at_micros(chunk, ts.as_ptr(), ts.len(), &mut err) };
        assert!(!ok);
        assert!(!err.is_null());
        unsafe { line_sender_error_free(err) };
        err = std::ptr::null_mut();

        // clear() resets the opt-in: the ts column is accepted again.
        assert!(unsafe { qwp_chunk_clear(chunk, &mut err) });
        assert!(unsafe { qwp_chunk_at_micros(chunk, ts.as_ptr(), ts.len(), &mut err) });
        assert!(err.is_null());

        unsafe { qwp_chunk_free(chunk) };
    }

    #[test]
    fn chunk_at_scalar_nanos_null_guard_validation_and_conflict() {
        let mut err: *mut line_sender_error = std::ptr::null_mut();

        let ok = unsafe { qwp_chunk_at_scalar_nanos(std::ptr::null_mut(), 7, &mut err) };
        assert!(!ok);
        assert!(!err.is_null());
        unsafe { line_sender_error_free(err) };
        err = std::ptr::null_mut();

        let table = b"trades";
        let chunk =
            unsafe { qwp_chunk_new(table.as_ptr() as *const c_char, table.len(), &mut err) };
        assert!(!chunk.is_null());

        let ok = unsafe { qwp_chunk_at_scalar_nanos(chunk, -1, &mut err) };
        assert!(!ok);
        assert!(!err.is_null());
        unsafe { line_sender_error_free(err) };
        err = std::ptr::null_mut();

        assert!(unsafe { qwp_chunk_at_scalar_nanos(chunk, 7, &mut err) });
        assert!(err.is_null());

        let ts = [1i64, 2, 3];
        let ok = unsafe { qwp_chunk_at_micros(chunk, ts.as_ptr(), ts.len(), &mut err) };
        assert!(!ok);
        assert!(!err.is_null());
        unsafe { line_sender_error_free(err) };
        err = std::ptr::null_mut();

        assert!(unsafe { qwp_chunk_clear(chunk, &mut err) });
        assert!(unsafe { qwp_chunk_at_micros(chunk, ts.as_ptr(), ts.len(), &mut err) });
        assert!(err.is_null());

        unsafe { qwp_chunk_free(chunk) };
    }

    #[test]
    fn chunk_new_validated_accepts_prevalidated_table_name() {
        // M7 regression: a caller who already validated a table name into a
        // `line_sender_table_name` (e.g. to reuse it across an Arrow flush via
        // `qwp_sender_flush_arrow_batch_at_column`) must be able to feed the
        // SAME validated handle into the chunk path, rather than being forced
        // to re-pass raw `const char*` bytes to `qwp_chunk_new`.
        let raw = b"trades";
        let mut err: *mut line_sender_error = std::ptr::null_mut();
        let mut table = line_sender_table_name {
            len: 0,
            buf: std::ptr::null(),
        };
        let ok = unsafe {
            crate::line_sender_table_name_init(
                &mut table,
                raw.len(),
                raw.as_ptr() as *const c_char,
                &mut err,
            )
        };
        assert!(ok, "valid table name should init");
        assert!(err.is_null());

        let chunk = unsafe { qwp_chunk_new_validated(table, &mut err) };
        assert!(
            !chunk.is_null(),
            "validated chunk constructor should succeed"
        );
        assert!(err.is_null());

        // The resulting chunk behaves identically to one built via the raw
        // `qwp_chunk_new` entrypoint.
        let name = b"price";
        let data: [i64; 3] = [1, 2, 3];
        let appended = unsafe {
            qwp_chunk_column_i64(
                chunk,
                name.as_ptr() as *const c_char,
                name.len(),
                data.as_ptr(),
                data.len(),
                std::ptr::null(),
                &mut err,
            )
        };
        assert!(appended, "column_i64 should succeed on the validated chunk");
        assert_eq!(
            unsafe { qwp_chunk_row_count(chunk, std::ptr::null_mut()) },
            3
        );
        unsafe { qwp_chunk_free(chunk) };
    }

    #[test]
    fn column_i64_round_trip_on_pure_data_path() {
        let table = b"trades";
        let mut err: *mut line_sender_error = std::ptr::null_mut();
        let chunk =
            unsafe { qwp_chunk_new(table.as_ptr() as *const c_char, table.len(), &mut err) };
        assert!(!chunk.is_null());

        let name = b"price";
        let data: [i64; 3] = [1, 2, 3];
        let ok = unsafe {
            qwp_chunk_column_i64(
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
            unsafe { qwp_chunk_row_count(chunk, std::ptr::null_mut()) },
            3
        );
        unsafe { qwp_chunk_free(chunk) };
    }

    #[test]
    fn column_i64_rejects_row_count_mismatch() {
        let table = b"trades";
        let mut err: *mut line_sender_error = std::ptr::null_mut();
        let chunk =
            unsafe { qwp_chunk_new(table.as_ptr() as *const c_char, table.len(), &mut err) };
        let name_a = b"a";
        let name_b = b"b";
        let data_a: [i64; 3] = [1, 2, 3];
        let data_b: [i64; 2] = [4, 5];
        assert!(unsafe {
            qwp_chunk_column_i64(
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
            qwp_chunk_column_i64(
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
        unsafe { qwp_chunk_free(chunk) };
    }

    #[test]
    fn column_bool_round_trip_on_pure_data_path() {
        let table = b"trades";
        let mut err: *mut line_sender_error = std::ptr::null_mut();
        let chunk =
            unsafe { qwp_chunk_new(table.as_ptr() as *const c_char, table.len(), &mut err) };
        assert!(!chunk.is_null());

        // 5 rows: true, false, true, true, false -> LSB-first bits 0,2,3 set.
        let name = b"flag";
        let data: [u8; 1] = [0b0000_1101];
        let row_count: usize = 5;
        let ok = unsafe {
            qwp_chunk_column_bool(
                chunk,
                name.as_ptr() as *const c_char,
                name.len(),
                data.as_ptr(),
                row_count,
                std::ptr::null(),
                &mut err,
            )
        };
        assert!(ok, "column_bool should succeed");
        assert!(err.is_null());
        assert_eq!(
            unsafe { qwp_chunk_row_count(chunk, std::ptr::null_mut()) },
            row_count
        );
        unsafe { qwp_chunk_free(chunk) };
    }

    #[test]
    fn column_bool_with_validity_nulls() {
        let table = b"trades";
        let mut err: *mut line_sender_error = std::ptr::null_mut();
        let chunk =
            unsafe { qwp_chunk_new(table.as_ptr() as *const c_char, table.len(), &mut err) };
        assert!(!chunk.is_null());

        // 4 rows of bool data, with rows 1 and 3 marked NULL via the
        // validity bitmap (LSB-first; bit = 1 means valid).
        let name = b"flag";
        let data: [u8; 1] = [0b0000_0101];
        let valid_bits: [u8; 1] = [0b0000_0101];
        let row_count: usize = 4;
        let validity = qwp_validity {
            bits: valid_bits.as_ptr(),
            bit_len: row_count,
        };
        let ok = unsafe {
            qwp_chunk_column_bool(
                chunk,
                name.as_ptr() as *const c_char,
                name.len(),
                data.as_ptr(),
                row_count,
                &validity,
                &mut err,
            )
        };
        assert!(ok, "column_bool with validity should succeed");
        assert!(err.is_null());
        assert_eq!(
            unsafe { qwp_chunk_row_count(chunk, std::ptr::null_mut()) },
            row_count
        );
        unsafe { qwp_chunk_free(chunk) };
    }

    #[test]
    fn column_bool_rejects_row_count_mismatch() {
        let table = b"trades";
        let mut err: *mut line_sender_error = std::ptr::null_mut();
        let chunk =
            unsafe { qwp_chunk_new(table.as_ptr() as *const c_char, table.len(), &mut err) };
        // Lock the chunk row_count to 3 via an i64 column.
        let name_a = b"a";
        let data_a: [i64; 3] = [1, 2, 3];
        assert!(unsafe {
            qwp_chunk_column_i64(
                chunk,
                name_a.as_ptr() as *const c_char,
                name_a.len(),
                data_a.as_ptr(),
                data_a.len(),
                std::ptr::null(),
                &mut err,
            )
        });

        // A bool column claiming 2 rows must be rejected.
        let name_b = b"flag";
        let data_b: [u8; 1] = [0b0000_0001];
        let ok = unsafe {
            qwp_chunk_column_bool(
                chunk,
                name_b.as_ptr() as *const c_char,
                name_b.len(),
                data_b.as_ptr(),
                2,
                std::ptr::null(),
                &mut err,
            )
        };
        assert!(!ok);
        assert!(!err.is_null());
        unsafe { line_sender_error_free(err) };
        unsafe { qwp_chunk_free(chunk) };
    }

    #[test]
    fn column_bool_rejects_null_data_with_rows() {
        let table = b"trades";
        let mut err: *mut line_sender_error = std::ptr::null_mut();
        let chunk =
            unsafe { qwp_chunk_new(table.as_ptr() as *const c_char, table.len(), &mut err) };
        // NULL data pointer with non-zero row_count must be rejected by the
        // bounded-slice guard.
        let name = b"flag";
        let ok = unsafe {
            qwp_chunk_column_bool(
                chunk,
                name.as_ptr() as *const c_char,
                name.len(),
                std::ptr::null(),
                3,
                std::ptr::null(),
                &mut err,
            )
        };
        assert!(!ok);
        assert!(!err.is_null());
        unsafe { line_sender_error_free(err) };
        unsafe { qwp_chunk_free(chunk) };
    }

    #[test]
    fn column_binary_round_trip_on_pure_data_path() {
        let table = b"trades";
        let mut err: *mut line_sender_error = std::ptr::null_mut();
        let chunk =
            unsafe { qwp_chunk_new(table.as_ptr() as *const c_char, table.len(), &mut err) };
        assert!(!chunk.is_null());

        // 3 rows: "ab" (2 bytes), "" (empty segment), "xyz" (3 bytes).
        // offsets has row_count + 1 == 4 entries, monotonically
        // non-decreasing; bytes is the concatenated buffer.
        let name = b"payload";
        let offsets: [i32; 4] = [0, 2, 2, 5];
        let bytes: [u8; 5] = *b"abxyz";
        let row_count: usize = 3;
        let ok = unsafe {
            qwp_chunk_column_binary(
                chunk,
                name.as_ptr() as *const c_char,
                name.len(),
                offsets.as_ptr(),
                bytes.as_ptr(),
                bytes.len(),
                row_count,
                std::ptr::null(),
                &mut err,
            )
        };
        assert!(ok, "column_binary should succeed");
        assert!(err.is_null());
        assert_eq!(
            unsafe { qwp_chunk_row_count(chunk, std::ptr::null_mut()) },
            row_count
        );
        unsafe { qwp_chunk_free(chunk) };
    }

    #[test]
    fn column_binary_rejects_row_count_mismatch() {
        let table = b"trades";
        let mut err: *mut line_sender_error = std::ptr::null_mut();
        let chunk =
            unsafe { qwp_chunk_new(table.as_ptr() as *const c_char, table.len(), &mut err) };
        // Lock the chunk row_count to 3.
        let name_a = b"a";
        let data_a: [i64; 3] = [1, 2, 3];
        assert!(unsafe {
            qwp_chunk_column_i64(
                chunk,
                name_a.as_ptr() as *const c_char,
                name_a.len(),
                data_a.as_ptr(),
                data_a.len(),
                std::ptr::null(),
                &mut err,
            )
        });

        // A binary column with 2 rows (offsets len 3) must be rejected.
        let name_b = b"payload";
        let offsets: [i32; 3] = [0, 1, 2];
        let bytes: [u8; 2] = *b"ab";
        let ok = unsafe {
            qwp_chunk_column_binary(
                chunk,
                name_b.as_ptr() as *const c_char,
                name_b.len(),
                offsets.as_ptr(),
                bytes.as_ptr(),
                bytes.len(),
                2,
                std::ptr::null(),
                &mut err,
            )
        };
        assert!(!ok);
        assert!(!err.is_null());
        unsafe { line_sender_error_free(err) };
        unsafe { qwp_chunk_free(chunk) };
    }

    #[test]
    fn column_binary_rejects_offset_out_of_bounds() {
        let table = b"trades";
        let mut err: *mut line_sender_error = std::ptr::null_mut();
        let chunk =
            unsafe { qwp_chunk_new(table.as_ptr() as *const c_char, table.len(), &mut err) };
        // Last offset (5) exceeds the 2-byte bytes buffer.
        let name = b"payload";
        let offsets: [i32; 2] = [0, 5];
        let bytes: [u8; 2] = *b"ab";
        let ok = unsafe {
            qwp_chunk_column_binary(
                chunk,
                name.as_ptr() as *const c_char,
                name.len(),
                offsets.as_ptr(),
                bytes.as_ptr(),
                bytes.len(),
                1,
                std::ptr::null(),
                &mut err,
            )
        };
        assert!(!ok);
        assert!(!err.is_null());
        unsafe { line_sender_error_free(err) };
        unsafe { qwp_chunk_free(chunk) };
    }

    #[test]
    fn column_str_round_trip_on_pure_data_path() {
        let table = b"trades";
        let mut err: *mut line_sender_error = std::ptr::null_mut();
        let chunk =
            unsafe { qwp_chunk_new(table.as_ptr() as *const c_char, table.len(), &mut err) };
        assert!(!chunk.is_null());

        // 3 rows: "hi" (ascii), "" (empty string), "héllo" (multi-byte:
        // 'é' is 2 UTF-8 bytes -> "héllo" is 6 bytes).
        let name = b"text";
        let bytes: Vec<u8> = {
            let mut v = Vec::new();
            v.extend_from_slice("hi".as_bytes());
            v.extend_from_slice("héllo".as_bytes());
            v
        };
        let split = "hi".len() as i32;
        let total = bytes.len() as i32;
        let offsets: [i32; 4] = [0, split, split, total];
        let row_count: usize = 3;
        let ok = unsafe {
            qwp_chunk_column_str(
                chunk,
                name.as_ptr() as *const c_char,
                name.len(),
                offsets.as_ptr(),
                bytes.as_ptr(),
                bytes.len(),
                row_count,
                std::ptr::null(),
                &mut err,
            )
        };
        assert!(ok, "column_str should succeed");
        assert!(err.is_null());
        assert_eq!(
            unsafe { qwp_chunk_row_count(chunk, std::ptr::null_mut()) },
            row_count
        );
        unsafe { qwp_chunk_free(chunk) };
    }

    #[test]
    fn column_str_rejects_row_count_mismatch() {
        let table = b"trades";
        let mut err: *mut line_sender_error = std::ptr::null_mut();
        let chunk =
            unsafe { qwp_chunk_new(table.as_ptr() as *const c_char, table.len(), &mut err) };
        // Lock the chunk row_count to 3.
        let name_a = b"a";
        let data_a: [i64; 3] = [1, 2, 3];
        assert!(unsafe {
            qwp_chunk_column_i64(
                chunk,
                name_a.as_ptr() as *const c_char,
                name_a.len(),
                data_a.as_ptr(),
                data_a.len(),
                std::ptr::null(),
                &mut err,
            )
        });

        // A varchar column with 2 rows (offsets len 3) must be rejected.
        let name_b = b"text";
        let offsets: [i32; 3] = [0, 2, 4];
        let bytes: [u8; 4] = *b"abcd";
        let ok = unsafe {
            qwp_chunk_column_str(
                chunk,
                name_b.as_ptr() as *const c_char,
                name_b.len(),
                offsets.as_ptr(),
                bytes.as_ptr(),
                bytes.len(),
                2,
                std::ptr::null(),
                &mut err,
            )
        };
        assert!(!ok);
        assert!(!err.is_null());
        unsafe { line_sender_error_free(err) };
        unsafe { qwp_chunk_free(chunk) };
    }

    #[test]
    fn column_str_rejects_offset_out_of_bounds() {
        let table = b"trades";
        let mut err: *mut line_sender_error = std::ptr::null_mut();
        let chunk =
            unsafe { qwp_chunk_new(table.as_ptr() as *const c_char, table.len(), &mut err) };
        // Last offset (9) exceeds the 4-byte bytes buffer.
        let name = b"text";
        let offsets: [i32; 2] = [0, 9];
        let bytes: [u8; 4] = *b"abcd";
        let ok = unsafe {
            qwp_chunk_column_str(
                chunk,
                name.as_ptr() as *const c_char,
                name.len(),
                offsets.as_ptr(),
                bytes.as_ptr(),
                bytes.len(),
                1,
                std::ptr::null(),
                &mut err,
            )
        };
        assert!(!ok);
        assert!(!err.is_null());
        unsafe { line_sender_error_free(err) };
        unsafe { qwp_chunk_free(chunk) };
    }

    #[test]
    fn column_str_rejects_invalid_utf8() {
        let table = b"trades";
        let mut err: *mut line_sender_error = std::ptr::null_mut();
        let chunk =
            unsafe { qwp_chunk_new(table.as_ptr() as *const c_char, table.len(), &mut err) };
        // 0xFF is not valid UTF-8; varchar validates the referenced bytes
        // while binary does not.
        let name = b"text";
        let offsets: [i32; 2] = [0, 1];
        let bytes: [u8; 1] = [0xFF];
        let ok = unsafe {
            qwp_chunk_column_str(
                chunk,
                name.as_ptr() as *const c_char,
                name.len(),
                offsets.as_ptr(),
                bytes.as_ptr(),
                bytes.len(),
                1,
                std::ptr::null(),
                &mut err,
            )
        };
        assert!(!ok);
        assert!(!err.is_null());
        unsafe { line_sender_error_free(err) };
        unsafe { qwp_chunk_free(chunk) };
    }

    #[test]
    fn validity_null_bits_with_nonzero_len_errors() {
        let table = b"trades";
        let mut err: *mut line_sender_error = std::ptr::null_mut();
        let chunk =
            unsafe { qwp_chunk_new(table.as_ptr() as *const c_char, table.len(), &mut err) };
        let name = b"a";
        let data: [i64; 2] = [1, 2];
        let v = qwp_validity {
            bits: std::ptr::null(),
            bit_len: 2,
        };
        let ok = unsafe {
            qwp_chunk_column_i64(
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
        unsafe { qwp_chunk_free(chunk) };
    }

    #[cfg(feature = "arrow")]
    #[test]
    fn append_arrow_dictionary_accepts_large_utf8_values() {
        let table = b"trades";
        let mut err: *mut line_sender_error = std::ptr::null_mut();
        let chunk =
            unsafe { qwp_chunk_new(table.as_ptr() as *const c_char, table.len(), &mut err) };
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
            qwp_chunk_append_arrow_column(
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
            unsafe { qwp_chunk_row_count(chunk, std::ptr::null_mut()) },
            codes.len()
        );
        unsafe { qwp_chunk_free(chunk) };
    }

    #[cfg(feature = "arrow")]
    #[test]
    fn arrow_import_append_twice_after_clear() {
        let table = b"trades";
        let mut err: *mut line_sender_error = std::ptr::null_mut();
        let chunk =
            unsafe { qwp_chunk_new(table.as_ptr() as *const c_char, table.len(), &mut err) };
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

        let imported =
            unsafe { qwp_arrow_import_new(&mut array, &schema, qwp_symbol_mode_auto, &mut err) };
        assert!(!imported.is_null());
        assert!(err.is_null());
        assert!(array.release.is_none());

        let name = b"sym";
        let ok = unsafe {
            qwp_chunk_append_arrow_import(
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
            unsafe { qwp_chunk_row_count(chunk, std::ptr::null_mut()) },
            2
        );

        unsafe { qwp_chunk_clear(chunk, std::ptr::null_mut()) };
        let ok = unsafe {
            qwp_chunk_append_arrow_import(
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
            unsafe { qwp_chunk_row_count(chunk, std::ptr::null_mut()) },
            2
        );

        unsafe {
            qwp_arrow_import_free(imported);
            qwp_chunk_free(chunk);
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
        let imported =
            unsafe { qwp_arrow_import_new(&mut array, &schema, qwp_symbol_mode_auto, &mut err) };
        assert!(!imported.is_null());
        assert!(err.is_null());
        assert!(array.release.is_none());

        let second =
            unsafe { qwp_arrow_import_new(&mut array, &schema, qwp_symbol_mode_auto, &mut err) };
        assert!(second.is_null());
        assert!(!err.is_null());

        unsafe {
            line_sender_error_free(err);
            qwp_arrow_import_free(imported);
        }
    }

    #[test]
    fn null_chunk_pointer_is_handled() {
        let mut err: *mut line_sender_error = std::ptr::null_mut();
        let name = b"a";
        let data: [i64; 1] = [1];
        let ok = unsafe {
            qwp_chunk_column_i64(
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
    fn qwp_direct_sender_from_conf_rejects_non_ws() {
        let conf = b"tcp::addr=localhost:9009;";
        let mut err: *mut line_sender_error = std::ptr::null_mut();
        let sender = unsafe {
            qwp_direct_sender_from_conf(conf.as_ptr() as *const c_char, conf.len(), &mut err)
        };
        assert!(sender.is_null());
        assert!(!err.is_null());
        unsafe { line_sender_error_free(err) };
    }

    #[test]
    fn qwp_direct_sender_from_conf_null_conf_errors() {
        let mut err: *mut line_sender_error = std::ptr::null_mut();
        let sender = unsafe { qwp_direct_sender_from_conf(std::ptr::null(), 1, &mut err) };
        assert!(sender.is_null());
        assert!(!err.is_null());
        unsafe { line_sender_error_free(err) };
    }

    #[test]
    fn qwp_direct_sender_free_accepts_null() {
        unsafe { qwp_direct_sender_free(std::ptr::null_mut()) };
    }

    #[test]
    fn qwp_direct_sender_from_opts_null_errors() {
        let mut err: *mut line_sender_error = std::ptr::null_mut();
        let sender = unsafe { qwp_direct_sender_from_opts(std::ptr::null(), &mut err) };
        assert!(sender.is_null());
        assert!(!err.is_null());
        unsafe { line_sender_error_free(err) };
    }

    #[test]
    fn ack_level_constants_map_correctly() {
        let mut err: *mut line_sender_error = std::ptr::null_mut();
        assert_eq!(
            ack_level_from_u32(qwpws_ack_level_ok, &mut err),
            Some(AckLevel::Ok)
        );
        assert!(err.is_null());
        assert_eq!(
            ack_level_from_u32(qwpws_ack_level_durable, &mut err),
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

    #[cfg(feature = "arrow")]
    #[test]
    fn symbol_mode_constants_map_correctly() {
        let mut err: *mut line_sender_error = std::ptr::null_mut();
        assert_eq!(
            symbol_mode_from_u32(qwp_symbol_mode_auto, &mut err),
            Some(None)
        );
        assert!(err.is_null());
        assert_eq!(
            symbol_mode_from_u32(qwp_symbol_mode_symbol, &mut err),
            Some(Some(true))
        );
        assert!(err.is_null());
        assert_eq!(
            symbol_mode_from_u32(qwp_symbol_mode_not_symbol, &mut err),
            Some(Some(false))
        );
        assert!(err.is_null());
    }

    #[cfg(feature = "arrow")]
    #[test]
    fn symbol_mode_rejects_out_of_range() {
        let mut err: *mut line_sender_error = std::ptr::null_mut();
        assert_eq!(symbol_mode_from_u32(5, &mut err), None);
        assert!(!err.is_null());
        unsafe { line_sender_error_free(err) };
    }

    /// Regression: a bare single-column (non-Struct) Arrow input must re-export
    /// in the same primitive shape so the re-exported array still pairs with
    /// the caller's retained (primitive) schema. The import wraps such input
    /// into a one-column RecordBatch; before the shape-aware fix the re-export
    /// produced a one-child Struct array that disagreed with the zero-child
    /// schema, and the retry was rejected by `validate_arrow_array_depth`.
    #[cfg(feature = "arrow")]
    #[test]
    fn reexport_bare_single_column_round_trips_for_retry() {
        use arrow::array::{Array, Int64Array};

        let col = Int64Array::from(vec![1_i64, 2, 3]);
        let (mut ffi_array, ffi_schema) =
            arrow::ffi::to_ffi(&col.to_data()).expect("to_ffi primitive");

        // Import consumes the array's release and wraps the bare column into a
        // one-column RecordBatch — exactly what a flush does.
        let mut err: *mut line_sender_error = std::ptr::null_mut();
        let rb = unsafe {
            crate::arrow_ffi_import_record_batch(
                &mut ffi_array,
                &ffi_schema,
                "reexport-test",
                &mut err,
            )
        }
        .expect("import");
        assert!(err.is_null());
        assert_eq!(rb.num_columns(), 1);

        // Re-export into the consumed slot using the retained schema's shape.
        unsafe { reexport_record_batch_into(rb, &mut ffi_array, &ffi_schema) };

        // The retry re-imports the re-exported array with the ORIGINAL
        // primitive schema; the pair must be valid again.
        let mut err2: *mut line_sender_error = std::ptr::null_mut();
        let retried = unsafe {
            crate::arrow_ffi_import_record_batch(
                &mut ffi_array,
                &ffi_schema,
                "reexport-retry",
                &mut err2,
            )
        };
        assert!(err2.is_null(), "re-exported pair must re-import on retry");
        let retried = retried.expect("retry import");
        assert_eq!(retried.num_columns(), 1);
        assert_eq!(retried.num_rows(), 3);
    }

    /// The Struct (standard RecordBatch) re-export path is unchanged by the
    /// shape-aware fix and still round-trips for retry.
    #[cfg(feature = "arrow")]
    #[test]
    fn reexport_struct_round_trips_for_retry() {
        use arrow::array::{Array, ArrayRef, Int64Array, StructArray};
        use arrow::datatypes::{DataType, Field};
        use std::sync::Arc;

        let col = Arc::new(Int64Array::from(vec![10_i64, 20])) as ArrayRef;
        let struct_arr = StructArray::from(vec![(
            Arc::new(Field::new("qty", DataType::Int64, false)),
            col,
        )]);
        let (mut ffi_array, ffi_schema) =
            arrow::ffi::to_ffi(&struct_arr.to_data()).expect("to_ffi struct");

        let mut err: *mut line_sender_error = std::ptr::null_mut();
        let rb = unsafe {
            crate::arrow_ffi_import_record_batch(&mut ffi_array, &ffi_schema, "s", &mut err)
        }
        .expect("import struct");
        assert!(err.is_null());

        unsafe { reexport_record_batch_into(rb, &mut ffi_array, &ffi_schema) };

        let mut err2: *mut line_sender_error = std::ptr::null_mut();
        let retried = unsafe {
            crate::arrow_ffi_import_record_batch(&mut ffi_array, &ffi_schema, "s2", &mut err2)
        };
        assert!(err2.is_null(), "struct re-export must re-import on retry");
        let retried = retried.expect("retry import struct");
        assert_eq!(retried.num_columns(), 1);
        assert_eq!(retried.num_rows(), 2);
    }
}
