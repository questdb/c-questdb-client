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

mod ilp;
mod op_state;

#[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
mod qwp;

use crate::ingress::ndarr::ArrayElementSealed;
use crate::ingress::{ArrayElement, DecimalView, NdArrayView, ProtocolVersion, Timestamp};
use crate::{Error, error};
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) use self::ilp::Buffer as IlpBuffer;
#[allow(unused_imports)]
pub(crate) use self::ilp::F64Serializer;
pub use self::ilp::{ColumnName, TableName};

#[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
pub(crate) use self::qwp::QwpBuffer;
#[cfg(feature = "_sender-qwp-udp")]
pub(crate) use self::qwp::QwpSendScratch;
#[cfg(feature = "_sender-qwp-ws")]
pub(crate) use self::qwp::{QwpWsEncodeScratch, SchemaRegistry, SymbolGlobalDict};

static NEXT_BOOKMARK_ORIGIN: AtomicU64 = AtomicU64::new(1);

/// Opaque rollback handle captured from a [`Buffer`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bookmark {
    origin: u64,
    generation: u64,
}

impl Bookmark {
    /// Construct a bookmark from raw parts.
    ///
    /// This is exposed for FFI interop. Application code should prefer
    /// [`Buffer::bookmark`].
    #[doc(hidden)]
    pub const fn from_raw(origin: u64, generation: u64) -> Self {
        Self { origin, generation }
    }

    /// Return the originating buffer namespace for this bookmark.
    ///
    /// This accessor is primarily intended for FFI wrappers.
    #[doc(hidden)]
    pub const fn origin(self) -> u64 {
        self.origin
    }

    /// Return the generation number associated with this bookmark.
    ///
    /// This accessor is primarily intended for FFI wrappers.
    #[doc(hidden)]
    pub const fn generation(self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct BufferBookmarkMeta {
    origin: u64,
}

impl BufferBookmarkMeta {
    pub(super) fn new() -> Self {
        Self {
            origin: NEXT_BOOKMARK_ORIGIN.fetch_add(1, Ordering::Relaxed),
        }
    }

    pub(super) const fn origin(self) -> u64 {
        self.origin
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct StoredBookmark<S: Copy> {
    generation: u64,
    state: Option<S>,
}

impl<S: Copy> StoredBookmark<S> {
    pub(super) const fn new() -> Self {
        Self {
            generation: 0,
            state: None,
        }
    }

    pub(super) fn capture(&mut self, origin: u64, state: S) -> Bookmark {
        self.generation = self.generation.wrapping_add(1);
        if self.generation == 0 {
            self.generation = 1;
        }
        self.state = Some(state);
        Bookmark::from_raw(origin, self.generation)
    }

    pub(super) const fn current(&self) -> Option<S> {
        self.state
    }

    pub(super) fn restore(&self, origin: u64, bookmark: Bookmark) -> crate::Result<S> {
        if bookmark.origin() != origin {
            return Err(error::fmt!(
                InvalidApiCall,
                "Can't rewind to the bookmark: Bookmark does not belong to this buffer."
            ));
        }
        if self.state.is_none() && self.generation == 0 {
            // This path is mainly defensive for forged or FFI-constructed
            // bookmarks. Normal Rust callers cannot obtain a matching-origin
            // bookmark without first capturing one, which advances generation.
            return Err(error::fmt!(
                InvalidApiCall,
                "Can't rewind to the bookmark: No bookmark set."
            ));
        }
        match self.state {
            Some(state) if self.generation == bookmark.generation() => Ok(state),
            _ => Err(error::fmt!(
                InvalidApiCall,
                "Can't rewind to the bookmark: Bookmark is stale."
            )),
        }
    }

    pub(super) fn clear_if_matches(&mut self, origin: u64, bookmark: Bookmark) {
        if bookmark.origin() == 0 {
            return;
        }
        if bookmark.origin() != origin {
            // `clear_bookmark()` is intentionally a no-op in release builds so
            // cleanup paths stay idempotent, but we still want debug builds to
            // catch obvious cross-buffer misuse early.
            debug_assert_eq!(
                bookmark.origin(),
                origin,
                "attempted to clear a bookmark from a different buffer"
            );
            return;
        }
        if self.state.is_some() && self.generation == bookmark.generation() {
            self.state = None;
        }
    }

    pub(super) fn clear(&mut self) {
        self.state = None;
    }
}

#[derive(Clone, Debug)]
enum BufferInner {
    Ilp(IlpBuffer),

    #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
    Qwp(Box<QwpBuffer>),
}

/// A reusable row buffer.
///
/// For ILP senders this exposes the existing byte-oriented buffer implementation.
/// For QWP/UDP senders it dispatches to the QWP-specific row buffer.
#[derive(Clone, Debug)]
pub struct Buffer {
    inner: BufferInner,
}

impl Buffer {
    /// Creates a new ILP buffer with default parameters.
    pub fn new(protocol_version: ProtocolVersion) -> Self {
        Self {
            inner: BufferInner::Ilp(IlpBuffer::new(protocol_version)),
        }
    }

    /// Creates a new ILP buffer with a custom maximum name length.
    pub fn with_max_name_len(protocol_version: ProtocolVersion, max_name_len: usize) -> Self {
        Self {
            inner: BufferInner::Ilp(IlpBuffer::with_max_name_len(protocol_version, max_name_len)),
        }
    }

    #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
    /// Creates a new QWP/UDP buffer with default parameters.
    pub fn new_qwp() -> Self {
        Self::qwp_with_max_name_len(127)
    }

    #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
    /// Creates a new QWP/UDP buffer with a custom maximum name length.
    pub fn qwp_with_max_name_len(max_name_len: usize) -> Self {
        Self {
            inner: BufferInner::Qwp(Box::new(QwpBuffer::new(max_name_len))),
        }
    }

    pub(crate) fn as_ilp(&self) -> Option<&IlpBuffer> {
        match &self.inner {
            BufferInner::Ilp(inner) => Some(inner),
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(_) => None,
        }
    }

    #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
    pub(crate) fn as_qwp(&self) -> Option<&QwpBuffer> {
        match &self.inner {
            BufferInner::Ilp(_) => None,
            BufferInner::Qwp(inner) => Some(inner.as_ref()),
        }
    }

    /// Returns the protocol version associated with this buffer.
    ///
    /// For ILP buffers this is the ILP protocol version. For QWP/UDP buffers
    /// this is the QWP datagram version, currently represented as
    /// [`ProtocolVersion::V1`]. Interpret the value together with the buffer
    /// transport; do not use it by itself for ILP feature gating.
    pub fn protocol_version(&self) -> ProtocolVersion {
        match &self.inner {
            BufferInner::Ilp(inner) => inner.protocol_version(),
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(_) => ProtocolVersion::V1,
        }
    }

    /// Reserves capacity associated with `additional` more bytes of buffered data.
    ///
    /// For ILP buffers this reserves exact serialized-byte capacity. For
    /// QWP/UDP buffers this is a heuristic prewarm of the internal arenas and
    /// planner scratch used during datagram planning and encoding; it is not an
    /// exact guarantee that [`Buffer::len`] can grow by `additional` bytes
    /// without further allocation.
    pub fn reserve(&mut self, additional: usize) {
        match &mut self.inner {
            BufferInner::Ilp(inner) => inner.reserve(additional),
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => inner.reserve(additional),
        }
    }

    /// Returns the current buffered size.
    ///
    /// For ILP buffers this is the exact serialized byte count. For QWP/UDP
    /// buffers this is the size hint used for flush planning.
    pub fn len(&self) -> usize {
        match &self.inner {
            BufferInner::Ilp(inner) => inner.len(),
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => inner.len(),
        }
    }

    /// Returns the number of completed rows currently buffered.
    ///
    /// A row is counted only after [`Buffer::at`] or [`Buffer::at_now`] completes
    /// it.
    pub fn row_count(&self) -> usize {
        match &self.inner {
            BufferInner::Ilp(inner) => inner.row_count(),
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => inner.row_count(),
        }
    }

    /// Returns whether the buffered batch is transactional.
    ///
    /// For ILP buffers this is `true` only while the buffer contains rows for
    /// at most one table. QWP/UDP does not support transactional flushes, so
    /// QWP buffers always return `false`.
    pub fn transactional(&self) -> bool {
        match &self.inner {
            BufferInner::Ilp(inner) => inner.transactional(),
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(_) => false,
        }
    }

    /// Returns `true` if the buffer contains no committed or in-progress rows.
    pub fn is_empty(&self) -> bool {
        match &self.inner {
            BufferInner::Ilp(inner) => inner.is_empty(),
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => inner.is_empty(),
        }
    }

    /// Returns the current retained-capacity hint for the buffer.
    ///
    /// For ILP buffers, this is byte capacity. For QWP/UDP buffers, this is an
    /// implementation-defined retained-capacity hint and should not be
    /// interpreted as exact byte capacity.
    pub fn capacity(&self) -> usize {
        match &self.inner {
            BufferInner::Ilp(inner) => inner.capacity(),
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => inner.capacity(),
        }
    }

    /// Returns the raw serialized ILP bytes currently stored in the buffer.
    ///
    /// QWP/UDP buffers build datagrams during flush, so this returns an empty
    /// slice for QWP/UDP.
    pub fn as_bytes(&self) -> &[u8] {
        match &self.inner {
            BufferInner::Ilp(inner) => inner.as_bytes(),
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => inner.as_bytes(),
        }
    }

    /// Marks the current buffer state so it can later be restored with
    /// [`Buffer::rewind_to_marker`].
    ///
    /// Setting a new marker replaces the currently stored rewind point,
    /// including one established by [`Buffer::bookmark`].
    pub fn set_marker(&mut self) -> crate::Result<()> {
        match &mut self.inner {
            BufferInner::Ilp(inner) => inner.set_marker(),
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => inner.set_marker(),
        }
    }

    /// Captures the current buffer state so it can later be restored with
    /// [`Buffer::rewind_to_bookmark`].
    ///
    /// Capturing a new bookmark replaces the previous bookmark or marker.
    pub fn bookmark(&mut self) -> crate::Result<Bookmark> {
        match &mut self.inner {
            BufferInner::Ilp(inner) => inner.bookmark(),
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => inner.bookmark(),
        }
    }

    /// Rewinds the buffer to the state referenced by `bookmark` and then
    /// clears that bookmark.
    pub fn rewind_to_bookmark(&mut self, bookmark: Bookmark) -> crate::Result<()> {
        match &mut self.inner {
            BufferInner::Ilp(inner) => inner.rewind_to_bookmark(bookmark),
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => inner.rewind_to_bookmark(bookmark),
        }
    }

    /// Clears `bookmark` if it is still the currently active bookmark.
    pub fn clear_bookmark(&mut self, bookmark: Bookmark) {
        match &mut self.inner {
            BufferInner::Ilp(inner) => inner.clear_bookmark(bookmark),
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => inner.clear_bookmark(bookmark),
        }
    }

    /// Rewinds the buffer to the currently stored rewind point and then clears
    /// it.
    ///
    /// This may rewind a state established by either [`Buffer::set_marker`] or
    /// [`Buffer::bookmark`].
    ///
    /// Returns an error if no rewind point is set.
    pub fn rewind_to_marker(&mut self) -> crate::Result<()> {
        match &mut self.inner {
            BufferInner::Ilp(inner) => inner.rewind_to_marker(),
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => inner.rewind_to_marker(),
        }
    }

    /// Clears the current stored rewind point, including one established by
    /// [`Buffer::bookmark`].
    pub fn clear_marker(&mut self) {
        match &mut self.inner {
            BufferInner::Ilp(inner) => inner.clear_marker(),
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => inner.clear_marker(),
        }
    }

    /// Clears the buffer contents and marker while retaining allocated capacity.
    pub fn clear(&mut self) {
        match &mut self.inner {
            BufferInner::Ilp(inner) => inner.clear(),
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => inner.clear(),
        }
    }

    /// Validates that the buffer is ready to be flushed with
    /// [`crate::ingress::Sender::flush`] or one of its variants.
    ///
    /// Returns an error when the current API call sequence is incomplete, such
    /// as an unfinished row.
    pub fn check_can_flush(&self) -> crate::Result<()> {
        match &self.inner {
            BufferInner::Ilp(inner) => inner.check_can_flush(),
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => inner.check_can_flush(),
        }
    }

    /// Starts a new row for `name`.
    ///
    /// Every row must begin with a table name. See [`Buffer`] for the full call
    /// sequence.
    pub fn table<'a, N>(&mut self, name: N) -> crate::Result<&mut Self>
    where
        N: TryInto<TableName<'a>>,
        Error: From<N::Error>,
    {
        match &mut self.inner {
            BufferInner::Ilp(inner) => {
                inner.table(name)?;
            }
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => {
                inner.table(name)?;
            }
        }
        Ok(self)
    }

    /// Adds a symbol column to the current row.
    ///
    /// All symbol columns must be recorded before any non-symbol columns.
    pub fn symbol<'a, N, S>(&mut self, name: N, value: S) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        S: AsRef<str>,
        Error: From<N::Error>,
    {
        match &mut self.inner {
            BufferInner::Ilp(inner) => {
                inner.symbol(name, value)?;
            }
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => {
                inner.symbol(name, value)?;
            }
        }
        Ok(self)
    }

    /// Adds a symbol column if `value` is `Some`; otherwise leaves the row unchanged.
    pub fn symbol_opt<'a, N, S>(&mut self, name: N, value: Option<S>) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        S: AsRef<str>,
        Error: From<N::Error>,
    {
        if let Some(value) = value {
            self.symbol(name, value)
        } else {
            Ok(self)
        }
    }

    /// Adds a boolean column to the current row.
    pub fn column_bool<'a, N>(&mut self, name: N, value: bool) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        match &mut self.inner {
            BufferInner::Ilp(inner) => {
                inner.column_bool(name, value)?;
            }
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => {
                inner.column_bool(name, value)?;
            }
        }
        Ok(self)
    }

    /// Adds a boolean column if `value` is `Some`; otherwise leaves the row unchanged.
    pub fn column_bool_opt<'a, N>(
        &mut self,
        name: N,
        value: Option<bool>,
    ) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        if let Some(value) = value {
            self.column_bool(name, value)
        } else {
            Ok(self)
        }
    }

    /// Adds an integer column to the current row.
    pub fn column_i64<'a, N>(&mut self, name: N, value: i64) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        match &mut self.inner {
            BufferInner::Ilp(inner) => {
                inner.column_i64(name, value)?;
            }
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => {
                inner.column_i64(name, value)?;
            }
        }
        Ok(self)
    }

    /// Adds an integer column if `value` is `Some`; otherwise leaves the row unchanged.
    pub fn column_i64_opt<'a, N>(&mut self, name: N, value: Option<i64>) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        if let Some(value) = value {
            self.column_i64(name, value)
        } else {
            Ok(self)
        }
    }

    /// Adds a floating-point column to the current row.
    pub fn column_f64<'a, N>(&mut self, name: N, value: f64) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        match &mut self.inner {
            BufferInner::Ilp(inner) => {
                inner.column_f64(name, value)?;
            }
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => {
                inner.column_f64(name, value)?;
            }
        }
        Ok(self)
    }

    /// Adds a floating-point column if `value` is `Some`; otherwise leaves the row unchanged.
    pub fn column_f64_opt<'a, N>(&mut self, name: N, value: Option<f64>) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        if let Some(value) = value {
            self.column_f64(name, value)
        } else {
            Ok(self)
        }
    }

    /// Adds a string column to the current row.
    pub fn column_str<'a, N, S>(&mut self, name: N, value: S) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        S: AsRef<str>,
        Error: From<N::Error>,
    {
        match &mut self.inner {
            BufferInner::Ilp(inner) => {
                inner.column_str(name, value)?;
            }
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => {
                inner.column_str(name, value)?;
            }
        }
        Ok(self)
    }

    /// Adds a string column if `value` is `Some`; otherwise leaves the row unchanged.
    pub fn column_str_opt<'a, N, S>(
        &mut self,
        name: N,
        value: Option<S>,
    ) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        S: AsRef<str>,
        Error: From<N::Error>,
    {
        if let Some(value) = value {
            self.column_str(name, value)
        } else {
            Ok(self)
        }
    }

    /// Adds a decimal column to the current row.
    ///
    /// Returns an error if the active protocol does not support decimal values.
    /// QWP/UDP accepts the same decimal input forms as ILP and encodes them as
    /// nullable DECIMAL256 columns on the wire.
    pub fn column_dec<'a, N, S>(&mut self, name: N, value: S) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        S: TryInto<DecimalView<'a>>,
        Error: From<N::Error>,
        Error: From<S::Error>,
    {
        match &mut self.inner {
            BufferInner::Ilp(inner) => {
                inner.column_dec(name, value)?;
            }
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => {
                inner.column_dec(name, value)?;
            }
        }
        Ok(self)
    }

    /// Adds a decimal column if `value` is `Some`; otherwise leaves the row unchanged.
    pub fn column_dec_opt<'a, N, S>(
        &mut self,
        name: N,
        value: Option<S>,
    ) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        S: TryInto<DecimalView<'a>>,
        Error: From<N::Error>,
        Error: From<S::Error>,
    {
        if let Some(value) = value {
            self.column_dec(name, value)
        } else {
            Ok(self)
        }
    }

    #[allow(private_bounds)]
    /// Adds an array column to the current row.
    ///
    /// Arrays require ILP protocol version 2 or later. QWP/UDP currently
    /// supports `f64` arrays.
    pub fn column_arr<'a, N, T, D>(&mut self, name: N, view: &T) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        T: NdArrayView<D>,
        D: ArrayElement + ArrayElementSealed,
        Error: From<N::Error>,
    {
        match &mut self.inner {
            BufferInner::Ilp(inner) => {
                inner.column_arr(name, view)?;
            }
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => {
                inner.column_arr(name, view)?;
            }
        }
        Ok(self)
    }

    /// Adds an array column if `value` is `Some`; otherwise leaves the row unchanged.
    #[allow(private_bounds)]
    pub fn column_arr_opt<'a, N, T, D>(
        &mut self,
        name: N,
        value: Option<&T>,
    ) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        T: NdArrayView<D>,
        D: ArrayElement + ArrayElementSealed,
        Error: From<N::Error>,
    {
        if let Some(value) = value {
            self.column_arr(name, value)
        } else {
            Ok(self)
        }
    }

    /// Adds a timestamp column to the current row.
    ///
    /// Accepts either microsecond or nanosecond timestamps.
    pub fn column_ts<'a, N, T>(&mut self, name: N, value: T) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        T: TryInto<Timestamp>,
        Error: From<N::Error>,
        Error: From<T::Error>,
    {
        match &mut self.inner {
            BufferInner::Ilp(inner) => {
                inner.column_ts(name, value)?;
            }
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => {
                inner.column_ts(name, value)?;
            }
        }
        Ok(self)
    }

    /// Adds a timestamp column if `value` is `Some`; otherwise leaves the row unchanged.
    pub fn column_ts_opt<'a, N, T>(&mut self, name: N, value: Option<T>) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        T: TryInto<Timestamp>,
        Error: From<N::Error>,
        Error: From<T::Error>,
    {
        if let Some(value) = value {
            self.column_ts(name, value)
        } else {
            Ok(self)
        }
    }

    /// Completes the current row with a designated timestamp.
    ///
    /// After this call you may begin the next row with [`Buffer::table`] or
    /// flush the buffer. Accepts either microsecond or nanosecond timestamps.
    pub fn at<T>(&mut self, timestamp: T) -> crate::Result<()>
    where
        T: TryInto<Timestamp>,
        Error: From<T::Error>,
    {
        match &mut self.inner {
            BufferInner::Ilp(inner) => inner.at(timestamp),
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => inner.at(timestamp),
        }
    }

    /// Completes the current row without a designated timestamp so the server
    /// assigns one.
    ///
    /// This is not equivalent to calling [`Buffer::at`] with the current client
    /// time.
    pub fn at_now(&mut self) -> crate::Result<()> {
        match &mut self.inner {
            BufferInner::Ilp(inner) => inner.at_now(),
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => inner.at_now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Bookmark, StoredBookmark};
    use crate::ErrorCode;

    #[test]
    fn stored_bookmark_reports_missing_bookmark_when_never_captured() {
        let bookmark = Bookmark::from_raw(7, 1);
        let stored = StoredBookmark::<u8>::new();
        let err = stored.restore(7, bookmark).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert_eq!(err.msg(), "Can't rewind to the bookmark: No bookmark set.");
    }

    #[test]
    fn stored_bookmark_ignores_invalid_zero_origin_clear() {
        let mut stored = StoredBookmark::<u8>::new();
        let bookmark = stored.capture(7, 42);

        stored.clear_if_matches(7, Bookmark::from_raw(0, 0));

        assert_eq!(stored.restore(7, bookmark).unwrap(), 42);
    }
}
