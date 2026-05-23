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

#[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
pub(crate) use self::qwp::QwpBuffer;
#[cfg(feature = "_sender-qwp-udp")]
pub(crate) use self::qwp::QwpSendScratch;
#[cfg(all(test, feature = "_sender-qwp-ws"))]
pub(crate) use self::qwp::SchemaRegistry;
#[cfg(feature = "_sender-qwp-ws")]
pub(crate) use self::qwp::{QwpWsColumnarBuffer, QwpWsEncodeScratch, SymbolGlobalDict};

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

/// A validated table name.
///
/// This type simply wraps a `&str`.
///
/// When you pass a `TableName` instead of a plain string to a [`Buffer`] method,
/// it doesn't have to validate it again. This saves CPU cycles.
#[derive(Clone, Copy)]
pub struct TableName<'a> {
    name: &'a str,
}

impl<'a> TableName<'a> {
    /// Construct a validated table name.
    pub fn new(name: &'a str) -> crate::Result<Self> {
        if name.is_empty() {
            return Err(error::fmt!(
                InvalidName,
                "Table names must have a non-zero length."
            ));
        }

        let mut prev = '\0';
        for (byte_idx, c) in name.char_indices() {
            match c {
                '.' if byte_idx == 0 || byte_idx + c.len_utf8() == name.len() || prev == '.' => {
                    return Err(error::fmt!(
                        InvalidName,
                        concat!("Bad string {:?}: ", "Found invalid dot `.` at position {}."),
                        name,
                        byte_idx
                    ));
                }
                '.' => {}
                '?' | ',' | '\'' | '\"' | '\\' | '/' | ':' | ')' | '(' | '+' | '*' | '%' | '~'
                | '\r' | '\n' | '\0' | '\u{0001}' | '\u{0002}' | '\u{0003}' | '\u{0004}'
                | '\u{0005}' | '\u{0006}' | '\u{0007}' | '\u{0008}' | '\u{0009}' | '\u{000b}'
                | '\u{000c}' | '\u{000e}' | '\u{000f}' | '\u{007f}' => {
                    return Err(error::fmt!(
                        InvalidName,
                        concat!(
                            "Bad string {:?}: ",
                            "Table names can't contain ",
                            "a {:?} character, which was found at ",
                            "byte position {}."
                        ),
                        name,
                        c,
                        byte_idx
                    ));
                }
                '\u{feff}' => {
                    // Reject Unicode char 'ZERO WIDTH NO-BREAK SPACE',
                    // aka UTF-8 BOM if it appears anywhere in the string.
                    return Err(error::fmt!(
                        InvalidName,
                        concat!(
                            "Bad string {:?}: ",
                            "Table names can't contain ",
                            "a UTF-8 BOM character, which was found at ",
                            "byte position {}."
                        ),
                        name,
                        byte_idx
                    ));
                }
                _ => (),
            }
            prev = c;
        }

        Ok(Self { name })
    }

    /// Construct a table name without validating it.
    ///
    /// This breaks API encapsulation and is only intended for use
    /// when the string was already previously validated.
    ///
    /// The QuestDB server will reject an invalid table name.
    pub fn new_unchecked(name: &'a str) -> Self {
        Self { name }
    }
}

impl<'a> TryFrom<&'a str> for TableName<'a> {
    type Error = Error;

    fn try_from(name: &'a str) -> crate::Result<Self> {
        Self::new(name)
    }
}

impl AsRef<str> for TableName<'_> {
    fn as_ref(&self) -> &str {
        self.name
    }
}

/// A validated column name.
///
/// This type simply wraps a `&str`.
///
/// When you pass a `ColumnName` instead of a plain string to a [`Buffer`] method,
/// it doesn't have to validate it again. This saves CPU cycles.
#[derive(Clone, Copy)]
pub struct ColumnName<'a> {
    name: &'a str,
}

impl<'a> ColumnName<'a> {
    /// Construct a validated column name.
    pub fn new(name: &'a str) -> crate::Result<Self> {
        if name.is_empty() {
            return Err(error::fmt!(
                InvalidName,
                "Column names must have a non-zero length."
            ));
        }

        for (byte_idx, c) in name.char_indices() {
            match c {
                '?' | '.' | ',' | '\'' | '\"' | '\\' | '/' | ':' | ')' | '(' | '+' | '-' | '*'
                | '%' | '~' | '\r' | '\n' | '\0' | '\u{0001}' | '\u{0002}' | '\u{0003}'
                | '\u{0004}' | '\u{0005}' | '\u{0006}' | '\u{0007}' | '\u{0008}' | '\u{0009}'
                | '\u{000b}' | '\u{000c}' | '\u{000e}' | '\u{000f}' | '\u{007f}' => {
                    return Err(error::fmt!(
                        InvalidName,
                        concat!(
                            "Bad string {:?}: ",
                            "Column names can't contain ",
                            "a {:?} character, which was found at ",
                            "byte position {}."
                        ),
                        name,
                        c,
                        byte_idx
                    ));
                }
                '\u{FEFF}' => {
                    // Reject Unicode char 'ZERO WIDTH NO-BREAK SPACE',
                    // aka UTF-8 BOM if it appears anywhere in the string.
                    return Err(error::fmt!(
                        InvalidName,
                        concat!(
                            "Bad string {:?}: ",
                            "Column names can't contain ",
                            "a UTF-8 BOM character, which was found at ",
                            "byte position {}."
                        ),
                        name,
                        byte_idx
                    ));
                }
                _ => (),
            }
        }

        Ok(Self { name })
    }

    /// Construct a column name without validating it.
    ///
    /// This breaks API encapsulation and is only intended for use
    /// when the string was already previously validated.
    ///
    /// The QuestDB server will reject an invalid column name.
    pub fn new_unchecked(name: &'a str) -> Self {
        Self { name }
    }
}

impl<'a> TryFrom<&'a str> for ColumnName<'a> {
    type Error = Error;

    fn try_from(name: &'a str) -> crate::Result<Self> {
        Self::new(name)
    }
}

impl AsRef<str> for ColumnName<'_> {
    fn as_ref(&self) -> &str {
        self.name
    }
}

#[derive(Clone, Debug)]
enum BufferInner {
    Ilp(IlpBuffer),

    #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
    Qwp(Box<QwpBuffer>),

    #[cfg(feature = "_sender-qwp-ws")]
    QwpWs(Box<QwpWsColumnarBuffer>),
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

    /// Creates a new ILP buffer that pre-allocates its byte storage to
    /// `init_capacity` and accepts table / column names up to `max_name_len`.
    /// The buffer is allowed to grow past `init_capacity`; it is purely a
    /// starting-size hint to avoid early reallocations.
    pub fn with_init_capacity_and_max_name_len(
        protocol_version: ProtocolVersion,
        init_capacity: usize,
        max_name_len: usize,
    ) -> Self {
        Self {
            inner: BufferInner::Ilp(IlpBuffer::with_init_capacity_and_max_name_len(
                protocol_version,
                init_capacity,
                max_name_len,
            )),
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

    #[cfg(feature = "_sender-qwp-ws")]
    pub(crate) fn qwp_ws_with_max_name_len(max_name_len: usize) -> Self {
        Self {
            inner: BufferInner::QwpWs(Box::new(QwpWsColumnarBuffer::new(max_name_len))),
        }
    }

    pub(crate) fn as_ilp(&self) -> Option<&IlpBuffer> {
        match &self.inner {
            BufferInner::Ilp(inner) => Some(inner),
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(_) => None,
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(_) => None,
        }
    }

    #[cfg(any(feature = "_sender-qwp-udp", all(test, feature = "_sender-qwp-ws")))]
    pub(crate) fn as_qwp(&self) -> Option<&QwpBuffer> {
        match &self.inner {
            BufferInner::Ilp(_) => None,
            BufferInner::Qwp(inner) => Some(inner.as_ref()),
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(_) => None,
        }
    }

    #[cfg(feature = "_sender-qwp-ws")]
    pub(crate) fn as_qwp_ws(&self) -> Option<&QwpWsColumnarBuffer> {
        match &self.inner {
            BufferInner::Ilp(_) => None,
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(_) => None,
            BufferInner::QwpWs(inner) => Some(inner.as_ref()),
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
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(_) => ProtocolVersion::V1,
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
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(inner) => inner.reserve(additional),
        }
    }

    /// Returns the current buffered size.
    ///
    /// For ILP buffers this is the exact serialized byte count. For QWP/UDP
    /// buffers this is the size hint used for flush planning. For QWP/WebSocket
    /// buffers this is only a local size hint; the sender enforces
    /// `max_buf_size` against the encoded replay message.
    pub fn len(&self) -> usize {
        match &self.inner {
            BufferInner::Ilp(inner) => inner.len(),
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => inner.len(),
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(inner) => inner.len(),
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
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(inner) => inner.row_count(),
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
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(_) => false,
        }
    }

    /// Returns `true` if the buffer contains no committed or in-progress rows.
    pub fn is_empty(&self) -> bool {
        match &self.inner {
            BufferInner::Ilp(inner) => inner.is_empty(),
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => inner.is_empty(),
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(inner) => inner.is_empty(),
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
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(inner) => inner.capacity(),
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
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(inner) => inner.as_bytes(),
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
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(inner) => inner.set_marker(),
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
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(inner) => inner.bookmark(),
        }
    }

    /// Rewinds the buffer to the state referenced by `bookmark` and then
    /// clears that bookmark.
    pub fn rewind_to_bookmark(&mut self, bookmark: Bookmark) -> crate::Result<()> {
        match &mut self.inner {
            BufferInner::Ilp(inner) => inner.rewind_to_bookmark(bookmark),
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => inner.rewind_to_bookmark(bookmark),
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(inner) => inner.rewind_to_bookmark(bookmark),
        }
    }

    /// Clears `bookmark` if it is still the currently active bookmark.
    pub fn clear_bookmark(&mut self, bookmark: Bookmark) {
        match &mut self.inner {
            BufferInner::Ilp(inner) => inner.clear_bookmark(bookmark),
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => inner.clear_bookmark(bookmark),
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(inner) => inner.clear_bookmark(bookmark),
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
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(inner) => inner.rewind_to_marker(),
        }
    }

    /// Clears the current stored rewind point, including one established by
    /// [`Buffer::bookmark`].
    pub fn clear_marker(&mut self) {
        match &mut self.inner {
            BufferInner::Ilp(inner) => inner.clear_marker(),
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => inner.clear_marker(),
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(inner) => inner.clear_marker(),
        }
    }

    /// Clears the buffer contents and marker while retaining allocated capacity.
    pub fn clear(&mut self) {
        match &mut self.inner {
            BufferInner::Ilp(inner) => inner.clear(),
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => inner.clear(),
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(inner) => inner.clear(),
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
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(inner) => inner.check_can_flush(),
        }
    }

    /// Starts a new row for `name`.
    ///
    /// Every row must begin with a table name. See [`Buffer`] for the full call
    /// sequence.
    #[inline(always)]
    pub fn table<'a, N>(&mut self, name: N) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<TableName<'a>>,
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
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(inner) => {
                inner.table(name)?;
            }
        }
        Ok(self)
    }

    /// Adds a symbol column to the current row.
    ///
    /// All symbol columns must be recorded before any non-symbol columns.
    #[inline(always)]
    pub fn symbol<'a, N, S>(&mut self, name: N, value: S) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
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
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(inner) => {
                inner.symbol(name, value)?;
            }
        }
        Ok(self)
    }

    /// Adds a symbol column if `value` is `Some`; otherwise leaves the row unchanged.
    pub fn symbol_opt<'a, N, S>(&mut self, name: N, value: Option<S>) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
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
        N: AsRef<str> + TryInto<ColumnName<'a>>,
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
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(inner) => {
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
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        if let Some(value) = value {
            self.column_bool(name, value)
        } else {
            Ok(self)
        }
    }

    /// Adds an integer column to the current row.
    #[inline(always)]
    pub fn column_i64<'a, N>(&mut self, name: N, value: i64) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
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
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(inner) => {
                inner.column_i64(name, value)?;
            }
        }
        Ok(self)
    }

    /// Adds an integer column if `value` is `Some`; otherwise leaves the row unchanged.
    pub fn column_i64_opt<'a, N>(&mut self, name: N, value: Option<i64>) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        if let Some(value) = value {
            self.column_i64(name, value)
        } else {
            Ok(self)
        }
    }

    /// Adds an 8-bit signed integer column to the current row. QWP-only.
    pub fn column_i8<'a, N>(&mut self, name: N, value: i8) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        let _ = (&name, &value);
        match &mut self.inner {
            BufferInner::Ilp(_) => Err(error::fmt!(
                InvalidApiCall,
                "column_i8 requires a QWP transport (qwpws:: or qwpudp::)"
            )),
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => {
                inner.column_i8(name, value)?;
                Ok(self)
            }
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(inner) => {
                inner.column_i8(name, value)?;
                Ok(self)
            }
        }
    }

    /// Adds an 8-bit signed integer column if `value` is `Some`. QWP-only.
    pub fn column_i8_opt<'a, N>(&mut self, name: N, value: Option<i8>) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        if let Some(value) = value {
            self.column_i8(name, value)
        } else {
            Ok(self)
        }
    }

    /// Adds a 16-bit signed integer column to the current row. QWP-only.
    pub fn column_i16<'a, N>(&mut self, name: N, value: i16) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        let _ = (&name, &value);
        match &mut self.inner {
            BufferInner::Ilp(_) => Err(error::fmt!(
                InvalidApiCall,
                "column_i16 requires a QWP transport (qwpws:: or qwpudp::)"
            )),
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => {
                inner.column_i16(name, value)?;
                Ok(self)
            }
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(inner) => {
                inner.column_i16(name, value)?;
                Ok(self)
            }
        }
    }

    /// Adds a 16-bit signed integer column if `value` is `Some`. QWP-only.
    pub fn column_i16_opt<'a, N>(&mut self, name: N, value: Option<i16>) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        if let Some(value) = value {
            self.column_i16(name, value)
        } else {
            Ok(self)
        }
    }

    /// Adds a 32-bit signed integer column to the current row. QWP-only.
    pub fn column_i32<'a, N>(&mut self, name: N, value: i32) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        let _ = (&name, &value);
        match &mut self.inner {
            BufferInner::Ilp(_) => Err(error::fmt!(
                InvalidApiCall,
                "column_i32 requires a QWP transport (qwpws:: or qwpudp::)"
            )),
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => {
                inner.column_i32(name, value)?;
                Ok(self)
            }
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(inner) => {
                inner.column_i32(name, value)?;
                Ok(self)
            }
        }
    }

    /// Adds a 32-bit signed integer column if `value` is `Some`. QWP-only.
    pub fn column_i32_opt<'a, N>(&mut self, name: N, value: Option<i32>) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        if let Some(value) = value {
            self.column_i32(name, value)
        } else {
            Ok(self)
        }
    }

    /// Adds a 32-bit floating-point column to the current row. QWP-only.
    pub fn column_f32<'a, N>(&mut self, name: N, value: f32) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        let _ = (&name, &value);
        match &mut self.inner {
            BufferInner::Ilp(_) => Err(error::fmt!(
                InvalidApiCall,
                "column_f32 requires a QWP transport (qwpws:: or qwpudp::)"
            )),
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => {
                inner.column_f32(name, value)?;
                Ok(self)
            }
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(inner) => {
                inner.column_f32(name, value)?;
                Ok(self)
            }
        }
    }

    /// Adds a 32-bit floating-point column if `value` is `Some`. QWP-only.
    pub fn column_f32_opt<'a, N>(&mut self, name: N, value: Option<f32>) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        if let Some(value) = value {
            self.column_f32(name, value)
        } else {
            Ok(self)
        }
    }

    /// Adds a floating-point column to the current row.
    #[inline(always)]
    pub fn column_f64<'a, N>(&mut self, name: N, value: f64) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
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
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(inner) => {
                inner.column_f64(name, value)?;
            }
        }
        Ok(self)
    }

    /// Adds a floating-point column if `value` is `Some`; otherwise leaves the row unchanged.
    pub fn column_f64_opt<'a, N>(&mut self, name: N, value: Option<f64>) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        if let Some(value) = value {
            self.column_f64(name, value)
        } else {
            Ok(self)
        }
    }

    /// Adds a string column to the current row.
    #[inline(always)]
    pub fn column_str<'a, N, S>(&mut self, name: N, value: S) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
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
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(inner) => {
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
        N: AsRef<str> + TryInto<ColumnName<'a>>,
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
        N: AsRef<str> + TryInto<ColumnName<'a>>,
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
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(inner) => {
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
        N: AsRef<str> + TryInto<ColumnName<'a>>,
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

    /// Adds a 64-bit decimal column to the current row. QWP-only.
    ///
    /// The unscaled magnitude (at the column's pinned scale) must fit a signed
    /// 64-bit integer; values that do not fit return `InvalidApiCall`.
    pub fn column_dec64<'a, N, S>(&mut self, name: N, value: S) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        S: TryInto<DecimalView<'a>>,
        Error: From<N::Error>,
        Error: From<S::Error>,
    {
        let _ = &name;
        match &mut self.inner {
            BufferInner::Ilp(_) => {
                let _ = value.try_into().map_err(Error::from)?;
                Err(error::fmt!(
                    InvalidApiCall,
                    "column_dec64 requires a QWP transport (qwpws:: or qwpudp::)"
                ))
            }
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => {
                inner.column_dec64(name, value)?;
                Ok(self)
            }
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(inner) => {
                inner.column_dec64(name, value)?;
                Ok(self)
            }
        }
    }

    /// Adds a 64-bit decimal column if `value` is `Some`. QWP-only.
    pub fn column_dec64_opt<'a, N, S>(
        &mut self,
        name: N,
        value: Option<S>,
    ) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        S: TryInto<DecimalView<'a>>,
        Error: From<N::Error>,
        Error: From<S::Error>,
    {
        if let Some(value) = value {
            self.column_dec64(name, value)
        } else {
            Ok(self)
        }
    }

    /// Adds a 128-bit decimal column to the current row. QWP-only.
    ///
    /// The unscaled magnitude (at the column's pinned scale) must fit a signed
    /// 128-bit integer; values that do not fit return `InvalidApiCall`.
    pub fn column_dec128<'a, N, S>(&mut self, name: N, value: S) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        S: TryInto<DecimalView<'a>>,
        Error: From<N::Error>,
        Error: From<S::Error>,
    {
        let _ = &name;
        match &mut self.inner {
            BufferInner::Ilp(_) => {
                let _ = value.try_into().map_err(Error::from)?;
                Err(error::fmt!(
                    InvalidApiCall,
                    "column_dec128 requires a QWP transport (qwpws:: or qwpudp::)"
                ))
            }
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => {
                inner.column_dec128(name, value)?;
                Ok(self)
            }
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(inner) => {
                inner.column_dec128(name, value)?;
                Ok(self)
            }
        }
    }

    /// Adds a 128-bit decimal column if `value` is `Some`. QWP-only.
    pub fn column_dec128_opt<'a, N, S>(
        &mut self,
        name: N,
        value: Option<S>,
    ) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        S: TryInto<DecimalView<'a>>,
        Error: From<N::Error>,
        Error: From<S::Error>,
    {
        if let Some(value) = value {
            self.column_dec128(name, value)
        } else {
            Ok(self)
        }
    }

    /// Adds a UUID column to the current row. QWP-only.
    ///
    /// Per spec, the wire encoding writes `lo` (8 bytes LE) followed by `hi`
    /// (8 bytes LE).
    pub fn column_uuid<'a, N>(&mut self, name: N, lo: u64, hi: u64) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        let _ = &name;
        let _ = (lo, hi);
        match &mut self.inner {
            BufferInner::Ilp(_) => Err(error::fmt!(
                InvalidApiCall,
                "column_uuid requires a QWP transport (qwpws:: or qwpudp::)"
            )),
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => {
                inner.column_uuid(name, lo, hi)?;
                Ok(self)
            }
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(inner) => {
                inner.column_uuid(name, lo, hi)?;
                Ok(self)
            }
        }
    }

    /// Adds a UUID column if `value` is `Some`. QWP-only.
    pub fn column_uuid_opt<'a, N>(
        &mut self,
        name: N,
        value: Option<(u64, u64)>,
    ) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        if let Some((lo, hi)) = value {
            self.column_uuid(name, lo, hi)
        } else {
            Ok(self)
        }
    }

    /// Adds a LONG256 column to the current row. QWP-only.
    ///
    /// `value` is the wire-format byte buffer: four 64-bit limbs encoded
    /// little-endian, least-significant limb first (32 bytes total).
    pub fn column_long256<'a, N>(&mut self, name: N, value: &[u8; 32]) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        let _ = (&name, value);
        match &mut self.inner {
            BufferInner::Ilp(_) => Err(error::fmt!(
                InvalidApiCall,
                "column_long256 requires a QWP transport (qwpws:: or qwpudp::)"
            )),
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => {
                inner.column_long256(name, value)?;
                Ok(self)
            }
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(inner) => {
                inner.column_long256(name, value)?;
                Ok(self)
            }
        }
    }

    /// Adds a LONG256 column if `value` is `Some`. QWP-only.
    pub fn column_long256_opt<'a, N>(
        &mut self,
        name: N,
        value: Option<&[u8; 32]>,
    ) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        if let Some(value) = value {
            self.column_long256(name, value)
        } else {
            Ok(self)
        }
    }

    /// Adds an IPv4 column to the current row. QWP-only.
    ///
    /// The wire encoding writes the 4 octets as `u32::from(addr).to_le_bytes()`,
    /// matching Rust's natural Ipv4Addr packing (octet 0 in the high byte).
    ///
    /// IPv4 (`0x18`) is part of the QWP v1 spec.
    pub fn column_ipv4<'a, N>(
        &mut self,
        name: N,
        value: std::net::Ipv4Addr,
    ) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        let _ = (&name, value);
        let packed = u32::from(value);
        let _ = packed;
        match &mut self.inner {
            BufferInner::Ilp(_) => Err(error::fmt!(
                InvalidApiCall,
                "column_ipv4 requires a QWP transport (qwpws:: or qwpudp::)"
            )),
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => {
                inner.column_ipv4(name, packed)?;
                Ok(self)
            }
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(inner) => {
                inner.column_ipv4(name, packed)?;
                Ok(self)
            }
        }
    }

    /// Adds an IPv4 column if `value` is `Some`. QWP-only.
    pub fn column_ipv4_opt<'a, N>(
        &mut self,
        name: N,
        value: Option<std::net::Ipv4Addr>,
    ) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        if let Some(value) = value {
            self.column_ipv4(name, value)
        } else {
            Ok(self)
        }
    }

    /// Adds a DATE column (milliseconds since the Unix epoch). QWP-only.
    pub fn column_date<'a, N>(&mut self, name: N, millis: i64) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        let _ = (&name, &millis);
        match &mut self.inner {
            BufferInner::Ilp(_) => Err(error::fmt!(
                InvalidApiCall,
                "column_date requires a QWP transport (qwpws:: or qwpudp::)"
            )),
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => {
                inner.column_date(name, millis)?;
                Ok(self)
            }
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(inner) => {
                inner.column_date(name, millis)?;
                Ok(self)
            }
        }
    }

    /// Adds a DATE column if `value` is `Some`. QWP-only.
    pub fn column_date_opt<'a, N>(
        &mut self,
        name: N,
        value: Option<i64>,
    ) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        if let Some(value) = value {
            self.column_date(name, value)
        } else {
            Ok(self)
        }
    }

    /// Adds a CHAR column (single UTF-16 code unit). QWP-only.
    pub fn column_char<'a, N>(&mut self, name: N, value: u16) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        let _ = (&name, &value);
        match &mut self.inner {
            BufferInner::Ilp(_) => Err(error::fmt!(
                InvalidApiCall,
                "column_char requires a QWP transport (qwpws:: or qwpudp::)"
            )),
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => {
                inner.column_char(name, value)?;
                Ok(self)
            }
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(inner) => {
                inner.column_char(name, value)?;
                Ok(self)
            }
        }
    }

    /// Adds a CHAR column if `value` is `Some`. QWP-only.
    pub fn column_char_opt<'a, N>(
        &mut self,
        name: N,
        value: Option<u16>,
    ) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        if let Some(value) = value {
            self.column_char(name, value)
        } else {
            Ok(self)
        }
    }

    /// Adds a BINARY column (opaque byte sequence). QWP-only.
    ///
    /// BINARY (`0x17`) is part of the QWP v1 spec.
    pub fn column_binary<'a, N>(&mut self, name: N, value: &[u8]) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        let _ = (&name, value);
        match &mut self.inner {
            BufferInner::Ilp(_) => Err(error::fmt!(
                InvalidApiCall,
                "column_binary requires a QWP transport (qwpws:: or qwpudp::)"
            )),
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => {
                inner.column_binary(name, value)?;
                Ok(self)
            }
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(inner) => {
                inner.column_binary(name, value)?;
                Ok(self)
            }
        }
    }

    /// Adds a BINARY column if `value` is `Some`. QWP-only.
    pub fn column_binary_opt<'a, N>(
        &mut self,
        name: N,
        value: Option<&[u8]>,
    ) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        if let Some(value) = value {
            self.column_binary(name, value)
        } else {
            Ok(self)
        }
    }

    /// Adds a GEOHASH column. `precision_bits` must be in `1..=60` and is
    /// pinned per column (subsequent rows must match). QWP-only.
    pub fn column_geohash<'a, N>(
        &mut self,
        name: N,
        bits: u64,
        precision_bits: u8,
    ) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        let _ = (&name, &bits, &precision_bits);
        match &mut self.inner {
            BufferInner::Ilp(_) => Err(error::fmt!(
                InvalidApiCall,
                "column_geohash requires a QWP transport (qwpws:: or qwpudp::)"
            )),
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => {
                inner.column_geohash(name, bits, precision_bits)?;
                Ok(self)
            }
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(inner) => {
                inner.column_geohash(name, bits, precision_bits)?;
                Ok(self)
            }
        }
    }

    /// Adds a GEOHASH column if `value` is `Some`. QWP-only.
    pub fn column_geohash_opt<'a, N>(
        &mut self,
        name: N,
        value: Option<(u64, u8)>,
    ) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        if let Some((bits, precision)) = value {
            self.column_geohash(name, bits, precision)
        } else {
            Ok(self)
        }
    }

    #[allow(private_bounds)]
    /// Adds an array column to the current row.
    ///
    /// Arrays require ILP protocol version 2 or later. QWP supports `f64`
    /// (DOUBLE_ARRAY, `0x11`) and `i64` (LONG_ARRAY, `0x12`) element types.
    /// LONG_ARRAY is part of the QWP v1 spec. Server-side ingest does not
    /// currently implement this wire type; batches using it will be rejected
    /// with a descriptive error. This may change in future server releases.
    pub fn column_arr<'a, N, T, D>(&mut self, name: N, view: &T) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        T: NdArrayView<D>,
        D: ArrayElement + ArrayElementSealed,
        Error: From<N::Error>,
    {
        match &mut self.inner {
            BufferInner::Ilp(inner) => {
                if D::type_tag() != 10 {
                    return Err(error::fmt!(
                        InvalidApiCall,
                        "column_arr with non-f64 element type requires a QWP transport (qwpws:: or qwpudp::)"
                    ));
                }
                inner.column_arr(name, view)?;
            }
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => {
                inner.column_arr(name, view)?;
            }
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(inner) => {
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
        N: AsRef<str> + TryInto<ColumnName<'a>>,
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
    #[inline(always)]
    pub fn column_ts<'a, N, T>(&mut self, name: N, value: T) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
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
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(inner) => {
                inner.column_ts(name, value)?;
            }
        }
        Ok(self)
    }

    /// Adds a timestamp column if `value` is `Some`; otherwise leaves the row unchanged.
    pub fn column_ts_opt<'a, N, T>(&mut self, name: N, value: Option<T>) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
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
    #[inline(always)]
    pub fn at<T>(&mut self, timestamp: T) -> crate::Result<()>
    where
        T: TryInto<Timestamp>,
        Error: From<T::Error>,
    {
        match &mut self.inner {
            BufferInner::Ilp(inner) => inner.at(timestamp),
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => inner.at(timestamp),
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(inner) => inner.at(timestamp),
        }
    }

    /// Completes the current row without a designated timestamp so the server
    /// assigns one.
    ///
    /// This is not equivalent to calling [`Buffer::at`] with the current client
    /// time.
    #[inline(always)]
    pub fn at_now(&mut self) -> crate::Result<()> {
        match &mut self.inner {
            BufferInner::Ilp(inner) => inner.at_now(),
            #[cfg(any(feature = "_sender-qwp-udp", feature = "_sender-qwp-ws"))]
            BufferInner::Qwp(inner) => inner.at_now(),
            #[cfg(feature = "_sender-qwp-ws")]
            BufferInner::QwpWs(inner) => inner.at_now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Bookmark, Buffer, ColumnName, StoredBookmark, TableName};
    use crate::ErrorCode;
    use crate::ingress::ProtocolVersion;

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

    #[test]
    fn buffer_column_i8_rejects_ilp_buffer() {
        let mut buf = Buffer::new(ProtocolVersion::V2);
        buf.table("trades").unwrap();
        let err = buf.column_i8("v", 1).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert!(
            err.msg().contains("column_i8"),
            "error message should name column_i8: {}",
            err.msg()
        );
    }

    #[test]
    fn buffer_column_i16_rejects_ilp_buffer() {
        let mut buf = Buffer::new(ProtocolVersion::V2);
        buf.table("trades").unwrap();
        let err = buf.column_i16("v", 1).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("column_i16"), "{}", err.msg());
    }

    #[test]
    fn buffer_column_i32_rejects_ilp_buffer() {
        let mut buf = Buffer::new(ProtocolVersion::V2);
        buf.table("trades").unwrap();
        let err = buf.column_i32("v", 1).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("column_i32"), "{}", err.msg());
    }

    #[test]
    fn buffer_column_dec64_rejects_ilp_buffer() {
        let mut buf = Buffer::new(ProtocolVersion::V3);
        buf.table("trades").unwrap();
        let err = buf.column_dec64("v", "1.25").unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("column_dec64"), "{}", err.msg());
    }

    #[test]
    fn buffer_column_dec128_rejects_ilp_buffer() {
        let mut buf = Buffer::new(ProtocolVersion::V3);
        buf.table("trades").unwrap();
        let err = buf.column_dec128("v", "1.25").unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("column_dec128"), "{}", err.msg());
    }

    #[test]
    fn buffer_column_uuid_rejects_ilp_buffer() {
        let mut buf = Buffer::new(ProtocolVersion::V2);
        buf.table("trades").unwrap();
        let err = buf.column_uuid("v", 1, 2).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("column_uuid"), "{}", err.msg());
    }

    #[test]
    fn buffer_column_long256_rejects_ilp_buffer() {
        let mut buf = Buffer::new(ProtocolVersion::V2);
        buf.table("trades").unwrap();
        let err = buf.column_long256("v", &[0u8; 32]).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("column_long256"), "{}", err.msg());
    }

    #[test]
    fn buffer_column_ipv4_rejects_ilp_buffer() {
        let mut buf = Buffer::new(ProtocolVersion::V2);
        buf.table("trades").unwrap();
        let err = buf
            .column_ipv4("v", std::net::Ipv4Addr::new(127, 0, 0, 1))
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("column_ipv4"), "{}", err.msg());
    }

    #[test]
    fn buffer_column_date_rejects_ilp_buffer() {
        let mut buf = Buffer::new(ProtocolVersion::V2);
        buf.table("t").unwrap();
        let err = buf.column_date("v", 42).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("column_date"), "{}", err.msg());
    }

    #[test]
    fn buffer_column_char_rejects_ilp_buffer() {
        let mut buf = Buffer::new(ProtocolVersion::V2);
        buf.table("t").unwrap();
        let err = buf.column_char("v", 0x0041).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("column_char"), "{}", err.msg());
    }

    #[test]
    fn buffer_column_binary_rejects_ilp_buffer() {
        let mut buf = Buffer::new(ProtocolVersion::V2);
        buf.table("t").unwrap();
        let err = buf.column_binary("v", b"abc").unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("column_binary"), "{}", err.msg());
    }

    #[test]
    fn buffer_column_geohash_rejects_ilp_buffer() {
        let mut buf = Buffer::new(ProtocolVersion::V2);
        buf.table("t").unwrap();
        let err = buf.column_geohash("v", 0xABCD, 16).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("column_geohash"), "{}", err.msg());
    }

    #[test]
    fn buffer_column_f32_rejects_ilp_buffer() {
        let mut buf = Buffer::new(ProtocolVersion::V2);
        buf.table("t").unwrap();
        let err = buf.column_f32("v", 1.5_f32).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("column_f32"), "{}", err.msg());
    }

    #[test]
    fn name_validation_table_name_uses_byte_offset_for_invalid_char() {
        let err = match TableName::new("é?") {
            Ok(_) => panic!("expected invalid table name"),
            Err(err) => err,
        };
        assert_eq!(err.code(), ErrorCode::InvalidName);
        assert_eq!(
            err.msg(),
            r#"Bad string "é?": Table names can't contain a '?' character, which was found at byte position 2."#
        );
    }

    #[test]
    fn name_validation_table_name_rejects_trailing_dot_at_byte_offset() {
        let err = match TableName::new("é.") {
            Ok(_) => panic!("expected invalid table name"),
            Err(err) => err,
        };
        assert_eq!(err.code(), ErrorCode::InvalidName);
        assert_eq!(
            err.msg(),
            r#"Bad string "é.": Found invalid dot `.` at position 2."#
        );
    }

    #[test]
    fn name_validation_column_name_uses_byte_offset_for_invalid_char() {
        let err = match ColumnName::new("é?") {
            Ok(_) => panic!("expected invalid column name"),
            Err(err) => err,
        };
        assert_eq!(err.code(), ErrorCode::InvalidName);
        assert_eq!(
            err.msg(),
            r#"Bad string "é?": Column names can't contain a '?' character, which was found at byte position 2."#
        );
    }
}
