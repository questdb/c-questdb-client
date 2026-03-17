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

#[cfg(feature = "_sender-qwp-udp")]
mod qwp;

use crate::Error;
use crate::ingress::ndarr::ArrayElementSealed;
use crate::ingress::{ArrayElement, DecimalView, NdArrayView, ProtocolVersion, Timestamp};

pub(crate) use self::ilp::Buffer as IlpBuffer;
#[allow(unused_imports)]
pub(crate) use self::ilp::F64Serializer;
pub use self::ilp::{ColumnName, TableName};

#[cfg(feature = "_sender-qwp-udp")]
pub(crate) use self::qwp::QwpBuffer;
#[cfg(feature = "_sender-qwp-udp")]
pub(crate) use self::qwp::QwpSendScratch;

#[derive(Clone, Debug)]
enum BufferInner {
    Ilp(IlpBuffer),

    #[cfg(feature = "_sender-qwp-udp")]
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

    #[cfg(feature = "_sender-qwp-udp")]
    /// Creates a new QWP/UDP buffer with default parameters.
    pub fn new_qwp() -> Self {
        Self::qwp_with_max_name_len(127)
    }

    #[cfg(feature = "_sender-qwp-udp")]
    /// Creates a new QWP/UDP buffer with a custom maximum name length.
    pub fn qwp_with_max_name_len(max_name_len: usize) -> Self {
        Self {
            inner: BufferInner::Qwp(Box::new(QwpBuffer::new(max_name_len))),
        }
    }

    pub(crate) fn as_ilp(&self) -> Option<&IlpBuffer> {
        match &self.inner {
            BufferInner::Ilp(inner) => Some(inner),
            #[cfg(feature = "_sender-qwp-udp")]
            BufferInner::Qwp(_) => None,
        }
    }

    #[cfg(feature = "_sender-qwp-udp")]
    pub(crate) fn as_qwp(&self) -> Option<&QwpBuffer> {
        match &self.inner {
            BufferInner::Ilp(_) => None,
            BufferInner::Qwp(inner) => Some(inner.as_ref()),
        }
    }

    /// Returns the protocol version associated with this buffer.
    ///
    /// See [`ProtocolVersion`] for transport-specific interpretation.
    pub fn protocol_version(&self) -> ProtocolVersion {
        match &self.inner {
            BufferInner::Ilp(inner) => inner.protocol_version(),
            #[cfg(feature = "_sender-qwp-udp")]
            BufferInner::Qwp(_) => ProtocolVersion::V1,
        }
    }

    /// Reserves capacity for at least `additional` more bytes of buffered data.
    ///
    /// For QWP/UDP buffers this reserves internal arena capacity used during
    /// datagram planning and encoding.
    pub fn reserve(&mut self, additional: usize) {
        match &mut self.inner {
            BufferInner::Ilp(inner) => inner.reserve(additional),
            #[cfg(feature = "_sender-qwp-udp")]
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
            #[cfg(feature = "_sender-qwp-udp")]
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
            #[cfg(feature = "_sender-qwp-udp")]
            BufferInner::Qwp(inner) => inner.row_count(),
        }
    }

    /// Returns whether the buffered batch is still eligible for transactional
    /// flushing.
    ///
    /// This is `true` only while the buffer contains rows for at most one table.
    /// Actual transactional behavior also depends on the transport; QWP/UDP does
    /// not support transactional flushes.
    pub fn transactional(&self) -> bool {
        match &self.inner {
            BufferInner::Ilp(inner) => inner.transactional(),
            #[cfg(feature = "_sender-qwp-udp")]
            BufferInner::Qwp(inner) => inner.transactional(),
        }
    }

    /// Returns `true` if the buffer contains no committed or in-progress rows.
    pub fn is_empty(&self) -> bool {
        match &self.inner {
            BufferInner::Ilp(inner) => inner.is_empty(),
            #[cfg(feature = "_sender-qwp-udp")]
            BufferInner::Qwp(inner) => inner.is_empty(),
        }
    }

    /// Returns the currently allocated backing capacity in bytes.
    pub fn capacity(&self) -> usize {
        match &self.inner {
            BufferInner::Ilp(inner) => inner.capacity(),
            #[cfg(feature = "_sender-qwp-udp")]
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
            #[cfg(feature = "_sender-qwp-udp")]
            BufferInner::Qwp(inner) => inner.as_bytes(),
        }
    }

    /// Marks the current buffer state so it can later be restored with
    /// [`Buffer::rewind_to_marker`].
    ///
    /// Setting a new marker replaces the previous one.
    pub fn set_marker(&mut self) -> crate::Result<()> {
        match &mut self.inner {
            BufferInner::Ilp(inner) => inner.set_marker(),
            #[cfg(feature = "_sender-qwp-udp")]
            BufferInner::Qwp(inner) => inner.set_marker(),
        }
    }

    /// Rewinds the buffer to the most recent marker and then clears that marker.
    ///
    /// Returns an error if no marker is set.
    pub fn rewind_to_marker(&mut self) -> crate::Result<()> {
        match &mut self.inner {
            BufferInner::Ilp(inner) => inner.rewind_to_marker(),
            #[cfg(feature = "_sender-qwp-udp")]
            BufferInner::Qwp(inner) => inner.rewind_to_marker(),
        }
    }

    /// Clears the current marker, if any.
    pub fn clear_marker(&mut self) {
        match &mut self.inner {
            BufferInner::Ilp(inner) => inner.clear_marker(),
            #[cfg(feature = "_sender-qwp-udp")]
            BufferInner::Qwp(inner) => inner.clear_marker(),
        }
    }

    /// Clears the buffer contents and marker while retaining allocated capacity.
    pub fn clear(&mut self) {
        match &mut self.inner {
            BufferInner::Ilp(inner) => inner.clear(),
            #[cfg(feature = "_sender-qwp-udp")]
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
            #[cfg(feature = "_sender-qwp-udp")]
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
            #[cfg(feature = "_sender-qwp-udp")]
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
            #[cfg(feature = "_sender-qwp-udp")]
            BufferInner::Qwp(inner) => {
                inner.symbol(name, value)?;
            }
        }
        Ok(self)
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
            #[cfg(feature = "_sender-qwp-udp")]
            BufferInner::Qwp(inner) => {
                inner.column_bool(name, value)?;
            }
        }
        Ok(self)
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
            #[cfg(feature = "_sender-qwp-udp")]
            BufferInner::Qwp(inner) => {
                inner.column_i64(name, value)?;
            }
        }
        Ok(self)
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
            #[cfg(feature = "_sender-qwp-udp")]
            BufferInner::Qwp(inner) => {
                inner.column_f64(name, value)?;
            }
        }
        Ok(self)
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
            #[cfg(feature = "_sender-qwp-udp")]
            BufferInner::Qwp(inner) => {
                inner.column_str(name, value)?;
            }
        }
        Ok(self)
    }

    /// Adds a decimal column to the current row.
    ///
    /// Returns an error if the active protocol does not support decimal values.
    /// QWP/UDP buffers currently reject this call.
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
            #[cfg(feature = "_sender-qwp-udp")]
            BufferInner::Qwp(inner) => {
                inner.column_dec(name, value)?;
            }
        }
        Ok(self)
    }

    #[allow(private_bounds)]
    /// Adds an array column to the current row.
    ///
    /// Arrays require ILP protocol version 2 or later and are not currently
    /// supported by QWP/UDP buffers.
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
            #[cfg(feature = "_sender-qwp-udp")]
            BufferInner::Qwp(inner) => {
                inner.column_arr(name, view)?;
            }
        }
        Ok(self)
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
            #[cfg(feature = "_sender-qwp-udp")]
            BufferInner::Qwp(inner) => {
                inner.column_ts(name, value)?;
            }
        }
        Ok(self)
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
            #[cfg(feature = "_sender-qwp-udp")]
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
            #[cfg(feature = "_sender-qwp-udp")]
            BufferInner::Qwp(inner) => inner.at_now(),
        }
    }
}
