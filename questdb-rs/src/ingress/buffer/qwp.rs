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

use crate::error;
use crate::ingress::decimal::DecimalView;
use crate::ingress::{ArrayElement, NdArrayView, Timestamp};
use crate::{Error, ErrorCode};
use std::fmt::Debug;

use super::ilp::{ColumnName, TableName};

/// Wire layout of a QWP datagram header.
///
/// ```text
/// [0..4]   magic        "QWP1"
/// [4]      version      protocol version (currently 1)
/// [5]      flags        reserved
/// [6..8]   table_count  little-endian u16
/// [8..12]  payload_len  little-endian u32
/// ```
#[repr(C, packed)]
pub(crate) struct QwpMessageHeader {
    pub(crate) magic: [u8; 4],
    pub(crate) version: u8,
    pub(crate) flags: u8,
    pub(crate) table_count: u16,
    pub(crate) payload_len: u32,
}

impl QwpMessageHeader {
    /// Serialize the header into the first [`QWP_MESSAGE_HEADER_SIZE`] bytes of `out`.
    fn write_to(&self, out: &mut [u8]) {
        out[..4].copy_from_slice(&self.magic);
        out[4] = self.version;
        out[5] = self.flags;
        out[6..8].copy_from_slice(&self.table_count.to_le_bytes());
        out[8..12].copy_from_slice(&self.payload_len.to_le_bytes());
    }
}

pub(crate) const QWP_MESSAGE_HEADER_SIZE: usize = std::mem::size_of::<QwpMessageHeader>();

// Compile-time guarantee that the header is exactly 12 bytes.
const _: () = assert!(QWP_MESSAGE_HEADER_SIZE == 12);

pub(crate) const QWP_SCHEMA_MODE_FULL: u8 = 0x00;
pub(crate) const QWP_TYPE_BOOLEAN: u8 = 0x01;
pub(crate) const QWP_TYPE_DOUBLE: u8 = 0x07;
pub(crate) const QWP_TYPE_LONG: u8 = 0x05;
pub(crate) const QWP_TYPE_STRING: u8 = 0x08;
pub(crate) const QWP_TYPE_SYMBOL: u8 = 0x09;
pub(crate) const QWP_TYPE_TIMESTAMP: u8 = 0x0A;
pub(crate) const QWP_TYPE_TIMESTAMP_NANOS: u8 = 0x10;
pub(crate) const QWP_TYPE_NULLABLE_FLAG: u8 = 0x80;
pub(crate) const QWP_VERSION_1: u8 = 1;
// --- Arena slice types ---

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ByteSlice {
    offset: u32,
    len: u32,
}

impl ByteSlice {
    fn as_range(&self) -> std::ops::Range<usize> {
        self.offset as usize..(self.offset as usize + self.len as usize)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NameSlice(ByteSlice);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ValueSlice(ByteSlice);

// --- Column kind ---

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ColumnKind {
    Bool,
    Symbol,
    I64,
    F64,
    String,
    TimestampMicros,
    TimestampNanos,
}

// --- Designated timestamp ---

#[derive(Clone, Copy, Debug)]
enum DesignatedTs {
    Micros(i64),
    Nanos(i64),
}

// --- Value reference into arenas ---

#[derive(Clone, Copy, Debug)]
enum ValueRef {
    Bool(bool),
    I64(i64),
    F64(f64),
    TimestampMicros(i64),
    TimestampNanos(i64),
    Symbol(ValueSlice),
    String(ValueSlice),
}

impl ValueRef {
    fn kind(&self) -> ColumnKind {
        match self {
            ValueRef::Bool(_) => ColumnKind::Bool,
            ValueRef::I64(_) => ColumnKind::I64,
            ValueRef::F64(_) => ColumnKind::F64,
            ValueRef::TimestampMicros(_) => ColumnKind::TimestampMicros,
            ValueRef::TimestampNanos(_) => ColumnKind::TimestampNanos,
            ValueRef::Symbol(_) => ColumnKind::Symbol,
            ValueRef::String(_) => ColumnKind::String,
        }
    }
}

// --- Cell reference (planner scratch) ---

const CELL_END: u32 = u32::MAX;

#[derive(Clone, Copy, Debug)]
struct CellRef {
    row_idx: u16,
    /// Pre-computed symbol dictionary index; unused for non-symbol columns.
    symbol_dict_idx: u16,
    next: u32,
    value: ValueRef,
}

// --- Row and entry metadata ---

#[derive(Clone, Copy, Debug)]
struct RowMeta {
    table: NameSlice,
    entry_start: u32,
    entry_count: u32,
    designated_ts: Option<DesignatedTs>,
}

#[derive(Clone, Copy, Debug)]
struct EntryMeta {
    name: NameSlice,
    value: ValueRef,
}

// --- Segment metadata ---

#[derive(Clone, Copy, Debug)]
struct SegmentMeta {
    table: NameSlice,
    row_start: u32,
    row_count: u32,
}

// --- Pending row state ---

#[derive(Clone, Copy, Debug)]
struct PendingRowState {
    table: Option<NameSlice>,
    entry_start: u32,
    name_bytes_start: u32,
    value_bytes_start: u32,
}

impl PendingRowState {
    fn empty() -> Self {
        Self {
            table: None,
            entry_start: 0,
            name_bytes_start: 0,
            value_bytes_start: 0,
        }
    }
}

// --- Op state machine ---

#[derive(Debug, Copy, Clone)]
enum Op {
    Table = 1,
    Symbol = 1 << 1,
    Column = 1 << 2,
    At = 1 << 3,
    Flush = 1 << 4,
}

impl Op {
    fn descr(self) -> &'static str {
        match self {
            Op::Table => "table",
            Op::Symbol => "symbol",
            Op::Column => "column",
            Op::At => "at",
            Op::Flush => "flush",
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
enum OpCase {
    Init = Op::Table as isize,
    TableWritten = Op::Symbol as isize | Op::Column as isize,
    SymbolWritten = Op::Symbol as isize | Op::Column as isize | Op::At as isize,
    ColumnWritten = Op::Column as isize | Op::At as isize,
    MayFlushOrTable = Op::Flush as isize | Op::Table as isize,
}

impl OpCase {
    fn next_op_descr(self) -> &'static str {
        match self {
            OpCase::Init => "should have called `table` instead",
            OpCase::TableWritten => "should have called `symbol` or `column` instead",
            OpCase::SymbolWritten => "should have called `symbol`, `column` or `at` instead",
            OpCase::ColumnWritten => "should have called `column` or `at` instead",
            OpCase::MayFlushOrTable => "should have called `flush` or `table` instead",
        }
    }
}

// --- Buffer state ---

#[derive(Clone, Copy, Debug)]
struct BufferState {
    op_case: OpCase,
    row_count: usize,
    first_table_name: Option<NameSlice>,
    transactional: bool,
}

impl BufferState {
    fn new() -> Self {
        Self {
            op_case: OpCase::Init,
            row_count: 0,
            first_table_name: None,
            transactional: true,
        }
    }
}

// --- Size hint ---

#[derive(Clone, Debug)]
struct QwpSizeHint {
    committed_len: usize,
    planner: RowGroupPlanner,
    group_table: Option<NameSlice>,
}

impl QwpSizeHint {
    fn new() -> Self {
        Self {
            committed_len: 0,
            planner: RowGroupPlanner::new_stats_only(),
            group_table: None,
        }
    }

    fn clear(&mut self) {
        self.committed_len = 0;
        self.planner.clear();
        self.group_table = None;
    }

    fn len(&self) -> usize {
        self.committed_len
    }

    fn add_committed_row(
        &mut self,
        row: &RowMeta,
        entries: &[EntryMeta],
        name_bytes: &[u8],
        value_bytes: &[u8],
        last_segment_table: Option<NameSlice>,
    ) -> crate::Result<()> {
        let table_name = &name_bytes[row.table.0.as_range()];
        let same_group = if let Some(group_table) = self.group_table {
            if let Some(seg_table) = last_segment_table {
                &name_bytes[group_table.0.as_range()] == table_name
                    && &name_bytes[seg_table.0.as_range()] == table_name
            } else {
                false
            }
        } else {
            false
        };

        let row_entries =
            &entries[row.entry_start as usize..(row.entry_start + row.entry_count) as usize];

        if same_group {
            let previous_len = self.planner.current_len;
            match self
                .planner
                .add_row(row, row_entries, name_bytes, value_bytes, table_name.len())
            {
                Ok(()) => {
                    let new_len = self.planner.current_len;
                    self.committed_len = self.committed_len - previous_len + new_len;
                }
                Err(err) if is_batched_type_change_error(&err) => {
                    self.committed_len +=
                        standalone_row_group_len(row, row_entries, name_bytes, value_bytes);
                    self.planner.clear();
                    self.group_table = None;
                }
                Err(err) => return Err(err),
            }
            return Ok(());
        }

        self.planner.clear();
        self.planner
            .add_row(row, row_entries, name_bytes, value_bytes, table_name.len())?;
        self.committed_len += self.planner.current_len;
        self.group_table = Some(row.table);
        Ok(())
    }
}

// --- Marker ---
// Design doc proposes snapshotting QwpSizeHint here, but that would clone
// the planner's Vecs on every set_marker(). Instead we store only scalar
// arena lengths and recompute the size hint from committed rows on rewind.
// The O(rows) replay cost on rewind_to_marker is acceptable since marker
// rewind is not a steady-state hot path.

#[derive(Clone, Copy, Debug)]
struct QwpMarker {
    rows_len: u32,
    entries_len: u32,
    segments_len: u32,
    tail_segment_row_count: Option<u32>,
    name_bytes_len: u32,
    value_bytes_len: u32,
    state: BufferState,
}

// --- QwpBuffer ---

#[derive(Debug)]
pub(crate) struct QwpBuffer {
    name_bytes: Vec<u8>,
    value_bytes: Vec<u8>,
    rows: Vec<RowMeta>,
    entries: Vec<EntryMeta>,
    segments: Vec<SegmentMeta>,
    pending: PendingRowState,
    state: BufferState,
    size_hint: QwpSizeHint,
    marker: Option<QwpMarker>,
    max_name_len: usize,
}

impl Clone for QwpBuffer {
    fn clone(&self) -> Self {
        // Copy only live data, not spare capacity
        let name_bytes = self.name_bytes[..].to_vec();
        let value_bytes = self.value_bytes[..].to_vec();
        let rows = self.rows[..].to_vec();
        let entries = self.entries[..].to_vec();
        let segments = self.segments[..].to_vec();
        Self {
            name_bytes,
            value_bytes,
            rows,
            entries,
            segments,
            pending: self.pending,
            state: self.state,
            size_hint: self.size_hint.clone(),
            marker: self.marker,
            max_name_len: self.max_name_len,
        }
    }
}

impl QwpBuffer {
    pub(crate) fn new(max_name_len: usize) -> Self {
        Self {
            name_bytes: Vec::new(),
            value_bytes: Vec::new(),
            rows: Vec::new(),
            entries: Vec::new(),
            segments: Vec::new(),
            pending: PendingRowState::empty(),
            state: BufferState::new(),
            size_hint: QwpSizeHint::new(),
            marker: None,
            max_name_len,
        }
    }

    pub(crate) fn reserve(&mut self, additional: usize) {
        // Conservative worst-case: the minimum encoded schema contribution
        // per column-entry is ~3 bytes (1-byte name varint + 1-byte name +
        // 1-byte type). Assume 1 entry per row for the row bound.
        // Multi-row packed-bool groups can still undercount rows, but the
        // first flush cycle's retained capacity covers that gap.
        let max_entries = additional / 3;
        let max_rows = max_entries;
        self.name_bytes.reserve(additional);
        self.value_bytes.reserve(additional);
        self.rows.reserve(max_rows.max(1));
        self.entries.reserve(max_entries.max(1));
        self.segments.reserve((max_rows / 4).max(1));
    }

    pub(crate) fn len(&self) -> usize {
        self.size_hint.len() + self.pending_size_hint()
    }

    pub(crate) fn row_count(&self) -> usize {
        self.state.row_count
    }

    pub(crate) fn transactional(&self) -> bool {
        self.state.transactional
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pending.table.is_none() && self.rows.is_empty()
    }

    pub(crate) fn capacity(&self) -> usize {
        self.name_bytes.capacity()
            + self.value_bytes.capacity()
            + self.rows.capacity() * std::mem::size_of::<RowMeta>()
            + self.entries.capacity() * std::mem::size_of::<EntryMeta>()
            + self.segments.capacity() * std::mem::size_of::<SegmentMeta>()
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &[]
    }

    pub(crate) fn set_marker(&mut self) -> crate::Result<()> {
        if (self.state.op_case as isize & Op::Table as isize) == 0 {
            return Err(error::fmt!(
                InvalidApiCall,
                concat!(
                    "Can't set the marker whilst constructing a line. ",
                    "A marker may only be set on an empty buffer or after ",
                    "`at` or `at_now` is called."
                )
            ));
        }
        self.marker = Some(QwpMarker {
            rows_len: self.rows.len() as u32,
            entries_len: self.entries.len() as u32,
            segments_len: self.segments.len() as u32,
            tail_segment_row_count: self.segments.last().map(|s| s.row_count),
            name_bytes_len: self.name_bytes.len() as u32,
            value_bytes_len: self.value_bytes.len() as u32,
            state: self.state,
        });
        Ok(())
    }

    pub(crate) fn rewind_to_marker(&mut self) -> crate::Result<()> {
        if let Some(marker) = self.marker.take() {
            self.rows.truncate(marker.rows_len as usize);
            self.entries.truncate(marker.entries_len as usize);
            self.name_bytes.truncate(marker.name_bytes_len as usize);
            self.value_bytes.truncate(marker.value_bytes_len as usize);
            self.segments.truncate(marker.segments_len as usize);
            if let Some(tail_row_count) = marker.tail_segment_row_count
                && let Some(last_seg) = self.segments.last_mut()
            {
                last_seg.row_count = tail_row_count;
            }
            self.pending = PendingRowState::empty();
            self.state = marker.state;
            self.recompute_size_hint();
            Ok(())
        } else {
            Err(error::fmt!(
                InvalidApiCall,
                "Can't rewind to the marker: No marker set."
            ))
        }
    }

    pub(crate) fn clear_marker(&mut self) {
        self.marker = None;
    }

    pub(crate) fn clear(&mut self) {
        self.name_bytes.clear();
        self.value_bytes.clear();
        self.rows.clear();
        self.entries.clear();
        self.segments.clear();
        self.pending = PendingRowState::empty();
        self.state = BufferState::new();
        self.size_hint.clear();
        self.marker = None;
    }

    fn recompute_size_hint(&mut self) {
        self.size_hint.clear();
        let mut prev_seg_table: Option<NameSlice> = None;
        for seg_idx in 0..self.segments.len() {
            let segment = self.segments[seg_idx];
            let start = segment.row_start as usize;
            for i in 0..segment.row_count as usize {
                let row = &self.rows[start + i];
                let last_seg_table = if i == 0 {
                    prev_seg_table
                } else {
                    Some(segment.table)
                };
                let _ = self.size_hint.add_committed_row(
                    row,
                    &self.entries,
                    &self.name_bytes,
                    &self.value_bytes,
                    last_seg_table,
                );
            }
            prev_seg_table = Some(segment.table);
        }
    }

    pub(crate) fn check_can_flush(&self) -> crate::Result<()> {
        self.check_op(Op::Flush)
    }

    fn check_op(&self, op: Op) -> crate::Result<()> {
        if (self.state.op_case as isize & op as isize) > 0 {
            Ok(())
        } else {
            Err(error::fmt!(
                InvalidApiCall,
                "State error: Bad call to `{}`, {}.",
                op.descr(),
                self.state.op_case.next_op_descr()
            ))
        }
    }

    fn validate_max_name_len(&self, name: &str) -> crate::Result<()> {
        if name.len() > self.max_name_len {
            return Err(error::fmt!(
                InvalidName,
                "Bad name: {:?}: Too long (max {} characters)",
                name,
                self.max_name_len
            ));
        }
        Ok(())
    }

    fn append_name(&mut self, name: &str) -> NameSlice {
        debug_assert!(
            self.name_bytes.len() + name.len() <= u32::MAX as usize,
            "name_bytes arena overflow"
        );
        let offset = self.name_bytes.len() as u32;
        self.name_bytes.extend_from_slice(name.as_bytes());
        NameSlice(ByteSlice {
            offset,
            len: name.len() as u32,
        })
    }

    fn append_value_str(&mut self, value: &str) -> ValueSlice {
        debug_assert!(
            self.value_bytes.len() + value.len() <= u32::MAX as usize,
            "value_bytes arena overflow"
        );
        let offset = self.value_bytes.len() as u32;
        self.value_bytes.extend_from_slice(value.as_bytes());
        ValueSlice(ByteSlice {
            offset,
            len: value.len() as u32,
        })
    }

    fn name_str(&self, ns: NameSlice) -> &str {
        std::str::from_utf8(&self.name_bytes[ns.0.as_range()]).expect("name must be valid UTF-8")
    }

    fn rollback_pending(&mut self) {
        self.entries.truncate(self.pending.entry_start as usize);
        self.name_bytes
            .truncate(self.pending.name_bytes_start as usize);
        self.value_bytes
            .truncate(self.pending.value_bytes_start as usize);
        self.pending.table = None;
    }

    fn update_transactional_state(&mut self, table_ns: NameSlice) {
        if let Some(first_ns) = self.state.first_table_name {
            let first_bytes = &self.name_bytes[first_ns.0.as_range()];
            let current_bytes = &self.name_bytes[table_ns.0.as_range()];
            if first_bytes != current_bytes {
                self.state.transactional = false;
            }
        } else {
            self.state.first_table_name = Some(table_ns);
        }
    }

    fn mark_pending_entry_name(&self, name: &str) -> crate::Result<()> {
        // Linear scan over current row's entries for duplicate detection
        let start = self.pending.entry_start as usize;
        for entry in &self.entries[start..] {
            let entry_name = self.name_str(entry.name);
            if entry_name == name {
                return Err(error::fmt!(
                    InvalidApiCall,
                    "column '{}' already set for current row",
                    name
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn table<'a, N>(&mut self, name: N) -> crate::Result<&mut Self>
    where
        N: TryInto<TableName<'a>>,
        Error: From<N::Error>,
    {
        let name: TableName<'a> = name.try_into()?;
        self.validate_max_name_len(name.as_ref())?;
        self.check_op(Op::Table)?;

        // Record rollback points
        self.pending = PendingRowState {
            table: None, // set below
            entry_start: self.entries.len() as u32,
            name_bytes_start: self.name_bytes.len() as u32,
            value_bytes_start: self.value_bytes.len() as u32,
        };

        let table_ns = self.append_name(name.as_ref());
        self.update_transactional_state(table_ns);
        self.pending.table = Some(table_ns);
        self.state.op_case = OpCase::TableWritten;
        Ok(self)
    }

    pub(crate) fn symbol<'a, N, S>(&mut self, name: N, value: S) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        S: AsRef<str>,
        Error: From<N::Error>,
    {
        let name: ColumnName<'a> = name.try_into()?;
        self.validate_max_name_len(name.as_ref())?;
        self.check_op(Op::Symbol)?;
        self.mark_pending_entry_name(name.as_ref())?;
        let name_ns = self.append_name(name.as_ref());
        let value_vs = self.append_value_str(value.as_ref());
        self.entries.push(EntryMeta {
            name: name_ns,
            value: ValueRef::Symbol(value_vs),
        });
        self.state.op_case = OpCase::SymbolWritten;
        Ok(self)
    }

    pub(crate) fn column_bool<'a, N>(&mut self, name: N, value: bool) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        let name: ColumnName<'a> = name.try_into()?;
        self.validate_max_name_len(name.as_ref())?;
        self.check_op(Op::Column)?;
        self.mark_pending_entry_name(name.as_ref())?;
        let name_ns = self.append_name(name.as_ref());
        self.entries.push(EntryMeta {
            name: name_ns,
            value: ValueRef::Bool(value),
        });
        self.state.op_case = OpCase::ColumnWritten;
        Ok(self)
    }

    pub(crate) fn column_i64<'a, N>(&mut self, name: N, value: i64) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        let name: ColumnName<'a> = name.try_into()?;
        self.validate_max_name_len(name.as_ref())?;
        self.check_op(Op::Column)?;
        self.mark_pending_entry_name(name.as_ref())?;
        let name_ns = self.append_name(name.as_ref());
        self.entries.push(EntryMeta {
            name: name_ns,
            value: ValueRef::I64(value),
        });
        self.state.op_case = OpCase::ColumnWritten;
        Ok(self)
    }

    pub(crate) fn column_f64<'a, N>(&mut self, name: N, value: f64) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        let name: ColumnName<'a> = name.try_into()?;
        self.validate_max_name_len(name.as_ref())?;
        self.check_op(Op::Column)?;
        self.mark_pending_entry_name(name.as_ref())?;
        let name_ns = self.append_name(name.as_ref());
        self.entries.push(EntryMeta {
            name: name_ns,
            value: ValueRef::F64(value),
        });
        self.state.op_case = OpCase::ColumnWritten;
        Ok(self)
    }

    pub(crate) fn column_str<'a, N, S>(&mut self, name: N, value: S) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        S: AsRef<str>,
        Error: From<N::Error>,
    {
        let name: ColumnName<'a> = name.try_into()?;
        self.validate_max_name_len(name.as_ref())?;
        self.check_op(Op::Column)?;
        self.mark_pending_entry_name(name.as_ref())?;
        let name_ns = self.append_name(name.as_ref());
        let value_vs = self.append_value_str(value.as_ref());
        self.entries.push(EntryMeta {
            name: name_ns,
            value: ValueRef::String(value_vs),
        });
        self.state.op_case = OpCase::ColumnWritten;
        Ok(self)
    }

    pub(crate) fn column_dec<'a, N, S>(&mut self, _name: N, _value: S) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        S: TryInto<DecimalView<'a>>,
        Error: From<N::Error>,
        Error: From<S::Error>,
    {
        Err(unsupported_qwp_call("column_dec"))
    }

    #[allow(private_bounds)]
    pub(crate) fn column_arr<'a, N, T, D>(
        &mut self,
        _name: N,
        _view: &T,
    ) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        T: NdArrayView<D>,
        D: ArrayElement,
        Error: From<N::Error>,
    {
        Err(unsupported_qwp_call("column_arr"))
    }

    pub(crate) fn column_ts<'a, N, T>(&mut self, name: N, value: T) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        T: TryInto<Timestamp>,
        Error: From<N::Error>,
        Error: From<T::Error>,
    {
        let name: ColumnName<'a> = name.try_into()?;
        self.validate_max_name_len(name.as_ref())?;
        self.check_op(Op::Column)?;
        self.mark_pending_entry_name(name.as_ref())?;
        let ts: Timestamp = value.try_into()?;
        let name_ns = self.append_name(name.as_ref());
        let value_ref = match ts {
            Timestamp::Micros(v) => ValueRef::TimestampMicros(v.as_i64()),
            Timestamp::Nanos(v) => ValueRef::TimestampNanos(v.as_i64()),
        };
        self.entries.push(EntryMeta {
            name: name_ns,
            value: value_ref,
        });
        self.state.op_case = OpCase::ColumnWritten;
        Ok(self)
    }

    pub(crate) fn at<T>(&mut self, timestamp: T) -> crate::Result<()>
    where
        T: TryInto<Timestamp>,
        Error: From<T::Error>,
    {
        self.check_op(Op::At)?;
        self.commit_current_row(Some(to_designated_ts(timestamp.try_into()?)))
    }

    pub(crate) fn at_now(&mut self) -> crate::Result<()> {
        self.check_op(Op::At)?;
        self.commit_current_row(None)
    }

    fn commit_current_row(&mut self, designated_ts: Option<DesignatedTs>) -> crate::Result<()> {
        let table_ns = match self.pending.table {
            Some(ns) => ns,
            None => {
                return Err(error::fmt!(
                    InvalidApiCall,
                    "table() must be called before adding columns"
                ));
            }
        };

        let entry_start = self.pending.entry_start;
        let entry_count = self.entries.len() as u32 - entry_start;

        if entry_count == 0 {
            self.rollback_pending();
            return Err(error::fmt!(InvalidApiCall, "no columns were provided"));
        }

        let row = RowMeta {
            table: table_ns,
            entry_start,
            entry_count,
            designated_ts,
        };

        let last_seg_table = self.segments.last().map(|s| s.table);
        let same_table = if let Some(last_table) = last_seg_table {
            self.name_bytes[last_table.0.as_range()] == self.name_bytes[table_ns.0.as_range()]
        } else {
            false
        };

        // Update size hint before segments (fallible, must not leave partial state)
        self.size_hint.add_committed_row(
            &row,
            &self.entries,
            &self.name_bytes,
            &self.value_bytes,
            last_seg_table,
        )?;

        // Update segments (infallible)
        if same_table {
            self.segments.last_mut().unwrap().row_count += 1;
        } else {
            self.segments.push(SegmentMeta {
                table: table_ns,
                row_start: self.rows.len() as u32,
                row_count: 1,
            });
        }

        self.rows.push(row);
        self.state.row_count += 1;
        self.state.op_case = OpCase::MayFlushOrTable;
        self.pending.table = None;
        Ok(())
    }

    fn pending_size_hint(&self) -> usize {
        if self.pending.table.is_none() {
            return 0;
        }
        let table_ns = self.pending.table.unwrap();
        let mut size = table_ns.0.len as usize;
        for entry in &self.entries[self.pending.entry_start as usize..] {
            size += entry.name.0.len as usize;
            size += match &entry.value {
                ValueRef::Bool(_) => 1,
                ValueRef::Symbol(vs) => vs.0.len as usize + 3,
                ValueRef::I64(_) | ValueRef::F64(_) => 8,
                ValueRef::String(vs) => vs.0.len as usize + 9,
                ValueRef::TimestampMicros(_) | ValueRef::TimestampNanos(_) => 9,
            };
        }
        size + 1
    }

    fn rows_for_segment(&self, segment: &SegmentMeta) -> &[RowMeta] {
        let start = segment.row_start as usize;
        let end = start + segment.row_count as usize;
        &self.rows[start..end]
    }

    fn entries_for_row(&self, row: &RowMeta) -> &[EntryMeta] {
        let start = row.entry_start as usize;
        let end = start + row.entry_count as usize;
        &self.entries[start..end]
    }

    /// Encode datagrams for the current buffer contents.
    /// Test-only helper that collects datagrams into a Vec.
    #[cfg(test)]
    fn encode_datagrams(&self, max_datagram_size: usize) -> crate::Result<Vec<Vec<u8>>> {
        if self.pending.table.is_some() {
            return Err(error::fmt!(
                InvalidApiCall,
                "Cannot flush with an incomplete row. \
                 Call `at` or `at_now` to complete the pending row."
            ));
        }
        let mut datagrams = Vec::new();
        let mut planner = RowGroupPlanner::new();
        let mut datagram_buf = Vec::new();

        for segment in &self.segments {
            let rows = self.rows_for_segment(segment);
            let table_name = &self.name_bytes[segment.table.0.as_range()];

            planner.clear();

            for row in rows {
                let row_entries = self.entries_for_row(row);

                let cp = planner.checkpoint();
                planner.add_row(
                    row,
                    row_entries,
                    &self.name_bytes,
                    &self.value_bytes,
                    table_name.len(),
                )?;

                if cp.row_count > 0 && planner.current_len > max_datagram_size {
                    planner.rollback(cp);

                    encode_row_group_from_scratch(
                        &planner,
                        &self.name_bytes,
                        &self.value_bytes,
                        table_name,
                        &mut datagram_buf,
                    )?;
                    datagrams.push(datagram_buf.clone());
                    datagram_buf.clear();

                    planner.clear();

                    planner.add_row(
                        row,
                        row_entries,
                        &self.name_bytes,
                        &self.value_bytes,
                        table_name.len(),
                    )?;
                    if planner.current_len > max_datagram_size {
                        return Err(error::fmt!(
                            InvalidApiCall,
                            "single row exceeds maximum datagram size ({} bytes), estimated {} bytes",
                            max_datagram_size,
                            planner.current_len
                        ));
                    }
                } else if planner.current_len > max_datagram_size {
                    return Err(error::fmt!(
                        InvalidApiCall,
                        "single row exceeds maximum datagram size ({} bytes), estimated {} bytes",
                        max_datagram_size,
                        planner.current_len
                    ));
                }
            }

            if planner.row_count() > 0 {
                encode_row_group_from_scratch(
                    &planner,
                    &self.name_bytes,
                    &self.value_bytes,
                    table_name,
                    &mut datagram_buf,
                )?;
                datagrams.push(datagram_buf.clone());
                datagram_buf.clear();
            }
        }

        Ok(datagrams)
    }

    /// Streaming flush: encode and send datagrams directly to the socket.
    /// Uses sender-owned scratch to avoid allocations.
    pub(crate) fn flush_to_socket(
        &self,
        scratch: &mut QwpSendScratch,
        max_datagram_size: usize,
        send: &mut dyn FnMut(&[u8]) -> crate::Result<()>,
    ) -> crate::Result<()> {
        if self.pending.table.is_some() {
            return Err(error::fmt!(
                InvalidApiCall,
                "Cannot flush with an incomplete row. \
                 Call `at` or `at_now` to complete the pending row."
            ));
        }
        for segment in &self.segments {
            let rows = self.rows_for_segment(segment);
            let table_name = &self.name_bytes[segment.table.0.as_range()];

            scratch.planner.clear();

            for row in rows {
                let row_entries = self.entries_for_row(row);

                let cp = scratch.planner.checkpoint();
                scratch.planner.add_row(
                    row,
                    row_entries,
                    &self.name_bytes,
                    &self.value_bytes,
                    table_name.len(),
                )?;

                if cp.row_count > 0 && scratch.planner.current_len > max_datagram_size {
                    scratch.planner.rollback(cp);

                    scratch.datagram.clear();
                    encode_row_group_from_scratch(
                        &scratch.planner,
                        &self.name_bytes,
                        &self.value_bytes,
                        table_name,
                        &mut scratch.datagram,
                    )?;
                    send(&scratch.datagram)?;

                    scratch.planner.clear();

                    scratch.planner.add_row(
                        row,
                        row_entries,
                        &self.name_bytes,
                        &self.value_bytes,
                        table_name.len(),
                    )?;
                    if scratch.planner.current_len > max_datagram_size {
                        return Err(error::fmt!(
                            InvalidApiCall,
                            "single row exceeds maximum datagram size ({} bytes), estimated {} bytes",
                            max_datagram_size,
                            scratch.planner.current_len
                        ));
                    }
                } else if scratch.planner.current_len > max_datagram_size {
                    return Err(error::fmt!(
                        InvalidApiCall,
                        "single row exceeds maximum datagram size ({} bytes), estimated {} bytes",
                        max_datagram_size,
                        scratch.planner.current_len
                    ));
                }
            }

            if scratch.planner.row_count() > 0 {
                scratch.datagram.clear();
                encode_row_group_from_scratch(
                    &scratch.planner,
                    &self.name_bytes,
                    &self.value_bytes,
                    table_name,
                    &mut scratch.datagram,
                )?;
                send(&scratch.datagram)?;
            }
        }
        Ok(())
    }
}

// --- Sender scratch ---

pub(crate) struct QwpSendScratch {
    pub(crate) planner: RowGroupPlanner,
    pub(crate) datagram: Vec<u8>,
}

impl QwpSendScratch {
    pub(crate) fn new(max_datagram_size: usize) -> Self {
        Self {
            planner: RowGroupPlanner::new(),
            datagram: Vec::with_capacity(max_datagram_size),
        }
    }
}

/// Synthetic designated-timestamp entry used when iterating row specs.
/// The empty column name is represented as a zero-length NameSlice.
const DESIGNATED_TS_NAME: NameSlice = NameSlice(ByteSlice { offset: 0, len: 0 });

fn designated_ts_entry(ts: DesignatedTs) -> EntryMeta {
    EntryMeta {
        name: DESIGNATED_TS_NAME,
        value: match ts {
            DesignatedTs::Micros(v) => ValueRef::TimestampMicros(v),
            DesignatedTs::Nanos(v) => ValueRef::TimestampNanos(v),
        },
    }
}

// --- Symbol dictionary entry (flat arena, linked per column) ---

#[derive(Clone, Copy, Debug)]
struct SymbolEntry {
    value: ValueSlice,
    next: u32,
}

// --- Column stats (all scalar, no nested Vecs) ---

#[derive(Clone, Copy, Debug)]
struct ColumnStats {
    name: NameSlice,
    non_null_count: u32,
    string_data_len: u32,
    symbol_dict_bytes: u32,
    symbol_row_index_bytes: u32,
    dict_head: u32,
    dict_tail: u32,
    cell_head: u32,
    cell_tail: u32,
    dict_count: u16,
    cached_schema_len: u16,
    kind: ColumnKind,
    base_nullable: bool,
}

impl ColumnStats {
    fn new(entry: &EntryMeta) -> Self {
        let kind = entry.value.kind();
        let name_len = entry.name.0.len as usize;
        let cached_schema_len = (qwp_varint_size(name_len as u64) + name_len + 1) as u16;
        Self {
            name: entry.name,
            non_null_count: 0,
            string_data_len: 0,
            symbol_dict_bytes: 0,
            symbol_row_index_bytes: 0,
            dict_head: CELL_END,
            dict_tail: CELL_END,
            cell_head: CELL_END,
            cell_tail: CELL_END,
            dict_count: 0,
            cached_schema_len,
            kind,
            base_nullable: matches!(
                kind,
                ColumnKind::Symbol
                    | ColumnKind::String
                    | ColumnKind::TimestampMicros
                    | ColumnKind::TimestampNanos
            ),
        }
    }

    fn payload_len(&self, row_count: usize) -> usize {
        let nullable = self.is_nullable(row_count);
        let bitmap = if nullable { bitmap_bytes(row_count) } else { 0 };

        bitmap
            + match self.kind {
                ColumnKind::Bool => packed_bytes(row_count),
                ColumnKind::I64 | ColumnKind::F64 => {
                    if nullable {
                        self.non_null_count as usize * 8
                    } else {
                        row_count * 8
                    }
                }
                ColumnKind::TimestampMicros | ColumnKind::TimestampNanos => {
                    self.non_null_count as usize * 8
                }
                ColumnKind::String => {
                    4 * (self.non_null_count as usize + 1) + self.string_data_len as usize
                }
                ColumnKind::Symbol => {
                    qwp_varint_size(self.dict_count as u64)
                        + self.symbol_dict_bytes as usize
                        + self.symbol_row_index_bytes as usize
                }
            }
    }

    fn add_non_symbol_value(&mut self, value: &ValueRef) -> crate::Result<()> {
        match self.kind {
            ColumnKind::Bool => match value {
                ValueRef::Bool(_) => {
                    self.non_null_count += 1;
                    Ok(())
                }
                _ => Err(error::fmt!(
                    InvalidApiCall,
                    "internal QWP type mismatch for boolean column"
                )),
            },
            ColumnKind::I64 => match value {
                ValueRef::I64(_) => {
                    self.non_null_count += 1;
                    Ok(())
                }
                _ => Err(error::fmt!(
                    InvalidApiCall,
                    "internal QWP type mismatch for long column"
                )),
            },
            ColumnKind::F64 => match value {
                ValueRef::F64(_) => {
                    self.non_null_count += 1;
                    Ok(())
                }
                _ => Err(error::fmt!(
                    InvalidApiCall,
                    "internal QWP type mismatch for double column"
                )),
            },
            ColumnKind::TimestampMicros | ColumnKind::TimestampNanos => match value {
                ValueRef::TimestampMicros(_) | ValueRef::TimestampNanos(_) => {
                    self.non_null_count += 1;
                    Ok(())
                }
                _ => Err(error::fmt!(
                    InvalidApiCall,
                    "internal QWP type mismatch for timestamp column"
                )),
            },
            ColumnKind::String => match value {
                ValueRef::String(vs) => {
                    self.non_null_count += 1;
                    self.string_data_len += vs.0.len;
                    Ok(())
                }
                _ => Err(error::fmt!(
                    InvalidApiCall,
                    "internal QWP type mismatch for string column"
                )),
            },
            ColumnKind::Symbol => {
                // Symbol accounting handled by RowGroupPlanner
                Ok(())
            }
        }
    }

    fn is_nullable(&self, row_count: usize) -> bool {
        self.base_nullable
            || (kind_supports_sparse_nulls(self.kind) && (self.non_null_count as usize) < row_count)
    }
}

// --- Checkpoint types ---

#[derive(Clone, Debug)]
struct ColumnUndo {
    non_null_count: u32,
    string_data_len: u32,
    symbol_dict_bytes: u32,
    symbol_row_index_bytes: u32,
    dict_tail: u32,
    cell_tail: u32,
    col_idx: u16,
    dict_count: u16,
}

#[derive(Clone, Copy, Debug)]
struct Checkpoint {
    columns_len: usize,
    cells_len: usize,
    symbol_dict_len: usize,
    row_count: usize,
    current_len: usize,
    total_schema_len: usize,
}

// --- Row group planner (unified estimator + flush scratch) ---

pub(crate) struct RowGroupPlanner {
    columns: Vec<ColumnStats>,
    cells: Vec<CellRef>,
    symbol_dict: Vec<SymbolEntry>,
    undo_stack: Vec<ColumnUndo>,
    row_count: usize,
    current_len: usize,
    total_schema_len: usize,
    track_cells: bool,
}

impl Clone for RowGroupPlanner {
    fn clone(&self) -> Self {
        Self {
            columns: self.columns.clone(),
            cells: self.cells.clone(),
            symbol_dict: self.symbol_dict.clone(),
            undo_stack: Vec::new(),
            row_count: self.row_count,
            current_len: self.current_len,
            total_schema_len: self.total_schema_len,
            track_cells: self.track_cells,
        }
    }
}

impl std::fmt::Debug for RowGroupPlanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RowGroupPlanner")
            .field("columns", &self.columns)
            .field("cells_len", &self.cells.len())
            .field("row_count", &self.row_count)
            .field("current_len", &self.current_len)
            .finish()
    }
}

impl RowGroupPlanner {
    fn new() -> Self {
        Self {
            columns: Vec::new(),
            cells: Vec::new(),
            symbol_dict: Vec::new(),
            undo_stack: Vec::new(),
            row_count: 0,
            current_len: 0,
            total_schema_len: 0,
            track_cells: true,
        }
    }

    fn new_stats_only() -> Self {
        Self {
            columns: Vec::new(),
            cells: Vec::new(),
            symbol_dict: Vec::new(),
            undo_stack: Vec::new(),
            row_count: 0,
            current_len: 0,
            total_schema_len: 0,
            track_cells: false,
        }
    }

    fn clear(&mut self) {
        self.columns.clear();
        self.cells.clear();
        self.symbol_dict.clear();
        self.undo_stack.clear();
        self.row_count = 0;
        self.current_len = 0;
        self.total_schema_len = 0;
    }

    fn row_count(&self) -> usize {
        self.row_count
    }

    fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            columns_len: self.columns.len(),
            cells_len: self.cells.len(),
            symbol_dict_len: self.symbol_dict.len(),
            row_count: self.row_count,
            current_len: self.current_len,
            total_schema_len: self.total_schema_len,
        }
    }

    fn rollback(&mut self, cp: Checkpoint) {
        for undo in self.undo_stack.drain(..).rev() {
            let col = &mut self.columns[undo.col_idx as usize];
            col.non_null_count = undo.non_null_count;
            col.string_data_len = undo.string_data_len;
            col.symbol_dict_bytes = undo.symbol_dict_bytes;
            col.symbol_row_index_bytes = undo.symbol_row_index_bytes;
            col.dict_tail = undo.dict_tail;
            col.dict_count = undo.dict_count;
            if col.dict_tail != CELL_END {
                self.symbol_dict[col.dict_tail as usize].next = CELL_END;
            } else {
                col.dict_head = CELL_END;
            }
            col.cell_tail = undo.cell_tail;
            if self.track_cells && col.cell_tail != CELL_END {
                self.cells[col.cell_tail as usize].next = CELL_END;
            } else {
                col.cell_head = CELL_END;
            }
        }
        self.columns.truncate(cp.columns_len);
        self.cells.truncate(cp.cells_len);
        self.symbol_dict.truncate(cp.symbol_dict_len);
        self.row_count = cp.row_count;
        self.current_len = cp.current_len;
        self.total_schema_len = cp.total_schema_len;
    }

    fn add_row(
        &mut self,
        row: &RowMeta,
        row_entries: &[EntryMeta],
        name_bytes: &[u8],
        value_bytes: &[u8],
        table_name_len: usize,
    ) -> crate::Result<()> {
        if self.track_cells && self.row_count >= u16::MAX as usize {
            return Err(error::fmt!(
                InvalidApiCall,
                "QWP/UDP row group exceeds maximum of {} rows",
                u16::MAX
            ));
        }
        self.undo_stack.clear();
        let ts_entry = row.designated_ts.map(designated_ts_entry);
        let extra = ts_entry.as_slice();
        let row_idx = self.row_count as u16;

        for entry in row_entries.iter().chain(extra.iter()) {
            let entry_name = &name_bytes[entry.name.0.as_range()];
            if let Some(idx) = self.find_column(entry_name, name_bytes) {
                let col = &mut self.columns[idx];
                if col.kind != entry.value.kind() {
                    return Err(error::fmt!(
                        InvalidApiCall,
                        "QWP/UDP column {:?} changes type within a batched table",
                        std::str::from_utf8(entry_name).unwrap_or("<invalid>")
                    ));
                }
                self.undo_stack.push(ColumnUndo {
                    non_null_count: col.non_null_count,
                    string_data_len: col.string_data_len,
                    symbol_dict_bytes: col.symbol_dict_bytes,
                    symbol_row_index_bytes: col.symbol_row_index_bytes,
                    dict_tail: col.dict_tail,
                    cell_tail: col.cell_tail,
                    col_idx: idx as u16,
                    dict_count: col.dict_count,
                });
                if self.track_cells {
                    let cell_idx = self.cells.len() as u32;
                    self.cells.push(CellRef {
                        row_idx,
                        symbol_dict_idx: 0,
                        next: CELL_END,
                        value: entry.value,
                    });
                    if col.cell_tail != CELL_END {
                        self.cells[col.cell_tail as usize].next = cell_idx;
                    } else {
                        col.cell_head = cell_idx;
                    }
                    col.cell_tail = cell_idx;
                }
                if col.kind == ColumnKind::Symbol {
                    self.add_symbol_value(idx, &entry.value, value_bytes);
                } else {
                    col.add_non_symbol_value(&entry.value)?;
                }
            } else {
                self.push_new_column(entry, value_bytes, row_idx)?;
            }
        }

        self.row_count += 1;
        self.recompute_len(table_name_len);
        Ok(())
    }

    fn add_symbol_value(&mut self, col_idx: usize, value: &ValueRef, value_bytes: &[u8]) {
        let ValueRef::Symbol(vs) = value else { return };
        let col = &mut self.columns[col_idx];
        col.non_null_count += 1;
        let symbol_bytes = &value_bytes[vs.0.as_range()];
        let mut cursor = col.dict_head;
        let mut pos = 0usize;
        let mut found_idx = None;
        while cursor != CELL_END {
            let de = &self.symbol_dict[cursor as usize];
            if &value_bytes[de.value.0.as_range()] == symbol_bytes {
                found_idx = Some(pos);
                break;
            }
            cursor = de.next;
            pos += 1;
        }
        let sym_idx = if let Some(idx) = found_idx {
            idx
        } else {
            let idx = col.dict_count as usize;
            col.symbol_dict_bytes += qwp_string_byte_len(symbol_bytes.len()) as u32;
            let dict_idx = self.symbol_dict.len() as u32;
            self.symbol_dict.push(SymbolEntry {
                value: *vs,
                next: CELL_END,
            });
            if col.dict_tail != CELL_END {
                self.symbol_dict[col.dict_tail as usize].next = dict_idx;
            } else {
                col.dict_head = dict_idx;
            }
            col.dict_tail = dict_idx;
            col.dict_count += 1;
            idx
        };
        col.symbol_row_index_bytes += qwp_varint_size(sym_idx as u64) as u32;
        if self.track_cells {
            // Store pre-computed index so encoding is O(1) per cell
            self.cells.last_mut().unwrap().symbol_dict_idx = sym_idx as u16;
        }
    }

    fn recompute_len(&mut self, table_name_len: usize) {
        let mut total = base_datagram_len(table_name_len, self.row_count, self.columns.len());
        total += self.total_schema_len;
        for col in &self.columns {
            total += col.payload_len(self.row_count);
        }
        self.current_len = total;
    }

    fn push_new_column(
        &mut self,
        entry: &EntryMeta,
        value_bytes: &[u8],
        row_idx: u16,
    ) -> crate::Result<()> {
        let col = ColumnStats::new(entry);
        self.total_schema_len += col.cached_schema_len as usize;
        self.columns.push(col);
        let col_idx = self.columns.len() - 1;

        if self.track_cells {
            let cell_idx = self.cells.len() as u32;
            self.cells.push(CellRef {
                row_idx,
                symbol_dict_idx: 0,
                next: CELL_END,
                value: entry.value,
            });
            let col = &mut self.columns[col_idx];
            col.cell_head = cell_idx;
            col.cell_tail = cell_idx;
        }

        if entry.value.kind() == ColumnKind::Symbol {
            self.add_symbol_value(col_idx, &entry.value, value_bytes);
        } else {
            self.columns[col_idx].add_non_symbol_value(&entry.value)?;
        }
        Ok(())
    }

    fn find_column(&self, name: &[u8], name_bytes: &[u8]) -> Option<usize> {
        self.columns
            .iter()
            .position(|c| &name_bytes[c.name.0.as_range()] == name)
    }
}

// --- Encoding functions ---

fn base_datagram_len(table_name_len: usize, row_count: usize, column_count: usize) -> usize {
    QWP_MESSAGE_HEADER_SIZE
        + qwp_string_byte_len(table_name_len)
        + qwp_varint_size(row_count as u64)
        + qwp_varint_size(column_count as u64)
        + 1
}

fn qwp_string_byte_len(byte_len: usize) -> usize {
    qwp_varint_size(byte_len as u64) + byte_len
}

fn qwp_varint_size(mut value: u64) -> usize {
    let mut size = 1usize;
    while value > 0x7F {
        value >>= 7;
        size += 1;
    }
    size
}

fn packed_bytes(value_count: usize) -> usize {
    value_count.div_ceil(8)
}

fn bitmap_bytes(value_count: usize) -> usize {
    value_count.div_ceil(8)
}

fn kind_supports_sparse_nulls(kind: ColumnKind) -> bool {
    matches!(
        kind,
        ColumnKind::Symbol
            | ColumnKind::String
            | ColumnKind::TimestampMicros
            | ColumnKind::TimestampNanos
    )
}

fn standalone_row_group_len(
    row: &RowMeta,
    row_entries: &[EntryMeta],
    name_bytes: &[u8],
    value_bytes: &[u8],
) -> usize {
    let table_name = &name_bytes[row.table.0.as_range()];
    let mut planner = RowGroupPlanner::new_stats_only();
    match planner.add_row(row, row_entries, name_bytes, value_bytes, table_name.len()) {
        Ok(()) => planner.current_len,
        Err(_) => 0,
    }
}

fn is_batched_type_change_error(err: &Error) -> bool {
    err.code() == ErrorCode::InvalidApiCall
        && err.msg().contains("changes type within a batched table")
}

fn write_qwp_varint(out: &mut Vec<u8>, mut value: u64) {
    while value > 0x7F {
        out.push(((value & 0x7F) as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn write_qwp_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    write_qwp_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn wire_type_byte(kind: ColumnKind, nullable: bool) -> u8 {
    let ty = match kind {
        ColumnKind::Bool => QWP_TYPE_BOOLEAN,
        ColumnKind::Symbol => QWP_TYPE_SYMBOL,
        ColumnKind::I64 => QWP_TYPE_LONG,
        ColumnKind::F64 => QWP_TYPE_DOUBLE,
        ColumnKind::String => QWP_TYPE_STRING,
        ColumnKind::TimestampMicros => QWP_TYPE_TIMESTAMP,
        ColumnKind::TimestampNanos => QWP_TYPE_TIMESTAMP_NANOS,
    };
    if nullable {
        ty | QWP_TYPE_NULLABLE_FLAG
    } else {
        ty
    }
}

/// Encode a row group directly from the planner's pre-indexed cells.
/// No intermediate dense matrices or entry scanning - writes directly to `out`.
fn encode_row_group_from_scratch(
    planner: &RowGroupPlanner,
    name_bytes: &[u8],
    value_bytes: &[u8],
    table_name: &[u8],
    out: &mut Vec<u8>,
) -> crate::Result<()> {
    let row_count = planner.row_count;

    // Write header placeholder
    let header_start = out.len();
    out.extend_from_slice(&[0u8; QWP_MESSAGE_HEADER_SIZE]);
    let payload_start = out.len();

    // Payload: table name, row count, column count, schema mode
    write_qwp_bytes(out, table_name);
    write_qwp_varint(out, row_count as u64);
    write_qwp_varint(out, planner.columns.len() as u64);
    out.push(QWP_SCHEMA_MODE_FULL);

    // Schema
    for col in &planner.columns {
        write_qwp_bytes(out, &name_bytes[col.name.0.as_range()]);
        out.push(wire_type_byte(col.kind, col.is_nullable(row_count)));
    }

    // Column payloads
    for col in &planner.columns {
        encode_column_from_cells(
            col,
            row_count,
            &planner.cells,
            &planner.symbol_dict,
            value_bytes,
            out,
        )?;
    }

    // Fill header
    let header = QwpMessageHeader {
        magic: *b"QWP1",
        version: QWP_VERSION_1,
        flags: 0,
        table_count: 1,
        payload_len: (out.len() - payload_start) as u32,
    };
    header.write_to(&mut out[header_start..header_start + QWP_MESSAGE_HEADER_SIZE]);

    Ok(())
}

// --- Cell iteration helpers ---

/// Iterates non-null cells for a column via linked list.
struct CellIter<'a> {
    cells: &'a [CellRef],
    cursor: u32,
}

impl<'a> CellIter<'a> {
    fn new(cells: &'a [CellRef], head: u32) -> Self {
        Self {
            cells,
            cursor: head,
        }
    }
}

impl<'a> Iterator for CellIter<'a> {
    type Item = &'a CellRef;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor == CELL_END {
            return None;
        }
        let cell = &self.cells[self.cursor as usize];
        self.cursor = cell.next;
        Some(cell)
    }
}

/// Iterates all rows 0..row_count, yielding `Some(&CellRef)` for non-null
/// rows and `None` for gaps. Used for null bitmaps and non-nullable gap-filling.
struct GapFillIter<'a> {
    cells: &'a [CellRef],
    cursor: u32,
    next_non_null: u16,
    row: u16,
    row_count: u16,
}

impl<'a> GapFillIter<'a> {
    fn new(cells: &'a [CellRef], head: u32, row_count: usize) -> Self {
        let next_non_null = if head != CELL_END {
            cells[head as usize].row_idx
        } else {
            u16::MAX
        };
        Self {
            cells,
            cursor: head,
            next_non_null,
            row: 0,
            row_count: row_count as u16,
        }
    }
}

impl<'a> Iterator for GapFillIter<'a> {
    type Item = Option<&'a CellRef>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.row >= self.row_count {
            return None;
        }
        let result = if self.row == self.next_non_null {
            let cell = &self.cells[self.cursor as usize];
            self.cursor = cell.next;
            self.next_non_null = if self.cursor != CELL_END {
                self.cells[self.cursor as usize].row_idx
            } else {
                u16::MAX
            };
            Some(cell)
        } else {
            None
        };
        self.row += 1;
        Some(result)
    }
}

/// Encode a single column's payload by following the pre-indexed cell linked list.
/// O(cells_for_column) instead of O(rows * entries_per_row) name comparisons.
fn encode_column_from_cells(
    col: &ColumnStats,
    row_count: usize,
    cells: &[CellRef],
    symbol_dict: &[SymbolEntry],
    value_bytes: &[u8],
    out: &mut Vec<u8>,
) -> crate::Result<()> {
    let nullable = col.is_nullable(row_count);

    // Null bitmap
    if nullable {
        let mut packed = 0u8;
        let mut bit_idx = 0u8;
        for maybe_cell in GapFillIter::new(cells, col.cell_head, row_count) {
            if maybe_cell.is_none() {
                packed |= 1 << bit_idx;
            }
            bit_idx += 1;
            if bit_idx == 8 {
                out.push(packed);
                packed = 0;
                bit_idx = 0;
            }
        }
        if bit_idx != 0 {
            out.push(packed);
        }
    }

    match col.kind {
        ColumnKind::Bool => {
            let mut packed = 0u8;
            let mut bit_idx = 0u8;
            if nullable {
                for cell in CellIter::new(cells, col.cell_head) {
                    if matches!(cell.value, ValueRef::Bool(true)) {
                        packed |= 1 << bit_idx;
                    }
                    bit_idx += 1;
                    if bit_idx == 8 {
                        out.push(packed);
                        packed = 0;
                        bit_idx = 0;
                    }
                }
            } else {
                for maybe_cell in GapFillIter::new(cells, col.cell_head, row_count) {
                    if maybe_cell.is_some_and(|c| matches!(c.value, ValueRef::Bool(true))) {
                        packed |= 1 << bit_idx;
                    }
                    bit_idx += 1;
                    if bit_idx == 8 {
                        out.push(packed);
                        packed = 0;
                        bit_idx = 0;
                    }
                }
            }
            if bit_idx != 0 {
                out.push(packed);
            }
        }

        ColumnKind::I64 => {
            if nullable {
                for cell in CellIter::new(cells, col.cell_head) {
                    if let ValueRef::I64(v) = cell.value {
                        out.extend_from_slice(&v.to_le_bytes());
                    }
                }
            } else {
                for maybe_cell in GapFillIter::new(cells, col.cell_head, row_count) {
                    let v = match maybe_cell.map(|c| c.value) {
                        Some(ValueRef::I64(v)) => v,
                        _ => i64::MIN,
                    };
                    out.extend_from_slice(&v.to_le_bytes());
                }
            }
        }

        ColumnKind::F64 => {
            if nullable {
                for cell in CellIter::new(cells, col.cell_head) {
                    if let ValueRef::F64(v) = cell.value {
                        out.extend_from_slice(&v.to_le_bytes());
                    }
                }
            } else {
                for maybe_cell in GapFillIter::new(cells, col.cell_head, row_count) {
                    let v = match maybe_cell.map(|c| c.value) {
                        Some(ValueRef::F64(v)) => v,
                        _ => f64::NAN,
                    };
                    out.extend_from_slice(&v.to_le_bytes());
                }
            }
        }

        ColumnKind::TimestampMicros | ColumnKind::TimestampNanos => {
            for cell in CellIter::new(cells, col.cell_head) {
                if let ValueRef::TimestampMicros(v) | ValueRef::TimestampNanos(v) = cell.value {
                    out.extend_from_slice(&v.to_le_bytes());
                }
            }
        }

        ColumnKind::String => {
            let non_null_count = col.non_null_count as usize;
            let offsets_start = out.len();
            out.resize(out.len() + (non_null_count + 1) * 4, 0);
            out[offsets_start..offsets_start + 4].copy_from_slice(&0i32.to_le_bytes());

            let mut cumulative: i32 = 0;
            let mut offset_idx = 1usize;
            for cell in CellIter::new(cells, col.cell_head) {
                if let ValueRef::String(vs) = cell.value {
                    let text = &value_bytes[vs.0.as_range()];
                    out.extend_from_slice(text);
                    cumulative += text.len() as i32;
                    let pos = offsets_start + offset_idx * 4;
                    out[pos..pos + 4].copy_from_slice(&cumulative.to_le_bytes());
                    offset_idx += 1;
                }
            }
        }

        ColumnKind::Symbol => {
            // Dictionary via linked list
            write_qwp_varint(out, col.dict_count as u64);
            let mut dict_cursor = col.dict_head;
            while dict_cursor != CELL_END {
                let de = &symbol_dict[dict_cursor as usize];
                write_qwp_bytes(out, &value_bytes[de.value.0.as_range()]);
                dict_cursor = de.next;
            }
            // Row indexes from pre-computed cell indexes (O(1) per cell)
            for cell in CellIter::new(cells, col.cell_head) {
                write_qwp_varint(out, cell.symbol_dict_idx as u64);
            }
        }
    }

    Ok(())
}

fn unsupported_qwp_call(method: &str) -> crate::Error {
    error::fmt!(
        InvalidApiCall,
        "QWP/UDP support for `{}` is not implemented yet.",
        method
    )
}

fn to_designated_ts(timestamp: Timestamp) -> DesignatedTs {
    match timestamp {
        Timestamp::Micros(ts) => DesignatedTs::Micros(ts.as_i64()),
        Timestamp::Nanos(ts) => DesignatedTs::Nanos(ts.as_i64()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingress::{TimestampMicros, TimestampNanos};

    #[test]
    fn qwp_struct_sizes() {
        use std::mem::size_of;
        assert_eq!(size_of::<ValueRef>(), 16);
        assert_eq!(size_of::<CellRef>(), 24);
        assert_eq!(size_of::<EntryMeta>(), 24);
        assert_eq!(size_of::<RowMeta>(), 32);
        assert_eq!(size_of::<ColumnStats>(), 48);
        assert_eq!(size_of::<ColumnUndo>(), 28);
        assert_eq!(size_of::<Option<DesignatedTs>>(), size_of::<DesignatedTs>());
    }

    #[test]
    fn qwp_single_row_with_designated_timestamp_encodes_header() {
        let mut buf = QwpBuffer::new(127);
        buf.table("trades")
            .unwrap()
            .symbol("sym", "ETH-USD")
            .unwrap()
            .column_i64("qty", 4)
            .unwrap();
        buf.at(TimestampNanos::new(42)).unwrap();

        let datagrams = buf.encode_datagrams(1400).unwrap();
        assert_eq!(datagrams.len(), 1);
        let datagram = &datagrams[0];
        assert_eq!(&datagram[0..4], b"QWP1");
        assert_eq!(datagram[4], QWP_VERSION_1);
        assert_eq!(u16::from_le_bytes([datagram[6], datagram[7]]), 1);
        assert_eq!(
            u32::from_le_bytes([datagram[8], datagram[9], datagram[10], datagram[11]]) as usize,
            datagram.len() - QWP_MESSAGE_HEADER_SIZE
        );
    }

    #[test]
    fn qwp_single_row_without_designated_timestamp_omits_empty_column() {
        let mut buf = QwpBuffer::new(127);
        buf.table("trades")
            .unwrap()
            .symbol("sym", "ETH-USD")
            .unwrap()
            .column_f64("px", 42.5)
            .unwrap();
        buf.at_now().unwrap();

        let datagram = buf.encode_datagrams(1400).unwrap().pop().unwrap();
        assert!(!datagram.windows(2).any(|w| w == [0, QWP_TYPE_TIMESTAMP]));
        assert!(
            !datagram
                .windows(2)
                .any(|w| w == [0, QWP_TYPE_TIMESTAMP_NANOS])
        );
    }

    #[test]
    fn qwp_state_machine_matches_ilp_shape() {
        let mut buf = QwpBuffer::new(127);
        let err = buf.at_now().unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("Bad call to `at`"));

        buf.table("trades").unwrap();
        let err = buf.at(TimestampMicros::new(1)).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert!(
            err.msg()
                .contains("should have called `symbol` or `column` instead")
        );
    }

    #[test]
    fn qwp_estimator_matches_actual_for_supported_prefixes() {
        let mut buf = QwpBuffer::new(127);

        buf.table("audit")
            .unwrap()
            .symbol("sym", "stable")
            .unwrap()
            .column_bool("active", true)
            .unwrap()
            .column_i64("qty", 1)
            .unwrap()
            .column_f64("px", 11.5)
            .unwrap()
            .column_str("venue", "tokyo-1")
            .unwrap()
            .column_ts("event_ts", TimestampMicros::new(100))
            .unwrap()
            .at(TimestampMicros::new(1000))
            .unwrap();

        buf.table("audit")
            .unwrap()
            .symbol("sym", "stable")
            .unwrap()
            .column_bool("active", false)
            .unwrap()
            .column_f64("px", 12.5)
            .unwrap()
            .at_now()
            .unwrap();

        buf.table("audit")
            .unwrap()
            .symbol("sym", "tokyo-3")
            .unwrap()
            .column_i64("qty", 3)
            .unwrap()
            .column_str("venue", "tokyo-3-xxxxxxxx")
            .unwrap()
            .at(TimestampMicros::new(3000))
            .unwrap();

        buf.table("audit")
            .unwrap()
            .symbol("sym", "tokyo-4")
            .unwrap()
            .column_bool("active", true)
            .unwrap()
            .column_ts("event_ts", TimestampMicros::new(444))
            .unwrap()
            .at_now()
            .unwrap();

        for prefix_len in 1..=buf.rows.len() {
            let rows = &buf.rows[..prefix_len];
            let table_name = buf.name_str(rows[0].table);
            let mut planner = RowGroupPlanner::new();
            for row in rows {
                let row_entries = buf.entries_for_row(row);
                planner
                    .add_row(
                        row,
                        row_entries,
                        &buf.name_bytes,
                        &buf.value_bytes,
                        table_name.len(),
                    )
                    .unwrap();
            }
            let estimated = planner.current_len;

            let mut datagram_buf = Vec::new();
            encode_row_group_from_scratch(
                &planner,
                &buf.name_bytes,
                &buf.value_bytes,
                table_name.as_bytes(),
                &mut datagram_buf,
            )
            .unwrap();
            let actual = datagram_buf.len();
            assert_eq!(estimated, actual, "prefix {prefix_len}");
        }
    }

    #[test]
    fn qwp_estimator_matches_actual_across_symbol_varint_boundary() {
        let mut buf = QwpBuffer::new(127);
        for i in 0..160 {
            buf.table("sym_audit")
                .unwrap()
                .symbol("sym", format!("sym-{i}"))
                .unwrap()
                .column_i64("x", i)
                .unwrap()
                .at_now()
                .unwrap();
        }

        for prefix_len in 1..=buf.rows.len() {
            let rows = &buf.rows[..prefix_len];
            let table_name = buf.name_str(rows[0].table);
            let mut planner = RowGroupPlanner::new();
            for row in rows {
                let row_entries = buf.entries_for_row(row);
                planner
                    .add_row(
                        row,
                        row_entries,
                        &buf.name_bytes,
                        &buf.value_bytes,
                        table_name.len(),
                    )
                    .unwrap();
            }
            let estimated = planner.current_len;

            let mut datagram_buf = Vec::new();
            encode_row_group_from_scratch(
                &planner,
                &buf.name_bytes,
                &buf.value_bytes,
                table_name.as_bytes(),
                &mut datagram_buf,
            )
            .unwrap();
            let actual = datagram_buf.len();
            assert_eq!(estimated, actual, "prefix {}", prefix_len);
        }
    }

    #[test]
    fn qwp_len_matches_unsplit_datagram_encoding_for_committed_groups() {
        let mut buf = QwpBuffer::new(127);

        buf.table("trades")
            .unwrap()
            .symbol("sym", "ETH-USD")
            .unwrap()
            .column_i64("qty", 4)
            .unwrap()
            .at_now()
            .unwrap();

        buf.table("trades")
            .unwrap()
            .symbol("sym", "BTC-USD")
            .unwrap()
            .column_str("venue", "binance")
            .unwrap()
            .at_now()
            .unwrap();

        buf.table("quotes")
            .unwrap()
            .symbol("sym", "ETH-USD")
            .unwrap()
            .column_f64("px", 42.5)
            .unwrap()
            .at_now()
            .unwrap();

        buf.table("trades")
            .unwrap()
            .symbol("sym", "SOL-USD")
            .unwrap()
            .column_i64("qty", 9)
            .unwrap()
            .at_now()
            .unwrap();

        let actual: usize = buf
            .encode_datagrams(usize::MAX)
            .unwrap()
            .iter()
            .map(Vec::len)
            .sum();
        assert_eq!(buf.len(), actual);
    }

    #[test]
    fn qwp_len_rewinds_with_marker_state() {
        let mut buf = QwpBuffer::new(127);

        buf.table("trades")
            .unwrap()
            .symbol("sym", "ETH-USD")
            .unwrap()
            .column_i64("qty", 1)
            .unwrap()
            .at_now()
            .unwrap();

        buf.table("trades")
            .unwrap()
            .symbol("sym", "BTC-USD")
            .unwrap()
            .column_i64("qty", 2)
            .unwrap()
            .at_now()
            .unwrap();

        let before = buf.len();
        buf.set_marker().unwrap();

        buf.table("trades")
            .unwrap()
            .symbol("sym", "SOL-USD")
            .unwrap()
            .column_i64("qty", 3)
            .unwrap()
            .at_now()
            .unwrap();

        buf.table("quotes")
            .unwrap()
            .symbol("sym", "ETH-USD")
            .unwrap()
            .column_f64("px", 42.5)
            .unwrap()
            .at_now()
            .unwrap();

        assert!(buf.len() > before);
        buf.rewind_to_marker().unwrap();
        assert_eq!(buf.len(), before);

        let actual: usize = buf
            .encode_datagrams(usize::MAX)
            .unwrap()
            .iter()
            .map(Vec::len)
            .sum();
        assert_eq!(buf.len(), actual);
    }

    #[test]
    fn qwp_len_resets_after_clear() {
        let mut buf = QwpBuffer::new(127);

        buf.table("trades")
            .unwrap()
            .symbol("sym", "ETH-USD")
            .unwrap()
            .column_i64("qty", 1)
            .unwrap()
            .at_now()
            .unwrap();

        assert!(!buf.is_empty());
        assert_eq!(buf.row_count(), 1);

        buf.clear();

        assert_eq!(buf.len(), 0);
        assert_eq!(buf.row_count(), 0);
        assert!(buf.is_empty());
    }

    #[test]
    fn qwp_len_clone_tracks_cached_state_independently() {
        let mut original = QwpBuffer::new(127);

        original
            .table("trades")
            .unwrap()
            .symbol("sym", "ETH-USD")
            .unwrap()
            .column_i64("qty", 1)
            .unwrap()
            .at_now()
            .unwrap();
        original
            .table("trades")
            .unwrap()
            .symbol("sym", "BTC-USD")
            .unwrap()
            .column_i64("qty", 2)
            .unwrap()
            .at_now()
            .unwrap();

        let mut cloned = original.clone();
        assert_eq!(original.len(), cloned.len());

        let original_actual: usize = original
            .encode_datagrams(usize::MAX)
            .unwrap()
            .iter()
            .map(Vec::len)
            .sum();
        let cloned_actual: usize = cloned
            .encode_datagrams(usize::MAX)
            .unwrap()
            .iter()
            .map(Vec::len)
            .sum();
        assert_eq!(original.len(), original_actual);
        assert_eq!(cloned.len(), cloned_actual);

        cloned
            .table("quotes")
            .unwrap()
            .symbol("sym", "ETH-USD")
            .unwrap()
            .column_f64("px", 42.5)
            .unwrap()
            .at_now()
            .unwrap();

        assert_ne!(original.len(), cloned.len());

        let original_after: usize = original
            .encode_datagrams(usize::MAX)
            .unwrap()
            .iter()
            .map(Vec::len)
            .sum();
        let cloned_after: usize = cloned
            .encode_datagrams(usize::MAX)
            .unwrap()
            .iter()
            .map(Vec::len)
            .sum();
        assert_eq!(original.len(), original_after);
        assert_eq!(cloned.len(), cloned_after);
    }

    #[test]
    fn qwp_len_treats_non_contiguous_same_table_rows_as_distinct_groups() {
        let mut buf = QwpBuffer::new(127);

        buf.table("trades")
            .unwrap()
            .symbol("sym", "ETH-USD")
            .unwrap()
            .column_i64("qty", 1)
            .unwrap()
            .at_now()
            .unwrap();
        buf.table("quotes")
            .unwrap()
            .symbol("sym", "ETH-USD")
            .unwrap()
            .column_f64("px", 42.5)
            .unwrap()
            .at_now()
            .unwrap();
        buf.table("trades")
            .unwrap()
            .symbol("sym", "BTC-USD")
            .unwrap()
            .column_i64("qty", 2)
            .unwrap()
            .at_now()
            .unwrap();

        let before = buf.len();
        let actual_before: usize = buf
            .encode_datagrams(usize::MAX)
            .unwrap()
            .iter()
            .map(Vec::len)
            .sum();
        assert_eq!(before, actual_before);

        buf.table("trades")
            .unwrap()
            .symbol("sym", "SOL-USD")
            .unwrap()
            .column_i64("qty", 3)
            .unwrap()
            .at_now()
            .unwrap();

        assert!(buf.len() > before);
        let actual_after: usize = buf
            .encode_datagrams(usize::MAX)
            .unwrap()
            .iter()
            .map(Vec::len)
            .sum();
        assert_eq!(buf.len(), actual_after);
    }

    #[test]
    fn qwp_retained_capacity_after_clear() {
        let mut buf = QwpBuffer::new(127);

        for i in 0..10 {
            buf.table("trades")
                .unwrap()
                .symbol("sym", format!("SYM-{i}"))
                .unwrap()
                .column_i64("qty", i)
                .unwrap()
                .at_now()
                .unwrap();
        }

        let cap_before = buf.capacity();
        assert!(cap_before > 0);

        buf.clear();
        let cap_after = buf.capacity();
        assert_eq!(
            cap_before, cap_after,
            "capacity must not drop after clear()"
        );

        // Refill
        for i in 0..10 {
            buf.table("trades")
                .unwrap()
                .symbol("sym", format!("SYM-{i}"))
                .unwrap()
                .column_i64("qty", i)
                .unwrap()
                .at_now()
                .unwrap();
        }

        let cap_refilled = buf.capacity();
        assert_eq!(
            cap_before, cap_refilled,
            "capacity must not change after refill with same workload"
        );
    }

    #[test]
    fn qwp_marker_rewind_tail_segment() {
        let mut buf = QwpBuffer::new(127);

        buf.table("trades")
            .unwrap()
            .symbol("sym", "ETH-USD")
            .unwrap()
            .column_i64("qty", 1)
            .unwrap()
            .at_now()
            .unwrap();

        buf.set_marker().unwrap();

        // Add more rows to same table (same segment)
        buf.table("trades")
            .unwrap()
            .symbol("sym", "BTC-USD")
            .unwrap()
            .column_i64("qty", 2)
            .unwrap()
            .at_now()
            .unwrap();

        buf.table("trades")
            .unwrap()
            .symbol("sym", "SOL-USD")
            .unwrap()
            .column_i64("qty", 3)
            .unwrap()
            .at_now()
            .unwrap();

        assert_eq!(buf.segments.len(), 1);
        assert_eq!(buf.segments[0].row_count, 3);

        buf.rewind_to_marker().unwrap();

        assert_eq!(buf.segments.len(), 1);
        assert_eq!(buf.segments[0].row_count, 1);
        assert_eq!(buf.rows.len(), 1);

        // Can continue adding rows
        buf.table("trades")
            .unwrap()
            .symbol("sym", "DOGE-USD")
            .unwrap()
            .column_i64("qty", 4)
            .unwrap()
            .at_now()
            .unwrap();

        assert_eq!(buf.segments[0].row_count, 2);

        let datagrams = buf.encode_datagrams(1400).unwrap();
        assert_eq!(datagrams.len(), 1);
    }

    #[test]
    fn qwp_clone_while_pending() {
        let mut buf = QwpBuffer::new(127);

        buf.table("trades")
            .unwrap()
            .symbol("sym", "ETH-USD")
            .unwrap()
            .column_i64("qty", 1)
            .unwrap()
            .at_now()
            .unwrap();

        // Start a new row but don't finish it
        buf.table("trades")
            .unwrap()
            .symbol("sym", "BTC-USD")
            .unwrap();

        let mut cloned = buf.clone();

        // Finish in original
        buf.column_i64("qty", 2).unwrap();
        buf.at_now().unwrap();

        // Finish in clone with different data
        cloned.column_f64("px", 42.5).unwrap();
        cloned.at_now().unwrap();

        assert_eq!(buf.row_count(), 2);
        assert_eq!(cloned.row_count(), 2);

        // They should produce different datagrams
        let orig_dgrams = buf.encode_datagrams(1400).unwrap();
        let cloned_dgrams = cloned.encode_datagrams(1400).unwrap();
        assert_ne!(orig_dgrams, cloned_dgrams);
    }

    #[test]
    fn qwp_line_sender_protocol_behavior_after_close() {
        let mut buf = QwpBuffer::new(127);
        buf.table("test")
            .unwrap()
            .symbol("s", "v")
            .unwrap()
            .column_i64("x", 1)
            .unwrap();
        buf.at_now().unwrap();

        buf.clear();
        assert!(buf.is_empty());
        assert_eq!(buf.row_count(), 0);
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn qwp_single_row_oversize_returns_error() {
        let mut buf = QwpBuffer::new(127);
        buf.table("trades")
            .unwrap()
            .symbol("sym", "ETH-USD")
            .unwrap()
            .column_str("venue", "a]]very-long-string-that-makes-the-row-big")
            .unwrap()
            .column_i64("qty", 42)
            .unwrap();
        buf.at_now().unwrap();

        // Use a very small max datagram size so one row can't fit
        let result = buf.encode_datagrams(30);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("single row exceeds"));
    }

    #[test]
    fn qwp_planner_checkpoint_rollback_restores_state() {
        let mut planner = RowGroupPlanner::new();
        let mut buf = QwpBuffer::new(127);

        buf.table("t")
            .unwrap()
            .symbol("s", "a")
            .unwrap()
            .column_i64("x", 1)
            .unwrap();
        buf.at_now().unwrap();

        buf.table("t")
            .unwrap()
            .symbol("s", "b")
            .unwrap()
            .column_i64("x", 2)
            .unwrap();
        buf.at_now().unwrap();

        let row0 = &buf.rows[0];
        let row1 = &buf.rows[1];
        let entries0 = buf.entries_for_row(row0);
        let entries1 = buf.entries_for_row(row1);

        // Add first row
        planner
            .add_row(row0, entries0, &buf.name_bytes, &buf.value_bytes, "t".len())
            .unwrap();
        let len_after_1 = planner.current_len;
        assert_eq!(planner.row_count(), 1);

        // Checkpoint, add second row, then rollback
        let cp = planner.checkpoint();
        planner
            .add_row(row1, entries1, &buf.name_bytes, &buf.value_bytes, "t".len())
            .unwrap();
        assert_eq!(planner.row_count(), 2);
        assert!(planner.current_len > len_after_1);

        planner.rollback(cp);
        assert_eq!(planner.row_count(), 1);
        assert_eq!(planner.current_len, len_after_1);
        assert_eq!(planner.columns.len(), cp.columns_len);
    }

    #[test]
    fn qwp_planner_rollback_returns_new_columns_to_pool() {
        let mut planner = RowGroupPlanner::new();
        let mut buf = QwpBuffer::new(127);

        // Row 1: only "x"
        buf.table("t").unwrap().column_i64("x", 1).unwrap();
        buf.at_now().unwrap();

        // Row 2: "x" and "y" (introduces new column)
        buf.table("t")
            .unwrap()
            .column_i64("x", 2)
            .unwrap()
            .column_i64("y", 3)
            .unwrap();
        buf.at_now().unwrap();

        let row0 = &buf.rows[0];
        let row1 = &buf.rows[1];
        let entries0 = buf.entries_for_row(row0);
        let entries1 = buf.entries_for_row(row1);

        planner
            .add_row(row0, entries0, &buf.name_bytes, &buf.value_bytes, "t".len())
            .unwrap();
        assert_eq!(planner.columns.len(), 1); // just "x"

        let cp = planner.checkpoint();
        planner
            .add_row(row1, entries1, &buf.name_bytes, &buf.value_bytes, "t".len())
            .unwrap();
        assert_eq!(planner.columns.len(), 2); // "x" + "y"

        planner.rollback(cp);
        assert_eq!(planner.columns.len(), 1); // "y" removed by truncate
    }

    #[test]
    fn qwp_long_lived_churn_retains_capacity_without_unbounded_growth() {
        let mut buf = QwpBuffer::new(127);
        let mut scratch = QwpSendScratch::new(1400);

        // Simulate many fill/flush/clear cycles with varying table names
        for cycle in 0..20 {
            for i in 0..5 {
                let tname = format!("table_{}", cycle % 3);
                buf.table(tname.as_str())
                    .unwrap()
                    .symbol("sym", format!("sym-{i}"))
                    .unwrap()
                    .column_i64("x", i)
                    .unwrap();
                buf.at_now().unwrap();
            }

            // Flush to a no-op sink
            buf.flush_to_socket(&mut scratch, 1400, &mut |_| Ok(()))
                .unwrap();
            buf.clear();
        }

        // After many cycles, capacity should be bounded, not growing unboundedly.
        // The pool should have reusable columns.
        let cap = buf.capacity();
        assert!(cap > 0);

        // Do one more cycle and verify capacity doesn't grow
        for i in 0..5 {
            buf.table("table_0")
                .unwrap()
                .symbol("sym", format!("sym-{i}"))
                .unwrap()
                .column_i64("x", i)
                .unwrap();
            buf.at_now().unwrap();
        }
        buf.flush_to_socket(&mut scratch, 1400, &mut |_| Ok(()))
            .unwrap();
        buf.clear();

        // Capacity should be stable
        assert!(
            buf.capacity() <= cap * 2,
            "capacity should not grow unboundedly"
        );
    }

    #[test]
    fn qwp_sparse_wide_rows_planner_stays_bounded() {
        // Test with rows that have very different column sets
        let mut buf = QwpBuffer::new(127);

        // Row 1: columns a, b, c
        buf.table("wide")
            .unwrap()
            .column_i64("a", 1)
            .unwrap()
            .column_i64("b", 2)
            .unwrap()
            .column_i64("c", 3)
            .unwrap();
        buf.at_now().unwrap();

        // Row 2: columns d, e, f (completely different)
        buf.table("wide")
            .unwrap()
            .column_i64("d", 4)
            .unwrap()
            .column_i64("e", 5)
            .unwrap()
            .column_i64("f", 6)
            .unwrap();
        buf.at_now().unwrap();

        // Row 3: columns a, d (mix)
        buf.table("wide")
            .unwrap()
            .column_i64("a", 7)
            .unwrap()
            .column_i64("d", 8)
            .unwrap();
        buf.at_now().unwrap();

        // Should produce valid datagrams
        let datagrams = buf.encode_datagrams(1400).unwrap();
        assert_eq!(datagrams.len(), 1);

        // Verify estimated len matches actual
        let estimated = buf.len();
        let actual: usize = datagrams.iter().map(Vec::len).sum();
        assert_eq!(estimated, actual);
    }

    #[test]
    fn qwp_split_near_varint_boundary() {
        // Create rows that push symbol dictionary size across varint boundary (128 symbols)
        let mut buf = QwpBuffer::new(127);
        for i in 0..140 {
            buf.table("syms")
                .unwrap()
                .symbol("s", format!("v{i}"))
                .unwrap()
                .column_i64("x", i)
                .unwrap();
            buf.at_now().unwrap();
        }

        // Use a size that forces splits around the varint boundary
        let datagrams = buf.encode_datagrams(400).unwrap();
        assert!(datagrams.len() > 1);

        // Verify each datagram is valid (starts with QWP1 header)
        for d in &datagrams {
            assert_eq!(&d[0..4], b"QWP1");
            let payload_len = u32::from_le_bytes([d[8], d[9], d[10], d[11]]) as usize;
            assert_eq!(payload_len, d.len() - QWP_MESSAGE_HEADER_SIZE);
        }

        // Verify total estimated len matches actual
        let estimated = buf.len();
        // The estimated len is for unsplit encoding, so it should match
        // a single-datagram encoding
        let unsplit: usize = buf
            .encode_datagrams(usize::MAX)
            .unwrap()
            .iter()
            .map(Vec::len)
            .sum();
        assert_eq!(estimated, unsplit);
    }

    /// Run with: `cargo test --features sync-sender-qwp-udp -- qwp_zero_alloc --ignored --test-threads=1`
    #[test]
    #[ignore = "requires single-threaded execution: --test-threads=1"]
    fn qwp_zero_alloc_steady_state_after_prewarm() {
        use crate::alloc_counter;

        // Prewarm: fill buffer and scratch, flush, clear
        let mut buf = QwpBuffer::new(127);
        let mut scratch = QwpSendScratch::new(1400);

        // Use fixed-length strings to avoid format! allocations in the hot loop
        let symbols = ["AAA", "BBB", "CCC", "DDD", "EEE"];
        let venues = ["tokyo", "london", "newyork", "paris", "berlin"];

        // Warmup cycle: ensure all vecs have grown to needed capacity
        for i in 0..5 {
            buf.table("trades")
                .unwrap()
                .symbol("sym", symbols[i])
                .unwrap()
                .column_i64("qty", i as i64)
                .unwrap()
                .column_str("venue", venues[i])
                .unwrap();
            buf.at_now().unwrap();
        }
        buf.flush_to_socket(&mut scratch, 1400, &mut |_| Ok(()))
            .unwrap();
        buf.clear();

        // Second warmup to ensure planner pool is populated
        for i in 0..5 {
            buf.table("trades")
                .unwrap()
                .symbol("sym", symbols[i])
                .unwrap()
                .column_i64("qty", i as i64)
                .unwrap()
                .column_str("venue", venues[i])
                .unwrap();
            buf.at_now().unwrap();
        }
        buf.flush_to_socket(&mut scratch, 1400, &mut |_| Ok(()))
            .unwrap();
        buf.clear();

        // Now measure steady-state allocations
        alloc_counter::start_counting();

        for _cycle in 0..5 {
            for i in 0..5 {
                buf.table("trades")
                    .unwrap()
                    .symbol("sym", symbols[i])
                    .unwrap()
                    .column_i64("qty", i as i64)
                    .unwrap()
                    .column_str("venue", venues[i])
                    .unwrap();
                buf.at_now().unwrap();
            }
            buf.flush_to_socket(&mut scratch, 1400, &mut |_| Ok(()))
                .unwrap();
            buf.clear();
        }

        let alloc_count = alloc_counter::stop_counting();
        assert_eq!(
            alloc_count, 0,
            "Expected zero allocations in steady state after prewarm, got {alloc_count}"
        );
    }
}
