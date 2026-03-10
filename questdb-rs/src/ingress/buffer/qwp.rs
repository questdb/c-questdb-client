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
use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Formatter};
use std::hash::{DefaultHasher, Hash, Hasher};

use super::ilp::{ColumnName, TableName};

pub(crate) const QWP_MESSAGE_HEADER_SIZE: usize = 12;
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
pub(crate) const QWP_DESIGNATED_TIMESTAMP_COLUMN_NAME: &str = "";

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

#[derive(Clone)]
struct BufferState {
    op_case: OpCase,
    row_count: usize,
    first_table_name: Option<String>,
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

#[derive(Clone, Debug)]
struct QwpSizeHint {
    committed_len: usize,
    active_group: Option<RowGroupEstimator>,
}

impl QwpSizeHint {
    fn new() -> Self {
        Self {
            committed_len: 0,
            active_group: None,
        }
    }

    fn len(&self) -> usize {
        self.committed_len
    }

    fn add_committed_row(&mut self, row: &CommittedRow) -> crate::Result<()> {
        let specs = row_value_specs(row);
        if let Some(group) = self.active_group.as_mut() {
            if group.table_name == row.table_name {
                let previous_len = group.current_len();
                let new_len = match group.estimate_len_with_specs(&specs) {
                    Ok(new_len) => new_len,
                    Err(err) if is_batched_type_change_error(&err) => {
                        self.committed_len += standalone_row_group_len(row);
                        self.active_group = None;
                        return Ok(());
                    }
                    Err(err) => return Err(err),
                };
                group.add_row_with_specs(&specs, new_len)?;
                self.committed_len = self.committed_len - previous_len + new_len;
                return Ok(());
            }
        }

        let mut group = RowGroupEstimator::new(&row.table_name);
        let new_len = group.estimate_len_with_specs(&specs)?;
        group.add_row_with_specs(&specs, new_len)?;
        self.committed_len += new_len;
        self.active_group = Some(group);
        Ok(())
    }
}

impl Debug for BufferState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BufferState")
            .field("op_case", &self.op_case)
            .field("row_count", &self.row_count)
            .field("first_table_name", &self.first_table_name)
            .field("transactional", &self.transactional)
            .finish()
    }
}

#[derive(Clone, Debug)]
struct QwpMarker {
    row_count: usize,
    state: BufferState,
    size_hint: QwpSizeHint,
}

#[derive(Clone, Debug)]
pub(crate) struct QwpBuffer {
    rows: Vec<CommittedRow>,
    pending_row: Option<PendingRow>,
    state: BufferState,
    size_hint: QwpSizeHint,
    marker: Option<QwpMarker>,
    max_name_len: usize,
}

#[derive(Clone, Debug)]
struct PendingRow {
    table_name: String,
    entries: Vec<PendingEntry>,
    seen_name_hashes: HashSet<u64>,
}

#[derive(Clone, Debug)]
struct CommittedRow {
    table_name: String,
    entries: Vec<PendingEntry>,
    designated_ts: Option<PendingTimestamp>,
}

#[derive(Clone, Copy, Debug)]
struct RowValueSpec<'a> {
    name: &'a str,
    value: ColumnValueRef<'a>,
    kind: ColumnKind,
}

#[derive(Clone, Debug)]
struct PendingEntry {
    name: String,
    value: PendingValue,
}

#[derive(Clone, Debug)]
enum PendingValue {
    Bool(bool),
    Symbol(String),
    I64(i64),
    F64(f64),
    String(String),
    Timestamp(PendingTimestamp),
}

#[derive(Clone, Copy, Debug)]
struct PendingTimestamp {
    value: i64,
    nanos: bool,
}

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

#[derive(Debug)]
struct BatchColumn<'a> {
    name: String,
    kind: ColumnKind,
    nullable: bool,
    values: Vec<Option<ColumnValueRef<'a>>>,
}

#[derive(Clone, Copy, Debug)]
enum ColumnValueRef<'a> {
    Bool(bool),
    Symbol(&'a str),
    I64(i64),
    F64(f64),
    String(&'a str),
    Timestamp(i64),
}

impl QwpBuffer {
    pub(crate) fn new(max_name_len: usize) -> Self {
        Self {
            rows: Vec::new(),
            pending_row: None,
            state: BufferState::new(),
            size_hint: QwpSizeHint::new(),
            marker: None,
            max_name_len,
        }
    }

    pub(crate) fn reserve(&mut self, _additional: usize) {}

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
        self.pending_row.is_none() && self.rows.is_empty()
    }

    pub(crate) fn capacity(&self) -> usize {
        self.rows.capacity()
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
            row_count: self.rows.len(),
            state: self.state.clone(),
            size_hint: self.size_hint.clone(),
        });
        Ok(())
    }

    pub(crate) fn rewind_to_marker(&mut self) -> crate::Result<()> {
        if let Some(marker) = self.marker.take() {
            self.rows.truncate(marker.row_count);
            self.pending_row = None;
            self.state = marker.state;
            self.size_hint = marker.size_hint;
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
        self.rows.clear();
        self.pending_row = None;
        self.state = BufferState::new();
        self.size_hint = QwpSizeHint::new();
        self.marker = None;
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

    fn pending_row_mut(&mut self) -> &mut PendingRow {
        self.pending_row
            .as_mut()
            .expect("pending row must exist after successful table()")
    }

    fn update_transactional_state(&mut self, table_name: &str) {
        if let Some(first_table_name) = self.state.first_table_name.as_ref() {
            if first_table_name != table_name {
                self.state.transactional = false;
            }
        } else {
            self.state.first_table_name = Some(table_name.to_owned());
        }
    }

    fn mark_pending_entry_name(&mut self, name: &str) -> crate::Result<()> {
        let pending_row = self.pending_row_mut();
        let name_hash = hash_name(name);
        if !pending_row.seen_name_hashes.insert(name_hash)
            && pending_row.entries.iter().any(|entry| entry.name == name)
        {
            return Err(error::fmt!(
                InvalidApiCall,
                "column '{}' already set for current row",
                name
            ));
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

        let table_name = name.as_ref().to_owned();
        self.update_transactional_state(&table_name);
        self.pending_row = Some(PendingRow {
            table_name,
            entries: Vec::new(),
            seen_name_hashes: HashSet::new(),
        });
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
        self.pending_row_mut().entries.push(PendingEntry {
            name: name.as_ref().to_owned(),
            value: PendingValue::Symbol(value.as_ref().to_owned()),
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
        self.pending_row_mut().entries.push(PendingEntry {
            name: name.as_ref().to_owned(),
            value: PendingValue::Bool(value),
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
        self.pending_row_mut().entries.push(PendingEntry {
            name: name.as_ref().to_owned(),
            value: PendingValue::I64(value),
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
        self.pending_row_mut().entries.push(PendingEntry {
            name: name.as_ref().to_owned(),
            value: PendingValue::F64(value),
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
        self.pending_row_mut().entries.push(PendingEntry {
            name: name.as_ref().to_owned(),
            value: PendingValue::String(value.as_ref().to_owned()),
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
        self.pending_row_mut().entries.push(PendingEntry {
            name: name.as_ref().to_owned(),
            value: PendingValue::Timestamp(pending_timestamp(value.try_into()?)),
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
        self.commit_current_row(Some(pending_timestamp(timestamp.try_into()?)))
    }

    pub(crate) fn at_now(&mut self) -> crate::Result<()> {
        self.check_op(Op::At)?;
        self.commit_current_row(None)
    }

    fn commit_current_row(&mut self, designated_ts: Option<PendingTimestamp>) -> crate::Result<()> {
        let Some(pending_row) = self.pending_row.take() else {
            return Err(error::fmt!(
                InvalidApiCall,
                "table() must be called before adding columns"
            ));
        };

        if pending_row.entries.is_empty() {
            return Err(error::fmt!(InvalidApiCall, "no columns were provided"));
        }

        let committed_row = CommittedRow {
            table_name: pending_row.table_name,
            entries: pending_row.entries,
            designated_ts,
        };
        self.size_hint.add_committed_row(&committed_row)?;
        self.rows.push(committed_row);
        self.state.row_count += 1;
        self.state.op_case = OpCase::MayFlushOrTable;
        Ok(())
    }

    fn pending_size_hint(&self) -> usize {
        let Some(pending_row) = self.pending_row.as_ref() else {
            return 0;
        };

        let mut size = pending_row.table_name.len();
        for entry in &pending_row.entries {
            size += entry.name.len();
            size += match &entry.value {
                PendingValue::Bool(_) => 1,
                PendingValue::Symbol(value) => value.len() + 3,
                PendingValue::I64(_) | PendingValue::F64(_) => 8,
                PendingValue::String(value) => value.len() + 9,
                PendingValue::Timestamp(_) => 9,
            };
        }
        size + 1
    }

    pub(crate) fn encode_datagrams(&self, max_datagram_size: usize) -> crate::Result<Vec<Vec<u8>>> {
        let mut datagrams = Vec::new();
        let mut start = 0usize;
        while start < self.rows.len() {
            let table_name = &self.rows[start].table_name;
            let mut end = start + 1;
            while end < self.rows.len() && self.rows[end].table_name == *table_name {
                end += 1;
            }
            encode_row_group_with_splitting(
                &self.rows[start..end],
                max_datagram_size,
                &mut datagrams,
            )?;
            start = end;
        }
        Ok(datagrams)
    }
}

#[derive(Clone, Debug)]
struct RowGroupEstimator {
    table_name: String,
    row_count: usize,
    current_len: usize,
    columns: Vec<EstimatedColumn>,
    indexes: HashMap<String, usize>,
}

#[derive(Clone, Debug)]
struct EstimatedColumn {
    name: String,
    kind: ColumnKind,
    base_nullable: bool,
    non_null_count: usize,
    string_data_len: usize,
    symbol_dict_bytes: usize,
    symbol_row_index_bytes: usize,
    symbol_indexes: HashMap<String, usize>,
}

impl RowGroupEstimator {
    fn new(table_name: &str) -> Self {
        Self {
            table_name: table_name.to_owned(),
            row_count: 0,
            current_len: base_datagram_len(table_name, 0, 0),
            columns: Vec::new(),
            indexes: HashMap::new(),
        }
    }

    fn row_count(&self) -> usize {
        self.row_count
    }

    fn current_len(&self) -> usize {
        self.current_len
    }

    fn estimate_len_with_specs(&self, specs: &[RowValueSpec<'_>]) -> crate::Result<usize> {
        let new_row_count = self.row_count + 1;
        let mut existing = Vec::<(usize, RowValueSpec<'_>)>::new();
        let mut created = Vec::<RowValueSpec<'_>>::new();

        for spec in specs {
            if let Some(&idx) = self.indexes.get(spec.name) {
                let column = &self.columns[idx];
                if column.kind != spec.kind {
                    return Err(error::fmt!(
                        InvalidApiCall,
                        "QWP/UDP column {:?} changes type within a batched table",
                        spec.name
                    ));
                }
                existing.push((idx, *spec));
            } else {
                created.push(*spec);
            }
        }

        let mut total = base_datagram_len(
            &self.table_name,
            new_row_count,
            self.columns.len() + created.len(),
        );

        for (idx, column) in self.columns.iter().enumerate() {
            total += column.schema_len();
            if let Some((_, spec)) = existing
                .iter()
                .find(|(existing_idx, _)| *existing_idx == idx)
            {
                total += column.payload_len_after_adding(new_row_count, spec.value)?;
            } else {
                total += column.payload_len(new_row_count);
            }
        }

        for spec in created {
            let column = EstimatedColumn::new(spec.name, spec.kind, spec.value)?;
            total += column.schema_len();
            total += column.payload_len(new_row_count);
        }

        Ok(total)
    }

    fn add_row_with_specs(
        &mut self,
        specs: &[RowValueSpec<'_>],
        new_len: usize,
    ) -> crate::Result<()> {
        for spec in specs {
            if let Some(&idx) = self.indexes.get(spec.name) {
                let column = &mut self.columns[idx];
                if column.kind != spec.kind {
                    return Err(error::fmt!(
                        InvalidApiCall,
                        "QWP/UDP column {:?} changes type within a batched table",
                        spec.name
                    ));
                }
                column.add_value(spec.value)?;
            } else {
                let idx = self.columns.len();
                self.columns
                    .push(EstimatedColumn::new(spec.name, spec.kind, spec.value)?);
                self.indexes.insert(spec.name.to_owned(), idx);
            }
        }

        self.row_count += 1;
        self.current_len = new_len;
        Ok(())
    }
}

impl EstimatedColumn {
    fn new(name: &str, kind: ColumnKind, value: ColumnValueRef<'_>) -> crate::Result<Self> {
        let mut column = Self {
            name: name.to_owned(),
            kind,
            base_nullable: matches!(
                kind,
                ColumnKind::Symbol
                    | ColumnKind::String
                    | ColumnKind::TimestampMicros
                    | ColumnKind::TimestampNanos
            ),
            non_null_count: 0,
            string_data_len: 0,
            symbol_dict_bytes: 0,
            symbol_row_index_bytes: 0,
            symbol_indexes: HashMap::new(),
        };
        column.add_value(value)?;
        Ok(column)
    }

    fn schema_len(&self) -> usize {
        qwp_string_len(&self.name) + 1
    }

    fn payload_len(&self, row_count: usize) -> usize {
        let nullable = self.is_nullable(row_count);
        let bitmap = if nullable { bitmap_bytes(row_count) } else { 0 };

        bitmap
            + match self.kind {
                ColumnKind::Bool => packed_bytes(row_count),
                ColumnKind::I64 | ColumnKind::F64 => {
                    if nullable {
                        self.non_null_count * 8
                    } else {
                        row_count * 8
                    }
                }
                ColumnKind::TimestampMicros | ColumnKind::TimestampNanos => self.non_null_count * 8,
                ColumnKind::String => 4 * (self.non_null_count + 1) + self.string_data_len,
                ColumnKind::Symbol => {
                    qwp_varint_size(self.symbol_indexes.len() as u64)
                        + self.symbol_dict_bytes
                        + self.symbol_row_index_bytes
                }
            }
    }

    fn payload_len_after_adding(
        &self,
        row_count_after: usize,
        value: ColumnValueRef<'_>,
    ) -> crate::Result<usize> {
        let non_null_count = self.non_null_count + 1;
        let nullable = self.is_nullable_with_count(row_count_after, non_null_count);
        let bitmap = if nullable {
            bitmap_bytes(row_count_after)
        } else {
            0
        };

        let payload = match self.kind {
            ColumnKind::Bool => {
                match value {
                    ColumnValueRef::Bool(_) => {}
                    _ => {
                        return Err(error::fmt!(
                            InvalidApiCall,
                            "internal QWP estimator type mismatch for boolean column"
                        ));
                    }
                }
                packed_bytes(row_count_after)
            }
            ColumnKind::I64 => {
                match value {
                    ColumnValueRef::I64(_) => {}
                    _ => {
                        return Err(error::fmt!(
                            InvalidApiCall,
                            "internal QWP estimator type mismatch for long column"
                        ));
                    }
                }
                if nullable {
                    non_null_count * 8
                } else {
                    row_count_after * 8
                }
            }
            ColumnKind::F64 => {
                match value {
                    ColumnValueRef::F64(_) => {}
                    _ => {
                        return Err(error::fmt!(
                            InvalidApiCall,
                            "internal QWP estimator type mismatch for double column"
                        ));
                    }
                }
                if nullable {
                    non_null_count * 8
                } else {
                    row_count_after * 8
                }
            }
            ColumnKind::TimestampMicros | ColumnKind::TimestampNanos => {
                match value {
                    ColumnValueRef::Timestamp(_) => {}
                    _ => {
                        return Err(error::fmt!(
                            InvalidApiCall,
                            "internal QWP estimator type mismatch for timestamp column"
                        ));
                    }
                }
                non_null_count * 8
            }
            ColumnKind::String => {
                let text_len = match value {
                    ColumnValueRef::String(text) => text.len(),
                    _ => {
                        return Err(error::fmt!(
                            InvalidApiCall,
                            "internal QWP estimator type mismatch for string column"
                        ));
                    }
                };
                4 * (non_null_count + 1) + self.string_data_len + text_len
            }
            ColumnKind::Symbol => {
                let symbol = match value {
                    ColumnValueRef::Symbol(symbol) => symbol,
                    _ => {
                        return Err(error::fmt!(
                            InvalidApiCall,
                            "internal QWP estimator type mismatch for symbol column"
                        ));
                    }
                };
                let (dict_len_after, dict_bytes_after, row_index_bytes_after) =
                    if let Some(&idx) = self.symbol_indexes.get(symbol) {
                        (
                            self.symbol_indexes.len(),
                            self.symbol_dict_bytes,
                            self.symbol_row_index_bytes + qwp_varint_size(idx as u64),
                        )
                    } else {
                        let idx = self.symbol_indexes.len();
                        (
                            idx + 1,
                            self.symbol_dict_bytes + qwp_string_len(symbol),
                            self.symbol_row_index_bytes + qwp_varint_size(idx as u64),
                        )
                    };

                qwp_varint_size(dict_len_after as u64) + dict_bytes_after + row_index_bytes_after
            }
        };

        Ok(bitmap + payload)
    }

    fn add_value(&mut self, value: ColumnValueRef<'_>) -> crate::Result<()> {
        match self.kind {
            ColumnKind::Bool => match value {
                ColumnValueRef::Bool(_) => {
                    self.non_null_count += 1;
                    Ok(())
                }
                _ => Err(error::fmt!(
                    InvalidApiCall,
                    "internal QWP estimator type mismatch for boolean column"
                )),
            },
            ColumnKind::I64 => match value {
                ColumnValueRef::I64(_) => {
                    self.non_null_count += 1;
                    Ok(())
                }
                _ => Err(error::fmt!(
                    InvalidApiCall,
                    "internal QWP estimator type mismatch for long column"
                )),
            },
            ColumnKind::F64 => match value {
                ColumnValueRef::F64(_) => {
                    self.non_null_count += 1;
                    Ok(())
                }
                _ => Err(error::fmt!(
                    InvalidApiCall,
                    "internal QWP estimator type mismatch for double column"
                )),
            },
            ColumnKind::TimestampMicros | ColumnKind::TimestampNanos => match value {
                ColumnValueRef::Timestamp(_) => {
                    self.non_null_count += 1;
                    Ok(())
                }
                _ => Err(error::fmt!(
                    InvalidApiCall,
                    "internal QWP estimator type mismatch for timestamp column"
                )),
            },
            ColumnKind::String => match value {
                ColumnValueRef::String(text) => {
                    self.non_null_count += 1;
                    self.string_data_len += text.len();
                    Ok(())
                }
                _ => Err(error::fmt!(
                    InvalidApiCall,
                    "internal QWP estimator type mismatch for string column"
                )),
            },
            ColumnKind::Symbol => match value {
                ColumnValueRef::Symbol(symbol) => {
                    let idx = if let Some(&idx) = self.symbol_indexes.get(symbol) {
                        idx
                    } else {
                        let idx = self.symbol_indexes.len();
                        self.symbol_indexes.insert(symbol.to_owned(), idx);
                        self.symbol_dict_bytes += qwp_string_len(symbol);
                        idx
                    };
                    self.non_null_count += 1;
                    self.symbol_row_index_bytes += qwp_varint_size(idx as u64);
                    Ok(())
                }
                _ => Err(error::fmt!(
                    InvalidApiCall,
                    "internal QWP estimator type mismatch for symbol column"
                )),
            },
        }
    }

    fn is_nullable(&self, row_count: usize) -> bool {
        self.is_nullable_with_count(row_count, self.non_null_count)
    }

    fn is_nullable_with_count(&self, row_count: usize, non_null_count: usize) -> bool {
        self.base_nullable || (kind_supports_sparse_nulls(self.kind) && non_null_count < row_count)
    }
}

fn base_datagram_len(table_name: &str, row_count: usize, column_count: usize) -> usize {
    QWP_MESSAGE_HEADER_SIZE
        + qwp_string_len(table_name)
        + qwp_varint_size(row_count as u64)
        + qwp_varint_size(column_count as u64)
        + 1
}

fn qwp_string_len(value: &str) -> usize {
    qwp_varint_size(value.len() as u64) + value.len()
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

fn row_value_specs(row: &CommittedRow) -> Vec<RowValueSpec<'_>> {
    let mut specs =
        Vec::with_capacity(row.entries.len() + usize::from(row.designated_ts.is_some()));
    for entry in &row.entries {
        specs.push(RowValueSpec {
            name: &entry.name,
            value: batch_value_ref(&entry.value),
            kind: batch_kind_from_value(&entry.value),
        });
    }
    if let Some(ts) = row.designated_ts {
        specs.push(RowValueSpec {
            name: QWP_DESIGNATED_TIMESTAMP_COLUMN_NAME,
            value: ColumnValueRef::Timestamp(ts.value),
            kind: if ts.nanos {
                ColumnKind::TimestampNanos
            } else {
                ColumnKind::TimestampMicros
            },
        });
    }
    specs
}

fn standalone_row_group_len(row: &CommittedRow) -> usize {
    estimated_row_group_len(std::slice::from_ref(row)).unwrap_or(0)
}

fn is_batched_type_change_error(err: &Error) -> bool {
    err.code() == ErrorCode::InvalidApiCall
        && err.msg().contains("changes type within a batched table")
}

fn estimated_row_group_len(rows: &[CommittedRow]) -> crate::Result<usize> {
    let Some(first_row) = rows.first() else {
        return Err(error::fmt!(
            InvalidApiCall,
            "cannot estimate empty QWP row group"
        ));
    };

    let mut estimator = RowGroupEstimator::new(&first_row.table_name);
    for row in rows {
        let specs = row_value_specs(row);
        let new_len = estimator.estimate_len_with_specs(&specs)?;
        estimator.add_row_with_specs(&specs, new_len)?;
    }
    Ok(estimator.current_len())
}

fn write_qwp_varint(out: &mut Vec<u8>, mut value: u64) {
    while value > 0x7F {
        out.push(((value & 0x7F) as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn write_qwp_string(out: &mut Vec<u8>, value: &str) {
    write_qwp_varint(out, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}

fn encode_row_group_with_splitting(
    rows: &[CommittedRow],
    max_datagram_size: usize,
    out: &mut Vec<Vec<u8>>,
) -> crate::Result<()> {
    let Some(first_row) = rows.first() else {
        return Ok(());
    };

    let mut batch_start = 0usize;
    let mut estimator = RowGroupEstimator::new(&first_row.table_name);

    for (idx, row) in rows.iter().enumerate() {
        let specs = row_value_specs(row);
        let estimated_len = estimator.estimate_len_with_specs(&specs)?;
        if estimator.row_count() > 0 && estimated_len > max_datagram_size {
            out.push(encode_row_group(&rows[batch_start..idx])?);
            batch_start = idx;
            estimator = RowGroupEstimator::new(&row.table_name);

            let single_row_len = estimator.estimate_len_with_specs(&specs)?;
            if single_row_len > max_datagram_size {
                return Err(error::fmt!(
                    InvalidApiCall,
                    "single row exceeds maximum datagram size ({} bytes), estimated {} bytes",
                    max_datagram_size,
                    single_row_len
                ));
            }
            estimator.add_row_with_specs(&specs, single_row_len)?;
        } else {
            if estimated_len > max_datagram_size {
                return Err(error::fmt!(
                    InvalidApiCall,
                    "single row exceeds maximum datagram size ({} bytes), estimated {} bytes",
                    max_datagram_size,
                    estimated_len
                ));
            }
            estimator.add_row_with_specs(&specs, estimated_len)?;
        }
    }

    if estimator.row_count() > 0 {
        out.push(encode_row_group(&rows[batch_start..])?);
    }
    Ok(())
}

fn encode_row_group(rows: &[CommittedRow]) -> crate::Result<Vec<u8>> {
    let Some(first_row) = rows.first() else {
        return Err(error::fmt!(
            InvalidApiCall,
            "cannot encode empty QWP row group"
        ));
    };

    let columns = build_batch_columns(rows)?;

    let mut payload = Vec::new();
    write_qwp_string(&mut payload, &first_row.table_name);
    write_qwp_varint(&mut payload, rows.len() as u64);
    write_qwp_varint(&mut payload, columns.len() as u64);
    payload.push(QWP_SCHEMA_MODE_FULL);

    for column in &columns {
        write_qwp_string(&mut payload, &column.name);
        payload.push(column.wire_type());
    }

    for column in &columns {
        column.encode_payload(&mut payload)?;
    }

    let payload_len: u32 = payload
        .len()
        .try_into()
        .map_err(|_| error::fmt!(InvalidApiCall, "QWP payload is too large"))?;

    let mut datagram = Vec::with_capacity(QWP_MESSAGE_HEADER_SIZE + payload.len());
    datagram.extend_from_slice(b"QWP1");
    datagram.push(QWP_VERSION_1);
    datagram.push(0);
    datagram.extend_from_slice(&(1u16).to_le_bytes());
    datagram.extend_from_slice(&payload_len.to_le_bytes());
    datagram.extend_from_slice(&payload);
    Ok(datagram)
}

fn build_batch_columns<'a>(rows: &'a [CommittedRow]) -> crate::Result<Vec<BatchColumn<'a>>> {
    let row_count = rows.len();
    let mut columns = Vec::<BatchColumn<'a>>::new();
    let mut indexes = HashMap::<String, usize>::new();

    for (row_idx, row) in rows.iter().enumerate() {
        for entry in &row.entries {
            add_batch_value(
                &mut columns,
                &mut indexes,
                row_count,
                row_idx,
                &entry.name,
                batch_value_ref(&entry.value),
                batch_kind_from_value(&entry.value),
                batch_nullable_from_value(&entry.value),
            )?;
        }

        if let Some(ts) = row.designated_ts {
            add_batch_value(
                &mut columns,
                &mut indexes,
                row_count,
                row_idx,
                QWP_DESIGNATED_TIMESTAMP_COLUMN_NAME,
                ColumnValueRef::Timestamp(ts.value),
                if ts.nanos {
                    ColumnKind::TimestampNanos
                } else {
                    ColumnKind::TimestampMicros
                },
                true,
            )?;
        }
    }

    for column in &mut columns {
        if column.values.iter().any(Option::is_none) && kind_supports_sparse_nulls(column.kind) {
            column.nullable = true;
        }
    }

    Ok(columns)
}

#[allow(clippy::too_many_arguments)]
fn add_batch_value<'a>(
    columns: &mut Vec<BatchColumn<'a>>,
    indexes: &mut HashMap<String, usize>,
    row_count: usize,
    row_idx: usize,
    name: &str,
    value: ColumnValueRef<'a>,
    kind: ColumnKind,
    nullable: bool,
) -> crate::Result<()> {
    if let Some(&column_idx) = indexes.get(name) {
        let column = &mut columns[column_idx];
        if column.kind != kind || column.nullable != nullable {
            return Err(error::fmt!(
                InvalidApiCall,
                "QWP/UDP column {:?} changes type within a batched table",
                name
            ));
        }
        column.values[row_idx] = Some(value);
        return Ok(());
    }

    let mut values = vec![None; row_count];
    values[row_idx] = Some(value);
    let column_idx = columns.len();
    columns.push(BatchColumn {
        name: name.to_owned(),
        kind,
        nullable,
        values,
    });
    indexes.insert(name.to_owned(), column_idx);
    Ok(())
}

fn batch_value_ref(value: &PendingValue) -> ColumnValueRef<'_> {
    match value {
        PendingValue::Bool(value) => ColumnValueRef::Bool(*value),
        PendingValue::Symbol(value) => ColumnValueRef::Symbol(value),
        PendingValue::I64(value) => ColumnValueRef::I64(*value),
        PendingValue::F64(value) => ColumnValueRef::F64(*value),
        PendingValue::String(value) => ColumnValueRef::String(value),
        PendingValue::Timestamp(value) => ColumnValueRef::Timestamp(value.value),
    }
}

fn batch_kind_from_value(value: &PendingValue) -> ColumnKind {
    match value {
        PendingValue::Bool(_) => ColumnKind::Bool,
        PendingValue::Symbol(_) => ColumnKind::Symbol,
        PendingValue::I64(_) => ColumnKind::I64,
        PendingValue::F64(_) => ColumnKind::F64,
        PendingValue::String(_) => ColumnKind::String,
        PendingValue::Timestamp(value) => {
            if value.nanos {
                ColumnKind::TimestampNanos
            } else {
                ColumnKind::TimestampMicros
            }
        }
    }
}

fn batch_nullable_from_value(value: &PendingValue) -> bool {
    matches!(
        value,
        PendingValue::Symbol(_) | PendingValue::String(_) | PendingValue::Timestamp(_)
    )
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

impl<'a> BatchColumn<'a> {
    fn wire_type(&self) -> u8 {
        let ty = match self.kind {
            ColumnKind::Bool => QWP_TYPE_BOOLEAN,
            ColumnKind::Symbol => QWP_TYPE_SYMBOL,
            ColumnKind::I64 => QWP_TYPE_LONG,
            ColumnKind::F64 => QWP_TYPE_DOUBLE,
            ColumnKind::String => QWP_TYPE_STRING,
            ColumnKind::TimestampMicros => QWP_TYPE_TIMESTAMP,
            ColumnKind::TimestampNanos => QWP_TYPE_TIMESTAMP_NANOS,
        };
        if self.nullable {
            ty | QWP_TYPE_NULLABLE_FLAG
        } else {
            ty
        }
    }

    fn encode_payload(&self, out: &mut Vec<u8>) -> crate::Result<()> {
        if self.nullable {
            write_null_bitmap(out, &self.values);
        }

        match self.kind {
            ColumnKind::Bool => self.encode_bool_payload(out),
            ColumnKind::Symbol => self.encode_symbol_payload(out),
            ColumnKind::I64 => self.encode_i64_payload(out),
            ColumnKind::F64 => self.encode_f64_payload(out),
            ColumnKind::String => self.encode_string_payload(out),
            ColumnKind::TimestampMicros | ColumnKind::TimestampNanos => {
                self.encode_timestamp_payload(out)
            }
        }
    }

    fn encode_bool_payload(&self, out: &mut Vec<u8>) -> crate::Result<()> {
        let mut packed = 0u8;
        let mut bit_idx = 0u8;
        if self.nullable {
            for value in self.values.iter().flatten() {
                let flag = match value {
                    ColumnValueRef::Bool(value) => *value,
                    _ => {
                        return Err(error::fmt!(
                            InvalidApiCall,
                            "internal QWP encoder type mismatch for boolean column"
                        ));
                    }
                };
                if flag {
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
            for value in &self.values {
                let flag = match value.unwrap_or(ColumnValueRef::Bool(false)) {
                    ColumnValueRef::Bool(value) => value,
                    _ => {
                        return Err(error::fmt!(
                            InvalidApiCall,
                            "internal QWP encoder type mismatch for boolean column"
                        ));
                    }
                };
                if flag {
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
        Ok(())
    }

    fn encode_i64_payload(&self, out: &mut Vec<u8>) -> crate::Result<()> {
        if self.nullable {
            for value in self.values.iter().flatten() {
                let encoded = match value {
                    ColumnValueRef::I64(value) => *value,
                    _ => {
                        return Err(error::fmt!(
                            InvalidApiCall,
                            "internal QWP encoder type mismatch for long column"
                        ));
                    }
                };
                out.extend_from_slice(&encoded.to_le_bytes());
            }
        } else {
            for value in &self.values {
                let encoded = match value.unwrap_or(ColumnValueRef::I64(i64::MIN)) {
                    ColumnValueRef::I64(value) => value,
                    _ => {
                        return Err(error::fmt!(
                            InvalidApiCall,
                            "internal QWP encoder type mismatch for long column"
                        ));
                    }
                };
                out.extend_from_slice(&encoded.to_le_bytes());
            }
        }
        Ok(())
    }

    fn encode_f64_payload(&self, out: &mut Vec<u8>) -> crate::Result<()> {
        if self.nullable {
            for value in self.values.iter().flatten() {
                let encoded = match value {
                    ColumnValueRef::F64(value) => *value,
                    _ => {
                        return Err(error::fmt!(
                            InvalidApiCall,
                            "internal QWP encoder type mismatch for double column"
                        ));
                    }
                };
                out.extend_from_slice(&encoded.to_le_bytes());
            }
        } else {
            for value in &self.values {
                let encoded = match value.unwrap_or(ColumnValueRef::F64(f64::NAN)) {
                    ColumnValueRef::F64(value) => value,
                    _ => {
                        return Err(error::fmt!(
                            InvalidApiCall,
                            "internal QWP encoder type mismatch for double column"
                        ));
                    }
                };
                out.extend_from_slice(&encoded.to_le_bytes());
            }
        }
        Ok(())
    }

    fn encode_timestamp_payload(&self, out: &mut Vec<u8>) -> crate::Result<()> {
        for value in self.values.iter().flatten() {
            let encoded = match value {
                ColumnValueRef::Timestamp(value) => *value,
                _ => {
                    return Err(error::fmt!(
                        InvalidApiCall,
                        "internal QWP encoder type mismatch for timestamp column"
                    ));
                }
            };
            out.extend_from_slice(&encoded.to_le_bytes());
        }
        Ok(())
    }

    fn encode_string_payload(&self, out: &mut Vec<u8>) -> crate::Result<()> {
        let mut offsets = Vec::new();
        offsets.push(0i32);
        let mut data = Vec::new();
        for value in self.values.iter().flatten() {
            let text = match value {
                ColumnValueRef::String(value) => *value,
                _ => {
                    return Err(error::fmt!(
                        InvalidApiCall,
                        "internal QWP encoder type mismatch for string column"
                    ));
                }
            };
            data.extend_from_slice(text.as_bytes());
            let offset: i32 = data.len().try_into().map_err(|_| {
                error::fmt!(InvalidApiCall, "QWP string payload exceeds i32 length")
            })?;
            offsets.push(offset);
        }
        for offset in offsets {
            out.extend_from_slice(&offset.to_le_bytes());
        }
        out.extend_from_slice(&data);
        Ok(())
    }

    fn encode_symbol_payload(&self, out: &mut Vec<u8>) -> crate::Result<()> {
        let mut dict = Vec::<String>::new();
        let mut dict_indexes = HashMap::<String, usize>::new();
        let mut row_indexes = Vec::<usize>::new();

        for value in self.values.iter().flatten() {
            let symbol = match value {
                ColumnValueRef::Symbol(value) => *value,
                _ => {
                    return Err(error::fmt!(
                        InvalidApiCall,
                        "internal QWP encoder type mismatch for symbol column"
                    ));
                }
            };
            let idx = if let Some(idx) = dict_indexes.get(symbol) {
                *idx
            } else {
                let idx = dict.len();
                let key = symbol.to_owned();
                dict.push(key.clone());
                dict_indexes.insert(key, idx);
                idx
            };
            row_indexes.push(idx);
        }

        write_qwp_varint(out, dict.len() as u64);
        for symbol in &dict {
            write_qwp_string(out, symbol);
        }
        for idx in row_indexes {
            write_qwp_varint(out, idx as u64);
        }
        Ok(())
    }
}

fn write_null_bitmap(out: &mut Vec<u8>, values: &[Option<ColumnValueRef<'_>>]) {
    let mut packed = 0u8;
    let mut bit_idx = 0u8;
    for value in values {
        if value.is_none() {
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

fn unsupported_qwp_call(method: &str) -> crate::Error {
    error::fmt!(
        InvalidApiCall,
        "QWP/UDP support for `{}` is not implemented yet.",
        method
    )
}

fn hash_name(name: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    name.hash(&mut hasher);
    hasher.finish()
}

fn pending_timestamp(timestamp: Timestamp) -> PendingTimestamp {
    match timestamp {
        Timestamp::Micros(ts) => PendingTimestamp {
            value: ts.as_i64(),
            nanos: false,
        },
        Timestamp::Nanos(ts) => PendingTimestamp {
            value: ts.as_i64(),
            nanos: true,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingress::{TimestampMicros, TimestampNanos};

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
            let estimated = estimated_row_group_len(rows).unwrap();
            let actual = encode_row_group(rows).unwrap().len();
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
            let estimated = estimated_row_group_len(rows).unwrap();
            let actual = encode_row_group(rows).unwrap().len();
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

        assert!(buf.len() > 0);
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
}
