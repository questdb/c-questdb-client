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

use std::collections::HashMap;
use std::hash::BuildHasher;

use crate::ingress::buffer::decode_qwp_varint;
use crate::ingress::{MAX_ARRAY_DIMS, MAX_NDARRAY_LEAF_ELEMS};
use crate::{Result, error};

const MAGIC: &[u8; 4] = b"QSR1";
const HEADER_LEN: usize = 7;
const MAX_SYMBOLS: usize = 2_000_000;
const MAX_MERGED_ROWS: usize = 1_000_000;

pub(crate) fn is_record(payload: &[u8]) -> bool {
    payload.starts_with(MAGIC)
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct RecordInfo {
    pub(crate) rows: usize,
    pub(crate) defer_commit: bool,
}

#[cfg(test)]
pub(crate) fn record_info(payload: &[u8]) -> Result<RecordInfo> {
    let mut reader = RecordReader::new(payload)?;
    let mut rows = 0usize;
    while let Some(table) = reader.next_table(None)? {
        rows = rows.checked_add(table.rows).ok_or_else(invalid_record)?;
        for column in table.columns(&mut reader.reader, None) {
            let column = column?;
            ColumnView::parse(column.kind, column.body, table.rows)?;
        }
    }
    Ok(RecordInfo {
        rows,
        defer_commit: reader.defer_commit,
    })
}

fn invalid_record() -> crate::Error {
    error::fmt!(ProtocolError, "invalid store-and-forward record")
}

fn size_error(size: usize, limit: usize) -> crate::Error {
    error::fmt!(
        BatchTooLarge,
        "SF record requires a QWP frame of {} bytes (limit {})",
        size,
        limit
    )
}

#[derive(Clone, Copy)]
struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    #[inline(always)]
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let (head, tail) = self
            .bytes
            .split_at_checked(len)
            .ok_or_else(invalid_record)?;
        self.bytes = tail;
        Ok(head)
    }

    #[inline(always)]
    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    #[inline(always)]
    fn varint(&mut self) -> Result<usize> {
        if let Some(&byte) = self.bytes.first()
            && byte < 0x80
        {
            self.bytes = &self.bytes[1..];
            return Ok(byte as usize);
        }
        let (value, end) = decode_qwp_varint(self.bytes, 0).ok_or_else(invalid_record)?;
        self.take(end)?;
        usize::try_from(value).map_err(|_| invalid_record())
    }

    #[inline(always)]
    fn string(&mut self) -> Result<&'a [u8]> {
        let len = self.varint()?;
        self.take(len)
    }

    #[inline(always)]
    fn u32(&mut self) -> Result<usize> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as usize)
    }
}

struct RecordReader<'a> {
    reader: Reader<'a>,
    tables: usize,
    defer_commit: bool,
}

impl<'a> RecordReader<'a> {
    fn new(payload: &'a [u8]) -> Result<Self> {
        if payload.len() < HEADER_LEN || !is_record(payload) || payload[4] > 1 {
            return Err(invalid_record());
        }
        let tables = u16::from_le_bytes([payload[5], payload[6]]) as usize;
        if tables > (payload.len() - HEADER_LEN) / 3 {
            return Err(invalid_record());
        }
        Ok(Self {
            reader: Reader {
                bytes: &payload[HEADER_LEN..],
            },
            tables,
            defer_commit: payload[4] != 0,
        })
    }

    fn next_table(&mut self, cached: Option<&Table>) -> Result<Option<TableView<'a>>> {
        if self.tables == 0 {
            if !self.reader.bytes.is_empty() {
                return Err(invalid_record());
            }
            return Ok(None);
        }
        let start = self.reader.bytes;
        let (name, rows, count, schema, cached_schema) = if let Some(cached) = cached
            && !cached.record_header.is_empty()
            && start.starts_with(&cached.record_header)
        {
            let name_start = cached.record_name_offset;
            self.reader.take(cached.record_header.len())?;
            (
                &start[name_start..][..cached.name.len()],
                cached.record_rows,
                cached.columns.len(),
                Reader {
                    bytes: &start[cached.record_schema_offset..],
                },
                true,
            )
        } else {
            let name = self.reader.string()?;
            validate_name(name, false)?;
            let rows = self.reader.varint()?;
            if rows == 0 || rows > u32::MAX as usize {
                return Err(invalid_record());
            }
            let count = self.reader.varint()?;
            if count == 0 || count > self.reader.bytes.len() / 7 {
                return Err(invalid_record());
            }
            let schema = self.reader;
            for _ in 0..count {
                validate_name(self.reader.string()?, true)?;
                validate_kind(self.reader.byte()?)?;
            }
            (name, rows, count, schema, false)
        };
        let header = &start[..start.len() - self.reader.bytes.len()];

        self.tables -= 1;
        Ok(Some(TableView {
            name,
            rows,
            count,
            schema,
            header,
            cached_schema,
        }))
    }
}

fn validate_name(name: &[u8], allow_empty: bool) -> Result<()> {
    if name.len() > 127 || (!allow_empty && name.is_empty()) || std::str::from_utf8(name).is_err() {
        return Err(invalid_record());
    }
    Ok(())
}

fn validate_kind(kind: u8) -> Result<()> {
    if matches!(kind, 1..=7 | 9..=24) {
        Ok(())
    } else {
        Err(invalid_record())
    }
}

#[derive(Clone, Copy)]
struct TableView<'a> {
    name: &'a [u8],
    rows: usize,
    count: usize,
    schema: Reader<'a>,
    header: &'a [u8],
    cached_schema: bool,
}

impl<'a> TableView<'a> {
    fn columns<'b>(
        self,
        reader: &'b mut Reader<'a>,
        cached: Option<&'b Table>,
    ) -> impl Iterator<Item = Result<ColumnRecord<'a>>> + 'b
    where
        'a: 'b,
    {
        let mut schema = self.schema;
        (0..self.count).map(move |index| {
            let (name, kind) = if self.cached_schema {
                let column = &cached.expect("matched cached schema").columns[index];
                (
                    &self.header[column.record_name_offset..][..column.name.len()],
                    column.kind,
                )
            } else {
                (schema.string()?, schema.byte()?)
            };
            let size = reader.u32()?;
            Ok(ColumnRecord {
                name,
                kind,
                body: reader.take(size)?,
            })
        })
    }
}

struct ColumnRecord<'a> {
    name: &'a [u8],
    kind: u8,
    body: &'a [u8],
}

struct ColumnView<'a> {
    bitmap: &'a [u8],
    values: usize,
    metadata: Option<u8>,
    data: &'a [u8],
    offsets: &'a [u8],
    symbols: &'a [u8],
    symbol_count: usize,
}

impl<'a> ColumnView<'a> {
    fn parse(kind: u8, body: &'a [u8], rows: usize) -> Result<Self> {
        let mut reader = Reader { bytes: body };
        let bitmap = match reader.byte()? {
            0 => &[][..],
            1 => reader.take(rows.div_ceil(8))?,
            _ => return Err(invalid_record()),
        };
        let nulls = if bitmap.is_empty() {
            0
        } else {
            if !rows.is_multiple_of(8) && bitmap[bitmap.len() - 1] >> (rows % 8) != 0 {
                return Err(invalid_record());
            }
            bitmap.iter().map(|byte| byte.count_ones() as usize).sum()
        };
        let values = rows.checked_sub(nulls).ok_or_else(invalid_record)?;
        let mut result = Self {
            bitmap,
            values,
            metadata: None,
            data: &[],
            offsets: &[],
            symbols: &[],
            symbol_count: 0,
        };
        match kind {
            1 => result.data = reader.take(values.div_ceil(8))?,
            2 => result.data = reader.take(values)?,
            3 | 22 => {
                result.data = reader.take(values.checked_mul(2).ok_or_else(invalid_record)?)?
            }
            4 | 6 | 24 => {
                result.data = reader.take(values.checked_mul(4).ok_or_else(invalid_record)?)?
            }
            5 | 7 | 10 | 11 | 16 => {
                result.data = reader.take(values.checked_mul(8).ok_or_else(invalid_record)?)?
            }
            12 => result.data = reader.take(values.checked_mul(16).ok_or_else(invalid_record)?)?,
            13 => result.data = reader.take(values.checked_mul(32).ok_or_else(invalid_record)?)?,
            9 => {
                let count = reader.varint()?;
                if count > MAX_SYMBOLS || count > reader.bytes.len() {
                    return Err(invalid_record());
                }
                let start = reader.bytes;
                for _ in 0..count {
                    if std::str::from_utf8(reader.string()?).is_err() {
                        return Err(invalid_record());
                    }
                }
                result.symbols = &start[..start.len() - reader.bytes.len()];
                result.symbol_count = count;
                let start = reader.bytes;
                if values > start.len() {
                    return Err(invalid_record());
                }
                for _ in 0..values {
                    if reader.varint()? >= count {
                        return Err(invalid_record());
                    }
                }
                result.data = &start[..start.len() - reader.bytes.len()];
            }
            14 => {
                let bits = reader.varint()?;
                if !(1..=60).contains(&bits) {
                    return Err(invalid_record());
                }
                result.metadata = Some(bits as u8);
                result.data = reader.take(
                    values
                        .checked_mul(bits.div_ceil(8))
                        .ok_or_else(invalid_record)?,
                )?;
            }
            15 | 23 => {
                let count = values.checked_add(1).ok_or_else(invalid_record)?;
                result.offsets = reader.take(count.checked_mul(4).ok_or_else(invalid_record)?)?;
                let mut previous = 0usize;
                for (index, bytes) in result.offsets.chunks_exact(4).enumerate() {
                    let offset = u32::from_le_bytes(bytes.try_into().unwrap()) as usize;
                    if (index == 0 && offset != 0)
                        || offset < previous
                        || offset > reader.bytes.len()
                    {
                        return Err(invalid_record());
                    }
                    if kind == 15 && std::str::from_utf8(&reader.bytes[previous..offset]).is_err() {
                        return Err(invalid_record());
                    }
                    previous = offset;
                }
                result.data = reader.take(previous)?;
            }
            17 | 18 => {
                let start = reader.bytes;
                if values > start.len() {
                    return Err(invalid_record());
                }
                for _ in 0..values {
                    let dimensions = reader.byte()? as usize;
                    if dimensions == 0 || dimensions > MAX_ARRAY_DIMS {
                        return Err(invalid_record());
                    }
                    let mut elements = 1usize;
                    for _ in 0..dimensions {
                        elements = elements
                            .checked_mul(reader.u32()?)
                            .ok_or_else(invalid_record)?;
                    }
                    if elements > MAX_NDARRAY_LEAF_ELEMS {
                        return Err(invalid_record());
                    }
                    reader.take(elements.checked_mul(8).ok_or_else(invalid_record)?)?;
                }
                result.data = &start[..start.len() - reader.bytes.len()];
            }
            19..=21 => {
                let scale = reader.byte()?;
                let width = match kind {
                    19 => 8,
                    20 => 16,
                    _ => 32,
                };
                // Wire width limits the mantissa, not the number of decimal places.
                if scale > 76 {
                    return Err(invalid_record());
                }
                result.metadata = Some(scale);
                result.data = reader.take(values.checked_mul(width).ok_or_else(invalid_record)?)?;
            }
            _ => return Err(invalid_record()),
        }
        if !reader.bytes.is_empty() {
            return Err(invalid_record());
        }
        Ok(result)
    }
}

#[derive(Debug, Default)]
pub(crate) struct RecordBatch {
    tables: Vec<Table>,
    records: usize,
    rows: usize,
    defer_commit: bool,
    table_plan: Vec<TablePlan>,
    column_plan: Vec<ColumnPlan>,
}

#[derive(Debug, Default)]
struct Table {
    name: Vec<u8>,
    rows: usize,
    columns: Vec<Column>,
    record_header: Vec<u8>,
    record_rows: usize,
    record_name_offset: usize,
    record_schema_offset: usize,
}

#[derive(Debug, Default)]
struct Column {
    name: Vec<u8>,
    kind: u8,
    record_name_offset: usize,
    metadata: Option<u8>,
    rows: usize,
    values: usize,
    bitmap: Vec<u8>,
    has_bitmap: bool,
    data: Vec<u8>,
    offsets: Vec<u32>,
    symbols: Vec<Symbol>,
    symbol_data: Vec<u8>,
    symbol_lookup: HashMap<u64, usize>,
    symbol_bytes: usize,
    local_ids: Vec<usize>,
}

#[derive(Debug)]
struct Symbol {
    start: usize,
    len: usize,
    next: Option<usize>,
}

#[derive(Debug, Clone, Copy)]
struct Span {
    start: usize,
    len: usize,
}

impl Span {
    fn new(payload: &[u8], bytes: &[u8]) -> Self {
        Self {
            start: if bytes.is_empty() {
                0
            } else {
                bytes.as_ptr() as usize - payload.as_ptr() as usize
            },
            len: bytes.len(),
        }
    }

    fn get(self, payload: &[u8]) -> &[u8] {
        &payload[self.start..self.start + self.len]
    }
}

#[derive(Debug)]
struct TablePlan {
    name: Span,
    header: Span,
    schema_offset: usize,
    rows: usize,
    first_column: usize,
    columns: usize,
}

#[derive(Debug)]
struct ColumnPlan {
    name: Span,
    kind: u8,
    bitmap: Span,
    values: usize,
    metadata: Option<u8>,
    data: Span,
    offsets: Span,
    symbols: Span,
    symbol_count: usize,
}

impl ColumnPlan {
    fn new(payload: &[u8], column: &ColumnRecord<'_>, view: &ColumnView<'_>) -> Self {
        Self {
            name: Span::new(payload, column.name),
            kind: column.kind,
            bitmap: Span::new(payload, view.bitmap),
            values: view.values,
            metadata: view.metadata,
            data: Span::new(payload, view.data),
            offsets: Span::new(payload, view.offsets),
            symbols: Span::new(payload, view.symbols),
            symbol_count: view.symbol_count,
        }
    }

    fn view<'a>(&self, payload: &'a [u8]) -> ColumnView<'a> {
        ColumnView {
            bitmap: self.bitmap.get(payload),
            values: self.values,
            metadata: self.metadata,
            data: self.data.get(payload),
            offsets: self.offsets.get(payload),
            symbols: self.symbols.get(payload),
            symbol_count: self.symbol_count,
        }
    }
}

impl RecordBatch {
    pub(crate) fn new() -> Self {
        Self::default()
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.records == 0
    }
    pub(crate) fn rows(&self) -> usize {
        self.rows
    }
    #[cfg(test)]
    pub(crate) fn defer_commit(&self) -> bool {
        self.defer_commit
    }

    pub(crate) fn clear(&mut self) {
        self.records = 0;
        self.rows = 0;
        self.defer_commit = false;
        for table in &mut self.tables {
            table.rows = 0;
            for column in &mut table.columns {
                column.clear();
            }
        }
    }

    pub(crate) fn try_append(
        &mut self,
        payload: &[u8],
        max_frame_bytes: usize,
        max_rows: usize,
    ) -> Result<bool> {
        let mut reader = RecordReader::new(payload)?;
        let max_frame_bytes = max_frame_bytes.min(u32::MAX as usize);
        let table_count = reader.tables;
        self.table_plan.clear();
        self.column_plan.clear();
        let mut compatible = self.is_empty() || table_count == self.tables.len();
        let mut rows = 0usize;
        let mut frame_size = 12usize;
        let mut table_index = 0;
        while let Some(table) = reader.next_table(self.tables.get(table_index))? {
            rows = rows.checked_add(table.rows).ok_or_else(invalid_record)?;
            self.table_plan.push(TablePlan {
                name: Span::new(payload, table.name),
                header: Span::new(payload, table.header),
                schema_offset: table.schema.bytes.as_ptr() as usize
                    - table.header.as_ptr() as usize,
                rows: table.rows,
                first_column: self.column_plan.len(),
                columns: table.count,
            });
            let previous = if self.is_empty() {
                None
            } else {
                self.tables.get(table_index)
            };
            if !table.cached_schema
                && previous
                    .is_some_and(|old| old.name != table.name || old.columns.len() != table.count)
            {
                compatible = false;
            }
            let total_rows = previous
                .map_or(0, |old| old.rows)
                .checked_add(table.rows)
                .ok_or_else(invalid_record)?;
            if total_rows > u32::MAX as usize || previous.is_some() && total_rows > MAX_MERGED_ROWS
            {
                compatible = false;
            }
            frame_size = frame_size.saturating_add(
                string_size(table.name.len()) + varint_size(total_rows) + varint_size(table.count),
            );
            for (column_index, column) in table
                .columns(&mut reader.reader, self.tables.get(table_index))
                .enumerate()
            {
                let column = column?;
                let view = ColumnView::parse(column.kind, column.body, table.rows)?;
                self.column_plan
                    .push(ColumnPlan::new(payload, &column, &view));
                let old = previous.and_then(|old| old.columns.get(column_index));
                if old.is_some_and(|old| {
                    (!table.cached_schema && (old.name != column.name || old.kind != column.kind))
                        || old.metadata != view.metadata
                }) {
                    compatible = false;
                }
                let projected = Column::projected_size(old, &view, column.kind, total_rows);
                frame_size =
                    frame_size.saturating_add(string_size(column.name.len()) + 1 + projected);
                if column.kind == 9
                    && old
                        .map_or(0, |old| old.symbols.len())
                        .saturating_add(view.symbol_count)
                        > MAX_SYMBOLS
                {
                    compatible = false;
                }
            }
            table_index += 1;
        }
        if !self.is_empty()
            && (!compatible
                || frame_size > max_frame_bytes
                || (max_rows > 0 && self.rows.saturating_add(rows) > max_rows))
        {
            return Ok(false);
        }
        if frame_size > max_frame_bytes {
            return Err(size_error(frame_size, max_frame_bytes));
        }
        self.tables.truncate(table_count);
        self.tables.resize_with(table_count, Table::default);
        for (target, table) in self.tables.iter_mut().zip(&self.table_plan) {
            if self.records == 0 {
                target.name.clear();
                target.name.extend_from_slice(table.name.get(payload));
                target.record_header.clear();
                target
                    .record_header
                    .extend_from_slice(table.header.get(payload));
                target.record_rows = table.rows;
                target.record_name_offset = table.name.start - table.header.start;
                target.record_schema_offset = table.schema_offset;
                target.columns.truncate(table.columns);
                target.columns.resize_with(table.columns, Column::default);
            }
            let columns = &self.column_plan[table.first_column..][..table.columns];
            for (target, column) in target.columns.iter_mut().zip(columns) {
                let view = column.view(payload);
                if self.records == 0 {
                    target.clear();
                    target.name.clear();
                    target.name.extend_from_slice(column.name.get(payload));
                    target.kind = column.kind;
                    target.record_name_offset = if column.name.len == 0 {
                        0
                    } else {
                        column.name.start - table.header.start
                    };
                    target.metadata = view.metadata;
                }
                target.append(&view, table.rows);
            }
            target.rows += table.rows;
        }
        self.rows += rows;
        self.records += 1;
        self.defer_commit = reader.defer_commit;
        Ok(true)
    }

    pub(crate) fn encode_frame(&self, out: &mut Vec<u8>) -> Result<()> {
        out.clear();
        out.extend_from_slice(b"QWP1");
        out.push(1);
        out.push(u8::from(self.defer_commit));
        out.extend_from_slice(&(self.tables.len() as u16).to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        for table in &self.tables {
            write_qwp_bytes(out, &table.name);
            write_qwp_varint(out, table.rows as u64);
            write_qwp_varint(out, table.columns.len() as u64);
            for column in &table.columns {
                write_qwp_bytes(out, &column.name);
                out.push(column.kind);
            }
            for column in &table.columns {
                column.encode(out);
            }
        }
        let length =
            u32::try_from(out.len() - 12).map_err(|_| size_error(out.len(), u32::MAX as usize))?;
        out[8..12].copy_from_slice(&length.to_le_bytes());
        Ok(())
    }
}

impl Column {
    fn clear(&mut self) {
        self.rows = 0;
        self.values = 0;
        self.has_bitmap = false;
        self.bitmap.clear();
        self.data.clear();
        self.offsets.clear();
        self.symbols.clear();
        self.symbol_data.clear();
        self.symbol_lookup.clear();
        self.symbol_bytes = 0;
        self.local_ids.clear();
    }

    fn projected_size(old: Option<&Self>, view: &ColumnView<'_>, kind: u8, rows: usize) -> usize {
        let bitmap = if !view.bitmap.is_empty() || old.is_some_and(|old| old.has_bitmap) {
            rows.div_ceil(8)
        } else {
            0
        };
        let prefix = 1 + bitmap + usize::from(view.metadata.is_some());
        let old_data = old.map_or(0, |old| old.data.len());
        let data = match kind {
            1 => old
                .map_or(0, |old| old.values)
                .saturating_add(view.values)
                .div_ceil(8),
            9 => {
                let symbols = old
                    .map_or(0, |old| old.symbols.len())
                    .saturating_add(view.symbol_count);
                varint_size(symbols)
                    + old.map_or(0, |old| old.symbol_bytes)
                    + view.symbols.len()
                    + old_data
                    + if old.is_none() {
                        view.data.len()
                    } else {
                        view.values
                            .saturating_mul(varint_size(symbols.saturating_sub(1)))
                    }
            }
            15 | 23 => old_data.saturating_add(view.data.len()).saturating_add(
                old.map_or(0, |old| old.values)
                    .saturating_add(view.values)
                    .saturating_add(1)
                    .saturating_mul(4),
            ),
            _ => old_data.saturating_add(view.data.len()),
        };
        prefix.saturating_add(data)
    }

    fn append(&mut self, view: &ColumnView<'_>, rows: usize) {
        if !view.bitmap.is_empty() || self.has_bitmap {
            append_bits(&mut self.bitmap, self.rows, view.bitmap, rows);
            self.has_bitmap = true;
        }
        match self.kind {
            1 => append_bits(&mut self.data, self.values, view.data, view.values),
            9 => {
                self.local_ids.clear();
                let mut symbols = Reader {
                    bytes: view.symbols,
                };
                for _ in 0..view.symbol_count {
                    let value = symbols.string().expect("validated record symbol");
                    let hash = self.symbol_lookup.hasher().hash_one(value);
                    let mut cursor = self.symbol_lookup.get(&hash).copied();
                    let id = loop {
                        let Some(index) = cursor else {
                            let id = self.symbols.len();
                            self.symbol_bytes += string_size(value.len());
                            self.symbols.push(Symbol {
                                start: self.symbol_data.len(),
                                len: value.len(),
                                next: self.symbol_lookup.insert(hash, id),
                            });
                            self.symbol_data.extend_from_slice(value);
                            break id;
                        };
                        let symbol = &self.symbols[index];
                        if &self.symbol_data[symbol.start..][..symbol.len] == value {
                            break index;
                        }
                        cursor = symbol.next;
                    };
                    self.local_ids.push(id);
                }
                let mut ids = Reader { bytes: view.data };
                for _ in 0..view.values {
                    let local = ids.varint().expect("validated record symbol ID");
                    write_qwp_varint(&mut self.data, self.local_ids[local] as u64);
                }
            }
            15 | 23 => {
                if self.offsets.is_empty() {
                    self.offsets.push(0);
                }
                let base = self.data.len() as u32;
                for offset in view.offsets.chunks_exact(4).skip(1) {
                    self.offsets
                        .push(base + u32::from_le_bytes(offset.try_into().unwrap()));
                }
                self.data.extend_from_slice(view.data);
            }
            _ => self.data.extend_from_slice(view.data),
        }
        self.rows += rows;
        self.values += view.values;
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.push(u8::from(self.has_bitmap));
        if self.has_bitmap {
            out.extend_from_slice(&self.bitmap);
        }
        if let Some(metadata) = self.metadata {
            out.push(metadata);
        }
        if self.kind == 9 {
            write_qwp_varint(out, self.symbols.len() as u64);
            for symbol in &self.symbols {
                write_qwp_bytes(out, &self.symbol_data[symbol.start..][..symbol.len]);
            }
        }
        for offset in &self.offsets {
            out.extend_from_slice(&offset.to_le_bytes());
        }
        out.extend_from_slice(&self.data);
    }
}

fn append_bits(out: &mut Vec<u8>, previous: usize, bits: &[u8], count: usize) {
    out.resize((previous + count).div_ceil(8), 0);
    if bits.is_empty() {
        return;
    }
    let shift = previous % 8;
    let offset = previous / 8;
    for (index, &byte) in bits.iter().enumerate() {
        let byte = if index + 1 == bits.len() && !count.is_multiple_of(8) {
            byte & ((1 << (count % 8)) - 1)
        } else {
            byte
        };
        out[offset + index] |= byte << shift;
        if shift != 0 && offset + index + 1 < out.len() {
            out[offset + index + 1] |= byte >> (8 - shift);
        }
    }
}

fn varint_size(value: usize) -> usize {
    ((usize::BITS - value.leading_zeros()).max(1) as usize).div_ceil(7)
}

fn string_size(length: usize) -> usize {
    varint_size(length) + length
}

fn write_qwp_varint(out: &mut Vec<u8>, mut value: u64) {
    while value > 0x7f {
        out.push(value as u8 | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn write_qwp_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    write_qwp_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingress::buffer::QwpWsColumnarBuffer;
    use crate::ingress::{DecimalView, TimestampMicros, TimestampNanos};
    use crate::tests::qwp_decode::{DecodedValue, decode_datagram};

    #[test]
    fn merging_respects_the_server_table_row_limit() {
        fn boolean_record(rows: usize) -> Vec<u8> {
            let mut bytes = b"QSR1\x00\x01\x00".to_vec();
            write_qwp_bytes(&mut bytes, b"trades");
            write_qwp_varint(&mut bytes, rows as u64);
            write_qwp_varint(&mut bytes, 1);
            write_qwp_bytes(&mut bytes, b"value");
            bytes.push(1);
            let body_len = 1 + rows.div_ceil(8);
            bytes.extend_from_slice(&(body_len as u32).to_le_bytes());
            bytes.resize(bytes.len() + body_len, 0);
            bytes
        }
        let half = boolean_record(MAX_MERGED_ROWS / 2);
        let mut batch = RecordBatch::new();
        assert!(batch.try_append(&half, usize::MAX, 0).unwrap());
        assert!(batch.try_append(&half, usize::MAX, 0).unwrap());
        assert_eq!(batch.rows(), MAX_MERGED_ROWS);
        assert!(!batch.try_append(&boolean_record(1), usize::MAX, 0).unwrap());
        assert_eq!(batch.rows(), MAX_MERGED_ROWS);
    }

    fn record(buffer: &QwpWsColumnarBuffer) -> Vec<u8> {
        let mut out = Vec::new();
        buffer.encode_sfa_record(&mut out, false).unwrap();
        out
    }

    fn frame(batch: &RecordBatch) -> Vec<u8> {
        let mut out = Vec::new();
        batch.encode_frame(&mut out).unwrap();
        out
    }

    fn append_all_types(buffer: &mut QwpWsColumnarBuffer, value: i64) {
        buffer
            .table("trades")
            .unwrap()
            .symbol("sym", if value % 2 == 0 { "alpha" } else { "beta" })
            .unwrap()
            .column_bool("bool", value % 2 == 0)
            .unwrap()
            .column_i8("byte", value as i8)
            .unwrap()
            .column_i16("short", value as i16)
            .unwrap()
            .column_i32("int", value as i32)
            .unwrap()
            .column_i64("long", value)
            .unwrap()
            .column_f32("float", value as f32 + 0.5)
            .unwrap()
            .column_f64("double", value as f64 + 0.5)
            .unwrap()
            .column_str("str", format!("row-{value}"))
            .unwrap()
            .column_dec64("dec64", "12.25")
            .unwrap()
            .column_dec128("dec128", "12.25")
            .unwrap()
            .column_dec("dec256", "12.25")
            .unwrap()
            .column_arr("doubles", &vec![1.0_f64, value as f64])
            .unwrap()
            .column_arr("longs", &vec![1_i64, value])
            .unwrap()
            .column_ts("micros", TimestampMicros::new(value))
            .unwrap()
            .column_ts("nanos", TimestampNanos::new(value))
            .unwrap()
            .column_uuid("uuid", value as u64, 9)
            .unwrap()
            .column_long256("long256", &[value as u8; 32])
            .unwrap()
            .column_ipv4("ip", value as u32)
            .unwrap()
            .column_date("date", value)
            .unwrap()
            .column_char("char", value as u16)
            .unwrap()
            .column_binary("binary", &[value as u8, 255])
            .unwrap()
            .column_geohash("geo", (value % 31) as u64, 5)
            .unwrap()
            .at(TimestampNanos::new(value))
            .unwrap();
    }

    #[test]
    fn merges_all_buffer_types_like_one_explicit_batch() {
        let mut single = QwpWsColumnarBuffer::new(127);
        let mut expected = QwpWsColumnarBuffer::new(127);
        let mut batch = RecordBatch::new();
        for value in 0..19 {
            append_all_types(&mut single, value);
            append_all_types(&mut expected, value);
            assert!(batch.try_append(&record(&single), 1 << 20, 1000).unwrap());
            single.clear();
        }
        let mut expected_batch = RecordBatch::new();
        assert!(
            expected_batch
                .try_append(&record(&expected), 1 << 20, 1000)
                .unwrap()
        );
        assert_eq!(frame(&batch), frame(&expected_batch));
        let decoded = decode_datagram(&frame(&batch)).unwrap();
        assert_eq!(decoded.table.row_count, 19);
        assert_eq!(decoded.table.columns.len(), 24);
        assert_eq!(
            decoded.table.rows[18][0],
            DecodedValue::Symbol("alpha".into())
        );
        assert_eq!(decoded.table.rows[18][23], DecodedValue::TimestampNanos(18));
    }

    #[test]
    fn decimal_wire_width_does_not_limit_supported_scale() {
        for scale in [19_u8, 39, 76] {
            let mut batch = RecordBatch::new();
            let mut buffer = QwpWsColumnarBuffer::new(127);
            for value in 1_u8..=2 {
                buffer
                    .table("decimals")
                    .unwrap()
                    .column_dec64(
                        "d64",
                        DecimalView::try_new_scaled(scale.into(), vec![value]).unwrap(),
                    )
                    .unwrap()
                    .column_dec128(
                        "d128",
                        DecimalView::try_new_scaled(scale.into(), vec![value]).unwrap(),
                    )
                    .unwrap()
                    .column_dec(
                        "d256",
                        DecimalView::try_new_scaled(scale.into(), vec![value]).unwrap(),
                    )
                    .unwrap()
                    .at(TimestampNanos::new(value.into()))
                    .unwrap();
                assert!(batch.try_append(&record(&buffer), 4096, 1000).unwrap());
                buffer.clear();
            }
            let decoded = decode_datagram(&frame(&batch)).unwrap();
            for (index, row) in decoded.table.rows.iter().enumerate() {
                for value in &row[..3] {
                    assert_eq!(
                        *value,
                        DecodedValue::Decimal {
                            scale,
                            unscaled_be: vec![(index + 1) as u8],
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn unsupported_decimal_scale_does_not_change_batch() {
        for (kind, width) in [(19, 8), (20, 16), (21, 32)] {
            let mut batch = RecordBatch::new();
            let mut body = vec![0; 2 + width];
            body[1] = 76;
            batch
                .try_append(&one_column(kind, 1, &body), 4096, 1000)
                .unwrap();
            let saved = frame(&batch);
            for scale in [77, 255] {
                body[1] = scale;
                assert!(
                    batch
                        .try_append(&one_column(kind, 1, &body), 4096, 1000)
                        .is_err()
                );
                assert_eq!(frame(&batch), saved);
            }
        }
    }

    #[test]
    fn combines_unaligned_sparse_bitmaps_and_variable_offsets() {
        let mut single = QwpWsColumnarBuffer::new(127);
        let mut expected = QwpWsColumnarBuffer::new(127);
        let mut batch = RecordBatch::new();
        for value in 0..37 {
            for buffer in [&mut single, &mut expected] {
                buffer.table("trades").unwrap();
                if value % 3 == 0 {
                    buffer.symbol("sym", "xyz").unwrap();
                    buffer.column_str("text", "你好").unwrap();
                    buffer.column_binary("bytes", &[0, 128, 255]).unwrap();
                    buffer.column_uuid("uuid", value as u64, 5).unwrap();
                }
                buffer.column_i64("qty", value).unwrap();
                buffer.at(TimestampNanos::new(value)).unwrap();
            }
            assert!(batch.try_append(&record(&single), 1 << 20, 1000).unwrap());
            single.clear();
        }
        let mut expected_batch = RecordBatch::new();
        expected_batch
            .try_append(&record(&expected), 1 << 20, 1000)
            .unwrap();
        assert_eq!(frame(&batch), frame(&expected_batch));
        let decoded = decode_datagram(&frame(&batch)).unwrap();
        assert_eq!(decoded.table.rows[1][0], DecodedValue::Null);
        assert_eq!(
            decoded.table.rows[36][1],
            DecodedValue::String("你好".into())
        );
    }

    fn one_column(kind: u8, rows: usize, body: &[u8]) -> Vec<u8> {
        let mut out = b"QSR1\0\x01\0".to_vec();
        write_qwp_bytes(&mut out, b"t");
        write_qwp_varint(&mut out, rows as u64);
        write_qwp_varint(&mut out, 1);
        write_qwp_bytes(&mut out, b"c");
        out.push(kind);
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn sparse_boolean_values_are_repacked_independently_of_nulls() {
        let mut batch = RecordBatch::new();
        for _ in 0..9 {
            batch
                .try_append(&one_column(1, 3, &[1, 0b010, 0b01]), 4096, 1000)
                .unwrap();
        }
        let decoded = decode_datagram(&frame(&batch)).unwrap();
        for rows in decoded.table.rows.chunks_exact(3) {
            assert_eq!(
                rows,
                &[
                    vec![DecodedValue::Bool(true)],
                    vec![DecodedValue::Null],
                    vec![DecodedValue::Bool(false)]
                ]
            );
        }
    }

    #[test]
    fn incompatible_schema_and_metadata_preserve_current_batch() {
        let mut batch = RecordBatch::new();
        let mut body = vec![0, 2];
        body.extend_from_slice(&125_i64.to_le_bytes());
        assert!(
            batch
                .try_append(&one_column(19, 1, &body), 4096, 1000)
                .unwrap()
        );
        let saved = frame(&batch);
        body[1] = 3;
        assert!(
            !batch
                .try_append(&one_column(19, 1, &body), 4096, 1000)
                .unwrap()
        );
        assert!(
            !batch
                .try_append(&one_column(1, 1, &[0, 1]), 4096, 1000)
                .unwrap()
        );
        assert_eq!(frame(&batch), saved);
        batch.clear();
        assert!(
            batch
                .try_append(&one_column(19, 1, &body), 4096, 1000)
                .unwrap()
        );
        assert_eq!(batch.rows(), 1);
    }

    #[test]
    fn row_and_byte_limits_do_not_consume_the_next_record() {
        let mut batch = RecordBatch::new();
        let record = one_column(1, 3, &[0, 5]);
        batch.try_append(&record, 4096, 5).unwrap();
        let saved = frame(&batch);
        assert!(!batch.try_append(&record, 4096, 5).unwrap());
        assert!(!batch.try_append(&record, saved.len() - 1, 1000).unwrap());
        assert_eq!(frame(&batch), saved);
        batch.clear();
        assert!(batch.try_append(&record, 1, 1000).is_err());
        assert!(batch.is_empty());
        assert!(batch.try_append(&record, 4096, 1).unwrap());
    }

    #[test]
    fn rejected_or_truncated_record_never_changes_batch() {
        let mut buffer = QwpWsColumnarBuffer::new(127);
        append_all_types(&mut buffer, 1);
        let valid = record(&buffer);
        let mut batch = RecordBatch::new();
        batch.try_append(&valid, 1 << 20, 1000).unwrap();
        let saved = frame(&batch);
        for len in 0..valid.len() {
            assert!(
                batch.try_append(&valid[..len], 1 << 20, 1000).is_err(),
                "length {len}"
            );
            assert_eq!(frame(&batch), saved);
        }
        for invalid in [
            one_column(9, 1, &[0, 1, 1, b'x', 1]),
            one_column(15, 1, &[0, 0, 0, 0, 0, 255, 255, 255, 255]),
            one_column(17, 1, &[0, 1, 255, 255, 255, 255]),
            one_column(14, 1, &[0, 0]),
            one_column(19, 1, &[0, 19]),
            one_column(1, 1, &[1, 0xff]),
            one_column(8, 1, &[0]),
        ] {
            assert!(batch.try_append(&invalid, 1 << 20, 1000).is_err());
            assert_eq!(frame(&batch), saved);
        }
    }

    #[test]
    fn multi_table_order_and_commit_flag_survive_assembly() {
        let mut buffer = QwpWsColumnarBuffer::new(127);
        for table in ["first", "second"] {
            buffer
                .table(table)
                .unwrap()
                .column_i64("x", 1)
                .unwrap()
                .at_now()
                .unwrap();
        }
        let mut input = Vec::new();
        buffer.encode_sfa_record(&mut input, true).unwrap();
        assert_eq!(record_info(&input).unwrap().rows, 2);
        assert!(record_info(&input).unwrap().defer_commit);
        let mut batch = RecordBatch::new();
        batch.try_append(&input, 4096, 1000).unwrap();
        batch.try_append(&input, 4096, 1000).unwrap();
        assert_eq!(batch.tables[0].name, b"first");
        assert_eq!(batch.tables[1].name, b"second");
        assert_eq!(batch.tables[0].rows, 2);
        assert_eq!(batch.tables[1].rows, 2);
        let encoded = frame(&batch);
        assert_eq!(&encoded[4..8], &[1, 1, 2, 0]);
        batch.clear();
        assert!(batch.try_append(b"QSR1\0\0\0", 12, 1000).unwrap());
        assert!(!batch.is_empty());
        assert!(!batch.defer_commit());
        assert_eq!(frame(&batch), b"QWP1\x01\0\0\0\0\0\0\0");
    }
    #[test]
    fn mutated_record_is_rejected_or_emits_a_decodable_frame() {
        let mut buffer = QwpWsColumnarBuffer::new(127);
        append_all_types(&mut buffer, 1);
        let valid = record(&buffer);
        let mut batch = RecordBatch::new();
        for index in 0..valid.len() {
            for bit in [1, 128] {
                let mut mutated = valid.clone();
                mutated[index] ^= bit;
                batch.clear();
                if matches!(batch.try_append(&mutated, 1 << 20, 1000), Ok(true)) {
                    decode_datagram(&frame(&batch)).unwrap();
                } else {
                    assert!(batch.is_empty());
                }
            }
        }
    }

    #[test]
    fn single_record_size_uses_actual_symbol_id_widths() {
        let mut buffer = QwpWsColumnarBuffer::new(127);
        for index in 0..130 {
            buffer
                .table("t")
                .unwrap()
                .symbol("s", format!("s{index}"))
                .unwrap()
                .at_now()
                .unwrap();
        }
        for _ in 0..100 {
            buffer
                .table("t")
                .unwrap()
                .symbol("s", "s0")
                .unwrap()
                .at_now()
                .unwrap();
        }
        let input = record(&buffer);
        let mut batch = RecordBatch::new();
        batch.try_append(&input, 1 << 20, 1000).unwrap();
        let expected = frame(&batch);
        batch.clear();
        assert!(batch.try_append(&input, expected.len(), 1000).unwrap());
        assert_eq!(frame(&batch), expected);
    }
    #[test]
    fn cached_schema_still_validates_body_and_changed_headers() {
        let valid = one_column(1, 3, &[0, 5]);
        let mut batch = RecordBatch::new();
        batch.try_append(&valid, 4096, 1000).unwrap();
        assert!(
            RecordReader::new(&valid)
                .unwrap()
                .next_table(Some(&batch.tables[0]))
                .unwrap()
                .unwrap()
                .cached_schema
        );
        let saved = frame(&batch);
        let mut invalid_body = valid.clone();
        let body_flag = invalid_body.len() - 2;
        invalid_body[body_flag] = 2;
        assert!(batch.try_append(&invalid_body, 4096, 1000).is_err());
        let mut invalid_length = valid.clone();
        invalid_length[body_flag - 4] = 3;
        assert!(batch.try_append(&invalid_length, 4096, 1000).is_err());
        let mut invalid_name = valid.clone();
        invalid_name[12] = 255;
        assert!(batch.try_append(&invalid_name, 4096, 1000).is_err());
        assert_eq!(frame(&batch), saved);
        batch.clear();
        assert!(batch.try_append(&valid, 4096, 1000).unwrap());
        assert_eq!(frame(&batch), saved);
    }

    #[test]
    fn cached_schema_preserves_noncanonical_varint_offsets() {
        let mut input = one_column(1, 1, &[0, 1]);
        input.splice(7..8, [0x81, 0]);
        let mut batch = RecordBatch::new();
        assert!(batch.try_append(&input, 4096, 1000).unwrap());
        assert!(batch.try_append(&input, 4096, 1000).unwrap());
        let decoded = decode_datagram(&frame(&batch)).unwrap();
        assert_eq!(decoded.table.name, "t");
        assert_eq!(decoded.table.rows, vec![vec![DecodedValue::Bool(true)]; 2]);
    }
}
