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

//! Splices consecutive compatible QWP messages into one wire message. The SF
//! log keeps every original frame; only the bytes sent on the socket change.
use std::ops::Range;

use crate::ingress::MAX_ARRAY_DIMS;
use crate::ingress::buffer::decode_qwp_varint;

const HEADER_LEN: usize = 12;
const VERSION: u8 = 1;
const FLAG_DEFER_COMMIT: u8 = 0x01;
const FLAG_DELTA_SYMBOL_DICT: u8 = 0x08;
const MAX_MESSAGE_LEN: usize = HEADER_LEN.saturating_add(u32::MAX as usize);
// Server limit on rows per table block.
const MAX_TABLE_ROWS: usize = 1_000_000;

#[derive(Debug, Default)]
pub(crate) struct FrameBatch {
    frames: usize,
    rows: usize,
    len: usize,
    defer_commit: bool,
    delta_start: u64,
    delta_count: u64,
    delta_entries: Vec<u8>,
    tables: Vec<Table>,
    parsed: Vec<ParsedTable>,
    bodies: Vec<Body>,
    kinds: Vec<u8>,
}

#[derive(Debug, Default)]
struct Table {
    name: Vec<u8>,
    schema: Vec<u8>,
    rows: usize,
    columns: Vec<Column>,
}

#[derive(Debug, Default)]
struct Column {
    kind: u8,
    meta: u8,
    has_nulls: bool,
    nulls: Vec<u8>,
    value_count: usize,
    values: Vec<u8>,
    offsets: Vec<u32>,
}

#[derive(Debug)]
struct ParsedTable {
    name: Range<usize>,
    schema: Range<usize>,
    rows: usize,
    bodies: Range<usize>,
    cached: bool,
}

#[derive(Debug)]
struct Body {
    kind: u8,
    meta: u8,
    bitmap: Option<Range<usize>>,
    value_count: usize,
    values: Range<usize>,
}

struct Header {
    flags: u8,
    table_count: usize,
    delta_start: u64,
    delta_count: u64,
    entries: Range<usize>,
}

struct Prefix<'a> {
    header: Header,
    name: &'a [u8],
    rows: usize,
    schema: &'a [u8],
}

struct Plan {
    defer_commit: bool,
    delta_start: u64,
    delta_count: u64,
    entries: Range<usize>,
    rows: usize,
    len: usize,
}

impl FrameBatch {
    pub(crate) fn is_empty(&self) -> bool {
        self.frames == 0
    }

    pub(crate) fn rows(&self) -> usize {
        self.rows
    }

    pub(crate) fn clear(&mut self) {
        self.frames = 0;
        self.rows = 0;
        self.len = 0;
        self.delta_count = 0;
        self.delta_entries.clear();
        for table in &mut self.tables {
            table.rows = 0;
            for column in &mut table.columns {
                column.clear();
            }
        }
    }

    /// Whether `payload` can open a message, judged from its first table header.
    /// A frame at `max_bytes` or `max_rows` on its own is sent as is.
    pub(crate) fn may_start(payload: &[u8], max_bytes: usize, max_rows: usize) -> bool {
        payload.len() < max_bytes
            && prefix(payload).is_some_and(|prefix| {
                prefix.rows <= MAX_TABLE_ROWS && (max_rows == 0 || prefix.rows < max_rows)
            })
    }

    /// Whether `next` may follow `first` in one message, judged from their first
    /// table headers. False is final; true still needs [`Self::try_append`].
    pub(crate) fn may_join(first: &[u8], next: &[u8], max_rows: usize) -> bool {
        let (Some(first), Some(next)) = (prefix(first), prefix(next)) else {
            return false;
        };
        let rows = first.rows.saturating_add(next.rows);
        first.header.table_count == next.header.table_count
            && first.name == next.name
            && first.schema == next.schema
            && first
                .header
                .delta_start
                .checked_add(first.header.delta_count)
                == Some(next.header.delta_start)
            && (first.header.flags & FLAG_DEFER_COMMIT != 0
                || next.header.flags & FLAG_DEFER_COMMIT == 0)
            && rows <= MAX_TABLE_ROWS
            && (max_rows == 0 || rows <= max_rows)
    }

    /// Returns false, leaving the batch unchanged, when `payload` cannot join it.
    /// A frame at `max_bytes` or `max_rows` on its own never joins; send it as is.
    pub(crate) fn try_append(&mut self, payload: &[u8], max_bytes: usize, max_rows: usize) -> bool {
        if payload.len() >= max_bytes {
            return false;
        }
        let Some(plan) = self.plan(payload, max_rows) else {
            return false;
        };
        let rows = self.rows.saturating_add(plan.rows);
        if plan.len > max_bytes.min(MAX_MESSAGE_LEN) {
            return false;
        }
        if self.is_empty() {
            self.delta_start = plan.delta_start;
            self.tables.truncate(self.parsed.len());
            self.tables.resize_with(self.parsed.len(), Table::default);
        }
        self.delta_count = plan.delta_count;
        self.delta_entries
            .extend_from_slice(slice(payload, plan.entries));
        for (table, parsed) in self.tables.iter_mut().zip(&self.parsed) {
            let bodies = self.bodies.get(parsed.bodies.clone()).unwrap_or_default();
            if !parsed.cached {
                table.name.clear();
                table
                    .name
                    .extend_from_slice(slice(payload, parsed.name.clone()));
                table.schema.clear();
                table
                    .schema
                    .extend_from_slice(slice(payload, parsed.schema.clone()));
                table.columns.truncate(bodies.len());
                table.columns.resize_with(bodies.len(), Column::default);
                for (column, body) in table.columns.iter_mut().zip(bodies) {
                    column.clear();
                    column.kind = body.kind;
                }
            }
            for (column, body) in table.columns.iter_mut().zip(bodies) {
                column.append(payload, body, table.rows, parsed.rows);
            }
            table.rows += parsed.rows;
        }
        self.rows = rows;
        self.len = plan.len;
        self.frames += 1;
        self.defer_commit = plan.defer_commit;
        true
    }

    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.clear();
        out.reserve(self.len);
        out.extend_from_slice(b"QWP1");
        out.push(VERSION);
        out.push(if self.defer_commit {
            FLAG_DELTA_SYMBOL_DICT | FLAG_DEFER_COMMIT
        } else {
            FLAG_DELTA_SYMBOL_DICT
        });
        out.extend_from_slice(&(self.tables.len() as u16).to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        write_varint(out, self.delta_start);
        write_varint(out, self.delta_count);
        out.extend_from_slice(&self.delta_entries);
        for table in &self.tables {
            out.extend_from_slice(&table.name);
            write_varint(out, table.rows as u64);
            out.extend_from_slice(&table.schema);
            for column in &table.columns {
                column.encode(out);
            }
        }
        debug_assert_eq!(out.len(), self.len);
        let payload_len = (out.len() - HEADER_LEN) as u32;
        out[8..HEADER_LEN].copy_from_slice(&payload_len.to_le_bytes());
    }

    fn plan(&mut self, payload: &[u8], max_rows: usize) -> Option<Plan> {
        let Header {
            flags,
            table_count,
            delta_start,
            delta_count,
            entries,
        } = header(payload)?;
        let empty = self.is_empty();
        if !empty
            && (table_count != self.tables.len()
                // A committed batch must not wait on a split that may never finish.
                || !self.defer_commit && flags & FLAG_DEFER_COMMIT != 0)
        {
            return None;
        }
        let mut pos = entries.end;
        let (delta_start, delta_count) = if empty {
            (delta_start, delta_count)
        } else if Some(delta_start) == self.delta_start.checked_add(self.delta_count) {
            (self.delta_start, self.delta_count.checked_add(delta_count)?)
        } else {
            return None;
        };
        let mut len = HEADER_LEN
            .saturating_add(varint_len(delta_start))
            .saturating_add(varint_len(delta_count))
            .saturating_add(self.delta_entries.len())
            .saturating_add(entries.len());

        let batch_rows = self.rows;
        let Self {
            tables,
            parsed,
            bodies,
            kinds,
            ..
        } = self;
        parsed.clear();
        bodies.clear();
        let mut rows = 0usize;
        for index in 0..table_count {
            let name_start = pos;
            let mut cached = tables.get(index).filter(|table| {
                payload
                    .get(pos..)
                    .is_some_and(|rest| rest.starts_with(&table.name))
            });
            pos = match cached {
                Some(table) => pos + table.name.len(),
                None => skip_bytes(payload, pos)?,
            };
            let name = name_start..pos;
            let (table_rows, next) = decode_qwp_varint(payload, pos)?;
            let table_rows = usize::try_from(table_rows).ok().filter(|rows| *rows > 0)?;
            pos = next;
            let schema_start = pos;
            cached = cached.filter(|table| {
                payload
                    .get(pos..)
                    .is_some_and(|rest| rest.starts_with(&table.schema))
            });
            let column_count = match cached {
                Some(table) => {
                    pos += table.schema.len();
                    table.columns.len()
                }
                None if empty => {
                    let (count, next) = decode_qwp_varint(payload, pos)?;
                    pos = next;
                    kinds.clear();
                    for _ in 0..count {
                        pos = skip_bytes(payload, pos)?;
                        kinds.push(*payload.get(pos)?);
                        pos += 1;
                    }
                    kinds.len()
                }
                None => return None,
            };
            if column_count == 0 {
                return None;
            }
            let schema = schema_start..pos;
            let total_rows = cached
                .map_or(0, |table| table.rows)
                .checked_add(table_rows)
                .filter(|rows| *rows <= MAX_TABLE_ROWS)?;
            rows = rows.checked_add(table_rows)?;
            let merged_rows = batch_rows.saturating_add(rows);
            if max_rows > 0 && (merged_rows > max_rows || empty && merged_rows >= max_rows) {
                return None;
            }
            len = len
                .saturating_add(name.len())
                .saturating_add(varint_len(total_rows as u64))
                .saturating_add(schema.len());
            let first_body = bodies.len();
            for column in 0..column_count {
                let existing = cached.and_then(|table| table.columns.get(column));
                let kind = match existing {
                    Some(existing) => existing.kind,
                    None => *kinds.get(column)?,
                };
                let body = parse_body(payload, pos, kind, table_rows)?;
                if !empty && existing.is_some_and(|existing| existing.meta != body.meta) {
                    return None;
                }
                len = len.saturating_add(merged_column_len(existing, &body, total_rows)?);
                pos = body.values.end;
                bodies.push(body);
            }
            parsed.push(ParsedTable {
                name,
                schema,
                rows: table_rows,
                bodies: first_body..bodies.len(),
                cached: cached.is_some(),
            });
        }
        if pos != payload.len() {
            return None;
        }
        Some(Plan {
            defer_commit: flags & FLAG_DEFER_COMMIT != 0,
            delta_start,
            delta_count,
            entries,
            rows,
            len,
        })
    }
}

impl Column {
    fn clear(&mut self) {
        self.has_nulls = false;
        self.nulls.clear();
        self.value_count = 0;
        self.values.clear();
        self.offsets.clear();
    }

    fn append(&mut self, payload: &[u8], body: &Body, existing_rows: usize, rows: usize) {
        if let Some(bitmap) = body.bitmap.clone() {
            if !self.has_nulls {
                self.has_nulls = true;
                self.nulls.resize(existing_rows.div_ceil(8), 0);
            }
            append_bits(&mut self.nulls, existing_rows, slice(payload, bitmap), rows);
        } else if self.has_nulls {
            self.nulls.resize((existing_rows + rows).div_ceil(8), 0);
        }
        self.meta = body.meta;
        let values = slice(payload, body.values.clone());
        match self.kind {
            1 => append_bits(&mut self.values, self.value_count, values, body.value_count),
            15 | 23 => {
                let base = self.offsets.last().copied().unwrap_or(0);
                let (offsets, data) = values
                    .split_at_checked(4 * (body.value_count + 1))
                    .unwrap_or_default();
                for offset in offsets.as_chunks::<4>().0.iter().skip(1) {
                    self.offsets
                        .push(base.saturating_add(u32::from_le_bytes(*offset)));
                }
                self.values.extend_from_slice(data);
            }
            _ => extend_small(&mut self.values, values),
        }
        self.value_count += body.value_count;
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.push(u8::from(self.has_nulls));
        out.extend_from_slice(&self.nulls);
        if has_meta(self.kind) {
            out.push(self.meta);
        }
        if matches!(self.kind, 15 | 23) {
            out.extend_from_slice(&0u32.to_le_bytes());
            for offset in &self.offsets {
                out.extend_from_slice(&offset.to_le_bytes());
            }
        }
        out.extend_from_slice(&self.values);
    }
}

fn parse_body(payload: &[u8], start: usize, kind: u8, rows: usize) -> Option<Body> {
    let mut pos = start.checked_add(1)?;
    let bitmap = match *payload.get(start)? {
        0 => None,
        1 => Some(pos..pos.checked_add(rows.div_ceil(8))?),
        _ => return None,
    };
    let mut value_count = rows;
    if let Some(range) = bitmap.clone() {
        let bits = payload.get(range.clone())?;
        if bits
            .last()
            .is_some_and(|last| !rows.is_multiple_of(8) && last >> (rows % 8) != 0)
        {
            return None;
        }
        let nulls = bits.iter().map(|byte| byte.count_ones() as usize).sum();
        value_count = rows.checked_sub(nulls)?;
        pos = range.end;
    }
    let meta = match kind {
        14 => {
            let (bits, next) = decode_qwp_varint(payload, pos)?;
            pos = next;
            u8::try_from(bits)
                .ok()
                .filter(|bits| (1..=60).contains(bits))?
        }
        19..=21 => {
            let scale = *payload.get(pos)?;
            pos += 1;
            scale
        }
        _ => 0,
    };
    let fixed = |width: usize| pos.checked_add(value_count.checked_mul(width)?);
    let end = match kind {
        1 => pos.checked_add(value_count.div_ceil(8))?,
        2 => fixed(1)?,
        3 | 22 => fixed(2)?,
        4 | 6 | 24 => fixed(4)?,
        5 | 7 | 10 | 11 | 16 | 19 => fixed(8)?,
        12 | 20 => fixed(16)?,
        13 | 21 => fixed(32)?,
        14 => fixed(usize::from(meta).div_ceil(8))?,
        9 => (0..value_count).try_fold(pos, |pos, _| Some(decode_qwp_varint(payload, pos)?.1))?,
        15 | 23 => varlen_end(payload, pos, value_count)?,
        17 | 18 => arrays_end(payload, pos, value_count)?,
        _ => return None,
    };
    (end <= payload.len()).then_some(Body {
        kind,
        meta,
        bitmap,
        value_count,
        values: pos..end,
    })
}

fn header(payload: &[u8]) -> Option<Header> {
    let fixed = payload.first_chunk::<HEADER_LEN>()?;
    let flags = fixed[5];
    let table_count = usize::from(u16::from_le_bytes([fixed[6], fixed[7]]));
    let payload_len = u32::from_le_bytes([fixed[8], fixed[9], fixed[10], fixed[11]]);
    if fixed[..4] != *b"QWP1"
        || fixed[4] != VERSION
        || flags & FLAG_DELTA_SYMBOL_DICT == 0
        || flags & !(FLAG_DELTA_SYMBOL_DICT | FLAG_DEFER_COMMIT) != 0
        || table_count == 0
        || usize::try_from(payload_len).ok()? != payload.len() - HEADER_LEN
    {
        return None;
    }
    let (delta_start, pos) = decode_qwp_varint(payload, HEADER_LEN)?;
    let (delta_count, mut pos) = decode_qwp_varint(payload, pos)?;
    let entries_start = pos;
    for _ in 0..delta_count {
        pos = skip_bytes(payload, pos)?;
    }
    Some(Header {
        flags,
        table_count,
        delta_start,
        delta_count,
        entries: entries_start..pos,
    })
}

fn prefix(payload: &[u8]) -> Option<Prefix<'_>> {
    let header = header(payload)?;
    let name_start = header.entries.end;
    let pos = skip_bytes(payload, name_start)?;
    let name = payload.get(name_start..pos)?;
    let (rows, pos) = decode_qwp_varint(payload, pos)?;
    let schema_start = pos;
    let (columns, mut pos) = decode_qwp_varint(payload, pos)?;
    for _ in 0..columns {
        pos = skip_bytes(payload, pos)?.checked_add(1)?;
    }
    Some(Prefix {
        header,
        name,
        rows: usize::try_from(rows).ok()?,
        schema: payload.get(schema_start..pos)?,
    })
}

fn varlen_end(payload: &[u8], pos: usize, values: usize) -> Option<usize> {
    let data = pos.checked_add(values.checked_add(1)?.checked_mul(4)?)?;
    let (offsets, _) = payload.get(pos..data)?.as_chunks::<4>();
    if offsets.first() != Some(&[0; 4]) {
        return None;
    }
    let mut last = 0;
    for offset in offsets {
        let offset = u32::from_le_bytes(*offset);
        if offset < last {
            return None;
        }
        last = offset;
    }
    data.checked_add(usize::try_from(last).ok()?)
}

fn arrays_end(payload: &[u8], mut pos: usize, values: usize) -> Option<usize> {
    for _ in 0..values {
        let dims = usize::from(*payload.get(pos)?);
        if dims == 0 || dims > MAX_ARRAY_DIMS {
            return None;
        }
        let shape_end = pos.checked_add(1 + 4 * dims)?;
        let (shape, _) = payload.get(pos + 1..shape_end)?.as_chunks::<4>();
        let elements = shape.iter().try_fold(1usize, |elements, dim| {
            elements.checked_mul(usize::try_from(u32::from_le_bytes(*dim)).ok()?)
        })?;
        pos = shape_end.checked_add(elements.checked_mul(8)?)?;
    }
    Some(pos)
}

fn merged_column_len(existing: Option<&Column>, body: &Body, rows: usize) -> Option<usize> {
    let (has_nulls, value_count, values_len, base) = existing.map_or((false, 0, 0, 0), |column| {
        (
            column.has_nulls,
            column.value_count,
            column.values.len(),
            column.offsets.last().copied().unwrap_or(0),
        )
    });
    let value_count = value_count.checked_add(body.value_count)?;
    let bitmap = if has_nulls || body.bitmap.is_some() {
        rows.div_ceil(8)
    } else {
        0
    };
    let values = match body.kind {
        1 => value_count.div_ceil(8),
        15 | 23 => {
            let data = body.values.len().checked_sub(4 * (body.value_count + 1))?;
            base.checked_add(u32::try_from(data).ok()?)?;
            values_len
                .checked_add(data)?
                .checked_add(value_count.checked_add(1)?.checked_mul(4)?)?
        }
        _ => values_len.checked_add(body.values.len())?,
    };
    values.checked_add(1 + bitmap + usize::from(has_meta(body.kind)))
}

fn has_meta(kind: u8) -> bool {
    matches!(kind, 14 | 19..=21)
}

fn append_bits(dst: &mut Vec<u8>, dst_bits: usize, src: &[u8], count: usize) {
    let total = dst_bits + count;
    let src = src.get(..count.div_ceil(8)).unwrap_or(src);
    let shift = dst_bits % 8;
    if shift == 0 {
        dst.extend_from_slice(src);
    } else {
        for &byte in src {
            if let Some(last) = dst.last_mut() {
                *last |= byte << shift;
            }
            dst.push(byte >> (8 - shift));
        }
    }
    dst.truncate(total.div_ceil(8));
    if !total.is_multiple_of(8)
        && let Some(last) = dst.last_mut()
    {
        *last &= (1 << (total % 8)) - 1;
    }
}

/// Spliced values are usually a few bytes; fixed-size copies avoid a `memcpy` call.
fn extend_small(dst: &mut Vec<u8>, src: &[u8]) {
    if let Ok(bytes) = <&[u8; 8]>::try_from(src) {
        dst.extend_from_slice(bytes);
        return;
    }
    match *src {
        [a] => dst.push(a),
        [a, b] => dst.extend_from_slice(&[a, b]),
        [a, b, c, d] => dst.extend_from_slice(&[a, b, c, d]),
        _ => dst.extend_from_slice(src),
    }
}

fn skip_bytes(payload: &[u8], pos: usize) -> Option<usize> {
    let (len, next) = decode_qwp_varint(payload, pos)?;
    let end = next.checked_add(usize::try_from(len).ok()?)?;
    (end <= payload.len()).then_some(end)
}

fn slice(payload: &[u8], range: Range<usize>) -> &[u8] {
    payload.get(range).unwrap_or_default()
}

fn varint_len(value: u64) -> usize {
    (64 - (value | 1).leading_zeros() as usize).div_ceil(7)
}

fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    while value > 0x7F {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingress::buffer::{QwpWsColumnarBuffer, QwpWsEncodeScratch, SymbolGlobalDict};
    use crate::ingress::column_sender::encoder::{
        EncodeScratch, encode_chunk_into, encode_chunk_replay_into,
    };
    use crate::ingress::column_sender::{Chunk, Validity};
    use crate::ingress::{TimestampMicros, TimestampNanos, TimestampUnit};

    fn seeded_like(dict: &SymbolGlobalDict) -> SymbolGlobalDict {
        let mut seeded = SymbolGlobalDict::new();
        for id in 0..dict.next_id() {
            seeded.intern(dict.entry(id).unwrap()).unwrap();
        }
        seeded
    }

    fn frames(
        rows_per_frame: &[usize],
        row: impl Fn(&mut QwpWsColumnarBuffer, i64),
    ) -> (Vec<Vec<u8>>, Vec<u8>) {
        let mut scratch = QwpWsEncodeScratch::new();
        let mut dict = SymbolGlobalDict::new();
        let mut single = QwpWsColumnarBuffer::new(127);
        let mut all = QwpWsColumnarBuffer::new(127);
        let mut frames = Vec::new();
        let mut value = 0;
        for &rows in rows_per_frame {
            for _ in 0..rows {
                row(&mut single, value);
                row(&mut all, value);
                value += 1;
            }
            let mut frame = Vec::new();
            single
                .encode_ws_replay_message_with_defer(
                    &mut frame,
                    &mut scratch,
                    &mut dict,
                    1,
                    false,
                    true,
                )
                .unwrap();
            frames.push(frame);
            single.clear();
        }
        let mut expected = Vec::new();
        all.encode_ws_replay_message_with_defer(
            &mut expected,
            &mut scratch,
            &mut seeded_like(&dict),
            1,
            false,
            false,
        )
        .unwrap();
        (frames, expected)
    }

    fn splice(frames: &[Vec<u8>]) -> Vec<u8> {
        let mut batch = FrameBatch::default();
        for frame in frames {
            assert!(batch.try_append(frame, usize::MAX, 0));
        }
        encoded(&batch)
    }

    fn encoded(batch: &FrameBatch) -> Vec<u8> {
        let mut out = Vec::new();
        batch.encode(&mut out);
        out
    }

    fn all_types(buffer: &mut QwpWsColumnarBuffer, value: i64) {
        buffer
            .table("trades")
            .unwrap()
            .symbol("sym", ["alpha", "beta", "gamma"][value as usize % 3])
            .unwrap()
            .symbol("venue", if value < 5 { "ldn" } else { "nyc" })
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
            .column_arr("longs", &vec![1_i64, value, -value])
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
            .column_geohash("geo8", value as u64, 8)
            .unwrap()
            .at(TimestampNanos::new(value))
            .unwrap();
    }

    fn sparse(buffer: &mut QwpWsColumnarBuffer, value: i64) {
        buffer
            .table("trades")
            .unwrap()
            .column_i64("id", value)
            .unwrap()
            .column_bool("flag", value % 2 == 1)
            .unwrap();
        if value % 3 != 2 {
            buffer
                .symbol("sym", format!("s{}", value % 4))
                .unwrap()
                .column_str("str", "x".repeat(value as usize))
                .unwrap()
                .column_dec64("dec", "15")
                .unwrap()
                .column_arr("doubles", &vec![value as f64; value as usize % 3 + 1])
                .unwrap()
                .column_ts("micros", TimestampMicros::new(value))
                .unwrap()
                .column_uuid("uuid", 1, value as u64)
                .unwrap()
                .column_long256("long256", &[7; 32])
                .unwrap()
                .column_ipv4("ip", value as u32)
                .unwrap()
                .column_date("date", value)
                .unwrap()
                .column_binary("binary", &[value as u8])
                .unwrap()
                .column_geohash("geo", value as u64, 5)
                .unwrap();
        }
        buffer.at(TimestampNanos::new(value)).unwrap();
    }

    fn qty(buffer: &mut QwpWsColumnarBuffer, value: i64) {
        buffer
            .table("trades")
            .unwrap()
            .column_i64("qty", value)
            .unwrap()
            .at_now()
            .unwrap();
    }

    #[test]
    fn splices_every_column_kind_like_one_buffer() {
        for rows_per_frame in [&[1; 19][..], &[3, 1, 5, 2, 8]] {
            let (frames, expected) = frames(rows_per_frame, all_types);
            assert_eq!(splice(&frames), expected, "{rows_per_frame:?}");
        }
    }

    #[test]
    fn splices_sparse_nulls_present_in_some_frames_only() {
        let (frames, expected) = frames(&[2, 1, 3, 2], sparse);
        assert_eq!(splice(&frames), expected);
    }

    #[test]
    fn cleared_batch_splices_the_next_window_like_a_fresh_one() {
        let (frames, _) = frames(&[1; 6], |buffer, value| {
            buffer
                .table("trades")
                .unwrap()
                .column_i64("id", value)
                .unwrap();
            if value % 3 != 1 {
                buffer
                    .symbol("sym", format!("s{value}"))
                    .unwrap()
                    .column_bool("flag", value % 2 == 0)
                    .unwrap()
                    .column_str("note", "x".repeat(value as usize))
                    .unwrap();
            }
            buffer.at(TimestampNanos::new(value)).unwrap();
        });
        let mut batch = FrameBatch::default();
        for (window, has_nulls) in [(0..2, true), (2..4, false), (4..6, true)] {
            batch.clear();
            for frame in &frames[window.clone()] {
                assert!(batch.try_append(frame, usize::MAX, 0));
            }
            assert_eq!(
                batch.tables[0]
                    .columns
                    .iter()
                    .any(|column| column.has_nulls),
                has_nulls
            );
            assert_eq!(encoded(&batch), splice(&frames[window]));
        }
    }

    #[test]
    fn splices_multi_table_frames_per_table() {
        let (frames, expected) = frames(&[1, 2, 1], |buffer, value| {
            buffer
                .table("trades")
                .unwrap()
                .symbol("sym", format!("s{value}"))
                .unwrap()
                .column_f64("px", value as f64)
                .unwrap()
                .at(TimestampNanos::new(value))
                .unwrap();
            buffer
                .table("quotes")
                .unwrap()
                .column_i64("bid", value)
                .unwrap()
                .column_str("venue", format!("v{value}"))
                .unwrap()
                .at(TimestampNanos::new(value))
                .unwrap();
        });
        assert_eq!(u16::from_le_bytes([expected[6], expected[7]]), 2);
        assert_eq!(splice(&frames), expected);
    }

    #[test]
    fn splices_chunk_frames_like_one_chunk() {
        let mut dict = SymbolGlobalDict::new();
        let mut scratch = EncodeScratch::new();
        let mut frames = Vec::new();
        let qty_valid = [0b101];
        let seen_valid = [0b011];
        let note_valid = [0b110];
        let validity = [
            Validity::from_bitmap(&qty_valid, 3).unwrap(),
            Validity::from_bitmap(&seen_valid, 3).unwrap(),
            Validity::from_bitmap(&note_valid, 3).unwrap(),
        ];
        let mut first = Chunk::new("trades");
        first
            .column_i64("qty", &[1, 2, 3], Some(&validity[0]))
            .unwrap()
            .column_ts(
                "seen",
                &[10, 20, 30],
                TimestampUnit::Micros,
                Some(&validity[1]),
            )
            .unwrap()
            .column_str("note", &[0, 1, 1, 4], b"abbb", Some(&validity[2]))
            .unwrap()
            .symbol_i32("sym", &[0, 1, 0], &[0, 5, 9], b"alphabeta", None)
            .unwrap()
            .column_bool("flag", &[0b101], 3, None)
            .unwrap()
            .at_nanos(&[100, 101, 102])
            .unwrap();
        let mut second = Chunk::new("trades");
        second
            .column_i64("qty", &[4, 5], None)
            .unwrap()
            .column_ts("seen", &[40, 50], TimestampUnit::Micros, None)
            .unwrap()
            .column_str("note", &[0, 2, 3], b"ccd", None)
            .unwrap()
            .symbol_i32("sym", &[0, 1], &[0, 5, 10], b"gammaalpha", None)
            .unwrap()
            .column_bool("flag", &[0b10], 2, None)
            .unwrap()
            .at_nanos(&[103, 104])
            .unwrap();
        for chunk in [&first, &second] {
            let mut frame = Vec::new();
            encode_chunk_into(&mut frame, chunk, &mut dict, &mut scratch, false).unwrap();
            frames.push(frame);
        }

        let all_valid = [0b11101, 0b11011, 0b11110];
        let validity = all_valid.map(|bits| [bits]);
        let validity = validity
            .iter()
            .map(|bits| Validity::from_bitmap(bits, 5).unwrap())
            .collect::<Vec<_>>();
        let mut all = Chunk::new("trades");
        all.column_i64("qty", &[1, 2, 3, 4, 5], Some(&validity[0]))
            .unwrap()
            .column_ts(
                "seen",
                &[10, 20, 30, 40, 50],
                TimestampUnit::Micros,
                Some(&validity[1]),
            )
            .unwrap()
            .column_str("note", &[0, 1, 1, 4, 6, 7], b"abbbccd", Some(&validity[2]))
            .unwrap()
            .symbol_i32(
                "sym",
                &[0, 1, 0, 2, 0],
                &[0, 5, 9, 14],
                b"alphabetagamma",
                None,
            )
            .unwrap()
            .column_bool("flag", &[0b10101], 5, None)
            .unwrap()
            .at_nanos(&[100, 101, 102, 103, 104])
            .unwrap();
        let mut expected = Vec::new();
        encode_chunk_replay_into(
            &mut expected,
            &all,
            &mut seeded_like(&dict),
            &mut scratch,
            false,
        )
        .unwrap();
        assert_eq!(splice(&frames), expected);
    }

    #[test]
    fn defer_commit_follows_the_last_frame() {
        let (frames, mut expected) = frames(&[1, 1], qty);
        let deferred = |frame: &Vec<u8>| {
            let mut frame = frame.clone();
            frame[5] |= FLAG_DEFER_COMMIT;
            frame
        };
        assert_eq!(splice(&[deferred(&frames[0]), frames[1].clone()]), expected);
        expected[5] |= FLAG_DEFER_COMMIT;
        assert_eq!(
            splice(&[deferred(&frames[0]), deferred(&frames[1])]),
            expected
        );

        let mut batch = FrameBatch::default();
        assert!(batch.try_append(&frames[0], usize::MAX, 0));
        let before = encoded(&batch);
        assert!(!batch.try_append(&deferred(&frames[1]), usize::MAX, 0));
        assert_eq!(encoded(&batch), before);
    }

    fn assert_rejected_without_change(first: &[u8], next: &[u8]) {
        let mut batch = FrameBatch::default();
        assert!(batch.try_append(first, usize::MAX, 0));
        let before = encoded(&batch);
        assert!(!batch.try_append(next, usize::MAX, 0));
        assert_eq!(encoded(&batch), before);
        assert_eq!(batch.rows(), 1);
    }

    #[test]
    fn incompatible_frames_end_the_batch() {
        let one = |row: &dyn Fn(&mut QwpWsColumnarBuffer), dict: &mut SymbolGlobalDict| {
            let mut buffer = QwpWsColumnarBuffer::new(127);
            row(&mut buffer);
            let mut frame = Vec::new();
            buffer
                .encode_ws_replay_message_with_defer(
                    &mut frame,
                    &mut QwpWsEncodeScratch::new(),
                    dict,
                    1,
                    false,
                    true,
                )
                .unwrap();
            frame
        };
        let decimal = |scale: &'static str| {
            move |buffer: &mut QwpWsColumnarBuffer| {
                buffer
                    .table("t")
                    .unwrap()
                    .column_dec64("d", scale)
                    .unwrap()
                    .at_now()
                    .unwrap();
            }
        };
        let geohash = |bits: u8| {
            move |buffer: &mut QwpWsColumnarBuffer| {
                buffer
                    .table("t")
                    .unwrap()
                    .column_geohash("g", 1, bits)
                    .unwrap()
                    .at_now()
                    .unwrap();
            }
        };
        let symbol = |value: &'static str| {
            move |buffer: &mut QwpWsColumnarBuffer| {
                buffer
                    .table("t")
                    .unwrap()
                    .symbol("s", value)
                    .unwrap()
                    .at_now()
                    .unwrap();
            }
        };
        let mut dict = SymbolGlobalDict::new();
        let first = one(&decimal("1.5"), &mut dict);
        assert_rejected_without_change(&first, &one(&decimal("1.25"), &mut dict));
        let mut version = one(&decimal("2.5"), &mut dict);
        version[4] = 2;
        assert_rejected_without_change(&first, &version);
        assert_rejected_without_change(&first, &one(&geohash(5), &mut dict));
        assert_rejected_without_change(&one(&geohash(5), &mut dict), &one(&geohash(6), &mut dict));
        let (frames, _) = frames(&[1], qty);
        assert_rejected_without_change(&first, &frames[0]);

        let first = one(&symbol("alpha"), &mut dict);
        dict.intern(b"skipped").unwrap();
        assert_rejected_without_change(&first, &one(&symbol("bravo"), &mut dict));
        assert_rejected_without_change(
            &first,
            &one(&symbol("alpha"), &mut SymbolGlobalDict::new()),
        );
    }

    #[test]
    fn byte_and_row_limits_bound_the_batch() {
        let (frames, _) = frames(&[1, 1, 1], qty);
        let two = splice(&frames[..2]);
        let mut batch = FrameBatch::default();
        assert!(batch.try_append(&frames[0], two.len(), 0));
        assert!(batch.try_append(&frames[1], two.len(), 0));
        assert!(!batch.try_append(&frames[2], two.len(), 0));
        assert_eq!(encoded(&batch), two);

        let mut batch = FrameBatch::default();
        assert!(batch.try_append(&frames[0], usize::MAX, 2));
        assert!(batch.try_append(&frames[1], usize::MAX, 2));
        assert_eq!(batch.rows(), 2);
        assert!(!batch.try_append(&frames[2], usize::MAX, 2));
        assert_eq!(encoded(&batch), two);

        let mut batch = FrameBatch::default();
        assert!(!batch.try_append(&frames[0], frames[0].len(), 0));
        assert!(!batch.try_append(&two, usize::MAX, 2));
        assert!(batch.is_empty());
        assert!(batch.try_append(&two, usize::MAX, 3));
        assert!(batch.try_append(&frames[0], usize::MAX, 3));
        assert_eq!(batch.rows(), 3);
    }

    #[test]
    fn table_block_stops_at_the_server_row_limit() {
        let bools = |rows: usize| raw_frame(rows as u64, 1, &vec![0; 1 + rows.div_ceil(8)]);
        let half = MAX_TABLE_ROWS / 2;
        let mut batch = FrameBatch::default();
        assert!(batch.try_append(&bools(half), usize::MAX, 0));
        assert!(batch.try_append(&bools(MAX_TABLE_ROWS - half), usize::MAX, 0));
        assert_eq!(batch.rows(), MAX_TABLE_ROWS);
        let full = encoded(&batch);
        assert!(!batch.try_append(&bools(1), usize::MAX, 0));
        assert_eq!(batch.rows(), MAX_TABLE_ROWS);
        assert_eq!(encoded(&batch), full);
    }

    #[test]
    fn pre_checks_stop_cheap_mismatches_and_never_refuse_a_merge() {
        let deferred = |frame: &Vec<u8>| {
            let mut frame = frame.clone();
            frame[5] |= FLAG_DEFER_COMMIT;
            frame
        };
        let quotes = |buffer: &mut QwpWsColumnarBuffer, value: i64| {
            buffer
                .table("quotes")
                .unwrap()
                .column_i64("qty", value)
                .unwrap()
                .at_now()
                .unwrap();
        };
        let (trades, _) = frames(&[1, 1], qty);
        let (other, _) = frames(&[1], quotes);
        let (typed, _) = frames(&[1, 1, 1], all_types);
        assert!(FrameBatch::may_start(&trades[0], usize::MAX, 2));
        assert!(!FrameBatch::may_start(&trades[0], usize::MAX, 1));
        assert!(!FrameBatch::may_start(&trades[0], trades[0].len(), 0));
        assert!(FrameBatch::may_join(&trades[0], &trades[1], 2));
        assert!(!FrameBatch::may_join(&trades[0], &trades[1], 1));
        assert!(!FrameBatch::may_join(&trades[0], &other[0], 0));
        assert!(!FrameBatch::may_join(&trades[0], &typed[0], 0));
        assert!(!FrameBatch::may_join(&typed[0], &typed[2], 0));
        assert!(!FrameBatch::may_join(&trades[0], &deferred(&trades[1]), 0));
        assert!(FrameBatch::may_join(&deferred(&trades[0]), &trades[1], 0));

        let mut pool: Vec<_> = [trades, other, typed, frames(&[2, 1], sparse).0]
            .into_iter()
            .flatten()
            .collect();
        pool.extend([
            raw_frame(2, 15, &varchar_body(&[0, 1, 3], b"abc")),
            raw_frame(3, 1, &[0, 0b101]),
        ]);
        pool.extend(pool.iter().map(deferred).collect::<Vec<_>>());
        for max_rows in 0..5 {
            for first in &pool {
                for max_bytes in [first.len(), usize::MAX] {
                    if FrameBatch::default().try_append(first, max_bytes, max_rows) {
                        assert!(FrameBatch::may_start(first, max_bytes, max_rows));
                    }
                }
                for next in &pool {
                    let mut batch = FrameBatch::default();
                    if batch.try_append(first, usize::MAX, max_rows)
                        && batch.try_append(next, usize::MAX, max_rows)
                    {
                        assert!(FrameBatch::may_join(first, next, max_rows));
                    }
                }
            }
        }
    }

    fn raw_frame(rows: u64, kind: u8, body: &[u8]) -> Vec<u8> {
        let mut payload = vec![0, 0, 1, b't'];
        write_varint(&mut payload, rows);
        payload.extend_from_slice(&[1, 1, b'c', kind]);
        payload.extend_from_slice(body);
        let mut frame = b"QWP1\x01\x08\x01\x00".to_vec();
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(&payload);
        frame
    }

    fn varchar_body(offsets: &[u32], data: &[u8]) -> Vec<u8> {
        let mut body = vec![0];
        for offset in offsets {
            body.extend_from_slice(&offset.to_le_bytes());
        }
        body.extend_from_slice(data);
        body
    }

    #[test]
    fn malformed_or_unsupported_frames_are_unmergeable() {
        let valid = raw_frame(2, 15, &varchar_body(&[0, 1, 3], b"abc"));
        let mut batch = FrameBatch::default();
        assert!(batch.try_append(&valid, usize::MAX, 0));
        assert!(batch.try_append(&valid, usize::MAX, 0));
        let before = encoded(&batch);

        let mut invalid = Vec::new();
        for index in [4, 5, 6] {
            let mut frame = valid.clone();
            frame[index] ^= match index {
                5 => 0x02,
                _ => 0x07,
            };
            invalid.push(frame);
        }
        let mut no_delta = valid.clone();
        no_delta[5] = 0;
        invalid.push(no_delta);
        let mut no_tables = valid.clone();
        no_tables[6] = 0;
        invalid.push(no_tables);
        let mut magic = valid.clone();
        magic[0] = b'X';
        invalid.push(magic);
        invalid.extend([
            raw_frame(2, 8, &[0, 0]),
            raw_frame(2, 15, &[2]),
            raw_frame(2, 1, &[1, 0b100, 0]),
            raw_frame(2, 15, &varchar_body(&[0, 3, 1], b"abc")),
            raw_frame(2, 15, &varchar_body(&[1, 1, 3], b"abc")),
            raw_frame(2, 15, &varchar_body(&[0, 1, 4], b"abc")),
            raw_frame(0, 5, &[0]),
            raw_frame(u64::MAX >> 1, 1, &[0, 0]),
            raw_frame(1, 17, &[0, 0]),
            raw_frame(1, 17, &[0, 33]),
            raw_frame(1, 18, &[0, 1, 255, 255, 255, 255]),
            raw_frame(1, 14, &[0, 0]),
            raw_frame(1, 14, &[0, 61, 0, 0, 0, 0, 0, 0, 0, 0]),
            raw_frame(1, 19, &[0, 2, 0, 0, 0]),
        ]);
        for len in 0..valid.len() {
            let mut truncated = valid[..len].to_vec();
            if len >= HEADER_LEN {
                truncated[8..HEADER_LEN]
                    .copy_from_slice(&((len - HEADER_LEN) as u32).to_le_bytes());
            }
            invalid.push(truncated);
        }
        for frame in &invalid {
            assert!(
                !FrameBatch::default().try_append(frame, usize::MAX, 0),
                "{frame:?}"
            );
            assert!(!batch.try_append(frame, usize::MAX, 0), "{frame:?}");
            assert_eq!(encoded(&batch), before);
        }
    }

    #[test]
    fn unaligned_bits_concatenate_bitmaps_and_booleans() {
        let mut bits = Vec::new();
        append_bits(&mut bits, 0, &[0b101], 3);
        append_bits(&mut bits, 3, &[0xFF, 0x01], 9);
        append_bits(&mut bits, 12, &[0b11], 1);
        assert_eq!(bits, [0b1111_1101, 0b0001_1111]);
        append_bits(&mut bits, 13, &[], 0);
        assert_eq!(bits, [0b1111_1101, 0b0001_1111]);
        append_bits(&mut bits, 13, &[0xFF], 3);
        assert_eq!(bits, [0b1111_1101, 0xFF]);
    }
}
