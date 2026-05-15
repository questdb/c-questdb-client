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

/// Wire layout of a QWP datagram header (mirrors production definition).
#[repr(C, packed)]
struct QwpMessageHeader {
    magic: [u8; 4],
    version: u8,
    flags: u8,
    table_count: u16,
    payload_len: u32,
}

const HEADER_SIZE: usize = std::mem::size_of::<QwpMessageHeader>();
const _: () = assert!(HEADER_SIZE == 12);
const TYPE_BOOLEAN: u8 = 0x01;
const TYPE_BYTE: u8 = 0x02;
const TYPE_SHORT: u8 = 0x03;
const TYPE_INT: u8 = 0x04;
const TYPE_LONG: u8 = 0x05;
const TYPE_FLOAT: u8 = 0x06;
const TYPE_DOUBLE: u8 = 0x07;
pub(crate) const TYPE_VARCHAR: u8 = 0x0F;
const TYPE_SYMBOL: u8 = 0x09;
const TYPE_TIMESTAMP: u8 = 0x0A;
const TYPE_DATE: u8 = 0x0B;
const TYPE_UUID: u8 = 0x0C;
const TYPE_LONG256: u8 = 0x0D;
const TYPE_GEOHASH: u8 = 0x0E;
const TYPE_TIMESTAMP_NANOS: u8 = 0x10;
const TYPE_DOUBLE_ARRAY: u8 = 0x11;
const TYPE_LONG_ARRAY: u8 = 0x12;
const TYPE_DECIMAL64: u8 = 0x13;
const TYPE_DECIMAL128: u8 = 0x14;
const TYPE_DECIMAL256: u8 = 0x15;
const TYPE_CHAR: u8 = 0x16;
const TYPE_BINARY: u8 = 0x17;
const TYPE_IPV4: u8 = 0x18;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DecodedDatagram {
    pub(crate) version: u8,
    pub(crate) flags: u8,
    pub(crate) table_count: u16,
    pub(crate) payload_len: u32,
    pub(crate) table: DecodedTable,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DecodedTable {
    pub(crate) name: String,
    pub(crate) row_count: u64,
    pub(crate) schema_mode: u8,
    pub(crate) columns: Vec<DecodedColumn>,
    pub(crate) rows: Vec<Vec<DecodedValue>>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DecodedColumn {
    pub(crate) name: String,
    pub(crate) type_code: u8,
    pub(crate) nullable: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum DecodedValue {
    Bool(bool),
    Symbol(String),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
    String(String),
    Decimal { scale: u8, unscaled_be: Vec<u8> },
    F64Array { shape: Vec<usize>, values: Vec<f64> },
    I64Array { shape: Vec<usize>, values: Vec<i64> },
    TimestampMicros(i64),
    TimestampNanos(i64),
    Uuid { lo: u64, hi: u64 },
    Long256([u8; 32]),
    Ipv4(u32),
    DateMillis(i64),
    Char(u16),
    Binary(Vec<u8>),
    Geohash { bits: u64, precision_bits: u8 },
    Null,
}

struct Decoder<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, String> {
        if self.pos >= self.bytes.len() {
            return Err("unexpected end of datagram".to_owned());
        }
        let value = self.bytes[self.pos];
        self.pos += 1;
        Ok(value)
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], String> {
        if len > self.bytes.len() - self.pos {
            return Err(format!(
                "unexpected end of datagram: need {} bytes, have {}",
                len,
                self.bytes.len().saturating_sub(self.pos)
            ));
        }
        let start = self.pos;
        self.pos += len;
        Ok(&self.bytes[start..self.pos])
    }

    fn read_varint(&mut self) -> Result<u64, String> {
        let mut shift = 0u32;
        let mut value = 0u64;
        loop {
            let byte = self.read_u8()?;
            value |= u64::from(byte & 0x7F) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
            if shift >= 64 {
                return Err("varint is too large".to_owned());
            }
        }
    }

    fn read_string(&mut self) -> Result<String, String> {
        let len = self.read_varint()? as usize;
        let bytes = self.read_exact(len)?;
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|err| format!("invalid utf-8 in string field: {err}"))
    }

    fn read_i64(&mut self) -> Result<i64, String> {
        let bytes = self.read_exact(8)?;
        let mut raw = [0u8; 8];
        raw.copy_from_slice(bytes);
        Ok(i64::from_le_bytes(raw))
    }

    fn read_f64(&mut self) -> Result<f64, String> {
        let bytes = self.read_exact(8)?;
        let mut raw = [0u8; 8];
        raw.copy_from_slice(bytes);
        Ok(f64::from_le_bytes(raw))
    }

    fn read_f32(&mut self) -> Result<f32, String> {
        let bytes = self.read_exact(4)?;
        let mut raw = [0u8; 4];
        raw.copy_from_slice(bytes);
        Ok(f32::from_le_bytes(raw))
    }

    fn read_i32(&mut self) -> Result<i32, String> {
        let bytes = self.read_exact(4)?;
        let mut raw = [0u8; 4];
        raw.copy_from_slice(bytes);
        Ok(i32::from_le_bytes(raw))
    }

    fn read_i16(&mut self) -> Result<i16, String> {
        let bytes = self.read_exact(2)?;
        let mut raw = [0u8; 2];
        raw.copy_from_slice(bytes);
        Ok(i16::from_le_bytes(raw))
    }
}

fn trim_signed_be(bytes: &[u8]) -> Vec<u8> {
    if bytes.is_empty() {
        return vec![0];
    }
    let negative = bytes[0] & 0x80 != 0;
    let mut keep_from = 0usize;
    while keep_from < bytes.len() - 1 {
        let current = bytes[keep_from];
        let next = bytes[keep_from + 1];
        let should_trim = if negative {
            current == 0xFF && (next & 0x80) == 0x80
        } else {
            current == 0x00 && (next & 0x80) == 0x00
        };
        if should_trim {
            keep_from += 1;
        } else {
            break;
        }
    }
    bytes[keep_from..].to_vec()
}

pub(crate) fn decode_datagram(bytes: &[u8]) -> Result<DecodedDatagram, String> {
    if bytes.len() < HEADER_SIZE {
        return Err(format!(
            "datagram too short: expected at least {} bytes, got {}",
            HEADER_SIZE,
            bytes.len()
        ));
    }
    if &bytes[0..4] != b"QWP1" {
        return Err(format!("bad magic: {:?}", &bytes[0..4]));
    }

    let version = bytes[4];
    let flags = bytes[5];
    let table_count = u16::from_le_bytes([bytes[6], bytes[7]]);
    let payload_len = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    let payload = &bytes[HEADER_SIZE..];
    if payload.len() != payload_len as usize {
        return Err(format!(
            "payload length mismatch: header says {}, actual {}",
            payload_len,
            payload.len()
        ));
    }
    if table_count != 1 {
        return Err(format!(
            "decoder only supports single-table datagrams, got {}",
            table_count
        ));
    }

    let mut decoder = Decoder::new(payload);
    let table_name = decoder.read_string()?;
    let row_count = decoder.read_varint()?;
    let column_count = decoder.read_varint()? as usize;
    let schema_mode = decoder.read_u8()?;
    if schema_mode != 0 {
        return Err(format!(
            "decoder only supports full inline schemas, got schema mode {}",
            schema_mode
        ));
    }
    let _schema_id = decoder.read_varint()?;

    let mut columns = Vec::with_capacity(column_count);
    for _ in 0..column_count {
        let name = decoder.read_string()?;
        let type_code = decoder.read_u8()?;
        columns.push(DecodedColumn {
            name,
            type_code,
            nullable: false,
        });
    }

    let row_count_usize: usize = row_count
        .try_into()
        .map_err(|_| format!("row count {} does not fit into usize", row_count))?;
    let mut column_values = Vec::with_capacity(column_count);
    for column in &mut columns {
        let has_null_bitmap = decoder.read_u8()? != 0;
        column.nullable = has_null_bitmap;
        let has_value = if has_null_bitmap {
            let bitmap_size = row_count_usize.div_ceil(8);
            let bitmap = decoder.read_exact(bitmap_size)?;
            (0..row_count_usize)
                .map(|row_idx| {
                    let byte = bitmap[row_idx / 8];
                    let bit = 1u8 << (row_idx % 8);
                    byte & bit == 0
                })
                .collect::<Vec<_>>()
        } else {
            vec![true; row_count_usize]
        };

        let value = match column.type_code {
            TYPE_BOOLEAN => {
                let non_null_count = has_value.iter().filter(|&&present| present).count();
                let packed_size = non_null_count.div_ceil(8);
                let bytes = decoder.read_exact(packed_size)?;
                let mut raw_values = Vec::with_capacity(non_null_count);
                for value_idx in 0..non_null_count {
                    let byte = bytes[value_idx / 8];
                    let bit = 1u8 << (value_idx % 8);
                    raw_values.push(byte & bit != 0);
                }

                let mut next_value = 0usize;
                let mut values = Vec::with_capacity(row_count_usize);
                for present in &has_value {
                    if !present {
                        values.push(DecodedValue::Null);
                        continue;
                    }
                    values.push(DecodedValue::Bool(raw_values[next_value]));
                    next_value += 1;
                }
                values
            }
            TYPE_SYMBOL => {
                let dict_size = decoder.read_varint()? as usize;
                let mut dict = Vec::with_capacity(dict_size);
                for _ in 0..dict_size {
                    dict.push(decoder.read_string()?);
                }
                let non_null_count = has_value.iter().filter(|&&present| present).count();
                let mut indexes = Vec::with_capacity(non_null_count);
                for _ in 0..non_null_count {
                    indexes.push(decoder.read_varint()? as usize);
                }
                let mut next_index = 0usize;
                let mut values = Vec::with_capacity(row_count_usize);
                for present in &has_value {
                    if !present {
                        values.push(DecodedValue::Null);
                        continue;
                    }
                    let idx = indexes[next_index];
                    next_index += 1;
                    let symbol = dict.get(idx).ok_or_else(|| {
                        format!(
                            "symbol index {} out of bounds for dictionary size {}",
                            idx,
                            dict.len()
                        )
                    })?;
                    values.push(DecodedValue::Symbol(symbol.clone()));
                }
                values
            }
            TYPE_BYTE => {
                let non_null_count = has_value.iter().filter(|&&present| present).count();
                let mut raw_values = Vec::with_capacity(non_null_count);
                for _ in 0..non_null_count {
                    raw_values.push(decoder.read_u8()? as i8);
                }
                let mut next_value = 0usize;
                let mut values = Vec::with_capacity(row_count_usize);
                for present in &has_value {
                    if !present {
                        values.push(DecodedValue::Null);
                        continue;
                    }
                    values.push(DecodedValue::I8(raw_values[next_value]));
                    next_value += 1;
                }
                values
            }
            TYPE_SHORT => {
                let non_null_count = has_value.iter().filter(|&&present| present).count();
                let mut raw_values = Vec::with_capacity(non_null_count);
                for _ in 0..non_null_count {
                    raw_values.push(decoder.read_i16()?);
                }
                let mut next_value = 0usize;
                let mut values = Vec::with_capacity(row_count_usize);
                for present in &has_value {
                    if !present {
                        values.push(DecodedValue::Null);
                        continue;
                    }
                    values.push(DecodedValue::I16(raw_values[next_value]));
                    next_value += 1;
                }
                values
            }
            TYPE_INT => {
                let non_null_count = has_value.iter().filter(|&&present| present).count();
                let mut raw_values = Vec::with_capacity(non_null_count);
                for _ in 0..non_null_count {
                    raw_values.push(decoder.read_i32()?);
                }
                let mut next_value = 0usize;
                let mut values = Vec::with_capacity(row_count_usize);
                for present in &has_value {
                    if !present {
                        values.push(DecodedValue::Null);
                        continue;
                    }
                    values.push(DecodedValue::I32(raw_values[next_value]));
                    next_value += 1;
                }
                values
            }
            TYPE_LONG => {
                let non_null_count = has_value.iter().filter(|&&present| present).count();
                let mut raw_values = Vec::with_capacity(non_null_count);
                for _ in 0..non_null_count {
                    raw_values.push(decoder.read_i64()?);
                }

                let mut next_value = 0usize;
                let mut values = Vec::with_capacity(row_count_usize);
                for present in &has_value {
                    if !present {
                        values.push(DecodedValue::Null);
                        continue;
                    }
                    values.push(DecodedValue::I64(raw_values[next_value]));
                    next_value += 1;
                }
                values
            }
            TYPE_FLOAT => {
                let mut raw_values = Vec::with_capacity(row_count_usize);
                for _ in 0..row_count_usize {
                    raw_values.push(decoder.read_f32()?);
                }
                let mut values = Vec::with_capacity(row_count_usize);
                for (idx, present) in has_value.iter().enumerate() {
                    if *present {
                        values.push(DecodedValue::F32(raw_values[idx]));
                    } else {
                        values.push(DecodedValue::Null);
                    }
                }
                values
            }
            TYPE_DOUBLE => {
                let non_null_count = has_value.iter().filter(|&&present| present).count();
                let mut raw_values = Vec::with_capacity(non_null_count);
                for _ in 0..non_null_count {
                    raw_values.push(decoder.read_f64()?);
                }

                let mut next_value = 0usize;
                let mut values = Vec::with_capacity(row_count_usize);
                for present in &has_value {
                    if !present {
                        values.push(DecodedValue::Null);
                        continue;
                    }
                    values.push(DecodedValue::F64(raw_values[next_value]));
                    next_value += 1;
                }
                values
            }
            TYPE_DECIMAL64 | TYPE_DECIMAL128 | TYPE_DECIMAL256 => {
                let width = match column.type_code {
                    TYPE_DECIMAL64 => 8,
                    TYPE_DECIMAL128 => 16,
                    TYPE_DECIMAL256 => 32,
                    _ => unreachable!(),
                };
                let scale = decoder.read_u8()?;
                let non_null_count = has_value.iter().filter(|&&present| present).count();
                let mut raw_values = Vec::with_capacity(non_null_count);
                for _ in 0..non_null_count {
                    let le = decoder.read_exact(width)?;
                    let mut be = le.to_vec();
                    be.reverse();
                    raw_values.push(DecodedValue::Decimal {
                        scale,
                        unscaled_be: trim_signed_be(&be),
                    });
                }

                let mut next_value = 0usize;
                let mut values = Vec::with_capacity(row_count_usize);
                for present in &has_value {
                    if !present {
                        values.push(DecodedValue::Null);
                        continue;
                    }
                    values.push(raw_values[next_value].clone());
                    next_value += 1;
                }
                values
            }
            TYPE_VARCHAR => {
                let non_null_count = has_value.iter().filter(|&&present| present).count();
                let offset_count = non_null_count + 1;
                let mut offsets = Vec::with_capacity(offset_count);
                for _ in 0..offset_count {
                    offsets.push(decoder.read_i32()?);
                }
                let string_data_len = usize::try_from(*offsets.last().unwrap_or(&0))
                    .map_err(|_| "negative string data length".to_owned())?;
                let data = decoder.read_exact(string_data_len)?;
                let mut next_offset = 0usize;
                let mut values = Vec::with_capacity(row_count_usize);
                for present in &has_value {
                    if !present {
                        values.push(DecodedValue::Null);
                        continue;
                    }
                    let start = usize::try_from(offsets[next_offset]).map_err(|_| {
                        format!("invalid string start offset {}", offsets[next_offset])
                    })?;
                    let end = usize::try_from(offsets[next_offset + 1]).map_err(|_| {
                        format!("invalid string end offset {}", offsets[next_offset + 1])
                    })?;
                    if start > end || end > data.len() {
                        return Err(format!(
                            "invalid string offsets: start={start}, end={end}, data_len={}",
                            data.len()
                        ));
                    }
                    let value = std::str::from_utf8(&data[start..end])
                        .map_err(|err| format!("invalid utf-8 in string value: {err}"))?;
                    values.push(DecodedValue::String(value.to_owned()));
                    next_offset += 1;
                }
                values
            }
            TYPE_DOUBLE_ARRAY => {
                let non_null_count = has_value.iter().filter(|&&present| present).count();
                let mut raw_values = Vec::with_capacity(non_null_count);
                for _ in 0..non_null_count {
                    let ndim = decoder.read_u8()? as usize;
                    let mut shape = Vec::with_capacity(ndim);
                    let mut elem_count = 1usize;
                    for _ in 0..ndim {
                        let dim = usize::try_from(decoder.read_i32()?)
                            .map_err(|_| "negative array dimension".to_owned())?;
                        elem_count = elem_count
                            .checked_mul(dim)
                            .ok_or_else(|| "array element count overflow".to_owned())?;
                        shape.push(dim);
                    }
                    let mut values = Vec::with_capacity(elem_count);
                    for _ in 0..elem_count {
                        values.push(decoder.read_f64()?);
                    }
                    raw_values.push(DecodedValue::F64Array { shape, values });
                }

                let mut next_value = 0usize;
                let mut values = Vec::with_capacity(row_count_usize);
                for present in &has_value {
                    if !present {
                        values.push(DecodedValue::Null);
                        continue;
                    }
                    values.push(raw_values[next_value].clone());
                    next_value += 1;
                }
                values
            }
            TYPE_LONG_ARRAY => {
                let non_null_count = has_value.iter().filter(|&&present| present).count();
                let mut raw_values = Vec::with_capacity(non_null_count);
                for _ in 0..non_null_count {
                    let ndim = decoder.read_u8()? as usize;
                    let mut shape = Vec::with_capacity(ndim);
                    let mut elem_count = 1usize;
                    for _ in 0..ndim {
                        let dim = usize::try_from(decoder.read_i32()?)
                            .map_err(|_| "negative array dimension".to_owned())?;
                        elem_count = elem_count
                            .checked_mul(dim)
                            .ok_or_else(|| "array element count overflow".to_owned())?;
                        shape.push(dim);
                    }
                    let mut values = Vec::with_capacity(elem_count);
                    for _ in 0..elem_count {
                        values.push(decoder.read_i64()?);
                    }
                    raw_values.push(DecodedValue::I64Array { shape, values });
                }

                let mut next_value = 0usize;
                let mut values = Vec::with_capacity(row_count_usize);
                for present in &has_value {
                    if !present {
                        values.push(DecodedValue::Null);
                        continue;
                    }
                    values.push(raw_values[next_value].clone());
                    next_value += 1;
                }
                values
            }
            TYPE_UUID => {
                let non_null_count = has_value.iter().filter(|&&present| present).count();
                let mut raw_values = Vec::with_capacity(non_null_count);
                for _ in 0..non_null_count {
                    let lo_bytes = decoder.read_exact(8)?;
                    let mut lo_arr = [0u8; 8];
                    lo_arr.copy_from_slice(lo_bytes);
                    let hi_bytes = decoder.read_exact(8)?;
                    let mut hi_arr = [0u8; 8];
                    hi_arr.copy_from_slice(hi_bytes);
                    raw_values.push((u64::from_le_bytes(lo_arr), u64::from_le_bytes(hi_arr)));
                }
                let mut next_value = 0usize;
                let mut values = Vec::with_capacity(row_count_usize);
                for present in &has_value {
                    if !present {
                        values.push(DecodedValue::Null);
                        continue;
                    }
                    let (lo, hi) = raw_values[next_value];
                    next_value += 1;
                    values.push(DecodedValue::Uuid { lo, hi });
                }
                values
            }
            TYPE_LONG256 => {
                let non_null_count = has_value.iter().filter(|&&present| present).count();
                let mut raw_values = Vec::with_capacity(non_null_count);
                for _ in 0..non_null_count {
                    let bytes = decoder.read_exact(32)?;
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(bytes);
                    raw_values.push(arr);
                }
                let mut next_value = 0usize;
                let mut values = Vec::with_capacity(row_count_usize);
                for present in &has_value {
                    if !present {
                        values.push(DecodedValue::Null);
                        continue;
                    }
                    values.push(DecodedValue::Long256(raw_values[next_value]));
                    next_value += 1;
                }
                values
            }
            TYPE_IPV4 => {
                let non_null_count = has_value.iter().filter(|&&present| present).count();
                let mut raw_values = Vec::with_capacity(non_null_count);
                for _ in 0..non_null_count {
                    let bytes = decoder.read_exact(4)?;
                    let mut arr = [0u8; 4];
                    arr.copy_from_slice(bytes);
                    raw_values.push(u32::from_le_bytes(arr));
                }
                let mut next_value = 0usize;
                let mut values = Vec::with_capacity(row_count_usize);
                for present in &has_value {
                    if !present {
                        values.push(DecodedValue::Null);
                        continue;
                    }
                    values.push(DecodedValue::Ipv4(raw_values[next_value]));
                    next_value += 1;
                }
                values
            }
            TYPE_DATE => {
                let non_null_count = has_value.iter().filter(|&&present| present).count();
                let mut raw_values = Vec::with_capacity(non_null_count);
                for _ in 0..non_null_count {
                    raw_values.push(decoder.read_i64()?);
                }
                let mut next_value = 0usize;
                let mut values = Vec::with_capacity(row_count_usize);
                for present in &has_value {
                    if !present {
                        values.push(DecodedValue::Null);
                        continue;
                    }
                    values.push(DecodedValue::DateMillis(raw_values[next_value]));
                    next_value += 1;
                }
                values
            }
            TYPE_CHAR => {
                let mut raw_values = Vec::with_capacity(row_count_usize);
                for _ in 0..row_count_usize {
                    let bytes = decoder.read_exact(2)?;
                    let mut arr = [0u8; 2];
                    arr.copy_from_slice(bytes);
                    raw_values.push(u16::from_le_bytes(arr));
                }
                let mut values = Vec::with_capacity(row_count_usize);
                for (idx, present) in has_value.iter().enumerate() {
                    if *present {
                        values.push(DecodedValue::Char(raw_values[idx]));
                    } else {
                        values.push(DecodedValue::Null);
                    }
                }
                values
            }
            TYPE_GEOHASH => {
                let precision_bits = decoder.read_varint()? as u8;
                let bytes_per_value = (precision_bits as usize).div_ceil(8);
                let non_null_count = has_value.iter().filter(|&&present| present).count();
                let mut raw_values = Vec::with_capacity(non_null_count);
                for _ in 0..non_null_count {
                    let bytes = decoder.read_exact(bytes_per_value)?;
                    let mut arr = [0u8; 8];
                    arr[..bytes.len()].copy_from_slice(bytes);
                    raw_values.push(u64::from_le_bytes(arr));
                }
                let mut next_value = 0usize;
                let mut values = Vec::with_capacity(row_count_usize);
                for present in &has_value {
                    if !present {
                        values.push(DecodedValue::Null);
                        continue;
                    }
                    values.push(DecodedValue::Geohash {
                        bits: raw_values[next_value],
                        precision_bits,
                    });
                    next_value += 1;
                }
                values
            }
            TYPE_BINARY => {
                let non_null_count = has_value.iter().filter(|&&present| present).count();
                let offset_count = non_null_count + 1;
                let mut offsets = Vec::with_capacity(offset_count);
                for _ in 0..offset_count {
                    offsets.push(decoder.read_i32()?);
                }
                let data_len = usize::try_from(*offsets.last().unwrap_or(&0))
                    .map_err(|_| "negative binary data length".to_owned())?;
                let data = decoder.read_exact(data_len)?;
                let mut next_offset = 0usize;
                let mut values = Vec::with_capacity(row_count_usize);
                for present in &has_value {
                    if !present {
                        values.push(DecodedValue::Null);
                        continue;
                    }
                    let start = usize::try_from(offsets[next_offset]).map_err(|_| {
                        format!("invalid binary start offset {}", offsets[next_offset])
                    })?;
                    let end = usize::try_from(offsets[next_offset + 1]).map_err(|_| {
                        format!("invalid binary end offset {}", offsets[next_offset + 1])
                    })?;
                    values.push(DecodedValue::Binary(data[start..end].to_vec()));
                    next_offset += 1;
                }
                values
            }
            TYPE_TIMESTAMP | TYPE_TIMESTAMP_NANOS => {
                let non_null_count = has_value.iter().filter(|&&present| present).count();
                let mut raw_values = Vec::with_capacity(non_null_count);
                for _ in 0..non_null_count {
                    raw_values.push(decoder.read_i64()?);
                }
                let mut next_value = 0usize;
                let mut values = Vec::with_capacity(row_count_usize);
                for present in &has_value {
                    if !present {
                        values.push(DecodedValue::Null);
                    } else {
                        let value = raw_values[next_value];
                        next_value += 1;
                        if column.type_code == TYPE_TIMESTAMP_NANOS {
                            values.push(DecodedValue::TimestampNanos(value));
                        } else {
                            values.push(DecodedValue::TimestampMicros(value));
                        }
                    }
                }
                values
            }
            other => return Err(format!("unsupported test decoder type code {}", other)),
        };
        column_values.push(value);
    }

    let mut rows = vec![Vec::with_capacity(columns.len()); row_count_usize];
    for values in &column_values {
        for (row_idx, value) in values.iter().cloned().enumerate() {
            rows[row_idx].push(value);
        }
    }

    if decoder.pos != payload.len() {
        return Err(format!(
            "unexpected trailing payload bytes: {}",
            payload.len() - decoder.pos
        ));
    }

    Ok(DecodedDatagram {
        version,
        flags,
        table_count,
        payload_len,
        table: DecodedTable {
            name: table_name,
            row_count,
            schema_mode,
            columns,
            rows,
        },
    })
}
