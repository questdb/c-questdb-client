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

//! `RecordBatch → Buffer` ingress. Walks the batch row-major; column
//! type-hint resolution follows Decision 14 of the design doc
//! (`questdb.column_type` > `ARROW:extension:name` > Arrow type alone).

use arrow_array::types::UInt32Type;
use arrow_array::{
    Array, ArrayRef, BinaryArray, BinaryViewArray, BooleanArray, Decimal64Array, Decimal128Array,
    Decimal256Array, DictionaryArray, FixedSizeBinaryArray, Float32Array, Float64Array, Int8Array,
    Int16Array, Int32Array, Int64Array, LargeBinaryArray, LargeListArray, LargeStringArray,
    ListArray, RecordBatch, StringArray, StringViewArray, TimestampMicrosecondArray,
    TimestampMillisecondArray, TimestampNanosecondArray, UInt16Array, UInt32Array,
};
use arrow_schema::{DataType, TimeUnit};

use crate::error::{Error, ErrorCode};
use crate::ingress::buffer::{
    ArrowBatchInfo, ArrowBulkCtx, ArrowDecimalSpec, QwpColumnKind, QwpWsColumnarBuffer,
};
use crate::ingress::{Buffer, ColumnName, TableName, TimestampNanos};
use crate::{Result, fmt};

/// Per-row designated-timestamp source for [`Buffer::append_arrow`].
#[derive(Clone, Copy)]
#[non_exhaustive]
pub enum DesignatedTimestamp<'a> {
    /// Pull from a named `Timestamp(_)` column.
    Column(ColumnName<'a>),
    /// `TimestampNanos::now()` per row.
    Now,
    /// Omit timestamp (server fills arrival time).
    ServerNow,
}

impl Buffer {
    /// Append every row of `batch` to this buffer via the QWP/WebSocket
    /// columnar bulk path. Requires a QWP/WS buffer; row-by-row protocols
    /// (ILP, QWP/UDP) reject the call. Type-mismatch against the
    /// destination QuestDB table surfaces from the next flush.
    pub fn append_arrow(
        &mut self,
        table: TableName<'_>,
        batch: &RecordBatch,
        designated_timestamp: DesignatedTimestamp<'_>,
    ) -> Result<()> {
        let schema = batch.schema();
        let row_count = batch.num_rows();
        let col_count = batch.num_columns();
        if schema.fields().len() != col_count {
            return Err(fmt!(
                ArrowIngest,
                "RecordBatch schema/columns mismatch: schema={} columns={}",
                schema.fields().len(),
                col_count
            ));
        }
        if row_count == 0 {
            return Ok(());
        }
        let ts_col_idx = match designated_timestamp {
            DesignatedTimestamp::Column(name) => Some(resolve_ts_column(batch, name)?),
            DesignatedTimestamp::Now | DesignatedTimestamp::ServerNow => None,
        };
        let user_columns: Vec<&dyn Array> = schema
            .fields()
            .iter()
            .enumerate()
            .filter_map(|(idx, _)| {
                if Some(idx) == ts_col_idx {
                    None
                } else {
                    Some(batch.column(idx).as_ref())
                }
            })
            .collect();
        let kept = build_kept_indices(&user_columns, row_count);
        if kept.is_empty() {
            return Ok(());
        }
        let effective_rows = u32::try_from(kept.len()).map_err(|_| {
            fmt!(
                ArrowIngest,
                "kept row count {} exceeds u32::MAX",
                kept.len()
            )
        })?;
        let qwp_ws = self.as_qwp_ws_mut().ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidApiCall,
                "Buffer::append_arrow requires a QWP/WebSocket buffer (Buffer::new_qwp)"
                    .to_string(),
            )
        })?;
        let ctx = qwp_ws.arrow_bulk_begin(table)?;
        for (idx, field) in schema.fields().iter().enumerate() {
            if Some(idx) == ts_col_idx {
                continue;
            }
            let col_name = ColumnName::new(field.name())?;
            let kind = classify(field.as_ref(), batch.column(idx).as_ref())?;
            emit_arrow_column(
                qwp_ws,
                &ctx,
                col_name,
                kind,
                batch.column(idx).as_ref(),
                &kept,
                effective_rows,
            )?;
        }
        match designated_timestamp {
            DesignatedTimestamp::Column(_) => {
                let idx = ts_col_idx.unwrap();
                let arr = batch.column(idx);
                emit_arrow_designated_ts(
                    qwp_ws,
                    &ctx,
                    schema.field(idx).data_type(),
                    arr.as_ref(),
                    &kept,
                    effective_rows,
                )?;
            }
            DesignatedTimestamp::Now => {
                emit_arrow_designated_ts_now(qwp_ws, &ctx, effective_rows)?;
            }
            DesignatedTimestamp::ServerNow => {}
        }
        qwp_ws.arrow_bulk_commit(ctx, effective_rows)
    }
}

fn build_kept_indices(user_columns: &[&dyn Array], row_count: usize) -> Vec<usize> {
    let mut kept = Vec::with_capacity(row_count);
    for row in 0..row_count {
        if user_columns.iter().any(|arr| !arr.is_null(row)) {
            kept.push(row);
        }
    }
    kept
}

fn resolve_ts_column(batch: &RecordBatch, name: ColumnName<'_>) -> Result<usize> {
    let target = name.as_ref();
    for (idx, field) in batch.schema().fields().iter().enumerate() {
        if field.name() == target {
            if !matches!(field.data_type(), DataType::Timestamp(_, _)) {
                return Err(fmt!(
                    ArrowIngest,
                    "designated timestamp column '{}' is not Timestamp(_), got {:?}",
                    target,
                    field.data_type()
                ));
            }
            return Ok(idx);
        }
    }
    Err(fmt!(
        ArrowIngest,
        "designated timestamp column '{}' not found in RecordBatch schema",
        target
    ))
}

fn emit_arrow_designated_ts(
    qwp_ws: &mut QwpWsColumnarBuffer,
    ctx: &ArrowBulkCtx,
    dtype: &DataType,
    arr: &dyn Array,
    kept: &[usize],
    effective_rows: u32,
) -> Result<()> {
    if kept.iter().any(|&i| arr.is_null(i)) {
        return Err(fmt!(
            ArrowIngest,
            "designated timestamp column must have no null rows among the kept rows"
        ));
    }
    let info = ArrowBatchInfo {
        bitmap: None,
        rows: effective_rows,
        non_null: effective_rows,
    };
    match dtype {
        DataType::Timestamp(TimeUnit::Microsecond, _) => {
            let a = arr
                .as_any()
                .downcast_ref::<TimestampMicrosecondArray>()
                .unwrap();
            let bytes = non_null_le(arr, kept, |row| a.value(row).to_le_bytes());
            qwp_ws.arrow_bulk_set_designated_ts(ctx, QwpColumnKind::TimestampMicros, &bytes, info)
        }
        DataType::Timestamp(TimeUnit::Nanosecond, _) => {
            let a = arr
                .as_any()
                .downcast_ref::<TimestampNanosecondArray>()
                .unwrap();
            let bytes = non_null_le(arr, kept, |row| a.value(row).to_le_bytes());
            qwp_ws.arrow_bulk_set_designated_ts(ctx, QwpColumnKind::TimestampNanos, &bytes, info)
        }
        DataType::Timestamp(TimeUnit::Millisecond, _) => {
            let a = arr
                .as_any()
                .downcast_ref::<TimestampMillisecondArray>()
                .unwrap();
            let bytes = non_null_le(arr, kept, |row| {
                a.value(row).saturating_mul(1_000).to_le_bytes()
            });
            qwp_ws.arrow_bulk_set_designated_ts(ctx, QwpColumnKind::TimestampMicros, &bytes, info)
        }
        other => Err(fmt!(
            ArrowIngest,
            "designated timestamp column has unsupported Arrow type {:?}",
            other
        )),
    }
}

fn emit_arrow_designated_ts_now(
    qwp_ws: &mut QwpWsColumnarBuffer,
    ctx: &ArrowBulkCtx,
    row_count: u32,
) -> Result<()> {
    let now = TimestampNanos::now().as_i64();
    let mut bytes = Vec::with_capacity(row_count as usize * 8);
    for _ in 0..row_count {
        bytes.extend_from_slice(&now.to_le_bytes());
    }
    qwp_ws.arrow_bulk_set_designated_ts(
        ctx,
        QwpColumnKind::TimestampNanos,
        &bytes,
        ArrowBatchInfo {
            bitmap: None,
            rows: row_count,
            non_null: row_count,
        },
    )
}

fn build_qwp_bitmap(arr: &dyn Array, kept: &[usize]) -> Option<Vec<u8>> {
    if !kept.iter().any(|&i| arr.is_null(i)) {
        return None;
    }
    let mut bitmap = vec![0u8; kept.len().div_ceil(8)];
    for (out_idx, &row) in kept.iter().enumerate() {
        if arr.is_null(row) {
            bitmap[out_idx / 8] |= 1 << (out_idx % 8);
        }
    }
    Some(bitmap)
}

fn full_with_sentinel<const N: usize>(
    arr: &dyn Array,
    kept: &[usize],
    sentinel: [u8; N],
    mut get_bytes: impl FnMut(usize) -> [u8; N],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(kept.len() * N);
    for &row in kept {
        if arr.is_null(row) {
            out.extend_from_slice(&sentinel);
        } else {
            out.extend_from_slice(&get_bytes(row));
        }
    }
    out
}

fn non_null_le<const N: usize>(
    arr: &dyn Array,
    kept: &[usize],
    mut get_bytes: impl FnMut(usize) -> [u8; N],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(kept.len() * N);
    for &row in kept {
        if arr.is_null(row) {
            continue;
        }
        out.extend_from_slice(&get_bytes(row));
    }
    out
}

fn non_null_fsb(arr: &FixedSizeBinaryArray, kept: &[usize], size: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(kept.len() * size);
    for &row in kept {
        if arr.is_null(row) {
            continue;
        }
        out.extend_from_slice(arr.value(row));
    }
    out
}

fn emit_arrow_column(
    qwp_ws: &mut QwpWsColumnarBuffer,
    ctx: &ArrowBulkCtx,
    col_name: ColumnName<'_>,
    kind: ColumnKind,
    arr: &dyn Array,
    kept: &[usize],
    effective_rows: u32,
) -> Result<()> {
    let qwp_bitmap = build_qwp_bitmap(arr, kept);
    let null_count = kept.iter().filter(|&&i| arr.is_null(i)).count();
    let non_null = u32::try_from(kept.len() - null_count).map_err(|_| {
        fmt!(
            ArrowIngest,
            "non-null count overflow for column '{}'",
            col_name.as_ref()
        )
    })?;
    let info_full = ArrowBatchInfo {
        bitmap: None,
        rows: effective_rows,
        non_null,
    };
    let info_sparse = ArrowBatchInfo {
        bitmap: qwp_bitmap.as_deref(),
        rows: effective_rows,
        non_null,
    };
    match kind {
        ColumnKind::Bool => {
            let a = arr.as_any().downcast_ref::<BooleanArray>().unwrap();
            let packed = pack_bool_bits(a, kept);
            qwp_ws.arrow_bulk_set_bool(ctx, col_name, &packed, info_full)
        }
        ColumnKind::I8 => {
            let a = arr.as_any().downcast_ref::<Int8Array>().unwrap();
            let bytes = full_with_sentinel(arr, kept, [0u8; 1], |row| [a.value(row) as u8]);
            qwp_ws.arrow_bulk_set_fixed(ctx, col_name, QwpColumnKind::I8, &bytes, info_full)
        }
        ColumnKind::I16 => {
            let a = arr.as_any().downcast_ref::<Int16Array>().unwrap();
            let bytes = full_with_sentinel(arr, kept, 0i16.to_le_bytes(), |row| {
                a.value(row).to_le_bytes()
            });
            qwp_ws.arrow_bulk_set_fixed(ctx, col_name, QwpColumnKind::I16, &bytes, info_full)
        }
        ColumnKind::I32 => {
            let a = arr.as_any().downcast_ref::<Int32Array>().unwrap();
            let bytes = full_with_sentinel(arr, kept, i32::MIN.to_le_bytes(), |row| {
                a.value(row).to_le_bytes()
            });
            qwp_ws.arrow_bulk_set_fixed(ctx, col_name, QwpColumnKind::I32, &bytes, info_full)
        }
        ColumnKind::I64 => {
            let a = arr.as_any().downcast_ref::<Int64Array>().unwrap();
            let bytes = full_with_sentinel(arr, kept, i64::MIN.to_le_bytes(), |row| {
                a.value(row).to_le_bytes()
            });
            qwp_ws.arrow_bulk_set_fixed(ctx, col_name, QwpColumnKind::I64, &bytes, info_full)
        }
        ColumnKind::F32 => {
            let a = arr.as_any().downcast_ref::<Float32Array>().unwrap();
            let bytes = full_with_sentinel(arr, kept, f32::NAN.to_le_bytes(), |row| {
                a.value(row).to_le_bytes()
            });
            qwp_ws.arrow_bulk_set_fixed(ctx, col_name, QwpColumnKind::F32, &bytes, info_full)
        }
        ColumnKind::F64 => {
            let a = arr.as_any().downcast_ref::<Float64Array>().unwrap();
            let bytes = full_with_sentinel(arr, kept, f64::NAN.to_le_bytes(), |row| {
                a.value(row).to_le_bytes()
            });
            qwp_ws.arrow_bulk_set_fixed(ctx, col_name, QwpColumnKind::F64, &bytes, info_full)
        }
        ColumnKind::Char => {
            let a = arr.as_any().downcast_ref::<UInt16Array>().unwrap();
            let bytes = full_with_sentinel(arr, kept, 0u16.to_le_bytes(), |row| {
                a.value(row).to_le_bytes()
            });
            qwp_ws.arrow_bulk_set_fixed(ctx, col_name, QwpColumnKind::Char, &bytes, info_full)
        }
        ColumnKind::Ipv4 => {
            let a = arr.as_any().downcast_ref::<UInt32Array>().unwrap();
            let bytes = non_null_le(arr, kept, |row| a.value(row).to_le_bytes());
            qwp_ws.arrow_bulk_set_fixed(ctx, col_name, QwpColumnKind::Ipv4, &bytes, info_sparse)
        }
        ColumnKind::U16WidenToI32 => {
            let a = arr.as_any().downcast_ref::<UInt16Array>().unwrap();
            let bytes = full_with_sentinel(arr, kept, i32::MIN.to_le_bytes(), |row| {
                (a.value(row) as i32).to_le_bytes()
            });
            qwp_ws.arrow_bulk_set_fixed(ctx, col_name, QwpColumnKind::I32, &bytes, info_full)
        }
        ColumnKind::U32WidenToI64 => {
            let a = arr.as_any().downcast_ref::<UInt32Array>().unwrap();
            let bytes = full_with_sentinel(arr, kept, i64::MIN.to_le_bytes(), |row| {
                (a.value(row) as i64).to_le_bytes()
            });
            qwp_ws.arrow_bulk_set_fixed(ctx, col_name, QwpColumnKind::I64, &bytes, info_full)
        }
        ColumnKind::TimestampMicros => {
            let a = arr
                .as_any()
                .downcast_ref::<TimestampMicrosecondArray>()
                .unwrap();
            let bytes = non_null_le(arr, kept, |row| a.value(row).to_le_bytes());
            qwp_ws.arrow_bulk_set_fixed(
                ctx,
                col_name,
                QwpColumnKind::TimestampMicros,
                &bytes,
                info_sparse,
            )
        }
        ColumnKind::TimestampNanos => {
            let a = arr
                .as_any()
                .downcast_ref::<TimestampNanosecondArray>()
                .unwrap();
            let bytes = non_null_le(arr, kept, |row| a.value(row).to_le_bytes());
            qwp_ws.arrow_bulk_set_fixed(
                ctx,
                col_name,
                QwpColumnKind::TimestampNanos,
                &bytes,
                info_sparse,
            )
        }
        ColumnKind::Date => {
            let a = arr
                .as_any()
                .downcast_ref::<TimestampMillisecondArray>()
                .unwrap();
            let bytes = non_null_le(arr, kept, |row| a.value(row).to_le_bytes());
            qwp_ws.arrow_bulk_set_fixed(ctx, col_name, QwpColumnKind::Date, &bytes, info_sparse)
        }
        ColumnKind::Utf8 => {
            let a = arr.as_any().downcast_ref::<StringArray>().unwrap();
            let (offsets, data) = build_varlen_from_string(a, kept)?;
            qwp_ws.arrow_bulk_set_varlen(
                ctx,
                col_name,
                QwpColumnKind::String,
                &offsets,
                &data,
                info_sparse,
            )
        }
        ColumnKind::LargeUtf8 => {
            let a = arr.as_any().downcast_ref::<LargeStringArray>().unwrap();
            let (offsets, data) = build_varlen_from_large_string(a, kept)?;
            qwp_ws.arrow_bulk_set_varlen(
                ctx,
                col_name,
                QwpColumnKind::String,
                &offsets,
                &data,
                info_sparse,
            )
        }
        ColumnKind::Utf8View => {
            let a = arr.as_any().downcast_ref::<StringViewArray>().unwrap();
            let (offsets, data) = build_varlen_from_string_view(a, kept)?;
            qwp_ws.arrow_bulk_set_varlen(
                ctx,
                col_name,
                QwpColumnKind::String,
                &offsets,
                &data,
                info_sparse,
            )
        }
        ColumnKind::Binary => {
            let a = arr.as_any().downcast_ref::<BinaryArray>().unwrap();
            let (offsets, data) = build_varlen_from_binary(a, kept)?;
            qwp_ws.arrow_bulk_set_varlen(
                ctx,
                col_name,
                QwpColumnKind::Binary,
                &offsets,
                &data,
                info_sparse,
            )
        }
        ColumnKind::LargeBinary => {
            let a = arr.as_any().downcast_ref::<LargeBinaryArray>().unwrap();
            let (offsets, data) = build_varlen_from_large_binary(a, kept)?;
            qwp_ws.arrow_bulk_set_varlen(
                ctx,
                col_name,
                QwpColumnKind::Binary,
                &offsets,
                &data,
                info_sparse,
            )
        }
        ColumnKind::BinaryView => {
            let a = arr.as_any().downcast_ref::<BinaryViewArray>().unwrap();
            let (offsets, data) = build_varlen_from_binary_view(a, kept)?;
            qwp_ws.arrow_bulk_set_varlen(
                ctx,
                col_name,
                QwpColumnKind::Binary,
                &offsets,
                &data,
                info_sparse,
            )
        }
        ColumnKind::Uuid => {
            let a = arr.as_any().downcast_ref::<FixedSizeBinaryArray>().unwrap();
            let bytes = non_null_fsb(a, kept, 16);
            qwp_ws.arrow_bulk_set_fixed(ctx, col_name, QwpColumnKind::Uuid, &bytes, info_sparse)
        }
        ColumnKind::Long256 => {
            let a = arr.as_any().downcast_ref::<FixedSizeBinaryArray>().unwrap();
            let bytes = non_null_fsb(a, kept, 32);
            qwp_ws.arrow_bulk_set_fixed(ctx, col_name, QwpColumnKind::Long256, &bytes, info_sparse)
        }
        ColumnKind::Geohash(precision) => {
            let bytes = build_geohash_bytes(arr, kept, precision)?;
            qwp_ws.arrow_bulk_set_geohash(ctx, col_name, &bytes, precision, info_sparse)
        }
        ColumnKind::SymbolDict => {
            let dict = arr
                .as_any()
                .downcast_ref::<DictionaryArray<UInt32Type>>()
                .unwrap();
            let (keys, entries, dict_data) = build_symbol_payload(dict, kept)?;
            qwp_ws.arrow_bulk_set_symbol(ctx, col_name, &keys, &entries, &dict_data, info_sparse)
        }
        ColumnKind::SymbolDictAsStr => {
            let dict = arr
                .as_any()
                .downcast_ref::<DictionaryArray<UInt32Type>>()
                .unwrap();
            let (offsets, data) = build_varlen_from_dict_as_str(dict, kept)?;
            qwp_ws.arrow_bulk_set_varlen(
                ctx,
                col_name,
                QwpColumnKind::String,
                &offsets,
                &data,
                info_sparse,
            )
        }
        ColumnKind::Decimal64 => {
            let a = arr.as_any().downcast_ref::<Decimal64Array>().unwrap();
            let (values, scale) = build_decimal_bytes_i64(a, kept)?;
            qwp_ws.arrow_bulk_set_decimal(
                ctx,
                col_name,
                QwpColumnKind::Decimal64,
                &values,
                ArrowDecimalSpec {
                    scale,
                    element_width: 8,
                },
                info_sparse,
            )
        }
        ColumnKind::Decimal128 => {
            let a = arr.as_any().downcast_ref::<Decimal128Array>().unwrap();
            let (values, scale) = build_decimal_bytes_i128(a, kept)?;
            qwp_ws.arrow_bulk_set_decimal(
                ctx,
                col_name,
                QwpColumnKind::Decimal128,
                &values,
                ArrowDecimalSpec {
                    scale,
                    element_width: 16,
                },
                info_sparse,
            )
        }
        ColumnKind::Decimal256 => {
            let a = arr.as_any().downcast_ref::<Decimal256Array>().unwrap();
            let (values, scale) = build_decimal_bytes_i256(a, kept)?;
            qwp_ws.arrow_bulk_set_decimal(
                ctx,
                col_name,
                QwpColumnKind::Decimal,
                &values,
                ArrowDecimalSpec {
                    scale,
                    element_width: 32,
                },
                info_sparse,
            )
        }
        ColumnKind::ArrayDouble(ndim) => {
            let data = build_array_blob_data(arr, kept, ndim)?;
            qwp_ws.arrow_bulk_set_array(
                ctx,
                col_name,
                QwpColumnKind::DoubleArray,
                &data,
                info_sparse,
            )
        }
    }
}

fn pack_bool_bits(arr: &BooleanArray, kept: &[usize]) -> Vec<u8> {
    let mut packed = vec![0u8; kept.len().div_ceil(8)];
    for (out_idx, &row) in kept.iter().enumerate() {
        if !arr.is_null(row) && arr.value(row) {
            packed[out_idx / 8] |= 1 << (out_idx % 8);
        }
    }
    packed
}

fn build_varlen_from_string(arr: &StringArray, kept: &[usize]) -> Result<(Vec<u32>, Vec<u8>)> {
    let mut offsets = vec![0u32];
    let mut data: Vec<u8> = Vec::with_capacity(arr.value_data().len());
    let mut cumulative: u32 = 0;
    for &row in kept {
        if arr.is_null(row) {
            continue;
        }
        let s = arr.value(row).as_bytes();
        cumulative = cumulative
            .checked_add(s.len() as u32)
            .ok_or_else(|| fmt!(ArrowIngest, "VARCHAR cumulative offset exceeds u32::MAX"))?;
        data.extend_from_slice(s);
        offsets.push(cumulative);
    }
    Ok((offsets, data))
}

fn build_varlen_from_large_string(
    arr: &LargeStringArray,
    kept: &[usize],
) -> Result<(Vec<u32>, Vec<u8>)> {
    let mut offsets = vec![0u32];
    let mut data: Vec<u8> = Vec::with_capacity(arr.value_data().len());
    let mut cumulative: u32 = 0;
    for &row in kept {
        if arr.is_null(row) {
            continue;
        }
        let s = arr.value(row).as_bytes();
        let len_u32 = u32::try_from(s.len())
            .map_err(|_| fmt!(ArrowIngest, "LargeUtf8 row length exceeds u32::MAX"))?;
        cumulative = cumulative
            .checked_add(len_u32)
            .ok_or_else(|| fmt!(ArrowIngest, "LargeUtf8 cumulative offset exceeds u32::MAX"))?;
        data.extend_from_slice(s);
        offsets.push(cumulative);
    }
    Ok((offsets, data))
}

fn build_varlen_from_string_view(
    arr: &StringViewArray,
    kept: &[usize],
) -> Result<(Vec<u32>, Vec<u8>)> {
    let mut offsets = vec![0u32];
    let mut data: Vec<u8> = Vec::new();
    let mut cumulative: u32 = 0;
    for &row in kept {
        if arr.is_null(row) {
            continue;
        }
        let s = arr.value(row).as_bytes();
        cumulative = cumulative
            .checked_add(s.len() as u32)
            .ok_or_else(|| fmt!(ArrowIngest, "VARCHAR cumulative offset exceeds u32::MAX"))?;
        data.extend_from_slice(s);
        offsets.push(cumulative);
    }
    Ok((offsets, data))
}

fn build_varlen_from_binary(arr: &BinaryArray, kept: &[usize]) -> Result<(Vec<u32>, Vec<u8>)> {
    let mut offsets = vec![0u32];
    let mut data: Vec<u8> = Vec::with_capacity(arr.value_data().len());
    let mut cumulative: u32 = 0;
    for &row in kept {
        if arr.is_null(row) {
            continue;
        }
        let s = arr.value(row);
        cumulative = cumulative
            .checked_add(s.len() as u32)
            .ok_or_else(|| fmt!(ArrowIngest, "BINARY cumulative offset exceeds u32::MAX"))?;
        data.extend_from_slice(s);
        offsets.push(cumulative);
    }
    Ok((offsets, data))
}

fn build_varlen_from_large_binary(
    arr: &LargeBinaryArray,
    kept: &[usize],
) -> Result<(Vec<u32>, Vec<u8>)> {
    let mut offsets = vec![0u32];
    let mut data: Vec<u8> = Vec::with_capacity(arr.value_data().len());
    let mut cumulative: u32 = 0;
    for &row in kept {
        if arr.is_null(row) {
            continue;
        }
        let s = arr.value(row);
        let len_u32 = u32::try_from(s.len())
            .map_err(|_| fmt!(ArrowIngest, "LargeBinary row length exceeds u32::MAX"))?;
        cumulative = cumulative.checked_add(len_u32).ok_or_else(|| {
            fmt!(
                ArrowIngest,
                "LargeBinary cumulative offset exceeds u32::MAX"
            )
        })?;
        data.extend_from_slice(s);
        offsets.push(cumulative);
    }
    Ok((offsets, data))
}

fn build_varlen_from_binary_view(
    arr: &BinaryViewArray,
    kept: &[usize],
) -> Result<(Vec<u32>, Vec<u8>)> {
    let mut offsets = vec![0u32];
    let mut data: Vec<u8> = Vec::new();
    let mut cumulative: u32 = 0;
    for &row in kept {
        if arr.is_null(row) {
            continue;
        }
        let s = arr.value(row);
        cumulative = cumulative
            .checked_add(s.len() as u32)
            .ok_or_else(|| fmt!(ArrowIngest, "BINARY cumulative offset exceeds u32::MAX"))?;
        data.extend_from_slice(s);
        offsets.push(cumulative);
    }
    Ok((offsets, data))
}

fn build_varlen_from_dict_as_str(
    dict: &DictionaryArray<UInt32Type>,
    kept: &[usize],
) -> Result<(Vec<u32>, Vec<u8>)> {
    let mut offsets = vec![0u32];
    let mut data: Vec<u8> = Vec::new();
    let mut cumulative: u32 = 0;
    for &row in kept {
        if dict.is_null(row) {
            continue;
        }
        let s = dict_value_str(dict, row)?.as_bytes();
        cumulative = cumulative
            .checked_add(s.len() as u32)
            .ok_or_else(|| fmt!(ArrowIngest, "VARCHAR cumulative offset exceeds u32::MAX"))?;
        data.extend_from_slice(s);
        offsets.push(cumulative);
    }
    Ok((offsets, data))
}

fn build_geohash_bytes(arr: &dyn Array, kept: &[usize], precision_bits: u8) -> Result<Vec<u8>> {
    if !(1..=60).contains(&precision_bits) {
        return Err(fmt!(
            ArrowIngest,
            "geohash precision_bits {} out of range (1..=60)",
            precision_bits
        ));
    }
    let width = (precision_bits as usize).div_ceil(8);
    let non_null = arr.len() - arr.null_count();
    let mut out = Vec::with_capacity(non_null * width);
    for &row in kept {
        if arr.is_null(row) {
            continue;
        }
        let v = geohash_value_from_array(arr, row)?;
        let le = v.to_le_bytes();
        out.extend_from_slice(&le[..width]);
    }
    Ok(out)
}

type SymbolPayload = (Vec<u32>, Vec<(u32, u32)>, Vec<u8>);

fn build_symbol_payload(
    dict: &DictionaryArray<UInt32Type>,
    kept: &[usize],
) -> Result<SymbolPayload> {
    let values = dict
        .values()
        .as_any()
        .downcast_ref::<StringArray>()
        .ok_or_else(|| {
            fmt!(
                ArrowIngest,
                "dictionary values must be Utf8 for SYMBOL ingress"
            )
        })?;
    let mut entries: Vec<(u32, u32)> = Vec::with_capacity(values.len());
    let mut dict_data: Vec<u8> = Vec::with_capacity(values.value_data().len());
    let mut cumulative: u32 = 0;
    for i in 0..values.len() {
        let bytes = values.value(i).as_bytes();
        let len = u32::try_from(bytes.len())
            .map_err(|_| fmt!(ArrowIngest, "SYMBOL entry length exceeds u32::MAX"))?;
        entries.push((cumulative, len));
        dict_data.extend_from_slice(bytes);
        cumulative = cumulative
            .checked_add(len)
            .ok_or_else(|| fmt!(ArrowIngest, "SYMBOL cumulative data exceeds u32::MAX"))?;
    }
    let keys_src = dict.keys();
    let mut keys: Vec<u32> = Vec::with_capacity(kept.len());
    for &row in kept {
        if dict.is_null(row) {
            keys.push(0);
            continue;
        }
        keys.push(keys_src.value(row));
    }
    Ok((keys, entries, dict_data))
}

fn build_decimal_bytes_i64(arr: &Decimal64Array, kept: &[usize]) -> Result<(Vec<u8>, u8)> {
    let scale_i8 = arr.scale();
    if scale_i8 < 0 {
        return Err(fmt!(
            ArrowIngest,
            "Arrow Decimal64 negative scale {} not supported",
            scale_i8
        ));
    }
    let scale = scale_i8 as u8;
    let mut out: Vec<u8> = Vec::with_capacity((arr.len() - arr.null_count()) * 8);
    for &row in kept {
        if arr.is_null(row) {
            continue;
        }
        out.extend_from_slice(&arr.value(row).to_le_bytes());
    }
    Ok((out, scale))
}

fn build_decimal_bytes_i128(arr: &Decimal128Array, kept: &[usize]) -> Result<(Vec<u8>, u8)> {
    let scale_i8 = arr.scale();
    if scale_i8 < 0 {
        return Err(fmt!(
            ArrowIngest,
            "Arrow Decimal128 negative scale {} not supported",
            scale_i8
        ));
    }
    let scale = scale_i8 as u8;
    let mut out: Vec<u8> = Vec::with_capacity((arr.len() - arr.null_count()) * 16);
    for &row in kept {
        if arr.is_null(row) {
            continue;
        }
        out.extend_from_slice(&arr.value(row).to_le_bytes());
    }
    Ok((out, scale))
}

fn build_decimal_bytes_i256(arr: &Decimal256Array, kept: &[usize]) -> Result<(Vec<u8>, u8)> {
    let scale_i8 = arr.scale();
    if scale_i8 < 0 {
        return Err(fmt!(
            ArrowIngest,
            "Arrow Decimal256 negative scale {} not supported",
            scale_i8
        ));
    }
    let scale = scale_i8 as u8;
    let mut out: Vec<u8> = Vec::with_capacity((arr.len() - arr.null_count()) * 32);
    for &row in kept {
        if arr.is_null(row) {
            continue;
        }
        let bytes = arr.value(row).to_le_bytes();
        out.extend_from_slice(&bytes);
    }
    Ok((out, scale))
}

fn build_array_blob_data(arr: &dyn Array, kept: &[usize], ndim: usize) -> Result<Vec<u8>> {
    let mut data: Vec<u8> = Vec::new();
    for &row in kept {
        if arr.is_null(row) {
            continue;
        }
        let extract = extract_array_row(arr, ndim, row)?;
        let leaf = extract
            .leaf
            .as_any()
            .downcast_ref::<Float64Array>()
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::ArrowUnsupportedColumnKind,
                    format!(
                        "ARRAY leaf must be Float64, got {:?}",
                        extract.leaf.data_type()
                    ),
                )
            })?;
        let leaf_values = &leaf.values()[extract.leaf_start..extract.leaf_end];
        let ndim_u8 = u8::try_from(extract.shape.len()).map_err(|_| {
            fmt!(
                ArrowIngest,
                "ARRAY ndim {} exceeds u8::MAX",
                extract.shape.len()
            )
        })?;
        data.push(ndim_u8);
        for &dim in &extract.shape {
            let dim_u32 = u32::try_from(dim)
                .map_err(|_| fmt!(ArrowIngest, "ARRAY dimension {} exceeds u32::MAX", dim))?;
            data.extend_from_slice(&dim_u32.to_le_bytes());
        }
        for &v in leaf_values {
            data.extend_from_slice(&v.to_le_bytes());
        }
    }
    Ok(data)
}

fn walk_list_leaf(dt: &DataType) -> (DataType, usize) {
    let mut current = dt;
    let mut ndim = 0;
    loop {
        match current {
            DataType::List(inner) | DataType::LargeList(inner) => {
                ndim += 1;
                current = inner.data_type();
            }
            _ => return (current.clone(), ndim),
        }
    }
}

struct ArrayRowExtract {
    shape: Vec<usize>,
    leaf: ArrayRef,
    leaf_start: usize,
    leaf_end: usize,
}

fn extract_array_row(outer: &dyn Array, ndim: usize, row: usize) -> Result<ArrayRowExtract> {
    let (mut start, mut end) = list_row_range(outer, row)?;
    let mut shape: Vec<usize> = Vec::with_capacity(ndim);
    shape.push(end - start);
    let mut current_values: ArrayRef = list_values(outer)?;
    for _ in 1..ndim {
        let (level_start, level_end, level_dim, next_values) =
            list_level_descend(&*current_values, start, end)?;
        shape.push(level_dim);
        start = level_start;
        end = level_end;
        current_values = next_values;
    }
    Ok(ArrayRowExtract {
        shape,
        leaf: current_values,
        leaf_start: start,
        leaf_end: end,
    })
}

fn list_row_range(arr: &dyn Array, row: usize) -> Result<(usize, usize)> {
    if let Some(la) = arr.as_any().downcast_ref::<ListArray>() {
        let offsets = la.offsets();
        Ok((offsets[row] as usize, offsets[row + 1] as usize))
    } else if let Some(la) = arr.as_any().downcast_ref::<LargeListArray>() {
        let offsets = la.offsets();
        Ok((offsets[row] as usize, offsets[row + 1] as usize))
    } else {
        Err(fmt!(
            ArrowIngest,
            "expected List / LargeList at outer ARRAY level, got {:?}",
            arr.data_type()
        ))
    }
}

fn list_values(arr: &dyn Array) -> Result<ArrayRef> {
    if let Some(la) = arr.as_any().downcast_ref::<ListArray>() {
        Ok(la.values().clone())
    } else if let Some(la) = arr.as_any().downcast_ref::<LargeListArray>() {
        Ok(la.values().clone())
    } else {
        Err(fmt!(
            ArrowIngest,
            "expected List / LargeList, got {:?}",
            arr.data_type()
        ))
    }
}

fn list_level_descend(
    arr: &dyn Array,
    start: usize,
    end: usize,
) -> Result<(usize, usize, usize, ArrayRef)> {
    if let Some(la) = arr.as_any().downcast_ref::<ListArray>() {
        let offsets = la.offsets();
        if end <= start {
            return Ok((0, 0, 0, la.values().clone()));
        }
        let next_start = offsets[start] as usize;
        let first_end = offsets[start + 1] as usize;
        let dim = first_end - next_start;
        let next_end = offsets[end] as usize;
        Ok((next_start, next_end, dim, la.values().clone()))
    } else if let Some(la) = arr.as_any().downcast_ref::<LargeListArray>() {
        let offsets = la.offsets();
        if end <= start {
            return Ok((0, 0, 0, la.values().clone()));
        }
        let next_start = offsets[start] as usize;
        let first_end = offsets[start + 1] as usize;
        let dim = first_end - next_start;
        let next_end = offsets[end] as usize;
        Ok((next_start, next_end, dim, la.values().clone()))
    } else {
        Err(fmt!(
            ArrowIngest,
            "expected List / LargeList in ARRAY descent, got {:?}",
            arr.data_type()
        ))
    }
}

fn dict_value_str(dict: &DictionaryArray<UInt32Type>, row: usize) -> Result<&str> {
    let key = dict.keys().value(row);
    let values = dict.values();
    let utf8 = values
        .as_any()
        .downcast_ref::<StringArray>()
        .ok_or_else(|| {
            fmt!(
                ArrowIngest,
                "dictionary values must be Utf8 for SYMBOL / VARCHAR ingress"
            )
        })?;
    let key_usize = key as usize;
    if key_usize >= utf8.len() {
        return Err(fmt!(
            ArrowIngest,
            "dict key {} out of range (dict size {})",
            key,
            utf8.len()
        ));
    }
    Ok(utf8.value(key_usize))
}

fn geohash_value_from_array(arr: &dyn Array, row: usize) -> Result<u64> {
    if let Some(a) = arr.as_any().downcast_ref::<Int8Array>() {
        Ok(a.value(row) as u8 as u64)
    } else if let Some(a) = arr.as_any().downcast_ref::<Int16Array>() {
        Ok(a.value(row) as u16 as u64)
    } else if let Some(a) = arr.as_any().downcast_ref::<Int32Array>() {
        Ok(a.value(row) as u32 as u64)
    } else if let Some(a) = arr.as_any().downcast_ref::<Int64Array>() {
        Ok(a.value(row) as u64)
    } else {
        Err(fmt!(
            ArrowIngest,
            "geohash column has unsupported Arrow type {:?}",
            arr.data_type()
        ))
    }
}

#[derive(Debug, Clone, Copy)]
enum ColumnKind {
    Bool,
    I8,
    I16,
    I32,
    I64,
    F32,
    F64,
    Char,
    Ipv4,
    U16WidenToI32,
    U32WidenToI64,
    TimestampMicros,
    TimestampNanos,
    Date,
    Utf8,
    LargeUtf8,
    Utf8View,
    Binary,
    LargeBinary,
    BinaryView,
    Uuid,
    Long256,
    Geohash(u8),
    SymbolDict,
    SymbolDictAsStr,
    Decimal64,
    Decimal128,
    Decimal256,
    ArrayDouble(usize),
}

fn classify(field: &arrow_schema::Field, _array: &dyn Array) -> Result<ColumnKind> {
    let md_type = field
        .metadata()
        .get(crate::egress::arrow::metadata::COLUMN_TYPE)
        .map(String::as_str);
    let md_ext = field
        .metadata()
        .get(crate::egress::arrow::metadata::ARROW_EXTENSION_NAME)
        .map(String::as_str);
    let md_symbol = field
        .metadata()
        .get(crate::egress::arrow::metadata::SYMBOL)
        .map(String::as_str)
        == Some("true");
    let md_geo_bits = field
        .metadata()
        .get(crate::egress::arrow::metadata::GEOHASH_BITS)
        .and_then(|s| s.parse::<u8>().ok());
    Ok(match (field.data_type(), md_type, md_ext) {
        (DataType::Boolean, _, _) => ColumnKind::Bool,
        (DataType::Int8, Some("byte"), _) => ColumnKind::I8,
        (DataType::Int8, Some(name), _) if name.starts_with("geohash") => {
            ColumnKind::Geohash(md_geo_bits.unwrap_or(8))
        }
        (DataType::Int8, _, _) if md_geo_bits.is_some() => {
            ColumnKind::Geohash(md_geo_bits.unwrap())
        }
        (DataType::Int8, _, _) => ColumnKind::I8,
        (DataType::Int16, _, _) if md_geo_bits.is_some() => {
            ColumnKind::Geohash(md_geo_bits.unwrap())
        }
        (DataType::Int16, _, _) => ColumnKind::I16,
        (DataType::Int32, _, _) if md_geo_bits.is_some() => {
            ColumnKind::Geohash(md_geo_bits.unwrap())
        }
        (DataType::Int32, _, _) => ColumnKind::I32,
        (DataType::Int64, _, _) if md_geo_bits.is_some() => {
            ColumnKind::Geohash(md_geo_bits.unwrap())
        }
        (DataType::Int64, _, _) => ColumnKind::I64,
        (DataType::Float32, _, _) => ColumnKind::F32,
        (DataType::Float64, _, _) => ColumnKind::F64,
        (DataType::UInt16, Some("char"), _) => ColumnKind::Char,
        (DataType::UInt16, _, _) => ColumnKind::U16WidenToI32,
        (DataType::UInt32, Some("ipv4"), _) => ColumnKind::Ipv4,
        (DataType::UInt32, _, _) => ColumnKind::U32WidenToI64,
        (DataType::Timestamp(TimeUnit::Microsecond, _), _, _) => ColumnKind::TimestampMicros,
        (DataType::Timestamp(TimeUnit::Nanosecond, _), _, _) => ColumnKind::TimestampNanos,
        (DataType::Timestamp(TimeUnit::Millisecond, _), _, _) => ColumnKind::Date,
        (DataType::Utf8, _, _) => ColumnKind::Utf8,
        (DataType::LargeUtf8, _, _) => ColumnKind::LargeUtf8,
        (DataType::Utf8View, _, _) => ColumnKind::Utf8View,
        (DataType::Binary, _, _) => ColumnKind::Binary,
        (DataType::LargeBinary, _, _) => ColumnKind::LargeBinary,
        (DataType::BinaryView, _, _) => ColumnKind::BinaryView,
        (DataType::FixedSizeBinary(16), Some("uuid"), _) => ColumnKind::Uuid,
        (DataType::FixedSizeBinary(16), _, Some("arrow.uuid")) => ColumnKind::Uuid,
        (DataType::FixedSizeBinary(16), _, _) => {
            return Err(Error::new(
                ErrorCode::ArrowUnsupportedColumnKind,
                format!(
                    "FixedSizeBinary(16) column '{}' lacks UUID metadata; LONG128 ingress is not yet wired",
                    field.name()
                ),
            ));
        }
        (DataType::FixedSizeBinary(32), _, _) => ColumnKind::Long256,
        (DataType::Dictionary(key, value), _, _)
            if matches!(**key, DataType::UInt32) && matches!(**value, DataType::Utf8) =>
        {
            if md_symbol {
                ColumnKind::SymbolDict
            } else {
                ColumnKind::SymbolDictAsStr
            }
        }
        (DataType::Decimal64(_, _), _, _) => ColumnKind::Decimal64,
        (DataType::Decimal128(_, _), _, _) => ColumnKind::Decimal128,
        (DataType::Decimal256(_, _), _, _) => ColumnKind::Decimal256,
        (DataType::List(_) | DataType::LargeList(_), _, _) => {
            let (leaf, ndim) = walk_list_leaf(field.data_type());
            match leaf {
                DataType::Float64 => ColumnKind::ArrayDouble(ndim),
                other => {
                    return Err(Error::new(
                        ErrorCode::ArrowUnsupportedColumnKind,
                        format!(
                            "Arrow nested-list column '{}' leaf {:?} is not supported; QuestDB ARRAY ingress requires Float64 leaf",
                            field.name(),
                            other
                        ),
                    ));
                }
            }
        }
        (other, _, _) => {
            return Err(Error::new(
                ErrorCode::ArrowUnsupportedColumnKind,
                format!(
                    "Arrow type {:?} on column '{}' is not supported by Buffer::append_arrow",
                    other,
                    field.name()
                ),
            ));
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use arrow_array::builder::{
        BinaryBuilder, BooleanBuilder, Decimal64Builder, Decimal128Builder, FixedSizeBinaryBuilder,
        Float64Builder, Int8Builder, Int16Builder, Int32Builder, Int64Builder, ListBuilder,
        StringBuilder, StringDictionaryBuilder, TimestampMicrosecondBuilder,
        TimestampMillisecondBuilder, TimestampNanosecondBuilder, UInt16Builder, UInt32Builder,
    };
    use arrow_array::types::UInt32Type;
    use arrow_array::{ArrayRef, RecordBatch};
    use arrow_schema::{DataType, Field, Schema as ArrowSchema, TimeUnit};

    use crate::ingress::{Buffer, TableName};

    fn arrow_schema_with(field: Field) -> Arc<ArrowSchema> {
        Arc::new(ArrowSchema::new(vec![field]))
    }

    fn fresh_buffer() -> Buffer {
        Buffer::qwp_ws_with_max_name_len(127)
    }

    fn table(name: &str) -> TableName<'_> {
        TableName::new(name).unwrap()
    }

    #[test]
    fn bool_column_appends_rows_skipping_all_null() {
        let mut b = BooleanBuilder::new();
        b.append_value(true);
        b.append_null();
        b.append_value(false);
        let arr = b.finish();
        let schema = arrow_schema_with(Field::new("flag", DataType::Boolean, true));
        let rb = RecordBatch::try_new(schema, vec![Arc::new(arr) as ArrayRef]).unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb, DesignatedTimestamp::Now)
            .unwrap();
        assert_eq!(buf.row_count(), 2);
    }

    #[test]
    fn int_family_appends_through_widening_dispatch() {
        let i8a = Int8Builder::new();
        let i16a = Int16Builder::new();
        let i32a = Int32Builder::new();
        let i64a = Int64Builder::new();
        let u16a = UInt16Builder::new();
        let u32a = UInt32Builder::new();
        let mut all_builders = (i8a, i16a, i32a, i64a, u16a, u32a);
        all_builders.0.append_value(1);
        all_builders.0.append_value(-1);
        all_builders.1.append_value(2);
        all_builders.1.append_value(-2);
        all_builders.2.append_value(3);
        all_builders.2.append_value(-3);
        all_builders.3.append_value(4);
        all_builders.3.append_value(-4);
        all_builders.4.append_value(0x41);
        all_builders.4.append_value(0x42);
        all_builders.5.append_value(0x0100_007F);
        all_builders.5.append_value(0x0101_A8C0);
        let cols: Vec<ArrayRef> = vec![
            Arc::new(all_builders.0.finish()),
            Arc::new(all_builders.1.finish()),
            Arc::new(all_builders.2.finish()),
            Arc::new(all_builders.3.finish()),
            Arc::new(all_builders.4.finish()),
            Arc::new(all_builders.5.finish()),
        ];
        let fields = vec![
            Field::new("byte", DataType::Int8, true),
            Field::new("short", DataType::Int16, true),
            Field::new("int", DataType::Int32, true),
            Field::new("long", DataType::Int64, true),
            Field::new("char_u16", DataType::UInt16, true).with_metadata(
                [(
                    crate::egress::arrow::metadata::COLUMN_TYPE.into(),
                    "char".into(),
                )]
                .into_iter()
                .collect(),
            ),
            Field::new("ipv4", DataType::UInt32, true).with_metadata(
                [(
                    crate::egress::arrow::metadata::COLUMN_TYPE.into(),
                    "ipv4".into(),
                )]
                .into_iter()
                .collect(),
            ),
        ];
        let schema = Arc::new(ArrowSchema::new(fields));
        let rb = RecordBatch::try_new(schema, cols).unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb, DesignatedTimestamp::Now)
            .unwrap();
        assert_eq!(buf.row_count(), 2);
    }

    #[test]
    fn float_double_columns_append() {
        let mut f64b = Float64Builder::new();
        f64b.append_value(1.5);
        f64b.append_value(-2.5);
        let schema = arrow_schema_with(Field::new("d", DataType::Float64, true));
        let rb = RecordBatch::try_new(schema, vec![Arc::new(f64b.finish()) as ArrayRef]).unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb, DesignatedTimestamp::Now)
            .unwrap();
        assert_eq!(buf.row_count(), 2);
    }

    #[test]
    fn timestamp_columns_route_to_correct_setter() {
        let mut us = TimestampMicrosecondBuilder::new();
        us.append_value(1_700_000_000_000_000);
        let mut ns = TimestampNanosecondBuilder::new();
        ns.append_value(1_700_000_000_000_000_000);
        let mut ms = TimestampMillisecondBuilder::new();
        ms.append_value(1_700_000_000_000);
        let cols: Vec<ArrayRef> = vec![
            Arc::new(us.finish()),
            Arc::new(ns.finish()),
            Arc::new(ms.finish()),
        ];
        let schema = Arc::new(ArrowSchema::new(vec![
            Field::new(
                "ts_us",
                DataType::Timestamp(TimeUnit::Microsecond, None),
                true,
            ),
            Field::new(
                "ts_ns",
                DataType::Timestamp(TimeUnit::Nanosecond, None),
                true,
            ),
            Field::new(
                "ts_ms",
                DataType::Timestamp(TimeUnit::Millisecond, None),
                true,
            ),
        ]));
        let rb = RecordBatch::try_new(schema, cols).unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb, DesignatedTimestamp::ServerNow)
            .unwrap();
        assert_eq!(buf.row_count(), 1);
    }

    #[test]
    fn utf8_and_binary_append() {
        let mut s = StringBuilder::new();
        s.append_value("hello");
        s.append_value("");
        s.append_value("yo");
        let mut bin = BinaryBuilder::new();
        bin.append_value(&[1u8, 2, 3]);
        bin.append_value(&[]);
        bin.append_value(&[0xFFu8]);
        let cols: Vec<ArrayRef> = vec![Arc::new(s.finish()), Arc::new(bin.finish())];
        let schema = Arc::new(ArrowSchema::new(vec![
            Field::new("name", DataType::Utf8, true),
            Field::new("blob", DataType::Binary, true),
        ]));
        let rb = RecordBatch::try_new(schema, cols).unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb, DesignatedTimestamp::Now)
            .unwrap();
        assert_eq!(buf.row_count(), 3);
    }

    #[test]
    fn uuid_with_arrow_uuid_extension_routes_to_column_uuid() {
        let mut b = FixedSizeBinaryBuilder::new(16);
        let bytes = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        b.append_value(bytes).unwrap();
        let field = Field::new("id", DataType::FixedSizeBinary(16), true).with_metadata(
            [(
                crate::egress::arrow::metadata::ARROW_EXTENSION_NAME.into(),
                "arrow.uuid".into(),
            )]
            .into_iter()
            .collect(),
        );
        let schema = arrow_schema_with(field);
        let rb = RecordBatch::try_new(schema, vec![Arc::new(b.finish()) as ArrayRef]).unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb, DesignatedTimestamp::Now)
            .unwrap();
        assert_eq!(buf.row_count(), 1);
    }

    #[test]
    fn uuid_without_metadata_rejected() {
        let mut b = FixedSizeBinaryBuilder::new(16);
        b.append_value([0u8; 16]).unwrap();
        let schema = arrow_schema_with(Field::new("id", DataType::FixedSizeBinary(16), true));
        let rb = RecordBatch::try_new(schema, vec![Arc::new(b.finish()) as ArrayRef]).unwrap();
        let mut buf = fresh_buffer();
        let err = buf
            .append_arrow(table("t"), &rb, DesignatedTimestamp::Now)
            .unwrap_err();
        assert_eq!(
            err.code(),
            crate::error::ErrorCode::ArrowUnsupportedColumnKind
        );
    }

    #[test]
    fn long256_routes_to_column_long256() {
        let mut b = FixedSizeBinaryBuilder::new(32);
        b.append_value([0u8; 32]).unwrap();
        let schema = arrow_schema_with(Field::new("l", DataType::FixedSizeBinary(32), true));
        let rb = RecordBatch::try_new(schema, vec![Arc::new(b.finish()) as ArrayRef]).unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb, DesignatedTimestamp::Now)
            .unwrap();
        assert_eq!(buf.row_count(), 1);
    }

    #[test]
    fn symbol_dictionary_routes_to_symbol_setter() {
        let mut b = StringDictionaryBuilder::<UInt32Type>::new();
        b.append("AAPL").unwrap();
        b.append("MSFT").unwrap();
        b.append("AAPL").unwrap();
        let arr = b.finish();
        let field = Field::new(
            "sym",
            DataType::Dictionary(Box::new(DataType::UInt32), Box::new(DataType::Utf8)),
            true,
        )
        .with_metadata(
            [(crate::egress::arrow::metadata::SYMBOL.into(), "true".into())]
                .into_iter()
                .collect(),
        );
        let schema = arrow_schema_with(field);
        let rb = RecordBatch::try_new(schema, vec![Arc::new(arr) as ArrayRef]).unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb, DesignatedTimestamp::Now)
            .unwrap();
        assert_eq!(buf.row_count(), 3);
    }

    #[test]
    fn dictionary_without_symbol_metadata_falls_back_to_varchar() {
        let mut b = StringDictionaryBuilder::<UInt32Type>::new();
        b.append("x").unwrap();
        b.append("y").unwrap();
        let arr = b.finish();
        let field = Field::new(
            "v",
            DataType::Dictionary(Box::new(DataType::UInt32), Box::new(DataType::Utf8)),
            true,
        );
        let schema = arrow_schema_with(field);
        let rb = RecordBatch::try_new(schema, vec![Arc::new(arr) as ArrayRef]).unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb, DesignatedTimestamp::Now)
            .unwrap();
        assert_eq!(buf.row_count(), 2);
    }

    #[test]
    fn geohash_routes_via_metadata() {
        let mut b = Int32Builder::new();
        b.append_value(0x0001_FFFF);
        let field = Field::new("g", DataType::Int32, true).with_metadata(
            [(
                crate::egress::arrow::metadata::GEOHASH_BITS.into(),
                "20".into(),
            )]
            .into_iter()
            .collect(),
        );
        let schema = arrow_schema_with(field);
        let rb = RecordBatch::try_new(schema, vec![Arc::new(b.finish()) as ArrayRef]).unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb, DesignatedTimestamp::Now)
            .unwrap();
        assert_eq!(buf.row_count(), 1);
    }

    #[test]
    fn decimal64_appends_via_be_mantissa() {
        let mut b = Decimal64Builder::new();
        b.append_value(12345);
        let arr = b.finish().with_precision_and_scale(18, 2).unwrap();
        let schema = arrow_schema_with(Field::new("d", DataType::Decimal64(18, 2), true));
        let rb = RecordBatch::try_new(schema, vec![Arc::new(arr) as ArrayRef]).unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb, DesignatedTimestamp::Now)
            .unwrap();
        assert_eq!(buf.row_count(), 1);
    }

    #[test]
    fn decimal128_appends_via_be_mantissa() {
        let mut b = Decimal128Builder::new();
        b.append_value(67890_i128);
        let arr = b.finish().with_precision_and_scale(38, 3).unwrap();
        let schema = arrow_schema_with(Field::new("d", DataType::Decimal128(38, 3), true));
        let rb = RecordBatch::try_new(schema, vec![Arc::new(arr) as ArrayRef]).unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb, DesignatedTimestamp::Now)
            .unwrap();
        assert_eq!(buf.row_count(), 1);
    }

    #[test]
    fn designated_timestamp_column_picks_per_row_value() {
        let mut ts = TimestampMicrosecondBuilder::new();
        ts.append_value(1_700_000_000_000_000);
        ts.append_value(1_700_000_000_000_001);
        let ts_arr = ts.finish().with_timezone("UTC");
        let mut v = Int64Builder::new();
        v.append_value(10);
        v.append_value(20);
        let schema = Arc::new(ArrowSchema::new(vec![
            Field::new(
                "ts",
                DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
                false,
            ),
            Field::new("v", DataType::Int64, false),
        ]));
        let rb = RecordBatch::try_new(
            schema,
            vec![
                Arc::new(ts_arr) as ArrayRef,
                Arc::new(v.finish()) as ArrayRef,
            ],
        )
        .unwrap();
        let mut buf = fresh_buffer();
        let ts_col = ColumnName::new("ts").unwrap();
        buf.append_arrow(table("t"), &rb, DesignatedTimestamp::Column(ts_col))
            .unwrap();
        assert_eq!(buf.row_count(), 2);
    }

    #[test]
    fn ts_column_not_found_returns_arrow_ingest_error() {
        let mut v = Int64Builder::new();
        v.append_value(10);
        let schema = arrow_schema_with(Field::new("v", DataType::Int64, false));
        let rb = RecordBatch::try_new(schema, vec![Arc::new(v.finish()) as ArrayRef]).unwrap();
        let mut buf = fresh_buffer();
        let missing = ColumnName::new("missing_ts").unwrap();
        let err = buf
            .append_arrow(table("t"), &rb, DesignatedTimestamp::Column(missing))
            .unwrap_err();
        assert_eq!(err.code(), crate::error::ErrorCode::ArrowIngest);
    }

    #[test]
    fn ts_column_wrong_dtype_returns_arrow_ingest_error() {
        let mut v = Int64Builder::new();
        v.append_value(10);
        let schema = arrow_schema_with(Field::new("v", DataType::Int64, false));
        let rb = RecordBatch::try_new(schema, vec![Arc::new(v.finish()) as ArrayRef]).unwrap();
        let mut buf = fresh_buffer();
        let v_col = ColumnName::new("v").unwrap();
        let err = buf
            .append_arrow(table("t"), &rb, DesignatedTimestamp::Column(v_col))
            .unwrap_err();
        assert_eq!(err.code(), crate::error::ErrorCode::ArrowIngest);
    }

    #[test]
    fn nested_double_list_routes_to_column_arr() {
        let mut single = ListBuilder::new(Float64Builder::new());
        single.values().append_value(1.0);
        single.values().append_value(2.0);
        single.values().append_value(3.0);
        single.append(true);
        let arr = single.finish();
        let field = Field::new(
            "a",
            DataType::List(Arc::new(Field::new("item", DataType::Float64, true))),
            true,
        );
        let schema = arrow_schema_with(field);
        let rb = RecordBatch::try_new(schema, vec![Arc::new(arr) as ArrayRef]).unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb, DesignatedTimestamp::Now)
            .unwrap();
        assert_eq!(buf.row_count(), 1);
    }

    #[test]
    fn nested_int_list_rejected_as_unsupported() {
        let mut single = ListBuilder::new(Int64Builder::new());
        single.values().append_value(1);
        single.append(true);
        let arr = single.finish();
        let field = Field::new(
            "a",
            DataType::List(Arc::new(Field::new("item", DataType::Int64, true))),
            true,
        );
        let schema = arrow_schema_with(field);
        let rb = RecordBatch::try_new(schema, vec![Arc::new(arr) as ArrayRef]).unwrap();
        let mut buf = fresh_buffer();
        let err = buf
            .append_arrow(table("t"), &rb, DesignatedTimestamp::Now)
            .unwrap_err();
        assert_eq!(
            err.code(),
            crate::error::ErrorCode::ArrowUnsupportedColumnKind
        );
    }

    #[test]
    fn empty_batch_is_noop() {
        let mut v = Int64Builder::new();
        let schema = arrow_schema_with(Field::new("v", DataType::Int64, false));
        let rb = RecordBatch::try_new(schema, vec![Arc::new(v.finish()) as ArrayRef]).unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb, DesignatedTimestamp::Now)
            .unwrap();
        assert_eq!(buf.row_count(), 0);
    }

    #[test]
    fn ilp_buffer_rejects_append_arrow() {
        let mut v = Int64Builder::new();
        v.append_value(1);
        let schema = arrow_schema_with(Field::new("v", DataType::Int64, false));
        let rb = RecordBatch::try_new(schema, vec![Arc::new(v.finish()) as ArrayRef]).unwrap();
        let mut buf = Buffer::new(crate::ingress::ProtocolVersion::V2);
        let err = buf
            .append_arrow(table("t"), &rb, DesignatedTimestamp::Now)
            .unwrap_err();
        assert_eq!(err.code(), crate::error::ErrorCode::InvalidApiCall);
    }

    #[test]
    fn i32_arrow_uses_min_sentinel_for_null_rows() {
        let mut b = Int32Builder::new();
        b.append_value(7);
        b.append_null();
        b.append_value(-3);
        let schema = arrow_schema_with(Field::new("n", DataType::Int32, true));
        let rb = RecordBatch::try_new(schema, vec![Arc::new(b.finish()) as ArrayRef]).unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb, DesignatedTimestamp::Now)
            .unwrap();
        assert_eq!(buf.row_count(), 2);
    }

    #[test]
    fn f64_arrow_uses_nan_sentinel_for_null_rows() {
        let mut b = Float64Builder::new();
        b.append_value(1.0);
        b.append_null();
        b.append_value(2.0);
        let schema = arrow_schema_with(Field::new("f", DataType::Float64, true));
        let rb = RecordBatch::try_new(schema, vec![Arc::new(b.finish()) as ArrayRef]).unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb, DesignatedTimestamp::Now)
            .unwrap();
        assert_eq!(buf.row_count(), 2);
    }

    #[test]
    fn timestamp_arrow_filters_nulls_via_bitmap() {
        let mut b = TimestampMicrosecondBuilder::new();
        b.append_value(1_700_000_000_000_000);
        b.append_null();
        b.append_value(1_700_000_000_000_100);
        let field = Field::new("ts", DataType::Timestamp(TimeUnit::Microsecond, None), true);
        let schema = arrow_schema_with(field);
        let rb = RecordBatch::try_new(schema, vec![Arc::new(b.finish()) as ArrayRef]).unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb, DesignatedTimestamp::Now)
            .unwrap();
        assert_eq!(buf.row_count(), 2);
    }

    #[test]
    fn varchar_arrow_skips_null_rows() {
        let mut b = StringBuilder::new();
        b.append_value("hello");
        b.append_null();
        b.append_value("world");
        let schema = arrow_schema_with(Field::new("v", DataType::Utf8, true));
        let rb = RecordBatch::try_new(schema, vec![Arc::new(b.finish()) as ArrayRef]).unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb, DesignatedTimestamp::Now)
            .unwrap();
        assert_eq!(buf.row_count(), 2);
    }

    #[test]
    fn symbol_arrow_builds_dict_and_dedups_keys() {
        let mut b = StringDictionaryBuilder::<UInt32Type>::new();
        b.append_value("us-east");
        b.append_value("us-west");
        b.append_value("us-east");
        b.append_null();
        b.append_value("us-west");
        let arr = b.finish();
        let field = Field::new(
            "region",
            DataType::Dictionary(Box::new(DataType::UInt32), Box::new(DataType::Utf8)),
            true,
        )
        .with_metadata(
            [(crate::egress::arrow::metadata::SYMBOL.into(), "true".into())]
                .into_iter()
                .collect(),
        );
        let schema = arrow_schema_with(field);
        let rb = RecordBatch::try_new(schema, vec![Arc::new(arr) as ArrayRef]).unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb, DesignatedTimestamp::Now)
            .unwrap();
        assert_eq!(buf.row_count(), 4);
    }

    #[test]
    fn decimal128_arrow_propagates_scale() {
        let mut b = Decimal128Builder::new().with_data_type(DataType::Decimal128(10, 2));
        b.append_value(12345);
        b.append_null();
        b.append_value(-67890);
        let schema = arrow_schema_with(Field::new("amt", DataType::Decimal128(10, 2), true));
        let rb = RecordBatch::try_new(schema, vec![Arc::new(b.finish()) as ArrayRef]).unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb, DesignatedTimestamp::Now)
            .unwrap();
        assert_eq!(buf.row_count(), 2);
    }

    #[test]
    fn geohash_arrow_emits_only_non_null_rows() {
        let mut b = Int32Builder::new();
        b.append_value(0x1234_5678);
        b.append_null();
        b.append_value(0x0DEA_DBEE);
        let field = Field::new("g", DataType::Int32, true).with_metadata(
            [(
                crate::egress::arrow::metadata::GEOHASH_BITS.into(),
                "32".into(),
            )]
            .into_iter()
            .collect(),
        );
        let schema = arrow_schema_with(field);
        let rb = RecordBatch::try_new(schema, vec![Arc::new(b.finish()) as ArrayRef]).unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb, DesignatedTimestamp::Now)
            .unwrap();
        assert_eq!(buf.row_count(), 2);
    }

    #[test]
    fn array_double_2d_arrow_encodes_per_row_blobs() {
        let mut outer = ListBuilder::new(ListBuilder::new(Float64Builder::new()));
        {
            let mid = outer.values();
            let leaf = mid.values();
            leaf.append_value(1.0);
            leaf.append_value(2.0);
            mid.append(true);
            let leaf = mid.values();
            leaf.append_value(3.0);
            leaf.append_value(4.0);
            mid.append(true);
        }
        outer.append(true);
        {
            let mid = outer.values();
            let leaf = mid.values();
            leaf.append_value(5.0);
            mid.append(true);
        }
        outer.append(true);
        let arr = outer.finish();
        let inner_field = Arc::new(Field::new(
            "item",
            DataType::List(Arc::new(Field::new("item", DataType::Float64, true))),
            true,
        ));
        let field = Field::new("a", DataType::List(inner_field), true);
        let schema = arrow_schema_with(field);
        let rb = RecordBatch::try_new(schema, vec![Arc::new(arr) as ArrayRef]).unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb, DesignatedTimestamp::Now)
            .unwrap();
        assert_eq!(buf.row_count(), 2);
    }

    #[test]
    fn multi_batch_append_accumulates_rows() {
        let schema = arrow_schema_with(Field::new("v", DataType::Int64, false));
        let mut buf = fresh_buffer();
        for value in [10i64, 20, 30] {
            let mut b = Int64Builder::new();
            b.append_value(value);
            let rb = RecordBatch::try_new(schema.clone(), vec![Arc::new(b.finish()) as ArrayRef])
                .unwrap();
            buf.append_arrow(table("t"), &rb, DesignatedTimestamp::Now)
                .unwrap();
        }
        assert_eq!(buf.row_count(), 3);
    }

    #[test]
    fn mixed_row_by_row_after_arrow_errors() {
        let mut b = Int64Builder::new();
        b.append_value(1);
        let schema = arrow_schema_with(Field::new("v", DataType::Int64, false));
        let rb = RecordBatch::try_new(schema, vec![Arc::new(b.finish()) as ArrayRef]).unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb, DesignatedTimestamp::Now)
            .unwrap();
        let err = buf
            .table(table("t"))
            .and_then(|b| b.column_i64("v", 99))
            .err();
        assert!(err.is_some());
    }

    #[test]
    fn designated_ts_with_null_rejects() {
        let mut v = Int64Builder::new();
        v.append_value(1);
        v.append_value(2);
        let mut ts = TimestampMicrosecondBuilder::new();
        ts.append_value(1_000);
        ts.append_null();
        let cols: Vec<ArrayRef> = vec![Arc::new(v.finish()), Arc::new(ts.finish())];
        let schema = Arc::new(ArrowSchema::new(vec![
            Field::new("v", DataType::Int64, true),
            Field::new("ts", DataType::Timestamp(TimeUnit::Microsecond, None), true),
        ]));
        let rb = RecordBatch::try_new(schema, cols).unwrap();
        let mut buf = fresh_buffer();
        let ts_name = ColumnName::new("ts").unwrap();
        let err = buf
            .append_arrow(table("t"), &rb, DesignatedTimestamp::Column(ts_name))
            .unwrap_err();
        assert_eq!(err.code(), crate::error::ErrorCode::ArrowIngest);
    }

    #[test]
    fn multi_column_all_null_row_is_skipped() {
        let mut a = Int64Builder::new();
        a.append_value(1);
        a.append_null();
        a.append_value(3);
        let mut b = StringBuilder::new();
        b.append_value("x");
        b.append_null();
        b.append_value("z");
        let cols: Vec<ArrayRef> = vec![Arc::new(a.finish()), Arc::new(b.finish())];
        let schema = Arc::new(ArrowSchema::new(vec![
            Field::new("a", DataType::Int64, true),
            Field::new("b", DataType::Utf8, true),
        ]));
        let rb = RecordBatch::try_new(schema, cols).unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb, DesignatedTimestamp::Now)
            .unwrap();
        assert_eq!(buf.row_count(), 2);
    }

    #[test]
    fn multi_column_partial_null_row_is_kept() {
        let mut a = Int64Builder::new();
        a.append_value(1);
        a.append_null();
        a.append_value(3);
        let mut b = StringBuilder::new();
        b.append_value("x");
        b.append_value("y");
        b.append_value("z");
        let cols: Vec<ArrayRef> = vec![Arc::new(a.finish()), Arc::new(b.finish())];
        let schema = Arc::new(ArrowSchema::new(vec![
            Field::new("a", DataType::Int64, true),
            Field::new("b", DataType::Utf8, true),
        ]));
        let rb = RecordBatch::try_new(schema, cols).unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb, DesignatedTimestamp::Now)
            .unwrap();
        assert_eq!(buf.row_count(), 3);
    }
}
