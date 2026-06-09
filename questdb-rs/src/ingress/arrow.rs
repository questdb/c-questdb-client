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

use arrow_array::types::{UInt8Type, UInt16Type, UInt32Type};
use arrow_array::{
    Array, ArrayRef, BinaryArray, BinaryViewArray, BooleanArray, Date32Array, Date64Array,
    Decimal32Array, Decimal64Array, Decimal128Array, Decimal256Array, DictionaryArray,
    DurationMicrosecondArray, DurationMillisecondArray, DurationNanosecondArray,
    DurationSecondArray, FixedSizeBinaryArray, FixedSizeListArray, Float16Array, Float32Array,
    Float64Array, Int8Array, Int16Array, Int32Array, Int64Array, LargeBinaryArray, LargeListArray,
    LargeStringArray, ListArray, RecordBatch, StringArray, StringViewArray, Time32MillisecondArray,
    Time32SecondArray, Time64MicrosecondArray, Time64NanosecondArray, TimestampMicrosecondArray,
    TimestampMillisecondArray, TimestampNanosecondArray, TimestampSecondArray, UInt8Array,
    UInt16Array, UInt32Array, UInt64Array,
};
use arrow_schema::{DataType, TimeUnit};

use crate::error::{Error, ErrorCode};
use crate::ingress::buffer::{
    ArrowBatchInfo, ArrowBulkCtx, ArrowDecimalSpec, QWP_DECIMAL_MAX_SCALE, QwpColumnKind,
    QwpWsColumnarBuffer,
};
use crate::ingress::{Buffer, ColumnName, TableName};
use crate::{Result, fmt};

impl Buffer {
    /// Append every row of `batch` to this buffer. Per-row designated
    /// timestamp is omitted from the wire payload; the server stamps
    /// each row on arrival (matches [`Buffer::at_now`](Buffer::at_now)
    /// per-row semantics).
    ///
    /// Requires a QWP/WS buffer. On error, the buffer is rolled back
    /// atomically to its pre-call state — no partial batch is committed.
    ///
    /// Use [`Buffer::append_arrow_at_column`] to source the timestamp
    /// from a batch column.
    ///
    /// # Null encoding (data loss)
    ///
    /// QuestDB's `BOOLEAN`, `BYTE` and `SHORT` wire kinds have no null
    /// representation. Nulls in an Arrow `Boolean` / `Int8` / `Int16`
    /// column are silently coerced to the zero value (`false`, `0`,
    /// `0`) when appended. Use the wider integer types if null
    /// fidelity matters (Arrow `Int32`/`Int64` carry sentinels;
    /// Arrow `UInt8` widens to QuestDB `INT` and preserves nulls via
    /// the `i32::MIN` sentinel).
    ///
    /// # Schema rigidity across batches
    ///
    /// Multiple `append_arrow` calls against the same table-in-buffer
    /// must supply the same set of columns. A batch that omits a
    /// previously-seen column is rejected with [`ErrorCode::InvalidApiCall`]
    /// at commit time. Project / re-order client-side if the producer
    /// sends a different shape per batch.
    ///
    /// # Errors
    ///
    /// * [`ErrorCode::ArrowUnsupportedColumnKind`] — column's Arrow
    ///   type has no QWP wire mapping.
    /// * [`ErrorCode::ArrowIngest`] — structural validation failed.
    /// * [`ErrorCode::InvalidApiCall`] — non-QWP/WS buffer, row-by-row
    ///   row already in progress on the same table, or a previously-
    ///   seen column was omitted from the batch.
    pub fn append_arrow(&mut self, table: TableName<'_>, batch: &RecordBatch) -> Result<()> {
        self.append_arrow_inner(table, batch, None)
    }

    /// Append every row of `batch`, sourcing the per-row designated
    /// timestamp from `ts_column`. The column must be a
    /// `Timestamp(Microsecond | Nanosecond | Millisecond, _)` with no
    /// null rows; `Millisecond` is widened to µs on the wire.
    ///
    /// # Errors
    ///
    /// In addition to the errors from [`Buffer::append_arrow`]:
    ///
    /// * [`ErrorCode::ArrowIngest`] — `ts_column` is missing, not a
    ///   `Timestamp(_)` Arrow type, or has null rows.
    pub fn append_arrow_at_column(
        &mut self,
        table: TableName<'_>,
        batch: &RecordBatch,
        ts_column: ColumnName<'_>,
    ) -> Result<()> {
        self.append_arrow_inner(table, batch, Some(ts_column))
    }

    fn append_arrow_inner(
        &mut self,
        table: TableName<'_>,
        batch: &RecordBatch,
        ts_column: Option<ColumnName<'_>>,
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
        if row_count > MAX_ARROW_INGEST_ROWS {
            return Err(fmt!(
                ArrowIngest,
                "row count {} exceeds maximum {} for a single append_arrow call",
                row_count,
                MAX_ARROW_INGEST_ROWS
            ));
        }
        check_batch_data_bounds(batch)?;
        let ts_col_idx = match ts_column {
            Some(name) => Some(resolve_ts_column(batch, name)?),
            None => None,
        };
        let user_col_count = col_count - if ts_col_idx.is_some() { 1 } else { 0 };
        if user_col_count == 0 {
            return Err(fmt!(
                ArrowIngest,
                "RecordBatch must have at least one non-timestamp column when row_count > 0"
            ));
        }
        let effective_rows = u32::try_from(row_count)
            .map_err(|_| fmt!(ArrowIngest, "row count {} exceeds u32::MAX", row_count))?;
        let qwp_ws = self.as_qwp_ws_mut().ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidApiCall,
                "Buffer::append_arrow requires a QWP/WebSocket buffer (Buffer::new_qwp_ws)"
                    .to_string(),
            )
        })?;
        let ctx = qwp_ws.arrow_bulk_begin(table)?;
        let mut guard = BulkGuard {
            qwp_ws,
            ctx: Some(ctx),
        };
        let inner_result = emit_arrow_batch(
            guard.qwp_ws,
            guard.ctx.as_ref().expect("ctx is Some until committed"),
            batch,
            &schema,
            ts_col_idx,
        );
        match inner_result {
            Ok(()) => {
                let ctx = guard.ctx.as_ref().expect("ctx is Some until committed");
                match guard.qwp_ws.arrow_bulk_commit(ctx, effective_rows) {
                    Ok(()) => {
                        let ctx = guard.ctx.take().expect("ctx is Some until committed");
                        guard.qwp_ws.arrow_bulk_finish(ctx);
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e),
        }
    }
}

struct BulkGuard<'a> {
    qwp_ws: &'a mut QwpWsColumnarBuffer,
    ctx: Option<ArrowBulkCtx>,
}

impl Drop for BulkGuard<'_> {
    fn drop(&mut self) {
        if let Some(ctx) = self.ctx.take() {
            self.qwp_ws.arrow_bulk_rollback(ctx);
        }
    }
}

#[inline]
fn emit_arrow_batch(
    qwp_ws: &mut QwpWsColumnarBuffer,
    ctx: &ArrowBulkCtx,
    batch: &RecordBatch,
    schema: &arrow_schema::SchemaRef,
    ts_col_idx: Option<usize>,
) -> Result<()> {
    for (idx, field) in schema.fields().iter().enumerate() {
        if Some(idx) == ts_col_idx {
            continue;
        }
        let col_name =
            ColumnName::new(field.name()).map_err(|e| decorate_column(e, field.name()))?;
        let kind = classify(field.as_ref(), batch.column(idx).as_ref())
            .map_err(|e| decorate_column(e, field.name()))?;
        emit_arrow_column(qwp_ws, ctx, col_name, kind, batch.column(idx).as_ref())
            .map_err(|e| decorate_column(e, field.name()))?;
    }
    if let Some(idx) = ts_col_idx {
        let arr = batch.column(idx);
        let field_name = schema.field(idx).name();
        emit_arrow_designated_ts(qwp_ws, ctx, schema.field(idx).data_type(), arr.as_ref())
            .map_err(|e| decorate_column(e, field_name))?;
    }
    Ok(())
}

// `starts_with` (not `contains`) so a user column name containing the
// substring cannot bypass the double-wrap guard.
const COLUMN_ERR_PREFIX: &str = "[column='";

fn decorate_column(err: Error, column_name: &str) -> Error {
    if err.msg().starts_with(COLUMN_ERR_PREFIX) {
        return err;
    }
    Error::new(
        err.code(),
        format!("{}{}'] {}", COLUMN_ERR_PREFIX, column_name, err.msg()),
    )
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
) -> Result<()> {
    if arr.null_count() > 0 {
        return Err(fmt!(
            ArrowIngest,
            "designated timestamp column must have no null rows"
        ));
    }
    let rows = arr.len() as u32;
    let info = ArrowBatchInfo {
        bitmap: None,
        rows,
        non_null: rows,
    };
    let le = cfg!(target_endian = "little");
    match dtype {
        DataType::Timestamp(TimeUnit::Microsecond, _) => {
            let a = arr
                .as_any()
                .downcast_ref::<TimestampMicrosecondArray>()
                .unwrap();
            qwp_ws.arrow_bulk_set_designated_ts(ctx, QwpColumnKind::TimestampMicros, info, |out| {
                if le {
                    // SAFETY: i64 has no padding; LE target → wire-format bytes.
                    extend_le_bytes_checked(out, unsafe { typed_slice_as_le_bytes(a.values()) })?;
                } else {
                    non_null_le_into(out, arr, |row| a.value(row).to_le_bytes())?;
                }
                Ok(())
            })
        }
        DataType::Timestamp(TimeUnit::Nanosecond, _) => {
            let a = arr
                .as_any()
                .downcast_ref::<TimestampNanosecondArray>()
                .unwrap();
            qwp_ws.arrow_bulk_set_designated_ts(ctx, QwpColumnKind::TimestampNanos, info, |out| {
                if le {
                    extend_le_bytes_checked(out, unsafe { typed_slice_as_le_bytes(a.values()) })?;
                } else {
                    non_null_le_into(out, arr, |row| a.value(row).to_le_bytes())?;
                }
                Ok(())
            })
        }
        DataType::Timestamp(TimeUnit::Millisecond, _) => {
            // QWP designated TS supports µs/ns only; widen ms → µs.
            let a = arr
                .as_any()
                .downcast_ref::<TimestampMillisecondArray>()
                .unwrap();
            qwp_ws.arrow_bulk_set_designated_ts(ctx, QwpColumnKind::TimestampMicros, info, |out| {
                try_non_null_le_into(out, arr, |row| {
                    let v = a.value(row);
                    v.checked_mul(1_000).map(i64::to_le_bytes).ok_or_else(|| {
                        fmt!(
                            ArrowIngest,
                            "designated timestamp ms→µs overflow at row {} (value {})",
                            row,
                            v
                        )
                    })
                })
            })
        }
        other => Err(fmt!(
            ArrowIngest,
            "designated timestamp column has unsupported Arrow type {:?}",
            other
        )),
    }
}

fn try_reserve_bytes(out: &mut Vec<u8>, additional: usize, label: &str) -> Result<()> {
    out.try_reserve(additional).map_err(|_| {
        fmt!(
            ArrowIngest,
            "{}: allocator could not reserve {} bytes",
            label,
            additional
        )
    })
}

fn try_reserve_typed<T>(v: &mut Vec<T>, additional: usize, label: &str) -> Result<()> {
    v.try_reserve(additional).map_err(|_| {
        fmt!(
            ArrowIngest,
            "{}: allocator could not reserve {} elements",
            label,
            additional
        )
    })
}

/// LE primitive fast-path: `try_reserve` then `extend_from_slice` of a
/// host-LE-equal slice. Funnels every LE no-null path through one
/// allocator-aware helper so OOM surfaces as `ArrowIngest` rather than
/// aborting under `panic = "abort"`.
///
/// SAFETY: `bytes` must be a host-LE re-interpretation of `T`'s value
/// representation. Caller is responsible for that invariant — every
/// in-tree caller pipes `typed_slice_as_le_bytes` which encodes it
/// statically.
fn extend_le_bytes_checked(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    try_reserve_bytes(out, bytes.len(), "primitive LE fast-path")?;
    out.extend_from_slice(bytes);
    Ok(())
}

fn full_with_sentinel_into<const N: usize>(
    out: &mut Vec<u8>,
    arr: &dyn Array,
    sentinel: [u8; N],
    mut get_bytes: impl FnMut(usize) -> [u8; N],
) -> Result<()> {
    let row_count = arr.len();
    let bytes = row_count.checked_mul(N).ok_or_else(|| {
        fmt!(
            ArrowIngest,
            "full_with_sentinel: row_count {} * elem {} overflows usize",
            row_count,
            N
        )
    })?;
    try_reserve_bytes(out, bytes, "primitive column")?;
    for row in 0..row_count {
        if arr.is_null(row) {
            out.extend_from_slice(&sentinel);
        } else {
            out.extend_from_slice(&get_bytes(row));
        }
    }
    Ok(())
}

fn try_full_with_sentinel_into<const N: usize>(
    out: &mut Vec<u8>,
    arr: &dyn Array,
    sentinel: [u8; N],
    mut get_bytes: impl FnMut(usize) -> Result<[u8; N]>,
) -> Result<()> {
    let row_count = arr.len();
    let bytes = row_count.checked_mul(N).ok_or_else(|| {
        fmt!(
            ArrowIngest,
            "try_full_with_sentinel: row_count {} * elem {} overflows usize",
            row_count,
            N
        )
    })?;
    try_reserve_bytes(out, bytes, "primitive column")?;
    for row in 0..row_count {
        if arr.is_null(row) {
            out.extend_from_slice(&sentinel);
        } else {
            let bytes = get_bytes(row)?;
            out.extend_from_slice(&bytes);
        }
    }
    Ok(())
}

// Returns `len - null_count`, surfacing the inconsistency from
// `arrow::ffi::from_ffi` (which uses `new_unchecked` and does not enforce
// `null_count ≤ len`) as a structured error rather than letting the
// subtraction wrap to near-usize::MAX and trigger an allocator abort.
fn non_null_count(arr: &dyn Array, label: &str) -> Result<usize> {
    let row_count = arr.len();
    let null_count = arr.null_count();
    if null_count > row_count {
        return Err(fmt!(
            ArrowIngest,
            "{}: null_count {} exceeds len {}; inconsistent Arrow buffer",
            label,
            null_count,
            row_count
        ));
    }
    Ok(row_count - null_count)
}

fn non_null_le_into<const N: usize>(
    out: &mut Vec<u8>,
    arr: &dyn Array,
    mut get_bytes: impl FnMut(usize) -> [u8; N],
) -> Result<()> {
    let non_null = non_null_count(arr, "primitive column")?;
    let row_count = arr.len();
    let bytes = non_null.checked_mul(N).ok_or_else(|| {
        fmt!(
            ArrowIngest,
            "primitive column: non_null {} * elem {} overflows usize",
            non_null,
            N
        )
    })?;
    try_reserve_bytes(out, bytes, "primitive column")?;
    for row in 0..row_count {
        if arr.is_null(row) {
            continue;
        }
        out.extend_from_slice(&get_bytes(row));
    }
    Ok(())
}

fn try_non_null_le_into<const N: usize>(
    out: &mut Vec<u8>,
    arr: &dyn Array,
    mut get_bytes: impl FnMut(usize) -> Result<[u8; N]>,
) -> Result<()> {
    let non_null = non_null_count(arr, "primitive column")?;
    let row_count = arr.len();
    let bytes = non_null.checked_mul(N).ok_or_else(|| {
        fmt!(
            ArrowIngest,
            "primitive column: non_null {} * elem {} overflows usize",
            non_null,
            N
        )
    })?;
    try_reserve_bytes(out, bytes, "primitive column")?;
    for row in 0..row_count {
        if arr.is_null(row) {
            continue;
        }
        let bytes = get_bytes(row)?;
        out.extend_from_slice(&bytes);
    }
    Ok(())
}

fn non_null_fsb_into(out: &mut Vec<u8>, arr: &FixedSizeBinaryArray, size: usize) -> Result<()> {
    let non_null = non_null_count(arr, "FixedSizeBinary column")?;
    let row_count = arr.len();
    let bytes = non_null.checked_mul(size).ok_or_else(|| {
        fmt!(
            ArrowIngest,
            "FixedSizeBinary column: non_null {} * elem {} overflows usize",
            non_null,
            size
        )
    })?;
    try_reserve_bytes(out, bytes, "FixedSizeBinary column")?;
    for row in 0..row_count {
        if arr.is_null(row) {
            continue;
        }
        out.extend_from_slice(arr.value(row));
    }
    Ok(())
}

#[inline]
unsafe fn typed_slice_as_le_bytes<T: Copy>(slice: &[T]) -> &[u8] {
    unsafe { std::slice::from_raw_parts(slice.as_ptr() as *const u8, std::mem::size_of_val(slice)) }
}

fn emit_arrow_column(
    qwp_ws: &mut QwpWsColumnarBuffer,
    ctx: &ArrowBulkCtx,
    col_name: ColumnName<'_>,
    kind: ColumnKind,
    arr: &dyn Array,
) -> Result<()> {
    let non_null_usize = non_null_count(arr, "column")?;
    let rows = u32::try_from(arr.len())
        .map_err(|_| fmt!(ArrowIngest, "row count {} exceeds u32::MAX", arr.len()))?;
    let non_null = u32::try_from(non_null_usize).map_err(|_| {
        fmt!(
            ArrowIngest,
            "non-null count {} exceeds u32::MAX",
            non_null_usize
        )
    })?;
    let null_count = arr.len() - non_null_usize;
    let validity = if null_count > 0 { arr.nulls() } else { None };
    let info_full = ArrowBatchInfo {
        bitmap: None,
        rows,
        non_null,
    };
    let info_sparse = ArrowBatchInfo {
        bitmap: validity,
        rows,
        non_null,
    };
    let le_no_nulls = cfg!(target_endian = "little") && null_count == 0;
    match kind {
        ColumnKind::Bool => {
            let a = arr.as_any().downcast_ref::<BooleanArray>().unwrap();
            qwp_ws.arrow_bulk_set_bool(ctx, col_name, info_full, |packed, existing_rows| {
                pack_bool_bits_into(packed, existing_rows, a)
            })
        }
        ColumnKind::I8 => {
            let a = arr.as_any().downcast_ref::<Int8Array>().unwrap();
            qwp_ws.arrow_bulk_set_fixed(ctx, col_name, QwpColumnKind::I8, info_full, |out| {
                if le_no_nulls {
                    extend_le_bytes_checked(out, unsafe { typed_slice_as_le_bytes(a.values()) })?;
                } else {
                    full_with_sentinel_into(out, arr, [0u8; 1], |row| [a.value(row) as u8])?;
                }
                Ok(())
            })
        }
        ColumnKind::I16 => {
            let a = arr.as_any().downcast_ref::<Int16Array>().unwrap();
            qwp_ws.arrow_bulk_set_fixed(ctx, col_name, QwpColumnKind::I16, info_full, |out| {
                if le_no_nulls {
                    extend_le_bytes_checked(out, unsafe { typed_slice_as_le_bytes(a.values()) })?;
                } else {
                    full_with_sentinel_into(out, arr, 0i16.to_le_bytes(), |row| {
                        a.value(row).to_le_bytes()
                    })?;
                }
                Ok(())
            })
        }
        ColumnKind::I32 => {
            let a = arr.as_any().downcast_ref::<Int32Array>().unwrap();
            qwp_ws.arrow_bulk_set_fixed(ctx, col_name, QwpColumnKind::I32, info_full, |out| {
                if le_no_nulls {
                    extend_le_bytes_checked(out, unsafe { typed_slice_as_le_bytes(a.values()) })?;
                } else {
                    full_with_sentinel_into(out, arr, i32::MIN.to_le_bytes(), |row| {
                        a.value(row).to_le_bytes()
                    })?;
                }
                Ok(())
            })
        }
        ColumnKind::I64 => {
            let a = arr.as_any().downcast_ref::<Int64Array>().unwrap();
            qwp_ws.arrow_bulk_set_fixed(ctx, col_name, QwpColumnKind::I64, info_full, |out| {
                if le_no_nulls {
                    extend_le_bytes_checked(out, unsafe { typed_slice_as_le_bytes(a.values()) })?;
                } else {
                    full_with_sentinel_into(out, arr, i64::MIN.to_le_bytes(), |row| {
                        a.value(row).to_le_bytes()
                    })?;
                }
                Ok(())
            })
        }
        ColumnKind::F16ToF32 => {
            let a = arr.as_any().downcast_ref::<Float16Array>().unwrap();
            qwp_ws.arrow_bulk_set_fixed(ctx, col_name, QwpColumnKind::F32, info_full, |out| {
                if null_count == 0 {
                    let bytes =
                        a.values().len().checked_mul(4).ok_or_else(|| {
                            fmt!(ArrowIngest, "Float16 dense extend size overflow")
                        })?;
                    try_reserve_bytes(out, bytes, "Float16 column")?;
                    for &h in a.values() {
                        out.extend_from_slice(&h.to_f32().to_le_bytes());
                    }
                } else {
                    full_with_sentinel_into(out, arr, f32::NAN.to_le_bytes(), |row| {
                        a.value(row).to_f32().to_le_bytes()
                    })?;
                }
                Ok(())
            })
        }
        ColumnKind::F32 => {
            let a = arr.as_any().downcast_ref::<Float32Array>().unwrap();
            qwp_ws.arrow_bulk_set_fixed(ctx, col_name, QwpColumnKind::F32, info_full, |out| {
                if le_no_nulls {
                    extend_le_bytes_checked(out, unsafe { typed_slice_as_le_bytes(a.values()) })?;
                } else {
                    full_with_sentinel_into(out, arr, f32::NAN.to_le_bytes(), |row| {
                        a.value(row).to_le_bytes()
                    })?;
                }
                Ok(())
            })
        }
        ColumnKind::F64 => {
            let a = arr.as_any().downcast_ref::<Float64Array>().unwrap();
            qwp_ws.arrow_bulk_set_fixed(ctx, col_name, QwpColumnKind::F64, info_full, |out| {
                if le_no_nulls {
                    extend_le_bytes_checked(out, unsafe { typed_slice_as_le_bytes(a.values()) })?;
                } else {
                    full_with_sentinel_into(out, arr, f64::NAN.to_le_bytes(), |row| {
                        a.value(row).to_le_bytes()
                    })?;
                }
                Ok(())
            })
        }
        ColumnKind::Char => {
            let a = arr.as_any().downcast_ref::<UInt16Array>().unwrap();
            qwp_ws.arrow_bulk_set_fixed(ctx, col_name, QwpColumnKind::Char, info_full, |out| {
                if le_no_nulls {
                    extend_le_bytes_checked(out, unsafe { typed_slice_as_le_bytes(a.values()) })?;
                } else {
                    full_with_sentinel_into(out, arr, 0u16.to_le_bytes(), |row| {
                        a.value(row).to_le_bytes()
                    })?;
                }
                Ok(())
            })
        }
        ColumnKind::Ipv4 => {
            let a = arr.as_any().downcast_ref::<UInt32Array>().unwrap();
            qwp_ws.arrow_bulk_set_fixed(ctx, col_name, QwpColumnKind::Ipv4, info_sparse, |out| {
                if le_no_nulls {
                    extend_le_bytes_checked(out, unsafe { typed_slice_as_le_bytes(a.values()) })?;
                } else {
                    non_null_le_into(out, arr, |row| a.value(row).to_le_bytes())?;
                }
                Ok(())
            })
        }
        ColumnKind::U8WidenToI32 => {
            let a = arr.as_any().downcast_ref::<UInt8Array>().unwrap();
            qwp_ws.arrow_bulk_set_fixed(ctx, col_name, QwpColumnKind::I32, info_full, |out| {
                if null_count == 0 {
                    try_reserve_bytes(
                        out,
                        a.values()
                            .len()
                            .checked_mul(4)
                            .ok_or_else(|| fmt!(ArrowIngest, "U8 widen reservation overflow"))?,
                        "U8 widen column",
                    )?;
                    for &v in a.values() {
                        out.extend_from_slice(&(v as i32).to_le_bytes());
                    }
                } else {
                    full_with_sentinel_into(out, arr, i32::MIN.to_le_bytes(), |row| {
                        (a.value(row) as i32).to_le_bytes()
                    })?;
                }
                Ok(())
            })
        }
        ColumnKind::U16WidenToI32 => {
            let a = arr.as_any().downcast_ref::<UInt16Array>().unwrap();
            qwp_ws.arrow_bulk_set_fixed(ctx, col_name, QwpColumnKind::I32, info_full, |out| {
                if null_count == 0 {
                    try_reserve_bytes(
                        out,
                        a.values()
                            .len()
                            .checked_mul(4)
                            .ok_or_else(|| fmt!(ArrowIngest, "U16 widen reservation overflow"))?,
                        "U16 widen column",
                    )?;
                    for &v in a.values() {
                        out.extend_from_slice(&(v as i32).to_le_bytes());
                    }
                } else {
                    full_with_sentinel_into(out, arr, i32::MIN.to_le_bytes(), |row| {
                        (a.value(row) as i32).to_le_bytes()
                    })?;
                }
                Ok(())
            })
        }
        ColumnKind::U32WidenToI64 => {
            let a = arr.as_any().downcast_ref::<UInt32Array>().unwrap();
            qwp_ws.arrow_bulk_set_fixed(ctx, col_name, QwpColumnKind::I64, info_full, |out| {
                if null_count == 0 {
                    try_reserve_bytes(
                        out,
                        a.values()
                            .len()
                            .checked_mul(8)
                            .ok_or_else(|| fmt!(ArrowIngest, "U32 widen reservation overflow"))?,
                        "U32 widen column",
                    )?;
                    for &v in a.values() {
                        out.extend_from_slice(&(v as i64).to_le_bytes());
                    }
                } else {
                    full_with_sentinel_into(out, arr, i64::MIN.to_le_bytes(), |row| {
                        (a.value(row) as i64).to_le_bytes()
                    })?;
                }
                Ok(())
            })
        }
        ColumnKind::U64WidenToI64Checked => {
            let a = arr.as_any().downcast_ref::<UInt64Array>().unwrap();
            qwp_ws.arrow_bulk_set_fixed(ctx, col_name, QwpColumnKind::I64, info_full, |out| {
                try_full_with_sentinel_into(out, arr, i64::MIN.to_le_bytes(), |row| {
                    let v = a.value(row);
                    if v > i64::MAX as u64 {
                        return Err(fmt!(
                            ArrowIngest,
                            "UInt64 value {} at row {} exceeds i64::MAX; \
                             QuestDB QWP-WS encodes integers as signed i64",
                            v,
                            row
                        ));
                    }
                    Ok((v as i64).to_le_bytes())
                })
            })
        }
        ColumnKind::TimestampSecondToMicros => {
            let a = arr.as_any().downcast_ref::<TimestampSecondArray>().unwrap();
            qwp_ws.arrow_bulk_set_fixed(
                ctx,
                col_name,
                QwpColumnKind::TimestampMicros,
                info_sparse,
                |out| {
                    if null_count == 0 {
                        let src = a.values();
                        let bytes = src.len().checked_mul(8).ok_or_else(|| {
                            fmt!(ArrowIngest, "TimestampSecond→µs reservation overflow")
                        })?;
                        try_reserve_bytes(out, bytes, "TimestampSecond column")?;
                        for (row, &v) in src.iter().enumerate() {
                            let widened = v.checked_mul(1_000_000).ok_or_else(|| {
                                fmt!(
                                    ArrowIngest,
                                    "Timestamp s→µs overflow at row {} (value {})",
                                    row,
                                    v
                                )
                            })?;
                            out.extend_from_slice(&widened.to_le_bytes());
                        }
                        Ok(())
                    } else {
                        try_non_null_le_into(out, arr, |row| {
                            let v = a.value(row);
                            v.checked_mul(1_000_000)
                                .map(i64::to_le_bytes)
                                .ok_or_else(|| {
                                    fmt!(
                                        ArrowIngest,
                                        "Timestamp s→µs overflow at row {} (value {})",
                                        row,
                                        v
                                    )
                                })
                        })
                    }
                },
            )
        }
        ColumnKind::TimestampMicros => {
            let a = arr
                .as_any()
                .downcast_ref::<TimestampMicrosecondArray>()
                .unwrap();
            qwp_ws.arrow_bulk_set_fixed(
                ctx,
                col_name,
                QwpColumnKind::TimestampMicros,
                info_sparse,
                |out| {
                    if le_no_nulls {
                        extend_le_bytes_checked(out, unsafe {
                            typed_slice_as_le_bytes(a.values())
                        })?;
                    } else {
                        non_null_le_into(out, arr, |row| a.value(row).to_le_bytes())?;
                    }
                    Ok(())
                },
            )
        }
        ColumnKind::TimestampNanos => {
            let a = arr
                .as_any()
                .downcast_ref::<TimestampNanosecondArray>()
                .unwrap();
            qwp_ws.arrow_bulk_set_fixed(
                ctx,
                col_name,
                QwpColumnKind::TimestampNanos,
                info_sparse,
                |out| {
                    if le_no_nulls {
                        extend_le_bytes_checked(out, unsafe {
                            typed_slice_as_le_bytes(a.values())
                        })?;
                    } else {
                        non_null_le_into(out, arr, |row| a.value(row).to_le_bytes())?;
                    }
                    Ok(())
                },
            )
        }
        ColumnKind::Date => {
            let a = arr
                .as_any()
                .downcast_ref::<TimestampMillisecondArray>()
                .unwrap();
            qwp_ws.arrow_bulk_set_fixed(ctx, col_name, QwpColumnKind::Date, info_sparse, |out| {
                if le_no_nulls {
                    extend_le_bytes_checked(out, unsafe { typed_slice_as_le_bytes(a.values()) })?;
                } else {
                    non_null_le_into(out, arr, |row| a.value(row).to_le_bytes())?;
                }
                Ok(())
            })
        }
        ColumnKind::Date32Days => {
            let a = arr.as_any().downcast_ref::<Date32Array>().unwrap();
            qwp_ws.arrow_bulk_set_fixed(ctx, col_name, QwpColumnKind::Date, info_sparse, |out| {
                if null_count == 0 {
                    let src = a.values();
                    let bytes = src
                        .len()
                        .checked_mul(8)
                        .ok_or_else(|| fmt!(ArrowIngest, "Date32 days→ms reservation overflow"))?;
                    try_reserve_bytes(out, bytes, "Date32 column")?;
                    for (row, &d) in src.iter().enumerate() {
                        let ms = (d as i64).checked_mul(86_400_000).ok_or_else(|| {
                            fmt!(
                                ArrowIngest,
                                "Date32 days→ms overflow at row {} (value {})",
                                row,
                                d
                            )
                        })?;
                        out.extend_from_slice(&ms.to_le_bytes());
                    }
                    Ok(())
                } else {
                    try_non_null_le_into(out, arr, |row| {
                        let days = a.value(row) as i64;
                        days.checked_mul(86_400_000)
                            .map(i64::to_le_bytes)
                            .ok_or_else(|| {
                                fmt!(
                                    ArrowIngest,
                                    "Date32 days→ms overflow at row {} (value {})",
                                    row,
                                    days
                                )
                            })
                    })
                }
            })
        }
        ColumnKind::Date64Ms => {
            let a = arr.as_any().downcast_ref::<Date64Array>().unwrap();
            qwp_ws.arrow_bulk_set_fixed(ctx, col_name, QwpColumnKind::Date, info_sparse, |out| {
                if le_no_nulls {
                    extend_le_bytes_checked(out, unsafe { typed_slice_as_le_bytes(a.values()) })?;
                } else {
                    non_null_le_into(out, arr, |row| a.value(row).to_le_bytes())?;
                }
                Ok(())
            })
        }
        ColumnKind::TimeAsLong(unit) => {
            qwp_ws.arrow_bulk_set_fixed(ctx, col_name, QwpColumnKind::I64, info_full, |out| {
                build_time_as_long_into(out, arr, unit)
            })
        }
        ColumnKind::DurationAsLong(unit) => {
            qwp_ws.arrow_bulk_set_fixed(ctx, col_name, QwpColumnKind::I64, info_full, |out| {
                build_duration_as_long_into(out, arr, unit)
            })
        }
        ColumnKind::Utf8 => {
            let a = arr.as_any().downcast_ref::<StringArray>().unwrap();
            qwp_ws.arrow_bulk_set_varlen(
                ctx,
                col_name,
                QwpColumnKind::String,
                info_sparse,
                |offsets, data| build_varlen_from_string_into(offsets, data, a),
            )
        }
        ColumnKind::LargeUtf8 => {
            let a = arr.as_any().downcast_ref::<LargeStringArray>().unwrap();
            qwp_ws.arrow_bulk_set_varlen(
                ctx,
                col_name,
                QwpColumnKind::String,
                info_sparse,
                |offsets, data| build_varlen_from_large_string_into(offsets, data, a),
            )
        }
        ColumnKind::Utf8View => {
            let a = arr.as_any().downcast_ref::<StringViewArray>().unwrap();
            qwp_ws.arrow_bulk_set_varlen(
                ctx,
                col_name,
                QwpColumnKind::String,
                info_sparse,
                |offsets, data| build_varlen_from_string_view_into(offsets, data, a),
            )
        }
        ColumnKind::Binary => {
            let a = arr.as_any().downcast_ref::<BinaryArray>().unwrap();
            qwp_ws.arrow_bulk_set_varlen(
                ctx,
                col_name,
                QwpColumnKind::Binary,
                info_sparse,
                |offsets, data| build_varlen_from_binary_into(offsets, data, a),
            )
        }
        ColumnKind::LargeBinary => {
            let a = arr.as_any().downcast_ref::<LargeBinaryArray>().unwrap();
            qwp_ws.arrow_bulk_set_varlen(
                ctx,
                col_name,
                QwpColumnKind::Binary,
                info_sparse,
                |offsets, data| build_varlen_from_large_binary_into(offsets, data, a),
            )
        }
        ColumnKind::BinaryView => {
            let a = arr.as_any().downcast_ref::<BinaryViewArray>().unwrap();
            qwp_ws.arrow_bulk_set_varlen(
                ctx,
                col_name,
                QwpColumnKind::Binary,
                info_sparse,
                |offsets, data| build_varlen_from_binary_view_into(offsets, data, a),
            )
        }
        ColumnKind::Uuid => {
            let a = arr.as_any().downcast_ref::<FixedSizeBinaryArray>().unwrap();
            let elem = a.value_length() as usize;
            qwp_ws.arrow_bulk_set_fixed(ctx, col_name, QwpColumnKind::Uuid, info_sparse, |out| {
                if null_count == 0 {
                    let start = a.offset() * elem;
                    out.extend_from_slice(&a.value_data()[start..start + a.len() * elem]);
                } else {
                    non_null_fsb_into(out, a, elem)?;
                }
                Ok(())
            })
        }
        ColumnKind::Long256 => {
            let a = arr.as_any().downcast_ref::<FixedSizeBinaryArray>().unwrap();
            let elem = a.value_length() as usize;
            qwp_ws.arrow_bulk_set_fixed(ctx, col_name, QwpColumnKind::Long256, info_sparse, |out| {
                if null_count == 0 {
                    let start = a.offset() * elem;
                    out.extend_from_slice(&a.value_data()[start..start + a.len() * elem]);
                } else {
                    non_null_fsb_into(out, a, elem)?;
                }
                Ok(())
            })
        }
        ColumnKind::Geohash(precision) => {
            qwp_ws.arrow_bulk_set_geohash(ctx, col_name, precision, info_sparse, |out| {
                build_geohash_bytes_into(out, arr, precision)
            })
        }
        ColumnKind::SymbolDict { key, value } => {
            let payload = build_symbol_payload_dyn(arr, key, value)?;
            qwp_ws.arrow_bulk_set_symbol(
                ctx,
                col_name,
                &payload.keys,
                &payload.entries,
                &payload.dict_data,
                info_sparse,
            )
        }
        ColumnKind::Decimal32WidenToDecimal64 => {
            let a = arr.as_any().downcast_ref::<Decimal32Array>().unwrap();
            let scale = decimal_scale_u8(a.scale(), "Decimal32", 9)?;
            qwp_ws.arrow_bulk_set_decimal(
                ctx,
                col_name,
                QwpColumnKind::Decimal64,
                ArrowDecimalSpec {
                    scale,
                    element_width: 8,
                },
                info_sparse,
                |out| {
                    build_decimal_bytes_i32_widen_into(out, a)?;
                    Ok(())
                },
            )
        }
        ColumnKind::Decimal64 => {
            let a = arr.as_any().downcast_ref::<Decimal64Array>().unwrap();
            let scale = decimal_scale_u8(a.scale(), "Decimal64", 18)?;
            qwp_ws.arrow_bulk_set_decimal(
                ctx,
                col_name,
                QwpColumnKind::Decimal64,
                ArrowDecimalSpec {
                    scale,
                    element_width: 8,
                },
                info_sparse,
                |out| {
                    if le_no_nulls {
                        // SAFETY: i64 has no padding; LE target → wire-format bytes.
                        extend_le_bytes_checked(out, unsafe {
                            typed_slice_as_le_bytes(a.values())
                        })?;
                    } else {
                        build_decimal_bytes_i64_into(out, a)?;
                    }
                    Ok(())
                },
            )
        }
        ColumnKind::Decimal128 => {
            let a = arr.as_any().downcast_ref::<Decimal128Array>().unwrap();
            let scale = decimal_scale_u8(a.scale(), "Decimal128", 38)?;
            qwp_ws.arrow_bulk_set_decimal(
                ctx,
                col_name,
                QwpColumnKind::Decimal128,
                ArrowDecimalSpec {
                    scale,
                    element_width: 16,
                },
                info_sparse,
                |out| {
                    if le_no_nulls {
                        // SAFETY: i128 has no padding; LE target → wire-format bytes.
                        extend_le_bytes_checked(out, unsafe {
                            typed_slice_as_le_bytes(a.values())
                        })?;
                    } else {
                        build_decimal_bytes_i128_into(out, a)?;
                    }
                    Ok(())
                },
            )
        }
        ColumnKind::Decimal256 => {
            let a = arr.as_any().downcast_ref::<Decimal256Array>().unwrap();
            let scale = decimal_scale_u8(a.scale(), "Decimal256", QWP_DECIMAL_MAX_SCALE)?;
            qwp_ws.arrow_bulk_set_decimal(
                ctx,
                col_name,
                QwpColumnKind::Decimal,
                ArrowDecimalSpec {
                    scale,
                    element_width: 32,
                },
                info_sparse,
                |out| {
                    if le_no_nulls {
                        // SAFETY: i256 is `#[repr(C)] { low: u128, high: i128 }`;
                        // on LE that's byte-identical to `to_le_bytes()` output.
                        // The static asserts on size + endianness fail to
                        // compile if a future arrow_buffer reshapes i256.
                        const _: () = {
                            assert!(std::mem::size_of::<arrow_buffer::i256>() == 32);
                            assert!(std::mem::align_of::<arrow_buffer::i256>() <= 32);
                        };
                        #[cfg(target_endian = "big")]
                        compile_error!("Decimal256 LE fast-path requires little-endian host");
                        extend_le_bytes_checked(out, unsafe {
                            typed_slice_as_le_bytes(a.values())
                        })?;
                    } else {
                        build_decimal_bytes_i256_into(out, a)?;
                    }
                    Ok(())
                },
            )
        }
        ColumnKind::ArrayDouble(ndim) => qwp_ws.arrow_bulk_set_array(
            ctx,
            col_name,
            QwpColumnKind::DoubleArray,
            info_sparse,
            |data| build_array_blob_data_into(data, arr, ndim),
        ),
    }
}

/// Bit-pack `arr` directly into `out`, appending after `existing_rows`
/// already present. Skips the intermediate `Vec<u8>` allocation the old
/// `pack_bool_bits` returned. The destination is the column's owned
/// `packed_bits` buffer.
fn pack_bool_bits_into(out: &mut Vec<u8>, existing_rows: usize, arr: &BooleanArray) -> Result<()> {
    let row_count = arr.len();
    let total_rows = existing_rows + row_count;
    let total_bytes = total_rows.div_ceil(8);
    if out.len() < total_bytes {
        out.resize(total_bytes, 0);
    }
    let value_buf = arr.values();
    let null_buf = arr.nulls();
    let nulls_aligned = null_buf.is_none_or(|nb| nb.offset().is_multiple_of(8));
    if existing_rows.is_multiple_of(8) && value_buf.offset().is_multiple_of(8) && nulls_aligned {
        let n_bytes = row_count.div_ceil(8);
        let v_start = value_buf.offset() / 8;
        let v_end = v_start.checked_add(n_bytes).ok_or_else(|| {
            fmt!(
                ArrowIngest,
                "BOOL pack: value-buffer end offset overflow (start={}, n_bytes={})",
                v_start,
                n_bytes
            )
        })?;
        // `from_ffi` builds the Boolean array via `new_unchecked`; a
        // truncated value buffer would slice-panic and abort the host.
        let raw = value_buf.values();
        if v_end > raw.len() {
            return Err(fmt!(
                ArrowIngest,
                "BOOL pack: value buffer {} bytes shorter than required {} bytes",
                raw.len(),
                v_end
            ));
        }
        let dst_off = existing_rows / 8;
        let full_bytes = row_count / 8;
        out[dst_off..dst_off + full_bytes].copy_from_slice(&raw[v_start..v_start + full_bytes]);
        let trailing = row_count % 8;
        if trailing != 0 {
            let mask = (1u8 << trailing) - 1;
            out[dst_off + full_bytes] |= raw[v_start + full_bytes] & mask;
        }
        if let Some(nb) = null_buf {
            let n_start = nb.offset() / 8;
            let n_end = n_start.checked_add(n_bytes).ok_or_else(|| {
                fmt!(
                    ArrowIngest,
                    "BOOL pack: null-buffer end offset overflow (start={}, n_bytes={})",
                    n_start,
                    n_bytes
                )
            })?;
            let null_raw = nb.buffer().as_slice();
            if n_end > null_raw.len() {
                return Err(fmt!(
                    ArrowIngest,
                    "BOOL pack: null buffer {} bytes shorter than required {} bytes",
                    null_raw.len(),
                    n_end
                ));
            }
            for (p, &v) in out[dst_off..dst_off + full_bytes]
                .iter_mut()
                .zip(&null_raw[n_start..n_start + full_bytes])
            {
                *p &= v;
            }
            if trailing != 0 {
                let mask = (1u8 << trailing) - 1;
                out[dst_off + full_bytes] &= null_raw[n_start + full_bytes] | !mask;
            }
        }
        return Ok(());
    }
    for row in 0..row_count {
        if !arr.is_null(row) && arr.value(row) {
            let target = existing_rows + row;
            out[target / 8] |= 1 << (target % 8);
        }
    }
    Ok(())
}

fn varlen_data_base(data: &[u8], label: &str) -> Result<u32> {
    u32::try_from(data.len())
        .map_err(|_| fmt!(ArrowIngest, "{} data base offset exceeds u32::MAX", label))
}

fn build_varlen_from_string_into(
    offsets: &mut Vec<u32>,
    data: &mut Vec<u8>,
    arr: &StringArray,
) -> Result<()> {
    if arr.null_count() == 0 && arr.offset() == 0 {
        return varlen_no_null_i32_into(
            offsets,
            data,
            arr.value_offsets(),
            arr.value_data(),
            arr.len(),
            "VARCHAR",
        );
    }
    let row_count = arr.len();
    let data_base = varlen_data_base(data, "VARCHAR")?;
    let mut cumulative: u32 = 0;
    try_reserve_typed(
        offsets,
        non_null_count(arr, "VARCHAR column")?,
        "VARCHAR offsets",
    )?;
    try_reserve_bytes(data, arr.value_data().len(), "VARCHAR data")?;
    for row in 0..row_count {
        if arr.is_null(row) {
            continue;
        }
        let s = arr.value(row).as_bytes();
        cumulative = cumulative
            .checked_add(s.len() as u32)
            .ok_or_else(|| fmt!(ArrowIngest, "VARCHAR cumulative offset exceeds u32::MAX"))?;
        let absolute = data_base
            .checked_add(cumulative)
            .ok_or_else(|| fmt!(ArrowIngest, "VARCHAR cumulative offset exceeds u32::MAX"))?;
        data.extend_from_slice(s);
        offsets.push(absolute);
    }
    Ok(())
}

fn varlen_no_null_i32_into(
    offsets: &mut Vec<u32>,
    data: &mut Vec<u8>,
    arr_offsets: &[i32],
    arr_data: &[u8],
    arr_len: usize,
    label: &str,
) -> Result<()> {
    if arr_offsets.len() != arr_len + 1 {
        return Err(fmt!(
            ArrowIngest,
            "{} offsets length {} != arr_len + 1 ({})",
            label,
            arr_offsets.len(),
            arr_len + 1
        ));
    }
    // Per-element validation. `arrow::ffi::from_ffi` uses `new_unchecked`
    // and does not enforce monotonic non-negative offsets; without this
    // pass an intermediate negative offset would reinterpret as a giant
    // u32 in the fast path and produce wire-format garbage.
    let mut prev = 0i32;
    for (i, &off) in arr_offsets.iter().enumerate() {
        if off < 0 {
            return Err(fmt!(
                ArrowIngest,
                "{} offset[{}] = {} is negative",
                label,
                i,
                off
            ));
        }
        if i > 0 && off < prev {
            return Err(fmt!(
                ArrowIngest,
                "{} offsets not monotonic: offset[{}] = {} < offset[{}] = {}",
                label,
                i,
                off,
                i - 1,
                prev
            ));
        }
        prev = off;
    }
    let first = arr_offsets[0];
    let last = arr_offsets[arr_len];
    let first_u = first as u32;
    let last_u = last as u32;
    let used = last_u - first_u;
    let last_usize = last as usize;
    if last_usize > arr_data.len() {
        return Err(fmt!(
            ArrowIngest,
            "{} last offset {} exceeds data len {}",
            label,
            last_usize,
            arr_data.len()
        ));
    }
    let data_base = varlen_data_base(data, label)?;
    data_base
        .checked_add(used)
        .ok_or_else(|| fmt!(ArrowIngest, "{} cumulative offset exceeds u32::MAX", label))?;
    try_reserve_typed(offsets, arr_len, "varlen offsets")?;
    try_reserve_bytes(data, used as usize, "varlen data")?;
    let rebase = data_base.wrapping_sub(first_u);
    if first == 0 && data_base == 0 {
        // SAFETY: every offset validated non-negative above; i32 and u32
        // have identical layout so the cast is a no-op bit reinterpret.
        let as_u32: &[u32] =
            unsafe { std::slice::from_raw_parts(arr_offsets[1..].as_ptr() as *const u32, arr_len) };
        offsets.extend_from_slice(as_u32);
    } else {
        for &off in &arr_offsets[1..] {
            offsets.push(rebase.wrapping_add(off as u32));
        }
    }
    data.extend_from_slice(&arr_data[first as usize..last_usize]);
    Ok(())
}

fn varlen_no_null_i64_narrow_into(
    offsets: &mut Vec<u32>,
    data: &mut Vec<u8>,
    arr_offsets: &[i64],
    arr_data: &[u8],
    arr_len: usize,
    label: &str,
) -> Result<()> {
    if arr_offsets.len() != arr_len + 1 {
        return Err(fmt!(
            ArrowIngest,
            "{} offsets length {} != arr_len + 1 ({})",
            label,
            arr_offsets.len(),
            arr_len + 1
        ));
    }
    let mut prev = 0i64;
    for (i, &off) in arr_offsets.iter().enumerate() {
        if off < 0 {
            return Err(fmt!(
                ArrowIngest,
                "{} offset[{}] = {} is negative",
                label,
                i,
                off
            ));
        }
        if i > 0 && off < prev {
            return Err(fmt!(
                ArrowIngest,
                "{} offsets not monotonic: offset[{}] = {} < offset[{}] = {}",
                label,
                i,
                off,
                i - 1,
                prev
            ));
        }
        prev = off;
    }
    let first = arr_offsets[0];
    let last = arr_offsets[arr_len];
    let first_u: u32 = u32::try_from(first).map_err(|_| {
        fmt!(
            ArrowIngest,
            "{} first offset {} exceeds u32::MAX",
            label,
            first
        )
    })?;
    let last_u: u32 = u32::try_from(last).map_err(|_| {
        fmt!(
            ArrowIngest,
            "{} last offset {} exceeds u32::MAX",
            label,
            last
        )
    })?;
    let used = last_u - first_u;
    let last_usize = last as usize;
    if last_usize > arr_data.len() {
        return Err(fmt!(
            ArrowIngest,
            "{} last offset {} exceeds data len {}",
            label,
            last_usize,
            arr_data.len()
        ));
    }
    let data_base = varlen_data_base(data, label)?;
    data_base
        .checked_add(used)
        .ok_or_else(|| fmt!(ArrowIngest, "{} cumulative offset exceeds u32::MAX", label))?;
    try_reserve_typed(offsets, arr_len, "varlen offsets")?;
    try_reserve_bytes(data, used as usize, "varlen data")?;
    let rebase = data_base.wrapping_sub(first_u);
    for &off in &arr_offsets[1..] {
        offsets.push(rebase.wrapping_add(off as u32));
    }
    data.extend_from_slice(&arr_data[first as usize..last_usize]);
    Ok(())
}

fn build_varlen_from_large_string_into(
    offsets: &mut Vec<u32>,
    data: &mut Vec<u8>,
    arr: &LargeStringArray,
) -> Result<()> {
    if arr.null_count() == 0 && arr.offset() == 0 {
        return varlen_no_null_i64_narrow_into(
            offsets,
            data,
            arr.value_offsets(),
            arr.value_data(),
            arr.len(),
            "LargeUtf8",
        );
    }
    let row_count = arr.len();
    let data_base = varlen_data_base(data, "LargeUtf8")?;
    let mut cumulative: u32 = 0;
    try_reserve_typed(
        offsets,
        non_null_count(arr, "LargeUtf8 column")?,
        "LargeUtf8 offsets",
    )?;
    try_reserve_bytes(data, arr.value_data().len(), "LargeUtf8 data")?;
    for row in 0..row_count {
        if arr.is_null(row) {
            continue;
        }
        let s = arr.value(row).as_bytes();
        let len_u32 = u32::try_from(s.len())
            .map_err(|_| fmt!(ArrowIngest, "LargeUtf8 row length exceeds u32::MAX"))?;
        cumulative = cumulative
            .checked_add(len_u32)
            .ok_or_else(|| fmt!(ArrowIngest, "LargeUtf8 cumulative offset exceeds u32::MAX"))?;
        let absolute = data_base
            .checked_add(cumulative)
            .ok_or_else(|| fmt!(ArrowIngest, "LargeUtf8 cumulative offset exceeds u32::MAX"))?;
        data.extend_from_slice(s);
        offsets.push(absolute);
    }
    Ok(())
}

fn build_varlen_from_string_view_into(
    offsets: &mut Vec<u32>,
    data: &mut Vec<u8>,
    arr: &StringViewArray,
) -> Result<()> {
    let row_count = arr.len();
    let data_base = varlen_data_base(data, "VARCHAR")?;
    let mut cumulative: u32 = 0;
    try_reserve_typed(
        offsets,
        non_null_count(arr, "Utf8View column")?,
        "Utf8View offsets",
    )?;
    for row in 0..row_count {
        if arr.is_null(row) {
            continue;
        }
        let s = arr.value(row).as_bytes();
        cumulative = cumulative
            .checked_add(s.len() as u32)
            .ok_or_else(|| fmt!(ArrowIngest, "VARCHAR cumulative offset exceeds u32::MAX"))?;
        let absolute = data_base
            .checked_add(cumulative)
            .ok_or_else(|| fmt!(ArrowIngest, "VARCHAR cumulative offset exceeds u32::MAX"))?;
        data.extend_from_slice(s);
        offsets.push(absolute);
    }
    Ok(())
}

fn build_varlen_from_binary_into(
    offsets: &mut Vec<u32>,
    data: &mut Vec<u8>,
    arr: &BinaryArray,
) -> Result<()> {
    if arr.null_count() == 0 && arr.offset() == 0 {
        return varlen_no_null_i32_into(
            offsets,
            data,
            arr.value_offsets(),
            arr.value_data(),
            arr.len(),
            "BINARY",
        );
    }
    let row_count = arr.len();
    let data_base = varlen_data_base(data, "BINARY")?;
    let mut cumulative: u32 = 0;
    try_reserve_typed(
        offsets,
        non_null_count(arr, "Binary column")?,
        "Binary offsets",
    )?;
    try_reserve_bytes(data, arr.value_data().len(), "Binary data")?;
    for row in 0..row_count {
        if arr.is_null(row) {
            continue;
        }
        let s = arr.value(row);
        cumulative = cumulative
            .checked_add(s.len() as u32)
            .ok_or_else(|| fmt!(ArrowIngest, "BINARY cumulative offset exceeds u32::MAX"))?;
        let absolute = data_base
            .checked_add(cumulative)
            .ok_or_else(|| fmt!(ArrowIngest, "BINARY cumulative offset exceeds u32::MAX"))?;
        data.extend_from_slice(s);
        offsets.push(absolute);
    }
    Ok(())
}

fn build_varlen_from_large_binary_into(
    offsets: &mut Vec<u32>,
    data: &mut Vec<u8>,
    arr: &LargeBinaryArray,
) -> Result<()> {
    if arr.null_count() == 0 && arr.offset() == 0 {
        return varlen_no_null_i64_narrow_into(
            offsets,
            data,
            arr.value_offsets(),
            arr.value_data(),
            arr.len(),
            "LargeBinary",
        );
    }
    let row_count = arr.len();
    let data_base = varlen_data_base(data, "LargeBinary")?;
    let mut cumulative: u32 = 0;
    try_reserve_typed(
        offsets,
        non_null_count(arr, "LargeBinary column")?,
        "LargeBinary offsets",
    )?;
    try_reserve_bytes(data, arr.value_data().len(), "LargeBinary data")?;
    for row in 0..row_count {
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
        let absolute = data_base.checked_add(cumulative).ok_or_else(|| {
            fmt!(
                ArrowIngest,
                "LargeBinary cumulative offset exceeds u32::MAX"
            )
        })?;
        data.extend_from_slice(s);
        offsets.push(absolute);
    }
    Ok(())
}

fn build_varlen_from_binary_view_into(
    offsets: &mut Vec<u32>,
    data: &mut Vec<u8>,
    arr: &BinaryViewArray,
) -> Result<()> {
    let row_count = arr.len();
    let data_base = varlen_data_base(data, "BINARY")?;
    let mut cumulative: u32 = 0;
    try_reserve_typed(
        offsets,
        non_null_count(arr, "BinaryView column")?,
        "BinaryView offsets",
    )?;
    for row in 0..row_count {
        if arr.is_null(row) {
            continue;
        }
        let s = arr.value(row);
        cumulative = cumulative
            .checked_add(s.len() as u32)
            .ok_or_else(|| fmt!(ArrowIngest, "BINARY cumulative offset exceeds u32::MAX"))?;
        let absolute = data_base
            .checked_add(cumulative)
            .ok_or_else(|| fmt!(ArrowIngest, "BINARY cumulative offset exceeds u32::MAX"))?;
        data.extend_from_slice(s);
        offsets.push(absolute);
    }
    Ok(())
}

fn build_geohash_bytes_into(out: &mut Vec<u8>, arr: &dyn Array, precision_bits: u8) -> Result<()> {
    if !(1..=60).contains(&precision_bits) {
        return Err(fmt!(
            ArrowIngest,
            "geohash precision_bits {} out of range (1..=60)",
            precision_bits
        ));
    }
    let row_count = arr.len();
    let width = (precision_bits as usize).div_ceil(8);
    let non_null = non_null_count(arr, "Geohash column")?;
    let bytes = non_null
        .checked_mul(width)
        .ok_or_else(|| fmt!(ArrowIngest, "Geohash byte-buffer reservation overflow"))?;
    try_reserve_bytes(out, bytes, "Geohash column")?;
    for row in 0..row_count {
        if arr.is_null(row) {
            continue;
        }
        let v = geohash_value_from_array(arr, row)?;
        let le = v.to_le_bytes();
        out.extend_from_slice(&le[..width]);
    }
    Ok(())
}

fn decimal_scale_u8(scale_i8: i8, label: &str, max_scale: u8) -> Result<u8> {
    if scale_i8 < 0 {
        return Err(fmt!(
            ArrowIngest,
            "Arrow {} negative scale {} not supported",
            label,
            scale_i8
        ));
    }
    let scale = scale_i8 as u8;
    if scale > max_scale {
        return Err(fmt!(
            ArrowIngest,
            "Arrow {} scale {} exceeds maximum {} for this Arrow decimal width",
            label,
            scale,
            max_scale
        ));
    }
    Ok(scale)
}

fn build_decimal_bytes_i32_widen_into(out: &mut Vec<u8>, arr: &Decimal32Array) -> Result<()> {
    if arr.null_count() == 0 {
        let src = arr.values();
        let bytes = src
            .len()
            .checked_mul(8)
            .ok_or_else(|| fmt!(ArrowIngest, "Decimal32 byte-buffer reservation overflow"))?;
        try_reserve_bytes(out, bytes, "Decimal32 column")?;
        for &v in src {
            out.extend_from_slice(&(v as i64).to_le_bytes());
        }
        return Ok(());
    }
    let non_null = non_null_count(arr, "Decimal32 column")?;
    let row_count = arr.len();
    let bytes = non_null
        .checked_mul(8)
        .ok_or_else(|| fmt!(ArrowIngest, "Decimal32 byte-buffer reservation overflow"))?;
    try_reserve_bytes(out, bytes, "Decimal32 column")?;
    for row in 0..row_count {
        if arr.is_null(row) {
            continue;
        }
        out.extend_from_slice(&(arr.value(row) as i64).to_le_bytes());
    }
    Ok(())
}

fn build_decimal_bytes_i64_into(out: &mut Vec<u8>, arr: &Decimal64Array) -> Result<()> {
    let non_null = non_null_count(arr, "Decimal64 column")?;
    let row_count = arr.len();
    let bytes = non_null
        .checked_mul(8)
        .ok_or_else(|| fmt!(ArrowIngest, "Decimal64 byte-buffer reservation overflow"))?;
    try_reserve_bytes(out, bytes, "Decimal64 column")?;
    for row in 0..row_count {
        if arr.is_null(row) {
            continue;
        }
        out.extend_from_slice(&arr.value(row).to_le_bytes());
    }
    Ok(())
}

fn build_decimal_bytes_i128_into(out: &mut Vec<u8>, arr: &Decimal128Array) -> Result<()> {
    let non_null = non_null_count(arr, "Decimal128 column")?;
    let row_count = arr.len();
    let bytes = non_null
        .checked_mul(16)
        .ok_or_else(|| fmt!(ArrowIngest, "Decimal128 byte-buffer reservation overflow"))?;
    try_reserve_bytes(out, bytes, "Decimal128 column")?;
    for row in 0..row_count {
        if arr.is_null(row) {
            continue;
        }
        out.extend_from_slice(&arr.value(row).to_le_bytes());
    }
    Ok(())
}

fn build_decimal_bytes_i256_into(out: &mut Vec<u8>, arr: &Decimal256Array) -> Result<()> {
    let non_null = non_null_count(arr, "Decimal256 column")?;
    let row_count = arr.len();
    let bytes = non_null
        .checked_mul(32)
        .ok_or_else(|| fmt!(ArrowIngest, "Decimal256 byte-buffer reservation overflow"))?;
    try_reserve_bytes(out, bytes, "Decimal256 column")?;
    for row in 0..row_count {
        if arr.is_null(row) {
            continue;
        }
        out.extend_from_slice(&arr.value(row).to_le_bytes());
    }
    Ok(())
}

fn build_array_blob_data_into(data: &mut Vec<u8>, arr: &dyn Array, ndim: usize) -> Result<()> {
    let row_count = arr.len();
    let ndim_u8 =
        u8::try_from(ndim).map_err(|_| fmt!(ArrowIngest, "ARRAY ndim {} exceeds u8::MAX", ndim))?;
    let mut shape: Vec<usize> = Vec::with_capacity(ndim);
    for row in 0..row_count {
        if arr.is_null(row) {
            continue;
        }
        shape.clear();
        let extract = extract_array_row(arr, ndim, row, &mut shape)?;
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
        data.push(ndim_u8);
        for &dim in shape.iter() {
            let dim_u32 = u32::try_from(dim)
                .map_err(|_| fmt!(ArrowIngest, "ARRAY dimension {} exceeds u32::MAX", dim))?;
            data.extend_from_slice(&dim_u32.to_le_bytes());
        }
        if cfg!(target_endian = "little") {
            // SAFETY: f64 has no padding; LE target → wire-format bytes.
            data.extend_from_slice(unsafe { typed_slice_as_le_bytes(leaf_values) });
        } else {
            for &v in leaf_values {
                data.extend_from_slice(&v.to_le_bytes());
            }
        }
    }
    Ok(())
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
            DataType::FixedSizeList(inner, _) => {
                ndim += 1;
                current = inner.data_type();
            }
            _ => return (current.clone(), ndim),
        }
    }
}

fn dict_key_for(dt: &DataType) -> Option<DictKey> {
    match dt {
        DataType::UInt8 => Some(DictKey::U8),
        DataType::UInt16 => Some(DictKey::U16),
        DataType::UInt32 => Some(DictKey::U32),
        _ => None,
    }
}

fn dict_value_for(dt: &DataType) -> Option<DictValue> {
    match dt {
        DataType::Utf8 => Some(DictValue::Utf8),
        DataType::LargeUtf8 => Some(DictValue::LargeUtf8),
        DataType::Utf8View => Some(DictValue::Utf8View),
        _ => None,
    }
}

fn emit_i32_widen_to_i64_full(out: &mut Vec<u8>, arr: &dyn Array, values: &[i32]) -> Result<()> {
    let sentinel = i64::MIN.to_le_bytes();
    if arr.null_count() == 0 {
        let bytes = values
            .len()
            .checked_mul(8)
            .ok_or_else(|| fmt!(ArrowIngest, "i32→i64 widen dense extend size overflow"))?;
        try_reserve_bytes(out, bytes, "i32→i64 column")?;
        for &v in values {
            out.extend_from_slice(&(v as i64).to_le_bytes());
        }
    } else {
        full_with_sentinel_into(out, arr, sentinel, |row| (values[row] as i64).to_le_bytes())?;
    }
    Ok(())
}

fn emit_i64_full(out: &mut Vec<u8>, arr: &dyn Array, values: &[i64]) -> Result<()> {
    let sentinel = i64::MIN.to_le_bytes();
    if arr.null_count() == 0 && cfg!(target_endian = "little") {
        // SAFETY: i64 has no padding; LE target → wire-format bytes.
        extend_le_bytes_checked(out, unsafe { typed_slice_as_le_bytes(values) })?;
    } else if arr.null_count() == 0 {
        let bytes = values
            .len()
            .checked_mul(8)
            .ok_or_else(|| fmt!(ArrowIngest, "i64 dense extend size overflow"))?;
        try_reserve_bytes(out, bytes, "i64 column")?;
        for &v in values {
            out.extend_from_slice(&v.to_le_bytes());
        }
    } else {
        full_with_sentinel_into(out, arr, sentinel, |row| values[row].to_le_bytes())?;
    }
    Ok(())
}

fn build_time_as_long_into(out: &mut Vec<u8>, arr: &dyn Array, unit: TimeUnit) -> Result<()> {
    match unit {
        TimeUnit::Second => {
            let a = arr.as_any().downcast_ref::<Time32SecondArray>().unwrap();
            emit_i32_widen_to_i64_full(out, arr, a.values())?;
        }
        TimeUnit::Millisecond => {
            let a = arr
                .as_any()
                .downcast_ref::<Time32MillisecondArray>()
                .unwrap();
            emit_i32_widen_to_i64_full(out, arr, a.values())?;
        }
        TimeUnit::Microsecond => {
            let a = arr
                .as_any()
                .downcast_ref::<Time64MicrosecondArray>()
                .unwrap();
            emit_i64_full(out, arr, a.values())?;
        }
        TimeUnit::Nanosecond => {
            let a = arr
                .as_any()
                .downcast_ref::<Time64NanosecondArray>()
                .unwrap();
            emit_i64_full(out, arr, a.values())?;
        }
    }
    Ok(())
}

fn build_duration_as_long_into(out: &mut Vec<u8>, arr: &dyn Array, unit: TimeUnit) -> Result<()> {
    match unit {
        TimeUnit::Second => {
            let a = arr.as_any().downcast_ref::<DurationSecondArray>().unwrap();
            emit_i64_full(out, arr, a.values())?;
        }
        TimeUnit::Millisecond => {
            let a = arr
                .as_any()
                .downcast_ref::<DurationMillisecondArray>()
                .unwrap();
            emit_i64_full(out, arr, a.values())?;
        }
        TimeUnit::Microsecond => {
            let a = arr
                .as_any()
                .downcast_ref::<DurationMicrosecondArray>()
                .unwrap();
            emit_i64_full(out, arr, a.values())?;
        }
        TimeUnit::Nanosecond => {
            let a = arr
                .as_any()
                .downcast_ref::<DurationNanosecondArray>()
                .unwrap();
            emit_i64_full(out, arr, a.values())?;
        }
    }
    Ok(())
}

fn dict_lookup_str(values: &ArrayRef, key_idx: usize, value: DictValue) -> Result<&str> {
    fn check<A: Array>(arr: &A, key_idx: usize) -> Result<()> {
        if key_idx >= arr.len() {
            return Err(fmt!(
                ArrowIngest,
                "dict key {} out of range (dict size {})",
                key_idx,
                arr.len()
            ));
        }
        if arr.is_null(key_idx) {
            return Err(fmt!(
                ArrowIngest,
                "dictionary values for SYMBOL / VARCHAR must not contain nulls"
            ));
        }
        Ok(())
    }
    match value {
        DictValue::Utf8 => {
            let utf8 = values
                .as_any()
                .downcast_ref::<StringArray>()
                .ok_or_else(|| {
                    fmt!(
                        ArrowIngest,
                        "dictionary values must be Utf8 for this column"
                    )
                })?;
            check(utf8, key_idx)?;
            Ok(utf8.value(key_idx))
        }
        DictValue::LargeUtf8 => {
            let utf8 = values
                .as_any()
                .downcast_ref::<LargeStringArray>()
                .ok_or_else(|| {
                    fmt!(
                        ArrowIngest,
                        "dictionary values must be LargeUtf8 for this column"
                    )
                })?;
            check(utf8, key_idx)?;
            Ok(utf8.value(key_idx))
        }
        DictValue::Utf8View => {
            let utf8 = values
                .as_any()
                .downcast_ref::<StringViewArray>()
                .ok_or_else(|| {
                    fmt!(
                        ArrowIngest,
                        "dictionary values must be Utf8View for this column"
                    )
                })?;
            check(utf8, key_idx)?;
            Ok(utf8.value(key_idx))
        }
    }
}

fn dict_values_dyn(arr: &dyn Array, key: DictKey) -> &ArrayRef {
    match key {
        DictKey::U32 => arr
            .as_any()
            .downcast_ref::<DictionaryArray<UInt32Type>>()
            .unwrap()
            .values(),
        DictKey::U16 => arr
            .as_any()
            .downcast_ref::<DictionaryArray<UInt16Type>>()
            .unwrap()
            .values(),
        DictKey::U8 => arr
            .as_any()
            .downcast_ref::<DictionaryArray<UInt8Type>>()
            .unwrap()
            .values(),
    }
}

struct SymbolPayload {
    keys: Vec<u32>,
    entries: Vec<(u32, u32)>,
    dict_data: Vec<u8>,
}

// Bounds reserved sizes so a hostile FFI batch cannot trigger an
// allocator-OOM abort under `panic = "abort"`.
const MAX_ARROW_DICT_VALUES: usize = 16 * 1024 * 1024;
const MAX_ARROW_INGEST_ROWS: usize = 16 * 1024 * 1024;
const MAX_ARROW_INGEST_DATA_BYTES: usize = 1024 * 1024 * 1024;

// Sum the data-buffer byte sizes that arrow-rs's internal validation /
// our own widening loops will visit, including dictionary value data,
// FixedSizeBinary backing bytes and the multi-buffer View arrays. Returns
// `None` for types whose data size is not bounded by a single byte-count
// (e.g. nested ListArray descends recursively below).
fn check_array_data_bounds_inner(arr: &dyn Array, depth: usize) -> Result<()> {
    if depth > 32 {
        return Err(fmt!(
            ArrowIngest,
            "nested array depth exceeds 32 in data-bounds check"
        ));
    }
    let dt = arr.data_type();
    let bytes: Option<usize> = match dt {
        DataType::Utf8 => arr
            .as_any()
            .downcast_ref::<StringArray>()
            .map(|a| a.value_data().len()),
        DataType::LargeUtf8 => arr
            .as_any()
            .downcast_ref::<LargeStringArray>()
            .map(|a| a.value_data().len()),
        DataType::Binary => arr
            .as_any()
            .downcast_ref::<BinaryArray>()
            .map(|a| a.value_data().len()),
        DataType::LargeBinary => arr
            .as_any()
            .downcast_ref::<LargeBinaryArray>()
            .map(|a| a.value_data().len()),
        DataType::Utf8View => arr
            .as_any()
            .downcast_ref::<StringViewArray>()
            .map(|a| a.data_buffers().iter().map(|b| b.len()).sum()),
        DataType::BinaryView => arr
            .as_any()
            .downcast_ref::<BinaryViewArray>()
            .map(|a| a.data_buffers().iter().map(|b| b.len()).sum()),
        DataType::FixedSizeBinary(width) => arr
            .as_any()
            .downcast_ref::<FixedSizeBinaryArray>()
            .map(|a| (*width as usize).saturating_mul(a.len())),
        DataType::Float64 => arr
            .as_any()
            .downcast_ref::<Float64Array>()
            .map(|a| a.values().len().saturating_mul(8)),
        _ => None,
    };
    if let Some(b) = bytes
        && b > MAX_ARROW_INGEST_DATA_BYTES
    {
        return Err(fmt!(
            ArrowIngest,
            "data-buffer length {} exceeds {} byte cap",
            b,
            MAX_ARROW_INGEST_DATA_BYTES
        ));
    }
    // Recurse into dictionary values, list/fixed-size-list children.
    if let Some(d) = arr.as_any().downcast_ref::<DictionaryArray<UInt8Type>>() {
        check_array_data_bounds_inner(d.values().as_ref(), depth + 1)?;
    } else if let Some(d) = arr.as_any().downcast_ref::<DictionaryArray<UInt16Type>>() {
        check_array_data_bounds_inner(d.values().as_ref(), depth + 1)?;
    } else if let Some(d) = arr.as_any().downcast_ref::<DictionaryArray<UInt32Type>>() {
        check_array_data_bounds_inner(d.values().as_ref(), depth + 1)?;
    } else if let Some(l) = arr.as_any().downcast_ref::<ListArray>() {
        check_array_data_bounds_inner(l.values().as_ref(), depth + 1)?;
    } else if let Some(l) = arr.as_any().downcast_ref::<LargeListArray>() {
        check_array_data_bounds_inner(l.values().as_ref(), depth + 1)?;
    } else if let Some(l) = arr.as_any().downcast_ref::<FixedSizeListArray>() {
        check_array_data_bounds_inner(l.values().as_ref(), depth + 1)?;
    }
    Ok(())
}

fn check_batch_data_bounds(batch: &RecordBatch) -> Result<()> {
    for (idx, col) in batch.columns().iter().enumerate() {
        check_array_data_bounds_inner(col.as_ref(), 0)
            .map_err(|e| fmt!(ArrowIngest, "column #{}: {}", idx, e.msg()))?;
    }
    Ok(())
}

fn build_symbol_payload_dyn(
    arr: &dyn Array,
    key: DictKey,
    value: DictValue,
) -> Result<SymbolPayload> {
    let values = dict_values_dyn(arr, key);
    let value_count = values.len();
    if value_count > MAX_ARROW_DICT_VALUES {
        return Err(fmt!(
            ArrowIngest,
            "SYMBOL dictionary has {} values exceeding limit {}",
            value_count,
            MAX_ARROW_DICT_VALUES
        ));
    }
    let row_count = arr.len();
    let mut keys: Vec<u32> = Vec::new();
    try_reserve_typed(&mut keys, row_count, "SYMBOL keys")?;
    fill_dict_keys_into(&mut keys, arr, key);
    debug_assert_eq!(keys.len(), row_count);
    // Skip unreferenced dict entries (Polars/Datafusion may leave
    // nulls there after filter/projection); emit zero-length stubs
    // so key→entry indexing on the wire stays intact.
    let mut referenced: Vec<bool> = Vec::new();
    try_reserve_typed(&mut referenced, value_count, "SYMBOL referenced bitmap")?;
    referenced.resize(value_count, false);
    let has_nulls = arr.null_count() != 0;
    for (row, &k) in keys.iter().enumerate() {
        if has_nulls && arr.is_null(row) {
            continue;
        }
        let idx = k as usize;
        if idx >= value_count {
            return Err(fmt!(
                ArrowIngest,
                "SYMBOL dictionary key {} at row {} exceeds dict size {}",
                k,
                row,
                value_count
            ));
        }
        referenced[idx] = true;
    }
    let mut entries: Vec<(u32, u32)> = Vec::new();
    try_reserve_typed(&mut entries, value_count, "SYMBOL entries")?;
    let mut dict_data: Vec<u8> = Vec::new();
    let mut cumulative: u32 = 0;
    for (i, used) in referenced.iter().enumerate() {
        if !*used {
            entries.push((cumulative, 0));
            continue;
        }
        let s = dict_lookup_str(values, i, value)?;
        let bytes = s.as_bytes();
        let len = u32::try_from(bytes.len())
            .map_err(|_| fmt!(ArrowIngest, "SYMBOL entry length exceeds u32::MAX"))?;
        let next_cumulative = cumulative
            .checked_add(len)
            .ok_or_else(|| fmt!(ArrowIngest, "SYMBOL cumulative data exceeds u32::MAX"))?;
        if (next_cumulative as usize) > MAX_ARROW_INGEST_DATA_BYTES {
            return Err(fmt!(
                ArrowIngest,
                "SYMBOL cumulative data {} exceeds {} byte cap",
                next_cumulative,
                MAX_ARROW_INGEST_DATA_BYTES
            ));
        }
        try_reserve_bytes(&mut dict_data, bytes.len(), "SYMBOL dict_data")?;
        dict_data.extend_from_slice(bytes);
        entries.push((cumulative, len));
        cumulative = next_cumulative;
    }
    Ok(SymbolPayload {
        keys,
        entries,
        dict_data,
    })
}

fn fill_dict_keys_into(out: &mut Vec<u32>, arr: &dyn Array, key: DictKey) {
    let has_nulls = arr.null_count() != 0;
    match key {
        DictKey::U32 => {
            let dict = arr
                .as_any()
                .downcast_ref::<DictionaryArray<UInt32Type>>()
                .unwrap();
            let raw = dict.keys().values();
            if !has_nulls {
                out.extend_from_slice(raw);
                return;
            }
            for (row, &k) in raw.iter().enumerate() {
                out.push(if arr.is_null(row) { 0 } else { k });
            }
        }
        DictKey::U16 => {
            let dict = arr
                .as_any()
                .downcast_ref::<DictionaryArray<UInt16Type>>()
                .unwrap();
            let raw = dict.keys().values();
            if !has_nulls {
                for &k in raw {
                    out.push(k as u32);
                }
            } else {
                for (row, &k) in raw.iter().enumerate() {
                    out.push(if arr.is_null(row) { 0 } else { k as u32 });
                }
            }
        }
        DictKey::U8 => {
            let dict = arr
                .as_any()
                .downcast_ref::<DictionaryArray<UInt8Type>>()
                .unwrap();
            let raw = dict.keys().values();
            if !has_nulls {
                for &k in raw {
                    out.push(k as u32);
                }
            } else {
                for (row, &k) in raw.iter().enumerate() {
                    out.push(if arr.is_null(row) { 0 } else { k as u32 });
                }
            }
        }
    }
}

struct ArrayRowExtract {
    leaf: ArrayRef,
    leaf_start: usize,
    leaf_end: usize,
}

fn extract_array_row(
    outer: &dyn Array,
    ndim: usize,
    row: usize,
    shape: &mut Vec<usize>,
) -> Result<ArrayRowExtract> {
    let (mut start, mut end) = list_row_range(outer, row)?;
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
        leaf: current_values,
        leaf_start: start,
        leaf_end: end,
    })
}

fn checked_offset_i32(off: i32, idx: usize) -> Result<usize> {
    if off < 0 {
        return Err(fmt!(
            ArrowIngest,
            "ARRAY List offset[{}] = {} is negative",
            idx,
            off
        ));
    }
    Ok(off as usize)
}

fn checked_offset_i64(off: i64, idx: usize) -> Result<usize> {
    if off < 0 {
        return Err(fmt!(
            ArrowIngest,
            "ARRAY LargeList offset[{}] = {} is negative",
            idx,
            off
        ));
    }
    usize::try_from(off).map_err(|_| {
        fmt!(
            ArrowIngest,
            "ARRAY LargeList offset[{}] = {} exceeds usize::MAX",
            idx,
            off
        )
    })
}

fn list_row_range(arr: &dyn Array, row: usize) -> Result<(usize, usize)> {
    if let Some(la) = arr.as_any().downcast_ref::<ListArray>() {
        let offsets = la.offsets();
        let start = checked_offset_i32(offsets[row], row)?;
        let end = checked_offset_i32(offsets[row + 1], row + 1)?;
        if end < start {
            return Err(fmt!(
                ArrowIngest,
                "ARRAY List outer offsets non-monotonic at row {} (start={}, end={})",
                row,
                start,
                end
            ));
        }
        Ok((start, end))
    } else if let Some(la) = arr.as_any().downcast_ref::<LargeListArray>() {
        let offsets = la.offsets();
        let start = checked_offset_i64(offsets[row], row)?;
        let end = checked_offset_i64(offsets[row + 1], row + 1)?;
        if end < start {
            return Err(fmt!(
                ArrowIngest,
                "ARRAY LargeList outer offsets non-monotonic at row {} (start={}, end={})",
                row,
                start,
                end
            ));
        }
        Ok((start, end))
    } else if let Some(la) = arr.as_any().downcast_ref::<FixedSizeListArray>() {
        let stride = la.value_length() as usize;
        let start = row.checked_mul(stride).ok_or_else(|| {
            fmt!(
                ArrowIngest,
                "ARRAY FixedSizeList row {} * stride {} overflows usize",
                row,
                stride
            )
        })?;
        let end = row
            .checked_add(1)
            .and_then(|n| n.checked_mul(stride))
            .ok_or_else(|| {
                fmt!(
                    ArrowIngest,
                    "ARRAY FixedSizeList row {} * stride {} overflows usize",
                    row + 1,
                    stride
                )
            })?;
        Ok((start, end))
    } else {
        Err(fmt!(
            ArrowIngest,
            "expected List / LargeList / FixedSizeList at outer ARRAY level, got {:?}",
            arr.data_type()
        ))
    }
}

fn list_values(arr: &dyn Array) -> Result<ArrayRef> {
    if let Some(la) = arr.as_any().downcast_ref::<ListArray>() {
        Ok(la.values().clone())
    } else if let Some(la) = arr.as_any().downcast_ref::<LargeListArray>() {
        Ok(la.values().clone())
    } else if let Some(la) = arr.as_any().downcast_ref::<FixedSizeListArray>() {
        Ok(la.values().clone())
    } else {
        Err(fmt!(
            ArrowIngest,
            "expected List / LargeList / FixedSizeList, got {:?}",
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
        let next_start = checked_offset_i32(offsets[start], start)?;
        let first_end = checked_offset_i32(offsets[start + 1], start + 1)?;
        let dim = first_end.checked_sub(next_start).ok_or_else(|| {
            fmt!(
                ArrowIngest,
                "ARRAY List inner offsets non-monotonic at row {}",
                start
            )
        })?;
        let next_end = checked_offset_i32(offsets[end], end)?;
        if next_end.checked_sub(next_start) != dim.checked_mul(end - start) {
            return Err(ragged_inner_error_i32(&offsets[..], start, end, dim));
        }
        Ok((next_start, next_end, dim, la.values().clone()))
    } else if let Some(la) = arr.as_any().downcast_ref::<LargeListArray>() {
        let offsets = la.offsets();
        if end <= start {
            return Ok((0, 0, 0, la.values().clone()));
        }
        let next_start = checked_offset_i64(offsets[start], start)?;
        let first_end = checked_offset_i64(offsets[start + 1], start + 1)?;
        let dim = first_end.checked_sub(next_start).ok_or_else(|| {
            fmt!(
                ArrowIngest,
                "ARRAY LargeList inner offsets non-monotonic at row {}",
                start
            )
        })?;
        let next_end = checked_offset_i64(offsets[end], end)?;
        if next_end.checked_sub(next_start) != dim.checked_mul(end - start) {
            return Err(ragged_inner_error_i64(&offsets[..], start, end, dim));
        }
        Ok((next_start, next_end, dim, la.values().clone()))
    } else if let Some(la) = arr.as_any().downcast_ref::<FixedSizeListArray>() {
        let stride = la.value_length() as usize;
        if end <= start {
            return Ok((0, 0, 0, la.values().clone()));
        }
        let next_start = start.checked_mul(stride).ok_or_else(|| {
            fmt!(
                ArrowIngest,
                "ARRAY FixedSizeList descent start {} * stride {} overflows usize",
                start,
                stride
            )
        })?;
        let next_end = end.checked_mul(stride).ok_or_else(|| {
            fmt!(
                ArrowIngest,
                "ARRAY FixedSizeList descent end {} * stride {} overflows usize",
                end,
                stride
            )
        })?;
        Ok((next_start, next_end, stride, la.values().clone()))
    } else {
        Err(fmt!(
            ArrowIngest,
            "expected List / LargeList / FixedSizeList in ARRAY descent, got {:?}",
            arr.data_type()
        ))
    }
}

fn geohash_on_unsigned_error(field: &arrow_schema::Field, dtype_name: &str) -> Error {
    fmt!(
        ArrowIngest,
        "column '{}': 'questdb.geohash_bits' metadata is not supported on {} columns; use a signed integer type (Int8/Int16/Int32/Int64)",
        field.name(),
        dtype_name
    )
}

#[cold]
#[inline(never)]
fn ragged_inner_error_i32(offsets: &[i32], start: usize, end: usize, dim: usize) -> Error {
    for i in start..end {
        let sz = (offsets[i + 1] - offsets[i]) as usize;
        if sz != dim {
            return fmt!(
                ArrowIngest,
                "ARRAY row has ragged inner-list sizes: inner #{} has size {} but row's first inner is {}; N-dim ARRAY ingest requires uniform inner sizes per row",
                i - start,
                sz,
                dim
            );
        }
    }
    fmt!(
        ArrowIngest,
        "ARRAY row has ragged inner-list sizes (unable to locate offending inner)"
    )
}

#[cold]
#[inline(never)]
fn ragged_inner_error_i64(offsets: &[i64], start: usize, end: usize, dim: usize) -> Error {
    for i in start..end {
        let sz = (offsets[i + 1] - offsets[i]) as usize;
        if sz != dim {
            return fmt!(
                ArrowIngest,
                "ARRAY row has ragged inner-list sizes: inner #{} has size {} but row's first inner is {}; N-dim ARRAY ingest requires uniform inner sizes per row",
                i - start,
                sz,
                dim
            );
        }
    }
    fmt!(
        ArrowIngest,
        "ARRAY row has ragged inner-list sizes (unable to locate offending inner)"
    )
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DictKey {
    U8,
    U16,
    U32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DictValue {
    Utf8,
    LargeUtf8,
    Utf8View,
}

#[derive(Debug, Clone, Copy)]
enum ColumnKind {
    Bool,
    I8,
    I16,
    I32,
    I64,
    F16ToF32,
    F32,
    F64,
    Char,
    Ipv4,
    U8WidenToI32,
    U16WidenToI32,
    U32WidenToI64,
    U64WidenToI64Checked,
    TimestampSecondToMicros,
    TimestampMicros,
    TimestampNanos,
    Date,
    Date32Days,
    Date64Ms,
    TimeAsLong(TimeUnit),
    DurationAsLong(TimeUnit),
    Utf8,
    LargeUtf8,
    Utf8View,
    Binary,
    LargeBinary,
    BinaryView,
    Uuid,
    Long256,
    Geohash(u8),
    SymbolDict { key: DictKey, value: DictValue },
    Decimal32WidenToDecimal64,
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
    let md_geo_bits = field
        .metadata()
        .get(crate::egress::arrow::metadata::GEOHASH_BITS)
        .and_then(|s| s.parse::<u8>().ok());
    let check_geohash_width = |bits: u8, max_bits: u8, dtype_name: &str| -> Result<u8> {
        if bits == 0 || bits > max_bits {
            return Err(fmt!(
                ArrowIngest,
                "geohash precision_bits {} out of range for {} column (must be 1..={})",
                bits,
                dtype_name,
                max_bits
            ));
        }
        Ok(bits)
    };
    Ok(match (field.data_type(), md_type, md_ext) {
        (DataType::Boolean, _, _) => ColumnKind::Bool,
        (DataType::Int8, Some("byte"), _) => ColumnKind::I8,
        (DataType::Int8, Some(name), _) if name.starts_with("geohash") => {
            let bits = md_geo_bits.ok_or_else(|| {
                fmt!(
                    ArrowIngest,
                    "column '{}' has column_type='{}' but missing or invalid 'questdb.geohash_bits' metadata (1..=60 expected)",
                    field.name(),
                    name
                )
            })?;
            ColumnKind::Geohash(check_geohash_width(bits, 8, "Int8")?)
        }
        (DataType::Int8, _, _) if md_geo_bits.is_some() => {
            ColumnKind::Geohash(check_geohash_width(md_geo_bits.unwrap(), 8, "Int8")?)
        }
        (DataType::Int8, _, _) => ColumnKind::I8,
        (DataType::Int16, _, _) if md_geo_bits.is_some() => {
            ColumnKind::Geohash(check_geohash_width(md_geo_bits.unwrap(), 16, "Int16")?)
        }
        (DataType::Int16, _, _) => ColumnKind::I16,
        (DataType::Int32, _, _) if md_geo_bits.is_some() => {
            ColumnKind::Geohash(check_geohash_width(md_geo_bits.unwrap(), 32, "Int32")?)
        }
        (DataType::Int32, _, _) => ColumnKind::I32,
        (DataType::Int64, _, _) if md_geo_bits.is_some() => {
            ColumnKind::Geohash(check_geohash_width(md_geo_bits.unwrap(), 60, "Int64")?)
        }
        (DataType::Int64, _, _) => ColumnKind::I64,
        (DataType::Float16, _, _) => ColumnKind::F16ToF32,
        (DataType::Float32, _, _) => ColumnKind::F32,
        (DataType::Float64, _, _) => ColumnKind::F64,
        (DataType::UInt8, _, _) if md_geo_bits.is_some() => {
            return Err(geohash_on_unsigned_error(field, "UInt8"));
        }
        (DataType::UInt8, _, _) => ColumnKind::U8WidenToI32,
        (DataType::UInt16, _, _) if md_geo_bits.is_some() => {
            return Err(geohash_on_unsigned_error(field, "UInt16"));
        }
        (DataType::UInt16, Some("char"), _) => ColumnKind::Char,
        (DataType::UInt16, _, _) => ColumnKind::U16WidenToI32,
        (DataType::UInt32, _, _) if md_geo_bits.is_some() => {
            return Err(geohash_on_unsigned_error(field, "UInt32"));
        }
        (DataType::UInt32, Some("ipv4"), _) => ColumnKind::Ipv4,
        (DataType::UInt32, _, _) => ColumnKind::U32WidenToI64,
        (DataType::UInt64, _, _) if md_geo_bits.is_some() => {
            return Err(geohash_on_unsigned_error(field, "UInt64"));
        }
        (DataType::UInt64, _, _) => ColumnKind::U64WidenToI64Checked,
        (DataType::Timestamp(TimeUnit::Second, _), _, _) => ColumnKind::TimestampSecondToMicros,
        (DataType::Timestamp(TimeUnit::Microsecond, _), _, _) => ColumnKind::TimestampMicros,
        (DataType::Timestamp(TimeUnit::Nanosecond, _), _, _) => ColumnKind::TimestampNanos,
        (DataType::Timestamp(TimeUnit::Millisecond, _), _, _) => ColumnKind::Date,
        (DataType::Date32, _, _) => ColumnKind::Date32Days,
        (DataType::Date64, _, _) => ColumnKind::Date64Ms,
        (DataType::Time32(unit), _, _) => ColumnKind::TimeAsLong(*unit),
        (DataType::Time64(unit), _, _) => ColumnKind::TimeAsLong(*unit),
        (DataType::Duration(unit), _, _) => ColumnKind::DurationAsLong(*unit),
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
            if dict_key_for(key).is_some() && dict_value_for(value).is_some() =>
        {
            let k = dict_key_for(key).unwrap();
            let v = dict_value_for(value).unwrap();
            ColumnKind::SymbolDict { key: k, value: v }
        }
        (DataType::Decimal32(_, _), _, _) => ColumnKind::Decimal32WidenToDecimal64,
        (DataType::Decimal64(_, _), _, _) => ColumnKind::Decimal64,
        (DataType::Decimal128(_, _), _, _) => ColumnKind::Decimal128,
        (DataType::Decimal256(_, _), _, _) => ColumnKind::Decimal256,
        (DataType::List(_) | DataType::LargeList(_) | DataType::FixedSizeList(_, _), _, _) => {
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
        BinaryBuilder, Decimal64Builder, Decimal128Builder, FixedSizeBinaryBuilder, Float64Builder,
        Int8Builder, Int16Builder, Int32Builder, Int64Builder, ListBuilder, StringBuilder,
        StringDictionaryBuilder, TimestampMicrosecondBuilder, TimestampMillisecondBuilder,
        TimestampNanosecondBuilder, UInt16Builder, UInt32Builder,
    };
    use arrow_array::types::UInt32Type;
    use arrow_array::{ArrayRef, RecordBatch};
    use arrow_schema::{DataType, Field, IntervalUnit, Schema as ArrowSchema, TimeUnit};

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
        buf.append_arrow(table("t"), &rb).unwrap();
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
        buf.append_arrow(table("t"), &rb).unwrap();
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
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 1);
    }

    #[test]
    fn utf8_and_binary_append() {
        let mut s = StringBuilder::new();
        s.append_value("hello");
        s.append_value("");
        s.append_value("yo");
        let mut bin = BinaryBuilder::new();
        bin.append_value([1u8, 2, 3]);
        bin.append_value([]);
        bin.append_value([0xFFu8]);
        let cols: Vec<ArrayRef> = vec![Arc::new(s.finish()), Arc::new(bin.finish())];
        let schema = Arc::new(ArrowSchema::new(vec![
            Field::new("name", DataType::Utf8, true),
            Field::new("blob", DataType::Binary, true),
        ]));
        let rb = RecordBatch::try_new(schema, cols).unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb).unwrap();
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
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 1);
    }

    #[test]
    fn uuid_without_metadata_rejected() {
        let mut b = FixedSizeBinaryBuilder::new(16);
        b.append_value([0u8; 16]).unwrap();
        let schema = arrow_schema_with(Field::new("id", DataType::FixedSizeBinary(16), true));
        let rb = RecordBatch::try_new(schema, vec![Arc::new(b.finish()) as ArrayRef]).unwrap();
        let mut buf = fresh_buffer();
        let err = buf.append_arrow(table("t"), &rb).unwrap_err();
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
        buf.append_arrow(table("t"), &rb).unwrap();
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
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 3);
    }

    #[test]
    fn dictionary_without_metadata_routes_to_symbol() {
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
        buf.append_arrow(table("t"), &rb).unwrap();
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
        buf.append_arrow(table("t"), &rb).unwrap();
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
        buf.append_arrow(table("t"), &rb).unwrap();
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
        buf.append_arrow(table("t"), &rb).unwrap();
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
        buf.append_arrow_at_column(table("t"), &rb, ts_col).unwrap();
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
            .append_arrow_at_column(table("t"), &rb, missing)
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
            .append_arrow_at_column(table("t"), &rb, v_col)
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
        buf.append_arrow(table("t"), &rb).unwrap();
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
        let err = buf.append_arrow(table("t"), &rb).unwrap_err();
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
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 0);
    }

    #[test]
    fn ilp_buffer_rejects_append_arrow() {
        let mut v = Int64Builder::new();
        v.append_value(1);
        let schema = arrow_schema_with(Field::new("v", DataType::Int64, false));
        let rb = RecordBatch::try_new(schema, vec![Arc::new(v.finish()) as ArrayRef]).unwrap();
        let mut buf = Buffer::new(crate::ingress::ProtocolVersion::V2);
        let err = buf.append_arrow(table("t"), &rb).unwrap_err();
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
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 3);
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
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 3);
    }

    #[test]
    fn timestamp_arrow_encodes_nulls_via_bitmap() {
        let mut b = TimestampMicrosecondBuilder::new();
        b.append_value(1_700_000_000_000_000);
        b.append_null();
        b.append_value(1_700_000_000_000_100);
        let field = Field::new("ts", DataType::Timestamp(TimeUnit::Microsecond, None), true);
        let schema = arrow_schema_with(field);
        let rb = RecordBatch::try_new(schema, vec![Arc::new(b.finish()) as ArrayRef]).unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 3);
    }

    #[test]
    fn varchar_arrow_encodes_null_rows() {
        let mut b = StringBuilder::new();
        b.append_value("hello");
        b.append_null();
        b.append_value("world");
        let schema = arrow_schema_with(Field::new("v", DataType::Utf8, true));
        let rb = RecordBatch::try_new(schema, vec![Arc::new(b.finish()) as ArrayRef]).unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 3);
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
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 5);
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
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 3);
    }

    #[test]
    fn geohash_arrow_encodes_null_rows_via_bitmap() {
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
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 3);
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
        buf.append_arrow(table("t"), &rb).unwrap();
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
            buf.append_arrow(table("t"), &rb).unwrap();
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
        buf.append_arrow(table("t"), &rb).unwrap();
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
            .append_arrow_at_column(table("t"), &rb, ts_name)
            .unwrap_err();
        assert_eq!(err.code(), crate::error::ErrorCode::ArrowIngest);
    }

    #[test]
    fn uint8_widens_to_int_appends() {
        use arrow_array::builder::UInt8Builder;
        let mut u = UInt8Builder::new();
        u.append_value(0);
        u.append_value(0xFF);
        u.append_null();
        let rb = RecordBatch::try_new(
            arrow_schema_with(Field::new("v", DataType::UInt8, true)),
            vec![Arc::new(u.finish()) as ArrayRef],
        )
        .unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 3);
    }

    #[test]
    fn uint64_within_i64_range_appends() {
        use arrow_array::builder::UInt64Builder;
        let mut u = UInt64Builder::new();
        u.append_value(0);
        u.append_value(i64::MAX as u64);
        u.append_value(42);
        let rb = RecordBatch::try_new(
            arrow_schema_with(Field::new("v", DataType::UInt64, true)),
            vec![Arc::new(u.finish()) as ArrayRef],
        )
        .unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 3);
    }

    #[test]
    fn uint64_above_i64_max_is_rejected() {
        use arrow_array::builder::UInt64Builder;
        let mut u = UInt64Builder::new();
        u.append_value(0);
        u.append_value(1u64 << 63);
        let rb = RecordBatch::try_new(
            arrow_schema_with(Field::new("v", DataType::UInt64, true)),
            vec![Arc::new(u.finish()) as ArrayRef],
        )
        .unwrap();
        let mut buf = fresh_buffer();
        let err = buf.append_arrow(table("t"), &rb).unwrap_err();
        assert_eq!(err.code(), crate::error::ErrorCode::ArrowIngest);
        assert!(err.msg().contains("UInt64 value"));
    }

    #[test]
    fn uint64_max_value_is_rejected() {
        use arrow_array::builder::UInt64Builder;
        let mut u = UInt64Builder::new();
        u.append_value(u64::MAX);
        let rb = RecordBatch::try_new(
            arrow_schema_with(Field::new("v", DataType::UInt64, true)),
            vec![Arc::new(u.finish()) as ArrayRef],
        )
        .unwrap();
        let mut buf = fresh_buffer();
        let err = buf.append_arrow(table("t"), &rb).unwrap_err();
        assert_eq!(err.code(), crate::error::ErrorCode::ArrowIngest);
    }

    #[test]
    fn date32_days_appends_as_date_ms() {
        use arrow_array::builder::Date32Builder;
        let mut d = Date32Builder::new();
        d.append_value(0);
        d.append_value(19_675);
        d.append_null();
        let rb = RecordBatch::try_new(
            arrow_schema_with(Field::new("d", DataType::Date32, true)),
            vec![Arc::new(d.finish()) as ArrayRef],
        )
        .unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 3);
    }

    #[test]
    fn time32_seconds_appends() {
        use arrow_array::builder::Time32SecondBuilder;
        let mut t = Time32SecondBuilder::new();
        t.append_value(0);
        t.append_value(86_399);
        let rb = RecordBatch::try_new(
            arrow_schema_with(Field::new("t", DataType::Time32(TimeUnit::Second), true)),
            vec![Arc::new(t.finish()) as ArrayRef],
        )
        .unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 2);
    }

    #[test]
    fn time64_nanoseconds_appends() {
        use arrow_array::builder::Time64NanosecondBuilder;
        let mut t = Time64NanosecondBuilder::new();
        t.append_value(0);
        t.append_value(86_399 * 1_000_000_000);
        let rb = RecordBatch::try_new(
            arrow_schema_with(Field::new(
                "t",
                DataType::Time64(TimeUnit::Nanosecond),
                true,
            )),
            vec![Arc::new(t.finish()) as ArrayRef],
        )
        .unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 2);
    }

    #[test]
    fn duration_microseconds_appends() {
        use arrow_array::builder::DurationMicrosecondBuilder;
        let mut d = DurationMicrosecondBuilder::new();
        d.append_value(1_000_000);
        d.append_value(-1);
        d.append_null();
        let rb = RecordBatch::try_new(
            arrow_schema_with(Field::new(
                "d",
                DataType::Duration(TimeUnit::Microsecond),
                true,
            )),
            vec![Arc::new(d.finish()) as ArrayRef],
        )
        .unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 3);
    }

    #[test]
    fn dict_u32_large_utf8_routes_to_symbol() {
        use arrow_array::DictionaryArray;
        use arrow_array::types::UInt32Type;
        let dict = DictionaryArray::<UInt32Type>::from_iter(
            ["AAPL", "MSFT", "AAPL"].into_iter().map(Some),
        );
        let large_values = LargeStringArray::from(vec!["AAPL", "MSFT"]);
        let dict =
            DictionaryArray::<UInt32Type>::try_new(dict.keys().clone(), Arc::new(large_values))
                .unwrap();
        let field = Field::new(
            "s",
            DataType::Dictionary(Box::new(DataType::UInt32), Box::new(DataType::LargeUtf8)),
            true,
        );
        let rb = RecordBatch::try_new(arrow_schema_with(field), vec![Arc::new(dict) as ArrayRef])
            .unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 3);
    }

    #[test]
    fn dict_u8_utf8_routes_to_symbol() {
        use arrow_array::DictionaryArray;
        use arrow_array::types::UInt8Type;
        let dict = DictionaryArray::<UInt8Type>::from_iter(
            ["red", "green", "blue", "red"].into_iter().map(Some),
        );
        let field = Field::new(
            "s",
            DataType::Dictionary(Box::new(DataType::UInt8), Box::new(DataType::Utf8)),
            true,
        );
        let rb = RecordBatch::try_new(arrow_schema_with(field), vec![Arc::new(dict) as ArrayRef])
            .unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 4);
    }

    #[test]
    fn dict_u32_utf8_view_routes_to_symbol() {
        // polars 0.53 emits Categorical as Dictionary(UInt32, Utf8View).
        use arrow_array::DictionaryArray;
        use arrow_array::types::UInt32Type;
        let dict = DictionaryArray::<UInt32Type>::from_iter(
            ["AAPL", "MSFT", "AAPL"].into_iter().map(Some),
        );
        let view_values = StringViewArray::from(vec!["AAPL", "MSFT"]);
        let dict =
            DictionaryArray::<UInt32Type>::try_new(dict.keys().clone(), Arc::new(view_values))
                .unwrap();
        let field = Field::new(
            "s",
            DataType::Dictionary(Box::new(DataType::UInt32), Box::new(DataType::Utf8View)),
            true,
        );
        let rb = RecordBatch::try_new(arrow_schema_with(field), vec![Arc::new(dict) as ArrayRef])
            .unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 3);
    }

    #[test]
    fn large_utf8_no_null_takes_bulk_memcpy_path() {
        let a = LargeStringArray::from(vec!["AAPL", "MSFT", "GOOG"]);
        let b = LargeStringArray::from(vec!["alpha", "beta", "gamma"]);
        let rb = RecordBatch::try_new(
            Arc::new(ArrowSchema::new(vec![
                Field::new("a", DataType::LargeUtf8, true),
                Field::new("b", DataType::LargeUtf8, true),
            ])),
            vec![Arc::new(a) as ArrayRef, Arc::new(b) as ArrayRef],
        )
        .unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 3);
    }

    #[test]
    fn large_binary_no_null_takes_bulk_memcpy_path() {
        let rows: Vec<&[u8]> = vec![b"\x00\x01", b"\xff", b"\x02\x03\x04"];
        let a = LargeBinaryArray::from_iter_values(rows);
        let rb = RecordBatch::try_new(
            arrow_schema_with(Field::new("a", DataType::LargeBinary, true)),
            vec![Arc::new(a) as ArrayRef],
        )
        .unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 3);
    }

    #[test]
    fn large_utf8_with_nulls_still_works_via_slow_path() {
        let a = LargeStringArray::from(vec![Some("x"), None, Some("yz")]);
        let rb = RecordBatch::try_new(
            arrow_schema_with(Field::new("a", DataType::LargeUtf8, true)),
            vec![Arc::new(a) as ArrayRef],
        )
        .unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 3);
    }

    #[test]
    fn fixed_size_list_float64_appends_as_array_1d() {
        use arrow_array::builder::FixedSizeListBuilder;
        let mut b = FixedSizeListBuilder::new(Float64Builder::new(), 3);
        b.values().append_value(1.0);
        b.values().append_value(2.0);
        b.values().append_value(3.0);
        b.append(true);
        b.values().append_value(4.0);
        b.values().append_value(5.0);
        b.values().append_value(6.0);
        b.append(true);
        let arr = b.finish();
        let rb = RecordBatch::try_new(
            arrow_schema_with(Field::new("a", arr.data_type().clone(), true)),
            vec![Arc::new(arr) as ArrayRef],
        )
        .unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 2);
    }

    #[test]
    fn time32_milliseconds_appends() {
        use arrow_array::builder::Time32MillisecondBuilder;
        let mut t = Time32MillisecondBuilder::new();
        t.append_value(0);
        t.append_value(86_399_999);
        t.append_null();
        let rb = RecordBatch::try_new(
            arrow_schema_with(Field::new(
                "t",
                DataType::Time32(TimeUnit::Millisecond),
                true,
            )),
            vec![Arc::new(t.finish()) as ArrayRef],
        )
        .unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 3);
    }

    #[test]
    fn time64_microseconds_appends() {
        use arrow_array::builder::Time64MicrosecondBuilder;
        let mut t = Time64MicrosecondBuilder::new();
        t.append_value(0);
        t.append_value(86_399_999_999);
        let rb = RecordBatch::try_new(
            arrow_schema_with(Field::new(
                "t",
                DataType::Time64(TimeUnit::Microsecond),
                true,
            )),
            vec![Arc::new(t.finish()) as ArrayRef],
        )
        .unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 2);
    }

    #[test]
    fn duration_seconds_appends() {
        use arrow_array::builder::DurationSecondBuilder;
        let mut d = DurationSecondBuilder::new();
        d.append_value(0);
        d.append_value(-3600);
        d.append_value(86_400);
        let rb = RecordBatch::try_new(
            arrow_schema_with(Field::new("d", DataType::Duration(TimeUnit::Second), true)),
            vec![Arc::new(d.finish()) as ArrayRef],
        )
        .unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 3);
    }

    #[test]
    fn duration_milliseconds_appends() {
        use arrow_array::builder::DurationMillisecondBuilder;
        let mut d = DurationMillisecondBuilder::new();
        d.append_value(1_500);
        d.append_value(0);
        let rb = RecordBatch::try_new(
            arrow_schema_with(Field::new(
                "d",
                DataType::Duration(TimeUnit::Millisecond),
                true,
            )),
            vec![Arc::new(d.finish()) as ArrayRef],
        )
        .unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 2);
    }

    #[test]
    fn duration_nanoseconds_appends() {
        use arrow_array::builder::DurationNanosecondBuilder;
        let mut d = DurationNanosecondBuilder::new();
        d.append_value(0);
        d.append_value(1_500_000_000);
        let rb = RecordBatch::try_new(
            arrow_schema_with(Field::new(
                "d",
                DataType::Duration(TimeUnit::Nanosecond),
                true,
            )),
            vec![Arc::new(d.finish()) as ArrayRef],
        )
        .unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 2);
    }

    #[test]
    fn dict_u16_utf8_routes_to_symbol() {
        use arrow_array::DictionaryArray;
        use arrow_array::types::UInt16Type;
        let dict =
            DictionaryArray::<UInt16Type>::from_iter(["x", "y", "x", "z"].into_iter().map(Some));
        let field = Field::new(
            "s",
            DataType::Dictionary(Box::new(DataType::UInt16), Box::new(DataType::Utf8)),
            true,
        );
        let rb = RecordBatch::try_new(arrow_schema_with(field), vec![Arc::new(dict) as ArrayRef])
            .unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 4);
    }

    #[test]
    fn dict_u8_large_utf8_routes_to_symbol() {
        use arrow_array::DictionaryArray;
        use arrow_array::types::UInt8Type;
        let keys = arrow_array::UInt8Array::from(vec![0u8, 1, 0, 1]);
        let values = LargeStringArray::from(vec!["alpha", "beta"]);
        let dict = DictionaryArray::<UInt8Type>::try_new(keys, Arc::new(values)).unwrap();
        let field = Field::new(
            "s",
            DataType::Dictionary(Box::new(DataType::UInt8), Box::new(DataType::LargeUtf8)),
            true,
        );
        let rb = RecordBatch::try_new(arrow_schema_with(field), vec![Arc::new(dict) as ArrayRef])
            .unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 4);
    }

    #[test]
    fn symbol_dict_with_metadata_still_routes_to_symbol() {
        use arrow_array::DictionaryArray;
        use arrow_array::types::UInt32Type;
        let dict = DictionaryArray::<UInt32Type>::from_iter(["A", "B", "A"].into_iter().map(Some));
        let field = Field::new(
            "s",
            DataType::Dictionary(Box::new(DataType::UInt32), Box::new(DataType::Utf8)),
            true,
        )
        .with_metadata(
            [(
                crate::egress::arrow::metadata::SYMBOL.to_string(),
                "true".to_string(),
            )]
            .into_iter()
            .collect(),
        );
        let rb = RecordBatch::try_new(arrow_schema_with(field), vec![Arc::new(dict) as ArrayRef])
            .unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 3);
    }

    #[test]
    fn date32_all_null_appends() {
        use arrow_array::builder::Date32Builder;
        let mut d = Date32Builder::new();
        d.append_null();
        d.append_null();
        let rb = RecordBatch::try_new(
            arrow_schema_with(Field::new("d", DataType::Date32, true)),
            vec![Arc::new(d.finish()) as ArrayRef],
        )
        .unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 2);
    }

    #[test]
    fn time64_ns_all_null_appends() {
        use arrow_array::builder::Time64NanosecondBuilder;
        let mut t = Time64NanosecondBuilder::new();
        t.append_null();
        t.append_null();
        t.append_null();
        let rb = RecordBatch::try_new(
            arrow_schema_with(Field::new(
                "t",
                DataType::Time64(TimeUnit::Nanosecond),
                true,
            )),
            vec![Arc::new(t.finish()) as ArrayRef],
        )
        .unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 3);
    }

    #[test]
    fn nested_list_ragged_inner_within_row_errors() {
        use arrow_array::builder::ListBuilder;
        let mut outer = ListBuilder::new(ListBuilder::new(Float64Builder::new()));
        outer.values().values().append_value(1.0);
        outer.values().values().append_value(2.0);
        outer.values().append(true);
        outer.values().values().append_value(3.0);
        outer.values().append(true);
        outer.append(true);
        let arr = outer.finish();
        let rb = RecordBatch::try_new(
            arrow_schema_with(Field::new("a", arr.data_type().clone(), true)),
            vec![Arc::new(arr) as ArrayRef],
        )
        .unwrap();
        let mut buf = fresh_buffer();
        let err = buf.append_arrow(table("t"), &rb).unwrap_err();
        assert_eq!(err.code(), crate::error::ErrorCode::ArrowIngest);
        assert!(
            format!("{err}").contains("ragged inner-list sizes"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn large_list_nested_float64_appends_as_array_2d() {
        use arrow_array::builder::LargeListBuilder;
        let mut outer = LargeListBuilder::new(LargeListBuilder::new(Float64Builder::new()));
        for v in [1.0, 2.0] {
            outer.values().values().append_value(v);
        }
        outer.values().append(true);
        for v in [3.0, 4.0] {
            outer.values().values().append_value(v);
        }
        outer.values().append(true);
        outer.append(true);
        for v in [5.0, 6.0, 7.0] {
            outer.values().values().append_value(v);
        }
        outer.values().append(true);
        for v in [8.0, 9.0, 10.0] {
            outer.values().values().append_value(v);
        }
        outer.values().append(true);
        outer.append(true);
        let arr = outer.finish();
        let rb = RecordBatch::try_new(
            arrow_schema_with(Field::new("a", arr.data_type().clone(), true)),
            vec![Arc::new(arr) as ArrayRef],
        )
        .unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 2);
    }

    #[test]
    fn float16_appends_as_double() {
        use arrow_array::builder::Float16Builder;
        use half::f16;
        let mut b = Float16Builder::new();
        b.append_value(f16::from_f32(1.5));
        b.append_value(f16::from_f32(-2.5));
        b.append_null();
        let rb = RecordBatch::try_new(
            arrow_schema_with(Field::new("h", DataType::Float16, true)),
            vec![Arc::new(b.finish()) as ArrayRef],
        )
        .unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 3);
    }

    #[test]
    fn date64_ms_appends_as_date() {
        use arrow_array::builder::Date64Builder;
        let mut d = Date64Builder::new();
        d.append_value(0);
        d.append_value(1_700_000_000_000);
        d.append_null();
        let rb = RecordBatch::try_new(
            arrow_schema_with(Field::new("d", DataType::Date64, true)),
            vec![Arc::new(d.finish()) as ArrayRef],
        )
        .unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 3);
    }

    #[test]
    fn timestamp_second_widens_to_micros() {
        use arrow_array::builder::TimestampSecondBuilder;
        let mut ts = TimestampSecondBuilder::new();
        ts.append_value(1_700_000_000);
        ts.append_value(0);
        ts.append_null();
        let rb = RecordBatch::try_new(
            arrow_schema_with(Field::new(
                "ts",
                DataType::Timestamp(TimeUnit::Second, None),
                true,
            )),
            vec![Arc::new(ts.finish()) as ArrayRef],
        )
        .unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 3);
    }

    #[test]
    fn decimal32_widens_to_decimal64() {
        use arrow_array::builder::Decimal32Builder;
        let mut b = Decimal32Builder::new();
        b.append_value(12345);
        b.append_value(-678);
        b.append_null();
        let arr = b.finish().with_precision_and_scale(9, 2).unwrap();
        let schema = arrow_schema_with(Field::new("d", DataType::Decimal32(9, 2), true));
        let rb = RecordBatch::try_new(schema, vec![Arc::new(arr) as ArrayRef]).unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 3);
    }

    #[test]
    fn decimal32_negative_scale_errors() {
        use arrow_array::builder::Decimal32Builder;
        let mut b = Decimal32Builder::new();
        b.append_value(1);
        let arr = b.finish().with_precision_and_scale(9, -2).unwrap();
        let schema = arrow_schema_with(Field::new("d", DataType::Decimal32(9, -2), true));
        let rb = RecordBatch::try_new(schema, vec![Arc::new(arr) as ArrayRef]).unwrap();
        let mut buf = fresh_buffer();
        let err = buf.append_arrow(table("t"), &rb).unwrap_err();
        assert_eq!(err.code(), crate::error::ErrorCode::ArrowIngest);
    }

    #[test]
    fn decimal_scale_u8_enforces_per_width_caps() {
        assert!(decimal_scale_u8(9, "Decimal32", 9).is_ok());
        let err = decimal_scale_u8(10, "Decimal32", 9).unwrap_err();
        assert_eq!(err.code(), crate::error::ErrorCode::ArrowIngest);
        assert!(err.msg().contains("Decimal32"));
        assert!(err.msg().contains("scale 10"));

        assert!(decimal_scale_u8(18, "Decimal64", 18).is_ok());
        assert!(decimal_scale_u8(19, "Decimal64", 18).is_err());

        assert!(decimal_scale_u8(38, "Decimal128", 38).is_ok());
        assert!(decimal_scale_u8(39, "Decimal128", 38).is_err());

        assert!(
            decimal_scale_u8(
                QWP_DECIMAL_MAX_SCALE as i8,
                "Decimal256",
                QWP_DECIMAL_MAX_SCALE
            )
            .is_ok()
        );
        assert!(
            decimal_scale_u8(
                (QWP_DECIMAL_MAX_SCALE as i8).saturating_add(1),
                "Decimal256",
                QWP_DECIMAL_MAX_SCALE,
            )
            .is_err()
        );

        let err = decimal_scale_u8(-1, "Decimal64", 18).unwrap_err();
        assert_eq!(err.code(), crate::error::ErrorCode::ArrowIngest);
        assert!(err.msg().contains("negative"));
    }

    fn assert_unsupported_column(field: Field, arr: ArrayRef) {
        let rb = RecordBatch::try_new(arrow_schema_with(field), vec![arr]).unwrap();
        let mut buf = fresh_buffer();
        let err = buf.append_arrow(table("t"), &rb).unwrap_err();
        assert_eq!(
            err.code(),
            crate::error::ErrorCode::ArrowUnsupportedColumnKind,
            "expected ArrowUnsupportedColumnKind, got: {err}"
        );
    }

    #[test]
    fn interval_year_month_rejected_as_unsupported() {
        use arrow_array::builder::IntervalYearMonthBuilder;
        let mut b = IntervalYearMonthBuilder::new();
        b.append_value(12);
        assert_unsupported_column(
            Field::new("c", DataType::Interval(IntervalUnit::YearMonth), true),
            Arc::new(b.finish()) as ArrayRef,
        );
    }

    #[test]
    fn interval_day_time_rejected_as_unsupported() {
        use arrow_array::builder::IntervalDayTimeBuilder;
        use arrow_array::types::IntervalDayTime;
        let mut b = IntervalDayTimeBuilder::new();
        b.append_value(IntervalDayTime::new(1, 0));
        assert_unsupported_column(
            Field::new("c", DataType::Interval(IntervalUnit::DayTime), true),
            Arc::new(b.finish()) as ArrayRef,
        );
    }

    #[test]
    fn interval_month_day_nano_rejected_as_unsupported() {
        use arrow_array::builder::IntervalMonthDayNanoBuilder;
        use arrow_array::types::IntervalMonthDayNano;
        let mut b = IntervalMonthDayNanoBuilder::new();
        b.append_value(IntervalMonthDayNano::new(1, 1, 1));
        assert_unsupported_column(
            Field::new("c", DataType::Interval(IntervalUnit::MonthDayNano), true),
            Arc::new(b.finish()) as ArrayRef,
        );
    }

    #[test]
    fn fixed_size_binary_non_uuid_rejected_as_unsupported() {
        let mut b = FixedSizeBinaryBuilder::new(16);
        b.append_value([0u8; 16]).unwrap();
        let arr = b.finish();
        assert_unsupported_column(
            Field::new("c", DataType::FixedSizeBinary(16), true),
            Arc::new(arr) as ArrayRef,
        );
    }

    #[test]
    fn fixed_size_binary_arbitrary_width_rejected_as_unsupported() {
        let mut b = FixedSizeBinaryBuilder::new(8);
        b.append_value([0u8; 8]).unwrap();
        assert_unsupported_column(
            Field::new("c", DataType::FixedSizeBinary(8), true),
            Arc::new(b.finish()) as ArrayRef,
        );
    }

    #[test]
    fn null_column_rejected_as_unsupported() {
        use arrow_array::NullArray;
        let arr = NullArray::new(3);
        assert_unsupported_column(
            Field::new("c", DataType::Null, true),
            Arc::new(arr) as ArrayRef,
        );
    }

    #[test]
    fn struct_column_rejected_as_unsupported() {
        use arrow_array::StructArray;
        let mut inner = Int32Builder::new();
        inner.append_value(1);
        let inner_arr = Arc::new(inner.finish()) as ArrayRef;
        let inner_field = Arc::new(Field::new("v", DataType::Int32, true));
        let arr = StructArray::from(vec![(inner_field.clone(), inner_arr)]);
        assert_unsupported_column(
            Field::new("c", DataType::Struct(vec![inner_field].into()), true),
            Arc::new(arr) as ArrayRef,
        );
    }

    #[test]
    fn map_column_rejected_as_unsupported() {
        use arrow_array::builder::{MapBuilder, StringBuilder};
        let mut b = MapBuilder::new(None, StringBuilder::new(), Int32Builder::new());
        b.keys().append_value("k");
        b.values().append_value(1);
        b.append(true).unwrap();
        let arr = b.finish();
        let dtype = arr.data_type().clone();
        assert_unsupported_column(Field::new("c", dtype, true), Arc::new(arr) as ArrayRef);
    }

    #[test]
    fn run_end_encoded_column_rejected_as_unsupported() {
        use arrow_array::builder::PrimitiveRunBuilder;
        use arrow_array::types::{Int32Type, Int64Type};
        let mut b = PrimitiveRunBuilder::<Int32Type, Int64Type>::new();
        b.append_value(42);
        b.append_value(42);
        b.append_value(7);
        let arr = b.finish();
        let dtype = arr.data_type().clone();
        assert_unsupported_column(Field::new("c", dtype, true), Arc::new(arr) as ArrayRef);
    }

    #[test]
    fn referenced_null_dict_entry_rejected_for_symbol() {
        use arrow_array::DictionaryArray;
        use arrow_array::types::UInt32Type;
        let mut vb = StringBuilder::new();
        vb.append_value("a");
        vb.append_null();
        vb.append_value("c");
        let values = vb.finish();
        let keys = arrow_array::UInt32Array::from(vec![0u32, 1, 2]);
        let dict =
            DictionaryArray::<UInt32Type>::try_new(keys, Arc::new(values) as ArrayRef).unwrap();
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
        let rb = RecordBatch::try_new(schema, vec![Arc::new(dict) as ArrayRef]).unwrap();
        let mut buf = fresh_buffer();
        let err = buf.append_arrow(table("t"), &rb).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ArrowIngest);
        assert!(
            err.msg().contains("dictionary values"),
            "unexpected error message: {}",
            err.msg()
        );
        assert_eq!(buf.row_count(), 0, "buffer should roll back to 0 rows");
    }

    #[test]
    fn referenced_null_dict_entry_rejected() {
        use arrow_array::DictionaryArray;
        use arrow_array::types::UInt32Type;
        let mut vb = StringBuilder::new();
        vb.append_value("a");
        vb.append_null();
        let values = vb.finish();
        let keys = arrow_array::UInt32Array::from(vec![0u32, 1]);
        let dict =
            DictionaryArray::<UInt32Type>::try_new(keys, Arc::new(values) as ArrayRef).unwrap();
        let field = Field::new(
            "v",
            DataType::Dictionary(Box::new(DataType::UInt32), Box::new(DataType::Utf8)),
            true,
        );
        let schema = arrow_schema_with(field);
        let rb = RecordBatch::try_new(schema, vec![Arc::new(dict) as ArrayRef]).unwrap();
        let mut buf = fresh_buffer();
        let err = buf.append_arrow(table("t"), &rb).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ArrowIngest);
        assert!(err.msg().contains("dictionary values"));
    }

    #[test]
    fn unreferenced_null_dict_entry_accepted_for_symbol() {
        use arrow_array::DictionaryArray;
        use arrow_array::types::UInt32Type;
        let mut vb = StringBuilder::new();
        vb.append_value("a");
        vb.append_null();
        vb.append_value("c");
        let values = vb.finish();
        let keys = arrow_array::UInt32Array::from(vec![0u32, 2, 0]);
        let dict =
            DictionaryArray::<UInt32Type>::try_new(keys, Arc::new(values) as ArrayRef).unwrap();
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
        let rb = RecordBatch::try_new(schema, vec![Arc::new(dict) as ArrayRef]).unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 3);
    }

    #[test]
    fn unreferenced_null_dict_entry_accepted() {
        use arrow_array::DictionaryArray;
        use arrow_array::types::UInt32Type;
        let mut vb = StringBuilder::new();
        vb.append_value("a");
        vb.append_null();
        let values = vb.finish();
        let keys = arrow_array::UInt32Array::from(vec![0u32, 0]);
        let dict =
            DictionaryArray::<UInt32Type>::try_new(keys, Arc::new(values) as ArrayRef).unwrap();
        let field = Field::new(
            "v",
            DataType::Dictionary(Box::new(DataType::UInt32), Box::new(DataType::Utf8)),
            true,
        );
        let schema = arrow_schema_with(field);
        let rb = RecordBatch::try_new(schema, vec![Arc::new(dict) as ArrayRef]).unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 2);
    }

    #[test]
    fn timestamp_ms_designated_overflow_rejected() {
        let mut ts = TimestampMillisecondBuilder::new();
        ts.append_value(i64::MAX / 1000 + 1);
        ts.append_value(0);
        let mut v = Int64Builder::new();
        v.append_value(1);
        v.append_value(2);
        let schema = Arc::new(ArrowSchema::new(vec![
            Field::new(
                "ts",
                DataType::Timestamp(TimeUnit::Millisecond, None),
                false,
            ),
            Field::new("v", DataType::Int64, false),
        ]));
        let rb = RecordBatch::try_new(
            schema,
            vec![
                Arc::new(ts.finish()) as ArrayRef,
                Arc::new(v.finish()) as ArrayRef,
            ],
        )
        .unwrap();
        let mut buf = fresh_buffer();
        let err = buf
            .append_arrow_at_column(table("t"), &rb, ColumnName::new("ts").unwrap())
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::ArrowIngest);
        assert!(
            err.msg().contains("ms→µs overflow"),
            "expected overflow message, got: {}",
            err.msg()
        );
        assert_eq!(buf.row_count(), 0);
    }

    #[test]
    fn timestamp_second_to_micros_overflow_rejected() {
        use arrow_array::builder::TimestampSecondBuilder;
        let mut b = TimestampSecondBuilder::new();
        b.append_value(i64::MAX / 1_000_000 + 1);
        let schema = arrow_schema_with(Field::new(
            "t",
            DataType::Timestamp(TimeUnit::Second, None),
            true,
        ));
        let rb = RecordBatch::try_new(schema, vec![Arc::new(b.finish()) as ArrayRef]).unwrap();
        let mut buf = fresh_buffer();
        let err = buf.append_arrow(table("u"), &rb).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ArrowIngest);
        assert!(
            err.msg().contains("s→µs overflow"),
            "expected overflow message, got: {}",
            err.msg()
        );
    }

    #[test]
    fn buffer_clear_after_arrow_allows_row_by_row_reuse() {
        let mut buf = fresh_buffer();
        let mut b = Int64Builder::new();
        b.append_value(1);
        b.append_value(2);
        let schema = arrow_schema_with(Field::new("v", DataType::Int64, false));
        let rb = RecordBatch::try_new(schema, vec![Arc::new(b.finish()) as ArrayRef]).unwrap();
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 2);
        buf.clear();
        assert_eq!(buf.row_count(), 0);
        buf.table(table("t")).unwrap();
        buf.column_i64("v", 99).unwrap();
        buf.at_now().unwrap();
        assert_eq!(buf.row_count(), 1);
    }

    #[test]
    fn append_arrow_error_rolls_back_columns() {
        // Two columns: the second one will fail classification (Map),
        // so the first column's bytes must not stick.
        use arrow_array::builder::{Int64Builder, MapBuilder, StringBuilder};
        let mut col1 = Int64Builder::new();
        col1.append_value(11);
        col1.append_value(22);
        let mut map = MapBuilder::new(None, StringBuilder::new(), Int32Builder::new());
        map.keys().append_value("k1");
        map.values().append_value(1);
        map.append(true).unwrap();
        map.keys().append_value("k2");
        map.values().append_value(2);
        map.append(true).unwrap();
        let map_arr = map.finish();
        let map_dtype = map_arr.data_type().clone();
        let schema = Arc::new(ArrowSchema::new(vec![
            Field::new("good", DataType::Int64, false),
            Field::new("bad", map_dtype, true),
        ]));
        let rb = RecordBatch::try_new(
            schema,
            vec![
                Arc::new(col1.finish()) as ArrayRef,
                Arc::new(map_arr) as ArrayRef,
            ],
        )
        .unwrap();
        let mut buf = fresh_buffer();
        let err = buf.append_arrow(table("t"), &rb).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ArrowUnsupportedColumnKind);
        assert_eq!(
            buf.row_count(),
            0,
            "rollback should leave buffer with 0 rows"
        );
        // A retry on a valid batch must succeed cleanly.
        let mut c2 = Int64Builder::new();
        c2.append_value(7);
        let schema2 = arrow_schema_with(Field::new("good", DataType::Int64, false));
        let rb2 = RecordBatch::try_new(schema2, vec![Arc::new(c2.finish()) as ArrayRef]).unwrap();
        buf.append_arrow(table("t"), &rb2).unwrap();
        assert_eq!(buf.row_count(), 1);
    }

    #[test]
    fn error_message_carries_column_name() {
        let inner_field = Arc::new(Field::new("x", DataType::Int32, true));
        let mut b = Int32Builder::new();
        b.append_value(1);
        let inner_arr = b.finish();
        let struct_arr = arrow_array::StructArray::from(vec![(
            inner_field.clone(),
            Arc::new(inner_arr) as ArrayRef,
        )]);
        let schema = arrow_schema_with(Field::new(
            "my_struct_col",
            DataType::Struct(vec![inner_field].into()),
            true,
        ));
        let rb = RecordBatch::try_new(schema, vec![Arc::new(struct_arr) as ArrayRef]).unwrap();
        let mut buf = fresh_buffer();
        let err = buf.append_arrow(table("t"), &rb).unwrap_err();
        assert!(
            err.msg().contains("my_struct_col"),
            "column name missing from error: {}",
            err.msg()
        );
    }

    #[test]
    fn multi_batch_arrow_appends_accumulate_rows() {
        let mut buf = fresh_buffer();
        let schema = arrow_schema_with(Field::new("v", DataType::Int64, false));

        let mut b1 = Int64Builder::new();
        b1.append_value(1);
        b1.append_value(2);
        let rb1 =
            RecordBatch::try_new(schema.clone(), vec![Arc::new(b1.finish()) as ArrayRef]).unwrap();
        buf.append_arrow(table("t"), &rb1).unwrap();
        assert_eq!(buf.row_count(), 2);

        let mut b2 = Int64Builder::new();
        b2.append_value(3);
        b2.append_value(4);
        b2.append_value(5);
        let rb2 = RecordBatch::try_new(schema, vec![Arc::new(b2.finish()) as ArrayRef]).unwrap();
        buf.append_arrow(table("t"), &rb2).unwrap();
        assert_eq!(buf.row_count(), 5);
    }

    #[test]
    fn sliced_int32_array_emits_sliced_window_only() {
        let mut b = Int32Builder::new();
        for v in 0..8 {
            b.append_value(v);
        }
        let full = b.finish();
        let sliced = full.slice(2, 4);
        assert_eq!(sliced.len(), 4);

        let rb = RecordBatch::try_new(
            arrow_schema_with(Field::new("v", DataType::Int32, false)),
            vec![Arc::new(sliced) as ArrayRef],
        )
        .unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 4);
    }

    #[test]
    fn sliced_utf8_array_emits_sliced_window_only() {
        let mut b = arrow_array::builder::StringBuilder::new();
        for s in ["a", "bb", "ccc", "dddd", "eeeee"] {
            b.append_value(s);
        }
        let full = b.finish();
        let sliced = full.slice(1, 3);
        assert_eq!(sliced.len(), 3);

        let rb = RecordBatch::try_new(
            arrow_schema_with(Field::new("s", DataType::Utf8, false)),
            vec![Arc::new(sliced) as ArrayRef],
        )
        .unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 3);
    }

    #[test]
    fn sliced_bool_array_with_offset_emits_sliced_window() {
        let mut b = arrow_array::builder::BooleanBuilder::new();
        for v in [true, false, true, false, true, false, true, false, true] {
            b.append_value(v);
        }
        let full = b.finish();
        let sliced = full.slice(3, 5);
        assert_eq!(sliced.len(), 5);

        let rb = RecordBatch::try_new(
            arrow_schema_with(Field::new("flag", DataType::Boolean, false)),
            vec![Arc::new(sliced) as ArrayRef],
        )
        .unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 5);
    }

    #[test]
    fn decimal256_negative_scale_rejected() {
        use arrow_array::builder::Decimal256Builder;
        use arrow_buffer::i256;
        let mut b = Decimal256Builder::new()
            .with_precision_and_scale(76, -1)
            .unwrap();
        b.append_value(i256::ZERO);
        let rb = RecordBatch::try_new(
            arrow_schema_with(Field::new("d", DataType::Decimal256(76, -1), false)),
            vec![Arc::new(b.finish()) as ArrayRef],
        )
        .unwrap();
        let mut buf = fresh_buffer();
        let err = buf.append_arrow(table("t"), &rb).unwrap_err();
        assert_eq!(err.code(), crate::error::ErrorCode::ArrowIngest);
        assert!(err.msg().to_lowercase().contains("negative"));
    }

    #[test]
    fn geohash_int8_precision_above_8_rejected() {
        let mut b = Int8Builder::new();
        b.append_value(0);
        let mut md = std::collections::HashMap::new();
        md.insert("questdb.geohash_bits".to_string(), "20".to_string());
        let field = Field::new("g", DataType::Int8, true).with_metadata(md);
        let rb = RecordBatch::try_new(
            arrow_schema_with(field),
            vec![Arc::new(b.finish()) as ArrayRef],
        )
        .unwrap();
        let mut buf = fresh_buffer();
        let err = buf.append_arrow(table("t"), &rb).unwrap_err();
        assert_eq!(err.code(), crate::error::ErrorCode::ArrowIngest);
        assert!(err.msg().contains("geohash"));
    }

    #[test]
    fn varlen_no_user_columns_rejected() {
        let mut ts = TimestampMicrosecondBuilder::new();
        ts.append_value(0);
        let rb = RecordBatch::try_new(
            arrow_schema_with(Field::new(
                "ts",
                DataType::Timestamp(TimeUnit::Microsecond, None),
                false,
            )),
            vec![Arc::new(ts.finish()) as ArrayRef],
        )
        .unwrap();
        let mut buf = fresh_buffer();
        let err = buf
            .append_arrow_at_column(table("t"), &rb, ColumnName::new("ts").unwrap())
            .unwrap_err();
        assert_eq!(err.code(), crate::error::ErrorCode::ArrowIngest);
        assert!(err.msg().contains("non-timestamp column"));
    }

    #[test]
    fn single_row_int64_appends_one_row() {
        let mut b = Int64Builder::new();
        b.append_value(0);
        let rb = RecordBatch::try_new(
            arrow_schema_with(Field::new("v", DataType::Int64, false)),
            vec![Arc::new(b.finish()) as ArrayRef],
        )
        .unwrap();
        let mut buf = fresh_buffer();
        buf.append_arrow(table("t"), &rb).unwrap();
        assert_eq!(buf.row_count(), 1);
    }
}
