//! Polars sub-feature: `RecordBatch ↔ DataFrame` via Arrow C Data Interface.

use std::sync::Arc;

use arrow_array::types::UInt32Type;
use arrow_array::{Array, ArrayRef, DictionaryArray, RecordBatch};
use arrow_data::ArrayData;
use arrow_schema::{DataType as ArrowDataType, SchemaRef};
use polars::frame::DataFrame;
use polars::prelude::{
    Categorical32Type, CategoricalChunked, CategoricalMapping, CategoricalPhysical, Categories,
    Column, DataType as PlDataType, IDX_DTYPE, IdxCa, IntoColumn, IntoSeries, PlSmallStr, Series,
};

use crate::egress::Cursor;
use crate::egress::arrow::has_tentative_array;
use crate::egress::error::{Error, ErrorCode, Result, fmt};
use crate::egress::symbol_dict::SymbolDict;

// FFI cross-crate helpers in `crate::ingress::polars`.

impl Cursor<'_> {
    /// Decode one batch as a Polars [`DataFrame`]. `Ok(None)` on
    /// stream end.
    ///
    /// This is the low-level per-batch entry point and does **not**
    /// detect mid-stream Arrow schema drift; if a later batch's
    /// schema differs from earlier ones the resulting DataFrames will
    /// simply disagree on columns. Use
    /// [`Cursor::iter_polars`](Cursor::iter_polars)
    /// for a drift-checked iterator, or
    /// [`Cursor::fetch_all_polars`] / [`Cursor::as_arrow_reader`]
    /// for higher-level adapters that pin the schema on first batch.
    pub fn next_polars(&mut self) -> Result<Option<DataFrame>> {
        match self.next_arrow_batch_inner(None)? {
            None => Ok(None),
            Some(rb) => Ok(Some(self.batch_to_dataframe(rb)?)),
        }
    }

    /// Per-batch `RecordBatch → DataFrame` via the cursor's persistent
    /// [`SymbolRegistry`], instead of rebuilding the categorical mapping every
    /// batch (the high-cardinality collapse).
    fn batch_to_dataframe(&mut self, rb: RecordBatch) -> Result<DataFrame> {
        let modes = self.symbol_delta_modes().to_vec();
        let registry = self.symbol_registry_synced()?;
        build_dataframe(rb, &modes, registry)
    }

    /// Eagerly drain into one chunked Polars [`DataFrame`]. A stream
    /// that yields a schema but no batches becomes an empty DataFrame;
    /// only a stream without a schema (e.g. cancelled pre-prelude)
    /// errors as `NoSchema`. Drift detection is inherited from
    /// [`Cursor::iter_polars`].
    pub fn fetch_all_polars(&mut self) -> Result<DataFrame> {
        // Materialise-whole: the full result is built internally before
        // anything is handed back, so a mid-query failover replays the
        // query from `batch_seq 0` transparently. Opt into replay and
        // drop the partial accumulation when the cursor reports a reset.
        self.enable_internal_replay();
        let mut iter = self.iter_polars()?;
        let mut resets_seen = iter.failover_resets();
        let mut acc: Option<DataFrame> = None;
        loop {
            // Manual drive (not `for`/`by_ref`) so the reset counter can be
            // polled between batches without holding an iterator borrow.
            let Some(item) = iter.next() else { break };
            let df = item?;
            let resets_now = iter.failover_resets();
            if resets_now != resets_seen {
                resets_seen = resets_now;
                acc = None;
            }
            acc = Some(match acc {
                None => df,
                Some(mut prev) => {
                    if prev.height() == 0 && prev.schema() != df.schema() {
                        df
                    } else {
                        prev.vstack_mut_owned(df)
                            .map_err(|e| fmt!(ArrowExport, "polars vstack failed: {}", e))?;
                        prev
                    }
                }
            });
        }
        let schema = iter.schema();
        match acc {
            Some(df) => Ok(df),
            None => record_batch_to_dataframe(RecordBatch::new_empty(schema)),
        }
    }
}

/// Drift-checked iterator yielding Polars [`DataFrame`]s, one per
/// QWP batch. Built by [`Cursor::iter_polars`]. Snapshots the first
/// batch's Arrow schema at construction and poisons (terminates) on
/// mid-stream schema drift.
pub struct CursorPolarsIter<'r, 'c> {
    cursor: &'c mut Cursor<'r>,
    schema: SchemaRef,
    pending: Option<RecordBatch>,
    poisoned: bool,
    /// `Cursor::failover_resets()` at the point `schema` was pinned. A
    /// later batch arriving with a higher count is the first frame of a
    /// transparently-replayed query (re-read from `batch_seq 0` on a new
    /// endpoint), so the pinned schema is re-snapshotted from it rather
    /// than treated as drift. `fetch_all_polars` reads the same counter to
    /// discard its partial `vstack` accumulation.
    resets_at_pin: u32,
}

impl<'r, 'c> CursorPolarsIter<'r, 'c> {
    pub(crate) fn new(cursor: &'c mut Cursor<'r>) -> Result<Self> {
        let first = cursor.next_arrow_batch_inner(None)?.ok_or_else(|| {
            Error::new(
                ErrorCode::NoSchema,
                "no batch produced; nothing to snapshot",
            )
        })?;
        let schema = first.schema();
        let resets_at_pin = cursor.failover_resets();
        Ok(Self {
            cursor,
            schema,
            pending: Some(first),
            poisoned: false,
            resets_at_pin,
        })
    }

    /// First batch's schema. Upgrades on tentative→firm ndim
    /// (see [`has_tentative_array`]).
    pub fn schema(&self) -> SchemaRef {
        self.schema.clone()
    }

    /// Reconnect count observed by the underlying cursor. `fetch_all_polars`
    /// polls this between batches: an increase means the query was replayed
    /// from scratch, so anything accumulated so far must be dropped.
    pub(crate) fn failover_resets(&self) -> u32 {
        self.cursor.failover_resets()
    }
}

impl Iterator for CursorPolarsIter<'_, '_> {
    type Item = Result<DataFrame>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.poisoned {
            return None;
        }
        let rb = if let Some(rb) = self.pending.take() {
            rb
        } else {
            // A transparent mid-query failover re-reads the result from
            // `batch_seq 0` on a new endpoint, so the pinned schema is
            // re-snapshotted from the first replayed batch instead of
            // being compared against it. Pass `None` (no drift check)
            // for that frame so the new node's batch 0 isn't rejected.
            let drift_check = if self.cursor.failover_resets() == self.resets_at_pin {
                Some(&self.schema)
            } else {
                None
            };
            match self.cursor.next_arrow_batch_inner(drift_check) {
                Ok(Some(rb)) => {
                    if self.cursor.failover_resets() != self.resets_at_pin {
                        self.schema = rb.schema();
                        self.resets_at_pin = self.cursor.failover_resets();
                    } else if has_tentative_array(&self.schema) && rb.schema() != self.schema {
                        self.poisoned = true;
                        return Some(Err(Error::new(
                            ErrorCode::SchemaDrift,
                            "tentative→firm ndim upgrade mid-stream; the \
                             iterator pins the first batch's schema. Use \
                             Cursor::next_polars to handle drift explicitly",
                        )));
                    }
                    rb
                }
                Ok(None) => {
                    self.poisoned = true;
                    return None;
                }
                Err(e) => {
                    self.poisoned = true;
                    return Some(Err(e));
                }
            }
        };
        let df = self.cursor.batch_to_dataframe(rb);
        if df.is_err() {
            self.poisoned = true;
        }
        Some(df)
    }
}

/// [`RecordBatch`] → Polars [`DataFrame`] via the Arrow C Data Interface.
/// Zero-copy for primitive/string/binary; SYMBOL columns become a polars
/// `Categorical` (see [`dictionary_to_categorical`]).
/// [`ErrorCode::ArrowExport`] on handoff failure.
pub fn record_batch_to_dataframe(rb: RecordBatch) -> Result<DataFrame> {
    let schema = rb.schema();
    let row_count = rb.num_rows();
    let mut columns: Vec<Column> = Vec::with_capacity(rb.num_columns());
    for (col, field) in rb.columns().iter().zip(schema.fields().iter()) {
        let name = field.name().as_str();
        let series = if matches!(col.data_type(), ArrowDataType::Dictionary(_, _)) {
            dictionary_to_categorical(name, col)?
        } else {
            import_polars_series(name, &col.to_data())?
        };
        columns.push(series.into_column());
    }
    DataFrame::new(row_count, columns)
        .map_err(|e| fmt!(ArrowExport, "DataFrame::new failed: {}", e))
}

fn import_polars_series(name: &str, array_data: &ArrayData) -> Result<Series> {
    let (rs_array, rs_schema) = arrow::ffi::to_ffi(array_data)
        .map_err(|e| fmt!(ArrowExport, "to_ffi failed for column '{}': {}", name, e))?;
    let pa_schema = unsafe { crate::ingress::polars::rs_schema_into_pa(rs_schema) };
    let pa_array = unsafe { crate::ingress::polars::rs_array_into_pa(rs_array) };
    let pa_field = unsafe { polars_arrow::ffi::import_field_from_c(&pa_schema) }
        .map_err(|e| fmt!(ArrowExport, "import_field_from_c('{}'): {}", name, e))?;
    let pa_array_box = unsafe { polars_arrow::ffi::import_array_from_c(pa_array, pa_field.dtype) }
        .map_err(|e| fmt!(ArrowExport, "import_array_from_c('{}'): {}", name, e))?;
    Series::from_arrow(name.into(), pa_array_box)
        .map_err(|e| fmt!(ArrowExport, "Series::from_arrow('{}'): {}", name, e))
}

/// Build a SYMBOL column's polars `Categorical` from its codes + dictionary
/// (cast the small dictionary, then `take` by code), avoiding
/// `Series::from_arrow`'s per-row remap. `Categories` exists since polars 0.50.
fn dictionary_to_categorical(name: &str, col: &ArrayRef) -> Result<Series> {
    let dict = col
        .as_any()
        .downcast_ref::<DictionaryArray<UInt32Type>>()
        .ok_or_else(|| {
            fmt!(
                ArrowExport,
                "SYMBOL '{}' is not Dictionary(UInt32, _)",
                name
            )
        })?;

    let values = import_polars_series(name, &dict.values().to_data())?;
    // Every RESULT_BATCH frame of one query must build its SYMBOL Categorical
    // against the SAME `Categories`: polars vstack/concat — used by
    // `fetch_all_polars` / `iter_polars` to stitch the per-batch frames — only
    // accepts Categoricals that share one `Categories` identity, otherwise it
    // errors "Categories name mismatch".
    //
    // Use the process-global `Categories`. This is exactly what the
    // pre-optimization path produced: SYMBOL columns used to flow through
    // `Series::from_arrow`, and polars maps a metadata-less Utf8 dictionary to
    // `Categories::global()` (polars `DataType::from_arrow`), so every batch and
    // every symbol column already shared one Categories. The faster
    // cast-and-take path that replaced it switched to `Categories::random()` — a
    // fresh UUID-named instance per call — which silently broke vstack for any
    // SYMBOL result spanning >1 batch (>~16k rows). `global()` restores the
    // shared identity so later batches' codes intern into one mapping and stack
    // cleanly. (A per-stream Categories would bound the mapping's lifetime to a
    // single query, but at the cost of cross-compatibility with the caller's own
    // global Categoricals — left as a possible future optimization.)
    let cats = Categories::global();
    let mapping = cats.mapping();
    let cat_dict = values
        .cast(&PlDataType::Categorical(cats, mapping))
        .map_err(|e| {
            fmt!(
                ArrowExport,
                "cast SYMBOL '{}' dict to Categorical: {}",
                name,
                e
            )
        })?;

    let keys = import_polars_series(name, &dict.keys().to_data())?;
    let idx: IdxCa = keys
        .cast(&IDX_DTYPE)
        .map_err(|e| fmt!(ArrowExport, "cast SYMBOL '{}' codes to index: {}", name, e))?
        .idx()
        .map_err(|e| {
            fmt!(
                ArrowExport,
                "SYMBOL '{}' codes not an index dtype: {}",
                name,
                e
            )
        })?
        .clone();
    cat_dict
        .take(&idx)
        .map_err(|e| fmt!(ArrowExport, "gather SYMBOL '{}' codes: {}", name, e))
}

/// Per-cursor registry that interns a query's connection SYMBOL dictionary into
/// one persistent polars `Categories` in QWP code order — so a global QWP code
/// is its own physical categorical code and keys wrap straight into a
/// Categorical, with no per-batch cast or gather.
pub(crate) struct SymbolRegistry {
    dtype: PlDataType,
    mapping: Arc<CategoricalMapping>,
    registered: usize,
}

impl SymbolRegistry {
    pub(crate) fn new() -> Self {
        let cats = Categories::random(PlSmallStr::from("questdb_symbol"), CategoricalPhysical::U32);
        let mapping = cats.mapping();
        let dtype = PlDataType::Categorical(cats, mapping.clone());
        Self {
            dtype,
            mapping,
            registered: 0,
        }
    }

    pub(crate) fn sync(&mut self, dict: &SymbolDict) -> Result<()> {
        // A CACHE_RESET clears the connection dict; the shrink restarts us.
        if dict.len() < self.registered {
            *self = Self::new();
        }
        for code in self.registered..dict.len() {
            let s = dict.get(code as u32).ok_or_else(|| {
                fmt!(
                    ArrowExport,
                    "symbol code {} missing from dict during registry sync",
                    code
                )
            })?;
            // `insert_cat` appends in call order, so the assigned id == `code`.
            self.mapping
                .insert_cat(s)
                .map_err(|e| fmt!(ArrowExport, "register SYMBOL '{}': {}", s, e))?;
        }
        self.registered = dict.len();
        Ok(())
    }

    fn categorical_from_keys(&self, name: &str, col: &ArrayRef) -> Result<Series> {
        let dict = col
            .as_any()
            .downcast_ref::<DictionaryArray<UInt32Type>>()
            .ok_or_else(|| {
                fmt!(
                    ArrowExport,
                    "SYMBOL '{}' is not Dictionary(UInt32, _)",
                    name
                )
            })?;
        let keys = import_polars_series(name, &dict.keys().to_data())?;
        let phys = keys
            .u32()
            .map_err(|e| fmt!(ArrowExport, "SYMBOL '{}' keys not u32: {}", name, e))?
            .clone();
        // SAFETY: `sync` registered every dict entry in code order, so each key is
        // a valid physical code; the decoder bounds-checks every non-null key
        // against `dict.len()`, and null rows (key 0) are masked by the imported
        // key buffer's null bitmap.
        let cat = unsafe {
            CategoricalChunked::<Categorical32Type>::from_cats_and_dtype_unchecked(
                phys,
                self.dtype.clone(),
            )
        };
        Ok(cat.into_series())
    }
}

/// `RecordBatch → DataFrame` for the cursor-driven polars paths. Delta-mode
/// SYMBOL columns (`delta_modes[i]`) resolve through the persistent `registry`;
/// column-local SYMBOL columns fall back to [`dictionary_to_categorical`].
fn build_dataframe(
    rb: RecordBatch,
    delta_modes: &[bool],
    registry: &SymbolRegistry,
) -> Result<DataFrame> {
    let schema = rb.schema();
    let row_count = rb.num_rows();
    let mut columns: Vec<Column> = Vec::with_capacity(rb.num_columns());
    for (i, (col, field)) in rb.columns().iter().zip(schema.fields().iter()).enumerate() {
        let name = field.name().as_str();
        let series = if matches!(col.data_type(), ArrowDataType::Dictionary(_, _)) {
            if delta_modes.get(i).copied().unwrap_or(false) {
                registry.categorical_from_keys(name, col)?
            } else {
                dictionary_to_categorical(name, col)?
            }
        } else {
            import_polars_series(name, &col.to_data())?
        };
        columns.push(series.into_column());
    }
    DataFrame::new(row_count, columns)
        .map_err(|e| fmt!(ArrowExport, "DataFrame::new failed: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use arrow_array::builder::{Float64Builder, Int64Builder, StringBuilder};
    use arrow_array::{ArrayRef, RecordBatch};
    use arrow_schema::{DataType, Field, Schema as ArrowSchema};

    fn rb_mixed() -> RecordBatch {
        let mut ii = Int64Builder::new();
        ii.append_value(1);
        ii.append_value(2);
        ii.append_value(3);
        let mut ff = Float64Builder::new();
        ff.append_value(1.5);
        ff.append_value(2.5);
        ff.append_value(3.5);
        let mut ss = StringBuilder::new();
        ss.append_value("a");
        ss.append_value("b");
        ss.append_value("c");
        let schema = Arc::new(ArrowSchema::new(vec![
            Field::new("i", DataType::Int64, false),
            Field::new("f", DataType::Float64, false),
            Field::new("s", DataType::Utf8, false),
        ]));
        RecordBatch::try_new(
            schema,
            vec![
                Arc::new(ii.finish()) as ArrayRef,
                Arc::new(ff.finish()) as ArrayRef,
                Arc::new(ss.finish()) as ArrayRef,
            ],
        )
        .unwrap()
    }

    #[test]
    fn record_batch_to_dataframe_preserves_column_count_and_height() {
        let rb = rb_mixed();
        let df = record_batch_to_dataframe(rb).unwrap();
        assert_eq!(df.width(), 3);
        assert_eq!(df.height(), 3);
        let cols = df.columns();
        assert_eq!(cols[0].name().as_str(), "i");
        assert_eq!(cols[1].name().as_str(), "f");
        assert_eq!(cols[2].name().as_str(), "s");
    }

    #[test]
    fn record_batch_to_dataframe_preserves_int_values() {
        let rb = rb_mixed();
        let df = record_batch_to_dataframe(rb).unwrap();
        let col = &df.columns()[0];
        let series = col.as_materialized_series();
        let i64s = series.i64().unwrap();
        assert_eq!(i64s.get(0), Some(1));
        assert_eq!(i64s.get(1), Some(2));
        assert_eq!(i64s.get(2), Some(3));
    }

    #[test]
    fn record_batch_to_dataframe_preserves_string_values() {
        let rb = rb_mixed();
        let df = record_batch_to_dataframe(rb).unwrap();
        let col = &df.columns()[2];
        let series = col.as_materialized_series();
        let s = series.str().unwrap();
        assert_eq!(s.get(0), Some("a"));
        assert_eq!(s.get(1), Some("b"));
        assert_eq!(s.get(2), Some("c"));
    }

    #[test]
    fn record_batch_to_dataframe_zero_rows_succeeds() {
        let schema = Arc::new(ArrowSchema::new(vec![Field::new(
            "v",
            DataType::Int64,
            false,
        )]));
        let mut ii = Int64Builder::new();
        let arr: ArrayRef = Arc::new(ii.finish());
        let rb = RecordBatch::try_new(schema, vec![arr]).unwrap();
        let df = record_batch_to_dataframe(rb).unwrap();
        assert_eq!(df.height(), 0);
        assert_eq!(df.width(), 1);
    }

    /// Every QuestDB table carries a designated TIMESTAMP, which the
    /// egress decoder maps to the tz-aware Arrow `Timestamp(Microsecond,
    /// Some("UTC"))`. Materialising that into a polars `DataFrame`
    /// requires the `dtype-datetime` + `timezones` polars features; this
    /// test guards that feature set (without them `Series::from_arrow`
    /// fails at runtime, which `fetch_all_polars` on any real result set
    /// would hit). See the `polars` feature in `Cargo.toml`.
    #[test]
    fn record_batch_to_dataframe_preserves_tz_timestamp() {
        use arrow_array::TimestampMicrosecondArray;
        let ts: ArrayRef = Arc::new(
            TimestampMicrosecondArray::from(vec![1_700_000_000_000_000i64, 1_700_000_000_000_001])
                .with_timezone("UTC"),
        );
        let schema = Arc::new(ArrowSchema::new(vec![Field::new(
            "ts",
            ts.data_type().clone(),
            false,
        )]));
        let rb = RecordBatch::try_new(schema, vec![ts]).unwrap();
        let df = record_batch_to_dataframe(rb).unwrap();
        assert_eq!(df.height(), 2);
        assert_eq!(df.width(), 1);
        // The column must round-trip as a polars Datetime, not error out.
        let series = df.columns()[0].as_materialized_series();
        assert!(
            matches!(series.dtype(), polars::prelude::DataType::Datetime(_, _)),
            "expected polars Datetime, got {:?}",
            series.dtype()
        );
    }

    #[test]
    fn record_batch_to_dataframe_symbol_dictionary_to_categorical() {
        use arrow_array::types::UInt32Type;
        use arrow_array::{DictionaryArray, StringArray, UInt32Array};

        let values: ArrayRef = Arc::new(StringArray::from(vec!["x", "y", "z"]));
        let keys = UInt32Array::from(vec![Some(2u32), Some(0), None, Some(1)]);
        let dict = DictionaryArray::<UInt32Type>::new(keys, values);
        let schema = Arc::new(ArrowSchema::new(vec![Field::new(
            "sym",
            DataType::Dictionary(Box::new(DataType::UInt32), Box::new(DataType::Utf8)),
            true,
        )]));
        let rb = RecordBatch::try_new(schema, vec![Arc::new(dict) as ArrayRef]).unwrap();

        let df = record_batch_to_dataframe(rb).unwrap();
        assert_eq!(df.width(), 1);
        assert_eq!(df.height(), 4);
        let col = &df.columns()[0];
        assert_eq!(col.name().as_str(), "sym");
        assert!(
            matches!(col.dtype(), PlDataType::Categorical(_, _)),
            "expected Categorical, got {:?}",
            col.dtype()
        );
        let as_str = col
            .as_materialized_series()
            .cast(&PlDataType::String)
            .unwrap();
        let s = as_str.str().unwrap();
        assert_eq!(s.get(0), Some("z"));
        assert_eq!(s.get(1), Some("x"));
        assert_eq!(s.get(2), None);
        assert_eq!(s.get(3), Some("y"));
    }

    #[test]
    fn symbol_categoricals_vstack_across_batches() {
        // Regression guard: a SYMBOL column from one query arrives across
        // many QWP RESULT_BATCH frames (~16k rows each), and
        // `fetch_all_polars` vstacks the per-batch DataFrames. polars only
        // vstacks Categoricals that share one `Categories` identity, so every
        // batch must build against the same one. Building each batch against a
        // fresh `Categories::random()` broke this: vstack failed with
        // "Categories name mismatch" the moment a result spanned >1 batch.
        use arrow_array::types::UInt32Type;
        use arrow_array::{DictionaryArray, StringArray, UInt32Array};

        fn sym_batch(values: &[&str], keys: &[Option<u32>]) -> RecordBatch {
            let values: ArrayRef = Arc::new(StringArray::from(values.to_vec()));
            let keys = UInt32Array::from(keys.to_vec());
            let dict = DictionaryArray::<UInt32Type>::new(keys, values);
            let schema = Arc::new(ArrowSchema::new(vec![Field::new(
                "sym",
                DataType::Dictionary(Box::new(DataType::UInt32), Box::new(DataType::Utf8)),
                true,
            )]));
            RecordBatch::try_new(schema, vec![Arc::new(dict) as ArrayRef]).unwrap()
        }

        // Two batches with *different* per-batch dictionaries (the second
        // introduces a new symbol), mirroring QWP's growing delta dictionary.
        let b1 = sym_batch(&["a", "b"], &[Some(0), Some(1), Some(0)]); // a, b, a
        let b2 = sym_batch(&["b", "c"], &[Some(0), Some(1)]); // b, c

        let mut df = record_batch_to_dataframe(b1).unwrap();
        let df2 = record_batch_to_dataframe(b2).unwrap();
        df.vstack_mut_owned(df2)
            .expect("SYMBOL Categoricals from different batches must vstack");

        assert_eq!(df.height(), 5);
        let as_str = df.columns()[0]
            .as_materialized_series()
            .cast(&PlDataType::String)
            .unwrap();
        let s = as_str.str().unwrap();
        let got: Vec<Option<&str>> = (0..df.height()).map(|i| s.get(i)).collect();
        assert_eq!(
            got,
            vec![Some("a"), Some("b"), Some("a"), Some("b"), Some("c")]
        );
    }

    #[test]
    fn symbol_categoricals_multi_column_and_interleaved_streams() {
        // All SYMBOL columns process-wide share `Categories::global()`, so prove
        // the two cases that make a shared mapping suspicious stay correct:
        // (1) several SYMBOL columns in one DataFrame, and (2) independent
        // cursors converting interleaved. Strings are deliberately reused across
        // columns and streams ("x", "p") to show the shared string<->id mapping
        // never crosswires them.
        use arrow_array::types::UInt32Type;
        use arrow_array::{DictionaryArray, StringArray, UInt32Array};

        fn sym(vals: &[&str], keys: &[Option<u32>]) -> ArrayRef {
            let values: ArrayRef = Arc::new(StringArray::from(vals.to_vec()));
            Arc::new(DictionaryArray::<UInt32Type>::new(
                UInt32Array::from(keys.to_vec()),
                values,
            )) as ArrayRef
        }
        fn batch(fields: &[&str], cols: Vec<ArrayRef>) -> RecordBatch {
            let dict_ty =
                DataType::Dictionary(Box::new(DataType::UInt32), Box::new(DataType::Utf8));
            let schema = Arc::new(ArrowSchema::new(
                fields
                    .iter()
                    .map(|n| Field::new(*n, dict_ty.clone(), true))
                    .collect::<Vec<_>>(),
            ));
            RecordBatch::try_new(schema, cols).unwrap()
        }
        fn vals(df: &DataFrame, i: usize) -> Vec<Option<String>> {
            let s = df.columns()[i]
                .as_materialized_series()
                .cast(&PlDataType::String)
                .unwrap();
            let s = s.str().unwrap();
            (0..df.height())
                .map(|r| s.get(r).map(str::to_owned))
                .collect()
        }
        let some = |xs: &[&str]| xs.iter().map(|s| Some(s.to_string())).collect::<Vec<_>>();

        // Stream 1: two SYMBOL columns "a","b". Stream 2: one column "a".
        let s1b1 = batch(
            &["a", "b"],
            vec![
                sym(&["x", "y"], &[Some(0), Some(1)]),
                sym(&["m"], &[Some(0), Some(0)]),
            ],
        );
        let s2b1 = batch(&["a"], vec![sym(&["x", "p"], &[Some(1), Some(0)])]);
        let s1b2 = batch(
            &["a", "b"],
            vec![
                sym(&["y", "z"], &[Some(0), Some(1)]),
                sym(&["m", "x"], &[Some(1), Some(0)]),
            ],
        );
        let s2b2 = batch(&["a"], vec![sym(&["p", "q"], &[Some(0), Some(1)])]);

        // Convert interleaved (mimics two concurrent cursors), then vstack per stream.
        let mut s1 = record_batch_to_dataframe(s1b1).unwrap();
        let mut s2 = record_batch_to_dataframe(s2b1).unwrap();
        s1.vstack_mut_owned(record_batch_to_dataframe(s1b2).unwrap())
            .unwrap();
        s2.vstack_mut_owned(record_batch_to_dataframe(s2b2).unwrap())
            .unwrap();

        assert_eq!(vals(&s1, 0), some(&["x", "y", "y", "z"])); // multi-column, col a
        assert_eq!(vals(&s1, 1), some(&["m", "m", "x", "m"])); // col b reuses "x","m"
        assert_eq!(vals(&s2, 0), some(&["p", "x", "p", "q"])); // other cursor, shares "x","p"
    }

    fn sym_batch(values: &[&str], keys: &[Option<u32>]) -> RecordBatch {
        use arrow_array::types::UInt32Type;
        use arrow_array::{DictionaryArray, StringArray, UInt32Array};
        let values: ArrayRef = Arc::new(StringArray::from(values.to_vec()));
        let dict = DictionaryArray::<UInt32Type>::new(UInt32Array::from(keys.to_vec()), values);
        let schema = Arc::new(ArrowSchema::new(vec![Field::new(
            "sym",
            DataType::Dictionary(Box::new(DataType::UInt32), Box::new(DataType::Utf8)),
            true,
        )]));
        RecordBatch::try_new(schema, vec![Arc::new(dict) as ArrayRef]).unwrap()
    }

    fn cat_strings(df: &DataFrame) -> Vec<Option<String>> {
        let s = df.columns()[0]
            .as_materialized_series()
            .cast(&PlDataType::String)
            .unwrap();
        let s = s.str().unwrap();
        (0..df.height())
            .map(|i| s.get(i).map(str::to_owned))
            .collect()
    }

    #[test]
    fn delta_symbol_registry_interns_once_and_vstacks_across_batches() {
        // The connection dict grows; the registry registers only the new tail
        // each batch and keys (global codes) wrap straight into a Categorical.
        // Both batches share the registry's `Categories`, so they vstack.
        let mut dict = SymbolDict::new();
        dict.apply_delta(0, [b"a".as_slice(), b"b".as_slice()])
            .unwrap();
        let mut reg = SymbolRegistry::new();
        reg.sync(&dict).unwrap();
        let df1 = build_dataframe(
            sym_batch(&["a", "b"], &[Some(0), Some(1), Some(0)]),
            &[true],
            &reg,
        )
        .unwrap();

        dict.apply_delta(2, [b"c".as_slice()]).unwrap();
        reg.sync(&dict).unwrap();
        let df2 = build_dataframe(
            sym_batch(&["a", "b", "c"], &[Some(2), None, Some(1)]),
            &[true],
            &reg,
        )
        .unwrap();

        let mut df = df1;
        df.vstack_mut_owned(df2)
            .expect("registry Categoricals from different batches must vstack");
        assert!(matches!(
            df.columns()[0].dtype(),
            PlDataType::Categorical(_, _)
        ));
        assert_eq!(
            cat_strings(&df),
            vec![
                Some("a".into()),
                Some("b".into()),
                Some("a".into()),
                Some("c".into()),
                None,
                Some("b".into()),
            ]
        );
    }

    #[test]
    fn delta_symbol_registry_rebuilds_on_dict_reset() {
        let mut dict = SymbolDict::new();
        dict.apply_delta(0, [b"x".as_slice(), b"y".as_slice(), b"z".as_slice()])
            .unwrap();
        let mut reg = SymbolRegistry::new();
        reg.sync(&dict).unwrap();

        // CACHE_RESET: dict cleared then re-grown; code 0 must now be "p".
        dict.reset();
        dict.apply_delta(0, [b"p".as_slice()]).unwrap();
        reg.sync(&dict).unwrap();

        let df = build_dataframe(sym_batch(&["p"], &[Some(0)]), &[true], &reg).unwrap();
        assert_eq!(cat_strings(&df), vec![Some("p".into())]);
    }

    #[test]
    fn column_local_symbol_still_builds_via_fallback() {
        // delta_modes = false → the column-local path (cast + take), not the
        // registry, so a non-prefix per-batch dict is still correct.
        let reg = SymbolRegistry::new();
        let df = build_dataframe(
            sym_batch(&["L0", "L1"], &[Some(1), Some(0)]),
            &[false],
            &reg,
        )
        .unwrap();
        assert!(matches!(
            df.columns()[0].dtype(),
            PlDataType::Categorical(_, _)
        ));
        assert_eq!(cat_strings(&df), vec![Some("L1".into()), Some("L0".into())]);
    }
}
