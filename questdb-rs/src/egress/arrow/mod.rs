//! Apache Arrow egress adapter. See `doc/QUESTDB_ARROW_INTEGRATION_DESIGN.md`.

pub(crate) mod convert;
#[cfg(feature = "polars")]
pub mod polars;
pub(crate) mod reader;
pub(crate) mod schema;

#[cfg(test)]
mod tests;

pub use convert::external_arrow_error;
#[cfg(feature = "polars")]
pub use polars::CursorPolarsIter;
pub use reader::{CursorRecordBatchReader, has_tentative_array, try_downcast_questdb};

pub(crate) use convert::batch_to_record_batch;
pub(crate) use schema::{batch_arrow_schema, schemas_equal};

/// Field-metadata keys this client writes into the `Arc<Field>` of
/// every column it emits via the Arrow egress adapter, plus the
/// standard Arrow extension-name key. Read by `classify` on ingress
/// and by mid-stream drift detection (`schemas_equal`).
pub mod metadata {
    /// Carries the QuestDB native column type when the Arrow type
    /// alone is ambiguous (e.g. `Int8` → `byte`, `UInt16` → `char`).
    pub const COLUMN_TYPE: &str = "questdb.column_type";
    /// `"true"` on the field that is the table's designated timestamp.
    /// Informational only — not load-bearing for drift detection.
    pub const DESIGNATED_TIMESTAMP: &str = "questdb.designated_timestamp";
    /// `"asc"` / `"desc"`. Informational only.
    pub const DESIGNATED_TIMESTAMP_ORDER: &str = "questdb.designated_timestamp_order";
    /// Geohash precision in bits (1..=60). Required when the QuestDB
    /// native column kind is `geohash*`.
    pub const GEOHASH_BITS: &str = "questdb.geohash_bits";
    /// Marks a UTF-8 / dictionary column as the QuestDB `SYMBOL` kind.
    pub const SYMBOL: &str = "questdb.symbol";
    /// Native ARRAY dimensionality.
    pub const ARRAY_DIM: &str = "questdb.array_dim";
    /// `"true"` when `ARRAY_DIM` is a placeholder from an empty batch;
    /// drift detection accepts any opposite ndim until firmed up.
    pub const ARRAY_DIM_TENTATIVE: &str = "questdb.array_dim_tentative";
    /// Standard Apache Arrow extension-name field-metadata key.
    pub const ARROW_EXTENSION_NAME: &str = "ARROW:extension:name";
    /// Value used in [`ARROW_EXTENSION_NAME`] to mark a
    /// `FixedSizeBinary(16)` column as the canonical Arrow UUID.
    pub const EXT_ARROW_UUID: &str = "arrow.uuid";
}
