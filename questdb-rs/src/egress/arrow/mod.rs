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
pub use reader::{CursorRecordBatchReader, try_downcast_questdb};

pub(crate) use convert::batch_to_record_batch;
pub(crate) use schema::{batch_arrow_schema, schemas_equal};

pub mod metadata {
    pub const COLUMN_TYPE: &str = "questdb.column_type";
    pub const DESIGNATED_TIMESTAMP: &str = "questdb.designated_timestamp";
    pub const DESIGNATED_TIMESTAMP_ORDER: &str = "questdb.designated_timestamp_order";
    pub const GEOHASH_BITS: &str = "questdb.geohash_bits";
    pub const SYMBOL: &str = "questdb.symbol";
    pub const ARRAY_DIM: &str = "questdb.array_dim";
    pub const ARROW_EXTENSION_NAME: &str = "ARROW:extension:name";
    pub const EXT_ARROW_UUID: &str = "arrow.uuid";
}
