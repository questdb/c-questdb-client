//! Apache Arrow egress adapter. See `doc/QUESTDB_ARROW_INTEGRATION_DESIGN.md`.

pub(crate) mod convert;
#[cfg(feature = "polars-egress")]
pub mod polars;
pub(crate) mod reader;
pub(crate) mod schema;

#[cfg(test)]
mod tests;

pub use convert::external_arrow_error;
#[cfg(feature = "polars-egress")]
pub use polars::CursorPolarsIter;
pub use reader::{CursorRecordBatchReader, has_tentative_array, try_downcast_questdb};

pub(crate) use convert::{
    SymbolBuildScratch, SymbolValuesCache, batch_to_record_batch, batch_to_record_batch_with,
};
pub(crate) use schema::{batch_arrow_schema, schemas_equal};

/// Field-metadata keys this client writes into the `Arc<Field>` of every
/// column it emits. Now homed in the transport-neutral [`crate::arrow_meta`]
/// (so the ingress encoder can share them); re-exported here to keep the
/// `egress::arrow::metadata::*` paths working.
pub use crate::arrow_meta as metadata;
