//! Transport-neutral Arrow field-metadata keys, shared by both the ingress
//! Arrow encoder (`RecordBatch` → `Buffer`) and the egress Arrow adapter
//! (`Cursor` → `RecordBatch`). Lives here — rather than under `egress::arrow`
//! — so a sender-only `arrow-ingress` build can reference the keys without
//! pulling in the egress reader. The egress adapter re-exports this module as
//! `egress::arrow::metadata` for backwards-compatible paths.
//!
//! These keys are written into the `Arc<Field>` of every column the client
//! emits, and read back by `classify` on ingress and by mid-stream drift
//! detection (`schemas_equal`).

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
