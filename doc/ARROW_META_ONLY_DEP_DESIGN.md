# Arrow dependency consolidation: meta-crate only

## Problem

`questdb-rs` and `questdb-rs-ffi` each declare the Arrow dependency twice
over: the meta crate `arrow` **and** four of its sub-crates
(`arrow-array`, `arrow-schema`, `arrow-buffer`, `arrow-data`) as separate
direct deps, all with the same `>=58, <60` range.

That gives the low-level arrow crates two independent resolution paths —
one via the `arrow` meta crate, one via our direct sub-crate deps. A fresh
resolve unifies them (both pick the newest in range), so normal builds are
fine. But the moment CI tries to pin arrow to an older version to test the
floor of the range, only the meta crate follows; the directly-declared
sub-crates keep floating to the newest, the family splits into two copies,
and `ArrayData` / `FFI_ArrowSchema` types from the two copies stop matching
(`mismatched types`). It also leaves a latent skew hazard: bumping `arrow`
without bumping `arrow-array` in lockstep desyncs the tree.

## Change

Depend only on the meta `arrow` crate (`default-features = false,
features = ["ffi"]`). Drop the four sub-crate deps. Migrate source imports
to the meta crate's re-export paths.

With a single arrow version knob, `cargo update arrow --precise <v>`
downgrades the whole family cleanly, the CI 58/59 matrix becomes trivial,
and skew is impossible.

## Path mapping (verified against arrow 59.0.0 source)

| From | To |
| --- | --- |
| `arrow_array::…` (incl. `types`, `builder`, `cast` modules, all array types, `make_array`, `ArrayRef`, `RecordBatch`, `RecordBatchReader`) | `arrow::array::…` |
| `arrow_array::ffi` | `arrow::ffi` |
| `arrow_data::{ArrayData, ArrayDataBuilder, layout}` | `arrow::array::…` |
| `arrow_schema::{Field, SchemaRef, DataType, IntervalUnit}` | `arrow::datatypes::…` |
| `arrow_buffer::{Buffer, BooleanBuffer, OffsetBuffer, NullBuffer}` | `arrow::buffer::…` |
| `arrow_buffer::i256` | `arrow::datatypes::i256` |

`arrow::array` is `pub use arrow_array::* + pub use arrow_data::{…, layout}`,
so array and array-data symbols collapse onto one module. `arrow::buffer`
is the `arrow_buffer::buffer` submodule; `i256` lives under
`arrow::datatypes`, not `arrow::buffer` — the one non-uniform case.

## Cargo.toml

- `questdb-rs`: remove the `arrow-array` / `arrow-schema` / `arrow-buffer`
  / `arrow-data` deps; `_arrow` feature drops the corresponding
  `dep:arrow-*` entries (keeps `dep:arrow`, `dep:aligned-vec`,
  `dep:bytes`). `aligned-vec` / `bytes` / dev-dep `half` remain reachable
  transitively through the meta crate.
- `questdb-rs-ffi`: remove the `arrow-array` dep; `arrow` feature drops
  `dep:arrow-array` (keeps `dep:arrow`).

## Verification

Both crates `cargo check` clean, on a consistent lock, at both ends of the
range:

- pin arrow `59.0.0` — `cargo check` `--features arrow,polars --tests`
  (`questdb-rs`) and `--features arrow` (`questdb-rs-ffi`);
- pin arrow `58.3.0` — same. With a single arrow dep the pin no longer
  splits the family, so this is the first honest floor check.

The true floor is whatever lowest 58.x compiles once the family is
consistent — to be confirmed after the consolidation, then reflected in
the `>=58.x, <60` requirement and the CI matrix versions.
