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

//! QuestDB Wire Protocol (QWP) egress reader.
//!
//! Implements the client side of the QWP egress extension: a binary,
//! columnar, WebSocket-based read protocol for streaming query results
//! from QuestDB. The module bundles the wire codec foundation (frame
//! header, varint, message kinds, column type codes, errors), the
//! `RESULT_BATCH` decoder and column views, the symbol dict and
//! per-query schema, and — when `sync-reader-qwp-ws` is enabled — the WebSocket
//! transport and `Reader`/`Cursor`/`BatchView` streaming API.

// Sub-modules.
//
// `pub mod` modules (column, column_kind, config, reader, wire)
// are part of the navigable API surface — tests and examples take
// sub-paths through them (e.g. `egress::column::FixedColumn`,
// `egress::wire::flags`, `egress::reader::Terminal`).
//
// `pub(crate) mod` modules contain decoder/protocol internals. The
// few user-facing types they define (`Bind`, `ServerInfo`, `ServerRole`)
// are surfaced via the top-level `pub use` block below; everything
// else stays internal and is free to evolve without a breaking
// change.
#[cfg(feature = "arrow-egress")]
pub mod arrow;
pub(crate) mod auth;
pub(crate) mod binds;
pub mod column;
pub mod column_kind;
pub mod config;
pub(crate) mod decoder;
pub(crate) mod gorilla;
pub(crate) mod query_request;
#[cfg(feature = "sync-reader-qwp-ws")]
pub mod reader;
pub(crate) mod schema;
pub(crate) mod server_event;
pub(crate) mod symbol_dict;
#[cfg(feature = "sync-reader-qwp-ws")]
pub(crate) mod tls;
#[cfg(feature = "sync-reader-qwp-ws")]
pub(crate) mod tracker;
#[cfg(feature = "sync-reader-qwp-ws")]
pub(crate) mod transport;
pub mod wire;
#[cfg(feature = "sync-reader-qwp-ws")]
pub(crate) mod ws;

// Top-level public surface. Anything not listed here is either
// reachable only through a `pub mod` sub-path (the navigable
// internals — column views, wire codecs the tests pin) or is fully
// crate-private. Adding to this list commits the crate to a semver
// contract; trim aggressively.
pub use crate::ingress::CertificateAuthority;
pub use binds::{Bind, SimpleNullKind};
pub use column::{
    BinaryColumn, ColumnView, Decimal64Column, Decimal128Column, Decimal256Column,
    DoubleArrayColumn, FixedBytesColumn, FixedColumn, FixedWidth, GeohashColumn, Long256Column,
    LongArrayColumn, SymbolColumn, UuidColumn, Validity, VarcharColumn,
};
pub use column_kind::ColumnKind;
pub use config::{
    Compression, DEFAULT_COMPRESSION_LEVEL, DEFAULT_FAILOVER_BACKOFF_INITIAL_MS,
    DEFAULT_FAILOVER_BACKOFF_MAX_MS, DEFAULT_FAILOVER_ENABLED, DEFAULT_FAILOVER_MAX_ATTEMPTS,
    Endpoint, MAX_ADDRS, MAX_COMPRESSION_LEVEL, MAX_FAILOVER_BACKOFF_MAX_MS,
    MAX_FAILOVER_MAX_ATTEMPTS, MIN_COMPRESSION_LEVEL, ReaderConfig, Target, TlsVerify,
};
#[cfg(feature = "sync-reader-qwp-ws")]
pub use reader::{
    BatchView, Cursor, FailoverPhase, FailoverProgressEvent, FailoverResetEvent, Reader,
    ReaderQuery, ReaderStats, Terminal,
};
pub use server_event::{ServerInfo, ServerRole, UpgradeReject};
pub use symbol_dict::{SymbolDict, SymbolEntry};

/// Decoder internals re-exported for the in-crate criterion benchmark
/// at `benches/decoder.rs`. **Not** a public API surface: the names
/// are prefixed `_` and the module is `#[doc(hidden)]` precisely so
/// downstream consumers don't reach into it. May be renamed or
/// removed without notice; everything in here moves on the same
/// stability footing as `pub(crate)`.
#[doc(hidden)]
#[cfg(feature = "sync-reader-qwp-ws")]
pub mod _bench_internals {
    pub use crate::egress::decoder::{DecodedBatch, ZstdScratch, decode_result_batch};
    pub use crate::egress::schema::Schema;
    pub use crate::egress::symbol_dict::SymbolDict;
    pub use bytes::Bytes;

    /// Assemble an already-decoded [`DecodedBatch`] into an
    /// `arrow::array::RecordBatch`, mirroring the in-crate
    /// `Cursor::next_arrow_batch` assembly path (`batch_arrow_schema` +
    /// `batch_to_record_batch`) so a server-free decode→assemble
    /// benchmark can isolate the column-build cost on top of the raw
    /// decode. The egress `schema` and `dict` are the ones
    /// [`decode_result_batch`] populated for the same payload.
    #[cfg(feature = "arrow-egress")]
    pub fn bench_batch_to_record_batch(
        schema: &Schema,
        batch: DecodedBatch,
        dict: &SymbolDict,
    ) -> crate::error::Result<arrow::array::RecordBatch> {
        use std::sync::Arc;
        let arrow_schema = Arc::new(crate::egress::arrow::batch_arrow_schema(schema, &batch)?);
        crate::egress::arrow::batch_to_record_batch(arrow_schema, schema, batch, dict)
    }

    /// Full decode→assemble→polars path for the `→ polars DataFrame`
    /// decoder bench arm: assemble the decoded batch into a
    /// `RecordBatch` (see [`bench_batch_to_record_batch`]) and hand it
    /// to polars via the Arrow C Data Interface
    /// (`record_batch_to_dataframe`). This is the honest
    /// `decode_plus_assemble`-to-DataFrame microbench with no network.
    #[cfg(feature = "polars-egress")]
    pub fn bench_batch_to_polars(
        schema: &Schema,
        batch: DecodedBatch,
        dict: &SymbolDict,
    ) -> crate::error::Result<polars::frame::DataFrame> {
        let rb = bench_batch_to_record_batch(schema, batch, dict)?;
        crate::egress::arrow::polars::record_batch_to_dataframe(rb)
    }
}
