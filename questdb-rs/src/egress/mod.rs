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
//! `RESULT_BATCH` decoder and column views, the symbol/schema
//! registries, and — when `sync-reader-ws` is enabled — the WebSocket
//! transport and `Reader`/`Cursor`/`BatchView` streaming API.

// Sub-modules.
//
// `pub mod` modules (column, column_kind, config, error, reader, wire)
// are part of the navigable API surface — tests and examples take
// sub-paths through them (e.g. `egress::column::FixedColumn`,
// `egress::wire::flags`, `egress::reader::Terminal`).
//
// `pub(crate) mod` modules contain decoder/protocol internals. The
// few user-facing types they define (`Bind`, `ServerInfo`, `ServerRole`)
// are surfaced via the top-level `pub use` block below; everything
// else stays internal and is free to evolve without a breaking
// change.
pub(crate) mod auth;
pub(crate) mod binds;
pub mod column;
pub mod column_kind;
pub mod config;
pub(crate) mod decoder;
pub mod error;
pub(crate) mod gorilla;
pub(crate) mod query_request;
#[cfg(feature = "sync-reader-ws")]
pub mod reader;
pub(crate) mod schema;
pub(crate) mod server_event;
pub(crate) mod symbol_dict;
#[cfg(feature = "sync-reader-ws")]
pub(crate) mod transport;
pub mod wire;

// Top-level public surface. Anything not listed here is either
// reachable only through a `pub mod` sub-path (the navigable
// internals — column views, wire codecs the tests pin) or is fully
// crate-private. Adding to this list commits the crate to a semver
// contract; trim aggressively.
pub use binds::Bind;
pub use column::{
    BinaryColumn, ColumnView, Decimal64Column, Decimal128Column, Decimal256Column,
    DoubleArrayColumn, FixedBytesColumn, FixedColumn, FixedWidth, GeohashColumn, Long256Column,
    LongArrayColumn, SymbolColumn, UuidColumn, Validity, VarcharColumn,
};
pub use column_kind::ColumnKind;
pub use config::{
    Compression, DEFAULT_FAILOVER_BACKOFF_INITIAL_MS, DEFAULT_FAILOVER_BACKOFF_MAX_MS,
    DEFAULT_FAILOVER_ENABLED, DEFAULT_FAILOVER_MAX_ATTEMPTS, Endpoint, MAX_ADDRS,
    MAX_FAILOVER_BACKOFF_MAX_MS, MAX_FAILOVER_MAX_ATTEMPTS, ReaderConfig, Target, TlsVerify,
};
pub use error::{Error, ErrorCode, Result};
#[cfg(feature = "sync-reader-ws")]
pub use reader::{BatchView, Cursor, FailoverEvent, Reader, ReaderQuery, Terminal};
pub use server_event::{ServerInfo, ServerRole};
