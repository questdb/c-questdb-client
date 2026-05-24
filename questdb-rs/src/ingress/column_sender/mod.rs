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

//! Column-major sender for QWP/WebSocket.
//!
//! This is a separate API surface from [`crate::ingress::Sender`] / [`crate::ingress::Buffer`].
//! It exists to ingest **Pandas/Polars DataFrames into QuestDB at the maximum
//! throughput the QWP/WebSocket wire allows**. See `doc/COLUMN_SENDER_PLAN.md`
//! for the design rationale.
//!
//! The user model is `DataFrame → Table`:
//!
//! - Open a connection pool with [`QuestDb::connect`].
//! - Borrow a sender with [`QuestDb::borrow_sender`].
//! - Build a [`Chunk`] of column buffers for one table, then pin a
//!   designated timestamp on it.
//! - Flush the chunk synchronously; the call blocks until the server
//!   acknowledges at the requested [`AckLevel`].
//! - Drop the [`BorrowedSender`] to return its connection to the pool.

mod chunk;
mod conf;
mod db;
mod encoder;
mod sender;
mod validity;
mod wire;

pub use chunk::Chunk;
pub use db::{BorrowedSender, QuestDb};
pub use sender::{AckLevel, ColumnSender};
pub use validity::Validity;

#[doc(hidden)]
pub use db::OwnedSender;

/// Internals exposed for criterion benchmarks under
/// `questdb-rs/benches/`. Not part of the public API; bumped freely
/// without semver concerns.
#[doc(hidden)]
pub mod _bench_internals {
    use crate::Result;
    use crate::ingress::buffer::SymbolGlobalDict;

    use super::chunk::Chunk;
    use super::encoder::{SchemaRegistry, encode_chunk};

    /// Opaque holder for the connection-scoped state the encoder needs.
    /// Lets benches reuse the encoder across iterations without
    /// promoting [`SchemaRegistry`] / [`SymbolGlobalDict`] to the
    /// public API.
    pub struct BenchEncoderState {
        schema_registry: SchemaRegistry,
        symbol_dict: SymbolGlobalDict,
    }

    impl Default for BenchEncoderState {
        fn default() -> Self {
            Self::new()
        }
    }

    impl BenchEncoderState {
        pub fn new() -> Self {
            Self {
                schema_registry: SchemaRegistry::new(),
                symbol_dict: SymbolGlobalDict::new(),
            }
        }
    }

    /// Encode `chunk` against `state`. Mirrors [`encode_chunk`] but
    /// hides the internal-state types so the bench module never has to
    /// touch them.
    pub fn bench_encode_chunk(chunk: &Chunk, state: &mut BenchEncoderState) -> Result<Vec<u8>> {
        encode_chunk(chunk, &mut state.schema_registry, &mut state.symbol_dict)
    }
}
