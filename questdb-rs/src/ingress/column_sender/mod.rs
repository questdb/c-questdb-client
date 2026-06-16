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
//! - Flush chunks to publish them without waiting for ACKs, then call
//!   [`ColumnSender::sync`] to commit and wait at the requested [`AckLevel`].
//! - Drop the [`BorrowedSender`] to return its connection to the pool.

#[cfg(feature = "arrow")]
mod arrow_batch;
mod chunk;
mod conf;
mod conn;
mod db;
mod encoder;
mod numpy_wire;
mod sender;
mod validity;
mod wire;

#[cfg(feature = "arrow")]
pub use arrow_batch::ArrowColumnOverride;
pub use chunk::Chunk;
#[cfg(feature = "arrow")]
pub use chunk::ImportedArrowColumn;
pub use db::{BorrowedSender, QuestDb};
pub use numpy_wire::NumpyDtype;
pub use sender::{AckLevel, ColumnSender};
pub use validity::Validity;

/// Per-flush row-count ceiling shared across every column-sender input
/// path (`Chunk::column_*`, `Chunk::push_numpy_deferred`,
/// `Chunk::push_arrow_column`, `flush_arrow_batch`). Bounds:
///   * upstream allocations sized as `row_count * element_size`
///     so they cannot saturate `usize` or panic in `Vec::reserve`,
///   * validity bitmap byte-length (`ceil(bit_len / 8)`) to a value
///     well below `isize::MAX` on every supported target.
///
/// The FFI-side `MAX_ARROW_ARRAY_LENGTH` cap is derived from this
/// constant, so raising it here raises both in lockstep.
pub const MAX_CHUNK_ROWS: usize = 16 * 1024 * 1024;

const _: () = assert!(
    cfg!(target_endian = "little"),
    "column_sender bulk-copy fast paths assume a little-endian host; \
     QuestDB QWP wire encoding is little-endian."
);

#[doc(hidden)]
pub use db::OwnedSender;

#[cfg(feature = "_egress")]
#[doc(hidden)]
pub use db::{OwnedReader, ReaderPoolHandle};

/// Internals exposed for criterion benchmarks under
/// `questdb-rs/benches/`. Not part of the public API; bumped freely
/// without semver concerns.
#[doc(hidden)]
pub mod _bench_internals {
    use crate::Result;
    use crate::ingress::buffer::SymbolGlobalDict;

    use super::chunk::Chunk;
    use super::encoder::{EncodeScratch, encode_chunk_into};

    /// Opaque holder for the connection-scoped state the encoder needs.
    /// Lets benches reuse the encoder across iterations without promoting
    /// [`SymbolGlobalDict`] to the public API.
    pub struct BenchEncoderState {
        symbol_dict: SymbolGlobalDict,
        scratch: EncodeScratch,
    }

    impl Default for BenchEncoderState {
        fn default() -> Self {
            Self::new()
        }
    }

    impl BenchEncoderState {
        pub fn new() -> Self {
            Self {
                symbol_dict: SymbolGlobalDict::new(),
                scratch: EncodeScratch::new(),
            }
        }
    }

    /// Encode `chunk` into `out`. Mirrors [`encode_chunk_into`] but hides
    /// the internal-state types so the bench module never has to touch
    /// them.
    pub fn bench_encode_chunk_into(
        out: &mut Vec<u8>,
        chunk: &Chunk<'_>,
        state: &mut BenchEncoderState,
    ) -> Result<()> {
        encode_chunk_into(
            out,
            chunk,
            &mut state.symbol_dict,
            &mut state.scratch,
            false,
        )
    }
}
