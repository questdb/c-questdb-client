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

//! Columnar payload support for the unified QWP/WebSocket ingress sender.
//!
//! [`Chunk`] and Arrow batches are payload orientations accepted by the same
//! [`crate::BorrowedSender`] that flushes row-built [`crate::ingress::Buffer`]
//! values. The columnar path ingests Pandas/Polars DataFrames without adding
//! per-row conversion, copies, or dispatch. A [`Chunk`] borrows caller-owned
//! column buffers until the flush completes, while [`crate::BorrowedSender`]
//! holds the pooled connection whose reusable outbound buffer owns the encoded
//! frame.
//!
//! The user model is `DataFrame → Table`:
//!
//! - Open a connection pool with [`crate::QuestDb::connect`].
//! - Borrow a sender with [`crate::QuestDb::borrow_sender`].
//! - Build a [`Chunk`] of column buffers for one table, then pin a
//!   designated timestamp on it.
//! - Publish a batch and wait for the server to commit it in one call with
//!   [`PooledSenderCore::flush_and_wait`] (the common safe shape: "send this batch
//!   and return when it is committed"). To pipeline many batches for
//!   throughput instead, publish each with [`PooledSenderCore::flush`] and drain
//!   once at the end with [`PooledSenderCore::sync`] at the requested
//!   [`crate::ingress::AckLevel`].
//! - Drop the [`crate::BorrowedSender`] to return its connection to the pool.
//!
//! ```ignore
//! let mut sender = db.borrow_sender()?;
//! let mut chunk = Chunk::new("trades");
//! chunk.column_f64("price", &prices, None)?;
//! chunk.at_nanos(&timestamps_ns)?;
//! // One call: publish + wait until the server WAL-commits this batch.
//! sender.flush_and_wait(&mut chunk, crate::ingress::AckLevel::Ok)?;
//! ```

#[cfg(feature = "arrow-ingress")]
mod arrow_batch;
mod chunk;
pub(crate) mod conn;
pub(crate) mod encoder;
mod numpy_wire;
mod sender;
mod validity;
mod wire;

#[cfg(feature = "arrow-ingress")]
pub use arrow_batch::ArrowColumnOverride;
pub use chunk::Chunk;
#[cfg(feature = "arrow-ingress")]
pub use chunk::ImportedArrowColumn;
pub use numpy_wire::NumpyDtype;
#[doc(hidden)]
pub use sender::DirectSenderCore;
pub use sender::PooledSenderCore;
pub use validity::Validity;

/// Per-flush row-count ceiling shared across every columnar input
/// path (`Chunk::column_*`, `Chunk::push_numpy_deferred`,
/// `Chunk::push_arrow_column`, `flush_arrow_batch_*`). Bounds:
///   * upstream allocations sized as `row_count * element_size`
///     so they cannot saturate `usize` or panic in `Vec::reserve`,
///   * validity bitmap byte-length (`ceil(bit_len / 8)`) to a value
///     well below `isize::MAX` on every supported target.
///
/// The FFI-side `MAX_ARROW_ARRAY_LENGTH` cap is derived from this
/// constant, so raising it here raises both in lockstep.
pub const MAX_CHUNK_ROWS: usize = 16 * 1024 * 1024;

/// Per-column ceiling on a categorical / symbol dictionary's distinct-entry
/// count, mirroring the connection-scoped symbol-dictionary cap. Independent of
/// [`MAX_CHUNK_ROWS`] (which bounds row counts): a dictionary holds distinct
/// values, of which there can be far more than a chunk has rows. The FFI
/// `dict_offsets` length bound is derived from this (`entries + 1`).
pub const MAX_SYMBOL_DICT_ENTRIES: usize = crate::ingress::buffer::MAX_CONN_SYMBOL_DICT_SIZE;

/// Default rows per chunk for DataFrame / Arrow ingestion helpers. Only a
/// pipelining-granularity knob: the column sender splits any frame that exceeds
/// the negotiated batch cap regardless of this value. Divisible by 8 so it
/// never forces validity-bitmap realignment.
///
/// Each language binding hardcodes this same literal (e.g. the Python client's
/// `DEFAULT_MAX_CHUNK_ROWS`); keep them in sync when changing it. Tests on both
/// sides pin the value so a change cannot drift silently.
pub const DEFAULT_MAX_CHUNK_ROWS: usize = 16_384;

// Pin the literal: changing the value above forces this assert and the binding
// tests to be updated together, so the cross-binding default can't drift.
const _: () = assert!(DEFAULT_MAX_CHUNK_ROWS == 16_384);

const _: () = assert!(
    cfg!(target_endian = "little"),
    "column_sender bulk-copy fast paths assume a little-endian host; \
     QuestDB QWP wire encoding is little-endian."
);

pub(crate) fn qwp_frame_size_error(encoded_len: usize, max_buf_size: usize) -> crate::Error {
    crate::error::fmt!(
        BatchTooLarge,
        "QWP frame ({} bytes) exceeds max_buf_size ({} bytes)",
        encoded_len,
        max_buf_size
    )
}

/// Delivery classification surfaced to the C FFI so the Arrow `_and_wait`
/// entry points can decide whether to re-export the caller's batch. Not part
/// of the public Rust API surface (the public `*_and_wait` methods return
/// `Result<()>`). Unlike the owned pool handles, this is a sender-result type,
/// so it stays on the `column_sender` surface rather than moving to
/// [`crate::ffi_support`].
#[doc(hidden)]
pub use sender::FlushFailure;

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
    /// `SymbolGlobalDict` to the public API.
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

    /// Encode `chunk` into `out`. Mirrors `encode_chunk_into` but hides
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
