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

//! FFI escape-hatch surface — **hidden, feature-gated, not semver-stable**.
//!
//! The `questdb-rs-ffi` C-ABI crate builds the C / C++ / Python clients on top
//! of [`QuestDb`]. C and Python cannot express Rust lifetimes, so the C ABI
//! cannot hand out the lifetime-bound `BorrowedColumnSender` /
//! `BorrowedRowSender` / `BorrowedReader` handles that the normal Rust API
//! uses. Instead it hands out *owned* (lifetime-free) handles that carry their
//! own pool reference internally, so a C caller can free its `questdb_db*`
//! before dropping outstanding `column_sender*` / `row_sender*` / `reader*`
//! handles. After the pool is closed those handles still return / drop safely;
//! new operations on them fail cleanly with `InvalidApiCall`.
//!
//! Those owned handles and the entry points that mint them live here, behind
//! the `ffi-support` feature, so they never appear on the public [`QuestDb`]
//! surface that ordinary Rust users see. **Rust users want the lifetime-bound
//! API** — [`QuestDb::borrow_column_sender`], [`QuestDb::borrow_row_sender`],
//! and (with egress) `QuestDb::borrow_reader` — which catches use-after-close
//! at compile time.
//!
//! Everything re-exported or defined here is `#[doc(hidden)]` via the module
//! gate and exempt from semver. Do not depend on it from regular Rust code.

use std::time::Duration;

use super::QuestDb;
use crate::Result;

pub use super::{OwnedColumnSender, OwnedRowSender};

#[cfg(feature = "_egress")]
pub use super::{OwnedReader, ReaderPoolHandle};

/// Borrow a column-major sender as an owned, lifetime-free handle.
///
/// FFI counterpart to [`QuestDb::borrow_column_sender`]; backs the C ABI's
/// `questdb_db_borrow_column_sender`.
pub fn borrow_column_sender_owned(db: &QuestDb) -> Result<OwnedColumnSender> {
    db.borrow_column_sender_owned()
}

/// Like [`borrow_column_sender_owned`] but retries the connect within `budget`
/// using the row API's reconnect backoff (the cluster may be electing a
/// primary). Backs the C ABI's `questdb_db_borrow_column_sender_with_retry`.
pub fn borrow_column_sender_owned_with_retry(
    db: &QuestDb,
    budget: Duration,
) -> Result<OwnedColumnSender> {
    db.borrow_column_sender_owned_with_retry(budget)
}

/// Borrow a **direct** (non-store-and-forward) column-major sender as an
/// owned, lifetime-free handle. FFI counterpart to
/// [`QuestDb::borrow_direct_column_sender`]; backs the C ABI's
/// `questdb_db_borrow_direct_column_sender`.
pub fn borrow_direct_column_sender_owned(db: &QuestDb) -> Result<OwnedColumnSender> {
    db.borrow_direct_column_sender_owned()
}

/// Like [`borrow_direct_column_sender_owned`] but retries the connect within
/// `budget` using the reconnect backoff. Backs the C ABI's
/// `questdb_db_borrow_direct_column_sender_with_retry`.
pub fn borrow_direct_column_sender_owned_with_retry(
    db: &QuestDb,
    budget: Duration,
) -> Result<OwnedColumnSender> {
    db.borrow_direct_column_sender_owned_with_retry(budget)
}

/// Borrow a row-major ([`crate::ingress::Sender`]) sender as an owned,
/// lifetime-free handle. FFI counterpart to [`QuestDb::borrow_row_sender`];
/// backs the C ABI's `questdb_db_borrow_row_sender`.
pub fn borrow_row_sender_owned(db: &QuestDb) -> Result<OwnedRowSender> {
    db.borrow_row_sender_owned()
}

/// Like [`borrow_row_sender_owned`] but retries the connect within `budget`
/// using the pool's reconnect backoff (`AuthError` / protocol-version errors
/// are terminal). `budget` `Duration::ZERO` makes a single attempt. Backs the
/// C ABI's `questdb_db_borrow_row_sender_with_retry`.
pub fn borrow_row_sender_owned_with_retry(
    db: &QuestDb,
    budget: Duration,
) -> Result<OwnedRowSender> {
    db.borrow_row_sender_owned_with_retry(budget)
}

/// The pool's failover budget (`reconnect_max_duration`, default 300s).
/// Exposed so the C ABI can let callers bound an overall failover deadline.
pub fn reconnect_max_duration(db: &QuestDb) -> Duration {
    db.reconnect_max_duration()
}

/// Borrow a query [`Reader`](crate::egress::Reader) as an owned, lifetime-free
/// handle. FFI counterpart to `QuestDb::borrow_reader`; backs the C ABI's
/// `questdb_db_borrow_reader`.
#[cfg(feature = "_egress")]
pub fn borrow_reader_owned(db: &QuestDb) -> crate::egress::error::Result<OwnedReader> {
    db.borrow_reader_owned()
}

/// An opaque pool reference the FFI's reader wrapper holds to return readers
/// without exposing the pool internals. Cheap to clone.
#[cfg(feature = "_egress")]
pub fn reader_pool_handle(db: &QuestDb) -> ReaderPoolHandle {
    db.reader_pool_handle()
}

/// Snapshot the number of idle (free) readers in the pool. Diagnostics only.
#[cfg(feature = "_egress")]
pub fn reader_free_count(db: &QuestDb) -> usize {
    db.reader_free_count()
}

/// Snapshot the number of currently-borrowed readers. Diagnostics only.
#[cfg(feature = "_egress")]
pub fn reader_in_use_count(db: &QuestDb) -> usize {
    db.reader_in_use_count()
}
