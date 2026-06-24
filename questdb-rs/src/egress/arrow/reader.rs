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

//! Streaming `RecordBatchReader` adapter over a [`Cursor`].

use arrow_array::{RecordBatch, RecordBatchReader};
use arrow_schema::{ArrowError, SchemaRef};

use crate::egress::Cursor;
use crate::egress::arrow::convert::external_arrow_error;
use crate::egress::error::{Error, ErrorCode};

/// Adapter implementing [`arrow_array::RecordBatchReader`] over a
/// [`Cursor`]. Snapshots the first batch's Arrow schema at construction
/// and poisons on mid-stream schema drift. Failover semantics inherit
/// from [`Cursor::next_batch`](crate::egress::Cursor::next_batch).
pub struct CursorRecordBatchReader<'r, 'c> {
    cursor: &'c mut Cursor<'r>,
    schema: SchemaRef,
    pending: Option<RecordBatch>,
    poisoned: bool,
    /// `Cursor::failover_resets()` at the point `schema` was pinned. A
    /// later batch arriving with a higher count is the first frame of a
    /// transparently-replayed query (re-read from `batch_seq 0` on a new
    /// endpoint), so the pinned schema is re-snapshotted from it rather
    /// than treated as drift. `fetch_all_arrow` reads the same counter to
    /// discard its partial accumulation.
    resets_at_pin: u32,
}

impl<'r, 'c> CursorRecordBatchReader<'r, 'c> {
    pub(crate) fn new(cursor: &'c mut Cursor<'r>) -> Result<Self, Error> {
        let first = cursor.next_arrow_batch_inner(None, false)?.ok_or_else(|| {
            Error::new(
                ErrorCode::NoSchema,
                "no batch produced; nothing to snapshot",
            )
        })?;
        let schema = first.schema();
        let resets_at_pin = cursor.failover_resets();
        Ok(Self {
            cursor,
            schema,
            pending: Some(first),
            poisoned: false,
            resets_at_pin,
        })
    }

    /// Snapshotted schema. Same as the [`RecordBatchReader::schema`]
    /// trait method, exposed for callers without the trait imported.
    pub fn schema(&self) -> SchemaRef {
        self.schema.clone()
    }

    /// Reconnect count observed by the underlying cursor. `fetch_all_arrow`
    /// polls this between batches: an increase means the query was replayed
    /// from scratch, so anything accumulated so far must be dropped.
    pub(crate) fn failover_resets(&self) -> u32 {
        self.cursor.failover_resets()
    }
}

impl Iterator for CursorRecordBatchReader<'_, '_> {
    type Item = Result<RecordBatch, ArrowError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.poisoned {
            return None;
        }
        if let Some(rb) = self.pending.take() {
            return Some(Ok(rb));
        }
        // A transparent mid-query failover re-reads the result from
        // `batch_seq 0` on a new endpoint, so the pinned schema is
        // re-snapshotted from the first replayed batch instead of being
        // compared against it; the drift check resumes against the new
        // schema. Pass `None` (no drift check) for that first replayed
        // frame so the new node's batch 0 isn't rejected as drift.
        let drift_check = if self.cursor.failover_resets() == self.resets_at_pin {
            Some(&self.schema)
        } else {
            None
        };
        match self.cursor.next_arrow_batch_inner(drift_check, false) {
            Ok(Some(rb)) => {
                if self.cursor.failover_resets() != self.resets_at_pin {
                    self.schema = rb.schema();
                    self.resets_at_pin = self.cursor.failover_resets();
                } else if has_tentative_array(&self.schema) && rb.schema() != self.schema {
                    self.poisoned = true;
                    return Some(Err(external_arrow_error(Error::new(
                        ErrorCode::SchemaDrift,
                        "tentative→firm ndim upgrade is not representable in \
                         RecordBatchReader (schema must be stable for the \
                         reader's lifetime); use Cursor::next_arrow_batch \
                         to handle drift explicitly",
                    ))));
                }
                Some(Ok(rb))
            }
            Ok(None) => {
                self.poisoned = true;
                None
            }
            Err(e) => {
                self.poisoned = true;
                Some(Err(external_arrow_error(e)))
            }
        }
    }
}

/// True if any field carries [`metadata::ARRAY_DIM_TENTATIVE`](crate::egress::arrow::metadata::ARRAY_DIM_TENTATIVE).
/// Gates the tentative→firm ndim mid-stream upgrade.
pub fn has_tentative_array(schema: &SchemaRef) -> bool {
    schema.fields().iter().any(|f| {
        f.metadata()
            .get(crate::egress::arrow::metadata::ARRAY_DIM_TENTATIVE)
            .is_some_and(|v| v == "true")
    })
}

impl RecordBatchReader for CursorRecordBatchReader<'_, '_> {
    fn schema(&self) -> SchemaRef {
        self.schema.clone()
    }
}

/// Downcast an [`ArrowError`] produced by this adapter to the
/// underlying [`Error`]. Returns `None` for foreign Arrow errors.
pub fn try_downcast_questdb(err: &ArrowError) -> Option<&Error> {
    match err {
        ArrowError::ExternalError(boxed) => boxed.downcast_ref::<Error>(),
        _ => None,
    }
}
