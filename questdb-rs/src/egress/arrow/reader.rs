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
}

impl<'r, 'c> CursorRecordBatchReader<'r, 'c> {
    pub(crate) fn new(cursor: &'c mut Cursor<'r>) -> Result<Self, Error> {
        let first = cursor.next_arrow_batch_inner(None)?.ok_or_else(|| {
            Error::new(
                ErrorCode::NoSchema,
                "no batch produced; nothing to snapshot",
            )
        })?;
        let schema = first.schema();
        Ok(Self {
            cursor,
            schema,
            pending: Some(first),
            poisoned: false,
        })
    }

    pub fn schema(&self) -> SchemaRef {
        self.schema.clone()
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
        match self.cursor.next_arrow_batch_inner(Some(&self.schema)) {
            Ok(Some(rb)) => {
                if has_tentative_array(&self.schema) {
                    self.schema = rb.schema();
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

fn has_tentative_array(schema: &SchemaRef) -> bool {
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
