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

//! Per-query result schema.
//!
//! The schema rides the first `RESULT_BATCH` (`batch_seq == 0`) of a query,
//! inline in the table block right after `col_count`:
//!
//! ```text
//! per column:
//!     name_len: varint
//!     name:     bytes  UTF-8
//!     type_code: u8    QWP type code
//! ```
//!
//! There is no schema-mode byte and no schema id. Continuation batches
//! (`batch_seq > 0`) carry rows only and reuse the schema parsed from
//! `batch_seq == 0`; the reader holds it for the duration of the query.

use crate::egress::column_kind::ColumnKind;
use crate::egress::decoder::MAX_COLUMN_NAME_LENGTH;
use crate::egress::error::{Result, fmt};
use crate::egress::wire::varint;

/// A single column in a result schema.
///
/// Marked `#[non_exhaustive]` so future schema metadata (nullability,
/// precision, etc.) can be added without breaking downstream struct
/// literal constructions or pattern matches. Crate-internal sites still
/// use field-name literal syntax — `non_exhaustive` only restricts
/// out-of-crate construction and exhaustive matches.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SchemaColumn {
    pub name: String,
    pub kind: ColumnKind,
}

/// Ordered list of columns describing the layout of a `RESULT_BATCH`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Schema {
    columns: Vec<SchemaColumn>,
}

impl Schema {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_columns(columns: Vec<SchemaColumn>) -> Self {
        Self { columns }
    }

    pub fn len(&self) -> usize {
        self.columns.len()
    }

    pub fn is_empty(&self) -> bool {
        self.columns.is_empty()
    }

    pub fn columns(&self) -> &[SchemaColumn] {
        &self.columns
    }

    pub fn column(&self, i: usize) -> Option<&SchemaColumn> {
        self.columns.get(i)
    }

    /// Decode `col_count` inline column descriptors from the start of `bytes`.
    ///
    /// Wire layout per column: `name_len: varint, name: utf8, type_code: u8`.
    /// There is no schema-mode byte and no schema id — the schema rides the
    /// first `RESULT_BATCH` (`batch_seq == 0`) of a query inline, right after
    /// the table block's `col_count`. Returns the decoded schema and the
    /// number of bytes consumed (the column data follows immediately after).
    pub fn decode_inline(bytes: &[u8], col_count: usize) -> Result<(Schema, usize)> {
        let mut cursor = 0usize;
        // Clamp initial capacity by available bytes so a hostile `col_count`
        // can't trigger an oversized allocation before the loop discovers the
        // section is too short.
        let safe_cap = col_count.min(bytes.len());
        let mut cols = Vec::with_capacity(safe_cap);
        for i in 0..col_count {
            let (name_len, n) = varint::decode_usize(&bytes[cursor..])?;
            cursor += n;
            if name_len > MAX_COLUMN_NAME_LENGTH {
                return Err(fmt!(
                    ProtocolError,
                    "schema column {} name length {} exceeds max {}",
                    i,
                    name_len,
                    MAX_COLUMN_NAME_LENGTH
                ));
            }
            let name_end = cursor
                .checked_add(name_len)
                .ok_or_else(|| fmt!(ProtocolError, "schema column {} name length overflow", i))?;
            if name_end > bytes.len() {
                return Err(fmt!(ProtocolError, "schema column {} name truncated", i));
            }
            let name = std::str::from_utf8(&bytes[cursor..name_end])
                .map_err(|e| {
                    fmt!(
                        InvalidUtf8,
                        "schema column {} name not valid UTF-8: {}",
                        i,
                        e
                    )
                })?
                .to_string();
            cursor = name_end;
            if cursor >= bytes.len() {
                return Err(fmt!(
                    ProtocolError,
                    "schema column {} truncated before type_code",
                    i
                ));
            }
            let kind = ColumnKind::from_u8(bytes[cursor])?;
            cursor += 1;
            cols.push(SchemaColumn { name, kind });
        }
        Ok((Schema::from_columns(cols), cursor))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::error::ErrorCode;
    use crate::egress::wire::varint::encode_u64;

    fn build_inline(cols: &[(&str, ColumnKind)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, kind) in cols {
            encode_u64(name.len() as u64, &mut out);
            out.extend_from_slice(name.as_bytes());
            out.push(kind.as_u8());
        }
        out
    }

    #[test]
    fn decode_inline_two_columns() {
        let bytes = build_inline(&[
            ("ts", ColumnKind::TimestampNanos),
            ("v", ColumnKind::Double),
        ]);
        let (schema, consumed) = Schema::decode_inline(&bytes, 2).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(schema.len(), 2);
        assert_eq!(schema.column(0).unwrap().name, "ts");
        assert_eq!(schema.column(0).unwrap().kind, ColumnKind::TimestampNanos);
        assert_eq!(schema.column(1).unwrap().name, "v");
        assert_eq!(schema.column(1).unwrap().kind, ColumnKind::Double);
    }

    #[test]
    fn decode_inline_zero_columns() {
        let (schema, consumed) = Schema::decode_inline(&[], 0).unwrap();
        assert!(schema.is_empty());
        assert_eq!(consumed, 0);
    }

    #[test]
    fn decode_inline_stops_at_schema_end() {
        // Schema for one column followed by unrelated column-data bytes; the
        // decoder must consume only the schema and leave the rest.
        let mut bytes = build_inline(&[("a", ColumnKind::Int)]);
        let schema_len = bytes.len();
        bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let (schema, consumed) = Schema::decode_inline(&bytes, 1).unwrap();
        assert_eq!(consumed, schema_len);
        assert_eq!(schema.column(0).unwrap().name, "a");
    }

    #[test]
    fn decode_inline_truncated_rejected() {
        let mut bytes = build_inline(&[("col", ColumnKind::Long)]);
        bytes.pop(); // drop the type_code
        let err = Schema::decode_inline(&bytes, 1).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtocolError);
    }

    #[test]
    fn decode_inline_bad_type_code_rejected() {
        let mut bytes = Vec::new();
        encode_u64(1, &mut bytes);
        bytes.extend_from_slice(b"c");
        bytes.push(0xFF); // not a valid QWP type code
        let err = Schema::decode_inline(&bytes, 1).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtocolError);
    }
}
