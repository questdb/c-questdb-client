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

//! Per-batch schema and the per-connection registry.
//!
//! Each `RESULT_BATCH` carries a schema section preceding the column data:
//!
//! ```text
//! schema_mode: u8     0x00 = full, 0x01 = reference
//! schema_id:   varint always present
//! [if full]: col_count varint, then per-column:
//!     name_len: varint
//!     name:     bytes  UTF-8
//!     type_code: u8    QWP type code
//! ```
//!
//! Reference mode reuses a previously seen `schema_id`. The registry is
//! cleared by `CACHE_RESET` with the schemas bit; post-reset ids may
//! collide with pre-reset ids.

use std::collections::HashMap;

use crate::egress::column_kind::ColumnKind;
use crate::egress::decoder::MAX_COLUMN_NAME_LENGTH;
use crate::egress::error::{Result, fmt};
use crate::egress::wire::varint;

/// Hard cap on registered schema ids per connection. Mirrors
/// `MAX_SCHEMAS_PER_CONNECTION` in the Java reference client. A hostile
/// or buggy server could otherwise stream `RESULT_BATCH` frames with
/// monotonically increasing `schema_id` values and grow this map without
/// bound; the soft `RESET_MASK_SCHEMAS` cap is meant to prevent this on
/// well-behaved servers but the client must not depend on that.
pub(crate) const MAX_SCHEMAS_PER_CONNECTION: usize = 65_535;

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
}

/// Wire-mode discriminator (the `schema_mode` byte).
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SchemaMode {
    Full = 0x00,
    Reference = 0x01,
}

impl SchemaMode {
    pub fn from_u8(byte: u8) -> Result<Self> {
        Ok(match byte {
            0x00 => SchemaMode::Full,
            0x01 => SchemaMode::Reference,
            other => return Err(fmt!(ProtocolError, "unknown schema_mode 0x{:02X}", other)),
        })
    }
}

/// Outcome of decoding a schema section.
#[derive(Debug, Clone, Copy)]
pub struct DecodedSchema {
    /// The schema id this batch refers to.
    pub schema_id: u64,
    /// `true` when the registry was just populated with this id.
    pub was_full: bool,
    /// Wire bytes consumed.
    pub bytes_consumed: usize,
}

/// Per-connection mapping `schema_id -> Schema`.
#[derive(Debug, Default, Clone)]
pub struct SchemaRegistry {
    by_id: HashMap<u64, Schema>,
}

impl SchemaRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    pub fn get(&self, id: u64) -> Option<&Schema> {
        self.by_id.get(&id)
    }

    pub fn insert(&mut self, id: u64, schema: Schema) {
        self.by_id.insert(id, schema);
    }

    pub fn remove(&mut self, id: u64) -> Option<Schema> {
        self.by_id.remove(&id)
    }

    /// Triggered by `CACHE_RESET` with the schemas bit.
    pub fn reset(&mut self) {
        self.by_id.clear();
    }

    /// Decode the `schema_mode`+`schema_id`+(optional full-schema) preamble
    /// from `bytes`. On `Full`, populates the registry with `col_count`
    /// columns (the value lives in the table block, not the schema section).
    /// On `Reference`, the referenced `schema_id` must already be registered.
    pub fn decode_section(&mut self, bytes: &[u8], col_count: usize) -> Result<DecodedSchema> {
        if bytes.is_empty() {
            return Err(fmt!(ProtocolError, "schema section truncated: empty"));
        }
        let mode = SchemaMode::from_u8(bytes[0])?;
        let mut cursor = 1usize;
        let (schema_id, n) = varint::decode_u64(&bytes[cursor..])?;
        cursor += n;

        match mode {
            SchemaMode::Reference => {
                let schema = self.by_id.get(&schema_id).ok_or_else(|| {
                    fmt!(
                        ProtocolError,
                        "schema reference {} not in registry",
                        schema_id
                    )
                })?;
                if schema.len() != col_count {
                    return Err(fmt!(
                        ProtocolError,
                        "schema {} has {} columns but table block declares {}",
                        schema_id,
                        schema.len(),
                        col_count
                    ));
                }
                Ok(DecodedSchema {
                    schema_id,
                    was_full: false,
                    bytes_consumed: cursor,
                })
            }
            SchemaMode::Full => {
                // Bound the per-connection schema map. A new schema id only
                // counts if it isn't already registered; replacing an
                // existing id is fine.
                if !self.by_id.contains_key(&schema_id)
                    && self.by_id.len() >= MAX_SCHEMAS_PER_CONNECTION
                {
                    return Err(fmt!(
                        ProtocolError,
                        "schema registry full: {} entries (max {}); \
                         server must emit CACHE_RESET(schemas) before \
                         registering new schemas",
                        self.by_id.len(),
                        MAX_SCHEMAS_PER_CONNECTION
                    ));
                }
                // Clamp initial capacity by remaining bytes so a hostile
                // `col_count` can't trigger an oversized allocation before
                // the loop discovers the section is too short.
                let safe_cap = col_count.min(bytes.len().saturating_sub(cursor));
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
                    let name_end = cursor.checked_add(name_len).ok_or_else(|| {
                        fmt!(ProtocolError, "schema column {} name length overflow", i)
                    })?;
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
                self.by_id.insert(schema_id, Schema::from_columns(cols));
                Ok(DecodedSchema {
                    schema_id,
                    was_full: true,
                    bytes_consumed: cursor,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::error::ErrorCode;
    use crate::egress::wire::varint::encode_u64;

    fn build_full(schema_id: u64, cols: &[(&str, ColumnKind)]) -> Vec<u8> {
        let mut out = vec![SchemaMode::Full as u8];
        encode_u64(schema_id, &mut out);
        // No col_count varint: it lives in the table block, not the schema section.
        for (name, kind) in cols {
            encode_u64(name.len() as u64, &mut out);
            out.extend_from_slice(name.as_bytes());
            out.push(kind.as_u8());
        }
        out
    }

    fn build_ref(schema_id: u64) -> Vec<u8> {
        let mut out = vec![SchemaMode::Reference as u8];
        encode_u64(schema_id, &mut out);
        out
    }

    #[test]
    fn decode_full_schema() {
        let bytes = build_full(
            7,
            &[
                ("ts", ColumnKind::TimestampNanos),
                ("v", ColumnKind::Double),
            ],
        );
        let mut reg = SchemaRegistry::new();
        let r = reg.decode_section(&bytes, 2).unwrap();
        assert_eq!(r.schema_id, 7);
        assert!(r.was_full);
        assert_eq!(r.bytes_consumed, bytes.len());
        let schema = reg.get(7).unwrap();
        assert_eq!(schema.len(), 2);
        assert_eq!(schema.column(0).unwrap().name, "ts");
        assert_eq!(schema.column(0).unwrap().kind, ColumnKind::TimestampNanos);
        assert_eq!(schema.column(1).unwrap().name, "v");
        assert_eq!(schema.column(1).unwrap().kind, ColumnKind::Double);
    }

    #[test]
    fn decode_reference_after_full() {
        let mut reg = SchemaRegistry::new();
        let full = build_full(3, &[("a", ColumnKind::Int)]);
        reg.decode_section(&full, 1).unwrap();
        let r = reg.decode_section(&build_ref(3), 1).unwrap();
        assert_eq!(r.schema_id, 3);
        assert!(!r.was_full);
        assert_eq!(reg.get(3).unwrap().column(0).unwrap().name, "a");
    }

    #[test]
    fn reference_to_unknown_id_rejected() {
        let mut reg = SchemaRegistry::new();
        let err = reg.decode_section(&build_ref(99), 0).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtocolError);
        assert!(err.msg().contains("99"));
    }

    #[test]
    fn unknown_schema_mode_rejected() {
        let mut reg = SchemaRegistry::new();
        let bytes = vec![0x05, 0x00];
        let err = reg.decode_section(&bytes, 0).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtocolError);
    }

    #[test]
    fn truncated_full_schema_rejected() {
        let mut bytes = build_full(1, &[("col", ColumnKind::Long)]);
        bytes.pop(); // drop the type_code
        let mut reg = SchemaRegistry::new();
        let err = reg.decode_section(&bytes, 1).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtocolError);
    }

    #[test]
    fn empty_section_rejected() {
        let mut reg = SchemaRegistry::new();
        let err = reg.decode_section(&[], 0).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtocolError);
    }

    #[test]
    fn reset_clears_registry() {
        let mut reg = SchemaRegistry::new();
        reg.decode_section(&build_full(1, &[("c", ColumnKind::Int)]), 1)
            .unwrap();
        reg.decode_section(&build_full(2, &[("c", ColumnKind::Int)]), 1)
            .unwrap();
        assert_eq!(reg.len(), 2);
        reg.reset();
        assert_eq!(reg.len(), 0);
        assert!(reg.get(1).is_none());
    }

    #[test]
    fn full_replaces_existing_id() {
        let mut reg = SchemaRegistry::new();
        reg.decode_section(&build_full(5, &[("a", ColumnKind::Int)]), 1)
            .unwrap();
        reg.decode_section(&build_full(5, &[("b", ColumnKind::Long)]), 1)
            .unwrap();
        assert_eq!(reg.get(5).unwrap().column(0).unwrap().name, "b");
        assert_eq!(
            reg.get(5).unwrap().column(0).unwrap().kind,
            ColumnKind::Long
        );
    }

    #[test]
    fn zero_column_schema_is_valid() {
        let mut reg = SchemaRegistry::new();
        reg.decode_section(&build_full(0, &[]), 0).unwrap();
        assert!(reg.get(0).unwrap().is_empty());
    }
}
