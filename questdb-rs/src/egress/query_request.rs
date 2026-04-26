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

//! `QUERY_REQUEST` (msg_kind `0x10`) builder + encoder.
//!
//! Frame layout (header omitted):
//!
//! ```text
//! msg_kind:       u8       0x10
//! request_id:     i64 LE   client-assigned, unique per connection
//! sql_length:     varint
//! sql_bytes:      bytes
//! initial_credit: varint   bytes; 0 = unbounded
//! bind_count:     varint
//! binds:          per egress::binds
//! ```

use std::net::Ipv4Addr;

use crate::egress::binds::{Bind, check_bindable, encode_bind};
use crate::egress::column_kind::ColumnKind;
use crate::egress::error::{Result, fmt};
use crate::egress::wire::header::{FrameHeader, HEADER_LEN};
use crate::egress::wire::msg_kind::MsgKind;
use crate::egress::wire::varint;

/// Per-spec hard limit on SQL text length (1 MiB UTF-8 bytes).
pub const MAX_SQL_BYTES: usize = 1024 * 1024;

/// Per-spec hard limit on bind-parameter count.
pub const MAX_BINDS: usize = 1024;

/// A complete, validated `QUERY_REQUEST` ready for serialization.
#[derive(Debug, Clone)]
pub struct QueryRequest {
    request_id: i64,
    sql: String,
    initial_credit: u64,
    binds: Vec<Bind>,
}

impl QueryRequest {
    /// Start building a request for the given SQL.
    pub fn builder<S: Into<String>>(sql: S) -> QueryRequestBuilder {
        QueryRequestBuilder {
            request_id: 0,
            sql: sql.into(),
            initial_credit: 0,
            binds: Vec::new(),
        }
    }

    pub fn request_id(&self) -> i64 {
        self.request_id
    }

    pub fn sql(&self) -> &str {
        &self.sql
    }

    pub fn initial_credit(&self) -> u64 {
        self.initial_credit
    }

    pub fn binds(&self) -> &[Bind] {
        &self.binds
    }

    /// Serialize this request as a complete framed message
    /// (12-byte header + payload) into `out`.
    ///
    /// `version` is the QWP version negotiated at HTTP-upgrade time and
    /// goes into the frame header; the server closes the connection on
    /// mismatch.
    pub fn encode(&self, version: u8, out: &mut Vec<u8>) -> Result<()> {
        let header_start = out.len();
        out.resize(out.len() + HEADER_LEN, 0);

        let payload_start = out.len();

        out.push(MsgKind::QueryRequest.as_u8());
        out.extend_from_slice(&self.request_id.to_le_bytes());
        varint::encode_u64(self.sql.len() as u64, out);
        out.extend_from_slice(self.sql.as_bytes());
        varint::encode_u64(self.initial_credit, out);
        varint::encode_u64(self.binds.len() as u64, out);
        for bind in &self.binds {
            encode_bind(bind, out)?;
        }

        let payload_len = out.len() - payload_start;
        let payload_len = u32::try_from(payload_len).map_err(|_| {
            fmt!(
                ProtocolError,
                "QUERY_REQUEST payload too large: {} bytes",
                payload_len
            )
        })?;

        let header = FrameHeader {
            version,
            flags: 0,
            table_count: 0,
            payload_length: payload_len,
        };
        let header_slot: &mut [u8; HEADER_LEN] = (&mut out[header_start..header_start + HEADER_LEN])
            .try_into()
            .expect("reserved HEADER_LEN bytes");
        header.write(header_slot);

        Ok(())
    }
}

/// Builder for [`QueryRequest`].
///
/// Bind position is implicit in call order (first `bind_*` → `$1`, etc.).
/// All `bind_*` methods are infallible; bind kind validation, SQL size,
/// and bind-count limits are enforced in [`build`](Self::build).
#[derive(Debug, Clone)]
pub struct QueryRequestBuilder {
    request_id: i64,
    sql: String,
    initial_credit: u64,
    binds: Vec<Bind>,
}

impl QueryRequestBuilder {
    /// Override the per-connection request id. Default `0`.
    pub fn request_id(mut self, id: i64) -> Self {
        self.request_id = id;
        self
    }

    /// Set the initial byte-credit window (`0` = unbounded). Default `0`.
    pub fn initial_credit(mut self, credit: u64) -> Self {
        self.initial_credit = credit;
        self
    }

    /// Append a typed bind parameter at the next position.
    pub fn bind(mut self, value: Bind) -> Self {
        self.binds.push(value);
        self
    }

    pub fn bind_null(self, kind: ColumnKind) -> Self {
        self.bind(Bind::Null(kind))
    }
    pub fn bind_bool(self, v: bool) -> Self {
        self.bind(Bind::Bool(v))
    }
    pub fn bind_i8(self, v: i8) -> Self {
        self.bind(Bind::I8(v))
    }
    pub fn bind_i16(self, v: i16) -> Self {
        self.bind(Bind::I16(v))
    }
    pub fn bind_i32(self, v: i32) -> Self {
        self.bind(Bind::I32(v))
    }
    pub fn bind_i64(self, v: i64) -> Self {
        self.bind(Bind::I64(v))
    }
    pub fn bind_f32(self, v: f32) -> Self {
        self.bind(Bind::F32(v))
    }
    pub fn bind_f64(self, v: f64) -> Self {
        self.bind(Bind::F64(v))
    }
    pub fn bind_varchar<S: Into<String>>(self, v: S) -> Self {
        self.bind(Bind::Varchar(v.into()))
    }
    pub fn bind_timestamp_micros(self, v: i64) -> Self {
        self.bind(Bind::TimestampMicros(v))
    }
    pub fn bind_timestamp_nanos(self, v: i64) -> Self {
        self.bind(Bind::TimestampNanos(v))
    }
    pub fn bind_date_millis(self, v: i64) -> Self {
        self.bind(Bind::DateMillis(v))
    }
    pub fn bind_uuid_bytes(self, v: [u8; 16]) -> Self {
        self.bind(Bind::Uuid(v))
    }
    pub fn bind_long256(self, v: [u8; 32]) -> Self {
        self.bind(Bind::Long256(v))
    }
    pub fn bind_char(self, v: u16) -> Self {
        self.bind(Bind::Char(v))
    }
    pub fn bind_ipv4(self, v: Ipv4Addr) -> Self {
        self.bind(Bind::Ipv4(v))
    }
    pub fn bind_decimal64(self, value: i64, scale: i8) -> Self {
        self.bind(Bind::Decimal64 { value, scale })
    }
    pub fn bind_decimal128(self, value: i128, scale: i8) -> Self {
        self.bind(Bind::Decimal128 { value, scale })
    }
    pub fn bind_decimal256(self, bytes: [u8; 32], scale: i8) -> Self {
        self.bind(Bind::Decimal256 { bytes, scale })
    }
    pub fn bind_geohash(self, value: u64, precision_bits: u8) -> Self {
        self.bind(Bind::Geohash {
            value,
            precision_bits,
        })
    }
    pub fn bind_binary<B: Into<Vec<u8>>>(self, v: B) -> Self {
        self.bind(Bind::Binary(v.into()))
    }
    pub fn bind_null_varchar(self) -> Self {
        self.bind(Bind::NullVarchar)
    }
    pub fn bind_null_binary(self) -> Self {
        self.bind(Bind::NullBinary)
    }
    pub fn bind_null_decimal64(self, scale: i8) -> Self {
        self.bind(Bind::NullDecimal64 { scale })
    }
    pub fn bind_null_decimal128(self, scale: i8) -> Self {
        self.bind(Bind::NullDecimal128 { scale })
    }
    pub fn bind_null_decimal256(self, scale: i8) -> Self {
        self.bind(Bind::NullDecimal256 { scale })
    }
    pub fn bind_null_geohash(self, precision_bits: u8) -> Self {
        self.bind(Bind::NullGeohash { precision_bits })
    }

    /// Validate and finalize.
    pub fn build(self) -> Result<QueryRequest> {
        if self.sql.len() > MAX_SQL_BYTES {
            return Err(fmt!(
                InvalidApiCall,
                "SQL too long: {} bytes (max {})",
                self.sql.len(),
                MAX_SQL_BYTES
            ));
        }
        if self.binds.len() > MAX_BINDS {
            return Err(fmt!(
                InvalidApiCall,
                "too many bind parameters: {} (max {})",
                self.binds.len(),
                MAX_BINDS
            ));
        }
        for (i, bind) in self.binds.iter().enumerate() {
            check_bindable(bind.kind()).map_err(|e| {
                fmt!(InvalidBind, "bind ${}: {}", i + 1, e.msg())
            })?;
        }
        Ok(QueryRequest {
            request_id: self.request_id,
            sql: self.sql,
            initial_credit: self.initial_credit,
            binds: self.binds,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::error::ErrorCode;
    use crate::egress::wire::header::MAGIC;

    fn parse_header(bytes: &[u8]) -> FrameHeader {
        FrameHeader::parse(bytes).unwrap()
    }

    #[test]
    fn no_binds_byte_exact() {
        let req = QueryRequest::builder("SELECT 1")
            .request_id(0x2A)
            .build()
            .unwrap();
        let mut buf = Vec::new();
        req.encode(1, &mut buf).unwrap();

        // Header: magic | v=1 | flags=0 | table_count=0 | payload_length
        assert_eq!(&buf[0..4], &MAGIC.to_le_bytes());
        let h = parse_header(&buf);
        assert_eq!(h.version, 1);
        assert_eq!(h.flags, 0);
        assert_eq!(h.table_count, 0);

        // Payload: 0x10 | i64 LE 0x2A | varint(8) | "SELECT 1" | varint(0) | varint(0)
        let payload = &buf[HEADER_LEN..];
        assert_eq!(payload[0], 0x10);
        assert_eq!(&payload[1..9], &0x2Ai64.to_le_bytes());
        assert_eq!(payload[9], 0x08); // varint sql_length
        assert_eq!(&payload[10..18], b"SELECT 1");
        assert_eq!(payload[18], 0x00); // varint initial_credit = 0
        assert_eq!(payload[19], 0x00); // varint bind_count = 0
        assert_eq!(payload.len(), 20);
        assert_eq!(h.payload_length as usize, payload.len());
    }

    #[test]
    fn with_mixed_binds_layout() {
        let req = QueryRequest::builder("X")
            .request_id(1)
            .bind_i64(42)
            .bind_varchar("hi")
            .bind_null(ColumnKind::Boolean)
            .build()
            .unwrap();
        let mut buf = Vec::new();
        req.encode(2, &mut buf).unwrap();
        let h = parse_header(&buf);
        assert_eq!(h.version, 2);

        let payload = &buf[HEADER_LEN..];
        // 0x10 | i64 LE 1 | varint(1)=0x01 | "X" | varint(0) | varint(3)=0x03
        // | bind1: 0x05 0x00 i64 LE 42
        // | bind2: 0x0F 0x00 [offsets 0,2 as u32_le ×2] 'h' 'i'
        // | bind3: 0x01 0x01 0x01
        let mut expected = vec![0x10];
        expected.extend_from_slice(&1i64.to_le_bytes());
        expected.push(0x01); // sql_length=1
        expected.push(b'X');
        expected.push(0x00); // initial_credit=0
        expected.push(0x03); // bind_count=3
        expected.extend_from_slice(&[0x05, 0x00]);
        expected.extend_from_slice(&42i64.to_le_bytes());
        expected.extend_from_slice(&[0x0F, 0x00]);
        expected.extend_from_slice(&0u32.to_le_bytes());
        expected.extend_from_slice(&2u32.to_le_bytes());
        expected.extend_from_slice(&[b'h', b'i']);
        expected.extend_from_slice(&[0x01, 0x01, 0x01]);
        assert_eq!(payload, expected.as_slice());
        assert_eq!(h.payload_length as usize, payload.len());
    }

    #[test]
    fn initial_credit_serialized() {
        let req = QueryRequest::builder("X")
            .initial_credit(0x4000)
            .build()
            .unwrap();
        let mut buf = Vec::new();
        req.encode(1, &mut buf).unwrap();
        let payload = &buf[HEADER_LEN..];
        // After 0x10 + 8-byte rid + varint(1) + 'X' = 11 bytes, then varint(0x4000)
        // varint(0x4000) = 0x80 0x80 0x01
        assert_eq!(&payload[11..14], &[0x80, 0x80, 0x01]);
    }

    #[test]
    fn sql_too_long_rejected() {
        let big = "a".repeat(MAX_SQL_BYTES + 1);
        let err = QueryRequest::builder(big).build().unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    }

    #[test]
    fn too_many_binds_rejected() {
        let mut b = QueryRequest::builder("X");
        for _ in 0..(MAX_BINDS + 1) {
            b = b.bind_i64(0);
        }
        let err = b.build().unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    }

    #[test]
    fn unsupported_bind_kind_rejected() {
        // Symbol bind not yet supported.
        let err = QueryRequest::builder("X")
            .bind(Bind::Null(ColumnKind::Symbol))
            .build()
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidBind);
        assert!(err.msg().contains("$1"));
    }

    #[test]
    fn header_payload_length_matches() {
        for binds in 0..50 {
            let mut b = QueryRequest::builder("SELECT * FROM t");
            for _ in 0..binds {
                b = b.bind_i64(0);
            }
            let req = b.build().unwrap();
            let mut buf = Vec::new();
            req.encode(1, &mut buf).unwrap();
            let h = parse_header(&buf);
            assert_eq!(
                h.payload_length as usize,
                buf.len() - HEADER_LEN,
                "binds={}",
                binds
            );
        }
    }
}
