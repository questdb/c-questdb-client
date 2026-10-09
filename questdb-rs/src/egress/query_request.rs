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
//! query_flags:    varint   optional trailer; omitted when 0
//! timeout_ms:     varint   present iff query_flags & QUERY_FLAG_TIMEOUT
//! ```

use std::net::Ipv4Addr;

use crate::egress::binds::{Bind, SimpleNullKind, check_bindable, encode_bind};
use crate::egress::wire::msg_kind::MsgKind;
use crate::egress::wire::varint;
use crate::error::{Result, fmt};

/// Per-spec hard limit on SQL text length (1 MiB UTF-8 bytes).
pub const MAX_SQL_BYTES: usize = 1024 * 1024;

/// Per-spec hard limit on bind-parameter count.
pub const MAX_BINDS: usize = 1024;

/// `query_flags` bit: reset the connection SYMBOL dict before this query
/// (query-scoped dict). Only honoured by servers advertising `CAP_QUERY_FLAGS`.
pub const QUERY_FLAG_RESET_DICT: u64 = 0x01;

/// `query_flags` bit: a `timeout_ms: varint` field follows the `query_flags`
/// varint. Only honoured by servers advertising `CAP_QUERY_TIMEOUT`.
///
/// The server rejects a missing, truncated, zero or negative `timeout_ms`
/// with `STATUS_PARSE_ERROR`, so "no timeout" is expressed by leaving this
/// bit clear rather than by sending `0`.
pub const QUERY_FLAG_TIMEOUT: u64 = 0x02;

/// A complete, validated `QUERY_REQUEST` ready for serialization.
#[derive(Debug, Clone)]
pub struct QueryRequest {
    request_id: i64,
    sql: String,
    initial_credit: u64,
    binds: Vec<Bind>,
    query_flags: u64,
    /// Per-query timeout in milliseconds. Serialized iff
    /// [`QUERY_FLAG_TIMEOUT`] is set in `query_flags`; `build` keeps the
    /// two in step.
    timeout_ms: u64,
}

/// Byte offset of the 8-byte little-endian `request_id` field inside
/// the payload produced by [`QueryRequest::encode`]. The id occupies
/// `[REQUEST_ID_OFFSET..REQUEST_ID_OFFSET + 8]`.
///
/// Lives next to `encode` so any refactor of the wire layout naturally
/// touches both. `Cursor::failover_reconnect_and_replay` uses this to
/// patch a fresh request_id into a stashed buffer on every replay
/// instead of re-encoding the builder + binds (multi-MB bind payloads
/// stay in their original allocation across reconnects).
///
/// The `request_id_offset_matches_encoding` test below asserts the
/// constant against an actual encoded buffer — drift between layout
/// and constant fails at `cargo test` time, not at runtime.
pub const REQUEST_ID_OFFSET: usize = 1;

impl QueryRequest {
    /// Start building a request for the given SQL.
    pub fn builder<S: Into<String>>(sql: S) -> QueryRequestBuilder {
        QueryRequestBuilder {
            request_id: 0,
            sql: sql.into(),
            initial_credit: 0,
            binds: Vec::new(),
            query_flags: 0,
            timeout_ms: 0,
        }
    }

    pub fn initial_credit(&self) -> u64 {
        self.initial_credit
    }

    /// Serialize this request as a bare QWP client→server payload (no
    /// 12-byte QWP1 header; only server→client frames carry it).
    ///
    /// If you change this layout, update [`REQUEST_ID_OFFSET`] (and the
    /// matching test) so mid-query failover patches the right bytes.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        out.push(MsgKind::QueryRequest.as_u8());
        out.extend_from_slice(&self.request_id.to_le_bytes());
        varint::encode_u64(self.sql.len() as u64, out);
        out.extend_from_slice(self.sql.as_bytes());
        varint::encode_u64(self.initial_credit, out);
        varint::encode_u64(self.binds.len() as u64, out);
        for bind in &self.binds {
            encode_bind(bind, out)?;
        }
        if self.query_flags != 0 {
            varint::encode_u64(self.query_flags, out);
            // Appended after the flags word, not after the binds: the
            // server's decoder reads the flags varint and then this field
            // only when the bit is set. `build` guarantees the pairing.
            if self.query_flags & QUERY_FLAG_TIMEOUT != 0 {
                varint::encode_u64(self.timeout_ms, out);
            }
        }
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
    query_flags: u64,
    timeout_ms: u64,
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

    /// Set the `query_flags` trailer (`0` = omit it). See
    /// [`QUERY_FLAG_RESET_DICT`] and [`QUERY_FLAG_TIMEOUT`]. Default `0`.
    pub fn query_flags(mut self, flags: u64) -> Self {
        self.query_flags = flags;
        self
    }

    /// Set the per-query `timeout_ms` field. Default `0` (field absent).
    ///
    /// Setting a non-zero value does **not** by itself put the field on the
    /// wire: [`QUERY_FLAG_TIMEOUT`] must also be set in
    /// [`query_flags`](Self::query_flags), which is what cap-gates the
    /// field against servers that would reject it. [`build`](Self::build)
    /// rejects the two being out of step.
    ///
    /// Capped at `i64::MAX`: the server decodes the field as a signed
    /// long, so anything larger would arrive negative and be rejected.
    pub fn timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms.min(i64::MAX as u64);
        self
    }

    /// Append a typed bind parameter at the next position.
    pub fn bind(mut self, value: Bind) -> Self {
        self.binds.push(value);
        self
    }

    pub fn bind_null(self, kind: SimpleNullKind) -> Self {
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
    /// Bind a UUID as its 16 canonical RFC-4122 big-endian bytes — what
    /// `uuid::Uuid::as_bytes()` and Python's `uuid.bytes` produce. The
    /// QWP wire wants (lo LE, hi LE), the full byte reversal, done here.
    pub fn bind_uuid(self, mut v: [u8; 16]) -> Self {
        v.reverse();
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
            check_bindable(bind.kind())
                .map_err(|e| fmt!(InvalidBind, "bind ${}: {}", i + 1, e.msg()))?;
        }
        // Keep the flag bit and the field in step. Either half alone
        // produces a frame the server reads wrong: the bit without a
        // positive value is a `STATUS_PARSE_ERROR` (it rejects zero), and
        // a value without the bit silently drops the timeout while the
        // caller believes it was applied. Caught here rather than on the
        // wire so the mistake cannot leave the process.
        let flag_set = self.query_flags & QUERY_FLAG_TIMEOUT != 0;
        if flag_set != (self.timeout_ms > 0) {
            return Err(fmt!(
                InvalidApiCall,
                "QUERY_FLAG_TIMEOUT and timeout_ms disagree: flag {}, timeout_ms {} \
                 (set both, or neither)",
                if flag_set { "set" } else { "clear" },
                self.timeout_ms,
            ));
        }
        Ok(QueryRequest {
            request_id: self.request_id,
            sql: self.sql,
            initial_credit: self.initial_credit,
            binds: self.binds,
            query_flags: self.query_flags,
            timeout_ms: self.timeout_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorCode;

    /// Locks the `REQUEST_ID_OFFSET` constant to the actual byte
    /// position the encoder emits. If `encode` ever shifts the
    /// request_id (length-prefix, version byte, extra header field),
    /// this test fails before any failover code patches the wrong
    /// bytes at runtime.
    #[test]
    fn request_id_offset_matches_encoding() {
        const SENTINEL: i64 = 0x0123_4567_89AB_CDEF;
        let req = QueryRequest::builder("S")
            .request_id(SENTINEL)
            .build()
            .unwrap();
        let mut buf = Vec::new();
        req.encode(&mut buf).unwrap();
        assert!(buf.len() >= REQUEST_ID_OFFSET + 8);
        let patched = i64::from_le_bytes(
            buf[REQUEST_ID_OFFSET..REQUEST_ID_OFFSET + 8]
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            patched, SENTINEL,
            "REQUEST_ID_OFFSET ({}) no longer points at the request_id field — \
             update the constant alongside the encoder layout",
            REQUEST_ID_OFFSET,
        );
    }

    #[test]
    fn bind_uuid_reverses_canonical_to_wire_order() {
        // Callers pass canonical RFC-4122 big-endian bytes; the QWP wire
        // wants (lo LE, hi LE) — the full 16-byte reversal, applied here
        // at the API boundary. This checks the bind side on its own, the
        // way `encoder::tests::uuid_payload_is_swapped_to_wire_order` does
        // for the encoder, so a bind that forwards the bytes unchanged
        // cannot be hidden by the reader reversing them again on decode.
        let canonical: [u8; 16] = [
            0x12, 0x3e, 0x45, 0x67, 0xe8, 0x9b, 0x12, 0xd3, 0xa4, 0x56, 0x42, 0x66, 0x14, 0x17,
            0x40, 0x00,
        ];
        let req = QueryRequest::builder("S")
            .bind_uuid(canonical)
            .build()
            .unwrap();
        let mut wire = canonical;
        wire.reverse();
        assert!(
            matches!(req.binds[0], Bind::Uuid(b) if b == wire),
            "bind_uuid must store the wire-order reversal, got {:?}",
            req.binds[0]
        );
    }

    #[test]
    fn no_binds_byte_exact() {
        let req = QueryRequest::builder("SELECT 1")
            .request_id(0x2A)
            .build()
            .unwrap();
        let mut buf = Vec::new();
        req.encode(&mut buf).unwrap();

        // Bare client→server payload: msg_kind | i64 rid | varint(8) | sql | varint(0) | varint(0)
        assert_eq!(buf[0], 0x10);
        assert_eq!(&buf[1..9], &0x2Ai64.to_le_bytes());
        assert_eq!(buf[9], 0x08); // varint sql_length
        assert_eq!(&buf[10..18], b"SELECT 1");
        assert_eq!(buf[18], 0x00); // varint initial_credit = 0
        assert_eq!(buf[19], 0x00); // varint bind_count = 0
        assert_eq!(buf.len(), 20);
    }

    #[test]
    fn with_mixed_binds_layout() {
        let req = QueryRequest::builder("X")
            .request_id(1)
            .bind_i64(42)
            .bind_varchar("hi")
            .bind_null(SimpleNullKind::Boolean)
            .build()
            .unwrap();
        let mut buf = Vec::new();
        req.encode(&mut buf).unwrap();

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
        expected.extend_from_slice(b"hi");
        expected.extend_from_slice(&[0x01, 0x01, 0x01]);
        assert_eq!(buf, expected);
    }

    #[test]
    fn initial_credit_serialized() {
        let req = QueryRequest::builder("X")
            .initial_credit(0x4000)
            .build()
            .unwrap();
        let mut buf = Vec::new();
        req.encode(&mut buf).unwrap();
        // After 0x10 + 8-byte rid + varint(1) + 'X' = 11 bytes, then varint(0x4000)
        // varint(0x4000) = 0x80 0x80 0x01
        assert_eq!(&buf[11..14], &[0x80, 0x80, 0x01]);
    }

    #[test]
    fn query_flags_trailer() {
        // Default 0 -> no trailer (byte-identical to the bindless baseline).
        let mut baseline = Vec::new();
        QueryRequest::builder("X")
            .build()
            .unwrap()
            .encode(&mut baseline)
            .unwrap();

        // Non-zero query_flags -> varint trailer appended after the binds.
        let mut with_flag = Vec::new();
        QueryRequest::builder("X")
            .query_flags(QUERY_FLAG_RESET_DICT)
            .build()
            .unwrap()
            .encode(&mut with_flag)
            .unwrap();

        assert_eq!(with_flag.len(), baseline.len() + 1);
        assert_eq!(&with_flag[..baseline.len()], &baseline[..]);
        assert_eq!(*with_flag.last().unwrap(), QUERY_FLAG_RESET_DICT as u8);
    }

    #[test]
    fn timeout_trailer_follows_flags() {
        // No timeout -> byte-identical to the bindless baseline, which is
        // what keeps an older server seeing the layout it has always seen.
        let mut baseline = Vec::new();
        QueryRequest::builder("X")
            .build()
            .unwrap()
            .encode(&mut baseline)
            .unwrap();

        let mut with_timeout = Vec::new();
        QueryRequest::builder("X")
            .query_flags(QUERY_FLAG_TIMEOUT)
            .timeout_ms(1_000)
            .build()
            .unwrap()
            .encode(&mut with_timeout)
            .unwrap();

        // flags varint (0x02) then timeout varint (1000 = 0xE8 0x07).
        assert_eq!(&with_timeout[..baseline.len()], &baseline[..]);
        assert_eq!(&with_timeout[baseline.len()..], &[0x02, 0xE8, 0x07]);
    }

    #[test]
    fn timeout_trailer_combines_with_reset_dict() {
        // Both bits in one word, timeout field last. The server decodes
        // the flags varint first, so a client that emitted the field
        // before the flags would be read as a bad flags word.
        let mut buf = Vec::new();
        QueryRequest::builder("X")
            .bind_i64(7)
            .query_flags(QUERY_FLAG_RESET_DICT | QUERY_FLAG_TIMEOUT)
            .timeout_ms(1)
            .build()
            .unwrap()
            .encode(&mut buf)
            .unwrap();
        assert_eq!(&buf[buf.len() - 2..], &[0x03, 0x01]);
    }

    #[test]
    fn timeout_ms_caps_at_i64_max() {
        let mut buf = Vec::new();
        QueryRequest::builder("X")
            .query_flags(QUERY_FLAG_TIMEOUT)
            .timeout_ms(u64::MAX)
            .build()
            .unwrap()
            .encode(&mut buf)
            .unwrap();
        let mut expected = vec![0xFF; 8];
        expected.push(0x7F);
        assert_eq!(&buf[buf.len() - 9..], &expected[..]);
    }

    #[test]
    fn timeout_ms_without_flag_rejected() {
        // A value with no bit would silently not reach the server.
        let err = QueryRequest::builder("X")
            .timeout_ms(1_000)
            .build()
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("timeout_ms"), "msg: {}", err.msg());
    }

    #[test]
    fn timeout_flag_without_value_rejected() {
        // The bit with no value is `STATUS_PARSE_ERROR` at the server,
        // which rejects a zero timeout.
        let err = QueryRequest::builder("X")
            .query_flags(QUERY_FLAG_TIMEOUT)
            .build()
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("timeout_ms"), "msg: {}", err.msg());

        // An explicit zero alongside the bit is the same mistake.
        let err = QueryRequest::builder("X")
            .query_flags(QUERY_FLAG_TIMEOUT)
            .timeout_ms(0)
            .build()
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    }

    #[test]
    fn query_flag_bits_are_distinct() {
        assert_eq!(QUERY_FLAG_RESET_DICT, 0x01);
        assert_eq!(QUERY_FLAG_TIMEOUT, 0x02);
        assert_eq!(QUERY_FLAG_RESET_DICT & QUERY_FLAG_TIMEOUT, 0);
    }

    #[test]
    fn timeout_does_not_move_the_request_id() {
        // The failover-replay path patches `[REQUEST_ID_OFFSET..+8]` of the
        // encoded buffer. The timeout field is a trailer, so it must not
        // shift that span.
        const SENTINEL: i64 = 0x0123_4567_89AB_CDEF;
        let mut buf = Vec::new();
        QueryRequest::builder("S")
            .request_id(SENTINEL)
            .query_flags(QUERY_FLAG_TIMEOUT)
            .timeout_ms(5_000)
            .build()
            .unwrap()
            .encode(&mut buf)
            .unwrap();
        assert_eq!(
            i64::from_le_bytes(
                buf[REQUEST_ID_OFFSET..REQUEST_ID_OFFSET + 8]
                    .try_into()
                    .unwrap()
            ),
            SENTINEL
        );
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
        // Server rejects IPv4 binds entirely (per Java reference, see
        // `check_bindable`). The simple-null variant `Bind::Null(SimpleNullKind::Ipv4)`
        // wire-encodes successfully but `build()` must surface the
        // server-side rejection client-side so the user sees a clear
        // `InvalidBind` rather than a generic server `QUERY_ERROR`.
        let err = QueryRequest::builder("X")
            .bind(Bind::Null(SimpleNullKind::Ipv4))
            .build()
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidBind);
        assert!(err.msg().contains("$1"));
    }

    #[test]
    fn encode_length_grows_monotonically_with_binds() {
        let mut prev = 0usize;
        for binds in 0..50 {
            let mut b = QueryRequest::builder("SELECT * FROM t");
            for _ in 0..binds {
                b = b.bind_i64(0);
            }
            let req = b.build().unwrap();
            let mut buf = Vec::new();
            req.encode(&mut buf).unwrap();
            assert!(
                buf.len() > prev || binds == 0,
                "binds={} len={} prev={}",
                binds,
                buf.len(),
                prev
            );
            prev = buf.len();
        }
    }
}
