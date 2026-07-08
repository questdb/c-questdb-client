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
 ******************************************************************************/

// In-process mock QWP server for the C/C++ reader tests. Speaks the
// HTTP-Upgrade + WebSocket + QWP1 binary frame layer well enough to drive
// the reader through every documented client-visible state without a real
// QuestDB instance.
//
// Mirrors the Rust `MockServer` in
// `questdb-rs/tests/egress_failover.rs` — same Action / Script vocabulary,
// same per-connection scripting model, same captured_requests semantics —
// so the wire-protocol expectations stay aligned between the two test
// surfaces.

#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstddef>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <variant>
#include <vector>

namespace qwp_mock
{

// ---------------------------------------------------------------------------
// Wire constants (mirror questdb-rs/src/egress/wire/msg_kind.rs and the
// failover-test mock).
// ---------------------------------------------------------------------------

inline constexpr uint8_t MSG_QUERY_REQUEST = 0x10;
inline constexpr uint8_t MSG_RESULT_BATCH = 0x11;
inline constexpr uint8_t MSG_RESULT_END = 0x12;
inline constexpr uint8_t MSG_QUERY_ERROR = 0x13;
inline constexpr uint8_t MSG_CANCEL = 0x14;
inline constexpr uint8_t MSG_CREDIT = 0x15;
inline constexpr uint8_t MSG_EXEC_DONE = 0x16;
inline constexpr uint8_t MSG_CACHE_RESET = 0x17;
inline constexpr uint8_t MSG_SERVER_INFO = 0x18;

// Server roles (mirror questdb::egress::ServerRole wire bytes).
inline constexpr uint8_t ROLE_STANDALONE = 0x00;
inline constexpr uint8_t ROLE_PRIMARY = 0x01;
inline constexpr uint8_t ROLE_REPLICA = 0x02;
inline constexpr uint8_t ROLE_PRIMARY_CATCHUP = 0x03;

// ColumnKind wire codes (mirror questdb-rs/src/egress/column_kind.rs).
inline constexpr uint8_t COL_BOOLEAN = 0x01;
inline constexpr uint8_t COL_BYTE = 0x02;
inline constexpr uint8_t COL_SHORT = 0x03;
inline constexpr uint8_t COL_INT = 0x04;
inline constexpr uint8_t COL_LONG = 0x05;
inline constexpr uint8_t COL_FLOAT = 0x06;
inline constexpr uint8_t COL_DOUBLE = 0x07;
inline constexpr uint8_t COL_SYMBOL = 0x09;
inline constexpr uint8_t COL_TIMESTAMP = 0x0A;
inline constexpr uint8_t COL_DATE = 0x0B;
inline constexpr uint8_t COL_UUID = 0x0C;
inline constexpr uint8_t COL_LONG256 = 0x0D;
inline constexpr uint8_t COL_GEOHASH = 0x0E;
inline constexpr uint8_t COL_VARCHAR = 0x0F;
inline constexpr uint8_t COL_TIMESTAMP_NANOS = 0x10;
inline constexpr uint8_t COL_DOUBLE_ARRAY = 0x11;
inline constexpr uint8_t COL_LONG_ARRAY = 0x12;
inline constexpr uint8_t COL_DECIMAL64 = 0x13;
inline constexpr uint8_t COL_DECIMAL128 = 0x14;
inline constexpr uint8_t COL_DECIMAL256 = 0x15;
inline constexpr uint8_t COL_CHAR = 0x16;
inline constexpr uint8_t COL_BINARY = 0x17;
inline constexpr uint8_t COL_IPV4 = 0x18;

// QueryError status codes (mirror StatusCode in msg_kind.rs).
inline constexpr uint8_t STATUS_SCHEMA_MISMATCH = 0x03;
inline constexpr uint8_t STATUS_PARSE_ERROR = 0x05;
inline constexpr uint8_t STATUS_INTERNAL_ERROR = 0x06;
inline constexpr uint8_t STATUS_SECURITY_ERROR = 0x08;
inline constexpr uint8_t STATUS_CANCELLED = 0x0A;
inline constexpr uint8_t STATUS_LIMIT_EXCEEDED = 0x0B;

// CACHE_RESET masks.
inline constexpr uint8_t CACHE_RESET_SYMBOLS = 0x01;
inline constexpr uint8_t CACHE_RESET_SCHEMA = 0x02;

// ---------------------------------------------------------------------------
// Wire helpers — public so tests can build their own custom payloads in
// addition to the canned helpers below.
// ---------------------------------------------------------------------------

void encode_varint_u64(uint64_t v, std::vector<uint8_t>& out);

// Wrap a payload in the 12-byte QWP1 frame header. Server frames carry
// this header; client→server frames are bare payloads (no header).
std::vector<uint8_t> framed(
    uint8_t version, uint8_t flags, uint16_t table_count,
    const std::vector<uint8_t>& payload);

// Convenience builders.
std::vector<uint8_t> server_info_frame(
    uint8_t role,
    const std::string& cluster_id,
    const std::string& node_id,
    uint64_t epoch = 0,
    uint32_t capabilities = 0,
    int64_t server_wall_ns = 0);
std::vector<uint8_t> result_end_frame(int64_t request_id);
std::vector<uint8_t> exec_done_frame(
    int64_t request_id, uint8_t op_type = 0, uint64_t rows_affected = 0);
std::vector<uint8_t> query_error_frame(
    int64_t request_id, uint8_t status_code, const std::string& message);
std::vector<uint8_t> cache_reset_frame(uint8_t mask);
// Server-origin QWP ingress OK response payload for a client-sent write frame.
// This is not wrapped in the QWP1 egress header: ingress ACKs are the raw
// WebSocket binary payload `[status=0][wire_seq_le][table_count=0]`.
std::vector<uint8_t> ingress_ok_frame(uint64_t wire_seq = 0);

// Build a single-table RESULT_BATCH frame given:
//  - request_id, batch_seq
//  - row_count, columns: list of (name, kind_code, raw_column_bytes)
//
// `raw_column_bytes` for each column must be the per-column wire payload
// — typically `[null_flag][validity_bitmap?][packed values]` for fixed-
// width columns, varlen-specific for varchar/binary, etc. Use the
// `fixed_column_bytes` / `varchar_column_bytes` helpers below to build
// these for common cases.
struct ColumnSpec
{
    std::string name;
    uint8_t kind;
    std::vector<uint8_t> data;
};
std::vector<uint8_t> result_batch_frame(
    int64_t request_id, uint64_t batch_seq,
    size_t row_count, const std::vector<ColumnSpec>& columns);

// `result_batch_frame` variant that ships a `FLAG_DELTA_SYMBOL_DICT` delta
// section in the payload before the table block. `dict_delta_start` is the
// conn-id of the first new entry — pass 0 on the first batch of a
// connection (the client validates `delta_start == current dict size`).
// Pair with `symbol_column_bytes` for any SYMBOL columns in `columns`.
std::vector<uint8_t> result_batch_frame_with_dict(
    int64_t request_id, uint64_t batch_seq,
    size_t row_count, const std::vector<ColumnSpec>& columns,
    uint64_t dict_delta_start,
    const std::vector<std::string>& dict_entries);

// SYMBOL column body for an all-non-null column: `[null_flag=0][varint code
// per row]`. Pair with `result_batch_frame_with_dict` to also ship the
// dictionary entries the codes index into.
std::vector<uint8_t> symbol_column_bytes(const std::vector<uint32_t>& codes);

// Build the per-column body for a fixed-width column where every row is
// non-null. `elem_size` is bytes per row. `packed_values` must already
// be `row_count × elem_size` bytes in little-endian wire order.
std::vector<uint8_t> fixed_column_bytes(
    size_t row_count, const std::vector<uint8_t>& packed_values);

// Build a varchar/binary column body from a per-row list of byte vectors,
// all rows non-null.
std::vector<uint8_t> varlen_column_bytes(
    const std::vector<std::vector<uint8_t>>& rows);

// Build a fixed-width column body with a validity bitmap. `is_null` has
// `row_count` entries; for null rows the value bytes are skipped on the
// wire (compact encoding).
std::vector<uint8_t> fixed_column_bytes_nullable(
    size_t row_count,
    const std::vector<bool>& is_null,
    const std::vector<uint8_t>& packed_non_null_values,
    size_t elem_size);

// Build a DECIMAL64 column body: `[validity][varint scale][non_null × i64 LE]`.
std::vector<uint8_t> decimal64_column_bytes(
    const std::vector<int64_t>& values, int8_t scale);

// Build a DECIMAL128 column body: `[validity][varint scale][non_null × 16 raw LE bytes]`.
// Each entry in `values` is the raw 16-byte two's-complement little-endian
// mantissa exactly as it should appear on the wire.
std::vector<uint8_t> decimal128_column_bytes(
    const std::vector<std::array<uint8_t, 16>>& values, int8_t scale);

// Build a DECIMAL256 column body: `[validity][1B scale][non_null × 32 raw LE bytes]`.
// Each entry in `values` is the raw 32-byte two's-complement little-endian
// mantissa exactly as it should appear on the wire.
std::vector<uint8_t> decimal256_column_bytes(
    const std::vector<std::array<uint8_t, 32>>& values, int8_t scale);

// Build a GEOHASH column body: `[validity][varint precision_bits][non_null × ceil(precision_bits/8) LE bytes]`.
// `packed_non_null_values` must already be `non_null_count × byte_width` bytes.
std::vector<uint8_t> geohash_column_bytes(
    const std::vector<bool>& is_null,
    const std::vector<uint8_t>& packed_non_null_values,
    uint8_t precision_bits);

// Build a DOUBLE_ARRAY / LONG_ARRAY column body: `[validity][per-row: 1B nDims, nDims×u32_le shape, prod(shape)×8 LE element bytes]`.
// `rows[i] == std::nullopt` marks a NULL row. Each present row carries its
// own shape and packed flat-data bytes (caller-provided so this helper
// stays single for both DOUBLE_ARRAY and LONG_ARRAY).
struct ArrayRow
{
    std::vector<uint32_t> shape;
    std::vector<uint8_t> data;
};
std::vector<uint8_t> array_column_bytes(
    const std::vector<std::optional<ArrayRow>>& rows);

// ---------------------------------------------------------------------------
// Action vocabulary (mirrors the Rust failover-test mock's `Action` enum).
// ---------------------------------------------------------------------------

struct ActionSendServerInfo
{
    uint8_t role = ROLE_STANDALONE;
    std::string cluster_id = "test-cluster";
    std::string node_id = "n1";
    uint64_t epoch = 0;
    uint32_t capabilities = 0;
    int64_t server_wall_ns = 0;
};
struct ActionAwaitQueryRequest
{};
struct ActionSendResultEnd
{};
struct ActionSendExecDone
{
    uint8_t op_type = 0;
    uint64_t rows_affected = 0;
};
struct ActionSendCacheReset
{
    uint8_t mask = CACHE_RESET_SYMBOLS | CACHE_RESET_SCHEMA;
};
// Send a pre-built RESULT_BATCH (or any other) frame. The test builds the
// frame via `result_batch_frame` etc. and stamps the request_id from
// the most-recent `AwaitQueryRequest` itself before pushing the action.
struct ActionSendRaw
{
    std::vector<uint8_t> frame;
};
// Like `ActionSendRaw`, but the frame is built lazily once the request_id
// is known, so the test doesn't have to hard-code one. The lambda receives
// the most-recent observed request_id.
struct ActionSendBuilt
{
    std::function<std::vector<uint8_t>(int64_t request_id)> build;
};
struct ActionAwaitClientFrame
{
    uint8_t expected_msg_kind;
};
struct ActionHardDrop
{};
struct ActionReject401
{};

using Action = std::variant<
    ActionSendServerInfo,
    ActionAwaitQueryRequest,
    ActionSendResultEnd,
    ActionSendExecDone,
    ActionSendCacheReset,
    ActionSendRaw,
    ActionSendBuilt,
    ActionAwaitClientFrame,
    ActionHardDrop,
    ActionReject401>;

using Script = std::vector<Action>;

// ---------------------------------------------------------------------------
// MockServer — one TCP listener bound to 127.0.0.1:0, a script per accepted
// connection, captures observed client→server frames for assertion.
// ---------------------------------------------------------------------------

class MockServer
{
public:
    explicit MockServer(std::vector<Script> scripts);
    ~MockServer();

    MockServer(const MockServer&) = delete;
    MockServer& operator=(const MockServer&) = delete;

    // "127.0.0.1:NNNN" — use to build the reader's `ws::addr=...`.
    std::string addr() const;

    // Number of TCP connections accepted so far.
    int accepts() const;

    // Block until at least `n` TCP connections have been accepted, or
    // `timeout` elapses; returns true if the count was reached. Store-and-
    // forward senders connect on a background thread, so the borrow returns
    // before the accept lands.
    bool wait_for_accepts(
        int n,
        std::chrono::milliseconds timeout = std::chrono::seconds(5)) const;

    // Snapshot of every payload (msg_kind + body) the workers have seen
    // from the client, in arrival order. Each entry is the bare client→
    // server frame payload.
    std::vector<std::vector<uint8_t>> captured_requests() const;

private:
    struct Impl;
    std::unique_ptr<Impl> _impl;
};

} // namespace qwp_mock
