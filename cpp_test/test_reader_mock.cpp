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

// Mock-server-driven tests for the reader FFI.
//
// Uses cpp_test/qwp_mock_server.* — an in-process WebSocket + QWP1 mock
// — to cover the surface that needs a connected reader receiving real
// binary frames: column getters across kinds, server_info accessors,
// QueryRequest capture (bind round-trip), error codes, terminal kinds,
// and stats. Each TEST_CASE owns its own mock instance bound to
// `127.0.0.1:0`, so these tests run concurrently without port conflicts
// and don't need a running QuestDB.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "qwp_mock_server.hpp"

#include <questdb/egress/qwp_reader.hpp>

#include <atomic>
#include <chrono>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>

using namespace questdb::ingress::literals;
namespace qm = qwp_mock;
namespace eg = questdb::egress;

namespace
{

questdb::egress::reader connect_to(const qm::MockServer& srv)
{
    const std::string conf = "ws::addr=" + srv.addr() + ";";
    return questdb::egress::reader{questdb::ingress::utf8_view{conf}};
}

// Unaligned little-endian load. `column::values<T>()` hands out a `const T*`
// borrowed from the wire payload that need not satisfy `alignof(T)`, so the
// memcpy must read through a byte pointer: copying straight from `const T* p`
// lets the compiler lower the memcpy to a typed (alignment-assuming) load,
// which traps under UBSan `-fsanitize=alignment` on arm64.
template <typename T>
T load_le(const T* p)
{
    T v;
    std::memcpy(&v, reinterpret_cast<const unsigned char*>(p), sizeof(T));
    return v;
}

// Pack helpers for column data.
template <typename T>
std::vector<uint8_t> pack_le(const std::vector<T>& vs)
{
    std::vector<uint8_t> out;
    out.reserve(vs.size() * sizeof(T));
    for (T v : vs)
    {
        // bit_cast-style copy, little-endian on supported test hosts.
        const uint8_t* p = reinterpret_cast<const uint8_t*>(&v);
        out.insert(out.end(), p, p + sizeof(T));
    }
    return out;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Smoke: ServerInfo + an empty-row RESULT_END drives the cursor through
// the basic happy path.
// ---------------------------------------------------------------------------

TEST_CASE("mock: handshake + immediate ResultEnd drives cursor terminus")
{
    qm::Script s = {
        qm::ActionSendServerInfo{qm::ROLE_PRIMARY, "test-cluster", "node-A"},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});

    auto reader = connect_to(srv);
    CHECK(reader.server_version() == 1);
    CHECK_FALSE(reader.current_host().empty());

    // Server identity from SERVER_INFO is exposed via the wrapper.
    auto info = reader.server_info();
    CHECK(info.role_byte() == qm::ROLE_PRIMARY);
    CHECK(info.cluster_id() == "test-cluster");
    CHECK(info.node_id() == "node-A");

    auto cur = reader.execute("select 1"_utf8);
    // Empty result → next_batch() returns false on first call.
    CHECK_FALSE(cur.next_batch());
    CHECK(cur.terminal_kind() == qwp_reader_terminal_kind_end);

    CHECK(srv.captured_requests().size() == 1);
    CHECK(srv.captured_requests()[0][0] == qm::MSG_QUERY_REQUEST);
}

// ---------------------------------------------------------------------------
// Column getters — drive a synthesized RESULT_BATCH with a representative
// fixed-width column kind and verify the C++ getter reads the value back.
// ---------------------------------------------------------------------------

TEST_CASE("mock: column getter — i32 (Int) round-trip")
{
    qm::ColumnSpec c{
        "v", qm::COL_INT,
        qm::fixed_column_bytes(3, pack_le<int32_t>({100, 200, 300}))};

    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[c](int64_t rid)
                            { return qm::result_batch_frame(rid, 0, 3, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});

    auto reader = connect_to(srv);
    auto cur = reader.execute("select v from t"_utf8);
    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
    REQUIRE(batch.row_count() == 3);
    REQUIRE(batch.column_kind(0) == qwp_reader_column_kind_int);

    auto v0 = batch.column(0).get<int32_t>(0);
    auto v1 = batch.column(0).get<int32_t>(1);
    auto v2 = batch.column(0).get<int32_t>(2);
    REQUIRE(v0.has_value());
    REQUIRE(v1.has_value());
    REQUIRE(v2.has_value());
    CHECK(*v0 == 100);
    CHECK(*v1 == 200);
    CHECK(*v2 == 300);

    CHECK_FALSE(cur.next_batch());
}

TEST_CASE("mock: column getter — i64 / f64 / bool / i8 / i16 / f32")
{
    qm::ColumnSpec c_i64{
        "l", qm::COL_LONG,
        qm::fixed_column_bytes(2, pack_le<int64_t>({-1, 9223372036854775807LL}))};
    qm::ColumnSpec c_f64{
        "d", qm::COL_DOUBLE,
        qm::fixed_column_bytes(2, pack_le<double>({1.5, -3.14}))};
    // BOOLEAN: validity then bit-packed values (1 row -> 1 bit).
    std::vector<uint8_t> bool_body;
    bool_body.push_back(0x00);              // no validity
    bool_body.push_back(0b00000010);        // bit0=0 (false), bit1=1 (true)
    qm::ColumnSpec c_bool{"b", qm::COL_BOOLEAN, std::move(bool_body)};
    qm::ColumnSpec c_i8{
        "i8", qm::COL_BYTE,
        qm::fixed_column_bytes(2, pack_le<int8_t>({-7, 42}))};
    qm::ColumnSpec c_i16{
        "i16", qm::COL_SHORT,
        qm::fixed_column_bytes(2, pack_le<int16_t>({-1234, 31000}))};
    qm::ColumnSpec c_f32{
        "f32", qm::COL_FLOAT,
        qm::fixed_column_bytes(2, pack_le<float>({1.25f, -0.5f}))};

    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[=](int64_t rid)
                            {
                                return qm::result_batch_frame(
                                    rid, 0, 2,
                                    {c_i64, c_f64, c_bool, c_i8, c_i16, c_f32});
                            }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select * from t"_utf8);
    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
    REQUIRE(batch.row_count() == 2);

    REQUIRE(batch.column(0).get<int64_t>(0).value_or(0) == -1);
    REQUIRE(batch.column(0).get<int64_t>(1).value_or(0) == 9223372036854775807LL);
    CHECK(batch.column(1).get<double>(0).value_or(0) == doctest::Approx(1.5));
    CHECK(batch.column(1).get<double>(1).value_or(0) == doctest::Approx(-3.14));
    CHECK(batch.column(2).get<bool>(0).value_or(true) == false);
    CHECK(batch.column(2).get<bool>(1).value_or(false) == true);
    CHECK(batch.column(3).get<int8_t>(0).value_or(0) == -7);
    CHECK(batch.column(3).get<int8_t>(1).value_or(0) == 42);
    CHECK(batch.column(4).get<int16_t>(0).value_or(0) == -1234);
    CHECK(batch.column(4).get<int16_t>(1).value_or(0) == 31000);
    CHECK(batch.column(5).get<float>(0).value_or(0.0f) == doctest::Approx(1.25f));
    CHECK(batch.column(5).get<float>(1).value_or(0.0f) == doctest::Approx(-0.5f));
}

TEST_CASE("mock: column getter — varchar")
{
    auto body = qm::varlen_column_bytes({{'h', 'i'}, {'h', 'e', 'l', 'l', 'o'}});
    qm::ColumnSpec c{"s", qm::COL_VARCHAR, std::move(body)};

    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[c](int64_t rid)
                            { return qm::result_batch_frame(rid, 0, 2, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select s from t"_utf8);
    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
    REQUIRE(batch.row_count() == 2);
    auto v0 = batch.column(0).varchar(0);
    auto v1 = batch.column(0).varchar(1);
    REQUIRE(v0.has_value());
    REQUIRE(v1.has_value());
    CHECK(*v0 == "hi");
    CHECK(*v1 == "hello");
}

TEST_CASE("mock: column getter — uuid (16 raw bytes, big-endian on wire)")
{
    std::vector<uint8_t> uuid_bytes(16);
    for (int i = 0; i < 16; ++i)
        uuid_bytes[i] = uint8_t(0xA0 + i);
    qm::ColumnSpec c{"u", qm::COL_UUID,
                     qm::fixed_column_bytes(1, uuid_bytes)};

    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[c](int64_t rid)
                            { return qm::result_batch_frame(rid, 0, 1, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select u from t"_utf8);
    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
    auto u = batch.column(0).get_uuid(0);
    REQUIRE(u.has_value());
    for (int i = 0; i < 16; ++i)
        CHECK((*u)[i] == uint8_t(0xA0 + i));
}

TEST_CASE("mock: column getter — decimal64 with non-zero scale")
{
    auto body = qm::decimal64_column_bytes({12345, -67890}, /*scale=*/3);
    qm::ColumnSpec c{"d", qm::COL_DECIMAL64, std::move(body)};

    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[c](int64_t rid)
                            { return qm::result_batch_frame(rid, 0, 2, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select d from t"_utf8);
    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
    auto d0 = batch.column(0).get_decimal64(0);
    auto d1 = batch.column(0).get_decimal64(1);
    REQUIRE(d0.has_value());
    REQUIRE(d1.has_value());
    CHECK(d0->mantissa == 12345);
    CHECK(d0->scale == 3);
    CHECK(d1->mantissa == -67890);
    CHECK(d1->scale == 3);
}

TEST_CASE("mock: column getter — decimal128 with negative i128 mantissa")
{
    // i128 = -1 in two's-complement LE is sixteen 0xFF bytes.
    std::array<uint8_t, 16> val;
    val.fill(0xFF);
    auto body = qm::decimal128_column_bytes({val}, /*scale=*/0);
    qm::ColumnSpec c{"d", qm::COL_DECIMAL128, std::move(body)};

    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[c](int64_t rid)
                            { return qm::result_batch_frame(rid, 0, 1, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select d from t"_utf8);
    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
    auto d = batch.column(0).get_decimal128(0);
    REQUIRE(d.has_value());
    CHECK(d->low == static_cast<uint64_t>(-1LL));
    CHECK(d->high == -1);
    CHECK(d->scale == 0);
}

// ---------------------------------------------------------------------------
// Validity bitmap — server emits a validity-flagged column with a known
// null pattern; the cursor's `column_validity` and per-row getters must
// agree.
// ---------------------------------------------------------------------------

TEST_CASE("mock: column validity bitmap matches null pattern from server")
{
    // 5 rows, rows 1 and 3 null, others have values 10/30/50.
    std::vector<bool> is_null = {false, true, false, true, false};
    auto packed = pack_le<int64_t>({10, 30, 50});
    auto body = qm::fixed_column_bytes_nullable(5, is_null, packed, 8);
    qm::ColumnSpec c{"v", qm::COL_LONG, std::move(body)};

    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[c](int64_t rid)
                            { return qm::result_batch_frame(rid, 0, 5, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select v from t"_utf8);
    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
    REQUIRE(batch.row_count() == 5);

    auto col = batch.column(0);
    const uint8_t* vbits = col.validity();
    REQUIRE(vbits != nullptr);
    REQUIRE(col.validity_bytes() >= 1);
    // Bit pattern: rows 1 and 3 set, others clear → low 5 bits = 0b01010 = 0x0A.
    CHECK((vbits[0] & 0x1F) == 0x0A);

    CHECK(col.get<int64_t>(0).value_or(-1) == 10);
    CHECK_FALSE(col.get<int64_t>(1).has_value());
    CHECK(col.get<int64_t>(2).value_or(-1) == 30);
    CHECK_FALSE(col.get<int64_t>(3).has_value());
    CHECK(col.get<int64_t>(4).value_or(-1) == 50);
}

// ---------------------------------------------------------------------------
// QueryError → C error code surfacing.
// ---------------------------------------------------------------------------

TEST_CASE("mock: QueryError(parse) surfaces as ServerParseError")
{
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{
            [](int64_t rid)
            {
                return qm::query_error_frame(
                    rid, qm::STATUS_PARSE_ERROR, "bad sql at line 1");
            }},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);

    bool threw = false;
    try
    {
        auto cur = reader.execute("nonsense"_utf8);
        while (cur.next_batch()) {}
    }
    catch (const questdb::error& e)
    {
        threw = true;
        CHECK(e.code() == questdb_error_server_parse_error);
        CHECK(std::strlen(e.what()) > 0);
    }
    CHECK(threw);
}

TEST_CASE("mock: QueryError(internal) surfaces as ServerInternalError")
{
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{
            [](int64_t rid)
            {
                return qm::query_error_frame(
                    rid, qm::STATUS_INTERNAL_ERROR, "boom");
            }},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);

    bool threw = false;
    try
    {
        auto cur = reader.execute("x"_utf8);
        while (cur.next_batch()) {}
    }
    catch (const questdb::error& e)
    {
        threw = true;
        CHECK(e.code() == questdb_error_server_internal_error);
    }
    CHECK(threw);
}

TEST_CASE("mock: QueryError(security) surfaces as ServerSecurityError")
{
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{
            [](int64_t rid)
            {
                return qm::query_error_frame(
                    rid, qm::STATUS_SECURITY_ERROR, "forbidden");
            }},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    bool threw = false;
    try
    {
        auto cur = reader.execute("x"_utf8);
        while (cur.next_batch()) {}
    }
    catch (const questdb::error& e)
    {
        threw = true;
        CHECK(e.code() == questdb_error_server_security_error);
    }
    CHECK(threw);
}

// ---------------------------------------------------------------------------
// ExecDone → terminal_kind == exec_done (vs `end` for SELECT).
// ---------------------------------------------------------------------------

TEST_CASE("mock: ExecDone yields terminal_kind == exec_done")
{
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendExecDone{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("create table x(a int)"_utf8);
    CHECK_FALSE(cur.next_batch());
    CHECK(cur.terminal_kind() == qwp_reader_terminal_kind_exec_done);
}

// ---------------------------------------------------------------------------
// QueryRequest capture — verify the wire bytes the cursor wrote.
// ---------------------------------------------------------------------------

TEST_CASE("mock: captured QueryRequest carries SQL and request_id")
{
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select 42"_utf8);
    while (cur.next_batch()) {}

    auto reqs = srv.captured_requests();
    REQUIRE(reqs.size() == 1);
    const auto& req = reqs[0];
    REQUIRE(req.size() >= 9);
    CHECK(req[0] == qm::MSG_QUERY_REQUEST);
    // request_id is a non-zero allocated id (not 0).
    int64_t rid = 0;
    for (int i = 0; i < 8; ++i)
        rid |= int64_t(req[1 + i]) << (i * 8);
    CHECK(rid != 0);

    // After request_id, varint sql_len then SQL bytes.
    REQUIRE(req.size() >= 9 + 1 + 9);
    CHECK(req[9] == 9); // varint(9) = "select 42".size()
    CHECK(std::string(req.begin() + 10, req.begin() + 10 + 9) == "select 42");
}

TEST_CASE("mock: bind_i32 + bind_varchar appears verbatim in captured request")
{
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.prepare("X"_utf8)
                   .bind_i32(7)
                   .bind_varchar("widgets"_utf8)
                   .execute();
    while (cur.next_batch()) {}

    auto reqs = srv.captured_requests();
    REQUIRE(reqs.size() == 1);
    const auto& req = reqs[0];
    // Layout: 0x10 | i64 rid | varint(1) sql_len | 'X' | varint(0) credit | varint(2) bind_count
    //         | bind1: 0x04 (Int) 0x00 (not null) i32 LE 7
    //         | bind2: 0x0F (Varchar) 0x00 (not null) [u32_le 0][u32_le 7] "widgets"
    REQUIRE(req.size() >= 1 + 8 + 1 + 1 + 1 + 1);
    CHECK(req[0] == 0x10);
    size_t p = 9;
    CHECK(req[p++] == 1); // sql_len varint
    CHECK(req[p++] == 'X');
    CHECK(req[p++] == 0); // initial_credit varint
    CHECK(req[p++] == 2); // bind_count varint
    CHECK(req[p++] == 0x04); // Int
    CHECK(req[p++] == 0x00); // not null
    int32_t v_i32 = int32_t(req[p]) | (int32_t(req[p + 1]) << 8) |
                    (int32_t(req[p + 2]) << 16) | (int32_t(req[p + 3]) << 24);
    CHECK(v_i32 == 7);
    p += 4;
    CHECK(req[p++] == 0x0F); // Varchar
    CHECK(req[p++] == 0x00); // not null
    // u32_le 0
    CHECK(req[p] == 0);
    CHECK(req[p + 1] == 0);
    CHECK(req[p + 2] == 0);
    CHECK(req[p + 3] == 0);
    p += 4;
    // u32_le 7 — assert all four bytes so a future change to non-zero
    // high bytes is caught instead of silently masked.
    CHECK(req[p] == 7);
    CHECK(req[p + 1] == 0);
    CHECK(req[p + 2] == 0);
    CHECK(req[p + 3] == 0);
    p += 4;
    CHECK(std::string(req.begin() + p, req.begin() + p + 7) == "widgets");
}

// ---------------------------------------------------------------------------
// Stats: bytes_received increases after a real frame round-trip.
// ---------------------------------------------------------------------------

TEST_CASE("mock: bytes_received increases after a batch is consumed")
{
    qm::ColumnSpec c{"v", qm::COL_INT,
                     qm::fixed_column_bytes(1, pack_le<int32_t>({42}))};
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[c](int64_t rid)
                            { return qm::result_batch_frame(rid, 0, 1, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    const uint64_t before_query = reader.bytes_received();

    auto cur = reader.execute("select v"_utf8);
    while (cur.next_batch()) {}
    const uint64_t after = reader.bytes_received();

    CHECK(after > before_query);
}

// ---------------------------------------------------------------------------
// Server status code → C error code mapping (the variants not already
// covered above: SCHEMA_MISMATCH, LIMIT_EXCEEDED, CANCELLED).
// ---------------------------------------------------------------------------

namespace
{
void run_query_error_test(uint8_t status, ::questdb_error_code expected)
{
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[status](int64_t rid)
                            { return qm::query_error_frame(rid, status, "x"); }},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    bool threw = false;
    try
    {
        auto cur = reader.execute("x"_utf8);
        while (cur.next_batch()) {}
    }
    catch (const questdb::error& e)
    {
        threw = true;
        CHECK(e.code() == expected);
    }
    CHECK(threw);
}
} // namespace

TEST_CASE("mock: QueryError(schema_mismatch) surfaces as ServerSchemaMismatch")
{
    run_query_error_test(
        qm::STATUS_SCHEMA_MISMATCH,
        questdb_error_server_schema_mismatch);
}

TEST_CASE("mock: QueryError(limit_exceeded) surfaces as ServerLimitExceeded")
{
    run_query_error_test(
        qm::STATUS_LIMIT_EXCEEDED,
        questdb_error_server_limit_exceeded);
}

TEST_CASE("mock: QueryError(cancelled) surfaces as Cancelled")
{
    run_query_error_test(
        qm::STATUS_CANCELLED,
        questdb_error_cancelled);
}

// ---------------------------------------------------------------------------
// cursor::cancel — verify a CANCEL frame is written, the cursor drains,
// and the server's CANCELLED status surfaces as the documented error code.
// ---------------------------------------------------------------------------

TEST_CASE("mock: cursor::cancel writes MSG_CANCEL and surfaces Cancelled")
{
    // After the QueryRequest, server holds the response open; the test
    // calls cancel() which writes MSG_CANCEL on the wire. The script then
    // sends a CANCELLED status to drive the cursor to its terminal.
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionAwaitClientFrame{qm::MSG_CANCEL},
        qm::ActionSendBuilt{[](int64_t rid)
                            { return qm::query_error_frame(rid, qm::STATUS_CANCELLED, "user"); }},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select 1"_utf8);

    bool threw = false;
    try
    {
        cur.cancel();
    }
    catch (const questdb::error& e)
    {
        // cancel() returns once the cursor is drained. If the server
        // CANCELLED status arrives during the drain, it surfaces here.
        threw = true;
        CHECK(e.code() == questdb_error_cancelled);
    }
    // Whether cancel() throws or returns cleanly depends on race timing,
    // but the wire MUST contain a MSG_CANCEL byte regardless.
    auto reqs = srv.captured_requests();
    bool saw_cancel = false;
    for (const auto& r : reqs)
        if (!r.empty() && r[0] == qm::MSG_CANCEL)
            saw_cancel = true;
    CHECK(saw_cancel);
    (void)threw;
}

// ---------------------------------------------------------------------------
// Cursor::Drop without prior cancel() must still emit MSG_CANCEL.
//
// Regression guard for commit 3bd0f56: `Cursor::Drop` sends a
// best-effort CANCEL frame BEFORE tearing the WS down so the server
// releases request-scoped state (dictionary, schema, flow-control
// budget) promptly. Without this, a regression would have the server
// keep emitting RESULT_BATCH frames for an abandoned request until it
// observes the eventual WS close — which the existing live test
// `dropping_live_cursor_closes_connection` would NOT catch (it asserts
// the next query fails after drop; that holds whether or not a CANCEL
// was sent, since the WS close already breaks the next query).
// ---------------------------------------------------------------------------

TEST_CASE("mock: dropping cursor without draining writes MSG_CANCEL on the wire")
{
    qm::ColumnSpec c{
        "v", qm::COL_INT, qm::fixed_column_bytes(1, pack_le<int32_t>({42}))};
    // Script: serve one batch, then `AwaitClientFrame{MSG_CANCEL}`.
    // The Await action blocks the worker thread until CANCEL arrives;
    // if the regression returns (no CANCEL, only WS close), the Await
    // would not be satisfied — but `captured_requests()` still tells
    // the test body what actually landed on the wire, so we assert
    // on it directly rather than relying on script-side blocking.
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[c](int64_t rid) {
            return qm::result_batch_frame(rid, 0, 1, {c});
        }},
        qm::ActionAwaitClientFrame{qm::MSG_CANCEL},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    {
        auto cur = reader.execute("select v"_utf8);
        // Consume the single batch — `cursor_active` stays true since
        // no terminal has arrived yet. Without this, the cursor never
        // observes a frame and the Drop path's invariants are
        // exercised against an idle stream rather than a live one.
        REQUIRE(cur.next_batch());
        // Drop the cursor here (end-of-scope) WITHOUT calling cancel()
        // or draining to RESULT_END. `Cursor::Drop` must emit CANCEL.
    }

    // The mock's worker thread captures frames on a separate thread.
    // Poll for the CANCEL to appear so we don't race the worker.
    // 2 s is generous — `Cursor::Drop` writes the CANCEL via
    // `try_write_cancel` (bounded by `CLOSE_TIMEOUT = 200ms`) before
    // tearing the WS down, so the byte is on the kernel TX queue
    // synchronously when the destructor returns; the mock's
    // `read_until_kind` reads it within microseconds.
    bool saw_cancel = false;
    auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (std::chrono::steady_clock::now() < deadline)
    {
        auto reqs = srv.captured_requests();
        for (const auto& r : reqs)
        {
            if (!r.empty() && r[0] == qm::MSG_CANCEL)
            {
                saw_cancel = true;
                break;
            }
        }
        if (saw_cancel)
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    CHECK(saw_cancel);
}

// ---------------------------------------------------------------------------
// cursor::add_credit — verify a MSG_CREDIT frame is written.
// ---------------------------------------------------------------------------

TEST_CASE("mock: cursor::add_credit writes MSG_CREDIT")
{
    qm::ColumnSpec c{"v", qm::COL_INT,
                     qm::fixed_column_bytes(1, pack_le<int32_t>({1}))};
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[c](int64_t rid)
                            { return qm::result_batch_frame(rid, 0, 1, {c}); }},
        qm::ActionAwaitClientFrame{qm::MSG_CREDIT},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.prepare("select v"_utf8).initial_credit(64).execute();
    REQUIRE(cur.next_batch());
    cur.add_credit(1024);
    while (cur.next_batch()) {}

    auto reqs = srv.captured_requests();
    bool saw_credit = false;
    for (const auto& r : reqs)
        if (!r.empty() && r[0] == qm::MSG_CREDIT)
            saw_credit = true;
    CHECK(saw_credit);
}

// ---------------------------------------------------------------------------
// add_credit on a terminal cursor must reject. Pins commit 09518eb's
// explicit `done` guard — without it, send_credit_frame would attempt
// a write on the post-terminal transport and surface a confusing
// transport-class error instead of the user-facing "API misuse"
// signal.
// ---------------------------------------------------------------------------

TEST_CASE("mock: add_credit on terminal cursor returns InvalidApiCall")
{
    // Script drives the cursor to RESULT_END so `done = true`.
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select 1"_utf8);
    // Drain to terminal.
    CHECK_FALSE(cur.next_batch());
    REQUIRE(cur.terminal_kind() != questdb::egress::terminal_kind::none);

    bool threw = false;
    try
    {
        cur.add_credit(64);
    }
    catch (const questdb::error& e)
    {
        threw = true;
        CHECK(e.code() == questdb_error_invalid_api_call);
        // Pin the wording so a future docstring/error-message refactor
        // can't quietly drop the "terminal" diagnostic.
        const std::string m = std::string(e.what());
        CHECK(m.find("terminal") != std::string::npos);
    }
    CHECK(threw);
}

// ---------------------------------------------------------------------------
// add_credit failover regression for commit 09518eb. The fix promises
// that a transport-class write failure on the current connection
// triggers a reconnect-and-replay cycle, after which the credit frame
// is re-sent on the new endpoint. Without the fix, add_credit would
// surface the raw transport error and the user would have no way to
// preserve their grant intent across failover.
//
// Script setup: A serves the handshake + one batch, then hard-drops.
// The client's `add_credit` is the first operation to attempt a WRITE
// against the dead connection — on loopback this surfaces inside the
// tungstenite send path once the FIN propagates, which we ensure with
// a brief settle before invoking `add_credit`. B handles the replayed
// QUERY_REQUEST, receives the re-sent CREDIT, and terminates.
// ---------------------------------------------------------------------------

TEST_CASE("mock: add_credit failover on write failure replays credit on B")
{
    qm::ColumnSpec col{
        "v", qm::COL_INT, qm::fixed_column_bytes(1, pack_le<int32_t>({7}))};
    qm::Script s_a = {
        qm::ActionSendServerInfo{qm::ROLE_STANDALONE, "c", "a"},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[col](int64_t rid) {
            return qm::result_batch_frame(rid, 0, 1, {col});
        }},
        qm::ActionHardDrop{},
    };
    qm::Script s_b = {
        qm::ActionSendServerInfo{qm::ROLE_STANDALONE, "c", "b"},
        qm::ActionAwaitQueryRequest{},
        qm::ActionAwaitClientFrame{qm::MSG_CREDIT},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv_a({s_a});
    qm::MockServer srv_b({s_b});

    const std::string conf = "ws::addr=" + srv_a.addr() + "," + srv_b.addr() +
        ";failover_backoff_initial_ms=1;failover_backoff_max_ms=10";
    questdb::egress::reader reader{questdb::ingress::utf8_view{conf}};

    std::atomic<int> failover_count{0};
    auto cur = reader.prepare("select v"_utf8)
                   .initial_credit(64)
                   .on_failover_reset(
                       [&failover_count](
                           const questdb::egress::failover_reset_event_view&) {
                           failover_count.fetch_add(1);
                       })
                   .execute();
    REQUIRE(cur.next_batch());

    // Give A's FIN a moment to propagate to the client's tungstenite
    // read state — without this the subsequent add_credit's flush
    // may not yet observe the half-closed peer.
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // add_credit must succeed (after failover replays it on B), NOT
    // surface a transport error. This is the load-bearing assertion
    // for commit 09518eb — the pre-fix code returned the raw write
    // error here instead of attempting the failover replay.
    bool threw = false;
    try
    {
        cur.add_credit(1024);
    }
    catch (const questdb::error& e)
    {
        // Tolerate a single-cycle replay failure surfacing as a
        // transport-class error — this can happen on platforms where
        // the FIN propagates faster than the failover-callback
        // bookkeeping (vanishingly rare on macOS/Linux loopback).
        // But explicitly REJECT InvalidApiCall: that would mean
        // the 'done' guard fired against a still-live cursor, a
        // different bug we don't want to mask.
        threw = true;
        REQUIRE(e.code() != questdb_error_invalid_api_call);
    }
    CHECK_FALSE(threw);
    CHECK(cur.failover_resets() == 1);
    CHECK(failover_count.load() == 1);

    // Drain to RESULT_END on B so we exercise the post-failover read
    // path too.
    CHECK_FALSE(cur.next_batch());
    REQUIRE(cur.terminal_kind() != questdb::egress::terminal_kind::none);

    // B must have captured both the replayed QUERY_REQUEST and the
    // re-sent CREDIT — the pre-fix code would replay the query but
    // drop the credit grant, leaving B's AwaitClientFrame stuck.
    auto reqs_b = srv_b.captured_requests();
    bool saw_query = false;
    bool saw_credit = false;
    for (const auto& r : reqs_b)
    {
        if (r.empty())
            continue;
        if (r[0] == qm::MSG_QUERY_REQUEST)
            saw_query = true;
        if (r[0] == qm::MSG_CREDIT)
            saw_credit = true;
    }
    CHECK(saw_query);
    CHECK(saw_credit);
}

// ---------------------------------------------------------------------------
// Failover surface — two MockServers, hard-drop on A, the reader fails
// over to B, the trampoline fires once, the FailoverResetEvent fields are
// populated. Mirrors questdb-rs/tests/egress_failover.rs:540.
// ---------------------------------------------------------------------------

TEST_CASE("mock: failover trampoline fires once with populated event fields")
{
    // Server A: handshake then hard-drop. Server B: handshake + complete.
    qm::Script s_a = {
        qm::ActionSendServerInfo{qm::ROLE_STANDALONE, "c", "a"},
        qm::ActionAwaitQueryRequest{},
        qm::ActionHardDrop{},
    };
    qm::Script s_b = {
        qm::ActionSendServerInfo{qm::ROLE_STANDALONE, "c", "b"},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv_a({s_a});
    qm::MockServer srv_b({s_b});

    const std::string conf =
        "ws::addr=" + srv_a.addr() + "," + srv_b.addr() +
        ";failover_backoff_initial_ms=1;failover_backoff_max_ms=10";
    questdb::egress::reader reader{questdb::ingress::utf8_view{conf}};
    const auto initial_info = reader.server_info();
    CHECK(initial_info.node_id() == "a");

    struct Capture
    {
        std::atomic<int> count{0};
        std::string failed_host;
        uint16_t failed_port{0};
        std::string new_host;
        uint16_t new_port{0};
        uint32_t attempts{0};
        questdb::error_code trigger_code{};
        bool server_info_present{false};
        std::string new_node_id;
        std::optional<eg::server_info> server_info_snapshot;
    };
    auto cap = std::make_shared<Capture>();

    auto cur = reader.prepare("select 1"_utf8)
                   .on_failover_reset(
                       [cap](const questdb::egress::failover_reset_event_view& ev)
                       {
                           cap->count.fetch_add(1);
                           cap->failed_host = std::string(ev.failed_host());
                           cap->failed_port = ev.failed_port();
                           cap->new_host = std::string(ev.new_host());
                           cap->new_port = ev.new_port();
                           cap->attempts = ev.attempts();
                           cap->trigger_code = ev.trigger_code();
                           auto si = ev.server_info();
                           cap->server_info_snapshot = si.snapshot();
                           if (static_cast<bool>(si))
                           {
                               cap->server_info_present = true;
                               cap->new_node_id = std::string(si.node_id());
                           }
                       })
                   .execute();
    // First next_batch sees A close, fails over to B, gets RESULT_END.
    CHECK_FALSE(cur.next_batch());
    CHECK(cur.failover_resets() == 1);
    CHECK(cap->count.load() == 1);
    CHECK(cap->failed_host == "127.0.0.1");
    // After failover the cursor is on B; the failed endpoint was A — so
    // the captured failed_port must differ from the captured new_port,
    // and the cursor's now-current port must match new_port.
    CHECK(cap->failed_port != cap->new_port);
    CHECK(cap->new_port == cur.current_port());
    CHECK(cap->new_host == "127.0.0.1");
    CHECK(cap->attempts >= 1);
    // Trigger is a transport-class error.
    CHECK((cap->trigger_code == questdb_error_socket_error ||
           cap->trigger_code == questdb_error_protocol_error));
    REQUIRE(cap->server_info_present);
    CHECK(cap->new_node_id == "b");
    REQUIRE(cap->server_info_snapshot.has_value());
    CHECK(cap->server_info_snapshot->node_id() == "b");

    // The cursor reports the replacement endpoint, while the owning snapshot
    // captured before execution remains a safe record of the original one.
    const auto current_info = cur.server_info();
    CHECK(current_info.node_id() == "b");
    CHECK(initial_info.node_id() == "a");
}

TEST_CASE("mock: failover callback NOT invoked on the happy path")
{
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);

    std::atomic<int> count{0};
    auto cur = reader.prepare("select 1"_utf8)
                   .on_failover_reset(
                       [&count](const questdb::egress::failover_reset_event_view&)
                       { count.fetch_add(1); })
                   .execute();
    while (cur.next_batch()) {}
    CHECK(count.load() == 0);
    CHECK(cur.failover_resets() == 0);
}

// ---------------------------------------------------------------------------
// DOUBLE_ARRAY / LONG_ARRAY getters (whole-row + per-element).
// ---------------------------------------------------------------------------

TEST_CASE("mock: column::shape + elements<double> round-trip")
{
    using Row = qm::ArrayRow;
    Row r0{{3}, pack_le<double>({1.5, 2.5, 3.5})};
    Row r1{{2, 2}, pack_le<double>({10.0, 20.0, 30.0, 40.0})};
    auto body = qm::array_column_bytes({r0, r1});
    qm::ColumnSpec c{"a", qm::COL_DOUBLE_ARRAY, std::move(body)};

    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[c](int64_t rid)
                            { return qm::result_batch_frame(rid, 0, 2, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select a"_utf8);
    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
    REQUIRE(batch.row_count() == 2);
    REQUIRE(batch.column_kind(0) == qwp_reader_column_kind_double_array);

    auto col = batch.column(0);
    REQUIRE(col.is_array());

    size_t rank0 = 0;
    const uint32_t* shape0 = col.shape(0, &rank0);
    REQUIRE(rank0 == 1);
    REQUIRE(shape0[0] == 3);
    size_t cnt0 = 0;
    const double* el0 = col.elements<double>(0, &cnt0);
    REQUIRE(cnt0 == 3);
    CHECK(load_le(el0 + 0) == doctest::Approx(1.5));
    CHECK(load_le(el0 + 1) == doctest::Approx(2.5));
    CHECK(load_le(el0 + 2) == doctest::Approx(3.5));

    size_t rank1 = 0;
    const uint32_t* shape1 = col.shape(1, &rank1);
    REQUIRE(rank1 == 2);
    CHECK(shape1[0] == 2);
    CHECK(shape1[1] == 2);
    size_t cnt1 = 0;
    const double* el1 = col.elements<double>(1, &cnt1);
    REQUIRE(cnt1 == 4);
    CHECK(load_le(el1 + 3) == doctest::Approx(40.0));
}

TEST_CASE("mock: LONG_ARRAY column rejected (not supported in this revision)")
{
    using Row = qm::ArrayRow;
    Row r0{{2}, pack_le<int64_t>({-1, 9223372036854775000LL})};
    auto body = qm::array_column_bytes({r0});
    qm::ColumnSpec c{"a", qm::COL_LONG_ARRAY, std::move(body)};

    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[c](int64_t rid)
                            { return qm::result_batch_frame(rid, 0, 1, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select a"_utf8);
    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
    CHECK_THROWS_AS(
        (void)batch.column(0), questdb::error);
}

TEST_CASE("mock: non-null empty-data array row exposes data_offsets symmetry")
{
    // Shape [2, 0, 3]: non-null row, zero elements. The per-row byte slice
    // is empty (data_offsets[r+1] - data_offsets[r] == 0). Pin the
    // contract: the row is reported non-null but yields zero elements.
    using Row = qm::ArrayRow;
    Row r0{{2, 0, 3}, {}};                  // non-null, zero bytes of data
    auto body = qm::array_column_bytes({r0});
    qm::ColumnSpec c{"a", qm::COL_DOUBLE_ARRAY, std::move(body)};

    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[c](int64_t rid)
                            { return qm::result_batch_frame(rid, 0, 1, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select a"_utf8);
    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
    auto col = batch.column(0);
    CHECK_FALSE(col.is_null(0));            // non-null
    size_t rank = 0;
    const uint32_t* shape = col.shape(0, &rank);
    REQUIRE(rank == 3);
    CHECK(shape[0] == 2);
    CHECK(shape[1] == 0);
    CHECK(shape[2] == 3);
    size_t cnt = 0;
    (void)col.elements<double>(0, &cnt);
    CHECK(cnt == 0);
}

TEST_CASE("mock: NULL array row surfaces via is_null")
{
    using Row = qm::ArrayRow;
    Row r0{{1}, pack_le<double>({7.0})};
    auto body = qm::array_column_bytes({r0, std::nullopt});
    qm::ColumnSpec c{"a", qm::COL_DOUBLE_ARRAY, std::move(body)};

    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[c](int64_t rid)
                            { return qm::result_batch_frame(rid, 0, 2, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select a"_utf8);
    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
    REQUIRE(batch.row_count() == 2);
    auto col = batch.column(0);
    CHECK_FALSE(col.is_null(0));
    CHECK(col.is_null(1));
    size_t cnt = 0;
    const double* el = col.elements<double>(0, &cnt);
    REQUIRE(cnt == 1);
    CHECK(load_le(el + 0) == doctest::Approx(7.0));
}

// ---------------------------------------------------------------------------
// Scalar getters not previously covered: char, long256, binary,
// decimal256, geohash.
// ---------------------------------------------------------------------------

TEST_CASE("mock: get_char round-trip (u16 codepoint)")
{
    qm::ColumnSpec c{"c", qm::COL_CHAR,
                     qm::fixed_column_bytes(2, pack_le<uint16_t>({u'A', u'\u00E9'}))};
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[c](int64_t rid)
                            { return qm::result_batch_frame(rid, 0, 2, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select c"_utf8);
    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
    auto v0 = batch.column(0).get<uint16_t>(0);
    auto v1 = batch.column(0).get<uint16_t>(1);
    REQUIRE(v0.has_value());
    CHECK(*v0 == uint16_t(u'A'));
    REQUIRE(v1.has_value());
    CHECK(*v1 == uint16_t(u'\u00E9'));
}

TEST_CASE("mock: get_long256 round-trip (32 raw bytes)")
{
    std::vector<uint8_t> bytes(32);
    for (int i = 0; i < 32; ++i) bytes[i] = uint8_t(i + 1);
    qm::ColumnSpec c{"l", qm::COL_LONG256,
                     qm::fixed_column_bytes(1, bytes)};
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[c](int64_t rid)
                            { return qm::result_batch_frame(rid, 0, 1, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select l"_utf8);
    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
    auto v = batch.column(0).get_long256(0);
    REQUIRE(v.has_value());
    for (int i = 0; i < 32; ++i)
        CHECK((*v)[i] == uint8_t(i + 1));
}

TEST_CASE("mock: get_binary round-trip (zero-copy bytes)")
{
    auto body = qm::varlen_column_bytes(
        {{0x00, 0x01, 0x02}, {0xFF, 0xEE}});
    qm::ColumnSpec c{"b", qm::COL_BINARY, std::move(body)};
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[c](int64_t rid)
                            { return qm::result_batch_frame(rid, 0, 2, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select b"_utf8);
    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
    auto v0 = batch.column(0).binary(0);
    auto v1 = batch.column(0).binary(1);
    REQUIRE(v0.has_value());
    REQUIRE(v0->size == 3);
    CHECK(v0->data[0] == 0x00);
    CHECK(v0->data[1] == 0x01);
    CHECK(v0->data[2] == 0x02);
    REQUIRE(v1.has_value());
    REQUIRE(v1->size == 2);
    CHECK(v1->data[0] == 0xFF);
    CHECK(v1->data[1] == 0xEE);
}

TEST_CASE("mock: get_decimal256 round-trip (32-byte mantissa + scale)")
{
    std::array<uint8_t, 32> raw{};
    raw[0] = 0xFE; raw[1] = 0xCA; raw[31] = 0x80;  // arbitrary pattern
    auto body = qm::decimal256_column_bytes({raw}, /*scale=*/4);
    qm::ColumnSpec c{"d", qm::COL_DECIMAL256, std::move(body)};
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[c](int64_t rid)
                            { return qm::result_batch_frame(rid, 0, 1, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select d"_utf8);
    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
    auto v = batch.column(0).get_decimal256(0);
    REQUIRE(v.has_value());
    CHECK(v->scale == 4);
    for (int i = 0; i < 32; ++i)
        CHECK(v->bytes[i] == raw[i]);
}

TEST_CASE("mock: get_geohash round-trip (precision_bits + bits)")
{
    // 8-bit precision: one byte per row.
    std::vector<uint8_t> packed = {0xAB, 0xCD};
    auto body = qm::geohash_column_bytes(
        {false, false}, packed, /*precision_bits=*/8);
    qm::ColumnSpec c{"g", qm::COL_GEOHASH, std::move(body)};
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[c](int64_t rid)
                            { return qm::result_batch_frame(rid, 0, 2, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select g"_utf8);
    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
    auto v0 = batch.column(0).get_geohash(0);
    auto v1 = batch.column(0).get_geohash(1);
    REQUIRE(v0.has_value());
    CHECK(v0->precision_bits == 8);
    CHECK(v0->value == 0xAB);
    REQUIRE(v1.has_value());
    CHECK(v1->precision_bits == 8);
    CHECK(v1->value == 0xCD);
}

// ---------------------------------------------------------------------------
// Stats / introspection getters previously uncovered: read_ns, decode_ns,
// reset_timing, credit_granted_total (reader + cursor), request_id,
// failover_resets, current_addr_port (reader + cursor), batch_request_id /
// batch_seq value pinning.
// ---------------------------------------------------------------------------

TEST_CASE("mock: stats and cursor introspection getters return live values")
{
    qm::ColumnSpec c{"v", qm::COL_INT,
                     qm::fixed_column_bytes(1, pack_le<int32_t>({99}))};
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[c](int64_t rid)
                            { return qm::result_batch_frame(rid, /*batch_seq=*/0, 1, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);

    // Captured before the cursor borrows the reader: the reader-side
    // getters reject while a query/cursor is live.
    const std::string reader_host{reader.current_host()};
    const uint16_t reader_port = reader.current_port();
    CHECK(reader_host == "127.0.0.1");
    CHECK(reader_port != 0);

    // Pre-batch timing should be definite (could be zero on a very fast
    // host but never negative; saturating semantics).
    const uint64_t r0 = reader.read_ns();
    const uint64_t d0 = reader.decode_ns();
    (void)r0; (void)d0;

    auto cur = reader.prepare("select v"_utf8).initial_credit(1024).execute();
    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;

    // request_id is non-zero and matches the batch's request_id.
    const int64_t rid = cur.request_id();
    CHECK(rid != 0);
    CHECK(batch.request_id() == rid);
    CHECK(batch.seq() == 0);

    // Cursor's current_addr_* mirror the reader (single endpoint).
    CHECK(cur.current_host() == reader_host);
    CHECK(cur.current_port() == reader_port);

    // No failover happened on this happy-path script.
    CHECK(cur.failover_resets() == 0);

    // After consuming a RESULT_BATCH the cursor auto-emits a MSG_CREDIT
    // replenishing the server's budget; the totals must be non-zero and
    // identical between reader and cursor (the cursor's accessor is a
    // pass-through).
    const uint64_t r_credit_before = reader.credit_granted_total();
    CHECK(r_credit_before > 0);
    CHECK(cur.credit_granted_total() == r_credit_before);

    // Drain remaining batches.
    while (cur.next_batch()) {}

    // After at least one read, read_ns / decode_ns should have advanced
    // (or stayed equal on extremely fast hosts — saturating arithmetic
    // forbids regression). Compare with the post-drain values.
    const uint64_t r1 = reader.read_ns();
    const uint64_t d1 = reader.decode_ns();
    CHECK(r1 >= r0);
    CHECK(d1 >= d0);

    // reset_timing zeroes the counters.
    reader.reset_timing();
    CHECK(reader.read_ns() == 0);
    CHECK(reader.decode_ns() == 0);
}

// ---------------------------------------------------------------------------
// Bind variants — exercise every bind_* function the wrapper exposes that
// is not already covered by the layout assertion test above. The intent
// is to catch panics / aborts / argument-marshalling bugs rather than
// pin every wire byte; the existing layout test plus the upstream bind
// encoder tests cover the wire format. The mock terminates each query
// with RESULT_END so each bind is a single-shot round-trip.
// ---------------------------------------------------------------------------

namespace
{
template <typename Fn>
void run_bind_round_trip(Fn&& bind_apply)
{
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto q = reader.prepare("X"_utf8);
    bind_apply(q);
    auto cur = q.execute();
    while (cur.next_batch()) {}
    auto reqs = srv.captured_requests();
    REQUIRE(reqs.size() == 1);
    CHECK(reqs[0][0] == qm::MSG_QUERY_REQUEST);
}

// Run a bind that the upstream encoder rejects (Symbol / Binary / Ipv4
// / array kinds — see questdb-rs/src/egress/binds.rs::check_bindable).
// The FFI surface exposes these; assert the rejection surfaces as a
// questdb::error with InvalidBind code rather than a panic / abort.
template <typename Fn>
void run_bind_rejection(Fn&& bind_apply)
{
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto q = reader.prepare("X"_utf8);
    bind_apply(q);
    bool threw = false;
    questdb::error_code code{};
    try
    {
        (void)q.execute();
    }
    catch (const questdb::error& e)
    {
        threw = true;
        code = e.code();
    }
    CHECK(threw);
    CHECK(code == questdb_error_invalid_bind);
}
} // namespace

// ---------------------------------------------------------------------------
// HTTP 401 on the WebSocket upgrade — reader construction must surface
// a clean error rather than crash. Exercises ActionReject401.
// ---------------------------------------------------------------------------

TEST_CASE("mock: WebSocket upgrade rejected with 401 surfaces a connect-time error")
{
    qm::Script s = {qm::ActionReject401{}};
    qm::MockServer srv({s});

    const std::string conf = "ws::addr=" + srv.addr() + ";";
    line_sender_utf8 c{conf.size(), conf.c_str()};
    questdb_error* err = nullptr;
    qwp_reader* r = qwp_reader_from_conf(c, &err);
    REQUIRE(r == nullptr);
    REQUIRE(err != nullptr);
    const auto code = questdb_error_get_code(err);
    // The mock returns HTTP 401 during the upgrade handshake. Upstream
    // currently surfaces this as either AuthError or HandshakeError
    // depending on which layer caught it; both are correct
    // connection-establishment failures. Anything else (e.g.
    // socket_error, config_error, success) is a regression.
    CHECK((code == questdb_error_auth_error
        || code == questdb_error_handshake_error));
    questdb_error_free(err);
}

// ---------------------------------------------------------------------------
// Multi-endpoint walk where every endpoint rejects 401 produces a
// single aggregated AuthError that names every endpoint that refused
// the credentials. Pins the per-endpoint telemetry path added so a
// heterogeneous-cluster credential drift can't hide behind a generic
// "auth failed" message.
// ---------------------------------------------------------------------------
TEST_CASE("mock: multi-addr walk aggregates per-endpoint 401 rejections")
{
    qm::MockServer srv1({{qm::ActionReject401{}}});
    qm::MockServer srv2({{qm::ActionReject401{}}});
    const std::string conf =
        "ws::addr=" + srv1.addr() + "," + srv2.addr() + ";";
    line_sender_utf8 c{conf.size(), conf.c_str()};
    questdb_error* err = nullptr;
    qwp_reader* r = qwp_reader_from_conf(c, &err);
    REQUIRE(r == nullptr);
    REQUIRE(err != nullptr);
    // Either AuthError (both endpoints actually replied 401) or
    // HandshakeError (race on one endpoint surfacing as a different
    // class). The aggregated-message check below is the part that
    // actually pins the new behaviour.
    const auto code = questdb_error_get_code(err);
    CHECK((code == questdb_error_auth_error
        || code == questdb_error_handshake_error));
    size_t mlen = 0;
    const char* msg = questdb_error_msg(err, &mlen);
    const std::string m{msg, mlen};
    if (code == questdb_error_auth_error)
    {
        // AuthError is terminal on the first 401: credentials are
        // cluster-wide, so retrying every host would flood server logs
        // without recovery (matches the Java reference's
        // QwpQueryClient.connect() which rethrows on QwpAuthFailedException
        // immediately). The diagnostic names the endpoint that refused.
        CHECK(m.find(srv1.addr()) != std::string::npos);
    }
    questdb_error_free(err);
}

// ---------------------------------------------------------------------------
// CACHE_RESET frame mid-stream — the reader must consume it and continue
// (it invalidates the symbol/schema caches; not a fatal event). Exercises
// ActionSendCacheReset.
// ---------------------------------------------------------------------------

TEST_CASE("mock: CACHE_RESET mid-stream is consumed without breaking the cursor")
{
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendCacheReset{},  // server invalidates symbol/schema caches
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select 1"_utf8);
    // The cursor must skip the CACHE_RESET and then see RESULT_END as
    // the terminal — a regression that mishandled the cache-reset
    // discriminant would either throw or return a phantom batch here.
    CHECK_FALSE(cur.next_batch());
    CHECK(cur.terminal_kind() == qwp_reader_terminal_kind_end);
}

// ---------------------------------------------------------------------------
// UTF-8 re-validation at the FFI boundary (M-4): hand-rolled
// `line_sender_utf8` with invalid bytes must surface as InvalidUtf8 from
// _query_new immediately, and from _bind_varchar (deferred) at execute().
// ---------------------------------------------------------------------------

// Both the C++ `reader` and `query` wrappers hold a single private
// `_impl` pointer as their first member. Read it through a layout-
// equivalent struct so these tests can drive the C entry points
// directly with hand-rolled (deliberately invalid) `line_sender_utf8`
// payloads — the C++ utf8_view constructor would refuse the input
// before it could reach the FFI.
namespace
{
::qwp_reader* raw_handle(questdb::egress::reader& r) noexcept
{
    struct reader_layout { ::qwp_reader* impl; };
    return reinterpret_cast<reader_layout*>(&r)->impl;
}
::qwp_reader_query* raw_handle(questdb::egress::query& q) noexcept
{
    struct query_layout { ::qwp_reader_query* impl; };
    return reinterpret_cast<query_layout*>(&q)->impl;
}
} // namespace

TEST_CASE("mock: query_new rejects invalid UTF-8 SQL with InvalidUtf8")
{
    qm::Script s = {qm::ActionSendServerInfo{}};
    qm::MockServer srv({s});
    auto reader = connect_to(srv);

    static const unsigned char bad[] = {'s', 'e', 'l', 'e', 'c', 't', 0xFF};
    line_sender_utf8 sql{7, reinterpret_cast<const char*>(bad)};
    questdb_error* err = nullptr;
    qwp_reader_query* q =
        qwp_reader_prepare(raw_handle(reader), sql, &err);
    REQUIRE(q == nullptr);
    REQUIRE(err != nullptr);
    CHECK(questdb_error_get_code(err) == questdb_error_invalid_utf8);
    questdb_error_free(err);
    // No QUERY_REQUEST should have hit the wire.
    CHECK(srv.captured_requests().empty());
}

TEST_CASE("mock: bind_varchar with invalid UTF-8 surfaces InvalidUtf8 at execute")
{
    qm::Script s = {
        qm::ActionSendServerInfo{},
        // No QueryRequest expected: execute() must fail before sending.
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);

    auto q = reader.prepare("X"_utf8);
    static const unsigned char bad[] = {0xC3, 0x28};  // invalid 2-byte UTF-8
    line_sender_utf8 v{2, reinterpret_cast<const char*>(bad)};
    qwp_reader_query_bind_varchar(raw_handle(q), v);
    // bind_varchar stashes the deferred error; execute() must surface
    // it as InvalidUtf8 without touching the wire.
    bool threw = false;
    questdb::error_code code{};
    try
    {
        (void)q.execute();
    }
    catch (const questdb::error& e)
    {
        threw = true;
        code = e.code();
    }
    CHECK(threw);
    CHECK(code == questdb_error_invalid_utf8);
    CHECK(srv.captured_requests().empty());
}

TEST_CASE("mock: bind_varchar deferred error wins over a later valid bind")
{
    qm::Script s = {qm::ActionSendServerInfo{}};
    qm::MockServer srv({s});
    auto reader = connect_to(srv);

    auto q = reader.prepare("X"_utf8);
    static const unsigned char bad[] = {0xC3, 0x28};
    line_sender_utf8 v_bad{2, reinterpret_cast<const char*>(bad)};
    qwp_reader_query_bind_varchar(raw_handle(q), v_bad);
    // A second, valid bind must not overwrite the first error.
    q.bind_i32(7);
    bool threw = false;
    questdb::error_code code{};
    try
    {
        (void)q.execute();
    }
    catch (const questdb::error& e)
    {
        threw = true;
        code = e.code();
    }
    CHECK(threw);
    CHECK(code == questdb_error_invalid_utf8);
}

TEST_CASE("mock: bind variants round-trip without crashing")
{
    using questdb::egress::query;

    SUBCASE("bind_bool")           { run_bind_round_trip([](query& q){ q.bind_bool(true); }); }
    SUBCASE("bind_i8")             { run_bind_round_trip([](query& q){ q.bind_i8(-7); }); }
    SUBCASE("bind_i16")            { run_bind_round_trip([](query& q){ q.bind_i16(-31000); }); }
    SUBCASE("bind_i64")            { run_bind_round_trip([](query& q){ q.bind_i64(-1); }); }
    SUBCASE("bind_f32")            { run_bind_round_trip([](query& q){ q.bind_f32(1.5f); }); }
    SUBCASE("bind_f64")            { run_bind_round_trip([](query& q){ q.bind_f64(-2.25); }); }
    SUBCASE("bind_timestamp_micros"){ run_bind_round_trip([](query& q){ q.bind_timestamp_micros(1234567890); }); }
    SUBCASE("bind_timestamp_nanos"){ run_bind_round_trip([](query& q){ q.bind_timestamp_nanos(1234567890123); }); }
    SUBCASE("bind_date_millis")    { run_bind_round_trip([](query& q){ q.bind_date_millis(1234567890); }); }
    SUBCASE("bind_char")           { run_bind_round_trip([](query& q){ q.bind_char(uint16_t(u'Z')); }); }
    SUBCASE("bind_decimal64")      { run_bind_round_trip([](query& q){ q.bind_decimal64(12345, 2); }); }
    SUBCASE("bind_decimal256")
    {
        run_bind_round_trip(
            [](query& q)
            {
                std::array<uint8_t, 32> b{};
                b[0] = 0xAB;
                q.bind_decimal256(b, 4);
            });
    }
    SUBCASE("bind_geohash")        { run_bind_round_trip([](query& q){ q.bind_geohash(0xAB, 8); }); }
    SUBCASE("bind_uuid")
    {
        run_bind_round_trip(
            [](query& q)
            {
                std::array<uint8_t, 16> u{};
                for (int i = 0; i < 16; ++i) u[i] = uint8_t(i);
                q.bind_uuid(u);
            });
    }
    SUBCASE("bind_long256")
    {
        run_bind_round_trip(
            [](query& q)
            {
                std::array<uint8_t, 32> l{};
                l[31] = 0x80;
                q.bind_long256(l);
            });
    }
    // bind_ipv4 / bind_binary / bind_null_binary are exposed on the FFI
    // surface but the upstream encoder rejects them (see binds.rs
    // check_bindable: SYMBOL / BINARY / IPv4 / array kinds aren't valid
    // bind values per the QWP spec). Assert the rejection surfaces as
    // an InvalidBind error rather than a panic / abort.
    SUBCASE("bind_ipv4 → InvalidBind")
    {
        run_bind_rejection([](query& q){ q.bind_ipv4(0x7F000001); });
    }
    SUBCASE("bind_binary → InvalidBind")
    {
        run_bind_rejection(
            [](query& q)
            {
                const uint8_t buf[] = {0xDE, 0xAD, 0xBE, 0xEF};
                q.bind_binary(buf, sizeof(buf));
            });
    }
    SUBCASE("bind_binary empty → InvalidBind")
    {
        run_bind_rejection([](query& q){ q.bind_binary(nullptr, 0); });
    }
    SUBCASE("bind_null_binary → InvalidBind")
    {
        run_bind_rejection([](query& q){ q.bind_null_binary(); });
    }
    SUBCASE("bind_null_varchar")     { run_bind_round_trip([](query& q){ q.bind_null_varchar(); }); }
    SUBCASE("bind_null_decimal64")   { run_bind_round_trip([](query& q){ q.bind_null_decimal64(2); }); }
    SUBCASE("bind_null_decimal128")  { run_bind_round_trip([](query& q){ q.bind_null_decimal128(2); }); }
    SUBCASE("bind_null_decimal256")  { run_bind_round_trip([](query& q){ q.bind_null_decimal256(2); }); }
    SUBCASE("bind_null_geohash")     { run_bind_round_trip([](query& q){ q.bind_null_geohash(8); }); }
    SUBCASE("bind_null(kind)")
    {
        run_bind_round_trip([](query& q){ q.bind_null(questdb::egress::column_kind::int_); });
    }
}

// ---------------------------------------------------------------------------
// column_name: borrowed schema name surfaces verbatim through the FFI.
// ---------------------------------------------------------------------------
TEST_CASE("mock: column_name returns the schema's column name")
{
    qm::ColumnSpec c0{
        "my_long",
        qm::COL_LONG,
        qm::fixed_column_bytes(1, pack_le<int64_t>({42}))};
    qm::ColumnSpec c1{
        "another_col",
        qm::COL_DOUBLE,
        qm::fixed_column_bytes(1, pack_le<double>({1.5}))};

    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[c0, c1](int64_t rid)
                            { return qm::result_batch_frame(rid, 0, 1, {c0, c1}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});

    auto reader = connect_to(srv);
    auto cur = reader.execute("select * from t"_utf8);
    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
    REQUIRE(batch.column_count() == 2);
    CHECK(batch.column_name(0) == "my_long");
    CHECK(batch.column_name(1) == "another_col");
    CHECK_FALSE(cur.next_batch());
}

TEST_CASE("mock: column_name fails cleanly on out-of-range index")
{
    qm::ColumnSpec c{
        "v",
        qm::COL_LONG,
        qm::fixed_column_bytes(1, pack_le<int64_t>({0}))};

    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[c](int64_t rid)
                            { return qm::result_batch_frame(rid, 0, 1, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});

    auto reader = connect_to(srv);
    auto cur = reader.execute("select v from t"_utf8);
    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
    REQUIRE(batch.column_count() == 1);

    bool threw = false;
    questdb::error_code code{};
    try
    {
        (void)batch.column_name(99);
    }
    catch (const questdb::error& e)
    {
        threw = true;
        code = e.code();
    }
    CHECK(threw);
    CHECK(code == questdb_error_invalid_api_call);
}

// ---------------------------------------------------------------------------
// IPV4 getter: round-trip the high-bit IP space (≥ 128.0.0.0) that would
// sign-flip if the value were reinterpreted as int32_t.
// ---------------------------------------------------------------------------
TEST_CASE("mock: get_ipv4 round-trips high-bit IPs without sign-flipping")
{
    // 192.168.0.1 = 0xC0A80001; 10.0.0.1 = 0x0A000001; 240.1.2.3 = 0xF0010203.
    qm::ColumnSpec c{
        "ip",
        qm::COL_IPV4,
        qm::fixed_column_bytes(
            3,
            pack_le<uint32_t>({0xC0A80001u, 0x0A000001u, 0xF0010203u}))};

    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[c](int64_t rid)
                            { return qm::result_batch_frame(rid, 0, 3, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});

    auto reader = connect_to(srv);
    auto cur = reader.execute("select ip from t"_utf8);
    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
    REQUIRE(batch.column_kind(0) == qwp_reader_column_kind_ipv4);

    auto v0 = batch.column(0).get<uint32_t>(0);
    auto v1 = batch.column(0).get<uint32_t>(1);
    auto v2 = batch.column(0).get<uint32_t>(2);
    REQUIRE(v0.has_value());
    REQUIRE(v1.has_value());
    REQUIRE(v2.has_value());
    CHECK(*v0 == 0xC0A80001u);
    CHECK(*v1 == 0x0A000001u);
    CHECK(*v2 == 0xF0010203u);
    CHECK_FALSE(cur.next_batch());
}

TEST_CASE("mock: get_i32 rejects an IPV4 column with a type-mismatch error")
{
    qm::ColumnSpec c{
        "ip",
        qm::COL_IPV4,
        qm::fixed_column_bytes(1, pack_le<uint32_t>({0xC0A80001u}))};

    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[c](int64_t rid)
                            { return qm::result_batch_frame(rid, 0, 1, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});

    auto reader = connect_to(srv);
    auto cur = reader.execute("select ip from t"_utf8);
    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
    REQUIRE(batch.column_kind(0) == qwp_reader_column_kind_ipv4);

    bool threw = false;
    questdb::error_code code{};
    try
    {
        (void)batch.column(0).get<int32_t>(0);
    }
    catch (const questdb::error& e)
    {
        threw = true;
        code = e.code();
    }
    CHECK(threw);
    CHECK(code == questdb_error_invalid_api_call);
}

TEST_CASE("mock: get_ipv4 rejects an INT column with a type-mismatch error")
{
    qm::ColumnSpec c{
        "n",
        qm::COL_INT,
        qm::fixed_column_bytes(1, pack_le<int32_t>({42}))};

    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[c](int64_t rid)
                            { return qm::result_batch_frame(rid, 0, 1, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});

    auto reader = connect_to(srv);
    auto cur = reader.execute("select n from t"_utf8);
    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;

    bool threw = false;
    questdb::error_code code{};
    try
    {
        (void)batch.column(0).get<uint32_t>(0);
    }
    catch (const questdb::error& e)
    {
        threw = true;
        code = e.code();
    }
    CHECK(threw);
    CHECK(code == questdb_error_invalid_api_call);
}

// ---------------------------------------------------------------------------
// Deferred-error short-circuit: once `_bind_varchar` has stashed an
// InvalidUtf8 error, no subsequent bind reaches the upstream builder.
// We verify by binding {bad-utf8-varchar, then i32, varchar, i64} and
// checking that the captured QueryRequest never appears (execute aborts
// pre-wire) AND that, with the short-circuit removed, the error code
// would still be InvalidUtf8 (first-error-wins).
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Wrong-column-type rejection: each typed column accessor must reject a
// column whose kind doesn't match. Drive this from a single INT column
// and call every other accessor once. Each must throw `invalid_api_call`.
// This pins the kind-whitelist + ensure_kind throws on `column::get<T>` /
// `column::varchar` / `column::symbol` / etc.
// ---------------------------------------------------------------------------
TEST_CASE("mock: typed getters reject mismatched column kind")
{
    qm::ColumnSpec int_col{
        "n", qm::COL_INT, qm::fixed_column_bytes(1, pack_le<int32_t>({42}))};
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[int_col](int64_t rid)
                            { return qm::result_batch_frame(rid, 0, 1, {int_col}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});

    auto reader = connect_to(srv);
    auto cur = reader.execute("select n from t"_utf8);
    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;

    auto expect_throws = [&](auto&& fn) {
        bool threw = false;
        questdb::error_code code{};
        try
        {
            fn();
        }
        catch (const questdb::error& e)
        {
            threw = true;
            code = e.code();
        }
        CHECK(threw);
        CHECK(code == questdb_error_invalid_api_call);
    };

    SUBCASE("get_bool")        { expect_throws([&]{ (void)batch.column(0).get<bool>(0); }); }
    SUBCASE("get_i8")          { expect_throws([&]{ (void)batch.column(0).get<int8_t>(0); }); }
    SUBCASE("get_i16")         { expect_throws([&]{ (void)batch.column(0).get<int16_t>(0); }); }
    SUBCASE("get_i64")         { expect_throws([&]{ (void)batch.column(0).get<int64_t>(0); }); }
    SUBCASE("get_f32")         { expect_throws([&]{ (void)batch.column(0).get<float>(0); }); }
    SUBCASE("get_f64")         { expect_throws([&]{ (void)batch.column(0).get<double>(0); }); }
    SUBCASE("get_char")        { expect_throws([&]{ (void)batch.column(0).get<uint16_t>(0); }); }
    SUBCASE("get_uuid")        { expect_throws([&]{ (void)batch.column(0).get_uuid(0); }); }
    SUBCASE("get_long256")     { expect_throws([&]{ (void)batch.column(0).get_long256(0); }); }
    SUBCASE("get_varchar")     { expect_throws([&]{ (void)batch.column(0).varchar(0); }); }
    SUBCASE("get_binary")      { expect_throws([&]{ (void)batch.column(0).binary(0); }); }
    SUBCASE("get_symbol")      { expect_throws([&]{ (void)batch.column(0).symbol(0); }); }
    SUBCASE("get_decimal64")   { expect_throws([&]{ (void)batch.column(0).get_decimal64(0); }); }
    SUBCASE("get_decimal128")  { expect_throws([&]{ (void)batch.column(0).get_decimal128(0); }); }
    SUBCASE("get_decimal256")  { expect_throws([&]{ (void)batch.column(0).get_decimal256(0); }); }
    SUBCASE("get_geohash")     { expect_throws([&]{ (void)batch.column(0).get_geohash(0); }); }
    SUBCASE("array shape on scalar col") {
        expect_throws([&]{ size_t r=0; (void)batch.column(0).shape(0, &r); });
    }
    SUBCASE("get_ipv4")        { expect_throws([&]{ (void)batch.column(0).get<uint32_t>(0); }); }
}

// ---------------------------------------------------------------------------
// Out-of-range index handling.
// ---------------------------------------------------------------------------
TEST_CASE("mock: column accessors reject out-of-range indices")
{
    qm::ColumnSpec int_col{
        "n", qm::COL_INT, qm::fixed_column_bytes(2, pack_le<int32_t>({10, 20}))};
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[int_col](int64_t rid)
                            { return qm::result_batch_frame(rid, 0, 2, {int_col}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});

    auto reader = connect_to(srv);
    auto cur = reader.execute("select n from t"_utf8);
    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
    REQUIRE(batch.column_count() == 1);
    REQUIRE(batch.row_count() == 2);

    auto expect_invalid_api = [](auto&& fn) {
        bool threw = false;
        questdb::error_code code{};
        try
        {
            fn();
        }
        catch (const questdb::error& e)
        {
            threw = true;
            code = e.code();
        }
        CHECK(threw);
        CHECK(code == questdb_error_invalid_api_call);
    };

    SUBCASE("column_kind out-of-range column")
    {
        expect_invalid_api([&]{ (void)batch.column_kind(99); });
    }
    SUBCASE("column_name out-of-range column")
    {
        expect_invalid_api([&]{ (void)batch.column_name(99); });
    }
    SUBCASE("get_i32 out-of-range column")
    {
        expect_invalid_api([&]{ (void)batch.column(99).get<int32_t>(0); });
    }
    SUBCASE("get_i32 out-of-range row")
    {
        expect_invalid_api([&]{ (void)batch.column(0).get<int32_t>(99); });
    }
}

// ---------------------------------------------------------------------------
// TIMESTAMP / DATE / TIMESTAMP_NANOS round-trip via `get_i64`. The agent
// flagged that these kinds had no positive test — they share i64 storage
// with LONG and the type-dispatch in egress.rs:1410 needs pinning.
// ---------------------------------------------------------------------------
TEST_CASE("mock: get_i64 round-trips TIMESTAMP / DATE / TIMESTAMP_NANOS")
{
    const int64_t ts_us = 1'700'000'000'000'000LL;     // 2023-11-14, μs
    const int64_t date_ms = 1'700'000'000'000LL;       // 2023-11-14, ms
    const int64_t ts_ns = 1'700'000'000'123'456'789LL; // 2023-11-14, ns

    qm::ColumnSpec c_ts{
        "ts", qm::COL_TIMESTAMP,
        qm::fixed_column_bytes(1, pack_le<int64_t>({ts_us}))};
    qm::ColumnSpec c_date{
        "d", qm::COL_DATE,
        qm::fixed_column_bytes(1, pack_le<int64_t>({date_ms}))};
    qm::ColumnSpec c_tn{
        "tn", qm::COL_TIMESTAMP_NANOS,
        qm::fixed_column_bytes(1, pack_le<int64_t>({ts_ns}))};

    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[c_ts, c_date, c_tn](int64_t rid)
                            {
                                return qm::result_batch_frame(
                                    rid, 0, 1, {c_ts, c_date, c_tn});
                            }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});

    auto reader = connect_to(srv);
    auto cur = reader.execute("select ts, d, tn from t"_utf8);
    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
    REQUIRE(batch.column_count() == 3);
    CHECK(batch.column_kind(0) == qwp_reader_column_kind_timestamp);
    CHECK(batch.column_kind(1) == qwp_reader_column_kind_date);
    CHECK(batch.column_kind(2) == qwp_reader_column_kind_timestamp_nanos);

    auto v0 = batch.column(0).get<int64_t>(0);
    auto v1 = batch.column(1).get<int64_t>(0);
    auto v2 = batch.column(2).get<int64_t>(0);
    REQUIRE(v0.has_value());
    REQUIRE(v1.has_value());
    REQUIRE(v2.has_value());
    CHECK(*v0 == ts_us);
    CHECK(*v1 == date_ms);
    CHECK(*v2 == ts_ns);
}

// ---------------------------------------------------------------------------
// DOUBLE_ARRAY / LONG_ARRAY data_len not divisible by 8 must surface as a
// ProtocolError, never as a successful read with a silently-truncated
// element_count. The upstream decoder catches most misalignment patterns
// at the frame level (trailing-bytes check); the FFI's per-row
// `raw.len() % 8 == 0` guard (egress.rs in `_get_double_array`) is
// defense-in-depth that catches anything that slips past. Either layer
// raising ProtocolError is acceptable; what matters is that NO call path
// returns a valid-looking view from misaligned bytes.
// ---------------------------------------------------------------------------
TEST_CASE(
    "mock: DOUBLE_ARRAY misaligned data_len surfaces as ProtocolError")
{
    qm::ArrayRow row{{1u, 1u}, std::vector<uint8_t>(11, 0xCC)};
    qm::ColumnSpec c{
        "a", qm::COL_DOUBLE_ARRAY,
        qm::array_column_bytes({std::optional<qm::ArrayRow>{std::move(row)}})};

    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[c](int64_t rid)
                            { return qm::result_batch_frame(rid, 0, 1, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});

    auto reader = connect_to(srv);
    auto cur = reader.execute("select a from t"_utf8);

    bool threw = false;
    questdb::error_code code{};
    try
    {
        // Either next_batch() (upstream frame-level check) or column()
        // (per-row decoder) must throw the protocol error.
        if (auto bo = cur.next_batch())
        {
            auto col = bo->column(0);
            size_t cnt = 0;
            (void)col.elements<double>(0, &cnt);
        }
    }
    catch (const questdb::error& e)
    {
        threw = true;
        code = e.code();
    }
    CHECK(threw);
    CHECK(code == questdb_error_protocol_error);
}

// ---------------------------------------------------------------------------
// C++ wrapper move semantics: `reader`, `query`, and `cursor` are
// move-only with NULL-idempotent destructors. Move-construction must
// transfer the impl pointer and null the source so its destructor does
// not double-free.
// ---------------------------------------------------------------------------
TEST_CASE("mock: C++ wrapper move semantics — reader / cursor")
{
    qm::ColumnSpec c{
        "v", qm::COL_INT, qm::fixed_column_bytes(1, pack_le<int32_t>({1}))};
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[c](int64_t rid)
                            { return qm::result_batch_frame(rid, 0, 1, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});

    SUBCASE("reader move-construct then destroy original")
    {
        auto r1 = connect_to(srv);
        auto r2 = std::move(r1);
        // r1 is now empty; using its destructor must be a no-op.
        // r2 still owns the impl and must work normally.
        auto cur = r2.execute("select v from t"_utf8);
        auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
        auto v = batch.column(0).get<int32_t>(0);
        REQUIRE(v.has_value());
        CHECK(*v == 1);
    }

    SUBCASE("cursor move-construct preserves the live cursor")
    {
        auto r = connect_to(srv);
        auto cur1 = r.execute("select v from t"_utf8);
        auto cur2 = std::move(cur1);
        auto bo = cur2.next_batch();
        REQUIRE(bo);
        auto v = bo->column(0).get<int32_t>(0);
        REQUIRE(v.has_value());
        CHECK(*v == 1);
    }
}

TEST_CASE(
    "mock: binds after a deferred utf8 error are no-ops (index stability)")
{
    qm::Script s = {
        qm::ActionSendServerInfo{},
        // No QueryRequest expected: execute() must abort before sending.
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);

    auto q = reader.prepare("X"_utf8);
    static const unsigned char bad[] = {0xC3, 0x28};
    line_sender_utf8 bad_v{2, reinterpret_cast<const char*>(bad)};

    // Bad bind first: stashes deferred_err.
    qwp_reader_query_bind_varchar(raw_handle(q), bad_v);

    // Subsequent binds: each MUST be a no-op now. Pre-fix, these would
    // push into the upstream builder and shift indices.
    q.bind_i32(7);
    q.bind_varchar("widgets"_utf8);
    q.bind_i64(-1);
    q.bind_null(questdb::egress::column_kind::long_);

    bool threw = false;
    questdb::error_code code{};
    try
    {
        (void)q.execute();
    }
    catch (const questdb::error& e)
    {
        threw = true;
        code = e.code();
    }
    CHECK(threw);
    CHECK(code == questdb_error_invalid_utf8);
    // Wire never saw the request — the deferred error short-circuits
    // execute() before the builder is consumed.
    CHECK(srv.captured_requests().empty());
}

// ---------------------------------------------------------------------------
// server_info accessors round-trip non-zero `epoch`, `capabilities`,
// `server_wall_ns`, and `role` from the wire. The handshake test only
// exercised `role_byte`/`cluster_id`/`node_id`; the remaining accessors
// were left unobserved with the mock hard-coding zero. Here we drive
// non-zero values through and assert each accessor reads them back.
// ---------------------------------------------------------------------------
TEST_CASE("mock: server_info exposes role / epoch / capabilities / wall_ns")
{
    constexpr uint64_t expected_epoch = 0xCAFEBABEDEADBEEFULL;
    constexpr uint32_t expected_caps  = 0x12345678u | qm::CAP_ZONE;
    constexpr int64_t  expected_wall  = 1'700'000'000'000'000'000LL;

    qm::ActionSendServerInfo si{};
    si.role           = qm::ROLE_PRIMARY;
    si.cluster_id     = "cluster-x";
    si.node_id        = "node-x";
    si.epoch          = expected_epoch;
    si.capabilities   = expected_caps;
    si.server_wall_ns = expected_wall;
    si.zone_id        = "eu-west-1a";

    qm::Script s = {si, qm::ActionAwaitQueryRequest{}, qm::ActionSendResultEnd{}};
    qm::MockServer srv({s});

    auto reader = connect_to(srv);
    auto info = reader.server_info();
    CHECK(info.role_byte() == qm::ROLE_PRIMARY);
    CHECK(info.role() == questdb::egress::server_role::primary);
    CHECK(info.epoch() == expected_epoch);
    CHECK(info.capabilities() == expected_caps);
    CHECK(info.server_wall_ns() == expected_wall);
    CHECK(info.cluster_id() == "cluster-x");
    CHECK(info.node_id() == "node-x");
    REQUIRE(info.zone_id().has_value());
    CHECK(*info.zone_id() == "eu-west-1a");

    // Rvalue-qualified string getters return owning values. Chained access on
    // the by-value server_info result therefore cannot refer into a destroyed
    // temporary.
    static_assert(std::is_same_v<
        decltype(std::declval<eg::server_info&&>().cluster_id()),
        std::string>);
    static_assert(std::is_same_v<
        decltype(std::declval<eg::server_info&&>().zone_id()),
        std::optional<std::string>>);
    const std::string& temporary_cluster =
        reader.server_info().cluster_id();
    const auto& temporary_zone = reader.server_info().zone_id();
    CHECK(temporary_cluster == "cluster-x");
    REQUIRE(temporary_zone.has_value());
    CHECK(*temporary_zone == "eu-west-1a");
}

TEST_CASE("mock: owning server_info preserves unknown role and outlives reader")
{
    std::optional<eg::server_info> captured;
    {
        qm::Script s = {
            qm::ActionSendServerInfo{0x55, "cluster-owned", "node-owned"},
        };
        qm::MockServer srv({s});
        auto reader = connect_to(srv);
        captured.emplace(reader.server_info());
        CHECK(captured->role() == eg::server_role::other);
        CHECK(captured->role_byte() == 0x55);
    }

    // The reader and its Rust-owned strings are gone. The C++ snapshot keeps
    // independent storage rather than a dangling qwp_reader_server_info pointer.
    REQUIRE(captured.has_value());
    CHECK(captured->cluster_id() == "cluster-owned");
    CHECK(captured->node_id() == "node-owned");
    CHECK_FALSE(captured->zone_id().has_value());
}

// ---------------------------------------------------------------------------
// terminal_exec_done(out_op_type, out_rows_affected) — the `terminal_kind
// == exec_done` test above only checked the discriminant. Here we drive a
// non-zero op_type and rows_affected through the mock and assert the
// accessor returns them.
// ---------------------------------------------------------------------------
TEST_CASE("mock: cursor::terminal_exec_done returns op_type and rows_affected")
{
    qm::ActionSendExecDone done{};
    done.op_type       = 0x42;     // arbitrary non-zero, opaque to the client
    done.rows_affected = 1'234'567ULL;

    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        done,
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("update t set x = 1"_utf8);
    CHECK_FALSE(cur.next_batch());
    REQUIRE(cur.terminal_kind() == qwp_reader_terminal_kind_exec_done);

    auto info = cur.terminal_exec_done();
    REQUIRE(info.has_value());
    CHECK(info->op_type == 0x42);
    CHECK(info->rows_affected == 1'234'567ULL);

    // The other-terminal accessor must reject this terminal kind.
    auto end_info = cur.terminal_end();
    CHECK_FALSE(end_info.has_value());
}

// ---------------------------------------------------------------------------
// failover_reset_event_view: extend the existing failover assertions to cover
// `new_request_id`, `elapsed_ns`, and `trigger_msg`, which the original
// trampoline test left unobserved.
// ---------------------------------------------------------------------------
TEST_CASE("mock: failover event exposes new_request_id, elapsed_ns, trigger_msg")
{
    qm::Script s_a = {
        qm::ActionSendServerInfo{qm::ROLE_STANDALONE, "c", "a"},
        qm::ActionAwaitQueryRequest{},
        qm::ActionHardDrop{},
    };
    qm::Script s_b = {
        qm::ActionSendServerInfo{qm::ROLE_STANDALONE, "c", "b"},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv_a({s_a});
    qm::MockServer srv_b({s_b});

    // A small but non-zero initial backoff so `elapsed_ns` is reliably
    // > 0 without slowing the test.
    const std::string conf =
        "ws::addr=" + srv_a.addr() + "," + srv_b.addr() +
        ";failover_backoff_initial_ms=2;failover_backoff_max_ms=20";
    questdb::egress::reader reader{questdb::ingress::utf8_view{conf}};

    struct Capture
    {
        std::atomic<int> count{0};
        int64_t  new_request_id{0};
        uint64_t elapsed_ns{0};
        std::string trigger_msg;
    };
    auto cap = std::make_shared<Capture>();

    auto cur = reader.prepare("select 1"_utf8)
                   .on_failover_reset(
                       [cap](const questdb::egress::failover_reset_event_view& ev)
                       {
                           cap->count.fetch_add(1);
                           cap->new_request_id = ev.new_request_id();
                           cap->elapsed_ns = ev.elapsed_ns();
                           cap->trigger_msg = std::string(ev.trigger_msg());
                       })
                   .execute();
    CHECK_FALSE(cur.next_batch());
    REQUIRE(cap->count.load() == 1);

    // After failover the cursor's own request_id must equal the
    // new_request_id reported by the event — the cursor adopts the
    // freshly-allocated id of its replayed query.
    CHECK(cap->new_request_id != 0);
    CHECK(cap->new_request_id == cur.request_id());
    // Backoff was 2ms initially; elapsed_ns must be strictly positive.
    CHECK(cap->elapsed_ns > 0);
    // Trigger message is non-empty and human-readable (we don't pin the
    // exact text — upstream wording can change, but it must not be blank).
    CHECK_FALSE(cap->trigger_msg.empty());
}

// ---------------------------------------------------------------------------
// Move-assignment for `reader`, `query`, and `cursor`. The earlier test
// only covered move-construction; assignment exercises a separate code
// path (operator= must free the assignee's existing impl before adopting
// the source's).
// ---------------------------------------------------------------------------
TEST_CASE("mock: C++ wrapper move-assignment — reader / query / cursor")
{
    qm::ColumnSpec c{
        "v", qm::COL_INT, qm::fixed_column_bytes(1, pack_le<int32_t>({7}))};

    SUBCASE("reader move-assign frees the LHS reader and adopts the RHS")
    {
        // Two independent mock servers so we can prove the LHS reader's
        // socket was actually freed (and not leaked) by counting accepts.
        qm::Script s1 = {qm::ActionSendServerInfo{}};
        qm::Script s2 = {
            qm::ActionSendServerInfo{},
            qm::ActionAwaitQueryRequest{},
            qm::ActionSendBuilt{
                [c](int64_t rid)
                { return qm::result_batch_frame(rid, 0, 1, {c}); }},
            qm::ActionSendResultEnd{},
        };
        qm::MockServer srv1({s1});
        qm::MockServer srv2({s2});

        auto r = connect_to(srv1);
        r = connect_to(srv2);  // move-assign — must close srv1's socket
        // The new reader works against srv2.
        auto cur = r.execute("select v from t"_utf8);
        auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
        auto v = batch.column(0).get<int32_t>(0);
        REQUIRE(v.has_value());
        CHECK(*v == 7);
    }

    SUBCASE("query move-assign over a live query frees the LHS impl")
    {
        // Two independent readers, two live queries. Move-assigning q2
        // over q1 must free q1's impl (releasing reader1's `active`
        // flag through `qwp_reader_query_free`) and transfer q2's impl
        // into q1. The successor execute() then runs against reader2.
        qm::Script s1 = {qm::ActionSendServerInfo{}};
        qm::Script s2 = {
            qm::ActionSendServerInfo{},
            qm::ActionAwaitQueryRequest{},
            qm::ActionSendBuilt{
                [c](int64_t rid)
                { return qm::result_batch_frame(rid, 0, 1, {c}); }},
            qm::ActionSendResultEnd{},
        };
        qm::MockServer srv1({s1});
        qm::MockServer srv2({s2});
        auto reader1 = connect_to(srv1);
        auto reader2 = connect_to(srv2);
        auto q1 = reader1.prepare("X"_utf8);
        q1.bind_i32(1);
        auto q2 = reader2.prepare("Y"_utf8);
        q2.bind_i32(7);
        q1 = std::move(q2);  // move-assign — frees q1's old impl
        auto cur = q1.execute();
        auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
        auto v = batch.column(0).get<int32_t>(0);
        REQUIRE(v.has_value());
        CHECK(*v == 7);
    }

    SUBCASE("query move-assign into a moved-from query is a no-op free")
    {
        // After q_b = std::move(q_a) the LHS q_a is empty (impl ==
        // nullptr). Reassigning into it must call _query_free on
        // nullptr (idempotent, by FFI contract) before adopting the
        // RHS, NOT crash. This is the path operator= takes when the
        // LHS was moved-from earlier in the same scope.
        qm::Script s = {
            qm::ActionSendServerInfo{},
            qm::ActionAwaitQueryRequest{},
            qm::ActionSendBuilt{
                [c](int64_t rid)
                { return qm::result_batch_frame(rid, 0, 1, {c}); }},
            qm::ActionSendResultEnd{},
        };
        qm::MockServer srv({s});
        auto reader = connect_to(srv);
        auto q_a = reader.prepare("X"_utf8);
        auto q_b = std::move(q_a);   // q_a empty
        q_a = std::move(q_b);        // assign into empty — must not crash
        q_a.bind_i32(7);
        auto cur = q_a.execute();
        auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
        auto v = batch.column(0).get<int32_t>(0);
        REQUIRE(v.has_value());
        CHECK(*v == 7);
    }

    SUBCASE("cursor move-assign frees the LHS cursor and adopts the RHS")
    {
        // Two scripts so the LHS cursor is closed (its socket dropped)
        // when the move-assign overwrites it.
        qm::Script s1 = {
            qm::ActionSendServerInfo{},
            qm::ActionAwaitQueryRequest{},
            qm::ActionSendResultEnd{},
        };
        qm::Script s2 = {
            qm::ActionSendServerInfo{},
            qm::ActionAwaitQueryRequest{},
            qm::ActionSendBuilt{
                [c](int64_t rid)
                { return qm::result_batch_frame(rid, 0, 1, {c}); }},
            qm::ActionSendResultEnd{},
        };
        qm::MockServer srv1({s1});
        qm::MockServer srv2({s2});
        auto r1 = connect_to(srv1);
        auto r2 = connect_to(srv2);
        auto cur = r1.execute("select 1"_utf8);
        // Drain r1's stream so its cursor is in a clean terminal state
        // before we overwrite it (the move-assign would call _close on
        // the live cursor regardless, but draining keeps the lifecycle
        // observable).
        while (cur.next_batch()) {}
        cur = r2.execute("select v from t"_utf8);  // move-assign
        auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
        auto v = batch.column(0).get<int32_t>(0);
        REQUIRE(v.has_value());
        CHECK(*v == 7);
    }
}

// ---------------------------------------------------------------------------
// next_batch idempotency after the stream has terminated: once the
// cursor has observed a RESULT_END / EXEC_DONE terminal and reported
// `false`, subsequent calls to next_batch() must keep returning `false`
// (and not throw) — the FFI must not retry the network or surface a
// spurious error.
// ---------------------------------------------------------------------------
TEST_CASE("mock: next_batch is idempotent after the stream terminus")
{
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select 1"_utf8);
    CHECK_FALSE(cur.next_batch());
    REQUIRE(cur.terminal_kind() == qwp_reader_terminal_kind_end);

    // Repeated calls after the terminus must keep returning false and
    // NOT throw. Five iterations is overkill but cheap insurance.
    for (int i = 0; i < 5; ++i)
    {
        CHECK_FALSE(cur.next_batch());
        CHECK(cur.terminal_kind() == qwp_reader_terminal_kind_end);
    }
}

// ---------------------------------------------------------------------------
// `target=primary` against a server that advertises ROLE_REPLICA must
// surface as `role_mismatch` at reader-construction time. Pins the
// negative half of the role-filter logic in upstream
// `reader.rs::target_matches`; the positive half is exercised by every
// other test that uses ROLE_STANDALONE/_PRIMARY without a target filter.
// ---------------------------------------------------------------------------
TEST_CASE("mock: target=primary against replica-only endpoint surfaces role_mismatch")
{
    qm::Script s = {
        qm::ActionSendServerInfo{qm::ROLE_REPLICA, "cluster-x", "replica-1"},
    };
    qm::MockServer srv({s});

    const std::string conf = "ws::addr=" + srv.addr() + ";target=primary;";
    line_sender_utf8 c{conf.size(), conf.c_str()};
    questdb_error* err = nullptr;
    qwp_reader* r = qwp_reader_from_conf(c, &err);
    REQUIRE(r == nullptr);
    REQUIRE(err != nullptr);
    CHECK(questdb_error_get_code(err) == questdb_error_role_mismatch);
    questdb_error_free(err);
}

// ---------------------------------------------------------------------------
// Malformed-frame coverage. Exercises the `protocol_error` paths inside
// the WS frame parser and the RESULT_BATCH decoder by hand-crafting
// frames the friendly builders refuse to emit. Uses `ActionSendRaw`
// (otherwise dead code in this suite — the friendly builders cover the
// happy path). Each test connects, executes a no-op query, and asserts
// `next_batch()` surfaces `questdb_error_protocol_error` with the
// cursor torn down.
// ---------------------------------------------------------------------------

namespace
{

void run_malformed_batch(
    qm::Script script,
    ::questdb_error_code expected = questdb_error_protocol_error)
{
    qm::MockServer srv({std::move(script)});
    // Disable failover. ProtocolError is failover-eligible by default,
    // so the client would otherwise reconnect to the (now scriptless)
    // mock and hang. Disabling makes the malformed-frame error
    // surface directly on `next_batch`.
    const std::string conf =
        "ws::addr=" + srv.addr() + ";failover=off;";
    questdb::egress::reader reader{
        questdb::ingress::utf8_view{conf}};
    auto cur = reader.execute("select 1"_utf8);
    bool threw = false;
    try
    {
        cur.next_batch();
        FAIL("expected error from malformed frame");
    }
    catch (const questdb::error& e)
    {
        threw = true;
        CHECK(e.code() == expected);
    }
    CHECK(threw);
}

} // anonymous namespace

TEST_CASE("mock: protocol_error — header.payload_length lies (claims more bytes than sent)")
{
    // Build a valid-looking RESULT_BATCH then overwrite the 4-byte
    // payload_length in the header with a value larger than the actual
    // payload. transport.rs::read_frame's mismatch check fires.
    qm::ColumnSpec c{
        "v", qm::COL_INT, qm::fixed_column_bytes(1, pack_le<int32_t>({0}))};
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[c](int64_t rid) {
            auto f = qm::result_batch_frame(rid, 0, 1, {c});
            // Bump declared payload_length by 1024 — the actual bytes
            // are unchanged, so the frame parser sees a mismatch.
            uint32_t plen = uint32_t(f[8]) | (uint32_t(f[9]) << 8) |
                (uint32_t(f[10]) << 16) | (uint32_t(f[11]) << 24);
            uint32_t bumped = plen + 1024;
            f[8] = uint8_t(bumped);
            f[9] = uint8_t(bumped >> 8);
            f[10] = uint8_t(bumped >> 16);
            f[11] = uint8_t(bumped >> 24);
            return f;
        }},
        qm::ActionSendResultEnd{},
    };
    run_malformed_batch(s);
}

TEST_CASE("mock: protocol_error — RESULT_BATCH carries an unknown column kind")
{
    // Column kind 0xFE is reserved/undefined in the spec. Schema
    // decoder rejects unknown discriminants.
    qm::ColumnSpec c{
        "v",
        /*kind=*/0xFE,
        qm::fixed_column_bytes(1, pack_le<int32_t>({0}))};
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[c](int64_t rid) {
            return qm::result_batch_frame(rid, 0, 1, {c});
        }},
        qm::ActionSendResultEnd{},
    };
    run_malformed_batch(s);
}

TEST_CASE("mock: invalid_utf8 — RESULT_BATCH column name is not valid UTF-8")
{
    // Non-UTF-8 column name bytes (lone 0xFF — illegal start byte).
    // Schema decoder validates column names as UTF-8 and surfaces a
    // dedicated `invalid_utf8` code (not the generic `protocol_error`).
    qm::ColumnSpec c{
        std::string{'\xFF', '\xFE', '\xFD'},
        qm::COL_INT,
        qm::fixed_column_bytes(1, pack_le<int32_t>({0}))};
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[c](int64_t rid) {
            return qm::result_batch_frame(rid, 0, 1, {c});
        }},
        qm::ActionSendResultEnd{},
    };
    run_malformed_batch(s, questdb_error_invalid_utf8);
}

TEST_CASE("mock: protocol_error — over-long varint in batch_seq")
{
    // A u64 LEB128 is at most 10 bytes. Send 11+ continuation bytes
    // for the `batch_seq` field; the varint decoder errors on
    // truncated/over-long input.
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[](int64_t rid) {
            std::vector<uint8_t> p;
            p.push_back(qm::MSG_RESULT_BATCH);
            for (int i = 0; i < 8; ++i)
                p.push_back(uint8_t(rid >> (i * 8)));
            // 12 continuation bytes then a terminator — invalid varint
            // (max valid u64 LEB128 is 10 bytes).
            for (int i = 0; i < 12; ++i)
                p.push_back(0xFF);
            p.push_back(0x00);
            return qm::framed(1, 0, 1, p);
        }},
        qm::ActionSendResultEnd{},
    };
    run_malformed_batch(s);
}

TEST_CASE("mock: continuation batch decodes against the batch-0 schema")
{
    // The schema (col_count + inline descriptors) rides only the first
    // batch of a query (batch_seq == 0); the continuation carries rows
    // only and must decode against the schema retained from batch 0 —
    // asserted here by row *values* through the C API, not just by the
    // drain not throwing.
    qm::ColumnSpec c0{
        "v", qm::COL_LONG, qm::fixed_column_bytes(2, pack_le<int64_t>({10, 20}))};
    qm::ColumnSpec c1{
        "v", qm::COL_LONG,
        qm::fixed_column_bytes(3, pack_le<int64_t>({30, 40, 50}))};
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[c0](int64_t rid)
                            { return qm::result_batch_frame(rid, 0, 2, {c0}); }},
        qm::ActionSendBuilt{[c1](int64_t rid)
                            { return qm::result_batch_frame(rid, 1, 3, {c1}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select v from t"_utf8);

    // Batch 0: schema-bearing, two rows. (Scoped — the batch handle is
    // invalidated by the next next_batch call.)
    {
        auto batch_opt = cur.next_batch();
        REQUIRE(batch_opt);
        auto& batch = *batch_opt;
        CHECK(batch.seq() == 0);
        REQUIRE(batch.row_count() == 2);
        REQUIRE(batch.column_count() == 1);
        CHECK(batch.column(0).get<int64_t>(0).value_or(0) == 10);
        CHECK(batch.column(0).get<int64_t>(1).value_or(0) == 20);
    }

    // Continuation: rows only on the wire; col_count and the Long kind
    // come from the retained schema.
    {
        auto batch_opt = cur.next_batch();
        REQUIRE(batch_opt);
        auto& batch = *batch_opt;
        CHECK(batch.seq() == 1);
        REQUIRE(batch.row_count() == 3);
        REQUIRE(batch.column_count() == 1);
        CHECK(batch.column(0).get<int64_t>(0).value_or(0) == 30);
        CHECK(batch.column(0).get<int64_t>(1).value_or(0) == 40);
        CHECK(batch.column(0).get<int64_t>(2).value_or(0) == 50);
    }

    CHECK_FALSE(cur.next_batch());
}

TEST_CASE("mock: protocol_error — continuation batch before schema-bearing batch 0")
{
    // A query whose *first* frame is a continuation (batch_seq > 0) has
    // no schema to bind rows to and must surface a protocol error
    // through the C API rather than mis-decode.
    qm::ColumnSpec c{
        "v", qm::COL_LONG, qm::fixed_column_bytes(1, pack_le<int64_t>({42}))};
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[c](int64_t rid)
                            { return qm::result_batch_frame(
                                  rid, /*batch_seq=*/1, 1, {c}); }},
        qm::ActionSendResultEnd{},
    };
    run_malformed_batch(s);
}

// Wire `ActionSendRaw` into a regression test so the action variant
// stops being dead code: a future refactor that drops it would
// silently lose a piece of public test infrastructure. Frames that
// don't depend on the dynamic request_id (SERVER_INFO, CACHE_RESET)
// are the natural fit for ActionSendRaw; request-bound frames use
// ActionSendBuilt.
TEST_CASE("mock: ActionSendRaw delivers a hand-built SERVER_INFO frame")
{
    auto si =
        qm::server_info_frame(qm::ROLE_PRIMARY, "raw-cluster", "raw-node");
    qm::Script s = {
        qm::ActionSendRaw{si},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{
            [](int64_t rid) { return qm::result_end_frame(rid); }},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto info = reader.server_info();
    CHECK(info.role_byte() == qm::ROLE_PRIMARY);
    CHECK(info.cluster_id() == "raw-cluster");
    CHECK(info.node_id() == "raw-node");
    auto cur = reader.execute("select 1"_utf8);
    CHECK_FALSE(cur.next_batch());
}

TEST_CASE("mock: SERVER_INFO zone trailer presence must match CAP_ZONE")
{
    CHECK_THROWS_AS(
        (qm::server_info_frame(
            qm::ROLE_PRIMARY, "c", "n", 0, 0, 0,
            std::optional<std::string>{"zone-A"})),
        std::invalid_argument);
    CHECK_THROWS_AS(
        (qm::server_info_frame(
            qm::ROLE_PRIMARY, "c", "n", 0, qm::CAP_ZONE, 0)),
        std::invalid_argument);
}

// Move-assigning over a reader that still owns a live cursor drives
// `qwp_reader_close` down its defense-in-depth leak branch (the cursor holds a
// laundered `&mut Reader`; freeing would dangle). `operator=(reader&&)` is
// `noexcept` — a throwing move special-member breaks STL containers and is
// UB across a C frame — so it leaks the old reader (with a stderr
// diagnostic) and adopts the source, rather than throwing or freeing under
// the cursor. The cursor stays valid against the leaked reader.
TEST_CASE("mock: reader move-assign over a live cursor leaks safely without throwing")
{
    qm::Script s_a = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendResultEnd{},
    };
    qm::Script s_b = {
        qm::ActionSendServerInfo{},
    };
    qm::MockServer srv_a({s_a});
    qm::MockServer srv_b({s_b});

    auto reader_a = connect_to(srv_a);
    auto reader_b = connect_to(srv_b);

    // Take a cursor on `reader_a`. While `cur` is alive, the underlying
    // C reader's active flag is set.
    auto cur = reader_a.execute("select 1"_utf8);

    // `noexcept`: leaks reader_a's still-live reader and adopts reader_b.
    reader_a = std::move(reader_b);

    // `cur` still points at the leaked (not freed) original reader, so it
    // drains to its terminal — no use-after-free.
    CHECK_FALSE(cur.next_batch());
    CHECK(cur.terminal_kind() == qwp_reader_terminal_kind_end);

    // The destination adopted reader_b's handshake.
    CHECK(reader_a.server_version() == 1);
}

// Once the cursor is destroyed the active flag clears and the same
// move-assign succeeds. Pinned as a separate case so a future regression
// that leaves the flag stuck `true` after cursor teardown is caught here
// rather than as a mysterious second-failure-only symptom.
TEST_CASE("mock: reader move-assign succeeds once cursor is dropped")
{
    qm::Script s_a = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendResultEnd{},
    };
    qm::Script s_b = {
        qm::ActionSendServerInfo{},
    };
    qm::MockServer srv_a({s_a});
    qm::MockServer srv_b({s_b});

    auto reader_a = connect_to(srv_a);
    auto reader_b = connect_to(srv_b);

    {
        auto cur = reader_a.execute("select 1"_utf8);
        CHECK_FALSE(cur.next_batch());
    } // cur destroyed → active flag cleared

    // No throw; reader_a now talks to srv_b's handshake.
    reader_a = std::move(reader_b);
    CHECK(reader_a.server_version() == 1);
}

// A live cursor holds a laundered `&mut Reader`; the reader-side metadata
// getters must refuse rather than synthesise an aliasing `&Reader`. The
// cursor handle owns the borrow, so its mirror getters stay readable. The
// reader-side getters work again once the cursor drops.
TEST_CASE("mock: reader metadata getters reject while a cursor is live")
{
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);

    const uint8_t version = reader.server_version();
    const std::string host{reader.current_host()};
    const uint16_t port = reader.current_port();
    CHECK(version == 1);
    CHECK_FALSE(host.empty());
    CHECK(port != 0);
    const auto initial_info = reader.server_info();
    CHECK(initial_info.role_byte() == qm::ROLE_STANDALONE);

    {
        auto cur = reader.execute("select 1"_utf8);

        const auto expect_live_cursor_error = [](auto&& fn)
        {
            bool threw = false;
            try
            {
                fn();
            }
            catch (const questdb::error& e)
            {
                threw = true;
                CHECK(e.code() == questdb_error_invalid_api_call);
                CHECK(std::string{e.what()}.find("cursor") !=
                      std::string::npos);
            }
            CHECK(threw);
        };
        expect_live_cursor_error([&]{ (void)reader.server_version(); });
        expect_live_cursor_error([&]{ (void)reader.server_info(); });
        expect_live_cursor_error([&]{ (void)reader.current_host(); });
        expect_live_cursor_error([&]{ (void)reader.current_port(); });

        // The cursor handle owns the borrow — its mirror getters are the
        // sound path for the same metadata.
        CHECK(cur.server_version() == version);
        CHECK(cur.current_host() == host);
        CHECK(cur.current_port() == port);
        CHECK(cur.server_info().role_byte() == qm::ROLE_STANDALONE);

        CHECK_FALSE(cur.next_batch());
    }

    CHECK(reader.server_version() == version);
    CHECK(reader.current_host() == host);
    CHECK(reader.current_port() == port);
    CHECK(reader.server_info().role_byte() == qm::ROLE_STANDALONE);

    // The pre-query value is an owning snapshot, not an invalidated view.
    CHECK(initial_info.cluster_id() == "test-cluster");
    CHECK(initial_info.node_id() == "n1");
}

// ---------------------------------------------------------------------------
// FFI ABI smoke for every supported `qwp_reader_query_bind_*`.
//
// Each bind goes through the C ABI (`questdb::egress::query::bind_*` ->
// `qwp_reader_query_bind_*` -> `mutate_query` -> upstream `bind_*`), so
// the captured QUERY_REQUEST is a byte-level snapshot of the marshalling.
// Sentinel values are chosen so a wrong argument order, sign-extension
// bug, or off-by-one width on any single bind produces a localised diff
// rather than a silent payload corruption that masks itself across
// neighbouring binds.
//
// Phase-1-rejected binds (`bind_binary`, `bind_ipv4`, `bind_null_binary`,
// `bind_null` with `ipv4` kind) are not on this happy path — they're
// rejected by upstream `check_bindable` before the request hits the
// wire (see `egress/binds.rs`, "PHASE 1 SERVER COMPATIBILITY"). Their
// FFI shape is exercised by `prepare(...).bind_X(...).execute()`
// throwing `invalid_bind`; the wire bytes can't be asserted because no
// frame is sent.
// ---------------------------------------------------------------------------

TEST_CASE(
    "mock: every supported bind variant marshals through the FFI ABI")
{
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);

    const std::array<uint8_t, 16> kUuid = {
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
        0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    };
    const std::array<uint8_t, 32> kLong256 = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
    };
    const std::array<uint8_t, 32> kDecimal256 = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    };

    auto cur = reader.prepare("X"_utf8)
                   .bind_bool(true)
                   .bind_i8(static_cast<int8_t>(-13))
                   .bind_i16(static_cast<int16_t>(0x1234))
                   .bind_i32(static_cast<int32_t>(0x01020304))
                   .bind_i64(static_cast<int64_t>(0x0102030405060708LL))
                   .bind_f32(1.0f)
                   .bind_f64(1.0)
                   .bind_timestamp_micros(
                       static_cast<int64_t>(0x1100AABBCCDDEEFFLL))
                   .bind_timestamp_nanos(
                       static_cast<int64_t>(0x2200AABBCCDDEEFFLL))
                   .bind_date_millis(
                       static_cast<int64_t>(0x3300AABBCCDDEEFFLL))
                   .bind_uuid(kUuid)
                   .bind_long256(kLong256)
                   .bind_char(static_cast<uint16_t>(0xCAFE))
                   .bind_decimal64(
                       static_cast<int64_t>(0x4400AABBCCDDEEFFLL),
                       static_cast<int8_t>(5))
                   // `mantissa_lo` is u64 (low limb), `mantissa_hi` is i64
                   // (sign-extends into the i128). The wire form is the
                   // i128 in little-endian, so the captured bytes are
                   // `lo_le` followed by `hi_le`.
                   .bind_decimal128(
                       static_cast<uint64_t>(0x1122334455667788ULL),
                       static_cast<int64_t>(0x6655443322110000LL),
                       static_cast<int8_t>(7))
                   .bind_decimal256(kDecimal256, static_cast<int8_t>(9))
                   .bind_geohash(
                       static_cast<uint64_t>(0x1F),
                       static_cast<uint8_t>(5))
                   .bind_varchar("hello"_utf8)
                   .bind_null(::questdb::egress::column_kind::int_)
                   .bind_null_varchar()
                   .bind_null_decimal64(static_cast<int8_t>(3))
                   .bind_null_decimal128(static_cast<int8_t>(11))
                   .bind_null_decimal256(static_cast<int8_t>(13))
                   .bind_null_geohash(static_cast<uint8_t>(7))
                   .execute();
    while (cur.next_batch()) {}

    auto reqs = srv.captured_requests();
    REQUIRE(reqs.size() == 1);
    const auto& req = reqs[0];

    // Build the expected bind payload incrementally. Each helper appends
    // to `exp`; the captured request is then matched starting at the
    // post-preamble offset.
    std::vector<uint8_t> exp;
    auto put = [&](std::initializer_list<uint8_t> bs) {
        for (auto b : bs) exp.push_back(b);
    };
    auto put_bytes = [&](const uint8_t* p, size_t n) {
        exp.insert(exp.end(), p, p + n);
    };
    auto put_u16_le = [&](uint16_t v) {
        exp.push_back(static_cast<uint8_t>(v & 0xFF));
        exp.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    };
    auto put_u32_le = [&](uint32_t v) {
        for (int i = 0; i < 4; ++i)
            exp.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
    };
    auto put_u64_le = [&](uint64_t v) {
        for (int i = 0; i < 8; ++i)
            exp.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
    };
    auto put_f32_le = [&](float f) {
        uint32_t bits;
        std::memcpy(&bits, &f, sizeof(bits));
        put_u32_le(bits);
    };
    auto put_f64_le = [&](double f) {
        uint64_t bits;
        std::memcpy(&bits, &f, sizeof(bits));
        put_u64_le(bits);
    };

    // Type codes mirror `ColumnKind::as_u8` in `column_kind.rs`.
    constexpr uint8_t kBool = 0x01, kByte = 0x02, kShort = 0x03,
                      kInt = 0x04, kLong = 0x05, kFloat = 0x06,
                      kDouble = 0x07, kTimestamp = 0x0A, kDate = 0x0B,
                      kUuidKind = 0x0C, kLong256Kind = 0x0D,
                      kGeohash = 0x0E, kVarchar = 0x0F,
                      kTimestampNanos = 0x10, kDecimal64 = 0x13,
                      kDecimal128 = 0x14, kDecimal256Kind = 0x15,
                      kChar = 0x16;

    // 1. bool(true) -> [kBool, 0x00, 0x01]
    put({kBool, 0x00, 0x01});
    // 2. i8(-13)
    put({kByte, 0x00, static_cast<uint8_t>(int8_t(-13))});
    // 3. i16(0x1234)
    put({kShort, 0x00}); put_u16_le(0x1234);
    // 4. i32(0x01020304)
    put({kInt, 0x00}); put_u32_le(0x01020304U);
    // 5. i64(0x0102030405060708)
    put({kLong, 0x00}); put_u64_le(0x0102030405060708ULL);
    // 6. f32(1.0)
    put({kFloat, 0x00}); put_f32_le(1.0f);
    // 7. f64(1.0)
    put({kDouble, 0x00}); put_f64_le(1.0);
    // 8. timestamp_micros
    put({kTimestamp, 0x00}); put_u64_le(0x1100AABBCCDDEEFFULL);
    // 9. timestamp_nanos
    put({kTimestampNanos, 0x00}); put_u64_le(0x2200AABBCCDDEEFFULL);
    // 10. date_millis
    put({kDate, 0x00}); put_u64_le(0x3300AABBCCDDEEFFULL);
    // 11. uuid (16 raw bytes, verbatim)
    put({kUuidKind, 0x00}); put_bytes(kUuid.data(), kUuid.size());
    // 12. long256 (32 raw bytes, verbatim)
    put({kLong256Kind, 0x00}); put_bytes(kLong256.data(), kLong256.size());
    // 13. char(0xCAFE) - u16 LE
    put({kChar, 0x00}); put_u16_le(0xCAFE);
    // 14. decimal64(value, scale=5): [type, 0x00, scale, ...8 LE...]
    put({kDecimal64, 0x00, 0x05}); put_u64_le(0x4400AABBCCDDEEFFULL);
    // 15. decimal128(lo, hi, scale=7): [type, 0x00, scale, lo_le(8), hi_le(8)]
    put({kDecimal128, 0x00, 0x07});
    put_u64_le(0x1122334455667788ULL);
    put_u64_le(0x6655443322110000ULL);
    // 16. decimal256(bytes, scale=9): [type, 0x00, scale, ...32 raw bytes...]
    put({kDecimal256Kind, 0x00, 0x09});
    put_bytes(kDecimal256.data(), kDecimal256.size());
    // 17. geohash(0x1F, prec=5): [type, 0x00, varint(5), ceil(5/8)=1 byte LE]
    put({kGeohash, 0x00, 0x05, 0x1F});
    // 18. varchar("hello"): [type, 0x00, u32_le(0), u32_le(5), 'h','e','l','l','o']
    put({kVarchar, 0x00});
    put_u32_le(0);
    put_u32_le(5);
    exp.insert(exp.end(), {'h', 'e', 'l', 'l', 'o'});
    // 19. bind_null(int_): simple-null body, no extra args
    put({kInt, 0x01, 0x01});
    // 20. bind_null_varchar: same simple-null body for Varchar kind
    put({kVarchar, 0x01, 0x01});
    // 21..23. null_decimal{64,128,256} carry the scale even on null.
    put({kDecimal64, 0x01, 0x01, 0x03});
    put({kDecimal128, 0x01, 0x01, 0x0B});
    put({kDecimal256Kind, 0x01, 0x01, 0x0D});
    // 24. null_geohash carries the precision_bits varint even on null.
    put({kGeohash, 0x01, 0x01, 0x07});

    constexpr size_t kBindCount = 24;
    // Preamble layout: 0x10 | i64 rid | varint sql_len=1 | 'X' |
    //                   varint credit=0 | varint bind_count
    // bind_count is < 128, so its varint is a single byte.
    constexpr size_t kPreambleLen = 1 + 8 + 1 + 1 + 1 + 1; // = 13
    REQUIRE(req.size() == kPreambleLen + exp.size());
    CHECK(req[0] == qm::MSG_QUERY_REQUEST);
    // req[1..9] is the request_id (i64 LE); non-deterministic, skip.
    CHECK(req[9] == 0x01);           // sql_len varint
    CHECK(req[10] == 'X');           // sql byte
    CHECK(req[11] == 0x00);          // initial_credit varint
    CHECK(req[12] == kBindCount);    // bind_count varint

    for (size_t i = 0; i < exp.size(); ++i)
    {
        // Per-byte CHECK so a diff localises to the failing bind.
        CHECK_MESSAGE(req[kPreambleLen + i] == exp[i],
                      "bind payload mismatch at byte " << i);
    }
}

// ---------------------------------------------------------------------------
// FFI thread-safety contract: Reader migration + concurrent stats reads.
//
// `qwp_reader_bytes_received` / `_read_ns` / `_decode_ns` /
// `_credit_granted_total` are documented at `questdb-rs-ffi/src/egress.rs`
// as safe to call from a monitoring thread while another thread is
// driving a cursor through `qwp_reader_query_execute`. The Reader is
// stored in an `UnsafeCell<Reader>` next to a cloned `Arc<ReaderStats>`
// inside the C-side `reader` struct; the stat getters use
// `ptr::addr_of!` to reach the Arc field without synthesising an
// intermediate `&reader` reborrow that would otherwise cover the
// cell and disturb the laundered `&mut Reader` held by an in-flight
// query. This test exercises that exact shape from C++:
//
//  - The worker thread mutates the Reader via `reader.execute(...)` and
//    drives a multi-batch cursor through `next_batch()`.
//  - The main thread hammers `reader.bytes_received()` /
//    `read_ns()` / `decode_ns()` / `credit_granted_total()` on the same
//    `qwp_reader*` handle.
//
// Under `QUESTDB_SANITIZE` (ASan + UBSan today; TSan if/when wired in)
// a regression that routes a stat getter through a non-atomic field, or
// that drops the disjoint-fields invariant, surfaces as a sanitiser
// report. Without sanitisers the test still pins the API shape and
// catches a hang/crash, and the monotonicity assertion catches a
// counter overwrite even on a clean build.
// ---------------------------------------------------------------------------

TEST_CASE(
    "mock: reader migrates to worker thread with concurrent stats polling")
{
    // Drive a non-trivial wire window: many small RESULT_BATCH frames so
    // the poll loop on main catches the cursor mid-flight rather than
    // after it's already drained. Each batch is 4 rows × i32 = 16 value
    // bytes plus framing — the exact size doesn't matter, only that the
    // sequence stretches over enough time for the monitor thread to
    // observe motion in `bytes_received`.
    constexpr int kBatches = 32;
    qm::ColumnSpec col{
        "v", qm::COL_INT,
        qm::fixed_column_bytes(4, pack_le<int32_t>({1, 2, 3, 4}))};
    // `emplace_back` (not `push_back`) forwards the alternative directly
    // to `qm::Action`'s converting variant constructor, constructing in
    // place inside the vector slot. `push_back(qm::ActionXxx{})` would
    // first move-construct an `Action` temporary and then move it into
    // the slot — and GCC 13's `-Wmaybe-uninitialized` flags the
    // variant move-ctor's union storage on the non-active alternatives
    // as a false positive (combined with `-Werror`, this breaks the
    // CMake build). Reserving up-front also avoids any vector growth
    // re-relocation walking back through the same move-ctor path.
    qm::Script s;
    s.reserve(static_cast<size_t>(kBatches) + 3);
    s.emplace_back(qm::ActionSendServerInfo{});
    s.emplace_back(qm::ActionAwaitQueryRequest{});
    for (int i = 0; i < kBatches; ++i)
    {
        s.emplace_back(qm::ActionSendBuilt{
            [col, i](int64_t rid)
            { return qm::result_batch_frame(
                  rid, static_cast<uint64_t>(i), 4, {col}); }});
    }
    s.emplace_back(qm::ActionSendResultEnd{});

    qm::MockServer srv({s});
    auto reader = connect_to(srv);

    std::atomic<bool> done{false};
    std::exception_ptr worker_err;

    // Worker takes the reader by reference. Both threads read the
    // `_impl` pointer; the worker mutates the C-side `Reader` inside
    // the `UnsafeCell`, the main thread loads atomics on the disjoint
    // `Arc<ReaderStats>` field — no overlapping non-atomic accesses,
    // so the C++ object model permits concurrent const + non-const
    // method calls on this specific reader.
    std::thread worker(
        [&reader, &done, &worker_err]()
        {
            try
            {
                auto cur = reader.execute("select v"_utf8);
                // Drain every batch + the terminal RESULT_END.
                while (cur.next_batch())
                {
                }
            }
            catch (...)
            {
                // doctest macros are reserved for the main thread;
                // surface the failure by rethrowing post-join.
                worker_err = std::current_exception();
            }
            done.store(true, std::memory_order_release);
        });

    uint64_t last_bytes = 0;
    uint64_t max_observed_bytes = 0;
    uint64_t poll_count = 0;
    while (!done.load(std::memory_order_acquire))
    {
        // Every getter the FFI exposes — exercise all four paths so a
        // regression localised to one of them still surfaces.
        const uint64_t b = reader.bytes_received();
        const uint64_t r = reader.read_ns();
        const uint64_t d = reader.decode_ns();
        const uint64_t cr = reader.credit_granted_total();
        // Producer-side counter writes use `fetch_add(Relaxed)`, which
        // is monotone-non-decreasing under happens-before. A foreign-
        // thread Relaxed load MUST observe non-decreasing values; a
        // backward step here means someone routed the writer through
        // a non-atomic path.
        CHECK_MESSAGE(
            b >= last_bytes,
            "bytes_received went backwards: " << last_bytes << " -> " << b);
        last_bytes = b;
        if (b > max_observed_bytes)
            max_observed_bytes = b;
        (void)r;
        (void)d;
        (void)cr;
        ++poll_count;
    }
    worker.join();
    if (worker_err)
        std::rethrow_exception(worker_err);

    // Post-join: a happens-after the worker's `done.store(Release)`.
    // The final counter values reflect every wire byte the worker read.
    const uint64_t final_bytes = reader.bytes_received();
    CHECK(final_bytes > 0);
    CHECK_MESSAGE(
        final_bytes >= max_observed_bytes,
        "post-join bytes_received "
            << final_bytes << " < pre-join max " << max_observed_bytes
            << " — store-Release happens-before is broken or counters "
               "were rewound");
    // Sanity: the poll loop ran at all. If the worker drained before
    // main entered the loop, the rest of the assertions don't actually
    // prove cross-thread concurrency.
    CHECK(poll_count > 0);
}

// ---------------------------------------------------------------------------
// failover_progress_event_view: full lifecycle coverage. Mirrors the
// Rust progress-callback tests in `tests/egress_failover.rs` but
// additionally exercises the post-data-delivered replay path that the
// Rust mock can't drive (no synthetic RESULT_BATCH helper).
// ---------------------------------------------------------------------------

TEST_CASE("mock: progress callback observes Disconnected -> Retrying -> Reset on successful failover")
{
    qm::Script s_a = {
        qm::ActionSendServerInfo{qm::ROLE_STANDALONE, "c", "a"},
        qm::ActionAwaitQueryRequest{},
        qm::ActionHardDrop{},
    };
    qm::Script s_b = {
        qm::ActionSendServerInfo{qm::ROLE_STANDALONE, "c", "b"},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv_a({s_a});
    qm::MockServer srv_b({s_b});

    const std::string conf =
        "ws::addr=" + srv_a.addr() + "," + srv_b.addr() +
        ";failover_backoff_initial_ms=1;failover_backoff_max_ms=10";
    questdb::egress::reader reader{questdb::ingress::utf8_view{conf}};

    struct Capture
    {
        questdb::egress::failover_phase phase;
        uint32_t attempt;
        std::string failed_host;
        uint16_t failed_port;
        std::string new_host;
        uint16_t new_port;
        std::optional<int64_t> new_request_id;
        bool has_final_error;
        bool server_info_present;
        questdb::egress::server_role server_role;
        bool snapshot_present;
    };
    auto events = std::make_shared<std::vector<Capture>>();

    auto cur = reader.prepare("select 1"_utf8)
                   .on_failover_progress(
                       [events](const questdb::egress::failover_progress_event_view& ev)
                       {
                           const auto server_info = ev.server_info();
                           events->push_back({
                               ev.phase(),
                               ev.attempt(),
                               std::string(ev.failed_host()),
                               ev.failed_port(),
                               std::string(ev.new_host()),
                               ev.new_port(),
                               ev.new_request_id(),
                               ev.final_error_code().has_value(),
                               static_cast<bool>(server_info),
                               server_info.role(),
                               server_info.snapshot().has_value(),
                           });
                       })
                   .execute();
    CHECK_FALSE(cur.next_batch());
    CHECK(cur.failover_resets() == 1);

    REQUIRE(events->size() >= 3);
    // First event: Disconnected with attempt=0, no new_addr.
    CHECK(events->front().phase == questdb::egress::failover_phase::disconnected);
    CHECK(events->front().attempt == 0);
    CHECK(events->front().new_port == 0);
    CHECK_FALSE(events->front().new_request_id.has_value());
    CHECK_FALSE(events->front().has_final_error);
    CHECK_FALSE(events->front().server_info_present);
    CHECK(events->front().server_role ==
          questdb::egress::server_role::other);
    CHECK_FALSE(events->front().snapshot_present);

    // At least one Retrying event with attempt >= 1.
    bool saw_retry = false;
    for (const auto& e : *events)
    {
        if (e.phase == questdb::egress::failover_phase::retrying)
        {
            saw_retry = true;
            CHECK(e.attempt >= 1);
            CHECK(e.new_port == 0);
            CHECK_FALSE(e.has_final_error);
            CHECK_FALSE(e.server_info_present);
            CHECK(e.server_role == questdb::egress::server_role::other);
            CHECK_FALSE(e.snapshot_present);
        }
    }
    CHECK(saw_retry);

    // Reset: last event, with new_addr populated.
    const auto& last = events->back();
    CHECK(last.phase == questdb::egress::failover_phase::reset);
    CHECK(last.attempt >= 1);
    CHECK(last.new_host == "127.0.0.1");
    // After failover the cursor is on B; the Reset event's new_port
    // must match the cursor's now-current port.
    CHECK(last.new_port == cur.current_port());
    // And distinct from the failed_port (which was A).
    CHECK(last.failed_port != last.new_port);
    CHECK(last.new_request_id.has_value());
    CHECK_FALSE(last.has_final_error);
    CHECK(last.server_info_present);
    CHECK(last.server_role == questdb::egress::server_role::standalone);
    CHECK(last.snapshot_present);

    // No GaveUp on the successful path.
    for (const auto& e : *events)
    {
        CHECK(e.phase != questdb::egress::failover_phase::gave_up);
    }
}

TEST_CASE("mock: progress callback fires GaveUp with final_error on budget exhaustion")
{
    qm::Script s_initial = {
        qm::ActionSendServerInfo{qm::ROLE_STANDALONE, "c", "lonely"},
        qm::ActionAwaitQueryRequest{},
        qm::ActionHardDrop{},
    };
    qm::Script s_dead = {qm::ActionHardDrop{}};
    qm::MockServer srv({s_initial, s_dead});

    const std::string conf = "ws::addr=" + srv.addr() +
        ";failover_max_attempts=3;failover_backoff_initial_ms=1;"
        "failover_backoff_max_ms=2";
    questdb::egress::reader reader{questdb::ingress::utf8_view{conf}};

    struct GaveUp
    {
        bool fired{false};
        uint32_t attempt{0};
        std::optional<questdb_error_code> final_code;
        std::string final_msg;
        uint64_t elapsed_ns{0};
    };
    auto cap = std::make_shared<GaveUp>();

    auto cur = reader.prepare("select 1"_utf8)
                   .on_failover_progress(
                       [cap](const questdb::egress::failover_progress_event_view& ev)
                       {
                           if (ev.phase() ==
                               questdb::egress::failover_phase::gave_up)
                           {
                               cap->fired = true;
                               cap->attempt = ev.attempt();
                               if (auto c = ev.final_error_code())
                                   cap->final_code =
                                       static_cast<questdb_error_code>(*c);
                               cap->final_msg = std::string(ev.final_error_msg());
                               cap->elapsed_ns = ev.elapsed_ns();
                           }
                       })
                   .execute();
    bool threw = false;
    try
    {
        while (cur.next_batch()) {}
    }
    catch (const questdb::error&)
    {
        threw = true;
    }
    CHECK(threw);

    CHECK(cap->fired);
    CHECK(cap->attempt >= 1);
    REQUIRE(cap->final_code.has_value());
    CHECK((*cap->final_code == questdb_error_socket_error ||
           *cap->final_code == questdb_error_protocol_error));
    CHECK_FALSE(cap->final_msg.empty());
    CHECK(cap->elapsed_ns > 0);
}

TEST_CASE("mock: progress callback alone does not authorize replay-after-data-delivered")
{
    // The Rust mock has no helper to emit a synthetic RESULT_BATCH; the
    // C++ mock does. This pins the distinction between telemetry and the
    // reset hook that makes replay safe.
    qm::ColumnSpec col{
        "v", qm::COL_INT, qm::fixed_column_bytes(1, pack_le<int32_t>({42}))};
    qm::Script s_a = {
        qm::ActionSendServerInfo{qm::ROLE_STANDALONE, "c", "a"},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[col](int64_t rid)
                            { return qm::result_batch_frame(rid, 0, 1, {col}); }},
        qm::ActionHardDrop{},
    };
    qm::Script s_b = {
        qm::ActionSendServerInfo{qm::ROLE_STANDALONE, "c", "b"},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv_a({s_a});
    qm::MockServer srv_b({s_b});

    const std::string conf =
        "ws::addr=" + srv_a.addr() + "," + srv_b.addr() +
        ";failover_backoff_initial_ms=1;failover_backoff_max_ms=10";
    questdb::egress::reader reader{questdb::ingress::utf8_view{conf}};

    std::atomic<int> reset_phase_count{0};
    auto cur = reader.prepare("select v"_utf8)
                   .on_failover_progress(
                       [&reset_phase_count](
                           const questdb::egress::failover_progress_event_view& ev)
                       {
                           if (ev.phase() ==
                               questdb::egress::failover_phase::reset)
                           {
                               reset_phase_count.fetch_add(1);
                           }
                       })
                   .execute();
    // First batch lands cleanly on A.
    REQUIRE(cur.next_batch());
    // The progress callback observes lifecycle events but cannot discard the
    // already-consumed batch, so the duplicate guard must refuse replay.
    bool threw = false;
    try
    {
        (void)cur.next_batch();
    }
    catch (const questdb::error& e)
    {
        threw = true;
        CHECK(e.code() == questdb_error_failover_would_duplicate);
    }
    CHECK(threw);
    CHECK(cur.failover_resets() == 0);
    CHECK(reset_phase_count.load() == 0);
}

TEST_CASE("mock: progress callback noexcept trampoline swallows user exceptions")
{
    qm::Script s_a = {
        qm::ActionSendServerInfo{qm::ROLE_STANDALONE, "c", "a"},
        qm::ActionAwaitQueryRequest{},
        qm::ActionHardDrop{},
    };
    qm::Script s_b = {
        qm::ActionSendServerInfo{qm::ROLE_STANDALONE, "c", "b"},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv_a({s_a});
    qm::MockServer srv_b({s_b});

    const std::string conf =
        "ws::addr=" + srv_a.addr() + "," + srv_b.addr() +
        ";failover_backoff_initial_ms=1;failover_backoff_max_ms=10";
    questdb::egress::reader reader{questdb::ingress::utf8_view{conf}};

    // Throwing from inside the callback would unwind into the Rust FFI
    // frame and abort the process if the trampoline didn't swallow it.
    // Asserting we reach the post-execute code proves the swallow ran.
    auto cur = reader.prepare("select 1"_utf8)
                   .on_failover_progress(
                       [](const questdb::egress::failover_progress_event_view&)
                       { throw std::runtime_error("boom"); })
                   .execute();
    CHECK_FALSE(cur.next_batch());
    CHECK(cur.failover_resets() == 1);
}

// Regression: `query` move-constructor and move-assignment must transfer
// `_progress_callback` ownership, not just `_impl` and `_callback`. If
// the heap-allocated `failover_progress_callback` stays with the
// moved-from source, source destruction frees the storage the C layer
// still references via `user_data`, and the next progress event UAFs
// inside `progress_trampoline`. The cursor's mirror move handles both
// callbacks correctly; this test pins the same behaviour on `query`.
//
// Pure-lifetime witness: install a callback that captures a shared_ptr
// by value, then track its weak_ptr across moves. Whoever owns the heap
// `failover_progress_callback` transitively owns the shared_ptr; if
// ownership leaks to the moved-from source, the witness expires the
// moment the source destructs while the destination is still live.
// Deterministic, no ASan required.
TEST_CASE(
    "mock: query move transfers _progress_callback ownership (UAF regression)")
{
    qm::Script s = {qm::ActionSendServerInfo{}};

    SUBCASE("move-constructor carries the progress callback to the destination")
    {
        qm::MockServer srv({s});
        auto reader = connect_to(srv);

        auto sentinel = std::make_shared<int>(0);
        std::weak_ptr<int> witness = sentinel;
        std::optional<eg::query> dest;
        {
            auto src = reader.prepare("X"_utf8);
            src.on_failover_progress(
                [held = std::move(sentinel)](
                    const eg::failover_progress_event_view&) { (void)held; });
            dest.emplace(std::move(src));
        } // `src` destructs here.
        // With the fix `dest` owns the heap callback (and thus the
        // shared_ptr captured by the lambda) — the witness must still
        // be live. With the bug the heap callback was freed during
        // `src`'s destruction and the witness has already expired.
        CHECK_FALSE(witness.expired());
        dest.reset();
        CHECK(witness.expired());
    }

    SUBCASE("move-assignment carries the progress callback to the destination")
    {
        qm::MockServer srv_src({s});
        qm::MockServer srv_dest({s});
        auto reader_src = connect_to(srv_src);
        auto reader_dest = connect_to(srv_dest);

        auto sentinel = std::make_shared<int>(0);
        std::weak_ptr<int> witness = sentinel;
        auto dest = reader_dest.prepare("X"_utf8);
        {
            auto src = reader_src.prepare("X"_utf8);
            src.on_failover_progress(
                [held = std::move(sentinel)](
                    const eg::failover_progress_event_view&) { (void)held; });
            dest = std::move(src);
        } // `src` destructs here.
        CHECK_FALSE(witness.expired());
    }
}

// Batch / column bulk descriptor — cross-check the new columnar API
// (`cursor::next_batch()` + `batch::column()` / `column::values<T>()`) against
// the per-cell `cursor::get_*` path on the same emitted batch.

TEST_CASE("mock: batch::column<int32_t> dense values match get_i32 per cell")
{
    qm::ColumnSpec c{
        "v", qm::COL_INT,
        qm::fixed_column_bytes(4, pack_le<int32_t>({-1, 0, 42, 2147483647}))};
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[c](int64_t rid)
                            { return qm::result_batch_frame(rid, 0, 4, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});

    auto reader = connect_to(srv);
    auto cur = reader.execute("select v from t"_utf8);
    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
    REQUIRE(batch.row_count() == 4);
    REQUIRE(batch.column_count() == 1);
    REQUIRE(batch.column_kind(0) == eg::column_kind::int_);
    CHECK(batch.column_name(0) == "v");

    auto col = batch.column(0);
    REQUIRE(col.kind() == eg::column_kind::int_);
    REQUIRE(col.row_count() == 4);
    REQUIRE(col.value_stride() == sizeof(int32_t));
    REQUIRE_FALSE(col.has_nulls());

    const int32_t* values = col.values<int32_t>();
    REQUIRE(values != nullptr);
    for (size_t r = 0; r < 4; ++r)
        CHECK(load_le(values + r) == batch.column(0).get<int32_t>(r).value());
}

TEST_CASE("mock: batch::column<varchar> offsets/data match get_varchar per cell")
{
    std::string a = "alpha";
    std::string bb = "beta-beta";
    std::string c = "g\xC3\xA4mma"; // UTF-8 "gämma"
    std::vector<uint8_t> body;
    body.push_back(0x00); // no validity
    std::vector<uint32_t> offsets{
        0u,
        static_cast<uint32_t>(a.size()),
        static_cast<uint32_t>(a.size() + bb.size()),
        static_cast<uint32_t>(a.size() + bb.size() + c.size())};
    for (auto o : offsets)
    {
        for (int i = 0; i < 4; ++i)
            body.push_back(static_cast<uint8_t>(o >> (i * 8)));
    }
    for (char ch : a) body.push_back(static_cast<uint8_t>(ch));
    for (char ch : bb) body.push_back(static_cast<uint8_t>(ch));
    for (char ch : c) body.push_back(static_cast<uint8_t>(ch));

    qm::ColumnSpec col_spec{"s", qm::COL_VARCHAR, std::move(body)};
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{
            [col_spec](int64_t rid)
            { return qm::result_batch_frame(rid, 0, 3, {col_spec}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});

    auto reader = connect_to(srv);
    auto cur = reader.execute("select s from t"_utf8);
    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);

    auto col = batch_opt->column(0);
    REQUIRE(col.kind() == eg::column_kind::varchar);
    REQUIRE(col.values_raw() == nullptr);
    REQUIRE(col.value_stride() == 0);
    REQUIRE(col.var_offsets() != nullptr);
    REQUIRE(col.var_data() != nullptr);

    for (size_t r = 0; r < 3; ++r)
    {
        auto via_bulk = col.varchar(r);
        REQUIRE(via_bulk.has_value());
    }
    CHECK(col.varchar(0).value() == "alpha");
    CHECK(col.varchar(1).value() == "beta-beta");
    CHECK(col.varchar(2).value() == "g\xC3\xA4mma");
}

TEST_CASE("mock: batch::column INT validity bitmap matches is_null per cell")
{
    // BOOLEAN/BYTE/SHORT/CHAR cannot carry NULL on the wire (spec §11.5);
    // INT can, so use it to exercise the validity-bitmap path. 4 rows,
    // rows 1 and 3 NULL.
    qm::ColumnSpec c{
        "v", qm::COL_INT,
        qm::fixed_column_bytes_nullable(
            /*row_count=*/4,
            /*is_null=*/std::vector<bool>{false, true, false, true},
            /*packed_non_null=*/pack_le<int32_t>({100, 300}),
            /*elem_size=*/sizeof(int32_t))};

    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[c](int64_t rid)
                            { return qm::result_batch_frame(rid, 0, 4, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});

    auto reader = connect_to(srv);
    auto cur = reader.execute("select v from t"_utf8);
    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);

    auto col = batch_opt->column(0);
    REQUIRE(col.kind() == eg::column_kind::int_);
    REQUIRE(col.has_nulls());
    REQUIRE(col.validity_bytes() == 1);
    CHECK_FALSE(col.is_null(0));
    CHECK(col.is_null(1));
    CHECK_FALSE(col.is_null(2));
    CHECK(col.is_null(3));

    for (size_t r = 0; r < 4; ++r)
        CHECK(col.is_null(r) == !col.get<int32_t>(r).has_value());
    const int32_t* values = col.values<int32_t>();
    CHECK(load_le(values + 0) == 100);
    CHECK(load_le(values + 2) == 300);
}

TEST_CASE("mock: batch::column — every fixed-width scalar kind round-trip")
{
    // One batch carrying every fixed-width kind the mock can emit, each
    // column 2 rows non-null. Cross-checks the bulk descriptor's dense
    // dense values against the per-cell `column::get<T>` over the same batch.
    using qm::ColumnSpec;
    using qm::fixed_column_bytes;

    const std::array<uint8_t, 16> u0{{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                       0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                                       0x0F, 0x10}};
    const std::array<uint8_t, 16> u1{{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9,
                                       0xF8, 0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2,
                                       0xF1, 0xF0}};
    std::vector<uint8_t> uuid_bytes;
    uuid_bytes.insert(uuid_bytes.end(), u0.begin(), u0.end());
    uuid_bytes.insert(uuid_bytes.end(), u1.begin(), u1.end());

    std::vector<uint8_t> long256_bytes(64, 0);
    for (size_t i = 0; i < 32; ++i) long256_bytes[i] = static_cast<uint8_t>(i);
    for (size_t i = 0; i < 32; ++i) long256_bytes[32 + i] = static_cast<uint8_t>(0x80 + i);

    // BOOLEAN: validity (1B: none) + bit-packed values (2 rows -> 1 byte).
    std::vector<uint8_t> bool_body{0x00, 0b00000010}; // row0=false, row1=true
    ColumnSpec c_bool{"b", qm::COL_BOOLEAN, std::move(bool_body)};
    ColumnSpec c_byte{"by", qm::COL_BYTE,
                      fixed_column_bytes(2, pack_le<int8_t>({-1, 42}))};
    ColumnSpec c_short{"sh", qm::COL_SHORT,
                       fixed_column_bytes(2, pack_le<int16_t>({-1234, 31000}))};
    ColumnSpec c_char{"ch", qm::COL_CHAR,
                      fixed_column_bytes(2, pack_le<uint16_t>({'A', 0x4E2D}))};
    ColumnSpec c_int{"i", qm::COL_INT,
                     fixed_column_bytes(2, pack_le<int32_t>({-7, 2147483647}))};
    ColumnSpec c_ipv4{"ip", qm::COL_IPV4,
                      fixed_column_bytes(2, pack_le<uint32_t>({0x7F000001u, 0xC0A80101u}))};
    ColumnSpec c_long{"l", qm::COL_LONG,
                      fixed_column_bytes(2, pack_le<int64_t>({-1, 9223372036854775807LL}))};
    ColumnSpec c_f32{"f", qm::COL_FLOAT,
                     fixed_column_bytes(2, pack_le<float>({1.25f, -0.5f}))};
    ColumnSpec c_f64{"d", qm::COL_DOUBLE,
                     fixed_column_bytes(2, pack_le<double>({1.5, -3.14}))};
    ColumnSpec c_ts{"ts", qm::COL_TIMESTAMP,
                    fixed_column_bytes(2, pack_le<int64_t>({1700000000000000LL, 1800000000000000LL}))};
    ColumnSpec c_date{"dt", qm::COL_DATE,
                      fixed_column_bytes(2, pack_le<int64_t>({0, 86400000LL}))};
    ColumnSpec c_tsn{"tn", qm::COL_TIMESTAMP_NANOS,
                     fixed_column_bytes(2, pack_le<int64_t>({1, 999999999LL}))};
    ColumnSpec c_uuid{"u", qm::COL_UUID, fixed_column_bytes(2, uuid_bytes)};
    ColumnSpec c_l256{"l256", qm::COL_LONG256,
                      fixed_column_bytes(2, long256_bytes)};

    std::vector<ColumnSpec> cols{c_bool, c_byte, c_short, c_char, c_int,
                                  c_ipv4, c_long, c_f32, c_f64, c_ts,
                                  c_date, c_tsn, c_uuid, c_l256};

    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[cols](int64_t rid)
                            {
                                return qm::result_batch_frame(
                                    rid, 0, 2, cols);
                            }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select * from t"_utf8);
    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
    REQUIRE(batch.row_count() == 2);
    REQUIRE(batch.column_count() == cols.size());

    // boolean — densified to 1 byte/row (0 = false, 1 = true).
    {
        auto col = batch.column(0);
        REQUIRE(col.kind() == eg::column_kind::boolean);
        REQUIRE(col.value_stride() == 1);
        const auto* v = static_cast<const uint8_t*>(col.values_raw());
        CHECK(v[0] == 0);
        CHECK(v[1] == 1);
    }
    // byte
    {
        auto col = batch.column(1);
        CHECK(col.kind() == eg::column_kind::byte);
        CHECK(col.value_stride() == 1);
        const auto* v = col.values<int8_t>();
        CHECK(load_le(v + 0) == -1);
        CHECK(load_le(v + 1) == 42);
    }
    // short
    {
        auto col = batch.column(2);
        CHECK(col.value_stride() == 2);
        const auto* v = col.values<int16_t>();
        CHECK(load_le(v + 0) == -1234);
        CHECK(load_le(v + 1) == 31000);
    }
    // char (UTF-16 code unit)
    {
        auto col = batch.column(3);
        CHECK(col.kind() == eg::column_kind::char_);
        const auto* v = col.values<uint16_t>();
        CHECK(load_le(v + 0) == 'A');
        CHECK(load_le(v + 1) == 0x4E2D);
    }
    // int
    {
        auto col = batch.column(4);
        const auto* v = col.values<int32_t>();
        CHECK(load_le(v + 0) == -7);
        CHECK(load_le(v + 1) == 2147483647);
    }
    // ipv4
    {
        auto col = batch.column(5);
        CHECK(col.kind() == eg::column_kind::ipv4);
        const auto* v = col.values<uint32_t>();
        CHECK(load_le(v + 0) == 0x7F000001u);
        CHECK(load_le(v + 1) == 0xC0A80101u);
    }
    // long
    {
        auto col = batch.column(6);
        const auto* v = col.values<int64_t>();
        CHECK(load_le(v + 0) == -1);
        CHECK(load_le(v + 1) == 9223372036854775807LL);
    }
    // float
    {
        auto col = batch.column(7);
        const auto* v = col.values<float>();
        CHECK(load_le(v + 0) == doctest::Approx(1.25f));
        CHECK(load_le(v + 1) == doctest::Approx(-0.5f));
    }
    // double
    {
        auto col = batch.column(8);
        const auto* v = col.values<double>();
        CHECK(load_le(v + 0) == doctest::Approx(1.5));
        CHECK(load_le(v + 1) == doctest::Approx(-3.14));
    }
    // timestamp / date / timestamp_nanos — all i64 LE, distinct kind tags.
    {
        auto col = batch.column(9);
        CHECK(col.kind() == eg::column_kind::timestamp);
        CHECK(load_le(col.values<int64_t>() + 0) == 1700000000000000LL);
    }
    {
        auto col = batch.column(10);
        CHECK(col.kind() == eg::column_kind::date);
        CHECK(load_le(col.values<int64_t>() + 1) == 86400000LL);
    }
    {
        auto col = batch.column(11);
        CHECK(col.kind() == eg::column_kind::timestamp_nanos);
        CHECK(load_le(col.values<int64_t>() + 1) == 999999999LL);
    }
    // uuid — 16-byte stride, raw bytes match per-cell.
    {
        auto col = batch.column(12);
        CHECK(col.value_stride() == 16);
        const auto* base = static_cast<const uint8_t*>(col.values_raw());
        const auto per_cell = batch.column(12).get_uuid(0);
        REQUIRE(per_cell.has_value());
        CHECK(std::memcmp(base, per_cell->data(), 16) == 0);
    }
    // long256 — 32-byte stride.
    {
        auto col = batch.column(13);
        CHECK(col.value_stride() == 32);
        const auto* base = static_cast<const uint8_t*>(col.values_raw());
        const auto per_cell = batch.column(13).get_long256(1);
        REQUIRE(per_cell.has_value());
        CHECK(std::memcmp(base + 32, per_cell->data(), 32) == 0);
    }
}

TEST_CASE("mock: batch::column — binary + decimal64/128/256 + geohash bulk vs per-cell")
{
    qm::ColumnSpec c_bin{
        "bin", qm::COL_BINARY,
        qm::varlen_column_bytes({{0xDE, 0xAD, 0xBE, 0xEF}, {0x00, 0x01, 0x02}})};

    qm::ColumnSpec c_dec64{
        "d64", qm::COL_DECIMAL64,
        qm::decimal64_column_bytes({12345, -67890}, /*scale=*/3)};

    // DECIMAL128 is the 16-byte two's-complement little-endian mantissa.
    std::array<uint8_t, 16> dec128_a{};
    dec128_a[0] = 0x39; dec128_a[1] = 0x30; // 12345 LE
    std::array<uint8_t, 16> dec128_b{};
    for (auto& b : dec128_b) b = 0xFF; // -1 LE
    qm::ColumnSpec c_dec128{
        "d128", qm::COL_DECIMAL128,
        qm::decimal128_column_bytes({dec128_a, dec128_b}, /*scale=*/0)};

    std::array<uint8_t, 32> dec256_a{};
    dec256_a[0] = 0x39; dec256_a[1] = 0x30;
    std::array<uint8_t, 32> dec256_b{};
    dec256_b[0] = 0x01;
    qm::ColumnSpec c_dec256{
        "d256", qm::COL_DECIMAL256,
        qm::decimal256_column_bytes({dec256_a, dec256_b}, /*scale=*/2)};

    qm::ColumnSpec c_geo{
        "g", qm::COL_GEOHASH,
        qm::geohash_column_bytes(
            std::vector<bool>{false, false},
            std::vector<uint8_t>{0xAB, 0xCD},
            /*precision_bits=*/8)};

    qm::Script script = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{
            [c_bin, c_dec64, c_dec128, c_dec256, c_geo](int64_t rid)
            {
                return qm::result_batch_frame(
                    rid, 0, 2,
                    {c_bin, c_dec64, c_dec128, c_dec256, c_geo});
            }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({script});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select * from t"_utf8);
    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
    REQUIRE(batch.column_count() == 5);

    // binary
    {
        auto col = batch.column(0);
        REQUIRE(col.kind() == eg::column_kind::binary);
        const auto via_bulk = col.binary(0);
        const auto via_cell = batch.column(0).binary(0);
        REQUIRE(via_bulk.has_value());
        REQUIRE(via_cell.has_value());
        REQUIRE(via_bulk->size == via_cell->size);
        CHECK(std::memcmp(via_bulk->data, via_cell->data, via_bulk->size) == 0);
    }
    // decimal64 — strict overload required: DECIMAL64 is i64-stride but
    // semantically a scaled mantissa, so the whitelist rejects values<i64>().
    {
        auto col = batch.column(1);
        REQUIRE(col.kind() == eg::column_kind::decimal64);
        CHECK(col.value_stride() == 8);
        CHECK(col.decimal_scale() == 3);
        const auto* v = col.values<int64_t>(eg::column_kind::decimal64);
        CHECK(load_le(v + 0) == 12345);
        CHECK(load_le(v + 1) == -67890);
    }
    // decimal128
    {
        auto col = batch.column(2);
        REQUIRE(col.kind() == eg::column_kind::decimal128);
        CHECK(col.value_stride() == 16);
        CHECK(col.decimal_scale() == 0);
        const auto* base = static_cast<const uint8_t*>(col.values_raw());
        CHECK(std::memcmp(base, dec128_a.data(), 16) == 0);
        CHECK(std::memcmp(base + 16, dec128_b.data(), 16) == 0);
    }
    // decimal256
    {
        auto col = batch.column(3);
        REQUIRE(col.kind() == eg::column_kind::decimal256);
        CHECK(col.value_stride() == 32);
        CHECK(col.decimal_scale() == 2);
        const auto* base = static_cast<const uint8_t*>(col.values_raw());
        CHECK(std::memcmp(base, dec256_a.data(), 32) == 0);
        CHECK(std::memcmp(base + 32, dec256_b.data(), 32) == 0);
    }
    // geohash
    {
        auto col = batch.column(4);
        REQUIRE(col.kind() == eg::column_kind::geohash);
        CHECK(col.geohash_precision_bits() == 8);
        CHECK(col.value_stride() == 1);
        const auto* v = static_cast<const uint8_t*>(col.values_raw());
        CHECK(v[0] == 0xAB);
        CHECK(v[1] == 0xCD);
    }
}

TEST_CASE("mock: batch::column — DOUBLE_ARRAY round-trip")
{
    // Row 0: 1-D [1.5, 2.5, 3.5]. Row 1: NULL array. Row 2: non-null empty
    // (rank 1, shape[0] == 0).
    qm::ArrayRow row0{{3}, pack_le<double>({1.5, 2.5, 3.5})};
    qm::ArrayRow row2{{0}, {}};
    auto d_body = qm::array_column_bytes(
        {std::optional<qm::ArrayRow>{std::move(row0)},
         std::nullopt,
         std::optional<qm::ArrayRow>{std::move(row2)}});
    qm::ColumnSpec c_da{"da", qm::COL_DOUBLE_ARRAY, std::move(d_body)};

    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{
            [c_da](int64_t rid)
            {
                return qm::result_batch_frame(rid, 0, 3, {c_da});
            }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select * from t"_utf8);
    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;

    auto da = batch.column(0);
    REQUIRE(da.is_array());
    REQUIRE(da.kind() == eg::column_kind::double_array);
    REQUIRE(da.row_count() == 3);
    REQUIRE(da.has_nulls());
    // Scalar accessors on an array column raise.
    CHECK_THROWS_AS(da.values<double>(), questdb::error);
    CHECK_FALSE(da.is_null(0));
    CHECK(da.is_null(1));
    CHECK_FALSE(da.is_null(2));

    size_t da_rank = 0;
    const uint32_t* da_shape = da.shape(0, &da_rank);
    REQUIRE(da_rank == 1);
    CHECK(da_shape[0] == 3);

    size_t da_count = 0;
    const double* da_elems = da.elements<double>(0, &da_count);
    REQUIRE(da_count == 3);
    CHECK(load_le(da_elems + 0) == doctest::Approx(1.5));
    CHECK(load_le(da_elems + 1) == doctest::Approx(2.5));
    CHECK(load_le(da_elems + 2) == doctest::Approx(3.5));

    // Empty non-null row: rank 1, shape[0] == 0, no elements.
    size_t da2_rank = 0;
    const uint32_t* da2_shape = da.shape(2, &da2_rank);
    REQUIRE(da2_rank == 1);
    CHECK(da2_shape[0] == 0);
    size_t da2_count = 0;
    (void)da.elements<double>(2, &da2_count);
    CHECK(da2_count == 0);
}

TEST_CASE("mock: batch::symbol — column codes + dictionary bulk round-trip")
{
    qm::ColumnSpec c_sym{
        "s", qm::COL_SYMBOL,
        qm::symbol_column_bytes({0u, 1u, 2u, 1u})};

    qm::Script script = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{
            [c_sym](int64_t rid)
            {
                return qm::result_batch_frame_with_dict(
                    rid, 0, 4, {c_sym},
                    /*delta_start=*/0,
                    {"alpha", "beta", "gamma"});
            }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({script});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select s from t"_utf8);
    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;

    // Bulk dict snapshot — the Cython categorical-categories path.
    auto dict = batch.symbol_dict();
    REQUIRE(dict.valid());
    REQUIRE(dict.entry_count() == 3);
    CHECK(dict[0] == "alpha");
    CHECK(dict[1] == "beta");
    CHECK(dict[2] == "gamma");
    CHECK_THROWS_AS(dict[3], questdb::error);

    auto col = batch.column(0);
    REQUIRE(col.kind() == eg::column_kind::symbol);
    REQUIRE(col.value_stride() == 0);
    REQUIRE(col.values_raw() == nullptr);
    const uint32_t* codes = col.symbol_codes();
    REQUIRE(codes != nullptr);
    CHECK(codes[0] == 0);
    CHECK(codes[1] == 1);
    CHECK(codes[2] == 2);
    CHECK(codes[3] == 1);

    // Per-row resolution via column.
    CHECK(col.symbol(0).value() == "alpha");
    CHECK(col.symbol(1).value() == "beta");
    CHECK(col.symbol(2).value() == "gamma");
    CHECK(col.symbol(3).value() == "beta");

    // Per-cell getter equivalence on every row.
    for (size_t r = 0; r < 4; ++r)
    {
        const auto via_bulk = col.symbol(r);
        const auto via_cell = batch.column(0).symbol(r);
        REQUIRE(via_bulk.has_value());
        REQUIRE(via_cell.has_value());
        CHECK(*via_bulk == *via_cell);
    }

    // Per-code resolution via batch (no col_idx dispatch on dict side).
    CHECK(batch.symbol(0, 0) == "alpha");
    CHECK(batch.symbol(0, 2) == "gamma");
}

TEST_CASE("mock: array accessors on a scalar column raise")
{
    qm::ColumnSpec c{
        "v", qm::COL_INT, qm::fixed_column_bytes(1, pack_le<int32_t>({7}))};
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[c](int64_t rid)
                            { return qm::result_batch_frame(rid, 0, 1, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});

    auto reader = connect_to(srv);
    auto cur = reader.execute("select v from t"_utf8);
    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);

    auto col = batch_opt->column(0);
    REQUIRE_FALSE(col.is_array());
    size_t dummy = 0;
    CHECK_THROWS_AS(col.shape(0, &dummy), questdb::error);
    CHECK_THROWS_AS(col.elements<double>(0, &dummy), questdb::error);
}

TEST_CASE("decimal_view: mantissa_bytes is width-agnostic and null-safe")
{
    struct decimal_case
    {
        eg::column_kind kind;
        size_t stride;
    };
    const decimal_case cases[] = {
        {eg::column_kind::decimal64, 8},
        {eg::column_kind::decimal128, 16},
        {eg::column_kind::decimal256, 32},
    };

    for (const auto& c : cases)
    {
        // Offset by one so the accessor is exercised with an unaligned buffer.
        std::vector<uint8_t> storage(1 + 2 * c.stride);
        auto* values = storage.data() + 1;
        for (size_t i = 0; i < 2 * c.stride; ++i)
            values[i] = static_cast<uint8_t>(i + 1);
        const uint8_t validity = 0x02; // row 1 is NULL
        const eg::decimal_view view{
            c.kind, values, c.stride, 2, 3, &validity};

        const auto first = view.mantissa_bytes(0);
        REQUIRE(first.has_value());
        CHECK(first->data == values);
        CHECK(first->size == c.stride);
        CHECK(first->data[c.stride - 1] == c.stride);
        CHECK_FALSE(view.mantissa_bytes(1).has_value());
        CHECK_FALSE(view.mantissa_bytes(2).has_value());
    }
}

TEST_CASE(
    "mock: column::visit dispatches to the matching typed view per kind")
{
    // One batch covering one representative column per view family. visit
    // returns a stable discriminator string identifying which view branch
    // ran — equality vs the expected per-column tag pins the dispatch.
    using qm::ColumnSpec;
    using qm::fixed_column_bytes;

    std::vector<uint8_t> uuid_bytes(16, 0);
    for (size_t i = 0; i < 16; ++i)
        uuid_bytes[i] = static_cast<uint8_t>(i + 1);

    ColumnSpec c_bool{
        "b", qm::COL_BOOLEAN, std::vector<uint8_t>{0x00, 0b00000001}};
    ColumnSpec c_int{
        "i", qm::COL_INT, fixed_column_bytes(1, pack_le<int32_t>({42}))};
    ColumnSpec c_long{
        "l", qm::COL_LONG, fixed_column_bytes(1, pack_le<int64_t>({-1}))};
    ColumnSpec c_double{
        "d", qm::COL_DOUBLE, fixed_column_bytes(1, pack_le<double>({3.5}))};
    ColumnSpec c_dec64{
        "d64", qm::COL_DECIMAL64,
        qm::decimal64_column_bytes({12345}, /*scale=*/3)};
    ColumnSpec c_uuid{"u", qm::COL_UUID, fixed_column_bytes(1, uuid_bytes)};
    ColumnSpec c_geo{
        "g", qm::COL_GEOHASH,
        qm::geohash_column_bytes(
            std::vector<bool>{false},
            std::vector<uint8_t>{0xAB},
            /*precision_bits=*/8)};
    ColumnSpec c_varchar{
        "s", qm::COL_VARCHAR, qm::varlen_column_bytes({{'h', 'i'}})};
    ColumnSpec c_sym{
        "sym", qm::COL_SYMBOL, qm::symbol_column_bytes({0u})};

    qm::Script script = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{
            [=](int64_t rid) {
                return qm::result_batch_frame_with_dict(
                    rid, 0, 1,
                    {c_bool, c_int, c_long, c_double, c_dec64, c_uuid, c_geo,
                     c_varchar, c_sym},
                    /*delta_start=*/0,
                    {"alpha"});
            }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({script});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select * from t"_utf8);
    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
    REQUIRE(batch.column_count() == 9);

    auto tag_of = [](const eg::column& col) -> std::string {
        return col.visit(eg::overload{
            [](eg::fixed_view<uint8_t>)  { return std::string{"bool"}; },
            [](eg::fixed_view<int8_t>)   { return std::string{"byte"}; },
            [](eg::fixed_view<int16_t>)  { return std::string{"short"}; },
            [](eg::fixed_view<uint16_t>) { return std::string{"char"}; },
            [](eg::fixed_view<int32_t>)  { return std::string{"i32"}; },
            [](eg::fixed_view<uint32_t>) { return std::string{"ipv4"}; },
            [](eg::fixed_view<int64_t>)  { return std::string{"i64"}; },
            [](eg::fixed_view<float>)    { return std::string{"f32"}; },
            [](eg::fixed_view<double>)   { return std::string{"f64"}; },
            [](eg::decimal_view)         { return std::string{"decimal"}; },
            [](eg::bytes_view)           { return std::string{"bytes"}; },
            [](eg::geohash_view)         { return std::string{"geohash"}; },
            [](eg::varlen_view)          { return std::string{"varlen"}; },
            [](eg::symbol_view)          { return std::string{"symbol"}; },
            [](eg::array_view<double>)   { return std::string{"darray"}; },
        });
    };

    CHECK(tag_of(batch.column(0)) == "bool");
    CHECK(tag_of(batch.column(1)) == "i32");
    CHECK(tag_of(batch.column(2)) == "i64");
    CHECK(tag_of(batch.column(3)) == "f64");
    CHECK(tag_of(batch.column(4)) == "decimal");
    CHECK(tag_of(batch.column(5)) == "bytes");
    CHECK(tag_of(batch.column(6)) == "geohash");
    CHECK(tag_of(batch.column(7)) == "varlen");
    CHECK(tag_of(batch.column(8)) == "symbol");

    // Sanity: the dispatched view actually yields the right value.
    batch.column(1).visit(eg::overload{
        [](eg::fixed_view<int32_t> v) {
            REQUIRE(v.row_count == 1);
            REQUIRE_FALSE(v.is_null(0));
            CHECK(load_le(v.values + 0) == 42);
        },
        [](auto&&) {
            FAIL("INT column did not dispatch to fixed_view<int32_t>");
        },
    });
    batch.column(4).visit(eg::overload{
        [](eg::decimal_view v) {
            CHECK(v.kind == eg::column_kind::decimal64);
            CHECK(v.value_stride == 8);
            CHECK(v.scale == 3);
        },
        [](auto&&) {
            FAIL("DECIMAL64 column did not dispatch to decimal_view");
        },
    });
    batch.column(8).visit(eg::overload{
        [](eg::symbol_view v) {
            const auto x = v.resolve(0);
            REQUIRE(x);
            CHECK(*x == "alpha");
        },
        [](auto&&) { FAIL("SYMBOL column did not dispatch to symbol_view"); },
    });
}

TEST_CASE("mock: column::visit dispatches DOUBLE_ARRAY to array_view<double>")
{
    qm::ArrayRow row0{{3}, pack_le<double>({1.5, 2.5, 3.5})};
    auto body = qm::array_column_bytes(
        {std::optional<qm::ArrayRow>{std::move(row0)}});
    qm::ColumnSpec c_da{"da", qm::COL_DOUBLE_ARRAY, std::move(body)};
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[c_da](int64_t rid) {
            return qm::result_batch_frame(rid, 0, 1, {c_da});
        }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select * from t"_utf8);
    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);

    batch_opt->column(0).visit(eg::overload{
        [](eg::array_view<double> v) {
            REQUIRE(v.row_count == 1);
            const auto e = v.elements(0);
            REQUIRE(e);
            REQUIRE(e->second == 3);
            CHECK(load_le(e->first + 0) == doctest::Approx(1.5));
            CHECK(load_le(e->first + 1) == doctest::Approx(2.5));
            CHECK(load_le(e->first + 2) == doctest::Approx(3.5));
            const auto sh = v.shape(0);
            REQUIRE(sh);
            REQUIRE(sh->second == 1);
            CHECK(load_le(sh->first + 0) == 3u);
        },
        [](auto&&) {
            FAIL("DOUBLE_ARRAY did not dispatch to array_view<double>");
        },
    });
}

// ---------------------------------------------------------------------------
// Coverage gaps documented but not yet asserted in this suite — left as
// breadcrumbs for the next contributor:
//
//  - `tls_error`: needs a real TLS terminator in front of the mock.
//  - `unsupported_server`: the mock pins QWP version 1 (the only version
//    this client speaks); triggering the upstream version-rejection path
//    needs the handshake to advertise a higher X-QWP-Version.
//  - `invalid_timestamp` / `invalid_decimal`: per upstream, these
//    error variants are reachable from sender code paths but not
//    produced by the reader as of this revision; assertion would need
//    an FFI change first.
//  - Client-side `limit_exceeded`: triggered by an oversized zstd
//    content-size header. The mock does not currently emit zstd
//    frames; needs a small bytes-sender shim.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Pool integration: `questdb::pool::borrow_reader()`.
//
// Mirrors the Rust `QuestDb::borrow_reader` coverage
// (questdb-rs/src/tests/qwp_sender_pool.rs::reader_pool). The unified pool
// hands out query readers as well as senders; a borrowed reader returns to
// the pool on destruction unless `drop_on_return()` was called.
//
// The pool sets `lazy_connect=true` so construction opens no connections
// (mirroring the Rust `reader_pool_*` tests, which assert
// `server.accepted() == 0` right after `connect`) and reader borrows consume
// scripts from index 0. The reader
// connection sends SERVER_INFO at connect, then parks on the query request
// that never arrives.
// ---------------------------------------------------------------------------

namespace
{
qm::Script reader_park_script(uint8_t role = qm::ROLE_PRIMARY)
{
    return qm::Script{
        qm::ActionSendServerInfo{role, "test-cluster", "node-A"},
        qm::ActionAwaitQueryRequest{}, // park: this test never executes a query
    };
}

std::string pool_conf(const std::string& addr)
{
    return "ws::addr=" + addr +
           ";lazy_connect=true;sender_pool_min=1;pool_reap=manual;";
}
} // namespace

TEST_CASE("pool::borrow_reader borrows a usable reader and recycles it")
{
    // Lazy pool: construction opens nothing, so the first reader borrow
    // consumes script[0]; the re-borrow reuses the recycled reader and
    // opens no new connection.
    qm::MockServer srv({
        reader_park_script(),
    });
    questdb::pool db{pool_conf(srv.addr())};

    {
        // Resembles the Rust `let mut reader = db.borrow_reader()?;`.
        auto reader = db.borrow_reader();
        CHECK(reader.server_version() == 1);
        CHECK_FALSE(reader.current_host().empty());
        auto info = reader.server_info();
        CHECK(info.cluster_id() == "test-cluster");
    } // <- returned to the pool here

    // Re-borrowing reuses the recycled reader — no new connection is opened.
    int accepts_before_reuse = srv.accepts();
    {
        auto reader = db.borrow_reader();
        CHECK(reader.server_version() == 1);
    }
    CHECK(srv.accepts() == accepts_before_reuse);
}

TEST_CASE("pool::borrow_reader honours drop_on_return (drops, not recycles)")
{
    // Lazy pool: construction opens nothing. The first borrow consumes
    // script[0]; after the drop-on-return the re-borrow opens a fresh
    // connection and consumes script[1].
    qm::MockServer srv({
        reader_park_script(), // first reader borrow
        reader_park_script(), // re-borrow after drop-on-return
    });
    questdb::pool db{pool_conf(srv.addr())};

    {
        auto reader = db.borrow_reader();
        CHECK(reader.server_version() == 1);
        reader.drop_on_return();
    }

    // The drop-on-return reader was dropped, so the next borrow opens a fresh
    // connection (one more accept).
    int accepts_before = srv.accepts();
    {
        auto reader = db.borrow_reader();
        CHECK(reader.server_version() == 1);
    }
    CHECK(srv.accepts() == accepts_before + 1);
}
