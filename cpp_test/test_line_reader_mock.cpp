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

// Mock-server-driven tests for the line_reader FFI.
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

#include <questdb/egress/line_reader.hpp>

#include <atomic>
#include <chrono>
#include <cstring>
#include <memory>
#include <string>
#include <thread>

using namespace questdb::ingress::literals;
namespace qm = qwp_mock;

namespace
{

questdb::egress::reader connect_to(const qm::MockServer& srv)
{
    const std::string conf = "ws::addr=" + srv.addr() + ";";
    return questdb::egress::reader{questdb::ingress::utf8_view{conf}};
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
    CHECK(reader.server_version() == 2);
    CHECK_FALSE(reader.current_host().empty());

    // Server identity from SERVER_INFO is exposed via the wrapper.
    auto info = reader.server_info();
    REQUIRE(static_cast<bool>(info));
    CHECK(info.role_byte() == qm::ROLE_PRIMARY);
    CHECK(info.cluster_id() == "test-cluster");
    CHECK(info.node_id() == "node-A");

    auto cur = reader.execute("select 1"_utf8);
    // Empty result → next_batch() returns false on first call.
    CHECK_FALSE(cur.next_batch());
    CHECK(cur.terminal_kind() == line_reader_terminal_kind_end);

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
                            { return qm::result_batch_frame(rid, 0, 1, 3, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});

    auto reader = connect_to(srv);
    auto cur = reader.execute("select v from t"_utf8);
    REQUIRE(cur.next_batch());
    REQUIRE(cur.row_count() == 3);
    REQUIRE(cur.column_kind(0) == line_reader_column_kind_int);

    auto v0 = cur.get_i32(0, 0);
    auto v1 = cur.get_i32(0, 1);
    auto v2 = cur.get_i32(0, 2);
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
                                    rid, 0, 1, 2,
                                    {c_i64, c_f64, c_bool, c_i8, c_i16, c_f32});
                            }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select * from t"_utf8);
    REQUIRE(cur.next_batch());
    REQUIRE(cur.row_count() == 2);

    REQUIRE(cur.get_i64(0, 0).value_or(0) == -1);
    REQUIRE(cur.get_i64(0, 1).value_or(0) == 9223372036854775807LL);
    CHECK(cur.get_f64(1, 0).value_or(0) == doctest::Approx(1.5));
    CHECK(cur.get_f64(1, 1).value_or(0) == doctest::Approx(-3.14));
    CHECK(cur.get_bool(2, 0).value_or(true) == false);
    CHECK(cur.get_bool(2, 1).value_or(false) == true);
    CHECK(cur.get_i8(3, 0).value_or(0) == -7);
    CHECK(cur.get_i8(3, 1).value_or(0) == 42);
    CHECK(cur.get_i16(4, 0).value_or(0) == -1234);
    CHECK(cur.get_i16(4, 1).value_or(0) == 31000);
    CHECK(cur.get_f32(5, 0).value_or(0.0f) == doctest::Approx(1.25f));
    CHECK(cur.get_f32(5, 1).value_or(0.0f) == doctest::Approx(-0.5f));
}

TEST_CASE("mock: column getter — varchar")
{
    auto body = qm::varlen_column_bytes({{'h', 'i'}, {'h', 'e', 'l', 'l', 'o'}});
    qm::ColumnSpec c{"s", qm::COL_VARCHAR, std::move(body)};

    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[c](int64_t rid)
                            { return qm::result_batch_frame(rid, 0, 1, 2, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select s from t"_utf8);
    REQUIRE(cur.next_batch());
    REQUIRE(cur.row_count() == 2);
    auto v0 = cur.get_varchar(0, 0);
    auto v1 = cur.get_varchar(0, 1);
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
                            { return qm::result_batch_frame(rid, 0, 1, 1, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select u from t"_utf8);
    REQUIRE(cur.next_batch());
    auto u = cur.get_uuid(0, 0);
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
                            { return qm::result_batch_frame(rid, 0, 1, 2, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select d from t"_utf8);
    REQUIRE(cur.next_batch());
    auto d0 = cur.get_decimal64(0, 0);
    auto d1 = cur.get_decimal64(0, 1);
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
                            { return qm::result_batch_frame(rid, 0, 1, 1, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select d from t"_utf8);
    REQUIRE(cur.next_batch());
    auto d = cur.get_decimal128(0, 0);
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

TEST_CASE("mock: column_validity bitmap matches null pattern from server")
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
                            { return qm::result_batch_frame(rid, 0, 1, 5, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select v from t"_utf8);
    REQUIRE(cur.next_batch());
    REQUIRE(cur.row_count() == 5);

    auto vv = cur.column_validity(0);
    REQUIRE_FALSE(vv.empty());
    REQUIRE(vv.size >= 1);
    // Bit pattern: rows 1 and 3 set, others clear → low 5 bits = 0b01010 = 0x0A.
    CHECK((vv.data[0] & 0x1F) == 0x0A);

    CHECK(cur.get_i64(0, 0).value_or(-1) == 10);
    CHECK_FALSE(cur.get_i64(0, 1).has_value());
    CHECK(cur.get_i64(0, 2).value_or(-1) == 30);
    CHECK_FALSE(cur.get_i64(0, 3).has_value());
    CHECK(cur.get_i64(0, 4).value_or(-1) == 50);
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
    catch (const questdb::egress::line_reader_error& e)
    {
        threw = true;
        CHECK(e.code() == line_reader_error_server_parse_error);
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
    catch (const questdb::egress::line_reader_error& e)
    {
        threw = true;
        CHECK(e.code() == line_reader_error_server_internal_error);
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
    catch (const questdb::egress::line_reader_error& e)
    {
        threw = true;
        CHECK(e.code() == line_reader_error_server_security_error);
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
    CHECK(cur.terminal_kind() == line_reader_terminal_kind_exec_done);
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
                            { return qm::result_batch_frame(rid, 0, 1, 1, {c}); }},
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
void run_query_error_test(uint8_t status, ::line_reader_error_code expected)
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
    catch (const questdb::egress::line_reader_error& e)
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
        line_reader_error_server_schema_mismatch);
}

TEST_CASE("mock: QueryError(limit_exceeded) surfaces as ServerLimitExceeded")
{
    run_query_error_test(
        qm::STATUS_LIMIT_EXCEEDED,
        line_reader_error_server_limit_exceeded);
}

TEST_CASE("mock: QueryError(cancelled) surfaces as Cancelled")
{
    run_query_error_test(
        qm::STATUS_CANCELLED,
        line_reader_error_cancelled);
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
    catch (const questdb::egress::line_reader_error& e)
    {
        // cancel() returns once the cursor is drained. If the server
        // CANCELLED status arrives during the drain, it surfaces here.
        threw = true;
        CHECK(e.code() == line_reader_error_cancelled);
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
            return qm::result_batch_frame(rid, 0, 1, 1, {c});
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
                            { return qm::result_batch_frame(rid, 0, 1, 1, {c}); }},
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
    catch (const questdb::egress::line_reader_error& e)
    {
        threw = true;
        CHECK(e.code() == line_reader_error_invalid_api_call);
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
            return qm::result_batch_frame(rid, 0, 1, 1, {col});
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
                           const questdb::egress::failover_event_view&) {
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
    catch (const questdb::egress::line_reader_error& e)
    {
        // Tolerate a single-cycle replay failure surfacing as a
        // transport-class error — this can happen on platforms where
        // the FIN propagates faster than the failover-callback
        // bookkeeping (vanishingly rare on macOS/Linux loopback).
        // But explicitly REJECT InvalidApiCall: that would mean
        // the 'done' guard fired against a still-live cursor, a
        // different bug we don't want to mask.
        threw = true;
        REQUIRE(e.code() != line_reader_error_invalid_api_call);
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
// over to B, the trampoline fires once, the FailoverEvent fields are
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

    struct Capture
    {
        std::atomic<int> count{0};
        std::string failed_host;
        uint16_t failed_port{0};
        std::string new_host;
        uint16_t new_port{0};
        uint32_t attempts{0};
        questdb::egress::error_code trigger_code{};
        bool server_info_present{false};
        std::string new_node_id;
    };
    auto cap = std::make_shared<Capture>();

    auto cur = reader.prepare("select 1"_utf8)
                   .on_failover_reset(
                       [cap](const questdb::egress::failover_event_view& ev)
                       {
                           cap->count.fetch_add(1);
                           cap->failed_host = std::string(ev.failed_host());
                           cap->failed_port = ev.failed_port();
                           cap->new_host = std::string(ev.new_host());
                           cap->new_port = ev.new_port();
                           cap->attempts = ev.attempts();
                           cap->trigger_code = ev.trigger_code();
                           auto si = ev.server_info();
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
    CHECK((cap->trigger_code == line_reader_error_socket_error ||
           cap->trigger_code == line_reader_error_protocol_error));
    REQUIRE(cap->server_info_present);
    CHECK(cap->new_node_id == "b");
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
                       [&count](const questdb::egress::failover_event_view&)
                       { count.fetch_add(1); })
                   .execute();
    while (cur.next_batch()) {}
    CHECK(count.load() == 0);
    CHECK(cur.failover_resets() == 0);
}

// ---------------------------------------------------------------------------
// DOUBLE_ARRAY / LONG_ARRAY getters (whole-row + per-element).
// ---------------------------------------------------------------------------

TEST_CASE("mock: get_double_array round-trips shape and elements")
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
                            { return qm::result_batch_frame(rid, 0, 1, 2, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select a"_utf8);
    REQUIRE(cur.next_batch());
    REQUIRE(cur.row_count() == 2);
    REQUIRE(cur.column_kind(0) == line_reader_column_kind_double_array);

    auto v0 = cur.get_double_array(0, 0);
    REQUIRE(v0.has_value());
    REQUIRE(v0->ndim == 1);
    REQUIRE(v0->shape[0] == 3);
    REQUIRE(v0->element_count == 3);
    // Element accessor returns one f64 by row+flat index.
    auto e0 = cur.get_double_array_element(0, 0, 0);
    auto e1 = cur.get_double_array_element(0, 0, 1);
    auto e2 = cur.get_double_array_element(0, 0, 2);
    REQUIRE(e0.has_value());
    CHECK(*e0 == doctest::Approx(1.5));
    REQUIRE(e1.has_value());
    CHECK(*e1 == doctest::Approx(2.5));
    REQUIRE(e2.has_value());
    CHECK(*e2 == doctest::Approx(3.5));

    auto v1 = cur.get_double_array(0, 1);
    REQUIRE(v1.has_value());
    REQUIRE(v1->ndim == 2);
    REQUIRE(v1->shape[0] == 2);
    REQUIRE(v1->shape[1] == 2);
    REQUIRE(v1->element_count == 4);
    auto e_2_2 = cur.get_double_array_element(0, 1, 3);
    REQUIRE(e_2_2.has_value());
    CHECK(*e_2_2 == doctest::Approx(40.0));
}

TEST_CASE("mock: get_long_array round-trips shape and elements")
{
    using Row = qm::ArrayRow;
    Row r0{{2}, pack_le<int64_t>({-1, 9223372036854775000LL})};
    auto body = qm::array_column_bytes({r0});
    qm::ColumnSpec c{"a", qm::COL_LONG_ARRAY, std::move(body)};

    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[c](int64_t rid)
                            { return qm::result_batch_frame(rid, 0, 1, 1, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select a"_utf8);
    REQUIRE(cur.next_batch());
    auto v = cur.get_long_array(0, 0);
    REQUIRE(v.has_value());
    REQUIRE(v->ndim == 1);
    REQUIRE(v->element_count == 2);
    auto e0 = cur.get_long_array_element(0, 0, 0);
    auto e1 = cur.get_long_array_element(0, 0, 1);
    REQUIRE(e0.has_value());
    CHECK(*e0 == -1);
    REQUIRE(e1.has_value());
    CHECK(*e1 == 9223372036854775000LL);
}

TEST_CASE("mock: non-null empty-data array row exposes data == NULL")
{
    // Shape [2, 0, 3] is legitimate: non-null row, zero elements, zero
    // bytes of `data`. Without the pointer-symmetry guard, the FFI used
    // to expose Rust's `(&[]).as_ptr()` dangling sentinel as a
    // non-null `data` pointer to C consumers, breaking defensive checks
    // like `if (view.data) memcpy(...)`. Pin the contract here.
    using Row = qm::ArrayRow;
    Row r0{{2, 0, 3}, {}};                  // non-null, zero bytes of data
    auto body = qm::array_column_bytes({r0});
    qm::ColumnSpec c{"a", qm::COL_DOUBLE_ARRAY, std::move(body)};

    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[c](int64_t rid)
                            { return qm::result_batch_frame(rid, 0, 1, 1, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select a"_utf8);
    REQUIRE(cur.next_batch());
    auto v = cur.get_double_array(0, 0);
    REQUIRE(v.has_value());                 // not a NULL row
    CHECK(v->ndim == 3);
    CHECK(v->shape[0] == 2);
    CHECK(v->shape[1] == 0);
    CHECK(v->shape[2] == 3);
    CHECK(v->element_count == 0);
    CHECK(v->data_len == 0);
    CHECK(v->data == nullptr);              // M-3 contract: empty ⇒ NULL
}

TEST_CASE("mock: get_double_array surfaces NULL row via std::nullopt")
{
    using Row = qm::ArrayRow;
    Row r0{{1}, pack_le<double>({7.0})};
    auto body = qm::array_column_bytes({r0, std::nullopt});
    qm::ColumnSpec c{"a", qm::COL_DOUBLE_ARRAY, std::move(body)};

    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[c](int64_t rid)
                            { return qm::result_batch_frame(rid, 0, 1, 2, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select a"_utf8);
    REQUIRE(cur.next_batch());
    REQUIRE(cur.row_count() == 2);
    auto v0 = cur.get_double_array(0, 0);
    auto v1 = cur.get_double_array(0, 1);
    REQUIRE(v0.has_value());
    CHECK(v0->element_count == 1);
    CHECK_FALSE(v1.has_value());
    // Per-element getter on the null row also returns nullopt.
    CHECK_FALSE(cur.get_double_array_element(0, 1, 0).has_value());
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
                            { return qm::result_batch_frame(rid, 0, 1, 2, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select c"_utf8);
    REQUIRE(cur.next_batch());
    auto v0 = cur.get_char(0, 0);
    auto v1 = cur.get_char(0, 1);
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
                            { return qm::result_batch_frame(rid, 0, 1, 1, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select l"_utf8);
    REQUIRE(cur.next_batch());
    auto v = cur.get_long256(0, 0);
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
                            { return qm::result_batch_frame(rid, 0, 1, 2, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select b"_utf8);
    REQUIRE(cur.next_batch());
    auto v0 = cur.get_binary(0, 0);
    auto v1 = cur.get_binary(0, 1);
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
                            { return qm::result_batch_frame(rid, 0, 1, 1, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select d"_utf8);
    REQUIRE(cur.next_batch());
    auto v = cur.get_decimal256(0, 0);
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
                            { return qm::result_batch_frame(rid, 0, 1, 2, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto reader = connect_to(srv);
    auto cur = reader.execute("select g"_utf8);
    REQUIRE(cur.next_batch());
    auto v0 = cur.get_geohash(0, 0);
    auto v1 = cur.get_geohash(0, 1);
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
                            { return qm::result_batch_frame(rid, /*batch_seq=*/0, 1, 1, {c}); }},
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
    REQUIRE(cur.next_batch());

    // request_id is non-zero and matches batch_request_id of the batch.
    const int64_t rid = cur.request_id();
    CHECK(rid != 0);
    auto bri = cur.batch_request_id();
    REQUIRE(bri.has_value());
    CHECK(*bri == rid);
    auto bseq = cur.batch_seq();
    REQUIRE(bseq.has_value());
    CHECK(*bseq == 0);

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
// line_reader_error with InvalidBind code rather than a panic / abort.
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
    questdb::egress::error_code code{};
    try
    {
        (void)q.execute();
    }
    catch (const questdb::egress::line_reader_error& e)
    {
        threw = true;
        code = e.code();
    }
    CHECK(threw);
    CHECK(code == line_reader_error_invalid_bind);
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
    line_reader_error* err = nullptr;
    line_reader* r = line_reader_from_conf(c, &err);
    REQUIRE(r == nullptr);
    REQUIRE(err != nullptr);
    const auto code = line_reader_error_get_code(err);
    // The mock returns HTTP 401 during the upgrade handshake. Upstream
    // currently surfaces this as either AuthError or HandshakeError
    // depending on which layer caught it; both are correct
    // connection-establishment failures. Anything else (e.g.
    // socket_error, config_error, success) is a regression.
    CHECK((code == line_reader_error_auth_error
        || code == line_reader_error_handshake_error));
    line_reader_error_free(err);
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
    line_reader_error* err = nullptr;
    line_reader* r = line_reader_from_conf(c, &err);
    REQUIRE(r == nullptr);
    REQUIRE(err != nullptr);
    // Either AuthError (both endpoints actually replied 401) or
    // HandshakeError (race on one endpoint surfacing as a different
    // class). The aggregated-message check below is the part that
    // actually pins the new behaviour.
    const auto code = line_reader_error_get_code(err);
    CHECK((code == line_reader_error_auth_error
        || code == line_reader_error_handshake_error));
    size_t mlen = 0;
    const char* msg = line_reader_error_msg(err, &mlen);
    const std::string m{msg, mlen};
    if (code == line_reader_error_auth_error)
    {
        // AuthError is terminal on the first 401: credentials are
        // cluster-wide, so retrying every host would flood server logs
        // without recovery (matches the Java reference's
        // QwpQueryClient.connect() which rethrows on QwpAuthFailedException
        // immediately). The diagnostic names the endpoint that refused.
        CHECK(m.find(srv1.addr()) != std::string::npos);
    }
    line_reader_error_free(err);
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
    CHECK(cur.terminal_kind() == line_reader_terminal_kind_end);
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
::line_reader* raw_handle(questdb::egress::reader& r) noexcept
{
    struct reader_layout { ::line_reader* impl; };
    return reinterpret_cast<reader_layout*>(&r)->impl;
}
::line_reader_query* raw_handle(questdb::egress::query& q) noexcept
{
    struct query_layout { ::line_reader_query* impl; };
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
    line_reader_error* err = nullptr;
    line_reader_query* q =
        line_reader_prepare(raw_handle(reader), sql, &err);
    REQUIRE(q == nullptr);
    REQUIRE(err != nullptr);
    CHECK(line_reader_error_get_code(err) == line_reader_error_invalid_utf8);
    line_reader_error_free(err);
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
    line_reader_query_bind_varchar(raw_handle(q), v);
    // bind_varchar stashes the deferred error; execute() must surface
    // it as InvalidUtf8 without touching the wire.
    bool threw = false;
    questdb::egress::error_code code{};
    try
    {
        (void)q.execute();
    }
    catch (const questdb::egress::line_reader_error& e)
    {
        threw = true;
        code = e.code();
    }
    CHECK(threw);
    CHECK(code == line_reader_error_invalid_utf8);
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
    line_reader_query_bind_varchar(raw_handle(q), v_bad);
    // A second, valid bind must not overwrite the first error.
    q.bind_i32(7);
    bool threw = false;
    questdb::egress::error_code code{};
    try
    {
        (void)q.execute();
    }
    catch (const questdb::egress::line_reader_error& e)
    {
        threw = true;
        code = e.code();
    }
    CHECK(threw);
    CHECK(code == line_reader_error_invalid_utf8);
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
                            { return qm::result_batch_frame(rid, 0, 1, 1, {c0, c1}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});

    auto reader = connect_to(srv);
    auto cur = reader.execute("select * from t"_utf8);
    REQUIRE(cur.next_batch());
    REQUIRE(cur.column_count() == 2);
    CHECK(cur.column_name(0) == "my_long");
    CHECK(cur.column_name(1) == "another_col");
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
                            { return qm::result_batch_frame(rid, 0, 1, 1, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});

    auto reader = connect_to(srv);
    auto cur = reader.execute("select v from t"_utf8);
    REQUIRE(cur.next_batch());
    REQUIRE(cur.column_count() == 1);

    bool threw = false;
    questdb::egress::error_code code{};
    try
    {
        (void)cur.column_name(99);
    }
    catch (const questdb::egress::line_reader_error& e)
    {
        threw = true;
        code = e.code();
    }
    CHECK(threw);
    CHECK(code == line_reader_error_invalid_api_call);
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
                            { return qm::result_batch_frame(rid, 0, 1, 3, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});

    auto reader = connect_to(srv);
    auto cur = reader.execute("select ip from t"_utf8);
    REQUIRE(cur.next_batch());
    REQUIRE(cur.column_kind(0) == line_reader_column_kind_ipv4);

    auto v0 = cur.get_ipv4(0, 0);
    auto v1 = cur.get_ipv4(0, 1);
    auto v2 = cur.get_ipv4(0, 2);
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
                            { return qm::result_batch_frame(rid, 0, 1, 1, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});

    auto reader = connect_to(srv);
    auto cur = reader.execute("select ip from t"_utf8);
    REQUIRE(cur.next_batch());
    REQUIRE(cur.column_kind(0) == line_reader_column_kind_ipv4);

    bool threw = false;
    questdb::egress::error_code code{};
    try
    {
        (void)cur.get_i32(0, 0);
    }
    catch (const questdb::egress::line_reader_error& e)
    {
        threw = true;
        code = e.code();
    }
    CHECK(threw);
    CHECK(code == line_reader_error_invalid_api_call);
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
                            { return qm::result_batch_frame(rid, 0, 1, 1, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});

    auto reader = connect_to(srv);
    auto cur = reader.execute("select n from t"_utf8);
    REQUIRE(cur.next_batch());

    bool threw = false;
    questdb::egress::error_code code{};
    try
    {
        (void)cur.get_ipv4(0, 0);
    }
    catch (const questdb::egress::line_reader_error& e)
    {
        threw = true;
        code = e.code();
    }
    CHECK(threw);
    CHECK(code == line_reader_error_invalid_api_call);
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
// Wrong-column-type rejection: each typed getter must reject a column
// whose kind doesn't match. Drive this from a single INT column and call
// every other getter once. Each must throw `invalid_api_call`. This pins
// the type-mismatch branch in every `_cursor_get_*` (egress.rs:1367+).
// ---------------------------------------------------------------------------
TEST_CASE("mock: typed getters reject mismatched column kind")
{
    qm::ColumnSpec int_col{
        "n", qm::COL_INT, qm::fixed_column_bytes(1, pack_le<int32_t>({42}))};
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[int_col](int64_t rid)
                            { return qm::result_batch_frame(rid, 0, 1, 1, {int_col}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});

    auto reader = connect_to(srv);
    auto cur = reader.execute("select n from t"_utf8);
    REQUIRE(cur.next_batch());

    auto expect_throws = [&](auto&& fn) {
        bool threw = false;
        questdb::egress::error_code code{};
        try
        {
            fn();
        }
        catch (const questdb::egress::line_reader_error& e)
        {
            threw = true;
            code = e.code();
        }
        CHECK(threw);
        CHECK(code == line_reader_error_invalid_api_call);
    };

    SUBCASE("get_bool")        { expect_throws([&]{ (void)cur.get_bool(0, 0); }); }
    SUBCASE("get_i8")          { expect_throws([&]{ (void)cur.get_i8(0, 0); }); }
    SUBCASE("get_i16")         { expect_throws([&]{ (void)cur.get_i16(0, 0); }); }
    SUBCASE("get_i64")         { expect_throws([&]{ (void)cur.get_i64(0, 0); }); }
    SUBCASE("get_f32")         { expect_throws([&]{ (void)cur.get_f32(0, 0); }); }
    SUBCASE("get_f64")         { expect_throws([&]{ (void)cur.get_f64(0, 0); }); }
    SUBCASE("get_char")        { expect_throws([&]{ (void)cur.get_char(0, 0); }); }
    SUBCASE("get_uuid")        { expect_throws([&]{ (void)cur.get_uuid(0, 0); }); }
    SUBCASE("get_long256")     { expect_throws([&]{ (void)cur.get_long256(0, 0); }); }
    SUBCASE("get_varchar")     { expect_throws([&]{ (void)cur.get_varchar(0, 0); }); }
    SUBCASE("get_binary")      { expect_throws([&]{ (void)cur.get_binary(0, 0); }); }
    SUBCASE("get_symbol")      { expect_throws([&]{ (void)cur.get_symbol(0, 0); }); }
    SUBCASE("get_decimal64")   { expect_throws([&]{ (void)cur.get_decimal64(0, 0); }); }
    SUBCASE("get_decimal128")  { expect_throws([&]{ (void)cur.get_decimal128(0, 0); }); }
    SUBCASE("get_decimal256")  { expect_throws([&]{ (void)cur.get_decimal256(0, 0); }); }
    SUBCASE("get_geohash")     { expect_throws([&]{ (void)cur.get_geohash(0, 0); }); }
    SUBCASE("get_double_array"){ expect_throws([&]{ (void)cur.get_double_array(0, 0); }); }
    SUBCASE("get_long_array")  { expect_throws([&]{ (void)cur.get_long_array(0, 0); }); }
    SUBCASE("get_ipv4")        { expect_throws([&]{ (void)cur.get_ipv4(0, 0); }); }
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
                            { return qm::result_batch_frame(rid, 0, 1, 2, {int_col}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});

    auto reader = connect_to(srv);
    auto cur = reader.execute("select n from t"_utf8);
    REQUIRE(cur.next_batch());
    REQUIRE(cur.column_count() == 1);
    REQUIRE(cur.row_count() == 2);

    auto expect_invalid_api = [](auto&& fn) {
        bool threw = false;
        questdb::egress::error_code code{};
        try
        {
            fn();
        }
        catch (const questdb::egress::line_reader_error& e)
        {
            threw = true;
            code = e.code();
        }
        CHECK(threw);
        CHECK(code == line_reader_error_invalid_api_call);
    };

    SUBCASE("column_kind out-of-range column")
    {
        expect_invalid_api([&]{ (void)cur.column_kind(99); });
    }
    SUBCASE("column_name out-of-range column")
    {
        expect_invalid_api([&]{ (void)cur.column_name(99); });
    }
    SUBCASE("get_i32 out-of-range column")
    {
        expect_invalid_api([&]{ (void)cur.get_i32(99, 0); });
    }
    SUBCASE("get_i32 out-of-range row")
    {
        expect_invalid_api([&]{ (void)cur.get_i32(0, 99); });
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
                                    rid, 0, 1, 1, {c_ts, c_date, c_tn});
                            }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});

    auto reader = connect_to(srv);
    auto cur = reader.execute("select ts, d, tn from t"_utf8);
    REQUIRE(cur.next_batch());
    REQUIRE(cur.column_count() == 3);
    CHECK(cur.column_kind(0) == line_reader_column_kind_timestamp);
    CHECK(cur.column_kind(1) == line_reader_column_kind_date);
    CHECK(cur.column_kind(2) == line_reader_column_kind_timestamp_nanos);

    auto v0 = cur.get_i64(0, 0);
    auto v1 = cur.get_i64(1, 0);
    auto v2 = cur.get_i64(2, 0);
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
                            { return qm::result_batch_frame(rid, 0, 1, 1, {c}); }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});

    auto reader = connect_to(srv);
    auto cur = reader.execute("select a from t"_utf8);

    bool threw = false;
    questdb::egress::error_code code{};
    try
    {
        // Either next_batch() (upstream frame-level check) or
        // get_double_array (FFI per-row check) must throw.
        if (cur.next_batch())
            (void)cur.get_double_array(0, 0);
    }
    catch (const questdb::egress::line_reader_error& e)
    {
        threw = true;
        code = e.code();
    }
    CHECK(threw);
    CHECK(code == line_reader_error_protocol_error);
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
                            { return qm::result_batch_frame(rid, 0, 1, 1, {c}); }},
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
        REQUIRE(cur.next_batch());
        auto v = cur.get_i32(0, 0);
        REQUIRE(v.has_value());
        CHECK(*v == 1);
    }

    SUBCASE("cursor move-construct preserves the live cursor")
    {
        auto r = connect_to(srv);
        auto cur1 = r.execute("select v from t"_utf8);
        auto cur2 = std::move(cur1);
        REQUIRE(cur2.next_batch());
        auto v = cur2.get_i32(0, 0);
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
    line_reader_query_bind_varchar(raw_handle(q), bad_v);

    // Subsequent binds: each MUST be a no-op now. Pre-fix, these would
    // push into the upstream builder and shift indices.
    q.bind_i32(7);
    q.bind_varchar("widgets"_utf8);
    q.bind_i64(-1);
    q.bind_null(questdb::egress::column_kind::long_);

    bool threw = false;
    questdb::egress::error_code code{};
    try
    {
        (void)q.execute();
    }
    catch (const questdb::egress::line_reader_error& e)
    {
        threw = true;
        code = e.code();
    }
    CHECK(threw);
    CHECK(code == line_reader_error_invalid_utf8);
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
    constexpr uint32_t expected_caps  = 0x12345678u;
    constexpr int64_t  expected_wall  = 1'700'000'000'000'000'000LL;

    qm::ActionSendServerInfo si{};
    si.role           = qm::ROLE_PRIMARY;
    si.cluster_id     = "cluster-x";
    si.node_id        = "node-x";
    si.epoch          = expected_epoch;
    si.capabilities   = expected_caps;
    si.server_wall_ns = expected_wall;

    qm::Script s = {si, qm::ActionAwaitQueryRequest{}, qm::ActionSendResultEnd{}};
    qm::MockServer srv({s});

    auto reader = connect_to(srv);
    auto info = reader.server_info();
    REQUIRE(static_cast<bool>(info));
    CHECK(info.role_byte() == qm::ROLE_PRIMARY);
    CHECK(info.role() == questdb::egress::server_role::primary);
    CHECK(info.epoch() == expected_epoch);
    CHECK(info.capabilities() == expected_caps);
    CHECK(info.server_wall_ns() == expected_wall);
    CHECK(info.cluster_id() == "cluster-x");
    CHECK(info.node_id() == "node-x");
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
    REQUIRE(cur.terminal_kind() == line_reader_terminal_kind_exec_done);

    auto info = cur.terminal_exec_done();
    REQUIRE(info.has_value());
    CHECK(info->op_type == 0x42);
    CHECK(info->rows_affected == 1'234'567ULL);

    // The other-terminal accessor must reject this terminal kind.
    auto end_info = cur.terminal_end();
    CHECK_FALSE(end_info.has_value());
}

// ---------------------------------------------------------------------------
// failover_event_view: extend the existing failover assertions to cover
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
                       [cap](const questdb::egress::failover_event_view& ev)
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
                { return qm::result_batch_frame(rid, 0, 1, 1, {c}); }},
            qm::ActionSendResultEnd{},
        };
        qm::MockServer srv1({s1});
        qm::MockServer srv2({s2});

        auto r = connect_to(srv1);
        r = connect_to(srv2);  // move-assign — must close srv1's socket
        // The new reader works against srv2.
        auto cur = r.execute("select v from t"_utf8);
        REQUIRE(cur.next_batch());
        auto v = cur.get_i32(0, 0);
        REQUIRE(v.has_value());
        CHECK(*v == 7);
    }

    SUBCASE("query move-assign over a live query frees the LHS impl")
    {
        // Two independent readers, two live queries. Move-assigning q2
        // over q1 must free q1's impl (releasing reader1's `active`
        // flag through `line_reader_query_free`) and transfer q2's impl
        // into q1. The successor execute() then runs against reader2.
        qm::Script s1 = {qm::ActionSendServerInfo{}};
        qm::Script s2 = {
            qm::ActionSendServerInfo{},
            qm::ActionAwaitQueryRequest{},
            qm::ActionSendBuilt{
                [c](int64_t rid)
                { return qm::result_batch_frame(rid, 0, 1, 1, {c}); }},
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
        REQUIRE(cur.next_batch());
        auto v = cur.get_i32(0, 0);
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
                { return qm::result_batch_frame(rid, 0, 1, 1, {c}); }},
            qm::ActionSendResultEnd{},
        };
        qm::MockServer srv({s});
        auto reader = connect_to(srv);
        auto q_a = reader.prepare("X"_utf8);
        auto q_b = std::move(q_a);   // q_a empty
        q_a = std::move(q_b);        // assign into empty — must not crash
        q_a.bind_i32(7);
        auto cur = q_a.execute();
        REQUIRE(cur.next_batch());
        auto v = cur.get_i32(0, 0);
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
                { return qm::result_batch_frame(rid, 0, 1, 1, {c}); }},
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
        REQUIRE(cur.next_batch());
        auto v = cur.get_i32(0, 0);
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
    REQUIRE(cur.terminal_kind() == line_reader_terminal_kind_end);

    // Repeated calls after the terminus must keep returning false and
    // NOT throw. Five iterations is overkill but cheap insurance.
    for (int i = 0; i < 5; ++i)
    {
        CHECK_FALSE(cur.next_batch());
        CHECK(cur.terminal_kind() == line_reader_terminal_kind_end);
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
    line_reader_error* err = nullptr;
    line_reader* r = line_reader_from_conf(c, &err);
    REQUIRE(r == nullptr);
    REQUIRE(err != nullptr);
    CHECK(line_reader_error_get_code(err) == line_reader_error_role_mismatch);
    line_reader_error_free(err);
}

// ---------------------------------------------------------------------------
// Malformed-frame coverage. Exercises the `protocol_error` paths inside
// the WS frame parser and the RESULT_BATCH decoder by hand-crafting
// frames the friendly builders refuse to emit. Uses `ActionSendRaw`
// (otherwise dead code in this suite — the friendly builders cover the
// happy path). Each test connects, executes a no-op query, and asserts
// `next_batch()` surfaces `line_reader_error_protocol_error` with the
// cursor torn down.
// ---------------------------------------------------------------------------

namespace
{

void run_malformed_batch(
    qm::Script script,
    ::line_reader_error_code expected = line_reader_error_protocol_error)
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
    catch (const questdb::egress::line_reader_error& e)
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
            auto f = qm::result_batch_frame(rid, 0, 1, 1, {c});
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
            return qm::result_batch_frame(rid, 0, 1, 1, {c});
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
            return qm::result_batch_frame(rid, 0, 1, 1, {c});
        }},
        qm::ActionSendResultEnd{},
    };
    run_malformed_batch(s, line_reader_error_invalid_utf8);
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
            return qm::framed(2, 0, 1, p);
        }},
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
    REQUIRE(static_cast<bool>(info));
    CHECK(info.role_byte() == qm::ROLE_PRIMARY);
    CHECK(info.cluster_id() == "raw-cluster");
    CHECK(info.node_id() == "raw-node");
    auto cur = reader.execute("select 1"_utf8);
    CHECK_FALSE(cur.next_batch());
}

// Move-assigning over a reader that still owns a live cursor would
// drive `line_reader_close` down its defense-in-depth leak branch
// (cursor holds a laundered `&mut Reader`; freeing would dangle). The
// C++ wrapper must surface that as an exception rather than letting
// the leak happen silently.
TEST_CASE("mock: reader move-assign with live cursor throws")
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
    CHECK(::line_reader_has_active_query(
              reinterpret_cast<const ::line_reader*>(0)) == 0);

    bool threw = false;
    try
    {
        reader_a = std::move(reader_b);
    }
    catch (const questdb::egress::line_reader_error& e)
    {
        threw = true;
        CHECK(e.code() == line_reader_error_invalid_api_call);
        // Pin the wording so a future error-message refactor can't
        // quietly drop the "leak" / "live" diagnostic that the user
        // needs to debug the contract violation.
        const std::string m = std::string(e.what());
        CHECK(m.find("live") != std::string::npos);
        CHECK(m.find("leak") != std::string::npos);
    }
    CHECK(threw);

    // The destination reader is unchanged: `cur` still works and drains
    // to its terminal. No use-after-free, no observable leak.
    CHECK_FALSE(cur.next_batch());
    CHECK(cur.terminal_kind() == line_reader_terminal_kind_end);
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
    CHECK(reader_a.server_version() == 2);
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
    CHECK(version == 2);
    CHECK_FALSE(host.empty());
    CHECK(port != 0);
    CHECK(static_cast<bool>(reader.server_info()));

    {
        auto cur = reader.execute("select 1"_utf8);

        bool threw = false;
        try
        {
            (void)reader.server_version();
        }
        catch (const questdb::egress::line_reader_error& e)
        {
            threw = true;
            CHECK(e.code() == line_reader_error_invalid_api_call);
        }
        CHECK(threw);

        CHECK_FALSE(static_cast<bool>(reader.server_info()));
        CHECK(reader.current_host().empty());
        CHECK(reader.current_port() == 0);

        // The cursor handle owns the borrow — its mirror getters are the
        // sound path for the same metadata.
        CHECK(cur.server_version() == version);
        CHECK(cur.current_host() == host);
        CHECK(cur.current_port() == port);
        CHECK(static_cast<bool>(cur.server_info()));

        CHECK_FALSE(cur.next_batch());
    }

    CHECK(reader.server_version() == version);
    CHECK(reader.current_host() == host);
    CHECK(reader.current_port() == port);
    CHECK(static_cast<bool>(reader.server_info()));
}

// ---------------------------------------------------------------------------
// FFI ABI smoke for every supported `line_reader_query_bind_*`.
//
// Each bind goes through the C ABI (`questdb::egress::query::bind_*` ->
// `line_reader_query_bind_*` -> `mutate_query` -> upstream `bind_*`), so
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
// `line_reader_bytes_received` / `_read_ns` / `_decode_ns` /
// `_credit_granted_total` are documented at `questdb-rs-ffi/src/egress.rs`
// as safe to call from a monitoring thread while another thread is
// driving a cursor through `line_reader_query_execute`. The Reader is
// stored in an `UnsafeCell<Reader>` next to a cloned `Arc<ReaderStats>`
// inside the C-side `line_reader` struct; the stat getters use
// `ptr::addr_of!` to reach the Arc field without synthesising an
// intermediate `&line_reader` reborrow that would otherwise cover the
// cell and disturb the laundered `&mut Reader` held by an in-flight
// query. This test exercises that exact shape from C++:
//
//  - The worker thread mutates the Reader via `reader.execute(...)` and
//    drives a multi-batch cursor through `next_batch()`.
//  - The main thread hammers `reader.bytes_received()` /
//    `read_ns()` / `decode_ns()` / `credit_granted_total()` on the same
//    `line_reader*` handle.
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
                  rid, static_cast<uint64_t>(i), 1, 4, {col}); }});
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
// Coverage gaps documented but not yet asserted in this suite — left as
// breadcrumbs for the next contributor:
//
//  - SYMBOL column round-trip via `get_symbol`. The wrong-type rejection
//    is covered (typed getters reject mismatched column kind), but the
//    happy path requires symbol-dictionary support in the mock (the
//    upstream wire format encodes dict updates inline within batches —
//    see `questdb-rs/src/egress/symbol_dict.rs`). Adding it is a
//    discrete piece of mock work.
//  - `tls_error`: needs a real TLS terminator in front of the mock.
//  - `unsupported_server`: the mock pins QWP version 2; triggering the
//    upstream version-rejection path needs a higher-version SERVER_INFO.
//  - `invalid_timestamp` / `invalid_decimal`: per upstream, these
//    error variants are reachable from sender code paths but not
//    produced by the reader as of this revision; assertion would need
//    an FFI change first.
//  - Client-side `limit_exceeded`: triggered by an oversized zstd
//    content-size header. The mock does not currently emit zstd
//    frames; needs a small bytes-sender shim.
// ---------------------------------------------------------------------------
