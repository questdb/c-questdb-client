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

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "qwp_mock_server.hpp"

#include <questdb/ingress/column_sender.h>
#include <questdb/ingress/column_sender.hpp>
#include <questdb/ingress/line_sender.hpp>

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace qdb = questdb::ingress;
namespace qm = qwp_mock;

namespace
{

std::unique_ptr<qm::MockServer> spawn_mock(int slot_count)
{
    qm::Script accept_one_frame = {qm::ActionAwaitClientFrame{0x51}};
    std::vector<qm::Script> scripts(static_cast<size_t>(slot_count), accept_one_frame);
    return std::make_unique<qm::MockServer>(std::move(scripts));
}

std::unique_ptr<qm::MockServer> spawn_acking_mock(int slot_count)
{
    qm::Script ack_one_frame = {
        qm::ActionAwaitClientFrame{0x51},
        qm::ActionSendRaw{qm::ingress_ok_frame()}};
    std::vector<qm::Script> scripts(static_cast<size_t>(slot_count), ack_one_frame);
    return std::make_unique<qm::MockServer>(std::move(scripts));
}

std::string conf_for(const std::string& addr, const std::string& extras = {})
{
    return "qwpws::addr=" + addr + ";pool_size=1;pool_reap=manual;" + extras;
}

} // namespace

TEST_CASE("column_chunk is move-constructible and move-assignable")
{
    qdb::column_chunk a{"trades"};
    REQUIRE(a.c_ptr() != nullptr);

    qdb::column_chunk b{std::move(a)};
    CHECK(a.c_ptr() == nullptr);
    CHECK(b.c_ptr() != nullptr);

    qdb::column_chunk c{"other"};
    c = std::move(b);
    CHECK(b.c_ptr() == nullptr);
    CHECK(c.c_ptr() != nullptr);
}

TEST_CASE("column_chunk row_count starts at 0 and is_empty after clear")
{
    qdb::column_chunk chunk{"t"};
    CHECK(chunk.row_count() == 0);
    int64_t data[] = {1, 2, 3};
    chunk.column_i64("v", data, 3);
    CHECK(chunk.row_count() == 3);
    chunk.clear();
    CHECK(chunk.row_count() == 0);
}

TEST_CASE("column_chunk fluent chaining returns the same chunk")
{
    qdb::column_chunk chunk{"t"};
    int64_t v[] = {1, 2, 3};
    double f[] = {1.5, 2.5, 3.5};
    int64_t ts[] = {1, 2, 3};
    auto& ref = chunk.column_i64("v", v, 3)
                     .column_f64("f", f, 3)
                     .at_nanos(ts, 3);
    CHECK(&ref == &chunk);
    CHECK(chunk.row_count() == 3);
}

TEST_CASE("pool construction throws on invalid connect string")
{
    CHECK_THROWS_AS(questdb::pool{"http::not-a-qwp-string;"}, qdb::line_sender_error);
}

TEST_CASE("borrowed_column_sender returns conn to pool on destructor")
{
    auto mock = spawn_mock(1);
    questdb::pool db{conf_for(mock->addr())};

    {
        auto conn = db.borrow_column_sender();
        CHECK(static_cast<bool>(conn));
        // The background runner opens one connection; wait for it to land.
        REQUIRE(mock->wait_for_accepts(1));
    }
    // Drop returns the sender to the pool (recycled, not dropped).
    {
        auto conn = db.borrow_column_sender();
        CHECK(static_cast<bool>(conn));
    }
    // The re-borrow reused the recycled connection: the mock only ever
    // accepted one connection, never a second.
    CHECK(mock->accepts() == 1);
}

TEST_CASE("borrowed_column_sender move transfers ownership without double-return")
{
    auto mock = spawn_mock(1);
    questdb::pool db{conf_for(mock->addr())};
    auto a = db.borrow_column_sender();
    REQUIRE(static_cast<bool>(a));

    auto b = std::move(a);
    CHECK_FALSE(static_cast<bool>(a));
    CHECK(static_cast<bool>(b));
}

TEST_CASE("column_chunk flush round-trips through the mock")
{
    auto mock = spawn_mock(1);
    questdb::pool db{conf_for(mock->addr())};
    auto conn = db.borrow_column_sender();

    qdb::column_chunk chunk{"trades"};
    int64_t qty[] = {10, 20, 30};
    int64_t ts[] = {1'700'000'000'000'000'000LL,
                    1'700'000'000'000'000'001LL,
                    1'700'000'000'000'000'002LL};
    chunk.column_i64("qty", qty, 3)
         .at_nanos(ts, 3);

    CHECK_FALSE(conn.published_fsn().has_value());
    CHECK_FALSE(conn.acked_fsn().has_value());

    const auto fsn = conn.flush_and_get_fsn(chunk);
    REQUIRE(fsn.has_value());
    CHECK(chunk.row_count() == 0);
    CHECK(conn.published_fsn() == fsn);
    CHECK_FALSE(conn.acked_fsn().has_value());

    // The mock graceful-closes after one frame, so sync() would hang.
    conn.drop_on_return();
}

TEST_CASE("column_chunk flush_and_wait round-trips through the mock")
{
    auto mock = spawn_acking_mock(1);
    questdb::pool db{conf_for(mock->addr())};
    auto conn = db.borrow_column_sender();

    qdb::column_chunk chunk{"trades"};
    int64_t qty[] = {10, 20, 30};
    int64_t ts[] = {1'700'000'000'000'000'000LL,
                    1'700'000'000'000'000'001LL,
                    1'700'000'000'000'000'002LL};
    chunk.column_i64("qty", qty, 3)
         .at_nanos(ts, 3);

    conn.flush_and_wait(chunk);
    CHECK(chunk.row_count() == 0);
    conn.drop_on_return();
}

TEST_CASE("borrowed_row_sender exposes QWP/WS buffer and FSN helpers")
{
    // Regression guard: a pooled row sender must be able to construct the
    // QWP/WS columnar buffer it requires (`row_sender_new_buffer`). Before
    // this was wired, C/C++ callers had no way to build a buffer that
    // `row_sender_flush` would accept.
    auto mock = spawn_mock(1);
    questdb::pool db{conf_for(mock->addr())};
    auto rs = db.borrow_row_sender();
    CHECK(rs);

    auto empty = rs.new_buffer();
    CHECK_FALSE(rs.published_fsn().has_value());
    CHECK_FALSE(rs.acked_fsn().has_value());
    CHECK_FALSE(rs.flush_and_keep_and_get_fsn(empty).has_value());

    auto buf = rs.new_buffer();
    buf.table("trades")
        .symbol("sym", "ETH-USD")
        .column("price", 2615.54)
        .at(qdb::timestamp_nanos::now());
    const auto fsn = rs.flush_and_get_fsn(buf);
    REQUIRE(fsn.has_value());
    CHECK(rs.published_fsn() == fsn);

    // The mock graceful-closes after one frame, so wait() would hang.
    rs.drop_on_return();
}

TEST_CASE("borrowed_row_sender flush_and_wait round-trips through the mock")
{
    auto mock = spawn_acking_mock(1);
    questdb::pool db{conf_for(mock->addr())};
    auto rs = db.borrow_row_sender();

    auto buf = rs.new_buffer();
    buf.table("trades")
        .symbol("sym", "ETH-USD")
        .column("price", 2615.54)
        .at(qdb::timestamp_nanos::now());
    rs.flush_and_wait(buf);
    const auto published = rs.published_fsn();
    REQUIRE(published.has_value());
    const auto acked = rs.acked_fsn();
    REQUIRE(acked.has_value());
    CHECK(*acked >= *published);
    rs.drop_on_return();
}

TEST_CASE("row_sender_flush_and_wait: NULL buffer -> invalid_api_call")
{
    // Raw C-ABI guard: a NULL buffer must report invalid_api_call, not
    // dereference the pointer.
    auto mock = spawn_mock(1);
    const std::string conf = conf_for(mock->addr());
    line_sender_error* err = nullptr;
    questdb_db* db = questdb_db_connect(conf.c_str(), conf.size(), &err);
    REQUIRE(db != nullptr);
    REQUIRE(err == nullptr);
    row_sender* rs = questdb_db_borrow_row_sender(db, &err);
    REQUIRE(rs != nullptr);
    REQUIRE(err == nullptr);

    const bool ok =
        row_sender_flush_and_wait(rs, nullptr, qwpws_ack_level_ok, &err);
    CHECK_FALSE(ok);
    REQUIRE(err != nullptr);
    CHECK(
        line_sender_error_get_code(err) ==
        line_sender_error_invalid_api_call);
    line_sender_error_free(err);

    questdb_db_drop_row_sender(db, rs);
    questdb_db_close(db);
}

TEST_CASE("borrowed_row_sender::new_buffer preserves max_name_len on lazy reinit")
{
    // A buffer minted from a row sender configured with `max_name_len=16`
    // must, after a move nulls its impl, lazily re-init with that same cap —
    // not the default 127. The cap check is `name.len() > max_name_len`, so
    // the boundary is exact: 16 chars is accepted, 17 rejected. Pinning both
    // sides proves the sender's cap (not the 127 default) was carried over.
    // Each case needs a fresh buffer: a second `table()` on a buffer that
    // already accepted one would fail with a *state* error, masking the cap.
    auto mock = spawn_mock(1);
    questdb::pool db{conf_for(mock->addr(), "max_name_len=16;")};
    auto rs = db.borrow_row_sender();

    {
        // 17 chars: rejected by the cap-16 re-init (pins cap <= 16).
        auto buf = rs.new_buffer();
        auto moved = std::move(buf); // nulls buf._impl; table() triggers may_init
        CHECK(moved.row_count() == 0);
        try
        {
            buf.table("table_name_len_17");
            FAIL("17-char name must exceed the cap-16 re-init");
        }
        catch (const qdb::line_sender_error& e)
        {
            CHECK(e.code() == qdb::line_sender_error_code::invalid_name);
        }
    }

    {
        // 16 chars: accepted (pins cap >= 16).
        auto buf = rs.new_buffer();
        auto moved = std::move(buf);
        CHECK_NOTHROW(buf.table("table_name_len16"));
    }

    rs.drop_on_return();
}

TEST_CASE("borrowed_row_sender::wait rejects a negative timeout")
{
    // The negative-timeout guard throws before any FFI call, so it is safe to
    // exercise against the one-shot mock: nothing is published, so there is no
    // ack to wait for and no hang risk.
    auto mock = spawn_mock(1);
    questdb::pool db{conf_for(mock->addr())};
    auto rs = db.borrow_row_sender();

    CHECK_THROWS_AS(
        rs.wait(qdb::qwpws_ack_level::ok, std::chrono::milliseconds{-1}),
        qdb::line_sender_error);

    rs.drop_on_return();
}

TEST_CASE("borrowed_row_sender::wait rejects durable ACK without opt-in")
{
    auto mock = spawn_mock(1);
    questdb::pool db{conf_for(mock->addr())};
    auto rs = db.borrow_row_sender();

    try
    {
        rs.wait(qdb::qwpws_ack_level::durable);
        FAIL("durable without opt-in must throw");
    }
    catch (const qdb::line_sender_error& e)
    {
        CHECK(e.code() == qdb::line_sender_error_code::invalid_api_call);
        CHECK(std::string{e.what()}.find("request_durable_ack=on") !=
              std::string::npos);
    }

    rs.drop_on_return();
}

TEST_CASE("flush rejects oversized table name")
{
    auto mock = spawn_mock(1);
    questdb::pool db{conf_for(mock->addr())};
    auto conn = db.borrow_column_sender();

    std::string oversized(200, 'x');
    qdb::column_chunk chunk{oversized};
    int64_t v[] = {1};
    int64_t t[] = {1};
    chunk.column_i64("v", v, 1).at_nanos(t, 1);

    CHECK_THROWS_AS(conn.flush(chunk), qdb::line_sender_error);
    CHECK(chunk.row_count() == 1);
    conn.drop_on_return();
}

TEST_CASE("wait rejects durable ACK without opt-in and keeps the chunk")
{
    auto mock = spawn_mock(1);
    questdb::pool db{conf_for(mock->addr())};
    auto conn = db.borrow_column_sender();

    qdb::column_chunk chunk{"trades"};
    int64_t qty[] = {10};
    int64_t ts[] = {1'700'000'000'000'000'000LL};
    chunk.column_i64("qty", qty, 1).at_nanos(ts, 1);

    // Durable is validated by `wait` (the ack barrier); with no `flush` no
    // frame is published, so the chunk is left intact and the exception
    // preserves the underlying `invalid_api_call` code.
    try
    {
        conn.wait(qdb::qwpws_ack_level::durable);
        FAIL("durable without opt-in must throw");
    }
    catch (const qdb::line_sender_error& e)
    {
        CHECK(e.code() == qdb::line_sender_error_code::invalid_api_call);
    }
    CHECK(chunk.row_count() == 1);
    conn.drop_on_return();
}

TEST_CASE("drop_on_return drops the conn instead of recycling it")
{
    auto mock = spawn_mock(2);
    questdb::pool db{conf_for(mock->addr())};

    {
        auto conn = db.borrow_column_sender();
        REQUIRE(mock->wait_for_accepts(1)); // first borrow opens conn #1
        conn.drop_on_return();              // force drop instead of recycle
    }
    {
        auto conn = db.borrow_column_sender();
        CHECK(static_cast<bool>(conn));
        // The slot was dropped (not recycled), so the re-borrow must open a
        // fresh conn #2 rather than reuse the first.
        REQUIRE(mock->wait_for_accepts(2));
    }
    CHECK(mock->accepts() == 2);
}

TEST_CASE("pool is move-constructible and move-assignable")
{
    auto mock = spawn_mock(1);
    questdb::pool a{conf_for(mock->addr())};
    REQUIRE(a.c_ptr() != nullptr);

    questdb::pool b{std::move(a)};
    CHECK(a.c_ptr() == nullptr);
    CHECK(b.c_ptr() != nullptr);
}

TEST_CASE("pool reap_idle is callable")
{
    auto mock = spawn_mock(2);
    questdb::pool db{conf_for(mock->addr(), "pool_idle_timeout_ms=1;")};
    {
        auto conn = db.borrow_column_sender();
        (void)conn;
    }
    [[maybe_unused]] size_t closed = db.reap_idle();
}
