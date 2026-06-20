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

#include <cstdint>
#include <memory>
#include <string>
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
                     .designated_timestamp_nanos(ts, 3);
    CHECK(&ref == &chunk);
    CHECK(chunk.row_count() == 3);
}

TEST_CASE("pool construction throws on invalid connect string")
{
    CHECK_THROWS_AS(questdb::pool{"http::not-a-qwp-string;"}, qdb::line_sender_error);
}

TEST_CASE("borrowed_conn returns conn to pool on destructor")
{
    auto mock = spawn_mock(1);
    questdb::pool db{conf_for(mock->addr())};

    {
        auto conn = db.borrow_column_sender();
        CHECK(conn->c_ptr() != nullptr);
        CHECK_FALSE(conn->must_close());
    }
    int accepts_before = mock->accepts();
    {
        auto conn = db.borrow_column_sender();
        CHECK(conn->c_ptr() != nullptr);
    }
    CHECK(mock->accepts() == accepts_before);
}

TEST_CASE("borrowed_conn move transfers ownership without double-return")
{
    auto mock = spawn_mock(1);
    questdb::pool db{conf_for(mock->addr())};
    auto a = db.borrow_column_sender();
    ::qwpws_conn* raw = a->c_ptr();
    REQUIRE(raw != nullptr);

    auto b = std::move(a);
    CHECK(b->c_ptr() == raw);
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
         .designated_timestamp_nanos(ts, 3);

    conn->flush(chunk);
    CHECK(chunk.row_count() == 0);

    // The mock graceful-closes after one frame, so sync() would hang.
    conn.drop_on_return();
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
    chunk.column_i64("v", v, 1).designated_timestamp_nanos(t, 1);

    CHECK_THROWS_AS(conn->flush(chunk), qdb::line_sender_error);
    CHECK(chunk.row_count() == 1);
    conn.drop_on_return();
}

TEST_CASE("drop_on_return drops the conn instead of recycling it")
{
    auto mock = spawn_mock(2);
    questdb::pool db{conf_for(mock->addr())};

    int accepts_before;
    {
        auto conn = db.borrow_column_sender();
        accepts_before = mock->accepts();
        conn.drop_on_return();
    }
    {
        auto conn = db.borrow_column_sender();
        CHECK(conn->c_ptr() != nullptr);
    }
    CHECK(mock->accepts() == accepts_before + 1);
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
