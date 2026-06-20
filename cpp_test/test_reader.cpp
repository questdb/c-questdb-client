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

// Live-broker integration tests for the egress reader FFI layer.
//
// Mirrors a subset of the upstream Rust `tests/egress_live_server.rs` at
// the C/C++ wrapper boundary. Exercises the round-trip path
// `_query_new` → `_query_bind_*` → `_query_execute` → `_cursor_next_batch`
// → `batch::column().get<T>()` plus the C++ wrapper's `nullable<T>`
// translation, the single-cursor invariant, and `bind_decimal128`'s
// i64-high-limb sign extension.
//
// These tests need a running QuestDB. Configure the broker via:
//   QDB_LIVE_BROKER_HOST       (default: localhost)
//   QDB_LIVE_BROKER_HTTP_PORT  (default: 9000)
// If the broker is not reachable, each TEST_CASE prints SKIP and returns
// without failing — so this binary is safe to wire into ctest even in
// environments without a broker.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <questdb/egress/reader.hpp>
#include <questdb/ingress/line_sender.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <sstream>
#include <string>
#include <thread>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#else
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

using namespace questdb::ingress::literals;

namespace
{

// MSVC flags `std::getenv` as deprecated (C4996) in favour of `_dupenv_s`,
// but the function is standard C/C++ and the test's usage is single-threaded.
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
inline const char* env_or_null(const char* name)
{
    return std::getenv(name);
}
#ifdef _MSC_VER
#pragma warning(pop)
#endif

std::string broker_host()
{
    if (const char* h = env_or_null("QDB_LIVE_BROKER_HOST"))
        return std::string{h};
    return "localhost";
}

uint16_t broker_http_port()
{
    if (const char* p = env_or_null("QDB_LIVE_BROKER_HTTP_PORT"))
        return static_cast<uint16_t>(std::atoi(p));
    return 9000;
}

// Probe a TCP connect to the broker's HTTP port. Returns true if the
// connect handshake completes within ~500ms.
bool broker_reachable()
{
    const std::string host = broker_host();
    const uint16_t port = broker_http_port();

#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return false;
#endif

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    const std::string port_s = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_s.c_str(), &hints, &res) != 0)
    {
#ifdef _WIN32
        WSACleanup();
#endif
        return false;
    }

    bool ok = false;
    for (addrinfo* p = res; p != nullptr; p = p->ai_next)
    {
        int fd = static_cast<int>(::socket(p->ai_family, p->ai_socktype, p->ai_protocol));
        if (fd < 0) continue;
        // Best-effort short timeout. On non-blocking it'd be nicer; but
        // a 500ms blocking connect attempt is fine for a one-time gate.
#ifdef _WIN32
        DWORD timeout_ms = 500;
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO,
                   reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
#else
        timeval tv{};
        tv.tv_sec = 0;
        tv.tv_usec = 500 * 1000;
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
        if (::connect(fd, p->ai_addr, static_cast<int>(p->ai_addrlen)) == 0)
        {
            ok = true;
        }
#ifdef _WIN32
        closesocket(fd);
#else
        ::close(fd);
#endif
        if (ok) break;
    }
    freeaddrinfo(res);
#ifdef _WIN32
    WSACleanup();
#endif
    return ok;
}

// Skip the current TEST_CASE if no broker is reachable. Use as the very
// first line of every test body.
#define REQUIRE_LIVE_BROKER()                                                  \
    do                                                                         \
    {                                                                          \
        if (!broker_reachable())                                               \
        {                                                                      \
            MESSAGE(                                                           \
                "SKIP: no QuestDB broker at "                                  \
                << broker_host() << ":" << broker_http_port()                  \
                << " (set QDB_LIVE_BROKER_HOST / "                             \
                   "QDB_LIVE_BROKER_HTTP_PORT to override)");                  \
            return;                                                            \
        }                                                                      \
    } while (0)

std::string reader_conf()
{
    std::ostringstream s;
    s << "ws::addr=" << broker_host() << ":" << broker_http_port() << ";";
    return s.str();
}

questdb::egress::reader make_reader()
{
    const std::string c = reader_conf();
    questdb::ingress::utf8_view view{c};
    return questdb::egress::reader{view};
}

// Append a unique suffix so parallel/repeated runs don't collide.
std::string unique_table(const std::string& stem)
{
    static std::atomic<uint64_t> counter{0};
    const auto nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();
    std::ostringstream s;
    s << "egress_" << stem << "_"
#ifdef _WIN32
      << GetCurrentProcessId()
#else
      << ::getpid()
#endif
      << "_" << (static_cast<uint64_t>(nanos) & 0xFFFFFFFFu) << "_"
      << counter.fetch_add(1, std::memory_order_relaxed);
    return s.str();
}

} // namespace

// ---------------------------------------------------------------------------
// Smoke / dispatch
// ---------------------------------------------------------------------------

TEST_CASE("smoke: select 1::long as v")
{
    REQUIRE_LIVE_BROKER();

    auto reader = make_reader();
    // Cast explicitly so the column kind is server-version-independent.
    auto cur = reader.execute("select 1::long as v"_utf8);

    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
    CHECK(batch.row_count() == 1);
    CHECK(batch.column_count() == 1);
    REQUIRE(batch.column_kind(0) == reader_column_kind_long);
    const auto v = batch.column(0).get<int64_t>(0);
    REQUIRE(v.has_value());
    CHECK(*v == 1);

    CHECK_FALSE(cur.next_batch()); // stream terminates
}

TEST_CASE("multi-row literal: long_sequence(5)")
{
    REQUIRE_LIVE_BROKER();

    auto reader = make_reader();
    auto cur = reader.execute(
        "select x as n from long_sequence(5)"_utf8);

    size_t total_rows = 0;
    int64_t expected = 1;
    while (auto bo = cur.next_batch())
    {
        auto& batch = *bo;
        const size_t rows = batch.row_count();
        REQUIRE(batch.column_count() == 1);
        REQUIRE(batch.column_kind(0) == reader_column_kind_long);
        for (size_t r = 0; r < rows; ++r)
        {
            const auto v = batch.column(0).get<int64_t>(r);
            REQUIRE(v.has_value());
            CHECK(*v == expected);
            ++expected;
        }
        total_rows += rows;
    }
    CHECK(total_rows == 5);
}

TEST_CASE("multi-column type dispatch: long + double")
{
    REQUIRE_LIVE_BROKER();

    auto reader = make_reader();
    auto cur = reader.execute(
        "select x as n, x * 1.5 as d from long_sequence(3)"_utf8);

    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
    REQUIRE(batch.row_count() == 3);
    REQUIRE(batch.column_count() == 2);
    REQUIRE(batch.column_kind(0) == reader_column_kind_long);
    REQUIRE(batch.column_kind(1) == reader_column_kind_double);

    for (size_t r = 0; r < 3; ++r)
    {
        const auto n = batch.column(0).get<int64_t>(r);
        const auto d = batch.column(1).get<double>(r);
        REQUIRE(n.has_value());
        REQUIRE(d.has_value());
        CHECK(*n == static_cast<int64_t>(r + 1));
        CHECK(*d == doctest::Approx(static_cast<double>(r + 1) * 1.5));
    }
}

// ---------------------------------------------------------------------------
// Bind parameters
// ---------------------------------------------------------------------------

TEST_CASE("bind: i32 + varchar")
{
    REQUIRE_LIVE_BROKER();

    auto reader = make_reader();
    // Cast the result to LONG so the column kind is server-version-
    // independent (otherwise the server may surface int*long as INT or
    // LONG depending on its widening rules).
    auto cur =
        reader
            .prepare("select ($1::int * x)::long as scaled, "
                     "$2 as label from long_sequence(3)"_utf8)
            .bind_i32(7)
            .bind_varchar("widgets"_utf8)
            .execute();

    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
    REQUIRE(batch.row_count() == 3);
    REQUIRE(batch.column_count() == 2);
    REQUIRE(batch.column_kind(0) == reader_column_kind_long);
    REQUIRE(batch.column_kind(1) == reader_column_kind_varchar);

    for (size_t r = 0; r < 3; ++r)
    {
        const int64_t expected_scaled = 7 * static_cast<int64_t>(r + 1);
        const auto v = batch.column(0).get<int64_t>(r);
        REQUIRE(v.has_value());
        CHECK(*v == expected_scaled);
        const auto label = batch.column(1).varchar(r);
        REQUIRE(label.has_value());
        CHECK(*label == "widgets");
    }
}

TEST_CASE("bind: f64 round-trip")
{
    REQUIRE_LIVE_BROKER();

    auto reader = make_reader();
    auto cur = reader.prepare("select $1::double as v"_utf8)
                   .bind_f64(3.14159)
                   .execute();

    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
    REQUIRE(batch.row_count() == 1);
    REQUIRE(batch.column_kind(0) == reader_column_kind_double);
    const auto v = batch.column(0).get<double>(0);
    REQUIRE(v.has_value());
    CHECK(*v == doctest::Approx(3.14159));
}

TEST_CASE("column_validity: bitmap matches null pattern, empty when no nulls")
{
    REQUIRE_LIVE_BROKER();

    auto reader = make_reader();

    // 5-row column with a deterministic null pattern (rows with even x are
    // NULL, odd x carry the value): rows 0/2/4 non-null, rows 1/3 null.
    // The validity bitmap is LSB-first with bit 1 == null, so byte 0
    // should encode 0b00001010 = 0x0A; bits 5..7 are padding.
    //
    // `cur` is scoped so it's destructed (releasing the reader's
    // single-cursor lock) before the second `reader.execute` below.
    {
        auto cur = reader.execute(
            "select case when x % 2 = 0 then cast(null as long) else x end as "
            "v "
            "from long_sequence(5)"_utf8);
        auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
        REQUIRE(batch.row_count() == 5);
        REQUIRE(batch.column_count() == 1);
        REQUIRE(batch.column_kind(0) == reader_column_kind_long);

        const auto col0 = batch.column(0);
        const uint8_t* vbits = col0.validity();
        REQUIRE(vbits != nullptr);
        REQUIRE(col0.validity_bytes() >= 1);
        // Mask off padding bits 5..7; only the lower 5 bits encode rows 0..4.
        CHECK((vbits[0] & 0x1F) == 0x0A);

        // Cross-check: per-row getter agrees with the bitmap.
        for (size_t r = 0; r < 5; ++r)
        {
            const bool expect_null = ((r % 2) == 1);
            const auto v = batch.column(0).get<int64_t>(r);
            if (expect_null)
                CHECK_FALSE(v.has_value());
            else
                CHECK(v.has_value());
        }
        while (cur.next_batch())
        {
        } // drain
    }

    // No-nulls case: every row is non-null, so the validity pointer is null.
    auto cur2 =
        reader.execute("select x from long_sequence(3)"_utf8);
    auto bo2 = cur2.next_batch();
    REQUIRE(bo2);
    REQUIRE(bo2->row_count() == 3);
    auto col0 = bo2->column(0);
    CHECK_FALSE(col0.has_nulls());
    CHECK(col0.validity() == nullptr);
    CHECK(col0.validity_bytes() == 0);
}

TEST_CASE("bind: typed null")
{
    REQUIRE_LIVE_BROKER();

    auto reader = make_reader();
    auto cur = reader.prepare("select $1::long as v"_utf8)
                   .bind_null(questdb::egress::column_kind::long_)
                   .execute();

    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
    REQUIRE(batch.row_count() == 1);
    const auto v = batch.column(0).get<int64_t>(0);
    CHECK_FALSE(v.has_value()); // null cell -> nullopt
}

TEST_CASE("bind: decimal128 sign-extension round-trip")
{
    REQUIRE_LIVE_BROKER();

    // Verifies the FFI's i64-high-limb sign extension by round-tripping
    // i128 = -1 (low = UINT64_MAX, high = -1) through a `$1::decimal(...)`
    // cast. Requires a QuestDB version with DECIMAL128 cast support — if
    // the server rejects the cast, this test fails (rather than skipping
    // silently, which would mask a real bind regression).
    auto reader = make_reader();
    auto cur = reader.prepare("select $1::decimal(38, 0) as v"_utf8)
                   .bind_decimal128(
                       static_cast<uint64_t>(-1LL),
                       -1,
                       0)
                   .execute();
    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
    REQUIRE(batch.row_count() == 1);
    REQUIRE(batch.column_kind(0) == reader_column_kind_decimal128);
    const auto d = batch.column(0).get_decimal128(0);
    REQUIRE(d.has_value());
    CHECK(d->low == static_cast<uint64_t>(-1LL));
    CHECK(d->high == -1);
    CHECK(d->scale == 0);
}

// ---------------------------------------------------------------------------
// Cursor lifecycle and invariants
// ---------------------------------------------------------------------------

TEST_CASE("single-cursor invariant: second query rejected")
{
    REQUIRE_LIVE_BROKER();

    auto reader = make_reader();
    [[maybe_unused]] auto cur1 =
        reader.execute("select x from long_sequence(2)"_utf8);

    // Now try to start a second query while cur1 is still alive.
    bool threw = false;
    try
    {
        // Discard the result; we only care that this throws.
        (void)reader.execute("select x from long_sequence(1)"_utf8);
    }
    catch (const questdb::egress::reader_error& e)
    {
        threw = true;
        CHECK(e.code() == reader_error_invalid_api_call);
    }
    CHECK(threw);
    // cur1 closes at scope exit; the next test verifies a follow-up cursor
    // succeeds against the same reader.
}

TEST_CASE("cursor reusable after explicit close")
{
    REQUIRE_LIVE_BROKER();

    auto reader = make_reader();
    {
        auto cur = reader.execute("select 1 as v"_utf8);
        while (cur.next_batch()) {}
    } // cur dtor closes
    // The reader's active flag should be cleared; a second cursor opens
    // without throwing.
    auto cur2 = reader.execute("select 2 as v"_utf8);
    auto bo2 = cur2.next_batch();
    REQUIRE(bo2);
    CHECK(bo2->row_count() == 1);
}

TEST_CASE("query_new + bind without execute releases the reader")
{
    REQUIRE_LIVE_BROKER();

    auto reader = make_reader();
    {
        auto q = reader.prepare("select 1"_utf8);
        q.bind_i32(42); // never executed; q's dtor frees the query.
    }
    // Reader is unencumbered; another query should work.
    auto cur = reader.execute("select 1 as v"_utf8);
    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
    CHECK(batch.row_count() == 1);
}

// ---------------------------------------------------------------------------
// Introspection
// ---------------------------------------------------------------------------

TEST_CASE("cursor introspection: request_id, batch_seq, server info")
{
    REQUIRE_LIVE_BROKER();

    auto reader = make_reader();

    // Captured before a cursor borrows the reader: the metadata getters
    // reject while a query/cursor is live.
    const uint8_t reader_version = reader.server_version();
    const std::string reader_host{reader.current_host()};
    const uint16_t reader_port = reader.current_port();
    CHECK(reader_version >= 1);
    CHECK_FALSE(reader_host.empty());

    auto cur = reader.execute("select x from long_sequence(2)"_utf8);

    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;

    // Cursor's request_id is allocated at execute() and is non-zero.
    // The first batch's request_id MUST equal the cursor's request_id.
    const int64_t rid = cur.request_id();
    CHECK(rid != 0);
    CHECK(batch.request_id() == rid);
    // First batch on a fresh cursor has batch_seq == 0; subsequent
    // batches monotonically increment.
    CHECK(batch.seq() == 0);

    // Cursor's view of the connected endpoint mirrors the reader's
    // (single endpoint, no failover involved on this happy path).
    CHECK(cur.current_host() == reader_host);
    CHECK(cur.current_port() == reader_port);
    CHECK(cur.failover_resets() == 0);
}

TEST_CASE("terminal_kind reaches end after stream completes")
{
    REQUIRE_LIVE_BROKER();

    auto reader = make_reader();
    auto cur = reader.execute("select x from long_sequence(2)"_utf8);
    while (cur.next_batch()) {}
    // SELECT streams terminate with `end` carrying total_rows; `exec_done`
    // is the terminator for non-result statements (DDL/DML), so a SELECT
    // here must always land on `end`.
    REQUIRE(cur.terminal_kind() == reader_terminal_kind_end);
    const auto info = cur.terminal_end();
    REQUIRE(info.has_value());
    CHECK(info->total_rows == 2);
}

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

TEST_CASE("invalid SQL surfaces a server error")
{
    REQUIRE_LIVE_BROKER();

    auto reader = make_reader();
    bool threw = false;
    questdb::egress::error_code code{};
    std::string msg;
    try
    {
        // `reader.execute` sends the QUERY_REQUEST and returns
        // immediately — QWP egress is asynchronous, so the server's
        // QUERY_ERROR (the parse failure) is delivered on the response
        // stream and only surfaces on the first `next_batch()`.
        // Discarding the cursor without consuming the response would
        // miss the error entirely.
        auto cur = reader.execute("syntactically invalid !!!"_utf8);
        cur.next_batch();
    }
    catch (const questdb::egress::reader_error& e)
    {
        threw = true;
        code = e.code();
        msg = e.what();
    }
    REQUIRE(threw);
    CHECK(msg.size() > 0);
    // Pin the error class. The server reports a parse error for SQL it
    // can't tokenize (`STATUS_PARSE_ERROR`), so the FFI must surface
    // `server_parse_error`. Some QuestDB versions classify certain bad
    // queries as `server_internal_error` instead; both are acceptable
    // server-side-failure codes for this input. A regression to
    // (e.g.) `socket_error`, `cancelled`, or any client-side code
    // would fail this check loudly instead of being masked by an
    // any-message-is-fine assertion.
    CHECK((code == reader_error_server_parse_error
        || code == reader_error_server_internal_error));
}

TEST_CASE("get_i64 type-mismatch on string column is reported, not a crash")
{
    REQUIRE_LIVE_BROKER();

    auto reader = make_reader();
    auto cur = reader.execute("select 'hello' as s"_utf8);
    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
    REQUIRE(batch.column_count() == 1);
    bool threw = false;
    try
    {
        (void)batch.column(0).get<int64_t>(0);
    }
    catch (const questdb::egress::reader_error& e)
    {
        threw = true;
        CHECK(e.code() == reader_error_invalid_api_call);
    }
    CHECK(threw);
}

// ---------------------------------------------------------------------------
// Ingress → egress round-trip (only runs if a broker is reachable)
// ---------------------------------------------------------------------------

TEST_CASE("ingress sender → egress reader round-trip for primitives")
{
    REQUIRE_LIVE_BROKER();

    const std::string table = unique_table("primitives");

    // Seed via the ingress sender (auto-CREATE TABLE).
    {
        std::ostringstream conf_s;
        conf_s << "http::addr=" << broker_host() << ":" << broker_http_port()
               << ";protocol_version=2;";
        const std::string conf = conf_s.str();
        auto sender = questdb::ingress::line_sender::from_conf(
            questdb::ingress::utf8_view{conf});
        auto buf = sender.new_buffer();
        const questdb::ingress::table_name_view tname{table};
        const questdb::ingress::column_name_view cn_l{"l"};
        const questdb::ingress::column_name_view cn_d{"d"};
        const questdb::ingress::column_name_view cn_b{"b"};
        for (int64_t i = 0; i < 3; ++i)
        {
            buf.table(tname)
                .column(cn_l, static_cast<int64_t>(100 + i))
                .column(cn_d, 1.5 * static_cast<double>(i))
                .column(cn_b, (i % 2) == 0)
                .at(questdb::ingress::timestamp_nanos{
                    1700000000000000000LL + i * 1000000LL});
        }
        sender.flush(buf);
    }

    // Wait until the table is queryable and has 3 rows.
    auto reader = make_reader();
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(15);
    bool ready = false;
    while (std::chrono::steady_clock::now() < deadline)
    {
        try
        {
            std::ostringstream sql_s;
            sql_s << "select count(*) as c from \"" << table << "\"";
            auto cur = reader.execute(
                questdb::ingress::utf8_view{sql_s.str()});
            int64_t n = -1;
            if (auto bo = cur.next_batch())
            {
                auto& batch = *bo;
                if (batch.row_count() == 1 && batch.column_count() == 1)
                {
                    const auto k = batch.column_kind(0);
                    if (k == reader_column_kind_long)
                    {
                        auto v = batch.column(0).get<int64_t>(0);
                        if (v) n = *v;
                    }
                    else if (k == reader_column_kind_int)
                    {
                        auto v = batch.column(0).get<int32_t>(0);
                        if (v) n = *v;
                    }
                }
            }
            // Drain to terminal so the cursor isn't dropped mid-stream —
            // otherwise `~cursor()` sends CANCEL and tears down the WS
            // transport, and the next iteration writes into a dead pipe.
            while (cur.next_batch()) {}
            if (n >= 3)
            {
                ready = true;
                break;
            }
        }
        catch (const questdb::egress::reader_error&)
        {
            // Table may not be visible yet; retry.
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(80));
    }
    REQUIRE(ready);

    // Read it back. We seeded exactly 3 rows; assert exact row count
    // (drained across however many batches the server splits them into)
    // so a regression that double-emits or drops rows would be caught.
    std::ostringstream sql_s;
    sql_s << "select l, d, b from \"" << table << "\" order by timestamp";
    auto cur = reader.execute(questdb::ingress::utf8_view{sql_s.str()});

    size_t total_rows = 0;
    while (auto bo = cur.next_batch())
    {
        auto& batch = *bo;
        const size_t rows = batch.row_count();
        for (size_t r = 0; r < rows; ++r)
        {
            const auto l = batch.column(0).get<int64_t>(r);
            const auto d = batch.column(1).get<double>(r);
            const auto b = batch.column(2).get<bool>(r);
            REQUIRE(l.has_value());
            REQUIRE(d.has_value());
            REQUIRE(b.has_value());
            const size_t global_r = total_rows + r;
            CHECK(*l == static_cast<int64_t>(100 + global_r));
            CHECK(*d == doctest::Approx(1.5 * static_cast<double>(global_r)));
            CHECK(*b == ((global_r % 2) == 0));
        }
        total_rows += rows;
    }
    CHECK(total_rows == 3);
}

// ---------------------------------------------------------------------------
// Batch / column bulk descriptor — live coverage of the new columnar API.
// Mock-level coverage of every kind lives in `test_reader_mock.cpp`;
// these three TEST_CASEs validate the kinds whose mock helper code is itself
// new (SYMBOL dict, DOUBLE_ARRAY four-buffer layout) plus a baseline scalar
// cross-check, so we close the loop against a real QuestDB.
// ---------------------------------------------------------------------------

namespace
{

// Poll until `select count(*) from "<table>"` returns at least `expected`.
// Mirrors the wait pattern in the primitives round-trip above.
bool wait_for_rows(
    questdb::egress::reader& reader, const std::string& table, int64_t expected)
{
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(15);
    while (std::chrono::steady_clock::now() < deadline)
    {
        try
        {
            std::ostringstream sql_s;
            sql_s << "select count(*) as c from \"" << table << "\"";
            auto cur = reader.execute(questdb::ingress::utf8_view{sql_s.str()});
            int64_t n = -1;
            if (auto bo = cur.next_batch())
            {
                auto& batch = *bo;
                if (batch.row_count() == 1 && batch.column_count() == 1)
                {
                    const auto k = batch.column_kind(0);
                    if (k == reader_column_kind_long)
                    {
                        auto v = batch.column(0).get<int64_t>(0);
                        if (v)
                            n = *v;
                    }
                    else if (k == reader_column_kind_int)
                    {
                        auto v = batch.column(0).get<int32_t>(0);
                        if (v)
                            n = *v;
                    }
                }
            }
            // Drain to terminal so the cursor isn't dropped mid-stream —
            // otherwise `~cursor()` sends CANCEL and tears down the WS
            // transport, and the next loop iteration writes into a dead
            // pipe (`Broken pipe (os error 32)`).
            while (cur.next_batch())
            {
            }
            if (n >= expected)
                return true;
        }
        catch (const questdb::egress::reader_error&)
        {
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(80));
    }
    return false;
}

} // namespace

TEST_CASE(
    "live: batch::column — scalar bulk vs per-cell (long + double + varchar)")
{
    REQUIRE_LIVE_BROKER();

    namespace eg = questdb::egress;
    auto reader = make_reader();
    auto cur = reader.execute(
        "select x as n, x * 1.5 as d, ('tag-' || x)::varchar as s "
        "from long_sequence(5)"_utf8);

    auto batch_opt = cur.next_batch();
    REQUIRE(batch_opt);
    auto& batch = *batch_opt;
    REQUIRE(batch.row_count() == 5);
    REQUIRE(batch.column_kind(0) == reader_column_kind_long);
    REQUIRE(batch.column_kind(1) == reader_column_kind_double);
    REQUIRE(batch.column_kind(2) == reader_column_kind_varchar);

    auto col_n = batch.column(0);
    auto col_d = batch.column(1);
    auto col_s = batch.column(2);
    REQUIRE(col_n.value_stride() == sizeof(int64_t));
    REQUIRE(col_d.value_stride() == sizeof(double));
    REQUIRE(col_s.value_stride() == 0);

    const int64_t* ns = col_n.values<int64_t>();
    const double* ds = col_d.values<double>();
    for (size_t r = 0; r < 5; ++r)
    {
        // Bulk values match per-cell getters.
        const auto via_n = batch.column(0).get<int64_t>(r);
        const auto via_d = batch.column(1).get<double>(r);
        const auto via_s = batch.column(2).varchar(r);
        REQUIRE(via_n.has_value());
        REQUIRE(via_d.has_value());
        REQUIRE(via_s.has_value());
        CHECK(ns[r] == *via_n);
        CHECK(ds[r] == doctest::Approx(*via_d));
        const auto bulk_s = col_s.varchar(r);
        REQUIRE(bulk_s.has_value());
        CHECK(*bulk_s == *via_s);
    }
}

TEST_CASE("live: batch — SYMBOL column codes + dictionary round-trip")
{
    REQUIRE_LIVE_BROKER();

    namespace eg = questdb::egress;
    const std::string table = unique_table("symbol_bulk");
    constexpr size_t kRows = 9;
    const std::array<const char*, 3> kSyms{{"alpha", "beta", "gamma"}};

    {
        std::ostringstream conf_s;
        conf_s << "http::addr=" << broker_host() << ":" << broker_http_port()
               << ";protocol_version=2;";
        auto sender = questdb::ingress::line_sender::from_conf(
            questdb::ingress::utf8_view{conf_s.str()});
        auto buf = sender.new_buffer();
        const questdb::ingress::table_name_view tname{table};
        const questdb::ingress::column_name_view sym_col{"sym"};
        for (size_t i = 0; i < kRows; ++i)
        {
            buf.table(tname)
                .symbol(
                    sym_col,
                    questdb::ingress::utf8_view{
                        std::string_view{kSyms[i % kSyms.size()]}})
                .at(questdb::ingress::timestamp_nanos{
                    1700000000000000000LL +
                    static_cast<int64_t>(i) * 1000000LL});
        }
        sender.flush(buf);
    }

    auto reader = make_reader();
    REQUIRE(wait_for_rows(reader, table, static_cast<int64_t>(kRows)));

    std::ostringstream sql_s;
    sql_s << "select sym from \"" << table << "\" order by timestamp";
    auto cur = reader.execute(questdb::ingress::utf8_view{sql_s.str()});

    size_t total_rows = 0;
    while (auto batch_opt = cur.next_batch())
    {
        auto& batch = *batch_opt;
        const size_t rows = batch.row_count();
        REQUIRE(batch.column_kind(0) == reader_column_kind_symbol);

        auto col = batch.column(0);
        REQUIRE(col.kind() == eg::column_kind::symbol);
        REQUIRE(col.symbol_codes() != nullptr);

        auto dict = batch.symbol_dict();
        REQUIRE(dict.valid());
        REQUIRE(dict.entry_count() >= kSyms.size());

        for (size_t r = 0; r < rows; ++r)
        {
            const size_t global_r = total_rows + r;
            const std::string_view expected = kSyms[global_r % kSyms.size()];

            // Per-cell getter.
            const auto via_cell = batch.column(0).symbol(r);
            REQUIRE(via_cell.has_value());
            CHECK(*via_cell == expected);

            // Bulk column path.
            const auto via_bulk = col.symbol(r);
            REQUIRE(via_bulk.has_value());
            CHECK(*via_bulk == expected);

            // Code → dict lookup matches bulk resolution.
            const uint32_t code = col.symbol_codes()[r];
            REQUIRE(code < dict.entry_count());
            CHECK(dict[code] == expected);
        }
        total_rows += rows;
    }
    CHECK(total_rows == kRows);
}

TEST_CASE("live: batch::column — DOUBLE_ARRAY round-trip")
{
    REQUIRE_LIVE_BROKER();

    namespace eg = questdb::egress;
    const std::string table = unique_table("double_array_bulk");

    // Two rows of identically-shaped 1-D arrays: [1.0, 2.0, 3.0] and
    // [10.0, 20.0, 30.0]. The server pins protocol_version=3 for array
    // support (see examples/line_sender_cpp_example_array_c_major.cpp).
    const std::array<double, 3> row0{{1.0, 2.0, 3.0}};
    const std::array<double, 3> row1{{10.0, 20.0, 30.0}};

    std::ostringstream conf_s;
    conf_s << "http::addr=" << broker_host() << ":" << broker_http_port()
           << ";protocol_version=3;";
    auto sender = questdb::ingress::line_sender::from_conf(
        questdb::ingress::utf8_view{conf_s.str()});
    auto buf = sender.new_buffer();
    const questdb::ingress::table_name_view tname{table};
    const questdb::ingress::column_name_view arr_col{"arr"};
    size_t rank = 1;
    std::array<uintptr_t, 1> shape{3};

    questdb::ingress::array::row_major_view<double> v0{
        rank, shape.data(), row0.data(), row0.size()};
    questdb::ingress::array::row_major_view<double> v1{
        rank, shape.data(), row1.data(), row1.size()};
    buf.table(tname)
        .column(arr_col, v0)
        .at(questdb::ingress::timestamp_nanos{1700000000000000000LL});
    buf.table(tname)
        .column(arr_col, v1)
        .at(questdb::ingress::timestamp_nanos{1700000001000000000LL});
    sender.flush(buf);
    sender.close();

    auto reader = make_reader();
    REQUIRE(wait_for_rows(reader, table, 2));

    std::ostringstream sql_s;
    sql_s << "select arr from \"" << table << "\" order by timestamp";
    auto cur = reader.execute(questdb::ingress::utf8_view{sql_s.str()});

    size_t total_rows = 0;
    while (auto batch_opt = cur.next_batch())
    {
        auto& batch = *batch_opt;
        const size_t rows = batch.row_count();
        REQUIRE(batch.column_kind(0) == reader_column_kind_double_array);

        auto ac = batch.column(0);
        REQUIRE(ac.is_array());
        REQUIRE(ac.kind() == eg::column_kind::double_array);
        // Scalar accessors on an array column raise.
        CHECK_THROWS_AS(ac.values<double>(), eg::reader_error);

        for (size_t r = 0; r < rows; ++r)
        {
            const size_t global_r = total_rows + r;
            const auto& expected = global_r == 0 ? row0 : row1;

            size_t row_rank = 0;
            const uint32_t* row_shape = ac.shape(r, &row_rank);
            REQUIRE(row_rank == 1);
            CHECK(row_shape[0] == 3);

            size_t count = 0;
            const double* elems = ac.elements<double>(r, &count);
            REQUIRE(count == expected.size());
            for (size_t i = 0; i < count; ++i)
                CHECK(elems[i] == doctest::Approx(expected[i]));
        }
        total_rows += rows;
    }
    CHECK(total_rows == 2);
}
