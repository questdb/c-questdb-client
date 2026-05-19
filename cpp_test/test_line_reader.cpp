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
// → `_cursor_get_*` plus the C++ wrapper's `nullable<T>` translation, the
// single-cursor invariant, and `bind_decimal128`'s i64-high-limb sign
// extension.
//
// These tests need a running QuestDB. Configure the broker via:
//   QDB_LIVE_BROKER_HOST       (default: localhost)
//   QDB_LIVE_BROKER_HTTP_PORT  (default: 9000)
// If the broker is not reachable, each TEST_CASE prints SKIP and returns
// without failing — so this binary is safe to wire into ctest even in
// environments without a broker.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <questdb/egress/line_reader.hpp>
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

    REQUIRE(cur.next_batch());
    CHECK(cur.row_count() == 1);
    CHECK(cur.column_count() == 1);
    REQUIRE(cur.column_kind(0) == line_reader_column_kind_long);
    const auto v = cur.get_i64(0, 0);
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
    while (cur.next_batch())
    {
        const size_t rows = cur.row_count();
        REQUIRE(cur.column_count() == 1);
        REQUIRE(cur.column_kind(0) == line_reader_column_kind_long);
        for (size_t r = 0; r < rows; ++r)
        {
            const auto v = cur.get_i64(0, r);
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

    REQUIRE(cur.next_batch());
    REQUIRE(cur.row_count() == 3);
    REQUIRE(cur.column_count() == 2);
    REQUIRE(cur.column_kind(0) == line_reader_column_kind_long);
    REQUIRE(cur.column_kind(1) == line_reader_column_kind_double);

    for (size_t r = 0; r < 3; ++r)
    {
        const auto n = cur.get_i64(0, r);
        const auto d = cur.get_f64(1, r);
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

    REQUIRE(cur.next_batch());
    REQUIRE(cur.row_count() == 3);
    REQUIRE(cur.column_count() == 2);
    REQUIRE(cur.column_kind(0) == line_reader_column_kind_long);
    REQUIRE(cur.column_kind(1) == line_reader_column_kind_varchar);

    for (size_t r = 0; r < 3; ++r)
    {
        const int64_t expected_scaled = 7 * static_cast<int64_t>(r + 1);
        const auto v = cur.get_i64(0, r);
        REQUIRE(v.has_value());
        CHECK(*v == expected_scaled);
        const auto label = cur.get_varchar(1, r);
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

    REQUIRE(cur.next_batch());
    REQUIRE(cur.row_count() == 1);
    REQUIRE(cur.column_kind(0) == line_reader_column_kind_double);
    const auto v = cur.get_f64(0, 0);
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
    auto cur = reader.execute(
        "select case when x % 2 = 0 then cast(null as long) else x end as v "
        "from long_sequence(5)"_utf8);
    REQUIRE(cur.next_batch());
    REQUIRE(cur.row_count() == 5);
    REQUIRE(cur.column_count() == 1);
    REQUIRE(cur.column_kind(0) == line_reader_column_kind_long);

    const auto vv = cur.column_validity(0);
    REQUIRE_FALSE(vv.empty());
    REQUIRE(vv.size >= 1);
    // Mask off padding bits 5..7; only the lower 5 bits encode rows 0..4.
    CHECK((vv.data[0] & 0x1F) == 0x0A);

    // Cross-check: per-row getter agrees with the bitmap.
    for (size_t r = 0; r < 5; ++r)
    {
        const bool expect_null = ((r % 2) == 1);
        const auto v = cur.get_i64(0, r);
        if (expect_null)
            CHECK_FALSE(v.has_value());
        else
            CHECK(v.has_value());
    }
    while (cur.next_batch()) {} // drain

    // No-nulls case: every row is non-null, so the validity view is empty.
    auto cur2 =
        reader.execute("select x from long_sequence(3)"_utf8);
    REQUIRE(cur2.next_batch());
    REQUIRE(cur2.row_count() == 3);
    const auto vv2 = cur2.column_validity(0);
    CHECK(vv2.empty());
    CHECK(vv2.data == nullptr);
    CHECK(vv2.size == 0);
}

TEST_CASE("bind: typed null")
{
    REQUIRE_LIVE_BROKER();

    auto reader = make_reader();
    auto cur = reader.prepare("select $1::long as v"_utf8)
                   .bind_null(questdb::egress::column_kind::long_)
                   .execute();

    REQUIRE(cur.next_batch());
    REQUIRE(cur.row_count() == 1);
    const auto v = cur.get_i64(0, 0);
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
    REQUIRE(cur.next_batch());
    REQUIRE(cur.row_count() == 1);
    REQUIRE(cur.column_kind(0) == line_reader_column_kind_decimal128);
    const auto d = cur.get_decimal128(0, 0);
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
    catch (const questdb::egress::line_reader_error& e)
    {
        threw = true;
        CHECK(e.code() == line_reader_error_invalid_api_call);
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
    REQUIRE(cur2.next_batch());
    CHECK(cur2.row_count() == 1);
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
    REQUIRE(cur.next_batch());
    CHECK(cur.row_count() == 1);
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

    // Before any batch, batch_* accessors return nullopt.
    CHECK_FALSE(cur.batch_request_id().has_value());
    CHECK_FALSE(cur.batch_seq().has_value());
    CHECK_FALSE(cur.batch_flags().has_value());

    REQUIRE(cur.next_batch());

    // After a batch, all three are populated. Pin actual values rather
    // than only `has_value()` — a regression returning `0/0/0` would
    // pass the bare has_value checks but fail these.
    const auto bri = cur.batch_request_id();
    const auto bseq = cur.batch_seq();
    const auto bflags = cur.batch_flags();
    REQUIRE(bri.has_value());
    REQUIRE(bseq.has_value());
    REQUIRE(bflags.has_value());
    // Cursor's request_id is allocated at execute() and is non-zero.
    // The first batch's request_id MUST equal the cursor's request_id —
    // a regression that returned 0 would fail here.
    const int64_t rid = cur.request_id();
    CHECK(rid != 0);
    CHECK(*bri == rid);
    // First batch on a fresh cursor has batch_seq == 0; subsequent
    // batches monotonically increment.
    CHECK(*bseq == 0);

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
    REQUIRE(cur.terminal_kind() == line_reader_terminal_kind_end);
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
        (void)reader.execute("syntactically invalid !!!"_utf8);
    }
    catch (const questdb::egress::line_reader_error& e)
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
    CHECK((code == line_reader_error_server_parse_error
        || code == line_reader_error_server_internal_error));
}

TEST_CASE("get_i64 type-mismatch on string column is reported, not a crash")
{
    REQUIRE_LIVE_BROKER();

    auto reader = make_reader();
    auto cur = reader.execute("select 'hello' as s"_utf8);
    REQUIRE(cur.next_batch());
    REQUIRE(cur.column_count() == 1);
    bool threw = false;
    try
    {
        (void)cur.get_i64(0, 0);
    }
    catch (const questdb::egress::line_reader_error& e)
    {
        threw = true;
        CHECK(e.code() == line_reader_error_invalid_api_call);
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
            if (cur.next_batch() && cur.row_count() == 1 &&
                cur.column_count() == 1)
            {
                const auto k = cur.column_kind(0);
                int64_t n = -1;
                if (k == line_reader_column_kind_long)
                {
                    auto v = cur.get_i64(0, 0);
                    if (v) n = *v;
                }
                else if (k == line_reader_column_kind_int)
                {
                    auto v = cur.get_i32(0, 0);
                    if (v) n = *v;
                }
                if (n >= 3)
                {
                    ready = true;
                    break;
                }
            }
        }
        catch (const questdb::egress::line_reader_error&)
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
    sql_s << "select l, d, b from \"" << table << "\" order by ts";
    auto cur = reader.execute(questdb::ingress::utf8_view{sql_s.str()});

    size_t total_rows = 0;
    while (cur.next_batch())
    {
        const size_t rows = cur.row_count();
        for (size_t r = 0; r < rows; ++r)
        {
            const auto l = cur.get_i64(0, r);
            const auto d = cur.get_f64(1, r);
            const auto b = cur.get_bool(2, r);
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
