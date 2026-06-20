// FFI-boundary smoke test for the C++ wrapper
// `column_sender_conn::flush_arrow_batch` over the new conn-level Arrow
// batch ingest API. Successful round-trip coverage and per-type
// classification coverage live in the Rust unit tests under
// `questdb-rs/src/ingress/column_sender/arrow_batch.rs` and the Python
// system tests under `system_test/arrow_polars_*.py`.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "qwp_mock_server.hpp"

#include <questdb/ingress/column_sender.h>
#include <questdb/ingress/column_sender.hpp>
#include <questdb/ingress/line_sender.hpp>

#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace qdb = questdb::ingress;
namespace qm = qwp_mock;
using namespace questdb::ingress::literals;

TEST_CASE("column_sender_conn::flush_arrow_batch rejects NULL conn")
{
    ArrowArray arr;
    ArrowSchema sch;
    std::memset(&arr, 0, sizeof(arr));
    std::memset(&sch, 0, sizeof(sch));

    qdb::column_sender_conn conn{nullptr};
    CHECK_THROWS_AS(
        conn.flush_arrow_batch("t"_tn, arr, sch),
        qdb::line_sender_error);
}

TEST_CASE("column_sender_conn::flush_arrow_batch at_column rejects NULL conn")
{
    ArrowArray arr;
    ArrowSchema sch;
    std::memset(&arr, 0, sizeof(arr));
    std::memset(&sch, 0, sizeof(sch));

    qdb::column_sender_conn conn{nullptr};
    CHECK_THROWS_AS(
        conn.flush_arrow_batch("t"_tn, arr, sch, "ts"_cn),
        qdb::line_sender_error);
}

TEST_CASE("column_sender_conn surfaces error_code on NULL-conn failure")
{
    ArrowArray arr;
    ArrowSchema sch;
    std::memset(&arr, 0, sizeof(arr));
    std::memset(&sch, 0, sizeof(sch));

    qdb::column_sender_conn conn{nullptr};
    try
    {
        conn.flush_arrow_batch("t"_tn, arr, sch);
        FAIL("expected throw");
    }
    catch (const qdb::line_sender_error& e)
    {
        CHECK(
            e.code() == qdb::line_sender_error_code::invalid_api_call);
    }
}

// ===========================================================================
// Mock-backed end-to-end coverage migrated from the deleted buffer-level
// append_arrow API. Each TEST_CASE spins up an in-process mock and a
// 1-slot `questdb_db` pool, then drives one
// `column_sender_flush_arrow_batch[_at_column]` call against a borrowed
// `qwpws_conn*`.
//
// Per-type wire correctness is covered by the Rust unit tests in
// `questdb-rs/src/ingress/column_sender/arrow_batch.rs`; here we only
// assert that each Arrow C Data Interface payload (a) classifies
// correctly and (b) survives the full Rust → FFI → mock socket
// round-trip without an exception.
// ===========================================================================

namespace
{

// Owner for heap allocations referenced by a hand-built ArrowArray. The
// arrow-rs FFI importer calls `release_owner` when it consumes the
// imported ArrayData; on the failure path the test calls it directly.
struct Owner
{
    std::vector<std::shared_ptr<std::vector<uint8_t>>> buffers_storage;
    std::vector<const void*> buffer_ptrs;
    std::vector<std::unique_ptr<ArrowArray>> children_storage;
    std::vector<ArrowArray*> children_ptrs;
};

void release_owner(ArrowArray* arr)
{
    if (!arr || !arr->private_data)
        return;
    auto* owner = static_cast<Owner*>(arr->private_data);
    for (auto& child_ptr : owner->children_storage)
    {
        if (child_ptr && child_ptr->release)
            child_ptr->release(child_ptr.get());
    }
    delete owner;
    arr->release = nullptr;
    arr->private_data = nullptr;
}

void schema_release_noop(ArrowSchema* sch)
{
    if (sch)
        sch->release = nullptr;
}

ArrowArray make_array(
    int64_t length,
    int64_t null_count,
    std::vector<std::shared_ptr<std::vector<uint8_t>>> buffers)
{
    auto owner = std::make_unique<Owner>();
    owner->buffers_storage = std::move(buffers);
    for (auto& buf : owner->buffers_storage)
        owner->buffer_ptrs.push_back(buf ? buf->data() : nullptr);

    ArrowArray arr;
    std::memset(&arr, 0, sizeof(arr));
    arr.length = length;
    arr.null_count = null_count;
    arr.n_buffers = static_cast<int64_t>(owner->buffer_ptrs.size());
    arr.buffers = owner->buffer_ptrs.data();
    arr.release = release_owner;
    arr.private_data = owner.release();
    return arr;
}

ArrowSchema make_schema(const char* format, const char* name)
{
    ArrowSchema sch;
    std::memset(&sch, 0, sizeof(sch));
    sch.format = format;
    sch.name = name;
    sch.flags = ARROW_FLAG_NULLABLE;
    sch.release = schema_release_noop;
    return sch;
}

template <typename T>
std::shared_ptr<std::vector<uint8_t>> pack_le(const std::vector<T>& vs)
{
    auto out = std::make_shared<std::vector<uint8_t>>();
    out->reserve(vs.size() * sizeof(T));
    for (T v : vs)
    {
        const uint8_t* p = reinterpret_cast<const uint8_t*>(&v);
        out->insert(out->end(), p, p + sizeof(T));
    }
    return out;
}

// RAII helper: starts a mock + opens a 1-slot column-sender db + borrows
// a conn. Returns the conn to the pool and closes the db on destruction.
struct MockConn
{
    qm::MockServer server;
    questdb_db* db = nullptr;
    qwpws_conn* conn = nullptr;

    MockConn()
        : server(std::vector<qm::Script>{
              qm::Script{qm::ActionAwaitClientFrame{0x51}}})
    {
        const std::string conf =
            "qwpws::addr=" + server.addr() + ";pool_size=1;pool_reap=manual;";
        line_sender_error* err = nullptr;
        db = questdb_db_connect(conf.c_str(), conf.size(), &err);
        REQUIRE(db != nullptr);
        REQUIRE(err == nullptr);
        conn = questdb_db_borrow_column_sender(db, &err);
        REQUIRE(conn != nullptr);
        REQUIRE(err == nullptr);
    }

    ~MockConn()
    {
        if (db != nullptr)
        {
            if (conn != nullptr)
                questdb_db_return_conn(db, conn);
            questdb_db_close(db);
        }
    }

    MockConn(const MockConn&) = delete;
    MockConn& operator=(const MockConn&) = delete;
};

// Validate that `conn.flush_arrow_batch(...)` for a primitive-column
// schema succeeds. On any throw the test fails with the error message.
void expect_flush_ok(
    MockConn& mc,
    const char* table,
    ArrowArray& arr,
    ArrowSchema& sch)
{
    qdb::column_sender_conn conn{mc.conn};
    try
    {
        conn.flush_arrow_batch(
            qdb::table_name_view{table, std::strlen(table)}, arr, sch);
    }
    catch (const qdb::line_sender_error& e)
    {
        FAIL("flush_arrow_batch threw: " << e.what());
    }
}

} // namespace

// ---------------------------------------------------------------------------
// NULL-payload contract via the C ABI (covers the surface that used to
// live in `arrow ingress: NULL buffer / array / schema → false + err_out`).
// The NULL-conn case is already covered by the three TEST_CASEs above; we
// add NULL-array and NULL-schema here using a real (mock-backed) conn so
// the array/schema branch in the impl is exercised.
// ---------------------------------------------------------------------------

TEST_CASE("flush_arrow_batch: NULL array → invalid_api_call")
{
    MockConn mc;
    ArrowSchema sch;
    std::memset(&sch, 0, sizeof(sch));
    line_sender_error* err = nullptr;
    line_sender_table_name tbl{1, "t"};
    bool ok = column_sender_flush_arrow_batch(
        mc.conn, tbl, nullptr, &sch, nullptr, 0, &err);
    CHECK_FALSE(ok);
    REQUIRE(err != nullptr);
    CHECK(line_sender_error_get_code(err) == line_sender_error_invalid_api_call);
    line_sender_error_free(err);
}

TEST_CASE("flush_arrow_batch: NULL schema → invalid_api_call")
{
    MockConn mc;
    ArrowArray arr;
    std::memset(&arr, 0, sizeof(arr));
    line_sender_error* err = nullptr;
    line_sender_table_name tbl{1, "t"};
    bool ok = column_sender_flush_arrow_batch(
        mc.conn, tbl, &arr, nullptr, nullptr, 0, &err);
    CHECK_FALSE(ok);
    REQUIRE(err != nullptr);
    CHECK(line_sender_error_get_code(err) == line_sender_error_invalid_api_call);
    line_sender_error_free(err);
}

TEST_CASE("flush_arrow_batch_at_column: empty ts_column_name throws invalid_name")
{
    try
    {
        qdb::column_name_view name{"", 0};
        FAIL("expected column_name_view{\"\", 0} to throw");
    }
    catch (const qdb::line_sender_error& e)
    {
        CHECK(e.code() == qdb::line_sender_error_code::invalid_name);
    }
}

// ---------------------------------------------------------------------------
// Primitive type dispatch — each Arrow format code routes to the right
// QuestDB column setter.
// ---------------------------------------------------------------------------

TEST_CASE("flush_arrow_batch: Boolean column")
{
    MockConn mc;
    // Boolean is bit-packed in Arrow C ABI (1 byte per 8 rows).
    auto values = std::make_shared<std::vector<uint8_t>>(
        std::vector<uint8_t>{0b00000101});
    auto arr = make_array(3, 0, {nullptr, values});
    auto sch = make_schema("b", "flag");
    expect_flush_ok(mc, "t_bool", arr, sch);
}

TEST_CASE("flush_arrow_batch: Int8 / Int16 / Int32 / Int64 columns")
{
    SUBCASE("Int8")
    {
        MockConn mc;
        auto col = pack_le<int8_t>({-1, 0, 127});
        auto arr = make_array(3, 0, {nullptr, col});
        auto sch = make_schema("c", "by");
        expect_flush_ok(mc, "t_i8", arr, sch);
    }
    SUBCASE("Int16")
    {
        MockConn mc;
        auto col = pack_le<int16_t>({-1234, 0, 31000});
        auto arr = make_array(3, 0, {nullptr, col});
        auto sch = make_schema("s", "sh");
        expect_flush_ok(mc, "t_i16", arr, sch);
    }
    SUBCASE("Int32")
    {
        MockConn mc;
        auto col = pack_le<int32_t>({-1, 0, 0x7FFFFFFF});
        auto arr = make_array(3, 0, {nullptr, col});
        auto sch = make_schema("i", "in");
        expect_flush_ok(mc, "t_i32", arr, sch);
    }
    SUBCASE("Int64")
    {
        MockConn mc;
        auto col = pack_le<int64_t>({-1, 0, 0x7FFFFFFF'FFFFFFFFLL});
        auto arr = make_array(3, 0, {nullptr, col});
        auto sch = make_schema("l", "lo");
        expect_flush_ok(mc, "t_i64", arr, sch);
    }
}

TEST_CASE("flush_arrow_batch: Float32 / Float64 columns")
{
    SUBCASE("Float32")
    {
        MockConn mc;
        auto col = pack_le<float>({1.5f, -2.5f, 3.14f});
        auto arr = make_array(3, 0, {nullptr, col});
        auto sch = make_schema("f", "f3");
        expect_flush_ok(mc, "t_f32", arr, sch);
    }
    SUBCASE("Float64")
    {
        MockConn mc;
        auto col = pack_le<double>({1.5, -2.5, 3.14159});
        auto arr = make_array(3, 0, {nullptr, col});
        auto sch = make_schema("g", "f6");
        expect_flush_ok(mc, "t_f64", arr, sch);
    }
}

TEST_CASE("flush_arrow_batch: UInt16 + questdb.column_type=char → column_char")
{
    MockConn mc;
    auto col = pack_le<uint16_t>({0x41, 0x42, 0x43});
    auto arr = make_array(3, 0, {nullptr, col});
    auto sch = make_schema("S", "c");
    static const char md[] =
        "\x01\x00\x00\x00"
        "\x13\x00\x00\x00" "questdb.column_type"
        "\x04\x00\x00\x00" "char";
    sch.metadata = md;
    expect_flush_ok(mc, "t_char", arr, sch);
}

TEST_CASE("flush_arrow_batch: UInt32 + questdb.column_type=ipv4 → column_ipv4")
{
    MockConn mc;
    auto col = pack_le<uint32_t>({0x0A000001u, 0xC0A80001u});
    auto arr = make_array(2, 0, {nullptr, col});
    auto sch = make_schema("I", "ip");
    static const char md[] =
        "\x01\x00\x00\x00"
        "\x13\x00\x00\x00" "questdb.column_type"
        "\x04\x00\x00\x00" "ipv4";
    sch.metadata = md;
    expect_flush_ok(mc, "t_ipv4", arr, sch);
}

TEST_CASE("flush_arrow_batch: Utf8 / Binary / LargeUtf8 / LargeBinary")
{
    auto build_utf8 = []() {
        auto offsets = std::make_shared<std::vector<uint8_t>>();
        for (int32_t off : {0, 5, 5, 7})
        {
            const uint8_t* p = reinterpret_cast<const uint8_t*>(&off);
            offsets->insert(offsets->end(), p, p + 4);
        }
        auto data = std::make_shared<std::vector<uint8_t>>(
            std::vector<uint8_t>{'h', 'e', 'l', 'l', 'o', 'y', 'o'});
        return std::make_pair(offsets, data);
    };
    auto build_large = []() {
        auto offsets = std::make_shared<std::vector<uint8_t>>();
        for (int64_t off : {0LL, 5LL, 5LL, 7LL})
        {
            const uint8_t* p = reinterpret_cast<const uint8_t*>(&off);
            offsets->insert(offsets->end(), p, p + 8);
        }
        auto data = std::make_shared<std::vector<uint8_t>>(
            std::vector<uint8_t>{'h', 'e', 'l', 'l', 'o', 'y', 'o'});
        return std::make_pair(offsets, data);
    };

    SUBCASE("Utf8")
    {
        MockConn mc;
        auto pair = build_utf8();
        auto arr = make_array(3, 0, {nullptr, pair.first, pair.second});
        auto sch = make_schema("u", "name");
        expect_flush_ok(mc, "t_utf8", arr, sch);
    }
    SUBCASE("Binary")
    {
        MockConn mc;
        auto pair = build_utf8();
        auto arr = make_array(3, 0, {nullptr, pair.first, pair.second});
        auto sch = make_schema("z", "blob");
        expect_flush_ok(mc, "t_binary", arr, sch);
    }
    SUBCASE("LargeUtf8")
    {
        MockConn mc;
        auto pair = build_large();
        auto arr = make_array(3, 0, {nullptr, pair.first, pair.second});
        auto sch = make_schema("U", "name_l");
        expect_flush_ok(mc, "t_lutf8", arr, sch);
    }
    SUBCASE("LargeBinary")
    {
        MockConn mc;
        auto pair = build_large();
        auto arr = make_array(3, 0, {nullptr, pair.first, pair.second});
        auto sch = make_schema("Z", "blob_l");
        expect_flush_ok(mc, "t_lbin", arr, sch);
    }
}

TEST_CASE("flush_arrow_batch: FixedSizeBinary(16) + arrow.uuid extension → column_uuid")
{
    MockConn mc;
    auto data = std::make_shared<std::vector<uint8_t>>();
    for (int i = 0; i < 32; ++i)
        data->push_back(static_cast<uint8_t>(i));
    auto arr = make_array(2, 0, {nullptr, data});
    auto sch = make_schema("w:16", "id");
    static const char md[] =
        "\x01\x00\x00\x00"
        "\x14\x00\x00\x00" "ARROW:extension:name"
        "\x0A\x00\x00\x00" "arrow.uuid";
    sch.metadata = md;
    expect_flush_ok(mc, "t_uuid", arr, sch);
}

TEST_CASE("flush_arrow_batch: FixedSizeBinary(16) without metadata defaults to column_uuid")
{
    MockConn mc;
    auto data = std::make_shared<std::vector<uint8_t>>(
        std::vector<uint8_t>(16, 0));
    auto arr = make_array(1, 0, {nullptr, data});
    auto sch = make_schema("w:16", "id");
    expect_flush_ok(mc, "t_uuid_default", arr, sch);
}

TEST_CASE("flush_arrow_batch: FixedSizeBinary(32) → column_long256")
{
    MockConn mc;
    auto data = std::make_shared<std::vector<uint8_t>>(
        std::vector<uint8_t>(64, 0xAB));
    auto arr = make_array(2, 0, {nullptr, data});
    auto sch = make_schema("w:32", "l256");
    expect_flush_ok(mc, "t_l256", arr, sch);
}

TEST_CASE("flush_arrow_batch: Timestamp(µs) / Timestamp(ns) / Timestamp(ms)")
{
    SUBCASE("Timestamp(µs)")
    {
        MockConn mc;
        auto col = pack_le<int64_t>(
            {1700000000000000LL, 1700000000000001LL});
        auto arr = make_array(2, 0, {nullptr, col});
        auto sch = make_schema("tsu:UTC", "ts");
        expect_flush_ok(mc, "t_tsu", arr, sch);
    }
    SUBCASE("Timestamp(ns)")
    {
        MockConn mc;
        auto col = pack_le<int64_t>(
            {1700000000000000000LL, 1700000000000000001LL});
        auto arr = make_array(2, 0, {nullptr, col});
        auto sch = make_schema("tsn:UTC", "ts");
        expect_flush_ok(mc, "t_tsn", arr, sch);
    }
    SUBCASE("Timestamp(ms)")
    {
        MockConn mc;
        auto col = pack_le<int64_t>({1700000000000LL, 1700000000001LL});
        auto arr = make_array(2, 0, {nullptr, col});
        auto sch = make_schema("tsm:UTC", "ts");
        expect_flush_ok(mc, "t_tsm", arr, sch);
    }
}

// ---------------------------------------------------------------------------
// Decimal dispatch.
// ---------------------------------------------------------------------------

TEST_CASE("flush_arrow_batch: Decimal64 / Decimal128 / Decimal256")
{
    SUBCASE("Decimal64")
    {
        MockConn mc;
        auto col = pack_le<int64_t>({12345, 67890});
        auto arr = make_array(2, 0, {nullptr, col});
        auto sch = make_schema("d:18,2,64", "d64");
        expect_flush_ok(mc, "t_d64", arr, sch);
    }
    SUBCASE("Decimal128")
    {
        MockConn mc;
        auto data = std::make_shared<std::vector<uint8_t>>(
            std::vector<uint8_t>(32, 0));
        auto arr = make_array(2, 0, {nullptr, data});
        auto sch = make_schema("d:38,3", "d128");
        expect_flush_ok(mc, "t_d128", arr, sch);
    }
    SUBCASE("Decimal256")
    {
        MockConn mc;
        auto data = std::make_shared<std::vector<uint8_t>>(
            std::vector<uint8_t>(64, 0));
        auto arr = make_array(2, 0, {nullptr, data});
        auto sch = make_schema("d:76,5,256", "d256");
        expect_flush_ok(mc, "t_d256", arr, sch);
    }
}

TEST_CASE("flush_arrow_batch: Int32 + questdb.geohash_bits → column_geohash")
{
    MockConn mc;
    auto col = pack_le<int32_t>({0x1FFFF, 0x10000});
    auto arr = make_array(2, 0, {nullptr, col});
    auto sch = make_schema("i", "g");
    static const char md[] =
        "\x01\x00\x00\x00"
        "\x14\x00\x00\x00" "questdb.geohash_bits"
        "\x02\x00\x00\x00" "20";
    sch.metadata = md;
    expect_flush_ok(mc, "t_geo", arr, sch);
}

// ---------------------------------------------------------------------------
// Designated-timestamp behaviour. In the new conn-level API, `now` and
// `server_now` collapse into the same entry point (no per-row stamp), so
// the two original variants are functionally identical here; the
// `Column` variant maps to the dedicated `flush_arrow_batch_at_column`.
// ---------------------------------------------------------------------------

TEST_CASE("flush_arrow_batch: omits per-row timestamp (server stamps on arrival)")
{
    MockConn mc;
    auto col = pack_le<int64_t>({10, 20});
    auto arr = make_array(2, 0, {nullptr, col});
    auto sch = make_schema("l", "v");
    expect_flush_ok(mc, "t_no_ts", arr, sch);
}

TEST_CASE("flush_arrow_batch_at_column: picks per-row ts from named Timestamp column")
{
    MockConn mc;

    // Two-column struct: ts (Timestamp µs UTC) + v (Int64).
    auto ts_col = pack_le<int64_t>(
        {1700000000000000LL, 1700000000000001LL});
    auto v_col = pack_le<int64_t>({10, 20});

    auto ts_arr = std::make_unique<ArrowArray>(
        make_array(2, 0, {nullptr, ts_col}));
    auto v_arr = std::make_unique<ArrowArray>(
        make_array(2, 0, {nullptr, v_col}));

    auto ts_sch = std::make_unique<ArrowSchema>(make_schema("tsu:UTC", "ts"));
    auto v_sch = std::make_unique<ArrowSchema>(make_schema("l", "v"));

    auto* outer_owner = new Owner;
    outer_owner->children_storage.push_back(std::move(ts_arr));
    outer_owner->children_storage.push_back(std::move(v_arr));
    outer_owner->children_ptrs.push_back(
        outer_owner->children_storage[0].get());
    outer_owner->children_ptrs.push_back(
        outer_owner->children_storage[1].get());

    ArrowArray outer_arr;
    std::memset(&outer_arr, 0, sizeof(outer_arr));
    outer_arr.length = 2;
    outer_arr.n_buffers = 1; // struct array has 1 buffer (validity)
    outer_arr.n_children = 2;
    outer_arr.children = outer_owner->children_ptrs.data();
    outer_arr.release = release_owner;
    outer_arr.private_data = outer_owner;
    static const void* outer_buf_slot[1] = {nullptr};
    outer_arr.buffers = outer_buf_slot;

    ArrowSchema outer_sch;
    std::memset(&outer_sch, 0, sizeof(outer_sch));
    outer_sch.format = "+s";
    outer_sch.n_children = 2;
    static ArrowSchema* child_schema_ptrs[2];
    child_schema_ptrs[0] = ts_sch.get();
    child_schema_ptrs[1] = v_sch.get();
    outer_sch.children = child_schema_ptrs;
    outer_sch.release = schema_release_noop;

    qdb::column_sender_conn conn{mc.conn};
    try
    {
        conn.flush_arrow_batch("t_dts_col"_tn, outer_arr, outer_sch, "ts"_cn);
    }
    catch (const qdb::line_sender_error& e)
    {
        FAIL("flush_arrow_batch_at_column threw: " << e.what());
    }
    // Keep static schemas alive across the call; clear release so we
    // don't double-free if doctest unwinds.
    ts_sch->release = nullptr;
    v_sch->release = nullptr;
}
