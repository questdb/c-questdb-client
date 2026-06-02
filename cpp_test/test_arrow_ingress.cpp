// Exhaustive tests for the Arrow C Data Interface ingress export
// (`line_sender_buffer_append_arrow`). The buffer-level path is
// network-free — we construct ArrowArray / ArrowSchema in-process and
// validate Buffer accumulation via `line_sender_buffer_size` and the
// new error codes (`arrow_unsupported_column_kind` /
// `arrow_ingest`).

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <questdb/ingress/line_sender.hpp>

#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

namespace
{

// Owner for heap allocations referenced by a hand-built ArrowArray. We
// register `release_owner` as the array's release callback; arrow-rs's
// `from_ffi` calls it when the imported ArrayData is dropped (consumed
// by `append_arrow`).
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
    delete static_cast<Owner*>(arr->private_data);
    arr->release = nullptr;
    arr->private_data = nullptr;
}

void schema_release_noop(ArrowSchema* sch)
{
    if (sch)
        sch->release = nullptr;
}

// Materialize an owner-backed ArrowArray. `validity` is optional; if
// absent the validity buffer slot is NULL and `null_count = 0`.
ArrowArray make_array(
    int64_t length,
    int64_t null_count,
    std::vector<std::shared_ptr<std::vector<uint8_t>>> buffers)
{
    auto owner = std::make_unique<Owner>();
    owner->buffers_storage = std::move(buffers);
    for (auto& buf : owner->buffers_storage)
    {
        owner->buffer_ptrs.push_back(buf ? buf->data() : nullptr);
    }

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

namespace qdb = questdb::ingress;

void append_ok(
    qdb::line_sender_buffer& buf,
    qdb::table_name_view tbl,
    ArrowArray& arr,
    ArrowSchema& sch)
{
    const size_t size_before = buf.size();
    const size_t row_count_before = buf.row_count();
    try
    {
        buf.append_arrow(tbl, arr, sch);
    }
    catch (const qdb::line_sender_error& e)
    {
        FAIL("append_arrow threw: " << e.what());
    }
    if (sch.release)
        sch.release(&sch);
    CHECK(buf.size() > size_before);
    CHECK(buf.row_count() > row_count_before);
}

void append_expect_error(
    qdb::line_sender_buffer& buf,
    qdb::table_name_view tbl,
    ArrowArray& arr,
    ArrowSchema& sch,
    qdb::line_sender_error_code expected_code)
{
    bool thrown = false;
    try
    {
        buf.append_arrow(tbl, arr, sch);
    }
    catch (const qdb::line_sender_error& e)
    {
        thrown = true;
        CHECK(e.code() == expected_code);
    }
    REQUIRE(thrown);
    if (arr.release)
        arr.release(&arr);
    if (sch.release)
        sch.release(&sch);
}

} // namespace

// NULL-pointer / contract tests for the C ABI live in `test_arrow_c.c`.
// The C++ wrapper takes references and validated views, so equivalents
// here would be untestable at compile time.

// ---------------------------------------------------------------------------
// Primitive type dispatch — each Arrow format code routes to the right
// QuestDB column setter.
// ---------------------------------------------------------------------------

TEST_CASE("arrow ingress: Boolean column")
{
    auto buf = qdb::line_sender_buffer::qwp_ws();
    // Boolean values are bit-packed in Arrow C ABI: 1 byte per 8 rows.
    auto values = std::make_shared<std::vector<uint8_t>>(std::vector<uint8_t>{0b00000101});
    auto arr = make_array(3, 0, {nullptr, values});
    auto sch = make_schema("b", "flag");
    append_ok(buf, "t_bool", arr, sch);
}

TEST_CASE("arrow ingress: Int8 / Int16 / Int32 / Int64 columns")
{
    {
        auto buf = qdb::line_sender_buffer::qwp_ws();
        auto col = pack_le<int8_t>({-1, 0, 127});
        auto arr = make_array(3, 0, {nullptr, col});
        auto sch = make_schema("c", "by");
        append_ok(buf, "t_i8", arr, sch);
    }
    {
        auto buf = qdb::line_sender_buffer::qwp_ws();
        auto col = pack_le<int16_t>({-1234, 0, 31000});
        auto arr = make_array(3, 0, {nullptr, col});
        auto sch = make_schema("s", "sh");
        append_ok(buf, "t_i16", arr, sch);
    }
    {
        auto buf = qdb::line_sender_buffer::qwp_ws();
        auto col = pack_le<int32_t>({-1, 0, 0x7FFFFFFF});
        auto arr = make_array(3, 0, {nullptr, col});
        auto sch = make_schema("i", "in");
        append_ok(buf, "t_i32", arr, sch);
    }
    {
        auto buf = qdb::line_sender_buffer::qwp_ws();
        auto col = pack_le<int64_t>({-1, 0, 0x7FFFFFFF'FFFFFFFFLL});
        auto arr = make_array(3, 0, {nullptr, col});
        auto sch = make_schema("l", "lo");
        append_ok(buf, "t_i64", arr, sch);
    }
}

TEST_CASE("arrow ingress: Float32 / Float64 columns")
{
    {
        auto buf = qdb::line_sender_buffer::qwp_ws();
        auto col = pack_le<float>({1.5f, -2.5f, 3.14f});
        auto arr = make_array(3, 0, {nullptr, col});
        auto sch = make_schema("f", "f3");
        append_ok(buf, "t_f32", arr, sch);
    }
    {
        auto buf = qdb::line_sender_buffer::qwp_ws();
        auto col = pack_le<double>({1.5, -2.5, 3.14159});
        auto arr = make_array(3, 0, {nullptr, col});
        auto sch = make_schema("g", "f6");
        append_ok(buf, "t_f64", arr, sch);
    }
}

TEST_CASE("arrow ingress: UInt16 + questdb.column_type=char routes to column_char")
{
    auto buf = qdb::line_sender_buffer::qwp_ws();
    auto col = pack_le<uint16_t>({0x41, 0x42, 0x43});
    auto arr = make_array(3, 0, {nullptr, col});
    auto sch = make_schema("S", "c"); // Arrow "S" = UInt16
    // Build an Arrow-spec metadata blob with one key/value:
    //   {key: "questdb.column_type", value: "char"}.
    // Arrow spec layout: i32 n_keys, then per pair: i32 key_len, key bytes, i32 val_len, val bytes.
    // We use a static buffer that outlives the call.
    static const char md[] =
        "\x01\x00\x00\x00" // n=1
        "\x13\x00\x00\x00"
        "questdb.column_type"
        "\x04\x00\x00\x00"
        "char";
    sch.metadata = md;
    append_ok(buf, "t_char", arr, sch);
}

TEST_CASE("arrow ingress: UInt32 + questdb.column_type=ipv4 routes to column_ipv4")
{
    auto buf = qdb::line_sender_buffer::qwp_ws();
    auto col = pack_le<uint32_t>({0x0A000001u, 0xC0A80001u});
    auto arr = make_array(2, 0, {nullptr, col});
    auto sch = make_schema("I", "ip");
    static const char md[] =
        "\x01\x00\x00\x00"
        "\x13\x00\x00\x00questdb.column_type"
        "\x04\x00\x00\x00ipv4";
    sch.metadata = md;
    append_ok(buf, "t_ipv4", arr, sch);
}

TEST_CASE("arrow ingress: Utf8 / Binary / LargeUtf8 / LargeBinary")
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

    {
        auto buf = qdb::line_sender_buffer::qwp_ws();
        auto pair = build_utf8();
        auto arr = make_array(3, 0, {nullptr, pair.first, pair.second});
        auto sch = make_schema("u", "name");
        append_ok(buf, "t_utf8", arr, sch);
    }
    {
        auto buf = qdb::line_sender_buffer::qwp_ws();
        auto pair = build_utf8();
        auto arr = make_array(3, 0, {nullptr, pair.first, pair.second});
        auto sch = make_schema("z", "blob");
        append_ok(buf, "t_binary", arr, sch);
    }
}

TEST_CASE("arrow ingress: FixedSizeBinary(16) + arrow.uuid extension → column_uuid")
{
    auto buf = qdb::line_sender_buffer::qwp_ws();
    auto data = std::make_shared<std::vector<uint8_t>>();
    for (int i = 0; i < 32; ++i)
        data->push_back(static_cast<uint8_t>(i));
    auto arr = make_array(2, 0, {nullptr, data});
    auto sch = make_schema("w:16", "id");
    static const char md[] =
        "\x01\x00\x00\x00"
        "\x14\x00\x00\x00"
        "ARROW:extension:name"
        "\x0A\x00\x00\x00"
        "arrow.uuid";
    sch.metadata = md;
    append_ok(buf, "t_uuid", arr, sch);
}

TEST_CASE("arrow ingress: FixedSizeBinary(16) without UUID metadata → ArrowUnsupportedColumnKind")
{
    auto buf = qdb::line_sender_buffer::qwp_ws();
    auto data = std::make_shared<std::vector<uint8_t>>(std::vector<uint8_t>(16, 0));
    auto arr = make_array(1, 0, {nullptr, data});
    auto sch = make_schema("w:16", "id");
    append_expect_error(
        buf,
        "t_unsup",
        arr,
        sch,
        qdb::line_sender_error_code::arrow_unsupported_column_kind);
}

TEST_CASE("arrow ingress: FixedSizeBinary(32) → column_long256")
{
    auto buf = qdb::line_sender_buffer::qwp_ws();
    auto data = std::make_shared<std::vector<uint8_t>>(std::vector<uint8_t>(64, 0xAB));
    auto arr = make_array(2, 0, {nullptr, data});
    auto sch = make_schema("w:32", "l256");
    append_ok(buf, "t_l256", arr, sch);
}

TEST_CASE("arrow ingress: Timestamp(µs) / Timestamp(ns) / Timestamp(ms)")
{
    auto build_ts_col = [](const char* fmt, int64_t v0, int64_t v1) {
        auto buf = qdb::line_sender_buffer::qwp_ws();
        auto col = pack_le<int64_t>({v0, v1});
        auto arr = make_array(2, 0, {nullptr, col});
        auto sch = make_schema(fmt, "ts");
        append_ok(buf, "t_ts", arr, sch);
    };
    build_ts_col("tsu:UTC", 1700000000000000LL, 1700000000000001LL);
    build_ts_col("tsn:UTC", 1700000000000000000LL, 1700000000000000001LL);
    build_ts_col("tsm:UTC", 1700000000000LL, 1700000000001LL);
}

// ---------------------------------------------------------------------------
// Designated-timestamp dispatch.
// ---------------------------------------------------------------------------

TEST_CASE("arrow ingress: DTS=Column picks per-row ts from the named ts column")
{
    auto buf = qdb::line_sender_buffer::qwp_ws();

    // Two columns: ts (Timestamp µs UTC) + v (Int64).
    auto ts_col = pack_le<int64_t>({1700000000000000LL, 1700000000000001LL});
    auto v_col = pack_le<int64_t>({10, 20});

    auto ts_arr = std::make_unique<ArrowArray>(make_array(2, 0, {nullptr, ts_col}));
    auto v_arr  = std::make_unique<ArrowArray>(make_array(2, 0, {nullptr, v_col}));

    auto ts_sch = std::make_unique<ArrowSchema>(make_schema("tsu:UTC", "ts"));
    auto v_sch  = std::make_unique<ArrowSchema>(make_schema("l", "v"));

    // Build the outer struct.
    Owner* outer_owner = new Owner;
    outer_owner->children_storage.push_back(std::move(ts_arr));
    outer_owner->children_storage.push_back(std::move(v_arr));
    outer_owner->children_ptrs.push_back(outer_owner->children_storage[0].get());
    outer_owner->children_ptrs.push_back(outer_owner->children_storage[1].get());

    ArrowArray outer_arr;
    std::memset(&outer_arr, 0, sizeof(outer_arr));
    outer_arr.length = 2;
    outer_arr.n_buffers = 1; // struct has 1 buffer: the validity bitmap
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

    try
    {
        buf.append_arrow(
            "t_dts_col", outer_arr, outer_sch, qdb::column_name_view{"ts"});
    }
    catch (const qdb::line_sender_error& e)
    {
        FAIL("DTS=Column failed: " << e.what());
    }
    ts_sch->release = nullptr;
    v_sch->release = nullptr;
}

TEST_CASE("arrow ingress: default append omits per-row timestamp (server stamps)")
{
    auto buf = qdb::line_sender_buffer::qwp_ws();
    auto col = pack_le<int64_t>({10, 20});
    auto arr = make_array(2, 0, {nullptr, col});
    auto sch = make_schema("l", "v");
    append_ok(buf, "t_dts_default", arr, sch);
}

// ---------------------------------------------------------------------------
// Decimal dispatch — verifies wire-through to column_dec64 / dec128 / dec.
// ---------------------------------------------------------------------------

TEST_CASE("arrow ingress: Decimal64 / Decimal128 / Decimal256")
{
    // Decimal64 (i64 mantissa, scale=2).
    // Format must carry explicit ",64" — Arrow C Data Interface defaults
    // `"d:p,s"` (no bitwidth) to Decimal128, not Decimal64.
    {
        auto buf = qdb::line_sender_buffer::qwp_ws();
        auto col = pack_le<int64_t>({12345, 67890});
        auto arr = make_array(2, 0, {nullptr, col});
        auto sch = make_schema("d:18,2,64", "d64");
        append_ok(buf, "t_d64", arr, sch);
    }
    // Decimal128 (i128 mantissa, scale=3).
    {
        auto buf = qdb::line_sender_buffer::qwp_ws();
        auto data = std::make_shared<std::vector<uint8_t>>(std::vector<uint8_t>(32, 0));
        auto arr = make_array(2, 0, {nullptr, data});
        auto sch = make_schema("d:38,3", "d128");
        append_ok(buf, "t_d128", arr, sch);
    }
    // Decimal256 (i256 mantissa, scale=5).
    {
        auto buf = qdb::line_sender_buffer::qwp_ws();
        auto data = std::make_shared<std::vector<uint8_t>>(std::vector<uint8_t>(64, 0));
        auto arr = make_array(2, 0, {nullptr, data});
        auto sch = make_schema("d:76,5,256", "d256");
        append_ok(buf, "t_d256", arr, sch);
    }
}

TEST_CASE("arrow ingress: Int32 + questdb.geohash_bits routes to column_geohash")
{
    auto buf = qdb::line_sender_buffer::qwp_ws();
    auto col = pack_le<int32_t>({0x1FFFF, 0x10000});
    auto arr = make_array(2, 0, {nullptr, col});
    auto sch = make_schema("i", "g");
    static const char md[] =
        "\x01\x00\x00\x00"
        "\x14\x00\x00\x00" "questdb.geohash_bits"
        "\x02\x00\x00\x00" "20";
    sch.metadata = md;
    append_ok(buf, "t_geo", arr, sch);
}
