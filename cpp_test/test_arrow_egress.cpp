// Mock-server-driven exhaustive tests for the Arrow C Data Interface
// egress export. Drives `reader_cursor_next_arrow_batch` against
// `qwp_mock_server` (the same in-process WebSocket+QWP1 mock used by
// `test_reader_mock.cpp`) so every assertion runs without a live
// QuestDB instance.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "qwp_mock_server.hpp"

#include <questdb/egress/reader.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace qm = qwp_mock;
namespace egress = questdb::egress;
namespace ingress = questdb::ingress;

namespace
{

template <typename T>
std::vector<uint8_t> pack_le(const std::vector<T>& vs)
{
    std::vector<uint8_t> out;
    out.reserve(vs.size() * sizeof(T));
    for (T v : vs)
    {
        const uint8_t* p = reinterpret_cast<const uint8_t*>(&v);
        out.insert(out.end(), p, p + sizeof(T));
    }
    return out;
}

// `reader + cursor` pair against an in-process mock. Move-only; both
// members RAII-release through their C++ wrappers.
struct ReaderHandles
{
    egress::reader reader;
    egress::cursor cursor;
};

ReaderHandles open_cursor(const qm::MockServer& srv, const char* sql)
{
    const std::string conf = "ws::addr=" + srv.addr() + ";";
    egress::reader r{ingress::utf8_view{conf.data(), conf.size()}};
    auto c = r.execute(ingress::utf8_view{sql, std::strlen(sql)});
    return {std::move(r), std::move(c)};
}

// Depth-first sanity check that every child in the array/schema tree has
// a release callback set.
void assert_release_chain_present(ArrowArray* a, ArrowSchema* s)
{
    REQUIRE(static_cast<bool>(a->release));
    REQUIRE(static_cast<bool>(s->release));
    for (int64_t i = 0; i < a->n_children; ++i)
    {
        REQUIRE(a->children[i] != nullptr);
        REQUIRE(static_cast<bool>(a->children[i]->release));
    }
    for (int64_t i = 0; i < s->n_children; ++i)
    {
        REQUIRE(s->children[i] != nullptr);
        REQUIRE(static_cast<bool>(s->children[i]->release));
    }
}

void release_pair(ArrowArray* a, ArrowSchema* s)
{
    if (a->release)
        a->release(a);
    if (s->release)
        s->release(s);
}

} // namespace

// ---------------------------------------------------------------------------
// Smoke — handshake + empty result drives tristate to `_end` cleanly.
// ---------------------------------------------------------------------------

TEST_CASE("arrow egress: empty stream returns _end without touching out_*")
{
    qm::Script s = {
        qm::ActionSendServerInfo{qm::ROLE_PRIMARY, "tc", "n1"},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto h = open_cursor(srv, "select 1 from t");

    // `next_arrow_batch` snapshots schema eagerly. With ZERO batches the
    // adapter must EITHER:
    //   - throw `reader_error_no_schema` (when QWP protocol path
    //     reaches `as_arrow_reader` with no first batch), OR
    //   - return `nullopt` directly (when the inner pump terminates
    //     first).
    try
    {
        auto b = h.cursor.next_arrow_batch();
        CHECK(!b.has_value());
    }
    catch (const egress::reader_error&)
    {
        // _error path acceptable per the doc.
    }
}

// ---------------------------------------------------------------------------
// Single batch — Long column. Walk ArrowArray and ArrowSchema field-by-field
// and verify the release-callback chain.
// ---------------------------------------------------------------------------

TEST_CASE("arrow egress: single Long batch — struct layout + release order")
{
    qm::ColumnSpec col_v{
        "v", qm::COL_LONG,
        qm::fixed_column_bytes(3, pack_le<int64_t>({10, 20, 30}))};

    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[col_v](int64_t rid) {
            return qm::result_batch_frame(rid, 0, 3, {col_v});
        }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto h = open_cursor(srv, "select v from t");

    auto _b = h.cursor.next_arrow_batch();
    REQUIRE(_b.has_value());
    auto& arr = _b->array;
    auto& sch = _b->schema;

    // The egress export wraps the RecordBatch as a StructArray, so the
    // outer ArrowArray represents the struct with N children.
    CHECK(arr.length == 3);
    CHECK(arr.n_children == 1);
    REQUIRE(arr.children != nullptr);
    REQUIRE(arr.children[0] != nullptr);
    CHECK(arr.children[0]->length == 3);
    CHECK(arr.children[0]->n_buffers == 2); // validity + values

    REQUIRE(sch.format != nullptr);
    CHECK(std::string(sch.format) == "+s"); // struct format code
    CHECK(sch.n_children == 1);
    REQUIRE(sch.children != nullptr);
    REQUIRE(sch.children[0] != nullptr);
    CHECK(std::string(sch.children[0]->format) == "l"); // Int64

    assert_release_chain_present(&arr, &sch);

    // Subsequent call returns _end.
    CHECK(!h.cursor.next_arrow_batch().has_value());

    release_pair(&arr, &sch);
}

// ---------------------------------------------------------------------------
// Per-kind coverage — drive a batch with every primitive kind in one
// schema and verify each child's format code.
// ---------------------------------------------------------------------------

TEST_CASE("arrow egress: mixed kinds — Bool / Byte / Short / Int / Long / Float / Double")
{
    std::vector<uint8_t> bool_body;
    bool_body.push_back(0x00);
    bool_body.push_back(0b00000010); // row0=false, row1=true

    qm::ColumnSpec c_bool{"b", qm::COL_BOOLEAN, std::move(bool_body)};
    qm::ColumnSpec c_byte{
        "by", qm::COL_BYTE, qm::fixed_column_bytes(2, pack_le<int8_t>({-1, 1}))};
    qm::ColumnSpec c_short{
        "sh", qm::COL_SHORT, qm::fixed_column_bytes(2, pack_le<int16_t>({-2, 2}))};
    qm::ColumnSpec c_int{
        "in", qm::COL_INT, qm::fixed_column_bytes(2, pack_le<int32_t>({-3, 3}))};
    qm::ColumnSpec c_long{
        "lo", qm::COL_LONG, qm::fixed_column_bytes(2, pack_le<int64_t>({-4, 4}))};
    qm::ColumnSpec c_f32{
        "f3", qm::COL_FLOAT, qm::fixed_column_bytes(2, pack_le<float>({1.5f, -2.5f}))};
    qm::ColumnSpec c_f64{
        "f6", qm::COL_DOUBLE, qm::fixed_column_bytes(2, pack_le<double>({1.5, -2.5}))};

    auto cols = std::vector<qm::ColumnSpec>{
        c_bool, c_byte, c_short, c_int, c_long, c_f32, c_f64};

    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[cols](int64_t rid) {
            return qm::result_batch_frame(rid, 0, 2, cols);
        }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto h = open_cursor(srv, "select * from t");

    auto _b = h.cursor.next_arrow_batch();
    REQUIRE(_b.has_value());
    auto& arr = _b->array;
    auto& sch = _b->schema;

    CHECK(arr.length == 2);
    CHECK(arr.n_children == 7);
    CHECK(sch.n_children == 7);

    const char* expected_formats[] = {"b", "c", "s", "i", "l", "f", "g"};
    for (int i = 0; i < 7; ++i)
    {
        REQUIRE(sch.children[i] != nullptr);
        CHECK(std::string(sch.children[i]->format) == expected_formats[i]);
        CHECK(arr.children[i]->length == 2);
    }

    release_pair(&arr, &sch);
}

TEST_CASE("arrow egress: TIMESTAMP / TIMESTAMP_NS / DATE — timezone-carrying format codes")
{
    qm::ColumnSpec c_ts{
        "ts", qm::COL_TIMESTAMP,
        qm::fixed_column_bytes(2, pack_le<int64_t>({1700000000000000LL, 1700000000000001LL}))};
    qm::ColumnSpec c_ts_ns{
        "tn", qm::COL_TIMESTAMP_NANOS,
        qm::fixed_column_bytes(2, pack_le<int64_t>({1700000000000000000LL, 1700000000000000001LL}))};
    qm::ColumnSpec c_date{
        "dt", qm::COL_DATE,
        qm::fixed_column_bytes(2, pack_le<int64_t>({1700000000000LL, 1700000000001LL}))};

    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[=](int64_t rid) {
            return qm::result_batch_frame(rid, 0, 2, {c_ts, c_ts_ns, c_date});
        }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto h = open_cursor(srv, "select * from t");

    auto _b = h.cursor.next_arrow_batch();
    REQUIRE(_b.has_value());
    auto& arr = _b->array;
    auto& sch = _b->schema;

    CHECK(sch.n_children == 3);
    REQUIRE(sch.children[0]->format != nullptr);
    REQUIRE(sch.children[1]->format != nullptr);
    REQUIRE(sch.children[2]->format != nullptr);
    // Apache Arrow timestamp format codes: tsu:UTC / tsn:UTC / tsm:UTC.
    CHECK(std::string(sch.children[0]->format).find("tsu") == 0);
    CHECK(std::string(sch.children[1]->format).find("tsn") == 0);
    CHECK(std::string(sch.children[2]->format).find("tsm") == 0);

    release_pair(&arr, &sch);
}

TEST_CASE("arrow egress: VARCHAR + BINARY — variable-length format codes")
{
    qm::ColumnSpec c_v{
        "v", qm::COL_VARCHAR,
        qm::varlen_column_bytes({{'a'}, {}, {'b', 'c'}})};
    qm::ColumnSpec c_b{
        "b", qm::COL_BINARY,
        qm::varlen_column_bytes({{0x01}, {}, {0xFF, 0x00}})};

    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[=](int64_t rid) {
            return qm::result_batch_frame(rid, 0, 3, {c_v, c_b});
        }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto h = open_cursor(srv, "select * from t");

    auto _b = h.cursor.next_arrow_batch();
    REQUIRE(_b.has_value());
    auto& arr = _b->array;
    auto& sch = _b->schema;

    CHECK(sch.n_children == 2);
    CHECK(std::string(sch.children[0]->format) == "u"); // Utf8
    CHECK(std::string(sch.children[1]->format) == "z"); // Binary

    // VARCHAR / BINARY arrays have 3 buffers: validity, offsets, values.
    CHECK(arr.children[0]->n_buffers == 3);
    CHECK(arr.children[1]->n_buffers == 3);

    release_pair(&arr, &sch);
}

TEST_CASE("arrow egress: UUID — FixedSizeBinary(16) with arrow.uuid extension metadata")
{
    std::vector<uint8_t> raw;
    for (int i = 0; i < 32; ++i)
        raw.push_back(static_cast<uint8_t>(i));
    qm::ColumnSpec c_uuid{"id", qm::COL_UUID, qm::fixed_column_bytes(2, raw)};

    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[=](int64_t rid) {
            return qm::result_batch_frame(rid, 0, 2, {c_uuid});
        }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto h = open_cursor(srv, "select id from t");

    auto _b = h.cursor.next_arrow_batch();
    REQUIRE(_b.has_value());
    auto& arr = _b->array;
    auto& sch = _b->schema;

    REQUIRE(sch.children[0]->format != nullptr);
    CHECK(std::string(sch.children[0]->format) == "w:16"); // FixedSizeBinary(16)

    // Metadata is encoded as a length-prefixed byte buffer in the spec. We
    // don't decode it here exhaustively — but it MUST be non-NULL because
    // the egress side stamps `ARROW:extension:name=arrow.uuid` on UUID
    // fields.
    CHECK(sch.children[0]->metadata != nullptr);

    release_pair(&arr, &sch);
}

TEST_CASE("arrow egress: LONG256 — FixedSizeBinary(32)")
{
    std::vector<uint8_t> raw(64, 0xAA);
    qm::ColumnSpec c_l256{"l", qm::COL_LONG256, qm::fixed_column_bytes(2, raw)};

    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[=](int64_t rid) {
            return qm::result_batch_frame(rid, 0, 2, {c_l256});
        }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto h = open_cursor(srv, "select l from t");

    auto _b = h.cursor.next_arrow_batch();
    REQUIRE(_b.has_value());
    auto& arr = _b->array;
    auto& sch = _b->schema;
    CHECK(std::string(sch.children[0]->format) == "w:32");

    release_pair(&arr, &sch);
}

TEST_CASE("arrow egress: SYMBOL — Dictionary(UInt32, Utf8) with questdb.symbol metadata")
{
    qm::ColumnSpec c_sym{
        "sym", qm::COL_SYMBOL,
        qm::symbol_column_bytes({0u, 1u, 0u})};

    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[=](int64_t rid) {
            return qm::result_batch_frame_with_dict(
                rid, 0, 3, {c_sym},
                /*dict_delta_start=*/0,
                {"alpha", "beta"});
        }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto h = open_cursor(srv, "select sym from t");

    auto _b = h.cursor.next_arrow_batch();
    REQUIRE(_b.has_value());
    auto& arr = _b->array;
    auto& sch = _b->schema;

    REQUIRE(sch.children[0]->format != nullptr);
    // Dictionary-encoded — Arrow encodes the keys' format ("I" for UInt32)
    // and exposes the values dictionary via .dictionary.
    REQUIRE(sch.children[0]->dictionary != nullptr);
    REQUIRE(arr.children[0]->dictionary != nullptr);
    CHECK(std::string(sch.children[0]->dictionary->format) == "u"); // Utf8

    release_pair(&arr, &sch);
}

TEST_CASE("arrow egress: DECIMAL64 / DECIMAL128 / DECIMAL256 — decimal format codes")
{
    qm::ColumnSpec c_d64{"d64", qm::COL_DECIMAL64,
                        qm::decimal64_column_bytes({12345, 6789}, 2)};

    std::vector<std::array<uint8_t, 16>> dec128_values(2);
    qm::ColumnSpec c_d128{"d128", qm::COL_DECIMAL128,
                          qm::decimal128_column_bytes(dec128_values, 5)};

    std::vector<std::array<uint8_t, 32>> dec256_values(2);
    qm::ColumnSpec c_d256{"d256", qm::COL_DECIMAL256,
                          qm::decimal256_column_bytes(dec256_values, 7)};

    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[=](int64_t rid) {
            return qm::result_batch_frame(rid, 0, 2, {c_d64, c_d128, c_d256});
        }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto h = open_cursor(srv, "select * from t");

    auto _b = h.cursor.next_arrow_batch();
    REQUIRE(_b.has_value());
    auto& arr = _b->array;
    auto& sch = _b->schema;

    // Arrow decimal format: "d:precision,scale" or "d:precision,scale,bitwidth".
    REQUIRE(sch.children[0]->format != nullptr);
    REQUIRE(sch.children[1]->format != nullptr);
    REQUIRE(sch.children[2]->format != nullptr);
    CHECK(std::string(sch.children[0]->format).rfind("d:", 0) == 0);
    CHECK(std::string(sch.children[1]->format).rfind("d:", 0) == 0);
    CHECK(std::string(sch.children[2]->format).rfind("d:", 0) == 0);

    release_pair(&arr, &sch);
}

TEST_CASE("arrow egress: DOUBLE_ARRAY — nested List(Float64)")
{
    std::vector<std::optional<qm::ArrayRow>> rows = {
        qm::ArrayRow{{3}, pack_le<double>({1.0, 2.0, 3.0})},
        qm::ArrayRow{{2}, pack_le<double>({10.0, 20.0})},
    };
    qm::ColumnSpec c_arr{"a", qm::COL_DOUBLE_ARRAY,
                         qm::array_column_bytes(rows)};

    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[=](int64_t rid) {
            return qm::result_batch_frame(rid, 0, 2, {c_arr});
        }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto h = open_cursor(srv, "select a from t");

    auto _b = h.cursor.next_arrow_batch();
    REQUIRE(_b.has_value());
    auto& arr = _b->array;
    auto& sch = _b->schema;

    // List(Float64) — format "+l" with a single child of format "g".
    REQUIRE(sch.children[0]->format != nullptr);
    CHECK(std::string(sch.children[0]->format) == "+l");
    REQUIRE(sch.children[0]->n_children == 1);
    REQUIRE(sch.children[0]->children[0] != nullptr);
    CHECK(std::string(sch.children[0]->children[0]->format) == "g");

    release_pair(&arr, &sch);
}

// ---------------------------------------------------------------------------
// Tristate contract — on _end / _error the out_array / out_schema MUST
// stay untouched.
// ---------------------------------------------------------------------------

TEST_CASE("arrow egress: stream exhaustion — second call returns nullopt")
{
    qm::ColumnSpec c{"v", qm::COL_LONG,
                     qm::fixed_column_bytes(1, pack_le<int64_t>({42}))};
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[=](int64_t rid) {
            return qm::result_batch_frame(rid, 0, 1, {c});
        }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto h = open_cursor(srv, "select v from t");

    auto first = h.cursor.next_arrow_batch();
    REQUIRE(first.has_value());
    release_pair(&first->array, &first->schema);

    CHECK(!h.cursor.next_arrow_batch().has_value());
}

// Since #156 the schema rides batch 0 only; continuation batches reuse it,
// so a continuation batch can no longer declare a different column dtype,
// name, or count. The one schema dimension that is still inferred per-batch
// is array ndim (derived from each batch's row shapes, not the query
// schema), so that is the only mid-stream drift the streaming Arrow adapter
// can observe end-to-end.
TEST_CASE("arrow egress: schema drift — array ndim change between batches throws schema_drift")
{
    std::vector<std::optional<qm::ArrayRow>> b1_rows = {
        qm::ArrayRow{{3}, pack_le<double>({1.0, 2.0, 3.0})}};
    std::vector<std::optional<qm::ArrayRow>> b2_rows = {
        qm::ArrayRow{{2, 2}, pack_le<double>({1.0, 2.0, 3.0, 4.0})}};
    qm::ColumnSpec b1_col{
        "a", qm::COL_DOUBLE_ARRAY, qm::array_column_bytes(b1_rows)};
    qm::ColumnSpec b2_col{
        "a", qm::COL_DOUBLE_ARRAY, qm::array_column_bytes(b2_rows)};
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[b1_col](int64_t rid) {
            return qm::result_batch_frame(rid, 0, 1, {b1_col});
        }},
        qm::ActionSendBuilt{[b2_col](int64_t rid) {
            return qm::result_batch_frame(rid, 1, 1, {b2_col});
        }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto h = open_cursor(srv, "select a from t");

    auto first = h.cursor.next_arrow_batch();
    REQUIRE(first.has_value());
    CHECK(std::string(first->schema.children[0]->format) == "+l"); // 1-D List
    release_pair(&first->array, &first->schema);

    try
    {
        (void)h.cursor.next_arrow_batch();
        FAIL("expected schema_drift on second batch with changed array ndim");
    }
    catch (const egress::reader_error& e)
    {
        CHECK(e.code() == egress::error_code::schema_drift);
    }
}

// Batch 0's only array row is null, so ndim can't be inferred and the field
// is marked tentative. A later firm batch refines ndim; the streaming
// adapter accepts this as an upgrade (`schemas_equal` ignores ndim while
// either side is tentative) rather than rejecting it as drift.
TEST_CASE("arrow egress: schema drift — tentative→firm array ndim upgrade does NOT drift")
{
    std::vector<std::optional<qm::ArrayRow>> b1_rows = {std::nullopt};
    std::vector<std::optional<qm::ArrayRow>> b2_rows = {
        qm::ArrayRow{{3}, pack_le<double>({1.0, 2.0, 3.0})}};
    qm::ColumnSpec b1_col{
        "a", qm::COL_DOUBLE_ARRAY, qm::array_column_bytes(b1_rows)};
    qm::ColumnSpec b2_col{
        "a", qm::COL_DOUBLE_ARRAY, qm::array_column_bytes(b2_rows)};
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[b1_col](int64_t rid) {
            return qm::result_batch_frame(rid, 0, 1, {b1_col});
        }},
        qm::ActionSendBuilt{[b2_col](int64_t rid) {
            return qm::result_batch_frame(rid, 1, 1, {b2_col});
        }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto h = open_cursor(srv, "select a from t");

    auto first = h.cursor.next_arrow_batch();
    REQUIRE(first.has_value());
    release_pair(&first->array, &first->schema);

    auto second = h.cursor.next_arrow_batch();
    REQUIRE(second.has_value());
    CHECK(std::string(second->schema.children[0]->format) == "+l"); // 1-D List
    release_pair(&second->array, &second->schema);

    CHECK(!h.cursor.next_arrow_batch().has_value());
}

TEST_CASE("arrow egress: schema drift — same schema across batches does NOT drift")
{
    qm::ColumnSpec b_col{
        "v", qm::COL_LONG,
        qm::fixed_column_bytes(2, pack_le<int64_t>({10, 20}))};
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[b_col](int64_t rid) {
            return qm::result_batch_frame(rid, 0, 2, {b_col});
        }},
        qm::ActionSendBuilt{[b_col](int64_t rid) {
            return qm::result_batch_frame(rid, 1, 2, {b_col});
        }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto h = open_cursor(srv, "select v from t");

    auto first = h.cursor.next_arrow_batch();
    REQUIRE(first.has_value());
    release_pair(&first->array, &first->schema);

    auto second = h.cursor.next_arrow_batch();
    REQUIRE(second.has_value());
    CHECK(second->array.length == 2);
    release_pair(&second->array, &second->schema);

    CHECK(!h.cursor.next_arrow_batch().has_value());
}

// Tristate / NULL-pointer contract tests for the C ABI live in
// `test_arrow_c.c`. The C++ wrapper returns `std::optional<arrow_batch>`
// directly, so those cases are unrepresentable at the call site.
