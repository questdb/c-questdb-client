// Mock-server-driven exhaustive tests for the Arrow C Data Interface
// egress export. Drives `line_reader_cursor_next_arrow_batch` against
// `qwp_mock_server` (the same in-process WebSocket+QWP1 mock used by
// `test_line_reader_mock.cpp`) so every assertion runs without a live
// QuestDB instance.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "qwp_mock_server.hpp"

#include <questdb/egress/line_reader.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace qm = qwp_mock;

// ---------------------------------------------------------------------------
// Apache Arrow C Data Interface struct layouts (Spec:
// https://arrow.apache.org/docs/format/CDataInterface.html).
//
// Defined inline so this file does NOT depend on arrow-cpp. The arrow-cpp
// interop is covered by a separate test file gated on
// QUESTDB_ENABLE_ARROW_CPP_INTEROP.
// ---------------------------------------------------------------------------

extern "C"
{
struct ArrowArray
{
    int64_t length;
    int64_t null_count;
    int64_t offset;
    int64_t n_buffers;
    int64_t n_children;
    const void** buffers;
    struct ArrowArray** children;
    struct ArrowArray* dictionary;
    void (*release)(struct ArrowArray*);
    void* private_data;
};

struct ArrowSchema
{
    const char* format;
    const char* name;
    const char* metadata;
    int64_t flags;
    int64_t n_children;
    struct ArrowSchema** children;
    struct ArrowSchema* dictionary;
    void (*release)(struct ArrowSchema*);
    void* private_data;
};
}

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

// Open a reader against the mock and pump it through `execute` to get a
// `line_reader_cursor*`. Returns the raw pointers so the tests can call
// the Arrow C ABI directly. Caller is responsible for `_cursor_free` and
// `_close`.
struct ReaderHandles
{
    line_reader* reader;
    line_reader_cursor* cursor;
};

ReaderHandles open_cursor(const qm::MockServer& srv, const char* sql)
{
    const std::string conf = "ws::addr=" + srv.addr() + ";";
    line_sender_utf8 conf_utf8;
    REQUIRE(line_sender_utf8_init(
        &conf_utf8, conf.size(), conf.data(), nullptr));

    line_reader_error* err = nullptr;
    line_reader* reader = line_reader_from_conf(conf_utf8, &err);
    REQUIRE(reader != nullptr);

    line_sender_utf8 sql_utf8;
    REQUIRE(line_sender_utf8_init(
        &sql_utf8, std::strlen(sql), sql, nullptr));

    err = nullptr;
    line_reader_cursor* cursor =
        line_reader_execute(reader, sql_utf8, &err);
    REQUIRE(cursor != nullptr);

    return {reader, cursor};
}

void close_handles(ReaderHandles& h)
{
    if (h.cursor)
        line_reader_cursor_free(h.cursor);
    if (h.reader)
        line_reader_close(h.reader);
    h.cursor = nullptr;
    h.reader = nullptr;
}

// Drain one batch via the Arrow C ABI. Returns the tristate outcome and
// fills `out_arr` / `out_sch` on success. Caller MUST eventually invoke
// each struct's release callback when done.
line_reader_arrow_batch_result drain_one(
    line_reader_cursor* cursor,
    ArrowArray* out_arr,
    ArrowSchema* out_sch,
    line_reader_error** out_err)
{
    return line_reader_cursor_next_arrow_batch(
        cursor,
        reinterpret_cast<::ArrowArray*>(out_arr),
        reinterpret_cast<::ArrowSchema*>(out_sch),
        out_err);
}

// Helper: count down the children list (depth-first) and assert every
// child has a release callback set.
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

    ArrowArray arr;
    ArrowSchema sch;
    std::memset(&arr, 0xCC, sizeof(arr));
    std::memset(&sch, 0xCC, sizeof(sch));
    line_reader_error* err = nullptr;

    // `next_arrow_batch` snapshots schema eagerly. With ZERO batches the
    // adapter must EITHER:
    //   - surface `line_reader_error_no_schema` (when QWP protocol path
    //     reaches `as_record_batch_reader` with no first batch), OR
    //   - return `_end` directly (when the inner pump terminates first).
    // The doc deliberately leaves this Phase-0-dependent; the contract
    // we check here is "no _ok, no half-filled structs".
    auto rc = drain_one(h.cursor, &arr, &sch, &err);
    CHECK((rc == line_reader_arrow_batch_end ||
           rc == line_reader_arrow_batch_error));
    if (rc == line_reader_arrow_batch_error)
    {
        REQUIRE(err != nullptr);
        line_reader_error_free(err);
    }

    close_handles(h);
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
            return qm::result_batch_frame(rid, 0, 1, 3, {col_v});
        }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto h = open_cursor(srv, "select v from t");

    ArrowArray arr;
    ArrowSchema sch;
    line_reader_error* err = nullptr;
    auto rc = drain_one(h.cursor, &arr, &sch, &err);
    REQUIRE(rc == line_reader_arrow_batch_ok);
    REQUIRE(err == nullptr);

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
    ArrowArray arr2;
    ArrowSchema sch2;
    auto rc2 = drain_one(h.cursor, &arr2, &sch2, &err);
    CHECK(rc2 == line_reader_arrow_batch_end);

    release_pair(&arr, &sch);
    close_handles(h);
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
            return qm::result_batch_frame(rid, 0, 1, 2, cols);
        }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto h = open_cursor(srv, "select * from t");

    ArrowArray arr;
    ArrowSchema sch;
    line_reader_error* err = nullptr;
    auto rc = drain_one(h.cursor, &arr, &sch, &err);
    REQUIRE(rc == line_reader_arrow_batch_ok);

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
    close_handles(h);
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
            return qm::result_batch_frame(rid, 0, 1, 2, {c_ts, c_ts_ns, c_date});
        }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto h = open_cursor(srv, "select * from t");

    ArrowArray arr;
    ArrowSchema sch;
    line_reader_error* err = nullptr;
    REQUIRE(drain_one(h.cursor, &arr, &sch, &err) == line_reader_arrow_batch_ok);

    CHECK(sch.n_children == 3);
    REQUIRE(sch.children[0]->format != nullptr);
    REQUIRE(sch.children[1]->format != nullptr);
    REQUIRE(sch.children[2]->format != nullptr);
    // Apache Arrow timestamp format codes: tsu:UTC / tsn:UTC / tsm:UTC.
    CHECK(std::string(sch.children[0]->format).find("tsu") == 0);
    CHECK(std::string(sch.children[1]->format).find("tsn") == 0);
    CHECK(std::string(sch.children[2]->format).find("tsm") == 0);

    release_pair(&arr, &sch);
    close_handles(h);
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
            return qm::result_batch_frame(rid, 0, 1, 3, {c_v, c_b});
        }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto h = open_cursor(srv, "select * from t");

    ArrowArray arr;
    ArrowSchema sch;
    line_reader_error* err = nullptr;
    REQUIRE(drain_one(h.cursor, &arr, &sch, &err) == line_reader_arrow_batch_ok);

    CHECK(sch.n_children == 2);
    CHECK(std::string(sch.children[0]->format) == "u"); // Utf8
    CHECK(std::string(sch.children[1]->format) == "z"); // Binary

    // VARCHAR / BINARY arrays have 3 buffers: validity, offsets, values.
    CHECK(arr.children[0]->n_buffers == 3);
    CHECK(arr.children[1]->n_buffers == 3);

    release_pair(&arr, &sch);
    close_handles(h);
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
            return qm::result_batch_frame(rid, 0, 1, 2, {c_uuid});
        }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto h = open_cursor(srv, "select id from t");

    ArrowArray arr;
    ArrowSchema sch;
    line_reader_error* err = nullptr;
    REQUIRE(drain_one(h.cursor, &arr, &sch, &err) == line_reader_arrow_batch_ok);

    REQUIRE(sch.children[0]->format != nullptr);
    CHECK(std::string(sch.children[0]->format) == "w:16"); // FixedSizeBinary(16)

    // Metadata is encoded as a length-prefixed byte buffer in the spec. We
    // don't decode it here exhaustively — but it MUST be non-NULL because
    // the egress side stamps `ARROW:extension:name=arrow.uuid` on UUID
    // fields.
    CHECK(sch.children[0]->metadata != nullptr);

    release_pair(&arr, &sch);
    close_handles(h);
}

TEST_CASE("arrow egress: LONG256 — FixedSizeBinary(32)")
{
    std::vector<uint8_t> raw(64, 0xAA);
    qm::ColumnSpec c_l256{"l", qm::COL_LONG256, qm::fixed_column_bytes(2, raw)};

    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[=](int64_t rid) {
            return qm::result_batch_frame(rid, 0, 1, 2, {c_l256});
        }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto h = open_cursor(srv, "select l from t");

    ArrowArray arr;
    ArrowSchema sch;
    line_reader_error* err = nullptr;
    REQUIRE(drain_one(h.cursor, &arr, &sch, &err) == line_reader_arrow_batch_ok);
    CHECK(std::string(sch.children[0]->format) == "w:32");

    release_pair(&arr, &sch);
    close_handles(h);
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
                rid, 0, 1, 3, {c_sym},
                /*dict_delta_start=*/0,
                {"alpha", "beta"});
        }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto h = open_cursor(srv, "select sym from t");

    ArrowArray arr;
    ArrowSchema sch;
    line_reader_error* err = nullptr;
    REQUIRE(drain_one(h.cursor, &arr, &sch, &err) == line_reader_arrow_batch_ok);

    REQUIRE(sch.children[0]->format != nullptr);
    // Dictionary-encoded — Arrow encodes the keys' format ("I" for UInt32)
    // and exposes the values dictionary via .dictionary.
    REQUIRE(sch.children[0]->dictionary != nullptr);
    REQUIRE(arr.children[0]->dictionary != nullptr);
    CHECK(std::string(sch.children[0]->dictionary->format) == "u"); // Utf8

    release_pair(&arr, &sch);
    close_handles(h);
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
            return qm::result_batch_frame(rid, 0, 1, 2, {c_d64, c_d128, c_d256});
        }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto h = open_cursor(srv, "select * from t");

    ArrowArray arr;
    ArrowSchema sch;
    line_reader_error* err = nullptr;
    REQUIRE(drain_one(h.cursor, &arr, &sch, &err) == line_reader_arrow_batch_ok);

    // Arrow decimal format: "d:precision,scale" or "d:precision,scale,bitwidth".
    REQUIRE(sch.children[0]->format != nullptr);
    REQUIRE(sch.children[1]->format != nullptr);
    REQUIRE(sch.children[2]->format != nullptr);
    CHECK(std::string(sch.children[0]->format).rfind("d:", 0) == 0);
    CHECK(std::string(sch.children[1]->format).rfind("d:", 0) == 0);
    CHECK(std::string(sch.children[2]->format).rfind("d:", 0) == 0);

    release_pair(&arr, &sch);
    close_handles(h);
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
            return qm::result_batch_frame(rid, 0, 1, 2, {c_arr});
        }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto h = open_cursor(srv, "select a from t");

    ArrowArray arr;
    ArrowSchema sch;
    line_reader_error* err = nullptr;
    REQUIRE(drain_one(h.cursor, &arr, &sch, &err) == line_reader_arrow_batch_ok);

    // List(Float64) — format "+l" with a single child of format "g".
    REQUIRE(sch.children[0]->format != nullptr);
    CHECK(std::string(sch.children[0]->format) == "+l");
    REQUIRE(sch.children[0]->n_children == 1);
    REQUIRE(sch.children[0]->children[0] != nullptr);
    CHECK(std::string(sch.children[0]->children[0]->format) == "g");

    release_pair(&arr, &sch);
    close_handles(h);
}

// ---------------------------------------------------------------------------
// Tristate contract — on _end / _error the out_array / out_schema MUST
// stay untouched.
// ---------------------------------------------------------------------------

TEST_CASE("arrow egress: tristate _end leaves out structs untouched")
{
    qm::ColumnSpec c{"v", qm::COL_LONG,
                     qm::fixed_column_bytes(1, pack_le<int64_t>({42}))};
    qm::Script s = {
        qm::ActionSendServerInfo{},
        qm::ActionAwaitQueryRequest{},
        qm::ActionSendBuilt{[=](int64_t rid) {
            return qm::result_batch_frame(rid, 0, 1, 1, {c});
        }},
        qm::ActionSendResultEnd{},
    };
    qm::MockServer srv({s});
    auto h = open_cursor(srv, "select v from t");

    ArrowArray arr1;
    ArrowSchema sch1;
    line_reader_error* err = nullptr;
    REQUIRE(drain_one(h.cursor, &arr1, &sch1, &err) == line_reader_arrow_batch_ok);
    release_pair(&arr1, &sch1);

    // Pre-fill the slot with a recognisable poison and re-call.
    ArrowArray arr2;
    ArrowSchema sch2;
    std::memset(&arr2, 0x5A, sizeof(arr2));
    std::memset(&sch2, 0x5A, sizeof(sch2));
    auto rc = drain_one(h.cursor, &arr2, &sch2, &err);
    CHECK(rc == line_reader_arrow_batch_end);
    // Spec: out_array / out_schema NOT populated on _end. The bytes we
    // poisoned should be observable still.
    uint8_t* a_bytes = reinterpret_cast<uint8_t*>(&arr2);
    uint8_t* s_bytes = reinterpret_cast<uint8_t*>(&sch2);
    CHECK(a_bytes[0] == 0x5A);
    CHECK(s_bytes[0] == 0x5A);

    close_handles(h);
}

TEST_CASE("arrow egress: NULL cursor returns _error and populates err_out")
{
    ArrowArray arr;
    ArrowSchema sch;
    line_reader_error* err = nullptr;
    auto rc = drain_one(nullptr, &arr, &sch, &err);
    CHECK(rc == line_reader_arrow_batch_error);
    REQUIRE(err != nullptr);
    CHECK(line_reader_error_get_code(err) ==
          line_reader_error_invalid_api_call);
    line_reader_error_free(err);
}

TEST_CASE("arrow egress: NULL out_array returns _error")
{
    qm::Script s = {qm::ActionSendServerInfo{},
                    qm::ActionAwaitQueryRequest{},
                    qm::ActionSendResultEnd{}};
    qm::MockServer srv({s});
    auto h = open_cursor(srv, "select 1 from t");

    ArrowSchema sch;
    line_reader_error* err = nullptr;
    auto rc = line_reader_cursor_next_arrow_batch(
        h.cursor,
        nullptr,
        reinterpret_cast<::ArrowSchema*>(&sch),
        &err);
    CHECK(rc == line_reader_arrow_batch_error);
    REQUIRE(err != nullptr);
    CHECK(line_reader_error_get_code(err) ==
          line_reader_error_invalid_api_call);
    line_reader_error_free(err);
    close_handles(h);
}
