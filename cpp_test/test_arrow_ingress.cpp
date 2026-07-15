// FFI-boundary test for the C++ wrapper `sender_view::flush_arrow_batch`
// over the conn-level Arrow batch ingest API.
//
// This layer is a thin, type-agnostic forwarder: it packs `table_name_view` /
// `column_name_view` into the C structs, passes the `ArrowArray*` / `ArrowSchema*`
// through to the C ABI, and translates a C error into a thrown
// `line_sender_error`. So the only things it can get wrong are argument
// marshalling and error translation — which is all this file covers:
//   * error / NULL paths (wrong conn, NULL array/schema, empty name);
//   * happy publish-only, FSN-returning, and ACKing Arrow flushes to prove
//     the marshalling paths reach the C ABI.
//
// Per-type Arrow->column classification is backend-agnostic Rust code, exercised
// exhaustively in `questdb-rs/src/ingress/qwp_sender/arrow_batch.rs` and
// round-tripped in C in `cpp_test/test_arrow_c.c`; re-testing it per type here
// would add no coverage.

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

TEST_CASE("sender_view::flush_arrow_batch rejects NULL conn")
{
    ArrowArray arr;
    ArrowSchema sch;
    std::memset(&arr, 0, sizeof(arr));
    std::memset(&sch, 0, sizeof(sch));

    qdb::sender_view conn{nullptr};
    CHECK_THROWS_AS(
        conn.flush_arrow_batch_at_now("t"_tn, arr, sch),
        qdb::line_sender_error);
}

TEST_CASE("sender_view::flush_arrow_batch at_column rejects NULL conn")
{
    ArrowArray arr;
    ArrowSchema sch;
    std::memset(&arr, 0, sizeof(arr));
    std::memset(&sch, 0, sizeof(sch));

    qdb::sender_view conn{nullptr};
    CHECK_THROWS_AS(
        conn.flush_arrow_batch("t"_tn, arr, sch, "ts"_cn),
        qdb::line_sender_error);
}

TEST_CASE("sender_view surfaces error_code on NULL-conn failure")
{
    ArrowArray arr;
    ArrowSchema sch;
    std::memset(&arr, 0, sizeof(arr));
    std::memset(&sch, 0, sizeof(sch));

    qdb::sender_view conn{nullptr};
    try
    {
        conn.flush_arrow_batch_at_now("t"_tn, arr, sch);
        FAIL("expected throw");
    }
    catch (const qdb::line_sender_error& e)
    {
        CHECK(e.code() == qdb::line_sender_error_code::invalid_api_call);
    }
}

namespace
{

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
        if (child_ptr && child_ptr->release)
            child_ptr->release(child_ptr.get());
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

// RAII helper: starts a mock + opens a 1-slot store-and-forward db + borrows a
// conn. `close_flush_timeout_millis=0` disables the close-drain wait, so a
// successful flush followed by teardown does not block on the non-acking mock.
struct MockConn
{
    qm::MockServer server;
    questdb_db* db = nullptr;
    qwp_sender* conn = nullptr;

    explicit MockConn(qm::Script script = qm::Script{qm::ActionAwaitClientFrame{0x51}})
        : server(std::vector<qm::Script>{std::move(script)})
    {
        const std::string conf = "ws::addr=" + server.addr() +
            ";sender_pool_min=1;pool_reap=manual;close_flush_timeout_millis=0;";
        line_sender_error* err = nullptr;
        db = questdb_db_connect(conf.c_str(), conf.size(), &err);
        REQUIRE(db != nullptr);
        REQUIRE(err == nullptr);
        conn = questdb_db_borrow_sender(db, &err);
        REQUIRE(conn != nullptr);
        REQUIRE(err == nullptr);
    }

    ~MockConn()
    {
        if (db != nullptr)
        {
            if (conn != nullptr)
                questdb_db_drop_sender(db, conn);
            questdb_db_close(db);
        }
    }

    MockConn(const MockConn&) = delete;
    MockConn& operator=(const MockConn&) = delete;
};

} // namespace

TEST_CASE("flush_arrow_batch: NULL array -> invalid_api_call")
{
    MockConn mc;
    ArrowSchema sch;
    std::memset(&sch, 0, sizeof(sch));
    line_sender_error* err = nullptr;
    line_sender_table_name tbl{1, "t"};
    bool ok = qwp_sender_flush_arrow_batch_at_now(
        mc.conn, tbl, nullptr, &sch, nullptr, 0, &err);
    CHECK_FALSE(ok);
    REQUIRE(err != nullptr);
    CHECK(line_sender_error_get_code(err) == line_sender_error_invalid_api_call);
    line_sender_error_free(err);
}

TEST_CASE("flush_arrow_batch: NULL schema -> invalid_api_call")
{
    MockConn mc;
    ArrowArray arr;
    std::memset(&arr, 0, sizeof(arr));
    line_sender_error* err = nullptr;
    line_sender_table_name tbl{1, "t"};
    bool ok = qwp_sender_flush_arrow_batch_at_now(
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

// Happy path: a valid batch marshals through the wrapper to the C ABI and is
// accepted (the SF flush encodes synchronously, so a clean return means the
// arguments reached and satisfied the C ABI).
TEST_CASE("flush_arrow_batch_at_now: happy path marshals through to the C ABI")
{
    MockConn mc;
    qdb::sender_view conn{mc.conn};

    auto col = pack_le<int64_t>({10, 20, 30});
    auto arr = make_array(3, 0, {nullptr, col});
    auto sch = make_schema("l", "v");
    try
    {
        const auto fsn =
            conn.flush_arrow_batch_at_now_and_get_fsn("t_at_now"_tn, arr, sch);
        REQUIRE(fsn.has_value());
        CHECK(conn.published_fsn() == fsn);
    }
    catch (const qdb::line_sender_error& e)
    {
        FAIL("flush_arrow_batch_at_now threw: " << e.what());
    }
}

TEST_CASE("borrowed_sender exposes Arrow FSN helper")
{
    qm::MockServer server(std::vector<qm::Script>{
        qm::Script{qm::ActionAwaitClientFrame{0x51}}});
    questdb::pool db{
        "ws::addr=" + server.addr() +
        ";sender_pool_min=1;pool_reap=manual;close_flush_timeout_millis=0;"};
    auto conn = db.borrow_sender();

    auto col = pack_le<int64_t>({10, 20, 30});
    auto arr = make_array(3, 0, {nullptr, col});
    auto sch = make_schema("l", "v");
    try
    {
        const auto fsn =
            conn.flush_arrow_batch_at_now_and_get_fsn("t_borrowed"_tn, arr, sch);
        REQUIRE(fsn.has_value());
        CHECK(conn.published_fsn() == fsn);
    }
    catch (const qdb::line_sender_error& e)
    {
        FAIL("borrowed Arrow FSN flush threw: " << e.what());
    }
    conn.drop_on_return();
}

TEST_CASE("qwp_sender_flush_arrow_batch_at_now_and_wait: C ABI happy path")
{
    MockConn mc{qm::Script{
        qm::ActionAwaitClientFrame{0x51},
        qm::ActionSendRaw{qm::ingress_ok_frame()}}};

    auto col = pack_le<int64_t>({10, 20, 30});
    auto arr = make_array(3, 0, {nullptr, col});
    auto sch = make_schema("l", "v");
    line_sender_error* err = nullptr;
    line_sender_table_name tbl{6, "t_wait"};
    const bool ok = qwp_sender_flush_arrow_batch_at_now_and_wait(
        mc.conn,
        tbl,
        &arr,
        &sch,
        nullptr,
        0,
        qwpws_ack_level_ok,
        &err);
    CHECK(ok);
    CHECK(err == nullptr);
    CHECK_FALSE(static_cast<bool>(arr.release));
}

TEST_CASE("borrowed_sender exposes Arrow ACKing helpers")
{
    qm::MockServer server(std::vector<qm::Script>{qm::Script{
        qm::ActionAwaitClientFrame{0x51},
        qm::ActionSendRaw{qm::ingress_ok_frame(0)},
        qm::ActionAwaitClientFrame{0x51},
        qm::ActionSendRaw{qm::ingress_ok_frame(1)}}});
    questdb::pool db{
        "ws::addr=" + server.addr() +
        ";sender_pool_min=1;pool_reap=manual;close_flush_timeout_millis=0;"};
    auto conn = db.borrow_sender();

    auto col = pack_le<int64_t>({10, 20, 30});
    auto arr = make_array(3, 0, {nullptr, col});
    auto sch = make_schema("l", "v");
    try
    {
        conn.flush_arrow_batch_at_now_and_wait("t_wait_now"_tn, arr, sch);
        CHECK_FALSE(static_cast<bool>(arr.release));
    }
    catch (const qdb::line_sender_error& e)
    {
        FAIL("borrowed Arrow at-now ACKing flush threw: " << e.what());
    }

    auto ts_col = pack_le<int64_t>(
        {1700000000000000LL, 1700000000000001LL});
    auto v_col = pack_le<int64_t>({10, 20});

    auto ts_arr =
        std::make_unique<ArrowArray>(make_array(2, 0, {nullptr, ts_col}));
    auto v_arr =
        std::make_unique<ArrowArray>(make_array(2, 0, {nullptr, v_col}));
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
    outer_arr.n_buffers = 1;
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
        conn.flush_arrow_batch_and_wait(
            "t_wait_col"_tn, outer_arr, outer_sch, "ts"_cn);
        CHECK_FALSE(static_cast<bool>(outer_arr.release));
    }
    catch (const qdb::line_sender_error& e)
    {
        FAIL("borrowed Arrow at-column ACKing flush threw: " << e.what());
    }
    ts_sch->release = nullptr;
    v_sch->release = nullptr;
    conn.drop_on_return();
}

// Happy path for the second marshalling path: the designated timestamp is taken
// from a named Timestamp column of a struct batch.
TEST_CASE("flush_arrow_batch (at_column): happy path picks ts from named column")
{
    MockConn mc;

    auto ts_col = pack_le<int64_t>(
        {1700000000000000LL, 1700000000000001LL});
    auto v_col = pack_le<int64_t>({10, 20});

    auto ts_arr =
        std::make_unique<ArrowArray>(make_array(2, 0, {nullptr, ts_col}));
    auto v_arr =
        std::make_unique<ArrowArray>(make_array(2, 0, {nullptr, v_col}));
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
    outer_arr.n_buffers = 1;
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

    qdb::sender_view conn{mc.conn};
    try
    {
        const auto fsn = conn.flush_arrow_batch_and_get_fsn(
            "t_at_col"_tn, outer_arr, outer_sch, "ts"_cn);
        REQUIRE(fsn.has_value());
        CHECK(conn.published_fsn() == fsn);
    }
    catch (const qdb::line_sender_error& e)
    {
        FAIL("flush_arrow_batch (at_column) threw: " << e.what());
    }
    ts_sch->release = nullptr;
    v_sch->release = nullptr;
}
