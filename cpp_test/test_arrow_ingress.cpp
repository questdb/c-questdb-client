// FFI-boundary test for the C++ wrapper `sender_view::flush_arrow_batch`
// over the conn-level Arrow batch ingest API.
//
// This layer is a thin, type-agnostic forwarder: it packs `table_name_view` /
// `column_name_view` into the C structs, passes the `ArrowArray*` /
// `ArrowSchema*` through to the C ABI, and translates a C error into a thrown
// `line_sender_error`. So the only things it can get wrong are argument
// marshalling and error translation — which is all this file covers:
//   * error / NULL paths (wrong conn, NULL array/schema, empty name);
//   * happy publish-only, FSN-returning, and ACKing Arrow flushes;
//   * failure/re-export, sliced values, and counted producer ownership through
//     the public ABI, including the release-profile native artifact.
//
// Per-type Arrow->column classification is backend-agnostic Rust code,
// exercised exhaustively in `questdb-rs/src/ingress/qwp_sender/arrow_batch.rs`
// and round-tripped in C in `cpp_test/test_arrow_c.c`; re-testing it per type
// here would add no coverage.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "qwp_mock_server.hpp"

#include <questdb/ingress/qwp_sender.h>
#include <questdb/ingress/qwp_sender.hpp>
#include <questdb/ingress/line_sender.hpp>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <vector>

// These existing direct-handle ACKing exports are not declared in qwp_sender.h.
// Exercise their native ABI as well as the public-header entry points below.
extern "C" bool qwp_direct_sender_flush_arrow_batch_at_now_and_wait(
    qwp_direct_sender*,
    line_sender_table_name,
    ArrowArray*,
    const ArrowSchema*,
    const qwp_arrow_override*,
    size_t,
    uint32_t,
    line_sender_error**);
extern "C" bool qwp_direct_sender_flush_arrow_batch_at_column_and_wait(
    qwp_direct_sender*,
    line_sender_table_name,
    ArrowArray*,
    const ArrowSchema*,
    line_sender_column_name,
    const qwp_arrow_override*,
    size_t,
    uint32_t,
    line_sender_error**);

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
    std::unique_ptr<ArrowArray> dictionary_storage;
    std::atomic<int>* release_count = nullptr;
};

void release_owner(ArrowArray* arr)
{
    if (!arr || !arr->private_data)
        return;
    auto* owner = static_cast<Owner*>(arr->private_data);
    if (owner->release_count)
        ++*owner->release_count;
    for (auto& child_ptr : owner->children_storage)
        if (child_ptr && child_ptr->release)
            child_ptr->release(child_ptr.get());
    if (owner->dictionary_storage && owner->dictionary_storage->release)
        owner->dictionary_storage->release(owner->dictionary_storage.get());
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

    explicit MockConn(
        qm::Script script = qm::Script{qm::ActionAwaitClientFrame{0x51}})
        : server(std::vector<qm::Script>{std::move(script)})
    {
        const std::string conf = "ws::addr=" + server.addr() +
                                 ";lazy_connect=true;sender_pool_min=1;pool_"
                                 "reap=manual;close_flush_timeout_millis=0;";
        line_sender_error* err = nullptr;
        db = questdb_db_connect(conf.c_str(), conf.size(), &err);
        REQUIRE(db != nullptr);
        REQUIRE(err == nullptr);
        conn = questdb_db_borrow_sender(db, &err);
        REQUIRE(conn != nullptr);
        REQUIRE(err == nullptr);
    }

    void drop_sender()
    {
        if (conn != nullptr)
        {
            questdb_db_drop_sender(db, conn);
            conn = nullptr;
        }
    }

    ~MockConn()
    {
        if (db != nullptr)
        {
            drop_sender();
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
    CHECK(
        line_sender_error_get_code(err) == line_sender_error_invalid_api_call);
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
    CHECK(
        line_sender_error_get_code(err) == line_sender_error_invalid_api_call);
    line_sender_error_free(err);
}

TEST_CASE(
    "flush_arrow_batch_at_column: empty ts_column_name throws invalid_name")
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
    qm::MockServer server(
        std::vector<qm::Script>{qm::Script{qm::ActionAwaitClientFrame{0x51}}});
    questdb::pool db{
        "ws::addr=" + server.addr() +
        ";lazy_connect=true;sender_pool_min=1;pool_reap=manual;close_flush_"
        "timeout_millis=0;"};
    auto conn = db.borrow_sender();

    auto col = pack_le<int64_t>({10, 20, 30});
    auto arr = make_array(3, 0, {nullptr, col});
    auto sch = make_schema("l", "v");
    try
    {
        const auto fsn = conn.flush_arrow_batch_at_now_and_get_fsn(
            "t_borrowed"_tn, arr, sch);
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
        mc.conn, tbl, &arr, &sch, nullptr, 0, qwpws_ack_level_ok, &err);
    CHECK(ok);
    CHECK(err == nullptr);
    CHECK_FALSE(static_cast<bool>(arr.release));
}

TEST_CASE("borrowed_sender exposes Arrow ACKing helpers")
{
    qm::MockServer server(
        std::vector<qm::Script>{qm::Script{
            qm::ActionAwaitClientFrame{0x51},
            qm::ActionSendRaw{qm::ingress_ok_frame(0)},
            qm::ActionAwaitClientFrame{0x51},
            qm::ActionSendRaw{qm::ingress_ok_frame(1)}}});
    questdb::pool db{
        "ws::addr=" + server.addr() +
        ";lazy_connect=true;sender_pool_min=1;pool_reap=manual;close_flush_"
        "timeout_millis=0;"};
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

    auto ts_col = pack_le<int64_t>({1700000000000000LL, 1700000000000001LL});
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
TEST_CASE(
    "flush_arrow_batch (at_column): happy path picks ts from named column")
{
    MockConn mc;

    auto ts_col = pack_le<int64_t>({1700000000000000LL, 1700000000000001LL});
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

namespace
{

// The producer owns every allocation and counts each node's release separately.
// Schema storage stays put through retries; only ArrowArray ownership moves.
struct CountedArrow
{
    ArrowArray array{};
    ArrowSchema schemas[3]{};
    ArrowSchema* schema_children[3]{};
    std::atomic<int> releases[3]{};
    size_t nodes = 0;

    explicit CountedArrow(const std::string& kind = "long")
    {
        if (kind == "utf8" || kind == "binary" || kind == "dictionary")
        {
            array = make_array(
                4,
                0,
                {nullptr,
                 pack_le<int32_t>({0, 1, 3, 6, 10}),
                 pack_le<uint8_t>(
                     {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j'})});
            schemas[0] = make_schema(kind == "binary" ? "z" : "u", "v");
        }
        else if (kind == "utf8_view")
        {
            // Four inline Arrow ByteViews: u32 length followed by up to 12
            // bytes, with no variadic data buffers. Exercise the view layout
            // independently of the ordinary UTF-8 offsets layout.
            auto views = std::make_shared<std::vector<uint8_t>>(64, 0);
            const std::string values[] = {"a", "bc", "def", "ghij"};
            for (size_t i = 0; i < 4; ++i)
            {
                const uint32_t length = static_cast<uint32_t>(values[i].size());
                std::memcpy(views->data() + i * 16, &length, 4);
                std::memcpy(
                    views->data() + i * 16 + 4, values[i].data(), length);
            }
            array = make_array(4, 0, {nullptr, views, nullptr});
            schemas[0] = make_schema("vu", "v");
        }
        else if (kind == "fixed_binary")
        {
            auto bytes = std::make_shared<std::vector<uint8_t>>();
            for (uint8_t value : {'a', 'b', 'c', 'd'})
                bytes->insert(bytes->end(), 16, value);
            array = make_array(4, 0, {nullptr, bytes});
            schemas[0] = make_schema("w:16", "v");
        }
        else if (kind == "bool")
        {
            array = make_array(4, 0, {nullptr, pack_le<uint8_t>({0x05})});
            schemas[0] = make_schema("b", "v");
        }
        else
        {
            const bool list = kind == "fixed_list" || kind == "list";
            array = make_array(
                list ? 8 : 4,
                0,
                {nullptr,
                 list ? pack_le<double>({10, 11, 20, 21, 30, 31, 40, 41})
                      : pack_le<int64_t>({10, 20, 30, 40})});
            schemas[0] = make_schema(list ? "g" : "l", "v");
        }
        count_root();
        if (kind == "fixed_list")
            wrap("+w:2", 4, {nullptr});
        else if (kind == "list")
            wrap("+l", 4, {nullptr, pack_le<int32_t>({0, 2, 4, 6, 8})});
        else if (kind == "dictionary")
        {
            auto dictionary = std::make_unique<ArrowArray>(array);
            array = make_array(4, 0, {nullptr, pack_le<int32_t>({0, 1, 2, 3})});
            auto* owner = static_cast<Owner*>(array.private_data);
            array.dictionary = dictionary.get();
            owner->dictionary_storage = std::move(dictionary);
            schemas[nodes] = make_schema("i", "v");
            schemas[nodes].dictionary = &schemas[nodes - 1];
            count_root();
        }
        // Every fixture starts with a nonzero Arrow offset. Entry-point slicing
        // selects the final two rows, not the beginning of the physical buffer.
        array.offset = 1;
        array.length = 3;
    }

    void count_root()
    {
        REQUIRE(nodes < 3);
        static_cast<Owner*>(array.private_data)->release_count =
            &releases[nodes++];
    }

    void wrap(
        const char* format,
        int64_t length,
        std::vector<std::shared_ptr<std::vector<uint8_t>>> buffers)
    {
        auto child = std::make_unique<ArrowArray>(array);
        array = make_array(length, 0, std::move(buffers));
        auto* owner = static_cast<Owner*>(array.private_data);
        owner->children_ptrs.push_back(child.get());
        owner->children_storage.push_back(std::move(child));
        array.n_children = 1;
        array.children = owner->children_ptrs.data();
        schemas[nodes] = make_schema(format, "v");
        schema_children[nodes] = &schemas[nodes - 1];
        schemas[nodes].n_children = 1;
        schemas[nodes].children = &schema_children[nodes];
        count_root();
    }

    void as_record_batch()
    {
        wrap("+s", 2, {nullptr});
        array.offset = 1;
    }

    ArrowSchema* schema()
    {
        return &schemas[nodes - 1];
    }

    void check_releases(int expected) const
    {
        for (size_t i = 0; i < nodes; ++i)
        {
            INFO("producer node " << i);
            CHECK(releases[i].load() == expected);
        }
    }

    void release()
    {
        if (array.release)
            array.release(&array);
    }

    ~CountedArrow()
    {
        release();
    }
    CountedArrow(const CountedArrow&) = delete;
    CountedArrow& operator=(const CountedArrow&) = delete;
};

std::string error_message(line_sender_error* err)
{
    if (!err)
        return {};
    size_t len = 0;
    const char* msg = line_sender_error_msg(err, &len);
    return std::string(msg, len);
}

struct DirectMockConn
{
    qm::MockServer server;
    qwp_direct_sender* sender = nullptr;

    explicit DirectMockConn(qm::Script script)
        : server(std::vector<qm::Script>{std::move(script)})
    {
        const auto conf = "ws::addr=" + server.addr() + ";";
        line_sender_error* err = nullptr;
        sender = qwp_direct_sender_from_conf(conf.c_str(), conf.size(), &err);
        std::unique_ptr<line_sender_error, decltype(&line_sender_error_free)>
            owned_err{err, &line_sender_error_free};
        INFO(error_message(err));
        REQUIRE(err == nullptr);
        REQUIRE(sender != nullptr);
    }

    ~DirectMockConn()
    {
        questdb_db_drop_direct_sender(nullptr, sender);
    }
    DirectMockConn(const DirectMockConn&) = delete;
    DirectMockConn& operator=(const DirectMockConn&) = delete;
};

// Decode the framing/schema, then compare the complete column body rather than
// searching for an expected byte subsequence (which could match the wrong row).
uint64_t take_varint(const std::vector<uint8_t>& frame, size_t& pos)
{
    uint64_t value = 0;
    for (unsigned shift = 0; shift < 64; shift += 7)
    {
        REQUIRE(pos < frame.size());
        const uint8_t byte = frame[pos++];
        value |= uint64_t(byte & 0x7f) << shift;
        if (!(byte & 0x80))
            return value;
    }
    FAIL("invalid varint in captured frame");
    return 0;
}

std::string take_bytes(const std::vector<uint8_t>& frame, size_t& pos)
{
    const auto len = take_varint(frame, pos);
    REQUIRE(len <= frame.size() - pos);
    std::string out(frame.begin() + pos, frame.begin() + pos + len);
    pos += len;
    return out;
}

void check_column_frame(
    const std::vector<uint8_t>& frame,
    uint8_t kind,
    const std::vector<uint8_t>& body,
    const std::vector<std::string>& symbols = {})
{
    REQUIRE(frame.size() >= 12);
    CHECK(std::string(frame.begin(), frame.begin() + 4) == "QWP1");
    CHECK(frame[6] == 1); // one table
    CHECK(frame[7] == 0);
    size_t pos = 12;
    CHECK(take_varint(frame, pos) == 0); // dictionary delta start
    REQUIRE(take_varint(frame, pos) == symbols.size());
    for (const auto& symbol : symbols)
        CHECK(take_bytes(frame, pos) == symbol);
    CHECK(take_bytes(frame, pos) == "t");
    CHECK(take_varint(frame, pos) == 2);
    CHECK(take_varint(frame, pos) == 1);
    CHECK(take_bytes(frame, pos) == "v");
    REQUIRE(pos < frame.size());
    CHECK(frame[pos++] == kind);
    CHECK(std::vector<uint8_t>(frame.begin() + pos, frame.end()) == body);
}

std::vector<uint8_t> expected_slice_body(const std::string& kind)
{
    if (kind == "utf8" || kind == "binary" || kind == "utf8_view")
        return qm::varlen_column_bytes({{'d', 'e', 'f'}, {'g', 'h', 'i', 'j'}});
    if (kind == "fixed_binary")
        return qm::varlen_column_bytes(
            {std::vector<uint8_t>(16, 'c'), std::vector<uint8_t>(16, 'd')});
    if (kind == "dictionary")
        return qm::symbol_column_bytes({0, 1});
    if (kind == "bool")
        return {0, 1}; // selected physical bits 2 and 3: true, false
    if (kind == "list" || kind == "fixed_list")
        return qm::array_column_bytes(
            {qm::ArrayRow{{2}, *pack_le<double>({30, 31})},
             qm::ArrayRow{{2}, *pack_le<double>({40, 41})}});
    return qm::fixed_column_bytes(2, *pack_le<int64_t>({30, 40}));
}

uint8_t expected_kind(const std::string& kind)
{
    if (kind == "utf8" || kind == "utf8_view")
        return qm::COL_VARCHAR;
    if (kind == "binary" || kind == "fixed_binary")
        return qm::COL_BINARY;
    if (kind == "dictionary")
        return qm::COL_SYMBOL;
    if (kind == "bool")
        return qm::COL_BOOLEAN;
    if (kind == "list" || kind == "fixed_list")
        return qm::COL_DOUBLE_ARRAY;
    return qm::COL_LONG;
}

} // namespace

TEST_CASE(
    "Arrow C flush failure reexports current input after earlier publication")
{
    for (bool record_batch : {false, true})
        for (bool waited : {false, true})
        {
            CAPTURE(record_batch);
            CAPTURE(waited);
            DirectMockConn mc{
                {qm::ActionAwaitClientFrame{0x51},
                 qm::ActionSendRaw{qm::ingress_ok_frame(0)},
                 qm::ActionAwaitClientFrame{0x51},
                 qm::ActionSendRaw{qm::ingress_ok_frame(1)}}};
            line_sender_error* err = nullptr;
            CountedArrow first;
            first.array.offset = 2;
            first.array.length = 2;
            REQUIRE(qwp_direct_sender_flush_arrow_batch_at_now(
                mc.sender,
                {1, "t"},
                &first.array,
                first.schema(),
                nullptr,
                0,
                &err));
            REQUIRE(err == nullptr);
            first.check_releases(1);

            CountedArrow input;
            if (record_batch)
                input.as_record_batch();
            else
            {
                input.array.offset = 2;
                input.array.length = 2;
            }
            // Missing timestamp validation happens after import, before
            // publish.
            const bool ok =
                waited ? qwp_direct_sender_flush_arrow_batch_at_column_and_wait(
                             mc.sender,
                             {1, "t"},
                             &input.array,
                             input.schema(),
                             {7, "missing"},
                             nullptr,
                             0,
                             qwpws_ack_level_ok,
                             &err)
                       : qwp_direct_sender_flush_arrow_batch_at_column(
                             mc.sender,
                             {1, "t"},
                             &input.array,
                             input.schema(),
                             {7, "missing"},
                             nullptr,
                             0,
                             &err);
            CHECK_FALSE(ok);
            REQUIRE(err != nullptr);
            CHECK(
                line_sender_error_get_code(err) ==
                line_sender_error_arrow_ingest);
            CHECK_FALSE(line_sender_error_in_doubt(err));
            line_sender_error_free(err);
            err = nullptr;
            REQUIRE((input.array.release != nullptr));
            input.check_releases(0);
            // Correct only the timestamp choice; retry the returned array
            // against the ORIGINAL schema. Values and primitive/Struct shape
            // must survive.
            REQUIRE(qwp_direct_sender_flush_arrow_batch_at_now_and_wait(
                mc.sender,
                {1, "t"},
                &input.array,
                input.schema(),
                nullptr,
                0,
                qwpws_ack_level_ok,
                &err));
            REQUIRE(err == nullptr);
            CHECK((input.array.release == nullptr));
            input.check_releases(1);
            const auto frames = mc.server.captured_requests();
            REQUIRE(frames.size() == 2); // rejected call published nothing
            for (const auto& frame : frames)
                check_column_frame(
                    frame, qm::COL_LONG, expected_slice_body("long"));
        }
}

TEST_CASE("Arrow C FSN failure reexports and ACK preflight never imports")
{
    for (bool record_batch : {false, true})
        for (bool ack_preflight : {false, true})
        {
            CAPTURE(record_batch);
            CAPTURE(ack_preflight);
            MockConn mc{
                {qm::ActionAwaitClientFrame{0x51},
                 qm::ActionSendRaw{qm::ingress_ok_frame(0)}}};
            CountedArrow input;
            if (record_batch)
                input.as_record_batch();
            else
            {
                input.array.offset = 2;
                input.array.length = 2;
            }
            line_sender_error* err = nullptr;
            line_sender_qwpws_fsn fsn{};
            const bool ok =
                ack_preflight
                    ? qwp_sender_flush_arrow_batch_at_now_and_wait(
                          mc.conn,
                          {1, "t"},
                          &input.array,
                          input.schema(),
                          nullptr,
                          0,
                          qwpws_ack_level_durable,
                          &err) // no durable opt-in
                    : qwp_sender_flush_arrow_batch_at_column_and_get_fsn(
                          mc.conn,
                          {1, "t"},
                          &input.array,
                          input.schema(),
                          {7, "missing"},
                          nullptr,
                          0,
                          &fsn,
                          &err);
            CHECK_FALSE(ok);
            REQUIRE(err != nullptr);
            CHECK(
                line_sender_error_get_code(err) ==
                (ack_preflight ? line_sender_error_invalid_api_call
                               : line_sender_error_arrow_ingest));
            CHECK_FALSE(line_sender_error_in_doubt(err));
            line_sender_error_free(err);
            err = nullptr;
            REQUIRE((input.array.release != nullptr));
            if (ack_preflight)
                CHECK((input.array.release == release_owner));
            input.check_releases(0);
            REQUIRE(qwp_sender_flush_arrow_batch_at_now_and_get_fsn(
                mc.conn,
                {1, "t"},
                &input.array,
                input.schema(),
                nullptr,
                0,
                &fsn,
                &err));
            CHECK(fsn.has_value);
            CHECK(fsn.value == 0);
            REQUIRE(qwp_sender_wait(mc.conn, qwpws_ack_level_ok, 2000, &err));
            REQUIRE(err == nullptr);
            CHECK((input.array.release == nullptr));
            input.check_releases(1);
            const auto frames = mc.server.captured_requests();
            REQUIRE(frames.size() == 1);
            check_column_frame(
                frames[0], qm::COL_LONG, expected_slice_body("long"));
        }
}

TEST_CASE("Arrow C post-publication ACK failure consumes rather than reexports")
{
    for (bool record_batch : {false, true})
    {
        CAPTURE(record_batch);
        DirectMockConn mc{
            {qm::ActionAwaitClientFrame{0x51}, qm::ActionHardDrop{}}};
        CountedArrow input;
        if (record_batch)
            input.as_record_batch();
        else
        {
            input.array.offset = 2;
            input.array.length = 2;
        }
        line_sender_error* err = nullptr;
        CHECK_FALSE(qwp_direct_sender_flush_arrow_batch_at_now_and_wait(
            mc.sender,
            {1, "t"},
            &input.array,
            input.schema(),
            nullptr,
            0,
            qwpws_ack_level_ok,
            &err));
        REQUIRE(err != nullptr);
        CHECK(line_sender_error_in_doubt(err));
        line_sender_error_free(err);
        CHECK((input.array.release == nullptr));
        input.check_releases(1);
        const auto frames = mc.server.captured_requests();
        REQUIRE(frames.size() == 1);
        check_column_frame(
            frames[0], qm::COL_LONG, expected_slice_body("long"));
    }
}

TEST_CASE(
    "Arrow C nonempty slices preserve values and release every producer node "
    "once")
{
    for (const std::string kind :
         {"long",
          "bool",
          "utf8",
          "binary",
          "list",
          "fixed_list",
          "fixed_binary",
          "utf8_view",
          "dictionary"})
        for (int route :
             {0, 1, 2}) // record batch, sliced column, imported handle
        {
            CAPTURE(kind);
            CAPTURE(route);
            CountedArrow input(
                kind); // counters outlive the sender on failure too
            MockConn mc{
                {qm::ActionAwaitClientFrame{0x51},
                 qm::ActionSendRaw{qm::ingress_ok_frame(0)}}};
            line_sender_error* err = nullptr;
            if (route == 0)
            {
                input.as_record_batch();
                REQUIRE(qwp_sender_flush_arrow_batch_at_now_and_wait(
                    mc.conn,
                    {1, "t"},
                    &input.array,
                    input.schema(),
                    nullptr,
                    0,
                    qwpws_ack_level_ok,
                    &err));
            }
            else
            {
                // Destroy a retained chunk before its imported handle on an
                // assertion failure too, respecting the public lifetime
                // contract.
                std::unique_ptr<
                    qwp_arrow_import,
                    decltype(&qwp_arrow_import_free)>
                    imported{nullptr, &qwp_arrow_import_free};
                qdb::column_chunk chunk{"t"};
                if (route == 1)
                    REQUIRE(qwp_chunk_append_arrow_column(
                        chunk.c_ptr(),
                        "v",
                        1,
                        &input.array,
                        input.schema(),
                        1,
                        2,
                        &err));
                else
                {
                    imported.reset(qwp_arrow_import_new(
                        &input.array,
                        input.schema(),
                        qwp_symbol_mode_auto,
                        &err));
                    REQUIRE(imported != nullptr);
                    CHECK(qwp_arrow_import_len(imported.get()) == 3);
                    CHECK_FALSE(qwp_chunk_append_arrow_import(
                        chunk.c_ptr(), "v", 1, imported.get(), 2, 2, &err));
                    REQUIRE(err != nullptr);
                    CHECK(
                        line_sender_error_get_code(err) ==
                        line_sender_error_invalid_api_call);
                    CHECK_FALSE(line_sender_error_in_doubt(err));
                    line_sender_error_free(err);
                    err = nullptr;
                    CHECK(chunk.row_count() == 0);
                    input.check_releases(
                        0); // failed slice leaves handle usable
                    REQUIRE(qwp_chunk_append_arrow_import(
                        chunk.c_ptr(), "v", 1, imported.get(), 1, 2, &err));
                }
                CHECK((input.array.release == nullptr));
                input.check_releases(0); // retained until encode, not at import
                REQUIRE(qwp_chunk_at_now(chunk.c_ptr(), &err));
                REQUIRE(qwp_sender_flush_chunk_and_wait(
                    mc.conn, chunk.c_ptr(), qwpws_ack_level_ok, &err));
                if (imported)
                {
                    input.check_releases(0); // handle still owns the buffers
                    imported.reset();
                }
            }
            REQUIRE(err == nullptr);
            CHECK((input.array.release == nullptr));
            // SYMBOL dictionary memoization deliberately pins Arrow buffers
            // for this connection. Retirement must release that cache too.
            if (kind == "dictionary")
            {
                input.check_releases(0);
                mc.drop_sender();
            }
            input.check_releases(1);
            const auto frames = mc.server.captured_requests();
            REQUIRE(frames.size() == 1);
            check_column_frame(
                frames[0],
                expected_kind(kind),
                expected_slice_body(kind),
                kind == "dictionary" ? std::vector<std::string>{"def", "ghij"}
                                     : std::vector<std::string>{});
        }
}

TEST_CASE("Arrow C post-import validation failure releases all producer nodes")
{
    // These two entry points validate payloads at import. Imported handles
    // deliberately use structural-only validation and are covered separately.
    for (int route : {0, 1})
    {
        CAPTURE(route);
        CountedArrow input("utf8");
        // Valid, fully allocated offsets/buffers but invalid UTF-8 in one of
        // the selected rows. Structural preflight accepts this; validate_full
        // rejects it after ownership has been consumed.
        auto* owner = static_cast<Owner*>(input.array.private_data);
        (*owner->buffers_storage[2])[3] = 0xff;
        if (route == 0)
            input.as_record_batch();
        MockConn mc;
        line_sender_error* err = nullptr;
        qdb::column_chunk chunk{"t"};
        if (route == 0)
            CHECK_FALSE(qwp_sender_flush_arrow_batch_at_now(
                mc.conn,
                {1, "t"},
                &input.array,
                input.schema(),
                nullptr,
                0,
                &err));
        else if (route == 1)
            CHECK_FALSE(qwp_chunk_append_arrow_column(
                chunk.c_ptr(),
                "v",
                1,
                &input.array,
                input.schema(),
                1,
                2,
                &err));
        REQUIRE(err != nullptr);
        CHECK(
            line_sender_error_get_code(err) == line_sender_error_arrow_ingest);
        CHECK(
            error_message(err).find("Arrow array validation failed") !=
            std::string::npos);
        CHECK_FALSE(line_sender_error_in_doubt(err));
        line_sender_error_free(err);
        CHECK((input.array.release == nullptr)); // consumed, NOT re-exported
        input.check_releases(1);
        CHECK(chunk.row_count() == 0);
        CHECK(mc.server.captured_requests().empty());
    }
}

TEST_CASE(
    "Arrow C structural and metadata preflight retains counted producer "
    "ownership")
{
    for (const std::string invalid :
         {"buffers",
          "child_count",
          "short_child",
          "metadata",
          "metadata_key_budget",
          "metadata_value_budget",
          "name",
          "nested_struct"})
        for (int route : {0, 1, 2})
        {
            CAPTURE(invalid);
            CAPTURE(route);
            MockConn mc;
            CountedArrow input(
                invalid == "short_child" ? "fixed_list" : "long");
            if (invalid == "nested_struct")
                input.as_record_batch();
            if (route == 0)
                input.as_record_batch();
            // Each malformed structure still points to valid, stable
            // allocations. In particular metadata has enough bytes for all
            // fields read before the deliberately negative key length is
            // rejected.
            const int32_t metadata[] = {1, -2, 0};
            const char invalid_name[] = {char(0xff), 0};
            // Allocate the full declared blob, even though the size guard must
            // reject before reading its payload. Never test with fictitious
            // memory.
            std::vector<uint8_t> oversized_metadata(1024 * 1024 + 12, 0);
            const int32_t one = 1;
            const int32_t megabyte = 1024 * 1024;
            std::memcpy(oversized_metadata.data(), &one, 4);
            std::string expected_message;
            if (invalid == "buffers")
            {
                input.array.n_buffers = 0;
                expected_message = "requires exactly";
            }
            else if (invalid == "child_count")
            {
                // Mismatch the array against the valid schema. Keep a real
                // pointer slot even for the scalar case; rejection must precede
                // traversal.
                input.array.n_children = route == 0 ? 0 : 1;
                if (route != 0)
                    input.array.children = &input.array.dictionary;
                expected_message = "disagrees with schema n_children";
            }
            else if (invalid == "short_child")
            {
                ArrowArray* list =
                    route == 0 ? input.array.children[0] : &input.array;
                list->children[0]->length =
                    7; // list slice needs 8 scalar values
                expected_message = "beyond child 0 length 7";
            }
            else if (invalid == "metadata")
            {
                input.schema()->metadata =
                    reinterpret_cast<const char*>(metadata);
                expected_message = "key length -2 is negative";
            }
            else if (
                invalid == "metadata_key_budget" ||
                invalid == "metadata_value_budget")
            {
                // An empty key precedes the oversized value in the second case.
                std::memcpy(
                    oversized_metadata.data() +
                        (invalid == "metadata_key_budget" ? 4 : 8),
                    &megabyte,
                    4);
                input.schema()->metadata =
                    reinterpret_cast<const char*>(oversized_metadata.data());
                expected_message = "metadata blob exceeds";
            }
            else if (invalid == "name")
            {
                input.schema()->name = invalid_name;
                expected_message = "name is not UTF-8";
            }
            else
                expected_message = "Struct columns are not supported";
            line_sender_error* err = nullptr;
            qdb::column_chunk chunk{"t"};
            if (route == 0)
                CHECK_FALSE(qwp_sender_flush_arrow_batch_at_now(
                    mc.conn,
                    {1, "t"},
                    &input.array,
                    input.schema(),
                    nullptr,
                    0,
                    &err));
            else if (route == 1)
                CHECK_FALSE(qwp_chunk_append_arrow_column(
                    chunk.c_ptr(),
                    "v",
                    1,
                    &input.array,
                    input.schema(),
                    1,
                    2,
                    &err));
            else
                CHECK(
                    qwp_arrow_import_new(
                        &input.array,
                        input.schema(),
                        qwp_symbol_mode_auto,
                        &err) == nullptr);
            REQUIRE(err != nullptr);
            CHECK(
                error_message(err).find(expected_message) != std::string::npos);
            CHECK(
                line_sender_error_get_code(err) ==
                (invalid == "nested_struct"
                     ? line_sender_error_arrow_unsupported_column_kind
                     : line_sender_error_arrow_ingest));
            CHECK_FALSE(line_sender_error_in_doubt(err));
            line_sender_error_free(err);
            CHECK(chunk.row_count() == 0);
            CHECK(
                (input.array.release ==
                 release_owner)); // never imported/reexported
            input.check_releases(0);
            input.release();
            input.check_releases(1);
            CHECK(mc.server.captured_requests().empty());
        }
}
