#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "mock_server.hpp"
#include "wsastartup_guard.hpp"

#include <questdb/linesender.h>
#include <questdb/linesender.hpp>
#include "../src/utf8.h"

#include <vector>

extern "C"
{
#include "../src/next_pow2.inc.c"
}

TEST_CASE("next_pow2")
{
    CHECK(next_pow2(2) == 2);
    CHECK(next_pow2(3) == 4);
    CHECK(next_pow2(4) == 4);
    CHECK(next_pow2(5) == 8);
    CHECK(next_pow2(6) == 8);
    CHECK(next_pow2(7) == 8);
    CHECK(next_pow2(8) == 8);
    CHECK(next_pow2(9) == 16);
    CHECK(next_pow2(64000) == 65536);
    CHECK(next_pow2(65535) == 65536);
    CHECK(next_pow2(65536) == 65536);
    CHECK(next_pow2(65537) == 131072);
    CHECK(next_pow2(100000) == 131072);
}

TEST_CASE("utf8: good ascii")
{
    WSASTARTUP_GUARD;
    const char buf[] = "abc";
    const size_t len = sizeof(buf) - 1;
    CHECK(len == 3);

    utf8_error err;
    CHECK(utf8_check(len, buf, &err));
}

TEST_CASE("utf8: ff ff - bad byte 2")
{
    WSASTARTUP_GUARD;
    const char buf[] = "\xff\xff";
    const size_t len = sizeof(buf) - 1;

    utf8_error err;
    CHECK_FALSE(utf8_check(len, buf, &err));

    CHECK(err.valid_up_to == 0);
    CHECK(err.need_more == false);
    CHECK(err.error_len == 1);
}

TEST_CASE("utf8: partial infinity symbol - need more")
{
    WSASTARTUP_GUARD;
    // First 2 chars of infinity symbol.
    const char buf[] = "\xe2\x88";  // \x9e
    const size_t len = sizeof(buf) - 1;

    utf8_error err;
    CHECK_FALSE(utf8_check(len, buf, &err));

    CHECK(err.valid_up_to == 0);
    CHECK(err.need_more == true);
    CHECK(err.error_len == 0);
}

TEST_CASE("utf8: Error after valid text")
{
    WSASTARTUP_GUARD;
    // 'abc' + First 2 chars of infinity symbol.
    const char buf[] = "abc\xe2\x88";  // \x9e
    const size_t len = sizeof(buf) - 1;

    utf8_error err;
    CHECK_FALSE(utf8_check(len, buf, &err));

    CHECK(err.valid_up_to == 3);
    CHECK(err.need_more == true);
    CHECK(err.error_len == 0);
}

template <typename F>
    class on_scope_exit
{
public:
    explicit on_scope_exit(F&& f) : _f{std::move(f)} {}
    ~on_scope_exit() { _f(); }
private:
    F _f;
};

TEST_CASE("linesender c api basics")
{
    WSASTARTUP_GUARD;
    for (auto transport : {linesender_tcp, linesender_udp})
    {    
        questdb::proto::line::test::mock_server
            server{transport == linesender_tcp};
        linesender_error* err = nullptr;
        on_scope_exit error_free_guard{[&]{
                if (err) linesender_error_free(err);
            }};
        linesender* sender = linesender_connect(
            transport,
            "0.0.0.0",
            "localhost",
            std::to_string(server.port()).c_str(),
            1,
            &err);
        CHECK(sender != nullptr);
        CHECK_FALSE(linesender_must_close(sender));
        on_scope_exit sender_close_guard{[&]
            {
                linesender_close(sender);
                sender = nullptr;
            }};
        server.accept();
        CHECK(server.recv() == 0);
        CHECK(linesender_table(sender, 4, "test", &err));
        CHECK(linesender_symbol(sender, 2, "t1", 2, "v1", &err));
        CHECK(linesender_column_f64(sender, 2, "f1", 0.5, &err));
        CHECK(linesender_at(sender, 10000000, &err));
        CHECK(server.recv() == 0);
        CHECK(linesender_pending_size(sender) == 27);
        CHECK(linesender_flush(sender, &err));
        CHECK(server.recv() == 1);
        CHECK(server.msgs().front() == "test,t1=v1 f1=0.5 10000000\n");    
    }
}

TEST_CASE("linesender c++ api basics")
{
    WSASTARTUP_GUARD;
    const auto transports = {
        questdb::proto::line::transport::tcp,
        questdb::proto::line::transport::udp};
    for (auto transport : transports)
    {
        questdb::proto::line::test::mock_server server{
            transport == questdb::proto::line::transport::tcp};
        questdb::proto::line::sender sender{
            transport,
            "localhost",
            std::to_string(server.port()).c_str()};
        CHECK_FALSE(sender.must_close());
        server.accept();
        CHECK(server.recv() == 0);

        sender
            .table("test")
            .symbol("t1", "v1")
            .column("f1", 0.5)
            .at(10000000);

        CHECK(server.recv() == 0);
        CHECK(sender.pending_size() == 27);
        sender.flush();
        CHECK(server.recv() == 1);
        CHECK(server.msgs().front() == "test,t1=v1 f1=0.5 10000000\n");
    }
}

TEST_CASE("State machine testing -- flush without data.")
{
    WSASTARTUP_GUARD;
    questdb::proto::line::sender sender{
        questdb::proto::line::transport::udp,
        "localhost",
        "9009"};
    
    CHECK(sender.pending_size() == 0);
    CHECK_THROWS_WITH_AS(
        sender.flush(),
        "State error: Bad call to `flush`, "
        "should have called `table` instead. "
        "Must now call `close`.",
        questdb::proto::line::sender_error);
    CHECK(sender.must_close());
    sender.close();
}

TEST_CASE("State machine testing -- endline without columns.")
{
    WSASTARTUP_GUARD;
    questdb::proto::line::sender sender{
        questdb::proto::line::transport::udp,
        "localhost",
        "9009"};
    
    sender.table("test").symbol("t1", "v1");
    CHECK_THROWS_WITH_AS(
        sender.at_now(),
        "State error: Bad call to `at`, "
        "should have called `symbol` or `column` instead. "
        "Must now call `close`.",
        questdb::proto::line::sender_error);
    CHECK(sender.must_close());
    sender.close();
}

TEST_CASE("Bad UTF-8 in table")
{
    WSASTARTUP_GUARD;
    questdb::proto::line::sender sender{
        questdb::proto::line::transport::udp,
        "localhost",
        "9009"};
    
    CHECK_THROWS_WITH_AS(
        sender.table("\xff\xff"),
        "Bad string \"\\xff\\xff\": "
        "Invalid UTF-8. Illegal codepoint starting at byte index 0.",
        questdb::proto::line::sender_error);
}

TEST_CASE("Validation of overly large UDP line.")
{
    WSASTARTUP_GUARD;
    questdb::proto::line::sender sender{
        questdb::proto::line::transport::udp,
        "localhost",
        "9009"};

    sender.table("test");
    while (sender.pending_size() < 1048576)
        sender.column("f1", 10000000.5);

    CHECK_THROWS_WITH_AS(
        sender.at_now(),
        "Current line is too long to be sent via UDP. "
        "Byte size 1048576 > 64000.",
        questdb::proto::line::sender_error);

    CHECK(sender.must_close());

    CHECK_THROWS_WITH_AS(
        sender.flush(),
        "State error: Bad call to `flush`, "
        "unrecoverable state due to previous error. "
        "Must now call `close`.",
        questdb::proto::line::sender_error);

    // Check idempotency of close.
    sender.close();
    sender.close();
    sender.close();
    sender.close();
}

TEST_CASE("Validation of bad chars in key names.")
{
    WSASTARTUP_GUARD;
    {
        questdb::proto::line::sender sender{
            questdb::proto::line::transport::udp,
            "localhost",
            "9009"};

        CHECK_THROWS_WITH_AS(
            sender.table("a*b"),
            "Bad string \"a*b\": table, symbol and column names "
            "can't contain a '*' character, "
            "which was found at byte position 1.",
            questdb::proto::line::sender_error);
    }

    {
        questdb::proto::line::sender sender{
            questdb::proto::line::transport::udp,
            "localhost",
            "9009"};

        sender.table("test");
        CHECK_THROWS_WITH_AS(
            sender.symbol("a+b", "v1"),
            "Bad string \"a+b\": table, symbol and column names "
            "can't contain a '+' character, "
            "which was found at byte position 1.",
            questdb::proto::line::sender_error);
    }

    {
        questdb::proto::line::sender sender{
            questdb::proto::line::transport::udp,
            "localhost",
            "9009"};

        sender.table("test");
        std::string_view column_name{"a\0b", 3};
        CHECK_THROWS_WITH_AS(
            sender.column(column_name, false),
            "Bad string \"a\\0b\": table, symbol and column names "
            "can't contain a '\\0' character, "
            "which was found at byte position 1.",
            questdb::proto::line::sender_error);
    }
}

TEST_CASE("Move testing.")
{
    WSASTARTUP_GUARD;
    questdb::proto::line::sender sender1{
        questdb::proto::line::transport::udp,
        "localhost",
        "9009"};

    CHECK_THROWS_AS(
        sender1.at_now(),
        questdb::proto::line::sender_error);
    CHECK(sender1.must_close());

    questdb::proto::line::sender sender2{std::move(sender1)};

    CHECK_FALSE(sender1.must_close());
    CHECK(sender2.must_close());

    questdb::proto::line::sender sender3{
        questdb::proto::line::transport::udp,
        "localhost",
        "9009"};
    sender3.table("test");
    CHECK(sender3.pending_size() == 4);
    CHECK_FALSE(sender3.must_close());

    sender3 = std::move(sender2);
    CHECK(sender3.pending_size() == 0);
    CHECK(sender3.must_close());
}
