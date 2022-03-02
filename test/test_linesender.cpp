#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "mock_server.hpp"

#include <questdb/linesender.h>
#include <questdb/linesender.hpp>
#include "../src/utf8.h"

#include <vector>


TEST_CASE("utf8: good ascii")
{
    const char buf[] = "abc";
    const size_t len = sizeof(buf) - 1;
    CHECK(len == 3);

    utf8_error err;
    CHECK(utf8_check(len, buf, &err));
}

TEST_CASE("utf8: ff ff - bad byte 2")
{
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
        CHECK(linesender_metric(sender, 4, "test", &err));
        CHECK(linesender_tag(sender, 2, "t1", 2, "v1", &err));
        CHECK(linesender_field_f64(sender, 2, "f1", 0.5, &err));
        CHECK(linesender_end_line_timestamp(sender, 10000000, &err));
        CHECK(server.recv() == 0);
        CHECK(linesender_pending_size(sender) == 27);
        CHECK(linesender_flush(sender, &err));
        CHECK(server.recv() == 1);
        CHECK(server.msgs().front() == "test,t1=v1 f1=0.5 10000000\n");
    }
}

TEST_CASE("linesender c++ api basics")
{
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
            .metric("test")
            .tag("t1", "v1")
            .field("f1", 0.5)
            .end_line(10000000);

        CHECK(server.recv() == 0);
        CHECK(sender.pending_size() == 27);
        sender.flush();
        CHECK(server.recv() == 1);
        CHECK(server.msgs().front() == "test,t1=v1 f1=0.5 10000000\n");
    }
}

TEST_CASE("State machine testing -- flush without data.")
{
    questdb::proto::line::sender sender{
        questdb::proto::line::transport::udp,
        "localhost",
        "9009"};
    
    CHECK(sender.pending_size() == 0);
    CHECK_THROWS_WITH_AS(
        sender.flush(),
        "State error: Bad call to `flush`, "
        "should have called `metric` instead. "
        "Must now call `close`.",
        questdb::proto::line::sender_error);
    CHECK(sender.must_close());
    sender.close();
}

TEST_CASE("State machine testing -- endline without fields.")
{
    questdb::proto::line::sender sender{
        questdb::proto::line::transport::udp,
        "localhost",
        "9009"};
    
    sender.metric("test").tag("t1", "v1");
    CHECK_THROWS_WITH_AS(
        sender.end_line(),
        "State error: Bad call to `end_line`, "
        "should have called `tag` or `field` instead. "
        "Must now call `close`.",
        questdb::proto::line::sender_error);
    CHECK(sender.must_close());
    sender.close();
}

TEST_CASE("Bad UTF-8 in metric")
{
    questdb::proto::line::sender sender{
        questdb::proto::line::transport::udp,
        "localhost",
        "9009"};
    
    CHECK_THROWS_WITH_AS(
        sender.metric("\xff\xff"),
        "Bad string \"\\xff\\xff\": "
        "Invalid UTF-8. Illegal codepoint starting at byte index 0.",
        questdb::proto::line::sender_error);
}

TEST_CASE("Validation of overly large UDP line.")
{
    questdb::proto::line::sender sender{
        questdb::proto::line::transport::udp,
        "localhost",
        "9009"};

    sender.metric("test");
    while (sender.pending_size() < 1048576)
        sender.field("f1", 10000000.5);

    CHECK_THROWS_WITH_AS(
        sender.end_line(),
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
    {
        questdb::proto::line::sender sender{
            questdb::proto::line::transport::udp,
            "localhost",
            "9009"};

        CHECK_THROWS_WITH_AS(
            sender.metric("a*b"),
            "Bad string \"a*b\": metric, tag and field names "
            "can't contain a '*' character, "
            "which was found at byte position 1.",
            questdb::proto::line::sender_error);
    }

    {
        questdb::proto::line::sender sender{
            questdb::proto::line::transport::udp,
            "localhost",
            "9009"};

        sender.metric("test");
        CHECK_THROWS_WITH_AS(
            sender.tag("a+b", "v1"),
            "Bad string \"a+b\": metric, tag and field names "
            "can't contain a '+' character, "
            "which was found at byte position 1.",
            questdb::proto::line::sender_error);
    }

    {
        questdb::proto::line::sender sender{
            questdb::proto::line::transport::udp,
            "localhost",
            "9009"};

        sender.metric("test");
        std::string_view field_name{"a\0b", 3};
        CHECK_THROWS_WITH_AS(
            sender.field(field_name, false),
            "Bad string \"a\\0b\": metric, tag and field names "
            "can't contain a '\\0' character, "
            "which was found at byte position 1.",
            questdb::proto::line::sender_error);
    }
}

TEST_CASE("Move testing.")
{
    questdb::proto::line::sender sender1{
        questdb::proto::line::transport::udp,
        "localhost",
        "9009"};

    CHECK_THROWS_AS(
        sender1.end_line(),
        questdb::proto::line::sender_error);
    CHECK(sender1.must_close());

    questdb::proto::line::sender sender2{std::move(sender1)};

    CHECK_FALSE(sender1.must_close());
    CHECK(sender2.must_close());

    questdb::proto::line::sender sender3{
        questdb::proto::line::transport::udp,
        "localhost",
        "9009"};
    sender3.metric("test");
    CHECK(sender3.pending_size() == 4);
    CHECK_FALSE(sender3.must_close());

    sender3 = std::move(sender2);
    CHECK(sender3.pending_size() == 0);
    CHECK(sender3.must_close());
}
