/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2022 QuestDB
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

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "mock_server.hpp"

#include <questdb/line_sender.h>
#include <questdb/line_sender.hpp>
#include "../src/utf8.h"

#include <vector>
#include <sstream>

extern "C"
{
#include "../src/next_pow2.inc.c"
}

using namespace std::string_literals;
using namespace questdb::literals;

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

TEST_CASE("line_sender c api basics")
{
    questdb::test::mock_server server;
    ::line_sender_error* err = nullptr;
    on_scope_exit error_free_guard{[&]{
            if (err)
                ::line_sender_error_free(err);
        }};
    ::line_sender* sender = ::line_sender_connect(
        "0.0.0.0",
        "localhost",
        std::to_string(server.port()).c_str(),
        &err);
    CHECK(sender != nullptr);
    CHECK_FALSE(::line_sender_must_close(sender));
    on_scope_exit sender_close_guard{[&]
        {
            ::line_sender_close(sender);
            sender = nullptr;
        }};
    server.accept();
    CHECK(server.recv() == 0);
    ::line_sender_name table_name{0, nullptr};
    CHECK(::line_sender_name_init(&table_name, 4, "test", &err));
    ::line_sender_name t1_name{0, nullptr};
    CHECK(::line_sender_name_init(&t1_name, 2, "t1", &err));
    ::line_sender_utf8 v1_utf8{0, nullptr};
    CHECK(::line_sender_utf8_init(&v1_utf8, 2, "v1", &err));
    ::line_sender_name f1_name{0, nullptr};
    CHECK(::line_sender_name_init(&f1_name, 2, "f1", &err));
    CHECK(::line_sender_table(sender, table_name, &err));
    CHECK(::line_sender_symbol(sender, t1_name, v1_utf8, &err));
    CHECK(::line_sender_column_f64(sender, f1_name, 0.5, &err));
    CHECK(::line_sender_at(sender, 10000000, &err));
    CHECK(server.recv() == 0);
    CHECK(::line_sender_pending_size(sender) == 27);
    CHECK(::line_sender_flush(sender, &err));
    CHECK(server.recv() == 1);
    CHECK(server.msgs().front() == "test,t1=v1 f1=0.5 10000000\n");
}

TEST_CASE("line_sender c++ connect disconnect")
{
    questdb::test::mock_server server;
    questdb::line_sender sender{
        "localhost",
        std::to_string(server.port()).c_str()};
    CHECK_FALSE(sender.must_close());
    server.accept();
    CHECK(server.recv() == 0);
}

TEST_CASE("line_sender c++ api basics")
{
    questdb::test::mock_server server;
    questdb::line_sender sender{
        "localhost",
        std::to_string(server.port()).c_str()};
    CHECK_FALSE(sender.must_close());
    server.accept();
    CHECK(server.recv() == 0);

    sender
        .table("test"_name)
        .symbol("t1"_name, "v1"_utf8)
        .column("f1"_name, 0.5)
        .at(10000000);

    CHECK(server.recv() == 0);
    CHECK(sender.pending_size() == 27);
    sender.flush();
    CHECK(server.recv() == 1);
    CHECK(server.msgs().front() == "test,t1=v1 f1=0.5 10000000\n");
}

TEST_CASE("test multiple lines")
{
    questdb::test::mock_server server;
    questdb::line_sender sender{
        "localhost",
        std::to_string(server.port()).c_str()};
    CHECK_FALSE(sender.must_close());
    server.accept();
    CHECK(server.recv() == 0);

    auto table_name = "metric1"_name;
    sender
        .table(table_name)
        .symbol("t1"_name, "val1"_utf8)
        .symbol("t2"_name, "val2"_utf8)
        .column("f1"_name, true)
        .column("f2"_name, static_cast<int64_t>(12345))
        .column("f3"_name, 10.75)
        .column("f4"_name, "val3"_utf8)
        .column("f5"_name, "val4"_utf8)
        .column("f6"_name, "val5"_utf8)
        .at(111222233333);
    sender
        .table(table_name)
        .symbol("tag3"_name, "value 3"_utf8)
        .symbol("tag\n4"_name, "value:4"_utf8)
        .column("field\t5"_name, false)
        .at_now();

    CHECK(server.recv() == 0);
    CHECK(sender.pending_size() == 138);
    sender.flush();
    CHECK(server.recv() == 2);
    CHECK(server.msgs()[0] ==
        ("metric1,t1=val1,t2=val2 f1=t,f2=12345i,"
         "f3=10.75,f4=\"val3\",f5=\"val4\",f6=\"val5\" 111222233333\n"));
    CHECK(server.msgs()[1] ==
        ("metric1,tag3=value\\ 3,tag\\\n"
         "4=value:4 field\t5=f\n"));
}

TEST_CASE("State machine testing -- flush without data.")
{
    questdb::test::mock_server server;
    questdb::line_sender sender{
        "localhost",
        std::to_string(server.port()).c_str()};

    CHECK(sender.pending_size() == 0);
    CHECK_THROWS_WITH_AS(
        sender.flush(),
        "State error: Bad call to `flush`, "
        "should have called `table` instead. "
        "Must now call `close`.",
        questdb::line_sender_error);
    CHECK(sender.must_close());
    sender.close();
}

TEST_CASE("One symbol only - flush before server accept")
{
    questdb::test::mock_server server;
    questdb::line_sender sender{
        "localhost",
        std::to_string(server.port()).c_str()};

    // Does not raise - this is unlike InfluxDB spec that disallows this.
    sender.table("test"_name).symbol("t1"_name, "v1"_utf8).at_now();
    CHECK(!sender.must_close());
    CHECK(sender.pending_size() == 11);
    sender.flush();
    sender.close();

    // Note the client has closed already,
    // but the server hasn't actually accepted the client connection yet.
    server.accept();
    CHECK(server.recv() == 1);
    CHECK(server.msgs()[0] == "test,t1=v1\n");
}

TEST_CASE("One column only - server.accept() after flush, before close")
{
    questdb::test::mock_server server;
    questdb::line_sender sender{
        "localhost",
        server.port()};

    // Does not raise - this is unlike InfluxDB spec that disallows this.
    sender.table("test"_name).column("t1"_name, "v1"_utf8).at_now();
    CHECK(!sender.must_close());
    CHECK(sender.pending_size() == 13);
    sender.flush();

    server.accept();
    sender.close();

    CHECK(server.recv() == 1);
    CHECK(server.msgs()[0] == "test t1=\"v1\"\n");
}

TEST_CASE("Symbol after column")
{
    questdb::test::mock_server server;
    questdb::line_sender sender{
        "localhost",
        server.port()};

    sender.table("test"_name).column("t1"_name, "v1"_utf8);

    CHECK_THROWS_AS(
        sender.symbol("t2"_name, "v2"_utf8),
        questdb::line_sender_error);

    CHECK(sender.must_close());

    CHECK_THROWS_WITH_AS(
        sender.flush(),
        "State error: Bad call to `flush`, "
        "unrecoverable state due to previous error. "
        "Must now call `close`.",
        questdb::line_sender_error);

    // Check idempotency of close.
    sender.close();
    sender.close();
    sender.close();
    sender.close();
}

TEST_CASE("Bad UTF-8")
{
    CHECK_THROWS_WITH_AS(
        "\xff\xff"_utf8,
        "Bad string \"\\xff\\xff\": "
        "Invalid UTF-8. Illegal codepoint starting at byte index 0.",
        questdb::line_sender_error);
}

TEST_CASE("Validation of bad chars in key names.")
{
    {
        CHECK_THROWS_WITH_AS(
            "a*b"_name,
            "Bad string \"a*b\": table, symbol and column names "
            "can't contain a '*' character, "
            "which was found at byte position 1.",
            questdb::line_sender_error);
    }

    {
        CHECK_THROWS_WITH_AS(
            "a+b"_name,
            "Bad string \"a+b\": table, symbol and column names "
            "can't contain a '+' character, "
            "which was found at byte position 1.",
            questdb::line_sender_error);
    }

    {
        std::string_view column_name{"a\0b", 3};
        CHECK_THROWS_WITH_AS(
            questdb::name_view{column_name},
            "Bad string \"a\\0b\": table, symbol and column names "
            "can't contain a '\\0' character, "
            "which was found at byte position 1.",
            questdb::line_sender_error);
    }

    auto test_bad_name = [](std::string bad_name)
        {
            try
            {
                questdb::name_view{bad_name};
                std::stringstream ss;
                ss << "Name `" << bad_name << "` (";
                for (const char& c : bad_name)
                {
                    ss << "\\x"
                       << std::hex
                       << std::setw(2)
                       << std::setfill('0')
                       << c;
                }
                ss << ") did not raise.";
                CHECK_MESSAGE(false, ss.str());
            }
            catch (const questdb::line_sender_error&)
            {
                return;
            }
            catch (...)
            {
                CHECK_MESSAGE(false, "Other exception raised.");
            }
        };

    std::vector<std::string> bad_chars{
        " "s, "?"s, "."s, ","s, "'"s, "\""s, "\\"s, "/"s, "\0"s, ":"s,
        ")"s, "("s, "+"s, "-"s, "*"s, "%"s, "~"s, "\xef\xbb\xbf"s};

    for (const auto& bad_char : bad_chars)
    {
        std::vector<std::string> bad_names{
            bad_char + "abc",
            "ab" + bad_char + "c",
            "abc" + bad_char};
        for (const auto& bad_name : bad_names)
        {
            test_bad_name(bad_name);
        }
    }
}

TEST_CASE("Move testing.")
{
    questdb::test::mock_server server1;
    questdb::test::mock_server server2;

    questdb::line_sender sender1{
        "localhost",
        std::to_string(server1.port()).c_str()};

    CHECK_THROWS_AS(
        sender1.at_now(),
        questdb::line_sender_error);
    CHECK(sender1.must_close());

    questdb::line_sender sender2{std::move(sender1)};

    CHECK_FALSE(sender1.must_close());
    CHECK(sender2.must_close());

    questdb::line_sender sender3{
        "localhost",
        std::to_string(server2.port()).c_str()};
    sender3.table("test"_name);
    CHECK(sender3.pending_size() == 4);
    CHECK_FALSE(sender3.must_close());

    sender3 = std::move(sender2);
    CHECK(sender3.pending_size() == 0);
    CHECK(sender3.must_close());
}

TEST_CASE("Bad hostname")
{
    try
    {
        questdb::line_sender sender{"dummy_hostname", "9009"};
        CHECK_MESSAGE(false, "Expected exception");
    }
    catch (const questdb::line_sender_error& se)
    {
        std::string msg{se.what()};
        CHECK(msg.rfind("Could not resolve \"dummy_hostname:9009\": ", 0) == 0);
    }
    catch (...)
    {
        CHECK_MESSAGE(false, "Other exception raised.");
    }
}

TEST_CASE("Bad interface")
{
    try
    {
        questdb::line_sender sender{
            "localhost",
            "9009",
            "dummy_hostname"};
        CHECK_MESSAGE(false, "Expected exception");
    }
    catch (const questdb::line_sender_error& se)
    {
        std::string msg{se.what()};
        CHECK(msg.rfind("Could not resolve \"dummy_hostname\": ", 0) == 0);
    }
    catch (...)
    {
        CHECK_MESSAGE(false, "Other exception raised.");
    }
}

TEST_CASE("Bad port")
{
    const auto test_bad_port = [](std::string bad_port)
        {
            try
            {
                questdb::line_sender sender{
                    "localhost",
                    bad_port};
                CHECK_MESSAGE(false, "Expected exception");
            }
            catch (const questdb::line_sender_error& se)
            {
                std::string msg{se.what()};
                std::string exp_msg{"\"localhost:" + bad_port + "\": "};
                CHECK(msg.find(exp_msg) != std::string::npos);
            }
            catch (...)
            {
                CHECK_MESSAGE(false, "Other exception raised.");
            }
        };

    test_bad_port("wombat");
    test_bad_port("0");

    // On Windows this *actually* resolves, but fails to connect.
    test_bad_port("-1");
}

TEST_CASE("Bad connect")
{
    try
    {
        // Port 1 is generally the tcpmux service which one would
        // very much expect to never be running.
        questdb::line_sender sender{
            "127.0.0.1",
            1};
        CHECK_MESSAGE(false, "Expected exception");
    }
    catch (const questdb::line_sender_error& se)
    {
        std::string msg{se.what()};
        CHECK(msg.rfind("Could not connect", 0) == 0);
    }
    catch (...)
    {
        CHECK_MESSAGE(false, "Other exception raised.");
    }
}
