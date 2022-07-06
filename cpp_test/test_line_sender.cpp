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

#include <questdb/ilp/line_sender.h>
#include <questdb/ilp/line_sender.hpp>

#include <vector>
#include <sstream>
#include <chrono>
#include <thread>

using namespace std::string_literals;
using namespace questdb::ilp::literals;

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
    questdb::ilp::test::mock_server server;
    ::line_sender_error* err = nullptr;
    on_scope_exit error_free_guard{[&]{
            if (err)
                ::line_sender_error_free(err);
        }};
    ::line_sender_utf8 host = {0, nullptr};
    CHECK(::line_sender_utf8_init(&host, 9, "localhost", &err));
    ::line_sender_opts* opts = ::line_sender_opts_new(host, server.port());
    CHECK_NE(opts, nullptr);
    ::line_sender* sender = ::line_sender_connect(opts, &err);
    line_sender_opts_free(opts);
    CHECK_NE(sender, nullptr);
    CHECK_FALSE(::line_sender_must_close(sender));
    on_scope_exit sender_close_guard{[&]
        {
            ::line_sender_close(sender);
            sender = nullptr;
        }};
    server.accept();
    CHECK(server.recv() == 0);
    ::line_sender_table_name table_name{0, nullptr};
    const char* test_buf = "test";
    CHECK(::line_sender_table_name_init(&table_name, 4, test_buf, &err));
    CHECK(table_name.len == 4);
    CHECK(table_name.buf == test_buf);
    ::line_sender_column_name t1_name{0, nullptr};
    CHECK(::line_sender_column_name_init(&t1_name, 2, "t1", &err));
    ::line_sender_utf8 v1_utf8{0, nullptr};
    CHECK(::line_sender_utf8_init(&v1_utf8, 2, "v1", &err));
    ::line_sender_column_name f1_name{0, nullptr};
    CHECK(::line_sender_column_name_init(&f1_name, 2, "f1", &err));
    ::line_sender_buffer* buffer = line_sender_buffer_new();
    CHECK(buffer != nullptr);
    CHECK(::line_sender_buffer_table(buffer, table_name, &err));
    CHECK(::line_sender_buffer_symbol(buffer, t1_name, v1_utf8, &err));
    CHECK(::line_sender_buffer_column_f64(buffer, f1_name, 0.5, &err));
    CHECK(::line_sender_buffer_at(buffer, 10000000, &err));
    CHECK(server.recv() == 0);
    CHECK(::line_sender_buffer_size(buffer) == 27);
    CHECK(::line_sender_flush(sender, buffer, &err));
    ::line_sender_buffer_free(buffer);
    CHECK(server.recv() == 1);
    CHECK(server.msgs().front() == "test,t1=v1 f1=0.5 10000000\n");
}

TEST_CASE("line_sender c++ connect disconnect")
{
    questdb::ilp::test::mock_server server;
    questdb::ilp::line_sender sender{"localhost", server.port()};
    CHECK_FALSE(sender.must_close());
    server.accept();
    CHECK(server.recv() == 0);
}

TEST_CASE("line_sender c++ api basics")
{
    questdb::ilp::test::mock_server server;
    questdb::ilp::line_sender sender{
        std::string("localhost"),
        std::to_string(server.port())};
    CHECK_FALSE(sender.must_close());
    server.accept();
    CHECK(server.recv() == 0);

    questdb::ilp::line_sender_buffer buffer;
    buffer
        .table("test")
        .symbol("t1", "v1")
        .symbol("t2", "")
        .column("f1", 0.5)
        .at(questdb::ilp::timestamp_nanos{10000000});

    CHECK(server.recv() == 0);
    CHECK(buffer.size() == 31);
    sender.flush(buffer);
    CHECK(server.recv() == 1);
    CHECK(server.msgs().front() == "test,t1=v1,t2= f1=0.5 10000000\n");
}

TEST_CASE("test multiple lines")
{
    questdb::ilp::test::mock_server server;
    questdb::ilp::line_sender sender{
        "localhost",
        server.port()};
    CHECK_FALSE(sender.must_close());
    server.accept();
    CHECK(server.recv() == 0);

    const auto table_name = "metric1"_tn;
    questdb::ilp::line_sender_buffer buffer;
    buffer
        .table(table_name)
        .symbol("t1"_cn, "val1"_utf8)
        .symbol("t2"_cn, "val2"_utf8)
        .column("f1"_cn, true)
        .column("f2"_cn, static_cast<int64_t>(12345))
        .column("f3"_cn, 10.75)
        .column("f4"_cn, "val3"_utf8)
        .column("f5"_cn, "val4"_utf8)
        .column("f6"_cn, "val5"_utf8)
        .at(questdb::ilp::timestamp_nanos{111222233333});
    buffer
        .table(table_name)
        .symbol("tag3"_cn, "value 3"_utf8)
        .symbol("tag 4"_cn, "value:4"_utf8)
        .column("field5"_cn, false)
        .at_now();

    CHECK(server.recv() == 0);
    CHECK(buffer.size() == 137);
    sender.flush(buffer);
    CHECK(server.recv() == 2);
    CHECK(server.msgs()[0] ==
        ("metric1,t1=val1,t2=val2 f1=t,f2=12345i,"
         "f3=10.75,f4=\"val3\",f5=\"val4\",f6=\"val5\" 111222233333\n"));
    CHECK(server.msgs()[1] ==
        "metric1,tag3=value\\ 3,tag\\ 4=value:4 field5=f\n");
}

TEST_CASE("State machine testing -- flush without data.")
{
    questdb::ilp::test::mock_server server;
    questdb::ilp::line_sender sender{
        std::string_view{"localhost"},
        std::to_string(server.port())};

    questdb::ilp::line_sender_buffer buffer;
    CHECK(buffer.size() == 0);
    CHECK_THROWS_WITH_AS(
        sender.flush(buffer),
        "State error: Bad call to `flush`, should have called `table` instead.",
        questdb::ilp::line_sender_error);
    CHECK(!sender.must_close());
    sender.close();
}

TEST_CASE("One symbol only - flush before server accept")
{
    questdb::ilp::test::mock_server server;
    questdb::ilp::line_sender sender{
        std::string{"localhost"},
        server.port()};

    // Does not raise - this is unlike InfluxDB spec that disallows this.
    questdb::ilp::line_sender_buffer buffer;
    buffer.table("test").symbol("t1", std::string{"v1"}).at_now();
    CHECK(!sender.must_close());
    CHECK(buffer.size() == 11);
    sender.flush(buffer);
    sender.close();

    // Note the client has closed already,
    // but the server hasn't actually accepted the client connection yet.
    server.accept();
    CHECK(server.recv() == 1);
    CHECK(server.msgs()[0] == "test,t1=v1\n");
}

TEST_CASE("One column only - server.accept() after flush, before close")
{
    questdb::ilp::test::mock_server server;
    questdb::ilp::line_sender sender{
        "localhost",
        server.port()};

    // Does not raise - this is unlike InfluxDB spec that disallows this.
    questdb::ilp::line_sender_buffer buffer;
    buffer.table("test").column("t1", "v1").at_now();
    CHECK(!sender.must_close());
    CHECK(buffer.size() == 13);
    sender.flush(buffer);

    server.accept();
    sender.close();

    CHECK(server.recv() == 1);
    CHECK(server.msgs()[0] == "test t1=\"v1\"\n");
}

TEST_CASE("Symbol after column")
{
    questdb::ilp::test::mock_server server;
    questdb::ilp::line_sender sender{
        "localhost",
        server.port()};

    questdb::ilp::line_sender_buffer buffer;
    buffer.table("test").column("t1", "v1");

    CHECK_THROWS_AS(
        buffer.symbol("t2", "v2"),
        questdb::ilp::line_sender_error);

    CHECK(!sender.must_close());

    CHECK_THROWS_WITH_AS(
        sender.flush(buffer),
        "State error: Bad call to `flush`, "
        "should have called `column` or `at` instead.",
        questdb::ilp::line_sender_error);

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
        questdb::ilp::line_sender_error);
}

TEST_CASE("Validation of bad chars in key names.")
{
    {
        CHECK_THROWS_WITH_AS(
            "a*b"_tn,
            "Bad string \"a*b\": Table names "
            "can't contain a '*' character, "
            "which was found at byte position 1.",
            questdb::ilp::line_sender_error);
    }

    {
        CHECK_THROWS_WITH_AS(
            "a+b"_tn,
            "Bad string \"a+b\": Table names "
            "can't contain a '+' character, "
            "which was found at byte position 1.",
            questdb::ilp::line_sender_error);
    }

    {
        std::string_view column_name{"a\0b", 3};
        CHECK_THROWS_WITH_AS(
            questdb::ilp::column_name_view{column_name},
            "Bad string \"a\\0b\": Column names "
            "can't contain a '\\0' character, "
            "which was found at byte position 1.",
            questdb::ilp::line_sender_error);
    }

    auto test_bad_name = [](std::string bad_name)
        {
            try
            {
                questdb::ilp::column_name_view{bad_name};
                std::stringstream ss;
                ss << "Name `" << bad_name << "` (";
                for (const char& c : bad_name)
                {
                    ss << "\\x"
                       << std::hex
                       << std::setw(2)
                       << std::setfill('0')
                       << (int)c;
                }
                ss << ") did not raise.";
                CHECK_MESSAGE(false, ss.str());
            }
            catch (const questdb::ilp::line_sender_error&)
            {
                return;
            }
            catch (...)
            {
                CHECK_MESSAGE(false, "Other exception raised.");
            }
        };

    std::vector<std::string> bad_chars{
        "?"s, "."s, ","s, "'"s, "\""s, "\\"s, "/"s, "\0"s, ":"s,
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

TEST_CASE("Buffer move and copy ctor testing")
{
    const size_t init_capacity = 128;

    questdb::ilp::line_sender_buffer buffer1{init_capacity};
    buffer1.table("buffer1");
    CHECK(buffer1.peek() == "buffer1");

    questdb::ilp::line_sender_buffer buffer2{2 * init_capacity};
    buffer2.table("buffer2");
    CHECK(buffer2.peek() == "buffer2");

    questdb::ilp::line_sender_buffer buffer3{3 * init_capacity};
    buffer3.table("buffer3");
    CHECK(buffer3.peek() == "buffer3");

    questdb::ilp::line_sender_buffer buffer4{buffer3};
    buffer4.symbol("t1", "v1");
    CHECK(buffer4.peek() == "buffer3,t1=v1");
    CHECK(buffer3.peek() == "buffer3");

    questdb::ilp::line_sender_buffer buffer5{std::move(buffer4)};
    CHECK(buffer5.peek() == "buffer3,t1=v1");
    CHECK(buffer4.peek() == "");

    buffer4.table("buffer4");
    CHECK(buffer4.peek() == "buffer4");

    buffer1 = buffer2;
    CHECK(buffer1.peek() == "buffer2");
    CHECK(buffer2.peek() == "buffer2");

    buffer1 = std::move(buffer3);
    CHECK(buffer1.peek() == "buffer3");
    CHECK(buffer3.peek() == "");
    CHECK(buffer3.size() == 0);
    CHECK(buffer3.capacity() == 3 * init_capacity);
    CHECK(buffer3.peek() == "");


}

TEST_CASE("Sender move testing.")
{
    questdb::ilp::test::mock_server server1;
    questdb::ilp::test::mock_server server2;

    questdb::ilp::utf8_view host{"localhost"};
    const questdb::ilp::utf8_view& host_ref = host;

    questdb::ilp::line_sender sender1{
        host_ref,
        server1.port()};

    questdb::ilp::line_sender_buffer buffer;
    buffer.table("test").column("t1", "v1").at_now();

    server1.close();

    auto fail_to_flush_eventually = [&]() {
        for (size_t counter = 0; counter < 1000; ++counter)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            sender1.flush_and_keep(buffer);
        }
    };

    CHECK_THROWS_AS(
        fail_to_flush_eventually(),
        questdb::ilp::line_sender_error);
    CHECK(sender1.must_close());

    questdb::ilp::line_sender sender2{std::move(sender1)};

    CHECK_FALSE(sender1.must_close());
    CHECK(sender2.must_close());

    questdb::ilp::line_sender sender3{
        "localhost",
        server2.port()};
    CHECK_FALSE(sender3.must_close());

    sender3 = std::move(sender2);
    CHECK(sender3.must_close());
}

TEST_CASE("Bad hostname")
{
    try
    {
        questdb::ilp::line_sender sender{"dummy_hostname", "9009"};
        CHECK_MESSAGE(false, "Expected exception");
    }
    catch (const questdb::ilp::line_sender_error& se)
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
        questdb::ilp::opts opts{"localhost", "9009"};
        opts.net_interface("dummy_hostname");
        questdb::ilp::line_sender sender{opts};
        CHECK_MESSAGE(false, "Expected exception");
    }
    catch (const questdb::ilp::line_sender_error& se)
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
                questdb::ilp::line_sender sender{
                    "localhost",
                    bad_port};
                CHECK_MESSAGE(false, "Expected exception");
            }
            catch (const questdb::ilp::line_sender_error& se)
            {
                std::string msg{se.what()};
                std::string exp_msg{"\"localhost:" + bad_port + "\": "};
                CHECK_MESSAGE(msg.find(exp_msg) != std::string::npos, msg);
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
        questdb::ilp::line_sender sender{
            "localhost",
            1};
        CHECK_MESSAGE(false, "Expected exception");
    }
    catch (const questdb::ilp::line_sender_error& se)
    {
        std::string msg{se.what()};
        CHECK(msg.rfind("Could not connect", 0) == 0);
    }
    catch (...)
    {
        CHECK_MESSAGE(false, "Other exception raised.");
    }
}

TEST_CASE("Bad CA path")
{
    try
    {
        questdb::ilp::test::mock_server server;
        questdb::ilp::opts opts{"localhost", server.port()};
        opts.tls("/an/invalid/path/to/ca.pem");
        questdb::ilp::line_sender sender{opts};
    }
    catch(const questdb::ilp::line_sender_error& se)
    {
        std::string msg{se.what()};
        CHECK(msg.rfind("Could not open certificate authority file", 0) == 0);
    }
    catch (...)
    {
        CHECK_MESSAGE(false, "Other exception raised.");
    }
}

TEST_CASE("Opts copy ctor, assignment and move testing.")
{
    {
        questdb::ilp::opts opts1{"localhost", "9009"};
        questdb::ilp::opts opts2{std::move(opts1)};
    }

    {
        questdb::ilp::opts opts1{"localhost", "9009"};
        questdb::ilp::opts opts2{opts1};
    }

    {
        questdb::ilp::opts opts1{"localhost", "9009"};
        questdb::ilp::opts opts2{"altavista.digital.com", "9009"};
        opts1 = std::move(opts2);
    }

    {
        questdb::ilp::opts opts1{"localhost", "9009"};
        questdb::ilp::opts opts2{"altavista.digital.com", "9009"};
        opts1 = opts2;
    }
}

TEST_CASE("Test timestamp column.")
{
    questdb::ilp::test::mock_server server;
    questdb::ilp::line_sender sender{"localhost", server.port()};

    const auto now = std::chrono::system_clock::now();
    const auto now_micros =
        std::chrono::duration_cast<std::chrono::microseconds>(
            now.time_since_epoch()).count();
    const auto now_nanos =
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            now.time_since_epoch()).count();

    questdb::ilp::line_sender_buffer buffer;
    buffer
        .table("test")
        .column("ts1", questdb::ilp::timestamp_micros{12345})
        .column("ts2", questdb::ilp::timestamp_micros{now})
        .at(now);

    std::stringstream ss;
    ss << "test ts1=12345t,ts2=" << now_micros << "t " << now_nanos << "\n";
    const auto exp = ss.str();
    CHECK(buffer.peek() == exp);

    sender.flush_and_keep(buffer);

    CHECK(buffer.peek() == exp);

    server.accept();
    sender.close();

    CHECK(server.recv() == 1);
    CHECK(server.msgs()[0] == exp);
}