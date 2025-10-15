/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2025 QuestDB
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

#include <questdb/ingress/line_sender.h>
#include <questdb/ingress/line_sender.hpp>

#include <chrono>
#include <cstring>
#include <sstream>
#include <thread>
#include <vector>

using namespace std::string_literals;
using namespace questdb::ingress::literals;

template <typename F>
class on_scope_exit
{
public:
    explicit on_scope_exit(F&& f)
        : _f{std::move(f)}
    {
    }
    ~on_scope_exit()
    {
        _f();
    }

private:
    F _f;
};

#if __cplusplus >= 202002L
template <size_t N>
bool operator==(std::span<const std::byte> lhs, const char (&rhs)[N])
{
    constexpr size_t bytelen = N - 1; // Exclude null terminator
    const std::span<const std::byte> rhs_span{
        reinterpret_cast<const std::byte*>(rhs), bytelen};
    return lhs.size() == bytelen && std::ranges::equal(lhs, rhs_span);
}

bool operator==(std::span<const std::byte> lhs, const std::string& rhs)
{
    const std::span<const std::byte> rhs_span{
        reinterpret_cast<const std::byte*>(rhs.data()), rhs.size()};
    return lhs.size() == rhs.size() && std::ranges::equal(lhs, rhs_span);
}
#else
template <size_t N>
bool operator==(
    const questdb::ingress::buffer_view lhs_view, const char (&rhs)[N])
{
    constexpr size_t bytelen = N - 1; // Exclude null terminator
    const questdb::ingress::buffer_view rhs_view{
        reinterpret_cast<const std::byte*>(rhs), bytelen};
    return lhs_view == rhs_view;
}

bool operator==(
    const questdb::ingress::buffer_view lhs_view, const std::string& rhs)
{
    const questdb::ingress::buffer_view rhs_view{
        reinterpret_cast<const std::byte*>(rhs.data()), rhs.size()};
    return lhs_view == rhs_view;
}
#endif

template <size_t N>
std::string& push_double_arr_to_buffer(
    std::string& buffer,
    std::array<double, N> data,
    size_t rank,
    uintptr_t* shape)
{
    buffer.push_back(14);
    buffer.push_back(10);
    buffer.push_back(static_cast<char>(rank));
    for (size_t i = 0; i < rank; ++i)
        buffer.append(
            reinterpret_cast<const char*>(&shape[i]), sizeof(uint32_t));
    buffer.append(
        reinterpret_cast<const char*>(data.data()),
        data.size() * sizeof(double));
    return buffer;
}

std::string& push_double_arr_to_buffer(
    std::string& buffer,
    std::vector<double>& data,
    size_t rank,
    uintptr_t* shape)
{
    buffer.push_back(14);
    buffer.push_back(10);
    buffer.push_back(static_cast<char>(rank));
    for (size_t i = 0; i < rank; ++i)
        buffer.append(
            reinterpret_cast<const char*>(&shape[i]), sizeof(uint32_t));
    buffer.append(
        reinterpret_cast<const char*>(data.data()),
        data.size() * sizeof(double));
    return buffer;
}

std::string& push_double_to_buffer(std::string& buffer, double data)
{
    buffer.push_back(16);
    buffer.append(reinterpret_cast<const char*>(&data), sizeof(double));
    return buffer;
}

TEST_CASE("line_sender c api basics")
{
    questdb::ingress::test::mock_server server;
    ::line_sender_error* err = nullptr;
    on_scope_exit error_free_guard{[&] {
        if (err)
            ::line_sender_error_free(err);
    }};
    ::line_sender_utf8 host = {0, nullptr};
    CHECK(::line_sender_utf8_init(&host, 9, "127.0.0.1", &err));
    ::line_sender_opts* opts =
        ::line_sender_opts_new(::line_sender_protocol_tcp, host, server.port());
    CHECK_NE(opts, nullptr);
    line_sender_opts_protocol_version(
        opts, ::line_sender_protocol_version_2, &err);
    ::line_sender* sender = ::line_sender_build(opts, &err);
    line_sender_opts_free(opts);
    CHECK_NE(sender, nullptr);
    CHECK_FALSE(::line_sender_must_close(sender));
    on_scope_exit sender_close_guard{[&] {
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
    ::line_sender_buffer* buffer = line_sender_buffer_new_for_sender(sender);
    CHECK(buffer != nullptr);
    CHECK(::line_sender_buffer_table(buffer, table_name, &err));
    CHECK(::line_sender_buffer_symbol(buffer, t1_name, v1_utf8, &err));
    CHECK(::line_sender_buffer_column_f64(buffer, f1_name, 0.5, &err));

    line_sender_column_name arr_name = QDB_COLUMN_NAME_LITERAL("a1");
    // 3D array of doubles
    size_t rank = 3;
    uintptr_t shape[] = {2, 3, 2};
    intptr_t strides[] = {48, 16, 8};
    std::array<double, 12> arr_data = {
        48123.5,
        2.4,
        48124.0,
        1.8,
        48124.5,
        0.9,
        48122.5,
        3.1,
        48122.0,
        2.7,
        48121.5,
        4.3};
    CHECK(
        ::line_sender_buffer_column_f64_arr_byte_strides(
            buffer,
            arr_name,
            rank,
            shape,
            strides,
            arr_data.data(),
            arr_data.size(),
            &err));

    line_sender_column_name arr_name2 = QDB_COLUMN_NAME_LITERAL("a2");
    intptr_t elem_strides[] = {6, 2, 1};
    CHECK(
        ::line_sender_buffer_column_f64_arr_elem_strides(
            buffer,
            arr_name2,
            rank,
            shape,
            elem_strides,
            arr_data.data(),
            arr_data.size(),
            &err));
    line_sender_column_name arr_name3 = QDB_COLUMN_NAME_LITERAL("a3");
    CHECK(
        ::line_sender_buffer_column_f64_arr_c_major(
            buffer,
            arr_name3,
            rank,
            shape,
            arr_data.data(),
            arr_data.size(),
            &err));
    CHECK(::line_sender_buffer_at_nanos(buffer, 10000000, &err));
    CHECK(server.recv() == 0);
    CHECK(::line_sender_buffer_size(buffer) == 382);
    CHECK(::line_sender_flush(sender, buffer, &err));
    ::line_sender_buffer_free(buffer);
    CHECK(server.recv() == 1);
    std::string expect{"test,t1=v1 f1=="};
    push_double_to_buffer(expect, 0.5).append(",a1==");
    push_double_arr_to_buffer(expect, arr_data, 3, shape).append(",a2==");
    push_double_arr_to_buffer(expect, arr_data, 3, shape).append(",a3==");
    push_double_arr_to_buffer(expect, arr_data, 3, shape).append(" 10000000\n");
    CHECK(server.msgs(0) == expect);
}

TEST_CASE("Opts service API tests")
{
    // We just check these compile and link.

    line_sender_utf8 host = QDB_UTF8_LITERAL("localhost");
    line_sender_utf8 port = QDB_UTF8_LITERAL("9009");

    ::line_sender_protocol protocols[] = {
        ::line_sender_protocol_tcp,
        ::line_sender_protocol_tcps,
        ::line_sender_protocol_http,
        ::line_sender_protocol_https};

    for (size_t index = 0;
         index < sizeof(protocols) / sizeof(::line_sender_protocol);
         ++index)
    {
        auto proto = protocols[index];
        ::line_sender_opts* opts1 =
            ::line_sender_opts_new_service(proto, host, port);
        ::line_sender_opts_free(opts1);
    }
}

TEST_CASE("line_sender c++ connect disconnect")
{
    questdb::ingress::test::mock_server server;
    questdb::ingress::line_sender sender{questdb::ingress::opts{
        questdb::ingress::protocol::tcp, "127.0.0.1", server.port()}};
    CHECK_FALSE(sender.must_close());
    server.accept();
    CHECK(server.recv() == 0);
}

TEST_CASE("line_sender c++ api basics")
{
    questdb::ingress::test::mock_server server;
    questdb::ingress::opts opts{
        questdb::ingress::protocol::tcp,
        std::string("127.0.0.1"),
        std::to_string(server.port())};
    opts.protocol_version(questdb::ingress::protocol_version::v2);
    questdb::ingress::line_sender sender{opts};
    CHECK_FALSE(sender.must_close());
    server.accept();
    CHECK(server.recv() == 0);

    questdb::ingress::line_sender_buffer buffer = sender.new_buffer();
    // 3D array of doubles
    size_t rank = 3;
    uintptr_t shape[] = {2, 3, 2};
    intptr_t strides[] = {48, 16, 8};
    std::array<double, 12> arr_data = {
        48123.5,
        2.4,
        48124.0,
        1.8,
        48124.5,
        0.9,
        48122.5,
        3.1,
        48122.0,
        2.7,
        48121.5,
        4.3};
    intptr_t elem_strides[] = {6, 2, 1};
    questdb::ingress::array::
        strided_view<double, questdb::ingress::array::strides_mode::bytes>
            a1{rank, shape, strides, arr_data.data(), arr_data.size()};
    questdb::ingress::array::
        strided_view<double, questdb::ingress::array::strides_mode::elements>
            a2{rank, shape, elem_strides, arr_data.data(), arr_data.size()};
    questdb::ingress::array::row_major_view<double> a3{
        rank, shape, arr_data.data(), arr_data.size()};
    questdb::ingress::array::
        strided_view<double, questdb::ingress::array::strides_mode::bytes>
            a4{rank, shape, strides, arr_data.data(), arr_data.size()};
    buffer.table("test")
        .symbol("t1", "v1")
        .symbol("t2", "")
        .column("f1", 0.5)
        .column("a1", a1)
        .column("a2", a2)
        .column("a3", a3)
        .column("a4", a4)
        .column("a5", arr_data)
        .at(questdb::ingress::timestamp_nanos{10000000});

    CHECK(server.recv() == 0);
    CHECK(buffer.size() == 610);
    sender.flush(buffer);
    CHECK(server.recv() == 1);
    std::string expect{"test,t1=v1,t2= f1=="};
    uintptr_t shapes_1dim[] = {12};
    push_double_to_buffer(expect, 0.5).append(",a1==");
    push_double_arr_to_buffer(expect, arr_data, 3, shape).append(",a2==");
    push_double_arr_to_buffer(expect, arr_data, 3, shape).append(",a3==");
    push_double_arr_to_buffer(expect, arr_data, 3, shape).append(",a4==");
    push_double_arr_to_buffer(expect, arr_data, 3, shape).append(",a5==");
    push_double_arr_to_buffer(expect, arr_data, 1, shapes_1dim)
        .append(" 10000000\n");
    CHECK(server.msgs(0) == expect);
}

TEST_CASE("line_sender array vector API")
{
    questdb::ingress::test::mock_server server;
    questdb::ingress::opts opts{
        questdb::ingress::protocol::tcp,
        std::string("127.0.0.1"),
        std::to_string(server.port())};
    opts.protocol_version(questdb::ingress::protocol_version::v2);
    questdb::ingress::line_sender sender{opts};
    CHECK_FALSE(sender.must_close());
    server.accept();
    CHECK(server.recv() == 0);
    questdb::ingress::line_sender_buffer buffer = sender.new_buffer();
    std::vector<double> arr_data = {
        48123.5,
        2.4,
        48124.0,
        1.8,
        48124.5,
        0.9,
        48122.5,
        3.1,
        48122.0,
        2.7,
        48121.5,
        4.3};
    buffer.table("test")
        .symbol("t1", "v1")
        .symbol("t2", "")
        .column("a1", arr_data)
        .at(questdb::ingress::timestamp_nanos{10000000});

    uintptr_t test_shape[] = {12};
    CHECK(server.recv() == 0);
    CHECK(buffer.size() == 132);
    sender.flush(buffer);
    CHECK(server.recv() == 1);
    std::string expect{"test,t1=v1,t2= a1=="};
    push_double_arr_to_buffer(expect, arr_data, 1, test_shape)
        .append(" 10000000\n");
    CHECK(server.msgs(0) == expect);
}

#if __cplusplus >= 202002L
TEST_CASE("line_sender array span API")
{
    questdb::ingress::test::mock_server server;
    questdb::ingress::opts opts{
        questdb::ingress::protocol::tcp,
        std::string("127.0.0.1"),
        std::to_string(server.port())};
    opts.protocol_version(questdb::ingress::protocol_version::v2);
    questdb::ingress::line_sender sender{opts};
    CHECK_FALSE(sender.must_close());
    server.accept();
    CHECK(server.recv() == 0);

    questdb::ingress::line_sender_buffer buffer = sender.new_buffer();

    std::vector<double> arr_data = {
        48123.5,
        2.4,
        48124.0,
        1.8,
        48124.5,
        0.9,
        48122.5,
        3.1,
        48122.0,
        2.7,
        48121.5,
        4.3};
    std::span<const double> data_span = arr_data;
    buffer.table("test")
        .symbol("t1", "v1")
        .symbol("t2", "")
        .column("a1", data_span.subspan(1, 8))
        .at(questdb::ingress::timestamp_nanos{10000000});
    std::vector<double> expect_arr_data = {
        2.4, 48124.0, 1.8, 48124.5, 0.9, 48122.5, 3.1, 48122.0};

    uintptr_t test_shape[] = {8};
    CHECK(server.recv() == 0);
    CHECK(buffer.size() == 100);
    sender.flush(buffer);
    CHECK(server.recv() == 1);
    std::string expect{"test,t1=v1,t2= a1=="};
    push_double_arr_to_buffer(expect, expect_arr_data, 1, test_shape)
        .append(" 10000000\n");
    CHECK(server.msgs(0) == expect);
}
#endif

TEST_CASE("test multiple lines")
{
    questdb::ingress::test::mock_server server;
    std::string conf_str =
        "tcp::addr=127.0.0.1:" + std::to_string(server.port()) +
        ";protocol_version=3;";
    questdb::ingress::line_sender sender =
        questdb::ingress::line_sender::from_conf(conf_str);
    CHECK_FALSE(sender.must_close());
    server.accept();
    CHECK(server.recv() == 0);

    const auto table_name = "metric1"_tn;
    questdb::ingress::line_sender_buffer buffer = sender.new_buffer();
    buffer.table(table_name)
        .symbol("t1"_cn, "val1"_utf8)
        .symbol("t2"_cn, "val2"_utf8)
        .column("f1"_cn, true)
        .column("f2"_cn, static_cast<int64_t>(12345))
        .column("f3"_cn, 10.75)
        .column("f4"_cn, "val3"_utf8)
        .column("f5"_cn, "val4"_utf8)
        .column("f6"_cn, "val5"_utf8)
        .at(questdb::ingress::timestamp_nanos{111222233333});
    buffer.table(table_name)
        .symbol("tag3"_cn, "value 3"_utf8)
        .symbol("tag 4"_cn, "value:4"_utf8)
        .column("field5"_cn, false)
        .at_now();

    CHECK(server.recv() == 0);
    CHECK(buffer.size() == 142);
    sender.flush(buffer);
    CHECK(server.recv() == 2);
    std::string expect{"metric1,t1=val1,t2=val2 f1=t,f2=12345i,f3=="};
    push_double_to_buffer(expect, 10.75)
        .append(",f4=\"val3\",f5=\"val4\",f6=\"val5\" 111222233333\n");
    CHECK(server.msgs(0) == expect);
    CHECK(
        server.msgs(1) == "metric1,tag3=value\\ 3,tag\\ 4=value:4 field5=f\n");
}

TEST_CASE("State machine testing -- flush without data.")
{
    questdb::ingress::test::mock_server server;
    questdb::ingress::line_sender sender{questdb::ingress::opts{
        questdb::ingress::protocol::tcp,
        std::string_view{"127.0.0.1"},
        std::to_string(server.port())}};

    questdb::ingress::line_sender_buffer buffer = sender.new_buffer();
    CHECK(buffer.size() == 0);
    CHECK_THROWS_WITH_AS(
        sender.flush(buffer),
        "State error: Bad call to `flush`, should have called `table` instead.",
        questdb::ingress::line_sender_error);
    CHECK(!sender.must_close());
    sender.close();
}

TEST_CASE("One symbol only - flush before server accept")
{
    questdb::ingress::test::mock_server server;
    questdb::ingress::line_sender sender{questdb::ingress::opts{
        questdb::ingress::protocol::tcp,
        std::string{"127.0.0.1"},
        server.port()}};

    // Does not raise - this is unlike InfluxDB spec that disallows this.
    questdb::ingress::line_sender_buffer buffer = sender.new_buffer();
    buffer.table("test").symbol("t1", std::string{"v1"}).at_now();
    CHECK(!sender.must_close());
    CHECK(buffer.size() == 11);
    sender.flush(buffer);
    sender.close();

    // Note the client has closed already,
    // but the server hasn't actually accepted the client connection yet.
    server.accept();
    CHECK(server.recv() == 1);
    CHECK(server.msgs(0) == "test,t1=v1\n");
}

TEST_CASE("One column only - server.accept() after flush, before close")
{
    questdb::ingress::test::mock_server server;
    questdb::ingress::line_sender sender{questdb::ingress::opts{
        questdb::ingress::protocol::tcp, "127.0.0.1", server.port()}};

    // Does not raise - this is unlike the InfluxDB spec that disallows this.
    questdb::ingress::line_sender_buffer buffer = sender.new_buffer();
    buffer.table("test").column("t1", "v1").at_now();
    CHECK(!sender.must_close());
    CHECK(buffer.size() == 13);
    sender.flush(buffer);

    server.accept();
    sender.close();

    CHECK(server.recv() == 1);
    CHECK(server.msgs(0) == "test t1=\"v1\"\n");
}

TEST_CASE("Symbol after column")
{
    questdb::ingress::test::mock_server server;
    questdb::ingress::line_sender sender{questdb::ingress::opts{
        questdb::ingress::protocol::tcp, "127.0.0.1", server.port()}};

    questdb::ingress::line_sender_buffer buffer = sender.new_buffer();
    buffer.table("test").column("t1", "v1");

    CHECK_THROWS_AS(
        buffer.symbol("t2", "v2"), questdb::ingress::line_sender_error);

    CHECK(!sender.must_close());

    CHECK_THROWS_WITH_AS(
        sender.flush(buffer),
        "State error: Bad call to `flush`, "
        "should have called `column` or `at` instead.",
        questdb::ingress::line_sender_error);

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
        questdb::ingress::line_sender_error);
}

TEST_CASE("Validation of bad chars in key names.")
{
    {
        CHECK_THROWS_WITH_AS(
            "a*b"_tn,
            "Bad string \"a*b\": Table names "
            "can't contain a '*' character, "
            "which was found at byte position 1.",
            questdb::ingress::line_sender_error);
    }

    {
        CHECK_THROWS_WITH_AS(
            "a+b"_tn,
            "Bad string \"a+b\": Table names "
            "can't contain a '+' character, "
            "which was found at byte position 1.",
            questdb::ingress::line_sender_error);
    }

    {
        std::string_view column_name{"a\0b", 3};
        CHECK_THROWS_WITH_AS(
            questdb::ingress::column_name_view{column_name},
            "Bad string \"a\\0b\": Column names "
            "can't contain a '\\0' character, "
            "which was found at byte position 1.",
            questdb::ingress::line_sender_error);
    }

    auto test_bad_name = [](std::string bad_name) {
        try
        {
            questdb::ingress::column_name_view{bad_name};
            std::stringstream ss;
            ss << "Name `" << bad_name << "` (";
            for (const char& c : bad_name)
            {
                ss << "\\x" << std::hex << std::setw(2) << std::setfill('0')
                   << (int)c;
            }
            ss << ") did not raise.";
            CHECK_MESSAGE(false, ss.str());
        }
        catch (const questdb::ingress::line_sender_error&)
        {
            return;
        }
        catch (...)
        {
            CHECK_MESSAGE(false, "Other exception raised.");
        }
    };

    std::vector<std::string> bad_chars{
        "?"s,
        "."s,
        ","s,
        "'"s,
        "\""s,
        "\\"s,
        "/"s,
        "\0"s,
        ":"s,
        ")"s,
        "("s,
        "+"s,
        "-"s,
        "*"s,
        "%"s,
        "~"s,
        "\xef\xbb\xbf"s};

    for (const auto& bad_char : bad_chars)
    {
        std::vector<std::string> bad_names{
            bad_char + "abc", "ab" + bad_char + "c", "abc" + bad_char};
        for (const auto& bad_name : bad_names)
        {
            test_bad_name(bad_name);
        }
    }
}

TEST_CASE("Buffer move and copy ctor testing")
{
    const size_t init_buf_size = 128;

    questdb::ingress::line_sender_buffer buffer1{
        questdb::ingress::protocol_version::v1, init_buf_size};
    buffer1.table("buffer1");
    CHECK(buffer1.peek() == "buffer1");

    questdb::ingress::line_sender_buffer buffer2{
        questdb::ingress::protocol_version::v1, 2 * init_buf_size};
    buffer2.table("buffer2");
    CHECK(buffer2.peek() == "buffer2");

    questdb::ingress::line_sender_buffer buffer3{
        questdb::ingress::protocol_version::v1, 3 * init_buf_size};
    buffer3.table("buffer3");
    CHECK(buffer3.peek() == "buffer3");

    questdb::ingress::line_sender_buffer buffer4{buffer3};
    buffer4.symbol("t1", "v1");
    CHECK(buffer4.peek() == "buffer3,t1=v1");
    CHECK(buffer3.peek() == "buffer3");

    questdb::ingress::line_sender_buffer buffer5{std::move(buffer4)};
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
    CHECK(buffer3.capacity() == 0);
    CHECK(buffer3.peek() == "");
}

TEST_CASE("Sender move testing.")
{
    questdb::ingress::test::mock_server server1;
    questdb::ingress::test::mock_server server2;

    questdb::ingress::utf8_view host{"127.0.0.1"};
    const questdb::ingress::utf8_view& host_ref = host;

    questdb::ingress::line_sender sender1{questdb::ingress::opts{
        questdb::ingress::protocol::tcp, host_ref, server1.port()}};

    questdb::ingress::line_sender_buffer buffer = sender1.new_buffer();
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
        fail_to_flush_eventually(), questdb::ingress::line_sender_error);
    CHECK(sender1.must_close());

    questdb::ingress::line_sender sender2{std::move(sender1)};

    CHECK_FALSE(sender1.must_close());
    CHECK(sender2.must_close());

    questdb::ingress::line_sender sender3{questdb::ingress::opts{
        questdb::ingress::protocol::tcp, "127.0.0.1", server2.port()}};
    CHECK_FALSE(sender3.must_close());

    sender3 = std::move(sender2);
    CHECK(sender3.must_close());
}

TEST_CASE("Bad hostname")
{
    try
    {
        questdb::ingress::line_sender sender{questdb::ingress::opts{
            questdb::ingress::protocol::tcp, "dummy_hostname", "9009"}};
        CHECK_MESSAGE(false, "Expected exception");
    }
    catch (const questdb::ingress::line_sender_error& se)
    {
        std::string msg{se.what()};
        CHECK_MESSAGE(
            msg.rfind("Could not resolve \"dummy_hostname:9009\": ", 0) == 0,
            msg);
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
        questdb::ingress::opts opts{
            questdb::ingress::protocol::tcp, "127.0.0.1", "9009"};
        opts.bind_interface("dummy_hostname");
        questdb::ingress::line_sender sender{opts};
        CHECK_MESSAGE(false, "Expected exception");
    }
    catch (const questdb::ingress::line_sender_error& se)
    {
        std::string msg{se.what()};
        CHECK_MESSAGE(
            msg.rfind("Could not resolve \"dummy_hostname\": ", 0) == 0, msg);
    }
    catch (...)
    {
        CHECK_MESSAGE(false, "Other exception raised.");
    }
}

TEST_CASE("Bad port")
{
    const auto test_bad_port = [](std::string bad_port) {
        try
        {
            questdb::ingress::line_sender sender{questdb::ingress::opts{
                questdb::ingress::protocol::tcp, "127.0.0.1", bad_port}};
            CHECK_MESSAGE(false, "Expected exception");
        }
        catch (const questdb::ingress::line_sender_error& se)
        {
            std::string msg{se.what()};
            std::string exp_msg{"\"127.0.0.1:" + bad_port + "\": "};
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
        questdb::ingress::line_sender sender{questdb::ingress::opts{
            questdb::ingress::protocol::tcp, "127.0.0.1", 1}};
        CHECK_MESSAGE(false, "Expected exception");
    }
    catch (const questdb::ingress::line_sender_error& se)
    {
        std::string msg{se.what()};
        CHECK_MESSAGE(msg.rfind("Could not connect", 0) == 0, msg);
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
        questdb::ingress::test::mock_server server;
        questdb::ingress::opts opts{
            questdb::ingress::protocol::tcps, "localhost", server.port()};

        opts.auth_timeout(1000);

        opts.tls_ca(questdb::ingress::ca::pem_file);
        opts.tls_roots("/an/invalid/path/to/ca.pem");
        questdb::ingress::line_sender sender{opts};
    }
    catch (const questdb::ingress::line_sender_error& se)
    {
        std::string msg{se.what()};
        CHECK_MESSAGE(
            msg.rfind("Could not open root certificate file from path", 0) == 0,
            msg);
    }
    catch (...)
    {
        CHECK_MESSAGE(false, "Other exception raised.");
    }
}

TEST_CASE("os certs")
{
    // We're just checking these APIs don't throw.
    questdb::ingress::test::mock_server server;
    {
        questdb::ingress::opts opts{
            questdb::ingress::protocol::tcps, "localhost", server.port()};
        opts.tls_ca(questdb::ingress::ca::webpki_roots);
    }

    {
        questdb::ingress::opts opts{
            questdb::ingress::protocol::https, "localhost", server.port()};
        opts.tls_ca(questdb::ingress::ca::os_roots);
    }

    {
        questdb::ingress::opts opts{
            questdb::ingress::protocol::https, "localhost", server.port()};
        opts.tls_ca(questdb::ingress::ca::webpki_and_os_roots);
    }
}

TEST_CASE("Opts copy ctor, assignment and move testing.")
{
    {
        questdb::ingress::opts opts1{
            questdb::ingress::protocol::tcp, "127.0.0.1", "9009"};
        questdb::ingress::opts opts2{std::move(opts1)};
    }

    {
        questdb::ingress::opts opts1{
            questdb::ingress::protocol::tcps, "localhost", "9009"};
        questdb::ingress::opts opts2{opts1};
    }

    {
        questdb::ingress::opts opts1{
            questdb::ingress::protocol::tcp, "127.0.0.1", "9009"};
        questdb::ingress::opts opts2{
            questdb::ingress::protocol::tcp, "altavista.digital.com", "9009"};
        opts1 = std::move(opts2);
    }

    {
        questdb::ingress::opts opts1{
            questdb::ingress::protocol::https, "localhost", "9009"};
        questdb::ingress::opts opts2{
            questdb::ingress::protocol::https, "altavista.digital.com", "9009"};
        opts1 = opts2;
    }
}

TEST_CASE("Test timestamp column.")
{
    questdb::ingress::test::mock_server server;
    questdb::ingress::line_sender sender{questdb::ingress::opts{
        questdb::ingress::protocol::tcp, "127.0.0.1", server.port()}};

    const auto now = std::chrono::system_clock::now();
    const auto now_micros =
        std::chrono::duration_cast<std::chrono::microseconds>(
            now.time_since_epoch())
            .count();
    const auto now_nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(
                               now.time_since_epoch())
                               .count();

    const auto now_nanos_ts = questdb::ingress::timestamp_nanos{now_nanos};
    const auto now_micros_ts = questdb::ingress::timestamp_micros{now_micros};

    questdb::ingress::line_sender_buffer buffer = sender.new_buffer();
    buffer.table("test")
        .column("ts1", questdb::ingress::timestamp_micros{12345})
        .column("ts2", now_micros_ts)
        .column("ts3", now_nanos_ts)
        .at(now_nanos_ts);

    std::stringstream ss;
    ss << "test ts1=12345t,ts2=" << now_micros << "t,ts3=" << now_nanos << "n "
       << now_nanos << "\n";
    const auto exp = ss.str();
    CHECK(buffer.peek() == exp);

    try
    {
        sender.flush_and_keep_with_flags(buffer, true);
        CHECK_MESSAGE(false, "Expected exception");
    }
    catch (const questdb::ingress::line_sender_error& se)
    {
        std::string msg{se.what()};
        CHECK_MESSAGE(
            msg.rfind(
                "Transactional flushes are not supported for ILP over TCP",
                0) == 0,
            msg);
    }
    catch (...)
    {
        CHECK_MESSAGE(false, "Other exception raised.");
    }

    sender.flush_and_keep(buffer);
    sender.flush_and_keep_with_flags(buffer, false);
    CHECK(buffer.peek() == exp);

    server.accept();
    sender.close();

    CHECK(server.recv() == 2);
    CHECK(server.msgs(0) == exp);
    CHECK(server.msgs(1) == exp);
}

TEST_CASE("test timestamp_micros and timestamp_nanos::now()")
{
    // Explicit in tests, just to be sure we haven't messed up the return types
    // :-)
    questdb::ingress::timestamp_micros micros_now{
        questdb::ingress::timestamp_micros::now()};
    questdb::ingress::timestamp_nanos nanos_now{
        questdb::ingress::timestamp_nanos::now()};

    // Check both are not zero.
    CHECK(micros_now.as_micros() != 0);
    CHECK(nanos_now.as_nanos() != 0);

    // Check both are within half second of each other.
    const int64_t micros_of_nanos = nanos_now.as_nanos() / 1000;
    const int64_t half_second_micros = 500000;
    CHECK(
        std::abs(micros_of_nanos - micros_now.as_micros()) <
        half_second_micros);
}

TEST_CASE("Test Marker")
{
    questdb::ingress::line_sender_buffer buffer{
        questdb::ingress::protocol_version::v1};
    buffer.clear_marker();
    buffer.clear_marker();

    buffer.set_marker();
    buffer.table("test");
    CHECK(buffer.peek() == "test");
    CHECK(buffer.size() == 4);

    buffer.rewind_to_marker();
    CHECK(buffer.peek() == "");
    CHECK(buffer.size() == 0);

    // Can't rewind, no marker set: Cleared by `rewind_to_marker`.
    CHECK_THROWS_AS(
        buffer.rewind_to_marker(), questdb::ingress::line_sender_error);

    buffer.table("a").symbol("b", "c");
    CHECK_THROWS_AS(buffer.set_marker(), questdb::ingress::line_sender_error);
    CHECK_THROWS_AS(
        buffer.rewind_to_marker(), questdb::ingress::line_sender_error);
    CHECK(buffer.peek() == "a,b=c");

    buffer.at_now();
    CHECK(buffer.peek() == "a,b=c\n");

    buffer.set_marker();
    buffer.clear_marker();
    buffer.clear_marker();
    CHECK_THROWS_AS(
        buffer.rewind_to_marker(), questdb::ingress::line_sender_error);
    buffer.set_marker();
    buffer.table("d").symbol("e", "f");
    CHECK(buffer.peek() == "a,b=c\nd,e=f");

    buffer.rewind_to_marker();
    CHECK(buffer.peek() == "a,b=c\n");

    buffer.clear();
    CHECK(buffer.peek() == "");
    CHECK_THROWS_AS(
        buffer.rewind_to_marker(), questdb::ingress::line_sender_error);
}

TEST_CASE("Moved View")
{
    auto v1 = "abc"_tn;
    CHECK(v1.size() == 3);
    questdb::ingress::table_name_view v2{std::move(v1)};
    CHECK(v2.size() == 3);
    CHECK(v1.size() == 3);
    CHECK(v1.data() == v2.data());
}

TEST_CASE("Empty Buffer")
{
    questdb::ingress::line_sender_buffer b1{
        questdb::ingress::protocol_version::v2};
    CHECK(b1.size() == 0);
    questdb::ingress::line_sender_buffer b2{std::move(b1)};
    CHECK(b1.size() == 0);
    CHECK(b2.size() == 0);
    questdb::ingress::line_sender_buffer b3{
        questdb::ingress::protocol_version::v2};
    b3 = std::move(b2);
    CHECK(b2.size() == 0);
    CHECK(b3.size() == 0);
    questdb::ingress::line_sender_buffer b4{
        questdb::ingress::protocol_version::v2};
    b4.table("test").symbol("a", "b").at_now();
    questdb::ingress::line_sender_buffer b5{
        questdb::ingress::protocol_version::v2};
    b5 = std::move(b4);
    CHECK(b4.size() == 0);
    CHECK(b5.size() == 9);

    questdb::ingress::test::mock_server server;
    questdb::ingress::line_sender sender{questdb::ingress::opts{
        questdb::ingress::protocol::tcp, "127.0.0.1", server.port()}};
    CHECK_THROWS_WITH_AS(
        sender.flush(b1),
        "State error: Bad call to `flush`, should have called `table` instead.",
        questdb::ingress::line_sender_error);
    CHECK_THROWS_WITH_AS(
        sender.flush_and_keep(b1),
        "State error: Bad call to `flush`, should have called `table` instead.",
        questdb::ingress::line_sender_error);
}

TEST_CASE("Opts from conf")
{
    questdb::ingress::opts opts1 =
        questdb::ingress::opts::from_conf("tcp::addr=127.0.0.1:9009;");
    questdb::ingress::opts opts2 =
        questdb::ingress::opts::from_conf("tcps::addr=localhost:9009;");
    questdb::ingress::opts opts3 =
        questdb::ingress::opts::from_conf("https::addr=127.0.0.1:9009;");
    questdb::ingress::opts opts4 =
        questdb::ingress::opts::from_conf("https::addr=localhost:9009;");
}

TEST_CASE("HTTP basics")
{
    questdb::ingress::opts opts1{
        questdb::ingress::protocol::http, "127.0.0.1", 1};
    questdb::ingress::opts opts1conf = questdb::ingress::opts::from_conf(
        "http::addr=127.0.0.1:1;username=user;password=pass;request_timeout="
        "5000;retry_timeout=5;protocol_version=3;");
    questdb::ingress::opts opts2{
        questdb::ingress::protocol::https, "localhost", "1"};
    questdb::ingress::opts opts2conf = questdb::ingress::opts::from_conf(
        "http::addr=127.0.0.1:1;token=token;request_min_throughput=1000;retry_"
        "timeout=0;protocol_version=3;");
    opts1.protocol_version(questdb::ingress::protocol_version::v2)
        .username("user")
        .password("pass")
        .max_buf_size(1000000)
        .request_timeout(5000)
        .retry_timeout(5);
    opts2.protocol_version(questdb::ingress::protocol_version::v2)
        .token("token")
        .request_min_throughput(1000)
        .retry_timeout(0);
    questdb::ingress::line_sender sender1{opts1};
    questdb::ingress::line_sender sender1conf{opts1conf};
    questdb::ingress::line_sender sender2{opts2};
    questdb::ingress::line_sender sender2conf{opts2conf};

    questdb::ingress::line_sender_buffer b1 = sender1.new_buffer();
    b1.table("test").symbol("a", "b").at_now();

    CHECK_THROWS_AS(sender1.flush(b1), questdb::ingress::line_sender_error);
    CHECK_THROWS_AS(sender1conf.flush(b1), questdb::ingress::line_sender_error);
    CHECK_THROWS_AS(sender2.flush(b1), questdb::ingress::line_sender_error);
    CHECK_THROWS_AS(sender2conf.flush(b1), questdb::ingress::line_sender_error);

    CHECK_THROWS_AS(
        questdb::ingress::opts::from_conf(
            "http::addr=127.0.0.1:1;bind_interface=0.0.0.0;"),
        questdb::ingress::line_sender_error);
}

TEST_CASE("line sender protocol version default v1 for tcp")
{
    questdb::ingress::test::mock_server server;
    questdb::ingress::line_sender sender{questdb::ingress::opts{
        questdb::ingress::protocol::tcp,
        std::string("127.0.0.1"),
        std::to_string(server.port())}};
    CHECK_FALSE(sender.must_close());
    server.accept();
    CHECK(server.recv() == 0);

    questdb::ingress::line_sender_buffer buffer = sender.new_buffer();
    buffer.table("test")
        .symbol("t1", "v1")
        .symbol("t2", "")
        .column("f1", 0.5)
        .at(questdb::ingress::timestamp_nanos{10000000});

    CHECK(sender.protocol_version() == questdb::ingress::protocol_version::v1);
    CHECK(server.recv() == 0);
    CHECK(buffer.size() == 31);
    sender.flush(buffer);
    CHECK(server.recv() == 1);
    std::string expect{"test,t1=v1,t2= f1=0.5 10000000\n"};
    CHECK(server.msgs(0) == expect);
}

TEST_CASE("line sender protocol version v2")
{
    questdb::ingress::test::mock_server server;
    questdb::ingress::opts opts{
        questdb::ingress::protocol::tcp,
        std::string("127.0.0.1"),
        std::to_string(server.port())};
    opts.protocol_version(questdb::ingress::protocol_version::v2);
    questdb::ingress::line_sender sender{opts};
    CHECK_FALSE(sender.must_close());
    server.accept();
    CHECK(server.recv() == 0);

    questdb::ingress::line_sender_buffer buffer = sender.new_buffer();
    buffer.table("test")
        .symbol("t1", "v1")
        .symbol("t2", "")
        .column("f1", 0.5)
        .at(questdb::ingress::timestamp_nanos{10000000});

    CHECK(server.recv() == 0);
    CHECK(buffer.size() == 38);
    sender.flush(buffer);
    CHECK(server.recv() == 1);
    std::string expect{"test,t1=v1,t2= f1=="};
    push_double_to_buffer(expect, 0.5).append(" 10000000\n");
    CHECK(server.msgs(0) == expect);
}

TEST_CASE("Http auto detect line protocol version failed")
{
    try
    {
        questdb::ingress::opts opts{
            questdb::ingress::protocol::http, "127.0.0.1", 1};
        questdb::ingress::line_sender sender1{opts};
        CHECK_MESSAGE(false, "Expected exception");
    }
    catch (const questdb::ingress::line_sender_error& se)
    {
        std::string msg{se.what()};
        CHECK_MESSAGE(
            msg.rfind("Could not detect server's line protocol version", 0) ==
                0,
            msg);
    }
    catch (...)
    {
        CHECK_MESSAGE(false, "Other exception raised.");
    }
}
