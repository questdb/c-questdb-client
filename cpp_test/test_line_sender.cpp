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

#include <array>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <sstream>
#include <thread>
#include <vector>

#if defined(PLATFORM_UNIX)
#    include <arpa/inet.h>
#    include <sys/socket.h>
#    include <unistd.h>
#elif defined(PLATFORM_WINDOWS)
#    include <winsock2.h>
#    include <ws2tcpip.h>
#endif

using namespace std::string_literals;
using namespace questdb::ingress::literals;

constexpr auto qwp_decimal256_max_positive =
    "57896044618658097711785492504343953926634992332820282019728792003956564819967";
constexpr auto qwp_decimal256_min_negative =
    "-57896044618658097711785492504343953926634992332820282019728792003956564819968";
constexpr auto qwp_decimal256_positive_overflow =
    "57896044618658097711785492504343953926634992332820282019728792003956564819968";

#if defined(PLATFORM_UNIX)
#    define QDB_TEST_CLOSESOCKET ::close
typedef const void* qdb_test_setsockopt_arg_t;
typedef size_t qdb_test_sock_len_t;
typedef ssize_t qdb_test_sock_ssize_t;
typedef socklen_t qdb_test_addr_len_t;
#    ifndef INVALID_SOCKET
#        define INVALID_SOCKET -1
#    endif
#elif defined(PLATFORM_WINDOWS)
#    define QDB_TEST_CLOSESOCKET ::closesocket
typedef const char* qdb_test_setsockopt_arg_t;
typedef int qdb_test_sock_len_t;
typedef int qdb_test_sock_ssize_t;
typedef int qdb_test_addr_len_t;

static void qdb_test_init_winsock()
{
    WORD vers_req = MAKEWORD(2, 2);
    WSADATA wsa_data;
    REQUIRE(WSAStartup(vers_req, &wsa_data) == 0);
}

static void qdb_test_release_winsock()
{
    (void)::WSACleanup();
}
#endif

class udp_capture
{
public:
    udp_capture()
        : _socket{INVALID_SOCKET}
        , _port{0}
    {
#if defined(PLATFORM_WINDOWS)
        qdb_test_init_winsock();
#endif
        _socket = ::socket(AF_INET, SOCK_DGRAM, 0);
        REQUIRE(_socket != INVALID_SOCKET);

        const int reuse_addr = 1;
        REQUIRE(
            ::setsockopt(
                _socket,
                SOL_SOCKET,
                SO_REUSEADDR,
                static_cast<qdb_test_setsockopt_arg_t>(
                    static_cast<const void*>(&reuse_addr)),
                sizeof(reuse_addr)) == 0);

        sockaddr_in listen_addr{};
        listen_addr.sin_family = AF_INET;
        listen_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        listen_addr.sin_port = htons(0);
        REQUIRE(
            ::bind(
                _socket,
                reinterpret_cast<const sockaddr*>(&listen_addr),
                sizeof(listen_addr)) == 0);

        sockaddr_in resolved_addr{};
        qdb_test_addr_len_t resolved_addr_len = sizeof(resolved_addr);
        REQUIRE(
            ::getsockname(
                _socket,
                reinterpret_cast<sockaddr*>(&resolved_addr),
                &resolved_addr_len) == 0);
        _port = ntohs(resolved_addr.sin_port);
    }

    udp_capture(const udp_capture&) = delete;
    udp_capture& operator=(const udp_capture&) = delete;

    ~udp_capture()
    {
        if (_socket != INVALID_SOCKET)
            QDB_TEST_CLOSESOCKET(_socket);
#if defined(PLATFORM_WINDOWS)
        qdb_test_release_winsock();
#endif
    }

    uint16_t port() const
    {
        return _port;
    }

    std::vector<std::byte> recv_datagram(double wait_timeout_sec = 0.5) const
    {
        fd_set read_set;
        FD_ZERO(&read_set);
        FD_SET(_socket, &read_set);

        timeval timeout{};
        timeout.tv_sec = static_cast<decltype(timeout.tv_sec)>(wait_timeout_sec);
        timeout.tv_usec = static_cast<decltype(timeout.tv_usec)>(
            1000000.0 * (wait_timeout_sec - static_cast<double>(timeout.tv_sec)));
        const int nfds = static_cast<int>(_socket) + 1;
        const int ready =
            ::select(nfds, &read_set, nullptr, nullptr, &timeout);
        REQUIRE(ready >= 0);
        REQUIRE(ready == 1);

        std::vector<std::byte> buffer(65536);
        sockaddr_in remote_addr{};
        qdb_test_addr_len_t remote_addr_len = sizeof(remote_addr);
        const auto count = ::recvfrom(
            _socket,
            reinterpret_cast<char*>(buffer.data()),
            static_cast<qdb_test_sock_len_t>(buffer.size()),
            0,
            reinterpret_cast<sockaddr*>(&remote_addr),
            &remote_addr_len);
        REQUIRE(count >= 0);
        buffer.resize(static_cast<size_t>(count));
        return buffer;
    }

    bool has_datagram(double wait_timeout_sec = 0.05) const
    {
        fd_set read_set;
        FD_ZERO(&read_set);
        FD_SET(_socket, &read_set);

        timeval timeout{};
        timeout.tv_sec = static_cast<decltype(timeout.tv_sec)>(wait_timeout_sec);
        timeout.tv_usec = static_cast<decltype(timeout.tv_usec)>(
            1000000.0 * (wait_timeout_sec - static_cast<double>(timeout.tv_sec)));
        const int nfds = static_cast<int>(_socket) + 1;
        const int ready =
            ::select(nfds, &read_set, nullptr, nullptr, &timeout);
        REQUIRE(ready >= 0);
        return ready == 1;
    }

private:
    socketfd_t _socket;
    uint16_t _port;
};

bool datagram_starts_with_qwp1(const std::vector<std::byte>& datagram)
{
    return datagram.size() >= 4 &&
        std::memcmp(datagram.data(), "QWP1", 4) == 0;
}

struct qwp_test_decoded_column
{
    std::string name;
    uint8_t type_code;
};

struct qwp_test_decoded_array_datagram
{
    std::string table_name;
    uint64_t row_count;
    qwp_test_decoded_column column;
    std::vector<uint32_t> shape;
    std::vector<double> values;
};

struct qwp_test_decoded_decimal_datagram
{
    std::string table_name;
    uint64_t row_count;
    qwp_test_decoded_column column;
    bool nullable;
    uint8_t scale;
    std::vector<std::optional<std::vector<uint8_t>>> values;
};

class qwp_test_decoder
{
public:
    explicit qwp_test_decoder(const std::vector<std::byte>& bytes)
        : _bytes{bytes}
        , _pos{0}
    {
    }

    uint8_t read_u8()
    {
        require_available(1);
        return std::to_integer<uint8_t>(_bytes[_pos++]);
    }

    std::vector<std::byte> read_exact(size_t len)
    {
        require_available(len);
        const size_t start = _pos;
        _pos += len;
        return {
            _bytes.begin() + static_cast<std::ptrdiff_t>(start),
            _bytes.begin() + static_cast<std::ptrdiff_t>(_pos)};
    }

    uint32_t read_u32()
    {
        const auto bytes = read_exact(4);
        std::array<uint8_t, 4> raw{};
        for (size_t i = 0; i < raw.size(); ++i)
            raw[i] = std::to_integer<uint8_t>(bytes[i]);
        return
            static_cast<uint32_t>(raw[0]) |
            (static_cast<uint32_t>(raw[1]) << 8) |
            (static_cast<uint32_t>(raw[2]) << 16) |
            (static_cast<uint32_t>(raw[3]) << 24);
    }

    uint64_t read_varint()
    {
        uint32_t shift = 0;
        uint64_t value = 0;
        for (;;)
        {
            const uint8_t byte = read_u8();
            value |= static_cast<uint64_t>(byte & 0x7f) << shift;
            if ((byte & 0x80) == 0)
                return value;
            shift += 7;
            REQUIRE(shift < 64);
        }
    }

    std::string read_string()
    {
        const auto len = static_cast<size_t>(read_varint());
        const auto bytes = read_exact(len);
        return {
            reinterpret_cast<const char*>(bytes.data()),
            bytes.size()};
    }

    double read_f64()
    {
        const auto bytes = read_exact(8);
        std::array<uint8_t, 8> raw{};
        for (size_t i = 0; i < raw.size(); ++i)
            raw[i] = std::to_integer<uint8_t>(bytes[i]);
        double value = 0.0;
        std::memcpy(&value, raw.data(), sizeof(value));
        return value;
    }

    size_t remaining() const
    {
        return _bytes.size() - _pos;
    }

private:
    void require_available(size_t len) const
    {
        REQUIRE(_pos + len <= _bytes.size());
    }

    const std::vector<std::byte>& _bytes;
    size_t _pos;
};

qwp_test_decoded_array_datagram decode_single_array_qwp_datagram(
    const std::vector<std::byte>& datagram)
{
    constexpr uint8_t qwp_type_double_array = 0x11;
    REQUIRE(datagram.size() >= 12);
    REQUIRE(datagram_starts_with_qwp1(datagram));
    CHECK(std::to_integer<uint8_t>(datagram[4]) == 1);
    CHECK(std::to_integer<uint8_t>(datagram[6]) == 1);
    CHECK(std::to_integer<uint8_t>(datagram[7]) == 0);
    const uint32_t payload_len =
        static_cast<uint32_t>(std::to_integer<uint8_t>(datagram[8])) |
        (static_cast<uint32_t>(std::to_integer<uint8_t>(datagram[9])) << 8) |
        (static_cast<uint32_t>(std::to_integer<uint8_t>(datagram[10])) << 16) |
        (static_cast<uint32_t>(std::to_integer<uint8_t>(datagram[11])) << 24);
    REQUIRE(datagram.size() == 12u + payload_len);

    std::vector<std::byte> payload{
        datagram.begin() + 12,
        datagram.end()};
    qwp_test_decoder decoder{payload};
    qwp_test_decoded_array_datagram decoded{};
    decoded.table_name = decoder.read_string();
    decoded.row_count = decoder.read_varint();
    REQUIRE(decoded.row_count == 1);
    REQUIRE(decoder.read_varint() == 1);
    REQUIRE(decoder.read_u8() == 0);
    (void)decoder.read_varint(); // schema id

    decoded.column.name = decoder.read_string();
    decoded.column.type_code = decoder.read_u8();
    REQUIRE(decoded.column.type_code == qwp_type_double_array);

    const bool has_null_bitmap = decoder.read_u8() != 0;
    if (has_null_bitmap)
    {
        const auto bitmap = decoder.read_exact(1);
        REQUIRE(std::to_integer<uint8_t>(bitmap[0]) == 0);
    }

    const uint8_t rank = decoder.read_u8();
    decoded.shape.reserve(rank);
    size_t value_count = 1;
    for (size_t i = 0; i < rank; ++i)
    {
        const uint32_t dim = decoder.read_u32();
        decoded.shape.push_back(dim);
        value_count *= dim;
    }

    decoded.values.reserve(value_count);
    for (size_t i = 0; i < value_count; ++i)
        decoded.values.push_back(decoder.read_f64());

    REQUIRE(decoder.remaining() == 0);
    return decoded;
}

std::vector<uint8_t> trim_signed_be_bytes(const std::vector<uint8_t>& bytes)
{
    REQUIRE(!bytes.empty());
    const bool negative = (bytes[0] & 0x80u) != 0;
    size_t keep_from = 0;
    while (keep_from + 1 < bytes.size())
    {
        const uint8_t current = bytes[keep_from];
        const uint8_t next = bytes[keep_from + 1];
        const bool should_trim = negative ?
            (current == 0xffu && (next & 0x80u) != 0) :
            (current == 0x00u && (next & 0x80u) == 0);
        if (!should_trim)
            break;
        ++keep_from;
    }
    return {
        bytes.begin() + static_cast<std::ptrdiff_t>(keep_from),
        bytes.end()};
}

std::vector<uint8_t> trimmed_signed_i64_be(int64_t value)
{
    std::array<uint8_t, 8> raw{};
    auto bits = static_cast<uint64_t>(value);
    for (size_t i = 0; i < raw.size(); ++i)
    {
        raw[raw.size() - 1 - i] = static_cast<uint8_t>(bits & 0xffu);
        bits >>= 8;
    }
    return trim_signed_be_bytes({raw.begin(), raw.end()});
}

std::vector<uint8_t> qwp_decimal256_max_positive_bytes()
{
    std::vector<uint8_t> out(32, 0xffu);
    out[0] = 0x7fu;
    return out;
}

std::vector<uint8_t> qwp_decimal256_min_negative_bytes()
{
    std::vector<uint8_t> out(32, 0x00u);
    out[0] = 0x80u;
    return out;
}

qwp_test_decoded_decimal_datagram decode_single_decimal_qwp_datagram(
    const std::vector<std::byte>& datagram)
{
    constexpr uint8_t qwp_type_decimal64 = 0x13;
    constexpr uint8_t qwp_type_decimal128 = 0x14;
    constexpr uint8_t qwp_type_decimal256 = 0x15;
    REQUIRE(datagram.size() >= 12);
    REQUIRE(datagram_starts_with_qwp1(datagram));
    CHECK(std::to_integer<uint8_t>(datagram[4]) == 1);
    CHECK(std::to_integer<uint8_t>(datagram[6]) == 1);
    CHECK(std::to_integer<uint8_t>(datagram[7]) == 0);
    const uint32_t payload_len =
        static_cast<uint32_t>(std::to_integer<uint8_t>(datagram[8])) |
        (static_cast<uint32_t>(std::to_integer<uint8_t>(datagram[9])) << 8) |
        (static_cast<uint32_t>(std::to_integer<uint8_t>(datagram[10])) << 16) |
        (static_cast<uint32_t>(std::to_integer<uint8_t>(datagram[11])) << 24);
    REQUIRE(datagram.size() == 12u + payload_len);

    std::vector<std::byte> payload{
        datagram.begin() + 12,
        datagram.end()};
    qwp_test_decoder decoder{payload};
    qwp_test_decoded_decimal_datagram decoded{};
    decoded.table_name = decoder.read_string();
    decoded.row_count = decoder.read_varint();
    REQUIRE(decoder.read_varint() == 1);
    REQUIRE(decoder.read_u8() == 0);
    (void)decoder.read_varint(); // schema id

    decoded.column.name = decoder.read_string();
    decoded.column.type_code = decoder.read_u8();
    const bool decimal_type_ok =
        decoded.column.type_code == qwp_type_decimal64 ||
        decoded.column.type_code == qwp_type_decimal128 ||
        decoded.column.type_code == qwp_type_decimal256;
    REQUIRE(decimal_type_ok);

    decoded.nullable = decoder.read_u8() != 0;
    std::vector<bool> has_value(
        static_cast<size_t>(decoded.row_count),
        true);
    if (decoded.nullable)
    {
        const size_t bitmap_len = (has_value.size() + 7) / 8;
        const auto bitmap = decoder.read_exact(bitmap_len);
        for (size_t row = 0; row < has_value.size(); ++row)
        {
            const uint8_t packed = std::to_integer<uint8_t>(bitmap[row / 8]);
            if ((packed & (1u << (row % 8))) != 0)
                has_value[row] = false;
        }
    }

    decoded.scale = decoder.read_u8();
    const size_t width = decoded.column.type_code == qwp_type_decimal64 ? 8 :
        (decoded.column.type_code == qwp_type_decimal128 ? 16 : 32);

    decoded.values.reserve(has_value.size());
    for (bool present : has_value)
    {
        if (!present)
        {
            decoded.values.push_back(std::nullopt);
            continue;
        }

        auto le = decoder.read_exact(width);
        std::vector<uint8_t> be;
        be.reserve(le.size());
        for (auto it = le.rbegin(); it != le.rend(); ++it)
            be.push_back(std::to_integer<uint8_t>(*it));
        decoded.values.push_back(trim_signed_be_bytes(be));
    }

    REQUIRE(decoder.remaining() == 0);
    return decoded;
}

std::string line_sender_error_message(const ::line_sender_error* err)
{
    size_t len = 0;
    const char* msg = ::line_sender_error_msg(err, &len);
    return {msg, len};
}

static bool qdb_test_set_env_var(const char* name, const char* value)
{
#if defined(PLATFORM_WINDOWS)
    return ::_putenv_s(name, value) == 0;
#else
    return ::setenv(name, value, 1) == 0;
#endif
}

static void qdb_test_unset_env_var(const char* name)
{
#if defined(PLATFORM_WINDOWS)
    (void)::_putenv_s(name, "");
#else
    (void)::unsetenv(name);
#endif
}

class scoped_env_var
{
public:
    scoped_env_var(const char* name, std::string value)
        : _name{name}
    {
        // MSVC C4996: getenv is not thread-safe, but this is
        // single-threaded test code and the value is immediately
        // copied into a std::string, so it's safe here.
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4996)
#endif
        if (const char* old_value = std::getenv(name))
#ifdef _MSC_VER
#pragma warning(pop)
#endif
            _old_value = old_value;
        REQUIRE(qdb_test_set_env_var(name, value.c_str()));
    }

    scoped_env_var(const scoped_env_var&) = delete;
    scoped_env_var& operator=(const scoped_env_var&) = delete;

    ~scoped_env_var()
    {
        if (_old_value)
            (void)qdb_test_set_env_var(_name.c_str(), _old_value->c_str());
        else
            qdb_test_unset_env_var(_name.c_str());
    }

private:
    std::string _name;
    std::optional<std::string> _old_value;
};

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
    CHECK(::line_sender_buffer_size(buffer) == 383);
    CHECK(::line_sender_flush(sender, buffer, &err));
    ::line_sender_buffer_free(buffer);
    CHECK(server.recv() == 1);
    std::string expect{"test,t1=v1 f1=="};
    push_double_to_buffer(expect, 0.5).append(",a1==");
    push_double_arr_to_buffer(expect, arr_data, 3, shape).append(",a2==");
    push_double_arr_to_buffer(expect, arr_data, 3, shape).append(",a3==");
    push_double_arr_to_buffer(expect, arr_data, 3, shape)
        .append(" 10000000n\n");
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
    opts.protocol_version(questdb::ingress::protocol_version::v3);
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
    CHECK(buffer.size() == 611);
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
        .append(" 10000000n\n");
    CHECK(server.msgs(0) == expect);
}

TEST_CASE("line_sender array vector API")
{
    questdb::ingress::test::mock_server server;
    questdb::ingress::opts opts{
        questdb::ingress::protocol::tcp,
        std::string("127.0.0.1"),
        std::to_string(server.port())};
    opts.protocol_version(questdb::ingress::protocol_version::v3);
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
    CHECK(buffer.size() == 133);
    sender.flush(buffer);
    CHECK(server.recv() == 1);
    std::string expect{"test,t1=v1,t2= a1=="};
    push_double_arr_to_buffer(expect, arr_data, 1, test_shape)
        .append(" 10000000n\n");
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
    opts.protocol_version(questdb::ingress::protocol_version::v3);
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
    CHECK(buffer.size() == 101);
    sender.flush(buffer);
    CHECK(server.recv() == 1);
    std::string expect{"test,t1=v1,t2= a1=="};
    push_double_arr_to_buffer(expect, expect_arr_data, 1, test_shape)
        .append(" 10000000n\n");
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
    CHECK(buffer.size() == 143);
    sender.flush(buffer);
    CHECK(server.recv() == 2);
    std::string expect{"metric1,t1=val1,t2=val2 f1=t,f2=12345i,f3=="};
    push_double_to_buffer(expect, 10.75)
        .append(",f4=\"val3\",f5=\"val4\",f6=\"val5\" 111222233333n\n");
    CHECK(server.msgs(0) == expect);
    CHECK(
        server.msgs(1) == "metric1,tag3=value\\ 3,tag\\ 4=value:4 field5=f\n");
}

TEST_CASE("State machine testing -- flush without data is no-op.")
{
    questdb::ingress::test::mock_server server;
    questdb::ingress::line_sender sender{questdb::ingress::opts{
        questdb::ingress::protocol::tcp,
        std::string_view{"127.0.0.1"},
        std::to_string(server.port())}};

    questdb::ingress::line_sender_buffer buffer = sender.new_buffer();
    CHECK(buffer.size() == 0);
    sender.flush(buffer);
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
    CHECK(::line_sender_opts_clone(nullptr) == nullptr);

    {
        questdb::ingress::opts opts1{
            questdb::ingress::protocol::tcp, "127.0.0.1", "9009"};
        questdb::ingress::opts opts2{std::move(opts1)};
        // opts1 is moved-from (internal _impl is null); copying and assigning
        // from it must not crash.
        questdb::ingress::opts opts3{opts1};
        questdb::ingress::opts opts4{
            questdb::ingress::protocol::tcp, "127.0.0.1", "9009"};
        opts4 = opts1;
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

TEST_CASE("Test timestamp column V1.")
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
    ss << "test ts1=12345t,ts2=" << now_micros << "t,ts3=" << (now_nanos / 1000)
       << "t " << now_nanos << "\n";
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

TEST_CASE("line_sender c++ buffer copies default-constructed buffer")
{
    questdb::ingress::line_sender_buffer source{
        questdb::ingress::protocol_version::v1};

    questdb::ingress::line_sender_buffer copied{source};
    CHECK(copied.peek() == "");

    questdb::ingress::line_sender_buffer assigned{
        questdb::ingress::protocol_version::v2};
    assigned = source;
    CHECK(assigned.peek() == "");
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

TEST_CASE("Test Bookmark")
{
    questdb::ingress::line_sender_buffer buffer{
        questdb::ingress::protocol_version::v1};

    auto empty = buffer.bookmark();
    buffer.table("test").symbol("a", "b").at_now();
    CHECK(buffer.peek() == "test,a=b\n");

    buffer.rewind_to_bookmark(empty);
    CHECK(buffer.peek() == "");

    auto stale = buffer.bookmark();
    buffer.table("test").symbol("a", "b").at_now();
    auto current = buffer.bookmark();
    buffer.table("test").symbol("a", "c").at_now();

    CHECK_THROWS_AS(
        buffer.rewind_to_bookmark(stale),
        questdb::ingress::line_sender_error);

    buffer.rewind_to_bookmark(current);
    CHECK(buffer.peek() == "test,a=b\n");

    auto old_bookmark = buffer.bookmark();
    buffer.table("test").symbol("a", "d").at_now();
    buffer.set_marker();
    CHECK_THROWS_AS(
        buffer.rewind_to_bookmark(old_bookmark),
        questdb::ingress::line_sender_error);

    buffer.table("test").symbol("a", "e").at_now();
    buffer.rewind_to_marker();
    CHECK(buffer.peek() == "test,a=b\ntest,a=d\n");

    auto cleared = buffer.bookmark();
    buffer.table("test").symbol("a", "f").at_now();
    buffer.clear_bookmark(cleared);
    CHECK_THROWS_AS(
        buffer.rewind_to_bookmark(cleared),
        questdb::ingress::line_sender_error);
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
        questdb::ingress::protocol_version::v3};
    CHECK(b1.size() == 0);
    questdb::ingress::line_sender_buffer b2{std::move(b1)};
    CHECK(b1.size() == 0);
    CHECK(b2.size() == 0);
    questdb::ingress::line_sender_buffer b3{
        questdb::ingress::protocol_version::v3};
    b3 = std::move(b2);
    CHECK(b2.size() == 0);
    CHECK(b3.size() == 0);
    questdb::ingress::line_sender_buffer b4{
        questdb::ingress::protocol_version::v3};
    b4.table("test").symbol("a", "b").at_now();
    questdb::ingress::line_sender_buffer b5{
        questdb::ingress::protocol_version::v3};
    b5 = std::move(b4);
    CHECK(b4.size() == 0);
    CHECK(b5.size() == 9);

    questdb::ingress::test::mock_server server;
    questdb::ingress::line_sender sender{questdb::ingress::opts{
        questdb::ingress::protocol::tcp, "127.0.0.1", server.port()}};
    // Flushing an empty buffer is a no-op.
    sender.flush(b1);
    sender.flush_and_keep(b1);
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
    opts1.protocol_version(questdb::ingress::protocol_version::v3)
        .username("user")
        .password("pass")
        .max_buf_size(1000000)
        .request_timeout(5000)
        .retry_timeout(5);
    opts2.protocol_version(questdb::ingress::protocol_version::v3)
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

TEST_CASE("line sender protocol throws after close")
{
    questdb::ingress::test::mock_server server;
    questdb::ingress::line_sender sender{questdb::ingress::opts{
        questdb::ingress::protocol::tcp,
        std::string("127.0.0.1"),
        std::to_string(server.port())}};
    CHECK(sender.protocol() == questdb::ingress::protocol::tcp);

    sender.close();

    CHECK_THROWS_WITH_AS(
        sender.protocol(), "Sender closed.", questdb::ingress::line_sender_error);
}

TEST_CASE("line sender protocol version v2")
{
    questdb::ingress::test::mock_server server;
    questdb::ingress::opts opts{
        questdb::ingress::protocol::tcp,
        std::string("127.0.0.1"),
        std::to_string(server.port())};
    opts.protocol_version(questdb::ingress::protocol_version::v3);
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
    CHECK(buffer.size() == 39);
    sender.flush(buffer);
    CHECK(server.recv() == 1);
    std::string expect{"test,t1=v1,t2= f1=="};
    push_double_to_buffer(expect, 0.5).append(" 10000000n\n");
    CHECK(server.msgs(0) == expect);
}

TEST_CASE("line_sender c api qwpudp basics")
{
    udp_capture receiver;
    ::line_sender_error* err = nullptr;
    on_scope_exit error_free_guard{[&] {
        if (err)
            ::line_sender_error_free(err);
    }};

    const auto host = QDB_UTF8_LITERAL("127.0.0.1");
    ::line_sender_opts* opts =
        ::line_sender_opts_new(::line_sender_protocol_qwpudp, host, receiver.port());
    REQUIRE(opts != nullptr);
    on_scope_exit opts_free_guard{[&] { ::line_sender_opts_free(opts); }};

    CHECK(::line_sender_opts_max_datagram_size(opts, 256, &err));
    CHECK(::line_sender_opts_multicast_ttl(opts, 7, &err));

    ::line_sender* sender = ::line_sender_build(opts, &err);
    REQUIRE(sender != nullptr);
    on_scope_exit sender_close_guard{[&] { ::line_sender_close(sender); }};
    CHECK(::line_sender_get_protocol(sender) == ::line_sender_protocol_qwpudp);

    ::line_sender_buffer* buffer = ::line_sender_buffer_new_for_sender(sender);
    REQUIRE(buffer != nullptr);
    on_scope_exit buffer_free_guard{[&] { ::line_sender_buffer_free(buffer); }};

    const auto table = QDB_TABLE_NAME_LITERAL("trades");
    const auto sym = QDB_COLUMN_NAME_LITERAL("sym");
    const auto qty = QDB_COLUMN_NAME_LITERAL("qty");
    const auto active = QDB_COLUMN_NAME_LITERAL("active");
    const auto venue = QDB_COLUMN_NAME_LITERAL("venue");
    const auto sym_value = QDB_UTF8_LITERAL("ETH-USD");
    const auto venue_value = QDB_UTF8_LITERAL("binance");

    CHECK(::line_sender_buffer_table(buffer, table, &err));
    CHECK(::line_sender_buffer_symbol(buffer, sym, sym_value, &err));
    CHECK(::line_sender_buffer_column_i64(buffer, qty, 4, &err));
    CHECK(::line_sender_buffer_column_bool(buffer, active, true, &err));
    CHECK(::line_sender_buffer_column_str(buffer, venue, venue_value, &err));
    CHECK(::line_sender_buffer_at_now(buffer, &err));
    CHECK(::line_sender_flush(sender, buffer, &err));
    CHECK(::line_sender_buffer_row_count(buffer) == 0);

    const auto datagram = receiver.recv_datagram();
    CHECK(datagram.size() >= 12);
    CHECK(datagram_starts_with_qwp1(datagram));
    CHECK(std::to_integer<uint8_t>(datagram[4]) == 1);
    CHECK(std::to_integer<uint8_t>(datagram[6]) == 1);
    CHECK(std::to_integer<uint8_t>(datagram[7]) == 0);
}

TEST_CASE("line_sender c api standalone qwpudp buffer")
{
    udp_capture receiver;
    ::line_sender_error* err = nullptr;
    on_scope_exit error_free_guard{[&] {
        if (err)
            ::line_sender_error_free(err);
    }};

    const auto host = QDB_UTF8_LITERAL("127.0.0.1");
    ::line_sender_opts* opts =
        ::line_sender_opts_new(::line_sender_protocol_qwpudp, host, receiver.port());
    REQUIRE(opts != nullptr);
    on_scope_exit opts_free_guard{[&] { ::line_sender_opts_free(opts); }};

    ::line_sender* sender = ::line_sender_build(opts, &err);
    REQUIRE(sender != nullptr);
    on_scope_exit sender_close_guard{[&] { ::line_sender_close(sender); }};

    ::line_sender_buffer* buffer = ::line_sender_buffer_new_qwp();
    REQUIRE(buffer != nullptr);
    on_scope_exit buffer_free_guard{[&] { ::line_sender_buffer_free(buffer); }};

    const auto table = QDB_TABLE_NAME_LITERAL("quotes");
    const auto sym = QDB_COLUMN_NAME_LITERAL("sym");
    const auto qty = QDB_COLUMN_NAME_LITERAL("qty");
    const auto sym_value = QDB_UTF8_LITERAL("BTC-USD");

    CHECK(::line_sender_buffer_table(buffer, table, &err));
    CHECK(::line_sender_buffer_symbol(buffer, sym, sym_value, &err));
    CHECK(::line_sender_buffer_column_i64(buffer, qty, 7, &err));
    CHECK(::line_sender_buffer_at_now(buffer, &err));
    CHECK(::line_sender_flush(sender, buffer, &err));

    const auto datagram = receiver.recv_datagram();
    CHECK(datagram.size() >= 12);
    CHECK(datagram_starts_with_qwp1(datagram));
}

TEST_CASE("line_sender c api qwpudp f64 array column")
{
    udp_capture receiver;
    ::line_sender_error* err = nullptr;
    on_scope_exit error_free_guard{[&] {
        if (err)
            ::line_sender_error_free(err);
    }};

    const auto host = QDB_UTF8_LITERAL("127.0.0.1");
    ::line_sender_opts* opts =
        ::line_sender_opts_new(::line_sender_protocol_qwpudp, host, receiver.port());
    REQUIRE(opts != nullptr);
    on_scope_exit opts_free_guard{[&] { ::line_sender_opts_free(opts); }};

    ::line_sender* sender = ::line_sender_build(opts, &err);
    REQUIRE(sender != nullptr);
    on_scope_exit sender_close_guard{[&] { ::line_sender_close(sender); }};

    ::line_sender_buffer* buffer = ::line_sender_buffer_new_for_sender(sender);
    REQUIRE(buffer != nullptr);
    on_scope_exit buffer_free_guard{[&] { ::line_sender_buffer_free(buffer); }};

    const auto table = QDB_TABLE_NAME_LITERAL("arrays");
    const auto arr_col = QDB_COLUMN_NAME_LITERAL("arr");
    uintptr_t shape[] = {2, 2};
    std::array<double, 4> arr_data = {1.5, 2.0, -3.25, 4.75};

    CHECK(::line_sender_buffer_table(buffer, table, &err));
    CHECK(
        ::line_sender_buffer_column_f64_arr_c_major(
            buffer,
            arr_col,
            2,
            shape,
            arr_data.data(),
            arr_data.size(),
            &err));
    CHECK(::line_sender_buffer_at_now(buffer, &err));
    CHECK(::line_sender_flush(sender, buffer, &err));
    CHECK(::line_sender_buffer_row_count(buffer) == 0);

    const auto datagram = receiver.recv_datagram();
    const auto decoded = decode_single_array_qwp_datagram(datagram);
    CHECK(decoded.table_name == "arrays");
    CHECK(decoded.column.name == "arr");
    CHECK(decoded.shape == std::vector<uint32_t>{2, 2});
    REQUIRE(decoded.values.size() == arr_data.size());
    for (size_t i = 0; i < arr_data.size(); ++i)
        CHECK(decoded.values[i] == doctest::Approx(arr_data[i]));
}

TEST_CASE("line_sender c api qwpudp decimal column")
{
    udp_capture receiver;
    ::line_sender_error* err = nullptr;
    on_scope_exit error_free_guard{[&] {
        if (err)
            ::line_sender_error_free(err);
    }};

    const auto host = QDB_UTF8_LITERAL("127.0.0.1");
    ::line_sender_opts* opts =
        ::line_sender_opts_new(::line_sender_protocol_qwpudp, host, receiver.port());
    REQUIRE(opts != nullptr);
    on_scope_exit opts_free_guard{[&] { ::line_sender_opts_free(opts); }};

    ::line_sender* sender = ::line_sender_build(opts, &err);
    REQUIRE(sender != nullptr);
    on_scope_exit sender_close_guard{[&] { ::line_sender_close(sender); }};

    ::line_sender_buffer* buffer = ::line_sender_buffer_new_for_sender(sender);
    REQUIRE(buffer != nullptr);
    on_scope_exit buffer_free_guard{[&] { ::line_sender_buffer_free(buffer); }};

    const auto table = QDB_TABLE_NAME_LITERAL("decimals");
    const auto price = QDB_COLUMN_NAME_LITERAL("price");
    const uint8_t neg_345[] = {0xfe, 0xa7};

    CHECK(::line_sender_buffer_table(buffer, table, &err));
    CHECK(::line_sender_buffer_column_dec_str(buffer, price, "1.2", 3, &err));
    CHECK(::line_sender_buffer_at_now(buffer, &err));

    CHECK(::line_sender_buffer_table(buffer, table, &err));
    CHECK(::line_sender_buffer_column_dec_str(buffer, price, "NaN", 3, &err));
    CHECK(::line_sender_buffer_at_now(buffer, &err));

    CHECK(::line_sender_buffer_table(buffer, table, &err));
    CHECK(
        ::line_sender_buffer_column_dec(
            buffer,
            price,
            2,
            neg_345,
            sizeof(neg_345),
            &err));
    CHECK(::line_sender_buffer_at_now(buffer, &err));

    CHECK(::line_sender_buffer_table(buffer, table, &err));
    CHECK(::line_sender_buffer_column_dec_str(buffer, price, "1.5e-3", 6, &err));
    CHECK(::line_sender_buffer_at_now(buffer, &err));

    CHECK(::line_sender_flush(sender, buffer, &err));
    CHECK(::line_sender_buffer_row_count(buffer) == 0);

    const auto datagram = receiver.recv_datagram();
    const auto decoded = decode_single_decimal_qwp_datagram(datagram);
    CHECK(decoded.table_name == "decimals");
    CHECK(decoded.row_count == 4);
    CHECK(decoded.column.name == "price");
    CHECK(decoded.column.type_code == 0x15);
    CHECK(decoded.nullable);
    CHECK(decoded.scale == 4);
    REQUIRE(decoded.values.size() == 4);
    REQUIRE(decoded.values[0].has_value());
    CHECK(*decoded.values[0] == trimmed_signed_i64_be(12'000));
    CHECK(!decoded.values[1].has_value());
    REQUIRE(decoded.values[2].has_value());
    CHECK(*decoded.values[2] == trimmed_signed_i64_be(-34'500));
    REQUIRE(decoded.values[3].has_value());
    CHECK(*decoded.values[3] == trimmed_signed_i64_be(15));
}

TEST_CASE("line_sender c api qwpudp decimal signed boundaries")
{
    udp_capture receiver;
    ::line_sender_error* err = nullptr;
    on_scope_exit error_free_guard{[&] {
        if (err)
            ::line_sender_error_free(err);
    }};

    const auto host = QDB_UTF8_LITERAL("127.0.0.1");
    ::line_sender_opts* opts =
        ::line_sender_opts_new(::line_sender_protocol_qwpudp, host, receiver.port());
    REQUIRE(opts != nullptr);
    on_scope_exit opts_free_guard{[&] { ::line_sender_opts_free(opts); }};

    ::line_sender* sender = ::line_sender_build(opts, &err);
    REQUIRE(sender != nullptr);
    on_scope_exit sender_close_guard{[&] { ::line_sender_close(sender); }};

    ::line_sender_buffer* buffer = ::line_sender_buffer_new_for_sender(sender);
    REQUIRE(buffer != nullptr);
    on_scope_exit buffer_free_guard{[&] { ::line_sender_buffer_free(buffer); }};

    const auto table = QDB_TABLE_NAME_LITERAL("decimals");
    const auto price = QDB_COLUMN_NAME_LITERAL("price");

    CHECK(::line_sender_buffer_table(buffer, table, &err));
    CHECK(
        ::line_sender_buffer_column_dec_str(
            buffer,
            price,
            qwp_decimal256_max_positive,
            std::strlen(qwp_decimal256_max_positive),
            &err));
    CHECK(::line_sender_buffer_at_now(buffer, &err));

    CHECK(::line_sender_buffer_table(buffer, table, &err));
    CHECK(
        ::line_sender_buffer_column_dec_str(
            buffer,
            price,
            qwp_decimal256_min_negative,
            std::strlen(qwp_decimal256_min_negative),
            &err));
    CHECK(::line_sender_buffer_at_now(buffer, &err));

    CHECK(::line_sender_flush(sender, buffer, &err));
    CHECK(::line_sender_buffer_row_count(buffer) == 0);

    const auto datagram = receiver.recv_datagram();
    const auto decoded = decode_single_decimal_qwp_datagram(datagram);
    CHECK(decoded.table_name == "decimals");
    CHECK(decoded.row_count == 2);
    CHECK(decoded.column.name == "price");
    CHECK(decoded.column.type_code == 0x15);
    CHECK(decoded.nullable);
    CHECK(decoded.scale == 0);
    REQUIRE(decoded.values.size() == 2);
    REQUIRE(decoded.values[0].has_value());
    CHECK(*decoded.values[0] == qwp_decimal256_max_positive_bytes());
    REQUIRE(decoded.values[1].has_value());
    CHECK(*decoded.values[1] == qwp_decimal256_min_negative_bytes());
}

TEST_CASE("line_sender c api qwpudp decimal rejects signed overflow")
{
    udp_capture receiver;
    ::line_sender_error* err = nullptr;
    on_scope_exit error_free_guard{[&] {
        if (err)
            ::line_sender_error_free(err);
    }};

    const auto host = QDB_UTF8_LITERAL("127.0.0.1");
    ::line_sender_opts* opts =
        ::line_sender_opts_new(::line_sender_protocol_qwpudp, host, receiver.port());
    REQUIRE(opts != nullptr);
    on_scope_exit opts_free_guard{[&] { ::line_sender_opts_free(opts); }};

    ::line_sender* sender = ::line_sender_build(opts, &err);
    REQUIRE(sender != nullptr);
    on_scope_exit sender_close_guard{[&] { ::line_sender_close(sender); }};

    ::line_sender_buffer* buffer = ::line_sender_buffer_new_for_sender(sender);
    REQUIRE(buffer != nullptr);
    on_scope_exit buffer_free_guard{[&] { ::line_sender_buffer_free(buffer); }};

    const auto table = QDB_TABLE_NAME_LITERAL("decimals");
    const auto price = QDB_COLUMN_NAME_LITERAL("price");

    CHECK(::line_sender_buffer_table(buffer, table, &err));
    CHECK(
        ::line_sender_buffer_column_dec_str(
            buffer,
            price,
            qwp_decimal256_positive_overflow,
            std::strlen(qwp_decimal256_positive_overflow),
            &err));
    CHECK(::line_sender_buffer_at_now(buffer, &err));

    CHECK_FALSE(::line_sender_flush(sender, buffer, &err));
    REQUIRE(err != nullptr);
    CHECK(
        line_sender_error_message(err).find("signed DECIMAL256 range") !=
        std::string::npos);
    CHECK(::line_sender_buffer_row_count(buffer) == 1);
}

TEST_CASE("line_sender c api qwpudp max name len and peek")
{
    ::line_sender_error* err = nullptr;
    on_scope_exit error_free_guard{[&] {
        if (err)
            ::line_sender_error_free(err);
    }};

    ::line_sender_buffer* buffer = ::line_sender_buffer_new_qwp_with_max_name_len(4);
    REQUIRE(buffer != nullptr);
    on_scope_exit buffer_free_guard{[&] { ::line_sender_buffer_free(buffer); }};

    auto peek = ::line_sender_buffer_peek(buffer);
    CHECK(peek.len == 0);

    const auto long_table = QDB_TABLE_NAME_LITERAL("trades");
    CHECK_FALSE(::line_sender_buffer_table(buffer, long_table, &err));
    REQUIRE(err != nullptr);
    CHECK(
        line_sender_error_message(err) ==
        "Bad name: \"trades\": Too long (max 4 characters)");
    ::line_sender_error_free(err);
    err = nullptr;

    const auto table = QDB_TABLE_NAME_LITERAL("t");
    const auto sym = QDB_COLUMN_NAME_LITERAL("s");
    const auto qty = QDB_COLUMN_NAME_LITERAL("q");
    const auto sym_value = QDB_UTF8_LITERAL("ok");
    CHECK(::line_sender_buffer_table(buffer, table, &err));
    CHECK(::line_sender_buffer_symbol(buffer, sym, sym_value, &err));
    CHECK(::line_sender_buffer_column_i64(buffer, qty, 7, &err));
    CHECK(::line_sender_buffer_at_now(buffer, &err));

    peek = ::line_sender_buffer_peek(buffer);
    CHECK(peek.len == 0);
}

TEST_CASE("line_sender c api qwpudp from env")
{
    udp_capture receiver;
    const std::string conf = "qwpudp::addr=127.0.0.1:"s +
        std::to_string(receiver.port()) +
        ";max_datagram_size=256;multicast_ttl=1;";
    scoped_env_var env_var{"QDB_CLIENT_CONF", conf};

    ::line_sender_error* err = nullptr;
    on_scope_exit error_free_guard{[&] {
        if (err)
            ::line_sender_error_free(err);
    }};

    ::line_sender* sender = ::line_sender_from_env(&err);
    REQUIRE(sender != nullptr);
    on_scope_exit sender_close_guard{[&] { ::line_sender_close(sender); }};
    CHECK(::line_sender_get_protocol(sender) == ::line_sender_protocol_qwpudp);

    ::line_sender_buffer* buffer = ::line_sender_buffer_new_for_sender(sender);
    REQUIRE(buffer != nullptr);
    on_scope_exit buffer_free_guard{[&] { ::line_sender_buffer_free(buffer); }};

    const auto table = QDB_TABLE_NAME_LITERAL("env_rows");
    const auto sym = QDB_COLUMN_NAME_LITERAL("sym");
    const auto qty = QDB_COLUMN_NAME_LITERAL("qty");
    const auto sym_value = QDB_UTF8_LITERAL("from-env");
    CHECK(::line_sender_buffer_table(buffer, table, &err));
    CHECK(::line_sender_buffer_symbol(buffer, sym, sym_value, &err));
    CHECK(::line_sender_buffer_column_i64(buffer, qty, 3, &err));
    CHECK(::line_sender_buffer_at_now(buffer, &err));
    CHECK(::line_sender_flush(sender, buffer, &err));

    const auto datagram = receiver.recv_datagram();
    CHECK(datagram_starts_with_qwp1(datagram));
}

TEST_CASE("line_sender c++ qwpudp flush_and_keep resends datagram")
{
    udp_capture receiver;
    questdb::ingress::opts opts{
        questdb::ingress::protocol::qwpudp,
        std::string("127.0.0.1"),
        std::to_string(receiver.port())};
    opts.max_datagram_size(256);
    questdb::ingress::line_sender sender{opts};

    questdb::ingress::line_sender_buffer buffer = sender.new_buffer();
    buffer.table("trades")
        .symbol("sym", "ETH-USD")
        .column("qty", int64_t{4})
        .column("active", true)
        .at_now();

    CHECK(buffer.row_count() == 1);
    sender.flush_and_keep(buffer);
    CHECK(buffer.row_count() == 1);
    const auto first = receiver.recv_datagram();
    CHECK(datagram_starts_with_qwp1(first));

    sender.flush(buffer);
    CHECK(buffer.row_count() == 0);
    const auto second = receiver.recv_datagram();
    CHECK(second == first);
}

TEST_CASE("line_sender c++ standalone qwpudp buffer")
{
    udp_capture receiver;
    questdb::ingress::opts opts{
        questdb::ingress::protocol::qwpudp,
        std::string("127.0.0.1"),
        std::to_string(receiver.port())};
    questdb::ingress::line_sender sender{opts};

    questdb::ingress::line_sender_buffer buffer =
        questdb::ingress::line_sender_buffer::qwp_udp();
    buffer.table("quotes")
        .symbol("sym", "SOL-USD")
        .column("qty", int64_t{9})
        .at_now();

    sender.flush(buffer);
    CHECK(buffer.row_count() == 0);
    const auto datagram = receiver.recv_datagram();
    CHECK(datagram_starts_with_qwp1(datagram));
}

TEST_CASE("line_sender c++ qwpudp f64 array column")
{
    udp_capture receiver;
    questdb::ingress::opts opts{
        questdb::ingress::protocol::qwpudp,
        std::string("127.0.0.1"),
        std::to_string(receiver.port())};
    questdb::ingress::line_sender sender{opts};

    uintptr_t shape[] = {2, 3};
    std::array<double, 6> arr_data = {10.0, 11.5, 12.0, 13.25, 14.0, 15.75};
    questdb::ingress::array::row_major_view<double> arr{
        2, shape, arr_data.data(), arr_data.size()};

    questdb::ingress::line_sender_buffer buffer = sender.new_buffer();
    buffer.table("cpp_arrays").column("arr", arr).at_now();

    sender.flush(buffer);
    CHECK(buffer.row_count() == 0);

    const auto datagram = receiver.recv_datagram();
    const auto decoded = decode_single_array_qwp_datagram(datagram);
    CHECK(decoded.table_name == "cpp_arrays");
    CHECK(decoded.column.name == "arr");
    CHECK(decoded.shape == std::vector<uint32_t>{2, 3});
    REQUIRE(decoded.values.size() == arr_data.size());
    for (size_t i = 0; i < arr_data.size(); ++i)
        CHECK(decoded.values[i] == doctest::Approx(arr_data[i]));
}

TEST_CASE("line_sender c++ qwpudp decimal column")
{
    udp_capture receiver;
    questdb::ingress::opts opts{
        questdb::ingress::protocol::qwpudp,
        std::string("127.0.0.1"),
        std::to_string(receiver.port())};
    questdb::ingress::line_sender sender{opts};

    const std::array<uint8_t, 2> neg_345 = {0xfe, 0xa7};
    const auto neg_345_decimal =
        questdb::ingress::decimal::decimal_view{2, neg_345};

    questdb::ingress::line_sender_buffer buffer = sender.new_buffer();
    buffer.table("cpp_decimals")
        .column(
            "price",
            questdb::ingress::decimal::decimal_str_view{std::string_view{"1.2"}})
        .at_now();
    buffer.table("cpp_decimals")
        .column(
            "price",
            questdb::ingress::decimal::decimal_str_view{std::string_view{"NaN"}})
        .at_now();
    buffer.table("cpp_decimals").column("price", neg_345_decimal).at_now();
    buffer.table("cpp_decimals")
        .column(
            "price",
            questdb::ingress::decimal::decimal_str_view{std::string_view{"1.5e-3"}})
        .at_now();

    sender.flush(buffer);
    CHECK(buffer.row_count() == 0);

    const auto datagram = receiver.recv_datagram();
    const auto decoded = decode_single_decimal_qwp_datagram(datagram);
    CHECK(decoded.table_name == "cpp_decimals");
    CHECK(decoded.row_count == 4);
    CHECK(decoded.column.name == "price");
    CHECK(decoded.column.type_code == 0x15);
    CHECK(decoded.nullable);
    CHECK(decoded.scale == 4);
    REQUIRE(decoded.values.size() == 4);
    REQUIRE(decoded.values[0].has_value());
    CHECK(*decoded.values[0] == trimmed_signed_i64_be(12'000));
    CHECK(!decoded.values[1].has_value());
    REQUIRE(decoded.values[2].has_value());
    CHECK(*decoded.values[2] == trimmed_signed_i64_be(-34'500));
    REQUIRE(decoded.values[3].has_value());
    CHECK(*decoded.values[3] == trimmed_signed_i64_be(15));
}

TEST_CASE("line_sender c++ qwpudp decimal signed boundaries")
{
    udp_capture receiver;
    questdb::ingress::opts opts{
        questdb::ingress::protocol::qwpudp,
        std::string("127.0.0.1"),
        std::to_string(receiver.port())};
    questdb::ingress::line_sender sender{opts};

    questdb::ingress::line_sender_buffer buffer = sender.new_buffer();
    buffer.table("cpp_decimals")
        .column(
            "price",
            questdb::ingress::decimal::decimal_str_view{
                std::string_view{qwp_decimal256_max_positive}})
        .at_now();
    buffer.table("cpp_decimals")
        .column(
            "price",
            questdb::ingress::decimal::decimal_str_view{
                std::string_view{qwp_decimal256_min_negative}})
        .at_now();

    sender.flush(buffer);
    CHECK(buffer.row_count() == 0);

    const auto datagram = receiver.recv_datagram();
    const auto decoded = decode_single_decimal_qwp_datagram(datagram);
    CHECK(decoded.table_name == "cpp_decimals");
    CHECK(decoded.row_count == 2);
    CHECK(decoded.column.name == "price");
    CHECK(decoded.column.type_code == 0x15);
    CHECK(decoded.nullable);
    CHECK(decoded.scale == 0);
    REQUIRE(decoded.values.size() == 2);
    REQUIRE(decoded.values[0].has_value());
    CHECK(*decoded.values[0] == qwp_decimal256_max_positive_bytes());
    REQUIRE(decoded.values[1].has_value());
    CHECK(*decoded.values[1] == qwp_decimal256_min_negative_bytes());
}

TEST_CASE("line_sender c++ qwpudp decimal rejects signed overflow")
{
    udp_capture receiver;
    questdb::ingress::opts opts{
        questdb::ingress::protocol::qwpudp,
        std::string("127.0.0.1"),
        std::to_string(receiver.port())};
    questdb::ingress::line_sender sender{opts};

    questdb::ingress::line_sender_buffer buffer = sender.new_buffer();
    buffer.table("cpp_decimals")
        .column(
            "price",
            questdb::ingress::decimal::decimal_str_view{
                std::string_view{qwp_decimal256_positive_overflow}})
        .at_now();

    bool threw = false;
    try
    {
        sender.flush(buffer);
    }
    catch (const questdb::ingress::line_sender_error& ex)
    {
        threw = true;
        CHECK(std::string{ex.what()}.find("signed DECIMAL256 range") != std::string::npos);
    }
    CHECK(threw);
    CHECK(buffer.row_count() == 1);
}

TEST_CASE("line_sender c++ qwpudp rejects flush with incomplete row")
{
    udp_capture receiver;
    questdb::ingress::opts opts{
        questdb::ingress::protocol::qwpudp,
        std::string("127.0.0.1"),
        std::to_string(receiver.port())};
    questdb::ingress::line_sender sender{opts};

    questdb::ingress::line_sender_buffer buffer = sender.new_buffer();
    buffer.table("trades")
        .symbol("sym", "ETH-USD")
        .column("qty", int64_t{4});

    CHECK_THROWS_WITH_AS(
        sender.flush(buffer),
        "State error: Bad call to `flush`, should have called `column` or "
        "`at` instead.",
        questdb::ingress::line_sender_error);
}

TEST_CASE("line_sender c++ qwpudp rejects ilp buffer")
{
    udp_capture receiver;
    questdb::ingress::opts opts{
        questdb::ingress::protocol::qwpudp,
        std::string("127.0.0.1"),
        std::to_string(receiver.port())};
    questdb::ingress::line_sender sender{opts};

    questdb::ingress::line_sender_buffer buffer{
        questdb::ingress::protocol_version::v1};
    buffer.table("trades").column("qty", int64_t{4}).at_now();

    CHECK_THROWS_WITH_AS(
        sender.flush(buffer),
        "QWP/UDP sender requires a QWP buffer created by `Sender::new_buffer()`.",
        questdb::ingress::line_sender_error);
}

TEST_CASE("line_sender c++ qwpudp rejects rows exceeding max datagram size")
{
    udp_capture receiver;
    questdb::ingress::opts opts{
        questdb::ingress::protocol::qwpudp,
        std::string("127.0.0.1"),
        std::to_string(receiver.port())};
    opts.max_datagram_size(24);
    questdb::ingress::line_sender sender{opts};

    questdb::ingress::line_sender_buffer buffer = sender.new_buffer();
    buffer.table("trades")
        .symbol("sym", "ETH-USD")
        .column("qty", int64_t{4})
        .at_now();

    try
    {
        sender.flush(buffer);
        CHECK_MESSAGE(false, "Expected exception");
    }
    catch (const questdb::ingress::line_sender_error& se)
    {
        std::string msg{se.what()};
        CHECK_MESSAGE(
            msg.find("single row exceeds maximum datagram size") !=
                std::string::npos,
            msg);
    }
    catch (...)
    {
        CHECK_MESSAGE(false, "Other exception raised.");
    }
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

TEST_CASE("line_sender c api err_out may be null on failure")
{
    ::line_sender_utf8 utf8{0, nullptr};
    const char invalid_utf8[] = {static_cast<char>(0xff)};
    CHECK_FALSE(::line_sender_utf8_init(
        &utf8, sizeof(invalid_utf8), invalid_utf8, nullptr));

    const auto host = QDB_UTF8_LITERAL("127.0.0.1");
    ::line_sender_opts* opts =
        ::line_sender_opts_new(::line_sender_protocol_tcp, host, 9009);
    REQUIRE(opts != nullptr);
    on_scope_exit opts_free_guard{[&] { ::line_sender_opts_free(opts); }};

    CHECK_FALSE(::line_sender_opts_max_datagram_size(opts, 256, nullptr));
    CHECK_FALSE(::line_sender_opts_multicast_ttl(opts, 3, nullptr));

    ::line_sender_buffer* buffer = ::line_sender_buffer_new_qwp();
    REQUIRE(buffer != nullptr);
    on_scope_exit buffer_free_guard{[&] { ::line_sender_buffer_free(buffer); }};

    const auto col = QDB_COLUMN_NAME_LITERAL("x");
    CHECK_FALSE(::line_sender_buffer_column_dec_str(
        buffer, col, "not_decimal?", 12, nullptr));

    uintptr_t shape[] = {1};
    double data[] = {1.0};
    CHECK_FALSE(::line_sender_buffer_column_f64_arr_c_major(
        buffer, col, 0, shape, data, 1, nullptr));

    ::line_sender_bookmark bookmark{};
    CHECK(::line_sender_buffer_bookmark(buffer, &bookmark, nullptr));
    ::line_sender_buffer_clear_bookmark(buffer, bookmark);
    CHECK_FALSE(
        ::line_sender_buffer_rewind_to_bookmark(buffer, bookmark, nullptr));
}

TEST_CASE("line_sender c api bookmark out may be null")
{
    ::line_sender_error* err = nullptr;
    on_scope_exit error_free_guard{[&] {
        if (err)
            ::line_sender_error_free(err);
    }};

    ::line_sender_buffer* buffer = ::line_sender_buffer_new_qwp();
    REQUIRE(buffer != nullptr);
    on_scope_exit buffer_free_guard{[&] { ::line_sender_buffer_free(buffer); }};

    const auto table = QDB_TABLE_NAME_LITERAL("t");
    const auto col = QDB_COLUMN_NAME_LITERAL("x");

    CHECK(::line_sender_buffer_table(buffer, table, &err));
    CHECK(::line_sender_buffer_column_i64(buffer, col, 1, &err));
    CHECK(::line_sender_buffer_at_now(buffer, &err));
    CHECK(::line_sender_buffer_row_count(buffer) == 1);

    CHECK_FALSE(::line_sender_buffer_bookmark(buffer, nullptr, &err));
    REQUIRE(err != nullptr);
    CHECK(
        ::line_sender_error_get_code(err) ==
        ::line_sender_error_invalid_api_call);
    CHECK(line_sender_error_message(err).find("out") != std::string::npos);
    ::line_sender_error_free(err);
    err = nullptr;

    CHECK(::line_sender_buffer_table(buffer, table, &err));
    CHECK(::line_sender_buffer_column_i64(buffer, col, 2, &err));
    CHECK(::line_sender_buffer_at_now(buffer, &err));
    CHECK(::line_sender_buffer_row_count(buffer) == 2);

    CHECK_FALSE(::line_sender_buffer_rewind_to_marker(buffer, &err));
    REQUIRE(err != nullptr);
    CHECK(
        ::line_sender_error_get_code(err) ==
        ::line_sender_error_invalid_api_call);
    ::line_sender_error_free(err);
    err = nullptr;
    CHECK(::line_sender_buffer_row_count(buffer) == 2);
}

TEST_CASE("line_sender c api max_datagram_size rejected for tcp opts")
{
    ::line_sender_error* err = nullptr;
    on_scope_exit error_free_guard{[&] {
        if (err)
            ::line_sender_error_free(err);
    }};

    const auto host = QDB_UTF8_LITERAL("127.0.0.1");
    ::line_sender_opts* opts =
        ::line_sender_opts_new(::line_sender_protocol_tcp, host, 9009);
    REQUIRE(opts != nullptr);
    on_scope_exit opts_free_guard{[&] { ::line_sender_opts_free(opts); }};

    CHECK_FALSE(::line_sender_opts_max_datagram_size(opts, 256, &err));
    REQUIRE(err != nullptr);
    CHECK(line_sender_error_message(err).find("only supported for QWP/UDP") != std::string::npos);
    ::line_sender_error_free(err);
    err = nullptr;

    CHECK_FALSE(::line_sender_opts_multicast_ttl(opts, 3, &err));
    REQUIRE(err != nullptr);
    CHECK(line_sender_error_message(err).find("only supported for QWP/UDP") != std::string::npos);
}

TEST_CASE("line_sender c api qwpudp opts reject invalid datagram settings")
{
    ::line_sender_error* err = nullptr;
    on_scope_exit error_free_guard{[&] {
        if (err)
            ::line_sender_error_free(err);
    }};

    const auto host = QDB_UTF8_LITERAL("127.0.0.1");
    ::line_sender_opts* opts =
        ::line_sender_opts_new(::line_sender_protocol_qwpudp, host, 9009);
    REQUIRE(opts != nullptr);
    on_scope_exit opts_free_guard{[&] { ::line_sender_opts_free(opts); }};

    CHECK_FALSE(::line_sender_opts_max_datagram_size(opts, 0, &err));
    REQUIRE(err != nullptr);
    CHECK(
        line_sender_error_message(err).find("greater than 0") !=
        std::string::npos);
    ::line_sender_error_free(err);
    err = nullptr;

    CHECK_FALSE(::line_sender_opts_multicast_ttl(opts, 256, &err));
    REQUIRE(err != nullptr);
    CHECK(
        line_sender_error_message(err).find("between 0 and 255") !=
        std::string::npos);
}

TEST_CASE("line_sender c api qwpudp array rank bounds are rejected")
{
    ::line_sender_error* err = nullptr;
    on_scope_exit error_free_guard{[&] {
        if (err)
            ::line_sender_error_free(err);
    }};

    ::line_sender_buffer* buffer = ::line_sender_buffer_new_qwp();
    REQUIRE(buffer != nullptr);
    on_scope_exit buffer_free_guard{[&] { ::line_sender_buffer_free(buffer); }};

    const auto table = QDB_TABLE_NAME_LITERAL("t");
    const auto col = QDB_COLUMN_NAME_LITERAL("arr");
    CHECK(::line_sender_buffer_table(buffer, table, &err));

    uintptr_t shape_one[] = {1};
    double data[] = {1.0};
    CHECK_FALSE(::line_sender_buffer_column_f64_arr_c_major(
        buffer, col, 0, shape_one, data, 1, &err));
    REQUIRE(err != nullptr);
    CHECK(
        line_sender_error_message(err).find("Zero-dimensional arrays") !=
        std::string::npos);
    ::line_sender_error_free(err);
    err = nullptr;

    std::array<uintptr_t, 33> shape_33{};
    shape_33.fill(1);
    CHECK_FALSE(::line_sender_buffer_column_f64_arr_c_major(
        buffer, col, shape_33.size(), shape_33.data(), data, 1, &err));
    REQUIRE(err != nullptr);
    CHECK(
        line_sender_error_message(err).find("expected at most") !=
        std::string::npos);
}

TEST_CASE("line_sender c++ qwpudp bookmark rewind and clear")
{
    udp_capture receiver;
    questdb::ingress::opts opts{
        questdb::ingress::protocol::qwpudp,
        std::string("127.0.0.1"),
        std::to_string(receiver.port())};
    questdb::ingress::line_sender sender{opts};

    questdb::ingress::line_sender_buffer buffer = sender.new_buffer();
    buffer.table("t").symbol("s", "a").column("x", int64_t{1}).at_now();

    auto bm = buffer.bookmark();
    buffer.table("t").symbol("s", "b").column("x", int64_t{2}).at_now();
    CHECK(buffer.row_count() == 2);

    buffer.rewind_to_bookmark(bm);
    CHECK(buffer.row_count() == 1);

    // Flush should send only the first row.
    sender.flush(buffer);
    auto datagram = receiver.recv_datagram();
    CHECK(datagram_starts_with_qwp1(datagram));

    // Clear bookmark and verify a stale bookmark is rejected.
    buffer = sender.new_buffer();
    buffer.table("t").symbol("s", "c").column("x", int64_t{3}).at_now();
    auto bm2 = buffer.bookmark();
    buffer.table("t").symbol("s", "d").column("x", int64_t{4}).at_now();
    buffer.clear_bookmark(bm2);
    CHECK_THROWS_AS(
        buffer.rewind_to_bookmark(bm2),
        questdb::ingress::line_sender_error);
}

TEST_CASE("line_sender c api flush empty qwpudp buffer is noop")
{
    udp_capture receiver;
    ::line_sender_error* err = nullptr;
    on_scope_exit error_free_guard{[&] {
        if (err)
            ::line_sender_error_free(err);
    }};

    const auto host = QDB_UTF8_LITERAL("127.0.0.1");
    ::line_sender_opts* opts =
        ::line_sender_opts_new(::line_sender_protocol_qwpudp, host, receiver.port());
    REQUIRE(opts != nullptr);

    ::line_sender* sender = ::line_sender_build(opts, &err);
    REQUIRE(sender != nullptr);
    on_scope_exit sender_close_guard{[&] { ::line_sender_close(sender); }};

    ::line_sender_buffer* buffer = ::line_sender_buffer_new_for_sender(sender);
    REQUIRE(buffer != nullptr);
    on_scope_exit buffer_free_guard{[&] { ::line_sender_buffer_free(buffer); }};

    // Empty buffer flush should succeed (no-op).
    CHECK(::line_sender_flush(sender, buffer, &err));
    CHECK(::line_sender_buffer_row_count(buffer) == 0);
    CHECK_FALSE(receiver.has_datagram());
}

TEST_CASE("line_sender c api qwp buffer rejected by tcp sender")
{
    questdb::ingress::test::mock_server server;
    ::line_sender_error* err = nullptr;
    on_scope_exit error_free_guard{[&] {
        if (err)
            ::line_sender_error_free(err);
    }};

    const auto host = QDB_UTF8_LITERAL("127.0.0.1");
    ::line_sender_opts* opts =
        ::line_sender_opts_new(::line_sender_protocol_tcp, host, server.port());
    REQUIRE(opts != nullptr);

    ::line_sender* sender = ::line_sender_build(opts, &err);
    REQUIRE(sender != nullptr);
    on_scope_exit sender_close_guard{[&] { ::line_sender_close(sender); }};
    server.accept();

    // Create a QWP buffer and try to flush it via a TCP sender.
    ::line_sender_buffer* buffer = ::line_sender_buffer_new_qwp();
    REQUIRE(buffer != nullptr);
    on_scope_exit buffer_free_guard{[&] { ::line_sender_buffer_free(buffer); }};

    const auto table = QDB_TABLE_NAME_LITERAL("t");
    const auto col = QDB_COLUMN_NAME_LITERAL("x");
    CHECK(::line_sender_buffer_table(buffer, table, &err));
    CHECK(::line_sender_buffer_column_i64(buffer, col, 1, &err));
    CHECK(::line_sender_buffer_at_now(buffer, &err));

    CHECK_FALSE(::line_sender_flush(sender, buffer, &err));
    REQUIRE(err != nullptr);
    CHECK(
        line_sender_error_message(err).find("ILP sender requires an ILP buffer") !=
        std::string::npos);
}

TEST_CASE("line_sender c++ qwpudp opts reusable after protocol_version error")
{
    udp_capture receiver;
    questdb::ingress::opts opts{
        questdb::ingress::protocol::qwpudp,
        std::string("127.0.0.1"),
        std::to_string(receiver.port())};

    // protocol_version is rejected for QWP/UDP — catch the error.
    CHECK_THROWS_AS(
        opts.protocol_version(questdb::ingress::protocol_version::v2),
        questdb::ingress::line_sender_error);

    // The opts must still be usable with its original configuration.
    questdb::ingress::line_sender sender{opts};
    CHECK(sender.protocol_version() != questdb::ingress::protocol_version::v2);
    questdb::ingress::line_sender_buffer buffer = sender.new_buffer();
    buffer.table("test").column("x", int64_t{1}).at_now();
    sender.flush(buffer);
}

TEST_CASE("line_sender c++ qwpudp all column types with designated timestamp")
{
    udp_capture receiver;
    questdb::ingress::opts opts{
        questdb::ingress::protocol::qwpudp,
        std::string("127.0.0.1"),
        std::to_string(receiver.port())};
    questdb::ingress::line_sender sender{opts};

    questdb::ingress::line_sender_buffer buffer = sender.new_buffer();
    buffer.table("sensor_data")
        .symbol("location", "NYC")
        .column("active", true)
        .column("count", int64_t{42})
        .column("temperature", 23.5)
        .column("label", "hello"_utf8)
        .column("event_ts", questdb::ingress::timestamp_nanos{123456789})
        .column("sample_ts", questdb::ingress::timestamp_micros{987654})
        .at(questdb::ingress::timestamp_nanos{1000000000});

    sender.flush(buffer);
    CHECK(buffer.row_count() == 0);
    const auto datagram = receiver.recv_datagram();
    CHECK(datagram_starts_with_qwp1(datagram));
    // Verify at least the header + one row was encoded.
    CHECK(datagram.size() > 20);
}

TEST_CASE("line_sender c++ qwpudp at_micros designated timestamp")
{
    udp_capture receiver;
    questdb::ingress::opts opts{
        questdb::ingress::protocol::qwpudp,
        std::string("127.0.0.1"),
        std::to_string(receiver.port())};
    questdb::ingress::line_sender sender{opts};

    questdb::ingress::line_sender_buffer buffer = sender.new_buffer();
    buffer.table("ticks")
        .symbol("sym", "AAPL")
        .column("px", 150.25)
        .at(questdb::ingress::timestamp_micros{5000000});

    sender.flush(buffer);
    const auto datagram = receiver.recv_datagram();
    CHECK(datagram_starts_with_qwp1(datagram));
}

TEST_CASE("line_sender c++ qwpudp sparse columns across rows")
{
    udp_capture receiver;
    questdb::ingress::opts opts{
        questdb::ingress::protocol::qwpudp,
        std::string("127.0.0.1"),
        std::to_string(receiver.port())};
    questdb::ingress::line_sender sender{opts};

    questdb::ingress::line_sender_buffer buffer = sender.new_buffer();
    // Row 1: has "qty" and "active", no "px"
    buffer.table("trades")
        .symbol("sym", "ETH-USD")
        .column("qty", int64_t{10})
        .column("active", true)
        .at_now();
    // Row 2: has "px" and "active", no "qty"
    buffer.table("trades")
        .symbol("sym", "BTC-USD")
        .column("px", 45000.0)
        .column("active", false)
        .at_now();
    // Row 3: only "qty"
    buffer.table("trades")
        .symbol("sym", "SOL-USD")
        .column("qty", int64_t{99})
        .at_now();

    CHECK(buffer.row_count() == 3);
    sender.flush(buffer);
    CHECK(buffer.row_count() == 0);
    const auto datagram = receiver.recv_datagram();
    CHECK(datagram_starts_with_qwp1(datagram));
}

TEST_CASE("line_sender c++ qwpudp multiple tables in one flush")
{
    udp_capture receiver;
    questdb::ingress::opts opts{
        questdb::ingress::protocol::qwpudp,
        std::string("127.0.0.1"),
        std::to_string(receiver.port())};
    questdb::ingress::line_sender sender{opts};

    questdb::ingress::line_sender_buffer buffer = sender.new_buffer();
    buffer.table("trades")
        .symbol("sym", "ETH-USD")
        .column("qty", int64_t{4})
        .at_now();
    buffer.table("quotes")
        .symbol("sym", "BTC-USD")
        .column("bid", 44000.0)
        .at_now();
    buffer.table("trades")
        .symbol("sym", "SOL-USD")
        .column("qty", int64_t{7})
        .at_now();

    CHECK(buffer.row_count() == 3);
    sender.flush(buffer);
    // Each table batch becomes a separate datagram.
    const auto d1 = receiver.recv_datagram();
    const auto d2 = receiver.recv_datagram();
    const auto d3 = receiver.recv_datagram();
    CHECK(datagram_starts_with_qwp1(d1));
    CHECK(datagram_starts_with_qwp1(d2));
    CHECK(datagram_starts_with_qwp1(d3));
    // Three contiguous table batches: trades, quotes, trades -> 3 datagrams.
}

TEST_CASE("line_sender c++ qwpudp clear and reuse buffer")
{
    udp_capture receiver;
    questdb::ingress::opts opts{
        questdb::ingress::protocol::qwpudp,
        std::string("127.0.0.1"),
        std::to_string(receiver.port())};
    questdb::ingress::line_sender sender{opts};

    questdb::ingress::line_sender_buffer buffer = sender.new_buffer();
    buffer.table("t").symbol("s", "a").column("x", int64_t{1}).at_now();
    CHECK(buffer.row_count() == 1);

    buffer.clear();
    CHECK(buffer.row_count() == 0);

    // Buffer should be reusable after clear.
    buffer.table("t").symbol("s", "b").column("x", int64_t{2}).at_now();
    CHECK(buffer.row_count() == 1);
    sender.flush(buffer);
    const auto datagram = receiver.recv_datagram();
    CHECK(datagram_starts_with_qwp1(datagram));
}

TEST_CASE("line_sender c++ qwpudp flush_and_keep empty buffer is noop")
{
    udp_capture receiver;
    questdb::ingress::opts opts{
        questdb::ingress::protocol::qwpudp,
        std::string("127.0.0.1"),
        std::to_string(receiver.port())};
    questdb::ingress::line_sender sender{opts};

    questdb::ingress::line_sender_buffer buffer = sender.new_buffer();
    CHECK(buffer.row_count() == 0);

    // Should not throw or send anything.
    sender.flush_and_keep(buffer);
    CHECK(buffer.row_count() == 0);
    CHECK_FALSE(receiver.has_datagram());
}

TEST_CASE("line_sender c api qwpudp marker rewind rows")
{
    udp_capture receiver;
    ::line_sender_error* err = nullptr;
    on_scope_exit error_free_guard{[&] {
        if (err)
            ::line_sender_error_free(err);
    }};

    const auto host = QDB_UTF8_LITERAL("127.0.0.1");
    ::line_sender_opts* opts =
        ::line_sender_opts_new(::line_sender_protocol_qwpudp, host, receiver.port());
    REQUIRE(opts != nullptr);
    on_scope_exit opts_free_guard{[&] { ::line_sender_opts_free(opts); }};

    ::line_sender* sender = ::line_sender_build(opts, &err);
    REQUIRE(sender != nullptr);
    on_scope_exit sender_close_guard{[&] { ::line_sender_close(sender); }};

    ::line_sender_buffer* buffer = ::line_sender_buffer_new_for_sender(sender);
    REQUIRE(buffer != nullptr);
    on_scope_exit buffer_free_guard{[&] { ::line_sender_buffer_free(buffer); }};

    const auto trades = QDB_TABLE_NAME_LITERAL("trades");
    const auto quotes = QDB_TABLE_NAME_LITERAL("quotes");
    const auto sym = QDB_COLUMN_NAME_LITERAL("sym");
    const auto qty = QDB_COLUMN_NAME_LITERAL("qty");

    CHECK(::line_sender_buffer_table(buffer, trades, &err));
    CHECK(::line_sender_buffer_symbol(buffer, sym, QDB_UTF8_LITERAL("ETH-USD"), &err));
    CHECK(::line_sender_buffer_column_i64(buffer, qty, 1, &err));
    CHECK(::line_sender_buffer_at_now(buffer, &err));
    CHECK(::line_sender_buffer_row_count(buffer) == 1);
    CHECK_FALSE(::line_sender_buffer_transactional(buffer));

    CHECK(::line_sender_buffer_set_marker(buffer, &err));
    CHECK(::line_sender_buffer_table(buffer, quotes, &err));
    CHECK(::line_sender_buffer_symbol(buffer, sym, QDB_UTF8_LITERAL("BTC-USD"), &err));
    CHECK(::line_sender_buffer_column_i64(buffer, qty, 2, &err));
    CHECK(::line_sender_buffer_at_now(buffer, &err));
    CHECK(::line_sender_buffer_row_count(buffer) == 2);

    CHECK(::line_sender_buffer_rewind_to_marker(buffer, &err));
    CHECK(::line_sender_buffer_row_count(buffer) == 1);
    CHECK_FALSE(::line_sender_buffer_transactional(buffer));

    CHECK(::line_sender_buffer_table(buffer, trades, &err));
    CHECK(::line_sender_buffer_symbol(buffer, sym, QDB_UTF8_LITERAL("SOL-USD"), &err));
    CHECK(::line_sender_buffer_column_i64(buffer, qty, 3, &err));
    CHECK(::line_sender_buffer_at_now(buffer, &err));
    CHECK(::line_sender_buffer_row_count(buffer) == 2);

    CHECK_FALSE(::line_sender_buffer_rewind_to_marker(buffer, &err));
    REQUIRE(err != nullptr);
    ::line_sender_error_free(err);
    err = nullptr;

    CHECK(::line_sender_flush(sender, buffer, &err));
    CHECK(::line_sender_buffer_row_count(buffer) == 0);
    const auto datagram = receiver.recv_datagram();
    CHECK(datagram_starts_with_qwp1(datagram));
    const std::string datagram_text{
        reinterpret_cast<const char*>(datagram.data()),
        datagram.size()};
    CHECK(datagram_text.find("trades") != std::string::npos);
    CHECK(datagram_text.find("ETH-USD") != std::string::npos);
    CHECK(datagram_text.find("SOL-USD") != std::string::npos);
    CHECK(datagram_text.find("quotes") == std::string::npos);
    CHECK(datagram_text.find("BTC-USD") == std::string::npos);
    CHECK_FALSE(receiver.has_datagram());
}

TEST_CASE("line_sender c api qwpudp bookmark rewind and stale rejection")
{
    udp_capture receiver;
    ::line_sender_error* err = nullptr;
    on_scope_exit error_free_guard{[&] {
        if (err)
            ::line_sender_error_free(err);
    }};

    const auto host = QDB_UTF8_LITERAL("127.0.0.1");
    ::line_sender_opts* opts =
        ::line_sender_opts_new(::line_sender_protocol_qwpudp, host, receiver.port());
    REQUIRE(opts != nullptr);

    ::line_sender* sender = ::line_sender_build(opts, &err);
    REQUIRE(sender != nullptr);
    on_scope_exit sender_close_guard{[&] { ::line_sender_close(sender); }};

    ::line_sender_buffer* buffer = ::line_sender_buffer_new_for_sender(sender);
    REQUIRE(buffer != nullptr);
    on_scope_exit buffer_free_guard{[&] { ::line_sender_buffer_free(buffer); }};

    const auto table = QDB_TABLE_NAME_LITERAL("t");
    const auto col = QDB_COLUMN_NAME_LITERAL("x");

    // Add a row, then bookmark.
    CHECK(::line_sender_buffer_table(buffer, table, &err));
    CHECK(::line_sender_buffer_column_i64(buffer, col, 1, &err));
    CHECK(::line_sender_buffer_at_now(buffer, &err));
    CHECK(::line_sender_buffer_row_count(buffer) == 1);

    ::line_sender_bookmark bm{};
    CHECK(::line_sender_buffer_bookmark(buffer, &bm, &err));

    // Add a second row.
    CHECK(::line_sender_buffer_table(buffer, table, &err));
    CHECK(::line_sender_buffer_column_i64(buffer, col, 2, &err));
    CHECK(::line_sender_buffer_at_now(buffer, &err));
    CHECK(::line_sender_buffer_row_count(buffer) == 2);

    // Rewind discards the second row.
    CHECK(::line_sender_buffer_rewind_to_bookmark(buffer, bm, &err));
    CHECK(::line_sender_buffer_row_count(buffer) == 1);

    // Flush sends only the first row.
    CHECK(::line_sender_flush(sender, buffer, &err));
    const auto datagram = receiver.recv_datagram();
    CHECK(datagram_starts_with_qwp1(datagram));

    // After flush the bookmark is consumed; rewind should fail.
    CHECK_FALSE(::line_sender_buffer_rewind_to_bookmark(buffer, bm, &err));
    REQUIRE(err != nullptr);
    ::line_sender_error_free(err);
    err = nullptr;
}

TEST_CASE("line_sender c api qwpudp flush_and_keep via c api")
{
    udp_capture receiver;
    ::line_sender_error* err = nullptr;
    on_scope_exit error_free_guard{[&] {
        if (err)
            ::line_sender_error_free(err);
    }};

    const auto host = QDB_UTF8_LITERAL("127.0.0.1");
    ::line_sender_opts* opts =
        ::line_sender_opts_new(::line_sender_protocol_qwpudp, host, receiver.port());
    REQUIRE(opts != nullptr);

    ::line_sender* sender = ::line_sender_build(opts, &err);
    REQUIRE(sender != nullptr);
    on_scope_exit sender_close_guard{[&] { ::line_sender_close(sender); }};

    ::line_sender_buffer* buffer = ::line_sender_buffer_new_for_sender(sender);
    REQUIRE(buffer != nullptr);
    on_scope_exit buffer_free_guard{[&] { ::line_sender_buffer_free(buffer); }};

    const auto table = QDB_TABLE_NAME_LITERAL("t");
    const auto col = QDB_COLUMN_NAME_LITERAL("x");

    CHECK(::line_sender_buffer_table(buffer, table, &err));
    CHECK(::line_sender_buffer_column_i64(buffer, col, 42, &err));
    CHECK(::line_sender_buffer_at_now(buffer, &err));

    // flush_and_keep preserves the buffer content.
    CHECK(::line_sender_flush_and_keep(sender, buffer, &err));
    CHECK(::line_sender_buffer_row_count(buffer) == 1);
    const auto first = receiver.recv_datagram();
    CHECK(datagram_starts_with_qwp1(first));

    // Second flush_and_keep sends the same data.
    CHECK(::line_sender_flush_and_keep(sender, buffer, &err));
    CHECK(::line_sender_buffer_row_count(buffer) == 1);
    const auto second = receiver.recv_datagram();
    CHECK(second == first);

    // Regular flush clears the buffer.
    CHECK(::line_sender_flush(sender, buffer, &err));
    CHECK(::line_sender_buffer_row_count(buffer) == 0);
}

TEST_CASE("line_sender c api qwpudp all column types with at_nanos")
{
    udp_capture receiver;
    ::line_sender_error* err = nullptr;
    on_scope_exit error_free_guard{[&] {
        if (err)
            ::line_sender_error_free(err);
    }};

    const auto host = QDB_UTF8_LITERAL("127.0.0.1");
    ::line_sender_opts* opts =
        ::line_sender_opts_new(::line_sender_protocol_qwpudp, host, receiver.port());
    REQUIRE(opts != nullptr);

    ::line_sender* sender = ::line_sender_build(opts, &err);
    REQUIRE(sender != nullptr);
    on_scope_exit sender_close_guard{[&] { ::line_sender_close(sender); }};

    ::line_sender_buffer* buffer = ::line_sender_buffer_new_for_sender(sender);
    REQUIRE(buffer != nullptr);
    on_scope_exit buffer_free_guard{[&] { ::line_sender_buffer_free(buffer); }};

    const auto table = QDB_TABLE_NAME_LITERAL("sensors");
    const auto sym = QDB_COLUMN_NAME_LITERAL("loc");
    const auto active = QDB_COLUMN_NAME_LITERAL("active");
    const auto count = QDB_COLUMN_NAME_LITERAL("count");
    const auto temp = QDB_COLUMN_NAME_LITERAL("temp");
    const auto label = QDB_COLUMN_NAME_LITERAL("label");
    const auto event_ts = QDB_COLUMN_NAME_LITERAL("event_ts");
    const auto sym_value = QDB_UTF8_LITERAL("NYC");
    const auto label_value = QDB_UTF8_LITERAL("sensor-a");

    CHECK(::line_sender_buffer_table(buffer, table, &err));
    CHECK(::line_sender_buffer_symbol(buffer, sym, sym_value, &err));
    CHECK(::line_sender_buffer_column_bool(buffer, active, true, &err));
    CHECK(::line_sender_buffer_column_i64(buffer, count, 100, &err));
    CHECK(::line_sender_buffer_column_f64(buffer, temp, 22.75, &err));
    CHECK(::line_sender_buffer_column_str(buffer, label, label_value, &err));
    CHECK(::line_sender_buffer_column_ts_nanos(buffer, event_ts, 123456789, &err));
    CHECK(::line_sender_buffer_at_nanos(buffer, 1000000000, &err));

    CHECK(::line_sender_flush(sender, buffer, &err));
    const auto datagram = receiver.recv_datagram();
    CHECK(datagram_starts_with_qwp1(datagram));
    CHECK(datagram.size() > 20);
}

TEST_CASE("line_sender c api qwpudp at_micros designated timestamp")
{
    udp_capture receiver;
    ::line_sender_error* err = nullptr;
    on_scope_exit error_free_guard{[&] {
        if (err)
            ::line_sender_error_free(err);
    }};

    const auto host = QDB_UTF8_LITERAL("127.0.0.1");
    ::line_sender_opts* opts =
        ::line_sender_opts_new(::line_sender_protocol_qwpudp, host, receiver.port());
    REQUIRE(opts != nullptr);

    ::line_sender* sender = ::line_sender_build(opts, &err);
    REQUIRE(sender != nullptr);
    on_scope_exit sender_close_guard{[&] { ::line_sender_close(sender); }};

    ::line_sender_buffer* buffer = ::line_sender_buffer_new_for_sender(sender);
    REQUIRE(buffer != nullptr);
    on_scope_exit buffer_free_guard{[&] { ::line_sender_buffer_free(buffer); }};

    const auto table = QDB_TABLE_NAME_LITERAL("ticks");
    const auto col = QDB_COLUMN_NAME_LITERAL("px");

    CHECK(::line_sender_buffer_table(buffer, table, &err));
    CHECK(::line_sender_buffer_column_f64(buffer, col, 150.25, &err));
    CHECK(::line_sender_buffer_at_micros(buffer, 5000000, &err));

    CHECK(::line_sender_flush(sender, buffer, &err));
    const auto datagram = receiver.recv_datagram();
    CHECK(datagram_starts_with_qwp1(datagram));
}

TEST_CASE("line_sender c api qwpudp sparse columns across rows")
{
    udp_capture receiver;
    ::line_sender_error* err = nullptr;
    on_scope_exit error_free_guard{[&] {
        if (err)
            ::line_sender_error_free(err);
    }};

    const auto host = QDB_UTF8_LITERAL("127.0.0.1");
    ::line_sender_opts* opts =
        ::line_sender_opts_new(::line_sender_protocol_qwpudp, host, receiver.port());
    REQUIRE(opts != nullptr);

    ::line_sender* sender = ::line_sender_build(opts, &err);
    REQUIRE(sender != nullptr);
    on_scope_exit sender_close_guard{[&] { ::line_sender_close(sender); }};

    ::line_sender_buffer* buffer = ::line_sender_buffer_new_for_sender(sender);
    REQUIRE(buffer != nullptr);
    on_scope_exit buffer_free_guard{[&] { ::line_sender_buffer_free(buffer); }};

    const auto table = QDB_TABLE_NAME_LITERAL("trades");
    const auto sym = QDB_COLUMN_NAME_LITERAL("sym");
    const auto qty = QDB_COLUMN_NAME_LITERAL("qty");
    const auto px = QDB_COLUMN_NAME_LITERAL("px");
    const auto active = QDB_COLUMN_NAME_LITERAL("active");

    // Row 1: has qty and active, no px.
    CHECK(::line_sender_buffer_table(buffer, table, &err));
    CHECK(::line_sender_buffer_symbol(buffer, sym, QDB_UTF8_LITERAL("ETH"), &err));
    CHECK(::line_sender_buffer_column_i64(buffer, qty, 10, &err));
    CHECK(::line_sender_buffer_column_bool(buffer, active, true, &err));
    CHECK(::line_sender_buffer_at_now(buffer, &err));

    // Row 2: has px and active, no qty.
    CHECK(::line_sender_buffer_table(buffer, table, &err));
    CHECK(::line_sender_buffer_symbol(buffer, sym, QDB_UTF8_LITERAL("BTC"), &err));
    CHECK(::line_sender_buffer_column_f64(buffer, px, 45000.0, &err));
    CHECK(::line_sender_buffer_column_bool(buffer, active, false, &err));
    CHECK(::line_sender_buffer_at_now(buffer, &err));

    // Row 3: only qty.
    CHECK(::line_sender_buffer_table(buffer, table, &err));
    CHECK(::line_sender_buffer_symbol(buffer, sym, QDB_UTF8_LITERAL("SOL"), &err));
    CHECK(::line_sender_buffer_column_i64(buffer, qty, 99, &err));
    CHECK(::line_sender_buffer_at_now(buffer, &err));

    CHECK(::line_sender_buffer_row_count(buffer) == 3);
    CHECK(::line_sender_flush(sender, buffer, &err));

    const auto datagram = receiver.recv_datagram();
    CHECK(datagram_starts_with_qwp1(datagram));
}

TEST_CASE("line_sender c++ qwpudp rejects duplicate column name")
{
    questdb::ingress::line_sender_buffer buffer =
        questdb::ingress::line_sender_buffer::qwp_udp();

    buffer.table("t").column("x", int64_t{1});
    CHECK_THROWS_AS(
        buffer.column("x", int64_t{2}),
        questdb::ingress::line_sender_error);
}

TEST_CASE("line_sender c++ qwpudp new_buffer inherits max_name_len")
{
    udp_capture receiver;
    questdb::ingress::opts opts{
        questdb::ingress::protocol::qwpudp,
        std::string("127.0.0.1"),
        std::to_string(receiver.port())};
    opts.max_name_len(16);
    questdb::ingress::line_sender sender{opts};

    questdb::ingress::line_sender_buffer buffer = sender.new_buffer();
    // Name with 17 chars should exceed the inherited max_name_len of 16.
    CHECK_THROWS_AS(
        buffer.table("abcdefghijklmnopq"),
        questdb::ingress::line_sender_error);

    // Name with exactly 16 chars should be fine.
    buffer.table("abcdefghijklmnop").column("x", int64_t{1}).at_now();
    sender.flush(buffer);
    const auto datagram = receiver.recv_datagram();
    CHECK(datagram_starts_with_qwp1(datagram));
}
