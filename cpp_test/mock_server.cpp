/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2023 QuestDB
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

#include "mock_server.hpp"

#include <string.h>

#if defined(PLATFORM_UNIX)
#include <fcntl.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#elif defined(PLATFORM_WINDOWS)
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#if defined(PLATFORM_UNIX)
#define CLOSESOCKET ::close
typedef const void* setsockopt_arg_t;
#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif
#elif defined(PLATFORM_WINDOWS)
#define CLOSESOCKET ::closesocket
typedef const char* setsockopt_arg_t;
typedef long suseconds_t;
#endif

#if defined(PLATFORM_UNIX)
typedef ssize_t sock_ssize_t;
typedef size_t sock_len_t;
#elif defined(PLATFORM_WINDOWS)
typedef int sock_ssize_t;
typedef int sock_len_t;
#endif

#if defined(PLATFORM_WINDOWS)
static void init_winsock()
{
    WORD vers_req = MAKEWORD(2, 2);
    WSADATA wsa_data;
    int err = WSAStartup(vers_req, &wsa_data);
    if (err != 0)
    {
        fprintf(
            stderr,
            "Socket init failed. WSAStartup failed with error: %d",
            err);
        abort();
    }
}

static void release_winsock()
{
    if (WSACleanup() != 0)
    {
        fprintf(
            stderr,
            "Releasing sockets failed: WSACleanup failed with error: %d",
            WSAGetLastError());
        abort();
    }
}
#endif

namespace questdb::ingress::test
{

mock_server::mock_server()
    : _listen_fd{INVALID_SOCKET}
    , _conn_fd{INVALID_SOCKET}
    , _port{0}
    , _msgs{}
{
#if defined(PLATFORM_WINDOWS)
    init_winsock();
#endif
    _listen_fd = socket(AF_INET, SOCK_STREAM, 0);

    const int reuse_addr = 1;
    if (setsockopt(
            _listen_fd,
            SOL_SOCKET,
            SO_REUSEADDR,
            static_cast<setsockopt_arg_t>(static_cast<const void*>(
                &reuse_addr)),
            sizeof(reuse_addr)) != 0)
    {
#if defined(PLATFORM_UNIX)
        perror("Bad SO_REUSEADDR");
        throw std::runtime_error{"Bad SO_REUSEADDR."};
#elif defined(PLATFORM_WINDOWS)
        std::string last_err_num = std::to_string(WSAGetLastError());
        throw std::runtime_error("Bad SO_REUSEADDR: " + last_err_num);
#endif
    }

    sockaddr_in listen_addr;
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = INADDR_ANY;
    listen_addr.sin_port = htons(0);
    if (bind(
            _listen_fd,
            (const sockaddr *)&listen_addr,
            sizeof(listen_addr)) == -1)
        throw std::runtime_error{"Bad `bind()`."};

    if (listen(_listen_fd, 1) == -1)
        throw std::runtime_error{"Bad `listen()`."};

    sockaddr_in resolved_addr;
    memset(&resolved_addr, 0, sizeof(resolved_addr));
    socklen_t resolved_addr_len = sizeof(resolved_addr);
    if (getsockname(
            _listen_fd,
            (sockaddr *)&resolved_addr,
            &resolved_addr_len) == -1)
        throw std::runtime_error{"Bad `getsockname()`."};
    _port = ntohs(resolved_addr.sin_port);
}

void mock_server::accept()
{
    sockaddr_in remote_addr;
    socklen_t remote_addr_len = sizeof(remote_addr);
    _conn_fd = ::accept(
        _listen_fd,
        (sockaddr *)&remote_addr,
        &remote_addr_len);
    if (_conn_fd == INVALID_SOCKET)
        throw std::runtime_error{"Bad `accept()`."};
#if defined(PLATFORM_UNIX)
    fcntl(_conn_fd, F_SETFL, O_NONBLOCK);
#elif defined(PLATFORM_WINDOWS)
    u_long mode = 1;
    ioctlsocket(_conn_fd, FIONBIO, &mode);
#endif
}

bool mock_server::wait_for_data(std::optional<double> wait_timeout_sec)
{
    fd_set read_set;
    FD_ZERO(&read_set);
    FD_SET(_conn_fd, &read_set);
    timeval* timeout_ptr = nullptr;  // nullptr blocks indefinitely.
    timeval timeout;
    if (wait_timeout_sec)
    {
#if defined(PLATFORM_UNIX)
        const time_t secs = static_cast<time_t>(*wait_timeout_sec);
#elif defined(PLATFORM_WINDOWS)
        const long secs = static_cast<long>(*wait_timeout_sec);
#endif
        const suseconds_t usec =
            static_cast<suseconds_t>(
                1000000.0 * (*wait_timeout_sec - static_cast<double>(secs)));
        timeout = timeval{secs, usec};
        timeout_ptr = &timeout;
    }
    int nfds = static_cast<int>(_conn_fd) + 1;
    int count = ::select(nfds, &read_set, nullptr, nullptr, timeout_ptr);
    if (count == -1)
    {
#if defined(PLATFORM_UNIX)
        int errnum = errno;
#elif defined(PLATFORM_WINDOWS)
        int errnum = WSAGetLastError();
#endif
        throw std::runtime_error{"Bad `select()`: " + std::to_string(errnum)};
    }
    return !!count;
}

size_t mock_server::recv(double wait_timeout_sec)
{
    if (!wait_for_data(wait_timeout_sec))
        return 0;

    char chunk[1024];
    size_t chunk_len{sizeof(chunk)};
    std::vector<char> accum;
    for (;;)
    {
        wait_for_data();
        sock_ssize_t count = ::recv(
            _conn_fd,
            &chunk[0],
            static_cast<sock_len_t>(chunk_len),
            0);
        if (count == -1)
            throw std::runtime_error{"Bad `recv()`."};
        const size_t u_count = static_cast<size_t>(count);
        accum.insert(accum.end(), chunk, chunk + u_count);
        if (accum.size() < 2)
            continue;
        if ((accum[accum.size() - 1] == '\n') &&
            (accum[accum.size() - 2] != '\\'))
            break;
    }

    size_t received_count{0};
    const char* head{&accum[0]};
    for (size_t index = 1; index < accum.size(); ++index)
    {
        const char& last = accum[index];
        const char& prev = accum[index - 1];
        if ((last == '\n') && (prev != '\\'))
        {
            const char* tail{&last + 1};
            _msgs.emplace_back(head, tail - head);
            head = tail;
            ++received_count;
        }
    }
    return received_count;
}

void mock_server::close()
{
    if (_conn_fd != INVALID_SOCKET)
    {
        CLOSESOCKET(_conn_fd);
        _conn_fd = INVALID_SOCKET;
    }

    if (_listen_fd != INVALID_SOCKET)
    {
        CLOSESOCKET(_listen_fd);
        _listen_fd = INVALID_SOCKET;
    }
}

mock_server::~mock_server()
{
    this->close();

#if defined(PLATFORM_WINDOWS)
    release_winsock();
#endif
}

}
