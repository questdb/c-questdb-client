#include "mock_server.hpp"

#include <string.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

namespace questdb::proto::line::test
{

mock_server::mock_server(bool tcp)  // false for `udp`.
    : _tcp{tcp}
    , _listen_fd{-1}
    , _conn_fd{-1}
    , _port{0}
    , _msgs{}
{
    if (_tcp)
        _listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    else
        _listen_fd = socket(AF_INET, SOCK_DGRAM, 0);

    const int reuse_addr = 1;
    if (setsockopt(
            _listen_fd,
            SOL_SOCKET,
            SO_REUSEADDR,
            &reuse_addr,
            sizeof(reuse_addr)) == -1)
        throw std::runtime_error{"Bad SO_REUSEADDR."};

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

    if (tcp && (listen(_listen_fd, 1) == -1))
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

    if (!_tcp)
    {
        _conn_fd = _listen_fd;
        _listen_fd = -1;
    }
}

void mock_server::accept()
{
    if (_tcp)
    {
        sockaddr_in remote_addr;
        socklen_t remote_addr_len = sizeof(remote_addr);
        _conn_fd = ::accept(
            _listen_fd,
            (sockaddr *)&remote_addr,
            &remote_addr_len);
        if (_conn_fd == -1)
            throw std::runtime_error{"Bad `accept()`."};
        fcntl(_conn_fd, F_SETFL, O_NONBLOCK);
    }
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
        const time_t secs = static_cast<time_t>(*wait_timeout_sec);
        const suseconds_t usec =
            static_cast<suseconds_t>(
                1000000.0 * (*wait_timeout_sec - static_cast<double>(secs)));
        timeout = timeval{secs, usec};
        timeout_ptr = &timeout;
    }
    int nfds = _conn_fd + 1;
    int count = ::select(nfds, &read_set, nullptr, nullptr, timeout_ptr);
    if (count == -1)
        throw std::runtime_error{"Bad `select()`."};
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
        ssize_t count = 0;
        if (_tcp)
        {
            count = ::recv(_conn_fd, &chunk, chunk_len, 0);
        }
        else
        {
            sockaddr_in src_addr;
            socklen_t src_addr_len{sizeof(src_addr)};
            count = ::recvfrom(
                _conn_fd,
                &chunk,
                chunk_len,
                0,
                (sockaddr *)&src_addr,
                &src_addr_len);
        }
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

mock_server::~mock_server()
{
    if (_conn_fd != -1)
        close(_conn_fd);
    if (_listen_fd != -1)
        close(_listen_fd);
}

}
