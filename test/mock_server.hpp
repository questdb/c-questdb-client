#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <optional>

namespace questdb::proto::line::test
{

/**
 * Bug-ridden mock server to handle TCP and UDP.
 * YMMV, but should be just good enough for testing.
*/
class mock_server
{
public:
    explicit mock_server(bool tcp);  // false for `udp`.

    uint16_t port() const { return _port; }

    void accept();

    size_t recv(double wait_timeout_sec=0.1);

    const std::vector<std::string>& msgs() const
    {
        return _msgs;
    }

    ~mock_server();

private:
    bool wait_for_data(std::optional<double> wait_timeout_sec = std::nullopt);

    bool _tcp;
    int _listen_fd;
    int _conn_fd;
    uint16_t _port;
    std::vector<std::string> _msgs;
};

}
