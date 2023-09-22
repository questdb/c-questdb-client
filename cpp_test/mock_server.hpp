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

#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <optional>
#include <stdexcept>

#include "build_env.h"

#if defined(PLATFORM_UNIX)
typedef int socketfd_t;
#elif defined(PLATFORM_WINDOWS)
#include <winsock2.h>
typedef SOCKET socketfd_t;
#endif

namespace questdb::ingress::test
{

/**
 * Bug-ridden mock server to handle line requests.
 * YMMV, but should be just good enough for testing.
*/
class mock_server
{
public:
    mock_server();

    uint16_t port() const { return _port; }

    void accept();

    size_t recv(double wait_timeout_sec=0.1);

    const std::vector<std::string>& msgs() const
    {
        return _msgs;
    }

    void close();

    ~mock_server();

private:
    bool wait_for_data(std::optional<double> wait_timeout_sec = std::nullopt);

    socketfd_t _listen_fd;
    socketfd_t _conn_fd;
    uint16_t _port;
    std::vector<std::string> _msgs;
};

}
