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

#include <questdb/client.hpp>
#include <questdb/egress/qwp_reader.hpp>
#include <questdb/ingress/line_sender.hpp>
#include <questdb/token_provider.hpp>

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

using namespace std::chrono_literals;

TEST_CASE("A refreshing provider serves its source's token")
{
    std::atomic<int> fetches{0};
    auto provider = questdb::token_provider::refreshing(
        [&fetches] {
            const int n = ++fetches;
            return questdb::expiring_token{
                "T" + std::to_string(n), std::chrono::system_clock::now() + 1h};
        },
        questdb::refreshing_token_provider_options{"cpp-test"});
    CHECK(provider.await_ready(10s));
    CHECK(provider.token() == "T1");

    // Copies share the provider; closing it ends every holder.
    const questdb::token_provider copy{provider};
    CHECK(copy.token() == "T1");
    copy.close();
    CHECK_THROWS_AS(provider.token(), questdb::error);
    CHECK(fetches.load() == 1);
}

TEST_CASE("A source's exception becomes a classified failure")
{
    questdb::refreshing_token_provider_options options;
    options.cold_wait = 50ms;
    auto provider = questdb::token_provider::refreshing(
        []() -> questdb::expiring_token {
            throw questdb::token_unavailable{
                "identity not assigned", false, 2500ms};
        },
        options);
    try
    {
        (void)provider.token();
        FAIL("expected a failure");
    }
    catch (const questdb::error& e)
    {
        CHECK(
            std::string{e.what()}.find("identity not assigned") !=
            std::string::npos);
    }
}

namespace
{
class recording_provider : public questdb::bearer_token_provider
{
public:
    std::string token() override
    {
        const std::lock_guard<std::mutex> lock{_mutex};
        return _rejected.empty() ? "stale" : "fresh";
    }

    void on_rejected(std::string_view token, uint16_t http_status) override
    {
        const std::lock_guard<std::mutex> lock{_mutex};
        _rejected.emplace_back(std::string{token}, http_status);
    }

    std::vector<std::pair<std::string, uint16_t>> rejected()
    {
        const std::lock_guard<std::mutex> lock{_mutex};
        return _rejected;
    }

private:
    std::mutex _mutex;
    std::vector<std::pair<std::string, uint16_t>> _rejected;
};
} // namespace

TEST_CASE("An application provider hears rejections and is released")
{
    auto app = std::make_shared<recording_provider>();
    std::weak_ptr<recording_provider> watch{app};
    {
        auto provider = questdb::token_provider::from(app);
        app.reset();
        CHECK(provider.token() == "stale");
        provider.on_rejected("stale", 401);
        CHECK(provider.token() == "fresh");
        CHECK(
            watch.lock()->rejected() ==
            std::vector<std::pair<std::string, uint16_t>>{{"stale", 401}});
        CHECK(provider.await_ready(0ms));
    }
    CHECK(watch.expired());
}

TEST_CASE("A provider attaches to HTTP and WebSocket sender options only")
{
    auto provider =
        questdb::token_provider::from(std::make_shared<recording_provider>());
    auto http = questdb::ingress::opts::from_conf("http::addr=localhost:9000;");
    CHECK_NOTHROW(http.token_provider(provider));
    auto ws = questdb::ingress::opts::from_conf("ws::addr=localhost:9000;");
    CHECK_NOTHROW(ws.token_provider(provider));
    auto tcp = questdb::ingress::opts::from_conf("tcp::addr=localhost:9009;");
    CHECK_THROWS_AS(
        tcp.token_provider(provider), questdb::ingress::line_sender_error);
    auto fixed =
        questdb::ingress::opts::from_conf("ws::addr=localhost:9000;token=x;");
    CHECK_THROWS_AS(
        fixed.token_provider(provider), questdb::ingress::line_sender_error);
}

TEST_CASE("The connect-string token-provider keys are rejected")
{
    CHECK_THROWS_AS(
        questdb::ingress::opts::from_conf(
            "wss::addr=localhost:9000;token_provider=azure;"),
        questdb::ingress::line_sender_error);
}
