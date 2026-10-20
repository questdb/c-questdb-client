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
#include <string_view>
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

TEST_CASE("Negative provider durations are rejected before conversion")
{
    using options_type = questdb::refreshing_token_provider_options;
    std::optional<std::chrono::milliseconds> options_type::* const fields[] = {
        &options_type::refresh_margin,
        &options_type::min_refresh_interval,
        &options_type::handout_floor,
        &options_type::cold_wait,
        &options_type::backoff_initial,
        &options_type::backoff_max,
        &options_type::retry_after_max,
        &options_type::forced_min_interval,
        &options_type::forced_wait};
    std::atomic<int> fetches{0};
    const auto source = [&fetches] {
        ++fetches;
        return questdb::expiring_token{
            "valid", std::chrono::system_clock::now() + 1h};
    };
    for (auto field : fields)
    {
        options_type options;
        options.*field = -1ms;
        CHECK_THROWS_AS(
            questdb::token_provider::refreshing(source, options),
            std::invalid_argument);
    }
    CHECK(fetches.load() == 0);

    auto provider = questdb::token_provider::refreshing(source);
    CHECK_THROWS_AS(provider.await_ready(-1ms), std::invalid_argument);
    CHECK_NOTHROW(provider.await_ready(0ms));
    CHECK(provider.await_ready(10s));
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
        const auto& classification = e.token_unavailable_diagnostic();
        REQUIRE(classification.has_value());
        CHECK_FALSE(classification->retryable);
        REQUIRE(classification->retry_after.has_value());
        CHECK(*classification->retry_after > 0ms);
    }
}

TEST_CASE("A failed flush keeps the provider's classification")
{
    questdb::refreshing_token_provider_options options;
    options.cold_wait = 50ms;
    auto provider = questdb::token_provider::refreshing(
        []() -> questdb::expiring_token {
            throw questdb::token_unavailable{
                "identity not assigned", false, 2500ms};
        },
        options);
    auto opts = questdb::ingress::opts::from_conf(
        "http::addr=127.0.0.1:1;protocol_version=1;");
    opts.token_provider(provider);
    questdb::ingress::line_sender sender{opts};
    auto buffer = sender.new_buffer();
    buffer.table("t").column("x", int64_t{1}).at_now();
    try
    {
        sender.flush(buffer);
        FAIL("expected the flush to fail");
    }
    catch (const questdb::ingress::line_sender_error& e)
    {
        // The transport reports even a permanent provider failure as
        // socket_error; only the classification tells the two apart.
        CHECK(e.code() == questdb::error_code::socket_error);
        const auto& classification = e.token_unavailable_diagnostic();
        REQUIRE(classification.has_value());
        CHECK_FALSE(classification->retryable);
        CHECK_FALSE(e.is_qwp_ws_role_reject());
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
            std::vector<std::pair<std::string, uint16_t>>{
                {"stale", uint16_t{401}}});
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

namespace
{
/** The code of the error `attach` throws; fails the test if it does not. */
template <typename Attach>
questdb::error_code attach_error_code(Attach&& attach)
{
    try
    {
        attach();
    }
    catch (const questdb::error& e)
    {
        return e.code();
    }
    FAIL("expected the attachment to be refused");
    return questdb::error_code::invalid_api_call;
}
} // namespace

TEST_CASE("An empty provider is refused by every attach point")
{
    auto empty =
        questdb::token_provider::from(std::make_shared<recording_provider>());
    const auto kept = std::move(empty); // `empty` is now moved from
    CHECK(kept.token() == "stale");

    // The C pool options read a NULL provider as "none": passing the empty
    // handle on used to open a pool without any credential.
    CHECK(attach_error_code([&] {
              questdb::pool pool{
                  "ws::addr=127.0.0.1:1;lazy_connect=true;", empty};
          }) == questdb::error_code::invalid_api_call);
    CHECK(attach_error_code([&] {
              auto opts =
                  questdb::ingress::opts::from_conf("ws::addr=127.0.0.1:1;");
              opts.token_provider(empty);
          }) == questdb::error_code::invalid_api_call);
    CHECK(attach_error_code([&] {
              questdb::egress::reader reader{"ws::addr=127.0.0.1:1;", empty};
          }) == questdb::error_code::invalid_api_call);
}

TEST_CASE("A closed provider is refused where it is attached")
{
    auto closed = questdb::token_provider::refreshing([] {
        return questdb::expiring_token{
            "T", std::chrono::system_clock::now() + 1h};
    });
    REQUIRE(closed.await_ready(10s));
    closed.close();

    auto opts = questdb::ingress::opts::from_conf(
        "ws::addr=127.0.0.1:1;initial_connect_retry=async;");
    try
    {
        opts.token_provider(closed);
        FAIL("a closed provider was attached");
    }
    catch (const questdb::ingress::line_sender_error& e)
    {
        CHECK(e.code() == questdb::error_code::auth_error);
        REQUIRE(e.token_unavailable_diagnostic().has_value());
        CHECK_FALSE(e.token_unavailable_diagnostic()->retryable);
    }
    CHECK(attach_error_code([&] {
              questdb::pool pool{
                  "ws::addr=127.0.0.1:1;lazy_connect=true;", closed};
          }) == questdb::error_code::auth_error);
    CHECK(attach_error_code([&] {
              questdb::egress::reader reader{"ws::addr=127.0.0.1:1;", closed};
          }) == questdb::error_code::auth_error);
}

TEST_CASE("One opts take one rotating provider")
{
    auto first =
        questdb::token_provider::from(std::make_shared<recording_provider>());
    auto second =
        questdb::token_provider::from(std::make_shared<recording_provider>());
    for (const std::string_view conf :
         {"http::addr=localhost:9000;", "ws::addr=localhost:9000;"})
    {
        auto opts = questdb::ingress::opts::from_conf(conf);
        opts.token_provider(first);
        try
        {
            opts.token_provider(second);
            FAIL("a second provider replaced the first");
        }
        catch (const questdb::ingress::line_sender_error& e)
        {
            CHECK(e.code() == questdb::error_code::config_error);
        }
    }
}

TEST_CASE("The connect-string token-provider keys are rejected")
{
    CHECK_THROWS_AS(
        questdb::ingress::opts::from_conf(
            "wss::addr=localhost:9000;token_provider=azure;"),
        questdb::ingress::line_sender_error);
}
