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
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

using namespace std::chrono_literals;

// Another handle is taken explicitly, as for `oidc::device_auth`: a copy would
// alias one shared provider, so `close()` on the "copy" would end every client
// of the original.
static_assert(!std::is_copy_constructible<questdb::token_provider>::value);
static_assert(!std::is_copy_assignable<questdb::token_provider>::value);
static_assert(
    std::is_nothrow_move_constructible<questdb::token_provider>::value);
static_assert(std::is_nothrow_move_assignable<questdb::token_provider>::value);

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

    // A shared handle addresses the same provider; closing it ends every
    // holder.
    const questdb::token_provider shared = provider.share();
    CHECK(shared.raw() != provider.raw());
    CHECK(shared.token() == "T1");
    shared.close();
    CHECK_THROWS_AS(provider.token(), questdb::error);
    CHECK(fetches.load() == 1);

    // A moved-from handle has nothing to share.
    auto moved = std::move(provider);
    try
    {
        (void)provider.share();
        FAIL("a moved-from provider was shared");
    }
    catch (const questdb::error& e)
    {
        CHECK(e.code() == questdb::error_code::invalid_api_call);
    }
}

TEST_CASE("A token that never expires is served")
{
    // With MSVC, time_point::max() lies past the end of Windows' SystemTime.
    auto provider = questdb::token_provider::refreshing([] {
        return questdb::expiring_token{
            "forever", std::chrono::system_clock::time_point::max()};
    });
    CHECK(provider.await_ready(10s));
    CHECK(provider.token() == "forever");
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

namespace
{
class retired_provider : public questdb::bearer_token_provider
{
public:
    std::string token() override
    {
        throw questdb::error{
            questdb::error_code::invalid_api_call, "provider retired"};
    }
};

class failing_provider : public questdb::bearer_token_provider
{
public:
    std::string token() override
    {
        throw std::runtime_error{"refresh failed"};
    }
};
} // namespace

TEST_CASE("A provider's invalid_api_call stops its clients")
{
    // The counterpart of a Rust provider returning `InvalidApiCall`: the
    // transports report config_error, which no reconnect retries. A reader
    // pulls the token before it dials, so no server is needed.
    auto retired =
        questdb::token_provider::from(std::make_shared<retired_provider>());
    CHECK(attach_error_code([&] {
              questdb::egress::reader reader{"ws::addr=127.0.0.1:1;", retired};
          }) == questdb::error_code::config_error);
    // A direct pull reports what the provider reported, unclassified.
    try
    {
        (void)retired.token();
        FAIL("expected a failure");
    }
    catch (const questdb::error& e)
    {
        CHECK(e.code() == questdb::error_code::invalid_api_call);
        CHECK_FALSE(e.token_unavailable_diagnostic().has_value());
    }

    // Any other exception stays retryable.
    auto failing =
        questdb::token_provider::from(std::make_shared<failing_provider>());
    CHECK(attach_error_code([&] {
              questdb::egress::reader reader{"ws::addr=127.0.0.1:1;", failing};
          }) == questdb::error_code::socket_error);
}

TEST_CASE("A source's invalid_api_call stays retryable")
{
    // A token source cannot stop its provider's clients: its sink refuses a
    // terminal failure, and the exception is reported as retryable instead.
    std::atomic<int> fetches{0};
    questdb::refreshing_token_provider_options options;
    options.cold_wait = 50ms;
    auto provider = questdb::token_provider::refreshing(
        [&fetches]() -> questdb::expiring_token {
            ++fetches;
            throw questdb::error{
                questdb::error_code::invalid_api_call, "source retired"};
        },
        options);
    const auto deadline = std::chrono::steady_clock::now() + 10s;
    while (fetches.load() == 0 && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(1ms);
    REQUIRE(fetches.load() > 0);
    try
    {
        (void)provider.token();
        FAIL("expected a failure");
    }
    catch (const questdb::error& e)
    {
        CHECK(
            std::string{e.what()}.find("source retired") != std::string::npos);
        const auto& classification = e.token_unavailable_diagnostic();
        REQUIRE(classification.has_value());
        CHECK(classification->retryable);
    }
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

TEST_CASE("A refused provider's source is freed exactly once")
{
    // The library leaves the source of a provider it refuses with the caller:
    // a leak would keep `witness` shared, and a double free would crash.
    const auto witness = std::make_shared<int>(0);
    questdb::refreshing_token_provider_options options;
    options.backoff_initial = 0ms;
    CHECK_THROWS_AS(
        questdb::token_provider::refreshing(
            [witness] {
                return questdb::expiring_token{
                    "unused", std::chrono::system_clock::now() + 1h};
            },
            options),
        questdb::error);
    CHECK(witness.use_count() == 1);
}

namespace
{
class counting_provider : public questdb::bearer_token_provider
{
public:
    explicit counting_provider(std::string token)
        : _token{std::move(token)}
    {
    }

    std::string token() override
    {
        ++calls;
        return _token;
    }

    std::atomic<int> calls{0};

private:
    std::string _token;
};
} // namespace

TEST_CASE("A token that is not UTF-8 fails with its reason")
{
    auto app = std::make_shared<counting_provider>("\xff\xfetok");
    auto provider = questdb::token_provider::from(app);
    try
    {
        (void)provider.token();
        FAIL("a token that is not UTF-8 was served");
    }
    catch (const questdb::error& e)
    {
        CHECK(
            std::string{e.what()}.find("not valid UTF-8") != std::string::npos);
    }

    // As for any unusable token, a connect the caller waits for ends at once
    // rather than pulling the provider until its budget runs out.
    auto opts = questdb::ingress::opts::from_conf(
        "ws::addr=127.0.0.1:1;initial_connect_retry=sync;"
        "reconnect_max_duration_millis=3000;");
    opts.token_provider(provider);
    app->calls = 0;
    try
    {
        questdb::ingress::line_sender sender{opts};
        FAIL("the sender connected without a usable token");
    }
    catch (const questdb::ingress::line_sender_error& e)
    {
        CHECK(
            std::string{e.what()}.find("not valid UTF-8") != std::string::npos);
    }
    CHECK(app->calls.load() == 1);
}
