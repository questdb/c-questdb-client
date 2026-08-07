#include <questdb/client.hpp>
#include <questdb/egress/qwp_reader.hpp>
#include <questdb/ingress/line_sender.hpp>

#include <cassert>
#include <cstdint>
#include <string_view>
#include <type_traits>

using oidc_token_view_member =
    std::string_view (questdb::oidc::token::*)() const & noexcept;
using oidc_config_member =
    questdb::oidc::config_view (questdb::oidc::device_auth::*)() const & noexcept;
using oidc_c_ptr_member =
    const questdb_oidc_auth* (questdb::oidc::device_auth::*)() const & noexcept;

[[maybe_unused]] constexpr auto oidc_token_view =
    static_cast<oidc_token_view_member>(&questdb::oidc::token::view);
[[maybe_unused]] constexpr auto oidc_config =
    static_cast<oidc_config_member>(&questdb::oidc::device_auth::config);
[[maybe_unused]] constexpr auto oidc_c_ptr =
    static_cast<oidc_c_ptr_member>(&questdb::oidc::device_auth::c_ptr);

static_assert(std::is_invocable_v<
              decltype(oidc_token_view),
              const questdb::oidc::token&>);
static_assert(!std::is_invocable_v<
              decltype(oidc_token_view),
              questdb::oidc::token&&>);
static_assert(std::is_invocable_v<
              decltype(oidc_config),
              const questdb::oidc::device_auth&>);
static_assert(!std::is_invocable_v<
              decltype(oidc_config),
              questdb::oidc::device_auth&&>);
static_assert(std::is_invocable_v<
              decltype(oidc_c_ptr),
              const questdb::oidc::device_auth&>);
static_assert(!std::is_invocable_v<
              decltype(oidc_c_ptr),
              questdb::oidc::device_auth&&>);

static_assert(!std::is_copy_constructible_v<questdb::oidc::event_view>);
static_assert(!std::is_copy_assignable_v<questdb::oidc::event_view>);
static_assert(!std::is_move_constructible_v<questdb::oidc::event_view>);
static_assert(!std::is_move_assignable_v<questdb::oidc::event_view>);

int main()
{
    bool empty_handler_rejected = false;
    try
    {
        questdb::oidc::builder{}.event_handler({});
    }
    catch (const questdb::error& error)
    {
        empty_handler_rejected = true;
        assert(error.code() == questdb::error_code::invalid_api_call);
    }
    assert(empty_handler_rejected);

    bool saw_structured_error = false;
    try
    {
        (void)questdb::oidc::builder{}.build();
    }
    catch (const questdb::oidc::error& error)
    {
        saw_structured_error = true;
        assert(error.kind() == questdb::oidc::error_kind::config);
        assert(error.code() == questdb::error_code::config_error);
    }
    assert(saw_structured_error);

    // The client-wide wrapper must also retain the dynamic OIDC type. Reader
    // and pool operations use this path rather than the OIDC builder helper.
    auto* raw_builder = ::questdb_oidc_builder_new();
    bool generic_wrapper_saw_structured_error = false;
    try
    {
        (void)questdb::error::wrapped_call(
            ::questdb_oidc_builder_build, raw_builder);
    }
    catch (const questdb::oidc::error& error)
    {
        generic_wrapper_saw_structured_error = true;
        assert(error.kind() == questdb::oidc::error_kind::config);
    }
    ::questdb_oidc_builder_free(raw_builder);
    assert(generic_wrapper_saw_structured_error);

    auto builder = questdb::oidc::builder{};
    builder.client_id("questdb-cpp")
        .scope("openid profile")
        .token_endpoint("https://idp.example/token")
        .device_authorization_endpoint("https://idp.example/device");
    auto auth = builder.build();
    auto copied_auth = auth;
    const auto config = copied_auth.config();
    assert(config.client_id == std::string_view{"questdb-cpp"});
    assert(config.scope == std::string_view{"openid profile"});

    auto sender_options = questdb::ingress::opts::from_conf(
        "https::addr=127.0.0.1:1;");
    sender_options.oidc_auth(auth);

    // A failure raised by an auth state attached to a normal sender must pass
    // through line_sender_error's conversion without being sliced to the
    // generic sender exception.
    // Even an auth configured to permit interactive sign-in must never start a
    // prompt from a sender operation. The unreachable loopback IdP would yield a
    // network error if flush accidentally attempted the device flow.
    auto attached_builder = questdb::oidc::builder{};
    attached_builder.client_id("questdb-cpp")
        .scope("openid")
        .token_endpoint("http://127.0.0.1:1/token")
        .device_authorization_endpoint("http://127.0.0.1:1/device")
        .interactive(true);
    auto attached_auth = attached_builder.build();
    auto attached_options = questdb::ingress::opts::from_conf(
        "http::addr=127.0.0.1:1;");
    attached_options.protocol_version(questdb::ingress::protocol_version::v1)
        .oidc_auth(attached_auth);
    questdb::ingress::line_sender attached_sender{attached_options};
    auto buffer = attached_sender.new_buffer();
    buffer.table("oidc_test").column("value", int64_t{1}).at_now();

    bool attached_sender_saw_structured_error = false;
    try
    {
        attached_sender.flush(buffer);
    }
    catch (const questdb::oidc::error& error)
    {
        attached_sender_saw_structured_error = true;
        assert(
            error.kind() ==
            questdb::oidc::error_kind::interaction_required);
    }
    assert(attached_sender_saw_structured_error);

    // Lazy construction performs no network I/O, but exercises ownership and
    // the shared sender/reader provider configuration in the pool FFI.
    questdb::pool pool{
        "ws::addr=127.0.0.1:1;lazy_connect=true;", copied_auth};
    return 0;
}
