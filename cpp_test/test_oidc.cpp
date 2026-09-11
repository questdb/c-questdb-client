#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <questdb/client.hpp>
#include <questdb/egress/qwp_reader.hpp>
#include <questdb/ingress/line_sender.hpp>

#include <cstdint>
#include <memory>
#include <string_view>
#include <type_traits>
#include <utility>

template <typename T, typename = void>
struct has_oidc_token_view : std::false_type
{
};

template <typename T>
struct has_oidc_token_view<T, std::void_t<decltype(std::declval<T>().view())>>
    : std::true_type
{
};

template <typename T, typename = void>
struct has_oidc_config : std::false_type
{
};

template <typename T>
struct has_oidc_config<T, std::void_t<decltype(std::declval<T>().config())>>
    : std::true_type
{
};

template <typename T, typename = void>
struct has_oidc_c_ptr : std::false_type
{
};

template <typename T>
struct has_oidc_c_ptr<T, std::void_t<decltype(std::declval<T>().c_ptr())>>
    : std::true_type
{
};

template <typename T, typename = void>
struct has_oidc_auth_token : std::false_type
{
};

template <typename T>
struct has_oidc_auth_token<T, std::void_t<decltype(std::declval<T>().token())>>
    : std::true_type
{
};

template <typename T, typename = void>
struct has_oidc_access_token : std::false_type
{
};

template <typename T>
struct has_oidc_access_token<
    T,
    std::void_t<decltype(std::declval<T>().access_token())>> : std::true_type
{
};

static_assert(has_oidc_token_view<const questdb::oidc::token&>::value);
static_assert(!has_oidc_token_view<questdb::oidc::token&&>::value);
static_assert(has_oidc_config<const questdb::oidc::device_auth&>::value);
static_assert(!has_oidc_config<questdb::oidc::device_auth&&>::value);
static_assert(has_oidc_c_ptr<const questdb::oidc::device_auth&>::value);
static_assert(!has_oidc_c_ptr<questdb::oidc::device_auth&&>::value);
static_assert(has_oidc_auth_token<const questdb::oidc::device_auth&>::value);
static_assert(!has_oidc_access_token<const questdb::oidc::device_auth&>::value);
static_assert(
    std::is_same_v<
        decltype(std::declval<const questdb::oidc::device_auth&>().token()),
        questdb::oidc::token>);

static_assert(!std::is_copy_constructible_v<questdb::oidc::event_view>);
static_assert(!std::is_copy_assignable_v<questdb::oidc::event_view>);
static_assert(!std::is_move_constructible_v<questdb::oidc::event_view>);
static_assert(!std::is_move_assignable_v<questdb::oidc::event_view>);

TEST_CASE("OIDC C++ wrappers preserve ownership and structured errors")
{
    bool empty_handler_rejected = false;
    try
    {
        questdb::oidc::builder{}.event_handler({});
    }
    catch (const questdb::error& error)
    {
        empty_handler_rejected = true;
        CHECK(error.code() == questdb::error_code::invalid_api_call);
    }
    CHECK(empty_handler_rejected);

    bool saw_structured_error = false;
    try
    {
        (void)questdb::oidc::builder{}.build();
    }
    catch (const questdb::oidc::error& error)
    {
        saw_structured_error = true;
        CHECK(error.kind() == questdb::oidc::error_kind::config);
        CHECK(error.code() == questdb::error_code::config_error);
    }
    CHECK(saw_structured_error);

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
        CHECK(error.kind() == questdb::oidc::error_kind::config);
    }
    ::questdb_oidc_builder_free(raw_builder);
    CHECK(generic_wrapper_saw_structured_error);

    auto builder = questdb::oidc::builder{};
    builder.client_id("questdb-cpp")
        .scope("openid profile")
        .token_endpoint("https://idp.example/token")
        .device_authorization_endpoint("https://idp.example/device")
        .groups_in_token(true);
    auto auth = builder.build();
    // An additional handle is taken explicitly. The copy constructor is
    // deleted: `questdb_oidc_auth_clone` aliases one shared provider rather
    // than duplicating it, so a value-shaped copy would let `clear()` on the
    // "copy" delete the credential the original's transports are using.
    static_assert(
        !std::is_copy_constructible<questdb::oidc::device_auth>::value);
    static_assert(!std::is_copy_assignable<questdb::oidc::device_auth>::value);
    auto shared_auth = auth.share();
    const auto config = shared_auth.config();
    CHECK(config.client_id == std::string_view{"questdb-cpp"});
    CHECK(config.scope == std::string_view{"openid profile"});
    CHECK(config.groups_in_token);
    // Both handles address the same provider.
    CHECK(shared_auth.c_ptr() != auth.c_ptr());
    CHECK(shared_auth.config().client_id == auth.config().client_id);

    auto moved_auth = std::move(auth);
    CHECK_THROWS_AS(auth.share(), questdb::oidc::error);
    CHECK_THROWS_AS(auth.sign_in(), questdb::oidc::error);
    CHECK_THROWS_AS(auth.token(), questdb::oidc::error);
    CHECK_THROWS_AS(auth.clear(), questdb::oidc::error);
    CHECK_THROWS_AS(auth.config(), questdb::oidc::error);
    // Move-assignment from a moved-from handle is still well defined; the
    // previous copy-assignment check is covered by `auth.share()` above, which
    // is now the only way to take another handle.
    shared_auth = std::move(moved_auth);
    CHECK_THROWS_AS(moved_auth.config(), questdb::oidc::error);
    CHECK_THROWS_AS(
        (questdb::pool{"ws::addr=127.0.0.1:1;lazy_connect=true;", auth}),
        questdb::oidc::error);

    auto moved_from_sender_options =
        questdb::ingress::opts::from_conf("https::addr=127.0.0.1:1;");
    CHECK_THROWS_AS(
        moved_from_sender_options.oidc_auth(auth), questdb::oidc::error);
    CHECK_THROWS_AS(
        (questdb::egress::reader{"ws::addr=127.0.0.1:1;", auth}),
        questdb::oidc::error);

    // `shared_auth` is the only live handle left: `auth` was moved from above,
    // and `moved_auth` was moved into `shared_auth`. Everything from here on
    // is a POSITIVE case, so it must use the live one -- passing an emptied
    // handle makes `device_auth::raw()` throw before the call under test even
    // runs, which aborts the rest of this case.
    auto sender_options =
        questdb::ingress::opts::from_conf("https::addr=127.0.0.1:1;");
    CHECK_NOTHROW(sender_options.oidc_auth(shared_auth));

    auto unsupported_sender_options =
        questdb::ingress::opts::from_conf("tcp::addr=127.0.0.1:1;");
    try
    {
        unsupported_sender_options.oidc_auth(shared_auth);
        FAIL("unsupported sender OIDC attachment must throw");
    }
    catch (const questdb::ingress::line_sender_error& error)
    {
        CHECK_FALSE(error.oidc_diagnostic().has_value());
    }

    // A failure raised by an auth state attached to a normal sender remains in
    // the sender exception hierarchy while retaining the structured OIDC
    // diagnostic. Existing applications that catch only line_sender_error must
    // not miss refresh or InteractionRequired failures.
    // Even an auth configured to permit interactive sign-in must never start a
    // prompt from a sender operation. The unreachable loopback IdP would yield
    // a network error if flush accidentally attempted the device flow.
    auto attached_builder = questdb::oidc::builder{};
    attached_builder.client_id("questdb-cpp")
        .scope("openid")
        .token_endpoint("http://127.0.0.1:1/token")
        .device_authorization_endpoint("http://127.0.0.1:1/device")
        .interactive(true);
    auto attached_auth = attached_builder.build();
    auto attached_options =
        questdb::ingress::opts::from_conf("http::addr=127.0.0.1:1;");
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
    catch (const questdb::ingress::line_sender_error& error)
    {
        attached_sender_saw_structured_error = true;
        REQUIRE(error.oidc_diagnostic().has_value());
        CHECK(
            error.oidc_diagnostic()->kind() ==
            questdb::oidc::error_kind::interaction_required);
        CHECK(error.oidc_diagnostic()->code() == error.code());
    }
    CHECK(attached_sender_saw_structured_error);

    // Lazy construction performs no network I/O, but exercises ownership and
    // the shared sender/reader provider configuration in the pool FFI.
    questdb::pool pool{"ws::addr=127.0.0.1:1;lazy_connect=true;", shared_auth};
}

TEST_CASE("OIDC C++ event handler ownership is released exactly once")
{
    // The C++ shim's ownership contract had no coverage: the case above only
    // checks that an EMPTY std::function is rejected, so nothing exercised
    // whether the caller's captured state is released, leaked, or released
    // twice. A leak strands it for the process; a double release is a
    // use-after-free.
    //
    // Only the exactly-once property is asserted. WHEN the release happens --
    // observed here at builder destruction rather than at replacement -- is an
    // implementation detail the header does not promise, so pinning it would
    // make this brittle.
    //
    // What is NOT covered here, and cannot be from C++ without a live identity
    // provider, is invoking the callback: the trampoline's catch(...)
    // containment and the struct_size guards on the appended event fields are
    // exercised only by the Rust-side tests, which drive a real flow.
    static int releases = 0;
    releases = 0;

    struct tracker
    {
        ~tracker()
        {
            ++releases;
        }
    };

    {
        questdb::oidc::builder builder{};
        auto owned = std::make_shared<tracker>();
        builder.event_handler(
            [owned](const questdb::oidc::event_view&) noexcept {});
        // The registration owns a copy, so the caller's handle is not the last.
        CHECK(owned.use_count() == 2);
        CHECK(releases == 0);

        // Replacing the handler must not release the first capture twice, nor
        // lose track of it.
        builder.event_handler([](const questdb::oidc::event_view&) noexcept {});
        CHECK(releases <= 1);
    }
    // Exactly one release for the one capturing handler: no leak, no double.
    CHECK(releases == 1);
}
