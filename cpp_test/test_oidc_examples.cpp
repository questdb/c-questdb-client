#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#define QUESTDB_OIDC_CPP_TEST_HOOKS
#if defined(_WIN32) && !defined(NOMINMAX)
#    define NOMINMAX
#endif
#include "doctest.h"

#include <cstdio>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>

#ifdef _WIN32
#    include <windows.h>
#endif

// Exercise the actual example handlers, not a copy of their output logic.
#define main oidc_c_example_main
#include "../examples/oidc_c_example.c"
#undef main
#define main oidc_cpp_example_main
#include "../examples/oidc_cpp_example.cpp"
#undef main

static std::string c_prompt(const questdb_oidc_event& event)
{
    FILE* file = nullptr;
#ifdef _WIN32
    // tmpfile_s uses the drive root and may require administrator rights.
    // Create the capture in the user's temp directory; D deletes it on close.
    wchar_t directory[MAX_PATH];
    wchar_t path[MAX_PATH];
    const auto length = GetTempPathW(MAX_PATH, directory);
    REQUIRE(length > 0);
    REQUIRE(length < MAX_PATH);
    REQUIRE(GetTempFileNameW(directory, L"qdb", 0, path) != 0);
    const auto error = _wfopen_s(&file, path, L"w+bD");
    if (error != 0)
        DeleteFileW(path);
    REQUIRE(error == 0);
#else
    file = std::tmpfile();
#endif
    // A lambda avoids putting glibc's attributed fclose type in a template.
    auto close_file = [](FILE* stream) {
        std::fclose(stream);
    };
    std::unique_ptr<FILE, decltype(close_file)> output{file, close_file};
    REQUIRE(output != nullptr);
    oidc_event(output.get(), &event);
    std::fflush(output.get());
    std::rewind(output.get());
    std::string text;
    char buffer[512];
    while (const auto count =
               std::fread(buffer, 1, sizeof buffer, output.get()))
        text.append(buffer, count);
    return text;
}

static std::string cpp_prompt(const questdb_oidc_event& event)
{
    std::ostringstream output;
    std::function<void(const questdb::oidc::event_view&)> handler =
        [&](const questdb::oidc::event_view& view) {
            oidc_cpp_event(view, output);
        };
    questdb::oidc::builder::test_invoke_event_handler(handler, &event);
    return output.str();
}

TEST_CASE("OIDC examples omit refused display URLs and retain vetted targets")
{
    questdb_oidc_event event{};
    event.struct_size = sizeof event;
    event.kind = QUESTDB_OIDC_EVENT_PROMPT;
    event.user_code = "CODE";
    event.user_code_len = 4;
    event.expires_in_seconds = 600;
    event.interval_seconds = 5;
    for (const auto refused :
         {"https://xn--80ak6aa92e.com/device",
          "HTTPS://xn--80ak6aa92e.com/device",
          "HtTpS://user@idp.example/device",
          "http://idp.example/device"})
    {
        event.verification_uri = refused;
        event.verification_uri_len = std::char_traits<char>::length(refused);
        for (const auto& shown : {c_prompt(event), cpp_prompt(event)})
        {
            CHECK(shown.find(refused) == std::string::npos);
            CHECK(shown.find("CODE") != std::string::npos);
            CHECK(shown.find("No vetted browser target") != std::string::npos);
        }
    }
    constexpr std::string_view target{"https://idp.example/activate"};
    event.browser_target = target.data();
    event.browser_target_len = target.size();
    for (const auto& shown : {c_prompt(event), cpp_prompt(event)})
    {
        CHECK(shown.find(target) != std::string::npos);
        CHECK(shown.find("Open ") != std::string::npos);
        CHECK(shown.find("CODE") != std::string::npos);
    }
}
