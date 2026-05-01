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
 ******************************************************************************/

// Broker-independent tests for the line_reader FFI.
//
// Covers the error-handling and configuration surface that does not need a
// running QuestDB instance: parser rejection paths, connect-failure error
// codes, the C error accessor functions, the C++ `line_reader_error`
// wrapper, NULL-idempotency of every `_free` / `_close` entry point, and
// the `from_env` env-var lookup. Complements `test_line_reader.cpp`, which
// covers the live-broker round-trip surface and skips entirely without a
// broker. CI runs both — together they verify symbol resolution, the error
// path, and the connect path even when no broker is reachable.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <questdb/egress/line_reader.h>
#include <questdb/egress/line_reader.hpp>

#include <cstdlib>
#include <cstring>
#include <string>

#ifdef _WIN32
#include <stdlib.h>
static int set_env(const char* name, const char* value)
{
    return _putenv_s(name, value);
}
static int unset_env(const char* name) { return _putenv_s(name, ""); }
#else
#include <stdlib.h>
static int set_env(const char* name, const char* value)
{
    return setenv(name, value, 1);
}
static int unset_env(const char* name) { return unsetenv(name); }
#endif

using namespace questdb::ingress::literals;

namespace
{

// Connect target that is virtually never bound on a developer machine —
// 127.0.0.1:1 is in the system reserved range and rejects connections
// fast on every supported platform.
constexpr const char* CLOSED_PORT_CONF = "qwp::addr=127.0.0.1:1;";

} // namespace

// ---------------------------------------------------------------------------
// NULL-idempotent free / close (every documented "idempotent on NULL" path).
// ---------------------------------------------------------------------------

TEST_CASE("free / close functions are NULL-idempotent")
{
    // None of these should crash; a regression that drops the NULL guard
    // would SIGSEGV here and fail the test rather than silently passing.
    line_reader_error_free(nullptr);
    line_reader_close(nullptr);
    line_reader_query_free(nullptr);
    line_reader_cursor_free(nullptr);
}

TEST_CASE("error accessors are NULL-safe (M-13)")
{
    // _get_code on NULL must not crash — returns a sentinel code.
    const auto code = line_reader_error_get_code(nullptr);
    CHECK(code == line_reader_error_invalid_api_call);

    // _msg on NULL must return a non-NULL empty string and zero out len.
    size_t len = 999;
    const char* msg = line_reader_error_msg(nullptr, &len);
    REQUIRE(msg != nullptr);
    CHECK(len == 0);
    CHECK(msg[0] == '\0');

    // _msg with a NULL len_out must also be safe (the function's
    // documented promise is "never returns NULL", and len_out is now
    // optional).
    msg = line_reader_error_msg(nullptr, nullptr);
    REQUIRE(msg != nullptr);
}

// ---------------------------------------------------------------------------
// `line_reader_from_conf` rejection paths — exercise the ConfigError surface.
// ---------------------------------------------------------------------------

TEST_CASE("from_conf rejects malformed config strings as ConfigError")
{
    struct case_t
    {
        const char* conf;
        const char* what;
    };
    const case_t cases[] = {
        {"", "empty config"},
        {"qwp::", "missing addr key"},
        {"unknown_scheme::addr=127.0.0.1:9000;", "unknown scheme"},
        {"qwp::addr=h:1;mystery_key=x;", "unknown parameter"},
        {"qwp::addr=h:1;username=u;password=p;token=t;",
         "conflicting auth parameters"},
        {"qwp::addr=h:notaport;", "non-numeric port"},
        {"qwp::addr=h:1;compression=xyz;", "invalid compression value"},
        {"qwp::addr=h:1;target=leader;", "invalid target value"},
    };

    for (const auto& c : cases)
    {
        CAPTURE(c.what);
        line_reader_error* err = nullptr;
        line_sender_utf8 conf{strlen(c.conf), c.conf};
        line_reader* r = line_reader_from_conf(conf, &err);
        REQUIRE(r == nullptr);
        REQUIRE(err != nullptr);
        CHECK(line_reader_error_get_code(err) ==
              line_reader_error_config_error);
        size_t msg_len = 0;
        const char* msg = line_reader_error_msg(err, &msg_len);
        CHECK(msg != nullptr);
        CHECK(msg_len > 0);
        line_reader_error_free(err);
    }
}

// ---------------------------------------------------------------------------
// Connect-failure path — exercises the FFI error allocation + error accessor
// surface against a guaranteed-closed port. The exact error code may vary
// across platforms (could_not_resolve_addr / socket_error / handshake_error),
// so we accept any of the connection-related codes rather than pinning one.
// ---------------------------------------------------------------------------

TEST_CASE("from_conf surfaces a connect-time error against a closed port")
{
    line_reader_error* err = nullptr;
    line_sender_utf8 conf{strlen(CLOSED_PORT_CONF), CLOSED_PORT_CONF};
    line_reader* r = line_reader_from_conf(conf, &err);
    REQUIRE(r == nullptr);
    REQUIRE(err != nullptr);

    const auto code = line_reader_error_get_code(err);
    const bool is_connect_failure =
        code == line_reader_error_socket_error ||
        code == line_reader_error_could_not_resolve_addr ||
        code == line_reader_error_handshake_error ||
        code == line_reader_error_tls_error;
    CHECK(is_connect_failure);

    size_t msg_len = 0;
    const char* msg = line_reader_error_msg(err, &msg_len);
    REQUIRE(msg != nullptr);
    CHECK(msg_len > 0);
    line_reader_error_free(err);
}

// ---------------------------------------------------------------------------
// `line_reader_from_env` — env var lookup + delegation to from_conf.
// ---------------------------------------------------------------------------

TEST_CASE("from_env returns ConfigError when QDB_CLIENT_CONF is unset")
{
    REQUIRE(unset_env("QDB_CLIENT_CONF") == 0);

    line_reader_error* err = nullptr;
    line_reader* r = line_reader_from_env(&err);
    REQUIRE(r == nullptr);
    REQUIRE(err != nullptr);
    CHECK(line_reader_error_get_code(err) ==
          line_reader_error_config_error);

    size_t msg_len = 0;
    const char* msg = line_reader_error_msg(err, &msg_len);
    REQUIRE(msg != nullptr);
    CHECK(msg_len > 0);
    line_reader_error_free(err);
}

TEST_CASE("from_env propagates parser errors when QDB_CLIENT_CONF is malformed")
{
    REQUIRE(set_env("QDB_CLIENT_CONF", "not_a_valid_config_string") == 0);

    line_reader_error* err = nullptr;
    line_reader* r = line_reader_from_env(&err);
    REQUIRE(r == nullptr);
    REQUIRE(err != nullptr);
    CHECK(line_reader_error_get_code(err) ==
          line_reader_error_config_error);
    line_reader_error_free(err);

    REQUIRE(unset_env("QDB_CLIENT_CONF") == 0);
}

#ifndef _WIN32
TEST_CASE("from_env distinguishes invalid-UTF-8 env value from unset")
{
    // POSIX setenv accepts arbitrary bytes (it's not utf-8-aware), so we
    // can plant a stray 0x80 continuation byte directly. Skipped on
    // Windows because _putenv_s takes a UTF-8 string and won't store
    // invalid bytes — there's no portable way to reproduce the
    // VarError::NotUnicode path there.
    REQUIRE(setenv("QDB_CLIENT_CONF", "qwp::addr=h:1\xC3\x28", 1) == 0);

    line_reader_error* err = nullptr;
    line_reader* r = line_reader_from_env(&err);
    REQUIRE(r == nullptr);
    REQUIRE(err != nullptr);
    // Previously this collapsed to "not set" (ConfigError); the M-10 fix
    // surfaces the actual cause as InvalidUtf8.
    CHECK(line_reader_error_get_code(err) ==
          line_reader_error_invalid_utf8);
    line_reader_error_free(err);

    REQUIRE(unset_env("QDB_CLIENT_CONF") == 0);
}
#endif

TEST_CASE("from_env reaches the connect path when QDB_CLIENT_CONF is parseable")
{
    REQUIRE(set_env("QDB_CLIENT_CONF", CLOSED_PORT_CONF) == 0);

    line_reader_error* err = nullptr;
    line_reader* r = line_reader_from_env(&err);
    CHECK(r == nullptr);
    REQUIRE(err != nullptr);
    // We don't pin the code — connect-failure shape varies — but it must
    // NOT be ConfigError, since the config parsed successfully.
    CHECK(line_reader_error_get_code(err) !=
          line_reader_error_config_error);
    line_reader_error_free(err);

    REQUIRE(unset_env("QDB_CLIENT_CONF") == 0);
}

// ---------------------------------------------------------------------------
// C++ wrapper: `line_reader_error` exception type.
// ---------------------------------------------------------------------------

TEST_CASE("C++ wrapper converts C error to thrown line_reader_error")
{
    using questdb::egress::line_reader_error;
    using questdb::egress::reader;

    bool threw = false;
    try
    {
        reader r{"qwp::"_utf8}; // missing addr → ConfigError
        (void)r;
    }
    catch (const line_reader_error& e)
    {
        threw = true;
        CHECK(e.code() == line_reader_error_config_error);
        CHECK(std::strlen(e.what()) > 0);
        // Must be catchable as the C++ standard exception base too.
        const std::exception& base = e;
        CHECK(std::strlen(base.what()) > 0);
    }
    CHECK(threw);
}

TEST_CASE("C++ wrapper from_env throws ConfigError when var is unset")
{
    using questdb::egress::line_reader_error;
    using questdb::egress::reader;

    REQUIRE(unset_env("QDB_CLIENT_CONF") == 0);

    bool threw = false;
    try
    {
        auto r = reader::from_env();
        (void)r;
    }
    catch (const line_reader_error& e)
    {
        threw = true;
        CHECK(e.code() == line_reader_error_config_error);
    }
    CHECK(threw);
}

TEST_CASE("C++ wrapper from_env throws connect-time error for closed port")
{
    using questdb::egress::line_reader_error;
    using questdb::egress::reader;

    REQUIRE(set_env("QDB_CLIENT_CONF", CLOSED_PORT_CONF) == 0);

    bool threw = false;
    try
    {
        auto r = reader::from_env();
        (void)r;
    }
    catch (const line_reader_error& e)
    {
        threw = true;
        CHECK(e.code() != line_reader_error_config_error);
    }
    CHECK(threw);

    REQUIRE(unset_env("QDB_CLIENT_CONF") == 0);
}

// ---------------------------------------------------------------------------
// Defensive: error accessors against repeated reads.
// ---------------------------------------------------------------------------

TEST_CASE("line_reader_error_msg is stable across repeated reads")
{
    line_reader_error* err = nullptr;
    line_sender_utf8 conf{0, ""};
    line_reader* r = line_reader_from_conf(conf, &err);
    REQUIRE(r == nullptr);
    REQUIRE(err != nullptr);

    size_t len_a = 0;
    const char* msg_a = line_reader_error_msg(err, &len_a);
    REQUIRE(msg_a != nullptr);

    // Reading the message a second time returns the same pointer and
    // length — borrowed view, not a fresh allocation.
    size_t len_b = 0;
    const char* msg_b = line_reader_error_msg(err, &len_b);
    CHECK(msg_a == msg_b);
    CHECK(len_a == len_b);

    line_reader_error_free(err);
}

TEST_CASE("line_reader_error_get_code is stable across repeated reads")
{
    line_reader_error* err = nullptr;
    line_sender_utf8 conf{0, ""};
    line_reader* r = line_reader_from_conf(conf, &err);
    REQUIRE(r == nullptr);
    REQUIRE(err != nullptr);

    const auto code_a = line_reader_error_get_code(err);
    const auto code_b = line_reader_error_get_code(err);
    CHECK(code_a == code_b);

    line_reader_error_free(err);
}

TEST_CASE("from_conf rejects invalid UTF-8 with InvalidUtf8")
{
    // Hand-rolled line_sender_utf8 carrying a stray 0x80 continuation byte
    // — the C struct has no encapsulation, so a buggy caller can bypass
    // line_sender_utf8_init. The FFI re-validates and surfaces a clean
    // InvalidUtf8 error instead of letting upstream walk an invalid &str.
    static const unsigned char bad[] = {'q', 'w', 'p', ':', ':', 0x80, 0x00};
    line_sender_utf8 conf{6, reinterpret_cast<const char*>(bad)};
    line_reader_error* err = nullptr;
    line_reader* r = line_reader_from_conf(conf, &err);
    REQUIRE(r == nullptr);
    REQUIRE(err != nullptr);
    CHECK(line_reader_error_get_code(err) == line_reader_error_invalid_utf8);
    size_t len = 0;
    const char* msg = line_reader_error_msg(err, &len);
    CHECK(len > 0);
    CHECK(msg != nullptr);
    line_reader_error_free(err);
}
