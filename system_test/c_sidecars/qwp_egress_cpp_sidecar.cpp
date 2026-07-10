/*
 * Out-of-process QWP egress (read-side) client driven by a line-oriented
 * stdin/stdout protocol, implemented against the c-questdb-client *C++*
 * reader wrapper (`include/questdb/egress/reader.hpp`).
 *
 * Unlike the ingress C++ sidecar (which must fall back to the C ABI because
 * the C++ wrapper has no row-major QWP-WS surface), the egress wrapper is a
 * genuine C++ API: this translation unit drives `questdb::egress::reader`,
 * `cursor` and `batch` directly, with `questdb::error` exceptions mapped onto
 * the wire protocol's ERR replies. That is the c_client_cpp egress signal:
 * the QWP reader works through the real C++ classes.
 *
 * Same protocol subset as `qwp_egress_c_sidecar.c` (see that file's header
 * comment for the verb table and the SERVER_INFO / SHOW_ZONE caveats --
 * the C++ wrapper surfaces the same accessors as the C API, so it too has
 * no zone string).
 *
 * The standalone `reader{conf}` constructor gives each CONNECT command one
 * dedicated transport, matching the Rust sidecar's `Reader::from_conf`.
 */

#include <questdb/egress/reader.hpp>

#include <chrono>
#include <cstdio>
#include <exception>
#include <iostream>
#include <optional>
#include <string>

/* CAP_ZONE bit (questdb-rs/src/egress/wire/capabilities.rs). */
static constexpr uint32_t QDB_CAP_ZONE = 0x00000001u;

namespace
{

std::optional<questdb::egress::reader> g_reader;

/* Newlines in an ERR message would break the line-based protocol; match the
 * other sidecars' substitution: CR -> space, LF -> '|'. */
void reply_err(const std::string& msg)
{
    std::string sanitized;
    sanitized.reserve(msg.size());
    for (char c : msg)
    {
        if (c == '\r')
            sanitized.push_back(' ');
        else if (c == '\n')
            sanitized.push_back('|');
        else
            sanitized.push_back(c);
    }
    std::cout << "ERR " << sanitized << '\n' << std::flush;
}

void reply_ok(const std::string& payload = {})
{
    if (payload.empty())
        std::cout << "OK\n" << std::flush;
    else
        std::cout << "OK " << payload << '\n' << std::flush;
}

void handle_connect(const std::string& rest)
{
    /* CONNECT replaces any active reader; the bind is EAGER (the ctor walks
     * the address list with the target/zone filter applied), so a role
     * mismatch surfaces as ERR here -- same semantics as the C and Rust
     * egress sidecars. */
    g_reader.reset();
    g_reader.emplace(questdb::ingress::utf8_view{rest});
    reply_ok();
}

void handle_query(const std::string& rest)
{
    if (!g_reader)
    {
        reply_err("no reader");
        return;
    }
    const auto t0 = std::chrono::steady_clock::now();
    questdb::egress::cursor cur =
        g_reader->execute(questdb::ingress::utf8_view{rest});
    unsigned long long rows = 0;
    while (auto batch = cur.next_batch())
        rows += static_cast<unsigned long long>(batch->row_count());
    const double latency_ms =
        std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - t0)
            .count();
    char payload[64];
    std::snprintf(payload, sizeof(payload), "%llu %.3f", rows, latency_ms);
    reply_ok(payload);
}

void handle_server_info()
{
    if (!g_reader)
    {
        reply_err("no reader");
        return;
    }
    /* In-memory snapshot from the most recent bind; no SQL round-trip. */
    const questdb::egress::server_info_view info = g_reader->server_info();
    if (!info)
    {
        reply_ok("role=-1 cap_zone=0");
        return;
    }
    char payload[64];
    std::snprintf(payload, sizeof(payload), "role=%u cap_zone=%d",
                  static_cast<unsigned>(info.role_byte()),
                  (info.capabilities() & QDB_CAP_ZONE) != 0 ? 1 : 0);
    reply_ok(payload);
}

} // namespace

int main()
{
    /* READY tells the harness the main loop is up before any command. */
    std::cout << "READY\n" << std::flush;

    std::string line;
    while (std::getline(std::cin, line))
    {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            line.pop_back();
        if (line.empty())
            continue;

        std::string verb = line;
        std::string rest;
        if (const auto sp = line.find(' '); sp != std::string::npos)
        {
            verb = line.substr(0, sp);
            rest = line.substr(line.find_first_not_of(' ', sp));
        }

        try
        {
            if (verb == "CONNECT")
                handle_connect(rest);
            else if (verb == "QUERY")
                handle_query(rest);
            else if (verb == "SERVER_INFO")
                handle_server_info();
            else if (verb == "SHOW_ZONE" || verb == "QUERY_ROW")
                reply_err("unsupported verb in the C++ egress sidecar (needs "
                          "string column extraction; extend "
                          "qwp_egress_cpp_sidecar.cpp)");
            else if (verb == "CLOSE")
            {
                g_reader.reset();
                reply_ok();
            }
            else if (verb == "EXIT")
            {
                g_reader.reset();
                return 0;
            }
            else
                reply_err("unknown verb: " + verb);
        }
        catch (const std::exception& e)
        {
            reply_err(e.what());
        }
    }

    g_reader.reset();
    return 0;
}
