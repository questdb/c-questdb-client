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
 * The C++ metadata wrapper exposes the decoded SERVER_INFO zone and its
 * column API can read SHOW PARAMETERS, so both SERVER_INFO and SHOW_ZONE use
 * the full Rust-sidecar wire shape. QUERY_ROW remains outside this sidecar's
 * deliberately small verb set.
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
#include <stdexcept>
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
    try
    {
        const questdb::egress::server_info info = g_reader->server_info();
        const auto& zone = info.zone_id();
        reply_ok(
            "zone=" + (zone ? *zone : std::string{"<unset>"}) +
            " role=" + std::to_string(static_cast<unsigned>(info.role_byte())) +
            " cap_zone=" +
            std::to_string((info.capabilities() & QDB_CAP_ZONE) != 0 ? 1 : 0));
    }
    catch (const questdb::error& e)
    {
        /* Preserve the cross-binding sidecar contract for the transient
         * no-snapshot state. Product callers still receive the C++ error. */
        if (e.code() != questdb::error_code::invalid_api_call)
            throw;
        reply_ok("zone=<unset> role=-1 cap_zone=0");
    }
}

void handle_show_zone()
{
    if (!g_reader)
    {
        reply_err("no reader");
        return;
    }

    auto cur = g_reader->execute(questdb::ingress::utf8_view{
        "(SHOW PARAMETERS) WHERE property_path = 'replication.zone'"});
    std::optional<std::string> value;
    while (auto batch = cur.next_batch())
    {
        /* Always drain to the terminal frame. Dropping a part-read cursor
         * poisons the connection for the next command. */
        if (value || batch->row_count() == 0)
            continue;

        const auto value_col = batch->column_by_name("value");
        std::optional<std::string_view> cell;
        switch (value_col.kind())
        {
            case questdb::egress::column_kind::varchar:
                cell = value_col.varchar(0);
                break;
            case questdb::egress::column_kind::symbol:
                cell = value_col.symbol(0);
                break;
            default:
                throw std::runtime_error{
                    "SHOW PARAMETERS 'value' column is not a string"};
        }
        if (cell && !cell->empty())
            value.emplace(*cell);
    }
    reply_ok(value ? *value : std::string{"<unset>"});
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
            else if (verb == "SHOW_ZONE")
                handle_show_zone();
            else if (verb == "QUERY_ROW")
                reply_err("unsupported verb in the C++ egress sidecar: "
                          "QUERY_ROW rendering is not implemented");
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
