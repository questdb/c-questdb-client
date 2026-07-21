// Out-of-process QWP/WebSocket sender driven by a line-oriented stdin/stdout
// protocol, built as a C++ translation unit against the c-questdb-client C++
// distribution. Byte-for-byte the same wire protocol as the Rust, Java, and C
// sidecars, so the Enterprise pytest harness `Sidecar` driver
// (questdb-ent/e2e/lib/sidecar.py) drives it unchanged.
//
// WHY THIS LOOKS LIKE THE C SIDECAR IN C++: the c-questdb-client C++ wrapper
// (`questdb::ingress::line_sender`, included from line_sender.hpp below) has NO
// row-major QWP/WebSocket surface -- `line_sender::new_buffer()` deliberately
// throws for `ws`/`wss` senders, steering WebSocket users to the
// column-major `qwp_sender` API, and there is no public way to obtain a
// row buffer (`new_for_sender`) or the raw sender handle from the wrapper. A
// C++ user who wants the ROW-MAJOR store-and-forward path therefore drops to
// the C ABI -- which this sidecar does. The value of the c_client_cpp variant
// is exactly that signal: the C++ header compiles under C++17 and links, and
// the row-major QWP-WS durable-ack path works when driven from a C++ binary.
// (The column-major C++ surface is exercised separately by the column sidecar.)
//
// Protocol (single ASCII lines terminated by '\n'):
//   READY                                <- emitted on startup
//   CONNECT <connect_string>             -> OK | ERR <msg>
//   SEND <table> <count> <start_index>   -> OK | ERR <msg>
//   FLUSH                                -> OK <fsn> | ERR <msg>
//   AWAIT_ACKED <fsn> <timeout_ms>       -> OK true|false | ERR <msg>
//   STATS                                -> OK acked=N sent=0 ... (acked only)
//   CLOSE                                -> OK | ERR <msg>
//   EXIT                                 -> (no reply, exits 0)
//
// STATS exposes only the real `acked` (line_sender_qwpws_acked_fsn); the
// sent/acks/reconn*/serverErrors counters have no FFI wrapper, so they are
// zeroed -- the same fallback the Rust sidecar uses.

// line_sender.hpp pulls in the C ABI (the ::line_sender_* functions we use) and
// proves the C++ header itself compiles + links from this C++17 binary.
#include <questdb/ingress/line_sender.hpp>

#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>

namespace {

::line_sender* g_sender = nullptr;
::line_sender_buffer* g_buffer = nullptr;
bool g_request_durable_ack = false;

std::string sanitize(const char* msg, std::size_t len)
{
    // CR -> space, LF -> '|' so an ERR message can't break the line protocol.
    std::string out;
    out.reserve(len);
    for (std::size_t i = 0; i < len; ++i)
    {
        char c = msg[i];
        if (c == '\r')
            out += ' ';
        else if (c == '\n')
            out += '|';
        else
            out += c;
    }
    return out;
}

void reply_ok(const std::string& payload)
{
    if (payload.empty())
        std::cout << "OK\n";
    else
        std::cout << "OK " << payload << "\n";
    std::cout.flush();
}

void reply_err(const std::string& msg)
{
    std::cout << "ERR " << sanitize(msg.data(), msg.size()) << "\n";
    std::cout.flush();
}

// Consume a ::line_sender_error: emit it as ERR and free it.
void reply_err_from(::line_sender_error* err)
{
    std::size_t len = 0;
    const char* msg = ::line_sender_error_msg(err, &len);
    std::cout << "ERR " << sanitize(msg ? msg : "(null)", msg ? len : 6) << "\n";
    std::cout.flush();
    ::line_sender_error_free(err);
}

// Best-effort graceful close, swallowing errors -- mirrors the Rust sidecar's
// close_quietly so CONNECT-replace and EXIT can't get stuck.
void close_quietly()
{
    if (g_sender)
    {
        ::line_sender_error* err = nullptr;
        ::line_sender_qwpws_close_drain(g_sender, &err);
        if (err)
            ::line_sender_error_free(err);
        ::line_sender_close(g_sender);
        g_sender = nullptr;
    }
    if (g_buffer)
    {
        ::line_sender_buffer_free(g_buffer);
        g_buffer = nullptr;
    }
    g_request_durable_ack = false;
}

bool request_durable_ack_enabled(const std::string& conf)
{
    return conf.find("request_durable_ack=on") != std::string::npos ||
           conf.find("request_durable_ack=true") != std::string::npos;
}

void handle_connect(const std::string& rest)
{
    close_quietly();
    ::line_sender_error* err = nullptr;
    ::line_sender_utf8 conf{0, nullptr};
    if (!::line_sender_utf8_init(&conf, rest.size(), rest.data(), &err))
    {
        reply_err_from(err);
        return;
    }
    ::line_sender* sender = ::line_sender_from_conf(conf, &err);
    if (!sender)
    {
        reply_err_from(err);
        return;
    }
    ::line_sender_buffer* buffer = ::line_sender_buffer_new_for_sender(sender);
    if (!buffer)
    {
        ::line_sender_close(sender);
        reply_err("could not create buffer for sender");
        return;
    }
    g_sender = sender;
    g_buffer = buffer;
    g_request_durable_ack = request_durable_ack_enabled(rest);
    reply_ok("");
}

void handle_send(const std::string& rest)
{
    if (!g_sender || !g_buffer)
    {
        reply_err("no sender");
        return;
    }
    std::istringstream iss(rest);
    std::string table;
    long long count = 0;
    long long start = 0;
    if (!(iss >> table >> count >> start))
    {
        reply_err("usage: SEND <table> <count> <start_index>");
        return;
    }

    ::line_sender_error* err = nullptr;
    ::line_sender_table_name table_name{0, nullptr};
    if (!::line_sender_table_name_init(&table_name, table.size(), table.data(), &err))
    {
        reply_err_from(err);
        return;
    }
    ::line_sender_column_name v_name{0, nullptr};
    if (!::line_sender_column_name_init(&v_name, 1, "v", &err))
    {
        reply_err_from(err);
        return;
    }

    for (long long i = 0; i < count; ++i)
    {
        const std::int64_t v = static_cast<std::int64_t>(start + i);
        // Identical schema/timestamps to the Rust + C sidecars: a single LONG
        // `v`, microsecond timestamps one second apart starting at second 1
        // (v=0 -> 1_000_000us), so the same dense-[0..N) oracle applies.
        if (!::line_sender_buffer_table(g_buffer, table_name, &err) ||
            !::line_sender_buffer_column_i64(g_buffer, v_name, v, &err) ||
            !::line_sender_buffer_at_micros(
                g_buffer, static_cast<std::int64_t>(1000000LL * (v + 1)), &err))
        {
            reply_err_from(err);
            return;
        }
    }
    reply_ok("");
}

void handle_flush()
{
    if (!g_sender || !g_buffer)
    {
        reply_err("no sender");
        return;
    }
    ::line_sender_error* err = nullptr;
    ::line_sender_qwpws_fsn fsn{false, 0};
    if (!::line_sender_qwpws_flush_and_get_fsn(g_sender, g_buffer, &fsn, &err))
    {
        reply_err_from(err);
        return;
    }
    // Empty-buffer flush has has_value == false; -1 is the matching sentinel.
    reply_ok(fsn.has_value ? std::to_string(fsn.value) : std::string("-1"));
}

void handle_await_acked(const std::string& rest)
{
    if (!g_sender)
    {
        reply_err("no sender");
        return;
    }
    std::istringstream iss(rest);
    unsigned long long fsn = 0; // retained for wire compatibility; the wait API
                                // targets the whole published boundary.
    unsigned long long timeout_ms = 0;
    if (!(iss >> fsn >> timeout_ms))
    {
        reply_err("usage: AWAIT_ACKED <fsn> <timeout_ms>");
        return;
    }
    (void)fsn;
    ::line_sender_error* err = nullptr;
    const uint32_t ack_level = g_request_durable_ack ? qwpws_ack_level_durable
                                                     : qwpws_ack_level_ok;
    if (::line_sender_qwpws_wait(
            g_sender, ack_level, timeout_ms, &err))
    {
        reply_ok("true");
        return;
    }
    if (::line_sender_error_get_code(err) == line_sender_error_failover_retry)
    {
        ::line_sender_error_free(err);
        reply_ok("false");
        return;
    }
    reply_err_from(err);
}

void handle_stats()
{
    if (!g_sender)
    {
        reply_err("no sender");
        return;
    }
    ::line_sender_error* err = nullptr;
    ::line_sender_qwpws_fsn fsn{false, 0};
    long long acked = -1;
    if (::line_sender_qwpws_acked_fsn(g_sender, &fsn, &err))
    {
        if (fsn.has_value)
            acked = static_cast<long long>(fsn.value);
    }
    else if (err)
    {
        ::line_sender_error_free(err);
    }
    std::ostringstream oss;
    oss << "acked=" << acked
        << " sent=0 acks=0 reconnAttempts=0 reconnSucc=0 serverErrors=0";
    reply_ok(oss.str());
}

void handle_close()
{
    if (g_sender)
    {
        ::line_sender_error* err = nullptr;
        const bool ok = ::line_sender_qwpws_close_drain(g_sender, &err);
        ::line_sender_close(g_sender);
        g_sender = nullptr;
        if (g_buffer)
        {
            ::line_sender_buffer_free(g_buffer);
            g_buffer = nullptr;
        }
        if (!ok)
        {
            reply_err_from(err);
            return;
        }
    }
    reply_ok("");
}

} // namespace

int main()
{
    std::ios::sync_with_stdio(false);
    std::cout << "READY\n";
    std::cout.flush();

    std::string line;
    while (std::getline(std::cin, line))
    {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            line.pop_back();
        if (line.empty())
            continue;

        const std::size_t sp = line.find(' ');
        const std::string verb = (sp == std::string::npos) ? line : line.substr(0, sp);
        std::string rest = (sp == std::string::npos) ? std::string{} : line.substr(sp + 1);
        const std::size_t b = rest.find_first_not_of(' ');
        rest = (b == std::string::npos) ? std::string{} : rest.substr(b);

        if (verb == "CONNECT")
            handle_connect(rest);
        else if (verb == "SEND")
            handle_send(rest);
        else if (verb == "FLUSH")
            handle_flush();
        else if (verb == "AWAIT_ACKED")
            handle_await_acked(rest);
        else if (verb == "STATS")
            handle_stats();
        else if (verb == "CLOSE")
            handle_close();
        else if (verb == "EXIT")
        {
            close_quietly();
            return 0;
        }
        else
            reply_err("unknown verb: " + verb);
    }

    close_quietly();
    return 0;
}
