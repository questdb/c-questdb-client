/*
 * Out-of-process QWP/WebSocket sender driven by a line-oriented stdin/stdout
 * protocol, implemented against the c-questdb-client *C* FFI binding.
 *
 * Byte-for-byte the same wire protocol as the Rust `qwp_sidecar`
 * (system_test/failover_clients/src/bin/qwp_sidecar.rs) and the Java
 * `QwpSidecarMain`, so the Enterprise pytest harness's `Sidecar` driver
 * (questdb-ent/e2e/lib/sidecar.py) can drive this binding unchanged. The
 * point of this sidecar is per-binding confidence: it exercises the C FFI
 * row-major store-and-forward path (line_sender_from_conf with a `ws::`
 * connect string, line_sender_buffer_new_for_sender, the
 * line_sender_qwpws_* publish/await/close calls) against the same Enterprise
 * failover scenarios the Rust binding runs.
 *
 * Protocol (single ASCII lines terminated by '\n'):
 *   READY                                <- emitted on startup
 *   CONNECT <connect_string>             -> OK | ERR <msg>
 *   SEND <table> <count> <start_index>   -> OK | ERR <msg>
 *   FLUSH                                -> OK <fsn> | ERR <msg>
 *   AWAIT_ACKED <fsn> <timeout_ms>       -> OK true|false | ERR <msg>
 *   STATS                                -> OK acked=N sent=N ... (see below)
 *   CLOSE                                -> OK | ERR <msg>
 *   EXIT                                 -> (no reply, exits 0)
 *
 * STATS note: the C FFI exposes the durable-ack watermark
 * (line_sender_qwpws_acked_fsn) but NOT the qwp_ws_totals counters
 * (sent/acks/reconnAttempts/reconnSucc/serverErrors). We emit the real
 * `acked` and zero the rest -- the same fallback shape the Rust sidecar
 * uses when totals are unavailable (qwp_sidecar.rs:236-238). The
 * binding-variant tests do not rely on the zeroed fields.
 */

#define _POSIX_C_SOURCE 200809L

#include <questdb/ingress/line_sender.h>

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

static line_sender* g_sender = NULL;
static line_sender_buffer* g_buffer = NULL;

/* Newlines in an ERR message would break the line-based protocol; match the
 * Rust/Java sidecars' substitution: CR -> space, LF -> '|'. */
static void reply_err_sanitized(const char* msg, size_t len)
{
    fputs("ERR ", stdout);
    for (size_t i = 0; i < len; ++i)
    {
        char c = msg[i];
        if (c == '\r')
            c = ' ';
        else if (c == '\n')
            c = '|';
        fputc(c, stdout);
    }
    fputc('\n', stdout);
    fflush(stdout);
}

static void reply_err(const char* msg)
{
    reply_err_sanitized(msg, strlen(msg));
}

/* Consume a line_sender_error: emit it as ERR and free it. */
static void reply_err_from(line_sender_error* err)
{
    size_t len = 0;
    const char* msg = line_sender_error_msg(err, &len);
    reply_err_sanitized(msg ? msg : "(null)", msg ? len : 6);
    line_sender_error_free(err);
}

static void reply_ok(const char* payload)
{
    if (payload && payload[0])
        printf("OK %s\n", payload);
    else
        fputs("OK\n", stdout);
    fflush(stdout);
}

/* Drain + free the current sender/buffer, swallowing errors. Mirrors the
 * Rust sidecar's close_quietly: a best-effort graceful close so the
 * CONNECT-replace and EXIT paths can't get stuck. */
static void close_quietly(void)
{
    if (g_sender)
    {
        line_sender_error* err = NULL;
        line_sender_qwpws_close_drain(g_sender, &err);
        if (err)
            line_sender_error_free(err);
        line_sender_close(g_sender);
        g_sender = NULL;
    }
    if (g_buffer)
    {
        line_sender_buffer_free(g_buffer);
        g_buffer = NULL;
    }
}

static void handle_connect(const char* rest)
{
    /* CONNECT replaces any active sender (tests reuse the sidecar across
     * scenarios), exactly like the Rust/Java sidecars. */
    close_quietly();

    line_sender_error* err = NULL;
    line_sender_utf8 conf = {0, NULL};
    if (!line_sender_utf8_init(&conf, strlen(rest), rest, &err))
    {
        reply_err_from(err);
        return;
    }
    line_sender* sender = line_sender_from_conf(conf, &err);
    if (!sender)
    {
        reply_err_from(err);
        return;
    }
    line_sender_buffer* buffer = line_sender_buffer_new_for_sender(sender);
    if (!buffer)
    {
        line_sender_close(sender);
        reply_err("could not create buffer for sender");
        return;
    }
    g_sender = sender;
    g_buffer = buffer;
    reply_ok("");
}

static void handle_send(const char* rest)
{
    if (!g_sender || !g_buffer)
    {
        reply_err("no sender");
        return;
    }
    char table[512];
    long long count = 0;
    long long start = 0;
    if (sscanf(rest, "%511s %lld %lld", table, &count, &start) != 3)
    {
        reply_err("usage: SEND <table> <count> <start_index>");
        return;
    }

    line_sender_error* err = NULL;
    line_sender_table_name table_name = {0, NULL};
    if (!line_sender_table_name_init(&table_name, strlen(table), table, &err))
    {
        reply_err_from(err);
        return;
    }
    line_sender_column_name v_name = {0, NULL};
    if (!line_sender_column_name_init(&v_name, 1, "v", &err))
    {
        reply_err_from(err);
        return;
    }

    for (long long i = 0; i < count; ++i)
    {
        int64_t v = (int64_t)(start + i);
        /* Identical schema/timestamps to the Rust + Java sidecars: a single
         * LONG column `v`, microsecond timestamps one second apart starting
         * at second 1 (v=0 -> 1_000_000us), so the same Enterprise asserting
         * queries (dense [0..N) over `v`) drive this binding unchanged. */
        if (!line_sender_buffer_table(g_buffer, table_name, &err) ||
            !line_sender_buffer_column_i64(g_buffer, v_name, v, &err) ||
            !line_sender_buffer_at_micros(g_buffer, 1000000LL * (v + 1), &err))
        {
            reply_err_from(err);
            return;
        }
    }
    reply_ok("");
}

static void handle_flush(void)
{
    if (!g_sender || !g_buffer)
    {
        reply_err("no sender");
        return;
    }
    line_sender_error* err = NULL;
    line_sender_qwpws_fsn fsn = {false, 0};
    if (!line_sender_qwpws_flush_and_get_fsn(g_sender, g_buffer, &fsn, &err))
    {
        reply_err_from(err);
        return;
    }
    /* Empty-buffer flush has has_value == false; the Python parser defaults a
     * missing fsn to -1, so -1 is the matching sentinel (mirrors the Rust
     * sidecar's `.unwrap_or(-1)`). */
    char payload[32];
    if (fsn.has_value)
        snprintf(payload, sizeof(payload), "%" PRIu64, fsn.value);
    else
        snprintf(payload, sizeof(payload), "-1");
    reply_ok(payload);
}

static void handle_await_acked(const char* rest)
{
    if (!g_sender)
    {
        reply_err("no sender");
        return;
    }
    unsigned long long fsn = 0; /* retained for wire compatibility; the wait
                                 * API waits for the whole published boundary,
                                 * exactly like the Rust sidecar. */
    unsigned long long timeout_ms = 0;
    if (sscanf(rest, "%llu %llu", &fsn, &timeout_ms) != 2)
    {
        reply_err("usage: AWAIT_ACKED <fsn> <timeout_ms>");
        return;
    }
    (void)fsn;
    line_sender_error* err = NULL;
    /* Durable ack level matches the Rust sidecar's AckLevel::Durable; it
     * falls back to ordinary acceptance when the connection did not negotiate
     * durable acks, so the negative (durable-ack-off) test works too. */
    if (line_sender_qwpws_wait(
            g_sender, line_sender_qwpws_ack_level_durable, timeout_ms, &err))
    {
        reply_ok("true");
        return;
    }
    /* A no-progress timeout reports line_sender_error_failover_retry; the Rust
     * sidecar maps that to OK false. Anything else is a real error. */
    if (line_sender_error_get_code(err) == line_sender_error_failover_retry)
    {
        line_sender_error_free(err);
        reply_ok("false");
        return;
    }
    reply_err_from(err);
}

static void handle_stats(void)
{
    if (!g_sender)
    {
        reply_err("no sender");
        return;
    }
    /* Only the durable-ack watermark is exported by the C FFI; the
     * sent / acks / reconnect / serverErrors counters have no FFI wrapper.
     * Emit the real acked and zero the rest, like the Rust sidecar fallback. */
    line_sender_error* err = NULL;
    line_sender_qwpws_fsn fsn = {false, 0};
    long long acked = -1;
    if (line_sender_qwpws_acked_fsn(g_sender, &fsn, &err))
    {
        if (fsn.has_value)
            acked = (long long)fsn.value;
    }
    else if (err)
    {
        line_sender_error_free(err);
    }
    char payload[160];
    snprintf(
        payload,
        sizeof(payload),
        "acked=%lld sent=0 acks=0 reconnAttempts=0 reconnSucc=0 serverErrors=0",
        acked);
    reply_ok(payload);
}

static void handle_close(void)
{
    if (g_sender)
    {
        line_sender_error* err = NULL;
        bool ok = line_sender_qwpws_close_drain(g_sender, &err);
        line_sender_close(g_sender);
        g_sender = NULL;
        if (g_buffer)
        {
            line_sender_buffer_free(g_buffer);
            g_buffer = NULL;
        }
        if (!ok)
        {
            reply_err_from(err);
            return;
        }
    }
    reply_ok("");
}

int main(void)
{
    /* READY tells the harness the main loop is up before any command. */
    fputs("READY\n", stdout);
    fflush(stdout);

    char* line = NULL;
    size_t cap = 0;
    ssize_t n;
    while ((n = getline(&line, &cap, stdin)) != -1)
    {
        /* strip trailing CR/LF */
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
            line[--n] = '\0';
        if (n == 0)
            continue;

        char* rest = strchr(line, ' ');
        const char* verb;
        if (rest)
        {
            *rest = '\0';
            rest++;
            while (*rest == ' ')
                rest++;
            verb = line;
        }
        else
        {
            verb = line;
            rest = line + n; /* empty */
        }

        if (strcmp(verb, "CONNECT") == 0)
            handle_connect(rest);
        else if (strcmp(verb, "SEND") == 0)
            handle_send(rest);
        else if (strcmp(verb, "FLUSH") == 0)
            handle_flush();
        else if (strcmp(verb, "AWAIT_ACKED") == 0)
            handle_await_acked(rest);
        else if (strcmp(verb, "STATS") == 0)
            handle_stats();
        else if (strcmp(verb, "CLOSE") == 0)
            handle_close();
        else if (strcmp(verb, "EXIT") == 0)
        {
            close_quietly();
            free(line);
            return 0;
        }
        else
        {
            char msg[128];
            snprintf(msg, sizeof(msg), "unknown verb: %s", verb);
            reply_err(msg);
        }
    }

    close_quietly();
    free(line);
    return 0;
}
