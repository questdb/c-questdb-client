/*
 * Out-of-process QWP egress (read-side) client driven by a line-oriented
 * stdin/stdout protocol, implemented against the c-questdb-client *C* FFI
 * reader binding (`include/questdb/egress/qwp_reader.h`, whose symbols are always
 * compiled into the C ABI).
 *
 * Same wire protocol as the Rust `qwp_egress_sidecar`
 * (system_test/failover_clients/src/bin/qwp_egress_sidecar.rs) and the Java
 * `QwpEgressSidecarMain`, restricted to the verbs the C API can express, so
 * the Enterprise pytest harness's `EgressSidecar` driver
 * (questdb-ent/e2e/lib/egress_sidecar.py) drives this binding unchanged.
 *
 * Protocol (single ASCII lines terminated by '\n'):
 *   READY                       <- emitted on startup
 *   CONNECT <connect_string>    -> OK | ERR <msg>       (eager bind)
 *   QUERY <sql>                 -> OK <row_count> <latency_ms> | ERR <msg>
 *   SERVER_INFO                 -> OK role=<byte> cap_zone=<0|1> | ERR <msg>
 *   CLOSE                       -> OK | ERR <msg>
 *   EXIT                        -> (no reply, exits 0)
 *
 * Deliberate protocol subset vs the Rust sidecar:
 *   - SERVER_INFO omits the `zone=` token: this reduced sidecar does not
 *     consume the C API's zone accessor, so only `cap_zone` (capabilities
 *     bit 0x1, CAP_ZONE) is reported. The Python wrapper defaults a missing
 *     zone to unset.
 *   - SHOW_ZONE and QUERY_ROW reply `ERR unsupported ...`: both need string
 *     column extraction that the bindings-matrix scenarios do not use; a
 *     future test that needs them should extend this sidecar rather than
 *     silently succeed.
 *
 * The standalone `qwp_reader_from_conf` constructor matches the Rust sidecar's
 * `Reader::from_conf` and gives each CONNECT command one dedicated transport.
 */

#define _POSIX_C_SOURCE 200809L
#include <questdb/egress/qwp_reader.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

/* CAP_ZONE bit (questdb-rs/src/egress/wire/capabilities.rs). */
#define QDB_CAP_ZONE 0x00000001u

static qwp_reader* g_reader = NULL;

/* Newlines in an ERR message would break the line-based protocol; match the
 * other sidecars' substitution: CR -> space, LF -> '|'. */
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

/* Consume a questdb_error: emit it as ERR and free it. */
static void reply_err_from(questdb_error* err)
{
    size_t len = 0;
    const char* msg = questdb_error_msg(err, &len);
    reply_err_sanitized(msg ? msg : "(null)", msg ? len : 6);
    questdb_error_free(err);
}

static void reply_ok(const char* payload)
{
    if (payload && payload[0])
        printf("OK %s\n", payload);
    else
        fputs("OK\n", stdout);
    fflush(stdout);
}

static void close_quietly(void)
{
    if (g_reader)
    {
        qwp_reader_close(g_reader);
        g_reader = NULL;
    }
}

static double monotonic_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static void handle_connect(const char* rest)
{
    /* CONNECT replaces any active reader (tests reuse the sidecar across
     * scenarios), exactly like the Rust/Java sidecars. The bind is EAGER:
     * qwp_reader_from_conf walks the address list with the target/zone filter
     * applied, so a role mismatch surfaces as ERR here -- same semantics
     * the target-filter scenarios pin on the Rust binding. */
    close_quietly();

    questdb_error* err = NULL;
    line_sender_utf8 conf = {0, NULL};
    if (!line_sender_utf8_init(&conf, strlen(rest), rest, &err))
    {
        reply_err_from(err);
        return;
    }
    qwp_reader* r = qwp_reader_from_conf(conf, &err);
    if (!r)
    {
        reply_err_from(err);
        return;
    }
    g_reader = r;
    reply_ok("");
}

static void handle_query(const char* rest)
{
    if (!g_reader)
    {
        reply_err("no reader");
        return;
    }
    questdb_error* err = NULL;
    line_sender_utf8 sql = {0, NULL};
    if (!line_sender_utf8_init(&sql, strlen(rest), rest, &err))
    {
        reply_err_from(err);
        return;
    }

    const double t0 = monotonic_ms();
    qwp_reader_query* query = qwp_reader_prepare(g_reader, sql, &err);
    if (!query)
    {
        reply_err_from(err);
        return;
    }
    qwp_reader_cursor* cursor = qwp_reader_query_execute(&query, &err);
    /* `query` is now NULL -- `_query_execute` consumed it. */
    if (!cursor)
    {
        reply_err_from(err);
        return;
    }

    unsigned long long rows = 0;
    const qwp_reader_batch* batch;
    while ((batch = qwp_reader_cursor_next_batch(cursor, &err)) != NULL)
        rows += (unsigned long long)qwp_reader_batch_row_count(batch);
    if (err)
    {
        qwp_reader_cursor_free(cursor);
        reply_err_from(err);
        return;
    }
    qwp_reader_cursor_free(cursor);
    const double latency_ms = monotonic_ms() - t0;

    char payload[64];
    snprintf(payload, sizeof(payload), "%llu %.3f", rows, latency_ms);
    reply_ok(payload);
}

static void handle_server_info(void)
{
    if (!g_reader)
    {
        reply_err("no reader");
        return;
    }
    /* In-memory snapshot from the most recent bind; no SQL round-trip, so
     * this does not itself drive reconnect (mirrors the Rust sidecar). */
    const qwp_reader_server_info* info = qwp_reader_current_server_info(g_reader);
    if (!info)
    {
        /* Same wire shape as the Rust sidecar's no-snapshot arm, minus the
         * zone token the C API cannot supply. */
        reply_ok("role=-1 cap_zone=0");
        return;
    }
    const unsigned role = (unsigned)qwp_reader_server_info_role_byte(info);
    const uint32_t caps = qwp_reader_server_info_capabilities(info);
    char payload[64];
    snprintf(payload, sizeof(payload), "role=%u cap_zone=%d",
             role, (caps & QDB_CAP_ZONE) != 0 ? 1 : 0);
    reply_ok(payload);
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
        else if (strcmp(verb, "QUERY") == 0)
            handle_query(rest);
        else if (strcmp(verb, "SERVER_INFO") == 0)
            handle_server_info();
        else if (strcmp(verb, "SHOW_ZONE") == 0 ||
                 strcmp(verb, "QUERY_ROW") == 0)
            reply_err("unsupported verb in the C egress sidecar (needs string "
                      "column extraction; extend qwp_egress_c_sidecar.c)");
        else if (strcmp(verb, "CLOSE") == 0)
        {
            close_quietly();
            reply_ok("");
        }
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
