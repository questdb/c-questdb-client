/*
 * Smoke test for the reader FFI.
 *
 * Two phases:
 *
 *  1. Closed-port phase (always runs). Targets 127.0.0.1:1 (the TCPMUX
 *     well-known port that is virtually never bound) and asserts that
 *     `reader_from_conf` reaches the connect path, fails cleanly,
 *     and surfaces a non-NULL error that the FFI can then free. This
 *     exercises symbol resolution, FFI argument marshalling, error
 *     allocation, and `reader_close`'s NULL-idempotent behaviour
 *     — all without fighting a developer machine that happens to have
 *     a QuestDB broker running on the default port (the case that
 *     broke the previous `WILL_FAIL`-based smoke).
 *
 *  2. Lifecycle phase (gated on `QDB_LIVE_BROKER_ADDR`). When the env
 *     var is set, drives `_from_conf` → `_query_new` → `_query_execute`
 *     → `_cursor_next_batch` → `_batch_column_data` →
 *     `reader_column_data_get_i64` → `_cursor_free` → `_close`
 *     against a real broker. The whole
 *     point of the C ABI is Cython-consumability; the C++ doctest
 *     suite covers these symbols but doesn't prove they link or
 *     argument-marshal correctly under a plain C compiler. This
 *     phase fills that gap.
 *
 *     Variable: `QDB_LIVE_BROKER_ADDR=host:port`. When unset (the CI
 *     default), the phase prints a skip message and returns success.
 *
 * Exit code is the standard "0 = pass, non-zero = fail" so SIGSEGV /
 * SIGABRT are correctly reported as failures rather than passes.
 */

#include <questdb/egress/reader.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int closed_port_phase(void)
{
    line_sender_utf8 conf =
        QDB_UTF8_LITERAL("ws::addr=127.0.0.1:1;");

    reader_error* err = NULL;
    reader* reader = reader_from_conf(conf, &err);

    if (reader != NULL)
    {
        fprintf(
            stderr,
            "smoke: expected reader_from_conf to fail against a "
            "guaranteed-closed port, but it succeeded\n");
        reader_close(reader);
        return 1;
    }

    if (err == NULL)
    {
        fprintf(
            stderr,
            "smoke: reader_from_conf returned NULL but did not set "
            "an error — FFI error-propagation contract violated\n");
        return 1;
    }

    size_t msg_len = 0;
    const char* msg = reader_error_msg(err, &msg_len);
    if (msg == NULL || msg_len == 0)
    {
        fprintf(
            stderr,
            "smoke: error has empty message — error-message accessor "
            "broken\n");
        reader_error_free(err);
        return 1;
    }

    /* Drop the error and confirm the NULL-idempotent close path. */
    reader_error_free(err);
    reader_close(NULL);
    return 0;
}

/*
 * Reader-only pool phase (always runs). Proves a read-only C consumer
 * can open, fail, and tear down the connection pool using ONLY
 * <questdb/egress/reader.h> and ONLY the `reader_error`
 * type — i.e. without including <questdb/ingress/column_sender.h> or
 * declaring a `line_sender_error`. This is the whole point of
 * `questdb_db_connect_reader`: the pool's connect call no longer drags
 * the ingress error type onto the read path.
 *
 * Targets the same guaranteed-closed 127.0.0.1:1 port via a `qwpws::`
 * connect string. The pool is lazy: `questdb_db_connect_reader` opens no
 * socket, so the connect itself succeeds and the connect failure surfaces
 * on the first `questdb_db_borrow_reader` — reported as a `reader_error*`
 * (not a `line_sender_error*`). Also exercises the NULL-idempotent
 * `questdb_db_close` / `questdb_db_return_reader` paths.
 */
static int pool_reader_only_phase(void)
{
    static const char conf[] = "qwpws::addr=127.0.0.1:1;";

    reader_error* err = NULL;
    struct questdb_db* db =
        questdb_db_connect_reader(conf, strlen(conf), &err);

    /*
     * Lazy pool: connect opens nothing, so it succeeds even against a
     * guaranteed-closed port.
     */
    if (db == NULL)
    {
        size_t connect_msg_len = 0;
        const char* connect_msg =
            err != NULL ? reader_error_msg(err, &connect_msg_len) : NULL;
        fprintf(
            stderr,
            "smoke pool: questdb_db_connect_reader unexpectedly failed for a "
            "lazy pool: %.*s\n",
            (int)connect_msg_len,
            connect_msg ? connect_msg : "(no error)");
        if (err != NULL)
            reader_error_free(err);
        return 1;
    }

    /*
     * The connect failure must surface here, on the first borrow, as a
     * `reader_error*`.
     */
    reader* reader = questdb_db_borrow_reader(db, &err);
    if (reader != NULL)
    {
        fprintf(
            stderr,
            "smoke pool: expected questdb_db_borrow_reader to fail against a "
            "guaranteed-closed port, but it succeeded\n");
        reader_close(reader);
        questdb_db_close(db);
        if (err != NULL)
            reader_error_free(err);
        return 1;
    }

    if (err == NULL)
    {
        fprintf(
            stderr,
            "smoke pool: questdb_db_borrow_reader returned NULL but did "
            "not set an error — FFI error-propagation contract violated\n");
        questdb_db_close(db);
        return 1;
    }

    size_t msg_len = 0;
    const char* msg = reader_error_msg(err, &msg_len);
    if (msg == NULL || msg_len == 0)
    {
        fprintf(
            stderr,
            "smoke pool: borrow error has empty message — egress error "
            "accessor broken on the pool borrow path\n");
        reader_error_free(err);
        questdb_db_close(db);
        return 1;
    }

    /* Single egress error type, freed through the egress accessor. */
    reader_error_free(err);
    questdb_db_close(db);

    /* NULL-idempotent teardown paths reachable from this header. */
    questdb_db_return_reader(NULL, NULL);
    questdb_db_close(NULL);
    return 0;
}

/*
 * Drive the full cursor lifecycle against the broker named by `addr`.
 * Returns 0 on success, non-zero on failure (with a diagnostic on
 * stderr). Frees every handle on every exit path so this smoke
 * doubles as a leak-shape audit when run under valgrind / leaks.
 */
static int live_lifecycle_phase(const char* addr)
{
    reader_error* err = NULL;
    reader* reader = NULL;
    reader_query* query = NULL;
    reader_cursor* cursor = NULL;
    int rc = 1;

    /*
     * `failover=off` keeps the diagnostic clean: a single endpoint
     * means a single attempt; any error surfaces directly without
     * multi-endpoint aggregation wrapping.
     */
    char conf_buf[256];
    int n = snprintf(
        conf_buf, sizeof(conf_buf), "ws::addr=%s;failover=off", addr);
    if (n <= 0 || (size_t)n >= sizeof(conf_buf))
    {
        fprintf(
            stderr,
            "smoke live: QDB_LIVE_BROKER_ADDR=%s is too long for the "
            "fixed connect-string buffer\n",
            addr);
        return 1;
    }
    line_sender_utf8 conf = {(size_t)n, conf_buf};

    reader = reader_from_conf(conf, &err);
    if (!reader)
        goto fail;

    line_sender_utf8 sql = QDB_UTF8_LITERAL("select 1");
    query = reader_prepare(reader, sql, &err);
    if (!query)
        goto fail;

    cursor = reader_query_execute(&query, &err);
    /* `_query_execute` consumed query — must now be NULL. */
    if (query != NULL)
    {
        fprintf(
            stderr,
            "smoke live: reader_query_execute did not nullify its "
            "query in-out parameter — ownership contract violated\n");
        goto fail;
    }
    if (!cursor)
        goto fail;

    /*
     * Drain. `select 1` is a SELECT, so we expect RESULT_END
     * after consuming the single one-row batch. Verify that we see
     * exactly that row with the expected value, exercising
     * `_batch_row_count`, `_batch_column_count`, `_batch_column_data`,
     * and `reader_column_data_get_i64` — the four most-used
     * per-row accessors on the bulk path.
     */
    int batch_count = 0;
    long long captured_value = 0;
    int captured_is_null = -1;
    const reader_batch* batch;
    while ((batch = reader_cursor_next_batch(cursor, &err)) != NULL)
    {
        ++batch_count;
        if (batch_count > 16)
        {
            fprintf(
                stderr,
                "smoke live: broker produced too many batches for "
                "`select 1`; aborting drain\n");
            goto fail;
        }

        const size_t rows = reader_batch_row_count(batch);
        const size_t cols = reader_batch_column_count(batch);
        if (cols == 0)
        {
            fprintf(
                stderr,
                "smoke live: batch has zero columns; expected 1\n");
            goto fail;
        }

        reader_column_data d;
        if (!reader_batch_column_data(batch, 0, &d, &err))
            goto fail;
        /*
         * QuestDB returns `select 1` as a LONG (i64). Accept INT too
         * in case a future server emits it as INT — we just need the
         * column-kind discriminant to give us a usable type.
         */
        if (d.kind != reader_column_kind_long &&
            d.kind != reader_column_kind_int)
        {
            fprintf(
                stderr,
                "smoke live: `select 1` column[0] kind=0x%02X is not "
                "LONG or INT\n",
                (unsigned)d.kind);
            goto fail;
        }

        for (size_t r = 0; r < rows; ++r)
        {
            bool is_null = false;
            int64_t v = 0;
            if (d.kind == reader_column_kind_long)
                v = reader_column_data_get_i64(&d, r, &is_null);
            else
                v = (int64_t)reader_column_data_get_i32(&d, r, &is_null);
            captured_value = (long long)v;
            captured_is_null = is_null ? 1 : 0;
        }
    }
    if (err)
        goto fail;

    if (batch_count == 0)
    {
        fprintf(
            stderr,
            "smoke live: broker produced no batches for `select 1`; "
            "expected at least one\n");
        goto fail;
    }
    if (captured_is_null != 0 || captured_value != 1)
    {
        fprintf(
            stderr,
            "smoke live: `select 1` returned %lld (is_null=%d); "
            "expected 1 (is_null=0)\n",
            captured_value,
            captured_is_null);
        goto fail;
    }

    rc = 0;
    goto cleanup;

fail:;
    if (err != NULL)
    {
        size_t err_len = 0;
        const char* err_msg = reader_error_msg(err, &err_len);
        fprintf(
            stderr,
            "smoke live: %.*s\n",
            (int)err_len,
            err_msg ? err_msg : "");
    }
    else
    {
        fprintf(
            stderr,
            "smoke live: failed without an err pointer set — likely "
            "a contract violation\n");
    }

cleanup:
    /*
     * Free in reverse-allocation order. Each free is NULL-idempotent
     * per the API contract, so this is safe even after a mid-pipeline
     * failure. `_query_execute` already nullified `query` on the
     * happy path, but the free is still defensive for the case where
     * `_query_execute` itself failed before consuming the query.
     */
    if (err != NULL)
        reader_error_free(err);
    reader_cursor_free(cursor);
    reader_query_free(query);
    reader_close(reader);
    return rc;
}

int main(void)
{
    int rc = closed_port_phase();
    if (rc != 0)
        return rc;

    rc = pool_reader_only_phase();
    if (rc != 0)
        return rc;

    const char* live_addr = getenv("QDB_LIVE_BROKER_ADDR");
    if (live_addr == NULL || live_addr[0] == '\0')
    {
        fprintf(
            stderr,
            "smoke: QDB_LIVE_BROKER_ADDR not set — skipping cursor "
            "lifecycle phase. Set `QDB_LIVE_BROKER_ADDR=host:port` to "
            "exercise the full _query_*/_cursor_*/_close lifecycle "
            "from C (the Cython contract surface).\n");
        return 0;
    }

    fprintf(
        stderr,
        "smoke: running cursor lifecycle phase against %s\n",
        live_addr);
    return live_lifecycle_phase(live_addr);
}
