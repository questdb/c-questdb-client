/*
 * One QWP/WebSocket pool shared by column ingestion and SQL queries.
 *
 * Run against QuestDB 10.0+ on localhost:9000:
 *
 *     ./qwp_ws_chunk_and_query_c_example
 *
 * The example recreates its own `c_shared_pool_trades` table.
 */

#ifndef _WIN32
#    define _POSIX_C_SOURCE 200809L
#endif

#include <questdb/egress/qwp_reader.h>
#include <questdb/ingress/qwp_sender.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#    include <windows.h>
#else
#    include <time.h>
#endif

#define ROW_COUNT 4

static void sleep_millis(unsigned millis)
{
#ifdef _WIN32
    Sleep(millis);
#else
    struct timespec delay = {
        (time_t)(millis / 1000), (long)(millis % 1000) * 1000000L};
    (void)nanosleep(&delay, NULL);
#endif
}

static void print_error(const char* operation, const questdb_error* err)
{
    size_t len = 0;
    const char* message = questdb_error_msg(err, &len);
    fprintf(stderr, "%s: %.*s\n", operation, (int)len, message);
}

static bool execute_sql(
    questdb_db* db, line_sender_utf8 sql, questdb_error** err_out)
{
    qwp_reader* r = questdb_db_borrow_reader(db, err_out);
    qwp_reader_cursor* cursor = NULL;
    bool ok = false;

    if (!r)
        return false;

    cursor = qwp_reader_execute(r, sql, err_out);
    if (!cursor)
        goto cleanup;

    while (qwp_reader_cursor_next_batch(cursor, err_out) != NULL)
    {
    }
    ok = *err_out == NULL;

cleanup:
    qwp_reader_cursor_free(cursor);
    qwp_reader_close(r);
    return ok;
}

static bool recreate_table(questdb_db* db, questdb_error** err_out)
{
    if (!execute_sql(
            db,
            QDB_UTF8_LITERAL("DROP TABLE IF EXISTS c_shared_pool_trades"),
            err_out))
        return false;

    return execute_sql(
        db,
        QDB_UTF8_LITERAL(
            "CREATE TABLE c_shared_pool_trades ("
            "symbol SYMBOL, price DOUBLE, amount DOUBLE, "
            "timestamp TIMESTAMP) TIMESTAMP(timestamp) PARTITION BY DAY WAL"),
        err_out);
}

static bool publish_trades(questdb_db* db, questdb_error** err_out)
{
    static const int8_t symbol_codes[ROW_COUNT] = {0, 1, 0, 1};
    static const int32_t symbol_offsets[] = {0, 8, 16};
    static const uint8_t symbol_bytes[] = "BTC-USDTETH-USDT";
    static const double prices[ROW_COUNT] = {
        65432.10, 2615.54, 65440.25, 2616.12};
    static const double amounts[ROW_COUNT] = {0.002, 0.25, 0.0004, 0.75};

    int64_t timestamps[ROW_COUNT];
    const int64_t now = line_sender_now_nanos();
    for (size_t i = 0; i < ROW_COUNT; ++i)
        timestamps[i] = now + (int64_t)i * 1000;

    qwp_chunk* chunk = qwp_chunk_new(
        "c_shared_pool_trades", sizeof("c_shared_pool_trades") - 1, err_out);
    qwp_sender* sender = NULL;
    bool ok = false;

    if (!chunk)
        return false;

    if (!qwp_chunk_symbol_i8(
            chunk,
            "symbol",
            sizeof("symbol") - 1,
            symbol_codes,
            ROW_COUNT,
            symbol_offsets,
            sizeof(symbol_offsets) / sizeof(symbol_offsets[0]),
            symbol_bytes,
            sizeof(symbol_bytes) - 1,
            NULL,
            err_out))
        goto cleanup;
    if (!qwp_chunk_column_f64(
            chunk,
            "price",
            sizeof("price") - 1,
            prices,
            ROW_COUNT,
            NULL,
            err_out))
        goto cleanup;
    if (!qwp_chunk_column_f64(
            chunk,
            "amount",
            sizeof("amount") - 1,
            amounts,
            ROW_COUNT,
            NULL,
            err_out))
        goto cleanup;
    if (!qwp_chunk_at_nanos(chunk, timestamps, ROW_COUNT, err_out))
        goto cleanup;

    sender = questdb_db_borrow_sender(db, err_out);
    if (!sender)
        goto cleanup;

    /* The OK barrier confirms server acceptance, not immediate WAL visibility.
     */
    ok = qwp_sender_flush_chunk_and_wait(
        sender, chunk, qwpws_ack_level_ok, err_out);

cleanup:
    questdb_db_return_sender(db, sender);
    qwp_chunk_free(chunk);
    return ok;
}

static bool query_count(
    questdb_db* db, int64_t* count_out, questdb_error** err_out)
{
    qwp_reader* r = questdb_db_borrow_reader(db, err_out);
    qwp_reader_cursor* cursor = NULL;
    bool ok = false;

    *count_out = 0;
    if (!r)
        return false;

    cursor = qwp_reader_execute(
        r,
        QDB_UTF8_LITERAL("SELECT count() FROM c_shared_pool_trades"),
        err_out);
    if (!cursor)
        goto cleanup;

    const qwp_reader_batch* batch;
    while ((batch = qwp_reader_cursor_next_batch(cursor, err_out)) != NULL)
    {
        if (qwp_reader_batch_row_count(batch) == 0)
            continue;

        qwp_reader_column_data count;
        if (!qwp_reader_batch_column_data(batch, 0, &count, err_out))
            goto cleanup;

        bool is_null = false;
        *count_out = qwp_reader_column_data_get_i64(&count, 0, &is_null);
        if (is_null)
        {
            fprintf(stderr, "count() unexpectedly returned NULL\n");
            goto cleanup;
        }
    }
    ok = *err_out == NULL;

cleanup:
    qwp_reader_cursor_free(cursor);
    qwp_reader_close(r);
    return ok;
}

static bool wait_until_visible(questdb_db* db, questdb_error** err_out)
{
    const int64_t deadline = line_sender_now_nanos() + 60000000000LL;
    int64_t visible = 0;

    do
    {
        if (!query_count(db, &visible, err_out))
            return false;
        if (visible >= ROW_COUNT)
            return true;
        sleep_millis(100);
    } while (line_sender_now_nanos() < deadline);

    fprintf(
        stderr,
        "only %lld/%d rows became query-visible before the deadline\n",
        (long long)visible,
        ROW_COUNT);
    return false;
}

static bool report_large_trades(questdb_db* db, questdb_error** err_out)
{
    qwp_reader* r = questdb_db_borrow_reader(db, err_out);
    qwp_reader_query* query = NULL;
    qwp_reader_cursor* cursor = NULL;
    bool ok = false;

    if (!r)
        return false;

    query = qwp_reader_prepare(
        r,
        QDB_UTF8_LITERAL(
            "SELECT symbol, price, amount FROM c_shared_pool_trades "
            "WHERE amount > $1 ORDER BY symbol"),
        err_out);
    if (!query)
        goto cleanup;

    qwp_reader_query_bind_f64(query, 0.005);
    cursor = qwp_reader_query_execute(&query, err_out);
    if (!cursor)
        goto cleanup;

    puts("trades with amount > 0.005:");
    const qwp_reader_batch* batch;
    while ((batch = qwp_reader_cursor_next_batch(cursor, err_out)) != NULL)
    {
        qwp_reader_column_data symbol;
        qwp_reader_column_data price;
        qwp_reader_column_data amount;
        qwp_reader_symbol_dict dictionary;

        if (!qwp_reader_batch_column_data(batch, 0, &symbol, err_out) ||
            !qwp_reader_batch_column_data(batch, 1, &price, err_out) ||
            !qwp_reader_batch_column_data(batch, 2, &amount, err_out) ||
            !qwp_reader_batch_symbol_dict(batch, &dictionary, err_out))
            goto cleanup;

        for (size_t row = 0; row < qwp_reader_batch_row_count(batch); ++row)
        {
            const char* symbol_text = NULL;
            size_t symbol_len = 0;
            bool symbol_null = false;
            bool price_null = false;
            bool amount_null = false;

            if (!qwp_reader_column_data_get_symbol(
                    &symbol,
                    &dictionary,
                    row,
                    &symbol_text,
                    &symbol_len,
                    &symbol_null))
            {
                fprintf(stderr, "symbol dictionary code out of range\n");
                goto cleanup;
            }

            const double price_value =
                qwp_reader_column_data_get_f64(&price, row, &price_null);
            const double amount_value =
                qwp_reader_column_data_get_f64(&amount, row, &amount_null);
            if (!symbol_null && !price_null && !amount_null)
                printf(
                    "  %.*s price=%.2f amount=%g\n",
                    (int)symbol_len,
                    symbol_text,
                    price_value,
                    amount_value);
        }
    }
    ok = *err_out == NULL;

cleanup:
    qwp_reader_query_free(query);
    qwp_reader_cursor_free(cursor);
    qwp_reader_close(r);
    return ok;
}

int main(int argc, const char* argv[])
{
    const char* conf = argc >= 2 ? argv[1]
                                 : "ws::addr=localhost:9000;sender_pool_max=2;"
                                   "query_pool_max=2;";
    questdb_error* err = NULL;
    questdb_db* db = questdb_db_connect(conf, strlen(conf), &err);
    const char* operation = "connect pool";
    bool ok = false;

    if (!db)
        goto cleanup;
    operation = "recreate table";
    if (!recreate_table(db, &err))
        goto cleanup;
    operation = "publish trades";
    if (!publish_trades(db, &err))
        goto cleanup;
    operation = "wait for WAL visibility";
    if (!wait_until_visible(db, &err))
        goto cleanup;
    operation = "query trades";
    if (!report_large_trades(db, &err))
        goto cleanup;

    ok = true;

cleanup:
    if (err)
        print_error(operation, err);
    else if (!ok)
        fprintf(stderr, "%s failed\n", operation);
    questdb_error_free(err);
    questdb_db_close(db);
    return ok ? 0 : 1;
}
