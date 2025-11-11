#include <questdb/ingress/line_sender.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "concat.h"

static bool example(const char* host, const char* port)
{
    line_sender_error* err = NULL;
    line_sender* sender = NULL;
    line_sender_buffer* buffer = NULL;
    char* conf_str = concat(
        "tcps::addr=",
        host,
        ":",
        port,
        ";"
        "protocol_version=3;"
        "username=admin;"
        "token=5UjEMuA0Pj5pjK8a-fa24dyIf-Es5mYny3oE_Wmus48;"
        "token_x=fLKYEaoEb9lrn3nkwLDA-M_xnuFOdSt9y0Z7_vWSHLU;"
        "token_y=Dt5tbS1dEDMSYfym3fgMv0B99szno-dFc1rYF9t0aac;");
    if (!conf_str)
    {
        fprintf(stderr, "Could not concatenate configuration string.\n");
        return false;
    }
    line_sender_utf8 conf_str_utf8 = {0, NULL};
    if (!line_sender_utf8_init(
            &conf_str_utf8, strlen(conf_str), conf_str, &err))
        goto on_error;

    sender = line_sender_from_conf(conf_str_utf8, &err);
    if (!sender)
        goto on_error;

    free(conf_str);
    conf_str = NULL;

    buffer = line_sender_buffer_new_for_sender(sender);
    line_sender_buffer_reserve(buffer, 64 * 1024); // 64KB buffer initial size.

    // We prepare all our table names and column names in advance.
    // If we're inserting multiple rows, this allows us to avoid
    // re-validating the same strings over and over again.
    line_sender_table_name table_name =
        QDB_TABLE_NAME_LITERAL("c_trades_auth_tls");
    line_sender_column_name symbol_name = QDB_COLUMN_NAME_LITERAL("symbol");
    line_sender_column_name side_name = QDB_COLUMN_NAME_LITERAL("side");
    line_sender_column_name price_name = QDB_COLUMN_NAME_LITERAL("price");
    line_sender_column_name amount_name = QDB_COLUMN_NAME_LITERAL("amount");

    if (!line_sender_buffer_table(buffer, table_name, &err))
        goto on_error;

    line_sender_utf8 symbol_value = QDB_UTF8_LITERAL("ETH-USD");
    if (!line_sender_buffer_symbol(buffer, symbol_name, symbol_value, &err))
        goto on_error;

    line_sender_utf8 side_value = QDB_UTF8_LITERAL("sell");
    if (!line_sender_buffer_symbol(buffer, side_name, side_value, &err))
        goto on_error;

    // The table must be created beforehand with the appropriate DECIMAL(N,M) type for the column.
    line_sender_utf8 price_value = QDB_UTF8_LITERAL("2615.54");
    if (!line_sender_buffer_column_dec_str(
            buffer, price_name, price_value, &err))
        goto on_error;

    if (!line_sender_buffer_column_f64(buffer, amount_name, 0.00044, &err))
        goto on_error;

    // 1997-07-04 04:56:55 UTC
    int64_t designated_timestamp = 867992215000000000;
    if (!line_sender_buffer_at_nanos(buffer, designated_timestamp, &err))
        goto on_error;

    //// If you want to get the current system timestamp as nanos, call:
    // if (!line_sender_buffer_at_nanos(buffer, line_sender_now_nanos(), &err))
    //     goto on_error;

    // To insert more records, call `line_sender_buffer_table(..)...` again.
    // It's recommended to keep a timer and/or maximum buffer size to flush
    // the buffer periodically with any accumulated records.
    if (!line_sender_flush(sender, buffer, &err))
        goto on_error;

    line_sender_buffer_free(buffer);
    line_sender_close(sender);

    return true;

on_error:;
    size_t err_len = 0;
    const char* err_msg = line_sender_error_msg(err, &err_len);
    fprintf(stderr, "Error running example: %.*s\n", (int)err_len, err_msg);
    free(conf_str);
    line_sender_error_free(err);
    line_sender_buffer_free(buffer);
    line_sender_close(sender);
    return false;
}

static bool displayed_help(int argc, const char* argv[])
{
    for (int index = 1; index < argc; ++index)
    {
        const char* arg = argv[index];
        if ((strncmp(arg, "-h", 2) == 0) || (strncmp(arg, "--help", 6) == 0))
        {
            fprintf(stderr, "Usage:\n");
            fprintf(stderr, "line_sender_c_example_auth_tls: [HOST [PORT]]\n");
            fprintf(
                stderr, "    HOST: ILP host (defaults to \"localhost\").\n");
            fprintf(stderr, "    PORT: ILP port (defaults to \"9009\").\n");
            return true;
        }
    }
    return false;
}

int main(int argc, const char* argv[])
{
    if (displayed_help(argc, argv))
        return 0;

    const char* host = "localhost";
    if (argc >= 2)
        host = argv[1];
    const char* port = "9009";
    if (argc >= 3)
        port = argv[2];

    return !example(host, port);
}
