#include <questdb/ingress/line_sender.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "concat.h"

/*
 * QuestDB server version 9.0.0 or later is required for array support.
 */
static bool example(const char* host, const char* port)
{
    line_sender_error* err = NULL;
    line_sender* sender = NULL;
    line_sender_buffer* buffer = NULL;
    char* conf_str =
        concat("tcp::addr=", host, ":", port, ";protocol_version=2;");
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
    line_sender_buffer_reserve(buffer, 64 * 1024);

    line_sender_table_name table_name =
        QDB_TABLE_NAME_LITERAL("market_orders_byte_strides");
    line_sender_column_name symbol_col = QDB_COLUMN_NAME_LITERAL("symbol");
    line_sender_column_name book_col = QDB_COLUMN_NAME_LITERAL("order_book");

    if (!line_sender_buffer_table(buffer, table_name, &err))
        goto on_error;

    line_sender_utf8 symbol_val = QDB_UTF8_LITERAL("BTC-USD");
    if (!line_sender_buffer_symbol(buffer, symbol_col, symbol_val, &err))
        goto on_error;

    size_t array_rank = 3;
    uintptr_t array_shape[] = {2, 3, 2};
    intptr_t array_strides[] = {48, 16, 8};

    double array_data[] = {
        48123.5,
        2.4,
        48124.0,
        1.8,
        48124.5,
        0.9,
        48122.5,
        3.1,
        48122.0,
        2.7,
        48121.5,
        4.3};

    if (!line_sender_buffer_column_f64_arr_byte_strides(
            buffer,
            book_col,
            array_rank,
            array_shape,
            array_strides,
            array_data,
            sizeof(array_data) / sizeof(array_data[0]),
            &err))
        goto on_error;

    if (!line_sender_buffer_at_nanos(buffer, line_sender_now_nanos(), &err))
        goto on_error;

    if (!line_sender_flush(sender, buffer, &err))
        goto on_error;

    line_sender_buffer_free(buffer);
    line_sender_close(sender);
    return true;

on_error:;
    size_t err_len = 0;
    const char* err_msg = line_sender_error_msg(err, &err_len);
    fprintf(stderr, "Error: %.*s\n", (int)err_len, err_msg);
    free(conf_str);
    line_sender_error_free(err);
    line_sender_buffer_free(buffer);
    line_sender_close(sender);
    return false;
}

int main(int argc, const char* argv[])
{
    const char* host = (argc >= 2) ? argv[1] : "localhost";
    const char* port = (argc >= 3) ? argv[2] : "9009";
    return !example(host, port);
}
