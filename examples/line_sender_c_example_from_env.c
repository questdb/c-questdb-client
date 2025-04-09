#include <questdb/ingress/line_sender.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

int main(int argc, const char* argv[])
{
    line_sender_error* err = NULL;
    line_sender_buffer* buffer = NULL;

    // Construct a sender from the `QDB_CLIENT_CONF` environment variable.
    line_sender* sender = line_sender_from_env(&err);
    if (!sender)
        goto on_error;

    buffer = line_sender_buffer_new();
    line_sender_buffer_reserve(buffer, 64 * 1024);  // 64KB buffer initial size.

    // We prepare all our table names and column names in advance.
    // If we're inserting multiple rows, this allows us to avoid
    // re-validating the same strings over and over again.
    line_sender_table_name table_name = QDB_TABLE_NAME_LITERAL("c_trades_from_env");
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

    if (!line_sender_buffer_column_f64(buffer, price_name, 2615.54, &err))
        goto on_error;

    if (!line_sender_buffer_column_f64(buffer, amount_name, 0.00044, &err))
        goto on_error;

    line_sender_column_name arr_name = QDB_COLUMN_NAME_LITERAL("order_book");
    // 3D array of doubles
    size_t rank = 3;
    uint32_t shapes[] = {2, 3, 2};
    int32_t strides[] = {48, 16, 8};
    double arr_data[] = {
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
    if (!line_sender_buffer_column_f64_arr(
            buffer,
            arr_name,
            rank,
            shapes,
            strides,
            (const uint8_t*)arr_data,
            sizeof(arr_data),
            &err))
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

    line_sender_close(sender);

    return 0;

on_error: ;
    size_t err_len = 0;
    const char* err_msg = line_sender_error_msg(err, &err_len);
    fprintf(stderr, "Error running example: %.*s\n", (int)err_len, err_msg);
    line_sender_error_free(err);
    line_sender_buffer_free(buffer);
    line_sender_close(sender);
    return 1;
}
