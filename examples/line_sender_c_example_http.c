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
    // Use `https` to enable TLS.
    // Use `username=...;password=...;` or `token=...` for authentication.
    char* conf_str = concat("http::addr=", host, ":", port, ";");
    if (!conf_str) {
        fprintf(stderr, "Could not concatenate configuration string.\n");
        return false;
    }
    line_sender_utf8 conf_str_utf8 = { 0, NULL };
    if (!line_sender_utf8_init(&conf_str_utf8, strlen(conf_str), conf_str, &err))
        goto on_error;

    sender = line_sender_from_conf(conf_str_utf8, &err);
    if (!sender)
        goto on_error;    

    free(conf_str);
    conf_str = NULL;

    buffer = line_sender_buffer_new();
    line_sender_buffer_reserve(buffer, 64 * 1024);  // 64KB buffer initial size.

    // We prepare all our table names and column names in advance.
    // If we're inserting multiple rows, this allows us to avoid
    // re-validating the same strings over and over again.
    line_sender_table_name table_name = QDB_TABLE_NAME_LITERAL("c_cars_http");
    line_sender_column_name id_name = QDB_COLUMN_NAME_LITERAL("id");
    line_sender_column_name x_name = QDB_COLUMN_NAME_LITERAL("x");
    line_sender_column_name y_name = QDB_COLUMN_NAME_LITERAL("y");
    line_sender_column_name booked_name = QDB_COLUMN_NAME_LITERAL("booked");
    line_sender_column_name passengers_name = QDB_COLUMN_NAME_LITERAL(
        "passengers");
    line_sender_column_name driver_name = QDB_COLUMN_NAME_LITERAL("driver");

    if (!line_sender_buffer_table(buffer, table_name, &err))
        goto on_error;

    line_sender_utf8 id_value = QDB_UTF8_LITERAL(
        "d6e5fe92-d19f-482a-a97a-c105f547f721");
    if (!line_sender_buffer_symbol(buffer, id_name, id_value, &err))
        goto on_error;

    if (!line_sender_buffer_column_f64(buffer, x_name, 30.5, &err))
        goto on_error;

    if (!line_sender_buffer_column_f64(buffer, y_name, -150.25, &err))
        goto on_error;

    if (!line_sender_buffer_column_bool(buffer, booked_name, true, &err))
        goto on_error;

    if (!line_sender_buffer_column_i64(buffer, passengers_name, 3, &err))
        goto on_error;

    line_sender_utf8 driver_value = QDB_UTF8_LITERAL("John Doe");
    if (!line_sender_buffer_column_str(buffer, driver_name, driver_value, &err))
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

    return true;

on_error: ;
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
            fprintf(stderr, "line_sender_c_example: [HOST [PORT]]\n");
            fprintf(stderr, "    HOST: ILP host (defaults to \"localhost\").\n");
            fprintf(stderr, "    PORT: HTTP port (defaults to \"9000\").\n");
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
    const char* port = "9000";
    if (argc >= 3)
        port = argv[2];

    return !example(host, port);
}
