#include <questdb/ingress/line_sender.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static bool example(const char* host, const char* port, const char* table)
{
    line_sender_error* err = NULL;
    line_sender* sender = NULL;
    line_sender_buffer* buffer = NULL;

    char conf_str[256];
    int conf_len = snprintf(
        conf_str,
        sizeof(conf_str),
        "qwpudp::addr=%s:%s;max_datagram_size=256;",
        host,
        port);
    if ((conf_len < 0) || ((size_t)conf_len >= sizeof(conf_str)))
    {
        fprintf(stderr, "Could not construct configuration string.\n");
        return false;
    }

    line_sender_utf8 conf_str_utf8 = {0, NULL};
    if (!line_sender_utf8_init(
            &conf_str_utf8, strlen(conf_str), conf_str, &err))
        goto on_error;

    sender = line_sender_from_conf(conf_str_utf8, &err);
    if (!sender)
        goto on_error;

    buffer = line_sender_buffer_new_for_sender(sender);
    if (!buffer)
        goto on_error;

    line_sender_table_name table_name = {0, NULL};
    if (!line_sender_table_name_init(&table_name, strlen(table), table, &err))
        goto on_error;
    line_sender_column_name host_name = QDB_COLUMN_NAME_LITERAL("host");
    line_sender_column_name active_name = QDB_COLUMN_NAME_LITERAL("active");
    line_sender_column_name qty_name = QDB_COLUMN_NAME_LITERAL("qty");
    line_sender_column_name temp_name = QDB_COLUMN_NAME_LITERAL("temp");
    line_sender_column_name note_name = QDB_COLUMN_NAME_LITERAL("note");

    if (!line_sender_buffer_table(buffer, table_name, &err))
        goto on_error;

    line_sender_utf8 host_a = QDB_UTF8_LITERAL("srv-a");
    if (!line_sender_buffer_symbol(buffer, host_name, host_a, &err))
        goto on_error;
    if (!line_sender_buffer_column_bool(buffer, active_name, true, &err))
        goto on_error;
    if (!line_sender_buffer_column_i64(buffer, qty_name, 1, &err))
        goto on_error;
    if (!line_sender_buffer_column_f64(buffer, temp_name, 20.5, &err))
        goto on_error;
    line_sender_utf8 note_a = QDB_UTF8_LITERAL("batch-a");
    if (!line_sender_buffer_column_str(buffer, note_name, note_a, &err))
        goto on_error;
    if (!line_sender_buffer_at_now(buffer, &err))
        goto on_error;

    if (!line_sender_buffer_table(buffer, table_name, &err))
        goto on_error;
    line_sender_utf8 host_b = QDB_UTF8_LITERAL("srv-b");
    if (!line_sender_buffer_symbol(buffer, host_name, host_b, &err))
        goto on_error;
    if (!line_sender_buffer_column_bool(buffer, active_name, false, &err))
        goto on_error;
    if (!line_sender_buffer_column_i64(buffer, qty_name, 2, &err))
        goto on_error;
    if (!line_sender_buffer_column_f64(buffer, temp_name, 22.5, &err))
        goto on_error;
    line_sender_utf8 note_b = QDB_UTF8_LITERAL("batch-b");
    if (!line_sender_buffer_column_str(buffer, note_name, note_b, &err))
        goto on_error;
    if (!line_sender_buffer_at_now(buffer, &err))
        goto on_error;

    if (!line_sender_flush(sender, buffer, &err))
        goto on_error;

    line_sender_buffer_free(buffer);
    line_sender_close(sender);
    return true;

on_error:
    if (err)
    {
        size_t err_len = 0;
        const char* err_msg = line_sender_error_msg(err, &err_len);
        fprintf(stderr, "Error running example: %.*s\n", (int)err_len, err_msg);
        line_sender_error_free(err);
    }
    line_sender_buffer_free(buffer);
    line_sender_close(sender);
    return false;
}

static bool displayed_help(int argc, const char* argv[])
{
    for (int index = 1; index < argc; ++index)
    {
        const char* arg = argv[index];
        if ((strcmp(arg, "-h") == 0) || (strcmp(arg, "--help") == 0))
        {
            fprintf(stderr, "Usage:\n");
            fprintf(
                stderr,
                "line_sender_c_example_qwpudp_batch: [HOST [PORT [TABLE]]]\n");
            fprintf(
                stderr,
                "    HOST: QWP/UDP host (defaults to \"localhost\").\n");
            fprintf(
                stderr,
                "    PORT: QWP/UDP port (defaults to \"9007\").\n");
            fprintf(
                stderr,
                "    TABLE: Target table (defaults to \"c_qwpudp_batch_example\").\n");
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
    const char* port = "9007";
    if (argc >= 3)
        port = argv[2];
    const char* table = "c_qwpudp_batch_example";
    if (argc >= 4)
        table = argv[3];

    return !example(host, port, table);
}
