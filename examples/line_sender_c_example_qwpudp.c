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
    line_sender_column_name retries_name = QDB_COLUMN_NAME_LITERAL("retries");
    line_sender_column_name port_name = QDB_COLUMN_NAME_LITERAL("port");
    line_sender_column_name region_name = QDB_COLUMN_NAME_LITERAL("region");
    line_sender_column_name temp_name = QDB_COLUMN_NAME_LITERAL("temp");
    line_sender_column_name temp_f_name = QDB_COLUMN_NAME_LITERAL("temp_f");
    line_sender_column_name trace_id_name = QDB_COLUMN_NAME_LITERAL("trace_id");
    line_sender_column_name client_ip_name = QDB_COLUMN_NAME_LITERAL("client_ip");
    line_sender_column_name first_seen_name =
        QDB_COLUMN_NAME_LITERAL("first_seen");
    line_sender_column_name price_name = QDB_COLUMN_NAME_LITERAL("price");
    line_sender_column_name loc_name = QDB_COLUMN_NAME_LITERAL("loc");
    line_sender_column_name note_name = QDB_COLUMN_NAME_LITERAL("note");

    if (!line_sender_buffer_table(buffer, table_name, &err))
        goto on_error;

    line_sender_utf8 host_value = QDB_UTF8_LITERAL("srv-api");
    if (!line_sender_buffer_symbol(buffer, host_name, host_value, &err))
        goto on_error;
    if (!line_sender_buffer_column_bool(buffer, active_name, true, &err))
        goto on_error;
    if (!line_sender_buffer_column_i64(buffer, qty_name, 7, &err))
        goto on_error;
    if (!line_sender_buffer_column_i8(buffer, retries_name, 3, &err))
        goto on_error;
    if (!line_sender_buffer_column_i16(buffer, port_name, 9009, &err))
        goto on_error;
    if (!line_sender_buffer_column_i32(buffer, region_name, 42, &err))
        goto on_error;
    if (!line_sender_buffer_column_f64(buffer, temp_name, 21.5, &err))
        goto on_error;
    if (!line_sender_buffer_column_f32(buffer, temp_f_name, 21.5f, &err))
        goto on_error;
    if (!line_sender_buffer_column_uuid(
            buffer,
            trace_id_name,
            0x0102030405060708ULL,
            0x090A0B0C0D0E0F10ULL,
            &err))
        goto on_error;
    if (!line_sender_buffer_column_ipv4(
            buffer, client_ip_name, 0xC0A8012AU, &err))
        goto on_error;
    if (!line_sender_buffer_column_date(
            buffer, first_seen_name, 1700000000000LL, &err))
        goto on_error;
    line_sender_utf8 price_value = QDB_UTF8_LITERAL("1.25");
    if (!line_sender_buffer_column_dec64_str(
            buffer, price_name, price_value.buf, price_value.len, &err))
        goto on_error;
    if (!line_sender_buffer_column_geohash(
            buffer, loc_name, 0x012EA85BULL, 25, &err))
        goto on_error;

    line_sender_utf8 note_value = QDB_UTF8_LITERAL("example-row");
    if (!line_sender_buffer_column_str(buffer, note_name, note_value, &err))
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
                "line_sender_c_example_qwpudp: [HOST [PORT [TABLE]]]\n");
            fprintf(
                stderr,
                "    HOST: QWP/UDP host (defaults to \"localhost\").\n");
            fprintf(
                stderr,
                "    PORT: QWP/UDP port (defaults to \"9007\").\n");
            fprintf(
                stderr,
                "    TABLE: Target table (defaults to \"c_qwpudp_example\").\n");
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
    const char* table = "c_qwpudp_example";
    if (argc >= 4)
        table = argv[3];

    return !example(host, port, table);
}
