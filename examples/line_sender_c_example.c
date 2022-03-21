#include <questdb/line_sender.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

static bool example(const char* host, const char* port)
{
    line_sender_error* err = NULL;
    line_sender* sender = NULL;

    sender = line_sender_connect("0.0.0.0", host, port, &err);
    if (!sender)
        goto on_error;

    if (!line_sender_table(sender, 6, "c_cars", &err))
        goto on_error;

    if (!line_sender_symbol(
        sender,
        2, "id",
        36, "d6e5fe92-d19f-482a-a97a-c105f547f721",
        &err))
        goto on_error;
    
    if (!line_sender_column_f64(sender, 1, "x", 30.5, &err))
        goto on_error;

    if (!line_sender_column_f64(sender, 1, "y", -150.25, &err))
        goto on_error;

    if (!line_sender_column_bool(sender, 6, "booked", true, &err))
        goto on_error;

    if (!line_sender_column_i64(sender, 10, "passengers", 3, &err))
        goto on_error;

    if (!line_sender_column_str(sender, 6, "driver", 12, "Ranjit Singh", &err))
        goto on_error;

    if (!line_sender_at_now(sender, &err))
        goto on_error;

    // To insert more records, call `line_sender_table(..)...` again.

    if (!line_sender_flush(sender, &err))
        goto on_error;

    line_sender_close(sender);

    return true;

on_error: ;
    size_t err_len = 0;
    const char* err_msg = line_sender_error_msg(err, &err_len);
    fprintf(stderr, "Error running example: %.*s\n", (int)err_len, err_msg);
    line_sender_error_free(err);
    if (sender)
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
            fprintf(stderr,"    HOST: ILP host (defaults to \"localhost\".\n");
            fprintf(stderr,"    PORT: ILP port (defaults to \"9009\".\n");
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
