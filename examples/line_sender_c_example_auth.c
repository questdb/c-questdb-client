#include <questdb/ilp/line_sender.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

static bool example(const char* host, const char* port)
{
    line_sender_error* err = NULL;
    line_sender_opts* opts = NULL;
    line_sender* sender = NULL;

    // Call `line_sender_opts_new` if instead you have an integer port.
    opts = line_sender_opts_new_service(host, port, &err);
    if (!opts)
        goto on_error;

    // Follow our authentication documentation to generate your own keys:
    // https://questdb.io/docs/reference/api/ilp/authenticate
    if (!line_sender_opts_auth(
        opts,
        "testUser1",                                    // key_id      (kid)
        "5UjEMuA0Pj5pjK8a-fa24dyIf-Es5mYny3oE_Wmus48",  // priv_key    (d)
        "fLKYEaoEb9lrn3nkwLDA-M_xnuFOdSt9y0Z7_vWSHLU",  // pub_key_x   (x)
        "Dt5tbS1dEDMSYfym3fgMv0B99szno-dFc1rYF9t0aac",  // pub_key_y   (y)
        &err))
        goto on_error;

    sender = line_sender_connect(opts, &err);
    line_sender_opts_free(opts);
    if (!sender)
        goto on_error;

    sender = line_sender_connect(opts, &err);
    if (!sender)
        goto on_error;

    // We prepare all our table names and column names in advance.
    // If we're inserting multiple rows, this allows us to avoid
    // re-validating the same strings over and over again.
    line_sender_table_name table_name;
    if (!line_sender_table_name_init(&table_name, 11, "c_cars_auth", &err))
        goto on_error;

    line_sender_column_name id_name;
    if (!line_sender_column_name_init(&id_name, 2, "id", &err))
        goto on_error;

    line_sender_column_name x_name;
    if (!line_sender_column_name_init(&x_name, 1, "x", &err))
        goto on_error;

    line_sender_column_name y_name;
    if (!line_sender_column_name_init(&y_name, 1, "y", &err))
        goto on_error;

    line_sender_column_name booked_name;
    if (!line_sender_column_name_init(&booked_name, 6, "booked", &err))
        goto on_error;

    line_sender_column_name passengers_name;
    if (!line_sender_column_name_init(&passengers_name, 10, "passengers", &err))
        goto on_error;

    line_sender_column_name driver_name;
    if (!line_sender_column_name_init(&driver_name, 6, "driver", &err))
        goto on_error;

    if (!line_sender_table(sender, table_name, &err))
        goto on_error;

    line_sender_utf8 id_value;
    if (!line_sender_utf8_init(
        &id_value,
        36,
        "d6e5fe92-d19f-482a-a97a-c105f547f721",
        &err))
        goto on_error;

    if (!line_sender_symbol(sender, id_name, id_value, &err))
        goto on_error;

    if (!line_sender_column_f64(sender, x_name, 30.5, &err))
        goto on_error;

    if (!line_sender_column_f64(sender, y_name, -150.25, &err))
        goto on_error;

    if (!line_sender_column_bool(sender, booked_name, true, &err))
        goto on_error;

    if (!line_sender_column_i64(sender, passengers_name, 3, &err))
        goto on_error;

    line_sender_utf8 driver_value;
    if (!line_sender_utf8_init(
        &driver_value,
        12,
        "Ranjit Singh",
        &err))
        goto on_error;

    if (!line_sender_column_str(sender, driver_name, driver_value, &err))
        goto on_error;

    if (!line_sender_at_now(sender, &err))
        goto on_error;

    // To insert more records, call `line_sender_table(..)...` again.

    if (!line_sender_flush(sender, &err))
        goto on_error;

    line_sender_close(sender);

    return true;

on_error: ;
    line_sender_opts_free(opts);
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
            fprintf(stderr, "line_sender_c_example_auth: [HOST [PORT]]\n");
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
