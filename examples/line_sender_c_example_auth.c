#include <questdb/ilp/line_sender.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

static bool example(const char* host, const char* port)
{
    line_sender_error* err = NULL;
    line_sender_opts* opts = NULL;
    line_sender* sender = NULL;

    // Declare and validate a UTF-8 string from a `const char*`.
    // This macro expands to:
    //     line_sender_utf8 host_utf8;
    //     const char* host_utf8____STR_EXPR = (host);
    //     if (!line_sender_utf8_init(
    //             &host_utf8,
    //             strlen(host_utf8____STR_EXPR),
    //             host_utf8____STR_EXPR,
    //             &err))
    //         goto on_error;
    QDB_UTF_8_FROM_STR_OR(host_utf8, host, &err)
        goto on_error;

    QDB_UTF_8_FROM_STR_OR(port_utf8, port, &err)
        goto on_error;

    // Call `line_sender_opts_new` if instead you have an integer port.
    opts = line_sender_opts_new_service(host_utf8, port_utf8);

    QDB_UTF8_FROM_LIT_OR(
            key_id,
            "testUser1",
            &err)
        goto on_error;

    QDB_UTF8_FROM_LIT_OR(
            priv_key,
            "5UjEMuA0Pj5pjK8a-fa24dyIf-Es5mYny3oE_Wmus48",
            &err)
        goto on_error;

    QDB_UTF8_FROM_LIT_OR(
            pub_key_x,
            "fLKYEaoEb9lrn3nkwLDA-M_xnuFOdSt9y0Z7_vWSHLU",
            &err)
        goto on_error;

    QDB_UTF8_FROM_LIT_OR(
            pub_key_y,
            "Dt5tbS1dEDMSYfym3fgMv0B99szno-dFc1rYF9t0aac",
            &err)
        goto on_error;

    line_sender_opts_auth(
        opts,
        key_id,      // kid
        priv_key,    // d
        pub_key_x,   // x
        pub_key_y);  // y
    sender = line_sender_connect(opts, &err);
    line_sender_opts_free(opts);
    opts = NULL;
    if (!sender)
        goto on_error;

    // We prepare all our table names and column names in advance.
    // If we're inserting multiple rows, this allows us to avoid
    // re-validating the same strings over and over again.

    // This macro expands to:
    //     line_sender_table_name table_name;
    //     if (!line_sender_table_name_init(
    //             &table_name,
    //             sizeof("c_cars_auth") - 1,
    //             "c_cars_auth",
    //             &err))
    //         goto on_error;
    QDB_TABLE_NAME_FROM_LIT_OR(table_name, "c_cars_auth", &err)
        goto on_error;

    // Same, but for the `line_sender_column_name` type.
    QDB_COLUMN_NAME_FROM_LIT_OR(id_name, "id", &err)
        goto on_error;

    QDB_COLUMN_NAME_FROM_LIT_OR(x_name, "x", &err)
        goto on_error;

    QDB_COLUMN_NAME_FROM_LIT_OR(y_name, "y", &err)
        goto on_error;

    QDB_COLUMN_NAME_FROM_LIT_OR(booked_name, "booked", &err)
        goto on_error;

    QDB_COLUMN_NAME_FROM_LIT_OR(passengers_name, "passengers", &err)
        goto on_error;

    QDB_COLUMN_NAME_FROM_LIT_OR(driver_name, "driver", &err)
        goto on_error;

    if (!line_sender_table(sender, table_name, &err))
        goto on_error;

    QDB_UTF8_FROM_LIT_OR(id_value, "d6e5fe92-d19f-482a-a97a-c105f547f721", &err)
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

    QDB_UTF8_FROM_LIT_OR(driver_value, "Ranjit Singh", &err)
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
