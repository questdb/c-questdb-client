#include <questdb/egress/line_reader.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>

int main(int argc, const char* argv[])
{
    (void)argc;
    (void)argv;

    line_reader_error* err = NULL;
    line_reader* reader = NULL;
    line_reader_query* query = NULL;
    line_reader_cursor* cursor = NULL;

    line_sender_utf8 conf = QDB_UTF8_LITERAL("ws::addr=localhost:9000;");
    reader = line_reader_from_conf(conf, &err);
    if (!reader)
        goto on_error;

    line_sender_utf8 sql = QDB_UTF8_LITERAL(
        "SELECT x AS n, x * 1.5 AS d FROM long_sequence(5)");
    query = line_reader_prepare(reader, sql, &err);
    if (!query)
        goto on_error;
    cursor = line_reader_query_execute(&query, &err);
    /* `query` is now NULL — `_query_execute` consumed it. */
    if (!cursor)
        goto on_error;

    const line_reader_batch* batch;
    while ((batch = line_reader_cursor_next_batch(cursor, &err)) != NULL)
    {
        const size_t rows = line_reader_batch_row_count(batch);
        const size_t cols = line_reader_batch_column_count(batch);

        /* Project every column once per batch; index per row below. */
        line_reader_column_data d[2];
        if (cols > sizeof(d) / sizeof(d[0]))
        {
            fprintf(stderr, "example expects at most 2 columns\n");
            goto on_error;
        }
        for (size_t c = 0; c < cols; ++c)
            if (!line_reader_batch_column_data(batch, c, &d[c], &err))
                goto on_error;

        for (size_t r = 0; r < rows; ++r)
        {
            for (size_t c = 0; c < cols; ++c)
            {
                bool is_null = false;
                switch (d[c].kind)
                {
                case line_reader_column_kind_long:
                {
                    int64_t v =
                        line_reader_column_data_get_i64(&d[c], r, &is_null);
                    if (is_null)
                        printf("NULL ");
                    else
                        printf("%lld ", (long long)v);
                    break;
                }
                case line_reader_column_kind_double:
                {
                    double v =
                        line_reader_column_data_get_f64(&d[c], r, &is_null);
                    if (is_null)
                        printf("NULL ");
                    else
                        printf("%g ", v);
                    break;
                }
                default:
                    /* Real code dispatches every kind; printing the opaque
                     * kind code keeps the example short. */
                    printf("(kind=0x%02X) ", (unsigned)d[c].kind);
                }
            }
            printf("\n");
        }
    }
    if (err)
        goto on_error;

    line_reader_cursor_free(cursor);
    line_reader_close(reader);
    return 0;

on_error:;
    size_t err_len = 0;
    const char* err_msg = line_reader_error_msg(err, &err_len);
    fprintf(stderr, "Error: %.*s\n", (int)err_len, err_msg);
    line_reader_error_free(err);
    line_reader_cursor_free(cursor);
    line_reader_close(reader);
    return 1;
}
