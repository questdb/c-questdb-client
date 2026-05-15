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

    line_reader_column_kind kind;

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

    int rc;
    while ((rc = line_reader_cursor_next_batch(cursor, &err)) == 1)
    {
        const size_t rows = line_reader_cursor_row_count(cursor);
        const size_t cols = line_reader_cursor_column_count(cursor);

        for (size_t r = 0; r < rows; ++r)
        {
            for (size_t c = 0; c < cols; ++c)
            {
                if (!line_reader_cursor_column_kind(cursor, c, &kind, &err))
                    goto on_error;

                bool is_null = false;
                if (kind == line_reader_column_kind_long)
                {
                    int64_t v = 0;
                    if (!line_reader_cursor_get_i64(
                            cursor, c, r, &v, &is_null, &err))
                        goto on_error;
                    if (is_null)
                        printf("NULL ");
                    else
                        printf("%lld ", (long long)v);
                }
                else if (kind == line_reader_column_kind_double)
                {
                    double v = 0.0;
                    if (!line_reader_cursor_get_f64(
                            cursor, c, r, &v, &is_null, &err))
                        goto on_error;
                    if (is_null)
                        printf("NULL ");
                    else
                        printf("%g ", v);
                }
                else
                {
                    // Illustrative fallback for this minimal example.
                    // Production code should call the matching
                    // `line_reader_cursor_get_*` for every column kind
                    // returned by your query (timestamp, varchar, uuid,
                    // decimal*, geohash, ipv4, etc.) — printing the
                    // opaque hex byte here just keeps the example
                    // short. See `line_reader_column_kind` in
                    // `line_reader.h` for the full enumeration.
                    printf("(kind=0x%02X) ", (unsigned)kind);
                }
            }
            printf("\n");
        }
    }
    if (rc < 0)
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
