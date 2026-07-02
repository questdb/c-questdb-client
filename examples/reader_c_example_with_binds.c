#include <questdb/egress/reader.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, const char* argv[])
{
    (void)argc;
    (void)argv;

    reader_error* err = NULL;
    reader* reader = NULL;
    reader_query* query = NULL;
    reader_cursor* cursor = NULL;

    line_sender_utf8 conf = QDB_UTF8_LITERAL("ws::addr=localhost:9000;");
    reader = reader_from_conf(conf, &err);
    if (!reader)
        goto on_error;

    /* SQL with two placeholders: $1 = INT, $2 = VARCHAR. */
    line_sender_utf8 sql = QDB_UTF8_LITERAL(
        "SELECT $1::int * x AS scaled, $2 AS label FROM long_sequence(3)");

    query = reader_prepare(reader, sql, &err);
    if (!query)
        goto on_error;

    reader_query_bind_i32(query, 7);
    reader_query_bind_varchar(query, QDB_UTF8_LITERAL("widgets"));

    cursor = reader_query_execute(&query, &err);
    /* `query` is now NULL — `_query_execute` consumed it. */
    if (!cursor)
        goto on_error;

    const reader_batch* batch;
    while ((batch = reader_cursor_next_batch(cursor, &err)) != NULL)
    {
        const size_t rows = reader_batch_row_count(batch);

        reader_column_data d_scaled, d_label;
        if (!reader_batch_column_data(batch, 0, &d_scaled, &err))
            goto on_error;
        if (!reader_batch_column_data(batch, 1, &d_label, &err))
            goto on_error;

        for (size_t r = 0; r < rows; ++r)
        {
            bool n_null = false;
            const int64_t scaled =
                reader_column_data_get_i64(&d_scaled, r, &n_null);

            bool s_null = false;
            const uint8_t* label_buf = NULL;
            size_t label_len = 0;
            reader_column_data_get_varlen(
                &d_label, r, &label_buf, &label_len, &s_null);

            // Print "NULL" rather than substituting a sentinel value:
            // a literal `0` for an i64 column or an empty string for a
            // varchar column would silently mask SQL NULLs in
            // production output. Always branch on the *_null flag.
            if (n_null)
                printf("scaled=NULL");
            else
                printf("scaled=%lld", (long long)scaled);
            if (s_null)
                printf(" label=NULL\n");
            else
                printf(" label=%.*s\n", (int)label_len, (const char*)label_buf);
        }
    }
    if (err)
        goto on_error;

    reader_cursor_free(cursor);
    reader_close(reader);
    return 0;

on_error:;
    size_t err_len = 0;
    const char* err_msg = reader_error_msg(err, &err_len);
    fprintf(stderr, "Error: %.*s\n", (int)err_len, err_msg);
    reader_error_free(err);
    reader_query_free(query);
    reader_cursor_free(cursor);
    reader_close(reader);
    return 1;
}
