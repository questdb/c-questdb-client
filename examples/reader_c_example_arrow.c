#include <questdb/egress/reader.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static void print_batch(const struct ArrowArray* arr, const struct ArrowSchema* sch)
{
    for (int64_t c = 0; c < sch->n_children; ++c)
    {
        if (c != 0)
            printf("\t");
        printf("%s", sch->children[c]->name ? sch->children[c]->name : "");
    }
    printf("\n");

    for (int64_t r = 0; r < arr->length; ++r)
    {
        for (int64_t c = 0; c < arr->n_children; ++c)
        {
            const struct ArrowArray* col = arr->children[c];
            const char* fmt = sch->children[c]->format;
            if (c != 0)
                printf("\t");

            if (strcmp(fmt, "l") == 0 || strcmp(fmt, "i") == 0)
            {
                int64_t v;
                if (fmt[0] == 'l')
                    v = ((const int64_t*)col->buffers[1])[r + col->offset];
                else
                    v = ((const int32_t*)col->buffers[1])[r + col->offset];
                printf("%" PRId64, v);
            }
            else if (strcmp(fmt, "g") == 0 || strcmp(fmt, "f") == 0)
            {
                double v;
                if (fmt[0] == 'g')
                    v = ((const double*)col->buffers[1])[r + col->offset];
                else
                    v = ((const float*)col->buffers[1])[r + col->offset];
                printf("%g", v);
            }
            else
            {
                printf("(format=%s)", fmt);
            }
        }
        printf("\n");
    }
}

int main(int argc, const char* argv[])
{
    (void)argc;
    (void)argv;

    questdb_error* err = NULL;
    reader* reader = NULL;
    reader_cursor* cursor = NULL;

    line_sender_utf8 conf = QDB_UTF8_LITERAL("ws::addr=localhost:9000;");
    reader = reader_from_conf(conf, &err);
    if (!reader)
        goto on_error;

    line_sender_utf8 sql = QDB_UTF8_LITERAL(
        "SELECT x AS n, x * 1.5 AS d FROM long_sequence(5)");
    cursor = reader_execute(reader, sql, &err);
    if (!cursor)
        goto on_error;

    for (;;)
    {
        struct ArrowArray arr;
        struct ArrowSchema sch;
        reader_arrow_batch_result rc =
            reader_cursor_next_arrow_batch(cursor, &arr, &sch, &err);
        if (rc == reader_arrow_batch_end)
            break;
        if (rc == reader_arrow_batch_error)
            goto on_error;

        print_batch(&arr, &sch);

        if (arr.release)
            arr.release(&arr);
        if (sch.release)
            sch.release(&sch);
    }

    reader_cursor_free(cursor);
    reader_close(reader);
    return 0;

on_error:;
    size_t err_len = 0;
    const char* err_msg = questdb_error_msg(err, &err_len);
    fprintf(stderr, "Error: %.*s\n", (int)err_len, err_msg);
    questdb_error_free(err);
    reader_cursor_free(cursor);
    reader_close(reader);
    return 1;
}
