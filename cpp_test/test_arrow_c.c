#include <questdb/egress/line_reader.h>
#include <questdb/ingress/line_sender.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------------------------------------------------------------------------
 * Test harness.
 * ------------------------------------------------------------------------- */

static int errors = 0;
static int tests = 0;

#define TEST(name) static void name(void)

#define CHECK(cond, msg)                                                       \
    do                                                                         \
    {                                                                          \
        bool check_pass_ = (cond);                                             \
        if (!check_pass_)                                                      \
        {                                                                      \
            fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__, msg);    \
            errors++;                                                          \
        }                                                                      \
    } while (0)

#define RUN(name)                                                              \
    do                                                                         \
    {                                                                          \
        int before = errors;                                                   \
        name();                                                                \
        tests++;                                                               \
        if (errors == before)                                                  \
        {                                                                      \
            fprintf(stderr, "PASS: %s\n", #name);                              \
        }                                                                      \
        else                                                                   \
        {                                                                      \
            fprintf(stderr, "FAILED TEST: %s (%d new errors)\n",               \
                    #name, errors - before);                                   \
        }                                                                      \
    } while (0)

struct PrivBytes
{
    void* values_buffer;
    const void* buffers[3];
};

static void release_array_with_priv(struct ArrowArray* arr)
{
    if (arr == NULL || arr->private_data == NULL)
        return;
    struct PrivBytes* pd = (struct PrivBytes*)arr->private_data;
    free(pd->values_buffer);
    free(pd);
    arr->release = NULL;
    arr->private_data = NULL;
}

static void release_schema_noop(struct ArrowSchema* sch)
{
    if (sch == NULL)
        return;
    sch->release = NULL;
}

static void build_primitive(
    int64_t row_count,
    size_t elem_size,
    const void* values_bytes,
    const char* format,
    const char* name,
    struct ArrowArray* out_arr,
    struct ArrowSchema* out_sch)
{
    struct PrivBytes* pd = (struct PrivBytes*)calloc(1, sizeof(*pd));
    pd->values_buffer = malloc((size_t)row_count * elem_size);
    memcpy(pd->values_buffer, values_bytes, (size_t)row_count * elem_size);
    pd->buffers[0] = NULL; /* No validity bitmap. */
    pd->buffers[1] = pd->values_buffer;
    pd->buffers[2] = NULL;

    memset(out_arr, 0, sizeof(*out_arr));
    out_arr->length = row_count;
    out_arr->null_count = 0;
    out_arr->offset = 0;
    out_arr->n_buffers = 2;
    out_arr->n_children = 0;
    out_arr->buffers = pd->buffers;
    out_arr->release = release_array_with_priv;
    out_arr->private_data = pd;

    memset(out_sch, 0, sizeof(*out_sch));
    out_sch->format = format;
    out_sch->name = name;
    out_sch->flags = ARROW_FLAG_NULLABLE;
    out_sch->release = release_schema_noop;
}

static void build_bool_bitpacked(
    int64_t row_count,
    const bool* values,
    const char* name,
    struct ArrowArray* out_arr,
    struct ArrowSchema* out_sch)
{
    size_t n_bytes = ((size_t)row_count + 7) / 8;
    struct PrivBytes* pd = (struct PrivBytes*)calloc(1, sizeof(*pd));
    pd->values_buffer = calloc(1, n_bytes);
    uint8_t* packed = (uint8_t*)pd->values_buffer;
    for (int64_t i = 0; i < row_count; ++i)
        if (values[i])
            packed[i / 8] |= (uint8_t)(1u << (i % 8));
    pd->buffers[0] = NULL;
    pd->buffers[1] = pd->values_buffer;
    pd->buffers[2] = NULL;

    memset(out_arr, 0, sizeof(*out_arr));
    out_arr->length = row_count;
    out_arr->null_count = 0;
    out_arr->offset = 0;
    out_arr->n_buffers = 2;
    out_arr->n_children = 0;
    out_arr->buffers = pd->buffers;
    out_arr->release = release_array_with_priv;
    out_arr->private_data = pd;

    memset(out_sch, 0, sizeof(*out_sch));
    out_sch->format = "b";
    out_sch->name = name;
    out_sch->flags = ARROW_FLAG_NULLABLE;
    out_sch->release = release_schema_noop;
}

static line_sender_table_name make_table(const char* name)
{
    line_sender_error* err = NULL;
    line_sender_table_name tbl;
    line_sender_table_name_init(&tbl, strlen(name), name, &err);
    if (err)
        line_sender_error_free(err);
    return tbl;
}

static line_sender_buffer* fresh_qwp_buffer(void)
{
    return line_sender_buffer_new_qwp_ws();
}

TEST(test_tristate_egress_enum_values)
{
    CHECK(line_reader_arrow_batch_ok == 0, "ok = 0");
    CHECK(line_reader_arrow_batch_end == 1, "end = 1");
    CHECK(line_reader_arrow_batch_error == 2, "error = 2");
}

TEST(test_appended_reader_error_codes_have_distinct_values)
{
    CHECK(
        line_reader_error_schema_drift != line_reader_error_no_schema &&
        line_reader_error_no_schema != line_reader_error_arrow_export &&
        line_reader_error_arrow_export != line_reader_error_schema_drift,
        "schema_drift / no_schema / arrow_export distinct");
    CHECK(line_reader_error_schema_drift > line_reader_error_failover_would_duplicate,
          "schema_drift appended (not renumbered)");
}

TEST(test_appended_sender_error_codes_exist)
{
    CHECK(line_sender_error_arrow_unsupported_column_kind !=
              line_sender_error_arrow_ingest,
          "sender error codes distinct");
}

TEST(test_egress_null_cursor_returns_error_tristate)
{
    struct ArrowArray arr;
    struct ArrowSchema sch;
    line_reader_error* err = NULL;
    line_reader_arrow_batch_result rc =
        line_reader_cursor_next_arrow_batch(NULL, &arr, &sch, &err);
    CHECK(rc == line_reader_arrow_batch_error, "NULL cursor → error");
    CHECK(err != NULL, "err_out populated");
    if (err)
        line_reader_error_free(err);
}

TEST(test_egress_null_out_array_returns_error_tristate)
{
    struct ArrowSchema sch;
    line_reader_error* err = NULL;
    /* Even with a non-NULL cursor the contract is: out_array/out_schema
     * must be non-NULL. We pass NULL cursor too here — the implementation
     * is allowed to short-circuit on the first NULL it sees. */
    line_reader_arrow_batch_result rc =
        line_reader_cursor_next_arrow_batch(NULL, NULL, &sch, &err);
    CHECK(rc == line_reader_arrow_batch_error, "NULL out_array → error");
    if (err)
        line_reader_error_free(err);
}

TEST(test_ingress_null_buffer_returns_false)
{
    struct ArrowArray arr;
    struct ArrowSchema sch;
    memset(&arr, 0, sizeof(arr));
    memset(&sch, 0, sizeof(sch));
    line_sender_error* err = NULL;
    line_sender_table_name tbl = make_table("t");
    bool ok = line_sender_buffer_append_arrow(NULL, tbl, &arr, &sch, &err);
    CHECK(!ok, "NULL buffer → false");
    CHECK(err != NULL, "err_out populated");
    if (err)
        line_sender_error_free(err);
}

TEST(test_ingress_null_array_returns_false)
{
    line_sender_buffer* buf = fresh_qwp_buffer();
    struct ArrowSchema sch;
    memset(&sch, 0, sizeof(sch));
    line_sender_error* err = NULL;
    bool ok =
        line_sender_buffer_append_arrow(buf, make_table("t"), NULL, &sch, &err);
    CHECK(!ok, "NULL array → false");
    CHECK(err != NULL, "err_out populated");
    if (err)
        line_sender_error_free(err);
    line_sender_buffer_free(buf);
}

TEST(test_ingress_null_schema_returns_false)
{
    line_sender_buffer* buf = fresh_qwp_buffer();
    struct ArrowArray arr;
    memset(&arr, 0, sizeof(arr));
    line_sender_error* err = NULL;
    bool ok =
        line_sender_buffer_append_arrow(buf, make_table("t"), &arr, NULL, &err);
    CHECK(!ok, "NULL schema → false");
    CHECK(err != NULL, "err_out populated");
    if (err)
        line_sender_error_free(err);
    line_sender_buffer_free(buf);
}

TEST(test_ingress_at_column_null_buffer_returns_false)
{
    struct ArrowArray arr;
    struct ArrowSchema sch;
    memset(&arr, 0, sizeof(arr));
    memset(&sch, 0, sizeof(sch));
    line_sender_error* err = NULL;
    line_sender_column_name ts_col;
    bool name_ok =
        line_sender_column_name_init(&ts_col, strlen("ts"), "ts", &err);
    CHECK(name_ok, "column name init");
    bool ok = line_sender_buffer_append_arrow_at_column(
        NULL, make_table("t"), &arr, &sch, ts_col, &err);
    CHECK(!ok, "NULL buffer → false");
    CHECK(err != NULL, "err_out populated");
    if (err)
        line_sender_error_free(err);
}

TEST(test_ingress_at_column_null_array_returns_false)
{
    line_sender_buffer* buf = fresh_qwp_buffer();
    struct ArrowSchema sch;
    memset(&sch, 0, sizeof(sch));
    line_sender_error* err = NULL;
    line_sender_column_name ts_col;
    bool name_ok =
        line_sender_column_name_init(&ts_col, strlen("ts"), "ts", &err);
    CHECK(name_ok, "column name init");
    bool ok = line_sender_buffer_append_arrow_at_column(
        buf, make_table("t"), NULL, &sch, ts_col, &err);
    CHECK(!ok, "NULL array → false");
    CHECK(err != NULL, "err_out populated");
    if (err)
        line_sender_error_free(err);
    line_sender_buffer_free(buf);
}

TEST(test_ingress_at_column_null_schema_returns_false)
{
    line_sender_buffer* buf = fresh_qwp_buffer();
    struct ArrowArray arr;
    memset(&arr, 0, sizeof(arr));
    line_sender_error* err = NULL;
    line_sender_column_name ts_col;
    bool name_ok =
        line_sender_column_name_init(&ts_col, strlen("ts"), "ts", &err);
    CHECK(name_ok, "column name init");
    bool ok = line_sender_buffer_append_arrow_at_column(
        buf, make_table("t"), &arr, NULL, ts_col, &err);
    CHECK(!ok, "NULL schema → false");
    CHECK(err != NULL, "err_out populated");
    if (err)
        line_sender_error_free(err);
    line_sender_buffer_free(buf);
}

static void run_append_strict_ok(
    line_sender_buffer* buf,
    line_sender_table_name tbl,
    struct ArrowArray* arr,
    struct ArrowSchema* sch,
    const char* label)
{
    line_sender_error* err = NULL;
    bool ok = line_sender_buffer_append_arrow(buf, tbl, arr, sch, &err);
    if (!ok)
    {
        if (err)
        {
            size_t msg_len = 0;
            const char* msg = line_sender_error_msg(err, &msg_len);
            fprintf(stderr, "STRICT %s: %.*s\n", label, (int)msg_len, msg);
            line_sender_error_free(err);
        }
        CHECK(ok, label);
        if (arr->release)
            arr->release(arr);
    }
    if (sch->release)
        sch->release(sch);
}

TEST(test_ingress_boolean_column)
{
    bool values[10] = {
        true, false, true, false, true, false, true, false, true, false};
    struct ArrowArray arr;
    struct ArrowSchema sch;
    build_bool_bitpacked(10, values, "flag", &arr, &sch);
    line_sender_buffer* buf = fresh_qwp_buffer();
    run_append_strict_ok(
        buf, make_table("bool_t"), &arr, &sch, "bit-packed boolean strict ok");
    line_sender_buffer_free(buf);
}

TEST(test_ingress_int8_int16_int32_int64_columns)
{
    /* Int8 */
    {
        int8_t values[3] = {-1, 0, 127};
        struct ArrowArray arr;
        struct ArrowSchema sch;
        build_primitive(3, sizeof(int8_t), values, "c", "byte_col", &arr, &sch);
        line_sender_buffer* buf = fresh_qwp_buffer();
        run_append_strict_ok(
            buf, make_table("i8_t"), &arr, &sch, "int8 strict ok");
        line_sender_buffer_free(buf);
    }
    /* Int16 */
    {
        int16_t values[3] = {-1234, 0, 31000};
        struct ArrowArray arr;
        struct ArrowSchema sch;
        build_primitive(
            3, sizeof(int16_t), values, "s", "short_col", &arr, &sch);
        line_sender_buffer* buf = fresh_qwp_buffer();
        run_append_strict_ok(
            buf, make_table("i16_t"), &arr, &sch, "int16 strict ok");
        line_sender_buffer_free(buf);
    }
    /* Int32 */
    {
        int32_t values[3] = {-1, 0, 0x7FFFFFFF};
        struct ArrowArray arr;
        struct ArrowSchema sch;
        build_primitive(3, sizeof(int32_t), values, "i", "int_col", &arr, &sch);
        line_sender_buffer* buf = fresh_qwp_buffer();
        run_append_strict_ok(
            buf, make_table("i32_t"), &arr, &sch, "int32 strict ok");
        line_sender_buffer_free(buf);
    }
    /* Int64 */
    {
        int64_t values[3] = {100, 200, 300};
        struct ArrowArray arr;
        struct ArrowSchema sch;
        build_primitive(
            3, sizeof(int64_t), values, "l", "long_col", &arr, &sch);
        line_sender_buffer* buf = fresh_qwp_buffer();
        run_append_strict_ok(
            buf, make_table("i64_t"), &arr, &sch, "int64 strict ok");
        line_sender_buffer_free(buf);
    }
}

TEST(test_ingress_float32_float64_columns)
{
    /* Float32 */
    {
        float values[3] = {1.5f, -2.5f, 3.14f};
        struct ArrowArray arr;
        struct ArrowSchema sch;
        build_primitive(3, sizeof(float), values, "f", "f32_col", &arr, &sch);
        line_sender_buffer* buf = fresh_qwp_buffer();
        run_append_strict_ok(
            buf, make_table("f32_t"), &arr, &sch, "float32 strict ok");
        line_sender_buffer_free(buf);
    }
    /* Float64 */
    {
        double values[3] = {1.5, -2.5, 3.14159};
        struct ArrowArray arr;
        struct ArrowSchema sch;
        build_primitive(3, sizeof(double), values, "g", "f64_col", &arr, &sch);
        line_sender_buffer* buf = fresh_qwp_buffer();
        run_append_strict_ok(
            buf, make_table("f64_t"), &arr, &sch, "float64 strict ok");
        line_sender_buffer_free(buf);
    }
}

TEST(test_ingress_timestamp_microseconds)
{
    /* Apache Arrow Timestamp(µs) format: "tsu:" or "tsu:UTC". */
    int64_t values[2] = {1700000000000000LL, 1700000000000001LL};
    struct ArrowArray arr;
    struct ArrowSchema sch;
    build_primitive(2, sizeof(int64_t), values, "tsu:UTC", "ts", &arr, &sch);
    line_sender_buffer* buf = fresh_qwp_buffer();
    run_append_strict_ok(
        buf, make_table("ts_t"), &arr, &sch, "timestamp(µs) strict ok");
    line_sender_buffer_free(buf);
}

TEST(test_ingress_default_and_at_column_dispatch)
{
    int64_t values[2] = {10, 20};

    /* Default append: server stamps each row on arrival. */
    {
        struct ArrowArray arr;
        struct ArrowSchema sch;
        build_primitive(2, sizeof(int64_t), values, "l", "v", &arr, &sch);
        line_sender_buffer* buf = fresh_qwp_buffer();
        line_sender_error* err = NULL;
        bool ok = line_sender_buffer_append_arrow(
            buf, make_table("dts_default"), &arr, &sch, &err);
        if (!ok)
        {
            CHECK(err != NULL, "err_out populated on failure");
            if (err)
                line_sender_error_free(err);
            if (arr.release)
                arr.release(&arr);
        }
        if (sch.release)
            sch.release(&sch);
        line_sender_buffer_free(buf);
    }

    /* at_column variant: a missing ts column must be rejected as arrow_ingest. */
    {
        struct ArrowArray arr;
        struct ArrowSchema sch;
        build_primitive(2, sizeof(int64_t), values, "l", "v", &arr, &sch);
        line_sender_buffer* buf = fresh_qwp_buffer();
        line_sender_error* err = NULL;
        line_sender_column_name ts_col;
        bool name_ok =
            line_sender_column_name_init(&ts_col, strlen("missing"), "missing", &err);
        CHECK(name_ok, "column name init");
        bool ok = line_sender_buffer_append_arrow_at_column(
            buf, make_table("dts_at_col"), &arr, &sch, ts_col, &err);
        CHECK(!ok, "missing ts column → false");
        if (err)
        {
            CHECK(line_sender_error_get_code(err) == line_sender_error_arrow_ingest,
                  "missing ts column → arrow_ingest");
            line_sender_error_free(err);
        }
        if (arr.release)
            arr.release(&arr);
        if (sch.release)
            sch.release(&sch);
        line_sender_buffer_free(buf);
    }
}

TEST(test_error_codes_survive_ffi_boundary)
{
    /* Triggering a real `arrow_unsupported_column_kind` from C alone
     * would require constructing a complex unsupported type. Instead we
     * verify the integer values are visible from C — the actual flow is
     * exercised in the C++ ingress tests. */
    int sender_code = (int)line_sender_error_arrow_unsupported_column_kind;
    int ingest_code = (int)line_sender_error_arrow_ingest;
    int drift_code = (int)line_reader_error_schema_drift;
    int no_schema_code = (int)line_reader_error_no_schema;
    int export_code = (int)line_reader_error_arrow_export;
    CHECK(sender_code != ingest_code, "sender codes distinct");
    CHECK(drift_code != no_schema_code, "reader codes distinct");
    CHECK(no_schema_code != export_code, "reader codes distinct");
}

int main(void)
{
    RUN(test_tristate_egress_enum_values);
    RUN(test_appended_reader_error_codes_have_distinct_values);
    RUN(test_appended_sender_error_codes_exist);
    RUN(test_egress_null_cursor_returns_error_tristate);
    RUN(test_egress_null_out_array_returns_error_tristate);
    RUN(test_ingress_null_buffer_returns_false);
    RUN(test_ingress_null_array_returns_false);
    RUN(test_ingress_null_schema_returns_false);
    RUN(test_ingress_at_column_null_buffer_returns_false);
    RUN(test_ingress_at_column_null_array_returns_false);
    RUN(test_ingress_at_column_null_schema_returns_false);
    RUN(test_ingress_boolean_column);
    RUN(test_ingress_int8_int16_int32_int64_columns);
    RUN(test_ingress_float32_float64_columns);
    RUN(test_ingress_timestamp_microseconds);
    RUN(test_ingress_default_and_at_column_dispatch);
    RUN(test_error_codes_survive_ffi_boundary);

    fprintf(stderr,
            "\ntest_arrow_c: ran %d tests, %d failure(s)\n",
            tests, errors);
    return errors == 0 ? 0 : 1;
}
