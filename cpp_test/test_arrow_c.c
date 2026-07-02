/* C ABI FFI-boundary tests for the conn-level Arrow batch ingest API
 * (`column_sender_flush_arrow_batch_at_now[_at_column]`) and the unchanged
 * egress reader API. Successful round-trip coverage lives in the Rust
 * unit tests under `questdb-rs/src/ingress/column_sender/arrow_batch.rs`
 * and the Python system tests under `system_test/`. */

#include <questdb/ingress/column_sender.h>
#include <questdb/egress/reader.h>
#include <questdb/ingress/line_sender.h>

#include "qwp_mock_c.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static line_sender_table_name make_table(const char* name)
{
    line_sender_error* err = NULL;
    line_sender_table_name tbl;
    line_sender_table_name_init(&tbl, strlen(name), name, &err);
    if (err)
        line_sender_error_free(err);
    return tbl;
}

static line_sender_column_name make_col(const char* name)
{
    line_sender_error* err = NULL;
    line_sender_column_name col;
    line_sender_column_name_init(&col, strlen(name), name, &err);
    if (err)
        line_sender_error_free(err);
    return col;
}

TEST(test_tristate_egress_enum_values)
{
    CHECK(reader_arrow_batch_ok == 0, "ok = 0");
    CHECK(reader_arrow_batch_end == 1, "end = 1");
    CHECK(reader_arrow_batch_error == 2, "error = 2");
}

TEST(test_appended_reader_error_codes_have_distinct_values)
{
    CHECK(
        reader_error_schema_drift != reader_error_no_schema &&
        reader_error_no_schema != reader_error_arrow_export &&
        reader_error_arrow_export != reader_error_schema_drift,
        "schema_drift / no_schema / arrow_export distinct");
    CHECK(reader_error_schema_drift > reader_error_failover_would_duplicate,
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
    reader_error* err = NULL;
    reader_arrow_batch_result rc =
        reader_cursor_next_arrow_batch(NULL, &arr, &sch, &err);
    CHECK(rc == reader_arrow_batch_error, "NULL cursor → error");
    CHECK(err != NULL, "err_out populated");
    if (err)
        reader_error_free(err);
}

TEST(test_egress_null_out_array_returns_error_tristate)
{
    struct ArrowSchema sch;
    reader_error* err = NULL;
    reader_arrow_batch_result rc =
        reader_cursor_next_arrow_batch(NULL, NULL, &sch, &err);
    CHECK(rc == reader_arrow_batch_error, "NULL out_array → error");
    if (err)
        reader_error_free(err);
}

TEST(test_ingress_null_conn_returns_false)
{
    struct ArrowArray arr;
    struct ArrowSchema sch;
    memset(&arr, 0, sizeof(arr));
    memset(&sch, 0, sizeof(sch));
    line_sender_error* err = NULL;
    line_sender_table_name tbl = make_table("t");
    bool ok = column_sender_flush_arrow_batch_at_now(
        NULL, tbl, &arr, &sch, NULL, 0, &err);
    CHECK(!ok, "NULL conn → false");
    CHECK(err != NULL, "err_out populated");
    if (err)
    {
        CHECK(
            line_sender_error_get_code(err) ==
                line_sender_error_invalid_api_call,
            "NULL conn → invalid_api_call");
        line_sender_error_free(err);
    }
}

TEST(test_ingress_null_array_returns_false)
{
    struct ArrowSchema sch;
    memset(&sch, 0, sizeof(sch));
    line_sender_error* err = NULL;
    /* `conn == NULL` short-circuits before array/schema validation, so
     * pre-construct an invalid-but-non-NULL conn pointer test by exercising
     * the NULL-array path through the conn-NULL branch first: the impl
     * checks conn before array. To validate the NULL-array branch we'd
     * need a real conn, which requires a live mock server. Coverage moved
     * to Rust unit tests. */
    bool ok = column_sender_flush_arrow_batch_at_now(
        NULL, make_table("t"), NULL, &sch, NULL, 0, &err);
    CHECK(!ok, "NULL array path through NULL-conn short-circuit");
    if (err)
        line_sender_error_free(err);
}

TEST(test_ingress_at_column_null_conn_returns_false)
{
    struct ArrowArray arr;
    struct ArrowSchema sch;
    memset(&arr, 0, sizeof(arr));
    memset(&sch, 0, sizeof(sch));
    line_sender_error* err = NULL;
    bool ok = column_sender_flush_arrow_batch_at_column(
        NULL, make_table("t"), &arr, &sch, make_col("ts"),
        NULL, 0, &err);
    CHECK(!ok, "NULL conn → false");
    CHECK(err != NULL, "err_out populated");
    if (err)
    {
        CHECK(
            line_sender_error_get_code(err) ==
                line_sender_error_invalid_api_call,
            "NULL conn → invalid_api_call");
        line_sender_error_free(err);
    }
}

/* -- Per-column Arrow appender (column_sender_chunk_append_arrow_column) -- */

static void noop_array_release(struct ArrowArray* a)
{
    a->release = NULL;
}

static void noop_schema_release(struct ArrowSchema* s)
{
    s->release = NULL;
}

TEST(test_chunk_append_arrow_column_null_chunk)
{
    struct ArrowArray arr;
    struct ArrowSchema sch;
    memset(&arr, 0, sizeof(arr));
    memset(&sch, 0, sizeof(sch));
    line_sender_error* err = NULL;
    bool ok = column_sender_chunk_append_arrow_column(
        NULL, "v", 1, &arr, &sch, 0, 0, &err);
    CHECK(!ok, "NULL chunk → false");
    CHECK(err != NULL, "err_out populated");
    if (err)
    {
        CHECK(
            line_sender_error_get_code(err) ==
                line_sender_error_invalid_api_call,
            "NULL chunk → invalid_api_call");
        line_sender_error_free(err);
    }
}

TEST(test_chunk_append_arrow_column_null_array_schema)
{
    line_sender_error* err = NULL;
    column_sender_chunk* chunk = column_sender_chunk_new("t", 1, &err);
    CHECK(chunk != NULL, "chunk constructed");
    CHECK(err == NULL, "no err on chunk_new");
    if (!chunk)
        return;
    bool ok = column_sender_chunk_append_arrow_column(
        chunk, "v", 1, NULL, NULL, 0, 0, &err);
    CHECK(!ok, "NULL array+schema → false");
    CHECK(err != NULL, "err_out populated");
    if (err)
    {
        CHECK(
            line_sender_error_get_code(err) ==
                line_sender_error_invalid_api_call,
            "NULL array+schema → invalid_api_call");
        line_sender_error_free(err);
    }
    column_sender_chunk_free(chunk);
}

TEST(test_chunk_append_arrow_column_valid_i64_smoke)
{
    line_sender_error* err = NULL;
    column_sender_chunk* chunk = column_sender_chunk_new("t", 1, &err);
    CHECK(chunk != NULL, "chunk constructed");
    if (!chunk)
        return;

    /* Minimal Arrow C Data Interface i64 array with one row. */
    static int64_t one = 1;
    static const void* buffers[2];
    buffers[0] = NULL; /* validity */
    buffers[1] = &one; /* values */

    struct ArrowArray arr;
    memset(&arr, 0, sizeof(arr));
    arr.length = 1;
    arr.null_count = 0;
    arr.offset = 0;
    arr.n_buffers = 2;
    arr.n_children = 0;
    arr.buffers = buffers;
    arr.children = NULL;
    arr.dictionary = NULL;
    arr.release = noop_array_release;
    arr.private_data = NULL;

    struct ArrowSchema sch;
    memset(&sch, 0, sizeof(sch));
    sch.format = "l";
    sch.name = "v";
    sch.metadata = NULL;
    sch.flags = 0;
    sch.n_children = 0;
    sch.children = NULL;
    sch.dictionary = NULL;
    sch.release = noop_schema_release;
    sch.private_data = NULL;

    bool ok = column_sender_chunk_append_arrow_column(
        chunk, "v", 1, &arr, &sch, 0, 1, &err);
    CHECK(ok, "valid i64 append → true");
    CHECK(err == NULL, "no err on success");
    if (err)
        line_sender_error_free(err);
    CHECK(column_sender_chunk_row_count(chunk, NULL) == 1, "row_count == 1");
    column_sender_chunk_free(chunk);
}

static column_sender_chunk* make_chunk_t(void)
{
    line_sender_error* err = NULL;
    column_sender_chunk* chunk = column_sender_chunk_new("t", 1, &err);
    if (err)
        line_sender_error_free(err);
    return chunk;
}

/* Non-owning assertion helper. The caller must free err after all checks. */
static void assert_invalid_api_call(line_sender_error* err, const char* tag)
{
    CHECK(err != NULL, tag);
    if (err)
    {
        CHECK(
            line_sender_error_get_code(err) ==
                line_sender_error_invalid_api_call,
            "code == invalid_api_call");
    }
}

static bool err_msg_contains(line_sender_error* err, const char* needle)
{
    size_t len = 0;
    const char* msg = line_sender_error_msg(err, &len);
    if (!msg || len == 0)
        return false;
    size_t nlen = strlen(needle);
    if (nlen > len)
        return false;
    for (size_t i = 0; i + nlen <= len; ++i)
    {
        if (memcmp(msg + i, needle, nlen) == 0)
            return true;
    }
    return false;
}

TEST(test_chunk_append_numpy_column_null_chunk)
{
    int64_t data[] = {1, 2, 3};
    line_sender_error* err = NULL;
    bool ok = column_sender_chunk_append_numpy_column(
        NULL,
        "v",
        1,
        column_sender_numpy_i64,
        (const uint8_t*)data,
        sizeof(data),
        3,
        NULL,
        NULL,
        &err);
    CHECK(!ok, "NULL chunk → false");
    assert_invalid_api_call(err, "NULL chunk → invalid_api_call");
    if (err)
        line_sender_error_free(err);
}

TEST(test_chunk_append_numpy_column_i64_smoke)
{
    column_sender_chunk* chunk = make_chunk_t();
    CHECK(chunk != NULL, "chunk constructed");
    if (!chunk)
        return;
    int64_t data[] = {1, 2, 3};
    line_sender_error* err = NULL;
    bool ok = column_sender_chunk_append_numpy_column(
        chunk,
        "v",
        1,
        column_sender_numpy_i64,
        (const uint8_t*)data,
        sizeof(data),
        3,
        NULL,
        NULL,
        &err);
    CHECK(ok, "i64 append → true");
    if (err)
    {
        line_sender_error_free(err);
        err = NULL;
    }
    CHECK(column_sender_chunk_row_count(chunk, NULL) == 3, "row_count == 3");
    column_sender_chunk_free(chunk);
}

TEST(test_chunk_append_numpy_column_f64_smoke)
{
    column_sender_chunk* chunk = make_chunk_t();
    CHECK(chunk != NULL, "chunk constructed");
    if (!chunk)
        return;
    double data[] = {1.0, 2.0, 3.0};
    line_sender_error* err = NULL;
    bool ok = column_sender_chunk_append_numpy_column(
        chunk,
        "v",
        1,
        column_sender_numpy_f64,
        (const uint8_t*)data,
        sizeof(data),
        3,
        NULL,
        NULL,
        &err);
    CHECK(ok, "f64 append → true");
    if (err)
        line_sender_error_free(err);
    CHECK(column_sender_chunk_row_count(chunk, NULL) == 3, "row_count == 3");
    column_sender_chunk_free(chunk);
}

TEST(test_chunk_append_numpy_column_bool_smoke)
{
    column_sender_chunk* chunk = make_chunk_t();
    CHECK(chunk != NULL, "chunk constructed");
    if (!chunk)
        return;
    uint8_t bits[] = {1, 0, 1};
    line_sender_error* err = NULL;
    bool ok = column_sender_chunk_append_numpy_column(
        chunk, "v", 1, column_sender_numpy_bool, bits, sizeof(bits), 3, NULL, NULL, &err);
    CHECK(ok, "bool append → true");
    if (err)
        line_sender_error_free(err);
    CHECK(column_sender_chunk_row_count(chunk, NULL) == 3, "row_count == 3");
    column_sender_chunk_free(chunk);
}

TEST(test_chunk_append_numpy_column_decimal_requires_extras)
{
    column_sender_chunk* chunk = make_chunk_t();
    CHECK(chunk != NULL, "chunk constructed");
    if (!chunk)
        return;
    int64_t data[] = {1, 2, 3};
    line_sender_error* err = NULL;
    bool ok = column_sender_chunk_append_numpy_column(
        chunk,
        "v",
        1,
        column_sender_numpy_decimal_s8,
        (const uint8_t*)data,
        sizeof(data),
        3,
        NULL,
        NULL,
        &err);
    CHECK(!ok, "decimal w/o extras → false");
    CHECK(err != NULL, "err_out populated");
    if (err)
    {
        CHECK(
            line_sender_error_get_code(err) ==
                line_sender_error_invalid_api_call,
            "decimal w/o extras → invalid_api_call");
        CHECK(
            err_msg_contains(
                err,
                "DECIMAL64 column requires non-NULL "
                "column_sender_numpy_extras"),
            "msg mentions DECIMAL64 requires non-NULL extras");
        line_sender_error_free(err);
    }
    column_sender_chunk_free(chunk);
}

TEST(test_chunk_append_numpy_column_decimal_scale_too_high)
{
    column_sender_chunk* chunk = make_chunk_t();
    CHECK(chunk != NULL, "chunk constructed");
    if (!chunk)
        return;
    int64_t data[] = {1, 2, 3};
    column_sender_numpy_extras extras;
    memset(&extras, 0, sizeof(extras));
    extras.decimal_scale = 19; /* cap is 18 for DECIMAL64 */
    line_sender_error* err = NULL;
    bool ok = column_sender_chunk_append_numpy_column(
        chunk,
        "v",
        1,
        column_sender_numpy_decimal_s8,
        (const uint8_t*)data,
        sizeof(data),
        3,
        NULL,
        &extras,
        &err);
    CHECK(!ok, "decimal scale 19 → false");
    assert_invalid_api_call(err, "decimal scale 19 → invalid_api_call");
    if (err)
        line_sender_error_free(err);
    column_sender_chunk_free(chunk);
}

TEST(test_chunk_append_numpy_column_decimal_scale_negative)
{
    column_sender_chunk* chunk = make_chunk_t();
    CHECK(chunk != NULL, "chunk constructed");
    if (!chunk)
        return;
    int64_t data[] = {1, 2, 3};
    column_sender_numpy_extras extras;
    memset(&extras, 0, sizeof(extras));
    extras.decimal_scale = -1;
    line_sender_error* err = NULL;
    bool ok = column_sender_chunk_append_numpy_column(
        chunk,
        "v",
        1,
        column_sender_numpy_decimal_s8,
        (const uint8_t*)data,
        sizeof(data),
        3,
        NULL,
        &extras,
        &err);
    CHECK(!ok, "decimal scale -1 → false");
    assert_invalid_api_call(err, "decimal scale -1 → invalid_api_call");
    if (err)
        line_sender_error_free(err);
    column_sender_chunk_free(chunk);
}

TEST(test_chunk_append_numpy_column_geohash_requires_extras)
{
    column_sender_chunk* chunk = make_chunk_t();
    CHECK(chunk != NULL, "chunk constructed");
    if (!chunk)
        return;
    int8_t data[] = {1, 2, 3};
    line_sender_error* err = NULL;
    bool ok = column_sender_chunk_append_numpy_column(
        chunk,
        "v",
        1,
        column_sender_numpy_geohash_i8,
        (const uint8_t*)data,
        sizeof(data),
        3,
        NULL,
        NULL,
        &err);
    CHECK(!ok, "geohash w/o extras → false");
    assert_invalid_api_call(err, "geohash w/o extras → invalid_api_call");
    if (err)
        line_sender_error_free(err);
    column_sender_chunk_free(chunk);
}

TEST(test_chunk_append_numpy_column_geohash_bits_zero)
{
    column_sender_chunk* chunk = make_chunk_t();
    CHECK(chunk != NULL, "chunk constructed");
    if (!chunk)
        return;
    int8_t data[] = {1, 2, 3};
    column_sender_numpy_extras extras;
    memset(&extras, 0, sizeof(extras));
    extras.geohash_bits = 0;
    line_sender_error* err = NULL;
    bool ok = column_sender_chunk_append_numpy_column(
        chunk,
        "v",
        1,
        column_sender_numpy_geohash_i8,
        (const uint8_t*)data,
        sizeof(data),
        3,
        NULL,
        &extras,
        &err);
    CHECK(!ok, "geohash bits 0 → false");
    assert_invalid_api_call(err, "geohash bits 0 → invalid_api_call");
    if (err)
        line_sender_error_free(err);
    column_sender_chunk_free(chunk);
}

TEST(test_chunk_append_numpy_column_geohash_bits_too_high)
{
    column_sender_chunk* chunk = make_chunk_t();
    CHECK(chunk != NULL, "chunk constructed");
    if (!chunk)
        return;
    int8_t data[] = {1, 2, 3};
    column_sender_numpy_extras extras;
    memset(&extras, 0, sizeof(extras));
    extras.geohash_bits = 9; /* cap is 8 for i8 */
    line_sender_error* err = NULL;
    bool ok = column_sender_chunk_append_numpy_column(
        chunk,
        "v",
        1,
        column_sender_numpy_geohash_i8,
        (const uint8_t*)data,
        sizeof(data),
        3,
        NULL,
        &extras,
        &err);
    CHECK(!ok, "geohash bits 9 → false");
    assert_invalid_api_call(err, "geohash bits 9 → invalid_api_call");
    if (err)
        line_sender_error_free(err);
    column_sender_chunk_free(chunk);
}

TEST(test_chunk_append_numpy_column_f64_ndarray_requires_extras)
{
    column_sender_chunk* chunk = make_chunk_t();
    CHECK(chunk != NULL, "chunk constructed");
    if (!chunk)
        return;
    double data[] = {1.0, 2.0, 3.0};
    line_sender_error* err = NULL;
    bool ok = column_sender_chunk_append_numpy_column(
        chunk,
        "v",
        1,
        column_sender_numpy_f64_ndarray,
        (const uint8_t*)data,
        sizeof(data),
        1,
        NULL,
        NULL,
        &err);
    CHECK(!ok, "ndarray w/o extras → false");
    assert_invalid_api_call(err, "ndarray w/o extras → invalid_api_call");
    if (err)
        line_sender_error_free(err);
    column_sender_chunk_free(chunk);
}

TEST(test_chunk_append_numpy_column_f64_ndarray_ndim_zero)
{
    column_sender_chunk* chunk = make_chunk_t();
    CHECK(chunk != NULL, "chunk constructed");
    if (!chunk)
        return;
    double data[] = {1.0, 2.0, 3.0};
    column_sender_numpy_extras extras;
    memset(&extras, 0, sizeof(extras));
    extras.array_ndim = 0;
    extras.array_shape = NULL;
    line_sender_error* err = NULL;
    bool ok = column_sender_chunk_append_numpy_column(
        chunk,
        "v",
        1,
        column_sender_numpy_f64_ndarray,
        (const uint8_t*)data,
        sizeof(data),
        1,
        NULL,
        &extras,
        &err);
    CHECK(!ok, "ndarray ndim 0 → false");
    assert_invalid_api_call(err, "ndarray ndim 0 → invalid_api_call");
    if (err)
        line_sender_error_free(err);
    column_sender_chunk_free(chunk);
}

TEST(test_chunk_append_numpy_column_f64_ndarray_ndim_too_high)
{
    column_sender_chunk* chunk = make_chunk_t();
    CHECK(chunk != NULL, "chunk constructed");
    if (!chunk)
        return;
    double data[] = {1.0};
    uint32_t shape[33];
    for (int i = 0; i < 33; ++i)
        shape[i] = 1;
    column_sender_numpy_extras extras;
    memset(&extras, 0, sizeof(extras));
    extras.array_ndim = 33; /* cap is 32 */
    extras.array_shape = shape;
    line_sender_error* err = NULL;
    bool ok = column_sender_chunk_append_numpy_column(
        chunk,
        "v",
        1,
        column_sender_numpy_f64_ndarray,
        (const uint8_t*)data,
        sizeof(data),
        1,
        NULL,
        &extras,
        &err);
    CHECK(!ok, "ndarray ndim 33 → false");
    assert_invalid_api_call(err, "ndarray ndim 33 → invalid_api_call");
    if (err)
        line_sender_error_free(err);
    column_sender_chunk_free(chunk);
}

TEST(test_chunk_append_numpy_column_f64_ndarray_null_shape)
{
    column_sender_chunk* chunk = make_chunk_t();
    CHECK(chunk != NULL, "chunk constructed");
    if (!chunk)
        return;
    double data[] = {1.0, 2.0, 3.0};
    column_sender_numpy_extras extras;
    memset(&extras, 0, sizeof(extras));
    extras.array_ndim = 2;
    extras.array_shape = NULL;
    line_sender_error* err = NULL;
    bool ok = column_sender_chunk_append_numpy_column(
        chunk,
        "v",
        1,
        column_sender_numpy_f64_ndarray,
        (const uint8_t*)data,
        sizeof(data),
        1,
        NULL,
        &extras,
        &err);
    CHECK(!ok, "ndarray null shape → false");
    assert_invalid_api_call(err, "ndarray null shape → invalid_api_call");
    if (err)
        line_sender_error_free(err);
    column_sender_chunk_free(chunk);
}

TEST(test_chunk_append_numpy_column_f64_ndarray_zero_dim)
{
    column_sender_chunk* chunk = make_chunk_t();
    CHECK(chunk != NULL, "chunk constructed");
    if (!chunk)
        return;
    double data[] = {1.0, 2.0, 3.0};
    uint32_t shape[] = {3, 0};
    column_sender_numpy_extras extras;
    memset(&extras, 0, sizeof(extras));
    extras.array_ndim = 2;
    extras.array_shape = shape;
    line_sender_error* err = NULL;
    bool ok = column_sender_chunk_append_numpy_column(
        chunk,
        "v",
        1,
        column_sender_numpy_f64_ndarray,
        (const uint8_t*)data,
        sizeof(data),
        1,
        NULL,
        &extras,
        &err);
    CHECK(!ok, "ndarray zero-dim → false");
    assert_invalid_api_call(err, "ndarray zero-dim → invalid_api_call");
    if (err)
        line_sender_error_free(err);
    column_sender_chunk_free(chunk);
}

TEST(test_chunk_append_numpy_column_f64_ndarray_smoke)
{
    column_sender_chunk* chunk = make_chunk_t();
    CHECK(chunk != NULL, "chunk constructed");
    if (!chunk)
        return;
    /* Per-row tensor shape [3], row_count = 2 → 6 doubles of source data. */
    double data[6] = {1.0, 2.0, 3.0, 4.0, 5.0, 6.0};
    uint32_t shape[] = {3};
    column_sender_numpy_extras extras;
    memset(&extras, 0, sizeof(extras));
    extras.array_ndim = 1;
    extras.array_shape = shape;
    line_sender_error* err = NULL;
    bool ok = column_sender_chunk_append_numpy_column(
        chunk,
        "v",
        1,
        column_sender_numpy_f64_ndarray,
        (const uint8_t*)data,
        sizeof(data),
        2,
        NULL,
        &extras,
        &err);
    CHECK(ok, "ndarray 1-D shape {3} × 2 rows → true");
    if (err)
        line_sender_error_free(err);
    CHECK(column_sender_chunk_row_count(chunk, NULL) == 2, "row_count == 2");
    column_sender_chunk_free(chunk);
}

TEST(test_chunk_append_numpy_column_data_len_too_small)
{
    column_sender_chunk* chunk = make_chunk_t();
    CHECK(chunk != NULL, "chunk constructed");
    if (!chunk)
        return;
    /* 3 i64 rows need 24 bytes; claim only 16 → must be rejected. */
    int64_t data[] = {1, 2, 3};
    line_sender_error* err = NULL;
    bool ok = column_sender_chunk_append_numpy_column(
        chunk,
        "v",
        1,
        column_sender_numpy_i64,
        (const uint8_t*)data,
        16,
        3,
        NULL,
        NULL,
        &err);
    CHECK(!ok, "undersized data_len_bytes → false");
    assert_invalid_api_call(err, "undersized buffer → invalid_api_call");
    if (err)
    {
        CHECK(
            err_msg_contains(err, "buffer too small"),
            "msg mentions buffer too small");
        line_sender_error_free(err);
        err = NULL;
    }
    CHECK(column_sender_chunk_row_count(chunk, NULL) == 0, "nothing appended");
    column_sender_chunk_free(chunk);
}

TEST(test_chunk_append_numpy_column_mistagged_dtype_rejected)
{
    column_sender_chunk* chunk = make_chunk_t();
    CHECK(chunk != NULL, "chunk constructed");
    if (!chunk)
        return;
    /* An int8 buffer (3 bytes) mis-tagged f64 would read 24 bytes; the
     * honest data_len_bytes = 3 must stop it before the OOB read. */
    int8_t data[] = {1, 2, 3};
    line_sender_error* err = NULL;
    bool ok = column_sender_chunk_append_numpy_column(
        chunk,
        "v",
        1,
        column_sender_numpy_f64,
        (const uint8_t*)data,
        sizeof(data),
        3,
        NULL,
        NULL,
        &err);
    CHECK(!ok, "int8 buffer mis-tagged f64 → false");
    assert_invalid_api_call(err, "mis-tagged dtype → invalid_api_call");
    if (err)
        line_sender_error_free(err);
    column_sender_chunk_free(chunk);
}

TEST(test_chunk_append_numpy_column_data_len_exact_ok)
{
    column_sender_chunk* chunk = make_chunk_t();
    CHECK(chunk != NULL, "chunk constructed");
    if (!chunk)
        return;
    /* Exact fit: 3 i64 rows == 24 bytes is accepted (boundary). */
    int64_t data[] = {1, 2, 3};
    line_sender_error* err = NULL;
    bool ok = column_sender_chunk_append_numpy_column(
        chunk,
        "v",
        1,
        column_sender_numpy_i64,
        (const uint8_t*)data,
        24,
        3,
        NULL,
        NULL,
        &err);
    CHECK(ok, "exact data_len_bytes → true");
    if (err)
        line_sender_error_free(err);
    CHECK(column_sender_chunk_row_count(chunk, NULL) == 3, "row_count == 3");
    column_sender_chunk_free(chunk);
}

TEST(test_error_codes_survive_ffi_boundary)
{
    int sender_code = (int)line_sender_error_arrow_unsupported_column_kind;
    int ingest_code = (int)line_sender_error_arrow_ingest;
    int drift_code = (int)reader_error_schema_drift;
    int no_schema_code = (int)reader_error_no_schema;
    int export_code = (int)reader_error_arrow_export;
    CHECK(sender_code != ingest_code, "sender codes distinct");
    CHECK(drift_code != no_schema_code, "reader codes distinct");
    CHECK(no_schema_code != export_code, "reader codes distinct");
}

/* ---------------------------------------------------------------------------
 * Mock-backed per-type smoke tests — migrated from the deleted buffer-level
 * `line_sender_buffer_append_arrow` C suite. Each test:
 *   1. Builds a single-column ArrowArray + ArrowSchema on the stack.
 *   2. Spins up `qwp_mock_c` (1-slot, accepts one QWP1 binary frame).
 *   3. Opens a `questdb_db` against the mock + borrows a `column_sender`.
 *   4. Calls `column_sender_flush_arrow_batch[_at_column]`.
 *   5. Accepts either ok=true OR a documented structured error code.
 * Per-column wire correctness is owned by the Rust unit tests under
 * `questdb-rs/src/ingress/column_sender/arrow_batch.rs`.
 * ------------------------------------------------------------------------- */

#define ARROW_FLAG_NULLABLE 2

struct fsm_owner
{
    void* values_buffer;
    const void* buffers[2];
};

static void fsm_release_array(struct ArrowArray* arr)
{
    if (arr == NULL || arr->private_data == NULL)
        return;
    struct fsm_owner* pd = (struct fsm_owner*)arr->private_data;
    free(pd->values_buffer);
    free(pd);
    arr->release = NULL;
    arr->private_data = NULL;
}

static void fsm_release_schema(struct ArrowSchema* sch)
{
    if (sch != NULL)
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
    struct fsm_owner* pd = (struct fsm_owner*)calloc(1, sizeof(*pd));
    pd->values_buffer = malloc((size_t)row_count * elem_size);
    memcpy(pd->values_buffer, values_bytes, (size_t)row_count * elem_size);
    pd->buffers[0] = NULL;
    pd->buffers[1] = pd->values_buffer;

    memset(out_arr, 0, sizeof(*out_arr));
    out_arr->length = row_count;
    out_arr->null_count = 0;
    out_arr->offset = 0;
    out_arr->n_buffers = 2;
    out_arr->n_children = 0;
    out_arr->buffers = pd->buffers;
    out_arr->release = fsm_release_array;
    out_arr->private_data = pd;

    memset(out_sch, 0, sizeof(*out_sch));
    out_sch->format = format;
    out_sch->name = name;
    out_sch->flags = ARROW_FLAG_NULLABLE;
    out_sch->release = fsm_release_schema;
}

/* Append a (deliberately malformed) ArrowArray and assert it is rejected
 * pre-import: a structured error, the producer's release left intact, and —
 * the point of the test — no abort under the FFI crate's panic = "abort". */
static void expect_arrow_array_rejected(
    struct ArrowArray* arr, struct ArrowSchema* sch, const char* label)
{
    line_sender_error* err = NULL;
    column_sender_chunk* chunk = column_sender_chunk_new("t", 1, &err);
    CHECK(chunk != NULL, "chunk constructed");
    if (err)
    {
        line_sender_error_free(err);
        err = NULL;
    }
    if (chunk == NULL)
    {
        if (arr->release)
            arr->release(arr);
        if (sch->release)
            sch->release(sch);
        return;
    }
    bool ok = column_sender_chunk_append_arrow_column(
        chunk, "v", 1, arr, sch, 0, 0, &err);
    CHECK(!ok, label);
    CHECK(err != NULL, "err_out populated on malformed array");
    if (err)
    {
        int code = (int)line_sender_error_get_code(err);
        int accepted =
            code == line_sender_error_arrow_ingest ||
            code == line_sender_error_invalid_api_call;
        CHECK(accepted, "malformed array → structured error (not abort)");
        line_sender_error_free(err);
    }
    CHECK(arr->release != NULL, "release intact on pre-import array reject");
    if (arr->release)
        arr->release(arr);
    if (sch->release)
        sch->release(sch);
    column_sender_chunk_free(chunk);
}

TEST(test_chunk_append_arrow_column_malformed_array_rejected)
{
    int64_t values[2] = {10, 20};

    {
        struct ArrowArray arr;
        struct ArrowSchema sch;
        build_primitive(2, sizeof(int64_t), values, "l", "v", &arr, &sch);
        arr.length = -1;
        expect_arrow_array_rejected(&arr, &sch, "negative length → false");
    }
    {
        struct ArrowArray arr;
        struct ArrowSchema sch;
        build_primitive(2, sizeof(int64_t), values, "l", "v", &arr, &sch);
        arr.length = (int64_t)(16 * 1024 * 1024) + 1; /* > MAX_CHUNK_ROWS */
        expect_arrow_array_rejected(&arr, &sch, "oversized length → false");
    }
    {
        struct ArrowArray arr;
        struct ArrowSchema sch;
        build_primitive(2, sizeof(int64_t), values, "l", "v", &arr, &sch);
        arr.offset = -1;
        expect_arrow_array_rejected(&arr, &sch, "negative offset → false");
    }
    {
        struct ArrowArray arr;
        struct ArrowSchema sch;
        build_primitive(2, sizeof(int64_t), values, "l", "v", &arr, &sch);
        arr.n_buffers = 0; /* int64 layout needs validity + values */
        expect_arrow_array_rejected(&arr, &sch, "too few buffers → false");
    }
    {
        struct ArrowArray arr;
        struct ArrowSchema sch;
        build_primitive(2, sizeof(int64_t), values, "l", "v", &arr, &sch);
        arr.buffers = NULL; /* n_buffers > 0 but the array is NULL */
        expect_arrow_array_rejected(&arr, &sch, "NULL buffer pointer → false");
    }
}

/* Open a mock + questdb_db + borrow a conn. Returns NULL on any setup
 * failure; populates *out_db / *out_mock on success. */
static column_sender* mock_borrow_column_sender(
    qwp_mock_c** out_mock,
    questdb_db** out_db)
{
    *out_mock = NULL;
    *out_db = NULL;
    qwp_mock_c* mock = qwp_mock_c_start(1);
    if (mock == NULL)
        return NULL;
    const char* addr = qwp_mock_c_addr(mock);
    char conf[256];
    snprintf(
        conf, sizeof(conf),
        "qwpws::addr=%s;pool_size=1;pool_reap=manual;",
        addr);
    line_sender_error* err = NULL;
    questdb_db* db = questdb_db_connect(conf, strlen(conf), &err);
    if (db == NULL)
    {
        if (err)
            line_sender_error_free(err);
        qwp_mock_c_stop(mock);
        return NULL;
    }
    column_sender* conn = questdb_db_borrow_column_sender(db, &err);
    if (conn == NULL)
    {
        if (err)
            line_sender_error_free(err);
        questdb_db_close(db);
        qwp_mock_c_stop(mock);
        return NULL;
    }
    *out_mock = mock;
    *out_db = db;
    return conn;
}

static void mock_return_close(
    qwp_mock_c* mock, questdb_db* db, column_sender* conn)
{
    if (conn != NULL && db != NULL)
        questdb_db_return_column_sender(db, conn);
    if (db != NULL)
        questdb_db_close(db);
    if (mock != NULL)
        qwp_mock_c_stop(mock);
}

static void run_arrow_flush(
    struct ArrowArray* arr, struct ArrowSchema* sch,
    const char* table, const char* label)
{
    qwp_mock_c* mock;
    questdb_db* db;
    column_sender* conn = mock_borrow_column_sender(&mock, &db);
    CHECK(conn != NULL, "mock conn borrowed");
    if (conn == NULL)
    {
        if (arr->release)
            arr->release(arr);
        if (sch->release)
            sch->release(sch);
        return;
    }
    line_sender_error* err = NULL;
    line_sender_table_name tbl = make_table(table);
    bool ok = column_sender_flush_arrow_batch_at_now(
        conn, tbl, arr, sch, NULL, 0, &err);
    if (!ok)
    {
        CHECK(err != NULL, "err_out populated on failure");
        if (err)
        {
            int code = (int)line_sender_error_get_code(err);
            int accepted =
                code == line_sender_error_invalid_api_call ||
                code == line_sender_error_arrow_ingest ||
                code == line_sender_error_arrow_unsupported_column_kind;
            CHECK(accepted, label);
            line_sender_error_free(err);
        }
        if (arr->release)
            arr->release(arr);
    }
    if (sch->release)
        sch->release(sch);
    mock_return_close(mock, db, conn);
}

TEST(test_mock_ingress_null_array_via_real_conn)
{
    /* With a real (mock-backed) conn, the NULL-array branch in the
     * impl is exercised — the conn-NULL short-circuit is already
     * covered above. */
    qwp_mock_c* mock;
    questdb_db* db;
    column_sender* conn = mock_borrow_column_sender(&mock, &db);
    CHECK(conn != NULL, "mock conn borrowed");
    if (conn == NULL)
        return;
    struct ArrowSchema sch;
    memset(&sch, 0, sizeof(sch));
    line_sender_error* err = NULL;
    bool ok = column_sender_flush_arrow_batch_at_now(
        conn, make_table("t"), NULL, &sch, NULL, 0, &err);
    CHECK(!ok, "NULL array → false");
    CHECK(err != NULL, "err_out populated");
    if (err)
    {
        CHECK(
            line_sender_error_get_code(err) ==
                line_sender_error_invalid_api_call,
            "NULL array → invalid_api_call");
        line_sender_error_free(err);
    }
    mock_return_close(mock, db, conn);
}

TEST(test_mock_ingress_at_column_empty_name_via_real_conn)
{
    /* The new at_column entry takes a line_sender_column_name, whose
     * construction (`line_sender_column_name_init`) rejects empty
     * names with `invalid_api_call` before any flush attempt. */
    line_sender_error* err = NULL;
    line_sender_column_name col;
    bool ok = line_sender_column_name_init(&col, 0, "", &err);
    CHECK(!ok, "empty column name init → false");
    CHECK(err != NULL, "err_out populated");
    if (err)
    {
        CHECK(
            line_sender_error_get_code(err) ==
                line_sender_error_invalid_name,
            "empty column name → invalid_name");
        line_sender_error_free(err);
    }
}

TEST(test_mock_ingress_boolean_column)
{
    uint8_t values[3] = {0x05, 0, 0};
    struct ArrowArray arr;
    struct ArrowSchema sch;
    build_primitive(3, 1, values, "b", "flag", &arr, &sch);
    run_arrow_flush(&arr, &sch, "bool_t", "boolean accepted/structured-error");
}

TEST(test_mock_ingress_int8_int16_int32_int64_columns)
{
    {
        int8_t values[3] = {-1, 0, 127};
        struct ArrowArray arr;
        struct ArrowSchema sch;
        build_primitive(3, sizeof(int8_t), values, "c", "by", &arr, &sch);
        run_arrow_flush(&arr, &sch, "i8_t", "int8 accepted/structured-error");
    }
    {
        int16_t values[3] = {-1234, 0, 31000};
        struct ArrowArray arr;
        struct ArrowSchema sch;
        build_primitive(3, sizeof(int16_t), values, "s", "sh", &arr, &sch);
        run_arrow_flush(&arr, &sch, "i16_t", "int16 accepted/structured-error");
    }
    {
        int32_t values[3] = {-1, 0, 0x7FFFFFFF};
        struct ArrowArray arr;
        struct ArrowSchema sch;
        build_primitive(3, sizeof(int32_t), values, "i", "in", &arr, &sch);
        run_arrow_flush(&arr, &sch, "i32_t", "int32 accepted/structured-error");
    }
    {
        int64_t values[3] = {100, 200, 300};
        struct ArrowArray arr;
        struct ArrowSchema sch;
        build_primitive(3, sizeof(int64_t), values, "l", "lo", &arr, &sch);
        run_arrow_flush(&arr, &sch, "i64_t", "int64 accepted/structured-error");
    }
}

TEST(test_mock_ingress_float32_float64_columns)
{
    {
        float values[3] = {1.5f, -2.5f, 3.14f};
        struct ArrowArray arr;
        struct ArrowSchema sch;
        build_primitive(3, sizeof(float), values, "f", "f3", &arr, &sch);
        run_arrow_flush(&arr, &sch, "f32_t", "float32 accepted/structured-error");
    }
    {
        double values[3] = {1.5, -2.5, 3.14159};
        struct ArrowArray arr;
        struct ArrowSchema sch;
        build_primitive(3, sizeof(double), values, "g", "f6", &arr, &sch);
        run_arrow_flush(&arr, &sch, "f64_t", "float64 accepted/structured-error");
    }
}

TEST(test_mock_ingress_timestamp_microseconds)
{
    int64_t values[2] = {1700000000000000LL, 1700000000000001LL};
    struct ArrowArray arr;
    struct ArrowSchema sch;
    build_primitive(2, sizeof(int64_t), values, "tsu:UTC", "ts", &arr, &sch);
    /* Designated TS comes from the column itself via the at_column
     * variant; here we use the no-ts variant so the server stamps each
     * row on arrival. */
    run_arrow_flush(&arr, &sch, "ts_t", "timestamp(µs) accepted/structured-error");
}

TEST(test_mock_ingress_both_designated_timestamp_variants)
{
    /* The original test exercised three DesignatedTimestamp kinds
     * (Now / ServerNow / Column). In the new conn-level API the first
     * two collapse onto `column_sender_flush_arrow_batch_at_now`
     * (no per-row stamp — server stamps on arrival), and Column maps to the
     * dedicated `column_sender_flush_arrow_batch_at_column`. We cover
     * both surviving variants here. */

    /* No-TS variant. */
    {
        int64_t values[2] = {10, 20};
        struct ArrowArray arr;
        struct ArrowSchema sch;
        build_primitive(2, sizeof(int64_t), values, "l", "v", &arr, &sch);
        run_arrow_flush(&arr, &sch, "dts_t_now", "no-ts accepted/structured-error");
    }

    /* At-column variant — pass a non-existent column name. The impl
     * is expected to reject this with arrow_ingest (column not found
     * in the batch schema). */
    {
        int64_t values[2] = {10, 20};
        struct ArrowArray arr;
        struct ArrowSchema sch;
        build_primitive(2, sizeof(int64_t), values, "l", "v", &arr, &sch);
        qwp_mock_c* mock;
        questdb_db* db;
        column_sender* conn = mock_borrow_column_sender(&mock, &db);
        CHECK(conn != NULL, "mock conn borrowed");
        if (conn == NULL)
        {
            if (arr.release)
                arr.release(&arr);
            if (sch.release)
                sch.release(&sch);
            return;
        }
        line_sender_error* err = NULL;
        line_sender_table_name tbl = make_table("dts_t_col");
        line_sender_column_name ts_col = make_col("missing_ts");
        bool ok = column_sender_flush_arrow_batch_at_column(
            conn, tbl, &arr, &sch, ts_col, NULL, 0, &err);
        CHECK(!ok, "missing ts column → false");
        if (err)
        {
            int code = (int)line_sender_error_get_code(err);
            int accepted =
                code == line_sender_error_arrow_ingest ||
                code == line_sender_error_invalid_api_call;
            CHECK(accepted, "missing ts column → structured error");
            line_sender_error_free(err);
        }
        if (arr.release)
            arr.release(&arr);
        if (sch.release)
            sch.release(&sch);
        mock_return_close(mock, db, conn);
    }
}

/* Exercises the documented `array->release` ownership contract of
 * `column_sender_flush_arrow_batch_at_now` on all three states: pre-import
 * failure leaves release intact (caller frees), a malformed nested schema
 * is rejected gracefully (not by aborting the panic=abort FFI crate) with
 * release intact, and a structurally-valid batch that reaches the Arrow
 * import step has release consumed regardless of the eventual outcome. */
TEST(test_mock_ingress_arrow_release_contract)
{
    qwp_mock_c* mock;
    questdb_db* db;
    column_sender* conn = mock_borrow_column_sender(&mock, &db);
    CHECK(conn != NULL, "mock conn borrowed");
    if (conn == NULL)
        return;
    int64_t values[2] = {10, 20};

    /* (A) Pre-import failure (NULL schema): release stays intact. */
    {
        struct ArrowArray arr;
        struct ArrowSchema sch;
        build_primitive(2, sizeof(int64_t), values, "l", "v", &arr, &sch);
        line_sender_error* err = NULL;
        bool ok = column_sender_flush_arrow_batch_at_now(
            conn, make_table("rc_a"), &arr, NULL, NULL, 0, &err);
        CHECK(!ok, "NULL schema → false");
        CHECK(
            arr.release != NULL,
            "release intact on pre-import (NULL schema) failure");
        if (err)
            line_sender_error_free(err);
        if (arr.release)
            arr.release(&arr);
        if (sch.release)
            sch.release(&sch);
    }

    /* (B) Malformed nested schema (List with zero children) must be
     * rejected before import — gracefully, not by aborting — with release
     * intact so the caller can free it. */
    {
        struct ArrowArray arr;
        struct ArrowSchema sch;
        build_primitive(2, sizeof(int64_t), values, "+l", "v", &arr, &sch);
        line_sender_error* err = NULL;
        bool ok = column_sender_flush_arrow_batch_at_now(
            conn, make_table("rc_b"), &arr, &sch, NULL, 0, &err);
        CHECK(!ok, "malformed +l schema → false");
        CHECK(err != NULL, "err_out populated on malformed schema");
        if (err)
        {
            int code = (int)line_sender_error_get_code(err);
            int accepted =
                code == line_sender_error_arrow_ingest ||
                code == line_sender_error_invalid_api_call;
            CHECK(accepted, "malformed +l → structured error (not abort)");
            line_sender_error_free(err);
        }
        CHECK(
            arr.release != NULL,
            "release intact on pre-import (malformed schema) reject");
        if (arr.release)
            arr.release(&arr);
        if (sch.release)
            sch.release(&sch);
    }

    /* (C) A structurally-valid batch reaches the Arrow import step, which
     * consumes release (sets it NULL) whether the flush ultimately
     * succeeds or fails afterward. The caller must NOT release it again. */
    {
        struct ArrowArray arr;
        struct ArrowSchema sch;
        build_primitive(2, sizeof(int64_t), values, "l", "v", &arr, &sch);
        line_sender_error* err = NULL;
        bool ok = column_sender_flush_arrow_batch_at_now(
            conn, make_table("rc_c"), &arr, &sch, NULL, 0, &err);
        (void)ok;
        CHECK(
            arr.release == NULL,
            "release consumed once the Arrow import step is reached");
        if (err)
            line_sender_error_free(err);
        if (sch.release)
            sch.release(&sch);
    }

    mock_return_close(mock, db, conn);
}

int main(void)
{
    RUN(test_tristate_egress_enum_values);
    RUN(test_appended_reader_error_codes_have_distinct_values);
    RUN(test_appended_sender_error_codes_exist);
    RUN(test_egress_null_cursor_returns_error_tristate);
    RUN(test_egress_null_out_array_returns_error_tristate);
    RUN(test_ingress_null_conn_returns_false);
    RUN(test_ingress_null_array_returns_false);
    RUN(test_ingress_at_column_null_conn_returns_false);
    RUN(test_chunk_append_arrow_column_null_chunk);
    RUN(test_chunk_append_arrow_column_null_array_schema);
    RUN(test_chunk_append_arrow_column_valid_i64_smoke);
    RUN(test_chunk_append_arrow_column_malformed_array_rejected);
    RUN(test_chunk_append_numpy_column_null_chunk);
    RUN(test_chunk_append_numpy_column_i64_smoke);
    RUN(test_chunk_append_numpy_column_f64_smoke);
    RUN(test_chunk_append_numpy_column_bool_smoke);
    RUN(test_chunk_append_numpy_column_decimal_requires_extras);
    RUN(test_chunk_append_numpy_column_decimal_scale_too_high);
    RUN(test_chunk_append_numpy_column_decimal_scale_negative);
    RUN(test_chunk_append_numpy_column_geohash_requires_extras);
    RUN(test_chunk_append_numpy_column_geohash_bits_zero);
    RUN(test_chunk_append_numpy_column_geohash_bits_too_high);
    RUN(test_chunk_append_numpy_column_f64_ndarray_requires_extras);
    RUN(test_chunk_append_numpy_column_f64_ndarray_ndim_zero);
    RUN(test_chunk_append_numpy_column_f64_ndarray_ndim_too_high);
    RUN(test_chunk_append_numpy_column_f64_ndarray_null_shape);
    RUN(test_chunk_append_numpy_column_f64_ndarray_zero_dim);
    RUN(test_chunk_append_numpy_column_f64_ndarray_smoke);
    RUN(test_chunk_append_numpy_column_data_len_too_small);
    RUN(test_chunk_append_numpy_column_mistagged_dtype_rejected);
    RUN(test_chunk_append_numpy_column_data_len_exact_ok);
    RUN(test_error_codes_survive_ffi_boundary);
    RUN(test_mock_ingress_null_array_via_real_conn);
    RUN(test_mock_ingress_at_column_empty_name_via_real_conn);
    RUN(test_mock_ingress_boolean_column);
    RUN(test_mock_ingress_int8_int16_int32_int64_columns);
    RUN(test_mock_ingress_float32_float64_columns);
    RUN(test_mock_ingress_timestamp_microseconds);
    RUN(test_mock_ingress_both_designated_timestamp_variants);
    RUN(test_mock_ingress_arrow_release_contract);
    fprintf(stderr, "Ran %d tests, %d errors\n", tests, errors);
    return errors == 0 ? 0 : 1;
}
