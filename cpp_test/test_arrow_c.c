/* C ABI FFI-boundary tests for the conn-level Arrow batch ingest API
 * (`qwp_sender_flush_arrow_batch_at_now[_at_column]`) and the unchanged
 * egress reader API. Successful round-trip coverage lives in the Rust
 * unit tests under `questdb-rs/src/ingress/qwp_sender/arrow_batch.rs`
 * and the Python system tests under `system_test/`. */

#include <questdb/ingress/qwp_sender.h>
#include <questdb/egress/qwp_reader.h>
#include <questdb/ingress/line_sender.h>

#include "qwp_mock_c.h"

#include <math.h>
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
            fprintf(                                                           \
                stderr,                                                        \
                "FAILED TEST: %s (%d new errors)\n",                           \
                #name,                                                         \
                errors - before);                                              \
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
    CHECK(qwp_reader_arrow_batch_ok == 0, "ok = 0");
    CHECK(qwp_reader_arrow_batch_end == 1, "end = 1");
    CHECK(qwp_reader_arrow_batch_error == 2, "error = 2");
}

TEST(test_appended_query_error_codes_have_distinct_values)
{
    CHECK(
        questdb_error_schema_drift != questdb_error_no_schema &&
            questdb_error_no_schema != questdb_error_arrow_export &&
            questdb_error_arrow_export != questdb_error_schema_drift,
        "schema_drift / no_schema / arrow_export distinct");
    CHECK(
        questdb_error_schema_drift > questdb_error_failover_would_duplicate,
        "schema_drift appended (not renumbered)");
}

TEST(test_appended_sender_error_codes_exist)
{
    CHECK(
        line_sender_error_arrow_unsupported_column_kind !=
            line_sender_error_arrow_ingest,
        "sender error codes distinct");
}

TEST(test_symbol_dict_full_is_a_distinct_appended_code)
{
    /* A full connection symbol dictionary must be recognisable by code, not by
     * message text -- that is the whole reason it is not invalid_api_call. */
    CHECK(
        line_sender_error_symbol_dict_full !=
            line_sender_error_invalid_api_call,
        "symbol_dict_full distinct from invalid_api_call");
    CHECK(
        line_sender_error_symbol_dict_full >
            line_sender_error_store_resend_required,
        "symbol_dict_full appended (not renumbered)");
    CHECK(
        questdb_error_symbol_dict_full == line_sender_error_symbol_dict_full,
        "neutral alias resolves to the same enumerator");
}

TEST(test_query_timeout_is_a_distinct_appended_code)
{
    /* A query that ran past its own timeout must be recognisable by code:
     * callers branch on it to avoid retrying a write the server may have
     * applied anyway. */
    CHECK(
        line_sender_error_query_timeout != line_sender_error_cancelled,
        "query_timeout distinct from cancelled");
    CHECK(
        line_sender_error_query_timeout !=
            line_sender_error_server_limit_exceeded,
        "query_timeout distinct from server_limit_exceeded");
    CHECK(
        line_sender_error_query_timeout != line_sender_error_invalid_api_call,
        "query_timeout distinct from invalid_api_call");
    CHECK(
        line_sender_error_query_timeout > line_sender_error_symbol_dict_full,
        "query_timeout appended (not renumbered)");
    CHECK(
        line_sender_error_query_timeout == 38,
        "query_timeout discriminant pinned at 38 for cached ABI consumers");
    CHECK(
        questdb_error_query_timeout == line_sender_error_query_timeout,
        "neutral alias resolves to the same enumerator");
}

TEST(test_flush_aborted_is_a_distinct_appended_code)
{
    /* A flush that stopped part way is safe to send again through a new
     * sender, which a failure of the connection is not: callers must be able
     * to tell the two apart by code. */
    CHECK(
        line_sender_error_flush_aborted != line_sender_error_socket_error,
        "flush_aborted distinct from socket_error");
    CHECK(
        line_sender_error_flush_aborted != line_sender_error_invalid_api_call,
        "flush_aborted distinct from invalid_api_call");
    CHECK(
        line_sender_error_flush_aborted > line_sender_error_query_timeout,
        "flush_aborted appended (not renumbered)");
    CHECK(
        line_sender_error_flush_aborted == 39,
        "flush_aborted discriminant pinned at 39 for cached ABI consumers");
    CHECK(
        questdb_error_flush_aborted == line_sender_error_flush_aborted,
        "neutral alias resolves to the same enumerator");
}

TEST(test_query_set_timeout_ms_null_query_is_tolerated)
{
    /* Proves the symbol links and argument-marshals under a plain C
     * compiler (the Cython contract surface), and that the NULL-handle
     * contract shared by every `qwp_reader_query_*` mutator holds: report
     * and return, never crash. */
    qwp_reader_query_set_timeout_ms(NULL, 1000);
    qwp_reader_query_set_timeout_ms(NULL, 0);
    CHECK(true, "NULL query handle did not crash");
}

TEST(test_egress_null_cursor_returns_error_tristate)
{
    struct ArrowArray arr;
    struct ArrowSchema sch;
    questdb_error* err = NULL;
    qwp_reader_arrow_batch_result rc =
        qwp_reader_cursor_next_arrow_batch(NULL, &arr, &sch, &err);
    CHECK(rc == qwp_reader_arrow_batch_error, "NULL cursor → error");
    CHECK(err != NULL, "err_out populated");
    if (err)
        questdb_error_free(err);
}

TEST(test_egress_null_out_array_returns_error_tristate)
{
    struct ArrowSchema sch;
    questdb_error* err = NULL;
    qwp_reader_arrow_batch_result rc =
        qwp_reader_cursor_next_arrow_batch(NULL, NULL, &sch, &err);
    CHECK(rc == qwp_reader_arrow_batch_error, "NULL out_array → error");
    if (err)
        questdb_error_free(err);
}

TEST(test_ingress_null_conn_returns_false)
{
    struct ArrowArray arr;
    struct ArrowSchema sch;
    memset(&arr, 0, sizeof(arr));
    memset(&sch, 0, sizeof(sch));
    line_sender_error* err = NULL;
    line_sender_table_name tbl = make_table("t");
    bool ok = qwp_sender_flush_arrow_batch_at_now(
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
    bool ok = qwp_sender_flush_arrow_batch_at_now(
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
    bool ok = qwp_sender_flush_arrow_batch_at_column(
        NULL, make_table("t"), &arr, &sch, make_col("ts"), NULL, 0, &err);
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

/* -- Per-column Arrow appender (qwp_chunk_append_arrow_column) -- */

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
    bool ok =
        qwp_chunk_append_arrow_column(NULL, "v", 1, &arr, &sch, 0, 0, &err);
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
    qwp_chunk* chunk = qwp_chunk_new("t", 1, &err);
    CHECK(chunk != NULL, "chunk constructed");
    CHECK(err == NULL, "no err on chunk_new");
    if (!chunk)
        return;
    bool ok =
        qwp_chunk_append_arrow_column(chunk, "v", 1, NULL, NULL, 0, 0, &err);
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
    qwp_chunk_free(chunk);
}

TEST(test_chunk_append_arrow_column_valid_i64_smoke)
{
    line_sender_error* err = NULL;
    qwp_chunk* chunk = qwp_chunk_new("t", 1, &err);
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

    bool ok =
        qwp_chunk_append_arrow_column(chunk, "v", 1, &arr, &sch, 0, 1, &err);
    CHECK(ok, "valid i64 append → true");
    CHECK(err == NULL, "no err on success");
    if (err)
        line_sender_error_free(err);
    CHECK(qwp_chunk_row_count(chunk, NULL) == 1, "row_count == 1");
    qwp_chunk_free(chunk);
}

static qwp_chunk* make_chunk_t(void)
{
    line_sender_error* err = NULL;
    qwp_chunk* chunk = qwp_chunk_new("t", 1, &err);
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
    bool ok = qwp_chunk_append_numpy_column(
        NULL,
        "v",
        1,
        qwp_numpy_i64,
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
    qwp_chunk* chunk = make_chunk_t();
    CHECK(chunk != NULL, "chunk constructed");
    if (!chunk)
        return;
    int64_t data[] = {1, 2, 3};
    line_sender_error* err = NULL;
    bool ok = qwp_chunk_append_numpy_column(
        chunk,
        "v",
        1,
        qwp_numpy_i64,
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
    CHECK(qwp_chunk_row_count(chunk, NULL) == 3, "row_count == 3");
    qwp_chunk_free(chunk);
}

TEST(test_chunk_append_numpy_column_f64_smoke)
{
    qwp_chunk* chunk = make_chunk_t();
    CHECK(chunk != NULL, "chunk constructed");
    if (!chunk)
        return;
    double data[] = {1.0, 2.0, 3.0};
    line_sender_error* err = NULL;
    bool ok = qwp_chunk_append_numpy_column(
        chunk,
        "v",
        1,
        qwp_numpy_f64,
        (const uint8_t*)data,
        sizeof(data),
        3,
        NULL,
        NULL,
        &err);
    CHECK(ok, "f64 append → true");
    if (err)
        line_sender_error_free(err);
    CHECK(qwp_chunk_row_count(chunk, NULL) == 3, "row_count == 3");
    qwp_chunk_free(chunk);
}

TEST(test_chunk_append_numpy_column_bool_smoke)
{
    qwp_chunk* chunk = make_chunk_t();
    CHECK(chunk != NULL, "chunk constructed");
    if (!chunk)
        return;
    uint8_t bits[] = {1, 0, 1};
    line_sender_error* err = NULL;
    bool ok = qwp_chunk_append_numpy_column(
        chunk, "v", 1, qwp_numpy_bool, bits, sizeof(bits), 3, NULL, NULL, &err);
    CHECK(ok, "bool append → true");
    if (err)
        line_sender_error_free(err);
    CHECK(qwp_chunk_row_count(chunk, NULL) == 3, "row_count == 3");
    qwp_chunk_free(chunk);
}

TEST(test_chunk_append_numpy_column_decimal_requires_extras)
{
    qwp_chunk* chunk = make_chunk_t();
    CHECK(chunk != NULL, "chunk constructed");
    if (!chunk)
        return;
    int64_t data[] = {1, 2, 3};
    line_sender_error* err = NULL;
    bool ok = qwp_chunk_append_numpy_column(
        chunk,
        "v",
        1,
        qwp_numpy_decimal_s8,
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
                "qwp_numpy_extras"),
            "msg mentions DECIMAL64 requires non-NULL extras");
        line_sender_error_free(err);
    }
    qwp_chunk_free(chunk);
}

TEST(test_chunk_append_numpy_column_decimal_scale_too_high)
{
    qwp_chunk* chunk = make_chunk_t();
    CHECK(chunk != NULL, "chunk constructed");
    if (!chunk)
        return;
    int64_t data[] = {1, 2, 3};
    qwp_numpy_extras extras;
    memset(&extras, 0, sizeof(extras));
    extras.decimal_scale = 19; /* cap is 18 for DECIMAL64 */
    line_sender_error* err = NULL;
    bool ok = qwp_chunk_append_numpy_column(
        chunk,
        "v",
        1,
        qwp_numpy_decimal_s8,
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
    qwp_chunk_free(chunk);
}

TEST(test_chunk_append_numpy_column_decimal_scale_negative)
{
    qwp_chunk* chunk = make_chunk_t();
    CHECK(chunk != NULL, "chunk constructed");
    if (!chunk)
        return;
    int64_t data[] = {1, 2, 3};
    qwp_numpy_extras extras;
    memset(&extras, 0, sizeof(extras));
    extras.decimal_scale = -1;
    line_sender_error* err = NULL;
    bool ok = qwp_chunk_append_numpy_column(
        chunk,
        "v",
        1,
        qwp_numpy_decimal_s8,
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
    qwp_chunk_free(chunk);
}

TEST(test_chunk_append_numpy_column_geohash_requires_extras)
{
    qwp_chunk* chunk = make_chunk_t();
    CHECK(chunk != NULL, "chunk constructed");
    if (!chunk)
        return;
    int8_t data[] = {1, 2, 3};
    line_sender_error* err = NULL;
    bool ok = qwp_chunk_append_numpy_column(
        chunk,
        "v",
        1,
        qwp_numpy_geohash_i8,
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
    qwp_chunk_free(chunk);
}

TEST(test_chunk_append_numpy_column_geohash_bits_zero)
{
    qwp_chunk* chunk = make_chunk_t();
    CHECK(chunk != NULL, "chunk constructed");
    if (!chunk)
        return;
    int8_t data[] = {1, 2, 3};
    qwp_numpy_extras extras;
    memset(&extras, 0, sizeof(extras));
    extras.geohash_bits = 0;
    line_sender_error* err = NULL;
    bool ok = qwp_chunk_append_numpy_column(
        chunk,
        "v",
        1,
        qwp_numpy_geohash_i8,
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
    qwp_chunk_free(chunk);
}

TEST(test_chunk_append_numpy_column_geohash_bits_too_high)
{
    qwp_chunk* chunk = make_chunk_t();
    CHECK(chunk != NULL, "chunk constructed");
    if (!chunk)
        return;
    int8_t data[] = {1, 2, 3};
    qwp_numpy_extras extras;
    memset(&extras, 0, sizeof(extras));
    extras.geohash_bits = 9; /* cap is 8 for i8 */
    line_sender_error* err = NULL;
    bool ok = qwp_chunk_append_numpy_column(
        chunk,
        "v",
        1,
        qwp_numpy_geohash_i8,
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
    qwp_chunk_free(chunk);
}

TEST(test_chunk_append_numpy_column_f64_ndarray_requires_extras)
{
    qwp_chunk* chunk = make_chunk_t();
    CHECK(chunk != NULL, "chunk constructed");
    if (!chunk)
        return;
    double data[] = {1.0, 2.0, 3.0};
    line_sender_error* err = NULL;
    bool ok = qwp_chunk_append_numpy_column(
        chunk,
        "v",
        1,
        qwp_numpy_f64_ndarray,
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
    qwp_chunk_free(chunk);
}

TEST(test_chunk_append_numpy_column_f64_ndarray_ndim_zero)
{
    qwp_chunk* chunk = make_chunk_t();
    CHECK(chunk != NULL, "chunk constructed");
    if (!chunk)
        return;
    double data[] = {1.0, 2.0, 3.0};
    qwp_numpy_extras extras;
    memset(&extras, 0, sizeof(extras));
    extras.array_ndim = 0;
    extras.array_shape = NULL;
    line_sender_error* err = NULL;
    bool ok = qwp_chunk_append_numpy_column(
        chunk,
        "v",
        1,
        qwp_numpy_f64_ndarray,
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
    qwp_chunk_free(chunk);
}

TEST(test_chunk_append_numpy_column_f64_ndarray_ndim_too_high)
{
    qwp_chunk* chunk = make_chunk_t();
    CHECK(chunk != NULL, "chunk constructed");
    if (!chunk)
        return;
    double data[] = {1.0};
    uint32_t shape[33];
    for (int i = 0; i < 33; ++i)
        shape[i] = 1;
    qwp_numpy_extras extras;
    memset(&extras, 0, sizeof(extras));
    extras.array_ndim = 33; /* cap is 32 */
    extras.array_shape = shape;
    line_sender_error* err = NULL;
    bool ok = qwp_chunk_append_numpy_column(
        chunk,
        "v",
        1,
        qwp_numpy_f64_ndarray,
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
    qwp_chunk_free(chunk);
}

TEST(test_chunk_append_numpy_column_f64_ndarray_null_shape)
{
    qwp_chunk* chunk = make_chunk_t();
    CHECK(chunk != NULL, "chunk constructed");
    if (!chunk)
        return;
    double data[] = {1.0, 2.0, 3.0};
    qwp_numpy_extras extras;
    memset(&extras, 0, sizeof(extras));
    extras.array_ndim = 2;
    extras.array_shape = NULL;
    line_sender_error* err = NULL;
    bool ok = qwp_chunk_append_numpy_column(
        chunk,
        "v",
        1,
        qwp_numpy_f64_ndarray,
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
    qwp_chunk_free(chunk);
}

TEST(test_chunk_append_numpy_column_f64_ndarray_zero_dim)
{
    qwp_chunk* chunk = make_chunk_t();
    CHECK(chunk != NULL, "chunk constructed");
    if (!chunk)
        return;
    double data[] = {1.0, 2.0, 3.0};
    uint32_t shape[] = {3, 0};
    qwp_numpy_extras extras;
    memset(&extras, 0, sizeof(extras));
    extras.array_ndim = 2;
    extras.array_shape = shape;
    line_sender_error* err = NULL;
    bool ok = qwp_chunk_append_numpy_column(
        chunk,
        "v",
        1,
        qwp_numpy_f64_ndarray,
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
    qwp_chunk_free(chunk);
}

TEST(test_chunk_append_numpy_column_f64_ndarray_smoke)
{
    qwp_chunk* chunk = make_chunk_t();
    CHECK(chunk != NULL, "chunk constructed");
    if (!chunk)
        return;
    /* Per-row tensor shape [3], row_count = 2 → 6 doubles of source data. */
    double data[6] = {1.0, 2.0, 3.0, 4.0, 5.0, 6.0};
    uint32_t shape[] = {3};
    qwp_numpy_extras extras;
    memset(&extras, 0, sizeof(extras));
    extras.array_ndim = 1;
    extras.array_shape = shape;
    line_sender_error* err = NULL;
    bool ok = qwp_chunk_append_numpy_column(
        chunk,
        "v",
        1,
        qwp_numpy_f64_ndarray,
        (const uint8_t*)data,
        sizeof(data),
        2,
        NULL,
        &extras,
        &err);
    CHECK(ok, "ndarray 1-D shape {3} × 2 rows → true");
    if (err)
        line_sender_error_free(err);
    CHECK(qwp_chunk_row_count(chunk, NULL) == 2, "row_count == 2");
    qwp_chunk_free(chunk);
}

TEST(test_chunk_append_numpy_column_data_len_too_small)
{
    qwp_chunk* chunk = make_chunk_t();
    CHECK(chunk != NULL, "chunk constructed");
    if (!chunk)
        return;
    /* 3 i64 rows need 24 bytes; claim only 16 → must be rejected. */
    int64_t data[] = {1, 2, 3};
    line_sender_error* err = NULL;
    bool ok = qwp_chunk_append_numpy_column(
        chunk,
        "v",
        1,
        qwp_numpy_i64,
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
    CHECK(qwp_chunk_row_count(chunk, NULL) == 0, "nothing appended");
    qwp_chunk_free(chunk);
}

TEST(test_chunk_append_numpy_column_mistagged_dtype_rejected)
{
    qwp_chunk* chunk = make_chunk_t();
    CHECK(chunk != NULL, "chunk constructed");
    if (!chunk)
        return;
    /* An int8 buffer (3 bytes) mis-tagged f64 would read 24 bytes; the
     * honest data_len_bytes = 3 must stop it before the OOB read. */
    int8_t data[] = {1, 2, 3};
    line_sender_error* err = NULL;
    bool ok = qwp_chunk_append_numpy_column(
        chunk,
        "v",
        1,
        qwp_numpy_f64,
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
    qwp_chunk_free(chunk);
}

TEST(test_chunk_append_numpy_column_data_len_exact_ok)
{
    qwp_chunk* chunk = make_chunk_t();
    CHECK(chunk != NULL, "chunk constructed");
    if (!chunk)
        return;
    /* Exact fit: 3 i64 rows == 24 bytes is accepted (boundary). */
    int64_t data[] = {1, 2, 3};
    line_sender_error* err = NULL;
    bool ok = qwp_chunk_append_numpy_column(
        chunk,
        "v",
        1,
        qwp_numpy_i64,
        (const uint8_t*)data,
        24,
        3,
        NULL,
        NULL,
        &err);
    CHECK(ok, "exact data_len_bytes → true");
    if (err)
        line_sender_error_free(err);
    CHECK(qwp_chunk_row_count(chunk, NULL) == 3, "row_count == 3");
    qwp_chunk_free(chunk);
}

TEST(test_error_codes_survive_ffi_boundary)
{
    int sender_code = (int)line_sender_error_arrow_unsupported_column_kind;
    int ingest_code = (int)line_sender_error_arrow_ingest;
    int drift_code = (int)questdb_error_schema_drift;
    int no_schema_code = (int)questdb_error_no_schema;
    int export_code = (int)questdb_error_arrow_export;
    CHECK(sender_code != ingest_code, "sender codes distinct");
    CHECK(drift_code != no_schema_code, "query codes distinct");
    CHECK(no_schema_code != export_code, "query codes distinct");
}

/* ---------------------------------------------------------------------------
 * Mock-backed per-type smoke tests — migrated from the deleted buffer-level
 * `line_sender_buffer_append_arrow` C suite. Each test:
 *   1. Builds a single-column ArrowArray + ArrowSchema on the stack.
 *   2. Spins up `qwp_mock_c` (1-slot, accepts one QWP1 binary frame).
 *   3. Opens a `questdb_db` against the mock + borrows a `qwp_sender`.
 *   4. Calls `qwp_sender_flush_arrow_batch[_at_column]`.
 *   5. Accepts either ok=true OR a documented structured error code.
 * Per-column wire correctness is owned by the Rust unit tests under
 * `questdb-rs/src/ingress/qwp_sender/arrow_batch.rs`.
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
    qwp_chunk* chunk = qwp_chunk_new("t", 1, &err);
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
    bool ok =
        qwp_chunk_append_arrow_column(chunk, "v", 1, arr, sch, 0, 0, &err);
    CHECK(!ok, label);
    CHECK(err != NULL, "err_out populated on malformed array");
    if (err)
    {
        int code = (int)line_sender_error_get_code(err);
        int accepted = code == line_sender_error_arrow_ingest ||
                       code == line_sender_error_invalid_api_call;
        CHECK(accepted, "malformed array → structured error (not abort)");
        line_sender_error_free(err);
    }
    CHECK(arr->release != NULL, "release intact on pre-import array reject");
    if (arr->release)
        arr->release(arr);
    if (sch->release)
        sch->release(sch);
    qwp_chunk_free(chunk);
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
static qwp_sender* mock_borrow_sender_frames(
    qwp_mock_c** out_mock, questdb_db** out_db, int frame_count)
{
    *out_mock = NULL;
    *out_db = NULL;
    qwp_mock_c* mock = qwp_mock_c_start_frames(1, frame_count);
    if (mock == NULL)
        return NULL;
    const char* addr = qwp_mock_c_addr(mock);
    char conf[256];
    snprintf(
        conf,
        sizeof(conf),
        "ws::addr=%s;lazy_connect=true;sender_pool_min=1;pool_reap=manual;"
        "close_flush_timeout_millis=0;",
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
    qwp_sender* conn = questdb_db_borrow_sender(db, &err);
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

static qwp_sender* mock_borrow_sender(
    qwp_mock_c** out_mock, questdb_db** out_db)
{
    return mock_borrow_sender_frames(out_mock, out_db, 1);
}

static void mock_return_close(
    qwp_mock_c* mock, questdb_db* db, qwp_sender* conn)
{
    if (conn != NULL && db != NULL)
        questdb_db_return_sender(db, conn);
    if (db != NULL)
        questdb_db_close(db);
    if (mock != NULL)
        qwp_mock_c_stop(mock);
}

TEST(test_one_sender_flushes_buffer_and_chunk)
{
    qwp_mock_c* mock;
    questdb_db* db;
    qwp_sender* sender = mock_borrow_sender_frames(&mock, &db, 2);
    CHECK(sender != NULL, "unified sender borrowed");
    if (sender == NULL)
        return;

    line_sender_error* err = NULL;
    line_sender_buffer* buffer = questdb_db_new_buffer(db, &err);
    CHECK(buffer != NULL, "buffer constructed from pool");
    CHECK(err == NULL, "no error constructing buffer");
    if (buffer != NULL)
    {
        line_sender_table_name table = make_table("mixed_c_buffer");
        line_sender_column_name value = make_col("value");
        CHECK(line_sender_buffer_table(buffer, table, &err), "buffer table");
        CHECK(
            line_sender_buffer_column_i64(buffer, value, 1, &err),
            "buffer value");
        CHECK(line_sender_buffer_at_now(buffer, &err), "buffer timestamp");
        CHECK(
            qwp_sender_flush_buffer(sender, buffer, &err),
            "buffer published through unified sender");
    }

    qwp_chunk* chunk =
        qwp_chunk_new("mixed_c_chunk", strlen("mixed_c_chunk"), &err);
    CHECK(chunk != NULL, "chunk constructed");
    if (chunk != NULL)
    {
        int64_t value = 2;
        CHECK(
            qwp_chunk_column_i64(
                chunk, "value", strlen("value"), &value, 1, NULL, &err),
            "chunk value");
        CHECK(qwp_chunk_at_now(chunk, &err), "chunk timestamp");
        CHECK(
            qwp_sender_flush_chunk(sender, chunk, &err),
            "chunk published through the same unified sender");
    }

    if (err != NULL)
    {
        line_sender_error_free(err);
        err = NULL;
    }
    if (chunk != NULL)
        qwp_chunk_free(chunk);
    if (buffer != NULL)
        line_sender_buffer_free(buffer);
    mock_return_close(mock, db, sender);
}

/* A standalone QWP/WebSocket sender with the extra `settings` of its
 * configuration string, connected to a mock that takes ingress frames as a
 * server with a frame limit of `frame_limit` bytes does. Returns NULL on any
 * setup failure; populates *out_mock on success. */
static line_sender* ingress_sender_with(
    qwp_mock_c** out_mock, size_t frame_limit, const char* settings)
{
    *out_mock = NULL;
    qwp_mock_c* mock = qwp_mock_c_start_ingress(frame_limit);
    if (mock == NULL)
        return NULL;
    char conf[128];
    snprintf(
        conf, sizeof(conf), "ws::addr=%s;%s", qwp_mock_c_addr(mock), settings);
    line_sender_utf8 conf_utf8 = {strlen(conf), conf};
    line_sender_error* err = NULL;
    line_sender* sender = line_sender_from_conf(conf_utf8, &err);
    if (sender == NULL)
    {
        if (err)
            line_sender_error_free(err);
        qwp_mock_c_stop(mock);
        return NULL;
    }
    *out_mock = mock;
    return sender;
}

/* `ingress_sender_with` without extra settings. */
static line_sender* ingress_sender(qwp_mock_c** out_mock, size_t frame_limit)
{
    return ingress_sender_with(out_mock, frame_limit, "");
}

/* True when `err` has `code` and its message contains `text`. Frees `err`. */
static bool error_is(
    line_sender_error* err, line_sender_error_code code, const char* text)
{
    if (err == NULL)
        return false;
    size_t len = 0;
    const char* msg = line_sender_error_msg(err, &len);
    const size_t text_len = strlen(text);
    bool found = false;
    for (size_t i = 0; !found && i + text_len <= len; ++i)
        found = memcmp(msg + i, text, text_len) == 0;
    const bool same_code = line_sender_error_get_code(err) == code;
    if (!same_code || !found)
        fprintf(
            stderr,
            "error code %d: %.*s\n",
            (int)line_sender_error_get_code(err),
            (int)len,
            msg);
    line_sender_error_free(err);
    return same_code && found;
}

/* One flush of a row buffer above the frame cap goes out in several frames:
 * all but the last have the defer flag, so the server commits them together
 * when the last one comes, and its answer confirms the whole flush. */
TEST(test_flush_above_the_frame_cap_goes_out_in_frames)
{
    const size_t frame_limit = 64 * 1024;
    const int64_t rows = 20000;
    qwp_mock_c* mock;
    line_sender* sender = ingress_sender(&mock, frame_limit);
    CHECK(sender != NULL, "sender connected to the mock");
    if (sender == NULL)
        return;
    line_sender_error* err = NULL;
    line_sender_buffer* buffer = line_sender_buffer_new_for_sender(sender);
    CHECK(buffer != NULL, "buffer of the sender");

    size_t cap = 0;
    bool server_cap_known = false;
    CHECK(
        line_sender_qwpws_effective_frame_cap(
            sender, &cap, &server_cap_known, &err),
        "frame cap read");
    CHECK(cap == frame_limit, "the frame cap is the limit the server told");
    CHECK(server_cap_known, "the server told its frame limit");

    line_sender_table_name table = make_table("c_large_flush");
    line_sender_column_name id = make_col("id");
    bool added = true;
    for (int64_t i = 0; added && i < rows; ++i)
        added = line_sender_buffer_table(buffer, table, &err) &&
                line_sender_buffer_column_i64(buffer, id, i, &err) &&
                line_sender_buffer_at_nanos(
                    buffer, 1700000000000000000LL + i, &err);
    CHECK(added, "rows added");
    CHECK(
        line_sender_buffer_size(buffer) > 4 * frame_limit,
        "the buffer is several times the frame cap");

    line_sender_qwpws_fsn fsn = {false, 0};
    CHECK(
        line_sender_qwpws_flush_and_get_fsn(sender, buffer, &fsn, &err),
        "a buffer above the frame cap is flushed");
    CHECK(line_sender_buffer_row_count(buffer) == 0, "the flush clears it");
    CHECK(
        line_sender_qwpws_wait(sender, qwpws_ack_level_ok, 5000, &err),
        "the flush is confirmed");
    line_sender_qwpws_fsn acked = {false, 0};
    CHECK(line_sender_qwpws_acked_fsn(sender, &acked, &err), "acked read");
    CHECK(
        fsn.has_value && acked.has_value && acked.value == fsn.value,
        "the flush is confirmed up to its last frame");

    /* The server answered the last frame, so it has counted them all. */
    const size_t frames = qwp_mock_c_ingress_frame_count(mock);
    CHECK(frames > 4, "the flush went out in several frames");
    CHECK(
        fsn.value + 1 == frames,
        "the flush returns the number of its last frame");
    for (size_t i = 0; i < frames; ++i)
    {
        size_t size = 0;
        bool deferred = false;
        CHECK(
            qwp_mock_c_ingress_frame(mock, i, &size, &deferred),
            "frame recorded");
        CHECK(size <= frame_limit, "each frame is within the frame limit");
        CHECK(
            deferred == (i + 1 < frames),
            "every frame but the last has the defer flag");
    }

    CHECK(line_sender_qwpws_close_drain(sender, &err), "close_drain");
    CHECK(!line_sender_must_close(sender), "the sender is in order");
    CHECK(err == NULL, "no error");
    if (err != NULL)
        line_sender_error_free(err);
    line_sender_buffer_free(buffer);
    line_sender_close(sender);
    qwp_mock_c_stop(mock);
}

/* A flush in several frames that cannot queue one of them, here because the
 * symbol dictionary of the connection is full (2,000,000 entries), fails
 * with `line_sender_error_flush_aborted`: nothing of it is committed, the
 * buffer keeps its rows, and the sender takes no more flushes while it still
 * delivers the flush before. The sender is driven by its caller, so nothing
 * sends a frame of the flush while it runs: the error is not in doubt, and
 * the sender sends no frame of it afterwards either. */
TEST(test_flush_that_stops_part_way_fails_with_flush_aborted)
{
    const size_t frame_limit = 1024 * 1024;
    /* With the symbol of the first flush, one more than the dictionary
     * holds. */
    const size_t symbols = 2000000;
    qwp_mock_c* mock;
    line_sender* sender =
        ingress_sender_with(&mock, frame_limit, "qwp_ws_progress=manual;");
    CHECK(sender != NULL, "sender connected to the mock");
    if (sender == NULL)
        return;
    line_sender_error* err = NULL;
    line_sender_buffer* buffer = line_sender_buffer_new_for_sender(sender);
    CHECK(buffer != NULL, "buffer of the sender");
    line_sender_table_name table = make_table("c_aborted_flush");
    line_sender_column_name sym = make_col("sym");

    line_sender_utf8 first = {strlen("first"), "first"};
    CHECK(
        line_sender_buffer_table(buffer, table, &err) &&
            line_sender_buffer_symbol(buffer, sym, first, &err) &&
            line_sender_buffer_at_nanos(buffer, 1700000000000000000LL, &err),
        "a row added");
    line_sender_qwpws_fsn before = {false, 0};
    CHECK(
        line_sender_qwpws_flush_and_get_fsn(sender, buffer, &before, &err),
        "the flush before");
    CHECK(before.has_value, "the flush before has a frame number");

    bool added = true;
    for (size_t i = 0; added && i < symbols; ++i)
    {
        char text[16];
        const int len = snprintf(text, sizeof(text), "%x", (unsigned)i);
        line_sender_utf8 symbol = {(size_t)len, text};
        added = line_sender_buffer_table(buffer, table, &err) &&
                line_sender_buffer_symbol(buffer, sym, symbol, &err) &&
                line_sender_buffer_at_nanos(
                    buffer, 1700000000000000000LL + (int64_t)i, &err);
    }
    CHECK(added, "rows added");
    CHECK(err == NULL, "no error so far");

    CHECK(
        !line_sender_flush(sender, buffer, &err),
        "the flush that fills the dictionary fails");
    CHECK(
        err != NULL && !line_sender_error_in_doubt(err),
        "no frame of the flush was sent: the error is not in doubt");
    CHECK(
        error_is(
            err,
            line_sender_error_flush_aborted,
            "None of its frames reached the server, nothing of it is "
            "committed"),
        "the flush fails with flush_aborted, which says nothing of it was "
        "sent");
    err = NULL;
    CHECK(
        line_sender_buffer_row_count(buffer) == symbols,
        "the buffer keeps its rows");
    CHECK(line_sender_must_close(sender), "the sender must be closed");
    line_sender_qwpws_fsn published = {false, 0};
    CHECK(
        line_sender_qwpws_published_fsn(sender, &published, &err),
        "published read");
    CHECK(
        published.has_value && published.value == before.value,
        "published is the last frame before the failed flush");

    /* A row whose symbol the dictionary holds: its flush would fit. */
    line_sender_buffer* small = line_sender_buffer_new_for_sender(sender);
    CHECK(small != NULL, "second buffer of the sender");
    CHECK(
        line_sender_buffer_table(small, table, &err) &&
            line_sender_buffer_symbol(small, sym, first, &err) &&
            line_sender_buffer_at_nanos(small, 1700000000000000000LL, &err),
        "a row added");
    CHECK(
        !line_sender_flush(sender, small, &err),
        "the sender takes no more flushes");
    CHECK(
        err != NULL && !line_sender_error_in_doubt(err),
        "nothing of the later flush was sent: its error is not in doubt");
    CHECK(
        error_is(
            err,
            line_sender_error_flush_aborted,
            "an earlier flush stopped part way"),
        "a later flush fails with flush_aborted too");
    err = NULL;
    CHECK(
        line_sender_buffer_row_count(small) == 1, "that buffer keeps its row");
    line_sender_buffer_free(small);

    CHECK(
        line_sender_qwpws_wait(sender, qwpws_ack_level_ok, 5000, &err),
        "wait covers the flush before the failed one");
    line_sender_qwpws_fsn acked = {false, 0};
    CHECK(line_sender_qwpws_acked_fsn(sender, &acked, &err), "acked read");
    CHECK(
        acked.has_value && acked.value == before.value,
        "the flush before is confirmed");
    CHECK(
        line_sender_qwpws_close_drain(sender, &err),
        "close_drain succeeds after the failed flush");
    CHECK(err == NULL, "no error after the failed flush");
    if (err != NULL)
        line_sender_error_free(err);
    line_sender_buffer_free(buffer);
    line_sender_close(sender);

    /* The server took the flush before, and no frame of the failed flush. */
    CHECK(
        qwp_mock_c_wait_for_ingress_closed(mock, 1, 5000),
        "the connection ended");
    CHECK(
        qwp_mock_c_ingress_frame_count(mock) == 1,
        "only the flush before was sent");
    size_t size = 0;
    bool deferred = true;
    CHECK(
        qwp_mock_c_ingress_frame(mock, 0, &size, &deferred) && !deferred,
        "the flush before was sent to be committed");
    qwp_mock_c_stop(mock);
}

static void run_arrow_flush(
    struct ArrowArray* arr,
    struct ArrowSchema* sch,
    const char* table,
    const char* label)
{
    qwp_mock_c* mock;
    questdb_db* db;
    qwp_sender* conn = mock_borrow_sender(&mock, &db);
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
    bool ok =
        qwp_sender_flush_arrow_batch_at_now(conn, tbl, arr, sch, NULL, 0, &err);
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
    qwp_sender* conn = mock_borrow_sender(&mock, &db);
    CHECK(conn != NULL, "mock conn borrowed");
    if (conn == NULL)
        return;
    struct ArrowSchema sch;
    memset(&sch, 0, sizeof(sch));
    line_sender_error* err = NULL;
    bool ok = qwp_sender_flush_arrow_batch_at_now(
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
            line_sender_error_get_code(err) == line_sender_error_invalid_name,
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
        run_arrow_flush(
            &arr, &sch, "f32_t", "float32 accepted/structured-error");
    }
    {
        double values[3] = {1.5, -2.5, 3.14159};
        struct ArrowArray arr;
        struct ArrowSchema sch;
        build_primitive(3, sizeof(double), values, "g", "f6", &arr, &sch);
        run_arrow_flush(
            &arr, &sch, "f64_t", "float64 accepted/structured-error");
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
    run_arrow_flush(
        &arr, &sch, "ts_t", "timestamp(µs) accepted/structured-error");
}

TEST(test_mock_ingress_both_designated_timestamp_variants)
{
    /* The original test exercised three DesignatedTimestamp kinds
     * (Now / ServerNow / Column). In the new conn-level API the first
     * two collapse onto `qwp_sender_flush_arrow_batch_at_now`
     * (no per-row stamp — server stamps on arrival), and Column maps to the
     * dedicated `qwp_sender_flush_arrow_batch_at_column`. We cover
     * both surviving variants here. */

    /* No-TS variant. */
    {
        int64_t values[2] = {10, 20};
        struct ArrowArray arr;
        struct ArrowSchema sch;
        build_primitive(2, sizeof(int64_t), values, "l", "v", &arr, &sch);
        run_arrow_flush(
            &arr, &sch, "dts_t_now", "no-ts accepted/structured-error");
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
        qwp_sender* conn = mock_borrow_sender(&mock, &db);
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
        bool ok = qwp_sender_flush_arrow_batch_at_column(
            conn, tbl, &arr, &sch, ts_col, NULL, 0, &err);
        CHECK(!ok, "missing ts column → false");
        if (err)
        {
            int code = (int)line_sender_error_get_code(err);
            int accepted = code == line_sender_error_arrow_ingest ||
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
 * `qwp_sender_flush_arrow_batch_at_now` on all three states: pre-import
 * failure leaves release intact (caller frees), a malformed nested schema
 * is rejected gracefully (not by aborting the panic=abort FFI crate) with
 * release intact, and a structurally-valid batch that reaches the Arrow
 * import step has release consumed regardless of the eventual outcome. */
TEST(test_mock_ingress_arrow_release_contract)
{
    qwp_mock_c* mock;
    questdb_db* db;
    qwp_sender* conn = mock_borrow_sender(&mock, &db);
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
        bool ok = qwp_sender_flush_arrow_batch_at_now(
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
        bool ok = qwp_sender_flush_arrow_batch_at_now(
            conn, make_table("rc_b"), &arr, &sch, NULL, 0, &err);
        CHECK(!ok, "malformed +l schema → false");
        CHECK(err != NULL, "err_out populated on malformed schema");
        if (err)
        {
            int code = (int)line_sender_error_get_code(err);
            int accepted = code == line_sender_error_arrow_ingest ||
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
        bool ok = qwp_sender_flush_arrow_batch_at_now(
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

#define NATIVE_CHECK(expr)                                                     \
    do                                                                         \
    {                                                                          \
        bool pass_ = (expr);                                                   \
        CHECK(pass_, #expr);                                                   \
        if (!pass_)                                                            \
            return;                                                            \
    } while (0)
#define NATIVE_OK(expr)                                                        \
    do                                                                         \
    {                                                                          \
        NATIVE_CHECK(expr);                                                    \
        NATIVE_CHECK(err == NULL);                                             \
    } while (0)
#define NATIVE_BAD(expr)                                                       \
    do                                                                         \
    {                                                                          \
        NATIVE_CHECK(!(expr));                                                 \
        NATIVE_CHECK(err != NULL);                                             \
        NATIVE_CHECK(                                                          \
            line_sender_error_get_code(err) ==                                 \
            line_sender_error_invalid_api_call);                               \
        line_sender_error_free(err);                                           \
        err = NULL;                                                            \
    } while (0)

TEST(test_native_decimal_and_array_columns)
{
    line_sender_error* err = NULL;
    qwp_chunk* chunk = qwp_chunk_new("native_columns", 14, &err);
    NATIVE_CHECK(chunk != NULL && err == NULL);
    const int64_t decimals[] = {12345, 0, -12345};
    /* Offsets deliberately remove any int128 alignment guarantee. */
    uint8_t wide128[49] = {0};
    uint8_t wide256[97] = {0};
    wide128[1] = 1;
    wide256[1] = 1;
    memset(wide128 + 33, 0xff, 16);
    memset(wide256 + 65, 0xff, 32);
    const uint8_t bits[] = {5};
    const qwp_validity valid = {bits, 3};
    const qwp_validity wrong_validity = {bits, 2};
    const double arrays[] = {
        100.25, NAN, 10, 20, 0, 0, 0, 0, 101, 100.5, 30, 40};
    const uint32_t shape[] = {2, 2};
    const uint32_t zero_shape[] = {2, 0};

    NATIVE_BAD(qwp_chunk_column_decimal64(
        chunk, "d64", 3, decimals, 3, 19, NULL, &err));
    NATIVE_BAD(qwp_chunk_column_decimal128(
        chunk, "d128", 4, wide128 + 1, 3, 39, NULL, &err));
    NATIVE_BAD(qwp_chunk_column_decimal256(
        chunk, "d256", 4, wide256 + 1, 3, 77, NULL, &err));
    NATIVE_BAD(
        qwp_chunk_column_decimal64(chunk, "d64", 3, NULL, 3, 2, NULL, &err));
    NATIVE_BAD(
        qwp_chunk_column_decimal128(chunk, "d128", 4, NULL, 3, 9, NULL, &err));
    NATIVE_BAD(
        qwp_chunk_column_decimal256(chunk, "d256", 4, NULL, 3, 76, NULL, &err));
    NATIVE_BAD(qwp_chunk_column_decimal128(
        NULL, "d128", 4, wide128 + 1, 3, 9, NULL, &err));
    NATIVE_BAD(qwp_chunk_column_decimal256(
        chunk, "d256", 4, wide256 + 1, SIZE_MAX, 0, NULL, &err));
    NATIVE_BAD(qwp_chunk_column_f64_array(
        chunk, "a", 1, arrays, 12, 3, shape, 0, NULL, &err));
    NATIVE_BAD(qwp_chunk_column_f64_array(
        chunk, "a", 1, arrays, 12, 3, shape, 33, NULL, &err));
    NATIVE_BAD(qwp_chunk_column_f64_array(
        chunk, "a", 1, arrays, 12, 3, zero_shape, 2, NULL, &err));
    NATIVE_BAD(qwp_chunk_column_f64_array(
        chunk, "a", 1, arrays, 11, 3, shape, 2, NULL, &err));
    NATIVE_BAD(qwp_chunk_column_f64_array(
        chunk, "a", 1, NULL, 12, 3, shape, 2, NULL, &err));
    NATIVE_BAD(qwp_chunk_column_f64_array(
        chunk, "a", 1, arrays, 12, 3, NULL, 2, NULL, &err));
    NATIVE_BAD(qwp_chunk_column_f64_array(
        chunk, "a", 1, arrays, SIZE_MAX, 3, shape, 2, NULL, &err));
    NATIVE_BAD(qwp_chunk_column_decimal64(
        chunk, "d64", 3, decimals, 3, 2, &wrong_validity, &err));
    NATIVE_BAD(qwp_chunk_column_decimal128(
        chunk, "d128", 4, wide128 + 1, 3, 9, &wrong_validity, &err));
    NATIVE_BAD(qwp_chunk_column_decimal256(
        chunk, "d256", 4, wide256 + 1, 3, 76, &wrong_validity, &err));
    NATIVE_BAD(qwp_chunk_column_f64_array(
        chunk, "a", 1, arrays, 12, 3, shape, 2, &wrong_validity, &err));
    NATIVE_CHECK(qwp_chunk_row_count(chunk, &err) == 0 && err == NULL);

    NATIVE_OK(qwp_chunk_column_decimal64(
        chunk, "d64", 3, decimals, 3, 18, &valid, &err));
    NATIVE_OK(qwp_chunk_column_decimal128(
        chunk, "d128", 4, wide128 + 1, 3, 38, &valid, &err));
    NATIVE_OK(qwp_chunk_column_decimal256(
        chunk, "d256", 4, wide256 + 1, 3, 76, &valid, &err));
    NATIVE_OK(qwp_chunk_column_f64_array(
        chunk, "a", 1, arrays, 12, 3, shape, 2, &valid, &err));
    NATIVE_CHECK(qwp_chunk_row_count(chunk, &err) == 3 && err == NULL);
    NATIVE_BAD(qwp_chunk_column_decimal64(
        chunk, "d64", 3, decimals, 3, 0, NULL, &err));
    NATIVE_BAD(qwp_chunk_column_decimal128(
        chunk, "other", 5, wide128 + 1, 2, 0, NULL, &err));
    NATIVE_BAD(qwp_chunk_column_f64_array(
        chunk, "other", 5, arrays, 4, 1, shape, 2, NULL, &err));
    qwp_chunk_free(chunk);

    chunk = qwp_chunk_new("empty", 5, &err);
    NATIVE_CHECK(chunk != NULL && err == NULL);
    NATIVE_OK(
        qwp_chunk_column_decimal64(chunk, "d64", 3, NULL, 0, 0, NULL, &err));
    NATIVE_OK(
        qwp_chunk_column_decimal128(chunk, "d128", 4, NULL, 0, 0, NULL, &err));
    NATIVE_OK(
        qwp_chunk_column_decimal256(chunk, "d256", 4, NULL, 0, 0, NULL, &err));
    NATIVE_OK(qwp_chunk_column_f64_array(
        chunk, "a", 1, NULL, 0, 0, shape, 2, NULL, &err));
    qwp_chunk_free(chunk);
}

#undef NATIVE_CHECK
#undef NATIVE_OK
#undef NATIVE_BAD

int main(void)
{
    RUN(test_tristate_egress_enum_values);
    RUN(test_native_decimal_and_array_columns);
    RUN(test_appended_query_error_codes_have_distinct_values);
    RUN(test_appended_sender_error_codes_exist);
    RUN(test_symbol_dict_full_is_a_distinct_appended_code);
    RUN(test_query_timeout_is_a_distinct_appended_code);
    RUN(test_flush_aborted_is_a_distinct_appended_code);
    RUN(test_query_set_timeout_ms_null_query_is_tolerated);
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
    RUN(test_one_sender_flushes_buffer_and_chunk);
    RUN(test_flush_above_the_frame_cap_goes_out_in_frames);
    RUN(test_flush_that_stops_part_way_fails_with_flush_aborted);
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
