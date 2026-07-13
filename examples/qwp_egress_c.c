/* C twin of questdb-rs/examples/qwp_egress_polars.rs. Populates the bench
 * table over QWP/WS (unless SKIP_POPULATE), then measures reading it back:
 *   decode-only  (floor) — drain reader_cursor_next_batch, count rows
 *   materialize  (e2e)   — additionally touch every cell via the
 *                          reader_column_data getters (the C-user analog of
 *                          assembling a DataFrame)
 * Reader conf mirrors the Rust example: fresh reader per iteration,
 * "ws::addr={host}:{port};compression=raw;". client="c-columnar".
 *
 * Shares env parsing, error exit and the stage/flush/checkpoint pass with
 * qwp_ingress_c.c via bench_ingest_c.{h,c} (Task 4). */
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <questdb/egress/reader.h>
#include <questdb/ingress/column_sender.h>

#include "bench_http_c.h"
#include "bench_ingest_c.h"
#include "bench_json_c.h"
#include "bench_schema_c.h"

#define PROG "qwp_egress_c"
#define POPULATE_BATCH_ROWS 10000 /* Rust egress hardcodes max_rows(10_000) */

static void populate(const char* host, size_t port, const char* base,
                     schema_kind kind, size_t rows, size_t sym_card,
                     size_t varchar_len, size_t hi_sym_card)
{
    const char* table = schema_table(kind);
    char drop[256];
    snprintf(drop, sizeof(drop), "DROP TABLE IF EXISTS %s", table);
    if (http_exec_sql(base, drop) != 0
        || http_exec_sql(base, schema_create_sql(kind)) != 0)
        exit(1);

    bench_data d;
    if (bench_data_build(&d, kind, rows, sym_card, varchar_len, hi_sym_card) != 0) {
        fprintf(stderr, "[" PROG "] data build OOM\n");
        exit(1);
    }
    char conf[256];
    snprintf(conf, sizeof(conf),
             "ws::addr=%s:%zu;sender_pool_min=1;sender_pool_max=1;pool_reap=manual;",
             host, port);
    line_sender_error* err = NULL;
    questdb_db* db = questdb_db_connect(conf, strlen(conf), &err);
    if (!db) bench_die(PROG, "connect", err);
    /* Direct sender = the pipelined backend flush_polars_dataframe uses
     * (parity with the Rust bench). Unlike the store-and-forward sender it
     * never re-states the connection-lifetime symbol dict in replay frames,
     * and it has no internal failover — errors are fatal for the bench
     * (bench_die), which is the intended behavior. */
    direct_column_sender* sender =
        questdb_db_borrow_direct_column_sender(db, &err);
    if (!sender) bench_die(PROG, "borrow sender", err);
    column_sender_chunk* chunk = column_sender_chunk_new(table, strlen(table), &err);
    if (!chunk) bench_die(PROG, "chunk_new", err);

    stage_scratch scratch = {0};
    ingest_pass(sender, chunk, &d, kind, 0, d.rows, POPULATE_BATCH_ROWS, &scratch, PROG);
    free(scratch.note_off);

    column_sender_chunk_free(chunk);
    questdb_db_return_direct_column_sender(db, sender);
    questdb_db_close(db);
    bench_data_free(&d);

    fprintf(stderr, "[" PROG "] waiting for WAL apply (count == %zu)\n", rows);
    long long count = wait_for_count(base, table, (long long)rows);
    if (count != (long long)rows) {
        fprintf(stderr, "[" PROG "] populate count %lld != %zu\n", count, rows);
        exit(2);
    }
}

/* One read pass. materialize=0: decode-only (row counting).
 * materialize=1: touch every cell through the typed getters, fold into a
 * checksum so the reads cannot be optimized away. Returns rows seen. */
static size_t read_pass(const char* rconf, const char* select, int materialize,
                        double* checksum_out)
{
    questdb_error* err = NULL;
    line_sender_utf8 conf_u, sql_u;
    if (!line_sender_utf8_init(&conf_u, strlen(rconf), rconf, &err))
        bench_die(PROG, "conf utf8", err);
    if (!line_sender_utf8_init(&sql_u, strlen(select), select, &err))
        bench_die(PROG, "sql utf8", err);
    reader* r = reader_from_conf(conf_u, &err);
    if (!r) bench_die(PROG, "reader_from_conf", err);
    reader_cursor* cur = reader_execute(r, sql_u, &err);
    if (!cur) bench_die(PROG, "reader_execute", err);

    size_t seen = 0;
    double checksum = 0.0;
    const reader_batch* batch;
    while ((batch = reader_cursor_next_batch(cur, &err)) != NULL) {
        size_t nrows = reader_batch_row_count(batch);
        if (materialize) {
            size_t ncols = reader_batch_column_count(batch);
            reader_symbol_dict dict = {0};
            if (!reader_batch_symbol_dict(batch, &dict, &err))
                bench_die(PROG, "symbol_dict", err);
            for (size_t c = 0; c < ncols; c++) {
                reader_column_data col = {0};
                if (!reader_batch_column_data(batch, c, &col, &err))
                    bench_die(PROG, "column_data", err);
                for (size_t i = 0; i < nrows; i++) {
                    bool is_null = false;
                    switch (col.kind) {
                    case reader_column_kind_long:
                    case reader_column_kind_timestamp:
                    case reader_column_kind_timestamp_nanos:
                        checksum += (double)reader_column_data_get_i64(&col, i, &is_null);
                        break;
                    case reader_column_kind_double:
                        checksum += reader_column_data_get_f64(&col, i, &is_null);
                        break;
                    case reader_column_kind_symbol: {
                        const char* s = NULL; size_t sl = 0;
                        reader_column_data_get_symbol(&col, &dict, i, &s, &sl, &is_null);
                        checksum += (double)sl;
                        break;
                    }
                    case reader_column_kind_varchar: {
                        const uint8_t* v = NULL; size_t vl = 0;
                        reader_column_data_get_varlen(&col, i, &v, &vl, &is_null);
                        checksum += (double)vl;
                        break;
                    }
                    default:
                        break;
                    }
                }
            }
        }
        seen += nrows;
    }
    if (err) bench_die(PROG, "next_batch", err);
    reader_cursor_free(cur);
    reader_close(r);
    if (checksum_out) *checksum_out = checksum;
    return seen;
}

int main(void)
{
    schema_kind kind;
    if (schema_parse(env_str("SCHEMA", "s1-narrow"), &kind) != 0) {
        fprintf(stderr, "[" PROG "] unknown SCHEMA\n");
        return 1;
    }
    size_t rows = env_zu("ROWS", 10000000);
    size_t sym_card = env_zu("QUESTDB_COLUMN_BENCH_SYM_CARD", 8);
    size_t varchar_len = env_zu("QUESTDB_COLUMN_BENCH_VARCHAR_LEN", 16);
    size_t hi_sym_card = env_zu("HI_SYM_CARD", 100000);
    size_t iterations = env_zu("ITERATIONS", 5);
    size_t warmups = env_zu("WARMUPS", 2);
    const char* run_mode = env_str("RUN_MODE", "full");
    const char* host = env_str("QDB_HOST", "127.0.0.1");
    size_t port = env_zu("QDB_PORT", 9000);
    int skip_populate = getenv("SKIP_POPULATE") != NULL;
    size_t columns = schema_columns(kind);
    const char* select = schema_select_sql(kind);

    char base[256], rconf[256];
    snprintf(base, sizeof(base), "http://%s:%zu", host, port);
    snprintf(rconf, sizeof(rconf), "ws::addr=%s:%zu;compression=raw;", host, port);

    fprintf(stderr, "[" PROG "] schema=%s rows=%zu it=%zu wu=%zu host=%s:%zu\n",
            schema_name(kind), rows, iterations, warmups, host, port);

    if (!skip_populate)
        populate(host, port, base, kind, rows, sym_card, varchar_len, hi_sym_card);
    else
        fprintf(stderr, "[" PROG "] SKIP_POPULATE: reading existing %s\n",
                schema_table(kind));

    uint64_t* wall = malloc(iterations * sizeof(uint64_t));
    uint64_t* cpu = malloc(iterations * sizeof(uint64_t));
    json_obj* paths = json_obj_new();

    /* decode-only floor */
    for (size_t w = 0; w < warmups; w++)
        if (read_pass(rconf, select, 0, NULL) != rows) {
            fprintf(stderr, "[" PROG "] warmup row mismatch\n");
            return 2;
        }
    for (size_t i = 0; i < iterations; i++) {
        uint64_t c0 = process_cpu_ns(), t0 = now_ns();
        size_t seen = read_pass(rconf, select, 0, NULL);
        wall[i] = now_ns() - t0;
        cpu[i] = process_cpu_ns() - c0;
        if (seen != rows) { fprintf(stderr, "[" PROG "] rows %zu != %zu\n", seen, rows); return 2; }
    }
    double floor_median = median_s_of(wall, iterations);
    json_obj_obj(paths, "decode-only",
        path_summary(wall, cpu, iterations, rows, columns, 0, "floor", warmups > 0));

    /* materialize e2e */
    double checksum = 0.0;
    for (size_t w = 0; w < warmups; w++)
        if (read_pass(rconf, select, 1, &checksum) != rows) {
            fprintf(stderr, "[" PROG "] warmup row mismatch\n");
            return 2;
        }
    for (size_t i = 0; i < iterations; i++) {
        uint64_t c0 = process_cpu_ns(), t0 = now_ns();
        size_t seen = read_pass(rconf, select, 1, &checksum);
        wall[i] = now_ns() - t0;
        cpu[i] = process_cpu_ns() - c0;
        if (seen != rows) { fprintf(stderr, "[" PROG "] rows %zu != %zu\n", seen, rows); return 2; }
    }
    double e2e_median = median_s_of(wall, iterations);
    json_obj_obj(paths, "materialize",
        path_summary(wall, cpu, iterations, rows, columns, 0, "e2e", warmups > 0));
    fprintf(stderr, "[" PROG "] checksum=%f\n", checksum);

    json_obj* report = json_obj_new();
    json_obj_str(report, "schema", schema_name(kind));
    json_obj_int(report, "rows", (uint64_t)rows);
    json_obj_int(report, "columns", (uint64_t)columns);
    json_obj_str(report, "direction", "egress");
    json_obj_str(report, "client", "c-columnar");
    json_obj_str(report, "run_mode", run_mode);
    json_obj_int(report, "warmups", (uint64_t)warmups);
    json_obj_int(report, "wire_bytes", 0);

    json_obj* machine = json_obj_new();
#if defined(__APPLE__)
    json_obj_str(machine, "platform", "macos");
#else
    json_obj_str(machine, "platform", "linux");
#endif
#if defined(__aarch64__)
    json_obj_str(machine, "arch", "aarch64");
#else
    json_obj_str(machine, "arch", "x86_64");
#endif
    json_obj_str(machine, "cc", __VERSION__);
    json_obj_obj(report, "machine", machine);

    json_obj* commits = json_obj_new();
    const char* cc = getenv("C_QUESTDB_CLIENT_COMMIT");
    const char* py = getenv("PY_QUESTDB_CLIENT_COMMIT");
    if (cc) json_obj_str(commits, "c_questdb_client", cc);
    else json_obj_null(commits, "c_questdb_client");
    if (py) json_obj_str(commits, "py_questdb_client", py);
    else json_obj_null(commits, "py_questdb_client");
    json_obj_obj(report, "commits", commits);

    json_obj* rcc = json_obj_new();
    json_obj_int(rcc, "expected", (uint64_t)rows);
    json_obj_int(rcc, "actual", (uint64_t)rows);
    json_obj_bool(rcc, "ok", 1);
    json_obj_bool(rcc, "inflated", 0);
    json_obj_obj(report, "row_count_check", rcc);

    json_obj* headline = json_obj_new();
    json_obj_float(headline, "decode_floor_s", floor_median);
    json_obj_float(headline, "materialize_s", e2e_median);
    if (e2e_median != 0.0)
        json_obj_float(headline, "materialize_rows_per_s", (double)rows / e2e_median);
    json_obj_obj(report, "headline", headline);

    json_obj_str(report, "real_conf", rconf);
    json_obj_str(report, "http_base", base);
    json_obj_obj(report, "paths", paths);

    char* out = json_obj_render(report);
    printf("%s\n", out);
    free(out);
    json_obj_free(report);
    free(wall);
    free(cpu);
    return 0;
}
