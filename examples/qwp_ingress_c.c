/* C twin of questdb-rs/examples/qwp_ingress_polars.rs.
 * C columnar ingress benchmark; schemas, paths, and report fields are
 * documented in doc/BENCHMARKS.md.
 * Measures the columnar C API end-to-end on the shared S1/S2 schemas:
 *   chunk-build   (floor) — stage all batches into a chunk, no network
 *   flush-chunks  (e2e)   — stage + qwp_direct_sender_flush per
 *                            MAX_BATCH_ROWS batch, commit(ok) checkpoint
 *                            every 64 batches, final commit(ok) (mirrors the
 *                            Rust flush_polars_dataframe checkpoint pipeline)
 * Emits the bench_json contract with client="c-columnar". wire_bytes is 0:
 * the C API has no encode-only hook — rows/s is the cross-client metric.
 * Env knobs identical to the Rust example (see bench_schema_c.h header). */
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <questdb/ingress/qwp_sender.h>

#include "bench_http_c.h"
#include "bench_ingest_c.h"
#include "bench_json_c.h"
#include "bench_schema_c.h"

#define PROG "qwp_ingress_c"

/* One parallel sender: its own connection, chunk, scratch and row range.
 * bench_die() exits the whole process on error — acceptable for a bench. */
typedef struct {
    qwp_direct_sender* sender;
    qwp_chunk* chunk;
    const bench_data* d;
    schema_kind kind;
    size_t lo, hi, max_batch_rows;
    stage_scratch scratch;
} sender_job;

static void* sender_thread(void* arg)
{
    sender_job* j = arg;
    ingest_pass(j->sender, j->chunk, j->d, j->kind, j->lo, j->hi,
                j->max_batch_rows, &j->scratch, PROG);
    return NULL;
}

static void run_multi_pass(sender_job* jobs, size_t n)
{
    if (n == 1) { /* classic path: no thread overhead in the timed region */
        sender_thread(&jobs[0]);
        return;
    }
    pthread_t* tids = malloc(n * sizeof(pthread_t));
    for (size_t k = 0; k < n; k++)
        if (pthread_create(&tids[k], NULL, sender_thread, &jobs[k]) != 0) {
            fprintf(stderr, "[" PROG "] pthread_create failed\n");
            exit(1);
        }
    for (size_t k = 0; k < n; k++)
        pthread_join(tids[k], NULL);
    free(tids);
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
    size_t max_batch_rows = env_zu("MAX_BATCH_ROWS", 10000);
    size_t n_senders = env_zu("SENDERS", 1);
    if (n_senders < 1) n_senders = 1;
    const char* run_mode = env_str("RUN_MODE", "full");
    const char* host = env_str("QDB_HOST", "127.0.0.1");
    size_t port = env_zu("QDB_PORT", 9000);
    int skip_e2e = getenv("SKIP_E2E") != NULL;
    size_t columns = schema_columns(kind);
    const char* table = schema_table(kind);

    fprintf(stderr,
        "[" PROG "] schema=%s rows=%zu it=%zu wu=%zu batch=%zu senders=%zu host=%s:%zu\n",
        schema_name(kind), rows, iterations, warmups, max_batch_rows, n_senders, host, port);

    bench_data d;
    if (bench_data_build(&d, kind, rows, sym_card, varchar_len, hi_sym_card) != 0) {
        fprintf(stderr, "[" PROG "] data build OOM\n");
        return 1;
    }

    line_sender_error* err = NULL;
    uint64_t* wall = malloc(iterations * sizeof(uint64_t));
    uint64_t* cpu = malloc(iterations * sizeof(uint64_t));
    json_obj* paths = json_obj_new();
    json_obj* headline = json_obj_new();

    /* ---- floor: chunk-build (no server) ---- */
    qwp_chunk* chunk = qwp_chunk_new(table, strlen(table), &err);
    if (!chunk) bench_die(PROG, "chunk_new", err);
    stage_scratch floor_scratch = {0};
    for (size_t w = 0; w < warmups; w++)
        ingest_pass(NULL, chunk, &d, kind, 0, rows, max_batch_rows, &floor_scratch, PROG);
    for (size_t i = 0; i < iterations; i++) {
        uint64_t c0 = process_cpu_ns(), t0 = now_ns();
        ingest_pass(NULL, chunk, &d, kind, 0, rows, max_batch_rows, &floor_scratch, PROG);
        wall[i] = now_ns() - t0;
        cpu[i] = process_cpu_ns() - c0;
    }
    free(floor_scratch.note_off);
    double floor_median = median_s_of(wall, iterations);
    json_obj_obj(paths, "chunk-build",
        path_summary(wall, cpu, iterations, rows, columns, 0, "floor", warmups > 0));

    char base[256], conf[256];
    snprintf(base, sizeof(base), "http://%s:%zu", host, port);
    snprintf(conf, sizeof(conf),
             "ws::addr=%s:%zu;sender_pool_min=1;sender_pool_max=1;pool_reap=manual;",
             host, port);

    long long count = -1;
    double e2e_median = 0.0;
    if (!skip_e2e) {
        char drop[256];
        snprintf(drop, sizeof(drop), "DROP TABLE IF EXISTS %s", table);
        if (http_exec_sql(base, drop) != 0
            || http_exec_sql(base, schema_create_sql(kind)) != 0)
            return 1;

        /* Direct sender = the pipelined backend flush_polars_dataframe uses
         * (parity with the Rust bench). Unlike the store-and-forward sender
         * it never re-states the connection-lifetime symbol dict in replay
         * frames, and it has no internal failover — errors are fatal for the
         * bench (bench_die), which is the intended behavior. */
        questdb_db** dbs = malloc(n_senders * sizeof(questdb_db*));
        sender_job* jobs = calloc(n_senders, sizeof(sender_job));
        for (size_t k = 0; k < n_senders; k++) {
            dbs[k] = questdb_db_connect(conf, strlen(conf), &err);
            if (!dbs[k]) bench_die(PROG, "connect", err);
            jobs[k].sender = questdb_db_borrow_direct_sender(dbs[k], &err);
            if (!jobs[k].sender) bench_die(PROG, "borrow sender", err);
            jobs[k].chunk = qwp_chunk_new(table, strlen(table), &err);
            if (!jobs[k].chunk) bench_die(PROG, "chunk_new", err);
            jobs[k].d = &d;
            jobs[k].kind = kind;
            sender_range(rows, n_senders, k, &jobs[k].lo, &jobs[k].hi);
            jobs[k].max_batch_rows = max_batch_rows;
        }

        for (size_t w = 0; w < warmups; w++)
            run_multi_pass(jobs, n_senders);
        for (size_t i = 0; i < iterations; i++) {
            uint64_t c0 = process_cpu_ns(), t0 = now_ns();
            run_multi_pass(jobs, n_senders);
            wall[i] = now_ns() - t0;
            cpu[i] = process_cpu_ns() - c0;
        }
        e2e_median = median_s_of(wall, iterations);
        json_obj_obj(paths, "flush-chunks",
            path_summary(wall, cpu, iterations, rows, columns, 0, "e2e", warmups > 0));

        for (size_t k = 0; k < n_senders; k++) {
            questdb_db_return_direct_sender(dbs[k], jobs[k].sender);
            questdb_db_close(dbs[k]);
            qwp_chunk_free(jobs[k].chunk);
            free(jobs[k].scratch.note_off);
        }
        free(jobs);
        free(dbs);

        fprintf(stderr, "[" PROG "] waiting for WAL apply (count == %zu)\n", rows);
        count = wait_for_count(base, table, (long long)rows);
    } else {
        fprintf(stderr, "[" PROG "] SKIP_E2E: floor only\n");
    }
    qwp_chunk_free(chunk);

    /* ---- report ---- */
    json_obj* report = json_obj_new();
    json_obj_str(report, "schema", schema_name(kind));
    json_obj_int(report, "rows", (uint64_t)rows);
    json_obj_int(report, "columns", (uint64_t)columns);
    json_obj_str(report, "direction", "ingress");
    json_obj_str(report, "client", "c-columnar");
    json_obj_str(report, "run_mode", run_mode);
    json_obj_int(report, "warmups", (uint64_t)warmups);
    json_obj_int(report, "wire_bytes", 0);
    json_obj_int(report, "senders", (uint64_t)n_senders);

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

    json_obj_float(headline, "chunk_build_s", floor_median);
    if (floor_median != 0.0)
        json_obj_float(headline, "chunk_build_rows_per_s", (double)rows / floor_median);
    if (!skip_e2e) {
        json_obj_float(headline, "flush_chunks_s", e2e_median);
        double ovh = e2e_median - floor_median;
        json_obj_float(headline, "staging_overhead_s", ovh < 0.0 ? 0.0 : ovh);
        if (e2e_median != 0.0)
            json_obj_float(headline, "flush_chunks_rows_per_s", (double)rows / e2e_median);
        json_obj* rcc = json_obj_new();
        json_obj_int(rcc, "expected", (uint64_t)rows);
        json_obj_int(rcc, "actual", (uint64_t)(count < 0 ? 0 : count));
        json_obj_bool(rcc, "ok", count == (long long)rows);
        json_obj_bool(rcc, "inflated", count > (long long)rows);
        json_obj_obj(report, "row_count_check", rcc);
        json_obj_str(report, "real_conf", conf);
        json_obj_str(report, "http_base", base);
    }
    json_obj_obj(report, "headline", headline);
    json_obj_obj(report, "paths", paths);

    char* out = json_obj_render(report);
    printf("%s\n", out);
    free(out);
    json_obj_free(report);
    bench_data_free(&d);
    free(wall);
    free(cpu);
    return (skip_e2e || count == (long long)rows) ? 0 : 2;
}
