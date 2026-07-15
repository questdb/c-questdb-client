#include "bench_ingest_c.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

size_t env_zu(const char* name, size_t dflt)
{
    const char* v = getenv(name);
    if (!v || !*v) return dflt;
    char* end = NULL;
    unsigned long long n = strtoull(v, &end, 10);
    return (end && *end == 0) ? (size_t)n : dflt;
}

const char* env_str(const char* name, const char* dflt)
{
    const char* v = getenv(name);
    return (v && *v) ? v : dflt;
}

void bench_die(const char* prog, const char* what, line_sender_error* err)
{
    size_t len = 0;
    const char* msg = err ? line_sender_error_msg(err, &len) : "";
    fprintf(stderr, "[%s] %s failed: %.*s\n", prog, what, (int)len, msg);
    if (err) line_sender_error_free(err);
    exit(1);
}

void sender_range(size_t rows, size_t n, size_t k, size_t* lo, size_t* hi)
{
    *lo = rows * k / n;
    *hi = rows * (k + 1) / n;
}

/* Append rows [start, start+n) of every column + the designated ts.
 * Chunk appends are zero-copy: the bench_data buffers outlive the flush. */
void stage_batch(column_sender_chunk* chunk, const bench_data* d,
                 schema_kind kind, size_t start, size_t n,
                 stage_scratch* scratch, const char* prog)
{
    line_sender_error* err = NULL;
    const column_sender_validity* NOV = NULL;
    if (!column_sender_chunk_column_i64(chunk, "id", 2, d->id + start, n, NOV, &err))
        bench_die(prog, "append id", err);
    if (!column_sender_chunk_column_f64(chunk, "price", 5, d->price + start, n, NOV, &err))
        bench_die(prog, "append price", err);
    if (!column_sender_chunk_symbol_i32(chunk, "sym", 3, d->sym.codes + start, n,
            d->sym.offsets, d->sym.card + 1, d->sym.bytes, d->sym.bytes_len, NOV, &err))
        bench_die(prog, "append sym", err);
    /* notes are fixed-length: rebased offsets are just i*varchar_len */
    if (scratch->cap < n + 1) {
        scratch->note_off = realloc(scratch->note_off, (n + 1) * sizeof(int32_t));
        scratch->cap = n + 1;
        for (size_t i = 0; i <= n; i++)
            scratch->note_off[i] = (int32_t)(i * d->varchar_len);
    }
    if (!column_sender_chunk_column_str(chunk, "note", 4, scratch->note_off,
            d->note_bytes + start * d->varchar_len, n * d->varchar_len, n, NOV, &err))
        bench_die(prog, "append note", err);
    if (kind == SCHEMA_S2_WIDE) {
        char name[4] = "d1";
        for (size_t j = 0; j < N_WIDE_DOUBLES; j++) {
            name[0] = 'd'; name[1] = (char)('1' + j); name[2] = 0;
            if (!column_sender_chunk_column_f64(chunk, name, 2,
                    d->doubles[j] + start, n, NOV, &err))
                bench_die(prog, "append dN", err);
        }
        for (size_t j = 0; j < N_WIDE_SYMS; j++) {
            name[0] = 's'; name[1] = (char)('1' + j); name[2] = 0;
            const sym_col* c = &d->hi_syms[j];
            if (!column_sender_chunk_symbol_i32(chunk, name, 2, c->codes + start, n,
                    c->offsets, c->card + 1, c->bytes, c->bytes_len, NOV, &err))
                bench_die(prog, "append sN", err);
        }
    }
    if (!column_sender_chunk_at_nanos(chunk, d->ts_nanos + start, n, &err))
        bench_die(prog, "at_nanos", err);
}

/* One full pass over the data. If sender is NULL: floor mode — stage each
 * batch then clear the chunk. Else: e2e — pipeline each batch with a direct
 * flush, commit(ok) checkpoint every CHECKPOINT_BATCHES batches, and a final
 * commit(ok) after the loop (mirrors flush_polars_dataframe's checkpoint
 * pipeline; the commit's no-progress wait is bounded by the pool's
 * request_timeout). */
void ingest_pass(direct_column_sender* sender, column_sender_chunk* chunk,
                 const bench_data* d, schema_kind kind, size_t lo, size_t hi,
                 size_t max_batch_rows, stage_scratch* scratch,
                 const char* prog)
{
    line_sender_error* err = NULL;
    size_t batch_no = 0;
    for (size_t start = lo; start < hi; start += max_batch_rows) {
        size_t n = hi - start < max_batch_rows ? hi - start : max_batch_rows;
        stage_batch(chunk, d, kind, start, n, scratch, prog);
        if (sender) {
            if (!direct_column_sender_flush(sender, chunk, &err)) /* clears chunk */
                bench_die(prog, "flush", err);
            if (++batch_no % CHECKPOINT_BATCHES == 0
                && !direct_column_sender_commit(sender, qwpws_ack_level_ok, &err))
                bench_die(prog, "checkpoint commit", err);
        } else {
            if (!column_sender_chunk_clear(chunk, &err))
                bench_die(prog, "chunk clear", err);
        }
    }
    if (sender
        && !direct_column_sender_commit(sender, qwpws_ack_level_ok, &err))
        bench_die(prog, "final commit", err);
}
