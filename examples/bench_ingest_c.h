/* Shared ingest helpers for the C QWP bench examples (qwp_ingress_c,
 * qwp_egress_c): env parsing, error exit, chunk staging and the
 * flush/checkpoint pass. */
#pragma once
#include <questdb/ingress/column_sender.h>
#include "bench_schema_c.h"

#define CHECKPOINT_BATCHES 64

size_t env_zu(const char* name, size_t dflt);
const char* env_str(const char* name, const char* dflt);
/* "[<prog>] <what> failed: <msg>" to stderr, free err, exit(1) */
void bench_die(const char* prog, const char* what, line_sender_error* err);
/* Per-thread scratch for stage_batch's rebased note offsets (was a
 * function-level static — not thread-safe). Zero-init; caller frees
 * .note_off. */
typedef struct {
    int32_t* note_off;
    size_t cap;
} stage_scratch;

/* sender k of n owns rows [lo, hi): lo = rows*k/n, hi = rows*(k+1)/n */
void sender_range(size_t rows, size_t n, size_t k, size_t* lo, size_t* hi);

/* append rows [start, start+n) of every column + designated ts (zero-copy) */
void stage_batch(column_sender_chunk* chunk, const bench_data* d,
                 schema_kind kind, size_t start, size_t n,
                 stage_scratch* scratch, const char* prog);
/* one full pass over d: sender NULL = floor (stage+clear); else pipelined
 * direct flush per batch, commit(ok) checkpoint every CHECKPOINT_BATCHES
 * batches and once after the loop (the commit's no-progress wait is bounded
 * by the pool's request_timeout) */
void ingest_pass(direct_column_sender* sender, column_sender_chunk* chunk,
                 const bench_data* d, schema_kind kind, size_t lo, size_t hi,
                 size_t max_batch_rows, stage_scratch* scratch,
                 const char* prog);
