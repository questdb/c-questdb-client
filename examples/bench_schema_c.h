/* Deterministic data + schema contract for the C QWP bench examples.
 * MUST stay byte-for-byte in sync with questdb-rs/examples/bench_schema/mod.rs
 * (the one place the cross-client parity contract lives). */
#pragma once
#include <stddef.h>
#include <stdint.h>

typedef enum { SCHEMA_S1_NARROW, SCHEMA_S2_WIDE } schema_kind;

#define N_WIDE_DOUBLES 5
#define N_WIDE_SYMS 5
#define TS_STEP_NANOS 1000LL
#define TS_BASE_NANOS 1704067200000000000LL

int schema_parse(const char* s, schema_kind* out); /* 0 = ok */
const char* schema_name(schema_kind k);
const char* schema_table(schema_kind k);
size_t schema_columns(schema_kind k);
const char* schema_create_sql(schema_kind k);
const char* schema_select_sql(schema_kind k);

size_t note_template_count(size_t rows);           /* clamp(rows, 1, 1024) */
void note_template(size_t idx, size_t varchar_len, char* out); /* exactly varchar_len bytes, no NUL */
void sym_label(size_t v, char* out);               /* "sym_%04zu", NUL-terminated */
void hi_sym_label(size_t col, size_t v, char* out);/* "s%zu_%06zu" with col-1  */
double wide_double(size_t i, size_t k);            /* i * (0.5 + k)           */

/* One SYMBOL column: per-row dict codes + dict as Arrow-Utf8 offsets/bytes. */
typedef struct
{
    int32_t* codes;   /* rows entries, codes[i] = i % card       */
    int32_t* offsets; /* card + 1 entries                        */
    uint8_t* bytes;
    size_t card;
    size_t bytes_len;
} sym_col;

typedef struct
{
    size_t rows;
    int64_t* ts_nanos;
    int64_t* id;
    double* price;
    sym_col sym;                      /* low-card `sym`                 */
    int32_t* note_offsets;            /* rows + 1; uniform varchar_len  */
    uint8_t* note_bytes;
    size_t note_bytes_len;
    size_t varchar_len;
    double* doubles[N_WIDE_DOUBLES];  /* NULL for S1                    */
    sym_col hi_syms[N_WIDE_SYMS];     /* zeroed for S1                  */
} bench_data;

int bench_data_build(bench_data* d, schema_kind k, size_t rows,
                     size_t sym_card, size_t varchar_len, size_t hi_sym_card);
void bench_data_free(bench_data* d);
