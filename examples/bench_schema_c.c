#include "bench_schema_c.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int schema_parse(const char* s, schema_kind* out)
{
    if (strcmp(s, "s1-narrow") == 0) { *out = SCHEMA_S1_NARROW; return 0; }
    if (strcmp(s, "s2-wide") == 0)   { *out = SCHEMA_S2_WIDE;   return 0; }
    return 1;
}

const char* schema_name(schema_kind k)
{ return k == SCHEMA_S1_NARROW ? "s1-narrow" : "s2-wide"; }

const char* schema_table(schema_kind k)
{ return k == SCHEMA_S1_NARROW ? "bench_s1_narrow" : "bench_s2_wide"; }

size_t schema_columns(schema_kind k)
{ return k == SCHEMA_S1_NARROW ? 5 : 5 + N_WIDE_DOUBLES + N_WIDE_SYMS; }

const char* schema_create_sql(schema_kind k)
{
    if (k == SCHEMA_S1_NARROW)
        return "CREATE TABLE bench_s1_narrow ("
               "id LONG, price DOUBLE, sym SYMBOL, note VARCHAR, ts TIMESTAMP"
               ") TIMESTAMP(ts) PARTITION BY HOUR WAL DEDUP UPSERT KEYS(ts)";
    return "CREATE TABLE bench_s2_wide ("
           "id LONG, price DOUBLE, sym SYMBOL, note VARCHAR, "
           "d1 DOUBLE, d2 DOUBLE, d3 DOUBLE, d4 DOUBLE, d5 DOUBLE, "
           "s1 SYMBOL CAPACITY 200000, s2 SYMBOL CAPACITY 200000, "
           "s3 SYMBOL CAPACITY 200000, s4 SYMBOL CAPACITY 200000, "
           "s5 SYMBOL CAPACITY 200000, ts TIMESTAMP"
           ") TIMESTAMP(ts) PARTITION BY HOUR WAL DEDUP UPSERT KEYS(ts)";
}

const char* schema_select_sql(schema_kind k)
{
    if (k == SCHEMA_S1_NARROW)
        return "SELECT ts, id, price, sym, note FROM bench_s1_narrow";
    return "SELECT ts, id, price, sym, note, "
           "d1, d2, d3, d4, d5, s1, s2, s3, s4, s5 FROM bench_s2_wide";
}

size_t note_template_count(size_t rows)
{
    if (rows < 1) return 1;
    return rows > 1024 ? 1024 : rows;
}

void note_template(size_t idx, size_t varchar_len, char* out)
{
    char pat[32];
    int plen = snprintf(pat, sizeof(pat), "note_%03zu_", idx);
    for (size_t i = 0; i < varchar_len; i++)
        out[i] = pat[i % (size_t)plen];
}

void sym_label(size_t v, char* out) { sprintf(out, "sym_%04zu", v); }

void hi_sym_label(size_t col, size_t v, char* out)
{ sprintf(out, "s%zu_%06zu", col - 1, v); }

double wide_double(size_t i, size_t k) { return (double)i * (0.5 + (double)k); }

/* Dict entries label(0)..label(card-1); codes cycle i % card. */
static int build_sym(sym_col* c, size_t rows, size_t card,
                     void (*label)(size_t, char*), size_t label_max)
{
    char buf[32];
    (void)label_max;
    c->card = card;
    c->codes = malloc(rows * sizeof(int32_t));
    c->offsets = malloc((card + 1) * sizeof(int32_t));
    /* every label here is < 16 bytes; over-allocate then record real len */
    c->bytes = malloc(card * 16);
    if (!c->codes || !c->offsets || !c->bytes) return 1;
    size_t pos = 0;
    c->offsets[0] = 0;
    for (size_t v = 0; v < card; v++) {
        label(v, buf);
        size_t n = strlen(buf);
        memcpy(c->bytes + pos, buf, n);
        pos += n;
        c->offsets[v + 1] = (int32_t)pos;
    }
    c->bytes_len = pos;
    for (size_t i = 0; i < rows; i++)
        c->codes[i] = (int32_t)(i % card);
    return 0;
}

/* hi_sym_label needs the column number too — wrap per column. */
static size_t g_hi_col;
static void hi_label_bound(size_t v, char* out) { hi_sym_label(g_hi_col, v, out); }

int bench_data_build(bench_data* d, schema_kind k, size_t rows,
                     size_t sym_card, size_t varchar_len, size_t hi_sym_card)
{
    memset(d, 0, sizeof(*d));
    d->rows = rows;
    d->varchar_len = varchar_len;
    d->ts_nanos = malloc(rows * sizeof(int64_t));
    d->id = malloc(rows * sizeof(int64_t));
    d->price = malloc(rows * sizeof(double));
    d->note_offsets = malloc((rows + 1) * sizeof(int32_t));
    d->note_bytes = malloc(rows * varchar_len);
    if (!d->ts_nanos || !d->id || !d->price || !d->note_offsets || !d->note_bytes)
        return 1;

    size_t tcount = note_template_count(rows);
    char* templates = malloc(tcount * varchar_len);
    if (!templates) return 1;
    for (size_t t = 0; t < tcount; t++)
        note_template(t, varchar_len, templates + t * varchar_len);

    d->note_offsets[0] = 0;
    for (size_t i = 0; i < rows; i++) {
        d->ts_nanos[i] = TS_BASE_NANOS + (int64_t)i * TS_STEP_NANOS;
        d->id[i] = (int64_t)i;
        d->price[i] = (double)i * 0.25;
        memcpy(d->note_bytes + i * varchar_len,
               templates + (i % tcount) * varchar_len, varchar_len);
        d->note_offsets[i + 1] = (int32_t)((i + 1) * varchar_len);
    }
    d->note_bytes_len = rows * varchar_len;
    free(templates);

    if (build_sym(&d->sym, rows, sym_card, sym_label, 16)) return 1;

    if (k == SCHEMA_S2_WIDE) {
        for (size_t j = 0; j < N_WIDE_DOUBLES; j++) {
            d->doubles[j] = malloc(rows * sizeof(double));
            if (!d->doubles[j]) return 1;
            for (size_t i = 0; i < rows; i++)
                d->doubles[j][i] = wide_double(i, j + 1); /* d1 → k=1 */
        }
        for (size_t j = 0; j < N_WIDE_SYMS; j++) {
            g_hi_col = j + 1; /* column s1 → labels s0_… */
            if (build_sym(&d->hi_syms[j], rows, hi_sym_card, hi_label_bound, 16))
                return 1;
        }
    }
    return 0;
}

void bench_data_free(bench_data* d)
{
    free(d->ts_nanos); free(d->id); free(d->price);
    free(d->note_offsets); free(d->note_bytes);
    free(d->sym.codes); free(d->sym.offsets); free(d->sym.bytes);
    for (size_t j = 0; j < N_WIDE_DOUBLES; j++) free(d->doubles[j]);
    for (size_t j = 0; j < N_WIDE_SYMS; j++) {
        free(d->hi_syms[j].codes); free(d->hi_syms[j].offsets);
        free(d->hi_syms[j].bytes);
    }
    memset(d, 0, sizeof(*d));
}
