/* Golden-value self-test for the C QWP bench modules. Values cross-checked
 * against questdb-rs/examples/bench_schema/mod.rs and bench_json/mod.rs —
 * if these drift, cross-client parity is broken. No server, no curl. */
#undef NDEBUG /* asserts are the test; keep them in Release (-DNDEBUG) builds */
#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bench_schema_c.h"
#include "bench_json_c.h"
#include "bench_ingest_c.h"

static void test_schema(void)
{
    schema_kind k;
    assert(schema_parse("s1-narrow", &k) == 0 && k == SCHEMA_S1_NARROW);
    assert(schema_parse("s2-wide", &k) == 0 && k == SCHEMA_S2_WIDE);
    assert(schema_parse("bogus", &k) != 0);
    assert(strcmp(schema_name(SCHEMA_S1_NARROW), "s1-narrow") == 0);
    assert(strcmp(schema_table(SCHEMA_S2_WIDE), "bench_s2_wide") == 0);
    assert(schema_columns(SCHEMA_S1_NARROW) == 5);
    assert(schema_columns(SCHEMA_S2_WIDE) == 15);
    assert(strstr(schema_create_sql(SCHEMA_S2_WIDE),
                  "s5 SYMBOL CAPACITY 200000") != NULL);
    assert(strstr(schema_create_sql(SCHEMA_S1_NARROW),
                  "DEDUP UPSERT KEYS(ts)") != NULL);
    assert(strncmp(schema_select_sql(SCHEMA_S1_NARROW),
                   "SELECT ts, id, price, sym, note FROM bench_s1_narrow", 53) == 0);
}

static void test_generators(void)
{
    char buf[64];
    assert(note_template_count(0) == 1);
    assert(note_template_count(500) == 500);
    assert(note_template_count(2000000) == 1024);

    note_template(0, 16, buf);
    assert(memcmp(buf, "note_000_note_00", 16) == 0);
    note_template(7, 9, buf);
    assert(memcmp(buf, "note_007_", 9) == 0);
    note_template(1023, 12, buf); /* pattern "note_1023_" is 10 chars */
    assert(memcmp(buf, "note_1023_no", 12) == 0);

    sym_label(3, buf);
    assert(strcmp(buf, "sym_0003") == 0);
    hi_sym_label(1, 5, buf); /* column s1 carries s0_… categories */
    assert(strcmp(buf, "s0_000005") == 0);
    hi_sym_label(5, 99999, buf);
    assert(strcmp(buf, "s4_099999") == 0);

    assert(wide_double(10, 3) == 35.0);
}

static void test_data_build(void)
{
    bench_data d;
    assert(bench_data_build(&d, SCHEMA_S2_WIDE, 2000, 8, 16, 1000) == 0);
    assert(d.rows == 2000);
    assert(d.ts_nanos[0] == 1704067200000000000LL);
    assert(d.ts_nanos[1] - d.ts_nanos[0] == 1000);
    assert(d.id[1999] == 1999);
    assert(d.price[4] == 1.0);
    assert(d.sym.card == 8 && d.sym.codes[9] == 1);          /* 9 % 8 */
    assert(d.note_offsets[2000] == 2000 * 16);               /* fixed-len notes */
    assert(memcmp(d.note_bytes + 16, "note_001_note_00", 16) == 0);
    assert(d.doubles[2][5] == 5.0 * 3.5);                    /* d3: k=3 */
    assert(d.hi_syms[0].card == 1000);
    assert(memcmp(d.hi_syms[4].bytes, "s4_000000", 9) == 0); /* dict entry 0 */
    bench_data_free(&d);

    assert(bench_data_build(&d, SCHEMA_S1_NARROW, 100, 8, 16, 1000) == 0);
    assert(d.doubles[0] == NULL && d.hi_syms[0].codes == NULL);
    bench_data_free(&d);
}

static void test_stats(void)
{
    /* samples 1..4 s in ns: median=(2+3)/2=2.5, stdev=sqrt(5/3), p95=idx round(2.85)=3 → 4.0 */
    uint64_t s[4] = {1000000000ULL, 2000000000ULL, 3000000000ULL, 4000000000ULL};
    json_obj* o = json_obj_new();
    summarize(o, s, 4, 10, 5, NULL);
    char* j = json_obj_render(o);
    assert(strstr(j, "\"iterations\":4") != NULL);
    assert(strstr(j, "\"median_s\":2.5") != NULL);
    assert(strstr(j, "\"p95_s\":4") != NULL);
    assert(strstr(j, "\"cov\":0.516397779494") != NULL);  /* stdev/mean, %.12f trimmed */
    assert(strstr(j, "\"rows_per_s_median\":4") != NULL); /* 10 / 2.5 */
    assert(strstr(j, "\"cells_per_s_median\":20") != NULL);
    assert(strstr(j, "\"mib_per_s\":null") != NULL);      /* no wire_bytes */
    free(j); json_obj_free(o);

    uint64_t one[1] = {2000000000ULL};
    uint64_t wb = 2097152; /* 2 MiB over 2 s → 1 MiB/s */
    o = json_obj_new();
    summarize(o, one, 1, 10, 5, &wb);
    j = json_obj_render(o);
    assert(strstr(j, "\"stdev_s\":0") != NULL);           /* n==1 → 0 */
    assert(strstr(j, "\"mib_per_s\":1") != NULL);
    free(j); json_obj_free(o);
}

static void test_json(void)
{
    json_obj* o = json_obj_new();
    json_obj_int(o, "b", 1);
    json_obj_str(o, "a", "x");
    json_obj_float(o, "c", 2.5);
    json_obj_float(o, "d", 1.0 / 3.0);
    char* j = json_obj_render(o);
    assert(strcmp(j, "{\"a\":\"x\",\"b\":1,\"c\":2.5,\"d\":0.333333333333}") == 0);
    free(j); json_obj_free(o);

    o = json_obj_new();
    json_obj_str(o, "s", "a\tb\nc\x01");
    j = json_obj_render(o);
    assert(strcmp(j, "{\"s\":\"a\\tb\\nc\\u0001\"}") == 0);
    free(j); json_obj_free(o);

    assert(now_ns() > 0);
    (void)process_cpu_ns();
}

static void test_sender_range(void)
{
    size_t lo, hi;
    sender_range(10, 1, 0, &lo, &hi); assert(lo == 0 && hi == 10);
    sender_range(10, 3, 0, &lo, &hi); assert(lo == 0 && hi == 3);
    sender_range(10, 3, 1, &lo, &hi); assert(lo == 3 && hi == 6);
    sender_range(10, 3, 2, &lo, &hi); assert(lo == 6 && hi == 10);
    /* exact tiling on an awkward split */
    size_t prev = 0;
    for (size_t k = 0; k < 7; k++) {
        sender_range(1000003, 7, k, &lo, &hi);
        assert(lo == prev && hi >= lo);
        prev = hi;
    }
    assert(prev == 1000003);
    /* n > rows: empty tail ranges are legal. Note k=n-1 (the true last
     * sender) always ends at hi==rows and can never be empty for rows>=1
     * (lo=rows*(n-1)/n < rows strictly); the empty ranges live at the
     * interior tail indices before that, e.g. k=6 here (k=7 is (1,2)). */
    sender_range(2, 8, 6, &lo, &hi); assert(lo == 1 && hi == 1);
}

int main(void)
{
    test_schema();
    test_generators();
    test_data_build();
    test_stats();
    test_json();
    test_sender_range();
    printf("qwp_bench_selftest: OK\n");
    return 0;
}
