/* Stats + JSON metric contract for the C QWP bench examples. MUST match
 * questdb-rs/examples/bench_json/mod.rs: sorted keys, %.12f trimmed floats,
 * ns→s samples, midpoint median, Bessel stdev, p95 = round((n-1)*0.95). */
#pragma once
#include <stddef.h>
#include <stdint.h>

uint64_t now_ns(void);         /* CLOCK_MONOTONIC */
uint64_t process_cpu_ns(void); /* getrusage user+sys */

typedef struct json_obj json_obj;
json_obj* json_obj_new(void);
void json_obj_str(json_obj* o, const char* k, const char* v);
void json_obj_int(json_obj* o, const char* k, uint64_t v);
void json_obj_float(json_obj* o, const char* k, double v);
void json_obj_bool(json_obj* o, const char* k, int v);
void json_obj_null(json_obj* o, const char* k);
void json_obj_obj(json_obj* o, const char* k, json_obj* child); /* takes ownership */
char* json_obj_render(json_obj* o); /* compact, keys sorted; caller frees */
void json_obj_free(json_obj* o);

/* iterations/median_s/mean_s/min_s/max_s/p95_s/stdev_s/cov +
 * rows_per_s_median/cells_per_s_median/mib_per_s (null unless wire_bytes). */
void summarize(json_obj* obj, const uint64_t* samples_ns, size_t n,
               size_t rows, size_t columns, const uint64_t* wire_bytes);

/* Full per-path object: wall stats + process_cpu sub-object + phase/warm/
 * wire_bytes. mib_per_s only when phase == "e2e" (rate_wire_bytes gating). */
json_obj* path_summary(const uint64_t* wall_ns, const uint64_t* cpu_ns,
                       size_t n, size_t rows, size_t columns,
                       uint64_t wire_bytes, const char* phase, int warm);

/* median of samples_ns in seconds (helper for headline blocks) */
double median_s_of(const uint64_t* samples_ns, size_t n);
