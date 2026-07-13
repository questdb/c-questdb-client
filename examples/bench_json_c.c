#include "bench_json_c.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

uint64_t process_cpu_ns(void)
{
    struct rusage u;
    if (getrusage(RUSAGE_SELF, &u) != 0) return 0;
    uint64_t ns = (uint64_t)u.ru_utime.tv_sec * 1000000000ULL
                + (uint64_t)u.ru_utime.tv_usec * 1000ULL
                + (uint64_t)u.ru_stime.tv_sec * 1000000000ULL
                + (uint64_t)u.ru_stime.tv_usec * 1000ULL;
    return ns;
}

/* -------- sorted-key object builder (mirrors bench_json Obj) -------- */

typedef struct { char* key; char* val; } json_entry;
struct json_obj { json_entry* e; size_t n, cap; };

json_obj* json_obj_new(void)
{
    json_obj* o = calloc(1, sizeof(*o));
    return o;
}

static void put(json_obj* o, const char* k, char* rendered /* owned */)
{
    if (o->n == o->cap) {
        o->cap = o->cap ? o->cap * 2 : 16;
        o->e = realloc(o->e, o->cap * sizeof(json_entry));
    }
    o->e[o->n].key = strdup(k);
    o->e[o->n].val = rendered;
    o->n++;
}

/* mirrors bench_json json_str(): escape quote/backslash, \n \r \t, and
 * any other codepoint < 0x20 as \u00xx (lowercase hex). */
static char* json_escape(const char* s)
{
    size_t n = strlen(s), j = 0;
    char* out = malloc(n * 6 + 3); /* worst case: every byte -> \u00xx */
    out[j++] = '"';
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
        case '"':  out[j++] = '\\'; out[j++] = '"';  break;
        case '\\': out[j++] = '\\'; out[j++] = '\\'; break;
        case '\n': out[j++] = '\\'; out[j++] = 'n';  break;
        case '\r': out[j++] = '\\'; out[j++] = 'r';  break;
        case '\t': out[j++] = '\\'; out[j++] = 't';  break;
        default:
            if (c < 0x20)
                j += (size_t)sprintf(out + j, "\\u%04x", (unsigned)c);
            else
                out[j++] = (char)c;
        }
    }
    out[j++] = '"';
    out[j] = 0;
    return out;
}

/* format!("{v:.12}") then trim trailing zeros and trailing '.' */
static char* json_f64(double v)
{
    char* out = malloc(64);
    if (!isfinite(v)) { strcpy(out, "null"); return out; }
    snprintf(out, 64, "%.12f", v);
    char* dot = strchr(out, '.');
    if (dot) {
        char* end = out + strlen(out) - 1;
        while (end > dot && *end == '0') *end-- = 0;
        if (end == dot) *end = 0;
    }
    if (out[0] == 0 || strcmp(out, "-") == 0) strcpy(out, "0");
    return out;
}

void json_obj_str(json_obj* o, const char* k, const char* v) { put(o, k, json_escape(v)); }
void json_obj_int(json_obj* o, const char* k, uint64_t v)
{ char* b = malloc(32); snprintf(b, 32, "%llu", (unsigned long long)v); put(o, k, b); }
void json_obj_float(json_obj* o, const char* k, double v) { put(o, k, json_f64(v)); }
void json_obj_bool(json_obj* o, const char* k, int v) { put(o, k, strdup(v ? "true" : "false")); }
void json_obj_null(json_obj* o, const char* k) { put(o, k, strdup("null")); }

void json_obj_obj(json_obj* o, const char* k, json_obj* child)
{
    put(o, k, json_obj_render(child));
    json_obj_free(child);
}

static int entry_cmp(const void* a, const void* b)
{ return strcmp(((const json_entry*)a)->key, ((const json_entry*)b)->key); }

char* json_obj_render(json_obj* o)
{
    qsort(o->e, o->n, sizeof(json_entry), entry_cmp);
    size_t need = 3;
    for (size_t i = 0; i < o->n; i++)
        need += strlen(o->e[i].key) + strlen(o->e[i].val) + 4;
    char* out = malloc(need);
    size_t j = 0;
    out[j++] = '{';
    for (size_t i = 0; i < o->n; i++) {
        if (i) out[j++] = ',';
        j += (size_t)sprintf(out + j, "\"%s\":%s", o->e[i].key, o->e[i].val);
    }
    out[j++] = '}';
    out[j] = 0;
    return out;
}

void json_obj_free(json_obj* o)
{
    if (!o) return;
    for (size_t i = 0; i < o->n; i++) { free(o->e[i].key); free(o->e[i].val); }
    free(o->e);
    free(o);
}

/* ------------------------- stats contract -------------------------- */

static int f64_cmp(const void* a, const void* b)
{
    double x = *(const double*)a, y = *(const double*)b;
    return (x > y) - (x < y);
}

double median_s_of(const uint64_t* samples_ns, size_t n)
{
    if (n == 0) return 0.0;
    double* s = malloc(n * sizeof(double));
    for (size_t i = 0; i < n; i++) s[i] = (double)samples_ns[i] / 1e9;
    qsort(s, n, sizeof(double), f64_cmp);
    double m = (n % 2 == 1) ? s[n / 2] : (s[n / 2 - 1] + s[n / 2]) / 2.0;
    free(s);
    return m;
}

static double percentile(const double* sorted, size_t n, double p)
{
    if (n == 0) return 0.0;
    size_t idx = (size_t)llround(((double)n - 1.0) * p);
    if (idx > n - 1) idx = n - 1;
    return sorted[idx];
}

void summarize(json_obj* obj, const uint64_t* samples_ns, size_t n,
               size_t rows, size_t columns, const uint64_t* wire_bytes)
{
    double* s = malloc((n ? n : 1) * sizeof(double));
    double sum = 0.0;
    for (size_t i = 0; i < n; i++) { s[i] = (double)samples_ns[i] / 1e9; sum += s[i]; }
    double mean = n ? sum / (double)n : 0.0;
    double* sorted = malloc((n ? n : 1) * sizeof(double));
    memcpy(sorted, s, n * sizeof(double));
    qsort(sorted, n, sizeof(double), f64_cmp);
    double median = (n == 0) ? 0.0
                  : (n % 2 == 1) ? sorted[n / 2]
                  : (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0;
    double stdev = 0.0;
    if (n > 1) {
        double var = 0.0;
        for (size_t i = 0; i < n; i++) var += (s[i] - mean) * (s[i] - mean);
        stdev = sqrt(var / ((double)n - 1.0));
    }
    json_obj_int(obj, "iterations", (uint64_t)n);
    json_obj_float(obj, "median_s", median);
    json_obj_float(obj, "mean_s", mean);
    json_obj_float(obj, "min_s", n ? sorted[0] : 0.0);
    json_obj_float(obj, "max_s", n ? sorted[n - 1] : 0.0);
    json_obj_float(obj, "p95_s", percentile(sorted, n, 0.95));
    json_obj_float(obj, "stdev_s", stdev);
    json_obj_float(obj, "cov", mean != 0.0 ? stdev / mean : 0.0);
    if (median != 0.0) {
        json_obj_float(obj, "rows_per_s_median", (double)rows / median);
        json_obj_float(obj, "cells_per_s_median", (double)(rows * columns) / median);
    } else {
        json_obj_null(obj, "rows_per_s_median");
        json_obj_null(obj, "cells_per_s_median");
    }
    if (wire_bytes && median != 0.0)
        json_obj_float(obj, "mib_per_s", ((double)*wire_bytes / (1024.0 * 1024.0)) / median);
    else
        json_obj_null(obj, "mib_per_s");
    free(s);
    free(sorted);
}

json_obj* path_summary(const uint64_t* wall_ns, const uint64_t* cpu_ns,
                       size_t n, size_t rows, size_t columns,
                       uint64_t wire_bytes, const char* phase, int warm)
{
    int e2e = strcmp(phase, "e2e") == 0;
    const uint64_t* rate_wb = e2e ? &wire_bytes : NULL;
    json_obj* o = json_obj_new();
    summarize(o, wall_ns, n, rows, columns, rate_wb);
    json_obj* cpu = json_obj_new();
    summarize(cpu, cpu_ns, n, rows, columns, rate_wb);
    json_obj_obj(o, "process_cpu", cpu);
    json_obj_str(o, "phase", phase);
    json_obj_bool(o, "warm", warm);
    json_obj_int(o, "wire_bytes", wire_bytes);
    return o;
}
