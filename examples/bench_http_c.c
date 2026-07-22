/* glibc hides XSI names (usleep) under strict -std=c11 (CMAKE_C_EXTENSIONS
 * OFF); macOS headers expose them unconditionally. */
#if defined(__linux__)
#define _XOPEN_SOURCE 600
#endif

#include "bench_http_c.h"
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

typedef struct { char* buf; size_t len; } body;

static size_t on_body(char* data, size_t sz, size_t nm, void* ud)
{
    body* b = ud;
    size_t n = sz * nm;
    b->buf = realloc(b->buf, b->len + n + 1);
    memcpy(b->buf + b->len, data, n);
    b->len += n;
    b->buf[b->len] = 0;
    return n;
}

/* GET {base}/exec?query=..., return HTTP status (0 on transport error);
 * body (optional) is heap-allocated into *out. */
static long exec_get(const char* base, const char* sql, char** out)
{
    CURL* c = curl_easy_init();
    if (!c) return 0;
    char* esc = curl_easy_escape(c, sql, 0);
    size_t ulen = strlen(base) + strlen(esc) + 32;
    char* url = malloc(ulen);
    snprintf(url, ulen, "%s/exec?query=%s", base, esc);
    body b = {0};
    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, on_body);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &b);
    curl_easy_setopt(c, CURLOPT_TIMEOUT_MS, 60000L);
    long status = 0;
    if (curl_easy_perform(c) == CURLE_OK)
        curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &status);
    curl_free(esc);
    free(url);
    curl_easy_cleanup(c);
    if (out) *out = b.buf; else free(b.buf);
    return status;
}

int http_exec_sql(const char* base, const char* sql)
{
    char* bdy = NULL;
    long status = exec_get(base, sql, &bdy);
    if (status != 200) {
        fprintf(stderr, "[bench_http] HTTP %ld for: %s\n%s\n",
                status, sql, bdy ? bdy : "");
        free(bdy);
        return 1;
    }
    free(bdy);
    return 0;
}

/* parse the LAST "dataset":[[<digits> in the /exec JSON (same as the Rust
 * examples' find-based parse). */
static long long parse_count(const char* bdy)
{
    const char* key = "\"dataset\":[[";
    const char* p = NULL;
    for (const char* q = strstr(bdy, key); q; q = strstr(q + 1, key))
        p = q;
    if (!p) return -1;
    return atoll(p + strlen(key));
}

long long wait_for_count(const char* base, const char* table, long long expected)
{
    char sql[256];
    snprintf(sql, sizeof(sql), "SELECT count() FROM %s", table);
    time_t deadline = time(NULL) + 300;
    long long n = -1;
    while (time(NULL) < deadline) {
        char* bdy = NULL;
        if (exec_get(base, sql, &bdy) == 200 && bdy) {
            long long c = parse_count(bdy);
            if (c >= 0) n = c;
        }
        free(bdy);
        if (n >= expected) return n;
        usleep(500 * 1000);
    }
    return n;
}
