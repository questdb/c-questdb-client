/* DDL + count()-polling over QuestDB's HTTP /exec, via libcurl.
 * Mirrors exec_sql / wait_for_count in qwp_ingress_polars.rs. */
#pragma once

/* GET {base}/exec?query=<url-escaped sql>. 0 on HTTP 200, non-zero otherwise
 * (curl error or HTTP status printed to stderr). */
int http_exec_sql(const char* base, const char* sql);

/* Poll `SELECT count() FROM {table}` every 500 ms until count >= expected or
 * 300 s elapse. Returns the last observed count (-1 if never parsed). */
long long wait_for_count(const char* base, const char* table, long long expected);
