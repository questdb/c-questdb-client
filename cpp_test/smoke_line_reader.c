/*
 * Smoke test for the line_reader FFI.
 *
 * Targets a guaranteed-closed port (127.0.0.1:1, the TCPMUX well-known
 * port that is virtually never bound) and asserts that
 * `line_reader_from_conf` reaches the connect path, fails cleanly, and
 * surfaces a non-NULL error that the FFI can then free. This exercises
 * symbol resolution, FFI argument marshalling, error allocation, and
 * `line_reader_close`'s NULL-idempotent behaviour — all without fighting
 * a developer machine that happens to have a QuestDB broker running on
 * the default port (the case that broke the previous `WILL_FAIL`-based
 * smoke).
 *
 * Exit code is the standard "0 = pass, non-zero = fail" so SIGSEGV /
 * SIGABRT are correctly reported as failures rather than passes.
 */

#include <questdb/egress/line_reader.h>
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    line_sender_utf8 conf =
        QDB_UTF8_LITERAL("qwp::addr=127.0.0.1:1;");

    line_reader_error* err = NULL;
    line_reader* reader = line_reader_from_conf(conf, &err);

    if (reader != NULL)
    {
        fprintf(
            stderr,
            "smoke: expected line_reader_from_conf to fail against a "
            "guaranteed-closed port, but it succeeded\n");
        line_reader_close(reader);
        return 1;
    }

    if (err == NULL)
    {
        fprintf(
            stderr,
            "smoke: line_reader_from_conf returned NULL but did not set "
            "an error — FFI error-propagation contract violated\n");
        return 1;
    }

    size_t msg_len = 0;
    const char* msg = line_reader_error_msg(err, &msg_len);
    if (msg == NULL || msg_len == 0)
    {
        fprintf(
            stderr,
            "smoke: error has empty message — error-message accessor "
            "broken\n");
        line_reader_error_free(err);
        return 1;
    }

    /* Drop the error and confirm the NULL-idempotent close path. */
    line_reader_error_free(err);
    line_reader_close(NULL);
    return 0;
}
