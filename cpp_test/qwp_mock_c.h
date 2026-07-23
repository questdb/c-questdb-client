/* C-friendly shim around `qwp_mock::MockServer` for the pure-C
 * test_arrow_c.c suite.
 *
 * Spins up an in-process mock that accepts one WS-Upgrade per slot and
 * silently swallows the first inbound QWP binary frame on each
 * connection — enough to drive `qwp_sender_flush_arrow_batch`
 * end-to-end without hitting a live QuestDB instance.
 *
 * CMake note: when wiring this into the build, add
 *   `cpp_test/qwp_mock_c.cpp` to the `c-questdb-client-test`
 * executable's source list (alongside `qwp_mock_server.cpp`). The
 * shim itself has no extra link deps beyond what
 * `qwp_mock_server.cpp` already pulls in.
 */

#ifndef QWP_MOCK_C_H
#define QWP_MOCK_C_H

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct qwp_mock_c qwp_mock_c;

/* Start a mock server bound to 127.0.0.1:0. The mock accepts up to
 * `slot_count` WS upgrades and, on each, waits for one inbound QWP
 * binary frame (first payload byte == 'Q', i.e. the QWP1 magic) before
 * cleanly closing the connection. `slot_count` must be >= 1 — pass 1
 * when using the default `sender_pool_min=1` connect string.
 *
 * Returns NULL on failure (e.g. OS-level bind failure). */
qwp_mock_c* qwp_mock_c_start(int slot_count);

/* Variant for tests that publish multiple frames through one connection. */
qwp_mock_c* qwp_mock_c_start_frames(int slot_count, int frame_count);

/* Return the mock's listening address as "127.0.0.1:NNNN", suitable for
 * splicing into a `ws::addr=...` connect string. Pointer is valid
 * until `qwp_mock_c_stop`. */
const char* qwp_mock_c_addr(qwp_mock_c* mock);

/* Shut down the mock and free its resources. Safe to pass NULL. */
void qwp_mock_c_stop(qwp_mock_c* mock);

#ifdef __cplusplus
}
#endif

#endif /* QWP_MOCK_C_H */
