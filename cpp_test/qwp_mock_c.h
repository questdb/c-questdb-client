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

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
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

/* Start a mock that takes ingress frames as a server with a frame limit of
 * `max_batch_size` bytes does, on every connection it accepts: it tells the
 * limit in the handshake, gives no answer to a data frame with the defer
 * flag, and answers a frame without it with an OK that confirms the frames
 * before it too.
 *
 * Returns NULL on failure. */
qwp_mock_c* qwp_mock_c_start_ingress(size_t max_batch_size);

/* The number of data frames that a mock started with
 * `qwp_mock_c_start_ingress` has taken so far, over all its connections. */
size_t qwp_mock_c_ingress_frame_count(qwp_mock_c* mock);

/* The size in bytes of the data frame `index` (in arrival order, from 0) and
 * whether it has the defer flag. Returns false when there is no such frame. */
bool qwp_mock_c_ingress_frame(
    qwp_mock_c* mock, size_t index, size_t* size_out, bool* deferred_out);

/* Wait up to `timeout_millis` until `count` connections of a mock started
 * with `qwp_mock_c_start_ingress` have ended. Returns true if they have: the
 * mock has then counted every frame the client sent on them. */
bool qwp_mock_c_wait_for_ingress_closed(
    qwp_mock_c* mock, int count, int timeout_millis);

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
