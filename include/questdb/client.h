/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2025 QuestDB
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

/*
 * The QWP/WebSocket connection pool: `questdb_db`.
 *
 * The pool is the entry point for both directions of traffic. It owns the
 * connect string, the connection lifecycle, and the reaper; leases are then
 * borrowed from it through the direction-specific headers:
 *
 *   - `questdb/ingress/qwp_sender.h` — borrow senders to write rows.
 *   - `questdb/egress/qwp_reader.h`         — borrow readers to run SQL queries.
 *
 * Either of those includes this header, so a consumer that needs only one
 * direction includes only that header. Include this one directly to hold or
 * configure a pool in a translation unit that borrows nothing itself.
 *
 * Error reporting follows the convention of `line_sender.h`: `err_out` is
 * optional on every fallible call, and if non-NULL, `*err_out` MUST be NULL on
 * entry.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <questdb/ingress/line_sender.h>

/* -------------------------------------------------------------------------
 * Pool handle
 * ------------------------------------------------------------------------- */

/** Connection pool. Thread-safe for borrow/return/reap operations while the
 *  owning handle remains open. `questdb_db_close` is the final owner release:
 *  do not call it concurrently with other operations on the same `db`. */
typedef struct questdb_db questdb_db;

/* -------------------------------------------------------------------------
 * Pool lifecycle
 * ------------------------------------------------------------------------- */

/**
 * Open a connection pool. This call performs no blocking network I/O. In
 * disk-backed store-and-forward mode it may pre-open parked recovery senders;
 * their initial connect and replay run in the background. Otherwise, the first
 * borrow opens a sender, so auth / TLS / connect errors usually surface from
 * the borrow, not from here. `sender_pool_min` (default 1) is the warm
 * minimum the reaper keeps once connections have been opened.
 *
 * `conf` is a `ws::` / `wss::` connect string. Pool-specific keys (aligned
 * with the Java client's `QuestDBBuilder`):
 *   `sender_pool_min`      (default 1)    warm/min sender connections;
 *   `sender_pool_max`      (default 4)    cap on the ingestion and direct
 *                                         pools, each capped independently;
 *   `query_pool_min`       (default 1)    warm/min reader connections;
 *   `query_pool_max`       (default 4)    cap on the reader pool;
 *   `acquire_timeout_ms`   (default 5000) how long a borrow at cap waits for
 *                                         a return before failing; 0 fails
 *                                         fast;
 *   `idle_timeout_ms`      (default 60000)
 *                                         reap above-minimum idle
 *                                         connections;
 *   `pool_reap`            (`auto`|`manual`, default `auto`)
 *                                         background reaper opt-in.
 *
 * Disk-backed store-and-forward is opt-in: `sf_dir` selects disk-backed queues
 * for the public ingestion pool. `sender_id` names the slot *base* (default
 * "default"); pooled senders mint `<sender_id>-ingest-<index>` slots with
 * stable lowest-free-first indices in `[0, sender_pool_max)`. The
 * `<sender_id>-ingest-*` directories under `sf_dir` belong to the pool
 * namespace; use a unique `sender_id` for each pool sharing an `sf_dir`. At
 * cap, disk-backed ingestion borrows usually
 * fail, but can wait up to `close_flush_timeout` (default 5s) if another
 * sender is currently closing and has not yet released its slot lock. An
 * unsuffixed slot `<sf_dir>/<sender_id>` is not pool-managed; it is treated
 * like any other orphan slot and is drained only when `drain_orphans=on`.
 */
QUESTDB_CLIENT_API
questdb_db* questdb_db_connect(
    const char* conf,
    size_t conf_len,
    questdb_error** err_out);

/**
 * Close the pool. Accepts NULL and no-ops.
 *
 * Final owner release: callers must ensure no other thread is concurrently
 * using `db` for borrow/reap/config operations. This invalidates `db` for
 * new borrows and closes idle connections.
 * Outstanding leases are independent: returning or dropping a sender, or
 * closing a reader, after pool close is safe, but new operations on them fail
 * with `questdb_error_invalid_api_call`. A lease returned after close is
 * closed, not recycled. Already-created cursors may continue streaming.
 * Close detaches and joins the connection-event and rejection dispatchers;
 * after it returns no callback can use its `user_data`, including callbacks
 * from an outstanding sender's background runner. Exception: when close is
 * called from a dispatcher thread, that thread is not joined (avoiding a
 * self-join deadlock) and its in-flight callback finishes after close returns.
 */
QUESTDB_CLIENT_API
void questdb_db_close(questdb_db* db);

/**
 * The pool's failover budget (`reconnect_max_duration`, default 300000 ms).
 * Callers tracking an overall failover deadline pass the remaining budget to
 * `questdb_db_borrow_sender_with_retry`. Returns 0 if `db` is NULL.
 */
QUESTDB_CLIENT_API
uint64_t questdb_db_reconnect_max_duration_ms(const questdb_db* db);

/**
 * Manually reap idle connections (closes free-list entries idle longer
 * than `idle_timeout_ms`, never shrinking the sender pools below
 * `sender_pool_min` or the reader pool below `query_pool_min`).
 * Returns the number of connections closed.
 */
QUESTDB_CLIENT_API
size_t questdb_db_reap_idle(questdb_db* db);

/* -------------------------------------------------------------------------
 * Connection lifecycle events
 *
 * Open the pool with `questdb_db_connect_with_event_handler` to register one
 * listener per pool. Events are delivered on a dedicated dispatcher thread
 * (never an I/O or producer thread) through a bounded inbox with a
 * drop-oldest overflow policy, so a slow callback cannot stall connects or
 * publishing. Direct and store-and-forward senders share this one source and
 * inbox; concurrent events are delivered in the order they enter that inbox.
 * Connected, reconnected, and failed-over events enter the inbox only after
 * negotiated connection state, including the server-advertised frame cap, is
 * committed. They are not data-delivery or acknowledgement barriers.
 *
 * Registration happens before the pool opens anything, so the listener
 * observes every transition — including the initial `connected` of disk
 * recovery senders pre-opened during connect. There is no post-connect
 * registration.
 * ------------------------------------------------------------------------- */

/* Connection-event types (`questdb_connection_event`, the kind constants,
 * and `questdb_connection_event_cb`) are declared in
 * `questdb/ingress/line_sender.h`, shared with the sender-level
 * `line_sender_opts_connection_event_handler`. */

/** `questdb_db_connect` with a connection lifecycle listener.
 * `inbox_capacity` of 0 selects the default (64). The caller guarantees
 * `user_data` is safe to use from the dispatcher thread until
 * `questdb_db_close` returns. On failure (NULL return) no callback runs
 * after this function returns and `user_data` may be released
 * immediately. */
QUESTDB_CLIENT_API
questdb_db* questdb_db_connect_with_event_handler(
    const char* conf,
    size_t conf_len,
    questdb_connection_event_cb callback,
    void* user_data,
    size_t inbox_capacity,
    questdb_error** err_out);

/** Like `questdb_db_connect_with_event_handler`, additionally registering a
 * server-rejection handler. Either callback may be NULL: a NULL
 * `event_callback` disables connection lifecycle events; a NULL
 * `rejection_callback` selects the default of logging every rejection (warn
 * for retriable policies — the frames are replayed, not lost — error for
 * terminal ones), so silence is never the default.
 *
 * The rejection handler receives every server rejection any of the pool's
 * store-and-forward connections records — including rejections for frames
 * whose sender was already returned to the pool — on a dedicated dispatcher
 * thread through a bounded inbox (`rejection_inbox_capacity` of 0 selects
 * the default 64; overflow drops the oldest event, counted by
 * `questdb_db_rejection_events_dropped`). The caller guarantees each
 * `user_data` is safe to use from its dispatcher thread until
 * `questdb_db_close` returns. A terminal rejection enters the handler inbox
 * only after the connection's terminal latch and pollable diagnostic have
 * been committed. */
QUESTDB_CLIENT_API
questdb_db* questdb_db_connect_with_handlers(
    const char* conf,
    size_t conf_len,
    questdb_connection_event_cb event_callback,
    void* event_user_data,
    size_t event_inbox_capacity,
    line_sender_qwpws_error_cb rejection_callback,
    void* rejection_user_data,
    size_t rejection_inbox_capacity,
    questdb_error** err_out);

/** Total events discarded by the inbox's drop-oldest policy. */
QUESTDB_CLIENT_API
uint64_t questdb_db_connection_events_dropped(const questdb_db* db);

/** Total events delivered to the listener. */
QUESTDB_CLIENT_API
uint64_t questdb_db_connection_events_delivered(const questdb_db* db);

/** Total server rejections delivered to the rejection handler (or to the
 *  default log handler when none was registered). `0` for a NULL `db`. */
QUESTDB_CLIENT_API
uint64_t questdb_db_rejection_events_delivered(const questdb_db* db);

/** Total server rejections discarded by the rejection handler inbox's
 *  drop-oldest policy. Always `0` without a registered handler: the default
 *  log handler has no inbox. `0` for a NULL `db`. */
QUESTDB_CLIENT_API
uint64_t questdb_db_rejection_events_dropped(const questdb_db* db);

/* -------------------------------------------------------------------------
 * Diagnostics: per-pool connection counts
 *
 * Soak / leak harnesses sample these and assert every pool drains back to a
 * steady baseline after load and failover episodes (a leaked connection / FD
 * shows up as `in_use` or `free` failing to fall back). Not part of the
 * stable ABI; the field set may change.
 * ------------------------------------------------------------------------- */

/** Connection counts for a single pool. */
typedef struct questdb_dbg_pool_count
{
    /** Idle connections parked on the free list. */
    size_t free;
    /** Borrowed connections plus in-flight grow operations. */
    size_t in_use;
    /** Disk store-and-forward slots mid-close, awaiting flock release. Always
     *  0 for the direct and reader pools. */
    size_t closing;
} questdb_dbg_pool_count;

/** Connection-count snapshot across all three pools. The ingestion and
 *  direct pools are each capped at `sender_pool_max` and the reader pool at
 *  `query_pool_max`, so `free + in_use` summed across the fields can reach
 *  `2 * sender_pool_max + query_pool_max`. */
typedef struct questdb_dbg_pool_counts
{
    /** Store-and-forward ingestion pool. */
    questdb_dbg_pool_count ingress;
    /** Always-direct column-sender pool (DataFrame ingest). */
    questdb_dbg_pool_count column_direct;
    /** Reader (egress) pool. */
    questdb_dbg_pool_count reader;
} questdb_dbg_pool_counts;

/**
 * Snapshot per-pool connection counts for diagnostics. Returns an all-zero
 * snapshot for a NULL `db`.
 */
QUESTDB_CLIENT_API
questdb_dbg_pool_counts questdb_db_dbg_pool_counts(const questdb_db* db);

#ifdef __cplusplus
}
#endif
