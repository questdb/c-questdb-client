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

// The QWP/WebSocket connection pool: `questdb::pool`.
//
// The pool is the entry point for both directions of traffic. Leases are
// borrowed from it through the direction-specific headers:
//
//   - `questdb/ingress/qwp_sender.hpp` — `pool::borrow_sender()`.
//   - `questdb/egress/qwp_reader.hpp`         — `pool::borrow_reader()`.
//
// Each of those defines the borrow methods it owns and includes this header,
// so a consumer that needs only one direction includes only that header.
// Include this one directly to hold or configure a pool in a translation unit
// that borrows nothing itself.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

#include <questdb/client.h>
#include <questdb/ingress/line_sender_core.hpp>

// Forward declarations so `pool` can hand out leases of either direction while
// keeping both lease headers off its own include path. The corresponding
// methods are DEFINED in the headers that own these types; include the header
// for the direction you borrow.
namespace questdb::ingress
{
class borrowed_sender;
}

namespace questdb::egress
{
class reader;
}

namespace questdb
{
/**
 * RAII wrapper around `::questdb_db*` — the QWP/WS connection pool.
 *
 * `conf` is a `ws::` / `wss::` connect string; see `questdb/client.h` for
 * pool-specific keys (`sender_pool_min`, `sender_pool_max`, `query_pool_min`,
 * `query_pool_max`, `acquire_timeout_ms`, `idle_timeout_ms`, `pool_reap`).
 * With `sf_dir`, `sender_id` is the
 * slot base; pooled senders mint `<sender_id>-ingest-<index>` disk slots.
 * Those `<sender_id>-ingest-*` directories under `sf_dir` belong to the pool namespace;
 * use a unique `sender_id` for each pool sharing an `sf_dir`.
 *
 * Construction connects eagerly by default: it pre-opens the warm minimums
 * (`sender_pool_min` senders, `query_pool_min` readers), honoring
 * `initial_connect_retry` for the senders (readers always connect
 * fail-fast), so connect errors throw from the constructor.
 * With `lazy_connect=true` it performs no blocking network I/O: senders
 * buffer locally and connect in the background, and readers connect on
 * first borrow. In disk-backed store-and-forward mode either variant may
 * pre-open parked recovery senders whose initial connect and replay run in
 * the background.
 *
 * Borrow/return operations are thread-safe while this owner remains alive.
 * Destruction is the final owner release: do not destroy the pool while
 * another thread may still call methods on this object. Borrowed guards that
 * outlive the pool remain safe to destroy; after pool close they are dropped
 * instead of recycled, and new operations on them fail. Destruction also
 * joins the C connection-event dispatcher, so callback `user_data` may be
 * released once it returns.
 */
class pool
{
public:
    explicit pool(std::string_view conf)
    {
        _raw = ::questdb::error::wrapped_call(
            ::questdb_db_connect, conf.data(), conf.size());
    }

    pool(const pool&) = delete;
    pool& operator=(const pool&) = delete;

    pool(pool&& other) noexcept
        : _raw{other._raw}
    {
        other._raw = nullptr;
    }

    pool& operator=(pool&& other) noexcept
    {
        if (this != &other)
        {
            close();
            _raw = other._raw;
            other._raw = nullptr;
        }
        return *this;
    }

    ~pool() noexcept { close(); }

    ::questdb_db* c_ptr() noexcept { return _raw; }
    const ::questdb_db* c_ptr() const noexcept { return _raw; }

    /** Borrow a store-and-forward sender. At cap, disk-backed slots can wait
     * up to `close_flush_timeout` (default 5s) while an in-flight close
     * releases its lock; otherwise throws on cap exhaustion or transport
     * failure.
     *
     * DEFINED in `questdb/ingress/qwp_sender.hpp`, alongside the
     * `borrowed_sender` type it returns. Include that header to call this. */
    ingress::borrowed_sender borrow_sender();

    /**
     * Borrow a store-and-forward sender, retrying the connect within `budget_ms`
     * using the pool's reconnect backoff. On a transient `failover_retry`,
     * drop the dead sender then call this with `reconnect_max_duration_ms()` (or
     * your tracked remaining budget). Throws on a terminal error or budget
     * exhaustion.
     *
     * DEFINED in `questdb/ingress/qwp_sender.hpp`, alongside the
     * `borrowed_sender` type it returns. Include that header to call this.
     */
    ingress::borrowed_sender borrow_sender_with_retry(uint64_t budget_ms);

    /**
     * Borrow a query reader from the pool, mirroring Rust
     * `QuestDb::borrow_reader`. Readers are pooled on a separate,
     * independently-capped free list with its own `query_pool_min` /
     * `query_pool_max` budget; `query_pool_min` readers are pre-opened at
     * construction (none under `lazy_connect=true`, where a connection
     * opens on first borrow). The returned `reader` is
     * equivalent to a standalone one and returns itself to the pool on
     * destruction — unless `reader::drop_on_return()` was called, in which
     * case it is dropped. If the pool has already been closed by the time the
     * reader is destroyed, it is closed instead of recycled. Throws
     * `questdb::error` on cap exhaustion or transport failure.
     *
     * DEFINED in `questdb/egress/qwp_reader.hpp`, alongside the `reader` type it
     * returns. Include that header to call this.
     */
    ::questdb::egress::reader borrow_reader();

    /** The pool's failover budget (`reconnect_max_duration`) in milliseconds. */
    uint64_t reconnect_max_duration_ms() const noexcept
    {
        return ::questdb_db_reconnect_max_duration_ms(_raw);
    }

    /** Close idle connections beyond the pool minimums. Returns count
     *  closed. */
    size_t reap_idle() noexcept
    {
        return ::questdb_db_reap_idle(_raw);
    }

    /**
     * Snapshot per-pool connection counts for diagnostics (soak / leak
     * harnesses assert every pool drains back to a steady baseline after
     * load and failover). Not part of the stable ABI; the field set may
     * change.
     */
    ::questdb_dbg_pool_counts dbg_pool_counts() const noexcept
    {
        return ::questdb_db_dbg_pool_counts(_raw);
    }

private:
    void close() noexcept
    {
        if (_raw)
        {
            ::questdb_db_close(_raw);
            _raw = nullptr;
        }
    }

    ::questdb_db* _raw{nullptr};
};

} // namespace questdb
