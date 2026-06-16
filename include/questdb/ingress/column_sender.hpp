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

#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <utility>

#include <questdb/ingress/column_sender.h>
#include <questdb/ingress/line_sender.hpp>

// NumPy appender (`::column_sender_chunk_append_numpy_column`) is
// intentionally not wrapped here; it is awkward to use from C++ without
// a NumPy host. C++ callers needing it can drop to the raw C API.

namespace questdb::ingress
{

/** Ack level for `column_sender_conn::sync`. */
enum class column_sender_ack_level : uint32_t
{
    ok = ::column_sender_ack_level_ok,
    durable = ::column_sender_ack_level_durable,
};

/**
 * Non-owning view over an Arrow-shape validity bitmap (bit = 1 means
 * VALID, LSB-first). `bit_len` must equal the chunk's row count; the
 * underlying buffer must outlive the next `column_chunk` flush.
 */
class validity_view
{
public:
    validity_view() noexcept = default;

    validity_view(const uint8_t* bits, size_t bit_len) noexcept
        : _bits{bits}
        , _bit_len{bit_len}
    {
    }

    const ::column_sender_validity* c_ptr() const noexcept
    {
        return &_impl;
    }

private:
    const uint8_t* _bits{nullptr};
    size_t _bit_len{0};
    ::column_sender_validity _impl{_bits, _bit_len};
};

/** Forward decl. */
class column_sender_conn;

/**
 * RAII wrapper around `::column_sender_chunk*`. Move-only.
 *
 * Holds raw-pointer descriptors into caller buffers; the caller MUST
 * keep every column buffer alive from the per-column append call until
 * the next `column_sender_conn::flush` returns.
 */
class column_chunk
{
public:
    /** Build a chunk targeting `table` (validated at flush time). */
    explicit column_chunk(std::string_view table)
    {
        _raw = line_sender_error::wrapped_call(
            ::column_sender_chunk_new, table.data(), table.size());
    }

    column_chunk(const column_chunk&) = delete;
    column_chunk& operator=(const column_chunk&) = delete;

    column_chunk(column_chunk&& other) noexcept
        : _raw{other._raw}
    {
        other._raw = nullptr;
    }

    column_chunk& operator=(column_chunk&& other) noexcept
    {
        if (this != &other)
        {
            if (_raw)
                ::column_sender_chunk_free(_raw);
            _raw = other._raw;
            other._raw = nullptr;
        }
        return *this;
    }

    ~column_chunk() noexcept
    {
        if (_raw)
            ::column_sender_chunk_free(_raw);
    }

    ::column_sender_chunk* c_ptr() noexcept { return _raw; }
    const ::column_sender_chunk* c_ptr() const noexcept { return _raw; }

    /**
     * Row count locked by the first appended column / designated ts.
     * Throws `line_sender_error` if the underlying handle is NULL,
     * freed, or held by a concurrent FFI call.
     */
    size_t row_count() const
    {
        ::line_sender_error* c_err{nullptr};
        size_t r = ::column_sender_chunk_row_count(_raw, &c_err);
        if (r == static_cast<size_t>(-1))
            throw line_sender_error::from_c(c_err);
        return r;
    }

    /**
     * Reset the chunk; retains descriptor-vec capacity. Throws
     * `line_sender_error` if the underlying handle is NULL, freed, or
     * held by a concurrent FFI call.
     */
    void clear()
    {
        line_sender_error::wrapped_call(::column_sender_chunk_clear, _raw);
    }

    // -- Fixed-width column appenders ---------------------------------

    column_chunk& column_i8(
        std::string_view name,
        const int8_t* data,
        size_t row_count,
        const validity_view* validity = nullptr)
    {
        line_sender_error::wrapped_call(
            ::column_sender_chunk_column_i8,
            _raw,
            name.data(),
            name.size(),
            data,
            row_count,
            validity ? validity->c_ptr() : nullptr);
        return *this;
    }

    column_chunk& column_i16(
        std::string_view name,
        const int16_t* data,
        size_t row_count,
        const validity_view* validity = nullptr)
    {
        line_sender_error::wrapped_call(
            ::column_sender_chunk_column_i16,
            _raw,
            name.data(),
            name.size(),
            data,
            row_count,
            validity ? validity->c_ptr() : nullptr);
        return *this;
    }

    column_chunk& column_i32(
        std::string_view name,
        const int32_t* data,
        size_t row_count,
        const validity_view* validity = nullptr)
    {
        line_sender_error::wrapped_call(
            ::column_sender_chunk_column_i32,
            _raw,
            name.data(),
            name.size(),
            data,
            row_count,
            validity ? validity->c_ptr() : nullptr);
        return *this;
    }

    column_chunk& column_i64(
        std::string_view name,
        const int64_t* data,
        size_t row_count,
        const validity_view* validity = nullptr)
    {
        line_sender_error::wrapped_call(
            ::column_sender_chunk_column_i64,
            _raw,
            name.data(),
            name.size(),
            data,
            row_count,
            validity ? validity->c_ptr() : nullptr);
        return *this;
    }

    column_chunk& column_f32(
        std::string_view name,
        const float* data,
        size_t row_count,
        const validity_view* validity = nullptr)
    {
        line_sender_error::wrapped_call(
            ::column_sender_chunk_column_f32,
            _raw,
            name.data(),
            name.size(),
            data,
            row_count,
            validity ? validity->c_ptr() : nullptr);
        return *this;
    }

    column_chunk& column_f64(
        std::string_view name,
        const double* data,
        size_t row_count,
        const validity_view* validity = nullptr)
    {
        line_sender_error::wrapped_call(
            ::column_sender_chunk_column_f64,
            _raw,
            name.data(),
            name.size(),
            data,
            row_count,
            validity ? validity->c_ptr() : nullptr);
        return *this;
    }

    /** Bit-packed boolean column (LSB-first). */
    column_chunk& column_bool(
        std::string_view name,
        const uint8_t* bits,
        size_t row_count,
        const validity_view* validity = nullptr)
    {
        line_sender_error::wrapped_call(
            ::column_sender_chunk_column_bool,
            _raw,
            name.data(),
            name.size(),
            bits,
            row_count,
            validity ? validity->c_ptr() : nullptr);
        return *this;
    }

    /** UUID column: 16 bytes per row — low half LE in bytes 0..8, high half LE in bytes 8..16. */
    column_chunk& column_uuid(
        std::string_view name,
        const uint8_t* data,
        size_t row_count,
        const validity_view* validity = nullptr)
    {
        line_sender_error::wrapped_call(
            ::column_sender_chunk_column_uuid,
            _raw,
            name.data(),
            name.size(),
            data,
            row_count,
            validity ? validity->c_ptr() : nullptr);
        return *this;
    }

    /** LONG256 column: 32 contiguous bytes per row (little-endian limbs). */
    column_chunk& column_long256(
        std::string_view name,
        const uint8_t* data,
        size_t row_count,
        const validity_view* validity = nullptr)
    {
        line_sender_error::wrapped_call(
            ::column_sender_chunk_column_long256,
            _raw,
            name.data(),
            name.size(),
            data,
            row_count,
            validity ? validity->c_ptr() : nullptr);
        return *this;
    }

    column_chunk& column_ipv4(
        std::string_view name,
        const uint32_t* data,
        size_t row_count,
        const validity_view* validity = nullptr)
    {
        line_sender_error::wrapped_call(
            ::column_sender_chunk_column_ipv4,
            _raw,
            name.data(),
            name.size(),
            data,
            row_count,
            validity ? validity->c_ptr() : nullptr);
        return *this;
    }

    column_chunk& column_ts_nanos(
        std::string_view name,
        const int64_t* data,
        size_t row_count,
        const validity_view* validity = nullptr)
    {
        line_sender_error::wrapped_call(
            ::column_sender_chunk_column_ts_nanos,
            _raw,
            name.data(),
            name.size(),
            data,
            row_count,
            validity ? validity->c_ptr() : nullptr);
        return *this;
    }

    column_chunk& column_ts_micros(
        std::string_view name,
        const int64_t* data,
        size_t row_count,
        const validity_view* validity = nullptr)
    {
        line_sender_error::wrapped_call(
            ::column_sender_chunk_column_ts_micros,
            _raw,
            name.data(),
            name.size(),
            data,
            row_count,
            validity ? validity->c_ptr() : nullptr);
        return *this;
    }

    column_chunk& column_date_millis(
        std::string_view name,
        const int64_t* data,
        size_t row_count,
        const validity_view* validity = nullptr)
    {
        line_sender_error::wrapped_call(
            ::column_sender_chunk_column_date_millis,
            _raw,
            name.data(),
            name.size(),
            data,
            row_count,
            validity ? validity->c_ptr() : nullptr);
        return *this;
    }

    /**
     * VARCHAR from Arrow Utf8 layout. `offsets` has `row_count + 1`
     * entries; `bytes` is the concatenated UTF-8 buffer.
     */
    column_chunk& column_varchar(
        std::string_view name,
        const int32_t* offsets,
        const uint8_t* bytes,
        size_t bytes_len,
        size_t row_count,
        const validity_view* validity = nullptr)
    {
        line_sender_error::wrapped_call(
            ::column_sender_chunk_column_varchar,
            _raw,
            name.data(),
            name.size(),
            offsets,
            bytes,
            bytes_len,
            row_count,
            validity ? validity->c_ptr() : nullptr);
        return *this;
    }

    /**
     * BINARY from Arrow Binary layout. Same offsets/bytes layout as
     * VARCHAR; no UTF-8 validation.
     */
    column_chunk& column_binary(
        std::string_view name,
        const int32_t* offsets,
        const uint8_t* bytes,
        size_t bytes_len,
        size_t row_count,
        const validity_view* validity = nullptr)
    {
        line_sender_error::wrapped_call(
            ::column_sender_chunk_column_binary,
            _raw,
            name.data(),
            name.size(),
            offsets,
            bytes,
            bytes_len,
            row_count,
            validity ? validity->c_ptr() : nullptr);
        return *this;
    }

    // -- Symbol-dict appenders ----------------------------------------

    column_chunk& symbol_dict_i8(
        std::string_view name,
        const int8_t* codes,
        size_t codes_len,
        const int32_t* dict_offsets,
        size_t dict_offsets_len,
        const uint8_t* dict_bytes,
        size_t dict_bytes_len,
        const validity_view* validity = nullptr)
    {
        line_sender_error::wrapped_call(
            ::column_sender_chunk_symbol_dict_i8,
            _raw,
            name.data(),
            name.size(),
            codes,
            codes_len,
            dict_offsets,
            dict_offsets_len,
            dict_bytes,
            dict_bytes_len,
            validity ? validity->c_ptr() : nullptr);
        return *this;
    }

    column_chunk& symbol_dict_i16(
        std::string_view name,
        const int16_t* codes,
        size_t codes_len,
        const int32_t* dict_offsets,
        size_t dict_offsets_len,
        const uint8_t* dict_bytes,
        size_t dict_bytes_len,
        const validity_view* validity = nullptr)
    {
        line_sender_error::wrapped_call(
            ::column_sender_chunk_symbol_dict_i16,
            _raw,
            name.data(),
            name.size(),
            codes,
            codes_len,
            dict_offsets,
            dict_offsets_len,
            dict_bytes,
            dict_bytes_len,
            validity ? validity->c_ptr() : nullptr);
        return *this;
    }

    column_chunk& symbol_dict_i32(
        std::string_view name,
        const int32_t* codes,
        size_t codes_len,
        const int32_t* dict_offsets,
        size_t dict_offsets_len,
        const uint8_t* dict_bytes,
        size_t dict_bytes_len,
        const validity_view* validity = nullptr)
    {
        line_sender_error::wrapped_call(
            ::column_sender_chunk_symbol_dict_i32,
            _raw,
            name.data(),
            name.size(),
            codes,
            codes_len,
            dict_offsets,
            dict_offsets_len,
            dict_bytes,
            dict_bytes_len,
            validity ? validity->c_ptr() : nullptr);
        return *this;
    }

    // -- Designated timestamp -----------------------------------------

    column_chunk& designated_timestamp_micros(
        const int64_t* data, size_t row_count)
    {
        line_sender_error::wrapped_call(
            ::column_sender_chunk_designated_timestamp_micros,
            _raw,
            data,
            row_count);
        return *this;
    }

    column_chunk& designated_timestamp_nanos(
        const int64_t* data, size_t row_count)
    {
        line_sender_error::wrapped_call(
            ::column_sender_chunk_designated_timestamp_nanos,
            _raw,
            data,
            row_count);
        return *this;
    }

#ifdef QUESTDB_CLIENT_ENABLE_ARROW
    /**
     * Append a slice of one column from an Arrow C Data Interface array.
     * On success, `array.release` is consumed (set to NULL); on failure
     * it may also have been consumed — check before invoking.
     * `schema` is borrowed.
     */
    column_chunk& append_arrow_column(
        std::string_view name,
        ::ArrowArray& array,
        const ::ArrowSchema& schema,
        size_t row_offset,
        size_t row_count)
    {
        line_sender_error::wrapped_call(
            ::column_sender_chunk_append_arrow_column,
            _raw,
            name.data(),
            name.size(),
            &array,
            &schema,
            row_offset,
            row_count);
        return *this;
    }

    /**
     * Append a slice of a previously-imported Arrow column. The
     * `arrow_import` wrapper must outlive the next
     * `column_sender_conn::flush`.
     */
    column_chunk& append_arrow_import(
        std::string_view name,
        const class arrow_import& imported,
        size_t row_offset,
        size_t row_count);
#endif

private:
    ::column_sender_chunk* _raw{nullptr};
};

#ifdef QUESTDB_CLIENT_ENABLE_ARROW
/**
 * RAII wrapper around `::column_sender_arrow_import*`. Move-only.
 *
 * Lets a caller import an `ArrowArray` + `ArrowSchema` pair once and
 * then slice/append it across many chunks (e.g. paginating a large
 * DataFrame) without re-paying the import cost per chunk. On
 * construction the array's buffers transfer into this wrapper —
 * `array.release` is cleared on success, and may also be cleared on
 * failure (check before invoking it on the error path). `schema` is
 * borrowed only for the duration of the constructor.
 *
 * `override_kind` reclassifies the column like the batch path's
 * `column_sender_arrow_override`: `-1` applies no override; otherwise it
 * is a `::column_sender_arrow_override_kind` value. `override_arg` is the
 * kind's argument — for `symbol`, `0` marks it SYMBOL and non-zero forces
 * VARCHAR; for `geohash`, the precision bits (`1..=60`); ignored by
 * `ipv4`/`char`.
 *
 * Not thread-safe. Bound to the importing thread until destroyed. MUST
 * outlive every `column_sender_conn::flush` that referenced it through
 * `column_chunk::append_arrow_import`.
 */
class arrow_import
{
public:
    arrow_import(
        ::ArrowArray& array,
        const ::ArrowSchema& schema,
        int32_t override_kind = -1,
        uint32_t override_arg = 0)
    {
        _raw = line_sender_error::wrapped_call(
            ::column_sender_arrow_import_new,
            &array,
            &schema,
            override_kind,
            override_arg);
    }

    arrow_import(const arrow_import&) = delete;
    arrow_import& operator=(const arrow_import&) = delete;

    arrow_import(arrow_import&& other) noexcept
        : _raw{other._raw}
    {
        other._raw = nullptr;
    }

    arrow_import& operator=(arrow_import&& other) noexcept
    {
        if (this != &other)
        {
            if (_raw)
                ::column_sender_arrow_import_free(_raw);
            _raw = other._raw;
            other._raw = nullptr;
        }
        return *this;
    }

    ~arrow_import() noexcept
    {
        if (_raw)
            ::column_sender_arrow_import_free(_raw);
    }

    /** Number of rows in the imported column. */
    size_t len() const noexcept
    {
        return ::column_sender_arrow_import_len(_raw);
    }

    ::column_sender_arrow_import* c_ptr() noexcept { return _raw; }
    const ::column_sender_arrow_import* c_ptr() const noexcept { return _raw; }

private:
    ::column_sender_arrow_import* _raw{nullptr};
};

inline column_chunk& column_chunk::append_arrow_import(
    std::string_view name,
    const arrow_import& imported,
    size_t row_offset,
    size_t row_count)
{
    line_sender_error::wrapped_call(
        ::column_sender_chunk_append_arrow_import,
        _raw,
        name.data(),
        name.size(),
        imported.c_ptr(),
        row_offset,
        row_count);
    return *this;
}
#endif

/**
 * Borrowed `::qwpws_conn*` wrapper exposing flush / sync / Arrow-batch
 * ingest. Owned by `borrowed_conn`; do not construct directly.
 */
class column_sender_conn
{
public:
    explicit column_sender_conn(::qwpws_conn* raw) noexcept
        : _raw{raw}
    {
    }

    ::qwpws_conn* c_ptr() noexcept { return _raw; }
    const ::qwpws_conn* c_ptr() const noexcept { return _raw; }

    /**
     * `true` if the conn has latched into terminal must-close. Pool
     * return will drop the slot instead of recycling.
     */
    bool must_close() const noexcept
    {
        return ::qwpws_conn_must_close(_raw);
    }

    /**
     * Encode `chunk` as one QWP/WS frame and publish it. On success
     * `chunk` is cleared; on failure it is left untouched. Throws on
     * error.
     */
    void flush(column_chunk& chunk)
    {
        line_sender_error::wrapped_call(
            ::column_sender_flush, _raw, chunk.c_ptr());
    }

    /**
     * Send a commit-triggering frame and wait for in-flight acks at
     * the requested level. Throws on error.
     */
    void sync(column_sender_ack_level level = column_sender_ack_level::ok)
    {
        line_sender_error::wrapped_call(
            ::column_sender_sync,
            _raw,
            static_cast<uint32_t>(level));
    }

#ifdef QUESTDB_CLIENT_ENABLE_ARROW
    /**
     * Encode an Arrow RecordBatch as one QWP/WS frame for `table` and
     * publish it through the borrowed connection in one pass. The
     * per-row designated timestamp is omitted; the server stamps each
     * row on arrival.
     *
     * Ownership: on success `array.release` is consumed (set to NULL);
     * on failure it may also have been consumed — check before
     * invoking. `schema` is borrowed.
     */
    void flush_arrow_batch(
        table_name_view table,
        ::ArrowArray& array,
        const ::ArrowSchema& schema,
        const ::column_sender_arrow_override* overrides = nullptr,
        size_t overrides_len = 0)
    {
        ::line_sender_table_name table_c{table.size(), table.data()};
        line_sender_error::wrapped_call(
            ::column_sender_flush_arrow_batch,
            _raw,
            table_c,
            &array,
            &schema,
            overrides,
            overrides_len);
    }

    /**
     * Variant of `flush_arrow_batch` that sources the per-row
     * designated timestamp from a named `Timestamp(_)` column inside
     * the batch.
     */
    void flush_arrow_batch(
        table_name_view table,
        ::ArrowArray& array,
        const ::ArrowSchema& schema,
        column_name_view ts_column,
        const ::column_sender_arrow_override* overrides = nullptr,
        size_t overrides_len = 0)
    {
        ::line_sender_table_name table_c{table.size(), table.data()};
        ::line_sender_column_name ts_c{ts_column.size(), ts_column.data()};
        line_sender_error::wrapped_call(
            ::column_sender_flush_arrow_batch_at_column,
            _raw,
            table_c,
            &array,
            &schema,
            ts_c,
            overrides,
            overrides_len);
    }
#endif

private:
    ::qwpws_conn* _raw;
};

/** Forward decl. */
class pool;

/**
 * RAII guard for a borrowed connection. On destruction the conn is
 * returned to the pool (or dropped if it has latched must-close).
 *
 * Constructed only via `pool::borrow_conn()`.
 */
class borrowed_conn
{
public:
    borrowed_conn(const borrowed_conn&) = delete;
    borrowed_conn& operator=(const borrowed_conn&) = delete;

    borrowed_conn(borrowed_conn&& other) noexcept
        : _db{other._db}
        , _conn{std::move(other._conn)}
        , _force_drop{other._force_drop}
    {
        other._db = nullptr;
        other._force_drop = false;
    }

    borrowed_conn& operator=(borrowed_conn&& other) noexcept
    {
        if (this != &other)
        {
            release();
            _db = other._db;
            _conn = std::move(other._conn);
            _force_drop = other._force_drop;
            other._db = nullptr;
            other._force_drop = false;
        }
        return *this;
    }

    ~borrowed_conn() noexcept { release(); }

    column_sender_conn* operator->() noexcept { return &_conn; }
    const column_sender_conn* operator->() const noexcept { return &_conn; }
    column_sender_conn& operator*() noexcept { return _conn; }
    const column_sender_conn& operator*() const noexcept { return _conn; }

    /**
     * Force the conn to drop on return instead of recycling. Use when
     * the conn holds in-flight uncommitted frames that the next
     * borrower would otherwise commit alongside their own.
     */
    void drop_on_return() noexcept { _force_drop = true; }

private:
    friend class pool;

    borrowed_conn(::questdb_db* db, ::qwpws_conn* raw) noexcept
        : _db{db}
        , _conn{raw}
    {
    }

    void release() noexcept
    {
        ::qwpws_conn* raw = _conn.c_ptr();
        if (_db && raw)
        {
            if (_force_drop || ::qwpws_conn_must_close(raw))
                ::questdb_db_drop_conn(_db, raw);
            else
                ::questdb_db_return_conn(_db, raw);
        }
        _db = nullptr;
    }

    ::questdb_db* _db;
    column_sender_conn _conn;
    bool _force_drop{false};
};

/**
 * RAII wrapper around `::questdb_db*` — the QWP/WS connection pool.
 *
 * `conf` is a `qwpws::` / `qwpwss::` connect string; see
 * `column_sender.h` for pool-specific keys (`pool_size`, `pool_max`,
 * `pool_idle_timeout_ms`, `pool_reap`).
 */
class pool
{
public:
    explicit pool(std::string_view conf)
    {
        _raw = line_sender_error::wrapped_call(
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

    /** Borrow a conn. Throws on cap exhaustion or transport failure. */
    borrowed_conn borrow_conn()
    {
        auto* raw = line_sender_error::wrapped_call(
            ::questdb_db_borrow_conn, _raw);
        return borrowed_conn{_raw, raw};
    }

    /** Close + drop idle conns beyond `pool_size`. Returns count closed. */
    size_t reap_idle() noexcept
    {
        return ::questdb_db_reap_idle(_raw);
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

} // namespace questdb::ingress
