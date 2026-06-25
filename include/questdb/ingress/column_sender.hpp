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

// Forward declaration so the unified `pool` can hand out query readers via
// `pool::borrow_reader()`, mirroring the Rust `QuestDb::borrow_reader`. The
// method is DEFINED out-of-line in `questdb/egress/reader.hpp` so the
// heavy egress header stays off the sender-only include path; include that
// header to call it.
namespace questdb::egress
{
class reader;
}

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
    /**
     * Build a chunk targeting `table`.
     *
     * Name validation timing: the table name grammar AND the 127-byte
     * length cap are both deferred to flush (mirrors
     * `::column_sender_chunk_new`). If you already hold a pre-validated
     * `table_name_view` — e.g. to share it with `flush_arrow_batch`,
     * which requires that type — prefer `from_validated`, which reports
     * grammar errors eagerly at `table_name_view` construction (the same
     * type/timing as the Arrow flush entrypoints).
     */
    explicit column_chunk(std::string_view table)
    {
        _raw = line_sender_error::wrapped_call(
            ::column_sender_chunk_new, table.data(), table.size());
    }

    /**
     * Build a chunk from a pre-validated `table_name_view`.
     *
     * Typed, eager-grammar-validation counterpart to the
     * `std::string_view` constructor: the name grammar was validated when
     * the `table_name_view` was constructed (same type and timing as
     * `flush_arrow_batch`), while the 127-byte length cap is still applied
     * at flush. Prefer this when you already hold a validated table name
     * and want to share it between the chunk and Arrow paths. Exposed as a
     * named factory rather than a constructor overload to avoid ambiguity
     * with the `std::string_view` constructor on string literals.
     */
    static column_chunk from_validated(table_name_view table)
    {
        ::line_sender_table_name table_c{table.size(), table.data()};
        column_chunk chunk;
        chunk._raw = line_sender_error::wrapped_call(
            ::column_sender_chunk_new_validated, table_c);
        return chunk;
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
        size_t row_count,
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
            row_count,
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
        size_t row_count,
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
            row_count,
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
        size_t row_count,
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
            row_count,
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

    column_chunk& designated_timestamp_millis(
        const int64_t* data, size_t row_count)
    {
        line_sender_error::wrapped_call(
            ::column_sender_chunk_designated_timestamp_millis,
            _raw,
            data,
            row_count);
        return *this;
    }

    column_chunk& designated_timestamp_seconds(
        const int64_t* data, size_t row_count)
    {
        line_sender_error::wrapped_call(
            ::column_sender_chunk_designated_timestamp_seconds,
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
    /// Leaves `_raw` null; used by `from_validated` before it installs the
    /// freshly-constructed handle.
    column_chunk() = default;

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
 * `symbol_mode` selects the SYMBOL-vs-VARCHAR disposition of a string
 * column (see `column_sender_symbol_mode`); a no-op for non-string columns.
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
        ::column_sender_symbol_mode symbol_mode =
            ::column_sender_symbol_mode_auto)
    {
        _raw = line_sender_error::wrapped_call(
            ::column_sender_arrow_import_new,
            &array,
            &schema,
            symbol_mode);
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
 * Borrowed `::column_sender*` wrapper exposing flush / sync / Arrow-batch
 * ingest. Owned by `borrowed_column_sender`; do not construct directly.
 */
class column_sender_conn
{
public:
    explicit column_sender_conn(::column_sender* raw) noexcept
        : _raw{raw}
    {
    }

    ::column_sender* c_ptr() noexcept { return _raw; }
    const ::column_sender* c_ptr() const noexcept { return _raw; }

    /**
     * `true` if the conn has latched into terminal must-close, or if the
     * pool has been closed. Pool return will drop the slot instead of
     * recycling.
     */
    bool must_close() const noexcept
    {
        return ::column_sender_must_close(_raw);
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
     * Wait for in-flight frames at the requested level. In direct mode this
     * sends the commit-triggering frame first. In store-and-forward mode,
     * frames are already non-deferred, so this waits for the published local
     * queue boundary. Throws on error.
     *
     * Bounded by `request_timeout` (default 30s): if the server stays
     * connected but never advances the ack/durable watermark for that long
     * (back-pressured WAL / stuck commit) this throws `failover_retry`. The
     * deadline resets on every watermark advance, so a slow-but-progressing
     * sync is not cut off. The unacked frames are retained for replay.
     */
    void sync(column_sender_ack_level level = column_sender_ack_level::ok)
    {
        line_sender_error::wrapped_call(
            ::column_sender_sync,
            _raw,
            static_cast<uint32_t>(level));
    }

    /**
     * Publish `chunk` as a completion boundary, then wait until every frame
     * published before or by this call reaches `level` (see `sync`). The
     * boundary is cumulative: success acknowledges all prior `flush`es plus
     * this one; an empty `chunk` behaves like `sync`.
     *
     * `level` has no default (unlike `sync`) so the blocking behaviour stays
     * explicit at every call site. `column_sender_ack_level::durable` requires
     * `request_durable_ack=on`. Throws on error. Once the frame is published
     * `chunk` is cleared even if the ACK wait then fails — delivery of that
     * frame is then unknown; drop and re-borrow per the error.
     */
    void flush_and_wait(column_chunk& chunk, column_sender_ack_level level)
    {
        line_sender_error::wrapped_call(
            ::column_sender_flush_and_wait,
            _raw,
            chunk.c_ptr(),
            static_cast<uint32_t>(level));
    }

#ifdef QUESTDB_CLIENT_ENABLE_ARROW
    /**
     * Encode an Arrow RecordBatch as one QWP/WS frame for `table` and
     * publish it through the borrowed connection in one pass, **without**
     * a per-row designated timestamp: the server stamps each row on
     * arrival.
     *
     * This is an explicit opt-in. If your batch carries a real
     * event-time column, use the `ts_column` overload of
     * `flush_arrow_batch` instead — reaching for this entry point would
     * discard that column's role as the designated timestamp and
     * silently substitute server arrival time, producing wrong
     * partitions/order.
     *
     * Ownership: on success `array.release` is consumed (set to NULL);
     * on failure it may also have been consumed — check before
     * invoking. `schema` is borrowed.
     */
    void flush_arrow_batch_server_stamped(
        table_name_view table,
        ::ArrowArray& array,
        const ::ArrowSchema& schema,
        const ::column_sender_arrow_override* overrides = nullptr,
        size_t overrides_len = 0)
    {
        ::line_sender_table_name table_c{table.size(), table.data()};
        line_sender_error::wrapped_call(
            ::column_sender_flush_arrow_batch_server_stamped,
            _raw,
            table_c,
            &array,
            &schema,
            overrides,
            overrides_len);
    }

    /**
     * ACKing counterpart of `flush_arrow_batch_server_stamped`: publish
     * `array` as a boundary, then wait for `level`. `level` is validated
     * before the Arrow import consumes `array.release`. On a pre-publication
     * failure `array` is re-exported for retry; on a post-publication failure
     * (delivery unknown) it is not — check `array.release` before invoking it.
     * `level` is positioned before the optional `overrides` (which keep their
     * defaults) and has no default of its own. Throws on error.
     */
    void flush_arrow_batch_server_stamped_and_wait(
        table_name_view table,
        ::ArrowArray& array,
        const ::ArrowSchema& schema,
        column_sender_ack_level level,
        const ::column_sender_arrow_override* overrides = nullptr,
        size_t overrides_len = 0)
    {
        ::line_sender_table_name table_c{table.size(), table.data()};
        line_sender_error::wrapped_call(
            ::column_sender_flush_arrow_batch_server_stamped_and_wait,
            _raw,
            table_c,
            &array,
            &schema,
            overrides,
            overrides_len,
            static_cast<uint32_t>(level));
    }

    /**
     * Variant of `flush_arrow_batch_server_stamped` that sources the
     * per-row designated timestamp from a named `Timestamp(_)` column
     * inside the batch.
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

    /**
     * ACKing counterpart of the `ts_column` `flush_arrow_batch`: publish
     * `array` (timestamp sourced from `ts_column`) as a boundary, then wait
     * for `level`. Same preflight/re-export contract as
     * `flush_arrow_batch_server_stamped_and_wait`: on a post-publication
     * failure `array` is not re-exported. Callers MUST check
     * `array.release != nullptr` before invoking it on failure. Throws on error.
     */
    void flush_arrow_batch_and_wait(
        table_name_view table,
        ::ArrowArray& array,
        const ::ArrowSchema& schema,
        column_name_view ts_column,
        column_sender_ack_level level,
        const ::column_sender_arrow_override* overrides = nullptr,
        size_t overrides_len = 0)
    {
        ::line_sender_table_name table_c{table.size(), table.data()};
        ::line_sender_column_name ts_c{ts_column.size(), ts_column.data()};
        line_sender_error::wrapped_call(
            ::column_sender_flush_arrow_batch_at_column_and_wait,
            _raw,
            table_c,
            &array,
            &schema,
            ts_c,
            overrides,
            overrides_len,
            static_cast<uint32_t>(level));
    }
#endif

private:
    ::column_sender* _raw;
};

/** Forward decl. */
class pool;

/**
 * RAII guard for a borrowed connection. On destruction the conn is
 * returned to the pool (or dropped if it has latched must-close, or if the
 * pool has been closed).
 *
 * Constructed only via `pool::borrow_column_sender()`.
 *
 * @warning The destructor returns/drops the conn but does NOT sync. If the
 * conn has flushed but not yet synced, destruction silently discards every
 * deferred (non-first) flush since the last sync — in direct mode those
 * source chunks were already cleared, so the data is unrecoverable. Call
 * `sync()` (or `flush_and_wait()` on the final chunk) before this guard goes
 * out of scope. The destructor is deliberately left non-syncing: a
 * destructor must not throw or block, so an automatic sync is not safe.
 */
class borrowed_column_sender
{
public:
    borrowed_column_sender(const borrowed_column_sender&) = delete;
    borrowed_column_sender& operator=(const borrowed_column_sender&) = delete;

    borrowed_column_sender(borrowed_column_sender&& other) noexcept
        : _db{other._db}
        , _conn{std::move(other._conn)}
        , _force_drop{other._force_drop}
    {
        other._db = nullptr;
        other._force_drop = false;
    }

    borrowed_column_sender& operator=(borrowed_column_sender&& other) noexcept
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

    ~borrowed_column_sender() noexcept { release(); }

    column_sender_conn* operator->() noexcept { return &_conn; }
    const column_sender_conn* operator->() const noexcept { return &_conn; }
    column_sender_conn& operator*() noexcept { return _conn; }
    const column_sender_conn& operator*() const noexcept { return _conn; }

    /**
     * Force the conn to drop on return instead of recycling. Use when
     * the conn holds in-flight uncommitted frames that the next
     * borrower would otherwise commit alongside their own. In
     * store-and-forward mode unresolved frames remain in the SFA slot for
     * replay by the next owner.
     */
    void drop_on_return() noexcept { _force_drop = true; }

private:
    friend class pool;

    borrowed_column_sender(::questdb_db* db, ::column_sender* raw) noexcept
        : _db{db}
        , _conn{raw}
    {
    }

    void release() noexcept
    {
        ::column_sender* raw = _conn.c_ptr();
        if (_db && raw)
        {
            if (_force_drop || ::column_sender_must_close(raw))
                ::questdb_db_drop_column_sender(_db, raw);
            else
                ::questdb_db_return_column_sender(_db, raw);
        }
        _db = nullptr;
    }

    ::questdb_db* _db;
    column_sender_conn _conn;
    bool _force_drop{false};
};

/**
 * RAII guard for a borrowed row-major sender. On destruction the sender is
 * returned to the pool (or dropped if `drop_on_return()` was called, or a
 * flush left it must-close, or the pool has been closed). Build rows with a
 * `questdb::ingress::line_sender_buffer` and send them via `flush()` /
 * `flush_and_keep()`.
 *
 * Constructed only via `pool::borrow_row_sender()`.
 */
class borrowed_row_sender
{
public:
    borrowed_row_sender(const borrowed_row_sender&) = delete;
    borrowed_row_sender& operator=(const borrowed_row_sender&) = delete;

    borrowed_row_sender(borrowed_row_sender&& other) noexcept
        : _db{other._db}
        , _sender{other._sender}
        , _force_drop{other._force_drop}
    {
        other._db = nullptr;
        other._sender = nullptr;
        other._force_drop = false;
    }

    borrowed_row_sender& operator=(borrowed_row_sender&& other) noexcept
    {
        if (this != &other)
        {
            release();
            _db = other._db;
            _sender = other._sender;
            _force_drop = other._force_drop;
            other._db = nullptr;
            other._sender = nullptr;
            other._force_drop = false;
        }
        return *this;
    }

    ~borrowed_row_sender() noexcept { release(); }

    /**
     * Send the buffer of rows to QuestDB, then clear the buffer.
     * @throws line_sender_error on failure.
     */
    void flush(line_sender_buffer& buffer)
    {
        buffer.may_init();
        line_sender_error::wrapped_call(
            ::row_sender_flush, _sender, buffer._impl);
    }

    /**
     * Send the buffer of rows to QuestDB, keeping the buffer intact (clear
     * it before starting a new batch). A never-initialised (empty) buffer
     * is a no-op.
     * @throws line_sender_error on failure.
     */
    void flush_and_keep(const line_sender_buffer& buffer)
    {
        if (buffer._impl)
            line_sender_error::wrapped_call(
                ::row_sender_flush_and_keep, _sender, buffer._impl);
    }

    /**
     * `true` if this sender will be dropped rather than recycled on return
     * (force-marked, a flush left the connection unusable, or the pool has
     * been closed).
     */
    bool must_close() const noexcept
    {
        return _sender && ::row_sender_must_close(_sender);
    }

    /** Force the sender to drop on return instead of recycling. */
    void drop_on_return() noexcept { _force_drop = true; }

    ::row_sender* c_ptr() noexcept { return _sender; }
    const ::row_sender* c_ptr() const noexcept { return _sender; }

private:
    friend class pool;

    borrowed_row_sender(::questdb_db* db, ::row_sender* raw) noexcept
        : _db{db}
        , _sender{raw}
    {
    }

    void release() noexcept
    {
        if (_db && _sender)
        {
            if (_force_drop || ::row_sender_must_close(_sender))
                ::questdb_db_drop_row_sender(_db, _sender);
            else
                ::questdb_db_return_row_sender(_db, _sender);
        }
        _db = nullptr;
        _sender = nullptr;
    }

    ::questdb_db* _db;
    ::row_sender* _sender;
    bool _force_drop{false};
};

/**
 * RAII wrapper around `::questdb_db*` — the QWP/WS connection pool.
 *
 * `conf` is a `qwpws::` / `qwpwss::` connect string; see
 * `column_sender.h` for pool-specific keys (`pool_size`, `pool_max`,
 * `pool_idle_timeout_ms`, `pool_reap`).
 *
 * Borrow/return operations are thread-safe while this owner remains alive.
 * Destruction is the final owner release: do not destroy the pool while
 * another thread may still call methods on this object. Borrowed guards that
 * outlive the pool remain safe to destroy; after pool close they are dropped
 * instead of recycled, and new operations on them fail.
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
    borrowed_column_sender borrow_column_sender()
    {
        auto* raw = line_sender_error::wrapped_call(
            ::questdb_db_borrow_column_sender, _raw);
        return borrowed_column_sender{_raw, raw};
    }

    /**
     * Borrow a conn, retrying the connect within `budget_ms` using the row
     * sender's reconnect backoff. On a transient `failover_retry`, drop the
     * dead conn then call this with `reconnect_max_duration_ms()` (or your
     * tracked remaining budget). Throws on a terminal error or budget
     * exhaustion.
     */
    borrowed_column_sender borrow_column_sender_with_retry(uint64_t budget_ms)
    {
        auto* raw = line_sender_error::wrapped_call(
            ::questdb_db_borrow_column_sender_with_retry, _raw, budget_ms);
        return borrowed_column_sender{_raw, raw};
    }

    /**
     * Borrow a row-major sender from the pool, mirroring Rust
     * `QuestDb::borrow_row_sender`. Row senders are pooled on a separate,
     * independently-capped free list that shares the pool budget; the pool
     * is lazy (a connection opens on first borrow). Build rows with a
     * `line_sender_buffer` and flush them through the returned guard. Throws
     * on cap exhaustion or transport failure.
     */
    borrowed_row_sender borrow_row_sender()
    {
        auto* raw = line_sender_error::wrapped_call(
            ::questdb_db_borrow_row_sender, _raw);
        return borrowed_row_sender{_raw, raw};
    }

    /**
     * Borrow a row-major sender, retrying the connect within `budget_ms`
     * using the pool's reconnect backoff. Throws on a terminal error or
     * budget exhaustion.
     */
    borrowed_row_sender borrow_row_sender_with_retry(uint64_t budget_ms)
    {
        auto* raw = line_sender_error::wrapped_call(
            ::questdb_db_borrow_row_sender_with_retry, _raw, budget_ms);
        return borrowed_row_sender{_raw, raw};
    }

    /**
     * Borrow a query reader from the pool, mirroring Rust
     * `QuestDb::borrow_reader`. Readers are pooled on a separate,
     * independently-capped free list that shares the `pool_size` /
     * `pool_max` / `pool_idle_timeout_ms` budget; the pool is lazy (a
     * connection opens on first borrow). The returned `reader` is
     * equivalent to a standalone one and returns itself to the pool on
     * destruction — unless `reader::mark_must_close()` was called, in which
     * case it is dropped. If the pool has already been closed by the time the
     * reader is destroyed, it is closed instead of recycled. Throws
     * `reader_error` on cap exhaustion or transport failure.
     *
     * DEFINED in `questdb/egress/reader.hpp` (the reader-pool entry
     * points live alongside the `reader` type, matching the C headers).
     * Include that header to call this.
     */
    ::questdb::egress::reader borrow_reader();

    /** The pool's failover budget (`reconnect_max_duration`) in milliseconds. */
    uint64_t reconnect_max_duration_ms() const noexcept
    {
        return ::questdb_db_reconnect_max_duration_ms(_raw);
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

namespace questdb
{
// `questdb::pool` is the canonical, top-level spelling of the connection
// pool. The pool is cross-cutting — it hands out write-side senders
// (`borrow_column_sender`) and read-side query readers (`borrow_reader`) — so it
// belongs at the top-level `questdb` namespace rather than under `ingress`.
// This re-export is the C++ analogue of the Rust `questdb::QuestDb`
// re-export; `questdb::ingress::pool` remains valid for back-compat.
using ingress::pool;
} // namespace questdb
