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

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
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
class sender_view;

/**
 * RAII wrapper around `::column_sender_chunk*`. Move-only.
 *
 * Holds raw-pointer descriptors into caller buffers; the caller MUST
 * keep every column buffer alive from the per-column append call until
 * the next `flush` returns.
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

    column_chunk& column_ts(
        std::string_view name,
        const int64_t* data,
        size_t row_count,
        ::column_sender_ts_unit unit,
        const validity_view* validity = nullptr)
    {
        line_sender_error::wrapped_call(
            ::column_sender_chunk_column_ts,
            _raw,
            name.data(),
            name.size(),
            data,
            row_count,
            static_cast<uint32_t>(unit),
            validity ? validity->c_ptr() : nullptr);
        return *this;
    }

    column_chunk& column_date(
        std::string_view name,
        const int64_t* data,
        size_t row_count,
        const validity_view* validity = nullptr)
    {
        line_sender_error::wrapped_call(
            ::column_sender_chunk_column_date,
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
    column_chunk& column_str(
        std::string_view name,
        const int32_t* offsets,
        const uint8_t* bytes,
        size_t bytes_len,
        size_t row_count,
        const validity_view* validity = nullptr)
    {
        line_sender_error::wrapped_call(
            ::column_sender_chunk_column_str,
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

    /**
     * SYMBOL via the dictionary fast path. `codes[i]` is the per-row
     * dictionary index (in `0 .. dict_offsets_len - 1`) for non-null rows;
     * `dict_offsets` (length `dict_offsets_len`, Arrow `Utf8` layout) and
     * `dict_bytes` (length `dict_bytes_len`) describe the dictionary. Only
     * referenced entries are interned into the connection symbol table, so a
     * wide dictionary (e.g. a Pandas `Categorical`) costs nothing for unused
     * entries. Each entry must be valid UTF-8 (validated eagerly here) and
     * every non-null code must be in range (checked here); the borrowed
     * buffers must stay alive and unchanged until the next `flush()` /
     * `wait()` returns. See `column_sender.h` for the full contract and caps.
     */
    column_chunk& symbol_i8(
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
            ::column_sender_chunk_symbol_i8,
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

    /** Same as `symbol_i8`, for `int16_t` dictionary codes. */
    column_chunk& symbol_i16(
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
            ::column_sender_chunk_symbol_i16,
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

    /** Same as `symbol_i8`, for `int32_t` dictionary codes. */
    column_chunk& symbol_i32(
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
            ::column_sender_chunk_symbol_i32,
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

    column_chunk& at_micros(
        const int64_t* data, size_t row_count)
    {
        line_sender_error::wrapped_call(
            ::column_sender_chunk_at_micros,
            _raw,
            data,
            row_count);
        return *this;
    }

    column_chunk& at_nanos(
        const int64_t* data, size_t row_count)
    {
        line_sender_error::wrapped_call(
            ::column_sender_chunk_at_nanos,
            _raw,
            data,
            row_count);
        return *this;
    }

    column_chunk& at_millis(
        const int64_t* data, size_t row_count)
    {
        line_sender_error::wrapped_call(
            ::column_sender_chunk_at_millis,
            _raw,
            data,
            row_count);
        return *this;
    }

    column_chunk& at_seconds(
        const int64_t* data, size_t row_count)
    {
        line_sender_error::wrapped_call(
            ::column_sender_chunk_at_seconds,
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
     * `flush`.
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
 * outlive every `flush` that referenced it through
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
 * Thin non-owning view over a borrowed `::qwp_sender*`: publish-only
 * `flush`, FSN-returning publish/progress helpers, the `wait` ack barrier, and
 * Arrow-batch ingest. The store-and-forward queue owns delivery. Use this
 * directly when adapting a raw C-borrowed handle; `borrowed_sender`
 * keeps the same view private so pooled leases cannot escape the guard.
 */
class sender_view
{
public:
    explicit sender_view(::qwp_sender* raw) noexcept
        : _raw{raw}
    {
    }

    /**
     * Encode `chunk` and publish it into the store-and-forward queue, returning
     * as soon as it is accepted locally. On success `chunk` is cleared; on
     * failure it is left untouched. Call `wait()` to block for the server ack.
     * Throws on error.
     */
    void flush(column_chunk& chunk)
    {
        line_sender_error::wrapped_call(
            ::qwp_sender_flush_chunk, _raw, chunk.c_ptr());
    }

    /**
     * Publish `chunk` as a completion boundary, then wait until it and all prior
     * frames published through this sender reach `level`. Uses the pool-wide
     * `request_timeout` as the wait's no-progress deadline. Throws on error.
     */
    void flush_and_wait(
        column_chunk& chunk,
        qwpws_ack_level level = qwpws_ack_level::ok)
    {
        line_sender_error::wrapped_call(
            ::qwp_sender_flush_chunk_and_wait,
            _raw,
            chunk.c_ptr(),
            static_cast<uint32_t>(level));
    }

    /**
     * Publish `chunk` locally and return the assigned frame sequence number.
     * If the chunk is split into multiple frames, the returned FSN is the last
     * frame boundary.
     */
    std::optional<uint64_t> flush_and_get_fsn(column_chunk& chunk)
    {
        ::line_sender_qwpws_fsn fsn{};
        line_sender_error::wrapped_call(
            ::qwp_sender_flush_chunk_and_get_fsn,
            _raw,
            chunk.c_ptr(),
            &fsn);
        return optional_fsn(fsn);
    }

    /**
     * Return the highest QWP/WebSocket frame sequence number published locally,
     * or `std::nullopt` if no frame has been published.
     */
    std::optional<uint64_t> published_fsn() const
    {
        ::line_sender_qwpws_fsn fsn{};
        line_sender_error::wrapped_call(
            ::qwp_sender_published_fsn, _raw, &fsn);
        return optional_fsn(fsn);
    }

    /**
     * Return the highest QWP/WebSocket frame sequence number completed by ACK,
     * or `std::nullopt` if none has completed.
     */
    std::optional<uint64_t> acked_fsn() const
    {
        ::line_sender_qwpws_fsn fsn{};
        line_sender_error::wrapped_call(
            ::qwp_sender_acked_fsn, _raw, &fsn);
        return optional_fsn(fsn);
    }

    /**
     * Block until every frame published on this sender so far reaches `level`.
     * The SFA queue owns delivery, so this is needed only to *observe* the ack,
     * never for durability. `timeout` is a no-progress deadline (it fires only
     * if the ack watermark fails to advance for that long); the default of zero
     * waits indefinitely. Throws on error.
     */
    void wait(
        qwpws_ack_level level = qwpws_ack_level::ok,
        std::chrono::milliseconds timeout = std::chrono::milliseconds::zero())
    {
        if (timeout.count() < 0)
            throw line_sender_error{
                line_sender_error_code::invalid_api_call,
                "QWP/WebSocket wait timeout must not be negative."};
        line_sender_error::wrapped_call(
            ::qwp_sender_wait,
            _raw,
            static_cast<uint32_t>(level),
            static_cast<uint64_t>(timeout.count()));
    }

#ifdef QUESTDB_CLIENT_ENABLE_ARROW
    /**
     * Publish-only Arrow flush (server-stamped) into the queue. Pair with
     * `wait()`. Ownership: on success `array.release` is consumed; on failure
     * it may also have been consumed — check before invoking. `schema` borrowed.
     */
    void flush_arrow_batch_at_now(
        table_name_view table,
        ::ArrowArray& array,
        const ::ArrowSchema& schema,
        const ::column_sender_arrow_override* overrides = nullptr,
        size_t overrides_len = 0)
    {
        ::line_sender_table_name table_c{table.size(), table.data()};
        line_sender_error::wrapped_call(
            ::qwp_sender_flush_arrow_batch_at_now,
            _raw,
            table_c,
            &array,
            &schema,
            overrides,
            overrides_len);
    }

    /**
     * ACKing counterpart of `flush_arrow_batch_at_now`: publish as a boundary,
     * then wait for `level`.
     */
    void flush_arrow_batch_at_now_and_wait(
        table_name_view table,
        ::ArrowArray& array,
        const ::ArrowSchema& schema,
        qwpws_ack_level level = qwpws_ack_level::ok)
    {
        flush_arrow_batch_at_now_and_wait(
            table, array, schema, nullptr, 0, level);
    }

    /**
     * ACKing counterpart of `flush_arrow_batch_at_now`, with per-column
     * overrides.
     */
    void flush_arrow_batch_at_now_and_wait(
        table_name_view table,
        ::ArrowArray& array,
        const ::ArrowSchema& schema,
        const ::column_sender_arrow_override* overrides,
        size_t overrides_len,
        qwpws_ack_level level = qwpws_ack_level::ok)
    {
        ::line_sender_table_name table_c{table.size(), table.data()};
        line_sender_error::wrapped_call(
            ::qwp_sender_flush_arrow_batch_at_now_and_wait,
            _raw,
            table_c,
            &array,
            &schema,
            overrides,
            overrides_len,
            static_cast<uint32_t>(level));
    }

    /**
     * FSN-returning counterpart of `flush_arrow_batch_at_now`.
     */
    std::optional<uint64_t> flush_arrow_batch_at_now_and_get_fsn(
        table_name_view table,
        ::ArrowArray& array,
        const ::ArrowSchema& schema,
        const ::column_sender_arrow_override* overrides = nullptr,
        size_t overrides_len = 0)
    {
        ::line_sender_table_name table_c{table.size(), table.data()};
        ::line_sender_qwpws_fsn fsn{};
        line_sender_error::wrapped_call(
            ::qwp_sender_flush_arrow_batch_at_now_and_get_fsn,
            _raw,
            table_c,
            &array,
            &schema,
            overrides,
            overrides_len,
            &fsn);
        return optional_fsn(fsn);
    }

    /**
     * Publish-only Arrow flush sourcing the designated timestamp from a named
     * `Timestamp(_)` column of the batch. Pair with `wait()`.
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
            ::qwp_sender_flush_arrow_batch_at_column,
            _raw,
            table_c,
            &array,
            &schema,
            ts_c,
            overrides,
            overrides_len);
    }

    /**
     * ACKing counterpart of `flush_arrow_batch`: publish as a boundary, then
     * wait for `level`.
     */
    void flush_arrow_batch_and_wait(
        table_name_view table,
        ::ArrowArray& array,
        const ::ArrowSchema& schema,
        column_name_view ts_column,
        qwpws_ack_level level = qwpws_ack_level::ok)
    {
        flush_arrow_batch_and_wait(
            table, array, schema, ts_column, nullptr, 0, level);
    }

    /**
     * ACKing counterpart of `flush_arrow_batch`, with per-column overrides.
     */
    void flush_arrow_batch_and_wait(
        table_name_view table,
        ::ArrowArray& array,
        const ::ArrowSchema& schema,
        column_name_view ts_column,
        const ::column_sender_arrow_override* overrides,
        size_t overrides_len,
        qwpws_ack_level level = qwpws_ack_level::ok)
    {
        ::line_sender_table_name table_c{table.size(), table.data()};
        ::line_sender_column_name ts_c{ts_column.size(), ts_column.data()};
        line_sender_error::wrapped_call(
            ::qwp_sender_flush_arrow_batch_at_column_and_wait,
            _raw,
            table_c,
            &array,
            &schema,
            ts_c,
            overrides,
            overrides_len,
            static_cast<uint32_t>(level));
    }

    /**
     * FSN-returning counterpart of `flush_arrow_batch`.
     */
    std::optional<uint64_t> flush_arrow_batch_and_get_fsn(
        table_name_view table,
        ::ArrowArray& array,
        const ::ArrowSchema& schema,
        column_name_view ts_column,
        const ::column_sender_arrow_override* overrides = nullptr,
        size_t overrides_len = 0)
    {
        ::line_sender_table_name table_c{table.size(), table.data()};
        ::line_sender_column_name ts_c{ts_column.size(), ts_column.data()};
        ::line_sender_qwpws_fsn fsn{};
        line_sender_error::wrapped_call(
            ::qwp_sender_flush_arrow_batch_at_column_and_get_fsn,
            _raw,
            table_c,
            &array,
            &schema,
            ts_c,
            overrides,
            overrides_len,
            &fsn);
        return optional_fsn(fsn);
    }
#endif

private:
    friend class borrowed_sender;

    ::qwp_sender* c_ptr() noexcept { return _raw; }
    const ::qwp_sender* c_ptr() const noexcept { return _raw; }

    static std::optional<uint64_t> optional_fsn(
        const ::line_sender_qwpws_fsn& fsn)
    {
        if (fsn.has_value)
            return fsn.value;
        return std::nullopt;
    }

    ::qwp_sender* _raw;
};

/**
 * RAII guard for a borrowed store-and-forward QWP sender. On destruction the
 * sender is returned to the pool (or dropped if `drop_on_return()` was called,
 * it has latched terminal state, or the pool has been closed). Constructed only
 * via `pool::borrow_sender()`.
 *
 * The store-and-forward queue owns delivery, so destruction does not lose
 * accepted frames; `wait()` is an ack barrier, not a commit step. The
 * destructor is non-blocking by design. Use `wait()` for a simple barrier over
 * everything published so far; use FSNs for non-blocking progress tracking
 * while you still hold the same borrowed sender.
 */
class borrowed_sender
{
public:
    borrowed_sender(const borrowed_sender&) = delete;
    borrowed_sender& operator=(const borrowed_sender&) = delete;

    borrowed_sender(borrowed_sender&& other) noexcept
        : _db{other._db}
        , _view{std::move(other._view)}
        , _force_drop{other._force_drop}
    {
        other._db = nullptr;
        other._view = sender_view{nullptr};
        other._force_drop = false;
    }

    borrowed_sender& operator=(borrowed_sender&& other) noexcept
    {
        if (this != &other)
        {
            release();
            _db = other._db;
            _view = std::move(other._view);
            _force_drop = other._force_drop;
            other._db = nullptr;
            other._view = sender_view{nullptr};
            other._force_drop = false;
        }
        return *this;
    }

    ~borrowed_sender() noexcept { release(); }

    /** `true` if this guard currently owns a borrowed sender. */
    explicit operator bool() const noexcept
    {
        return _db && _view.c_ptr();
    }

    /** Create a caller-owned QWP/WebSocket buffer using the pool settings. */
    line_sender_buffer new_buffer(size_t init_buf_size = 64 * 1024)
    {
        ::line_sender_error* c_err{nullptr};
        auto* raw = ::questdb_db_new_buffer(_db, &c_err);
        if (!raw)
            throw line_sender_error::from_c(c_err);
        try
        {
            line_sender_error::wrapped_call(
                ::line_sender_buffer_reserve, raw, init_buf_size);
        }
        catch (...)
        {
            ::line_sender_buffer_free(raw);
            throw;
        }
        return line_sender_buffer{
            raw,
            protocol_version::v1,
            init_buf_size,
            ::questdb_db_buffer_max_name_len(_db),
            line_sender_buffer::_backend_kind::qwp_ws};
    }

    /** Publish and clear a Buffer after local queue acceptance. */
    void flush(line_sender_buffer& buffer)
    {
        buffer.may_init();
        line_sender_error::wrapped_call(
            ::qwp_sender_flush_buffer, _view.c_ptr(), buffer._impl);
    }

    /** Publish and clear a Buffer, then wait for `level`. */
    void flush_and_wait(
        line_sender_buffer& buffer,
        qwpws_ack_level level = qwpws_ack_level::ok)
    {
        buffer.may_init();
        line_sender_error::wrapped_call(
            ::qwp_sender_flush_buffer_and_wait,
            _view.c_ptr(),
            buffer._impl,
            static_cast<uint32_t>(level));
    }

    /** Publish a Buffer without clearing it. */
    void flush_and_keep(const line_sender_buffer& buffer)
    {
        if (buffer._impl)
            line_sender_error::wrapped_call(
                ::qwp_sender_flush_buffer_and_keep,
                _view.c_ptr(),
                buffer._impl);
    }

    /** Publish and clear a Buffer and return its local FSN boundary. */
    std::optional<uint64_t> flush_and_get_fsn(line_sender_buffer& buffer)
    {
        buffer.may_init();
        ::line_sender_qwpws_fsn fsn{};
        line_sender_error::wrapped_call(
            ::qwp_sender_flush_buffer_and_get_fsn,
            _view.c_ptr(),
            buffer._impl,
            &fsn);
        return optional_fsn(fsn);
    }

    /** Publish a Buffer without clearing it and return its local FSN. */
    std::optional<uint64_t> flush_and_keep_and_get_fsn(
        const line_sender_buffer& buffer)
    {
        ::line_sender_qwpws_fsn fsn{};
        if (buffer._impl)
            line_sender_error::wrapped_call(
                ::qwp_sender_flush_buffer_and_keep_and_get_fsn,
                _view.c_ptr(),
                buffer._impl,
                &fsn);
        return optional_fsn(fsn);
    }

    /**
     * Encode `chunk` and publish it into the store-and-forward queue, returning
     * as soon as it is accepted locally. On success `chunk` is cleared; on
     * failure it is left untouched. Call `wait()` to block for the server ack.
     * Throws on error.
     */
    void flush(column_chunk& chunk)
    {
        _view.flush(chunk);
    }

    /**
     * Publish `chunk` as a completion boundary, then wait until it and all prior
     * frames published through this sender reach `level`.
     */
    void flush_and_wait(
        column_chunk& chunk,
        qwpws_ack_level level = qwpws_ack_level::ok)
    {
        _view.flush_and_wait(chunk, level);
    }

    /**
     * Publish `chunk` locally and return the assigned frame sequence number.
     * If the chunk is split into multiple frames, the returned FSN is the last
     * frame boundary. Use `wait()` for a simple blocking ack barrier.
     */
    std::optional<uint64_t> flush_and_get_fsn(column_chunk& chunk)
    {
        return _view.flush_and_get_fsn(chunk);
    }

    /**
     * Return the highest QWP/WebSocket frame sequence number published locally,
     * or `std::nullopt` if no frame has been published.
     */
    std::optional<uint64_t> published_fsn() const
    {
        return _view.published_fsn();
    }

    /**
     * Return the highest QWP/WebSocket frame sequence number completed by ACK,
     * or `std::nullopt` if none has completed.
     */
    std::optional<uint64_t> acked_fsn() const
    {
        return _view.acked_fsn();
    }

    /**
     * Block until every frame published on this sender so far reaches `level`.
     * The SFA queue owns delivery, so this is needed only to *observe* the ack,
     * never for durability. `timeout` is a no-progress deadline (it fires only
     * if the ack watermark fails to advance for that long); the default of zero
     * waits indefinitely. Throws on error.
     */
    void wait(
        qwpws_ack_level level = qwpws_ack_level::ok,
        std::chrono::milliseconds timeout = std::chrono::milliseconds::zero())
    {
        _view.wait(level, timeout);
    }

#ifdef QUESTDB_CLIENT_ENABLE_ARROW
    /**
     * Publish-only Arrow flush (server-stamped) into the queue. Pair with
     * `wait()`. Ownership: on success `array.release` is consumed; on failure
     * it may also have been consumed; check before invoking. `schema` borrowed.
     */
    void flush_arrow_batch_at_now(
        table_name_view table,
        ::ArrowArray& array,
        const ::ArrowSchema& schema,
        const ::column_sender_arrow_override* overrides = nullptr,
        size_t overrides_len = 0)
    {
        _view.flush_arrow_batch_at_now(
            table, array, schema, overrides, overrides_len);
    }

    /**
     * ACKing counterpart of `flush_arrow_batch_at_now`.
     */
    void flush_arrow_batch_at_now_and_wait(
        table_name_view table,
        ::ArrowArray& array,
        const ::ArrowSchema& schema,
        qwpws_ack_level level = qwpws_ack_level::ok)
    {
        _view.flush_arrow_batch_at_now_and_wait(table, array, schema, level);
    }

    /**
     * ACKing counterpart of `flush_arrow_batch_at_now`, with per-column
     * overrides.
     */
    void flush_arrow_batch_at_now_and_wait(
        table_name_view table,
        ::ArrowArray& array,
        const ::ArrowSchema& schema,
        const ::column_sender_arrow_override* overrides,
        size_t overrides_len,
        qwpws_ack_level level = qwpws_ack_level::ok)
    {
        _view.flush_arrow_batch_at_now_and_wait(
            table, array, schema, overrides, overrides_len, level);
    }

    /**
     * FSN-returning counterpart of `flush_arrow_batch_at_now`.
     */
    std::optional<uint64_t> flush_arrow_batch_at_now_and_get_fsn(
        table_name_view table,
        ::ArrowArray& array,
        const ::ArrowSchema& schema,
        const ::column_sender_arrow_override* overrides = nullptr,
        size_t overrides_len = 0)
    {
        return _view.flush_arrow_batch_at_now_and_get_fsn(
            table, array, schema, overrides, overrides_len);
    }

    /**
     * Publish-only Arrow flush sourcing the designated timestamp from a named
     * `Timestamp(_)` column of the batch. Pair with `wait()`.
     */
    void flush_arrow_batch(
        table_name_view table,
        ::ArrowArray& array,
        const ::ArrowSchema& schema,
        column_name_view ts_column,
        const ::column_sender_arrow_override* overrides = nullptr,
        size_t overrides_len = 0)
    {
        _view.flush_arrow_batch(
            table, array, schema, ts_column, overrides, overrides_len);
    }

    /**
     * ACKing counterpart of `flush_arrow_batch`.
     */
    void flush_arrow_batch_and_wait(
        table_name_view table,
        ::ArrowArray& array,
        const ::ArrowSchema& schema,
        column_name_view ts_column,
        qwpws_ack_level level = qwpws_ack_level::ok)
    {
        _view.flush_arrow_batch_and_wait(
            table, array, schema, ts_column, level);
    }

    /**
     * ACKing counterpart of `flush_arrow_batch`, with per-column overrides.
     */
    void flush_arrow_batch_and_wait(
        table_name_view table,
        ::ArrowArray& array,
        const ::ArrowSchema& schema,
        column_name_view ts_column,
        const ::column_sender_arrow_override* overrides,
        size_t overrides_len,
        qwpws_ack_level level = qwpws_ack_level::ok)
    {
        _view.flush_arrow_batch_and_wait(
            table, array, schema, ts_column, overrides, overrides_len, level);
    }

    /**
     * FSN-returning counterpart of `flush_arrow_batch`.
     */
    std::optional<uint64_t> flush_arrow_batch_and_get_fsn(
        table_name_view table,
        ::ArrowArray& array,
        const ::ArrowSchema& schema,
        column_name_view ts_column,
        const ::column_sender_arrow_override* overrides = nullptr,
        size_t overrides_len = 0)
    {
        return _view.flush_arrow_batch_and_get_fsn(
            table, array, schema, ts_column, overrides, overrides_len);
    }
#endif

    /**
     * Force this borrowed sender to be closed instead of recycled when the guard
     * is destroyed.
     *
     * Use normal destruction for healthy senders: the return path already closes
     * senders that have latched terminal state, or whose pool has been closed.
     * Call this after abandoning work or handling an error where the next
     * borrower must not inherit this backend. If queued store-and-forward
     * frames must not be lost, call `wait()` first or configure `sf_dir` for
     * replay.
     */
    void drop_on_return() noexcept { _force_drop = true; }

private:
    friend class ::questdb::pool;

    borrowed_sender(::questdb_db* db, ::qwp_sender* raw) noexcept
        : _db{db}
        , _view{raw}
    {
    }

    void release() noexcept
    {
        ::qwp_sender* raw = _view.c_ptr();
        if (_db && raw)
        {
            if (_force_drop)
                ::questdb_db_drop_sender(_db, raw);
            else
                ::questdb_db_return_sender(_db, raw);
        }
        _db = nullptr;
        _view = sender_view{nullptr};
    }

    ::questdb_db* _db;
    sender_view _view;
    bool _force_drop{false};

    static std::optional<uint64_t> optional_fsn(
        const ::line_sender_qwpws_fsn& fsn)
    {
        if (fsn.has_value)
            return fsn.value;
        return std::nullopt;
    }
};

} // namespace questdb::ingress

namespace questdb
{
/**
 * RAII wrapper around `::questdb_db*` — the QWP/WS connection pool.
 *
 * `conf` is a `ws::` / `wss::` connect string; see
 * `column_sender.h` for pool-specific keys (`sender_pool_min`,
 * `sender_pool_max`, `query_pool_min`, `query_pool_max`,
 * `acquire_timeout_ms`, `idle_timeout_ms`, `pool_reap`). With `sf_dir`,
 * `sender_id` is the
 * slot base; pooled senders mint `<sender_id>-ingest-<index>` disk slots.
 * Those `<sender_id>-ingest-*` directories under `sf_dir` belong to the pool namespace;
 * use a unique `sender_id` for each pool sharing an `sf_dir`.
 *
 * Construction performs no blocking network I/O. In disk-backed
 * store-and-forward mode it may pre-open parked recovery senders whose initial
 * connect and replay run in the background; otherwise senders are opened on
 * first borrow.
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
     * failure. */
    ingress::borrowed_sender borrow_sender()
    {
        auto* raw = ingress::line_sender_error::wrapped_call(
            ::questdb_db_borrow_sender, _raw);
        return ingress::borrowed_sender{_raw, raw};
    }

    /**
     * Borrow a store-and-forward sender, retrying the connect within `budget_ms`
     * using the pool's reconnect backoff. On a transient `failover_retry`,
     * drop the dead sender then call this with `reconnect_max_duration_ms()` (or
     * your tracked remaining budget). Throws on a terminal error or budget
     * exhaustion.
     */
    ingress::borrowed_sender borrow_sender_with_retry(
        uint64_t budget_ms)
    {
        auto* raw = ingress::line_sender_error::wrapped_call(
            ::questdb_db_borrow_sender_with_retry, _raw, budget_ms);
        return ingress::borrowed_sender{_raw, raw};
    }

    /**
     * Borrow a query reader from the pool, mirroring Rust
     * `QuestDb::borrow_reader`. Readers are pooled on a separate,
     * independently-capped free list with its own `query_pool_min` /
     * `query_pool_max` budget; the reader pool is lazy (a
     * connection opens on first borrow). The returned `reader` is
     * equivalent to a standalone one and returns itself to the pool on
     * destruction — unless `reader::drop_on_return()` was called, in which
     * case it is dropped. If the pool has already been closed by the time the
     * reader is destroyed, it is closed instead of recycled. Throws
     * `questdb::error` on cap exhaustion or transport failure.
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
