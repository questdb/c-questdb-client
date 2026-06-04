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

#include <questdb/ingress/column_sender.h>
#include <questdb/ingress/line_sender.hpp>

#ifdef QUESTDB_CLIENT_ENABLE_ARROW

namespace questdb::ingress
{

/**
 * Borrowed `::qwpws_conn*` wrapper exposing the conn-level Arrow batch
 * ingest API.
 *
 * Holds no ownership of the underlying connection — the caller obtains
 * the handle via `::questdb_db_borrow_conn` (raw C, no C++ wrapper at
 * this layer yet) and is responsible for `::questdb_db_return_conn`
 * (or `::questdb_db_drop_conn`) when done.
 *
 * The rest of `column_sender.h` (chunk lifecycle, per-column appenders,
 * `column_sender_flush` / `column_sender_sync`, db lifecycle) remains
 * available via the raw C API. A full C++ wrapper for those entries is
 * a separate, focused patch.
 */
class column_sender_conn
{
public:
    explicit column_sender_conn(::qwpws_conn* raw) noexcept
        : _raw{raw}
    {
    }

    ::qwpws_conn* c_ptr() noexcept
    {
        return _raw;
    }

    const ::qwpws_conn* c_ptr() const noexcept
    {
        return _raw;
    }

    /**
     * Encode an Arrow RecordBatch (Arrow C Data Interface) as one
     * QWP/WebSocket frame for `table` and publish it through the
     * borrowed connection in one pass. The per-row designated timestamp
     * is omitted; the server stamps each row on arrival.
     *
     * Ownership of `array` / `schema` is consumed on success
     * (release callbacks fire); on failure the caller retains them.
     *
     * Throws `line_sender_error` on failure.
     */
    void flush_arrow_batch(
        table_name_view table,
        ::ArrowArray& array,
        ::ArrowSchema& schema)
    {
        ::line_sender_table_name table_c{table.size(), table.data()};
        line_sender_error::wrapped_call(
            ::column_sender_flush_arrow_batch,
            _raw,
            table_c,
            &array,
            &schema);
    }

    /**
     * Variant of [`flush_arrow_batch`] that sources the per-row
     * designated timestamp from a named `Timestamp(_)` column inside
     * the batch. The column must be
     * `Timestamp(Microsecond | Nanosecond | Millisecond, _)` with no
     * null rows and no values before the Unix epoch.
     */
    void flush_arrow_batch(
        table_name_view table,
        ::ArrowArray& array,
        ::ArrowSchema& schema,
        column_name_view ts_column)
    {
        ::line_sender_table_name table_c{table.size(), table.data()};
        ::line_sender_column_name ts_c{ts_column.size(), ts_column.data()};
        line_sender_error::wrapped_call(
            ::column_sender_flush_arrow_batch_at_column,
            _raw,
            table_c,
            &array,
            &schema,
            ts_c);
    }

private:
    ::qwpws_conn* _raw;
};

} // namespace questdb::ingress

#endif // QUESTDB_CLIENT_ENABLE_ARROW
