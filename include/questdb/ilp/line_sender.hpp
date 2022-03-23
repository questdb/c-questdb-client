/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2022 QuestDB
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

#include "line_sender.h"

#include <string>
#include <string_view>
#include <stdexcept>
#include <cstdint>

namespace questdb::ilp
{
    constexpr const char* inaddr_any = "0.0.0.0";

    class line_sender;

    /** Category of error. */
    enum class line_sender_error_code
    {
        /** The host, port, or interface was incorrect. */
        could_not_resolve_addr,

        /** Called methods in the wrong order. E.g. `symbol` after `column`. */
        invalid_api_call,

        /** A network error connecting of flushing data out. */
        socket_error,

        /** The string or symbol field is not encoded in valid UTF-8. */
        invalid_utf8,

        /** The table name, symbol name or column name contains bad characters. */
        invalid_name
    };

    /**
     * An error that occured when using the line sender.
     *
     * Call `.what()` to obtain ASCII encoded error message.
     */
    class line_sender_error : public std::runtime_error
    {
    public:
        line_sender_error(line_sender_error_code code, const std::string& what)
                : std::runtime_error{what}
                , _code{code}
        {}

        /** Error code categorising the error. */
        line_sender_error_code code() const { return _code; }

    private:
        inline static line_sender_error from_c(::line_sender_error* c_err)
        {
            line_sender_error_code code =
                static_cast<line_sender_error_code>(
                    static_cast<int>(
                        ::line_sender_error_get_code(c_err)));
            size_t c_len{0};
            const char* c_msg{::line_sender_error_msg(c_err, &c_len)};
            std::string msg{c_msg, c_len};
            line_sender_error err{code, msg};
            ::line_sender_error_free(c_err);
            return err;
        }

        template <typename F, typename... Args>
            inline static void wrapped_call(F&& f, Args&&... args)
        {
            ::line_sender_error* c_err{nullptr};
            if (!f(std::forward<Args>(args)..., &c_err))
                throw from_c(c_err);
        }

        friend class line_sender;
        friend class utf8_view;
        friend class name_view;

        line_sender_error_code _code;
    };

    /** Non-owning validated UTF-8 encoded string. */
    class utf8_view
    {
    public:
        utf8_view(const char* buf, size_t len)
            : _impl{0, nullptr}
        {
            line_sender_error::wrapped_call(
                ::line_sender_utf8_init,
                &_impl,
                len,
                buf);
        }

        explicit utf8_view(std::string_view s_view)
            : utf8_view{s_view.data(), s_view.size()}
        {}

        size_t size() const { return _impl.len; }
        const char* data() const { return _impl.buf; }

    private:
        ::line_sender_utf8 _impl;

        friend class line_sender;
    };

    /** Non-owning validated table, symbol or column name. UTF-8 encoded. */
    class name_view
    {
    public:
        name_view(const char* buf, size_t len)
            : _impl{0, nullptr}
        {
            line_sender_error::wrapped_call(
                ::line_sender_name_init,
                &_impl,
                len,
                buf);
        }

        explicit name_view(std::string_view s_view)
            : name_view{s_view.data(), s_view.size()}
        {}

        size_t size() const { return _impl.len; }
        const char* data() const { return _impl.buf; }

    private:
        ::line_sender_name _impl;

        friend class line_sender;
    };

    namespace literals
    {
        /**
         * Utility to construct `utf8_view` objects from string literals.
         * @code {.cpp}
         * auto validated = "A UTF-8 encoded string"_utf8;
         * @endcode
         */
        utf8_view operator "" _utf8(const char* buf, size_t len)
        {
            return utf8_view{buf, len};
        }

        /**
         * Utility to construct `name_view` objects from string literals.
         * @code {.cpp}
         * auto table_name = "events"_name;
         * @endcode
         */
        name_view operator "" _name(const char* buf, size_t len)
        {
            return name_view{buf, len};
        }
    }

    /**
     * Insert data into QuestDB via the InfluxDB Line Protocol.
     *
     * Batch up rows, then call `.flush()` to send.
     */
    class line_sender
    {
    public:
        line_sender(
            const char* host,
            const char* port,
            const char* net_interface = inaddr_any)
                : _impl{nullptr}
        {
            ::line_sender_error* c_err{nullptr};
            _impl = ::line_sender_connect(
                net_interface,
                host,
                port,
                &c_err);
            if (!_impl)
                throw line_sender_error::from_c(c_err);
        }

        line_sender(
            std::string_view host,
            std::string_view port,
            std::string_view net_interface = inaddr_any)
                : line_sender{
                    std::string{host}.c_str(),
                    std::string{port}.c_str(),
                    std::string{net_interface}.c_str()}
        {}

        line_sender(
            std::string_view host,
            uint16_t port,
            std::string_view net_interface = inaddr_any)
                : line_sender{
                    std::string{host}.c_str(),
                    std::to_string(port).c_str(),
                    std::string{net_interface}.c_str()}
        {}

        line_sender(
            const char* host,
            uint16_t port,
            const char* net_interface = inaddr_any)
                : line_sender{
                    host,
                    std::to_string(port).c_str(),
                    net_interface}
        {}

        line_sender(line_sender&& other)
            : _impl{other._impl}
        {
            if (this != &other)
                other._impl = nullptr;
        }

        line_sender& operator=(line_sender&& other)
        {
            if (this != &other)
            {
                close();
                _impl = other._impl;
                other._impl = nullptr;
            }
            return *this;
        }

        line_sender(const line_sender&) = delete;
        line_sender& operator=(const line_sender&) = delete;

        /**
         * Start batching the next row of input for the named table.
         * @param name Table name.
         */
        line_sender& table(name_view name)
        {
            line_sender_error::wrapped_call(
                ::line_sender_table,
                _impl,
                name._impl);
            return *this;
        }

        /**
         * Append a value for a SYMBOL column.
         * Symbol columns must always be written before other columns for any
         * given row.
         * @param name Column name.
         * @param value Column value.
         */
        line_sender& symbol(name_view name, utf8_view value)
        {
            line_sender_error::wrapped_call(
                ::line_sender_symbol,
                _impl,
                name._impl,
                value._impl);
            return *this;
        }

        // Require specific overloads of `column` to avoid
        // involuntary usage of the `bool` overload.
        template <typename T>
        line_sender& column(name_view name, T value) = delete;

        /**
         * Append a value for a BOOLEAN column.
         * @param name Column name.
         * @param value Column value.
         */
        line_sender& column(name_view name, bool value)
        {
            line_sender_error::wrapped_call(
                ::line_sender_column_bool,
                _impl,
                name._impl,
                value);
            return *this;
        }

        /**
         * Append a value for a LONG column.
         * @param name Column name.
         * @param value Column value.
         */
        line_sender& column(name_view name, int64_t value)
        {
            line_sender_error::wrapped_call(
                ::line_sender_column_i64,
                _impl,
                name._impl,
                value);
            return *this;
        }

        /**
         * Append a value for a DOUBLE column.
         * @param name Column name.
         * @param value Column value.
         */
        line_sender& column(name_view name, double value)
        {
            line_sender_error::wrapped_call(
                ::line_sender_column_f64,
                _impl,
                name._impl,
                value);
            return *this;
        }

        /**
         * Append a value for a STRING column.
         * @param name Column name.
         * @param value Column value.
         */
        line_sender& column(name_view name, utf8_view value)
        {
            line_sender_error::wrapped_call(
                ::line_sender_column_str,
                _impl,
                name._impl,
                value._impl);
            return *this;
        }

        /**
         * Complete the row with a specified timestamp.
         *
         * After this call, you can start batching the next row by calling
         * `.table(..)` again, or you can send the accumulated batch by
         * calling `.flush(..)`.
         *
         * @param epoch_nanos Number of nanoseconds since 1st Jan 1970 UTC.
         */
        void at(int64_t epoch_nanos)
        {
            line_sender_error::wrapped_call(
                ::line_sender_at,
                _impl,
                epoch_nanos);
        }

        /**
         * Complete the row without providing a timestamp.
         * The QuestDB instance will insert its own timestamp.
         */
        void at_now()
        {
            line_sender_error::wrapped_call(
                ::line_sender_at_now,
                _impl);
        }

        /**
         * Number of bytes that will be sent at next call to `.flush()`.
         *
         * @return Accumulated batch size.
         */
        size_t pending_size()
        {
            return _impl
                ? ::line_sender_pending_size(_impl)
                : 0;
        }

        /**
         * Send batch-up rows messages to the QuestDB server.
         *
         * After sending a batch, you can close the connection or begin
         * preparing a new batch by calling `.table(..)` again.
         */
        void flush()
        {
            line_sender_error::wrapped_call(
                ::line_sender_flush,
                _impl);
        }

        /**
         * Check if an error occured previously and the sender must be closed.
         * @return true if an error occured with a sender and it must be closed.
         */
        bool must_close() noexcept
        {
            return _impl
                ? ::line_sender_must_close(_impl)
                : false;
        }

        /**
         * Close the connection. Does not flush. Idempotent.
         */
        void close() noexcept
        {
            if (_impl)
            {
                ::line_sender_close(_impl);
                _impl = nullptr;
            }
        }

        ~line_sender() noexcept
        {
            close();
        }

    private:
        ::line_sender* _impl;
    };

}
