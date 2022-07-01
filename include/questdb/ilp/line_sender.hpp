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
#include <optional>

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

        /** A network error connecting or flushing data out. */
        socket_error,

        /** The string or symbol field is not encoded in valid UTF-8. */
        invalid_utf8,

        /** The table name, symbol name or column name contains bad characters. */
        invalid_name,

        /** Error during the authentication process. */
        auth_error,

        /** Error during TLS handshake. */
        tls_error
    };

    /**
     * An error that occurred when using the line sender.
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

        /** Error code categorizing the error. */
        line_sender_error_code code() const noexcept { return _code; }

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

        template <
            typename T,
            bool (*F)(T*, size_t, const char*, ::line_sender_error**)>
        friend class basic_view;

        line_sender_error_code _code;
    };

    /**
     * Non-owning validated string.
     *
     * See `table_name_view`, `column_name_view` and `utf8_view` along with the
     * `_utf8`, `_tn` and `_cn` literal suffixes in the `literals` namespace.
     */
    template <
        typename T,
        bool (*F)(T*, size_t, const char*, ::line_sender_error**)>
    class basic_view
    {
    public:
        basic_view(const char* buf, size_t len)
            : _impl{0, nullptr}
        {
            line_sender_error::wrapped_call(
                F,
                &_impl,
                len,
                buf);
        }

        template <size_t N>
        basic_view(const char (&buf)[N])
            : basic_view{buf, N - 1}
        {}

        basic_view(std::string_view s_view)
            : basic_view{s_view.data(), s_view.size()}
        {}

        basic_view(const std::string& s)
            : basic_view{s.data(), s.size()}
        {}

        size_t size() const noexcept { return _impl.len; }

        const char* data() const noexcept { return _impl.buf; }

        std::string_view to_string_view() const noexcept
        {
            return std::string_view{_impl.buf, _impl.len};
        }

    private:
        T _impl;

        friend class line_sender;
    };

    using utf8_view = basic_view<
        ::line_sender_utf8,
        ::line_sender_utf8_init>;

    using table_name_view = basic_view<
        ::line_sender_table_name,
        ::line_sender_table_name_init>;

    using column_name_view = basic_view<
        ::line_sender_column_name,
        ::line_sender_column_name_init>;

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
         * Utility to construct `table_name_view` objects from string literals.
         * @code {.cpp}
         * auto table_name = "events"_tn;
         * @endcode
         */
        table_name_view operator "" _tn(const char* buf, size_t len)
        {
            return table_name_view{buf, len};
        }

        /**
         * Utility to construct `column_name_view` objects from string literals.
         * @code {.cpp}
         * auto column_name = "events"_cn;
         * @endcode
         */
        column_name_view operator "" _cn(const char* buf, size_t len)
        {
            return column_name_view{buf, len};
        }
    }

    /** Whole connection encryption options. */
    enum class tls
    {
        /** No TLS connection encryption. */
        disabled,

        /** Enable TLS. See `sec_opts::tls_ca` for behaviour. */
        enabled,

        /**
         * Enable TLS whilst dangerously accepting any certificate as valid.
         * This should only be used for debugging.
         * Consider using `enabled` and supplying a self-signed `tls_ca` instead.
         */
        insecure_skip_verify
    };

    /**
     * * Connection security options.
     */
    class sec_opts
    {
    public:
        /** Construct with auth parameters and optionally with TLS. */
        sec_opts(
            std::string_view auth_key_id,
            std::string_view auth_priv_key,
            std::string_view auth_pub_key_x,
            std::string_view auth_pub_key_y,
            tls tls = tls::disabled,
            std::optional<std::string_view> tls_ca = std::nullopt)
                : _auth_key_id{auth_key_id}
                , _auth_priv_key{auth_priv_key}
                , _auth_pub_key_x{auth_pub_key_x}
                , _auth_pub_key_y{auth_pub_key_y}
                , _tls{tls}
                , _tls_ca{tls_ca}
        {}

        /** Construct with TLS parameters only. */
        sec_opts(tls tls, std::optional<std::string_view> tls_ca = std::nullopt)
            : _auth_key_id(std::nullopt)
            , _auth_priv_key(std::nullopt)
            , _auth_pub_key_x(std::nullopt)
            , _auth_pub_key_y(std::nullopt)
            , _tls(tls)
            , _tls_ca(tls_ca)
        {}

    private:
        friend class line_sender;

        /** Authentication key id. AKA "kid". */
        std::optional<std::string> _auth_key_id;

        /** Authentication private key. AKA "d". */
        std::optional<std::string> _auth_priv_key;

        /** Authentication public key X coordinate. AKA "x". */
        std::optional<std::string> _auth_pub_key_x;

        /** Authentication public key Y coordinate. AKA "y". */
        std::optional<std::string> _auth_pub_key_y;

        /** Settings for secure connection over TLS. */
        tls _tls;

        /**
         * Set a custom CA file path to use for verification.
         * If set to a nullopt, defaults to `webpki-roots` certificates which
         * accepts most well-know certificate authorities.
         *
         * This argument is generally only specified during dev-testing.
         */
        std::optional<std::string> _tls_ca;
    };

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
            const char* host,
            const char* port,
            const sec_opts& sec_opts,
            const char* net_interface = inaddr_any)
                : _impl{nullptr}
        {
            ::line_sender_error* c_err{nullptr};
            ::line_sender_sec_opts c_sec_opts;

            auto to_c_str = [](const std::optional<std::string>& str)
                {
                    return str
                        ? str->c_str()
                        : nullptr;
                };

            c_sec_opts.auth_key_id = to_c_str(sec_opts._auth_key_id);
            c_sec_opts.auth_priv_key = to_c_str(sec_opts._auth_priv_key);
            c_sec_opts.auth_pub_key_x = to_c_str(sec_opts._auth_pub_key_x);
            c_sec_opts.auth_pub_key_y = to_c_str(sec_opts._auth_pub_key_y);
            c_sec_opts.tls = static_cast<::line_sender_tls>(sec_opts._tls);
            c_sec_opts.tls_ca = to_c_str(sec_opts._tls_ca);
            _impl = ::line_sender_connect_secure(
                net_interface,
                host,
                port,
                &c_sec_opts,
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
            std::string_view port,
            const sec_opts& sec_opts,
            std::string_view net_interface = inaddr_any)
                : line_sender{
                    std::string{host}.c_str(),
                    std::string{port}.c_str(),
                    sec_opts,
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
            std::string_view host,
            uint16_t port,
            const sec_opts& sec_opts,
            std::string_view net_interface = inaddr_any)
                : line_sender{
                    std::string{host}.c_str(),
                    std::to_string(port).c_str(),
                    sec_opts,
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

        line_sender(
            const char* host,
            uint16_t port,
            const sec_opts& sec_opts,
            const char* net_interface = inaddr_any)
                : line_sender{
                    host,
                    std::to_string(port).c_str(),
                    sec_opts,
                    net_interface}
        {}

        line_sender(line_sender&& other) noexcept
            : _impl{other._impl}
        {
            if (this != &other)
                other._impl = nullptr;
        }

        line_sender& operator=(line_sender&& other) noexcept
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
        line_sender& table(table_name_view name)
        {
            ensure_impl();
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
        line_sender& symbol(column_name_view name, utf8_view value)
        {
            ensure_impl();
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
        line_sender& column(column_name_view name, T value) = delete;

        /**
         * Append a value for a BOOLEAN column.
         * @param name Column name.
         * @param value Column value.
         */
        line_sender& column(column_name_view name, bool value)
        {
            ensure_impl();
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
        line_sender& column(column_name_view name, int64_t value)
        {
            ensure_impl();
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
        line_sender& column(column_name_view name, double value)
        {
            ensure_impl();
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
        line_sender& column(column_name_view name, utf8_view value)
        {
            ensure_impl();
            line_sender_error::wrapped_call(
                ::line_sender_column_str,
                _impl,
                name._impl,
                value._impl);
            return *this;
        }

        template <size_t N>
        line_sender& column(column_name_view name, const char (&value)[N])
        {
            return column(name, utf8_view{value});
        }

        line_sender& column(column_name_view name, std::string_view value)
        {
            return column(name, utf8_view{value});
        }

        line_sender& column(column_name_view name, const std::string& value)
        {
            return column(name, utf8_view{value});
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
            ensure_impl();
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
            ensure_impl();
            line_sender_error::wrapped_call(
                ::line_sender_at_now,
                _impl);
        }

        /**
         * Number of bytes that will be sent at next call to `.flush()`.
         *
         * @return Accumulated batch size.
         */
        size_t pending_size() const noexcept
        {
            return _impl
                ? ::line_sender_pending_size(_impl)
                : 0;
        }

        /**
         * Peek into the accumulated buffer that is to be sent out at the next `flush`.
         *
         * @return UTF-8 encoded buffer. The buffer is not nul-terminated.
         */
        std::string_view peek_pending() const noexcept
        {
            if (_impl)
            {
                size_t len = 0;
                const char* buf = ::line_sender_peek_pending(_impl, &len);
                return {buf, len};
            }
            else
            {
                return {};
            }
        }

        /**
         * Send batch-up rows messages to the QuestDB server.
         *
         * After sending a batch, you can close the connection or begin
         * preparing a new batch by calling `.table(..)` again.
         */
        void flush()
        {
            ensure_impl();
            line_sender_error::wrapped_call(
                ::line_sender_flush,
                _impl);
        }

        /**
         * Check if an error occurred previously and the sender must be closed.
         * @return true if an error occurred with a sender and it must be closed.
         */
        bool must_close() const noexcept
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
        void ensure_impl()
        {
            if (!_impl)
                throw line_sender_error{
                    line_sender_error_code::invalid_api_call,
                    "Sender closed."};
        }

        ::line_sender* _impl;
    };

}
