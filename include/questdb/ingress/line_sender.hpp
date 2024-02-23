/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2024 QuestDB
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
#include <chrono>
#include <type_traits>

namespace questdb::ingress
{
    constexpr const char* inaddr_any = "0.0.0.0";

    class line_sender;
    class line_sender_buffer;
    class opts;

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

        /** The table name or column name contains bad characters. */
        invalid_name,

        /** The supplied timestamp is invalid. */
        invalid_timestamp,

        /** Error during the authentication process. */
        auth_error,

        /** Error during TLS handshake. */
        tls_error,

        /** The server does not support ILP over HTTP. */
        http_not_supported,

        /** Error sent back from the server during flush. */
        server_flush_error,

        /** Bad configuration. */
        config_error,
    };

    /* Certificate authority used to determine how to validate the server's TLS certificate. */
    enum class line_sender_ca {
        /** Use the set of root certificates provided by the `webpki` crate. */
        webpki_roots,

        /** Use the set of root certificates provided by the operating system. */
        os_roots,

        /** Use the set of root certificates provided by both the `webpki` crate and the operating system. */
        webpki_and_os_roots,

        /** Use a custom root certificate `.pem` file. */
        pem_file,
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
        inline static auto wrapped_call(F&& f, Args&&... args)
        {
            ::line_sender_error* c_err{nullptr};
            auto obj = f(std::forward<Args>(args)..., &c_err);
            if (obj)
                return obj;
            else
                throw from_c(c_err);
        }

        friend class line_sender;
        friend class line_sender_buffer;
        friend class opts;

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
        friend class line_sender_buffer;
        friend class opts;
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
        inline utf8_view operator "" _utf8(const char* buf, size_t len)
        {
            return utf8_view{buf, len};
        }

        /**
         * Utility to construct `table_name_view` objects from string literals.
         * @code {.cpp}
         * auto table_name = "events"_tn;
         * @endcode
         */
        inline table_name_view operator "" _tn(const char* buf, size_t len)
        {
            return table_name_view{buf, len};
        }

        /**
         * Utility to construct `column_name_view` objects from string literals.
         * @code {.cpp}
         * auto column_name = "events"_cn;
         * @endcode
         */
        inline column_name_view operator "" _cn(const char* buf, size_t len)
        {
            return column_name_view{buf, len};
        }
    }

    class timestamp_micros
    {
    public:
        template <typename ClockT, typename DurationT>
        explicit timestamp_micros(std::chrono::time_point<ClockT, DurationT> tp)
            : _ts{std::chrono::duration_cast<std::chrono::microseconds>(
                tp.time_since_epoch()).count()}
        {}

        explicit timestamp_micros(int64_t ts) noexcept
            : _ts{ts}
        {}

        int64_t as_micros() const noexcept { return _ts; }

        static inline timestamp_micros now() noexcept
        {
            return timestamp_micros{::line_sender_now_micros()};
        }

    private:
        int64_t _ts;
    };

    class timestamp_nanos
    {
    public:
        template <typename ClockT, typename DurationT>
        explicit timestamp_nanos(std::chrono::time_point<ClockT, DurationT> tp)
            : _ts{std::chrono::duration_cast<std::chrono::nanoseconds>(
                tp.time_since_epoch()).count()}
        {}

        explicit timestamp_nanos(int64_t ts) noexcept
            : _ts{ts}
        {}

        int64_t as_nanos() const noexcept { return _ts; }

        static inline timestamp_nanos now() noexcept
        {
            return timestamp_nanos{::line_sender_now_nanos()};
        }

    private:
        int64_t _ts;
    };

    class line_sender_buffer
    {
    public:
        explicit line_sender_buffer(size_t init_capacity = 64 * 1024) noexcept
            : line_sender_buffer{init_capacity, 127}
        {}

        line_sender_buffer(
            size_t init_capacity,
            size_t max_name_len) noexcept
            : _impl{nullptr}
            , _init_capacity{init_capacity}
            , _max_name_len{max_name_len}
        {
        }

        line_sender_buffer(const line_sender_buffer& other) noexcept
            : _impl{::line_sender_buffer_clone(other._impl)}
            , _init_capacity{other._init_capacity}
            , _max_name_len{other._max_name_len}
        {}

        line_sender_buffer(line_sender_buffer&& other) noexcept
            : _impl{other._impl}
            , _init_capacity{other._init_capacity}
            , _max_name_len{other._max_name_len}
        {
            other._impl = nullptr;
        }

        line_sender_buffer& operator=(const line_sender_buffer& other) noexcept
        {
            if (this != &other)
            {
                ::line_sender_buffer_free(_impl);
                if (other._impl)
                    _impl = ::line_sender_buffer_clone(other._impl);
                else
                    _impl = nullptr;
                _init_capacity = other._init_capacity;
                _max_name_len = other._max_name_len;
            }
            return *this;
        }

        line_sender_buffer& operator=(line_sender_buffer&& other) noexcept
        {
            if (this != &other)
            {
                ::line_sender_buffer_free(_impl);
                _impl = other._impl;
                _init_capacity = other._init_capacity;
                _max_name_len = other._max_name_len;
                other._impl = nullptr;
            }
            return *this;
        }

        /**
         * Pre-allocate to ensure the buffer has enough capacity for at least
         * the specified additional byte count. This may be rounded up.
         * This does not allocate if such additional capacity is already
         * satisfied.
         * See: `capacity`.
         */
        void reserve(size_t additional)
        {
            may_init();
            ::line_sender_buffer_reserve(_impl, additional);
        }

        /** Get the current capacity of the buffer. */
        size_t capacity() const noexcept
        {
            if (_impl)
                return ::line_sender_buffer_capacity(_impl);
            else
                return 0;
        }

        /** Number of bytes in the accumulated buffer. */
        size_t size() const noexcept
        {
            if (_impl)
                return ::line_sender_buffer_size(_impl);
            else
                return 0;
        }

        /** The number of rows accumulated in the buffer. */
        size_t row_count() const noexcept
        {
            if (_impl)
                return ::line_sender_buffer_row_count(_impl);
            else
                return 0;
        }

        /**
         * The buffer is transactional if sent over HTTP.
         * A buffer stops being transactional if it contains rows for multiple tables.
         */
        bool transactional() const noexcept
        {
            if (_impl)
                return ::line_sender_buffer_transactional(_impl);
            else
                return 0;
        }

        /**
         * Get a view of the accumulated buffer.
         * This is useful for debugging.
         */
        std::string_view peek() const noexcept
        {
            if (_impl)
            {
                size_t len = 0;
                const char* buf = ::line_sender_buffer_peek(_impl, &len);
                return {buf, len};
            }
            else
            {
                return {};
            }
        }

        /**
         * Mark a rewind point.
         * This allows undoing accumulated changes to the buffer for one or more
         * rows by calling `rewind_to_marker`.
         * Any previous marker will be discarded.
         * Once the marker is no longer needed, call `clear_marker`.
         */
        void set_marker()
        {
            may_init();
            line_sender_error::wrapped_call(
                ::line_sender_buffer_set_marker, _impl);
        }

        /**
         * Undo all changes since the last `set_marker` call.
         * As a side-effect, this also clears the marker.
         */
        void rewind_to_marker()
        {
            may_init();
            line_sender_error::wrapped_call(
                ::line_sender_buffer_rewind_to_marker, _impl);
        }

        /** Discard the marker. */
        void clear_marker() noexcept
        {
            if (_impl)
                ::line_sender_buffer_clear_marker(_impl);
        }

        /**
         * Remove all accumulated data and prepare the buffer for new lines.
         * This does not affect the buffer's capacity.
         */
        void clear() noexcept
        {
            if (_impl)
                ::line_sender_buffer_clear(_impl);
        }

        /**
         * Start batching the next row of input for the named table.
         * @param name Table name.
         */
        line_sender_buffer& table(table_name_view name)
        {
            may_init();
            line_sender_error::wrapped_call(
                ::line_sender_buffer_table,
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
        line_sender_buffer& symbol(column_name_view name, utf8_view value)
        {
            may_init();
            line_sender_error::wrapped_call(
                ::line_sender_buffer_symbol,
                _impl,
                name._impl,
                value._impl);
            return *this;
        }

        // Require specific overloads of `column` to avoid
        // involuntary usage of the `bool` overload.
        template <typename T>
        line_sender_buffer& column(column_name_view name, T value) = delete;

        /**
         * Append a value for a BOOLEAN column.
         * @param name Column name.
         * @param value Column value.
         */
        line_sender_buffer& column(column_name_view name, bool value)
        {
            may_init();
            line_sender_error::wrapped_call(
                ::line_sender_buffer_column_bool,
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
        line_sender_buffer& column(column_name_view name, int64_t value)
        {
            may_init();
            line_sender_error::wrapped_call(
                ::line_sender_buffer_column_i64,
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
        line_sender_buffer& column(column_name_view name, double value)
        {
            may_init();
            line_sender_error::wrapped_call(
                ::line_sender_buffer_column_f64,
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
        line_sender_buffer& column(column_name_view name, utf8_view value)
        {
            may_init();
            line_sender_error::wrapped_call(
                ::line_sender_buffer_column_str,
                _impl,
                name._impl,
                value._impl);
            return *this;
        }

        template <size_t N>
        line_sender_buffer& column(
            column_name_view name,
            const char (&value)[N])
        {
            return column(name, utf8_view{value});
        }

        line_sender_buffer& column(
            column_name_view name,
            std::string_view value)
        {
            return column(name, utf8_view{value});
        }

        line_sender_buffer& column(
            column_name_view name,
            const std::string& value)
        {
            return column(name, utf8_view{value});
        }

        template <typename ClockT>
        line_sender_buffer& column(
            column_name_view name,
            std::chrono::time_point<ClockT, std::chrono::nanoseconds> tp)
        {
            timestamp_nanos nanos{tp};
            return column(name, nanos);
        }

        template <typename ClockT, typename DurationT>
        line_sender_buffer& column(
            column_name_view name,
            std::chrono::time_point<ClockT, DurationT> tp)
        {
            timestamp_micros micros{tp};
            return column(name, micros);
        }

        line_sender_buffer& column(
            column_name_view name,
            timestamp_nanos value)
        {
            may_init();
            line_sender_error::wrapped_call(
                ::line_sender_buffer_column_ts_nanos,
                _impl,
                name._impl,
                value.as_nanos());
            return *this;
        }

        line_sender_buffer& column(
            column_name_view name,
            timestamp_micros value)
        {
            may_init();
            line_sender_error::wrapped_call(
                ::line_sender_buffer_column_ts_micros,
                _impl,
                name._impl,
                value.as_micros());
            return *this;
        }

        /**
         * Complete the row with a timestamp specified as nanoseconds.
         *
         * After this call, you can start batching the next row by calling
         * `.table(..)` again, or you can send the accumulated batch by
         * calling `.flush(..)`.
         *
         * @param timestamp Number of nanoseconds since 1st Jan 1970 UTC.
         */
        void at(timestamp_nanos timestamp)
        {
            may_init();
            line_sender_error::wrapped_call(
                ::line_sender_buffer_at_nanos,
                _impl,
                timestamp.as_nanos());
        }

        /**
         * Complete the row with a timestamp specified as microseconds.
         *
         * After this call, you can start batching the next row by calling
         * `.table(..)` again, or you can send the accumulated batch by
         * calling `.flush(..)`.
         *
         * @param timestamp Number of microseconds since 1st Jan 1970 UTC.
         */
        void at(timestamp_micros timestamp)
        {
            may_init();
            line_sender_error::wrapped_call(
                ::line_sender_buffer_at_micros,
                _impl,
                timestamp.as_micros());
        }

        /**
         * Complete the row without providing a timestamp.
         * The QuestDB instance will insert its own timestamp.
         *
         * This is NOT equivalent to calling `at()` with the
         * current system time.
         * There's a trade-off: Letting the server assign the timestamp
         * can be faster since it a reliable way to avoid out-of-order
         * operations in the database for maximum ingestion throughput.
         * On the other hand, it removes the ability to deduplicate rows.
         *
         * In almost all cases, you should prefer the `at()` method.
         */
        void at_now()
        {
            may_init();
            line_sender_error::wrapped_call(
                ::line_sender_buffer_at_now,
                _impl);
        }

        ~line_sender_buffer() noexcept
        {
            if (_impl)
                ::line_sender_buffer_free(_impl);
        }
    private:
        inline void may_init()
        {
            if (!_impl)
            {
                _impl = ::line_sender_buffer_with_max_name_len(_max_name_len);
                ::line_sender_buffer_reserve(_impl, _init_capacity);
            }
        }

        ::line_sender_buffer* _impl;
        size_t _init_capacity;
        size_t _max_name_len;

        friend class line_sender;
    };

    /**
     * Protocol to use for the line sender.
     */
    enum class line_sender_protocol
    {
        /** ILP/TCP */
        tcp,

        /** ILP/HTTP */
        http,
    };

    class opts
    {
        public:
            /**
             * Create a new `ops` instance from configuration string.
             * The format of the string is: "tcp::addr=host:port;key=value;...;"
             * Alongside "tcp" you can also specify "tcps", "http", and "https".
             * The accepted set of keys and values is the same as for the opt's API.
             * E.g. "tcp::addr=host:port;user=alice;password=secret;tls_ca=os_roots;"
             */
            static inline opts from_conf(utf8_view conf)
            {
                return {line_sender_error::wrapped_call(
                    ::line_sender_opts_from_conf,
                    conf._impl)};
            }

            /**
             * Create a new `ops` instance from configuration string read from the
             * `QDB_CLIENT_CONF` environment variable.
             */
            static inline opts from_env()
            {
                return {line_sender_error::wrapped_call(
                    ::line_sender_opts_from_env)};
            }

            /**
             * A new set of options for a line sender connection.
             * @param[in] protocol The protocol to use.
             * @param[in] host The QuestDB database host.
             * @param[in] port The QuestDB tcp or http port.
             */
            opts(
                line_sender_protocol protocol,
                utf8_view host,
                uint16_t port) noexcept
                : _impl{
                    protocol == line_sender_protocol::tcp
                        ? ::line_sender_opts_new_tcp(host._impl, port)
                        : ::line_sender_opts_new_http(host._impl, port)
                }
            {}

            /**
             * A new set of options for a line sender connection.
             * @param[in] host The QuestDB database host.
             * @param[in] port The QuestDB tcp or http port as service name.
             */
            opts(
                line_sender_protocol protocol,
                utf8_view host,
                utf8_view port) noexcept
                : _impl{
                    protocol == line_sender_protocol::tcp
                        ? ::line_sender_opts_new_tcp_service(host._impl, port._impl)
                        : ::line_sender_opts_new_http_service(host._impl, port._impl)
                }
            {}

            opts(const opts& other) noexcept
                : _impl{::line_sender_opts_clone(other._impl)}
            {}

            opts(opts&& other) noexcept
                : _impl{other._impl}
            {
                other._impl = nullptr;
            }

            opts& operator=(const opts& other) noexcept
            {
                if (this != &other)
                {
                    reset();
                    _impl = ::line_sender_opts_clone(other._impl);
                }
                return *this;
            }

            opts& operator=(opts&& other) noexcept
            {
                if (this != &other)
                {
                    reset();
                    _impl = other._impl;
                    other._impl = nullptr;
                }
                return *this;
            }

            /** 
             * Select local outbound network "bind" interface.
             *
             * This may be relevant if your machine has multiple network interfaces.
             *
             * The default is `0.0.0.0``.
             */
            opts& bind_interface(utf8_view bind_interface)
            {
                line_sender_error::wrapped_call(
                    ::line_sender_opts_bind_interface,
                    _impl,
                    bind_interface._impl);
                return *this;
            }

            // /**
            //  * Set the username for authentication.
            //  * 
            //  * For TCP this is the `kid` part of the ECDSA key set.
            //  * The other fields are `token` `token_x` and `token_y`.
            //  * 
            //  * For HTTP this is part of basic authentication.
            //  * Also see `pass`.
            //  */
            // LINESENDER_API
            // bool line_sender_opts_user(
            //     line_sender_opts* opts,
            //     line_sender_utf8 user,
            //     line_sender_error** err_out);

            /**
             * Set the username for basic HTTP authentication.
             * 
             * For TCP this is the `kid` part of the ECDSA key set.
             * The other fields are `token` `token_x` and `token_y`.
             * 
             * For HTTP this is part of basic authentication.
             * Also see `pass`.
             */
            opts& user(utf8_view user)
            {
                line_sender_error::wrapped_call(
                    ::line_sender_opts_user,
                    _impl,
                    user._impl);
                return *this;
            }

            /**
             * Set the password for basic HTTP authentication.
             * Also see `user`.
             */
            opts& pass(utf8_view pass)
            {
                line_sender_error::wrapped_call(
                    ::line_sender_opts_pass,
                    _impl,
                    pass._impl);
                return *this;
            }

            /**
             * Token (Bearer) Authentication Parameters for ILP over HTTP,
             * or the ECDSA private key for ILP over TCP authentication.
             */
            opts& token(utf8_view token)
            {
                line_sender_error::wrapped_call(
                    ::line_sender_opts_token,
                    _impl,
                    token._impl);
                return *this;
            }

            /**
             * The ECDSA public key X for ILP over TCP authentication.
             */
            opts& token_x(utf8_view token_x)
            {
                line_sender_error::wrapped_call(
                    ::line_sender_opts_token_x,
                    _impl,
                    token_x._impl);
                return *this;
            }

            /**
             * The ECDSA public key Y for ILP over TCP authentication.
             */
            opts& token_y(utf8_view token_y)
            {
                line_sender_error::wrapped_call(
                    ::line_sender_opts_token_y,
                    _impl,
                    token_y._impl);
                return *this;
            }

            /**
             * Configure how long to wait for messages from the QuestDB server during
             * the TLS handshake and authentication process.
             * The default is 15 seconds.
             */
            opts& auth_timeout(uint64_t millis)
            {
                line_sender_error::wrapped_call(
                    ::line_sender_opts_auth_timeout,
                    _impl,
                    millis);
                return *this;
            }

            /**
             * Enable or disable TLS.
             */
            opts& tls_enabled(bool enabled)
            {
                line_sender_error::wrapped_call(
                    ::line_sender_opts_tls_enabled,
                    _impl,
                    enabled);
                return *this;
            }

            /**
             * Set to `false` to disable TLS certificate verification.
             * This should only be used for debugging purposes as it reduces security.
             * 
             * For testing consider specifying a path to a `.pem` file instead via
             * the `tls_roots` setting.
             */
            opts& tls_verify(bool verify)
            {
                line_sender_error::wrapped_call(
                    ::line_sender_opts_tls_verify,
                    _impl,
                    verify);
                return *this;
            }

            /**
             * Set the certificate authority used to determine how to validate the server's TLS certificate.
             */
            opts& tls_ca(line_sender_ca ca)
            {
                line_sender_error::wrapped_call(
                    ::line_sender_opts_tls_ca,
                    _impl,
                    ca);
                return *this;
            }

            /**
             * Set the path to a custom root certificate `.pem` file.
             * This is used to validate the server's certificate during the TLS handshake.
             * The file may be password-protected, if so, also specify the password
             * via the `tls_roots_password` method.
             *
             * See notes on how to test with self-signed certificates:
             * https://github.com/questdb/c-questdb-client/tree/main/tls_certs.
             */
            opts& tls_roots(utf8_view path)
            {
                line_sender_error::wrapped_call(
                    ::line_sender_opts_tls_roots,
                    _impl,
                    path._impl);
                return *this;
            }

            /**
             * The maximum buffer size that the client will flush to the server.
             * The default is 100 MiB.
             */
            opts& max_buf_size(size_t max_buf_size)
            {
                line_sender_error::wrapped_call(
                    ::line_sender_opts_max_buf_size,
                    _impl,
                    max_buf_size);
                return *this;
            }

            /**
             * Cumulative duration spent in retries.
             * Default is 10 seconds.
             */
            opts& retry_timeout(uint64_t millis)
            {
                line_sender_error::wrapped_call(
                    ::line_sender_opts_retry_timeout,
                    _impl,
                    millis);
                return *this;
            }

            /**
             * Minimum expected throughput in bytes per second for HTTP requests.
             * If the throughput is lower than this value, the connection will time out.
             * The default is 100 KiB/s.
             * The value is expressed as a number of bytes per second.
             */
            opts& min_throughput(uint64_t bytes_per_sec)
            {
                line_sender_error::wrapped_call(
                    ::line_sender_opts_min_throughput,
                    _impl,
                    bytes_per_sec);
                return *this;
            }

            /**
             * Grace request timeout before relying on the minimum throughput logic.
             * The default is 5 seconds.
             */
            opts& grace_timeout(uint64_t millis)
            {
                line_sender_error::wrapped_call(
                    ::line_sender_opts_grace_timeout,
                    _impl,
                    millis);
                return *this;
            }

            ~opts() noexcept
            {
                reset();
            }
        private:
            opts(::line_sender_opts* impl) : _impl{impl}
            {}

            void reset() noexcept
            {
                if (_impl)
                {
                    ::line_sender_opts_free(_impl);
                    _impl = nullptr;
                }
            }

            friend class line_sender;

            ::line_sender_opts* _impl;
    };

    /**
     * Insert data into QuestDB via the InfluxDB Line Protocol.
     *
     * A `line_sender` object connects on construction.
     * If you want to connect later, wrap it up in an std::optional.
     *
     * Batch up rows, then call `.flush()` to send.
     */
    class line_sender
    {
    public:
        /**
         * Create a new `line_sender` instance from configuration string.
         * The format of the string is: "tcp::addr=host:port;key=value;...;"
         * Alongside "tcp" you can also specify "tcps", "http", and "https".
         * The accepted set of keys and values is the same as for the opt's API.
         * E.g. "tcp::addr=host:port;user=alice;password=secret;tls_ca=os_roots;"
         */
        static inline line_sender from_conf(utf8_view conf)
        {
            return {opts::from_conf(conf)};
        }

        /**
         * Create a new `line_sender` instance from configuration string read from the
         * `QDB_CLIENT_CONF` environment variable.
         */
        static inline line_sender from_env()
        {
            return {opts::from_env()};
        }

        line_sender(line_sender_protocol protocol, utf8_view host, uint16_t port)
            : line_sender{opts{protocol, host, port}}
        {}

        line_sender(line_sender_protocol protocol, utf8_view host, utf8_view port)
            : line_sender{opts{protocol, host, port}}
        {}

        line_sender(const opts& opts)
            : _impl{line_sender_error::wrapped_call(
                ::line_sender_build, opts._impl)}
        {}

        line_sender(const line_sender&) = delete;

        line_sender(line_sender&& other) noexcept
            : _impl{other._impl}
        {
            other._impl = nullptr;
        }

        line_sender& operator=(const line_sender&) = delete;

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

        /**
         * Send batched-up rows to the QuestDB server.
         *
         * This method automatically clears the buffer.
         * See `flush_and_keep` if you want to retain the buffer contents.
         *
         * After sending a batch, you can close the connection or begin
         * preparing a new batch by calling `.table(..)` on the buffer again.
         */
        void flush(line_sender_buffer& buffer)
        {
            buffer.may_init();
            ensure_impl();
            line_sender_error::wrapped_call(
                ::line_sender_flush,
                _impl,
                buffer._impl);
        }

        /**
         * Send batched-up rows to the QuestDB server.
         *
         * This method does not affect the buffer and its contains
         * will be retained.
         */
        void flush_and_keep(const line_sender_buffer& buffer)
        {
            if (buffer._impl)
            {
                ensure_impl();
                line_sender_error::wrapped_call(
                    ::line_sender_flush_and_keep,
                    _impl,
                    buffer._impl);
            }
            else
            {
                line_sender_buffer buffer2{0};
                buffer2.may_init();
                line_sender_error::wrapped_call(
                    ::line_sender_flush_and_keep,
                    _impl,
                    buffer2._impl);
            }
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
