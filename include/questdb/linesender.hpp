#pragma once

#include "linesender.h"

#include <string>
#include <string_view>
#include <stdexcept>

namespace questdb::proto::line
{
    constexpr const char* inaddr_any = "0.0.0.0";

    class sender_error : public std::runtime_error
    {
    public:
        sender_error(int errnum, const std::string& what)
                : std::runtime_error{what}
                , _errnum{errnum}
        {}

        /** Returns 0 if there is no associated error number. */
        int errnum() const { return _errnum; }

    private:
        inline static sender_error from_c(linesender_error* c_err)
        {
            int errnum{linesender_error_errnum(c_err)};
            size_t c_len{0};
            const char* c_msg{linesender_error_msg(c_err, &c_len)};
            std::string msg{c_msg, c_len};
            sender_error err{errnum, msg};
            linesender_error_free(c_err);
            return err;
        }

        template <typename F, typename... Args>
            inline static void wrapped_call(F&& f, Args&&... args)
        {
            linesender_error* c_err{nullptr};
            if (!f(std::forward<Args>(args)..., &c_err))
                throw from_c(c_err);
        }

        friend class sender;

        int _errnum;
    };

    enum class transport : uint8_t
    {
        tcp = linesender_tcp,
        udp = linesender_udp
    };

    class sender
    {
    public:
        sender(
            transport t,
            const char* host,
            const char* port,
            const char* interface = inaddr_any,
            int udp_multicast_ttl = 1)
                : _impl{nullptr}
        {
            linesender_error* c_err{nullptr};
            _impl = linesender_connect(
                static_cast<linesender_transport>(static_cast<int>(t)),
                interface,
                host,
                port,
                udp_multicast_ttl,
                &c_err);
            if (!_impl)
                throw sender_error::from_c(c_err);
        }

        sender(sender&& other)
            : _impl{other._impl}
        {
            if (this != &other)
                other._impl = nullptr;
        }

        sender& operator=(sender&& other)
        {
            if (this != &other)
            {
                close();
                _impl = other._impl;
                other._impl = nullptr;
            }
            return *this;
        }

        sender(const sender&) = delete;
        sender& operator=(const sender&) = delete;

        sender& table(std::string_view name)
        {
            sender_error::wrapped_call(
                linesender_table,
                _impl,
                name.size(),
                name.data());
            return *this;
        }

        sender& symbol(std::string_view name, std::string_view value)
        {
            sender_error::wrapped_call(
                linesender_symbol,
                _impl,
                name.size(),
                name.data(),
                value.size(),
                value.data());
            return *this;
        }

        sender& column(std::string_view name, bool value)
        {
            sender_error::wrapped_call(
                linesender_column_bool,
                _impl,
                name.size(),
                name.data(),
                value);
            return *this;
        }

        sender& column(std::string_view name, int64_t value)
        {
            sender_error::wrapped_call(
                linesender_column_i64,
                _impl,
                name.size(),
                name.data(),
                value);
            return *this;
        }

        sender& column(std::string_view name, double value)
        {
            sender_error::wrapped_call(
                linesender_column_f64,
                _impl,
                name.size(),
                name.data(),
                value);
            return *this;
        }

        sender& column(std::string_view name, std::string_view value)
        {
            sender_error::wrapped_call(
                linesender_column_str,
                _impl,
                name.size(),
                name.data(),
                value.size(),
                value.data());
            return *this;
        }

        void at(int64_t timestamp_epoch_nanos)
        {
            sender_error::wrapped_call(
                linesender_at,
                _impl,
                timestamp_epoch_nanos);
        }

        void at_now()
        {
            sender_error::wrapped_call(
                linesender_at_now,
                _impl);
        }

        size_t pending_size()
        {
            return _impl
                ? linesender_pending_size(_impl)
                : 0;
        }

        void flush()
        {
            sender_error::wrapped_call(
                linesender_flush,
                _impl);
        }

        bool must_close() noexcept
        {
            return _impl
                ? linesender_must_close(_impl)
                : false;
        }

        void close() noexcept
        {
            if (_impl)
            {
                linesender_close(_impl);
                _impl = nullptr;
            }
        }

        ~sender() noexcept
        {
            close();
        }

    private:
        linesender* _impl;
    };

}
