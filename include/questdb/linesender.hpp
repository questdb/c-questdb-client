#pragma once

#include "linesender.h"

#include <string>
#include <string_view>
#include <stdexcept>
#include <cstdint>

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

    class sender
    {
    public:
        sender(
            const char* host,
            const char* port,
            const char* net_interface = inaddr_any)
                : _impl{nullptr}
        {
            linesender_error* c_err{nullptr};
            _impl = linesender_connect(
                net_interface,
                host,
                port,
                &c_err);
            if (!_impl)
                throw sender_error::from_c(c_err);
        }

        sender(
            std::string_view host,
            std::string_view port,
            std::string_view net_interface = inaddr_any)
                : sender{
                    std::string{host}.c_str(),
                    std::string{port}.c_str(),
                    std::string{net_interface}.c_str()}
        {}

        sender(
            std::string_view host,
            uint16_t port,
            std::string_view net_interface = inaddr_any)
                : sender{
                    std::string{host}.c_str(),
                    std::to_string(port).c_str(),
                    std::string{net_interface}.c_str()}
        {}

        sender(
            const char* host,
            uint16_t port,
            const char* net_interface = inaddr_any)
                : sender{
                    host,
                    std::to_string(port).c_str(),
                    net_interface}
        {}

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

        // Require specific overloads of `column` to avoid
        // involuntary usage of the `bool` overload.
        template <typename T>
        sender& column(std::string_view name, T value) = delete;

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

        sender& column(std::string_view name, const char* value)
        {
            return column(name, std::string_view{value});
        }

        sender& column(std::string_view name, const std::string& value)
        {
            return column(name, std::string_view{value});
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
