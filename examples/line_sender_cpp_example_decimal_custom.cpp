#include <questdb/ingress/line_sender.hpp>
#include <iostream>

using namespace std::literals::string_view_literals;
using namespace questdb::ingress::literals;
using namespace questdb::ingress::decimal;

struct ViewHolder
{
    std::array<uint8_t, sizeof(uint32_t)> data;
    uint32_t scale;
    questdb::ingress::decimal::binary_view view() const
    {
        return {scale, data};
    }
};

namespace custom_decimal
{
class Decimal32
{
public:
    Decimal32(uint32_t scale, int32_t unscaled_value)
        : _scale(scale)
        , _unscaled_value(unscaled_value)
    {
    }

    int32_t unscaled_value() const
    {
        return _unscaled_value;
    }

    uint32_t scale() const
    {
        return _scale;
    }

private:
    uint32_t _scale;
    int32_t _unscaled_value;
};

// Customization point for QuestDB decimal API (discovered via König lookup)
// If you need to support a 3rd party type, put this function in the namespace
// of the type in question or in the `questdb::ingress::decimal` namespace
inline auto to_decimal_view_state_impl(const Decimal32& d)
{
    int32_t unscaled_value = d.unscaled_value();
    return ViewHolder{
        {
            // Big-Endian bytes
            static_cast<uint8_t>(unscaled_value >> 24),
            static_cast<uint8_t>(unscaled_value >> 16),
            static_cast<uint8_t>(unscaled_value >> 8),
            static_cast<uint8_t>(unscaled_value >> 0),
        },
        d.scale()};
}
}

static bool example(std::string_view host, std::string_view port)
{
    try
    {
        auto sender = questdb::ingress::line_sender::from_conf(
            "tcp::addr=" + std::string{host} + ":" + std::string{port} +
            ";protocol_version=2;");

        // We prepare all our table names and column names in advance.
        // If we're inserting multiple rows, this allows us to avoid
        // re-validating the same strings over and over again.
        const auto table_name = "cpp_trades"_tn;
        const auto symbol_name = "symbol"_cn;
        const auto side_name = "side"_cn;
        const auto price_name = "price"_cn;
        const auto amount_name = "amount"_cn;

        // 123 with a scale of 1 gives a decimal of 12.3
        const auto price_value = custom_decimal::Decimal32(1, 123);

        questdb::ingress::line_sender_buffer buffer = sender.new_buffer();
        buffer.table(table_name)
            .symbol(symbol_name, "ETH-USD"_utf8)
            .symbol(side_name, "sell"_utf8)
            .column(price_name, price_value)
            .column(amount_name, 0.00044)
            .at(questdb::ingress::timestamp_nanos::now());

        // To insert more records, call `buffer.table(..)...` again.

        sender.flush(buffer);

        // It's recommended to keep a timer and/or maximum buffer size to flush
        // the buffer periodically with any accumulated records.

        return true;
    }
    catch (const questdb::ingress::line_sender_error& err)
    {
        std::cerr << "Error running example: " << err.what() << std::endl;

        return false;
    }
}

static bool displayed_help(int argc, const char* argv[])
{
    for (int index = 1; index < argc; ++index)
    {
        const std::string_view arg{argv[index]};
        if ((arg == "-h"sv) || (arg == "--help"sv))
        {
            std::cerr << "Usage:\n"
                      << "line_sender_c_example: [HOST [PORT]]\n"
                      << "    HOST: ILP host (defaults to \"localhost\").\n"
                      << "    PORT: ILP port (defaults to \"9009\")."
                      << std::endl;
            return true;
        }
    }
    return false;
}

int main(int argc, const char* argv[])
{
    if (displayed_help(argc, argv))
        return 0;

    auto host = "localhost"sv;
    if (argc >= 2)
        host = std::string_view{argv[1]};
    auto port = "9009"sv;
    if (argc >= 3)
        port = std::string_view{argv[2]};

    return !example(host, port);
}
