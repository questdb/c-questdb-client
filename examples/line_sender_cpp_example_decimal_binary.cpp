#include <questdb/ingress/line_sender.hpp>
#include <iostream>

using namespace std::literals::string_view_literals;
using namespace questdb::ingress::literals;

static bool example(std::string_view host, std::string_view port)
{
    try
    {
        auto sender = questdb::ingress::line_sender::from_conf(
            "http::addr=" + std::string{host} + ":" + std::string{port} + ";");

        // We prepare all our table names and column names in advance.
        // If we're inserting multiple rows, this allows us to avoid
        // re-validating the same strings over and over again.
        const auto table_name = "cpp_trades_decimal"_tn;
        const auto symbol_name = "symbol"_cn;
        const auto side_name = "side"_cn;
        const auto price_name = "price"_cn;
        const auto amount_name = "amount"_cn;
        const uint8_t price_unscaled_value[] = {123};
        // The table must be created beforehand with the appropriate DECIMAL(N,M) type for the column.
        // 123 with a scale of 1 gives a decimal of 12.3
        const auto price_value =
            questdb::ingress::decimal::decimal_view(1, price_unscaled_value);

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
            std::cerr
                << "Usage:\n"
                << "  " << argv[0] << ": [HOST [PORT]]\n"
                << "    HOST: ILP/HTTP host (defaults to \"localhost\").\n"
                << "    PORT: ILP/HTTP port (defaults to \"9000\")."
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
    auto port = "9000"sv;
    if (argc >= 3)
        port = std::string_view{argv[2]};

    return !example(host, port);
}
