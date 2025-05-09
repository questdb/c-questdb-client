#include <questdb/ingress/line_sender.hpp>
#include <iostream>

using namespace std::literals::string_view_literals;
using namespace questdb::ingress::literals;

int main(int argc, const char* argv[])
{
    try
    {
        auto sender = questdb::ingress::line_sender::from_conf(
            "tcp::addr=localhost:9009;");

        // We prepare all our table names and column names in advance.
        // If we're inserting multiple rows, this allows us to avoid
        // re-validating the same strings over and over again.
        const auto table_name = "cpp_trades_from_conf"_tn;
        const auto symbol_name = "symbol"_cn;
        const auto side_name = "side"_cn;
        const auto price_name = "price"_cn;
        const auto amount_name = "amount"_cn;

        questdb::ingress::line_sender_buffer buffer;
        buffer.table(table_name)
            .symbol(symbol_name, "ETH-USD"_utf8)
            .symbol(side_name, "sell"_utf8)
            .column(price_name, 2615.54)
            .column(amount_name, 0.00044)
            .at(questdb::ingress::timestamp_nanos::now());

        // To insert more records, call `buffer.table(..)...` again.

        sender.flush(buffer);

        // It's recommended to keep a timer and/or maximum buffer size to flush
        // the buffer periodically with any accumulated records.

        return 0;
    }
    catch (const questdb::ingress::line_sender_error& err)
    {
        std::cerr << "Error running example: " << err.what() << std::endl;

        return 1;
    }
}
