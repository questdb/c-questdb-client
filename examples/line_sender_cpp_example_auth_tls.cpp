#include <questdb/ingress/line_sender.hpp>
#include <iostream>

using namespace std::literals::string_view_literals;
using namespace questdb::ingress::literals;

static bool example(
    std::string_view host,
    std::string_view port)
{
    try
    {
        auto sender = questdb::ingress::line_sender::from_conf(
            "tcps::addr=" + std::string{host} + ":" + std::string{port} + ";"
            "username=admin;"
            "token=5UjEMuA0Pj5pjK8a-fa24dyIf-Es5mYny3oE_Wmus48;"
            "token_x=fLKYEaoEb9lrn3nkwLDA-M_xnuFOdSt9y0Z7_vWSHLU;"
            "token_y=Dt5tbS1dEDMSYfym3fgMv0B99szno-dFc1rYF9t0aac;");

        // We prepare all our table names and column names in advance.
        // If we're inserting multiple rows, this allows us to avoid
        // re-validating the same strings over and over again.
        const auto table_name = "cpp_trades_auth_tls"_tn;
        const auto symbol_name = "symbol"_cn;
        const auto side_name = "side"_cn;
        const auto price_name = "price"_cn;
        const auto amount_name = "amount"_cn;
        const auto order_book_name = "order_book"_cn;
        size_t rank = 3;
        std::vector<uint32_t> shape{2, 3, 2};
        std::vector<int32_t> strides{48, 16, 8};
        std::array<double, 12> arr_data = {
            48123.5,
            2.4,
            48124.0,
            1.8,
            48124.5,
            0.9,
            48122.5,
            3.1,
            48122.0,
            2.7,
            48121.5,
            4.3};

        questdb::ingress::line_sender_buffer buffer;
        buffer
            .table(table_name)
            .symbol(symbol_name, "ETH-USD"_utf8)
            .symbol(side_name, "sell"_utf8)
            .column(price_name, 2615.54)
            .column(amount_name, 0.00044)
            .column(order_book_name, 3, shape, strides, arr_data)
            .at(questdb::ingress::timestamp_nanos::now());

        // To insert more records, call `buffer.table(..)...` again.

        sender.flush(buffer);

        // It's recommended to keep a timer and/or maximum buffer size to flush
        // the buffer periodically with any accumulated records.

        return true;
    }
    catch (const questdb::ingress::line_sender_error& err)
    {
        std::cerr
            << "Error running example: "
            << err.what()
            << std::endl;

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
                      << "line_sender_c_example: CA_PATH [HOST [PORT]]\n"
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
