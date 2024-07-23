#include <questdb/ingress/line_sender.hpp>
#include <iostream>

using namespace std::literals::string_view_literals;
using namespace questdb::ingress::literals;

static bool example(
    std::string_view ca_path,
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
            "token_y=Dt5tbS1dEDMSYfym3fgMv0B99szno-dFc1rYF9t0aac;"
            "tls_roots=" + std::string{ca_path} + ";");  // path to custom `.pem` file.

        // We prepare all our table names and column names in advance.
        // If we're inserting multiple rows, this allows us to avoid
        // re-validating the same strings over and over again.
        const auto table_name = "trades"_tn;
        const auto symbol_name = "symbol"_cn;
        const auto side_name = "side"_cn;
        const auto price_name = "price"_cn;
        const auto amount_name = "amount"_cn;

        questdb::ingress::line_sender_buffer buffer;
        buffer
            .table(table_name)
            .symbol(symbol_name, "ETH-USD"_utf8)
            .symbol(side_name, "sell"_utf8)
            .column(price_name, 2615.54)
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
                << "    CA_PATH: Certificate authority pem file.\n"
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

    if (argc < 2)
    {
        std::cerr << "CA_PATH required." << std::endl;
        return 1;
    }
    auto ca_path = std::string_view{argv[1]};

    auto host = "localhost"sv;
    if (argc >= 3)
        host = std::string_view{argv[2]};
    auto port = "9009"sv;
    if (argc >= 4)
        port = std::string_view{argv[3]};

    return !example(ca_path, host, port);
}
