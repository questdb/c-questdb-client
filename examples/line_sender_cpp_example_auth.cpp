#include <questdb/ingress/line_sender.hpp>
#include <iostream>

using namespace std::literals::string_view_literals;
using namespace questdb::ingress::literals;

static bool example(std::string_view host, std::string_view port)
{
    try
    {
        // Follow our authentication documentation to generate your own keys:
        // https://questdb.io/docs/reference/api/ilp/authenticate
        questdb::ingress::opts opts{host, port};
        opts.auth(
            "testUser1",  // key_id
            "5UjEMuA0Pj5pjK8a-fa24dyIf-Es5mYny3oE_Wmus48",  // priv_key
            "fLKYEaoEb9lrn3nkwLDA-M_xnuFOdSt9y0Z7_vWSHLU",  // pub_key_x
            "Dt5tbS1dEDMSYfym3fgMv0B99szno-dFc1rYF9t0aac");  // pub_key_y

        // Connect.
        questdb::ingress::line_sender sender{opts};

        // We prepare all our table names and column names in advance.
        // If we're inserting multiple rows, this allows us to avoid
        // re-validating the same strings over and over again.
        const auto table_name = "cpp_cars_auth"_tn;
        const auto id_name = "id"_cn;
        const auto x_name = "x"_cn;
        const auto y_name = "y"_cn;
        const auto booked_name = "booked"_cn;
        const auto passengers_name = "passengers"_cn;
        const auto driver_name = "driver"_cn;

        questdb::ingress::line_sender_buffer buffer;
        // 1997-07-04 04:56:55 UTC
        questdb::ingress::timestamp_nanos designated_timestamp{867992215000000000};
        buffer
            .table(table_name)
            .symbol(id_name, "d6e5fe92-d19f-482a-a97a-c105f547f721"_utf8)
            .column(x_name, 30.5)
            .column(y_name, -150.25)
            .column(booked_name, true)
            .column(passengers_name, int64_t{3})
            .column(driver_name, "John Doe"_utf8)
            .at(designated_timestamp);

        // Call `.at(timestamp_nanos::now())` to use the current system time.

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
                <<  "Usage:\n"
                <<  "line_sender_c_example: [HOST [PORT]]\n"
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
