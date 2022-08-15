#include <questdb/ilp/line_sender.hpp>
#include <iostream>

using namespace std::literals::string_view_literals;
using namespace questdb::ilp::literals;

static bool example(std::string_view host, std::string_view port)
{
    try
    {
        // Connect.
        questdb::ilp::line_sender sender{host, port};

        // We prepare all our table names and column names in advance.
        // If we're inserting multiple rows, this allows us to avoid
        // re-validating the same strings over and over again.
        const auto table_name = "cpp_cars"_tn;
        const auto id_name = "id"_cn;
        const auto x_name = "x"_cn;
        const auto y_name = "y"_cn;
        const auto booked_name = "booked"_cn;
        const auto passengers_name = "passengers"_cn;
        const auto driver_name = "driver"_cn;

        questdb::ilp::line_sender_buffer buffer;
        buffer
            .table(table_name)
            .symbol(id_name, "d6e5fe92-d19f-482a-a97a-c105f547f721"_utf8)
            .column(x_name, 30.5)
            .column(y_name, -150.25)
            .column(booked_name, true)
            .column(passengers_name, int64_t{3})
            .column(driver_name, "John Doe"_utf8)
            .at_now();

        // To insert more records, call `buffer.table(..)...` again.

        sender.flush(buffer);

        return true;
    }
    catch (const questdb::ilp::line_sender_error& err)
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
