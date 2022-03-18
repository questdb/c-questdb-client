#include <questdb/line_sender.hpp>
#include <iostream>

using namespace std::literals::string_view_literals;

static bool example(std::string_view host, std::string_view port)
{
    try
    {
        questdb::line_sender sender{host, port};

        sender
            .table("cpp_cars"sv)
            .symbol("id"sv, "d6e5fe92-d19f-482a-a97a-c105f547f721"sv)
            .column("x"sv, 30.5)
            .column("y"sv, -150.25)
            .column("booked"sv, true)
            .column("passengers"sv, int64_t{3})
            .column("driver"sv, "Ranjit Singh"sv)
            .at_now();

        // To insert more records, call `sender.table(..)...` again.

        sender.flush();

        return true;
    }
    catch (const questdb::line_sender_error& err)
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
                << "    HOST: ILP host (defaults to \"localhost\".\n"
                << "    PORT: ILP port (defaults to \"9009\"."
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
