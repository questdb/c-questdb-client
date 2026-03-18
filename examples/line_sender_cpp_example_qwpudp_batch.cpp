#include <questdb/ingress/line_sender.hpp>
#include <iostream>

using namespace std::literals::string_view_literals;
using namespace questdb::ingress::literals;

static bool example(
    std::string_view host,
    std::string_view port,
    std::string_view table_name)
{
    try
    {
        auto sender = questdb::ingress::line_sender::from_conf(
            "qwpudp::addr=" + std::string{host} + ":" + std::string{port} +
            ";max_datagram_size=256;");

        questdb::ingress::line_sender_buffer buffer = sender.new_buffer();
        const auto table = questdb::ingress::table_name_view{table_name};
        buffer.table(table)
            .symbol("host"_cn, "srv-a"_utf8)
            .column("active"_cn, true)
            .column("qty"_cn, int64_t{1})
            .column("temp"_cn, 20.5)
            .column("note"_cn, "batch-a"_utf8)
            .at_now();

        buffer.table(table)
            .symbol("host"_cn, "srv-b"_utf8)
            .column("active"_cn, false)
            .column("qty"_cn, int64_t{2})
            .column("temp"_cn, 22.5)
            .column("note"_cn, "batch-b"_utf8)
            .at_now();

        sender.flush(buffer);
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
                << "line_sender_cpp_example_qwpudp_batch: [HOST [PORT [TABLE]]]\n"
                << "    HOST: QWP/UDP host (defaults to \"localhost\").\n"
                << "    PORT: QWP/UDP port (defaults to \"9007\").\n"
                << "    TABLE: Target table (defaults to \"cpp_qwpudp_batch_example\")."
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
    auto port = "9007"sv;
    if (argc >= 3)
        port = std::string_view{argv[2]};
    auto table_name = "cpp_qwpudp_batch_example"sv;
    if (argc >= 4)
        table_name = std::string_view{argv[3]};

    return !example(host, port, table_name);
}
