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
            "udp::addr=" + std::string{host} + ":" + std::string{port} +
            ";max_datagram_size=256;");

        questdb::ingress::line_sender_buffer buffer = sender.new_buffer();
        buffer.table(questdb::ingress::table_name_view{table_name})
            .symbol("host"_cn, "srv-api"_utf8)
            .column("active"_cn, true)
            .column("qty"_cn, int64_t{7})
            .column_i8("retries"_cn, int8_t{3})
            .column_i16("port"_cn, int16_t{9009})
            .column_i32("region"_cn, int32_t{42})
            .column_f32("temp_f"_cn, 21.5f)
            .column("temp"_cn, 21.5)
            .column_uuid("trace_id"_cn, 0x0102030405060708ULL, 0x090A0B0C0D0E0F10ULL)
            .column_date("first_seen"_cn, int64_t{1700000000000})
            .column_dec64("price"_cn, "1.25"sv)
            .column_geohash("loc"_cn, uint64_t{0x012EA85B}, uint8_t{25})
            .column("note"_cn, "example-row"_utf8)
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
                << "line_sender_cpp_example_udp: [HOST [PORT [TABLE]]]\n"
                << "    HOST: QWP/UDP host (defaults to \"localhost\").\n"
                << "    PORT: QWP/UDP port (defaults to \"9007\").\n"
                << "    TABLE: Target table (defaults to \"cpp_udp_example\")."
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
    auto table_name = "cpp_udp_example"sv;
    if (argc >= 4)
        table_name = std::string_view{argv[3]};

    return !example(host, port, table_name);
}
