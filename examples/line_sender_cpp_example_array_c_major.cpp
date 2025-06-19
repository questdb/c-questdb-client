#include <questdb/ingress/line_sender.hpp>
#include <iostream>
#include <vector>

using namespace std::literals::string_view_literals;
using namespace questdb::ingress::literals;

/*
 * QuestDB server version 8.4.0 or later is required for array support.
 */
static bool array_example(std::string_view host, std::string_view port)
{
    try
    {
        auto sender = questdb::ingress::line_sender::from_conf(
            "tcp::addr=" + std::string{host} + ":" + std::string{port} +
            ";protocol_version=2;");

        const auto table_name = "cpp_market_orders_c_major"_tn;
        const auto symbol_col = "symbol"_cn;
        const auto book_col = "order_book"_cn;
        size_t rank = 3;
        std::vector<uintptr_t> shape{2, 3, 2};
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

        questdb::ingress::array::row_major_view<double> book_data{
            rank, shape.data(), arr_data.data(), arr_data.size()};

        questdb::ingress::line_sender_buffer buffer = sender.new_buffer();
        buffer.table(table_name)
            .symbol(symbol_col, "BTC-USD"_utf8)
            .column(book_col, book_data)
            .at(questdb::ingress::timestamp_nanos::now());
        sender.flush(buffer);
        return true;
    }
    catch (const questdb::ingress::line_sender_error& err)
    {
        std::cerr << "[ERROR] " << err.what() << std::endl;
        return false;
    }
}

int main(int argc, const char* argv[])
{
    auto host = "localhost"sv;
    if (argc >= 2)
        host = std::string_view{argv[1]};

    auto port = "9009"sv;
    if (argc >= 3)
        port = std::string_view{argv[2]};

    return !array_example(host, port);
}
