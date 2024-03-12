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
        const auto table_name = "cpp_cars_from_conf"_tn;
        const auto id_name = "id"_cn;
        const auto x_name = "x"_cn;
        const auto y_name = "y"_cn;
        const auto booked_name = "booked"_cn;
        const auto passengers_name = "passengers"_cn;
        const auto driver_name = "driver"_cn;

        questdb::ingress::line_sender_buffer buffer;
        buffer
            .table(table_name)
            .symbol(id_name, "d6e5fe92-d19f-482a-a97a-c105f547f721"_utf8)
            .column(x_name, 30.5)
            .column(y_name, -150.25)
            .column(booked_name, true)
            .column(passengers_name, int64_t{3})
            .column(driver_name, "John Doe"_utf8)
            .at(questdb::ingress::timestamp_nanos::now());

        // To insert more records, call `buffer.table(..)...` again.

        sender.flush(buffer);

        // It's recommended to keep a timer and/or maximum buffer size to flush
        // the buffer periodically with any accumulated records.

        return 0;
    }
    catch (const questdb::ingress::line_sender_error& err)
    {
        std::cerr
            << "Error running example: "
            << err.what()
            << std::endl;

        return 1;
    }
}
