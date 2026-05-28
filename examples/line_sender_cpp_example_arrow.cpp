#include <questdb/ingress/line_sender.hpp>

#include <arrow/array/builder_primitive.h>
#include <arrow/c/bridge.h>
#include <arrow/record_batch.h>
#include <arrow/status.h>
#include <arrow/table.h>
#include <arrow/type.h>

#include <cstdio>
#include <memory>
#include <string>

namespace {

namespace qdb = questdb::ingress;

std::shared_ptr<arrow::RecordBatch> build_batch()
{
    auto pool = arrow::default_memory_pool();
    arrow::TimestampBuilder ts_b(
        arrow::timestamp(arrow::TimeUnit::MICRO, "UTC"), pool);
    arrow::DoubleBuilder price_b(pool);

    constexpr int64_t base = 1700000000000000LL;
    ts_b.AppendValues({base, base + 1, base + 2}).ok();
    price_b.AppendValues({2615.54, 2615.55, 2615.50}).ok();

    std::shared_ptr<arrow::Array> ts_arr, price_arr;
    ts_b.Finish(&ts_arr).ok();
    price_b.Finish(&price_arr).ok();

    auto schema = arrow::schema(
        {arrow::field("ts", ts_arr->type()),
         arrow::field("price", arrow::float64())});
    return arrow::RecordBatch::Make(schema, ts_arr->length(), {ts_arr, price_arr});
}

bool example(const std::string& host, const std::string& port)
{
    try
    {
        const std::string conf_str = "qwpws::addr=" + host + ":" + port + ";";
        auto sender = qdb::line_sender::from_conf(conf_str);
        auto buffer = sender.new_buffer();

        auto batch = build_batch();
        ArrowArray c_arr{};
        ArrowSchema c_sch{};
        auto st = arrow::ExportRecordBatch(*batch, &c_arr, &c_sch);
        if (!st.ok())
        {
            std::fprintf(stderr, "ExportRecordBatch: %s\n", st.ToString().c_str());
            return false;
        }

        // Designated timestamp pulled from the "ts" column. `c_arr` is
        // consumed by the call; `c_sch` is borrowed (we release it).
        buffer.append_arrow(
            "cpp_arrow_trades", c_arr, c_sch, qdb::column_name_view{"ts"});
        if (c_sch.release)
            c_sch.release(&c_sch);

        sender.flush(buffer);
        return true;
    }
    catch (const qdb::line_sender_error& e)
    {
        std::fprintf(stderr, "Error: %s\n", e.what());
        return false;
    }
}

} // namespace

int main(int argc, const char* argv[])
{
    const std::string host = (argc >= 2) ? argv[1] : "localhost";
    const std::string port = (argc >= 3) ? argv[2] : "9000";
    return example(host, port) ? 0 : 1;
}
