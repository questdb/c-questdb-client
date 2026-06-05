#include <questdb/ingress/column_sender.h>
#include <questdb/ingress/column_sender.hpp>
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
using namespace questdb::ingress::literals;

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
    const std::string conf_str = "qwpws::addr=" + host + ":" + port + ";";
    ::line_sender_error* err = nullptr;
    ::questdb_db* db =
        ::questdb_db_connect(conf_str.data(), conf_str.size(), &err);
    if (!db)
    {
        std::fprintf(
            stderr, "questdb_db_connect: %s\n",
            ::line_sender_error_msg(err, nullptr));
        ::line_sender_error_free(err);
        return false;
    }
    ::qwpws_conn* raw_conn = ::questdb_db_borrow_conn(db, &err);
    if (!raw_conn)
    {
        std::fprintf(
            stderr, "questdb_db_borrow_conn: %s\n",
            ::line_sender_error_msg(err, nullptr));
        ::line_sender_error_free(err);
        ::questdb_db_close(db);
        return false;
    }

    struct arrow_c_guard
    {
        ArrowArray& a;
        ArrowSchema& s;
        ~arrow_c_guard()
        {
            if (a.release)
                a.release(&a);
            if (s.release)
                s.release(&s);
        }
    };

    bool ok = false;
    try
    {
        auto batch = build_batch();
        ArrowArray c_arr{};
        ArrowSchema c_sch{};
        auto st = arrow::ExportRecordBatch(*batch, &c_arr, &c_sch);
        if (!st.ok())
        {
            std::fprintf(stderr, "ExportRecordBatch: %s\n", st.ToString().c_str());
        }
        else
        {
            arrow_c_guard guard{c_arr, c_sch};
            qdb::column_sender_conn conn{raw_conn};
            conn.flush_arrow_batch("cpp_arrow_trades"_tn, c_arr, c_sch, "ts"_cn);
            if (!::column_sender_sync(raw_conn, ::column_sender_ack_level_ok, &err))
            {
                std::fprintf(
                    stderr, "column_sender_sync: %s\n",
                    ::line_sender_error_msg(err, nullptr));
                ::line_sender_error_free(err);
            }
            else
            {
                ok = true;
            }
        }
    }
    catch (const qdb::line_sender_error& e)
    {
        std::fprintf(stderr, "Error: %s\n", e.what());
    }

    if (::qwpws_conn_must_close(raw_conn))
        ::questdb_db_drop_conn(db, raw_conn);
    else
        ::questdb_db_return_conn(db, raw_conn);
    ::questdb_db_close(db);
    return ok;
}

} // namespace

int main(int argc, const char* argv[])
{
    const std::string host = (argc >= 2) ? argv[1] : "localhost";
    const std::string port = (argc >= 3) ? argv[2] : "9000";
    return example(host, port) ? 0 : 1;
}
