#include <questdb/egress/reader.hpp>

#include <arrow/array.h>
#include <arrow/c/bridge.h>
#include <arrow/pretty_print.h>
#include <arrow/record_batch.h>
#include <arrow/result.h>
#include <arrow/status.h>

#include <cstdio>
#include <iostream>
#include <string>

namespace {

namespace egress = questdb::egress;
namespace ingress = questdb::ingress;

bool example()
{
    try
    {
        egress::reader reader{ingress::utf8_view{"ws::addr=localhost:9000;"}};
        auto cursor = reader.execute(ingress::utf8_view{
            "SELECT x AS n, x * 1.5 AS d FROM long_sequence(5)"});

        while (auto batch = cursor.next_arrow_batch())
        {
            // `arrow::ImportRecordBatch` consumes the release callbacks on
            // success; both `batch->array.release` and
            // `batch->schema.release` are zeroed by Arrow afterwards.
            auto rb_res =
                arrow::ImportRecordBatch(&batch->array, &batch->schema);
            if (!rb_res.ok())
            {
                std::fprintf(
                    stderr, "ImportRecordBatch: %s\n",
                    rb_res.status().ToString().c_str());
                if (batch->array.release)
                    batch->array.release(&batch->array);
                if (batch->schema.release)
                    batch->schema.release(&batch->schema);
                return false;
            }
            const auto& rb = *rb_res;
            std::cout << rb->schema()->ToString() << "\n";
            auto pp = arrow::PrettyPrint(*rb, {}, &std::cout);
            (void)pp;
            std::cout << "\n";
        }
        return true;
    }
    catch (const questdb::error& e)
    {
        std::fprintf(stderr, "Error: %s\n", e.what());
        return false;
    }
    catch (const ingress::line_sender_error& e)
    {
        std::fprintf(stderr, "Error: %s\n", e.what());
        return false;
    }
}

} // namespace

int main(int argc, const char* argv[])
{
    (void)argc;
    (void)argv;
    return example() ? 0 : 1;
}
