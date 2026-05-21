#include <questdb/egress/line_reader.hpp>
#include <iostream>

using namespace questdb::ingress::literals;

int main()
{
    try
    {
        auto reader =
            questdb::egress::reader::open("ws::addr=localhost:9000;");
        auto cur = reader.execute(
            "SELECT x AS n, x * 1.5 AS d FROM long_sequence(5)"_utf8);

        while (auto bo = cur.next_batch())
        {
            auto& batch = *bo;
            const size_t rows = batch.row_count();
            const size_t cols = batch.column_count();
            for (size_t r = 0; r < rows; ++r)
            {
                for (size_t c = 0; c < cols; ++c)
                {
                    auto col = batch.column(c);
                    const auto k = col.kind();
                    if (k == questdb::egress::column_kind::long_)
                    {
                        auto v = col.get<int64_t>(r);
                        if (v) std::cout << *v << " ";
                        else std::cout << "NULL ";
                    }
                    else if (k == questdb::egress::column_kind::double_)
                    {
                        auto v = col.get<double>(r);
                        if (v) std::cout << *v << " ";
                        else std::cout << "NULL ";
                    }
                    else
                    {
                        std::cout << "(kind=0x" << std::hex
                                  << static_cast<unsigned>(k) << std::dec
                                  << ") ";
                    }
                }
                std::cout << "\n";
            }
        }
        return 0;
    }
    catch (const questdb::egress::line_reader_error& e)
    {
        std::cerr << "Error (code " << static_cast<int>(e.code())
                  << "): " << e.what() << "\n";
        return 1;
    }
}
