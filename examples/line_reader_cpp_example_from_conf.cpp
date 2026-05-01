#include <questdb/egress/line_reader.hpp>
#include <iostream>

using namespace questdb::ingress::literals;

int main()
{
    try
    {
        questdb::egress::reader reader{"qwp::addr=localhost:9000;"_utf8};
        auto cur = reader.execute(
            "SELECT x AS n, x * 1.5 AS d FROM long_sequence(5)"_utf8);

        while (cur.next_batch())
        {
            const size_t rows = cur.row_count();
            const size_t cols = cur.column_count();
            for (size_t r = 0; r < rows; ++r)
            {
                for (size_t c = 0; c < cols; ++c)
                {
                    const auto k = cur.column_kind(c);
                    if (k == line_reader_column_kind_long)
                    {
                        auto v = cur.get_i64(c, r);
                        if (v) std::cout << *v << " ";
                        else std::cout << "NULL ";
                    }
                    else if (k == line_reader_column_kind_double)
                    {
                        auto v = cur.get_f64(c, r);
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
