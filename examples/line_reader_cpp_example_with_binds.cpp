#include <questdb/egress/line_reader.hpp>
#include <iostream>

using namespace questdb::ingress::literals;

int main()
{
    try
    {
        questdb::egress::reader reader{"ws::addr=localhost:9000;"_utf8};

        auto cur = reader
                       .prepare(
                           "SELECT $1::int * x AS scaled, $2 AS label "
                           "FROM long_sequence(3)"_utf8)
                       .bind_i32(7)
                       .bind_varchar("widgets"_utf8)
                       .execute();

        while (auto bo = cur.next_batch())
        {
            auto& batch = *bo;
            auto col_scaled = batch.column(0);
            auto col_label = batch.column(1);
            const size_t rows = batch.row_count();
            for (size_t r = 0; r < rows; ++r)
            {
                // Print "NULL" rather than a sentinel: `0` for an i32
                // and an empty string for a varchar are valid values
                // and would silently mask SQL NULLs in production
                // output. Branch on the optional's engaged state.
                auto scaled = col_scaled.get<int64_t>(r);
                auto label = col_label.varchar(r);
                std::cout << "scaled=";
                if (scaled) std::cout << *scaled; else std::cout << "NULL";
                std::cout << " label=";
                if (label) std::cout << *label; else std::cout << "NULL";
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
