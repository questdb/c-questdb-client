#include <questdb/egress/line_reader.hpp>
#include <iostream>

using namespace questdb::ingress::literals;

int main()
{
    try
    {
        questdb::egress::reader reader{"qwp::addr=localhost:9000;"_utf8};

        auto cur = reader
                       .query(
                           "SELECT $1::int * x AS scaled, $2 AS label "
                           "FROM long_sequence(3)"_utf8)
                       .bind_i32(7)
                       .bind_varchar("widgets"_utf8)
                       .execute();

        while (cur.next_batch())
        {
            const size_t rows = cur.row_count();
            for (size_t r = 0; r < rows; ++r)
            {
                // Print "NULL" rather than a sentinel: `0` for an i32
                // and an empty string for a varchar are valid values
                // and would silently mask SQL NULLs in production
                // output. Branch on the optional's engaged state.
                auto scaled = cur.get_i32(0, r);
                auto label = cur.get_varchar(1, r);
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
