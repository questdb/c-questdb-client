#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <questdb/token_provider.h>

#include <memory>
#include <stdexcept>
#include <string>

namespace
{
bool oversized_copy = false;
size_t token_frees = 0;

size_t token_copy_len(const questdb_token* token)
{
    // Force the string constructor to throw without exhausting memory.
    return oversized_copy ? std::string{}.max_size() + 1
                          : ::questdb_token_len(token);
}

void token_copy_free(questdb_token* token)
{
    if (token)
        ++token_frees;
    ::questdb_token_free(token);
}
} // namespace

// Keep the real native provider; observe cleanup only in this wrapper's copy.
#define questdb_token_len token_copy_len
#define questdb_token_free token_copy_free
#include <questdb/token_provider.hpp>
#undef questdb_token_free
#undef questdb_token_len

namespace
{
class fixed_provider : public questdb::bearer_token_provider
{
public:
    std::string token() override
    {
        return "synthetic-token";
    }
};
} // namespace

TEST_CASE("A token copy frees its native token on success and on exception")
{
    token_frees = 0;
    auto provider =
        questdb::token_provider::from(std::make_shared<fixed_provider>());

    CHECK(provider.token() == "synthetic-token");
    CHECK(token_frees == 1);

    oversized_copy = true;
    CHECK_THROWS_AS(provider.token(), std::length_error);
    oversized_copy = false;
    CHECK(token_frees == 2);

    CHECK(provider.token() == "synthetic-token");
    CHECK(token_frees == 3);
}
