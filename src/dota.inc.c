#define IEEE_8087 1
#define MALLOC aborting_malloc
#define REALLOC aborting_realloc
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough="
#include "dota.c"
#pragma GCC diagnostic pop
#pragma GCC diagnostic pop
