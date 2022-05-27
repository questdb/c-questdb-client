#include "build_env.h"

#define IEEE_8087 1

#define MALLOC aborting_malloc
#define REALLOC aborting_realloc

#if defined(COMPILER_MSVC)
#    pragma warning( push )
#    pragma warning( disable : 4244 )
#    pragma warning( disable : 4273 )
#    pragma warning( disable : 4146 )
#    pragma warning( disable : 4334 )
#    pragma warning( disable : 4706 )
#    pragma warning( disable : 4701 )
#    pragma warning( disable : 4703 )
#endif

#if defined(COMPILER_GNUC)
#    pragma GCC diagnostic ignored "-Wsign-compare"
#    pragma GCC diagnostic ignored "-Wimplicit-fallthrough="
#endif

#include "dota.c"

#if defined(COMPILER_GNUC)
#    pragma GCC diagnostic pop
#    pragma GCC diagnostic pop
#endif

#undef MALLOC
#undef REALLOC
