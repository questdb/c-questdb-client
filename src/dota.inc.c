#include "build_env.h"

// ================== dota.c's `strtod` naming conflict ======================
// The `strtod` is also sometimes defined in `stdlib.h`. Workaround:
// (1) First including the conflicting library ahead of time.
#include <stdlib.h>
// (2) Using a define to use another name during the compile time of `dota.c`.
#define strtod dota_strtod
// ===========================================================================

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
#undef strtod
