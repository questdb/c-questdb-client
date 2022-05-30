#include "build_env.h"

// =============================  naming conflicts =============================
// The `strtod` is also sometimes defined in `stdlib.h` (Mingw64).
// As a work-around we include the conflicting library ahead of time.
#include <stdlib.h>
// We then re-name the conflicting symbol, along with all the other ones in case
// third party libraries that are being linked also define these symbols.
#define gethex   dtoalib_gethex
#define strtod   dtoalib_strtod
#define freedtoa dtoalib_freedtoa
#define dtoa_r   dtoalib_dtoa_r
#define dtoa     dtoalib_dtoa
// =============================================================================

// This should work on all architectures with little-endian doubles.
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

#if defined(COMPILER_GCC)
#    pragma GCC diagnostic push
#    pragma GCC diagnostic ignored "-Wsign-compare"
#    pragma GCC diagnostic ignored "-Wimplicit-fallthrough="
#endif

#if defined(COMPILER_CLANG)
#    pragma clang diagnostic push
#    pragma clang diagnostic ignored "-Wsign-compare"
#endif

#include "dtoa.c"

#if defined(COMPILER_GCC)
#    pragma GCC diagnostic pop
#endif

#if defined(COMPILER_CLANG)
#    pragma clang diagnostic pop
#endif

#undef MALLOC
#undef REALLOC
#undef strtod
