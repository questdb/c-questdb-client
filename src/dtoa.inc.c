#include "build_env.h"
#include "qdb_lock.h"
#include "qdb_call_once.h"
#include "qdb_thread_id.h"

// =============================  naming conflicts =============================
// The `strtod` is also sometimes defined in `stdlib.h` (Mingw64).
// As a work-around we include the conflicting library ahead of time.
#include <stdlib.h>
// We then re-name the conflicting symbol, along with all the other ones in case
// third party libraries that are being linked also define these symbols.
#define set_max_dtoa_threads dtoalib_set_max_dtoa_threads
#define gethex               dtoalib_gethex
#define strtod               dtoalib_strtod
#define freedtoa             dtoalib_freedtoa
#define dtoa_r               dtoalib_dtoa_r
#define dtoa                 dtoalib_dtoa
// =============================================================================

// This should work on all architectures with little-endian doubles.
#define IEEE_8087 1

static void* malloc_log(size_t size)
{
    void* p = aborting_malloc(size);
    fprintf(stderr, "malloc_log :: (A) size: %zu, p: %p\n", size, p);
    return p;
}

static void* realloc_log(void* p, size_t size)
{
    void* p2 = aborting_realloc(p, size);
    fprintf(stderr, "realloc_log :: (A) p: %p, size: %zu, p2: %p\n", p, size, p2);
    return p2;
}

static void free_log(void* p)
{
    fprintf(stderr, "free_log :: (A) p: %p\n", p);
    free(p);
}

#define MALLOC malloc_log
#define REALLOC realloc_log
#define FREE free_log

#define MULTIPLE_THREADS 1

static qdb_lock_t lock0;
static qdb_lock_t lock1;

static void dtoa_inc_lock(int n)
{
    fprintf(stderr, "dtoa_inc_lock :: (A) n: %d\n", n);
    if (n == 0)
        QDB_LOCK_ACQUIRE(&lock0);
    else
        QDB_LOCK_ACQUIRE(&lock1);
}

static void dtoa_inc_free_lock(int n)
{
    fprintf(stderr, "dtoa_inc_free_lock :: (A) n: %d\n", n);
    if (n == 0)
        QDB_LOCK_RELEASE(&lock0);
    else
        QDB_LOCK_RELEASE(&lock1);
}

#define ACQUIRE_DTOA_LOCK dtoa_inc_lock
#define FREE_DTOA_LOCK dtoa_inc_free_lock

#define dtoa_get_threadno qdb_thread_id

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

static void init_impl()
{
    QDB_LOCK_INIT(&lock0);
    QDB_LOCK_INIT(&lock1);

    qdb_thread_id_init();
    dtoalib_set_max_dtoa_threads(16);
}

static qdb_call_once_flag init_flag;

static void dtoa_inc_init()
{
    qdb_call_once(&init_flag, init_impl);
}

#undef MALLOC
#undef REALLOC
#undef MULTIPLE_THREADS
#undef ACQUIRE_DTOA_LOCK
#undef FREE_DTOA_LOCK
#undef dtoa_get_threadno
