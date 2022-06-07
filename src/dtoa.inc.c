#include "build_env.h"
#include "qdb_lock.h"
#include "qdb_call_once.h"

#if defined(PLATFORM_WINDOWS)
#    include <Windows.h>
#else
#    include <pthread.h>
#endif

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

// A fake thread id.
// We use a counter and re-use values if they fall out of use.
// The counter is accessed by `dtoa` through the `dtoalib_get_current_thread_id`
// which in turn obtains its ID from a thread local.
// We associate one ID per `mem_writer` object, NOT per thread.
// This allows us to clean up ID values despite windows not proving a callback
// on thread exit on thread locals.
typedef unsigned int dtoalib_tid;

static qdb_lock_t dtoalib_tid_lock;
static dtoalib_tid dtoalib_tid_counter = 0;
static size_t dtoalib_tid_free_list_len;
static size_t dtoalib_tid_free_list_capacity;
static dtoalib_tid* dtoalib_tid_free_list;

static void dtoalib_tid_free_list_init()
{
    dtoalib_tid_free_list_len = 0;
    dtoalib_tid_free_list_capacity = 8;
    dtoalib_tid_free_list = aborting_malloc(
        dtoalib_tid_free_list_capacity * sizeof(dtoalib_tid));
}

static int dtoalib_tid_reverse_compare(const void* lhs, const void* rhs)
{
    dtoalib_tid left = (dtoalib_tid)(size_t)lhs;
    dtoalib_tid right = (dtoalib_tid)(size_t)rhs;
    return (int)right - (int)left;
}

static dtoalib_tid dtoalib_acquire_thread_id()
{
    QDB_LOCK_ACQUIRE(&dtoalib_tid_lock);
    if (dtoalib_tid_free_list_len)
    {
        qsort(
            dtoalib_tid_free_list,
            dtoalib_tid_free_list_len,
            sizeof(dtoalib_tid),
            dtoalib_tid_reverse_compare);
        dtoalib_tid id = dtoalib_tid_free_list[--dtoalib_tid_free_list_len];
        QDB_LOCK_RELEASE(&dtoalib_tid_lock);
        return id;
    }
    else
    {
        dtoalib_tid id = dtoalib_tid_counter;
        ++dtoalib_tid_counter;
        QDB_LOCK_RELEASE(&dtoalib_tid_lock);
        return id;
    }
}

static void dtoalib_release_thread_id(dtoalib_tid id)
{
    if (dtoalib_tid_free_list_capacity == dtoalib_tid_free_list_len)
    {
        dtoalib_tid_free_list_capacity *= 2;
        dtoalib_tid_free_list = aborting_realloc(
            dtoalib_tid_free_list,
            dtoalib_tid_free_list_capacity * sizeof(dtoalib_tid));
    }
    dtoalib_tid_free_list[dtoalib_tid_free_list_len++] = id;
}

#if defined(PLATFORM_WINDOWS)
static DWORD tls_key;

static void dtoalib_init_current_thread_id()
{
    tls_key = TlsAlloc();
    if (tls_key == TLS_OUT_OF_INDEXES)
    {
        fprintf(
            stderr,
            "Failed to allocate thread local. GetLastError: %d.\n",
            GetLastError());
        abort();
    }
}

static void dtoalib_set_current_thread_id(dtoalib_tid id)
{
    if (!TlsSetValue(tls_key, (void*)(size_t)(id + 1)))
    {
        fprintf(
            stderr, 
            "Failed setting thread ID local. Error: %d.\n", 
            GetLastError());
        abort();
    }
}

static dtoalib_tid dtoalib_get_current_thread_id()
{
    dtoalib_tid id = (dtoalib_tid)(size_t)TlsGetValue(tls_key);
    if (!id)
    {
        fprintf(
            stderr, 
            "Failed getting thread ID local. Error: %d.\n", 
            GetLastError());
        abort();
    }
    fprintf(stderr, "dtoalib_get_current_thread_id :: (A) %d\n", id - 1);
    return id - 1;
}
#else
static pthread_key_t tls_key;

static void dtoalib_init_current_thread_id()
{
    const int error = pthread_key_create(&tls_key, NULL);
    if (error)
    {
        fprintf(
            stderr, 
            "Failed to create thread local key. Error: %d.\n", 
            error);
        abort();
    }
}

static void dtoalib_set_current_thread_id(dtoalib_tid id)
{
    int error = pthread_setspecific(tls_key, (void*)(id + 1));
    if (error)
    {
        fprintf(
            stderr, 
            "Failed setting thread ID local. Error: %d\n", 
            error);
        abort();
    }
}

static dtoalib_tid dtoalib_get_current_thread_id()
{
    return ((dtoalib_tid)pthread_getspecific(tls_key)) - 1;
}
#endif

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

#define dtoa_get_threadno dtoalib_get_current_thread_id

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
    QDB_LOCK_INIT(&dtoalib_tid_lock);
    QDB_LOCK_INIT(&lock0);
    QDB_LOCK_INIT(&lock1);

    dtoalib_tid_free_list_init();
    dtoalib_init_current_thread_id();
    dtoalib_set_max_dtoa_threads(32);
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
