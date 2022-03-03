#pragma once

#include <stdint.h>
#include <inttypes.h>

#if defined(__unix__) || defined(__APPLE__)
#    define PLATFORM_UNIX
#elif defined(_WIN32) || defined(WIN32)
#    define PLATFORM_WINDOWS
#else
#    error Platform detection failed.
#endif

#if defined(__GNUC__) || defined(__clang__)
#    define COMPILER_GNUC
#    ifdef __cplusplus
#        define STATIC_ASSERT static_assert
#    else
#        define STATIC_ASSERT _Static_assert
#    endif
#elif defined(_MSC_VER)
#    define COMPILER_MSVC
#    define STATIC_ASSERT static_assert
#else
#    error Compiler detection failed.
#endif

#if UINTPTR_MAX == 0xffffffffffffffff
#    define TARGET_64
#elif UINTPTR_MAX == 0xffffffff
#    define TARGET_32
#else
#    error Can not determine if compiling for 32-bit or 64-bit target.
#endif

#ifdef PLATFORM_WINDOWS
#    ifdef TARGET_64
#        define PRI_SIZET PRIu64
#    else
#        define PRI_SIZET PRIu32
#    endif
#else
#    define PRI_SIZET "zu"
#endif
