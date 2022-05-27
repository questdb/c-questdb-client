/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2022 QuestDB
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

#include <stddef.h>

#include "build_env.h"

/**
 * Calculate the next power of two.
 *
 * Here are some example inputs / outputs to understand behaviour:
 *     next_pow2(2): 2
 *     next_pow2(3): 4
 *     next_pow2(4): 4
 *     next_pow2(5): 8
 *     next_pow2(6): 8
 *     next_pow2(7): 8
 *     next_pow2(8): 8
 *     next_pow2(9): 16
 *
 * Note that values of 0 and 1 yield inconsistent results between compilers and
 * platforms, but this doesn't affect usage as we never input such values.
 */
static size_t next_pow2(size_t n)
{
    // See: https://jameshfisher.com/2018/03/30/round-up-power-2/
    // In this portable code we use two different slightly different intrinsics
    // for MSVC and others.
    //  * __builtin_clz(l): counts the number of leading zeros.
    //  * _BitScanReverse(64): counts the 0-based index of the highest bit.
    // As such they need to be handled slightly differently.
    const size_t prev = n - 1;

#ifdef TARGET_64
    STATIC_ASSERT(sizeof(size_t) == 8, "64-bit `size_t` expected");
#    if defined(COMPILER_GCC_LIKE)
    STATIC_ASSERT(sizeof(unsigned long long) == 8,
        "64-bit `unsized long long` expected");
    const int n_leading_zeros = (size_t)__builtin_clzll(prev);
    const size_t width = 64;
#    else
    unsigned long bit_index = 0;
    _BitScanReverse64(&bit_index, prev);
#    endif
#endif

#ifdef TARGET_32
    STATIC_ASSERT(sizeof(size_t) == 4, "32-bit `size_t` expected");
#    if defined(COMPILER_GCC_LIKE)
    STATIC_ASSERT(sizeof(unsigned int) == 4,
        "64-bit `unsigned long long` expected");
    const int n_leading_zeros = (size_t)__builtin_clz(prev);
    const size_t width = 32;
#    else
    unsigned long bit_index = 0;
    _BitScanReverse(&bit_index, prev);
#    endif
#endif

#if defined(COMPILER_GCC_LIKE)
    return ((size_t)1) << (width - n_leading_zeros);
#else
    return ((size_t)1) << (bit_index + 1);
#endif
}

#undef STATIC_ASSERT
