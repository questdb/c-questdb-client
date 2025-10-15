/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2025 QuestDB
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

#pragma once

#include "line_sender.h"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>
#if __cplusplus >= 202002L
#    include <span>
#endif

namespace questdb::ingress::array
{
enum class strides_mode
{
    /** Strides are provided in bytes */
    bytes,

    /** Strides are provided in elements */
    elements,
};

/**
 * A view over a multi-dimensional array with custom strides.
 *
 * The strides can be expressed as bytes offsets or as element counts.
 * The `rank` is the number of dimensions in the array, and the `shape`
 * describes the size of each dimension.
 *
 * If the data is stored in a row-major order, it may be more convenient and
 * efficient to use the `row_major_view` instead of `strided_view`.
 *
 * The `data` pointer must point to a contiguous block of memory that contains
 * the array data.
 */
template <typename T, strides_mode M>
class strided_view
{
public:
    using element_type = T;
    static constexpr strides_mode stride_size_mode = M;

    strided_view(
        size_t rank,
        const uintptr_t* shape,
        const intptr_t* strides,
        const T* data,
        size_t data_size)
        : _rank{rank}
        , _shape{shape}
        , _strides{strides}
        , _data{data}
        , _data_size{data_size}
    {
    }

    size_t rank() const
    {
        return _rank;
    }

    const uintptr_t* shape() const
    {
        return _shape;
    }

    const intptr_t* strides() const
    {
        return _strides;
    }

    const T* data() const
    {
        return _data;
    }

    size_t data_size() const
    {
        return _data_size;
    }

    const strided_view<T, M>& view() const
    {
        return *this;
    }

private:
    size_t _rank;
    const uintptr_t* _shape;
    const intptr_t* _strides;
    const T* _data;
    size_t _data_size;
};

/**
 * A view over a multi-dimensional array in row-major order.
 *
 * The `rank` is the number of dimensions in the array, and the `shape`
 * describes the size of each dimension.
 *
 * The `data` pointer must point to a contiguous block of memory that contains
 * the array data.
 *
 * If the source array is not stored in a row-major order, you may express
 * the strides explicitly using the `strided_view` class.
 *
 * This class provides a simpler and more efficient interface for row-major
 * arrays.
 */
template <typename T>
class row_major_view
{
public:
    using element_type = T;

    row_major_view(
        size_t rank, const uintptr_t* shape, const T* data, size_t data_size)
        : _rank{rank}
        , _shape{shape}
        , _data{data}
        , _data_size{data_size}
    {
    }

    size_t rank() const
    {
        return _rank;
    }
    const uintptr_t* shape() const
    {
        return _shape;
    }
    const T* data() const
    {
        return _data;
    }

    size_t data_size() const
    {
        return _data_size;
    }

    const row_major_view<T>& view() const
    {
        return *this;
    }

private:
    size_t _rank;
    const uintptr_t* _shape;
    const T* _data;
    size_t _data_size;
};

template <typename T>
struct row_major_1d_holder
{
    uintptr_t shape[1];
    const T* data;
    size_t size;

    row_major_1d_holder(const T* d, size_t s)
        : data(d)
        , size(s)
    {
        shape[0] = static_cast<uintptr_t>(s);
    }

    array::row_major_view<T> view() const
    {
        return {1, shape, data, size};
    }
};

template <typename T>
inline auto to_array_view_state_impl(const std::vector<T>& vec)
{
    return row_major_1d_holder<typename std::remove_cv<T>::type>(
        vec.data(), vec.size());
}

#if __cplusplus >= 202002L
template <typename T>
inline auto to_array_view_state_impl(const std::span<T>& span)
{
    return row_major_1d_holder<typename std::remove_cv<T>::type>(
        span.data(), span.size());
}
#endif

template <typename T, size_t N>
inline auto to_array_view_state_impl(const std::array<T, N>& arr)
{
    return row_major_1d_holder<typename std::remove_cv<T>::type>(arr.data(), N);
}

/**
 * Customization point to enable serialization of additional types as arrays.
 *
 * Forwards to a namespace or ADL (König) lookup function.
 * The customized `to_array_view_state_impl` for your custom type can be placed
 * in either:
 *  * The namespace of the type in question.
 *  * In the `questdb::ingress::array` namespace.
///
 * The function can either return a view object directly (either
 * `row_major_view` or `strided_view`), or, if you need to place some fields on
 * the stack, an object with a `.view()` method which returns a `const&` to one
 * "materialize" shape or strides information into contiguous memory.
 * of the two view types. Returning an object may be useful if you need to
 */
struct to_array_view_state_fn
{
    template <typename T>
    auto operator()(const T& array) const
    {
        // Implement your own `to_array_view_state_impl` as needed.
        return to_array_view_state_impl(array);
    }
};

inline constexpr to_array_view_state_fn to_array_view_state{};

template <typename T, typename = void>
struct has_array_view_state : std::false_type
{
};

template <typename T>
struct has_array_view_state<
    T,
    std::void_t<decltype(to_array_view_state_impl(std::declval<const T&>()))>>
    : std::true_type
{
};

template <typename T>
inline constexpr bool has_array_view_state_v = has_array_view_state<T>::value;
} // namespace questdb::ingress::array
