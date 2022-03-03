cmake_minimum_required(VERSION 3.10.0)
project(c-questdb-client VERSION 1.0.0)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)

include(CTest)
enable_testing()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/install)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/install)

set(lib_sources
    src/aborting_malloc.c
    src/linesender.c
    src/memwriter.c
    src/utf8.c)

function(set_compile_flags TARGET_NAME)
    if(MSVC)
        target_compile_options(
            ${TARGET_NAME} PRIVATE
            /W4 /WX)
    else()
        target_compile_options(
            ${TARGET_NAME} PRIVATE
            -Wall -Wextra -Wpedantic -Werror)
    endif()
endfunction()

# Shared Library
add_library(
    c_questdb_client SHARED
    ${lib_sources})
target_include_directories(
    c_questdb_client
    PUBLIC ${CMAKE_SOURCE_DIR}/include)
set_compile_flags(c_questdb_client)

# Static Library
add_library(
    c_questdb_client_static STATIC
    ${lib_sources})
target_include_directories(
    c_questdb_client_static
    PUBLIC ${CMAKE_SOURCE_DIR}/include)
set_compile_flags(c_questdb_client_static)

# Static Library w/ -fPIC
if (UNIX)
    add_library(
        c_questdb_client_static_pic STATIC
        ${lib_sources})
    set_property(
        TARGET c_questdb_client_static_pic
        PROPERTY POSITION_INDEPENDENT_CODE ON)
    target_include_directories(
        c_questdb_client_static_pic
        PUBLIC ${CMAKE_SOURCE_DIR}/include)
    set_compile_flags(c_questdb_client_static_pic)
endif (UNIX)

# Test binary.
add_executable(
    test_linesender
    test/mock_server.cpp
    test/test_linesender.cpp)
target_link_libraries(
    test_linesender
    c_questdb_client_static)
target_include_directories(
    test_linesender
    PUBLIC ${CMAKE_SOURCE_DIR}/include)
set_compile_flags(test_linesender)
add_test(
    NAME test_linesender
    COMMAND test_linesender)

