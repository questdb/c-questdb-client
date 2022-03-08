cmake_minimum_required(VERSION 3.15.0)
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

set(LIB_SOURCES
    src/aborting_malloc.c
    src/linesender.c
    src/memwriter.c
    src/utf8.c)

function(set_compile_flags TARGET_NAME)
    if(MSVC)
        # We disable warning C5105 via `/wd5105`
        # to work around non-C11-compliant 
        # code in WinBase.h which is included from
        # #include <winsock2.h>
        # See: https://docs.microsoft.com/en-us/cpp/
        #   error-messages/compiler-warnings/c5105?view=msvc-170
        # And: https://developercommunity2.visualstudio.com/t/
        #   std:c17-generates-warning-compiling-Win/1249671?preview=true
        # The warning is not applicable in new releases of the Windows SDK.
        target_compile_options(
            ${TARGET_NAME} PRIVATE
            /W4 /WX $<$<COMPILE_LANGUAGE:C>:/wd5105>)
    else()
        target_compile_options(
            ${TARGET_NAME} PRIVATE
            -Wall -Wextra -Wpedantic -Werror)
    endif()
endfunction()

# Shared Library
add_library(
    c_questdb_client SHARED
    ${LIB_SOURCES})
target_include_directories(
    c_questdb_client
    PUBLIC ${CMAKE_SOURCE_DIR}/include)
set_compile_flags(c_questdb_client)
if(WIN32)
    set_target_properties(
        c_questdb_client
        PROPERTIES
        DEFINE_SYMBOL "LINESENDER_DYN_LIB"
        DEFINE_SYMBOL "LINESENDER_EXPORTS")
    target_link_libraries(c_questdb_client wsock32 ws2_32)
endif(WIN32)
if(UNIX)
    target_compile_options(
        c_questdb_client PRIVATE
        -fvisibility=hidden)
endif(UNIX)

# Static Library
add_library(
    c_questdb_client_static STATIC
    ${LIB_SOURCES})
target_include_directories(
    c_questdb_client_static
    PUBLIC ${CMAKE_SOURCE_DIR}/include)
set_compile_flags(c_questdb_client_static)
if(WIN32)
    target_link_libraries(c_questdb_client_static wsock32 ws2_32)
endif(WIN32)

# Static Library w/ -fPIC
if(UNIX)
    add_library(
        c_questdb_client_static_pic STATIC
        ${LIB_SOURCES})
    set_property(
        TARGET c_questdb_client_static_pic
        PROPERTY POSITION_INDEPENDENT_CODE ON)
    target_include_directories(
        c_questdb_client_static_pic
        PUBLIC ${CMAKE_SOURCE_DIR}/include)
    set_compile_flags(c_questdb_client_static_pic)
endif(UNIX)

# Test binary.
add_executable(
    test_linesender
    test/mock_server.cpp
    test/wsastartup_guard.cpp
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
