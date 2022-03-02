cmake_minimum_required(VERSION 3.0.0)
project(c-questdb-client VERSION 0.1.0)

include(CTest)
enable_testing()

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/install)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/install)

add_library(
    c_questdb_client SHARED
    src/c-questdb-client.cpp)

add_library(
    c_questdb_client_static STATIC
    src/c-questdb-client.cpp)

if (UNIX)
    add_library(
        c_questdb_client_static_pic STATIC
        src/c-questdb-client.cpp)
    set_property(
        TARGET c_questdb_client_static_pic
        PROPERTY POSITION_INDEPENDENT_CODE ON)
endif (UNIX)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
