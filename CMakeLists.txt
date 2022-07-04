cmake_minimum_required(VERSION 3.15.0)
project(c-questdb-client VERSION 1.1.0)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build static and dynamic lib written in Rust by invoking `cargo`.
# Imports `questdb_client` target.
add_subdirectory(corrosion)
corrosion_import_crate(
    MANIFEST_PATH Cargo.toml
    FEATURES ffi
    LINK_AS C)
target_include_directories(
    questdb_client INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/include)
if(WIN32)
    set_target_properties(
        questdb_client-shared
        PROPERTIES
        DEFINE_SYMBOL "LINESENDER_DYN_LIB")
    target_link_libraries(
        questdb_client-shared
        INTERFACE wsock32 ws2_32)
endif(WIN32)
if(APPLE)
    target_link_libraries(
        questdb_client
        INTERFACE "-framework Security")
endif()

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
