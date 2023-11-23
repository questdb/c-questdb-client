cmake_minimum_required(VERSION 3.15.0)
project(c-questdb-client VERSION 3.1.0)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)

option(QUESTDB_TESTS_AND_EXAMPLES "Build test and example targets" OFF)

if (QUESTDB_TESTS_AND_EXAMPLES)
    include(CTest)
    enable_testing()
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(
    BUILD_SHARED_LIBS
    "Build shared library dependencies instead of static."
    OFF)

# Build static and dynamic lib written in Rust by invoking `cargo`.
# Imports `questdb_client` target.
add_subdirectory(corrosion)
corrosion_import_crate(
    MANIFEST_PATH questdb-rs-ffi/Cargo.toml
    LOCKED)   # Use `Cargo.lock`
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
        INTERFACE wsock32 ws2_32 ntdll crypt32 Secur32 Ncrypt)
    target_link_libraries(
        questdb_client-static
        INTERFACE wsock32 ws2_32 ntdll crypt32 Secur32 Ncrypt)
endif(WIN32)
if(APPLE)
    target_link_libraries(
        questdb_client
        INTERFACE "-framework Security")
    target_link_libraries(
        questdb_client
        INTERFACE "-framework CoreFoundation")
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

# Examples
function(compile_example TARGET_NAME)
    list(POP_FRONT ARGV)
    add_executable(
        ${TARGET_NAME}
        ${ARGV})
    target_link_libraries(
        ${TARGET_NAME}
        questdb_client)
endfunction()

if (QUESTDB_TESTS_AND_EXAMPLES)
    compile_example(
        line_sender_c_example
        examples/line_sender_c_example.c)
    compile_example(
        line_sender_c_example_auth
        examples/line_sender_c_example_auth.c)
    compile_example(
        line_sender_c_example_tls_ca
        examples/line_sender_c_example_tls_ca.c)
    compile_example(
        line_sender_c_example_auth_tls
        examples/line_sender_c_example_auth_tls.c)
    compile_example(
        line_sender_cpp_example
        examples/line_sender_cpp_example.cpp)
    compile_example(
        line_sender_cpp_example_auth
        examples/line_sender_cpp_example_auth.cpp)
    compile_example(
        line_sender_cpp_example_tls_ca
        examples/line_sender_cpp_example_tls_ca.cpp)
    compile_example(
        line_sender_cpp_example_auth_tls
        examples/line_sender_cpp_example_auth_tls.cpp)

    # Include Rust tests as part of the tests run
    add_test(
        NAME rust_tests
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/questdb-rs
        COMMAND cargo test --features insecure-skip-verify -- --nocapture)

    # Unit test binaries.
    function(compile_test TARGET_NAME)
        list(POP_FRONT ARGV)  # compile_test
        add_executable(
            ${TARGET_NAME}
            ${ARGV})
        target_link_libraries(
            ${TARGET_NAME}
            questdb_client)
        target_include_directories(
            ${TARGET_NAME}
            PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
        set_compile_flags(${TARGET_NAME})
        add_test(
            NAME ${TARGET_NAME}
            COMMAND ${TARGET_NAME})
    endfunction()

    compile_test(
        test_line_sender
        cpp_test/mock_server.cpp
        cpp_test/test_line_sender.cpp)

    # System testing Python3 script.
    # This will download the latest QuestDB instance from Github,
    # thus will also require a Java 11 installation to run the tests.
    option(QUESTDB_SYSTEM_TESTING "Run system tests" OFF)
    if(QUESTDB_SYSTEM_TESTING)
        find_package(
            Python3
            REQUIRED
            COMPONENTS Interpreter)
        find_package(
            Java
            11
            REQUIRED)
        add_test(
            NAME system_test
            COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/system_test/test.py run -v)
        set_tests_properties(
            system_test PROPERTIES
            ENVIRONMENT BUILD_DIR_PATH=${CMAKE_BINARY_DIR})
    endif(QUESTDB_SYSTEM_TESTING)
endif()
