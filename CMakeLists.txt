cmake_minimum_required(VERSION 3.15.0)
project(c-questdb-client VERSION 7.0.0)

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

set(MINIMUM_REQUIRED_CXX_STANDARD 17)

if((NOT CMAKE_CXX_STANDARD) OR (CMAKE_CXX_STANDARD LESS MINIMUM_REQUIRED_CXX_STANDARD))
    set(CMAKE_CXX_STANDARD ${MINIMUM_REQUIRED_CXX_STANDARD})
endif()
message(STATUS "C++ standard: ${CMAKE_CXX_STANDARD}")

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(
    BUILD_SHARED_LIBS
    "Build shared library dependencies instead of static."
    OFF)

# Opt in to the synchronous WebSocket egress reader (`line_reader_*`
# C/C++ surface). Pulls in the `tungstenite` + `zstd` Rust crates as
# transitive dependencies, so downstreams that only need the line
# sender can flip this OFF to keep the resulting library minimal.
# Defaults ON for the in-tree build because the `line_reader_*`
# examples and tests need it; external consumers who add this
# project via `add_subdirectory` should set
# `-DQUESTDB_ENABLE_READER=OFF` if they don't want the surface.
option(
    QUESTDB_ENABLE_READER
    "Enable the synchronous WebSocket egress reader (line_reader_* API). Adds tungstenite+zstd."
    ON)

# When QUESTDB_TESTS_AND_EXAMPLES is enabled the reader-related
# examples and tests need the reader API present. Refusing to build
# in that combination is friendlier than producing a confusing link
# error from missing `line_reader_*` symbols.
if(QUESTDB_TESTS_AND_EXAMPLES AND NOT QUESTDB_ENABLE_READER)
    message(FATAL_ERROR
        "QUESTDB_TESTS_AND_EXAMPLES=ON requires QUESTDB_ENABLE_READER=ON: "
        "the line_reader_* examples and tests would fail to link without it.")
endif()

# Compile in the `tls_verify=false` (sender) / `tls_verify=unsafe_off`
# (egress reader) escape hatch. ON by default to preserve the legacy
# behaviour of the shipped C ABI; security-conscious distributions can
# flip it OFF (`-DQUESTDB_ENABLE_INSECURE_SKIP_VERIFY=OFF`) to harden
# the resulting library — `line_sender_opts_tls_verify` then disappears
# from the symbol table and `tls_verify=unsafe_off` in a connect string
# is rejected at parse time.
option(
    QUESTDB_ENABLE_INSECURE_SKIP_VERIFY
    "Compile in support for tls_verify off. Allows downstream code to disable TLS certificate verification at runtime."
    ON)

# Build static and dynamic lib written in Rust by invoking `cargo`.
# Imports `questdb_client` target.
add_subdirectory(corrosion)
set(QUESTDB_CARGO_FEATURES "")
if(QUESTDB_ENABLE_READER)
    list(APPEND QUESTDB_CARGO_FEATURES sync-reader-ws)
endif()
if(QUESTDB_ENABLE_INSECURE_SKIP_VERIFY)
    list(APPEND QUESTDB_CARGO_FEATURES insecure-skip-verify)
endif()
if(QUESTDB_CARGO_FEATURES)
    corrosion_import_crate(
        MANIFEST_PATH questdb-rs-ffi/Cargo.toml
        LOCKED
        FEATURES ${QUESTDB_CARGO_FEATURES})
else()
    corrosion_import_crate(
        MANIFEST_PATH questdb-rs-ffi/Cargo.toml
        LOCKED)
endif()
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
        examples/concat.c
        examples/line_sender_c_example.c)
    compile_example(
        line_sender_c_example_array_byte_strides
        examples/concat.c
        examples/line_sender_c_example_array_byte_strides.c)
    compile_example(
        line_sender_c_example_array_elem_strides
        examples/concat.c
        examples/line_sender_c_example_array_elem_strides.c)
    compile_example(
        line_sender_c_example_array_c_major
        examples/concat.c
        examples/line_sender_c_example_array_c_major.c)
    compile_example(
        line_sender_c_example_auth
        examples/concat.c
        examples/line_sender_c_example_auth.c)
    compile_example(
        line_sender_c_example_tls_ca
        examples/concat.c
        examples/line_sender_c_example_tls_ca.c)
    compile_example(
        line_sender_c_example_auth_tls
        examples/concat.c
        examples/line_sender_c_example_auth_tls.c)
    compile_example(
        line_sender_c_example_http
        examples/concat.c
        examples/line_sender_c_example_http.c)
    compile_example(
        line_sender_c_example_from_conf
        examples/line_sender_c_example_from_conf.c)
    compile_example(
        line_sender_c_example_from_env
        examples/line_sender_c_example_from_env.c)
    compile_example(
        line_sender_c_example_qwpudp
        examples/line_sender_c_example_qwpudp.c)
    compile_example(
        line_sender_c_example_qwpudp_batch
        examples/line_sender_c_example_qwpudp_batch.c)
    compile_example(
        line_sender_c_example_decimal_binary
        examples/concat.c
        examples/line_sender_c_example_decimal_binary.c)
    compile_example(
        line_sender_cpp_example
        examples/line_sender_cpp_example.cpp)
    compile_example(
        line_sender_cpp_example_array_byte_strides
        examples/line_sender_cpp_example_array_byte_strides.cpp)
    compile_example(
        line_sender_cpp_example_array_elem_strides
        examples/line_sender_cpp_example_array_elem_strides.cpp)
    compile_example(
        line_sender_cpp_example_array_custom
        examples/line_sender_cpp_example_array_custom.cpp)
    compile_example(
        line_sender_cpp_example_auth
        examples/line_sender_cpp_example_auth.cpp)
    compile_example(
        line_sender_cpp_example_array_c_major
        examples/line_sender_cpp_example_array_c_major.cpp)
    compile_example(
        line_sender_cpp_example_tls_ca
        examples/line_sender_cpp_example_tls_ca.cpp)
    compile_example(
        line_sender_cpp_example_auth_tls
        examples/line_sender_cpp_example_auth_tls.cpp)
    compile_example(
        line_sender_cpp_example_http
        examples/line_sender_cpp_example_http.cpp)
    compile_example(
        line_sender_cpp_example_from_conf
        examples/line_sender_cpp_example_from_conf.cpp)
    compile_example(
        line_sender_cpp_example_from_env
        examples/line_sender_cpp_example_from_env.cpp)
    compile_example(
        line_sender_cpp_example_qwpudp
        examples/line_sender_cpp_example_qwpudp.cpp)
    compile_example(
        line_sender_cpp_example_qwpudp_batch
        examples/line_sender_cpp_example_qwpudp_batch.cpp)
    compile_example(
        line_sender_cpp_example_decimal_custom
        examples/line_sender_cpp_example_decimal_custom.cpp)
    compile_example(
        line_sender_cpp_example_decimal_binary
        examples/line_sender_cpp_example_decimal_binary.cpp)
    compile_example(
        line_reader_c_example_from_conf
        examples/line_reader_c_example_from_conf.c)
    compile_example(
        line_reader_cpp_example_from_conf
        examples/line_reader_cpp_example_from_conf.cpp)
    compile_example(
        line_reader_c_example_with_binds
        examples/line_reader_c_example_with_binds.c)
    compile_example(
        line_reader_cpp_example_with_binds
        examples/line_reader_cpp_example_with_binds.cpp)

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

    # Live-broker integration tests for the egress reader. Skips per-test
    # if no broker is reachable on QDB_LIVE_BROKER_HOST:QDB_LIVE_BROKER_HTTP_PORT
    # (defaults: localhost:9000), so this test is safe to wire into ctest
    # even on machines without a broker.
    compile_test(
        test_line_reader
        cpp_test/test_line_reader.cpp)

    # Broker-independent smoke test for the line_reader FFI. Targets a
    # guaranteed-closed port (127.0.0.1:1) and asserts the FFI surfaces
    # a non-NULL error that can be inspected and freed. Uses standard
    # exit-code semantics so SIGSEGV / SIGABRT correctly fail the test
    # (the previous WILL_FAIL-based smoke treated any non-zero exit as a
    # pass, and inverted to a failure when QuestDB happened to be running
    # on the developer's machine).
    compile_test(
        line_reader_c_smoke
        cpp_test/smoke_line_reader.c)

    # Broker-independent C++ tests for the line_reader FFI. Covers the
    # error-handling surface, parser rejection paths, the connect-failure
    # path against a closed port, NULL-idempotent free / close functions,
    # `from_env`, and the C++ `line_reader_error` exception wrapper.
    compile_test(
        test_line_reader_offline
        cpp_test/test_line_reader_offline.cpp)

    # Mock-server-driven C++ tests for the line_reader FFI. Drives the
    # reader against an in-process WebSocket + QWP1 mock so the
    # column-getter / bind-encoding / server_info / error-code / stats
    # surface that previously needed a live broker now runs in CI.
    compile_test(
        test_line_reader_mock
        cpp_test/qwp_mock_server.cpp
        cpp_test/test_line_reader_mock.cpp)

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
