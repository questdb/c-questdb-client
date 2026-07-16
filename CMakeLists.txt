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

# The synchronous WebSocket egress reader (`reader_*` C/C++ surface) is
# always compiled in, on the same footing as the line senders — it is not
# gated by any option. This pulls in the `tungstenite` + `zstd` Rust crates
# as transitive dependencies. (The Rust-side switch still exists as the
# `questdb-rs` `sync-reader` feature for downstreams that build that crate
# directly; the C ABI always ships the surface.)

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

option(
    QUESTDB_SANITIZE
    "Build the C/C++ tests with -fsanitize=address,undefined."
    OFF)

option(
    QUESTDB_ENABLE_ARROW
    "Build with Apache Arrow C Data Interface exports. Opt-in: pulls arrow-rs."
    OFF)

# OFF keeps a downstream QUESTDB_TESTS_AND_EXAMPLES=ON build single-standard;
# our CI opts in to also build a C++20 twin of each C++ test/example.
option(
    QUESTDB_TEST_CXX20_VARIANTS
    "Also build a C++20 twin of each C++ test/example target (header conformance)."
    OFF)

option(QUESTDB_QWP_BENCH
    "Build the C QWP bench examples (qwp_ingress_c/qwp_egress_c need libcurl)"
    OFF)

# Build static and dynamic lib written in Rust by invoking `cargo`.
# Imports `questdb_client` target.
add_subdirectory(corrosion)
set(QUESTDB_CARGO_FEATURES "")
if(QUESTDB_ENABLE_INSECURE_SKIP_VERIFY)
    list(APPEND QUESTDB_CARGO_FEATURES insecure-skip-verify)
endif()
if(QUESTDB_TESTS_AND_EXAMPLES AND NOT QUESTDB_ENABLE_ARROW)
    message(STATUS "QUESTDB_TESTS_AND_EXAMPLES=ON: enabling QUESTDB_ENABLE_ARROW")
    set(QUESTDB_ENABLE_ARROW ON)
endif()
if(QUESTDB_ENABLE_ARROW)
    list(APPEND QUESTDB_CARGO_FEATURES arrow)
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
if(QUESTDB_ENABLE_ARROW)
    target_compile_definitions(questdb_client INTERFACE QUESTDB_CLIENT_ENABLE_ARROW)
endif()
if(WIN32)
    set_target_properties(
        questdb_client-shared
        PROPERTIES
        DEFINE_SYMBOL "QUESTDB_CLIENT_DYN_LIB")
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

function(apply_sanitizers TARGET_NAME)
    if(NOT QUESTDB_SANITIZE)
        return()
    endif()
    if(MSVC)
        message(WARNING
            "QUESTDB_SANITIZE is not supported on MSVC (its ASan runtime is "
            "not validated against the rustc-built library); skipping.")
    else()
        target_compile_options(
            ${TARGET_NAME} PRIVATE
            -fsanitize=address,undefined
            -fno-sanitize-recover=all
            -fno-omit-frame-pointer
            -g)
        target_link_options(
            ${TARGET_NAME} PRIVATE
            -fsanitize=address,undefined)
    endif()
endfunction()

function(_questdb_sources_have_cpp OUT_VAR)
    set(result FALSE)
    foreach(src IN LISTS ARGN)
        if(src MATCHES "\\.(cpp|cc|cxx)$")
            set(result TRUE)
        endif()
    endforeach()
    set(${OUT_VAR} ${result} PARENT_SCOPE)
endfunction()

# Empty std => inherit the caller's CMAKE_CXX_STANDARD; a non-empty std pins it.
function(_questdb_finish_example tgt std)
    target_link_libraries(${tgt} questdb_client)
    if(NOT "${std}" STREQUAL "")
        set_target_properties(${tgt} PROPERTIES CXX_STANDARD ${std} CXX_STANDARD_REQUIRED ON)
    endif()
endfunction()

function(_questdb_finish_test tgt std)
    _questdb_finish_example(${tgt} "${std}")
    target_include_directories(${tgt} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
    set_compile_flags(${tgt})
    apply_sanitizers(${tgt})
    add_test(NAME ${tgt} COMMAND ${tgt})
    if(QUESTDB_SANITIZE AND NOT MSVC)
        # Leak detection off: the Rust library legitimately retains
        # process-global allocations at exit that LSan can't tell apart from
        # an FFI leak. ASan UAF/OOB/double-free checks stay active.
        set_tests_properties(
            ${tgt} PROPERTIES
            ENVIRONMENT
            "ASAN_OPTIONS=detect_leaks=0;UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1")
    endif()
endfunction()

# Examples
function(compile_example TARGET_NAME)
    add_executable(${TARGET_NAME} ${ARGN})
    _questdb_finish_example(${TARGET_NAME} "")
    _questdb_sources_have_cpp(has_cpp ${ARGN})
    if(QUESTDB_TEST_CXX20_VARIANTS AND has_cpp)
        add_executable(${TARGET_NAME}_cxx20 ${ARGN})
        _questdb_finish_example(${TARGET_NAME}_cxx20 20)
    endif()
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
        line_sender_c_example_udp
        examples/line_sender_c_example_udp.c)
    compile_example(
        line_sender_c_example_udp_batch
        examples/line_sender_c_example_udp_batch.c)
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
        line_sender_cpp_example_udp
        examples/line_sender_cpp_example_udp.cpp)
    compile_example(
        line_sender_cpp_example_udp_batch
        examples/line_sender_cpp_example_udp_batch.cpp)
    compile_example(
        line_sender_cpp_example_decimal_custom
        examples/line_sender_cpp_example_decimal_custom.cpp)
    compile_example(
        line_sender_cpp_example_decimal_binary
        examples/line_sender_cpp_example_decimal_binary.cpp)
    compile_example(
        reader_c_example_from_conf
        examples/reader_c_example_from_conf.c)
    compile_example(
        reader_cpp_example_from_conf
        examples/reader_cpp_example_from_conf.cpp)
    compile_example(
        reader_c_example_with_binds
        examples/reader_c_example_with_binds.c)
    compile_example(
        reader_cpp_example_with_binds
        examples/reader_cpp_example_with_binds.cpp)
    compile_example(
        reader_cpp_example_columns
        examples/reader_cpp_example_columns.cpp)
    compile_example(
        reader_c_example_columns
        examples/reader_c_example_columns.c)
    compile_example(
        reader_c_example_arrow
        examples/reader_c_example_arrow.c)
    find_package(Threads REQUIRED)
    compile_example(
        qwp_ws_chunk_and_query_cpp_example
        examples/qwp_ws_chunk_and_query_cpp_example.cpp)
    foreach(v qwp_ws_chunk_and_query_cpp_example
              qwp_ws_chunk_and_query_cpp_example_cxx20)
        if(TARGET ${v})
            target_link_libraries(${v} Threads::Threads)
        endif()
    endforeach()

    find_package(Arrow QUIET)
    if(Arrow_FOUND)
        compile_example(
            line_sender_cpp_example_arrow
            examples/line_sender_cpp_example_arrow.cpp)
        compile_example(
            reader_cpp_example_arrow
            examples/reader_cpp_example_arrow.cpp)
        foreach(arrow_example line_sender_cpp_example_arrow reader_cpp_example_arrow)
            foreach(v ${arrow_example} ${arrow_example}_cxx20)
                if(TARGET ${v})
                    target_link_libraries(${v} Arrow::arrow_shared)
                endif()
            endforeach()
        endforeach()
    else()
        message(STATUS
            "arrow-cpp not found; skipping line_{sender,reader}_cpp_example_arrow.")
    endif()

    # Include Rust tests as part of the tests run
    add_test(
        NAME rust_tests
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/questdb-rs
        COMMAND cargo test --features insecure-skip-verify -- --nocapture)

    # Unit test binaries.
    function(compile_test TARGET_NAME)
        add_executable(${TARGET_NAME} ${ARGN})
        _questdb_finish_test(${TARGET_NAME} "")
        _questdb_sources_have_cpp(has_cpp ${ARGN})
        if(QUESTDB_TEST_CXX20_VARIANTS AND has_cpp)
            add_executable(${TARGET_NAME}_cxx20 ${ARGN})
            _questdb_finish_test(${TARGET_NAME}_cxx20 20)
        endif()
    endfunction()

    # These probes must fail to compile: the unified C++ lease is move-only,
    # and its non-owning view does not expose the raw pooled handle. Normal
    # test targets compile the same header first, so a failure here cannot hide
    # a general header error.
    function(expect_cxx_compile_failure PROBE_NAME SOURCE_FILE)
        try_compile(
            PROBE_COMPILED
            ${CMAKE_CURRENT_BINARY_DIR}/compile_fail/${PROBE_NAME}
            ${CMAKE_CURRENT_SOURCE_DIR}/${SOURCE_FILE}
            CMAKE_FLAGS
                -DCMAKE_CXX_STANDARD=${CMAKE_CXX_STANDARD}
                -DCMAKE_CXX_STANDARD_REQUIRED=ON
                -DCMAKE_CXX_EXTENSIONS=OFF
                -DINCLUDE_DIRECTORIES=${CMAKE_CURRENT_SOURCE_DIR}/include
            OUTPUT_VARIABLE PROBE_OUTPUT)
        if(PROBE_COMPILED)
            message(FATAL_ERROR
                "compile-fail probe ${PROBE_NAME} unexpectedly compiled:\n${PROBE_OUTPUT}")
        endif()
    endfunction()

    expect_cxx_compile_failure(
        borrowed_sender_copy
        cpp_test/compile_fail_borrowed_sender_copy.cpp)
    expect_cxx_compile_failure(
        sender_view_raw_escape
        cpp_test/compile_fail_sender_view_raw.cpp)

    compile_test(
        test_line_sender
        cpp_test/mock_server.cpp
        cpp_test/test_line_sender.cpp)

    # Live-broker integration tests for the egress reader. Skips per-test
    # if no broker is reachable on QDB_LIVE_BROKER_HOST:QDB_LIVE_BROKER_HTTP_PORT
    # (defaults: localhost:9000), so this test is safe to wire into ctest
    # even on machines without a broker.
    compile_test(
        test_reader
        cpp_test/test_reader.cpp)

    # Broker-independent smoke test for the reader FFI. Targets a
    # guaranteed-closed port (127.0.0.1:1) and asserts the FFI surfaces
    # a non-NULL error that can be inspected and freed. Uses standard
    # exit-code semantics so SIGSEGV / SIGABRT correctly fail the test
    # (the previous WILL_FAIL-based smoke treated any non-zero exit as a
    # pass, and inverted to a failure when QuestDB happened to be running
    # on the developer's machine).
    compile_test(
        reader_c_smoke
        cpp_test/smoke_reader.c)

    # Broker-independent C++ tests for the reader FFI. Covers the
    # error-handling surface, parser rejection paths, the connect-failure
    # path against a closed port, NULL-idempotent free / close functions,
    # `from_env`, and the C++ `questdb::error` exception wrapper.
    compile_test(
        test_reader_offline
        cpp_test/test_reader_offline.cpp)

    # Mock-server-driven C++ tests for the reader FFI. Drives the
    # reader against an in-process WebSocket + QWP1 mock so the
    # column-getter / bind-encoding / server_info / error-code / stats
    # surface that previously needed a live broker now runs in CI.
    compile_test(
        test_reader_mock
        cpp_test/qwp_mock_server.cpp
        cpp_test/test_reader_mock.cpp)

    # Apache Arrow C Data Interface tests. QUESTDB_ENABLE_ARROW is
    # auto-enabled when QUESTDB_TESTS_AND_EXAMPLES=ON (see above), so
    # these always build alongside the rest of the suite.
    compile_test(
        test_arrow_c
        cpp_test/qwp_mock_server.cpp
        cpp_test/qwp_mock_c.cpp
        cpp_test/test_arrow_c.c)
    compile_test(
        test_arrow_egress
        cpp_test/qwp_mock_server.cpp
        cpp_test/test_arrow_egress.cpp)
    compile_test(
        test_arrow_ingress
        cpp_test/qwp_mock_server.cpp
        cpp_test/test_arrow_ingress.cpp)

    compile_test(
        test_column_sender
        cpp_test/qwp_mock_server.cpp
        cpp_test/test_column_sender.cpp)

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

if(QUESTDB_QWP_BENCH)
    compile_example(
        qwp_bench_selftest
        examples/bench_schema_c.c
        examples/bench_json_c.c
        examples/bench_ingest_c.c
        examples/qwp_bench_selftest.c)

    find_package(CURL REQUIRED)
    find_package(Threads REQUIRED)
    compile_example(
        qwp_ingress_c
        examples/bench_schema_c.c
        examples/bench_json_c.c
        examples/bench_http_c.c
        examples/bench_ingest_c.c
        examples/qwp_ingress_c.c)
    target_link_libraries(qwp_ingress_c CURL::libcurl Threads::Threads)

    compile_example(
        qwp_egress_c
        examples/bench_schema_c.c
        examples/bench_json_c.c
        examples/bench_http_c.c
        examples/bench_ingest_c.c
        examples/qwp_egress_c.c)
    target_link_libraries(qwp_egress_c CURL::libcurl)
endif()
