# Build instructions

This page covers building the native C/C++ library and running this
repository's tests. See [DEPENDENCY.md](DEPENDENCY.md) for adding a tagged
release to another project and [COMPATIBILITY.md](COMPATIBILITY.md) for the
supported toolchain and dependency ranges.

## Prerequisites

The library build requires:

- Rust 1.91.1 or newer, installed with [rustup](https://rustup.rs/);
- a C11 compiler and a C++17 compiler; and
- CMake 3.15 or newer.

Rust 1.91.1 is the minimum supported Rust version (MSRV) for both
`questdb-rs` and `questdb-rs-ffi`, including the Arrow and Polars feature set
used by docs.rs.

## Build the library

On Linux and macOS, with GCC or Clang:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

On Windows, use a Visual Studio 2022 developer shell or let an IDE configure
the CMake project, then run the same commands. The project is also exercised
with current Clang/GCC toolchains in CI.

The default build produces static and shared forms of `questdb_client` in the
selected build directory. Set `BUILD_SHARED_LIBS=ON` when a downstream CMake
project should link the shared form by default:

```bash
cmake -S . -B build-shared \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=ON
cmake --build build-shared --config Release
```

To expose the Arrow C Data Interface, set `QUESTDB_ENABLE_ARROW=ON`. Tests and
examples enable it automatically.

## Build and run tests and examples

Tests and examples are not built by default:

```bash
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DQUESTDB_TESTS_AND_EXAMPLES=ON
cmake --build build --config Release
ctest --test-dir build --output-on-failure -C Release
```

The examples are build targets but are not CTest tests because most of them
require a running QuestDB instance. For example, after starting QuestDB 10.0
or newer locally:

```bash
cmake --build build --target qwp_ws_chunk_and_query_c_example
cmake --build build --target qwp_ws_chunk_and_query_cpp_example
./build/qwp_ws_chunk_and_query_c_example
./build/qwp_ws_chunk_and_query_cpp_example
```

Multi-config generators may place executables under `build/Release/`.

## Rust-only tests

Run Cargo from each crate directory; the repository root is not a Cargo
workspace:

```bash
cd questdb-rs
cargo test
cargo test --features almost-all-features,arrow,polars

cd ../questdb-rs-ffi
cargo test --all-features
```

The CI-equivalent Rust and native unit suite can be invoked from the repository
root after configuring the CMake build shown above:

```bash
python3 ci/run_all_tests.py unit
```

## Live-server system tests

The system-test harness requires Python 3.10 or newer. To build the current
QuestDB server from source it also requires JDK 25, Maven, and a QuestDB source
checkout at `./questdb`:

```bash
python3 ci/run_all_tests.py integration
```

Before QuestDB 10.0 is published, test the compatibility floor against the
approved, Maven-built 10.0 release-candidate checkout:

```bash
python3 system_test/test.py run --repo /path/to/questdb-10.0-rc -v
```

After the server release exists, rerun with its exact release tag:

```bash
python3 system_test/test.py run --versions <QUESTDB_10_RELEASE_TAG> -v
```

Do not substitute `10.0` for the placeholder until that exact downloadable
tag exists.

Some Arrow and Polars system tests additionally require current `numpy`,
`pyarrow`, `polars`, and `tzdata` Python packages. The CI setup in
`ci/templates/compile.yaml` is the authoritative dependency list.

## Cleaning

Use CMake's clean target, or remove a disposable build directory yourself:

```bash
cmake --build build --target clean
```
