# Build Instructions

This page describes how to build this project.

Also make sure to read the page on
[integrating this library into your project](DEPENDENCY.md).

## Pre-requisites and dependencies

* Rust 1.61 or newer (get it from [https://rustup.rs/](https://rustup.rs/))
* A modern C11 or C++17 compiler.
* CMake 3.15 or newer.

The library statically links all its dependencies.

```
$ ls build/libquestdb_client.*
build/libquestdb_client.a  build/libquestdb_client.so
$ ldd build/libquestdb_client.so
        linux-vdso.so.1 (0x00007ffddd344000)
        libgcc_s.so.1 => /lib/x86_64-linux-gnu/libgcc_s.so.1 (0x00007fe61d252000)
        libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007fe61d22f000)
        libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007fe61d229000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fe61d037000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fe61d2ee000)
```

## Build steps

### Linux / MacOS

Tested compilers are GCC and Clang.

```bash
$ cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release  # .. or -DCMAKE_BUILD_TYPE=Debug for debugging.
$ cmake --build build
```

**Note**: Tests and examples are not built by default. To build them add
`-DQUESTDB_TESTS_AND_EXAMPLES=ON` to the `cmake` command line above.

```bash

### Windows

The project should compile with Visual Studio 2017 and newer. It should
also work with MinGW-w64.

Building on Windows is usually easier done through an IDE.

### IDEs

Open Visual Studio 2017 or CLion and import as CMake project.
Visual Studio Code should also work well provided you have the "C/C++",
"CMake Tools" and "CMake Test Explorer" extensions installed.

## Build outputs

The build will generate both static and dynamic libraries compiled to `./build`
(or your otherwise selected CMake build directory).

## Running tests

### Unit Tests
C++ unit tests are compiled by default.

In Linux and MacOS you can run these through `ctest` via the command line.

```bash
$ (cd build && ctest)
```

On Windows it's usually easier to run tests through your IDE.

### System Tests (optional)
If you also want to run the system tests which test the client
libraries against a live instance of QuestDB you need to:

* Ensure you have a Java 11 installation pointed to by the `JAVA_HOME`
  environment variable.

* Python3.8 or newer installed and available as `python3` on the `PATH`
  environment variable.

* Then re-run cmake whilst defining `QUESTDB_SYSTEM_TESTING`:
  ```bash
  $ cmake -S . -B build -DQUESTDB_SYSTEM_TESTING=ON
  $ (cd build && make && ctest)
  ```

## Cleaning

Delete the `./build` directory.

```bash
$ rm -fR build  # or your otherwise selected CMake build directory.
```
