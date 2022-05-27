# Build Instructions

This page describes how to build this project.

Also make sure to read the page on
[integrating this library into your project](DEPENDENCY.md).

## Pre-requisites

* A modern C11/C++17 compiler.
* CMake 3.12 or newer.

## Build steps

### Linux / MacOS

Tested compilers are GCC and Clang.

```bash
$ cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release  # .. or -DCMAKE_BUILD_TYPE=Debug for debugging.
$ (cd build && make)
```

### Windows

The project should compile with Visual Studio 2017 and newer. It should
also work with MinGW-w64.

Building on Windows is usually easier done through an IDE.

### IDEs

Open Visual Studio 2017 or CLion and import as CMake project.
Visual Studio Code should also work well provided you have the "C/C++",
"CMake Tools" and "CMake Test Explorer" extensions installed.

## Build outputs

The build will generate libraries compiled to `./build`
(or your otherwise selected CMake build directory).

You will find one dynamic library and depending on
the operating system either one or two static libraries.

On platforms that support compiling with position independent code (Linux, Mac)
we ship both a static library with `-fPIC` enabled and one with the option
disabled. Use the former if you intend to link the static library into a dynamic
library and use the latter if you intend to link it into an executable.
If you intend to create your own language binding (e.g. for Python), then you
probably want to use the `-fPIC` static library.
On Windows there is just one static library you may use for all purposes.

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
