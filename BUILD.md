# Build Instructions

## Pre-requisites

* A modern C++ compiler
* CMake

## Build steps

```bash
$ cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release  # .. or -DCMAKE_BUILD_TYPE=Debug
$ (cd build && make)
```

## Build outputs

The build will generate libraries compiled to `.build/install/`.

You will find a dynamic library (`.dll`, `.dynlib` or `.so`) and either one or
two static libraries (platform dependent).

On platforms that support compiling with position independent code (Linux, Mac)
we ship both a static library with `-fPIC` enabled and one with the option
disabled. Use the former if you intend to link the static library into a dynamic
library and use the latter if you intend to link it into an executable.
On Windows there is just one static library you may use for all purposes.

## Running tests

```bash
$ (cd build && make test)
```

## Cleaning

```bash
$ (cd build && make clean)
```

Or more simply just delete the `./build` directory.
