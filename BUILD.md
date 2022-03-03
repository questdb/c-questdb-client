# Build Instructions

## Pre-requisites

* A modern C++ compiler
* CMake

## Build steps

```bash
$ cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release  # .. or -DCMAKE_BUILD_TYPE=Debug for debugging.
$ (cd build && make)
```

## Build outputs

The build will generate libraries compiled to `.build/install/`.

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

```bash
$ (cd build && ctest)
```

## Cleaning

Delete the `./build` directory.

```bash
$ rm -fR build
```

