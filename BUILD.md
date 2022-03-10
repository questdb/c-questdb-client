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

The build will generate libraries compiled to `.build/`.

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
You can run them through `ctest` as so:

```bash
$ (cd build && ctest)
```

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
$ rm -fR build
```
