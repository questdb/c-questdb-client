# Add this library as a dependency to your project

Once you know you have the prerequisites to [build](BUILD.md) this library,
you can learn here to to integrate it into your project.

There's many ways of doing this, each with tradeoffs, but first we will cover
how we tag releases.

## Release tagging

We do not ship binaries.

Instead you should rely on a copy of the code sync'ed up
to the latest annotated tag. You can find the list of tags on
the [project's GitHub tag page](../tags) or by listing the annotated tags in git
from a checked out copy of the code.

```bash
# Following a git clone of https://github.com/questdb/c-questdb-client.git
git tag -n99 --sort=-creatordate
```

Examples below will use a dummy name of `CHOSEN_RELEASE_TAG` that you will have
to substitute for one of these tag names. During development you may also
substitute it to a specific commit or just `main`, but we don't recommend
running non-tagged code for production use.

## Getting notified of new releases

To get notified for new releases, sign up to the QuestDB mailing list through
our [community page](https://questdb.io/community/).

## main.cpp

We will cover various approaches of including `c-questdb-client` into your
project.

In all examples below, we will attempt to compile:

```cpp
// main.cpp
#include <questdb/ingress/line_sender.hpp>

int main()
{
    questdb::ingress::line_sender sender{"localhost", 9009};
    return 0;
}
```

## Option 1: CMake & FetchContent integration

If your project already uses CMake, you may use its `FetchContent` feature to
automatically clone the repository into your temporary build directory when
compiling your project.

Approach upsides:
* Easiest setup.
* No additional files in your source tree.
* No workflow changes to your project.
* Works with any version control system, so long as you also have `git`
  available in your `PATH`.

Approach downsides:
* Your build will break if GitHub is down or otherwise unaccessible.
* Slightly slows down your clean-build time as it runs `git clone` every time
  you configure your CMake project (no impact on rebuild).

In the example `CMakeLists.txt` configuration below, you need to substitute
`CHOSEN_RELEASE_TAG` for one of our releases. Don't forget to also update
`your_project_name`.

```cmake
# CMakeLists.txt
cmake_minimum_required(VERSION 3.15.0)
project(your_project_name VERSION 1.0.0)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(FetchContent)

FetchContent_Declare(
    c_questdb_client_proj
    GIT_REPOSITORY https://github.com/questdb/c-questdb-client.git
    GIT_TAG CHOSEN_RELEASE_TAG)   # CHANGE ME!

FetchContent_MakeAvailable(c_questdb_client)

add_executable(
    main
    main.cpp)
target_link_libraries(
    main
    questdb_client)
```

*Note:* By default, the library will be linked statically. Call `cmake .. -DBUILD_SHARED_LIBS=ON` to depend on the dynamic library.

## Option 2: CMake add_subdirectory & Git source code grafting

If you're using both CMake and git in your project, then you can graft this
library's source into your own project's source and then use the
`add_subdirectory` feature to expose our library's targets to your project.

Grafting can be accomplished via either one of:
* `git subtree`: Copies source code into your repository.
* `git submodule`: Links and references our external GitHub repo.

Pick either approach to obtain a copy of this library's code into
the `deps/c-questdb-client` directory within your git repository.

Once done, [configuring `CMakeLists.txt`](#cmakeliststxt-with-subdirectory)
config is the same.

### Grafting via `git subtree` (recommended)

Git subtree will merge our source code into a directory of your project and
committed into your repo.

Approach upsides:
* More resilient to GitHub outages.
* Minimal workflow changes to your project:
  Just `git clone`, then build.

Approach downsides:
* More files in your repo.
* Gets complicated if you check in changes into subtree directory.

To initially add our project's source code, substitute `CHOSEN_RELEASE_TAG`
from the command below and run it from your project's root:

```bash
git subtree add --prefix deps/c-questdb-client https://github.com/questdb/c-questdb-client.git CHOSEN_RELEASE_TAG --squash
```

Anyone else in the team who will `git clone` your repo will obtain all necessary
files to build the project without additional steps.

At a later date, to upgrade to a newer release (or to revert back to an older
one) pick a new release tag and run the following command, editing
`NEWLY_CHOSEN_RELEASE_TAG` appropriately:

```bash
git subtree pull --prefix deps/c-questdb-client https://github.com/questdb/c-questdb-client.git NEWLY_CHOSEN_RELEASE_TAG --squash
```

### Grafting via `git submodule`

The lighter-weight way to graft our source code into your repo is via
`git submodule` which simply points to a commit into our GitHub repository.

Approach upsides:
* Fewer additional files in your project (compared to subtree).

Approach downsides:
* Complex additional workflow for the whole team before building the project.
* Less resilient in case of GitHub outages.

To initially add our project's source code, substitute `CHOSEN_RELEASE_TAG`
from the commands below and run them from your project's root:

```bash
git submodule add https://github.com/questdb/c-questdb-client.git deps/c-questdb-client
cd deps/c-questdb-client
git checkout tags/CHOSEN_RELEASE_TAG
cd ../..
git add deps/c-questdb-client
git commit -m "Added submodule: c-questdb-client @ CHOSEN_RELEASE_TAG"
```

This commit only checked in enough information to track the submodule and not
the contents themselves.

From now on everyone on the project will have to routinely update submodules:

```bash
git submodule update --init --recursive
```

To update your dependency to a newer (or older) release, replace
`NEWLY_CHOSEN_RELEASE_TAG` in the set of commands below and run them.

```bash
cd deps/c-questdb-client
git fetch --all --tags
git checkout tags/NEWLY_CHOSEN_RELEASE_TAG
cd ../..
git add deps/c-questdb-client
git commit -m "Updated submodule: c-questdb-client @ NEWLY_CHOSEN_RELEASE_TAG"
```

### CMakeLists.txt with subdirectory

Now that our library's code is accessible within your project's
`deps/c-questdb-client` path we will try and build with it.

Use the following CMake configuration and don't forget to also update
`your_project_name`.

```cmake
# CMakeLists.txt
cmake_minimum_required(VERSION 3.15.0)
project(your_project_name VERSION 1.0.0)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_subdirectory(
    deps/c-questdb-client
    EXCLUDE_FROM_ALL)

add_executable(
    main
    main.cpp)
target_link_libraries(
    main
    questdb_client)
```

## Option 3: Other build systems

If you use a build system other than CMake, the following tips should help you:

* Add `include/` to the include path.

* Define `LINESENDER_DYN_LIB` when *building* or *using* this code as a dynamic
  library. This is especially important on Windows to mark
  `__declspec(dllimport)`.
  On Linux and Mac the `LINESENDER_DYN_LIB` is used to mark
  `__attribute__ ((visibility("default")))` and should be enabled in conjunction
  with the `-fvisibility=hidden` flag to GCC/Clang.

* Whilst *building* the library on Windows also define `LINESENDER_EXPORTS`
  to mark `__declspec(dllexport)`:
  This define should *not* be present when *using* the library.

*Note:* By default, the library will be linked statically. Call `cmake .. -DBUILD_SHARED_LIBS=ON` to depend on the dynamic library.

## Package Managers

If you are using a particular package manager (e.g. Conan or vcpkg), contact us
on slack, create an issue (or better yet a pull request) and we'll try and help
you out.
