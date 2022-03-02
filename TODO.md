Build Infra
-----------
  * Enable: `-Wall -Werror -pedanic` flags (or MSVC equivalents).

Implementation
--------------
  * Add Windows support (MSVC).
  * Additionally test MinGW-W64.
  * Port more test scenarios over from Python (that's where most tests live).
  * New `linesender_field_str_unchecked` API to avoid double-checking UTF-8 buffers in wrapper libs.
  * C++20 module wrapper in `include/linesender.hpp` (optional).

Documentation
-------------
  * Write a C example.
  * Write an equivalent C++ example.
  * Document usage from another CMake project
    (follow https://github.com/doctest/doctest/blob/master/doc/markdown/build-systems.md).
  * Explain what to do if not seeing data.
  * Link to existing documentation for the line protocol.

