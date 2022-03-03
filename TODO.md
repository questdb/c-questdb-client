Implementation
--------------
  * Port more test scenarios over from Python (that's where most tests live).
  * New `linesender_field_str_unchecked` API to avoid double-checking UTF-8 buffers in wrapper libs.
  * C++20 module wrapper in `include/linesender.hpp` (optional).
  * DLLImport / DLLExport & -fvisibility

Documentation
-------------
  * Write a C example.
  * Write an equivalent C++ example.
  * Document usage from another CMake project
    (follow https://github.com/doctest/doctest/blob/master/doc/markdown/build-systems.md).
  * Explain what to do if not seeing data.
  * Link to existing documentation for the line protocol.
  * Document protocol limitations, e.g. lack of authentication erros, atomicity and input resume.
