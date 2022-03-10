Implementation
--------------
  * New `linesender_column_str_unchecked` API to avoid double-checking UTF-8 buffers in wrapper libs (optional).
  * C++20 module wrapper in `include/linesender.hpp` (optional).
  * Rename C++ namespace to simply "questdb".
  * Introduce new reason error code / scrap OS error code.
  * [last thing] non-strictly monotonically increasing check for timestamp `at`.

Documentation
-------------
  * API docs.
  * API docs for nul-terminator handling and len semantics.
  * Document duplicate column names.
  * Document timestamp field can either be set via .column() or .at(), not both.
  * Write a C example.
  * Write an equivalent C++ example.
  * Document usage from another CMake project
    (follow https://github.com/doctest/doctest/blob/master/doc/markdown/build-systems.md).
  * Review "Library-validated rules" and write "Non-validated rules" sections.
  * Reword section around config. It's no longer correct.
  * Docs for updated API sequential coupling allowing symbol without column.

Tests
-----
  * Perf test / throughput. Including numerics.

QuestDB changes
---------------
  * Port 0 support in logs and config.
  * Error on typos in `server.conf`.
