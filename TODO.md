Implementation
--------------
  * Review TODOs in code.
  * Live tests with private-running QuestDB instance on port 0.
  * Consider removing string port names and stick to uint16_t instead.
  * New `linesender_column_str_unchecked` API to avoid double-checking UTF-8 buffers in wrapper libs (optional).
  * C++20 module wrapper in `include/linesender.hpp` (optional).
  * Rename C++ namespace to simply "questdb".

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

To review
---------
  * Why do we need at least one column? Why is `table().symbol().at()` not enough?

  * Idea to split buffer construction from sending in the API to
    allow multiple threads to construct their own buffers independently.
    This does not introduce any threads, queues or locks. It's just a refactor.
    It would also allow us to add more features going forward without breaking
    the API (such as better error reporting or different protocol).

    ```cpp
    // C++
    questdb::client client{"host", 9009};

    questdb::batch batch;
    batch.table("table1")
         .symbol("a", "b")
         .symbol("b", "b")
         .column("c", true)
         .at_now();
    batch.table("table1")
         .symbol("a", "b")
         .symbol("b", "b")
         .column("c", true)
         .at_now();
    batch.table("table2")
         .symbol("a", "b")
         .symbol("b", "b")
         .column("c", true)
         .at_now();

    client.insert(batch);

    batch.table("table1")
         .symbol("a", "b")
         .symbol("b", "b")
         .column("c", true)
         .at_now();

    client.insert(batch);
    ```
