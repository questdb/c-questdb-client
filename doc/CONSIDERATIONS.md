# Considerations

## Threading

By design, the sender and buffer objects perform all operations on the current
thread. The library will not spawn any threads internally.

By constructing multiple buffers you can design your application to build ILP
messages on multiple threads whilst handling network connectivity in a separate
part of your application on a different thread (for example by passing buffers
that need sending over a concurrent queue and sending flushed buffers back over
another queue).

Buffer and sender objects don't use any locks, so it's down to you to ensure
that a single thread owns a buffer or sender at any given point in time.

## Data Types

The ILP protocol has its own set of data types which is smaller
that the set supported by QuestDB.
We map these types into QuestDB types and perform conversions
as necessary wherever possible.

Strings may be recorded as either the `STRING` type or the `SYMBOL` type.

`SYMBOL`s are strings with which are automatically
[interned](https://en.wikipedia.org/wiki/String_interning) by the database on a
per-column basis.
You should use this type if you expect the string to be re-used over and over.
This is common for identifiers, etc.

For one-off strings use `STRING` columns which aren't interned.

For more details see our
[datatypes](https://questdb.io/docs/reference/sql/datatypes) page.

## Data quality considerations

When inserting data through the API, you must follow a set of considerations.

### Library-validated considerations

* Strings and symbols must be passed in as valid UTF-8 which
  need not be nul-terminated.
* Table names and column names must conform to valid names as accepted by the
  database (see `isValidTableName` and `isValidColumnName` in the QuestDB java
  [codebase](https://github.com/questdb/questdb) for details).
* Each row should contain, *in order*:
  * table name
  * at least one of:
    * symbols, zero or more
    * columns, zero or more
  * [designated timestamp](https://questdb.io/docs/concept/designated-timestamp/),
    optionally

Breaking these rules above will result in a runtime error in the client library.

Errors are reported via:
* `Result` type in Rust.
* An "out" pointer in C.
* An exception in C++.

### Additional considerations

Additionally you should also ensure that:

* For a given row, a column name should not be repeated.
  If it's repeated, only the first value will be kept.
  This also applies to symbols.
* Values for a given column should always have the same type.
  If changing types the whole row will be dropped (unless we can cast).
* The timestamp column should be written out through the provided
  `line_sender_buffer_at_*` functions (in C) or or `.at()` method in (C++ and
  Rust).
  It is also possible to write out additional timestamps values
  as columns.

The client library will not check any of these types of data issues.

### Flushing

The API doesn't send any data over the network until you call `flush()`.

You may not see data appear in a timely manner because you’re not calling
`flush()` often enough.

It's recommended you maintain a maxium buffer size and/or timer to determine how
often to flush.

Flushing too often may also degrade performance.

To determine the buffer size, call:
* C: `line_sender_buffer_size(..)`
* C++: `buffer.size()`
* Rust: `buffer.len()`

*Closing the connection will not auto-flush.*

### Disconnections, Data Errors and troubleshooting

A failure when flushing data gerally indicates that the network connection was
dropped.

The ILP protocol does not send errors back to the client. Instead, by design,
it will disconnect a client if it encounters any insertion errors. This is to
avoid errors going unnoticed.

As an example, if a client were to insert a `STRING` value into a `BOOLEAN`
column, the QuestDB server would disconnect the client.

To determine the root cause of a disconnect, inspect the
[server logs](https://questdb.io/docs/troubleshooting/log/).

You can inspect the contents of a constructed buffer at any time calling:
* C: `line_sender_buffer_peek`
* C++: `buffer.peek()`
* Rust: `buffer.as_str()`
