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
  * timestamp, optionally

Breaking these rules above will result in an error in the client library.

### Additional considerations

Additionally you should also ensure that:

* For a given row, a column name should not be repeated.
  If it's repeated, only the first value will be kept.
  This also applies to symbols.
* Values for a given column should always have the same type.
  If changing types the whole row will be dropped (unless we can cast).
* If supplying timestamps these need to be at least equal to
  previous ones in the same table, unless using the out of order
  feature. Out of order rows would be dropped.
* The timestamp column should be written out through the provided
  `line_sender_at` function (in C) or or `.at()` method in (C++).
  It is also possible to write out additional timestamps values
  as columns.

The client library will not check any of these types of data issues.

To debug these issues you may consult the QuestDB instance logs.