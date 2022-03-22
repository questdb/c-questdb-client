Implementation
--------------
  * [last thing] non-strictly monotonically increasing check for timestamp `at`.

Documentation
-------------
  * API docs.
  * Document duplicate column names.
  * Document timestamp field can either be set via .column() or .at(), not both.
  * Review "Library-validated rules" and write "Non-validated rules" sections.

Tests
-----
  * Perf test / throughput. Including numerics.

QuestDB changes
---------------
  * Port 0 support in logs and config.
  * Error on typos in `server.conf`.
