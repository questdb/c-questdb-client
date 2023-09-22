# Getting Started with C

## Building and depending on this library
* To begin with, we suggest first building the library to ensure you have all
  the tooling and build dependencies set up just right by following the
  [build instructions](BUILD.md)
* Then read the guide for including this library as a
  [dependency from your project](DEPENDENCY.md).

## Complete Examples

* [Basic example in C](../examples/line_sender_c_example.c).
* [With authentication](../examples/line_sender_c_example_auth.c).
* [With authentication and TLS](../examples/line_sender_c_example_auth_tls.c).
* [Custom certificate authority file](../examples/line_sender_c_example_tls_ca.c).

## API Overview

### Header

* [`.h` header file](../include/questdb/ingress/line_sender.h)

### Connecting

```c
#include <questdb/ingress/line_sender.h>

...

line_sender_error* err = NULL;
line_sender_opts* opts = NULL;
line_sender* sender = NULL;

line_sender_utf8 host = QDB_UTF8_LITERAL("localhost");
opts = line_sender_opts_new(host, 9009, &err);
if (!opts) {
    /* ... handle error ... */
}

sender = line_sender_connect(opts, &err);
line_sender_opts_free(opts);
opts = NULL;
if (!sender) {
    /* ... handle error ... */
}

```

The `opts` object can additionally take parameters for the outbound interface,
authentication, full-connection encryption via TLS and more.

### Building Messages

The `line_sender` object is responsible for connecting to the network and
sending data.

Use the `line_sender_buffer` type to construct messages (aka rows, aka records,
aka lines).

To avoid malformed messages, this object's functions (`line_sender_buffer_*`)
must be called in a specific order.

For each row, you need to specify a table name and at least one symbol or
column. Symbols must be specified before columns.

You can accumulate multiple lines (rows) with a given buffer and a buffer is
re-usable, but a buffer may only be flushed via the sender after a call to
`line_sender_buffer_at_*(..)` (preferred) or `line_sender_buffer_at_now()`.

```c
line_sender_table_name table_name = QDB_TABLE_NAME_LITERAL("c_cars");
line_sender_column_name id_name = QDB_COLUMN_NAME_LITERAL("id");
line_sender_column_name x_name = QDB_COLUMN_NAME_LITERAL("x");

line_sender_buffer* buffer = line_sender_buffer_new();

if (!line_sender_buffer_table(buffer, table_name, &err))
    goto on_error;

line_sender_utf8 id_value = QDB_UTF8_LITERAL(
    "d6e5fe92-d19f-482a-a97a-c105f547f721");
if (!line_sender_buffer_symbol(buffer, id_name, id_value, &err))
    goto on_error;

if (!line_sender_buffer_column_f64(buffer, x_name, 30.5, &err))
    goto on_error;

if (!line_sender_buffer_at_nanos(buffer, line_sender_now_nanos(), &err))
    goto on_error;

// To insert more records, call `line_sender_buffer_table(..)...` again.

if (!line_sender_flush(sender, buffer, &err))
    goto on_error;

line_sender_close(sender);
```

Diagram of valid call order of the buffer API.

![Sequential Coupling](../api_seq/seq.svg)

## Error handling

In the C API, functions that can result in errors take a `line_sender_error**`
parameter as the last argument. When calling such functions you must check the
return value for errors. Functions that return `bool` use `false` to indicate
a failure, whilst functions that return a pointer use NULL as the failure
sentinel value.

You may then call `line_sender_error_msg(err)` and
`line_sender_error_get_code(err)` to extract error details.

Once handled, the error object *must* be disposed of by calling
`line_sender_error_free(err)`.

On error, you must also call `line_sender_close(sender)`.

Here's a complete example of how to handle an error without leaks:

```c
line_sender* sender = ...;
line_sender_error* err = NULL;
if (!line_sender_flush(sender, &err))
{
  size_t msg_len = 0;
  const char* msg = line_sender_error_msg(err, &msg_len);
  fprintf(stderr, "Could not set table name: %.*s", (int)msg_len, msg);

  // Clean-up
  line_sender_error_free(err);
  line_sender_close(sender);
  return;
}
```

This type of error handling can get error-prone and verbose,
so you may want to use a `goto` to simplify handling
(see [example](../examples/line_sender_c_example.c)).

## Further Topics

* [Data quality and threading considerations](CONSIDERATIONS.md)
* [Authentication and TLS encryption](SECURITY.md)
