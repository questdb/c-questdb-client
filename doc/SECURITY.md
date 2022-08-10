# Connection Security

You may choose to enable authentication and/or TLS encryption by setting the
appropriate properties on the `opts` (C and C++) or (`SenderBuilder` in Rust)
object used for connecting.

## Authentication

We support QuestDB's ECDSA P256 SHA256 signing-based authentication.

To create your own keys, follow the QuestDB's
[authentication documentation](https://questdb.io/docs/reference/api/ilp/authenticate/).

Authentication can be used independently of TLS encryption.

## TLS Encryption

As of writing, whilst QuestDB itself can't be configured to support TLS natively
it is recommended that you use [HAProxy](http://www.haproxy.org/) or other
to secure the connection for any public-facing servers.

TLS can be used independently and provides no authentication itself.

The `tls_certs` directory of this project contains tests certificates, its
[README](../tls_certs/README.md) page describes generating your own certs.

For API usage:
* Rust: `SenderBuilder`'s [`auth`](https://docs.rs/questdb-rs/2.1.0/questdb/ingress/struct.SenderBuilder.html#method.auth)
  and [`tls`](https://docs.rs/questdb-rs/2.1.0/questdb/ingress/struct.SenderBuilder.html#method.tls) methods.
* C: [examples/line_sender_c_example_auth.c](../examples/line_sender_c_example_auth.c)
* C++: [examples/line_sender_cpp_example_auth.cpp](../examples/line_sender_cpp_example_auth.cpp)