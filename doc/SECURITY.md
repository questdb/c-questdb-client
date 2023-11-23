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

As of writing, only QuestDB Enterprise can be configured to support TLS natively.
If you're using the open source edition, you can still use TLS encryption by setting
up [HAProxy](http://www.haproxy.org/) or other proxy
to secure the connection for any public-facing servers.

TLS can be used independently and provides no authentication itself.

The `tls_certs` directory of this project contains tests certificates, its
[README](../tls_certs/README.md) page describes generating your own test certs.

A few important technical details on TLS:
  * The libraries use the `rustls` Rust crate for TLS support.
  * They also, by default, use the `webpki_roots` Rust crate for root certificate verification
    which require no OS-specific configuration.
  * Alternatively, If you want to use your operating system's root certificates,
    you can do so calling the `tls_os_roots` method when building the "sender" object.
    The latter is especially desireable in corporate environments where the certificates
    are managed centrally.

For API usage:
* Rust: `SenderBuilder`'s [`auth`](https://docs.rs/questdb-rs/3.1.0/questdb/ingress/struct.SenderBuilder.html#method.auth)
  and [`tls`](https://docs.rs/questdb-rs/3.1.0/questdb/ingress/struct.SenderBuilder.html#method.tls) methods.
* C: [examples/line_sender_c_example_auth.c](../examples/line_sender_c_example_auth.c)
* C++: [examples/line_sender_cpp_example_auth.cpp](../examples/line_sender_cpp_example_auth.cpp)
