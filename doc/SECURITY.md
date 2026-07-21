# Connection security

Use an encrypted transport whenever credentials or data cross an untrusted
network. The configuration string selects both the wire protocol and its
security properties.

## Authentication by transport

| Transport | Authentication | Configuration |
| --- | --- | --- |
| ILP/TCP(S) | ECDSA P-256/SHA-256 challenge signing | `username`, `token`, `token_x`, and `token_y` together |
| ILP/HTTP(S) | HTTP Basic (OSS and Enterprise); bearer token (Enterprise) | `username` plus `password`, or `token` alone |
| QWP/WebSocket(S) | HTTP Basic (OSS and Enterprise); bearer token (Enterprise) during WebSocket upgrade | `username` plus `password`, or `token` alone |
| QWP/UDP | None | Authentication settings are rejected |

Follow the [QuestDB Open Source authentication
guide](https://questdb.com/docs/query/rest-api/#authentication-in-questdb-open-source)
for HTTP Basic authentication or the [Enterprise RBAC authentication
guide](https://questdb.com/docs/security/rbac/#authentication)
for bearer tokens and OIDC. Do not combine the authentication forms for one
connection, log configuration strings containing secrets, or commit
credentials to source control. Prefer a secret manager or protected
environment variable and restrict tokens to the intended environment.

Authentication does not encrypt traffic. Pair it with `tcps::`, `https::`, or
`wss::` outside a trusted private network.

## TLS

The secure schemes are:

- `tcps::` for ILP/TCP;
- `https::` for ILP/HTTP; and
- `wss::` for QWP/WebSocket.

Certificate verification is enabled by default. `tls_ca` selects the trust
source supported by the compiled feature set:

- `webpki_roots` for the bundled public WebPKI roots;
- `os_roots` for the operating-system trust store;
- `webpki_and_os_roots` for both; or
- `pem_file`, with `tls_roots=/path/to/ca.pem`, for a custom CA bundle.

For QWP/WebSocket only, `tls_roots` may instead name a JKS or PKCS#12 trust
store when `tls_roots_password` is supplied. ILP transports accept PEM custom
roots only.

The Rust crate exposes trust sources according to its TLS features. The C ABI
ships the configured Rust TLS implementation; native distributors can disable
the certificate-verification escape hatch with
`-DQUESTDB_ENABLE_INSECURE_SKIP_VERIFY=OFF`.

`tls_verify=unsafe_off` disables certificate and hostname verification. It is
available only when the `insecure-skip-verify` feature was compiled in and is
intended for isolated diagnostics, not production. Install the relevant CA
instead. The certificates under [`tls_certs`](../tls_certs/README.md) are test
fixtures and must not be deployed as production trust material.

## QWP/UDP posture

`udp::` provides neither authentication nor TLS and has no `udps::` form. Its
datagrams are readable and forgeable by any party with network access, and the
protocol cannot verify delivery. Use it only on a controlled, isolated network
segment with appropriate host and network access controls. Use authenticated
`wss::` or `https::` for public or otherwise untrusted paths.

## Examples and API reference

- Rust: [`SenderBuilder`](https://docs.rs/questdb-rs/latest/questdb/ingress/struct.SenderBuilder.html)
- C: [`line_sender_c_example_auth.c`](../examples/line_sender_c_example_auth.c)
  and [`line_sender_c_example_auth_tls.c`](../examples/line_sender_c_example_auth_tls.c)
- C++: [`line_sender_cpp_example_auth.cpp`](../examples/line_sender_cpp_example_auth.cpp)
  and [`line_sender_cpp_example_auth_tls.cpp`](../examples/line_sender_cpp_example_auth_tls.cpp)
