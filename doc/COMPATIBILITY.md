# Compatibility

This page records the supported versions and toolchains for the 7.0.0 client
release. It is the repository source of truth; language guides should link here
instead of inventing their own compatibility claims.

## Server compatibility

| Client path | Minimum QuestDB version | Notes |
| --- | --- | --- |
| QWP over WebSocket (`ws::` / `wss::`) | 10.0 | Shared ingestion/query pool, automatic reconnect, `ok` acknowledgements, Arrow, and Polars |
| QWP over UDP (`udp::`) | A server release with QWP/UDP enabled | Best effort; no acknowledgement, authentication, or TLS |
| ILP over HTTP/TCP | Unchanged from the 6.x client | Legacy compatibility transports; QWP additions do not change their server requirements |

HTTP Basic authentication and reconnect to one configured endpoint work with
QuestDB Open Source and Enterprise. Bearer-token and OIDC authentication,
multi-host failover, and durable acknowledgement require QuestDB Enterprise.

Before the server release is published, QWP/WebSocket release qualification
must include a full system-test pass against the approved QuestDB 10.0
release-candidate SHA as well as the current QuestDB development branch. Rerun
the compatibility suite against the exact downloadable 10.0 release artifact
as soon as it exists.

## Build compatibility

| Surface | Minimum or supported version |
| --- | --- |
| Rust toolchain | 1.91.1 |
| C language | C11 |
| C++ language | C++17 |
| CMake | 3.15 |
| Arrow crate | `>=58, <60` |
| Polars crates | `>=0.52, <0.55` |

Rust 1.91.1 applies to `questdb-rs`, all features advertised on docs.rs, and
the Rust FFI crate used by C and C++. CI also tests current stable, beta, and
nightly Rust.

The supported native platforms are Linux, macOS, and Windows. CI covers GCC or
Clang on Linux, Apple Clang on macOS, and the MSVC toolsets installed on the
Microsoft-hosted `windows-2022` and `windows-2025` images. Those names identify
Windows Server images, not MSVC releases; record the compiler version printed
by each final Windows build. The C and C++ client is distributed as source;
releases do not contain pre-built native libraries.

Python, Java, Maven, and a local QuestDB checkout are needed only for the
repository's live-server test harness. They are not runtime dependencies of the
client library.
