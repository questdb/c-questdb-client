# QWP browser WebAssembly prototype

This prototype compiles `questdb-rs`'s QWP v1 row encoder, ACK/rejection
decoder, FSN accounting, replay cursor, reconnect policy, and in-memory
Store-and-Forward queue to WebAssembly. The browser still owns the WebSocket
connection, TLS, masking, RFC 6455 framing, and opening the next configured
endpoint.

## Build

The prototype needs the `wasm32-unknown-unknown` Rust target and a
`wasm-bindgen` CLI whose version matches `Cargo.toml`:

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.114
cd wasm-browser-prototype
cargo build --release --target wasm32-unknown-unknown
wasm-bindgen \
  --target web \
  --out-dir web/pkg \
  target/wasm32-unknown-unknown/release/questdb_qwp_browser.wasm
```

For ingestion and SQL together, serve the web directory from the experimental
QuestDB process itself. One complete development launch command is:

```bash
mkdir -p /tmp/qwp-browser-demo
QDB_HTTP_BIND_TO=127.0.0.1:19000 \
QDB_HTTP_STATIC_PUBLIC_DIRECTORY=/home/jara/devel/oss/c-questdb-client/questdb-rs/wasm-browser-prototype/web \
QDB_PG_ENABLED=false \
QDB_LINE_TCP_ENABLED=false \
QDB_SHARED_WORKER_COUNT=2 \
/usr/lib/jvm/java-25-openjdk-amd64/bin/java \
  --add-exports=java.base/jdk.internal.vm=ALL-UNNAMED \
  --enable-native-access=ALL-UNNAMED \
  -jar /home/jara/devel/oss/questdb-http2/core/target/questdb-10.0.1-SNAPSHOT.jar \
  -d /tmp/qwp-browser-demo
```

With the development server on port 19000, open
`http://localhost:19000/index.html`.
The page derives the QWP ingress `/api/v4/write` and QWP egress `/read/v1`
WebSocket URLs from that origin. The ingress field accepts a comma-separated
endpoint list and rotates automatically after disconnects or retriable server
responses. Rows can be published into the in-memory replay queue before a
connection is open; they drain after a connection succeeds. Send the sample
row, connect, then execute `select * from wasm_ticks`.

Serving the page separately with `python3 -m http.server 5173 --directory web`
also works because the experimental server ignores the WebSocket `Origin` for
both ingress and egress.

For a repeatable wire-level smoke test against a development server on port
19000, run:

```bash
node smoke-node.mjs
```

The smoke test loads the generated WASM, drains an ingress frame, simulates a
connection loss before the browser sends it, verifies that the Rust driver
replays the same unresolved frame, and ACKs it over `/api/v4/write`. It then
issues a SQL `QUERY_REQUEST` over `/read/v1` and fails unless the inserted row
comes back through QWP egress.

## Required experimental server change

Stock QuestDB intentionally rejects QWP WebSocket handshakes containing an
`Origin` header. A browser always sends one. This experimental server removes
that check from `QwpIngressHttpProcessor.validateHandshake`; the ingress and
egress upgrade processors share the validator. This allows arbitrary websites
to connect to a reachable QuestDB server, so it must not be used as a
production default.

Run the experiment against an unauthenticated development instance. The browser
WebSocket API cannot set QuestDB's current `Authorization` upgrade header.

## Deliberate limits

- QWP v1 only; the missing `X-QWP-Max-Version` request header defaults to v1.
- Ordinary ACKs only; no durable-ACK handshake opt-in.
- SQL uses QWP egress over `/read/v1`; result frames are decoded by the same
  Rust QWP schema, column, and symbol-dictionary codecs as the native reader.
- Result cells cross the WASM boundary as lossless strings (and `null`) for
  this UI prototype; there is no Arrow JavaScript adapter yet.
- Automatic reconnect/failover uses the configured browser URL order. The
  existing Rust replay driver retains unresolved frames and advances them from
  QWP ACKs.
- The replay queue is bounded but memory-only. Reloading or closing the tab
  loses it; an IndexedDB publication-log backend is not implemented yet.
- No pooling and no browser authentication adapter.
- Small messages only. Browser-controlled WebSocket fragmentation needs a
  server-side reassembly test before larger payloads are safe.
