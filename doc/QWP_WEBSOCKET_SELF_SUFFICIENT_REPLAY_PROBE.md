# QWP/WebSocket Step 4 self-sufficient replay probe

Date: 2026-04-28

Status: real-server probe passed against a local `questdb-arrays` QuestDB
server.

## Harness

The ignored Rust test
`tests::qwp_ws_replay_probe::qwp_ws_replay_frame_is_self_sufficient_on_fresh_connection`
exercises the Step 4 protocol assumption directly.

It deliberately avoids the new sender, receipts, volatile queue, disk
Store-and-Forward, and background progress machinery. The test:

- builds replay-mode QWP payloads directly with `encode_ws_replay_message`,
- sends the first payload over one QWP/WebSocket connection,
- opens a fresh QWP/WebSocket connection,
- sends the later replay payload alone as the first data frame on that
  connection,
- verifies rows through QuestDB's HTTP `/exec` API,
- prints unmasked payload metrics and the QuestDB build string.

The first payload inserts ten rows with symbols `SYM_000` through `SYM_009`.
The second payload inserts one row referencing only `SYM_009`, so the replay
payload must carry the dense dictionary prefix for ids `0..=9`.

## Running

Default endpoint:

```sh
env QDB_QWP_WS_REPLAY_PROBE=1 \
    cargo test --manifest-path questdb-rs/Cargo.toml \
    qwp_ws_replay_frame_is_self_sufficient_on_fresh_connection \
    -- --ignored --nocapture
```

Environment:

- `QDB_QWP_WS_HOST`: defaults to `127.0.0.1`.
- `QDB_QWP_WS_PORT`: QWP/WebSocket port, defaults to `9000`.
- `QDB_QWP_WS_HTTP_PORT`: HTTP query port, defaults to `QDB_QWP_WS_PORT`.
- `QDB_QWP_WS_AUTH_HEADER`: optional raw `Authorization` header value.
- `QDB_QWP_WS_KEEP_TABLE=1`: keep the generated probe table for inspection.
  By default the probe drops it at the end of the run.

## Current Result

The harness compiles and is skipped by default. It passed against the local
server provided by `/home/jara/devel/oss/questdb-arrays`.

Observed run:

```text
QuestDB build: Build Information: unknown [DEVELOPMENT], JDK unknown, Commit Hash unknown
first replay payload: len=406, flags=0x08, table_count=1, payload_len=394, delta_start=0, delta_count=10
second replay payload: len=181, flags=0x08, table_count=1, payload_len=169, delta_start=0, delta_count=10
first connection acked QWP sequence 0
fresh connection acked replay QWP sequence 0
```

The first run exposed a client-side assumption bug: the real server ACKs the
first frame on a fresh QWP/WebSocket connection with wire sequence `0`, not `1`.
The sync and async QWP/WebSocket senders and their mock tests were adjusted to
use zero-based per-connection wire sequences.

## Local reflection

- How does this particular step feel?

  The probe shape is appropriately narrow. It sends replay encoder output
  directly and does not require queue or sender-state implementation.

- What was simpler or more awkward than expected?

  Reusing the existing WebSocket upgrade and frame helpers kept the transport
  side small. The useful surprise was the zero-based ACK sequence, which the
  previous mocks hid by starting at one.

- Did the API or implementation shape create accidental complexity?

  Not yet. The probe did not need public API changes. The only test-only
  complexity is HTTP query polling to prove rows are visible, not merely ACKed.

## Global reflection

- How does this fit into the bigger QWP/WebSocket Store-and-Forward design?

  It clears the hard protocol gate before queue work for Rust-generated
  self-sufficient replay frames.

- Did this step strengthen or weaken the core assumptions?

  It strengthens the core self-sufficient-frame assumption. A later replay frame
  carrying the dense symbol prefix and full schema was accepted as the first
  data frame on a fresh connection, and the replayed row was queryable.

- Should the next step proceed, or should the design be adjusted first?

  The real-server replay gate is passed. The core Java/Rust payload parity gate
  is now covered separately in
  `doc/QWP_WEBSOCKET_JAVA_RUST_GOLDEN_PAYLOADS.md`, so Step 5 can proceed.
