# QWP/WebSocket Failover Alignment Design

Status: design handoff

Date: 2026-05-12

Repository: `/home/jara/devel/oss/c-questdb-client`

Server and Java reference repository: `/home/jara/devel/oss/questdb-arrays`

## Goal

Close the Rust QWP/WebSocket failover gaps against the current QWP failover
spec and the Java client. The design should stay in the existing Rust shape:
configuration builds a QWP/WebSocket publisher, the transport owns connection
state, and the SFA queue remains only a publication/completion store.

The implementation must not add new SFA concepts, a new retry framework, or a
new public abstraction unless a spec requirement cannot be represented by the
existing code. When the spec and Rust are ambiguous, use the Java client as the
reference implementation.

Implement this in two slices:

1. **Slice 1: v1 multi-host failover.** Add multi-address parsing, the
   Java-like host tracker, endpoint walking, upgrade classification, equal
   jitter, initial-connect modes, and orphan-drainer reuse. Keep the current
   v1-pinned behavior for role/zone discovery: role is observed only through
   `421 + X-QuestDB-Role`, and zone stays unknown.
2. **Slice 2: v2 target/zone discovery.** Add the `SERVER_INFO` exchange,
   target matching, role/zone parsing, and zone-aware ordering after validating
   the current server and Java behavior. This slice is still part of full
   failover compliance, but it should not complicate the first v1 failover
   implementation.

## Sources Checked

Spec:

- [failover.md](/home/jara/devel/oss/questdb-arrays/docs/qwp/failover.md)
  - Multi-host `addr`, host states, zone priority, and no-shuffle endpoint
    order: lines 22-77.
  - Host tracker operations and ordering invariants: lines 82-160.
  - Equal-jitter backoff and role-reject retry rules: lines 191-236.
  - Ingress reconnect model: lines 238-247.
  - Target/role filtering and `SERVER_INFO` v2 behavior: lines 249-303.
  - Error classification and defaults: lines 305-389.

- [sf-client.md](/home/jara/devel/oss/questdb-arrays/docs/qwp/sf-client.md)
  - QWP/WebSocket config keys: lines 128-166.
  - Reconnect/failover requirements: lines 672-865.

Java reference:

- [Sender.java](/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/Sender.java)
  - `InitialConnectMode`: around lines 552-568.
  - Builder `address(...)` parsing and duplicate checks: around lines 780-878.
  - Config-string comma-separated `addr` parsing: around lines 2536-2566.
  - `initial_connect_retry` values `off`, `sync`, and `async`: around lines
    2812-2832.

- [QwpHostHealthTracker.java](/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/QwpHostHealthTracker.java)
  - State, zone-tier, attempted-this-round, `beginRound`, `pickNext`,
    `recordSuccess`, `recordTransportError`, `recordRoleReject`, and
    `recordMidStreamFailure`.

- [QwpWebSocketSender.java](/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/QwpWebSocketSender.java)
  - `buildAndConnect(ReconnectSupplier)` endpoint walk, typed upgrade
    classification, durable ACK mismatch handling, success/failover events,
    and round failure behavior: around lines 1920-2135.

- [QwpUpgradeFailures.java](/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/QwpUpgradeFailures.java)
  - `421` plus `X-QuestDB-Role` becomes role reject; `401` and `403` become
    auth failure; all other non-101 upgrade errors stay per-endpoint failures.

- [CursorWebSocketSendLoop.java](/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/CursorWebSocketSendLoop.java)
  - Reconnect loop, terminal upgrade classification, role-reject sleep, and
    equal-jitter exponential backoff: around lines 570-705.

Rust implementation:

- [questdb-rs/src/ingress.rs](/home/jara/devel/oss/c-questdb-client/questdb-rs/src/ingress.rs)
  - `from_conf` reads a single `addr` from `params.get("addr")`, splits it
    once on `:`, and builds one `(host, port)`: around lines 492-515.
  - QWP/WebSocket reconnect and auth config parsing: around lines 534-575.
  - `initial_connect_retry=async` is rejected: around lines 2018-2038.

- [questdb-rs/src/ingress/conf.rs](/home/jara/devel/oss/c-questdb-client/questdb-rs/src/ingress/conf.rs)
  - `QwpWsConfig` currently stores reconnect knobs, `auth_timeout`,
    `max_protocol_version`, durable ACK opt-in, and a boolean
    `initial_connect_retry`: around lines 159-229.

- [questdb-rs/src/ingress/sender/qwp_ws.rs](/home/jara/devel/oss/c-questdb-client/questdb-rs/src/ingress/sender/qwp_ws.rs)
  - The background runner intentionally keeps transport, cursor state,
    reconnect, and backoff out of the publication mutex: around lines 183-190.
  - `establish_connection(host, port, ...)` connects and upgrades one endpoint:
    around lines 1748-1815.
  - `open_qwp_ws_publisher` and `connect_blocking_transport_with_retry` retry
    the same endpoint with deterministic backoff: around lines 1865-1999.

- [questdb-rs/src/ingress/sender/qwp_ws_driver.rs](/home/jara/devel/oss/c-questdb-client/questdb-rs/src/ingress/sender/qwp_ws_driver.rs)
  - `QwpWsSendCore::reconnect_transport_with_policy` retries the current
    transport through `transport.restart_connection(reason)`: around lines
    866-935.
  - `reconnect_error_is_terminal` currently treats auth and protocol-version
    errors as terminal: around lines 1578-1588.
  - `BlockingQwpWsTransport` stores a single `host` and `port` and reconnects
    the same endpoint: around lines 1868-1935.

- [questdb-rs/src/ingress/sender/qwp_ws_codec.rs](/home/jara/devel/oss/c-questdb-client/questdb-rs/src/ingress/sender/qwp_ws_codec.rs)
  - `validate_upgrade_response` handles `401`/`403` as auth failures and any
    other non-101 status as protocol-version error. It reads `X-QWP-Version`
    and durable ACK support, but it does not classify `421` role rejects or
    compare the negotiated version against `max_protocol_version`: around
    lines 230-315.

- [questdb-rs/src/ingress/sender/qwp_ws_orphan.rs](/home/jara/devel/oss/c-questdb-client/questdb-rs/src/ingress/sender/qwp_ws_orphan.rs)
  - Orphan drainers currently connect with one configured host/port and their
    own reconnect policy: around lines 386-435.

## Current Gap Summary

Rust is a coherent single-endpoint QWP/WebSocket client. It does not yet
implement the failover document's multi-host endpoint selection semantics.

The main gaps are:

1. `addr` is single-valued in Rust. The spec and Java allow comma-separated
   entries and repeated `addr` keys, reject empty entries, and reject duplicate
   effective `(host, port)` entries.

2. The transport owns only one `(host, port)`. Reconnect retries the same
   endpoint instead of walking a host-health-ordered list.

3. There is no Rust equivalent of Java's `QwpHostHealthTracker`. Rust does not
   track `HEALTHY`, `FAILED_THIS_ROUND`, `ROLE_REJECTED`, or
   `HEALTH_UNKNOWN`, does not reset attempted hosts by round, and does not
   demote a mid-stream failed endpoint before picking the next endpoint.

4. Upgrade failure classification is too coarse. Rust treats most non-101
   upgrade responses as protocol-version errors. The spec and Java require:
   auth failures (`401`/`403`) are terminal, `421` with
   `X-QuestDB-Role` is a role/topology reject, and other transport/status
   failures are per-endpoint transient failures until the whole round is
   exhausted.

5. The retry sleep is deterministic. The spec and Java use equal jitter:
   sleep in `[backoff, 2 * backoff)`, capped by the remaining reconnect budget,
   with exponential backoff only after failed rounds.

6. `initial_connect_retry=async` is not supported. Java supports `OFF`, `SYNC`,
   and `ASYNC`. The Rust config currently stores a boolean and rejects `async`.

7. `auth_timeout_ms` semantics are not aligned. The Java builder documents it
   as the per-endpoint WebSocket upgrade response read timeout. Rust currently
   passes the QWP auth timeout into TCP/TLS setup as well as upgrade.

8. Full failover compliance includes v2 `SERVER_INFO` role/zone discovery and
   `target=` behavior. The current Rust ingress path is effectively v1-pinned
   by default and does not expose target selection.

## Design Principles

- Keep failover in the connect/reconnect layer. SFA queue, FSN completion,
  durable ACK FIFO, and publication locking should not change.

- Keep the publication hot path lock-free and allocation-free. All endpoint
  vectors, role strings, parsed headers, tracker state, random state, and error
  messages are configuration/connect/reconnect concerns, not row publication
  concerns.

- Use one simple internal host tracker, modeled directly on Java's
  `QwpHostHealthTracker`. Do not add a generic load balancer, service discovery
  layer, or pluggable retry strategy.

- Preserve configured address order. The spec explicitly says not to shuffle.
  Priority is `(host state, zone tier, configured order)`.

- Keep host-health state local to each connect/reconnect loop in slice 1. The
  main transport and each orphan drainer get their own tracker and their own
  `previous_idx`. This avoids cross-thread tracker locking while preserving
  correct endpoint walking per loop. Add shared health later only if a measured
  behavior gap requires it.

- Treat Java behavior as the implementation oracle when a spec edge is
  underspecified. The current Java client walks endpoints inside a round, only
  sleeps after a failed round, immediately terminalizes auth, and latches
  typed durable/version/upgrade failures until the round has been walked.

## Target Rust Shape

### 1. Address List Parsing

Add an internal endpoint type close to:

```rust
struct QwpWsEndpoint {
    host: String,
    port: String,
}
```

The config parser should produce `Vec<QwpWsEndpoint>` for QWP/WebSocket.
Existing single-address builder behavior should become the one-element case.

Parsing rules:

- Accept `addr=host`, `addr=host:port`, and comma-separated entries.
- Accept repeated `addr` keys and append entries in source order.
- Trim whitespace around comma-separated entries.
- Reject empty entries, empty hosts, invalid ports, and duplicate effective
  `(host, port)` pairs.
- Use the protocol default port when an entry omits a port.
- Do not change UDP/TCP/HTTP address semantics in this failover slice.

Implementation note: current Rust `from_conf` uses `params.get("addr")`, which
only exposes one value to this code path. The implementation must first verify
whether the `questdb_confstr` parser preserves duplicate keys anywhere. If it
does not, add a small QWP/WebSocket-only `addr` pre-scan or parser extension so
repeated `addr` keys are not silently dropped. Do not mirror every Java builder
detail; just make the config-string behavior compliant.

### 2. Host Health Tracker

Add a small internal `QwpWsHostHealthTracker` under the QWP/WebSocket sender
module. It should mirror Java's state machine rather than inventing a generic
policy object.

State per endpoint:

- `Healthy`
- `HealthUnknown`
- `FailedThisRound`
- `RoleRejected`

Additional per-endpoint data:

- `attempted_this_round: bool`
- `zone_tier: u8` or equivalent small integer, defaulting to unknown in slice 1

Operations:

- `begin_round(reset_attempted: bool)`
- `is_round_exhausted()`
- `pick_next() -> Option<usize>`
- `record_success(idx)`
- `record_transport_error(idx)`
- `record_role_reject(idx, transient: bool)`
- `record_mid_stream_failure(idx)`
- `record_zone(idx, zone)` in slice 2

Selection order:

1. Lower state priority wins.
2. Lower zone tier wins.
3. Lower configured endpoint index wins.

Do not allocate during `pick_next`; it should scan the existing endpoint slice
and return an index.

Threading:

- The foreground sender and orphan drainers each own a tracker and a
  `previous_idx`.
- Do not introduce `Arc<Mutex<QwpWsHostHealthTracker>>` in slice 1. Reconnect is
  off the publication hot path, but the simpler per-loop tracker avoids shared
  lifetime and locking concerns.
- The endpoint list itself can still be shared by `Arc<[QwpWsEndpoint]>`.

### 3. Connect Attempt Classification

Split upgrade/connect failures into the outcomes needed by the endpoint walk.
This can be a small internal enum returned by one connect-attempt helper; it
does not need to become a public error taxonomy.

Use four outcomes:

- `Connected`: TCP/TLS/WebSocket upgrade succeeded and the connected transport
  can become the active transport.
- `AuthTerminal`: HTTP `401` or `403`. Terminal immediately because
  credentials are cluster-wide.
- `RoleReject`: HTTP `421` with non-empty `X-QuestDB-Role`. Record role reject
  and continue walking the current round. `PRIMARY_CATCHUP` is transient; all
  other role values are topology rejects. Preserve the role and optional
  `X-QuestDB-Zone` for diagnostics and slice 2 zone recording.
- `RetryableEndpointFailure`: TCP failure, TLS failure, HTTP status without a
  terminal classification, frame decode failure, timeout, `421` without a role
  header, unsupported version, durable ACK mismatch, or slice 2 target mismatch
  while the round still has candidates.

For retryable failures that should win the final error when the full round
fails, keep a latched error alongside the loop state. Unsupported QWP version,
durable ACK mismatch, and slice 2 target mismatch are examples of latched
round failures. This keeps the connect-attempt enum small while preserving
Java-like final error reporting.

Concrete codec changes:

- Keep `401`/`403` as auth errors.
- Stop mapping every non-101 status to protocol-version error.
- Parse `421` plus `X-QuestDB-Role` and optional role-zone header into a role
  rejection result.
- Compare `X-QWP-Version` to `[1, max_protocol_version]`. If the server's
  version is unsupported, treat the endpoint attempt as retryable, latch the
  version error, and surface it if the full round fails.
- Keep `request_durable_ack` validation after a successful upgrade, because it
  depends on parsed upgrade headers.

### 4. Endpoint Walk and Reconnect Loop

Replace the single-endpoint reconnect loop with one Java-like endpoint-walk
helper. Use this same helper for initial connect, mid-stream reconnect, and
orphan-drainer reconnect. Do not fork separate endpoint-walk implementations.

The helper should:

1. On mid-stream failure, first record `record_mid_stream_failure(previous_idx)`
   for the endpoint that just failed. Then clear the local `previous_idx`.

2. If the current round is exhausted, increment the round sequence and call
   `begin_round(true)`.

3. Repeatedly call `pick_next()` until it returns no endpoint:
   - attempt TCP/TLS/WebSocket upgrade for that endpoint,
   - classify the failure,
   - update tracker state,
   - continue without sleeping while the round still has candidates.

4. On success:
   - `record_success(idx)`,
   - set local `previous_idx = Some(idx)`,
   - swap the transport's stream/codec state,
   - preserve the existing replay path. Reconnect success should still call
     the existing `finish_reconnect_success` queue/driver path.

5. On exhausted round:
   - if a typed terminal cluster error was latched, surface it,
   - if the last role reject explains the outage, surface role mismatch,
   - otherwise surface "all endpoints unreachable" with the last endpoint and
     last error.

6. The outer retry loop sleeps only after a failed round, not between
   endpoints. Use equal jitter and clamp to the reconnect deadline.

Role-reject retry:

- If the failure after a round is role mismatch or role reject, reset backoff
  to `reconnect_initial_backoff` and sleep the initial interval before the next
  round. Do not double backoff on each role-reject round.

Backoff:

```text
base = current_backoff
sleep = base + uniform_random(0, base)
sleep = min(sleep, remaining_budget)
next_backoff = min(base * 2, reconnect_max_backoff)
```

The random number generator is used only in reconnect code. It must not touch
the publication path.

### 5. Initial Connect Modes

Replace the QWP/WebSocket boolean `initial_connect_retry` with an internal enum:

```rust
enum InitialConnectMode {
    Off,
    Sync,
    Async,
}
```

Config compatibility:

- `off` and `false` map to `Off`.
- `on`, `true`, and `sync` map to `Sync`.
- `async` maps to `Async`.

Behavior:

- `Off`: constructor performs one no-sleep endpoint-list walk. If all endpoints
  fail, construction returns the classified error. This still tries every
  configured endpoint once, matching Java's `buildAndConnect` behavior.
- `Sync`: constructor keeps retrying failed rounds with the reconnect policy
  until success, terminal error, or reconnect budget exhaustion.
- `Async`: constructor returns after creating the publication queue and
  starting the background I/O loop. The I/O loop runs the same connect/reconnect
  policy and reports terminal failure through the existing async error path.

Rust manual-progress mode is not Java's normal mode. If `Async` cannot make
progress without a background runner, reject `initial_connect_retry=async` when
`qwpws_progress=manual` is selected, with a clear error. Do not silently
downgrade it to `Sync`.

Implementation detail:

- `QwpWsSendCore` currently requires a live transport, so `Async` should be
  implemented in the threaded runner, not by teaching the send core a fake
  disconnected transport.
- Make the runner core hold `Option<QwpWsSendCore<BlockingQwpWsTransport>>`
  plus the immutable connect plan while initial connect is pending.
- While the option is `None`, `drive_step` runs the same endpoint-walk reconnect
  policy used by `Sync`, with phase text "initial connect". On success it
  constructs `QwpWsSendCore` from the connected transport and then enters the
  normal send/reconnect path.
- Producer publication still goes only through `QwpWsPublicationStore`, so rows
  can accumulate while the background thread is connecting.
- Manual progress mode must reject `initial_connect_retry=async` because no
  background thread exists to make progress.

This is the smallest Java-like shape because the publication store already
exists before the background thread is started, while the transport/send core is
connection-local.

### 6. Timeout Semantics

There is a spec/Java wording mismatch around `auth_timeout_ms`:

- Java's builder text describes it as the per-endpoint WebSocket upgrade
  response read timeout.
- `failover.md` describes the per-endpoint role-filter sequence as opening
  TCP/TLS within `auth_timeout_ms`, then issuing the HTTP upgrade.
- Rust currently passes the QWP auth timeout into TCP/TLS setup as well as
  upgrade.

Do not rework timeout ownership in slice 1 unless a failover test requires it.
Before changing the timeout behavior, validate Java and server behavior and
update this section with the chosen contract. The endpoint-walk design should
work with either interpretation because timeout failures are just
`RetryableEndpointFailure` for the current endpoint.

### 7. Slice 2: Target, Role, Zone, and SERVER_INFO

Full failover compliance requires the v2 behavior described in `failover.md`.
This is the second implementation slice. It must remain implementable, but it
should not be mixed into the first v1 multi-host failover slice.

Implement slice 2 in this order:

1. Validate the public ingress config key for target selection against the
   current spec, Java config parser, and server. If the confirmed key is
   `target`, accept exactly `any`, `primary`, and `replica`.

2. Add an internal target enum:

   ```rust
   enum QwpWsTarget {
       Any,
       Primary,
       Replica,
   }
   ```

   Preserve current behavior when the key is absent. Do not guess a new public
   default from the failover doc alone; use the Java/server behavior validated
   in step 1.

3. Raise `max_protocol_version` only after validating server and Java
   interoperability. Until then, slice 1 keeps the existing v1-pinned behavior.

4. After a successful upgrade with negotiated version >= 2, read one
   `SERVER_INFO` frame before sending application data. Parse:
   - role byte,
   - capabilities,
   - `zone_id` when `capabilities & CAP_ZONE` is set.

5. Apply the failover role table:
   - `target=any` accepts `STANDALONE`, `PRIMARY`, `REPLICA`, and
     `PRIMARY_CATCHUP`.
   - `target=primary` accepts `STANDALONE`, `PRIMARY`, and
     `PRIMARY_CATCHUP`; rejects `REPLICA`.
   - `target=replica` accepts `REPLICA`; rejects `STANDALONE`, `PRIMARY`, and
     `PRIMARY_CATCHUP`.

6. For v1 negotiation after target support exists:
   - `target=any` matches,
   - `target=primary` and `target=replica` produce topology reject, because v1
     cannot prove the role through `SERVER_INFO`.

7. Record zones:
   - On `421`, read `X-QuestDB-Zone` when present.
   - On v2 success, read `SERVER_INFO.zone_id` when `CAP_ZONE` is set.
   - Compare zone identifiers case-insensitively against configured `zone=`.
   - For ingress, keep zone preference disabled unless the spec says otherwise;
     the checked failover doc says ingress is zone-blind and pinned to v1.

8. Feed target mismatch back into the same endpoint-walk helper as a retryable
   endpoint failure with a latched topology error. Do not add a separate
   topology manager.

Do not add a broad cluster-topology cache. The host tracker needs only the
reported role/zone data for endpoint ordering and error messages.

### 8. Orphan Drainers

Orphan drainers should use the same endpoint list and classification rules as
the main sender. They do not need special failover logic.

Recommended shape:

- Store the parsed endpoint list and reconnect policy in the drainer config.
- Give each drainer its own host tracker and `previous_idx`.
- Reuse the same connect helper used by the foreground/background sender.

This avoids a second implementation of role rejects, jitter, and endpoint
rounds.

### 9. Events and Errors

The Rust data path does not need a Java-style public connection listener to be
behaviorally compliant. Existing driver events and sender errors are enough for
data correctness.

Still, error text should carry the same operational facts Java exposes:

- auth failed at endpoint,
- all endpoints unreachable,
- role mismatch with last observed role and endpoint,
- durable ACK mismatch,
- unsupported QWP version,
- reconnect budget exhausted after elapsed time and attempt count.

If public failover events are added later, do not add a separate event system
for this slice. Map them onto the existing driver/event plumbing or a narrow
connection callback in the builder.

## Implementation Order

### Slice 1: v1 Multi-Host Failover

1. Add endpoint-list parsing and tests.
   - This is independent of reconnect.
   - Keep single-address behavior as the one-endpoint case.

2. Add the per-loop host tracker with Java-mirroring unit tests.
   - Test configured-order tie breaks.
   - Test healthy-before-unknown.
   - Test `recordMidStreamFailure` demotion.
   - Test role reject and round reset behavior.

3. Refactor single-endpoint connect into a reusable endpoint-attempt helper.
   - No behavior change yet except clearer classification internals.
   - Keep allocations limited to connection setup and error construction.

4. Implement multi-endpoint initial connect `Off` and `Sync`.
   - One full endpoint walk before returning failure for `Off`.
   - Equal-jitter sleeps only after failed rounds for `Sync`.

5. Route reconnect through the endpoint walk.
   - Preserve existing replay and completion behavior.
   - Add tests proving a failed previous endpoint is demoted before round
     reset.

6. Align upgrade classification.
   - `401`/`403` terminal.
   - `421` plus role header role-reject.
   - other non-101 statuses per-endpoint transient until round exhaustion.
   - durable ACK mismatch latched across a round.
   - version mismatch latched across a round.

7. Implement `initial_connect_retry=async`.
   - Use existing background runner/error delivery.
   - Reject clearly for manual progress if there is no background thread to
     make progress.

8. Wire orphan drainers to the same endpoint-list connect helper, with each
   drainer keeping its own tracker and `previous_idx`.

### Slice 2: v2 Target, Zone, and SERVER_INFO

1. Validate the ingress `target` key and default against the current spec,
   Java parser, and server.

2. Add `QwpWsTarget` config parsing only after the key/default are confirmed.

3. Raise or expose `max_protocol_version` for v2 only after interoperability is
   validated.

4. Read and parse `SERVER_INFO` after successful v2 upgrade and before sending
   application data.

5. Apply target matching and zone recording through the same endpoint-walk
   helper.

6. Add behavioral tests for `target=any`, `target=primary`, `target=replica`,
   v1 target rejection, `421 + X-QuestDB-Zone`, and v2 `SERVER_INFO.zone_id`.

Slice 1 is required to close the observable v1 multi-host failover gap. Slice 2
is required for full v2 failover compliance.

## Tests

Prefer behavioral tests at the public or transport boundary. Avoid tests that
assert private field layout unless the unit is the host tracker itself.

Parser tests:

- `qwpws::addr=a:1,b:2;` preserves order.
- repeated `addr` values append in order.
- whitespace around comma-separated entries is ignored.
- empty entry, empty host, invalid port, and duplicate effective endpoint are
  rejected.
- non-QWP protocols retain existing single-address behavior.

Host tracker unit tests:

- `pick_next` follows `(state, zone tier, configured order)`.
- slice 1 initializes every endpoint with the same unknown zone tier, so state
  and configured order decide selection.
- `record_success` makes an endpoint healthy and clears round-attempt state as
  Java does.
- `record_transport_error` marks the endpoint failed for the round.
- `record_role_reject(transient=false)` keeps the endpoint role-rejected across
  normal round reset.
- `record_mid_stream_failure` demotes the previous live endpoint before the
  next pick.

Connection classification tests:

- Fake upgrade response `401` or `403` terminalizes immediately.
- `421` with `X-QuestDB-Role` records role reject and tries the next endpoint.
- `421` without a role header is a transient endpoint failure.
- `404` or `500` walks the remaining endpoints and only then reports all
  endpoints unreachable or the latched typed failure.
- unsupported `X-QWP-Version` is latched while walking the rest of the round.
- durable ACK mismatch walks remaining endpoints and terminalizes only if no
  endpoint satisfies durable ACK.

Reconnect behavior tests:

- initial `Off` tries every configured endpoint once and succeeds if a later
  endpoint is reachable.
- initial `Off` does not sleep or retry a second round.
- initial `Sync` retries failed rounds until success or budget exhaustion.
- mid-stream failure of endpoint A demotes A and reconnects to B when B is
  available.
- role-reject rounds reset to the initial backoff instead of exponential
  doubling.
- equal-jitter sleep is bounded by `[backoff, 2 * backoff)` and by the
  remaining reconnect budget. Use an injected deterministic RNG/sleeper in
  tests, not wall-clock sleeps.

Orphan-drainer tests:

- a drainer can recover through the second endpoint when the first endpoint is
  down.
- drainer reconnect uses the same classification for `421` role reject.

Slice 2 tests:

- `target=any` accepts every `SERVER_INFO` role in the failover table.
- `target=primary` accepts `STANDALONE`, `PRIMARY`, and `PRIMARY_CATCHUP`, and
  rejects `REPLICA`.
- `target=replica` accepts `REPLICA` and rejects other roles.
- v1 negotiation with explicit `target=primary` or `target=replica` produces a
  topology reject.
- `421 + X-QuestDB-Zone` and v2 `SERVER_INFO.zone_id` update zone tier without
  allocating during `pick_next`.
- target mismatch walks the next endpoint and latches a topology error for
  round exhaustion.

System tests:

- Use real QuestDB QWP/WebSocket where possible.
- Keep Java tests as the model: one dead endpoint followed by one live endpoint
  should be enough to prove endpoint-list failover without creating a large
  special-case matrix.
- Add a role-reject/topology test only when the local server harness can expose
  a replica or controlled `421` role response. Do not emulate server protocol
  behavior with excessive mocks.

## Performance Notes

- Address parsing allocates during configuration only.
- Endpoint metadata is stored once and reused. Prefer `Arc<[QwpWsEndpoint]>`
  or a `Vec<QwpWsEndpoint>` owned by a shared connect plan.
- Each host tracker uses fixed-size vectors sized to the endpoint count. It
  should not allocate in `pick_next` or state updates.
- Slice 1 should not add a tracker mutex. Trackers are local to the reconnect
  loop that owns them.
- Reconnect may allocate error strings and parse HTTP headers; this is outside
  the row-publication hot path.
- Do not put DNS resolution, TCP connect, TLS handshake, upgrade parsing, RNG,
  or sleeps behind the publication mutex.
- The existing comment in `qwp_ws.rs` that reconnect/backoff stay in the
  background loop should remain true after this work.

## Non-Goals

- No change to SFA segment format, durable ACK FIFO, replay encoding, receipt
  completion, or close-drain semantics.
- No UDP failover work.
- No generic service-discovery interface.
- No new public connection-listener API unless a separate API design explicitly
  requires it.
- No broad rewrite of Rust error taxonomy. Add only the internal
  classification needed to implement the endpoint walk correctly.

## Required Pre-Implementation Validation

These are not design guesses; they are explicit checks for the implementation
agent before editing code:

1. Repeated `addr` keys:
   - Check whether `questdb_confstr::parse_conf_str` preserves duplicate keys
     in any accessible form.
   - Required outcome: `qwpws::addr=a:1;addr=b:2;` produces endpoints
     `[a:1, b:2]` in this order.
   - If the parser exposes only the last value or an unordered map, add a small
     QWP/WebSocket config pre-scan for `addr` before applying the generic
     parsed map. Do not accept silent dropping of earlier addresses.

2. Role and zone headers:
   - Inspect the current Java `WebSocketClient` and server upgrade code for
     the exact role and zone header names.
   - Required outcome: codec tests use the exact server header names. `421`
     with the role header is role reject; `421` without that header is a
     transient endpoint failure.

3. `auth_timeout_ms` ownership:
   - Check Java connection code, server expectations, and current spec wording.
   - Required outcome for slice 1: do not change existing Rust timeout behavior
     unless a failover behavior test depends on the change.
   - Required outcome for any timeout change: update this doc with the chosen
     Java/spec contract before editing code.

4. Ingress `target` key:
   - Re-check `failover.md`, `sf-client.md`, Java config parsing, and server
     behavior for whether ingress currently exposes `target=`.
   - Required outcome for v1 work: do not add a guessed public key.
   - Required outcome for v2 work: if the spec confirms a key, implement that
     exact key; otherwise implement only role/zone discovery needed by the
     protocol and leave public target selection out.

5. Protocol v2 and `SERVER_INFO`:
   - Confirm current server support and Java behavior before raising Rust's
     default `max_protocol_version`.
   - Required outcome for v1 work: keep the existing default, classify
     unsupported `X-QWP-Version` correctly, and do not send unimplemented v2
     control requests.
   - Required outcome for full v2 work: add a concrete `SERVER_INFO` exchange,
     parse role/zone, and add behavioral tests against either the Java shape or
     a real server.

6. `initial_connect_retry=async`:
   - Confirm that only the threaded/background QWP/WebSocket mode can make
     progress without a connected transport.
   - Required outcome: threaded mode supports `async`; manual progress mode
     rejects it with a clear config error.

## Validation Commands

Run these after the failover implementation:

```bash
cargo fmt --check --manifest-path questdb-rs/Cargo.toml
cargo test --manifest-path questdb-rs/Cargo.toml --features sync-sender-qwp-ws --lib qwp_ws
cargo test --manifest-path questdb-rs/Cargo.toml --features sync-sender-qwp-ws --lib qwp_ws_driver
cargo check --manifest-path questdb-rs/Cargo.toml --no-default-features --features _sender-qwp-ws,ring-crypto,tls-webpki-certs
```

If the change touches publication, replay, transport read buffers, or any code
claimed to stay allocation-free after warmup, also run the warmed allocation
regression:

```bash
cargo test --manifest-path questdb-rs/Cargo.toml --features sync-sender-qwp-ws --lib zero_alloc_after_warmup -- --ignored --test-threads=1
```

If system tests are available in the checkout, add one live QWP/WebSocket
multi-endpoint test using `/home/jara/devel/oss/questdb-arrays` as the server
repo:

```bash
python3 system_test/test.py run
```

The exact system-test selector may change with the local harness. The required
behavior is not a broad matrix: one unreachable endpoint followed by one live
QWP/WebSocket endpoint must publish, flush, and observe ACK progress.
