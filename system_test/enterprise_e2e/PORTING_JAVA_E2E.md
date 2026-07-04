# Porting java-questdb-client Enterprise e2e scenarios to c-questdb-client

Tracking checklist for porting every QWP e2e scenario that today only exists
for the Java client (in `questdb-enterprise`) into this repo's
`system_test/enterprise_e2e` suite (run by Enterprise's
`ci/build-and-test-e2e-c-client.yaml` cross-repo pipeline, marker `c_client`).

## Scope decisions (agreed 2026-07-04)

- **QWP only** — no ILP (TCP/HTTP) tests, no QWP-UDP.
- **ACL / OIDC / TLS-auth deferred** — not in this pass.
- **Egress (reader) parity: in scope.** Rust client already has
  `egress::ReaderConfig` with `target=` / `zone=`.
- **Transactions: in scope.** Rust sender already has transactional QWP
  flush (`flush_qwp_ws_buffer(.., transactional)`).
- **Bindings: yes** — key scenarios duplicated to C and C++ sidecars,
  following the `test_orphan_drainer_bindings.py` pattern.
- **Java in-process JUnit lifecycle tests: in scope** — re-expressed as
  forked-server pytest scenarios against real servers (not in-process).

Source suites in `questdb-enterprise`:

- **A.** Python-orchestrated suite `questdb-ent/e2e/tests/` driving the
  production Java `QwpWebSocketSender` / `QwpQueryClient` via
  `QwpSidecarMain` / `QwpEgressSidecarMain`.
- **B.** Java JUnit tests under `questdb-ent/src/test/java/com/questdb/`
  (`lifecycle/`, `cairo/wal/transfer/`) that drive the QWiP java client
  against in-process Ent clusters.

## Already ported (no action)

From `questdb-ent/e2e/tests/` — 1:1 Rust equivalents exist here:

- `test_failover.py` (all 8: kill9 no-data-loss, failover during active
  send, two failovers, no-durable-ack loses rows, orphan-drainer survives
  kill, sender kill9 SF recovery, repeated-SIGKILL torture, partial-ack
  sealed-segment dedup) — plus extra Rust-only variants.
- `test_failover_fuzz.py::test_random_failover`
- `test_failover_graceful.py::test_graceful_failover_round_trip`
- `test_switch_roundtrip_crash_repro.py`
- Orphan-drainer + no-durable-ack already duplicated to **C** and **C++**
  (`test_orphan_drainer_bindings.py`).

---

## Group 1 — ingress sender scenarios (from python suite A)

### `test_txn_kill9_atomicity.py` (transaction=on + SIGKILL mid-txn)

**Capability verdict (resolved): the Rust QWP/WS row sender has NO
`transaction=on` mode.** Evidence:
`questdb-rs/src/ingress/sender.rs:318-323` explicitly rejects
transactional QWP/WS flushes ("Transactional flushes are not supported
for QWP/WebSocket."); `conf.rs` has no `transaction` key; the deferred
encoder exists (`buffer/qwp.rs:3562`, flag at :3654) but its only caller
hardcodes `defer_commit=false` (`buffer/qwp.rs:3559`,
`qwp_ws_publisher.rs:52`); SF recovery has no orphan-tail retirement
(torn-frame scan only). A FLUSH_DEFER sidecar verb was therefore NOT
added — there is no client API to bind it to. **Client feature gap:**
`transaction=on` (FLAG_DEFER_COMMIT framing + commit on FLUSH) + orphan
deferred-tail retirement in SF recovery.

- [ ] **BLOCKED (client gap above)**
      `test_kill9_mid_txn_uncommitted_rows_never_appear` — commit txn 1,
      open txn 2, SIGKILL between deferred auto-flushes, restart on same
      slot; uncommitted rows must never appear.
- [ ] **BLOCKED (client gap above)**
      `test_kill9_whole_log_deferred_fast_path_retirement` — nothing ever
      committed; recovery retires the whole orphan deferred log via the
      fast path.
- [ ] **BLOCKED (client gap above + needs FLUSH_DEFER verb)**
      `test_kill9_between_deferred_flushes_deterministic` — the literal
      "SIGKILL between deferred flushes" scenario made deterministic via
      the FLUSH_DEFER verb.
- [x] `test_kill9_at_commit_boundary_no_orphan` — SIGKILL immediately
      after commit flush returns; SF log ends with commit-bearing frame,
      no orphan tail. **Ported** as
      `test_kill9_at_commit_boundary_no_orphan_c_client_rust`, adapted:
      no deferred prefix (every Rust FLUSH is commit-bearing); the
      distinctive surface vs the existing kill9-recovery test is the
      zero-settle kill immediately after FLUSH returns (pins
      FLUSH-return ⇒ publication durable in SF).

### `test_durable_ack_failover.py`

- [x] `test_durable_ack_sender_survives_replica_only_window` — durable-ack
      sender must survive a window where only a replica is reachable.
- [x] `test_durable_ack_drainer_never_gives_up_on_reconnect_budget` —
      INVARIANT B: with rows in on-disk SF the drainer must never
      terminate on a wall-clock reconnect budget (may back off only).
      (Related but distinct from the existing
      `test_orphan_drainer_durable_ack_survives_drain_reconnect_c_client_rust`.)
      Rust adaptation: the post-promotion confirmation publishes one tail
      row before the final flush — the Rust empty-buffer flush returns -1
      (Java returns the highest published FSN), which AWAIT_ACKED rejects.
      Verified in-source that the Rust driver rolls the budget over
      (`retry_budget_exhausted_error` is not `reconnect_error_is_terminal`;
      only AuthError/ProtocolVersionError latch terminal, role-rejects
      explicitly retryable) — matching shipped Java semantics.

### `test_demotion_mid_stream.py`

- [x] `test_graceful_demotion_mid_stream_sender_survives` — in-place
      graceful P→R demotion underneath an actively-sending sender.
      Also covers Group-3 `testQwpDurableAckSenderSurvivesInPlaceDemote`
      (ticked there). `server_errors == 0` wire pin maps to the Rust
      driver's `total_server_errors` (TransportResponse::Reject only —
      same NACK-not-close semantics as Java).

### `test_switch.py` (D-23 / D-24 graceful role-switch suite)

Note: the existing `test_switch.py` here has 2 SF-centric switch tests;
these 4 are additional, probe-oriented scenarios.

- [x] `test_characterize` — D-23 empirical characterization of the P→R→P
      switch window. Ported as `test_characterize_c_client_rust`
      (tests/test_switch.py); Rust-only — the QWeP probes need the Rust
      egress sidecar. Probes/lifecycle come from the shared Enterprise
      harness (`lib.probes` / `lib.lifecycle`) — nothing copied.
- [x] `test_reads_not_frozen` — D-24(i): reads-not-frozen regression
      guard, 100% oblivious probes. Ported as
      `test_reads_not_frozen_c_client_rust`. The flat-`reconn_succ`
      assertion holds for the Rust sender too: the idle, durably-acked
      ingress connection survives the P→R→P round-trip (verified live).
- [x] `test_write_path_across_switch` — D-24(ii). Ported as
      `test_write_path_across_switch_c_client_rust` (Invariant B
      containment + REPLICA exact-count + ack-barriered SF drain +
      dense oracle).
- [x] `test_disturbance_honesty_guard` — D-24(iii): "disturbance really
      happened" honesty guard. Ported as
      `test_disturbance_honesty_guard_c_client_rust` (T-10-22).
      Rust adaptations for the quartet: `username=`/`sender_id=` connect
      keys, 0-based FSN guards (`>= 0`), and a published-FSN guard before
      every `await_acked` (empty-buffer flush returns -1).

### `test_switch_fuzz.py`

Existing here: `test_qwp_role_switch_fuzz_uncoordinated_client`. Port the
remaining dimensions:

- [ ] `test_switch_fuzz` — seed-isolated switch-roundtrip fuzz with
      chain/survival/read-prober/exact-count-with-quiescence oracles.
- [ ] `test_switch_fuzz_pitr` — live QWP client ingesting across
      PITR-recovered boot + first switch.
- [ ] `test_switch_fuzz_pinned_seed_5171257088512701991` — port as a
      **pinned flip-chain** (explicit P→R→P sequence), not the raw seed
      (Java RNG seed will not reproduce the same chain in this harness).
- [ ] `test_switch_fuzz_live_replica_failover` — bounded live-replica
      failover fuzz dimension.

## Group 2 — egress / reader parity (from python suite A)

Rust prereqs present: `egress::ReaderConfig` `target=` (any/primary/replica)
and `zone=`; `qwp_egress_sidecar.rs` exists. Extend the egress sidecar
verbs as needed (SHOW_ZONE / role probes).

### `test_target_filter.py` — ported (tests/test_target_filter.py, all pass live)

- [x] `test_target_replica_skips_primary_at_startup`
- [x] `test_target_replica_fails_when_only_primary_available` — must fail
      loudly with a role-mismatch error, not silently degrade.
      (Adapted: Rust error text is `does not match target=Replica`
      (enum Debug casing) vs Java's `target=replica`; asserted with a
      case-insensitive match.)
- [x] `test_target_replica_failover_skips_primary` — per-Execute reconnect
      keeps filtering the primary mid-failover.
- [x] `test_target_primary_failover_to_promoted_replica` — "follow the
      master" across promotion.

No sidecar verbs needed: `qwp_egress_sidecar.rs` already speaks
CONNECT/QUERY/SHOW_ZONE/SERVER_INFO/CLOSE, and `Reader::from_conf`
binds eagerly with the target filter applied at CONNECT time (same
semantics as the Java `QwpQueryClient.connect()`).

### `test_zone_failover.py`

- [x] `test_startup_reports_bound_zone` → `test_zone_failover.py::test_startup_reports_bound_zone_c_client_rust`
- [x] `test_falls_back_to_other_zone_when_no_same_zone_available` —
      zone is a preference, not a constraint. →
      `test_falls_back_to_other_zone_when_no_same_zone_available_c_client_rust`
- [x] `test_failover_reports_new_zone` → `test_failover_reports_new_zone_c_client_rust`
- [x] `test_zone_preference_breaks_state_ties` →
      `test_zone_preference_breaks_state_ties_c_client_rust` (proves the
      Rust tracker's `(state, zone_tier)` lattice breaks TransportError
      ties by zone exactly like the Java WalkTracker; no adaptation
      needed — sidecar already had CONNECT/SHOW_ZONE/SERVER_INFO)

## Group 3 — Java JUnit in-process tests → forked-server pytest scenarios

These exist only as JUnit tests with in-process two-node clusters.
Re-express each as a pytest scenario with forked servers + Rust sidecar.

### Ingress lifecycle

- [ ] `SqlFailoverQwpClientLosslessTest.testObliviousQwpClientLosslessAcrossSqlFailover`
      — sender configured with BOTH endpoints, oblivious to a
      SQL-triggered primary move; lossless.
- [ ] `SqlFailoverQwpClientLosslessTest.testObliviousDurableAckQwpClientLosslessNoCatchupWait`
      — durable-ack variant, no catch-up wait.
- [ ] `SqlFailoverQwpDeferredCloseExactlyOnceTest.testDeferredCloseExactlyOnceWithUploadsHeldUntilDemoteDrain`
      — deterministic witness for role-change close deferral
      (`roleChangeCloseWithUploadGrace`): exactly-once delivery with
      uploads held until demote drain.
- [ ] `DurableAckThroughDemoteTest.testDurableAckClientThroughDemoteIsReleasedOrTerminalWithinBound`
      — durable-ack client carried through P→R demote is released or
      terminal within a bound (never hangs).
- [x] `DurableAckThroughDemoteTest.testQwpDurableAckSenderSurvivesInPlaceDemote`
      — overlaps Group 1 `test_demotion_mid_stream`; covered by
      `test_graceful_demotion_mid_stream_sender_survives_c_client_rust`.
- [ ] `QwpRoleBounceChaosLosslessTest.testObliviousDurableAckSenderAndHistoricalReadersSurviveRoleBouncing`
      — chaos role bouncing (P→R, R→P, repeatedly, randomized timing);
      oblivious durable-ack sender + concurrent historical readers, lossless.

### Egress lifecycle

- [ ] `QwpEgressDropDemoteRaceTest.testQwpEgressDropTableDuringDemoteReplicatesOrRefuses`
      — WAL DROP driven through the QWP egress channel racing a demote:
      must replicate or refuse (no half-state). Requires egress DDL/exec
      support in the Rust reader; verify API exists first.

### Egress server-info / role / zone

Dedup note: the `target=` scenarios overlap Group 2 `test_target_filter`;
tick them off jointly where one pytest scenario covers both.

- [ ] `QwpEgressServerInfoRoleTest.testPrimaryReportsPrimaryRole`
- [ ] `QwpEgressServerInfoRoleTest.testReplicaReportsReplicaRole`
- [ ] `QwpEgressServerInfoRoleTest.testMultiEndpointTargetPrimaryPicksPrimary` (≈ Group 2)
- [ ] `QwpEgressServerInfoRoleTest.testMultiEndpointTargetReplicaPicksReplica` (≈ Group 2)
- [ ] `QwpEgressServerInfoRoleTest.testTargetPrimaryAgainstReplicaOnlyRaisesMismatch` (≈ Group 2)
- [ ] `QwpEgressServerInfoRoleTest.testReadFromReplicaReturnsSameDataAsPrimary`
- [ ] `QwpEgressServerInfoRoleTest.testFailoverToReplicaReplaysAfterMidStreamDisconnect`
- [ ] `QwpEgressServerInfoZoneTest.testPrimaryAdvertisesConfiguredZone`
- [ ] `QwpEgressServerInfoZoneTest.testReplicaAdvertisesConfiguredZone`
- [ ] `QwpEgressServerInfoZoneTest.testPrimaryAndReplicaAdvertiseDifferentZones`
- [ ] `QwpEgressServerInfoZoneTest.testNoZoneConfiguredOmitsCapZone`
- [ ] `QwpEgressServerInfoZoneTest.testBlankZoneConfigOmitsCapZone`
- [ ] `QwpEgressServerInfoZoneTest.testZoneRoundTripsUtf8`

### Ingress connection behavior

API gap: the Rust client has **no public connection-listener API**
(`ConnectionListener` equivalent). 3 of 5 scenarios are portable as
observable behavior; 2 are listener-API-specific.

- [ ] `QwpIngressConnectionListenerTest.testInitialConnectAllEndpointsUnreachableRetriesForever`
      (portable: behavioral)
- [ ] `QwpIngressConnectionListenerTest.testInitialConnectFailsOverPastBogusEndpoint`
      (portable: behavioral)
- [ ] `QwpIngressConnectionListenerTest.testMidStreamServerDownRetriesForever`
      (portable: behavioral)
- [ ] `QwpIngressConnectionListenerTest.testInitialConnectAuthFailedFiresEvent`
      — **blocked on client API** (connection-event surface) or adapt to
      error-return assertion.
- [ ] `QwpIngressConnectionListenerTest.testConnectionListenerInboxCapacityHonouredEndToEnd`
      — **blocked on client API**; skip unless an event API is added.

## Bindings matrix (C / C++ duplicates)

Per the existing pattern (Rust = full suite; C/C++ = key durable-ack
scenarios via cmake-built sidecars), duplicate at minimum:

- [ ] `test_kill9_mid_txn_uncommitted_rows_never_appear` → C
- [ ] `test_kill9_mid_txn_uncommitted_rows_never_appear` → C++
- [ ] `test_durable_ack_sender_survives_replica_only_window` → C
- [ ] `test_durable_ack_sender_survives_replica_only_window` → C++
- [ ] `test_graceful_demotion_mid_stream_sender_survives` → C
- [ ] `test_graceful_demotion_mid_stream_sender_survives` → C++
- [ ] egress happy-path read with `target=replica` → C
- [ ] egress happy-path read with `target=replica` → C++

(Extend if review flags more binding-sensitive paths.)

## Explicitly excluded (this pass)

- **QWP-UDP**: `QwpUdpRoleSwitchFreezeTest` (3 tests) — no UDP transport
  in this client.
- **ACL / OIDC / TLS-auth** (~53 tests, deferred): `QwpWebSocketAclTest`,
  `QwpWebSocketDynamicAuthenticationTest`, `QwpWebSocketTlsAclTest`,
  `QwpWebSocketOidcTest`, `QwpWebSocketTlsOidcTest`, `QwpEgressAuthTest`,
  `QwpEgressOidcAuthTest`, `QwpEgressTlsTest`, `SqlRoleSwitchAclTest`.
- **ILP-path java-client Ent tests** (`LineHttpAclTest`,
  `SenderTokenAuthTest`, `LineTlsTest`, …) — out of scope (QWP only).

## Totals

- Group 1: **15** scenarios
- Group 2: **8** scenarios
- Group 3: **25** scenarios (5 overlap-dedupable → ~20 net-new)
- Bindings: **8** C/C++ duplicates
- Blocked on client API: 2 (connection-listener); verify-first: multi-flush
  txn semantics, egress DDL/exec.

## Harness prerequisites (do these first)

1. `qwp_sidecar.rs`: add `FLUSH_DEFER` / transactional-commit verbs
   (parity with Enterprise `QwpSidecarMain`).
2. `qwp_egress_sidecar.rs`: add zone/role probe verbs (`SHOW_ZONE`
   equivalent) used by `test_zone_failover` / `test_target_filter`.
3. C/C++ sidecars: extend with txn + demote-survival verbs for the
   bindings matrix.
4. Verify Rust sender multi-flush transaction semantics match Java
   (`transaction=on` spanning deferred flushes, commit on final flush).
