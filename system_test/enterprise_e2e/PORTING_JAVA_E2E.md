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

- [x] `test_switch_fuzz` — seed-isolated switch-roundtrip fuzz with
      chain/survival/read-prober/exact-count-with-quiescence oracles.
      Ported as `test_switch_fuzz_c_client_rust`. Rust adaptations: the
      ingest loop publishes single-row frames via SEND+FLUSH (Java's SEND
      publishes per call); the pre-demote ack-observe and post-chain drain
      barrier await the loop's last *published* FSN (Rust empty-buffer
      flush returns −1, Java re-flushes to learn the highest FSN); the
      reconnect-**attempts** bound is a per-leg budget (chain_len×20+slack)
      because the Rust role-reject retry cadence is flat-initial-backoff by
      design (`qwp_ws.rs` reconnect_sleep_duration role_reject branch) —
      the reconn-**succ** bound stays chain_len+slack, same shape as Java.
- [x] `test_switch_fuzz_pitr` — live QWP client ingesting across
      PITR-recovered boot + first switch. Ported as
      `test_switch_fuzz_pitr_c_client_rust` (#092 guard; fresh sf_dir +
      sender_id for the recovered-primary connection).
- [x] `test_switch_fuzz_pinned_seed_5171257088512701991` — ported as a
      **pinned flip-chain**: the Enterprise harness's only seeded draws are
      `baseline_rows=randint(10,50)` then `chain_len=randint(1,6)`, and the
      seed decodes (Python MT19937) to baseline_rows=22, chain_len=6 —
      pinned explicitly in
      `test_switch_fuzz_pinned_chain_5171257088512701991_c_client_rust`,
      zero RNG dependency.
- [x] `test_switch_fuzz_live_replica_failover` — bounded live-replica
      failover fuzz dimension. Ported as
      `test_switch_fuzz_live_replica_failover_c_client_rust`
      (onward-convergence oracle + clean-shutdown asserts intact).

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

- [x] `SqlFailoverQwpClientLosslessTest.testObliviousQwpClientLosslessAcrossSqlFailover`
      — sender configured with BOTH endpoints, oblivious to a
      SQL-triggered primary move; lossless. Ported:
      `test_sql_failover_lossless.py::test_oblivious_sender_lossless_across_sql_failover_c_client_rust`
      (pg-wire `SWITCH ROLE` vehicle preserved; ownership-token parity
      wait substituted by the documented promote-with-retry recovery).
- [x] `SqlFailoverQwpClientLosslessTest.testObliviousDurableAckQwpClientLosslessNoCatchupWait`
      — durable-ack variant, no catch-up wait. Ported:
      `test_sql_failover_lossless.py::test_oblivious_durable_ack_sender_lossless_no_catchup_wait_c_client_rust`.
- [x] `SqlFailoverQwpDeferredCloseExactlyOnceTest.testDeferredCloseExactlyOnceWithUploadsHeldUntilDemoteDrain`
      — deterministic witness for role-change close deferral
      (`roleChangeCloseWithUploadGrace`): exactly-once delivery with
      uploads held until demote drain. Ported:
      `test_sql_failover_lossless.py::test_deferred_close_exactly_once_uploads_held_until_demote_drain_c_client_rust`
      (DurableAckRegistry watermark tripwires substituted by
      replication-visible equivalents: B holds 0 rows pre-demote, B
      converges on the committed corpus post-demote pre-promote;
      QuestDB facade readback substituted by ingress + egress sidecars
      on the same endpoints).
- [x] `DurableAckThroughDemoteTest.testDurableAckClientThroughDemoteIsReleasedOrTerminalWithinBound`
      — durable-ack client carried through P→R demote is released or
      terminal within a bound (never hangs). Ported:
      `test_durable_ack_demote_bound.py::test_durable_ack_through_demote_released_or_terminal_within_bound_c_client_rust`
      (pending-ack premise made deterministic via the upload-holding
      throttle window + an explicit pre-demote AWAIT_ACKED-times-out
      tripwire).
- [x] `DurableAckThroughDemoteTest.testQwpDurableAckSenderSurvivesInPlaceDemote`
      — overlaps Group 1 `test_demotion_mid_stream`; covered by
      `test_graceful_demotion_mid_stream_sender_survives_c_client_rust`.
- [x] `QwpRoleBounceChaosLosslessTest.testObliviousDurableAckSenderAndHistoricalReadersSurviveRoleBouncing`
      — chaos role bouncing (P→R, R→P, repeatedly, randomized timing);
      oblivious durable-ack sender + concurrent historical readers, lossless.
      Ported:
      `test_role_bounce_chaos.py::test_oblivious_durable_ack_sender_and_readers_survive_role_bouncing_c_client_rust`
      (knobs: `QDB_E2E_BOUNCE_ROUNDS` default 3, `QDB_E2E_FUZZ_SEED`
      logged for replay; the JUnit row-by-row scan verification is
      pinned through row-count predicates — full-scan count, exact
      count+sum, distinct/min/max density, zero-row ts-mismatch probe —
      since the egress sidecar QUERY verb returns row counts; batch
      arrival ORDER is the one property left pinned Java-side).

### Egress lifecycle

- [x] `QwpEgressDropDemoteRaceTest.testQwpEgressDropTableDuringDemoteReplicatesOrRefuses`
      — ported as `test_egress_drop_demote_race.py` (Rust). Egress DDL
      verified supported: `Reader::execute` handles the `EXEC_DONE`
      terminal (`reader.rs` `Terminal::ExecDone`), same wire path as
      Java `QwpQueryClient.execute`. Adaptation: the JUnit in-JVM
      determinism hooks (mint-site observer + switch-step injector)
      don't exist for forked servers, so the port overlaps the SQL
      demote with the egress DROP wall-clock and pins the same terminal
      replicate-or-refuse invariant (A/B agreement, refusal-message
      classification, `failover=off` single-endpoint semantics).

### Egress server-info / role / zone

Dedup note: the `target=` scenarios overlap Group 2 `test_target_filter`;
tick them off jointly where one pytest scenario covers both. Ported
suites live in `test_egress_server_info.py`; sidecar surface extended
(`qwp_egress_sidecar.rs`): `SERVER_INFO` now reports `cap_zone=<0|1>`
(decoded `capabilities & CAP_ZONE`), `QUERY` reports
`resets=/pre_reset_rows=/last_replay_rows=` from
`Cursor::failover_resets`, and a new `QUERY_ROW` verb renders the first
result row for fingerprint probes — all backward-compatible with the
shared `lib/egress_sidecar.py` parser (extra tokens ignored). The QUERY
verb now installs a no-op `on_failover_reset` handler: the Rust cursor
refuses silent mid-query replays unless the caller opts in (by design),
matching the Java handler's inherent replay-awareness.

- [x] `QwpEgressServerInfoRoleTest.testPrimaryReportsPrimaryRole`
      — `test_primary_reports_primary_role_c_client_rust`
- [x] `QwpEgressServerInfoRoleTest.testReplicaReportsReplicaRole`
      — `test_replica_reports_replica_role_c_client_rust`
- [x] `QwpEgressServerInfoRoleTest.testMultiEndpointTargetPrimaryPicksPrimary`
      — `test_multi_endpoint_target_primary_picks_primary_c_client_rust`
      (replica-listed-first ordering was NOT covered by Group 2, so
      ported rather than pointer-ticked)
- [x] `QwpEgressServerInfoRoleTest.testMultiEndpointTargetReplicaPicksReplica`
      — dedup-pointer: covered 1:1 by Group 2
      `test_target_filter.py::test_target_replica_skips_primary_at_startup_c_client_rust`
- [x] `QwpEgressServerInfoRoleTest.testTargetPrimaryAgainstReplicaOnlyRaisesMismatch`
      — `test_target_primary_against_replica_only_raises_mismatch_c_client_rust`
      (mirror direction of the Group 2 mismatch test; both kept — the
      two filters classify STANDALONE differently)
- [x] `QwpEgressServerInfoRoleTest.testReadFromReplicaReturnsSameDataAsPrimary`
      — `test_read_from_replica_returns_same_data_as_primary_c_client_rust`
      (adaptation: aggregate fingerprint via `QUERY_ROW` instead of
      in-process row-by-row compare; deterministic labels)
- [x] `QwpEgressServerInfoRoleTest.testFailoverToReplicaReplaysAfterMidStreamDisconnect`
      — `test_failover_to_replica_replays_after_mid_stream_disconnect_c_client_rust`
      (adaptation: no `DEBUG_FORCE_TRANSPORT_FAILURE_AFTER_BATCHES` hook
      for forked servers → 10M-row progressive cross-join + mid-stream
      `kill -9`; oracle mapped 1:1 to `resets>=1` /
      `pre_reset_rows>=1` / `last_replay_rows==N`)
- [x] `QwpEgressServerInfoZoneTest.testPrimaryAdvertisesConfiguredZone`
      — `test_primary_advertises_configured_zone_c_client_rust`
- [x] `QwpEgressServerInfoZoneTest.testReplicaAdvertisesConfiguredZone`
      — `test_replica_advertises_configured_zone_c_client_rust`
- [x] `QwpEgressServerInfoZoneTest.testPrimaryAndReplicaAdvertiseDifferentZones`
      — `test_primary_and_replica_advertise_different_zones_c_client_rust`
- [x] `QwpEgressServerInfoZoneTest.testNoZoneConfiguredOmitsCapZone`
      — `test_no_zone_configured_omits_cap_zone_c_client_rust`
- [x] `QwpEgressServerInfoZoneTest.testBlankZoneConfigOmitsCapZone`
      — `test_blank_zone_config_omits_cap_zone_c_client_rust`
- [x] `QwpEgressServerInfoZoneTest.testZoneRoundTripsUtf8`
      — `test_zone_round_trips_utf8_c_client_rust`

### Ingress connection behavior

API gap: the Rust client has **no public connection-listener API** — no
equivalent of `io.questdb.client.SenderConnectionListener` /
`SenderConnectionEvent` anywhere under `questdb-rs/src` (no event kinds,
no dispatcher, no per-event host/port/cause introspection). Ported
scenarios re-express each event assertion as an observable behavior;
the substitution map is documented in
`tests/test_connection_behavior.py`'s module docstring.

Secondary observability gap (noted, not blocking): the async
initial-connect loop keeps a LOCAL attempt counter
(`connect_with_retry`, `qwp_ws.rs:688-757`) and never bumps the
`qwp_ws_totals` `reconnect_attempts` counter (recorder sites are only the
mid-stream loop `qwp_ws.rs:1206` and manual-progress
`qwp_ws_driver.rs:1361`), so STATS cannot witness initial-connect sweeps;
the all-unreachable port proves loop liveness via eventual connect + full
backlog drain instead.

- [x] `QwpIngressConnectionListenerTest.testInitialConnectAllEndpointsUnreachableRetriesForever`
      — `test_initial_connect_all_endpoints_unreachable_retries_forever_c_client_rust`
      (async initial connect, 8 budgets all-unreachable, every FLUSH
      succeeds, then successor on a listed port drains the full backlog;
      budget-rollover semantics pinned at
      `SyncQwpWsPendingRunnerCore::drive_step`, `qwp_ws.rs:774-798`)
- [x] `QwpIngressConnectionListenerTest.testInitialConnectFailsOverPastBogusEndpoint`
      — `test_initial_connect_fails_over_past_bogus_endpoint_c_client_rust`
- [x] `QwpIngressConnectionListenerTest.testMidStreamServerDownRetriesForever`
      — `test_mid_stream_server_down_retries_forever_c_client_rust`
      (dead-wire transport-error path: server never returns; STATS
      reconnAttempts strictly grows, reconnSucc + acked watermark flat,
      no terminal past 8 budgets — distinct from
      `test_durable_ack_failover.py`'s replica-only role-reject path)
- [x] `QwpIngressConnectionListenerTest.testInitialConnectAuthFailedFiresEvent`
      — behavioral core ported:
      `test_initial_connect_auth_failed_surfaces_terminal_promptly_c_client_rust`
      (401 upgrade reject → `AuthError` terminal surfaces as prompt
      CONNECT `ERR`, 0.01s observed vs a 30s budget; clean-terminal tail
      re-connects with good credentials). The **listener-event half is
      blocked on the client API gap above**: AUTH_FAILED event kind,
      event host/port fields, and `getCause()` class introspection have
      no Rust surface.
- [ ] `QwpIngressConnectionListenerTest.testConnectionListenerInboxCapacityHonouredEndToEnd`
      — **blocked on client API**, not portable even behaviorally: the
      scenario exists to pin the Java client's bounded event-dispatcher
      inbox (`connection_listener_inbox_capacity` builder knob +
      `QwpWebSocketSender.getDroppedConnectionNotifications()`); the Rust
      client has no dispatcher thread, no event inbox, and no
      dropped-notification counter to honour or regress. Revisit only if
      a connection-event API is added to questdb-rs.

## Bindings matrix (C / C++ duplicates)

Per the existing pattern (Rust = full suite; C/C++ = key durable-ack
scenarios via cmake-built sidecars). All ported duplicates live in
`tests/test_bindings_matrix.py`.

- [ ] `test_kill9_mid_txn_uncommitted_rows_never_appear` → C — **BLOCKED**
      (same client gap as the Rust original: no multi-flush
      `transaction=on`; see the Group 1 txn notes). SUBSTITUTED with the
      portable commit-boundary sibling below.
- [ ] `test_kill9_mid_txn_uncommitted_rows_never_appear` → C++ — **BLOCKED**
      (ditto; substituted below).
- [x] `test_kill9_at_commit_boundary_no_orphan` → C (substitute for the
      blocked mid-txn boxes; zero-settle SIGKILL + slot recovery)
- [x] `test_kill9_at_commit_boundary_no_orphan` → C++ (ditto)
- [x] `test_durable_ack_sender_survives_replica_only_window` → C
- [x] `test_durable_ack_sender_survives_replica_only_window` → C++
- [x] `test_graceful_demotion_mid_stream_sender_survives` → C
- [x] `test_graceful_demotion_mid_stream_sender_survives` → C++
- [x] egress happy-path read with `target=replica` → C
      (`qwp_egress_c_sidecar.c`: the always-compiled `reader_*` C API —
      verdict: the C API **does** expose the reader,
      `include/questdb/egress/reader.h`)
- [x] egress happy-path read with `target=replica` → C++
      (`qwp_egress_cpp_sidecar.cpp`: the genuine `questdb::egress`
      C++ wrapper classes in `reader.hpp`)

C-FFI observability substitutions (same precedent as
`test_orphan_drainer_bindings.py`; details in the module docstring):

- The Rust originals' `STATS reconnAttempts` +2 all-replica-round barrier
  is replaced by the server-side witness `"ingress upgrade rejected by
  role"` (QwpIngressUpgradeProcessor's 421 gate) in the replica's logs —
  the C FFI does not export the qwp_ws_totals counters.
- The demotion scenario's `server_errors == 0` wire pin is dropped in the
  C/C++ duplicates (counter zeroed by the FFI → vacuous); it stays pinned
  by the Rust variant.
- The egress C API exposes no zone accessor (`reader.h` server-info
  surface: role / epoch / capabilities / cluster_id / node_id), so the
  C/C++ egress sidecars' `SERVER_INFO` omits the `zone=` token and
  `SHOW_ZONE` / `QUERY_ROW` reply `ERR unsupported`.

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

## Totals (final state of this porting pass)

- Group 1: **15** scenarios — 12 ported, **3 blocked** on the client's
  missing multi-flush `transaction=on` mode (txn notes above).
- Group 2: **8** scenarios — all ported.
- Group 3: **25** scenarios — 22 ported, 1 covered by dedup pointer,
  **2 blocked** on the missing connection-listener/event client API.
- Bindings: **8** C/C++ duplicates ported (2 checklist boxes blocked by
  the same txn client gap, substituted with the commit-boundary sibling).
- Blocked total: 5 checklist items across 2 client feature gaps
  (multi-flush transactions; connection-listener events).

## Harness prerequisites (resolution)

1. `qwp_sidecar.rs` `FLUSH_DEFER` / transactional-commit verbs: **not
   added** — no client API to bind to (multi-flush txn unsupported);
   dead verbs were deliberately not introduced.
2. `qwp_egress_sidecar.rs` zone/role probe verbs: already present
   (`SHOW_ZONE` / `SERVER_INFO`); extended during Group 3 with
   `cap_zone=`, failover-reset counters on `QUERY`, and `QUERY_ROW`.
3. C/C++ sidecars: **no new ingress verbs needed** (CONNECT / SEND /
   FLUSH / AWAIT_ACKED / STATS / CLOSE sufficed); NEW egress sidecars
   added (`qwp_egress_c_sidecar.c`, `qwp_egress_cpp_sidecar.cpp`). The
   shared `libquestdb_client` for native sidecars always includes the
   `reader_*` symbols without a feature flag, and the build helper resolves
   the platform library name (`.dylib` on macOS, `.so` elsewhere — fixes
   local C/C++ runs on macOS).
4. Rust sender multi-flush transaction semantics: **verified ABSENT**
   (explicit QWP/WS rejection in `sender.rs`; no `transaction` conf
   key; deferred-commit encoder is dead capability) — the 3 Group 1
   txn scenarios and 2 bindings boxes stay blocked until the client
   grows the mode.
