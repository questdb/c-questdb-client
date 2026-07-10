# Column Sender SFA Row-Path Test Inventory

This document inventories the existing row-oriented QWP/WebSocket
store-and-forward (SFA) tests and turns them into a task list for closing the
columnar sender SFA test gap.

The row path means `Sender` / `Buffer` line-protocol ingestion over
`ws::...` with `sf_dir` and `sender_id`. The columnar gap means
`questdb_db` / `column_sender`, Arrow C Data Interface ingestion, and
Python `Client.dataframe()` when the client is opened with `sf_dir`.

## Current Columnar Baseline

Columnar SFA has Rust-level mock/contract tests, but it does not yet match the
row path's live system and fuzz coverage.

- [x] Reject SFA keys without `sf_dir`:
  `questdb-rs/src/tests/column_sender_pool.rs::refuses_store_and_forward_keys_without_sf_dir`.
- [x] Enforce one active SFA borrower:
  `store_and_forward_pool_allows_one_active_borrower`.
- [x] Surface a drop-and-continue rejection once:
  `store_and_forward_sync_reports_drop_and_continue_once`.
- [x] Drop and reopen a poisoned SFA backend on the next borrow:
  `store_and_forward_drop_on_return_drops_backend_and_reopens_on_next_borrow`.
- [x] Roll back symbols and keep the chunk retryable on local append timeout:
  `store_and_forward_append_timeout_rolls_back_symbols_and_keeps_chunk`.
- [x] Live columnar SFA single-batch Arrow round trip with slot cleanup:
  `system_test/arrow_ingress_fuzz.py::TestArrowIngressSfa::test_sfa_single_batch_round_trip_and_cleans_slot`.
- [x] Live columnar SFA schema evolution across two Arrow batches:
  `system_test/arrow_ingress_fuzz.py::TestArrowIngressSfa::test_sfa_schema_evolution_across_batches`.
- [x] Live columnar SFA write/schema rejection with one-shot diagnostic:
  `system_test/arrow_ingress_fuzz.py::TestArrowIngressSfa::test_sfa_write_rejection_reports_once_and_continues`.
- [x] Live columnar SFA restart recovery with a new owner of the same slot:
  `system_test/arrow_ingress_fuzz.py::TestArrowIngressSfa::test_sfa_new_owner_recovers_server_accepted_unacked_batch`.
- [x] Live columnar SFA Arrow ingest fuzz variant:
  `system_test/arrow_ingress_fuzz.py::TestArrowIngressSfa::test_sfa_random_arrow_ingest`.
- [x] Parent Python `Client.dataframe()` SFA smoke and rejection tests:
  `test/system_test.py::TestClientDataframeFailover::test_sfa_dataframe_numpy_round_trip`,
  `test_sfa_dataframe_arrow_round_trip`, and
  `test_sfa_dataframe_rejection_reports_once_and_continues`.
- [x] Parent Python local dataframe fuzz variants with SFA enabled:
  `test/test_client_dataframe_fuzz.py::TestClientDataframeSfaFuzz` and
  `test/test_client_polars_fuzz.py::TestClientPolarsDataframeSfaFuzz`.
- [x] Live columnar SFA bounce-during-producer coverage:
  `system_test/arrow_ingress_fuzz.py::TestArrowIngressSfa::test_sfa_arrow_producer_survives_server_bounces`.
- [x] Repeated columnar SFA fuzz loop:
  `system_test/_arrow_sfa_fuzz_loop.py`.

Those tests are important, but they do not yet prove same-sender restart
recovery, bounce-during-producer behavior, parent Python `Client.dataframe()`
behavior, broad C ABI behavior, or randomized dataframe coverage.

## Row-Path System Tests in `py-questdb-client`

These tests exercise the Python row-sender API against a live QuestDB fixture.
They all build configs with `sender_id` and `sf_dir` via
`test/system_test.py::_mk_qwpws_conf`.

- [x] Columnar equivalent for single-batch round trip.
  Row reference: `test/system_test.py::test_qwp_websocket_single_batch_round_trip`.
  It establishes a row sender, flushes one SFA frame, waits for the FSN, drains
  on close, asserts the SFA slot is empty, and verifies rows through SQL.

- [ ] Columnar equivalent for dead-endpoint failover.
  Row reference:
  `test/system_test.py::test_qwp_websocket_dead_endpoint_failover_and_ack_progresses`.
  It puts a dead endpoint before the real endpoint, writes a frame, waits for
  ack progress, closes drained, and verifies the row.

- [ ] Columnar equivalent for schema evolution across frames.
  Row reference:
  `test/system_test.py::test_qwp_websocket_schema_evolution_across_batches`.
  It sends multiple frames with growing/sparse schemas and verifies server-side
  null backfill and final data.

- [x] Columnar equivalent for write/schema rejection with drop-and-continue.
  Row reference:
  `test/system_test.py::test_qwp_websocket_write_rejection_drops_and_sender_continues`.
  It sends valid, invalid, valid frames; waits for the final FSN; checks the
  rejection diagnostic category, policy, status, and FSN range; verifies the
  sender can continue and the SFA slot is cleaned.

- [ ] Decide and test the columnar diagnostic callback contract.
  Row reference:
  `test/system_test.py::test_qwp_websocket_error_handler_callback_fires`.
  If `Client.dataframe()` or the columnar C ABI exposes async SFA diagnostics,
  add callback coverage. If it intentionally does not, document that columnar
  users observe server errors through `sync()` / `Client.dataframe()` return.

- [ ] Columnar equivalent for seeded schema fuzz.
  Row reference: `test/system_test.py::test_qwp_websocket_schema_fuzz`.
  It randomizes tables, symbols, columns, unicode values, flush boundaries, and
  FSN ordering while using SFA. Columnar should reuse the dataframe fuzz
  builders with `sf_dir` enabled and assert the same row-level results.

## Row-Path System Tests in `c-questdb-client`

These tests exercise the C/Python wrapper around the row sender against a live
QuestDB fixture. They are broader than the parent Python suite, especially for
restart and fuzz coverage.

- [ ] Columnar equivalent for SFA smoke under C client system tests.
  Row reference: `system_test/test.py::TestQwpWsSender`.
  It covers QWP/WS sender construction, auth rejection, TLS smoke variants, SFA
  file cleanup, and live row verification.

- [ ] Columnar equivalent for protocol failover and schema evolution.
  Row references:
  `TestQwpWsProtocol::test_initial_connect_skips_dead_endpoint_and_ack_progresses`,
  `TestQwpWsProtocol::test_schema_evolution_across_batches`.
  These should map to `questdb_db_connect` plus borrowed columnar connections,
  with Arrow/chunk batches replacing row frames.

- [x] Columnar equivalent for server rejection policy.
  Row reference:
  `TestQwpWsProtocol::test_write_rejection_drops_and_sender_continues`.
  Columnar should prove a rejected SFA payload is reported once, later valid
  payloads land, and cleaned SFA files do not remain after drain.

- [ ] Columnar equivalent for same-sender restart recovery.
  Row reference:
  `TestQwpWsRestart::test_same_sender_survives_server_restart`.
  It stops and restarts QuestDB while the same sender remains alive, then proves
  rows before and after the restart land.

- [ ] Columnar equivalent for retry-forever reconnect past the budget.
  Row reference: `TestQwpWsRestart::test_reconnect_retries_forever_past_cap`.
  Columnar should prove a transport outage never terminalizes: publishes keep
  succeeding past several reconnect budgets, and every accepted row drains once
  an endpoint reappears (only auth/protocol errors are terminal).

- [x] Columnar equivalent for new-sender recovery from an existing `sf_dir`.
  Row reference: `TestQwpWsRestart::test_new_sender_recovers_from_sf_dir`.
  It creates an accepted-but-unacked frame, restarts QuestDB, opens a new sender
  with the same `sender_id` and `sf_dir`, and verifies recovery.

- [ ] Columnar equivalent for continuous producer while QuestDB bounces.
  Row reference:
  `TestQwpWsRestart::test_sender_pushes_continuously_while_server_bounces`.
  Columnar should keep producing dataframe/Arrow batches while QuestDB restarts
  and prove every user-accepted batch lands.

- [ ] Columnar equivalent for multi-restart recovery fuzz.
  Row reference: `TestQwpWsRestart::test_fuzz_multiple_restarts_new_sender`.
  It repeats accepted-unacked frame creation and recovery across several epochs.

- [ ] Columnar equivalent for randomized QWP/WS fuzz.
  Row reference: `TestQwpWsFuzz`.
  The row fuzz creates per-producer `sf_dir` directories, randomizes schemas and
  values, optionally runs ALTERs, and compares server rows with the client-side
  oracle.

- [ ] Columnar equivalent for bounce-during-fuzz variants.
  Row references:
  `TestQwpWsFuzz::test_load_with_bounce`,
  `TestQwpWsFuzz::test_all_mixed_with_bounce`,
  `TestQwpWsFuzz::test_n_bounce_sweep`.
  These are the strongest row-path SFA tests: QuestDB is stopped and restarted
  while producers are mid-batch, and SFA must preserve queued frames across the
  bounce.

- [ ] Add a repeat runner for columnar SFA fuzz.
  Row reference: `system_test/_fuzz_loop.py`.
  The row runner executes `TestQwpWsFuzz` repeatedly with fresh random seeds
  against one live QuestDB fixture. Add a similar loop once columnar fuzz exists.

## Rust Row-Path SFA Tests

These are mostly mock-server and local SFA-engine tests. Columnar should share
the SFA engine behavior by construction, but API-specific wiring still needs
targeted columnar coverage where payload encoding, chunk clearing, `sync()`,
pool lifecycle, and C/Python surfaces differ.

- [ ] Verify columnar max-buffer behavior against replay-safe payload size.
  Row references:
  `qwp_ws_max_buf_size_allows_frame_when_encoded_replay_len_fits_in_all_progress_modes`,
  `qwp_ws_max_buf_size_rejects_oversized_replay_frame_in_all_progress_modes`.

- [ ] Verify columnar ack and durable-ack boundaries.
  Row references:
  `qwp_ws_publish_ack_completes_in_all_progress_modes`,
  `qwp_ws_durable_ack_requires_upgrade_echo`,
  `qwp_ws_durable_ack_completion_waits_for_durable_confirmation_in_all_progress_modes`,
  `qwp_ws_sender_fsn_watermarks_and_close_drain_work_in_all_progress_modes`.

- [ ] Verify columnar drop-and-continue and halt semantics.
  Row references:
  `qwp_ws_drop_reject_reports_error_and_continues_in_all_progress_modes`,
  `qwp_ws_schema_rejection_drops_and_sender_continues`,
  `qwp_ws_halt_reject_terminalizes_in_all_progress_modes`,
  `qwp_ws_terminal_close_is_pollable_as_protocol_violation`.

- [ ] Verify columnar local backpressure and append-deadline behavior.
  Row reference: `qwp_ws_backpressure_timeout_matches_in_all_progress_modes`.
  Columnar has one targeted timeout test today; add API-level variants for Arrow
  and Python dataframe paths.

- [ ] Verify columnar SFA config compatibility and constraints.
  Row references:
  `qwp_ws_store_and_forward_config_opens_java_slot_layout`,
  `qwp_ws_store_and_forward_rejects_one_segment_total_capacity`.

- [ ] Verify columnar orphan-drain behavior if columnar exposes orphan draining.
  Row references:
  `qwp_ws_manual_orphan_drainer_replays_sibling_slot`,
  `qwp_ws_manual_orphan_drainer_walks_endpoint_list`,
  `qwp_ws_manual_orphan_drainer_role_reject_tries_next_endpoint`,
  `qwp_ws_background_orphan_close_is_bounded_and_leaves_orphan_recoverable`.

- [ ] Verify columnar replay-safe symbol/schema encoding.
  Row references:
  `qwp_ws_subsequent_message_reemits_replay_dictionary_and_full_schema`,
  `qwp_ws_replay_full_schema_used_when_columns_match`,
  `qwp_ws_full_schema_re_emitted_when_columns_change`,
  `qwp_ws_replay_payloads_match_java_golden_bytes`.
  Columnar has a different encoder, so this is not covered merely by reusing
  the SFA queue.

- [ ] Verify columnar reconnect behavior across endpoint and handshake failures.
  Row references:
  `qwp_ws_reconnects_and_replays_in_all_progress_modes`,
  `qwp_ws_midstream_failure_reconnects_to_next_endpoint`,
  `qwp_ws_sync_reconnect_retries_failed_attempt`,
  `qwp_ws_sync_initial_connect_retry_survives_dropped_upgrade`,
  `qwp_ws_initial_connect_walks_endpoint_list_in_off_mode`,
  `qwp_ws_initial_connect_role_reject_tries_next_endpoint`,
  `qwp_ws_initial_connect_retryable_status_tries_next_endpoint`,
  `qwp_ws_initial_connect_unsupported_version_tries_next_endpoint`,
  `qwp_ws_sync_initial_retry_budget_exhaustion_reports_context`.

- [ ] Verify columnar high-level flush contract.
  Row references:
  `qwp_ws_high_level_flush_returns_before_ack`,
  `qwp_ws_high_level_flush_and_keep_returns_before_ack_and_preserves_buffer`,
  `qwp_ws_high_level_flushes_pipeline_before_ack`.
  Columnar has a different public contract: low-level `flush()` locally queues
  in SFA mode, while Python `Client.dataframe()` waits for `AckLevel::Ok`.
  Tests should pin both contracts.

## SFA Queue and Segment Engine Coverage

These row-path internals are shared infrastructure. They usually do not need
columnar duplicates unless the columnar API makes a different promise.

- Java-compatible segment layout:
  `qwp_ws_sfa_segment.rs::scans_java_segment_header_and_frames_from_golden_bytes`,
  `create_memory_and_append_uses_same_segment_layout`,
  `segment_file_names_match_java_slot_convention`,
  `java_and_rust_read_each_others_segments`.
- Torn-tail and corruption recovery:
  `scan_stops_at_crc_mismatch_and_reports_torn_tail`,
  `scan_treats_length_and_payload_without_crc_commit_as_torn`,
  `recovery_quarantines_empty_torn_initial_segment_and_continues`,
  `recovery_quarantines_empty_torn_spare_without_dropping_valid_frames`,
  `recovery_records_non_empty_torn_tail_diagnostic`.
- Replay-only and orphan recovery:
  `replay_only_replays_and_cleans_recovered_frames_without_spares`,
  `replay_only_skips_bad_side_file_without_dropping_contiguous_frames`,
  `replay_only_skipped_middle_file_preserves_gap_failure`,
  `manual_driver_sends_recovered_sfa_frames`.
- Ack watermark safety:
  `ack_watermark_skips_completed_frames_after_restart`,
  `ack_watermark_bounds_are_safe`,
  `future_ack_watermark_is_invalidated_before_new_publish`,
  `ack_watermark_unavailable_is_ignored_for_recovery`,
  `ack_watermark_invalid_contents_are_ignored_and_repaired`,
  `ack_watermark_applies_to_replay_only_orphan_open`.
- Capacity, rotation, cleanup:
  `rotation_uses_prepared_hot_spare_and_respects_segment_cap`,
  `detached_producer_rotates_replays_and_trims_runner_owned_segments`,
  `recovered_segments_above_cap_start_but_block_new_segments`,
  `cumulative_ack_trims_fully_acked_sealed_segments_but_keeps_active`,
  `driver_close_drain_removes_sfa_files_after_delivery`,
  `driver_close_timeout_retains_recoverable_sfa_files`.

## Recommended Columnar Test Closure Order

1. [x] Add one live C-system-test helper that opens `questdb_db` with
   `sender_id` and `sf_dir`, borrows a columnar connection, and verifies SFA
   file cleanup after `column_sender_sync(Ok)`.
2. [x] Add live single-batch Arrow/chunk round trip.
3. [x] Add live schema evolution across two or more columnar batches.
4. [x] Add live schema/write rejection and one-shot diagnostic surfacing.
5. [x] Add accepted-unacked restart recovery with the same SFA slot and a new owner.
6. [x] Run the existing Arrow ingest fuzz with `sender_conf_extras` containing
   `sender_id` and `sf_dir`.
7. [x] Add parent Python `Client.dataframe()` SFA smoke and rejection tests.
8. [x] Add pandas and polars dataframe fuzz variants with `sf_dir`.
9. [x] Add bounce-during-fuzz for columnar batches once the smoke/restart cases
   are stable.
10. [x] Add a repeated fuzz loop equivalent to `system_test/_fuzz_loop.py`.
