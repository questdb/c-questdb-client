"""
In-place graceful demotion UNDERNEATH an actively-sending QWP sender,
driven by the c-questdb-client Rust sender.

Port of the Enterprise harness's ``test_demotion_mid_stream.py`` (java
client). This scenario also covers the Enterprise JUnit witness
``DurableAckThroughDemoteTest.testQwpDurableAckSenderSurvivesInPlaceDemote``
(same client contract, forked servers instead of in-process nodes).

Coverage gap this closes (mid-stream role change):
  - test_failover_graceful.py quiesces QWP ingest (flush + durable-ack await)
    BEFORE the demote and reconnects a FRESH sender to the promoted node --
    the QWP sender never experiences the demotion.
  - test_durable_ack_failover.py kill-9s the primary -- an abnormal transport
    drop, never the graceful role-change path.
  - test_switch.py / test_switch_fuzz.py quiesce or checkpoint ingest around
    the switch, so no data frame lands on a just-demoted node.
  None of them lands an ingest frame on a connection whose peer has just
  demoted -- the exact path where the server must reply with a
  reconnect-eligible role-change close (NORMAL_CLOSURE), NOT a
  SECURITY_ERROR NACK.

Server wire contract under test (QwpIngressProcessorState):
  A data frame arriving after the in-place PRIMARY->REPLICA demote hits the
  read-only gate (or the commit path's authorization-refusal containment);
  both flag ``roleChangeClosePending`` and the processor closes the WebSocket
  with NORMAL_CLOSURE after flushing any pending ACK -- the client must never
  see a client-visible error status for a role change.

Client contract under test (NACK policy, c-questdb-client Rust binding):
  - A server error NACK on the data channel bumps ``total_server_errors``
    (TransportResponse::Reject in qwp_ws_driver.rs) -- the ``server_errors
    == 0`` pin below catches a server that regresses to NACKing the
    read-only refusal instead of sending the role-change close.
  - An orderly close never counts against the sender; it reconnects, walks
    A (role-reject on the fresh upgrade) and B (still a replica), and
    retries indefinitely (Invariant B) until B is promoted.
  - After promotion the sender replays from ackedFsn+1: every row --
    pre-demote, in-flight at the demote, produced during the all-replica
    window -- lands exactly once on B (dense-sequence oracle: no loss AND
    no duplicates).

Topology:
  A (primary) + B (replica), shared object store (real replication). Sender
  lists BOTH endpoints.
  1. Ingest into A, durably acked; B converges (settled baseline).
  2. Submit A's demote WITHOUT waiting and keep ingesting straight through
     the transition -- frames are in flight while the role flips.
  3. Await A settled as REPLICA, then keep ingesting: the drainer's live,
     surviving connection to A now carries a data frame into the read-only
     gate -- the deterministic mid-stream role-change close.
  4. Coverage barrier: require a COMPLETED all-replica reconnect round.
  5. Wire-contract pin: ``server_errors == 0`` -- the demote surfaced as a
     role-change close, never as a NACK.
  6. Promote B underneath the still-producing sender; ingest tail rows; one
     final durable-ack await; dense-sequence on B for the full range.

Scope note:
  A's post-demote convergence on B's rows (onward replication) is already
  pinned by test_failover_graceful.py and is NOT re-asserted here -- a
  replication regression should fail that test, keeping this test's failure
  surface focused on the mid-stream client/server role-change contract.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

import pytest

from lib import lifecycle as lc
from lib.pg_query import count_rows, wait_for_dense_sequence
from lib.sidecar import Sidecar, SidecarError

from c_client_sidecar import CClientRustSidecar

LOG = logging.getLogger(__name__)

_TABLE = "demotion_mid_stream_c_client_rust"

# Rows ingested into A (durably acked) before the demote.
_INITIAL_ROWS = 30
# Rows ingested across the demote transition and the all-replica window.
# Split in half around the role-flip await so at least one data frame is
# guaranteed to land on A's surviving connection AFTER the flip.
_WINDOW_ROWS = 40
# Rows ingested after B's promotion, still unaware anything happened.
_POST_ROWS = 20

# Ingest is issued in small batches with a brief pause so the producer is
# genuinely "in flight" across the demote/promote events (not one atomic
# burst that could settle before the switch).
_INGEST_BATCH = 10
_INGEST_BATCH_INTERVAL_S = 0.2

_DURABLE_ACK_AWAIT_TIMEOUT_MS = 60_000
_AWAIT_ROLE_TIMEOUT_S = 60.0
_POLL_INTERVAL_S = 0.25


def _wait_count(*, port: int, table: str, expected: int, timeout_s: float) -> None:
    """Block until a plain COUNT(*) on ``port`` reaches ``expected`` rows."""
    deadline = time.monotonic() + timeout_s
    last = -1
    while time.monotonic() < deadline:
        last = count_rows(port=port, table=table)
        if last >= expected:
            return
        time.sleep(_POLL_INTERVAL_S)
    raise AssertionError(
        f"row count on :{port} reached {last}, expected >= {expected} within {timeout_s}s"
    )


def _ingest_unaware(sidecar: Sidecar, *, count: int, start_index: int) -> int:
    """Produce ``count`` rows into store-and-forward exactly as a real SF
    producer does: COMPLETELY UNAWARE of the role switch. It never inspects
    role, never waits for a "healthy" sender, never probes reconnect state --
    it just appends (SEND) and publishes to on-disk SF (FLUSH), both local
    operations that return whether or not any primary is reachable.

    The ONLY terminal condition is SF exhaustion. If SEND/FLUSH ever
    hard-fails across the demote, that IS the regression this test guards
    (e.g. the demoted node NACKing SECURITY_ERROR -> client-terminal instead
    of sending the role-change close): translate it into a descriptive,
    inline red-first assertion instead of letting a raw SidecarError bubble
    up."""
    try:
        sidecar.send(_TABLE, count=count, start_index=start_index)
        return sidecar.flush()  # publishes into SF; returns the published fsn
    except SidecarError as e:
        raise AssertionError(
            f"store-and-forward producer hard-failed while ingesting rows "
            f"[{start_index}..{start_index + count}) across an in-place demote -- "
            f"a graceful role change must surface to the sender as a "
            f"reconnect-eligible close (retry from SF), never as a terminal; "
            f"only SF exhaustion may be terminal. sidecar error: {e!r}"
        )


def _ingest_range_unaware(sidecar: Sidecar, *, start_index: int, total: int) -> int:
    """Drive ``total`` rows through :func:`_ingest_unaware` in small batches,
    returning the highest published fsn. Batching + a brief pause keeps the
    producer genuinely mid-stream across the demote/promote events."""
    end = start_index + total
    idx = start_index
    last_fsn = -1
    while idx < end:
        n = min(_INGEST_BATCH, end - idx)
        last_fsn = _ingest_unaware(sidecar, count=n, start_index=idx)
        idx += n
        time.sleep(_INGEST_BATCH_INTERVAL_S)
    return last_fsn


def _await_all_replica_round(sidecar: Sidecar, baseline, *, timeout_s: float) -> None:
    """Harness-side coverage guard (never touches the producer): block until
    the sender has COMPLETED at least one full reconnect round against the
    all-replica topology, so the role-reject walk -- the exact surface the
    role-change close hands the client over to -- is provably exercised
    before we promote.

    reconnAttempts increments at the TOP of each reconnect round (the Rust
    runner's ``record_reconnect_attempt``), BEFORE the endpoint walk reaches
    B, so a single increment only proves a round STARTED -- promoting on +1
    is a promote-too-early race. Requiring +2 proves the first round's walk
    completed (it threw, looped back, and incremented again), i.e. both A
    and B were actually reached and role-rejected. STATS reads counters
    directly, never a flush."""
    target = baseline.reconn_attempts + 2
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if sidecar.stats().reconn_attempts >= target:
            return
        time.sleep(0.1)
    raise AssertionError(
        "sender did not complete a full all-replica reconnect round after the "
        f"in-place demote (needed reconnAttempts >= {target}); the mid-stream "
        "role-change close either never happened (frame not in flight?) or the "
        "client did not treat it as reconnect-eligible"
    )


def _await_role_change_close_evidence(log_dir: Path, *, node: str,
                                      timeout_s: float) -> None:
    """Coverage witness: prove the demoted node's read-only gate actually
    fired on a mid-stream QWP frame -- the precondition for the role-change
    close this test exists to exercise. Without this check a green run could
    silently be riding some other close (e.g. a listener bounce) and the
    role-change path would be dead coverage.

    The witness is the write-refusal message a read-only node emits --
    ``CairoException.READ_ONLY_ACCESS_MESSAGE`` ("replica access is
    read-only"), documented in-source as the single source of truth for
    this refusal. The forked server logs it when the ingress rejects the
    in-flight frame. Log drain is asynchronous; poll briefly."""
    needles = ("replica access is read-only",)
    files = (log_dir / f"{node}.stdout.log", log_dir / f"{node}.stderr.log")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for f in files:
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
            except FileNotFoundError:
                continue
            if any(n in text for n in needles):
                LOG.info("role-change close witnessed in %s", f.name)
                return
        time.sleep(_POLL_INTERVAL_S)
    raise AssertionError(
        f"no mid-stream read-only refusal found in {node}'s logs within "
        f"{timeout_s}s -- the ingest frames never hit the demoted node's "
        f"read-only gate, so the role-change close path this test exists to "
        f"cover was not exercised (did the switch bounce the listener, or did "
        f"ingest quiesce before the flip?)"
    )


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_graceful_demotion_mid_stream_sender_survives_c_client_rust(
    server_factory, c_client_rust_sidecar: CClientRustSidecar,
    scenario_dir, log_dir: Path
) -> None:
    sidecar = c_client_rust_sidecar
    sf_dir = scenario_dir / "sf"
    sf_dir.mkdir(parents=True, exist_ok=True)

    # ---- Boot A (primary) + B (replica), shared object store, both min-http. ----
    a = server_factory("a", role="primary")
    b = server_factory("b", role="replica")
    a_ports = a.start(min_http=True)
    b_ports = b.start(min_http=True)
    assert a_ports.min_http is not None, (
        "node a (primary): min_http port not reported; needed to demote A"
    )
    assert b_ports.min_http is not None, (
        "node b (replica): min_http port not reported; needed to promote B"
    )
    LOG.info("a_ports=%s b_ports=%s", a_ports, b_ports)

    # ---- Durable-ack HA sender listing BOTH endpoints. A is primary -> binds A. ----
    connect_str = (
        f"ws::addr=127.0.0.1:{a_ports.http},127.0.0.1:{b_ports.http}"
        ";username=admin;password=quest"
        f";sf_dir={sf_dir}"
        ";request_durable_ack=on"
        # reconnect_max_duration_millis bounds only a blocking (sync) initial
        # connect; the mid-stream reconnect loop that rides out the demote ->
        # all-replica window -> promote sequence never gives up on it
        # (Invariant B: no wall-clock give-up).
        ";reconnect_max_duration_millis=300000"
        ";reconnect_initial_backoff_millis=100"
        ";reconnect_max_backoff_millis=1000"
        ";close_flush_timeout_millis=5000;"
    )
    sidecar.connect(connect_str)

    # ---- Settled baseline: initial rows durably acked on A, B converged. ----
    # The durable ack proves the wire is warm and bound to A; convergence
    # proves replication is live before we disturb anything.
    initial_fsn = _ingest_range_unaware(sidecar, start_index=0, total=_INITIAL_ROWS)
    assert sidecar.await_acked(initial_fsn, _DURABLE_ACK_AWAIT_TIMEOUT_MS), (
        f"initial batch was not durably acked by A [publishedFsn={initial_fsn}]"
    )
    wait_for_dense_sequence(port=a_ports.pg, table=_TABLE,
                            expected_count=_INITIAL_ROWS, timeout_s=60.0)
    _wait_count(port=b_ports.pg, table=_TABLE, expected=_INITIAL_ROWS, timeout_s=120.0)
    LOG.info("A durably holds %d rows; B converged via replication", _INITIAL_ROWS)

    baseline = sidecar.stats()
    assert baseline.server_errors == 0, (
        f"pre-demote baseline already carries server errors "
        f"({baseline.server_errors}); the wire-contract pin below would be "
        f"meaningless -- fix the happy path first"
    )

    # ---- Disturbance: demote A IN PLACE, underneath the producing sender. ----
    # Deliberately wait=False: frames must be in flight WHILE the role flips.
    LOG.info("submitting A PRIMARY -> REPLICA demote underneath the producing sender")
    lc.submit_switch(a_ports.min_http, "replica", wait=False)

    # First half of the window: produced across the transition itself.
    _ingest_range_unaware(sidecar, start_index=_INITIAL_ROWS, total=_WINDOW_ROWS // 2)

    lc.await_role(a_ports.min_http, "replica", timeout_s=_AWAIT_ROLE_TIMEOUT_S)
    LOG.info("A settled as REPLICA; continuing ingest into the surviving wire")

    # Second half: A is now settled read-only. QWP connections survive an
    # in-place demote (no listener bounce), so the drainer's live wire to A
    # carries at least one of these data frames into the read-only gate --
    # the deterministic mid-stream role-change close. From there the client
    # reconnects and walks an all-replica topology (A demoted, B not yet
    # promoted) until we promote below.
    _ingest_range_unaware(sidecar,
                          start_index=_INITIAL_ROWS + _WINDOW_ROWS // 2,
                          total=_WINDOW_ROWS - _WINDOW_ROWS // 2)
    LOG.info("ingested %d rows across the demote + all-replica window", _WINDOW_ROWS)

    # ---- Coverage barrier: a full all-replica reconnect round completed. ----
    _await_all_replica_round(sidecar, baseline, timeout_s=30.0)

    # ---- Coverage witness: the demoted node's read-only gate fired on a
    #      mid-stream frame (the role-change close trigger), so the green
    #      path below is provably the one under test. ----
    _await_role_change_close_evidence(log_dir, node="a", timeout_s=15.0)

    # ---- Wire-contract pin: the demote surfaced as a role-change close,
    #      never as a client-visible NACK. A server that NACKs the read-only
    #      refusal (e.g. SECURITY_ERROR 0x08) bumps serverErrors (the Rust
    #      driver's TransportResponse::Reject counter) -- and a terminal
    #      classification would be caught even earlier, by the window FLUSH
    #      hard-failing above. ----
    stats = sidecar.stats()
    assert stats.server_errors == 0, (
        f"the in-place demote surfaced as {stats.server_errors} client-visible "
        f"NACK(s); a graceful role change must close the WebSocket with a "
        f"reconnect-eligible NORMAL_CLOSURE (roleChangeClosePending), never "
        f"send an error status the client classifies"
    )

    # ---- Promote B -> primary underneath the still-producing sender. ----
    LOG.info("promoting B REPLICA -> PRIMARY via /lifecycle/switch")
    lc.submit_switch(b_ports.min_http, "primary", wait=True,
                     wait_timeout_s=_AWAIT_ROLE_TIMEOUT_S)

    # ---- Keep ingesting after promotion, still unaware anything happened.
    #      The SAME sender is used throughout -- never a fresh CONNECT, which
    #      would mask a halted sender and defeat the test. ----
    final_fsn = _ingest_range_unaware(
        sidecar, start_index=_INITIAL_ROWS + _WINDOW_ROWS, total=_POST_ROWS
    )

    # ---- Terminal drain: one await for the FULL published sequence. Every
    #      row -- pre-demote, in flight at the demote (including the frame the
    #      role-change close rejected, which must replay), and window-produced
    #      -- must durably ack on the promoted primary. ----
    assert sidecar.await_acked(final_fsn, _DURABLE_ACK_AWAIT_TIMEOUT_MS), (
        f"rows produced across the in-place demote were lost: full published "
        f"sequence not durably acked by promoted B [publishedFsn={final_fsn}]. "
        f"The frame rejected by the role-change close must be replayed from SF "
        f"(ackedFsn+1) after reconnect."
    )

    total = _INITIAL_ROWS + _WINDOW_ROWS + _POST_ROWS
    # Dense sequence = no loss AND no duplicates: the frame in flight at the
    # demote was rejected-then-replayed and must land exactly once.
    wait_for_dense_sequence(port=b_ports.pg, table=_TABLE,
                            expected_count=total, timeout_s=120.0)
    LOG.info("recovered: sender rode the mid-stream demote; B holds [0..%d) exactly once", total)
