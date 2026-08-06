"""
Durable-ack sender must survive a replica-only failover window, driven by
the c-questdb-client Rust sender.

Port of the Enterprise harness's ``test_durable_ack_failover.py`` (java
client). The server orchestration is identical; the binding under test is
the Rust ``qwp_sidecar`` instead of the Java one.

Store-and-forward invariant (the whole point of the SF client):
  The producer appends into on-disk store-and-forward; a background drainer
  ships SF -> server. The producer is COMPLETELY UNAWARE of server topology: it
  does not know or care whether a primary exists, whether a failover is in
  flight, or whether the only reachable endpoint is a replica. It never checks
  role, never waits for a "healthy" sender, never probes reconnect state -- it
  just keeps appending and publishing to SF (both local, on-disk operations that
  return regardless of reachability). A transient failover condition -- server
  rejects, role=REPLICA, ALL endpoints currently replicas, durable-ack header
  not echoed, network flap -- is NEVER terminal: the drainer keeps the rows in
  SF and retries indefinitely (capped backoff, no wall-clock give-up). The only
  terminal conditions are SF exhaustion (the on-disk buffer is full and cannot
  be extended) and a genuinely non-retriable error (auth failure, or a
  cluster-wide durable-ack capability gap where a server upgrades but cannot
  serve durable ack). A replica can be promoted; a primary will reappear.

Production incident this guards against (red-first, java client):
  An HA durable-ack sender lost its primary and, during the window before a
  replica was promoted, walked an all-replica endpoint list. Instead of
  retrying, the client synthesized a terminal durable-ack-mismatch and HALTED;
  the worker died and never recovered even after a replica was promoted. The
  Rust client has the same two surfaces and must make the same distinction:
  a role-reject carrying role info is retryable even with
  ``request_durable_ack=on`` (``reconnect_error_is_terminal`` short-circuits
  on ``qwp_ws_role_reject``), while a genuine capability mismatch WITHOUT
  role info stays terminal.

Why this is a deterministic test rather than a fuzz extension:
  test_switch_fuzz.py exercises durable-ack across an in-place P->R->P switch on
  a single, surviving connection to a single endpoint: the sender never runs a
  fresh reconnect round into a replica-only topology. The kill-9 suite always
  stands up a successor PRIMARY on the same port. Neither ever presents
  "primary gone, only replicas reachable, promote later" to the ingress sender.

Topology:
  A (primary) + B (replica), sharing one object store (real replication).
  Sender lists BOTH endpoints (addr=A,B), request_durable_ack=on.
  1. Ingest into A, durably acked; B converges via replication.
  2. kill -9 A. Only B (a REPLICA) is now reachable -> the failover window.
  3. Keep ingesting straight through the window, UNAWARE. These rows cannot
     be durably acked yet (a REPLICA rejects durable ack), so they accumulate
     in SF and MUST survive.
  4. Promote B -> primary underneath the still-producing sender.
  5. Keep ingesting after promotion (still unaware). The SAME sender (never a
     fresh CONNECT, which would mask a halt) drains SF to B. Assert the FULL
     sequence -- including every row produced during the outage -- durably acks
     on B and lands as a dense [0..total). A halted sender instead hard-fails a
     mid-stream FLUSH, which is the red-first signal.

Scope note:
  This also implicitly exercises SERVER-side unilateral promotion (kill the
  primary, then promote a replica while the old primary stays dead). If B
  fails to promote cleanly with A dead, that is a server/replication
  regression to triage separately, NOT the client store-and-forward
  invariant under test here.
"""

from __future__ import annotations

import logging
import time

import pytest

from lib import lifecycle as lc
from lib.pg_query import count_rows, wait_for_dense_sequence
from lib.sidecar import Sidecar, SidecarError

from c_client_sidecar import CClientRustSidecar

LOG = logging.getLogger(__name__)

_TABLE = "durable_ack_failover_c_client_rust"

# Rows ingested into A (durably acked) before the primary is killed.
_INITIAL_ROWS = 30
# Rows ingested DURING the replica-only window (no primary reachable). The
# producer keeps going, unaware; these cannot be durably acked until B is
# promoted, so they must be retained in on-disk SF and survive the outage --
# the data-continuity core of the SF invariant.
_WINDOW_ROWS = 40
# Rows ingested after promotion, still unaware anything happened.
_POST_ROWS = 20
# Ingest is issued in small batches with a brief pause so the producer is
# genuinely "in flight" across the kill/promote events (not one atomic burst).
_INGEST_BATCH = 10
_INGEST_BATCH_INTERVAL_S = 0.2

_DURABLE_ACK_AWAIT_TIMEOUT_MS = 60_000
_AWAIT_ROLE_TIMEOUT_S = 60.0
_POLL_INTERVAL_S = 0.3
# Deliberately short reconnect budget for the Invariant B red test. Invariant B
# says an SF drainer must NOT treat this as a give-up deadline -- it must keep
# retrying long after it elapses. Only SF exhaustion is terminal. In the Rust
# client the budget expiry rolls the reconnect state over
# (``retry_budget_exhausted_error`` is not ``reconnect_error_is_terminal``);
# this test pins that behaviour end-to-end.
_INVARIANT_B_SHORT_BUDGET_MS = 3000
# How many budgets' worth of replica-only window to hold open before asserting
# the sender is still alive.
_INVARIANT_B_HOLD_BUDGETS = 3


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
    producer does: COMPLETELY UNAWARE of failover. It never inspects role, never
    waits for a "healthy" sender, never probes reconnect state -- it just appends
    (SEND) and publishes to on-disk SF (FLUSH), both local operations that return
    whether or not any primary is reachable. The background drainer ships
    SF -> server on its own schedule.

    The ONLY terminal condition is SF exhaustion. So if SEND/FLUSH ever hard-
    fails on a transient failover window, that IS the regression this test
    guards: translate it into a descriptive, inline red-first assertion instead
    of letting a raw SidecarError bubble up."""
    try:
        sidecar.send(_TABLE, count=count, start_index=start_index)
        return sidecar.flush()  # publishes into SF; returns the published fsn
    except SidecarError as e:
        raise AssertionError(
            f"store-and-forward producer hard-failed while ingesting rows "
            f"[{start_index}..{start_index + count}) -- a transient replica-only "
            f"failover window must be survived by keeping rows in SF and retrying; "
            f"only SF exhaustion may be terminal. sidecar error: {e!r}"
        )


def _ingest_range_unaware(sidecar: Sidecar, *, start_index: int, total: int) -> int:
    """Drive ``total`` rows through :func:`_ingest_unaware` in small batches,
    returning the highest published fsn. Batching + a brief pause keeps the
    producer genuinely mid-stream across the kill/promote events."""
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
    """Harness-side coverage guard (never touches the producer): block until the
    sender has COMPLETED at least one full reconnect round against the
    replica-only topology, so the all-replica role-reject path -- the exact bug
    surface -- is provably exercised before we promote.

    reconnAttempts increments at the TOP of each reconnect round (the Rust
    runner's ``record_reconnect_attempt`` before each
    ``connect_qwp_ws_endpoint_round`` walk, same site as the Java client),
    BEFORE the endpoint walk reaches B, so a single increment only proves a
    round STARTED, not that it walked to B-as-replica -- promoting on +1 is a
    promote-too-early race. Requiring +2 proves the first round's walk
    completed (it threw, looped back, and incremented again), i.e. B was
    actually reached and role-rejected. STATS reads counters directly, never
    a flush."""
    target = baseline.reconn_attempts + 2
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if sidecar.stats().reconn_attempts >= target:
            return
        time.sleep(0.1)
    raise AssertionError(
        "sender did not complete a full replica-only reconnect round after the "
        f"primary was killed (needed reconnAttempts >= {target}); the all-replica "
        "role-reject path was never exercised before promotion"
    )


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_durable_ack_sender_survives_replica_only_window_c_client_rust(
    server_factory, c_client_rust_sidecar: CClientRustSidecar, scenario_dir
) -> None:
    sidecar = c_client_rust_sidecar
    sf_dir = scenario_dir / "sf"
    sf_dir.mkdir(parents=True, exist_ok=True)

    # ---- Boot A (primary) + B (replica), shared object store, both min-http. ----
    a = server_factory("a", role="primary")
    b = server_factory("b", role="replica")
    a_ports = a.start(min_http=True)
    b_ports = b.start(min_http=True)
    assert b_ports.min_http is not None, (
        "node b (replica): min_http port not reported; needed to promote B later"
    )
    LOG.info("a_ports=%s b_ports=%s", a_ports, b_ports)

    # ---- Durable-ack HA sender listing BOTH endpoints. A is primary -> binds A. ----
    connect_str = (
        f"ws::addr=127.0.0.1:{a_ports.http},127.0.0.1:{b_ports.http}"
        ";username=admin;password=quest"
        f";sf_dir={sf_dir}"
        ";request_durable_ack=on"
        # reconnect_max_duration_millis bounds only a blocking (sync) initial
        # connect. The mid-stream reconnect loop that rides out the promotion
        # window never gives up on it (Invariant B: budget expiry rolls the
        # reconnect state over; only SF exhaustion or a genuinely
        # non-retriable auth/upgrade reject is terminal), so this value is
        # inert for the outage this test stages.
        ";reconnect_max_duration_millis=300000"
        ";reconnect_initial_backoff_millis=100"
        ";reconnect_max_backoff_millis=1000"
        ";close_flush_timeout_millis=5000;"
    )
    sidecar.connect(connect_str)

    # ---- Ingest N rows, durably acked by A; B converges via replication. ----
    initial_fsn = _ingest_range_unaware(sidecar, start_index=0, total=_INITIAL_ROWS)
    assert sidecar.await_acked(initial_fsn, _DURABLE_ACK_AWAIT_TIMEOUT_MS), (
        f"initial batch was not durably acked by A [publishedFsn={initial_fsn}]"
    )
    wait_for_dense_sequence(port=a_ports.pg, table=_TABLE,
                            expected_count=_INITIAL_ROWS, timeout_s=60.0)
    _wait_count(port=b_ports.pg, table=_TABLE, expected=_INITIAL_ROWS, timeout_s=120.0)
    LOG.info("A durably holds %d rows; B converged via replication", _INITIAL_ROWS)

    # ---- Disturbance: kill the primary. Only B (a REPLICA) is now reachable. ----
    baseline = sidecar.stats()
    a.kill_9()
    LOG.info("killed primary A; entering replica-only failover window")

    # ---- Keep ingesting straight through the window, UNAWARE. These rows are
    #      produced while no primary is reachable, so the drainer cannot ship
    #      them (B rejects durable ack as a REPLICA); they accumulate in on-disk
    #      SF and must survive. The producer never checks health or waits. ----
    _ingest_range_unaware(sidecar, start_index=_INITIAL_ROWS, total=_WINDOW_ROWS)
    LOG.info("ingested %d rows into SF during the replica-only window", _WINDOW_ROWS)

    # Coverage guard: make sure a full all-replica reconnect ROUND completed
    # before we promote (counters only; never drives the producer).
    _await_all_replica_round(sidecar, baseline, timeout_s=30.0)

    # ---- Promote B -> primary underneath the still-producing sender. ----
    LOG.info("promoting B REPLICA -> PRIMARY via /lifecycle/switch")
    lc.submit_switch(b_ports.min_http, "primary", wait=True, wait_timeout_s=_AWAIT_ROLE_TIMEOUT_S)

    # ---- Keep ingesting after promotion, still unaware anything happened. The
    #      SAME sender is used throughout -- never a fresh CONNECT, which would
    #      mask a halted sender and defeat the test. ----
    final_fsn = _ingest_range_unaware(
        sidecar, start_index=_INITIAL_ROWS + _WINDOW_ROWS, total=_POST_ROWS
    )

    # ---- Terminal drain: one await for the FULL published sequence. Every row
    #      -- including those produced during the outage -- must durably ack on
    #      the promoted primary. (A halted sender would already have hard-failed
    #      a mid-stream FLUSH above.) ----
    assert sidecar.await_acked(final_fsn, _DURABLE_ACK_AWAIT_TIMEOUT_MS), (
        f"rows produced across the failover were lost: full published sequence not "
        f"durably acked by promoted B [publishedFsn={final_fsn}]. A store-and-forward "
        f"sender must retain outage-window rows in SF and drain them after promotion."
    )

    total = _INITIAL_ROWS + _WINDOW_ROWS + _POST_ROWS
    wait_for_dense_sequence(port=b_ports.pg, table=_TABLE,
                            expected_count=total, timeout_s=120.0)
    LOG.info("recovered: durable-ack sender drained across the failover; B holds [0..%d)", total)


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_durable_ack_drainer_never_gives_up_on_reconnect_budget_c_client_rust(
    server_factory, c_client_rust_sidecar: CClientRustSidecar, scenario_dir
) -> None:
    """INVARIANT B (red-first in the java client): once rows are in on-disk SF,
    the drainer must NEVER terminate on a wall-clock reconnect budget. It may
    back off, but only SF exhaustion is terminal, and the client must never
    fail because of the drainer.

    We establish a durably-acked sender, kill the primary, then hold a
    replica-only window (NO promotion) for several times the reconnect budget
    while the producer keeps appending to SF. The sender must stay alive: every
    FLUSH must keep succeeding (publishing to on-disk SF).

    Red-first history (java): the client originally enforced
    reconnect_max_duration_millis as a give-up deadline, so the first FLUSH
    after the budget elapsed hard-failed -> RED. Shipped semantics (both
    clients): the drainer never gives up on the budget and only ever
    terminates on SF exhaustion. In the Rust client the budget expiry rolls
    the reconnect state over (``reconnect_with_policy`` re-arms on
    ``retry_budget_exhausted_error``; only AuthError/ProtocolVersionError are
    ``reconnect_error_is_terminal``). This test pins that end-to-end.

    Contrast test_durable_ack_sender_survives_replica_only_window (above),
    which promotes B inside the outage window and never outlives the budget:
    this test deliberately outlives a SHORT budget to pin Invariant B.

    Relationship to test_failover.py::
    test_orphan_drainer_durable_ack_survives_drain_reconnect_c_client_rust:
    that test churns the ORPHAN (background-adoption) drainer's drain
    connection against a live primary and pins trim discipline across
    re-adoption; this test targets the IN-PROCESS sender's own drainer
    outliving a wall-clock reconnect budget in a replica-only window --
    give-up semantics, not trim discipline.
    """
    sidecar = c_client_rust_sidecar
    sf_dir = scenario_dir / "sf"
    sf_dir.mkdir(parents=True, exist_ok=True)

    a = server_factory("a", role="primary")
    b = server_factory("b", role="replica")
    a_ports = a.start(min_http=True)
    b_ports = b.start(min_http=True)
    assert b_ports.min_http is not None, (
        "node b (replica): min_http port not reported; needed to promote B later"
    )
    LOG.info("a_ports=%s b_ports=%s", a_ports, b_ports)

    connect_str = (
        f"ws::addr=127.0.0.1:{a_ports.http},127.0.0.1:{b_ports.http}"
        ";username=admin;password=quest"
        f";sf_dir={sf_dir}"
        ";request_durable_ack=on"
        # Deliberately short -- Invariant B forbids treating this as terminal for
        # an SF drainer. The window below outlives it several times over.
        f";reconnect_max_duration_millis={_INVARIANT_B_SHORT_BUDGET_MS}"
        ";reconnect_initial_backoff_millis=100"
        ";reconnect_max_backoff_millis=1000"
        ";close_flush_timeout_millis=5000;"
    )
    sidecar.connect(connect_str)

    # ---- Establish a live, durably-acked sender against A; B converges. ----
    sidecar.send(_TABLE, count=_INITIAL_ROWS, start_index=0)
    initial_fsn = sidecar.flush()
    assert sidecar.await_acked(initial_fsn, _DURABLE_ACK_AWAIT_TIMEOUT_MS), (
        f"initial batch was not durably acked by A [publishedFsn={initial_fsn}]"
    )
    _wait_count(port=b_ports.pg, table=_TABLE, expected=_INITIAL_ROWS, timeout_s=120.0)
    LOG.info("A durably holds %d rows; B converged via replication", _INITIAL_ROWS)

    # ---- Kill the primary and DELIBERATELY do not promote. Hold the
    #      replica-only window open for several reconnect budgets. ----
    a.kill_9()
    kill_at = time.monotonic()
    hold_s = (_INVARIANT_B_SHORT_BUDGET_MS / 1000.0) * _INVARIANT_B_HOLD_BUDGETS
    LOG.info("killed primary A; holding replica-only window for %.1fs (%dx the %dms budget)",
             hold_s, _INVARIANT_B_HOLD_BUDGETS, _INVARIANT_B_SHORT_BUDGET_MS)

    # The producer keeps appending to SF, unaware. Invariant B: it must NEVER
    # give up -> every FLUSH must keep succeeding, well past the budget.
    idx = _INITIAL_ROWS
    hold_deadline = kill_at + hold_s
    while time.monotonic() < hold_deadline:
        elapsed_ms = int((time.monotonic() - kill_at) * 1000)
        try:
            sidecar.send(_TABLE, count=1, start_index=idx)
            sidecar.flush()  # publishes into SF; must keep succeeding
        except SidecarError as e:
            raise AssertionError(
                f"durable-ack SF drainer gave up ~{elapsed_ms}ms into a replica-only window "
                f"with a {_INVARIANT_B_SHORT_BUDGET_MS}ms reconnect budget: a store-and-forward "
                f"drainer must NEVER terminate on a wall-clock reconnect budget -- only SF "
                f"exhaustion is terminal, and the client must never fail because of the drainer. "
                f"sidecar error: {e}"
            )
        idx += 1
        time.sleep(0.25)
    LOG.info("sender stayed alive across %.1fs of replica-only window (well past budget)", hold_s)

    # ---- Positive confirmation the sender was genuinely alive (not silently
    #      wedged): promote B and assert every row -- including all produced
    #      during the long window -- durably acks and lands as a dense [0..idx). ----
    LOG.info("promoting B REPLICA -> PRIMARY via /lifecycle/switch")
    lc.submit_switch(b_ports.min_http, "primary", wait=True, wait_timeout_s=_AWAIT_ROLE_TIMEOUT_S)
    # Rust adaptation: Java's flush() returns the highest published FSN even
    # on an empty buffer; the Rust empty-buffer flush returns -1 (None), which
    # AWAIT_ACKED rejects. Publish one tail row post-promotion instead -- a
    # strictly stronger liveness proof (the sender must still accept work
    # after the outage) that yields a definitive final fsn.
    sidecar.send(_TABLE, count=1, start_index=idx)
    idx += 1
    final_fsn = sidecar.flush()
    assert sidecar.await_acked(final_fsn, _DURABLE_ACK_AWAIT_TIMEOUT_MS), (
        f"rows produced across the long replica-only window were lost: not durably acked by "
        f"promoted B [publishedFsn={final_fsn}]"
    )
    wait_for_dense_sequence(port=b_ports.pg, table=_TABLE, expected_count=idx, timeout_s=120.0)
    LOG.info("drainer never gave up; B holds [0..%d) after promotion", idx)
