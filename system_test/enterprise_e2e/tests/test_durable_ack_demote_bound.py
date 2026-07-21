"""
Durable-ack waiter carried THROUGH a PRIMARY-to-REPLICA demote must be
released or terminal within a bound -- never an indefinite hang.

Port of the Enterprise JUnit witness
``DurableAckThroughDemoteTest.testDurableAckClientThroughDemoteIsReleasedOrTerminalWithinBound``
(the sibling ``testQwpDurableAckSenderSurvivesInPlaceDemote`` is already
covered by ``test_demotion_mid_stream.py`` -- deliberately not
duplicated here).

Contract: a ``request_durable_ack=on`` client does not treat a commit as
acknowledged on the OK frame; it waits for the second "durable" ack,
which the server emits only once the object store has persisted the
commit's seqTxn. On a demote the engine swaps the ``DurableAckRegistry``
to the disabled sentinel, whose watermark never advances. A client still
waiting on a pending seqTxn at that moment must not be left hanging with
no signal: the rubric (Phase-15, criterion 2b) is "released OR a prompt
terminal error within a bound". This test does NOT require the server to
auto-reconcile the pending durable ack -- a prompt terminal suffices; a
silent hang past the bound is the bug.

Determinism substitution (in-process JUnit -> forked harness): the JUnit
test keeps the pending durable ack outstanding at demote time with a
slow request-retry + long keepalive; the forked harness pins the same
premise HARDER with the data-upload throttle window (the same seam
``SqlFailoverQwpDeferredCloseExactlyOnceTest`` uses): DATA uploads are
held far longer than the test budget, so the durable ack for the
committed batch CANNOT have arrived before the demote -- verified by an
explicit premise tripwire (a bounded AWAIT_ACKED that must time out
pre-demote). The demote drain (``cleanShutdown``'s urgent advance) then
completes the uploads inside the switch cascade, so on current servers
the expected green outcome is "released" via the role-change close's
final durable ack; a clean sidecar ERR is the "terminal" outcome; an
AWAIT_ACKED that returns false within the bound is the hang -- red.

Vehicle note: the JUnit demote uses the in-process
``orch.submitSwitch(Role.REPLICA)`` API; the observable equivalent here
is the min-http ``POST /lifecycle/switch`` (same processor underneath).
The SQL-trigger vehicle is pinned separately by
``test_sql_failover_lossless.py``.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from lib import lifecycle as lc
from lib.pg_query import wait_for_dense_sequence
from lib.sidecar import SidecarError

from c_client_sidecar import CClientRustSidecar

LOG = logging.getLogger(__name__)

_TABLE = "durable_through_demote_c_client_rust"
_ROWS = 10

# Premise tripwire: with A's data uploads held by the 600s throttle
# window, the durable ack for the committed batch must NOT arrive within
# this pre-demote probe window.
_PREMISE_PROBE_MS = 1_500
# Upper bound on how long the durable-ack waiter may stay outstanding
# through the demote before it must be released or surfaced as terminal.
# The JUnit bound is 10s from the post-settle await; forked servers get
# a little slack for the drain's store round-trips.
_WAITER_RESOLUTION_BOUND_MS = 15_000
_SETTLE_WAIT_S = 60.0
_UPLOAD_HOLDING_THROTTLE_WINDOW_MS = 600_000


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_durable_ack_through_demote_released_or_terminal_within_bound_c_client_rust(
    server_factory, c_client_rust_sidecar: CClientRustSidecar, scenario_dir: Path
) -> None:
    sidecar = c_client_rust_sidecar
    sf_dir = scenario_dir / "sf"
    sf_dir.mkdir(parents=True, exist_ok=True)

    # ---- Boot A as a primary whose DATA uploads are held (so the pending
    #      durable ack is deterministically outstanding when the role
    #      flips); index uploads stay immediate. ----
    a = server_factory("a", role="primary", extra_env={
        "QDB_REPLICATION_PRIMARY_THROTTLE_WINDOW_DURATION":
            str(_UPLOAD_HOLDING_THROTTLE_WINDOW_MS),
        "QDB_REPLICATION_PRIMARY_INDEX_UPLOAD_THROTTLE_INTERVAL": "0",
    })
    a_ports = a.start(min_http=True)
    assert a_ports.min_http is not None, (
        "node a: min_http port not reported; needed to demote A"
    )
    LOG.info("a_ports=%s", a_ports)

    # ---- Commit a batch with request_durable_ack=on. The acked watermark
    #      advances only on the durable ack frame, so publishedFsn stays
    #      outstanding until the (held) upload completes. ----
    sidecar.connect(
        f"ws::addr=127.0.0.1:{a_ports.http}"
        ";username=admin;password=quest"
        f";sf_dir={sf_dir}"
        ";request_durable_ack=on"
        ";close_flush_timeout_millis=15000;"
    )
    sidecar.send(_TABLE, count=_ROWS, start_index=0)
    published_fsn = sidecar.flush()
    assert published_fsn >= 0, "FLUSH must publish the committed batch to SF"

    # PREMISE TRIPWIRE: the durable ack is genuinely outstanding at demote
    # time. With uploads held for 600s this bounded await MUST time out --
    # if it returns released, the premise is broken (an upload raced the
    # window) and the demote below would have nothing pending to resolve.
    premise_released = sidecar.await_acked(published_fsn, _PREMISE_PROBE_MS)
    assert not premise_released, (
        f"test premise broken: the batch durably acked BEFORE the demote "
        f"despite the {_UPLOAD_HOLDING_THROTTLE_WINDOW_MS}ms upload-holding "
        f"throttle window [publishedFsn={published_fsn}] -- the waiter would "
        f"not be carried through the demote at all"
    )
    LOG.info("premise pinned: durable ack outstanding at demote submit "
             "[publishedFsn=%d]", published_fsn)

    # ---- Demote A -> REPLICA underneath the pending durable-ack waiter. ----
    lc.submit_switch(a_ports.min_http, "replica", wait=True,
                     wait_timeout_s=_SETTLE_WAIT_S)
    LOG.info("A settled as REPLICA; awaiting waiter resolution within %dms",
             _WAITER_RESOLUTION_BOUND_MS)

    # ---- The waiter must resolve within the bound: released (durable ack
    #      arrived -- on current servers via the demote drain completing
    #      the held uploads + the role-change close's final durable ack)
    #      or a prompt terminal error (clean sidecar ERR). A false return
    #      is the hang -- the witness for a real durable-ack-through-demote
    #      bug: escalate, don't relabel flaky. ----
    released = False
    terminal = False
    try:
        released = sidecar.await_acked(published_fsn, _WAITER_RESOLUTION_BOUND_MS)
    except SidecarError as exc:
        terminal = True
        LOG.info("waiter resolved TERMINAL (prompt error): %s", exc)

    assert released or terminal, (
        f"a durable-ack client carried through a demote must be released "
        f"(durable ack arrived) or get a prompt terminal error within "
        f"{_WAITER_RESOLUTION_BOUND_MS}ms, never hang "
        f"[released={released}, terminal={terminal}, publishedFsn={published_fsn}]"
    )
    LOG.info("waiter resolved within bound [released=%s, terminal=%s]",
             released, terminal)

    # ---- Outcome capture for triage (the JUnit test logs the same): on
    #      the released path, the demote drain uploaded the commit, so the
    #      rows are durable in the store; pin data continuity on A itself
    #      (a REPLICA serves reads) -- the batch must be visible exactly
    #      once. ----
    if released:
        wait_for_dense_sequence(port=a_ports.pg, table=_TABLE,
                                expected_count=_ROWS, timeout_s=30.0)
        LOG.info("released path: batch visible exactly once on the demoted node")
