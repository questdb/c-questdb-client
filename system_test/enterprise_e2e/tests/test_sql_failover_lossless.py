"""
SQL-triggered failover losslessness for an OBLIVIOUS c-questdb-client
Rust sender, ported from the Enterprise JUnit witnesses:

  * ``SqlFailoverQwpClientLosslessTest.testObliviousQwpClientLosslessAcrossSqlFailover``
  * ``SqlFailoverQwpClientLosslessTest.testObliviousDurableAckQwpClientLosslessNoCatchupWait``
  * ``SqlFailoverQwpDeferredCloseExactlyOnceTest.testDeferredCloseExactlyOnceWithUploadsHeldUntilDemoteDrain``

Scenario (all three): a two-node replicated pair (A primary, B replica).
One Rust QWP sender is configured with BOTH endpoints and an on-disk SF
dir, and a background writer thread streams uniquely-timestamped rows
continuously. While the writer is producing, the operator demotes A via
the SQL trigger (``SWITCH ROLE TO REPLICA`` over a real pg-wire client
connection -- the exact operator vehicle the JUnit tests pin; NO node is
ever restarted) and then promotes B via SQL. The client is never told
about the move: it must ride out the window where NO node is writable
on its own reconnect walk -- role rejects are transient, rows park in
on-disk SF, and the drainer replays from ackedFsn+1 once B accepts
writes.

Oracles (shared):
  * Obliviousness -- the writer thread never observes a sidecar error
    across the whole move and keeps making append progress after B's
    promote settles.
  * No loss / no duplication -- after a full drain (one AWAIT_ACKED on
    the highest published fsn), the new primary B holds EXACTLY the
    dense sequence [0..total) (``wait_for_dense_sequence``: exact count,
    exact values -- strictly stronger than the JUnit count+sum pair).
  * Onward convergence -- the demoted A, now a downloading replica of
    B, converges to the same exact count.

In-process-JUnit -> forked-harness substitutions (documented per test):
  * ``orch.currentRole()`` / ``waitForRole`` -> min-http ``GET
    /lifecycle`` polling (``lib.lifecycle.await_role``).
  * ``awaitOwnershipTokenParity`` (reads the store's ``index.msgpack``
    sync id + the replica's ``_replication_sync_id.d`` mmap) -> not
    observable black-box; replaced by the promote-with-retry loop the
    JUnit tests document as the designed recovery for the clean ER005
    fence refusal ("this retry loop can genuinely recover from a fence
    refusal once the token catches up"). The first submit may be
    refused; the loop resubmits until the role settles.
  * ``engine.getDurableAckRegistry().getDurablyUploadedSeqTxn(..)``
    (deferred-close premise/mechanism tripwires) -> replication-visible
    equivalents: with A's DATA uploads held by the throttle window, B
    (a live downloading replica) provably CANNOT hold the committed
    corpus before the demote (premise tripwire), and B converging on
    that corpus after the demote settles -- before any promote -- proves
    the demote drain completed the held uploads (mechanism tripwire).
  * ``Sender.drain(timeout)`` -> AWAIT_ACKED on the last published fsn
    (the writer always flushes each batch, so at stop time published ==
    appended).

The role-switch vehicle is deliberately pg-wire SQL here (not the
min-http /lifecycle/switch used by test_switch.py and friends): the
JUnit witnesses exist specifically to pin the *SQL-triggered* failover
path (``SWITCH ROLE`` submitted by an operator through a SQL
connection), so the port preserves that trigger. Role *settling* is
still observed via min-http /lifecycle -- the JUnit equivalent is the
in-process ``waitForRole``, and the SQL trigger returns its accepted
row immediately (async handoff) in both harnesses.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from lib import lifecycle as lc
from lib.pg_query import count_rows, execute_ddl, wait_for_dense_sequence

from c_client_sidecar import CClientRustEgressSidecar, CClientRustSidecar
from tests.qwp_sql_switch import (
    ObliviousWriter,
    count_or_zero,
    ha_connect_string,
    promote_with_retry_sql,
    submit_switch_sql,
    wait_count_at_least,
)

LOG = logging.getLogger(__name__)

# Corpus sizes -- same as the JUnit constants.
_PRE_SWITCH_ROWS = 500
_POST_PROMOTE_ROWS = 500

_SETTLE_WAIT_S = 60.0
_DRAIN_AWAIT_TIMEOUT_MS = 120_000
_CONVERGENCE_TIMEOUT_S = 120.0

# Deferred-close test: DATA uploads on A are held far longer than the
# test budget, so committed work is deterministically pending-upload at
# demote time and the demote drain (not the throttle schedule) is what
# completes the uploads. Index uploads stay immediate so the ownership
# sync id keeps tracking (mirrors the JUnit setUp).
_UPLOAD_HOLDING_THROTTLE_WINDOW_MS = 600_000


def _run_lossless_sql_failover(server_factory, sidecar: CClientRustSidecar,
                               scenario_dir: Path, *, durable_ack: bool,
                               table: str) -> None:
    """Shared runner for the two SqlFailoverQwpClientLosslessTest
    variants (mirrors ``runLosslessFailoverScenario``)."""
    sf_dir = scenario_dir / "sf"
    sf_dir.mkdir(parents=True, exist_ok=True)

    # ---- Boot A (primary) + B (replica), shared object store. ----
    a = server_factory("a", role="primary")
    b = server_factory("b", role="replica")
    a_ports = a.start(min_http=True)
    b_ports = b.start(min_http=True)
    assert a_ports.min_http is not None and b_ports.min_http is not None
    LOG.info("a_ports=%s b_ports=%s", a_ports, b_ports)

    # Dedup with a unique per-row designated timestamp turns the final
    # dense-sequence oracle into a combined no-loss/no-duplication pin:
    # SF replay of a committed-but-unacked frame after the mid-move
    # disconnect legitimately resends rows B already received through
    # the demote drain; dedup collapses them. (Schema matches the
    # sidecar's SEND shape: single long column `v`, ts = (v+1) seconds.)
    execute_ddl(port=a_ports.pg, ddl=(
        f'CREATE TABLE "{table}" (ts TIMESTAMP, v LONG) '
        "TIMESTAMP(ts) PARTITION BY DAY WAL DEDUP UPSERT KEYS(ts)"
    ))

    sidecar.connect(ha_connect_string(a_ports.http, b_ports.http, sf_dir,
                                      durable_ack=durable_ack))

    writer = ObliviousWriter(sidecar, table)
    writer.start()
    try:
        # Phase 1: a pre-switch corpus lands on A and B proves it is
        # downloading (replication live before the disturbance).
        writer.await_appended(_PRE_SWITCH_ROWS)
        wait_count_at_least(a_ports.pg, table, _PRE_SWITCH_ROWS,
                            timeout_s=_SETTLE_WAIT_S)
        wait_count_at_least(b_ports.pg, table, _PRE_SWITCH_ROWS,
                            timeout_s=_CONVERGENCE_TIMEOUT_S)
        LOG.info("pre-switch corpus committed on A and replicated to B")

        # Phase 2: demote A via the SQL trigger while the client keeps
        # writing (the trigger returns immediately; the cascade settles
        # in the background -- exactly the JUnit submit).
        assert submit_switch_sql(a_ports.pg, "replica"), (
            "SWITCH ROLE TO REPLICA must be accepted on the primary"
        )
        lc.await_role(a_ports.min_http, "replica", timeout_s=_SETTLE_WAIT_S)
        LOG.info("A settled as REPLICA (SQL-triggered demote)")

        if not durable_ack:
            # Operator-style promote precondition: B has applied
            # everything A drained to the object store. A is fenced, so
            # its count is final; wait until B has at least that.
            # (JUnit waitTableReplicated(A -> B).) The durable-ack
            # variant SKIPS this data wait on purpose: a durable ack
            # certifies the store already has the row, so B's own
            # promote-path catch-up must be sufficient -- that is the
            # invariant it pins.
            a_final = count_rows(port=a_ports.pg, table=table, timeout_s=10.0)
            wait_count_at_least(b_ports.pg, table, a_final,
                                timeout_s=_CONVERGENCE_TIMEOUT_S)
            LOG.info("operator catch-up wait done: B holds >= %d rows", a_final)

        # Phase 3: promote B via the SQL trigger, retrying the designed
        # clean ownership-fence refusal (substitutes the JUnit's
        # awaitOwnershipTokenParity + promoteWithRetry pair; see module
        # docstring).
        promote_with_retry_sql(b_ports.pg, b_ports.min_http)
        LOG.info("B settled as PRIMARY (SQL-triggered promote)")

        # Phase 4: the oblivious client keeps producing a post-promote
        # corpus -- append progress proves the writer was never wedged.
        writer.await_appended(writer.appended + _POST_PROMOTE_ROWS)
    finally:
        writer.stop()

    writer.assert_oblivious()
    total = writer.appended
    final_fsn = writer.last_fsn
    assert total > 0 and final_fsn >= 0

    # Phase 5: full drain -- every published frame server-acked (with
    # durable ack requested, additionally store-persisted). From here
    # the oracle is exact.
    assert sidecar.await_acked(final_fsn, _DRAIN_AWAIT_TIMEOUT_MS), (
        f"sender must drain fully after the failover (all rows acked) "
        f"[publishedFsn={final_fsn}]"
    )

    # No-loss/no-duplication oracle on the new primary: exact dense
    # sequence [0..total) (count + values; supersedes JUnit count+sum).
    wait_for_dense_sequence(port=b_ports.pg, table=table,
                            expected_count=total, timeout_s=_CONVERGENCE_TIMEOUT_S)

    # Phase 6: onward convergence -- A (now a downloading replica of B)
    # reaches the same exact count.
    wait_count_at_least(a_ports.pg, table, total, timeout_s=_CONVERGENCE_TIMEOUT_S)
    assert count_rows(port=a_ports.pg, table=table) == total, (
        "A (demoted replica) must converge to the exact acked row count"
    )
    LOG.info("lossless across SQL failover: %d rows exactly once on both nodes", total)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_oblivious_sender_lossless_across_sql_failover_c_client_rust(
    server_factory, c_client_rust_sidecar: CClientRustSidecar, scenario_dir: Path
) -> None:
    """Plain-ack variant: operator-style handover (promote only a
    caught-up replica). Port of
    ``testObliviousQwpClientLosslessAcrossSqlFailover``."""
    _run_lossless_sql_failover(
        server_factory, c_client_rust_sidecar, scenario_dir,
        durable_ack=False, table="sql_failover_lossless_c_client_rust",
    )


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_oblivious_durable_ack_sender_lossless_no_catchup_wait_c_client_rust(
    server_factory, c_client_rust_sidecar: CClientRustSidecar, scenario_dir: Path
) -> None:
    """Durable-ack variant: ``request_durable_ack=on`` and NO
    operator-side catch-up wait between demote and promote -- the count
    oracle pins the promote path's own store catch-up as sufficient for
    durably-acked data. Port of
    ``testObliviousDurableAckQwpClientLosslessNoCatchupWait``."""
    _run_lossless_sql_failover(
        server_factory, c_client_rust_sidecar, scenario_dir,
        durable_ack=True, table="sql_failover_da_lossless_c_client_rust",
    )


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_deferred_close_exactly_once_uploads_held_until_demote_drain_c_client_rust(
    server_factory, c_client_rust_sidecar: CClientRustSidecar,
    c_client_rust_egress_sidecar: CClientRustEgressSidecar,
    scenario_dir: Path,
) -> None:
    """Deterministic witness for the QWP role-change close deferral
    (INVARIANT B, ``QwpIngressUpgradeProcessor.roleChangeCloseWithUploadGrace``):
    a durable-ack client survives a SQL-triggered failover EXACTLY ONCE
    on a table WITHOUT dedup keys, with committed work FORCED to be
    pending-upload at demote time. Port of
    ``SqlFailoverQwpDeferredCloseExactlyOnceTest``.

    Why this exists on top of the durable-ack lossless variant above:
    with immediate uploads the durable watermark usually covers every
    committed seqTxn BEFORE the demote's close polls the deferral, so a
    broken deferral can pass unnoticed -- and a dedup table silently
    collapses the replayed duplicate. Here node A holds DATA uploads for
    600s (>> test budget) so nothing is durably acked until the demote
    drain completes the uploads INSIDE the switch cascade, and the table
    has NO dedup keys so a replay duplicate is a visible dense-sequence
    violation.

    Tripwires (observable substitutions for the JUnit's
    DurableAckRegistry watermark reads, see module docstring):
      * PREMISE  -- committed work is provably pending-upload at demote
        submit: A holds the corpus (pg-visible = committed) while B --
        a live downloading replica polling the shared store -- holds
        NONE of it.
      * MECHANISM -- after the demote settles (and before any promote),
        B converges on A's committed corpus: the demote drain completed
        the held uploads and the store now serves them.

    Client surface note: the JUnit test drives ONE ``QuestDB`` cluster
    facade for both ingest and readback. The Rust binding has no such
    facade; the port uses the ingress sidecar + the egress Reader
    sidecar configured with the SAME two endpoints -- written via the
    ingress client, survived the failover, seen via the egress client
    (the loop the JUnit closes client-to-client).
    """
    table = "deferred_close_exactly_once_c_client_rust"
    sf_dir = scenario_dir / "sf"
    sf_dir.mkdir(parents=True, exist_ok=True)

    # Node A: primary with the upload-holding DATA throttle window; index
    # uploads stay immediate so the ownership sync id keeps tracking.
    a = server_factory("a", role="primary", extra_env={
        "QDB_REPLICATION_PRIMARY_THROTTLE_WINDOW_DURATION":
            str(_UPLOAD_HOLDING_THROTTLE_WINDOW_MS),
        "QDB_REPLICATION_PRIMARY_INDEX_UPLOAD_THROTTLE_INTERVAL": "0",
    })
    # Node B: replica whose own primary tuning uses an IMMEDIATE window,
    # so once promoted, uploads (and the client's durable acks and the
    # final drain) flow without delay.
    b = server_factory("b", role="replica", extra_env={
        "QDB_REPLICATION_PRIMARY_THROTTLE_WINDOW_DURATION": "0",
        "QDB_REPLICATION_PRIMARY_INDEX_UPLOAD_THROTTLE_INTERVAL": "0",
    })
    a_ports = a.start(min_http=True)
    b_ports = b.start(min_http=True)
    assert a_ports.min_http is not None and b_ports.min_http is not None
    LOG.info("a_ports=%s b_ports=%s", a_ports, b_ports)

    # NO DEDUP KEYS -- deliberately (the table is auto-created by the
    # first ingest commit as a plain WAL table). A replayed duplicate is
    # a visible dense-sequence violation.
    sidecar = c_client_rust_sidecar
    sidecar.connect(ha_connect_string(a_ports.http, b_ports.http, sf_dir,
                                      durable_ack=True))

    writer = ObliviousWriter(sidecar, table)
    writer.start()
    try:
        # Phase 1: pre-switch corpus published AND committed on A. No
        # B-replication wait -- B CANNOT have the data yet, that is the
        # point (A's data uploads are held).
        writer.await_appended(_PRE_SWITCH_ROWS)
        wait_count_at_least(a_ports.pg, table, _PRE_SWITCH_ROWS,
                            timeout_s=_SETTLE_WAIT_S)
        committed_before_demote = count_rows(port=a_ports.pg, table=table,
                                             timeout_s=10.0)

        # PREMISE TRIPWIRE: the throttle window genuinely holds the
        # committed work's upload -- B, a live polling replica of the
        # shared store, must hold NONE of it at demote-submit time.
        b_before = count_or_zero(b_ports.pg, table)
        assert b_before == 0, (
            f"test premise broken: B already holds {b_before} rows before the "
            f"demote, so A's data-throttle window did not hold the uploads and "
            f"the role-change close deferral would not be genuinely exercised"
        )
        LOG.info("premise pinned: A committed %d rows, B holds 0 (uploads held)",
                 committed_before_demote)

        # Phase 2: demote A via the SQL trigger while the client keeps
        # writing -- the gate-refused in-flight frame arms the deferral;
        # the drain completes the held uploads; the close must flush the
        # final durable ack before the reconnect-eligible CLOSE.
        assert submit_switch_sql(a_ports.pg, "replica"), (
            "SWITCH ROLE TO REPLICA must be accepted on the primary"
        )
        lc.await_role(a_ports.min_http, "replica", timeout_s=_SETTLE_WAIT_S)
        LOG.info("A settled as REPLICA (SQL-triggered demote)")

        # MECHANISM TRIPWIRE: the drain covered the held uploads -- B
        # (still an un-promoted replica) can now download the corpus
        # from the store. Runs BEFORE any promote, so the coverage can
        # only have come from A's demote drain.
        wait_count_at_least(b_ports.pg, table, committed_before_demote,
                            timeout_s=_CONVERGENCE_TIMEOUT_S)
        LOG.info("mechanism pinned: demote drain uploaded the held corpus "
                 "(B converged on %d rows pre-promote)", committed_before_demote)

        # Durable-ack contract: NO operator-side data catch-up wait
        # beyond the mechanism tripwire above; promote with the designed
        # clean-refusal retry.
        promote_with_retry_sql(b_ports.pg, b_ports.min_http)
        LOG.info("B settled as PRIMARY (SQL-triggered promote)")

        # Phase 4: post-promote append progress.
        writer.await_appended(writer.appended + _POST_PROMOTE_ROWS)
    finally:
        writer.stop()

    writer.assert_oblivious()
    total = writer.appended
    final_fsn = writer.last_fsn

    # Phase 5: full drain -- every published frame durably acked (B's
    # window is 0, so uploads and durable acks flow).
    assert sidecar.await_acked(final_fsn, _DRAIN_AWAIT_TIMEOUT_MS), (
        f"sender must drain fully after the failover (all rows durably acked) "
        f"[publishedFsn={final_fsn}]"
    )

    # EXACTLY-ONCE oracle on the new primary, server-side: the dense
    # sequence [0..total) on a table with NO dedup to hide behind.
    # count > total (a replay duplicate a broken deferral produced) and
    # count < total (a wrongly-trimmed replay slot) both fail, as does
    # any value corruption (supersedes the JUnit count+sum pair).
    wait_for_dense_sequence(port=b_ports.pg, table=table,
                            expected_count=total, timeout_s=_CONVERGENCE_TIMEOUT_S)

    # Phase 6: onward convergence -- A (now a downloading replica of B)
    # reaches the identical exact count. Runs BEFORE the client-side
    # readback (a deliberate reorder vs the JUnit sequence): the egress
    # Reader is free to bind EITHER endpoint (target=any walks the list
    # in order and A is listed first), so both nodes must hold exactly
    # `total` for the readback to be exact whichever node serves it --
    # the same sequencing the JUnit chaos sibling uses for its readback.
    wait_count_at_least(a_ports.pg, table, total, timeout_s=_CONVERGENCE_TIMEOUT_S)
    assert count_rows(port=a_ports.pg, table=table) == total, (
        "A (demoted replica) must converge to the exact acked row count"
    )

    # CLIENT-SIDE readback oracle over QWP egress: written via the
    # ingress client, survived the failover exactly once, seen via the
    # egress Reader. The Reader's QUERY verb returns the row count; the
    # exact-sum check rides a row-count predicate (a wrong sum yields
    # zero rows).
    expected_sum = total * (total - 1) // 2
    egress = c_client_rust_egress_sidecar
    egress.connect(
        f"ws::addr=127.0.0.1:{a_ports.http},127.0.0.1:{b_ports.http};"
        "username=admin;password=quest;failover_max_duration_ms=30000;"
    )
    rows_seen, _ = egress.query(f'SELECT v FROM "{table}"')
    assert rows_seen == total, (
        f"client-side QWP egress query must see every appended row exactly "
        f"once [saw {rows_seen}, expected {total}]"
    )
    sum_rows, _ = egress.query(
        f'SELECT 1 FROM (SELECT sum(v) s FROM "{table}") WHERE s = {expected_sum}'
    )
    assert sum_rows == 1, (
        f"client-side QWP egress query must see the exact appended id sum "
        f"{expected_sum}"
    )
    LOG.info("deferred close exactly-once: %d rows, no dedup, both nodes exact", total)
