"""
Role-bounce CHAOS witness: an oblivious durable-ack Rust sender keeps
publishing and historical readers keep reading while a two-node pair
bounces roles repeatedly (P->R, R->P, and again, with randomized
timing).

Port of the Enterprise JUnit witness
``QwpRoleBounceChaosLosslessTest.testObliviousDurableAckSenderAndHistoricalReadersSurviveRoleBouncing``.

This is the multi-flap generalization of the single-handover
``test_sql_failover_lossless.py`` durable-ack variant crossed with the
reads-never-frozen contract: every flap runs the full INVARIANT B
machinery on the demoting node's live QWP connections (role-change
close deferred until the object store covers the connection's committed
seqTxns), the client rides every close out on store-and-forward
reconnect-replay, and no flap may strand data or wedge a reader.

Scenario:
  1. Node A boots primary, node B boots replica, shared object store.
  2. A HISTORICAL corpus (deterministic values on old timestamps,
     disjoint from anything the live sender writes) is ingested on A
     and replicated to B before any chaos starts.
  3. Two READER legs -- each its own egress Reader (own forked sidecar)
     configured with BOTH endpoints and held across every switch --
     loop three verified read shapes per iteration (see
     ``_HistoricalReader``). The reader pool's own failover walk across
     the flapping nodes IS the thing under test: transparent
     reconnect/re-submit is expected and welcome; a surfaced query
     error or a wrong result is a test failure.
  4. One oblivious durable-ack sender (``sf_dir`` +
     ``request_durable_ack=on``) streams uniquely-timestamped rows
     continuously from a writer thread that is never told about any
     role change.
  5. The operator leg bounces roles ``QDB_E2E_BOUNCE_ROUNDS`` times
     (default 3 = 6 role switches, ending with B primary) with
     randomized dwell and handover jitter: demote the current primary
     via the SQL trigger over a real pg-wire connection (``SWITCH ROLE
     TO REPLICA`` -- no node is ever restarted; every role change is an
     in-place hot switch), then promote the other node, retrying the
     designed clean ownership-fence refusal. The chaos schedule NEVER
     waits on the producer or the readers -- they find out about every
     move the hard way.

Oracles:
  * All new data survives -- the sender is shut down through nothing
    but its own ordinary lifecycle (CLOSE, bounded by
    ``close_flush_timeout_millis``); deliberately NO test-side drain or
    ack-wait: the producer stays 100% oblivious end to end. The final
    primary is then polled SERVER-SIDE until it holds EXACTLY the dense
    sequence [0..total) (dedup on unique per-row ts = combined
    no-loss/no-duplication oracle), and a CLIENT-SIDE readback over QWP
    egress must see the identical count and sum -- the loop closes
    client-to-client: written via the ingress client, survived the
    chaos, seen via the egress client.
  * Sender obliviousness -- the writer thread never observes any error
    across ALL flaps and makes fresh append progress once the LAST
    promote has settled.
  * Readers never fail -- neither reader records a single error across
    every switch window, and
  * Readers keep receiving correct data -- every iteration asserts
    exact corpus-level answers, and an END-OF-RUN progress gate proves
    both readers complete fresh successful reads after the last flap
    and after the producer's close.

In-process-JUnit -> forked-harness substitutions:
  * ``QuestDB.connect`` facade (borrowSender/borrowQuery pools) -> the
    Rust binding has no cluster facade; the port drives the ingress
    sidecar + two egress Reader sidecars configured with the same two
    endpoints (documented in the deferred-close port too).
  * The JUnit readers verify the multi-batch full scan ROW BY ROW
    (contiguous ids, exact ts per id). The egress sidecar's QUERY verb
    returns only the streamed row count, so the port pins the same
    content invariants through row-count predicates: full-scan row
    count (multi-batch streaming path), an exact count+sum aggregate,
    distinct/min/max density, and a zero-row ts-mismatch probe (any row
    whose ts does not match its value id yields a row and fails).
    Arrival ORDER of the streamed batches is the one property the
    row-count protocol cannot observe; it is pinned Java-side.
  * ``awaitOwnershipTokenParity`` -> promote-with-retry on the clean
    ER005 fence refusal (see ``qwp_sql_switch``).

Knobs: ``QDB_E2E_BOUNCE_ROUNDS`` (default 3),
``QDB_E2E_FUZZ_SEED`` (default time-derived; logged for replay).
"""

from __future__ import annotations

import logging
import os
import random
import threading
import time
from pathlib import Path

import psycopg
import pytest

from lib import lifecycle as lc
from lib.pg_query import count_rows, execute_ddl, wait_for_dense_sequence

from c_client_sidecar import (
    CClientRustEgressSidecar,
    CClientRustSidecar,
    build_qwp_egress_sidecar,
)
from tests.qwp_sql_switch import (
    ObliviousWriter,
    ha_connect_string,
    promote_with_retry_sql,
    submit_switch_sql,
    wait_count_at_least,
)

LOG = logging.getLogger(__name__)

_LIVE_TABLE = "qwp_bounce_live_c_client_rust"
_HIST_TABLE = "qwp_bounce_hist_c_client_rust"

# Historical corpus: deterministic values 1..N on timestamps far older
# than anything the live sender writes (the sidecar's live rows start at
# ts ~1970 epoch + seconds; the hist base sits in 2020 -- disjoint
# tables anyway, the corpora never mix).
_HIST_ROWS = 10_000
_HIST_SUM = _HIST_ROWS * (_HIST_ROWS + 1) // 2
_HIST_BASE_TS_MICROS = 1_600_000_000_000_000

_PRE_SWITCH_ROWS = 500
_POST_CHAOS_PROGRESS_ROWS = 300
_SETTLE_WAIT_S = 60.0
_CONVERGENCE_TIMEOUT_S = 120.0
_READER_PROGRESS_WAIT_S = 30.0
_READER_LOOP_PAUSE_S = 0.1


class _HistoricalReader:
    """A long-lived historical reader leg: ONE egress Reader (its own
    forked sidecar process) held across every role switch, looping
    verified reads and counting only fully-verified iterations. The
    underlying Reader is EXPECTED to fail over across the flapping nodes
    on its own -- transparent reconnect/re-submit is the machinery under
    test, never an error. What DOES fail the test: a surfaced query
    error, a failed connect, or a wrong result."""

    def __init__(self, name: str, binary: Path, log_dir: Path,
                 connect_string: str) -> None:
        self._name = name
        self._connect_string = connect_string
        self._sidecar = CClientRustEgressSidecar(
            log_dir=log_dir, classpath=None, name=name, binary_path=binary,
        )
        self._stop = threading.Event()
        self.iterations = 0
        self.error: BaseException | None = None
        self._thread = threading.Thread(target=self._run, name=name, daemon=True)

    def start(self) -> None:
        self._sidecar.start()
        self._sidecar.connect(self._connect_string)
        self._thread.start()

    def _run(self) -> None:
        try:
            while not self._stop.is_set():
                self._verified_read()
                self.iterations += 1
                time.sleep(_READER_LOOP_PAUSE_S)
        except BaseException as exc:  # noqa: BLE001 -- captured for the oracle
            self.error = exc

    def _verified_read(self) -> None:
        # 1. Exact corpus aggregate (count + sum in one predicate: a
        #    wrong sum with a right count is corruption the count alone
        #    would miss).
        agg_rows, _ = self._sidecar.query(
            f"SELECT 1 FROM (SELECT count() c, sum(v) s FROM \"{_HIST_TABLE}\") "
            f"WHERE c = {_HIST_ROWS} AND s = {_HIST_SUM}"
        )
        if agg_rows != 1:
            raise AssertionError(
                f"historical count+sum aggregate must be exact on every read "
                f"[{self._name}: predicate matched {agg_rows} rows]"
            )
        # 2. Multi-row FULL SCAN: streams the whole corpus through the
        #    multi-batch egress path (many RESULT_BATCH frames, unlike
        #    the single-row aggregate); a mid-stream failover must
        #    re-deliver the complete result.
        scan_rows, _ = self._sidecar.query(f'SELECT v FROM "{_HIST_TABLE}"')
        if scan_rows != _HIST_ROWS:
            raise AssertionError(
                f"historical full scan must deliver every row "
                f"[{self._name}: got {scan_rows}, expected {_HIST_ROWS}]"
            )
        # 3. Row-integrity probes (row-count substitutions for the JUnit
        #    row-by-row checks; see module docstring): density of the
        #    value domain, and every row's ts must match its value id.
        density_rows, _ = self._sidecar.query(
            f"SELECT 1 FROM (SELECT count_distinct(v) c, min(v) mn, max(v) mx "
            f"FROM \"{_HIST_TABLE}\") "
            f"WHERE c = {_HIST_ROWS} AND mn = 1 AND mx = {_HIST_ROWS}"
        )
        if density_rows != 1:
            raise AssertionError(
                f"historical value domain must stay dense [1..{_HIST_ROWS}] "
                f"[{self._name}: predicate matched {density_rows} rows]"
            )
        mismatch_rows, _ = self._sidecar.query(
            f"SELECT 1 FROM \"{_HIST_TABLE}\" "
            f"WHERE CAST(ts AS LONG) <> {_HIST_BASE_TS_MICROS} + v * 1000000"
        )
        if mismatch_rows != 0:
            raise AssertionError(
                f"historical rows' ts must match their value id "
                f"[{self._name}: {mismatch_rows} mismatching rows]"
            )

    def snapshot(self) -> int:
        return self.iterations

    def await_progress(self, snapshot: int, *, timeout_s: float) -> None:
        """Poll until the iteration counter advances past ``snapshot``,
        failing fast on a captured reader error. Every counted iteration
        is a fully-verified read, so advancement proves the reader is
        still receiving correct data, not merely alive. Invoked ONLY
        after the chaos is over."""
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if self.error is not None:
                raise AssertionError(
                    f"readers must not experience errors across role bounces "
                    f"-- {self._name} saw: {self.error!r}"
                ) from self.error
            if self.iterations > snapshot:
                return
            time.sleep(0.05)
        raise AssertionError(
            f"{self._name} made no verified read progress after the chaos "
            f"within {timeout_s}s [iterations={self.iterations}]"
        )

    def stop(self, *, join_timeout_s: float = 30.0) -> None:
        self._stop.set()
        self._thread.join(join_timeout_s)
        try:
            self._sidecar.stop()
        except Exception:  # noqa: BLE001 -- teardown best-effort
            LOG.exception("stopping %s sidecar failed", self._name)

    def assert_clean_exit(self) -> None:
        assert not self._thread.is_alive(), (
            f"{self._name} thread must have exited"
        )
        if self.error is not None:
            raise AssertionError(
                f"readers must not experience errors across role bounces -- "
                f"{self._name} saw: {self.error!r}"
            ) from self.error


def _query_one_row(pg_port: int, sql: str) -> tuple:
    with psycopg.connect(
        host="127.0.0.1", port=pg_port, user="admin", password="quest",
        dbname="qdb", connect_timeout=10, autocommit=True,
    ) as conn:
        with conn.cursor() as cur:
            cur.execute(sql)  # type: ignore[arg-type]
            row = cur.fetchone()
            assert row is not None, f"{sql!r} must return a row"
            return row


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_oblivious_durable_ack_sender_and_readers_survive_role_bouncing_c_client_rust(
    server_factory, c_client_rust_sidecar: CClientRustSidecar,
    c_client_rust_egress_sidecar: CClientRustEgressSidecar,
    scenario_dir: Path, log_dir: Path,
) -> None:
    rounds = int(os.environ.get("QDB_E2E_BOUNCE_ROUNDS", "3"))
    seed = int(os.environ.get("QDB_E2E_FUZZ_SEED", str(time.time_ns() & 0xFFFFFFFF)))
    rnd = random.Random(seed)
    LOG.info("role-bounce chaos: rounds=%d seed=%d (QDB_E2E_FUZZ_SEED to replay)",
             rounds, seed)

    sf_dir = scenario_dir / "sf"
    sf_dir.mkdir(parents=True, exist_ok=True)

    # ---- Boot A (primary) + B (replica), shared object store. ----
    a = server_factory("a", role="primary")
    b = server_factory("b", role="replica")
    a_ports = a.start(min_http=True)
    b_ports = b.start(min_http=True)
    assert a_ports.min_http is not None and b_ports.min_http is not None
    LOG.info("a_ports=%s b_ports=%s", a_ports, b_ports)

    # Live table: dedup on the unique per-row designated timestamp turns
    # the final dense-sequence oracle into a combined no-loss/
    # no-duplication pin (SF replay of a committed-but-unacked frame
    # after any flap collapses into the original row).
    execute_ddl(port=a_ports.pg, ddl=(
        f'CREATE TABLE "{_LIVE_TABLE}" (ts TIMESTAMP, v LONG) '
        "TIMESTAMP(ts) PARTITION BY DAY WAL DEDUP UPSERT KEYS(ts)"
    ))
    # Historical corpus: fully ingested and replicated BEFORE any chaos,
    # so every reader iteration has one exact expected answer.
    execute_ddl(port=a_ports.pg, ddl=(
        f'CREATE TABLE "{_HIST_TABLE}" (ts TIMESTAMP, v LONG) '
        "TIMESTAMP(ts) PARTITION BY DAY WAL"
    ))
    execute_ddl(port=a_ports.pg, ddl=(
        f'INSERT INTO "{_HIST_TABLE}" '
        f"SELECT ({_HIST_BASE_TS_MICROS} + x * 1000000)::timestamp, x "
        f"FROM long_sequence({_HIST_ROWS})"
    ))
    wait_count_at_least(a_ports.pg, _HIST_TABLE, _HIST_ROWS,
                        timeout_s=_SETTLE_WAIT_S)
    wait_count_at_least(b_ports.pg, _HIST_TABLE, _HIST_ROWS,
                        timeout_s=_CONVERGENCE_TIMEOUT_S)
    # Server-side pre-chaos gate on BOTH nodes (count + sum): a failure
    # here is a replication problem, not a reader-survival finding.
    for name, port in (("A", a_ports.pg), ("B", b_ports.pg)):
        cnt, total = _query_one_row(
            port, f'SELECT count(), sum(v) FROM "{_HIST_TABLE}"')
        assert (int(cnt), int(total)) == (_HIST_ROWS, _HIST_SUM), (
            f"node {name} pre-chaos historical corpus wrong: "
            f"count={cnt}, sum={total}"
        )
    LOG.info("historical corpus (%d rows) verified on both nodes", _HIST_ROWS)

    # ---- Reader legs: one egress Reader each, BOTH endpoints, held
    #      across every switch. ----
    egress_binary = build_qwp_egress_sidecar()
    reader_cs = (
        f"ws::addr=127.0.0.1:{a_ports.http},127.0.0.1:{b_ports.http};"
        "username=admin;password=quest;failover_max_duration_ms=30000;"
    )
    reader_1 = _HistoricalReader("qwp-hist-reader-1", egress_binary, log_dir, reader_cs)
    reader_2 = _HistoricalReader("qwp-hist-reader-2", egress_binary, log_dir, reader_cs)
    reader_1.start()
    reader_2.start()

    # ---- Oblivious durable-ack sender: BOTH endpoints, never
    #      reconfigured, never told about any role change. Producer
    #      surface: SEND + FLUSH + ordinary CLOSE -- none of the wait
    #      verbs are ever touched (an oblivious producer has no business
    #      synchronizing on acks). ----
    sidecar = c_client_rust_sidecar
    sidecar.connect(ha_connect_string(a_ports.http, b_ports.http, sf_dir,
                                      durable_ack=True))
    writer = ObliviousWriter(sidecar, _LIVE_TABLE)
    writer.start()

    final_primary = None  # (ports, server)
    final_replica = None
    total = 0
    try:
        try:
            # Seed corpus BEFORE any chaos: the wire path works and A is
            # committing, so the first demote lands on a connection with
            # genuinely in-flight durable work. After this there are NO
            # further waits on either client until the chaos is over.
            writer.await_appended(_PRE_SWITCH_ROWS)

            primary_ports, replica_ports = a_ports, b_ports
            primary_srv, replica_srv = a, b
            for round_no in range(1, rounds + 1):
                LOG.info("bounce round %d/%d [appended=%d, reads1=%d, reads2=%d]",
                         round_no, rounds, writer.appended,
                         reader_1.iterations, reader_2.iterations)
                # Random dwell: the sender commits against the current
                # primary for a random stretch so each demote lands on a
                # connection with in-flight durable work.
                time.sleep(rnd.uniform(0.05, 0.30))

                # Demote the current primary via the SQL trigger while
                # the client keeps writing.
                assert submit_switch_sql(primary_ports.pg, "replica"), (
                    f"round {round_no}: SWITCH ROLE TO REPLICA must be accepted"
                )
                lc.await_role(primary_ports.min_http, "replica",
                              timeout_s=_SETTLE_WAIT_S)

                # Random handover jitter: stretch the no-writable-node
                # window so the client's reconnect walk meets role
                # rejects for a random spell.
                time.sleep(rnd.uniform(0.0, 0.15))

                # Promote the other node, retrying the designed clean
                # ownership-fence refusal like a real orchestrator.
                promote_with_retry_sql(replica_ports.pg, replica_ports.min_http)

                # Deliberately NO waits on the producer or the readers
                # here -- the operator bounces on its own schedule.
                primary_ports, replica_ports = replica_ports, primary_ports
                primary_srv, replica_srv = replica_srv, primary_srv

            final_primary = (primary_ports, primary_srv)
            final_replica = (replica_ports, replica_srv)

            # END-OF-CHAOS progress gate -- the only post-seed wait on
            # the producer, strictly AFTER the last promote settled:
            # fresh appends prove the oblivious sender rode out every
            # flap on its own reconnect walk.
            writer.await_appended(writer.appended + _POST_CHAOS_PROGRESS_ROWS)
        finally:
            writer.stop()

        writer.assert_oblivious()
        total = writer.appended
        assert total > 0, "producer must have appended rows"

        # Ordinary close -- the ONLY remaining sender interaction
        # (deliberately no drain()/AWAIT_ACKED: the close's own bounded
        # flush ships the SF tail; everything below is server-side
        # observation, exactly the JUnit contract).
        sidecar.close()

        assert final_primary is not None and final_replica is not None
        fp_ports, _ = final_primary
        fr_ports, _ = final_replica

        # All new data survives, exactly once: the dense sequence
        # [0..total) on the final primary (count + values; supersedes
        # the JUnit count+sum pair; dedup collapses legitimate SF
        # replays, so above-count is a dedup regression and below-count
        # is loss).
        wait_for_dense_sequence(port=fp_ports.pg, table=_LIVE_TABLE,
                                expected_count=total,
                                timeout_s=_CONVERGENCE_TIMEOUT_S)

        # Onward convergence: the final replica reaches the identical
        # count -- upload/download still work after all the flapping.
        wait_count_at_least(fr_ports.pg, _LIVE_TABLE, total,
                            timeout_s=_CONVERGENCE_TIMEOUT_S)
        assert count_rows(port=fr_ports.pg, table=_LIVE_TABLE) == total, (
            "final replica must converge to the exact acked row count"
        )

        # CLIENT-SIDE readback oracle over QWP egress: the same client
        # library that wrote the rows must SEE them (count + exact-sum
        # predicate; both nodes hold exactly `total`, so the assertion
        # is exact whichever node serves it).
        expected_sum = total * (total - 1) // 2
        egress = c_client_rust_egress_sidecar
        egress.connect(reader_cs)
        live_rows, _ = egress.query(f'SELECT v FROM "{_LIVE_TABLE}"')
        assert live_rows == total, (
            f"client-side QWP query must see every appended row "
            f"[saw {live_rows}, expected {total}]"
        )
        live_sum_rows, _ = egress.query(
            f"SELECT 1 FROM (SELECT sum(v) s FROM \"{_LIVE_TABLE}\") "
            f"WHERE s = {expected_sum}"
        )
        assert live_sum_rows == 1, (
            f"client-side QWP query must see the exact appended id sum "
            f"{expected_sum}"
        )

        # END-OF-RUN reader gate -- the only wait on the readers in the
        # whole test, after every flap, the producer's close and the
        # convergence oracles: both readers must still complete fresh,
        # fully-verified reads.
        reader_1.await_progress(reader_1.snapshot(),
                                timeout_s=_READER_PROGRESS_WAIT_S)
        reader_2.await_progress(reader_2.snapshot(),
                                timeout_s=_READER_PROGRESS_WAIT_S)
    finally:
        reader_1.stop()
        reader_2.stop()

    reader_1.assert_clean_exit()
    reader_2.assert_clean_exit()
    LOG.info("role-bounce chaos survived: %d rounds, %d live rows exactly once, "
             "both readers verified throughout [seed=%d]", rounds, total, seed)
