"""
Shared helpers for the SQL-triggered role-switch scenario ports
(``test_sql_failover_lossless.py``, ``test_role_bounce_chaos.py``).

These port the operator vehicle and client-side machinery of the
Enterprise JUnit witnesses ``SqlFailoverQwpClientLosslessTest`` /
``SqlFailoverQwpDeferredCloseExactlyOnceTest`` /
``QwpRoleBounceChaosLosslessTest``:

* ``submit_switch_sql``     -- the pg-wire ``SWITCH ROLE`` trigger, one
                               execution per submit (the vehicle those
                               tests pin; never the min-http API).
* ``promote_with_retry_sql``-- the designed clean-ownership-fence-refusal
                               retry loop (JUnit ``promoteWithRetry``;
                               also substitutes for the in-process
                               ``awaitOwnershipTokenParity``, which reads
                               server files a black-box harness must not
                               depend on).
* ``ObliviousWriter``       -- the background producer thread: appends
                               batches and publishes each to on-disk SF,
                               never told about any role change; owns the
                               ingress sidecar exclusively while running.

Not a test module (no ``test_`` prefix) -- pytest does not collect it.
"""

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path

import psycopg

from lib import lifecycle as lc
from lib.pg_query import count_rows
from lib.sidecar import Sidecar

LOG = logging.getLogger(__name__)

# Writer cadence (mirrors the JUnit writer: 50-row batches, brief pause).
BATCH_ROWS = 50
BATCH_INTERVAL_S = 0.02

PROGRESS_WAIT_S = 60.0
SWITCH_TIMEOUT_MS = 30_000
PROMOTE_ATTEMPT_SETTLE_S = 20.0
PROMOTE_RETRY_BUDGET_S = 90.0
_POLL_INTERVAL_S = 0.25


def submit_switch_sql(pg_port: int, target_role: str,
                      *, timeout_ms: int = SWITCH_TIMEOUT_MS) -> bool:
    """Submit ``SWITCH ROLE TO <role> TIMEOUT <ms>`` over a real pg-wire
    connection, exactly one execution (the JUnit tests pin the
    single-cursor-open vehicle -- a multi-pass assert battery would
    re-submit). Returns the ``accepted`` column. The accepted row
    returns immediately (async handoff); the cascade settles in the
    background -- callers poll min-http /lifecycle for settlement."""
    sql = f"SWITCH ROLE TO {target_role.upper()} TIMEOUT {timeout_ms}"
    with psycopg.connect(
        host="127.0.0.1", port=pg_port, user="admin", password="quest",
        dbname="qdb", connect_timeout=10, autocommit=True,
    ) as conn:
        with conn.cursor() as cur:
            cur.execute(sql)  # type: ignore[arg-type]
            row = cur.fetchone()
            assert row is not None, f"{sql!r} must return its accepted row"
            accepted = bool(row[0])
            assert cur.fetchone() is None, f"{sql!r} must return exactly one row"
            return accepted


def await_role_quiet(min_http_port: int, role: str, timeout_s: float) -> bool:
    """Like ``lc.await_role`` but returns False on timeout instead of
    raising -- the promote retry loop distinguishes "attempt failed,
    retry" from a hard assertion (JUnit ``waitForRoleQuiet``)."""
    try:
        lc.await_role(min_http_port, role, timeout_s=timeout_s)
        return True
    except TimeoutError:
        return False


def promote_with_retry_sql(pg_port: int, min_http_port: int) -> None:
    """Promote via the SQL trigger, retrying the designed clean
    ownership-fence refusal like a real failover orchestrator (JUnit
    ``promoteWithRetry``). A refused promote rolls back cleanly (the
    node stays a live replica whose ownership token keeps tracking the
    store), so resubmission genuinely recovers once the token catches
    up. Bounded overall by ``PROMOTE_RETRY_BUDGET_S``."""
    deadline = time.monotonic() + PROMOTE_RETRY_BUDGET_S
    attempts = 0
    while True:
        attempts += 1
        accepted = submit_switch_sql(pg_port, "primary")
        if accepted and await_role_quiet(min_http_port, "primary",
                                         PROMOTE_ATTEMPT_SETTLE_S):
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"node did not settle PRIMARY after {attempts} SQL promote "
                f"attempt(s) within {PROMOTE_RETRY_BUDGET_S}s "
                f"[last accepted={accepted}]"
            )
        # The failed attempt must have fully rolled back (no switch in
        # flight) before a re-submit; a concurrent submit would be
        # CAS-rejected by the orchestrator.
        rollback_deadline = time.monotonic() + PROMOTE_ATTEMPT_SETTLE_S
        while time.monotonic() < rollback_deadline:
            if not lc.lifecycle(min_http_port).get("switchInFlight"):
                break
            time.sleep(0.05)
        assert not lc.lifecycle(min_http_port).get("switchInFlight"), (
            "failed promote attempt must roll back cleanly (no switch in flight)"
        )
        # Give the rolled-back replica a beat to re-record the store's
        # latest sync id (JUnit does the same 500ms).
        time.sleep(0.5)


class ObliviousWriter:
    """Background producer mirroring the JUnit writer thread: appends
    ``BATCH_ROWS``-row batches and publishes each to on-disk SF via
    FLUSH, forever, never told about any role change. The sidecar is
    owned EXCLUSIVELY by this thread while it runs (one in-flight verb
    at a time on the stdin/stdout protocol); the orchestrating test only
    reads the plain-int progress counter (GIL-atomic) and touches the
    sidecar again only after ``stop()`` has joined the thread."""

    def __init__(self, sidecar: Sidecar, table: str) -> None:
        self._sidecar = sidecar
        self._table = table
        self._stop = threading.Event()
        self.appended = 0          # rows successfully published to SF
        self.last_fsn = -1         # highest published fsn
        self.error: BaseException | None = None
        self._thread = threading.Thread(target=self._run,
                                        name="qwp-oblivious-writer", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def _run(self) -> None:
        try:
            while not self._stop.is_set():
                self._sidecar.send(self._table, count=BATCH_ROWS,
                                   start_index=self.appended)
                # SF-mode flush publishes to on-disk store-and-forward and
                # returns; acks arrive asynchronously. It must never throw
                # across the move (Invariant B) -- an error here IS the
                # obliviousness regression.
                self.last_fsn = self._sidecar.flush()
                self.appended += BATCH_ROWS
                time.sleep(BATCH_INTERVAL_S)
        except BaseException as exc:  # noqa: BLE001 -- captured for the oracle
            self.error = exc

    def await_appended(self, target: int, *, timeout_s: float = PROGRESS_WAIT_S) -> None:
        """Poll until ``appended >= target``, failing fast on a captured
        writer error (JUnit ``awaitAppended``)."""
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if self.error is not None:
                raise AssertionError(
                    "the client must be oblivious to the role change -- "
                    f"writer saw: {self.error!r}"
                ) from self.error
            if self.appended >= target:
                return
            time.sleep(0.05)
        raise AssertionError(
            f"writer made no progress: appended={self.appended}, waiting for "
            f"{target} after {timeout_s}s"
        )

    def stop(self, *, join_timeout_s: float = 30.0) -> None:
        self._stop.set()
        self._thread.join(join_timeout_s)
        assert not self._thread.is_alive(), "writer thread must have exited"

    def assert_oblivious(self) -> None:
        if self.error is not None:
            raise AssertionError(
                "the client must be oblivious to the role change -- "
                f"writer saw: {self.error!r}"
            ) from self.error


def ha_connect_string(a_http: int, b_http: int, sf_dir: Path,
                      *, durable_ack: bool) -> str:
    """Both endpoints up front, never reconfigured; reconnect budget
    comfortably exceeding any demote+promote window so every all-replica
    interval is ridden out on backoff (mirrors the JUnit config)."""
    return (
        f"ws::addr=127.0.0.1:{a_http},127.0.0.1:{b_http}"
        ";username=admin;password=quest"
        f";sf_dir={sf_dir}"
        + (";request_durable_ack=on" if durable_ack else "")
        + ";reconnect_max_duration_millis=120000"
        ";reconnect_initial_backoff_millis=50"
        ";reconnect_max_backoff_millis=500"
        ";close_flush_timeout_millis=60000;"
    )


def count_or_zero(pg_port: int, table: str) -> int:
    """COUNT(*) that treats "table does not exist yet" as zero."""
    try:
        return count_rows(port=pg_port, table=table, timeout_s=2.0)
    except TimeoutError:
        return 0


def wait_count_at_least(pg_port: int, table: str, expected: int,
                        *, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    last = -1
    while time.monotonic() < deadline:
        last = count_or_zero(pg_port, table)
        if last >= expected:
            return
        time.sleep(_POLL_INTERVAL_S)
    raise AssertionError(
        f"row count on :{pg_port} reached {last}, expected >= {expected} "
        f"within {timeout_s}s"
    )
