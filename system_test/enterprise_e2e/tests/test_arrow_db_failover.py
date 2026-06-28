"""
Failover/resilience tests for the direct Arrow facade ``Db::flush_arrow_batch``.

These exercise the *application-facing* call::

    db.flush_arrow_batch("trades", &record_batch, None, &[], None)?;

driven through the column sidecar's ``arrow_db`` SEND shape (which calls
``Db::flush_arrow_batch`` directly), against a real QuestDB Enterprise primary
that moves underneath the client.

How ``flush_arrow_batch`` differs from the store-and-forward paths
-----------------------------------------------------------------
``Db::flush_arrow_batch`` borrows a **direct** (non-store-and-forward) column
sender, publishes the batch as a commit boundary, and blocks until the default
ack level. It owns **no SF replay queue**: on a primary move mid-publish it
returns ``FailoverRetry`` to the caller rather than replaying (the batch is
caller-owned, so retrying is a plain re-call). The documented contract is
therefore "re-call on FailoverRetry", which the column sidecar surfaces as an
``ERR`` and these tests honour via :func:`_flush_with_failover_retry` (a bare
re-FLUSH rebuilds the same batch from the still-buffered rows).

Consequences for the scenarios below:
  * There is no client-side SF, so the kill-9 + wipe + fresh-successor disaster
    used by the store-and-forward failover tests does not apply: a fresh-root
    successor would refuse to start against the existing object-store DataID,
    and there is no client copy to replay. Pre-move data is preserved
    *server-side* instead -- via same-database crash recovery (test 2) or a
    graceful in-place role switch (test 3).
  * The headline assertion is "the call does not permanently fail when the
    primary moves" -- i.e. with the documented re-call it reconnects to the
    current primary and the rows land, dense and gap-free.

Covers the three requested scenarios:
  1. stale primary -- the configured primary is already gone at the first send;
  2. primary failover mid-stream -- kill -9 then crash-restart the primary;
  3. in-place role switch -- a node flips primary<->replica with no process
     bounce via ``POST /lifecycle/switch {"role":..,"timeout_ms":..}``.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

import pytest

from lib.lifecycle import lifecycle, submit_switch
from lib.pg_query import wait_for_dense_sequence
from lib.server import wait_port_free
from lib.sidecar import SidecarError

from c_client_sidecar import CClientRustColumnSidecar

LOG = logging.getLogger(__name__)

_SRC = "arrow_db"  # column sidecar SEND shape that drives Db::flush_arrow_batch


def _connect_string(http_ports: list[int], *, request_durable_ack: bool = False,
                    reconnect_max_ms: int = 60_000,
                    close_flush_timeout_ms: int = 5_000) -> str:
    """Direct Arrow facade connect string (``qwpws`` schema).

    ``request_durable_ack`` defaults off: ``flush_arrow_batch`` then waits for
    the server ``Ok`` watermark (committed to the WAL) rather than the slower
    durable upload. That is sufficient here -- pre-move data is recovered from
    the same local WAL (crash-restart) or kept by a graceful switch, never from
    a client-side SF queue (the direct path has none).

    Accepts multiple ports so a failover-list ``addr=`` can be formed; the
    tests below use a single address.
    """
    addr = ",".join(f"127.0.0.1:{p}" for p in http_ports)
    parts = [
        f"qwpws::addr={addr}",
        "username=admin",
        "password=quest",
        f"reconnect_max_duration_millis={reconnect_max_ms}",
        f"close_flush_timeout_millis={close_flush_timeout_ms}",
        "pool_size=1",
        "pool_max=1",
    ]
    if request_durable_ack:
        parts.append("request_durable_ack=on")
    return ";".join(parts) + ";"


def _flush_with_failover_retry(sidecar: CClientRustColumnSidecar, *,
                               budget_s: float = 45.0) -> int:
    """Re-issue FLUSH until it succeeds or ``budget_s`` elapses; returns the
    number of attempts.

    ``Db::flush_arrow_batch`` surfaces ``FailoverRetry`` to the caller rather
    than replaying, so the documented contract across a primary move is to
    re-call. The column sidecar leaves the buffered rows in place on a failed
    FLUSH, so a bare re-FLUSH rebuilds and re-publishes the identical batch --
    no re-SEND needed.
    """
    deadline = time.monotonic() + budget_s
    last: Exception | None = None
    attempts = 0
    while time.monotonic() < deadline:
        attempts += 1
        try:
            sidecar.flush()
            return attempts
        except SidecarError as exc:
            last = exc
            LOG.info("flush_arrow_batch FailoverRetry, re-calling (attempt %d): %s",
                     attempts, exc)
            time.sleep(0.3)
    raise AssertionError(
        f"Db::flush_arrow_batch never succeeded within {budget_s}s after "
        f"{attempts} attempt(s); last error: {last}"
    )


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_arrow_db_flush_against_stale_primary_at_first_send_c_client_rust(
    server_factory,
    c_client_rust_column_sidecar: CClientRustColumnSidecar,
    obj_store,
    scenario_dir: Path,
) -> None:
    """Stale primary: the configured primary is already gone before the FIRST
    send. ``QuestDb::connect`` is lazy (opens a sender only on first borrow), so
    the first ``flush_arrow_batch`` is what binds a connection -- it must reach
    the live successor on the configured address rather than failing on the
    dead one."""
    table = "trades_arrow_db_stale_c_client_rust"
    row_count = 50

    p1 = server_factory("p1")
    p1_ports = p1.start()

    # Lazy connect -- no sender is opened against P1 yet.
    c_client_rust_column_sidecar.connect(_connect_string([p1_ports.http]))

    # The configured primary dies BEFORE any send. Nothing was ingested, so
    # wiping the object store (clearing P1's DataID claim) loses no data and
    # lets a fresh successor bind the same address.
    p1.kill_9()
    wait_port_free(p1_ports.http)
    wait_port_free(p1_ports.pg)
    obj_store.wipe()

    p2 = server_factory("p2", db_root_name="p2-fresh")
    p2.start(http_port=p1_ports.http, pg_port=p1_ports.pg)

    # First send + flush: the lazy open must bind the live successor.
    c_client_rust_column_sidecar.send(table, count=row_count, start_index=0, src=_SRC)
    attempts = _flush_with_failover_retry(c_client_rust_column_sidecar)
    LOG.info("first flush_arrow_batch against stale primary succeeded after %d attempt(s)",
             attempts)

    wait_for_dense_sequence(port=p1_ports.pg, table=table,
                            expected_count=row_count, timeout_s=60.0)


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_arrow_db_flush_survives_primary_failover_c_client_rust(
    server_factory,
    c_client_rust_column_sidecar: CClientRustColumnSidecar,
    obj_store,
    scenario_dir: Path,
) -> None:
    """Primary failover mid-stream: send a batch, kill -9 the primary, then
    crash-restart the SAME database (same db_root + object store) on the same
    port. The next ``flush_arrow_batch`` hits the dead pooled connection,
    surfaces FailoverRetry, and the documented re-call reconnects to the
    restarted primary. Both batches must be present, dense.

    A same-database restart (not a fresh-root successor) is the right model for
    the direct path: it has no client SF to replay, so pre-move rows are
    recovered from the server's own WAL rather than wiped-and-replayed."""
    table = "trades_arrow_db_failover_c_client_rust"

    p1 = server_factory("p1")
    p1_ports = p1.start()
    c_client_rust_column_sidecar.connect(_connect_string([p1_ports.http]))

    # Batch 1 -- the Ok ack means it is committed to P1's WAL on disk.
    c_client_rust_column_sidecar.send(table, count=25, start_index=0, src=_SRC)
    _flush_with_failover_retry(c_client_rust_column_sidecar)

    # The primary moves: kill -9, then bring the SAME database back on the same
    # port (crash recovery restores batch 1 from its WAL). No object-store wipe.
    p1.kill_9()
    wait_port_free(p1_ports.http)
    wait_port_free(p1_ports.pg)
    p1b = server_factory("p1b", db_root_name="p1")  # reuse p1's db_root
    p1b.start(http_port=p1_ports.http, pg_port=p1_ports.pg)

    # Batch 2 across the move: the first FLUSH sees the dead pooled connection
    # (FailoverRetry); the re-call reconnects to the restarted primary.
    c_client_rust_column_sidecar.send(table, count=25, start_index=25, src=_SRC)
    attempts = _flush_with_failover_retry(c_client_rust_column_sidecar)
    LOG.info("post-failover flush_arrow_batch succeeded after %d attempt(s)", attempts)

    wait_for_dense_sequence(port=p1_ports.pg, table=table,
                            expected_count=50, timeout_s=90.0)


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_arrow_db_flush_across_inplace_role_switch_c_client_rust(
    server_factory,
    c_client_rust_column_sidecar: CClientRustColumnSidecar,
    scenario_dir: Path,
) -> None:
    """In-place role switch with no process bounce: a node flips
    primary->replica->primary via ``POST /lifecycle/switch
    {"role":..,"timeout_ms":5000}``. ``flush_arrow_batch`` must be cleanly
    REJECTED while the node is a read-only replica (not hang), and resume once
    it is promoted back to primary -- with the pre-switch rows intact (a
    graceful switch destroys nothing; no object-store wipe)."""
    table = "trades_arrow_db_switch_c_client_rust"
    pre = 30

    p1 = server_factory("p1")
    p1_ports = p1.start(min_http=True)
    assert p1_ports.min_http is not None, "min_http port not reported"

    c_client_rust_column_sidecar.connect(_connect_string([p1_ports.http]))

    # Pre-switch ingest while PRIMARY.
    c_client_rust_column_sidecar.send(table, count=pre, start_index=0, src=_SRC)
    _flush_with_failover_retry(c_client_rust_column_sidecar)

    # Demote to replica IN PLACE (no bounce). timeout_ms mirrors the API example.
    submit_switch(p1_ports.min_http, "replica", timeout_ms=5000, wait=True,
                  wait_timeout_s=60.0)
    assert lifecycle(p1_ports.min_http).get("currentRole") == "REPLICA"

    # On the read-only replica, flush_arrow_batch must be rejected (raise), not
    # freeze. Probe with an out-of-band index; the buffered row is discarded by
    # the reconnect below so it never lands.
    c_client_rust_column_sidecar.send(table, count=1, start_index=999_000, src=_SRC)
    rejected = False
    for _ in range(5):
        try:
            c_client_rust_column_sidecar.flush()
        except SidecarError as exc:
            rejected = True
            LOG.info("flush_arrow_batch rejected on read-only replica (expected): %s", exc)
            break
        time.sleep(0.5)
    assert rejected, "flush_arrow_batch was NOT rejected on the read-only replica"

    # Drop the buffered probe row + reset the pool (CONNECT is lazy, so this
    # does not open a connection against the replica).
    c_client_rust_column_sidecar.connect(_connect_string([p1_ports.http]))

    # Promote back to primary IN PLACE.
    submit_switch(p1_ports.min_http, "primary", timeout_ms=5000, wait=True,
                  wait_timeout_s=60.0)
    assert lifecycle(p1_ports.min_http).get("currentRole") == "PRIMARY"

    # Resume ingest on the promoted node -- writes must be accepted again.
    c_client_rust_column_sidecar.send(table, count=pre, start_index=pre, src=_SRC)
    _flush_with_failover_retry(c_client_rust_column_sidecar)

    # Pre-switch rows + post-promote rows, dense and gap-free; the graceful
    # switch preserved the pre-switch data.
    wait_for_dense_sequence(port=p1_ports.pg, table=table,
                            expected_count=2 * pre, timeout_s=90.0)
