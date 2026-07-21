"""
Failover/resilience tests for the direct DataFrame facade
``Db::flush_polars_dataframe``.

These exercise the application call::

    db.flush_polars_dataframe("trades", &df, &opts)?;

driven through the column sidecar's ``polars`` SEND shape (which calls
``Db::flush_polars_dataframe`` directly), against a real QuestDB Enterprise
primary that moves underneath the client.

How ``flush_polars_dataframe`` differs from ``flush_arrow_batch``
----------------------------------------------------------------
Both borrow a **direct** (non-store-and-forward) column sender, but they differ
in how they handle a primary move mid-publish:

  * ``flush_arrow_batch`` -- the batch is borrowed from the caller, so it
    **surfaces FailoverRetry** and the caller must re-call (see
    ``test_arrow_db_failover.py``, which uses an explicit retry loop).
  * ``flush_polars_dataframe`` -- it **owns the source DataFrame**, so it
    **re-drives automatically**: a single call reconnects and re-sends
    internally, returning ``Ok`` across the move with no caller retry.

The headline assertion here is therefore stronger than the arrow_db tests: a
**single** ``flush_polars_dataframe`` call must return ``Ok`` across a primary
move (no caller-side retry). If it ever raised on a transient failover, the
auto-redrive contract regressed.

Build gating
------------
The ``polars`` SEND shape requires the column sidecar's heavy ``polars`` cargo
feature, which is off by default. The module skips unless
``C_QUESTDB_CLIENT_COLUMN_POLARS`` is set (the e2e CI sets it so these run; the
``c_client_rust_column_sidecar`` fixture then builds the binary with the
feature).

As with the arrow_db tests, the direct path has no client SF, so pre-move data
is preserved server-side (same-database crash recovery / graceful switch),
never via a wipe-and-replay.
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path

import pytest

from lib.lifecycle import lifecycle, submit_switch
from lib.pg_query import wait_for_dense_sequence
from lib.server import wait_port_free
from lib.sidecar import SidecarError

from c_client_sidecar import CClientRustColumnSidecar

LOG = logging.getLogger(__name__)

_SRC = "polars"  # column sidecar SEND shape that drives Db::flush_polars_dataframe

# The polars SEND shape only exists when the sidecar is built with the heavy
# `polars` feature. Skip the whole module otherwise.
pytestmark = pytest.mark.skipif(
    not os.environ.get("C_QUESTDB_CLIENT_COLUMN_POLARS"),
    reason="set C_QUESTDB_CLIENT_COLUMN_POLARS to build the sidecar's polars feature",
)


def _connect_string(http_ports: list[int], *, request_durable_ack: bool = False,
                    reconnect_max_ms: int = 60_000,
                    close_flush_timeout_ms: int = 5_000) -> str:
    """Direct DataFrame facade connect string (``ws`` schema).

    ``request_durable_ack`` defaults off: ``flush_polars_dataframe`` then waits
    for the server ``Ok`` watermark (committed to the WAL) rather than the
    slower durable upload -- sufficient here, as pre-move data is recovered from
    the same local WAL (crash-restart) or kept by a graceful switch.
    """
    addr = ",".join(f"127.0.0.1:{p}" for p in http_ports)
    parts = [
        f"ws::addr={addr}",
        "username=admin",
        "password=quest",
        f"reconnect_max_duration_millis={reconnect_max_ms}",
        f"close_flush_timeout_millis={close_flush_timeout_ms}",
        "sender_pool_min=1",
        "sender_pool_max=1",
    ]
    if request_durable_ack:
        parts.append("request_durable_ack=on")
    return ";".join(parts) + ";"


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_polars_db_flush_against_stale_primary_at_first_send_c_client_rust(
    server_factory,
    c_client_rust_column_sidecar: CClientRustColumnSidecar,
    obj_store,
    scenario_dir: Path,
) -> None:
    """Stale primary: the configured primary is already gone before the FIRST
    send. ``QuestDb::connect`` is lazy, so the first ``flush_polars_dataframe``
    binds a connection -- a single call must reach the live successor (the
    DataFrame path re-drives internally)."""
    table = "trades_polars_db_stale_c_client_rust"
    row_count = 50

    p1 = server_factory("p1")
    p1_ports = p1.start()

    c_client_rust_column_sidecar.connect(_connect_string([p1_ports.http]))

    # The configured primary dies BEFORE any send. Nothing was ingested, so the
    # object-store wipe (clearing P1's DataID claim) loses no data and lets a
    # fresh successor bind the same address.
    p1.kill_9()
    wait_port_free(p1_ports.http)
    wait_port_free(p1_ports.pg)
    obj_store.wipe()

    p2 = server_factory("p2", db_root_name="p2-fresh")
    p2.start(http_port=p1_ports.http, pg_port=p1_ports.pg)

    # Single flush -- the auto-redrive binds the live successor on the first try.
    c_client_rust_column_sidecar.send(table, count=row_count, start_index=0, src=_SRC)
    c_client_rust_column_sidecar.flush()

    wait_for_dense_sequence(port=p1_ports.pg, table=table,
                            expected_count=row_count, timeout_s=60.0)


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_polars_db_flush_survives_primary_failover_c_client_rust(
    server_factory,
    c_client_rust_column_sidecar: CClientRustColumnSidecar,
    obj_store,
    scenario_dir: Path,
) -> None:
    """Primary failover mid-stream: send a batch, kill -9 the primary, then
    crash-restart the SAME database on the same port. The next
    ``flush_polars_dataframe`` hits the dead pooled connection and **re-drives
    automatically** -- a single call (no caller retry) must reconnect to the
    restarted primary and land. Both batches present, dense.

    This is the key contrast with ``test_arrow_db_failover.py``: there the
    equivalent flush needs an explicit re-call; here one call suffices."""
    table = "trades_polars_db_failover_c_client_rust"

    p1 = server_factory("p1")
    p1_ports = p1.start()
    c_client_rust_column_sidecar.connect(_connect_string([p1_ports.http]))

    # Batch 1 -- the Ok ack means it is committed to P1's WAL on disk.
    c_client_rust_column_sidecar.send(table, count=25, start_index=0, src=_SRC)
    c_client_rust_column_sidecar.flush()

    # The primary moves: kill -9, then bring the SAME database back on the same
    # port (crash recovery restores batch 1 from its WAL). No object-store wipe.
    p1.kill_9()
    wait_port_free(p1_ports.http)
    wait_port_free(p1_ports.pg)
    p1b = server_factory("p1b", db_root_name="p1")  # reuse p1's db_root
    p1b.start(http_port=p1_ports.http, pg_port=p1_ports.pg)

    # Batch 2 across the move: a SINGLE flush. flush_polars_dataframe's
    # auto-redrive must reconnect to the restarted primary internally and
    # return Ok -- no caller retry. (If this raised, the auto-redrive contract
    # regressed and the test fails loudly here.)
    c_client_rust_column_sidecar.send(table, count=25, start_index=25, src=_SRC)
    c_client_rust_column_sidecar.flush()

    wait_for_dense_sequence(port=p1_ports.pg, table=table,
                            expected_count=50, timeout_s=90.0)


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_polars_db_flush_across_inplace_role_switch_c_client_rust(
    server_factory,
    c_client_rust_column_sidecar: CClientRustColumnSidecar,
    scenario_dir: Path,
) -> None:
    """In-place role switch with no process bounce: a node flips
    primary->replica->primary via ``POST /lifecycle/switch
    {"role":..,"timeout_ms":5000}``. ``flush_polars_dataframe`` must be REJECTED
    while the node is a read-only replica (the role reject is sticky, not a
    transient failover, so auto-redrive gives up within the reconnect budget and
    surfaces an error), and resume once promoted back -- with the pre-switch
    rows intact (graceful switch destroys nothing; no wipe)."""
    table = "trades_polars_db_switch_c_client_rust"
    pre = 30

    p1 = server_factory("p1")
    p1_ports = p1.start(min_http=True)
    assert p1_ports.min_http is not None, "min_http port not reported"

    # Short reconnect budget so the replica-window flush gives up quickly
    # instead of auto-redriving for the full default budget.
    cs = _connect_string([p1_ports.http], reconnect_max_ms=8_000)
    c_client_rust_column_sidecar.connect(cs)

    # Pre-switch ingest while PRIMARY.
    c_client_rust_column_sidecar.send(table, count=pre, start_index=0, src=_SRC)
    c_client_rust_column_sidecar.flush()

    # Demote to replica IN PLACE (no bounce).
    submit_switch(p1_ports.min_http, "replica", timeout_ms=5000, wait=True,
                  wait_timeout_s=60.0)
    assert lifecycle(p1_ports.min_http).get("currentRole") == "REPLICA"

    # On the read-only replica, flush must be rejected (raise) within the
    # reconnect budget, not silently accepted. Probe with an out-of-band index;
    # the buffered row is discarded by the reconnect below so it never lands.
    c_client_rust_column_sidecar.send(table, count=1, start_index=999_000, src=_SRC)
    rejected = False
    try:
        c_client_rust_column_sidecar.flush()
    except SidecarError as exc:
        rejected = True
        LOG.info("flush_polars_dataframe rejected on read-only replica (expected): %s", exc)
    assert rejected, "flush_polars_dataframe was NOT rejected on the read-only replica"

    # Drop the buffered probe row + reset the pool (CONNECT is lazy).
    c_client_rust_column_sidecar.connect(cs)

    # Promote back to primary IN PLACE.
    submit_switch(p1_ports.min_http, "primary", timeout_ms=5000, wait=True,
                  wait_timeout_s=60.0)
    assert lifecycle(p1_ports.min_http).get("currentRole") == "PRIMARY"

    # Resume ingest on the promoted node -- writes accepted again.
    c_client_rust_column_sidecar.send(table, count=pre, start_index=pre, src=_SRC)
    c_client_rust_column_sidecar.flush()

    wait_for_dense_sequence(port=p1_ports.pg, table=table,
                            expected_count=2 * pre, timeout_s=90.0)
