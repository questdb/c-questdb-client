"""
c-questdb-client Rust binding failover tests against a real QuestDB
Enterprise primary.

These tests live in this repo (not in questdb-enterprise) because the
sender under test is the c-questdb-client Rust client; the Enterprise
side provides only the server-orchestration harness (fixtures imported
via the ``lib.shared_fixtures`` pytest plugin) plus the JVM build of the
Enterprise primary that the sender connects to.

Test naming follows the cross-repo scheme: ``..._c_client_<binding>``;
each test carries both ``@pytest.mark.c_client`` (umbrella) and
``@pytest.mark.c_client_<binding>`` so the dispatched Enterprise CI
can either run every binding's tests (``-m c_client``) or just one
(``-m c_client_rust``).
"""

from __future__ import annotations

import logging
import os
import shutil
import time
from pathlib import Path

import pytest

# server.wait_port_free and pg_query helpers come from the Enterprise
# harness on PYTHONPATH (set up by conftest.py).
from lib.pg_query import wait_for_dense_sequence
from lib.server import wait_port_free

from c_client_sidecar import CClientRustColumnSidecar, CClientRustSidecar

LOG = logging.getLogger(__name__)


def _connect_string(http_port: int, sf_dir: Path, *,
                    request_durable_ack: bool = True,
                    reconnect_max_ms: int = 60_000,
                    close_flush_timeout_ms: int = 5_000) -> str:
    parts = [
        f"ws::addr=127.0.0.1:{http_port}",
        # Canonical "username" keyword (both Java and Rust senders
        # accept it; "user" is a Java-only alias).
        "username=admin",
        "password=quest",
        f"sf_dir={sf_dir}",
        f"reconnect_max_duration_millis={reconnect_max_ms}",
        f"close_flush_timeout_millis={close_flush_timeout_ms}",
    ]
    if request_durable_ack:
        parts.append("request_durable_ack=on")
    return ";".join(parts) + ";"


def _connect_string_columnar(http_port: int, sf_dir: Path, *,
                             request_durable_ack: bool = True,
                             reconnect_max_ms: int = 60_000,
                             close_flush_timeout_ms: int = 5_000) -> str:
    """Column-major QWP/WebSocket connect string. Same store-and-forward
    knobs as :func:`_connect_string`, with the ``qwpws`` schema and the
    single-slot pool the column sender's store-and-forward path requires
    (``pool_size=1`` / ``pool_max=1``)."""
    parts = [
        f"qwpws::addr=127.0.0.1:{http_port}",
        "username=admin",
        "password=quest",
        f"sf_dir={sf_dir}",
        f"reconnect_max_duration_millis={reconnect_max_ms}",
        f"close_flush_timeout_millis={close_flush_timeout_ms}",
        "pool_size=1",
        "pool_max=1",
    ]
    if request_durable_ack:
        parts.append("request_durable_ack=on")
    return ";".join(parts) + ";"


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_kill9_primary_failover_no_data_loss_c_client_rust(
    server_factory,
    c_client_rust_sidecar: CClientRustSidecar,
    obj_store,
    scenario_dir: Path,
) -> None:
    """The headline failover scenario, driven by the c-questdb-client
    Rust binding's QWP/WebSocket sender. Kill -9 P1 mid-flight; verify
    P2 (started on the same port with a fresh DB root and a wiped
    object store) ends up with every row the sender appended.

    Body is inlined rather than shared with the Java equivalent
    (which lives in the Enterprise repo's test tree) because the two
    bindings will diverge over time -- assertions about counters,
    knobs, and corner cases differ. Cheap duplication beats a
    cross-repo helper for ~30 lines of test."""
    table = "trades_failover_c_client_rust"
    row_count = 50
    sf_dir = scenario_dir / "sf"

    p1 = server_factory("p1")
    p1_ports = p1.start()

    c_client_rust_sidecar.connect(_connect_string(p1_ports.http, sf_dir))
    c_client_rust_sidecar.send(table, count=row_count, start_index=0)
    c_client_rust_sidecar.flush()

    # Brief settle so P1 has a chance to OK at least the first batch.
    # The test passes either way -- under no-OK the sender's SF still
    # has the bytes; we just want to exercise the more interesting
    # OK-but-not-durable case more often than not.
    time.sleep(0.5)

    p1.kill_9()
    # Kernel needs a moment to release the listening socket, especially
    # on Linux where SO_REUSEADDR is honoured but TIME_WAIT can still
    # bite without it.
    wait_port_free(p1_ports.http)
    wait_port_free(p1_ports.pg)

    # Wipe both local disk AND object store -- worst-case disaster.
    # The only remaining copy is the sender's SF.
    if p1.db_root.exists():
        shutil.rmtree(p1.db_root)
    obj_store.wipe()

    p2 = server_factory("p2", db_root_name="p2-fresh")
    p2.start(http_port=p1_ports.http, pg_port=p1_ports.pg)

    # The sender reconnects on its own; we just have to wait for the
    # rows to land. pg-wire query, not sidecar stats, because the
    # primary's row count is the authoritative answer to "did anything
    # get lost." Sidecar stats can lag legitimately under the piggyback
    # durable-ack contract.
    wait_for_dense_sequence(port=p1_ports.pg, table=table,
                            expected_count=row_count, timeout_s=60.0)


@pytest.mark.c_client
@pytest.mark.c_client_rust
@pytest.mark.parametrize(
    "src",
    [
        "chunk",
        "arrow",
        pytest.param(
            "polars",
            marks=pytest.mark.skipif(
                not os.environ.get("C_QUESTDB_CLIENT_COLUMN_POLARS"),
                reason="set C_QUESTDB_CLIENT_COLUMN_POLARS to build the sidecar's polars feature",
            ),
        ),
    ],
)
def test_kill9_primary_failover_no_data_loss_c_client_rust_columnar(
    src: str,
    server_factory,
    c_client_rust_column_sidecar: CClientRustColumnSidecar,
    obj_store,
    scenario_dir: Path,
) -> None:
    """Failover scenario driven by the c-questdb-client Rust binding's
    column-major (``ColumnSender``) QWP/WebSocket path. Same body as the
    row-major test -- kill -9 P1, wipe disk + object store, bring P2 up on
    the same port -- but the sender ingests a column-major frame over a
    store-and-forward connection. Asserts P2 ends up with every row.

    ``src`` parametrizes the input shape: ``chunk`` (a borrowed-slice
    ``Chunk``) or ``arrow`` (an Arrow ``RecordBatch``); both encode to the
    same columnar wire. The schema (single LONG ``v`` + designated timestamp)
    matches the row-major test, so the same ``wait_for_dense_sequence`` oracle
    applies."""
    table = f"trades_failover_c_client_rust_columnar_{src}"
    row_count = 50
    sf_dir = scenario_dir / "sf"

    p1 = server_factory("p1")
    p1_ports = p1.start()

    c_client_rust_column_sidecar.connect(_connect_string_columnar(p1_ports.http, sf_dir))
    c_client_rust_column_sidecar.send(table, count=row_count, start_index=0, src=src)
    c_client_rust_column_sidecar.flush()

    # Brief settle so P1 has a chance to OK the batch before the kill.
    time.sleep(0.5)

    p1.kill_9()
    wait_port_free(p1_ports.http)
    wait_port_free(p1_ports.pg)

    # Worst-case disaster: the only surviving copy is the sender's SF.
    if p1.db_root.exists():
        shutil.rmtree(p1.db_root)
    obj_store.wipe()

    p2 = server_factory("p2", db_root_name="p2-fresh")
    p2.start(http_port=p1_ports.http, pg_port=p1_ports.pg)

    # The column sender's store-and-forward backend reconnects and replays
    # on its own; wait for every row to land on the successor.
    wait_for_dense_sequence(port=p1_ports.pg, table=table,
                            expected_count=row_count, timeout_s=60.0)
