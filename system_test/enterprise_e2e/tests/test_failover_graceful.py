"""
Production-faithful two-node graceful failover round-trip, driven by the
c-questdb-client Rust sender.

Port of the Enterprise harness's ``test_failover_graceful.py``. The
server-orchestration (two forked ENT JVMs sharing an ``fs::`` object
store, the demote/promote /lifecycle/switch calls, the pg-wire / web-http
write-rejection probes) is identical; the only binding-specific part is
the ingress sender, which here is the Rust ``qwp_sidecar`` instead of the
Java one. The Rust sender uses ``username=`` (the canonical keyword);
``user=`` is a Java-only alias.

Two forked JVMs share an ``fs::`` object store. Node A boots as primary;
node B boots as a live downloading replica. The test drives a symmetric
demote-then-promote sequence:

  A (primary) --> A (replica)   [demote A via /lifecycle/switch]
  B (replica) --> B (primary)   [promote B via /lifecycle/switch]

Then ingests into the newly-promoted B (via the Rust sender) and asserts
that A (now a replica) downloads B's post-promote rows.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

import psycopg
import pytest

from lib import lifecycle as lc
from lib.pg_query import count_rows, wait_for_dense_sequence
from lib.shutdown import assert_clean_shutdown

from c_client_sidecar import CClientRustSidecar

LOG = logging.getLogger(__name__)

_TABLE = "graceful_failover_c_client_rust"
_POLL_INTERVAL_S = 0.3
_AWAIT_ROLE_TIMEOUT_S = 60.0
_DURABLE_ACK_AWAIT_TIMEOUT_MS = 60_000
_INITIAL_ROWS = 30
_ONWARD_ROWS = 20


def _connect_string(http_port: int, sf_dir: Path) -> str:
    return (
        f"ws::addr=127.0.0.1:{http_port}"
        ";username=admin;password=quest"
        f";sf_dir={sf_dir}"
        ";request_durable_ack=on"
        ";reconnect_max_duration_millis=60000"
        ";close_flush_timeout_millis=5000;"
    )


def _wait_replica_converges(*, pg_port: int, table: str, expected: int,
                            timeout_s: float = 90.0) -> None:
    """Block until the replica's pg-wire query shows the expected count.

    Uses count_rows (not dense-sequence) because the replica table is
    populated purely by WAL download from the primary, so a count match
    is sufficient here.
    """
    deadline = time.monotonic() + timeout_s
    last = -1
    while time.monotonic() < deadline:
        try:
            last = count_rows(port=pg_port, table=table, timeout_s=5.0)
        except TimeoutError:
            last = -1
        if last == expected:
            LOG.info("replica converged: count=%d == expected=%d", last, expected)
            return
        time.sleep(_POLL_INTERVAL_S)
    raise AssertionError(
        f"replica did not converge on {expected} rows in {table} within {timeout_s}s "
        f"(last observed: {last})"
    )


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_graceful_failover_round_trip_c_client_rust(
    server_factory,
    c_client_rust_sidecar: CClientRustSidecar,
    obj_store,
    scenario_dir: Path,
) -> None:
    """Symmetric A-primary -> A-replica + B-replica -> B-primary round-trip.

    Verifies:
      - A's initial rows (sent via the Rust sender) reach B before the demote.
      - A refuses writes after demotion (role-correct rejection).
      - A's existing pg-wire connection survives the demotion and delivers
        a clean write-rejection error, not a broken pipe or hang.
      - B accepts the Rust sender's writes after promotion.
      - A converges on B's post-promote rows (onward replication).
      - The object store is never wiped; a graceful switch loses nothing.
      - Both nodes shut down cleanly with no fd-race signatures.
    """
    sf_dir = scenario_dir / "sf"
    sf_dir.mkdir(parents=True, exist_ok=True)

    # ---- Boot A (primary) and B (replica), both with min-http enabled. ----
    a = server_factory("a", role="primary")
    b = server_factory("b", role="replica")
    a_ports = a.start(min_http=True)
    b_ports = b.start(min_http=True)

    assert a_ports.min_http is not None, (
        "node a (primary): min_http port not reported in READY line"
    )
    assert b_ports.min_http is not None, (
        "node b (replica): min_http port not reported in READY line"
    )
    LOG.info("a_ports=%s b_ports=%s", a_ports, b_ports)

    # ---- Ingest initial rows into A via the Rust QWP sender. ----
    c_client_rust_sidecar.connect(_connect_string(a_ports.http, sf_dir))
    c_client_rust_sidecar.send(_TABLE, count=_INITIAL_ROWS, start_index=0)
    initial_fsn = c_client_rust_sidecar.flush()
    assert c_client_rust_sidecar.await_acked(initial_fsn, _DURABLE_ACK_AWAIT_TIMEOUT_MS), (
        f"initial batch was not durably acked by A before demote [publishedFsn={initial_fsn}]"
    )
    LOG.info("initial %d rows sent to A, flushed, and durably acked", _INITIAL_ROWS)

    wait_for_dense_sequence(port=a_ports.pg, table=_TABLE,
                            expected_count=_INITIAL_ROWS, timeout_s=60.0)
    _wait_replica_converges(pg_port=b_ports.pg, table=_TABLE,
                            expected=_INITIAL_ROWS, timeout_s=120.0)
    LOG.info("B: caught up with A's initial %d rows", _INITIAL_ROWS)

    # ---- Open a pg-wire connection to A BEFORE the demotion (survivor). ----
    survivor_conn = psycopg.connect(
        host="127.0.0.1", port=a_ports.pg, user="admin", password="quest",
        dbname="qdb", connect_timeout=10, autocommit=True,
    )

    try:
        # ---- Demote A: primary -> replica. ----
        LOG.info("demoting A from PRIMARY to REPLICA via /lifecycle/switch")
        lc.submit_switch(a_ports.min_http, "replica", wait=True,
                         wait_timeout_s=_AWAIT_ROLE_TIMEOUT_S)
        snap_a = lc.lifecycle(a_ports.min_http)
        assert snap_a.get("currentRole") == "REPLICA", (
            f"A should be REPLICA after demotion, got {snap_a.get('currentRole')!r}"
        )

        # A refuses NEW writes, the pre-opened connection survives + rejects
        # cleanly, and the web-http /exec path rejects too.
        _assert_write_rejected_pg(pg_port=a_ports.pg, table=_TABLE)
        _assert_existing_conn_rejects_write(survivor_conn, table=_TABLE)
        _assert_write_rejected_http(http_port=a_ports.http, table=_TABLE)

        # ---- Promote B: replica -> primary. ----
        LOG.info("promoting B from REPLICA to PRIMARY via /lifecycle/switch")
        lc.submit_switch(b_ports.min_http, "primary", wait=True,
                         wait_timeout_s=_AWAIT_ROLE_TIMEOUT_S)
        snap_b = lc.lifecycle(b_ports.min_http)
        assert snap_b.get("currentRole") == "PRIMARY", (
            f"B should be PRIMARY after promotion, got {snap_b.get('currentRole')!r}"
        )

        # ---- Ingest onward rows into B (now the primary) via the Rust sender. ----
        c_client_rust_sidecar.close()
        sf_dir_b = scenario_dir / "sf_b"
        sf_dir_b.mkdir(parents=True, exist_ok=True)
        c_client_rust_sidecar.connect(_connect_string(b_ports.http, sf_dir_b))
        c_client_rust_sidecar.send(_TABLE, count=_ONWARD_ROWS, start_index=_INITIAL_ROWS)
        onward_fsn = c_client_rust_sidecar.flush()
        assert c_client_rust_sidecar.await_acked(onward_fsn, _DURABLE_ACK_AWAIT_TIMEOUT_MS), (
            f"onward batch was not durably acked by B before close [publishedFsn={onward_fsn}]"
        )

        total_expected = _INITIAL_ROWS + _ONWARD_ROWS
        wait_for_dense_sequence(port=b_ports.pg, table=_TABLE,
                                expected_count=total_expected, timeout_s=60.0)

        # ---- A converges on B's onward rows (B -> A onward replication). ----
        _wait_replica_converges(pg_port=a_ports.pg, table=_TABLE,
                                expected=total_expected, timeout_s=120.0)
        LOG.info("A (now replica): converged on B's %d total rows", total_expected)
    finally:
        survivor_conn.close()

    # ---- Shutdown both nodes and assert clean exit. ----
    c_client_rust_sidecar.close()
    b.stop()
    a.stop()
    assert_clean_shutdown(b)
    assert_clean_shutdown(a)


# ---------------------------------------------------------------------------
# Write-rejection helpers (identical to the Java harness; the rejection is a
# server-side property, binding-independent).
# ---------------------------------------------------------------------------


def _assert_write_rejected_pg(*, pg_port: int, table: str) -> None:
    LOG.info("write-rejection check: INSERT on A (demoted REPLICA) via pg-wire")
    try:
        with psycopg.connect(
            host="127.0.0.1", port=pg_port, user="admin", password="quest",
            dbname="qdb", connect_timeout=5, autocommit=True,
        ) as conn:
            with conn.cursor() as cur:
                cur.execute(f'INSERT INTO "{table}" (ts, v) VALUES (now(), 99999);')
        raise AssertionError(
            f"INSERT was accepted on demoted REPLICA (pg-wire port {pg_port}); "
            f"expected a clean 'replica access is read-only' rejection"
        )
    except psycopg.DatabaseError as exc:
        msg = str(exc).lower()
        assert "read-only" in msg, (
            f"INSERT raised DatabaseError but message did not contain 'read-only': {exc!r}"
        )
        LOG.info("write-rejection confirmed (pg-wire): %s", exc)


def _assert_existing_conn_rejects_write(conn: psycopg.Connection, *, table: str) -> None:
    LOG.info("connection-survival check: INSERT via pre-opened pg-wire connection")
    try:
        with conn.cursor() as cur:
            cur.execute(f'INSERT INTO "{table}" (ts, v) VALUES (now(), 88888);')
        raise AssertionError(
            "pre-opened connection accepted INSERT on demoted REPLICA; "
            "expected a clean 'replica access is read-only' rejection"
        )
    except psycopg.DatabaseError as exc:
        msg = str(exc).lower()
        assert "read-only" in msg, (
            f"pre-opened connection raised DatabaseError without 'read-only': {exc!r}"
        )
        LOG.info("connection survival confirmed: write cleanly rejected: %s", exc)


def _assert_write_rejected_http(*, http_port: int, table: str) -> None:
    import http.client
    import urllib.parse

    sql = f'INSERT INTO "{table}" (ts, v) VALUES (now(), 77777)'
    path = "/exec?query=" + urllib.parse.quote_plus(sql)
    LOG.info("write-rejection check: /exec INSERT on A (demoted REPLICA) via web-http")
    try:
        conn = http.client.HTTPConnection("127.0.0.1", http_port, timeout=5)
        try:
            conn.request("GET", path, headers={"Authorization": "Basic YWRtaW46cXVlc3Q="})
            resp = conn.getresponse()
            status = resp.status
            body = resp.read().decode("utf-8", errors="replace")
        finally:
            conn.close()
    except Exception as exc:
        raise AssertionError(
            f"web-http /exec INSERT raised a connection error on demoted REPLICA: {exc!r}; "
            f"expected a clean HTTP 403 'replica access is read-only'"
        ) from exc

    if 200 <= status < 300:
        raise AssertionError(
            f"web-http /exec INSERT was accepted (HTTP {status}) on demoted REPLICA; "
            f"expected HTTP 403 'replica access is read-only'. Body: {body!r}"
        )
    assert status == 403, (
        f"web-http /exec INSERT: expected HTTP 403 on demoted REPLICA, got HTTP {status}. "
        f"Body: {body!r}"
    )
    assert "read-only" in body.lower(), (
        f"HTTP 403 body did not contain 'read-only' on demoted REPLICA. Body: {body!r}"
    )
    LOG.info("write-rejection confirmed (web-http /exec): HTTP 403")
