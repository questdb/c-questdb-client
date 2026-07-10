"""
C and C++ binding duplicates of key ported e2e scenarios (the bindings
matrix of PORTING_JAVA_E2E.md).

The scenario logic lives in the shared Rust core; the C and C++ FFI
bindings inherit it. These tests pin that each *binding* actually drives
the paths correctly, mirroring the Rust originals:

  1. kill-9 at the commit boundary (zero-settle SIGKILL + SF recovery)
     -- from ``test_txn_kill9_atomicity.py``. NOTE: this is the agreed
     SUBSTITUTE for the checklist's ``kill9_mid_txn_uncommitted_rows``
     boxes: the multi-flush ``transaction=on`` mode those need is not
     implemented by the client (see the txn module docstring), so the
     commit-boundary scenario -- the one that WAS portable -- is
     duplicated instead.
  2. durable-ack sender survives a replica-only failover window
     -- from ``test_durable_ack_failover.py``.
  3. graceful in-place demotion underneath an actively-sending sender
     -- from ``test_demotion_mid_stream.py``.
  4. egress happy-path read with ``target=replica``
     -- the always-compiled reader C API
     (``include/questdb/egress/reader.h``) and the genuine C++ wrapper
     (``reader.hpp``) driven via ``qwp_egress_c_sidecar`` /
     ``qwp_egress_cpp_sidecar``.

FFI observability substitutions (same precedent as
``test_orphan_drainer_bindings.py``: confirm server-side what the C FFI
cannot report client-side):

  * The Rust originals gate promotion on ``STATS reconnAttempts`` (+2 =
    a completed all-replica reconnect round). The C FFI does not export
    the qwp_ws_totals counters (the C sidecars zero them), so these
    duplicates use the server's OWN witness instead: the replica logs
    ``"ingress upgrade rejected by role"`` (QwpIngressUpgradeProcessor's
    421 gate) once per rejected walk. Two occurrences on a node prove
    two distinct walks reached it -- i.e. at least one full round
    completed in between -- which is the same promote-too-early guard,
    anchored in direct server evidence rather than client counters.
  * The demotion scenario's Rust-side ``server_errors == 0`` wire pin
    (role change must surface as a NORMAL_CLOSURE, never a NACK) is
    DROPPED here: the C FFI zeroes that counter, so asserting it would
    be vacuously green. The pin lives in the Rust variant; these
    duplicates still catch a terminal misclassification (the window
    FLUSH would hard-fail) and still witness the read-only gate firing
    in the server log.

The bodies are shared across bindings; each binding gets its own
``@pytest.mark.c_client_<binding>`` so CI can run one binding
(``-m c_client_c``) or all (``-m c_client``).
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Callable

import pytest

from lib import lifecycle as lc
from lib.pg_query import (
    count_rows,
    execute_ddl,
    fetch_column_sorted,
    wait_for_count,
    wait_for_dense_sequence,
)
from lib.sidecar import Sidecar, SidecarError

from c_client_sidecar import CClientCppSidecar, CClientCSidecar

LOG = logging.getLogger(__name__)

_INGEST_BATCH = 10
_INGEST_BATCH_INTERVAL_S = 0.2
_DURABLE_ACK_AWAIT_TIMEOUT_MS = 60_000
_AWAIT_ROLE_TIMEOUT_S = 60.0
_POLL_INTERVAL_S = 0.25

# Server-side witness of a role-rejected QWP producer upgrade: logged by
# QwpIngressUpgradeProcessor when the 421 role gate refuses the walk.
_ROLE_REJECT_NEEDLE = "ingress upgrade rejected by role"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _wait_count(*, port: int, table: str, expected: int, timeout_s: float) -> None:
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


def _ingest_unaware(sidecar: Sidecar, table: str, *, count: int,
                    start_index: int) -> int:
    """SF-producer ingest, COMPLETELY UNAWARE of topology (see the Rust
    originals): SEND + FLUSH are local SF operations that must keep
    succeeding through any transient failover window; a hard failure IS
    the regression under test."""
    try:
        sidecar.send(table, count=count, start_index=start_index)
        return sidecar.flush()
    except SidecarError as e:
        raise AssertionError(
            f"store-and-forward producer hard-failed while ingesting rows "
            f"[{start_index}..{start_index + count}) -- a transient failover/"
            f"role-change window must be survived by keeping rows in SF and "
            f"retrying; only SF exhaustion may be terminal. sidecar error: {e!r}"
        )


def _ingest_range_unaware(sidecar: Sidecar, table: str, *, start_index: int,
                          total: int) -> int:
    end = start_index + total
    idx = start_index
    last_fsn = -1
    while idx < end:
        n = min(_INGEST_BATCH, end - idx)
        last_fsn = _ingest_unaware(sidecar, table, count=n, start_index=idx)
        idx += n
        time.sleep(_INGEST_BATCH_INTERVAL_S)
    return last_fsn


def _count_role_rejects(log_dir: Path, node: str) -> int:
    total = 0
    for suffix in ("stdout", "stderr"):
        f = log_dir / f"{node}.{suffix}.log"
        try:
            total += f.read_text(encoding="utf-8", errors="replace").count(
                _ROLE_REJECT_NEEDLE)
        except FileNotFoundError:
            continue
    return total


def _await_role_reject_witness(log_dir: Path, *, nodes: list[str],
                               min_per_node: int, timeout_s: float) -> None:
    """C/C++ substitute for the Rust originals' ``reconnAttempts`` barrier
    (the C FFI zeroes that counter). Blocks until every node in ``nodes``
    has logged >= ``min_per_node`` 421 role-rejected upgrade walks. Two
    occurrences on a node prove two distinct walks reached it, so at least
    one full reconnect round completed in between -- the same
    promote-too-early guard, witnessed server-side."""
    deadline = time.monotonic() + timeout_s
    counts: dict[str, int] = {}
    while time.monotonic() < deadline:
        counts = {n: _count_role_rejects(log_dir, n) for n in nodes}
        if all(c >= min_per_node for c in counts.values()):
            LOG.info("role-reject witness satisfied: %s", counts)
            return
        time.sleep(0.1)
    raise AssertionError(
        f"sender did not complete a full all-replica reconnect round: needed "
        f">= {min_per_node} '{_ROLE_REJECT_NEEDLE}' log line(s) on each of "
        f"{nodes}, saw {counts} within {timeout_s}s -- the all-replica "
        f"role-reject path was never provably exercised before promotion"
    )


# ---------------------------------------------------------------------------
# Scenario bodies
# ---------------------------------------------------------------------------

def _commit_boundary_body(sidecar: Sidecar, make_restart_sidecar: Callable[[], Sidecar],
                          server_factory, scenario_dir: Path, suffix: str) -> None:
    """(1) Zero-settle SIGKILL immediately after the commit FLUSH returns;
    a fresh sidecar on the same slot must recover every committed row
    exactly once (DEDUP collapses any replay). Same shape as
    ``test_kill9_at_commit_boundary_no_orphan_c_client_rust``; the slot
    naming (``<sf_dir>/<sender_id>``) is identical because the C FFI wraps
    the same single-sender Rust core (``line_sender_from_conf``)."""
    table = f"trades_txn_boundary_{suffix}"
    sf_dir = scenario_dir / "sf"
    sender_id = "txnedge"

    p1 = server_factory("p1")
    p1_ports = p1.start()
    execute_ddl(port=p1_ports.pg, ddl=(
        f'CREATE TABLE "{table}" ('
        "v LONG, timestamp TIMESTAMP"
        ") TIMESTAMP(timestamp) PARTITION BY DAY WAL "
        "DEDUP UPSERT KEYS(timestamp, v)"
    ))

    cs = ";".join([
        f"ws::addr=127.0.0.1:{p1_ports.http}",
        "username=admin",
        "password=quest",
        f"sf_dir={sf_dir}",
        f"sender_id={sender_id}",
        "request_durable_ack=on",
        "reconnect_max_duration_millis=60000",
        "close_flush_timeout_millis=5000",
    ]) + ";"
    sidecar.connect(cs)

    sidecar.send(table, count=40, start_index=0)
    committed_fsn = sidecar.flush()
    assert committed_fsn >= 0, f"commit flush published nothing (fsn={committed_fsn})"

    # ZERO settle: kill races the I/O loop right at the commit boundary.
    sidecar.kill_9()
    assert sidecar.process is not None
    assert sidecar.process.poll() is not None, "sidecar must be dead"

    # Guard against a vacuous pass: the slot must still hold .sfa segments.
    slot_dir = sf_dir / sender_id
    sfa_files = list(slot_dir.glob("sf-*.sfa")) if slot_dir.exists() else []
    assert sfa_files, (
        f"expected .sfa segments in {slot_dir} after SIGKILL; the restart "
        f"would not exercise recovery. dir contents: "
        f"{list(slot_dir.iterdir()) if slot_dir.exists() else '<missing>'}"
    )

    sidecar2 = make_restart_sidecar()
    sidecar2.start()
    try:
        sidecar2.connect(cs)
        wait_for_count(port=p1_ports.pg, table=table, expected=40, timeout_s=60.0)
        # And the recovered slot keeps working.
        sidecar2.send(table, count=10, start_index=200)
        sidecar2.flush()
        wait_for_count(port=p1_ports.pg, table=table, expected=50, timeout_s=60.0)
    finally:
        sidecar2.stop()

    values = fetch_column_sorted(port=p1_ports.pg, table=table, column="v")
    assert values == list(range(0, 40)) + list(range(200, 210)), (
        f"commit-boundary recovery lost or duplicated rows; full: {values}"
    )


def _replica_only_window_body(sidecar: Sidecar, server_factory,
                              scenario_dir: Path, log_dir: Path,
                              suffix: str) -> None:
    """(2) Durable-ack sender survives a replica-only failover window:
    kill -9 the primary, keep producing UNAWARE while only a replica is
    reachable, promote it, and require the full dense sequence durably
    acked. Same shape as the Rust original; the all-replica-round barrier
    is the server-side role-reject witness (see module docstring)."""
    table = f"durable_ack_failover_{suffix}"
    sf_dir = scenario_dir / "sf"
    sf_dir.mkdir(parents=True, exist_ok=True)
    initial_rows, window_rows, post_rows = 30, 40, 20

    a = server_factory("a", role="primary")
    b = server_factory("b", role="replica")
    a_ports = a.start(min_http=True)
    b_ports = b.start(min_http=True)
    assert b_ports.min_http is not None, (
        "node b (replica): min_http port not reported; needed to promote B later"
    )

    connect_str = (
        f"ws::addr=127.0.0.1:{a_ports.http},127.0.0.1:{b_ports.http}"
        ";username=admin;password=quest"
        f";sf_dir={sf_dir}"
        ";request_durable_ack=on"
        ";reconnect_max_duration_millis=300000"
        ";reconnect_initial_backoff_millis=100"
        ";reconnect_max_backoff_millis=1000"
        ";close_flush_timeout_millis=5000;"
    )
    sidecar.connect(connect_str)

    initial_fsn = _ingest_range_unaware(sidecar, table, start_index=0,
                                        total=initial_rows)
    assert sidecar.await_acked(initial_fsn, _DURABLE_ACK_AWAIT_TIMEOUT_MS), (
        f"initial batch was not durably acked by A [publishedFsn={initial_fsn}]"
    )
    wait_for_dense_sequence(port=a_ports.pg, table=table,
                            expected_count=initial_rows, timeout_s=60.0)
    _wait_count(port=b_ports.pg, table=table, expected=initial_rows, timeout_s=120.0)
    LOG.info("A durably holds %d rows; B converged via replication", initial_rows)

    reject_baseline = _count_role_rejects(log_dir, "b")
    a.kill_9()
    LOG.info("killed primary A; entering replica-only failover window")

    _ingest_range_unaware(sidecar, table, start_index=initial_rows,
                          total=window_rows)

    # Coverage barrier (C FFI substitute): B must have role-rejected two
    # NEW walks since the kill -> a full replica-only round completed.
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        if _count_role_rejects(log_dir, "b") >= reject_baseline + 2:
            break
        time.sleep(0.1)
    else:
        raise AssertionError(
            "sender did not complete a full replica-only reconnect round after "
            f"the primary was killed (needed >= 2 new '{_ROLE_REJECT_NEEDLE}' "
            "lines on b); the all-replica role-reject path was never exercised "
            "before promotion"
        )

    LOG.info("promoting B REPLICA -> PRIMARY via /lifecycle/switch")
    lc.submit_switch(b_ports.min_http, "primary", wait=True,
                     wait_timeout_s=_AWAIT_ROLE_TIMEOUT_S)

    final_fsn = _ingest_range_unaware(sidecar, table,
                                      start_index=initial_rows + window_rows,
                                      total=post_rows)
    assert sidecar.await_acked(final_fsn, _DURABLE_ACK_AWAIT_TIMEOUT_MS), (
        f"rows produced across the failover were lost: full published sequence "
        f"not durably acked by promoted B [publishedFsn={final_fsn}]"
    )
    total = initial_rows + window_rows + post_rows
    wait_for_dense_sequence(port=b_ports.pg, table=table,
                            expected_count=total, timeout_s=120.0)
    LOG.info("recovered: durable-ack sender drained across the failover; "
             "B holds [0..%d)", total)


def _demotion_mid_stream_body(sidecar: Sidecar, server_factory,
                              scenario_dir: Path, log_dir: Path,
                              suffix: str) -> None:
    """(3) In-place graceful A demotion underneath an actively-sending
    sender, then B promotion; dense [0..total) exactly once. Same shape as
    the Rust original with the two C-FFI substitutions documented in the
    module docstring. The read-only-gate log witness (binding-agnostic) is
    kept: it proves the mid-stream role-change close path was really
    exercised."""
    table = f"demotion_mid_stream_{suffix}"
    sf_dir = scenario_dir / "sf"
    sf_dir.mkdir(parents=True, exist_ok=True)
    initial_rows, window_rows, post_rows = 30, 40, 20

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

    connect_str = (
        f"ws::addr=127.0.0.1:{a_ports.http},127.0.0.1:{b_ports.http}"
        ";username=admin;password=quest"
        f";sf_dir={sf_dir}"
        ";request_durable_ack=on"
        ";reconnect_max_duration_millis=300000"
        ";reconnect_initial_backoff_millis=100"
        ";reconnect_max_backoff_millis=1000"
        ";close_flush_timeout_millis=5000;"
    )
    sidecar.connect(connect_str)

    initial_fsn = _ingest_range_unaware(sidecar, table, start_index=0,
                                        total=initial_rows)
    assert sidecar.await_acked(initial_fsn, _DURABLE_ACK_AWAIT_TIMEOUT_MS), (
        f"initial batch was not durably acked by A [publishedFsn={initial_fsn}]"
    )
    wait_for_dense_sequence(port=a_ports.pg, table=table,
                            expected_count=initial_rows, timeout_s=60.0)
    _wait_count(port=b_ports.pg, table=table, expected=initial_rows, timeout_s=120.0)
    LOG.info("A durably holds %d rows; B converged via replication", initial_rows)

    # ---- Demote A IN PLACE underneath the producing sender (wait=False:
    #      frames must be in flight WHILE the role flips). ----
    LOG.info("submitting A PRIMARY -> REPLICA demote underneath the producing sender")
    lc.submit_switch(a_ports.min_http, "replica", wait=False)

    _ingest_range_unaware(sidecar, table, start_index=initial_rows,
                          total=window_rows // 2)
    lc.await_role(a_ports.min_http, "replica", timeout_s=_AWAIT_ROLE_TIMEOUT_S)
    LOG.info("A settled as REPLICA; continuing ingest into the surviving wire")
    _ingest_range_unaware(sidecar, table,
                          start_index=initial_rows + window_rows // 2,
                          total=window_rows - window_rows // 2)

    # ---- Coverage barrier (C FFI substitute): the reconnect walk must have
    #      role-rejected on BOTH A (demoted) and B (not yet promoted) -- the
    #      full all-replica round the Rust original proves via counters. ----
    _await_role_reject_witness(log_dir, nodes=["a", "b"], min_per_node=2,
                               timeout_s=30.0)

    # ---- Coverage witness (binding-agnostic): the demoted node's read-only
    #      gate fired on a mid-stream frame -- the role-change close trigger.
    needles_found = False
    deadline = time.monotonic() + 15.0
    while time.monotonic() < deadline:
        for f in (log_dir / "a.stdout.log", log_dir / "a.stderr.log"):
            try:
                if "replica access is read-only" in f.read_text(
                        encoding="utf-8", errors="replace"):
                    needles_found = True
                    break
            except FileNotFoundError:
                continue
        if needles_found:
            break
        time.sleep(_POLL_INTERVAL_S)
    assert needles_found, (
        "no mid-stream read-only refusal found in a's logs within 15s -- the "
        "ingest frames never hit the demoted node's read-only gate, so the "
        "role-change close path this test exists to cover was not exercised"
    )

    LOG.info("promoting B REPLICA -> PRIMARY via /lifecycle/switch")
    lc.submit_switch(b_ports.min_http, "primary", wait=True,
                     wait_timeout_s=_AWAIT_ROLE_TIMEOUT_S)

    final_fsn = _ingest_range_unaware(sidecar, table,
                                      start_index=initial_rows + window_rows,
                                      total=post_rows)
    assert sidecar.await_acked(final_fsn, _DURABLE_ACK_AWAIT_TIMEOUT_MS), (
        f"rows produced across the in-place demote were lost: full published "
        f"sequence not durably acked by promoted B [publishedFsn={final_fsn}]. "
        f"The frame rejected by the role-change close must be replayed from SF."
    )
    total = initial_rows + window_rows + post_rows
    wait_for_dense_sequence(port=b_ports.pg, table=table,
                            expected_count=total, timeout_s=120.0)
    LOG.info("recovered: sender rode the mid-stream demote; B holds [0..%d) "
             "exactly once", total)


def _egress_target_replica_read_body(ingress_sidecar: Sidecar, egress_sidecar,
                                     server_factory, scenario_dir: Path,
                                     suffix: str) -> None:
    """(4) Egress happy-path read with ``target=replica``: with the PRIMARY
    listed FIRST in ``addr=``, the reader must skip it, bind the REPLICA
    (proved via SERVER_INFO role byte 2), and stream the replicated rows.
    The write side uses the same binding's ingress sidecar so the whole
    round-trip is per-binding."""
    table = f"egress_target_replica_{suffix}"
    sf_dir = scenario_dir / "sf"
    row_count = 25

    a = server_factory("a", role="primary")
    b = server_factory("b", role="replica")
    a_ports = a.start()
    b_ports = b.start()

    ingress_cs = (
        f"ws::addr=127.0.0.1:{a_ports.http}"
        ";username=admin;password=quest"
        f";sf_dir={sf_dir}"
        ";request_durable_ack=on"
        ";close_flush_timeout_millis=5000;"
    )
    ingress_sidecar.connect(ingress_cs)
    ingress_sidecar.send(table, count=row_count, start_index=0)
    fsn = ingress_sidecar.flush()
    assert ingress_sidecar.await_acked(fsn, _DURABLE_ACK_AWAIT_TIMEOUT_MS), (
        f"ingest batch was not durably acked by A [publishedFsn={fsn}]"
    )
    _wait_count(port=b_ports.pg, table=table, expected=row_count, timeout_s=120.0)
    LOG.info("B (replica) converged on %d rows; reading them back via egress",
             row_count)

    # PRIMARY first: binding the replica proves the target filter skipped A.
    egress_cs = (
        f"ws::addr=127.0.0.1:{a_ports.http},127.0.0.1:{b_ports.http}"
        ";username=admin;password=quest"
        ";target=replica"
        ";failover_max_duration_ms=15000"
        ";auth_timeout_ms=5000;"
    )
    egress_sidecar.connect(egress_cs)

    info = egress_sidecar.server_info()
    assert info.role == 2, (
        f"target=replica bound a node with role byte {info.role}, expected "
        f"REPLICA (2) -- the target filter did not skip the primary listed "
        f"first in addr="
    )

    rows, latency_ms = egress_sidecar.query(f'SELECT v FROM "{table}"')
    LOG.info("egress read %d rows in %.1fms from the bound replica", rows, latency_ms)
    assert rows == row_count, (
        f"egress read returned {rows} rows, expected {row_count} -- the bound "
        f"replica does not serve the replicated data"
    )


# ---------------------------------------------------------------------------
# C binding
# ---------------------------------------------------------------------------

@pytest.mark.c_client
@pytest.mark.c_client_c
def test_kill9_at_commit_boundary_no_orphan_c_client_c(
    c_client_c_sidecar, c_client_c_sidecar_binary: Path, server_factory,
    scenario_dir: Path, log_dir: Path,
) -> None:
    def make_restart() -> Sidecar:
        return CClientCSidecar(
            log_dir=log_dir, classpath=None,
            name="c-client-c-sidecar-boundary-restart",
            binary_path=c_client_c_sidecar_binary)
    _commit_boundary_body(c_client_c_sidecar, make_restart, server_factory,
                          scenario_dir, "c_client_c")


@pytest.mark.c_client
@pytest.mark.c_client_c
def test_durable_ack_sender_survives_replica_only_window_c_client_c(
    c_client_c_sidecar, server_factory, scenario_dir: Path, log_dir: Path,
) -> None:
    _replica_only_window_body(c_client_c_sidecar, server_factory,
                              scenario_dir, log_dir, "c_client_c")


@pytest.mark.c_client
@pytest.mark.c_client_c
def test_graceful_demotion_mid_stream_sender_survives_c_client_c(
    c_client_c_sidecar, server_factory, scenario_dir: Path, log_dir: Path,
) -> None:
    _demotion_mid_stream_body(c_client_c_sidecar, server_factory,
                              scenario_dir, log_dir, "c_client_c")


@pytest.mark.c_client
@pytest.mark.c_client_c
def test_egress_target_replica_read_c_client_c(
    c_client_c_sidecar, c_client_c_egress_sidecar, server_factory,
    scenario_dir: Path,
) -> None:
    _egress_target_replica_read_body(c_client_c_sidecar,
                                     c_client_c_egress_sidecar,
                                     server_factory, scenario_dir, "c_client_c")


# ---------------------------------------------------------------------------
# C++ binding
# ---------------------------------------------------------------------------

@pytest.mark.c_client
@pytest.mark.c_client_cpp
def test_kill9_at_commit_boundary_no_orphan_c_client_cpp(
    c_client_cpp_sidecar, c_client_cpp_sidecar_binary: Path, server_factory,
    scenario_dir: Path, log_dir: Path,
) -> None:
    def make_restart() -> Sidecar:
        return CClientCppSidecar(
            log_dir=log_dir, classpath=None,
            name="c-client-cpp-sidecar-boundary-restart",
            binary_path=c_client_cpp_sidecar_binary)
    _commit_boundary_body(c_client_cpp_sidecar, make_restart, server_factory,
                          scenario_dir, "c_client_cpp")


@pytest.mark.c_client
@pytest.mark.c_client_cpp
def test_durable_ack_sender_survives_replica_only_window_c_client_cpp(
    c_client_cpp_sidecar, server_factory, scenario_dir: Path, log_dir: Path,
) -> None:
    _replica_only_window_body(c_client_cpp_sidecar, server_factory,
                              scenario_dir, log_dir, "c_client_cpp")


@pytest.mark.c_client
@pytest.mark.c_client_cpp
def test_graceful_demotion_mid_stream_sender_survives_c_client_cpp(
    c_client_cpp_sidecar, server_factory, scenario_dir: Path, log_dir: Path,
) -> None:
    _demotion_mid_stream_body(c_client_cpp_sidecar, server_factory,
                              scenario_dir, log_dir, "c_client_cpp")


@pytest.mark.c_client
@pytest.mark.c_client_cpp
def test_egress_target_replica_read_c_client_cpp(
    c_client_cpp_sidecar, c_client_cpp_egress_sidecar, server_factory,
    scenario_dir: Path,
) -> None:
    _egress_target_replica_read_body(c_client_cpp_sidecar,
                                     c_client_cpp_egress_sidecar,
                                     server_factory, scenario_dir, "c_client_cpp")
