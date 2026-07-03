"""
Graceful role-switch e2e coverage for c-questdb-client QWP-WS senders.

These tests target the Enterprise PR-1105 server contract:

* demoting a node closes QWP ingress with a reconnectable close instead of
  streaming read-only NACKs forever;
* store-and-forward producers do not see transient role state as user-visible
  write errors;
* rows published while the node is a settled replica remain buffered and drain
  after the node becomes primary again.

The same body runs against the Rust, C, and C++ row-major sidecars. The C and
C++ sidecars intentionally do not expose reconnect counters, so the assertions
use producer-visible OK/ERR behavior, pg-wire role evidence, server-side row
counts, durable ACK, and the final dense sequence oracle.
"""

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path

import psycopg
import pytest

from lib.lifecycle import lifecycle, submit_switch
from lib.pg_query import count_rows, fetch_column_sorted, wait_for_dense_sequence

LOG = logging.getLogger(__name__)

_INITIAL_ROWS = 40
_REPLICA_WINDOW_ROWS = 12
_DURABLE_ACK_AWAIT_TIMEOUT_MS = 60_000
_UNCOORDINATED_INITIAL_ROWS = 10
_UNCOORDINATED_REPLICA_OBSERVATION_S = 1.0


def _binding_cases():
    return [
        pytest.param(
            "c_client_rust_sidecar",
            "c_client_rust",
            marks=pytest.mark.c_client_rust,
            id="rust",
        ),
        pytest.param(
            "c_client_c_sidecar",
            "c_client_c",
            marks=pytest.mark.c_client_c,
            id="c",
        ),
        pytest.param(
            "c_client_cpp_sidecar",
            "c_client_cpp",
            marks=pytest.mark.c_client_cpp,
            id="cpp",
        ),
    ]


def _connect_string(http_port: int, sf_dir: Path, *, sender_id: str) -> str:
    return (
        f"ws::addr=127.0.0.1:{http_port}"
        ";username=admin;password=quest"
        f";sf_dir={sf_dir}"
        f";sender_id={sender_id}"
        ";request_durable_ack=on"
        ";reconnect_max_duration_millis=60000"
        ";close_flush_timeout_millis=5000;"
    )


def _await_role_tolerant(
    min_http_port: int,
    role: str,
    *,
    timeout_s: float = 60.0,
    poll_interval_s: float = 0.5,
    label: str = "",
) -> dict:
    target = role.upper()
    deadline = time.monotonic() + timeout_s
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            snap = lifecycle(min_http_port)
            if not snap.get("switchInFlight") and snap.get("currentRole") == target:
                LOG.info("%s: role %s settled", label, target)
                return snap
        except Exception as exc:
            last_error = exc
            LOG.debug("%s: lifecycle poll transient error: %s", label, exc)
        time.sleep(min(poll_interval_s, max(0.0, deadline - time.monotonic())))
    raise AssertionError(
        f"{label}: role {target} did not settle within {timeout_s:.0f}s "
        f"(last lifecycle error: {last_error!r})"
    )


def _submit_switch_tolerant(
    min_http_port: int,
    role: str,
    *,
    max_attempts: int = 5,
    retry_sleep_s: float = 1.0,
    label: str = "",
) -> None:
    for attempt in range(1, max_attempts + 1):
        try:
            submit_switch(min_http_port, role, wait=False)
            LOG.info("%s: submit_switch(%s) accepted on attempt %d", label, role, attempt)
            return
        except Exception as exc:
            LOG.debug("%s: submit_switch(%s) attempt %d failed: %s", label, role, attempt, exc)
            if attempt < max_attempts:
                time.sleep(retry_sleep_s)
    raise AssertionError(f"{label}: submit_switch({role}) failed after {max_attempts} attempts")


def _assert_write_rejected_pg(*, pg_port: int, table: str) -> None:
    """A settled replica must reject ordinary pg-wire writes cleanly."""
    try:
        with psycopg.connect(
            host="127.0.0.1",
            port=pg_port,
            user="admin",
            password="quest",
            dbname="qdb",
            connect_timeout=5,
            autocommit=True,
        ) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f'INSERT INTO "{table}" ("timestamp", v) VALUES (now(), 99999);'
                )
        raise AssertionError(
            f"pg-wire INSERT was accepted on settled REPLICA for {table}; "
            "expected a clean read-only rejection"
        )
    except (psycopg.OperationalError, psycopg.errors.ConnectionTimeout) as exc:
        raise AssertionError(
            f"pg-wire INSERT raised a connection error on settled REPLICA: {exc!r}; "
            "expected a clean read-only rejection"
        ) from exc
    except psycopg.DatabaseError as exc:
        msg = str(exc).lower()
        assert "read-only" in msg, (
            "pg-wire INSERT rejected on settled REPLICA, but the error was not "
            f"role-specific: {exc!r}"
        )
        LOG.info("pg-wire read-only rejection confirmed: %s", exc)


def _stable_row_count(
    *,
    pg_port: int,
    table: str,
    stable_window_s: float = 1.0,
    timeout_s: float = 20.0,
) -> int:
    deadline = time.monotonic() + timeout_s
    stable_since: float | None = None
    last = -1
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            current = count_rows(port=pg_port, table=table, timeout_s=3.0)
        except (TimeoutError, psycopg.DatabaseError) as exc:
            last_error = exc
            time.sleep(0.2)
            continue

        if current != last:
            last = current
            stable_since = time.monotonic()
        elif stable_since is not None and time.monotonic() - stable_since >= stable_window_s:
            return current
        time.sleep(0.2)

    raise AssertionError(
        f"row count for {table} did not become stable within {timeout_s:.0f}s "
        f"(last={last}, last_error={last_error!r})"
    )


def _assert_count_frozen(
    *,
    pg_port: int,
    table: str,
    expected: int,
    duration_s: float = 2.0,
) -> None:
    deadline = time.monotonic() + duration_s
    observations: list[int] = []
    while time.monotonic() < deadline:
        observed = count_rows(port=pg_port, table=table, timeout_s=3.0)
        observations.append(observed)
        assert observed == expected, (
            f"{table}: row count changed on settled REPLICA; expected {expected}, "
            f"observed {observed}. observations={observations}"
        )
        time.sleep(0.2)


def _wait_for_published_rows_above(
    *,
    get_published_rows,
    threshold: int,
    timeout_s: float,
    label: str,
) -> int:
    deadline = time.monotonic() + timeout_s
    last = get_published_rows()
    while time.monotonic() < deadline:
        last = get_published_rows()
        if last > threshold:
            return last
        time.sleep(0.05)
    raise AssertionError(
        f"{label}: background producer did not publish beyond {threshold} "
        f"within {timeout_s:.1f}s (last={last})"
    )


def _wait_for_no_extra_dense_sequence(
    *,
    pg_port: int,
    table: str,
    expected_count: int,
    timeout_s: float,
) -> list[int]:
    deadline = time.monotonic() + timeout_s
    expected = list(range(expected_count))
    observed: list[int] = []
    while time.monotonic() < deadline:
        try:
            observed = fetch_column_sorted(
                port=pg_port,
                table=table,
                timeout_s=3.0,
            )
        except TimeoutError:
            observed = []

        if observed == expected:
            return observed
        if len(observed) >= expected_count:
            break
        time.sleep(0.25)

    observed_set = set(observed)
    expected_set = set(expected)
    missing = sorted(expected_set - observed_set)[:10]
    extra = sorted(observed_set - expected_set)[:10]
    raise AssertionError(
        f"{table}.v: expected dense values [0..{expected_count}), "
        f"observed {len(observed)} rows; first missing={missing}; first extra={extra}"
    )


@pytest.mark.c_client
@pytest.mark.parametrize("sidecar_fixture,suffix", _binding_cases())
def test_qwp_store_and_forward_survives_graceful_role_switch(
    request: pytest.FixtureRequest,
    server_factory,
    scenario_dir: Path,
    sidecar_fixture: str,
    suffix: str,
) -> None:
    table = f"switch_test_{suffix}"
    sf_dir = scenario_dir / f"sf-{suffix}"
    sf_dir.mkdir(parents=True, exist_ok=True)
    sidecar = request.getfixturevalue(sidecar_fixture)

    p1 = server_factory("p1")
    p1_ports = p1.start(min_http=True)
    assert p1_ports.min_http is not None, "min_http port not reported"
    LOG.info("%s: server ready http=%d pg=%d min_http=%d",
             suffix, p1_ports.http, p1_ports.pg, p1_ports.min_http)

    initial_snap = lifecycle(p1_ports.min_http)
    assert initial_snap.get("currentRole") == "PRIMARY", (
        f"{suffix}: server did not start as PRIMARY: {initial_snap!r}"
    )
    assert not initial_snap.get("switchInFlight"), (
        f"{suffix}: switchInFlight=True before the test starts: {initial_snap!r}"
    )

    sidecar.connect(_connect_string(p1_ports.http, sf_dir, sender_id=suffix))

    sidecar.send(table, count=_INITIAL_ROWS, start_index=0)
    initial_fsn = sidecar.flush()
    assert initial_fsn >= 0, f"{suffix}: initial flush did not publish an FSN"
    assert sidecar.await_acked(initial_fsn, _DURABLE_ACK_AWAIT_TIMEOUT_MS), (
        f"{suffix}: initial frame fsn={initial_fsn} was not durably acked before demotion"
    )
    wait_for_dense_sequence(
        port=p1_ports.pg,
        table=table,
        expected_count=_INITIAL_ROWS,
        timeout_s=60.0,
    )

    stats_before = sidecar.stats()

    LOG.info("%s: demoting PRIMARY to REPLICA", suffix)
    _submit_switch_tolerant(p1_ports.min_http, "replica", label=suffix)
    replica_snap = _await_role_tolerant(p1_ports.min_http, "replica", label=suffix)
    assert replica_snap.get("currentRole") == "REPLICA"
    assert not replica_snap.get("switchInFlight")

    _assert_write_rejected_pg(pg_port=p1_ports.pg, table=table)

    replica_count = _stable_row_count(pg_port=p1_ports.pg, table=table)
    assert replica_count == _INITIAL_ROWS, (
        f"{suffix}: settled REPLICA count should contain only pre-switch rows; "
        f"expected {_INITIAL_ROWS}, observed {replica_count}"
    )

    LOG.info("%s: publishing rows while server is a settled REPLICA", suffix)
    sidecar.send(table, count=_REPLICA_WINDOW_ROWS, start_index=_INITIAL_ROWS)
    replica_fsn = sidecar.flush()
    assert replica_fsn > initial_fsn, (
        f"{suffix}: replica-window flush returned invalid fsn {replica_fsn} "
        f"(initial fsn {initial_fsn})"
    )

    _assert_count_frozen(
        pg_port=p1_ports.pg,
        table=table,
        expected=_INITIAL_ROWS,
        duration_s=2.0,
    )

    LOG.info("%s: promoting REPLICA back to PRIMARY", suffix)
    _submit_switch_tolerant(p1_ports.min_http, "primary", label=suffix)
    primary_snap = _await_role_tolerant(p1_ports.min_http, "primary", label=suffix)
    assert primary_snap.get("currentRole") == "PRIMARY"
    assert not primary_snap.get("switchInFlight")

    assert sidecar.await_acked(replica_fsn, _DURABLE_ACK_AWAIT_TIMEOUT_MS), (
        f"{suffix}: replica-window frame fsn={replica_fsn} was not durably acked "
        "after the node became PRIMARY again"
    )

    expected_total = _INITIAL_ROWS + _REPLICA_WINDOW_ROWS
    wait_for_dense_sequence(
        port=p1_ports.pg,
        table=table,
        expected_count=expected_total,
        timeout_s=90.0,
    )

    stats_after = sidecar.stats()
    LOG.info(
        "%s: PASS initial=%d buffered=%d final=%d acked=%d reconn_succ_delta=%d",
        suffix,
        _INITIAL_ROWS,
        _REPLICA_WINDOW_ROWS,
        expected_total,
        stats_after.acked,
        stats_after.reconn_succ - stats_before.reconn_succ,
    )


@pytest.mark.c_client
@pytest.mark.xfail(
    reason=(
        "future-state mid-stream role-switch invariant: current PR-1105 path "
        "can replay one duplicate row without STATUS_NOT_WRITABLE/idempotent "
        "NACK semantics"
    ),
    strict=True,
)
@pytest.mark.parametrize("sidecar_fixture,suffix", _binding_cases())
def test_qwp_store_and_forward_uncoordinated_role_switch(
    request: pytest.FixtureRequest,
    server_factory,
    scenario_dir: Path,
    sidecar_fixture: str,
    suffix: str,
) -> None:
    table = f"switch_uncoord_{suffix}"
    sf_dir = scenario_dir / f"sf-uncoord-{suffix}"
    sf_dir.mkdir(parents=True, exist_ok=True)
    sidecar = request.getfixturevalue(sidecar_fixture)
    label = f"{suffix}-uncoord"

    p1 = server_factory("p1")
    p1_ports = p1.start(min_http=True)
    assert p1_ports.min_http is not None, "min_http port not reported"

    initial_snap = lifecycle(p1_ports.min_http)
    assert initial_snap.get("currentRole") == "PRIMARY", (
        f"{label}: server did not start as PRIMARY: {initial_snap!r}"
    )
    assert not initial_snap.get("switchInFlight"), (
        f"{label}: switchInFlight=True before the test starts: {initial_snap!r}"
    )

    sidecar.connect(_connect_string(p1_ports.http, sf_dir, sender_id=label))
    sidecar.send(table, count=_UNCOORDINATED_INITIAL_ROWS, start_index=0)
    seed_fsn = sidecar.flush()
    assert seed_fsn >= 0, f"{label}: seed flush did not publish an FSN"
    assert sidecar.await_acked(seed_fsn, _DURABLE_ACK_AWAIT_TIMEOUT_MS), (
        f"{label}: seed frame fsn={seed_fsn} was not durably acked"
    )
    wait_for_dense_sequence(
        port=p1_ports.pg,
        table=table,
        expected_count=_UNCOORDINATED_INITIAL_ROWS,
        timeout_s=60.0,
    )

    state_lock = threading.Lock()
    stop_event = threading.Event()
    published_fsn = [seed_fsn]
    published_rows = [_UNCOORDINATED_INITIAL_ROWS]
    ingest_errors: list[str] = []

    def current_published_rows() -> int:
        with state_lock:
            return published_rows[0]

    def ingest_loop() -> None:
        while not stop_event.is_set():
            with state_lock:
                start = published_rows[0]
            try:
                sidecar.send(table, count=1, start_index=start)
                fsn = sidecar.flush()
                if fsn < 0:
                    raise AssertionError(f"flush returned invalid fsn {fsn}")
            except Exception as exc:
                ingest_errors.append(repr(exc))
                stop_event.set()
                return
            with state_lock:
                published_rows[0] = start + 1
                published_fsn[0] = fsn
            time.sleep(0.1)

    ingest_thread = threading.Thread(target=ingest_loop, name=f"{label}-ingest")
    ingest_thread.start()

    try:
        _wait_for_published_rows_above(
            get_published_rows=current_published_rows,
            threshold=_UNCOORDINATED_INITIAL_ROWS,
            timeout_s=10.0,
            label=label,
        )
        assert not ingest_errors, f"{label}: ingest failed before role switch: {ingest_errors}"

        rows_before_demote = current_published_rows()
        LOG.info("%s: demoting PRIMARY -> REPLICA while producer is active", label)
        _submit_switch_tolerant(p1_ports.min_http, "replica", label=label)
        replica_snap = _await_role_tolerant(p1_ports.min_http, "replica", label=label)
        assert replica_snap.get("currentRole") == "REPLICA"
        assert not replica_snap.get("switchInFlight")
        _wait_for_published_rows_above(
            get_published_rows=current_published_rows,
            threshold=rows_before_demote,
            timeout_s=10.0,
            label=label,
        )
        assert not ingest_errors, f"{label}: ingest failed during demotion: {ingest_errors}"

        _assert_write_rejected_pg(pg_port=p1_ports.pg, table=table)
        frozen = _stable_row_count(pg_port=p1_ports.pg, table=table)
        rows_before_frozen_window = current_published_rows()
        _assert_count_frozen(
            pg_port=p1_ports.pg,
            table=table,
            expected=frozen,
            duration_s=_UNCOORDINATED_REPLICA_OBSERVATION_S,
        )
        _wait_for_published_rows_above(
            get_published_rows=current_published_rows,
            threshold=rows_before_frozen_window,
            timeout_s=0.5,
            label=label,
        )
        assert not ingest_errors, f"{label}: ingest failed on settled REPLICA: {ingest_errors}"

        LOG.info("%s: promoting REPLICA -> PRIMARY while producer is active", label)
        rows_before_promote = current_published_rows()
        _submit_switch_tolerant(p1_ports.min_http, "primary", label=label)
        primary_snap = _await_role_tolerant(p1_ports.min_http, "primary", label=label)
        assert primary_snap.get("currentRole") == "PRIMARY"
        assert not primary_snap.get("switchInFlight")
        _wait_for_published_rows_above(
            get_published_rows=current_published_rows,
            threshold=rows_before_promote,
            timeout_s=10.0,
            label=label,
        )
    finally:
        stop_event.set()
        ingest_thread.join(timeout=70.0)

    assert not ingest_thread.is_alive(), f"{label}: ingest thread did not stop"
    assert not ingest_errors, f"{label}: ingest failed: {ingest_errors}"

    with state_lock:
        final_fsn = published_fsn[0]
        final_rows = published_rows[0]

    assert sidecar.await_acked(final_fsn, _DURABLE_ACK_AWAIT_TIMEOUT_MS), (
        f"{label}: final fsn={final_fsn} for {final_rows} rows was not durably acked"
    )
    _wait_for_no_extra_dense_sequence(
        pg_port=p1_ports.pg,
        table=table,
        expected_count=final_rows,
        timeout_s=30.0,
    )

    LOG.info(
        "%s: PASS initial=%d final=%d final_fsn=%d frozen=%d",
        label,
        _UNCOORDINATED_INITIAL_ROWS,
        final_rows,
        final_fsn,
        frozen,
    )
