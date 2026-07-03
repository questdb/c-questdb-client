"""
Randomized graceful role-switch fuzz for c-questdb-client QWP-WS senders.

This deliberately keeps the ingest client unaware of role changes: a background
thread continuously issues SEND + FLUSH while the main thread performs P->R->P
switches through the Enterprise lifecycle API. At every settled REPLICA apex,
pg-wire must reject writes and server-side row count must remain frozen even
though the sidecar keeps publishing rows into store-and-forward.

The test is marked ``fuzz`` plus a binding-specific marker, but not
``c_client``. That keeps the normal deterministic c-client CI lane focused,
matching the existing kill-9 fuzz cadence.
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

from lib.lifecycle import lifecycle, submit_switch
from lib.pg_query import count_rows, execute_ddl, wait_for_dense_sequence

LOG = logging.getLogger(__name__)

_SEED_ROWS = 5
_DURABLE_ACK_AWAIT_TIMEOUT_MS = 60_000
_REPLICA_OBSERVATION_S = 1.0


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
        ";close_flush_timeout_millis=5000"
        ";max_in_flight=1024"
        ";sf_max_total_bytes=67108864"
        ";sf_append_deadline_millis=30000;"
    )


def _seed_for_iteration(base: int, i: int) -> int:
    return (base * 0x9E3779B97F4A7C15 + i) & 0xFFFFFFFFFFFFFFFF


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


def _assert_write_rejected_pg(*, pg_port: int, table: str, step: int) -> None:
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
            f"step {step}: pg-wire INSERT was accepted on settled REPLICA for {table}"
        )
    except (psycopg.OperationalError, psycopg.errors.ConnectionTimeout) as exc:
        raise AssertionError(
            f"step {step}: pg-wire INSERT raised a connection error on settled REPLICA: "
            f"{exc!r}"
        ) from exc
    except psycopg.DatabaseError as exc:
        msg = str(exc).lower()
        assert "read-only" in msg, (
            f"step {step}: pg-wire INSERT rejected without read-only evidence: {exc!r}"
        )


def _stable_row_count(
    *,
    pg_port: int,
    table: str,
    stable_window_s: float = 0.8,
    timeout_s: float = 15.0,
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
        f"{table}: count did not stabilize within {timeout_s:.0f}s "
        f"(last={last}, last_error={last_error!r})"
    )


def _assert_count_frozen(
    *,
    pg_port: int,
    table: str,
    expected: int,
    duration_s: float,
    step: int,
) -> None:
    deadline = time.monotonic() + duration_s
    observations: list[int] = []
    while time.monotonic() < deadline:
        observed = count_rows(port=pg_port, table=table, timeout_s=3.0)
        observations.append(observed)
        assert observed == expected, (
            f"step {step}: {table} count changed on settled REPLICA while ingest "
            f"continued; expected {expected}, observed {observed}. "
            f"observations={observations}"
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


@pytest.mark.fuzz
@pytest.mark.parametrize(
    "iteration",
    range(int(os.environ.get("QDB_E2E_SWITCH_FUZZ_ITERS", "3"))),
)
@pytest.mark.parametrize("sidecar_fixture,suffix", _binding_cases())
def test_qwp_role_switch_fuzz_uncoordinated_client(
    request: pytest.FixtureRequest,
    iteration: int,
    server_factory,
    scenario_dir: Path,
    sidecar_fixture: str,
    suffix: str,
) -> None:
    base_seed = int(os.environ.get("QDB_E2E_FUZZ_SEED", str(time.time_ns() & 0xFFFFFFFF)))
    seed = _seed_for_iteration(base_seed, iteration)
    rng = random.Random(seed)
    table = f"switch_fuzz_{suffix}_{iteration}"
    sf_dir = scenario_dir / f"sf-{suffix}-{iteration}"
    sf_dir.mkdir(parents=True, exist_ok=True)
    label = f"{suffix}[{iteration}]"
    sidecar = request.getfixturevalue(sidecar_fixture)

    LOG.info("%s: fuzz seed=%d base_seed=%d", label, seed, base_seed)

    p1 = server_factory("p1")
    p1_ports = p1.start(min_http=True)
    assert p1_ports.min_http is not None, "min_http port not reported"
    execute_ddl(port=p1_ports.pg, ddl=(
        f'CREATE TABLE "{table}" ('
        "v LONG, timestamp TIMESTAMP"
        ") TIMESTAMP(timestamp) PARTITION BY DAY WAL "
        "DEDUP UPSERT KEYS(timestamp, v)"
    ))

    sidecar.connect(_connect_string(p1_ports.http, sf_dir, sender_id=f"{suffix}_{iteration}"))
    sidecar.send(table, count=_SEED_ROWS, start_index=0)
    seed_fsn = sidecar.flush()
    assert seed_fsn >= 0, f"{label}: seed flush did not publish an FSN"
    assert sidecar.await_acked(seed_fsn, _DURABLE_ACK_AWAIT_TIMEOUT_MS), (
        f"{label}: seed fsn={seed_fsn} was not durably acked"
    )
    wait_for_dense_sequence(
        port=p1_ports.pg,
        table=table,
        expected_count=_SEED_ROWS,
        timeout_s=60.0,
    )

    state_lock = threading.Lock()
    stop_event = threading.Event()
    published_fsn = [seed_fsn]
    published_rows = [_SEED_ROWS]
    ingest_errors: list[str] = []

    def current_published_rows() -> int:
        with state_lock:
            return published_rows[0]

    def ingest_loop() -> None:
        local_rng = random.Random(seed ^ 0xA5A5A5A5A5A5A5A5)
        while not stop_event.is_set():
            batch = 1
            with state_lock:
                start = published_rows[0]
            try:
                sidecar.send(table, count=batch, start_index=start)
                fsn = sidecar.flush()
                if fsn < 0:
                    raise AssertionError(f"flush returned invalid fsn {fsn}")
            except Exception as exc:
                ingest_errors.append(repr(exc))
                stop_event.set()
                return
            with state_lock:
                published_rows[0] = start + batch
                published_fsn[0] = fsn
            time.sleep(local_rng.uniform(0.1, 0.2))

    ingest_thread = threading.Thread(target=ingest_loop, name=f"{label}-ingest")
    ingest_thread.start()
    _wait_for_published_rows_above(
        get_published_rows=current_published_rows,
        threshold=_SEED_ROWS,
        timeout_s=10.0,
        label=label,
    )

    roundtrips = rng.randint(1, 3)
    try:
        for step in range(roundtrips):
            assert not ingest_errors, f"{label}: ingest failed before step {step}: {ingest_errors}"

            rows_before_demote = current_published_rows()
            LOG.info("%s: step %d demote PRIMARY -> REPLICA", label, step)
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

            _assert_write_rejected_pg(pg_port=p1_ports.pg, table=table, step=step)
            frozen = _stable_row_count(pg_port=p1_ports.pg, table=table)
            rows_before_frozen_window = current_published_rows()
            _assert_count_frozen(
                pg_port=p1_ports.pg,
                table=table,
                expected=frozen,
                duration_s=_REPLICA_OBSERVATION_S,
                step=step,
            )
            _wait_for_published_rows_above(
                get_published_rows=current_published_rows,
                threshold=rows_before_frozen_window,
                timeout_s=0.5,
                label=label,
            )

            assert not ingest_errors, f"{label}: ingest failed during REPLICA step {step}: {ingest_errors}"

            LOG.info("%s: step %d promote REPLICA -> PRIMARY", label, step)
            _submit_switch_tolerant(p1_ports.min_http, "primary", label=label)
            primary_snap = _await_role_tolerant(p1_ports.min_http, "primary", label=label)
            assert primary_snap.get("currentRole") == "PRIMARY"
            assert not primary_snap.get("switchInFlight")
            time.sleep(rng.uniform(0.1, 0.5))
    finally:
        stop_event.set()
        ingest_thread.join(timeout=70.0)

    assert not ingest_thread.is_alive(), f"{label}: ingest thread did not stop"
    assert not ingest_errors, f"{label}: ingest failed: {ingest_errors}"

    with state_lock:
        final_fsn = published_fsn[0]
        final_rows = published_rows[0]

    assert sidecar.await_acked(final_fsn, _DURABLE_ACK_AWAIT_TIMEOUT_MS), (
        f"{label}: final fsn={final_fsn} for {final_rows} published rows was not durably acked"
    )

    try:
        wait_for_dense_sequence(
            port=p1_ports.pg,
            table=table,
            expected_count=final_rows,
            timeout_s=120.0,
        )
    except AssertionError as exc:
        repro = (
            f"QDB_E2E_FUZZ_SEED={base_seed} "
            f"QDB_E2E_SWITCH_FUZZ_ITERS=1 "
            f"pytest -m 'fuzz and {suffix}' "
            f"tests/test_switch_fuzz.py::test_qwp_role_switch_fuzz_uncoordinated_client"
        )
        raise AssertionError(
            f"{label}: seed={seed} roundtrips={roundtrips} final_rows={final_rows}: {exc}\n"
            f"To reproduce: {repro}"
        ) from exc

    LOG.info(
        "%s: PASS roundtrips=%d final_rows=%d final_fsn=%d",
        label,
        roundtrips,
        final_rows,
        final_fsn,
    )
