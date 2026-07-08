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

import http.client
import logging
import os
import random
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Optional

import psycopg
import pytest

from lib.lifecycle import lifecycle, submit_switch
from lib.pg_query import count_rows, execute_ddl, wait_for_dense_sequence
from lib.probes import (
    HTTP_PROBE_BOUND_MS,
    PG_PROBE_BOUND_MS,
    QWEP_PROBE_BOUND_MS,
    _probe_http,
    _probe_pg,
    _probe_qwep,
)

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


# ---------------------------------------------------------------------------
# Ported Enterprise switch-fuzz dimensions (questdb-ent/e2e/tests/
# test_switch_fuzz.py): the multi-flip P->R->P chain with in-switch read
# prober + exact-count-with-quiescence oracle, the PITR variant, the pinned
# regression chain, and the bounded live-replica failover dimension.
#
# Rust binding only: the chain core consumes STATS reconnect counters and the
# QWeP read probe, which only the Rust ingress + egress sidecars expose.
#
# Rust adaptations (vs the Java sidecar):
#   * The ingest loop publishes one single-row frame per iteration via
#     SEND+FLUSH (the Java sidecar's SEND publishes a frame by itself); the
#     durable watermark therefore still maps 1 frame -> 1 row exactly as the
#     Enterprise oracles require.
#   * Java's flush() returns the highest published FSN even with an empty
#     buffer; Rust returns -1. The pre-demote durable-ack observe and the
#     post-chain drain barrier therefore await the last published FSN
#     tracked by the ingest loop instead of re-flushing to discover it.
#   * connect string uses ``username=`` + explicit ``sender_id=``; FSN
#     guards are ``>= 0`` (0-based FSNs).
# ---------------------------------------------------------------------------

_CHAIN_TABLE = "switch_fuzz_chain"
_RECONN_SLACK = 4
# Rust adaptation: on a ROLE REJECT (node is a settled REPLICA) the Rust
# reconnect walk deliberately sleeps a flat `reconnect_initial_backoff`
# (100ms default) and RESETS the backoff instead of doubling
# (qwp_ws.rs `reconnect_sleep_duration` role_reject branch) so the sender
# re-binds quickly after promotion. Reconnect ATTEMPTS therefore scale with
# the REPLICA-window duration over that cadence (~2-4 per leg observed),
# not ~1 per leg like the Java client. The attempts bound is a per-leg
# budget: generous enough for slow CI (long quiesce windows), tight enough
# that an order-of-magnitude flapping storm (hundreds of attempts) still
# fails. The reconn_SUCC bound stays at chain_len + slack — a successful
# re-bind per demote-close leg is the same shape as Java.
_RECONN_ATTEMPTS_PER_LEG_BOUND = 20
_CHAIN_DURABLE_ACK_AWAIT_TIMEOUT_MS = 10_000
_QUIESCE_STABLE_WINDOW_S = 1.0
_QUIESCE_POLL_INTERVAL_S = 0.2
_RECOVER_SENTINEL = "_recover_point_in_time"
# ISO-8601 far-future string: MicrosTimestampDriver.parseAnyFormat rejects a
# raw Long.MAX_VALUE (see Enterprise smoke/fixtures/row_pitr_restore.py).
_RECOVERY_LATEST_TIMESTAMP = "9999-12-31T23:59:59.999999Z"


def _egress_connect_string(http_port: int) -> str:
    """Egress (QWeP read) connect string — same keys as the D-23/D-24 port."""
    return (
        f"ws::addr=127.0.0.1:{http_port}"
        ";username=admin;password=quest"
        ";failover_max_duration_ms=10000"
        ";auth_timeout_ms=5000;"
    )


def _durable_acked_rows(stats) -> int:
    """Rows durably acked, derived from the durable watermark (stats().acked,
    the client's acked FSN — NOT the transport-frame counter stats().acks).

    Every frame in these runs carries exactly one row (baseline + ingest loop
    both publish single-row frames), so durably-acked rows = acked_fsn + 1
    (0-based FSN), and 0 while the watermark is still -1.
    """
    acked_fsn = stats.acked
    return acked_fsn + 1 if acked_fsn >= 0 else 0


def _quiesce_and_watermark(
    p1_ports,
    sidecar,
    stop_flag: threading.Event,
    table: str,
    step: int,
    *,
    label: str = "",
) -> int:
    """Pause ingest, drain the sidecar, and capture a stable row count.

    QUIESCED COUNT PLANE: the returned watermark_expected is the exact row
    count at the quiescence point that the strict == oracle must equal.
    Ported 1:1 from the Enterprise harness (flush is tolerant in the REPLICA
    window: the Rust sender buffers to SF and returns without error, but a
    transient error racing the demote is legitimate).
    """
    LOG.info("%s quiesce step=%d: setting stop flag, pausing ingest", label, step)
    stop_flag.set()

    try:
        sidecar.flush()
        LOG.info("%s quiesce step=%d: sidecar flushed", label, step)
    except Exception as exc:
        LOG.warning("%s quiesce step=%d: sidecar flush raised %s (tolerable in REPLICA window)",
                    label, step, exc)

    _await_role_tolerant(p1_ports.min_http, "replica", label=f"{label} quiesce step={step}")

    deadline = time.monotonic() + 30.0
    stable_since: Optional[float] = None
    last_count = -1
    watermark = -1
    reflushed = False
    while time.monotonic() < deadline:
        try:
            current = count_rows(port=p1_ports.pg, table=table, timeout_s=5.0)
        except (TimeoutError, psycopg.DatabaseError) as exc:
            LOG.debug("%s quiesce step=%d: count_rows raised %s; retrying", label, step, exc)
            time.sleep(_QUIESCE_POLL_INTERVAL_S)
            continue

        if current != last_count:
            last_count = current
            stable_since = time.monotonic()
            reflushed = False
        elif stable_since is not None and (time.monotonic() - stable_since) >= _QUIESCE_STABLE_WINDOW_S:
            if not reflushed:
                # Drain any last acked-but-unapplied frames, then re-confirm
                # stability so the captured value reflects a drained table.
                try:
                    sidecar.flush()
                except Exception as exc:
                    LOG.warning("%s quiesce step=%d: re-flush raised %s (tolerable)",
                                label, step, exc)
                reflushed = True
                stable_since = time.monotonic()
                time.sleep(_QUIESCE_POLL_INTERVAL_S)
                continue
            watermark = current
            LOG.info("%s quiesce step=%d: watermark_expected=%d (stable across re-flush)",
                     label, step, watermark)
            break

        time.sleep(_QUIESCE_POLL_INTERVAL_S)

    if watermark == -1:
        watermark = last_count
        LOG.warning("%s quiesce step=%d: stability timeout; using last_count=%d as watermark",
                    label, step, watermark)
    return watermark


def _run_in_switch_probes(
    p1_ports,
    egress_sidecar,
    switch_deadline: float,
    target_role: str = "replica",
) -> list[str]:
    """Poll the three read probes while a switch is in progress (LIVE plane).

    Returns bound-violation strings; a None probe return counts as a freeze.
    Exits early once the role settles to target_role.
    """
    target_role_upper = target_role.upper()
    violations: list[str] = []
    while time.monotonic() < switch_deadline:
        ms = _probe_http(p1_ports.http)
        if ms is None:
            violations.append(
                f"HTTP probe returned None (freeze / connection error) during switch window "
                f"(bound={HTTP_PROBE_BOUND_MS}ms)"
            )
        elif ms > HTTP_PROBE_BOUND_MS:
            violations.append(
                f"HTTP probe {ms:.1f}ms > HTTP_PROBE_BOUND_MS={HTTP_PROBE_BOUND_MS}ms"
            )

        ms = _probe_pg(p1_ports.pg)
        if ms is None:
            violations.append(
                f"PG probe returned None (freeze / connection error) during switch window "
                f"(bound={PG_PROBE_BOUND_MS}ms)"
            )
        elif ms > PG_PROBE_BOUND_MS:
            violations.append(
                f"PG probe {ms:.1f}ms > PG_PROBE_BOUND_MS={PG_PROBE_BOUND_MS}ms"
            )

        if egress_sidecar is not None:
            ms = _probe_qwep(egress_sidecar)
            if ms is None:
                violations.append(
                    f"QWeP probe returned None (freeze / connection error) during switch window "
                    f"(bound={QWEP_PROBE_BOUND_MS}ms)"
                )
            elif ms > QWEP_PROBE_BOUND_MS:
                violations.append(
                    f"QWeP probe {ms:.1f}ms > QWEP_PROBE_BOUND_MS={QWEP_PROBE_BOUND_MS}ms"
                )

        try:
            snap = lifecycle(p1_ports.min_http)
            if not snap.get("switchInFlight") and snap.get("currentRole") == target_role_upper:
                LOG.info("in-switch prober: %s confirmed, exiting probe loop", target_role_upper)
                break
        except Exception:
            pass

        time.sleep(0.1)

    return violations


def _assert_http_exec_write_rejection(http_port: int, table: str, step: int) -> None:
    """web-http /exec INSERT on the settled REPLICA must be cleanly rejected.

    Separate server dispatch (JsonQueryProcessor) from pg-wire, so asserted
    independently: HTTP 403 with 'replica access is read-only' in the body.
    """
    sql = f'INSERT INTO "{table}" ("timestamp", v) VALUES (now(), 99_998)'
    path = "/exec?query=" + urllib.parse.quote_plus(sql)
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
            f"WRITE-REJECTION (/exec): connection error on settled REPLICA at step={step}: "
            f"{exc!r}. Expected a clean HTTP 403 'replica access is read-only' — a connection "
            f"error here may indicate a freeze on the /exec write path."
        ) from exc

    if 200 <= status < 300:
        raise AssertionError(
            f"WRITE-REJECTION (/exec): INSERT was accepted (HTTP {status}) on settled REPLICA "
            f"at step={step}, body={body!r}. Expected HTTP 403 'replica access is read-only'."
        )
    assert status == 403, (
        f"WRITE-REJECTION (/exec): expected HTTP 403 on settled REPLICA at step={step}, got "
        f"HTTP {status}, body={body!r}."
    )
    assert "replica access is read-only" in body.lower() or "read-only" in body.lower(), (
        f"WRITE-REJECTION (/exec): HTTP 403 body did not contain 'replica access is read-only' "
        f"at step={step}. Body: {body!r}."
    )


def _assert_copy_from_write_rejection(http_port: int, table: str, step: int) -> None:
    """CSV /upload import on a settled REPLICA must be cleanly refused.

    The import path acquires a TableWriter via the engine-level gate
    (EntCairoEngine.getWriter), bypassing the per-statement read-only gate —
    asserted independently for that reason.
    """
    csv_body = b"ts,v\n2020-01-01T00:00:00.000000Z,42\n"
    boundary = "----TestBoundary"
    body = (
        f'--{boundary}\r\n'
        f'Content-Disposition: form-data; name="data"; filename="test.csv"\r\n'
        f'Content-Type: text/plain\r\n'
        f'\r\n'
    ).encode() + csv_body + f'\r\n--{boundary}--\r\n'.encode()
    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Content-Length": str(len(body)),
        "Authorization": "Basic YWRtaW46cXVlc3Q=",
    }
    path = f"/upload?name={urllib.parse.quote(table)}&timestamp=ts&fmt=csv"
    try:
        conn = http.client.HTTPConnection("127.0.0.1", http_port, timeout=10)
        try:
            conn.request("POST", path, body=body, headers=headers)
            resp = conn.getresponse()
            status = resp.status
            resp_body = resp.read().decode("utf-8", errors="replace")
        finally:
            conn.close()
    except Exception as exc:
        raise AssertionError(
            f"copy_from_write_rejection step={step}: upload raised a connection error on "
            f"settled REPLICA: {exc!r}. Expected a clean 'replica access is read-only' refusal."
        ) from exc

    # Parenthesised status check (chained comparison + `is False` is a trap).
    assert not (200 <= status < 300) or "replica access is read-only" in resp_body.lower(), (
        f"copy_from_write_rejection step={step}: CSV upload to settled REPLICA returned HTTP "
        f"{status} without 'replica access is read-only'. body={resp_body!r}."
    )
    LOG.info("copy_from_write_rejection step=%d: REPLICA refused import with HTTP %d", step, status)


def _chain_ingest_loop(
    sidecar,
    table: str,
    stop_flag: threading.Event,
    state_lock: threading.Lock,
    index_counter: list,   # [next_row_index]
    published_fsn: list,   # [last_published_fsn]
    error_holder: list,    # [exception | None]
    send_failures: list,   # [count, last_exc_repr]
) -> None:
    """Background single-row-frame publisher (SEND+FLUSH per row).

    SEND/FLUSH failures are recorded as evidence, not swallowed and not
    fatal: a transient refusal racing the demote is legitimate, and the
    growth floor + acked reconciliation catch a run where every send failed.
    """
    try:
        while not stop_flag.is_set():
            with state_lock:
                idx = index_counter[0]
            try:
                sidecar.send(table, count=1, start_index=idx)
                fsn = sidecar.flush()
                if fsn < 0:
                    raise RuntimeError(f"flush returned invalid fsn {fsn} after send")
                with state_lock:
                    index_counter[0] = idx + 1
                    published_fsn[0] = fsn
            except Exception as exc:
                send_failures[0] += 1
                send_failures[1] = repr(exc)
                LOG.warning("chain ingest: send/flush raised at index=%d (failure #%d): %s",
                            idx, send_failures[0], exc)
            time.sleep(0.05)
    except Exception as exc:
        error_holder[0] = exc


def _run_switch_fuzz_chain(
    *,
    seed: int,
    baseline_rows: int,
    chain_len: int,
    label: str,
    server_factory,
    ingress_sidecar,
    egress_sidecar,
    scenario_dir: Path,
) -> None:
    """Core multi-flip P->R->P chain body (Enterprise `_run_switch_fuzz_chain`).

    Takes the chain shape (baseline_rows, chain_len) EXPLICITLY so the pinned
    regression replays a decoded flip-chain instead of trusting RNG parity.
    """
    sf_dir = scenario_dir / f"sf-{label}"
    sf_dir.mkdir(parents=True, exist_ok=True)

    p1 = server_factory("p1")
    p1_ports = p1.start(min_http=True)
    assert p1_ports.min_http is not None, "min_http port not reported"

    ingress_sidecar.connect(
        _connect_string(p1_ports.http, sf_dir, sender_id=f"chain_{label}")
    )

    # Baseline as SINGLE-ROW FRAMES (send+flush per row) so every frame
    # carries exactly one row for the whole run — the durable watermark
    # (acked FSN) must stay mappable to a durably-acked ROW count.
    last_baseline_fsn = -1
    for i in range(baseline_rows):
        ingress_sidecar.send(_CHAIN_TABLE, count=1, start_index=i)
        last_baseline_fsn = ingress_sidecar.flush()
        assert last_baseline_fsn >= 0, (
            f"{label}: baseline flush {i} did not publish an FSN"
        )
    LOG.info("%s: baseline rows sent and flushed: %d (single-row frames)", label, baseline_rows)

    stop_flag = threading.Event()
    state_lock = threading.Lock()
    index_counter = [baseline_rows]
    published_fsn = [last_baseline_fsn]
    error_holder: list = [None]
    send_failures: list = [0, None]

    ingest_thread = threading.Thread(
        target=_chain_ingest_loop,
        args=(ingress_sidecar, _CHAIN_TABLE, stop_flag, state_lock, index_counter,
              published_fsn, error_holder, send_failures),
        name=f"ingest-{label}",
        daemon=True,
    )
    ingest_thread.start()

    stats_before = ingress_sidecar.stats()
    reconn_before = stats_before.reconn_succ
    reconn_attempts_before = stats_before.reconn_attempts
    jdbc_conn = None
    http_conn = None
    qwep_for_probes = None
    all_probe_violations: list[str] = []

    try:
        # Survival-plane witnesses opened INSIDE the try (always torn down).
        jdbc_conn = psycopg.connect(
            host="127.0.0.1",
            port=p1_ports.pg,
            user="admin",
            password="quest",
            dbname="qdb",
            connect_timeout=10,
            autocommit=True,
        )
        http_conn = http.client.HTTPConnection("127.0.0.1", p1_ports.http, timeout=10)

        try:
            egress_sidecar.connect(_egress_connect_string(p1_ports.http))
            qwep_for_probes = egress_sidecar
            LOG.info("%s: egress QWeP sidecar connected (availability plane)", label)
        except Exception as exc:
            qwep_for_probes = None
            LOG.warning("%s: egress QWeP sidecar failed to connect: %s -- skipping QWeP probes",
                        label, exc)

        for step in range(chain_len):
            LOG.info("%s: chain step=%d: P->R (live probe + quiescence at apex)", label, step)

            # Observe the durable ack WHILE STILL PRIMARY (before the demote):
            # await the last published FSN so the durable watermark has a real
            # non-(-1) value for the acked-loss oracle and the growth floor.
            # (Rust adaptation: Java re-flushes to learn the highest published
            # FSN; Rust flush returns -1 on an empty buffer, so we track it.)
            with state_lock:
                pre_demote_fsn = published_fsn[0]
            if pre_demote_fsn >= 0:
                ingress_sidecar.await_acked(pre_demote_fsn, _CHAIN_DURABLE_ACK_AWAIT_TIMEOUT_MS)

            _submit_switch_tolerant(p1_ports.min_http, "replica", label=f"{label} step={step}")
            probe_deadline = time.monotonic() + 25.0
            all_probe_violations.extend(
                _run_in_switch_probes(p1_ports, qwep_for_probes, probe_deadline)
            )
            _await_role_tolerant(p1_ports.min_http, "replica", label=f"{label} step={step}")

            watermark_expected = _quiesce_and_watermark(
                p1_ports, ingress_sidecar, stop_flag, _CHAIN_TABLE, step, label=label,
            )

            actual_count = count_rows(port=p1_ports.pg, table=_CHAIN_TABLE)
            assert actual_count == watermark_expected, (
                f"BOUNDARY-RACE REGRESSION at step={step}: "
                f"count_rows={actual_count} != watermark_expected={watermark_expected}. "
                f"A QWP connection or pg-wire client landed "
                f"{actual_count - watermark_expected} excess row(s) on the settled REPLICA. "
                f"Watermark was captured fresh at the per-apex quiescence point, so the "
                f"strict == oracle is sound (>= would blind the boundary-race class)."
            )

            # ACKED-ROW-LOSS RECONCILIATION (loss direction): every durably
            # acked single-row frame must be present in the table.
            acked_rows = _durable_acked_rows(ingress_sidecar.stats())
            assert actual_count >= acked_rows, (
                f"ACKED-ROW LOSS at step={step}: count_rows={actual_count} < "
                f"durable_acked_rows={acked_rows}. The sidecar durably acked {acked_rows} "
                f"single-row frames (request_durable_ack=on => persisted before the watermark "
                f"advanced) but only {actual_count} rows are present on the settled REPLICA — "
                f"{acked_rows - actual_count} durably-acked row(s) went missing across the "
                f"switch (the loss direction the == watermark oracle cannot see)."
            )

            # Write-rejection oracle on every client write path.
            _assert_write_rejected_pg(pg_port=p1_ports.pg, table=_CHAIN_TABLE, step=step)
            _assert_http_exec_write_rejection(p1_ports.http, _CHAIN_TABLE, step)
            _assert_copy_from_write_rejection(p1_ports.http, _CHAIN_TABLE, step)
            # line-UDP refusal is engine-gate covered (ReadOnlyWriterAcquireRefusalTest,
            # JVM tier); the UDP receiver is not enabled in this fs:// e2e environment.

            stop_flag.clear()
            LOG.info("%s: chain step=%d: ingest resumed after REPLICA apex", label, step)

            LOG.info("%s: chain step=%d: R->P (live probe)", label, step)
            _submit_switch_tolerant(p1_ports.min_http, "primary", label=f"{label} step={step}")
            probe_deadline = time.monotonic() + 25.0
            all_probe_violations.extend(
                _run_in_switch_probes(p1_ports, qwep_for_probes, probe_deadline,
                                      target_role="primary")
            )
            _await_role_tolerant(p1_ports.min_http, "primary", label=f"{label} step={step}")

        # ---- post-chain: stop ingest, drain barrier, growth floor, witnesses ----
        stop_flag.set()
        ingest_thread.join(timeout=10.0)
        if error_holder[0] is not None:
            raise RuntimeError(
                f"Background ingest thread raised: {error_holder[0]!r}"
            ) from error_holder[0]

        # DRAIN BARRIER (Invariant B): rows buffered across demote-close
        # windows must ship now the chain settled as PRIMARY. Await the last
        # published FSN (Rust adaptation; see module note).
        try:
            final_flush_fsn = ingress_sidecar.flush()
        except Exception as exc:
            final_flush_fsn = -1
            LOG.warning("%s: final flush raised %s (buffer already drained)", label, exc)
        with state_lock:
            final_published = max(published_fsn[0], final_flush_fsn)
        if final_published >= 0:
            assert ingress_sidecar.await_acked(final_published, _CHAIN_DURABLE_ACK_AWAIT_TIMEOUT_MS), (
                f"SF DRAIN FAILED after the chain (chain_len={chain_len}): rows published up "
                f"to FSN={final_published} were not durably acked within "
                f"{_CHAIN_DURABLE_ACK_AWAIT_TIMEOUT_MS} ms although the node settled as "
                f"PRIMARY. Invariant B promises rows buffered across the demote-close window "
                f"ship once a primary is reachable again."
            )
            LOG.info("%s: drain barrier: durable ack reached FSN=%d", label, final_published)

        # GROWTH FLOOR: kill the vacuous zero-ingest pass.
        final_acked_rows = _durable_acked_rows(ingress_sidecar.stats())
        final_count = count_rows(port=p1_ports.pg, table=_CHAIN_TABLE)
        with state_lock:
            sends_attempted = index_counter[0] - baseline_rows
        LOG.info(
            "%s: growth floor: baseline=%d sends_attempted=%d final_count=%d "
            "final_acked_rows=%d send_failures=%d",
            label, baseline_rows, sends_attempted, final_count, final_acked_rows,
            send_failures[0],
        )
        assert sends_attempted > 0, (
            f"ZERO-INGEST ITERATION (vacuous pass) for chain_len={chain_len}: the background "
            f"ingest thread published no rows past the baseline of {baseline_rows}. "
            f"send_failures={send_failures[0]} last_send_error={send_failures[1]!r}"
        )
        assert final_acked_rows > 0, (
            f"NO DURABLE INGEST (vacuous pass) for chain_len={chain_len}: zero durably acked "
            f"rows ({sends_attempted} sends attempted, final_count={final_count}). "
            f"send_failures={send_failures[0]} last_send_error={send_failures[1]!r}"
        )
        if send_failures[0] > 0:
            LOG.warning(
                "%s: ingest send path saw %d failure(s) across the chain (last=%s); growth "
                "floor + acked reconciliation held, so a partial set of switch-window "
                "rejections is tolerated", label, send_failures[0], send_failures[1],
            )

        # Plane 1: QWP ingress reconnects are EXPECTED (Invariant B demote-
        # close) but BOUNDED — a reconnect storm still fails.
        stats_after = ingress_sidecar.stats()
        reconn_delta = stats_after.reconn_succ - reconn_before
        reconn_attempts_delta = stats_after.reconn_attempts - reconn_attempts_before
        reconn_upper = chain_len + _RECONN_SLACK
        reconn_attempts_upper = chain_len * _RECONN_ATTEMPTS_PER_LEG_BOUND + _RECONN_SLACK
        LOG.info(
            "%s: reconn: succ_delta=%d (bound=%d) attempts_delta=%d (bound=%d) chain_len=%d",
            label, reconn_delta, reconn_upper, reconn_attempts_delta,
            reconn_attempts_upper, chain_len,
        )
        assert reconn_delta <= reconn_upper, (
            f"RECONNECT STORM: SF sender reconnected {reconn_delta} times across the chain "
            f"(chain_len={chain_len}, bound chain_len+{_RECONN_SLACK}={reconn_upper}). "
            f"Expected ~one demote-close reconnect per leg (Invariant B), not a "
            f"flapping/looping reconnect."
        )
        assert reconn_attempts_delta <= reconn_attempts_upper, (
            f"RECONNECT-ATTEMPT STORM: {reconn_attempts_delta} reconnect attempts across the "
            f"chain (chain_len={chain_len}, bound chain_len*"
            f"{_RECONN_ATTEMPTS_PER_LEG_BOUND}+{_RECONN_SLACK}={reconn_attempts_upper}). "
            f"The Rust role-reject retry cadence is flat-initial-backoff by design (fast "
            f"re-bind after promotion), so a per-leg budget applies — but an attempt count "
            f"this high is a flapping reconnect loop, not window-paced role-reject retries."
        )

        # Plane 2: pre-opened psycopg connection survives the whole chain.
        with jdbc_conn.cursor() as cur:
            cur.execute("SELECT 1")
            row = cur.fetchone()
            assert row is not None, (
                f"pre-opened psycopg connection returned None on SELECT 1 after chain "
                f"(chain_len={chain_len})"
            )

        # Plane 3: pre-opened HTTP keep-alive connection still returns 200.
        http_conn.request(
            "GET",
            "/exec?query=SELECT+1&limit=1",
            headers={"Authorization": "Basic YWRtaW46cXVlc3Q="},
        )
        http_resp = http_conn.getresponse()
        http_resp.read()
        assert http_resp.status == 200, (
            f"HTTP keep-alive probe returned {http_resp.status} after chain "
            f"(chain_len={chain_len}); expected 200"
        )

        # No in-switch freeze across any switch window.
        assert not all_probe_violations, (
            f"IN-SWITCH FREEZE DETECTED: {len(all_probe_violations)} probe(s) exceeded "
            f"latency bounds or returned None during the switch chain (chain_len={chain_len}). "
            f"Violations:\n  " + "\n  ".join(all_probe_violations)
        )

    except AssertionError as exc:
        raise AssertionError(
            f"seed={seed} label={label} chain_len={chain_len}: {exc}"
        ) from exc
    finally:
        stop_flag.set()
        ingest_thread.join(timeout=5.0)
        if jdbc_conn is not None:
            try:
                jdbc_conn.close()
            except Exception:
                pass
        if http_conn is not None:
            try:
                http_conn.close()
            except Exception:
                pass
        try:
            egress_sidecar.close()
        except Exception:
            pass


@pytest.mark.fuzz
@pytest.mark.c_client_rust
@pytest.mark.parametrize(
    "iteration",
    range(int(os.environ.get("QDB_E2E_FUZZ_ITERS", "10"))),
)
def test_switch_fuzz_c_client_rust(
    iteration: int,
    server_factory,
    c_client_rust_sidecar,
    c_client_rust_egress_sidecar,
    scenario_dir: Path,
) -> None:
    """Seed-isolated switch-roundtrip fuzz with the chain/survival/read-prober/
    exact-count oracles (Enterprise `test_switch_fuzz`, Rust binding).

    TWO PLANES:
      * LIVE (survival + read prober): pg-wire/HTTP witnesses + in-switch
        HTTP/PG/QWeP probes during every switch window; QWP ingress reconnects
        are expected (Invariant B demote-close) but bounded to chain_len+slack.
      * QUIESCED COUNT (exact-count oracle): at each REPLICA apex ingest is
        paused, the sidecar drained, and count_rows must == the fresh
        quiesced watermark (strict ==; >= blinds the boundary-race class).
    """
    base_seed = int(os.environ.get("QDB_E2E_FUZZ_SEED", str(time.time_ns() & 0xFFFFFFFF)))
    seed = _seed_for_iteration(base_seed, iteration)
    rng = random.Random(seed)
    LOG.info("switch fuzz chain iteration=%d seed=%d (base=%d)", iteration, seed, base_seed)

    # Same draw order as Enterprise `_run_switch_fuzz_chain`: baseline first,
    # then chain length (keeps QDB_E2E_FUZZ_SEED repro strings meaningful
    # across the two harnesses).
    baseline_rows = rng.randint(10, 50)
    chain_len = rng.randint(1, 6)

    try:
        _run_switch_fuzz_chain(
            seed=seed,
            baseline_rows=baseline_rows,
            chain_len=chain_len,
            label=f"iter{iteration}",
            server_factory=server_factory,
            ingress_sidecar=c_client_rust_sidecar,
            egress_sidecar=c_client_rust_egress_sidecar,
            scenario_dir=scenario_dir,
        )
    except AssertionError as exc:
        repro = (
            f"QDB_E2E_FUZZ_SEED={base_seed} "
            f"pytest -m 'fuzz and c_client_rust' "
            f"'tests/test_switch_fuzz.py::test_switch_fuzz_c_client_rust[{iteration}]'"
        )
        raise AssertionError(
            f"fuzz iteration={iteration} base_seed={base_seed} derived_seed={seed}: {exc}\n"
            f"To reproduce: {repro}"
        ) from exc


@pytest.mark.fuzz
@pytest.mark.c_client_rust
def test_switch_fuzz_pinned_chain_5171257088512701991_c_client_rust(
    server_factory,
    c_client_rust_sidecar,
    c_client_rust_egress_sidecar,
    scenario_dir: Path,
) -> None:
    """Pinned regression: the multi-flip P->R->P chain that exposed a
    debug-build crash in the uploader's post-upload sync_id cross-check
    (Enterprise `test_switch_fuzz_pinned_seed_5171257088512701991`).

    Ported as a PINNED FLIP-CHAIN, not a raw seed replay: the Enterprise
    harness's only seed-driven draws are `baseline_rows = randint(10, 50)`
    and `chain_len = randint(1, 6)`, and
    `random.Random(5171257088512701991)` decodes them to **baseline_rows=22,
    chain_len=6** (Python MT19937 — decoded once, pinned here explicitly so
    this port carries zero RNG dependency and the 6-flip shape is preserved
    verbatim even if either harness's draw order ever changes).
    """
    _run_switch_fuzz_chain(
        seed=5171257088512701991,
        baseline_rows=22,
        chain_len=6,
        label="pinned-5171257088512701991",
        server_factory=server_factory,
        ingress_sidecar=c_client_rust_sidecar,
        egress_sidecar=c_client_rust_egress_sidecar,
        scenario_dir=scenario_dir,
    )


def _write_recover_point_in_time(data_root: Path, source_obj_store_uri: str) -> Path:
    """Write the _recover_point_in_time Properties sentinel (EXACTLY two keys;
    extra keys fail the boot — PointInTimeRecoveryConfiguration.java)."""
    sentinel = data_root / _RECOVER_SENTINEL
    sentinel.write_text(
        f"replication.object.store={source_obj_store_uri}\n"
        f"replication.recovery.timestamp={_RECOVERY_LATEST_TIMESTAMP}\n"
    )
    return sentinel


@pytest.mark.fuzz
@pytest.mark.c_client_rust
def test_switch_fuzz_pitr_c_client_rust(
    server_factory,
    c_client_rust_sidecar,
    c_client_rust_egress_sidecar,
    obj_store,
    scenario_dir: Path,
) -> None:
    """PITR variant: live QWP client ingesting across PITR-recovered-boot +
    first switch (Enterprise `test_switch_fuzz_pitr`, Rust binding).

    #092 guard: if count_rows != watermark_expected at the quiescence point
    after the PITR-recovered boot + first switch, ingest was silently dropped
    (or excess rows landed) while acceptOpen=false during the restore boot.
    ONE deterministic high-value test, not a fuzz sub-dimension (the
    boot+upload+recover-boot fixture cost exceeds the per-iteration budget).
    """
    from lib.classpath import build_classpath
    from lib.server import ForkedEntServer

    sidecar = c_client_rust_sidecar
    egress_sidecar = c_client_rust_egress_sidecar

    sf_dir = scenario_dir / "sf"
    sf_dir.mkdir(parents=True, exist_ok=True)

    # ---- Phase 1: boot original primary, ingest, durably ack (=> uploaded) ----
    p1 = server_factory("p1-pitr-source")
    p1_ports = p1.start(min_http=True)
    assert p1_ports.min_http is not None, "min_http port not reported"

    sidecar.connect(_connect_string(p1_ports.http, sf_dir, sender_id="pitr_src"))
    pre_pitr_rows = 50
    sidecar.send(_CHAIN_TABLE, count=pre_pitr_rows, start_index=0)
    src_fsn = sidecar.flush()
    assert src_fsn >= 0, "PITR source flush did not publish an FSN"
    assert sidecar.await_acked(src_fsn, _DURABLE_ACK_AWAIT_TIMEOUT_MS), (
        f"PITR source rows (fsn={src_fsn}) were not durably acked — the durable ack is the "
        f"upload guarantee the recover-boot depends on"
    )
    time.sleep(2.0)  # belt-and-braces slack for async index/cleanup tail
    LOG.info("PITR: %d rows durably acked on source primary", pre_pitr_rows)

    p1.stop()
    LOG.info("PITR: source primary stopped")

    # ---- Phase 2: boot PITR-recovered primary from the source obj_store ----
    # The PITR recovery TARGET must be a different, EMPTY object store
    # (uploader raises ER001 on a non-empty target after PITR).
    pitr_target_dir = scenario_dir / "pitr_target"
    pitr_target_obj = pitr_target_dir / "objstore" / "root"
    pitr_target_scratch = pitr_target_dir / "objstore" / "scratch"
    pitr_target_obj.mkdir(parents=True, exist_ok=True)
    pitr_target_scratch.mkdir(parents=True, exist_ok=True)
    pitr_target_uri = f"fs::root={pitr_target_obj};atomic_write_dir={pitr_target_scratch};"

    pitr_db_root_db = scenario_dir / "pitr_db" / "db"
    pitr_db_root_db.mkdir(parents=True, exist_ok=True)
    sentinel = _write_recover_point_in_time(pitr_db_root_db, obj_store.uri)
    LOG.info("PITR: sentinel written at %s (source=%s)", sentinel, obj_store.uri)

    pitr_server = ForkedEntServer(
        db_root=pitr_db_root_db,
        object_store_uri=pitr_target_uri,
        log_dir=scenario_dir / "logs" / "pitr-recovered",
        classpath=build_classpath(),
        name="p1-pitr-recovered",
    )
    pitr_ports = pitr_server.start(min_http=True, ready_timeout=180.0)
    assert pitr_ports.min_http is not None, "PITR-recovered server: min_http port not reported"
    LOG.info("PITR: recovered primary ready at %s", pitr_ports)

    # Live QWP client on the recovered primary: FRESH sf_dir + sender_id
    # (CONNECT replaces the prior sender; fresh slot => fresh counters).
    sf_dir_pitr = scenario_dir / "sf_pitr"
    sf_dir_pitr.mkdir(parents=True, exist_ok=True)
    sidecar.connect(_connect_string(pitr_ports.http, sf_dir_pitr, sender_id="pitr_live"))

    stop_flag = threading.Event()
    state_lock = threading.Lock()
    index_counter = [0]
    published_fsn = [-1]
    error_holder: list = [None]
    send_failures: list = [0, None]
    ingest_thread = threading.Thread(
        target=_chain_ingest_loop,
        args=(sidecar, _CHAIN_TABLE, stop_flag, state_lock, index_counter,
              published_fsn, error_holder, send_failures),
        name="pitr-ingest",
        daemon=True,
    )
    ingest_thread.start()
    time.sleep(0.5)  # let a few rows arrive before the first switch

    qwep_for_probes = None
    try:
        try:
            egress_sidecar.connect(_egress_connect_string(pitr_ports.http))
            qwep_for_probes = egress_sidecar
        except Exception as exc:
            LOG.warning("PITR: egress QWeP sidecar failed to connect: %s -- skipping QWeP probes",
                        exc)

        # Observe the durable ack WHILE STILL PRIMARY (Rust adaptation: await
        # the ingest loop's last published FSN — see chain body note).
        with state_lock:
            pitr_pre_fsn = published_fsn[0]
        if pitr_pre_fsn >= 0:
            sidecar.await_acked(pitr_pre_fsn, _CHAIN_DURABLE_ACK_AWAIT_TIMEOUT_MS)

        _submit_switch_tolerant(pitr_ports.min_http, "replica", label="pitr")
        probe_deadline = time.monotonic() + 25.0
        pitr_violations = _run_in_switch_probes(pitr_ports, qwep_for_probes, probe_deadline)
        _await_role_tolerant(pitr_ports.min_http, "replica", label="pitr")

        pitr_watermark = _quiesce_and_watermark(
            pitr_ports, sidecar, stop_flag, _CHAIN_TABLE, 0, label="pitr",
        )
        pitr_actual = count_rows(port=pitr_ports.pg, table=_CHAIN_TABLE)
        assert pitr_actual == pitr_watermark, (
            f"#092 PITR INGEST GUARD: count_rows={pitr_actual} != "
            f"watermark_expected={pitr_watermark} on PITR-recovered primary after first "
            f"switch. Ingest may have been silently dropped while acceptOpen=false during "
            f"the PITR-restore boot (bug #092). Deterministic test — no seed needed. "
            f"Watermark captured at the quiescence point (same protocol as the main fuzz)."
        )
        LOG.info("PITR: #092 guard PASSED — count_rows=%d == watermark=%d",
                 pitr_actual, pitr_watermark)

        # Acked-loss reconciliation + growth floor (the recovered primary
        # ingested from a fresh baseline of 0 in single-row frames).
        pitr_acked_rows = _durable_acked_rows(sidecar.stats())
        assert pitr_actual >= pitr_acked_rows, (
            f"PITR ACKED-ROW LOSS: count_rows={pitr_actual} < "
            f"durable_acked_rows={pitr_acked_rows} on the recovered+settled REPLICA — "
            f"{pitr_acked_rows - pitr_actual} durably-acked row(s) went missing across the "
            f"PITR-restore boot + first switch. send_failures={send_failures[0]} "
            f"last_send_error={send_failures[1]!r}"
        )
        assert pitr_acked_rows > 0, (
            f"PITR ZERO-INGEST (vacuous pass): the recovered primary durably acked no rows "
            f"(sends_attempted={index_counter[0]}), so the #092 == guard proved nothing. "
            f"send_failures={send_failures[0]} last_send_error={send_failures[1]!r}"
        )

        _assert_write_rejected_pg(pg_port=pitr_ports.pg, table=_CHAIN_TABLE, step=0)
        _assert_http_exec_write_rejection(pitr_ports.http, _CHAIN_TABLE, 0)

        assert not pitr_violations, (
            f"IN-SWITCH FREEZE on PITR-recovered primary: {len(pitr_violations)} "
            f"violation(s):\n  " + "\n  ".join(pitr_violations)
        )
        LOG.info("PITR: PASSED — #092 guard green, no freeze, write-rejection clean")
    finally:
        stop_flag.set()
        ingest_thread.join(timeout=5.0)
        try:
            egress_sidecar.close()
        except Exception:
            pass
        try:
            pitr_server.stop()
        except Exception:
            pass


@pytest.mark.fuzz
@pytest.mark.c_client_rust
def test_switch_fuzz_live_replica_failover_c_client_rust(
    c_client_rust_sidecar,
    classpath: str,
    log_dir: Path,
    scenario_dir: Path,
) -> None:
    """Bounded live-replica failover fuzz dimension (Enterprise
    `test_switch_fuzz_live_replica_failover`, Rust binding).

    max(1, QDB_E2E_FUZZ_ITERS // 5) cycles; each boots a fresh A (primary) +
    B (replica) pair on a fresh per-cycle object store (ER007 DataID
    isolation), demotes A, promotes B, ingests onward rows into B, and
    asserts A converges on B's total — the headline onward-convergence
    invariant. Both nodes must shut down cleanly.
    """
    from lib.obj_store import make_obj_store
    from lib.server import ForkedEntServer
    from lib.shutdown import assert_clean_shutdown

    sidecar = c_client_rust_sidecar
    iters = int(os.environ.get("QDB_E2E_FUZZ_ITERS", "10"))
    num_cycles = max(1, iters // 5)
    base_seed = int(os.environ.get("QDB_E2E_FUZZ_SEED", str(time.time_ns() & 0xFFFFFFFF)))
    LOG.info("live_replica_failover: iters=%d num_cycles=%d base_seed=%d",
             iters, num_cycles, base_seed)

    failover_table = "switch_fuzz_failover"
    converge_timeout_s = 120.0
    poll_interval_s = 0.3

    def _wait_replica_converges(*, pg_port: int, expected: int,
                                timeout_s: float = converge_timeout_s) -> None:
        deadline = time.monotonic() + timeout_s
        last = -1
        while time.monotonic() < deadline:
            try:
                last = count_rows(port=pg_port, table=failover_table, timeout_s=5.0)
            except Exception:
                last = -1
            if last == expected:
                LOG.info("live_replica_failover: replica converged count=%d", last)
                return
            time.sleep(poll_interval_s)
        raise AssertionError(
            f"live_replica_failover: replica did not converge on {expected} rows in "
            f"{failover_table} within {timeout_s}s (last observed: {last}). Headline "
            f"onward-convergence invariant: A (now replica) must download B's post-promote "
            f"rows; a failure means onward replication broke after the hot in-place promote."
        )

    for cycle in range(num_cycles):
        cycle_seed = _seed_for_iteration(base_seed, cycle)
        rng = random.Random(cycle_seed)
        initial_rows = rng.randint(10, 40)
        onward_rows = rng.randint(5, 20)
        LOG.info("live_replica_failover: cycle=%d/%d seed=%d initial=%d onward=%d",
                 cycle, num_cycles, cycle_seed, initial_rows, onward_rows)
        cycle_start = time.monotonic()

        cycle_dir = scenario_dir / f"cycle_{cycle}"
        cycle_dir.mkdir(parents=True, exist_ok=True)
        cycle_store = make_obj_store(cycle_dir)
        db_a = cycle_dir / "db_a"
        db_b = cycle_dir / "db_b"
        db_a.mkdir(parents=True, exist_ok=True)
        db_b.mkdir(parents=True, exist_ok=True)

        a = ForkedEntServer(
            db_root=db_a,
            object_store_uri=cycle_store.uri,
            log_dir=log_dir,
            extra_env={"QDB_REPLICATION_ROLE": "primary"},
            classpath=classpath,
            name=f"failover-a-c{cycle}",
        )
        b = ForkedEntServer(
            db_root=db_b,
            object_store_uri=cycle_store.uri,
            log_dir=log_dir,
            extra_env={
                "QDB_REPLICATION_ROLE": "replica",
                "QDB_REPLICATION_REPLICA_POLL_INTERVAL": "5",
            },
            classpath=classpath,
            name=f"failover-b-c{cycle}",
        )

        a_ports = a.start(min_http=True)
        b_ports = b.start(min_http=True)
        assert a_ports.min_http is not None, f"cycle {cycle}: node A min_http not reported"
        assert b_ports.min_http is not None, f"cycle {cycle}: node B min_http not reported"

        sf_a = scenario_dir / "sf" / f"c{cycle}_a"
        sf_a.mkdir(parents=True, exist_ok=True)

        try:
            sidecar.connect(_connect_string(a_ports.http, sf_a, sender_id=f"c{cycle}_a"))
            sidecar.send(failover_table, count=initial_rows, start_index=0)
            fsn = sidecar.flush()
            assert fsn >= 0, f"cycle {cycle}: initial flush did not publish an FSN"
            wait_for_dense_sequence(port=a_ports.pg, table=failover_table,
                                    expected_count=initial_rows, timeout_s=60.0)
            _wait_replica_converges(pg_port=b_ports.pg, expected=initial_rows)
            LOG.info("live_replica_failover: cycle=%d B caught up (%d rows)",
                     cycle, initial_rows)

            # Demote A, then promote B (the hot in-place failover).
            submit_switch(a_ports.min_http, "replica", wait=True, wait_timeout_s=60.0)
            snap_a = lifecycle(a_ports.min_http)
            assert snap_a.get("currentRole") == "REPLICA", (
                f"cycle {cycle}: A should be REPLICA after demotion, "
                f"got {snap_a.get('currentRole')!r}"
            )
            submit_switch(b_ports.min_http, "primary", wait=True, wait_timeout_s=60.0)
            snap_b = lifecycle(b_ports.min_http)
            assert snap_b.get("currentRole") == "PRIMARY", (
                f"cycle {cycle}: B should be PRIMARY after promotion, "
                f"got {snap_b.get('currentRole')!r}"
            )

            # Onward rows into B via a fresh slot (close + reconnect).
            sidecar.close()
            sf_b = scenario_dir / "sf" / f"c{cycle}_b"
            sf_b.mkdir(parents=True, exist_ok=True)
            sidecar.connect(_connect_string(b_ports.http, sf_b, sender_id=f"c{cycle}_b"))
            sidecar.send(failover_table, count=onward_rows, start_index=initial_rows)
            fsn = sidecar.flush()
            assert fsn >= 0, f"cycle {cycle}: onward flush did not publish an FSN"

            total_expected = initial_rows + onward_rows
            wait_for_dense_sequence(port=b_ports.pg, table=failover_table,
                                    expected_count=total_expected, timeout_s=60.0)
            _wait_replica_converges(pg_port=a_ports.pg, expected=total_expected)
            LOG.info("live_replica_failover: cycle=%d A converged on %d total rows "
                     "-- onward replication confirmed", cycle, total_expected)

            sidecar.close()
            b.stop()
            a.stop()
            assert_clean_shutdown(b)
            assert_clean_shutdown(a)
        except Exception:
            for closer in (sidecar.close, b.stop, a.stop):
                try:
                    closer()
                except Exception:
                    pass
            raise

        LOG.info("live_replica_failover: cycle=%d PASSED in %.1fs (total=%d rows)",
                 cycle, time.monotonic() - cycle_start, initial_rows + onward_rows)

    LOG.info("live_replica_failover: all %d cycle(s) PASSED (base_seed=%d)",
             num_cycles, base_seed)
