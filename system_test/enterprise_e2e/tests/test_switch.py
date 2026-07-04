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

D-23/D-24 quartet (ported 1:1 from the Enterprise java-client suite,
``questdb-ent/e2e/tests/test_switch.py``; Rust binding only — the QWeP read
probes require the Rust egress sidecar):

* ``test_characterize_c_client_rust`` — D-23 empirical characterization of
  the P→R→P switch window (observation pass; structural assertions only).
* ``test_reads_not_frozen_c_client_rust`` — D-24(i) reads-not-frozen
  regression guard with 100% oblivious probes.
* ``test_write_path_across_switch_c_client_rust`` — D-24(ii)
  write-path-across-switch (Invariant B containment + exact-count + drain).
* ``test_disturbance_honesty_guard_c_client_rust`` — D-24(iii) "disturbance
  really happened" honesty guard (T-10-22 no-op-switch repudiation).

Rust adaptations (vs the Java sidecar): connect string uses ``username=``
and an explicit ``sender_id=``; FSNs are 0-based (guards are ``>= 0``, never
truthiness); an empty-buffer flush returns -1 so ``await_acked`` is always
preceded by a published-FSN guard.
"""

from __future__ import annotations

import logging
import statistics
import threading
import time
from pathlib import Path

import psycopg
import pytest

from lib.lifecycle import lifecycle, submit_switch
from lib.pg_query import count_rows, fetch_column_sorted, wait_for_dense_sequence
from lib.probes import (
    HTTP_PROBE_BOUND_MS,
    PG_PROBE_BOUND_MS,
    QWEP_PROBE_BOUND_MS,
    _probe_http,
    _probe_http_rows,
    _probe_pg,
    _probe_pg_rows,
    _probe_qwep,
)
from lib.sidecar import SidecarError

from c_client_sidecar import CClientRustEgressSidecar, CClientRustSidecar

LOG = logging.getLogger(__name__)

_INITIAL_ROWS = 40
_REPLICA_WINDOW_ROWS = 12
_DURABLE_ACK_AWAIT_TIMEOUT_MS = 60_000
_UNCOORDINATED_INITIAL_ROWS = 10
_UNCOORDINATED_REPLICA_OBSERVATION_S = 1.0
# Sentinel committed by accepted pg-wire write probes (lands in ``v`` outside
# any dense [0..N) oracle range). See Enterprise test_switch.py:_pg_write_probe.
_PG_PROBE_SENTINEL = 999_999


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


def _assert_write_rejected_pg(*, pg_port: int, table: str) -> str:
    """A settled replica must reject ordinary pg-wire writes cleanly.

    Returns the rejection message (the D-24 write-gate proof)."""
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
        return str(exc)


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


# ---------------------------------------------------------------------------
# D-23/D-24 helpers (ported from Enterprise test_switch.py)
# ---------------------------------------------------------------------------


def _egress_connect_string(http_port: int) -> str:
    """Egress (QWeP read) connect string — same keys as Enterprise's
    characterize/reads_not_frozen QWeP probe connection."""
    return (
        f"ws::addr=127.0.0.1:{http_port}"
        ";username=admin;password=quest"
        ";failover_max_duration_ms=10000"
        ";auth_timeout_ms=5000;"
    )


def _pg_write_probe(pg_port: int, table: str) -> tuple[str, str]:
    """One pg-wire INSERT write probe against ``table``.

    Returns ``(status, detail)`` where status is:
      * ``"rejected"`` — the server gated the write ('replica access is
        read-only'); detail is the error message (the D-24 write-gate proof);
      * ``"accepted"`` — the INSERT committed (expected while PRIMARY; a
        failure on a settled REPLICA);
      * ``"error"``    — transient/unrelated failure (connect refused
        mid-switch, etc.); detail is the message.

    Accepted probes commit the sentinel value ``_PG_PROBE_SENTINEL``, so
    tests that run a dense oracle must only hard-probe once REPLICA is
    settled — where acceptance itself fails the test before any oracle runs.
    """
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
                # Column list is ("timestamp", v): the QWP-auto-created table
                # is (v, timestamp), so the sentinel lands in v (outside any
                # dense [0..N) oracle range) and the write actually commits on
                # a writable node.
                cur.execute(
                    f'INSERT INTO "{table}" ("timestamp", v) '
                    f"VALUES (now(), {_PG_PROBE_SENTINEL});"
                )
        return "accepted", ""
    except psycopg.DatabaseError as exc:
        msg = str(exc)
        if "read-only" in msg.lower():
            return "rejected", msg
        return "error", msg
    except Exception as exc:  # connect refused / timeout mid-switch
        return "error", str(exc)


def _await_role_noraise(
    min_http_port: int,
    role: str,
    *,
    timeout_s: float = 60.0,
    poll_interval_s: float = 0.5,
    label: str = "",
) -> bool:
    """Non-raising counterpart of ``_await_role_tolerant`` for the D-23
    characterization pass: records the observation instead of failing."""
    try:
        _await_role_tolerant(
            min_http_port, role,
            timeout_s=timeout_s, poll_interval_s=poll_interval_s, label=label,
        )
        return True
    except AssertionError:
        LOG.warning(
            "%s: await_role_noraise(%s) did not settle within %.0fs",
            label, role, timeout_s,
        )
        return False


def _submit_switch_noraise(
    min_http_port: int,
    role: str,
    *,
    max_attempts: int = 5,
    retry_sleep_s: float = 1.0,
    label: str = "",
) -> bool:
    """Non-raising counterpart of ``_submit_switch_tolerant`` (D-23 only)."""
    try:
        _submit_switch_tolerant(
            min_http_port, role,
            max_attempts=max_attempts, retry_sleep_s=retry_sleep_s, label=label,
        )
        return True
    except AssertionError:
        LOG.warning("%s: submit_switch_noraise(%s) failed", label, role)
        return False


# ---------------------------------------------------------------------------
# D-23 characterization pass
# ---------------------------------------------------------------------------


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_characterize_c_client_rust(
    server_factory,
    c_client_rust_sidecar: CClientRustSidecar,
    c_client_rust_egress_sidecar: CClientRustEgressSidecar,
    scenario_dir: Path,
) -> None:
    """D-23: empirical characterization of the P→R→P switch window.

    OBSERVATION PASS — LOGS only, no latency assertions. Ported 1:1 from
    Enterprise ``test_switch.py::test_characterize`` (java sidecar) to the
    Rust binding.

    Sequence: boot a single server with the min-http control plane, connect
    the Rust ingress + egress sidecars, seed rows, drive P→R→P via
    non-blocking switch submits, and probe all three read paths (HTTP /
    QWeP / pg-wire) plus the pg-wire write gate throughout. Structural
    assertions only: the switch must demonstrably happen (lifecycle flip or
    pg-wire write rejections) and the QWP producer must never see a role
    error (Invariant B containment).
    """
    sidecar = c_client_rust_sidecar
    egress_sidecar = c_client_rust_egress_sidecar
    table = "switch_char_c_rust"
    sf_dir = scenario_dir / "sf"
    sf_dir.mkdir(parents=True, exist_ok=True)

    # ---- 1. Boot server with min-http control plane ----
    p1 = server_factory("p1")
    p1_ports = p1.start(min_http=True)
    assert p1_ports.min_http is not None, (
        "min_http port not reported; check ForkedEntServerLauncher READY line"
    )
    LOG.info(
        "characterize: server ready http=%d pg=%d min_http=%d",
        p1_ports.http, p1_ports.pg, p1_ports.min_http,
    )

    # ---- 2. Connect ingress sidecar ----
    sidecar.connect(_connect_string(p1_ports.http, sf_dir, sender_id="char-rust"))

    # ---- 3. Connect egress sidecar (QWeP read probe) ----
    try:
        egress_sidecar.connect(_egress_connect_string(p1_ports.http))
        qwep_available = True
        LOG.info("characterize: QWeP egress sidecar connected")
    except Exception as exc:
        qwep_available = False
        LOG.warning(
            "characterize: QWeP egress sidecar failed to connect: %s — "
            "skipping QWeP probes", exc,
        )

    # ---- 4. Seed initial rows (so the table exists for read probes) ----
    SEED_ROWS = 50
    sidecar.send(table, count=SEED_ROWS, start_index=0)
    sidecar.flush()
    LOG.info("characterize: seeded %d rows in %s", SEED_ROWS, table)

    # Brief settle so WAL apply makes the rows visible before probing
    time.sleep(1.0)

    # ---- 5. Baseline measurements (PRIMARY, pre-switch) ----
    LOG.info("characterize: === BASELINE (PRIMARY) ===")
    baseline_http: list[float] = []
    baseline_pg: list[float] = []
    baseline_qwep: list[float] = []

    for _ in range(5):
        ms = _probe_http(p1_ports.http)
        if ms is not None:
            baseline_http.append(ms)
        ms = _probe_pg(p1_ports.pg)
        if ms is not None:
            baseline_pg.append(ms)
        if qwep_available:
            ms = _probe_qwep(egress_sidecar)
            if ms is not None:
                baseline_qwep.append(ms)
        time.sleep(0.1)

    LOG.info("characterize: baseline HTTP latencies (ms): %s",
             [f"{v:.1f}" for v in baseline_http])
    LOG.info("characterize: baseline PG latencies (ms): %s",
             [f"{v:.1f}" for v in baseline_pg])
    LOG.info("characterize: baseline QWeP latencies (ms): %s",
             [f"{v:.1f}" for v in baseline_qwep])

    stats_before = sidecar.stats()
    reconn_succ_before = stats_before.reconn_succ
    LOG.info("characterize: reconn_succ before switch: %d", reconn_succ_before)

    # ---- 6. Drive P→R switch (non-blocking) ----
    LOG.info("characterize: === SWITCHING PRIMARY→REPLICA (non-blocking) ===")
    t_switch_start = time.monotonic()
    _submit_switch_noraise(p1_ports.min_http, "replica", label="characterize")
    LOG.info("characterize: submit_switch(replica) issued (switch in flight)")

    switch_http: list[float] = []
    switch_pg: list[float] = []
    switch_qwep: list[float] = []
    write_rejections: list[str] = []
    qwp_writes_accepted = 0
    qwp_containment_violations: list[str] = []
    write_attempt_index = SEED_ROWS

    probe_deadline = time.monotonic() + 30.0
    replica_confirmed = False
    while time.monotonic() < probe_deadline:
        ms = _probe_http(p1_ports.http)
        if ms is not None:
            switch_http.append(ms)
        ms = _probe_pg(p1_ports.pg)
        if ms is not None:
            switch_pg.append(ms)
        if qwep_available:
            ms = _probe_qwep(egress_sidecar)
            if ms is not None:
                switch_qwep.append(ms)

        # QWP write probe: under the Invariant B contract the SF sender
        # absorbs the switch window — sends must keep succeeding (rows buffer
        # to SF). A SidecarError here is a containment violation.
        try:
            sidecar.send(table, count=1, start_index=write_attempt_index)
            sidecar.flush()
            write_attempt_index += 1
            qwp_writes_accepted += 1
        except SidecarError as exc:
            qwp_containment_violations.append(str(exc))
            LOG.warning("characterize: QWP producer saw a role error "
                        "(Invariant B violation): %s", exc)
        except Exception as exc:
            LOG.warning("characterize: write probe unexpected error: %s", exc)

        # pg-wire write probe: the only client-visible proof of the REPLICA
        # write gate now that the QWP path is contractually silent.
        status, detail = _pg_write_probe(p1_ports.pg, table)
        if status == "rejected":
            write_rejections.append(detail)
            LOG.info("characterize: pg-wire write rejected "
                     "(expected in REPLICA window): %s", detail)

        try:
            snap = lifecycle(p1_ports.min_http)
            if not snap.get("switchInFlight") and snap.get("currentRole") == "REPLICA":
                replica_confirmed = True
                LOG.info(
                    "characterize: REPLICA role confirmed at t+%.1fs",
                    time.monotonic() - t_switch_start,
                )
                break
        except Exception:
            pass

        time.sleep(0.2)

    if not replica_confirmed:
        LOG.warning("characterize: REPLICA not confirmed within probe window "
                    "— switch may be slow or hung")

    # ---- 7. Wait for REPLICA to fully settle ----
    _await_role_noraise(p1_ports.min_http, "replica", timeout_s=60.0,
                        label="characterize")

    LOG.info("characterize: === IN REPLICA STATE ===")
    replica_http: list[float] = []
    replica_pg: list[float] = []
    replica_qwep: list[float] = []
    replica_write_rejections: list[str] = []

    try:
        snap = lifecycle(p1_ports.min_http)
        LOG.info("characterize: lifecycle snapshot at REPLICA: %s", snap)
    except Exception as exc:
        LOG.warning("characterize: lifecycle snapshot at REPLICA failed "
                    "(transient): %s", exc)

    for _ in range(5):
        ms = _probe_http(p1_ports.http)
        if ms is not None:
            replica_http.append(ms)
        ms = _probe_pg(p1_ports.pg)
        if ms is not None:
            replica_pg.append(ms)
        if qwep_available:
            ms = _probe_qwep(egress_sidecar)
            if ms is not None:
                replica_qwep.append(ms)

        try:
            sidecar.send(table, count=1, start_index=write_attempt_index)
            sidecar.flush()
            write_attempt_index += 1
            qwp_writes_accepted += 1
        except SidecarError as exc:
            qwp_containment_violations.append(str(exc))
            LOG.warning("characterize: QWP producer saw a role error in "
                        "settled REPLICA (Invariant B violation): %s", exc)
        except Exception as exc:
            LOG.warning("characterize: write probe error in REPLICA: %s", exc)

        status, detail = _pg_write_probe(p1_ports.pg, table)
        if status == "rejected":
            replica_write_rejections.append(detail)
            LOG.info("characterize: pg-wire write rejected in REPLICA "
                     "(correct): %s", detail)
        elif status == "accepted":
            LOG.warning("characterize: pg-wire write ACCEPTED in settled "
                        "REPLICA (unexpected)")

        time.sleep(0.2)

    # ---- 8. Drive R→P switch-back ----
    LOG.info("characterize: === SWITCHING REPLICA→PRIMARY ===")
    _submit_switch_noraise(p1_ports.min_http, "primary", label="characterize")

    switchback_http: list[float] = []
    switchback_pg: list[float] = []
    switchback_qwep: list[float] = []

    switchback_deadline = time.monotonic() + 30.0
    primary_confirmed = False
    while time.monotonic() < switchback_deadline:
        ms = _probe_http(p1_ports.http)
        if ms is not None:
            switchback_http.append(ms)
        ms = _probe_pg(p1_ports.pg)
        if ms is not None:
            switchback_pg.append(ms)
        if qwep_available:
            ms = _probe_qwep(egress_sidecar)
            if ms is not None:
                switchback_qwep.append(ms)

        try:
            snap2 = lifecycle(p1_ports.min_http)
            if not snap2.get("switchInFlight") and snap2.get("currentRole") == "PRIMARY":
                primary_confirmed = True
                LOG.info("characterize: PRIMARY role confirmed after switch-back")
                break
        except Exception:
            pass
        time.sleep(0.2)

    if not primary_confirmed:
        LOG.warning("characterize: PRIMARY not confirmed within probe window "
                    "after switch-back")

    _await_role_noraise(p1_ports.min_http, "primary", timeout_s=60.0,
                        label="characterize")

    try:
        stats_after = sidecar.stats()
        reconn_succ_after = stats_after.reconn_succ
    except Exception:
        reconn_succ_after = -1
    LOG.info("characterize: reconn_succ after switch: %d", reconn_succ_after)

    # ---- 9. Produce observation summary ----
    all_http = baseline_http + switch_http + replica_http + switchback_http
    all_pg = baseline_pg + switch_pg + replica_pg + switchback_pg
    all_qwep = baseline_qwep + switch_qwep + replica_qwep + switchback_qwep
    all_write_rej = write_rejections + replica_write_rejections

    def _summary(vals: list[float], protocol: str) -> str:
        if not vals:
            return f"{protocol}: NO SUCCESSFUL PROBES (possible freeze or connect failure)"
        p99 = statistics.quantiles(vals, n=100)[-1] if len(vals) >= 2 else vals[0]
        return (
            f"{protocol}: n={len(vals)} "
            f"max={max(vals):.1f}ms "
            f"p99={p99:.1f}ms "
            f"p50={statistics.median(vals):.1f}ms "
            f"min={min(vals):.1f}ms"
        )

    summary_lines = [
        "",
        "=" * 72,
        "D-23 CHARACTERIZATION SUMMARY (P→R→P SWITCH WINDOW) — c-client rust",
        "=" * 72,
        "",
        "READ PROBE LATENCIES (baseline + switch + replica + switchback):",
        f"  {_summary(all_http, 'HTTP')}",
        f"  {_summary(all_pg, 'PG-wire')}",
        f"  {_summary(all_qwep, 'QWeP')}",
        "",
        "SWITCH WINDOW ONLY (mid-switch probes):",
        f"  {_summary(switch_http, 'HTTP')}",
        f"  {_summary(switch_pg, 'PG-wire')}",
        f"  {_summary(switch_qwep, 'QWeP')}",
        "",
        "REPLICA WINDOW (settled REPLICA probes):",
        f"  {_summary(replica_http, 'HTTP')}",
        f"  {_summary(replica_pg, 'PG-wire')}",
        f"  {_summary(replica_qwep, 'QWeP')}",
        "",
        f"PG-WIRE WRITE REJECTIONS during switch+replica window: {len(all_write_rej)}",
    ]
    if all_write_rej:
        summary_lines.append(f"  First rejection message: {all_write_rej[0]!r}")
    else:
        summary_lines.append(
            "  (no pg-wire write rejections observed — unexpected for REPLICA window)"
        )
    summary_lines.append(
        f"QWP WRITES (Invariant B containment): accepted={qwp_writes_accepted} "
        f"producer-visible role errors={len(qwp_containment_violations)} "
        f"(must be 0 — the SF sender absorbs the window and drains after switch-back)"
    )

    reconn_succ_delta = reconn_succ_after - reconn_succ_before
    summary_lines += [
        "",
        f"CONNECTION BEHAVIOR: reconn_succ before={reconn_succ_before} "
        f"after={reconn_succ_after} delta={reconn_succ_delta}",
        "  (delta>0 is EXPECTED: an in-place demote closes the QWP ingress connection;",
        "   the SF sender reconnects once a primary is reachable again — Invariant B)",
        "",
        f"READS FROZE: "
        f"{'YES (see missing probes above)' if not all_http or not all_pg else 'NO — probes completed throughout'}",
        "=" * 72,
    ]

    for line in summary_lines:
        LOG.info("characterize: %s", line)
    print("\n".join(summary_lines))  # Also force to stdout for -s capture

    # ---- Structural assertions (no latency bound) ----
    switch_happened_via_lifecycle = replica_confirmed or primary_confirmed
    switch_happened_via_rejections = len(all_write_rej) > 0
    switch_happened = switch_happened_via_lifecycle or switch_happened_via_rejections

    if not switch_happened_via_lifecycle:
        LOG.warning(
            "characterize: lifecycle() did not confirm REPLICA during the "
            "switch window; write rejections provide alternative proof."
        )

    assert switch_happened, (
        "Neither lifecycle confirmation NOR pg-wire write rejections observed — "
        "the switch may not have happened at all. "
        f"replica_confirmed={replica_confirmed}, primary_confirmed={primary_confirmed}, "
        f"pg_write_rejections={len(all_write_rej)}"
    )
    assert switch_happened_via_rejections, (
        "No pg-wire write rejections observed through the switch window. "
        "Expected 'replica access is read-only' on pg-wire INSERT probes in "
        "the REPLICA window. Either the switch did not happen, or the pg-wire "
        "write gate is broken. (QWP probes are contractually silent under "
        "Invariant B and cannot provide this evidence.)"
    )
    assert not qwp_containment_violations, (
        "INVARIANT B CONTAINMENT: the QWP producer saw role error(s) during the "
        f"switch window: {qwp_containment_violations[:3]!r}. The SF sender must "
        "absorb a P→R→P window (buffer to SF, drain after switch-back) and never "
        "surface transient role state to the producer."
    )


# ---------------------------------------------------------------------------
# D-24 deterministic sub-tests
# ---------------------------------------------------------------------------


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_reads_not_frozen_c_client_rust(
    server_factory,
    c_client_rust_sidecar: CClientRustSidecar,
    c_client_rust_egress_sidecar: CClientRustEgressSidecar,
    scenario_dir: Path,
) -> None:
    """D-24(i): reads-not-frozen regression guard — 100% OBLIVIOUS probes.

    Ported 1:1 from Enterprise ``test_switch.py::test_reads_not_frozen``.
    Free-running threads fire fresh-connection BATCH reads over web-http and
    pg-wire on a fixed own-clock cadence from before the first switch until
    after the last settle; the P→R→P orchestration never communicates with
    the probe threads. Freeze detection is timeline-based: a frozen
    accept-loop tears a multi-second hole in the SUCCESS timeline
    (MAX_SUCCESS_GAP_S); a DEAD listener fails instantly and is caught by
    the served floor (MIN_SERVED_PROBES). Every served probe must return the
    complete seeded batch and stay within the D-23 latency bounds.

    The flat-``reconn_succ`` assertion: the idle, durably-acked QWP ingress
    connection (this time from the Rust sender) must survive the round-trip.
    """
    sidecar = c_client_rust_sidecar
    egress_sidecar = c_client_rust_egress_sidecar
    table = "switch_frozen_c_rust"

    # ---- Oblivious-probe constants (Enterprise parity) ----
    SEED_ROWS = 200
    PROBE_PERIOD_S = 0.1
    BASELINE_S = 1.0
    TAIL_S = 2.0
    MAX_SUCCESS_GAP_S = 5.0
    MIN_SERVED_PROBES = 10
    MIN_ATTEMPTED_PROBES = 15

    sf_dir = scenario_dir / "sf"
    sf_dir.mkdir(parents=True, exist_ok=True)

    p1 = server_factory("p1")
    p1_ports = p1.start(min_http=True)
    assert p1_ports.min_http is not None, "min_http port not reported"
    LOG.info("reads_not_frozen: server ready http=%d pg=%d min_http=%d",
             p1_ports.http, p1_ports.pg, p1_ports.min_http)

    sidecar.connect(_connect_string(p1_ports.http, sf_dir, sender_id="frozen-rust"))

    try:
        egress_sidecar.connect(_egress_connect_string(p1_ports.http))
        qwep_available = True
    except Exception as exc:
        qwep_available = False
        LOG.warning("reads_not_frozen: QWeP egress sidecar failed to connect: %s", exc)

    # Seed the batch the probes will read — durably acked so SF is trimmed
    # and the ingress connection is provably idle at the flip.
    sidecar.send(table, count=SEED_ROWS, start_index=0)
    seed_fsn = sidecar.flush()
    assert seed_fsn >= 0, "seed flush did not publish an FSN"
    assert sidecar.await_acked(seed_fsn, _DURABLE_ACK_AWAIT_TIMEOUT_MS), (
        f"seed rows were not durably acked [fsn={seed_fsn}]"
    )

    # Pre-window visibility barrier (synchronises with data visibility only —
    # never with the switch).
    visible_deadline = time.monotonic() + 30.0
    while time.monotonic() < visible_deadline:
        if (
            _probe_http_rows(p1_ports.http, table, SEED_ROWS) is not None
            and _probe_pg_rows(p1_ports.pg, table, SEED_ROWS) is not None
        ):
            break
        time.sleep(0.2)
    else:
        pytest.fail(f"seeded batch of {SEED_ROWS} rows not readable on http+pg within 30s")

    stats_before = sidecar.stats()
    reconn_succ_before = stats_before.reconn_succ

    # ---- Start the oblivious probe threads ----
    stop = threading.Event()
    http_samples: list[tuple[float, float | None]] = []
    pg_samples: list[tuple[float, float | None]] = []
    qwep_samples: list[tuple[float, float | None]] = []

    def _prober(probe_fn, samples: list[tuple[float, float | None]]) -> None:
        while not stop.is_set():
            t0 = time.monotonic()
            samples.append((t0, probe_fn()))
            stop.wait(PROBE_PERIOD_S)

    threads = [
        threading.Thread(
            target=_prober,
            args=(lambda: _probe_http_rows(p1_ports.http, table, SEED_ROWS), http_samples),
            name="http-prober",
            daemon=True,
        ),
        threading.Thread(
            target=_prober,
            args=(lambda: _probe_pg_rows(p1_ports.pg, table, SEED_ROWS), pg_samples),
            name="pg-prober",
            daemon=True,
        ),
    ]
    if qwep_available:
        threads.append(
            threading.Thread(
                target=_prober,
                args=(
                    lambda: _probe_qwep(
                        egress_sidecar,
                        query=f"select * from {table} limit {SEED_ROWS}",
                        expect_rows=SEED_ROWS,
                    ),
                    qwep_samples,
                ),
                name="qwep-prober",
                daemon=True,
            )
        )

    window_start = time.monotonic()
    for th in threads:
        th.start()

    # ---- Orchestration (main thread only; the probes are never told) ----
    try:
        time.sleep(BASELINE_S)

        LOG.info("reads_not_frozen: submit_switch(replica) non-blocking")
        _submit_switch_tolerant(p1_ports.min_http, "replica", label="reads_not_frozen")
        _await_role_tolerant(p1_ports.min_http, "replica", timeout_s=60.0,
                             label="reads_not_frozen")
        t_replica_settled = time.monotonic()

        LOG.info("reads_not_frozen: submit_switch(primary) non-blocking")
        _submit_switch_tolerant(p1_ports.min_http, "primary", label="reads_not_frozen")
        _await_role_tolerant(p1_ports.min_http, "primary", timeout_s=60.0,
                             label="reads_not_frozen")
        t_primary_settled = time.monotonic()

        time.sleep(TAIL_S)
    finally:
        window_end = time.monotonic()
        stop.set()
        for th in threads:
            th.join(timeout=30.0)
            if th.is_alive():
                LOG.warning("reads_not_frozen: %s did not join within 30s", th.name)

    stats_after = sidecar.stats()
    reconn_succ_after = stats_after.reconn_succ

    LOG.info(
        "reads_not_frozen: window=%.1fs replica_settled=+%.1fs primary_settled=+%.1fs",
        window_end - window_start,
        t_replica_settled - window_start,
        t_primary_settled - window_start,
    )

    # ---- Assertions (from the probe timelines alone) ----
    def _max_success_gap(samples: list[tuple[float, float | None]]) -> float:
        edges = (
            [window_start]
            + [t for t, ms in samples if ms is not None]
            + [window_end]
        )
        return max(b - a for a, b in zip(edges, edges[1:]))

    bound_violations: list[str] = []
    freeze_evidence: list[str] = []
    harness_evidence: list[str] = []

    for name, samples, bound_ms in (
        ("HTTP", http_samples, HTTP_PROBE_BOUND_MS),
        ("PG", pg_samples, PG_PROBE_BOUND_MS),
    ):
        served = [(t, ms) for t, ms in samples if ms is not None]
        gap = _max_success_gap(samples)
        LOG.info(
            "reads_not_frozen: %s attempts=%d served=%d max_success_gap=%.2fs "
            "max_latency=%.1fms",
            name, len(samples), len(served), gap,
            max((ms for _, ms in served), default=0.0),
        )
        if gap > MAX_SUCCESS_GAP_S:
            freeze_evidence.append(
                f"{name}: {gap:.1f}s hole in the success timeline "
                f"(bound {MAX_SUCCESS_GAP_S}s; attempts={len(samples)}, "
                f"served={len(served)})"
            )
        if len(served) < MIN_SERVED_PROBES:
            freeze_evidence.append(
                f"{name}: only {len(served)}/{len(samples)} probe(s) served "
                f"(floor {MIN_SERVED_PROBES}) — an instantly-failing path "
                f"leaves no timeline hole for the gap bound to see"
            )
        if len(samples) < MIN_ATTEMPTED_PROBES:
            harness_evidence.append(
                f"{name}: only {len(samples)} attempts (floor {MIN_ATTEMPTED_PROBES})"
            )
        for t, ms in served:
            if ms > bound_ms:
                bound_violations.append(
                    f"{name} probe at +{t - window_start:.1f}s took {ms:.1f}ms "
                    f"> {bound_ms}ms (D-23 characterization bound)"
                )

    for t, ms in qwep_samples:
        if ms is not None and ms > QWEP_PROBE_BOUND_MS:
            bound_violations.append(
                f"QWeP probe at +{t - window_start:.1f}s took {ms:.1f}ms "
                f"> {QWEP_PROBE_BOUND_MS}ms (D-23 characterization bound)"
            )

    assert not freeze_evidence, (
        "D-24(i) READS-NOT-FROZEN: hole(s) in the oblivious-probe success "
        "timeline across the P→R→P window — a read path stopped being served. "
        + "; ".join(freeze_evidence)
    )

    assert not bound_violations, (
        f"D-24(i) READS-NOT-FROZEN: {len(bound_violations)} probe(s) exceeded "
        f"latency bounds during P→R→P switch. Violations:\n  "
        + "\n  ".join(bound_violations)
    )

    assert not harness_evidence, (
        "D-24(i) probe-harness sanity: oblivious probe threads produced too few "
        f"attempts for a >={BASELINE_S + TAIL_S:.0f}s window at {PROBE_PERIOD_S}s "
        "cadence — harness bug or extreme scheduling starvation. "
        + "; ".join(harness_evidence)
    )

    assert reconn_succ_after == reconn_succ_before, (
        f"D-24(i) CONNECTION SURVIVAL: reconn_succ changed from {reconn_succ_before} "
        f"to {reconn_succ_after} (delta={reconn_succ_after - reconn_succ_before}). "
        f"The idle QWP ingress connection was dropped and reconnected during the "
        f"switch — expected the connection to survive the P→R→P round-trip."
    )

    LOG.info(
        "reads_not_frozen: PASSED — http served=%d pg served=%d, no timeline "
        "holes, no latency bound violations; reconn_succ flat at %d",
        sum(1 for _, ms in http_samples if ms is not None),
        sum(1 for _, ms in pg_samples if ms is not None),
        reconn_succ_before,
    )


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_write_path_across_switch_c_client_rust(
    server_factory,
    c_client_rust_sidecar: CClientRustSidecar,
    scenario_dir: Path,
) -> None:
    """D-24(ii): write-path-across-switch.

    Ported 1:1 from Enterprise ``test_switch.py::test_write_path_across_switch``.
    During sidecar ingest, drives a P→R→P round-trip and asserts the
    Invariant B contract: (1) QWP writes in the settled REPLICA window are
    ACCEPTED locally and do NOT commit on the replica (exact-count); (2) the
    pg-wire write gate is live on the settled REPLICA; (3) after switch-back
    the SF drain durably acks the window rows and the dense oracle holds
    [0..PRE+WINDOW) — exactly-once delivery.

    CRITICAL: do NOT wipe the object store — a graceful switch destroys
    nothing; wiping would mask real data loss.
    """
    sidecar = c_client_rust_sidecar
    table = "switch_writepath_c_rust"
    sf_dir = scenario_dir / "sf"
    sf_dir.mkdir(parents=True, exist_ok=True)

    p1 = server_factory("p1")
    p1_ports = p1.start(min_http=True)
    assert p1_ports.min_http is not None, "min_http port not reported"
    LOG.info("write_path: server ready http=%d pg=%d min_http=%d",
             p1_ports.http, p1_ports.pg, p1_ports.min_http)

    sidecar.connect(_connect_string(p1_ports.http, sf_dir, sender_id="writepath-rust"))

    # Phase 1: pre-switch ingestion, durably acked so SF is trimmed (without
    # the barrier the demote-close leaves the seed un-acked in SF and the
    # drainer replays it after switch-back — duplicates on a non-DEDUP table).
    PRE_SWITCH_ROWS = 100
    sidecar.send(table, count=PRE_SWITCH_ROWS, start_index=0)
    seed_fsn = sidecar.flush()
    assert seed_fsn >= 0, "pre-switch flush did not publish an FSN"
    assert sidecar.await_acked(seed_fsn, _DURABLE_ACK_AWAIT_TIMEOUT_MS), (
        f"pre-switch seed was not durably acked [fsn={seed_fsn}]"
    )

    stats_before = sidecar.stats()
    reconn_succ_before = stats_before.reconn_succ

    # Drive P→R switch (non-blocking) and wait for REPLICA to settle.
    LOG.info("write_path: submit_switch(replica) non-blocking")
    _submit_switch_tolerant(p1_ports.min_http, "replica", label="write_path")
    _await_role_tolerant(p1_ports.min_http, "replica", timeout_s=60.0,
                         label="write_path")
    LOG.info("write_path: REPLICA settled — writing window rows through SF "
             "+ probing the pg-wire write gate")

    # Phase 2: QWP sends in the settled REPLICA window must be ACCEPTED
    # locally (Invariant B); a SidecarError is a containment regression.
    WINDOW_ROWS = 5
    write_index = PRE_SWITCH_ROWS
    window_fsn = -1
    for _ in range(WINDOW_ROWS):
        try:
            sidecar.send(table, count=1, start_index=write_index)
            window_fsn = sidecar.flush()
            write_index += 1
        except SidecarError as exc:
            raise AssertionError(
                "D-24(ii) INVARIANT B CONTAINMENT: the QWP producer saw a role "
                f"error in the settled REPLICA window: {exc}. The SF sender must "
                "absorb the window (buffer to SF, drain after switch-back) and "
                "never surface transient role state to the producer."
            ) from exc
        time.sleep(0.1)
    assert window_fsn >= 0, "window flushes did not publish an FSN"
    LOG.info("write_path: %d window rows accepted into SF during settled "
             "REPLICA (publishedFsn=%d)", write_index - PRE_SWITCH_ROWS, window_fsn)

    # Server-side write-gate evidence: pg-wire must reject cleanly.
    _assert_write_rejected_pg(pg_port=p1_ports.pg, table=table)

    stats_mid = sidecar.stats()
    LOG.info(
        "write_path: REPLICA evidence — pg-wire gate confirmed; qwp window rows "
        "buffered=%d; server_errors=%d reconn_succ=%d",
        write_index - PRE_SWITCH_ROWS, stats_mid.server_errors, stats_mid.reconn_succ,
    )

    # Exact-count invariant: ZERO boundary rows commit on the settled REPLICA.
    replica_count = count_rows(port=p1_ports.pg, table=table)
    assert replica_count == PRE_SWITCH_ROWS, (
        f"D-24(ii) BOUNDARY-RACE REGRESSION: {replica_count - PRE_SWITCH_ROWS} "
        f"boundary row(s) committed on the settled REPLICA (expected exactly "
        f"{PRE_SWITCH_ROWS} pre-switch rows). A QWP connection's cached PRIMARY "
        f"SecurityContext landed writes on a read-only replica."
    )
    LOG.info("write_path: REPLICA exact-count invariant passed "
             "(committed=%d == pre-switch=%d)", replica_count, PRE_SWITCH_ROWS)

    # Phase 3: switch back to PRIMARY
    LOG.info("write_path: submit_switch(primary)")
    _submit_switch_tolerant(p1_ports.min_http, "primary", label="write_path")
    _await_role_tolerant(p1_ports.min_http, "primary", timeout_s=60.0,
                         label="write_path")

    stats_after_switchback = sidecar.stats()
    reconn_succ_after = stats_after_switchback.reconn_succ

    # Phase 4: drain barrier + data-integrity oracle. No object-store wipe.
    total_rows = write_index  # PRE_SWITCH_ROWS + accepted window rows
    assert sidecar.await_acked(window_fsn, _DURABLE_ACK_AWAIT_TIMEOUT_MS), (
        f"window rows buffered in SF during the REPLICA window were not drained "
        f"to the re-promoted primary [publishedFsn={window_fsn}]. Invariant B "
        f"promises buffered rows survive the window and ship after promotion."
    )
    LOG.info(
        "write_path: SF drained after switch-back — verifying [0..%d) via dense "
        "oracle (pre-switch %d + window %d)",
        total_rows, PRE_SWITCH_ROWS, total_rows - PRE_SWITCH_ROWS,
    )
    wait_for_dense_sequence(
        port=p1_ports.pg,
        table=table,
        expected_count=total_rows,
        timeout_s=90.0,
    )

    LOG.info(
        "write_path: PASSED — dense [0..%d) verified (pre-switch %d durably "
        "acked, %d window rows drained after switch-back); reconn_succ %d -> %d "
        "(reconnect after demote-close is expected under Invariant B)",
        total_rows, PRE_SWITCH_ROWS, total_rows - PRE_SWITCH_ROWS,
        reconn_succ_before, reconn_succ_after,
    )


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_disturbance_honesty_guard_c_client_rust(
    server_factory,
    c_client_rust_sidecar: CClientRustSidecar,
    scenario_dir: Path,
) -> None:
    """D-24(iii): "disturbance really happened" honesty guard.

    Ported 1:1 from Enterprise ``test_switch.py::test_disturbance_honesty_guard``
    (T-10-22: a no-op switch must never pass silently). Asserts via
    ``lifecycle()`` that the role actually flipped to REPLICA AND that the
    REPLICA window actually gated writes: a pg-wire INSERT is cleanly
    rejected, and QWP rows sent on the settled REPLICA buffer into SF
    without committing (frozen count), then drain after switch-back. The
    QWP producer itself must stay error-free throughout (Invariant B).
    """
    sidecar = c_client_rust_sidecar
    table = "switch_honesty_c_rust"
    sf_dir = scenario_dir / "sf"
    sf_dir.mkdir(parents=True, exist_ok=True)

    p1 = server_factory("p1")
    p1_ports = p1.start(min_http=True)
    assert p1_ports.min_http is not None, "min_http port not reported"
    LOG.info("honesty_guard: server ready http=%d pg=%d min_http=%d",
             p1_ports.http, p1_ports.pg, p1_ports.min_http)

    sidecar.connect(_connect_string(p1_ports.http, sf_dir, sender_id="honesty-rust"))

    # Seed initial rows, durably acked so SF is trimmed.
    SEED_ROWS = 30
    sidecar.send(table, count=SEED_ROWS, start_index=0)
    seed_fsn = sidecar.flush()
    assert seed_fsn >= 0, "seed flush did not publish an FSN"
    assert sidecar.await_acked(seed_fsn, _DURABLE_ACK_AWAIT_TIMEOUT_MS), (
        f"seed rows were not durably acked [fsn={seed_fsn}]"
    )

    # Verify we START as PRIMARY (otherwise the guard is vacuous).
    initial_snap = lifecycle(p1_ports.min_http)
    assert initial_snap.get("currentRole") == "PRIMARY", (
        f"D-24(iii) HONESTY GUARD: server did not start as PRIMARY. "
        f"Got currentRole={initial_snap.get('currentRole')!r}."
    )
    assert not initial_snap.get("switchInFlight"), (
        "D-24(iii) HONESTY GUARD: switchInFlight=True at test start — unexpected."
    )

    # Drive P→R switch (non-blocking)
    LOG.info("honesty_guard: submit_switch(replica) non-blocking")
    _submit_switch_tolerant(p1_ports.min_http, "replica", label="honesty_guard")

    # Poll lifecycle during the switch window; QWP writes continue through
    # the window and must be ACCEPTED (Invariant B containment).
    replica_snap: dict | None = None
    qwp_containment_violations: list[str] = []
    window_fsn = -1
    write_idx = SEED_ROWS
    poll_deadline = time.monotonic() + 30.0

    while time.monotonic() < poll_deadline:
        try:
            sidecar.send(table, count=1, start_index=write_idx)
            window_fsn = sidecar.flush()
            write_idx += 1
        except SidecarError as exc:
            qwp_containment_violations.append(str(exc))
            LOG.warning("honesty_guard: QWP producer saw a role error "
                        "(Invariant B violation): %s", exc)
        except Exception as exc:
            LOG.warning("honesty_guard: unexpected write error: %s", exc)

        try:
            snap = lifecycle(p1_ports.min_http)
            if not snap.get("switchInFlight") and snap.get("currentRole") == "REPLICA":
                replica_snap = snap
                LOG.info(
                    "honesty_guard: REPLICA confirmed — currentRole=%r switchInFlight=%r",
                    snap.get("currentRole"), snap.get("switchInFlight"),
                )
                break
        except Exception as exc:
            LOG.debug("honesty_guard: lifecycle poll transient error: %s", exc)

        time.sleep(0.2)

    # Ensure REPLICA is fully settled before measuring the write gate.
    _await_role_tolerant(p1_ports.min_http, "replica", timeout_s=60.0,
                         label="honesty_guard")

    if replica_snap is None:
        try:
            replica_snap = lifecycle(p1_ports.min_http)
            LOG.info(
                "honesty_guard: post-await lifecycle snapshot: currentRole=%r "
                "switchInFlight=%r",
                replica_snap.get("currentRole"), replica_snap.get("switchInFlight"),
            )
        except Exception as exc:
            LOG.warning("honesty_guard: could not fetch lifecycle snapshot "
                        "post-await: %s", exc)

    # Server-side write-gate evidence on the settled REPLICA.
    pg_rejection_msg = _assert_write_rejected_pg(pg_port=p1_ports.pg, table=table)

    # Freeze evidence: QWP rows sent on the settled REPLICA must buffer into
    # SF, not commit. Anchored via convergence (stable row count sized above
    # the ~0.9s freeze-measurement window below), not a fixed sleep.
    count_at_apex = _stable_row_count(
        pg_port=p1_ports.pg, table=table, stable_window_s=1.2, timeout_s=30.0,
    )
    for _ in range(3):
        try:
            sidecar.send(table, count=1, start_index=write_idx)
            window_fsn = sidecar.flush()
            write_idx += 1
        except SidecarError as exc:
            qwp_containment_violations.append(str(exc))
            LOG.warning("honesty_guard: QWP producer saw a role error in settled "
                        "REPLICA (Invariant B violation): %s", exc)
        time.sleep(0.3)
    count_after_writes = count_rows(port=p1_ports.pg, table=table)
    qwp_window_writes = write_idx - SEED_ROWS

    # Drive R→P switch-back
    LOG.info("honesty_guard: submit_switch(primary)")
    _submit_switch_tolerant(p1_ports.min_http, "primary", label="honesty_guard")
    _await_role_tolerant(p1_ports.min_http, "primary", timeout_s=60.0,
                         label="honesty_guard")

    # ---- Honesty assertions ----

    # (a) lifecycle() must confirm currentRole==REPLICA, switchInFlight==False.
    assert replica_snap is not None, (
        "D-24(iii) HONESTY GUARD: lifecycle() snapshot was never captured "
        "confirming REPLICA. The switch may not have happened, or the lifecycle "
        f"endpoint was unavailable throughout. qwp_window_writes={qwp_window_writes}. "
        "A passing test without this confirmation would be vacuous."
    )
    assert replica_snap.get("currentRole") == "REPLICA", (
        f"D-24(iii) HONESTY GUARD: lifecycle snapshot at apex has currentRole="
        f"{replica_snap.get('currentRole')!r}, expected 'REPLICA'. "
        f"Snapshot: {replica_snap!r}"
    )
    assert not replica_snap.get("switchInFlight"), (
        f"D-24(iii) HONESTY GUARD: lifecycle snapshot at apex has "
        f"switchInFlight=True — the switch was still in progress when we "
        f"expected REPLICA to be settled. Snapshot: {replica_snap!r}"
    )

    # (b) Invariant B containment: the producer never saw the switch.
    assert not qwp_containment_violations, (
        "D-24(iii) HONESTY GUARD / INVARIANT B: the QWP producer saw role "
        f"error(s) during the switch window: {qwp_containment_violations[:3]!r}. "
        "The SF sender must absorb a P→R→P window silently."
    )

    # (c) The REPLICA window was live and actually gated writes.
    assert qwp_window_writes > 0, (
        "D-24(iii) HONESTY GUARD: no QWP writes were issued during the switch "
        "window — the freeze evidence below would be vacuous."
    )
    assert count_after_writes == count_at_apex, (
        f"D-24(iii) HONESTY GUARD: commit count grew on the settled REPLICA "
        f"({count_at_apex} -> {count_after_writes}) while QWP rows were being "
        f"sent — the REPLICA window is not gating the QWP write path."
    )

    # (d) Recovery honesty: the buffered window rows must drain to the
    #     re-promoted primary — proves the disturbance was real AND recovered.
    assert window_fsn >= 0, (
        "D-24(iii) HONESTY GUARD: no window FSN was ever published — cannot "
        "verify the post-switch-back drain."
    )
    assert sidecar.await_acked(window_fsn, _DURABLE_ACK_AWAIT_TIMEOUT_MS), (
        f"window rows buffered in SF were not drained after switch-back "
        f"[publishedFsn={window_fsn}]"
    )

    LOG.info(
        "honesty_guard: PASSED — lifecycle confirmed REPLICA (currentRole=%r, "
        "switchInFlight=%r); pg-wire gate rejected (%.60s); commit count frozen "
        "at %d across %d QWP window writes; SF drained after switch-back",
        replica_snap.get("currentRole"),
        replica_snap.get("switchInFlight"),
        pg_rejection_msg,
        count_at_apex,
        qwp_window_writes,
    )
