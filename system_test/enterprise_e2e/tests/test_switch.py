"""
Graceful role-switch e2e suite, driven by the c-questdb-client Rust sender.

Port of the ingress-driven subset of the Enterprise harness's
``test_switch.py``. The server-side role-switch machinery (min-http
control plane, /lifecycle/switch, the read-only gate) is identical; the
binding-specific part is the QWP ingress sender, which here is the Rust
``qwp_sidecar`` (``username=`` keyword).

Scope vs the Enterprise original
--------------------------------
The Enterprise file has four tests. Two of them -- ``test_characterize``
and ``test_reads_not_frozen`` -- probe the server's read paths (HTTP /
pg-wire / QWeP) for switch-window latency, and the QWeP probe needs a
read-side ``QwpQueryClient`` egress sidecar that c-questdb-client does
not ship. Those are server-read-path guards, not Rust-*sender* scenarios,
so they are intentionally out of scope here (they belong with a future
egress query sidecar). The two tests below are the ones where the Rust
*sender* is the system under test:

  * ``test_write_path_across_switch_c_client_rust`` -- the Rust sender's
    writes are CLEAN-rejected on the demoted replica (not frozen), the
    connection survives (reconn_succ flat), and the pre-switch rows stay
    dense after switch-back.
  * ``test_disturbance_honesty_guard_c_client_rust`` -- proves the switch
    really happened (lifecycle flip + write rejections), so nothing passes
    vacuously on a no-op switch.

CRITICAL: a graceful switch destroys nothing -- never wipe the object
store here (unlike the kill-9 fuzz, which wipes to simulate disk loss).
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

import pytest

from lib.lifecycle import lifecycle, submit_switch
from lib.pg_query import count_rows, wait_for_dense_sequence
from lib.sidecar import SidecarError

from c_client_sidecar import CClientRustSidecar

LOG = logging.getLogger(__name__)

TABLE = "switch_test_c_client_rust"


def _connect_string(http_port: int, sf_dir: Path) -> str:
    return (
        f"ws::addr=127.0.0.1:{http_port}"
        ";username=admin;password=quest"
        f";sf_dir={sf_dir}"
        ";request_durable_ack=on"
        ";reconnect_max_duration_millis=60000"
        ";close_flush_timeout_millis=5000;"
    )


def _await_role_tolerant(min_http_port: int, role: str, *, timeout_s: float = 60.0,
                         poll_interval_s: float = 0.5, label: str = "") -> bool:
    """Poll lifecycle until ``role`` is settled, tolerating transient HTTP
    errors (the min-http server may drop connections mid-switch). Returns
    True if confirmed, False on timeout (does not raise)."""
    target = role.upper()
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            snap = lifecycle(min_http_port)
            if not snap.get("switchInFlight") and snap.get("currentRole") == target:
                LOG.info("%s: await_role_tolerant(%s) settled", label, role)
                return True
        except Exception as exc:
            LOG.debug("%s: await_role_tolerant transient error: %s", label, exc)
        time.sleep(min(poll_interval_s, max(0.0, deadline - time.monotonic())))
    LOG.warning("%s: await_role_tolerant(%s) did not settle within %.0fs", label, role, timeout_s)
    return False


def _submit_switch_tolerant(min_http_port: int, role: str, *, max_attempts: int = 5,
                            retry_sleep_s: float = 1.0, label: str = "") -> bool:
    """Submit a switch, retrying on transient connection errors."""
    for attempt in range(1, max_attempts + 1):
        try:
            submit_switch(min_http_port, role, wait=False)
            LOG.info("%s: submit_switch(%s) accepted (attempt %d)", label, role, attempt)
            return True
        except Exception as exc:
            LOG.debug("%s: submit_switch(%s) attempt %d failed: %s", label, role, attempt, exc)
            if attempt < max_attempts:
                time.sleep(retry_sleep_s)
    LOG.warning("%s: submit_switch(%s) failed after %d attempts", label, role, max_attempts)
    return False


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_write_path_across_switch_c_client_rust(
    server_factory,
    c_client_rust_sidecar: CClientRustSidecar,
    scenario_dir: Path,
) -> None:
    """During Rust-sender ingest, drive a P->R->P round-trip. Asserts:

    1. Writes are CLEAN-rejected ('replica access is read-only') in the
       REPLICA window -- not frozen/hung.
    2. ``reconn_succ`` stays flat -- the connection survives the switch.
    3. Exactly the pre-switch rows committed on the settled replica (no
       boundary-race rows), and after switch-back the dense oracle holds
       ``[0..N)`` with no gaps, duplicates, or shifts.

    Port of Java ``test_write_path_across_switch``.
    """
    sf_dir = scenario_dir / "sf"
    sf_dir.mkdir(parents=True, exist_ok=True)

    p1 = server_factory("p1")
    p1_ports = p1.start(min_http=True)
    assert p1_ports.min_http is not None, "min_http port not reported"
    LOG.info("write_path: server ready http=%d pg=%d min_http=%d",
             p1_ports.http, p1_ports.pg, p1_ports.min_http)

    c_client_rust_sidecar.connect(_connect_string(p1_ports.http, sf_dir))

    # Phase 1: pre-switch ingestion.
    PRE_SWITCH_ROWS = 100
    c_client_rust_sidecar.send(TABLE, count=PRE_SWITCH_ROWS, start_index=0)
    c_client_rust_sidecar.flush()
    time.sleep(0.5)

    reconn_succ_before = c_client_rust_sidecar.stats().reconn_succ

    LOG.info("write_path: submit_switch(replica) non-blocking")
    assert _submit_switch_tolerant(p1_ports.min_http, "replica", label="write_path"), \
        "submit_switch(replica) failed after retries"

    # Wait for REPLICA to settle, THEN probe write rejection (avoid
    # flooding the partially-switched WAL path with accepted writes).
    assert _await_role_tolerant(p1_ports.min_http, "replica", timeout_s=60.0,
                                label="write_path"), \
        "write_path: REPLICA role did not settle within 60s"
    LOG.info("write_path: REPLICA settled -- now probing write rejection")

    write_rejections: list[str] = []
    write_index = PRE_SWITCH_ROWS
    for attempt in range(5):
        try:
            c_client_rust_sidecar.send(TABLE, count=1, start_index=write_index)
            c_client_rust_sidecar.flush()
            write_index += 1
            LOG.debug("write_path: write accepted in settled REPLICA (attempt %d) -- retry",
                      attempt)
        except SidecarError as exc:
            write_rejections.append(str(exc))
            LOG.info("write_path: write rejected in REPLICA (attempt %d): %s", attempt, exc)
            break
        except Exception as exc:
            LOG.warning("write_path: unexpected write error (attempt %d): %s", attempt, exc)
        time.sleep(0.5)

    stats_mid = c_client_rust_sidecar.stats()
    server_errors_at_replica = stats_mid.server_errors

    # Exact-count invariant: ZERO boundary rows commit on the settled
    # REPLICA (the QWP ingress gate re-checks the live read-only mode per
    # batch). count==PRE_SWITCH_ROWS, not ">=".
    replica_count = count_rows(port=p1_ports.pg, table=TABLE)
    assert replica_count == PRE_SWITCH_ROWS, (
        f"BOUNDARY-RACE: {replica_count - PRE_SWITCH_ROWS} boundary row(s) committed on the "
        f"settled REPLICA (expected exactly {PRE_SWITCH_ROWS} pre-switch rows). A QWP "
        f"connection's cached PRIMARY context landed writes on a read-only replica."
    )

    # Phase 3: switch back to PRIMARY.
    LOG.info("write_path: submit_switch(primary)")
    assert _submit_switch_tolerant(p1_ports.min_http, "primary", label="write_path"), \
        "submit_switch(primary) failed after retries"
    _await_role_tolerant(p1_ports.min_http, "primary", timeout_s=60.0, label="write_path")

    reconn_succ_after = c_client_rust_sidecar.stats().reconn_succ

    # Phase 4: data-integrity oracle on the pre-switch rows. A graceful
    # switch does NOT destroy local WAL data -- no object-store wipe.
    wait_for_dense_sequence(port=p1_ports.pg, table=TABLE,
                            expected_count=PRE_SWITCH_ROWS, timeout_s=90.0)

    # (a) Writes were cleanly rejected in the REPLICA window (not frozen).
    assert len(write_rejections) > 0 or server_errors_at_replica > 0, (
        "WRITE-PATH: no write rejections recorded during the REPLICA window. "
        "Expected 'replica access is read-only'. "
        f"write_rejections={len(write_rejections)}, server_errors={server_errors_at_replica}."
    )
    # (b) The original connection survived the switch (no reconnect).
    assert reconn_succ_after == reconn_succ_before, (
        f"CONNECTION SURVIVAL: reconn_succ changed from {reconn_succ_before} to "
        f"{reconn_succ_after}. The QWP ingress connection dropped and reconnected during the "
        f"switch -- expected it to survive the P->R->P window."
    )
    LOG.info("write_path: PASSED -- dense [0..%d) verified; %d rejection(s); reconn_succ flat at %d",
             PRE_SWITCH_ROWS, len(write_rejections) + server_errors_at_replica, reconn_succ_before)


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_disturbance_honesty_guard_c_client_rust(
    server_factory,
    c_client_rust_sidecar: CClientRustSidecar,
    scenario_dir: Path,
) -> None:
    """Honesty guard: nothing must pass on a no-op switch.

    Asserts via ``lifecycle()`` that the role actually flipped to REPLICA
    (``currentRole == 'REPLICA'`` and ``switchInFlight == False`` at the
    apex) AND that the Rust sender's writes were actually rejected in that
    window. Port of Java ``test_disturbance_honesty_guard``.
    """
    sf_dir = scenario_dir / "sf"
    sf_dir.mkdir(parents=True, exist_ok=True)

    p1 = server_factory("p1")
    p1_ports = p1.start(min_http=True)
    assert p1_ports.min_http is not None, "min_http port not reported"

    c_client_rust_sidecar.connect(_connect_string(p1_ports.http, sf_dir))
    c_client_rust_sidecar.send(TABLE, count=30, start_index=0)
    c_client_rust_sidecar.flush()
    time.sleep(0.5)

    # Must START as PRIMARY else the guard is vacuous.
    initial_snap = lifecycle(p1_ports.min_http)
    assert initial_snap.get("currentRole") == "PRIMARY", (
        f"HONESTY GUARD: server did not start as PRIMARY. "
        f"Got currentRole={initial_snap.get('currentRole')!r}."
    )
    assert not initial_snap.get("switchInFlight"), (
        "HONESTY GUARD: switchInFlight=True at test start -- unexpected."
    )

    LOG.info("honesty_guard: submit_switch(replica) non-blocking")
    assert _submit_switch_tolerant(p1_ports.min_http, "replica", label="honesty_guard"), \
        "submit_switch(replica) failed after retries"

    replica_snap: dict | None = None
    write_rejections_during_switch: list[str] = []
    write_idx = 30
    poll_deadline = time.monotonic() + 30.0
    while time.monotonic() < poll_deadline:
        try:
            c_client_rust_sidecar.send(TABLE, count=1, start_index=write_idx)
            c_client_rust_sidecar.flush()
            write_idx += 1
        except SidecarError as exc:
            write_rejections_during_switch.append(str(exc))
            LOG.info("honesty_guard: write rejected in switch window: %s", exc)
        except Exception as exc:
            LOG.warning("honesty_guard: unexpected write error: %s", exc)

        try:
            snap = lifecycle(p1_ports.min_http)
            if not snap.get("switchInFlight") and snap.get("currentRole") == "REPLICA":
                replica_snap = snap
                LOG.info("honesty_guard: REPLICA confirmed")
                break
        except Exception as exc:
            LOG.debug("honesty_guard: lifecycle poll transient error: %s", exc)
        time.sleep(0.2)

    _await_role_tolerant(p1_ports.min_http, "replica", timeout_s=60.0, label="honesty_guard")

    if replica_snap is None:
        try:
            replica_snap = lifecycle(p1_ports.min_http)
        except Exception as exc:
            LOG.warning("honesty_guard: could not fetch lifecycle snapshot post-await: %s", exc)

    try:
        server_errors_evidence = c_client_rust_sidecar.stats().server_errors
    except Exception:
        server_errors_evidence = 0

    # Switch back to PRIMARY.
    LOG.info("honesty_guard: submit_switch(primary)")
    assert _submit_switch_tolerant(p1_ports.min_http, "primary", label="honesty_guard"), \
        "submit_switch(primary) failed after retries"
    _await_role_tolerant(p1_ports.min_http, "primary", timeout_s=60.0, label="honesty_guard")

    # (a) lifecycle confirmed REPLICA at the apex.
    assert replica_snap is not None, (
        "HONESTY GUARD: lifecycle() snapshot was never captured confirming REPLICA. "
        f"write_rejections={len(write_rejections_during_switch)}, "
        f"server_errors={server_errors_evidence}."
    )
    assert replica_snap.get("currentRole") == "REPLICA", (
        f"HONESTY GUARD: lifecycle snapshot at apex has currentRole="
        f"{replica_snap.get('currentRole')!r}, expected 'REPLICA'."
    )
    assert not replica_snap.get("switchInFlight"), (
        f"HONESTY GUARD: lifecycle snapshot at apex has switchInFlight=True. Snapshot: {replica_snap!r}"
    )

    # (b) Writes were actually rejected -- the REPLICA window was live.
    write_evidence_total = len(write_rejections_during_switch) + server_errors_evidence
    assert write_evidence_total > 0, (
        "HONESTY GUARD: no write rejections observed during the REPLICA window. "
        "Expected 'replica access is read-only'. A test that passes without write "
        "rejections would be vacuous."
    )
    if write_rejections_during_switch:
        first = write_rejections_during_switch[0]
        assert "read-only" in first.lower() or "security_error" in first.lower(), (
            f"HONESTY GUARD: write rejection message lacks 'read-only'/'SECURITY_ERROR'. Got: {first!r}"
        )

    LOG.info("honesty_guard: PASSED -- lifecycle confirmed REPLICA; %d write rejection(s)",
             write_evidence_total)
