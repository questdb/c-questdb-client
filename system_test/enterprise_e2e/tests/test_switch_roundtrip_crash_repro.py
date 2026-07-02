"""
Regression guard for the QWP switch-roundtrip crash + boundary race,
driven by the c-questdb-client Rust sender.

Port of the Enterprise harness's ``test_switch_roundtrip_crash_repro.py``.
It exercises the aggressive path the shipped ``test_write_path_across_switch``
avoids: a write storm during the P->R settlement window (the boundary
race), then a sidecar close + reconnect + fresh QWP writes AFTER the R->P
switch-back. The binding-specific part is the Rust ``qwp_sidecar`` ingress
sender (``username=`` keyword); the server-side fixes under guard are
identical.

Asserted invariants (all server-side fixes, exercised through the Rust sender):
  1. No durably acknowledged row is lost across the P->R boundary.
  2. No server crash; the JVM stays alive through the whole round-trip.
  3. After R->P switch-back, a reconnected QWP connection writes again.
"""

from __future__ import annotations

import http.client
import logging
import os
import time
import urllib.parse
from pathlib import Path

import pytest

from lib.lifecycle import lifecycle, submit_switch
from lib.pg_query import count_rows, fetch_column_sorted
from lib.sidecar import SidecarError

from c_client_sidecar import CClientRustSidecar

LOG = logging.getLogger(__name__)

TABLE = "switch_test_c_client_rust"
_BASIC_AUTH = "Basic YWRtaW46cXVlc3Q="  # admin:quest

PRE = 100  # rows seeded while PRIMARY, before the P->R switch
_DURABLE_ACK_AWAIT_TIMEOUT_MS = 60_000


def _durably_acked_rows(accepted_by_fsn: list[tuple[int, int]], acked_fsn: int) -> int:
    """Map the sidecar's durable FSN watermark to cumulative accepted rows."""
    rows = 0
    for fsn, cumulative_rows in accepted_by_fsn:
        if fsn <= acked_fsn:
            rows = max(rows, cumulative_rows)
    return rows


def _connect_string(http_port: int, sf_dir: Path) -> str:
    return (
        f"ws::addr=127.0.0.1:{http_port}"
        ";username=admin;password=quest"
        f";sf_dir={sf_dir}"
        ";request_durable_ack=on"
        ";reconnect_max_duration_millis=60000"
        ";close_flush_timeout_millis=5000;"
    )


def _crash_artifact_dir() -> Path:
    d = Path(os.environ.get(
        "QDB_CRASH_ARTIFACT_DIR",
        str(Path(__file__).resolve().parent.parent / "crash-artifacts"),
    ))
    d.mkdir(parents=True, exist_ok=True)
    return d


def _lifecycle_brief(min_http_port: int) -> str:
    try:
        snap = lifecycle(min_http_port)
        comps = {c.get("name"): c.get("state") for c in snap.get("components", [])}
        return (f"role={snap.get('currentRole')} switchInFlight={snap.get('switchInFlight')} "
                f"components={comps}")
    except Exception as exc:
        return f"<lifecycle unavailable: {exc}>"


def _http_insert(http_port: int, table: str, ts_micros: int) -> tuple[int, str]:
    """POST an INSERT via /exec. A read-only engine rejects; a healthy
    PRIMARY returns 200."""
    sql = f'INSERT INTO "{table}"(v, timestamp) VALUES({ts_micros}, {ts_micros})'
    q = urllib.parse.quote(sql, safe="")
    conn = http.client.HTTPConnection("127.0.0.1", http_port, timeout=10)
    try:
        conn.request("GET", f"/exec?query={q}", headers={"Authorization": _BASIC_AUTH})
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", errors="replace")
        return resp.status, body
    finally:
        conn.close()


def _await_role_tolerant(min_http_port: int, role: str, *, timeout_s: float = 60.0,
                         label: str = "") -> bool:
    target = role.upper()
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            snap = lifecycle(min_http_port)
            if not snap.get("switchInFlight") and snap.get("currentRole") == target:
                return True
        except Exception:
            pass
        time.sleep(0.25)
    return False


def _submit_switch_tolerant(min_http_port: int, role: str, *, max_attempts: int = 5,
                            label: str = "") -> bool:
    for attempt in range(1, max_attempts + 1):
        try:
            submit_switch(min_http_port, role, wait=False)
            LOG.info("%s: submit_switch(%s) accepted (attempt %d)", label, role, attempt)
            return True
        except Exception as exc:
            LOG.debug("%s: submit_switch(%s) attempt %d: %s", label, role, attempt, exc)
            time.sleep(1.0)
    return False


def _signal_name(returncode) -> str:
    if returncode is None:
        return "alive"
    if returncode < 0:
        try:
            import signal as _sig
            return f"signal {_sig.Signals(-returncode).name} ({-returncode})"
        except Exception:
            return f"signal {-returncode}"
    return f"exit code {returncode}"


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_roundtrip_post_switch_write_no_crash_no_replica_writes_c_client_rust(
    server_factory,
    c_client_rust_sidecar: CClientRustSidecar,
    scenario_dir: Path,
    log_dir: Path,
) -> None:
    """Regression guard for the QWP switch-roundtrip crash + boundary race,
    driven by the Rust sender. Asserts the fixed invariants:
      1. No durably acknowledged row is lost across the P->R boundary.
      2. No server crash; the JVM stays alive through the whole round-trip.
      3. After R->P switch-back, a reconnected QWP connection writes again.
    """
    crash_dir = _crash_artifact_dir()
    sf_dir = scenario_dir / "sf"
    sf_dir.mkdir(parents=True, exist_ok=True)

    # Preserve any native crash stack outside the auto-cleaned scenario tree.
    error_file = crash_dir / "hs_err_p1_%p.log"
    fork_opts = os.environ.get("JAVA_OPTS_FORK", "-Xmx512m")
    os.environ["JAVA_OPTS_FORK"] = f"{fork_opts} -XX:ErrorFile={error_file}"
    LOG.info("switch_roundtrip: ErrorFile=%s", error_file)

    p1 = server_factory("p1")
    p1_ports = p1.start(min_http=True)
    assert p1_ports.min_http is not None
    LOG.info("switch_roundtrip: ready http=%d pg=%d min_http=%d pid=%s",
             p1_ports.http, p1_ports.pg, p1_ports.min_http,
             p1.process.pid if p1.process else "?")

    c_client_rust_sidecar.connect(_connect_string(p1_ports.http, sf_dir))

    accepted_by_fsn: list[tuple[int, int]] = []

    # Phase 1: pre-switch seed.
    c_client_rust_sidecar.send(TABLE, count=PRE, start_index=0)
    seed_fsn = c_client_rust_sidecar.flush()
    accepted_rows = PRE
    accepted_by_fsn.append((seed_fsn, accepted_rows))
    assert c_client_rust_sidecar.await_acked(seed_fsn, _DURABLE_ACK_AWAIT_TIMEOUT_MS), (
        f"seed frame was not durably acked [fsn={seed_fsn}]"
    )
    time.sleep(0.5)
    pre_count = count_rows(port=p1_ports.pg, table=TABLE)
    LOG.info("switch_roundtrip: pre-switch count=%d", pre_count)
    assert pre_count == PRE, f"seed mismatch: expected {PRE}, got {pre_count}"

    # Phase 2: P->R with an aggressive boundary-race write storm.
    assert _submit_switch_tolerant(p1_ports.min_http, "replica", label="switch_roundtrip")
    boundary_accepted = boundary_rejected = 0
    idx = PRE
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        if not p1.is_alive():
            break
        try:
            c_client_rust_sidecar.send(TABLE, count=1, start_index=idx)
            fsn = c_client_rust_sidecar.flush()
            idx += 1
            accepted_rows += 1
            accepted_by_fsn.append((fsn, accepted_rows))
            boundary_accepted += 1
        except SidecarError:
            boundary_rejected += 1
        except Exception as exc:
            LOG.warning("switch_roundtrip: boundary write error: %s", exc)
        try:
            snap = lifecycle(p1_ports.min_http)
            if not snap.get("switchInFlight") and snap.get("currentRole") == "REPLICA":
                break
        except Exception:
            pass
        time.sleep(0.05)
    assert _await_role_tolerant(p1_ports.min_http, "replica", label="switch_roundtrip"), \
        "node did not settle as REPLICA"
    LOG.info("switch_roundtrip: REPLICA settled -- boundary accepted=%d rejected=%d idx=%d",
             boundary_accepted, boundary_rejected, idx)

    # INVARIANT 1: no acknowledged data loss across the boundary.
    replica_count = count_rows(port=p1_ports.pg, table=TABLE)
    acked_fsn = c_client_rust_sidecar.stats().acked
    durably_acked_rows = _durably_acked_rows(accepted_by_fsn, acked_fsn)
    LOG.info("switch_roundtrip: committed=%d (seed=%d accepted=%d acked_fsn=%d durably_acked=%d)",
             replica_count, PRE, accepted_rows, acked_fsn, durably_acked_rows)
    assert p1.is_alive(), "server crashed during P->R boundary-write storm"
    assert replica_count >= durably_acked_rows, (
        f"ACKED-ROW LOSS: count_rows={replica_count} < durably_acked_rows={durably_acked_rows}. "
        f"{durably_acked_rows - replica_count} acknowledged row(s) missing on the settled REPLICA."
    )
    assert replica_count <= accepted_rows, (
        f"UNEXPLAINED ROW GROWTH: count_rows={replica_count} > accepted_rows={accepted_rows}."
    )
    observed_values = fetch_column_sorted(port=p1_ports.pg, table=TABLE, timeout_s=5.0)
    expected_values = list(range(replica_count))
    assert observed_values == expected_values, (
        f"DENSE ROW INVARIANT FAILED: expected [0..{replica_count}), "
        f"observed first={observed_values[:10]}, last={observed_values[-10:]}"
    )

    # Phase 3: R->P switch-back.
    assert _submit_switch_tolerant(p1_ports.min_http, "primary", label="switch_roundtrip")
    assert _await_role_tolerant(p1_ports.min_http, "primary", label="switch_roundtrip"), \
        "node did not settle back to PRIMARY"
    assert p1.is_alive(), "server crashed during R->P switch-back"

    # Phase 4: THE PATH that used to abort the JVM -- reconnect the QWP
    # sidecar, write across a window, and probe an independent HTTP INSERT.
    LOG.info("switch_roundtrip: closing sidecar, reconnecting")
    qwp_results: list[str] = []
    http_results: list[str] = []
    try:
        c_client_rust_sidecar.close()
        c_client_rust_sidecar.connect(_connect_string(p1_ports.http, sf_dir))
    except Exception as exc:  # noqa: BLE001
        LOG.warning("switch_roundtrip: reconnect raised: %s", exc)

    probe_deadline = time.monotonic() + 20.0
    attempt = 0
    crash_observed = False
    crash_detail = ""
    while time.monotonic() < probe_deadline and not crash_observed:
        attempt += 1
        if not p1.is_alive():
            crash_observed = True
            crash_detail = f"server died before QWP attempt {attempt}"
            break
        try:
            c_client_rust_sidecar.send(TABLE, count=1, start_index=idx)
            c_client_rust_sidecar.flush()
            idx += 1
            qwp_results.append(f"a{attempt}:OK")
        except SidecarError as exc:
            qwp_results.append(f"a{attempt}:REJ({exc})")
        except Exception as exc:  # noqa: BLE001
            qwp_results.append(f"a{attempt}:ERR({exc})")
        if attempt % 2 == 0 and p1.is_alive():
            try:
                st, body = _http_insert(p1_ports.http, TABLE, 1_700_000_000_000_000 + attempt)
                http_results.append(f"a{attempt}:{st}:{body[:120]}")
            except Exception as exc:  # noqa: BLE001
                http_results.append(f"a{attempt}:HTTP_ERR({exc})")
        time.sleep(0.5)

    # Give the rebuilt uploader's keepalive/throttled upload path time to run.
    time.sleep(3.0)
    if not p1.is_alive():
        crash_observed = True
        rc = p1.process.returncode if p1.process else None
        crash_detail = (crash_detail + "; " if crash_detail else "") + \
            f"server exited: {_signal_name(rc)}"

    LOG.info("switch_roundtrip: QWP post-switch results: %s", qwp_results)
    LOG.info("switch_roundtrip: HTTP post-switch results: %s", http_results)
    final_count = count_rows(port=p1_ports.pg, table=TABLE)
    LOG.info("switch_roundtrip: final count=%d", final_count)

    hs_err_files = sorted(crash_dir.glob("hs_err_p1_*.log"))
    stderr_log = log_dir / "p1.stderr.log"
    tail = ""
    if stderr_log.exists():
        tail = "\n".join(
            stderr_log.read_text(encoding="utf-8", errors="replace").splitlines()[-50:])

    # INVARIANT 2: no crash.
    assert not crash_observed, (
        "CRASH/SHUTDOWN REGRESSION on the post-R->P reconnect-write path.\n"
        f"detail: {crash_detail}\n"
        f"boundary_accepted={boundary_accepted} rejected={boundary_rejected}\n"
        f"qwp_results={qwp_results}\nhttp_results={http_results}\n"
        f"hs_err: {[str(f) for f in hs_err_files]}\n"
        f"--- p1.stderr tail ---\n{tail}\n"
    )

    # INVARIANT 3: after switch-back the engine admits PRIMARY writes again.
    qwp_ok = any(r.endswith(":OK") for r in qwp_results)
    http_ok = any(":200:" in r for r in http_results)
    assert qwp_ok or http_ok, (
        "POST-SWITCH WRITE REGRESSION: no QWP or HTTP write succeeded after R->P switch-back.\n"
        f"qwp_results={qwp_results}\nhttp_results={http_results}\n"
        f"final lifecycle={_lifecycle_brief(p1_ports.min_http)}\n"
    )
    assert final_count > PRE, (
        f"POST-SWITCH WRITE REGRESSION: final committed count {final_count} did not exceed the "
        f"seed {PRE}; post-switch writes did not land on the PRIMARY."
    )
    LOG.info("switch_roundtrip: PASS -- 0 replica writes, no crash, PRIMARY admits writes; "
             "final_count=%d", final_count)
