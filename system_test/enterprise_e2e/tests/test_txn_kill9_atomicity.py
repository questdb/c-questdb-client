"""
Transactional-atomicity kill tests, ported from the Enterprise java-client
suite (``questdb-ent/e2e/tests/test_txn_kill9_atomicity.py``).

PORT STATUS: 1 of 4 scenarios portable today.

The Java scenarios pivot on the sender's ``transaction=on`` mode: deferred
publishes carry ``FLAG_DEFER_COMMIT``, only an explicit FLUSH commits, and
a successor sender on the same slot must RETIRE (not replay) an orphan
deferred tail. The Rust QWP/WS row sender does not implement that mode:

  * ``questdb-rs/src/ingress/sender.rs:318-323`` -- transactional flushes
    are explicitly rejected for QWP/WebSocket
    ("Transactional flushes are not supported for QWP/WebSocket.").
  * ``questdb-rs/src/ingress/conf.rs`` -- no ``transaction`` config key
    (contrast ``request_durable_ack`` at conf.rs:209).
  * ``questdb-rs/src/ingress/buffer/qwp.rs:3559`` -- the encoder CAN frame
    deferred commits (``encode_ws_replay_message_with_defer``, flag applied
    at qwp.rs:3654) but the only production caller hardcodes
    ``defer_commit=false``; ``qwp_ws_publisher.rs:52`` uses the non-defer
    wrapper. Dead capability on the publish path.
  * No orphan-tail retirement in SF recovery (no retirement logic in
    ``qwp_ws_sfa_slot.rs`` / ``qwp_ws_sfa_segment.rs``; the segment scan
    handles torn frames only).

Blocked until the client grows ``transaction=on`` + tail retirement:

  - test_kill9_mid_txn_uncommitted_rows_never_appear
  - test_kill9_whole_log_deferred_fast_path_retirement
  - test_kill9_between_deferred_flushes_deterministic (also needs a
    FLUSH_DEFER sidecar verb, which has no client API to bind to today)

Ported below: the commit-boundary scenario. In the Rust client every FLUSH
is commit-bearing, so the Java oracle's core -- "the SF log ends with a
commit-bearing frame; recovery must not throw away committed-but-not-
durably-acked rows, and replay must not duplicate them" -- is exactly
expressible without the deferred prefix. The distinctive mechanics vs the
existing ``test_sender_kill9_sf_recovery_replays_c_client_rust`` is the
ZERO-SETTLE kill: SIGKILL races the I/O loop immediately after FLUSH
returns, pinning the contract that FLUSH's return already implies the
publication is durable in the SF log (rows may never have reached the
wire at all -- recovery alone must deliver them).
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from lib.pg_query import execute_ddl, fetch_column_sorted, wait_for_count

from c_client_sidecar import CClientRustSidecar

LOG = logging.getLogger(__name__)


def _connect_string(http_port: int, sf_dir: Path, *, sender_id: str) -> str:
    """Disk-backed SF connect string. ``request_durable_ack=on`` keeps the
    OK acks from trimming the SF log -- only the (slower, WAL-upload-gated)
    durable acks trim -- so the .sfa segments still hold the committed
    frames when the kill lands and the restart genuinely recovers."""
    return ";".join([
        f"ws::addr=127.0.0.1:{http_port}",
        "username=admin",
        "password=quest",
        f"sf_dir={sf_dir}",
        f"sender_id={sender_id}",
        "request_durable_ack=on",
        "reconnect_max_duration_millis=60000",
        "close_flush_timeout_millis=5000",
    ]) + ";"


def _assert_sf_segments_on_disk(sf_dir: Path, sender_id: str) -> None:
    """Guard against a vacuous pass: the killed sender's slot dir must
    still hold .sfa segments, otherwise the restart would have nothing to
    recover and the oracle would be satisfied by the pre-kill wire sends
    alone. (Rust slot naming: ``<sf_dir>/<sender_id>`` -- ``from_conf`` is
    a single sender, not the pooled facade, so no ``-0`` suffix.)"""
    slot_dir = sf_dir / sender_id
    sfa_files = list(slot_dir.glob("sf-*.sfa")) if slot_dir.exists() else []
    assert sfa_files, (
        f"expected .sfa segments in {slot_dir} after SIGKILL; the restart "
        f"would not exercise recovery. dir contents: "
        f"{list(slot_dir.iterdir()) if slot_dir.exists() else '<missing>'}"
    )
    LOG.info("recovery surface: %d .sfa file(s) in %s", len(sfa_files), slot_dir)


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_kill9_at_commit_boundary_no_orphan_c_client_rust(
        server_factory,
        c_client_rust_sidecar: CClientRustSidecar,
        c_client_rust_sidecar_binary: Path,
        scenario_dir: Path,
        log_dir: Path) -> None:
    """SIGKILL immediately AFTER the commit flush returns, with zero
    settle. The SF log ends with a commit-bearing frame, so recovery must
    not retire anything: every committed row must survive, whether it
    reached the server before the kill (dedup collapses the replay) or
    only ever lived in the SF log (replay delivers it).

    Port of the Java scenario minus the ``transaction=on`` deferred prefix
    (unsupported by the Rust client -- see module docstring). Guards the
    same failure modes the Java test pins at the commit boundary:

      - loss: recovery (or a future over-eager tail-retirement heuristic,
        e.g. 'retire everything after the last durable ack' instead of
        'after the last commit boundary') throws away committed-but-not-
        durably-acked rows -> count < 40 after restart;
      - duplication: replay of frames the still-alive server already
        applied fails to collapse -> dedup escape valve broken end-to-end.

    Table has DEDUP: nothing was durably acked before the kill (the WAL
    uploader runs on a longer cadence than the zero-settle window), so
    with the server still alive the successor replays the committed log
    and the replay must collapse to exactly one row per ``v``.
    """
    table = "trades_txn_boundary_c_client_rust"
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

    cs = _connect_string(p1_ports.http, sf_dir, sender_id=sender_id)
    c_client_rust_sidecar.connect(cs)

    # One commit-bearing publication. FLUSH returning means the frame is
    # durable in the SF log; whether it also reached the wire is up to the
    # race below -- both outcomes must satisfy the oracle.
    c_client_rust_sidecar.send(table, count=40, start_index=0)
    # Adaptation vs Java: Rust FSNs are 0-based (first publication is
    # fsn=0; the sidecar replies -1 only for an empty-buffer flush), so
    # the vacuousness guard is >= 0 where the Java original used > 0.
    committed_fsn = c_client_rust_sidecar.flush()
    assert committed_fsn >= 0, f"commit flush published nothing (fsn={committed_fsn})"

    # ZERO settle: kill races the I/O loop right at the commit boundary.
    c_client_rust_sidecar.kill_9()
    assert c_client_rust_sidecar.process is not None
    assert c_client_rust_sidecar.process.poll() is not None, "sidecar must be dead"

    _assert_sf_segments_on_disk(sf_dir, sender_id)

    sidecar2 = CClientRustSidecar(
        log_dir=log_dir,
        classpath=None,
        name="c-client-rust-sidecar-boundary-restart",
        binary_path=c_client_rust_sidecar_binary,
    )
    sidecar2.start()
    try:
        sidecar2.connect(cs)
        # Every committed row must survive recovery.
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
