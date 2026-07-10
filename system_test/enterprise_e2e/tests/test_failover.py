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
import shutil
import time
from pathlib import Path
from typing import Optional

import pytest

# server.wait_port_free and pg_query helpers come from the Enterprise
# harness on PYTHONPATH (set up by conftest.py).
from lib.lifecycle import submit_switch
from lib.obj_store import ObjStore
from lib.pg_query import count_rows, execute_ddl, wait_for_count, wait_for_dense_sequence
from lib.server import wait_port_free

from c_client_sidecar import (
    CClientRustColumnSidecar,
    CClientRustEgressSidecar,
    CClientRustSidecar,
)

LOG = logging.getLogger(__name__)

ZONE_A = "zone-A"
ZONE_B = "zone-B"

_REQUIRES_OBJ_STORE_FREEZE = pytest.mark.skipif(
    not all(hasattr(ObjStore, name) for name in ("freeze", "thaw", "frozen")),
    reason="requires questdb-enterprise PR #1094 ObjStore durability gate",
)


def _connect_string(http_port: int, sf_dir: Optional[Path], *,
                    request_durable_ack: bool = True,
                    reconnect_max_ms: int = 60_000,
                    close_flush_timeout_ms: int = 5_000,
                    sender_id: Optional[str] = None,
                    sf_max_bytes: Optional[int] = None) -> str:
    """Row-major QWP/WebSocket connect string.

    ``sf_dir`` selects the store-and-forward backend, the distinction the
    two SF-survival tests below pivot on:
      * a path  -> **disk-backed** SF (``SfaSlotQueue::open``). The on-disk
        ``.sfa`` segments under ``<sf_dir>/<sender_id>/`` outlive the
        *client* process, so a fresh sender that opens the same slot
        recovers and replays them.
      * ``None`` -> **in-memory** SF (``SfaSlotQueue::open_memory``). The
        queue lives in the sender's address space, so it survives a
        *server* restart/failover while the client stays alive, but is lost
        if the client itself dies.

    ``sender_id`` names the slot under ``sf_dir`` (disk-backed only).
    ``sf_max_bytes`` caps one SF segment; a small value seals many segments
    from a modest ingest, exercising multi-segment recovery cheaply.
    """
    parts = [
        f"ws::addr=127.0.0.1:{http_port}",
        # Canonical "username" keyword (both Java and Rust senders
        # accept it; "user" is a Java-only alias).
        "username=admin",
        "password=quest",
        f"reconnect_max_duration_millis={reconnect_max_ms}",
        f"close_flush_timeout_millis={close_flush_timeout_ms}",
    ]
    if sf_dir is not None:
        parts.append(f"sf_dir={sf_dir}")
    if sender_id is not None:
        parts.append(f"sender_id={sender_id}")
    if sf_max_bytes is not None:
        parts.append(f"sf_max_bytes={sf_max_bytes}")
    if request_durable_ack:
        parts.append("request_durable_ack=on")
    return ";".join(parts) + ";"


def _connect_string_columnar(http_port: int, sf_dir: Path, *,
                             request_durable_ack: bool = True,
                             reconnect_max_ms: int = 60_000,
                             close_flush_timeout_ms: int = 5_000) -> str:
    """Column-major QWP/WebSocket connect string. Same store-and-forward
    knobs as :func:`_connect_string`, with the ``ws`` schema and the
    single-slot pool the column sender's store-and-forward path requires
    (``pool_size=1`` / ``pool_max=1``)."""
    parts = [
        f"ws::addr=127.0.0.1:{http_port}",
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


def _egress_connect_string(http_ports: list[int], *, zone: Optional[str] = None,
                           target: str = "any",
                           failover_max_duration_ms: int = 15_000,
                           auth_timeout_ms: int = 5_000) -> str:
    """Multi-endpoint read-side (``Reader``) connect string.

    ``target=any`` (default) binds the first reachable endpoint in addr-order
    and may fail over to any of the others regardless of role. ``zone`` is a
    *preference*: the Reader prefers endpoints whose server-advertised
    ``zone_id`` matches, but it is not a hard filter -- it still binds a
    different-zone host when no same-zone host is reachable. Same-zone
    preference only biases selection once at least two hosts have been
    classified; the first connect against an all-Unknown tracker is decided
    by addr-order. The short failover/auth timeouts keep the per-host walk
    snappy so kill-and-rebind stays well inside the assertion budget.
    """
    addr = ",".join(f"127.0.0.1:{p}" for p in http_ports)
    parts = [
        f"ws::addr={addr}",
        "username=admin",
        "password=quest",
        f"target={target}",
        f"failover_max_duration_ms={failover_max_duration_ms}",
        f"auth_timeout_ms={auth_timeout_ms}",
    ]
    if zone is not None:
        parts.append(f"zone={zone}")
    return ";".join(parts) + ";"


def _wait_for_zone(egress_sidecar: CClientRustEgressSidecar, expected_zone: str,
                   *, timeout_s: float = 15.0) -> None:
    """Poll ``SHOW_ZONE`` until it settles on ``expected_zone`` (or fail).

    A read-side failover takes a few hundred ms: the bound socket surfaces a
    transport error, the Reader's per-execute reconnect loop walks to a
    surviving endpoint, re-issues the query, and only then returns a fresh
    SHOW_ZONE reply. A single immediate assert would race the first
    just-failed attempt, so we poll -- the *terminal* zone is asserted;
    transient values along the way are tolerated."""
    deadline = time.monotonic() + timeout_s
    observed = ""
    while time.monotonic() < deadline:
        observed = egress_sidecar.show_zone()
        if observed == expected_zone:
            return
        time.sleep(0.1)
    pytest.fail(
        f"SHOW_ZONE never settled on {expected_zone!r} within {timeout_s}s "
        f"(last observed: {observed!r}); the Reader did not bind the "
        f"expected zone."
    )


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
def test_sender_kill9_sf_recovery_replays_c_client_rust(
    server_factory,
    c_client_rust_sidecar: CClientRustSidecar,
    c_client_rust_sidecar_binary: Path,
    scenario_dir: Path,
    log_dir: Path,
) -> None:
    """Disk-backed store-and-forward (``sf_dir`` set) must survive the
    *client's own* death. SIGKILL the sender mid-flight while the primary
    stays alive, then bring up a fresh sender on the same
    ``sf_dir``/``sender_id``: it recovers the on-disk ``.sfa`` segments the
    dead predecessor left behind and replays them to the live primary.

    Contrast with the failover tests, which kill the *server* and lean on a
    still-alive sender to reconnect. Here the *server* never dies; the
    *sender* does, and durability rides entirely on the on-disk SF.

    Dedup is mandatory: a fresh sender negotiates ``fsnAtZero`` from 0 on its
    new WebSocket, so it re-delivers frames P1 had already accepted before
    the kill. ``request_durable_ack=on`` prevents *loss*, not *duplicates*
    after a sender crash; ``DEDUP UPSERT KEYS(timestamp, v)`` is the
    documented escape valve, collapsing replayed rows back to one per ``v``
    while leaving gaps and corruption for the dense-sequence oracle to
    catch."""
    table = "trades_sender_kill_c_client_rust"
    row_count = 20_000
    sf_dir = scenario_dir / "sf"
    # 64 KiB segments roll the SF across several sealed .sfa files, so the
    # recovery path scans a real multi-segment ring rather than one open
    # segment. A single QWP publication must fit inside ONE segment, so the
    # rows are published in sub-segment chunks below (one big flush of all
    # 20k rows would be ~320 KiB and be rejected with
    # PayloadExceedsByteCapacity).
    sf_max_bytes = 64 * 1024
    chunk_rows = 1_000  # ~16 KiB per publication, comfortably under 64 KiB

    p1 = server_factory("p1")
    p1_ports = p1.start()

    # Pre-create with DEDUP on (timestamp, v). The SEND verb emits one row
    # per ``v`` at timestamp ``1_000_000us * (v + 1)``, so (timestamp, v) is
    # unique per logical row -- duplicate replay collapses; gaps and
    # corruption do not.
    execute_ddl(port=p1_ports.pg, ddl=(
        f'CREATE TABLE "{table}" ('
        "v LONG, timestamp TIMESTAMP"
        ") TIMESTAMP(timestamp) PARTITION BY DAY WAL "
        "DEDUP UPSERT KEYS(timestamp, v)"
    ))

    cs = _connect_string(p1_ports.http, sf_dir, sender_id="primary",
                         sf_max_bytes=sf_max_bytes)
    c_client_rust_sidecar.connect(cs)
    # Publish in sub-segment chunks: each flush is one QWP publication that
    # must fit in a single segment, and the sequence of them seals multiple
    # .sfa segments for the recovery walk.
    for start in range(0, row_count, chunk_rows):
        c_client_rust_sidecar.send(table, count=chunk_rows, start_index=start)
        c_client_rust_sidecar.flush()

    # Small settle so some frames leave the wire and P1 OKs them; the rest
    # stay in the SF. With request_durable_ack=on only the (slower) WAL
    # upload trims, so the .sfa segments still hold un-acked frames at kill.
    time.sleep(0.5)

    # SIGKILL the sender process group -- no CLOSE, no EXIT. The kernel
    # releases the slot lock; the .sfa segments are untouched on disk.
    c_client_rust_sidecar.kill_9()
    assert c_client_rust_sidecar.process is not None
    assert c_client_rust_sidecar.process.poll() is not None, \
        "sender must be dead before recovery"

    # Guard that we're actually exercising recovery: un-trimmed .sfa
    # segments must survive in the slot dir. (Had everything been
    # durably-acked and trimmed, P1 would already hold every row and the
    # restart would replay nothing.)
    slot_dir = sf_dir / "primary"
    sfa_files = sorted(slot_dir.glob("sf-*.sfa")) if slot_dir.exists() else []
    assert sfa_files, (
        f"expected un-trimmed .sfa segments in {slot_dir} after SIGKILL; "
        f"test is not exercising the recovery path. dir contents: "
        f"{list(slot_dir.iterdir()) if slot_dir.exists() else '<missing>'}"
    )
    LOG.info("recovery surface: %d .sfa segment(s) survived SIGKILL in %s",
             len(sfa_files), slot_dir)

    # Fresh sender on the SAME sf_dir + sender_id: it opens the same slot,
    # recovers the segment ring, and replays it to the (still-alive) P1.
    sidecar2 = CClientRustSidecar(
        log_dir=log_dir,
        classpath=None,
        name="c-client-rust-sidecar-restart",
        binary_path=c_client_rust_sidecar_binary,
    )
    sidecar2.start()
    try:
        sidecar2.connect(cs)
        wait_for_dense_sequence(port=p1_ports.pg, table=table,
                                expected_count=row_count, timeout_s=90.0)
    finally:
        sidecar2.stop()


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_inmem_sf_survives_primary_failover_c_client_rust(
    server_factory,
    c_client_rust_sidecar: CClientRustSidecar,
    obj_store,
    scenario_dir: Path,
) -> None:
    """In-memory store-and-forward (no ``sf_dir``) must survive a *server*
    failover while the client process stays alive. Same kill -9 + wipe +
    successor-on-the-same-port disaster as the headline failover test, but
    the sender holds its un-acked frames in RAM (``open_memory``) instead of
    on disk: the still-running client reconnects to P2 and replays from
    memory.

    Complement of ``test_sender_kill9_sf_recovery_replays_c_client_rust``:
    that one survives the *client* dying (disk-backed SF); this one survives
    the *server* dying (in-memory SF) and would lose data if the client
    itself were killed. ``request_durable_ack=on`` is what makes it hold:
    without it the in-memory queue would trim on a plain server OK and the
    OK-but-not-durable tail would vanish on failover. No dedup needed -- P2
    is a fresh root with a wiped object store, so the replayed frames are
    the only copy."""
    table = "trades_inmem_failover_c_client_rust"
    row_count = 50

    p1 = server_factory("p1")
    p1_ports = p1.start()

    # sf_dir=None -> in-memory SFA queue. The sidecar process must outlive
    # the server failover for this copy to survive.
    c_client_rust_sidecar.connect(_connect_string(p1_ports.http, None))
    c_client_rust_sidecar.send(table, count=row_count, start_index=0)
    c_client_rust_sidecar.flush()

    # Brief settle so P1 OKs at least the first batch -- the OK-but-not-
    # durable case the in-memory queue must not trim away.
    time.sleep(0.5)

    p1.kill_9()
    wait_port_free(p1_ports.http)
    wait_port_free(p1_ports.pg)

    # Worst-case disaster: wipe local disk AND object store. The only
    # surviving copy is the sender's in-memory SF.
    if p1.db_root.exists():
        shutil.rmtree(p1.db_root)
    obj_store.wipe()

    p2 = server_factory("p2", db_root_name="p2-fresh")
    p2.start(http_port=p1_ports.http, pg_port=p1_ports.pg)

    # The still-alive sender reconnects and replays from RAM; every row must
    # land on the successor.
    wait_for_dense_sequence(port=p1_ports.pg, table=table,
                            expected_count=row_count, timeout_s=60.0)


@pytest.mark.c_client
@pytest.mark.c_client_rust
@pytest.mark.parametrize(
    "src",
    [
        # Store-and-forward column shapes only. The direct-path `polars`
        # shape (Db::flush_polars_dataframe) does NOT survive this body's
        # kill-9 + object-store wipe -- it has no client-side SF replay --
        # so its failover coverage lives in test_polars_db_failover.py, which
        # uses the correct no-wipe survival model and asserts auto-redrive.
        "chunk",
        "arrow",
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


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_primary_failover_egress_read_c_client_rust(
    server_factory,
    c_client_rust_egress_sidecar: CClientRustEgressSidecar,
    obj_store,
    scenario_dir: Path,
) -> None:
    """Read-side failover, driven by the c-questdb-client Rust binding's
    ``Reader``. A primary + replica share the object store; the reader binds the
    primary, then after a kill -9 the next query rebinds to the replica and
    still returns every row.

    Egress failover differs from the ingress tests -- the data must already
    exist on the survivor (the replica applied the replicated WAL), so there is
    no client-side replay. The assertion is that the read transparently walks to
    a live endpoint and the row count is unchanged."""
    table = "trades_egress_failover_c_client_rust"
    row_count = 200

    p1 = server_factory("p1")
    p1_ports = p1.start()
    r1 = server_factory("r1", role="replica")
    r1_ports = r1.start()

    # Seed on the primary; the WAL replicates to the replica via the shared
    # object store.
    execute_ddl(port=p1_ports.pg, ddl=(
        f'CREATE TABLE "{table}" AS ('
        f'  SELECT x - 1 AS v, timestamp_sequence(0, 1000000) AS ts'
        f'  FROM long_sequence({row_count})'
        f') TIMESTAMP(ts) PARTITION BY DAY WAL'
    ))
    # Wait for the replica to catch up before we read from the cluster.
    wait_for_count(port=r1_ports.pg, table=table, expected=row_count, timeout_s=60.0)

    # Reader binds p1 first (addr-order); confirm the full read.
    cs = _egress_connect_string([p1_ports.http, r1_ports.http])
    c_client_rust_egress_sidecar.connect(cs)
    rows, _ = c_client_rust_egress_sidecar.query(f'SELECT * FROM "{table}"')
    assert rows == row_count

    # Kill the bound primary; the next query must rebind to the replica.
    p1.kill_9()
    wait_port_free(p1_ports.http)

    rows, _ = c_client_rust_egress_sidecar.query(f'SELECT * FROM "{table}"')
    assert rows == row_count, f"expected {row_count} rows after failover, got {rows}"


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_zone_failover_stays_in_zone_then_crosses_c_client_rust(
    server_factory,
    c_client_rust_egress_sidecar: CClientRustEgressSidecar,
) -> None:
    """Zone-aware read-side failover across 3 servers in 2 zones, driven by
    the c-questdb-client Rust binding's ``Reader``.

    Topology: two zone-A servers (a1, a2) and one zone-B server (b1), listed
    zone-A-first in ``addr=`` with ``zone=A``. The oracle is the Reader
    itself -- ``SHOW_ZONE`` runs ``(SHOW PARAMETERS) WHERE
    property_path = 'replication.zone'`` over the bound connection, so the
    answer can only come from whichever server the client is currently
    talking to (a cached client-side zone would be caught here).

    Sequence:
      1. Bind -> zone A (addr-order first wins on the all-Unknown tracker).
      2. Kill the bound zone-A host (a1). Intra-zone failover: the surviving
         zone-A sibling (a2) keeps the client in zone A. This is the
         "still connected to zone A" guarantee while any zone-A host lives.
      3. Kill the last zone-A host (a2). Zone exhaustion: ``zone=`` is a
         preference, NOT a hard filter, so the Reader falls through to
         zone B (b1) rather than erroring. The cross happens exactly at
         exhaustion -- not one host early.

    Complements the single-server-per-zone egress test above and mirrors
    the Enterprise Java ``test_zone_failover.py`` suite; the binding under
    test is the Rust ``Reader``, the Enterprise side only orchestrates the
    forked zoned servers."""
    a1 = server_factory("a1", zone=ZONE_A)
    a1_ports = a1.start()
    a2 = server_factory("a2", role="replica", zone=ZONE_A)
    a2_ports = a2.start()
    b1 = server_factory("b1", role="replica", zone=ZONE_B)
    b1_ports = b1.start()

    # zone-A endpoints first in addr-order so the initial bind and the first
    # (intra-zone) failover deterministically stay in zone A -- the
    # all-Unknown tracker decides the first pick by addr-order, and a
    # surviving zone-A sibling earlier in the list beats the zone-B host.
    cs = _egress_connect_string(
        [a1_ports.http, a2_ports.http, b1_ports.http], zone=ZONE_A)
    c_client_rust_egress_sidecar.connect(cs)
    assert c_client_rust_egress_sidecar.show_zone() == ZONE_A, \
        "addr=A,A,B with zone=A should bind a zone-A host first"

    # Intra-zone failover: kill the bound zone-A host; the client must stay
    # in zone A via the surviving zone-A sibling (a2).
    a1.kill_9()
    wait_port_free(a1_ports.http)
    _wait_for_zone(c_client_rust_egress_sidecar, ZONE_A)

    # Zone exhaustion: kill the last zone-A host. Only zone B remains, so
    # the zone preference falls through (preference, not hard filter).
    a2.kill_9()
    wait_port_free(a2_ports.http)
    _wait_for_zone(c_client_rust_egress_sidecar, ZONE_B)


# ---------------------------------------------------------------------------
# Additional deterministic failover scenarios ported from the Enterprise
# reference suite (questdb-ent/e2e/tests/test_failover.py). Bodies inlined
# per binding (cheap duplication; the bindings diverge over time). The
# sender-side recovery test ``test_sender_kill9_sf_recovery_replays`` is
# already covered above, so it is not re-ported here.
# ---------------------------------------------------------------------------


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_failover_during_active_send_c_client_rust(
    server_factory,
    c_client_rust_sidecar: CClientRustSidecar,
    obj_store,
    scenario_dir: Path,
) -> None:
    """Kill P1 *while* the Rust sender is still pushing batches -- the
    sender has an in-flight send buffer at the moment the wire dies, not
    just an idle connection."""
    table = "trades_inflight_c_client_rust"
    sf_dir = scenario_dir / "sf"
    batches = 5
    rows_per_batch = 20
    expected = batches * rows_per_batch

    p1 = server_factory("p1")
    p1_ports = p1.start()
    c_client_rust_sidecar.connect(_connect_string(p1_ports.http, sf_dir))

    # First batch synchronously, then more batches without flushing between
    # them so the I/O thread is actively draining frames when we yank the rug.
    c_client_rust_sidecar.send(table, count=rows_per_batch, start_index=0)
    c_client_rust_sidecar.flush()
    for i in range(1, batches):
        c_client_rust_sidecar.send(table, count=rows_per_batch,
                                   start_index=i * rows_per_batch)
    p1.kill_9()
    wait_port_free(p1_ports.http)
    wait_port_free(p1_ports.pg)
    if p1.db_root.exists():
        shutil.rmtree(p1.db_root)
    obj_store.wipe()

    p2 = server_factory("p2", db_root_name="p2-fresh")
    p2.start(http_port=p1_ports.http, pg_port=p1_ports.pg)

    # Flush now; the sender reconnects transparently inside the call.
    c_client_rust_sidecar.flush()
    wait_for_dense_sequence(port=p1_ports.pg, table=table,
                            expected_count=expected, timeout_s=60.0)


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_two_failovers_in_one_scenario_c_client_rust(
    server_factory,
    c_client_rust_sidecar: CClientRustSidecar,
    obj_store,
    scenario_dir: Path,
) -> None:
    """Two failovers in a row driven by the Rust sender. Each successor
    picks up where the previous left off; no row is lost across two kill
    events from one sender."""
    table = "trades_two_fail_c_client_rust"
    sf_dir = scenario_dir / "sf"
    rows_per_phase = 25
    expected = rows_per_phase * 3

    p1 = server_factory("p1")
    p1_ports = p1.start()
    c_client_rust_sidecar.connect(_connect_string(p1_ports.http, sf_dir))
    c_client_rust_sidecar.send(table, count=rows_per_phase, start_index=0)
    c_client_rust_sidecar.flush()
    time.sleep(0.5)
    p1.kill_9()
    wait_port_free(p1_ports.http)
    wait_port_free(p1_ports.pg)
    if p1.db_root.exists():
        shutil.rmtree(p1.db_root)
    obj_store.wipe()

    p2 = server_factory("p2", db_root_name="p2-fresh")
    p2.start(http_port=p1_ports.http, pg_port=p1_ports.pg)
    c_client_rust_sidecar.send(table, count=rows_per_phase, start_index=rows_per_phase)
    c_client_rust_sidecar.flush()
    time.sleep(0.5)
    p2.kill_9()
    wait_port_free(p1_ports.http)
    wait_port_free(p1_ports.pg)
    if p2.db_root.exists():
        shutil.rmtree(p2.db_root)
    obj_store.wipe()

    p3 = server_factory("p3", db_root_name="p3-fresh")
    p3.start(http_port=p1_ports.http, pg_port=p1_ports.pg)
    c_client_rust_sidecar.send(table, count=rows_per_phase, start_index=rows_per_phase * 2)
    c_client_rust_sidecar.flush()
    wait_for_dense_sequence(port=p1_ports.pg, table=table,
                            expected_count=expected, timeout_s=90.0)


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_no_request_durable_ack_loses_rows_c_client_rust(
    server_factory,
    c_client_rust_sidecar: CClientRustSidecar,
    obj_store,
    scenario_dir: Path,
) -> None:
    """Negative case: WITHOUT ``request_durable_ack=on`` the SF trims on OK
    frames, so killing P1 between OK and WAL upload then wiping disk +
    object store *should* lose rows. Asserting the loss proves the positive
    failover tests pass *because of* the opt-in, not by luck."""
    table = "trades_no_durable_c_client_rust"
    sf_dir = scenario_dir / "sf"
    row_count = 50

    p1 = server_factory("p1")
    p1_ports = p1.start()
    c_client_rust_sidecar.connect(
        _connect_string(p1_ports.http, sf_dir, request_durable_ack=False))
    c_client_rust_sidecar.send(table, count=row_count, start_index=0)
    published_fsn = c_client_rust_sidecar.flush()
    # Wait deterministically for OK-driven trim to drain the SF.
    assert c_client_rust_sidecar.await_acked(published_fsn, timeout_ms=15_000), (
        f"OKs for fsn={published_fsn} not received within 15s; "
        "cannot set up the OK-driven-trim scenario under test."
    )

    baseline_reconn = c_client_rust_sidecar.stats().reconn_succ

    p1.kill_9()
    wait_port_free(p1_ports.http)
    wait_port_free(p1_ports.pg)
    if p1.db_root.exists():
        shutil.rmtree(p1.db_root)
    obj_store.wipe()

    p2 = server_factory("p2", db_root_name="p2-fresh")
    p2.start(http_port=p1_ports.http, pg_port=p1_ports.pg)

    # Force a reconnect to P2. Unlike the Java client, the Rust sender only
    # (re)connects when it has data to flush -- an idle sender whose SF was
    # OK-trimmed never reconnects on its own. Send a fresh probe row so the
    # sender connects to P2, proving it CAN reach the successor (so the loss
    # assertion below can't pass for a "never reached P2" reason). The probe
    # (index row_count) is the only row P2 receives; the OK-trimmed original
    # batch is gone.
    c_client_rust_sidecar.send(table, count=1, start_index=row_count)
    c_client_rust_sidecar.flush()
    deadline = time.monotonic() + 15.0
    while time.monotonic() < deadline:
        if c_client_rust_sidecar.stats().reconn_succ > baseline_reconn:
            break
        time.sleep(0.1)
    else:
        pytest.fail(
            f"sender never reconnected to P2 within 15s even after a probe send "
            f"(reconn_succ stayed at {baseline_reconn}); the loss assertion "
            "would pass for the wrong reason."
        )

    try:
        observed = count_rows(port=p1_ports.pg, table=table, timeout_s=10.0)
    except TimeoutError:
        # Table never created on P2 -- 100% loss, the strongest form.
        observed = 0
    LOG.info("OK-only trim observed=%d expected_loss=%d", observed, row_count)
    assert observed < row_count, (
        "OK-driven trim is supposed to be vulnerable; if every row still "
        "survives without request_durable_ack=on the test setup isn't "
        "actually exercising the failure mode it claims to."
    )


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_orphan_drainer_durable_ack_survives_kill_c_client_rust(
    server_factory,
    c_client_rust_sidecar: CClientRustSidecar,
    obj_store,
    scenario_dir: Path,
) -> None:
    """The orphan drainer must honour ``request_durable_ack=on``. A "ghost"
    sender writes rows with durable-ack opt-in and closes with
    ``close_flush_timeout_millis=0`` so its SF slot retains the
    un-durably-acked frames; a "foreground" sender with ``drain_orphans=on``
    adopts the orphan slot and must NOT trim it on plain OK before the WAL
    upload is durable. After kill+wipe, only the drainer's SF carries the
    rows forward."""
    table = "trades_orphan_drain_c_client_rust"
    sf_dir = scenario_dir / "sf"
    row_count = 50

    p1 = server_factory("p1")
    p1_ports = p1.start()

    ghost_cs = (
        f"ws::addr=127.0.0.1:{p1_ports.http};"
        "username=admin;password=quest;"
        f"sf_dir={sf_dir};"
        "sender_id=ghost;"
        "request_durable_ack=on;"
        # CLOSE returns immediately; the ghost slot stays full of
        # un-durably-acked frames -- the drainer is what should empty it.
        "close_flush_timeout_millis=0;"
    )
    c_client_rust_sidecar.connect(ghost_cs)
    c_client_rust_sidecar.send(table, count=row_count, start_index=0)
    c_client_rust_sidecar.flush()
    c_client_rust_sidecar.close()

    fg_cs = (
        f"ws::addr=127.0.0.1:{p1_ports.http};"
        "username=admin;password=quest;"
        f"sf_dir={sf_dir};"
        "sender_id=primary;"
        "drain_orphans=on;"
        "request_durable_ack=on;"
        "reconnect_max_duration_millis=60000;"
        "close_flush_timeout_millis=5000;"
    )
    c_client_rust_sidecar.connect(fg_cs)

    # Window for the drainer to schedule, connect, push the orphan frame(s),
    # and receive OK back from P1.
    time.sleep(1.0)

    p1.kill_9()
    wait_port_free(p1_ports.http)
    wait_port_free(p1_ports.pg)
    if p1.db_root.exists():
        shutil.rmtree(p1.db_root)
    obj_store.wipe()

    p2 = server_factory("p2", db_root_name="p2-fresh")
    p2.start(http_port=p1_ports.http, pg_port=p1_ports.pg)

    # When P1 died mid-drain the orphan worker returned RetryLater and stopped:
    # the Rust drainer (drain_orphan_to_completion) does NOT autonomously
    # reconnect to a successor within one attempt. The orphan slot is only
    # re-attempted by a *fresh* orphan scan, which runs on the next CONNECT with
    # drain_orphans=on. Reconnect the foreground sender so a new scan adopts the
    # still-un-acked ghost slot and replays it to P2.
    c_client_rust_sidecar.connect(fg_cs)

    wait_for_dense_sequence(port=p1_ports.pg, table=table,
                            expected_count=row_count, timeout_s=60.0)


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_sender_repeated_sigkill_no_state_corruption_c_client_rust(
    server_factory,
    c_client_rust_sidecar: CClientRustSidecar,
    c_client_rust_sidecar_binary: Path,
    obj_store,
    scenario_dir: Path,
    log_dir: Path,
) -> None:
    """Multi-cycle SIGKILL torture. Kill-and-restart the Rust sender N times
    against the same primary and the same ``sf_dir``/``sender_id``; the
    on-disk slot state must stay consistent through every recovery. Catches
    bugs that *accumulate* across cycles -- stale .sfa files, slot-lock
    release flakes, sealed segments that never trim. ``sf_max_bytes`` forces
    frequent rotation so each cycle leaves multiple sealed segments."""
    table = "trades_multi_cycle_c_client_rust"
    cycles = 6
    rows_per_cycle = 200
    total = cycles * rows_per_cycle
    sf_dir = scenario_dir / "sf"
    settle_secs = [0.0, 0.1, 0.3, 0.0, 0.2, 0.5]
    assert len(settle_secs) == cycles

    p1 = server_factory("p1")
    p1_ports = p1.start()
    execute_ddl(port=p1_ports.pg, ddl=(
        f'CREATE TABLE "{table}" ('
        "v LONG, timestamp TIMESTAMP"
        ") TIMESTAMP(timestamp) PARTITION BY DAY WAL "
        "DEDUP UPSERT KEYS(timestamp, v)"
    ))

    cs = _connect_string(p1_ports.http, sf_dir, sender_id="primary", sf_max_bytes=8192)

    fixture_consumed = False
    for cycle in range(cycles):
        if not fixture_consumed:
            current = c_client_rust_sidecar
            fixture_consumed = True
        else:
            current = CClientRustSidecar(
                log_dir=log_dir, classpath=None,
                name=f"c-client-rust-cycle{cycle}",
                binary_path=c_client_rust_sidecar_binary,
            )
            current.start()
        current.connect(cs)
        current.send(table, count=rows_per_cycle, start_index=cycle * rows_per_cycle)
        current.flush()
        if settle_secs[cycle] > 0:
            time.sleep(settle_secs[cycle])
        current.kill_9()
        LOG.info("cycle %d/%d: killed after %dms settle",
                 cycle + 1, cycles, int(settle_secs[cycle] * 1000))

    slot_dir = sf_dir / "primary"
    sfa_files = sorted(slot_dir.glob("sf-*.sfa")) if slot_dir.exists() else []
    assert sfa_files, (
        f"expected un-trimmed .sfa segments in {slot_dir} after {cycles} "
        f"SIGKILL cycles; recovery path is not under test. dir contents: "
        f"{list(slot_dir.iterdir()) if slot_dir.exists() else '<missing>'}"
    )
    LOG.info("recovery surface after %d kills: %d .sfa file(s) in %s",
             cycles, len(sfa_files), slot_dir)

    final = CClientRustSidecar(
        log_dir=log_dir, classpath=None, name="c-client-rust-final",
        binary_path=c_client_rust_sidecar_binary,
    )
    final.start()
    try:
        final.connect(cs)
        wait_for_dense_sequence(port=p1_ports.pg, table=table,
                                expected_count=total, timeout_s=180.0)
    finally:
        final.stop()


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_partial_ack_sealed_segment_replay_dedup_collapses_c_client_rust(
    server_factory,
    c_client_rust_sidecar: CClientRustSidecar,
    c_client_rust_sidecar_binary: Path,
    obj_store,
    scenario_dir: Path,
    log_dir: Path,
) -> None:
    """Recovery through a partially-acked surviving sealed segment is correct:
    the persisted ``ack-watermark`` carries the previous sender's durable-ack
    high-water mark across the SIGKILL boundary, so the new sender positions
    past the already-acked prefix instead of re-replaying it. Any residual
    re-replay is absorbed by DEDUP on the target."""
    table = "trades_partial_ack_c_client_rust"
    batch_size = 200
    batches = 10
    row_count = batch_size * batches
    sf_dir = scenario_dir / "sf"

    p1 = server_factory("p1")
    p1_ports = p1.start()
    execute_ddl(port=p1_ports.pg, ddl=(
        f'CREATE TABLE "{table}" ('
        "v LONG, timestamp TIMESTAMP"
        ") TIMESTAMP(timestamp) PARTITION BY DAY WAL "
        "DEDUP UPSERT KEYS(timestamp, v)"
    ))

    cs = _connect_string(p1_ports.http, sf_dir, sender_id="primary", sf_max_bytes=32768)
    c_client_rust_sidecar.connect(cs)
    # Many smaller flushes -> many frames -> exercise the
    # multiple-frames-per-segment path that makes partial-ack possible.
    for b in range(batches):
        c_client_rust_sidecar.send(table, count=batch_size, start_index=b * batch_size)
        c_client_rust_sidecar.flush()

    # Let the WAL apply + durable-ack cadence trim the early sealed segments
    # while the most-recent ones stay un-durably-acked.
    time.sleep(4.0)

    slot_dir = sf_dir / "primary"
    pre_kill = sorted(slot_dir.glob("sf-*.sfa")) if slot_dir.exists() else []
    LOG.info("pre-kill SF surface: %d .sfa file(s) survived partial trim",
             len(pre_kill))
    assert pre_kill, (
        "expected at least one un-durably-acked .sfa segment at kill time; "
        "partial-ack recovery path is not under test. If this consistently "
        "fails, raise sf_max_bytes or reduce the settle time."
    )

    c_client_rust_sidecar.kill_9()

    sidecar2 = CClientRustSidecar(
        log_dir=log_dir, classpath=None, name="c-client-rust-sidecar-restart",
        binary_path=c_client_rust_sidecar_binary,
    )
    sidecar2.start()
    try:
        sidecar2.connect(cs)
        wait_for_dense_sequence(port=p1_ports.pg, table=table,
                                expected_count=row_count, timeout_s=120.0)
    finally:
        sidecar2.stop()


@pytest.mark.c_client
@pytest.mark.c_client_rust
@_REQUIRES_OBJ_STORE_FREEZE
def test_orphan_drainer_durable_ack_trim_timing_c_client_rust(
    server_factory,
    c_client_rust_sidecar: CClientRustSidecar,
    obj_store,
    scenario_dir: Path,
) -> None:
    """No-kill pin of the exact line fix 19b9fda changed: an adopted orphan
    slot under ``request_durable_ack=on`` must be trimmed ONLY once the WAL
    upload is durable, never on a plain server OK.

    Where ``test_orphan_drainer_durable_ack_survives_kill`` proves the
    end-to-end *consequence* (rows survive a failover) and so needs a kill +
    object-store wipe, this test pins the *cause* directly and deterministically
    by holding the OK->durable window open with the harness durability gate
    (``obj_store.freeze()`` makes the filesystem store reject writes, so the
    server's durable-upload watermark -- and therefore the durable ack -- cannot
    advance while local commits still get a plain OK). With that window held:

      1. assert the adopted orphan ``.sfa`` segments are RETAINED after the OK,
      2. thaw, then assert they are trimmed once the durable ack arrives.

    Pre-fix (orphan drainer hard-coded OK-trim) step 1 fails the instant the
    drainer receives the OK -- the slot is trimmed while the store is still
    frozen. No failover, no wipe; it fails fast and points straight at the
    regression."""
    table = "trades_orphan_trim_timing_c_client_rust"
    sf_dir = scenario_dir / "sf"
    ghost_slot = sf_dir / "ghost"
    row_count = 50

    def orphan_sfa() -> list[Path]:
        return sorted(ghost_slot.glob("sf-*.sfa")) if ghost_slot.exists() else []

    p1 = server_factory("p1")
    p1_ports = p1.start()

    # Pre-create while the store is writable so the table's structure is
    # registered before the freeze; the test pivots on the durability of the
    # *row* commits, not the create. DEDUP keeps the post-thaw re-scan replay
    # idempotent so the dense-sequence oracle stays focused on trim timing
    # (duplicate-freeness across a partial-durability kill is the subject of
    # test_orphan_drainer_partial_durability_at_kill).
    execute_ddl(port=p1_ports.pg, ddl=(
        f'CREATE TABLE "{table}" ('
        "v LONG, timestamp TIMESTAMP"
        ") TIMESTAMP(timestamp) PARTITION BY DAY WAL "
        "DEDUP UPSERT KEYS(timestamp, v)"
    ))

    # Hold the OK->durable window open across the whole orphan handoff. frozen()
    # thaws on exit even if an assertion inside raises, so a failure never
    # leaves the store read-only for teardown.
    with obj_store.frozen():
        # Ghost writes durable-ack rows and abandons the slot
        # (close_flush_timeout_millis=0 -> CLOSE returns immediately), leaving
        # ghost/ full of OK'd-but-not-durable frames: the orphan.
        ghost_cs = (
            f"ws::addr=127.0.0.1:{p1_ports.http};"
            "username=admin;password=quest;"
            f"sf_dir={sf_dir};"
            "sender_id=ghost;"
            "request_durable_ack=on;"
            "close_flush_timeout_millis=0;"
        )
        c_client_rust_sidecar.connect(ghost_cs)
        c_client_rust_sidecar.send(table, count=row_count, start_index=0)
        c_client_rust_sidecar.flush()
        c_client_rust_sidecar.close()
        assert orphan_sfa(), (
            f"ghost slot {ghost_slot} should hold .sfa frames after an abandon "
            f"with close_flush_timeout_millis=0; got {list(ghost_slot.iterdir()) if ghost_slot.exists() else '<missing>'}"
        )

        # Foreground sender adopts the orphan slot; its background drainer pushes
        # the frames and P1 returns a plain OK (local commit), but no durable ack
        # can arrive while the store is frozen.
        fg_cs = (
            f"ws::addr=127.0.0.1:{p1_ports.http};"
            "username=admin;password=quest;"
            f"sf_dir={sf_dir};"
            "sender_id=primary;"
            "drain_orphans=on;"
            "request_durable_ack=on;"
            "reconnect_max_duration_millis=60000;"
            "close_flush_timeout_millis=5000;"
        )
        c_client_rust_sidecar.connect(fg_cs)

        # The orphan rows reaching P1 proves the drainer pushed them and P1 OK'd
        # them -- the exact moment pre-fix OK-trim would delete the slot.
        wait_for_count(port=p1_ports.pg, table=table, expected=row_count, timeout_s=30.0)

        # THE CRUX: with the store still frozen no durable ack is possible, so a
        # correct (post-19b9fda) drainer RETAINS the adopted orphan slot. Hold
        # the assertion a few seconds so a pre-fix OK-trim has ample time to
        # fire after the OK.
        hold_deadline = time.monotonic() + 5.0
        while time.monotonic() < hold_deadline:
            assert orphan_sfa(), (
                "orphan .sfa segments were trimmed on a plain server OK while the "
                "object store was frozen (no durable ack possible) -- the orphan "
                "drainer is OK-trimming instead of honouring request_durable_ack "
                "(regression of c-questdb-client fix 19b9fda)."
            )
            time.sleep(0.25)

    # Thawed: the uploader's retry now publishes the parked WAL, the durable
    # watermark advances, and the server can finally durable-ack. Re-scan via a
    # fresh foreground connect (the proven orphan re-adoption path) so the
    # now-durable slot is completed, and assert the .sfa segments disappear.
    c_client_rust_sidecar.connect(fg_cs)
    trim_deadline = time.monotonic() + 60.0
    while time.monotonic() < trim_deadline:
        if not orphan_sfa():
            break
        time.sleep(0.5)
    else:
        pytest.fail(
            f"orphan .sfa segments in {ghost_slot} were never trimmed after the "
            "object store was thawed and the rows became durable; the drainer is "
            "not completing the durably-acked orphan slot."
        )

    # Loss-free and (via DEDUP) duplicate-free: every orphan row is on P1 exactly
    # once. Confirms the retained-then-trimmed slot actually carried the data.
    wait_for_dense_sequence(port=p1_ports.pg, table=table,
                            expected_count=row_count, timeout_s=30.0)


@pytest.mark.c_client
@pytest.mark.c_client_rust
@_REQUIRES_OBJ_STORE_FREEZE
def test_orphan_drainer_partial_durability_at_kill_c_client_rust(
    server_factory,
    c_client_rust_sidecar: CClientRustSidecar,
    obj_store,
    scenario_dir: Path,
) -> None:
    """Partial durability across a kill: when an orphan slot is killed with
    some frames already durable and some only OK'd, exactly the non-durable
    frames must replay -- loss-free AND duplicate-free.

    Split the orphan into two halves on one ghost slot:
      * batch 1 is made durable BEFORE the freeze (await_acked under
        request_durable_ack=on returns only on the durable ack, so the ghost
        slot durably trims it -- those frames now live in the object store and
        are gone from the slot);
      * batch 2 is written AFTER ``obj_store.freeze()``, so it is OK'd but never
        durable; the ghost abandons the slot with only batch 2 left in it.

    The foreground drainer adopts the slot and pushes batch 2 (P1 OKs locally).
    P1 is then killed *without wiping the object store*. The successor comes up
    as a replica on the dead primary's ports -- a fresh primary would refuse the
    populated store (ER007: the object store owns another database's DataID),
    whereas a replica legitimately adopts the store's DataID and downloads the
    durable batch 1 -- and is then promoted so it can take the ingress replay.
    The re-adopting drainer replays batch 2 from the slot to the promoted
    successor. The dense-sequence oracle then proves it holds exactly ``[0..N)``
    -- batch 1 recovered from the store (not lost, not duplicated by a stale
    re-push), batch 2 recovered from the client SF. No DEDUP on the table, so a
    spurious re-push of the already-durable half would surface as extra rows.

    Pre-fix, batch 2 would have been OK-trimmed off the adopted slot before the
    kill and lost (gap at ``[M..N)``); the OK-trim regression that 19b9fda fixes
    is what this guards on the partial-durability boundary."""
    table = "trades_orphan_partial_dura_c_client_rust"
    sf_dir = scenario_dir / "sf"
    ghost_slot = sf_dir / "ghost"
    row_count = 60
    durable_rows = 30  # batch 1: [0..30) made durable before the freeze
    # batch 2: [30..60) OK'd-but-not-durable, carried across the kill in the SF

    def orphan_sfa() -> list[Path]:
        return sorted(ghost_slot.glob("sf-*.sfa")) if ghost_slot.exists() else []

    p1 = server_factory("p1")
    p1_ports = p1.start()

    # No DEDUP: the dense-sequence oracle must be free to catch a duplicate of
    # the already-durable half as an extra row.
    execute_ddl(port=p1_ports.pg, ddl=(
        f'CREATE TABLE "{table}" ('
        "v LONG, timestamp TIMESTAMP"
        ") TIMESTAMP(timestamp) PARTITION BY DAY WAL"
    ))

    ghost_cs = (
        f"ws::addr=127.0.0.1:{p1_ports.http};"
        "username=admin;password=quest;"
        f"sf_dir={sf_dir};"
        "sender_id=ghost;"
        "request_durable_ack=on;"
        "close_flush_timeout_millis=0;"
    )
    c_client_rust_sidecar.connect(ghost_cs)

    # Batch 1 -> durable. await_acked under request_durable_ack=on only returns
    # once the WAL upload is durable, so this both proves batch 1 reached the
    # object store and durably trims it out of the ghost slot.
    c_client_rust_sidecar.send(table, count=durable_rows, start_index=0)
    fsn1 = c_client_rust_sidecar.flush()
    assert c_client_rust_sidecar.await_acked(fsn1, timeout_ms=30_000), (
        f"batch 1 (fsn={fsn1}) was not durably acked within 30s; cannot set up "
        "the partial-durability split under test."
    )

    # Freeze: from here nothing can become durable. Batch 2 is OK'd-but-not-
    # durable, and the ghost abandons the slot holding only batch 2.
    obj_store.freeze()
    try:
        c_client_rust_sidecar.send(table, count=row_count - durable_rows,
                                   start_index=durable_rows)
        c_client_rust_sidecar.flush()
        c_client_rust_sidecar.close()
        assert orphan_sfa(), (
            f"ghost slot {ghost_slot} should retain batch-2 .sfa frames after "
            "abandon; the durable batch-1 trim must not have emptied the slot."
        )

        # Foreground drainer adopts the slot and pushes batch 2; P1 OKs locally
        # but cannot durable-ack while frozen.
        fg_cs = (
            f"ws::addr=127.0.0.1:{p1_ports.http};"
            "username=admin;password=quest;"
            f"sf_dir={sf_dir};"
            "sender_id=primary;"
            "drain_orphans=on;"
            "request_durable_ack=on;"
            "reconnect_max_duration_millis=60000;"
            "close_flush_timeout_millis=5000;"
        )
        c_client_rust_sidecar.connect(fg_cs)

        # All N rows applied on P1 (batch 1 + drained batch 2) confirms the
        # drainer pushed batch 2 and P1 OK'd it -- the pre-fix OK-trim point.
        wait_for_count(port=p1_ports.pg, table=table, expected=row_count, timeout_s=30.0)

        # Kill with batch 2 still only OK'd. Crucially do NOT wipe the object
        # store: batch 1 is durable there and must survive on the successor.
        p1.kill_9()
        wait_port_free(p1_ports.http)
        wait_port_free(p1_ports.pg)
        if p1.db_root.exists():
            shutil.rmtree(p1.db_root)
    finally:
        # Thaw so the successor can read the store (and write its own uploads).
        obj_store.thaw()

    # Successor comes up as a replica on the dead primary's ports: a fresh
    # primary would hit ER007 against the populated store, but a replica adopts
    # the store's DataID and downloads the durable batch 1. min_http exposes the
    # lifecycle control plane used to promote it below.
    p2 = server_factory("p2", db_root_name="p2-fresh", role="replica")
    p2_ports = p2.start(http_port=p1_ports.http, pg_port=p1_ports.pg, min_http=True)

    # Replica has caught up once batch 1 is visible; batch 2 never reached the
    # store (frozen until after the kill), so the replica must NOT have it yet.
    wait_for_count(port=p1_ports.pg, table=table, expected=durable_rows, timeout_s=60.0)

    # Promote so the successor accepts the ingress replay of batch 2.
    assert p2_ports.min_http is not None, "replica must expose min-http for promotion"
    submit_switch(p2_ports.min_http, "primary", wait=True, wait_timeout_s=60.0)

    # Re-scan so the drainer re-adopts the still-un-acked ghost slot and replays
    # batch 2 to the promoted successor.
    c_client_rust_sidecar.connect(fg_cs)

    # Exactly [0..N): batch 1 recovered from the store, batch 2 replayed from the
    # client SF, no gap (loss-free) and no extra (the already-durable half is not
    # re-pushed -> duplicate-free).
    wait_for_dense_sequence(port=p1_ports.pg, table=table,
                            expected_count=row_count, timeout_s=90.0)


@pytest.mark.c_client
@pytest.mark.c_client_rust
@_REQUIRES_OBJ_STORE_FREEZE
def test_orphan_drainer_multi_slot_durable_ack_survives_kill_c_client_rust(
    server_factory,
    c_client_rust_sidecar: CClientRustSidecar,
    obj_store,
    scenario_dir: Path,
) -> None:
    """Several orphan slots adopted concurrently (``max_background_drainers>1``)
    must ALL survive a primary failover under ``request_durable_ack=on``: every
    non-durable frame across every slot replays to the successor.

    ``K`` ghost senders each abandon a slot full of OK'd-but-not-durable frames
    over a disjoint ``v`` range; one foreground sender with ``drain_orphans=on``
    and ``max_background_drainers=K`` adopts all ``K`` at once. The object store
    is frozen for the whole handoff so nothing becomes durable -- this is what
    makes the kill deterministic: no frame is durably trimmed off a client slot
    before the kill, so the subsequent object-store wipe cannot strand a
    legitimately-durable row. After kill + disk/store wipe, a fresh successor on
    the same ports holds nothing; only the ``K`` client slots carry the data,
    and a re-scan replays them all. The dense-sequence oracle proves every
    slot's frames landed exactly once -- nothing lost, nothing duplicated.

    Pre-fix every adopted slot OK-trims on the plain OK, so the whole
    ``[0..K*R)`` range vanishes on failover (the single-slot
    ``..._survives_kill`` test is this with ``K=1``; here the value is the
    concurrent multi-drainer fan-out)."""
    table = "trades_orphan_multi_slot_c_client_rust"
    sf_dir = scenario_dir / "sf"
    slots = 3
    rows_per_slot = 40
    total = slots * rows_per_slot

    def slot_sfa(i: int) -> list[Path]:
        d = sf_dir / f"ghost{i}"
        return sorted(d.glob("sf-*.sfa")) if d.exists() else []

    p1 = server_factory("p1")
    p1_ports = p1.start()

    # DEDUP keeps P1's row count clean at the retention check below: a pre-fix
    # drainer re-pushes frames under concurrent multi-slot drain, and without
    # DEDUP that overshoot would trip the count gate during setup instead of the
    # retention assertion that names the actual regression. (P2 is wiped fresh
    # and auto-creates without DEDUP, but needs none -- post-wipe replay delivers
    # each frame once.)
    execute_ddl(port=p1_ports.pg, ddl=(
        f'CREATE TABLE "{table}" ('
        "v LONG, timestamp TIMESTAMP"
        ") TIMESTAMP(timestamp) PARTITION BY DAY WAL "
        "DEDUP UPSERT KEYS(timestamp, v)"
    ))

    # Freeze spans the whole handoff AND the kill: thawing before the kill would
    # let the uploader durably-trim some slots and the wipe below would then
    # lose them. thaw() runs in the finally so teardown can always clean up.
    obj_store.freeze()
    try:
        # K ghosts, each abandoning a slot of OK'd-but-not-durable frames over a
        # disjoint v-range.
        for i in range(slots):
            ghost_cs = (
                f"ws::addr=127.0.0.1:{p1_ports.http};"
                "username=admin;password=quest;"
                f"sf_dir={sf_dir};"
                f"sender_id=ghost{i};"
                "request_durable_ack=on;"
                "close_flush_timeout_millis=0;"
            )
            c_client_rust_sidecar.connect(ghost_cs)
            c_client_rust_sidecar.send(table, count=rows_per_slot,
                                       start_index=i * rows_per_slot)
            c_client_rust_sidecar.flush()
            c_client_rust_sidecar.close()
            assert slot_sfa(i), (
                f"ghost{i} slot should hold .sfa frames after an abandon with "
                "close_flush_timeout_millis=0."
            )

        # One foreground sender adopts all K slots concurrently.
        fg_cs = (
            f"ws::addr=127.0.0.1:{p1_ports.http};"
            "username=admin;password=quest;"
            f"sf_dir={sf_dir};"
            "sender_id=primary;"
            "drain_orphans=on;"
            "request_durable_ack=on;"
            f"max_background_drainers={slots};"
            "reconnect_max_duration_millis=60000;"
            "close_flush_timeout_millis=5000;"
        )
        c_client_rust_sidecar.connect(fg_cs)

        # Every slot's frames pushed + OK'd on P1 (frozen => none durable).
        wait_for_count(port=p1_ports.pg, table=table, expected=total, timeout_s=45.0)

        # CRUX: with the store frozen no durable ack is possible, so every
        # adopted slot must be RETAINED. Pre-fix each slot OK-trims here under
        # the concurrent drainers; hold a few seconds so that trim would fire.
        hold_deadline = time.monotonic() + 3.0
        while time.monotonic() < hold_deadline:
            retained = [i for i in range(slots) if slot_sfa(i)]
            assert len(retained) == slots, (
                f"only slots {retained} of {slots} retained their .sfa while the "
                "store was frozen (no durable ack possible) -- a concurrently "
                "adopted orphan slot OK-trimmed instead of honouring "
                "request_durable_ack (regression of fix 19b9fda)."
            )
            time.sleep(0.25)

        # Kill with all K slots still only OK'd.
        p1.kill_9()
        wait_port_free(p1_ports.http)
        wait_port_free(p1_ports.pg)
        if p1.db_root.exists():
            shutil.rmtree(p1.db_root)
    finally:
        obj_store.thaw()

    # Worst-case disaster: only the K client slots survive. (wipe self-thaws, so
    # ordering vs the finally above is immaterial.)
    obj_store.wipe()

    p2 = server_factory("p2", db_root_name="p2-fresh")
    p2.start(http_port=p1_ports.http, pg_port=p1_ports.pg)

    # A fresh orphan scan re-adopts all K slots and replays them to the successor.
    c_client_rust_sidecar.connect(fg_cs)
    wait_for_dense_sequence(port=p1_ports.pg, table=table,
                            expected_count=total, timeout_s=90.0)


@pytest.mark.c_client
@pytest.mark.c_client_rust
@_REQUIRES_OBJ_STORE_FREEZE
def test_orphan_drainer_durable_ack_survives_drain_reconnect_c_client_rust(
    server_factory,
    c_client_rust_sidecar: CClientRustSidecar,
    obj_store,
    scenario_dir: Path,
) -> None:
    """A drain connection dropping and reconnecting mid-drain must not
    prematurely trim un-durable orphan frames.

    With the object store frozen so the adopted slot can never durable-ack,
    repeatedly tear the drainer down and re-adopt (each foreground reconnect
    drops the previous drain connection and starts a fresh orphan scan). Across
    every reconnect the slot must be RETAINED -- never trimmed on the connection
    churn nor on the plain OKs the drainer keeps collecting. Thawing then
    completes the slot normally.

    No kill: the primary stays up throughout, so the churn is isolated to the
    drain connection (this is the angle the kill-based tests can't isolate --
    there the connection drop and the data-loss window coincide). Pre-fix the
    very first adoption OK-trims the slot, so there is nothing left for the
    reconnect loop to retain and it fails on cycle 0."""
    table = "trades_orphan_drain_reconnect_c_client_rust"
    sf_dir = scenario_dir / "sf"
    ghost_slot = sf_dir / "ghost"
    row_count = 50
    reconnects = 3

    def orphan_sfa() -> list[Path]:
        return sorted(ghost_slot.glob("sf-*.sfa")) if ghost_slot.exists() else []

    p1 = server_factory("p1")
    p1_ports = p1.start()

    # DEDUP so each reconnect's re-adoption replay is idempotent on the
    # still-alive primary; this test asserts trim discipline, not dup-freeness.
    execute_ddl(port=p1_ports.pg, ddl=(
        f'CREATE TABLE "{table}" ('
        "v LONG, timestamp TIMESTAMP"
        ") TIMESTAMP(timestamp) PARTITION BY DAY WAL "
        "DEDUP UPSERT KEYS(timestamp, v)"
    ))

    fg_cs = (
        f"ws::addr=127.0.0.1:{p1_ports.http};"
        "username=admin;password=quest;"
        f"sf_dir={sf_dir};"
        "sender_id=primary;"
        "drain_orphans=on;"
        "request_durable_ack=on;"
        "reconnect_max_duration_millis=60000;"
        "close_flush_timeout_millis=5000;"
    )

    with obj_store.frozen():
        # Ghost abandons an orphan slot of OK'd-but-not-durable frames.
        ghost_cs = (
            f"ws::addr=127.0.0.1:{p1_ports.http};"
            "username=admin;password=quest;"
            f"sf_dir={sf_dir};"
            "sender_id=ghost;"
            "request_durable_ack=on;"
            "close_flush_timeout_millis=0;"
        )
        c_client_rust_sidecar.connect(ghost_cs)
        c_client_rust_sidecar.send(table, count=row_count, start_index=0)
        c_client_rust_sidecar.flush()
        c_client_rust_sidecar.close()
        assert orphan_sfa(), "ghost slot should hold .sfa frames after abandon"

        # Drop-and-re-adopt the orphan repeatedly. The store stays frozen, so no
        # durable ack can arrive and the slot must survive every reconnect.
        for cycle in range(reconnects):
            c_client_rust_sidecar.connect(fg_cs)  # drops prior drainer; fresh scan re-adopts
            wait_for_count(port=p1_ports.pg, table=table, expected=row_count, timeout_s=30.0)
            hold = time.monotonic() + 2.0
            while time.monotonic() < hold:
                assert orphan_sfa(), (
                    f"orphan .sfa trimmed across drain reconnect #{cycle} while the "
                    "store was frozen (no durable ack possible) -- premature trim on "
                    "connection churn or a plain OK (regression of fix 19b9fda)."
                )
                time.sleep(0.2)

    # Thaw + one more reconnect lets the now-durable slot complete and trim.
    c_client_rust_sidecar.connect(fg_cs)
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        if not orphan_sfa():
            break
        time.sleep(0.5)
    else:
        pytest.fail(
            f"orphan .sfa in {ghost_slot} never trimmed after thaw + reconnect; "
            "the drainer is not completing the durably-acked slot."
        )

    # Loss-free and (via DEDUP) duplicate-free despite the reconnect churn.
    wait_for_dense_sequence(port=p1_ports.pg, table=table,
                            expected_count=row_count, timeout_s=30.0)
