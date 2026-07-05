"""
QWP egress ``SERVER_INFO`` role + zone advertisement tests for the
c-questdb-client Rust binding's ``Reader``.

Ported from the Enterprise Java JUnit suites
``questdb-ent/src/test/java/com/questdb/cairo/wal/transfer/QwpEgressServerInfoRoleTest.java``
and ``QwpEgressServerInfoZoneTest.java`` (which drive the java-client
``QwpQueryClient`` against in-process two-node pairs). Re-expressed here
against forked ENT servers with the Rust egress sidecar.

Unlike the committed ``test_target_filter.py`` / ``test_zone_failover.py``
siblings (which pin *routing decisions* and the ``SHOW PARAMETERS``
server-side oracle), this file pins the **wire advertisement itself**: the
role byte and the ``CAP_ZONE`` capability bit + zone trailer the server
puts on the ``SERVER_INFO`` frame, as decoded by the production Rust
client (``questdb-rs/src/egress/server_event.rs::ServerInfo``,
``wire/capabilities.rs::CAP_ZONE``).

Dedup notes (vs. the committed egress ports):

* ``testMultiEndpointTargetReplicaPicksReplica`` is covered 1:1 by
  ``test_target_filter.py::test_target_replica_skips_primary_at_startup_c_client_rust``
  (primary listed first, SERVER_INFO role asserted) -- not duplicated here.
* ``testTargetPrimaryAgainstReplicaOnlyRaisesMismatch`` here is the
  mirror direction of
  ``test_target_filter.py::test_target_replica_fails_when_only_primary_available_c_client_rust``;
  both directions are pinned because they exercise different reject
  classifications (STANDALONE acceptance differs between the two filters).

Sidecar surface used (``qwp_egress_sidecar.rs``):

* ``SERVER_INFO`` -> ``zone=<id|<unset>> role=<byte> cap_zone=<0|1>``;
  ``cap_zone`` is the decoded ``capabilities & CAP_ZONE`` bit, added so
  the "omits CAP_ZONE" scenarios can distinguish "zone configured as
  empty" from "zone unset" exactly like the Java assertions on
  ``QwpServerInfo.getCapabilities()``.
* ``QUERY_ROW`` -> first result row rendered as ``col=value`` tokens,
  used for the replica-data-parity fingerprint.
* ``QUERY`` -> now reports ``resets= pre_reset_rows= last_replay_rows=``
  (from ``Cursor::failover_resets``), used by the mid-stream-disconnect
  replay scenario as the observable stand-in for the Java handler's
  ``onFailoverReset`` + before/after batch counters.
"""

from __future__ import annotations

import logging
import time

import pytest

from lib.pg_query import execute_ddl
from lib.sidecar import SidecarError

from c_client_sidecar import CClientRustEgressSidecar
from tests.qwp_sql_switch import wait_count_at_least

LOG = logging.getLogger(__name__)

# SERVER_INFO role bytes (questdb-rs egress/wire/roles.rs; identical to
# the Java QwpEgressMsgKind constants).
ROLE_PRIMARY = 1
ROLE_REPLICA = 2

ZONE_UTF8 = "eu-west-1a-中文-éñ-🚀"


def _connect_string(addrs: list[tuple[str, int]], *,
                    target: str = "any",
                    zone: str | None = None,
                    failover: str | None = None,
                    max_batch_rows: int | None = None,
                    failover_max_duration_ms: int = 15_000,
                    auth_timeout_ms: int = 5_000) -> str:
    """Egress connect string. Duplicated per file (suite convention;
    defaults diverge over time): this file defaults ``target=any``
    because most scenarios pin the *advertisement*, not routing."""
    addr_str = ",".join(f"{h}:{p}" for h, p in addrs)
    parts = [
        f"ws::addr={addr_str}",
        "username=admin",
        "password=quest",
        f"target={target}",
        f"failover_max_duration_ms={failover_max_duration_ms}",
        f"auth_timeout_ms={auth_timeout_ms}",
    ]
    if zone is not None:
        parts.append(f"zone={zone}")
    if failover is not None:
        parts.append(f"failover={failover}")
    if max_batch_rows is not None:
        parts.append(f"max_batch_rows={max_batch_rows}")
    return ";".join(parts) + ";"


def _server_info_kv(egress: CClientRustEgressSidecar) -> dict[str, str]:
    """Raw SERVER_INFO reply as a k=v dict. The shared harness wrapper
    (:meth:`lib.egress_sidecar.EgressSidecar.server_info`) drops the
    ``cap_zone`` token (its dataclass predates it), so the capability
    assertions read the raw reply. Uses the wrapper's own private
    plumbing rather than a parallel socket -- same process, same
    protocol, one source of truth."""
    egress._send("SERVER_INFO")
    reply = egress._expect_ok()
    return dict(p.split("=", 1) for p in reply if "=" in p)


def _query_kv(egress: CClientRustEgressSidecar, sql: str) -> dict[str, str]:
    """Raw QUERY reply: positional ``rows``/``latency_ms`` plus the
    trailing k=v failover-observability tokens."""
    egress._send(f"QUERY {sql}")
    reply = egress._expect_ok()
    kv = dict(p.split("=", 1) for p in reply if "=" in p)
    kv["rows"] = reply[0]
    kv["latency_ms"] = reply[1]
    return kv


def _query_row(egress: CClientRustEgressSidecar, sql: str) -> dict[str, str]:
    """First result row of ``sql`` as a column-name -> rendered-value
    dict (sidecar ``QUERY_ROW`` verb)."""
    egress._send(f"QUERY_ROW {sql}")
    reply = egress._expect_ok()
    return dict(p.split("=", 1) for p in reply if "=" in p)


# ---------------------------------------------------------------------------
# Role advertisement (QwpEgressServerInfoRoleTest)
# ---------------------------------------------------------------------------


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_primary_reports_primary_role_c_client_rust(
    server_factory,
    c_client_rust_egress_sidecar: CClientRustEgressSidecar,
) -> None:
    """An Enterprise PRIMARY must advertise ``ROLE_PRIMARY`` on the
    SERVER_INFO frame and the Rust client must surface exactly that
    byte. ``target=any`` so the assertion is purely about what the
    server advertised, not about any routing filter."""
    p1 = server_factory("p1", role="primary")
    p1_ports = p1.start()

    c_client_rust_egress_sidecar.connect(
        _connect_string([("127.0.0.1", p1_ports.http)])
    )
    info = c_client_rust_egress_sidecar.server_info()
    assert info.role == ROLE_PRIMARY, \
        f"Enterprise PRIMARY must surface ROLE_PRIMARY ({ROLE_PRIMARY}); got {info.role}"


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_replica_reports_replica_role_c_client_rust(
    server_factory,
    c_client_rust_egress_sidecar: CClientRustEgressSidecar,
) -> None:
    """An Enterprise REPLICA must advertise ``ROLE_REPLICA``. The
    primary runs alongside (the replica needs a live object store
    lineage to boot), but the client connects to the replica only."""
    p1 = server_factory("p1", role="primary")
    p1.start()
    r1 = server_factory("r1", role="replica")
    r1_ports = r1.start()

    c_client_rust_egress_sidecar.connect(
        _connect_string([("127.0.0.1", r1_ports.http)])
    )
    info = c_client_rust_egress_sidecar.server_info()
    assert info.role == ROLE_REPLICA, \
        f"Enterprise REPLICA must surface ROLE_REPLICA ({ROLE_REPLICA}); got {info.role}"


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_multi_endpoint_target_primary_picks_primary_c_client_rust(
    server_factory,
    c_client_rust_egress_sidecar: CClientRustEgressSidecar,
) -> None:
    """``target=primary`` with the REPLICA listed first must walk past
    the replica (role reject) and bind the primary. Mirror of
    ``test_target_filter.py::test_target_replica_skips_primary_at_startup``
    for the opposite filter direction -- the Java suite pins both
    because the two filters classify STANDALONE differently, so a
    shared-code regression can break one direction only."""
    p1 = server_factory("p1", role="primary")
    p1_ports = p1.start()
    r1 = server_factory("r1", role="replica")
    r1_ports = r1.start()

    # Replica FIRST so any bug that ignored target= on the initial bind
    # would land on the replica and fail the role assertion.
    c_client_rust_egress_sidecar.connect(
        _connect_string(
            [("127.0.0.1", r1_ports.http), ("127.0.0.1", p1_ports.http)],
            target="primary",
        )
    )
    info = c_client_rust_egress_sidecar.server_info()
    assert info.role == ROLE_PRIMARY, \
        f"target=primary must route to the primary; got role={info.role}"


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_target_primary_against_replica_only_raises_mismatch_c_client_rust(
    server_factory,
    c_client_rust_egress_sidecar: CClientRustEgressSidecar,
) -> None:
    """``target=primary`` against a replica-only address list must fail
    loudly with a role-mismatch error identifying both the target and
    the observed role -- the java-client asserts
    ``QwpRoleMismatchException.getLastObserved().getRole() == ROLE_REPLICA``;
    the Rust error message carries the same facts
    (``... role=replica ... does not match target=Primary``, enum Debug
    casing, hence the case-insensitive matches)."""
    p1 = server_factory("p1", role="primary")
    p1.start()
    r1 = server_factory("r1", role="replica")
    r1_ports = r1.start()

    cs = _connect_string(
        [("127.0.0.1", r1_ports.http)],
        target="primary",
    )
    with pytest.raises(SidecarError, match=r"(?i)target=primary") as exc_info:
        c_client_rust_egress_sidecar.connect(cs)
    assert "replica" in str(exc_info.value).lower(), (
        "the mismatch error must carry the last-observed role (replica), "
        f"got: {exc_info.value}"
    )


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_read_from_replica_returns_same_data_as_primary_c_client_rust(
    server_factory,
    c_client_rust_egress_sidecar: CClientRustEgressSidecar,
) -> None:
    """Data-correctness under replication: a stationary row set written
    to the primary must read back identically through a replica-bound
    egress client. Guards against a replica-only read path that
    silently returns a different projection or partial data.

    Adaptation from the JUnit original (which compared 32 decoded rows
    field-by-field in-process): the sidecar QUERY verb only surfaces
    row counts, so the comparison uses an aggregate fingerprint row
    (count / sum(id) / sum(price) / label stats) decoded through the
    egress wire on BOTH bindings via ``QUERY_ROW`` -- any dropped,
    duplicated, or value-corrupted row moves at least one component.
    Deterministic labels (no ``rnd_symbol``) keep the fingerprint
    reproducible on re-runs."""
    p1 = server_factory("p1", role="primary")
    p1_ports = p1.start()
    r1 = server_factory("r1", role="replica")
    r1_ports = r1.start()

    execute_ddl(
        port=p1_ports.pg,
        ddl="CREATE TABLE repl_read (id LONG, label SYMBOL, price DOUBLE, ts TIMESTAMP) "
            "TIMESTAMP(ts) PARTITION BY DAY WAL",
    )
    execute_ddl(
        port=p1_ports.pg,
        ddl="INSERT INTO repl_read "
            "SELECT x, CAST('s' || (x % 4) AS SYMBOL), x * 1.5, x::TIMESTAMP "
            "FROM long_sequence(32)",
    )
    # Replica applied every txn before any read comparison (the JUnit
    # original's waitTableReplicated).
    wait_count_at_least(r1_ports.pg, "repl_read", 32, timeout_s=60.0)

    fingerprint_sql = (
        "SELECT count(*) cnt, sum(id) sum_id, sum(price) sum_price, "
        "count(label) cnt_label, sum(length(label)) sum_label_len "
        "FROM repl_read"
    )

    c_client_rust_egress_sidecar.connect(
        _connect_string([("127.0.0.1", p1_ports.http)], target="primary")
    )
    from_primary = _query_row(c_client_rust_egress_sidecar, fingerprint_sql)

    c_client_rust_egress_sidecar.connect(
        _connect_string([("127.0.0.1", r1_ports.http)], target="replica")
    )
    from_replica = _query_row(c_client_rust_egress_sidecar, fingerprint_sql)

    assert from_primary.get("cnt") == "32", \
        f"primary must serve the full 32-row set; fingerprint={from_primary}"
    assert from_replica == from_primary, (
        "replica-bound read must return byte-identical data to the primary; "
        f"primary={from_primary} replica={from_replica}"
    )


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_failover_to_replica_replays_after_mid_stream_disconnect_c_client_rust(
    server_factory,
    c_client_rust_egress_sidecar: CClientRustEgressSidecar,
) -> None:
    """Mid-stream failover: the bound primary dies while a result is
    streaming; the cursor must transparently reconnect to the replica
    and REPLAY the query from the start, delivering the full row set on
    the new connection.

    The JUnit original arms an in-JVM server hook
    (``DEBUG_FORCE_TRANSPORT_FAILURE_AFTER_BATCHES``) to force the
    disconnect after exactly one batch; forked servers offer no such
    hook, so this port stretches the stream wall-clock and kills the
    primary from the test thread mid-flight. Sizing note: a plain scan
    of even 500k x ~100-byte rows completes in ~100ms on localhost
    (measured), leaving no kill window -- so the query CROSS JOINs the
    200k-row table with ``long_sequence(50)`` (10M rows, ~1GB). The
    nested-loop join streams progressively (no upfront ORDER BY
    materialization), holding the stream open for seconds. Both nodes
    compute the identical deterministic result, so the replayed total
    is exact. The observable oracle maps 1:1:

    * ``onFailoverReset`` fired            -> ``resets >= 1``
    * ``batchesBeforeReset >= 1``          -> ``pre_reset_rows >= 1``
    * ``rowsAfterReset == rowCount``       -> ``last_replay_rows == N``
    * ``RESULT_END totalRows == rowCount`` -> replay ran to the terminal
      frame (``last_replay_rows`` only counts a completed final replay).

    Data is stationary and fully replicated before the kill, so the
    replayed result equals the primary's. Content parity between the
    two nodes is pinned separately by the same-data fingerprint test;
    this one pins the *replay* semantics (a client that silently
    RESUMED instead of replaying would deliver last_replay_rows < N)."""
    rows = 200_000
    mult = 50
    total = rows * mult

    p1 = server_factory("p1", role="primary")
    p1_ports = p1.start()
    r1 = server_factory("r1", role="replica")
    r1_ports = r1.start()

    execute_ddl(
        port=p1_ports.pg,
        ddl="CREATE TABLE failover_t (id LONG, pad STRING, ts TIMESTAMP) "
            "TIMESTAMP(ts) PARTITION BY DAY WAL",
    )
    execute_ddl(
        port=p1_ports.pg,
        ddl=f"INSERT INTO failover_t "
            f"SELECT x, rnd_str(90, 110, 0), x::TIMESTAMP FROM long_sequence({rows})",
        timeout_s=120.0,
    )
    wait_count_at_least(r1_ports.pg, "failover_t", rows, timeout_s=120.0)

    # Primary first, replica second; target=any so both qualify and the
    # walk binds the primary on connect (addr order). Small batches keep
    # the stream long enough for the kill to land mid-flight.
    c_client_rust_egress_sidecar.connect(
        _connect_string(
            [("127.0.0.1", p1_ports.http), ("127.0.0.1", r1_ports.http)],
            failover="on",
            max_batch_rows=1024,
            failover_max_duration_ms=30_000,
        )
    )
    info = c_client_rust_egress_sidecar.server_info()
    assert info.role == ROLE_PRIMARY, \
        "client must land on primary for the failover setup"

    # Fire the query, then kill the primary while the result streams.
    # 0.6s sits inside the multi-second stream window: the nested-loop
    # cross join starts delivering batches immediately (no sort
    # materialization -> pre_reset_rows >= 1 by then) and the full 10M
    # rows take several seconds (so the disconnect is genuinely
    # mid-stream).
    c_client_rust_egress_sidecar._send(
        f"QUERY SELECT a.id, a.pad FROM failover_t a "
        f"CROSS JOIN long_sequence({mult})"
    )
    time.sleep(0.6)
    p1.kill_9()

    reply = c_client_rust_egress_sidecar._expect_ok()  # raises SidecarError on ERR
    kv = dict(p.split("=", 1) for p in reply if "=" in p)
    diag = f"reply={reply!r}"

    assert int(kv["resets"]) >= 1, \
        f"the mid-stream kill must trigger at least one failover reset [{diag}]"
    assert int(kv["pre_reset_rows"]) >= 1, (
        "the primary must have delivered at least one batch before the "
        f"disconnect (kill landed too early -- widen the result set?) [{diag}]"
    )
    assert int(kv["last_replay_rows"]) == total, (
        "the replay on the replica must deliver the FULL row set from the "
        f"start (a resumed/partial stream is a replay-semantics bug) [{diag}]"
    )


# ---------------------------------------------------------------------------
# Zone advertisement (QwpEgressServerInfoZoneTest)
# ---------------------------------------------------------------------------


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_primary_advertises_configured_zone_c_client_rust(
    server_factory,
    c_client_rust_egress_sidecar: CClientRustEgressSidecar,
) -> None:
    """``replication.zone=eu-west-1a`` on the primary must surface as
    CAP_ZONE set + the exact zone string on the client's decoded
    SERVER_INFO, alongside the PRIMARY role."""
    p1 = server_factory("p1", role="primary", zone="eu-west-1a")
    p1_ports = p1.start()

    c_client_rust_egress_sidecar.connect(
        _connect_string([("127.0.0.1", p1_ports.http)])
    )
    kv = _server_info_kv(c_client_rust_egress_sidecar)
    assert kv["role"] == str(ROLE_PRIMARY), \
        f"PRIMARY role must still surface alongside zone; got {kv}"
    assert kv["cap_zone"] == "1", \
        f"CAP_ZONE bit must be set when replication.zone is configured; got {kv}"
    assert kv["zone"] == "eu-west-1a", f"got {kv}"


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_replica_advertises_configured_zone_c_client_rust(
    server_factory,
    c_client_rust_egress_sidecar: CClientRustEgressSidecar,
) -> None:
    """Zone advertisement on a REPLICA (primary itself has no zone --
    the two knobs must not bleed into each other)."""
    p1 = server_factory("p1", role="primary")
    p1.start()
    r1 = server_factory("r1", role="replica", zone="us-east-2c")
    r1_ports = r1.start()

    c_client_rust_egress_sidecar.connect(
        _connect_string([("127.0.0.1", r1_ports.http)])
    )
    kv = _server_info_kv(c_client_rust_egress_sidecar)
    assert kv["role"] == str(ROLE_REPLICA), f"got {kv}"
    assert kv["cap_zone"] == "1", f"got {kv}"
    assert kv["zone"] == "us-east-2c", f"got {kv}"


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_primary_and_replica_advertise_different_zones_c_client_rust(
    server_factory,
    c_client_rust_egress_sidecar: CClientRustEgressSidecar,
) -> None:
    """The realistic deployment: primary in zone-A, replica in zone-B,
    each node reports its OWN zone. A bug that wired the zone through
    shared static state or swapped it with cluster_id/node_id would
    surface as the wrong string on at least one node. The client
    re-CONNECTs per node (the sidecar swaps its Reader), so each
    assertion reads a fresh SERVER_INFO decode."""
    p1 = server_factory("p1", role="primary", zone="zone-A")
    p1_ports = p1.start()
    r1 = server_factory("r1", role="replica", zone="zone-B")
    r1_ports = r1.start()

    c_client_rust_egress_sidecar.connect(
        _connect_string([("127.0.0.1", p1_ports.http)])
    )
    kv = _server_info_kv(c_client_rust_egress_sidecar)
    assert (kv["role"], kv["zone"], kv["cap_zone"]) == (str(ROLE_PRIMARY), "zone-A", "1"), \
        f"primary advertisement wrong: {kv}"

    c_client_rust_egress_sidecar.connect(
        _connect_string([("127.0.0.1", r1_ports.http)])
    )
    kv = _server_info_kv(c_client_rust_egress_sidecar)
    assert (kv["role"], kv["zone"], kv["cap_zone"]) == (str(ROLE_REPLICA), "zone-B", "1"), \
        f"replica advertisement wrong: {kv}"


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_no_zone_configured_omits_cap_zone_c_client_rust(
    server_factory,
    c_client_rust_egress_sidecar: CClientRustEgressSidecar,
) -> None:
    """No ``replication.zone`` configured -> the CAP_ZONE bit must be
    UNSET and the client's decoded zone must be absent (``None`` on the
    wrapper / ``<unset>`` on the wire)."""
    p1 = server_factory("p1", role="primary")
    p1_ports = p1.start()

    c_client_rust_egress_sidecar.connect(
        _connect_string([("127.0.0.1", p1_ports.http)])
    )
    kv = _server_info_kv(c_client_rust_egress_sidecar)
    assert kv["cap_zone"] == "0", \
        f"no replication.zone configured -> CAP_ZONE bit unset; got {kv}"
    assert kv["zone"] == "<unset>", \
        f"no zone configured -> zone_id must be absent; got {kv}"
    assert c_client_rust_egress_sidecar.server_info().zone is None


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_blank_zone_config_omits_cap_zone_c_client_rust(
    server_factory,
    c_client_rust_egress_sidecar: CClientRustEgressSidecar,
) -> None:
    """Operator sets ``replication.zone=`` (the empty string)
    explicitly. The server-side coalesce branch must turn blank into
    null so the wire omits the CAP_ZONE trailer entirely -- "zone
    configured as empty" and "zone unset" must be indistinguishable on
    the wire (a zero-length trailer with CAP_ZONE set would be a
    semantically distinct, and wrong, third state)."""
    p1 = server_factory("p1", role="primary", zone="")
    p1_ports = p1.start()

    c_client_rust_egress_sidecar.connect(
        _connect_string([("127.0.0.1", p1_ports.http)])
    )
    kv = _server_info_kv(c_client_rust_egress_sidecar)
    assert kv["cap_zone"] == "0", \
        f"blank replication.zone= must coalesce to null on the wire; got {kv}"
    assert kv["zone"] == "<unset>", f"got {kv}"


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_zone_round_trips_utf8_c_client_rust(
    server_factory,
    c_client_rust_egress_sidecar: CClientRustEgressSidecar,
) -> None:
    """Punctuation, accented Latin, CJK, and an emoji exercise
    1/2/3/4-byte UTF-8 sequences end-to-end: server env -> config ->
    SERVER_INFO writer -> WebSocket frame -> Rust decoder -> sidecar
    stdout -> Python. The wire contract is plain UTF-8 and must not
    degrade anywhere along that chain."""
    p1 = server_factory("p1", role="primary", zone=ZONE_UTF8)
    p1_ports = p1.start()

    c_client_rust_egress_sidecar.connect(
        _connect_string([("127.0.0.1", p1_ports.http)])
    )
    kv = _server_info_kv(c_client_rust_egress_sidecar)
    assert kv["cap_zone"] == "1", f"got {kv}"
    assert kv["zone"] == ZONE_UTF8, \
        f"zone must round-trip UTF-8 byte-for-byte; got {kv['zone']!r}"
    # The wrapper path must agree (same reply, ergonomic accessor).
    assert c_client_rust_egress_sidecar.server_info().zone == ZONE_UTF8
