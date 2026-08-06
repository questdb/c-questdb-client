"""
Target-role failover tests for the c-questdb-client Rust binding's
egress ``Reader`` (``target=`` endpoint filtering).

Ported 1:1 from the Enterprise java-client suite
(``questdb-ent/e2e/tests/test_target_filter.py``, which drives
``QwpQueryClient``). Sibling to the zone-preference coverage in
``test_failover.py::test_zone_failover_stays_in_zone_then_crosses_c_client_rust``:
where that exercises the ``zone=`` half of the WalkTracker priority
lattice, this file exercises the ``target=`` role filter (failover.md
§2 / §5, wire-egress.md §11.9.3).

The primary motivation for ``target=replica`` is operator protection of
the primary: read-only services that should NOT load the primary even
under failover. The Reader consumes ``SERVER_INFO`` on each attempted
bind and applies the role filter locally:

* ``target=primary``  -- accepts PRIMARY and STANDALONE (so OSS
                         deployments still bind), rejects REPLICA.
* ``target=replica``  -- accepts REPLICA, rejects PRIMARY / STANDALONE.
* ``target=any``      -- accepts everything (the default).

PRIMARY_CATCHUP is a transient reject (worth a retry); other
non-matching roles are sticky topology rejects. On a connect that
exhausts every endpoint with no role match, ``Reader::from_conf``
surfaces ``ErrorCode::RoleMismatch`` rather than a transport error --
so callers can distinguish "no replica available" from "all endpoints
unreachable" and retry the former after a failover window. (The Java
client's equivalent is ``QwpRoleMismatchException``.)

These tests prove the filter end-to-end: a real ENT primary genuinely
returns ``ROLE_PRIMARY`` in its ``SERVER_INFO``, and the Rust Reader
really walks past it. A regression that loosened the filter would
silently load the primary in a "replica-only" deployment.
"""

from __future__ import annotations

import logging
import time

import pytest

from lib.obj_store import ObjStore
from lib.server import wait_port_free
from lib.sidecar import SidecarError

from c_client_sidecar import CClientRustEgressSidecar

LOG = logging.getLogger(__name__)

# SERVER_INFO role bytes (questdb-rs egress/wire/roles.rs; identical to
# the Java QwpEgressMsgKind constants): STANDALONE=0, PRIMARY=1,
# REPLICA=2, PRIMARY_CATCHUP=3.
ROLE_PRIMARY = 1
ROLE_REPLICA = 2


def _connect_string(addrs: list[tuple[str, int]], *,
                    target: str,
                    zone: str | None = None,
                    failover_max_duration_ms: int = 15_000,
                    auth_timeout_ms: int = 5_000) -> str:
    """Egress connect string with explicit ``target=``. Shares the same
    shape as ``test_failover._egress_connect_string`` but is duplicated
    rather than imported because the defaults differ: this file always
    sets ``target=`` explicitly, while the failover file defaults to
    ``target=any``."""
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
    return ";".join(parts) + ";"


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_target_replica_skips_primary_at_startup_c_client_rust(
    server_factory,
    c_client_rust_egress_sidecar: CClientRustEgressSidecar,
) -> None:
    """``target=replica`` MUST walk past a PRIMARY listed earlier in the
    address list and bind a REPLICA further down. The whole point of
    the target filter is to keep read traffic off the primary; a
    regression that accepted any role would silently violate that
    operator contract.

    The primary is listed FIRST in ``addr=`` so any bug that ignored
    ``target=`` (or that applied it only to mid-stream failover, not
    the initial bind) would land on the primary and the SERVER_INFO
    assertion would fail."""
    p1 = server_factory("p1", role="primary")
    p1_ports = p1.start()
    r1 = server_factory("r1", role="replica")
    r1_ports = r1.start()

    cs = _connect_string(
        [("127.0.0.1", p1_ports.http), ("127.0.0.1", r1_ports.http)],
        target="replica",
    )
    c_client_rust_egress_sidecar.connect(cs)

    # SERVER_INFO is the in-memory snapshot the Reader cached on the
    # most-recent successful bind (Reader::from_conf connects eagerly
    # and consumes SERVER_INFO before returning). Using SERVER_INFO
    # rather than SHOW_ZONE here is deliberate: it avoids the wire
    # round-trip, so the assertion is purely about what the bind
    # decided, not what the bound server answers when queried.
    info = c_client_rust_egress_sidecar.server_info()
    assert info.role == ROLE_REPLICA, \
        f"target=replica must bind a replica (role={ROLE_REPLICA}); got role={info.role}"


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_target_replica_fails_when_only_primary_available_c_client_rust(
    server_factory,
    c_client_rust_egress_sidecar: CClientRustEgressSidecar,
) -> None:
    """When every endpoint is a primary and ``target=replica`` is set,
    connect MUST fail loudly with a role-mismatch error rather than
    silently degrading to "best available" and binding the primary.
    The connect-time failure is the *only* way a read-only service
    learns that the cluster has no replicas right now -- a silent
    fallback would route every query into the primary it was
    configured to protect.

    The sidecar's CONNECT verb propagates ``Reader::from_conf`` errors
    as ``ERR <msg>`` over the line protocol, which the Python wrapper
    raises as SidecarError. The Rust RoleMismatch message reads
    ``endpoint 0 role=primary cluster=... does not match
    target=Replica`` (enum Debug casing), where the Java client's read
    ``... target=replica`` -- hence the case-insensitive match. Either
    way the assertion pins the "no replica available" signal as
    observably different from a transport failure ("all endpoints
    unreachable")."""
    p1 = server_factory("p1", role="primary")
    p1_ports = p1.start()

    cs = _connect_string(
        [("127.0.0.1", p1_ports.http)],
        target="replica",
    )
    with pytest.raises(SidecarError, match=r"(?i)target=replica"):
        c_client_rust_egress_sidecar.connect(cs)


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_target_replica_failover_skips_primary_c_client_rust(
    server_factory,
    c_client_rust_egress_sidecar: CClientRustEgressSidecar,
) -> None:
    """During a mid-stream failover with ``target=replica``, the
    per-Execute reconnect loop MUST keep filtering out the primary
    even though the bound replica is the host that just died. The
    primary's role classification on the tracker becomes a sticky
    topology reject after the first walk past it; this test verifies
    the loop walks past it AGAIN on a fresh round rather than
    accidentally treating a previously-bound-and-failed replica as
    higher priority than the still-primary host.

    Topology: r1 (replica), p1 (primary), r2 (replica). addr=r1, p1,
    r2. target=replica. Initial bind r1 (addr-first replica). Kill r1.
    Reconnect MUST walk past p1 (role reject again) and bind r2.
    """
    p1 = server_factory("p1", role="primary")
    p1_ports = p1.start()
    r1 = server_factory("r1", role="replica")
    r1_ports = r1.start()
    r2 = server_factory("r2", role="replica")
    r2_ports = r2.start()

    cs = _connect_string(
        [
            ("127.0.0.1", r1_ports.http),
            ("127.0.0.1", p1_ports.http),
            ("127.0.0.1", r2_ports.http),
        ],
        target="replica",
    )
    c_client_rust_egress_sidecar.connect(cs)
    info = c_client_rust_egress_sidecar.server_info()
    assert info.role == ROLE_REPLICA, "initial bind must be a replica"

    # Kill r1 and force a reconnect via the next sidecar call. The
    # host-health tracker will see r1=TransportError, p1=TopologyReject
    # (from the initial walk that recorded the role reject), and
    # r2=Unknown. The "Unknown beats TopologyReject" rule lifts r2
    # above p1, so p1 is not retried until the round-exhaust
    # forget-classifications reset. r2 binds first.
    r1.kill_9()
    wait_port_free(r1_ports.http)

    deadline = time.monotonic() + 15.0
    while time.monotonic() < deadline:
        try:
            info = c_client_rust_egress_sidecar.server_info()
        except SidecarError:
            # SERVER_INFO doesn't trigger reconnect on its own (it
            # reads the in-memory snapshot). The first SHOW_ZONE after
            # the kill is what drives a fresh Execute, which triggers
            # the reconnect loop. Poll until SERVER_INFO reports a
            # replica role -- the Reader refreshes its snapshot from
            # the freshly-bound endpoint on every reconnect.
            info = None
        if info is not None and info.role == ROLE_REPLICA:
            # Sanity-check the bound endpoint is live (r2, not the dead
            # r1, which would still report role=2 from the stale
            # snapshot if the client failed to refresh on reconnect).
            try:
                zone_after = c_client_rust_egress_sidecar.show_zone()
                # SHOW_ZONE succeeding proves the bind is live -- and
                # since both replicas left a zone unset, the value will
                # be the literal ``<unset>`` token from the sidecar.
                # Any concrete value also indicates a successful bind
                # to a live host.
                assert zone_after  # non-empty reply
                break
            except SidecarError:
                pass
        time.sleep(0.1)
    else:
        pytest.fail("egress client never recovered to a replica within 15s")

    info = c_client_rust_egress_sidecar.server_info()
    assert info.role == ROLE_REPLICA, "post-failover bind must still be a replica"


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_target_primary_failover_to_promoted_replica_c_client_rust(
    server_factory,
    c_client_rust_egress_sidecar: CClientRustEgressSidecar,
    obj_store: ObjStore,
) -> None:
    """``target=primary`` is "follow the master across topology changes":
    write-side and strong-read clients must always reach the cluster's
    current primary, including across a primary-failover event where
    the old primary dies and a different host takes over.

    Sequence:
    1. Start p1 (primary) and r1 (replica) sharing one object store.
    2. Client connects with ``target=primary``, ``addr=p1, r1``. Bind
       p1 because it matches PRIMARY; r1 would have been
       topology-rejected had it been reached.
    3. ``kill -9`` both processes and wipe the object store (mirrors
       the existing test_failover suite's pattern -- ENT refuses to
       start a fresh primary against an object store that already
       owns a different database's DataID). Then start a fresh
       primary on the address that previously hosted the replica.
       Operationally this models a primary-failover event where the
       cluster's current primary lives at a different wire address
       than the one the client originally bound; the role at that
       new address has flipped to PRIMARY.
    4. The next SHOW_ZONE issued through the sidecar drives an Execute,
       which fails on the dead bound socket and triggers the
       per-Execute reconnect loop. The tracker walks past p1 (dead) to
       the address that previously hosted r1, reads SERVER_INFO, sees
       ``ROLE_PRIMARY``, and binds.

    Failure modes this guards against:

    * A regression that cached the initial bind's role and refused to
      re-evaluate the new endpoint's role on reconnect would surface
      as the assertion below seeing ``role != ROLE_PRIMARY``.
    * A regression that latched the per-host classification across a
      restart (treating a now-primary endpoint as the stale REPLICA it
      was last classified as) would topology-reject the promoted host.
      r1 was never tried during initial connect (p1 bound first), so
      it has *no* prior classification -- the promoted host therefore
      starts from Unknown, exercising the realistic happy-path. The
      "stale classification" failure mode is exercised separately by
      ``test_target_replica_failover_skips_primary_c_client_rust``.
    """
    p1 = server_factory("p1", role="primary")
    p1_ports = p1.start()
    r1 = server_factory("r1", role="replica")
    r1_ports = r1.start()

    cs = _connect_string(
        [("127.0.0.1", p1_ports.http), ("127.0.0.1", r1_ports.http)],
        target="primary",
    )
    c_client_rust_egress_sidecar.connect(cs)
    info = c_client_rust_egress_sidecar.server_info()
    # ROLE_PRIMARY=1; STANDALONE=0 is also accepted by target=primary,
    # but ENT primaries never advertise STANDALONE, so this assertion
    # is strict.
    assert info.role == ROLE_PRIMARY, \
        f"initial bind must be PRIMARY (role={ROLE_PRIMARY}); got role={info.role}"

    # Kill both processes so the new primary can claim r1's port, and
    # wipe the object store so the new primary doesn't refuse on
    # DataID mismatch (the existing test_failover suite hits the same
    # constraint in its kill-and-restart-primary scenario). Wiping
    # loses data, which doesn't matter here -- the assertion is on
    # the bound endpoint's role, not on row continuity.
    p1.kill_9()
    r1.kill_9()
    wait_port_free(p1_ports.http)
    wait_port_free(r1_ports.http)
    obj_store.wipe()

    promoted = server_factory("r1_promoted", role="primary",
                              db_root_name="r1-promoted-fresh")
    promoted.start(http_port=r1_ports.http, pg_port=r1_ports.pg)

    # Drive a reconnect through the sidecar. server_info() alone reads
    # the cached snapshot and does not trigger a wire round-trip; only
    # an Execute (via show_zone) walks the failover loop. Poll because
    # the first Execute after the kill races the OS-level RST delivery
    # and may surface a brief transient failure before the reconnect
    # completes.
    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        try:
            # SHOW_ZONE is a side-effect-free way to force an Execute;
            # the returned zone string isn't load-bearing for this
            # test (we assert on the role via server_info next).
            c_client_rust_egress_sidecar.show_zone()
            info = c_client_rust_egress_sidecar.server_info()
            if info.role == ROLE_PRIMARY:
                break
        except SidecarError:
            # Mid-reconnect: the dead socket might surface a transient
            # error before the loop finds the promoted endpoint.
            pass
        time.sleep(0.2)
    else:
        pytest.fail(
            "egress client never re-bound to the promoted primary "
            "within 20s; target=primary did not follow the master."
        )

    info = c_client_rust_egress_sidecar.server_info()
    assert info.role == ROLE_PRIMARY, \
        f"post-failover bind must be the new PRIMARY (role={ROLE_PRIMARY}); got role={info.role}"
