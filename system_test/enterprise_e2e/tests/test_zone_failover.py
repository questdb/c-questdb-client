"""
Zone-based failover tests for the c-questdb-client Rust binding's
egress ``Reader`` (``zone=`` endpoint preference).

Ported 1:1 from the Enterprise java-client suite
(``questdb-ent/e2e/tests/test_zone_failover.py``, which drives
``QwpQueryClient``). Sibling to
``test_target_filter.py`` (the ``target=`` role half of the priority
lattice) and to
``test_failover.py::test_zone_failover_stays_in_zone_then_crosses_c_client_rust``
(zone exhaustion across a 3-host / 2-zone topology).

These tests exercise the zone-related half of the host-health tracker's
priority lattice (failover.md §2, wire-egress.md §11.9; Rust
implementation in ``questdb-rs/src/egress/tracker.rs``). The oracle for
"which server am I bound to" is the egress client itself: running
``(SHOW PARAMETERS) WHERE property_path = 'replication.zone'`` returns
the zone the bound server was started with. Doing the lookup over the
egress wire path proves the bind end-to-end -- a buggy in-process check
that surfaced the *configured* zone instead of the *bound* zone would
pass silently.

The priority lattice combines ``(state, zone_tier)`` lexicographically.
State outranks zone, and zone tier is ``Unknown`` until the client has
observed a host's zone (via ``SERVER_INFO.zone_id`` on a successful
upgrade, or the ``X-QuestDB-Zone`` header on a 421 reject). The
practical consequence is that the FIRST connect against an all-Unknown
tracker is decided by ``addr=`` order, not by ``zone=``. Same-zone
preference only biases selection after at least two hosts have been
classified -- which is why the last test
(``zone_preference_breaks_state_ties``) goes to some length to drive
the tracker through that state. The Rust ``WalkTracker`` mirrors the
Java lattice exactly (``Healthy < Unknown < TransientReject <
TransportError < TopologyReject`` states; ``Same < Unknown < Other``
zone tiers), so no behavioral adaptation was needed in this port.

Topology (started per-test, not all at once):

* ``p1``  -- primary, ``replication.zone=zone-A``
* ``r2``  -- replica, ``replication.zone=zone-B``
* ``h_a`` / ``h_b`` -- replicas in zone-A / zone-B (tie-break test)

Restarted instances reuse the original instance's ports (the
cross-zone-preference test in particular reuses ports across the test
body).
"""

from __future__ import annotations

import logging
import socket
import time

import pytest

from lib.server import wait_port_free

from c_client_sidecar import CClientRustEgressSidecar

LOG = logging.getLogger(__name__)

ZONE_A = "zone-A"
ZONE_B = "zone-B"


def _pick_unused_port() -> int:
    """Bind ephemeral on 127.0.0.1, immediately release, return the port.

    The kernel won't hand the same port back instantly, so the returned
    port is effectively "guaranteed unused" for the brief window between
    this call and the test using it. Used to stand in for a never-started
    server when we need a syntactically valid ``addr=`` entry that
    resolves but refuses connections, exercising the tracker's
    "skip transport error" path without starting a doomed JVM.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _connect_string(addrs: list[tuple[str, int]], *, zone: str | None,
                    target: str = "any",
                    failover_max_duration_ms: int = 15_000,
                    auth_timeout_ms: int = 5_000) -> str:
    """Egress connect string with an optional ``zone=``. Shares the same
    shape as ``test_target_filter._connect_string`` but is duplicated
    rather than imported (per-file duplication is the suite's
    convention; the bindings and defaults diverge over time). Keeps the
    per-host upgrade timeout short (5s) so a test that walks through an
    unreachable ``addr=`` entry doesn't burn the default on each one.
    """
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


def _wait_for_zone(egress_sidecar: CClientRustEgressSidecar, expected_zone: str,
                   *, timeout_s: float = 15.0) -> None:
    """Poll ``SHOW_ZONE`` until it matches ``expected_zone`` (or timeout).

    A mid-stream failover takes a few hundred ms: the Reader's send
    fails, the per-execute reconnect loop walks via the tracker,
    re-issues the query, and only then surfaces a fresh SHOW_ZONE
    reply. A single immediate assert would race the first attempt that
    just fails. Polling here is purely a deflake -- the *terminal*
    state is asserted; transient values along the way are tolerated.
    """
    deadline = time.monotonic() + timeout_s
    observed = ""
    while time.monotonic() < deadline:
        observed = egress_sidecar.show_zone()
        if observed == expected_zone:
            return
        time.sleep(0.1)
    pytest.fail(
        f"SHOW_ZONE never settled on {expected_zone!r} within {timeout_s}s "
        f"(last observed: {observed!r}); the egress client did not bind "
        f"to the expected zone."
    )


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_startup_reports_bound_zone_c_client_rust(
    server_factory,
    c_client_rust_egress_sidecar: CClientRustEgressSidecar,
) -> None:
    """Happy path: with ``zone=A`` configured and a single zone-A server
    in ``addr=``, the egress client binds and ``SHOW PARAMETERS`` over
    that bound connection reports ``replication.zone=zone-A``. Catches:

    * the ``zone=`` connect-string key being silently ignored (the
      client would still bind, but the test would fail if a regression
      on the server side returned an empty/wrong zone value),
    * the egress wire path losing the per-row STRING column or
      mis-aligning column indices in the column batch decoder (the
      sidecar looks up the value column by name, not index, but a
      server-side schema regression would still surface here).
    """
    p1 = server_factory("p1", zone=ZONE_A)
    p1_ports = p1.start()

    cs = _connect_string(
        [("127.0.0.1", p1_ports.http)],
        zone=ZONE_A,
    )
    c_client_rust_egress_sidecar.connect(cs)
    assert c_client_rust_egress_sidecar.show_zone() == ZONE_A


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_falls_back_to_other_zone_when_no_same_zone_available_c_client_rust(
    server_factory,
    c_client_rust_egress_sidecar: CClientRustEgressSidecar,
) -> None:
    """``zone=`` is a *preference*, not a hard constraint. When no
    same-zone endpoint is reachable the client must still bind to a
    wrong-zone host rather than refusing the connect. Guards against a
    regression where the priority comparator turned zone tier into a
    hard filter (refusing other-zone candidates outright). The negative
    of "happy-path zone-A": the same client config falls through to
    zone-B when only zone-B is up."""
    # The zone-A "addr=" entries point at kernel-allocated-then-released
    # ports that nothing is listening on, producing TCP RST /
    # ECONNREFUSED on the tracker walk. A real misconfig where the
    # operator typo'd a host would surface the same way -- so the test
    # also documents the no-zone-A-host behaviour for an operator
    # reading the suite.
    fake_a_port_1 = _pick_unused_port()
    fake_a_port_2 = _pick_unused_port()

    r2 = server_factory("r2", role="replica", zone=ZONE_B)
    r2_ports = r2.start()

    cs = _connect_string(
        [
            ("127.0.0.1", fake_a_port_1),
            ("127.0.0.1", fake_a_port_2),
            ("127.0.0.1", r2_ports.http),
        ],
        zone=ZONE_A,
    )
    c_client_rust_egress_sidecar.connect(cs)
    assert c_client_rust_egress_sidecar.show_zone() == ZONE_B


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_failover_reports_new_zone_c_client_rust(
    server_factory,
    c_client_rust_egress_sidecar: CClientRustEgressSidecar,
) -> None:
    """When the bound endpoint dies and the per-execute reconnect loop
    moves the connection to a different-zone host, ``SHOW_ZONE`` must
    surface the *new* server's zone, not a cached value from the
    previous bind.

    Failure mode this guards against: a bug that records the bound
    zone in client-local state and keeps reporting it after a failover
    would pass the trivial "same zone before kill" check but get the
    post-failover read wrong. Using SQL over the egress wire (the
    sidecar's SHOW_ZONE verb) instead of the client's cached
    ``server_info`` snapshot is deliberate: it routes through the bound
    TCP connection, so the answer can only come from whatever server
    the client is currently talking to.
    """
    p1 = server_factory("p1", zone=ZONE_A)
    p1_ports = p1.start()
    r2 = server_factory("r2", role="replica", zone=ZONE_B)
    r2_ports = r2.start()

    cs = _connect_string(
        [("127.0.0.1", p1_ports.http), ("127.0.0.1", r2_ports.http)],
        zone=ZONE_A,
    )
    c_client_rust_egress_sidecar.connect(cs)
    assert c_client_rust_egress_sidecar.show_zone() == ZONE_A, \
        "addr=A,B with zone=A should bind A first (addr-order)"

    p1.kill_9()
    wait_port_free(p1_ports.http)

    # The next SHOW_ZONE triggers a fresh execute -- the dead socket
    # surfaces as a transport error, the per-execute loop walks via the
    # tracker, and r2 is the only remaining endpoint. Polling because
    # the very first SHOW_ZONE after the kill might race the OS-level
    # RST delivery.
    _wait_for_zone(c_client_rust_egress_sidecar, ZONE_B)


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_zone_preference_breaks_state_ties_c_client_rust(
    server_factory,
    c_client_rust_egress_sidecar: CClientRustEgressSidecar,
) -> None:
    """The unique scenario in this file that actually exercises
    same-zone *preference*, not just addr-order. Setup walks the
    tracker through enough state that two hosts share priority
    ``TransportError`` and their zone tiers are the tie-breaker:

    1. ``addr=h_B, h_A`` (zone-B first), client ``zone=A``.
    2. Initial connect -> bind to h_B (addr first, all hosts Unknown).
       Tracker observes h_B's zone -> tier=Other.
    3. Kill h_B. Reconnect -> bind to h_A (Unknown beats h_B's
       TransportError). Tracker observes h_A's zone -> tier=Same.
    4. Restart h_B on the same port (still classified as TransportError
       on the tracker).
    5. Kill h_A. The next execute walks via the tracker. Both hosts are
       now ``TransportError``, but h_A is ``Same``, h_B is ``Other``.
       Without zone preference, addr-order picks h_B (zone-B). With
       zone preference, the lattice picks h_A (zone-A).
    6. Restart h_A so the pick-next-of-h_A succeeds.

    The assertion at the end (``zone-A``) only passes if zone tier
    breaks the state tie correctly. A regression that collapsed every
    host's zone tier to ``Same`` (the zone-blind code path,
    ``tracker.rs``'s writer/no-zone mode) would land on h_B by addr
    order and fail loudly.
    """
    # Initial fixtures.
    h_a = server_factory("h_a", role="replica", zone=ZONE_A)
    h_a_ports = h_a.start()
    h_b = server_factory("h_b", role="replica", zone=ZONE_B)
    h_b_ports = h_b.start()

    # h_B (zone-B) listed BEFORE h_A (zone-A) in addr= so initial bind
    # lands on the wrong-zone host. The whole point of the test is to
    # observe the tracker recover to same-zone after enough state
    # accumulates.
    cs = _connect_string(
        [("127.0.0.1", h_b_ports.http), ("127.0.0.1", h_a_ports.http)],
        zone=ZONE_A,
    )
    c_client_rust_egress_sidecar.connect(cs)
    assert c_client_rust_egress_sidecar.show_zone() == ZONE_B, \
        "addr-order first wins on initial connect; zone= does not yet bias"

    # Kill h_B -> failover should reach h_A (the only untried Unknown
    # host left, beating h_B's freshly-TransportError state).
    h_b.kill_9()
    wait_port_free(h_b_ports.http)
    _wait_for_zone(c_client_rust_egress_sidecar, ZONE_A)

    # Bring h_B back on its original port. The tracker still classifies
    # the index-0 host as TransportError + Other -- the wire layer
    # learning that h_B is reachable again only happens on the next
    # tracker walk.
    h_b_restart = server_factory("h_b_restart", role="replica", zone=ZONE_B,
                                 db_root_name="h_b_restart")
    h_b_restart.start(http_port=h_b_ports.http, pg_port=h_b_ports.pg)

    # Kill h_A and immediately restart it on its port. The mid-stream
    # demote in the reconnect loop moves h_A to TransportError + Same.
    # After the restart h_A is alive again, but the tracker still
    # remembers the demotion. Now both hosts are TransportError; only
    # zone tier differs (h_A = Same, h_B = Other).
    h_a.kill_9()
    wait_port_free(h_a_ports.http)
    h_a_restart = server_factory("h_a_restart", role="replica", zone=ZONE_A,
                                 db_root_name="h_a_restart")
    h_a_restart.start(http_port=h_a_ports.http, pg_port=h_a_ports.pg)

    # Next SHOW_ZONE -> reconnect -> pick-next. With zone preference
    # honoured, h_A (Same) wins over h_B (Other) even though h_B is at
    # index 0. The bind succeeds (h_A was just restarted) and SHOW_ZONE
    # returns zone-A.
    _wait_for_zone(c_client_rust_egress_sidecar, ZONE_A)
