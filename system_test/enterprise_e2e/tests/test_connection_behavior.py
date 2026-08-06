"""
Ingress connection-behavior scenarios for the Rust QWP/WebSocket sender.

Port of the portable subset of Enterprise's
``com.questdb.cairo.wal.transfer.QwpIngressConnectionListenerTest`` (java
client). The JUnit suite drives connection-state transitions and asserts on
the ``SenderConnectionListener`` event stream (CONNECTED / DISCONNECTED /
ENDPOINT_ATTEMPT_FAILED / ALL_ENDPOINTS_UNREACHABLE / AUTH_FAILED / ...).

The Rust client has NO public connection-listener/event API (no equivalent
of ``io.questdb.client.SenderConnectionListener`` anywhere under
``questdb-rs/src``), so each scenario here re-expresses the *behavioral
contract* the events witnessed, using surfaces the Rust binding does have:

  event assertion (java)              observable stand-in (rust)
  ----------------------------------  ------------------------------------
  ALL_ENDPOINTS_UNREACHABLE sweeps,   every FLUSH keeps succeeding past
  no terminal past the budget         several budgets (SF-local publish
                                      never hard-fails), and the sender
                                      later connects when an endpoint
                                      appears (a gave-up loop cannot)
  ENDPOINT_ATTEMPT_FAILED count       STATS reconnAttempts growth
  (mid-stream reconnect loop)         (recorded at qwp_ws.rs:1206, the
                                      same per-round site the Java client
                                      bumps)
  CONNECTED / functional sender       CONNECT replies OK + a row durably
                                      lands (pg-wire count, authoritative)
  RECONNECTED / FAILED_OVER == 0      STATS reconnSucc stays flat
  DISCONNECTED then no acks           STATS acked watermark stays flat
  AUTH_FAILED fires + typed throw     CONNECT replies ERR promptly with an
                                      auth message (AuthError is terminal:
                                      reconnect_error_is_terminal,
                                      qwp_ws_driver.rs:1978-1986)

Two JUnit scenarios are NOT portable and are documented as blocked in
PORTING_JAVA_E2E.md:

* ``testInitialConnectAuthFailedFiresEvent`` -- only the listener-event
  half (event kind, host/port fields, cause class). The behavioral core
  (auth failure surfaces promptly as a terminal error instead of being
  retried until the reconnect budget) IS ported below.
* ``testConnectionListenerInboxCapacityHonouredEndToEnd`` -- entirely an
  artifact of the Java client's dispatcher thread + bounded event inbox
  (``connection_listener_inbox_capacity``,
  ``getDroppedConnectionNotifications``); the Rust client has no
  dispatcher, no inbox, no dropped-notification counter.

Observability note (initial-connect phase): the Rust async initial-connect
loop keeps a LOCAL attempt counter (``connect_with_retry``,
qwp_ws.rs:688-757) and does not bump the ``qwp_ws_totals`` reconnAttempts
counter (recorded only at the mid-stream site qwp_ws.rs:1206 and the
manual-progress site qwp_ws_driver.rs:1361). STATS therefore cannot witness
initial-connect sweeps; the all-unreachable test below proves the loop kept
sweeping via eventual connect instead (strictly observable: a loop that
latched a terminal or wedged can never drain to the late-arriving server).
"""

from __future__ import annotations

import logging
import re
import shutil
import socket
import time
from pathlib import Path

import pytest

from lib.pg_query import wait_for_dense_sequence
from lib.server import wait_port_free
from lib.sidecar import SidecarError

from c_client_sidecar import CClientRustSidecar

LOG = logging.getLogger(__name__)

# Deliberately short budget + tight backoffs, mirroring the JUnit's
# reconnect_max_duration_millis=500 / 50 / 200: Invariant B says the budget
# is NOT a give-up deadline for a store-and-forward sender, so the tests
# below hold windows open for many multiples of it.
_SHORT_BUDGET_MS = 500
_BACKOFF_INITIAL_MS = 50
_BACKOFF_MAX_MS = 200
# How long to keep producing while no endpoint is reachable. 4s = 8 budgets
# (the JUnit observed 3x; more budgets, same claim, still fast).
_HOLD_S = 4.0
_PUBLISH_INTERVAL_S = 0.25

_AUTH_BUDGET_MS = 30_000
# Auth rejection must surface well before the budget: half of it is already
# generous for a localhost 401 (the JUnit used a 5s await on the event).
_AUTH_PROMPT_S = 15.0

_DENSE_TIMEOUT_S = 60.0


def _pick_closed_port() -> int:
    """Bind an ephemeral socket, close it, return the port: connecting to it
    gets ECONNREFUSED. Same approach and same tiny reuse race as the JUnit's
    ``pickClosedPort`` -- acceptable for localhost test infrastructure."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _publish_or_fail(sidecar, table: str, idx: int, *, context: str) -> int:
    """One SEND+FLUSH that must succeed: both are SF-local operations that
    return regardless of endpoint reachability. A hard failure here is the
    red-first signal that the client surfaced a terminal on a transient
    condition (Invariant B violation). Returns the published fsn."""
    try:
        sidecar.send(table, count=1, start_index=idx)
        return sidecar.flush()
    except SidecarError as e:
        raise AssertionError(
            f"sender surfaced a terminal while {context} (row index {idx}): "
            f"a transient unreachable window must be retried forever -- the "
            f"reconnect budget is not a give-up deadline and only genuine "
            f"auth/protocol errors are terminal. sidecar error: {e}"
        )


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_initial_connect_all_endpoints_unreachable_retries_forever_c_client_rust(
    server_factory, c_client_rust_sidecar: CClientRustSidecar, obj_store,
    scenario_dir: Path,
) -> None:
    """INVARIANT B at the INITIAL-connect phase (port of
    ``testInitialConnectAllEndpointsUnreachableRetriesForever``): an
    all-unreachable address list is a TRANSIENT condition -- servers may
    appear -- so an async initial connect retries FOREVER.
    ``reconnect_max_duration_millis`` is ignored as a give-up deadline.

    Rust semantics pinned in-source: the async pending runner treats a
    budget-exhaustion error as non-terminal and re-enters the connect loop
    (``SyncQwpWsPendingRunnerCore::drive_step``, qwp_ws.rs:774-798 -- only
    ``reconnect_error_is_terminal`` marks the store terminal); this test
    pins it end-to-end.

    Shape: kill a just-started primary so its port is a *guaranteed-dead*
    listed endpoint, CONNECT (async) against [dead-primary-port,
    closed-port], produce through 8 budgets' worth of all-unreachable
    window (every FLUSH must keep succeeding -- the JUnit's
    ``drainUntilTerminal == null``), then stand a successor primary up on
    the listed port and require the ENTIRE backlog to land dense. The
    eventual drain replaces the JUnit's ALL_ENDPOINTS_UNREACHABLE /
    ENDPOINT_ATTEMPT_FAILED sweep counting (no event API; see module
    docstring): a loop that gave up or latched a terminal during the
    window can never connect later."""
    table = "connbehavior_all_unreachable_c_client_rust"
    sf_dir = scenario_dir / "sf"

    # A real, then killed, primary: its port is both provably closed during
    # the window AND the address the successor will later reuse.
    p1 = server_factory("p1")
    p1_ports = p1.start()
    p1.kill_9()
    wait_port_free(p1_ports.http)
    wait_port_free(p1_ports.pg)
    bogus = _pick_closed_port()

    connect_str = (
        f"ws::addr=127.0.0.1:{p1_ports.http},127.0.0.1:{bogus}"
        ";username=admin;password=quest"
        f";sf_dir={sf_dir}"
        ";initial_connect_retry=async"
        f";reconnect_max_duration_millis={_SHORT_BUDGET_MS}"
        f";reconnect_initial_backoff_millis={_BACKOFF_INITIAL_MS}"
        f";reconnect_max_backoff_millis={_BACKOFF_MAX_MS}"
        # Fast close, same rationale as the JUnit: if the test fails while
        # everything is still unreachable, teardown must not park in a
        # close-drain that can never be acked.
        ";close_flush_timeout_millis=0;"
    )
    # Async mode: build returns immediately with zero reachable endpoints.
    # An ERR here means the async initial connect blocked or failed on
    # build -- itself a regression against the async contract.
    c_client_rust_sidecar.connect(connect_str)

    # Produce straight through the all-unreachable window, unaware. Every
    # publish is SF-local and must succeed well past the 500ms budget.
    idx = 0
    deadline = time.monotonic() + _HOLD_S
    while time.monotonic() < deadline:
        _publish_or_fail(c_client_rust_sidecar, table, idx,
                         context="all endpoints were unreachable at initial connect")
        idx += 1
        time.sleep(_PUBLISH_INTERVAL_S)
    LOG.info("published %d rows across %.1fs of all-unreachable initial-connect window "
             "(%.0fx the %dms budget)", idx, _HOLD_S,
             _HOLD_S * 1000 / _SHORT_BUDGET_MS, _SHORT_BUDGET_MS)

    # A server appears on a listed endpoint (fresh root + wiped store: the
    # sender's SF is the only copy, same worst-case as the kill9 suite).
    if p1.db_root.exists():
        shutil.rmtree(p1.db_root)
    obj_store.wipe()
    p2 = server_factory("p2", db_root_name="p2-fresh")
    p2.start(http_port=p1_ports.http, pg_port=p1_ports.pg)

    # The still-sweeping initial-connect loop must find it and drain the
    # full backlog -- the liveness proof that it retried forever instead of
    # giving up on the budget.
    wait_for_dense_sequence(port=p1_ports.pg, table=table,
                            expected_count=idx, timeout_s=_DENSE_TIMEOUT_S)
    LOG.info("initial-connect loop outlived the budget and drained [0..%d)", idx)


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_initial_connect_fails_over_past_bogus_endpoint_c_client_rust(
    server_factory, c_client_rust_sidecar: CClientRustSidecar,
    scenario_dir: Path,
) -> None:
    """Port of ``testInitialConnectFailsOverPastBogusEndpoint``: a bogus
    first entry in the address list must not break the initial connect --
    the endpoint walk moves on and binds the real second entry.

    Event substitutions: CONNECT replying OK *is* the CONNECTED-on-the-real-
    endpoint witness (the connect string's reconnect keys imply
    ``initial_connect_retry=sync``, so an OK reply means the build-time
    connect walked past the bogus endpoint and completed); a durably landed
    row replaces the "sender is functional after the failover-to-second"
    tail assertion; flat reconnSucc replaces ``DISCONNECTED == 0`` (a clean
    first connect is not a reconnect cycle)."""
    table = "connbehavior_bogus_first_c_client_rust"
    sf_dir = scenario_dir / "sf"

    p = server_factory("p")
    p_ports = p.start()
    bogus = _pick_closed_port()

    connect_str = (
        f"ws::addr=127.0.0.1:{bogus},127.0.0.1:{p_ports.http}"
        ";username=admin;password=quest"
        f";sf_dir={sf_dir}"
        ";reconnect_max_duration_millis=10000"
        f";reconnect_initial_backoff_millis={_BACKOFF_INITIAL_MS}"
        ";reconnect_max_backoff_millis=100;"
    )
    started = time.monotonic()
    c_client_rust_sidecar.connect(connect_str)
    elapsed = time.monotonic() - started
    # ECONNREFUSED on localhost is immediate; the walk-past must not burn
    # anywhere near the 10s budget on the bogus entry.
    assert elapsed < 8.0, (
        f"initial connect took {elapsed:.1f}s with a bogus first endpoint; "
        f"the endpoint walk should skip past ECONNREFUSED almost instantly"
    )

    c_client_rust_sidecar.send(table, count=1, start_index=0)
    fsn = c_client_rust_sidecar.flush()
    assert fsn >= 0, f"expected a published fsn after flush, got {fsn}"
    wait_for_dense_sequence(port=p_ports.pg, table=table,
                            expected_count=1, timeout_s=_DENSE_TIMEOUT_S)

    stats = c_client_rust_sidecar.stats()
    assert stats.reconn_succ == 0, (
        f"clean bogus-first initial connect must not register a reconnect "
        f"cycle (reconnSucc={stats.reconn_succ}); the walk-past happens "
        f"inside the initial round, not the reconnect loop"
    )
    LOG.info("connected past bogus endpoint in %.2fs; row landed; stats=%s",
             elapsed, stats)


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_mid_stream_server_down_retries_forever_c_client_rust(
    server_factory, c_client_rust_sidecar: CClientRustSidecar,
    scenario_dir: Path,
) -> None:
    """INVARIANT B at the MID-STREAM phase against a DEAD WIRE (port of
    ``testMidStreamServerDownRetriesForever``): connect to a live primary,
    kill it, never bring anything back. The reconnect loop must sweep
    forever -- ``reconnect_max_duration_millis`` is ignored as a give-up
    deadline -- and the producer must never see a terminal.

    Distinct surface vs test_durable_ack_failover.py's budget test: that
    scenario holds a REPLICA-reachable window (the role-reject
    classification path, ``request_durable_ack=on``) and later promotes;
    this one is a plain-ack sender against pure ECONNREFUSED (the
    transport-error classification path), and the server NEVER returns --
    the loop's sweeping is witnessed directly via STATS growth rather than
    by eventual recovery.

    Event substitutions: reconnAttempts strictly grows across the hold
    (ENDPOINT_ATTEMPT_FAILED sweeps; counter recorded at the top of each
    reconnect round, qwp_ws.rs:1206); reconnSucc and the acked watermark
    stay flat (RECONNECTED == 0, FAILED_OVER == 0, and nothing acks on a
    dead wire); every FLUSH succeeding past 8 budgets is the JUnit's
    ``drainUntilTerminal == null``."""
    table = "connbehavior_midstream_down_c_client_rust"
    sf_dir = scenario_dir / "sf"

    p = server_factory("p")
    p_ports = p.start()

    connect_str = (
        f"ws::addr=127.0.0.1:{p_ports.http}"
        ";username=admin;password=quest"
        f";sf_dir={sf_dir}"
        f";reconnect_max_duration_millis={_SHORT_BUDGET_MS}"
        f";reconnect_initial_backoff_millis={_BACKOFF_INITIAL_MS}"
        f";reconnect_max_backoff_millis={_BACKOFF_MAX_MS}"
        # Fast close: the server is killed and never restarted, so the
        # unacked tail can never drain; without this, teardown parks in
        # the bounded close-drain (same rationale as the JUnit).
        ";close_flush_timeout_millis=0;"
    )
    c_client_rust_sidecar.connect(connect_str)

    # Fully exercise the wire before the kill (the CONNECTED premise): one
    # row must actually land, by authoritative pg-wire count.
    c_client_rust_sidecar.send(table, count=1, start_index=0)
    c_client_rust_sidecar.flush()
    wait_for_dense_sequence(port=p_ports.pg, table=table,
                            expected_count=1, timeout_s=_DENSE_TIMEOUT_S)

    p.kill_9()
    # Let the I/O thread hit the dead wire and enter the reconnect loop
    # (also puts us past the first budget before the baseline sample, so
    # any give-up-on-budget regression fires inside the observed window).
    time.sleep((_SHORT_BUDGET_MS + 200) / 1000.0)
    baseline = c_client_rust_sidecar.stats()

    idx = 1
    deadline = time.monotonic() + _HOLD_S
    while time.monotonic() < deadline:
        _publish_or_fail(c_client_rust_sidecar, table, idx,
                         context="the mid-stream wire was dead (server killed, never restarted)")
        idx += 1
        time.sleep(_PUBLISH_INTERVAL_S)

    final = c_client_rust_sidecar.stats()
    assert final.reconn_attempts > baseline.reconn_attempts, (
        f"reconnect loop stopped sweeping the dead endpoint: reconnAttempts "
        f"flat at {final.reconn_attempts} across a {_HOLD_S:.0f}s window "
        f"({_HOLD_S * 1000 / _SHORT_BUDGET_MS:.0f} budgets) -- the loop must "
        f"retry forever, the budget is not a give-up deadline"
    )
    assert final.reconn_succ == baseline.reconn_succ, (
        f"no server ever returned, yet reconnSucc moved "
        f"{baseline.reconn_succ} -> {final.reconn_succ}"
    )
    assert final.acked == baseline.acked, (
        f"nothing can ack on a dead wire, yet the acked watermark moved "
        f"{baseline.acked} -> {final.acked}"
    )
    LOG.info("dead-wire loop kept sweeping: reconnAttempts %d -> %d, "
             "reconnSucc flat at %d, %d rows published into SF",
             baseline.reconn_attempts, final.reconn_attempts,
             final.reconn_succ, idx)


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_initial_connect_auth_failed_surfaces_terminal_promptly_c_client_rust(
    server_factory, c_client_rust_sidecar: CClientRustSidecar,
    scenario_dir: Path,
) -> None:
    """Behavioral core of ``testInitialConnectAuthFailedFiresEvent``: bad
    credentials at initial connect are a GENUINE terminal -- the exact
    counterpoint to the retries-forever invariants above. The failure must
    surface promptly as a typed auth error, not be retried until the
    reconnect budget elapses.

    Rust semantics pinned in-source and here end-to-end: a 401/403 upgrade
    reject classifies as ``AuthError``
    (``classify_qwp_handshake_reject``, qwp_ws_codec.rs:201-206), and
    ``AuthError`` short-circuits the connect/reconnect loops
    (``reconnect_error_is_terminal``, qwp_ws_driver.rs:1978-1986; the sync
    initial-connect walk returns it immediately instead of sleeping toward
    the budget).

    The listener-event half of the JUnit (AUTH_FAILED event kind, host/port
    fields on the event, cause-class introspection) is BLOCKED on a client
    API gap -- no connection-event surface exists in questdb-rs -- and is
    documented in PORTING_JAVA_E2E.md. The sidecar's ERR reply on CONNECT
    is the producer-side half of the same contract (the JUnit's synchronous
    ``QwpAuthFailedException`` throw from ``build()``).

    Tail assertion: the same sidecar then connects with CORRECT credentials
    and lands a row -- the auth terminal was a clean, non-wedging failure."""
    table = "connbehavior_auth_terminal_c_client_rust"
    sf_dir = scenario_dir / "sf"

    p = server_factory("p")
    p_ports = p.start()

    bad_connect_str = (
        f"ws::addr=127.0.0.1:{p_ports.http}"
        ";username=admin;password=DEFINITELY-WRONG-PASSWORD"
        f";sf_dir={sf_dir}"
        ";initial_connect_retry=sync"
        f";reconnect_max_duration_millis={_AUTH_BUDGET_MS}"
        f";reconnect_initial_backoff_millis={_BACKOFF_INITIAL_MS}"
        ";reconnect_max_backoff_millis=100;"
    )
    started = time.monotonic()
    with pytest.raises(SidecarError) as excinfo:
        c_client_rust_sidecar.connect(bad_connect_str)
    elapsed = time.monotonic() - started

    msg = str(excinfo.value)
    assert re.search(r"(?i)auth", msg), (
        f"CONNECT with bad credentials must surface a typed auth error "
        f"(java: QwpAuthFailedException; rust: AuthError from the 401/403 "
        f"upgrade reject), got: {msg!r}"
    )
    assert elapsed < _AUTH_PROMPT_S, (
        f"auth rejection took {elapsed:.1f}s to surface against a "
        f"{_AUTH_BUDGET_MS}ms reconnect budget -- a terminal must "
        f"short-circuit the sync connect walk, not ride the retry loop"
    )
    LOG.info("auth terminal surfaced in %.2fs: %s", elapsed, msg)

    # Clean-terminal tail: the sidecar (and a fresh sender) must be fully
    # usable afterwards with correct credentials.
    good_connect_str = (
        f"ws::addr=127.0.0.1:{p_ports.http}"
        ";username=admin;password=quest"
        f";sf_dir={sf_dir / 'good'};"
    )
    c_client_rust_sidecar.connect(good_connect_str)
    c_client_rust_sidecar.send(table, count=1, start_index=0)
    c_client_rust_sidecar.flush()
    wait_for_dense_sequence(port=p_ports.pg, table=table,
                            expected_count=1, timeout_s=_DENSE_TIMEOUT_S)
