"""
C and C++ binding variants of the durable-ack orphan-drainer failover tests
(scenario 6 of the 19b9fda coverage).

The fix lives in the shared Rust core; the C and C++ FFI bindings inherit it.
These tests pin that each *binding* actually drives the QWP-WS store-and-forward
durable-ack path correctly -- the positive survival case (1) and the negative
no-durable-ack control (2) -- via the ``qwp_c_sidecar`` / ``qwp_cpp_sidecar``
drivers built from this repo's C / C++ FFI.

The bodies are shared across bindings (the underlying core is identical); each
binding gets its own ``@pytest.mark.c_client_<binding>`` so CI can run one
binding (``-m c_client_c``) or all of them (``-m c_client``). The C/C++ FFI does
not export the ``reconnSucc`` counter the Rust negative test reads, so (2)
confirms the sender reached the successor server-side (the probe row lands on
P2) instead of via client stats.
"""

from __future__ import annotations

import logging
import shutil
import time
from pathlib import Path

import pytest

from lib.pg_query import count_rows, wait_for_dense_sequence
from lib.server import wait_port_free

LOG = logging.getLogger(__name__)


def _survives_kill_body(sidecar, server_factory, obj_store, scenario_dir: Path,
                        suffix: str) -> None:
    """(1) The orphan drainer honours ``request_durable_ack`` across a primary
    failover. A ghost abandons a slot of OK'd-but-not-durable frames; a
    foreground sender with ``drain_orphans=on`` adopts it; after kill + disk and
    object-store wipe, only the client SF carries the rows, and the re-adopting
    drainer replays them to the successor. Same shape as the Rust
    ``..._survives_kill`` test, driven by a C/C++ binding instead."""
    table = f"trades_orphan_survive_{suffix}"
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
        "close_flush_timeout_millis=0;"
    )
    sidecar.connect(ghost_cs)
    sidecar.send(table, count=row_count, start_index=0)
    sidecar.flush()
    sidecar.close()

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
    sidecar.connect(fg_cs)
    # Window for the drainer to adopt, push the orphan frame(s), and get OK.
    time.sleep(1.0)

    p1.kill_9()
    wait_port_free(p1_ports.http)
    wait_port_free(p1_ports.pg)
    if p1.db_root.exists():
        shutil.rmtree(p1.db_root)
    obj_store.wipe()

    p2 = server_factory("p2", db_root_name="p2-fresh")
    p2.start(http_port=p1_ports.http, pg_port=p1_ports.pg)

    # A fresh orphan scan on reconnect re-adopts the still-un-acked ghost slot
    # and replays it to P2.
    sidecar.connect(fg_cs)
    wait_for_dense_sequence(port=p1_ports.pg, table=table,
                            expected_count=row_count, timeout_s=60.0)


def _no_durable_ack_loses_rows_body(sidecar, server_factory, obj_store,
                                    scenario_dir: Path, suffix: str) -> None:
    """(2) Negative control: WITHOUT ``request_durable_ack=on`` the SF trims on
    OK, so killing P1 between OK and WAL upload then wiping disk + object store
    loses rows. Asserting the loss proves the positive test passes *because of*
    the opt-in, not by luck. Reaching P2 is confirmed server-side (the probe row
    lands) since the C/C++ FFI does not export the reconnect counter."""
    table = f"trades_no_durable_{suffix}"
    sf_dir = scenario_dir / "sf"
    row_count = 50

    p1 = server_factory("p1")
    p1_ports = p1.start()

    # NOTE: request_durable_ack omitted -> default off -> OK-driven trim.
    cs = (
        f"ws::addr=127.0.0.1:{p1_ports.http};"
        "username=admin;password=quest;"
        f"sf_dir={sf_dir};"
        "reconnect_max_duration_millis=60000;"
        "close_flush_timeout_millis=5000;"
    )
    sidecar.connect(cs)
    sidecar.send(table, count=row_count, start_index=0)
    published_fsn = sidecar.flush()
    # Deterministically wait for OK-driven trim to drain the SF.
    assert sidecar.await_acked(published_fsn, timeout_ms=15_000), (
        f"OKs for fsn={published_fsn} not received within 15s; "
        "cannot set up the OK-driven-trim scenario under test."
    )

    p1.kill_9()
    wait_port_free(p1_ports.http)
    wait_port_free(p1_ports.pg)
    if p1.db_root.exists():
        shutil.rmtree(p1.db_root)
    obj_store.wipe()

    p2 = server_factory("p2", db_root_name="p2-fresh")
    p2.start(http_port=p1_ports.http, pg_port=p1_ports.pg)

    # A fresh probe row (index row_count) forces a reconnect to P2 and proves
    # the sender CAN reach the successor -- so the loss assertion below can't
    # pass for a "never reached P2" reason. We confirm reach server-side: the
    # probe is the only row P2 should receive; the OK-trimmed batch is gone.
    sidecar.send(table, count=1, start_index=row_count)
    sidecar.flush()
    deadline = time.monotonic() + 20.0
    reached = False
    while time.monotonic() < deadline:
        try:
            if count_rows(port=p1_ports.pg, table=table, timeout_s=2.0) >= 1:
                reached = True
                break
        except TimeoutError:
            pass
        time.sleep(0.2)
    assert reached, (
        "probe row never landed on P2 within 20s; the sender did not reach the "
        "successor, so the loss assertion would pass for the wrong reason."
    )

    observed = count_rows(port=p1_ports.pg, table=table, timeout_s=10.0)
    LOG.info("OK-only trim observed=%d expected_loss_of=%d", observed, row_count)
    assert observed < row_count, (
        "OK-driven trim is supposed to be vulnerable; if every row still "
        "survives without request_durable_ack=on the test setup isn't actually "
        "exercising the failure mode it claims to."
    )


# ---------------------------------------------------------------------------
# C binding
# ---------------------------------------------------------------------------

@pytest.mark.c_client
@pytest.mark.c_client_c
def test_orphan_drainer_durable_ack_survives_kill_c_client_c(
    c_client_c_sidecar, server_factory, obj_store, scenario_dir: Path,
) -> None:
    _survives_kill_body(c_client_c_sidecar, server_factory, obj_store,
                        scenario_dir, "c_client_c")


@pytest.mark.c_client
@pytest.mark.c_client_c
def test_no_request_durable_ack_loses_rows_c_client_c(
    c_client_c_sidecar, server_factory, obj_store, scenario_dir: Path,
) -> None:
    _no_durable_ack_loses_rows_body(c_client_c_sidecar, server_factory, obj_store,
                                    scenario_dir, "c_client_c")


# ---------------------------------------------------------------------------
# C++ binding
# ---------------------------------------------------------------------------

@pytest.mark.c_client
@pytest.mark.c_client_cpp
def test_orphan_drainer_durable_ack_survives_kill_c_client_cpp(
    c_client_cpp_sidecar, server_factory, obj_store, scenario_dir: Path,
) -> None:
    _survives_kill_body(c_client_cpp_sidecar, server_factory, obj_store,
                        scenario_dir, "c_client_cpp")


@pytest.mark.c_client
@pytest.mark.c_client_cpp
def test_no_request_durable_ack_loses_rows_c_client_cpp(
    c_client_cpp_sidecar, server_factory, obj_store, scenario_dir: Path,
) -> None:
    _no_durable_ack_loses_rows_body(c_client_cpp_sidecar, server_factory, obj_store,
                                    scenario_dir, "c_client_cpp")
