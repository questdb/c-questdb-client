"""
Explicit ``request_durable_ack`` tiers against a live Enterprise primary,
driven by the c-questdb-client Rust ``qwp_sidecar``.

The other tests here request ``on``. These request the tier names:

* ``replicated``: the server echoes ``replicated`` and sends the replicated
  durable ack once the commit reached the object store; AWAIT_ACKED waits at
  the durable level.
* ``local,replicated``: Enterprise grants this set only when the primary runs
  ``cairo.commit.mode=adaptive``. The sender trims on the replicated ack only,
  as the Java client does, so a local durable ack alone must not move its
  acked watermark.
* ``local``: on the same adaptive primary, AWAIT_ACKED waits at the local
  durable level and completes without any upload.

A replication primary defaults to NOSYNC unless ``cairo.commit.mode`` is set,
so the adaptive tests set it explicitly.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterator

import pytest

from lib.pg_query import wait_for_count, wait_for_dense_sequence

from c_client_sidecar import CClientRustSidecar

LOG = logging.getLogger(__name__)

_ROWS = 10
_DURABLE_ACK_AWAIT_TIMEOUT_MS = 60_000
# Long enough for several keepalive PINGs (200 ms) and the local durable acks
# they draw, far shorter than the held uploads.
_NOT_TRIMMED_PROBE_MS = 3_000
_ADAPTIVE_ENV = {"QDB_CAIRO_COMMIT_MODE": "adaptive"}
# Holds DATA uploads far longer than the test, so no replicated durable ack
# can arrive (the seam test_durable_ack_demote_bound.py uses).
_UPLOADS_HELD_ENV = {
    "QDB_REPLICATION_PRIMARY_THROTTLE_WINDOW_DURATION": "600000",
    "QDB_REPLICATION_PRIMARY_INDEX_UPLOAD_THROTTLE_INTERVAL": "0",
}


@pytest.fixture(scope="function")
def second_rust_sidecar(
    c_client_rust_sidecar_binary: Path, log_dir: Path
) -> Iterator[CClientRustSidecar]:
    """A second Rust row sidecar, for a second connection in one test."""
    s = CClientRustSidecar(
        log_dir=log_dir,
        classpath=None,
        name="c-client-rust-sidecar-2",
        binary_path=c_client_rust_sidecar_binary,
    )
    s.start()
    try:
        yield s
    finally:
        s.stop()


def _connect_string(http_port: int, sf_dir: Path, tiers: str) -> str:
    sf_dir.mkdir(parents=True, exist_ok=True)
    return (
        f"ws::addr=127.0.0.1:{http_port}"
        ";username=admin;password=quest"
        f";sf_dir={sf_dir}"
        f";request_durable_ack={tiers}"
        ";close_flush_timeout_millis=1000;"
    )


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_replicated_tier_durable_wait_completes_c_client_rust(
    server_factory, c_client_rust_sidecar: CClientRustSidecar, scenario_dir: Path
) -> None:
    table = "durable_tier_replicated_c_client_rust"
    sidecar = c_client_rust_sidecar
    a_ports = server_factory("a", role="primary").start()
    b_ports = server_factory("b", role="replica").start()

    sidecar.connect(_connect_string(a_ports.http, scenario_dir / "sf", "replicated"))
    sidecar.send(table, count=_ROWS, start_index=0)
    fsn = sidecar.flush()
    assert sidecar.await_acked(fsn, _DURABLE_ACK_AWAIT_TIMEOUT_MS), (
        f"request_durable_ack=replicated: the durable wait did not complete [fsn={fsn}]"
    )
    assert sidecar.stats().acked == fsn
    wait_for_dense_sequence(port=b_ports.pg, table=table, expected_count=_ROWS,
                            timeout_s=120.0)


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_local_replicated_tiers_durable_wait_completes_on_adaptive_primary_c_client_rust(
    server_factory, c_client_rust_sidecar: CClientRustSidecar, scenario_dir: Path
) -> None:
    table = "durable_tier_local_replicated_c_client_rust"
    sidecar = c_client_rust_sidecar
    a_ports = server_factory("a", role="primary", extra_env=_ADAPTIVE_ENV).start()

    sidecar.connect(_connect_string(a_ports.http, scenario_dir / "sf", "local,replicated"))
    sidecar.send(table, count=_ROWS, start_index=0)
    fsn = sidecar.flush()
    assert sidecar.await_acked(fsn, _DURABLE_ACK_AWAIT_TIMEOUT_MS), (
        f"request_durable_ack=local,replicated: the durable wait did not complete [fsn={fsn}]"
    )
    assert sidecar.stats().acked == fsn
    wait_for_dense_sequence(port=a_ports.pg, table=table, expected_count=_ROWS)


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_local_ack_trims_local_tier_but_not_local_replicated_c_client_rust(
    server_factory,
    c_client_rust_sidecar: CClientRustSidecar,
    second_rust_sidecar: CClientRustSidecar,
    scenario_dir: Path,
) -> None:
    table = "durable_tier_local_only_ack_c_client_rust"
    a_ports = server_factory(
        "a", role="primary", extra_env={**_ADAPTIVE_ENV, **_UPLOADS_HELD_ENV}
    ).start()

    # The local,replicated sender commits first: its rows are visible on A.
    both = c_client_rust_sidecar
    both.connect(_connect_string(a_ports.http, scenario_dir / "sf-both", "local,replicated"))
    both.send(table, count=_ROWS, start_index=0)
    both_fsn = both.flush()
    wait_for_count(port=a_ports.pg, table=table, expected=_ROWS)

    # A later commit to the same table reaches the local durable level with
    # uploads held, so the local frontier now covers the first commit too.
    local = second_rust_sidecar
    local.connect(_connect_string(a_ports.http, scenario_dir / "sf-local", "local"))
    local.send(table, count=_ROWS, start_index=_ROWS)
    local_fsn = local.flush()
    assert local.await_acked(local_fsn, _DURABLE_ACK_AWAIT_TIMEOUT_MS), (
        f"request_durable_ack=local: the local durable wait did not complete "
        f"with uploads held [fsn={local_fsn}]"
    )
    assert local.stats().acked == local_fsn

    # The local,replicated sender keeps its frame until the replicated ack.
    assert not both.await_acked(both_fsn, _NOT_TRIMMED_PROBE_MS), (
        "request_durable_ack=local,replicated: the durable wait completed while "
        f"uploads were held, so a local durable ack trimmed [fsn={both_fsn}]"
    )
    stats = both.stats()
    LOG.info("local,replicated sender stats with uploads held: %s", stats)
    assert stats.acked == -1, f"acked watermark moved without a replicated ack: {stats}"
    wait_for_dense_sequence(port=a_ports.pg, table=table, expected_count=2 * _ROWS)
