"""
Randomized failover fuzz, driven by the c-questdb-client Rust sender.

Port of the Enterprise harness's ``test_failover_fuzz.py``. Same shape --
"send batches, kill-restart the primary, verify content" -- but rolls
dice for row counts, batch counts, settle timing, and whether to do one
or two disturbances in a single scenario. The only binding-specific part
is the ingress sender (Rust ``qwp_sidecar`` here, ``username=`` keyword).

Cadence note
------------
This test is marked ``fuzz`` and ``c_client_rust`` but NOT ``c_client``,
so the deterministic CI selection (``pytest -m c_client``) skips it --
mirroring the Enterprise split where fuzz runs on a separate cadence
(``-m fuzz``), not in the PR pipeline. Run it explicitly with::

    pytest -m "c_client_rust and fuzz"
    QDB_E2E_FUZZ_ITERS=20 pytest -m "c_client_rust and fuzz"

Verification is a *content* oracle, not a row-count check: each row
carries a deterministic ``v`` column equal to its global index, so the
post-disturbance survivor must contain exactly ``v in [0, flushed[table])``
with no gaps, duplicates, or shifts.

The seed is logged on every iteration; to reproduce a flake, set
``QDB_E2E_FUZZ_SEED=<seed>`` in the env and re-run.
"""

from __future__ import annotations

import logging
import os
import random
import shutil
import time
from pathlib import Path

import pytest

from lib.pg_query import wait_for_dense_sequence
from lib.server import wait_port_free

from c_client_sidecar import CClientRustSidecar

LOG = logging.getLogger(__name__)

# Two table names; the fuzz interleaves rows across both to exercise the
# per-table watermark drain logic in addition to the per-FSN pending queue.
TABLES = ("fuzz_a_c_client_rust", "fuzz_b_c_client_rust")


def _connect_string(http_port: int, sf_dir: Path) -> str:
    return (
        f"ws::addr=127.0.0.1:{http_port}"
        ";username=admin;password=quest"
        f";sf_dir={sf_dir}"
        ";request_durable_ack=on"
        ";reconnect_max_duration_millis=60000"
        ";close_flush_timeout_millis=5000;"
    )


def _seed_for_iteration(base: int, i: int) -> int:
    return (base * 0x9E3779B97F4A7C15 + i) & 0xFFFFFFFFFFFFFFFF


def _disturbance_kill_restart(server, ports, obj_store) -> None:
    """Kill-9 the given server, wipe its DB root and the object store.

    Correct here because kill-9 simulates disk loss: the SF segments on
    the client side are the only surviving copy. Do NOT call this on a
    graceful-switch path (switch destroys nothing).
    """
    server.kill_9()
    wait_port_free(ports.http)
    wait_port_free(ports.pg)
    if server.db_root.exists():
        shutil.rmtree(server.db_root)
    obj_store.wipe()


@pytest.mark.c_client_rust
@pytest.mark.fuzz
@pytest.mark.parametrize("iteration", range(int(os.environ.get("QDB_E2E_FUZZ_ITERS", "10"))))
def test_random_failover_c_client_rust(iteration: int, server_factory,
                                       c_client_rust_sidecar: CClientRustSidecar,
                                       obj_store, scenario_dir: Path) -> None:
    base_seed = int(os.environ.get("QDB_E2E_FUZZ_SEED", str(time.time_ns() & 0xFFFFFFFF)))
    seed = _seed_for_iteration(base_seed, iteration)
    rng = random.Random(seed)

    LOG.info("fuzz iteration=%d seed=%d (base=%d)", iteration, seed, base_seed)

    sf_dir = scenario_dir / "sf"

    size_class = rng.choices(
        ["small", "medium", "large"],
        weights=[0.70, 0.25, 0.05],
    )[0]
    if size_class == "small":
        batches = rng.randint(1, 5)
        rows_per_batch = rng.randint(5, 40)
    elif size_class == "medium":
        batches = rng.randint(1, 5)
        rows_per_batch = rng.randint(200, 2_000)
    else:  # large
        batches = rng.randint(1, 2)
        rows_per_batch = rng.randint(10_000, 25_000)
    settle_ms = rng.randint(0, 800)
    do_second_failover = rng.choice([True, False])

    LOG.info(
        "fuzz params: size_class=%s batches=%d rows_per_batch=%d settle_ms=%d "
        "do_second_failover=%s",
        size_class, batches, rows_per_batch, settle_ms, do_second_failover,
    )

    # sent: total handed to SEND (includes still-buffered rows).
    # flushed: rows committed to the SF mmap'd segment via FLUSH. The
    # durable-ack contract only promises survival for flushed bytes;
    # asserting on `sent` would assert a guarantee the system never made.
    sent: dict[str, int] = {t: 0 for t in TABLES}
    flushed: dict[str, int] = {t: 0 for t in TABLES}

    p1 = server_factory("p1")
    p1_ports = p1.start()
    c_client_rust_sidecar.connect(_connect_string(p1_ports.http, sf_dir))

    for _b in range(batches):
        table = rng.choice(TABLES)
        c_client_rust_sidecar.send(table, count=rows_per_batch, start_index=sent[table])
        sent[table] += rows_per_batch

    c_client_rust_sidecar.flush()
    flushed = dict(sent)
    if settle_ms:
        time.sleep(settle_ms / 1000.0)

    # Phase 1 disturbance: kill-restart.
    _disturbance_kill_restart(p1, p1_ports, obj_store)
    p2 = server_factory("p2", db_root_name="p2-fresh")
    p2.start(http_port=p1_ports.http, pg_port=p1_ports.pg)

    if do_second_failover:
        for _ in range(rng.randint(1, 3)):
            table = rng.choice(TABLES)
            extra = rng.randint(5, 20)
            c_client_rust_sidecar.send(table, count=extra, start_index=sent[table])
            sent[table] += extra
        c_client_rust_sidecar.flush()
        flushed = dict(sent)
        time.sleep(rng.randint(0, 600) / 1000.0)

        _disturbance_kill_restart(p2, p1_ports, obj_store)
        p3 = server_factory("p3", db_root_name="p3-fresh")
        p3.start(http_port=p1_ports.http, pg_port=p1_ports.pg)

    # Strong per-table oracle: the surviving v column is exactly
    # [0, 1, ..., flushed[table] - 1]. Per-table (not global) so one
    # table being short and another long by the same amount can't mask.
    timeout_s = 60.0 if size_class == "small" else (120.0 if size_class == "medium" else 240.0)
    for table, count in flushed.items():
        if count == 0:
            continue
        try:
            wait_for_dense_sequence(
                port=p1_ports.pg, table=table,
                expected_count=count, timeout_s=timeout_s,
            )
        except AssertionError as exc:
            repro = (
                f"QDB_E2E_FUZZ_SEED={base_seed} "
                f"pytest -m 'c_client_rust and fuzz' "
                f"tests/test_failover_fuzz.py::test_random_failover_c_client_rust[{iteration}]"
            )
            raise AssertionError(
                f"fuzz iteration={iteration} base_seed={base_seed} "
                f"derived_seed={seed} size_class={size_class}: {exc}; "
                f"params batches={batches} rows_per_batch={rows_per_batch} "
                f"settle_ms={settle_ms} do_second_failover={do_second_failover}\n"
                f"To reproduce: {repro}"
            ) from exc
