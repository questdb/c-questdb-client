#!/usr/bin/env python3
"""Benchmark the shipped pool against localhost:9000; verify and remove fresh tables."""
import argparse
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import random
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import uuid

sys.dont_write_bytecode = True
BASE_TS = 1_700_000_000_000_000_000
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def sql(query):
    url = "http://127.0.0.1:9000/exec?" + urllib.parse.urlencode({"query": query})
    with OPENER.open(url, timeout=30) as response:
        result = json.load(response)
    if "error" in result:
        raise RuntimeError(result)
    return result["dataset"] if "dataset" in result else result


def create_table(table):
    sql(f"create table {table} (sym symbol capacity 1024, qty long, px double, ts timestamp_ns) timestamp(ts) partition by day WAL")


def expected_groups(rows, warmup):
    groups = {}
    for qty in range(-warmup, rows):
        sym = f"SYM{abs(qty) % 1000:04}"
        ts = BASE_TS + qty
        group = groups.setdefault(sym, [0, 0, 0, ts, ts])
        group[0] += 1
        group[1] += qty
        group[2] += 100 + (qty & 1023)
        group[4] = ts
    return groups


def verify(table, expected):
    deadline = time.monotonic() + 120
    while True:
        groups = sql(f"select sym, count(), sum(qty), sum(px), min(cast(ts as long)), max(cast(ts as long)) from {table}")
        if {row[0]: row[1:] for row in groups} == expected:
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"{table}: all-column validation failed")
        time.sleep(0.05)
    wal = sql(f"select writerTxn, sequencerTxn, suspended from wal_tables() where name='{table}'")[0]
    assert wal[0] == wal[1] and wal[2] is False, wal
    return {"wal": wal, "verified_symbol_groups": len(groups),
            "grouped_data_sha256": hashlib.sha256(json.dumps(sorted(groups)).encode()).hexdigest()}


def environment(conf, table, mode, rows, warmup, batch):
    env = {k: v for k, v in os.environ.items() if not k.startswith("QWP_POOL_BENCH_")}
    env.update(NO_PROXY="127.0.0.1,localhost", no_proxy="127.0.0.1,localhost",
               QWP_POOL_BENCH_CONF=conf, QWP_POOL_BENCH_TABLE=table,
               QWP_POOL_BENCH_MODE=mode, QWP_POOL_BENCH_ROWS=str(rows),
               QWP_POOL_BENCH_WARMUP=str(warmup), QWP_POOL_BENCH_BATCH=str(batch),
               QWP_POOL_BENCH_SYMBOLS="1000")
    return env


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rows", type=int, default=1_000_000)
    parser.add_argument("--warmup", type=int, default=10_000)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--case", action="append", dest="cases")
    parser.add_argument("--variant", action="append", choices=("network", "commit"))
    parser.add_argument("--sf-mode", choices=("memory", "disk"), default="memory")
    parser.add_argument("--commit-rows", type=int, default=1000)
    parser.add_argument("--commit-interval-ms", type=int, default=10)
    args = parser.parse_args()
    if min(args.rows, args.rounds, args.commit_rows, args.commit_interval_ms) <= 0 or args.warmup < 0:
        parser.error("rows, rounds and commit limits must be positive; warmup must be nonnegative")
    cases = args.cases or ["per_flush:1", "per_flush:1000", "standalone:1000"]
    trials = []
    for case in cases:
        try:
            mode, batch = case.split(":")
            assert mode in ("hold", "per_flush", "standalone") and int(batch) > 0
        except (ValueError, AssertionError):
            parser.error(f"invalid case: {case}")
        for variant in args.variant or ["network", "commit"]:
            if mode != "standalone" or variant == "network":
                trials.append((case, variant))
    if not trials:
        parser.error("commit windows apply to the pool, not standalone senders")
    binary = args.binary.resolve(strict=True)
    args.output.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[2]
    sources = ["Cargo.toml", "examples/qwp_pool_bench.rs", "src/db.rs", "src/db/conf.rs",
               "src/ingress/buffer/qwp.rs", "src/ingress/column_sender/sender.rs",
               "src/ingress/sender/qwp_ws.rs", "src/ingress/sender/qwp_ws_batch.rs",
               "src/ingress/sender/qwp_ws_driver.rs", "src/ingress/sender/qwp_ws_sfa_queue.rs"]
    metadata = {
        "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "source_sha256": {p: hashlib.sha256((root / "questdb-rs" / p).read_bytes()).hexdigest() for p in sources},
        "platform": platform.platform(), "server_build": sql("select build()"),
        "rows": args.rows, "warmup": args.warmup, "rounds": args.rounds,
        "sf_mode": args.sf_mode, "disk_durability": "OS page cache, default 4 MiB segments",
        "commit_rows": args.commit_rows, "commit_interval_ms": args.commit_interval_ms,
        "completion": "OK ACK on last publishing lease; all-column SQL verification outside timing",
        "cases": trials,
    }
    (args.output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    expected = expected_groups(args.rows, args.warmup)
    records = []
    randomizer = random.Random(42)
    for round_no in range(args.rounds):
        order = trials.copy()
        randomizer.shuffle(order)
        for case, variant in order:
            mode, batch = case.split(":")
            batch = int(batch)
            label = f"{variant}/{case}"
            table = "qpbench_" + uuid.uuid4().hex
            print(f"START round={round_no + 1} case={label}", flush=True)
            with tempfile.TemporaryDirectory(prefix="qwp_pool_bench_") as sf_dir:
                conf = "ws::addr=127.0.0.1:9000;sender_pool_min=1;sender_pool_max=1;pool_reap=manual;"
                if args.sf_mode == "disk":
                    conf += f"sf_dir={sf_dir};sender_id=pool_bench;"
                if variant == "commit":
                    conf += f"commit_rows={args.commit_rows};commit_interval_ms={args.commit_interval_ms};"
                create_table(table)
                try:
                    process = subprocess.run([str(binary)], env=environment(conf, table, mode, args.rows, args.warmup, batch),
                                             capture_output=True, text=True, timeout=600)
                    (args.output / f"{len(records):03}.stdout").write_text(process.stdout)
                    (args.output / f"{len(records):03}.stderr").write_text(process.stderr)
                    if process.returncode:
                        raise RuntimeError(process.stderr)
                    metrics = dict(item.split("=", 1) for item in process.stdout.strip().split())
                    for key in ("rows", "batch", "warmup", "symbols", "frames"):
                        metrics[key] = int(metrics[key])
                    for key in ("publish_ms", "drain_ms", "total_ms", "publish_cpu_ms", "total_cpu_ms", "acked_rows_per_sec"):
                        value = float(metrics[key])
                        metrics[key] = value if math.isfinite(value) else None
                    assert metrics["frames"] == math.ceil(args.rows / batch)
                    verification = verify(table, expected)
                    publications = math.ceil(args.rows / batch) + math.ceil(args.warmup / batch)
                    if variant == "network":
                        assert verification["wal"][:2] == [publications, publications], verification
                    else:
                        assert 0 < verification["wal"][0] <= publications, verification
                    record = {"round": round_no + 1, "case": label, **metrics, **verification}
                finally:
                    sql(f"drop table {table}")
            record["table_and_sf_directory_removed"] = True
            records.append(record)
            with (args.output / "runs.jsonl").open("a") as out:
                out.write(json.dumps(record) + "\n")
            print(f"DONE {label}: {record['total_ms']:.3f} ms, verified and cleaned", flush=True)
    summary = {}
    for case, variant in trials:
        label = f"{variant}/{case}"
        group = [r for r in records if r["case"] == label]
        summary[label] = {
            key: {"median": statistics.median(values), "min": min(values), "max": max(values)}
            for key in ("publish_ms", "drain_ms", "total_ms", "total_cpu_ms")
            if (values := [r[key] for r in group if r[key] is not None])
        }
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
