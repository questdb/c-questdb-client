#!/usr/bin/env python3
"""Kill an offline SF publisher, then verify recovery on the existing local server."""
import argparse
import hashlib
import json
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import uuid

sys.dont_write_bytecode = True
from run_pool_baseline import create_table, environment, expected_groups, sql, verify


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    args.output.mkdir(parents=True, exist_ok=False)
    rows = 10003
    table = "qpbench_" + uuid.uuid4().hex
    create_table(table)
    try:
        with tempfile.TemporaryDirectory(prefix="qwp_pool_recovery_") as sf_dir:
            common = (f"lazy_connect=true;sender_pool_min=1;sender_pool_max=1;query_pool_min=0;pool_reap=manual;"
                      f"sf_dir={sf_dir};sender_id=pool_recovery;close_flush_timeout_millis=10000;"
                      "reconnect_max_duration_millis=60000;commit_rows=1000;commit_interval_ms=10;")
            env = environment("ws::addr=127.0.0.1:1;" + common, table, "per_flush", rows, 0, 1)
            env["QWP_POOL_BENCH_PAUSE_AFTER_PUBLISH"] = "on"
            seed = subprocess.Popen([str(binary)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            marker = ""
            try:
                ready, _, _ = select.select([seed.stdout], [], [], 30)
                assert ready, "publisher did not confirm SF acceptance"
                marker = seed.stdout.readline()
                assert marker.strip() == f"qwp_pool_bench_published rows={rows} publications={rows}", marker
            finally:
                seed.kill()
                stdout, stderr = seed.communicate(timeout=10)
                (args.output / "seed.stdout").write_text(marker + stdout)
                (args.output / "seed.stderr").write_text(stderr)
            assert seed.returncode == -9
            assert sql(f"select count() from {table}") == [[0]]
            assert list(Path(sf_dir).rglob("*.sfa")), "SF records must survive SIGKILL"
            env = environment("ws::addr=127.0.0.1:9000;" + common, table, "recover", rows, 0, 1)
            replay = subprocess.run([str(binary)], env=env, capture_output=True, text=True, timeout=30)
            (args.output / "replay.stdout").write_text(replay.stdout)
            (args.output / "replay.stderr").write_text(replay.stderr)
            assert replay.returncode == 0, replay.stderr
            report = {"table": table, "rows": rows, "seed_exit": seed.returncode,
                      "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                      "sf_mode": "disk, OS page cache; not a power-loss test",
                      "server_build": sql("select build()"), **verify(table, expected_groups(rows, 0))}
    finally:
        sql(f"drop table {table}")
    report["table_and_sf_directory_removed"] = True
    (args.output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
