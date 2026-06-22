#!/usr/bin/env python3
"""Run the columnar Arrow SFA fuzz tests N times against one QuestDB fixture.

This is the columnar counterpart to ``_fuzz_loop.py``. It keeps one managed
QuestDB process alive, drops tables between iterations, and runs the SFA fuzz
shapes with a fresh random master seed each time.

Usage:

    python3 system_test/_arrow_sfa_fuzz_loop.py [iterations] [log_path]

Defaults: 25 iterations, log at system_test/_arrow_sfa_fuzz_loop.log.

Exit code: 0 only if every iteration passes.
"""

import io
import os
import pathlib
import sys
import time
import traceback
import unittest
import warnings

sys.dont_write_bytecode = True
warnings.filterwarnings("ignore", category=ResourceWarning)

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import questdb_line_sender as qls  # noqa: E402
import test as t  # noqa: E402  -- this is system_test/test.py
from fixture import QuestDbFixture, install_questdb_from_repo  # noqa: E402

ITERATIONS = int(sys.argv[1]) if len(sys.argv) > 1 else 25
LOG_PATH = (
    pathlib.Path(sys.argv[2])
    if len(sys.argv) > 2
    else (HERE / "_arrow_sfa_fuzz_loop.log")
)
REPO_PATH = pathlib.Path(
    os.environ.get("QDB_REPO_PATH", HERE.parent / "questdb")
).resolve()


def _columnar_sfa_fuzz_suite() -> unittest.TestSuite:
    suite = unittest.TestSuite()
    for name in (
        "test_sfa_random_arrow_ingest",
        "test_sfa_arrow_producer_survives_server_bounces",
    ):
        suite.addTest(t.TestArrowIngressSfa(name))
    return suite


def main() -> int:
    questdb_dir = install_questdb_from_repo(REPO_PATH)
    t.QDB_FIXTURE = QuestDbFixture(questdb_dir, auth=False, qwp_udp=False)
    t.BUILD_MODE = qls.BuildMode.CONF
    t.QDB_FIXTURE.http = False
    t.QDB_FIXTURE.protocol_version = sorted(list(qls.ProtocolVersion))[-1]

    failed_iters = []
    pass_count = 0
    started_at = time.monotonic()

    with open(LOG_PATH, "w", buffering=1) as log:
        log.write(
            f">>>> arrow-sfa-fuzz-loop started: iterations={ITERATIONS}, "
            f"repo={REPO_PATH}, log={LOG_PATH}\n"
        )
        sys.stderr.write(
            f">>>> arrow-sfa-fuzz-loop started: iterations={ITERATIONS}, "
            f"log={LOG_PATH}\n"
        )

        t.QDB_FIXTURE.start()
        try:
            for i in range(1, ITERATIONS + 1):
                t.QDB_FIXTURE.drop_all_tables()
                # Ensure each iteration picks its own fresh master seed via
                # secrets.randbits. The Arrow harness uses qwp_ws_fuzz's seed
                # helper, so this is the same env knob as the row SFA loop.
                os.environ.pop("QWP_WS_FUZZ_SEED", None)

                suite = _columnar_sfa_fuzz_suite()
                buf = io.StringIO()
                runner = unittest.TextTestRunner(
                    verbosity=2, stream=buf, buffer=False)
                start = time.monotonic()
                try:
                    result = runner.run(suite)
                except Exception:  # noqa: BLE001 -- keep the loop alive
                    log.write(f"\n===== iter {i} CRASH =====\n")
                    log.write(buf.getvalue())
                    log.write(traceback.format_exc())
                    sys.stderr.write(
                        f"[arrow-sfa-fuzz-loop {i:>3}/{ITERATIONS}] CRASH\n")
                    failed_iters.append(i)
                    continue
                dur = time.monotonic() - start
                if result.wasSuccessful():
                    pass_count += 1
                    sys.stderr.write(
                        f"[arrow-sfa-fuzz-loop {i:>3}/{ITERATIONS}] OK "
                        f"({dur:.1f}s, ran {result.testsRun})\n")
                else:
                    failed_iters.append(i)
                    sys.stderr.write(
                        f"[arrow-sfa-fuzz-loop {i:>3}/{ITERATIONS}] FAIL "
                        f"(failures={len(result.failures)} "
                        f"errors={len(result.errors)}, {dur:.1f}s)\n")
                    log.write(f"\n===== iter {i} FAIL =====\n")
                    log.write(buf.getvalue())
        finally:
            t.QDB_FIXTURE.stop()

        total_dur = time.monotonic() - started_at
        log.write(
            f">>>> arrow-sfa-fuzz-loop summary: {pass_count}/{ITERATIONS} OK, "
            f"wall={total_dur:.1f}s, failed_iters={failed_iters}\n")
        sys.stderr.write(
            f">>>> arrow-sfa-fuzz-loop summary: {pass_count}/{ITERATIONS} OK, "
            f"wall={total_dur:.1f}s, failed_iters={failed_iters}\n")

    return 0 if not failed_iters else 1


if __name__ == "__main__":
    sys.exit(main())
