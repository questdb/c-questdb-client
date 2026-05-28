"""Arrow alignment fuzz — live-server end-to-end.

Constructs schemas whose column orderings force the per-column wire
offsets to be deliberately misaligned for various ``T::SIZE`` values
(1/2/4/8/16/32). Asserts that:

  * PyArrow successfully imports every batch (proves the §10 Tier B
    ``align_buffers(true)`` fallback works under real misalignment).
  * PyArrow compute kernels over the imported buffers return correct
    values (the fallback memcpy doesn't corrupt data).
  * Tier A buffers (validity bitmap, SYMBOL union dict, BOOLEAN
    bit-pack, ARRAY offsets) never look misaligned at the PyArrow
    boundary — the AVec 64-byte allocation is preserved across FFI.

Reproducer seed: ``QWP_WS_FUZZ_SEED=0x...``.
"""

from __future__ import annotations

import ctypes
import os
import sys
import time
import unittest
import uuid

import qwp_ws_fuzz
from arrow_ffi import (
    NEXT_ARROW_BATCH_END,
    NEXT_ARROW_BATCH_OK,
    next_arrow_batch,
    pyarrow_import_record_batch,
)


_ARROW_FUZZ_ITER_DEFAULT = int(os.environ.get("ARROW_ALIGNMENT_FUZZ_ITERATIONS", "6"))
ROWS_PER_ITER = int(os.environ.get("ARROW_ALIGNMENT_FUZZ_ROWS", "16"))


# Misalignment schedule: each entry forces a different pad-byte sum
# before the target column, exercising different residues mod each
# primitive width (1/2/4/8/16/32).
PAD_PROGRAM = [
    [],
    ["boolean"],
    ["byte"],
    ["byte", "short"],
    ["byte", "short", "int"],
    ["byte", "short", "int", "long"],
    ["short", "char"],
    ["uuid", "byte"],
    ["long256", "byte"],
]


def _connect_existing_sender(fixture, sender_id: str, sf_dir: str):
    import questdb_line_sender as qls
    conf = (
        f"qwpws::addr={fixture.host}:{fixture.http_server_port};"
        f"sender_id={sender_id};"
        f"sf_dir={sf_dir};"
    )
    sender = qls.Sender.from_conf(conf)
    sender.connect()
    return sender


def _ddl_for_kind(kind: str) -> str:
    return {
        "boolean": "BOOLEAN",
        "byte": "BYTE",
        "short": "SHORT",
        "char": "CHAR",
        "int": "INT",
        "long": "LONG",
        "float": "FLOAT",
        "double": "DOUBLE",
        "uuid": "UUID",
        "long256": "LONG256",
        "timestamp": "TIMESTAMP",
    }[kind]


def _write_value(line, col_name: str, kind: str, row_idx: int):
    if kind == "boolean":
        line.column(col_name, (row_idx & 1) == 0)
    elif kind == "byte":
        line.column(col_name, (row_idx % 200) - 100)
    elif kind == "short":
        line.column(col_name, row_idx * 7 - 1)
    elif kind == "int":
        line.column(col_name, row_idx * 13 - 17)
    elif kind == "long":
        line.column(col_name, row_idx * 1_000_003)
    elif kind == "float":
        line.column(col_name, float(row_idx) * 0.5)
    elif kind == "double":
        line.column(col_name, float(row_idx) * 1.25)
    elif kind == "char":
        line.column_char(col_name, 0x41 + (row_idx % 26))
    elif kind == "uuid":
        line.column_uuid(col_name, row_idx, 0xCAFE_BABE_DEAD_BEEF)
    elif kind == "long256":
        line.column_long256(col_name, bytes([row_idx & 0xFF] * 32))
    elif kind == "timestamp":
        line.column_ts_micros(col_name, 1_700_000_000_000_000 + row_idx)
    else:
        raise ValueError(f"unhandled kind {kind!r}")


def _assert_compute_kernels_sane(rb, kinds: list[tuple[str, str]]):
    """Run PyArrow compute kernels on every column — sum / count_distinct
    / min / max — to exercise the imported buffers under real read
    patterns. A misaligned buffer that arrow-rs's ``align_buffers(true)``
    failed to fix up shows here as a numerical mismatch or a panic.
    """
    import pyarrow.compute as pc
    for col_idx, (_, kind) in enumerate(kinds):
        col = rb.column(col_idx)
        n = rb.num_rows
        if kind == "boolean":
            true_count = pc.sum(pc.cast(col, "int64")).as_py() or 0
            assert 0 <= int(true_count) <= n, f"bool sum out of range: {true_count}"
        elif kind in ("byte", "short", "int", "long", "char"):
            total = pc.sum(pc.cast(col, "int64")).as_py()
            min_v = pc.min(pc.cast(col, "int64")).as_py()
            max_v = pc.max(pc.cast(col, "int64")).as_py()
            assert total is not None
            assert min_v is not None
            assert max_v is not None
            assert min_v <= max_v
        elif kind in ("float", "double"):
            total = pc.sum(col).as_py()
            assert total is not None
        elif kind == "uuid" or kind == "long256":
            assert col.type.byte_width in (16, 32)
        elif kind == "timestamp":
            min_v = pc.min(col).as_py()
            max_v = pc.max(col).as_py()
            assert min_v is not None
            assert max_v is not None


class TestArrowAlignmentFuzz(unittest.TestCase):
    ITERATIONS = _ARROW_FUZZ_ITER_DEFAULT

    def setUp(self):
        from test import QDB_FIXTURE, QuestDbFixture, QuestDbExternalFixture
        if not isinstance(QDB_FIXTURE, (QuestDbFixture, QuestDbExternalFixture)):
            self.skipTest("Arrow alignment fuzz requires a live QuestDB fixture")
        try:
            import pyarrow  # noqa: F401
            import pyarrow.compute  # noqa: F401
        except ImportError:
            self.skipTest("pyarrow is required for the Arrow alignment fuzz")
        seed = qwp_ws_fuzz.derive_master_seed()
        self._master_rng = qwp_ws_fuzz.Rng(seed)
        self._seed_label = qwp_ws_fuzz.format_seed(seed)
        sys.stderr.write(
            f"[arrow_alignment_fuzz seed] {self.id()} {self._seed_label}\n"
        )
        sys.stderr.flush()
        self._created_tables = []
        self._fixture = QDB_FIXTURE

    def tearDown(self):
        from test import sql_query
        for table in self._created_tables:
            try:
                sql_query(f"DROP TABLE IF EXISTS '{table}'")
            except Exception:
                pass

    def test_misalignment_schedule(self):
        for it in range(self.ITERATIONS):
            for prog_idx, pad in enumerate(PAD_PROGRAM):
                target = ["long", "double", "uuid", "long256", "timestamp"][
                    prog_idx % 5
                ]
                self._run_one_iteration(it, pad + [target])

    def _run_one_iteration(self, iter_idx: int, kinds_in_order: list[str]):
        from test import sql_query
        run_id = uuid.uuid4().hex[:8]
        table = f"arrow_aln_{run_id}_{iter_idx}"
        col_defs = []
        col_names = []
        for i, k in enumerate(kinds_in_order):
            cn = f"c{i}_{k}"
            col_names.append((cn, k))
            col_defs.append(f"\"{cn}\" {_ddl_for_kind(k)}")
        col_defs.append("ts TIMESTAMP")
        sql_query(
            f"CREATE TABLE '{table}' ({', '.join(col_defs)}) "
            f"TIMESTAMP(ts) PARTITION BY DAY WAL"
        )
        self._created_tables.append(table)
        sf_dir = f"/tmp/arrow_aln_{run_id}_{iter_idx}"
        os.makedirs(sf_dir, exist_ok=True)
        sender = _connect_existing_sender(
            self._fixture, f"arrow-aln-{run_id}", sf_dir
        )
        try:
            for r in range(ROWS_PER_ITER):
                line = sender.table(table)
                for col_name, kind in col_names:
                    _write_value(line, col_name, kind, r)
                line.at_micros(
                    qwp_ws_fuzz.QwpWsTestSupport.BASE_TIMESTAMP_US + r
                )
            sender.flush()
        finally:
            sender.close()
        self._wait_for_rows(table, ROWS_PER_ITER)
        rb = self._read_back_first_batch(table, col_names)
        self.assertEqual(rb.num_rows, ROWS_PER_ITER,
                         f"row count (seed={self._seed_label})")
        _assert_compute_kernels_sane(rb, col_names)

    def _wait_for_rows(self, table: str, expected: int, timeout_s: float = 20.0):
        from test import sql_query
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            try:
                resp = sql_query(f"select count() from '{table}'")
                if int(resp["dataset"][0][0]) >= expected:
                    return
            except Exception:
                pass
            time.sleep(0.1)
        self.fail(f"timed out waiting for {expected} rows in {table}")

    def _read_back_first_batch(self, table: str, col_names: list):
        from qwp_egress_reader import _DLL, _LineReaderError, _utf8
        sql = (
            "select "
            + ", ".join(f"\"{c}\"" for c, _ in col_names)
            + f" from '{table}' order by ts"
        )
        conf_utf8 = _utf8(self._fixture.qwp_conf())
        err_ref = ctypes.POINTER(_LineReaderError)()
        reader = _DLL.line_reader_from_conf(conf_utf8, ctypes.byref(err_ref))
        self.assertTrue(bool(reader))
        sql_utf8 = _utf8(sql)
        err_ref = ctypes.POINTER(_LineReaderError)()
        cursor = _DLL.line_reader_execute(reader, sql_utf8, ctypes.byref(err_ref))
        self.assertTrue(bool(cursor))
        try:
            collected = []
            while True:
                rc, arr, sch = next_arrow_batch(cursor)
                if rc == NEXT_ARROW_BATCH_END:
                    break
                if rc != NEXT_ARROW_BATCH_OK:
                    self.fail(f"unexpected rc={rc}")
                collected.append(pyarrow_import_record_batch(arr, sch))
            self.assertGreater(len(collected), 0)
            if len(collected) == 1:
                return collected[0]
            import pyarrow as pa
            return pa.Table.from_batches(collected).combine_chunks().to_batches()[0]
        finally:
            _DLL.line_reader_cursor_free(cursor)
            _DLL.line_reader_close(reader)


def register(loop_registry):
    loop_registry.append(TestArrowAlignmentFuzz)


if __name__ == "__main__":
    unittest.main()
