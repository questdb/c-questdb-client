"""Arrow C Data Interface egress fuzz — live-server end-to-end.

Drives `line_reader_cursor_next_arrow_batch` from Python via PyArrow's
`_import_from_c`. Each iteration:

1. Picks a random subset of Arrow-round-trip-able types from the QWP type
   matrix and creates a fresh QuestDB table for them.
2. Generates ``ROWS_PER_ITER`` rows of deterministic values and ingests
   them through the **existing** QWP/WS Sender (the egress fuzz tests
   reading, not writing).
3. Waits for the rows to land via ``SELECT count(*)``.
4. Streams the result back via the new Arrow C ABI:
   ``line_reader_cursor_next_arrow_batch`` → pyarrow.RecordBatch.
5. Asserts that:
     * PyArrow accepts every batch (Apache-Arrow-spec valid).
     * The total row count matches the expected.
     * Per-cell values round-trip equal modulo documented degradations
       (validity inversion, SYMBOL dict densification, GEOHASH widening).
6. Cleans up the table.

Reproducer seed: ``QWP_WS_FUZZ_SEED=0x...``.
"""

from __future__ import annotations

import datetime as _dt
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


_ARROW_FUZZ_ITER_DEFAULT = int(os.environ.get("ARROW_EGRESS_FUZZ_ITERATIONS", "8"))
ROWS_PER_ITER = int(os.environ.get("ARROW_EGRESS_FUZZ_ROWS", "16"))


ARROW_KIND_DDL = {
    "boolean": "BOOLEAN",
    "byte": "BYTE",
    "short": "SHORT",
    "int": "INT",
    "long": "LONG",
    "float": "FLOAT",
    "double": "DOUBLE",
    "char": "CHAR",
    "ipv4": "IPV4",
    "symbol": "SYMBOL",
    "varchar": "VARCHAR",
    "binary": "BINARY",
    "uuid": "UUID",
    "long256": "LONG256",
    "date": "DATE",
    "timestamp": "TIMESTAMP",
    "timestamp_ns": "TIMESTAMP_NS",
}


def _connect_existing_sender(host: str, port: int, sender_id: str, sf_dir: str):
    """Build a QWP/WS Sender via the *existing* (non-Arrow) Python wrapper."""
    import questdb_line_sender as qls
    conf = (
        f"qwpws::addr={host}:{port};"
        f"sender_id={sender_id};"
        f"sf_dir={sf_dir};"
    )
    sender = qls.Sender.from_conf(conf)
    sender.connect()
    return sender


def _populate_via_existing_sender(sender, table: str, rows):
    """Write each row through the existing per-type column setters."""
    for r in rows:
        line = sender.table(table)
        for col_name, kind, value in r["cols"]:
            if value is None:
                continue
            if kind == "boolean":
                line.column(col_name, bool(value))
            elif kind in ("byte", "short", "int", "long"):
                line.column(col_name, int(value))
            elif kind in ("float", "double"):
                line.column(col_name, float(value))
            elif kind == "char":
                line.column_char(col_name, int(value))
            elif kind == "ipv4":
                line.column_ipv4(col_name, int(value))
            elif kind == "symbol":
                line.symbol(col_name, str(value))
            elif kind == "varchar":
                line.column(col_name, str(value))
            elif kind == "binary":
                line.column_binary(col_name, bytes(value))
            elif kind == "uuid":
                lo, hi = value
                line.column_uuid(col_name, lo, hi)
            elif kind == "long256":
                line.column_long256(col_name, bytes(value))
            elif kind == "date":
                line.column_date(col_name, int(value))
            elif kind == "timestamp":
                line.column_ts_micros(col_name, int(value))
            elif kind == "timestamp_ns":
                line.column_ts_nanos(col_name, int(value))
            else:
                raise ValueError(f"unhandled kind {kind!r}")
        line.at_micros(r["ts_us"])


def _generate_row(row_idx: int, kinds, rnd: qwp_ws_fuzz.Rng):
    cols = []
    for col_name, kind in kinds:
        cols.append((col_name, kind, _gen_value_for_kind(kind, row_idx, rnd)))
    return {"ts_us": qwp_ws_fuzz.QwpWsTestSupport.BASE_TIMESTAMP_US + row_idx,
            "cols": cols}


def _gen_value_for_kind(kind: str, row_idx: int, rnd: qwp_ws_fuzz.Rng):
    if kind == "boolean":
        return (row_idx & 1) == 0
    if kind == "byte":
        return (row_idx % 200) - 100
    if kind == "short":
        return row_idx * 7 - 1
    if kind == "int":
        return row_idx * 13 - 17
    if kind == "long":
        return row_idx * 1_000_003
    if kind == "float":
        return float(row_idx) * 0.5
    if kind == "double":
        return float(row_idx) * 1.25
    if kind == "char":
        return 0x41 + (row_idx % 26)
    if kind == "ipv4":
        return 0x0A000000 | (row_idx & 0xFF_FFFF)
    if kind == "symbol":
        return ["alpha", "beta", "gamma", "delta"][row_idx % 4]
    if kind == "varchar":
        return f"row-{row_idx:04d}"
    if kind == "binary":
        return bytes((row_idx & 0xFF, (row_idx >> 8) & 0xFF, 0xAA, 0x55))
    if kind == "uuid":
        return (row_idx, 0xCAFE_BABE_DEAD_BEEF)
    if kind == "long256":
        return bytes([row_idx & 0xFF] * 32)
    if kind == "date":
        return 1_700_000_000_000 + row_idx
    if kind == "timestamp":
        return 1_700_000_000_000_000 + row_idx
    if kind == "timestamp_ns":
        return 1_700_000_000_000_000_000 + row_idx
    raise ValueError(f"no generator for kind {kind!r}")


def _pyarrow_cell(rb, col_idx: int, row_idx: int):
    col = rb.column(col_idx)
    if col.is_null(row_idx):
        return None
    return col[row_idx].as_py()


class TestArrowEgressFuzz(unittest.TestCase):
    ITERATIONS = _ARROW_FUZZ_ITER_DEFAULT

    def setUp(self):
        from test import QDB_FIXTURE, QuestDbFixture, QuestDbExternalFixture
        if not isinstance(QDB_FIXTURE, (QuestDbFixture, QuestDbExternalFixture)):
            self.skipTest("Arrow egress fuzz requires a live QuestDB fixture")
        try:
            import pyarrow  # noqa: F401
        except ImportError:
            self.skipTest("pyarrow is required for the Arrow egress fuzz")
        seed = qwp_ws_fuzz.derive_master_seed()
        self._master_rng = qwp_ws_fuzz.Rng(seed)
        self._seed_label = qwp_ws_fuzz.format_seed(seed)
        sys.stderr.write(f"[arrow_egress_fuzz seed] {self.id()} {self._seed_label}\n")
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

    def test_per_type_round_trip_across_iterations(self):
        all_kinds = list(ARROW_KIND_DDL.keys())
        for it in range(self.ITERATIONS):
            self._master_rng.shuffle(all_kinds)
            picked = all_kinds[: 4 + (it % 4)]
            self._run_one_iteration(it, picked)

    def _run_one_iteration(self, iter_idx: int, kinds: list):
        from test import sql_query
        run_id = uuid.uuid4().hex[:8]
        table = f"arrow_eg_{run_id}_{iter_idx}"
        col_defs = ["ts TIMESTAMP"]
        col_names = []
        for i, k in enumerate(kinds):
            cn = f"c{i}_{k}"
            col_names.append((cn, k))
            col_defs.append(f"\"{cn}\" {ARROW_KIND_DDL[k]}")
        ddl = (
            f"CREATE TABLE '{table}' ({', '.join(col_defs)}) "
            f"TIMESTAMP(ts) PARTITION BY DAY WAL"
        )
        sql_query(ddl)
        self._created_tables.append(table)
        rows = [_generate_row(i, col_names, self._master_rng) for i in range(ROWS_PER_ITER)]
        sf_dir = f"/tmp/arrow_eg_{run_id}_{iter_idx}"
        os.makedirs(sf_dir, exist_ok=True)
        sender = _connect_existing_sender(
            self._fixture.host,
            self._fixture.http_server_port,
            f"arrow-eg-{run_id}",
            sf_dir,
        )
        try:
            _populate_via_existing_sender(sender, table, rows)
            sender.flush()
        finally:
            sender.close()
        self._wait_for_rows(table, len(rows))
        self._read_back_and_assert(table, col_names, rows)

    def _wait_for_rows(self, table: str, expected: int, timeout_s: float = 20.0):
        from test import sql_query
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            resp = sql_query(f"select count() from '{table}'")
            if int(resp["dataset"][0][0]) >= expected:
                return
            time.sleep(0.1)
        self.fail(f"timed out waiting for {expected} rows in {table}")

    def _read_back_and_assert(self, table, col_names, rows):
        sql = (
            f"select "
            + ", ".join(f"\"{c}\"" for c, _ in col_names)
            + f" from '{table}' order by ts"
        )
        cursor, reader = self._arrow_cursor(sql)
        try:
            collected = []
            while True:
                rc, arr, sch = next_arrow_batch(cursor)
                if rc == NEXT_ARROW_BATCH_END:
                    break
                if rc != NEXT_ARROW_BATCH_OK:
                    self.fail(f"unexpected rc={rc}")
                rb = pyarrow_import_record_batch(arr, sch)
                self.assertGreater(rb.num_columns, 0)
                collected.append(rb)
            total = sum(rb.num_rows for rb in collected)
            self.assertEqual(total, len(rows), f"row count mismatch (table={table})")
            self._assert_per_cell_equal(collected, col_names, rows)
        finally:
            from qwp_egress_reader import _DLL
            _DLL.line_reader_cursor_free(cursor)
            _DLL.line_reader_close(reader)

    def _arrow_cursor(self, sql: str):
        from qwp_egress_reader import _DLL, _LineReader, _LineReaderError, _utf8
        import ctypes
        conf = self._fixture.qwp_conf() if hasattr(self._fixture, "qwp_conf") else None
        if conf is None:
            self.skipTest("fixture does not expose qwp_conf()")
        conf_utf8 = _utf8(conf)
        err_ref = ctypes.POINTER(_LineReaderError)()
        reader = _DLL.line_reader_from_conf(conf_utf8, ctypes.byref(err_ref))
        self.assertTrue(bool(reader), f"line_reader_from_conf failed (label={self._seed_label})")
        sql_utf8 = _utf8(sql)
        err_ref = ctypes.POINTER(_LineReaderError)()
        cursor = _DLL.line_reader_execute(reader, sql_utf8, ctypes.byref(err_ref))
        self.assertTrue(bool(cursor), f"line_reader_execute failed (label={self._seed_label})")
        return cursor, reader

    def _assert_per_cell_equal(self, batches, col_names, rows):
        flat_idx = 0
        for rb in batches:
            for r in range(rb.num_rows):
                expected_row = rows[flat_idx]
                for col_idx, (col_name, kind) in enumerate(col_names):
                    expected = expected_row["cols"][col_idx][2]
                    actual = _pyarrow_cell(rb, col_idx, r)
                    self._assert_value(kind, col_name, expected, actual)
                flat_idx += 1
        self.assertEqual(flat_idx, len(rows))

    def _assert_value(self, kind, col_name, expected, actual):
        if expected is None:
            self.assertIsNone(
                actual,
                f"col={col_name} kind={kind} expected None got {actual!r} (seed={self._seed_label})",
            )
            return
        if kind == "boolean":
            self.assertEqual(bool(actual), bool(expected))
        elif kind in ("byte", "short", "int", "long", "char", "ipv4"):
            self.assertEqual(int(actual), int(expected),
                             f"col={col_name} (seed={self._seed_label})")
        elif kind == "float":
            self.assertAlmostEqual(float(actual), float(expected), places=5)
        elif kind == "double":
            self.assertAlmostEqual(float(actual), float(expected), places=10)
        elif kind == "symbol":
            self.assertEqual(str(actual), str(expected))
        elif kind == "varchar":
            self.assertEqual(str(actual), str(expected))
        elif kind == "binary":
            self.assertEqual(bytes(actual), bytes(expected))
        elif kind == "uuid":
            lo, hi = expected
            uuid_int = (hi << 64) | lo
            actual_uuid = uuid.UUID(bytes=bytes(actual)) if isinstance(actual, (bytes, bytearray)) else actual
            if isinstance(actual_uuid, uuid.UUID):
                self.assertEqual(actual_uuid.int, uuid_int)
            else:
                self.assertEqual(actual, expected)
        elif kind == "long256":
            self.assertEqual(bytes(actual), bytes(expected))
        elif kind == "date":
            if isinstance(actual, _dt.datetime):
                expected_dt = _dt.datetime.fromtimestamp(expected / 1000.0, tz=_dt.timezone.utc)
                self.assertEqual(actual.replace(tzinfo=_dt.timezone.utc), expected_dt)
            else:
                self.assertEqual(int(actual), int(expected))
        elif kind in ("timestamp", "timestamp_ns"):
            if isinstance(actual, _dt.datetime):
                divisor = 1_000_000 if kind == "timestamp" else 1_000_000_000
                expected_dt = _dt.datetime.fromtimestamp(expected / divisor, tz=_dt.timezone.utc)
                self.assertEqual(actual.replace(tzinfo=_dt.timezone.utc), expected_dt)
            else:
                self.assertEqual(int(actual), int(expected))
        else:
            self.fail(f"no oracle for kind {kind!r}")


def register(loop_registry):
    loop_registry.append(TestArrowEgressFuzz)


if __name__ == "__main__":
    unittest.main()
