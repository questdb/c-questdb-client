from __future__ import annotations

import contextlib
import io
import math
import sys
import types
import unittest
import uuid
from unittest import mock

import pyarrow as pa

import arrow_fuzz_common as afc
import arrow_ingress_fuzz as aif
import fixture


def _norm_cell(v):
    """Normalise a scalar `as_py()` value to a representation-agnostic form.

    The `arrow.uuid` kind is a plain `FixedSizeBinary(16)` carrying the
    `ARROW:extension:name` field metadata. A source array surfaces it as
    `bytes`, but once it crosses the Arrow C Data Interface pyarrow
    recognises the canonical extension and materialises `uuid.UUID`. Both
    encode the same 16 bytes, so collapse UUID to its big-endian bytes
    before comparing values across an FFI round-trip.
    """
    if isinstance(v, uuid.UUID):
        return v.bytes
    return v


class TestKindRegistryCompleteness(unittest.TestCase):
    """Every registry entry must satisfy the KindSpec contract."""

    def test_all_specs_resolve(self):
        self.assertGreater(len(afc.KIND_REGISTRY), 20,
                           "registry should contain ~28 entries")
        for name, spec in afc.KIND_REGISTRY.items():
            with self.subTest(kind=name):
                self.assertEqual(spec.name, name)
                self.assertIsInstance(spec.ddl, str)
                self.assertTrue(spec.ddl, "DDL fragment must be non-empty")
                dtype = spec.arrow_type()
                self.assertIsInstance(dtype, pa.DataType)
                # `metadata()` returns either None or a dict[bytes, bytes].
                md = spec.metadata()
                if md is not None:
                    self.assertIsInstance(md, dict)
                    for k, v in md.items():
                        self.assertIsInstance(k, (bytes, str))
                        self.assertIsInstance(v, (bytes, str))

    def test_each_spec_builds_valid_arrow_array(self):
        rnd = afc.Rng(0xDEADBEEF)
        for name, spec in afc.KIND_REGISTRY.items():
            with self.subTest(kind=name):
                mask = afc.all_valid_mask(8)
                values = spec.generate_values(rnd, 8, mask, edge=False)
                self.assertEqual(len(values), 8)
                arr = spec.build_arrow_array(values)
                self.assertEqual(len(arr), 8)
                self.assertEqual(arr.null_count, 0)

    def test_each_spec_handles_null_mask(self):
        rnd = afc.Rng(0xCAFEBABE)
        for name, spec in afc.KIND_REGISTRY.items():
            with self.subTest(kind=name):
                mask = [True, False, True, False, True, False, True, False]
                values = spec.generate_values(rnd, 8, mask, edge=False)
                arr = spec.build_arrow_array(values)
                self.assertEqual(arr.null_count, 4,
                                 f"{name}: expected 4 nulls")

    def test_each_spec_handles_all_null(self):
        rnd = afc.Rng(0x12345678)
        for name, spec in afc.KIND_REGISTRY.items():
            with self.subTest(kind=name):
                mask = afc.all_null_mask(8)
                values = spec.generate_values(rnd, 8, mask, edge=False)
                arr = spec.build_arrow_array(values)
                self.assertEqual(arr.null_count, 8,
                                 f"{name}: expected 8 nulls")

    def test_field_construction_carries_metadata(self):
        for name, spec in afc.KIND_REGISTRY.items():
            with self.subTest(kind=name):
                field = spec.make_field(f"c_{name}")
                if spec.metadata() is not None:
                    self.assertIsNotNone(field.metadata,
                                         f"{name}: field metadata stripped")

    def test_edge_mode_produces_distinct_values(self):
        rnd = afc.Rng(0xFEEDFACE)
        for name, spec in afc.KIND_REGISTRY.items():
            with self.subTest(kind=name):
                mask = afc.all_valid_mask(8)
                normal = spec.generate_values(rnd, 8, mask, edge=False)
                edge = spec.generate_values(rnd, 8, mask, edge=True)
                self.assertEqual(len(normal), len(edge))


class TestCompareSemantics(unittest.TestCase):
    def test_default_equality(self):
        spec = afc.KIND_REGISTRY["int"]
        self.assertTrue(spec.compare(42, 42))
        self.assertFalse(spec.compare(42, 43))
        self.assertTrue(spec.compare(None, None))
        self.assertFalse(spec.compare(None, 0))

    def test_float_nan_compares_equal_to_itself(self):
        spec = afc.KIND_REGISTRY["double"]
        nan = float("nan")
        self.assertTrue(spec.compare(nan, nan))
        self.assertFalse(spec.compare(nan, 0.0))
        self.assertTrue(spec.compare(float("inf"), float("inf")))
        self.assertTrue(spec.compare(float("inf"), float("-inf")))
        self.assertTrue(spec.compare(float("nan"), float("inf")))

    def test_float32_rounding_tolerated(self):
        spec = afc.KIND_REGISTRY["float"]
        self.assertTrue(spec.compare(0.5, 0.5))
        self.assertFalse(spec.compare(0.1, 0.2))

    def test_decimal_normalises(self):
        from decimal import Decimal
        spec = afc.KIND_REGISTRY["decimal64"]
        self.assertTrue(spec.compare(Decimal("1.10"), Decimal("1.1")))
        self.assertTrue(spec.compare(Decimal("0"), Decimal("0.000")))


class TestRngDeterminism(unittest.TestCase):
    def test_two_rngs_same_seed_match(self):
        a = afc.Rng(0xAA55AA55)
        b = afc.Rng(0xAA55AA55)
        for _ in range(20):
            self.assertEqual(a.next_int(1_000_000), b.next_int(1_000_000))

    def test_seed_label_round_trips(self):
        for seed in (0x0, 0x1, 0xDEADBEEF, (1 << 63)):
            label = afc.format_seed(seed)
            self.assertEqual(label, f"0x{seed:016x}")


class TestBuildRecordBatch(unittest.TestCase):
    def test_build_minimal_batch(self):
        rnd = afc.Rng(0xBEEF1234)
        kinds = [
            ("c_int", afc.KIND_REGISTRY["int"]),
            ("c_double", afc.KIND_REGISTRY["double"]),
            ("c_symbol", afc.KIND_REGISTRY["symbol"]),
        ]
        rb = afc.build_record_batch(kinds, rnd, 4, null_mode="valid")
        self.assertEqual(rb.num_rows, 4)
        self.assertEqual(rb.num_columns, 4)  # 3 kinds + ts
        self.assertEqual(rb.column(3).type, pa.timestamp("us", tz="UTC"))

    def test_partial_null_mode_inserts_some_nulls(self):
        rnd = afc.Rng(0xABCD)
        kinds = [("c_int", afc.KIND_REGISTRY["int"])]
        rb = afc.build_record_batch(kinds, rnd, 100, null_mode="partial",
                                     null_p=0.5)
        nulls = rb.column(0).null_count
        self.assertGreater(nulls, 10, "expected >10 nulls in 100-row sample")
        self.assertLess(nulls, 90)

    def test_all_null_mode(self):
        rnd = afc.Rng(0x9999)
        kinds = [("c_uuid", afc.KIND_REGISTRY["uuid"])]
        rb = afc.build_record_batch(kinds, rnd, 8, null_mode="all_null")
        self.assertEqual(rb.column(0).null_count, 8)


class TestSlicedRecordBatchOffsets(unittest.TestCase):
    """Server-free guard for the non-zero-offset / sliced-array surface.

    The Rust unit tests cannot easily produce `offset() != 0` because
    arrow-rs re-bases `Array::slice()` to offset 0, but an FFI-imported
    sliced array *does* carry the offset. These tests pin the Python side
    of that path: a sliced `RecordBatch` must (a) carry the window offset
    on every column and (b) survive the Arrow C Data Interface round-trip
    with exactly the windowed values — which is what `ingest_via_arrow(...,
    slice_window=...)` relies on to feed offset arrays to the encoder."""

    def _batch(self, n: int):
        rnd = afc.Rng(0x5117_ED00)
        kinds = [
            ("c_int", afc.KIND_REGISTRY["int"]),
            ("c_long", afc.KIND_REGISTRY["long"]),
            ("c_bool", afc.KIND_REGISTRY["boolean"]),
            ("c_uuid", afc.KIND_REGISTRY["uuid"]),
            ("c_symbol", afc.KIND_REGISTRY["symbol"]),
        ]
        return kinds, afc.build_record_batch(kinds, rnd, n, null_mode="valid")

    def test_slice_carries_window_offset_on_every_column(self):
        _kinds, rb = self._batch(12)
        off, length = 3, 6
        sl = rb.slice(off, length)
        self.assertEqual(sl.num_rows, length)
        for i in range(sl.num_columns):
            self.assertEqual(
                sl.column(i).offset, off,
                f"column {i} ({sl.schema.field(i).name}) lost the slice offset",
            )

    def test_sliced_batch_round_trips_through_c_data_interface(self):
        import arrow_ffi
        _kinds, rb = self._batch(12)
        off, length = 3, 6
        sl = rb.slice(off, length)
        arr, sch = arrow_ffi.pyarrow_export_record_batch(sl)
        rt = arrow_ffi.pyarrow_import_record_batch(arr, sch)
        self.assertEqual(rt.num_rows, length)
        for c in range(sl.num_columns):
            name = sl.schema.field(c).name
            for r in range(length):
                self.assertEqual(
                    _norm_cell(rt.column(c)[r].as_py()),
                    _norm_cell(sl.column(c)[r].as_py()),
                    f"FFI round-trip mismatch col={name} row={r}",
                )

    def test_window_differs_from_unsliced_prefix(self):
        # Guards the test itself: the window must not coincide with the
        # offset-0 prefix, otherwise an offset-ignoring bug would be
        # invisible.
        _kinds, rb = self._batch(12)
        off, length = 3, 6
        sl = rb.slice(off, length)
        prefix = rb.slice(0, length)
        differs = any(
            sl.column(c)[r].as_py() != prefix.column(c)[r].as_py()
            for c in range(sl.num_columns)
            for r in range(length)
        )
        self.assertTrue(differs, "sliced window must differ from the prefix")


class TestEdgeCorpora(unittest.TestCase):
    def test_edge_floats_contain_nan_inf_minus_zero(self):
        self.assertTrue(any(math.isnan(v) for v in afc.EDGE_FLOATS))
        self.assertTrue(any(v == float("inf") for v in afc.EDGE_FLOATS))
        self.assertTrue(any(v == float("-inf") for v in afc.EDGE_FLOATS))
        zeros = [v for v in afc.EDGE_FLOATS if v == 0.0]
        self.assertEqual(len(zeros), 2, "should include +0.0 and -0.0")

    def test_edge_ints_cover_min_max(self):
        self.assertIn(-128, afc.EDGE_INTS_I8)
        self.assertIn(127, afc.EDGE_INTS_I8)
        self.assertIn(-(1 << 63), afc.EDGE_INTS_I64)
        self.assertIn((1 << 63) - 1, afc.EDGE_INTS_I64)

    def test_edge_strings_include_empty_and_unicode(self):
        self.assertIn("", afc.EDGE_STRINGS)
        self.assertTrue(
            any(ord(c) > 0x7F for s in afc.EDGE_STRINGS for c in s),
            "expected at least one non-ASCII edge string",
        )


class _RecordingFixture:
    """Stand-in fixture that records start() calls and never launches a JVM."""

    def __init__(self, proc, raise_on_start=False):
        self._proc = proc
        self.start_calls = []
        self._raise_on_start = raise_on_start

    def start(self, **kwargs):
        self.start_calls.append(kwargs)
        if self._raise_on_start:
            raise RuntimeError("simulated restart failure")


class _FakeProc:
    """Minimal Popen stand-in: poll() reports None while alive, an exit code
    once dead."""

    def __init__(self, exit_code):
        self._exit_code = exit_code

    def poll(self):
        return self._exit_code


class _FakeArrowSelf:
    """The subset of an ArrowFuzzBase instance that _ensure_fixture_running
    reads: the fixture, a suite label, and id() for the log line."""

    SUITE_LABEL = "arrow_recovery_test"

    def __init__(self, fixture_obj):
        self._fixture = fixture_obj

    def id(self):
        return "SharedFixtureRecoveryTest.fake"


class SharedFixtureRecoveryTest(unittest.TestCase):
    """The SFA suite's shared-server recovery helpers, driven without a live
    server. Both restore the managed fixture after a bounce leaves it stopped;
    a regression in either would let the shared server stay down and fail every
    following SFA test. Integration exercises only their success path."""

    def _make_sfa(self, fixture_obj):
        # A real TestArrowIngressSfa built without setUp: _restart_if_down reads
        # only self._fixture plus the class attributes (SUITE_LABEL,
        # BOUNCE_RESTART_TIMEOUT_S), so the class lookup supplies the rest.
        sfa = aif.TestArrowIngressSfa.__new__(aif.TestArrowIngressSfa)
        sfa._fixture = fixture_obj
        return sfa

    def test_restart_if_down_skips_when_process_alive(self):
        fx = _RecordingFixture(proc=object())  # _proc is not None
        self._make_sfa(fx)._restart_if_down(probe_min_http=True)
        self.assertEqual(fx.start_calls, [],
                         "a live server must not be restarted")

    def test_restart_if_down_starts_when_process_gone(self):
        fx = _RecordingFixture(proc=None)
        self._make_sfa(fx)._restart_if_down(probe_min_http=True)
        self.assertEqual(len(fx.start_calls), 1)
        self.assertEqual(
            fx.start_calls[0],
            {"start_timeout_sec": aif.TestArrowIngressSfa.BOUNCE_RESTART_TIMEOUT_S,
             "probe_min_http": True})

    def test_restart_if_down_passes_probe_flag_through(self):
        fx = _RecordingFixture(proc=None)
        self._make_sfa(fx)._restart_if_down(probe_min_http=False)
        self.assertIs(fx.start_calls[0]["probe_min_http"], False)

    def test_restart_if_down_swallows_start_failure(self):
        # Called from a finally, it must log a failed recovery start rather
        # than raise and mask the exception already propagating.
        fx = _RecordingFixture(proc=None, raise_on_start=True)
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self._make_sfa(fx)._restart_if_down(probe_min_http=True)
        self.assertEqual(len(fx.start_calls), 1)
        self.assertIn("recovery restart failed", stderr.getvalue())

    @contextlib.contextmanager
    def _test_module_exposing_questdbfixture(self):
        # _ensure_fixture_running does `from test import QuestDbFixture`; inject
        # a stand-in `test` module carrying the real class so the isinstance
        # gate sees it without importing the heavyweight test.py.
        fake = types.ModuleType("test")
        fake.QuestDbFixture = fixture.QuestDbFixture
        with mock.patch.dict(sys.modules, {"test": fake}):
            yield

    def _make_managed_fixture(self, proc, events):
        f = fixture.QuestDbFixture.__new__(fixture.QuestDbFixture)
        f._proc = proc
        f.start = lambda: events.append("start")
        f.stop = lambda: events.append("stop")
        return f

    def test_ensure_running_ignores_non_managed_fixture(self):
        # An external fixture is not a QuestDbFixture: it has no start()/stop()
        # to call, so a no-op is the only non-crashing outcome.
        fake_self = _FakeArrowSelf(object())
        with self._test_module_exposing_questdbfixture():
            afc.ArrowFuzzBase._ensure_fixture_running(fake_self)

    def test_ensure_running_skips_when_server_alive(self):
        events = []
        fx = self._make_managed_fixture(_FakeProc(exit_code=None), events)
        fake_self = _FakeArrowSelf(fx)
        with self._test_module_exposing_questdbfixture():
            afc.ArrowFuzzBase._ensure_fixture_running(fake_self)
        self.assertEqual(events, [], "a live server must be left untouched")

    def test_ensure_running_reaps_then_restarts_dead_server(self):
        events = []
        fx = self._make_managed_fixture(_FakeProc(exit_code=0), events)
        fake_self = _FakeArrowSelf(fx)
        with contextlib.redirect_stderr(io.StringIO()), \
                self._test_module_exposing_questdbfixture():
            afc.ArrowFuzzBase._ensure_fixture_running(fake_self)
        # A process that died without stop() clearing _proc must be reaped
        # before start(), which overwrites _proc unconditionally.
        self.assertEqual(events, ["stop", "start"])

    def test_ensure_running_restarts_without_reap_when_proc_cleared(self):
        events = []
        fx = self._make_managed_fixture(None, events)  # _proc already cleared
        fake_self = _FakeArrowSelf(fx)
        with contextlib.redirect_stderr(io.StringIO()), \
                self._test_module_exposing_questdbfixture():
            afc.ArrowFuzzBase._ensure_fixture_running(fake_self)
        self.assertEqual(events, ["start"], "no process to reap: restart only")


if __name__ == "__main__":
    unittest.main()
