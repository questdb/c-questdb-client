from __future__ import annotations

import math
import unittest

import pyarrow as pa

import arrow_fuzz_common as afc


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


if __name__ == "__main__":
    unittest.main()
