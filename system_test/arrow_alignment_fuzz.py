from __future__ import annotations

import os
import sys
import unittest
from typing import Dict, List, Tuple

import pyarrow as pa

import arrow_fuzz_common as afc
from arrow_fuzz_common import KIND_REGISTRY, KindSpec

_ITERATIONS = int(os.environ.get("ARROW_ALIGNMENT_FUZZ_ITERATIONS", "4"))
_ROWS_PER_ITER = int(os.environ.get("ARROW_ALIGNMENT_FUZZ_ROWS", "16"))

# Each program forces a different pad-byte sum before the target
# column, exercising different residues mod each primitive width
# (1/2/4/8/16/32) on the wire.
_PAD_PROGRAM: List[List[str]] = [
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

_TARGET_ROTATION = ["long", "double", "uuid", "long256", "timestamp"]


def _exercise_compute_kernels(rb: pa.RecordBatch, kinds: List[Tuple[str, KindSpec]]) -> None:
    import pyarrow.compute as pc
    for col_idx, (_, spec) in enumerate(kinds):
        col = rb.column(col_idx)
        name = spec.name
        if name in {"boolean"}:
            true_count = pc.sum(pc.cast(col, "int64")).as_py() or 0
            assert 0 <= int(true_count) <= rb.num_rows
        elif name in {"byte", "short", "int", "long", "char", "ipv4"}:
            total = pc.sum(pc.cast(col, "int64")).as_py()
            min_v = pc.min(pc.cast(col, "int64")).as_py()
            max_v = pc.max(pc.cast(col, "int64")).as_py()
            assert total is not None
            assert min_v is not None and max_v is not None
            assert min_v <= max_v
        elif name in {"float", "double"}:
            total = pc.sum(col).as_py()
            assert total is not None
        elif name in {"uuid", "long256"}:
            assert col.type.byte_width in (16, 32)
        elif name in {"timestamp", "timestamp_ns", "date"}:
            min_v = pc.min(col).as_py()
            max_v = pc.max(col).as_py()
            assert min_v is not None and max_v is not None


def _populate_via_ilp(sender, table: str, kinds, values_per_col, ts_base_us: int) -> None:
    n = len(next(iter(values_per_col.values())))
    ordered = sorted(kinds, key=lambda kv: 0 if kv[1].name == "symbol" else 1)
    for r in range(n):
        sender.table(table)
        for col_name, spec in ordered:
            v = values_per_col[col_name][r]
            if v is None:
                continue
            spec.ilp_set(sender, col_name, v)
        sender.at_micros(ts_base_us + r)
    sender.flush()


def _read_back(fixture, table: str, kinds) -> pa.RecordBatch:
    cols_sql = ", ".join(f'"{c}"' for c, _ in kinds)
    return afc.read_back_arrow_concat(
        fixture, f"select {cols_sql} from '{table}' order by ts"
    )


class TestArrowAlignment(afc.ArrowFuzzBase):
    SUITE_LABEL = "arrow_alignment_fuzz"

    def _run_program(self, iter_idx: int, kind_order: List[str]):
        table = self.fresh_table(f"arrow_aln_{iter_idx}")
        kinds = [(f"c{i}_{n}", KIND_REGISTRY[n]) for i, n in enumerate(kind_order)]
        afc.create_table_from_kinds(self._fixture, table, kinds)
        n = _ROWS_PER_ITER
        rnd = self._master_rng
        values_per_col: Dict[str, list] = {}
        for col_name, spec in kinds:
            mask = afc.all_valid_mask(n)
            values_per_col[col_name] = spec.generate_values(rnd, n, mask, edge=False)
        with afc.existing_sender(self._fixture) as sender:
            _populate_via_ilp(sender, table, kinds, values_per_col,
                              ts_base_us=1_700_000_000_000_000 + iter_idx * 1_000_000)
        afc.wait_for_rows(self._fixture, table, n)
        rb = _read_back(self._fixture, table, kinds)
        self.assertEqual(rb.num_rows, n, self.label())
        return rb, kinds

    def test_misalignment_schedule_imports_and_computes(self):
        for it in range(_ITERATIONS):
            for prog_idx, pad in enumerate(_PAD_PROGRAM):
                with self.subTest(iter=it, prog_idx=prog_idx):
                    target = _TARGET_ROTATION[prog_idx % len(_TARGET_ROTATION)]
                    kind_order = pad + [target]
                    rb, kinds = self._run_program(prog_idx + it * len(_PAD_PROGRAM),
                                                  kind_order)
                    _exercise_compute_kernels(rb, kinds)


def register(loop_registry):
    loop_registry.append(TestArrowAlignment)


if __name__ == "__main__":
    print(
        "Note: arrow_alignment_fuzz tests require a live QuestDB fixture. "
        "Run via `python test.py run --existing HOST:ILP:HTTP TestArrowAlignment`.",
        file=sys.stderr,
    )
    unittest.main()
