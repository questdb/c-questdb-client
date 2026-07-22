import contextlib
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import aggregate


def path_summary(phase="floor", rps=2_000_000.0):
    return {
        "phase": phase,
        "rows_per_s_median": rps,
        "median_s": 5.0,
        "mib_per_s": None,
    }


def report(path, *, direction="ingress", client="rust-polars",
           schema="s1-narrow", rows=10_000_000, senders=1,
           run_mode="full", phase="floor", include_senders=True,
           row_check=True):
    value = {
        "direction": direction,
        "client": client,
        "schema": schema,
        "rows": rows,
        "run_mode": run_mode,
        "paths": {path: path_summary(phase)},
        "machine": {"platform": "linux", "arch": "aarch64"},
        "commits": {"c_questdb_client": "abc"},
    }
    if include_senders:
        value["senders"] = senders
    if row_check is not None:
        value["row_count_check"] = {
            "expected": rows,
            "actual": rows if row_check else rows - 1,
            "ok": row_check,
            "inflated": False,
        }
    return value


class AggregatorTest(unittest.TestCase):
    def test_all_known_paths_have_expected_roles(self):
        self.assertEqual({
            "columnar-populate": ("ingress", "columnar CPU floor"),
            "encode-floor": ("ingress", "columnar CPU floor"),
            "chunk-build": ("ingress", "C chunk-build floor"),
            "row-build": ("ingress", "row-build floor"),
            "real-client": ("ingress", "columnar e2e"),
            "flush-polars-dataframe": ("ingress", "columnar e2e"),
            "flush-chunks": ("ingress", "columnar e2e"),
            "row-flush": ("ingress", "row e2e"),
            "decode-only": ("egress", "decode floor"),
            "materialize": ("egress", "materialize"),
            "to-arrow": ("egress", "-> Arrow"),
            "to-polars": ("egress", "-> polars"),
            "fetch-all-polars": ("egress", "-> polars"),
            "iter-polars": ("egress", "-> polars (lazy/iter)"),
            "iter-pandas": ("egress", "-> pandas (lazy/iter)"),
            "to-pandas": ("egress", "-> pandas (numpy)"),
            "to-pandas-arrow": ("egress", "-> pandas (Arrow)"),
            "to-pandas-nullable": ("egress", "-> pandas (nullable)"),
            "arrow-c-stream": ("egress", "Arrow C-stream"),
        }, aggregate.ROLE_OF_PATH)

    def test_partition_uses_all_five_dimensions(self):
        values = [
            report("flush-polars-dataframe", phase="e2e"),
            report("flush-polars-dataframe", phase="e2e", schema="s2-wide"),
            report("flush-polars-dataframe", phase="e2e", rows=9_000_000),
            report("flush-polars-dataframe", phase="e2e", senders=2),
            report("flush-polars-dataframe", phase="e2e", run_mode="e2e"),
        ]
        for index, value in enumerate(values):
            value["_source"] = f"r{index}.json"
        groups = aggregate.collect(values)
        self.assertEqual(5, len(groups))
        self.assertEqual(
            {("ingress", "s1-narrow", 10_000_000, 1, "full"),
             ("ingress", "s2-wide", 10_000_000, 1, "full"),
             ("ingress", "s1-narrow", 9_000_000, 1, "full"),
             ("ingress", "s1-narrow", 10_000_000, 2, "full"),
             ("ingress", "s1-narrow", 10_000_000, 1, "e2e")},
            set(groups),
        )

    def test_sender_defaults_and_egress_effective_sender(self):
        ingress = report("encode-floor", include_senders=False, row_check=None)
        egress = report("decode-only", direction="egress", senders=8,
                        row_check=None)
        self.assertEqual(1, aggregate.comparison_key(ingress).senders)
        self.assertEqual(1, aggregate.comparison_key(egress).senders)

    def test_duplicate_cell_rejected_but_nonoverlapping_roles_merge(self):
        floor = report("encode-floor", row_check=None)
        floor["_source"] = "floor.json"
        duplicate = report("columnar-populate", client="rust-polars",
                           row_check=None)
        duplicate["_source"] = "duplicate.json"
        with self.assertRaisesRegex(aggregate.ReportError, "duplicate"):
            aggregate.collect([floor, duplicate])
        e2e = report("flush-polars-dataframe", phase="e2e")
        e2e["_source"] = "e2e.json"
        groups = aggregate.collect([floor, e2e])
        slot = next(iter(groups.values()))
        self.assertEqual(
            {"columnar CPU floor", "columnar e2e"}, set(slot["grid"])
        )

    def test_ingress_e2e_requires_boolean_true_row_check(self):
        for check in (None, False, 1):
            value = report("flush-polars-dataframe", phase="e2e",
                           row_check=check)
            if check == 1:
                value["row_count_check"]["ok"] = 1
            value["_source"] = f"check-{check}.json"
            with self.subTest(check=check), self.assertRaises(
                aggregate.ReportError
            ):
                aggregate.collect([value])
        valid = report("flush-polars-dataframe", phase="e2e", row_check=True)
        valid["_source"] = "valid.json"
        self.assertEqual(1, len(aggregate.collect([valid])))
        floor = report("encode-floor", row_check=None)
        floor["_source"] = "floor.json"
        self.assertEqual(1, len(aggregate.collect([floor])))

    def test_unknown_and_wrong_direction_paths_are_errors(self):
        unknown = report("future-path", row_check=None)
        unknown["_source"] = "unknown.json"
        with self.assertRaisesRegex(aggregate.ReportError, "unknown path"):
            aggregate.collect([unknown])
        wrong = report("decode-only", row_check=None)
        wrong["_source"] = "wrong.json"
        with self.assertRaisesRegex(aggregate.ReportError, "direction"):
            aggregate.collect([wrong])

    def test_canonical_bpr_and_override_rules(self):
        key = aggregate.GroupKey
        self.assertEqual(45.0, aggregate.bytes_per_row(
            key("ingress", "s1-narrow", 10_000_000, 1, "full")))
        self.assertEqual(37.1283602, aggregate.bytes_per_row(
            key("egress", "s1-narrow", 10_000_000, 1, "full")))
        self.assertEqual(100.335059, aggregate.bytes_per_row(
            key("ingress", "s2-wide", 10_000_000, 1, "full")))
        self.assertEqual(92.4641382, aggregate.bytes_per_row(
            key("egress", "s2-wide", 10_000_000, 1, "full")))
        custom = key("ingress", "s1-narrow", 1_000, 1, "full")
        with self.assertRaisesRegex(aggregate.ReportError, "--ingress-bpr"):
            aggregate.bytes_per_row(custom)
        self.assertEqual(12.5, aggregate.bytes_per_row(
            custom, ingress_override=12.5))

    def test_markdown_and_text_render_distinct_groups(self):
        a = report("encode-floor", row_check=None)
        b = report("encode-floor", schema="s2-wide", row_check=None)
        a["_source"], b["_source"] = "a.json", "b.json"
        groups = aggregate.collect([a, b])
        markdown = aggregate.render(groups, "md", None, None, raw=False)
        text = aggregate.render(groups, "text", None, None, raw=False)
        for output in (markdown, text):
            self.assertIn("s1-narrow", output)
            self.assertIn("s2-wide", output)
            self.assertIn("senders=1", output)
            self.assertIn("run_mode=full", output)

    def test_glob_cli_and_cli_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "a.json").write_text(json.dumps(
                report("encode-floor", row_check=None)))
            (root / "b.json").write_text(json.dumps(
                report("encode-floor", schema="s2-wide", row_check=None)))
            ok = subprocess.run(
                [sys.executable, str(HERE / "aggregate.py"),
                 "--glob", str(root / "*.json"), "--format", "text"],
                text=True, capture_output=True, check=False)
            self.assertEqual(0, ok.returncode, ok.stderr)
            self.assertIn("s1-narrow", ok.stdout)
            self.assertIn("s2-wide", ok.stdout)
            malformed = root / "bad.json"
            malformed.write_text("{")
            bad = subprocess.run(
                [sys.executable, str(HERE / "aggregate.py"), str(malformed)],
                text=True, capture_output=True, check=False)
            self.assertEqual(2, bad.returncode)
            self.assertIn("bad.json", bad.stderr)

    def test_raw_output_keeps_group_identity(self):
        a = report("encode-floor", row_check=None)
        b = report("encode-floor", senders=2, row_check=None)
        a["_source"], b["_source"] = "a.json", "b.json"
        output = aggregate.render(
            aggregate.collect([a, b]), "md", None, None, raw=True
        )
        self.assertIn("senders=1", output)
        self.assertIn("senders=2", output)
        self.assertEqual(2, output.count('"columnar CPU floor"'))

    def test_remaining_cli_error_contracts_and_override(self):
        def invoke(*args):
            return subprocess.run(
                [sys.executable, str(HERE / "aggregate.py"), *map(str, args)],
                text=True, capture_output=True, check=False,
            )

        self.assertEqual(2, invoke().returncode)
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.assertEqual(
                2, invoke("--glob", root / "missing-*.json").returncode
            )

            valid = root / "valid.json"
            valid.write_text(json.dumps(report("encode-floor", row_check=None)))
            duplicate = invoke(valid, "--glob", root / "*.json")
            self.assertEqual(2, duplicate.returncode)
            self.assertIn("duplicate", duplicate.stderr)

            unknown = root / "unknown.json"
            unknown.write_text(json.dumps(report("future-path", row_check=None)))
            unknown_result = invoke(unknown)
            self.assertEqual(2, unknown_result.returncode)
            self.assertIn("unknown path", unknown_result.stderr)

            custom = root / "custom.json"
            custom.write_text(json.dumps(
                report("encode-floor", rows=1_000, row_check=None)))
            no_override = invoke(custom)
            self.assertEqual(2, no_override.returncode)
            self.assertIn("--ingress-bpr", no_override.stderr)
            with_override = invoke(custom, "--ingress-bpr", "12.5")
            self.assertEqual(0, with_override.returncode, with_override.stderr)

    def test_partition_separates_ingress_and_egress(self):
        ingress = report("encode-floor", row_check=None)
        egress = report("decode-only", direction="egress", row_check=None)
        ingress["_source"] = "ingress.json"
        egress["_source"] = "egress.json"
        groups = aggregate.collect([ingress, egress])
        self.assertEqual({
            aggregate.GroupKey(
                "ingress", "s1-narrow", 10_000_000, 1, "full"
            ),
            aggregate.GroupKey(
                "egress", "s1-narrow", 10_000_000, 1, "full"
            ),
        }, set(groups))

    def test_strict_report_validation_contract(self):
        key_cases = (
            ("direction", "sideways", "direction"),
            ("direction", None, "direction"),
            ("schema", "", "schema"),
            ("schema", 1, "schema"),
            ("schema", None, "schema"),
            ("run_mode", "", "run_mode"),
            ("run_mode", 1, "run_mode"),
            ("run_mode", None, "run_mode"),
            ("rows", True, "rows"),
            ("rows", 0, "rows"),
            ("rows", 1.5, "rows"),
            ("senders", False, "senders"),
            ("senders", 0, "senders"),
            ("senders", 1.5, "senders"),
        )
        for field, invalid, message in key_cases:
            value = report("encode-floor", row_check=None)
            value[field] = invalid
            value["_source"] = "invalid-key.json"
            with self.subTest(field=field, invalid=invalid), \
                    self.assertRaisesRegex(
                        aggregate.ReportError,
                        rf"invalid-key\.json.*{message}",
                    ):
                aggregate.comparison_key(value)

        collect_cases = []
        for field, invalid, message in (
            ("client", "", "client"),
            ("client", 1, "client"),
            ("paths", {}, "paths"),
            ("paths", [], "paths"),
            ("machine", None, "machine"),
            ("commits", None, "commits"),
        ):
            value = report("encode-floor", row_check=None)
            value[field] = invalid
            collect_cases.append((value, message))
        invalid_summary = report("encode-floor", row_check=None)
        invalid_summary["paths"]["encode-floor"] = 1
        collect_cases.append((invalid_summary, "object"))
        invalid_floor_check = report("encode-floor", row_check=False)
        collect_cases.append((invalid_floor_check, "row_count_check"))
        malformed_floor_check = report("encode-floor", row_check=None)
        malformed_floor_check["row_count_check"] = 1
        collect_cases.append((malformed_floor_check, "row_count_check"))
        missing_client = report("encode-floor", row_check=None)
        missing_client.pop("client")
        collect_cases.append((missing_client, "client"))
        missing_paths = report("encode-floor", row_check=None)
        missing_paths.pop("paths")
        collect_cases.append((missing_paths, "paths"))

        for index, (value, message) in enumerate(collect_cases):
            value["_source"] = f"invalid-report-{index}.json"
            with self.subTest(index=index), self.assertRaisesRegex(
                aggregate.ReportError,
                rf"invalid-report-{index}\.json.*{message}",
            ):
                aggregate.collect([value])

        egress = report(
            "decode-only", direction="egress", senders=False, row_check=False
        )
        egress["row_count_check"] = 1
        egress["_source"] = "egress.json"
        key = next(iter(aggregate.collect([egress])))
        self.assertEqual(1, key.senders)

        first = report("encode-floor", row_check=None)
        second = report("columnar-populate", row_check=None)
        first["_source"] = "first.json"
        second["_source"] = "second.json"
        with self.assertRaises(aggregate.ReportError) as raised:
            aggregate.collect([first, second])
        self.assertIn("duplicate", str(raised.exception))
        self.assertIn("first.json", str(raised.exception))
        self.assertIn("second.json", str(raised.exception))

    def test_raw_output_uses_exact_group_keys(self):
        first = report("encode-floor", row_check=None)
        second = report("encode-floor", senders=2, row_check=None)
        first["paths"]["encode-floor"]["rows_per_s_median"] = 1_000_000.0
        second["paths"]["encode-floor"]["rows_per_s_median"] = 3_000_000.0
        first["_source"] = "first.json"
        second["_source"] = "second.json"
        output = aggregate.render(
            aggregate.collect([first, second]), "md", raw=True
        )
        raw_text = output.split("```json\n", 1)[1].split("\n```", 1)[0]
        raw = json.loads(raw_text)
        self.assertEqual({
            "direction=ingress|schema=s1-narrow|rows=10000000|"
            "senders=1|run_mode=full",
            "direction=ingress|schema=s1-narrow|rows=10000000|"
            "senders=2|run_mode=full",
        }, set(raw))
        rates = [
            group["columnar CPU floor"]["rust-polars"]["rows_per_s"]
            for group in raw.values()
        ]
        self.assertEqual([1_000_000.0, 3_000_000.0], rates)

    def test_render_tables_are_complete_and_deterministic(self):
        wide = report("encode-floor", schema="s2-wide", row_check=None)
        narrow = report("encode-floor", row_check=None)
        wide["_source"] = "wide.json"
        narrow["_source"] = "narrow.json"
        groups = aggregate.collect([wide, narrow])
        markdown = aggregate.render(groups, "md")
        text = aggregate.render(groups, "text")

        narrow_title = (
            "Ingress — s1-narrow, 10,000,000 rows, senders=1, "
            "run_mode=full (GiB/s @ 45 on-wire B/row)"
        )
        wide_title = (
            "Ingress — s2-wide, 10,000,000 rows, senders=1, "
            "run_mode=full (GiB/s @ 100.335 on-wire B/row)"
        )
        for output in (markdown, text):
            self.assertIn(narrow_title, output)
            self.assertIn(wide_title, output)
            self.assertLess(output.index(narrow_title), output.index(wide_title))
            self.assertIn("2.0 M/s · 0.08 GiB/s", output)
            self.assertIn("2.0 M/s · 0.19 GiB/s", output)
        self.assertEqual(2, markdown.count("| role | rust-polars |"))
        self.assertEqual(2, markdown.count("### Ingress"))
        self.assertNotIn("| role |", text)

    def test_group_order_uses_all_five_dimensions(self):
        specs = (
            ("egress", "s0", 1_000, 99, "alpha"),
            ("ingress", "s2-wide", 1_000, 1, "alpha"),
            ("ingress", "s1-narrow", 2_000, 1, "alpha"),
            ("ingress", "s1-narrow", 1_000, 2, "alpha"),
            ("ingress", "s1-narrow", 1_000, 1, "zeta"),
            ("ingress", "s1-narrow", 1_000, 1, "alpha"),
        )
        values = []
        for index, (direction, schema, rows, senders, run_mode) in enumerate(
            specs
        ):
            path = "decode-only" if direction == "egress" else "encode-floor"
            value = report(
                path, direction=direction, schema=schema, rows=rows,
                senders=senders, run_mode=run_mode, row_check=None,
            )
            value["_source"] = f"order-{index}.json"
            values.append(value)

        output = aggregate.render(
            aggregate.collect(values), "md", ingress_override=1.0,
            egress_override=1.0, raw=True,
        )
        headings = [
            line[4:]
            for line in output.splitlines()
            if line.startswith("### ")
        ]
        self.assertEqual([
            "Ingress — s1-narrow, 1,000 rows, senders=1, run_mode=alpha "
            "(GiB/s @ 1 on-wire B/row)",
            "Ingress — s1-narrow, 1,000 rows, senders=1, run_mode=zeta "
            "(GiB/s @ 1 on-wire B/row)",
            "Ingress — s1-narrow, 1,000 rows, senders=2, run_mode=alpha "
            "(GiB/s @ 1 on-wire B/row)",
            "Ingress — s1-narrow, 2,000 rows, senders=1, run_mode=alpha "
            "(GiB/s @ 1 on-wire B/row)",
            "Ingress — s2-wide, 1,000 rows, senders=1, run_mode=alpha "
            "(GiB/s @ 1 on-wire B/row)",
            "Egress — s0, 1,000 rows, senders=1, run_mode=alpha "
            "(GiB/s @ 1 on-wire B/row)",
        ], headings)

        raw_text = output.split("```json\n", 1)[1].split("\n```", 1)[0]
        self.assertEqual([
            "direction=ingress|schema=s1-narrow|rows=1000|senders=1|"
            "run_mode=alpha",
            "direction=ingress|schema=s1-narrow|rows=1000|senders=1|"
            "run_mode=zeta",
            "direction=ingress|schema=s1-narrow|rows=1000|senders=2|"
            "run_mode=alpha",
            "direction=ingress|schema=s1-narrow|rows=2000|senders=1|"
            "run_mode=alpha",
            "direction=ingress|schema=s2-wide|rows=1000|senders=1|"
            "run_mode=alpha",
            "direction=egress|schema=s0|rows=1000|senders=1|run_mode=alpha",
        ], list(json.loads(raw_text)))

    def test_main_argv_repeatable_glob_and_raw(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "narrow.json").write_text(json.dumps(
                report("encode-floor", row_check=None)))
            (root / "wide.json").write_text(json.dumps(
                report("encode-floor", schema="s2-wide", row_check=None)))
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                aggregate.main([
                    "--glob", str(root / "narrow*.json"),
                    "--glob", str(root / "wide*.json"),
                    "--format", "text",
                    "--raw",
                ])
            output = stdout.getvalue()
            self.assertIn("s1-narrow", output)
            self.assertIn("s2-wide", output)
            self.assertIn(
                "direction=ingress|schema=s1-narrow|rows=10000000|"
                "senders=1|run_mode=full",
                output,
            )

    def test_additional_cli_errors_and_egress_override(self):
        def invoke(*args):
            return subprocess.run(
                [sys.executable, str(HERE / "aggregate.py"), *map(str, args)],
                text=True, capture_output=True, check=False,
            )

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            custom = root / "egress.json"
            custom.write_text(json.dumps(report(
                "decode-only", direction="egress", rows=1_000,
                row_check=False,
            )))
            no_override = invoke(custom)
            self.assertEqual(2, no_override.returncode)
            self.assertIn("--egress-bpr", no_override.stderr)
            override = invoke(custom, "--egress-bpr", "12.5", "--raw")
            self.assertEqual(0, override.returncode, override.stderr)
            self.assertIn("direction=egress", override.stdout)

            canonical = root / "canonical.json"
            canonical.write_text(json.dumps(
                report("encode-floor", row_check=None)))
            for invalid in ("0", "-1", "nan", "inf"):
                result = invoke(canonical, "--ingress-bpr", invalid)
                with self.subTest(invalid=invalid):
                    self.assertEqual(2, result.returncode)
                    self.assertIn("must be positive", result.stderr)

            non_object = root / "non-object.json"
            non_object.write_text("[]")
            result = invoke(non_object)
            self.assertEqual(2, result.returncode)
            self.assertIn("top-level JSON must be an object", result.stderr)

    def test_environment_preserves_all_provenance(self):
        floor = report("encode-floor", row_check=None)
        e2e = report("flush-polars-dataframe", phase="e2e")
        floor["_source"] = "floor.json"
        e2e["_source"] = "e2e.json"
        floor["commits"]["c_questdb_client"] = "floor-commit"
        e2e["machine"] = {"platform": "macos", "arch": "aarch64"}
        e2e["commits"]["c_questdb_client"] = "e2e-commit"
        groups = aggregate.collect([floor, e2e])
        output = aggregate.render(groups, "text")
        self.assertIn("linux/arm64", output)
        self.assertIn("macos/arm64", output)
        self.assertIn("floor-commit", output)
        self.assertIn("e2e-commit", output)
        self.assertIn("boxes differ across inputs", output)
        slot = next(iter(groups.values()))
        self.assertEqual(
            {"floor.json", "e2e.json"},
            {entry["source"] for entry in slot["env"]},
        )

    def test_documentation_and_help_name_the_aggregator(self):
        self.assertIn("QWP benchmark aggregator", aggregate.__doc__)
        self.assertIn("tools/qwp_bench/aggregate.py", aggregate.__doc__)
        self.assertIn("doc/BENCHMARKS.md", aggregate.__doc__)
        for forbidden in ("Step 4", "§", "_PLAN", "historical"):
            self.assertNotIn(forbidden, aggregate.__doc__)

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), self.assertRaises(
            SystemExit
        ) as raised:
            aggregate.main(["--help"])
        self.assertEqual(0, raised.exception.code)
        help_text = stdout.getvalue()
        self.assertIn("QWP benchmark aggregator", help_text)
        self.assertIn("tools/qwp_bench/aggregate.py", help_text)
        self.assertIn("doc/BENCHMARKS.md", help_text)
        for forbidden in ("Step 4", "§", "_PLAN", "historical"):
            self.assertNotIn(forbidden, help_text)

    def test_raw_group_identity_is_collision_safe(self):
        first = report(
            "encode-floor", schema="x", rows=1, senders=1,
            run_mode="z|rows=2|senders=2|run_mode=y", row_check=None,
        )
        second = report(
            "encode-floor", schema="x|rows=1|senders=1|run_mode=z",
            rows=2, senders=2, run_mode="y", row_check=None,
        )
        first["paths"]["encode-floor"]["rows_per_s_median"] = 1_000_000.0
        second["paths"]["encode-floor"]["rows_per_s_median"] = 3_000_000.0
        first["_source"] = "collision-first.json"
        second["_source"] = "collision-second.json"

        groups = aggregate.collect([first, second])
        raw_text = aggregate.render_raw(groups, "text").split("\n", 1)[1]
        raw = json.loads(raw_text)
        self.assertEqual(2, len(groups))
        self.assertEqual({
            "direction=ingress|schema=x|rows=1|senders=1|"
            "run_mode=z%7Crows%3D2%7Csenders%3D2%7Crun_mode%3Dy",
            "direction=ingress|schema=x%7Crows%3D1%7Csenders%3D1%7C"
            "run_mode%3Dz|rows=2|senders=2|run_mode=y",
        }, set(raw))
        self.assertEqual(
            [1_000_000.0, 3_000_000.0],
            sorted(
                group["columnar CPU floor"]["rust-polars"]["rows_per_s"]
                for group in raw.values()
            ),
        )

        delimiter = report(
            "encode-floor", schema="x|y", rows=3, row_check=None
        )
        percent = report(
            "encode-floor", schema="x%7Cy", rows=3, row_check=None
        )
        delimiter["_source"] = "delimiter.json"
        percent["_source"] = "percent.json"
        percent_raw = json.loads(
            aggregate.render_raw(
                aggregate.collect([delimiter, percent]), "text"
            ).split("\n", 1)[1]
        )
        self.assertEqual({
            "direction=ingress|schema=x%7Cy|rows=3|senders=1|run_mode=full",
            "direction=ingress|schema=x%257Cy|rows=3|senders=1|run_mode=full",
        }, set(percent_raw))

    def test_ingress_e2e_role_requires_row_check_despite_phase(self):
        e2e_paths = (
            "real-client", "flush-polars-dataframe", "flush-chunks",
            "row-flush",
        )
        for path in e2e_paths:
            for phase in ("floor", False, None):
                value = report(path, phase=phase, row_check=None)
                if phase is None:
                    value["paths"][path].pop("phase")
                value["_source"] = f"{path}-{phase}.json"
                with self.subTest(path=path, phase=phase), \
                        self.assertRaisesRegex(
                            aggregate.ReportError,
                            rf"{path}-{phase}\.json.*e2e.*row_count_check",
                        ):
                    aggregate.collect([value])

        mislabeled_floor = report(
            "encode-floor", phase="e2e", row_check=None
        )
        mislabeled_floor["_source"] = "mislabeled-floor.json"
        self.assertEqual(1, len(aggregate.collect([mislabeled_floor])))

    def test_numeric_summaries_are_strict_and_cli_errors_are_controlled(self):
        invalid_metrics = (
            ("rows_per_s_median", True),
            ("rows_per_s_median", -1),
            ("rows_per_s_median", 0),
            ("rows_per_s_median", None),
            ("rows_per_s_median", "fast"),
            ("median_s", float("nan")),
            ("median_s", -1),
            ("median_s", 0),
            ("median_s", None),
            ("mib_per_s", float("inf")),
            ("mib_per_s", -1),
        )
        for index, (metric, invalid) in enumerate(invalid_metrics):
            value = report("encode-floor", row_check=None)
            value["paths"]["encode-floor"][metric] = invalid
            value["_source"] = f"invalid-{index}.json"
            with self.subTest(metric=metric, invalid=invalid), \
                    self.assertRaisesRegex(
                        aggregate.ReportError,
                        rf"invalid-{index}\.json.*{metric}",
                ):
                aggregate.collect([value])

        for metric in ("rows_per_s_median", "median_s", "mib_per_s"):
            value = report("encode-floor", row_check=None)
            value["paths"]["encode-floor"].pop(metric)
            value["_source"] = f"missing-{metric}.json"
            with self.subTest(missing=metric), self.assertRaisesRegex(
                aggregate.ReportError,
                rf"missing-{metric}\.json.*{metric}",
            ):
                aggregate.collect([value])

        null_mib = report("encode-floor", row_check=None)
        null_mib["_source"] = "null-mib.json"
        self.assertEqual(1, len(aggregate.collect([null_mib])))
        zero_mib = report("encode-floor", row_check=None)
        zero_mib["paths"]["encode-floor"]["mib_per_s"] = 0
        zero_mib["_source"] = "zero-mib.json"
        self.assertEqual(1, len(aggregate.collect([zero_mib])))

        def invoke(path):
            return subprocess.run(
                [sys.executable, str(HERE / "aggregate.py"), str(path)],
                text=True, capture_output=True, check=False,
            )

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            values = (
                ("nan", "rows_per_s_median", float("nan")),
                ("infinity", "rows_per_s_median", float("inf")),
                ("boolean", "rows_per_s_median", True),
                ("oversized", "rows_per_s_median", 10 ** 400),
                ("raw-median", "median_s", "slow"),
                ("raw-mib", "mib_per_s", -1),
            )
            for name, metric, invalid in values:
                value = report("encode-floor", row_check=None)
                value["paths"]["encode-floor"][metric] = invalid
                path = root / f"{name}.json"
                path.write_text(json.dumps(value))
                result = invoke(path)
                with self.subTest(cli=name):
                    self.assertEqual(2, result.returncode, result.stderr)
                    self.assertIn(path.name, result.stderr)
                    self.assertNotIn("Traceback", result.stderr)
                    self.assertEqual("", result.stdout)
                    if name not in ("nan", "infinity"):
                        self.assertIn("encode-floor", result.stderr)
                        self.assertIn(metric, result.stderr)
                    else:
                        self.assertIn(
                            "invalid JSON numeric constant", result.stderr
                        )

            exponent_value = report("encode-floor", row_check=None)
            exponent_text = json.dumps(exponent_value).replace(
                '"rows_per_s_median": 2000000.0',
                '"rows_per_s_median": 1e400',
                1,
            )
            exponent_path = root / "exponent.json"
            exponent_path.write_text(exponent_text)
            exponent_result = invoke(exponent_path)
            self.assertEqual(2, exponent_result.returncode)
            self.assertIn(exponent_path.name, exponent_result.stderr)
            self.assertIn("encode-floor", exponent_result.stderr)
            self.assertIn("rows_per_s_median", exponent_result.stderr)
            self.assertNotIn("Traceback", exponent_result.stderr)
            self.assertEqual("", exponent_result.stdout)

        defensive = report("encode-floor", row_check=None)
        defensive["_source"] = "defensive.json"
        groups = aggregate.collect([defensive])
        slot = next(iter(groups.values()))
        slot["grid"]["columnar CPU floor"]["rust-polars"][
            "rows_per_s_median"
        ] = float("nan")
        with self.assertRaises(aggregate.ReportError):
            aggregate.render_raw(groups, "text")

    def test_nested_raw_output_is_deterministic(self):
        values = []
        for client in ("rust-polars", "py-pandas"):
            e2e = report(
                "flush-polars-dataframe", client=client, phase="e2e"
            )
            floor = report("encode-floor", client=client, row_check=None)
            e2e["_source"] = f"{client}-e2e.json"
            floor["_source"] = f"{client}-floor.json"
            values.extend((e2e, floor))

        forward = aggregate.render_raw(aggregate.collect(values), "text")
        reverse = aggregate.render_raw(
            aggregate.collect(list(reversed(values))), "text"
        )
        self.assertEqual(forward, reverse)

        raw = json.loads(forward.split("\n", 1)[1])
        group = next(iter(raw.values()))
        self.assertEqual(
            ["columnar CPU floor", "columnar e2e"], list(group)
        )
        for clients in group.values():
            self.assertEqual(["py-pandas", "rust-polars"], list(clients))


if __name__ == "__main__":
    unittest.main()
