#!/usr/bin/env python3
"""The QWP benchmark aggregator combines JSON reports into comparison tables.

Reports are partitioned by direction, schema, row count, sender count, and run
mode so results from different workloads never overwrite each other. See
``doc/BENCHMARKS.md`` for the report contract and benchmark methodology.

Usage:
    tools/qwp_bench/aggregate.py FILE [FILE ...] [--glob 'dir/*.json']
                                 [--format md|text] [--ingress-bpr BPR]
                                 [--egress-bpr BPR] [--raw]
"""

import argparse
import glob as globmod
import json
import math
from typing import NamedTuple

GIB = 1024.0 ** 3


class ReportError(ValueError):
    pass


class GroupKey(NamedTuple):
    direction: str
    schema: str
    rows: int
    senders: int
    run_mode: str


CANONICAL_BPR = {
    ("s1-narrow", 10_000_000): {"ingress": 45.0, "egress": 37.1283602},
    ("s2-wide", 10_000_000): {"ingress": 100.335059, "egress": 92.4641382},
}

# Path name -> (direction, canonical role). Every emitter's path names live
# here; add a row when a new path is introduced.
ROLE_OF_PATH = {
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
}

# Render order of roles within each direction.
ROLE_ORDER = {
    "ingress": ["columnar CPU floor", "C chunk-build floor",
                "row-build floor", "columnar e2e", "row e2e"],
    "egress": ["decode floor", "materialize", "-> Arrow", "-> polars",
               "-> polars (lazy/iter)", "-> pandas (numpy)",
               "-> pandas (Arrow)", "-> pandas (nullable)",
               "-> pandas (lazy/iter)", "Arrow C-stream"],
}

INGRESS_E2E_ROLES = frozenset({"columnar e2e", "row e2e"})

# Stable client column order; unknown clients follow in lexical order.
CLIENT_ORDER = ["py-pandas", "rust-polars", "java", "go"]


def reject_json_constant(value):
    raise ValueError(f"invalid JSON numeric constant {value}")


def reject_surrogate_code_points(source, field, value):
    if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise ReportError(
            f"{source}: {field} must not contain surrogate code points"
        )


def rendered_text(value, fmt):
    """Keep report-provided text on one output line and Markdown-safe."""
    result = []
    replacing_control = False
    for char in value:
        code_point = ord(char)
        is_control = (
            code_point < 0x20
            or 0x7F <= code_point <= 0x9F
            or code_point in (0x2028, 0x2029)
        )
        if is_control:
            if not replacing_control:
                result.append(" ")
        else:
            result.append(char)
        replacing_control = is_control
    text = "".join(result)
    if fmt == "md":
        text = text.replace("\\", "\\\\").replace("|", "\\|")
    return text


def load_reports(paths):
    reports = []
    for path in paths:
        try:
            with open(path, encoding="utf-8") as handle:
                value = json.load(
                    handle,
                    parse_constant=reject_json_constant,
                    object_pairs_hook=reject_duplicate_json_members,
                )
        except (OSError, ValueError) as exc:
            raise ReportError(f"cannot load {path}: {exc}") from exc
        if not isinstance(value, dict):
            raise ReportError(f"{path}: top-level JSON must be an object")
        value["_source"] = path
        reports.append(value)
    return reports


def comparison_key(report):
    source = report.get("_source", "<input>")
    direction = report.get("direction")
    if direction not in ("ingress", "egress"):
        raise ReportError(f"{source}: direction must be ingress or egress")
    schema = report.get("schema")
    run_mode = report.get("run_mode")
    rows = report.get("rows")
    if not isinstance(schema, str) or not schema:
        raise ReportError(f"{source}: schema must be a non-empty string")
    if not isinstance(run_mode, str) or not run_mode:
        raise ReportError(f"{source}: run_mode must be a non-empty string")
    reject_surrogate_code_points(source, "schema", schema)
    reject_surrogate_code_points(source, "run_mode", run_mode)
    if isinstance(rows, bool) or not isinstance(rows, int) or rows <= 0:
        raise ReportError(f"{source}: rows must be a positive integer")
    senders = 1 if direction == "egress" else report.get("senders", 1)
    if isinstance(senders, bool) or not isinstance(senders, int) or senders <= 0:
        raise ReportError(f"{source}: senders must be a positive integer")
    return GroupKey(direction, schema, rows, senders, run_mode)


def validate_row_count(report, paths):
    if report["direction"] != "ingress":
        return
    source = report.get("_source", "<input>")
    has_e2e = any(
        ROLE_OF_PATH[name][1] in INGRESS_E2E_ROLES for name in paths
    )
    if "row_count_check" not in report:
        if not has_e2e:
            return
        raise ReportError(
            f"{source}: ingress e2e report requires row_count_check"
        )
    check = report["row_count_check"]
    if not isinstance(check, dict):
        raise ReportError(f"{source}: ingress row_count_check must be an object")
    for field in ("expected", "actual"):
        value = check.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ReportError(
                f"{source}: ingress row_count_check.{field} must be a "
                "positive integer"
            )
    if check["expected"] != report["rows"]:
        raise ReportError(
            f"{source}: ingress row_count_check.expected must equal rows"
        )
    if check["actual"] != check["expected"]:
        raise ReportError(
            f"{source}: ingress row_count_check.actual must equal expected"
        )
    if check.get("ok") is not True:
        raise ReportError(f"{source}: ingress row_count_check.ok must be true")
    if check.get("inflated") is not False:
        raise ReportError(
            f"{source}: ingress row_count_check.inflated must be false"
        )


def validate_summary_metrics(source, path, summary):
    for name in ("rows_per_s_median", "median_s", "mib_per_s"):
        if name not in summary:
            raise ReportError(
                f"{source}: path {path!r} requires {name}"
            )
        value = summary[name]
        if value is None:
            if name == "mib_per_s":
                continue
            raise ReportError(
                f"{source}: path {path!r} {name} must be a finite "
                "positive number"
            )
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            sign = "non-negative" if name == "mib_per_s" else "positive"
            raise ReportError(
                f"{source}: path {path!r} {name} must be a finite "
                f"{sign} number"
            )
        try:
            number = float(value)
        except (OverflowError, ValueError) as exc:
            raise ReportError(
                f"{source}: path {path!r} {name} is outside the supported "
                "numeric range"
            ) from exc
        invalid_sign = number < 0 if name == "mib_per_s" else number <= 0
        if not math.isfinite(number) or invalid_sign:
            sign = "non-negative" if name == "mib_per_s" else "positive"
            raise ReportError(
                f"{source}: path {path!r} {name} must be a finite "
                f"{sign} number"
            )


def platform_class(machine):
    """Reduce a machine block to a coarse (os, arch) compatibility token.

    Producers spell these differently (macOS-26..-arm64 vs macos/aarch64),
    so compare families rather than exact strings. This is not physical-machine
    identity.
    """
    blob = " ".join(
        str(machine.get(k, "")) for k in ("platform", "arch", "cpu")).lower()
    if "arm64" in blob or "aarch64" in blob:
        arch = "arm64"
    elif "x86_64" in blob or "amd64" in blob:
        arch = "x86_64"
    else:
        arch = "?"
    if "mac" in blob or "darwin" in blob:
        os_ = "macos"
    elif "linux" in blob:
        os_ = "linux"
    elif "win" in blob:
        os_ = "windows"
    else:
        os_ = "?"
    return (os_, arch)


def client_rank(client):
    return (CLIENT_ORDER.index(client) if client in CLIENT_ORDER
            else len(CLIENT_ORDER), client)


def collect(reports):
    """Collect reports into five-dimensional comparison groups."""
    groups = {}
    for report in reports:
        key = comparison_key(report)
        source = report.get("_source", "<input>")
        client = report.get("client")
        if not isinstance(client, str) or not client:
            raise ReportError(f"{source}: client must be a non-empty string")
        reject_surrogate_code_points(source, "client", client)
        paths = report.get("paths")
        if not isinstance(paths, dict) or not paths:
            raise ReportError(f"{source}: paths must be a non-empty object")
        for name, summary in paths.items():
            mapped = ROLE_OF_PATH.get(name)
            if mapped is None:
                raise ReportError(f"{source}: unknown path {name!r}")
            if mapped[0] != key.direction:
                raise ReportError(
                    f"{source}: path {name!r} is for {mapped[0]} direction, "
                    f"not {key.direction}"
                )
            if not isinstance(summary, dict):
                raise ReportError(f"{source}: path {name!r} must be an object")
            validate_summary_metrics(source, name, summary)
        validate_row_count(report, paths)
        machine = report.get("machine", {})
        if not isinstance(machine, dict):
            raise ReportError(f"{source}: machine must be an object")
        commits = report.get("commits", {})
        if not isinstance(commits, dict):
            raise ReportError(f"{source}: commits must be an object")
        for name in ("c_questdb_client", "py_questdb_client"):
            value = commits.get(name)
            if isinstance(value, str):
                reject_surrogate_code_points(source, f"commits.{name}", value)

        slot = groups.setdefault(key, {
            "grid": {}, "clients": [], "env": [], "sources": [],
            "cell_sources": {},
        })
        if client not in slot["clients"]:
            slot["clients"].append(client)
        slot["env"].append({
            "client": client,
            "machine": machine,
            "commits": commits,
            "platform_class": platform_class(machine),
            "source": source,
        })
        slot["sources"].append(source)
        for name, summary in paths.items():
            role = ROLE_OF_PATH[name][1]
            role_sources = slot["cell_sources"].setdefault(role, {})
            if client in role_sources:
                raise ReportError(
                    f"duplicate {key.direction} {role!r}/{client!r} cell in "
                    f"{role_sources[client]} and {source}"
                )
            role_sources[client] = source
            slot["grid"].setdefault(role, {})[client] = summary
    return groups


def fmt_cell(summary, bpr):
    if not summary:
        return "—"
    rps = summary.get("rows_per_s_median")
    if not isinstance(rps, (int, float)):
        return "—"
    try:
        rps = float(rps)
        gibs = (rps / GIB) * bpr
    except (OverflowError, ValueError) as exc:
        raise ReportError(
            "rows_per_s_median is outside the renderable range"
        ) from exc
    if not math.isfinite(rps) or not math.isfinite(gibs):
        raise ReportError("rows_per_s_median is outside the renderable range")
    return f"{rps / 1e6:.1f} M/s · {gibs:.2f} GiB/s"


def bytes_per_row(key, ingress_override=None, egress_override=None):
    override = ingress_override if key.direction == "ingress" else egress_override
    flag = "--ingress-bpr" if key.direction == "ingress" else "--egress-bpr"
    if override is not None:
        if isinstance(override, bool) or not isinstance(
            override, (int, float)
        ):
            raise ReportError(f"{flag} must be positive")
        try:
            finite = math.isfinite(override)
        except (OverflowError, TypeError, ValueError) as exc:
            raise ReportError(
                f"{flag} is outside the supported numeric range"
            ) from exc
        if not finite or override <= 0:
            raise ReportError(f"{flag} must be positive")
        return override
    defaults = CANONICAL_BPR.get((key.schema, key.rows))
    if defaults is None:
        raise ReportError(
            f"{key.schema}/{key.rows} {key.direction} has no canonical B/row; "
            f"pass {flag} explicitly"
        )
    return defaults[key.direction]


def render_group(key, slot, bpr, fmt):
    clients = sorted(slot["clients"], key=client_rank)
    client_labels = [rendered_text(client, fmt) for client in clients]
    schema = rendered_text(key.schema, fmt)
    run_mode = rendered_text(key.run_mode, fmt)
    title = (
        f"{key.direction.title()} — {schema}, {key.rows:,} rows, "
        f"senders={key.senders}, run_mode={run_mode} "
        f"(GiB/s @ {bpr:g} on-wire B/row)"
    )

    roles = [
        role for role in ROLE_ORDER[key.direction] if role in slot["grid"]
    ]
    roles += [r for r in slot["grid"] if r not in roles]

    lines = []
    if fmt == "md":
        lines.append(f"### {title}\n")
        lines.append("| role | " + " | ".join(client_labels) + " |")
        lines.append("|" + "---|" * (len(clients) + 1))
        for role in roles:
            cells = [fmt_cell(slot["grid"][role].get(c), bpr) for c in clients]
            lines.append(f"| {role} | " + " | ".join(cells) + " |")
    else:
        lines.append(title)
        w = max([len(r) for r in roles] + [4])
        lines.append("  " + "role".ljust(w) + "  "
                     + "  ".join(c.center(24) for c in client_labels))
        for role in roles:
            cells = [fmt_cell(slot["grid"][role].get(c), bpr).center(24)
                     for c in clients]
            lines.append("  " + role.ljust(w) + "  " + "  ".join(cells))
    return "\n".join(lines)


def render_env(groups, fmt):
    lines = []
    by_client = {}
    distinct_platform_classes = set()
    for slot in groups.values():
        for env in slot["env"]:
            by_client.setdefault(env["client"], []).append(env)
            distinct_platform_classes.add(env["platform_class"])
    warn = len(distinct_platform_classes) > 1

    head = "## Environment" if fmt == "md" else "Environment"
    lines.append(head)
    for client in sorted(by_client, key=client_rank):
        environments = by_client[client]
        client_platforms = sorted({
            env["platform_class"] for env in environments
        })
        platform_text = ", ".join(
            f"{os_}/{arch}" for os_, arch in client_platforms
        )

        def commit_text(name):
            values = sorted({
                str(value)[:12]
                for env in environments
                if (value := env["commits"].get(name))
            })
            return rendered_text("/".join(values) or "—", fmt)

        cc = commit_text("c_questdb_client")
        pc = commit_text("py_questdb_client")
        client_label = rendered_text(client, fmt)
        lines.append(
            f"- **{client_label}**: {platform_text} · py={pc} · c={cc}"
            if fmt == "md" else
            f"  {client_label}: {platform_text}  py={pc} c={cc}")
    if warn:
        lines.append(
            ("> ⚠️ **Platform classes differ across inputs** "
             if fmt == "md" else
             "  !! platform classes differ across inputs ")
            + f"({sorted(distinct_platform_classes)}) — physical box "
            "unverified; comparisons require compatible hardware.")
    else:
        lines.append(
            ("> ⚠️ **Single platform class** " if fmt == "md" else
             "  !! single platform class ")
            + f"({next(iter(distinct_platform_classes))}) — physical box "
            "unverified.")
    return "\n".join(lines)


def raw_group_label(key):
    def escape(value):
        return (
            value.replace("%", "%25")
            .replace("|", "%7C")
            .replace("=", "%3D")
        )

    return (
        f"direction={key.direction}|schema={escape(key.schema)}|rows={key.rows}|"
        f"senders={key.senders}|run_mode={escape(key.run_mode)}"
    )


def reject_duplicate_json_members(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ReportError(f"duplicate JSON member collision for {key!r}")
        result[key] = value
    return result


def render_raw(groups, fmt):
    raw = {}
    direction_rank = {"ingress": 0, "egress": 1}
    ordered = sorted(
        groups,
        key=lambda key: (
            direction_rank[key.direction], key.schema, key.rows,
            key.senders, key.run_mode,
        ),
    )
    for key in ordered:
        label = raw_group_label(key)
        if label in raw:
            raise ReportError(f"raw group label collision: {label}")
        grid = groups[key]["grid"]
        roles = [role for role in ROLE_ORDER[key.direction] if role in grid]
        roles += sorted(role for role in grid if role not in roles)
        raw[label] = {
            role: {
                client: {
                    "rows_per_s": grid[role][client].get(
                        "rows_per_s_median"
                    ),
                    "mib_per_s_native": grid[role][client].get("mib_per_s"),
                    "median_s": grid[role][client].get("median_s"),
                }
                for client in sorted(grid[role], key=client_rank)
            }
            for role in roles
        }
    try:
        body = json.dumps(raw, indent=2, allow_nan=False, ensure_ascii=True)
        json.loads(body, object_pairs_hook=reject_duplicate_json_members)
    except ReportError:
        raise
    except (OverflowError, ValueError) as exc:
        raise ReportError(f"cannot render raw metrics: {exc}") from exc
    if fmt == "md":
        return f"## Raw\n```json\n{body}\n```"
    return f"Raw\n{body}"


def render(groups, fmt, ingress_override=None, egress_override=None, raw=False):
    for direction, override, flag in (
        ("ingress", ingress_override, "--ingress-bpr"),
        ("egress", egress_override, "--egress-bpr"),
    ):
        if override is None:
            continue
        shapes = {
            (key.schema, key.rows)
            for key in groups
            if key.direction == direction
        }
        if len(shapes) > 1:
            raise ReportError(
                f"{flag} cannot cover multiple (schema, rows) workloads; "
                "use separate invocations for each workload"
            )

    blocks = [
        "# QWP benchmark comparison" if fmt == "md"
        else "QWP benchmark comparison"
    ]
    direction_rank = {"ingress": 0, "egress": 1}
    ordered = sorted(
        groups,
        key=lambda key: (
            direction_rank[key.direction], key.schema, key.rows,
            key.senders, key.run_mode,
        ),
    )
    for key in ordered:
        bpr = bytes_per_row(key, ingress_override, egress_override)
        blocks.append(render_group(key, groups[key], bpr, fmt))
    blocks.append(render_env(groups, fmt))
    if raw:
        blocks.append(render_raw(groups, fmt))
    return "\n\n".join(blocks)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="tools/qwp_bench/aggregate.py",
        description=(
            "QWP benchmark aggregator; see doc/BENCHMARKS.md for the report "
            "contract"
        ),
    )
    ap.add_argument("files", nargs="*", help="contract JSON files")
    ap.add_argument("--glob", action="append", default=[],
                    help="glob pattern(s) for contract JSON (repeatable)")
    ap.add_argument("--format", choices=["md", "text"], default="md")
    ap.add_argument("--ingress-bpr", type=float, default=None,
                    help="canonical on-wire bytes/row for ingress GiB/s")
    ap.add_argument("--egress-bpr", type=float, default=None,
                    help="canonical on-wire bytes/row for egress GiB/s")
    ap.add_argument("--raw", action="store_true",
                    help="also dump each path's native rows/s + mib_per_s")
    args = ap.parse_args(argv)

    paths = list(args.files)
    for pattern in args.glob:
        paths += sorted(globmod.glob(pattern))
    if not paths:
        ap.error("no input files (pass paths and/or --glob)")

    try:
        reports = load_reports(paths)
        groups = collect(reports)
        output = render(
            groups, args.format, args.ingress_bpr, args.egress_bpr, args.raw
        )
    except ReportError as exc:
        ap.error(str(exc))
    print(output)


if __name__ == "__main__":
    main()
