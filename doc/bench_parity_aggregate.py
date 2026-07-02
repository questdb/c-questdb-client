#!/usr/bin/env python3
"""Step 4 parity-table aggregator (QWP_DATAFRAME_BENCH_PLAN.md §7).

Consumes the §3.2 JSON metric contract emitted by every bench path -- Python
(``py-questdb-client``: ``benchmark_pandas_columnar.py`` ingress,
``benchmark_pandas_egress.py`` egress) and Rust (``c-questdb-client``:
``examples/qwp_ingress_polars.rs`` / ``qwp_egress_polars.rs`` via
``examples/bench_json``) -- and renders one ``rows/s`` + ``GiB/s`` parity table
per direction, lining the clients up side by side.

Two contract facts this normalizes (verified against real 10M S1 output):

* **Path names differ per client.** The same role carries different names:
  ingress CPU floor is ``columnar-populate`` (py) vs ``encode-floor`` (rust);
  the polars egress assemble is ``to-polars`` (py) vs ``fetch-all-polars``
  (rust). ``ROLE_OF_PATH`` maps every known path name onto a canonical role.

* **Egress byte basis differs.** py-egress records the *decoded Arrow* nbytes
  (~480 MB for 10M S1) as its wire proxy; rust-egress and all ingress paths
  record the *on-wire QWP* payload (~371 MB egress / ~450 MB ingress). Native
  ``mib_per_s`` is therefore NOT comparable across clients. We instead derive
  GiB/s from the basis-independent ``rows_per_s`` times a single canonical
  on-wire bytes/row per direction (``--ingress-bpr`` / ``--egress-bpr``), which
  reproduces the on-wire MiB/s the parity comment uses for both clients.

Usage:
    bench_parity_aggregate.py FILE [FILE ...] [--glob 'dir/*.json']
                              [--format md|text] [--ingress-bpr 45.0]
                              [--egress-bpr 37.1283602] [--raw]
"""

import argparse
import glob as globmod
import json
import sys

GIB = 1024.0 ** 3
MIB = 1024.0 ** 2

# Canonical on-wire QWP bytes/row for S1-narrow (10M): ingress 450,000,140 B,
# egress 371,283,602 B. Identical for both clients, so GiB/s derived from
# rows/s x bpr is apples-to-apples. Overridable for other schemas.
DEFAULT_BPR = {"ingress": 45.0, "egress": 37.1283602}

# Path name -> (direction, canonical role). Every emitter's path names live
# here; add a row when a new path is introduced.
ROLE_OF_PATH = {
    # --- ingress ---
    "columnar-populate":      ("ingress", "CPU floor"),
    "encode-floor":           ("ingress", "CPU floor"),
    "real-client":            ("ingress", "e2e DataFrame->wire"),
    "flush-polars-dataframe": ("ingress", "e2e DataFrame->wire"),
    # --- egress ---
    "decode-only":            ("egress", "decode floor"),
    "to-polars":              ("egress", "-> polars"),
    "fetch-all-polars":       ("egress", "-> polars"),
    "iter-polars":            ("egress", "-> polars (lazy/iter)"),
    "iter-pandas":            ("egress", "-> pandas (lazy/iter)"),
    "to-pandas":              ("egress", "-> pandas (numpy)"),
    "to-pandas-arrow":        ("egress", "-> pandas (Arrow)"),
    "to-pandas-nullable":     ("egress", "-> pandas (nullable)"),
    "arrow-c-stream":         ("egress", "Arrow C-stream"),
}

# Render order of roles within each direction.
ROLE_ORDER = {
    "ingress": ["CPU floor", "e2e DataFrame->wire"],
    "egress": [
        "decode floor", "-> polars", "-> polars (lazy/iter)",
        "-> pandas (numpy)", "-> pandas (Arrow)", "-> pandas (nullable)",
        "-> pandas (lazy/iter)", "Arrow C-stream",
    ],
}

# Stable client column order; unknown clients append in first-seen order.
CLIENT_ORDER = ["py-pandas", "rust-polars", "java", "go"]


def load_reports(paths):
    reports = []
    for p in paths:
        try:
            with open(p) as fh:
                d = json.load(fh)
        except (OSError, ValueError) as exc:
            print(f"warning: skipping {p}: {exc}", file=sys.stderr)
            continue
        d["_source"] = p
        reports.append(d)
    return reports


def coarse_box(machine):
    """Reduce a machine block to a coarse (os, arch) token for the single-box
    check; py and rust spell these differently (macOS-26..-arm64 vs macos /
    aarch64), so we compare families, not exact strings."""
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
    """Build {direction: {role: {client: path_summary}}} plus per-direction
    metadata (clients, rows, schema, env per client, sources, skipped paths)."""
    by_dir = {}
    for d in reports:
        direction = d.get("direction")
        client = d.get("client", "?")
        slot = by_dir.setdefault(direction, {
            "grid": {}, "clients": [], "rows": set(), "schema": set(),
            "env": {}, "sources": [], "skipped": [], "wire_bytes": {},
        })
        if client not in slot["clients"]:
            slot["clients"].append(client)
        slot["rows"].add(d.get("rows"))
        slot["schema"].add(d.get("schema"))
        slot["env"][client] = {
            "machine": d.get("machine", {}), "commits": d.get("commits", {}),
            "box": coarse_box(d.get("machine", {})),
        }
        slot["wire_bytes"][client] = d.get("wire_bytes")
        slot["sources"].append(d["_source"])
        slot.setdefault("client_sources", {}).setdefault(
            client, []).append(d["_source"])
        for name, summary in d.get("paths", {}).items():
            mapped = ROLE_OF_PATH.get(name)
            if mapped is None or mapped[0] != direction:
                slot["skipped"].append(f"{client}:{name}")
                continue
            role = mapped[1]
            slot["grid"].setdefault(role, {})[client] = summary
    return by_dir


def fmt_cell(summary, bpr):
    if not summary:
        return "—"
    rps = summary.get("rows_per_s_median")
    if not isinstance(rps, (int, float)):
        return "—"
    gibs = rps * bpr / GIB
    return f"{rps / 1e6:.1f} M/s · {gibs:.2f} GiB/s"


def render_direction(direction, slot, bpr, fmt):
    clients = sorted(slot["clients"], key=client_rank)
    rows = sorted(r for r in slot["rows"] if r is not None)
    schema = sorted(s for s in slot["schema"] if s)
    rowstr = "/".join(f"{r:,}" for r in rows) if rows else "?"
    title = (f"{direction.title()} — {', '.join(schema) or '?'}, "
             f"{rowstr} rows  (GiB/s @ {bpr:g} on-wire B/row)")

    roles = [r for r in ROLE_ORDER.get(direction, []) if r in slot["grid"]]
    roles += [r for r in slot["grid"] if r not in roles]

    lines = []
    if fmt == "md":
        lines.append(f"### {title}\n")
        lines.append("| role | " + " | ".join(clients) + " |")
        lines.append("|" + "---|" * (len(clients) + 1))
        for role in roles:
            cells = [fmt_cell(slot["grid"][role].get(c), bpr) for c in clients]
            lines.append(f"| {role} | " + " | ".join(cells) + " |")
    else:
        lines.append(title)
        w = max([len(r) for r in roles] + [4])
        lines.append("  " + "role".ljust(w) + "  "
                     + "  ".join(c.center(24) for c in clients))
        for role in roles:
            cells = [fmt_cell(slot["grid"][role].get(c), bpr).center(24)
                     for c in clients]
            lines.append("  " + role.ljust(w) + "  " + "  ".join(cells))
    return "\n".join(lines)


def render_env(by_dir, fmt):
    lines = []
    boxes, commits, sources = {}, {}, []
    for slot in by_dir.values():
        sources += slot["sources"]
        for client, env in slot["env"].items():
            boxes[client] = env["box"]
            pc = env["commits"]
            commits[client] = {k: pc.get(k) for k in (
                "py_questdb_client", "c_questdb_client")}
    distinct_boxes = set(boxes.values())
    warn = len(distinct_boxes) > 1

    dupes = []
    for direction, slot in by_dir.items():
        for client, srcs in slot.get("client_sources", {}).items():
            if len(srcs) > 1:
                dupes.append(f"{direction}/{client}: {len(srcs)} files "
                             "(paths merged, last wins per path)")

    head = "## Environment" if fmt == "md" else "Environment"
    lines.append(head)
    for client in sorted(boxes, key=client_rank):
        os_, arch = boxes[client]
        c = commits[client]
        cc = c.get("c_questdb_client") or "—"
        pc = c.get("py_questdb_client") or "—"
        lines.append(
            f"- **{client}**: {os_}/{arch} · py={pc[:12]} · c={cc[:12]}"
            if fmt == "md" else
            f"  {client}: {os_}/{arch}  py={pc[:12]} c={cc[:12]}")
    if warn:
        lines.append(
            ("> ⚠️ **Boxes differ across inputs** " if fmt == "md" else
             "  !! boxes differ across inputs ")
            + f"({sorted(distinct_boxes)}) — parity requires single-box, "
            "single-stream (plan §3.7/§7).")
    else:
        lines.append(
            ("> ✅ single box " if fmt == "md" else "  single box ")
            + f"({next(iter(distinct_boxes))}).")
    for dup in dupes:
        lines.append(("> ⚠️ duplicate inputs " if fmt == "md"
                      else "  !! duplicate inputs ") + dup)
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Step 4 QWP DataFrame parity-table aggregator")
    ap.add_argument("files", nargs="*", help="contract JSON files")
    ap.add_argument("--glob", action="append", default=[],
                    help="glob pattern(s) for contract JSON (repeatable)")
    ap.add_argument("--format", choices=["md", "text"], default="md")
    ap.add_argument("--ingress-bpr", type=float, default=DEFAULT_BPR["ingress"],
                    help="canonical on-wire bytes/row for ingress GiB/s")
    ap.add_argument("--egress-bpr", type=float, default=DEFAULT_BPR["egress"],
                    help="canonical on-wire bytes/row for egress GiB/s")
    ap.add_argument("--raw", action="store_true",
                    help="also dump each path's native rows/s + mib_per_s")
    args = ap.parse_args()

    paths = list(args.files)
    for g in args.glob:
        paths += sorted(globmod.glob(g))
    if not paths:
        ap.error("no input files (pass paths and/or --glob)")

    reports = load_reports(paths)
    if not reports:
        ap.error("no valid contract JSON loaded")
    by_dir = collect(reports)
    bpr = {"ingress": args.ingress_bpr, "egress": args.egress_bpr}

    blocks = []
    title = "# QWP DataFrame parity table" if args.format == "md" \
        else "QWP DataFrame parity table"
    blocks.append(title)
    for direction in ("ingress", "egress"):
        if direction in by_dir:
            blocks.append(render_direction(
                direction, by_dir[direction], bpr[direction], args.format))
    blocks.append(render_env(by_dir, args.format))

    # Footnotes.
    skipped = sorted({s for slot in by_dir.values() for s in slot["skipped"]})
    notes = [
        "GiB/s = rows/s × canonical on-wire bytes/row (basis-independent); "
        "native per-file `mib_per_s` is NOT cross-client comparable on egress "
        "(py records decoded-Arrow nbytes, rust records on-wire).",
    ]
    if skipped:
        notes.append("Paths not in the parity roles (shown for completeness): "
                     + ", ".join(skipped) + ".")
    nb = "\n".join((f"> {n}" if args.format == "md" else f"  note: {n}")
                   for n in notes)
    blocks.append(("## Notes\n" if args.format == "md" else "Notes\n") + nb)

    if args.raw:
        raw = {d: {role: {c: {
            "rows_per_s": s.get("rows_per_s_median"),
            "mib_per_s_native": s.get("mib_per_s"),
            "median_s": s.get("median_s"),
        } for c, s in cols.items()}
            for role, cols in slot["grid"].items()}
            for d, slot in by_dir.items()}
        blocks.append(("## Raw\n```json\n" if args.format == "md" else "Raw\n")
                      + json.dumps(raw, indent=2)
                      + ("\n```" if args.format == "md" else ""))

    print("\n\n".join(blocks))


if __name__ == "__main__":
    main()
