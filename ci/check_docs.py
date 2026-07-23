#!/usr/bin/env python3

"""Check release-facing Markdown links and compatibility statements."""

import json
import pathlib
import re
import sys
import urllib.parse


ROOT = pathlib.Path(__file__).resolve().parent.parent
EXPECTED_QUESTDB_VERSION = "10.0"
EXPECTED_RUST_VERSION = "1.91.1"
EXPECTED_ARROW_RANGE = ">=58, <60"
EXPECTED_POLARS_RANGE = ">=0.52, <0.55"

ACTIVE_DOCS = (
    ROOT / "README.md",
    ROOT / "questdb-rs" / "README.md",
    ROOT / "doc" / "README.md",
    ROOT / "doc" / "BENCHMARKS.md",
    ROOT / "doc" / "BUILD.md",
    ROOT / "doc" / "C.md",
    ROOT / "doc" / "CPP.md",
    ROOT / "doc" / "COMPATIBILITY.md",
    ROOT / "doc" / "CONSIDERATIONS.md",
    ROOT / "doc" / "DEPENDENCY.md",
    ROOT / "doc" / "RELEASING.md",
    ROOT / "doc" / "RELEASE_RUNBOOK.md",
    ROOT / "doc" / "SECURITY.md",
    ROOT / "tools" / "qwp_bench" / "net" / "README.md",
)

LINK_RE = re.compile(r"!?(?:\[[^]]*\])\(([^)]+)\)")
RUST_VERSION_RE = re.compile(r'^rust-version\s*=\s*"([^"]+)"\s*$', re.MULTILINE)
PACKAGE_VERSION_RE = re.compile(r'^version\s*=\s*"([^"]+)"\s*$', re.MULTILINE)
CURRENT_VERSION_RE = re.compile(
    r'^current_version\s*=\s*"([^"]+)"\s*$', re.MULTILINE
)
RUST_CLAIM_RE = re.compile(r"\bRust\s+(\d+\.\d+(?:\.\d+)?)\b")
BUMP_FILE_BLOCK_RE = re.compile(
    r"^\[\[tool\.bumpversion\.files\]\]\s*(.*?)"
    r"(?=^\[\[tool\.bumpversion\.files\]\]|\Z)",
    re.MULTILINE | re.DOTALL,
)


def local_link_target(raw_target):
    target = raw_target.strip()
    if target.startswith("<") and ">" in target:
        target = target[1 : target.index(">")]
    else:
        target = target.split(maxsplit=1)[0]

    if not target or target.startswith("#"):
        return None
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", target):
        return None
    if target.startswith("/"):
        return None

    target = target.split("#", 1)[0].split("?", 1)[0]
    return urllib.parse.unquote(target) if target else None


def check_links(errors):
    checked = 0
    for doc in ACTIVE_DOCS:
        if not doc.is_file():
            errors.append(f"missing release-facing document: {doc.relative_to(ROOT)}")
            continue

        text = doc.read_text(encoding="utf-8")
        for match in LINK_RE.finditer(text):
            target = local_link_target(match.group(1))
            if target is None:
                continue
            checked += 1
            destination = (doc.parent / target).resolve()
            if not destination.exists():
                line = text.count("\n", 0, match.start()) + 1
                errors.append(
                    f"{doc.relative_to(ROOT)}:{line}: broken local link: {target}"
                )
    return checked


def manifest_rust_version(manifest, errors):
    text = manifest.read_text(encoding="utf-8")
    match = RUST_VERSION_RE.search(text)
    if not match:
        errors.append(f"{manifest.relative_to(ROOT)}: missing rust-version")
        return None
    return match.group(1)


def match_value(path, pattern, description, errors):
    text = path.read_text(encoding="utf-8")
    match = pattern.search(text)
    if not match:
        errors.append(f"{path.relative_to(ROOT)}: missing {description}")
        return None
    return match.group(1)


def manifest_dependency_range(manifest, dependency, errors):
    pattern = re.compile(
        rf"^{re.escape(dependency)}\s*=\s*\{{[^\n}}]*"
        rf'version\s*=\s*"([^"]+)"',
        re.MULTILINE,
    )
    return match_value(
        manifest, pattern, f"{dependency} dependency version range", errors
    )


def bump_field(block, field):
    match = re.search(
        rf'^{re.escape(field)}\s*=\s*"((?:\\.|[^"\\])*)"\s*$',
        block,
        re.MULTILINE,
    )
    if not match:
        return None
    return json.loads(f'"{match.group(1)}"')


def check_bump_config(errors, current_version):
    config = ROOT / ".bumpversion.toml"
    text = config.read_text(encoding="utf-8")
    blocks = BUMP_FILE_BLOCK_RE.findall(text)
    if not blocks:
        errors.append(".bumpversion.toml: no managed files configured")
        return

    for index, block in enumerate(blocks, start=1):
        filename = bump_field(block, "filename")
        search = bump_field(block, "search")
        replace = bump_field(block, "replace")
        if filename is None or search is None or replace is None:
            errors.append(
                f".bumpversion.toml: incomplete managed-file block {index}"
            )
            continue

        path = ROOT / filename
        if not path.is_file():
            errors.append(
                f".bumpversion.toml: managed file does not exist: {filename}"
            )
            continue

        expanded_search = search.replace("{current_version}", current_version)
        if expanded_search not in path.read_text(encoding="utf-8"):
            errors.append(
                f".bumpversion.toml: search text for {filename!r} is absent: "
                f"{expanded_search!r}"
            )


def require_doc_text(path, requirements, errors):
    text = path.read_text(encoding="utf-8")
    for needle, description in requirements:
        if needle not in text:
            errors.append(
                f"{path.relative_to(ROOT)}: missing {description}: {needle!r}"
            )


def check_compatibility(errors):
    bump_config = ROOT / ".bumpversion.toml"
    current_version = match_value(
        bump_config, CURRENT_VERSION_RE, "current release version", errors
    )

    manifests = (
        ROOT / "questdb-rs" / "Cargo.toml",
        ROOT / "questdb-rs-ffi" / "Cargo.toml",
    )
    versions = [manifest_rust_version(path, errors) for path in manifests]
    for manifest, version in zip(manifests, versions):
        if version is not None and version != EXPECTED_RUST_VERSION:
            errors.append(
                f"{manifest.relative_to(ROOT)}: rust-version is {version}, "
                f"expected {EXPECTED_RUST_VERSION}"
            )

    if current_version is not None:
        check_bump_config(errors, current_version)
        cmake_version = match_value(
            ROOT / "CMakeLists.txt",
            re.compile(r"^project\(c-questdb-client VERSION ([^)]+)\)", re.MULTILINE),
            "CMake project version",
            errors,
        )
        if cmake_version is not None and cmake_version != current_version:
            errors.append(
                f"CMakeLists.txt: project version is {cmake_version}, "
                f"expected {current_version}"
            )

        for manifest in manifests:
            package_version = match_value(
                manifest, PACKAGE_VERSION_RE, "package version", errors
            )
            if package_version is not None and package_version != current_version:
                errors.append(
                    f"{manifest.relative_to(ROOT)}: package version is "
                    f"{package_version}, expected {current_version}"
                )

    dependency_ranges = (
        (manifests[0], "arrow", EXPECTED_ARROW_RANGE),
        (manifests[0], "polars", EXPECTED_POLARS_RANGE),
        (manifests[0], "polars-arrow", EXPECTED_POLARS_RANGE),
        (manifests[1], "arrow", EXPECTED_ARROW_RANGE),
    )
    for manifest, dependency, expected in dependency_ranges:
        actual = manifest_dependency_range(manifest, dependency, errors)
        if actual is not None and actual != expected:
            errors.append(
                f"{manifest.relative_to(ROOT)}: {dependency} range is "
                f"{actual!r}, expected {expected!r}"
            )

    rust_text = f"Rust {EXPECTED_RUST_VERSION}"
    questdb_text = f"QuestDB {EXPECTED_QUESTDB_VERSION}"
    failover_edition_text = "Multi-endpoint failover requires QuestDB Enterprise"
    durable_edition_text = "Durable acknowledgement requires QuestDB Enterprise"
    requirements = {
        ROOT / "README.md": (
            (rust_text, "declared Rust MSRV"),
            (questdb_text, "QWP/WebSocket server floor"),
            (failover_edition_text, "failover edition qualifier"),
            (
                "https://questdb.com/docs/ingestion/overview/",
                "client overview URL",
            ),
        ),
        ROOT / "questdb-rs" / "README.md": (
            (rust_text, "declared Rust MSRV"),
            (questdb_text, "QWP/WebSocket server floor"),
            (failover_edition_text, "failover edition qualifier"),
        ),
        ROOT / "doc" / "BUILD.md": (
            (rust_text, "declared Rust MSRV"),
            (questdb_text, "QWP/WebSocket server floor"),
        ),
        ROOT / "doc" / "C.md": (
            (rust_text, "declared Rust MSRV"),
            (questdb_text, "QWP/WebSocket server floor"),
            (durable_edition_text, "durable ACK edition qualifier"),
        ),
        ROOT / "doc" / "CPP.md": (
            (rust_text, "declared Rust MSRV"),
            (questdb_text, "QWP/WebSocket server floor"),
            ("QuestDB Enterprise multi-host failover", "failover edition qualifier"),
        ),
        ROOT / "doc" / "COMPATIBILITY.md": (
            (
                f"| QWP over WebSocket (`ws::` / `wss::`) | {EXPECTED_QUESTDB_VERSION} |",
                "QWP/WebSocket server floor",
            ),
            (rust_text, "declared Rust MSRV"),
            (
                f"| Arrow crate | `{EXPECTED_ARROW_RANGE}` |",
                "Arrow compatibility range",
            ),
            (
                f"| Polars crates | `{EXPECTED_POLARS_RANGE}` |",
                "Polars compatibility range",
            ),
            ("require QuestDB Enterprise", "Enterprise feature boundary"),
            ("`windows-2022` and `windows-2025`", "Windows CI image coverage"),
        ),
        ROOT / "doc" / "CONSIDERATIONS.md": (
            (
                "`durable` requires QuestDB Enterprise",
                "durable ACK edition qualifier",
            ),
        ),
        ROOT / "doc" / "DEPENDENCY.md": (
            (questdb_text, "QWP/WebSocket server floor"),
        ),
        ROOT / "doc" / "RELEASING.md": (
            (rust_text, "declared Rust MSRV"),
            (questdb_text, "QWP/WebSocket server floor"),
        ),
        ROOT / "doc" / "RELEASE_RUNBOOK.md": (
            (rust_text, "declared Rust MSRV"),
            (questdb_text, "QWP/WebSocket server floor"),
            (f"Arrow `{EXPECTED_ARROW_RANGE}`", "Arrow compatibility range"),
            (f"Polars `{EXPECTED_POLARS_RANGE}`", "Polars compatibility range"),
            ("require QuestDB Enterprise", "Enterprise feature boundary"),
        ),
        ROOT / "doc" / "SECURITY.md": (
            ("bearer token (Enterprise)", "bearer-token edition qualifier"),
            (
                "https://questdb.com/docs/query/rest-api/"
                "#authentication-in-questdb-open-source",
                "QuestDB Open Source authentication URL",
            ),
            (
                "https://questdb.com/docs/security/rbac/#authentication",
                "Enterprise RBAC authentication URL",
            ),
        ),
    }

    pipeline = ROOT / "ci" / "run_tests_pipeline.yaml"
    require_doc_text(
        pipeline,
        (
            (f"toolchain install {EXPECTED_RUST_VERSION}", "MSRV installation"),
            (f"cargo +{EXPECTED_RUST_VERSION} check", "MSRV Cargo check"),
            ('imageName: "windows-2022"', "Windows Server 2022 CI image"),
            ('imageName: "windows-2025"', "Windows Server 2025 CI image"),
        ),
        errors,
    )

    if current_version is not None:
        requirements[ROOT / "questdb-rs" / "README.md"] += (
            (f"Version {current_version} requires Rust", "client release version"),
        )
        requirements[ROOT / "doc" / "COMPATIBILITY.md"] += (
            (f"for the {current_version} client", "client release version"),
        )
        requirements[ROOT / "doc" / "RELEASING.md"] += (
            (current_version, "client release version"),
        )
        requirements[ROOT / "doc" / "RELEASE_RUNBOOK.md"] += (
            (current_version, "client release version"),
        )

    for doc, required_text in requirements.items():
        require_doc_text(doc, required_text, errors)

    public_contract_requirements = {
        ROOT / "questdb-rs" / "src" / "ingress" / "sender.rs": (
            (
                "QuestDB Enterprise and a sender opened with",
                "durable ACK edition qualifier",
            ),
        ),
        ROOT / "questdb-rs" / "src" / "db.rs": (
            (
                "only the Enterprise durable level confirms",
                "accurate OK-versus-durable acknowledgement contract",
            ),
            (
                "QuestDB Enterprise and a pool opened with",
                "durable ACK edition qualifier",
            ),
        ),
        ROOT / "questdb-rs" / "src" / "ingress" / "polars.rs": (
            (
                "requires QuestDB Enterprise and `request_durable_ack=on`",
                "durable ACK edition qualifier",
            ),
        ),
        ROOT
        / "questdb-rs"
        / "src"
        / "ingress"
        / "column_sender"
        / "sender.rs": (
            (
                "requires QuestDB Enterprise and a pool opened with",
                "durable ACK edition qualifier",
            ),
        ),
        ROOT / "questdb-rs-ffi" / "src" / "lib.rs": (
            (
                "`qwpws_ack_level_durable` requires QuestDB Enterprise",
                "durable ACK edition qualifier",
            ),
        ),
        ROOT / "questdb-rs-ffi" / "src" / "column_sender.rs": (
            (
                "Enterprise-only `qwpws_ack_level_durable`",
                "durable ACK edition qualifier",
            ),
        ),
        ROOT / "include" / "questdb" / "ingress" / "line_sender.h": (
            (
                "`qwpws_ack_level_durable` requires QuestDB Enterprise and",
                "durable ACK edition qualifier",
            ),
        ),
        ROOT / "include" / "questdb" / "ingress" / "line_sender.hpp": (
            (
                "`qwpws_ack_level::durable` requires QuestDB\n"
                "     * Enterprise and",
                "durable ACK edition qualifier",
            ),
        ),
        ROOT / "include" / "questdb" / "ingress" / "qwp_sender.h": (
            (
                "Enterprise-only\n * `qwpws_ack_level_durable`",
                "durable ACK edition qualifier",
            ),
        ),
    }
    for path, required_text in public_contract_requirements.items():
        require_doc_text(path, required_text, errors)

    rust_claim_docs = tuple(
        doc
        for doc, required_text in requirements.items()
        if any(needle == rust_text for needle, _ in required_text)
    )
    for doc in rust_claim_docs:
        claims = set(RUST_CLAIM_RE.findall(doc.read_text(encoding="utf-8")))
        unexpected = claims - {EXPECTED_RUST_VERSION}
        if unexpected:
            errors.append(
                f"{doc.relative_to(ROOT)}: unexpected Rust version claim(s): "
                f"{', '.join(sorted(unexpected))}; expected {EXPECTED_RUST_VERSION}"
            )

    forbidden = (
        "Rust 1.61",
        "QuestDB 9.4.3",
        "latest annotated tag",
        "https://questdb.com/docs/connect/clients/overview/",
        "https://questdb.com/docs/reference/api/ilp/authenticate/",
    )
    for needle in forbidden:
        for doc in ACTIVE_DOCS:
            text = doc.read_text(encoding="utf-8")
            if needle in text:
                errors.append(
                    f"{doc.relative_to(ROOT)}: stale release text: {needle!r}"
                )

    publish_with_token = re.compile(r"^\s*cargo publish[^\n]*--token", re.MULTILINE)
    for doc in ACTIVE_DOCS:
        if publish_with_token.search(doc.read_text(encoding="utf-8")):
            errors.append(
                f"{doc.relative_to(ROOT)}: do not put a crates.io token "
                "in a publish command"
            )


def main():
    errors = []
    checked_links = check_links(errors)
    check_compatibility(errors)

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    print(
        f"documentation checks passed "
        f"({len(ACTIVE_DOCS)} files, {checked_links} local links)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
