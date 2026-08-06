# Publishing a release

This is the routine release checklist. The
[release runbook](RELEASE_RUNBOOK.md) contains the full prerequisites,
go/no-go gates, fallback validation, ownership, and rollback procedures. Use
both documents for a production release.

The repository publishes:

- a lightweight Git tag and GitHub Release for the source-only C/C++ clients;
- the `questdb-rs` crate on crates.io and its docs.rs build; and
- coordinated C, C++, and Rust pages from `questdb/documentation`.

## 1. Prepare a clean release branch

```bash
git fetch origin --tags --prune
git switch main
git pull --ff-only
test -z "$(git status --porcelain=v1 --untracked-files=all)"
git switch -c release/7.0.0
```

Replace `7.0.0` throughout these examples with the intended version.

Confirm publisher access, a crates.io token configured with `cargo login` or a
protected environment variable, a release verifier, and a merge-ready
`questdb/documentation` PR before proceeding.

## 2. Update versions and release documentation

Install the bump tool once if needed:

```bash
uv tool install bump-my-version
```

Preview and then apply the version update:

```bash
bump-my-version replace --new-version 7.0.0 --dry-run
bump-my-version replace --new-version 7.0.0
```

Review every changed version and update the release notes, compatibility
statements, and this repository's documentation. The QWP/WebSocket floor for
7.0.0 is QuestDB 10.0 and the Rust MSRV is 1.91.1.

Refresh every tracked lockfile containing this client:

```bash
cargo build --manifest-path questdb-rs-ffi/Cargo.toml
cargo build --manifest-path system_test/failover_clients/Cargo.toml
cargo build --manifest-path system_test/soak/workload_rs/Cargo.toml
git diff -- '*Cargo.lock'
```

## 3. Validate and merge the release PR

At minimum, run the repository documentation check, native formatting check,
MSRV checks, rustdoc, and the ordinary test pipeline described in the full
runbook:

```bash
python3 ci/check_docs.py
python3 ci/format_cpp.py --check

cargo +1.91.1 check --manifest-path questdb-rs/Cargo.toml
cargo +1.91.1 check --manifest-path questdb-rs/Cargo.toml \
  --features almost-all-features,arrow,polars
cargo +1.91.1 check --manifest-path questdb-rs-ffi/Cargo.toml --all-features

RUSTDOCFLAGS="-D warnings" cargo +1.91.1 doc \
  --manifest-path questdb-rs/Cargo.toml \
  --no-deps --features almost-all-features,arrow,polars
```

Commit, push, and merge a normal release PR. Do not tag its feature-branch
head. After merge, identify the exact `main` SHA and require the full release
gates against that commit, including the QuestDB 10.0 integration check,
Enterprise check, and release-candidate soak.

## 4. Inspect the crate and source archive

From a clean checkout of the approved `main` commit:

```bash
VERSION=7.0.0
RELEASE_SHA="$(git rev-parse HEAD)"

cd questdb-rs
cargo generate-lockfile
cargo package --list --locked
cargo publish --dry-run --locked
cd ..

git archive --format=tar.gz \
  --prefix="c-questdb-client-${VERSION}/" \
  --output="/tmp/c-questdb-client-${VERSION}.tar.gz" \
  "$RELEASE_SHA"
```

Review the packaged files and checksum, and smoke-build the extracted source
archive as a C11 and C++17 consumer. Record all results against `RELEASE_SHA`.

## 5. Create the lightweight tag

Have the release verifier compare `RELEASE_SHA` with the approved CI results,
then create only the intended tag:

```bash
git tag "$VERSION" "$RELEASE_SHA"
git push origin "refs/tags/$VERSION"

test "$(git rev-parse "$VERSION^{commit}")" = "$RELEASE_SHA"
test "$(git ls-remote origin "refs/tags/$VERSION" | cut -f1)" = \
  "$RELEASE_SHA"
```

Do not use `git push --tags`, move a published tag, or reuse a version.

## 6. Publish the Rust crate and GitHub Release

Publish from the same clean checkout and generated lock used for the final dry
run:

```bash
cd questdb-rs
cargo publish --dry-run --locked
cargo publish --locked
cd ..
```

Verify crates.io before retrying a command that timed out; an upload may have
succeeded even when the local wait did not. Once the exact version is visible,
publish the prepared GitHub Release:

```bash
gh release create "$VERSION" \
  --verify-tag \
  --title "$VERSION" \
  --notes-file /path/to/release-notes.md
```

No native binaries are attached; GitHub's tag source archives are the C/C++
release artifacts.

## 7. Publish and verify documentation

Wait for docs.rs to build the exact crate version, then merge the prepared
`questdb/documentation` PR and wait for questdb.com deployment. Verify:

- the crates.io package and docs.rs API pages;
- the GitHub Release and its source archives;
- the C, C++, and Rust product guides and cross-links; and
- the QuestDB 10.0 and Rust 1.91.1 compatibility statements.

ReadTheDocs is used by the Python client and is not part of this release unless
a separate Python-client release is also being coordinated.
