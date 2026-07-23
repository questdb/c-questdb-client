# Release runbook

This is the full release-control document. For the shorter command checklist,
see [RELEASING.md](RELEASING.md); do not use the compact checklist as a
substitute for the gates and ownership requirements below.

This runbook covers a coordinated release of:

- the Rust `questdb-rs` crate;
- the C API and C++ wrapper from this repository;
- the generated Rust API documentation on docs.rs; and
- the C, C++, and Rust guides on the QuestDB documentation website.

The C and C++ clients are distributed as source. We do not currently publish
pre-built native binaries. A complete release therefore consists of a Git tag,
a GitHub Release, a crates.io publication, successful docs.rs output, and the
corresponding website documentation.

For the 7.0.0 release, the primary implementation PR is
[questdb/c-questdb-client#153](https://github.com/questdb/c-questdb-client/pull/153)
and the website documentation PR is
[questdb/documentation#444](https://github.com/questdb/documentation/pull/444).

## Release principles

- One release coordinator owns the release from final candidate selection
  through post-release verification.
- A second person verifies the release commit, artifacts, and publication.
- Every test result used for sign-off must identify the exact Git commit it ran
  against.
- Never tag a commit that has unresolved release blockers.
- Never move or reuse a published release tag.
- A crates.io version is permanent. It can be yanked, but it cannot be replaced
  or deleted.
- Do not put a crates.io token directly on the command line or in a shell
  history.

## Distribution channels

| Deliverable | Channel | Completion condition |
| --- | --- | --- |
| C and C++ source | Git tag and GitHub source archive | Archive builds and tag resolves to the approved commit |
| Release announcement | GitHub Release | Published Release exists for the exact tag |
| Rust client | crates.io | Exact version is visible in the crates.io index |
| Rust API documentation | docs.rs | Build succeeds with the configured feature set |
| Product documentation | `questdb/documentation` and questdb.com | Documentation PR is merged and production pages are live |
| Compatible server | QuestDB 10.0 release | Approved RC SHA passes before publication; exact downloadable release artifact passes when available |

ReadTheDocs is used by the Python client and is not part of this Rust/C/C++
release. A Python client release, including any vendored native-client update,
has its own release process.

## Prerequisites

### Access and ownership

Before beginning, confirm all of the following:

- The release coordinator can push tags and create Releases in
  `questdb/c-questdb-client`.
- The coordinator or an available publisher owns `questdb-rs` on crates.io and
  has a scoped publication token.
- The team can inspect and rerun the Azure Pipelines used by this repository,
  including the self-hosted soak runner.
- The Enterprise end-to-end client check can be run and inspected.
- The website documentation PR has an owner with merge and deployment access.
- A release verifier is available and has not authored the final tag command.
- The QuestDB 10.0 release owner has supplied the exact RC SHA, expected
  release tag, artifact ordering, and an owner for the post-publication rerun.

Authenticate Cargo with `cargo login` or a protected environment variable. Do
not copy the token into `cargo publish --token ...`:

```bash
cargo login
gh auth status
```

### Required tools

The release and fallback local-validation environment needs:

- Git and GitHub CLI;
- Rustup, Cargo, the current stable Rust toolchain, and the declared minimum
  supported Rust version (MSRV);
- a C11 compiler and a C++17 compiler;
- CMake 3.15 or newer;
- Python 3.10 or newer for the current system-test harness;
- JDK 25 and Maven when building the current QuestDB server from source;
- `uv` and `bump-my-version` when changing the repository version; and
- enough disk and memory for QuestDB integration, fuzz, Arrow/Polars, and soak
  testing.

Install the version-bump tool if needed:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
uv tool install bump-my-version
```

The declared tool versions in `doc/BUILD.md` must be corrected before release
if they do not match the toolchains actually used by CI and the published
crate.

### Product decisions

Record these decisions in the release issue before approving the release
candidate:

- Release version.
- Minimum supported QuestDB server version for QWP/WebSocket.
- Which QWP features require QuestDB Enterprise.
- Rust MSRV for default features and for every advertised feature combination.
- Supported Arrow and Polars version ranges.
- Supported operating systems, CI images, and native compiler families; record
  the exact compiler versions from the final CI run.
- Whether C/C++ remains source-only.
- Any accepted change to the established lightweight Git tag policy.
- Any accepted limitations or deferred correctness-review findings.

For 7.0.0, the approved compatibility decisions are:

- QuestDB 10.0 is the QWP/WebSocket server floor;
- HTTP Basic authentication and single-endpoint reconnect work with QuestDB
  Open Source and Enterprise, while bearer-token and OIDC authentication,
  multi-host failover, and durable acknowledgement require QuestDB Enterprise;
- Rust 1.91.1 is the MSRV for default and advertised docs.rs features;
- Arrow `>=58, <60` and Polars `>=0.52, <0.55` are the supported ranges;
- C/C++ remains source-only; and
- release tags remain lightweight.

Test the public server minimum; a green run against QuestDB `master` is not a
substitute for this compatibility check.

### Release record

Create a release issue or other durable record containing at least:

```text
Version:
Release coordinator:
Release verifier:
Release commit SHA:
Client PR:
Documentation PR:
Minimum QuestDB version:
QuestDB 10.0 RC SHA:
QuestDB 10.0 release tag and artifact URL:
Rust MSRV:
Required CI build IDs:
Enterprise build ID:
Soak build ID, duration, and seed:
Crate package checksum:
Git tag:
GitHub Release URL:
crates.io URL:
docs.rs URL:
Production documentation URLs:
Accepted exceptions and follow-up issues:
```

## Go/no-go gate

Do not tag until every applicable item is checked:

- [ ] The implementation PR is approved and all required checks are green on
      its final head commit.
- [ ] The final `main` commit is identified. If merging created a new commit,
      release tests have been run on that commit rather than only the PR head.
- [ ] Formatting and Clippy pass.
- [ ] Rust tests pass on Linux, macOS, and Windows.
- [ ] C and C++ builds and tests pass on supported compilers and platforms.
- [ ] ASan and UBSan jobs pass.
- [ ] QWP/WebSocket fuzz jobs pass on Linux, macOS, and Windows.
- [ ] QWP egress live-server tests pass.
- [ ] Arrow and Polars version-range jobs pass.
- [ ] QuestDB `master` integration passes.
- [ ] Integration against the approved QuestDB 10.0 RC SHA passes.
- [ ] The QuestDB 10.0 artifact/tag publication order and post-publication
      compatibility rerun have an owner; if the server artifact already
      exists, that rerun passes before the client is tagged.
- [ ] Enterprise end-to-end client tests pass.
- [ ] A two-hour release-candidate soak passes and its seed and artifacts are
      retained.
- [ ] The declared Rust MSRV passes default and advertised feature builds.
- [ ] Rust documentation builds with warnings denied.
- [ ] The crate package list and size have been reviewed.
- [ ] A source archive builds independently as C and C++ consumer code would
      build it.
- [ ] Release notes are approved.
- [ ] The website documentation PR is current, approved, green, and ready to
      merge.
- [ ] Compatibility statements agree across repository and website docs.
- [ ] Any QWP correctness-review checklist adopted by the team is complete, or
      every exception has an owner and explicit risk acceptance.

## Phase 1: prepare the release PR

### 1. Start from current `main`

Use a clean checkout or dedicated release worktree:

```bash
git fetch origin --tags --prune
git switch main
git pull --ff-only
test -z "$(git status --porcelain=v1 --untracked-files=all)"
git switch -c release/7.0.0
```

Do not prepare a release from a dirty feature-branch checkout.

### 2. Update and verify versions

For a future version change, preview before modifying files:

```bash
NEW_VERSION=7.0.0
bump-my-version replace --new-version "$NEW_VERSION" --dry-run
bump-my-version replace --new-version "$NEW_VERSION"
```

The 7.0.0 feature branch already declares 7.0.0. Verify at least:

- `.bumpversion.toml`;
- root `CMakeLists.txt`;
- `questdb-rs/Cargo.toml`;
- `questdb-rs-ffi/Cargo.toml`;
- C++ user-agent strings;
- version-specific links in Rust and security documentation; and
- tracked Cargo lockfiles.

Search for stale release references:

```bash
rg -n '6\.1\.0|7\.0\.0' \
  .bumpversion.toml CMakeLists.txt include doc questdb-rs questdb-rs-ffi \
  system_test
```

Review every result rather than mechanically replacing historical references.

### 3. Refresh tracked lockfiles

The release documentation historically refreshed only the FFI lockfile. A
version change can also affect lockfiles in system-test crates. Refresh and
review all tracked lockfiles that contain `questdb-rs`, currently including:

- `questdb-rs-ffi/Cargo.lock`;
- `system_test/failover_clients/Cargo.lock`; and
- `system_test/soak/workload_rs/Cargo.lock`.

For example:

```bash
cargo build --manifest-path questdb-rs-ffi/Cargo.toml
cargo build --manifest-path system_test/failover_clients/Cargo.toml
cargo build --manifest-path system_test/soak/workload_rs/Cargo.toml

git diff -- '*Cargo.lock'
```

### 4. Update repository documentation

At minimum, review:

- `doc/RELEASING.md` and this runbook;
- `doc/BUILD.md` for Rust, Java, Python, CMake, and test prerequisites;
- `doc/DEPENDENCY.md` for tag terminology and QWP/Arrow build options;
- `doc/SECURITY.md` for QWP/WSS authentication, TLS, trust stores, and tokens;
- `doc/CONSIDERATIONS.md` for protocol-specific flush, ACK, close, retry,
  background-thread, and store-and-forward semantics;
- `doc/C.md` and `doc/CPP.md` for the pool, reader, row sender, column sender,
  and Arrow APIs;
- `README.md` and `questdb-rs/README.md` for server compatibility; and
- CI comments describing when fixed-release QWP testing becomes available.

### 5. Prepare release notes

The notes for a major QWP release should include:

1. Overview.
2. Supported QuestDB versions and OSS/Enterprise differences.
3. QWP/WebSocket ingestion and query features.
4. Rust API changes.
5. C API and ABI changes.
6. C++ API changes.
7. Row, column, Arrow, and Polars support.
8. Connection pooling, reconnect, failover, acknowledgement, and
   store-and-forward behavior.
9. Authentication and TLS behavior.
10. New build options and crate features.
11. Rust MSRV and dependency ranges.
12. Breaking changes and migration examples.
13. Known limitations.
14. A full `6.1.0...7.0.0` changelog link.

State explicitly that C and C++ are distributed as source and that no pre-built
native binaries are attached.

### 6. Make website documentation merge-ready

The website documentation must:

- use the same minimum server version as the release notes;
- describe both ingestion and query paths;
- distinguish QWP/WebSocket from QWP/UDP and ILP;
- use final API names and signatures from the release candidate;
- contain no draft labels or links to unpublished versions;
- pass preview, broken-link, converter, and secret checks; and
- be approved and current with its base branch.

Do not merge version-specific website docs long before the artifacts exist.
Keep the PR ready and merge it immediately after publication.

## Phase 2: validate the release candidate

### 1. Freeze and record the candidate

After the release PR is merged, update a clean release checkout:

```bash
git fetch origin --tags --prune
git switch main
git pull --ff-only
test -z "$(git status --porcelain=v1 --untracked-files=all)"

VERSION=7.0.0
RELEASE_SHA="$(git rev-parse HEAD)"

git show --no-patch --format=fuller "$RELEASE_SHA"
```

Write `RELEASE_SHA` into the release record. All later commands in this
runbook must use this checkout and SHA.

If the merge strategy created a commit that was not the PR head, queue the full
required pipeline manually for `RELEASE_SHA`. Do not infer that tests on a
parent commit cover it.

### 2. Run CI and QWP integration gates

Require successful jobs for:

- stable, beta, and nightly Rust;
- formatting and Clippy;
- C/C++ and Rust tests on Linux, macOS, and supported Windows/MSVC versions;
- ASan and UBSan;
- QWP/WS fuzzing on Linux, macOS, and Windows;
- QWP egress against a live server;
- supported Arrow and Polars versions;
- QuestDB `master`; and
- QuestDB Enterprise client end-to-end coverage.

Run the full system suite against the chosen public minimum as a separate gate.
Until QuestDB 10.0 is published, build the approved release-candidate SHA and
test that checkout directly:

```bash
python3 system_test/test.py run --repo /path/to/questdb-10.0-rc -v
```

Record the server SHA. Once the server artifact exists, use its exact release
tag and archive—not a guessed shorthand—and record that second result:

```bash
python3 system_test/test.py run --versions <QUESTDB_10_RELEASE_TAG> -v
```

The ordinary integration path in `ci/run_all_tests.py` runs against a
from-source build of QuestDB `master`; both paths are valuable and neither
replaces the other.

### 3. Run a two-hour soak

The merge-to-`main` soak is normally only 30 minutes. Before tagging, require a
manual two-hour run for `RELEASE_SHA`, or the scheduled two-hour run if it can
be conclusively tied to that commit.

Record:

- Azure build ID;
- tested client and server SHAs;
- duration and seed;
- summary and journal artifacts; and
- any warnings, retries, dropped operations, or cleanup failures.

### 4. Verify the Rust MSRV

`questdb-rs/Cargo.toml` must contain an explicit `rust-version`. The same
version must appear in build documentation and CI.

The MSRV gate must cover default features and the feature set advertised to
docs.rs. Do not use `--all-features` if it enables mutually exclusive crypto
backends.

```bash
MSRV=1.91.1
cargo generate-lockfile --manifest-path questdb-rs/Cargo.toml

cargo +"$MSRV" check --manifest-path questdb-rs/Cargo.toml --locked
cargo +"$MSRV" check --manifest-path questdb-rs/Cargo.toml --locked \
  --features almost-all-features,arrow,polars

cargo +stable test --manifest-path questdb-rs/Cargo.toml --locked
cargo +stable test --manifest-path questdb-rs/Cargo.toml --locked \
  --features almost-all-features,arrow,polars
```

If the intended MSRV fails because current dependency resolution selects newer
packages, either raise the declared MSRV or constrain compatible dependencies.
Do not document an untested lower version.

### 5. Build documentation with warnings denied

Use the same feature set configured under `[package.metadata.docs.rs]`:

```bash
RUSTDOCFLAGS="-D warnings" cargo +1.91.1 doc \
  --manifest-path questdb-rs/Cargo.toml --no-deps --locked \
  --features almost-all-features,arrow,polars
```

Open the generated documentation and inspect the top-level crate page, ingress,
egress, connection-pool, reader, Arrow, and Polars APIs.

### 6. Inspect the crates.io package

`questdb-rs/Cargo.lock` is currently ignored. Generate it in the clean release
checkout so `--locked` verifies the exact dependency resolution used for
packaging. Retain the lockfile or package checksum in the release record even
if repository policy remains not to commit the library lockfile.

```bash
cargo generate-lockfile --manifest-path questdb-rs/Cargo.toml
cargo package --manifest-path questdb-rs/Cargo.toml --list --locked
cargo publish --manifest-path questdb-rs/Cargo.toml --dry-run --locked
```

Inspect the generated package under `questdb-rs/target/package/`:

- confirm `.cargo_vcs_info.json` names `RELEASE_SHA` and does not mark the
  package dirty;
- review every packaged source, generated file, README, license, and lockfile;
- confirm no test databases, fuzz corpora, credentials, logs, or unrelated
  generated files are included;
- record compressed and unpacked package sizes; and
- compare the size and file count with the previous release.

Record the file count and compressed and unpacked sizes in the release record.
Compare them with the previous release and review unexpected differences on
the final release commit.

### 7. Smoke-test the source archive

Before pushing the tag, approximate GitHub's source archive and build outside
the repository:

```bash
git archive --format=tar.gz \
  --prefix="c-questdb-client-${VERSION}/" \
  --output="/tmp/c-questdb-client-${VERSION}.tar.gz" \
  "$RELEASE_SHA"
```

Extract it into a clean temporary directory and verify at least:

- the default static C and C++ build;
- `BUILD_SHARED_LIBS=ON`;
- the Arrow-enabled build;
- C11 and C++17 consumer examples; and
- a minimal QWP ingestion/query round trip against the declared server
  minimum.

## Phase 3: tag and publish

Do not begin this phase unless the go/no-go gate is complete. Prepare and
approve the GitHub release text before creating the tag, but leave it as a
draft until crates.io publication succeeds.

### 1. Reconfirm the release commit

```bash
git fetch origin --tags --prune
git switch main
git pull --ff-only
test -z "$(git status --porcelain=v1 --untracked-files=all)"

VERSION=7.0.0
RELEASE_SHA="$(git rev-parse HEAD)"

git show --no-patch --format=fuller "$RELEASE_SHA"
```

Have the release verifier compare this SHA with the release record and the
completed CI and soak runs.

### 2. Create and push the tag

This repository's release tags are lightweight. Create the tag at the exact
approved commit and push only that ref.

```bash
git tag "$VERSION" "$RELEASE_SHA"
git push origin "refs/tags/$VERSION"
```

Do not use `git push --tags`, which can publish unrelated local tags.

Verify local and remote resolution:

```bash
test "$(git rev-parse "$VERSION^{commit}")" = "$RELEASE_SHA"
test "$(git ls-remote origin "refs/tags/$VERSION" | cut -f1)" = \
  "$RELEASE_SHA"
```

### 3. Publish `questdb-rs`

Publish from the same clean checkout and dependency lock used for the final
dry-run:

```bash
cargo publish --manifest-path questdb-rs/Cargo.toml --dry-run --locked
cargo publish --manifest-path questdb-rs/Cargo.toml --locked
```

Wait for the exact version to appear in the crates.io index. Cargo can time out
while waiting even after a successful upload, so verify registry state before
retrying. Never issue a second publish merely because the local command timed
out.

### 4. Publish the GitHub Release

Once crates.io shows the version, publish the prepared Release against the
existing tag:

```bash
gh release create "$VERSION" \
  --verify-tag \
  --title "$VERSION" \
  --notes-file /path/to/release-notes.md
```

No manually built native artifacts are expected. Verify that GitHub exposes
the tag source archives and that the Release is not left in draft state.

### 5. Merge product documentation

Merge the prepared `questdb/documentation` PR after the crate and GitHub
Release are visible. Wait for production deployment and verify:

- C and C++ guide and API pages;
- Rust guide pages;
- navigation and cross-links;
- crates.io and docs.rs links;
- final API names and examples; and
- server-version and Enterprise compatibility statements.

ReadTheDocs does not need an update for this release unless a separate Python
client release is also in scope.

## Phase 4: post-release verification

### 1. Test the published crate as a consumer

Use a new temporary project so no path dependency or local cache configuration
can hide packaging mistakes:

```bash
SMOKE_ROOT="$(mktemp -d)"
cargo new "$SMOKE_ROOT/qdb-rs-release-smoke"
cd "$SMOKE_ROOT/qdb-rs-release-smoke"
cargo add questdb-rs@=7.0.0
cargo check
```

Also build the advertised optional feature combinations and run a QWP
ingestion/query smoke test against the supported server minimum.

### 2. Verify all public surfaces

- crates.io shows the exact version, owners, README, features, dependencies,
  license, and repository URL.
- docs.rs reports a successful build and renders the expected APIs.
- The GitHub Release points to the approved tag and commit.
- GitHub's source archives build in a clean environment.
- Product documentation pages return successfully and show the intended
  version and compatibility statements.
- The GitHub Release is marked as the latest stable release when appropriate.
- The exact QuestDB 10.0 release artifact passes the compatibility suite. If
  coordinated release ordering made this impossible before the client was
  published, keep the release record open until this gate passes.

### 3. Close the release record

Add final URLs and checksums to the release record. The release coordinator and
verifier should sign off only after all public surfaces have been checked.

Announce the release only after this verification is complete.

## Failure and rollback procedure

### Before publishing

Stop, document the failed gate, fix it on a normal PR, and repeat validation on
the new final commit. Do not create a tag merely to reserve the version.

### After the tag is pushed but before crates.io publication

Do not move the tag to a different commit. If code must change, prepare a new
version and tag. Record the abandoned version so it is not accidentally reused.

### After crates.io publication

A crates.io version cannot be overwritten or deleted.

1. Assess severity and customer impact.
2. Prepare and publish a corrected version, normally 7.0.1 for a compatible
   fix.
3. Add a prominent warning and mitigation to the affected GitHub Release.
4. Correct the website documentation.
5. Yank the affected crate only when leaving it selectable for new dependency
   resolution would be materially harmful.

To yank without deleting the already published package:

```bash
cargo yank --version 7.0.0 questdb-rs
```

Yanking does not break consumers whose lockfiles already select the version.
Never reuse 7.0.0 after yanking it.

## Final release checklist

```text
[ ] Product compatibility decisions recorded
[ ] Prerequisites and publisher access confirmed
[ ] Release PR merged
[ ] Exact main SHA recorded
[ ] Full CI green on exact SHA
[ ] Minimum public server integration green
[ ] Exact QuestDB 10.0 artifact rerun green, or explicitly pending coordinated server publication
[ ] Enterprise integration green
[ ] Two-hour soak green
[ ] Rust MSRV gate green
[ ] Rustdoc warnings gate green
[ ] Crate package contents and size approved
[ ] Source archive smoke-build green
[ ] Website documentation approved and merge-ready
[ ] Release notes approved
[ ] Tag pushed and verified
[ ] Crate published and verified
[ ] GitHub Release published and verified
[ ] docs.rs build verified
[ ] Website documentation merged and production verified
[ ] Published consumer smoke test green
[ ] Release record completed and independently verified
```
