# How to publish a new release

## 1. Ensure you're fully in sync with the remote repo

```bash
git switch main
git pull
git status
```

## 2. Create the release branch

```bash
git switch -c vX.Y.Z
```

## 3. Update all the occurrences of the version in the repo

## Updating version in the codebase before releasing

* Ensure you have `uv` and `bump-my-version` installed:
  * `curl -LsSf https://astral.sh/uv/install.sh | sh` : see https://docs.astral.sh/uv/getting-started/installation/
  * `uv tool install bump-my-version`: see https://github.com/callowayproject/bump-my-version.

```console
bump-my-version replace --new-version NEW_VERSION
```

If you're unsure, append `--dry-run` to preview changes.

## 4. Refresh `Cargo.lock`

```bash
cd questdb-rs-ffi
cargo clean
cargo build
```

## 5. Merge the release branch to master

```bash
git commit -a -m "Bump version: <current> → <new>"
git push
```

Replace the `<current>` and `<new>` placeholders!

Create and merge a PR with the same name: "Bump version: \<current\> → \<new\>"

## 6. Tag the new version

Once the PR is merged, pull main and add the version tag:

```bash
git switch main
git pull --prune
git tag X.Y.Z
git push --tags
```

## 7. Create a new release on GitHub

[GitHub Release Page](https://github.com/questdb/c-questdb-client/releases)

On that page you'll see all the previous releases. Follow their manually-written
style, and note that the style differs between patch, minor, and major releases.

## 8. Publish the Rust crate to crates.io

Ensure once more you're fully in sync with the remote repo:

```bash
git switch main
git pull
git status
```

Publish the crate:

```bash
cd questdb-rs
cargo publish --dry-run --token [your API token from crates.io]
cargo publish --token [your API token from crates.io]
```

## 9. Ensure the docs are online on docs.rs

The release is immediately visible on crates.io, but there's a delay until it
becomes available on [docs.rs](https://docs.rs/questdb-rs/latest/questdb/). Watch that site and ensure it
appears there.
