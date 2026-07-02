#!/usr/bin/env bash
# Pre-commit fmt + clippy for the touched Rust crates (fmt before clippy,
# no `-D warnings` — see CLAUDE.md). Each crate is linted twice: once with
# default features, once with the arrow/polars features so the feature-gated
# code is also compiled and linted.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

cargo fmt --manifest-path questdb-rs/Cargo.toml
cargo clippy --manifest-path questdb-rs/Cargo.toml --tests
cargo clippy --manifest-path questdb-rs/Cargo.toml --tests --features arrow,polars

cargo fmt --manifest-path questdb-rs-ffi/Cargo.toml
cargo clippy --manifest-path questdb-rs-ffi/Cargo.toml --tests
cargo clippy --manifest-path questdb-rs-ffi/Cargo.toml --tests --features arrow
