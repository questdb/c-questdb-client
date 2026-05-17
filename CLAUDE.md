# Project conventions

## Rust lints

- Never pass `-D warnings` to `cargo clippy` or `cargo build`. Run plain
  `cargo clippy` / `cargo build` and read the output. New rustc/clippy
  releases add lints; `-D warnings` turns every new lint into an error
  for code that was fine yesterday, producing CI-style failures during
  ordinary local verification.

## Pre-commit checks

Before every commit, run both of these against any Rust crate touched by
the change (typically `questdb-rs` and/or `questdb-rs-ffi`):

- `cargo fmt --manifest-path <crate>/Cargo.toml` — apply formatting.
- `cargo clippy --manifest-path <crate>/Cargo.toml --tests` — plain
  clippy (no `-D warnings`), read the output, and address anything
  introduced by the change.

Run them in that order so clippy sees the formatted source. Do not
commit if either reports issues attributable to the current change.
