# Project conventions

## Rust lints

- Never pass `-D warnings` to `cargo clippy` or `cargo build`. Run plain
  `cargo clippy` / `cargo build` and read the output. New rustc/clippy
  releases add lints; `-D warnings` turns every new lint into an error
  for code that was fine yesterday, producing CI-style failures during
  ordinary local verification.
