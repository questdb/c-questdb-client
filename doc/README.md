# Documentation index

## User documentation

- [Compatibility](COMPATIBILITY.md)
- [Build the native client](BUILD.md)
- [Use the client from C](C.md)
- [Use the client from C++](CPP.md)
- [Add the native client as a dependency](DEPENDENCY.md)
- [Threading, delivery, and data considerations](CONSIDERATIONS.md)
- [Authentication and TLS](SECURITY.md)
- [Rust crate guide](../questdb-rs/README.md)

The public QuestDB guides contain the complete connection-string reference and
deployment guidance. The files above are deliberately compact and stay close
to the source, headers, and executable examples in this repository.

## Maintainer documentation

- [Routine release checklist](RELEASING.md)
- [Full release runbook](RELEASE_RUNBOOK.md)
- [Development notes](DEV_NOTES.md)
- [QWP soak harness](QWP_SOAK_HARNESS.md)
- [QWP network benchmark plan](QWP_NETWORK_BENCH_PLAN.md)
- [Unified QWP sender design](QWP_UNIFIED_SENDER_DESIGN.md)
- [Unified QWP sender baseline](QWP_UNIFIED_SENDER_M0_BASELINE.md)

These files describe repository maintenance, validation, performance work, or
internal architecture. They are not substitutes for public client guides.

## Historical material

Superseded implementation plans and completed design investigations live under
[`historical/`](historical/). They are retained as engineering records and do
not define the current API or release process.
