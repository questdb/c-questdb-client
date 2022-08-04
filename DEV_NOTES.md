# Developer notes

## JSON Tests
The library shares some test cases with other ILP clients.

These tests were added as so:

```
git subtree add --prefix questdb-rs/src/tests/interop https://github.com/questdb/questdb-client-test.git main --squash
```

These should be updated with:

```
git subtree pull --prefix questdb-rs/src/tests/interop https://github.com/questdb/questdb-client-test.git main --squash
```

## CMake Integration
We temporarily use a forked version of https://github.com/corrosion-rs/corrosion
to enable linking the Rust crate as C rather than C++.

The "corrosion" directory has been added as:

```
git subtree add --prefix corrosion https://github.com/amunra/corrosion master --squash
```

and is being maintained as:

```
git subtree pull --prefix corrosion https://github.com/amunra/corrosion master --squash
```

Until our outstanding pull request with the upstream project is resolved.
See: https://github.com/corrosion-rs/corrosion/pull/188.


## Building without CMake
For development, you may also call `cargo build` directly.
By default, this will not build the `C` FFI layer.

For that, call `cargo build --features ffi`.

If you are editing the C functions and what to see the resulting generated
header file, call `cargo build --features cbindgen`.

Note that to reduce compile time we don't use cbindgen in the header we ship.
