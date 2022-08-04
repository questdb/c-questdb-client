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
For development, you may also call `cargo build` (`cargo test` etc) directly in
either of the two Rust projects:
* [questdb-rs](../questdb-rs/) - Core library
* [questdb-rs-ffi](../questdb-rs-ffi/) - C bindings layer.

If you are editing the C functions in the `questdb-rs-ffi` project and what to
see the resulting generated header file, call `cargo build --features gen_h`.

Note that to reduce compile time we don't use cbindgen in the header we ship,
which also contains additional formatting and comments.

Similarly, we also support generating Cython bindings via the `gen_cython`
feature.

This generated files should be not be checked in:
* `include/questdb/ilp/line_sender.gen.h`
* `cython/questdb/ilp/line_sender.pxd`
