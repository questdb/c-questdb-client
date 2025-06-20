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
We use the [Corrosion](https://corrosion-rs.github.io/corrosion/) CMake library to compile Rust
from C and C++ projects.

The "corrosion" directory has been added as:

```
git subtree add --prefix corrosion https://github.com/corrosion-rs/corrosion v0.4.3 --squash
```

and is being maintained as:

```
git subtree pull --prefix corrosion https://github.com/corrosion-rs/corrosion NEXT_VERSION --squash
```


## Building without CMake
For development, you may also call `cargo build` (`cargo test` etc) directly in
either of the two Rust projects:
* [questdb-rs](../questdb-rs/) - Core library
* [questdb-rs-ffi](../questdb-rs-ffi/) - C bindings layer.

Note that to reduce compile time we don't use cbindgen in the header we ship,
which also contains additional formatting and comments.

This generated files should be not be checked in:
* `include/questdb/ingress/line_sender.gen.h`
* `cython/questdb/ingress/line_sender.pxd`
