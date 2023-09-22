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

If you are editing the C functions in the `questdb-rs-ffi` project and what to
see the resulting generated header file, call `cargo build --features gen_h`.

Note that to reduce compile time we don't use cbindgen in the header we ship,
which also contains additional formatting and comments.

Similarly, we also support generating Cython bindings via the `gen_cython`
feature.

This generated files should be not be checked in:
* `include/questdb/ingress/line_sender.gen.h`
* `cython/questdb/ingress/line_sender.pxd`

## Updating version in the codebase before releasing

* Ensure you have `python3` and `bump2version` installed (`python3 -m pip install bump2version`).

```console
bump2version --config-file .bumpversion.cfg patch
```

Last argument argument:
  * `patch` would bump from (for example) `0.1.0` to `0.1.1`.
  * `minor` would bump from `0.1.0` to `0.2.0`.
  * `major` would bump from `0.1.0` to `1.0.0`.

* For more command line options, see: https://pypi.org/project/bump2version/

If you're editing the config file, a good set of arguments to debug issues is:

```
bump2version --dry-run --allow-dirty --verbose --config-file .bumpversion.cfg patch
```
