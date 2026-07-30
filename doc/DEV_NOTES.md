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

## Store-and-forward durability

Rust and Java clients use the same disk-backed QWP/WebSocket slot format. The
records and segment headers must remain byte-compatible with Java's
`SfManifest`, `AckWatermark`, and SFA segments. Any format change must also
update `questdb-rs/src/tests/qwp_ws_java_golden.rs`.

`sf-manifest.bin` and `.ack-watermark` share the same dual-slot record format:

- Each file is 8192 bytes: two 4096-byte slots, with 64-byte little-endian
  records at offsets 0 and 4096.
- A record stores its magic (`SFM1` or `AKW1`) at byte 0, version 1 at byte 4,
  a positive signed 64-bit generation at byte 8, its payload from byte 16, and
  a CRC32C at byte 60 covering bytes `[0, 60)`.
- Generation parity selects the slot to write. Generation 1 goes to offset
  4096, leaving the first slot zeroed. Recovery uses the highest valid
  generation, so one intact record is enough after a torn update.
- The manifest stores the monotonic `(head_base, active_base)` segment
  boundary. The watermark stores the highest acknowledged frame sequence
  number; `-1` means no acknowledgement.

Manifested `.sfa` segments set `MANIFEST_REQUIRED` (bit `0x1` at header byte
5). Recovery rejects a flagged segment without a valid manifest.

Recovery migrates a legacy unflagged slot in place: it validates the segment
chain, creates the manifest, and stamps every surviving segment with
`MANIFEST_REQUIRED`. It resets the old 16-byte watermark because that format
has no CRC. The reset may replay acknowledged frames once, but cannot skip
unacknowledged frames. Migration is one-way; clients predating this format
cannot read the flagged segments and 8192-byte watermark. Drain or copy aside
the slot before downgrading.

Differences from Java:

- Rust writes the watermark with positional file I/O and `sync_data`; Java
  uses an mmap. When a recovered watermark is ahead of the segment chain, Rust
  repairs it on disk to the segment floor. Java clamps only the in-memory
  value.
- Rust uses four barriers per trimmed segment: watermark file sync,
  slot-directory sync, manifest sync, and post-unlink directory sync. Java
  batches trim barriers across up to 64 segments.
- Rust creates a slot in this order: durable watermark, durable unflagged
  segment, manifest, then `MANIFEST_REQUIRED` stamp. Java writes the manifest
  before the segments. A crash at any point in the Rust sequence recovers as
  either a legacy or manifested slot.
- If periodic close cannot sync live data, `SfaSlotQueue::close` reports the
  error and retains the flock. `Drop` retries once. If that retry also fails,
  field destruction releases the flock; Java retains the retired slot until
  process exit. This leaves a power-loss window until the next periodic-mode
  adopter completes its baseline sync.
- Periodic checkpoints use best-effort `mlock`/`munlock` on Unix. Windows skips
  page pinning and directory fsync, but still calls `FlushViewOfFile` for the
  mapping and `FlushFileBuffers` for the file handle.
- After a failed checkpoint, a rotation request waits
  `min(sf_sync_interval_millis, 1000)` before retrying. Java retries
  immediately. The Rust delay prevents a busy loop on a failing device.
