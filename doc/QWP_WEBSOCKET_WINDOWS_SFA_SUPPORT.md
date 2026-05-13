# QWP/WebSocket Windows SFA Support Design

Date: 2026-05-13

Status: reviewed design handoff. No implementation is included in this
document.

## Purpose

Enable QWP/WebSocket Store-and-Forward (`sf_dir`) on Windows without changing
the SFA file format or the Java-compatible slot contract.

The immediate gap is slot locking. Rust currently opens disk-backed SFA slots
only on Unix because `SlotLock::lock_file` uses `flock`; non-Unix returns
`SlotLockUnsupported`. The Java reference and the `sf-client.md` spec require
Windows clients to use `LockFileEx` on `<sf_dir>/<sender_id>/.lock`.

## Source Of Truth

- `../questdb-arrays/docs/qwp/sf-client.md`:
  - `.lock` is held for the engine lifetime.
  - POSIX clients use `flock`/`fcntl`.
  - Windows clients use `LockFileEx`.
  - a second engine on the same slot must fail at acquire time.
  - `.lock.pid` is a sibling diagnostic file because Windows locks make the
    lock file itself unreadable to the second opener.
- `../questdb-arrays/java-questdb-client/.../SlotLock.java`:
  - creates/opens `<slot>/.lock`;
  - calls `Files.lock(fd)`;
  - writes `<slot>/.lock.pid` after successful lock acquisition;
  - treats lock failure as slot contention and reports the holder PID.
- `../questdb-arrays/java-questdb-client/core/src/main/c/windows/files.c`:
  - implements `Files.lock` with `LockFileEx` using exclusive,
    fail-immediately flags.

## Current Rust State

Relevant files:

- `questdb-rs/src/ingress/sender/qwp_ws_sfa_slot.rs`
- `questdb-rs/src/ingress/sender/qwp_ws_sfa_segment.rs`
- `questdb-rs/src/ingress/sender/qwp_ws_sfa_queue.rs`

Current slot ownership:

- `SfaSlotQueue::open` validates `sf_dir` and `sender_id`, creates
  `<sf_dir>/<sender_id>`, acquires `SlotLock`, then opens the SFA queue.
- Unix `SlotLock::lock_file` opens `.lock`, calls `libc::flock` with
  `LOCK_EX | LOCK_NB`, writes `.lock.pid`, and keeps the `File` alive.
- `#[cfg(not(unix))] SlotLock::lock_file` returns
  `SfaQueueError::SlotLockUnsupported`.
- Several lock behavior tests are currently Unix-only because the implementation
  is Unix-only.

Current segment storage:

- `.sfa` segments are backed by `memmap2::MmapMut`.
- `memmap2` has a Windows implementation using `CreateFileMappingW` and
  `MapViewOfFile`.
- Rust creates a segment by opening the file, calling `set_len(size_bytes)`, and
  mapping it. Java models this step as `Files.allocate`; on Windows the current
  Java native implementation extends the file to EOF. Treat that as a known
  spec/reference portability tension, not as proof that `set_len` satisfies the
  stronger `sf-client.md` block-reservation invariant.

## Goals

- Make disk-backed QWP/WebSocket SFA slots usable on Windows.
- Preserve the on-disk slot layout:
  - `<sf_dir>/<sender_id>/.lock`
  - `<sf_dir>/<sender_id>/.lock.pid`
  - `sf-<gen>.sfa` segment files
- Preserve Java-compatible contention behavior:
  - second opener fails before any segment recovery or mutation;
  - failure reports `SfaQueueError::SlotInUse`;
  - holder text is read from `.lock.pid`, or `unknown` if absent/unreadable.
- Keep the lock held by owning the lock file handle for the `SlotLock` lifetime.
- Keep `SlotLockUnsupported` for platforms that are neither Unix nor Windows.
- Keep Windows cleanup simple by avoiding long-lived mapped payload handles on
  Windows replay reads.

## Chosen Scope

The first implementation slice should enable Windows slot locking, return owned
payloads for Windows SFA replay reads, and run the existing SFA segment/queue
tests on Windows.

Keep Unix replay reads zero-copy via `SfaMappedPayload`. On Windows, convert the
mapped bytes to `PendingPayload::Owned` before returning a payload from the SFA
queue. That preserves the existing `PendingPayload` abstraction and avoids a
delete-later queue for segments whose mapping is still held by an outbound
frame.

## Non-Goals

- Do not change the `.sfa` segment format.
- Do not introduce a non-mmap segment implementation.
- Do not implement `sf_durability=flush` or `sf_durability=append`.
- Do not solve the stronger preallocation invariant from `sf-client.md`.
  This design makes slot locking Java-compatible on Windows; Rust still remains
  weaker than the spec until segment creation has an explicit allocation path.
  Java Windows currently implements `Files.allocate` via EOF extension, so keep
  Windows preallocation as a known spec/reference follow-up instead of relaxing
  the spec.
- Do not add orphan draining or `.failed` sentinel behavior.
- Do not change reconnect, retry, close-drain, or ACK semantics.
- Do not attempt cross-OS slot sharing on network filesystems. The spec requires
  POSIX and Windows clients to refuse to share a slot on such filesystems.

## Design

### 1. Make `SlotLock` Own A File On All Supported Platforms

Change `SlotLock` from Unix-only file ownership to platform-neutral ownership:

```rust
struct SlotLock {
    slot_dir: PathBuf,
    file: File,
}
```

`File` should be imported unconditionally. Closing the file releases the lock on
both Unix and Windows, matching the spec and Java behavior. No explicit unlock
call is needed in the normal path.

On Windows, opening `.lock` must preserve Java's contention shape: the second
process should be able to open the file, then fail at `LockFileEx`. Use
Windows-specific open options with read/write/delete sharing, matching Java's
`openRW`, rather than relying on an opener that could fail before the lock call.

### 2. Use One `SlotLock::lock_file` Flow

Use one common lock acquisition flow, with only the file open and OS lock call
behind cfg-specific helpers:

```rust
let lock_path = slot_dir.join(LOCK_FILE_NAME);
let pid_path = slot_dir.join(LOCK_PID_FILE_NAME);
let file = open_lock_file(&lock_path)?;
if !try_lock_file(&file) {
    let holder = read_lock_holder(&pid_path);
    return Err(SfaQueueError::SlotInUse { slot_dir, holder });
}
write_pid(&pid_path);
Ok(Self { slot_dir, file })
```

This keeps `SlotInUse` mapping identical across Unix and Windows: open failures
remain `Io`, while lock-call failures after a successful open are contention.
Do not add a new public lock abstraction for this slice.

### 3. Add Platform Lock Helpers

Unix helpers keep the current behavior:

```rust
#[cfg(unix)]
fn open_lock_file(lock_path: &Path) -> Result<File, io::Error> {
    OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(lock_path)
}

#[cfg(unix)]
fn try_lock_file(file: &File) -> bool {
    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0
}
```

Windows helpers mirror Java:

1. Open `<slot_dir>/.lock` with read/write/create/truncate(false) and
   Java-compatible sharing:
   `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`.
2. Call `LockFileEx` with:
   - `LOCKFILE_EXCLUSIVE_LOCK`
   - `LOCKFILE_FAIL_IMMEDIATELY`
   - offset `0`
   - length `u32::MAX, u32::MAX`
   - zeroed `OVERLAPPED`

Do not special-case individual Windows errors in the first slice. The common
flow treats any `LockFileEx` failure after open as `SlotInUse`, matching Java's
`Files.lock(fd) != 0` behavior and Rust's current Unix path.

Implementation shape:

```rust
#[cfg(windows)]
use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};

#[cfg(windows)]
use windows_sys::Win32::Foundation::HANDLE;
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, LOCKFILE_EXCLUSIVE_LOCK,
    LOCKFILE_FAIL_IMMEDIATELY, LockFileEx,
};
#[cfg(windows)]
use windows_sys::Win32::System::IO::OVERLAPPED;
```

Open the file with explicit sharing:

```rust
let file = OpenOptions::new()
    .read(true)
    .write(true)
    .create(true)
    .truncate(false)
    .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
    .open(&lock_path)?;
```

The lock call should cast `file.as_raw_handle()` to `HANDLE`, pass a zeroed
`OVERLAPPED`, and lock the full byte range with `u32::MAX, u32::MAX`, matching
Java's `MAXDWORD, MAXDWORD`.

Implementation dependency:

- Replace the current Windows-only `winapi` dependency with `windows-sys`. The
  existing `winapi` usage is only `AF_INET`, `SOCK_DGRAM`, and `SOCK_STREAM` in
  `gai.rs`; import those from
  `windows_sys::Win32::Networking::WinSock` instead of carrying both Windows FFI
  crates.

```toml
[target.'cfg(windows)'.dependencies]
windows-sys = { version = "0.60", features = [
    "Win32_Foundation",
    "Win32_Networking_WinSock",
    "Win32_Storage_FileSystem",
    "Win32_System_IO",
] }
```

### 4. Make PID Helpers Platform-Neutral

`read_lock_holder` is already platform-neutral. `write_pid` should lose its
Unix-only cfg so both Unix and Windows write the same `.lock.pid` payload:

```rust
fn write_pid(pid_path: &Path) {
    let payload = format!("{}\n", std::process::id());
    let _ = fs::write(pid_path, payload);
}
```

The write remains best effort. A stale or missing `.lock.pid` is allowed by the
spec and produces `holder=unknown`.

### 5. Return Owned Replay Payloads On Windows

Keep Unix replay reads as mapped payloads. On Windows, convert mapped SFA bytes
to an owned payload before returning them from the queue:

```rust
#[cfg(unix)]
return Some(PendingPayload::sfa_mapped(payload));

#[cfg(windows)]
{
    let owned = payload.with_bytes(|bytes| Arc::<[u8]>::from(bytes));
    return Some(PendingPayload::owned(owned));
}
```

Apply this at the SFA queue boundary where `SfaMappedPayload` currently becomes
`PendingPayload`. Do not add a delete-later list, tombstone state, or a
Windows-only cleanup scheduler.

This keeps the existing public queue shape: callers still hold a
`PendingPayload`, but Windows payloads do not keep the mapped segment alive
after trim.

### 6. Keep Unsupported Fallback For Other Platforms

After adding Unix and Windows implementations, keep:

```rust
#[cfg(not(any(unix, windows)))]
fn lock_file(slot_dir: PathBuf) -> Result<Self, SfaQueueError> {
    let _ = slot_dir;
    Err(SfaQueueError::SlotLockUnsupported)
}
```

This preserves an explicit failure mode for unsupported targets.

## Mmap And File Lifecycle Considerations

Windows slot locking is the blocker; mmap itself is not the primary design gap.

The current Rust segment layer already uses `memmap2`, and `memmap2` maps files
on Windows with `CreateFileMappingW` and `MapViewOfFile`. The design should not
replace this with a custom mmap abstraction.

Important lifecycle rules to validate on Windows:

- Cleanup must not silently assume POSIX unlink semantics. The current
  `SfaStorageCleanup::perform` drops its owned segment before `remove_file`; on
  Windows, returned replay payloads must be owned so they do not keep an
  additional mapping alive after trim.
- Quarantine rename is best effort. The current queue removes a stale
  `.corrupt` target before `rename`, which is already the right Windows shape.
- Closing a `SlotLock` must close the `.lock` file handle after all segment
  cleanup has had a chance to run. `SfaSlotQueue::close` currently closes the
  queue first and drops the lock second; keep that order.
- `MmapMut::flush()` is not part of this slice because `sf_durability=flush` and
  `append` are not enabled. When those durability modes are designed, Windows
  flush semantics must be checked separately.

Preallocation caveat:

- `sf-client.md` requires real block reservation as a create-path invariant.
- Rust currently uses `File::set_len`, which may create sparse files on some
  filesystems.
- Java's Windows reference uses `SetEndOfFile`, so enabling Windows slot
  locking keeps Rust aligned with the current Java Windows reference, but it
  does not make either path fully satisfy the stronger spec text.
- A later preallocation slice can compare `posix_fallocate`, macOS
  `F_PREALLOCATE`, Windows allocation behavior, and `memmap2` error surfaces.

## Test Plan

Run existing slot tests on Windows by changing Unix-only cfgs to
`#[cfg(any(unix, windows))]`. Do not remove cfgs wholesale; unsupported
platforms should still exercise `SlotLockUnsupported`.

- `open_creates_slot_layout_and_lock_file`
- `replay_only_existing_open_does_not_create_missing_slot`
- `second_open_on_same_slot_fails_fast_before_interleaving_segments`
- `distinct_sender_ids_are_independent_slots`
- `close_releases_lock_but_leaves_lock_file_for_reuse`

Add or keep coverage for:

- `.lock.pid` exists after successful open on Windows.
- second open reports `SlotInUse` and includes the PID text written by the first
  holder.
- closing the first queue releases the Windows lock and allows a second open.
- distinct `sender_id` values can be opened concurrently under the same
  `sf_dir`.
- `open_replay_only_existing` does not create missing slot directories.
- a subprocess holder case: parent acquires the lock, child reports `SlotInUse`
  with the parent's PID text, then a fresh child can acquire after the parent
  holder exits. This validates kernel cleanup on process exit, not only
  same-process drops.
- `drained_trim_keeps_existing_mapped_payload_alive` or an equivalent Windows
  queue test. On Windows, the payload should remain readable because it is owned,
  and the retired segment file should be removable immediately.

Run on Linux/macOS:

```bash
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws_sfa_slot --features sync-sender-qwp-ws --lib
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws_sfa_segment --features sync-sender-qwp-ws --lib
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws_sfa_queue --features sync-sender-qwp-ws --lib
```

Run on Windows CI:

```bash
cargo check --target x86_64-pc-windows-msvc --manifest-path questdb-rs/Cargo.toml --features sync-sender-qwp-ws --lib
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws_sfa_slot --features sync-sender-qwp-ws --lib
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws_sfa_segment --features sync-sender-qwp-ws --lib
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws_sfa_queue --features sync-sender-qwp-ws --lib
```

Run the Java/Rust segment interop test on at least one Windows validation job
after building the Java client classes:

```bash
QDB_JAVA_CLIENT_CORE=/path/to/java-questdb-client/core \
  cargo test --manifest-path questdb-rs/Cargo.toml java_and_rust_read_each_others_segments --features sync-sender-qwp-ws --lib -- --ignored --exact
```

If the focused Windows runs pass, broaden to:

```bash
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws --features sync-sender-qwp-ws --lib
```

## Rollout

1. Replace `winapi` with `windows-sys` for Windows constants and locking.
2. Add the Windows lock helpers and platform-neutral PID helper.
3. Return owned SFA replay payloads on Windows.
4. Enable slot-lock tests on Windows.
5. Run focused SFA tests locally on Unix.
6. Push and validate focused SFA tests on Windows CI, including the owned
   payload cleanup case.
7. Only after Windows CI passes, consider enabling broader QWP/WebSocket
   Windows coverage that currently avoids `sf_dir`.

## Open Questions

- Should non-contention `LockFileEx` failures stay mapped to `SlotInUse` for
  exact Java/current-Rust parity, or should Rust split impossible/permission
  failures into `Io` after the first parity slice?
- Should `SlotLockUnsupported` remain as a public-ish internal variant once the
  only tier-1 unsupported targets are gone?
- Should preallocation become the next storage-hardening slice after Windows
  locking, or wait until `sf_durability=flush` / `append` is designed? This
  should be answered against the spec text, not by assuming Java Windows EOF
  extension is the final contract.
