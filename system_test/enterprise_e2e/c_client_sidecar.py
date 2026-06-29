"""
c-questdb-client sender sidecar adapters.

Cross-repo bindings for the QWP/WebSocket sender sidecars built from
this repo (Rust today, with C / C++ siblings to follow). Every adapter
speaks the same line-oriented protocol as ``lib.sidecar.Sidecar`` (in
the Enterprise harness) -- READY on startup, then verb/reply lines
over stdin/stdout. The only thing each subclass overrides is the
launched process: a JVM for the Java sidecar (Enterprise side), a
cargo-built Rust binary for :class:`CClientRustSidecar`, and (later)
cmake-built C / C++ binaries for their siblings.

The Enterprise harness's :mod:`lib.sidecar` module is imported via
:envvar:`PYTHONPATH`; the cross-repo CI pipeline sets that path before
invoking pytest, and the local-dev conftest does the same via a
sibling-checkout fallback.

Binary discovery
----------------

The path to this c-questdb-client checkout is resolved by walking up
from this file's location. No env var is needed locally; CI builds the
binary at a known path under the checked-out repo.

Cargo profile
-------------

The default is ``debug`` -- fast incremental rebuilds during local
iteration. CI can opt into release with
``C_QUESTDB_CLIENT_PROFILE=release``. Either way, the harness invokes
``cargo build`` itself on first call (idempotent: cargo no-ops if the
target is already current) so tests don't depend on a pre-build step.
"""

from __future__ import annotations

import logging
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# lib.sidecar / lib.egress_sidecar come from the Enterprise e2e harness (PYTHONPATH).
from lib.egress_sidecar import EgressSidecar
from lib.sidecar import Sidecar

LOG = logging.getLogger(__name__)


def _resolve_client_root() -> Path:
    # __file__ → <repo>/system_test/enterprise_e2e/c_client_sidecar.py
    # parents[2] → <repo>
    return Path(__file__).resolve().parents[2]


def _build_failover_bin(bin_name: str, features: Optional[str] = None) -> Path:
    """Build (idempotently) a binary from the ``failover_clients`` crate and
    return its absolute path. Cargo no-ops when the target is already up to
    date, so this is cheap to call from a session fixture. ``features`` enables
    optional crate features (e.g. ``polars``)."""
    client_root = _resolve_client_root()
    manifest = client_root / "system_test" / "failover_clients" / "Cargo.toml"
    if not manifest.is_file():
        raise RuntimeError(f"failover_clients Cargo.toml not found at {manifest}")

    profile = os.environ.get("C_QUESTDB_CLIENT_PROFILE", "debug")
    cmd = [
        "cargo",
        "build",
        "--manifest-path",
        str(manifest),
        "--bin",
        bin_name,
    ]
    if features:
        cmd += ["--features", features]
    if profile == "release":
        cmd.insert(2, "--release")
    elif profile != "debug":
        raise RuntimeError(
            f"C_QUESTDB_CLIENT_PROFILE must be 'debug' or 'release', got {profile!r}"
        )

    LOG.info("building %s (%s profile)", bin_name, profile)
    # Inherit stderr so cargo's progress lines reach the developer's
    # terminal during local runs; stdout is captured because cargo emits
    # nothing useful there and CI logs are quieter without it.
    subprocess.run(cmd, check=True, stdout=subprocess.PIPE)

    binary = (
        client_root
        / "system_test"
        / "failover_clients"
        / "target"
        / profile
        / bin_name
    )
    if not binary.is_file():
        raise RuntimeError(
            f"cargo build succeeded but {binary} is missing; "
            "check the failover_clients crate manifest"
        )
    return binary


def build_qwp_sidecar() -> Path:
    """Build the row-major ``qwp_sidecar`` binary."""
    return _build_failover_bin("qwp_sidecar")


def build_qwp_column_sidecar() -> Path:
    """Build the column-major ``qwp_column_sidecar`` binary. With
    ``C_QUESTDB_CLIENT_COLUMN_POLARS`` set, enable the heavy ``polars`` feature
    so the ``SEND ... polars`` input shape is available; off by default to keep
    the e2e build light."""
    features = "polars" if os.environ.get("C_QUESTDB_CLIENT_COLUMN_POLARS") else None
    return _build_failover_bin("qwp_column_sidecar", features=features)


def build_qwp_egress_sidecar() -> Path:
    """Build the egress (read-side) ``qwp_egress_sidecar`` binary."""
    return _build_failover_bin("qwp_egress_sidecar")


def _build_native_sidecar(*, src_name: str, bin_name: str,
                          compiler_default: str, compiler_env: str,
                          std_flag: str) -> Path:
    """Build (idempotently) a C or C++ sidecar from ``system_test/c_sidecars``
    and return its absolute path.

    Two steps, both cheap to repeat from a session fixture:

      1. ``cargo build`` the ``questdb-rs-ffi`` crate so ``libquestdb_client``
         carries the *current* QWP-WS C ABI (the checked-in ``build/`` artifact
         can be stale -- e.g. the pre-rename ``..._await_acked_fsn`` symbol).
      2. Compile + link the one sidecar translation unit against that shared
         library, with an rpath so the binary finds it at run time.

    The compiler is ``compiler_default`` unless ``compiler_env`` (``CC`` /
    ``CXX``) overrides it. Honours ``C_QUESTDB_CLIENT_PROFILE`` like the cargo
    sidecars so a release CI run links the release library."""
    client_root = _resolve_client_root()
    profile = os.environ.get("C_QUESTDB_CLIENT_PROFILE", "debug")
    if profile not in ("debug", "release"):
        raise RuntimeError(
            f"C_QUESTDB_CLIENT_PROFILE must be 'debug' or 'release', got {profile!r}"
        )

    ffi_manifest = client_root / "questdb-rs-ffi" / "Cargo.toml"
    if not ffi_manifest.is_file():
        raise RuntimeError(f"questdb-rs-ffi Cargo.toml not found at {ffi_manifest}")
    cargo = ["cargo", "build", "--manifest-path", str(ffi_manifest)]
    if profile == "release":
        cargo.append("--release")
    LOG.info("building libquestdb_client (%s) for %s", profile, bin_name)
    subprocess.run(cargo, check=True, stdout=subprocess.PIPE)

    libdir = client_root / "questdb-rs-ffi" / "target" / profile
    if not (libdir / "libquestdb_client.so").is_file():
        raise RuntimeError(f"libquestdb_client.so missing in {libdir} after cargo build")

    src = client_root / "system_test" / "c_sidecars" / src_name
    if not src.is_file():
        raise RuntimeError(f"sidecar source not found at {src}")
    out_dir = client_root / "system_test" / "c_sidecars" / "target" / profile
    out_dir.mkdir(parents=True, exist_ok=True)
    binary = out_dir / bin_name

    compiler = os.environ.get(compiler_env, compiler_default)
    cmd = [
        compiler, std_flag, "-O2", "-Wall",
        "-I", str(client_root / "include"),
        "-o", str(binary), str(src),
        "-L", str(libdir), "-lquestdb_client",
        f"-Wl,-rpath,{libdir}",
        "-lpthread", "-ldl", "-lm",
    ]
    LOG.info("compiling %s: %s", bin_name, " ".join(cmd))
    subprocess.run(cmd, check=True)
    if not binary.is_file():
        raise RuntimeError(f"{compiler} succeeded but {binary} is missing")
    return binary


def build_c_sidecar() -> Path:
    """Build the C-binding ``qwp_c_sidecar`` (row-major QWP-WS via the C FFI)."""
    return _build_native_sidecar(
        src_name="qwp_c_sidecar.c", bin_name="qwp_c_sidecar",
        compiler_default="cc", compiler_env="CC", std_flag="-std=c11")


def build_cpp_sidecar() -> Path:
    """Build the C++-binding ``qwp_cpp_sidecar``. The c-questdb-client C++
    wrapper has no row-major QWP-WS surface (``line_sender::new_buffer()``
    rejects WebSocket senders -- WS is column-major in C++), so this C++
    translation unit drives the row-major store-and-forward path via the C ABI
    while still compiling + linking the C++ header. That is the c_client_cpp
    signal: row-major QWP-WS works from a C++ binary."""
    return _build_native_sidecar(
        src_name="qwp_cpp_sidecar.cpp", bin_name="qwp_cpp_sidecar",
        compiler_default="c++", compiler_env="CXX", std_flag="-std=c++17")


@dataclass
class CClientRustSidecar(Sidecar):
    """c-questdb-client Rust-binding sender sidecar. Inherits every
    protocol verb from :class:`Sidecar`; only the launch step differs.

    Sister classes for the C and C++ bindings will sit alongside once
    those FFI-driven sidecars exist; they all share this file because
    they all live in the same source repo."""

    binary_path: Optional[Path] = field(default=None)

    def _default_binary(self) -> Path:
        """Binary built when no explicit ``binary_path`` is supplied.
        Subclasses override to launch a different ``failover_clients`` bin."""
        return build_qwp_sidecar()

    def start(self, *, ready_timeout: float = 30.0) -> None:
        if self.process is not None:
            raise RuntimeError(f"sidecar {self.name!r} already started")
        binary = self.binary_path or self._default_binary()
        cmd = [str(binary)]

        self.log_dir.mkdir(parents=True, exist_ok=True)
        stderr_log = open(self.log_dir / f"{self.name}.stderr.log", "w", encoding="utf-8")

        LOG.info("starting c-questdb-client (rust) sidecar %s (%s)", self.name, binary)
        self.process = subprocess.Popen(
            cmd,
            env=os.environ.copy(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )

        from lib.server import _drain  # noqa: PLC0415 - shared helper, avoids a public reshuffle
        self._stderr_thread = _drain(
            self.process.stderr, stderr_log, f"{self.name}-stderr"
        )

        # Identical READY wait as the Java sidecar -- the protocol
        # mandates READY before any command, so the loop logic is
        # binding-agnostic.
        deadline = time.monotonic() + ready_timeout
        while True:
            if self.process.poll() is not None:
                raise RuntimeError(
                    f"sidecar {self.name!r} exited prematurely (code "
                    f"{self.process.returncode}); see "
                    f"{self.log_dir / f'{self.name}.stderr.log'}"
                )
            if time.monotonic() > deadline:
                raise TimeoutError(
                    f"sidecar {self.name!r} did not READY within {ready_timeout}s"
                )
            line = self._readline(self.process.stdout, 0.2)
            if line is None:
                continue
            line = line.strip()
            if line == "READY":
                break
            LOG.warning("sidecar %s pre-READY: %r", self.name, line)


@dataclass
class CClientRustColumnSidecar(CClientRustSidecar):
    """c-questdb-client Rust-binding column-major sender sidecar.

    Drives the ``QuestDb`` -> ``ColumnSender`` (column-major QWP/WebSocket)
    path via the ``qwp_column_sidecar`` binary. Speaks the same line protocol
    as :class:`CClientRustSidecar`, so the harness's CONNECT/SEND/FLUSH/CLOSE
    verbs work unchanged and tests can take a ``Sidecar``-typed parameter."""

    def _default_binary(self) -> Path:
        return build_qwp_column_sidecar()

    def send(self, table: str, count: int, start_index: int = 0,
             src: str = "chunk") -> None:
        """Column-major SEND with an explicit input shape. ``src`` is one of:
        ``chunk`` (default; a borrowed-slice ``Chunk``) or ``arrow`` (an Arrow
        ``RecordBatch``) -- both go through the store-and-forward column sender;
        or ``arrow_db`` -- the direct ``Db::flush_arrow_batch`` facade (no
        store-and-forward; surfaces FailoverRetry to the caller). The sidecar
        builds the matching column-major frame at FLUSH."""
        self._send(f"SEND {table} {count} {start_index} {src}")
        self._expect_ok()


@dataclass
class CClientRustEgressSidecar(EgressSidecar):
    """c-questdb-client Rust-binding egress (read-side) sidecar. Drives
    ``questdb::egress::Reader`` via the ``qwp_egress_sidecar`` binary, speaking
    the same line protocol as the Java ``QwpEgressSidecarMain`` -- so
    :class:`lib.egress_sidecar.EgressSidecar`'s CONNECT/QUERY/SHOW_ZONE/
    SERVER_INFO/CLOSE verbs work unchanged; only the launched process differs."""

    binary_path: Optional[Path] = field(default=None)

    def start(self, *, ready_timeout: float = 30.0) -> None:
        if self.process is not None:
            raise RuntimeError(f"egress sidecar {self.name!r} already started")
        binary = self.binary_path or build_qwp_egress_sidecar()
        cmd = [str(binary)]

        self.log_dir.mkdir(parents=True, exist_ok=True)
        stderr_log = open(self.log_dir / f"{self.name}.stderr.log", "w", encoding="utf-8")

        LOG.info("starting c-questdb-client (rust) egress sidecar %s (%s)", self.name, binary)
        self.process = subprocess.Popen(
            cmd,
            env=os.environ.copy(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )

        from lib.server import _drain  # noqa: PLC0415 - shared helper
        self._stderr_thread = _drain(
            self.process.stderr, stderr_log, f"{self.name}-stderr"
        )

        deadline = time.monotonic() + ready_timeout
        while True:
            if self.process.poll() is not None:
                raise RuntimeError(
                    f"egress sidecar {self.name!r} exited prematurely (code "
                    f"{self.process.returncode}); see "
                    f"{self.log_dir / f'{self.name}.stderr.log'}"
                )
            if time.monotonic() > deadline:
                raise TimeoutError(
                    f"egress sidecar {self.name!r} did not READY within {ready_timeout}s"
                )
            line = self._readline(self.process.stdout, 0.2)
            if line is None:
                continue
            line = line.strip()
            if line == "READY":
                break
            LOG.warning("egress sidecar %s pre-READY: %r", self.name, line)


@dataclass
class CClientCSidecar(CClientRustSidecar):
    """c-questdb-client **C-binding** sender sidecar.

    Drives the row-major QWP-WS store-and-forward path through the C FFI
    (``qwp_c_sidecar``: ``line_sender_from_conf`` + ``line_sender_qwpws_*``).
    Speaks the same line protocol as every other sidecar, so it reuses
    :class:`lib.sidecar.Sidecar`'s CONNECT/SEND/FLUSH/AWAIT_ACKED/CLOSE verbs
    and the inherited :meth:`CClientRustSidecar.start` launch; only the built
    binary differs."""

    def _default_binary(self) -> Path:
        return build_c_sidecar()


@dataclass
class CClientCppSidecar(CClientRustSidecar):
    """c-questdb-client **C++-binding** sender sidecar (``qwp_cpp_sidecar``).

    The C++ wrapper has no row-major QWP-WS API (``line_sender::new_buffer()``
    throws for WebSocket senders; WS is column-major in C++), so this C++
    translation unit includes the C++ header (proving it compiles + links under
    C++17) and drives the row-major store-and-forward path via the C ABI -- the
    same path a real C++ user takes for row-major WS. Same line protocol as the
    other sidecars."""

    def _default_binary(self) -> Path:
        return build_cpp_sidecar()
