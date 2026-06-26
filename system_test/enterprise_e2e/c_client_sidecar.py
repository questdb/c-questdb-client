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

# lib.sidecar comes from the Enterprise e2e harness (PYTHONPATH).
from lib.sidecar import Sidecar

LOG = logging.getLogger(__name__)


def _resolve_client_root() -> Path:
    # __file__ → <repo>/system_test/enterprise_e2e/c_client_sidecar.py
    # parents[2] → <repo>
    return Path(__file__).resolve().parents[2]


def _build_failover_bin(bin_name: str) -> Path:
    """Build (idempotently) a binary from the ``failover_clients`` crate and
    return its absolute path. Cargo no-ops when the target is already up to
    date, so this is cheap to call from a session fixture."""
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
    """Build the column-major ``qwp_column_sidecar`` binary."""
    return _build_failover_bin("qwp_column_sidecar")


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
        """Column-major SEND with an explicit input shape. ``src`` is ``chunk``
        (default; a borrowed-slice ``Chunk``) or ``arrow`` (an Arrow
        ``RecordBatch``); the sidecar builds the matching column-major frame at
        FLUSH. Both encode to the same QWP/WebSocket columnar wire."""
        self._send(f"SEND {table} {count} {start_index} {src}")
        self._expect_ok()
