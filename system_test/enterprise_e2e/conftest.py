"""
Pytest root config for the c-questdb-client cross-repo Enterprise e2e
suite.

The Enterprise harness fixtures (``server_factory``, ``sidecar``,
``scenario_dir``, ``obj_store``, ``log_dir``, ``classpath``, plus the
``rep_call`` reporting hook) are reused by registering Enterprise's
``lib.shared_fixtures`` module as a pytest plugin. This requires
``questdb-ent/e2e`` to be on ``PYTHONPATH`` -- the cross-repo CI
pipeline sets that up, and locally the convention is a sibling
``questdb-enterprise`` checkout (resolved below via the
``QUESTDB_ENTERPRISE_E2E_DIR`` env var or the sibling-default).

Tests in this tree opt into a binding-specific fixture
(``c_client_rust_sidecar``, ``c_client_c_sidecar``, ...) defined below;
each one launches its respective ``qwp_sidecar`` binary built from the
sibling crates / C / C++ sources under ``system_test/``.
"""

from __future__ import annotations

import logging
import os
import shutil
import sys
from pathlib import Path
from typing import Iterator

import pytest

# Discover the Enterprise e2e dir so its `lib.shared_fixtures` plugin
# can be imported. The cross-repo pipeline sets QUESTDB_ENTERPRISE_E2E_DIR
# explicitly; locally we fall back to a sibling checkout convention.
_THIS_DIR = Path(__file__).resolve().parent
_C_CLIENT_REPO_ROOT = _THIS_DIR.parent.parent  # system_test/ → repo root


def _resolve_enterprise_e2e_dir() -> Path:
    env = os.environ.get("QUESTDB_ENTERPRISE_E2E_DIR")
    if env:
        path = Path(env).resolve()
        if not path.is_dir():
            raise RuntimeError(
                f"QUESTDB_ENTERPRISE_E2E_DIR={env!r} is not a directory"
            )
        return path
    # Local-dev sibling convention: <c-questdb-client>/.. holds
    # questdb-enterprise/, and its e2e harness sits at
    # questdb-ent/e2e/.
    sibling = (
        _C_CLIENT_REPO_ROOT.parent / "questdb-enterprise" / "questdb-ent" / "e2e"
    ).resolve()
    if not sibling.is_dir():
        raise RuntimeError(
            f"Enterprise e2e harness not found at {sibling}; set "
            "QUESTDB_ENTERPRISE_E2E_DIR to override"
        )
    return sibling


_ENT_E2E_DIR = _resolve_enterprise_e2e_dir()
if str(_ENT_E2E_DIR) not in sys.path:
    sys.path.insert(0, str(_ENT_E2E_DIR))

# Re-use every Enterprise harness fixture (server_factory, sidecar,
# scenario_dir, etc.) plus the rep_call hook. Same line that
# Enterprise's own conftest.py uses.
pytest_plugins = ("lib.shared_fixtures",)

# Imports below depend on the sys.path insert above.
from c_client_sidecar import (  # noqa: E402
    CClientCEgressSidecar,
    CClientCppEgressSidecar,
    CClientCppSidecar,
    CClientCSidecar,
    CClientRustColumnSidecar,
    CClientRustEgressSidecar,
    CClientRustSidecar,
    build_c_egress_sidecar,
    build_c_sidecar,
    build_cpp_egress_sidecar,
    build_cpp_sidecar,
    build_qwp_column_sidecar,
    build_qwp_egress_sidecar,
    build_qwp_sidecar,
)

LOG = logging.getLogger(__name__)


# --------------------------------------------------------------------
# Forked JVM temp files.
# --------------------------------------------------------------------
#
# Each forked Enterprise server JVM unpacks its native libraries
# (libquestdb, libquestdbr, libqdb_ent) into java.io.tmpdir and relies on
# File.deleteOnExit() to remove them. ForkedEntServer.kill_9() SIGKILLs
# the JVM, so every killed server leaves its copies behind, and
# libqdb_ent is large (a release build with debuginfo). A full run kills
# ~30 servers: on the CI agents, where /tmp is a 12 GiB tmpfs, the
# leftovers fill /tmp and the last tests fail with ENOSPC (replicas stop
# applying WAL, servers can't unpack libqdb_ent).
#
# So the forked JVMs get a session-private temp dir, via the harness's
# JAVA_OPTS_FORK knob, which is emptied after every test -- the cleanup
# SIGKILL skipped.

_FORK_OPTS_ENV = "JAVA_OPTS_FORK"
# ForkedEntServer's JVM options when JAVA_OPTS_FORK is unset
# (questdb-ent/e2e/lib/server.py); setting the variable replaces them.
_FORK_OPTS_DEFAULT = "-Xmx512m"
_TMPDIR_OPT = "-Djava.io.tmpdir="


@pytest.fixture(scope="session", autouse=True)
def _forked_jvm_tmpdir(
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[Path | None]:
    """The forked JVMs' ``java.io.tmpdir``, or None if it isn't ours to
    empty: JAVA_OPTS_FORK already sets one, or ours can't be passed."""
    fork_opts = os.environ.get(_FORK_OPTS_ENV)
    if fork_opts is not None and _TMPDIR_OPT in fork_opts:
        yield None
        return
    tmpdir = tmp_path_factory.mktemp("forked-jvm-tmp")
    if any(ch.isspace() for ch in str(tmpdir)):
        # The harness splits JAVA_OPTS_FORK on whitespace.
        LOG.warning("forked JVMs keep the default java.io.tmpdir: "
                    "%s contains whitespace", tmpdir)
        yield None
        return
    if fork_opts is None:
        fork_opts = _FORK_OPTS_DEFAULT
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv(_FORK_OPTS_ENV, f"{fork_opts} {_TMPDIR_OPT}{tmpdir}")
        yield tmpdir


@pytest.fixture(autouse=True)
def _empty_forked_jvm_tmpdir(_forked_jvm_tmpdir: Path | None) -> Iterator[None]:
    """Delete what the test's forked JVMs left in their temp dir. Autouse
    fixtures are set up first and torn down last, so ``server_factory``
    has already stopped every server the test started."""
    yield
    if _forked_jvm_tmpdir is None:
        return
    for leftover in _forked_jvm_tmpdir.iterdir():
        try:
            if leftover.is_dir() and not leftover.is_symlink():
                shutil.rmtree(leftover)
            else:
                leftover.unlink()
        except OSError as exc:
            LOG.warning("could not delete forked JVM temp file %s: %s",
                        leftover, exc)


# --------------------------------------------------------------------
# Binding-specific fixtures.
# --------------------------------------------------------------------

@pytest.fixture(scope="session")
def c_client_rust_sidecar_binary() -> Path:
    """One cargo build per session. Cargo no-ops when the target is
    already current."""
    return build_qwp_sidecar()


@pytest.fixture(scope="function")
def c_client_rust_sidecar(
    c_client_rust_sidecar_binary: Path, log_dir: Path
) -> Iterator[CClientRustSidecar]:
    """Sidecar driven by the c-questdb-client Rust binding's
    ``qwp_sidecar`` binary. Speaks the same QWP/WebSocket line protocol
    as Enterprise's Java sidecar, so tests can polymorphically take a
    ``Sidecar``-typed parameter."""
    s = CClientRustSidecar(
        log_dir=log_dir,
        classpath=None,
        name="c-client-rust-sidecar",
        binary_path=c_client_rust_sidecar_binary,
    )
    s.start()
    try:
        yield s
    finally:
        s.stop()


@pytest.fixture(scope="session")
def c_client_rust_column_sidecar_binary() -> Path:
    """One cargo build per session for the column-major sidecar."""
    return build_qwp_column_sidecar()


@pytest.fixture(scope="function")
def c_client_rust_column_sidecar(
    c_client_rust_column_sidecar_binary: Path, log_dir: Path
) -> Iterator[CClientRustColumnSidecar]:
    """Sidecar driven by the Rust binding's column-major
    ``qwp_column_sidecar`` binary. Speaks the same line protocol as
    :func:`c_client_rust_sidecar`, so tests take a ``Sidecar``-typed
    parameter polymorphically."""
    s = CClientRustColumnSidecar(
        log_dir=log_dir,
        classpath=None,
        name="c-client-rust-column-sidecar",
        binary_path=c_client_rust_column_sidecar_binary,
    )
    s.start()
    try:
        yield s
    finally:
        s.stop()


@pytest.fixture(scope="session")
def c_client_rust_egress_sidecar_binary() -> Path:
    """One cargo build per session for the egress (read-side) sidecar."""
    return build_qwp_egress_sidecar()


@pytest.fixture(scope="function")
def c_client_rust_egress_sidecar(
    c_client_rust_egress_sidecar_binary: Path, log_dir: Path
) -> Iterator[CClientRustEgressSidecar]:
    """Read-side sidecar driven by the Rust binding's ``qwp_egress_sidecar``
    binary (``questdb::egress::Reader``). Speaks the same line protocol as the
    Enterprise Java egress sidecar, so it reuses
    :class:`lib.egress_sidecar.EgressSidecar`'s verbs."""
    s = CClientRustEgressSidecar(
        log_dir=log_dir,
        classpath=None,
        name="c-client-rust-egress-sidecar",
        binary_path=c_client_rust_egress_sidecar_binary,
    )
    s.start()
    try:
        yield s
    finally:
        s.stop()


@pytest.fixture(scope="session")
def c_client_c_sidecar_binary() -> Path:
    """One C build per session (cargo build of the FFI lib + cc of the
    sidecar; both no-op when already current)."""
    return build_c_sidecar()


@pytest.fixture(scope="function")
def c_client_c_sidecar(
    c_client_c_sidecar_binary: Path, log_dir: Path
) -> Iterator[CClientCSidecar]:
    """Sidecar driven by the c-questdb-client **C** binding's ``qwp_c_sidecar``
    binary. Speaks the same QWP-WS line protocol as the Rust sidecar, so tests
    take a ``Sidecar``-typed parameter polymorphically."""
    s = CClientCSidecar(
        log_dir=log_dir,
        classpath=None,
        name="c-client-c-sidecar",
        binary_path=c_client_c_sidecar_binary,
    )
    s.start()
    try:
        yield s
    finally:
        s.stop()


@pytest.fixture(scope="session")
def c_client_c_egress_sidecar_binary() -> Path:
    """One C build per session for the egress (read-side) C sidecar."""
    return build_c_egress_sidecar()


@pytest.fixture(scope="function")
def c_client_c_egress_sidecar(
    c_client_c_egress_sidecar_binary: Path, log_dir: Path
) -> Iterator[CClientCEgressSidecar]:
    """Read-side sidecar driven by the **C** binding's ``qwp_egress_c_sidecar``
    binary (the ``qwp_reader_*`` C API). Its reduced sidecar protocol omits the
    zone token and leaves SHOW_ZONE / QUERY_ROW unsupported."""
    s = CClientCEgressSidecar(
        log_dir=log_dir,
        classpath=None,
        name="c-client-c-egress-sidecar",
        binary_path=c_client_c_egress_sidecar_binary,
    )
    s.start()
    try:
        yield s
    finally:
        s.stop()


@pytest.fixture(scope="session")
def c_client_cpp_egress_sidecar_binary() -> Path:
    """One C++ build per session for the egress (read-side) C++ sidecar."""
    return build_cpp_egress_sidecar()


@pytest.fixture(scope="function")
def c_client_cpp_egress_sidecar(
    c_client_cpp_egress_sidecar_binary: Path, log_dir: Path
) -> Iterator[CClientCppEgressSidecar]:
    """Read-side sidecar driven by the **C++** binding's
    ``qwp_egress_cpp_sidecar`` binary (the genuine ``questdb::egress``
    C++ wrapper classes)."""
    s = CClientCppEgressSidecar(
        log_dir=log_dir,
        classpath=None,
        name="c-client-cpp-egress-sidecar",
        binary_path=c_client_cpp_egress_sidecar_binary,
    )
    s.start()
    try:
        yield s
    finally:
        s.stop()


@pytest.fixture(scope="session")
def c_client_cpp_sidecar_binary() -> Path:
    """One C++ build per session (cargo build of the FFI lib + c++ of the
    sidecar; both no-op when already current)."""
    return build_cpp_sidecar()


@pytest.fixture(scope="function")
def c_client_cpp_sidecar(
    c_client_cpp_sidecar_binary: Path, log_dir: Path
) -> Iterator[CClientCppSidecar]:
    """Sidecar driven by the c-questdb-client **C++** binding's
    ``qwp_cpp_sidecar`` binary. Same QWP-WS line protocol as the others."""
    s = CClientCppSidecar(
        log_dir=log_dir,
        classpath=None,
        name="c-client-cpp-sidecar",
        binary_path=c_client_cpp_sidecar_binary,
    )
    s.start()
    try:
        yield s
    finally:
        s.stop()
