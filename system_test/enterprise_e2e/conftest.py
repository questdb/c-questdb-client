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

import os
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
    CClientRustColumnSidecar,
    CClientRustEgressSidecar,
    CClientRustSidecar,
    build_qwp_column_sidecar,
    build_qwp_egress_sidecar,
    build_qwp_sidecar,
)


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
