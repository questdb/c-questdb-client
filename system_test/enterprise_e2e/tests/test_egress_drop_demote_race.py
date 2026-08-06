"""
WAL DROP driven through the QWP egress channel racing a P->R demote.

Ported from the Enterprise Java JUnit witness
``questdb-ent/src/test/java/com/questdb/lifecycle/QwpEgressDropDemoteRaceTest.java``
(``testQwpEgressDropTableDuringDemoteReplicatesOrRefuses``).

Why this channel matters: the QWP egress path (a WebSocket upgrade on the
HTTP server) compiles client SQL and executes a non-SELECT directly,
never consulting ``ReadOnlyStatementGate`` -- that gate is armed only by
pg-wire and HTTP /exec. A WAL DROP over QWP egress reaches the engine's
WAL drop branch with no role-switch lock and no read-only re-check, so
the only barrier on this channel is the engine-level DROP fence. The
invariant under a concurrent demote is **replicate-or-refuse**: the DROP
either completes as PRIMARY (table absent on BOTH nodes) or is refused
(table present on BOTH nodes) -- never the destructive divergence where
the demoting node drops locally but the closing uploader strands the
drop (gone on A, still present on B).

Determinism adaptation: the JUnit original pauses the DROP at its
externalization point (engine mint-site observer) and the demote cascade
at step 3 (switch-step injector) to force the exact interleaving. Those
are in-JVM hooks; forked servers offer neither. This port overlaps the
two operations wall-clock instead -- submit the SQL demote (async
cascade), fire the DROP through the Rust egress client mid-cascade --
and asserts the SAME terminal invariant. Whichever way the race lands,
agreement between A and B is what the fence guarantees; a fence
regression shows up as sustained disagreement, which the settle-poll
below converts into a hard failure. (The engine-fence unit-level
interleaving stays covered by the JUnit test on the Enterprise side;
this port keeps the *client-channel* axis honest end-to-end.)

The Rust ``Reader`` executes DDL through the same wire path the Java
``QwpQueryClient.execute`` uses: a refused DROP surfaces as a per-query
``QUERY_ERROR`` frame carrying the read-only message (sidecar reply
``ERR ...``); an acked DROP surfaces as ``EXEC_DONE``
(``Terminal::ExecDone`` -- reader.rs) and an ``OK 0 <ms> ...`` reply.
``failover=off`` pins the single-endpoint semantics of the original
(``newPlainText``): the client must NOT retry the refused DROP against
another node, which could otherwise execute it twice.
"""

from __future__ import annotations

import logging
import time

import psycopg
import pytest

from lib.pg_query import execute_ddl
from lib.sidecar import SidecarError

from c_client_sidecar import CClientRustEgressSidecar
from tests.qwp_sql_switch import (
    await_role_quiet,
    submit_switch_sql,
    wait_count_at_least,
)

LOG = logging.getLogger(__name__)

TABLE = "qwp_dt"
SETTLE_S = 30.0


def _table_exists(pg_port: int, table: str) -> bool:
    """``tables()`` catalog check over pg-wire -- works on PRIMARY and
    (read-only) REPLICA alike, so it stays valid after the demote."""
    with psycopg.connect(
        host="127.0.0.1", port=pg_port, user="admin", password="quest",
        dbname="qdb", connect_timeout=10, autocommit=True,
    ) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT count(*) FROM tables() WHERE table_name = %s", (table,)
            )
            row = cur.fetchone()
            return row is not None and int(row[0]) > 0


@pytest.mark.c_client
@pytest.mark.c_client_rust
def test_qwp_egress_drop_table_during_demote_replicates_or_refuses_c_client_rust(
    server_factory,
    c_client_rust_egress_sidecar: CClientRustEgressSidecar,
) -> None:
    """See module docstring. Terminal oracle: A and B AGREE on the
    table's existence after both the demote cascade and the drop's
    replication settle; a per-query error, when one surfaces with a
    message, must be the read-only refusal (not some unrelated SQL
    failure that would mask a fence bug)."""
    p1 = server_factory("p1", role="primary")
    p1_ports = p1.start(min_http=True)
    r1 = server_factory("r1", role="replica")
    r1_ports = r1.start()

    execute_ddl(
        port=p1_ports.pg,
        ddl=f"CREATE TABLE {TABLE} (ts TIMESTAMP, val INT) "
            "TIMESTAMP(ts) PARTITION BY DAY WAL",
    )
    execute_ddl(
        port=p1_ports.pg,
        ddl=f"INSERT INTO {TABLE} VALUES "
            "(to_timestamp('2026-06-14T00:00:00', 'yyyy-MM-ddTHH:mm:ss'), 1),"
            "(to_timestamp('2026-06-14T01:00:00', 'yyyy-MM-ddTHH:mm:ss'), 2)",
    )
    wait_count_at_least(r1_ports.pg, TABLE, 2, timeout_s=60.0)

    # Bind the egress client to node A only, no failover: the DROP's
    # fate must be decided by A's engine fence, not by a client-side
    # retry against another node.
    c_client_rust_egress_sidecar.connect(
        f"ws::addr=127.0.0.1:{p1_ports.http};target=any;failover=off;"
        "username=admin;password=quest;"
        "failover_max_duration_ms=15000;auth_timeout_ms=5000;"
    )

    # Race: submit the demote (returns on the accepted row; the cascade
    # settles asynchronously), then immediately drive the DROP through
    # the QWP egress channel so it lands inside the cascade window.
    accepted = submit_switch_sql(p1_ports.pg, "replica")
    assert accepted, "SWITCH ROLE TO REPLICA must be accepted on a live primary"

    drop_error: str | None = None
    try:
        c_client_rust_egress_sidecar._send(f"QUERY DROP TABLE {TABLE}")
        c_client_rust_egress_sidecar._expect_ok()
    except SidecarError as e:
        drop_error = str(e)

    # Let the demote cascade settle before judging the outcome; the
    # invariant is about terminal state, not the mid-cascade view.
    assert p1_ports.min_http is not None
    assert await_role_quiet(p1_ports.min_http, "replica", SETTLE_S), \
        "node A must settle REPLICA after the accepted demote"

    # A refusal, when it surfaces as a per-query error frame, must be
    # the read-only refusal. Transport-flavored errors (the demote can
    # tear the WebSocket down under the in-flight execute) don't drive
    # the classification -- as in the JUnit original, only the A/B
    # agreement does. But an unrelated SQL error (e.g. "table does not
    # exist") would mean the race harness itself is broken -- fail loud.
    if drop_error is not None:
        LOG.info("QWP egress DROP surfaced an error during demote: %s", drop_error)
        assert "does not exist" not in drop_error.lower(), (
            "the DROP must not fail with a missing-table error -- that "
            f"indicates a broken setup, not a fence outcome: {drop_error}"
        )

    # Replicate-or-refuse: poll until A and B agree on the table's
    # existence. On a fence regression the drop mints on the demoting
    # node but strands on the peer (gone on A, present on B) and this
    # poll never converges.
    deadline = time.monotonic() + SETTLE_S
    present_a = _table_exists(p1_ports.pg, TABLE)
    present_b = _table_exists(r1_ports.pg, TABLE)
    while present_a != present_b and time.monotonic() < deadline:
        time.sleep(0.2)
        present_a = _table_exists(p1_ports.pg, TABLE)
        present_b = _table_exists(r1_ports.pg, TABLE)

    assert present_a == present_b, (
        "nodes A and B must agree on the QWP-egress DROP target after the "
        "demote (no destructive divergence): the drop must either be "
        "refused (present on both) or replicate (absent on both); got "
        f"presentOnA={present_a} presentOnB={present_b} "
        f"dropError={drop_error!r}"
    )

    # Consistency between the observed client-side outcome and the
    # terminal state, where the outcome was unambiguous:
    if drop_error is None:
        assert not present_a and not present_b, (
            "an acked DROP (EXEC_DONE) must have replicated -- table "
            f"still present (A={present_a}, B={present_b})"
        )
    elif "read-only" in drop_error.lower():
        assert present_a and present_b, (
            "a read-only-refused DROP must leave the table present on "
            f"both nodes (A={present_a}, B={present_b})"
        )
    LOG.info(
        "race outcome: %s (presentOnA=%s presentOnB=%s)",
        "replicated" if not present_a else "refused/held",
        present_a, present_b,
    )
