//! Out-of-process egress (read-side) QWP/WebSocket client driven by the same
//! line-oriented stdin/stdout protocol as the Java `QwpEgressSidecarMain`.
//!
//! Sibling to `qwp_sidecar` / `qwp_column_sidecar` (the ingress senders); this
//! one drives a `questdb::egress::Reader` so the Enterprise pytest harness can
//! verify the read-side client's failover behaviour end-to-end against forked
//! ENT primaries/replicas. By matching `QwpEgressSidecarMain`'s wire protocol
//! the same Python driver (`e2e/lib/egress_sidecar.py`) drives either binary.
//!
//! Protocol (single ASCII lines terminated by `\n`):
//!   READY                          <- emitted on startup
//!   CONNECT <connect_string>       -> OK | ERR <msg>
//!   QUERY <sql>                    -> OK <row_count> <latency_ms> resets=<n> pre_reset_rows=<n> last_replay_rows=<n> | ERR <msg>
//!   QUERY_ROW <sql>                -> OK <col>=<val>... | ERR <msg>
//!   SHOW_ZONE                      -> OK <value|<unset>> | ERR <msg>
//!   SERVER_INFO                    -> OK zone=<id|<unset>> role=<byte> cap_zone=<0|1> | ERR <msg>
//!   CLOSE                          -> OK | ERR <msg>
//!   EXIT                           -> (no reply, exits 0)
//!
//! `QUERY` executes `sql` and returns the total number of rows streamed (summed
//! across batches), plus the wall-clock latency around `execute()` + drain —
//! the read-probe signal a real caller would observe. Executing drives the
//! reader's per-execute reconnect loop, so a `QUERY` issued after the bound
//! endpoint dies is what exercises the failover walk to a surviving endpoint.
//!
//! The trailing `k=v` tokens on `QUERY` expose the cursor's mid-stream
//! failover observability (`Cursor::failover_resets`): `resets` is the number
//! of successful mid-query failover reconnects, `pre_reset_rows` the rows
//! streamed before the first reset, and `last_replay_rows` the rows streamed
//! since the most recent reset (== the full replayed result when the replay
//! ran to the terminal frame). On the no-failover happy path `resets=0` and
//! both row counters equal `<row_count>`. The Enterprise Python wrapper
//! (`lib/egress_sidecar.py::query`) only reads the first two tokens, so the
//! extension is backward-compatible with the shared harness; tests that need
//! the counters parse the raw reply.
//!
//! `QUERY_ROW` executes `sql`, drains the stream, and renders the FIRST row
//! as space-separated `<col>=<val>` tokens (NULL -> `<null>`; whitespace in
//! values replaced by `_` to keep the line protocol parseable). Intended for
//! scalar/fingerprint probes (`SELECT count(*) c, sum(id) s ...`) where the
//! harness needs decoded VALUES, not just the row count.
//!
//! Errors during command handling become `ERR <msg>` replies and the loop keeps
//! reading; an internal fault (poisoned stdout, etc.) exits with status 4.

use std::io::{BufRead, BufReader, Write};
use std::process;
use std::time::Instant;

use questdb::egress::column::ColumnView;
use questdb::egress::reader::Reader;
use questdb::egress::wire::CAP_ZONE;

fn main() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut out = stdout.lock();

    if writeln!(out, "READY").is_err() || out.flush().is_err() {
        process::exit(4);
    }

    let mut state = State::default();
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => {
                let _ = writeln!(std::io::stderr(), "egress sidecar fatal: stdin read: {e}");
                process::exit(4);
            }
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Err(e) = handle(trimmed, &mut state, &mut out)
            && (writeln!(out, "ERR {}", sanitize(&e)).is_err() || out.flush().is_err())
        {
            let _ = writeln!(std::io::stderr(), "egress sidecar fatal: stdout write");
            process::exit(4);
        }
    }
}

#[derive(Default)]
struct State {
    reader: Option<Reader>,
}

fn handle(line: &str, state: &mut State, out: &mut impl Write) -> Result<(), String> {
    let (verb, rest) = match line.find(' ') {
        Some(i) => (&line[..i], line[i + 1..].trim()),
        None => (line, ""),
    };

    match verb {
        "CONNECT" => {
            // Replace any prior client; CONNECT may be reissued across scenarios.
            state.reader = None;
            let r = Reader::from_conf(rest).map_err(|e| e.to_string())?;
            state.reader = Some(r);
            reply_ok(out, "")
        }
        "QUERY" => {
            let reader = state
                .reader
                .as_mut()
                .ok_or_else(|| "no reader".to_string())?;
            let start = Instant::now();
            // Install a (no-op) on_failover_reset handler: the Rust
            // cursor refuses to silently REPLAY rows already delivered
            // unless the caller opts in (reader.rs guards mid-query
            // replays behind the callback). The Java sidecar's
            // QwpColumnBatchHandler is inherently replay-aware
            // (onFailoverReset), so opting in here keeps the two
            // sidecars' QUERY verbs semantically identical. Replay
            // *observability* comes from `Cursor::failover_resets()`.
            let mut cursor = reader
                .prepare(rest)
                .on_failover_reset(|_| {})
                .execute()
                .map_err(|e| e.to_string())?;
            let mut rows: u64 = 0;
            // Mid-stream failover observability: rows before the first
            // reset, and rows since the most recent reset. A replayed
            // query re-delivers the full result on the new connection, so
            // `last_replay_rows` equals the complete row set when the
            // replay ran to the terminal frame.
            let mut resets_seen: u32 = 0;
            let mut pre_reset_rows: u64 = 0;
            let mut last_replay_rows: u64 = 0;
            loop {
                // Take the batch's row count inside the match arm so the
                // BatchView's borrow of the cursor ends before we consult
                // `failover_resets()` (which takes `&self`).
                let batch_rows = match cursor.next_batch().map_err(|e| e.to_string())? {
                    Some(view) => view.row_count() as u64,
                    None => break,
                };
                let resets_now = cursor.failover_resets();
                if resets_now != resets_seen {
                    if resets_seen == 0 {
                        pre_reset_rows = rows;
                    }
                    resets_seen = resets_now;
                    last_replay_rows = 0;
                }
                rows += batch_rows;
                last_replay_rows += batch_rows;
            }
            // A reset can also land between the last batch and the
            // terminal frame (no rows after it); fold that in so the
            // reported counters stay consistent with `resets`.
            let resets_now = cursor.failover_resets();
            if resets_now != resets_seen {
                if resets_seen == 0 {
                    pre_reset_rows = rows;
                }
                resets_seen = resets_now;
                last_replay_rows = 0;
            }
            if resets_seen == 0 {
                pre_reset_rows = rows;
            }
            let ms = start.elapsed().as_millis();
            drop(cursor);
            reply_ok(
                out,
                &format!(
                    "{rows} {ms} resets={resets_seen} pre_reset_rows={pre_reset_rows} \
                     last_replay_rows={last_replay_rows}"
                ),
            )
        }
        "QUERY_ROW" => {
            let reader = state
                .reader
                .as_mut()
                .ok_or_else(|| "no reader".to_string())?;
            let mut cursor = reader.execute(rest).map_err(|e| e.to_string())?;
            let mut row: Option<String> = None;
            // Drain to completion (dropping a part-read cursor poisons
            // the connection for the next verb; see SHOW_ZONE).
            while let Some(view) = cursor.next_batch().map_err(|e| e.to_string())? {
                if row.is_some() || view.row_count() == 0 {
                    continue;
                }
                let mut parts: Vec<String> = Vec::new();
                let names: Vec<String> = view
                    .schema()
                    .columns()
                    .iter()
                    .map(|c| c.name.clone())
                    .collect();
                for (i, name) in names.iter().enumerate() {
                    let col = view.column(i).map_err(|e| e.to_string())?;
                    parts.push(format!("{}={}", name, render_cell(&col)));
                }
                row = Some(parts.join(" "));
            }
            drop(cursor);
            match row {
                Some(r) => reply_ok(out, &r),
                None => Err("no rows".to_string()),
            }
        }
        "SHOW_ZONE" => {
            let reader = state
                .reader
                .as_mut()
                .ok_or_else(|| "no reader".to_string())?;
            // Runs on whichever endpoint is currently bound; triggers the
            // per-execute reconnect loop if that socket is dead, exactly as a
            // real read-side caller would.
            let sql = "(SHOW PARAMETERS) WHERE property_path = 'replication.zone'";
            let mut cursor = reader.execute(sql).map_err(|e| e.to_string())?;
            let mut value: Option<String> = None;
            // Drain the cursor to completion -- do NOT break early. The Rust
            // Reader poisons a connection whose cursor is dropped before it
            // is fully read, which would make the NEXT SHOW_ZONE fail with
            // "connection is closed and cannot be reused". SHOW PARAMETERS
            // returns a tiny result, so draining the rest is cheap.
            while let Some(view) = cursor.next_batch().map_err(|e| e.to_string())? {
                if value.is_some() || view.row_count() == 0 {
                    continue;
                }
                let idx = view
                    .schema()
                    .columns()
                    .iter()
                    .position(|c| c.name == "value")
                    .ok_or_else(|| "SHOW PARAMETERS missing 'value' column".to_string())?;
                value = match view.column(idx).map_err(|e| e.to_string())? {
                    ColumnView::Varchar(c) => c.value(0).map(|s| s.to_string()),
                    ColumnView::Symbol(c) => c.resolve(0).map(|s| s.to_string()),
                    _ => return Err("SHOW PARAMETERS 'value' column is not a string".into()),
                };
            }
            drop(cursor);
            // Reserve <unset> for "row not present" or a NULL/empty value, so
            // the harness can distinguish it from a real zone id.
            let payload = match value {
                Some(ref s) if !s.is_empty() => s.clone(),
                _ => "<unset>".to_string(),
            };
            reply_ok(out, &payload)
        }
        "SERVER_INFO" => {
            let reader = state
                .reader
                .as_ref()
                .ok_or_else(|| "no reader".to_string())?;
            // In-memory snapshot from the most recent bind; no SQL round-trip,
            // so this does not itself drive reconnect.
            let (zone, role, cap_zone) = match reader.server_info() {
                Some(info) => (
                    info.zone_id
                        .clone()
                        .unwrap_or_else(|| "<unset>".to_string()),
                    i32::from(info.role.as_u8()),
                    i32::from(info.capabilities & CAP_ZONE != 0),
                ),
                None => ("<unset>".to_string(), -1, 0),
            };
            reply_ok(out, &format!("zone={zone} role={role} cap_zone={cap_zone}"))
        }
        "CLOSE" => {
            state.reader = None;
            reply_ok(out, "")
        }
        "EXIT" => {
            state.reader = None;
            process::exit(0);
        }
        _ => Err(format!("unknown verb: {verb}")),
    }
}

fn reply_ok(out: &mut impl Write, payload: &str) -> Result<(), String> {
    let line = if payload.is_empty() {
        "OK".to_string()
    } else {
        format!("OK {payload}")
    };
    writeln!(out, "{line}").map_err(|e| e.to_string())?;
    out.flush().map_err(|e| e.to_string())
}

fn sanitize(s: &str) -> String {
    // Newlines in an ERR message would break the line-based protocol.
    s.replace('\r', " ").replace('\n', "|")
}

/// Render row 0 of `col` as a single whitespace-free token for the
/// `QUERY_ROW` reply. NULL -> `<null>`; unsupported column kinds ->
/// `<unsupported>`. Covers the kinds fingerprint probes actually emit
/// (counts, sums, min/max over LONG/INT/DOUBLE/TIMESTAMP + string
/// labels); extend as scenarios require.
fn render_cell(col: &ColumnView<'_>) -> String {
    fn tok(s: String) -> String {
        let cleaned: String = s
            .chars()
            .map(|c| if c.is_whitespace() { '_' } else { c })
            .collect();
        if cleaned.is_empty() {
            "<empty>".to_string()
        } else {
            cleaned
        }
    }
    match col {
        ColumnView::Boolean(c) => {
            if c.is_null(0) {
                "<null>".into()
            } else {
                (c.value(0) != 0).to_string()
            }
        }
        ColumnView::Byte(c) => {
            if c.is_null(0) {
                "<null>".into()
            } else {
                c.value(0).to_string()
            }
        }
        ColumnView::Short(c) => {
            if c.is_null(0) {
                "<null>".into()
            } else {
                c.value(0).to_string()
            }
        }
        ColumnView::Int(c) => {
            if c.is_null(0) {
                "<null>".into()
            } else {
                c.value(0).to_string()
            }
        }
        ColumnView::Long(c) => {
            if c.is_null(0) {
                "<null>".into()
            } else {
                c.value(0).to_string()
            }
        }
        ColumnView::Float(c) => {
            if c.is_null(0) {
                "<null>".into()
            } else {
                c.value(0).to_string()
            }
        }
        ColumnView::Double(c) => {
            if c.is_null(0) {
                "<null>".into()
            } else {
                c.value(0).to_string()
            }
        }
        ColumnView::Timestamp(c) | ColumnView::Date(c) | ColumnView::TimestampNanos(c) => {
            if c.is_null(0) {
                "<null>".into()
            } else {
                c.value(0).to_string()
            }
        }
        ColumnView::Varchar(c) => match c.value(0) {
            Some(s) => tok(s.to_string()),
            None => "<null>".into(),
        },
        ColumnView::Symbol(c) => match c.resolve(0) {
            Some(s) => tok(s.to_string()),
            None => "<null>".into(),
        },
        _ => "<unsupported>".into(),
    }
}
