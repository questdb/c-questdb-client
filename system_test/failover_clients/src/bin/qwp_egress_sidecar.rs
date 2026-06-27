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
//!   QUERY <sql>                    -> OK <row_count> <latency_ms> | ERR <msg>
//!   SHOW_ZONE                      -> OK <value|<unset>> | ERR <msg>
//!   SERVER_INFO                    -> OK zone=<id|<unset>> role=<byte> | ERR <msg>
//!   CLOSE                          -> OK | ERR <msg>
//!   EXIT                           -> (no reply, exits 0)
//!
//! `QUERY` executes `sql` and returns the total number of rows streamed (summed
//! across batches), plus the wall-clock latency around `execute()` + drain —
//! the read-probe signal a real caller would observe. Executing drives the
//! reader's per-execute reconnect loop, so a `QUERY` issued after the bound
//! endpoint dies is what exercises the failover walk to a surviving endpoint.
//!
//! Errors during command handling become `ERR <msg>` replies and the loop keeps
//! reading; an internal fault (poisoned stdout, etc.) exits with status 4.

use std::io::{BufRead, BufReader, Write};
use std::process;
use std::time::Instant;

use questdb::egress::column::ColumnView;
use questdb::egress::reader::Reader;

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
            let mut cursor = reader.execute(rest).map_err(|e| e.to_string())?;
            let mut rows: u64 = 0;
            while let Some(view) = cursor.next_batch().map_err(|e| e.to_string())? {
                rows += view.row_count() as u64;
            }
            let ms = start.elapsed().as_millis();
            drop(cursor);
            reply_ok(out, &format!("{rows} {ms}"))
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
            while let Some(view) = cursor.next_batch().map_err(|e| e.to_string())? {
                if view.row_count() == 0 {
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
                break;
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
            let (zone, role) = match reader.server_info() {
                Some(info) => (
                    info.zone_id
                        .clone()
                        .unwrap_or_else(|| "<unset>".to_string()),
                    i32::from(info.role.as_u8()),
                ),
                None => ("<unset>".to_string(), -1),
            };
            reply_ok(out, &format!("zone={zone} role={role}"))
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
