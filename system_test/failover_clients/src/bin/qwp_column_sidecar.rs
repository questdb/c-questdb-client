//! Out-of-process column-major QWP/WebSocket sender driven by the same
//! line-oriented stdin/stdout protocol as `qwp_sidecar`.
//!
//! Sibling to `qwp_sidecar.rs`, which drives the row-major `Sender`. This one
//! drives the column-major path — `QuestDb` → `borrow_column_sender()` →
//! `ColumnSender` — over a store-and-forward QWP/WebSocket connection, so the
//! Enterprise pytest harness can run the same kill-9 failover scenario against
//! the columnar ingest API. Matching `qwp_sidecar`'s wire protocol byte-for-byte
//! lets the same Python `Sidecar` driver (`e2e/lib/sidecar.py`) drive either
//! binary.
//!
//! Protocol (single ASCII lines terminated by `\n`):
//!   READY                                       <- emitted on startup
//!   CONNECT <connect_string>                    -> OK | ERR <msg>
//!   SEND <table> <count> <start_index> [<src>]  -> OK | ERR <msg>
//!   FLUSH                                       -> OK <fsn> | ERR <msg>
//!   CLOSE                                       -> OK | ERR <msg>
//!   EXIT                                        -> (no reply, exits 0)
//!
//! `<src>` selects the column-major input shape FLUSH builds from the
//! accumulated rows: `chunk` (default; a `Chunk` of borrowed column slices) or
//! `arrow` (an Arrow `RecordBatch`). Both funnel to the same QWP/WebSocket
//! columnar wire and the same store-and-forward backend, so the failover
//! contract is identical — the variants differ only in how the sender ingests
//! the data.
//!
//! Durability model: the column sender expresses acknowledgement through
//! `AckLevel`, not an integer FSN. `SEND` accumulates a single `LONG` column
//! `v` plus a designated timestamp (the same per-row schema the row sidecar
//! emits, so the harness's asserting queries are unchanged). `FLUSH` builds the
//! column-major frame, publishes it, and waits for the server `Ok` watermark,
//! then replies `OK -1` — there is no FSN handle on the column path, and the
//! Python driver defaults a missing value to -1. With `request_durable_ack=on`
//! and an `sf_dir`, the store-and-forward backend retains the frame until it is
//! *durably* acked and replays it to a reconnected primary; killing the primary
//! before the durable ack is the failover case the test exercises.
//!
//! Errors during command handling become `ERR <msg>` replies and the loop keeps
//! reading; an internal fault (poisoned stdout, etc.) exits with status 4.

use std::io::{BufRead, BufReader, Write};
use std::process;
use std::sync::Arc;

use arrow_array::{ArrayRef, Int64Array, RecordBatch, TimestampMicrosecondArray};
use arrow_schema::{DataType, Field, Schema, TimeUnit};
use questdb::QuestDb;
use questdb::ingress::ColumnName;
use questdb::ingress::column_sender::{AckLevel, Chunk};
#[cfg(feature = "polars")]
use questdb::ingress::polars::PolarsIngestOptions;

fn main() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut out = stdout.lock();

    // READY tells the harness the main loop is up, matching the row sidecar's
    // handshake so the Python "wait for READY" path is shared.
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
                let _ = writeln!(std::io::stderr(), "sidecar fatal: stdin read: {e}");
                state.close();
                process::exit(4);
            }
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Err(e) = handle(trimmed, &mut state, &mut out) {
            if writeln!(out, "ERR {}", sanitize(&e)).is_err() || out.flush().is_err() {
                let _ = writeln!(std::io::stderr(), "sidecar fatal: stdout write");
                state.close();
                process::exit(4);
            }
        }
    }

    state.close();
}

#[derive(Default)]
struct State {
    db: Option<QuestDb>,
    // Accumulated by SEND, drained by FLUSH into a column-major frame. Held as
    // owned vectors because both a `Chunk` (borrowed column slices) and an Arrow
    // `RecordBatch` are built transiently inside FLUSH from these.
    table: Option<String>,
    src: SendSrc,
    v: Vec<i64>,
    ts: Vec<i64>,
}

/// Column-major input shape FLUSH builds from the accumulated rows. Both encode
/// to the same QWP/WebSocket columnar wire.
#[derive(Default, Clone, Copy)]
enum SendSrc {
    #[default]
    Chunk,
    Arrow,
    #[cfg(feature = "polars")]
    Polars,
}

impl State {
    fn close(&mut self) {
        // Dropping the QuestDb returns its pooled connection and tears down the
        // store-and-forward background driver. The harness drives EXIT only
        // after its assertions have run, so abandoning any not-yet-replayed
        // sf_dir frames here is intentional.
        self.db = None;
        self.table = None;
        self.v.clear();
        self.ts.clear();
    }
}

fn handle(line: &str, state: &mut State, out: &mut impl Write) -> Result<(), String> {
    let (verb, rest) = match line.find(' ') {
        Some(i) => (&line[..i], line[i + 1..].trim()),
        None => (line, ""),
    };

    match verb {
        "CONNECT" => {
            // Replace any prior pool; CONNECT may be reissued across scenarios.
            state.close();
            let db = QuestDb::connect(rest).map_err(|e| e.to_string())?;
            state.db = Some(db);
            reply_ok(out, "")
        }
        "SEND" => {
            if state.db.is_none() {
                return Err("no sender".to_string());
            }
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if parts.len() < 3 {
                return Err("usage: SEND <table> <count> <start_index> [chunk|arrow]".into());
            }
            let table = parts[0];
            let count: i64 = parts[1].parse().map_err(|_| "invalid count".to_string())?;
            let start: i64 = parts[2]
                .parse()
                .map_err(|_| "invalid start_index".to_string())?;
            let src = match parts.get(3).copied() {
                None | Some("chunk") => SendSrc::Chunk,
                Some("arrow") => SendSrc::Arrow,
                #[cfg(feature = "polars")]
                Some("polars") => SendSrc::Polars,
                Some(other) => return Err(format!("unknown SEND src: {other}")),
            };

            state.table = Some(table.to_string());
            state.src = src;
            for i in 0..count {
                let val = start + i;
                state.v.push(val);
                // Designated timestamp in microseconds, one second apart from
                // second 1 — the same wall-clock the row sidecar emits
                // (`TimestampMicros::new(1_000_000 * (v + 1))`). Only `v` is
                // asserted, but the table still needs a designated timestamp.
                state.ts.push(1_000_000 * (val + 1));
            }
            reply_ok(out, "")
        }
        "FLUSH" => {
            if state.db.is_none() {
                return Err("no sender".to_string());
            }
            let table = state.table.clone().ok_or_else(|| "no table".to_string())?;
            {
                let db = state.db.as_ref().unwrap();
                let mut sender = db.borrow_column_sender().map_err(|e| e.to_string())?;
                // Publish and wait for the server `Ok` watermark. The frame stays
                // in the sf_dir until durably acked, so a kill-9 of the primary
                // before that durable ack leaves it to replay to the successor —
                // the row sidecar's OK-but-not-durable case.
                match state.src {
                    SendSrc::Chunk => {
                        let mut chunk = Chunk::new(table.as_str());
                        chunk
                            .column_i64("v", state.v.as_slice(), None)
                            .map_err(|e| e.to_string())?;
                        chunk
                            .designated_timestamp_micros(state.ts.as_slice())
                            .map_err(|e| e.to_string())?;
                        sender
                            .flush_and_wait(&mut chunk, AckLevel::Ok)
                            .map_err(|e| e.to_string())?;
                    }
                    SendSrc::Arrow => {
                        let batch = build_arrow_batch(&state.v, &state.ts)?;
                        let ts_col = ColumnName::new("ts").map_err(|e| e.to_string())?;
                        sender
                            .flush_arrow_batch_at_column_and_wait(
                                table.as_str(),
                                &batch,
                                ts_col,
                                &[],
                                AckLevel::Ok,
                            )
                            .map_err(|e| e.to_string())?;
                    }
                    #[cfg(feature = "polars")]
                    SendSrc::Polars => {
                        let df = build_polars_df(&state.v, &state.ts)?;
                        let ts_col = ColumnName::new("ts").map_err(|e| e.to_string())?;
                        let opts = PolarsIngestOptions::new().timestamp_column(ts_col);
                        // flush_polars_dataframe owns the commit, ACKing each
                        // checkpoint at the server `Ok` watermark (not durable),
                        // so the store-and-forward backend still replays to the
                        // successor after the kill.
                        sender
                            .flush_polars_dataframe(table.as_str(), &df, &opts)
                            .map_err(|e| e.to_string())?;
                    }
                }
            }
            state.v.clear();
            state.ts.clear();
            reply_ok(out, "-1")
        }
        "CLOSE" => {
            state.close();
            reply_ok(out, "")
        }
        "EXIT" => {
            state.close();
            // No reply: the harness's stop() path doesn't wait for an OK.
            process::exit(0);
        }
        _ => Err(format!("unknown verb: {verb}")),
    }
}

/// Build a `RecordBatch` with a `v` LONG column and a `ts` microsecond-timestamp
/// column — the same schema the `chunk` path designates, so the harness's
/// `v`-sequence oracle is unchanged.
fn build_arrow_batch(v: &[i64], ts: &[i64]) -> Result<RecordBatch, String> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("v", DataType::Int64, false),
        Field::new(
            "ts",
            DataType::Timestamp(TimeUnit::Microsecond, None),
            false,
        ),
    ]));
    let columns: Vec<ArrayRef> = vec![
        Arc::new(Int64Array::from(v.to_vec())),
        Arc::new(TimestampMicrosecondArray::from(ts.to_vec())),
    ];
    RecordBatch::try_new(schema, columns).map_err(|e| e.to_string())
}

/// Build a polars `DataFrame` with a `v` LONG column and a `ts`
/// microsecond-`Datetime` column — the same schema the other shapes use.
#[cfg(feature = "polars")]
fn build_polars_df(v: &[i64], ts: &[i64]) -> Result<polars::frame::DataFrame, String> {
    use polars::prelude::*;
    let v_col = Series::new(PlSmallStr::from("v"), v).into_column();
    let ts_col = Series::new(PlSmallStr::from("ts"), ts)
        .cast(&DataType::Datetime(TimeUnit::Microseconds, None))
        .map_err(|e| e.to_string())?
        .into_column();
    DataFrame::new_with_height(v.len(), vec![v_col, ts_col]).map_err(|e| e.to_string())
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
