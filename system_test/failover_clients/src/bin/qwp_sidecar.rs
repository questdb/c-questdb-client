//! Out-of-process QWP/WebSocket sender driven by a line-oriented
//! stdin/stdout protocol.
//!
//! Rust port of the Java reference at
//! `questdb-enterprise/questdb-ent/src/test/java/com/questdb/e2e/QwpSidecarMain.java`.
//! The Enterprise pytest harness in `questdb-ent/e2e` forks one of these
//! per logical sender, pipes commands into stdin, and reads single-line
//! replies from stdout. By matching the Java sidecar's wire protocol
//! byte-for-byte, the same Python `Sidecar` driver (`e2e/lib/sidecar.py`)
//! can drive either implementation.
//!
//! Why a sidecar at all: the Python harness orchestrates real QuestDB
//! processes (start, SIGKILL, restart) and needs a sender it can issue
//! deterministic SEND/FLUSH/AWAIT_ACKED commands to. The sender being
//! tested is the production client — porting the QWP/WS state machine
//! into Python would mean testing a parallel implementation, not the
//! shipping code.
//!
//! Protocol (single ASCII lines terminated by `\n`):
//!   READY                                     <- emitted on startup
//!   CONNECT <connect_string>                  -> OK | ERR <msg>
//!   SEND <table> <count> <start_index>        -> OK | ERR <msg>
//!   FLUSH                                     -> OK <fsn> | ERR <msg>
//!   AWAIT_ACKED <fsn> <timeout_ms>            -> OK true|false | ERR <msg>
//!   STATS                                     -> OK acked=N sent=N acks=N
//!                                                reconnAttempts=N reconnSucc=N
//!                                                serverErrors=N
//!   CLOSE                                     -> OK | ERR <msg>
//!   EXIT                                      -> (no reply, exits 0)
//!
//! Errors during command handling become `ERR <msg>` replies and the
//! loop keeps reading; only an internal fault (poisoned stdout, etc.)
//! exits with status 4.
//!
//! STATS coverage: emits the same six fields the Java sidecar reports
//! (`acked`, `sent`, `acks`, `reconnAttempts`, `reconnSucc`, `serverErrors`).
//! `acked` comes from `Sender::acked_fsn`; the rest come from
//! `Sender::qwp_ws_totals` and are bumped at the same QWP/WebSocket
//! event sites as their Java counterparts.

use std::io::{BufRead, BufReader, Write};
use std::process;
use std::time::Duration;

use questdb::ingress::{Buffer, Sender, TimestampMicros};

fn main() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut out = stdout.lock();

    // READY tells the harness the main loop is up. Without it a bug
    // that hangs early in startup is indistinguishable from "harness
    // sent CONNECT before the sidecar was listening" — a debugging
    // nightmare matching the rationale in the Java sidecar.
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
                state.close_quietly();
                process::exit(4);
            }
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Err(e) = handle(trimmed, &mut state, &mut out) {
            // Any handler error (parse, wire, etc.) is surfaced as ERR
            // and the loop continues — the harness can recover or shut
            // down deliberately.
            if writeln!(out, "ERR {}", sanitize(&e)).is_err() || out.flush().is_err() {
                let _ = writeln!(std::io::stderr(), "sidecar fatal: stdout write");
                state.close_quietly();
                process::exit(4);
            }
        }
    }

    state.close_quietly();
}

#[derive(Default)]
struct State {
    sender: Option<Sender>,
    buf: Option<Buffer>,
}

impl State {
    fn close_quietly(&mut self) {
        // Mirrors Java's `closeQuietly`: drain the in-flight QWP/WS
        // queue with the configured close-flush timeout, then drop the
        // sender. Errors are swallowed so the harness's EXIT path and
        // recovery paths can't get stuck.
        if let Some(mut s) = self.sender.take() {
            let _ = s.close_drain();
        }
        self.buf = None;
    }
}

fn handle(line: &str, state: &mut State, out: &mut impl Write) -> Result<(), String> {
    let (verb, rest) = match line.find(' ') {
        Some(i) => (&line[..i], line[i + 1..].trim()),
        None => (line, ""),
    };

    match verb {
        "CONNECT" => {
            // Tear down any prior sender before swapping; mirrors Java
            // behaviour where CONNECT is allowed to replace an active
            // sender (tests reuse the sidecar across scenarios).
            state.close_quietly();
            let sender = Sender::from_conf(rest).map_err(|e| e.to_string())?;
            let buf = sender.new_buffer();
            state.sender = Some(sender);
            state.buf = Some(buf);
            reply_ok(out, "")
        }
        "SEND" => {
            let sender = state
                .sender
                .as_mut()
                .ok_or_else(|| "no sender".to_string())?;
            let buf = state.buf.as_mut().ok_or_else(|| "no buffer".to_string())?;
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if parts.len() < 3 {
                return Err("usage: SEND <table> <count> <start_index>".into());
            }
            let table = parts[0];
            let count: i64 = parts[1].parse().map_err(|_| "invalid count".to_string())?;
            let start: i64 = parts[2]
                .parse()
                .map_err(|_| "invalid start_index".to_string())?;

            for i in 0..count {
                let v = start + i;
                // Mirrors the Java sidecar exactly: single long column
                // `v`, microsecond timestamps spaced one second apart
                // starting at second 1 so v=0 → 1_000_000us. Keeping
                // the schema identical lets the same Enterprise
                // failover scenarios drive either sidecar without
                // touching the asserting queries.
                buf.table(table)
                    .and_then(|b| b.column_i64("v", v))
                    .and_then(|b| b.at(TimestampMicros::new(1_000_000 * (v + 1))))
                    .map_err(|e| e.to_string())?;
            }
            // `sender` is borrowed only via the Result chain above on the
            // buf; ignore the unused binding warning by suppressing —
            // sender will be used by FLUSH/STATS later.
            let _ = sender;
            reply_ok(out, "")
        }
        "FLUSH" => {
            let sender = state
                .sender
                .as_mut()
                .ok_or_else(|| "no sender".to_string())?;
            let buf = state.buf.as_mut().ok_or_else(|| "no buffer".to_string())?;
            let fsn = sender
                .flush_and_get_fsn(buf)
                .map_err(|e| e.to_string())?
                // Empty-buffer flush returns None in Rust; Java's
                // flushAndGetSequence always returns a long. Python
                // parses `int(reply[0])` and defaults to -1 if missing,
                // so -1 is the closest equivalent sentinel.
                .map(|n| n as i64)
                .unwrap_or(-1);
            reply_ok(out, &fsn.to_string())
        }
        "AWAIT_ACKED" => {
            let sender = state
                .sender
                .as_mut()
                .ok_or_else(|| "no sender".to_string())?;
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if parts.len() < 2 {
                return Err("usage: AWAIT_ACKED <fsn> <timeout_ms>".into());
            }
            let fsn: u64 = parts[0].parse().map_err(|_| "invalid fsn".to_string())?;
            let timeout_ms: u64 = parts[1]
                .parse()
                .map_err(|_| "invalid timeout_ms".to_string())?;
            let reached = sender
                .await_acked_fsn(fsn, Duration::from_millis(timeout_ms))
                .map_err(|e| e.to_string())?;
            reply_ok(out, if reached { "true" } else { "false" })
        }
        "STATS" => {
            let sender = state
                .sender
                .as_ref()
                .ok_or_else(|| "no sender".to_string())?;
            // `acked_fsn` returns None until the first ACK lands; emit
            // -1 to match the Python parser's default and the Java
            // sidecar's "no-frame-yet" convention.
            let acked = sender
                .acked_fsn()
                .map_err(|e| e.to_string())?
                .map(|n| n as i64)
                .unwrap_or(-1);
            let totals = sender.qwp_ws_totals().map_err(|e| e.to_string())?;
            let payload = format!(
                "acked={acked} sent={} acks={} reconnAttempts={} reconnSucc={} serverErrors={}",
                totals.frames_sent,
                totals.acks,
                totals.reconnect_attempts,
                totals.reconnects_succeeded,
                totals.server_errors,
            );
            reply_ok(out, &payload)
        }
        "CLOSE" => {
            if let Some(mut s) = state.sender.take() {
                // close_drain is the Rust analogue of Java's
                // Sender.close(): flush, wait for ACKs up to the
                // configured timeout, then the sender is dropped. The
                // sender is dropped automatically on scope exit.
                s.close_drain().map_err(|e| e.to_string())?;
            }
            state.buf = None;
            reply_ok(out, "")
        }
        "EXIT" => {
            state.close_quietly();
            // No reply: matches Java sidecar — the harness's stop()
            // path doesn't wait for an OK after EXIT.
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
    // Match the Java sidecar's substitution: CR → space, LF → '|'.
    s.replace('\r', " ").replace('\n', "|")
}
