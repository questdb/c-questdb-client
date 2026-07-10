//! Soak workload driver CLI.
//!
//! Subcommands land incrementally per `doc/SOAK_HARNESS_DESIGN.md` §S1. Today:
//!
//!   soak-workload gen-vectors [--seed N] [--worker N] [--rows N]
//!       Emit the deterministic golden vectors (JSON lines) that the C /
//!       Python generator mirrors assert against for cross-language parity.
//!
//! The `run --leg <name> …` subcommand drives one workload leg (see
//! `src/legs.rs`); `gen-vectors` emits the cross-language golden vectors.

use soak_workload::gen;
use soak_workload::legs::{self, LegConfig};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("gen-vectors") => cmd_gen_vectors(&args[1..]),
        Some("run") => cmd_run(&args[1..]),
        Some("--help") | Some("-h") | None => {
            eprintln!("{USAGE}");
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("soak-workload: unknown subcommand {other:?}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

const USAGE: &str = "\
usage: soak-workload <subcommand> [options]

subcommands:
  gen-vectors   emit deterministic golden vectors as JSON lines
                options: --seed N (default 1) --worker N (default 0)
                         --rows N (default 64)
  run           drive one workload leg
                options: --leg NAME --seed N --worker-id N --addr HOST:PORT
                         --table NAME --journal PATH --stats PATH
                         --rate ROWS_PER_SEC --duration-sec N --batch N
                         [--sf-dir DIR] [--sf-mem-bytes N]
";

fn cmd_run(args: &[String]) -> ExitCode {
    let mut leg = String::new();
    let mut seed: u64 = 1;
    let mut worker_id: u32 = 0;
    let mut addr = String::from("127.0.0.1:9000");
    let mut table = String::from("soak");
    let mut journal = PathBuf::new();
    let mut stats = PathBuf::new();
    let mut rate: u64 = 0;
    let mut sf_dir: Option<PathBuf> = None;
    let mut sf_mem_bytes: Option<u64> = None;
    let mut duration_sec: u64 = 60;
    let mut batch: u64 = 1000;

    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let Some(val) = it.next() else {
            eprintln!("run: {flag} requires a value");
            return ExitCode::from(2);
        };
        let parsed = match flag.as_str() {
            "--leg" => {
                leg = val.clone();
                true
            }
            "--seed" => val.parse().map(|v| seed = v).is_ok(),
            "--worker-id" => val.parse().map(|v| worker_id = v).is_ok(),
            "--addr" => {
                addr = val.clone();
                true
            }
            "--table" => {
                table = val.clone();
                true
            }
            "--journal" => {
                journal = PathBuf::from(val);
                true
            }
            "--stats" => {
                stats = PathBuf::from(val);
                true
            }
            "--rate" => val.parse().map(|v| rate = v).is_ok(),
            "--sf-dir" => {
                sf_dir = Some(PathBuf::from(val));
                true
            }
            "--sf-mem-bytes" => val.parse().map(|v| sf_mem_bytes = Some(v)).is_ok(),
            "--duration-sec" => val.parse().map(|v| duration_sec = v).is_ok(),
            "--batch" => val.parse().map(|v| batch = v).is_ok(),
            other => {
                eprintln!("run: unknown flag {other:?}");
                return ExitCode::from(2);
            }
        };
        if !parsed {
            eprintln!("run: invalid value {val:?} for {flag}");
            return ExitCode::from(2);
        }
    }

    if leg.is_empty() || journal.as_os_str().is_empty() || stats.as_os_str().is_empty() {
        eprintln!("run: --leg, --journal and --stats are required");
        return ExitCode::from(2);
    }

    let cfg = LegConfig {
        leg,
        seed,
        worker_id,
        addr,
        table,
        journal_path: journal,
        stats_path: stats,
        target_rows_per_sec: rate,
        sf_dir,
        sf_mem_bytes,
        duration: Duration::from_secs(duration_sec),
        batch: batch.max(1),
    };

    match legs::run_leg(&cfg) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("soak-workload run: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_gen_vectors(args: &[String]) -> ExitCode {
    let mut seed: u64 = 1;
    let mut worker: u32 = 0;
    let mut rows: u64 = 64;
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let val = match it.next() {
            Some(v) => v,
            None => {
                eprintln!("gen-vectors: {flag} requires a value");
                return ExitCode::from(2);
            }
        };
        let ok = match flag.as_str() {
            "--seed" => val.parse().map(|v| seed = v).is_ok(),
            "--worker" => val.parse().map(|v| worker = v).is_ok(),
            "--rows" => val.parse().map(|v| rows = v).is_ok(),
            _ => {
                eprintln!("gen-vectors: unknown flag {flag:?}");
                return ExitCode::from(2);
            }
        };
        if !ok {
            eprintln!("gen-vectors: invalid value {val:?} for {flag}");
            return ExitCode::from(2);
        }
    }

    let mut out = String::new();
    gen::write_golden_vectors(&mut out, seed, worker, rows);
    print!("{out}");
    ExitCode::SUCCESS
}
