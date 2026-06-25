/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2025 QuestDB
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 ******************************************************************************/

//! Synthetic equities L1 quote feed → QuestDB via the column-major sender.
//!
//! Generates a 5M-row dataset that mimics a Level-1 order book stream
//! (per-symbol top-of-book bid/ask with a trailing last-trade) and
//! ingests it into a single QuestDB table. Reports end-to-end
//! throughput (rows/s, MB/s) and the average per-chunk flush latency.
//!
//! Default schema:
//!     ts          TIMESTAMP_NANOS  (designated)
//!     symbol      SYMBOL           (~500 tickers)
//!     exchange    SYMBOL           (5 venues)
//!     bid_px      DOUBLE
//!     ask_px      DOUBLE
//!     last_px     DOUBLE
//!     bid_sz      LONG
//!     ask_sz      LONG
//!     last_sz     LONG
//!
//! Run against a local QuestDB instance:
//!     cargo run --release --features sync-sender-qwp-ws \
//!         --example qwp_ws_l1_quotes
//!
//! Positional args:
//!     1: connect string  (default `qwpws::addr=localhost:9000;`)
//!     2: table name      (default `l1_quotes`)
//!     3: row count       (default 5_000_000)
//!
//! Pre-create the table (paste into the QuestDB Web Console at
//! http://localhost:9000 or post via curl):
//!
//!     CREATE TABLE l1_quotes (
//!         ts         TIMESTAMP,
//!         symbol     SYMBOL CAPACITY 512 NOCACHE,
//!         exchange   SYMBOL CAPACITY 8   NOCACHE,
//!         bid_px     DOUBLE,
//!         ask_px     DOUBLE,
//!         last_px    DOUBLE,
//!         bid_sz     LONG,
//!         ask_sz     LONG,
//!         last_sz    LONG
//!     ) TIMESTAMP(ts) PARTITION BY HOUR WAL;
//!
//! Verify after run:
//!     curl 'http://localhost:9000/exec?query=SELECT%20count()%20FROM%20l1_quotes'
//!     curl 'http://localhost:9000/exec?query=SELECT%20*%20FROM%20l1_quotes%20LIMIT%2010'

use std::time::Instant;

use questdb::QuestDb;
use questdb::ingress::column_sender::{AckLevel, Chunk};

const DEFAULT_TOTAL_ROWS: usize = 5_000_000;
/// 25 000 rows × ~60 bytes/row ≈ 1.5 MB. Stays under the QuestDB server's
/// default 2 MiB WebSocket receive buffer (the server logs
/// `QwpIngressUpgradeProcessor … frame too large` and closes the
/// connection for larger frames; the spec's 16 MiB cap is only relevant
/// when the server's buffer is sized for it).
const CHUNK_ROWS: usize = 25_000;
const SYMBOL_CARDINALITY: usize = 500;
const EXCHANGES: &[&str] = &["NYSE", "NASDAQ", "BATS", "ARCA", "IEX"];

fn main() -> questdb::Result<()> {
    let conf = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "qwpws::addr=localhost:9000;".to_string());
    let table_name = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "l1_quotes".to_string());
    let total_rows: usize = std::env::args()
        .nth(3)
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_TOTAL_ROWS);

    println!(
        "Generating {} rows of L1 quote data ({} tickers × {} venues)...",
        humanise(total_rows),
        SYMBOL_CARDINALITY,
        EXCHANGES.len()
    );
    let gen_start = Instant::now();

    let symbol_dict_strings: Vec<String> = (0..SYMBOL_CARDINALITY)
        .map(|i| format!("TICK{i:03}"))
        .collect();
    let (sym_dict_offsets, sym_dict_bytes) =
        build_dict(symbol_dict_strings.iter().map(String::as_str));
    let (ex_dict_offsets, ex_dict_bytes) = build_dict(EXCHANGES.iter().copied());

    // Pre-allocate columnar buffers for the full dataset. At 5 M × 8 B per
    // f64/i64 column the peak working set is ~280 MB; comfortable on any
    // dev box.
    let mut symbol_codes = Vec::with_capacity(total_rows);
    let mut exchange_codes = Vec::with_capacity(total_rows);
    let mut ts_ns = Vec::with_capacity(total_rows);
    let mut bid_px = Vec::with_capacity(total_rows);
    let mut ask_px = Vec::with_capacity(total_rows);
    let mut last_px = Vec::with_capacity(total_rows);
    let mut bid_sz = Vec::with_capacity(total_rows);
    let mut ask_sz = Vec::with_capacity(total_rows);
    let mut last_sz = Vec::with_capacity(total_rows);

    let start_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as i64;

    // Splitmix-style RNG: avoids a dep on `rand` and produces a uniform
    // enough spread for the symbol distribution.
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut step = || {
        state = state.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        state ^= state >> 27;
        state
    };

    for i in 0..total_rows {
        let r1 = step();
        let r2 = step();

        let sym = (r1 as usize % SYMBOL_CARDINALITY) as i32;
        let ex = ((r1 >> 32) as usize % EXCHANGES.len()) as i8;
        // Per-symbol base price so the L1 feed has realistic price strata.
        let base = 100.0 + sym as f64;
        let spread = 0.01 + (((r2 & 0xFFFF) as f64) / 65_535.0) * 0.05;
        let drift = (((r2 >> 16) & 0xFFFF) as f64 - 32_768.0) / 1_000_000.0;
        let mid = base + drift;
        let bid = mid - spread / 2.0;
        let ask = mid + spread / 2.0;
        let last = mid + (((r2 >> 32) & 0xFFFF) as f64 - 32_768.0) / 1_000_000.0;
        let sz_bid = 100 + ((r1 >> 8) & 0xFFFF) as i64;
        let sz_ask = 100 + ((r1 >> 24) & 0xFFFF) as i64;
        let sz_last = 100 + ((r2 >> 48) & 0x3FF) as i64;

        symbol_codes.push(sym);
        exchange_codes.push(ex);
        // Monotonic 1 µs cadence — characteristic of a top-of-book feed
        // even if individual events are slightly out of order in real
        // life.
        ts_ns.push(start_ts + (i as i64) * 1_000);
        bid_px.push(bid);
        ask_px.push(ask);
        last_px.push(last);
        bid_sz.push(sz_bid);
        ask_sz.push(sz_ask);
        last_sz.push(sz_last);
    }
    let gen_elapsed = gen_start.elapsed();
    println!(
        "  generated in {:.2}s ({:.1} M rows/s)",
        gen_elapsed.as_secs_f64(),
        total_rows as f64 / gen_elapsed.as_secs_f64() / 1e6
    );

    println!("\nConnecting to {conf} ...");
    let db = QuestDb::connect(&conf)?;
    let mut sender = db.borrow_column_sender()?;

    // One chunk reused across flushes — the bench design exists exactly
    // for this case: per-column `Vec<u8>` capacity is retained across
    // flush().
    let mut chunk = Chunk::new(&table_name);

    let mut chunk_micros: Vec<u128> = Vec::new();
    let send_start = Instant::now();
    let mut flushed = 0usize;
    let mut chunk_idx = 0usize;
    while flushed < total_rows {
        let end = (flushed + CHUNK_ROWS).min(total_rows);

        chunk.column_i64("bid_sz", &bid_sz[flushed..end], None)?;
        chunk.column_i64("ask_sz", &ask_sz[flushed..end], None)?;
        chunk.column_i64("last_sz", &last_sz[flushed..end], None)?;
        chunk.column_f64("bid_px", &bid_px[flushed..end], None)?;
        chunk.column_f64("ask_px", &ask_px[flushed..end], None)?;
        chunk.column_f64("last_px", &last_px[flushed..end], None)?;
        chunk.symbol_dict_i32(
            "symbol",
            &symbol_codes[flushed..end],
            &sym_dict_offsets,
            &sym_dict_bytes,
            None,
        )?;
        chunk.symbol_dict_i8(
            "exchange",
            &exchange_codes[flushed..end],
            &ex_dict_offsets,
            &ex_dict_bytes,
            None,
        )?;
        chunk.designated_timestamp_nanos(&ts_ns[flushed..end])?;

        let t = Instant::now();
        sender.flush(&mut chunk)?;
        chunk_micros.push(t.elapsed().as_micros());

        flushed = end;
        chunk_idx += 1;
        eprint!(
            "\r  flushed chunk {chunk_idx:02} ({}/{} rows)",
            humanise(flushed),
            humanise(total_rows)
        );
    }
    // This example pipelines many chunks (publish-only `flush`) and drains
    // once here for throughput. To instead publish one batch and wait for its
    // commit in a single call, use `sender.flush_and_wait(&mut chunk, AckLevel::Ok)`.
    sender.sync(AckLevel::Ok)?;
    eprintln!();
    let send_elapsed = send_start.elapsed();

    // Per-row wire payload estimate:
    //   3 × f64 + 3 × i64 + 1 × i64 (ts) + 2 B symbol varint + 1 B exchange varint
    // = 24 + 24 + 8 + 3 = 59 bytes. Schema/header overhead amortises away.
    let bytes_per_row = 59usize;
    let total_bytes = total_rows * bytes_per_row;

    println!(
        "\nFlushed {} rows in {:.2}s ({} chunks of up to {})",
        humanise(total_rows),
        send_elapsed.as_secs_f64(),
        chunk_idx,
        humanise(CHUNK_ROWS)
    );
    println!(
        "  throughput:        {:>7.2} M rows/s",
        total_rows as f64 / send_elapsed.as_secs_f64() / 1e6
    );
    println!(
        "  bandwidth:         {:>7.1} MB/s (≈ {:.0} byte/row × rows/s)",
        total_bytes as f64 / send_elapsed.as_secs_f64() / 1e6,
        bytes_per_row
    );
    println!(
        "  per-chunk avg:     {:>7.1} ms",
        send_elapsed.as_millis() as f64 / chunk_idx as f64
    );
    if let (Some(&min), Some(&max)) = (chunk_micros.iter().min(), chunk_micros.iter().max()) {
        let mut sorted = chunk_micros.clone();
        sorted.sort_unstable();
        let p50 = sorted[sorted.len() / 2];
        let p95 = sorted[(sorted.len() * 19) / 20];
        println!(
            "  per-chunk min/p50/p95/max: {:.2} / {:.2} / {:.2} / {:.2} ms",
            min as f64 / 1000.0,
            p50 as f64 / 1000.0,
            p95 as f64 / 1000.0,
            max as f64 / 1000.0,
        );
    }

    println!("\nVerify in QuestDB:");
    println!("  curl 'http://localhost:9000/exec?query=SELECT%20count()%20FROM%20{table_name}'");
    println!(
        "  curl 'http://localhost:9000/exec?query=SELECT%20*%20FROM%20{table_name}%20LIMIT%2010'"
    );

    Ok(())
}

fn build_dict<'a, I>(strings: I) -> (Vec<i32>, Vec<u8>)
where
    I: IntoIterator<Item = &'a str>,
{
    let mut offsets: Vec<i32> = vec![0];
    let mut bytes: Vec<u8> = Vec::new();
    for s in strings {
        bytes.extend_from_slice(s.as_bytes());
        offsets.push(bytes.len() as i32);
    }
    (offsets, bytes)
}

fn humanise(n: usize) -> String {
    if n >= 1_000_000 {
        format!("{:.2} M", n as f64 / 1e6)
    } else if n >= 1_000 {
        format!("{:.1} k", n as f64 / 1e3)
    } else {
        n.to_string()
    }
}
