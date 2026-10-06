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
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

//! Column-major sender hot-path bench (`questdb-rs/benches/column_sender.rs`).
//!
//! Anchors the encoder floor tracked in
//! `doc/QWP_UNIFIED_SENDER_M0_BASELINE.md`. Each bench reports
//! throughput in rows/s and bytes/s so a regression shows up as either
//! a row-rate or bandwidth drop.
//!
//! Four families:
//!
//! 1. **Per-column bulk append** — exercises [`Chunk::column_i64`],
//!    [`Chunk::column_f64`], [`Chunk::column_str`], and
//!    [`Chunk::symbol_i32`] in both no-null and nullable shapes.
//!    Baseline: a raw `extend_from_slice` from the caller's typed
//!    buffer into a fresh `Vec<u8>`, the absolute floor any
//!    columnar payload hot path is competing with.
//!
//! 2. **Symbol bulk-intern** — compares the column path
//!    ([`Chunk::symbol_i32`] + flush-time interning) with a
//!    naive per-row HashMap lookup that mirrors what the row API pays
//!    on the same cardinality, to anchor the WS-4 plan claim ("10M
//!    rows × 1000-card drops from 10M probes to 1000").
//!
//! 3. **Encode-only end-to-end** — populate a 10M-row chunk with a
//!    representative column mix, then time
//!    [`bench_encode_chunk`](_bench_internals::bench_encode_chunk).
//!    Pure encoder cost (no network) so a regression in
//!    `encode_chunk` or in any per-column append shows up here.
//!
//! 4. **Timestamp encoding** — one narrow column plus a timestamp in the
//!    shapes that set the encoder's cost: regular and jittery data that
//!    compresses, and data that falls back to raw at once or only on its
//!    last row. `raw_copy`, a DATE column over the same data, is the
//!    plain-copy baseline.
//!
//! Run:
//!
//! ```text
//! cargo bench --features sync-sender-qwp-ws --bench column_sender
//! QUESTDB_COLUMN_BENCH_ROWS=10000000 cargo bench --features sync-sender-qwp-ws --bench column_sender
//! ```

use std::collections::HashMap;
use std::time::Duration;

use criterion::{BatchSize, Criterion, Throughput, black_box, criterion_group, criterion_main};

use questdb::ingress::TimestampUnit;
use questdb::ingress::column_sender::_bench_internals::{
    BenchEncoderState, bench_encode_chunk_into,
};
use questdb::ingress::column_sender::{Chunk, Validity};

// ---------------------------------------------------------------------------
// Workload sizes. Defaults are tuned for sub-second criterion samples so the
// bench runs in CI; bump via `QUESTDB_COLUMN_BENCH_ROWS` for headline numbers.
// ---------------------------------------------------------------------------

fn row_count() -> usize {
    std::env::var("QUESTDB_COLUMN_BENCH_ROWS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100_000)
}

fn varchar_len() -> usize {
    std::env::var("QUESTDB_COLUMN_BENCH_VARCHAR_LEN")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(16)
}

fn symbol_cardinality() -> usize {
    std::env::var("QUESTDB_COLUMN_BENCH_SYM_CARD")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1_000)
}

// ---------------------------------------------------------------------------
// Workload generators
// ---------------------------------------------------------------------------

fn make_i64_data(rows: usize) -> Vec<i64> {
    (0..rows as i64).collect()
}

fn make_f64_data(rows: usize) -> Vec<f64> {
    (0..rows).map(|i| i as f64 * 1.5).collect()
}

/// Arrow-shape validity: every 16th row is null, all others valid.
fn make_validity_bits(rows: usize) -> Vec<u8> {
    let bytes = rows.div_ceil(8);
    let mut out = vec![0xFFu8; bytes];
    for (row_idx, byte) in (0..rows).zip(0..) {
        let _ = byte; // pacify clippy if unused
        if row_idx.is_multiple_of(16) {
            out[row_idx / 8] &= !(1u8 << (row_idx % 8));
        }
    }
    out
}

fn make_varchar(rows: usize, len: usize) -> (Vec<i32>, Vec<u8>) {
    let mut offsets = Vec::with_capacity(rows + 1);
    let mut bytes = Vec::with_capacity(rows * len);
    let alphabet = b"abcdefghijklmnopqrstuvwxyz";
    offsets.push(0);
    for row in 0..rows {
        for i in 0..len {
            bytes.push(alphabet[(row + i) % alphabet.len()]);
        }
        offsets.push(bytes.len() as i32);
    }
    (offsets, bytes)
}

fn make_symbol_workload(rows: usize, cardinality: usize) -> (Vec<i32>, Vec<i32>, Vec<u8>) {
    let mut dict_offsets = Vec::with_capacity(cardinality + 1);
    let mut dict_bytes = Vec::new();
    dict_offsets.push(0);
    for i in 0..cardinality {
        // Short distinct strings: "sym-12345".
        let entry = format!("sym-{i:08}");
        dict_bytes.extend_from_slice(entry.as_bytes());
        dict_offsets.push(dict_bytes.len() as i32);
    }
    // Splitmix-style spread of codes across the dict so the encoder's
    // intern + gather path sees a realistic distribution.
    let mut codes = Vec::with_capacity(rows);
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    for _ in 0..rows {
        state = state.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        state ^= state >> 27;
        codes.push((state as usize % cardinality) as i32);
    }
    (codes, dict_offsets, dict_bytes)
}

// ---------------------------------------------------------------------------
// Bench helpers
// ---------------------------------------------------------------------------

fn fresh_chunk<'a>(table: &str) -> Chunk<'a> {
    Chunk::new(table)
}

// ---------------------------------------------------------------------------
// Per-column bulk-append benchmarks
// ---------------------------------------------------------------------------

fn bench_column_i64(c: &mut Criterion) {
    let rows = row_count();
    let data = make_i64_data(rows);
    let mut group = c.benchmark_group("column_i64");
    group.throughput(Throughput::Bytes((rows * 8) as u64));

    group.bench_function("memcpy_baseline", |b| {
        b.iter_batched(
            || Vec::<u8>::with_capacity(rows * 8 + 1),
            |mut out| {
                out.push(0);
                let bytes: &[u8] = unsafe {
                    std::slice::from_raw_parts(
                        data.as_ptr().cast::<u8>(),
                        std::mem::size_of_val(data.as_slice()),
                    )
                };
                out.extend_from_slice(bytes);
                black_box(out);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("column_sender_no_null", |b| {
        b.iter_batched(
            || fresh_chunk("trades"),
            |mut chunk| {
                chunk.column_i64("v", &data, None).unwrap();
                black_box(&chunk);
            },
            BatchSize::SmallInput,
        );
    });

    let bits = make_validity_bits(rows);
    let validity = Validity::from_bitmap(&bits, rows).unwrap();
    group.bench_function("column_sender_nullable", |b| {
        b.iter_batched(
            || fresh_chunk("trades"),
            |mut chunk| {
                chunk.column_i64("v", &data, Some(&validity)).unwrap();
                black_box(&chunk);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_column_f64(c: &mut Criterion) {
    let rows = row_count();
    let data = make_f64_data(rows);
    let mut group = c.benchmark_group("column_f64");
    group.throughput(Throughput::Bytes((rows * 8) as u64));

    group.bench_function("memcpy_baseline", |b| {
        b.iter_batched(
            || Vec::<u8>::with_capacity(rows * 8 + 1),
            |mut out| {
                out.push(0);
                let bytes: &[u8] = unsafe {
                    std::slice::from_raw_parts(
                        data.as_ptr().cast::<u8>(),
                        std::mem::size_of_val(data.as_slice()),
                    )
                };
                out.extend_from_slice(bytes);
                black_box(out);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("column_sender_no_null", |b| {
        b.iter_batched(
            || fresh_chunk("trades"),
            |mut chunk| {
                chunk.column_f64("v", &data, None).unwrap();
                black_box(&chunk);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_column_str(c: &mut Criterion) {
    let rows = row_count();
    let len = varchar_len();
    let (offsets, bytes) = make_varchar(rows, len);
    let mut group = c.benchmark_group("column_str");
    group.throughput(Throughput::Bytes((4 * (rows + 1) + bytes.len()) as u64));

    group.bench_function("memcpy_baseline", |b| {
        b.iter_batched(
            || Vec::<u8>::with_capacity(4 * (rows + 1) + bytes.len() + 1),
            |mut out| {
                out.push(0);
                let offset_bytes: &[u8] = unsafe {
                    std::slice::from_raw_parts(
                        offsets.as_ptr().cast::<u8>(),
                        std::mem::size_of_val(offsets.as_slice()),
                    )
                };
                out.extend_from_slice(offset_bytes);
                out.extend_from_slice(&bytes);
                black_box(out);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("column_sender_no_null", |b| {
        b.iter_batched(
            || fresh_chunk("logs"),
            |mut chunk| {
                chunk.column_str("msg", &offsets, &bytes, None).unwrap();
                black_box(&chunk);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Symbol bulk-intern: column path vs naïve per-row HashMap
// ---------------------------------------------------------------------------

fn bench_symbol_dict(c: &mut Criterion) {
    let rows = row_count();
    let card = symbol_cardinality();
    let (codes, dict_offsets, dict_bytes) = make_symbol_workload(rows, card);
    let mut group = c.benchmark_group("symbol_dict");
    group.throughput(Throughput::Elements(rows as u64));

    // Column-sender path: bulk three-pass intern at append time.
    group.bench_function("column_sender", |b| {
        b.iter_batched(
            || fresh_chunk("ticks"),
            |mut chunk| {
                chunk
                    .symbol_i32("sym", &codes, &dict_offsets, &dict_bytes, None)
                    .unwrap();
                black_box(&chunk);
            },
            BatchSize::SmallInput,
        );
    });

    // Row-API analogue: per-row HashMap probe. Mimics what the legacy
    // path pays for each symbol cell. We don't use the actual row
    // encoder because it owns much more state than this measurement
    // is trying to isolate — the point here is the per-row HashMap
    // hit, which dominates symbol-column cost on the row path.
    group.bench_function("naive_per_row_hashmap", |b| {
        b.iter_batched(
            || {
                let map: HashMap<&[u8], u64> = HashMap::new();
                (map, Vec::<u64>::with_capacity(rows))
            },
            |(mut map, mut gids)| {
                let mut next_id: u64 = 0;
                for &code in &codes {
                    let start = dict_offsets[code as usize] as usize;
                    let end = dict_offsets[code as usize + 1] as usize;
                    let entry: &[u8] = &dict_bytes[start..end];
                    let gid = *map.entry(entry).or_insert_with(|| {
                        let id = next_id;
                        next_id += 1;
                        id
                    });
                    gids.push(gid);
                }
                black_box(&gids);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// End-to-end encode (no network)
// ---------------------------------------------------------------------------

fn encode_chunk_group(c: &mut Criterion) {
    let rows = row_count();
    let i64_data = make_i64_data(rows);
    let f64_data = make_f64_data(rows);
    let (offsets, varchar_bytes) = make_varchar(rows, varchar_len());
    let (codes, dict_offsets, dict_bytes) = make_symbol_workload(rows, symbol_cardinality());
    let ts_data = make_i64_data(rows);

    let mut group = c.benchmark_group("encode_chunk");
    group.sample_size(20); // larger workload — fewer samples
    group.measurement_time(Duration::from_secs(5));
    group.throughput(Throughput::Elements(rows as u64));

    let build_chunk = || {
        let mut chunk = Chunk::new("ticks");
        chunk.column_i64("qty", &i64_data, None).unwrap();
        chunk.column_f64("price", &f64_data, None).unwrap();
        chunk
            .column_str("msg", &offsets, &varchar_bytes, None)
            .unwrap();
        chunk
            .symbol_i32("sym", &codes, &dict_offsets, &dict_bytes, None)
            .unwrap();
        chunk.at_nanos(&ts_data).unwrap();
        chunk
    };

    group.bench_function("populate_only", |b| {
        b.iter_batched(
            || (),
            |_| {
                let chunk = build_chunk();
                black_box(&chunk);
            },
            BatchSize::SmallInput,
        );
    });

    let prebuilt = build_chunk();
    group.bench_function("encode_only", |b| {
        b.iter_batched(
            || {
                (
                    BenchEncoderState::new(),
                    Vec::<u8>::with_capacity(64 * 1024),
                )
            },
            |(mut state, mut out)| {
                out.clear();
                bench_encode_chunk_into(&mut out, &prebuilt, &mut state).unwrap();
                black_box(&out);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("populate_plus_encode", |b| {
        b.iter_batched(
            || {
                (
                    BenchEncoderState::new(),
                    Vec::<u8>::with_capacity(64 * 1024),
                )
            },
            |(mut state, mut out)| {
                let chunk = build_chunk();
                out.clear();
                bench_encode_chunk_into(&mut out, &chunk, &mut state).unwrap();
                black_box(&out);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Timestamp encoding: Gorilla and its raw fallback (no network)
// ---------------------------------------------------------------------------

/// Nanosecond timestamps in the shapes that set the cost of the Gorilla
/// timestamp encoder:
///
/// - `regular`: a fixed 1 ms step. Every delta-of-delta is zero, so the
///   column compresses to one bit per row: the cheapest Gorilla pass.
/// - `jittery`: the same step with up to 50 us of jitter either way. About
///   98% of the delta-of-deltas need the widest code (36 bits): the
///   costliest pass.
/// - `early_fallback`: gaps of up to 10 s. A delta-of-delta leaves the i32
///   range within the first few rows, so the column goes out raw almost at
///   once.
/// - `late_fallback`, `jittery_late_fallback`: `regular` and `jittery` with
///   the last row 3 s late. The column goes out raw only after every other
///   row has been Gorilla-encoded and that work is thrown away. The jittery
///   one is the encoder's worst case.
fn make_ts_shape(shape: &str, rows: usize) -> Vec<i64> {
    const START: i64 = 1_700_000_000_000_000_000;
    const STEP: i64 = 1_000_000;
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move |bound: u64| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        (state % bound) as i64
    };
    let (base, late) = match shape.strip_suffix("late_fallback") {
        Some(base) => (base.strip_suffix('_').unwrap_or("regular"), true),
        None => (shape, false),
    };
    let mut ts: Vec<i64> = match base {
        "regular" => (0..rows as i64).map(|i| START + i * STEP).collect(),
        "jittery" => (0..rows as i64)
            .map(|i| START + i * STEP + next(100_001) - 50_000)
            .collect(),
        "early_fallback" => {
            let mut t = START;
            (0..rows)
                .map(|_| {
                    t += next(10_000_000_000);
                    t
                })
                .collect()
        }
        other => panic!("unknown timestamp shape {other}"),
    };
    if late && let Some(last) = ts.last_mut() {
        *last += 3_000_000_000;
    }
    ts
}

/// One `i8` column plus a nanosecond timestamp. `designated` and `column`
/// carry it as the designated timestamp and as an ordinary column, both from
/// a contiguous slice; `column_with_nulls` has one null row in 16, which
/// takes the per-value writer instead.
///
/// A fallback case ships the bytes a plain copy of the column would, so for
/// `column/*` whatever it costs beyond `raw_copy` is what the Gorilla attempt
/// cost. `raw_copy` is the same data as a DATE column, which is never
/// Gorilla-encoded. `designated/*` also pays the designated timestamp's
/// validation scan, as it does without Gorilla.
fn encode_timestamps_group(c: &mut Criterion) {
    let rows = row_count();
    let flags = vec![1_i8; rows];
    let bits = make_validity_bits(rows);
    let validity = Validity::from_bitmap(&bits, rows).unwrap();

    let mut group = c.benchmark_group("encode_timestamps");
    group.throughput(Throughput::Elements(rows as u64));

    let mut bench = |name: String, chunk: &Chunk<'_>| {
        group.bench_function(name, |b| {
            // One output buffer for the whole run, as a sender reuses its
            // own: this times the encoder, not the allocator.
            let mut state = BenchEncoderState::new();
            let mut out = Vec::new();
            b.iter(|| {
                out.clear();
                bench_encode_chunk_into(&mut out, chunk, &mut state).unwrap();
                black_box(&out);
            });
        });
    };

    let regular = make_ts_shape("regular", rows);
    let mut raw_copy = Chunk::new("ticks");
    raw_copy.column_i8("flag", &flags, None).unwrap();
    raw_copy.column_date("ts2", &regular, None).unwrap();
    raw_copy.at_now().unwrap();
    bench("raw_copy".to_owned(), &raw_copy);

    for shape in [
        "regular",
        "jittery",
        "early_fallback",
        "late_fallback",
        "jittery_late_fallback",
    ] {
        let ts = make_ts_shape(shape, rows);

        let mut designated = Chunk::new("ticks");
        designated.column_i8("flag", &flags, None).unwrap();
        designated.at_nanos(&ts).unwrap();
        bench(format!("designated/{shape}"), &designated);

        let mut column = Chunk::new("ticks");
        column.column_i8("flag", &flags, None).unwrap();
        column
            .column_ts("ts2", &ts, TimestampUnit::Nanos, None)
            .unwrap();
        column.at_now().unwrap();
        bench(format!("column/{shape}"), &column);

        if shape == "early_fallback" {
            let mut with_nulls = Chunk::new("ticks");
            with_nulls.column_i8("flag", &flags, None).unwrap();
            with_nulls
                .column_ts("ts2", &ts, TimestampUnit::Nanos, Some(&validity))
                .unwrap();
            with_nulls.at_now().unwrap();
            bench(format!("column_with_nulls/{shape}"), &with_nulls);
        }
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_column_i64,
    bench_column_f64,
    bench_column_str,
    bench_symbol_dict,
    encode_chunk_group,
    encode_timestamps_group,
);
criterion_main!(benches);
