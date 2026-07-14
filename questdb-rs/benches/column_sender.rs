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
//! Three families:
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
//! Run:
//!
//! ```text
//! cargo bench --features sync-sender-qwp-ws --bench column_sender
//! QUESTDB_COLUMN_BENCH_ROWS=10000000 cargo bench --features sync-sender-qwp-ws --bench column_sender
//! ```

use std::collections::HashMap;
use std::time::Duration;

use criterion::{BatchSize, Criterion, Throughput, black_box, criterion_group, criterion_main};

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
        if row_idx % 16 == 0 {
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

criterion_group!(
    benches,
    bench_column_i64,
    bench_column_f64,
    bench_column_str,
    bench_symbol_dict,
    encode_chunk_group,
);
criterion_main!(benches);
