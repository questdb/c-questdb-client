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

//! Decoder hot-path criterion benchmark.
//!
//! Anchors the perf claims from commits `8ec0a85` ("zero-copy decode of
//! RESULT_BATCH payloads") and `1163d43` ("tighter SYMBOL + VARCHAR
//! decode hot paths"). Without an in-tree benchmark the PR's
//! "11.6 M → 13.3 M rows/s" / "754 ms → ~625 ms" numbers are
//! unreproducible and the next decoder refactor cannot be
//! regression-guarded.
//!
//! Workload (matches the PR description verbatim, modulo `column_count`
//! to hit the stated 15):
//!
//!   * **5 SYMBOL** columns, each with 10 000 distinct dict entries
//!     (`sym-{seed}-{i}` UUID-ish strings). Row codes are spread
//!     pseudo-randomly across the dict via a splitmix step so the
//!     code-densification loop sees a realistic varint mix (1–2 bytes
//!     most rows, occasional 3 bytes).
//!   * **1 VARCHAR** column cycling through a pool of 10 distinct
//!     short strings ("GET /api/v1/users" etc.).
//!   * **7 fixed-width** columns: `BOOLEAN`, `SHORT`, `INT`,
//!     `LONG` × 2, `FLOAT`, `DOUBLE`, `IPV4` — covers every fixed-
//!     width decoder path (`expect_no_validity_flag`-style and the
//!     standard nullable `decode_fixed` path).
//!   * **1 TIMESTAMP** column (μs since epoch, regularly spaced).
//!   * Total: **15 columns**.
//!
//! Default row count is 100 000 to keep CI iteration time bounded
//! (one batch decodes in single-digit ms; criterion's default 100
//! samples completes in well under a minute). Set
//! `QUESTDB_BENCH_ROWS=1000000` to reproduce the PR's 1M-row-per-batch
//! number directly — note `decoder::MAX_ROWS_PER_BATCH` caps single
//! batches at ~1.05M rows, so the 10M-row aggregate figure from the
//! PR description corresponds to ten of these decodes.
//!
//! Run:
//!
//! ```text
//! cargo bench --features sync-reader-ws --bench decoder
//! QUESTDB_BENCH_ROWS=1000000 cargo bench --features sync-reader-ws --bench decoder
//! ```

use std::time::Duration;

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};

#[cfg(feature = "polars")]
use questdb::egress::_bench_internals::bench_batch_to_polars;
#[cfg(feature = "arrow")]
use questdb::egress::_bench_internals::bench_batch_to_record_batch;
use questdb::egress::_bench_internals::{
    Bytes, Schema, SymbolDict, ZstdScratch, decode_result_batch,
};
use questdb::egress::ColumnKind;
#[cfg(feature = "polars")]
use questdb::egress::arrow::polars::record_batch_to_dataframe;

// ---------------------------------------------------------------------------
// Wire-format helpers. Replicate the minimum of what the decoder's tests
// `BatchBuilder` does — kept inline so the bench is self-contained.
// ---------------------------------------------------------------------------

/// Wire byte for the `RESULT_BATCH` message kind.
const MSG_KIND_RESULT_BATCH: u8 = 0x11;
/// `decode_validity`'s convention for the null_flag prefix when the
/// column body carries no bitmap.
const NULL_FLAG_NONE: u8 = 0x00;

fn varint_u64(mut v: u64, out: &mut Vec<u8>) {
    while v & !0x7F != 0 {
        out.push(((v & 0x7F) as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

// ---------------------------------------------------------------------------
// Per-column body synthesisers. All use the no-nulls layout
// (`null_flag = 0x00`, no bitmap) — matches the realistic "wide read"
// case the perf commits actually targeted and exercises the no-null
// fast paths in `densify_fixed` / `decode_codes_no_nulls` /
// `decode_varlen`.
// ---------------------------------------------------------------------------

/// QWP `BOOLEAN`: non-nullable on the wire, bit-packed into
/// `ceil(row_count/8)` bytes.
fn boolean_body(row_count: usize) -> Vec<u8> {
    let bit_bytes = row_count.div_ceil(8);
    let mut out = Vec::with_capacity(1 + bit_bytes);
    out.push(NULL_FLAG_NONE);
    out.resize(1 + bit_bytes, 0);
    for row in 0..row_count {
        // Mix some pattern so the bit reader doesn't get a constant
        // input. Every 3rd row is `true`.
        if row % 3 == 0 {
            out[1 + (row >> 3)] |= 1 << (row & 7);
        }
    }
    out
}

/// QWP `SHORT` (i16): non-nullable on the wire.
fn short_body(row_count: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + row_count * 2);
    out.push(NULL_FLAG_NONE);
    for i in 0..row_count {
        let v = ((i as i32).wrapping_mul(7) & 0xFFFF) as i16;
        out.extend_from_slice(&v.to_le_bytes());
    }
    out
}

/// Standard nullable fixed-width body: `null_flag=0x00` + tightly
/// packed LE bytes. Used by `INT`, `LONG`, `FLOAT`, `DOUBLE`, `IPV4`,
/// and the raw-encoded `TIMESTAMP`.
fn fixed_le_bytes<F, const N: usize>(row_count: usize, mut write: F) -> Vec<u8>
where
    F: FnMut(usize) -> [u8; N],
{
    let mut out = Vec::with_capacity(1 + row_count * N);
    out.push(NULL_FLAG_NONE);
    for i in 0..row_count {
        out.extend_from_slice(&write(i));
    }
    out
}

/// QWP `SYMBOL` column-local layout (FLAG_DELTA_SYMBOL_DICT clear):
/// `null_flag=0x00` then `varint dict_size`, then `dict_size`
/// `(varint entry_len + entry_bytes)` pairs, then `row_count` varint
/// row codes. Codes are spread across the dict via a splitmix step so
/// the varint mix is realistic (1-byte for codes < 128, 2-byte up to
/// 16 383, 3-byte beyond — matches what a server-side high-cardinality
/// SYMBOL column emits).
fn symbol_body(row_count: usize, dict_size: usize, seed: u64) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(NULL_FLAG_NONE);
    varint_u64(dict_size as u64, &mut out);
    // Dict entries: ~16 bytes each (UUID-ish content).
    for i in 0..dict_size {
        let entry = format!(
            "sym-{:08x}-{:04x}",
            (seed as usize).wrapping_add(i),
            i & 0xFFFF
        );
        varint_u64(entry.len() as u64, &mut out);
        out.extend_from_slice(entry.as_bytes());
    }
    // Row codes: splitmix64-driven pseudo-uniform draw from `[0, dict_size)`.
    let mut state: u64 = seed | 1;
    for _ in 0..row_count {
        state = state.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        let mixed = state ^ (state >> 32);
        let code = (mixed as usize) % dict_size;
        varint_u64(code as u64, &mut out);
    }
    out
}

/// QWP `VARCHAR` (no nulls): `null_flag=0x00`, then `(row_count + 1) × u32`
/// compact offsets, then concatenated string bytes. Cycles through a
/// small pool of distinct strings so the decoder's UTF-8 validation
/// and dense-offset reuse fast path are both exercised on realistic
/// content.
fn varchar_body(row_count: usize) -> Vec<u8> {
    const POOL: &[&str] = &[
        "GET /api/v1/users",
        "POST /api/v1/orders",
        "PUT /api/v1/users/42",
        "DELETE /api/v1/sessions/abc",
        "GET /metrics",
        "GET /healthz",
        "POST /api/v1/auth/login",
        "GET /api/v1/products?page=1&limit=20",
        "OPTIONS /api/v1/cors",
        "GET /static/main.js?v=2",
    ];
    let mut data: Vec<u8> = Vec::new();
    let mut offsets: Vec<u32> = Vec::with_capacity(row_count + 1);
    offsets.push(0);
    for i in 0..row_count {
        let s = POOL[i % POOL.len()];
        data.extend_from_slice(s.as_bytes());
        offsets.push(data.len() as u32);
    }
    let mut out = Vec::with_capacity(1 + offsets.len() * 4 + data.len());
    out.push(NULL_FLAG_NONE);
    for o in &offsets {
        out.extend_from_slice(&o.to_le_bytes());
    }
    out.extend_from_slice(&data);
    out
}

// ---------------------------------------------------------------------------
// Workload assembly.
// ---------------------------------------------------------------------------

struct ColSpec {
    name: &'static str,
    kind: ColumnKind,
    body: Vec<u8>,
}

/// Synthesise a single `RESULT_BATCH` payload (post-FrameHeader bytes,
/// matching the `decode_result_batch` input type). Constructs a
/// 15-column schema (5 SYMBOL + 1 VARCHAR + 7 fixed-width + 1
/// TIMESTAMP + 1 LONG → 15 columns total) with `row_count` rows per
/// column.
fn build_workload(row_count: usize) -> Bytes {
    let cols: Vec<ColSpec> = vec![
        // 5 SYMBOL columns — high-cardinality, distinct seeds so the
        // splitmix code stream differs per column and the decoder's
        // SYMBOL dict isn't accidentally reused across columns.
        ColSpec {
            name: "sym0",
            kind: ColumnKind::Symbol,
            body: symbol_body(row_count, 10_000, 1),
        },
        ColSpec {
            name: "sym1",
            kind: ColumnKind::Symbol,
            body: symbol_body(row_count, 10_000, 2),
        },
        ColSpec {
            name: "sym2",
            kind: ColumnKind::Symbol,
            body: symbol_body(row_count, 10_000, 3),
        },
        ColSpec {
            name: "sym3",
            kind: ColumnKind::Symbol,
            body: symbol_body(row_count, 10_000, 4),
        },
        ColSpec {
            name: "sym4",
            kind: ColumnKind::Symbol,
            body: symbol_body(row_count, 10_000, 5),
        },
        // 1 VARCHAR.
        ColSpec {
            name: "url",
            kind: ColumnKind::Varchar,
            body: varchar_body(row_count),
        },
        // 7 fixed-width.
        ColSpec {
            name: "active",
            kind: ColumnKind::Boolean,
            body: boolean_body(row_count),
        },
        ColSpec {
            name: "kind",
            kind: ColumnKind::Short,
            body: short_body(row_count),
        },
        ColSpec {
            name: "count",
            kind: ColumnKind::Int,
            body: fixed_le_bytes(row_count, |i| (i as i32).to_le_bytes()),
        },
        ColSpec {
            name: "user_id",
            kind: ColumnKind::Long,
            body: fixed_le_bytes(row_count, |i| (i as i64).to_le_bytes()),
        },
        ColSpec {
            name: "duration_us",
            kind: ColumnKind::Long,
            body: fixed_le_bytes(row_count, |i| ((i as i64).wrapping_mul(17)).to_le_bytes()),
        },
        ColSpec {
            name: "duration_s",
            kind: ColumnKind::Float,
            body: fixed_le_bytes(row_count, |i| ((i as f32) * 0.5).to_le_bytes()),
        },
        ColSpec {
            name: "amount",
            kind: ColumnKind::Double,
            body: fixed_le_bytes(row_count, |i| ((i as f64) * 0.25).to_le_bytes()),
        },
        ColSpec {
            name: "src_ip",
            kind: ColumnKind::Ipv4,
            body: fixed_le_bytes(row_count, |i| (i as u32).to_le_bytes()),
        },
        // 1 TIMESTAMP (microseconds).
        ColSpec {
            name: "ts",
            kind: ColumnKind::Timestamp,
            body: fixed_le_bytes(row_count, |i| {
                let base: i64 = 1_700_000_000_000_000;
                (base + (i as i64) * 1_000_000).to_le_bytes()
            }),
        },
    ];
    assert_eq!(
        cols.len(),
        15,
        "workload spec calls for 15 columns; got {}",
        cols.len()
    );

    serialize_batch(&cols, row_count)
}

/// Serialise a column set into a single `RESULT_BATCH` payload (the
/// post-FrameHeader bytes `decode_result_batch` consumes). Shared by
/// the 15-column wide workload and the S1 narrow workload.
fn serialize_batch(cols: &[ColSpec], row_count: usize) -> Bytes {
    let mut out = Vec::new();
    // Frame prefix: msg_kind + request_id + batch_seq.
    out.push(MSG_KIND_RESULT_BATCH);
    out.extend_from_slice(&1i64.to_le_bytes());
    varint_u64(0, &mut out);

    // Table block: empty table name, row count, col count.
    varint_u64(0, &mut out);
    varint_u64(row_count as u64, &mut out);
    varint_u64(cols.len() as u64, &mut out);

    // Columns inline: per-column (name, kind). No schema-mode byte, no schema id.
    for c in cols {
        varint_u64(c.name.len() as u64, &mut out);
        out.extend_from_slice(c.name.as_bytes());
        out.push(c.kind.as_u8());
    }

    // Per-column bodies, in declaration order.
    for c in cols {
        out.extend_from_slice(&c.body);
    }

    Bytes::from(out)
}

/// Synthesise the **S1 narrow** `RESULT_BATCH` payload (plan §3.1): the
/// 5-column headline schema the cross-client parity table reads back —
/// `ts` TIMESTAMP, `id` LONG, `price` DOUBLE, `sym` SYMBOL (card 8),
/// `note` VARCHAR (~16 bytes). This is the workload behind the
/// `→ polars DataFrame` decoder arm: it matches the S1 examples and,
/// unlike the wide 15-col workload, sticks to the dtypes the crate's
/// minimal polars feature set (`dtype-categorical` only — no `dtype-i16`
/// / `dtype-i8`) can build a `Series` from.
#[cfg(feature = "arrow")]
fn build_s1_workload(row_count: usize) -> Bytes {
    let cols: Vec<ColSpec> = vec![
        ColSpec {
            name: "ts",
            kind: ColumnKind::Timestamp,
            body: fixed_le_bytes(row_count, |i| {
                let base: i64 = 1_700_000_000_000_000;
                // 1 µs spacing — mirrors the S1 monotonic-unique ts.
                (base + (i as i64)).to_le_bytes()
            }),
        },
        ColSpec {
            name: "id",
            kind: ColumnKind::Long,
            body: fixed_le_bytes(row_count, |i| (i as i64).to_le_bytes()),
        },
        ColSpec {
            name: "price",
            kind: ColumnKind::Double,
            body: fixed_le_bytes(row_count, |i| ((i as f64) * 0.25).to_le_bytes()),
        },
        ColSpec {
            name: "sym",
            kind: ColumnKind::Symbol,
            // Cardinality 8 to match the S1 SYMBOL column.
            body: symbol_body(row_count, 8, 1),
        },
        ColSpec {
            name: "note",
            kind: ColumnKind::Varchar,
            body: varchar_body(row_count),
        },
    ];
    serialize_batch(&cols, row_count)
}

// ---------------------------------------------------------------------------
// Criterion harness.
// ---------------------------------------------------------------------------

fn bench_decoder(c: &mut Criterion) {
    let row_count: usize = std::env::var("QUESTDB_BENCH_ROWS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100_000);

    let payload = build_workload(row_count);

    // Sanity-decode once before entering Criterion's iteration loop so
    // a wire-layout bug in the synthesiser surfaces as a clear panic
    // before the harness starts amortising samples over a broken
    // payload.
    {
        let mut dict = SymbolDict::new();
        let mut reg: Option<Schema> = None;
        let mut scratch = ZstdScratch::new();
        let batch = decode_result_batch(&payload, 0, &mut dict, &mut reg, &mut scratch)
            .expect("synthesised workload must decode cleanly");
        assert_eq!(batch.row_count, row_count, "row count round-trip");
        assert_eq!(batch.columns.len(), 15, "column count round-trip");
    }

    let mut group = c.benchmark_group("decoder");
    group.throughput(Throughput::Elements(row_count as u64));
    // Bigger batches need fewer samples to converge — and the default
    // sample size of 100 would have 1M-row runs take ~minutes.
    if row_count >= 500_000 {
        group.sample_size(20);
        group.measurement_time(Duration::from_secs(15));
    }
    group.bench_function(
        format!("realistic_15col_{}_rows_per_batch", row_count),
        |b| {
            b.iter(|| {
                let mut dict = SymbolDict::new();
                let mut reg: Option<Schema> = None;
                let mut scratch = ZstdScratch::new();
                let batch =
                    decode_result_batch(black_box(&payload), 0, &mut dict, &mut reg, &mut scratch)
                        .expect("decode");
                black_box(batch);
            });
        },
    );

    // Decode→assemble arms (plan §6 / §3.6) on the **S1 narrow** schema (the
    // shape the cross-client parity table reads back; the wide 15-col workload
    // above carries Int16/Int8 columns the crate's minimal polars feature set
    // can't build a Series from). Three nested floors so subtraction isolates
    // each stage:
    //   * `_decode`     — wire bytes → `DecodedBatch` (raw decode floor).
    //   * `_to_arrow`   — `+ batch_to_record_batch` (DecodedBatch → Arrow,
    //                     i.e. `convert.rs` column build). `_to_arrow − _decode`
    //                     is the Arrow assemble cost.
    //   * `_to_polars`  — `+ record_batch_to_dataframe` (Arrow → polars via the
    //                     C Data Interface). `_to_polars − _to_arrow` is the
    //                     polars FFI / `Series::from_arrow` cost.
    // `_decode` and `_to_arrow` need only `arrow` (stable toolchain); `_to_polars`
    // needs `polars`.
    #[cfg(feature = "arrow")]
    {
        let s1_payload = build_s1_workload(row_count);
        {
            let mut dict = SymbolDict::new();
            let mut reg: Option<Schema> = None;
            let mut scratch = ZstdScratch::new();
            let batch = decode_result_batch(&s1_payload, 0, &mut dict, &mut reg, &mut scratch)
                .expect("synthesised S1 workload must decode cleanly");
            assert_eq!(batch.row_count, row_count, "S1 row count round-trip");
            assert_eq!(batch.columns.len(), 5, "S1 column count round-trip");
            let schema = reg.as_ref().expect("schema populated by decode");
            let rb = bench_batch_to_record_batch(schema, batch, &dict)
                .expect("S1 batch must assemble into an arrow RecordBatch");
            assert_eq!(rb.num_rows(), row_count, "S1 arrow row round-trip");
            assert_eq!(rb.num_columns(), 5, "S1 arrow column round-trip");
            #[cfg(feature = "polars")]
            {
                // `bench_batch_to_record_batch` consumed the first decode; the
                // polars pre-flight re-decodes the same payload.
                let mut dict = SymbolDict::new();
                let mut reg: Option<Schema> = None;
                let mut scratch = ZstdScratch::new();
                let batch = decode_result_batch(&s1_payload, 0, &mut dict, &mut reg, &mut scratch)
                    .expect("synthesised S1 workload must decode cleanly");
                let schema = reg.as_ref().expect("schema populated by decode");
                let df = bench_batch_to_polars(schema, batch, &dict)
                    .expect("S1 batch must assemble into a polars DataFrame");
                assert_eq!(df.height(), row_count, "S1 polars height round-trip");
                assert_eq!(df.width(), 5, "S1 polars width round-trip");
            }
        }
        group.bench_function(format!("s1_5col_{}_rows_decode", row_count), |b| {
            b.iter(|| {
                let mut dict = SymbolDict::new();
                let mut reg: Option<Schema> = None;
                let mut scratch = ZstdScratch::new();
                let batch = decode_result_batch(
                    black_box(&s1_payload),
                    0,
                    &mut dict,
                    &mut reg,
                    &mut scratch,
                )
                .expect("decode");
                black_box(batch);
            });
        });
        group.bench_function(format!("s1_5col_{}_rows_to_arrow", row_count), |b| {
            b.iter(|| {
                let mut dict = SymbolDict::new();
                let mut reg: Option<Schema> = None;
                let mut scratch = ZstdScratch::new();
                let batch = decode_result_batch(
                    black_box(&s1_payload),
                    0,
                    &mut dict,
                    &mut reg,
                    &mut scratch,
                )
                .expect("decode");
                let schema = reg.as_ref().expect("schema populated by decode");
                let rb = bench_batch_to_record_batch(schema, batch, &dict)
                    .expect("decoded batch must assemble into an arrow RecordBatch");
                black_box(rb);
            });
        });
        #[cfg(feature = "polars")]
        group.bench_function(format!("s1_5col_{}_rows_to_polars", row_count), |b| {
            b.iter(|| {
                let mut dict = SymbolDict::new();
                let mut reg: Option<Schema> = None;
                let mut scratch = ZstdScratch::new();
                let batch = decode_result_batch(
                    black_box(&s1_payload),
                    0,
                    &mut dict,
                    &mut reg,
                    &mut scratch,
                )
                .expect("decode");
                let schema = reg.as_ref().expect("schema populated by decode");
                let df = bench_batch_to_polars(schema, batch, &dict)
                    .expect("decoded batch must assemble into a polars DataFrame");
                black_box(df);
            });
        });
        // Per-column probe of `record_batch_to_dataframe` (decode/convert once,
        // outside the loop): `col_id` is the zero-copy baseline; `col_sym/col_note`
        // minus it isolate the Dictionary→Categorical / Utf8→Utf8View costs.
        #[cfg(feature = "polars")]
        {
            let rb = {
                let mut dict = SymbolDict::new();
                let mut reg: Option<Schema> = None;
                let mut scratch = ZstdScratch::new();
                let batch = decode_result_batch(&s1_payload, 0, &mut dict, &mut reg, &mut scratch)
                    .expect("decode");
                let schema = reg.as_ref().expect("schema populated by decode");
                bench_batch_to_record_batch(schema, batch, &dict)
                    .expect("S1 batch must assemble into an arrow RecordBatch")
            };
            group.bench_function(
                format!("s1_5col_{}_rows_to_polars_col_id", row_count),
                |b| {
                    b.iter(|| {
                        let sub = rb.project(&[1]).expect("project");
                        black_box(record_batch_to_dataframe(sub).expect("to df"));
                    });
                },
            );
            group.bench_function(
                format!("s1_5col_{}_rows_to_polars_col_sym", row_count),
                |b| {
                    b.iter(|| {
                        let sub = rb.project(&[3]).expect("project");
                        black_box(record_batch_to_dataframe(sub).expect("to df"));
                    });
                },
            );
            group.bench_function(
                format!("s1_5col_{}_rows_to_polars_col_note", row_count),
                |b| {
                    b.iter(|| {
                        let sub = rb.project(&[4]).expect("project");
                        black_box(record_batch_to_dataframe(sub).expect("to df"));
                    });
                },
            );
        }
    }

    group.finish();
}

criterion_group!(benches, bench_decoder);
criterion_main!(benches);
