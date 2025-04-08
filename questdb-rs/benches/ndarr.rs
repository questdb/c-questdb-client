use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ndarray::{Array, Array2};
use questdb::ingress::{Buffer, ColumnName};

/// run with
/// ```shell
/// cargo bench --bench ndarr --features="benchmark, ndarray"
/// ```
fn bench_write_array_data(c: &mut Criterion) {
    let mut group = c.benchmark_group("write_array_data");
    let contiguous_array: Array2<f64> = Array::zeros((1000, 1000));
    let non_contiguous_array = contiguous_array.t();
    assert!(contiguous_array.is_standard_layout());
    assert!(!non_contiguous_array.is_standard_layout());

    let col_name = ColumnName::new("col1").unwrap();
    // Case 1
    group.bench_function("contiguous_writer", |b| {
        let mut buffer = Buffer::new();
        buffer.table("x1").unwrap();
        b.iter(|| {
            buffer
                .column_arr(col_name, black_box(&contiguous_array.view()))
                .unwrap();
        });
        buffer.clear();
    });

    // Case 2
    group.bench_function("contiguous_raw_buffer", |b| {
        let mut buffer = Buffer::new();
        buffer.table("x1").unwrap();
        b.iter(|| {
            buffer
                .column_arr_use_raw_buffer(col_name, black_box(&contiguous_array.view()))
                .unwrap();
        });
        buffer.clear();
    });

    // Case 3
    group.bench_function("non_contiguous_writer", |b| {
        let mut buffer = Buffer::new();
        buffer.table("x1").unwrap();
        b.iter(|| {
            buffer
                .column_arr(col_name, black_box(&non_contiguous_array.view()))
                .unwrap();
        });
        buffer.clear();
    });

    // Case 4
    group.bench_function("non_contiguous_raw_buffer", |b| {
        let mut buffer = Buffer::new();
        buffer.table("x1").unwrap();
        b.iter(|| {
            buffer
                .column_arr_use_raw_buffer(col_name, black_box(&non_contiguous_array.view()))
                .unwrap();
        });
        buffer.clear();
    });

    group.finish();
}

criterion_group!(benches, bench_write_array_data);
criterion_main!(benches);
