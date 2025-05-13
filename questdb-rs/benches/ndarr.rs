use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ndarray::{Array, Array2};
use questdb::ingress::{Buffer, ColumnName, StrideArrayView};

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

// bench NdArrayView and StridedArrayView write performance.
fn bench_array_view(c: &mut Criterion) {
    let mut group = c.benchmark_group("write_array_view");
    let col_name = ColumnName::new("col1").unwrap();
    let array: Array2<f64> = Array::ones((1000, 1000));
    let transposed_view = array.t();

    // Case 1
    group.bench_function("ndarray_view", |b| {
        let mut buffer = Buffer::new();
        buffer.table("x1").unwrap();
        b.iter(|| {
            buffer
                .column_arr(col_name, black_box(&transposed_view))
                .unwrap();
        });
        buffer.clear();
    });

    let elem_size = size_of::<f64>() as isize;
    let strides: Vec<isize> = transposed_view
        .strides()
        .iter()
        .map(|&s| s * elem_size) // 转换为字节步长
        .collect();
    let view2: StrideArrayView<'_, f64> = unsafe {
        StrideArrayView::new(
            transposed_view.ndim(),
            transposed_view.shape().as_ptr(),
            strides.as_ptr(),
            transposed_view.as_ptr() as *const u8,
            transposed_view.len() * elem_size as usize,
        )
        .unwrap()
    };

    // Case 2
    group.bench_function("strides_view", |b| {
        let mut buffer = Buffer::new();
        buffer.table("x1").unwrap();
        b.iter(|| {
            buffer.column_arr(col_name, black_box(&view2)).unwrap();
        });
        buffer.clear();
    });
}

criterion_group!(benches, bench_write_array_data, bench_array_view);
criterion_main!(benches);
