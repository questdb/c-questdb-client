use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ndarray::{Array, Array2};
use questdb::ingress::{Buffer, ColumnName};
use questdb_client::StrideArrayView;

// benches NdArrayView and StridedArrayView write performance.
fn bench_array_view(c: &mut Criterion) {
    let mut group = c.benchmark_group("write_array_view");
    let col_name = ColumnName::new("col1").unwrap();
    let array: Array2<f64> = Array::ones((1000, 1000));
    let transposed_view = array.t();

    // Case 1
    group.bench_function("ndarray_view", |b| {
        let mut buffer = Buffer::new(questdb::ingress::ProtocolVersion::V2);
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
        .map(|&s| s * elem_size)
        .collect();
    let view2: StrideArrayView<'_, f64, 1> = unsafe {
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
        let mut buffer = Buffer::new(questdb::ingress::ProtocolVersion::V2);
        buffer.table("x1").unwrap();
        b.iter(|| {
            buffer.column_arr(col_name, black_box(&view2)).unwrap();
        });
        buffer.clear();
    });
}

criterion_group!(benches, bench_array_view);
criterion_main!(benches);