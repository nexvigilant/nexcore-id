//! Benchmark comparison: nexcore-id vs uuid crate
//!
//! Run with: `cargo bench -p nexcore-id`

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};

fn bench_v4_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("v4_generation");
    group.throughput(Throughput::Elements(1));

    group.bench_function("nexcore_id::NexId::v4", |b| {
        b.iter(|| black_box(nexcore_id::NexId::v4()))
    });

    group.bench_function("uuid::Uuid::new_v4", |b| {
        b.iter(|| black_box(uuid::Uuid::new_v4()))
    });

    group.finish();
}

fn bench_v7_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("v7_generation");
    group.throughput(Throughput::Elements(1));

    group.bench_function("nexcore_id::NexId::v7", |b| {
        b.iter(|| black_box(nexcore_id::NexId::v7()))
    });

    group.bench_function("uuid::Uuid::now_v7", |b| {
        b.iter(|| black_box(uuid::Uuid::now_v7()))
    });

    group.finish();
}

fn bench_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("parsing");
    let uuid_str = "550e8400-e29b-41d4-a716-446655440000";
    group.throughput(Throughput::Elements(1));

    group.bench_function("nexcore_id::parse", |b| {
        b.iter(|| black_box(uuid_str.parse::<nexcore_id::NexId>()))
    });

    group.bench_function("uuid::parse", |b| {
        b.iter(|| black_box(uuid_str.parse::<uuid::Uuid>()))
    });

    group.finish();
}

fn bench_formatting(c: &mut Criterion) {
    let mut group = c.benchmark_group("formatting");
    let nex_id = nexcore_id::NexId::v4();
    let uuid_id = uuid::Uuid::new_v4();
    group.throughput(Throughput::Elements(1));

    group.bench_function("nexcore_id::to_string", |b| {
        b.iter(|| black_box(nex_id.to_string()))
    });

    group.bench_function("uuid::to_string", |b| {
        b.iter(|| black_box(uuid_id.to_string()))
    });

    group.finish();
}

fn bench_batch_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_1000");
    group.throughput(Throughput::Elements(1000));

    group.bench_function("nexcore_id::v4_batch", |b| {
        b.iter(|| {
            let ids: Vec<_> = (0..1000).map(|_| nexcore_id::NexId::v4()).collect();
            black_box(ids)
        })
    });

    group.bench_function("uuid::v4_batch", |b| {
        b.iter(|| {
            let ids: Vec<_> = (0..1000).map(|_| uuid::Uuid::new_v4()).collect();
            black_box(ids)
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_v4_generation,
    bench_v7_generation,
    bench_parsing,
    bench_formatting,
    bench_batch_generation,
);

criterion_main!(benches);
