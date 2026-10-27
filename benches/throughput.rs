use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use viperlog::engine::ScrubScanner;

fn bench_clean_log_scan(c: &mut Criterion) {
    let scanner = ScrubScanner::new();
    let clean_log = "2026-10-27 19:40:12.894 [INFO] [http-worker-4] Status 200 OK GET /api/v1/healthz duration=1.4ms";

    let mut group = c.benchmark_group("Scanner");
    group.throughput(Throughput::Bytes(clean_log.len() as u64));

    group.bench_function("clean_line_zero_copy", |b| {
        b.iter(|| {
            scanner.scrub_line(black_box(clean_log));
        });
    });

    group.finish();
}

fn bench_dirty_log_scan(c: &mut Criterion) {
    let scanner = ScrubScanner::new();
    let dirty_log = "2026-10-27 19:40:14 [WARN] payment failed for card 4532-0150-1234-5674 email alice@example.com token Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";

    let mut group = c.benchmark_group("Scanner");
    group.throughput(Throughput::Bytes(dirty_log.len() as u64));

    group.bench_function("dirty_line_detection_and_mask", |b| {
        b.iter(|| {
            scanner.scrub_line(black_box(dirty_log));
        });
    });

    group.finish();
}

criterion_group!(benches, bench_clean_log_scan, bench_dirty_log_scan);
criterion_main!(benches);
