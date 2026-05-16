// SPDX-License-Identifier: MIT OR Apache-2.0
//! Criterion benches for `sieve-core`.
//!
//! Phase 0 stub. Real benchmarks land alongside the Scanner orchestrator in
//! Phase 10.

use criterion::{criterion_group, criterion_main, Criterion};
use sieve_core::Scanner;

fn scanner_construction(c: &mut Criterion) {
    c.bench_function("scanner_construction_stub", |b| {
        b.iter(Scanner::default);
    });
}

criterion_group!(benches, scanner_construction);
criterion_main!(benches);
