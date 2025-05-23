use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use merkle_toolkit::MerkleTree;
use sha2::{Digest, Sha256};
use std::time::Duration;

/// Build a Merkle tree with the given depth (2^depth leaves)
fn build_tree(depth: usize) -> MerkleTree {
    let mut tree = MerkleTree::new(depth);
    for i in 0u32..(1u32 << depth) {
        tree.append_leaf(Sha256::digest(i.to_le_bytes()).into());
    }
    tree
}

/// Benchmark both the unoptimized and optimized get_proof methods
fn bench_get_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_proof");
    group
        .sample_size(30)
        .measurement_time(Duration::from_secs(15));

    let depth = 20;
    let tree = build_tree(depth);
    let index = 1 << (depth - 1); // Use a middle index

    group.bench_function(BenchmarkId::new("get_proof", index), |b| {
        b.iter(|| {
            let result = tree.get_proof(black_box(index));
            black_box(result);
        })
    });

    group.bench_function(BenchmarkId::new("get_proof_optimized", index), |b| {
        b.iter(|| {
            let result = tree.get_proof_optimized(black_box(index));
            black_box(result);
        })
    });

    group.finish();
}

criterion_group!(benches, bench_get_proof);
criterion_main!(benches);
