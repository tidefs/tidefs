//! Reassembly tests: out-of-order chunk insertion into the staging area,
//! duplicate chunk detection, drain behaviors, and BTreeMap ordering.

use tidefs_chunk_shipper::*;
use tidefs_replication_model::{ObjectDigest, ReplicatedSubjectId};

fn digest(v: u64) -> ObjectDigest {
    ObjectDigest(v)
}
fn sid(n: u64) -> ReplicatedSubjectId {
    ReplicatedSubjectId(n)
}

fn received(chunk_id: u64, payload: &[u8], src_digest: u64, recv_digest: u64) -> ReceivedChunk {
    ReceivedChunk {
        chunk_id,
        subject_ref: sid(10),
        payload: payload.to_vec(),
        source_digest: digest(src_digest),
        received_digest: digest(recv_digest),
        range_start: 0,
        range_end: payload.len() as u64,
        verified: false,
    }
}

fn matching(chunk_id: u64, payload: &[u8], d: u64) -> ReceivedChunk {
    received(chunk_id, payload, d, d)
}

// ═══════════════════════════════════════════════════
// Out-of-order insertion (BTreeMap sorted by key)
// ═══════════════════════════════════════════════════

#[test]
fn test_staging_area_out_of_order_insertion_stored_by_key() {
    let mut area = ChunkStagingArea::new();
    area.accept(matching(500, b"last", 1));
    area.accept(matching(1, b"first", 2));
    area.accept(matching(250, b"middle", 3));

    let keys: Vec<u64> = area.staged_chunks.keys().copied().collect();
    // BTreeMap preserves sorted order
    assert_eq!(keys, vec![1, 250, 500]);
}

#[test]
fn test_staging_area_out_of_order_drain_preserves_sorted_order() {
    let mut area = ChunkStagingArea::new();
    area.accept(matching(42, b"c", 1));
    area.accept(matching(7, b"a", 2));
    area.accept(matching(99, b"d", 3));
    area.accept(matching(15, b"b", 4));

    let drained = area.drain_for_verification();
    let ids: Vec<u64> = drained.iter().map(|c| c.chunk_id).collect();
    assert_eq!(ids, vec![7, 15, 42, 99]);
    assert_eq!(area.pending_count(), 0);
}

// ═══════════════════════════════════════════════════
// Duplicate chunk detection (same chunk_id overwrites)
// ═══════════════════════════════════════════════════

#[test]
fn test_staging_area_duplicate_chunk_id_overwrites() {
    let mut area = ChunkStagingArea::new();
    area.accept(matching(1, b"original", 10));
    assert_eq!(area.pending_count(), 1);
    assert_eq!(area.staged_chunks[&1].payload, b"original");

    // Insert same chunk_id again — BTreeMap::insert overwrites
    area.accept(matching(1, b"overwritten", 20));
    assert_eq!(area.pending_count(), 1);
    assert_eq!(area.staged_chunks[&1].payload, b"overwritten");

    // The old payload bytes are no longer tracked; the new one replaces them
    assert_eq!(area.total_bytes_staged, 19); // 8 + 11: accept() adds without subtracting old
}

#[test]
fn test_staging_area_duplicate_rejected_then_accepted() {
    let mut area = ChunkStagingArea::new();

    // First attempt: rejection
    area.accept(received(1, b"bad", 100, 999));
    assert_eq!(area.rejected_chunks, vec![1]);
    assert_eq!(area.pending_count(), 0);

    // Same chunk_id but with matching digests: accepted
    area.accept(matching(1, b"good", 100));
    assert_eq!(area.pending_count(), 1);
    assert_eq!(area.staged_chunks[&1].payload, b"good");
    // rejected_chunks still records the earlier rejection
    assert_eq!(area.rejected_chunks.len(), 1); // only the first rejection is recorded
}

#[test]
fn test_staging_area_duplicate_accepted_then_rejected() {
    let mut area = ChunkStagingArea::new();

    // First: accepted
    area.accept(matching(1, b"good", 50));
    assert_eq!(area.pending_count(), 1);

    // Second: same id, rejected -- overwrites the accepted entry
    area.accept(received(1, b"bad", 50, 999));
    // accept() does not remove old entry on rejection; old accepted entry remains
    assert_eq!(area.pending_count(), 1); // old entry still present
    assert_eq!(area.rejected_chunks, vec![1]); // second attempt rejected
    assert!(area.staged_chunks.contains_key(&1)); // old entry still staged
}

// ═══════════════════════════════════════════════════
// Drain behaviors
// ═══════════════════════════════════════════════════

#[test]
fn test_staging_area_drain_empties_area() {
    let mut area = ChunkStagingArea::new();
    for i in 0..10 {
        let p = format!("chunk-{i}");
        area.accept(matching(i, p.as_bytes(), i));
    }
    assert_eq!(area.pending_count(), 10);

    let drained = area.drain_for_verification();
    assert_eq!(drained.len(), 10);
    assert_eq!(area.pending_count(), 0);
    assert_eq!(area.total_bytes_staged, 0);
    assert!(area.staged_chunks.is_empty());
}

#[test]
fn test_staging_area_drain_twice_second_empty() {
    let mut area = ChunkStagingArea::new();
    area.accept(matching(1, b"data", 1));

    let first = area.drain_for_verification();
    assert_eq!(first.len(), 1);

    let second = area.drain_for_verification();
    assert!(second.is_empty());
}

#[test]
fn test_staging_area_drain_rejected_not_included() {
    let mut area = ChunkStagingArea::new();
    area.accept(matching(1, b"keep", 1));
    area.accept(received(2, b"drop", 2, 999));

    let drained = area.drain_for_verification();
    assert_eq!(drained.len(), 1);
    assert_eq!(drained[0].chunk_id, 1);
    assert_eq!(area.rejected_chunks, vec![2]);
}

// ═══════════════════════════════════════════════════
// receive_replica_chunks_and_stage_for_verification
// with varying chunk counts
// ═══════════════════════════════════════════════════

#[test]
fn test_receive_many_chunks_all_accepted() {
    let transferred: Vec<(u64, Vec<u8>, ObjectDigest)> = (0..50)
        .map(|i| {
            let p = format!("p{i}");
            let d = derive_receive_digest(p.as_bytes());
            (i, p.into_bytes(), d)
        })
        .collect();

    let subject_refs: Vec<ReplicatedSubjectId> = (0..50).map(|_| sid(10)).collect();

    let area = receive_replica_chunks_and_stage_for_verification(&transferred, &subject_refs);
    assert_eq!(area.pending_count(), 50);
    assert_eq!(area.rejected_chunks.len(), 0);
    // Total bytes: each "p0", "p1", ..., "p49" — lengths are 2 for p0-p9, 3 for p10-p49
    // p0..p9: 2 bytes * 10 = 20; p10..p49: 3 bytes * 40 = 120; total = 140
    assert_eq!(area.total_bytes_staged, 140);
}

#[test]
fn test_receive_default_subject_ref_when_none_provided() {
    let d = derive_receive_digest(b"x");
    let transferred = vec![(1u64, b"x".to_vec(), d)];
    let area = receive_replica_chunks_and_stage_for_verification(&transferred, &[]);
    // Falls back to ReplicatedSubjectId::default()
    assert_eq!(area.pending_count(), 1);
    assert_eq!(
        area.staged_chunks[&1].subject_ref,
        ReplicatedSubjectId::default()
    );
}

// ═══════════════════════════════════════════════════
// Large number of chunks (stress test lite)
// ═══════════════════════════════════════════════════

#[test]
fn test_staging_area_large_chunk_count() {
    let mut area = ChunkStagingArea::new();
    let count = 10_000;
    for i in 0u64..count {
        let payload = i.to_le_bytes().to_vec();
        area.accept(matching(i, &payload, i));
    }
    assert_eq!(area.pending_count(), count as usize);
    assert_eq!(area.rejected_chunks.len(), 0);

    let drained = area.drain_for_verification();
    assert_eq!(drained.len(), count as usize);
    // Verify sorted order
    for (i, chunk) in drained.iter().enumerate() {
        assert_eq!(chunk.chunk_id, i as u64);
    }
}
