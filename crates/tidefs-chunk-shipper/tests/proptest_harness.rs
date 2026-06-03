//! Deterministic property-like fuzz tests for tidefs-chunk-shipper.
//!
//! Exercises the same invariants as property-based testing would,
//! using a curated corpus of payload byte sequences, digest values,
//! and struct field combinations instead of random generation.

use tidefs_chunk_shipper::*;
use tidefs_membership_epoch::MemberId;
use tidefs_replication_model::{
    ObjectDigest, ReplicaTransferTicketRecord, ReplicatedReceiptId, ReplicatedSubjectId,
};

fn member(n: u64) -> MemberId {
    MemberId(n)
}
fn rid(n: u64) -> ReplicatedReceiptId {
    ReplicatedReceiptId(n)
}

/// A curated corpus of payloads covering:
/// - empty, single-byte, small, medium, large, power-of-2 sizes,
///   repeating patterns, random-looking bytes, all-zero, all-0xFF,
///   ASCII text, binary, and boundary-sitting bytes.
fn payload_corpus() -> Vec<Vec<u8>> {
    vec![
        vec![],
        vec![0],
        vec![255],
        vec![0, 0, 0],
        vec![255, 255, 255],
        b"hello world".to_vec(),
        b"tidefs chunk shipper deterministic fuzz".to_vec(),
        vec![0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF],
        (0..=255).collect::<Vec<u8>>(), // all bytes 0x00..0xFF
        vec![0x00u8; 64],
        vec![0xFFu8; 64],
        vec![0xAAu8; 128],
        vec![0x55u8; 256],
        vec![0xDE, 0xAD, 0xBE, 0xEF],
        vec![0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00],
        // Powers of 2
        vec![0x01u8; 1],
        vec![0x01u8; 2],
        vec![0x01u8; 4],
        vec![0x01u8; 8],
        vec![0x01u8; 16],
        vec![0x01u8; 32],
        vec![0x01u8; 64],
        vec![0x01u8; 128],
        vec![0x01u8; 256],
        vec![0x01u8; 512],
        vec![0x01u8; 1024],
        // Near max sizes
        vec![0xABu8; 100_000],
    ]
}

// ═══════════════════════════════════════════════════
// Payload round-trip invariance
// ═══════════════════════════════════════════════════

#[test]
fn test_corpus_payload_round_trip_preserves_bytes() {
    for payload in payload_corpus() {
        let t = ReplicaTransferTicketRecord {
            ticket_id: rid(1),
            intent_ref: rid(100),
            subject_refs: vec![ReplicatedSubjectId(10)],
            source_anchor_set: vec![member(1)],
            target_ref: member(2),
            pin_budget_ref: rid(200),
            freshness_fence_ref: 0,
            expiry: 1000,
        };

        let received_digest = derive_receive_digest(&payload);
        let chunk_data = vec![(1u64, payload.clone(), received_digest)];

        let buffers = stage_replica_chunks_for_transport(
            &t,
            &chunk_data,
            ChunkShippingTransport::TcpFallback,
        );

        let mut session =
            ChunkShippingSession::new(1, t.clone(), ChunkShippingTransport::TcpFallback, 3);
        let (transferred, bytes_moved) = stream_replica_chunks_under_ticket(&mut session, &buffers);

        let staging_area =
            receive_replica_chunks_and_stage_for_verification(&transferred, &t.subject_refs);

        assert_eq!(
            bytes_moved,
            payload.len() as u64,
            "bytes_moved mismatch for payload len {}",
            payload.len()
        );
        assert_eq!(
            staging_area.pending_count(),
            1,
            "pending_count != 1 for payload len {}",
            payload.len()
        );
        assert!(
            staging_area.rejected_chunks.is_empty(),
            "rejected_chunks not empty for payload len {}",
            payload.len()
        );
        assert_eq!(
            staging_area.total_bytes_staged,
            payload.len() as u64,
            "total_bytes_staged mismatch for payload len {}",
            payload.len()
        );

        let staged = &staging_area.staged_chunks[&1];
        assert_eq!(
            staged.payload,
            payload,
            "payload mismatch for len {}",
            payload.len()
        );
        assert_eq!(
            staged.source_digest,
            received_digest,
            "source_digest mismatch for payload len {}",
            payload.len()
        );
        assert_eq!(
            staged.received_digest,
            received_digest,
            "received_digest mismatch for payload len {}",
            payload.len()
        );
    }
}

// ═══════════════════════════════════════════════════
// derive_receive_digest determinism over corpus
// ═══════════════════════════════════════════════════

#[test]
fn test_corpus_derive_receive_digest_deterministic() {
    for payload in payload_corpus() {
        let d1 = derive_receive_digest(&payload);
        let d2 = derive_receive_digest(&payload);
        let d3 = derive_receive_digest(&payload);
        assert_eq!(
            d1,
            d2,
            "digest not deterministic for payload len {}",
            payload.len()
        );
        assert_eq!(
            d2,
            d3,
            "digest not deterministic on 3rd call for payload len {}",
            payload.len()
        );
    }
}

// ═══════════════════════════════════════════════════
// ChunkStagingBuffer serde round-trip over corpus
// ═══════════════════════════════════════════════════

#[test]
fn test_corpus_chunk_staging_buffer_serde_round_trip() {
    for payload in payload_corpus() {
        let buf = ChunkStagingBuffer {
            chunk_id: 42,
            subject_ref: ReplicatedSubjectId(10),
            range_start: 0,
            range_end: payload.len() as u64,
            payload: payload.clone(),
            digest: derive_receive_digest(&payload),
            phase: ChunkStagingPhase::Staged,
            transport: ChunkShippingTransport::TcpFallback,
        };
        let json = serde_json::to_string(&buf).expect("serialize failed");
        let back: ChunkStagingBuffer = serde_json::from_str(&json).expect("deserialize failed");
        assert_eq!(
            buf,
            back,
            "serde round-trip mismatch for payload len {}",
            payload.len()
        );
    }
}

// ═══════════════════════════════════════════════════
// ReceivedChunk serde round-trip over digest corpus
// ═══════════════════════════════════════════════════

fn digest_corpus() -> Vec<(u64, u64)> {
    vec![
        (0, 0),
        (1, 1),
        (0, 1),
        (u64::MAX, u64::MAX),
        (0xDEADBEEF, 0xDEADBEEF),
        (0xDEADBEEF, 0xCAFEBABE),
        (0, u64::MAX),
        (u64::MAX, 0),
        (0x0123456789ABCDEF, 0xFEDCBA9876543210),
        (0xAAAAAAAAAAAAAAAA, 0x5555555555555555),
    ]
}

#[test]
fn test_corpus_received_chunk_serde_round_trip() {
    for (src, recv) in digest_corpus() {
        for payload in &[
            b"small".to_vec(),
            b"medium payload for serde".to_vec(),
            vec![],
            vec![0u8; 1000],
        ] {
            let rc = ReceivedChunk {
                chunk_id: 7,
                subject_ref: ReplicatedSubjectId(10),
                payload: payload.clone(),
                source_digest: ObjectDigest(src),
                received_digest: ObjectDigest(recv),
                range_start: 0,
                range_end: payload.len() as u64,
                verified: false,
            };
            let json = serde_json::to_string(&rc).expect("serialize failed");
            let back: ReceivedChunk = serde_json::from_str(&json).expect("deserialize failed");
            assert_eq!(
                rc, back,
                "serde mismatch for src_digest={src}, recv_digest={recv}"
            );
        }
    }
}

// ═══════════════════════════════════════════════════
// Transport selection determinism
// ═══════════════════════════════════════════════════

fn member_corpus() -> Vec<(u64, u64)> {
    vec![
        (0, 0),
        (0, 1),
        (1, 0),
        (1, 1),
        (42, 42),
        (42, 99),
        (u64::MAX, u64::MAX),
        (u64::MAX, 0),
        (0, u64::MAX),
    ]
}

#[test]
fn test_corpus_transport_selection_deterministic() {
    for &(src, tgt) in &member_corpus() {
        for &rdma in &[false, true] {
            for &uring in &[false, true] {
                let t1 = ChunkShippingTransport::select(MemberId(src), MemberId(tgt), rdma, uring);
                let t2 = ChunkShippingTransport::select(MemberId(src), MemberId(tgt), rdma, uring);
                assert_eq!(
                    t1, t2,
                    "nondeterministic transport: src={src}, tgt={tgt}, rdma={rdma}, uring={uring}"
                );
            }
        }
    }
}

#[test]
fn test_corpus_same_node_io_uring_always_wins() {
    for &node in &[0u64, 1, 42, u64::MAX] {
        for &rdma in &[false, true] {
            let t = ChunkShippingTransport::select(MemberId(node), MemberId(node), rdma, true);
            assert_eq!(
                t,
                ChunkShippingTransport::IoUringSplice,
                "same-node with io_uring should win: node={node}, rdma={rdma}"
            );
        }
    }
}

#[test]
fn test_corpus_cross_node_rdma_wins() {
    // When source != target and rdma_capable=true
    let pairs: Vec<(u64, u64)> = vec![(0, 1), (1, 2), (42, 99), (0, u64::MAX)];
    for (src, tgt) in pairs {
        let t = ChunkShippingTransport::select(MemberId(src), MemberId(tgt), true, false);
        assert_eq!(
            t,
            ChunkShippingTransport::RdmaDirectDataPlacement,
            "cross-node RDMA should win: src={src}, tgt={tgt}"
        );
    }
}

#[test]
fn test_corpus_cross_node_no_rdma_tcp_fallback() {
    let pairs: Vec<(u64, u64)> = vec![(0, 1), (1, 2), (42, 99), (0, u64::MAX)];
    for (src, tgt) in pairs {
        let t = ChunkShippingTransport::select(MemberId(src), MemberId(tgt), false, true);
        assert_eq!(
            t,
            ChunkShippingTransport::TcpFallback,
            "cross-node without RDMA should fallback to TCP: src={src}, tgt={tgt}"
        );
    }
}

// ═══════════════════════════════════════════════════
// derive_anchor_hash determinism
// ═══════════════════════════════════════════════════

#[test]
fn test_corpus_derive_anchor_hash_deterministic() {
    let inputs: Vec<(u64, u64)> = vec![
        (0, 0),
        (1, 0),
        (0, 1),
        (1, 1),
        (42, 99),
        (u64::MAX, u64::MAX),
        (0x9E3779B97F4A7C15, 0x9E3779B97F4A7C15),
    ];
    for (base, seed) in inputs {
        assert_eq!(
            derive_anchor_hash(base, seed),
            derive_anchor_hash(base, seed),
            "derive_anchor_hash non-deterministic: base={base}, seed={seed}"
        );
    }
}

// ═══════════════════════════════════════════════════
// StagingBuffer len/is_empty invariants
// ═══════════════════════════════════════════════════

#[test]
fn test_corpus_staging_buffer_len_invariants() {
    for payload in payload_corpus() {
        let buf = ChunkStagingBuffer::new(
            1,
            ReplicatedSubjectId(10),
            0,
            0,
            payload.clone(),
            derive_receive_digest(b""),
            ChunkShippingTransport::TcpFallback,
        );
        assert_eq!(
            buf.len(),
            payload.len(),
            "len mismatch for payload len {}",
            payload.len()
        );
        assert_eq!(
            buf.is_empty(),
            payload.is_empty(),
            "is_empty mismatch for payload len {}",
            payload.len()
        );
    }
}

// ═══════════════════════════════════════════════════
// ChunkTransferProgress progress_ratio invariants
// ═══════════════════════════════════════════════════

#[test]
fn test_progress_ratio_zero_total_always_one() {
    let ratios: Vec<u64> = vec![0, 1, 100, 10_000, u64::MAX];
    for bytes_transferred in ratios {
        let mut p = ChunkTransferProgress::new(1, ReplicatedSubjectId(10), 0);
        p.bytes_transferred = bytes_transferred;
        assert!(
            (p.progress_ratio() - 1.0).abs() < 1e-9,
            "zero total should give 1.0, not {}",
            p.progress_ratio()
        );
    }
}

#[test]
fn test_progress_ratio_nonzero_total() {
    let cases: Vec<(u64, u64)> = vec![
        (100, 0),
        (100, 25),
        (100, 50),
        (100, 75),
        (100, 100),
        (1000, 500),
        (1000, 1000),
        (1, 0),
        (1, 1),
        (1_000_000, 500_000),
        (1_000_000, 1_000_000),
    ];
    for (total, transferred) in cases {
        let mut p = ChunkTransferProgress::new(1, ReplicatedSubjectId(10), total);
        p.bytes_transferred = transferred;
        let expected = transferred as f64 / total as f64;
        let actual = p.progress_ratio();
        assert!(
            (actual - expected).abs() < 1e-9,
            "progress_ratio mismatch: total={total}, transferred={transferred}, expected={expected}, actual={actual}"
        );
    }
}
