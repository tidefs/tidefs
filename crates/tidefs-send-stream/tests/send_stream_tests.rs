//! Integration tests for tidefs-send-stream: ObjectChunkFramer with
//! real ObjectStore backing, SendQueue backpressure, and chunk-integrity
//! end-to-end verification.

use tidefs_local_object_store::{LocalObjectStore, ObjectKey, StoreOptions};
use tidefs_send_stream::{ChunkPacket, FrameError, ObjectChunkFramer, SendQueue};

use std::sync::Arc;
use std::thread;

// ── helpers ──────────────────────────────────────────────────────

fn object_id(b: u8) -> [u8; 32] {
    [b; 32]
}

fn temp_store() -> (LocalObjectStore, tempfile::TempDir) {
    let dir = tempfile::TempDir::new().unwrap();
    let store = LocalObjectStore::open_with_options(dir.path(), StoreOptions::test_fast()).unwrap();
    (store, dir)
}

// ── ObjectChunkFramer with real store ────────────────────────────

#[test]
fn framer_reads_from_store_and_produces_chunks() {
    let (mut store, _dir) = temp_store();
    let data = b"abcdefghijklmnop"; // 16 bytes, chunk_size=7 -> 3 chunks
    let key = store.put_content_addressed(data).unwrap();

    let framer = ObjectChunkFramer::new(7);
    let packets = framer.frame_object(&store, key).unwrap();

    assert!(packets.len() >= 2);
    for pkt in &packets {
        assert!(pkt.verify());
        assert_eq!(pkt.object_id, *key.as_bytes());
    }
}

#[test]
fn framer_not_found_returns_error() {
    let (store, _dir) = temp_store();
    let unknown_key = ObjectKey::default();
    let framer = ObjectChunkFramer::new(256);

    let result = framer.frame_object(&store, unknown_key);
    assert!(matches!(result, Err(FrameError::NotFound(_))));
}

// ── frame_data tests (no store needed) ──────────────────────────

#[test]
fn frame_data_single_chunk() {
    let framer = ObjectChunkFramer::new(1024);
    let data = b"hello";
    let packets = framer.frame_data(object_id(1), data);

    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].payload, data);
    assert!(packets[0].is_last);
    assert!(packets[0].verify());
}

#[test]
fn frame_data_multi_chunk_splitting() {
    let framer = ObjectChunkFramer::new(4);
    let data = b"0123456789"; // 10 bytes = 3 chunks (4+4+2)
    let packets = framer.frame_data(object_id(2), data);

    assert_eq!(packets.len(), 3);
    assert_eq!(packets[2].payload, b"89");
    assert!(packets[2].is_last);

    let mut reassembled = Vec::new();
    for pkt in &packets {
        reassembled.extend_from_slice(&pkt.payload);
    }
    assert_eq!(reassembled, data);
}

#[test]
fn frame_data_empty_object() {
    let framer = ObjectChunkFramer::new(256);
    let packets = framer.frame_data(object_id(3), &[]);

    assert_eq!(packets.len(), 1);
    assert!(packets[0].payload.is_empty());
    assert!(packets[0].is_last);
    assert!(packets[0].verify());
}

#[test]
fn frame_data_exact_chunk_boundary() {
    let framer = ObjectChunkFramer::new(8);
    let data = b"ABCDEFGH";
    let packets = framer.frame_data(object_id(4), data);

    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].payload, data);
}

#[test]
fn frame_data_partial_final_chunk() {
    let framer = ObjectChunkFramer::new(8);
    let data = b"ABCDEFGHI"; // 9 bytes -> 2 chunks
    let packets = framer.frame_data(object_id(5), data);

    assert_eq!(packets.len(), 2);
    assert_eq!(packets[0].payload.len(), 8);
    assert!(!packets[0].is_last);
    assert_eq!(packets[1].payload.len(), 1);
    assert!(packets[1].is_last);
}

#[test]
fn frame_data_sequence_numbers_monotonic() {
    let framer = ObjectChunkFramer::new(2);
    let data = vec![0xAAu8; 10];
    let packets = framer.frame_data(object_id(6), &data);

    assert_eq!(packets.len(), 5);
    for (i, pkt) in packets.iter().enumerate() {
        assert_eq!(pkt.chunk_seq, i as u32);
        assert_eq!(pkt.total_chunks, 5);
    }
}

// ── BLAKE3 determinism ───────────────────────────────────────────

#[test]
fn blake3_hashes_are_deterministic() {
    let data = b"deterministic hash test data";
    let framer = ObjectChunkFramer::new(16);
    let packets_a = framer.frame_data(object_id(1), data);
    let packets_b = framer.frame_data(object_id(1), data);

    assert_eq!(packets_a.len(), packets_b.len());
    for (a, b) in packets_a.iter().zip(packets_b.iter()) {
        assert_eq!(a.blake3_hash, b.blake3_hash);
    }
}

// ── SendQueue backpressure ───────────────────────────────────────

#[test]
fn send_queue_enqueue_drain_preserves_order() {
    let q = SendQueue::new(4);
    for i in 0..4 {
        q.enqueue(i);
    }
    assert_eq!(q.len(), 4);
    assert!(q.is_full());

    let drained = q.drain();
    assert_eq!(drained, vec![0, 1, 2, 3]);
    assert!(q.is_empty());
}

#[test]
fn send_queue_backpressure_blocks_and_resumes() {
    let q = Arc::new(SendQueue::new(2));
    q.enqueue(1u32);
    q.enqueue(2u32);
    assert!(q.is_full());

    let q_clone = Arc::clone(&q);
    let handle = thread::spawn(move || {
        q_clone.enqueue(3u32);
        3u32
    });

    thread::sleep(std::time::Duration::from_millis(100));

    let batch1 = q.drain();
    assert_eq!(batch1, vec![1, 2]);

    let result = handle.join().unwrap();
    assert_eq!(result, 3);
}

#[test]
fn send_queue_try_enqueue_rejects_when_full() {
    let q = SendQueue::new(1);
    assert!(q.try_enqueue(99u32).is_ok());
    assert_eq!(q.try_enqueue(100u32), Err(100));
}

#[test]
fn send_queue_returns_capacity() {
    let q = SendQueue::<u32>::new(10);
    assert_eq!(q.capacity(), 10);
    assert!(q.is_empty());
    assert!(!q.is_full());
}

// ── ChunkPacket integrity ────────────────────────────────────────

#[test]
fn chunk_packet_verify_detects_corruption() {
    let payload = b"integrity test payload".to_vec();
    let hash: [u8; 32] = blake3::hash(&payload).into();
    let pkt = ChunkPacket {
        object_id: object_id(1),
        chunk_seq: 0,
        total_chunks: 1,
        offset: 0,
        payload,
        blake3_hash: hash,
        is_last: true,
    };
    assert!(pkt.verify());

    let mut corrupt = pkt.clone();
    corrupt.payload[2] ^= 0xFF;
    assert!(!corrupt.verify());
}

// ── Default configuration ────────────────────────────────────────

#[test]
fn default_framer_uses_64kib_chunk_size() {
    let framer = ObjectChunkFramer::default();
    assert_eq!(framer.chunk_size(), 65536);
}

// ── Edge cases ───────────────────────────────────────────────────

#[test]
fn framer_object_exactly_one_chunk_below_limit() {
    let framer = ObjectChunkFramer::new(100);
    let data = vec![0u8; 100];
    assert_eq!(framer.chunk_count(100), 1);
    let packets = framer.frame_data(object_id(2), &data);
    assert_eq!(packets.len(), 1);
}

#[test]
fn framer_object_one_byte_over_boundary() {
    let framer = ObjectChunkFramer::new(100);
    let data = vec![0u8; 101];
    assert_eq!(framer.chunk_count(101), 2);
    let packets = framer.frame_data(object_id(3), &data);
    assert_eq!(packets.len(), 2);
    assert_eq!(packets[0].payload.len(), 100);
    assert_eq!(packets[1].payload.len(), 1);
}
