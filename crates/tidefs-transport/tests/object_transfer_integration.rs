// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Integration test for object payload transfer over transport sessions.
//!
//! Exercises the ObjectTransferMessage wire types, TransferHandle
//! request/response pairing, chunk-shipper integration for large
//! payloads, and concurrent transfer dispatch. Uses a simple
//! in-process loopback channel (two VecDeque-backed FIFOs).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use tidefs_transport::{
    build_read_responses, build_write_requests, ChunkReassembler, ObjectTransferMessage,
    TransferHandle, WriteStatus, MAX_CHUNK_PAYLOAD,
};

// ---------------------------------------------------------------------------
// Simple in-process loopback for message exchange
// ---------------------------------------------------------------------------

struct LoopbackChannel {
    queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
}

impl LoopbackChannel {
    fn new() -> Self {
        Self {
            queue: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    fn send(&self, data: Vec<u8>) {
        self.queue.lock().unwrap().push_back(data);
    }

    fn recv(&self) -> Option<Vec<u8>> {
        self.queue.lock().unwrap().pop_front()
    }

    #[allow(dead_code)]
    fn recv_timeout(&self, timeout: Duration) -> Option<Vec<u8>> {
        let start = Instant::now();
        loop {
            if let Some(data) = self.recv() {
                return Some(data);
            }
            if start.elapsed() >= timeout {
                return None;
            }
            thread::sleep(Duration::from_micros(100));
        }
    }
}

struct LoopbackPair {
    a_to_b: LoopbackChannel,
    b_to_a: LoopbackChannel,
}

impl LoopbackPair {
    fn new() -> Self {
        Self {
            a_to_b: LoopbackChannel::new(),
            b_to_a: LoopbackChannel::new(),
        }
    }

    fn side_a_send(&self, msg: &ObjectTransferMessage) {
        self.a_to_b.send(msg.encode().expect("encode"));
    }

    fn side_a_recv(&self) -> ObjectTransferMessage {
        let data = self.b_to_a.recv().expect("side A recv");
        ObjectTransferMessage::decode(&data).expect("decode")
    }

    fn side_b_send(&self, msg: &ObjectTransferMessage) {
        self.b_to_a.send(msg.encode().expect("encode"));
    }

    fn side_b_recv(&self) -> ObjectTransferMessage {
        let data = self.a_to_b.recv().expect("side B recv");
        ObjectTransferMessage::decode(&data).expect("decode")
    }
}

// ---------------------------------------------------------------------------
// BLAKE3 hash helper
// ---------------------------------------------------------------------------

fn blake3_hash(data: &[u8]) -> [u8; 32] {
    blake3::hash(data).into()
}

// ---------------------------------------------------------------------------
// Reassembly helper: drain all response chunks into assembled payload
// ---------------------------------------------------------------------------

fn reassemble_responses(pair: &LoopbackPair, expected_chunks: usize) -> Vec<u8> {
    let mut reassembler: Option<ChunkReassembler> = None;
    let mut assembled = Vec::new();
    for _ in 0..expected_chunks {
        let resp = pair.side_a_recv();
        resp.verify_payload().expect("payload digest");
        let (ci, tc, ts, pl, dg) = match resp {
            ObjectTransferMessage::ReadResponse {
                chunk_index,
                total_chunks,
                total_size,
                payload,
                payload_digest,
                ..
            } => (
                chunk_index,
                total_chunks,
                total_size,
                payload,
                payload_digest,
            ),
            _ => panic!("expected ReadResponse"),
        };
        if reassembler.is_none() {
            reassembler = Some(ChunkReassembler::new(tc, ts));
        }
        let done = reassembler
            .as_mut()
            .unwrap()
            .feed(ci, tc, &pl, &dg)
            .expect("feed chunk");
        if done {
            assembled = reassembler.take().unwrap().into_payload();
        }
    }
    assembled
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_read_4kib() {
    let pair = LoopbackPair::new();
    let payload = vec![0xABu8; 4096];
    let key = blake3_hash(&payload);

    pair.side_a_send(&ObjectTransferMessage::read_request(
        1,
        key,
        0,
        payload.len() as u64,
    ));

    let req = pair.side_b_recv();
    assert_eq!(req.transfer_id(), 1);

    let responses = build_read_responses(1, payload.len() as u64, &payload, MAX_CHUNK_PAYLOAD);
    let n = responses.len();
    for r in &responses {
        pair.side_b_send(r);
    }

    let assembled = reassemble_responses(&pair, n);
    assert_eq!(assembled, payload);
    assert_eq!(blake3_hash(&assembled), key);
}

#[test]
fn roundtrip_write_4kib() {
    let pair = LoopbackPair::new();
    let payload = b"write test payload: exact content for verification".to_vec();
    let key = blake3_hash(&payload);

    let reqs = build_write_requests(1, key, 0, payload.len() as u64, &payload, MAX_CHUNK_PAYLOAD);
    for r in &reqs {
        r.verify_payload().expect("write chunk digest");
        pair.side_a_send(r);
    }

    // Receive, reassemble
    let mut reassembler: Option<ChunkReassembler> = None;
    let mut assembled = Vec::new();
    let n = reqs.len();
    for _ in 0..n {
        let req = pair.side_b_recv();
        req.verify_payload().expect("write chunk digest");
        let (ci, tc, ts, pl, dg) = match req {
            ObjectTransferMessage::WriteRequest {
                chunk_index,
                total_chunks,
                total_size,
                payload,
                payload_digest,
                ..
            } => (
                chunk_index,
                total_chunks,
                total_size,
                payload,
                payload_digest,
            ),
            _ => panic!("expected WriteRequest"),
        };
        if reassembler.is_none() {
            reassembler = Some(ChunkReassembler::new(tc, ts));
        }
        let done = reassembler
            .as_mut()
            .unwrap()
            .feed(ci, tc, &pl, &dg)
            .expect("feed write chunk");
        if done {
            assembled = reassembler.take().unwrap().into_payload();
        }
    }
    assert_eq!(assembled, payload);

    pair.side_b_send(&ObjectTransferMessage::write_ack(
        1,
        payload.len() as u64,
        WriteStatus::Ok,
    ));

    let ack = pair.side_a_recv();
    let (tid, bw, st) = match ack {
        ObjectTransferMessage::WriteAck {
            transfer_id,
            bytes_written,
            status,
        } => (transfer_id, bytes_written, status),
        _ => panic!("expected WriteAck"),
    };
    assert_eq!(tid, 1);
    assert_eq!(bw, payload.len() as u64);
    assert_eq!(st, WriteStatus::Ok);
}

#[test]
fn roundtrip_empty_payload() {
    let pair = LoopbackPair::new();
    let key = blake3_hash(&[]);

    pair.side_a_send(&ObjectTransferMessage::read_request(1, key, 0, 0));
    let req = pair.side_b_recv();
    assert_eq!(req.transfer_id(), 1);

    pair.side_b_send(&ObjectTransferMessage::read_response(1, 0, 1, 0, vec![]));

    let resp = pair.side_a_recv();
    resp.verify_payload().expect("empty payload verify");
    match resp {
        ObjectTransferMessage::ReadResponse { payload, .. } => assert!(payload.is_empty()),
        _ => panic!("expected ReadResponse"),
    }
}

#[test]
fn roundtrip_1mib_single_chunk() {
    let pair = LoopbackPair::new();
    let payload = vec![0x5Au8; 1_048_576];
    let key = blake3_hash(&payload);

    pair.side_a_send(&ObjectTransferMessage::read_request(
        42,
        key,
        0,
        payload.len() as u64,
    ));
    let req = pair.side_b_recv();
    assert_eq!(req.transfer_id(), 42);

    let responses = build_read_responses(42, payload.len() as u64, &payload, MAX_CHUNK_PAYLOAD);
    assert_eq!(responses.len(), 1);
    pair.side_b_send(&responses[0]);

    let resp = pair.side_a_recv();
    resp.verify_payload().expect("1 MiB verify");
    let pl = match resp {
        ObjectTransferMessage::ReadResponse { payload, .. } => payload,
        _ => panic!("expected ReadResponse"),
    };
    assert_eq!(pl.len(), 1_048_576);
    assert_eq!(pl, payload);
    assert_eq!(blake3_hash(&pl), key);
}

#[test]
fn roundtrip_16mib_multi_chunk() {
    let pair = LoopbackPair::new();
    let payload: Vec<u8> = (0..16_777_216u64).map(|i| (i % 251) as u8).collect();
    let key = blake3_hash(&payload);

    pair.side_a_send(&ObjectTransferMessage::read_request(
        7,
        key,
        0,
        payload.len() as u64,
    ));
    let req = pair.side_b_recv();
    assert_eq!(req.transfer_id(), 7);

    let responses = build_read_responses(7, payload.len() as u64, &payload, MAX_CHUNK_PAYLOAD);
    assert_eq!(responses.len(), 16);
    for r in &responses {
        pair.side_b_send(r);
    }

    let assembled = reassemble_responses(&pair, 16);
    assert_eq!(assembled.len(), 16_777_216);
    assert_eq!(assembled, payload);
    assert_eq!(blake3_hash(&assembled), key);
}

#[test]
fn multi_chunk_2_chunks() {
    let pair = LoopbackPair::new();
    let payload = vec![0xCCu8; MAX_CHUNK_PAYLOAD + 1];
    let key = blake3_hash(&payload);

    pair.side_a_send(&ObjectTransferMessage::read_request(
        1,
        key,
        0,
        payload.len() as u64,
    ));
    pair.side_b_recv();

    let responses = build_read_responses(1, payload.len() as u64, &payload, MAX_CHUNK_PAYLOAD);
    assert_eq!(responses.len(), 2);
    for r in &responses {
        pair.side_b_send(r);
    }

    let assembled = reassemble_responses(&pair, 2);
    assert_eq!(assembled, payload);
    assert_eq!(blake3_hash(&assembled), key);
}

#[test]
fn multi_chunk_3_chunks() {
    let pair = LoopbackPair::new();
    let payload = vec![0xDDu8; MAX_CHUNK_PAYLOAD * 2 + 512];
    let key = blake3_hash(&payload);

    pair.side_a_send(&ObjectTransferMessage::read_request(
        1,
        key,
        0,
        payload.len() as u64,
    ));
    pair.side_b_recv();

    let responses = build_read_responses(1, payload.len() as u64, &payload, MAX_CHUNK_PAYLOAD);
    assert_eq!(responses.len(), 3);
    for r in &responses {
        pair.side_b_send(r);
    }

    let assembled = reassemble_responses(&pair, 3);
    assert_eq!(assembled, payload);
    assert_eq!(blake3_hash(&assembled), key);
}

#[test]
fn multi_chunk_50_plus_chunks() {
    let pair = LoopbackPair::new();
    let chunk_sz: usize = 65536;
    let total = chunk_sz * 50 + 123;
    let payload: Vec<u8> = (0..total as u64).map(|i| (i % 251) as u8).collect();
    let key = blake3_hash(&payload);

    pair.side_a_send(&ObjectTransferMessage::read_request(
        1,
        key,
        0,
        payload.len() as u64,
    ));
    pair.side_b_recv();

    let responses = build_read_responses(1, payload.len() as u64, &payload, chunk_sz);
    let n = responses.len();
    assert!(n >= 50);
    for r in &responses {
        pair.side_b_send(r);
    }

    let assembled = reassemble_responses(&pair, n);
    assert_eq!(assembled.len(), total);
    assert_eq!(assembled, payload);
    assert_eq!(blake3_hash(&assembled), key);
}

#[test]
fn concurrent_4_transfers() {
    let pair = LoopbackPair::new();
    let payloads: Vec<Vec<u8>> = (0..4)
        .map(|i| {
            let base = (i * 1000) as u64;
            (base..base + 1024).map(|b| (b % 251) as u8).collect()
        })
        .collect();

    // Side A: send 4 read requests
    for (i, pl) in payloads.iter().enumerate() {
        let key = blake3_hash(pl);
        pair.side_a_send(&ObjectTransferMessage::read_request(
            (i + 1) as u64,
            key,
            0,
            pl.len() as u64,
        ));
    }

    // Side B: receive all 4, build responses
    let mut responses: Vec<Vec<ObjectTransferMessage>> = Vec::new();
    for _ in 0..4 {
        let req = pair.side_b_recv();
        let tid = req.transfer_id();
        let pi = (tid - 1) as usize;
        let pl = &payloads[pi];
        responses.push(build_read_responses(
            tid,
            pl.len() as u64,
            pl,
            MAX_CHUNK_PAYLOAD,
        ));
    }

    // Interleave responses
    let max_n = responses.iter().map(|r| r.len()).max().unwrap_or(0);
    for ci in 0..max_n {
        for rl in &responses {
            if let Some(r) = rl.get(ci) {
                pair.side_b_send(r);
            }
        }
    }

    // Side A: reassemble all 4
    let mut reassemblers: Vec<Option<ChunkReassembler>> = (0..4).map(|_| None).collect();
    let mut assembled: Vec<Vec<u8>> = (0..4).map(|_| Vec::new()).collect();
    let mut completed = [false; 4];

    let total_resp: usize = responses.iter().map(|r| r.len()).sum();
    for _ in 0..total_resp {
        let resp = pair.side_a_recv();
        resp.verify_payload().expect("chunk verify");
        let (tid, ci, tc, ts, pl, dg) = match resp {
            ObjectTransferMessage::ReadResponse {
                transfer_id,
                chunk_index,
                total_chunks,
                total_size,
                payload,
                payload_digest,
            } => (
                transfer_id,
                chunk_index,
                total_chunks,
                total_size,
                payload,
                payload_digest,
            ),
            _ => panic!("expected ReadResponse"),
        };
        let idx = (tid - 1) as usize;
        if reassemblers[idx].is_none() {
            reassemblers[idx] = Some(ChunkReassembler::new(tc, ts));
        }
        let done = reassemblers[idx]
            .as_mut()
            .unwrap()
            .feed(ci, tc, &pl, &dg)
            .expect("feed chunk");
        if done {
            assembled[idx] = reassemblers[idx].take().unwrap().into_payload();
            completed[idx] = true;
        }
    }

    for (i, pl) in payloads.iter().enumerate() {
        assert!(completed[i], "transfer {i} should be complete");
        assert_eq!(assembled[i], *pl);
        assert_eq!(blake3_hash(&assembled[i]), blake3_hash(pl));
    }
}

#[test]
fn transfer_handle_lifecycle() {
    let pair = LoopbackPair::new();
    let mut handle = TransferHandle::with_limits(Duration::from_secs(2), 2);

    let payload = b"transfer handle test payload".to_vec();
    let key = blake3_hash(&payload);

    let tid = handle.register_request(ObjectTransferMessage::read_request(
        0,
        key,
        0,
        payload.len() as u64,
    ));
    assert_eq!(tid, 1);
    assert_eq!(handle.pending_count(), 1);

    // Build and send request with correct transfer_id
    pair.side_a_send(&ObjectTransferMessage::read_request(
        tid,
        key,
        0,
        payload.len() as u64,
    ));

    let req = pair.side_b_recv();
    assert_eq!(req.transfer_id(), 1);

    let responses = build_read_responses(1, payload.len() as u64, &payload, MAX_CHUNK_PAYLOAD);
    for r in &responses {
        pair.side_b_send(r);
    }

    let resp = pair.side_a_recv();
    resp.verify_payload().expect("payload verify");
    let pl = match resp {
        ObjectTransferMessage::ReadResponse { payload, .. } => payload,
        _ => panic!("expected ReadResponse"),
    };
    assert_eq!(&pl, &payload);

    let completed = handle.complete(tid);
    assert!(completed.is_some());
    assert_eq!(handle.pending_count(), 0);
}

#[test]
fn write_status_no_space_propagation() {
    let pair = LoopbackPair::new();
    let payload = b"write that fails".to_vec();
    let key = blake3_hash(&payload);

    let reqs = build_write_requests(1, key, 0, payload.len() as u64, &payload, MAX_CHUNK_PAYLOAD);
    for r in &reqs {
        pair.side_a_send(r);
    }
    for _ in 0..reqs.len() {
        pair.side_b_recv();
    }

    pair.side_b_send(&ObjectTransferMessage::write_ack(
        1,
        0,
        WriteStatus::NoSpace {
            available: 1024,
            needed: 8192,
        },
    ));

    let ack = pair.side_a_recv();
    let (tid, bw, st) = match ack {
        ObjectTransferMessage::WriteAck {
            transfer_id,
            bytes_written,
            status,
        } => (transfer_id, bytes_written, status),
        _ => panic!("expected WriteAck"),
    };
    assert_eq!(tid, 1);
    assert_eq!(bw, 0);
    assert_eq!(
        st,
        WriteStatus::NoSpace {
            available: 1024,
            needed: 8192
        }
    );
}

#[test]
fn payload_digest_tamper_detected() {
    let payload = b"payload to be tampered in transit".to_vec();
    let resp = ObjectTransferMessage::read_response(1, 0, 1, payload.len() as u64, payload);
    resp.verify_payload().expect("fresh verify");

    let mut encoded = resp.encode().expect("encode");
    let flip_pos = encoded.len() - 5;
    encoded[flip_pos] ^= 0xFF;

    let tampered = ObjectTransferMessage::decode(&encoded).expect("decode");
    assert!(tampered.verify_payload().is_err(), "tampered must fail");
}

#[test]
fn chunk_reassembly_digest_mismatch_detected() {
    let payload = b"legitimate chunk".to_vec();
    let legit_dg = {
        let resp = ObjectTransferMessage::read_response(
            1,
            0,
            2,
            payload.len() as u64 * 2,
            payload.clone(),
        );
        match resp {
            ObjectTransferMessage::ReadResponse { payload_digest, .. } => payload_digest,
            _ => unreachable!(),
        }
    };

    let mut reassembler = ChunkReassembler::new(2, payload.len() as u64 * 2);
    let mut bad_dg = legit_dg;
    bad_dg[0] ^= 0xFF;
    let err = reassembler.feed(0, 2, &payload, &bad_dg).unwrap_err();
    assert!(matches!(
        err,
        tidefs_transport::ChunkReassemblyError::DigestMismatch { chunk_index: 0 }
    ));
}
