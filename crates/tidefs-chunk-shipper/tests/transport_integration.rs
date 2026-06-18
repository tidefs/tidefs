// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Two-node loopback integration tests for chunk-shipper orchestrated
//! state transfer with BLAKE3-256 integrity verification.
//!
//! Exercises the full pipeline: source encodes chunks via TransferChunkEncoder,
//! dispatches wire frames through a deterministic loopback network, target
//! decodes via ChunkDecoder and reassembles via ObjectAssembler, with
//! end-to-end BLAKE3 session-integrity comparison.

use tidefs_chunk_shipper::{ObjectDescriptor, TransferPlan};
use tidefs_membership_epoch::{EpochMemberSet, NodeIdentity};
use tidefs_receive_stream::assembler::{AssembledObject, ObjectAssembler};
use tidefs_receive_stream::decoder::ChunkDecoder;
use tidefs_send_stream::chunk_encoder::{TransferChunkEncoder, TransferChunkEncoderConfig};
use tidefs_transport::harness::{LoopbackNetwork, SchedulerConfig};

// ── Helpers ────────────────────────────────────────────────────────────

fn make_object(id_byte: u8, data: &[u8]) -> ObjectDescriptor {
    let mut oid = [0u8; 32];
    oid[0] = id_byte;
    ObjectDescriptor::new(oid, data.to_vec())
}

fn make_plan(chunk_size: u32, objects: Vec<ObjectDescriptor>) -> TransferPlan {
    TransferPlan {
        objects,
        chunk_size,
    }
}

fn encode_plan(plan: &TransferPlan) -> Vec<Vec<u8>> {
    let encoder = TransferChunkEncoder::new(TransferChunkEncoderConfig {
        chunk_size: plan.chunk_size,
    });
    let mut wires = Vec::new();
    for obj in &plan.objects {
        let chunks = encoder.encode_object(obj.object_id, &obj.data);
        for c in &chunks {
            wires.push(c.encode_to_wire());
        }
    }
    wires
}

fn decode_and_assemble(wires: &[Vec<u8>]) -> Vec<([u8; 32], Vec<u8>)> {
    let decoder = ChunkDecoder::new();
    let mut assembler = ObjectAssembler::new();

    for wire in wires {
        let mut remaining: &[u8] = wire;
        while !remaining.is_empty() {
            match decoder.decode_chunk(remaining) {
                Ok((chunk, rest)) => {
                    let _ = assembler.feed_chunk(chunk);
                    remaining = rest;
                }
                Err(e) => {
                    panic!("decode error: {e:?}");
                }
            }
        }
    }

    let completed: Vec<AssembledObject> = assembler.drain_complete();
    completed
        .into_iter()
        .map(|o| (o.object_id, o.payload))
        .collect()
}

fn two_node_network() -> (usize, usize, LoopbackNetwork) {
    let config = SchedulerConfig::deterministic(12345);
    let mut net = LoopbackNetwork::new(config);

    let n1_id = NodeIdentity::new(1);
    let n2_id = NodeIdentity::new(2);
    let members = EpochMemberSet::new(vec![n1_id, n2_id]);

    let src_idx = net.add_node(n1_id, members.clone());
    let tgt_idx = net.add_node(n2_id, members);

    (src_idx, tgt_idx, net)
}

// ── Direct wire-format round-trip tests ────────────────────────────────

#[test]
fn two_node_single_small_object() {
    let data = b"hello from the loopback network".to_vec();
    let plan = make_plan(1024, vec![make_object(0x10, &data)]);

    let wires = encode_plan(&plan);
    assert_eq!(wires.len(), 1);

    let assembled = decode_and_assemble(&wires);
    assert_eq!(assembled.len(), 1);
    assert_eq!(assembled[0].1, data);

    let expected: [u8; 32] = blake3::hash(&data).into();
    let computed: [u8; 32] = blake3::hash(&assembled[0].1).into();
    assert_eq!(computed, expected);
}

#[test]
fn two_node_multi_chunk_object() {
    let data = b"0123456789ABCDEF".to_vec();
    let plan = make_plan(4, vec![make_object(0x20, &data)]);

    let wires = encode_plan(&plan);
    assert_eq!(wires.len(), 4);

    let assembled = decode_and_assemble(&wires);
    assert_eq!(assembled.len(), 1);
    assert_eq!(assembled[0].1, data);

    let expected: [u8; 32] = blake3::hash(&data).into();
    let computed: [u8; 32] = blake3::hash(&assembled[0].1).into();
    assert_eq!(computed, expected);
}

#[test]
fn two_node_multi_object() {
    let plan = make_plan(
        1024,
        vec![
            make_object(1, b"first"),
            make_object(2, b"second"),
            make_object(3, b"third"),
        ],
    );

    let wires = encode_plan(&plan);
    assert_eq!(wires.len(), 3);

    let assembled = decode_and_assemble(&wires);
    assert_eq!(assembled.len(), 3);

    let mut sorted: Vec<Vec<u8>> = assembled.iter().map(|(_, p)| p.clone()).collect();
    sorted.sort();
    assert_eq!(
        sorted,
        vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()]
    );
}

#[test]
fn two_node_empty_object() {
    let plan = make_plan(1024, vec![make_object(0x40, b"")]);

    let wires = encode_plan(&plan);
    assert_eq!(wires.len(), 1);

    let assembled = decode_and_assemble(&wires);
    assert_eq!(assembled.len(), 1);
    assert_eq!(assembled[0].1.len(), 0);
}

#[test]
fn two_node_large_64k_object() {
    let data = vec![0xABu8; 65536];
    let plan = make_plan(1024, vec![make_object(0x50, &data)]);

    let wires = encode_plan(&plan);
    assert_eq!(wires.len(), 64);

    let assembled = decode_and_assemble(&wires);
    assert_eq!(assembled.len(), 1);
    assert_eq!(assembled[0].1, data);

    let expected: [u8; 32] = blake3::hash(&data).into();
    let computed: [u8; 32] = blake3::hash(&assembled[0].1).into();
    assert_eq!(computed, expected);
}

// ── Transport-level send/recv tests ────────────────────────────────────

#[test]
fn two_node_with_actual_transport_round_trip() {
    let (src_idx, tgt_idx, mut net) = two_node_network();

    let data = b"transport-level round trip with BLAKE3 integrity".to_vec();
    let plan = make_plan(1024, vec![make_object(0x60, &data)]);

    let wires = encode_plan(&plan);
    assert_eq!(wires.len(), 1);

    for wire in &wires {
        let seq = net.send(src_idx, net.node(tgt_idx).identity, wire.clone());
        assert!(seq.is_some(), "send should succeed on loopback");
    }

    net.burst();

    let mut received_wires: Vec<Vec<u8>> = Vec::new();
    while let Some((msg, _stale)) = net.recv(tgt_idx) {
        received_wires.push(msg.payload);
    }

    assert_eq!(received_wires.len(), 1);
    assert_eq!(received_wires[0], wires[0]);

    let assembled = decode_and_assemble(&received_wires);
    assert_eq!(assembled[0].1, data);
}

#[test]
fn two_node_flow_controlled_multi_chunk_transfer() {
    let (src_idx, tgt_idx, mut net) = two_node_network();

    let data = vec![0xCCu8; 4096];
    let plan = make_plan(256, vec![make_object(0x70, &data)]);

    let wires = encode_plan(&plan);
    assert_eq!(wires.len(), 16);

    let max_inflight = 4;
    let mut sent_count = 0;
    let mut acked_count = 0;
    let mut received_wires: Vec<Vec<u8>> = Vec::new();

    for batch in wires.chunks(max_inflight) {
        for wire in batch {
            let seq = net.send(src_idx, net.node(tgt_idx).identity, wire.clone());
            assert!(seq.is_some());
            sent_count += 1;
        }

        net.burst();

        while let Some((msg, _stale)) = net.recv(tgt_idx) {
            received_wires.push(msg.payload);
            acked_count += 1;
        }

        let inflight = sent_count - acked_count;
        assert!(inflight <= max_inflight);
    }

    assert_eq!(received_wires.len(), 16);
    let assembled = decode_and_assemble(&received_wires);
    assert_eq!(assembled.len(), 1);
    assert_eq!(assembled[0].1, data);
}

#[test]
fn two_node_session_integrity_with_transport() {
    let (src_idx, tgt_idx, mut net) = two_node_network();

    let data = b"session integrity over loopback transport".to_vec();
    let plan = make_plan(1024, vec![make_object(0x80, &data)]);

    let wires = encode_plan(&plan);
    let chunk_count = wires.len() as u64;

    let mut send_hasher = blake3::Hasher::new();
    send_hasher.update(b"tidefs-chunk-shipper-session-v1");

    for wire in &wires {
        let decoder = ChunkDecoder::new();
        if let Ok((chunk, _)) = decoder.decode_chunk(wire) {
            let len_prefix = (chunk.payload.len() as u64).to_le_bytes();
            send_hasher.update(&len_prefix);
            send_hasher.update(&chunk.payload);
        }
        net.send(src_idx, net.node(tgt_idx).identity, wire.clone());
    }

    net.burst();

    let mut recv_hasher = blake3::Hasher::new();
    recv_hasher.update(b"tidefs-chunk-shipper-session-v1");

    while let Some((msg, _stale)) = net.recv(tgt_idx) {
        let decoder = ChunkDecoder::new();
        let mut remaining: &[u8] = &msg.payload;
        while !remaining.is_empty() {
            if let Ok((chunk, rest)) = decoder.decode_chunk(remaining) {
                let len_prefix = (chunk.payload.len() as u64).to_le_bytes();
                recv_hasher.update(&len_prefix);
                recv_hasher.update(&chunk.payload);
                remaining = rest;
            } else {
                break;
            }
        }
    }

    let mut s = send_hasher.clone();
    s.update(&chunk_count.to_le_bytes());
    let send_digest = *s.finalize().as_bytes();

    let mut r = recv_hasher.clone();
    r.update(&chunk_count.to_le_bytes());
    let recv_digest = *r.finalize().as_bytes();

    assert_eq!(send_digest, recv_digest);
}

#[test]
fn two_node_variable_size_objects() {
    let objects = vec![
        make_object(1, b""),
        make_object(2, b"x"),
        make_object(3, &[0x42u8; 255]),
        make_object(4, &[0x42u8; 256]),
        make_object(5, &[0x42u8; 257]),
        make_object(6, &[0xAAu8; 1024]),
        make_object(7, &[0xBBu8; 2047]),
    ];

    let plan = make_plan(256, objects);
    let wires = encode_plan(&plan);
    let assembled = decode_and_assemble(&wires);
    assert_eq!(assembled.len(), 7);

    let expected_payloads: Vec<&[u8]> = vec![
        b"",
        b"x",
        &[0x42u8; 255],
        &[0x42u8; 256],
        &[0x42u8; 257],
        &[0xAAu8; 1024],
        &[0xBBu8; 2047],
    ];

    for (i, (expected, (obj_id, payload))) in
        expected_payloads.iter().zip(assembled.iter()).enumerate()
    {
        assert_eq!(obj_id[0], (i + 1) as u8);
        assert_eq!(payload.as_slice(), *expected);

        let expected_digest: [u8; 32] = blake3::hash(expected).into();
        let computed_digest: [u8; 32] = blake3::hash(payload).into();
        assert_eq!(computed_digest, expected_digest);
    }
}

#[test]
fn two_node_throughput_stress() {
    let data = vec![0xDDu8; 8192];
    let plan = make_plan(64, vec![make_object(0x90, &data)]);

    let wires = encode_plan(&plan);
    assert_eq!(wires.len(), 128);

    let assembled = decode_and_assemble(&wires);
    assert_eq!(assembled.len(), 1);
    assert_eq!(assembled[0].1, data);

    let expected: [u8; 32] = blake3::hash(&data).into();
    let computed: [u8; 32] = blake3::hash(&assembled[0].1).into();
    assert_eq!(computed, expected);
}

// ── ShipperSession with transport loopback ─────────────────────────────

#[test]
fn shipper_session_over_loopback_with_integrity() {
    use tidefs_chunk_shipper::ShipperSession;

    let (src_idx, tgt_idx, mut net) = two_node_network();

    let data = vec![0xEEu8; 1024];
    let plan = make_plan(256, vec![make_object(0xA0, &data)]);

    // Source: ShipperSession manages send-side hashing
    let mut session = ShipperSession::new(1, 32);
    session.start_transfer().unwrap();

    let encoder = TransferChunkEncoder::new(TransferChunkEncoderConfig {
        chunk_size: plan.chunk_size,
    });

    for obj in &plan.objects {
        let chunks = encoder.encode_object(obj.object_id, &obj.data);
        for chunk in &chunks {
            session.hash_send_payload(&chunk.payload);
            let wire = chunk.encode_to_wire();
            session.record_frame_sent(chunk.payload.len());
            net.send(src_idx, net.node(tgt_idx).identity, wire);
        }
    }

    net.burst();

    // Target: receive and compute recv-side integrity
    let mut recv_hasher = blake3::Hasher::new();
    recv_hasher.update(b"tidefs-chunk-shipper-session-v1");

    let decoder = ChunkDecoder::new();
    let mut assembler = ObjectAssembler::new();
    let mut recv_count: u64 = 0;

    while let Some((msg, _stale)) = net.recv(tgt_idx) {
        recv_count += 1;
        let mut remaining: &[u8] = &msg.payload;
        while !remaining.is_empty() {
            if let Ok((chunk, rest)) = decoder.decode_chunk(remaining) {
                let len_prefix = (chunk.payload.len() as u64).to_le_bytes();
                recv_hasher.update(&len_prefix);
                recv_hasher.update(&chunk.payload);
                let _ = assembler.feed_chunk(chunk);
                remaining = rest;
            } else {
                break;
            }
        }
    }

    // Verify assembly
    let assembled: Vec<AssembledObject> = assembler.drain_complete();
    assert_eq!(assembled.len(), 1);
    assert_eq!(assembled[0].payload, data);

    // Verify session integrity matches
    let mut r = recv_hasher.clone();
    r.update(&recv_count.to_le_bytes());
    let recv_digest = *r.finalize().as_bytes();

    assert_eq!(
        session.send_digest(),
        recv_digest,
        "session integrity mismatch"
    );
}
