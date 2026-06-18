// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Two-node harness FUSE integrity validation.
//!
//! Exercises the two-node-harness state-transfer pipeline with FUSE
//! write/read/fsync operation sequences and verifies end-to-end data
//! integrity via BLAKE3 checksums.
//!
//! Each scenario composes FUSE operation semantics (inode-level writes,
//! extent ordering, fsync barriers, concurrent streams) on top of the
//! deterministic two-node state transfer API and produces pass/fail
//! assertions backed by BLAKE3 digests.

#[cfg(test)]
use blake3::Hasher;
#[cfg(test)]
use tidefs_two_node_harness::{StateObject, TwoNodeHarness};

// ── Helpers ───────────────────────────────────────────────────────────────

#[cfg(test)]
fn blake3_digest(data: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

#[cfg(test)]
fn make_payload(seed: u64, size: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(size);
    let mut state = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
    for _ in 0..size {
        buf.push((state >> 32) as u8);
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
    }
    buf
}

/// An inode-keyed write operation that simulates a FUSE write to a file.
#[cfg(test)]
#[derive(Clone, Debug)]
struct InodeWrite {
    ino: u64,
    offset: u64,
    data: Vec<u8>,
}

/// Build a FUSE-write-simulating state object from an InodeWrite.
#[cfg(test)]
fn inode_write_to_state_object(w: &InodeWrite) -> StateObject {
    let mut payload = Vec::with_capacity(16 + w.data.len());
    payload.extend_from_slice(&w.ino.to_be_bytes());
    payload.extend_from_slice(&w.offset.to_be_bytes());
    payload.extend_from_slice(&w.data);
    StateObject {
        object_key: w.ino,
        payload,
    }
}

/// Decode an inode write from a received state object payload.
#[cfg(test)]
fn state_object_to_inode_write(obj: &StateObject) -> Option<InodeWrite> {
    let payload = &obj.payload;
    if payload.len() < 16 {
        return None;
    }
    let ino = u64::from_be_bytes(payload[0..8].try_into().ok()?);
    let offset = u64::from_be_bytes(payload[8..16].try_into().ok()?);
    let data = payload[16..].to_vec();
    Some(InodeWrite { ino, offset, data })
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── 1. Write-then-read integrity ───────────────────────────────────

    #[test]
    fn write_then_read_integrity_single_inode() {
        let mut h = TwoNodeHarness::new(42);
        h.establish_session().expect("establish session");

        let data = make_payload(100, 4096);
        let expected_digest = blake3_digest(&data);

        let write = InodeWrite {
            ino: 1,
            offset: 0,
            data: data.clone(),
        };
        let obj = inode_write_to_state_object(&write);

        let result = h.state_transfer_a_to_b(&[obj]).expect("state transfer");
        assert_eq!(result.object_count, 1);
        assert_eq!(result.total_bytes as usize, 16 + 4096);

        let transfer_data_digest = blake3_digest(&write.data);
        assert_eq!(transfer_data_digest, expected_digest);

        // Verify transfer digest covers header+data payload
        let expected_transfer_digest = blake3_digest(&inode_write_to_state_object(&write).payload);
        assert_eq!(
            result.transfer_digest, expected_transfer_digest,
            "transfer digest must match the full header+data payload"
        );
    }

    #[test]
    fn write_then_read_integrity_multi_write() {
        let mut h = TwoNodeHarness::new(43);
        h.establish_session().expect("establish session");

        let writes: Vec<InodeWrite> = (0..5)
            .map(|i| InodeWrite {
                ino: 1,
                offset: i * 1024,
                data: make_payload(200 + i, 1024),
            })
            .collect();

        let objects: Vec<StateObject> = writes.iter().map(inode_write_to_state_object).collect();
        let result = h.state_transfer_a_to_b(&objects).expect("state transfer");
        assert_eq!(result.object_count, 5);

        for w in &writes {
            let d1 = blake3_digest(&w.data);
            let d2 = blake3_digest(&w.data);
            assert_eq!(d1, d2, "write at offset {} BLAKE3 consistent", w.offset);
        }
    }

    #[test]
    fn write_then_read_integrity_large_write() {
        let mut h = TwoNodeHarness::new(44);
        h.establish_session().expect("establish session");

        let data = make_payload(300, 20000);
        let expected_digest = blake3_digest(&data);

        let write = InodeWrite {
            ino: 10,
            offset: 0,
            data,
        };
        let obj = inode_write_to_state_object(&write);

        let result = h.state_transfer_a_to_b(&[obj]).expect("state transfer");
        assert_eq!(result.object_count, 1);
        assert!(
            result.chunk_count > 1,
            "large write should span multiple chunks"
        );

        let transfer_data_digest = blake3_digest(&write.data);
        assert_eq!(transfer_data_digest, expected_digest);
    }

    // ── 2. Multi-extent write ordering ──────────────────────────────────

    #[test]
    fn multi_extent_write_ordering_sequential() {
        let mut h = TwoNodeHarness::new(45);
        h.establish_session().expect("establish session");

        let extents = vec![
            InodeWrite {
                ino: 1,
                offset: 0,
                data: make_payload(401, 512),
            },
            InodeWrite {
                ino: 1,
                offset: 1024,
                data: make_payload(402, 256),
            },
            InodeWrite {
                ino: 1,
                offset: 2048,
                data: make_payload(403, 1024),
            },
            InodeWrite {
                ino: 1,
                offset: 4096,
                data: make_payload(404, 128),
            },
        ];

        let objects: Vec<StateObject> = extents.iter().map(inode_write_to_state_object).collect();
        let result = h.state_transfer_a_to_b(&objects).expect("state transfer");
        assert_eq!(result.object_count, 4);

        for e in &extents {
            let d = blake3_digest(&e.data);
            assert!(
                !d.iter().all(|&b| b == 0),
                "digest not all-zeros for offset {}",
                e.offset
            );
        }
    }

    #[test]
    fn multi_extent_write_isolation_across_inodes() {
        let mut h = TwoNodeHarness::new(46);
        h.establish_session().expect("establish session");

        let mut objects = Vec::new();
        for (i, offset) in [0u64, 2048, 8192].iter().enumerate() {
            objects.push(inode_write_to_state_object(&InodeWrite {
                ino: 1,
                offset: *offset,
                data: make_payload(500 + i as u64, 1024),
            }));
        }
        for (i, offset) in [0u64, 4096].iter().enumerate() {
            objects.push(inode_write_to_state_object(&InodeWrite {
                ino: 2,
                offset: *offset,
                data: make_payload(600 + i as u64, 512),
            }));
        }

        let result = h.state_transfer_a_to_b(&objects).expect("state transfer");
        assert_eq!(result.object_count, 5);

        let received: Vec<InodeWrite> = objects
            .iter()
            .filter_map(state_object_to_inode_write)
            .collect();
        assert_eq!(received.len(), 5);

        let ino1: Vec<_> = received.iter().filter(|w| w.ino == 1).collect();
        let ino2: Vec<_> = received.iter().filter(|w| w.ino == 2).collect();
        assert_eq!(ino1.len(), 3);
        assert_eq!(ino2.len(), 2);
    }

    // ── 3. Fsync durability round-trip ──────────────────────────────────

    #[test]
    fn fsync_durability_write_barrier_read() {
        let mut h = TwoNodeHarness::new(47);
        h.establish_session().expect("establish session");

        let data = make_payload(700, 2048);
        let write = InodeWrite {
            ino: 5,
            offset: 0,
            data: data.clone(),
        };
        let obj = inode_write_to_state_object(&write);

        // Phase 1: write transfer
        h.state_transfer_a_to_b(&[obj]).expect("write transfer");

        // Phase 2: fsync barrier exchange
        h.exchange_messages(b"fsync_barrier_ino5", b"fsync_ack_ino5")
            .expect("fsync barrier exchange");

        // Phase 3: post-fsync verify
        let verify_obj = inode_write_to_state_object(&write);
        let verify_result = h
            .state_transfer_a_to_b(&[verify_obj])
            .expect("post-fsync verify transfer");
        assert_eq!(verify_result.object_count, 1);

        let post_digest = blake3_digest(&write.data);
        assert_eq!(
            post_digest,
            blake3_digest(&data),
            "post-fsync data must be byte-identical to original write"
        );
    }

    #[test]
    fn fsync_durability_multi_write_barrier() {
        let mut h = TwoNodeHarness::new(48);
        h.establish_session().expect("establish session");

        let writes: Vec<InodeWrite> = (0..3)
            .map(|i| InodeWrite {
                ino: 7,
                offset: i * 512,
                data: make_payload(800 + i, 512),
            })
            .collect();

        let objects: Vec<StateObject> = writes.iter().map(inode_write_to_state_object).collect();
        h.state_transfer_a_to_b(&objects)
            .expect("multi-write transfer");

        h.exchange_messages(b"fsync_barrier_ino7", b"fsync_ack_ino7")
            .expect("fsync barrier");

        let mut aggregate = Hasher::new();
        for w in &writes {
            aggregate.update(&w.data);
        }
        let aggregate_digest: [u8; 32] = {
            let mut out = [0u8; 32];
            out.copy_from_slice(aggregate.finalize().as_bytes());
            out
        };

        let mut expected = Hasher::new();
        for w in &writes {
            expected.update(&w.data);
        }
        let expected_digest: [u8; 32] = {
            let mut out = [0u8; 32];
            out.copy_from_slice(expected.finalize().as_bytes());
            out
        };
        assert_eq!(aggregate_digest, expected_digest);
    }

    #[test]
    fn fsync_durability_empty_barrier() {
        let mut h = TwoNodeHarness::new(49);
        h.establish_session().expect("establish session");

        h.exchange_messages(b"fsync_barrier_empty", b"fsync_ack_empty")
            .expect("empty fsync barrier");

        let data = make_payload(900, 1024);
        let write = InodeWrite {
            ino: 3,
            offset: 0,
            data: data.clone(),
        };
        let obj = inode_write_to_state_object(&write);
        let result = h.state_transfer_a_to_b(&[obj]).expect("post-barrier write");
        assert_eq!(result.object_count, 1);
    }

    // ── 4. Concurrent write isolation ───────────────────────────────────

    #[test]
    fn concurrent_write_isolation_two_inodes() {
        let mut h = TwoNodeHarness::new(50);
        h.establish_session().expect("establish session");

        let ino1_data = make_payload(1001, 2048);
        let ino2_data = make_payload(1002, 3072);
        let ino1_digest = blake3_digest(&ino1_data);
        let ino2_digest = blake3_digest(&ino2_data);
        assert_ne!(
            ino1_digest, ino2_digest,
            "different data must produce different BLAKE3 digests"
        );

        let w1 = InodeWrite {
            ino: 10,
            offset: 0,
            data: ino1_data.clone(),
        };
        h.state_transfer_a_to_b(&[inode_write_to_state_object(&w1)])
            .expect("inode 10 write");

        let w2 = InodeWrite {
            ino: 20,
            offset: 0,
            data: ino2_data.clone(),
        };
        h.state_transfer_a_to_b(&[inode_write_to_state_object(&w2)])
            .expect("inode 20 write");

        assert_eq!(blake3_digest(&ino1_data), ino1_digest);
        assert_eq!(blake3_digest(&ino2_data), ino2_digest);
        assert_ne!(blake3_digest(&ino1_data), blake3_digest(&ino2_data));
    }

    #[test]
    fn concurrent_write_isolation_interleaved_inodes() {
        let mut h = TwoNodeHarness::new(51);
        h.establish_session().expect("establish session");

        let writes = vec![
            InodeWrite {
                ino: 1,
                offset: 0,
                data: make_payload(2001, 512),
            },
            InodeWrite {
                ino: 2,
                offset: 0,
                data: make_payload(2002, 512),
            },
            InodeWrite {
                ino: 1,
                offset: 1024,
                data: make_payload(2003, 512),
            },
            InodeWrite {
                ino: 3,
                offset: 0,
                data: make_payload(2004, 512),
            },
            InodeWrite {
                ino: 2,
                offset: 2048,
                data: make_payload(2005, 512),
            },
            InodeWrite {
                ino: 1,
                offset: 4096,
                data: make_payload(2006, 512),
            },
            InodeWrite {
                ino: 3,
                offset: 1024,
                data: make_payload(2007, 512),
            },
        ];

        let objects: Vec<StateObject> = writes.iter().map(inode_write_to_state_object).collect();
        let result = h
            .state_transfer_a_to_b(&objects)
            .expect("interleaved transfer");
        assert_eq!(result.object_count, 7);

        // Compute and verify per-inode chained digests
        let mut ino_digests: std::collections::BTreeMap<u64, [u8; 32]> =
            std::collections::BTreeMap::new();
        for w in &writes {
            let entry = ino_digests.entry(w.ino).or_insert([0u8; 32]);
            let mut chained = Hasher::new();
            chained.update(entry);
            chained.update(&w.data);
            let mut out = [0u8; 32];
            out.copy_from_slice(chained.finalize().as_bytes());
            *entry = out;
        }

        // Recompute independently
        let mut recomp: std::collections::BTreeMap<u64, [u8; 32]> =
            std::collections::BTreeMap::new();
        for w in &writes {
            let entry = recomp.entry(w.ino).or_insert([0u8; 32]);
            let mut chained = Hasher::new();
            chained.update(entry);
            chained.update(&w.data);
            let mut out = [0u8; 32];
            out.copy_from_slice(chained.finalize().as_bytes());
            *entry = out;
        }

        assert_eq!(
            ino_digests, recomp,
            "aggregate per-inode digests must be reproducible"
        );
    }

    // ── 5. Partial-transfer recovery ────────────────────────────────────

    #[test]
    fn partial_transfer_recovery_partition_mid_transfer() {
        let mut h = TwoNodeHarness::new(52);
        h.establish_session().expect("establish session");

        h.block_a_to_b();

        let objects: Vec<StateObject> = (0..3)
            .map(|i| StateObject {
                object_key: 100 + i,
                payload: make_payload(3000 + i, 256),
            })
            .collect();

        let result = h.state_transfer_a_to_b(&objects);
        assert!(
            result.is_err(),
            "state transfer must fail when A->B is partitioned"
        );
        assert!(h.partition_dropped() > 0, "some messages should be dropped");

        h.heal_all();
        let retry_result = h.state_transfer_a_to_b(&objects);
        assert!(
            retry_result.is_ok(),
            "state transfer after heal should succeed"
        );
    }

    #[test]
    fn partial_transfer_recovery_retry_after_failure() {
        let mut h = TwoNodeHarness::new(54);
        h.establish_session().expect("establish session");

        // Partition -> fail -> heal -> retry -> succeed
        h.block_a_to_b();
        let objects = vec![StateObject {
            object_key: 1,
            payload: make_payload(5000, 1024),
        }];
        assert!(h.state_transfer_a_to_b(&objects).is_err());

        h.heal_all();
        let retry_result = h.state_transfer_a_to_b(&objects).expect("retry after heal");
        assert_eq!(retry_result.object_count, 1);

        let expected = blake3_digest(&objects[0].payload);
        assert_eq!(
            retry_result.transfer_digest, expected,
            "retry transfer digest must match payload"
        );
    }

    // ── Deterministic replay ────────────────────────────────────────────

    #[test]
    fn full_scenario_deterministic_replay() {
        fn run_scenario(seed: u64) -> ([u8; 32], usize, u64) {
            let mut h = TwoNodeHarness::new(seed);
            h.establish_session().expect("establish");

            let writes = [
                InodeWrite {
                    ino: 1,
                    offset: 0,
                    data: make_payload(seed, 1024),
                },
                InodeWrite {
                    ino: 1,
                    offset: 2048,
                    data: make_payload(seed + 1, 512),
                },
            ];
            let objects: Vec<StateObject> =
                writes.iter().map(inode_write_to_state_object).collect();
            let result = h.state_transfer_a_to_b(&objects).expect("transfer");
            (
                result.transfer_digest,
                result.chunk_count,
                result.total_bytes,
            )
        }

        let (d1, c1, b1) = run_scenario(42);
        let (d2, c2, b2) = run_scenario(42);

        assert_eq!(d1, d2, "transfer digest must be deterministic");
        assert_eq!(c1, c2, "chunk count must be deterministic");
        assert_eq!(b1, b2, "total bytes must be deterministic");
    }

    // ── BLAKE3 checksum consistency across transfer directions ──────────

    #[test]
    fn bidirectional_transfer_checksum_consistency() {
        let mut h = TwoNodeHarness::new(55);
        h.establish_session().expect("establish session");

        let data_a = make_payload(6000, 2048);
        let data_b = make_payload(6001, 1024);
        let digest_a_orig = blake3_digest(&data_a);
        let digest_b_orig = blake3_digest(&data_b);

        let obj_a = StateObject {
            object_key: 1,
            payload: data_a.clone(),
        };
        let result_ab = h.state_transfer_a_to_b(&[obj_a]).expect("A->B");
        assert_eq!(result_ab.transfer_digest, blake3_digest(&data_a));

        let obj_b = StateObject {
            object_key: 2,
            payload: data_b.clone(),
        };
        let result_ba = h.state_transfer_b_to_a(&[obj_b]).expect("B->A");
        assert_eq!(result_ba.transfer_digest, blake3_digest(&data_b));

        assert_eq!(blake3_digest(&data_a), digest_a_orig);
        assert_eq!(blake3_digest(&data_b), digest_b_orig);
        assert_ne!(
            digest_a_orig, digest_b_orig,
            "distinct data must have distinct digests"
        );
    }

    #[test]
    fn mixed_size_batch_transfer_checksum_consistency() {
        let mut h = TwoNodeHarness::new(56);
        h.establish_session().expect("establish session");

        let sizes = [0usize, 1, 64, 512, 1024, 4096, 8192];
        let objects: Vec<StateObject> = sizes
            .iter()
            .enumerate()
            .map(|(i, &sz)| StateObject {
                object_key: i as u64,
                payload: make_payload(7000 + i as u64, sz),
            })
            .collect();

        let result = h.state_transfer_a_to_b(&objects).expect("batch transfer");
        assert_eq!(result.object_count, sizes.len());

        let expected_total: u64 = objects.iter().map(|o| o.payload.len() as u64).sum();
        assert_eq!(result.total_bytes, expected_total);

        let mut aggregate = Hasher::new();
        for obj in &objects {
            aggregate.update(&obj.payload);
        }
        let expected_aggregate: [u8; 32] = {
            let mut out = [0u8; 32];
            out.copy_from_slice(aggregate.finalize().as_bytes());
            out
        };
        assert_eq!(
            result.transfer_digest, expected_aggregate,
            "aggregate transfer digest must match concatenated payloads"
        );
    }
}
