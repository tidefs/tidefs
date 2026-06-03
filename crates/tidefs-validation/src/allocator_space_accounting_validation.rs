//! Block-allocator free-space tracking and object-store data-integrity
//! validation across write-delete-reallocate-write cycles.
//!
//! Wires together BlockAllocator, SpaceAccounting, and LocalObjectStore
//! and exercises the full lifecycle: allocate, write (BLAKE3
//! content-addressed), read-back, delete, reallocate freed space,
//! verify no stale data, and assert zero cumulative free-space drift.
//!
//! The entire module is `#[cfg(test)]` — no library surface.

#![deny(dead_code)]
#![deny(unused_imports)]

#[cfg(test)]
#[cfg(all(feature = "storage-core", feature = "fuse"))]
mod imp {
    use std::collections::HashMap;
    use std::time::{SystemTime, UNIX_EPOCH};

    use tidefs_block_allocator::{BlockAllocator, BlockId, Region};
    use tidefs_local_object_store::{LocalObjectStore, ObjectKey, StoreOptions};
    use tidefs_space_accounting::{PoolCounters, SpaceAccounting};
    use tidefs_types_space_accounting_core::SpaceDelta;

    const TEST_POOL_BLOCKS: u64 = 4096;
    const BLOCK_SIZE: u64 = 4096;

    /// Create a StoreOptions suitable for validation tests:
    /// small enough to exercise segment rotation, large enough
    /// to accept multi-KiB payloads up to 512 KiB.
    fn test_store_options() -> StoreOptions {
        StoreOptions {
            max_segment_bytes: 2 * 1024 * 1024,
            sync_on_write: false,
            ..StoreOptions::durable()
        }
    }

    struct Validator {
        allocator: BlockAllocator,
        space: SpaceAccounting,
        store: LocalObjectStore,
        block_tracker: HashMap<ObjectKey, Vec<BlockId>>,
        expected_used_blocks: u64,
        expected_logical_bytes: u64,
    }

    impl Validator {
        fn new(temp_root: &std::path::Path) -> Self {
            let allocator = BlockAllocator::new(
                TEST_POOL_BLOCKS,
                BLOCK_SIZE as u32,
                Region::new(0, TEST_POOL_BLOCKS * BLOCK_SIZE),
            );
            let mut space = SpaceAccounting::empty();
            space.update_pool_counters(PoolCounters {
                phys_total_bytes: TEST_POOL_BLOCKS * BLOCK_SIZE,
                phys_free_bytes: TEST_POOL_BLOCKS * BLOCK_SIZE,
                ..Default::default()
            });

            let store = LocalObjectStore::open_with_options(temp_root, test_store_options())
                .expect("LocalObjectStore::open_with_options");

            Validator {
                allocator,
                space,
                store,
                block_tracker: HashMap::new(),
                expected_used_blocks: 0,
                expected_logical_bytes: 0,
            }
        }

        fn write_object(&mut self, payload: &[u8]) -> (ObjectKey, u32) {
            let key = self
                .store
                .put_content_addressed(payload)
                .expect("store.put_content_addressed");
            let blocks_needed = self.blocks_for_bytes(payload.len() as u64);

            let mut allocated = Vec::with_capacity(blocks_needed as usize);
            for _ in 0..blocks_needed {
                let ids = self
                    .allocator
                    .alloc(1)
                    .expect("allocator.alloc(1): pool full");
                allocated.push(ids[0]);
            }
            self.expected_used_blocks += blocks_needed as u64;
            self.expected_logical_bytes += payload.len() as u64;

            let delta = SpaceDelta::new_write(payload.len() as u64);
            self.space
                .commit_delta(delta)
                .expect("space.commit_delta(write)");

            self.block_tracker.insert(key, allocated);
            (key, blocks_needed)
        }

        fn read_object(&self, key: ObjectKey, expected_payload: &[u8]) {
            let got = self.store.get(key).expect("store.get");
            assert_eq!(
                got.as_deref(),
                Some(expected_payload),
                "payload mismatch for key {key}: stale data or corruption"
            );
        }

        fn delete_object(&mut self, key: ObjectKey, blocks: u32, byte_len: u64) {
            let existed = self.store.delete(key).expect("store.delete");
            assert!(existed, "delete should report key existed");

            let block_ids = self
                .block_tracker
                .remove(&key)
                .unwrap_or_else(|| panic!("block_tracker missing key {key}"));
            assert_eq!(
                block_ids.len() as u32,
                blocks,
                "block count mismatch for key {key}"
            );

            let free_before = self.allocator.free_count();
            self.allocator.free(&block_ids);
            let free_after = self.allocator.free_count();
            assert_eq!(
                free_after - free_before,
                blocks as u64,
                "free_count should increase by exactly {blocks} after freeing"
            );
            self.expected_used_blocks -= blocks as u64;
            self.expected_logical_bytes -= byte_len;

            let delta = SpaceDelta::new_free(byte_len);
            self.space
                .commit_delta(delta)
                .expect("space.commit_delta(free)");
        }

        fn blocks_for_bytes(&self, byte_len: u64) -> u32 {
            if byte_len == 0 {
                return 1;
            }
            byte_len.div_ceil(BLOCK_SIZE) as u32
        }

        fn assert_no_drift(&self) {
            let expected_free = TEST_POOL_BLOCKS - self.expected_used_blocks;
            let actual_free = self.allocator.free_count();
            assert_eq!(
                actual_free, expected_free,
                "free-space drift: allocator free_count={actual_free}, expected={expected_free}"
            );
        }

        fn assert_space_consistent(&self) {
            let counters = self.space.counters();
            let expected = self.expected_logical_bytes;
            let used = counters.logical_used_bytes;
            let diff = if used > expected {
                used - expected
            } else {
                expected - used
            };
            assert!(
                diff <= BLOCK_SIZE * 100,
                "space accounting drift: logical_used={used}, expected={expected}, diff={diff}"
            );
        }
    }

    // ── Helpers ────────────────────────────────────────────────────

    fn make_payload(seed: u64, len: usize) -> Vec<u8> {
        let mut buf = Vec::with_capacity(len);
        let mut state = seed;
        for _ in 0..len {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            buf.push((state >> 32) as u8);
        }
        buf
    }

    fn blake3_hash(data: &[u8]) -> [u8; 32] {
        *blake3::hash(data).as_bytes()
    }

    // ── Tests ──────────────────────────────────────────────────────

    #[test]
    fn sequential_write_read_delete_reallocate_cycle() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("tidefs-alloc-val-seq-{nanos}"));
        std::fs::create_dir_all(&root).expect("create_dir_all");

        let mut v = Validator::new(&root);

        let sizes: &[usize] = &[512, 1024, 4096, 2048, 256, 8192, 16384];
        let mut objects: Vec<(ObjectKey, Vec<u8>, u32)> = Vec::new();

        for (i, &size) in sizes.iter().enumerate() {
            let payload = make_payload(i as u64, size);
            let (key, blocks) = v.write_object(&payload);
            let expected_key_hash = blake3_hash(&payload);
            assert_eq!(
                key.as_bytes32(),
                expected_key_hash,
                "ObjectKey should be BLAKE3-256 of payload"
            );
            objects.push((key, payload, blocks));
        }

        for (key, payload, _) in &objects {
            v.read_object(*key, payload);
        }

        v.assert_no_drift();

        let keep_count = objects.len() / 2;
        let mut deleted: Vec<(ObjectKey, Vec<u8>, u32)> = Vec::new();
        for _ in 0..(objects.len() - keep_count) {
            deleted.push(objects.pop().unwrap());
        }

        for (key, payload, blocks) in &deleted {
            v.delete_object(*key, *blocks, payload.len() as u64);
        }

        for (key, _, _) in &deleted {
            let got = v.store.get(*key).expect("store.get");
            assert!(got.is_none(), "deleted key should return None");
        }

        for (key, payload, _) in &objects {
            v.read_object(*key, payload);
        }

        v.assert_no_drift();

        let new_sizes: &[usize] = &[3276, 1024, 2048, 768];
        let mut new_objects: Vec<(ObjectKey, Vec<u8>, u32)> = Vec::new();

        for (i, &size) in new_sizes.iter().enumerate() {
            let payload = make_payload(100 + i as u64, size);
            let (key, _blocks) = v.write_object(&payload);
            for (old_key, _, _) in deleted.iter().chain(objects.iter()) {
                assert_ne!(
                    key, *old_key,
                    "new object key collides with existing key: stale data risk"
                );
            }
            new_objects.push((key, payload, _blocks));
        }

        for (key, payload, _) in &new_objects {
            v.read_object(*key, payload);
        }

        for (key, payload, _) in &objects {
            v.read_object(*key, payload);
        }

        v.assert_no_drift();
        v.assert_space_consistent();

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn random_write_delete_rewrite_drift_zero() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("tidefs-alloc-val-rand-{nanos}"));
        std::fs::create_dir_all(&root).expect("create_dir_all");

        let mut v = Validator::new(&root);
        let mut live: Vec<(ObjectKey, Vec<u8>, u32)> = Vec::new();
        let mut rng: u64 = 42;

        for _cycle in 0..20 {
            let write_count = ((rng % 4) + 2) as usize;
            for _i in 0..write_count {
                rng = rng.wrapping_mul(1664525).wrapping_add(1013904223);
                let size = ((rng % 32) + 1) as usize * 128;
                let payload = make_payload(rng, size);
                let (key, blocks) = v.write_object(&payload);
                live.push((key, payload, blocks));
            }

            rng = rng.wrapping_mul(1664525).wrapping_add(1013904223);
            let delete_target = ((live.len() as u64 * 30 / 100).max(1)).min(live.len() as u64);
            for _ in 0..delete_target {
                if live.is_empty() {
                    break;
                }
                rng = rng.wrapping_mul(1664525).wrapping_add(1013904223);
                let idx = (rng as usize) % live.len();
                let (key, payload, blocks) = live.swap_remove(idx);
                v.delete_object(key, blocks, payload.len() as u64);
            }

            for (key, payload, _) in &live {
                v.read_object(*key, payload);
            }

            v.assert_no_drift();
        }

        v.assert_space_consistent();

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn near_full_pool_stress() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("tidefs-alloc-val-stress-{nanos}"));
        std::fs::create_dir_all(&root).expect("create_dir_all");

        let mut v = Validator::new(&root);
        let mut live: Vec<(ObjectKey, Vec<u8>, u32)> = Vec::new();
        let mut total_blocks: u64 = 0;

        let target_blocks = TEST_POOL_BLOCKS - 50;
        while total_blocks < target_blocks {
            let payload = make_payload(total_blocks, 512);
            let (key, blocks) = v.write_object(&payload);
            total_blocks += blocks as u64;
            live.push((key, payload, blocks));
        }

        v.assert_no_drift();

        let remove_indices: &[usize] = &[0, 5, 10, 15, 20, 25, 30];
        for &idx in remove_indices.iter().rev() {
            if idx < live.len() {
                let (key, payload, blocks) = live.remove(idx);
                v.delete_object(key, blocks, payload.len() as u64);
                total_blocks -= blocks as u64;
            }
        }

        v.assert_no_drift();

        while total_blocks < target_blocks {
            let payload = make_payload(total_blocks + 100000, 512);
            let (key, blocks) = v.write_object(&payload);
            total_blocks += blocks as u64;
            live.push((key, payload, blocks));
        }

        for (key, payload, _) in &live {
            v.read_object(*key, payload);
        }

        v.assert_no_drift();
        v.assert_space_consistent();

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn no_double_allocation() {
        let allocator = BlockAllocator::new(128, 4096, Region::new(0, 128 * 4096));

        let mut seen = std::collections::HashSet::new();
        for _ in 0..128 {
            let blocks = allocator.alloc(1).expect("alloc(1)");
            let id = blocks[0];
            assert!(
                seen.insert(id),
                "double-allocation: block {id} was already allocated"
            );
        }
        assert!(allocator.alloc(1).is_err());
        assert_eq!(allocator.free_count(), 0);
    }

    #[test]
    fn space_accounting_delta_tracking_baseline() {
        let mut space = SpaceAccounting::empty();
        space.update_pool_counters(PoolCounters {
            phys_total_bytes: 1_000_000,
            phys_free_bytes: 1_000_000,
            ..Default::default()
        });

        space
            .commit_delta(SpaceDelta::new_write(102400))
            .expect("write delta");
        assert_eq!(space.counters().logical_used_bytes, 102400);

        space
            .commit_delta(SpaceDelta::new_write(51200))
            .expect("write delta");
        assert_eq!(space.counters().logical_used_bytes, 153600);

        space
            .commit_delta(SpaceDelta::new_free(81920))
            .expect("free delta");
        assert_eq!(space.counters().logical_used_bytes, 71680);

        space
            .commit_delta(SpaceDelta::new_free(71680))
            .expect("free delta");
        assert_eq!(space.counters().logical_used_bytes, 0);
    }

    #[test]
    fn block_allocator_free_used_invariant() {
        let total: u64 = 256;
        let allocator = BlockAllocator::new(total, 4096, Region::new(0, total * 4096));
        assert_eq!(allocator.free_count(), total);
        assert_eq!(total - allocator.free_count(), 0);

        let a = allocator.alloc_contiguous(10).unwrap();
        assert_eq!(allocator.free_count(), total - 10);
        assert_eq!(total - allocator.free_count(), 10);

        let b = allocator.alloc_any(20).unwrap();
        assert_eq!(allocator.free_count(), total - 30);

        allocator.free(&a);
        assert_eq!(allocator.free_count(), total - 20);

        allocator.free(&b);
        assert_eq!(allocator.free_count(), total);
        assert_eq!(total - allocator.free_count(), 0);
    }
}
