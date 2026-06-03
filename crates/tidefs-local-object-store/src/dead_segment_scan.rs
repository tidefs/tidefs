//! Bootstrap dead-segment scan for reclaim-queue priming on pool open.
//!
//! On pool open, the reclaim queue starts empty. Online population
//! handles the steady-state case, but segments that became dead before
//! the last unmount are invisible until their objects are deleted again.
//!
//! This module scans every on-disk segment file, reads its
//! [`SegmentIntegrityFooter`](crate::SegmentIntegrityFooter), cross-references
//! with the live object index, and classifies each segment as:
//!
//! - **Fully dead**: zero live objects, non-zero record count. The
//!   segment ID is returned for immediate reclamation.
//! - **Partially live**: some live objects remain. A liveness summary
//!   is recorded for future cleaning-priority decisions.
//! - **Fully live**: all records still referenced. No action needed.
//!
//! Corrupt or unparseable footers are logged at warn level and the
//! segment is skipped without failing the pool open.

use std::collections::BTreeMap;
use std::path::Path;

use crate::constants::RECORD_OVERHEAD_BYTES;
use crate::constants::SEGMENT_INTEGRITY_FOOTER_LEN_U64;
use crate::store::{
    decode_segment_integrity_footer, discover_segment_ids, file_len, io_error, segment_path,
    SegmentIntegrityFooter,
};
use crate::{ObjectKey, ObjectLocation, Result, StoreError};

/// Result of a dead-segment bootstrap scan on pool open.
#[derive(Clone, Debug, Default)]
pub struct DeadSegmentScanResult {
    pub segments_scanned: usize,
    pub dead_segment_ids: Vec<u64>,
    pub total_dead_bytes: u64,
    pub partial_segments: Vec<SegmentLivenessSummary>,
    pub corrupt_footers: usize,
}

/// Per-segment liveness summary for partially-dead segments.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SegmentLivenessSummary {
    pub segment_id: u64,
    pub live_object_count: u64,
    pub live_bytes: u64,
    pub dead_bytes: u64,
}

/// Scan all segment files on pool open to identify fully-dead segments
/// and build a liveness summary for partially-dead segments.
///
/// This is a **read-only** pass over existing segment footers. No segment
/// data is mutated.
pub fn scan_dead_segments_on_open(
    segments_dir: &Path,
    index: &BTreeMap<ObjectKey, ObjectLocation>,
    history: &BTreeMap<ObjectKey, Vec<ObjectLocation>>,
) -> Result<DeadSegmentScanResult> {
    let segment_ids = discover_segment_ids(segments_dir)?;

    let mut result = DeadSegmentScanResult {
        segments_scanned: segment_ids.len(),
        ..Default::default()
    };

    if segment_ids.is_empty() {
        return Ok(result);
    }

    // Build per-segment live stats from the index and history in one pass.
    // History entries keep segments alive for get_at_location access even
    // after the corresponding index entry is removed by a delete, but
    // history entries superseded by index entries (same key in both) are
    // only counted once via the index pass.
    let mut per_segment_live: BTreeMap<u64, (u64, u64)> = BTreeMap::new();
    for loc in index.values() {
        let entry = per_segment_live.entry(loc.segment_id).or_default();
        entry.0 = entry.0.saturating_add(1);
        entry.1 = entry.1.saturating_add(loc.payload_len);
    }
    for (key, locations) in history.iter() {
        // Only count history for keys not in the live index.
        if !index.contains_key(key) {
            for loc in locations {
                let entry = per_segment_live.entry(loc.segment_id).or_default();
                entry.0 = entry.0.saturating_add(1);
                entry.1 = entry.1.saturating_add(loc.payload_len);
            }
        }
    }

    // Scan each segment footer and classify.
    for &segment_id in &segment_ids {
        let path = segment_path(segments_dir, segment_id);

        let seg_len = match file_len(&path) {
            Ok(l) => l,
            Err(_) => continue,
        };

        let footer = match read_segment_footer(&path, seg_len) {
            Ok(f) => f,
            Err(_) => {
                tracing::warn!(
                    segment_id = segment_id,
                    "dead-segment scan: unparseable or missing segment footer, skipping"
                );
                result.corrupt_footers += 1;
                continue;
            }
        };

        let (live_obj_count, live_bytes) =
            per_segment_live.get(&segment_id).copied().unwrap_or((0, 0));

        if live_obj_count == 0 && footer.record_count > 0 {
            result.dead_segment_ids.push(segment_id);
            let est_dead_bytes = seg_len.saturating_sub(SEGMENT_INTEGRITY_FOOTER_LEN_U64);
            result.total_dead_bytes = result.total_dead_bytes.saturating_add(est_dead_bytes);
        } else if live_obj_count > 0 {
            // Account for per-record overhead (headers, trailers, footers).
            let record_overhead = footer.record_count.saturating_mul(RECORD_OVERHEAD_BYTES);
            let total_payload_estimate = seg_len
                .saturating_sub(SEGMENT_INTEGRITY_FOOTER_LEN_U64)
                .saturating_sub(record_overhead);
            let dead_bytes = total_payload_estimate.saturating_sub(live_bytes);
            result.partial_segments.push(SegmentLivenessSummary {
                segment_id,
                live_object_count: live_obj_count,
                live_bytes,
                dead_bytes,
            });
        }
    }

    Ok(result)
}

fn read_segment_footer(path: &Path, seg_len: u64) -> Result<SegmentIntegrityFooter> {
    if seg_len < SEGMENT_INTEGRITY_FOOTER_LEN_U64 {
        return Err(StoreError::InvalidOptions {
            reason: "segment file too short for SegmentIntegrityFooter",
        });
    }

    let offset = seg_len - SEGMENT_INTEGRITY_FOOTER_LEN_U64;
    let mut buf = [0u8; crate::constants::SEGMENT_INTEGRITY_FOOTER_LEN];

    use std::os::unix::fs::FileExt;
    let file = std::fs::File::open(path)
        .map_err(|source| io_error("open segment for footer", path, source))?;
    file.read_exact_at(&mut buf, offset)
        .map_err(|source| io_error("read segment footer", path, source))?;

    decode_segment_integrity_footer(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::LocalObjectStore;
    use crate::StoreOptions;
    use std::collections::BTreeMap;

    fn test_options() -> StoreOptions {
        StoreOptions {
            max_segment_bytes: 4096,
            sync_on_write: false,
            repair_torn_tail: true,
            reclaim_enabled: false,
            ..StoreOptions::test_fast()
        }
    }

    /// Helper: open a store, write named objects, flush, and return
    /// the store, segments_dir, and live index snapshot.
    fn open_and_write(
        dir: &tempfile::TempDir,
        opts: &StoreOptions,
        named_payloads: &[(&str, &[u8])],
    ) -> (
        LocalObjectStore,
        std::path::PathBuf,
        BTreeMap<ObjectKey, ObjectLocation>,
    ) {
        let mut store =
            LocalObjectStore::open_with_options(dir.path(), opts.clone()).expect("open store");

        for (name, payload) in named_payloads {
            store.put_named(name, payload).expect("put named object");
        }

        store.flush_segment().expect("flush segment");
        let segments_dir = store.segments_dir().to_path_buf();
        let index = store.test_index().clone();

        (store, segments_dir, index)
    }

    // ── Test 1: all segments live ──────────────────────────────────

    #[test]
    fn all_live_segments_empty_result() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (_store, segments_dir, index) =
            open_and_write(&dir, &test_options(), &[("a", b"hello"), ("b", b"world")]);

        let result =
            scan_dead_segments_on_open(&segments_dir, &index, &BTreeMap::new()).expect("scan");

        assert!(result.dead_segment_ids.is_empty());
        assert_eq!(result.total_dead_bytes, 0);
    }

    // ── Test 2: one fully-dead segment ─────────────────────────────

    #[test]
    fn fully_dead_segment_detected() {
        let dir = tempfile::tempdir().expect("tempdir");
        // max_segment_bytes = 1024, overhead = 224, max payload = 800.
        // Write alpha (700 bytes) in seg 0, beta (700 bytes) rotates
        // to seg 1, overwrite alpha (300 bytes) rotates to seg 2.
        // After overwrite, seg 0 has zero live objects.
        let opts = StoreOptions {
            max_segment_bytes: 1024,
            sync_on_write: false,
            repair_torn_tail: true,
            reclaim_enabled: false,
            ..StoreOptions::test_fast()
        };

        let mut store = LocalObjectStore::open_with_options(dir.path(), opts).expect("open store");

        store.put_named("alpha", &[0xAAu8; 700]).expect("put alpha");
        store.flush_segment().expect("flush seg1");
        let seg1_id = store.current_segment_id;

        store.put_named("beta", &[0xBBu8; 700]).expect("put beta");
        store.flush_segment().expect("flush seg2");

        // Overwrite alpha to move it out of seg1.
        store
            .put_named("alpha", &[0xCCu8; 300])
            .expect("overwrite alpha");
        store.flush_segment().expect("flush after overwrite");

        let segments_dir = store.segments_dir().to_path_buf();
        let index = store.test_index().clone();
        drop(store);

        let result =
            scan_dead_segments_on_open(&segments_dir, &index, &BTreeMap::new()).expect("scan");

        assert!(
            result.dead_segment_ids.contains(&seg1_id),
            "segment {seg1_id} should be fully dead"
        );
        assert!(result.total_dead_bytes > 0);
    }

    // ── Test 3: mixed live, dead, partial ──────────────────────────

    #[test]
    fn mixed_live_dead_partial_classification() {
        let dir = tempfile::tempdir().expect("tempdir");
        // max_segment_bytes = 2048, overhead = 224, max payload = 1824.
        // With 700-byte payloads, each record = 700+224 = 924 bytes.
        // Two records = 1848 bytes, fits in one 2048-byte segment.
        let opts = StoreOptions {
            max_segment_bytes: 2048,
            sync_on_write: false,
            repair_torn_tail: true,
            reclaim_enabled: false,
            ..StoreOptions::test_fast()
        };

        let mut store = LocalObjectStore::open_with_options(dir.path(), opts).expect("open store");

        // Segment A: two live objects (a1, a2), both still live.
        store.put_named("a1", &[0xA1u8; 700]).expect("put a1");
        store.put_named("a2", &[0xA2u8; 700]).expect("put a2");
        store.flush_segment().expect("flush seg A");
        let seg_a = store.current_segment_id;

        // Ensure b1 gets its own segment by using a payload that fills
        // most of the segment, so c1 cannot fit in the same segment.
        // 1500 + 224 = 1724 bytes, segment has 324 bytes left.
        store.put_named("b1", &[0xB1u8; 1500]).expect("put b1");
        store.flush_segment().expect("flush seg B");
        let seg_b = store.current_segment_id;

        // Segment C: two objects (c1, c2). c2 will be overwritten.
        store.put_named("c1", &[0xC1u8; 700]).expect("put c1");
        store.put_named("c2", &[0xC2u8; 700]).expect("put c2");
        store.flush_segment().expect("flush seg C");
        let seg_c = store.current_segment_id;

        // Overwrite b1 and c2.
        store.put_named("b1", &[0xDDu8; 200]).expect("overwrite b1");
        store.flush_segment().expect("flush after overwrite b1");
        store.put_named("c2", &[0xEEu8; 200]).expect("overwrite c2");
        store.flush_segment().expect("flush after overwrite c2");

        let segments_dir = store.segments_dir().to_path_buf();
        let index = store.test_index().clone();
        drop(store);

        let result =
            scan_dead_segments_on_open(&segments_dir, &index, &BTreeMap::new()).expect("scan");

        // seg A: both objects still live.
        assert!(!result.dead_segment_ids.contains(&seg_a));
        let seg_a_summary = result
            .partial_segments
            .iter()
            .find(|s| s.segment_id == seg_a);
        if let Some(s) = seg_a_summary {
            assert_eq!(s.dead_bytes, 0, "seg A should have no dead bytes");
        }

        // seg B: b1 overwritten, no other objects in segment.
        assert!(
            result.dead_segment_ids.contains(&seg_b),
            "seg B (id={seg_b}) should be in dead list: {:?}",
            result.dead_segment_ids
        );

        // seg C: c1 still live, c2 overwritten.
        let seg_c_summary = result
            .partial_segments
            .iter()
            .find(|s| s.segment_id == seg_c)
            .expect("seg C should be in partial list");
        assert_eq!(seg_c_summary.live_object_count, 1);
        assert!(seg_c_summary.live_bytes > 0);
        assert!(seg_c_summary.dead_bytes > 0);
    }
    #[test]
    fn empty_pool_no_panic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let segments_dir = dir.path().join("segments");
        std::fs::create_dir_all(&segments_dir).expect("create segments dir");

        let index: BTreeMap<ObjectKey, ObjectLocation> = BTreeMap::new();
        let result =
            scan_dead_segments_on_open(&segments_dir, &index, &BTreeMap::new()).expect("scan");

        assert_eq!(result.segments_scanned, 0);
        assert!(result.dead_segment_ids.is_empty());
        assert_eq!(result.total_dead_bytes, 0);
        assert!(result.partial_segments.is_empty());
    }

    // ── Test 5: corrupt footer skipped ─────────────────────────────

    #[test]
    fn corrupt_footer_skipped_no_panic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let segments_dir = dir.path().join("segments");
        std::fs::create_dir_all(&segments_dir).expect("create segments dir");

        let bad_path = segments_dir.join("segment-0000000000000001.vlos");
        let data = vec![0xFFu8; 256];
        std::fs::write(&bad_path, &data).expect("write corrupt segment");

        let index: BTreeMap<ObjectKey, ObjectLocation> = BTreeMap::new();
        let result =
            scan_dead_segments_on_open(&segments_dir, &index, &BTreeMap::new()).expect("scan");

        assert_eq!(result.segments_scanned, 1);
        assert_eq!(result.corrupt_footers, 1);
        assert!(result.dead_segment_ids.is_empty());
    }

    // ── Test 6: read-only guarantee ────────────────────────────────

    #[test]
    fn scan_does_not_mutate_segment_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let opts = test_options();

        let mut store = LocalObjectStore::open_with_options(dir.path(), opts).expect("open store");
        store.put_named("ro-test", b"read-only data").expect("put");
        store.flush_segment().expect("flush");

        let segments_dir = store.segments_dir().to_path_buf();
        let index = store.test_index().clone();
        drop(store);

        let seg_ids = discover_segment_ids(&segments_dir).expect("discover");
        let sizes_before: BTreeMap<u64, u64> = seg_ids
            .iter()
            .map(|&id| {
                let path = segment_path(&segments_dir, id);
                let len = file_len(&path).expect("file_len");
                (id, len)
            })
            .collect();

        let _result =
            scan_dead_segments_on_open(&segments_dir, &index, &BTreeMap::new()).expect("scan");

        for (&id, &size_before) in &sizes_before {
            let path = segment_path(&segments_dir, id);
            let size_after = file_len(&path).expect("file_len after scan");
            assert_eq!(
                size_before, size_after,
                "segment {id} size changed after scan"
            );
        }
    }

    // ── Test 7: empty segment (footer with 0 records) not dead ─────

    #[test]
    fn empty_segment_not_classified_dead() {
        let dir = tempfile::tempdir().expect("tempdir");
        let segments_dir = dir.path().join("segments");
        std::fs::create_dir_all(&segments_dir).expect("create segments dir");

        let seg_path = segments_dir.join("segment-0000000000000001.vlos");
        let footer = SegmentIntegrityFooter {
            segment_id: 1,
            record_count: 0,
            total_payload_bytes: 0,
            segment_digest: crate::ProductionIntegrityDigest::ZERO,
            previous_segment_digest: crate::ProductionIntegrityDigest::ZERO,
        };
        let encoded = crate::store::encode_segment_integrity_footer(&footer);
        std::fs::write(&seg_path, encoded).expect("write empty segment");

        let index: BTreeMap<ObjectKey, ObjectLocation> = BTreeMap::new();
        let result =
            scan_dead_segments_on_open(&segments_dir, &index, &BTreeMap::new()).expect("scan");

        assert!(result.dead_segment_ids.is_empty());
        assert!(result.partial_segments.is_empty());
    }

    // ── Integration test: pool open frees dead segments ─────────────

    #[test]
    fn dead_segments_freed_on_pool_open() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Each record: 500+224 = 724 bytes. With max_segment_bytes=1024,
        // each object gets its own segment.
        let opts = StoreOptions {
            max_segment_bytes: 1024,
            sync_on_write: false,
            repair_torn_tail: true,
            reclaim_enabled: false,
            ..StoreOptions::test_fast()
        };

        let seg1_path: std::path::PathBuf;

        {
            let mut store =
                LocalObjectStore::open_with_options(dir.path(), opts.clone()).expect("open store");

            // Write alpha in segment 0.
            store.put_named("alpha", &[0xAAu8; 500]).expect("put alpha");
            store.flush_segment().expect("flush seg0");
            let seg0_id = store.current_segment_id;
            seg1_path = segment_path(store.segments_dir(), seg0_id);
            assert!(seg1_path.exists(), "segment 0 file must exist");

            // Write beta, which rotates to segment 1.
            store.put_named("beta", &[0xBBu8; 500]).expect("put beta");
            store.flush_segment().expect("flush seg1");

            // Overwrite alpha, rotating to segment 2.
            // This makes segment 0 fully dead.
            store
                .put_named("alpha", &[0xCCu8; 300])
                .expect("overwrite alpha");
            store.flush_segment().expect("flush after overwrite");

            // Verify segment 0 file still exists before close.
            assert!(seg1_path.exists(), "segment 0 file must exist before close");
        }
        // Store dropped — pool closed.

        // Re-open: the bootstrap scan should free segment 0.
        let store2 = LocalObjectStore::open_with_options(dir.path(), opts).expect("re-open store");

        // The dead segment's file should be gone.
        assert!(
            !seg1_path.exists(),
            "segment 0 file should be deleted by bootstrap scan"
        );

        // The free_map should have segment 0 marked as free.
        // (PoolAllocator::is_free checks the spacemap bitmap.)
        // We check via the free_count: after freeing, at least one
        // segment should be free.
        let free = store2.free_map.free_count();
        assert!(
            free > 0,
            "free_map should have at least one free segment, got {free}"
        );

        drop(store2);
    }
}
