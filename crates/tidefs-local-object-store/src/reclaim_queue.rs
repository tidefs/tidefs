//! Persistent reclaim-queue storage backed by the local object store.
//!
//! Implements [`tidefs_reclaim_queue_core::ReclaimQueueStorage`] for
//! [`LocalObjectStore`], storing serialized reclaim-queue bytes as a
//! named object. Each store/flush wraps the payload in an
//! [`IntegrityTrailerV2`] (via the object store's normal write path),
//! providing integrity verification on load.
//!
//! The [`SegmentLivenessQueue`] is additionally wrapped in a CRC32C-
//! protected wire format ([`tidefs_reclaim::encode_reclaim_wire`])
//! wire-format frame is verified before deserialisation.

use tidefs_reclaim::{decode_reclaim_wire, encode_reclaim_wire, ReclaimWireError};
use tidefs_reclaim_queue_core::{
    BPlusTreeReclaimQueue, ReclaimQueueStorage, SegmentLivenessPersistError, SegmentLivenessQueue,
};

use crate::error::StoreError;
use crate::store::LocalObjectStore;

/// Well-known name for the reclaim-queue (liveness) object.
pub(crate) const RECLAIM_QUEUE_OBJECT_NAME: &str = "tidefs-reclaim-queue";

impl ReclaimQueueStorage for LocalObjectStore {
    type Error = StoreError;

    fn load_reclaim_queue(&self) -> Result<Option<Vec<u8>>, Self::Error> {
        self.get_named(RECLAIM_QUEUE_OBJECT_NAME)
    }

    fn store_reclaim_queue(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        self.put_named(RECLAIM_QUEUE_OBJECT_NAME, data)?;
        Ok(())
    }
}

/// Well-known name for the BPlusTreeReclaimQueue entries (refcount deltas).
pub(crate) const RECLAIM_QUEUE_ENTRIES_OBJECT_NAME: &str = "tidefs-reclaim-queue-entries";

/// Load a [`BPlusTreeReclaimQueue`] from the object store.
pub(crate) fn load_reclaim_queue_entries(store: &LocalObjectStore) -> BPlusTreeReclaimQueue {
    match store.get_named(RECLAIM_QUEUE_ENTRIES_OBJECT_NAME) {
        Ok(Some(bytes)) => match BPlusTreeReclaimQueue::decode(&bytes) {
            Ok(queue) => queue,
            Err(e) => {
                eprintln!("tidefs: reclaim-queue entries decode error: {e}");
                BPlusTreeReclaimQueue::new()
            }
        },
        Ok(None) => BPlusTreeReclaimQueue::new(),
        Err(e) => {
            eprintln!("tidefs: reclaim-queue entries load error: {e}");
            BPlusTreeReclaimQueue::new()
        }
    }
}

/// Persist a [`BPlusTreeReclaimQueue`] to the object store.
pub(crate) fn store_reclaim_queue_entries(
    queue: &BPlusTreeReclaimQueue,
    store: &mut LocalObjectStore,
) -> Result<(), StoreError> {
    let bytes = queue.encode();
    store.put_named(RECLAIM_QUEUE_ENTRIES_OBJECT_NAME, &bytes)?;
    Ok(())
}

/// Load a [`SegmentLivenessQueue`] from the object store.
/// Decodes the stored bytes as a CRC32C-protected wire-format
/// frame (see [`tidefs_reclaim::decode_reclaim_wire`]) and
/// deserialises the verified payload.
///
/// Returns an empty queue if no persisted queue exists or if the stored
/// data is corrupt beyond recovery.
pub fn load_segment_liveness_queue(
    store: &LocalObjectStore,
) -> Result<SegmentLivenessQueue, SegmentLivenessPersistError> {
    match store
        .load_reclaim_queue()
        .map_err(|e| SegmentLivenessPersistError::Storage(format!("{e}")))?
    {
        Some(bytes) => {
            // Try wire-format decode first
            match decode_reclaim_wire(&bytes) {
                Ok(frame) => {
                    // Wire format verified; deserialise payload
                    SegmentLivenessQueue::from_bytes(&frame.payload)
                        .map_err(|e| SegmentLivenessPersistError::Deserialize(format!("{e}")))
                }
                Err(ReclaimWireError::InvalidMagic) | Err(ReclaimWireError::Truncated) => {
                    // Not a wire-format frame and no legacy migration path
                    // is supported (TideFS has no public release).
                    Ok(SegmentLivenessQueue::new())
                }
                Err(e) => {
                    // Wire format was present but corrupt
                    eprintln!("tidefs: reclaim-queue wire-format error: {e}");
                    Ok(SegmentLivenessQueue::new())
                }
            }
        }
        None => Ok(SegmentLivenessQueue::new()),
    }
}

/// Flush a [`SegmentLivenessQueue`] to the object store.
///
/// Serialises the queue to bytes via [`SegmentLivenessQueue::to_bytes`],
/// wraps the payload in a CRC32C-protected wire-format frame via
/// [`tidefs_reclaim::encode_reclaim_wire`], then persists the framed
/// bytes through the object store.
pub fn flush_segment_liveness_queue(
    queue: &SegmentLivenessQueue,
    store: &mut LocalObjectStore,
) -> Result<(), SegmentLivenessPersistError> {
    let raw = queue.to_bytes();
    let framed = encode_reclaim_wire(&raw);
    store
        .store_reclaim_queue(&framed)
        .map_err(|e| SegmentLivenessPersistError::Storage(format!("{e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::LocalObjectStore;

    fn temp_store() -> (LocalObjectStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = LocalObjectStore::open(dir.path()).expect("open");
        (store, dir)
    }

    #[test]
    fn roundtrip_empty_queue() {
        let (mut store, _dir) = temp_store();
        let queue = SegmentLivenessQueue::new();

        flush_segment_liveness_queue(&queue, &mut store).expect("flush empty queue");

        let loaded = load_segment_liveness_queue(&store).expect("load empty queue");
        assert!(loaded.is_empty());
        assert_eq!(loaded, queue);
    }

    #[test]
    fn roundtrip_populated_queue() {
        let (mut store, _dir) = temp_store();
        let mut queue = SegmentLivenessQueue::new();

        for seg in 1..=20u64 {
            queue.record_write(seg, seg * 1000);
        }
        queue.record_overwrite(3, 1500);
        queue.record_delete(7, 3000);
        queue.record_overwrite(10, 5000);

        flush_segment_liveness_queue(&queue, &mut store).expect("flush populated queue");

        let loaded = load_segment_liveness_queue(&store).expect("load populated queue");
        assert_eq!(loaded.len(), queue.len());
        assert_eq!(loaded, queue);
    }

    #[test]
    fn load_returns_empty_when_no_queue_persisted() {
        let (mut store, _dir) = temp_store();
        store.put_named("other-key", b"hello").expect("put");

        let queue = load_segment_liveness_queue(&store).expect("load from fresh store");
        assert!(queue.is_empty());
    }

    #[test]
    fn multiple_flush_overwrites_successfully() {
        let (mut store, _dir) = temp_store();

        let mut q1 = SegmentLivenessQueue::new();
        q1.record_write(1, 100);
        flush_segment_liveness_queue(&q1, &mut store).expect("first flush");

        let mut q2 = SegmentLivenessQueue::new();
        q2.record_write(2, 200);
        q2.record_write(3, 300);
        flush_segment_liveness_queue(&q2, &mut store).expect("second flush");

        let loaded = load_segment_liveness_queue(&store).expect("load after overwrite");
        assert_eq!(loaded, q2);
    }

    #[test]
    fn candidate_selection_works_after_load() {
        let (mut store, _dir) = temp_store();
        let mut queue = SegmentLivenessQueue::new();

        queue.record_write(1, 100_000);
        queue.record_overwrite(1, 90_000);
        queue.record_write(2, 100_000);
        queue.record_overwrite(2, 50_000);
        queue.record_write(3, 100_000);
        queue.record_delete(3, 10_000);

        flush_segment_liveness_queue(&queue, &mut store).expect("flush");
        let loaded = load_segment_liveness_queue(&store).expect("load");

        assert_eq!(loaded.next_candidate(0.60), Some(1));
        assert_eq!(loaded.next_candidate(0.80), Some(1));
        assert_eq!(loaded.next_candidate(0.91), None);
    }

    #[test]
    fn commit_dead_persists_after_flush() {
        let (mut store, _dir) = temp_store();
        let mut queue = SegmentLivenessQueue::new();

        queue.record_write(1, 100);
        queue.record_delete(1, 100);
        queue.record_write(2, 200);

        flush_segment_liveness_queue(&queue, &mut store).expect("flush");

        let mut loaded = load_segment_liveness_queue(&store).expect("load");
        assert!(loaded.commit_dead(1));
        assert!(!loaded.contains(1));
        assert!(loaded.contains(2));

        flush_segment_liveness_queue(&loaded, &mut store).expect("flush after commit");

        let reloaded = load_segment_liveness_queue(&store).expect("reload");
        assert!(!reloaded.contains(1));
        assert!(reloaded.contains(2));
        assert_eq!(reloaded.len(), 1);
    }

    // -- BPlusTreeReclaimQueue persistence tests --

    #[test]
    fn reclaim_queue_entries_roundtrip_empty() {
        let (mut store, _dir) = temp_store();
        let queue = BPlusTreeReclaimQueue::new();
        store_reclaim_queue_entries(&queue, &mut store).expect("store empty");
        let loaded = load_reclaim_queue_entries(&store);
        assert!(loaded.is_empty());
    }

    #[test]
    fn reclaim_queue_entries_roundtrip_populated() {
        let (mut store, _dir) = temp_store();
        let mut queue = BPlusTreeReclaimQueue::new();
        let e1 = tidefs_types_reclaim_queue_core::ReclaimQueueEntry::new(
            tidefs_types_reclaim_queue_core::ObjectKey([1u8; 32]),
            -1,
            tidefs_types_reclaim_queue_core::QueueFamily::Extent,
        );
        queue.insert(e1);
        store_reclaim_queue_entries(&queue, &mut store).expect("store populated");
        let loaded = load_reclaim_queue_entries(&store);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.get(&e1.object_key), Some(e1));
    }

    #[test]
    fn reclaim_queue_entries_persist_across_reloads() {
        let (mut store, _dir) = temp_store();
        let mut queue = BPlusTreeReclaimQueue::new();
        let e = tidefs_types_reclaim_queue_core::ReclaimQueueEntry::new(
            tidefs_types_reclaim_queue_core::ObjectKey([42u8; 32]),
            -3,
            tidefs_types_reclaim_queue_core::QueueFamily::Rebake,
        );
        queue.insert(e);

        store_reclaim_queue_entries(&queue, &mut store).expect("first store");
        let loaded1 = load_reclaim_queue_entries(&store);
        assert_eq!(loaded1.len(), 1);

        store_reclaim_queue_entries(&loaded1, &mut store).expect("second store");
        let loaded2 = load_reclaim_queue_entries(&store);
        assert_eq!(loaded2.len(), 1);
        assert_eq!(loaded2.get(&e.object_key), Some(e));
    }

    // -- Wire-format corruption detection tests --

    #[test]
    fn wire_format_corrupted_crc_returns_empty_queue() {
        let (mut store, _dir) = temp_store();
        let mut queue = SegmentLivenessQueue::new();
        queue.record_write(1, 4096);
        queue.record_write(2, 8192);

        // Flush with correct wire format
        let raw = queue.to_bytes();
        let mut framed = encode_reclaim_wire(&raw);

        // Corrupt one byte in the payload
        framed[14] ^= 0xFF;

        // Store corrupted frame directly (bypassing flush helper)
        store
            .store_reclaim_queue(&framed)
            .expect("store corrupted frame");

        // Load should detect corruption and return empty queue
        let loaded = load_segment_liveness_queue(&store).expect("load corrupted");
        assert!(
            loaded.is_empty(),
            "corrupted wire format should yield empty queue"
        );
    }

    #[test]
    fn wire_format_corrupted_magic_returns_empty_queue() {
        let (mut store, _dir) = temp_store();
        let mut queue = SegmentLivenessQueue::new();
        queue.record_write(1, 100);

        let raw = queue.to_bytes();
        let mut framed = encode_reclaim_wire(&raw);
        framed[0] = b'X'; // corrupt magic

        store
            .store_reclaim_queue(&framed)
            .expect("store bad magic frame");

        // Bad magic -> not a wire-format frame -> empty queue
        let loaded = load_segment_liveness_queue(&store).expect("load bad magic");
        assert!(loaded.is_empty());
    }

    #[test]
    fn wire_format_truncated_data_returns_empty_queue() {
        let (mut store, _dir) = temp_store();
        let queue = SegmentLivenessQueue::new();

        let raw = queue.to_bytes();
        let framed = encode_reclaim_wire(&raw);
        let truncated = &framed[..framed.len() - 5];

        store
            .store_reclaim_queue(truncated)
            .expect("store truncated frame");

        let loaded = load_segment_liveness_queue(&store).expect("load truncated");
        assert!(loaded.is_empty());
    }

    #[test]
    fn wire_format_flush_then_corrupt_store_detects() {
        let (mut store, _dir) = temp_store();
        let mut queue = SegmentLivenessQueue::new();
        queue.record_write(1, 4096);
        queue.record_write(2, 8192);

        flush_segment_liveness_queue(&queue, &mut store).expect("flush");

        // Manually corrupt the persisted bytes via the store
        let bytes = store
            .get_named(RECLAIM_QUEUE_OBJECT_NAME)
            .expect("get named")
            .expect("should exist");
        let mut corrupted = bytes.clone();
        let footer_byte = corrupted.len() - 2;
        corrupted[footer_byte] ^= 0xFF; // flip in CRC footer

        store
            .put_named(RECLAIM_QUEUE_OBJECT_NAME, &corrupted)
            .expect("store corrupted");

        let loaded = load_segment_liveness_queue(&store).expect("load after corruption");
        // CRC mismatch -> wire format is present but corrupt -> empty queue
        assert!(loaded.is_empty());
    }

    #[test]
    fn wire_format_multiple_corruption_sites_all_detected() {
        let (mut store, _dir) = temp_store();
        let mut queue = SegmentLivenessQueue::new();
        for seg in 0..10u64 {
            queue.record_write(seg, seg * 1000);
        }

        let raw = queue.to_bytes();
        let framed = encode_reclaim_wire(&raw);

        // Try corrupting each byte; every single corruption should be detected
        for pos in [0, 4, 8, 12, framed.len() - 1, framed.len() / 2] {
            let mut corrupted = framed.clone();
            corrupted[pos] ^= 0x01;
            store
                .store_reclaim_queue(&corrupted)
                .expect("store corrupted variant");
            let loaded = load_segment_liveness_queue(&store).expect("load corrupted variant");

            // Corrupted data returns empty queue (no legacy fallback);
            // corrupted data must not be silently accepted.
            assert!(
                loaded.is_empty() || loaded != queue,
                "corruption at byte {pos} should not yield original queue"
            );
        }
    }
}
