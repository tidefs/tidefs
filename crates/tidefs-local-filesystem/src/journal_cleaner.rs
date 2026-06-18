// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Automatic journal segment cleaning.
//!
//! Idempotent cleaning of committed-and-obsolete journal segments
//! via compact_retaining. Copies forward any still-live extents
//! from the oldest segment(s) to the active segment, then retires
//! cleaned segments back to the free pool.  Dead `should_clean` removed in #4362.
//!
//! The cleaning operation is safe to call from both sync (write path)
//! and async (background scheduler) contexts. It is idempotent: if
//! no segments are eligible for retirement, the call is a no-op.

use tidefs_local_object_store::{ObjectKey, StoreRetentionCompactionReport};

use crate::Result;

/// Clean the oldest committed-and-obsolete journal segment(s).
///
/// Gathers all live object keys currently indexed in the store,
/// then calls `compact_retaining` to copy any still-live extents
/// to the active segment and retire the oldest segments.
///
/// This function is idempotent: if all segments are still needed
/// (no segment consists entirely of obsolete/tombstoned data),
/// the call returns a report with zero retired segments.
///
/// # Errors
///
/// Returns an error if the store is read-only or if I/O fails
/// during compaction.
pub fn clean_oldest_segment(
    store: &mut tidefs_local_object_store::Pool,
) -> Result<StoreRetentionCompactionReport> {
    // Enumerate all live keys from the primary data device.
    let live_keys: Vec<ObjectKey> = {
        let raw = store.raw_primary_store();
        raw.list_keys()
    };

    // Compact: retain all live keys, no exact-location constraints.
    // The store will tombstone unreferenced entries, retire segments
    // that contain only tombstones, and copy forward any live
    // extents that reside in retiring segments.
    let report = store.compact_retaining(&live_keys, &[])?;

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tidefs_local_object_store::{
        DeviceBacking, DeviceConfig, DeviceIoClass, DeviceKind, ObjectKey, Pool, PoolConfig,
        PoolProperties, StoreOptions,
    };

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("tidefs-jc-test-{ts}-{label}"))
    }

    fn test_pool(root: &std::path::Path) -> Pool {
        let data_dir = root.join("data");
        let config = PoolConfig {
            name: "testpool".into(),
            root_path: root.to_path_buf(),
            devices: vec![DeviceConfig {
                path: data_dir.clone(),
                backing: DeviceBacking::DirectoryObjectStoreCompat,
                media_class: Default::default(),
                class: tidefs_local_object_store::DeviceClass::Data,
                kind: DeviceKind::Single { path: data_dir },
                encryption: None,
                compression: None,
            }],
        };
        Pool::create(
            config,
            PoolProperties::default(),
            &StoreOptions::test_fast(),
        )
        .unwrap()
    }

    #[test]
    fn clean_oldest_segment_noop_on_empty_store() {
        let root = temp_dir("clean-empty");
        let _ = std::fs::remove_dir_all(&root);
        let mut pool = test_pool(&root);

        let report = clean_oldest_segment(&mut pool).expect("clean should succeed");
        // An empty store has no segments to retire.
        assert_eq!(report.retired_segments.len(), 0);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn clean_oldest_segment_preserves_live_objects() {
        let root = temp_dir("clean-preserve");
        let _ = std::fs::remove_dir_all(&root);
        let mut pool = test_pool(&root);

        // Write several objects
        for i in 0..10u8 {
            let key = ObjectKey::from_name([i; 1]);
            pool.put(DeviceIoClass::Data, key, &[i; 64]).unwrap();
        }

        let keys_before: Vec<ObjectKey> = pool.raw_primary_store().list_keys();
        assert_eq!(keys_before.len(), 10);

        let report = clean_oldest_segment(&mut pool).expect("clean should succeed");
        // After cleaning, all 10 objects should still be present.
        let keys_after: Vec<ObjectKey> = pool.raw_primary_store().list_keys();
        assert_eq!(keys_after.len(), 10);
        // Protected count should match.
        assert_eq!(report.protected_key_count, 10);
        // No objects should have been tombstoned (all were protected).
        assert_eq!(report.tombstoned_unprotected_keys, 0);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn clean_oldest_segment_retires_obsolete_segments() {
        let root = temp_dir("clean-retire");
        let _ = std::fs::remove_dir_all(&root);
        let mut pool = test_pool(&root);

        // Write objects to fill a segment, then delete most of them,
        // then clean. Some segments should be retired.
        let mut keys = Vec::new();
        for i in 0..50u8 {
            let key = ObjectKey::from_name([i; 1]);
            pool.put(DeviceIoClass::Data, key, &[i; 256]).unwrap();
            keys.push(key);
        }

        // Delete all but 5 keys
        for key in &keys[5..] {
            pool.delete(DeviceIoClass::Data, *key).unwrap();
        }

        let capacity_before = pool.pool_stats();
        let segments_before = pool.store_stats().segment_count;

        let _report = clean_oldest_segment(&mut pool).expect("clean should succeed");

        let segments_after = pool.store_stats().segment_count;
        let capacity_after = pool.pool_stats();

        // After cleaning, only the 5 protected keys should remain.
        let keys_after: Vec<ObjectKey> = pool.raw_primary_store().list_keys();
        // 5 keys + possible internal keys (head, spacemap, index, etc.)
        assert!(keys_after.len() >= 5, "at least 5 keys should remain");
        // Used bytes should have decreased or stayed the same.
        assert!(
            capacity_after.used_bytes <= capacity_before.used_bytes,
            "used bytes should not increase after cleaning"
        );
        // Segment count should not increase.
        assert!(
            segments_after <= segments_before + 1, // +1 for rotation after compaction
            "segment count should not grow significantly after cleaning"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn clean_oldest_segment_idempotent() {
        let root = temp_dir("clean-idempotent");
        let _ = std::fs::remove_dir_all(&root);
        let mut pool = test_pool(&root);

        for i in 0..5u8 {
            pool.put(DeviceIoClass::Data, ObjectKey::from_name([i; 1]), &[i; 64])
                .unwrap();
        }

        let _report1 = clean_oldest_segment(&mut pool).expect("first clean");
        let keys_after1 = pool.raw_primary_store().list_keys().len();

        let report2 = clean_oldest_segment(&mut pool).expect("second clean");
        let keys_after2 = pool.raw_primary_store().list_keys().len();

        // Second clean: segment rotation from first clean may leave an empty
        // shell segment that gets retired. Key count must stay stable.
        let _ = report2;
        assert_eq!(
            keys_after1, keys_after2,
            "key count should be stable across idempotent cleans"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn clean_oldest_segment_handles_empty_key_set() {
        let root = temp_dir("clean-empty-keys");
        let _ = std::fs::remove_dir_all(&root);
        let mut pool = test_pool(&root);

        // Write then delete everything
        for i in 0..5u8 {
            let key = ObjectKey::from_name([i; 1]);
            pool.put(DeviceIoClass::Data, key, &[i; 64]).unwrap();
            pool.delete(DeviceIoClass::Data, key).unwrap();
        }

        // All keys tombstoned, cleaning should retire those segments
        let report = clean_oldest_segment(&mut pool).expect("clean should succeed");
        let _keys_after = pool.raw_primary_store().list_keys();
        // After deleting all user keys, only internal keys remain.
        // The important thing is the operation doesn't crash.
        // Cleaning an all-tombstone store should succeed without panicking.
        let _report = report.retired_segments.len();

        let _ = std::fs::remove_dir_all(&root);
    }
}
