// Snapshot auto-pruner: per-dataset retention policies, age-based expiry,
// fail-closed pin-evidence planning, BLAKE3-verified integrity gating, and
// explicit snapshot deletion with permission validation.
//
// # Retention Policies
//
// `SnapshotRetentionPolicy` supports count-based (`keep_last`),
// time-bucketed (`keep_hourly`/`keep_daily`/`keep_weekly`/`keep_monthly`/
// `keep_yearly`), age-based (`max_age_days`), and cap-based (`max_snapshots`)
// constraints. Bucket evaluation uses proleptic Gregorian civil-date
// arithmetic for deterministic, timezone-independent grouping.
//
// # BLAKE3 Integrity Gating
//
// Before deletion, each snapshot entry is verified via a domain-separated
// BLAKE3-256 checksum (derive-key: "TideFS snapshot-pruner integrity v1").
// The checksum covers the full encoded snapshot entry (name, txg anchor,
// committed root, creation timestamp, parent dataset key). If a stored
// checksum does not match the freshly computed one, the prune is rejected
// with `IntegrityFailure`. When no checksum exists, one is computed and
// optionally stored via `store_snapshot_checksum`. This ensures corrupted
// snapshots are never silently removed.
//
// # Fail-Closed Pin Evidence
//
// Retention pruning records a plan before deleting anything. Each candidate
// needs current per-snapshot evidence for its snapshot root, clone-origin
// protection, and deadlist pins. Missing or corrupt evidence blocks the
// candidate and is reported separately from retention-policy keeps,
// clone-origin protection, deadlist protection, and checksum failures.

pub mod pruner;
pub mod retention;

// Re-export public API
pub use pruner::{
    snapshot_checksum_key, snapshot_pin_evidence_object_key, CloneIndex, CloneOriginPin,
    CloneOriginPinKind, DeadlistPin, OriginIndex, PruneResult, SnapshotInfo, SnapshotPinEvidence,
    SnapshotPinEvidenceIndex, SnapshotPruneAction, SnapshotPruneBlock, SnapshotPruneDecision,
    SnapshotPruner, SnapshotPrunerError, SnapshotPrunerStats, SnapshotRootPin, CLONE_INDEX_PREFIX,
    ORIGIN_INDEX_PREFIX, SNAPSHOT_CHECKSUM_PREFIX, SNAPSHOT_PIN_EVIDENCE_PREFIX,
};
pub use retention::SnapshotRetentionPolicy;
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tidefs_local_object_store::LocalObjectStore;

    fn s(name: &str, secs: u64) -> SnapshotInfo {
        SnapshotInfo {
            name: name.into(),
            created_at: UNIX_EPOCH + Duration::from_secs(secs),
            size_bytes: 1024,
            txg_anchor: secs,
            ordinal: secs,
        }
    }
    fn ten() -> Vec<SnapshotInfo> {
        (0..10)
            .map(|i| s(&format!("snap_{i:02}"), (i + 1) * 100))
            .collect()
    }
    fn ns(td: &[String]) -> Vec<&str> {
        td.iter().map(|x| x.as_str()).collect()
    }
    fn record_empty_pin_evidence(
        pruner: &SnapshotPruner,
        store: &mut LocalObjectStore,
        dataset_name: &str,
        snapshot_names: &[&str],
    ) {
        for snapshot_name in snapshot_names {
            pruner
                .record_snapshot_pin_evidence(
                    store,
                    dataset_name,
                    snapshot_name,
                    Vec::new(),
                    Vec::new(),
                )
                .unwrap();
        }
    }

    fn store_incomplete_pin_evidence(
        store: &mut LocalObjectStore,
        dataset_name: &str,
        snapshot_name: &str,
        clone_origin_pins: Option<Vec<CloneOriginPin>>,
        deadlist_pins: Option<Vec<DeadlistPin>>,
    ) {
        let entry = store
            .list_snapshots(dataset_name)
            .into_iter()
            .find(|entry| entry.name == snapshot_name)
            .unwrap();
        let mut index = SnapshotPinEvidenceIndex::new();
        index.insert(
            format!("{dataset_name}/{snapshot_name}"),
            SnapshotPinEvidence {
                snapshot_root: SnapshotRootPin::from_snapshot_entry(&entry),
                clone_origin_pins,
                deadlist_pins,
            },
        );
        index.save(store).unwrap();
    }

    // -- Retention policy tests (existing) --------------------------------

    #[test]
    fn keep5() {
        let p = SnapshotPruner::new(SnapshotRetentionPolicy {
            keep_last: Some(5),
            ..Default::default()
        });
        let td = p.evaluate(&ten(), UNIX_EPOCH + Duration::from_secs(2000));
        assert_eq!(td.len(), 5);
        let n = ns(&td);
        assert!(n.contains(&"snap_00"));
        assert!(n.contains(&"snap_04"));
        assert!(!n.contains(&"snap_09"));
    }
    #[test]
    fn keep_exceeds() {
        let p = SnapshotPruner::new(SnapshotRetentionPolicy {
            keep_last: Some(50),
            ..Default::default()
        });
        assert!(p
            .evaluate(&ten(), UNIX_EPOCH + Duration::from_secs(2000))
            .is_empty());
    }
    #[test]
    fn keep0() {
        let p = SnapshotPruner::new(SnapshotRetentionPolicy {
            keep_last: Some(0),
            ..Default::default()
        });
        assert_eq!(
            p.evaluate(&ten(), UNIX_EPOCH + Duration::from_secs(2000))
                .len(),
            10
        );
    }
    #[test]
    fn max_age30() {
        let p = SnapshotPruner::new(SnapshotRetentionPolicy {
            max_age_days: Some(30),
            ..Default::default()
        });
        let d: u64 = 86400;
        let ss = vec![
            SnapshotInfo {
                name: "old".into(),
                created_at: UNIX_EPOCH + Duration::from_secs(1000),
                size_bytes: 0,
                txg_anchor: 0,
                ordinal: 0,
            },
            SnapshotInfo {
                name: "mid".into(),
                created_at: UNIX_EPOCH + Duration::from_secs(20 * d),
                size_bytes: 0,
                txg_anchor: 0,
                ordinal: 0,
            },
            SnapshotInfo {
                name: "new".into(),
                created_at: UNIX_EPOCH + Duration::from_secs(35 * d),
                size_bytes: 0,
                txg_anchor: 0,
                ordinal: 0,
            },
        ];
        let td = p.evaluate(&ss, UNIX_EPOCH + Duration::from_secs(40 * d + 1000));
        let n = ns(&td);
        assert!(n.contains(&"old"));
        assert!(!n.contains(&"mid"));
        assert!(!n.contains(&"new"));
    }
    #[test]
    fn max3() {
        let p = SnapshotPruner::new(SnapshotRetentionPolicy {
            max_snapshots: Some(3),
            ..Default::default()
        });
        let td = p.evaluate(&ten(), UNIX_EPOCH + Duration::from_secs(2000));
        assert_eq!(td.len(), 7);
        let n = ns(&td);
        assert!(!n.contains(&"snap_07"));
        assert!(!n.contains(&"snap_08"));
        assert!(!n.contains(&"snap_09"));
    }
    #[test]
    fn combined() {
        let p = SnapshotPruner::new(SnapshotRetentionPolicy {
            keep_last: Some(5),
            keep_daily: Some(7),
            max_age_days: Some(30),
            ..Default::default()
        });
        let d: u64 = 86400;
        let mut ss = Vec::new();
        for i in 0u64..20 {
            ss.push(SnapshotInfo {
                name: format!("snap_{i:02}"),
                created_at: UNIX_EPOCH + Duration::from_secs((60 - i * 3) * d),
                size_bytes: 1024,
                txg_anchor: 0,
                ordinal: 0,
            });
        }
        let td = p.evaluate(&ss, UNIX_EPOCH + Duration::from_secs(60 * d));
        let n = ns(&td);
        for name in &["snap_00", "snap_01", "snap_02", "snap_03", "snap_04"] {
            assert!(!n.contains(name));
        }
        assert!(n.contains(&"snap_15"));
        assert!(n.contains(&"snap_19"));
    }
    #[test]
    fn daily2() {
        let p = SnapshotPruner::new(SnapshotRetentionPolicy {
            keep_daily: Some(2),
            ..Default::default()
        });
        let d: u64 = 86400;
        let ss = vec![
            s("d1a", d),
            s("d1b", d + 3600),
            s("d1c", d + 7200),
            s("d2a", 2 * d),
            s("d2b", 2 * d + 3600),
            s("d2c", 2 * d + 7200),
        ];
        let td = p.evaluate(&ss, UNIX_EPOCH + Duration::from_secs(3 * d));
        assert_eq!(td.len(), 2);
        let n = ns(&td);
        assert!(n.contains(&"d1a"));
        assert!(n.contains(&"d2a"));
    }
    #[test]
    fn yearly1() {
        let p = SnapshotPruner::new(SnapshotRetentionPolicy {
            keep_yearly: Some(1),
            ..Default::default()
        });
        let d: u64 = 86400;
        let yr: u64 = 365 * d;
        let ss = vec![
            s("y1o", yr),
            s("y1n", yr + 100 * d),
            s("y2o", 2 * yr),
            s("y2n", 2 * yr + 200 * d),
        ];
        let td = p.evaluate(&ss, UNIX_EPOCH + Duration::from_secs(3 * yr));
        let n = ns(&td);
        assert!(n.contains(&"y1o"));
        assert!(!n.contains(&"y1n"));
        assert!(n.contains(&"y2o"));
        assert!(!n.contains(&"y2n"));
    }
    #[test]
    fn empty_ds() {
        let p = SnapshotPruner::new(SnapshotRetentionPolicy {
            keep_last: Some(10),
            max_snapshots: Some(5),
            max_age_days: Some(30),
            ..Default::default()
        });
        assert!(p.evaluate(&[], UNIX_EPOCH).is_empty());
    }
    #[test]
    fn one() {
        let p = SnapshotPruner::new(SnapshotRetentionPolicy {
            keep_last: Some(10),
            max_snapshots: Some(5),
            ..Default::default()
        });
        assert!(p
            .evaluate(&[s("o", 1000)], UNIX_EPOCH + Duration::from_secs(2000))
            .is_empty());
    }
    #[test]
    fn policy_change() {
        let ss = ten();
        let now = UNIX_EPOCH + Duration::from_secs(2000);
        let mut p = SnapshotPruner::new(SnapshotRetentionPolicy {
            keep_last: Some(10),
            ..Default::default()
        });
        assert!(p.evaluate(&ss, now).is_empty());
        p.set_policy(SnapshotRetentionPolicy {
            keep_last: Some(3),
            ..Default::default()
        });
        let td = p.evaluate(&ss, now);
        assert_eq!(td.len(), 7);
        let n = ns(&td);
        assert!(!n.contains(&"snap_07"));
        assert!(!n.contains(&"snap_08"));
        assert!(!n.contains(&"snap_09"));
    }
    #[test]
    fn stats() {
        let ss = vec![
            SnapshotInfo {
                name: "a".into(),
                created_at: UNIX_EPOCH,
                size_bytes: 100,
                txg_anchor: 0,
                ordinal: 0,
            },
            SnapshotInfo {
                name: "b".into(),
                created_at: UNIX_EPOCH + Duration::from_secs(1),
                size_bytes: 200,
                txg_anchor: 0,
                ordinal: 0,
            },
            SnapshotInfo {
                name: "c".into(),
                created_at: UNIX_EPOCH + Duration::from_secs(2),
                size_bytes: 300,
                txg_anchor: 0,
                ordinal: 0,
            },
        ];
        let mut p = SnapshotPruner::new(SnapshotRetentionPolicy {
            keep_last: Some(1),
            ..Default::default()
        });
        let td = p.evaluate(&ss, UNIX_EPOCH + Duration::from_secs(10));
        assert_eq!(td.len(), 2);
        p.record_outcome(&ss, &td);
        let st = p.stats();
        assert_eq!(st.datasets_processed, 1);
        assert_eq!(st.snapshots_destroyed, 2);
        assert_eq!(st.snapshots_retained, 1);
        assert_eq!(st.bytes_freed, 300);
    }
    #[test]
    fn empty_policy() {
        assert!(SnapshotPruner::new(SnapshotRetentionPolicy::default())
            .evaluate(&ten(), UNIX_EPOCH)
            .is_empty());
    }
    #[test]
    fn is_empty() {
        assert!(SnapshotRetentionPolicy::default().is_empty());
        assert!(!SnapshotRetentionPolicy {
            keep_last: Some(5),
            ..Default::default()
        }
        .is_empty());
    }

    // -- SnapshotPrunerError Display -----------------------------------

    #[test]
    fn pruner_error_display() {
        assert_eq!(
            format!("{}", SnapshotPrunerError::SnapshotNotFound),
            "snapshot not found"
        );
        assert_eq!(
            format!("{}", SnapshotPrunerError::HasClones),
            "snapshot has held clones"
        );
        assert_eq!(
            format!("{}", SnapshotPrunerError::IsLiveDatasetOrigin),
            "snapshot is the origin of a live dataset"
        );
        assert_eq!(
            format!("{}", SnapshotPrunerError::Store("disk full".into())),
            "store error: disk full"
        );
    }

    #[test]
    fn pruner_error_integrity_display() {
        assert_eq!(
            format!(
                "{}",
                SnapshotPrunerError::IntegrityFailure("bad hash".into())
            ),
            "snapshot integrity failure: bad hash"
        );
    }

    #[test]
    fn pruner_error_policy_display() {
        assert_eq!(
            format!(
                "{}",
                SnapshotPrunerError::PolicyViolation("too many".into())
            ),
            "policy violation: too many"
        );
    }

    #[test]
    fn verify_snapshot_integrity_no_stored_checksum_passes() {
        let dir = std::env::temp_dir().join("tidefs-pruner-verify-no-checksum-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut store = LocalObjectStore::open(&dir).unwrap();
        store
            .put(
                tidefs_local_object_store::ObjectKey::from_name(b"obj"),
                b"data",
            )
            .unwrap();
        store.create_snapshot("ds", "snap-1").unwrap();

        let pruner = SnapshotPruner::new(SnapshotRetentionPolicy::default());
        // No stored checksum -> passes (first verification)
        assert!(pruner
            .verify_snapshot_integrity(&store, "ds", "snap-1")
            .is_ok());

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn store_and_verify_snapshot_checksum_roundtrip() {
        let dir = std::env::temp_dir().join("tidefs-pruner-checksum-roundtrip-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut store = LocalObjectStore::open(&dir).unwrap();
        store
            .put(
                tidefs_local_object_store::ObjectKey::from_name(b"obj"),
                b"data",
            )
            .unwrap();
        store.create_snapshot("ds", "snap-x").unwrap();

        let pruner = SnapshotPruner::new(SnapshotRetentionPolicy::default());

        // Store the checksum
        pruner
            .store_snapshot_checksum(&mut store, "ds", "snap-x")
            .unwrap();

        // Verify the checksum matches
        assert!(pruner
            .verify_snapshot_integrity(&store, "ds", "snap-x")
            .is_ok());

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_snapshot_integrity_rejects_corrupted_checksum() {
        let dir = std::env::temp_dir().join("tidefs-pruner-corrupt-checksum-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut store = LocalObjectStore::open(&dir).unwrap();
        store
            .put(
                tidefs_local_object_store::ObjectKey::from_name(b"obj"),
                b"data",
            )
            .unwrap();
        store.create_snapshot("ds", "snap-bad").unwrap();

        let pruner = SnapshotPruner::new(SnapshotRetentionPolicy::default());

        // Store the real checksum first
        pruner
            .store_snapshot_checksum(&mut store, "ds", "snap-bad")
            .unwrap();

        // Corrupt the stored checksum object
        let ck = snapshot_checksum_key("ds", "snap-bad");
        store.put(ck, &[0xFFu8; 32]).unwrap();

        // Now verification should fail
        let err = pruner
            .verify_snapshot_integrity(&store, "ds", "snap-bad")
            .unwrap_err();
        match err {
            SnapshotPrunerError::IntegrityFailure(_) => {}
            other => panic!("expected IntegrityFailure, got {other:?}"),
        }

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn destroy_snapshot_rejected_on_integrity_failure() {
        let dir = std::env::temp_dir().join("tidefs-pruner-destroy-integrity-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut store = LocalObjectStore::open(&dir).unwrap();
        store
            .put(
                tidefs_local_object_store::ObjectKey::from_name(b"obj"),
                b"data",
            )
            .unwrap();
        store.create_snapshot("ds", "snap-to-corrupt").unwrap();

        let mut pruner = SnapshotPruner::new(SnapshotRetentionPolicy::default());

        // Store a checksum, then corrupt it
        pruner
            .store_snapshot_checksum(&mut store, "ds", "snap-to-corrupt")
            .unwrap();
        let ck = snapshot_checksum_key("ds", "snap-to-corrupt");
        store.put(ck, &[0xAAu8; 32]).unwrap();

        // destroy_snapshot should reject due to integrity failure
        let err = pruner
            .destroy_snapshot(&mut store, "ds", "snap-to-corrupt")
            .unwrap_err();
        match err {
            SnapshotPrunerError::IntegrityFailure(_) => {}
            other => panic!("expected IntegrityFailure, got {other:?}"),
        }

        // Snapshot still exists
        let list = store.list_snapshots("ds");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "snap-to-corrupt");

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn destroy_snapshot_with_valid_checksum_succeeds() {
        let dir = std::env::temp_dir().join("tidefs-pruner-destroy-valid-checksum-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut store = LocalObjectStore::open(&dir).unwrap();
        store
            .put(
                tidefs_local_object_store::ObjectKey::from_name(b"obj"),
                b"data",
            )
            .unwrap();
        store.create_snapshot("ds", "snap-valid").unwrap();

        let mut pruner = SnapshotPruner::new(SnapshotRetentionPolicy::default());

        // Store a valid checksum
        pruner
            .store_snapshot_checksum(&mut store, "ds", "snap-valid")
            .unwrap();

        // destroy_snapshot should succeed with valid checksum
        let removed = pruner
            .destroy_snapshot(&mut store, "ds", "snap-valid")
            .unwrap();
        assert_eq!(removed.name, "snap-valid");

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn destroy_snapshot_releases_extent_pins() {
        let dir = std::env::temp_dir().join("tidefs-pruner-destroy-pin-release-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut store = LocalObjectStore::open(&dir).unwrap();
        store
            .put(
                tidefs_local_object_store::ObjectKey::from_name(b"obj"),
                b"data",
            )
            .unwrap();
        store.create_snapshot("ds", "snap-pinned").unwrap();

        let snapshot_id = "ds/snap-pinned";
        let extent_key = tidefs_types_reclaim_queue_core::ObjectKey(
            *tidefs_local_object_store::ObjectKey::from_name(b"pinned-extent").as_bytes(),
        );
        store.pin_snapshot_extent(snapshot_id, extent_key);

        let mut pruner_pin_set = tidefs_gc_pin_set::SnapshotExtentPinSet::new();
        pruner_pin_set.pin(snapshot_id, extent_key);
        let mut pruner = SnapshotPruner::new(SnapshotRetentionPolicy::default());
        pruner.set_extent_pin_set(pruner_pin_set);

        assert!(store.snapshot_extent_pin_set().is_pinned(&extent_key));
        let removed = pruner
            .destroy_snapshot(&mut store, "ds", "snap-pinned")
            .unwrap();
        assert_eq!(removed.name, "snap-pinned");
        assert!(!store.snapshot_extent_pin_set().is_pinned(&extent_key));

        let pruner_pin_set = pruner.take_extent_pin_set().unwrap();
        assert!(!pruner_pin_set.is_pinned(&extent_key));

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- Snapshot deletion tests ---------------------------------------

    #[test]
    fn destroy_snapshot_removes_from_catalog() {
        let dir = std::env::temp_dir().join("tidefs-pruner-destroy-catalog-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut store = LocalObjectStore::open(&dir).unwrap();
        let ds = "test-ds";

        // Write data and create a snapshot
        store
            .put(
                tidefs_local_object_store::ObjectKey::from_name(b"obj1"),
                b"hello",
            )
            .unwrap();
        let _snap = store.create_snapshot(ds, "snap-to-destroy").unwrap();

        // Verify it's listed
        let list = store.list_snapshots(ds);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "snap-to-destroy");

        // Destroy via the pruner
        let mut pruner = SnapshotPruner::new(SnapshotRetentionPolicy::default());
        let removed = pruner
            .destroy_snapshot(&mut store, ds, "snap-to-destroy")
            .unwrap();
        assert_eq!(removed.name, "snap-to-destroy");

        // Catalog is now empty
        let list = store.list_snapshots(ds);
        assert_eq!(list.len(), 0);

        // Stats reflect the destroy
        let stats = pruner.stats();
        assert_eq!(stats.snapshots_destroyed, 1);

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn destroy_nonexistent_snapshot_errors() {
        let dir = std::env::temp_dir().join("tidefs-pruner-nonexist-destroy-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut store = LocalObjectStore::open(&dir).unwrap();
        let mut pruner = SnapshotPruner::new(SnapshotRetentionPolicy::default());

        let err = pruner
            .destroy_snapshot(&mut store, "no-dataset", "no-such-snapshot")
            .unwrap_err();
        assert_eq!(err, SnapshotPrunerError::SnapshotNotFound);

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_destroy_permission_nonexistent() {
        let dir = std::env::temp_dir().join("tidefs-pruner-validate-perm-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let store = LocalObjectStore::open(&dir).unwrap();
        let pruner = SnapshotPruner::new(SnapshotRetentionPolicy::default());

        let err = pruner
            .validate_destroy_permission(&store, "no-ds", "no-snap")
            .unwrap_err();
        assert_eq!(err, SnapshotPrunerError::SnapshotNotFound);

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_destroy_permission_existing_passes() {
        let dir = std::env::temp_dir().join("tidefs-pruner-validate-ok-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut store = LocalObjectStore::open(&dir).unwrap();
        store
            .put(
                tidefs_local_object_store::ObjectKey::from_name(b"obj1"),
                b"data",
            )
            .unwrap();
        store.create_snapshot("ds", "snap-ok").unwrap();

        let pruner = SnapshotPruner::new(SnapshotRetentionPolicy::default());
        assert!(pruner
            .validate_destroy_permission(&store, "ds", "snap-ok")
            .is_ok());

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn integration_create_two_destroy_first() {
        let dir = std::env::temp_dir().join("tidefs-pruner-integration-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut store = LocalObjectStore::open(&dir).unwrap();
        let ds = "test-ds";

        // Create first snapshot
        store
            .put(
                tidefs_local_object_store::ObjectKey::from_name(b"obj-a"),
                b"first write",
            )
            .unwrap();
        let snap1 = store.create_snapshot(ds, "snap-1").unwrap();
        assert_eq!(snap1.name, "snap-1");

        // Write more data and create second snapshot
        store
            .put(
                tidefs_local_object_store::ObjectKey::from_name(b"obj-b"),
                b"second write",
            )
            .unwrap();
        let snap2 = store.create_snapshot(ds, "snap-2").unwrap();
        assert_eq!(snap2.name, "snap-2");

        // Both are listed
        let list = store.list_snapshots(ds);
        assert_eq!(list.len(), 2);

        // Destroy first snapshot
        let mut pruner = SnapshotPruner::new(SnapshotRetentionPolicy::default());
        let removed = pruner.destroy_snapshot(&mut store, ds, "snap-1").unwrap();
        assert_eq!(removed.name, "snap-1");

        // Only snap-2 remains
        let list = store.list_snapshots(ds);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "snap-2");

        // Second snapshot is still accessible
        let snap2_key = snap2.object_key();
        let payload = store.get(snap2_key).unwrap().unwrap();
        let decoded = tidefs_local_object_store::SnapshotEntry::decode(&payload).unwrap();
        assert_eq!(decoded.name, "snap-2");

        // Verify snap-1 entry object is gone
        let snap1_key = snap1.object_key();
        assert!(store.get(snap1_key).unwrap().is_none());

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- CloneIndex unit tests ---------------------------------------

    #[test]
    fn clone_index_insert_and_has_clones() {
        let mut idx = CloneIndex::default();
        assert!(!idx.has_clones("ds/snap-a"));

        idx.insert("ds/snap-a", "ds/clone-1");
        assert!(idx.has_clones("ds/snap-a"));
        assert_eq!(idx.clone_count("ds/snap-a"), 1);
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn clone_index_multiple_clones() {
        let mut idx = CloneIndex::default();
        idx.insert("ds/snap-a", "ds/clone-1");
        idx.insert("ds/snap-a", "ds/clone-2");
        idx.insert("ds/snap-a", "ds/clone-3");

        assert!(idx.has_clones("ds/snap-a"));
        assert_eq!(idx.clone_count("ds/snap-a"), 3);
        assert_eq!(idx.total_edges(), 3);
    }

    #[test]
    fn clone_index_remove_clone() {
        let mut idx = CloneIndex::default();
        idx.insert("ds/snap-a", "ds/clone-1");
        idx.insert("ds/snap-a", "ds/clone-2");

        assert!(idx.remove("ds/snap-a", "ds/clone-1"));
        assert_eq!(idx.clone_count("ds/snap-a"), 1);
        assert!(idx.has_clones("ds/snap-a"));

        assert!(idx.remove("ds/snap-a", "ds/clone-2"));
        assert!(!idx.has_clones("ds/snap-a"));
        assert_eq!(idx.len(), 0);
    }

    #[test]
    fn clone_index_remove_nonexistent() {
        let mut idx = CloneIndex::default();
        idx.insert("ds/snap-a", "ds/clone-1");
        assert!(!idx.remove("ds/snap-a", "ds/clone-nonexistent"));
        assert!(!idx.remove("ds/nonexistent", "ds/clone-1"));
    }

    #[test]
    fn clone_index_remove_all_edges_for() {
        let mut idx = CloneIndex::default();
        idx.insert("ds/parent-1", "ds/clone-x");
        idx.insert("ds/parent-2", "ds/clone-x");
        idx.insert("ds/parent-1", "ds/clone-y");

        idx.remove_all_clone_edges_for("ds/clone-x");
        assert_eq!(idx.clone_count("ds/parent-1"), 1); // only clone-y left
        assert!(!idx.has_clones("ds/parent-2")); // parent-2 had only clone-x
    }

    #[test]
    fn clone_index_different_parents() {
        let mut idx = CloneIndex::default();
        idx.insert("ds/snap-a", "ds/clone-a1");
        idx.insert("ds/snap-b", "ds/clone-b1");

        assert!(idx.has_clones("ds/snap-a"));
        assert!(idx.has_clones("ds/snap-b"));
        assert!(!idx.has_clones("ds/snap-c"));
        assert_eq!(idx.len(), 2);
    }

    #[test]
    fn clone_index_clones_of_iterator() {
        let mut idx = CloneIndex::default();
        idx.insert("ds/snap-a", "ds/clone-1");
        idx.insert("ds/snap-a", "ds/clone-2");

        let clones: Vec<&str> = idx.clones_of("ds/snap-a").collect();
        assert_eq!(clones.len(), 2);
        assert!(clones.contains(&"ds/clone-1"));
        assert!(clones.contains(&"ds/clone-2"));
    }

    #[test]
    fn clone_index_clones_of_empty() {
        let idx = CloneIndex::default();
        let clones: Vec<&str> = idx.clones_of("nobody").collect();
        assert!(clones.is_empty());
    }

    #[test]
    fn clone_index_encode_decode_roundtrip() {
        let mut idx = CloneIndex::default();
        idx.insert("pool/ds/snap-a", "pool/ds/clone-1");
        idx.insert("pool/ds/snap-a", "pool/ds/clone-2");
        idx.insert("pool/ds/snap-b", "pool/ds/clone-b1");

        let encoded = idx.encode();
        let decoded = CloneIndex::decode(&encoded).unwrap();
        assert_eq!(decoded, idx);
        assert!(decoded.has_clones("pool/ds/snap-a"));
        assert_eq!(decoded.clone_count("pool/ds/snap-a"), 2);
        assert!(decoded.has_clones("pool/ds/snap-b"));
    }

    #[test]
    fn clone_index_decode_empty() {
        let idx = CloneIndex::default();
        let encoded = idx.encode();
        let decoded = CloneIndex::decode(&encoded).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn clone_index_decode_rejects_short() {
        assert!(CloneIndex::decode(&[]).is_none());
        assert!(CloneIndex::decode(&[0u8; 3]).is_none());
    }

    #[test]
    fn clone_index_is_empty_and_len() {
        let mut idx = CloneIndex::default();
        assert!(idx.is_empty());
        assert_eq!(idx.len(), 0);
        idx.insert("a/b", "a/c");
        assert!(!idx.is_empty());
        assert_eq!(idx.len(), 1);
    }

    // -- OriginIndex unit tests --------------------------------------

    #[test]
    fn origin_index_insert_and_check() {
        let mut idx = OriginIndex::default();
        idx.insert("live-ds", "pool/snap-origin");

        assert!(idx.is_origin_of_live_dataset("pool/snap-origin"));
        assert!(!idx.is_origin_of_live_dataset("pool/other-snap"));
        assert_eq!(idx.origin_of("live-ds"), Some("pool/snap-origin"));
    }

    #[test]
    fn origin_index_multiple_datasets() {
        let mut idx = OriginIndex::default();
        idx.insert("ds-alpha", "pool/snap-1");
        idx.insert("ds-beta", "pool/snap-1"); // same origin

        assert!(idx.is_origin_of_live_dataset("pool/snap-1"));
        assert_eq!(idx.len(), 2);

        idx.remove("ds-alpha");
        assert!(idx.is_origin_of_live_dataset("pool/snap-1"));
        assert_eq!(idx.len(), 1);

        idx.remove("ds-beta");
        assert!(!idx.is_origin_of_live_dataset("pool/snap-1"));
    }

    #[test]
    fn origin_index_remove_nonexistent() {
        let mut idx = OriginIndex::default();
        idx.insert("ds-a", "pool/snap-x");
        assert!(!idx.remove("ds-nonexistent"));
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn origin_index_replace_origin() {
        let mut idx = OriginIndex::default();
        idx.insert("ds-main", "pool/snap-old");
        assert!(idx.is_origin_of_live_dataset("pool/snap-old"));

        // Replace
        idx.insert("ds-main", "pool/snap-new");
        assert!(!idx.is_origin_of_live_dataset("pool/snap-old"));
        assert!(idx.is_origin_of_live_dataset("pool/snap-new"));
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn origin_index_encode_decode_roundtrip() {
        let mut idx = OriginIndex::default();
        idx.insert("live-ds-1", "pool/ds/snap-a");
        idx.insert("live-ds-2", "pool/ds/snap-b");

        let encoded = idx.encode();
        let decoded = OriginIndex::decode(&encoded).unwrap();
        assert_eq!(decoded, idx);
        assert!(decoded.is_origin_of_live_dataset("pool/ds/snap-a"));
        assert!(decoded.is_origin_of_live_dataset("pool/ds/snap-b"));
        assert!(!decoded.is_origin_of_live_dataset("pool/ds/snap-c"));
    }

    #[test]
    fn origin_index_decode_empty() {
        let idx = OriginIndex::default();
        let encoded = idx.encode();
        let decoded = OriginIndex::decode(&encoded).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn origin_index_decode_rejects_short() {
        assert!(OriginIndex::decode(&[]).is_none());
        assert!(OriginIndex::decode(&[0u8; 3]).is_none());
    }

    #[test]
    fn origin_index_is_empty_and_len() {
        let mut idx = OriginIndex::default();
        assert!(idx.is_empty());
        assert_eq!(idx.len(), 0);
        idx.insert("ds", "pool/snap");
        assert!(!idx.is_empty());
        assert_eq!(idx.len(), 1);
    }

    // -- Pruner integration: validate_destroy_permission with indices -

    #[test]
    fn destroy_rejected_by_has_clones() {
        let dir = std::env::temp_dir().join("tidefs-pruner-has-clones-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut store = LocalObjectStore::open(&dir).unwrap();
        let ds = "test-ds";

        store
            .put(
                tidefs_local_object_store::ObjectKey::from_name(b"obj"),
                b"data",
            )
            .unwrap();
        store.create_snapshot(ds, "parent-snap").unwrap();

        let mut pruner = SnapshotPruner::new(SnapshotRetentionPolicy::default());
        // Record a clone dependency
        pruner
            .record_clone(&mut store, "test-ds/parent-snap", "test-ds/clone-snap")
            .unwrap();

        let err = pruner
            .validate_destroy_permission(&store, ds, "parent-snap")
            .unwrap_err();
        assert_eq!(err, SnapshotPrunerError::HasClones);

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn destroy_rejected_by_is_live_dataset_origin() {
        let dir = std::env::temp_dir().join("tidefs-pruner-live-origin-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut store = LocalObjectStore::open(&dir).unwrap();
        let ds = "test-ds";

        store
            .put(
                tidefs_local_object_store::ObjectKey::from_name(b"obj"),
                b"data",
            )
            .unwrap();
        store.create_snapshot(ds, "origin-snap").unwrap();

        let mut pruner = SnapshotPruner::new(SnapshotRetentionPolicy::default());
        // Record a live dataset whose origin is this snapshot
        pruner
            .record_origin(&mut store, "live-ds", "test-ds/origin-snap")
            .unwrap();

        let err = pruner
            .validate_destroy_permission(&store, ds, "origin-snap")
            .unwrap_err();
        assert_eq!(err, SnapshotPrunerError::IsLiveDatasetOrigin);

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn destroy_leaf_clone_succeeds() {
        let dir = std::env::temp_dir().join("tidefs-pruner-leaf-clone-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut store = LocalObjectStore::open(&dir).unwrap();
        let ds = "test-ds";

        store
            .put(
                tidefs_local_object_store::ObjectKey::from_name(b"obj"),
                b"data",
            )
            .unwrap();
        store.create_snapshot(ds, "parent-snap").unwrap();
        store
            .put(
                tidefs_local_object_store::ObjectKey::from_name(b"obj2"),
                b"more",
            )
            .unwrap();
        store.create_snapshot(ds, "clone-snap").unwrap();

        let mut pruner = SnapshotPruner::new(SnapshotRetentionPolicy::default());
        pruner
            .record_clone(&mut store, "test-ds/parent-snap", "test-ds/clone-snap")
            .unwrap();

        // Parent has clones → rejected
        assert_eq!(
            pruner.validate_destroy_permission(&store, ds, "parent-snap"),
            Err(SnapshotPrunerError::HasClones)
        );

        // Clone has no children → allowed
        assert!(pruner
            .validate_destroy_permission(&store, ds, "clone-snap")
            .is_ok());

        // Destroy the clone
        let removed = pruner
            .destroy_snapshot(&mut store, ds, "clone-snap")
            .unwrap();
        assert_eq!(removed.name, "clone-snap");

        // Clean up clone index
        pruner
            .remove_clone(&mut store, "test-ds/parent-snap", "test-ds/clone-snap")
            .unwrap();

        // Now parent can be destroyed
        assert!(pruner
            .validate_destroy_permission(&store, ds, "parent-snap")
            .is_ok());

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn destroy_dependency_free_succeeds() {
        let dir = std::env::temp_dir().join("tidefs-pruner-depfree-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut store = LocalObjectStore::open(&dir).unwrap();
        let ds = "test-ds";

        store
            .put(
                tidefs_local_object_store::ObjectKey::from_name(b"obj"),
                b"data",
            )
            .unwrap();
        store.create_snapshot(ds, "lonely-snap").unwrap();

        let pruner = SnapshotPruner::new(SnapshotRetentionPolicy::default());
        // No clone edges, no origin edges → allowed
        assert!(pruner
            .validate_destroy_permission(&store, ds, "lonely-snap")
            .is_ok());

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn clone_index_persistence_roundtrip() {
        let dir = std::env::temp_dir().join("tidefs-pruner-clone-persist-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut store = LocalObjectStore::open(&dir).unwrap();

        // Populate clone index via pruner
        let mut pruner = SnapshotPruner::new(SnapshotRetentionPolicy::default());
        pruner
            .record_clone(&mut store, "ds/parent", "ds/clone-a")
            .unwrap();
        pruner
            .record_clone(&mut store, "ds/parent", "ds/clone-b")
            .unwrap();
        pruner
            .record_clone(&mut store, "ds/other", "ds/other-clone")
            .unwrap();

        // Reload from store
        let pruner2 = SnapshotPruner::load(&store, SnapshotRetentionPolicy::default());
        assert!(pruner2.clone_index().has_clones("ds/parent"));
        assert_eq!(pruner2.clone_index().clone_count("ds/parent"), 2);
        assert!(pruner2.clone_index().has_clones("ds/other"));

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn origin_index_persistence_roundtrip() {
        let dir = std::env::temp_dir().join("tidefs-pruner-origin-persist-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut store = LocalObjectStore::open(&dir).unwrap();

        let mut pruner = SnapshotPruner::new(SnapshotRetentionPolicy::default());
        pruner
            .record_origin(&mut store, "live-alpha", "pool/snap-1")
            .unwrap();
        pruner
            .record_origin(&mut store, "live-beta", "pool/snap-2")
            .unwrap();

        let pruner2 = SnapshotPruner::load(&store, SnapshotRetentionPolicy::default());
        assert!(pruner2
            .origin_index()
            .is_origin_of_live_dataset("pool/snap-1"));
        assert!(pruner2
            .origin_index()
            .is_origin_of_live_dataset("pool/snap-2"));
        assert!(!pruner2
            .origin_index()
            .is_origin_of_live_dataset("pool/snap-3"));

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_and_reload_indices() {
        let dir = std::env::temp_dir().join("tidefs-pruner-save-reload-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut store = LocalObjectStore::open(&dir).unwrap();

        let mut pruner = SnapshotPruner::new(SnapshotRetentionPolicy::default());
        pruner
            .record_clone(&mut store, "ds/snap-a", "ds/clone-1")
            .unwrap();
        pruner
            .record_origin(&mut store, "live-ds", "ds/snap-a")
            .unwrap();

        // Reload in a fresh pruner
        let mut pruner2 = SnapshotPruner::load(&store, SnapshotRetentionPolicy::default());
        assert!(pruner2.clone_index().has_clones("ds/snap-a"));
        assert!(pruner2
            .origin_index()
            .is_origin_of_live_dataset("ds/snap-a"));

        // Modify and save
        pruner2
            .remove_clone(&mut store, "ds/snap-a", "ds/clone-1")
            .unwrap();
        pruner2.remove_origin(&mut store, "live-ds").unwrap();

        let pruner3 = SnapshotPruner::load(&store, SnapshotRetentionPolicy::default());
        assert!(!pruner3.clone_index().has_clones("ds/snap-a"));
        assert!(!pruner3
            .origin_index()
            .is_origin_of_live_dataset("ds/snap-a"));

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn record_clone_idempotent() {
        let dir = std::env::temp_dir().join("tidefs-pruner-clone-idemp-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut store = LocalObjectStore::open(&dir).unwrap();
        let mut pruner = SnapshotPruner::new(SnapshotRetentionPolicy::default());

        // Insert same edge twice is idempotent via BTreeSet
        pruner
            .record_clone(&mut store, "ds/parent", "ds/clone-x")
            .unwrap();
        pruner
            .record_clone(&mut store, "ds/parent", "ds/clone-x")
            .unwrap();

        assert_eq!(pruner.clone_index().clone_count("ds/parent"), 1);

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn record_origin_idempotent_replace() {
        let dir = std::env::temp_dir().join("tidefs-pruner-origin-idemp-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut store = LocalObjectStore::open(&dir).unwrap();
        let mut pruner = SnapshotPruner::new(SnapshotRetentionPolicy::default());

        pruner
            .record_origin(&mut store, "ds-main", "pool/snap-old")
            .unwrap();
        pruner
            .record_origin(&mut store, "ds-main", "pool/snap-new")
            .unwrap();

        assert_eq!(pruner.origin_index().len(), 1);
        assert!(!pruner
            .origin_index()
            .is_origin_of_live_dataset("pool/snap-old"));
        assert!(pruner
            .origin_index()
            .is_origin_of_live_dataset("pool/snap-new"));

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- prune_dataset integration tests ----------------------------

    #[test]
    fn prune_dataset_empty_policy_noops() {
        let dir = std::env::temp_dir().join("tidefs-pruner-prune-empty-policy-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut store = LocalObjectStore::open(&dir).unwrap();
        store
            .put(
                tidefs_local_object_store::ObjectKey::from_name(b"obj"),
                b"data",
            )
            .unwrap();
        store.create_snapshot("ds", "snap-1").unwrap();
        store.create_snapshot("ds", "snap-2").unwrap();

        let mut pruner = SnapshotPruner::new(SnapshotRetentionPolicy::default());
        let result = pruner.prune_dataset(&mut store, "ds", SystemTime::now());
        assert_eq!(result.candidates_evaluated, 0);
        assert_eq!(result.destroyed, 0);
        // Snapshots intact
        assert_eq!(store.list_snapshots("ds").len(), 2);

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prune_dataset_keep_2_of_5_destroys_3() {
        let dir = std::env::temp_dir().join("tidefs-pruner-prune-keep2-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut store = LocalObjectStore::open(&dir).unwrap();
        let ds = "test-ds";

        // Create 5 snapshots with distinct creation times
        let mut names = Vec::new();
        for i in 0u64..5 {
            store
                .put(
                    tidefs_local_object_store::ObjectKey::from_name(format!("obj{i}").as_bytes()),
                    b"data",
                )
                .unwrap();
            let name = format!("snap-{i}");
            store.create_snapshot(ds, &name).unwrap();
            names.push(name);
            // Ensure distinct timestamps for ordering
            std::thread::sleep(Duration::from_millis(10));
        }

        let mut pruner = SnapshotPruner::new(SnapshotRetentionPolicy {
            keep_last: Some(2),
            ..Default::default()
        });
        let name_refs: Vec<&str> = names.iter().map(String::as_str).collect();
        record_empty_pin_evidence(&pruner, &mut store, ds, &name_refs);
        let result = pruner.prune_dataset(&mut store, ds, SystemTime::now());
        // 5 snapshots, keep 2 latest => 3 candidates
        assert_eq!(result.candidates_evaluated, 3);
        assert_eq!(result.retention_kept, 2);
        assert_eq!(result.destroyed, 3);
        assert_eq!(result.clone_origin_protected, 0);
        assert_eq!(result.deadlist_pin_protected, 0);
        assert_eq!(result.missing_evidence_blocks, 0);
        assert_eq!(
            result.delete_set,
            vec![
                "snap-0".to_string(),
                "snap-1".to_string(),
                "snap-2".to_string()
            ]
        );

        // Only 2 latest remain
        let remaining = store.list_snapshots(ds);
        assert_eq!(remaining.len(), 2);
        let remaining_names: Vec<&str> = remaining.iter().map(|e| e.name.as_str()).collect();
        assert!(remaining_names.contains(&"snap-3"));
        assert!(remaining_names.contains(&"snap-4"));

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prune_dataset_skips_clone_parent() {
        let dir = std::env::temp_dir().join("tidefs-pruner-prune-clone-parent-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut store = LocalObjectStore::open(&dir).unwrap();
        let ds = "test-ds";

        // Create parent snapshot
        store
            .put(
                tidefs_local_object_store::ObjectKey::from_name(b"obj1"),
                b"data",
            )
            .unwrap();
        store.create_snapshot(ds, "parent-snap").unwrap();

        // Create child snapshot
        store
            .put(
                tidefs_local_object_store::ObjectKey::from_name(b"obj2"),
                b"more",
            )
            .unwrap();
        store.create_snapshot(ds, "child-snap").unwrap();

        let mut pruner = SnapshotPruner::new(SnapshotRetentionPolicy {
            keep_last: Some(0), // Keep none => all are candidates
            ..Default::default()
        });

        // Record clone dependency: child derives from parent
        pruner
            .record_clone(&mut store, "test-ds/parent-snap", "test-ds/child-snap")
            .unwrap();
        pruner
            .record_snapshot_pin_evidence(
                &mut store,
                ds,
                "parent-snap",
                vec![CloneOriginPin::clone_snapshot("test-ds/child-snap")],
                Vec::new(),
            )
            .unwrap();
        pruner
            .record_snapshot_pin_evidence(&mut store, ds, "child-snap", Vec::new(), Vec::new())
            .unwrap();

        let result = pruner.prune_dataset(&mut store, ds, SystemTime::now());

        // Child-snap can be destroyed (no clones, no origins)
        // Parent-snap skipped because it has a clone
        assert_eq!(result.clone_origin_protected, 1);
        assert_eq!(result.destroyed, 1);
        assert_eq!(result.delete_set, vec!["child-snap".to_string()]);
        let parent_decision = result
            .decisions
            .iter()
            .find(|decision| decision.snapshot_name == "parent-snap")
            .unwrap();
        assert_eq!(
            parent_decision.clone_origin_pins,
            vec![CloneOriginPin::clone_snapshot("test-ds/child-snap")]
        );

        // Only parent remains
        let remaining = store.list_snapshots(ds);
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].name, "parent-snap");

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prune_dataset_blocks_stale_empty_clone_origin_evidence() {
        let dir = std::env::temp_dir().join("tidefs-pruner-stale-clone-evidence-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut store = LocalObjectStore::open(&dir).unwrap();
        let ds = "test-ds";

        store
            .put(
                tidefs_local_object_store::ObjectKey::from_name(b"obj1"),
                b"data",
            )
            .unwrap();
        store.create_snapshot(ds, "parent-snap").unwrap();
        store
            .put(
                tidefs_local_object_store::ObjectKey::from_name(b"obj2"),
                b"more",
            )
            .unwrap();
        store.create_snapshot(ds, "child-snap").unwrap();

        let mut pruner = SnapshotPruner::new(SnapshotRetentionPolicy {
            keep_last: Some(0),
            ..Default::default()
        });
        pruner
            .record_clone(&mut store, "test-ds/parent-snap", "test-ds/child-snap")
            .unwrap();
        pruner
            .record_snapshot_pin_evidence(&mut store, ds, "parent-snap", Vec::new(), Vec::new())
            .unwrap();
        pruner
            .record_snapshot_pin_evidence(&mut store, ds, "child-snap", Vec::new(), Vec::new())
            .unwrap();

        let result = pruner.prune_dataset(&mut store, ds, SystemTime::now());

        assert_eq!(result.clone_origin_protected, 1);
        assert_eq!(result.corrupt_evidence_blocks, 1);
        assert_eq!(result.destroyed, 1);
        assert_eq!(result.delete_set, vec!["child-snap".to_string()]);
        let parent_decision = result
            .decisions
            .iter()
            .find(|decision| decision.snapshot_name == "parent-snap")
            .unwrap();
        assert_eq!(
            parent_decision.clone_origin_pins,
            vec![CloneOriginPin::clone_snapshot("test-ds/child-snap")]
        );

        let remaining = store.list_snapshots(ds);
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].name, "parent-snap");

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prune_dataset_skips_live_dataset_origin() {
        let dir = std::env::temp_dir().join("tidefs-pruner-prune-origin-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut store = LocalObjectStore::open(&dir).unwrap();
        let ds = "test-ds";

        // Create a snapshot that is a live dataset origin
        store
            .put(
                tidefs_local_object_store::ObjectKey::from_name(b"obj"),
                b"data",
            )
            .unwrap();
        store.create_snapshot(ds, "origin-snap").unwrap();

        // Create a regular snapshot
        store
            .put(
                tidefs_local_object_store::ObjectKey::from_name(b"obj2"),
                b"more",
            )
            .unwrap();
        store.create_snapshot(ds, "normal-snap").unwrap();

        let mut pruner = SnapshotPruner::new(SnapshotRetentionPolicy {
            keep_last: Some(0),
            ..Default::default()
        });

        // Mark origin-snap as the origin of a live dataset
        pruner
            .record_origin(&mut store, "live-dataset", "test-ds/origin-snap")
            .unwrap();
        pruner
            .record_snapshot_pin_evidence(
                &mut store,
                ds,
                "origin-snap",
                vec![CloneOriginPin::live_dataset_origin("live-dataset")],
                Vec::new(),
            )
            .unwrap();
        pruner
            .record_snapshot_pin_evidence(&mut store, ds, "normal-snap", Vec::new(), Vec::new())
            .unwrap();

        let result = pruner.prune_dataset(&mut store, ds, SystemTime::now());

        // origin-snap skipped, normal-snap destroyed
        assert_eq!(result.clone_origin_protected, 1);
        assert_eq!(result.destroyed, 1);
        assert_eq!(result.delete_set, vec!["normal-snap".to_string()]);

        let remaining = store.list_snapshots(ds);
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].name, "origin-snap");

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prune_dataset_blocks_deadlist_pin() {
        let dir = std::env::temp_dir().join("tidefs-pruner-prune-deadlist-pin-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut store = LocalObjectStore::open(&dir).unwrap();
        let ds = "test-ds";
        store
            .put(
                tidefs_local_object_store::ObjectKey::from_name(b"obj"),
                b"data",
            )
            .unwrap();
        store.create_snapshot(ds, "pinned-snap").unwrap();

        let mut pruner = SnapshotPruner::new(SnapshotRetentionPolicy {
            keep_last: Some(0),
            ..Default::default()
        });
        pruner
            .record_snapshot_pin_evidence(
                &mut store,
                ds,
                "pinned-snap",
                Vec::new(),
                vec![DeadlistPin::new("extent-42")],
            )
            .unwrap();

        let result = pruner.prune_dataset(&mut store, ds, SystemTime::now());

        assert_eq!(result.candidates_evaluated, 1);
        assert_eq!(result.destroyed, 0);
        assert_eq!(result.deadlist_pin_protected, 1);
        assert!(result.delete_set.is_empty());
        assert_eq!(store.list_snapshots(ds).len(), 1);
        assert_eq!(
            result.decisions[0].deadlist_pins,
            vec![DeadlistPin::new("extent-42")]
        );

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prune_dataset_blocks_missing_clone_origin_entry() {
        let dir = std::env::temp_dir().join("tidefs-pruner-missing-clone-origin-evidence-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut store = LocalObjectStore::open(&dir).unwrap();
        let ds = "test-ds";
        store
            .put(
                tidefs_local_object_store::ObjectKey::from_name(b"obj"),
                b"data",
            )
            .unwrap();
        store.create_snapshot(ds, "snap").unwrap();

        let mut pruner = SnapshotPruner::new(SnapshotRetentionPolicy {
            keep_last: Some(0),
            ..Default::default()
        });
        store_incomplete_pin_evidence(&mut store, ds, "snap", None, Some(Vec::new()));

        let result = pruner.prune_dataset(&mut store, ds, SystemTime::now());

        assert_eq!(result.candidates_evaluated, 1);
        assert_eq!(result.missing_evidence_blocks, 1);
        assert_eq!(result.destroyed, 0);
        assert!(result.delete_set.is_empty());
        assert_eq!(store.list_snapshots(ds).len(), 1);

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prune_dataset_blocks_missing_deadlist_pin_entry() {
        let dir = std::env::temp_dir().join("tidefs-pruner-missing-deadlist-evidence-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut store = LocalObjectStore::open(&dir).unwrap();
        let ds = "test-ds";
        store
            .put(
                tidefs_local_object_store::ObjectKey::from_name(b"obj"),
                b"data",
            )
            .unwrap();
        store.create_snapshot(ds, "snap").unwrap();

        let mut pruner = SnapshotPruner::new(SnapshotRetentionPolicy {
            keep_last: Some(0),
            ..Default::default()
        });
        store_incomplete_pin_evidence(&mut store, ds, "snap", Some(Vec::new()), None);

        let result = pruner.prune_dataset(&mut store, ds, SystemTime::now());

        assert_eq!(result.candidates_evaluated, 1);
        assert_eq!(result.missing_evidence_blocks, 1);
        assert_eq!(result.destroyed, 0);
        assert!(result.delete_set.is_empty());
        assert_eq!(store.list_snapshots(ds).len(), 1);

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prune_dataset_blocks_corrupt_pin_evidence() {
        let dir = std::env::temp_dir().join("tidefs-pruner-corrupt-pin-evidence-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut store = LocalObjectStore::open(&dir).unwrap();
        let ds = "test-ds";
        store
            .put(
                tidefs_local_object_store::ObjectKey::from_name(b"obj"),
                b"data",
            )
            .unwrap();
        store.create_snapshot(ds, "snap").unwrap();
        store
            .put(snapshot_pin_evidence_object_key(), b"not-current-evidence")
            .unwrap();

        let mut pruner = SnapshotPruner::new(SnapshotRetentionPolicy {
            keep_last: Some(0),
            ..Default::default()
        });
        let result = pruner.prune_dataset(&mut store, ds, SystemTime::now());

        assert_eq!(result.candidates_evaluated, 1);
        assert_eq!(result.corrupt_evidence_blocks, 1);
        assert_eq!(result.destroyed, 0);
        assert!(result.delete_set.is_empty());
        assert_eq!(store.list_snapshots(ds).len(), 1);

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prune_dataset_blocks_corrupt_snapshot_checksum() {
        let dir = std::env::temp_dir().join("tidefs-pruner-prune-corrupt-checksum-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut store = LocalObjectStore::open(&dir).unwrap();
        let ds = "test-ds";
        store
            .put(
                tidefs_local_object_store::ObjectKey::from_name(b"obj"),
                b"data",
            )
            .unwrap();
        store.create_snapshot(ds, "snap").unwrap();

        let mut pruner = SnapshotPruner::new(SnapshotRetentionPolicy {
            keep_last: Some(0),
            ..Default::default()
        });
        pruner
            .record_snapshot_pin_evidence(&mut store, ds, "snap", Vec::new(), Vec::new())
            .unwrap();
        pruner
            .store_snapshot_checksum(&mut store, ds, "snap")
            .unwrap();
        store
            .put(snapshot_checksum_key(ds, "snap"), &[0xAAu8; 32])
            .unwrap();

        let result = pruner.prune_dataset(&mut store, ds, SystemTime::now());

        assert_eq!(result.candidates_evaluated, 1);
        assert_eq!(result.integrity_failures, 1);
        assert_eq!(result.destroyed, 0);
        assert!(result.delete_set.is_empty());
        assert_eq!(store.list_snapshots(ds).len(), 1);

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prune_dataset_empty_snapshot_set() {
        let dir = std::env::temp_dir().join("tidefs-pruner-prune-empty-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut store = LocalObjectStore::open(&dir).unwrap();
        let mut pruner = SnapshotPruner::new(SnapshotRetentionPolicy {
            keep_last: Some(10),
            ..Default::default()
        });
        let result = pruner.prune_dataset(&mut store, "no-such-ds", SystemTime::now());
        assert_eq!(result, PruneResult::default());

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prune_dataset_stats_updated() {
        let dir = std::env::temp_dir().join("tidefs-pruner-prune-stats-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut store = LocalObjectStore::open(&dir).unwrap();
        let ds = "test-ds";

        let mut names = Vec::new();
        for i in 0u64..5 {
            store
                .put(
                    tidefs_local_object_store::ObjectKey::from_name(format!("obj{i}").as_bytes()),
                    b"data",
                )
                .unwrap();
            let name = format!("snap-{i}");
            store.create_snapshot(ds, &name).unwrap();
            names.push(name);
            std::thread::sleep(Duration::from_millis(5));
        }

        let mut pruner = SnapshotPruner::new(SnapshotRetentionPolicy {
            keep_last: Some(2),
            ..Default::default()
        });
        let name_refs: Vec<&str> = names.iter().map(String::as_str).collect();
        record_empty_pin_evidence(&pruner, &mut store, ds, &name_refs);
        let _ = pruner.prune_dataset(&mut store, ds, SystemTime::now());

        let stats = pruner.stats();
        assert_eq!(stats.snapshots_destroyed, 3);
        assert_eq!(stats.snapshots_retained, 2);

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prune_dataset_candidate_ordering_oldest_first() {
        let dir = std::env::temp_dir().join("tidefs-pruner-prune-ordering-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut store = LocalObjectStore::open(&dir).unwrap();
        let ds = "test-ds";

        // Create snapshots with distinct timestamps via sleep
        store
            .put(
                tidefs_local_object_store::ObjectKey::from_name(b"obj-old"),
                b"old data",
            )
            .unwrap();
        store.create_snapshot(ds, "oldest").unwrap();
        std::thread::sleep(Duration::from_millis(10));

        store
            .put(
                tidefs_local_object_store::ObjectKey::from_name(b"obj-mid1"),
                b"mid1",
            )
            .unwrap();
        store.create_snapshot(ds, "mid1").unwrap();
        std::thread::sleep(Duration::from_millis(10));

        store
            .put(
                tidefs_local_object_store::ObjectKey::from_name(b"obj-mid2"),
                b"mid2",
            )
            .unwrap();
        store.create_snapshot(ds, "mid2").unwrap();
        std::thread::sleep(Duration::from_millis(10));

        store
            .put(
                tidefs_local_object_store::ObjectKey::from_name(b"obj-new"),
                b"new",
            )
            .unwrap();
        store.create_snapshot(ds, "newest").unwrap();

        let mut pruner = SnapshotPruner::new(SnapshotRetentionPolicy {
            keep_last: Some(1),
            ..Default::default()
        });
        record_empty_pin_evidence(
            &pruner,
            &mut store,
            ds,
            &["oldest", "mid1", "mid2", "newest"],
        );
        let result = pruner.prune_dataset(&mut store, ds, SystemTime::now());
        assert_eq!(result.candidates_evaluated, 3);
        assert_eq!(result.destroyed, 3);
        assert_eq!(
            result.delete_set,
            vec!["oldest".to_string(), "mid1".to_string(), "mid2".to_string()]
        );

        let remaining = store.list_snapshots(ds);
        assert_eq!(remaining.len(), 1);
        // Newest is kept
        assert_eq!(remaining[0].name, "newest");

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prune_dataset_max_age_filter() {
        let dir = std::env::temp_dir().join("tidefs-pruner-prune-maxage-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut store = LocalObjectStore::open(&dir).unwrap();
        let ds = "test-ds";

        // Create 3 snapshots
        store
            .put(tidefs_local_object_store::ObjectKey::from_name(b"a"), b"a")
            .unwrap();
        store.create_snapshot(ds, "snap-a").unwrap();
        store
            .put(tidefs_local_object_store::ObjectKey::from_name(b"b"), b"b")
            .unwrap();
        store.create_snapshot(ds, "snap-b").unwrap();
        store
            .put(tidefs_local_object_store::ObjectKey::from_name(b"c"), b"c")
            .unwrap();
        store.create_snapshot(ds, "snap-c").unwrap();

        // Policy: keep last 10, but max age 0 days => all expire
        let mut pruner = SnapshotPruner::new(SnapshotRetentionPolicy {
            keep_last: Some(10),
            max_age_days: Some(0),
            ..Default::default()
        });
        record_empty_pin_evidence(&pruner, &mut store, ds, &["snap-a", "snap-b", "snap-c"]);
        let result =
            pruner.prune_dataset(&mut store, ds, SystemTime::now() + Duration::from_secs(1));
        // All snapshots are older than 0 days from "now + 1s"
        assert_eq!(result.candidates_evaluated, 3);
        assert_eq!(result.destroyed, 3);
        assert_eq!(store.list_snapshots(ds).len(), 0);

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
