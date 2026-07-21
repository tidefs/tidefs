// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
// Deadlist drain consistency: verify that deadlist pins are created on
// snapshot, block auto-prune, are released on explicit destroy, and
// fully drained afterward with capacity reflected as freed.

use std::time::SystemTime;

use tidefs_local_object_store::{LocalObjectStore, ObjectKey, StoreOptions};
use tidefs_snapshot_pruner::{
    DeadlistPin, SnapshotPinEvidenceIndex, SnapshotPruneAction, SnapshotPruner,
    SnapshotRetentionPolicy,
};
use tidefs_types_reclaim_queue_core::{
    DeadObjectEntry, DeadObjectReplacementReceipt, ObjectKey as ReclaimObjectKey,
};

fn reclaim_key(key: ObjectKey) -> ReclaimObjectKey {
    ReclaimObjectKey(*key.as_bytes())
}

fn dead_object_entry_for_payload(
    key: ReclaimObjectKey,
    payload: &[u8],
    receipt_generation: u64,
) -> DeadObjectEntry {
    let digest = *blake3::hash(payload).as_bytes();
    let receipt = DeadObjectReplacementReceipt::replicated(
        key,
        7,
        receipt_generation,
        2,
        payload.len() as u64,
        digest,
    );
    DeadObjectEntry::new(key, [key.0[0]; 16], 5, true, 5).with_replacement_receipt(receipt)
}

/// After a snapshot is created with deadlist pin evidence, the evidence
/// index must contain those pins.
#[test]
fn deadlist_pin_evidence_persisted_on_snapshot() {
    let dir = std::env::temp_dir().join("tidefs-deadlist-drain-evidence-persist-test");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let mut store = LocalObjectStore::open(&dir).unwrap();
    let ds = "test-ds";
    store
        .put(
            tidefs_local_object_store::ObjectKey::from_name(b"obj1"),
            b"deadlisted data",
        )
        .unwrap();
    store.create_snapshot(ds, "snap-1").unwrap();

    let deadlist_pins = vec![
        DeadlistPin::new("dead-object-1"),
        DeadlistPin::new("dead-object-2"),
    ];
    let pruner = SnapshotPruner::new(SnapshotRetentionPolicy::default());
    pruner
        .record_snapshot_pin_evidence(&mut store, ds, "snap-1", Vec::new(), deadlist_pins)
        .unwrap();

    // Verify evidence is persisted
    let index = SnapshotPinEvidenceIndex::load(&store).unwrap().unwrap();
    let evidence = index.get("test-ds/snap-1").unwrap();
    let stored_pins = evidence.deadlist_pins.as_ref().unwrap();
    assert_eq!(stored_pins.len(), 2);
    assert_eq!(stored_pins[0].object_id, "dead-object-1");
    assert_eq!(stored_pins[1].object_id, "dead-object-2");

    drop(store);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Deadlist pins must block an auto-pruner retention candidate so it is
/// never deleted before explicit pin release.
#[test]
fn deadlist_pins_block_auto_prune() {
    let dir = std::env::temp_dir().join("tidefs-deadlist-drain-block-prune-test");
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
    store.create_snapshot(ds, "snap-1").unwrap();

    let pruner = SnapshotPruner::new(SnapshotRetentionPolicy {
        keep_last: Some(0),
        ..Default::default()
    });
    pruner
        .record_snapshot_pin_evidence(
            &mut store,
            ds,
            "snap-1",
            Vec::new(),
            vec![DeadlistPin::new("dead-object-1")],
        )
        .unwrap();

    // Plan: deadlist pins should block
    let result = pruner.plan_dataset_prune(&store, ds, SystemTime::now());
    assert_eq!(result.deadlist_pin_protected, 1);
    assert!(result.delete_set.is_empty());

    // Verify the decision
    let decision = result
        .decisions
        .iter()
        .find(|d| d.snapshot_name == "snap-1")
        .unwrap();
    assert!(matches!(decision.action, SnapshotPruneAction::Blocked(_)));
    assert_eq!(decision.deadlist_pins.len(), 1);

    drop(store);
    let _ = std::fs::remove_dir_all(&dir);
}

/// An explicit destroy must release extent pins held by the snapshot.
#[test]
fn explicit_destroy_releases_extent_pins() {
    let dir = std::env::temp_dir().join("tidefs-deadlist-drain-extent-pin-release-test");
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
    store.create_snapshot(ds, "snap-1").unwrap();

    // Pin an extent to the snapshot
    let snapshot_id = "test-ds/snap-1";
    let extent_key = tidefs_types_reclaim_queue_core::ObjectKey(
        *tidefs_local_object_store::ObjectKey::from_name(b"pinned-extent").as_bytes(),
    );
    store.pin_snapshot_extent(snapshot_id, extent_key);

    let mut pruner_pin_set = tidefs_gc_pin_set::SnapshotExtentPinSet::new();
    pruner_pin_set.pin(snapshot_id, extent_key);
    let mut pruner = SnapshotPruner::new(SnapshotRetentionPolicy::default());
    pruner.set_extent_pin_set(pruner_pin_set);

    assert!(store.snapshot_extent_pin_set().is_pinned(&extent_key));

    pruner
        .store_snapshot_checksum(&mut store, ds, "snap-1")
        .unwrap();

    let removed = pruner.destroy_snapshot(&mut store, ds, "snap-1").unwrap();
    assert_eq!(removed.name, "snap-1");

    // Extent pins must be released
    assert!(!store.snapshot_extent_pin_set().is_pinned(&extent_key));
    let pruner_pin_set = pruner.take_extent_pin_set().unwrap();
    assert!(!pruner_pin_set.is_pinned(&extent_key));

    drop(store);
    let _ = std::fs::remove_dir_all(&dir);
}

/// After explicit destroy and automatic evidence index cleanup, a subsequent
/// prune plan must produce zero deadlist-pin-protected candidates.
#[test]
fn deadlist_drain_completes_after_destroy_cleanup() {
    let dir = std::env::temp_dir().join("tidefs-deadlist-drain-complete-after-cleanup-test");
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
    store.create_snapshot(ds, "snap-1").unwrap();

    let mut pruner = SnapshotPruner::new(SnapshotRetentionPolicy::default());
    pruner
        .record_snapshot_pin_evidence(
            &mut store,
            ds,
            "snap-1",
            Vec::new(),
            vec![DeadlistPin::new("dead-object-1")],
        )
        .unwrap();
    pruner
        .store_snapshot_checksum(&mut store, ds, "snap-1")
        .unwrap();

    // Verify evidence exists before destroy
    let index = SnapshotPinEvidenceIndex::load(&store).unwrap().unwrap();
    assert!(index.get("test-ds/snap-1").is_some());

    // Destroy
    pruner.destroy_snapshot(&mut store, ds, "snap-1").unwrap();

    // The destroy path must clean up the stale evidence entry.
    let index = SnapshotPinEvidenceIndex::load(&store).unwrap().unwrap();
    assert!(index.get("test-ds/snap-1").is_none());
    assert!(index.is_empty());

    // Now plan a prune: nothing to protect
    let pruner2 = SnapshotPruner::new(SnapshotRetentionPolicy {
        keep_last: Some(0),
        ..Default::default()
    });
    let result = pruner2.plan_dataset_prune(&store, ds, SystemTime::now());
    assert_eq!(result.deadlist_pin_protected, 0);
    assert_eq!(result.candidates_evaluated, 0); // no snapshots left

    drop(store);
    let _ = std::fs::remove_dir_all(&dir);
}

// -- Capacity observation ------------------------------------------------

/// After writing known-size data, creating a snapshot with deadlist pins, and
/// destroying it, the receipt-bound deadlist drain must account the pinned
/// physical capacity as reclaimed.
#[test]
fn capacity_reflects_freed_extents_after_destroy() {
    let dir = std::env::temp_dir().join("tidefs-deadlist-drain-capacity-test");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let mut options = StoreOptions::test_fast();
    options.max_segment_bytes = 2048;
    let mut store = LocalObjectStore::open_with_options(&dir, options).unwrap();
    let ds = "test-ds";
    let snapshot_id = "test-ds/snap-capacity";
    let object_key = ObjectKey::from_name(b"deadlist-capacity-object");
    let old_payload = vec![0xA5; 1536];
    let replacement_payload = vec![0x5A; 1536];

    store.put(object_key, &old_payload).unwrap();
    store.create_snapshot(ds, "snap-capacity").unwrap();

    store.put(object_key, &replacement_payload).unwrap();
    let dead_extent = reclaim_key(object_key);
    let entry = dead_object_entry_for_payload(dead_extent, &old_payload, 1);
    assert!(store.enqueue_receipt_bound_dead_object(entry).unwrap());
    store.pin_snapshot_extent(snapshot_id, dead_extent);

    let mut pruner = SnapshotPruner::new(SnapshotRetentionPolicy::default());
    pruner
        .record_snapshot_pin_evidence(
            &mut store,
            ds,
            "snap-capacity",
            Vec::new(),
            vec![DeadlistPin::new(format!("{dead_extent}"))],
        )
        .unwrap();
    pruner
        .store_snapshot_checksum(&mut store, ds, "snap-capacity")
        .unwrap();

    let held = store
        .drain_receipt_bound_dead_objects_at_stable_generation(6, 1, 16)
        .unwrap();
    assert_eq!(held.entries_processed, 0);
    assert_eq!(held.segments_reclaimed, 0);
    assert_eq!(held.gate_extents_denied, 1);
    assert_eq!(held.reclaim_queue_depth, 1);
    assert!(store.snapshot_extent_pin_set().is_pinned(&dead_extent));

    pruner
        .destroy_snapshot(&mut store, ds, "snap-capacity")
        .unwrap();
    assert!(!store.snapshot_extent_pin_set().is_pinned(&dead_extent));

    let index = SnapshotPinEvidenceIndex::load(&store).unwrap().unwrap();
    assert!(index.get(snapshot_id).is_none());

    let before_drain_free_segments = store.free_segment_count();
    let segment_bytes = store.max_segment_bytes();
    let freed = store
        .drain_receipt_bound_dead_objects_at_stable_generation(6, 1, 16)
        .unwrap();
    assert_eq!(freed.entries_processed, 1);
    assert_eq!(freed.segments_reclaimed, 1);
    assert_eq!(freed.blocks_freed, 1);
    assert_eq!(freed.reclaim_queue_depth, 0);
    assert_eq!(store.reclaim_receipts().len(), 1);
    assert_eq!(store.reclaim_receipts()[0].freed_extents, vec![dead_extent]);

    let after_drain_free_segments = store.free_segment_count();
    assert!(
        after_drain_free_segments >= before_drain_free_segments,
        "deadlist drain must not reduce live free-segment capacity"
    );
    assert_eq!(
        freed.segments_reclaimed as u64 * segment_bytes,
        segment_bytes,
        "deadlist drain should expose the reclaimed segment as free capacity"
    );

    drop(store);
    let _ = std::fs::remove_dir_all(&dir);
}
