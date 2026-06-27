// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
// Clone pin blocks destroy: verify that a live clone dependency gates
// explicit snapshot destroy and that deadlist drain proceeds after the
// clone is removed.

use std::time::SystemTime;

use tidefs_local_object_store::LocalObjectStore;
use tidefs_snapshot_pruner::{
    CloneOriginPin, DeadlistPin, SnapshotPinEvidenceIndex, SnapshotPruneAction, SnapshotPruner,
    SnapshotPrunerError, SnapshotRetentionPolicy,
};

/// A snapshot with a live clone cannot be explicitly destroyed.
#[test]
fn clone_pin_blocks_explicit_destroy() {
    let dir = std::env::temp_dir().join("tidefs-clone-pin-blocks-destroy-test");
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
    store.create_snapshot(ds, "snap-origin").unwrap();

    // Create a clone dependency on snap-origin
    let parent_id = "test-ds/snap-origin";
    let clone_id = "test-ds/clone-snap";
    let mut pruner = SnapshotPruner::load(&store, SnapshotRetentionPolicy::default());
    pruner
        .record_clone(&mut store, parent_id, clone_id)
        .unwrap();

    // Store checksum so destroy can proceed if permitted
    pruner
        .store_snapshot_checksum(&mut store, ds, "snap-origin")
        .unwrap();

    // Record pin evidence with clone origin pin
    pruner
        .record_snapshot_pin_evidence(
            &mut store,
            ds,
            "snap-origin",
            vec![CloneOriginPin::clone_snapshot(clone_id)],
            Vec::new(),
        )
        .unwrap();

    // Destroy should fail because a clone exists
    let err = pruner
        .destroy_snapshot(&mut store, ds, "snap-origin")
        .unwrap_err();
    assert!(matches!(err, SnapshotPrunerError::HasClones));

    // Snapshot still exists
    let snapshots = store.list_snapshots(ds);
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].name, "snap-origin");

    drop(store);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Clone origin pins block auto-pruner retention deletion via the plan.
#[test]
fn clone_origin_pins_block_auto_prune() {
    let dir = std::env::temp_dir().join("tidefs-clone-pin-blocks-autoprune-test");
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
    store.create_snapshot(ds, "snap-origin").unwrap();

    let clone_id = "test-ds/clone-snap";
    let mut pruner = SnapshotPruner::load(&store, SnapshotRetentionPolicy::default());
    pruner
        .record_clone(&mut store, "test-ds/snap-origin", clone_id)
        .unwrap();
    pruner
        .record_snapshot_pin_evidence(
            &mut store,
            ds,
            "snap-origin",
            vec![CloneOriginPin::clone_snapshot(clone_id)],
            Vec::new(),
        )
        .unwrap();

    // Plan with keep_last=0 so snap-origin is a candidate
    let pruner2 = SnapshotPruner::load(
        &store,
        SnapshotRetentionPolicy {
            keep_last: Some(0),
            ..Default::default()
        },
    );
    let result = pruner2.plan_dataset_prune(&store, ds, SystemTime::now());
    assert_eq!(result.clone_origin_protected, 1);
    assert!(result.delete_set.is_empty());

    let decision = result
        .decisions
        .iter()
        .find(|d| d.snapshot_name == "snap-origin")
        .unwrap();
    assert!(matches!(decision.action, SnapshotPruneAction::Blocked(_)));
    assert_eq!(decision.clone_origin_pins.len(), 1);

    drop(store);
    let _ = std::fs::remove_dir_all(&dir);
}

/// After the clone is removed from the index, explicit destroy succeeds
/// and deadlist drain completes.
#[test]
fn destroy_succeeds_after_clone_removed() {
    let dir = std::env::temp_dir().join("tidefs-clone-pin-removed-destroy-test");
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
    store.create_snapshot(ds, "snap-origin").unwrap();

    let parent_id = "test-ds/snap-origin";
    let clone_id = "test-ds/clone-snap";
    let mut pruner = SnapshotPruner::load(&store, SnapshotRetentionPolicy::default());
    pruner
        .record_clone(&mut store, parent_id, clone_id)
        .unwrap();

    // Record pin evidence with both clone origin pins and deadlist pins
    pruner
        .record_snapshot_pin_evidence(
            &mut store,
            ds,
            "snap-origin",
            vec![CloneOriginPin::clone_snapshot(clone_id)],
            vec![DeadlistPin::new("dead-extent-1")],
        )
        .unwrap();
    pruner
        .store_snapshot_checksum(&mut store, ds, "snap-origin")
        .unwrap();

    // Destroy blocked by clone
    assert!(matches!(
        pruner.destroy_snapshot(&mut store, ds, "snap-origin"),
        Err(SnapshotPrunerError::HasClones)
    ));

    // Remove the clone dependency
    pruner
        .remove_clone(&mut store, parent_id, clone_id)
        .unwrap();

    // Now destroy succeeds
    let removed = pruner
        .destroy_snapshot(&mut store, ds, "snap-origin")
        .unwrap();
    assert_eq!(removed.name, "snap-origin");

    // Verify snapshot is gone
    assert!(store.list_snapshots(ds).is_empty());

    // The destroy path cleans up evidence for the destroyed snapshot.
    let index = SnapshotPinEvidenceIndex::load(&store).unwrap().unwrap();
    assert!(index.get("test-ds/snap-origin").is_none());

    drop(store);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A snapshot with both deadlist pins and clone origin pins protects
/// against both until the clone is removed, after which explicit destroy
/// releases all remaining pins.
#[test]
fn combined_pins_drain_after_clone_removed() {
    let dir = std::env::temp_dir().join("tidefs-combined-pins-drain-test");
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
    store.create_snapshot(ds, "snap-combined").unwrap();

    let parent_id = "test-ds/snap-combined";
    let clone_id = "test-ds/clone-snap-combined";
    let mut pruner = SnapshotPruner::load(&store, SnapshotRetentionPolicy::default());
    pruner
        .record_clone(&mut store, parent_id, clone_id)
        .unwrap();

    // Record both clone origin and deadlist pins
    pruner
        .record_snapshot_pin_evidence(
            &mut store,
            ds,
            "snap-combined",
            vec![CloneOriginPin::clone_snapshot(clone_id)],
            vec![
                DeadlistPin::new("dead-extent-a"),
                DeadlistPin::new("dead-extent-b"),
            ],
        )
        .unwrap();
    pruner
        .store_snapshot_checksum(&mut store, ds, "snap-combined")
        .unwrap();

    // Both protections should appear in auto-prune plan
    let pruner2 = SnapshotPruner::load(
        &store,
        SnapshotRetentionPolicy {
            keep_last: Some(0),
            ..Default::default()
        },
    );
    let result = pruner2.plan_dataset_prune(&store, ds, SystemTime::now());
    assert_eq!(result.clone_origin_protected, 1);
    assert_eq!(result.deadlist_pin_protected, 1);

    // Remove clone and destroy
    pruner
        .remove_clone(&mut store, parent_id, clone_id)
        .unwrap();
    let removed = pruner
        .destroy_snapshot(&mut store, ds, "snap-combined")
        .unwrap();
    assert_eq!(removed.name, "snap-combined");
    assert!(store.list_snapshots(ds).is_empty());

    // The destroy path removes the stale entry for the destroyed snapshot.
    let index = SnapshotPinEvidenceIndex::load(&store).unwrap().unwrap();
    assert!(index.is_empty());

    drop(store);
    let _ = std::fs::remove_dir_all(&dir);
}
