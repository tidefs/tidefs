//! Integration tests for the TDMA scheduler: slot allocation determinism,
//! epoch-boundary expiry, BLAKE3 integrity verification, slot collision
//! rejection, and slot-table capacity limits.

use std::collections::HashSet;
use tidefs_membership_epoch::EpochId;
use tidefs_tdma_scheduler::slot_allocator::SlotAllocator;
use tidefs_tdma_scheduler::slot_integrity::{SlotIntegrity, TdmaSlotHashInput};
use tidefs_tdma_scheduler::slot_table::{SlotEntry, SlotTable, SlotTableError};

// ---------------------------------------------------------------------------
// SlotAllocator integration tests
// ---------------------------------------------------------------------------

#[test]
fn integration_alloc_determinism_across_configs() {
    let mut a1 = SlotAllocator::new(EpochId(42), 1024).unwrap();
    let mut a2 = SlotAllocator::new(EpochId(42), 1024).unwrap();

    for node_id in 0..100u64 {
        for txg in 0..5u64 {
            let s1 = a1.allocate(EpochId(42), node_id, txg).unwrap();
            let s2 = a2.allocate(EpochId(42), node_id, txg).unwrap();
            assert_eq!(
                s1.slot_index, s2.slot_index,
                "non-deterministic: node={node_id} txg={txg}"
            );
        }
    }
}

#[test]
fn integration_no_collision_in_full_table() {
    let mut a = SlotAllocator::new(EpochId(1), 1024).unwrap();
    let mut seen = HashSet::new();

    for i in 0..1024u64 {
        let slot = a.allocate(EpochId(1), i, 0).unwrap();
        assert!(
            seen.insert(slot.slot_index),
            "duplicate slot_index for node={i}"
        );
    }
    assert!(a.is_full());
    assert_eq!(a.allocated_count(), 1024);
}

#[test]
fn integration_epoch_isolation() {
    let mut a5 = SlotAllocator::new(EpochId(5), 64).unwrap();
    let mut a6 = SlotAllocator::new(EpochId(6), 64).unwrap();

    let s5 = a5.allocate(EpochId(5), 10, 1).unwrap();
    let s6 = a6.allocate(EpochId(6), 10, 1).unwrap();
    assert_ne!(
        s5.slot_index, s6.slot_index,
        "same (node,txg) should hash to different slots in different epochs"
    );
    assert!(a5.allocate(EpochId(6), 20, 1).is_err());
}

#[test]
fn integration_release_and_reuse_cycle() {
    let mut a = SlotAllocator::new(EpochId(1), 64).unwrap();
    let first = a.allocate(EpochId(1), 10, 1).unwrap();
    assert!(a.release(10, 1));
    let second = a.allocate(EpochId(1), 10, 1).unwrap();
    assert_eq!(first.slot_index, second.slot_index);
}

#[test]
fn integration_lookup_finds_allocated_slot() {
    let mut a = SlotAllocator::new(EpochId(1), 64).unwrap();
    let slot = a.allocate(EpochId(1), 42, 3).unwrap();
    let found = a.lookup(42, 3).unwrap();
    assert_eq!(found.slot_index, slot.slot_index);
}

#[test]
fn integration_lookup_missing_returns_none() {
    let a = SlotAllocator::new(EpochId(1), 64).unwrap();
    assert!(a.lookup(99, 99).is_none());
}

// ---------------------------------------------------------------------------
// SlotIntegrity integration tests
// ---------------------------------------------------------------------------

#[test]
fn integration_integrity_full_roundtrip() {
    let input = TdmaSlotHashInput {
        epoch: 7,
        node_id: 42,
        write_txg: 3,
        slot_index: 15,
        slot_start: 1000,
        slot_end: 1100,
    };
    let hash = SlotIntegrity::hash_slot(&input);
    assert_eq!(hash.len(), 32);
    SlotIntegrity::verify_slot(&input, &hash).expect("roundtrip should pass");
}

#[test]
fn integration_tampered_epoch_fails() {
    let input = TdmaSlotHashInput {
        epoch: 7,
        node_id: 42,
        write_txg: 3,
        slot_index: 15,
        slot_start: 1000,
        slot_end: 1100,
    };
    let hash = SlotIntegrity::hash_slot(&input);
    let mut tampered = input;
    tampered.epoch = 99;
    assert!(SlotIntegrity::verify_slot(&tampered, &hash).is_err());
}

#[test]
fn integration_tampered_node_id_fails() {
    let input = TdmaSlotHashInput {
        epoch: 7,
        node_id: 42,
        write_txg: 3,
        slot_index: 15,
        slot_start: 1000,
        slot_end: 1100,
    };
    let hash = SlotIntegrity::hash_slot(&input);
    let mut tampered = input;
    tampered.node_id = 999;
    assert!(SlotIntegrity::verify_slot(&tampered, &hash).is_err());
}

#[test]
fn integration_tampered_txg_fails() {
    let input = TdmaSlotHashInput {
        epoch: 7,
        node_id: 42,
        write_txg: 3,
        slot_index: 15,
        slot_start: 1000,
        slot_end: 1100,
    };
    let hash = SlotIntegrity::hash_slot(&input);
    let mut tampered = input;
    tampered.write_txg = 99;
    assert!(SlotIntegrity::verify_slot(&tampered, &hash).is_err());
}

#[test]
fn integration_checksum_mismatch_error_text() {
    let input = TdmaSlotHashInput {
        epoch: 1,
        node_id: 1,
        write_txg: 1,
        slot_index: 1,
        slot_start: 1,
        slot_end: 1,
    };
    let hash = SlotIntegrity::hash_slot(&input);
    let mut bad = input;
    bad.epoch = 2;
    let err = SlotIntegrity::verify_slot(&bad, &hash).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("checksum mismatch"));
    assert!(msg.contains("computed"));
    assert!(msg.contains("stored"));
}

// ---------------------------------------------------------------------------
// SlotTable integration tests
// ---------------------------------------------------------------------------

#[test]
fn integration_table_insert_lookup_remove_cycle() {
    let mut t = SlotTable::new(64).unwrap();
    let entry = SlotEntry::new(EpochId(3), 10, 1, 5, 1000, 1100);
    t.insert(entry.clone()).unwrap();

    let found = t.lookup(10, 1).unwrap();
    assert_eq!(found.node_id, 10);
    assert_eq!(found.epoch, EpochId(3));

    let removed = t.remove(10, 1).unwrap();
    assert_eq!(removed.slot_index, 5);
    assert!(t.lookup(10, 1).is_none());
    assert!(t.is_empty());
}

#[test]
fn integration_table_epoch_expiry() {
    let mut t = SlotTable::new(64).unwrap();
    t.insert(SlotEntry::new(EpochId(1), 10, 1, 0, 0, 100))
        .unwrap();
    t.insert(SlotEntry::new(EpochId(2), 20, 1, 0, 0, 100))
        .unwrap();
    t.insert(SlotEntry::new(EpochId(4), 30, 1, 0, 0, 100))
        .unwrap();

    let removed = t.expire_epoch(EpochId(3));
    assert_eq!(removed.len(), 2);
    assert!(t.lookup(10, 1).is_none());
    assert!(t.lookup(20, 1).is_none());
    assert!(t.lookup(30, 1).is_some());
}

#[test]
fn integration_table_time_expiry() {
    let mut t = SlotTable::new(64).unwrap();
    t.insert(SlotEntry::new(EpochId(1), 10, 1, 0, 1000, 1100))
        .unwrap();
    t.insert(SlotEntry::new(EpochId(1), 20, 1, 0, 1000, 1200))
        .unwrap();
    t.insert(SlotEntry::new(EpochId(1), 30, 1, 0, 1000, 1300))
        .unwrap();

    let removed = t.expire_by_time(1150);
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0].node_id, 10);
    assert_eq!(t.len(), 2);

    let removed = t.expire_by_time(1300);
    assert_eq!(removed.len(), 2);
    assert!(t.is_empty());
}

#[test]
fn integration_table_capacity_enforcement() {
    let mut t = SlotTable::new(3).unwrap();
    t.insert(SlotEntry::new(EpochId(1), 1, 0, 0, 0, 100))
        .unwrap();
    t.insert(SlotEntry::new(EpochId(1), 2, 0, 0, 0, 100))
        .unwrap();
    t.insert(SlotEntry::new(EpochId(1), 3, 0, 0, 0, 100))
        .unwrap();
    assert!(t.is_full());

    let err = t
        .insert(SlotEntry::new(EpochId(1), 4, 0, 0, 0, 100))
        .unwrap_err();
    assert!(matches!(err, SlotTableError::TableFull { capacity: 3 }));
}

#[test]
fn integration_table_duplicate_rejected() {
    let mut t = SlotTable::new(64).unwrap();
    t.insert(SlotEntry::new(EpochId(1), 10, 1, 5, 1000, 1100))
        .unwrap();
    let err = t
        .insert(SlotEntry::new(EpochId(1), 10, 1, 7, 1000, 1100))
        .unwrap_err();
    assert!(matches!(
        err,
        SlotTableError::SlotAlreadyActive { node: 10, txg: 1 }
    ));
}

// ---------------------------------------------------------------------------
// TdmaSchedule trait integration tests
// ---------------------------------------------------------------------------

#[test]
fn integration_tdma_schedule_trait_on_allocator() {
    use tidefs_tdma_scheduler::TdmaSchedule;

    let mut a = SlotAllocator::new(EpochId(1), 256).unwrap();

    let slot = TdmaSchedule::allocate_slot(&mut a, EpochId(1), 42, 3).unwrap();
    assert_eq!(slot.epoch, EpochId(1));
    assert_eq!(slot.node_id, 42);
    assert_eq!(slot.write_txg, 3);

    let found = TdmaSchedule::lookup_slot(&a, 42, 3);
    assert!(found.is_some());

    assert!(TdmaSchedule::release_slot(&mut a, 42, 3));
    assert_eq!(TdmaSchedule::allocated_count(&a), 0);
    assert_eq!(TdmaSchedule::max_slots(&a), 256);

    assert!(TdmaSchedule::lookup_slot(&a, 42, 3).is_none());
}
