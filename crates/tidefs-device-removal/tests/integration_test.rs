//! Integration test: full device removal lifecycle with a 3-device pool,
//! LocatorTable-backed enumeration, data-mover-backed evacuation, and
//! pool-import detection.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use tidefs_block_allocator::DeviceId;
use tidefs_device_removal::{
    locator_integration::{LocatorTableObjectEnumerator, LocatorTableObjectMover},
    AllocationFence, DeviceRemovalDriver, DeviceRemovalPhase, EvacuationCheckpoint,
};
use tidefs_local_object_store::LocalObjectStore;
use tidefs_locator_table::{ExtentId, LocatorEntry, LocatorTable, RelocationDataMover};
use tidefs_pool_scan::{DeviceHealth, DeviceType};
use tidefs_types_pool_label_core::DeviceClass;

// ── Helpers ─────────────────────────────────────────────────────

fn make_leaf(path: &str, guid_byte: u8, index: u32, capacity: u64) -> DeviceType {
    DeviceType::Leaf {
        device_path: PathBuf::from(path),
        device_guid: [guid_byte; 16],
        device_index: index,
        capacity_bytes: capacity,
        device_class: DeviceClass::Hdd,
        health: DeviceHealth::Online,
        read_errors: 0,
        write_errors: 0,
        checksum_errors: 0,
    }
}

fn make_3_device_config() -> tidefs_pool_scan::PoolConfig {
    let leaf0 = make_leaf("/dev/disk0", 1, 0, 1024 * 1024 * 1024);
    let leaf1 = make_leaf("/dev/disk1", 2, 1, 1024 * 1024 * 1024);
    let leaf2 = make_leaf("/dev/disk2", 3, 2, 1024 * 1024 * 1024);
    tidefs_pool_scan::PoolConfig {
        pool_uuid: [0x42u8; 16],
        pool_name: "testpool".to_string(),
        redundancy_policy: tidefs_types_pool_label_core::PoolRedundancyPolicy::replicated(1),
        device_tree: DeviceType::Mirror {
            children: vec![leaf0, leaf1, leaf2],
        },
        health: DeviceHealth::Online,
        state: tidefs_types_pool_label_core::PoolState::Active,
        total_capacity_bytes: 3 * 1024 * 1024 * 1024,
        allocated_bytes: 0,
        feature_flags: 0,
        topology_generation: 1,
        device_count: 3,
        missing_indices: vec![],
        removing_device_indices: vec![],
    }
}

// ── In-memory data mover ─────────────────────────────────────────

/// An in-memory RelocationDataMover that stores extents in a HashMap.
struct MemDataMover {
    data: Mutex<HashMap<(u64, u64), Vec<u8>>>,
}

impl MemDataMover {
    fn new() -> Self {
        Self {
            data: Mutex::new(HashMap::new()),
        }
    }

    fn put(&self, device_id: u64, physical_offset: u64, payload: Vec<u8>) {
        self.data
            .lock()
            .unwrap()
            .insert((device_id, physical_offset), payload);
    }
}

impl RelocationDataMover for MemDataMover {
    fn read_extent(
        &self,
        device_id: u64,
        physical_offset: u64,
        _length: u32,
    ) -> Result<Vec<u8>, tidefs_locator_table::LocatorError> {
        self.data
            .lock()
            .unwrap()
            .get(&(device_id, physical_offset))
            .cloned()
            .ok_or(tidefs_locator_table::LocatorError::NotFound)
    }

    fn write_extent(
        &self,
        device_id: u64,
        physical_offset: u64,
        data: &[u8],
    ) -> Result<(), tidefs_locator_table::LocatorError> {
        self.data
            .lock()
            .unwrap()
            .insert((device_id, physical_offset), data.to_vec());
        Ok(())
    }
}

// ── AllocationFence mock ─────────────────────────────────────────

#[derive(Debug, Default)]
struct TestAllocationFence {
    fenced: Mutex<BTreeSet<DeviceId>>,
}

impl AllocationFence for TestAllocationFence {
    fn fence_device(&self, device_id: DeviceId) {
        self.fenced.lock().unwrap().insert(device_id);
    }
    fn unfence_device(&self, device_id: DeviceId) {
        self.fenced.lock().unwrap().remove(&device_id);
    }
    fn is_device_fenced(&self, device_id: DeviceId) -> bool {
        self.fenced.lock().unwrap().contains(&device_id)
    }
}

// ── Tests ───────────────────────────────────────────────────────

#[test]
fn full_3_device_removal_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalObjectStore::open(dir.path()).unwrap();
    let locator = Arc::new(LocatorTable::new(store, 1));
    let data_mover = Arc::new(MemDataMover::new());

    // Populate locator table: 5 objects on device 1.
    let objects: Vec<ExtentId> = (0..5).map(|i| ExtentId::from(i as u64)).collect();

    for (i, &eid) in objects.iter().enumerate() {
        let payload = vec![(i as u8 + 1) * 10; 256];
        let physical_offset = i as u64 * 4096;
        data_mover.put(1, physical_offset, payload.clone());

        locator
            .insert(
                100 + i as u64,
                LocatorEntry {
                    logical_offset: i as u64 * 4096,
                    extent_id: eid,
                    device_id: 1,
                    physical_offset,
                    length: 256,
                    flags: 0,
                    checksum: [0u8; 32],
                },
            )
            .unwrap();
    }

    // Build the driver for removing device 1.
    let config = make_3_device_config();
    let mut driver = DeviceRemovalDriver::prepare(
        Box::new(TestAllocationFence::default()),
        Path::new("/dev/disk1"),
        config,
        vec![DeviceId(0), DeviceId(2)],
        objects.len() as u64,
    )
    .unwrap();

    assert_eq!(driver.state().phase, DeviceRemovalPhase::Removing);

    // Phase: Removing -> Evacuating
    driver.begin_evacuation().unwrap();
    assert_eq!(driver.state().phase, DeviceRemovalPhase::Evacuating);

    // Evacuate all objects to device 0.
    let enumr = LocatorTableObjectEnumerator::new(locator.clone());
    let mover = LocatorTableObjectMover::with_data_mover(locator.clone(), data_mover.clone());

    let (evacuated, failed) = driver
        .evacuate_batch(&enumr, &mover, DeviceId(0), 10)
        .unwrap();

    assert_eq!(evacuated, 5, "should evacuate all 5 objects");
    assert_eq!(failed, 0, "no failures expected");
    assert_eq!(driver.state().objects_evacuated, 5);
    assert_eq!(driver.state().objects_failed, 0);
    assert!(driver.state().is_evacuation_complete());

    // Phase: Evacuating -> Evacuated
    driver.mark_evacuated().unwrap();
    assert_eq!(driver.state().phase, DeviceRemovalPhase::Evacuated);

    // Phase: Evacuated -> Vacated
    let leaf0 = make_leaf("/dev/disk0", 1, 0, 1024 * 1024 * 1024);
    let leaf2 = make_leaf("/dev/disk2", 3, 2, 1024 * 1024 * 1024);
    let updated_config = tidefs_pool_scan::PoolConfig {
        pool_uuid: [0x42u8; 16],
        pool_name: "testpool".to_string(),
        redundancy_policy: tidefs_types_pool_label_core::PoolRedundancyPolicy::replicated(1),
        device_tree: DeviceType::Mirror {
            children: vec![leaf0, leaf2],
        },
        health: DeviceHealth::Online,
        state: tidefs_types_pool_label_core::PoolState::Active,
        total_capacity_bytes: 2 * 1024 * 1024 * 1024,
        allocated_bytes: 0,
        feature_flags: 0,
        topology_generation: 2,
        device_count: 2,
        missing_indices: vec![],
        removing_device_indices: vec![],
    };

    driver.commit_vacated(updated_config).unwrap();
    assert_eq!(driver.state().phase, DeviceRemovalPhase::Vacated);

    // Phase: Vacated -> Removed
    driver.mark_removed().unwrap();
    assert_eq!(driver.state().phase, DeviceRemovalPhase::Removed);

    // Verify all objects now reside on device 0.
    for &eid in &objects {
        let entry = locator.lookup_extent(100 + eid.0, eid).unwrap();
        assert!(entry.is_some(), "object {eid:?} not found in locator");
        let e = entry.unwrap();
        assert_eq!(
            e.device_id, 0,
            "object {eid:?} should be on device 0, but is on device {}",
            e.device_id
        );
    }

    // Verify data mover still has all payloads (written to device 0).
    for (i, &eid) in objects.iter().enumerate() {
        let payload = data_mover.read_extent(0, i as u64 * 4096, 256).unwrap();
        let expected_byte = (i as u8 + 1) * 10;
        assert_eq!(
            payload,
            vec![expected_byte; 256],
            "payload mismatch for object {eid:?}"
        );
    }
}

#[test]
fn checkpoint_recovery_resumes_evacuation() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalObjectStore::open(dir.path()).unwrap();
    let locator = Arc::new(LocatorTable::new(store, 1));
    let data_mover = Arc::new(MemDataMover::new());

    // 6 objects on device 2.
    let objects: Vec<ExtentId> = (0..6).map(|i| ExtentId::from(i as u64)).collect();

    for (i, &eid) in objects.iter().enumerate() {
        let payload = vec![(i as u8) * 7; 128];
        let phys = i as u64 * 2048;
        data_mover.put(2, phys, payload.clone());

        locator
            .insert(
                200 + i as u64,
                LocatorEntry {
                    logical_offset: i as u64 * 2048,
                    extent_id: eid,
                    device_id: 2,
                    physical_offset: phys,
                    length: 128,
                    flags: 0,
                    checksum: [0u8; 32],
                },
            )
            .unwrap();
    }

    let config = make_3_device_config();
    let mut driver = DeviceRemovalDriver::prepare(
        Box::new(TestAllocationFence::default()),
        Path::new("/dev/disk2"),
        config,
        vec![DeviceId(0), DeviceId(1)],
        6,
    )
    .unwrap();

    driver.begin_evacuation().unwrap();

    let enumr = LocatorTableObjectEnumerator::new(locator.clone());
    let mover = LocatorTableObjectMover::with_data_mover(locator.clone(), data_mover.clone());

    // Evacuate only 2 objects, then checkpoint (simulating crash before
    // completing).
    driver
        .evacuate_batch(&enumr, &mover, DeviceId(0), 2)
        .unwrap();
    assert_eq!(driver.state().objects_evacuated, 2);

    let checkpoint = driver.create_checkpoint(DeviceId(0));
    let serialized = serde_json::to_vec(&checkpoint).unwrap();

    // ── Simulate crash: create a new driver and apply checkpoint ──
    let config2 = make_3_device_config();
    let mut driver2 = DeviceRemovalDriver::prepare(
        Box::new(TestAllocationFence::default()),
        Path::new("/dev/disk2"),
        config2,
        vec![DeviceId(0), DeviceId(1)],
        6,
    )
    .unwrap();

    driver2.begin_evacuation().unwrap();

    // Restore checkpoint.
    let cp: EvacuationCheckpoint = serde_json::from_slice(&serialized).unwrap();
    assert_eq!(cp.objects_evacuated, 2);
    driver2.apply_checkpoint(&cp).unwrap();

    // Evacuate remaining 4 objects.
    let enumr2 = LocatorTableObjectEnumerator::new(locator.clone());
    let mover2 = LocatorTableObjectMover::with_data_mover(locator.clone(), data_mover.clone());

    let (evac, failed) = driver2
        .evacuate_batch(&enumr2, &mover2, DeviceId(0), 10)
        .unwrap();

    // We already evacuated 2, so the batch should skip those and do the
    // remaining 4.
    assert_eq!(evac, 4, "should evacuate remaining 4 objects");
    assert_eq!(failed, 0);
    assert_eq!(driver2.state().objects_evacuated, 6);
}

#[test]
fn pool_import_detects_removal_in_progress() {
    // Simulate the pool-import detection path.
    let mut config = make_3_device_config();
    config.mark_device_removing(1);
    assert!(config.is_device_removing(1));
    assert_eq!(config.removing_device_ids(), vec![1]);

    // The pool-import crate's `detect_in_progress_removal` sets
    // PoolImportStats::removal_in_progress based on this.
    // Here we just verify the pool-config-level flag is correct.
    let indices = config.removing_device_ids();
    assert!(!indices.is_empty());
    assert_eq!(indices.len(), 1);
    assert_eq!(indices[0], 1);
}

#[test]
fn removal_with_zero_objects_completes_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalObjectStore::open(dir.path()).unwrap();
    let locator = Arc::new(LocatorTable::new(store, 1));

    let config = make_3_device_config();
    let mut driver = DeviceRemovalDriver::prepare(
        Box::new(TestAllocationFence::default()),
        Path::new("/dev/disk1"),
        config,
        vec![DeviceId(0), DeviceId(2)],
        0,
    )
    .unwrap();

    driver.begin_evacuation().unwrap();
    driver.mark_evacuated().unwrap();

    let leaf0 = make_leaf("/dev/disk0", 1, 0, 1024 * 1024 * 1024);
    let leaf2 = make_leaf("/dev/disk2", 3, 2, 1024 * 1024 * 1024);
    let updated_config = tidefs_pool_scan::PoolConfig {
        pool_uuid: [0x42u8; 16],
        pool_name: "testpool".to_string(),
        redundancy_policy: tidefs_types_pool_label_core::PoolRedundancyPolicy::replicated(1),
        device_tree: DeviceType::Mirror {
            children: vec![leaf0, leaf2],
        },
        health: DeviceHealth::Online,
        state: tidefs_types_pool_label_core::PoolState::Active,
        total_capacity_bytes: 2 * 1024 * 1024 * 1024,
        allocated_bytes: 0,
        feature_flags: 0,
        topology_generation: 2,
        device_count: 2,
        missing_indices: vec![],
        removing_device_indices: vec![],
    };
    driver.commit_vacated(updated_config).unwrap();
    driver.mark_removed().unwrap();

    assert_eq!(driver.state().phase, DeviceRemovalPhase::Removed);
    let _ = locator; // silence unused warning
}
