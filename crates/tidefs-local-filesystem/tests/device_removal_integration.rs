// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Local removal-record fixture: three-directory local topology, synthetic data
//! evacuation, label update, and BLAKE3 integrity verification.
//!
//! Exercises the local record helper pipeline:
//!   DeviceRemovalPlanner → DeviceRemovalExecutor → PoolConfig::remove_device
//!   → anchor_device_removal with PoolLabelV1 persistence.
//! It does not exercise a mounted live owner, canonical placement/refcount
//! evidence, raw device labels, or supported online device removal.

use std::collections::BTreeMap;
use std::path::PathBuf;

use tidefs_local_filesystem::device_removal::{
    anchor_device_removal, DeviceRemovalRecord, DEVICE_REMOVAL_RECORD_KEY, POOL_LABEL_KEY_PREFIX,
};
use tidefs_local_object_store::{LocalObjectStore, ObjectKey};
use tidefs_pool_scan::{
    DeviceHealth, DeviceRemovalError, DeviceRemovalExecutor, DeviceRemovalPlanner,
    DeviceRemovalResult, DeviceType, ObjectPlacement, PoolConfig,
};
use tidefs_replication_model::{FailureDomain, ReplicationIntent};
use tidefs_types_pool_label_core::{decode_label, DeviceClass, PoolState};

/// Build a single leaf device for a pool tree.
fn make_leaf_device(path: PathBuf, index: u32, guid: u8) -> DeviceType {
    DeviceType::Leaf {
        device_path: path,
        device_guid: [guid; 16],
        device_index: index,
        capacity_bytes: 1024 * 1024 * 1024,
        device_class: DeviceClass::Hdd,
        health: DeviceHealth::Online,
        read_errors: 0,
        write_errors: 0,
        checksum_errors: 0,
    }
}

#[test]
fn local_removal_record_fixture_checks_label_and_payload_encoding() {
    let dir = tempfile::tempdir().unwrap();

    // Create three separate backing stores.
    let disk0_dir = dir.path().join("disk0");
    let disk1_dir = dir.path().join("disk1");
    let disk2_dir = dir.path().join("disk2");
    std::fs::create_dir_all(&disk0_dir).unwrap();
    std::fs::create_dir_all(&disk1_dir).unwrap();
    std::fs::create_dir_all(&disk2_dir).unwrap();

    let mut store0 = LocalObjectStore::open(&disk0_dir).unwrap();
    let mut store1 = LocalObjectStore::open(&disk1_dir).unwrap();
    let mut store2 = LocalObjectStore::open(&disk2_dir).unwrap();

    // Write known objects to each store with BLAKE3 digest tracking.
    let mut disk1_objects: Vec<(u64, Vec<u8>, [u8; 32])> = Vec::new();

    // Objects on disk1 (the device to remove).
    for i in 0u64..5 {
        let data = format!("disk1-object-{i}-payload-filler-data").into_bytes();
        let digest: [u8; 32] = blake3::hash(&data).into();
        let name = format!("d1-obj-{i}");
        let key = ObjectKey::from_name(&name);
        store1.put(key, &data).unwrap();
        disk1_objects.push((i, data, digest));
    }

    // Objects on disk0 and disk2 (surviving devices, should not move).
    for i in 0u64..3 {
        let data = format!("disk0-object-{i}").into_bytes();
        let key = ObjectKey::from_name(format!("d0-obj-{i}"));
        store0.put(key, &data).unwrap();
    }
    for i in 0u64..3 {
        let data = format!("disk2-object-{i}").into_bytes();
        let key = ObjectKey::from_name(format!("d2-obj-{i}"));
        store2.put(key, &data).unwrap();
    }

    store0.sync().unwrap();
    store1.sync().unwrap();
    store2.sync().unwrap();
    drop(store0);
    drop(store1);
    drop(store2);

    // Build a three-directory local topology.
    let disk0_path: PathBuf = disk0_dir.clone();
    let disk1_path: PathBuf = disk1_dir.clone();
    let disk2_path: PathBuf = disk2_dir.clone();

    let leaf0 = make_leaf_device(disk0_path.clone(), 0, 0x01);
    let leaf1 = make_leaf_device(disk1_path.clone(), 1, 0x02);
    let leaf2 = make_leaf_device(disk2_path.clone(), 2, 0x03);

    let mut pool_config = PoolConfig {
        pool_uuid: [0x42u8; 16],
        pool_name: "integration-test-pool".to_string(),
        device_tree: DeviceType::Mirror {
            children: vec![leaf0, leaf1, leaf2],
        },
        redundancy_policy: tidefs_types_pool_label_core::PoolRedundancyPolicy::replicated(1),
        health: DeviceHealth::Online,
        state: PoolState::Active,
        total_capacity_bytes: 3 * 1024 * 1024 * 1024,
        allocated_bytes: 0,
        feature_flags: 0,
        topology_generation: 1,
        device_count: 3,
        missing_indices: vec![],
        removing_device_indices: vec![],
        completed_evacuations: vec![],
    };

    // Build object placements: all objects currently on disk1.
    let object_placements: Vec<ObjectPlacement> = disk1_objects
        .iter()
        .map(|(id, data, _digest)| ObjectPlacement::new(*id, disk1_path.clone(), data.len() as u64))
        .collect();

    // The fixture copies each local object once, matching the configured
    // one-copy policy rather than claiming two-target mirror evacuation.
    let intent = ReplicationIntent::new_mirror(1, FailureDomain::Device).unwrap();

    // Phase 1: Plan evacuation.
    let plan = DeviceRemovalPlanner::plan_removal(
        &pool_config.device_tree,
        &disk1_path,
        &object_placements,
        intent,
        pool_config.topology_generation,
    )
    .expect("plan_removal should succeed");

    assert_eq!(plan.device_count_before, 3);
    assert_eq!(plan.device_count_after, 2);
    assert_eq!(plan.object_count(), 5);
    assert_eq!(plan.surviving_devices.len(), 2);
    assert!(plan.surviving_devices.contains(&disk0_path));
    assert!(plan.surviving_devices.contains(&disk2_path));

    // Phase 2: Execute evacuation with real store I/O.
    let mut write_store0 = LocalObjectStore::open(&disk0_dir).unwrap();
    let mut write_store2 = LocalObjectStore::open(&disk2_dir).unwrap();

    // Maps from device path to the mutable store handle for writing.
    let mut store_map: BTreeMap<PathBuf, &mut LocalObjectStore> = BTreeMap::new();
    store_map.insert(disk0_path.clone(), &mut write_store0);
    store_map.insert(disk2_path.clone(), &mut write_store2);

    // Pre-load disk1 objects into memory for fast reads during evacuation.
    let disk1_data_map: BTreeMap<u64, Vec<u8>> = disk1_objects
        .iter()
        .map(|(id, data, _)| (*id, data.clone()))
        .collect();

    // Track which objects were written to which surviving device.
    let mut evacuated_to: BTreeMap<u64, PathBuf> = BTreeMap::new();

    let result = DeviceRemovalExecutor::execute_plan(
        &plan,
        |object_id| {
            disk1_data_map
                .get(&object_id)
                .cloned()
                .ok_or(DeviceRemovalError::NoObjectsOnDevice)
        },
        |object_id, data, target_device| {
            if let Some(target_store) = store_map.get_mut(target_device) {
                let key = ObjectKey::from_name(format!("evac-obj-{object_id}"));
                target_store.put(key, data).map_err(|e| {
                    DeviceRemovalError::DomainConstraintViolation {
                        details: e.to_string(),
                    }
                })?;
                evacuated_to.insert(object_id, target_device.to_path_buf());
                Ok(())
            } else {
                Err(DeviceRemovalError::TargetDeviceNotFound {
                    path: target_device.to_path_buf(),
                })
            }
        },
        |_| true,
    );

    // Sync surviving stores after all writes.
    write_store0.sync().unwrap();
    write_store2.sync().unwrap();
    drop(write_store0);
    drop(write_store2);

    assert_eq!(result.objects_evacuated, 5);
    assert_eq!(result.objects_failed, 0);
    let expected_bytes: u64 = disk1_objects
        .iter()
        .map(|(_, d, _)| d.len() as u64)
        .sum::<u64>();
    assert_eq!(result.bytes_evacuated, expected_bytes);

    // Phase 3: Update pool config (remove disk1).
    pool_config
        .remove_device(std::path::Path::new(&disk1_path))
        .expect("remove_device should succeed");
    assert_eq!(pool_config.device_count, 2);
    assert_eq!(pool_config.topology_generation, 2);

    // Phase 4: Anchor removal with label persistence.
    let anchoring_result = DeviceRemovalResult {
        objects_evacuated: result.objects_evacuated,
        bytes_evacuated: result.bytes_evacuated,
        objects_failed: result.objects_failed,
        removed_device: disk1_path.clone(),
        surviving_devices: vec![disk0_path.clone(), disk2_path.clone()],
        topology_generation: pool_config.topology_generation,
        committed_root_anchored: false,
    };

    // Write the anchor into one of the surviving stores.
    let mut anchor_store = LocalObjectStore::open(&disk0_dir).unwrap();
    anchor_device_removal(
        &mut anchor_store,
        &plan,
        &anchoring_result,
        Some(&pool_config),
        None,
        None,
    )
    .expect("anchor_device_removal should succeed");

    // Phase 5: Verify removal record exists and is valid.
    let record_key = ObjectKey::from_name(DEVICE_REMOVAL_RECORD_KEY);
    let record_bytes = anchor_store
        .get(record_key)
        .unwrap()
        .expect("removal record should exist");
    let record = DeviceRemovalRecord::decode_durable(&record_bytes).expect("record should decode");
    assert_eq!(record.removed_device, disk1_path);
    assert_eq!(record.device_count_before, 3);
    assert_eq!(record.device_count_after, 2);
    assert!(record.removal_complete);

    // Phase 6: Verify surviving device labels exist with correct data.
    for (idx, _expected_path) in [(0u32, &disk0_path), (2u32, &disk2_path)] {
        let label_key = ObjectKey::from_name(format!("{POOL_LABEL_KEY_PREFIX}{idx}"));
        let label_bytes = anchor_store
            .get(label_key)
            .unwrap()
            .unwrap_or_else(|| panic!("label for device {idx} should exist"));
        let decoded = decode_label(&label_bytes).expect("label should decode");
        assert_eq!(decoded.pool_guid, [0x42u8; 16]);
        assert_eq!(decoded.device_count, 2);
        assert_eq!(decoded.topology_generation, 2);
        assert_eq!(decoded.device_index, idx);
        assert!(
            tidefs_types_pool_label_core::verify_label_checksum(&decoded),
            "label checksum should be valid for device {idx}"
        );
    }

    // No label for the removed device (index 1).
    let removed_label_key = ObjectKey::from_name(format!("{POOL_LABEL_KEY_PREFIX}1"));
    assert!(
        anchor_store.get(removed_label_key).unwrap().is_none(),
        "no label should exist for removed device index 1"
    );

    // Phase 7: BLAKE3 integrity verification of evacuated objects.
    let verify_store0 = LocalObjectStore::open(&disk0_dir).unwrap();
    let verify_store2 = LocalObjectStore::open(&disk2_dir).unwrap();

    for (object_id, orig_data, orig_digest) in &disk1_objects {
        let evacuated_path = evacuated_to
            .get(object_id)
            .expect("every evac object should have a destination");

        let target_store = if evacuated_path == &disk0_path {
            &verify_store0
        } else if evacuated_path == &disk2_path {
            &verify_store2
        } else {
            panic!("unexpected evacuation target: {evacuated_path:?}");
        };

        let key = ObjectKey::from_name(format!("evac-obj-{object_id}"));
        let evacuated_data = target_store
            .get(key)
            .unwrap()
            .unwrap_or_else(|| panic!("evacuated object {object_id} should exist"));

        assert_eq!(
            &evacuated_data, orig_data,
            "evacuated data for object {object_id} should match original"
        );

        let actual_digest: [u8; 32] = blake3::hash(&evacuated_data).into();
        assert_eq!(
            actual_digest, *orig_digest,
            "BLAKE3 digest mismatch for evacuated object {object_id}"
        );
    }

    // Phase 8: Disk0 and disk2 original objects should still be intact.
    for i in 0u64..3 {
        let key0 = ObjectKey::from_name(format!("d0-obj-{i}"));
        assert!(
            verify_store0.get(key0).unwrap().is_some(),
            "disk0 original object {i} should still exist"
        );
        let key2 = ObjectKey::from_name(format!("d2-obj-{i}"));
        assert!(
            verify_store2.get(key2).unwrap().is_some(),
            "disk2 original object {i} should still exist"
        );
    }
}

#[test]
fn removal_with_no_objects_on_target_is_an_empty_plan() {
    let dir = tempfile::tempdir().unwrap();

    let disk0_dir = dir.path().join("disk0");
    let disk1_dir = dir.path().join("disk1");
    std::fs::create_dir_all(&disk0_dir).unwrap();
    std::fs::create_dir_all(&disk1_dir).unwrap();

    let mut store0 = LocalObjectStore::open(&disk0_dir).unwrap();
    let mut store1 = LocalObjectStore::open(&disk1_dir).unwrap();

    // Put objects only on disk0, not disk1.
    for i in 0u64..3 {
        let data = vec![i as u8; 256];
        let key = ObjectKey::from_name(format!("obj-{i}"));
        store0.put(key, &data).unwrap();
    }
    store0.sync().unwrap();
    store1.sync().unwrap();
    drop(store0);
    drop(store1);

    let disk0_path: PathBuf = disk0_dir.clone();
    let disk1_path: PathBuf = disk1_dir.clone();

    let leaf0 = make_leaf_device(disk0_path.clone(), 0, 0x01);
    let leaf1 = make_leaf_device(disk1_path.clone(), 1, 0x02);

    let pool_config = PoolConfig {
        pool_uuid: [0x99u8; 16],
        pool_name: "empty-evac-pool".to_string(),
        device_tree: DeviceType::Mirror {
            children: vec![leaf0, leaf1],
        },
        redundancy_policy: tidefs_types_pool_label_core::PoolRedundancyPolicy::replicated(1),
        health: DeviceHealth::Online,
        state: PoolState::Active,
        total_capacity_bytes: 2 * 1024 * 1024 * 1024,
        allocated_bytes: 0,
        feature_flags: 0,
        topology_generation: 1,
        device_count: 2,
        missing_indices: vec![],
        removing_device_indices: vec![],
        completed_evacuations: vec![],
    };

    // No objects on disk1 to evacuate.
    let object_placements: Vec<ObjectPlacement> = vec![];
    let intent = ReplicationIntent::new_mirror(1, FailureDomain::Device).unwrap();

    let plan = DeviceRemovalPlanner::plan_removal(
        &pool_config.device_tree,
        &disk1_path,
        &object_placements,
        intent,
        1,
    )
    .expect("an empty target should produce a valid local plan");

    assert!(plan.is_empty());
    assert_eq!(
        plan.evacuation_outcome,
        tidefs_pool_scan::EvacuationPlanOutcome::EmptySuccess
    );
}

#[test]
fn last_device_removal_refused() {
    let leaf = make_leaf_device(PathBuf::from("/dev/solo"), 0, 0x01);
    let mut config = PoolConfig {
        pool_uuid: [0x11u8; 16],
        pool_name: "solo-pool".to_string(),
        device_tree: leaf,
        redundancy_policy: tidefs_types_pool_label_core::PoolRedundancyPolicy::replicated(1),
        health: DeviceHealth::Online,
        state: PoolState::Active,
        total_capacity_bytes: 1024 * 1024 * 1024,
        allocated_bytes: 0,
        feature_flags: 0,
        topology_generation: 1,
        device_count: 1,
        missing_indices: vec![],
        removing_device_indices: vec![],
        completed_evacuations: vec![],
    };

    let result = config.remove_device(std::path::Path::new("/dev/solo"));
    assert!(matches!(result, Err(DeviceRemovalError::WouldEmptyPool)));
}

#[test]
fn pool_label_writer_raw_device_roundtrip_after_removal() {
    // Create temp files representing raw block devices for a 3-device mirror.
    let dir = tempfile::tempdir().unwrap();
    let disk0_path = dir.path().join("disk0");
    let disk1_path = dir.path().join("disk1");
    let disk2_path = dir.path().join("disk2");

    let file_size = 2 * 1024 * 1024; // 2 MiB each
    for p in &[&disk0_path, &disk1_path, &disk2_path] {
        let f = std::fs::File::create(p).unwrap();
        f.set_len(file_size).unwrap();
    }

    // Build 3-device mirror pool config.
    let leaf0 = DeviceType::Leaf {
        device_path: disk0_path.clone(),
        device_guid: [0x01u8; 16],
        device_index: 0,
        capacity_bytes: 1024 * 1024 * 1024,
        device_class: DeviceClass::Hdd,
        health: tidefs_pool_scan::DeviceHealth::Online,
        read_errors: 0,
        write_errors: 0,
        checksum_errors: 0,
    };
    let leaf1 = DeviceType::Leaf {
        device_path: disk1_path.clone(),
        device_guid: [0x02u8; 16],
        device_index: 1,
        capacity_bytes: 1024 * 1024 * 1024,
        device_class: DeviceClass::Hdd,
        health: tidefs_pool_scan::DeviceHealth::Online,
        read_errors: 0,
        write_errors: 0,
        checksum_errors: 0,
    };
    let leaf2 = DeviceType::Leaf {
        device_path: disk2_path.clone(),
        device_guid: [0x03u8; 16],
        device_index: 2,
        capacity_bytes: 1024 * 1024 * 1024,
        device_class: DeviceClass::Hdd,
        health: tidefs_pool_scan::DeviceHealth::Online,
        read_errors: 0,
        write_errors: 0,
        checksum_errors: 0,
    };

    let mut pool_config = PoolConfig {
        pool_uuid: [0xABu8; 16],
        pool_name: "writer-roundtrip-pool".to_string(),
        device_tree: DeviceType::Mirror {
            children: vec![leaf0, leaf1, leaf2],
        },
        redundancy_policy: tidefs_types_pool_label_core::PoolRedundancyPolicy::replicated(1),
        health: tidefs_pool_scan::DeviceHealth::Online,
        state: PoolState::Active,
        total_capacity_bytes: 3 * 1024 * 1024 * 1024,
        allocated_bytes: 0,
        feature_flags: 0,
        topology_generation: 3,
        device_count: 3,
        missing_indices: vec![],
        removing_device_indices: vec![],
        completed_evacuations: vec![],
    };

    // Remove disk1 via PoolConfig::remove_device.
    pool_config
        .remove_device(std::path::Path::new(&disk1_path))
        .expect("remove_device should succeed");
    assert_eq!(pool_config.device_count, 2);
    assert_eq!(pool_config.topology_generation, 4);

    // Write updated labels to surviving raw devices.
    let scan_cfg =
        tidefs_pool_scan::PoolScanConfig::new(vec![disk0_path.clone(), disk2_path.clone()])
            .with_label_area(256 * 1024);
    let writer = tidefs_pool_scan::PoolLabelWriter::new(scan_cfg.clone());

    let mut device_sizes = BTreeMap::new();
    device_sizes.insert(0, file_size);
    device_sizes.insert(2, file_size);

    writer
        .write_pool_labels(&pool_config, Some(&device_sizes))
        .expect("write_pool_labels should succeed");

    // Read labels back via LabelReader.
    let reader = tidefs_pool_scan::LabelReader::new(scan_cfg);
    let valid = reader.scan_valid_labels();
    assert_eq!(valid.len(), 2, "should have 2 surviving device labels");

    for (_path, label) in &valid {
        assert_eq!(label.pool_guid, [0xABu8; 16]);
        assert_eq!(
            label.device_count, 2,
            "device_count should be 2 after removal"
        );
        assert_eq!(
            label.topology_generation, 4,
            "topology should be 4 after removal"
        );
        assert!(
            tidefs_types_pool_label_core::verify_label_checksum(label),
            "label checksum should be valid"
        );
    }

    // Verify removed device index 1 is not present.
    let indices: Vec<u32> = valid.iter().map(|(_, l)| l.device_index).collect();
    assert!(
        !indices.contains(&1),
        "removed device index 1 should not be present"
    );
    assert!(indices.contains(&0));
    assert!(indices.contains(&2));

    // Verify the backup label is also writable and readable.
    let backup_offset = file_size - 256 * 1024;
    let mut backup_buf = [0u8; tidefs_types_pool_label_core::POOL_LABEL_V1_EXT_WIRE_SIZE];
    {
        use std::io::{Read, Seek};
        let mut f = std::fs::File::open(&disk0_path).unwrap();
        f.seek(std::io::SeekFrom::Start(backup_offset)).unwrap();
        f.read_exact(&mut backup_buf).unwrap();
    }
    let decoded = tidefs_types_pool_label_core::decode_label(&backup_buf).unwrap();
    assert!(tidefs_types_pool_label_core::verify_label_checksum(
        &decoded
    ));
    assert_eq!(decoded.device_count, 2);
    assert_eq!(decoded.topology_generation, 4);
}
