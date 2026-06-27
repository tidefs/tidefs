// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::path::PathBuf;

use tidefs_local_object_store::{
    DeviceBacking, DeviceClass, DeviceConfig, DeviceIoClass as IoClass, DeviceKind,
    DeviceMediaClass, ObjectKey, Pool, PoolConfig, PoolProperties, PoolRedundancyPolicy,
    StoreOptions,
};
use tidefs_membership_epoch::MemberId;
use tidefs_rebuild_runtime::admission::{LossRecord, RebuildAdmission};
use tidefs_rebuild_runtime::scheduler::BackfillScheduler;
use tidefs_replication_model::{ReplicaMovementClass, ReplicatedSubjectId};

fn data_device(path: PathBuf) -> DeviceConfig {
    DeviceConfig {
        path: path.clone(),
        backing: DeviceBacking::DirectoryObjectStoreCompat,
        class: DeviceClass::Data,
        media_class: DeviceMediaClass::Ssd,
        kind: DeviceKind::Single { path },
        compression: None,
        encryption: None,
    }
}

#[test]
fn local_pool_receipt_refs_feed_rebuild_admission() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config = PoolConfig {
        name: "receipt-ingest".to_string(),
        root_path: temp.path().join("pool"),
        devices: vec![
            data_device(temp.path().join("dev0")),
            data_device(temp.path().join("dev1")),
        ],
    };
    let properties = PoolProperties {
        redundancy_policy: PoolRedundancyPolicy::replicated(2),
        ..PoolProperties::default()
    };
    let mut pool =
        Pool::create(config, properties, &StoreOptions::test_fast()).expect("create local pool");

    let payload = b"local pool placement receipt payload";
    let key = ObjectKey::from_name(b"local-pool-rebuild-admission");
    pool.put(IoClass::Data, key, payload).expect("pool put");

    let receipt_refs = pool
        .placement_receipt_refs(IoClass::Data)
        .expect("placement receipt refs");
    assert_eq!(receipt_refs.len(), 1);
    let receipt_ref = receipt_refs[0];
    assert!(!receipt_ref.is_synthetic());
    assert_eq!(receipt_ref.object_key, key.as_bytes32());
    assert_eq!(receipt_ref.payload_len, payload.len() as u64);
    assert_eq!(receipt_ref.target_count, 2);

    let loss = LossRecord::from_placement_receipt_refs(
        vec![MemberId::new(1)],
        vec![MemberId::new(2)],
        receipt_refs,
        ReplicaMovementClass::RebuildLostOrSuspectCopy,
        receipt_ref.receipt_epoch.0,
        10_000,
    )
    .expect("loss record from local receipt refs");

    let mut admission = RebuildAdmission::with_epoch(receipt_ref.receipt_epoch.0);
    let mut scheduler = BackfillScheduler::new();
    let outcome = admission.admit(&loss, &mut scheduler);

    assert_eq!(outcome.admitted, vec![MemberId::new(1)]);
    assert!(outcome.refused.is_empty());
    assert_eq!(outcome.report_count, 1);

    let tasks = scheduler.drain_eligible();
    assert_eq!(tasks.len(), 1);
    assert_eq!(
        tasks[0].subject_ref,
        ReplicatedSubjectId::new(receipt_ref.object_id)
    );
    assert_eq!(tasks[0].placement_receipt_ref, receipt_ref);
    assert_eq!(tasks[0].source_member, MemberId::new(2));
    assert_eq!(tasks[0].target_member, MemberId::new(1));
    assert_eq!(tasks[0].payload_len, payload.len() as u64);
    assert!(!tasks[0].placement_receipt_ref.is_synthetic());

    let intents = admission.generate_intents(&loss);
    assert_eq!(intents.len(), 1);
    assert_eq!(intents[0].placement_receipt_ref, receipt_ref);
    assert_eq!(intents[0].source_member_ref, MemberId::new(2));
    assert_eq!(intents[0].target_member_ref, MemberId::new(1));
    assert_eq!(intents[0].payload_len, payload.len() as u64);
    assert!(!intents[0].placement_receipt_ref.is_synthetic());
}

#[test]
fn rebuild_after_replacement_generates_new_receipt() {
    // After a rebuild replaces a lost device, the replacement receipt must
    // have a higher generation and the original receipt targets must not be
    // treated as live.  This is a local-pool integration test that exercises
    // the receipt-generation path end-to-end without requiring multi-node
    // transport.
    let temp = tempfile::tempdir().expect("tempdir");
    let config = PoolConfig {
        name: "rebuild-replacement".to_string(),
        root_path: temp.path().join("pool"),
        devices: vec![
            data_device(temp.path().join("dev0")),
            data_device(temp.path().join("dev1")),
            data_device(temp.path().join("dev2")),
        ],
    };
    let properties = PoolProperties {
        redundancy_policy: PoolRedundancyPolicy::replicated(2),
        ..PoolProperties::default()
    };
    let mut pool = Pool::create(config, properties, &StoreOptions::test_fast())
        .expect("create rebuild-replacement pool");

    // Write initial data through the pool — this produces the first receipt.
    let payload = b"rebuild-after-replacement payload v1";
    let key = ObjectKey::from_name(b"rebuild-after-replacement");
    let (_stored, receipt1) = pool
        .put_with_receipt(IoClass::Data, key, payload)
        .expect("initial put_with_receipt");

    assert!(
        receipt1.generation > 0,
        "receipt must have non-zero generation"
    );
    assert_eq!(receipt1.targets.len(), 2);
    assert!(!receipt1.shared_receipt_ref().unwrap().is_synthetic());

    // Write replacement data (simulating a rebuild that restores the object
    // onto a different device set).  In a full rebuild the placement planner
    // would select the remaining healthy devices; we rely on put_with_receipt
    // to issue a fresh receipt.
    let replacement_payload = b"rebuild-after-replacement payload v2";
    let (_stored2, receipt2) = pool
        .put_with_receipt(IoClass::Data, key, replacement_payload)
        .expect("replacement put_with_receipt");

    // The replacement receipt must have a strictly higher generation.
    assert!(
        receipt2.generation > receipt1.generation,
        "replacement receipt generation {} must exceed original {}",
        receipt2.generation,
        receipt1.generation
    );

    // A shared receipt ref projection from the replacement receipt must not
    // be synthetic and must carry the newer generation.
    let ref2 = receipt2
        .shared_receipt_ref()
        .expect("shared receipt ref for replacement");
    assert!(!ref2.is_synthetic());
    assert_eq!(ref2.receipt_generation, receipt2.generation);

    // The latest receipt scan must return only the replacement receipt.
    let receipts = pool
        .placement_receipts(IoClass::Data)
        .expect("placement_receipts after replacement");
    let key_receipts: Vec<_> = receipts.iter().filter(|r| r.object_key == key).collect();
    assert_eq!(
        key_receipts.len(),
        1,
        "only the latest receipt should be retained per object key"
    );
    assert_eq!(key_receipts[0].generation, receipt2.generation);
    assert_eq!(key_receipts[0].payload_digest, receipt2.payload_digest);

    // The replacement receipt target count must match the redundancy policy.
    assert_eq!(key_receipts[0].targets.len(), 2);
}
