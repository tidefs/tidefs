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
}
