// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note

use tidefs_local_filesystem::{
    ChangedRecordExport, ChangedRecordTransformContract, CommittedRootSummary,
};
use tidefs_local_object_store::IntegrityDigest64;

fn root_summary(transaction_id: u64, generation: u64) -> CommittedRootSummary {
    CommittedRootSummary {
        slot: 0,
        transaction_id,
        generation,
        next_inode_id: 1,
        inode_count: 0,
        superblock_checksum: IntegrityDigest64(0x1000 + transaction_id),
        has_transaction_manifest: true,
        manifest_checksum: IntegrityDigest64(0x2000 + transaction_id),
        manifest_entry_count: 0,
        has_root_authentication: false,
        root_authentication_policy_epoch: None,
        root_authentication_algorithm_suite_id: None,
        superblock_digest: None,
        manifest_digest: None,
        root_authentication_code: None,
    }
}

fn export(incremental: bool, placement_epoch: Option<u64>) -> ChangedRecordExport {
    ChangedRecordExport {
        spec: "test",
        stream_version: if incremental { 2 } else { 1 },
        current_root: root_summary(2, 20),
        roots: Vec::new(),
        total_records: 0,
        payload_bytes: 0,
        production_fsck_required: false,
        from_root: incremental.then(|| root_summary(1, 10)),
        incremental,
        placement_epoch,
        transform_contract: ChangedRecordTransformContract::StoredFrameNoDeviceTransforms,
    }
}

#[test]
fn vfssend1_versions_decode_as_local_only_sender_authority() {
    for (incremental, placement_epoch, expected_version) in [
        (false, None, 1),
        (true, None, 2),
        (false, Some(7), 3),
        (true, Some(7), 4),
    ] {
        let encoded = export(incremental, placement_epoch).encode();
        let decoded = ChangedRecordExport::decode(&encoded).unwrap();

        assert_eq!(decoded.stream_version, expected_version);
        assert!(decoded.sender_authority().is_absent_local_only());
    }
}
