// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Read-path unit tests for the local-filesystem layer.
//!
//! Exercises the read, getattr, and lookup entry points on regular files.
//! Complements the write-read integration tests in write_read_integration.rs
//! which already cover the data path. This module adds targeted coverage for
//! the metadata-side read operations: getattr attribute verification and
//! lookup namespace resolution.

use std::env;
use std::fs;
use std::path::PathBuf;

use tidefs_local_filesystem::{FileSystemError, LocalFileSystem, DEFAULT_FILE_PERMISSIONS};
use tidefs_storage_intent_core::{
    EvidenceCompletenessVerdict, EvidenceConsumerClass, EvidenceFamilyFreshness,
    EvidenceFamilyFreshnessSet, EvidenceFamilyFreshnessState, EvidenceQueryContextClass,
    EvidenceQuerySubjectScope, EvidenceQuerySubjectScopeClass, EvidenceRetentionClass,
    StorageIntentDomainId, StorageIntentEvidenceId, StorageIntentEvidenceKind,
    StorageIntentEvidenceRef, StorageIntentEvidenceRefs as CoreEvidenceRefs,
    StorageIntentObjectScope, StorageIntentPolicyId, StorageIntentPolicyRevision,
    StorageIntentReceiptId, StorageIntentRefusalReason,
};
use tidefs_storage_intent_read_serving::{
    DegradedReadPolicy, ReadFreshnessProfile, ReadServingCandidateRecord, ReadServingDecisionInput,
    ReadServingDecisionState, ReadServingEvidenceCutState, ReadServingEvidenceRefs,
    ReadServingPolicy, ReadServingRejectionMask, StorageIntentReadSourceClass,
};
use tidefs_types_vfs_core::{InodeId, NodeKind, S_IFREG};

// Helpers

fn set_test_key() {
    std::env::set_var("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64));
}

fn temp_dir(label: &str) -> PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = env::temp_dir().join(format!("tidefs-rp-{label}-{ts}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn open_fs(dir: &std::path::Path) -> LocalFileSystem {
    LocalFileSystem::open(dir).expect("open filesystem")
}

fn make_data(seed: u8, len: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(len);
    let mut val = seed;
    for _ in 0..len {
        buf.push(val);
        val = val.wrapping_add(1);
    }
    buf
}

const POLICY_ID: StorageIntentPolicyId = StorageIntentPolicyId([0x31; 16]);
const POLICY_REVISION: StorageIntentPolicyRevision = StorageIntentPolicyRevision(7);
const DATASET_ID: StorageIntentDomainId = StorageIntentDomainId([0x41; 16]);
const OBJECT_ID: StorageIntentEvidenceId = StorageIntentEvidenceId([0x51; 32]);
const SOURCE_RECEIPT: StorageIntentReceiptId = StorageIntentReceiptId([0x61; 16]);

fn evidence_ref(kind: StorageIntentEvidenceKind, seed: u8) -> StorageIntentEvidenceRef {
    StorageIntentEvidenceRef::new(kind, StorageIntentEvidenceId([seed; 32]), 1, 1)
}

fn read_serving_refs() -> ReadServingEvidenceRefs {
    ReadServingEvidenceRefs {
        compiled_policy_ref: evidence_ref(StorageIntentEvidenceKind::LocalIntentRecord, 1),
        evidence_query_snapshot_ref: evidence_ref(
            StorageIntentEvidenceKind::EvidenceQuerySnapshot,
            2,
        ),
        freshness_ref: evidence_ref(StorageIntentEvidenceKind::ReadFreshnessEvidence, 3),
        namespace_generation_ref: evidence_ref(
            StorageIntentEvidenceKind::MetadataNamespaceEvidence,
            4,
        ),
        placement_receipt_ref: evidence_ref(StorageIntentEvidenceKind::PlacementReceipt, 5),
        cache_anchor_ref: evidence_ref(StorageIntentEvidenceKind::ReadFreshnessEvidence, 6),
        cache_fence_ref: evidence_ref(StorageIntentEvidenceKind::OrderingEvidence, 7),
        membership_epoch_ref: evidence_ref(StorageIntentEvidenceKind::MembershipEvidence, 8),
        lease_epoch_ref: evidence_ref(StorageIntentEvidenceKind::MembershipEvidence, 9),
        transport_path_ref: evidence_ref(StorageIntentEvidenceKind::TransportPathEvidence, 10),
        trust_domain_ref: evidence_ref(StorageIntentEvidenceKind::TrustDomainEvidence, 11),
        data_shape_ref: evidence_ref(StorageIntentEvidenceKind::DataShapeEvidence, 12),
        layout_allocator_ref: evidence_ref(StorageIntentEvidenceKind::LayoutAllocatorEvidence, 13),
        digest_checksum_ref: evidence_ref(StorageIntentEvidenceKind::DataShapeEvidence, 14),
        media_capability_ref: evidence_ref(StorageIntentEvidenceKind::MediaCapabilityEvidence, 15),
        ram_authority_ref: evidence_ref(StorageIntentEvidenceKind::RamAuthorityEvidence, 16),
        recovery_degradation_ref: evidence_ref(
            StorageIntentEvidenceKind::RecoveryDegradationEvidence,
            17,
        ),
        redundancy_ref: evidence_ref(StorageIntentEvidenceKind::DataShapeEvidence, 18),
        temporal_ref: evidence_ref(StorageIntentEvidenceKind::TemporalEvidence, 19),
        scheduler_admission_ref: evidence_ref(
            StorageIntentEvidenceKind::SchedulerAdmissionRecord,
            20,
        ),
        repair_budget_ref: evidence_ref(StorageIntentEvidenceKind::CapacityAdmissionEvidence, 21),
        replacement_receipt_ref: StorageIntentEvidenceRef::default(),
        prefetch_decision_ref: evidence_ref(
            StorageIntentEvidenceKind::DecisionFrontierEvidence,
            22,
        ),
        result_refusal_ref: evidence_ref(StorageIntentEvidenceKind::ResultRefusalEvidence, 23),
        ordering_evidence_ref: evidence_ref(StorageIntentEvidenceKind::OrderingEvidence, 24),
        policy_rollout_ref: evidence_ref(StorageIntentEvidenceKind::PolicyRolloutEvidence, 25),
        tenant_isolation_ref: evidence_ref(StorageIntentEvidenceKind::TenantIsolationEvidence, 26),
        service_objective_ref: evidence_ref(
            StorageIntentEvidenceKind::ServiceObjectiveEvidence,
            27,
        ),
        capacity_admission_ref: evidence_ref(
            StorageIntentEvidenceKind::CapacityAdmissionEvidence,
            28,
        ),
    }
}

fn family_ref(
    kind: StorageIntentEvidenceKind,
    refs: ReadServingEvidenceRefs,
) -> StorageIntentEvidenceRef {
    match kind {
        StorageIntentEvidenceKind::LocalIntentRecord => refs.compiled_policy_ref,
        StorageIntentEvidenceKind::ReadFreshnessEvidence => refs.freshness_ref,
        StorageIntentEvidenceKind::TemporalEvidence => refs.temporal_ref,
        StorageIntentEvidenceKind::MetadataNamespaceEvidence => refs.namespace_generation_ref,
        StorageIntentEvidenceKind::LayoutAllocatorEvidence => refs.layout_allocator_ref,
        StorageIntentEvidenceKind::PlacementReceipt => refs.placement_receipt_ref,
        StorageIntentEvidenceKind::OrderingEvidence => refs.cache_fence_ref,
        StorageIntentEvidenceKind::DataShapeEvidence => refs.data_shape_ref,
        StorageIntentEvidenceKind::MembershipEvidence => refs.membership_epoch_ref,
        StorageIntentEvidenceKind::TransportPathEvidence => refs.transport_path_ref,
        StorageIntentEvidenceKind::TrustDomainEvidence => refs.trust_domain_ref,
        StorageIntentEvidenceKind::DecisionFrontierEvidence => refs.prefetch_decision_ref,
        StorageIntentEvidenceKind::PolicyRolloutEvidence => refs.policy_rollout_ref,
        StorageIntentEvidenceKind::TenantIsolationEvidence => refs.tenant_isolation_ref,
        StorageIntentEvidenceKind::ServiceObjectiveEvidence => refs.service_objective_ref,
        StorageIntentEvidenceKind::CapacityAdmissionEvidence => refs.capacity_admission_ref,
        _ => evidence_ref(kind, 90),
    }
}

fn read_serving_policy(profile: ReadFreshnessProfile) -> ReadServingPolicy {
    ReadServingPolicy {
        policy_id: POLICY_ID,
        policy_revision: POLICY_REVISION,
        freshness_profile: profile,
        required_object_generation: 0,
        required_namespace_generation: 0,
        required_layout_generation: 0,
        required_snapshot_generation: 0,
        max_remote_lag_ms: 0,
        degraded_read_policy: DegradedReadPolicy::ServeWhenVerified,
        allow_cache_only: matches!(profile, ReadFreshnessProfile::CacheOnlyAcceleration),
        allow_serving_trial: matches!(profile, ReadFreshnessProfile::CacheOnlyAcceleration),
        allow_read_repair: false,
        repair_requires_reserve: true,
        require_digest_verification: true,
    }
}

fn read_serving_snapshot(
    policy: ReadServingPolicy,
    refs: ReadServingEvidenceRefs,
    families: &[StorageIntentEvidenceKind],
) -> tidefs_storage_intent_core::StorageIntentEvidenceQuerySnapshot {
    let mut included_refs = CoreEvidenceRefs::EMPTY;
    let mut family_freshness = EvidenceFamilyFreshnessSet::EMPTY;
    for &kind in families {
        let evidence = family_ref(kind, refs);
        included_refs
            .push(evidence)
            .expect("push included evidence");
        family_freshness
            .push(EvidenceFamilyFreshness {
                kind,
                state: EvidenceFamilyFreshnessState::Fresh,
                source_index_generation: 1,
                producer_generation: 1,
                freshness_frontier_ms: 1000,
                allowed_staleness_ms: 0,
                evidence_ref: evidence,
            })
            .expect("push family freshness");
    }

    tidefs_storage_intent_core::StorageIntentEvidenceQuerySnapshot {
        snapshot_id: StorageIntentEvidenceId([0x71; 32]),
        query_id: StorageIntentEvidenceId([0x72; 32]),
        consumer: EvidenceConsumerClass::ReadPath,
        context: EvidenceQueryContextClass::ReadServing,
        subject: EvidenceQuerySubjectScope {
            scope_class: EvidenceQuerySubjectScopeClass::ObjectRange,
            object_scope: StorageIntentObjectScope {
                dataset_id: DATASET_ID,
                object_id: OBJECT_ID,
                range_start: 0,
                range_len: 0,
                generation: 1,
            },
            pool_id: StorageIntentDomainId::ZERO,
            domain_id: StorageIntentDomainId::ZERO,
            request_ref: StorageIntentEvidenceRef::default(),
            action_ref: StorageIntentEvidenceRef::default(),
            validation_ref: StorageIntentEvidenceRef::default(),
        },
        policy_id: policy.policy_id,
        policy_revision: policy.policy_revision,
        temporal_frontier_ms: 1000,
        freshness_frontier_ms: 1000,
        allowed_staleness_ms: 0,
        source_catalog_ref: evidence_ref(StorageIntentEvidenceKind::EvidenceQuerySnapshot, 73),
        source_index_ref: evidence_ref(StorageIntentEvidenceKind::EvidenceQuerySnapshot, 74),
        source_index_generation: 1,
        producer_generation: 1,
        producer_watermark_ms: 1000,
        compaction_generation: 0,
        redaction_generation: 0,
        included_refs,
        family_freshness,
        completeness: EvidenceCompletenessVerdict::CompleteForPurpose,
        retention: EvidenceRetentionClass::ExactRequired,
        retention_ref: evidence_ref(StorageIntentEvidenceKind::EvidenceRetentionEvidence, 75),
        refusal: StorageIntentRefusalReason::None,
    }
}

fn read_serving_input(source: StorageIntentReadSourceClass) -> ReadServingDecisionInput {
    let policy = read_serving_policy(ReadFreshnessProfile::LatestLocal);
    let refs = read_serving_refs();
    let families = [
        StorageIntentEvidenceKind::LocalIntentRecord,
        StorageIntentEvidenceKind::ReadFreshnessEvidence,
        StorageIntentEvidenceKind::TemporalEvidence,
        StorageIntentEvidenceKind::PlacementReceipt,
        StorageIntentEvidenceKind::DataShapeEvidence,
        StorageIntentEvidenceKind::OrderingEvidence,
        StorageIntentEvidenceKind::TenantIsolationEvidence,
    ];

    ReadServingDecisionInput {
        policy,
        candidate: ReadServingCandidateRecord {
            policy_id: policy.policy_id,
            policy_revision: policy.policy_revision,
            source_class: source,
            source_receipt: SOURCE_RECEIPT,
            lag_known: true,
            freshness_frontier_ms: 1000,
            digest_verified: true,
            evidence_refs: refs,
            ..ReadServingCandidateRecord::default()
        },
        evidence_cut_state: ReadServingEvidenceCutState::Bound,
        evidence_query_snapshot: read_serving_snapshot(policy, refs, &families),
    }
}

// getattr after create

#[test]
fn getattr_after_create_returns_correct_file_attributes() {
    set_test_key();
    let dir = temp_dir("getattr_create");
    let payload = make_data(0xCD, 1024);

    let mut fs = open_fs(&dir);
    fs.create_file("/attr_test.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/attr_test.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    let attr = fs.stat_attr("/attr_test.bin").expect("stat_attr");
    assert_eq!(attr.kind, NodeKind::File, "inode kind is regular file");
    assert_eq!(
        attr.posix.mode & S_IFREG,
        S_IFREG,
        "mode has S_IFREG bit set"
    );
    assert_eq!(attr.posix.size, 1024, "size matches written data");
    assert!(attr.posix.nlink >= 1, "nlink is at least 1");
    assert!(attr.posix.atime_ns > 0, "atime is set");
    assert!(attr.posix.mtime_ns > 0, "mtime is set");
    assert!(attr.posix.ctime_ns > 0, "ctime is set");
    assert_ne!(attr.inode_id, InodeId(0), "inode_id is not zero");
}

#[test]
fn getattr_after_create_then_reopen_preserves_attributes() {
    set_test_key();
    let dir = temp_dir("getattr_reopen");
    let payload = b"persistent attr check".to_vec();

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/persist.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/persist.bin", 0, &payload).expect("write");
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let attr = fs
            .stat_attr("/persist.bin")
            .expect("stat_attr after reopen");
        assert_eq!(attr.kind, NodeKind::File);
        assert_eq!(attr.posix.size, payload.len() as u64);
        assert!(attr.posix.nlink >= 1);
    }
}

// getattr on empty file

#[test]
fn getattr_on_empty_file_returns_zero_size() {
    set_test_key();
    let dir = temp_dir("getattr_empty");

    let mut fs = open_fs(&dir);
    fs.create_file("/empty.dat", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.sync_all().expect("sync");

    let attr = fs.stat_attr("/empty.dat").expect("stat_attr");
    assert_eq!(attr.kind, NodeKind::File);
    assert_eq!(attr.posix.size, 0, "empty file has size 0");
    assert!(attr.posix.nlink >= 1);
}

// lookup existing file

#[test]
fn lookup_existing_file_returns_valid_inode_id() {
    set_test_key();
    let dir = temp_dir("lookup_exist");

    let mut fs = open_fs(&dir);
    fs.create_file("/target.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.sync_all().expect("sync");

    let ino = fs.lookup("/target.bin").expect("lookup existing file");
    assert_ne!(ino, InodeId(0), "lookup returns non-zero inode");

    let attr = fs.stat_attr("/target.bin").expect("stat_attr");
    assert_eq!(ino, attr.inode_id, "lookup inode matches stat_attr inode");
}

#[test]
fn lookup_existing_file_in_subdirectory() {
    set_test_key();
    let dir = temp_dir("lookup_subdir");

    let mut fs = open_fs(&dir);
    fs.create_dir("/sub", 0o755).expect("create dir");
    fs.create_file("/sub/nested.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create nested");
    fs.sync_all().expect("sync");

    let ino = fs.lookup("/sub/nested.bin").expect("lookup nested file");
    assert_ne!(ino, InodeId(0));

    let attr = fs.stat_attr("/sub/nested.bin").expect("stat_attr nested");
    assert_eq!(ino, attr.inode_id);
    assert_eq!(attr.kind, NodeKind::File);
}

// lookup nonexistent

#[test]
fn lookup_nonexistent_file_returns_error() {
    set_test_key();
    let dir = temp_dir("lookup_enoent");

    let fs = open_fs(&dir);
    let result = fs.lookup("/no_such_file.txt");
    assert!(result.is_err(), "lookup nonexistent must fail");
}

#[test]
fn lookup_nonexistent_in_populated_filesystem() {
    set_test_key();
    let dir = temp_dir("lookup_enoent_populated");

    let mut fs = open_fs(&dir);
    fs.create_file("/real.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create real");
    fs.sync_all().expect("sync");

    assert!(fs.lookup("/real.bin").is_ok());
    assert!(fs.lookup("/not_here.bin").is_err());
    assert!(fs.lookup("/real.bin/sub").is_err());
}

// getattr on nonexistent

#[test]
fn getattr_on_nonexistent_file_returns_error() {
    set_test_key();
    let dir = temp_dir("getattr_enoent");

    let fs = open_fs(&dir);
    let result = fs.stat_attr("/ghost.dat");
    assert!(result.is_err(), "getattr on nonexistent must fail");
}

// Read edge cases

#[test]
fn read_file_range_past_eof_returns_empty() {
    set_test_key();
    let dir = temp_dir("read_past_eof");
    let payload = make_data(0x5A, 256);

    let mut fs = open_fs(&dir);
    fs.create_file("/short.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/short.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    let past = fs
        .read_file_range("/short.bin", 512, 64)
        .expect("read past eof");
    assert!(past.is_empty(), "read past EOF returns empty");

    let spanning = fs
        .read_file_range("/short.bin", 128, 256)
        .expect("read spanning eof");
    assert_eq!(
        spanning.len(),
        128,
        "read spanning EOF truncates at file end"
    );
    assert_eq!(&spanning[..], &payload[128..256]);
}

#[test]
fn read_file_range_at_zero_len_returns_empty() {
    set_test_key();
    let dir = temp_dir("read_zero_len");
    let payload = make_data(0x7E, 1024);

    let mut fs = open_fs(&dir);
    fs.create_file("/data.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/data.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    let chunk = fs
        .read_file_range("/data.bin", 64, 0)
        .expect("read zero len");
    assert!(chunk.is_empty(), "zero-length read returns empty");
}

#[test]
fn read_serving_missing_evidence_cut_refuses_without_bytes() {
    set_test_key();
    let dir = temp_dir("rs_missing_cut");
    let payload = make_data(0x33, 512);

    let mut fs = open_fs(&dir);
    fs.create_file("/gated.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/gated.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    let result = fs
        .read_file_range_with_read_serving(
            "/gated.bin",
            0,
            payload.len(),
            ReadServingDecisionInput::default(),
        )
        .expect("read-serving decision");

    assert!(result.bytes.is_none(), "missing cut must not serve bytes");
    assert_eq!(
        result.decision.requested_source,
        StorageIntentReadSourceClass::LocalPlacementReceipt
    );
    assert_eq!(
        result.decision.decision_state,
        ReadServingDecisionState::Unavailable
    );
    assert_eq!(
        result.decision.rejected_reasons,
        ReadServingRejectionMask::MISSING_EVIDENCE_CUT
    );
}

#[test]
fn read_serving_clean_cache_refuses_latest_local_authority() {
    set_test_key();
    let dir = temp_dir("rs_clean_cache");
    let payload = make_data(0x44, 768);

    let mut fs = open_fs(&dir);
    fs.create_file("/cache.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/cache.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    let result = fs
        .read_file_range_with_read_serving(
            "/cache.bin",
            0,
            payload.len(),
            read_serving_input(StorageIntentReadSourceClass::CleanCache),
        )
        .expect("read-serving decision");

    assert!(result.bytes.is_none(), "clean cache is acceleration only");
    assert_eq!(
        result.decision.requested_source,
        StorageIntentReadSourceClass::CleanCache
    );
    assert_eq!(
        result.decision.decision_state,
        ReadServingDecisionState::Refused
    );
    assert_eq!(
        result.decision.refusal,
        StorageIntentRefusalReason::CacheCannotBeAuthority
    );
    assert!(result
        .decision
        .rejected_reasons
        .intersects(ReadServingRejectionMask::CACHE_CANNOT_BE_AUTHORITY));
}

#[test]
fn read_serving_stale_evidence_cut_refuses_without_bytes() {
    set_test_key();
    let dir = temp_dir("rs_stale_cut");
    let payload = make_data(0x55, 1024);

    let mut fs = open_fs(&dir);
    fs.create_file("/stale.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/stale.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    let mut input = read_serving_input(StorageIntentReadSourceClass::LocalPlacementReceipt);
    input.evidence_cut_state = ReadServingEvidenceCutState::Stale;
    let result = fs
        .read_file_range_with_read_serving("/stale.bin", 0, payload.len(), input)
        .expect("read-serving decision");

    assert!(result.bytes.is_none(), "stale cut must not serve bytes");
    assert_eq!(
        result.decision.decision_state,
        ReadServingDecisionState::Unavailable
    );
    assert_eq!(
        result.decision.evidence_cut_state,
        ReadServingEvidenceCutState::Stale
    );
    assert_eq!(
        result.decision.rejected_reasons,
        ReadServingRejectionMask::MISSING_EVIDENCE_CUT
    );
}

#[test]
fn read_serving_required_range_maps_missing_cut_to_typed_error() {
    set_test_key();
    let dir = temp_dir("rs_required_missing_cut");
    let payload = make_data(0x57, 640);

    let mut fs = open_fs(&dir);
    fs.create_file("/required.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/required.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    let err = fs
        .read_file_range_with_required_read_serving(
            "/required.bin",
            0,
            payload.len(),
            ReadServingDecisionInput::default(),
        )
        .expect_err("missing evidence cut refuses byte-serving read");

    let decision = match err {
        FileSystemError::ReadServingRefused { decision } => decision,
        other => panic!("unexpected read-serving error: {other:?}"),
    };
    assert_eq!(
        decision.decision_state,
        ReadServingDecisionState::Unavailable
    );
    assert_eq!(
        decision.requested_source,
        StorageIntentReadSourceClass::LocalPlacementReceipt
    );
    assert_eq!(
        decision.rejected_reasons,
        ReadServingRejectionMask::MISSING_EVIDENCE_CUT
    );
}

#[test]
fn read_serving_required_range_maps_clean_cache_refusal_to_typed_error() {
    set_test_key();
    let dir = temp_dir("rs_required_clean_cache");
    let payload = make_data(0x59, 896);

    let mut fs = open_fs(&dir);
    fs.create_file("/cache-required.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/cache-required.bin", 0, &payload)
        .expect("write");
    fs.sync_all().expect("sync");

    let err = fs
        .read_file_range_with_required_read_serving(
            "/cache-required.bin",
            0,
            payload.len(),
            read_serving_input(StorageIntentReadSourceClass::CleanCache),
        )
        .expect_err("clean cache cannot satisfy latest-local byte read");

    let decision = match err {
        FileSystemError::ReadServingRefused { decision } => decision,
        other => panic!("unexpected read-serving error: {other:?}"),
    };
    assert_eq!(decision.decision_state, ReadServingDecisionState::Refused);
    assert_eq!(
        decision.refusal,
        StorageIntentRefusalReason::CacheCannotBeAuthority
    );
    assert!(decision
        .rejected_reasons
        .intersects(ReadServingRejectionMask::CACHE_CANNOT_BE_AUTHORITY));
}

#[test]
fn read_serving_required_range_maps_stale_cut_to_typed_error() {
    set_test_key();
    let dir = temp_dir("rs_required_stale_cut");
    let payload = make_data(0x5B, 1152);

    let mut fs = open_fs(&dir);
    fs.create_file("/stale-required.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/stale-required.bin", 0, &payload)
        .expect("write");
    fs.sync_all().expect("sync");

    let mut input = read_serving_input(StorageIntentReadSourceClass::LocalPlacementReceipt);
    input.evidence_cut_state = ReadServingEvidenceCutState::Stale;
    let err = fs
        .read_file_range_with_required_read_serving("/stale-required.bin", 0, payload.len(), input)
        .expect_err("stale evidence cut refuses byte-serving read");

    let decision = match err {
        FileSystemError::ReadServingRefused { decision } => decision,
        other => panic!("unexpected read-serving error: {other:?}"),
    };
    assert_eq!(
        decision.decision_state,
        ReadServingDecisionState::Unavailable
    );
    assert_eq!(
        decision.evidence_cut_state,
        ReadServingEvidenceCutState::Stale
    );
}

#[test]
fn read_serving_local_receipt_projection_serves_and_preserves_refs() {
    set_test_key();
    let dir = temp_dir("rs_local_receipt");
    let payload = make_data(0x66, 2048);

    let mut fs = open_fs(&dir);
    fs.create_file("/receipt.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/receipt.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    let input = read_serving_input(StorageIntentReadSourceClass::LocalPlacementReceipt);
    let placement_ref = input.candidate.evidence_refs.placement_receipt_ref;
    let result = fs
        .read_file_range_with_read_serving("/receipt.bin", 128, 512, input)
        .expect("read-serving decision");

    assert_eq!(result.served_bytes(), Some(&payload[128..640]));
    assert_eq!(
        result.decision.decision_state,
        ReadServingDecisionState::Available
    );
    assert_eq!(
        result.decision.chosen_source,
        StorageIntentReadSourceClass::LocalPlacementReceipt
    );
    assert_eq!(result.decision.source_receipt, SOURCE_RECEIPT);
    assert_eq!(
        result.decision.evidence_refs.placement_receipt_ref,
        placement_ref
    );
    assert_eq!(result.decision.scope.range_start, 128);
    assert_eq!(result.decision.scope.range_len, 512);
    assert!(result.decision.object_generation > 0);
    assert!(result.decision.layout_generation > 0);
}

#[test]
fn read_serving_required_full_read_serves_receipt_backed_bytes() {
    set_test_key();
    let dir = temp_dir("rs_required_local_receipt");
    let payload = make_data(0x67, 1536);

    let mut fs = open_fs(&dir);
    fs.create_file("/receipt-required.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/receipt-required.bin", 0, &payload)
        .expect("write");
    fs.sync_all().expect("sync");

    let bytes = fs
        .read_file_with_required_read_serving(
            "/receipt-required.bin",
            read_serving_input(StorageIntentReadSourceClass::LocalPlacementReceipt),
        )
        .expect("receipt-backed read-serving source");

    assert_eq!(bytes, payload);
}

// ── Full-file sequential read ─────────────────────────────────────────

#[test]
fn full_file_sequential_read_byte_for_byte() {
    set_test_key();
    let dir = temp_dir("seq_read");
    let payload = make_data(0x5A, 4096);

    let mut fs = open_fs(&dir);
    fs.create_file("/seq.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/seq.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    let result = fs.read_file("/seq.bin").expect("read full file");
    assert_eq!(result.len(), 4096, "full file length matches");
    assert_eq!(result, payload, "byte-for-byte match");
}

#[test]
fn full_file_sequential_read_in_chunks() {
    set_test_key();
    let dir = temp_dir("chunk_read");
    let payload = make_data(0x3C, 16384); // 16 KiB

    let mut fs = open_fs(&dir);
    fs.create_file("/chunks.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/chunks.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    let mut assembled = Vec::new();
    let mut offset = 0u64;
    loop {
        let chunk = fs
            .read_file_range("/chunks.bin", offset, 4096)
            .expect("read chunk");
        if chunk.is_empty() {
            break;
        }
        assembled.extend_from_slice(&chunk);
        offset += chunk.len() as u64;
    }
    assert_eq!(assembled, payload, "chunked assembly matches original");
}

// ── Partial read at offset ────────────────────────────────────────────

#[test]
fn partial_read_at_offset_returns_correct_slice() {
    set_test_key();
    let dir = temp_dir("partial");
    let payload = make_data(0x7B, 65536); // 64 KiB

    let mut fs = open_fs(&dir);
    fs.create_file("/partial.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/partial.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    // Read 17 bytes at offset 8193
    let slice = fs
        .read_file_range("/partial.bin", 8193, 17)
        .expect("read partial");
    assert_eq!(slice.len(), 17);
    assert_eq!(&slice[..], &payload[8193..8210]);
}

#[test]
fn partial_read_at_multiple_offsets() {
    set_test_key();
    let dir = temp_dir("multi_off");
    let payload = make_data(0x11, 4096);

    let mut fs = open_fs(&dir);
    fs.create_file("/offsets.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/offsets.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    for off in [0u64, 1, 512, 4095, 2048] {
        let want = &payload[off as usize..];
        let got = fs
            .read_file_range("/offsets.bin", off, (4096 - off) as usize)
            .expect("read at offset");
        assert_eq!(got, want, "mismatch at offset {off}");
    }
}

// ── Read spanning segment boundaries ───────────────────────────────────

#[test]
fn read_spanning_segment_boundaries() {
    set_test_key();
    let dir = temp_dir("seg_bound");
    // Write enough data to force multiple object-store segments.
    // The segment size in tidefs-local-object-store defaults to
    // SEGMENT_CAPACITY_BYTES; 128 KiB should span at least two segments.
    let payload = make_data(0xA1, 131072); // 128 KiB

    let mut fs = open_fs(&dir);
    fs.create_file("/span.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/span.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    // Read the full file to verify assembly
    let full = fs.read_file("/span.bin").expect("read full");
    assert_eq!(full, payload, "full-file assembly across segments");

    // Read a chunk that straddles the typical 64 KiB segment boundary
    let boundary = 65535; // one byte before 64 KiB
    let straddle = fs
        .read_file_range("/span.bin", boundary, 128)
        .expect("read straddle");
    assert_eq!(straddle.len(), 128);
    assert_eq!(
        &straddle[..],
        &payload[boundary as usize..(boundary as usize + 128)]
    );
}

// ── Concurrent reads ───────────────────────────────────────────────────

#[test]
fn concurrent_reads_disjoint_ranges() {
    set_test_key();
    let dir = temp_dir("concurrent");
    let payload = make_data(0x42, 16384); // 16 KiB, 4 pages

    let mut fs = open_fs(&dir);
    fs.create_file("/shared.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/shared.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    // Reopen read-only for thread safety (LocalFileSystem is not Sync,
    // so we open separate handles per thread).
    let fs_static: &'static std::path::Path = Box::leak(dir.clone().into_boxed_path());
    let payload_static: &'static [u8] = Box::leak(payload.into_boxed_slice());

    std::thread::scope(|s| {
        let handles: Vec<_> = (0..4)
            .map(|i| {
                s.spawn(move || {
                    let fs = open_fs(fs_static);
                    let off = (i * 4096) as u64;
                    let chunk = fs
                        .read_file_range("/shared.bin", off, 4096)
                        .expect("concurrent read");
                    assert_eq!(chunk.len(), 4096);
                    let expected = &payload_static[off as usize..(off as usize + 4096)];
                    assert_eq!(chunk, expected, "thread {i} mismatch");
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
    });
}

// ── Error handling: directory as file ─────────────────────────────────

#[test]
fn read_file_on_directory_returns_is_directory() {
    set_test_key();
    let dir = temp_dir("read_dir_err");

    let mut fs = open_fs(&dir);
    fs.create_dir("/mydir", 0o755).expect("create dir");
    fs.sync_all().expect("sync");

    let result = fs.read_file("/mydir");
    assert!(result.is_err(), "read_file on directory must fail");
    assert!(
        format!("{:?}", result.as_ref().err()).contains("IsDirectory")
            || format!("{:?}", result.as_ref().err()).contains("is a directory"),
        "expected IsDirectory error, got {:?}",
        result.err()
    );
}

#[test]
fn read_file_range_on_directory_returns_is_directory() {
    set_test_key();
    let dir = temp_dir("read_range_dir_err");

    let mut fs = open_fs(&dir);
    fs.create_dir("/mydir", 0o755).expect("create dir");
    fs.sync_all().expect("sync");

    let result = fs.read_file_range("/mydir", 0, 64);
    assert!(result.is_err(), "read_file_range on directory must fail");
    assert!(
        format!("{:?}", result.as_ref().err()).contains("IsDirectory")
            || format!("{:?}", result.as_ref().err()).contains("is a directory"),
        "expected IsDirectory error, got {:?}",
        result.err()
    );
}

#[test]
fn read_file_on_nonexistent_path_returns_error() {
    set_test_key();
    let dir = temp_dir("read_enoent");

    let fs = open_fs(&dir);
    let result = fs.read_file("/no_such_file.bin");
    assert!(result.is_err(), "read_file on nonexistent must fail");
}

#[test]
fn read_file_range_on_nonexistent_path_returns_error() {
    set_test_key();
    let dir = temp_dir("read_range_enoent");

    let fs = open_fs(&dir);
    let result = fs.read_file_range("/ghost.bin", 0, 64);
    assert!(result.is_err(), "read_file_range on nonexistent must fail");
}

// ── Overwrite + read-back ─────────────────────────────────────────────

#[test]
fn overwrite_middle_portion_and_read_back() {
    set_test_key();
    let dir = temp_dir("overwrite_mid");
    let original = make_data(0x11, 8192);
    let replacement = make_data(0xFF, 512);

    let mut fs = open_fs(&dir);
    fs.create_file("/over.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/over.bin", 0, &original).expect("write");
    fs.sync_all().expect("sync");

    // Overwrite 512 bytes starting at offset 2048
    fs.write_file("/over.bin", 2048, &replacement)
        .expect("overwrite");
    fs.sync_all().expect("sync");

    let result = fs.read_file("/over.bin").expect("read back");
    assert_eq!(result.len(), 8192);
    // First 2048 bytes unchanged
    assert_eq!(&result[..2048], &original[..2048]);
    // Overwritten region
    assert_eq!(&result[2048..2560], &replacement[..]);
    // Remainder unchanged
    assert_eq!(&result[2560..], &original[2560..]);
}

#[test]
fn overwrite_at_file_end_and_read_back() {
    set_test_key();
    let dir = temp_dir("overwrite_end");
    let original = make_data(0x22, 4096);
    let extension = make_data(0xAA, 2048);

    let mut fs = open_fs(&dir);
    fs.create_file("/extend.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/extend.bin", 0, &original).expect("write");
    fs.sync_all().expect("sync");

    // Write at offset 4096 (exact end — extends the file)
    fs.write_file("/extend.bin", 4096, &extension)
        .expect("extend");
    fs.sync_all().expect("sync");

    let result = fs.read_file("/extend.bin").expect("read back");
    assert_eq!(result.len(), 4096 + 2048);
    assert_eq!(&result[..4096], &original[..]);
    assert_eq!(&result[4096..], &extension[..]);
}

// ── Truncate + read-back ──────────────────────────────────────────────

#[test]
fn truncate_shorter_and_read_back() {
    set_test_key();
    let dir = temp_dir("truncate_shorter");
    let payload = make_data(0x33, 8192);

    let mut fs = open_fs(&dir);
    fs.create_file("/trunc.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/trunc.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    fs.truncate_file("/trunc.bin", 2048).expect("truncate");
    fs.sync_all().expect("sync");

    let result = fs.read_file("/trunc.bin").expect("read truncated");
    assert_eq!(result.len(), 2048);
    assert_eq!(&result[..], &payload[..2048]);

    // Read past the new EOF should return empty
    let past = fs
        .read_file_range("/trunc.bin", 4096, 64)
        .expect("read past new eof");
    assert!(past.is_empty());
}

#[test]
fn truncate_to_zero_and_read_back() {
    set_test_key();
    let dir = temp_dir("truncate_zero");
    let payload = make_data(0x44, 4096);

    let mut fs = open_fs(&dir);
    fs.create_file("/zero.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/zero.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    fs.truncate_file("/zero.bin", 0).expect("truncate to zero");
    fs.sync_all().expect("sync");

    let result = fs.read_file("/zero.bin").expect("read truncated");
    assert!(result.is_empty(), "truncated to zero must be empty");
}

// ── Unaligned / small reads ───────────────────────────────────────────

#[test]
fn read_unaligned_sizes_byte_for_byte() {
    set_test_key();
    let dir = temp_dir("unaligned");
    // Use prime-sized data to avoid accidental alignment
    let payload = make_data(0x55, 7919); // prime-sized

    let mut fs = open_fs(&dir);
    fs.create_file("/unaligned.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/unaligned.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    // Read with various sizes that cross chunk boundaries
    for read_len in [1usize, 511, 512, 513, 1023, 1024, 4095, 4096, 4097] {
        let chunk = fs
            .read_file_range("/unaligned.bin", 0, read_len)
            .expect("read unaligned");
        let expected_len = read_len.min(7919);
        assert_eq!(
            chunk.len(),
            expected_len,
            "length mismatch for len={read_len}"
        );
        assert_eq!(
            &chunk[..],
            &payload[..expected_len],
            "data mismatch for len={read_len}"
        );
    }
}

#[test]
fn read_unaligned_offsets_with_varying_lengths() {
    set_test_key();
    let dir = temp_dir("unaligned_off");
    let payload = make_data(0x66, 16384);

    let mut fs = open_fs(&dir);
    fs.create_file("/offlen.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/offlen.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    // Vary both offset and length, hitting chunk boundaries
    let cases: &[(u64, usize)] = &[
        (0, 1),
        (1, 511),
        (0, 512),
        (512, 512),
        (511, 2),
        (4095, 2),
        (4095, 512),
        (4096, 1),
        (4096, 4096),
        (8191, 2),
        (8192, 1),
        (16383, 1),
        (1024, 1337), // straddles multiple chunks
    ];
    for &(off, len) in cases {
        let want = &payload[off as usize..(off as usize + len).min(payload.len())];
        let got = fs
            .read_file_range("/offlen.bin", off, len)
            .expect("read at offset/length");
        assert_eq!(got, want, "mismatch at offset={off} len={len}");
    }
}

// ── Read at exact file boundary ───────────────────────────────────────

#[test]
fn read_at_exact_end_of_file_returns_empty() {
    set_test_key();
    let dir = temp_dir("exact_end");
    let payload = make_data(0x77, 4096);

    let mut fs = open_fs(&dir);
    fs.create_file("/end.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/end.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    // Read starting exactly at file size
    let end = fs
        .read_file_range("/end.bin", 4096, 64)
        .expect("read at exact end");
    assert!(end.is_empty(), "read at exact EOF returns empty");
}

#[test]
fn read_last_byte_of_file() {
    set_test_key();
    let dir = temp_dir("last_byte");
    let payload = make_data(0x88, 4096);

    let mut fs = open_fs(&dir);
    fs.create_file("/last.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/last.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    let last = fs
        .read_file_range("/last.bin", 4095, 1)
        .expect("read last byte");
    assert_eq!(last.len(), 1);
    assert_eq!(last[0], payload[4095]);
}

// ── Multiple writes, single read ──────────────────────────────────────

#[test]
fn scattered_writes_single_read_back() {
    set_test_key();
    let dir = temp_dir("scattered");
    let chunk_a = make_data(0xA1, 1024);
    let chunk_b = make_data(0xB2, 1024);
    let chunk_c = make_data(0xC3, 1024);

    let mut fs = open_fs(&dir);
    fs.create_file("/scattered.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    // Write non-contiguous chunks, leaving holes
    fs.write_file("/scattered.bin", 0, &chunk_a)
        .expect("write A");
    fs.write_file("/scattered.bin", 4096, &chunk_b)
        .expect("write B");
    fs.write_file("/scattered.bin", 8192, &chunk_c)
        .expect("write C");
    fs.sync_all().expect("sync");

    // Full read should return zeros for the holes
    let result = fs.read_file("/scattered.bin").expect("read back");
    assert_eq!(result.len(), 8192 + 1024);
    assert_eq!(&result[..1024], &chunk_a[..]);
    assert_eq!(&result[1024..4096], &vec![0u8; 3072][..]);
    assert_eq!(&result[4096..5120], &chunk_b[..]);
    assert_eq!(&result[5120..8192], &vec![0u8; 3072][..]);
    assert_eq!(&result[8192..], &chunk_c[..]);
}

// ── Concurrent read of same range ─────────────────────────────────────

#[test]
fn concurrent_reads_same_range() {
    set_test_key();
    let dir = temp_dir("concurrent_same");
    let payload = make_data(0x99, 8192);

    let mut fs = open_fs(&dir);
    fs.create_file("/same.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/same.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    let fs_static: &'static std::path::Path = Box::leak(dir.clone().into_boxed_path());
    let payload_static: &'static [u8] = Box::leak(payload.into_boxed_slice());

    std::thread::scope(|s| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                s.spawn(move || {
                    let fs = open_fs(fs_static);
                    // All threads read the exact same range
                    let chunk = fs
                        .read_file_range("/same.bin", 1024, 4096)
                        .expect("concurrent same-range read");
                    assert_eq!(chunk.len(), 4096);
                    let expected = &payload_static[1024..1024 + 4096];
                    assert_eq!(chunk, expected);
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
    });
}

// ── Read spanning many chunks ─────────────────────────────────────────

#[test]
fn read_spanning_many_chunks() {
    set_test_key();
    let dir = temp_dir("many_chunks");
    // 256 KiB — should span at least 4 chunks (chunk size is 64 KiB default)
    let payload = make_data(0xEE, 262144);

    let mut fs = open_fs(&dir);
    fs.create_file("/many.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/many.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    // Full file read
    let full = fs.read_file("/many.bin").expect("read full");
    assert_eq!(full, payload, "full file across many chunks");

    // Read a range that spans 3+ chunks
    let straddle = fs
        .read_file_range("/many.bin", 65000, 70000)
        .expect("read straddle");
    assert_eq!(straddle.len(), 70000);
    assert_eq!(&straddle[..], &payload[65000..65000 + 70000]);

    // Read crossing exact chunk boundaries at 64 KiB, 128 KiB, 192 KiB
    for boundary in [65535u64, 131071, 196607] {
        let cross = fs
            .read_file_range("/many.bin", boundary, 4)
            .expect("read across chunk boundary");
        let end = (boundary as usize + 4).min(payload.len());
        assert_eq!(cross.len(), end - boundary as usize);
        assert_eq!(&cross[..], &payload[boundary as usize..end]);
    }
}

// ── Single-byte reads across entire file ──────────────────────────────

#[test]
fn single_byte_reads_across_entire_file() {
    set_test_key();
    let dir = temp_dir("byte_by_byte");
    let payload = make_data(0xBA, 1024);

    let mut fs = open_fs(&dir);
    fs.create_file("/bytes.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/bytes.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    // Verify every single byte is individually readable
    for (i, &expected) in payload.iter().enumerate() {
        let byte = fs
            .read_file_range("/bytes.bin", i as u64, 1)
            .expect("read single byte");
        assert_eq!(byte.len(), 1, "single byte at offset {i}");
        assert_eq!(byte[0], expected, "byte mismatch at offset {i}");
    }
}

// ── Empty file read ──────────────────────────────────────────────────

#[test]
fn read_empty_file_returns_zero_bytes() {
    set_test_key();
    let dir = temp_dir("read_empty");

    let mut fs = open_fs(&dir);
    fs.create_file("/empty.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create empty");
    fs.sync_all().expect("sync");

    let result = fs.read_file("/empty.bin").expect("read empty file");
    assert!(
        result.is_empty(),
        "read_file on empty file returns empty vec"
    );
}

#[test]
fn read_empty_file_range_returns_zero_bytes() {
    set_test_key();
    let dir = temp_dir("read_empty_range");

    let mut fs = open_fs(&dir);
    fs.create_file("/empty.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create empty");
    fs.sync_all().expect("sync");

    // Read at offset 0 with positive length on an empty file
    let result = fs
        .read_file_range("/empty.bin", 0, 64)
        .expect("read range on empty file");
    assert!(
        result.is_empty(),
        "read_file_range on empty file returns empty vec"
    );

    // Read at offset 1024 on an empty file
    let result = fs
        .read_file_range("/empty.bin", 1024, 64)
        .expect("read range past empty file");
    assert!(result.is_empty());
}

// ── Read after unlink ────────────────────────────────────────────────

#[test]
fn read_after_unlink_returns_error() {
    set_test_key();
    let dir = temp_dir("unlink_read");

    let mut fs = open_fs(&dir);
    fs.create_file("/unlink_me.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/unlink_me.bin", 0, &make_data(0xAA, 1024))
        .expect("write");
    fs.sync_all().expect("sync");

    // Verify file is readable before unlink
    let before = fs.read_file("/unlink_me.bin").expect("read before unlink");
    assert!(!before.is_empty());

    fs.unlink("/unlink_me.bin").expect("unlink");
    fs.sync_all().expect("sync");

    let result = fs.read_file("/unlink_me.bin");
    assert!(result.is_err(), "read after unlink must fail");
}

#[test]
fn read_range_after_unlink_returns_error() {
    set_test_key();
    let dir = temp_dir("unlink_range_read");

    let mut fs = open_fs(&dir);
    fs.create_file("/unlink_range.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/unlink_range.bin", 0, &make_data(0xBB, 2048))
        .expect("write");
    fs.sync_all().expect("sync");

    fs.unlink("/unlink_range.bin").expect("unlink");
    fs.sync_all().expect("sync");

    let result = fs.read_file_range("/unlink_range.bin", 0, 64);
    assert!(result.is_err(), "read_file_range after unlink must fail");
}

#[test]
fn getattr_after_unlink_returns_error() {
    set_test_key();
    let dir = temp_dir("unlink_getattr");

    let mut fs = open_fs(&dir);
    fs.create_file("/gone.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/gone.bin", 0, &make_data(0xCC, 512))
        .expect("write");
    fs.sync_all().expect("sync");

    fs.unlink("/gone.bin").expect("unlink");
    fs.sync_all().expect("sync");

    let result = fs.stat_attr("/gone.bin");
    assert!(result.is_err(), "getattr after unlink must fail");
}

#[test]
fn lookup_after_unlink_returns_error() {
    set_test_key();
    let dir = temp_dir("unlink_lookup");

    let mut fs = open_fs(&dir);
    fs.create_file("/vanish.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.sync_all().expect("sync");

    let ino = fs.lookup("/vanish.bin").expect("lookup before unlink");
    assert_ne!(ino, InodeId(0));

    fs.unlink("/vanish.bin").expect("unlink");
    fs.sync_all().expect("sync");

    let result = fs.lookup("/vanish.bin");
    assert!(result.is_err(), "lookup after unlink must fail");
}

// ── Read consistency through fresh filesystem reopen ─────────────────

#[test]
fn read_consistency_through_fresh_open() {
    set_test_key();
    let dir = temp_dir("fresh_open");
    let payload = make_data(0x77, 4096);

    // Write and sync
    {
        let mut fs = open_fs(&dir);
        fs.create_file("/fresh.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/fresh.bin", 0, &payload).expect("write");
        fs.sync_all().expect("sync");
    }

    // Open a completely fresh filesystem handle and read back
    {
        let fs = open_fs(&dir);
        let result = fs.read_file("/fresh.bin").expect("read via fresh handle");
        assert_eq!(result.len(), payload.len());
        assert_eq!(result, payload, "byte-for-byte match through fresh open");
    }
}

#[test]
fn read_consistency_range_through_fresh_open() {
    set_test_key();
    let dir = temp_dir("fresh_range");
    let payload = make_data(0x88, 8192);

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/fresh2.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/fresh2.bin", 0, &payload).expect("write");
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        // Read a partial range through the fresh handle
        let slice = fs
            .read_file_range("/fresh2.bin", 2048, 4096)
            .expect("partial read via fresh handle");
        assert_eq!(slice.len(), 4096);
        assert_eq!(&slice[..], &payload[2048..2048 + 4096]);
    }
}

#[test]
fn read_consistency_after_small_write_through_fresh_open() {
    set_test_key();
    let dir = temp_dir("small_write_consistency");
    let payload = b"small payload for consistency check";

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/small.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/small.bin", 0, payload).expect("write");
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let result = fs.read_file("/small.bin").expect("read small payload back");
        assert_eq!(
            result,
            payload.to_vec(),
            "small payload byte-for-byte match"
        );
    }
}
