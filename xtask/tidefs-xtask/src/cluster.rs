// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct ClusterCheckError {
    missing: Vec<String>,
}

impl fmt::Display for ClusterCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "cluster membership epoch check failed:")?;
        for item in &self.missing {
            writeln!(f, "- {item}")?;
        }
        Ok(())
    }
}

pub fn check_membership_epoch_model_current_workspace() -> Result<(), ClusterCheckError> {
    let root = find_workspace_root().ok_or_else(|| ClusterCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "Cargo.toml",
        "crates/tidefs-membership-epoch/Cargo.toml",
        "crates/tidefs-membership-epoch/src/lib.rs",
        "docs/MEMBERSHIP_AUTHORITY.md",
        "docs/MEMBERSHIP_CONFIG_QUORUM_SET_IDENTITY_OW302B.md",
        "nix/tidefs-validation.sh",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "Cargo.toml",
        &["crates/tidefs-membership-epoch"],
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-membership-epoch/src/lib.rs",
        &[
            "MEMBERSHIP_EPOCH_MODEL_FAMILY",
            "MEMBERSHIP_EPOCH_FAILURE_REJOIN_GATE",
            "ClusterMemberRecord",
            "MembershipConfigRecord",
            "MemberFailureDomainBindingRecord",
            "CohortPopulationRecord",
            "MembershipPlacementVerdictRecord",
            "MembershipTransitionRecord",
            "SplitBrainHazardRecord",
            "inventory_members_and_classify_participation_roles",
            "bind_member_to_failure_domain_vector",
            "synthesize_membership_config_epoch_and_quorum_sets",
            "populate_transport_session_cohorts_from_membership_epoch",
            "derive_authority_home_and_failover_successor_candidates",
            "derive_replica_targets_from_failure_domain_policy",
            "evaluate_transition_catchup_and_readiness",
            "issue_membership_or_placement_verdict",
            "detect_split_brain_hazard_and_force_hold_or_quarantine",
            "control_membership_placement_failure_domain_protocol",
            "bootstrap_epoch_admits_failure_domain_separated_successor",
            "same_rack_successor_is_held_as_domain_gap",
            "split_brain_validation_refuses_ordinary_failover",
            "learner_rejoin_waits_for_catchup_then_enters_joint_config",
            "quarantined_member_is_excluded_from_cohorts_and_replica_placement",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/MEMBERSHIP_AUTHORITY.md",
        &[
            "`tidefs-membership-epoch` is the single authority owner",
            "source-owned membership, placement, and",
            "failure-domain model",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/MEMBERSHIP_CONFIG_QUORUM_SET_IDENTITY_OW302B.md",
        &["quorum set", "production cluster membership service"],
        &mut missing,
    );
    if missing.is_empty() {
        println!(
            "membership epoch model ok: epochs, failure-domain placement, split-brain refusal, cohort exclusion, and learner rejoin gates are implementation-tracked non-release"
        );
        Ok(())
    } else {
        Err(ClusterCheckError { missing })
    }
}

pub fn check_failure_domain_placement_current_workspace() -> Result<(), ClusterCheckError> {
    let root = find_workspace_root().ok_or_else(|| ClusterCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "crates/tidefs-membership-epoch/src/lib.rs",
        "docs/MEMBERSHIP_AUTHORITY.md",
        "nix/tidefs-validation.sh",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "crates/tidefs-membership-epoch/src/lib.rs",
        &[
            "AntiAffinityClass",
            "FailureDomainPlacementPolicy",
            "FailureDomainPlacementPlan",
            "FAILURE_DOMAIN_PLACEMENT_GATE_OW_303",
            "plan_failure_domain_placement_from_policy",
            "deterministic_failure_domain_policy_ignores_input_order",
            "strict_anti_affinity_holds_duplicate_domain_targets",
            "degraded_visible_policy_marks_duplicate_domain_selection",
            "ineligible_members_are_excluded_from_failure_domain_plan",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/MEMBERSHIP_AUTHORITY.md",
        &[
            "`tidefs-membership-epoch` is the single authority owner",
            "source-owned membership, placement, and",
            "failure-domain model",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!(
            "failure-domain placement ok: deterministic target choice, strict anti-affinity, degraded duplicate-domain visibility, and ineligible-member exclusion are implementation-tracked non-release"
        );
        Ok(())
    } else {
        Err(ClusterCheckError { missing })
    }
}

pub fn check_replicated_storage_model_current_workspace() -> Result<(), ClusterCheckError> {
    let root = find_workspace_root().ok_or_else(|| ClusterCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "Cargo.toml",
        "Cargo.lock",
        "crates/tidefs-replication-model/Cargo.toml",
        "crates/tidefs-replication-model/src/lib.rs",
        "docs/LOCAL_DISTRIBUTED_RECEIPT_AUTHORITY.md",
        "docs/DOCUMENTATION_AUTHORITY_REGISTER.md",
        "nix/tidefs-validation.sh",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "Cargo.toml",
        &["crates/tidefs-replication-model"],
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-replication-model/src/lib.rs",
        &[
            "ReplicatedObjectRootRecord",
            "ReplicaCopyRecord",
            "ReplicatedWritePlan",
            "ReplicatedReadPlan",
            "RebuildPlan",
            "commit_replicated_object_root_write",
            "plan_replicated_object_root_read",
            "rebuild_replicated_object_root_from_sources",
            "degraded_write_commits_with_quorum_and_records_unplaced_target",
            "write_refuses_without_replica_quorum",
            "degraded_read_uses_verified_replica_and_requests_rebuild",
            "rebuild_restores_required_failure_domain_spread",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/LOCAL_DISTRIBUTED_RECEIPT_AUTHORITY.md",
        &[
            "PlacementReceiptRef",
            "rebuild, backfill,",
            "transport models",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!(
            "replicated object/root storage ok: degraded write, degraded read, no-quorum refusal, and rebuild restoration tests are implementation-tracked non-release"
        );
        Ok(())
    } else {
        Err(ClusterCheckError { missing })
    }
}

pub fn check_rebuild_backfill_rebalance_current_workspace() -> Result<(), ClusterCheckError> {
    let root = find_workspace_root().ok_or_else(|| ClusterCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "crates/tidefs-replication-model/src/lib.rs",
        "docs/LOCAL_DISTRIBUTED_RECEIPT_AUTHORITY.md",
        "docs/STORAGE_INTENT_POLICY_AUTHORITY.md",
        "nix/tidefs-validation.sh",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "crates/tidefs-replication-model/src/lib.rs",
        &[
            "ReplicaMovementIntentRecord",
            "ReplicaCapacityRecord",
            "ReplicaMovementPlan",
            "open_rebuild_flow_from_loss_event",
            "schedule_backfill_batches_from_witness_sets",
            "plan_rebalance_for_capacity_movement",
            "rebuild_flow_restores_faulted_copy_from_verified_source",
            "rebuild_blocks_when_all_sources_are_corrupt_or_missing",
            "backfill_targets_lagged_replica_without_replacing_fresh_sources",
            "rebalance_moves_overloaded_verified_copy_to_capacity_target",
            "rebalance_blocks_when_spare_capacity_would_violate_reserve_floor",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/LOCAL_DISTRIBUTED_RECEIPT_AUTHORITY.md",
        &[
            "PlacementReceiptRef",
            "rebuild, backfill,",
            "transport models",
            "receipt reference",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!(
            "rebuild/backfill/rebalance ok: faulted-copy rebuild, lagged-copy backfill, capacity rebalance, and reserve-floor blockage are implementation-tracked non-release"
        );
        Ok(())
    } else {
        Err(ClusterCheckError { missing })
    }
}

pub fn check_erasure_coded_layout_current_workspace() -> Result<(), ClusterCheckError> {
    let root = find_workspace_root().ok_or_else(|| ClusterCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "crates/tidefs-replication-model/src/lib.rs",
        "docs/ERASURE_CODED_STORE_AUTHORITY.md",
        "nix/tidefs-validation.sh",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "crates/tidefs-replication-model/src/lib.rs",
        &[
            "ErasureLayoutPolicy",
            "ErasureShardRecord",
            "ErasureStripeRecord",
            "ErasureDecodePlan",
            "encode_single_parity_erasure_stripe",
            "decode_single_parity_erasure_stripe",
            "erasure_decode_round_trips_complete_single_parity_stripe",
            "erasure_rebuilds_one_missing_data_shard_from_parity",
            "erasure_rebuilds_missing_parity_from_data_shards",
            "erasure_refuses_when_two_data_shards_are_missing",
            "erasure_refuses_when_data_and_parity_are_missing",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/ERASURE_CODED_STORE_AUTHORITY.md",
        &[
            "`encode_single_parity_erasure_stripe()`",
            "`decode_single_parity_erasure_stripe()`",
            "data shard from parity plus the remaining data shards",
            "parity shard from data shards",
            "shards or simultaneous data/parity loss",
            "This is a model boundary consumed by the EC store authority.",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!(
            "erasure-coded layout ok: single-parity decode, data-shard rebuild, parity rebuild, and too-many-missing refusal are implementation-tracked non-release"
        );
        Ok(())
    } else {
        Err(ClusterCheckError { missing })
    }
}

fn find_workspace_root() -> Option<PathBuf> {
    let mut current = std::env::current_dir().ok()?;
    loop {
        let manifest = current.join("Cargo.toml");
        if let Ok(text) = fs::read_to_string(&manifest) {
            if text.contains("[workspace]") {
                return Some(current);
            }
        }
        if !current.pop() {
            return None;
        }
    }
}

pub fn check_chunk_shipper_current_workspace() -> Result<(), ClusterCheckError> {
    let root = find_workspace_root().ok_or_else(|| ClusterCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "Cargo.toml",
        "crates/tidefs-chunk-shipper/Cargo.toml",
        "crates/tidefs-chunk-shipper/src/lib.rs",
        "docs/LOCAL_DISTRIBUTED_RECEIPT_AUTHORITY.md",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "crates/tidefs-chunk-shipper/src/lib.rs",
        &[
            "CHUNK_SHIPPER_GATE_DATA_COPY_6",
            "data_copy_6",
            "ChunkStagingBuffer",
            "ChunkTransferProgress",
            "ChunkStagingArea",
            "ChunkShippingSession",
            "stage_replica_chunks_for_transport",
            "stream_replica_chunks_under_ticket",
            "receive_replica_chunks_and_stage_for_verification",
            "advance_chunks_after_verification",
            "ChunkShippingState",
            "ShippingSessionState",
            "ChunkShipFailure",
        ],
        &mut missing,
    );

    if missing.is_empty() {
        Ok(())
    } else {
        Err(ClusterCheckError { missing })
    }
}

pub fn check_flow_commit_coordinator_current_workspace() -> Result<(), ClusterCheckError> {
    let root = find_workspace_root().ok_or_else(|| ClusterCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "Cargo.toml",
        "crates/tidefs-flow-commit-coordinator/Cargo.toml",
        "crates/tidefs-flow-commit-coordinator/src/lib.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "crates/tidefs-flow-commit-coordinator/src/lib.rs",
        &[
            "data_copy_7",
            "FlowCommitCoordinator",
            "commit_transfer_receipt",
            "commit_verification_receipt",
            "advance_flow_after_receipt_commit",
            "seal_batch_and_emit_completion",
            "TrackedChunk",
            "TrackedBatch",
            "FLOW_COMMIT_COORDINATOR_GATE_DATA_COPY_7",
        ],
        &mut missing,
    );

    if missing.is_empty() {
        Ok(())
    } else {
        Err(ClusterCheckError { missing })
    }
}
pub fn check_extent_map_current_workspace() -> Result<(), ClusterCheckError> {
    let root = find_workspace_root().ok_or_else(|| ClusterCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "Cargo.toml",
        "crates/tidefs-extent-map/Cargo.toml",
        "crates/tidefs-extent-map/src/lib.rs",
        "crates/tidefs-extent-map/src/userspace.rs",
        "crates/tidefs-types-extent-map-core/src/lib.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "crates/tidefs-extent-map/src/userspace.rs",
        &[
            "pub struct InlineExtentMap",
            "impl ExtentMapOps for InlineExtentMap",
            "lookup_range",
            "insert_extent",
            "truncate",
            "punch_hole",
            "convert_unwritten_to_data",
            "seek_data",
            "seek_hole",
            "fiemap",
        ],
        &mut missing,
    );

    check_source_markers(
        &root,
        "crates/tidefs-types-extent-map-core/src/lib.rs",
        &[
            "pub trait ExtentMapOps",
            "EXTENT_MAP_V1_MAX_ENTRIES",
            "ExtentMapError::MapFull",
        ],
        &mut missing,
    );

    if missing.is_empty() {
        Ok(())
    } else {
        Err(ClusterCheckError { missing })
    }
}

fn check_required_file(root: &Path, rel: &str, missing: &mut Vec<String>) {
    if !root.join(rel).is_file() {
        missing.push(format!("missing required file `{rel}`"));
    }
}

fn check_source_markers(root: &Path, rel: &str, markers: &[&str], missing: &mut Vec<String>) {
    let path = root.join(rel);
    let Ok(text) = fs::read_to_string(&path) else {
        missing.push(format!("could not read `{rel}`"));
        return;
    };
    for marker in markers {
        if !text.contains(marker) {
            missing.push(format!("`{rel}` missing marker `{marker}`"));
        }
    }
}

pub fn check_locator_table_current_workspace() -> Result<(), ClusterCheckError> {
    let root = find_workspace_root().ok_or_else(|| ClusterCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "Cargo.toml",
        "crates/tidefs-locator-table/Cargo.toml",
        "crates/tidefs-locator-table/src/lib.rs",
        "crates/tidefs-locator-table/src/extent_id.rs",
        "crates/tidefs-locator-table/src/locator_table_types.rs",
        "crates/tidefs-locator-table/src/spec.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "crates/tidefs-locator-table/src/lib.rs",
        &[
            "pub struct LocatorTable",
            "pub fn lookup",
            "pub fn insert",
            "pub fn remove",
            "pub fn lookup_extent",
            "pub fn grow",
            "pub fn relocate_prepare",
            "pub fn relocate_commit",
            "#![forbid(unsafe_code)]",
            "LocatorError::NotFound",
            "LocatorError::WouldGrow",
        ],
        &mut missing,
    );

    check_source_markers(
        &root,
        "crates/tidefs-locator-table/src/locator_table_types.rs",
        &[
            "ExtentLocatorValueV1",
            "pub trait LocatorTableOps",
            "fn resolve",
            "fn allocate",
            "fn relocate",
            "fn retire",
            "fn batch_resolve",
            "LocatorTableError::NotFound",
            "LOCATOR_TABLE_PAGE_MAGIC",
        ],
        &mut missing,
    );

    if missing.is_empty() {
        Ok(())
    } else {
        Err(ClusterCheckError { missing })
    }
}

pub fn check_extent_map_v2_current_workspace() -> Result<(), ClusterCheckError> {
    let root = find_workspace_root().ok_or_else(|| ClusterCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "Cargo.toml",
        "crates/tidefs-extent-map/Cargo.toml",
        "crates/tidefs-extent-map/src/btree.rs",
        "crates/tidefs-types-extent-map-core/src/lib.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "crates/tidefs-extent-map/src/btree.rs",
        &[
            "BTreeExtentMap",
            "impl ExtentMapOps for BTreeExtentMap",
            "lookup_range",
            "insert_extent",
            "truncate",
            "punch_hole",
            "convert_unwritten_to_data",
            "seek_data",
            "seek_hole",
            "fiemap",
            "validate",
            "MAX_LEAF",
            "BTreeNode",
            "MAX_INTERNAL",
        ],
        &mut missing,
    );

    if missing.is_empty() {
        Ok(())
    } else {
        Err(ClusterCheckError { missing })
    }
}
pub fn check_checksum_architecture_current_workspace() -> Result<(), ClusterCheckError> {
    let root = find_workspace_root().ok_or_else(|| ClusterCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "docs/CHECKSUM_ARCHITECTURE_DESIGN.md",
        "docs/design/end-to-end-checksum-architecture-g3-pillar.md",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "docs/CHECKSUM_ARCHITECTURE_DESIGN.md",
        &[
            "CHECKSUM_ARCHITECTURE_SPEC",
            "IntegrityTrailerV2",
            "BLAKE3-256",
            "domain_separation",
            "SuspectLog",
            "SegmentIntegrityFooter",
        ],
        &mut missing,
    );

    check_source_markers(
        &root,
        "docs/design/end-to-end-checksum-architecture-g3-pillar.md",
        &[
            "CHECKSUM_ARCHITECTURE_SPEC",
            "IntegrityTrailerV2",
            "BLAKE3-256",
            "domain_separation",
            "SuspectLog",
            "SegmentIntegrityFooter",
            "#1559",
        ],
        &mut missing,
    );

    if missing.is_empty() {
        Ok(())
    } else {
        Err(ClusterCheckError { missing })
    }
}

pub fn check_feature_flags_current_workspace() -> Result<(), ClusterCheckError> {
    let root = find_workspace_root().ok_or_else(|| ClusterCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "crates/tidefs-types-dataset-feature-flags-core/Cargo.toml",
        "crates/tidefs-types-dataset-feature-flags-core/src/lib.rs",
        "docs/DATASET_FEATURE_FLAGS_DESIGN.md",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "crates/tidefs-types-dataset-feature-flags-core/src/lib.rs",
        &[
            "FEATURE_NAME_MAX_LEN",
            "FeatureClass",
            "FeatureFlagValueV1",
            "DatasetFeatureFlagsV1",
            "BtreeRootPointer",
            "CANONICAL_V1_FEATURES",
            "FEATURE_POSIX_ACL",
            "FEATURE_CHECKSUM_BLAKE3",
            "InvalidFeatureName",
            "canonical_feature!",
        ],
        &mut missing,
    );

    check_source_markers(
        &root,
        "crates/tidefs-types-dataset-feature-flags-core/Cargo.toml",
        &["tidefs-types-dataset-feature-flags-core"],
        &mut missing,
    );

    check_source_markers(
        &root,
        "docs/DATASET_FEATURE_FLAGS_DESIGN.md",
        &[
            "Dataset Feature Flags Architecture Design",
            "Feature Name",
            "compat",
            "ro_compat",
            "incompat",
        ],
        &mut missing,
    );

    if missing.is_empty() {
        Ok(())
    } else {
        Err(ClusterCheckError { missing })
    }
}

// ---------------------------------------------------------------------------
// check_polymorphic_directory_index_current_workspace
// ---------------------------------------------------------------------------

pub fn check_polymorphic_directory_index_current_workspace() -> Result<(), ClusterCheckError> {
    let root = find_workspace_root().ok_or_else(|| ClusterCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "crates/tidefs-types-polymorphic-directory-index-core/Cargo.toml",
        "crates/tidefs-types-polymorphic-directory-index-core/src/lib.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "crates/tidefs-types-polymorphic-directory-index-core/src/lib.rs",
        &[
            "LocatorId",
            "DirStorageKind",
            "DirMicroListV1",
            "DirMicroEntry",
            "DirBtreeRootV1",
            "DirBtreePageHeader",
            "DirBtreeLeafEntry",
            "DirBtreeInternalEntry",
            "DirStorage",
            "DatasetDirPolicy",
            "DirCookie",
            "FEATURE_POLYMORPHIC_DIR_INDEX",
            "DIR_BTREE_ROOT_MAGIC",
            "DIR_BTREE_PAGE_MAGIC",
            "should_use_btree",
            "should_use_micro_from_btree",
        ],
        &mut missing,
    );

    check_source_markers(
        &root,
        "crates/tidefs-types-polymorphic-directory-index-core/Cargo.toml",
        &["tidefs-types-polymorphic-directory-index-core"],
        &mut missing,
    );

    if missing.is_empty() {
        Ok(())
    } else {
        Err(ClusterCheckError { missing })
    }
}

// ---------------------------------------------------------------------------
// check_polymorphic_xattr_current_workspace
// ---------------------------------------------------------------------------

pub fn check_polymorphic_xattr_current_workspace() -> Result<(), ClusterCheckError> {
    let root = find_workspace_root().ok_or_else(|| ClusterCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "crates/tidefs-types-polymorphic-xattr-core/Cargo.toml",
        "crates/tidefs-types-polymorphic-xattr-core/src/lib.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "crates/tidefs-types-polymorphic-xattr-core/src/lib.rs",
        &[
            "XattrStorageKind",
            "XattrBundleV1",
            "XattrInlineEntry",
            "XattrBtreeRootV1",
            "XattrBtreePageHeader",
            "XattrBtreeLeafEntry",
            "XattrBtreeInternalEntry",
            "XattrStorage",
            "DatasetXattrPolicy",
            "should_use_tree",
            "XATTR_BUNDLE_MAGIC",
            "XATTR_BTREE_ROOT_MAGIC",
            "XATTR_BTREE_PAGE_MAGIC",
            "should_use_inline_from_tree",
            "XattrStorageKind",
        ],
        &mut missing,
    );

    check_source_markers(
        &root,
        "crates/tidefs-types-polymorphic-xattr-core/Cargo.toml",
        &["tidefs-types-polymorphic-xattr-core"],
        &mut missing,
    );

    if missing.is_empty() {
        Ok(())
    } else {
        Err(ClusterCheckError { missing })
    }
}

// ---------------------------------------------------------------------------
// check_polymorphic_directory_index_current_workspace

// ---------------------------------------------------------------------------
// check_posix_acl_current_workspace
// ---------------------------------------------------------------------------

pub fn check_posix_acl_current_workspace() -> Result<(), ClusterCheckError> {
    let root = find_workspace_root().ok_or_else(|| ClusterCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "crates/tidefs-posix-acl/Cargo.toml",
        "crates/tidefs-posix-acl/src/lib.rs",
        "docs/POSIX_ACL_XATTR_CODEC_DESIGN.md",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "crates/tidefs-posix-acl/src/lib.rs",
        &[
            "PosixAclEntry",
            "PosixAcl",
            "AclError",
            "POSIX_ACL_XATTR_VERSION",
            "MAX_ACL_ENTRIES",
            "ACL_USER_OBJ",
            "ACL_GROUP_OBJ",
            "ACL_MASK",
            "ACL_OTHER",
            "decode_posix_acl_xattr",
            "encode_posix_acl_xattr",
            "#![forbid(unsafe_code)]",
            "apply_chmod_to_acl",
            "posix_mode_from_access_acl",
            "posix_acl_perm_bits_for_caller",
            "find_entry",
        ],
        &mut missing,
    );

    check_source_markers(
        &root,
        "crates/tidefs-posix-acl/Cargo.toml",
        &["tidefs-posix-acl"],
        &mut missing,
    );

    check_source_markers(
        &root,
        "docs/POSIX_ACL_XATTR_CODEC_DESIGN.md",
        &[
            "PosixAclEntry",
            "PosixAcl",
            "AclError",
            "decode_posix_acl_xattr",
            "encode_posix_acl_xattr",
        ],
        &mut missing,
    );

    if missing.is_empty() {
        Ok(())
    } else {
        Err(ClusterCheckError { missing })
    }
}

// ---------------------------------------------------------------------------
// check_pool_allocator_current_workspace
// ---------------------------------------------------------------------------

pub fn check_pool_allocator_current_workspace() -> Result<(), ClusterCheckError> {
    let root = find_workspace_root().ok_or_else(|| ClusterCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "crates/tidefs-pool-allocator/Cargo.toml",
        "crates/tidefs-pool-allocator/src/lib.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "crates/tidefs-pool-allocator/src/lib.rs",
        &[
            "PoolAllocator",
            "PoolAllocatorError",
            "SpacePressureEvent",
            "PoolAllocatorStats",
            "check_pressure_transition",
            "NoFreeSegments",
            "MULTI_DEVICE_ALLOCATOR_COORDINATION",
        ],
        &mut missing,
    );

    check_source_markers(
        &root,
        "crates/tidefs-pool-allocator/Cargo.toml",
        &["tidefs-pool-allocator"],
        &mut missing,
    );

    if missing.is_empty() {
        Ok(())
    } else {
        Err(ClusterCheckError { missing })
    }
}

// ---------------------------------------------------------------------------
// check_membership_types_current_workspace
// ---------------------------------------------------------------------------

pub fn check_membership_types_current_workspace() -> Result<(), ClusterCheckError> {
    let root = find_workspace_root().ok_or_else(|| ClusterCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "crates/tidefs-membership-types/Cargo.toml",
        "crates/tidefs-membership-types/src/lib.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "crates/tidefs-membership-types/src/lib.rs",
        &[
            "MountMode",
            "MountReportV1",
            "JoinRequestV1",
            "JoinResponseV1",
            "LeaderRedirectV1",
            "HeartbeatV1",
            "HeartbeatAckV1",
            "NodeDescriptorV1",
            "DatasetViewV1",
            "ClusterViewV1",
            "MembershipTransition",
            "MembershipTransitionRecord",
            "MembershipCodec",
            "MembershipCodecError",
            "crc32c",
            "#![no_std]",
            "#![forbid(unsafe_code)]",
        ],
        &mut missing,
    );

    check_source_markers(
        &root,
        "Cargo.toml",
        &["crates/tidefs-membership-types"],
        &mut missing,
    );

    if missing.is_empty() {
        println!("membership-types ok: wire types, MembershipCodec, CRC32C checksums, and roundtrip tests are implementation-tracked non-release");
        Ok(())
    } else {
        Err(ClusterCheckError { missing })
    }
}

pub fn check_distributed_replication_runtime_current_workspace() -> Result<(), ClusterCheckError> {
    let root = find_workspace_root().ok_or_else(|| ClusterCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    // Verify all 9 source-owned distributed replication component crates exist.
    let crate_specs: &[(&str, &str, &[&str])] = &[
        (
            "data_copy_0.placement_planner",
            "crates/tidefs-placement-planner/src/lib.rs",
            &["data_copy_0", "compute_replica_target_set"],
        ),
        (
            "data_copy_1.transfer_orchestrator",
            "crates/tidefs-transport/src/lib.rs",
            &["data_copy_1", "TransferOrchestrator"],
        ),
        (
            "data_copy_2.verification_engine",
            "crates/tidefs-verification-engine/src/lib.rs",
            &["data_copy_2", "verify_digest_against_authoritative_source"],
        ),
        (
            "data_copy_3.replica_health_tracker",
            "crates/tidefs-replica-health/src/lib.rs",
            &["data_copy_3", "advance_replica_health_and_lag_frontiers"],
        ),
        (
            "data_copy_4.rebuild_planner",
            "crates/tidefs-rebuild-planner/src/lib.rs",
            &[
                "data_copy_4",
                "RebuildPlanner",
                "open_rebuild_flow_from_loss_event",
            ],
        ),
        (
            "data_copy_5.relocation_planner",
            "crates/tidefs-relocation-planner/src/lib.rs",
            &["data_copy_5", "RelocationPlanner", "open_relocation_flow"],
        ),
        (
            "data_copy_6.chunk_shipper",
            "crates/tidefs-chunk-shipper/src/lib.rs",
            &["data_copy_6", "stage_replica_chunks_for_transport"],
        ),
        (
            "data_copy_7.flow_commit_coordinator",
            "crates/tidefs-flow-commit-coordinator/src/lib.rs",
            &["data_copy_7", "FlowCommitCoordinator"],
        ),
        (
            "data_copy_8.anti_entropy_auditor",
            "crates/tidefs-anti-entropy-auditor/src/lib.rs",
            &["data_copy_8", "AntiEntropyAuditor"],
        ),
    ];

    for (label, rel_path, markers) in crate_specs {
        let abs_path = root.join(rel_path);
        if !abs_path.exists() {
            missing.push(format!("missing crate source: {rel_path} ({label})"));
            continue;
        }
        let content = match std::fs::read_to_string(&abs_path) {
            Ok(c) => c,
            Err(e) => {
                missing.push(format!("cannot read {rel_path}: {e}"));
                continue;
            }
        };
        for marker in *markers {
            if !content.contains(marker) {
                missing.push(format!("{rel_path}: missing marker '{marker}' ({label})"));
            }
        }
    }

    for rel in [
        "docs/LOCAL_DISTRIBUTED_RECEIPT_AUTHORITY.md",
        "docs/DOCUMENTATION_AUTHORITY_REGISTER.md",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    if missing.is_empty() {
        println!(
            "source-owned distributed replication runtime ok: all 9 data_copy component crates are implementation-tracked non-release with implementations"
        );
        Ok(())
    } else {
        Err(ClusterCheckError { missing })
    }
}
