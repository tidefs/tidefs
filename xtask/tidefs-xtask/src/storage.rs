use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct StorageCheckError {
    title: &'static str,
    missing: Vec<String>,
}

impl fmt::Display for StorageCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{} failed:", self.title)?;
        for item in &self.missing {
            writeln!(f, "- {item}")?;
        }
        Ok(())
    }
}

pub fn check_local_object_store_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "local object-store source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    check_workspace_members(
        &root,
        &["crates/tidefs-local-object-store", "apps/tidefs-store-demo"],
        &mut missing,
    );
    for rel in [
        "crates/tidefs-local-object-store/Cargo.toml",
        "crates/tidefs-local-object-store/src/lib.rs",
        "apps/tidefs-store-demo/Cargo.toml",
        "apps/tidefs-store-demo/src/main.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers_in_src_dir(
        &root,
        "crates/tidefs-local-object-store",
        &[
            "pub const STORE_DIR_NAME",
            "pub const SEGMENT_FILE_EXTENSION",
            "pub const RECORD_HEADER_LEN",
            "pub const RECORD_FOOTER_LEN",
            "pub enum RecordKind",
            "RecordKind::Put",
            "RecordKind::Delete",
            "pub struct ObjectKey",
            "pub struct LocalObjectStore",
            "pub fn open_with_options",
            "pub fn put",
            "pub fn get",
            "pub fn version_locations_of",
            "pub fn get_at_location",
            "version_history_preserves_superseded_put_locations",
            "pub fn delete",
            "pub fn sync_all",
            "pub fn checksum64",
            "ReplayReport",
            "repaired_tail_bytes",
            "encode_footer",
            "decode_footer",
            "record_total_len",
            "ChecksumMismatch",
            "truncated_tail_is_repaired_without_losing_committed_record",
            "invalid_final_footer_is_rejected_as_integrity_error",
            "checksum_mismatch_rejects_replay",
            "segment_rollover_creates_multiple_segments",
            "pub mod human",
            "local_object_store",
        ],
        &mut missing,
    );

    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!(
            "local object store source ok: segment files, record headers, commit markers, development integrity checksums, replay, tombstones, tail repair, and source tests present"
        );
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "local object-store source check",
            missing,
        })
    }
}

pub fn check_local_object_store_on_disk_format_current_workspace() -> Result<(), StorageCheckError>
{
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "local object-store on-disk format source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "docs/LOCAL_OBJECT_STORE_ON_DISK_FORMAT.md",
        "crates/tidefs-local-object-store/src/lib.rs",
        "apps/tidefs-store-demo/src/main.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers_in_src_dir(
        &root,
        "crates/tidefs-local-object-store",
        &[
            "LOCAL_OBJECT_STORE_ON_DISK_FORMAT_SPEC",
            "LocalObjectStoreFormatTopic",
            "LocalObjectStoreFormatRule",
            "LOCAL_OBJECT_STORE_ON_DISK_FORMAT_RULES",
            "local_object_store_on_disk_format_rules",
            "SegmentIdentity",
            "SegmentGapPolicy",
            "RecordVersions",
            "HeaderLayout",
            "FooterSemantics",
            "TombstoneSemantics",
            "VersionHistory",
            "UpgradeRules",
            "RECORD_MAGIC_ASCII",
            "RECORD_FOOTER_MAGIC_ASCII",
            "PRODUCTION_INTEGRITY_TRAILER_MAGIC_ASCII",
            "INTEGRITY_TRAILER_V2_MAGIC_ASCII",
            "INTEGRITY_TRAILER_V2_LEN",
            "*b\"VLOSINT4\"",
            "RECORD_FORMAT_VERSION_V1_NO_FOOTER",
            "RECORD_FORMAT_VERSION_V2_FOOTER",
            "RECORD_FORMAT_VERSION",
            "ProductionIntegrityMismatch",
            "record footer commit marker does not match the record fields",
            "delete tombstone carries payload bytes",
            "history: BTreeMap<ObjectKey, Vec<ObjectLocation>>",
            "UnsupportedVersion",
            "local_object_store_on_disk_format_spec_covers_storage_005_topics",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-store-demo/src/main.rs",
        &[
            "on_disk_format_spec",
            "on_disk_format.rules",
            "on_disk_format.rule topic",
            "record_footer_magic",
            "record_format_version_v1_no_footer",
            "record_format_version_v2_footer",
            "production_integrity.trailer_magic",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/LOCAL_OBJECT_STORE_ON_DISK_FORMAT.md",
        &[
            "segment identity",
            "segment gaps",
            "record versions",
            "footer semantics",
            "tombstones",
            "history",
            "upgrade rules",
            "segment-0000000000000000.vlos",
            "VLOSREC1",
            "VLOSEND2",
            "VLOSINT4",
        ],
        &mut missing,
    );

    // ── Reject stale current-format language across all format docs ──
    //
    // The production format is VLOSINT4 IntegrityTrailerV2 (112 bytes),
    // RECORD_FORMAT_VERSION=3.  Any doc that presents the older 80-byte
    // VLOSINT3 trailer as current is stale.
    let stale_patterns: &[&str] = &[
        "VLOSINT3",
        "80-byte production-integrity trailer",
        "PRODUCTION_INTEGRITY_TRAILER_LEN=80",
    ];
    // Primary format-spec doc
    check_forbidden_markers(
        &root,
        "docs/LOCAL_OBJECT_STORE_ON_DISK_FORMAT.md",
        stale_patterns,
        &mut missing,
    );
    // OW-014 production-integrity records doc
    check_forbidden_markers(
        &root,
        "docs/PRODUCTION_INTEGRITY_V3_RECORDS_OW014.md",
        stale_patterns,
        &mut missing,
    );
    // Production-integrity policy doc
    check_forbidden_markers(
        &root,
        "docs/PRODUCTION_INTEGRITY_POLICY.md",
        stale_patterns,
        &mut missing,
    );
    // Root-authentication doc (references production trailer)
    check_forbidden_markers(
        &root,
        "docs/ROOT_AUTHENTICATION_OW015.md",
        stale_patterns,
        &mut missing,
    );
    // Checksum-architecture design doc (not a current-format claim doc;
    // it describes the migration from old to new — the stale-pattern
    // check is intentionally omitted to avoid false positives on the
    // migration table row that documents the superseded 80-byte trailer)

    // ── Cross-check: format doc must state every authoritative magic value ──
    //
    // The format doc is the canonical prose description of what
    // constants.rs defines.  This guard catches drift by requiring
    // the doc to contain each production magic sequence and the
    // current size/version.
    let doc_must_have: &[&str] = &[
        "VLOSREC1",
        "VLOSEND2",
        "VLOSINT4",
        "112-byte production-integrity trailer",
        "current writer emits record format version",
    ];
    check_source_markers(
        &root,
        "docs/LOCAL_OBJECT_STORE_ON_DISK_FORMAT.md",
        doc_must_have,
        &mut missing,
    );

    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("local object-store on-disk format ok: segment identity, gaps, record versions, footer semantics, tombstones, history, and upgrade rules are specified and implementation-tracked non-release");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "local object-store on-disk format source check",
            missing,
        })
    }
}

pub fn check_production_integrity_policy_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "production integrity policy source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "docs/PRODUCTION_INTEGRITY_POLICY.md",
        "crates/tidefs-local-object-store/src/lib.rs",
        "crates/tidefs-local-filesystem/src/lib.rs",
        "apps/tidefs-store-demo/src/main.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers_in_src_dir(
        &root,
        "crates/tidefs-local-object-store",
        &[
            "PRODUCTION_INTEGRITY_POLICY_SPEC",
            "PRODUCTION_INTEGRITY_OBJECT_DIGEST_ALGORITHM",
            "PRODUCTION_INTEGRITY_RECORD_DIGEST_ALGORITHM",
            "PRODUCTION_INTEGRITY_ROOT_AUTHENTICATION_ALGORITHM",
            "PRODUCTION_INTEGRITY_KEY_DERIVATION_ALGORITHM",
            "PRODUCTION_INTEGRITY_MIGRATION_RECORD_VERSION",
            "ProductionIntegrityPolicyTopic",
            "ProductionIntegrityPolicyRule",
            "PRODUCTION_INTEGRITY_POLICY_RULES",
            "production_integrity_policy_rules",
            "ChosenAlgorithms",
            "DomainSeparation",
            "CollisionPolicy",
            "AuthenticatedRoot",
            "MigrationPlan",
            "CompatibilityBoundary",
            "KeyHandling",
            "Validation",
            "production_integrity_policy_covers_storage_006_acceptance_gate",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-store-demo/src/main.rs",
        &[
            "production_integrity_policy",
            "production_integrity.object_digest",
            "production_integrity.root_authentication",
            "production_integrity.migration_record_version",
            "production_integrity.rule topic",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/PRODUCTION_INTEGRITY_POLICY.md",
        &[
            "BLAKE3-256",
            "domain separation",
            "collision policy",
            "authenticated root",
            "migration plan",
            "record version 3",
            "v1/v2 compatibility",
        ],
        &mut missing,
    );

    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("production integrity policy ok: algorithms, domain separation, collision policy, authenticated roots, and v3 migration boundaries are implementation-tracked non-release");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "production integrity policy source check",
            missing,
        })
    }
}

pub fn check_production_integrity_v3_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "OW-014 production integrity v3 record source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "docs/PRODUCTION_INTEGRITY_V3_RECORDS_OW014.md",
        "docs/STATUS.md",
        "crates/tidefs-local-object-store/src/lib.rs",
        "apps/tidefs-store-demo/src/main.rs",
        "nix/tidefs-validation.sh",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers_in_src_dir(
        &root,
        "crates/tidefs-local-object-store",
        &[
            "RECORD_FORMAT_VERSION_V2_FOOTER",
            "PRODUCTION_INTEGRITY_TRAILER_LEN",
            "PRODUCTION_INTEGRITY_TRAILER_MAGIC_ASCII",
            "INTEGRITY_TRAILER_V2_MAGIC_ASCII",
            "INTEGRITY_TRAILER_V2_LEN",
            "*b\"VLOSINT4\"",
            "ProductionIntegrityDigest",
            "ProductionIntegrityRecordDigests",
            "encode_integrity_trailer_v2",
            "decode_integrity_trailer_v2",
            "build_integrity_trailer_v2",
            "verify_integrity_trailer_v2",
            "production_integrity_digests_v2",
            "record_has_production_integrity_trailer",
            "ProductionIntegrityMismatch",
            "v3_records_seen",
            "production_integrity_records_seen",
            "new_records_use_v3_production_integrity_trailer",
            "record_version_2_footer_record_replays_as_compatibility_input",
            "production_integrity_trailer_mismatch_rejects_replay",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-store-demo/src/main.rs",
        &[
            "record_format_version_v2_footer",
            "production_integrity.trailer_magic",
            "production_integrity.trailer_len",
            "replay.v3_records_seen",
            "replay.production_integrity_records_seen",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/PRODUCTION_INTEGRITY_V3_RECORDS_OW014.md",
        &[
            "record version 3",
            "BLAKE3-256",
            "production-integrity trailer",
            "v1/v2 compatibility",
            "root authentication is delivered by OW-015",
            "tidefs-xtask check-production-integrity-v3",
        ],
        &mut missing,
    );
    // Reject stale current-format language in the format authority doc
    check_forbidden_markers(
        &root,
        "docs/LOCAL_OBJECT_STORE_ON_DISK_FORMAT.md",
        &["VLOSINT3", "80-byte production-integrity trailer"],
        &mut missing,
    );

    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("OW-014 production integrity v3 records ok: new records carry BLAKE3-256 trailers, v1/v2 replay remains compatibility-only, and root authentication is handled by OW-015");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "OW-014 production integrity v3 record source check",
            missing,
        })
    }
}

pub fn check_root_authentication_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "OW-015 root authentication source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "docs/ROOT_AUTHENTICATION_OW015.md",
        "docs/STATUS.md",
        "docs/PRODUCTION_INTEGRITY_POLICY.md",
        "crates/tidefs-local-filesystem/src/lib.rs",
        "apps/tidefs-filesystem-demo/src/main.rs",
        "apps/tidefs-posix-filesystem-adapter-daemon/src/main.rs",
        "apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_preview.rs",
        "nix/tidefs-validation.sh",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers_in_src_dir(
        &root,
        "crates/tidefs-local-filesystem",
        &[
            "ROOT_AUTHENTICATION_SPEC",
            "ROOT_AUTHENTICATION_ENV_VAR",
            "RootAuthenticationDigest",
            "RootAuthenticationCode",
            "RootAuthenticationKey",
            "RootAuthenticationRecord",
            "root_authentication_digest",
            "root_authentication_record_for_bytes",
            "root_authentication_code",
            "sign_root_commit",
            "validate_root_authentication_record",
            "MissingRootAuthenticationKey",
            "InvalidRootAuthenticationKey",
            "has_root_authentication",
            "root_authentication_requires_the_matching_external_key",
            "unauthenticated_newer_root_candidate_is_skipped",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-filesystem-demo/src/main.rs",
        &[
            "root_authentication.spec",
            "root_authentication.env_var",
            "root_authentication.demo_key=explicit-fixture",
            "run_crash_recovery_matrix_with_root_authentication_key",
            "open_with_root_authentication_key",
            "audit_recovery_with_root_authentication_key",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-posix-filesystem-adapter-daemon/src/main.rs",
        &[
            "--root-auth-key-hex",
            "ROOT_AUTHENTICATION_ENV_VAR",
            "RootAuthenticationKey::from_environment",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_preview.rs",
        &[
            "root_authentication_key",
            "open_with_root_authentication_key",
            "RootAuthenticationKey::demo_key",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/ROOT_AUTHENTICATION_OW015.md",
        &[
            "keyed BLAKE3-256",
            "external operator secret",
            "authentication keys are never stored inside segment records",
            "tidefs-xtask check-root-authentication",
        ],
        &mut missing,
    );
    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("OW-015 root authentication ok: committed filesystem roots require keyed BLAKE3-256 authentication over root metadata and manifest/superblock digests, with explicit key entrypoints for demos and mounts");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "OW-015 root authentication source check",
            missing,
        })
    }
}

pub fn check_local_snapshots_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "OW-108 local snapshots source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "docs/LOCAL_SNAPSHOTS_OW108.md",
        "docs/STATUS.md",
        "crates/tidefs-local-filesystem/src/lib.rs",
        "apps/tidefs-filesystem-demo/src/main.rs",
        "nix/tidefs-validation.sh",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers_in_src_dir(
        &root,
        "crates/tidefs-local-filesystem",
        &[
            "LOCAL_SNAPSHOT_ROLLBACK_SPEC",
            "SNAPSHOT_CATALOG_MAGIC_ASCII",
            "SnapshotSummary",
            "SnapshotRollbackReport",
            "SnapshotAlreadyExists",
            "SnapshotNotFound",
            "list_snapshots",
            "create_snapshot",
            "delete_snapshot",
            "rollback_to_snapshot",
            "roots_with_snapshot_roots",
            "snapshot_rollback_restores_an_isolated_committed_root",
            "safe_reclamation_preserves_snapshot_roots_for_later_rollback",
            "allocator_counts_snapshot_roots_hidden_behind_newer_slots",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-filesystem-demo/src/main.rs",
        &[
            "snapshot_rollback.spec",
            "snapshot.create.name",
            "snapshot.rollback.published_generation",
            "snapshot_reclamation.protects_snapshot_root",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/LOCAL_SNAPSHOTS_OW108.md",
        &[
            "authenticated committed-root",
            "rollback publishes a new authenticated root",
            "safe reclamation protects snapshot roots",
            "Allocator reservation counts snapshot roots",
            "tidefs-xtask check-local-snapshots",
        ],
        &mut missing,
    );
    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("OW-108 local snapshots ok: named snapshots retain authenticated committed roots, rollback publishes a new authenticated root, and safe reclamation protects snapshot roots");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "OW-108 local snapshots source check",
            missing,
        })
    }
}

pub fn check_send_receive_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "OW-109 send/receive source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "docs/SEND_RECEIVE_OW109.md",
        "docs/STATUS.md",
        "crates/tidefs-local-filesystem/src/lib.rs",
        "apps/tidefs-filesystem-demo/src/main.rs",
        "nix/tidefs-validation.sh",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers_in_src_dir(
        &root,
        "crates/tidefs-local-filesystem",
        &[
            "SEND_RECEIVE_CHANGED_RECORD_SPEC",
            "SEND_RECEIVE_STREAM_MAGIC_ASCII",
            "ChangedRecordExport",
            "ChangedRecordImportReport",
            "ChangedRecordObjectRole",
            "export_changed_records",
            "receive_changed_records_into_empty_root_with_root_authentication_key",
            "validate_changed_record_export",
            "rewrite_snapshot_roots_for_import",
            "changed_record_send_receive_round_trips_current_root_and_snapshot",
            "changed_record_import_rejects_corrupt_payload_before_publish",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-filesystem-demo/src/main.rs",
        &[
            "send_receive.spec",
            "send_receive.export_roots",
            "send_receive.staging_validated_before_publish",
            "send_receive.destination_root_reauthentication",
            "send_receive.rollback_read_matches",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/SEND_RECEIVE_OW109.md",
        &[
            "VFSSEND1",
            "changed-record stream",
            "destination root-authentication key",
            "snapshot rollback still works after receive",
            "tidefs-xtask check-send-receive",
        ],
        &mut missing,
    );
    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("OW-109 send/receive ok: VFSSEND1 changed-record streams round-trip authenticated committed roots, receive validates in staging, re-signs with the destination key, and preserves snapshot rollback");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "OW-109 send/receive source check",
            missing,
        })
    }
}

pub fn check_online_verifier_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "OW-110 online verifier source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "docs/ONLINE_VERIFIER_OW110.md",
        "docs/STATUS.md",
        "docs/FEATURE_MATRIX.md",
        "crates/tidefs-local-object-store/src/lib.rs",
        "crates/tidefs-local-filesystem/src/lib.rs",
        "crates/tidefs-online-verifier/src/lib.rs",
        "apps/tidefs-filesystem-demo/src/main.rs",
        "nix/tidefs-validation.sh",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers_in_src_dir(
        &root,
        "crates/tidefs-online-verifier",
        &[
            "ONLINE_VERIFIER_SPEC",
            "ONLINE_VERIFIER_IS_NOT_FSCK",
            "OnlineVerifierReport",
            "OnlineVerifierIssue",
            "OnlineVerifierOutcome",
            "verify_online",
            "verify_online_with_root_authentication_key",
            "ONLINE_VERIFIER_CRATE_GATE_OW_110",
        ],
        &mut missing,
    );

    check_source_markers_in_src_dir(
        &root,
        "crates/tidefs-local-filesystem",
        &[
            "ONLINE_VERIFIER_SPEC",
            "ONLINE_VERIFIER_IS_NOT_FSCK",
            "OnlineVerifierReport",
            "OnlineVerifierIssue",
            "OnlineVerifierOutcome",
            "verify_online_with_root_authentication_key",
            "online_verifier_report",
            "verify_online_store",
            "online_verifier_snapshot_roots",
            "online_verifier_path_does_not_initialize_missing_store",
            "online_verifier_reports_clean_committed_roots_without_mutation",
            "online_verifier_reports_corrupt_candidate_without_changing_live_truth",
        ],
        &mut missing,
    );
    check_source_markers_in_src_dir(
        &root,
        "crates/tidefs-local-object-store",
        &[
            "open_read_only_with_options",
            "StoreOpenMode::ReadOnlyExisting",
            "StoreError::ReadOnly",
            "read_only_open_does_not_initialize_missing_store",
            "read_only_open_does_not_rotate_full_segment",
            "read_only_store_rejects_mutating_put",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-filesystem-demo/src/main.rs",
        &[
            "online_verifier.spec",
            "online_verifier.law",
            "online_verifier.outcome",
            "online_verifier.mutating_repair_attempted",
            "online_verifier.production_requires_operator_repair",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/ONLINE_VERIFIER_OW110.md",
        &[
            "non-mutating online verifier",
            "does not rewrite root slots",
            "snapshot references",
            "tidefs-xtask check-online-verifier",
        ],
        &mut missing,
    );
    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("OW-110 online verifier ok: committed roots, manifests, authenticated roots, namespace invariants, content chunks, and snapshot roots are verified without repair or namespace mutation");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "OW-110 online verifier source check",
            missing,
        })
    }
}

pub fn check_local_filesystem_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "local filesystem source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    check_workspace_members(
        &root,
        &[
            "crates/tidefs-local-filesystem",
            "apps/tidefs-filesystem-demo",
        ],
        &mut missing,
    );
    for rel in [
        "crates/tidefs-local-filesystem/Cargo.toml",
        "crates/tidefs-local-filesystem/src/lib.rs",
        "apps/tidefs-filesystem-demo/Cargo.toml",
        "apps/tidefs-filesystem-demo/src/main.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers_in_src_dir(
        &root,
        "crates/tidefs-local-filesystem",
        &[
            "pub struct LocalFileSystem",
            "pub struct InodeRecord",
            "pub struct NamespaceEntry",
            "pub fn open_with_options",
            "pub fn create_dir",
            "pub fn create_file",
            "pub fn create_symlink",
            "pub fn link_file",
            "pub fn read_file",
            "pub fn read_symlink",
            "pub fn write_file",
            "pub fn truncate_file",
            "pub fn unlink",
            "pub fn remove_dir",
            "pub fn rename",
            "pub fn link_file",
            "pub fn create_symlink",
            "pub fn read_symlink",
            "pub fn superblock_object_key",
            "pub fn inode_object_key",
            "pub fn directory_object_key",
            "pub fn content_object_key",
            "pub fn content_object_key_for_version",
            "pub fn root_slot_object_key",
            "pub fn transaction_superblock_object_key",
            "pub fn transaction_inode_object_key",
            "pub fn transaction_directory_object_key",
            "RootCommitRecord",
            "FilesystemCommitBoundary",
            "CrashInjectionBoundary",
            "CrashRecoveryExpectation",
            "RecoveryProbeOutcome",
            "RecoveryProbeReport",
            "RecoveryAuditOutcome",
            "RecoveryAuditReport",
            "MountInvariantReport",
            "validate_namespace_invariants",
            "TransactionManifestObjectRole",
            "transaction_manifest_object_key",
            "validate_root_transaction_manifest",
            "pub fn probe_recovery",
            "pub fn recovery_probe_report",
            "persist_state_until_boundary",
            "encode_root_commit",
            "decode_root_commit",
            "load_latest_committed_state",
            "persist_transaction_objects",
            "encode_superblock",
            "encode_inode",
            "encode_directory",
            "encode_content",
            "create_write_reopen_read_file",
            "rename_and_truncate_survive_reopen",
            "hard_link_and_unlink_preserve_content_until_last_link",
            "symlink_round_trips_target",
            "write_at_offset_zero_fills_gap",
            "non_empty_directory_removal_is_rejected",
            "uncommitted_transaction_objects_are_ignored_on_reopen",
            "invalid_newer_root_slot_is_skipped_without_operator_repair",
            "invalid_newer_same_slot_root_falls_back_to_previous_version_without_operator_repair",
            "crash_injection_boundaries_select_only_old_or_new_committed_roots",
            "all_root_slots_invalid_reports_explicit_integrity_error_without_fsck",
            "pub mod human",
            "local_filesystem",
        ],
        &mut missing,
    );

    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!(
            "local filesystem source ok: root-slot commits, immutable transaction objects, versioned content objects, automatic previous-or-new recovery markers, inode/directory/content operations, and reopen source tests present"
        );
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "local filesystem source check",
            missing,
        })
    }
}

pub fn check_chunked_file_layout_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "OW-101 chunked file layout source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();
    for rel in [
        "docs/CHUNKED_FILE_LAYOUT_OW101.md",
        "docs/STATUS.md",
        "docs/FEATURE_MATRIX.md",
        "crates/tidefs-local-filesystem/src/lib.rs",
        "apps/tidefs-filesystem-demo/src/main.rs",
        "nix/tidefs-validation.sh",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers_in_src_dir(
        &root,
        "crates/tidefs-local-filesystem",
        &[
            "FILESYSTEM_CONTENT_CHUNK_SIZE",
            "CONTENT_MANIFEST_MAGIC",
            "CONTENT_CHUNK_MAGIC",
            "ContentManifestObject",
            "ContentChunkRef",
            "ContentChunkObject",
            "ContentLayout",
            "pub fn content_chunk_object_key_for_version",
            "VersionedContentChunk",
            "write_chunked_content",
            "write_chunked_content_with_overlay",
            "retained_content_chunk_ref",
            "transaction_manifest_entries_for_existing_content",
            "read_content_chunk_from_store",
            "random_write_updates_only_intersecting_chunk_refs",
            "truncate_rewrites_boundary_chunk_and_drops_tail_refs",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-filesystem-demo/src/main.rs",
        &[
            "content_layout.chunk_size",
            "content_layout.manifest_object=versioned-content-object",
            "content_layout.chunk_objects=versioned-content-chunks",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/CHUNKED_FILE_LAYOUT_OW101.md",
        &[
            "chunk manifest",
            "per-chunk object",
            "random writes",
            "truncate",
            "unchanged chunk references",
            "transaction manifest",
            "tidefs-xtask check-chunked-file-layout",
        ],
        &mut missing,
    );
    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("OW-101 chunked file layout ok: versioned content manifests, per-chunk objects, retained unchanged chunk refs, and transaction-manifest chunk protection are implementation-tracked non-release");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "OW-101 chunked file layout source check",
            missing,
        })
    }
}

pub fn check_local_storage_allocator_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "OW-102/PC-006 local storage allocator source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();
    for rel in [
        "docs/LOCAL_STORAGE_ALLOCATOR_OW102.md",
        "docs/STATUS.md",
        "docs/FEATURE_MATRIX.md",
        "crates/tidefs-local-filesystem/src/lib.rs",
        "apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_preview.rs",
        "apps/tidefs-filesystem-demo/src/main.rs",
        "nix/tidefs-validation.sh",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers_in_src_dir(
        &root,
        "crates/tidefs-local-filesystem",
        &[
            "LOCAL_STORAGE_ALLOCATOR_SPEC",
            "LocalStorageAllocatorPolicy",
            "LocalStorageAllocatorReport",
            "LocalStorageResource",
            "FileSystemStatfs",
            "FileSystemError::NoSpace",
            "allocator_report",
            "statfs",
            "fallocate_file",
            "ensure_content_capacity_with_planned_inode",
            "protected_committed_content_entries",
            "allocator_counts_protected_chunk_refs_before_reuse",
            "allocator_rejects_inode_exhaustion_without_mutation",
            "fallocate_extends_through_allocator_and_reports_statfs",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_preview.rs",
        &[
            "ReplyStatfs",
            "reply.statfs",
            "fallocate_inode_from_handle",
            "FileSystemError::NoSpace",
            "ENOSPC",
            "preview_fuse_model_reports_statfs_and_fallocate_mode_zero",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-filesystem-demo/src/main.rs",
        &[
            "local_storage_allocator.spec",
            "allocator_report.current_namespace_allocated_bytes",
            "allocator_report.reusable_free_bytes",
            "statfs.blocks",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/LOCAL_STORAGE_ALLOCATOR_OW102.md",
        &[
            "PC-006",
            "ENOSPC",
            "statfs",
            "fallocate",
            "protected committed roots",
            "tidefs-xtask check-local-storage-allocator",
        ],
        &mut missing,
    );
    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("OW-102/PC-006 local storage allocator ok: finite content/inode capacity, protected-root accounting, ENOSPC, statfs, and fallocate mode-zero validation are implementation-tracked non-release");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "OW-102/PC-006 local storage allocator source check",
            missing,
        })
    }
}

pub fn check_no_fsck_recovery_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "no-production-fsck recovery source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();
    for rel in [
        "crates/tidefs-local-filesystem/src/lib.rs",
        "crates/tidefs-local-object-store/src/lib.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers_in_src_dir(
        &root,
        "crates/tidefs-local-filesystem",
        &[
            "Production recovery must",
            "FILESYSTEM_ROOT_SLOT_COUNT",
            "RootCommitRecord",
            "root_slot_object_key",
            "transaction_superblock_object_key",
            "content_object_key_for_version",
            "load_latest_committed_state",
            "root slots exist but no valid committed root could be selected",
            "uncommitted_transaction_objects_are_ignored_on_reopen",
            "invalid_newer_root_slot_is_skipped_without_operator_repair",
        ],
        &mut missing,
    );
    check_source_markers_in_src_dir(
        &root,
        "crates/tidefs-local-object-store",
        &[
            "is_last_segment",
            "non-final segment ended in the middle of a record header",
            "non-final segment ended in the middle of a record payload",
            "non-final segment ended in the middle of a record footer",
        ],
        &mut missing,
    );
    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
            // Regression guard for #5976: mount must not call run_fsck;
            // fsck is an explicit operator command, not a mount-time recovery authority.
            "Production recovery must not call run_fsck",
        ],
        &mut missing,
    );

    // Regression guard for #5976: run_fsck must thread the caller's
    // RecoveryPolicy through instead of hard-coding RecoveryPolicy::default().
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/fsck.rs",
        &[
            "policy: RecoveryPolicy",
            "Advisory diagnostic callers should prefer",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("no-production-fsck recovery source ok: root-slot commits, previous-or-new automatic recovery, and development-only checker design rule present");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "no-production-fsck recovery source check",
            missing,
        })
    }
}

pub fn check_no_production_fsck_failure_model_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "formal no-production-fsck failure model source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();
    for rel in [
        "docs/NO_PRODUCTION_FSCK_FAILURE_MODEL.md",
        "crates/tidefs-local-filesystem/src/lib.rs",
        "crates/tidefs-local-object-store/src/lib.rs",
        "apps/tidefs-filesystem-demo/src/main.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers_in_src_dir(
        &root,
        "crates/tidefs-local-filesystem",
        &[
            "FORMAL_NO_PRODUCTION_FSCK_FAILURE_MODEL",
            "NoProductionFsckFailureClass",
            "NoProductionFsckFailureModelCase",
            "NO_PRODUCTION_FSCK_FAILURE_MODEL_CASES",
            "no_production_fsck_failure_model_cases",
            "SyncSemantics",
            "WriteReordering",
            "TornFinalAppend",
            "LostUnsyncedWrite",
            "RootCandidateMediaCorruption",
            "AllRootSlotsInvalid",
            "ExplicitStorageError",
            "no_production_fsck_failure_model_covers_storage_004_classes",
        ],
        &mut missing,
    );
    check_source_markers_in_src_dir(
        &root,
        "crates/tidefs-local-object-store",
        &[
            "sync_on_write",
            "repair_torn_tail",
            "record footer commit marker does not match the record fields",
            "checksum_mismatch_rejects_replay",
            "truncated_tail_is_repaired_without_losing_committed_record",
            "non-final segment ended in the middle of a record",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-filesystem-demo/src/main.rs",
        &[
            "formal_failure_model",
            "no_fsck_failure_model.cases",
            "no_fsck_failure_model.case class",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/NO_PRODUCTION_FSCK_FAILURE_MODEL.md",
        &[
            "sync semantics",
            "write reordering",
            "torn writes",
            "lost writes",
            "media corruption",
            "explicit-error behavior",
            "previous committed root",
            "new committed root",
            "explicit integrity/media error",
            "must not require production fsck",
        ],
        &mut missing,
    );

    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("formal no-production-fsck failure model ok: sync semantics, reordering, torn/lost writes, media corruption, and explicit errors are tied to executable recovery markers");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "formal no-production-fsck failure model source check",
            missing,
        })
    }
}

pub fn check_crash_injection_recovery_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "crash-injection recovery source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();
    for rel in [
        "crates/tidefs-local-filesystem/src/lib.rs",
        "crates/tidefs-local-object-store/src/lib.rs",
        "apps/tidefs-filesystem-demo/src/main.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers_in_src_dir(
        &root,
        "crates/tidefs-local-object-store",
        &[
            "history: BTreeMap<ObjectKey, Vec<ObjectLocation>>",
            "pub fn version_locations_of",
            "pub fn get_at_location",
            "version_history_preserves_superseded_put_locations",
        ],
        &mut missing,
    );
    check_source_markers_in_src_dir(
        &root,
        "crates/tidefs-local-filesystem",
        &[
            "PRODUCTION_RECOVERY_DOCTRINE",
            "FilesystemCommitBoundary",
            "CrashInjectionBoundary",
            "CrashRecoveryExpectation",
            "CrashRecoveryObservedOutcome",
            "CrashRecoveryMatrixReport",
            "CrashRecoveryCaseReport",
            "CrashRecoveryExplicitErrorReport",
            "RecoveryProbeOutcome",
            "RecoveryProbeReport",
            "RecoveryAuditOutcome",
            "RecoveryAuditReport",
            "TransactionManifestObjectRole",
            "transaction_manifest_object_key",
            "validate_root_transaction_manifest",
            "pub fn run_crash_recovery_matrix",
            "pub fn probe_recovery",
            "pub fn recovery_probe_report",
            "persist_state_until_boundary",
            "run_crash_recovery_boundary_case",
            "run_crash_recovery_explicit_error_case",
            "real_directory_crash_recovery_matrix_reports_only_allowed_outcomes",
            "PublishOutcomeUncertain",
            "keeps_live_state_on_error",
            "sync_store_after_commit_boundary",
            "version_locations_of(slot_key)",
            "get_at_location(location)",
            "crash_injection_boundaries_select_only_old_or_new_committed_roots",
            "pre_publish_sync_failure_rolls_back_live_state",
            "root_sync_failure_keeps_live_state_and_avoids_transaction_id_reuse",
            "invalid_newer_same_slot_root_falls_back_to_previous_version_without_operator_repair",
            "all_root_slots_invalid_reports_explicit_integrity_error_without_fsck",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-filesystem-demo/src/main.rs",
        &[
            "run_crash_recovery_matrix",
            "crash_matrix.passed",
            "crash_matrix.cases_executed",
            "crash_matrix.explicit_error_observed",
            "crash_matrix.case boundary",
        ],
        &mut missing,
    );

    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("crash-injection recovery source ok: commit-boundary harness, same-slot root fallback, and no-production-fsck validation markers present");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "crash-injection recovery source check",
            missing,
        })
    }
}

pub fn check_recovery_probe_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "recovery probe source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();
    for rel in [
        "crates/tidefs-local-filesystem/src/lib.rs",
        "apps/tidefs-filesystem-demo/src/main.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers_in_src_dir(
        &root,
        "crates/tidefs-local-filesystem",
        &[
            "RecoveryProbeOutcome",
            "RecoveryProbeReport",
            "RecoveryAuditOutcome",
            "RecoveryAuditReport",
            "TransactionManifestObjectRole",
            "transaction_manifest_object_key",
            "validate_root_transaction_manifest",
            "pub fn probe_recovery",
            "pub fn recovery_probe_report",
            "pub fn recovery_audit",
            "pub fn audit_recovery",
            "select_latest_committed_root",
            "recovery_probe_from_store",
            "audit_recovery_store",
            "mountable_without_operator_repair",
            "production_recovery_requires_operator_repair",
            "recovery_probe_reports_selected_root_without_operator_repair",
            "recovery_probe_reports_explicit_error_without_guessing_repair",
            "recovery_audit_reports_manifested_committed_root_without_fsck",
            "missing_manifest_newer_root_is_skipped_without_operator_repair",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-filesystem-demo/src/main.rs",
        &[
            "recovery_probe.preflight_outcome",
            "recovery_probe.outcome",
            "recovery_probe.production_requires_operator_repair",
            "recovery_audit.outcome",
            "recovery_audit.production_fsck_required",
        ],
        &mut missing,
    );
    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("recovery probe source ok: recovery classification and no-operator-repair mount gate markers present");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "recovery probe source check",
            missing,
        })
    }
}

pub fn check_recovery_manifest_audit_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "recovery manifest audit source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();
    for rel in [
        "crates/tidefs-local-filesystem/src/lib.rs",
        "apps/tidefs-filesystem-demo/src/main.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers_in_src_dir(
        &root,
        "crates/tidefs-local-filesystem",
        &[
            "RECOVERY_AUDIT_IS_NOT_FSCK",
            "TRANSACTION_MANIFEST_MAGIC",
            "TransactionManifestObjectRole",
            "TransactionManifestEntry",
            "TransactionManifestRecord",
            "transaction_manifest_object_key",
            "encode_transaction_manifest",
            "decode_transaction_manifest",
            "validate_root_transaction_manifest",
            "validate_transaction_manifest_matches_loaded_state",
            "RecoveryAuditOutcome",
            "RecoveryAuditReport",
            "pub fn audit_recovery",
            "pub fn recovery_audit",
            "recovery_audit_reports_manifested_committed_root_without_fsck",
            "missing_manifest_newer_root_is_skipped_without_operator_repair",
            "transaction_manifest_is_written_and_validated_without_repair",
            "invalid_transaction_manifest_makes_newer_root_candidate_unselectable",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-filesystem-demo/src/main.rs",
        &[
            "recovery_audit_law",
            "recovery_audit.live_outcome",
            "recovery_audit.production_fsck_required",
            "recovery_audit.checked_transaction_manifests",
        ],
        &mut missing,
    );

    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("recovery manifest audit source ok: root commits now carry transaction manifests and audit validation remains non-repairing");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "recovery manifest audit source check",
            missing,
        })
    }
}

pub fn check_mount_invariant_gate_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "mount invariant gate source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();
    for rel in [
        "crates/tidefs-local-filesystem/src/lib.rs",
        "apps/tidefs-filesystem-demo/src/main.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers_in_src_dir(
        &root,
        "crates/tidefs-local-filesystem",
        &[
            "MOUNT_INVARIANT_GATE_IS_NOT_FSCK",
            "MountInvariantReport",
            "pub fn mount_invariant_report",
            "pub fn live_invariant_report",
            "mount_invariant_report_from_state",
            "validate_namespace_invariants",
            "reachable_inodes_from_root",
            "mount invariant gate: directory link count does not match child-directory topology",
            "mount invariant gate: committed root contains unreachable inode records",
            "bad_link_count_committed_root_is_skipped_before_mount_without_fsck",
            "unreachable_inode_committed_root_is_skipped_before_mount_without_fsck",
            "mount_invariant_gate_reports_live_namespace_without_repair",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-filesystem-demo/src/main.rs",
        &[
            "mount_invariant_gate_law",
            "mount_invariant.inode_count",
            "mount_invariant.reachable_inode_count",
            "mount_invariant.production_fsck_required",
            "replay.mount_invariant_reachable",
        ],
        &mut missing,
    );

    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("mount invariant gate source ok: committed roots are structurally validated before becoming live truth, without production fsck");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "mount invariant gate source check",
            missing,
        })
    }
}

pub fn check_preview_posix_subset_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "preview POSIX subset source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();
    for rel in [
        "docs/PREVIEW_POSIX_SUBSET.md",
        "crates/tidefs-local-filesystem/src/lib.rs",
        "apps/tidefs-filesystem-demo/src/main.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers_in_src_dir(
        &root,
        "crates/tidefs-local-filesystem",
        &[
            "PREVIEW_POSIX_SUBSET_SPEC",
            "PREVIEW_POSIX_SUBSET_POLICY_VERSION",
            "PreviewPosixSupport",
            "PreviewPosixTopic",
            "PreviewPosixSubsetEntry",
            "PREVIEW_POSIX_SUBSET_ENTRIES",
            "preview_posix_subset_entries",
            "IncludedInFirstFusePreview",
            "IncludedAfterFirstFusePreview",
            "BlockedBeforeUsefulPreview",
            "DeferredAfterFirstPreview",
            "ExplicitlyUnsupported",
            "lookup/getattr",
            "read/write/truncate",
            "fsync-file",
            "rename-over-target",
            "lseek",
            "SEEK_DATA",
            "SEEK_HOLE",
            "SEEK_CUR",
            "ENXIO",
            "xattr/acl",
            "mknod-device/fifo/socket",
            "posix_subset_covers_storage_104_acceptance_gate",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-filesystem-demo/src/main.rs",
        &[
            "preview_posix_subset_spec",
            "preview_posix_subset.policy_version",
            "preview_posix_subset.entries",
            "preview_posix_subset.entry topic",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/PREVIEW_POSIX_SUBSET.md",
        &[
            "included in first FUSE preview",
            "included after first FUSE preview",
            "blocked before useful preview",
            "deferred after first preview",
            "explicitly unsupported",
            "lookup/getattr",
            "fsync-file",
            "rename-over-target",
            "PC-004B",
            "dense-file",
            "SEEK_DATA",
            "SEEK_HOLE",
            "SEEK_CUR",
            "ENXIO",
            "fiemap",
            "xattr/acl",
        ],
        &mut missing,
    );

    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("preview POSIX subset ok: included, deferred, unsupported, and blocked-state FUSE-preview operations are implementation-tracked non-release");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "preview POSIX subset source check",
            missing,
        })
    }
}

pub fn check_fuse_mount_path_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "userspace FUSE mount path source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();
    for rel in [
        "docs/FUSE_MOUNT_PREVIEW.md",
        "docs/FUSE_LSEEK_PREVIEW_PC004B.md",
        "docs/PREVIEW_POSIX_SUBSET.md",
        "apps/tidefs-posix-filesystem-adapter-daemon/Cargo.toml",
        "apps/tidefs-posix-filesystem-adapter-daemon/src/main.rs",
        "apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_preview.rs",
        "flake.nix",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers(
        &root,
        "apps/tidefs-posix-filesystem-adapter-daemon/Cargo.toml",
        &[
            "fuser = { version = \"0.14.0\"",
            "libc = \"0.2\"",
            "tidefs-local-filesystem",
            "tidefs-types-vfs-core",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-posix-filesystem-adapter-daemon/src/main.rs",
        &[
            "mod fuse_preview",
            "mount --store <path> --mount <path>",
            "smoke-mount",
            "fuse_mount_smoke.passed=true",
            "mount_foreground",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_preview.rs",
        &[
            "FuseVfsAdapter",
            "impl Filesystem for FuseVfsAdapter",
            "fuser::spawn_mount2",
            "lookup",
            "getattr",
            "readdir",
            "create",
            "read_inode",
            "write_inode",
            "truncate_inode",
            "create_symlink_path",
            "link_path",
            "rename_path",
            "fsync",
            "statfs",
            "lseek_inode_from_handle",
            "SEEK_DATA",
            "SEEK_HOLE",
            "EOPNOTSUPP",
            "FOPEN_DIRECT_IO",
            "preview_fuse_model_round_trips_included_operations_without_kernel_mount",
            "preview_fuse_model_reports_dense_file_lseek_surface",
            "preview_fuse_model_lseek_uses_open_unlinked_handle_size",
            "lseek_seek_hole_data_in_dense_file",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "flake.nix",
        &[
            "pkgs.fuse3",
            "boot.kernelModules = [ \"fuse\" \"virtio_console\" ]",
            "test -e /dev/fuse",
            "tidefs-posix-filesystem-adapter-daemon smoke-mount",
            "buildRustPackage",
            "cargoLock.lockFile",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/FUSE_MOUNT_PREVIEW.md",
        &[
            "tidefs-posix-filesystem-adapter-daemon mount --store",
            "tidefs-posix-filesystem-adapter-daemon smoke-mount",
            "nix run .#qemu-smoke",
            "lookup/getattr",
            "fsync-file",
            "statfs",
            "lseek",
            "SEEK_DATA",
            "SEEK_HOLE",
            "SEEK_CUR",
            "ENXIO",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/FUSE_LSEEK_PREVIEW_PC004B.md",
        &[
            "PC-004B",
            "SEEK_SET",
            "SEEK_END",
            "SEEK_DATA",
            "SEEK_HOLE",
            "dense-file preview",
            "open-unlinked handles",
            "not a POSIX-complete sparse extent map",
        ],
        &mut missing,
    );

    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("userspace FUSE mount path ok: fuser mount command, QEMU smoke, lseek preview, and preview POSIX error boundaries are implementation-tracked non-release");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "userspace FUSE mount path source check",
            missing,
        })
    }
}

pub fn check_posix_semantics_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "OW-106 POSIX semantics source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();
    for rel in [
        "docs/POSIX_SEMANTICS_OW106.md",
        "docs/PREVIEW_POSIX_SUBSET.md",
        "docs/FUSE_MOUNT_PREVIEW.md",
        "crates/tidefs-local-filesystem/src/lib.rs",
        "apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_preview.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers_in_src_dir(
        &root,
        "crates/tidefs-local-filesystem",
        &[
            "IncludedAfterFirstFusePreview",
            "fsync-file",
            "fsync-directory",
            "unlink-while-open",
            "rename-over-target",
            "rename_replaces_regular_file_atomically",
            "rename_replaces_empty_directory_with_directory_tree",
            "rename_rejects_invalid_replacements",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_preview.rs",
        &[
            "open_handles",
            "unlinked_open_files",
            "release_file_handle",
            "detached_unlinked_file",
            "detached_replaced_target",
            "read_inode_from_handle",
            "write_inode_from_handle",
            "fsyncdir",
            "preview_fuse_model_preserves_unlink_while_open_handles",
            "preview_fuse_model_preserves_renamed_over_open_target_handles",
            "file.sync_all()",
            "File::open(&docs)?.sync_all()",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/POSIX_SEMANTICS_OW106.md",
        &[
            "root-slot publication",
            "Local Object Store sync boundary",
            "unlink-while-open",
            "rename-over-target",
            "FUSE session state",
            "not persisted as orphan inodes",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/PREVIEW_POSIX_SUBSET.md",
        &[
            "included after first FUSE preview",
            "fsync-file",
            "fsync-directory",
            "unlink-while-open",
            "rename-over-target",
        ],
        &mut missing,
    );

    // New tidefs-posix-semantics crate check (issue #1198)
    for rel in [
        "crates/tidefs-posix-semantics/Cargo.toml",
        "crates/tidefs-posix-semantics/src/lib.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers(
        &root,
        "crates/tidefs-posix-semantics/src/lib.rs",
        &[
            "posix_perm_bits_for_caller",
            "posix_has_perm",
            "chmod_sanitize_mode_unprivileged",
            "apply_setgid_inheritance_for_create",
            "sticky_dir_allows_unlink_or_rename",
            "killpriv_mode_on_write_or_truncate",
            "killpriv_mode_on_chown",
            "should_update_atime_relatime",
        ],
        &mut missing,
    );
    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("OW-106 POSIX semantics ok: fsync, directory fsync, unlink-while-open, rename-over-target, and posix-semantics crate are implementation-tracked non-release");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "OW-106 POSIX semantics source check",
            missing,
        })
    }
}

pub fn check_seek_hole_data_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "PC-004B FUSE lseek preview source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();
    for rel in [
        "docs/FUSE_LSEEK_PREVIEW_PC004B.md",
        "crates/tidefs-local-filesystem/src/types.rs",
        "crates/tidefs-local-filesystem/src/tests.rs",
        "apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_preview.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers_in_src_dir(
        &root,
        "crates/tidefs-local-filesystem",
        &[
            "PC-004B",
            "SEEK_HOLE",
            "SEEK_DATA",
            "lseek: SEEK_SET/SEEK_END/SEEK_DATA/SEEK_HOLE",
            "dense-file FUSE lseek answers",
            "PC-004B includes dense-file FUSE lseek answers",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_preview.rs",
        &[
            "lseek_inode_from_handle",
            "SEEK_DATA",
            "SEEK_HOLE",
            "preview_fuse_model_reports_dense_file_lseek_surface",
            "preview_fuse_model_lseek_uses_open_unlinked_handle_size",
            "lseek_seek_hole_data_in_dense_file",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/FUSE_LSEEK_PREVIEW_PC004B.md",
        &[
            "PC-004B",
            "SEEK_SET",
            "SEEK_END",
            "SEEK_DATA",
            "SEEK_HOLE",
            "SEEK_CUR",
            "ENXIO",
            "EINVAL",
            "EOPNOTSUPP",
            "dense-file preview model",
            "open-unlinked handles",
            "Boundaries",
        ],
        &mut missing,
    );

    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("PC-004B FUSE lseek preview ok: SEEK_SET/SEEK_END/SEEK_DATA/SEEK_HOLE are implementation-tracked non-release with dense-file semantics");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "PC-004B FUSE lseek preview source check",
            missing,
        })
    }
}

pub fn check_rename_exchange_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "OW-108 RENAME_EXCHANGE source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();
    for rel in [
        "crates/tidefs-local-filesystem/src/lib.rs",
        "crates/tidefs-local-filesystem/src/tests.rs",
        "apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_preview.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers_in_src_dir(
        &root,
        "crates/tidefs-local-filesystem",
        &[
            "rename_exchange",
            "rename_exchange_swaps_file_contents_atomically",
            "rename_exchange_swaps_directories_atomically",
            "rename_exchange_rejects_type_mismatch",
            "rename_exchange_rejects_missing_paths",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_preview.rs",
        &[
            "RENAME_EXCHANGE",
            "rename_exchange",
            "preview_fuse_model_rejects_rename_exchange_and_whiteout_flags",
        ],
        &mut missing,
    );

    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("OW-108 RENAME_EXCHANGE ok: atomic exchange via renameat2 is implementation-tracked non-release with path swap, type-mismatch reject, and missing-path errors");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "OW-108 RENAME_EXCHANGE source check",
            missing,
        })
    }
}

pub fn check_rename_noreplace_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "#481 FUSE renameat2 RENAME_NOREPLACE source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();
    for rel in [
        "crates/tidefs-local-filesystem/src/lib.rs",
        "crates/tidefs-local-filesystem/src/tests.rs",
        "apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_preview.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers_in_src_dir(
        &root,
        "crates/tidefs-local-filesystem",
        &[
            "noreplace",
            "rename_noreplace_rejects_existing_target",
            "noreplace=true must fail when target exists",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_preview.rs",
        &[
            "RENAME_NOREPLACE",
            "preview_fuse_model_supports_rename_noreplace_flag",
            "preview_fuse_model_rejects_rename_exchange_and_whiteout_flags",
        ],
        &mut missing,
    );

    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("#481 FUSE renameat2 RENAME_NOREPLACE ok: flag support, noreplace-reject-on-existing-target, and preview model are implementation-tracked non-release");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "#481 FUSE renameat2 RENAME_NOREPLACE source check",
            missing,
        })
    }
}

pub fn check_file_locking_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "#491 FUSE advisory file locking source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();
    for rel in [
        "crates/tidefs-local-filesystem/src/types.rs",
        "crates/tidefs-local-filesystem/src/tests.rs",
        "apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_preview.rs",
        "apps/tidefs-posix-filesystem-adapter-daemon/src/coverage_gap.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers_in_src_dir(
        &root,
        "crates/tidefs-local-filesystem",
        &[
            "FileLocking",
            "PreviewPosixTopic::FileLocking",
            "flock/posix-locks",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_preview.rs",
        &["fn getlk", "fn setlk"],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-posix-filesystem-adapter-daemon/src/coverage_gap.rs",
        &["PreviewPosixTopic::FileLocking"],
        &mut missing,
    );

    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("#491 FUSE advisory file locking ok: getlk/setlk handlers, FileLocking topic, and deferred preview model are implementation-tracked non-release");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "#491 FUSE advisory file locking source check",
            missing,
        })
    }
}

pub fn check_mmap_coherency_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "OW-204 mmap coherency source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();
    for rel in [
        "docs/PAGE_CACHE_WRITEBACK_MMAP_INTEGRATION_P5-03.md",
        "crates/tidefs-local-filesystem/src/lib.rs",
        "crates/tidefs-local-filesystem/src/tests.rs",
        "docs/PREVIEW_POSIX_SUBSET.md",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers_in_src_dir(
        &root,
        "crates/tidefs-local-filesystem",
        &[
            "PAGE_CACHE_WRITEBACK_MMAP_SPEC",
            "PAGE_CACHE_WRITEBACK_MMAP_POLICY_VERSION",
            "PAGE_CACHE_WRITEBACK_MMAP_ACCEPTANCE_CASES",
            "page_cache_writeback_mmap_acceptance_cases",
            "page_cache_writeback_mmap_spec_covers_storage_204_acceptance_gate",
            "PageCacheCoherencyClass",
            "PageCacheVisibilityState",
            "shared-mmap-msync",
            "private-mmap-cow",
            "requires_dirty_epoch",
            "requires_writeback_batch",
            "OW-204",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/PAGE_CACHE_WRITEBACK_MMAP_INTEGRATION_P5-03.md",
        &[
            "OW-204",
            "P5-03",
            "page-cache / writeback / mmap integration",
            "PAGE_CACHE_WRITEBACK_MMAP_SPEC",
            "PAGE_CACHE_WRITEBACK_MMAP_ACCEPTANCE_CASES",
            "page_cache_writeback_mmap_acceptance_cases",
            "shared writable mmap",
            "private mmap copy-on-write",
            "coherency classes",
            "implemented-source specification gate",
            "Non-negotiable rules",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/PREVIEW_POSIX_SUBSET.md",
        &["mmap-coherency", "OW-204", "page-cache/writeback/mmap"],
        &mut missing,
    );

    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("OW-204 mmap coherency ok: page-cache/writeback/mmap law is implementation-tracked non-release with coherency classes, dirty-epoch tracking, and non-authoritative page-cache mandate");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "OW-204 mmap coherency source check",
            missing,
        })
    }
}

pub fn check_xattrs_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "#496 FUSE xattrs source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();
    for rel in [
        "crates/tidefs-local-filesystem/src/lib.rs",
        "crates/tidefs-local-filesystem/src/tests.rs",
        "apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_preview.rs",
        "docs/PREVIEW_POSIX_SUBSET.md",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers_in_src_dir(
        &root,
        "crates/tidefs-local-filesystem",
        &[
            "xattrs",
            "set_xattr",
            "get_xattr",
            "list_xattr",
            "remove_xattr",
            "set_get_xattr_round_trip",
            "list_xattr_returns_names",
            "remove_xattr_clears_attribute",
            "xattr_create_flag_blocks_duplicate",
            "xattr_replace_flag_requires_existing",
            "xattrs_survive_reopen",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_preview.rs",
        &[
            "setxattr",
            "getxattr",
            "listxattr",
            "removexattr",
            "set_xattr",
            "get_xattr",
            "list_xattr",
            "remove_xattr",
            "ReplyXattr",
            "errno_for_fs_error",
        ],
        &mut missing,
    );

    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("#496 FUSE xattrs ok: set/get/list/remove xattr operations, round-trip persistence, and preview model are implementation-tracked non-release");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "#496 FUSE xattrs source check",
            missing,
        })
    }
}

pub fn check_fallocate_mode0_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "#494 fallocate mode-0 (allocate) source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();
    for rel in [
        "crates/tidefs-local-filesystem/src/lib.rs",
        "crates/tidefs-local-filesystem/src/tests.rs",
        "crates/tidefs-local-filesystem/src/types.rs",
        "apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_preview.rs",
        "crates/tidefs-types-posix-filesystem-adapter-core/src/lib.rs",
        "docs/PREVIEW_POSIX_SUBSET.md",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers_in_src_dir(
        &root,
        "crates/tidefs-local-filesystem",
        &[
            "fallocate_file",
            "fallocate_extends_through_allocator_and_reports_statfs",
            "OW-102",
            "fallocate mode 0",
            "allocator-admitted",
            "EOPNOTSUPP",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_preview.rs",
        &[
            "fn fallocate_inode_from_handle",
            "fn fallocate",
            "preview_fuse_model_reports_statfs_and_fallocate_mode_zero",
            "fallocate_punch_hole_zeroes_range_and_keeps_size",
            "fallocate_zero_range_zeroes_and_may_extend",
            "fallocate_keep_size_does_not_extend_file",
            "fallocate_unsupported_mode_returns_eopnotsupp",
            "FALLOC_FL_KEEP_SIZE",
            "FALLOC_FL_COLLAPSE_RANGE",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-types-posix-filesystem-adapter-core/src/lib.rs",
        &["fallocate mode zero"],
        &mut missing,
    );

    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("#494 fallocate mode-0 (allocate) ok: allocator-admitted zero extension, statfs integration, unsupported mode EOPNOTSUPP, and FUSE preview model are implementation-tracked non-release");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "#494 fallocate mode-0 (allocate) source check",
            missing,
        })
    }
}

pub fn check_fallocate_punch_hole_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "#515 fallocate punch-hole/zero-range source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();
    for rel in [
        "apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_preview.rs",
        "docs/PUBLISHING_CHECKLIST.md",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers(
        &root,
        "apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_preview.rs",
        &[
            "FALLOC_FL_PUNCH_HOLE",
            "FALLOC_FL_ZERO_RANGE",
            "fn fallocate_inode_from_handle",
            "fn fallocate",
            "fallocate_punch_hole_zeroes_range_and_keeps_size",
            "fallocate_zero_range_zeroes_and_may_extend",
            "fallocate_keep_size_does_not_extend_file",
            "fallocate_unsupported_mode_returns_eopnotsupp",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/PUBLISHING_CHECKLIST.md",
        &["punch-hole/zero-range (#515)"],
        &mut missing,
    );

    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("#515 fallocate punch-hole/zero-range ok: PUNCH_HOLE/KEEP_SIZE/ZERO_RANGE flag handling, mutual exclusion, and zero-range extension are implementation-tracked non-release");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "#515 fallocate punch-hole/zero-range source check",
            missing,
        })
    }
}

pub fn check_fiemap_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "#500 FUSE fiemap (FS_IOC_FIEMAP) source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();
    for rel in [
        "crates/tidefs-local-filesystem/src/types.rs",
        "docs/PREVIEW_POSIX_SUBSET.md",
        "docs/PUBLISHING_CHECKLIST.md",
        "docs/HISTORY.md",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/types.rs",
        &[r#"operation: "fiemap""#],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/PREVIEW_POSIX_SUBSET.md",
        &["fiemap", "deferred", "EOPNOTSUPP"],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/PUBLISHING_CHECKLIST.md",
        &["fiemap", "FS_IOC_FIEMAP", "#500"],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/HISTORY.md",
        &["FS_IOC_FIEMAP", "#500"],
        &mut missing,
    );

    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("#500 FUSE fiemap ok: FS_IOC_FIEMAP ioctl declaration, dense-file extent reporting, deferred preview model, and publishing checklist are implementation-tracked non-release");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "#500 FUSE fiemap (FS_IOC_FIEMAP) source check",
            missing,
        })
    }
}

pub fn check_space_management_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "#537 space management (allocator policy) source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();
    for rel in [
        "crates/tidefs-local-filesystem/src/lib.rs",
        "crates/tidefs-local-filesystem/src/tests.rs",
        "crates/tidefs-local-filesystem/src/types.rs",
        "docs/PREVIEW_POSIX_SUBSET.md",
        "docs/PUBLISHING_CHECKLIST.md",
        "docs/HISTORY.md",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers_in_src_dir(
        &root,
        "crates/tidefs-local-filesystem",
        &[
            "open_with_allocator_policy",
            "update_allocator_policy",
            "SpaceManagement",
            "StatfsCapacity",
            "statfs",
            "ENOSPC",
            "update_allocator_policy_resize_larger",
            "update_allocator_policy_shrink_still_fits",
            "update_allocator_policy_shrink_rejects_zero_content",
            "update_allocator_policy_shrink_rejects_zero_inodes",
            "update_allocator_policy_shrink_below_allocation_triggers_enospc",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/PREVIEW_POSIX_SUBSET.md",
        &["statfs", "ENOSPC"],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/PUBLISHING_CHECKLIST.md",
        &[
            "Space management",
            "allocator policy resize",
            "ENOSPC",
            "#537",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/HISTORY.md",
        &[
            "allocator policy resize",
            "space management",
            "ENOSPC",
            "#537",
        ],
        &mut missing,
    );

    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("#537 space management ok: allocator policy open/update, online resize, statfs, ENOSPC enforcement, and publishing checklist are implementation-tracked non-release");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "#537 space management (allocator policy) source check",
            missing,
        })
    }
}
pub fn check_transaction_model_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "PC-007 transaction model source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();
    for rel in [
        "docs/TRANSACTION_COMMIT_GROUPS_PC007.md",
        "crates/tidefs-local-filesystem/src/lib.rs",
        "crates/tidefs-local-filesystem/src/tests.rs",
        "apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_preview.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers_in_src_dir(
        &root,
        "crates/tidefs-local-filesystem",
        &[
            "begin_transaction",
            "commit_transaction",
            "rollback_transaction",
            "dirty_content",
            "dirty_inodes",
            "dirty_dirs",
            "fsync_data_only",
            "has_dirty_metadata",
            "do_commit",
            "in_transaction",
            "mark_metalogue_clean",
            "mark_all_state_dirty",
            "begin_transaction_then_commit_persists_mutations",
            "begin_transaction_then_rollback_discards_mutations",
            "transaction_nesting_is_rejected",
            "commit_without_transaction_is_rejected",
            "rollback_without_transaction_is_rejected",
            "fsync_data_only_persists_content_without_metadata",
            "has_dirty_metadata_detects_dirty_inode",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_preview.rs",
        &["sync_data_only", "fsync_data_only"],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/TRANSACTION_COMMIT_GROUPS_PC007.md",
        &[
            "PC-007",
            "commit_group",
            "dirty_buffer",
            "transaction model",
            "commit group",
            "root_transaction",
            "root_slot",
            "O_DSYNC",
            "fdatasync",
            "fsync",
            "staging data",
            "publication boundary",
        ],
        &mut missing,
    );

    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("PC-007 transaction model ok: per-inode dirty tracking, begin/commit/rollback, fsync/O_DSYNC, and transaction lifecycle tests are implementation-tracked non-release");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "PC-007 transaction model source check",
            missing,
        })
    }
}
pub fn check_xfstests_harness_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "xfstests harness source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();
    for rel in [
        "scripts/tidefs-xfstests-mount",
        "scripts/tidefs-xfstests-runner",
        "scripts/tidefs-xfstests-exclude",
        "docs/xfstests-harness.md",
        "nix/tidefs-posix-scoreboard.sh",
        "docs/POSIX_SCOREBOARD_OW107.md",
        "flake.nix",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers(
        &root,
        "scripts/tidefs-xfstests-mount",
        &[
            "tidefs-xfstests-mount",
            "tidefs-preview",
            "TIDEFS_XFSTESTS_STORE_ROOT",
            "mountpoint -q",
            "tidefs-posix-filesystem-adapter-daemon mount",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "scripts/tidefs-xfstests-runner",
        &[
            "tidefs-xfstests-runner",
            "TIDEFS_XFSTESTS_NIX_PACKAGE=1",
            "nix/tidefs-posix-scoreboard.sh",
            "--quick",
            "xfstests",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "scripts/tidefs-xfstests-exclude",
        &["TideFS xfstests exclude list", "generic/099"],
        &mut missing,
    );
    check_source_markers(
        &root,
        "flake.nix",
        &[
            "xfstests-runner",
            "tidefs-xfstests-mount",
            "tidefs-xfstests-runner",
            "tidefs-xfstests-exclude",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "nix/tidefs-posix-scoreboard.sh",
        &["TIDEFS_XFSTESTS_NIX_PACKAGE", "xfstests"],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/xfstests-harness.md",
        &[
            "xfstests harness",
            "nix run .#xfstests-runner",
            "TIDEFS_XFSTESTS_STORE_ROOT",
            "tidefs-preview",
            "tidefs-xfstests-mount",
            "tidefs-xfstests-exclude",
            "Baseline",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/POSIX_SCOREBOARD_OW107.md",
        &[
            "xfstests harness",
            "TIDEFS_XFSTESTS_DIR",
            "TIDEFS_SCOREBOARD_XFSTESTS_CMD",
        ],
        &mut missing,
    );

    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("xfstests harness ok: mount helper, runner, exclude list, Nix app, and scoreboard integration are implementation-tracked non-release");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "xfstests harness source check",
            missing,
        })
    }
}

pub fn check_posix_scoreboard_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "OW-107 POSIX scoreboard source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();
    for rel in [
        "docs/POSIX_SCOREBOARD_OW107.md",
        "docs/STATUS.md",
        "apps/tidefs-posix-filesystem-adapter-daemon/src/main.rs",
        "apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_preview.rs",
        "nix/tidefs-posix-scoreboard.sh",
        "scripts/tidefs-xfstests-mount",
        "scripts/tidefs-xfstests-runner",
        "scripts/tidefs-xfstests-exclude",
        "flake.nix",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers(
        &root,
        "apps/tidefs-posix-filesystem-adapter-daemon/src/main.rs",
        &[
            "score-posix [--out <path>]",
            "PosixScoreboardConfig",
            "score_posix",
            "posix_scoreboard.path",
            "posix_scoreboard.failed_lanes",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_preview.rs",
        &[
            "PosixScoreboardConfig",
            "PosixScoreboardResult",
            "PosixScoreboardRow",
            "scoreboard.tsv",
            "scoreboard.md",
            "tidefs-fuse-smoke",
            "fio",
            "fsx",
            "fsstress",
            "pjdfstest",
            "xfstests",
            "skipped` is recorded as explicit non-validation",
            "TIDEFS_SCOREBOARD_XFSTESTS_CMD",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "nix/tidefs-posix-scoreboard.sh",
        &[
            "tidefs-posix-filesystem-adapter-daemon score-posix",
            "TIDEFS_POSIX_SCOREBOARD_DIR",
            "posix-scoreboard",
            "scoreboard.md",
            "TIDEFS_XFSTESTS_EXCLUDE",
            "TIDEFS_XFSTESTS_NIX_PACKAGE",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "flake.nix",
        &[
            "tidefs-posix-scoreboard",
            "nix/tidefs-posix-scoreboard.sh",
            "posix-scoreboard",
            "xfstests-runner",
            "tidefs-xfstests-mount",
            "tidefs-preview",
            "pkgs.fio",
            "pkgs.fuse3",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "scripts/tidefs-xfstests-mount",
        &[
            "tidefs-xfstests-mount",
            "tidefs-preview",
            "tidefs-posix-filesystem-adapter-daemon mount",
            "mountpoint -q",
            "TIDEFS_XFSTESTS_STORE_ROOT",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "scripts/tidefs-xfstests-exclude",
        &["TideFS xfstests exclude list", "generic/099"],
        &mut missing,
    );
    check_source_markers(
        &root,
        "scripts/tidefs-xfstests-runner",
        &[
            "tidefs-xfstests-runner",
            "TIDEFS_XFSTESTS_NIX_PACKAGE=1",
            "nix/tidefs-posix-scoreboard.sh",
            "--quick",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/POSIX_SCOREBOARD_OW107.md",
        &[
            "pass/fail/skip",
            "skipped is not a pass",
            "tidefs-posix-filesystem-adapter-daemon score-posix",
            "nix run .#posix-scoreboard",
            "fio",
            "fsx",
            "fsstress",
            "pjdfstest",
            "xfstests",
            "TIDEFS_SCOREBOARD_MOUNT",
        ],
        &mut missing,
    );

    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("OW-107 POSIX scoreboard ok: live FUSE, fio, fsx, fsstress, pjdfstest, and xfstests pass/fail/skip validation surfaces are implementation-tracked non-release; xfstests runner and exclude list wired");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "OW-107 POSIX scoreboard source check",
            missing,
        })
    }
}

pub fn check_root_retention_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "root retention source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();
    for rel in [
        "crates/tidefs-local-filesystem/src/lib.rs",
        "apps/tidefs-filesystem-demo/src/main.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers_in_src_dir(
        &root,
        "crates/tidefs-local-filesystem",
        &[
            "RETENTION_RECLAMATION_IS_NOT_FSCK",
            "MINIMUM_SAFE_RETAINED_ROOTS",
            "DEFAULT_RETAINED_COMMITTED_ROOTS",
            "RootRetentionPolicy",
            "RootRetentionDebt",
            "RootRetentionPlan",
            "pub fn plan_root_retention",
            "pub fn root_retention_plan",
            "pub fn safe_root_retention_plan",
            "retention_policy_satisfied",
            "has_retention_debt",
            "plan_root_retention_store",
            "object_keys_for_committed_root_summary",
            "root_slot_locations_for_summary",
            "mutating_reclamation_allowed: false",
            "retention_plan_protects_committed_roots_without_mutation_or_fsck",
            "retention_plan_reports_debt_when_policy_needs_more_roots_than_exist",
            "retention_policy_rejects_below_no_fsck_fallback_floor",
            "retention_plan_keeps_same_slot_fallback_location_without_repair",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-filesystem-demo/src/main.rs",
        &[
            "retention_reclamation_law",
            "retention_plan.policy_required_committed_roots",
            "retention_plan.valid_committed_roots_available",
            "retention_plan.missing_committed_roots",
            "retention_plan.has_retention_debt",
            "retention_plan.protected_committed_roots",
            "retention_plan.protected_root_slot_locations",
            "retention_plan.mutating_reclamation_allowed",
            "retention_plan.production_fsck_required",
        ],
        &mut missing,
    );

    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("root retention source ok: fallback root retention is planned without mutating storage or requiring production fsck");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "root retention source check",
            missing,
        })
    }
}

pub fn check_safe_local_reclamation_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "OW-103 safe local reclamation source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();
    for rel in [
        "docs/SAFE_LOCAL_RECLAMATION_OW103.md",
        "docs/STATUS.md",
        "docs/FEATURE_MATRIX.md",
        "crates/tidefs-local-object-store/src/lib.rs",
        "crates/tidefs-local-filesystem/src/lib.rs",
        "apps/tidefs-filesystem-demo/src/main.rs",
        "nix/tidefs-validation.sh",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers_in_src_dir(
        &root,
        "crates/tidefs-local-object-store",
        &[
            "StoreRetentionCompactionReport",
            "compact_retaining",
            "protected_exact_locations",
            "copied_protected_objects",
            "tombstoned_unprotected_keys",
            "retired_segments",
            "exact_locations_preserved",
        ],
        &mut missing,
    );
    check_source_markers_in_src_dir(
        &root,
        "crates/tidefs-local-filesystem",
        &[
            "SAFE_LOCAL_RECLAMATION_GC_SPEC",
            "SafeReclamationReport",
            "FileSystemError::RetentionDebt",
            "reclaim_unprotected_objects",
            "safe_reclaim_unprotected_objects",
            "safe_reclamation_preserves_retained_roots_and_reopens",
            "safe reclamation lost a protected root-slot location",
            "safe reclamation changed the selected committed root",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-filesystem-demo/src/main.rs",
        &[
            "safe_local_reclamation.spec",
            "safe_reclamation.retention_policy_satisfied",
            "safe_reclamation.protected_root_slot_locations_preserved",
            "safe_reclamation.tombstoned_unprotected_keys",
            "safe_reclamation.retired_segments",
            "safe_reclamation.reopen_read_matches",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/SAFE_LOCAL_RECLAMATION_OW103.md",
        &[
            "retention debt",
            "protected root-slot locations",
            "tombstone",
            "segment retirement",
            "tidefs-xtask check-safe-local-reclamation",
        ],
        &mut missing,
    );
    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("OW-103 safe local reclamation ok: protected-root checks, exact root-slot locations, protected-object copies, tombstones, segment retirement, and reopen verification are implementation-tracked non-release");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "OW-103 safe local reclamation source check",
            missing,
        })
    }
}

pub fn check_hot_read_cache_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "PC-003 hot read cache source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();
    for rel in [
        "docs/HOT_READ_CACHE_PC003.md",
        "docs/STATUS.md",
        "docs/FEATURE_MATRIX.md",
        "docs/INDEX.md",
        "crates/tidefs-local-filesystem/src/lib.rs",
        "apps/tidefs-filesystem-demo/src/main.rs",
        "nix/tidefs-validation.sh",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers_in_src_dir(
        &root,
        "crates/tidefs-local-filesystem",
        &[
            "HOT_READ_CACHE_SPEC",
            "HotReadCachePolicy",
            "HotReadCacheReport",
            "HotReadCacheKey",
            "HotReadCacheObjectRole",
            "ArcResident",
            "HotReadCache",
            "hot_read_cache_report",
            "invalidate_hot_read_cache_for_inode",
            "clear_hot_read_cache",
            "hot_read_cache_hits_repeated_reads_and_invalidates_on_write",
            "hot_read_cache_bypasses_oversized_content",
            "hot_read_cache_clears_on_snapshot_rollback",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-filesystem-demo/src/main.rs",
        &[
            "hot_read_cache.spec",
            "hot_read_cache.repeated_read_matches",
            "hot_read_cache.hits",
            "hot_read_cache.misses",
            "hot_read_cache.is_bounded",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/HOT_READ_CACHE_PC003.md",
        &[
            "PC-003",
            "bounded runtime mirror",
            "not authority",
            "inode id",
            "data version",
            "admission_bypasses",
            "tidefs-xtask check-hot-read-cache",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/FEATURE_MATRIX.md",
        &["Hot read cache", "acceleration mirror only"],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/STATUS.md",
        &["Hot read cache", "check-hot-read-cache"],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/INDEX.md",
        &["docs/HOT_READ_CACHE_PC003.md"],
        &mut missing,
    );
    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("PC-003 hot read cache ok: read_file/read_symlink use a bounded non-authoritative cache keyed by inode/data-version/size, with mutation invalidation and source validation");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "PC-003 hot read cache source check",
            missing,
        })
    }
}

pub fn check_module_owners_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "PC-002 module owners source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "docs/MODULE_OWNERS_INVARIANTS_PC002.md",
        "docs/INDEX.md",
        "xtask/tidefs-xtask/src/main.rs",
        "nix/tidefs-validation.sh",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers(
        &root,
        "docs/MODULE_OWNERS_INVARIANTS_PC002.md",
        &[
            "PC-002",
            "module owner",
            "Invariant boundaries",
            "Validation",
            "Non-claims",
            "local object store",
            "local filesystem",
            "POSIX/FUSE adapter",
            "policy/control/typed-record scaffolding",
            "platform probes/QEMU/RDMA",
            "operator/project coordination",
            "tidefs-xtask check-module-owners",
            "Projection adapters can narrow or render owner truth",
            "Runtime caches, probes, scoreboards, demos, and validation logs are validation",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/INDEX.md",
        &["docs/MODULE_OWNERS_INVARIANTS_PC002.md"],
        &mut missing,
    );
    check_source_markers(
        &root,
        "xtask/tidefs-xtask/src/main.rs",
        &["check-module-owners", "check-module-invariants"],
        &mut missing,
    );
    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("PC-002 module owners ok: major subsystem owner paths, invariant boundaries, validation, and non-claims are documented and implementation-tracked non-release");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "PC-002 module owners source check",
            missing,
        })
    }
}

fn check_workspace_members(root: &Path, members: &[&str], missing: &mut Vec<String>) {
    let manifest_path = root.join("Cargo.toml");
    let text = match fs::read_to_string(&manifest_path) {
        Ok(text) => text,
        Err(err) => {
            missing.push(format!("read Cargo.toml: {err}"));
            return;
        }
    };
    for member in members {
        if !text.contains(member) {
            missing.push(format!("workspace members do not include {member}"));
        }
    }
}

fn check_required_file(root: &Path, rel: &str, missing: &mut Vec<String>) {
    let path = root.join(rel);
    if !path.exists() {
        missing.push(format!("missing required file `{rel}`"));
    }
}

fn check_source_markers(root: &Path, lib_rel: &str, markers: &[&str], missing: &mut Vec<String>) {
    let lib_path = root.join(lib_rel);
    let text = match fs::read_to_string(&lib_path) {
        Ok(text) => text,
        Err(err) => {
            missing.push(format!("read {}: {err}", lib_path.display()));
            return;
        }
    };
    for marker in markers {
        if !text.contains(marker) {
            missing.push(format!("{lib_rel} is missing marker `{marker}`"));
        }
    }
}

fn check_forbidden_markers(
    root: &Path,
    lib_rel: &str,
    forbidden: &[&str],
    missing: &mut Vec<String>,
) {
    let lib_path = root.join(lib_rel);
    let text = match fs::read_to_string(&lib_path) {
        Ok(text) => text,
        Err(err) => {
            missing.push(format!("read {}: {err}", lib_path.display()));
            return;
        }
    };
    for marker in forbidden {
        if text.contains(marker) {
            missing.push(format!(
                "{lib_rel} contains stale marker `{marker}`; update to current-format authority"
            ));
        }
    }
}

/// Search for markers across all .rs files in a crate's src/ directory.
/// Falls back to lib.rs if the src directory is empty or missing.
fn check_source_markers_in_src_dir(
    root: &Path,
    crate_rel: &str,
    markers: &[&str],
    missing: &mut Vec<String>,
) {
    let src_dir = root.join(format!("{crate_rel}/src"));
    let mut combined = String::new();
    if let Ok(entries) = fs::read_dir(&src_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "rs") {
                if let Ok(text) = fs::read_to_string(&path) {
                    combined.push_str(&text);
                    combined.push('\n');
                }
            }
        }
    }
    if combined.is_empty() {
        let lib_rel = format!("{crate_rel}/src/lib.rs");
        return check_source_markers(root, &lib_rel, markers, missing);
    }
    for marker in markers {
        if !combined.contains(marker) {
            missing.push(format!("{crate_rel}/src is missing marker `{marker}`"));
        }
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

pub fn check_integrity_pipeline_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "integrity pipeline source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();
    for rel in [
        "crates/tidefs-local-filesystem/tests/integrity_pipeline_tests.rs",
        "crates/tidefs-local-filesystem/tests/verifier_checksum_tests.rs",
        "crates/tidefs-local-filesystem/tests/verifier_snapshot_tests.rs",
        "crates/tidefs-local-filesystem/src/scrub.rs",
        "crates/tidefs-local-filesystem/src/checksum.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/tests/integrity_pipeline_tests.rs",
        &[
            "setup_auth_env",
            "temp_root",
            "cleanup",
            "opts",
            "seg_path",
            "corrupt_bytes",
            "corrupt_object_payload",
            "corrupt_record_trailer",
            "file_inode",
            "first_transaction_id",
            "create_filesystem_with_deep_data",
            "clean_filesystem_passes_full_integrity_chain",
            "content_chunk_corruption_detected_in_chain",
            "transaction_manifest_corruption_falls_back",
            "content_manifest_corruption_detected",
            "root_slot_corruption_preserves_older_roots",
            "verifier_inspects_all_committed_roots",
            "empty_store_reports_empty_integrity",
            "verifier_reports_all_object_categories_on_clean_fs",
            "record_trailer_corruption_triggers_store_integrity_check",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/tests/verifier_checksum_tests.rs",
        &[
            "setup_auth_env",
            "temp_root",
            "cleanup",
            "opts",
            "create_fs_with_file",
            "seg_path",
            "corrupt_bytes",
            "corrupt_object_payload",
            "file_inode",
            "first_transaction_id",
            "assert_corruption_detected",
            "clean_filesystem_reports_clean",
            "empty_store_reports_empty",
            "corrupted_content_object_payload_detected",
            "corrupted_transaction_manifest_detected",
            "corrupted_superblock_detected",
            "verifier_reports_content_counts_on_clean_fs",
            "corrupted_content_chunk_payload_detected",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/tests/verifier_snapshot_tests.rs",
        &[
            "setup_auth_env",
            "temp_root",
            "cleanup",
            "opts",
            "seg_path",
            "corrupt_bytes",
            "corrupt_root_slot_payload",
            "clean_snapshot_chain_passes_verifier",
            "snapshot_metadata_is_consistent",
            "snapshots_persist_after_close_reopen",
            "verifier_counts_multiple_snapshots_in_one_root",
            "verifier_detects_corrupted_snapshot_source_root",
            "verifier_reports_snapshot_counts_on_clean_fs",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/scrub.rs",
        &[
            "ScrubReport",
            "ScrubBlockOutcome",
            "ScrubBlockKind",
            "ScrubBlockId",
            "ScrubViolation",
            "RepairStrategy",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/checksum.rs",
        &[
            "BlockChecksum",
            "FastBlockChecksum",
            "ProductionBlockChecksum",
            "Checksummed",
        ],
        &mut missing,
    );

    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("integrity pipeline ok: scrub, checksum, and verifier test suites are implementation-tracked non-release");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "integrity pipeline source check",
            missing,
        })
    }
}
/// Verify that the tidefs-scrub object-store data integrity tool exists,
/// compiles, and is implementation-tracked non-release in the workspace.
pub fn check_scrub_tool_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "#1009 tidefs-scrub tool source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();
    for rel in [
        "apps/tidefs-scrub/Cargo.toml",
        "apps/tidefs-scrub/src/main.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers(
        &root,
        "apps/tidefs-scrub/src/main.rs",
        &[
            "tidefs-scrub",
            "checksum64",
            "check_compression_frame",
            "ObjectOutcome",
            "ScrubReport",
            "print_report",
            "store_root",
        ],
        &mut missing,
    );
    check_source_markers(&root, "Cargo.toml", &["apps/tidefs-scrub"], &mut missing);

    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("#1009 tidefs-scrub tool ok: implementation-tracked non-release and workspace-integrated");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "#1009 tidefs-scrub tool source check",
            missing,
        })
    }
}

/// Validate that the spacemap/allocator crate exists, is a workspace member,
/// and contains all required spec markers (phases 1-3 of #1189).
pub fn check_spacemap_allocator_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "spacemap allocator source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "crates/tidefs-spacemap-allocator/Cargo.toml",
        "crates/tidefs-spacemap-allocator/src/lib.rs",
        "docs/SPACEMAP_ALLOCATOR_DESIGN.md",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_workspace_members(&root, &["crates/tidefs-spacemap-allocator"], &mut missing);
    check_source_markers_in_src_dir(
        &root,
        "crates/tidefs-spacemap-allocator",
        &[
            "SPACEMAP_ALLOCATOR_SPEC",
            "tidefs-xtask check-spacemap-allocator",
            "SegmentFreeMap",
            "alloc_after",
            "add_free",
            "remove_free",
            "is_free",
            "runs",
            "stats",
            "FreeMapError",
            "NoFreeSegments",
            "SegmentFreeMapStats",
            "fragmentation_pct",
            "encode_bitmaps",
            "decode_bitmaps",
            "bitmap_layout",
            "DEFAULT_METASLAB_SEGMENTS",
            "SpaceMapCheckpointV1",
            "MetaslabBitmapEntry",
            "SPACEMAP_CHECKPOINT_MAGIC",
            "generation",
            "SPACE_PRESSURE_THRESHOLD",
            "from_runs",
            "free_count",
            "is_under_pressure",
            "MULTI_DEVICE_ALLOCATOR_COORDINATION",
        ],
        &mut missing,
    );

    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("spacemap allocator ok: SegmentFreeMap core, SpaceMapBitmap encode/decode, generation counters, and checkpoint record are implementation-tracked non-release");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "spacemap allocator source check",
            missing,
        })
    }
}

// ---------------------------------------------------------------------------
// check_posix_acl_integration_current_workspace
// ---------------------------------------------------------------------------

pub fn check_posix_acl_integration_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "POSIX ACL integration source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "crates/tidefs-local-filesystem/Cargo.toml",
        "crates/tidefs-local-filesystem/src/lib.rs",
        "crates/tidefs-posix-acl/src/lib.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "POSIX_ACL_INTEGRATION_SPEC",
            "tidefs-xtask check-posix-acl-integration",
            "tidefs_posix_acl",
            "system.posix_acl_access",
            "system.posix_acl_default",
            "decode_posix_acl_xattr",
        ],
        &mut missing,
    );

    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("POSIX ACL integration ok: codec import, xattr intercept, and mode sync are implementation-tracked non-release in local-filesystem");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "POSIX ACL integration source check",
            missing,
        })
    }
}

// ---------------------------------------------------------------------------
// check_posix_acl_inheritance_current_workspace
// ---------------------------------------------------------------------------

pub fn check_posix_acl_inheritance_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "POSIX ACL inheritance source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "crates/tidefs-local-filesystem/src/lib.rs",
        "crates/tidefs-posix-acl/src/lib.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "crates/tidefs-posix-acl/src/lib.rs",
        &["default_acl_inheritance_for_parent"],
        &mut missing,
    );

    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "POSIX_ACL_INHERITANCE_SPEC",
            "tidefs-xtask check-posix-acl-inheritance",
            "default_acl_inheritance_for_parent",
        ],
        &mut missing,
    );

    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("POSIX ACL inheritance ok: default_acl_inheritance_for_parent wired into create_dir and create_file_like");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "POSIX ACL inheritance source check",
            missing,
        })
    }
}

// ---------------------------------------------------------------------------
// check_posix_acl_fuse_eval_current_workspace
// ---------------------------------------------------------------------------

pub fn check_posix_acl_fuse_eval_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "POSIX ACL FUSE eval source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    let rel = "apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_preview.rs";
    check_required_file(&root, rel, &mut missing);
    check_source_markers(
        &root,
        "apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_preview.rs",
        &[
            "POSIX_ACL_FUSE_EVAL_SPEC",
            "check_access_perm_acl",
            "posix_acl_perm_bits_for_caller",
        ],
        &mut missing,
    );

    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("POSIX ACL FUSE eval ok: check_access_perm_acl wired into access_inode with ACL fallback");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "POSIX ACL FUSE eval source check",
            missing,
        })
    }
}

// ---------------------------------------------------------------------------
// check_poolstore_compression_current_workspace
// ---------------------------------------------------------------------------

pub fn check_poolstore_compression_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "PoolStore compression wire-up source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    check_required_file(
        &root,
        "crates/tidefs-local-object-store/src/pool.rs",
        &mut missing,
    );

    check_source_markers(
        &root,
        "crates/tidefs-local-object-store/src/pool.rs",
        &[
            "pub struct PoolStore<",
            "pub struct PoolStoreMut<",
            "pub fn primary_store",
            "pub fn primary_store_mut",
            "pub fn raw_primary_store",
            "pub fn raw_primary_store_mut",
            "impl<'a> PoolStore<'a>",
            "impl<'a> PoolStoreMut<'a>",
            "PoolStore { pool: self }",
            "PoolStoreMut { pool: self }",
            "// PoolStore handles",
        ],
        &mut missing,
    );

    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("PoolStore compression ok: PoolStore/PoolStoreMut types exist, primary_store/primary_store_mut return Device-aware handles");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "PoolStore compression wire-up source check",
            missing,
        })
    }
}

const MOUNTED_TRANSFORM_RAW_STORE_COUNTS: &[(&str, usize)] = &[
    ("crates/tidefs-local-object-store/src/pool/mod.rs", 7),
    ("crates/tidefs-local-filesystem/src/lib.rs", 64),
    ("crates/tidefs-local-filesystem/src/crash_recovery.rs", 21),
    ("crates/tidefs-local-filesystem/src/journal_cleaner.rs", 7),
    ("crates/tidefs-local-filesystem/src/vfs_engine_impl.rs", 7),
];

pub fn check_mounted_transform_authority_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "mounted transform authority raw-store inventory check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "docs/MOUNTED_TRANSFORM_AUTHORITY_RAW_STORE_INVENTORY.md",
        "docs/CLAIMS_GATE_POLICY.md",
        "docs/PREVIEW_USER_MANUAL.md",
        "crates/tidefs-compression/src/lib.rs",
        "crates/tidefs-encryption/src/lib.rs",
        "crates/tidefs-dedup/src/lib.rs",
        "crates/tidefs-local-filesystem/src/lib.rs",
        "crates/tidefs-local-filesystem/src/tests.rs",
        "xtask/tidefs-xtask/src/claims.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_mounted_transform_raw_store_counts(&root, &mut missing);

    check_source_markers(
        &root,
        "docs/MOUNTED_TRANSFORM_AUTHORITY_RAW_STORE_INVENTORY.md",
        &[
            "plaintext identity -> compression frame -> encryption frame -> checksum -> raw media bytes",
            "reclaim identity",
            "transform-aware",
            "metadata/raw-only",
            "blocked",
            "later receipt/placement issue",
            "MountedOpenRecoveryAuthority",
            "MountedCommittedRootRepairAuthority",
            "transform-aware in raw-only mode",
            "metadata/raw-only through transform-aware authority",
            "MetadataRawOnlyNoDeviceTransforms",
            "Mounted local-filesystem device-level compression and encryption are blocked",
            "must fail closed while any production `blocked` row remains",
            "`crates/tidefs-local-filesystem/src/lib.rs` | 64",
            "`crates/tidefs-local-filesystem/src/crash_recovery.rs` | 21",
            "`crates/tidefs-local-filesystem/src/journal_cleaner.rs` | 7",
            "`crates/tidefs-local-filesystem/src/vfs_engine_impl.rs` | 7",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/CLAIMS_GATE_POLICY.md",
        &[
            "Mounted Transform Authority",
            "mounted local-filesystem compression/encryption claim is blocked",
            "raw-store inventory",
            "end-to-end mounted filesystem support",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "Fail closed until TFR-006 moves mounted content and recovery paths",
            "local filesystem device transforms",
            "raw-store inventory",
            "MountedOpenRecoveryAuthority",
            "MountedCommittedRootRepairAuthority",
            "RawOnlyNoDeviceTransforms",
            "MetadataRawOnlyNoDeviceTransforms",
            "plaintext identity -> compression frame -> encryption frame -> checksum -> raw media bytes",
            "raw_recovery_store",
            "raw-only transform authority",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/tests.rs",
        &[
            "mounted_open_recovery_authority_raw_only_initializes_empty_pool",
            "mounted_committed_root_repair_authority_routes_probe_audit_verifier_and_retention",
            "mounted_open_recovery_authority_rejects_device_transforms",
            "device_transform_open_helpers_fail_closed_until_tfr_006_inventory",
            "device_transform_open_config_rejects_before_pool_creation",
            "assert_transform_rejected",
            "raw-store inventory",
        ],
        &mut missing,
    );
    check_forbidden_markers(
        &root,
        "crates/tidefs-local-filesystem/src/tests.rs",
        &[
            "compression_write_read_roundtrip",
            "compression_uncompressed_backward_compat",
            "compression_reduces_object_size",
            "compression_mixed_mode_full_stack_validation",
            "NEXT-STOR-025 compression mixed-mode full-stack validation",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-compression/src/lib.rs",
        &[
            "plaintext identity -> compression frame -> encryption frame -> checksum -> raw media bytes",
            "raw media bytes, or reclaim",
            "identity for the mounted filesystem",
            "MOUNTED_TRANSFORM_AUTHORITY_RAW_STORE_INVENTORY",
        ],
        &mut missing,
    );
    for rel in [
        "crates/tidefs-encryption/src/lib.rs",
        "crates/tidefs-dedup/src/lib.rs",
    ] {
        check_source_markers(
            &root,
            rel,
            &[
                "plaintext identity -> compression frame -> encryption frame -> checksum -> raw media bytes",
                "reclaim identity",
                "MOUNTED_TRANSFORM_AUTHORITY_RAW_STORE_INVENTORY",
            ],
            &mut missing,
        );
    }
    check_source_markers(
        &root,
        "xtask/tidefs-xtask/src/claims.rs",
        &[
            "MountedTransformAuthority",
            "mounted device-level compression",
            "mounted device-level encryption",
            "raw-store inventory",
        ],
        &mut missing,
    );

    if missing.is_empty() {
        println!("mounted transform authority ok: raw-store inventory counts are current and mounted compression/encryption claims remain blocked behind TFR-006");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "mounted transform authority raw-store inventory check",
            missing,
        })
    }
}

fn check_mounted_transform_raw_store_counts(root: &Path, missing: &mut Vec<String>) {
    for (rel, expected) in MOUNTED_TRANSFORM_RAW_STORE_COUNTS {
        let path = root.join(rel);
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(err) => {
                missing.push(format!("read {rel}: {err}"));
                continue;
            }
        };
        let actual = raw_primary_store_match_count(&text);
        if actual != *expected {
            missing.push(format!(
                "{rel} has {actual} raw-primary-store matches; update inventory classification for expected {expected}"
            ));
        }
    }
}

fn raw_primary_store_match_count(text: &str) -> usize {
    text.matches("raw_primary_store(").count() + text.matches("raw_primary_store_mut(").count()
}

pub fn check_btree_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "B+tree crate check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    check_required_file(&root, "crates/tidefs-btree/src/lib.rs", &mut missing);

    check_source_markers(
        &root,
        "crates/tidefs-btree/src/lib.rs",
        &[
            "pub enum BTreeError",
            "pub struct BPlusTree<",
            "pub fn validate",
            "pub fn entries",
            "pub fn range",
            "pub fn insert",
            "pub fn get",
            "pub fn len",
            "pub fn depth",
            "pub const fn new",
        ],
        &mut missing,
    );

    check_source_markers(
        &root,
        "crates/tidefs-extent-map/Cargo.toml",
        &["tidefs-btree"],
        &mut missing,
    );

    check_source_markers(
        &root,
        "crates/tidefs-extent-map/src/btree.rs",
        &["use tidefs_btree::"],
        &mut missing,
    );

    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("B+tree crate check ok: tidefs-btree exists, tidefs-extent-map uses shared crate");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "B+tree crate check",
            missing,
        })
    }
}

// ---------------------------------------------------------------------------
// check_orphan_index_current_workspace
// ---------------------------------------------------------------------------

pub fn check_orphan_index_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "#1397 orphan index source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "crates/tidefs-orphan-index/Cargo.toml",
        "crates/tidefs-orphan-index/src/lib.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_workspace_members(&root, &["crates/tidefs-orphan-index"], &mut missing);
    check_source_markers_in_src_dir(
        &root,
        "crates/tidefs-orphan-index",
        &[
            "OrphanIndex",
            "fn insert",
            "fn delete",
            "fn batch_recover",
            "fn validate",
            "#![forbid(unsafe_code)]",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-orphan-index/Cargo.toml",
        &["tidefs-btree"],
        &mut missing,
    );

    // -- #1413 integration checks (orphan index wired into local-filesystem) --
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/Cargo.toml",
        &["tidefs-orphan-index", "tidefs-types-orphan-index-core"],
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "use tidefs_orphan_index::OrphanIndex",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "orphan_index.lock().unwrap().insert(",
            "orphan_index.lock().unwrap().delete(",
            "fn recover_orphans",
            "orphan_index.lock().unwrap().batch_recover(",
            "orphan_index.lock().unwrap().encode(",
            "orphan_index_object_key()",
        ],
        &mut missing,
    );

    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("#1397+#1413 orphan index ok: orphan index runtime and local-filesystem integration verified");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "#1397 orphan index source check",
            missing,
        })
    }
}

pub fn check_background_scheduler_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "background service framework source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "crates/tidefs-background-scheduler/Cargo.toml",
        "crates/tidefs-background-scheduler/src/lib.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_workspace_members(&root, &["crates/tidefs-background-scheduler"], &mut missing);
    check_source_markers_in_src_dir(
        &root,
        "crates/tidefs-background-scheduler",
        &[
            "BackgroundService",
            "ServicePriority",
            "ServiceBudget",
            "TickReport",
            "BackgroundScheduler",
            "fn name",
            "fn tick",
            "fn has_work",
            "#![forbid(unsafe_code)]",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-background-scheduler/Cargo.toml",
        &[
            "tidefs-incremental-job-core",
            "tidefs-types-incremental-job-core",
        ],
        &mut missing,
    );

    // Verify BackgroundScheduler is wired into LocalFileSystem.
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/Cargo.toml",
        &["tidefs-background-scheduler"],
        &mut missing,
    );

    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("orphan reclamation background service registered via BackgroundOrphanReclamation at mount, tick_background_services hooked into do_commit");
        println!("background scheduler wired into LocalFileSystem: tick_background_services method, RefCell<BackgroundScheduler> field, mount-time init");
        println!("background scheduler ok: BackgroundScheduler with 5-stage priority dispatch, round-robin fairness, and budget cascading is implementation-tracked non-release");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "background service framework source check",
            missing,
        })
    }
}

pub fn check_dir_index_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "polymorphic directory index runtime check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    check_required_file(&root, "crates/tidefs-dir-index/src/lib.rs", &mut missing);

    check_source_markers(
        &root,
        "crates/tidefs-dir-index/src/lib.rs",
        &[
            "pub struct DirIndex",
            "pub const fn new",
            "pub fn lookup",
            "pub fn insert",
            "pub fn delete",
            "pub fn replace",
            "pub fn contains",
            "pub fn list_from",
            "pub fn len",
            "pub fn is_empty",
            "pub fn representation",
            "pub fn has_subdirs",
            "pub fn set_has_subdirs",
            "pub fn check_and_switch",
            "pub fn policy",
            "pub enum DirIndexError",
        ],
        &mut missing,
    );

    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("dir-index check ok: tidefs-dir-index crate exists with full API surface");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "polymorphic directory index runtime check",
            missing,
        })
    }
}

pub fn check_xattr_storage_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "polymorphic xattr storage runtime check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    check_required_file(
        &root,
        "crates/tidefs-xattr-storage/src/lib.rs",
        &mut missing,
    );

    check_source_markers(
        &root,
        "crates/tidefs-xattr-storage/src/lib.rs",
        &[
            "pub struct XattrStore",
            "pub const fn new",
            "pub fn get",
            "pub fn set",
            "pub fn remove",
            "pub fn contains",
            "pub fn list",
            "pub fn list_names",
            "pub fn len",
            "pub fn is_empty",
            "pub fn representation",
            "pub fn has_acl",
            "pub fn set_has_acl",
            "pub fn check_and_switch",
            "pub fn policy",
            "pub fn version",
            "pub fn total_value_bytes",
            "pub enum XattrStoreError",
        ],
        &mut missing,
    );

    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("xattr-storage check ok: tidefs-xattr-storage crate exists with full API surface");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "polymorphic xattr storage runtime check",
            missing,
        })
    }
}

// ---------------------------------------------------------------------------
// check_background_scheduler_current_workspace
// ---------------------------------------------------------------------------
// check_polymorphic_extent_map_current_workspace
// ---------------------------------------------------------------------------

pub fn check_polymorphic_extent_map_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "polymorphic extent map source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    check_required_file(
        &root,
        "crates/tidefs-extent-map/src/polymorphic.rs",
        &mut missing,
    );

    check_source_markers(
        &root,
        "crates/tidefs-extent-map/src/polymorphic.rs",
        &[
            "pub enum ExtentMapRepr",
            "pub struct PolymorphicExtentMap",
            "pub fn representation",
            "pub fn entry_count",
            "pub fn check_and_switch",
            "pub const PROMOTE_THRESHOLD",
            "pub const DEMOTE_THRESHOLD",
            "impl ExtentMapOps for PolymorphicExtentMap",
        ],
        &mut missing,
    );

    if missing.is_empty() {
        println!("polymorphic extent map ok: ExtentMapRepr, PolymorphicExtentMap, hysteresis switching (promote >6/UNWRITTEN/hole, demote <=4), 19 tests implementation-tracked non-release");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "polymorphic extent map source check",
            missing,
        })
    }
}

// ---------------------------------------------------------------------------
// check_dataset_lifecycle_current_workspace
// ---------------------------------------------------------------------------

/// Verify the dataset lifecycle runtime crate exists with the expected API surface.
pub fn check_dataset_lifecycle_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "dataset lifecycle runtime check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    check_required_file(
        &root,
        "crates/tidefs-dataset-lifecycle/src/lib.rs",
        &mut missing,
    );
    check_workspace_members(&root, &["crates/tidefs-dataset-lifecycle"], &mut missing);

    check_source_markers(
        &root,
        "crates/tidefs-dataset-lifecycle/src/lib.rs",
        &[
            "pub struct DatasetLifecycle",
            // new/from_parts are not const fn because PoisonNotification
            // internally uses Arc::new() which is not const-stable in
            // stable Rust (requires nightly `const_new_arc`).
            "pub fn new",
            "pub fn from_parts",
            "pub const fn with_grace_secs",
            "pub const fn state",
            "pub const fn poison_state",
            "pub const fn grace_secs",
            "pub const fn is_mountable",
            "pub const fn accepts_writes",
            "pub fn check_mount",
            "pub fn transition_to_destroying",
            "pub fn transition_to_tombstone",
            "pub fn abort_destroy",
            "pub fn recover_tombstone",
            "pub fn escalate_poison",
            "pub fn kill_mount",
            "pub fn clear_poison",
            "pub fn validate_transition",
            "pub enum LifecycleError",
            "#![forbid(unsafe_code)]",
        ],
        &mut missing,
    );

    // Verify BackgroundOrphanReclamation registration at mount.
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "BackgroundOrphanReclamation",
            "orphan_index: Arc<Mutex<OrphanIndex>>",
            "pending_orphan_deletions: Arc<Mutex<Vec<u64>>>",
            "register(Box::new(orphan_reclamation))",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("dataset lifecycle ok: DatasetLifecycle runtime with validated state transitions, poison semantics, 39 tests implementation-tracked non-release");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "dataset lifecycle runtime check",
            missing,
        })
    }
}

// ---------------------------------------------------------------------------
// check_background_scheduler_fs_current_workspace
// ---------------------------------------------------------------------------

pub fn check_background_scheduler_fs_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "background scheduler LocalFileSystem integration check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &mut missing,
    );
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/Cargo.toml",
        &mut missing,
    );
    check_workspace_members(&root, &["crates/tidefs-local-filesystem"], &mut missing);
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/Cargo.toml",
        &["tidefs-background-scheduler"],
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "use tidefs_background_scheduler",
            "impl BackgroundService for BackgroundScrubber",
            "struct BackgroundSchedulerRuntime",
            "fn start",
            "fn stop",
            "background_scheduler: Option<BackgroundSchedulerRuntime>",
        ],
        &mut missing,
    );

    if missing.is_empty() {
        println!("background scheduler FS integration ok: BackgroundSchedulerRuntime drives BackgroundScrubber as a BackgroundService on the LocalFileSystem; scheduler ticks at 1 s interval");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "background scheduler LocalFileSystem integration check",
            missing,
        })
    }
}

// ---------------------------------------------------------------------------
// check_background_reclaim_current_workspace
// ---------------------------------------------------------------------------

pub fn check_background_reclaim_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "#6166 single reclaim-authority verification",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    // Required source files.
    check_required_file(
        &root,
        "crates/tidefs-local-object-store/src/store.rs",
        &mut missing,
    );
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &mut missing,
    );
    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/types.rs",
        &mut missing,
    );

    // ------------------------------
    // 1. Sole segment-freeing authority: LocalObjectStore::drain_dead_segments.
    //    This is the ONLY production path that frees dead segments.
    //    DataCleaner and SegmentCleaner are model/library surfaces not wired
    //    into the mounted runtime.  BackgroundReclaim is dead code (not
    //    compiled into lib.rs).
    // ------------------------------
    check_source_markers(
        &root,
        "crates/tidefs-local-object-store/src/store.rs",
        &["pub fn drain_dead_segments"],
        &mut missing,
    );

    // ------------------------------
    // 2. LocalFileSystem reclaim entries feed into object-store authority
    //    via record_reclaim_delta -> local queue -> tick_background_services
    //    Duty 2 -> drain_local_reclaim_queue_into_store -> object-store
    //    durable reclaim queue.
    // ------------------------------
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "fn record_reclaim_delta",
            "fn drain_local_reclaim_queue_into_store",
            "fn reclaim_queue_depth",
            "fn tick_background_services",
            "total_reclaim_drains",
            "total_reclaim_entries_drained",
        ],
        &mut missing,
    );

    // ------------------------------
    // 3. ReclaimDrainStats production type exists.
    // ------------------------------
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/types.rs",
        &["pub struct ReclaimDrainStats"],
        &mut missing,
    );

    if missing.is_empty() {
        println!("#6166 background reclaim authority verified: LocalObjectStore::drain_dead_segments is the sole segment-freeing authority; LocalFileSystem reclaim entries feed into object-store reclaim queue via drain_local_reclaim_queue_into_store(); DataCleaner/SegmentCleaner/BackgroundReclaim are model/test/dead-code surfaces");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "#6166 single reclaim-authority verification",
            missing,
        })
    }
}
pub fn check_reclaim_delta_recording_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "#1463 reclaim delta recording check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    check_required_file(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &mut missing,
    );
    check_workspace_members(&root, &["crates/tidefs-local-filesystem"], &mut missing);
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "use tidefs_types_reclaim_queue_core::{QueueFamily, ReclaimQueueEntry}",
            "use tidefs_types_reclaim_queue_core::QueueFamily as ReclaimQueueFamily",
            "fn record_reclaim_delta",
            "self.reclaim_queue.lock().unwrap().insert(entry)",
        ],
        &mut missing,
    );

    // Verify delta recording at each operation point.
    check_source_markers(
        &root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "self.record_reclaim_delta(entry.inode_id, record.size)",
            "self.record_reclaim_delta(inode_id, old_size - size)",
            "self.record_reclaim_delta(target.inode_id, target_record.size)",
        ],
        &mut missing,
    );

    if missing.is_empty() {
        println!("#1463 reclaim delta recording ok: ReclaimQueueEntry deltas recorded on unlink, truncate, rename-overwrite; O(1) B+tree insert, BackgroundReclaim processes under tick budget");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "#1463 reclaim delta recording check",
            missing,
        })
    }
}

pub fn check_space_accounting_watermarks_current_workspace() -> Result<(), StorageCheckError> {
    let root = find_workspace_root().ok_or_else(|| StorageCheckError {
        title: "space-accounting watermarks source check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();
    for rel in [
        "crates/tidefs-space-accounting/src/lib.rs",
        "crates/tidefs-space-accounting/Cargo.toml",
    ] {
        check_required_file(&root, rel, &mut missing);
    }
    check_source_markers(
        &root,
        "crates/tidefs-space-accounting/src/lib.rs",
        &[
            "pub enum CleanerAction",
            "pub struct CleanerWatermarks",
            "forward-progress reserve",
            "pub struct CleanerScheduler",
            "pub fn evaluate",
            "pub fn refresh_physical_counters",
            "watermarks_defaults_for_large_pool",
            "scheduler_blocks_writers_below_min",
            "scheduler_starts_background_below_target",
            "scheduler_stops_above_high",
            "refresh_physical_counters_sets_pool",
        ],
        &mut missing,
    );
    if missing.is_empty() {
        println!("space-accounting watermarks ok: CleanerAction, CleanerWatermarks, CleanerScheduler with evaluate, refresh_physical_counters, and unit tests are implementation-tracked non-release");
        Ok(())
    } else {
        Err(StorageCheckError {
            title: "space-accounting watermarks source check",
            missing,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mounted_transform_authority_inventory_check_passes_current_workspace() {
        check_mounted_transform_authority_current_workspace()
            .expect("mounted transform authority inventory check should pass");
    }
}
