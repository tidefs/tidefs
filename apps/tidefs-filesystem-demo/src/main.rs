// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]
#[allow(dead_code)]
mod mount;

use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_filesystem::human::local_filesystem::{
    audit_recovery_with_root_authentication_key, no_production_fsck_failure_model_cases,
    posix_subset_entries, run_crash_recovery_matrix_with_root_authentication_key,
    ChangedRecordExport, CrashInjectionBoundary, LocalFilesystem, RootAuthenticationKey,
    RootRetentionPolicy, StoreOptions, FILESYSTEM_CONTENT_CHUNK_SIZE,
    FILESYSTEM_CONTENT_OBJECT_PREFIX, FILESYSTEM_FORMAT_VERSION, FILESYSTEM_ROOT_OBJECT_PREFIX,
    FILESYSTEM_ROOT_SLOT_COUNT, FILESYSTEM_SUPERBLOCK_OBJECT_NAME,
    FILESYSTEM_TRANSACTION_OBJECT_PREFIX, FORMAL_NO_PRODUCTION_FSCK_FAILURE_MODEL,
    LOCAL_SNAPSHOT_ROLLBACK_SPEC, LOCAL_STORAGE_ALLOCATOR_GRAIN_BYTES,
    LOCAL_STORAGE_ALLOCATOR_SPEC, MOUNT_INVARIANT_GATE_IS_NOT_FSCK, ONLINE_VERIFIER_IS_NOT_FSCK,
    ONLINE_VERIFIER_SPEC, POSIX_SUBSET_POLICY_VERSION, POSIX_SUBSET_SPEC,
    PRODUCTION_RECOVERY_DOCTRINE, RECOVERY_AUDIT_IS_NOT_FSCK, RETENTION_RECLAMATION_IS_NOT_FSCK,
    ROOT_AUTHENTICATION_ALGORITHM_SUITE_ID, ROOT_AUTHENTICATION_CODE_LEN,
    ROOT_AUTHENTICATION_DIGEST_LEN, ROOT_AUTHENTICATION_ENV_VAR, ROOT_AUTHENTICATION_KEY_LEN,
    ROOT_AUTHENTICATION_MAGIC_ASCII, ROOT_AUTHENTICATION_POLICY_EPOCH,
    ROOT_AUTHENTICATION_RECORD_VERSION, ROOT_AUTHENTICATION_SPEC, SAFE_LOCAL_RECLAMATION_GC_SPEC,
    SEND_RECEIVE_CHANGED_RECORD_SPEC, SEND_RECEIVE_STREAM_MAGIC_ASCII, SEND_RECEIVE_STREAM_VERSION,
    SNAPSHOT_CATALOG_MAGIC_ASCII,
};

fn main() -> Result<(), Box<dyn Error>> {
    let (root, ephemeral) = demo_root();
    if ephemeral {
        let _ = fs::remove_dir_all(&root);
    }

    println!("tidefs local filesystem MVP demo");
    println!("filesystem_root={}", root.display());
    println!("wire_v0390_fixed_superblock_object_name={FILESYSTEM_SUPERBLOCK_OBJECT_NAME}");
    println!("root_slot_object_prefix={FILESYSTEM_ROOT_OBJECT_PREFIX}");
    println!("transaction_object_prefix={FILESYSTEM_TRANSACTION_OBJECT_PREFIX}");
    println!("versioned_content_object_prefix={FILESYSTEM_CONTENT_OBJECT_PREFIX}");
    println!("content_layout.chunk_size={FILESYSTEM_CONTENT_CHUNK_SIZE}");
    println!("content_layout.manifest_object=versioned-content-object");
    println!("content_layout.chunk_objects=versioned-content-chunks");
    println!("filesystem_format_version={FILESYSTEM_FORMAT_VERSION}");
    println!("recovery_model={PRODUCTION_RECOVERY_DOCTRINE}");
    println!("formal_failure_model={FORMAL_NO_PRODUCTION_FSCK_FAILURE_MODEL}");
    println!("recovery_audit_law={RECOVERY_AUDIT_IS_NOT_FSCK}");
    println!("mount_invariant_gate_law={MOUNT_INVARIANT_GATE_IS_NOT_FSCK}");
    println!("retention_reclamation_law={RETENTION_RECLAMATION_IS_NOT_FSCK}");
    println!("local_storage_allocator.spec={LOCAL_STORAGE_ALLOCATOR_SPEC}");
    println!("local_storage_allocator.grain_bytes={LOCAL_STORAGE_ALLOCATOR_GRAIN_BYTES}");
    println!("safe_local_reclamation.spec={SAFE_LOCAL_RECLAMATION_GC_SPEC}");
    println!("snapshot_rollback.spec={LOCAL_SNAPSHOT_ROLLBACK_SPEC}");
    println!("snapshot_rollback.catalog_magic={SNAPSHOT_CATALOG_MAGIC_ASCII}");
    println!("send_receive.spec={SEND_RECEIVE_CHANGED_RECORD_SPEC}");
    println!("send_receive.stream_magic={SEND_RECEIVE_STREAM_MAGIC_ASCII}");
    println!("send_receive.stream_version={SEND_RECEIVE_STREAM_VERSION}");
    println!("online_verifier.spec={ONLINE_VERIFIER_SPEC}");
    println!("online_verifier.law={ONLINE_VERIFIER_IS_NOT_FSCK}");
    let root_authentication_key = RootAuthenticationKey::demo_key();
    println!("root_authentication.spec={ROOT_AUTHENTICATION_SPEC}");
    println!("root_authentication.env_var={ROOT_AUTHENTICATION_ENV_VAR}");
    println!("root_authentication.demo_key=explicit-fixture");
    println!("root_authentication.magic={ROOT_AUTHENTICATION_MAGIC_ASCII}");
    println!("root_authentication.record_version={ROOT_AUTHENTICATION_RECORD_VERSION}");
    println!("root_authentication.algorithm_suite_id={ROOT_AUTHENTICATION_ALGORITHM_SUITE_ID}");
    println!("root_authentication.policy_epoch={ROOT_AUTHENTICATION_POLICY_EPOCH}");
    println!("root_authentication.key_bytes={ROOT_AUTHENTICATION_KEY_LEN}");
    println!("root_authentication.digest_bytes={ROOT_AUTHENTICATION_DIGEST_LEN}");
    println!("root_authentication.code_bytes={ROOT_AUTHENTICATION_CODE_LEN}");
    println!("posix_subset_spec={POSIX_SUBSET_SPEC}");
    println!("posix_subset.policy_version={POSIX_SUBSET_POLICY_VERSION}");
    println!("root_slot_count={FILESYSTEM_ROOT_SLOT_COUNT}");
    let posix_subset = posix_subset_entries();
    println!("posix_subset.entries={}", posix_subset.len());
    for entry in posix_subset {
        println!(
            "posix_subset.entry topic={} operation={} support={} errno={} rule={}",
            entry.topic.stable_id(),
            entry.operation,
            entry.support.stable_id(),
            entry.errno,
            entry.rule
        );
    }
    let failure_model = no_production_fsck_failure_model_cases();
    println!("no_fsck_failure_model.cases={}", failure_model.len());
    for case in failure_model {
        println!(
            "no_fsck_failure_model.case class={} expected={} production_fsck_required={}",
            case.failure_class.stable_id(),
            case.expected_recovery.human_name(),
            case.production_fsck_required
        );
    }
    println!(
        "crash_injection_boundaries={}",
        CrashInjectionBoundary::ALL.len()
    );
    let crash_matrix_root = temp_named_root("tidefs-filesystem-crash-matrix");
    let _ = fs::remove_dir_all(&crash_matrix_root);
    let crash_matrix = run_crash_recovery_matrix_with_root_authentication_key(
        &crash_matrix_root,
        StoreOptions::test_fast(),
        root_authentication_key,
    )?;
    println!("crash_matrix.root={}", crash_matrix_root.display());
    println!("crash_matrix.passed={}", crash_matrix.passed());
    println!(
        "crash_matrix.cases_executed={}",
        crash_matrix.cases_executed()
    );
    println!(
        "crash_matrix.boundary_cases={}",
        crash_matrix.boundary_cases.len()
    );
    println!(
        "crash_matrix.previous_root_cases={}",
        crash_matrix.previous_root_cases()
    );
    println!(
        "crash_matrix.new_root_cases={}",
        crash_matrix.new_root_cases()
    );
    println!(
        "crash_matrix.explicit_error_observed={}",
        crash_matrix.explicit_error_case.observed.human_name()
    );
    for case in &crash_matrix.boundary_cases {
        println!(
            "crash_matrix.case boundary={} expected={} observed={} production_fsck_required={}",
            case.boundary.stable_id(),
            case.expected.human_name(),
            case.observed.human_name(),
            case.production_fsck_required
        );
    }
    run_safe_reclamation_demo(root_authentication_key)?;
    run_snapshot_reclamation_demo(root_authentication_key)?;
    run_send_receive_demo(root_authentication_key)?;

    let preflight = LocalFilesystem::probe_recovery_with_root_authentication_key(
        &root,
        StoreOptions::default(),
        root_authentication_key,
    )?;
    println!(
        "recovery_probe.preflight_outcome={}",
        preflight.outcome.human_name()
    );
    println!(
        "recovery_probe.preflight_mountable_without_operator_repair={}",
        preflight.mountable_without_operator_repair()
    );
    println!(
        "recovery_probe.production_requires_operator_repair={}",
        preflight.production_recovery_requires_operator_repair()
    );

    let mut fs = LocalFilesystem::open_with_root_authentication_key(
        &root,
        StoreOptions::default(),
        root_authentication_key,
    )?;
    let initial_stats = fs.stats();
    println!(
        "initial.filesystem_generation={}",
        initial_stats.filesystem_generation
    );
    println!("initial.inode_count={}", initial_stats.inode_count);

    let docs = fs.create_dir("/docs", 0o755)?;
    println!("create_dir.path=/docs");
    println!("create_dir.inode={}", docs.inode_id.get());

    let created = fs.create_file("/docs/readme.txt", 0o644)?;
    println!("create_file.path=/docs/readme.txt");
    println!("create_file.inode={}", created.inode_id.get());

    let written = fs.write_file(
        "/docs/readme.txt",
        0,
        b"hello from the TideFS local filesystem",
    )?;
    println!("write1.inode={}", written.inode_id.get());
    println!("write1.size={}", written.size);
    println!("write1.data_version={}", written.data_version);

    let appended = fs.write_file(
        "/docs/readme.txt",
        written.size,
        b"; reopen replay should preserve this",
    )?;
    println!("write2.size={}", appended.size);
    println!("write2.data_version={}", appended.data_version);

    let link = fs.link_file("/docs/readme.txt", "/docs/readme.link")?;
    println!("hard_link.path=/docs/readme.link");
    println!("hard_link.inode={}", link.inode_id.get());
    println!("hard_link.nlink={}", link.nlink);

    let symlink = fs.create_symlink("/docs/current", b"readme.txt")?;
    println!("symlink.path=/docs/current");
    println!("symlink.inode={}", symlink.inode_id.get());

    fs.rename("/docs/readme.txt", "/docs/README.txt", false)?;
    println!("rename.from=/docs/readme.txt");
    println!("rename.to=/docs/README.txt");

    let immediate = fs.read_file("/docs/README.txt")?;
    println!(
        "read.immediate_utf8={}",
        String::from_utf8_lossy(&immediate)
    );
    let cached = fs.read_file("/docs/README.txt")?;
    let hot_read_cache = fs.hot_read_cache_report();
    println!("hot_read_cache.spec={}", hot_read_cache.spec);
    println!(
        "hot_read_cache.repeated_read_matches={}",
        cached == immediate
    );
    println!("hot_read_cache.hits={}", hot_read_cache.hits);
    println!("hot_read_cache.misses={}", hot_read_cache.misses);
    println!("hot_read_cache.insertions={}", hot_read_cache.insertions);
    println!("hot_read_cache.evictions={}", hot_read_cache.evictions);
    println!(
        "hot_read_cache.invalidations={}",
        hot_read_cache.invalidations
    );
    println!(
        "hot_read_cache.admission_bypasses={}",
        hot_read_cache.admission_bypasses
    );
    println!(
        "hot_read_cache.resident_entries={}",
        hot_read_cache.resident_entries
    );
    println!(
        "hot_read_cache.resident_bytes={}",
        hot_read_cache.resident_bytes
    );
    println!("hot_read_cache.max_entries={}", hot_read_cache.max_entries);
    println!("hot_read_cache.max_bytes={}", hot_read_cache.max_bytes);
    println!("hot_read_cache.is_bounded={}", hot_read_cache.is_bounded());
    let snapshot = fs.create_snapshot("demo-before-rollback")?;
    println!("snapshot.create.name={}", snapshot.name);
    println!(
        "snapshot.create.source_generation={}",
        snapshot.source_generation
    );
    println!(
        "snapshot.create.created_at_generation={}",
        snapshot.created_at_generation
    );
    fs.replace_file("/docs/README.txt", b"temporary post-snapshot content")?;
    println!(
        "snapshot.post_snapshot_utf8={}",
        String::from_utf8_lossy(&fs.read_file("/docs/README.txt")?)
    );
    let rollback = fs.rollback_to_snapshot("demo-before-rollback")?;
    println!("snapshot.rollback.name={}", rollback.snapshot.name);
    println!(
        "snapshot.rollback.restored_source_generation={}",
        rollback.restored_source_generation
    );
    println!(
        "snapshot.rollback.published_generation={}",
        rollback.published_generation
    );
    println!(
        "snapshot.rollback.catalog_entries={}",
        rollback.snapshot_catalog_entries
    );
    println!(
        "snapshot.after_rollback_utf8={}",
        String::from_utf8_lossy(&fs.read_file("/docs/README.txt")?)
    );
    println!(
        "readlink.current_utf8={}",
        String::from_utf8_lossy(&fs.read_symlink("/docs/current")?)
    );
    let stats = fs.stats();
    println!(
        "stats.filesystem_generation={}",
        stats.filesystem_generation
    );
    println!("stats.inode_count={}", stats.inode_count);
    println!("stats.directory_count={}", stats.directory_count);
    println!("stats.file_count={}", stats.file_count);
    println!("stats.symlink_count={}", stats.symlink_count);
    println!("stats.snapshot_count={}", stats.snapshot_count);
    println!(
        "stats.object_store_live_objects={}",
        stats.object_store.live_objects
    );
    let allocator_report = fs.allocator_report()?;
    println!(
        "allocator_report.current_namespace_allocated_bytes={}",
        allocator_report.current_namespace_allocated_bytes
    );
    println!(
        "allocator_report.protected_committed_root_allocated_bytes={}",
        allocator_report.protected_committed_root_allocated_bytes
    );
    println!(
        "allocator_report.allocator_reserved_bytes={}",
        allocator_report.allocator_reserved_bytes
    );
    println!(
        "allocator_report.pending_free_bytes={}",
        allocator_report.pending_free_bytes
    );
    println!(
        "allocator_report.reusable_free_bytes={}",
        allocator_report.reusable_free_bytes
    );
    println!(
        "allocator_report.free_inodes={}",
        allocator_report.free_inodes
    );
    let online_verifier = fs.online_verifier_report()?;
    println!(
        "online_verifier.outcome={}",
        online_verifier.outcome.human_name()
    );
    println!(
        "online_verifier.verified_committed_roots={}",
        online_verifier.verified_committed_roots.len()
    );
    println!(
        "online_verifier.issue_count={}",
        online_verifier.issue_count()
    );
    println!(
        "online_verifier.checked_content_chunks={}",
        online_verifier.checked_content_chunks
    );
    println!(
        "online_verifier.verified_snapshot_roots={}",
        online_verifier.verified_snapshot_roots
    );
    println!(
        "online_verifier.mutating_repair_attempted={}",
        online_verifier.mutating_repair_attempted
    );
    println!(
        "online_verifier.production_requires_operator_repair={}",
        online_verifier.production_recovery_requires_operator_repair()
    );
    let statfs = fs.statfs()?;
    println!("statfs.blocks={}", statfs.blocks);
    println!("statfs.bfree={}", statfs.bfree);
    println!("statfs.bavail={}", statfs.bavail);
    println!("statfs.files={}", statfs.files);
    println!("statfs.ffree={}", statfs.ffree);
    let invariant_report = fs.mount_invariant_report()?;
    println!(
        "mount_invariant.inode_count={}",
        invariant_report.inode_count
    );
    println!(
        "mount_invariant.reachable_inode_count={}",
        invariant_report.reachable_inode_count
    );
    println!(
        "mount_invariant.directory_entry_count={}",
        invariant_report.directory_entry_count
    );
    println!(
        "mount_invariant.hard_link_edge_count={}",
        invariant_report.hard_link_edge_count
    );
    println!(
        "mount_invariant.production_fsck_required={}",
        invariant_report.production_fsck_required
    );
    let live_audit = fs.recovery_audit()?;
    println!(
        "recovery_audit.live_outcome={}",
        live_audit.outcome.human_name()
    );
    println!(
        "recovery_audit.live_checked_transaction_manifests={}",
        live_audit.checked_transaction_manifests
    );
    println!(
        "recovery_audit.production_fsck_required={}",
        live_audit.production_fsck_required
    );
    let retention = fs.root_retention_plan(RootRetentionPolicy::safe_default())?;
    println!(
        "retention_plan.policy_required_committed_roots={}",
        retention.retention_debt.policy_required_committed_roots
    );
    println!(
        "retention_plan.valid_committed_roots_available={}",
        retention.retention_debt.valid_committed_roots_available
    );
    println!(
        "retention_plan.missing_committed_roots={}",
        retention.retention_debt.missing_committed_roots
    );
    println!(
        "retention_plan.has_retention_debt={}",
        retention.has_retention_debt()
    );
    println!(
        "retention_plan.protected_committed_roots={}",
        retention.protected_committed_roots.len()
    );
    println!(
        "retention_plan.protected_object_keys={}",
        retention.protected_object_keys.len()
    );
    println!(
        "retention_plan.protected_root_slot_locations={}",
        retention.protected_root_slot_locations.len()
    );
    println!(
        "retention_plan.reclaimable_live_object_keys={}",
        retention.reclaimable_live_object_keys.len()
    );
    println!(
        "retention_plan.mutating_reclamation_allowed={}",
        retention.mutating_reclamation_allowed
    );
    println!(
        "retention_plan.production_fsck_required={}",
        retention.production_fsck_required
    );
    drop(fs);

    let recovery = LocalFilesystem::probe_recovery_with_root_authentication_key(
        &root,
        StoreOptions::default(),
        root_authentication_key,
    )?;
    println!("recovery_probe.outcome={}", recovery.outcome.human_name());
    println!(
        "recovery_probe.root_slot_records_seen={}",
        recovery.root_slot_records_seen
    );
    println!(
        "recovery_probe.valid_committed_roots_seen={}",
        recovery.valid_committed_roots_seen
    );
    println!(
        "recovery_probe.skipped_root_candidates={}",
        recovery.skipped_root_candidates
    );
    println!(
        "recovery_probe.selected_transaction_id={:?}",
        recovery.selected_transaction_id
    );
    println!(
        "recovery_probe.selected_generation={:?}",
        recovery.selected_generation
    );
    println!(
        "recovery_probe.repaired_tail_bytes={}",
        recovery.object_store_repaired_tail_bytes
    );
    let audit = audit_recovery_with_root_authentication_key(
        &root,
        StoreOptions::default(),
        root_authentication_key,
    )?;
    println!("recovery_audit.outcome={}", audit.outcome.human_name());
    println!(
        "recovery_audit.root_candidates_seen={}",
        audit.root_candidates_seen
    );
    println!(
        "recovery_audit.valid_committed_roots={}",
        audit.valid_committed_roots.len()
    );
    println!(
        "recovery_audit.checked_transaction_manifests={}",
        audit.checked_transaction_manifests
    );
    println!(
        "recovery_audit.selected_generation={:?}",
        audit.selected_root.as_ref().map(|root| root.generation)
    );

    let reopened = LocalFilesystem::open_with_root_authentication_key(
        &root,
        StoreOptions::default(),
        root_authentication_key,
    )?;
    let replayed = reopened.read_file("/docs/README.txt")?;
    let reopened_invariants = reopened.mount_invariant_report()?;
    println!(
        "replay.filesystem_generation={}",
        reopened.stats().filesystem_generation
    );
    println!(
        "replay.mount_invariant_reachable={}",
        reopened_invariants.reachable_inode_count == reopened_invariants.inode_count
    );
    println!(
        "read.after_reopen_utf8={}",
        String::from_utf8_lossy(&replayed)
    );
    for entry in reopened.list_dir("/docs")? {
        println!(
            "dir.docs.entry name={} inode={} kind={:?}",
            entry.name_lossy(),
            entry.inode_id.get(),
            entry.kind()
        );
    }

    Ok(())
}

fn run_safe_reclamation_demo(
    root_authentication_key: RootAuthenticationKey,
) -> Result<(), Box<dyn Error>> {
    let root = temp_named_root("tidefs-filesystem-safe-reclamation");
    let _ = fs::remove_dir_all(&root);
    let mut fs = LocalFilesystem::open_with_root_authentication_key(
        &root,
        StoreOptions::test_fast(),
        root_authentication_key,
    )?;
    fs.create_file("/data.bin", 0o644)?;
    let mut expected = Vec::new();
    for round in 0..20_u8 {
        expected = vec![round; FILESYSTEM_CONTENT_CHUNK_SIZE];
        fs.write_file("/data.bin", 0, &expected)?;
    }
    fs.sync_all()?;
    let before = fs.object_store().stats();
    let report = fs.safe_reclaim_unprotected_objects()?;
    println!("safe_reclamation.root={}", root.display());
    println!(
        "safe_reclamation.retention_policy_satisfied={}",
        report.retention_policy_satisfied()
    );
    println!(
        "safe_reclamation.mutating_reclamation_allowed={}",
        report.mutating_reclamation_allowed
    );
    println!(
        "safe_reclamation.production_fsck_required={}",
        report.production_fsck_required
    );
    println!(
        "safe_reclamation.protected_committed_roots_preserved={}",
        report.protected_committed_roots_preserved
    );
    println!(
        "safe_reclamation.protected_root_slot_locations_preserved={}",
        report.protected_root_slot_locations_preserved
    );
    println!(
        "safe_reclamation.copied_protected_objects={}",
        report.store.copied_protected_objects
    );
    println!(
        "safe_reclamation.tombstoned_unprotected_keys={}",
        report.store.tombstoned_unprotected_keys
    );
    println!(
        "safe_reclamation.retired_segments={}",
        report.store.retired_segments.len()
    );
    println!(
        "safe_reclamation.segment_count_before={}",
        report.store.segment_count_before
    );
    println!(
        "safe_reclamation.segment_count_after={}",
        report.store.segment_count_after
    );
    println!(
        "safe_reclamation.live_objects_before={}",
        report.store.live_objects_before
    );
    println!(
        "safe_reclamation.live_objects_after={}",
        report.store.live_objects_after
    );
    println!(
        "safe_reclamation.exact_locations_preserved={}",
        report.store.exact_locations_preserved
    );
    println!(
        "safe_reclamation.selected_generation_after={:?}",
        report.selected_generation_after
    );
    println!(
        "safe_reclamation.pre_reclaim_segment_count={}",
        before.segment_count
    );
    drop(fs);

    let reopened = LocalFilesystem::open_with_root_authentication_key(
        &root,
        StoreOptions::test_fast(),
        root_authentication_key,
    )?;
    println!(
        "safe_reclamation.reopen_read_matches={}",
        reopened.read_file("/data.bin")? == expected
    );
    let _ = fs::remove_dir_all(&root);
    Ok(())
}

fn run_snapshot_reclamation_demo(
    root_authentication_key: RootAuthenticationKey,
) -> Result<(), Box<dyn Error>> {
    let root = temp_named_root("tidefs-filesystem-snapshot-reclamation");
    let _ = fs::remove_dir_all(&root);
    let mut fs = LocalFilesystem::open_with_root_authentication_key(
        &root,
        StoreOptions::test_fast(),
        root_authentication_key,
    )?;
    fs.create_file("/data.bin", 0o644)?;
    fs.write_file("/data.bin", 0, b"snapshot-retained-by-gc")?;
    fs.sync_all()?;
    let snapshot = fs.create_snapshot("gc-safe")?;
    for round in 0..8_u8 {
        let payload = vec![round; FILESYSTEM_CONTENT_CHUNK_SIZE];
        fs.replace_file("/data.bin", &payload)?;
    }
    let plan = fs.root_retention_plan(RootRetentionPolicy::safe_default())?;
    println!("snapshot_reclamation.root={}", root.display());
    println!(
        "snapshot_reclamation.snapshot_source_generation={}",
        snapshot.source_generation
    );
    println!(
        "snapshot_reclamation.protects_snapshot_root={}",
        plan.protected_committed_roots
            .iter()
            .any(|root| root == &snapshot.source_root)
    );
    println!(
        "snapshot_reclamation.protected_committed_roots={}",
        plan.protected_committed_roots.len()
    );
    let report = fs.safe_reclaim_unprotected_objects()?;
    println!(
        "snapshot_reclamation.exact_locations_preserved={}",
        report.store.exact_locations_preserved
    );
    let rollback = fs.rollback_to_snapshot("gc-safe")?;
    println!(
        "snapshot_reclamation.rollback_published_generation={}",
        rollback.published_generation
    );
    println!(
        "snapshot_reclamation.rollback_read_matches={}",
        fs.read_file("/data.bin")? == b"snapshot-retained-by-gc".to_vec()
    );
    let _ = fs::remove_dir_all(&root);
    Ok(())
}

fn run_send_receive_demo(source_key: RootAuthenticationKey) -> Result<(), Box<dyn Error>> {
    let source_root = temp_named_root("tidefs-filesystem-send-receive-source");
    let target_root = temp_named_root("tidefs-filesystem-send-receive-target");
    let _ = fs::remove_dir_all(&source_root);
    let _ = fs::remove_dir_all(&target_root);
    let target_key = RootAuthenticationKey::from_bytes32([0x52_u8; ROOT_AUTHENTICATION_KEY_LEN]);

    let mut source = LocalFilesystem::open_with_root_authentication_key(
        &source_root,
        StoreOptions::test_fast(),
        source_key,
    )?;
    source.create_file("/replica.bin", 0o644)?;
    source.write_file("/replica.bin", 0, b"send-receive-baseline")?;
    source.sync_all()?;
    source.create_snapshot("send-baseline")?;
    source.replace_file("/replica.bin", b"send-receive-current")?;
    let export = source.export_changed_records()?;
    let encoded = export.encode();
    let decoded = ChangedRecordExport::decode(&encoded)?;
    let report =
        LocalFilesystem::receive_changed_records_into_empty_root_with_root_authentication_key(
            &target_root,
            StoreOptions::test_fast(),
            &decoded,
            target_key,
            [0u8; 16],
            [0u8; 16],
            None,
        )?;
    let mut received = LocalFilesystem::open_with_root_authentication_key(
        &target_root,
        StoreOptions::test_fast(),
        target_key,
    )?;
    println!("send_receive.source_root={}", source_root.display());
    println!("send_receive.target_root={}", target_root.display());
    println!("send_receive.export_roots={}", export.roots.len());
    println!("send_receive.export_records={}", export.total_records);
    println!("send_receive.export_payload_bytes={}", export.payload_bytes);
    println!("send_receive.encoded_bytes={}", encoded.len());
    println!("send_receive.imported_roots={}", report.imported_roots);
    println!("send_receive.imported_records={}", report.imported_records);
    println!(
        "send_receive.staging_validated_before_publish={}",
        report.staging_validated_before_publish
    );
    println!(
        "send_receive.destination_root_reauthentication={}",
        report.destination_root_reauthentication
    );
    println!(
        "send_receive.snapshot_catalog_entries={}",
        report.snapshot_catalog_entries
    );
    println!(
        "send_receive.current_read_matches={}",
        received.read_file("/replica.bin")? == b"send-receive-current".to_vec()
    );
    received.rollback_to_snapshot("send-baseline")?;
    println!(
        "send_receive.rollback_read_matches={}",
        received.read_file("/replica.bin")? == b"send-receive-baseline".to_vec()
    );
    let _ = fs::remove_dir_all(&source_root);
    let _ = fs::remove_dir_all(&target_root);
    Ok(())
}

fn demo_root() -> (PathBuf, bool) {
    if let Some(path) = env::args_os().nth(1) {
        return (PathBuf::from(path), false);
    }

    (temp_named_root("tidefs-filesystem-demo"), true)
}

fn temp_named_root(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let mut root = env::temp_dir();
    root.push(format!("{prefix}-{}-{nanos}", std::process::id()));
    root
}

// ── Namespace mutation tests: mkdir / rmdir / unlink ──────────────────────
#[cfg(test)]
mod namespace_mutation_tests {
    use super::*;
    use std::fs;
    use tidefs_local_filesystem::human::local_filesystem::{
        FileSystemError, LocalFilesystem, NodeKind, RootAuthenticationKey, StoreOptions,
    };

    fn test_fs() -> (LocalFilesystem, PathBuf) {
        let root = temp_named_root("tidefs-namespace-mutation-test");
        let _ = fs::remove_dir_all(&root);
        let key = RootAuthenticationKey::demo_key();
        let fs = LocalFilesystem::open_with_root_authentication_key(
            &root,
            StoreOptions::test_fast(),
            key,
        )
        .expect("open filesystem");
        (fs, root)
    }

    #[test]
    fn mkdir_creates_directory_visible_in_readdir() {
        let (mut fs, root) = test_fs();
        let rec = fs
            .create_dir("/subdir", 0o755)
            .expect("mkdir should succeed");
        assert!(rec.inode_id.get() > 0);

        let entries = fs.list_dir("/").expect("list_dir root");
        let subdir_entry = entries
            .iter()
            .find(|e| e.name == b"subdir")
            .expect("subdir should be in root listing");
        assert_eq!(subdir_entry.kind(), NodeKind::Dir);

        drop(fs);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn mkdir_on_existing_name_returns_eexist() {
        let (mut fs, root) = test_fs();
        fs.create_dir("/only", 0o755).expect("first mkdir");
        let err = fs.create_dir("/only", 0o755).unwrap_err();
        assert!(
            matches!(err, FileSystemError::AlreadyExists { .. }),
            "expected AlreadyExists, got {err:?}"
        );
        drop(fs);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rmdir_empty_directory_succeeds() {
        let (mut fs, root) = test_fs();
        fs.create_dir("/emptydir", 0o755).expect("mkdir");
        fs.remove_dir("/emptydir").expect("rmdir empty directory");

        let entries = fs.list_dir("/").expect("list_dir root");
        assert!(
            !entries.iter().any(|e| e.name == b"emptydir"),
            "emptydir should no longer exist"
        );
        drop(fs);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rmdir_nonempty_directory_returns_enotempty() {
        let (mut fs, root) = test_fs();
        fs.create_dir("/populated", 0o755).expect("mkdir");
        fs.create_file("/populated/file.txt", 0o644)
            .expect("create file inside dir");

        let err = fs.remove_dir("/populated").unwrap_err();
        assert!(
            matches!(err, FileSystemError::DirectoryNotEmpty { .. }),
            "expected DirectoryNotEmpty, got {err:?}"
        );
        drop(fs);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rmdir_nonexistent_returns_enoent() {
        let (mut fs, root) = test_fs();
        let err = fs.remove_dir("/nonexistent").unwrap_err();
        assert!(
            matches!(err, FileSystemError::NotFound { .. }),
            "expected NotFound, got {err:?}"
        );
        drop(fs);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn unlink_removes_file_and_stat_returns_enoent() {
        let (mut fs, root) = test_fs();
        fs.create_file("/ephemeral.txt", 0o644)
            .expect("create file");
        assert!(fs.stat("/ephemeral.txt").is_ok());

        fs.unlink("/ephemeral.txt").expect("unlink file");

        let err = fs.stat("/ephemeral.txt").unwrap_err();
        assert!(
            matches!(err, FileSystemError::NotFound { .. }),
            "expected NotFound after unlink, got {err:?}"
        );
        drop(fs);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn unlink_nonexistent_returns_enoent() {
        let (mut fs, root) = test_fs();
        let err = fs.unlink("/ghost").unwrap_err();
        assert!(
            matches!(err, FileSystemError::NotFound { .. }),
            "expected NotFound, got {err:?}"
        );
        drop(fs);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn mkdir_then_unlink_is_rejected_is_directory() {
        let (mut fs, root) = test_fs();
        fs.create_dir("/adir", 0o755).expect("mkdir");
        let err = fs.unlink("/adir").unwrap_err();
        assert!(
            matches!(err, FileSystemError::IsDirectory { .. }),
            "expected IsDirectory, got {err:?}"
        );
        drop(fs);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rmdir_file_returns_not_directory() {
        let (mut fs, root) = test_fs();
        fs.create_file("/notadir", 0o644).expect("create file");
        let err = fs.remove_dir("/notadir").unwrap_err();
        assert!(
            matches!(err, FileSystemError::NotDirectory { .. }),
            "expected NotDirectory, got {err:?}"
        );
        drop(fs);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn mkdir_rmdir_recreate_idempotent() {
        let (mut fs, root) = test_fs();
        for _ in 0..3 {
            fs.create_dir("/cycle", 0o755).expect("mkdir");
            assert!(fs.list_dir("/cycle").is_ok());
            fs.remove_dir("/cycle").expect("rmdir");
        }
        drop(fs);
        let _ = fs::remove_dir_all(&root);
    }
}
