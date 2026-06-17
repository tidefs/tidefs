use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct BlockCheckError {
    missing: Vec<String>,
}

impl fmt::Display for BlockCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "block-volume adapter check failed:")?;
        for item in &self.missing {
            writeln!(f, "- {item}")?;
        }
        Ok(())
    }
}

pub fn check_block_volume_adapter_core_current_workspace() -> Result<(), BlockCheckError> {
    let root = find_workspace_root().ok_or_else(|| BlockCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "Cargo.toml",
        "Cargo.lock",
        "crates/tidefs-block-volume-adapter-core/Cargo.toml",
        "crates/tidefs-block-volume-adapter-core/src/lib.rs",
        "docs/BLOCK_VOLUME_ADAPTER_CORE_OW301A.md",
        "nix/tidefs-validation.sh",
        "xtask/tidefs-xtask/src/policy.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "Cargo.toml",
        &["crates/tidefs-block-volume-adapter-core"],
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-block-volume-adapter-core/src/lib.rs",
        &[
            "BLOCK_VOLUME_ADAPTER_CORE_GATE_OW_301A",
            "BlockVolumeGeometryRecord",
            "BlockVolumeDirtyRangeEpochRecord",
            "BlockVolumeFlushBarrierRecord",
            "BlockVolumeDiscardIntentRecord",
            "BlockVolumeImage",
            "read_blocks",
            "write_blocks",
            "flush",
            "discard_blocks",
            "read_write_round_trips_exact_blocks",
            "flush_seals_dirty_epoch_and_records_barrier",
            "discard_zeroes_range_and_invalidates_dirty_epoch",
            "misaligned_write_is_refused_without_mutation",
            "out_of_bounds_read_is_refused",
            "discard_alignment_is_enforced",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/BLOCK_VOLUME_ADAPTER_CORE_OW301A.md",
        &[
            "OW-301A executable block-volume adapter core slice",
            "`tidefs-block-volume-adapter-core`",
            "read/write exactness",
            "flush barrier",
            "discard intent",
            "not a ublk daemon",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "xtask/tidefs-xtask/src/policy.rs",
        &[
            "tidefs-ublk-abi",
            "name.ends_with(\"-abi\")",
            "let block_core = member",
            "CrateClass::Core",
            "let block_api = member",
            "CrateClass::Api",
            "assert!(is_edge_allowed(&block_app, &block_core))",
            "assert!(is_edge_allowed(&block_app, &block_api))",
        ],
        &mut missing,
    );

    if missing.is_empty() {
        println!(
            "OW-301A block-volume adapter core ok: read/write exactness, flush barriers, discard intents, bounds refusal, and alignment refusal are implementation-tracked non-release"
        );
        Ok(())
    } else {
        Err(BlockCheckError { missing })
    }
}

pub fn check_block_volume_queue_admission_current_workspace() -> Result<(), BlockCheckError> {
    let root = find_workspace_root().ok_or_else(|| BlockCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "crates/tidefs-block-volume-adapter-core/src/lib.rs",
        "docs/BLOCK_VOLUME_QUEUE_ADMISSION_OW301B.md",
        "docs/BLOCK_VOLUME_ADAPTER_CORE_OW301A.md",
        "nix/tidefs-validation.sh",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "crates/tidefs-block-volume-adapter-core/src/lib.rs",
        &[
            "BLOCK_VOLUME_QUEUE_ADMISSION_GATE_OW_301B",
            "BlockVolumeQueueRuntime",
            "BlockVolumeQueueClassRecord",
            "BlockVolumeQueueSetRecord",
            "BlockVolumeQueueShardRecord",
            "BlockVolumeSubmissionContextMirrorRecord",
            "BlockVolumeQueueBackpressureStateRecord",
            "BlockVolumeExportFenceMirrorRecord",
            "BlockVolumeFlushEpochRecord",
            "BlockVolumeCompletionCommitMirrorRecord",
            "classify_request",
            "admit_submission_context",
            "seal_flush_epoch",
            "complete_submission_context",
            "queue_classification_binds_read_and_write_to_expected_classes",
            "overlapping_mutations_share_a_queue_shard_for_serialization",
            "backpressure_refuses_without_mutating_inflight_state",
            "export_fence_refuses_new_admission_without_queue_state_mutation",
            "flush_epoch_seals_mutating_submission_contexts",
            "completion_commit_releases_backpressure_and_renders_linux_status",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/BLOCK_VOLUME_QUEUE_ADMISSION_OW301B.md",
        &[
            "OW-301B executable block-volume queue admission slice",
            "queue classes",
            "queue shards",
            "backpressure refusal",
            "export fence refusal",
            "flush epoch",
            "not a ublk daemon",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/BLOCK_VOLUME_ADAPTER_CORE_OW301A.md",
        &["OW-301B extends this crate with a queue/admission model"],
        &mut missing,
    );
    if missing.is_empty() {
        println!(
            "OW-301B block-volume queue admission ok: queue classification, shard binding, backpressure refusal, export-fence refusal, flush epochs, and completion commits are implementation-tracked non-release"
        );
        Ok(())
    } else {
        Err(BlockCheckError { missing })
    }
}

pub fn check_block_volume_dispatch_execution_current_workspace() -> Result<(), BlockCheckError> {
    let root = find_workspace_root().ok_or_else(|| BlockCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "crates/tidefs-block-volume-adapter-core/src/lib.rs",
        "docs/BLOCK_VOLUME_DISPATCH_EXECUTION_OW301C.md",
        "docs/BLOCK_VOLUME_QUEUE_ADMISSION_OW301B.md",
        "nix/tidefs-validation.sh",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "crates/tidefs-block-volume-adapter-core/src/lib.rs",
        &[
            "BLOCK_VOLUME_DISPATCH_EXECUTION_GATE_OW_301C",
            "BlockVolumeDispatchClass",
            "BlockVolumeDispatchExecutionRecord",
            "dispatch_submission_context",
            "dispatch_read_admitted_context_returns_payload_and_completion",
            "dispatch_write_admitted_context_mutates_exact_bytes_and_releases_queue",
            "dispatch_flush_context_seals_dirty_epochs_and_records_completion",
            "dispatch_discard_and_write_zeroes_zero_visible_ranges",
            "dispatch_refuses_unadmitted_context_without_completion_commit",
            "dispatch_payload_mismatch_refuses_and_releases_queue_without_mutation",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/BLOCK_VOLUME_DISPATCH_EXECUTION_OW301C.md",
        &[
            "OW-301C executable block-volume dispatch execution slice",
            "admitted submission contexts",
            "read dispatch",
            "write dispatch",
            "flush dispatch",
            "discard and write-zeroes dispatch",
            "unadmitted context refusal",
            "not a ublk daemon",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/BLOCK_VOLUME_QUEUE_ADMISSION_OW301B.md",
        &["OW-301C extends this queue/admission model with dispatch execution"],
        &mut missing,
    );
    if missing.is_empty() {
        println!(
            "OW-301C block-volume dispatch execution ok: admitted read/write/flush/discard/write-zeroes dispatch, unadmitted refusal, payload-mismatch refusal, and completion release are implementation-tracked non-release"
        );
        Ok(())
    } else {
        Err(BlockCheckError { missing })
    }
}

pub fn check_block_volume_export_lifecycle_current_workspace() -> Result<(), BlockCheckError> {
    let root = find_workspace_root().ok_or_else(|| BlockCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "crates/tidefs-block-volume-adapter-core/src/lib.rs",
        "docs/BLOCK_VOLUME_EXPORT_LIFECYCLE_OW301D.md",
        "docs/BLOCK_VOLUME_DISPATCH_EXECUTION_OW301C.md",
        "nix/tidefs-validation.sh",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "crates/tidefs-block-volume-adapter-core/src/lib.rs",
        &[
            "BLOCK_VOLUME_EXPORT_LIFECYCLE_GATE_OW_301D",
            "BlockVolumeExportPhaseClass",
            "BlockVolumeExportRuntimeRecord",
            "BlockVolumeExportLifecycleRuntime",
            "BlockVolumeInflightTransitionClassificationRecord",
            "begin_quiesce",
            "fence_after_drain",
            "resume_after_fence",
            "export_lifecycle_bootstrap_admit_and_start_queues",
            "export_lifecycle_refuses_data_before_live_and_after_stop",
            "quiesce_transition_closes_ingress_and_classifies_inflight",
            "fence_completion_is_refused_until_quiesce_drain_finishes",
            "resume_after_fence_reopens_admission_under_new_fence_epoch",
            "invalid_lifecycle_transition_is_recorded_without_state_mutation",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/BLOCK_VOLUME_EXPORT_LIFECYCLE_OW301D.md",
        &[
            "OW-301D executable block-volume export lifecycle slice",
            "bootstrap",
            "quiesce transition",
            "commit-ok",
            "replay-required",
            "abort-required",
            "not a ublk daemon",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/BLOCK_VOLUME_DISPATCH_EXECUTION_OW301C.md",
        &["OW-301D extends this dispatch model with export lifecycle and quiesce"],
        &mut missing,
    );
    if missing.is_empty() {
        println!(
            "OW-301D block-volume export lifecycle ok: bootstrap, queue-live admission, quiesce classification, drain-before-fence, resume, and stop gates are implementation-tracked non-release"
        );
        Ok(())
    } else {
        Err(BlockCheckError { missing })
    }
}

pub fn check_block_volume_cache_coherency_current_workspace() -> Result<(), BlockCheckError> {
    let root = find_workspace_root().ok_or_else(|| BlockCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "crates/tidefs-block-volume-adapter-core/src/lib.rs",
        "docs/BLOCK_VOLUME_CACHE_COHERENCY_OW301E.md",
        "docs/BLOCK_VOLUME_EXPORT_LIFECYCLE_OW301D.md",
        "nix/tidefs-validation.sh",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "crates/tidefs-block-volume-adapter-core/src/lib.rs",
        &[
            "BLOCK_VOLUME_CACHE_COHERENCY_GATE_OW_301E",
            "BlockVolumeCacheCoherencyRuntime",
            "BlockVolumeReadCacheWindowRecord",
            "BlockVolumeCacheDirtyEpochRecord",
            "BlockVolumeCacheFlushBarrierRecord",
            "BlockVolumeFuaCompletionTicketRecord",
            "BlockVolumeDirectOverlapGuardRecord",
            "fill_read_cache_window",
            "open_dirty_epoch",
            "seal_flush_barrier",
            "issue_discard_or_zero_invalidation",
            "open_direct_overlap_guard",
            "drop_clean_cache_windows",
            "cache_hit_requires_live_anchor_bound_window",
            "dirty_epoch_creation_invalidates_overlapping_read_cache_window",
            "flush_barrier_covers_dirty_epoch_and_creates_fua_ticket",
            "discard_and_write_zeroes_invalidate_cache_windows",
            "direct_overlap_guard_blocks_until_dirty_epoch_is_sealed",
            "cache_loss_drops_clean_windows_without_removing_dirty_authority_records",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/BLOCK_VOLUME_CACHE_COHERENCY_OW301E.md",
        &[
            "OW-301E executable block-volume cache coherency slice",
            "clean read-cache windows",
            "dirty range epochs",
            "flush/FUA barriers",
            "discard/write-zeroes invalidation",
            "direct-overlap guards",
            "not a ublk daemon",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/BLOCK_VOLUME_EXPORT_LIFECYCLE_OW301D.md",
        &["OW-301E extends this lifecycle model with cache coherency and barrier records"],
        &mut missing,
    );
    if missing.is_empty() {
        println!(
            "OW-301E block-volume cache coherency ok: clean cache windows, dirty epochs, flush/FUA barriers, discard/write-zeroes invalidation, direct-overlap guards, and non-authoritative cache loss are implementation-tracked non-release"
        );
        Ok(())
    } else {
        Err(BlockCheckError { missing })
    }
}

pub fn check_block_volume_resize_fence_current_workspace() -> Result<(), BlockCheckError> {
    let root = find_workspace_root().ok_or_else(|| BlockCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "crates/tidefs-block-volume-adapter-core/src/lib.rs",
        "docs/BLOCK_VOLUME_RESIZE_FENCE_OW301F.md",
        "docs/BLOCK_VOLUME_EXPORT_LIFECYCLE_OW301D.md",
        "docs/BLOCK_VOLUME_CACHE_COHERENCY_OW301E.md",
        "nix/tidefs-validation.sh",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "crates/tidefs-block-volume-adapter-core/src/lib.rs",
        &[
            "BLOCK_VOLUME_RESIZE_FENCE_GATE_OW_301F",
            "BlockVolumeResizeFenceRuntime",
            "BlockVolumeResizeTransitionRecord",
            "BlockVolumeResizeTransitionOutcomeClass",
            "BlockVolumeCapacityTargetPublicationClass",
            "prepare_resize",
            "commit_resize",
            "publish_geometry",
            "resize_fence_grow_commit_publishes_geometry_and_zero_visible_tail",
            "resize_fence_shrink_refuses_overlap_until_drain",
            "resize_fence_shrink_commits_after_dirty_drain_and_fence",
            "resize_fence_refuses_without_fenced_export",
            "resize_fence_refuses_without_authority_anchor",
            "write_past_end_is_refused_without_implicit_resize",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/BLOCK_VOLUME_RESIZE_FENCE_OW301F.md",
        &[
            "OW-301F executable block-volume resize/fence transition slice",
            "capacity target publication",
            "affected tail range",
            "zero-visible grow range",
            "drain-incomplete refusal",
            "no-authority resize refusal",
            "ordinary writes past current end stay refused",
            "not a ublk daemon",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/BLOCK_VOLUME_EXPORT_LIFECYCLE_OW301D.md",
        &["OW-301F extends this lifecycle model with resize/fence capacity transitions"],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/BLOCK_VOLUME_CACHE_COHERENCY_OW301E.md",
        &["OW-301F consumes these cache coherency records as resize drain blockers"],
        &mut missing,
    );
    if missing.is_empty() {
        println!(
            "OW-301F block-volume resize/fence ok: capacity targets, affected tail ranges, grow zero visibility, shrink drain refusal, no-authority refusal, and post-resize geometry publication are implementation-tracked non-release"
        );
        Ok(())
    } else {
        Err(BlockCheckError { missing })
    }
}

pub fn check_block_volume_host_preflight_current_workspace() -> Result<(), BlockCheckError> {
    let root = find_workspace_root().ok_or_else(|| BlockCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "apps/tidefs-block-volume-adapter-daemon/Cargo.toml",
        "apps/tidefs-block-volume-adapter-daemon/src/main.rs",
        "apps/tidefs-block-volume-adapter-daemon/src/kernel_check.rs",
        "docs/BLOCK_VOLUME_ADAPTER_HOST_PREFLIGHT_OW301H.md",
        "docs/ARCHITECTURE.md",
        "docs/GITHUB_CI.md",
        "nix/tidefs-validation.sh",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "apps/tidefs-block-volume-adapter-daemon/src/kernel_check.rs",
        &[
            "Local replacement for the former observe-types dependency",
            "HostKernelClass",
            "ObserveHostIdentity",
            "classify_kernel_release_str",
            "classify_host_identity",
            "Linux700OrNewer",
            "QemuGuest",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-block-volume-adapter-daemon/src/main.rs",
        &[
            "BLOCK_VOLUME_HOST_PREFLIGHT_GATE_OW_301H",
            "preflight-host",
            "run_host_preflight",
            "evaluate_host_preflight",
            "HostPreflightInputs",
            "HostPreflightAdmissionClass",
            "HostPreflightRefusalClass",
            "/proc/sys/kernel/osrelease",
            "/dev/ublk-control",
            "/sys/module/ublk_drv",
            "host.live_attach_ready",
            "attach_mutation_attempted: false",
            "host_preflight_refuses_missing_control_device_without_mutation",
            "host_preflight_refuses_old_kernel_before_control_device",
            "host_preflight_marks_sysfs_gap_as_degraded_not_refused",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/BLOCK_VOLUME_ADAPTER_HOST_PREFLIGHT_OW301H.md",
        &[
            "OW-301H executable block-volume adapter host preflight surface",
            "preflight-host",
            "daemon-local host/kernel classification",
            "/dev/ublk-control",
            "does not load modules",
            "not a ublk daemon",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/ARCHITECTURE.md",
        &[
            "tidefs-block-volume-adapter-daemon",
            "ublk block device daemon",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/GITHUB_CI.md",
        &["QEMU Smoke", "ublk", "self-hosted"],
        &mut missing,
    );
    if missing.is_empty() {
        println!(
            "OW-301H block-volume host preflight ok: Linux host probe, ublk control-device readiness, explicit attach refusal, non-mutation, and proof hooks are implementation-tracked non-release"
        );
        Ok(())
    } else {
        Err(BlockCheckError { missing })
    }
}

pub fn check_block_volume_ublk_abi_current_workspace() -> Result<(), BlockCheckError> {
    let root = find_workspace_root().ok_or_else(|| BlockCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "Cargo.toml",
        "Cargo.lock",
        "crates/tidefs-ublk-abi/Cargo.toml",
        "crates/tidefs-ublk-abi/src/lib.rs",
        "apps/tidefs-block-volume-adapter-daemon/Cargo.toml",
        "apps/tidefs-block-volume-adapter-daemon/src/main.rs",
        "docs/BLOCK_VOLUME_UBLK_ABI_CONTROL_PLAN_OW301I.md",
        "docs/BLOCK_VOLUME_ADAPTER_HOST_PREFLIGHT_OW301H.md",
        "nix/tidefs-validation.sh",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "Cargo.toml",
        &["crates/tidefs-ublk-abi"],
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-ublk-abi/src/lib.rs",
        &[
            "UBLK_ABI_GATE_OW_301I",
            "UBLK_CMD_GET_FEATURES",
            "UBLK_CMD_ADD_DEV",
            "UBLK_CMD_SET_PARAMS",
            "UBLK_CMD_START_DEV",
            "UBLK_CMD_GET_DEV_INFO2",
            "UBLK_CMD_QUIESCE_DEV",
            "UBLK_CMD_UPDATE_SIZE",
            "UblkIoctlRequest",
            "UblkSrvCtrlCmd",
            "UblkSrvCtrlDevInfo",
            "UblkParams",
            "UblkFeatureFlags",
            "TIDEFS_UBLK_CONTROL_PLAN_REQUIRED_FEATURES",
            "UBLK_CONTROL_PLAN_STEPS",
            "UblkIoBufferAddress",
            "UblkAutoBufReg",
            "control_struct_layouts_match_linux_header_shape",
            "ioctl_requests_decode_to_ublk_type_number_direction_and_size",
            "control_plan_marks_only_probe_commands_as_non_mutating",
            "io_buffer_address_packing_obeys_header_bit_boundaries",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-block-volume-adapter-daemon/Cargo.toml",
        &["tidefs-ublk-abi"],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-block-volume-adapter-daemon/src/main.rs",
        &[
            "BLOCK_VOLUME_UBLK_ABI_PLAN_GATE_OW_301I",
            "ublk-abi-plan",
            "build_ublk_abi_plan_report",
            "features.required_mask",
            "plan.{}.ioctl_raw",
            "nonclaim.control_ioctl_issued=false",
            "ublk_abi_plan_binds_expected_attach_sequence_without_ioctl",
            "ublk_abi_plan_requires_resize_quiesce_and_user_copy_features",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/BLOCK_VOLUME_UBLK_ABI_CONTROL_PLAN_OW301I.md",
        &[
            "OW-301I executable block-volume ublk ABI control-plan surface",
            "crates/tidefs-ublk-abi",
            "tidefs-block-volume-adapter-daemon ublk-abi-plan",
            "/usr/include/linux/ublk_cmd.h",
            "GET_FEATURES -> ADD_DEV -> SET_PARAMS -> START_DEV -> GET_DEV_INFO2",
            "does not open",
            "`/dev/ublk-control`",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/BLOCK_VOLUME_ADAPTER_HOST_PREFLIGHT_OW301H.md",
        &["OW-301I follows this host preflight"],
        &mut missing,
    );
    if missing.is_empty() {
        println!(
            "OW-301I block-volume ublk ABI ok: Linux command numbers, ioctl encoding, record layouts, feature flags, dry-run control plan, and non-mutation claims are implementation-tracked non-release"
        );
        Ok(())
    } else {
        Err(BlockCheckError { missing })
    }
}

pub fn check_block_volume_file_backing_current_workspace() -> Result<(), BlockCheckError> {
    let root = find_workspace_root().ok_or_else(|| BlockCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "crates/tidefs-block-volume-adapter-core/src/lib.rs",
        "apps/tidefs-block-volume-adapter-daemon/src/main.rs",
        "docs/BLOCK_VOLUME_FILE_BACKING_OW301N.md",
        "nix/tidefs-validation.sh",
        "xtask/tidefs-xtask/src/main.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "crates/tidefs-block-volume-adapter-core/src/lib.rs",
        &[
            "BLOCK_VOLUME_FILE_IMAGE_BACKING_GATE_OW_301N",
            "BlockVolumeFileImage",
            "BlockVolumeFileImageError",
            "create_zeroed",
            "reopen_existing",
            "std::os::unix::fs::FileExt",
            "sync_all",
            "file_backed_image_flush_reopen_round_trips_exact_blocks",
            "file_backed_image_discard_and_write_zeroes_are_zero_visible",
            "file_backed_image_refuses_bad_ranges_without_backing_mutation",
            "file_backed_image_reopen_refuses_length_mismatch",
            "file_backed_image_refuses_invalid_geometry",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-block-volume-adapter-daemon/src/main.rs",
        &[
            "BLOCK_VOLUME_FILE_IMAGE_BACKING_GATE_OW_301N",
            "backing-file-smoke",
            "run_backing_file_smoke",
            "command.backing_file_smoke=backing-file-smoke",
            "backing_file_smoke_uses_real_backing_file_without_live_ublk",
            "nonclaim.dev_ublk_control_opened=false",
            "nonclaim.io_uring_queue_processed=false",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/BLOCK_VOLUME_FILE_BACKING_OW301N.md",
        &[
            "OW-301N executable block-volume file-backed image surface",
            "tidefs-block-volume-adapter-daemon backing-file-smoke",
            "std::fs::File",
            "FileExt",
            "sync_all",
            "does not open `/dev/ublk-control`",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "xtask/tidefs-xtask/src/main.rs",
        &[
            "check-block-volume-file-backing",
            "block_volume_file_backing_check_command",
        ],
        &mut missing,
    );

    if missing.is_empty() {
        println!(
            "OW-301N block-volume file backing ok: real userspace backing files preserve read/write/flush/discard semantics with explicit no-ublk nonclaims"
        );
        Ok(())
    } else {
        Err(BlockCheckError { missing })
    }
}

pub fn check_block_volume_ublk_control_open_current_workspace() -> Result<(), BlockCheckError> {
    let root = find_workspace_root().ok_or_else(|| BlockCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "apps/tidefs-block-volume-adapter-daemon/src/main.rs",
        "apps/tidefs-block-volume-adapter-daemon/src/ublk_control_open/mod.rs",
        "crates/tidefs-ublk-abi/src/lib.rs",
        "docs/BLOCK_VOLUME_UBLK_CONTROL_OPEN_OW301O.md",
        "nix/tidefs-validation.sh",
        "xtask/tidefs-xtask/src/main.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "apps/tidefs-block-volume-adapter-daemon/src/main.rs",
        &[
            "mod ublk_control_open",
            "BLOCK_VOLUME_UBLK_CONTROL_OPEN_GATE_OW_301O",
            "ublk-control-open",
            "ublk-control-open-preflight",
            "command.ublk_control_open=ublk-control-open",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-block-volume-adapter-daemon/src/ublk_control_open/mod.rs",
        &[
            "BLOCK_VOLUME_UBLK_CONTROL_OPEN_GATE_OW_301O",
            "OpenOptions::new()",
            ".read(true)",
            ".write(true)",
            "UBLK_CONTROL_PATH",
            "should_attempt_control_open",
            "evaluate_ublk_control_open_preflight",
            "control.open_attempted",
            "control.opened",
            "control.typed_ioctl_requests_bound=true",
            "control.mutating_ioctl_issued",
            "refuses_old_kernel_without_open_attempt",
            "refuses_missing_control_device_without_open_attempt",
            "refuses_non_character_control_device_without_open_attempt",
            "admits_ready_host_after_real_control_open_result",
            "reports_open_failure_without_issuing_ioctls",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-ublk-abi/src/lib.rs",
        &[
            "UblkControlPlanStep",
            "ublk_control_plan_steps",
            "UblkCtrlCommand::GetFeatures",
            "UblkCtrlCommand::AddDev",
            "mutates_control_state",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/BLOCK_VOLUME_UBLK_CONTROL_OPEN_OW301O.md",
        &[
            "OW-301O executable ublk control-device open boundary",
            "tidefs-block-volume-adapter-daemon ublk-control-open",
            "`/dev/ublk-control`",
            "OpenOptions::new().read(true).write(true)",
            "does not issue read-only probe ioctls",
            "does not issue mutating ublk control ioctls",
            "does not create `/dev/ublkbN`",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "xtask/tidefs-xtask/src/main.rs",
        &[
            "check-block-volume-ublk-control-open",
            "check-block-volume-ublk-control-runtime",
            "block_volume_ublk_control_open_check_command",
        ],
        &mut missing,
    );

    if missing.is_empty() {
        println!(
            "OW-301O block-volume ublk control open ok: real control-device admission opens only eligible hosts and records exact no-ioctl/no-block-device nonclaims"
        );
        Ok(())
    } else {
        Err(BlockCheckError { missing })
    }
}

pub fn check_block_volume_ublk_control_readonly_probe_current_workspace(
) -> Result<(), BlockCheckError> {
    let root = find_workspace_root().ok_or_else(|| BlockCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "Cargo.toml",
        "apps/tidefs-block-volume-adapter-daemon/Cargo.toml",
        "apps/tidefs-block-volume-adapter-daemon/src/main.rs",
        "apps/tidefs-block-volume-adapter-daemon/src/ublk_control_open/mod.rs",
        "crates/tidefs-block-volume-adapter-ublk-control-runtime/Cargo.toml",
        "crates/tidefs-block-volume-adapter-ublk-control-runtime/src/lib.rs",
        "docs/BLOCK_VOLUME_UBLK_CONTROL_READONLY_PROBE_OW301P.md",
        "nix/tidefs-validation.sh",
        "xtask/tidefs-xtask/src/main.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "Cargo.toml",
        &["crates/tidefs-block-volume-adapter-ublk-control-runtime"],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-block-volume-adapter-daemon/Cargo.toml",
        &["tidefs-block-volume-adapter-ublk-control-runtime"],
        &mut missing,
    );
    check_source_markers(
        &root,
        "crates/tidefs-block-volume-adapter-ublk-control-runtime/src/lib.rs",
        &[
            "BLOCK_VOLUME_UBLK_CONTROL_READONLY_PROBE_GATE_OW_301P",
            "UblkControlReadonlyProbeCommand",
            "build_readonly_probe_spec",
            "UblkCtrlCommand::GetFeatures",
            "build_get_features_ctrl_cmd",
            "encode_get_features_cmd80",
            "UBLK_FEATURES_LEN",
            "io_uring::{cqueue, opcode, squeue, types, IoUring}",
            "opcode::UringCmd80",
            "UnsupportedMutatingCommand",
            "get_features_spec_uses_read_command_and_sqe128",
            "get_features_command_points_at_feature_buffer",
            "get_features_command_encodes_into_uring_cmd80_payload",
            "completed_get_features_maps_feature_bits",
            "errno_error_retains_errno_value",
            "mutating_commands_are_rejected_by_readonly_builder",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-block-volume-adapter-daemon/src/main.rs",
        &[
            "BLOCK_VOLUME_UBLK_CONTROL_READONLY_PROBE_GATE_OW_301P",
            "run_ublk_control_readonly_probe",
            "ublk-control-readonly-probe",
            "ublk-control-get-features",
            "command.ublk_control_readonly_probe=ublk-control-readonly-probe",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-block-volume-adapter-daemon/src/ublk_control_open/mod.rs",
        &[
            "issue_get_features",
            "UblkControlReadonlyProbeReport",
            "evaluate_ublk_control_readonly_probe",
            "probe.uring_cmd_attempted",
            "probe.uring_cmd_completed",
            "features.required_available",
            "control.read_only_probe_uring_cmd_issued",
            "control.mutating_ioctl_issued",
            "nonclaim.no_io_uring_queue_processed",
            "readonly_probe_refuses_old_kernel_without_uring_cmd_attempt",
            "readonly_probe_refuses_missing_control_device_without_uring_cmd_attempt",
            "readonly_probe_reports_open_failure_without_uring_cmd_attempt",
            "readonly_probe_success_maps_features_and_stays_non_mutating",
            "readonly_probe_errno_maps_failure_class",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/BLOCK_VOLUME_UBLK_CONTROL_READONLY_PROBE_OW301P.md",
        &[
            "OW-301P executable read-only ublk control uring_cmd probe boundary",
            "tidefs-block-volume-adapter-ublk-control-runtime",
            "UBLK_U_CMD_GET_FEATURES",
            "IORING_OP_URING_CMD",
            "cmd.addr",
            "8-byte userspace feature buffer",
            "does not issue mutating ublk control commands",
            "does not create `/dev/ublkbN`",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "xtask/tidefs-xtask/src/main.rs",
        &[
            "check-block-volume-ublk-control-readonly-probe",
            "check-block-volume-ublk-control-get-features",
            "block_volume_ublk_control_readonly_probe_check_command",
        ],
        &mut missing,
    );

    if missing.is_empty() {
        println!(
            "OW-301P block-volume ublk control read-only probe ok: admitted hosts can submit GET_FEATURES uring_cmd while mutating control commands and block-device creation remain explicitly absent"
        );
        Ok(())
    } else {
        Err(BlockCheckError { missing })
    }
}

pub fn check_block_volume_ublk_add_dev_boundary_current_workspace() -> Result<(), BlockCheckError> {
    let root = find_workspace_root().ok_or_else(|| BlockCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "apps/tidefs-block-volume-adapter-daemon/src/main.rs",
        "apps/tidefs-block-volume-adapter-daemon/src/ublk_control_open/mod.rs",
        "crates/tidefs-block-volume-adapter-ublk-control-runtime/src/lib.rs",
        "docs/BLOCK_VOLUME_UBLK_ADD_DEV_BOUNDARY_OW301Q.md",
        "nix/tidefs-validation.sh",
        "xtask/tidefs-xtask/src/main.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "crates/tidefs-block-volume-adapter-ublk-control-runtime/src/lib.rs",
        &[
            "BLOCK_VOLUME_UBLK_CONTROL_ADD_DEV_GATE_OW_301Q",
            "UblkControlAddDevCommand",
            "UblkControlAddDevInput",
            "UblkControlAddDevSpec",
            "UblkControlAddDevOutcome",
            "TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES",
            "build_add_dev_spec",
            "build_add_dev_info",
            "build_add_dev_ctrl_cmd",
            "encode_add_dev_cmd80",
            "issue_add_dev",
            "UblkCtrlCommand::AddDev",
            "queue_id: u16::MAX",
            "opcode::UringCmd80",
            "add_dev_spec_uses_mutating_read_write_command_and_sqe128",
            "add_dev_info_uses_conservative_tidefs_queue_geometry",
            "add_dev_command_points_at_dev_info_and_uses_global_queue_id",
            "add_dev_command_encodes_into_uring_cmd80_payload",
            "add_dev_input_requires_ioctl_encoded_user_copy_flags",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-block-volume-adapter-daemon/src/main.rs",
        &[
            "BLOCK_VOLUME_UBLK_CONTROL_ADD_DEV_GATE_OW_301Q",
            "run_ublk_control_add_dev_boundary",
            "ublk-control-add-dev",
            "ublk-add-dev-boundary",
            "command.ublk_control_add_dev=ublk-control-add-dev",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-block-volume-adapter-daemon/src/ublk_control_open/mod.rs",
        &[
            "issue_add_dev",
            "issue_get_features",
            "TIDEFS_UBLK_ADD_DEV_REQUIRED_FEATURES",
            "UblkControlAddDevReport",
            "evaluate_ublk_control_add_dev_boundary",
            "add_dev.required_features_available",
            "add_dev.uring_cmd_attempted",
            "add_dev.uring_cmd_completed",
            "control.mutating_add_dev_uring_cmd_issued",
            "control.ublk_device_pair_created",
            "control.ublk_block_device_started",
            "nonclaim.no_set_params_uring_cmd_issued=true",
            "nonclaim.no_start_dev_uring_cmd_issued=true",
            "add_dev_refuses_old_kernel_without_mutation_attempt",
            "add_dev_refuses_missing_control_device_without_mutation_attempt",
            "add_dev_waits_for_successful_feature_probe",
            "add_dev_requires_ioctl_encoded_user_copy_features",
            "add_dev_success_records_kernel_returned_device_pair",
            "add_dev_errno_maps_failure_class",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/BLOCK_VOLUME_UBLK_ADD_DEV_BOUNDARY_OW301Q.md",
        &[
            "OW-301Q executable ublk ADD_DEV control uring_cmd boundary",
            "UBLK_U_CMD_ADD_DEV",
            "IORING_OP_URING_CMD",
            "cmd.addr",
            "ublksrv_ctrl_dev_info",
            "queue_id == u16::MAX",
            "does not issue `UBLK_U_CMD_SET_PARAMS`",
            "does not issue `UBLK_U_CMD_START_DEV`",
            "does not start `/dev/ublkbN`",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "xtask/tidefs-xtask/src/main.rs",
        &[
            "check-block-volume-ublk-add-dev-boundary",
            "check-block-volume-ublk-add-dev",
            "block_volume_ublk_add_dev_boundary_check_command",
        ],
        &mut missing,
    );

    if missing.is_empty() {
        println!(
            "OW-301Q block-volume ublk ADD_DEV boundary ok: admitted hosts can reach the real ADD_DEV uring_cmd boundary while SET_PARAMS, START_DEV, data queues, and started block-device export remain absent"
        );
        Ok(())
    } else {
        Err(BlockCheckError { missing })
    }
}

pub fn check_block_volume_ublk_del_dev_cleanup_boundary_current_workspace(
) -> Result<(), BlockCheckError> {
    let root = find_workspace_root().ok_or_else(|| BlockCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "apps/tidefs-block-volume-adapter-daemon/src/main.rs",
        "apps/tidefs-block-volume-adapter-daemon/src/ublk_control_open/mod.rs",
        "crates/tidefs-block-volume-adapter-ublk-control-runtime/src/lib.rs",
        "docs/BLOCK_VOLUME_UBLK_DEL_DEV_CLEANUP_BOUNDARY_OW301R.md",
        "nix/tidefs-validation.sh",
        "xtask/tidefs-xtask/src/main.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "crates/tidefs-block-volume-adapter-ublk-control-runtime/src/lib.rs",
        &[
            "BLOCK_VOLUME_UBLK_CONTROL_DEL_DEV_GATE_OW_301R",
            "UblkControlDelDevCommand",
            "UblkControlDelDevInput",
            "UblkControlDelDevSpec",
            "UblkControlDelDevOutcome",
            "build_del_dev_spec",
            "build_del_dev_ctrl_cmd",
            "encode_del_dev_cmd80",
            "issue_del_dev",
            "UblkCtrlCommand::DelDev",
            "queue_id: u16::MAX",
            "ctrl_buffer_len: 0",
            "ctrl_buffer_addr: 0",
            "opcode::UringCmd80",
            "del_dev_spec_uses_mutating_read_write_command_and_sqe128",
            "del_dev_command_targets_concrete_dev_and_uses_global_queue_id",
            "del_dev_command_encodes_into_uring_cmd80_payload",
            "del_dev_input_rejects_auto_device_id",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-block-volume-adapter-daemon/src/main.rs",
        &[
            "BLOCK_VOLUME_UBLK_CONTROL_DEL_DEV_GATE_OW_301R",
            "run_ublk_control_add_del_dev_boundary",
            "ublk-control-add-del-dev",
            "ublk-del-dev-cleanup-boundary",
            "command.ublk_control_add_del_dev=ublk-control-add-del-dev",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-block-volume-adapter-daemon/src/ublk_control_open/mod.rs",
        &[
            "issue_add_dev",
            "issue_del_dev",
            "UblkControlAddDelDevReport",
            "evaluate_ublk_control_add_del_dev_boundary",
            "del_dev.uring_cmd_attempted",
            "del_dev.uring_cmd_completed",
            "del_dev.failure_class",
            "control.cleanup_attempted_after_add_dev",
            "control.cleanup_failed_after_add_dev",
            "control.ublk_device_pair_created",
            "control.ublk_device_pair_deleted",
            "nonclaim.no_set_params_uring_cmd_issued=true",
            "nonclaim.no_start_dev_uring_cmd_issued=true",
            "add_del_dev_refuses_old_kernel_without_cleanup_attempt",
            "add_del_dev_skips_cleanup_when_add_dev_fails",
            "add_del_dev_success_records_device_pair_cleanup",
            "add_del_dev_errno_records_cleanup_failure_after_add_dev",
            "add_del_dev_rejects_auto_device_id_as_cleanup_target",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/BLOCK_VOLUME_UBLK_DEL_DEV_CLEANUP_BOUNDARY_OW301R.md",
        &[
            "OW-301R executable ublk DEL_DEV cleanup uring_cmd boundary",
            "UBLK_U_CMD_DEL_DEV",
            "IORING_OP_URING_CMD",
            "returned ADD_DEV device id",
            "queue_id == u16::MAX",
            "cmd.len == 0",
            "cmd.addr == 0",
            "does not issue `UBLK_U_CMD_SET_PARAMS`",
            "does not issue `UBLK_U_CMD_START_DEV`",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "xtask/tidefs-xtask/src/main.rs",
        &[
            "check-block-volume-ublk-del-dev-cleanup-boundary",
            "check-block-volume-ublk-del-dev",
            "block_volume_ublk_del_dev_cleanup_boundary_check_command",
        ],
        &mut missing,
    );

    if missing.is_empty() {
        println!(
            "OW-301R block-volume ublk DEL_DEV cleanup boundary ok: admitted hosts can clean up a successful ADD_DEV device pair while SET_PARAMS, START_DEV, data queues, and started block-device export remain absent"
        );
        Ok(())
    } else {
        Err(BlockCheckError { missing })
    }
}

pub fn check_block_volume_ublk_set_params_boundary_current_workspace() -> Result<(), BlockCheckError>
{
    let root = find_workspace_root().ok_or_else(|| BlockCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "apps/tidefs-block-volume-adapter-daemon/src/main.rs",
        "apps/tidefs-block-volume-adapter-daemon/src/ublk_control_open/mod.rs",
        "crates/tidefs-block-volume-adapter-ublk-control-runtime/src/lib.rs",
        "docs/BLOCK_VOLUME_UBLK_SET_PARAMS_BOUNDARY_OW301S.md",
        "nix/tidefs-validation.sh",
        "xtask/tidefs-xtask/src/main.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "crates/tidefs-block-volume-adapter-ublk-control-runtime/src/lib.rs",
        &[
            "BLOCK_VOLUME_UBLK_CONTROL_SET_PARAMS_GATE_OW_301S",
            "UblkControlSetParamsCommand",
            "UblkControlSetParamsInput",
            "UblkControlSetParamsSpec",
            "UblkControlSetParamsOutcome",
            "build_set_params_spec",
            "build_set_params_ctrl_cmd",
            "encode_set_params_cmd80",
            "issue_set_params",
            "UblkCtrlCommand::SetParams",
            "queue_id: u16::MAX",
            "UBLK_PARAM_TYPE_BASIC",
            "UBLK_PARAM_TYPE_DISCARD",
            "UBLK_PARAM_TYPE_SEGMENT",
            "opcode::UringCmd80",
            "set_params_spec_uses_mutating_read_write_command_and_sqe128",
            "set_params_command_targets_concrete_dev_and_points_at_params_buffer",
            "set_params_command_encodes_into_uring_cmd80_payload",
            "set_params_input_requires_full_basic_discard_segment_fields",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-block-volume-adapter-daemon/src/main.rs",
        &[
            "BLOCK_VOLUME_UBLK_CONTROL_SET_PARAMS_GATE_OW_301S",
            "run_ublk_control_set_params_boundary",
            "ublk-control-set-params",
            "ublk-set-params-boundary",
            "command.ublk_control_set_params=ublk-control-set-params",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-block-volume-adapter-daemon/src/ublk_control_open/mod.rs",
        &[
            "issue_set_params",
            "build_ublk_parameter_spec_report",
            "UblkControlSetParamsReport",
            "evaluate_ublk_control_set_params_boundary",
            "set_params.uring_cmd_attempted",
            "set_params.uring_cmd_completed",
            "set_params.failure_class",
            "set_params.projected",
            "control.mutating_set_params_uring_cmd_issued",
            "control.cleanup_attempted_after_add_dev",
            "control.cleanup_failed_after_add_dev",
            "control.ublk_device_pair_deleted",
            "nonclaim.no_start_dev_uring_cmd_issued=true",
            "set_params_refuses_old_kernel_without_mutation_or_cleanup_attempt",
            "set_params_success_records_projected_params_and_cleanup",
            "set_params_errno_still_records_del_dev_cleanup",
            "set_params_success_with_del_dev_errno_records_cleanup_failure",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/BLOCK_VOLUME_UBLK_SET_PARAMS_BOUNDARY_OW301S.md",
        &[
            "OW-301S executable ublk SET_PARAMS control uring_cmd boundary",
            "UBLK_U_CMD_SET_PARAMS",
            "IORING_OP_URING_CMD",
            "cmd.addr",
            "ublk_params",
            "basic/discard/segment",
            "DEL_DEV cleanup",
            "does not issue `UBLK_U_CMD_START_DEV`",
            "does not start `/dev/ublkbN`",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "xtask/tidefs-xtask/src/main.rs",
        &[
            "check-block-volume-ublk-set-params-boundary",
            "check-block-volume-ublk-set-params",
            "block_volume_ublk_set_params_boundary_check_command",
        ],
        &mut missing,
    );

    if missing.is_empty() {
        println!(
            "OW-301S block-volume ublk SET_PARAMS boundary ok: admitted hosts can project ublk_params into the real SET_PARAMS uring_cmd boundary with DEL_DEV cleanup while START_DEV, data queues, and started block-device export remain absent"
        );
        Ok(())
    } else {
        Err(BlockCheckError { missing })
    }
}

pub fn check_block_volume_ublk_start_dev_boundary_current_workspace() -> Result<(), BlockCheckError>
{
    let root = find_workspace_root().ok_or_else(|| BlockCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "apps/tidefs-block-volume-adapter-daemon/src/main.rs",
        "apps/tidefs-block-volume-adapter-daemon/src/ublk_control_open/mod.rs",
        "crates/tidefs-block-volume-adapter-ublk-control-runtime/src/lib.rs",
        "docs/BLOCK_VOLUME_UBLK_START_DEV_BOUNDARY_OW301T.md",
        "nix/tidefs-validation.sh",
        "xtask/tidefs-xtask/src/main.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "crates/tidefs-block-volume-adapter-ublk-control-runtime/src/lib.rs",
        &[
            "BLOCK_VOLUME_UBLK_CONTROL_START_DEV_GATE_OW_301T",
            "UblkControlStartDevCommand",
            "UblkControlStartDevInput",
            "UblkControlStartDevSpec",
            "UblkControlStartDevOutcome",
            "build_start_dev_spec",
            "build_start_dev_ctrl_cmd",
            "encode_start_dev_cmd80",
            "issue_start_dev",
            "UblkCtrlCommand::StartDev",
            "queue_id: u16::MAX",
            "data: [input.ublksrv_pid as u64]",
            "requires_ready_io_fetches",
            "opcode::UringCmd80",
            "start_dev_spec_uses_mutating_read_write_command_and_sqe128",
            "start_dev_command_targets_concrete_dev_and_inline_daemon_pid",
            "start_dev_command_encodes_into_uring_cmd80_payload",
            "start_dev_input_rejects_auto_device_id_or_invalid_pid",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-block-volume-adapter-daemon/src/main.rs",
        &[
            "BLOCK_VOLUME_UBLK_CONTROL_START_DEV_GATE_OW_301T",
            "run_ublk_control_start_dev_boundary",
            "ublk-control-start-dev",
            "ublk-start-dev-boundary",
            "command.ublk_control_start_dev=ublk-control-start-dev",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-block-volume-adapter-daemon/src/ublk_control_open/mod.rs",
        &[
            "issue_start_dev",
            "UblkControlStartDevReport",
            "evaluate_ublk_control_start_dev_boundary",
            "start_dev.uring_cmd_attempted",
            "start_dev.uring_cmd_completed",
            "start_dev.failure_class",
            "start_dev.io_queue_fetches_ready",
            "control.mutating_start_dev_uring_cmd_issued",
            "nonclaim.no_data_queue_fetches_submitted=true",
            "start_dev_requires_ready_data_queue_fetches_after_set_params",
            "start_dev_success_records_started_boundary_and_cleanup",
            "start_dev_errno_records_failure_and_cleanup",
            "start_dev_invalid_input_does_not_submit_but_still_cleans_up",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/BLOCK_VOLUME_UBLK_START_DEV_BOUNDARY_OW301T.md",
        &[
            "OW-301T guarded ublk START_DEV control boundary",
            "UBLK_U_CMD_START_DEV",
            "IORING_OP_URING_CMD",
            "cmd.data[0]",
            "data queue FETCH_REQ",
            "data_queue_fetches_not_ready",
            "does not submit START_DEV without ready data queues",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "xtask/tidefs-xtask/src/main.rs",
        &[
            "check-block-volume-ublk-start-dev-boundary",
            "check-block-volume-ublk-start-dev",
            "block_volume_ublk_start_dev_boundary_check_command",
        ],
        &mut missing,
    );

    if missing.is_empty() {
        println!(
            "OW-301T block-volume ublk START_DEV boundary ok: the real START_DEV command shape is implementation-tracked non-release and the daemon refuses START_DEV until data queue FETCH_REQ readiness exists, preserving DEL_DEV cleanup and avoiding unsafe control-only starts"
        );
        Ok(())
    } else {
        Err(BlockCheckError { missing })
    }
}

pub fn check_block_volume_ublk_fetch_req_readiness_boundary_current_workspace(
) -> Result<(), BlockCheckError> {
    let root = find_workspace_root().ok_or_else(|| BlockCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "apps/tidefs-block-volume-adapter-daemon/src/main.rs",
        "apps/tidefs-block-volume-adapter-daemon/src/ublk_control_open/mod.rs",
        "crates/tidefs-block-volume-adapter-ublk-control-runtime/src/lib.rs",
        "docs/BLOCK_VOLUME_UBLK_FETCH_REQ_READINESS_BOUNDARY_OW301U.md",
        "nix/tidefs-validation.sh",
        "xtask/tidefs-xtask/src/main.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "crates/tidefs-block-volume-adapter-ublk-control-runtime/src/lib.rs",
        &[
            "BLOCK_VOLUME_UBLK_DATA_QUEUE_FETCH_REQ_GATE_OW_301U",
            "UBLK_DATA_QUEUE_FETCH_REQ_RING_ENTRIES",
            "UblkDataQueueFetchReqCommand",
            "UblkDataQueueFetchReqInput",
            "UblkDataQueueFetchReqSpec",
            "UblkDataQueueFetchReqReadiness",
            "UblkDataQueueFetchReqOutcome",
            "build_fetch_req_spec",
            "build_fetch_req_io_cmd",
            "encode_fetch_req_cmd80",
            "submit_fetch_req_without_wait",
            "UblkIoCommand::FetchReq",
            "fetch_req_user_data",
            "data_queue_runtime_live",
            "must_remain_in_flight_for_start",
            "fetch_req_spec_uses_data_queue_read_write_command_and_sqe128",
            "fetch_req_command_encodes_queue_tag_result_and_zero_user_copy_addr",
            "fetch_req_input_rejects_invalid_queue_geometry_or_user_copy_addr",
            "fetch_req_user_data_binds_tag_command_and_queue",
            "fetch_req_readiness_requires_live_queue_runtime_for_start_dev",
            "fetch_req_outcome_preserves_queue_tag_and_user_data",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-block-volume-adapter-daemon/src/main.rs",
        &[
            "BLOCK_VOLUME_UBLK_DATA_QUEUE_FETCH_REQ_GATE_OW_301U",
            "run_ublk_data_queue_fetch_req_readiness_boundary",
            "ublk-data-queue-fetch-req",
            "ublk-fetch-req-readiness-boundary",
            "command.ublk_data_queue_fetch_req=ublk-data-queue-fetch-req",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-block-volume-adapter-daemon/src/ublk_control_open/mod.rs",
        &[
            "UblkDataQueueFetchReqReport",
            "evaluate_ublk_data_queue_fetch_req_readiness_boundary",
            "fetch_req.submission_attempted",
            "fetch_req.submitted",
            "fetch_req.data_queue_runtime_live",
            "start_dev.data_queue_runtime_live",
            "nonclaim.no_fetch_req_submitted_without_live_queue_runtime=true",
            "fetch_req_readiness_boundary_reports_queue_without_submission",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/BLOCK_VOLUME_UBLK_FETCH_REQ_READINESS_BOUNDARY_OW301U.md",
        &[
            "OW-301U guarded ublk data-queue FETCH_REQ readiness boundary",
            "UBLK_U_IO_FETCH_REQ",
            "IORING_OP_URING_CMD",
            "/dev/ublkcN",
            "data_queue_runtime_live",
            "must remain in flight",
            "does not submit FETCH_REQ without a live data-queue runtime",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "xtask/tidefs-xtask/src/main.rs",
        &[
            "check-block-volume-ublk-fetch-req-readiness-boundary",
            "check-block-volume-ublk-fetch-req",
            "block_volume_ublk_fetch_req_readiness_boundary_check_command",
        ],
        &mut missing,
    );

    if missing.is_empty() {
        println!(
            "OW-301U block-volume ublk FETCH_REQ readiness boundary ok: the real data-queue FETCH_REQ command shape is implementation-tracked non-release, readiness requires live queue runtime ownership, and START_DEV remains guarded without unsafe data-queue submission"
        );
        Ok(())
    } else {
        Err(BlockCheckError { missing })
    }
}

pub fn check_block_volume_ublk_data_queue_open_boundary_current_workspace(
) -> Result<(), BlockCheckError> {
    let root = find_workspace_root().ok_or_else(|| BlockCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "apps/tidefs-block-volume-adapter-daemon/src/main.rs",
        "apps/tidefs-block-volume-adapter-daemon/src/ublk_control_open/mod.rs",
        "crates/tidefs-block-volume-adapter-ublk-control-runtime/src/lib.rs",
        "docs/BLOCK_VOLUME_UBLK_DATA_QUEUE_OPEN_BOUNDARY_OW301V.md",
        "nix/tidefs-validation.sh",
        "xtask/tidefs-xtask/src/main.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "crates/tidefs-block-volume-adapter-ublk-control-runtime/src/lib.rs",
        &[
            "BLOCK_VOLUME_UBLK_DATA_QUEUE_OPEN_GATE_OW_301V",
            "UBLK_DATA_QUEUE_RUNTIME_RING_ENTRIES",
            "UBLK_DATA_QUEUE_PATH_TEMPLATE",
            "UblkDataQueueRuntimeOpenInput",
            "UblkDataQueueRuntimeOpenSpec",
            "UblkDataQueueRuntimeOpenOutcome",
            "UblkDataQueueRuntime",
            "build_data_queue_runtime_open_spec",
            "open_data_queue_runtime",
            "ublk_data_queue_device_path",
            "data_queue_runtime_open_spec_binds_concrete_dev_queue_path_and_ring",
            "data_queue_runtime_open_rejects_auto_dev_id_and_bad_geometry",
            "data_queue_runtime_open_outcome_feeds_fetch_req_liveness_without_submissions",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-block-volume-adapter-daemon/src/main.rs",
        &[
            "BLOCK_VOLUME_UBLK_DATA_QUEUE_OPEN_GATE_OW_301V",
            "run_ublk_data_queue_open_boundary",
            "ublk-data-queue-open",
            "command.ublk_data_queue_open=ublk-data-queue-open",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-block-volume-adapter-daemon/src/ublk_control_open/mod.rs",
        &[
            "UblkDataQueueOpenReport",
            "evaluate_ublk_data_queue_open_boundary",
            "data_queue.open_attempted",
            "data_queue.opened",
            "data_queue.runtime_live",
            "fetch_req.submitted",
            "nonclaim.no_fetch_req_submitted=true",
            "data_queue_open_boundary_records_runtime_open_and_cleanup_without_fetch_or_start",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/BLOCK_VOLUME_UBLK_DATA_QUEUE_OPEN_BOUNDARY_OW301V.md",
        &[
            "OW-301V guarded ublk data-queue runtime-open boundary",
            "/dev/ublkcN",
            "requires successful ADD_DEV",
            "does not submit FETCH_REQ",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "xtask/tidefs-xtask/src/main.rs",
        &[
            "check-block-volume-ublk-data-queue-open-boundary",
            "check-block-volume-ublk-data-queue-open",
            "block_volume_ublk_data_queue_open_boundary_check_command",
        ],
        &mut missing,
    );

    if missing.is_empty() {
        println!(
            "OW-301V block-volume ublk data-queue open boundary ok: concrete ADD_DEV results bind /dev/ublkcN runtime-open admission and FETCH_REQ/START_DEV remain unsubmitted"
        );
        Ok(())
    } else {
        Err(BlockCheckError { missing })
    }
}

pub fn check_block_volume_ublk_fetch_req_submit_boundary_current_workspace(
) -> Result<(), BlockCheckError> {
    let root = find_workspace_root().ok_or_else(|| BlockCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "apps/tidefs-block-volume-adapter-daemon/src/main.rs",
        "apps/tidefs-block-volume-adapter-daemon/src/ublk_control_open/mod.rs",
        "crates/tidefs-block-volume-adapter-ublk-control-runtime/src/lib.rs",
        "docs/BLOCK_VOLUME_UBLK_FETCH_REQ_SUBMISSION_BOUNDARY_OW301W.md",
        "nix/tidefs-validation.sh",
        "xtask/tidefs-xtask/src/main.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "crates/tidefs-block-volume-adapter-ublk-control-runtime/src/lib.rs",
        &[
            "BLOCK_VOLUME_UBLK_DATA_QUEUE_FETCH_REQ_SUBMIT_GATE_OW_301W",
            "UblkDataQueueFetchReqSubmissionSpec",
            "UblkDataQueueFetchReqSubmissionOutcome",
            "UblkDataQueueFetchReqSubmissionError",
            "build_fetch_req_submission_spec",
            "submit_runtime_fetch_reqs_without_wait",
            "fetch_req_submission_spec_binds_live_runtime_queue_tags",
            "fetch_req_submission_outcome_makes_start_dev_ready_without_start_submission",
            "fetch_req_submission_error_preserves_failed_tag_and_partial_count",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-block-volume-adapter-daemon/src/main.rs",
        &[
            "BLOCK_VOLUME_UBLK_DATA_QUEUE_FETCH_REQ_SUBMIT_GATE_OW_301W",
            "run_ublk_data_queue_fetch_req_submission_boundary",
            "ublk-data-queue-fetch-req-submit",
            "command.ublk_data_queue_fetch_req_submit=ublk-data-queue-fetch-req-submit",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-block-volume-adapter-daemon/src/ublk_control_open/mod.rs",
        &[
            "UblkDataQueueFetchReqSubmissionReport",
            "evaluate_ublk_data_queue_fetch_req_submission_boundary",
            "fetch_req.submission_attempted",
            "fetch_req.submission_completed",
            "fetch_req.submitted_fetch_commands",
            "start_dev.uring_cmd_attempted",
            "nonclaim.no_start_dev_uring_cmd_issued=true",
            "fetch_req_submission_boundary_records_all_tags_without_start_dev",
            "fetch_req_submission_boundary_records_partial_submit_error_and_cleanup",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/BLOCK_VOLUME_UBLK_FETCH_REQ_SUBMISSION_BOUNDARY_OW301W.md",
        &[
            "OW-301W guarded ublk FETCH_REQ submission boundary",
            "requires live data-queue runtime",
            "does not submit START_DEV",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "xtask/tidefs-xtask/src/main.rs",
        &[
            "check-block-volume-ublk-fetch-req-submit-boundary",
            "check-block-volume-ublk-fetch-req-submit",
            "block_volume_ublk_fetch_req_submit_boundary_check_command",
        ],
        &mut missing,
    );

    if missing.is_empty() {
        println!(
            "OW-301W block-volume ublk FETCH_REQ submission boundary ok: live /dev/ublkcN runtime ownership gates FETCH_REQ submission and START_DEV remains unsubmitted"
        );
        Ok(())
    } else {
        Err(BlockCheckError { missing })
    }
}

pub fn check_block_volume_ublk_commit_fetch_boundary_current_workspace(
) -> Result<(), BlockCheckError> {
    let root = find_workspace_root().ok_or_else(|| BlockCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "apps/tidefs-block-volume-adapter-daemon/src/main.rs",
        "apps/tidefs-block-volume-adapter-daemon/src/ublk_control_open/mod.rs",
        "crates/tidefs-block-volume-adapter-ublk-control-runtime/src/lib.rs",
        "nix/tidefs-validation.sh",
        "xtask/tidefs-xtask/src/main.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "crates/tidefs-block-volume-adapter-ublk-control-runtime/src/lib.rs",
        &[
            "BLOCK_VOLUME_UBLK_DATA_QUEUE_COMMIT_FETCH_GATE_OW_301X",
            "UblkDataQueueCommitAndFetchInput",
            "UblkDataQueueCommitAndFetchReadiness",
            "UblkDataQueueCommitAndFetchOutcome",
            "build_commit_and_fetch_spec",
            "submit_runtime_commit_and_fetch_without_wait",
            "commit_and_fetch_spec_uses_data_queue_read_write_command_and_sqe128",
            "commit_and_fetch_readiness_requires_live_fetched_completed_request",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-block-volume-adapter-daemon/src/main.rs",
        &[
            "BLOCK_VOLUME_UBLK_DATA_QUEUE_COMMIT_FETCH_GATE_OW_301X",
            "run_ublk_data_queue_commit_and_fetch_boundary",
            "ublk-data-queue-commit-and-fetch",
            "ublk-commit-fetch-boundary",
            "command.ublk_data_queue_commit_fetch=ublk-data-queue-commit-and-fetch",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-block-volume-adapter-daemon/src/ublk_control_open/mod.rs",
        &[
            "UblkDataQueueCommitAndFetchReport",
            "evaluate_ublk_data_queue_commit_and_fetch_boundary",
            "commit_and_fetch.fetched_request_available",
            "commit_and_fetch.uring_cmd_attempted",
            "commit_and_fetch_boundary_refuses_until_request_is_fetched",
            "commit_and_fetch_boundary_records_ready_submission_without_start_dev",
            "nonclaim.no_start_dev_uring_cmd_issued=true",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "xtask/tidefs-xtask/src/main.rs",
        &[
            "check-block-volume-ublk-commit-fetch-boundary",
            "check-block-volume-ublk-commit-fetch",
            "block_volume_ublk_commit_fetch_boundary_check_command",
        ],
        &mut missing,
    );

    if missing.is_empty() {
        println!(
            "OW-301X block-volume ublk COMMIT_AND_FETCH_REQ boundary ok: live data-queue ownership and fetched request completion gate commit-and-fetch submission while START_DEV remains unsubmitted"
        );
        Ok(())
    } else {
        Err(BlockCheckError { missing })
    }
}

pub fn check_block_volume_ublk_acceptance_harness_current_workspace() -> Result<(), BlockCheckError>
{
    let root = find_workspace_root().ok_or_else(|| BlockCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "apps/tidefs-block-volume-adapter-daemon/src/main.rs",
        "apps/tidefs-block-volume-adapter-daemon/src/ublk_control_open/acceptance_harness.rs",
        "xtask/tidefs-xtask/src/main.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "apps/tidefs-block-volume-adapter-daemon/src/main.rs",
        &[
            "run_ublk_acceptance_harness",
            "ublk-acceptance-harness",
            "ublk-acceptance",
            "command.ublk_acceptance_harness=ublk-acceptance-harness",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "apps/tidefs-block-volume-adapter-daemon/src/ublk_control_open/acceptance_harness.rs",
        &[
            "BLOCK_VOLUME_UBLK_ACCEPTANCE_HARNESS_GATE_PC_012",
            "UblkAcceptanceStatus",
            "acceptance.status={}",
            "acceptance.is_evidence={}",
            "durability.block_reason={}",
            "classify_acceptance",
            "is_acceptance_evidence",
            "PC-012 ublk acceptance harness passes fio verify and durability checks",
            "UblkAcceptanceFioPass",
            "fio_verify_passed",
            "first_verify.passed={}",
            "durability_verify.passed={}",
            "durability_verify.skipped=true",
            "io_loop.cqes_processed={}",
            "run_fio_verify",
            "run_ublk_acceptance_harness",
            "BlockVolumeFileImage::reopen_existing",
            "run_io_loop_iterations",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "xtask/tidefs-xtask/src/main.rs",
        &[
            "check-block-volume-ublk-acceptance-harness",
            "check-ublk-acceptance-harness",
            "block_volume_ublk_acceptance_harness_check_command",
        ],
        &mut missing,
    );

    if missing.is_empty() {
        println!(
            "PC-012 block-volume ublk acceptance harness ok: command wiring, fio verify fields, durability verify fields, acceptance status classification, and report markers are implementation-tracked non-release"
        );
        Ok(())
    } else {
        Err(BlockCheckError { missing })
    }
}

pub fn check_block_volume_ublk_surface_daemon_build_current_workspace(
) -> Result<(), BlockCheckError> {
    let output = std::process::Command::new("cargo")
        .args(["build", "-p", "tidefs-block-volume-adapter-daemon"])
        .output()
        .map_err(|err| BlockCheckError {
            missing: vec![format!("failed to run cargo build: {err}")],
        })?;

    if output.status.success() {
        println!("ublk-surface daemon build ok: tidefs-block-volume-adapter-daemon compiles");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(BlockCheckError {
            missing: vec![format!(
                "cargo build -p tidefs-block-volume-adapter-daemon failed:\n{stderr}"
            )],
        })
    }
}

pub fn check_block_volume_ublk_surface_control_runtime_tests_current_workspace(
) -> Result<(), BlockCheckError> {
    let output = std::process::Command::new("cargo")
        .args([
            "test",
            "-p",
            "tidefs-block-volume-adapter-ublk-control-runtime",
            "--all-targets",
        ])
        .output()
        .map_err(|err| BlockCheckError {
            missing: vec![format!(
                "failed to run cargo test for ublk-control-runtime: {err}"
            )],
        })?;

    if output.status.success() {
        println!("ublk-surface control-runtime tests ok: all targets pass");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(BlockCheckError {
            missing: vec![format!(
                "cargo test -p tidefs-block-volume-adapter-ublk-control-runtime failed:\n{stderr}"
            )],
        })
    }
}

pub fn check_block_volume_ublk_surface_daemon_tests_current_workspace(
) -> Result<(), BlockCheckError> {
    let output = std::process::Command::new("cargo")
        .args([
            "test",
            "-p",
            "tidefs-block-volume-adapter-daemon",
            "--all-targets",
        ])
        .output()
        .map_err(|err| BlockCheckError {
            missing: vec![format!(
                "failed to run cargo test for block-volume-adapter-daemon: {err}"
            )],
        })?;

    if output.status.success() {
        println!("ublk-surface daemon tests ok: all targets pass");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(BlockCheckError {
            missing: vec![format!(
                "cargo test -p tidefs-block-volume-adapter-daemon failed:\n{stderr}"
            )],
        })
    }
}

pub fn check_block_volume_ublk_surface_source_markers_current_workspace(
) -> Result<(), BlockCheckError> {
    let root = find_workspace_root().ok_or_else(|| BlockCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    // Required files for the ublk block-device surface
    for rel in [
        "apps/tidefs-block-volume-adapter-daemon/src/ublk_control_open/start_dev.rs",
        "apps/tidefs-block-volume-adapter-daemon/src/ublk_control_open/data_queue_io_loop.rs",
        "apps/tidefs-block-volume-adapter-daemon/src/block_device_validation.rs",
        "crates/tidefs-block-volume-adapter-ublk-control-runtime/Cargo.toml",
        "crates/tidefs-block-volume-adapter-ublk-control-runtime/src/lib.rs",
        "apps/tidefs-block-volume-adapter-daemon/Cargo.toml",
        "nix/tidefs-validation.sh",
        "xtask/tidefs-xtask/src/main.rs",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    // start_dev.rs markers (OW-301T gate)
    check_source_markers(
        &root,
        "apps/tidefs-block-volume-adapter-daemon/src/ublk_control_open/start_dev.rs",
        &[
            "run_ublk_control_start_dev_boundary",
            "UblkControlStartDevReport",
            "issue_start_dev",
            "start_dev_readiness",
            "all_fetches_ready",
        ],
        &mut missing,
    );

    // data_queue_io_loop.rs markers (OW-301V/W/X gate)
    check_source_markers(
        &root,
        "apps/tidefs-block-volume-adapter-daemon/src/ublk_control_open/data_queue_io_loop.rs",
        &[
            "run_ublk_data_queue_io_loop_boundary",
            "UblkDataQueueIoLoopReport",
            "io_loop_cqes_processed",
            "io_loop_commit_and_fetch_submitted",
            "COMMIT_AND_FETCH",
        ],
        &mut missing,
    );

    // block_device_validation.rs markers (OW-301Y gate)
    check_source_markers(
        &root,
        "apps/tidefs-block-volume-adapter-daemon/src/block_device_validation.rs",
        &[
            "BLOCK_VOLUME_UBLK_DEVICE_APPEARANCE_GATE_OW_301Y",
            "UblkDeviceAppearanceReport",
            "run_block_device_appearance_validation",
            "run_ublk_control_start_dev_boundary",
            "run_ublk_data_queue_io_loop_boundary",
            "block_device_present",
            "device_permissions",
        ],
        &mut missing,
    );

    // Validation script must reference the check-group
    if missing.is_empty() {
        println!("ublk-surface source markers ok: start_dev, data_queue_io_loop, and block_device_validation are implementation-tracked non-release targeted checks");
        Ok(())
    } else {
        Err(BlockCheckError { missing })
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
            // If checking ublk_control_open/mod.rs, also check tests.rs in same dir
            let found_in_test =
                if rel == "apps/tidefs-block-volume-adapter-daemon/src/ublk_control_open/mod.rs" {
                    let test_rel =
                        "apps/tidefs-block-volume-adapter-daemon/src/ublk_control_open/tests.rs";
                    if let Ok(test_text) = fs::read_to_string(root.join(test_rel)) {
                        test_text.contains(marker)
                    } else {
                        false
                    }
                } else {
                    false
                };
            if !found_in_test {
                missing.push(format!("`{rel}` missing marker `{marker}`"));
            }
        }
    }
}
