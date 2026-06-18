#![forbid(unsafe_code)]

mod bg_framework;

mod authority;
mod block;
mod claims;
mod cluster;
mod contract_codecs;
mod coverage;
mod crash_oracle;
mod forgejo_work;
mod format_golden;
mod hygiene;
mod kernel_closure;
mod kmod_guard;
mod no_hidden_queues;
mod observe;
mod platform;
mod policy;
mod qemu_pin;
mod storage;
mod terminology;
mod trace_oracle;

use std::env;
use std::process;
use std::process::Command;
use tidefs_types_package_profile_catalog::SURFACES;
// Group check macros: call check functions directly (no re-exec)
macro_rules! run_checks {
    ($($check:expr),* $(,)?) => {{
        let mut errors: Vec<String> = Vec::new();
        $(
            if let Err(e) = $check {
                errors.push(format!("FAIL: {e}"));
            }
        )*
        if !errors.is_empty() {
            for e in &errors { eprintln!("{e}"); }
            process::exit(1);
        }
    }}
}

fn main() {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        None | Some("summary") => print_summary(),
        Some("check-workspace-policy" | "check") => {
            if let Err(err) = policy::check_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-workspace-hygiene") => {
            if let Err(err) = hygiene::check_workspace_hygiene() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-background-service-framework" | "check-bg-framework") => {
            if let Err(err) = bg_framework::check_background_service_framework_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-code-navigability") => {
            if let Err(err) = run_code_navigability_check() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-trace-oracle") => {
            let trace_oracle_args: Vec<String> = args.collect();
            let result = if trace_oracle_args.is_empty() {
                trace_oracle::check_trace_oracle_current_workspace()
            } else {
                trace_oracle::check_trace_oracle_current_workspace_with_args(
                    trace_oracle_args.into_iter(),
                )
            };
            if let Err(err) = result {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-crash-oracle") => {
            if let Err(err) = crash_oracle::check_crash_oracle_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-contract-codecs") => {
            if let Err(err) = contract_codecs::check_contract_codecs_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("terminology" | "human-map") => terminology::print_human_map(),
        Some("human-api" | "human-api-aliases") => terminology::print_human_api_aliases(),
        Some("check-terminology") => {
            if let Err(err) = terminology::check_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-human-readability") => {
            if let Err(err) = terminology::check_human_readability_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-human-api-aliases") => {
            if let Err(err) = terminology::check_human_api_aliases_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-prepreview-naming") => {
            if let Err(err) = terminology::check_prepreview_naming_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-platform-scaffolding" | "check-nix-qemu-rdma") => {
            if let Err(err) = platform::check_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("collect-qemu-pin-manifest" | "qemu-pin-manifest") => {
            qemu_pin::run_collect(args);
        }

        Some("perf-gate" | "performance-gate") => {
            // Parse optional --baseline <path> and --current-run <path> flags
            let mut baseline_path: Option<String> = None;
            let mut current_run_path: Option<String> = None;
            let mut positional_args: Vec<String> = Vec::new();
            while let Some(arg) = args.next() {
                if arg == "--baseline" {
                    baseline_path = args.next();
                } else if arg == "--current-run" {
                    current_run_path = args.next();
                } else {
                    positional_args.push(arg);
                }
            }
            let mut pargs = positional_args.into_iter();

            let commit_sha = pargs.next().unwrap_or_else(|| {
                std::process::Command::new("git")
                    .args(["rev-parse", "--short", "HEAD"])
                    .output()
                    .ok()
                    .and_then(|o| String::from_utf8(o.stdout).ok())
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|| "unknown".into())
            });

            let profile_ref = pargs.next().unwrap_or_else(|| "ci-default".into());
            let storage_backend = pargs.next().unwrap_or_else(|| "los".into());
            let cache_mode = pargs.next().unwrap_or_else(|| "none".into());

            let env_manifest =
                tidefs_validation::performance_gate::system_info::capture_environment(
                    &profile_ref,
                    &storage_backend,
                    &cache_mode,
                );

            let receipt = if let (Some(ref bp), Some(ref cr)) = (&baseline_path, &current_run_path)
            {
                tidefs_validation::performance_gate::runner::GateRunner::build_from_baseline_and_current(
                    &commit_sha,
                    env_manifest,
                    bp,
                    cr,
                )
            } else if let Some(ref bp) = baseline_path {
                tidefs_validation::performance_gate::runner::GateRunner::build_from_baseline_package(
                    &commit_sha,
                    env_manifest,
                    bp,
                )
            } else {
                tidefs_validation::performance_gate::runner::GateRunner::build_current_head_receipt(
                    &commit_sha,
                    env_manifest,
                )
            };

            let md = receipt.render_markdown();
            println!("{md}");

            let receipt_dir = if let Some(ref bp) = baseline_path {
                format!("{bp}/perf-gate-receipt")
            } else {
                "/root/ai/tmp/tidefs-validation".to_string()
            };
            let receipt_path = std::path::PathBuf::from(format!(
                "{receipt_dir}/perf-gate-receipt-{}.json",
                &receipt.generated_at.replace([':', 'T'], "-")
            ));
            if let Some(parent) = receipt_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            match serde_json::to_string_pretty(&receipt) {
                Ok(json) => {
                    if let Err(e) = std::fs::write(&receipt_path, &json) {
                        eprintln!(
                            "perf-gate: failed to write receipt to {}: {}",
                            receipt_path.display(),
                            e
                        );
                    } else {
                        eprintln!(
                            "perf-gate receipt written to {}: rows={} passed={} failed={} refused={} skipped={} artifact_gap={} budget_gap={} release_ready={}",
                            receipt_path.display(),
                            receipt.summary.total,
                            receipt.summary.passed,
                            receipt.summary.failed,
                            receipt.summary.refused,
                            receipt.summary.skipped,
                            receipt.summary.artifact_gap,
                            receipt.summary.budget_gap,
                            receipt.release_ready,
                        );
                    }
                }
                Err(e) => {
                    eprintln!("perf-gate: failed to serialize receipt: {e}");
                }
            }

            // Write markdown receipt alongside JSON
            let md_path = receipt_path.with_extension("md");
            let _ = std::fs::write(&md_path, &md);

            let mut exit_code = 0i32;

            if !receipt.invariant_holds {
                eprintln!(
                    "PERF GATE FAIL: required subjects missing — {}",
                    receipt.missing_subjects.join(", ")
                );
                exit_code = 1;
            }

            if !receipt.release_ready {
                let mut reasons: Vec<String> = Vec::new();
                if receipt.summary.artifact_gap > 0 {
                    reasons.push(format!(
                        "{} rows with artifact gaps",
                        receipt.summary.artifact_gap
                    ));
                }
                if receipt.summary.budget_gap > 0 {
                    reasons.push(format!(
                        "{} rows with budget gaps",
                        receipt.summary.budget_gap
                    ));
                }
                if receipt.summary.failed > 0 {
                    reasons.push(format!("{} rows failed", receipt.summary.failed));
                }
                if receipt.summary.runtime_pass == 0 {
                    reasons.push("no runtime validation rows passed".into());
                }
                let reason_str = if reasons.is_empty() {
                    "no release-ready conditions met".into()
                } else {
                    reasons.join("; ")
                };
                eprintln!("PERF GATE FAIL: not release-ready — {reason_str}");
                if exit_code == 0 {
                    exit_code = 1;
                }
            }

            if receipt.summary.artifact_gap > 0 || receipt.summary.budget_gap > 0 {
                eprintln!(
                    "PERF GATE: {} artifact gaps, {} budget gaps — review receipt for details",
                    receipt.summary.artifact_gap, receipt.summary.budget_gap,
                );
            }

            if exit_code != 0 {
                process::exit(exit_code);
            }
        }

        Some("check-observation-substrate" | "check-adaptive-governor") => {
            if let Err(err) = observe::check_observation_substrate_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-authority-publication-spine" | "check-authority-spine") => {
            if let Err(err) = authority::check_authority_publication_spine_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-validation-packaging-host-probe" | "check-wave-zero-d") => {
            if let Err(err) = observe::check_validation_packaging_host_probe_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-membership-epoch-model" | "check-cluster-membership") => {
            if let Err(err) = cluster::check_membership_epoch_model_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-membership-types") => {
            if let Err(err) = cluster::check_membership_types_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-p8-03-distributed-runtime") => {
            if let Err(err) = cluster::check_p8_03_distributed_runtime_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-failure-domain-placement" | "check-replica-placement") => {
            if let Err(err) = cluster::check_failure_domain_placement_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-replicated-storage-model" | "check-replicated-storage") => {
            if let Err(err) = cluster::check_replicated_storage_model_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-rebuild-backfill-rebalance" | "check-rebuild-rebalance") => {
            if let Err(err) = cluster::check_rebuild_backfill_rebalance_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-erasure-coded-layout" | "check-erasure-layout") => {
            if let Err(err) = cluster::check_erasure_coded_layout_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-chunk-shipper") => {
            if let Err(err) = cluster::check_chunk_shipper_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-flow-commit-coordinator") => {
            if let Err(err) = cluster::check_flow_commit_coordinator_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-extent-map") => {
            if let Err(err) = cluster::check_extent_map_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-extent-map-v2") => {
            if let Err(err) = cluster::check_extent_map_v2_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-locator-table") => {
            if let Err(err) = cluster::check_locator_table_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-checksum-architecture") => {
            if let Err(err) = cluster::check_checksum_architecture_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-feature-flags" | "check-dataset-feature-flags") => {
            if let Err(err) = cluster::check_feature_flags_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-feature-flags-validate") => {
            // compile-time validity guaranteed by canonical_feature! macro
        }
        Some("check-polymorphic-directory-index" | "check-polymorphic-dir-index") => {
            if let Err(err) = cluster::check_polymorphic_directory_index_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-polymorphic-xattr") => {
            if let Err(err) = cluster::check_polymorphic_xattr_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-posix-acl") => {
            if let Err(err) = cluster::check_posix_acl_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-pool-allocator") => {
            if let Err(err) = cluster::check_pool_allocator_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-posix-acl-integration") => {
            if let Err(err) = storage::check_posix_acl_integration_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-poolstore-compression") => {
            if let Err(err) = storage::check_poolstore_compression_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-mounted-transform-authority" | "check-transform-authority") => {
            if let Err(err) = storage::check_mounted_transform_authority_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-btree") => {
            if let Err(err) = storage::check_btree_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-dir-index") => {
            if let Err(err) = storage::check_dir_index_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-xattr-storage") => {
            if let Err(err) = storage::check_xattr_storage_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-background-scheduler") => {
            if let Err(err) = storage::check_background_scheduler_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-background-scheduler-fs") => {
            if let Err(err) = storage::check_background_scheduler_fs_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-background-reclaim") => {
            if let Err(err) = storage::check_background_reclaim_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-polymorphic-extent-map") => {
            if let Err(err) = storage::check_polymorphic_extent_map_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-reclaim-delta-recording") => {
            if let Err(err) = storage::check_reclaim_delta_recording_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-dataset-lifecycle") => {
            if let Err(err) = storage::check_dataset_lifecycle_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-posix-acl-inheritance") => {
            if let Err(err) = storage::check_posix_acl_inheritance_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-posix-acl-fuse-eval") => {
            if let Err(err) = storage::check_posix_acl_fuse_eval_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-block-volume-adapter-core" | "check-block-volume-core") => {
            if let Err(err) = block::check_block_volume_adapter_core_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-block-volume-queue-admission" | "check-block-volume-queue") => {
            if let Err(err) = block::check_block_volume_queue_admission_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-block-volume-dispatch-execution" | "check-block-volume-dispatch") => {
            if let Err(err) = block::check_block_volume_dispatch_execution_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-block-volume-export-lifecycle" | "check-block-volume-lifecycle") => {
            if let Err(err) = block::check_block_volume_export_lifecycle_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-block-volume-cache-coherency" | "check-block-volume-cache") => {
            if let Err(err) = block::check_block_volume_cache_coherency_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-block-volume-resize-fence" | "check-block-volume-resize") => {
            if let Err(err) = block::check_block_volume_resize_fence_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-block-volume-host-preflight" | "check-block-volume-host") => {
            if let Err(err) = block::check_block_volume_host_preflight_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-block-volume-ublk-abi" | "check-ublk-abi") => {
            if let Err(err) = block::check_block_volume_ublk_abi_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-block-volume-file-backing" | "check-block-volume-backing-file") => {
            if let Err(err) = block::check_block_volume_file_backing_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some(
            "check-block-volume-ublk-control-open" | "check-block-volume-ublk-control-runtime",
        ) => {
            if let Err(err) = block::check_block_volume_ublk_control_open_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some(
            "check-block-volume-ublk-control-readonly-probe"
            | "check-block-volume-ublk-control-get-features",
        ) => {
            if let Err(err) =
                block::check_block_volume_ublk_control_readonly_probe_current_workspace()
            {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-block-volume-ublk-add-dev-boundary" | "check-block-volume-ublk-add-dev") => {
            if let Err(err) = block::check_block_volume_ublk_add_dev_boundary_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some(
            "check-block-volume-ublk-del-dev-cleanup-boundary" | "check-block-volume-ublk-del-dev",
        ) => {
            if let Err(err) =
                block::check_block_volume_ublk_del_dev_cleanup_boundary_current_workspace()
            {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some(
            "check-block-volume-ublk-set-params-boundary" | "check-block-volume-ublk-set-params",
        ) => {
            if let Err(err) = block::check_block_volume_ublk_set_params_boundary_current_workspace()
            {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some(
            "check-block-volume-ublk-start-dev-boundary" | "check-block-volume-ublk-start-dev",
        ) => {
            if let Err(err) = block::check_block_volume_ublk_start_dev_boundary_current_workspace()
            {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some(
            "check-block-volume-ublk-fetch-req-readiness-boundary"
            | "check-block-volume-ublk-fetch-req",
        ) => {
            if let Err(err) =
                block::check_block_volume_ublk_fetch_req_readiness_boundary_current_workspace()
            {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some(
            "check-block-volume-ublk-data-queue-open-boundary"
            | "check-block-volume-ublk-data-queue-open",
        ) => {
            if let Err(err) =
                block::check_block_volume_ublk_data_queue_open_boundary_current_workspace()
            {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some(
            "check-block-volume-ublk-fetch-req-submit-boundary"
            | "check-block-volume-ublk-fetch-req-submit",
        ) => {
            if let Err(err) =
                block::check_block_volume_ublk_fetch_req_submit_boundary_current_workspace()
            {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some(
            "check-block-volume-ublk-commit-fetch-boundary"
            | "check-block-volume-ublk-commit-fetch",
        ) => {
            if let Err(err) =
                block::check_block_volume_ublk_commit_fetch_boundary_current_workspace()
            {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-block-volume-ublk-acceptance-harness" | "check-ublk-acceptance-harness") => {
            if let Err(err) = block::check_block_volume_ublk_acceptance_harness_current_workspace()
            {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-local-store") => {
            if let Err(err) = storage::check_local_object_store_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-local-store-format" | "check-object-store-format") => {
            if let Err(err) = storage::check_local_object_store_on_disk_format_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-production-integrity" | "check-integrity-policy") => {
            if let Err(err) = storage::check_production_integrity_policy_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-production-integrity-v3" | "check-v3-record-integrity") => {
            if let Err(err) = storage::check_production_integrity_v3_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-root-authentication" | "check-root-auth") => {
            if let Err(err) = storage::check_root_authentication_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-local-snapshots" | "check-snapshot-rollback") => {
            if let Err(err) = storage::check_local_snapshots_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-send-receive" | "check-changed-record-export-import") => {
            if let Err(err) = storage::check_send_receive_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-online-verifier" | "check-online-scrub") => {
            if let Err(err) = storage::check_online_verifier_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-hot-read-cache" | "check-read-cache") => {
            if let Err(err) = storage::check_hot_read_cache_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-module-owners" | "check-module-invariants") => {
            if let Err(err) = storage::check_module_owners_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-claims-gate" | "check-overclaims") => {
            if let Err(err) = claims::check_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("validate-claim") => {
            let claim_id = match args.next() {
                Some(claim_id) => claim_id,
                None => {
                    eprintln!("validate-claim requires a claim id");
                    process::exit(2);
                }
            };
            if let Some(extra) = args.next() {
                eprintln!("validate-claim accepts one claim id, got extra argument `{extra}`");
                process::exit(2);
            }
            if let Err(err) = claims::validate_claim_current_workspace(&claim_id) {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("validate-ublk-completion-artifact") => {
            let artifact_path = match args.next() {
                Some(path) => path,
                None => {
                    eprintln!("validate-ublk-completion-artifact requires an artifact path");
                    process::exit(2);
                }
            };
            if let Some(extra) = args.next() {
                eprintln!(
                    "validate-ublk-completion-artifact accepts one path, got extra argument `{extra}`"
                );
                process::exit(2);
            }
            match tidefs_validation::ublk_completion_artifact::validate_ublk_completion_artifact_path(
                &artifact_path,
            ) {
                Ok(summary) => {
                    println!(
                        "ublk completion artifact validated: events={} terminal_completions={} queues={} depth={}",
                        summary.event_count,
                        summary.terminal_completion_count,
                        summary.nr_hw_queues,
                        summary.queue_depth
                    );
                }
                Err(err) => {
                    eprintln!("{err}");
                    process::exit(1);
                }
            }
        }
        Some("validate-ublk-started-export-admission-artifact") => {
            let artifact_path = match args.next() {
                Some(path) => path,
                None => {
                    eprintln!(
                        "validate-ublk-started-export-admission-artifact requires an artifact path"
                    );
                    process::exit(2);
                }
            };
            if let Some(extra) = args.next() {
                eprintln!(
                    "validate-ublk-started-export-admission-artifact accepts one path, got extra argument `{extra}`"
                );
                process::exit(2);
            }
            match tidefs_validation::ublk_started_export_admission_artifact::validate_ublk_started_export_admission_artifact_path(
                &artifact_path,
            ) {
                Ok(summary) => {
                    println!(
                        "ublk started-export admission artifact validated: claim_state={} start_dev_succeeded={} first_request_serviced={} bounded_no_request_observed={} cleanup_succeeded={}",
                        summary.claim_state,
                        summary.start_dev_succeeded,
                        summary.first_request_serviced,
                        summary.bounded_no_request_observed,
                        summary.cleanup_succeeded
                    );
                }
                Err(err) => {
                    eprintln!("{err}");
                    process::exit(1);
                }
            }
        }
        Some("validate-evidence-manifest") => {
            let artifact_path = match args.next() {
                Some(path) => path,
                None => {
                    eprintln!("validate-evidence-manifest requires an artifact path");
                    process::exit(2);
                }
            };
            if let Some(extra) = args.next() {
                eprintln!(
                    "validate-evidence-manifest accepts one path, got extra argument `{extra}`"
                );
                process::exit(2);
            }
            match tidefs_validation::evidence_artifact_manifest::load_evidence_artifact_manifest_json_path(
                &artifact_path,
            ) {
                Ok(manifest) => {
                    println!(
                        "evidence manifest validated: claim_id={} evidence_class={} source={} scope={}",
                        manifest.claim_id, manifest.evidence_class, manifest.source, manifest.scope
                    );
                }
                Err(err) => {
                    eprintln!("{err}");
                    process::exit(1);
                }
            }
        }

        Some("check-no-hidden-queues") => {
            if let Err(err) = no_hidden_queues::check_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-claim-gate" | "check-worktree-claim") => {
            if let Err(err) = forgejo_work::check_claim_gate_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-stale-claims" | "check-stale-forgejo-claims") => {
            if let Err(err) = forgejo_work::check_stale_claims_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-duplicate-claims" | "check-duplicate-forgejo-claims") => {
            if let Err(err) = forgejo_work::check_duplicate_claims_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-kernel-closure" | "check-kernel-portable-closure") => {
            if let Err(err) = kernel_closure::check_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-abandoned-worktrees" | "check-stale-worktrees") => {
            if let Err(err) = forgejo_work::check_abandoned_worktrees_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("auto-release-stale-claims" | "auto-release-stale" | "auto-release") => {
            if let Err(err) = forgejo_work::auto_release_stale_claims() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("coordination-health" | "coordination-health-report") => {
            if let Err(err) = forgejo_work::print_coordination_health_report() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("acquire-claim" | "claim-issue") => {
            let issue_num: u64 = match args.next().and_then(|s| s.parse().ok()) {
                Some(n) => n,
                None => {
                    eprintln!("usage: tidefs-xtask acquire-claim <issue-number>");
                    process::exit(1);
                }
            };
            match forgejo_work::acquire_claim(issue_num) {
                Ok(true) => {
                    println!("claimed issue #{issue_num}");
                }
                Ok(false) => {
                    println!("issue #{issue_num} is already claimed");
                }
                Err(err) => {
                    eprintln!("claim failed: {err}");
                    process::exit(1);
                }
            }
        }
        Some("generate-format-golden") => {
            if let Err(err) = format_golden::generate_format_golden() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("validate-format-golden") => {
            if let Err(err) = format_golden::validate_format_golden() {
                eprintln!("{err}");
                process::exit(1);
            }
        }

        Some("check-local-filesystem") => {
            if let Err(err) = storage::check_local_filesystem_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-chunked-file-layout") => {
            if let Err(err) = storage::check_chunked_file_layout_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-local-storage-allocator" | "check-free-space-accounting") => {
            if let Err(err) = storage::check_local_storage_allocator_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-space-accounting-watermarks") => {
            if let Err(err) = storage::check_space_accounting_watermarks_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }

        Some("check-no-fsck-recovery") => {
            if let Err(err) = storage::check_no_fsck_recovery_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-no-fsck-failure-model" | "check-failure-model") => {
            if let Err(err) = storage::check_no_production_fsck_failure_model_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-crash-injection-recovery" | "check-crash-recovery") => {
            if let Err(err) = storage::check_crash_injection_recovery_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-recovery-probe" | "check-mount-readiness") => {
            if let Err(err) = storage::check_recovery_probe_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-recovery-manifest-audit" | "check-root-manifest-audit") => {
            if let Err(err) = storage::check_recovery_manifest_audit_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-mount-invariant-gate" | "check-mount-invariants") => {
            if let Err(err) = storage::check_mount_invariant_gate_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-preview-posix-subset" | "check-posix-subset") => {
            if let Err(err) = storage::check_preview_posix_subset_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-fuse-mount-path" | "check-userspace-fuse") => {
            if let Err(err) = storage::check_fuse_mount_path_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-posix-semantics") => {
            if let Err(err) = storage::check_posix_semantics_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-seek-hole-data") => {
            if let Err(err) = storage::check_seek_hole_data_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-xfstests-harness") => {
            if let Err(err) = storage::check_xfstests_harness_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-rename-exchange") => {
            if let Err(err) = storage::check_rename_exchange_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-rename-noreplace") => {
            if let Err(err) = storage::check_rename_noreplace_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-file-locking") => {
            if let Err(err) = storage::check_file_locking_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-mmap-coherency") => {
            if let Err(err) = storage::check_mmap_coherency_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-xattrs") => {
            if let Err(err) = storage::check_xattrs_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-fallocate-mode0") => {
            if let Err(err) = storage::check_fallocate_mode0_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-fallocate-punch-hole") => {
            if let Err(err) = storage::check_fallocate_punch_hole_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-fiemap") => {
            if let Err(err) = storage::check_fiemap_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-space-management") => {
            if let Err(err) = storage::check_space_management_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-transaction-model") => {
            if let Err(err) = storage::check_transaction_model_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-integrity-pipeline") => {
            if let Err(err) = storage::check_integrity_pipeline_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-posix-scoreboard") => {
            if let Err(err) = storage::check_posix_scoreboard_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-root-retention") => {
            if let Err(err) = storage::check_root_retention_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some(
            "check-safe-local-reclamation"
            | "check-safe-reclamation"
            | "check-safe-gc"
            | "check-local-gc",
        ) => {
            if let Err(err) = storage::check_safe_local_reclamation_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-scrub-tool" | "check-object-store-scrub") => {
            if let Err(err) = storage::check_scrub_tool_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-spacemap-allocator" | "check-spacemap") => {
            if let Err(err) = storage::check_spacemap_allocator_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-orphan-index") => {
            if let Err(err) = storage::check_orphan_index_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-dead-crates" | "check-dead-crate-audit") => {
            if let Err(err) = policy::check_dead_crates_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-secret-policy") => {
            let mode = args.next();
            let result = match mode.as_deref() {
                None => policy::check_secret_policy_current_workspace(),
                Some("--seeded-violation-fixtures") => {
                    if let Some(extra) = args.next() {
                        eprintln!(
                            "check-secret-policy --seeded-violation-fixtures accepts no extra argument, got `{extra}`"
                        );
                        process::exit(2);
                    }
                    policy::check_secret_policy_seeded_violation_fixtures()
                }
                Some(extra) => {
                    eprintln!(
                        "usage: cargo run -p tidefs-xtask -- check-secret-policy [--seeded-violation-fixtures]"
                    );
                    eprintln!("unexpected check-secret-policy argument `{extra}`");
                    process::exit(2);
                }
            };
            if let Err(err) = result {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-coverage-closure") => {
            if let Err(err) = coverage::check_coverage_closure_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-kmod-blake3-guard") => {
            if let Err(err) = kmod_guard::check_kmod_blake3_guard_current_workspace() {
                eprintln!("{err}");
                process::exit(1);
            }
        }
        Some("check-dispatch-exists") => {
            let name = args.next().unwrap_or_else(|| {
                eprintln!("check-dispatch-exists requires a FUSE callback name (e.g. readlink, rename, tmpfile)");
                process::exit(2);
            });
            if name == "--help" || name == "-h" {
                eprintln!("usage: cargo run -p tidefs-xtask -- check-dispatch-exists <name>");
                eprintln!("  Checks whether a FUSE callback method already exists");
                eprintln!("  in FuseVfsAdapter (apps/.../fuse_vfs_adapter.rs).");
                eprintln!("  Exits 0 if found (prints line number), 1 if missing.");
                return;
            }
            let adapter_path = std::path::Path::new(
                "apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_vfs_adapter.rs",
            );
            let text = std::fs::read_to_string(adapter_path).unwrap_or_else(|e| {
                eprintln!("could not read {}: {e}", adapter_path.display());
                process::exit(1);
            });
            let pattern = format!("fn {name}(");
            let found: Vec<(usize, &str)> = text
                .lines()
                .enumerate()
                .filter(|(_, line)| line.trim_start().starts_with(&pattern))
                .map(|(i, line)| (i + 1, line.trim()))
                .collect();
            if found.is_empty() {
                eprintln!("dispatch {name}: NOT FOUND in FuseVfsAdapter");
                process::exit(1);
            }
            for (lineno, line) in &found {
                println!("dispatch {name}: already exists at line {lineno} — {line}");
            }
        }

        Some("check-group") => {
            let group = args.next().unwrap_or_else(|| {
                eprintln!("check-group requires a group name");
                eprintln!("Available groups: policy, terminology, platform, observe, authority, cluster, block, ublk-surface, storage, claims, format, all");
                process::exit(1);
            });
            match group.as_str() {
                "policy" => run_checks!(
                    policy::check_current_workspace(),
                    run_code_navigability_check(),
                ),
                "terminology" => run_checks!(
                    terminology::check_current_workspace(),
                    terminology::check_human_readability_current_workspace(),
                    terminology::check_human_api_aliases_current_workspace(),
                    terminology::check_prepreview_naming_current_workspace(),
                ),
                "platform" => run_checks!(platform::check_current_workspace(),),
                "observe" => run_checks!(
                    observe::check_observation_substrate_current_workspace(),
                    observe::check_validation_packaging_host_probe_current_workspace(),
                ),
                "authority" => {
                    run_checks!(authority::check_authority_publication_spine_current_workspace(),)
                }
                "cluster" => run_checks!(
                    cluster::check_membership_epoch_model_current_workspace(),
                    cluster::check_membership_types_current_workspace(),
                    cluster::check_failure_domain_placement_current_workspace(),
                    cluster::check_replicated_storage_model_current_workspace(),
                    cluster::check_rebuild_backfill_rebalance_current_workspace(),
                    cluster::check_erasure_coded_layout_current_workspace(),
                    cluster::check_chunk_shipper_current_workspace(),
                    cluster::check_p8_03_distributed_runtime_current_workspace(),
                ),
                "block" => run_checks!(
                    block::check_block_volume_adapter_core_current_workspace(),
                    block::check_block_volume_queue_admission_current_workspace(),
                    block::check_block_volume_dispatch_execution_current_workspace(),
                    block::check_block_volume_export_lifecycle_current_workspace(),
                    block::check_block_volume_cache_coherency_current_workspace(),
                    block::check_block_volume_resize_fence_current_workspace(),
                    block::check_block_volume_host_preflight_current_workspace(),
                    block::check_block_volume_ublk_abi_current_workspace(),
                    block::check_block_volume_file_backing_current_workspace(),
                    block::check_block_volume_ublk_control_open_current_workspace(),
                    block::check_block_volume_ublk_control_readonly_probe_current_workspace(),
                    block::check_block_volume_ublk_add_dev_boundary_current_workspace(),
                    block::check_block_volume_ublk_del_dev_cleanup_boundary_current_workspace(),
                    block::check_block_volume_ublk_set_params_boundary_current_workspace(),
                    block::check_block_volume_ublk_start_dev_boundary_current_workspace(),
                    block::check_block_volume_ublk_fetch_req_readiness_boundary_current_workspace(),
                    block::check_block_volume_ublk_data_queue_open_boundary_current_workspace(),
                    block::check_block_volume_ublk_fetch_req_submit_boundary_current_workspace(),
                    block::check_block_volume_ublk_commit_fetch_boundary_current_workspace(),
                    block::check_block_volume_ublk_acceptance_harness_current_workspace(),
                ),
                "ublk-surface" => run_checks!(
                    block::check_block_volume_ublk_surface_daemon_build_current_workspace(),
                    block::check_block_volume_ublk_surface_control_runtime_tests_current_workspace(
                    ),
                    block::check_block_volume_ublk_surface_daemon_tests_current_workspace(),
                    block::check_block_volume_ublk_surface_source_markers_current_workspace(),
                ),
                "storage" => run_checks!(
                    storage::check_local_object_store_current_workspace(),
                    storage::check_local_object_store_on_disk_format_current_workspace(),
                    storage::check_production_integrity_policy_current_workspace(),
                    storage::check_local_filesystem_current_workspace(),
                    storage::check_no_fsck_recovery_current_workspace(),
                    storage::check_no_production_fsck_failure_model_current_workspace(),
                    storage::check_crash_injection_recovery_current_workspace(),
                    storage::check_recovery_probe_current_workspace(),
                    storage::check_integrity_pipeline_current_workspace(),
                    storage::check_recovery_manifest_audit_current_workspace(),
                    storage::check_mount_invariant_gate_current_workspace(),
                    storage::check_root_retention_current_workspace(),
                    storage::check_xattr_storage_current_workspace(),
                    storage::check_background_scheduler_current_workspace(),
                    storage::check_background_scheduler_fs_current_workspace(),
                    storage::check_polymorphic_extent_map_current_workspace(),
                    storage::check_dataset_lifecycle_current_workspace(),
                    storage::check_space_accounting_watermarks_current_workspace(),
                ),
                "claims" => run_checks!(
                    claims::check_current_workspace(),
                    forgejo_work::check_claim_gate_current_workspace(),
                    forgejo_work::check_stale_claims_current_workspace(),
                    forgejo_work::check_duplicate_claims_current_workspace(),
                    forgejo_work::check_abandoned_worktrees_current_workspace(),
                ),
                "format" => run_checks!(
                    format_golden::validate_format_golden(),
                    run_cargo_fmt_check(),
                ),
                "all" => run_all_checks(),
                _ => {
                    eprintln!("unknown check group: {group}");
                    eprintln!("Available groups: policy, terminology, platform, observe, authority, cluster, block, ublk-surface, storage, claims, format, all");
                    process::exit(2);
                }
            }
            println!("\nAll checks in group '{group}' passed");
        }

        Some("help" | "--help" | "-h") => print_help(),
        Some(other) => {
            eprintln!("unknown tidefs-xtask command: {other}");
            eprintln!("run `cargo run -p tidefs-xtask -- help` for usage");
            process::exit(2);
        }
    }
}

fn run_all_checks() {
    let mut errors: Vec<String> = Vec::new();
    // policy
    if let Err(e) = policy::check_current_workspace() {
        errors.push(format!("policy/check-workspace-policy: {e}"));
    }
    if let Err(e) = run_code_navigability_check() {
        errors.push(format!("policy/check-code-navigability: {e}"));
    }
    // terminology
    if let Err(e) = terminology::check_current_workspace() {
        errors.push(format!("terminology/check-terminology: {e}"));
    }
    if let Err(e) = terminology::check_human_readability_current_workspace() {
        errors.push(format!("terminology/check-human-readability: {e}"));
    }
    if let Err(e) = terminology::check_human_api_aliases_current_workspace() {
        errors.push(format!("terminology/check-human-api-aliases: {e}"));
    }
    if let Err(e) = terminology::check_prepreview_naming_current_workspace() {
        errors.push(format!("terminology/check-prepreview-naming: {e}"));
    }
    // platform
    if let Err(e) = platform::check_current_workspace() {
        errors.push(format!("platform/check-platform-scaffolding: {e}"));
    }
    // observe
    if let Err(e) = observe::check_observation_substrate_current_workspace() {
        errors.push(format!("observe/check-observation-substrate: {e}"));
    }
    if let Err(e) = observe::check_validation_packaging_host_probe_current_workspace() {
        errors.push(format!(
            "observe/check-validation-packaging-host-probe: {e}"
        ));
    }
    // authority
    if let Err(e) = authority::check_authority_publication_spine_current_workspace() {
        errors.push(format!("authority/check-authority-publication-spine: {e}"));
    }
    // cluster
    if let Err(e) = cluster::check_membership_epoch_model_current_workspace() {
        errors.push(format!("cluster/check-membership-epoch-model: {e}"));
    }
    if let Err(e) = cluster::check_membership_types_current_workspace() {
        errors.push(format!("cluster/check-membership-types: {e}"));
    }
    if let Err(e) = cluster::check_failure_domain_placement_current_workspace() {
        errors.push(format!("cluster/check-failure-domain-placement: {e}"));
    }
    if let Err(e) = cluster::check_replicated_storage_model_current_workspace() {
        errors.push(format!("cluster/check-replicated-storage-model: {e}"));
    }
    if let Err(e) = cluster::check_rebuild_backfill_rebalance_current_workspace() {
        errors.push(format!("cluster/check-rebuild-backfill-rebalance: {e}"));
    }
    if let Err(e) = cluster::check_erasure_coded_layout_current_workspace() {
        errors.push(format!("cluster/check-erasure-coded-layout: {e}"));
    }
    if let Err(e) = cluster::check_chunk_shipper_current_workspace() {
        errors.push(format!("cluster/check-chunk-shipper: {e}"));
    }
    if let Err(e) = cluster::check_flow_commit_coordinator_current_workspace() {
        errors.push(format!("cluster/check-flow-commit-coordinator: {e}"));
    }
    if let Err(e) = cluster::check_extent_map_current_workspace() {
        errors.push(format!("cluster/check-extent-map: {e}"));
    }
    if let Err(e) = cluster::check_locator_table_current_workspace() {
        errors.push(format!("cluster/check-locator-table: {e}"));
    }
    if let Err(e) = cluster::check_checksum_architecture_current_workspace() {
        errors.push(format!("cluster/check-checksum-architecture: {e}"));
    }
    if let Err(e) = cluster::check_p8_03_distributed_runtime_current_workspace() {
        errors.push(format!("cluster/check-p8-03-distributed-runtime: {e}"));
    }
    // block
    if let Err(e) = block::check_block_volume_adapter_core_current_workspace() {
        errors.push(format!("block/check-block-volume-adapter-core: {e}"));
    }
    if let Err(e) = block::check_block_volume_queue_admission_current_workspace() {
        errors.push(format!("block/check-block-volume-queue-admission: {e}"));
    }
    if let Err(e) = block::check_block_volume_dispatch_execution_current_workspace() {
        errors.push(format!("block/check-block-volume-dispatch-execution: {e}"));
    }
    if let Err(e) = block::check_block_volume_export_lifecycle_current_workspace() {
        errors.push(format!("block/check-block-volume-export-lifecycle: {e}"));
    }
    if let Err(e) = block::check_block_volume_cache_coherency_current_workspace() {
        errors.push(format!("block/check-block-volume-cache-coherency: {e}"));
    }
    if let Err(e) = block::check_block_volume_resize_fence_current_workspace() {
        errors.push(format!("block/check-block-volume-resize-fence: {e}"));
    }
    if let Err(e) = block::check_block_volume_host_preflight_current_workspace() {
        errors.push(format!("block/check-block-volume-host-preflight: {e}"));
    }
    if let Err(e) = block::check_block_volume_ublk_abi_current_workspace() {
        errors.push(format!("block/check-block-volume-ublk-abi: {e}"));
    }
    if let Err(e) = block::check_block_volume_file_backing_current_workspace() {
        errors.push(format!("block/check-block-volume-file-backing: {e}"));
    }
    if let Err(e) = block::check_block_volume_ublk_control_open_current_workspace() {
        errors.push(format!("block/check-block-volume-ublk-control-open: {e}"));
    }
    if let Err(e) = block::check_block_volume_ublk_control_readonly_probe_current_workspace() {
        errors.push(format!(
            "block/check-block-volume-ublk-control-readonly-probe: {e}"
        ));
    }
    if let Err(e) = block::check_block_volume_ublk_add_dev_boundary_current_workspace() {
        errors.push(format!(
            "block/check-block-volume-ublk-add-dev-boundary: {e}"
        ));
    }
    if let Err(e) = block::check_block_volume_ublk_del_dev_cleanup_boundary_current_workspace() {
        errors.push(format!(
            "block/check-block-volume-ublk-del-dev-cleanup-boundary: {e}"
        ));
    }
    if let Err(e) = block::check_block_volume_ublk_set_params_boundary_current_workspace() {
        errors.push(format!(
            "block/check-block-volume-ublk-set-params-boundary: {e}"
        ));
    }
    if let Err(e) = block::check_block_volume_ublk_start_dev_boundary_current_workspace() {
        errors.push(format!(
            "block/check-block-volume-ublk-start-dev-boundary: {e}"
        ));
    }
    if let Err(e) = block::check_block_volume_ublk_fetch_req_readiness_boundary_current_workspace()
    {
        errors.push(format!(
            "block/check-block-volume-ublk-fetch-req-readiness-boundary: {e}"
        ));
    }
    if let Err(e) = block::check_block_volume_ublk_data_queue_open_boundary_current_workspace() {
        errors.push(format!(
            "block/check-block-volume-ublk-data-queue-open-boundary: {e}"
        ));
    }
    if let Err(e) = block::check_block_volume_ublk_fetch_req_submit_boundary_current_workspace() {
        errors.push(format!(
            "block/check-block-volume-ublk-fetch-req-submit-boundary: {e}"
        ));
    }
    if let Err(e) = block::check_block_volume_ublk_commit_fetch_boundary_current_workspace() {
        errors.push(format!(
            "block/check-block-volume-ublk-commit-fetch-boundary: {e}"
        ));
    }
    if let Err(e) = block::check_block_volume_ublk_acceptance_harness_current_workspace() {
        errors.push(format!(
            "block/check-block-volume-ublk-acceptance-harness: {e}"
        ));
    }
    // storage
    if let Err(e) = storage::check_local_object_store_current_workspace() {
        errors.push(format!("storage/check-local-store: {e}"));
    }
    if let Err(e) = storage::check_local_object_store_on_disk_format_current_workspace() {
        errors.push(format!("storage/check-local-store-format: {e}"));
    }
    if let Err(e) = storage::check_production_integrity_policy_current_workspace() {
        errors.push(format!("storage/check-production-integrity: {e}"));
    }
    if let Err(e) = storage::check_local_filesystem_current_workspace() {
        errors.push(format!("storage/check-local-filesystem: {e}"));
    }
    if let Err(e) = storage::check_mounted_transform_authority_current_workspace() {
        errors.push(format!("storage/check-mounted-transform-authority: {e}"));
    }
    if let Err(e) = storage::check_no_fsck_recovery_current_workspace() {
        errors.push(format!("storage/check-no-fsck-recovery: {e}"));
    }
    if let Err(e) = storage::check_no_production_fsck_failure_model_current_workspace() {
        errors.push(format!("storage/check-no-fsck-failure-model: {e}"));
    }
    if let Err(e) = storage::check_crash_injection_recovery_current_workspace() {
        errors.push(format!("storage/check-crash-injection-recovery: {e}"));
    }
    if let Err(e) = storage::check_recovery_probe_current_workspace() {
        errors.push(format!("storage/check-recovery-probe: {e}"));
    }
    if let Err(e) = storage::check_integrity_pipeline_current_workspace() {
        errors.push(format!("storage/check-integrity-pipeline: {e}"));
    }
    if let Err(e) = storage::check_recovery_manifest_audit_current_workspace() {
        errors.push(format!("storage/check-recovery-manifest-audit: {e}"));
    }
    if let Err(e) = storage::check_mount_invariant_gate_current_workspace() {
        errors.push(format!("storage/check-mount-invariant-gate: {e}"));
    }
    if let Err(e) = storage::check_root_retention_current_workspace() {
        errors.push(format!("storage/check-root-retention: {e}"));
    }
    if let Err(e) = storage::check_xattr_storage_current_workspace() {
        errors.push(format!("storage/check-xattr-storage: {e}"));
    }
    if let Err(e) = storage::check_background_scheduler_current_workspace() {
        errors.push(format!("storage/check-background-scheduler: {e}"));
    }
    if let Err(e) = storage::check_background_scheduler_fs_current_workspace() {
        errors.push(format!("storage/check-background-scheduler-fs: {e}"));
    }
    if let Err(e) = storage::check_polymorphic_extent_map_current_workspace() {
        errors.push(format!("storage/check-polymorphic-extent-map: {e}"));
    }
    if let Err(e) = storage::check_dataset_lifecycle_current_workspace() {
        errors.push(format!("storage/check-dataset-lifecycle: {e}"));
    }
    if let Err(e) = storage::check_space_accounting_watermarks_current_workspace() {
        errors.push(format!("storage/check-space-accounting-watermarks: {e}"));
    }
    // claims
    if let Err(e) = claims::check_current_workspace() {
        errors.push(format!("claims/check-claims-gate: {e}"));
        // forgejo_work
        if let Err(e) = forgejo_work::check_claim_gate_current_workspace() {
            errors.push(format!("forgejo_work/check-claim-gate: {e}"));
        }
        if let Err(e) = forgejo_work::check_stale_claims_current_workspace() {
            errors.push(format!("forgejo_work/check-stale-claims: {e}"));
        }
        if let Err(e) = forgejo_work::check_abandoned_worktrees_current_workspace() {
            errors.push(format!("forgejo_work/check-abandoned-worktrees: {e}"));
        }
    }
    // kernel closure
    if let Err(e) = kernel_closure::check_current_workspace() {
        errors.push(format!("kernel_closure/check-kernel-closure: {e}"));
    }
    // format
    if let Err(e) = format_golden::validate_format_golden() {
        errors.push(format!("format/check-format-golden: {e}"));
    }
    // report
    if !errors.is_empty() {
        let total = errors.len();
        for e in &errors {
            eprintln!("{e}");
        }
        eprintln!("\n{total} checks FAILED");
        process::exit(1);
    }
    println!("All 67 checks passed");
}

fn run_code_navigability_check() -> Result<(), String> {
    let output = Command::new("cargo")
        .args(["clippy", "--workspace", "--all-targets", "--all-features"])
        .output()
        .map_err(|e| format!("failed to run cargo clippy: {e}"))?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let warnings = clippy_warning_lines(&stderr);

    if !warnings.is_empty() {
        eprintln!("cargo clippy found {} warning(s):", warnings.len());
        for w in warnings.iter().take(10) {
            eprintln!("  {w}");
        }
        if warnings.len() > 10 {
            eprintln!("  ... and {} more", warnings.len() - 10);
        }
    }

    if !output.status.success() {
        eprintln!("cargo clippy failed with {}", output.status);
        let details = clippy_output_excerpt(&stdout, &stderr, 12);
        if !details.is_empty() {
            eprintln!("first clippy failure lines:");
            for line in details {
                eprintln!("  {line}");
            }
        }
        return Err(format!(
            "cargo clippy failed with {}; {} warning(s) detected",
            output.status,
            warnings.len()
        ));
    }

    if warnings.is_empty() {
        Ok(())
    } else {
        Err(format!("{} clippy warning(s) detected", warnings.len()))
    }
}

fn clippy_warning_lines(stderr: &str) -> Vec<&str> {
    stderr
        .lines()
        .filter(|line| line.contains("warning:"))
        .collect()
}

fn clippy_output_excerpt(stdout: &str, stderr: &str, max_lines: usize) -> Vec<String> {
    stderr
        .lines()
        .chain(stdout.lines())
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with("Checking "))
        .filter(|line| !line.starts_with("Compiling "))
        .take(max_lines)
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod code_navigability_tests {
    use super::*;

    #[test]
    fn clippy_warning_lines_counts_warning_lines() {
        let stderr = "\
warning: first lint
note: help text
warning: second lint
";

        let warnings = clippy_warning_lines(stderr);
        assert_eq!(
            warnings,
            vec!["warning: first lint", "warning: second lint"]
        );
    }

    #[test]
    fn clippy_output_excerpt_keeps_failure_context() {
        let stdout = "    Checking ignored\nstdout detail\n";
        let stderr = "\
    Compiling skipped

error[E0308]: mismatched types
  --> src/lib.rs:1:1
";

        let details = clippy_output_excerpt(stdout, stderr, 3);
        assert_eq!(
            details,
            vec![
                "error[E0308]: mismatched types",
                "--> src/lib.rs:1:1",
                "stdout detail"
            ]
        );
    }
}

fn run_cargo_fmt_check() -> Result<(), String> {
    let output = Command::new("cargo")
        .args(["fmt", "--", "--check"])
        .output()
        .map_err(|e| format!("failed to run cargo fmt: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let details: Vec<&str> = stdout
            .lines()
            .filter(|line| line.contains("Diff in"))
            .collect();
        if !details.is_empty() {
            eprintln!(
                "cargo fmt --check found {} unformatted file(s):",
                details.len()
            );
            for d in details.iter().take(20) {
                eprintln!("  {d}");
            }
            if details.len() > 20 {
                eprintln!("  ... and {} more", details.len() - 20);
            }
        } else if !stderr.is_empty() {
            eprintln!("cargo fmt failed:\n{stderr}");
        }
        Err("cargo fmt --check failed: unformatted files detected".to_string())
    }
}

fn print_summary() {
    println!("tidefs Wave Zero workspace summary");
    println!("group_commands=check-group-policy,check-group-terminology,check-group-platform,check-group-observe,check-group-authority,check-group-cluster,check-group-block,check-group-storage,check-group-claims,check-group-all");
    println!("human_spine=Control Plane -> Policy Authority -> Publication Pipeline -> Response Registry");
    println!("stable_locator_spine=control_plane -> policy_authority -> publication_pipeline -> response_registry");
    for surface in SURFACES {
        print!(
            "- binary={} | service={} | service_key={} | stable_family_id={} | profile={} | bundle={} | capabilities=",
            surface.binary_name,
            surface.human_name(),
            surface.rust_hint(),
            surface.family.stable_id(),
            surface.profile.human_name(),
            surface.bundle.human_name(),
        );
        for (idx, cap) in surface.capabilities.iter().enumerate() {
            if idx != 0 {
                print!(",");
            }
            print!("{}", cap.human_name());
        }
        print!(" | stable_capability_ids=");
        for (idx, cap) in surface.capabilities.iter().enumerate() {
            if idx != 0 {
                print!(",");
            }
            print!("{}", cap.stable_id());
        }
        println!(" | stage={}", surface.stage);
    }
    println!("policy_check_command=check-workspace-policy");
    println!("code_navigability_check_command=check-code-navigability");
    println!("contract_codecs_check_command=check-contract-codecs");
    println!("terminology_command=terminology");
    println!("terminology_check_command=check-terminology");
    println!("human_readability_check_command=check-human-readability");
    println!("human_api_aliases_command=human-api");
    println!("human_api_aliases_check_command=check-human-api-aliases");
    println!("prepreview_naming_check_command=check-prepreview-naming");
    println!("platform_scaffolding_check_command=check-platform-scaffolding");
    println!("observation_substrate_check_command=check-observation-substrate");
    println!("authority_spine_check_command=check-authority-publication-spine");
    println!("validation_packaging_host_probe_check_command=check-validation-packaging-host-probe");
    println!("membership_epoch_model_check_command=check-membership-epoch-model");
    println!("membership_types_check_command=check-membership-types");
    println!("failure_domain_placement_check_command=check-failure-domain-placement");
    println!("replicated_storage_model_check_command=check-replicated-storage-model");
    println!("rebuild_backfill_rebalance_check_command=check-rebuild-backfill-rebalance");
    println!("erasure_coded_layout_check_command=check-erasure-coded-layout");
    println!(
        "block_volume_adapter_core_check_command=check-block-volume-adapter-core stable_id=block_volume_adapter human_name=\"Block Volume Adapter Core\""
    );
    println!(
        "block_volume_queue_admission_check_command=check-block-volume-queue-admission stable_id=block_volume_adapter human_name=\"Block Volume Adapter Queue Admission\""
    );
    println!(
        "block_volume_dispatch_execution_check_command=check-block-volume-dispatch-execution stable_id=block_volume_adapter human_name=\"Block Volume Adapter Dispatch Execution\""
    );
    println!(
        "block_volume_export_lifecycle_check_command=check-block-volume-export-lifecycle stable_id=block_volume_adapter human_name=\"Block Volume Adapter Export Lifecycle\""
    );
    println!(
        "block_volume_cache_coherency_check_command=check-block-volume-cache-coherency stable_id=block_volume_adapter human_name=\"Block Volume Adapter Cache Coherency\""
    );
    println!(
        "block_volume_resize_fence_check_command=check-block-volume-resize-fence stable_id=block_volume_adapter human_name=\"Block Volume Adapter Resize Fence\""
    );
    println!(
        "block_volume_host_preflight_check_command=check-block-volume-host-preflight stable_id=block_volume_adapter human_name=\"Block Volume Adapter Host Preflight\""
    );
    println!(
        "block_volume_ublk_abi_check_command=check-block-volume-ublk-abi stable_id=block_volume_adapter human_name=\"Block Volume Adapter ublk ABI\""
    );
    println!(
        "block_volume_file_backing_check_command=check-block-volume-file-backing stable_id=block_volume_adapter human_name=\"Block Volume Adapter File Backing\""
    );
    println!(
        "block_volume_ublk_control_open_check_command=check-block-volume-ublk-control-open stable_id=block_volume_adapter human_name=\"Block Volume Adapter ublk Control Open\""
    );
    println!(
        "block_volume_ublk_control_readonly_probe_check_command=check-block-volume-ublk-control-readonly-probe stable_id=block_volume_adapter human_name=\"Block Volume Adapter ublk Control Readonly Probe\""
    );
    println!(
        "block_volume_ublk_add_dev_boundary_check_command=check-block-volume-ublk-add-dev-boundary stable_id=block_volume_adapter human_name=\"Block Volume Adapter ublk ADD_DEV Boundary\""
    );
    println!(
        "block_volume_ublk_del_dev_cleanup_boundary_check_command=check-block-volume-ublk-del-dev-cleanup-boundary stable_id=block_volume_adapter human_name=\"Block Volume Adapter ublk DEL_DEV Cleanup Boundary\""
    );
    println!(
        "block_volume_ublk_set_params_boundary_check_command=check-block-volume-ublk-set-params-boundary stable_id=block_volume_adapter human_name=\"Block Volume Adapter ublk SET_PARAMS Boundary\""
    );
    println!(
        "block_volume_ublk_start_dev_boundary_check_command=check-block-volume-ublk-start-dev-boundary stable_id=block_volume_adapter human_name=\"Block Volume Adapter ublk START_DEV Boundary\""
    );
    println!(
        "block_volume_ublk_fetch_req_readiness_boundary_check_command=check-block-volume-ublk-fetch-req-readiness-boundary stable_id=block_volume_adapter human_name=\"Block Volume Adapter ublk FETCH_REQ Readiness Boundary\""
    );
    println!(
        "block_volume_ublk_data_queue_open_boundary_check_command=check-block-volume-ublk-data-queue-open-boundary stable_id=block_volume_adapter human_name=\"Block Volume Adapter ublk Data Queue Open Boundary\""
    );
    println!(
        "block_volume_ublk_fetch_req_submit_boundary_check_command=check-block-volume-ublk-fetch-req-submit-boundary stable_id=block_volume_adapter human_name=\"Block Volume Adapter ublk FETCH_REQ Submit Boundary\""
    );
    println!(
        "block_volume_ublk_commit_fetch_boundary_check_command=check-block-volume-ublk-commit-fetch-boundary stable_id=block_volume_adapter human_name=\"Block Volume Adapter ublk COMMIT_AND_FETCH_REQ Boundary\""
    );
    println!(
        "block_volume_ublk_acceptance_harness_check_command=check-block-volume-ublk-acceptance-harness stable_id=block_volume_adapter human_name=\"Block Volume Adapter ublk Acceptance Harness\""
    );
    println!("local_store_check_command=check-local-store");
    println!("local_store_format_check_command=check-local-store-format");
    println!("production_integrity_check_command=check-production-integrity");
    println!("production_integrity_v3_check_command=check-production-integrity-v3");
    println!("root_authentication_check_command=check-root-authentication");
    println!("local_snapshots_check_command=check-local-snapshots");
    println!("send_receive_check_command=check-send-receive");
    println!("online_verifier_check_command=check-online-verifier");
    println!("hot_read_cache_check_command=check-hot-read-cache");
    println!("module_owners_check_command=check-module-owners");
    println!("claims_gate_check_command=check-claims-gate");
    println!("claim_validate_command=validate-claim");
    println!("claim_gate_check_command=check-claim-gate");
    println!("stale_claims_check_command=check-stale-claims");
    println!("duplicate_claims_check_command=check-duplicate-claims");
    println!("abandoned_worktrees_check_command=check-abandoned-worktrees");
    println!("auto_release_stale_check_command=auto-release-stale-claims");
    println!("coordination_health_command=coordination-health");
    println!("acquire_claim_command=acquire-claim");
    println!("group_check_command=check-group");
    println!("local_filesystem_check_command=check-local-filesystem");
    println!("chunked_file_layout_check_command=check-chunked-file-layout");
    println!("local_storage_allocator_check_command=check-local-storage-allocator");
    println!("no_production_fsck_recovery_check_command=check-no-fsck-recovery");
    println!("no_production_fsck_failure_model_check_command=check-no-fsck-failure-model");
    println!("crash_injection_recovery_check_command=check-crash-injection-recovery");
    println!("crash_recovery_check_command=check-crash-recovery");
    println!("recovery_probe_check_command=check-recovery-probe");
    println!("mount_readiness_check_command=check-mount-readiness");
    println!("recovery_manifest_audit_check_command=check-recovery-manifest-audit");
    println!("mount_invariant_gate_check_command=check-mount-invariant-gate");
    println!("preview_posix_subset_check_command=check-preview-posix-subset");
    println!("fuse_mount_path_check_command=check-fuse-mount-path");
    println!("posix_semantics_check_command=check-posix-semantics");
    println!("seek_hole_data_check_command=check-seek-hole-data");
    println!("xfstests_harness_check_command=check-xfstests-harness");
    println!("rename_exchange_check_command=check-rename-exchange");
    println!("rename_noreplace_check_command=check-rename-noreplace");
    println!("file_locking_check_command=check-file-locking");
    println!("mmap_coherency_check_command=check-mmap-coherency");
    println!("xattrs_check_command=check-xattrs");
    println!("fallocate_mode0_check_command=check-fallocate-mode0");
    println!("fallocate_punch_hole_check_command=check-fallocate-punch-hole");
    println!("fiemap_check_command=check-fiemap");
    println!("space_management_check_command=check-space-management");
    println!("transaction_model_check_command=check-transaction-model");
    println!("integrity_pipeline_check_command=check-integrity-pipeline");
    println!("posix_scoreboard_check_command=check-posix-scoreboard");
    println!("scrub_tool_check_command=check-scrub-tool");
    println!("spacemap_allocator_check_command=check-spacemap-allocator");
    println!("orphan_index_check_command=check-orphan-index");
    println!("posix_acl_check_command=check-posix-acl");
    println!("posix_acl_integration_check_command=check-posix-acl-integration");
    println!("posix_acl_inheritance_check_command=check-posix-acl-inheritance");
    println!("root_retention_check_command=check-root-retention");
    println!("safe_reclamation_check_command=check-safe-local-reclamation");
}

fn print_help() {
    println!("tidefs-xtask commands:");
    println!("  summary                  print current human-readable surface inventory");
    println!();
    println!("  --- Gate group commands ---");
    println!(
        "  check-group policy        run workspace-policy and code-navigability checks (2 checks)"
    );
    println!("  check-group terminology   run all terminology checks (4 checks)");
    println!("  check-group platform      run platform scaffolding checks");
    println!("  check-group observe       run current observe checks (2 checks)");
    println!("  check-group authority     run authority publication spine check (2 checks)");
    println!("  check-group cluster       run all cluster checks (7 checks)");
    println!("  check-group block         run all block-volume checks (26 checks)");
    println!("  check-group storage       run all storage checks (36 checks)");
    println!("  check-group claims        run claims gate + work ownership + kernel closure checks (6 checks)");
    println!("  check-group all           run all 80 checks, report all failures");
    println!();
    println!("  --- Individual check commands ---");
    println!("  check-workspace-policy   validate workspace_layout dependency-edge rules");
    println!(
        "  check-workspace-hygiene detect duplicate Cargo.toml deps, mod decls, and use imports"
    );
    println!("  check-code-navigability  validate zero clippy-warning state across all targets");
    println!("  terminology              print human terminology map");
    println!("  check-terminology        validate required human-terminology docs");
    println!("  human-api                print human-named Rust API alias map");
    println!("  check-human-api-aliases  validate required human-named Rust API alias modules");
    println!("  check-human-readability  detect naked internal-locator use in selected public docs and demo labels");
    println!(
        "  check-prepreview-naming detect banned pre-cleanup wording and compact family labels"
    );
    println!("  check-platform-scaffolding validate Nix, QEMU, and optional RDMA repo surfaces");
    println!("  check-nix-qemu-rdma alias for check-platform-scaffolding");
    println!("  collect-qemu-pin-manifest collect a QEMU pin manifest outside repo storage");
    println!("  qemu-pin-manifest        alias for collect-qemu-pin-manifest");
    println!("  perf-gate [--baseline <path>] [--current-run <path>] [sha] [profile] [backend] [cache]  run performance regression gate");
    println!("  performance-gate         alias for perf-gate");
    println!("  check-observation-substrate validate current VFS truth-view markers");
    println!("  check-adaptive-governor alias for check-observation-substrate");
    println!(
        "  check-authority-publication-spine validate current authority/publication/response/POSIX wake markers"
    );
    println!("  check-authority-spine alias for check-authority-publication-spine");
    println!("  check-projection-charter validate Rule 6 POSIX projection charter markers");
    println!(
        "  check-validation-packaging-host-probe validate current block-volume host preflight markers"
    );
    println!("  check-wave-zero-d alias for check-validation-packaging-host-probe");
    println!("  check-membership-epoch-model validate OW-302 membership epoch model markers");
    println!("  check-cluster-membership alias for check-membership-epoch-model");
    println!(
        "  check-membership-types    validate MEMBERSHIP wire types with CRC32C encode/decode"
    );
    println!("  check-failure-domain-placement validate OW-303 failure-domain placement markers");
    println!("  check-replica-placement alias for check-failure-domain-placement");
    println!("  check-replicated-storage-model validate OW-304 replicated storage markers");
    println!("  check-replicated-storage alias for check-replicated-storage-model");
    println!(
        "  check-rebuild-backfill-rebalance validate OW-305 rebuild/backfill/rebalance markers"
    );
    println!("  check-rebuild-rebalance alias for check-rebuild-backfill-rebalance");
    println!("  check-erasure-coded-layout validate OW-306 erasure-coded layout markers");
    println!("  check-erasure-layout alias for check-erasure-coded-layout");
    println!("  check-chunk-shipper      validate P8-03 data_copy_6 chunk shipper markers");
    println!("  check-flow-commit-coordinator validate P8-03 data_copy_7 flow commit coordinator markers");
    println!(
        "  check-extent-map         validate V1 inline-list extent map implementation markers"
    );
    println!("  check-polymorphic-dir-index validate polymorphic directory index type definitions and canonical registry");
    println!("  check-polymorphic-xattr   validate polymorphic xattr storage type definitions and canonical registry");
    println!("  check-pool-allocator    validate pool allocator crate markers (#1347)");
    println!(
        "  check-posix-acl-integration validate POSIX ACL local-filesystem integration markers"
    );
    println!("  check-posix-acl-inheritance validate POSIX ACL default inheritance on create/mkdir markers");
    println!("  check-background-reclaim validate #1459 BackgroundReclaim BackgroundService on LocalFileSystem");
    println!("  check-polymorphic-directory-index alias for check-polymorphic-dir-index");
    println!(
        "  check-trace-oracle       validate trace oracle crate and replay golden trace corpus"
    );
    println!(
        "  check-trace-oracle --compare-trace <path> compare model/local-runtime backends for one trace"
    );
    println!("  check-crash-oracle       validate crash oracle crate and crash matrix artifact");
    println!("  check-contract-codecs    validate request contract codec golden vectors");
    println!(
        "  check-locator-table      validate V1 inline-hash locator table implementation markers"
    );
    println!(
        "  check-checksum-architecture validate G3 end-to-end checksum architecture design markers"
    );
    println!("  check-background-scheduler validate background service framework crate");
    println!(
        "  check-background-scheduler-fs validate LocalFileSystem BackgroundScheduler integration"
    );
    println!("  check-background-service-framework validate background service framework gate (#3404): all services registered, priority ordering, budget enforcement, starvation prevention");
    println!("  check-bg-framework     alias for check-background-service-framework");
    println!("  check-feature-flags      validate dataset feature flags type definitions and canonical registry");
    println!("  check-dataset-feature-flags alias for check-feature-flags");
    println!(
        "  check-block-volume-adapter-core validate OW-301A block-volume adapter core markers"
    );
    println!("  check-block-volume-core alias for check-block-volume-adapter-core");
    println!(
        "  check-block-volume-queue-admission validate OW-301B block-volume queue admission markers"
    );
    println!("  check-block-volume-queue alias for check-block-volume-queue-admission");
    println!(
        "  check-block-volume-dispatch-execution validate OW-301C block-volume dispatch markers"
    );
    println!("  check-block-volume-dispatch alias for check-block-volume-dispatch-execution");
    println!(
        "  check-block-volume-export-lifecycle validate OW-301D block-volume lifecycle markers"
    );
    println!("  check-block-volume-lifecycle alias for check-block-volume-export-lifecycle");
    println!(
        "  check-block-volume-cache-coherency validate OW-301E block-volume cache coherency markers"
    );
    println!("  check-block-volume-cache alias for check-block-volume-cache-coherency");
    println!(
        "  check-block-volume-resize-fence validate OW-301F block-volume resize/fence markers"
    );
    println!("  check-block-volume-resize alias for check-block-volume-resize-fence");
    println!(
        "  check-block-volume-host-preflight validate OW-301H block-volume host preflight markers"
    );
    println!("  check-block-volume-host alias for check-block-volume-host-preflight");
    println!("  check-block-volume-ublk-abi validate OW-301I block-volume ublk ABI markers");
    println!("  check-ublk-abi alias for check-block-volume-ublk-abi");
    println!(
        "  check-block-volume-file-backing validate OW-301N block-volume file-backed image markers"
    );
    println!("  check-block-volume-backing-file alias for check-block-volume-file-backing");
    println!(
        "  check-block-volume-ublk-control-open validate OW-301O block-volume ublk control open markers"
    );
    println!(
        "  check-block-volume-ublk-control-runtime alias for check-block-volume-ublk-control-open"
    );
    println!(
        "  check-block-volume-ublk-control-readonly-probe validate OW-301P read-only GET_FEATURES markers"
    );
    println!(
        "  check-block-volume-ublk-control-get-features alias for check-block-volume-ublk-control-readonly-probe"
    );
    println!("  check-block-volume-ublk-add-dev-boundary validate OW-301Q guarded ADD_DEV markers");
    println!(
        "  check-block-volume-ublk-add-dev alias for check-block-volume-ublk-add-dev-boundary"
    );
    println!(
        "  check-block-volume-ublk-del-dev-cleanup-boundary validate OW-301R guarded DEL_DEV cleanup markers"
    );
    println!(
        "  check-block-volume-ublk-del-dev alias for check-block-volume-ublk-del-dev-cleanup-boundary"
    );
    println!(
        "  check-block-volume-ublk-set-params-boundary validate OW-301S guarded SET_PARAMS markers"
    );
    println!(
        "  check-block-volume-ublk-set-params alias for check-block-volume-ublk-set-params-boundary"
    );
    println!(
        "  check-block-volume-ublk-start-dev-boundary validate OW-301T guarded START_DEV markers"
    );
    println!(
        "  check-block-volume-ublk-start-dev alias for check-block-volume-ublk-start-dev-boundary"
    );
    println!(
        "  check-block-volume-ublk-fetch-req-readiness-boundary validate OW-301U guarded FETCH_REQ readiness markers"
    );
    println!(
        "  check-block-volume-ublk-fetch-req alias for check-block-volume-ublk-fetch-req-readiness-boundary"
    );
    println!(
        "  check-block-volume-ublk-data-queue-open-boundary validate OW-301V guarded data-queue open markers"
    );
    println!(
        "  check-block-volume-ublk-data-queue-open alias for check-block-volume-ublk-data-queue-open-boundary"
    );
    println!(
        "  check-block-volume-ublk-fetch-req-submit-boundary validate OW-301W guarded FETCH_REQ submission markers"
    );
    println!(
        "  check-block-volume-ublk-fetch-req-submit alias for check-block-volume-ublk-fetch-req-submit-boundary"
    );
    println!(
        "  check-block-volume-ublk-commit-fetch-boundary validate OW-301X guarded COMMIT_AND_FETCH_REQ markers"
    );
    println!(
        "  check-block-volume-ublk-commit-fetch alias for check-block-volume-ublk-commit-fetch-boundary"
    );
    println!(
        "  check-block-volume-ublk-acceptance-harness validate PC-012 ublk acceptance harness markers"
    );
    println!(
        "  check-ublk-acceptance-harness alias for check-block-volume-ublk-acceptance-harness"
    );
    println!(
        "  check-local-store        validate the first durable local object-store source slice"
    );
    println!("  check-local-store-format validate the local object-store on-disk format spec");
    println!("  check-object-store-format alias for check-local-store-format");
    println!("  check-production-integrity validate the production integrity policy spec");
    println!("  check-integrity-policy    alias for check-production-integrity");
    println!("  check-production-integrity-v3 validate OW-014 v3 record integrity markers");
    println!("  check-v3-record-integrity alias for check-production-integrity-v3");
    println!("  check-root-authentication validate OW-015 committed-root authentication markers");
    println!("  check-root-auth        alias for check-root-authentication");
    println!(
        "  check-mounted-transform-authority validate TFR-006 mounted raw-store inventory and transform claim guard"
    );
    println!("  check-transform-authority alias for check-mounted-transform-authority");
    println!("  check-local-snapshots validate OW-108 snapshot and rollback markers");
    println!("  check-snapshot-rollback alias for check-local-snapshots");
    println!("  check-send-receive validate OW-109 changed-record export/import markers");
    println!("  check-changed-record-export-import alias for check-send-receive");
    println!("  check-online-verifier validate OW-110 non-mutating online verifier markers");
    println!("  check-online-scrub alias for check-online-verifier");
    println!("  check-hot-read-cache validate PC-003 hot read cache markers");
    println!("  check-read-cache alias for check-hot-read-cache");
    println!("  check-module-owners validate PC-002 module owner and invariant markers");
    println!("  check-module-invariants alias for check-module-owners");
    println!("  check-claims-gate       validate publish-facing capability claims");
    println!("  check-overclaims        alias for check-claims-gate");
    println!("  validate-claim <id>     validate a registered claim evidence set");
    println!(
        "  validate-ublk-completion-artifact <path> validate qid/tag runtime completion evidence"
    );
    println!(
        "  validate-ublk-started-export-admission-artifact <path> validate started uBLK export admission evidence"
    );
    println!("  check-no-hidden-queues  validate queue roots in touched implementation packages");
    println!(
        "  validate-evidence-manifest <path> validate a claim evidence artifact manifest JSON against schema"
    );
    println!("  check-claim-gate        validate current worktree has a valid issue owner");
    println!("  check-worktree-claim    alias for check-claim-gate");
    println!("  check-stale-claims      scan Forgejo for stale codex:claimed issues");
    println!("  check-stale-forgejo-claims alias for check-stale-claims");
    println!("  check-duplicate-claims  scan Forgejo for duplicate codex:claimed work keys");
    println!("  check-duplicate-forgejo-claims alias for check-duplicate-claims");
    println!("  auto-release-stale-claims auto-release stale codex:claimed issues (set TIDEFS_AUTO_RELEASE_STALE=1 to enable)");
    println!(
        "  coordination-health      print a coordination health report from Forgejo issue metrics"
    );
    println!("  acquire-claim <N>     atomically claim issue N (adds codex:claimed label with optimistic locking)");
    println!("  check-abandoned-worktrees detect stale local worktree directories");
    println!("  check-stale-worktrees   alias for check-abandoned-worktrees");
    println!("  check-local-filesystem   validate the local filesystem MVP source slice");
    println!("  check-chunked-file-layout validate OW-101 chunked content layout markers");
    println!(
        "  check-local-storage-allocator validate OW-102 allocator/free-space accounting markers"
    );
    println!("  check-free-space-accounting alias for check-local-storage-allocator");
    println!("  check-no-fsck-recovery   validate automatic previous-or-new recovery design rule and source markers");
    println!("  check-no-fsck-failure-model validate formal failure model markers");
    println!("  check-failure-model     alias for check-no-fsck-failure-model");
    println!("  check-crash-injection-recovery validate commit-boundary crash-injection recovery markers");
    println!("  check-crash-recovery    alias for check-crash-injection-recovery");
    println!("  check-recovery-probe    validate recovery probe and mount-readiness markers");
    println!("  check-mount-readiness   alias for check-recovery-probe");
    println!(
        "  check-recovery-manifest-audit validate transaction-manifest recovery audit markers"
    );
    println!("  check-root-manifest-audit alias for check-recovery-manifest-audit");
    println!(
        "  check-mount-invariant-gate validate pre-mount namespace/link-count invariant markers"
    );
    println!("  check-mount-invariants alias for check-mount-invariant-gate");
    println!("  check-preview-posix-subset validate first FUSE-preview POSIX matrix markers");
    println!("  check-posix-subset alias for check-preview-posix-subset");
    println!("  check-fuse-mount-path validate userspace FUSE mount-path source markers");
    println!("  check-userspace-fuse alias for check-fuse-mount-path");
    println!("  check-posix-semantics validate OW-106 POSIX semantics source markers");
    println!("  check-seek-hole-data validate PC-004B FUSE lseek preview surface markers");
    println!(
        "  check-xfstests-harness validate xfstests mount helper, runner, and exclude list markers"
    );
    println!("  check-rename-exchange validate OW-108 RENAME_EXCHANGE atomic swap markers");
    println!("  check-rename-noreplace validate #481 FUSE renameat2 RENAME_NOREPLACE flag markers");
    println!("  check-file-locking validate #491 FUSE advisory file locking getlk/setlk markers");
    println!("  check-mmap-coherency validate OW-204 mmap coherency page-cache/writeback markers");
    println!("  check-xattrs           validate #496 FUSE xattr operations (set/get/list/remove) markers");
    println!("  check-fallocate-mode0  validate #494 fallocate mode-0 allocator-admitted markers");
    println!("  check-fallocate-punch-hole validate #515 fallocate punch-hole/zero-range markers");
    println!("  check-fiemap            validate #500 FUSE fiemap (FS_IOC_FIEMAP) markers");
    println!("  check-space-management  validate #537 space management allocator policy markers");
    println!("  check-spacemap-allocator validate spacemap allocator crate (SegmentFreeMap, bitmap encode/decode, generation counters)");
    println!("  check-space-accounting-watermarks validate cleaner watermarks, refresh_physical_counters, and threshold transitions");
    println!("  check-orphan-index      validate #1397 orphan index B+tree runtime markers");
    println!("  check-spacemap-allocator validate spacemap allocator crate (SegmentFreeMap, bitmap encode/decode, generation counters)");
    println!("  check-space-accounting-watermarks validate cleaner watermarks, refresh_physical_counters, and threshold transitions");
    println!("  check-transaction-model validate PC-007 transaction model markers");
    println!("  check-integrity-pipeline validate integrity pipeline source markers");
    println!("  check-posix-scoreboard validate OW-107 POSIX scoreboard source markers");
    println!("  check-root-retention   validate non-mutating committed-root retention markers");
    println!("  check-safe-local-reclamation validate OW-103 mutating-safe local GC markers");
    println!("  check-safe-reclamation alias for check-safe-local-reclamation");
    println!("  check-safe-gc          alias for check-safe-local-reclamation");
    println!("  check-local-gc         alias for check-safe-local-reclamation");
    println!("  check-dead-crates      audit all crates for zero consumers (dead crates)");
    println!("  check-dead-crate-audit alias for check-dead-crates");
    println!("  check-secret-policy [--seeded-violation-fixtures] scan workflows and policy docs for forbidden GitHub secret surfaces");
    println!("  check-coverage-closure  audit coverage gaps: scan /root/ai/tmp/tidefs-validation/ receipts and print closure snapshot");
    println!("  check-kmod-blake3-guard  scan kmod-posix-vfs source/docs for BLAKE3 proof-marker regressions");
    println!("  check-dispatch-exists  check whether a FUSE callback method already exists in FuseVfsAdapter (exits 0 with line if found, 1 if missing)");
}
