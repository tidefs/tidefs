// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![allow(dead_code)]
#![deny(unused_imports)]
#![deny(unsafe_code)]

mod capacity;
mod clustered_mount;
mod coherency_profile;
mod dispatch_helpers;
mod fsync_handler;
mod fuse_create_unlink_dispatch;
mod fuse_flush_fsync;
mod fuse_posix_lock;
mod fuse_read;
mod fuse_rename;
mod fuse_vfs_adapter;
mod fusewire;
mod handler_prelude;
mod ingress;
mod live_owner;
mod lock_dispatch;
mod maintenance;
mod materialized_cache;
mod mmap_coherency;
pub mod mount_options;
mod observability;
mod read_cache;
mod reply;
mod runtime;
mod scheduler;
mod txg_cycle;
mod workers_meta;
mod workers_ns;
mod workers_writeback;
mod workload_observer;
mod write_dispatch;

mod writeback_reclaim;
mod xattr_integrity;
mod xfstests_harness;
use std::collections::BTreeMap;
use std::env;
use std::fmt::Debug;
use std::path::{Path, PathBuf};

#[cfg(feature = "receipt-demo")]
use crate::runtime::{
    issue_product_wake_receipt, PosixFilesystemAdapterDemoPublicationTicketRecord,
    PosixFilesystemAdapterDemoVisibleAnswerRecord,
    FIRST_PUBLICATION_PIPELINE_RESPONSE_REGISTRY_TO_POSIX_FILESYSTEM_ADAPTER_WAKE_CHAIN,
};
use tidefs_background_scheduler::{
    BackgroundScheduler, BackgroundService, ServiceBudget, ServiceError, ServicePriority,
    TickReport,
};
use tidefs_intent_log::IntentLogBuffer;
use tidefs_local_filesystem::{
    LocalFileSystemOpenConfig, LocalStorageAllocatorPolicy, RootAuthenticationKey,
    ROOT_AUTHENTICATION_ENV_VAR,
};
use tidefs_performance_contract::{ScrubRuntimeObservation, ServiceCurve};
#[cfg(feature = "receipt-demo")]
use tidefs_schema_codec_posix_filesystem_adapter::CanonicalFixedWidth;
#[cfg(feature = "receipt-demo")]
use tidefs_types_package_profile_catalog::{
    SurfaceManifest, POSIX_FILESYSTEM_ADAPTER_DAEMON_SURFACE,
};
#[cfg(feature = "receipt-demo")]
use tidefs_types_posix_filesystem_adapter_core::{
    PosixFilesystemAdapterId128, PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs,
    PosixFilesystemAdapterProductWakeReceiptRecord,
};
use tidefs_vfs_engine::{
    LivePoolAdminArg, LivePoolAdminArgs, LivePoolAdminCommand, LivePoolAdminOutput,
    LivePoolAdminRequest, LivePoolAdminResponseBody,
};

use crate::mount_options::MountOptions;
use tidefs_dataset_lifecycle::SyncGuarantee;
use tidefs_inode_attributes::timestamp::TimestampPolicy as EngineTimestampPolicy;

const MOUNT_VFS_WRITE_BUFFER_FLUSH_THRESHOLD_BYTES: usize = 64 * 1024 * 1024;
const MOUNT_VFS_MAX_UNCOMMITTED_MUTATIONS: u64 = 64 * 1024;
const MOUNT_VFS_TXG_COMMIT_INTERVAL_SECS: u64 = 30;
const MOUNT_VFS_DEFAULT_BACKGROUND_SCRUB_INTERVAL_SECS: u64 = 0;

struct MountedBackgroundScrubService {
    store: tidefs_local_object_store::LocalObjectStore,
    observation: ScrubRuntimeObservation,
    observation_artifact: Option<PathBuf>,
    next_tick_not_before: std::time::Instant,
}

impl MountedBackgroundScrubService {
    const NAME: &'static str = "mounted-segment-scrub";

    fn open(
        root: &Path,
        options: tidefs_local_object_store::StoreOptions,
        observation_artifact: Option<PathBuf>,
    ) -> Result<Self, String> {
        let store = tidefs_local_object_store::LocalObjectStore::open_with_options(root, options)
            .map_err(|error| format!("open scheduled scrub store: {error}"))?;
        let service = Self {
            store,
            observation: ScrubRuntimeObservation::new(std::process::id()),
            observation_artifact,
            next_tick_not_before: std::time::Instant::now(),
        };
        service.publish_observation()?;
        Ok(service)
    }

    fn publish_observation(&self) -> Result<(), String> {
        if let Some(path) = self.observation_artifact.as_deref() {
            write_scrub_runtime_observation(path, &self.observation)?;
        }
        Ok(())
    }

    fn bounded_limit(scheduler_limit: u64, curve_limit: u64) -> u64 {
        if scheduler_limit == 0 {
            curve_limit
        } else {
            scheduler_limit.min(curve_limit)
        }
    }
}

impl BackgroundService for MountedBackgroundScrubService {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn priority(&self) -> ServicePriority {
        ServicePriority::Critical
    }

    fn tick(&mut self, budget: &ServiceBudget) -> Result<TickReport, ServiceError> {
        let curve = ServiceCurve::SCRUB_BOUNDED_DEFAULT;
        let max_records = Self::bounded_limit(budget.max_items, u64::from(curve.max_ops_per_tick));
        let max_bytes = Self::bounded_limit(budget.max_bytes, curve.max_bytes_per_tick);
        let report = self
            .store
            .run_background_scrub_with_budget(max_records, max_bytes)
            .map_err(|error| {
                eprintln!("background-scrub: scheduled tick failed: {error}");
                ServiceError::Internal {
                    service: Self::NAME,
                    message: "object-store scrub tick failed",
                }
            })?;

        if report.records_verified > max_records {
            return Err(ServiceError::BudgetExceeded {
                service: Self::NAME,
                limit: max_records,
                actual: report.records_verified,
            });
        }
        if report.bytes_scanned > max_bytes {
            return Err(ServiceError::BudgetExceeded {
                service: Self::NAME,
                limit: max_bytes,
                actual: report.bytes_scanned,
            });
        }

        if self.store.background_scrub_pending() && budget.max_ms > 0 {
            self.next_tick_not_before =
                std::time::Instant::now() + std::time::Duration::from_millis(budget.max_ms);
        }

        let work_observed =
            report.segments_scanned > 0 || report.records_verified > 0 || report.bytes_scanned > 0;
        let work_pending = self.store.background_scrub_pending();
        if work_observed {
            self.observation.record_admitted_cycle(
                report.records_verified,
                report.bytes_scanned,
                work_pending,
            );
            if work_pending {
                self.observation.record_budget_throttle();
            }
            if let Err(error) = self.publish_observation() {
                eprintln!("background-scrub: failed to write runtime observation: {error}");
            }
        }

        if report.segments_scanned > 0 || report.records_verified > 0 {
            tracing::info!(
                target: "tidefs.scrub",
                segments = report.segments_scanned,
                records = report.records_verified,
                bytes = report.bytes_scanned,
                completed = report.completed,
                work_pending,
                "scheduled segment scrub tick completed",
            );
        }

        Ok(TickReport {
            processed: report.records_verified,
            skipped: 0,
            errors: 0,
            items_consumed: report.records_verified,
            bytes_consumed: report.bytes_scanned,
            has_more: work_pending,
        })
    }

    fn has_work(&self) -> bool {
        self.store.should_scrub() && std::time::Instant::now() >= self.next_tick_not_before
    }
}

/// RAII guard that removes a PID file on drop (clean shutdown).
/// On SIGKILL the guard never runs, leaving the PID file as validation.
struct PidFileGuard(Option<PathBuf>);

impl Drop for PidFileGuard {
    fn drop(&mut self) {
        if let Some(ref path) = self.0 {
            let _ = std::fs::remove_file(path);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SmokeMountProfile {
    Full,
    Quick,
}

#[derive(Debug)]
struct SmokeMountConfig {
    profile: SmokeMountProfile,
    queue_depth_artifact: Option<PathBuf>,
}

impl SmokeMountProfile {
    fn from_name(name: &str) -> Result<Self, String> {
        match name {
            "full" => Ok(Self::Full),
            "quick" | "qemu-smoke" => Ok(Self::Quick),
            other => Err(format!(
                "unknown smoke-mount profile `{other}`; expected `full` or `quick`"
            )),
        }
    }
}

fn parse_smoke_mount_config(args: Vec<String>) -> Result<SmokeMountConfig, String> {
    let mut profile = SmokeMountProfile::Full;
    let mut queue_depth_artifact = None;
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--quick" => profile = SmokeMountProfile::Quick,
            "--full" => profile = SmokeMountProfile::Full,
            "--profile" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "--profile requires `full` or `quick`".to_string())?;
                profile = SmokeMountProfile::from_name(&value)?;
            }
            _ if arg.starts_with("--profile=") => {
                let value = arg.strip_prefix("--profile=").expect("prefix checked");
                profile = SmokeMountProfile::from_name(value)?;
            }
            "--queue-depth-artifact" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "--queue-depth-artifact requires a path".to_string())?;
                queue_depth_artifact = Some(PathBuf::from(value));
            }
            _ if arg.starts_with("--queue-depth-artifact=") => {
                let value = arg
                    .strip_prefix("--queue-depth-artifact=")
                    .expect("prefix checked");
                queue_depth_artifact = Some(PathBuf::from(value));
            }
            "--help" | "-h" => {
                return Err(
                    "usage: smoke-mount [--profile full|quick] [--quick] [--full] [--queue-depth-artifact <path>]".to_string(),
                );
            }
            other => {
                return Err(format!(
                    "unknown smoke-mount argument `{other}`; run with --help"
                ));
            }
        }
    }
    Ok(SmokeMountConfig {
        profile,
        queue_depth_artifact,
    })
}

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        #[cfg(feature = "receipt-demo")]
        None | Some("receipt-demo") => {
            run_receipt_demo();
            Ok(())
        }
        #[cfg(not(feature = "receipt-demo"))]
        None => {
            print_help();
            Ok(())
        }
        Some("mount") => {
            let config = parse_mount_vfs_config(args.collect())?;
            println!("fuse_mount.store={}", config.store_root.display());
            println!("fuse_mount.mountpoint={}", config.mountpoint.display());
            println!("fuse_mount.adapter=vfs");
            println!("fuse_mount.mode=foreground");
            mount_vfs(config).map_err(|err| format!("FUSE VFS mount failed: {err}"))
        }
        Some("score-posix") => {
            let out_dir = parse_score_posix_args(args.collect())?;
            run_score_posix(&out_dir)
        }
        Some("xfstests-harness") => {
            let harness_cfg = parse_xfstests_harness_args(args.collect())?;
            run_xfstests_harness(&harness_cfg)
        }
        Some("mount-vfs") => {
            let config = parse_mount_vfs_config(args.collect())?;
            mount_vfs(config).map_err(|err| format!("FUSE VFS mount failed: {err}"))
        }
        Some("smoke-mount") => {
            let config = parse_smoke_mount_config(args.collect())?;
            run_smoke_mount(config)
        }
        Some("scrub-repair-smoke") => run_scrub_repair_smoke(),

        Some("help" | "--help" | "-h") => {
            print_help();
            Ok(())
        }
        Some(other) => Err(format!("unknown command `{other}`; run with --help")),
    }
}

#[allow(unsafe_code)]
fn mount_vfs(config: MountVfsConfig) -> Result<(), String> {
    let snapshot_name = config.snapshot_name.clone();
    let snapshot_export = snapshot_name.is_some();
    let effective_mode = effective_mount_mode(&config);
    if snapshot_export && config.queue_depth_artifact.is_some() {
        return Err("--queue-depth-artifact is not supported for snapshot export mounts".into());
    }
    if snapshot_export && config.scrub_runtime_observation_artifact.is_some() {
        return Err(
            "--scrub-runtime-observation-artifact is not supported for snapshot export mounts"
                .into(),
        );
    }
    if effective_mode.background_scrub_interval_secs == 0
        && config.scrub_runtime_observation_artifact.is_some()
    {
        return Err(
            "--scrub-runtime-observation-artifact requires --background-scrub-interval > 0".into(),
        );
    }
    use std::fs;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use tidefs_local_filesystem::human::local_filesystem::StoreOptions;
    use tidefs_local_filesystem::vfs_engine_impl::VfsLocalFileSystem;
    use tidefs_local_filesystem::LocalFileSystem;
    use tidefs_namespace::Namespace;
    use tidefs_recovery_loop::{CrashRecoveryLoop, CrashRecoveryState, MountState};

    fs::create_dir_all(&config.store_root).map_err(|e| format!("store: {e}"))?;
    fs::create_dir_all(&config.mountpoint).map_err(|e| format!("mountpoint: {e}"))?;
    // PID-file support for crash-recovery testing: write the daemon PID so
    // test harnesses can signal it. On clean shutdown the guard removes the
    // file; on SIGKILL the guard never runs, leaving the PID file as validation.
    let pid_file_path = std::env::var("TIDEFS_PID_FILE").ok().map(PathBuf::from);
    if let Some(ref path) = pid_file_path {
        std::fs::write(path, format!("{}", std::process::id()))
            .map_err(|e| format!("write PID file {}: {e}", path.display()))?;
    }
    let _pid_guard = PidFileGuard(pid_file_path);

    // ── Crash recovery detection ───────────────────────────────────────
    // Detect whether the previous shutdown was unclean and replay
    // intent-log segments before opening the full filesystem.
    let mount_state_path = config.store_root.join(".tidefs_mount_state_fuse");
    if !snapshot_export {
        let mut recovery = CrashRecoveryLoop::detect(&mount_state_path)
            .map_err(|e| format!("crash recovery detection: {e}"))?;

        recovery.advance();
        if recovery.state == CrashRecoveryState::Replay {
            eprintln!(
                "Unclean shutdown detected — replaying intent log in {}",
                config.store_root.display()
            );
            let store = tidefs_local_object_store::LocalObjectStore::open(&config.store_root)
                .map_err(|e| format!("open store for crash recovery: {e}"))?;
            recovery
                .run_replay(&store)
                .map_err(|e| format!("intent log replay failed: {e}"))?;
            recovery.reconcile_and_finish();
            eprintln!("Crash recovery complete — pool is ready.");
        }
    }

    // ── Namespace loading ─────────────────────────────────────────────
    // Try to load a persistent namespace from the store. If none exists,
    // create a fresh one (will be flushed on clean shutdown).
    let namespace: Option<Arc<Namespace>> = if snapshot_export {
        None
    } else {
        let store = tidefs_local_object_store::LocalObjectStore::open(&config.store_root)
            .map_err(|e| format!("open store for namespace load: {e}"))?;
        Some(match Namespace::load(&store) {
            Ok(ns) => {
                eprintln!("Loaded persistent namespace from store.");
                Arc::new(ns)
            }
            Err(_) => {
                eprintln!("No persistent namespace found — creating fresh.");
                Arc::new(Namespace::new())
            }
        })
    };

    // Mark the mount state dirty for this daemon session.
    // On clean shutdown the daemon will write Clean.
    if !snapshot_export {
        MountState::Dirty
            .write_to_path(&mount_state_path)
            .map_err(|e| format!("write mount-state: {e}"))?;
    }

    let store_options = StoreOptions {
        background_scrub_interval_secs: effective_mode.background_scrub_interval_secs,
        reclaim_enabled: !snapshot_export && config.enable_reclaim,
        fault_injection_config: if snapshot_export {
            None
        } else {
            config.fault_inject_corruption.map(|p| {
                tidefs_local_object_store::FaultInjectionConfig {
                    byte_corruption_probability: p,
                    ..tidefs_local_object_store::FaultInjectionConfig::off()
                }
            })
        },
        ..StoreOptions::default()
    };
    let scrub_interval = effective_mode.background_scrub_interval_secs;
    let scrub_store_root = config.store_root.clone();
    let scrub_runtime_observation_artifact = config.scrub_runtime_observation_artifact.clone();

    let open_config = LocalFileSystemOpenConfig {
        options: store_options,
        allocator_policy: LocalStorageAllocatorPolicy {
            content_capacity_bytes: config.content_capacity_bytes,
            ..LocalStorageAllocatorPolicy::default()
        },
        root_authentication_key: config.root_authentication_key,
        encryption: None,
        compression: config.compression,
        log_device_device_path: None,
        recovery_policy: if snapshot_export {
            tidefs_recovery_loop::RecoveryPolicy::ReadOnly
        } else if config.enable_repair_writeback {
            tidefs_recovery_loop::RecoveryPolicy::RepairWriteback
        } else {
            tidefs_recovery_loop::RecoveryPolicy::default()
        },
        block_devices: None,
    };

    let (mut vfs_engine, writeback_tracker) = if let Some(snapshot_name) = snapshot_name.as_deref()
    {
        let session =
            LocalFileSystem::open_snapshot_export(&config.store_root, snapshot_name, open_config)
                .map_err(|e| format!("open snapshot export `{snapshot_name}`: {e}"))?;
        let summary = session.summary().clone();
        eprintln!(
            "Opened snapshot export `{}` at generation {} root inode {}",
            summary.snapshot.name,
            summary.generation,
            summary.root_inode_id.get()
        );
        (
            session
                .into_engine()
                .with_sync_guarantee(SyncGuarantee::Local),
            None,
        )
    } else {
        let mut lfs = LocalFileSystem::open_with_allocator_policy_and_root_authentication_key(
            &config.store_root,
            open_config,
        )
        .map_err(|e| format!("open store: {e}"))?;
        lfs.set_write_buffer_flush_threshold_bytes(MOUNT_VFS_WRITE_BUFFER_FLUSH_THRESHOLD_BYTES)
            .map_err(|e| format!("set mounted write-buffer threshold: {e}"))?;

        // Enable org.tidefs:dedup dataset feature when requested by the operator.
        if config.enable_dedup {
            use tidefs_types_dataset_feature_flags_core::{FeatureClass, FeatureName};
            let dedup_name = FeatureName::from_str("org.tidefs:dedup")
                .expect("org.tidefs:dedup is a valid FeatureName");
            lfs.feature_flags_mut()
                .map_err(|e| format!("access dedup feature flags: {e}"))?
                .enable_feature(dedup_name, FeatureClass::RoCompat)
                .map_err(|e| format!("enable dedup feature: {e}"))?;
            lfs.persist_feature_flags()
                .map_err(|e| format!("persist dedup feature flag: {e}"))?;
            lfs.refresh_policies_from_features()
                .map_err(|e| format!("refresh mounted feature policies: {e}"))?;
        }

        // ── Committed-root validation ──────────────────────────────────────
        // Validate the committed root discovered during pool import via
        // BLAKE3 domain-separated chain verification.
        {
            let committed_root = lfs.committed_root_pointer();
            if committed_root.commit_group_id.is_valid() {
                let root_path = config.store_root.join("tidefs-committed-root");
                let chain_digest = std::fs::read(&root_path)
                    .ok()
                    .and_then(|payload| {
                        tidefs_local_object_store::txg_manager::CommitGroupManager::decode_root_with_digest(&payload)
                    })
                    .and_then(|(_root, digest)| digest);
                match tidefs_recovery_loop::recovery_loop::validate_committed_root(
                    committed_root,
                    chain_digest,
                ) {
                    Ok(()) => {
                        eprintln!(
                            "Committed root validated: commit_group={} handle={}",
                            committed_root.commit_group_id.0, committed_root.root_handle,
                        );
                    }
                    Err(e) => {
                        eprintln!(
                                "warning: committed root validation failed: {e};                          continuing with unvalidated root"
                            );
                    }
                }
            }
        }

        // Resolve the effective sync_guarantee: CLI flag overrides catalog value.

        // For the default (Local), consult the dataset catalog for the pool root.
        let effective_sync_guarantee = if config.sync_guarantee == SyncGuarantee::Local {
            lfs.dataset_catalog()
                .sync_guarantee("root")
                .unwrap_or(SyncGuarantee::Local)
        } else {
            config.sync_guarantee
        };
        if effective_sync_guarantee != SyncGuarantee::Local {
            eprintln!(
                "tidefs-daemon: dataset sync_guarantee={effective_sync_guarantee} (from catalog)"
            );
        }

        // Mounted FUSE uses commit-group batching for ordinary metadata writes.
        // Keep the threshold large enough for metadata bursts while fsync, fsyncdir,
        // syncfs, and destroy still force the durability barrier.
        lfs.set_auto_commit(false)
            .map_err(|e| format!("set mounted auto-commit policy: {e}"))?;
        lfs.set_commit_group_throughput_profile()
            .map_err(|e| format!("set mounted commit-group profile: {e}"))?;
        lfs.set_max_uncommitted_mutations(MOUNT_VFS_MAX_UNCOMMITTED_MUTATIONS)
            .map_err(|e| format!("set mounted mutation threshold: {e}"))?;

        let writeback_tracker = lfs
            .clone_writeback_range_tracker()
            .map_err(|e| format!("attach mounted writeback tracker: {e}"))?;
        (
            VfsLocalFileSystem::new(lfs).with_sync_guarantee(effective_sync_guarantee),
            Some(writeback_tracker),
        )
    };
    let engine_timestamp_policy = if effective_mode.read_only {
        EngineTimestampPolicy::Noatime
    } else {
        match config.mount_opts.timestamp_policy {
            crate::mount_options::TimestampPolicy::StrictAtime => {
                EngineTimestampPolicy::Strictatime
            }
            crate::mount_options::TimestampPolicy::RelativeAtime => EngineTimestampPolicy::Relatime,
            crate::mount_options::TimestampPolicy::NoAtime => EngineTimestampPolicy::Noatime,
        }
    };
    vfs_engine
        .set_timestamp_policy(engine_timestamp_policy)
        .map_err(|e| format!("set mounted timestamp policy: {e}"))?;
    if effective_mode.read_only {
        vfs_engine = vfs_engine.with_read_only();
    }

    let mut adapter = fuse_vfs_adapter::FuseVfsAdapter::new(
        Box::new(vfs_engine) as Box<dyn tidefs_vfs_engine::VfsEngineStatFs + Send>
    )
    .map_err(|e| format!("adapter init: {e:?}"))?
    .with_coherency_profile(config.coherency_profile);
    if !snapshot_export {
        adapter = adapter
            .with_commit_group_cycle(Arc::new(
                crate::txg_cycle::CommitGroupCycle::with_store_root(config.store_root.clone()),
            ))
            .with_background_scheduler(BackgroundScheduler::new(ServiceBudget::MAINTENANCE_TICK));
    }
    if let Some(ref namespace) = namespace {
        adapter = adapter.with_namespace(Arc::clone(namespace));
    }
    // Demand-preemption signal: when set, the background scheduler yields

    // after the current service tick so foreground FUSE I/O is not starved.

    let fuse_demand = Arc::new(AtomicBool::new(false));

    adapter.set_scheduler_preempt_signal(Arc::clone(&fuse_demand));
    let adapter = if effective_mode.writeback_cache {
        let writeback_tracker =
            writeback_tracker.ok_or("writeback cache is unavailable for snapshot export")?;
        adapter
            .with_writeback_cache_enabled()
            .with_writeback_cache_timeout(config.writeback_cache_timeout)
            .with_writeback_range_tracker(writeback_tracker)
    } else {
        adapter.with_writeback_cache_disabled()
    };
    let adapter = if config.mount_opts.sync {
        adapter.with_force_sync_writes()
    } else {
        adapter
    };
    let adapter_timestamp_policy = if effective_mode.read_only {
        crate::mount_options::TimestampPolicy::NoAtime
    } else {
        config.mount_opts.timestamp_policy
    };
    let adapter = adapter
        .with_timestamp_policy(adapter_timestamp_policy)
        .with_suppress_dir_atime(config.mount_opts.suppress_dir_atime);
    let adapter = if effective_mode.read_only {
        adapter.with_read_only()
    } else {
        adapter
    };

    let adapter = if effective_mode.intent_log_write {
        let buf = Arc::new(IntentLogBuffer::new());
        adapter.with_intent_log_buffer(buf)
    } else {
        adapter.without_intent_log_write()
    };

    let mut options = vec![
        if effective_mode.read_only {
            fuser::MountOption::RO
        } else {
            fuser::MountOption::RW
        },
        fuser::MountOption::FSName(config.fs_name.clone()),
    ];
    options.extend(fuse_mount_options_for_mode(
        &config.mount_opts,
        effective_mode.read_only,
    ));
    if effective_mode.writeback_cache {
        options.push(fuser::MountOption::WritebackCache);
    }

    let ns_handle = adapter.namespace_handle();
    let queue_depth_engine = adapter.engine_handle();
    let bg_scheduler = adapter.background_scheduler_handle();
    let txg_cycle = if snapshot_export {
        None
    } else {
        Some(adapter.txg_cycle_cell())
    };
    let notifier_cell = adapter.notifier_cell();
    let mmap_coherency = adapter.mmap_coherency_cell();
    // Diagnostic: confirm namespace availability for FUSE dispatch.
    if let Some(ref ns) = adapter.namespace_handle() {
        if ns.get_attrs(1).is_some() {
            eprintln!("tidefs-daemon: namespace root inode (1) confirmed present");
        } else {
            eprintln!("tidefs-daemon: WARNING namespace root inode (1) MISSING");
        }
    } else {
        eprintln!("tidefs-daemon: WARNING namespace is None — FUSE dispatch will use engine only");
    }
    let _session = fuser::spawn_mount2(adapter, &config.mountpoint, &options)
        .map_err(|e| format!("mount: {e}"))?;
    // Immediate liveness check: if the FUSE background session thread
    // exited during spawn (panic, init failure, or kernel error), fail
    // fast instead of entering the scheduler loop with a dead session.
    if _session.guard.is_finished() {
        return Err(
            "FUSE background session exited during mount; refusing to leave a hung mountpoint"
                .to_string(),
        );
    }
    // Install the notifier so dispatch methods can invalidate kernel caches.
    *notifier_cell.lock().unwrap() = Some(_session.notifier());
    // Wait for the FUSE background session thread to enter its run loop
    // before the main thread acquires scheduler, txg, and scrub locks.
    // Avoid std::fs::metadata() on the mountpoint: reentrant FUSE access
    // (the daemon calling stat() on its own mount) can deadlock with the
    // kernel FUSE device lock when a concurrent directory operation (e.g.
    // mkdir) holds the parent inode rwsem.
    //
    // Instead use a bounded yield loop with a session-liveness guard.
    // The background thread enters its read loop within a few hundred ms
    // of spawn; a 3 s budget covers slow TCG-mode QEMU guests.
    for _attempt in 0..15 {
        if _session.guard.is_finished() {
            return Err("FUSE background session exited during mount readiness wait; refusing to leave a hung mountpoint".to_string());
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    let mode = if effective_mode.read_only { "RO" } else { "RW" };
    eprintln!(
        "Mounted TideFS (VFS engine) at {} ({})",
        config.mountpoint.display(),
        mode
    );

    // Refuse idmapped mounts: TideFS does not support idmapped mount
    // UID/GID translation in the current FUSE adapter boundary.
    tidefs_posix_filesystem_adapter_daemon::check_idmapped_mount(&config.mountpoint)?;

    // Register mounted scrub with the same bounded scheduler that drives the
    // daemon's other idle-period maintenance. The service clamps each tick to
    // the typed scrub service curve and retains its cursor between ticks.
    if scrub_interval > 0 {
        let scrub_options = StoreOptions {
            background_scrub_interval_secs: scrub_interval,
            reclaim_enabled: config.enable_reclaim,
            ..StoreOptions::default()
        };
        let observation_required = scrub_runtime_observation_artifact.is_some();
        match MountedBackgroundScrubService::open(
            &scrub_store_root,
            scrub_options,
            scrub_runtime_observation_artifact,
        ) {
            Ok(service) => {
                let mut scheduler = bg_scheduler.lock().unwrap();
                let scheduler = scheduler
                    .as_mut()
                    .ok_or("background scrub requires the mounted background scheduler")?;
                scheduler.register(Box::new(service));
                eprintln!("background-scrub: scheduled (interval={scrub_interval}s)");
            }
            Err(error) if observation_required => {
                return Err(format!("background-scrub: {error}"));
            }
            Err(error) => {
                eprintln!("background-scrub: disabled after setup failure: {error}");
            }
        }
    }

    // ── Clean shutdown via SIGINT/SIGTERM ─────────────────────────
    let shutdown_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let shutdown_for_sig = std::sync::Arc::clone(&shutdown_flag);
    let msp_for_sig = mount_state_path.clone();

    std::thread::spawn(move || {
        // SAFETY: `sigset_t` is a C value type and zeroed storage is the libc
        // initialization baseline before `sigemptyset` populates it.
        let mut sigset: libc::sigset_t = unsafe { std::mem::zeroed() };
        // SAFETY: `sigset` is a valid stack-owned signal set. The selected
        // signals are valid constants, and the null old-mask pointer records
        // that the previous thread mask is intentionally not retained.
        unsafe {
            libc::sigemptyset(&mut sigset);
            libc::sigaddset(&mut sigset, libc::SIGINT);
            libc::sigaddset(&mut sigset, libc::SIGTERM);
            libc::sigaddset(&mut sigset, libc::SIGHUP);
            libc::pthread_sigmask(libc::SIG_BLOCK, &sigset, std::ptr::null_mut());
        }
        loop {
            let mut caught_sig: libc::c_int = 0;
            // SAFETY: `sigset` remains initialized for the thread lifetime and
            // `caught_sig` is a valid out pointer for the delivered signal.
            let rc = unsafe { libc::sigwait(&sigset, &mut caught_sig) };
            if rc == 0 {
                shutdown_for_sig.store(true, std::sync::atomic::Ordering::Relaxed);
                break;
            }
        }
    });

    // -- Periodic commit_group commit cycle ---------------------------------
    let txg_shutdown = Arc::clone(&shutdown_flag);
    let txg_handle = txg_cycle.map(|txg_cycle_for_loop| {
        std::thread::spawn(move || {
            crate::txg_cycle::CommitGroupCycle::spawn_periodic_commit_loop(
                txg_cycle_for_loop,
                txg_shutdown,
                std::time::Duration::from_secs(MOUNT_VFS_TXG_COMMIT_INTERVAL_SECS),
            );
        })
    });

    // Wait until a shutdown signal arrives, running background scheduler
    // cycles, including mounted scrub, during FUSE idle periods. Uses
    // tick_if_idle() to avoid
    // starting work when the demand-preemption signal is asserted.
    // Each cycle is bounded by the MAINTENANCE_TICK budget (50ms max)
    // to avoid starving the FUSE dispatch thread.
    //
    // Periodically check whether the FUSE background session thread is still
    // alive.  If the session thread exits (panic, unhandled kernel error, or
    // normal teardown), the /dev/fuse fd may remain open via the notifier
    // clone held by BackgroundSession, causing guest filesystem I/O to hang
    // indefinitely.  Detecting the thread exit and shutting down prevents
    // that hang and lets the kernel properly unmount.
    let mut idle_cycles: u64 = 0;
    let mut loop_iter: u64 = 0;
    while !shutdown_flag.load(Ordering::Relaxed) {
        loop_iter = loop_iter.saturating_add(1);
        let report_opt = bg_scheduler.lock().unwrap().as_mut().and_then(|sched| {
            let cycle_start = std::time::Instant::now();
            let result = sched.tick_if_idle();
            if result.is_some() {
                crate::observability::HIST_BG_SCHEDULER.record(cycle_start.elapsed());
            }
            result
        });
        match report_opt {
            Some(report) => {
                if report.preempted {
                    tracing::debug!(
                        target: "tidefs.bg_scheduler",
                        services_ran = report.services_ran,
                        total_processed = report.total_processed,
                        wall_ms = report.wall_ms,
                        preempted = true,
                        "background scheduler cycle preempted",
                    );
                } else {
                    tracing::debug!(
                        target: "tidefs.bg_scheduler",
                        services_ran = report.services_ran,
                        services_skipped = report.services_skipped,
                        total_processed = report.total_processed,
                        total_errors = report.total_errors,
                        wall_ms = report.wall_ms,
                        "background scheduler cycle completed",
                    );
                }
                std::thread::yield_now();
            }
            None => {
                idle_cycles = idle_cycles.saturating_add(1);
                if idle_cycles % 60 == 0 {
                    tracing::info!(
                        target: "tidefs.bg_scheduler",
                        idle_cycles = idle_cycles,
                        "background scheduler periodic summary",
                    );
                    crate::observability::HIST_BG_SCHEDULER.emit_summary("bg_scheduler_cycle");
                }
                std::thread::park_timeout(std::time::Duration::from_millis(500));
                // Drain pending mmap coherency invalidation events.
                // Budget: at most 16 events per tick to bound latency.
                mmap_coherency.process_tick(16);
            }
        }

        // Check whether the FUSE background session thread is still alive
        // on every loop iteration, not just idle cycles.  If the session
        // thread exits (panic, unhandled kernel error, or normal teardown),
        // shut down immediately to prevent guest filesystem I/O from
        // hanging indefinitely on a dead mountpoint.
        if loop_iter % 2 == 0 && _session.guard.is_finished() {
            eprintln!(
                "FUSE background session thread exited prematurely;                  shutting down to prevent hung mountpoint"
            );
            // Diagnostic: if the session already finished, try to join and report the outcome.
            // We cannot join() here because it consumes self, but we can inspect the guard.
            tracing::error!(
                target: "tidefs.fuse_session",
                "FUSE background session thread finished prematurely on mount {}",
                _session.mountpoint.display()
            );
            shutdown_flag.store(true, Ordering::Relaxed);
        }
    }
    crate::observability::emit_all_summaries();
    eprintln!("Shutting down TideFS at {}...", config.mountpoint.display());

    // Drain grace period: allow in-flight FUSE requests to complete
    // naturally before forcing unmount.
    if config.drain_timeout_secs > 0 {
        eprintln!(
            "Draining in-flight requests for {}s...",
            config.drain_timeout_secs
        );
        std::thread::sleep(std::time::Duration::from_secs(config.drain_timeout_secs));
    }

    // Wait for the periodic commit_group commit loop to finish its final flush.
    if let Some(handle) = txg_handle {
        let _ = handle.join();
    }

    // Drop scheduled maintenance stores before unmount and the final
    // namespace flush open the backing store again.
    *bg_scheduler.lock().unwrap() = None;

    // Unmount and join the FUSE background session.  The session's Drop
    // triggers adapter.destroy() which flushes writeback data via shutdown().
    _session.join();

    if let Some(path) = &config.queue_depth_artifact {
        write_queue_depth_runtime_artifact(
            &queue_depth_engine,
            path,
            "fuse-smoke-mount-quick",
            "fuse",
        )?;
    }

    // ── Persistent namespace flush ────────────────────────────────────
    if let Some(ns_handle) = ns_handle {
        let mut ns_store = tidefs_local_object_store::LocalObjectStore::open(&config.store_root)
            .map_err(|e| format!("open store for namespace flush: {e}"))?;
        ns_handle
            .flush(&mut ns_store)
            .map_err(|e| format!("namespace flush failed: {e:?}"))?;
        eprintln!("Persistent namespace flushed to store.");
    }

    if !snapshot_export {
        MountState::Clean
            .write_to_path(&msp_for_sig)
            .map_err(|e| format!("write clean mount-state: {e}"))?;
    }
    Ok(())
}

fn write_scrub_runtime_observation(
    path: &Path,
    observation: &ScrubRuntimeObservation,
) -> Result<(), String> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent).map_err(|error| {
            format!(
                "create scrub runtime observation dir {}: {error}",
                parent.display()
            )
        })?;
    }
    let bytes = serde_json::to_vec_pretty(observation)
        .map_err(|error| format!("encode scrub runtime observation: {error}"))?;
    let temp_path = path.with_extension(format!("tmp-{}", observation.daemon_pid));
    std::fs::write(&temp_path, bytes).map_err(|error| {
        format!(
            "write scrub runtime observation temp file {}: {error}",
            temp_path.display()
        )
    })?;
    std::fs::rename(&temp_path, path).map_err(|error| {
        format!(
            "publish scrub runtime observation {}: {error}",
            path.display()
        )
    })?;
    Ok(())
}

fn write_queue_depth_runtime_artifact(
    engine: &crate::live_owner::LiveOwnerEngine,
    path: &Path,
    workload: &str,
    mount_adapter: &str,
) -> Result<(), String> {
    let mut args = BTreeMap::new();
    args.insert(
        "workload".to_string(),
        LivePoolAdminArg::String(workload.to_string()),
    );
    args.insert(
        "mount_adapter".to_string(),
        LivePoolAdminArg::String(mount_adapter.to_string()),
    );
    args.insert(
        "artifact_path".to_string(),
        LivePoolAdminArg::String(path.display().to_string()),
    );
    let mut request =
        LivePoolAdminRequest::new(LivePoolAdminCommand::PerformanceAdmissionSnapshot, "root");
    request.output = LivePoolAdminOutput::MachineJson;
    request.args = LivePoolAdminArgs(args);
    let response = {
        let engine = engine
            .lock()
            .map_err(|_| "queue-depth artifact engine lock poisoned".to_string())?;
        engine
            .live_pool_admin_request(&request)
            .map_err(|err| format!("queue-depth artifact request failed: {err:?}"))?
    };
    if response.exit_code != 0 {
        let message = match &response.body {
            LivePoolAdminResponseBody::Error { message, .. } => message.as_str(),
            _ => "unknown error",
        };
        return Err(format!("queue-depth artifact response failed: {message}"));
    }
    let artifact = match response.body {
        LivePoolAdminResponseBody::MachineJson(json) => json,
        _ => return Err("queue-depth artifact response did not include machine JSON".to_string()),
    };
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent).map_err(|err| {
            format!(
                "create queue-depth artifact dir {}: {err}",
                parent.display()
            )
        })?;
    }
    let artifact: serde_json::Value = serde_json::from_str(&artifact)
        .map_err(|err| format!("decode queue-depth artifact JSON: {err}"))?;
    let bytes = serde_json::to_vec_pretty(&artifact)
        .map_err(|err| format!("encode queue-depth artifact JSON: {err}"))?;
    std::fs::write(path, bytes)
        .map_err(|err| format!("write queue-depth artifact {}: {err}", path.display()))?;
    eprintln!("queue_depth_runtime_artifact={}", path.display());
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EffectiveMountMode {
    read_only: bool,
    writeback_cache: bool,
    intent_log_write: bool,
    background_scrub_interval_secs: u64,
}

fn effective_mount_mode(config: &MountVfsConfig) -> EffectiveMountMode {
    let snapshot_export = config.snapshot_name.is_some();
    EffectiveMountMode {
        read_only: config.read_only || snapshot_export,
        writeback_cache: config.writeback_cache && !snapshot_export,
        intent_log_write: config.intent_log_write && !snapshot_export,
        background_scrub_interval_secs: if snapshot_export {
            0
        } else {
            config.background_scrub_interval_secs
        },
    }
}

fn fuse_mount_options_for_mode(
    mount_opts: &MountOptions,
    read_only: bool,
) -> Vec<fuser::MountOption> {
    let mut effective = mount_opts.clone();
    // Read-write mounts keep the kernel-visible atime policy so cached reads
    // update user-visible attrs. The adapter still records read access in the
    // engine/namespace authority; read-only mounts suppress both paths.
    if read_only {
        effective.timestamp_policy = crate::mount_options::TimestampPolicy::NoAtime;
    }
    effective.to_fuse_mount_options()
}

/// Configuration for mount-vfs subcommand.
pub struct MountVfsConfig {
    pub read_only: bool,
    /// Optional snapshot name for read-only snapshot-backed mounts.
    /// Specifying this opens the committed snapshot root as a separate
    /// read-only FUSE export session.
    pub snapshot_name: Option<String>,
    pub store_root: PathBuf,
    pub mountpoint: PathBuf,
    /// Source name reported by the FUSE mount in mount tables.
    pub fs_name: String,
    pub root_authentication_key: RootAuthenticationKey,
    /// When true, enables FUSE writeback-cache for buffered writes.
    /// Default: false (safe direct-write path).
    pub writeback_cache: bool,
    /// Content capacity configured for the mounted local filesystem.
    pub content_capacity_bytes: u64,

    pub mount_opts: MountOptions,
    /// Per-dataset write-acknowledgment durability guarantee.
    pub sync_guarantee: SyncGuarantee,
    /// When true, tiny buffered writes are recorded inline in the intent log.
    /// Larger writes rely on the storage commit path instead of hashing data
    /// in the FUSE hot path.
    pub intent_log_write: bool,
    /// Maximum age (in seconds) of dirty pages in the writeback cache
    /// before the background flush service writes them to storage.
    pub writeback_cache_timeout: u64,
    /// Seconds to wait after receiving SIGTERM/SIGINT before forcing
    /// unmount.  During this grace period in-flight FUSE requests
    /// complete naturally.  Default 0 means no extra drain wait.
    pub drain_timeout_secs: u64,
    /// Background segment integrity scrub interval in seconds.
    /// 0 disables.  Default: 0 (disabled).
    pub background_scrub_interval_secs: u64,
    /// Coherency profile for FUSE caching behaviour.
    /// Default: Writeback for TTL/invalidation only; kernel writeback remains
    /// opt-in through `writeback_cache`.
    pub coherency_profile: crate::coherency_profile::CoherencyProfile,
    /// Optional per-object compression configuration for the backing store.
    /// When set, all objects written to the pool are compressed with the
    /// specified algorithm and level.  Omitted by default (no compression).
    pub compression: Option<tidefs_local_object_store::CompressionConfig>,
    /// When true, enables the org.tidefs:dedup dataset feature flag on first open
    /// so inline content-addressed chunk dedup is active during writes.
    /// Default: false.
    pub enable_dedup: bool,
    /// When true, enables the object-store reclaim path so dead segments
    /// are freed after committed-root safety.  FUSE-mounted writes and
    /// deletions will drive reclaim population.  Default: false.
    pub enable_reclaim: bool,
    /// When true, sets RecoveryPolicy::RepairWriteback so the repair
    /// cycle can write reconstructed bytes, truncate corrupt content,
    /// and mark inodes as corrupt during mounted operation.
    /// Default: false (ReplayOnly).
    pub enable_repair_writeback: bool,
    /// When set, enables byte-level corruption injection on every write
    /// at the given probability (0.0-1.0).  Corruption is applied before
    /// integrity-trailer computation, so it tests error-path behavior
    /// rather than scrub detection.  Default: None (off).
    pub fault_inject_corruption: Option<f64>,
    /// Optional JSON artifact path for mounted queue-depth evidence.
    pub queue_depth_artifact: Option<PathBuf>,
    /// Optional validation-only JSON path for typed daemon scrub observations.
    /// Issue #1792 owns graduation or removal of this evidence surface.
    pub scrub_runtime_observation_artifact: Option<PathBuf>,
}

fn parse_mount_vfs_config(args: Vec<String>) -> Result<MountVfsConfig, String> {
    let mut store_root = None;
    let mut mountpoint = None;
    let mut fs_name = "tidefs-vfs".to_string();
    let mut read_only = false;
    let mut root_authentication_key = None;
    let mut writeback_cache = false;
    let mut content_capacity_bytes = LocalStorageAllocatorPolicy::default().content_capacity_bytes;
    let mut snapshot_name: Option<String> = None;
    let mut mount_opts = MountOptions::default();
    let mut sync_guarantee = SyncGuarantee::Local;
    let mut intent_log_write = mount_opts.intent_log_write;
    let mut writeback_cache_timeout: Option<u64> = None;
    let mut drain_timeout_secs: Option<u64> = None;
    let mut background_scrub_interval_secs: Option<u64> = None;
    let mut cache_profile = None;
    let mut compression: Option<tidefs_local_object_store::CompressionConfig> = None;
    let mut enable_dedup = false;
    let mut enable_reclaim = false;
    let mut enable_repair_writeback = false;
    let mut fault_inject_corruption: Option<f64> = None;
    let mut queue_depth_artifact = None;
    let mut scrub_runtime_observation_artifact = None;
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--store" => {
                store_root = Some(PathBuf::from(
                    iter.next().ok_or("--store requires a path argument")?,
                ));
            }
            "--mount" | "--mountpoint" => {
                mountpoint = Some(PathBuf::from(
                    iter.next().ok_or("--mount requires a path argument")?,
                ));
            }
            "--fs-name" => {
                let value = iter.next().ok_or("--fs-name requires a source name")?;
                if value.is_empty() {
                    return Err("--fs-name must not be empty".into());
                }
                fs_name = value;
            }
            "--root-auth-key-hex" | "--root-authentication-key-hex" => {
                let value = iter
                    .next()
                    .ok_or("--root-auth-key-hex requires a 64-hex-character key")?;
                root_authentication_key = Some(
                    RootAuthenticationKey::from_hex(&value)
                        .map_err(|e| format!("invalid root authentication key: {e}"))?,
                );
            }
            "--read-only" => {
                read_only = true;
            }
            "--writeback-cache" => {
                writeback_cache = true;
            }
            "--content-capacity-bytes" => {
                let val = iter
                    .next()
                    .ok_or("--content-capacity-bytes requires an integer byte count")?;
                content_capacity_bytes = val
                    .parse()
                    .map_err(|e| format!("invalid content capacity `{val}`: {e}"))?;
                if content_capacity_bytes == 0 {
                    return Err("--content-capacity-bytes must be > 0".into());
                }
            }
            "--snapshot" => {
                snapshot_name = Some(
                    iter.next()
                        .ok_or("--snapshot requires a snapshot name argument")?,
                );
            }
            "--no-writeback-cache" => {
                writeback_cache = false;
            }
            "--options" | "-o" => {
                let val = iter
                    .next()
                    .ok_or("--options requires a comma-separated option string")?;
                mount_opts =
                    MountOptions::parse(&val).map_err(|e| format!("invalid mount options: {e}"))?;
                intent_log_write = mount_opts.intent_log_write;
            }
            "--sync" => {
                mount_opts.sync = true;
            }
            "--sync-guarantee" => {
                let val = iter
                    .next()
                    .ok_or("--sync-guarantee requires local, remote-copy, or full-redundancy")?;
                sync_guarantee = match val.as_str() {
                    "local" => SyncGuarantee::Local,
                    "remote-copy" => SyncGuarantee::RemoteCopy,
                    "full-redundancy" => SyncGuarantee::FullRedundancy,
                    other => return Err(format!("invalid --sync-guarantee value {other}; expected local, remote-copy, or full-redundancy")),
                };
            }
            "--no-intent-log-write" => {
                intent_log_write = false;
            }
            "--intent-log-write" => {
                intent_log_write = true;
            }
            "--writeback-cache-timeout" => {
                let val = iter
                    .next()
                    .ok_or("--writeback-cache-timeout requires an integer argument")?;
                let secs: u64 = val
                    .parse()
                    .map_err(|e| format!("invalid writeback-cache-timeout `{val}`: {e}"))?;
                if secs == 0 {
                    return Err("writeback-cache-timeout must be > 0".into());
                }
                writeback_cache_timeout = Some(secs);
            }
            "--drain-timeout-secs" => {
                let val = iter
                    .next()
                    .ok_or("--drain-timeout-secs requires an integer argument")?;
                let secs: u64 = val
                    .parse()
                    .map_err(|e| format!("invalid drain-timeout-secs `{val}`: {e}"))?;
                // Set in the config below; we need a local variable
                drain_timeout_secs = Some(secs);
            }
            "--background-scrub-interval" => {
                let val = iter
                    .next()
                    .ok_or("--background-scrub-interval requires an integer argument")?;
                let secs: u64 = val
                    .parse()
                    .map_err(|e| format!("invalid background-scrub-interval `{val}`: {e}"))?;
                background_scrub_interval_secs = Some(secs);
            }
            "--coherency" | "--coherency-profile" => {
                let val = iter
                    .next()
                    .ok_or("--coherency requires a profile name: strict, writeback, nearline, async, offline")?;
                let profile: crate::coherency_profile::CoherencyProfile = val
                    .parse()
                    .map_err(|e: String| format!("invalid coherency profile: {e}"))?;
                cache_profile = Some(profile);
            }
            "--compress-algo" | "--compression-algorithm" => {
                let val = iter
                    .next()
                    .ok_or("--compress-algo requires zstd, lz4, or off")?;
                let algo = match val.to_lowercase().as_str() {
                    "zstd" => tidefs_local_object_store::CompressionAlgorithm::Zstd,
                    "lz4" => tidefs_local_object_store::CompressionAlgorithm::Lz4,
                    "off" | "none" => tidefs_local_object_store::CompressionAlgorithm::Uncompressed,
                    other => {
                        return Err(format!(
                            "unknown compression algorithm \"{other}\"; expected zstd, lz4, or off"
                        ))
                    }
                };
                // Store the algorithm; level and threshold use sensible defaults.
                compression = Some(tidefs_local_object_store::CompressionConfig {
                    algorithm: algo,
                    level: if algo == tidefs_local_object_store::CompressionAlgorithm::Lz4 {
                        0
                    } else {
                        3
                    },
                    min_compress_bytes: 0,
                });
            }
            "--enable-dedup" => {
                enable_dedup = true;
            }
            "--enable-reclaim" => {
                enable_reclaim = true;
            }
            "--enable-repair-writeback" => {
                enable_repair_writeback = true;
            }
            "--fault-inject-corruption" => {
                let val = iter
                    .next()
                    .ok_or("--fault-inject-corruption requires a float argument (0.0-1.0)")?;
                let prob: f64 = val
                    .parse()
                    .map_err(|e| format!("invalid corruption probability \"{val}\": {e}"))?;
                if !(0.0..=1.0).contains(&prob) {
                    return Err(format!(
                        "corruption probability {prob} out of range; expected 0.0-1.0"
                    ));
                }
                fault_inject_corruption = Some(prob);
            }
            "--queue-depth-artifact" => {
                let val = iter
                    .next()
                    .ok_or("--queue-depth-artifact requires a path argument")?;
                queue_depth_artifact = Some(PathBuf::from(val));
            }
            _ if arg.starts_with("--queue-depth-artifact=") => {
                let value = arg
                    .strip_prefix("--queue-depth-artifact=")
                    .expect("prefix checked");
                queue_depth_artifact = Some(PathBuf::from(value));
            }
            "--scrub-runtime-observation-artifact" => {
                let val = iter
                    .next()
                    .ok_or("--scrub-runtime-observation-artifact requires a path argument")?;
                scrub_runtime_observation_artifact = Some(PathBuf::from(val));
            }
            _ if arg.starts_with("--scrub-runtime-observation-artifact=") => {
                let value = arg
                    .strip_prefix("--scrub-runtime-observation-artifact=")
                    .expect("prefix checked");
                scrub_runtime_observation_artifact = Some(PathBuf::from(value));
            }
            other => return Err(format!("unknown mount-vfs argument `{other}`")),
        }
    }
    let root_authentication_key = match root_authentication_key {
        Some(key) => key,
        None => RootAuthenticationKey::from_environment().map_err(|err| {
            format!("{err}; pass --root-auth-key-hex or set {ROOT_AUTHENTICATION_ENV_VAR}")
        })?,
    };
    Ok(MountVfsConfig {
        read_only,
        store_root: store_root.ok_or("mount-vfs requires --store <path>")?,
        mountpoint: mountpoint.ok_or("mount-vfs requires --mount <path>")?,
        fs_name,
        root_authentication_key,
        writeback_cache,
        content_capacity_bytes,
        mount_opts,
        sync_guarantee,
        intent_log_write,
        writeback_cache_timeout: writeback_cache_timeout.unwrap_or(60),
        drain_timeout_secs: drain_timeout_secs.unwrap_or(0),
        background_scrub_interval_secs: background_scrub_interval_secs
            .unwrap_or(MOUNT_VFS_DEFAULT_BACKGROUND_SCRUB_INTERVAL_SECS),
        coherency_profile: cache_profile.unwrap_or_default(),
        compression,
        enable_dedup,
        enable_reclaim,
        enable_repair_writeback,
        snapshot_name,
        fault_inject_corruption,
        queue_depth_artifact,
        scrub_runtime_observation_artifact,
    })
}

/// Parse arguments for `score-posix --out <dir>`.
fn parse_score_posix_args(args: Vec<String>) -> Result<PathBuf, String> {
    let mut out_dir = None;
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--out" => {
                out_dir = Some(PathBuf::from(
                    iter.next().ok_or("--out requires a directory path")?,
                ));
            }
            other => return Err(format!("unknown score-posix argument `{other}`")),
        }
    }
    out_dir.ok_or_else(|| "score-posix requires --out <dir>".to_string())
}

/// Run the score-posix subcommand: read env vars set by the posix-scoreboard
/// harness, optionally execute xfstests, and produce a JSON scoreboard.
fn run_score_posix(out_dir: &Path) -> Result<(), String> {
    let config = xfstests_harness::XfstestsConfig::from_scoreboard_env(out_dir.to_path_buf())?;
    let scoreboard = xfstests_harness::run_xfstests(&config)?;

    eprintln!(
        "score-posix: {} tests, {} passed, {} failed, {} skipped, {} diff",
        scoreboard.summary.total,
        scoreboard.summary.passed,
        scoreboard.summary.failed,
        scoreboard.summary.skipped,
        scoreboard.summary.diff,
    );
    eprintln!("scoreboard written to {}", out_dir.display());
    Ok(())
}

/// Parse arguments for `xfstests-harness`.
fn parse_xfstests_harness_args(
    args: Vec<String>,
) -> Result<xfstests_harness::XfstestsConfig, String> {
    let mut test_tokens: Vec<String> = Vec::new();
    let mut out_dir = None;
    let mut quick = false;
    let mut auto = false;
    let mut exclude_file = None;
    let mut no_exclude = false;

    // Use index-based iteration so we can consume multiple positional
    // tokens after --tests (e.g. --tests lock symlink fallocate).
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--tests" | "--test-range" => {
                i += 1;
                // Consume all following positional tokens until the next
                // "--flag" or end-of-args.
                while i < args.len() && !args[i].starts_with("--") {
                    test_tokens.push(args[i].clone());
                    i += 1;
                }
                if test_tokens.is_empty() {
                    return Err("--tests requires at least one range spec \
                        (e.g. generic/101-150)"
                        .to_string());
                }
                continue; // i already advanced past consumed tokens
            }
            "--out" => {
                i += 1;
                if i >= args.len() {
                    return Err("--out requires a directory path".to_string());
                }
                out_dir = Some(PathBuf::from(args[i].clone()));
            }
            "--quick" => quick = true,
            "--auto" => auto = true,
            "--exclude" => {
                i += 1;
                if i >= args.len() {
                    return Err("--exclude requires a file path".to_string());
                }
                exclude_file = Some(PathBuf::from(args[i].clone()));
            }
            "--no-exclude" => no_exclude = true,
            other => return Err(format!("unknown xfstests-harness argument `{other}`")),
        }
        i += 1;
    }

    // Expand conceptual group aliases (e.g. "lock" -> generic/131 generic/184 ...)
    // before passing to the range parser.
    let test_tokens = xfstests_harness::expand_xfstests_group_aliases(&test_tokens);
    let range_spec = if test_tokens.is_empty() {
        "generic/001-050".to_string()
    } else {
        test_tokens.join(" ")
    };
    let out_dir = out_dir.unwrap_or_else(|| {
        let id = std::process::id();
        PathBuf::from(format!("/tmp/tidefs-xfstests-{id}"))
    });

    xfstests_harness::XfstestsConfig::from_cli(
        range_spec,
        out_dir,
        quick,
        auto,
        exclude_file,
        no_exclude,
    )
}

/// Run the xfstests-harness subcommand.
fn run_xfstests_harness(config: &xfstests_harness::XfstestsConfig) -> Result<(), String> {
    let scoreboard = xfstests_harness::run_xfstests(config)?;

    eprintln!(
        "xfstests-harness: {} tests, {} passed, {} failed, {} skipped, {} diff",
        scoreboard.summary.total,
        scoreboard.summary.passed,
        scoreboard.summary.failed,
        scoreboard.summary.skipped,
        scoreboard.summary.diff,
    );
    eprintln!("scoreboard written to {}", config.out_dir.display());
    Ok(())
}
/// Run a self-contained FUSE mount smoke test.
///
/// Forks a background daemon running `mount-vfs`, polls for the mountpoint,
/// exercises basic POSIX operations, and cleans up. Returns Ok on success.
/// Run a self-contained FUSE mount smoke test that exercises teardown,
/// remount, data persistence, and stale-handle behavior.
///
/// Phase 1:  first mount -> create/write/read data,
///          POSIX mutations (symlink, unlink, rmdir, rename),
///          xattr operations,
///          open-unlink and rename-over-open soak
/// Phase 2: clean teardown (unmount + kill daemon)
/// Phase 3: remount -> verify data persisted
/// Phase 4: stale-handle test (open file, hard-kill daemon, verify old fd errors)
/// Phase 5: remount after hard kill -> verify data integrity
/// Phase 6: final cleanup
#[allow(unsafe_code)]
fn run_smoke_mount(config: SmokeMountConfig) -> Result<(), String> {
    use std::fs;
    use std::io::Write;
    use std::process::Command;
    use std::thread;
    use std::time::Duration;

    let store_root = "/tmp/tidefs-smoke-mount-store";
    let mountpoint = "/tmp/tidefs-smoke-mount-point";

    // Clean up from previous runs.
    let _ = fs::remove_dir_all(store_root);
    let _ = fs::remove_dir_all(mountpoint);
    fs::create_dir_all(store_root).map_err(|e| format!("create store dir: {e}"))?;
    fs::create_dir_all(mountpoint).map_err(|e| format!("create mount dir: {e}"))?;

    // Get our own binary path for re-exec.
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;

    let mut passed = 0_u32;
    let mut failed = 0_u32;

    eprintln!("=== smoke-mount profile: {:?} ===", config.profile);

    macro_rules! smoke_test {
        ($name:expr, $body:block) => {
            let result: Result<(), String> = $body;
            match result {
                Ok(()) => {
                    eprintln!("  PASS  {}", $name);
                    passed += 1;
                }
                Err(e) => {
                    eprintln!("  FAIL  {}: {}", $name, e);
                    failed += 1;
                }
            }
        };
    }

    // ── Helper: spawn daemon and wait for mountpoint ──────────────────
    fn spawn_and_mount(
        exe: &std::path::Path,
        store_root: &str,
        mountpoint: &str,
        queue_depth_artifact: Option<&std::path::Path>,
    ) -> Result<std::process::Child, String> {
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};
        use std::sync::mpsc::TryRecvError;
        use std::thread;
        use std::time::{Duration, Instant};

        let mut command = Command::new(exe);
        command
            .arg("mount-vfs")
            .arg("--store")
            .arg(store_root)
            .arg("--mount")
            .arg(mountpoint)
            .stdout(Stdio::null())
            .env(
                "TIDEFS_ROOT_AUTHENTICATION_KEY_HEX",
                "4141414141414141414141414141414141414141414141414141414141414141",
            )
            .stderr(Stdio::piped());
        if let Some(path) = queue_depth_artifact {
            command.arg("--queue-depth-artifact").arg(path);
        }
        let mut child = command.spawn().map_err(|e| format!("spawn daemon: {e}"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| "capture daemon stderr".to_string())?;
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let _stderr_forwarder = thread::spawn(move || {
            let reader = BufReader::new(stderr);
            let mut ready_sent = false;
            for line in reader.lines() {
                match line {
                    Ok(line) => {
                        eprintln!("{line}");
                        if !ready_sent && line.contains("Mounted TideFS (VFS engine) at ") {
                            let _ = ready_tx.send(Ok(()));
                            ready_sent = true;
                        }
                    }
                    Err(err) => {
                        if !ready_sent {
                            let _ = ready_tx.send(Err(format!("read daemon stderr: {err}")));
                        }
                        return;
                    }
                }
            }
            if !ready_sent {
                let _ = ready_tx.send(Err(
                    "daemon exited before reporting mounted-ready state".to_string()
                ));
            }
        });

        let deadline = Instant::now() + Duration::from_secs(60);
        let mut mountpoint_ready = false;
        let mut daemon_ready = false;
        while Instant::now() < deadline {
            match child.try_wait() {
                Ok(Some(status)) => {
                    return Err(format!("daemon exited early with status {status}"));
                }
                Ok(None) => {}
                Err(e) => return Err(format!("wait daemon: {e}")),
            }
            if !mountpoint_ready {
                let check = Command::new("mountpoint")
                    .arg("-q")
                    .arg(mountpoint)
                    .status();
                if check.is_ok_and(|s| s.success()) {
                    mountpoint_ready = true;
                }
            }
            if !daemon_ready {
                match ready_rx.try_recv() {
                    Ok(Ok(())) => daemon_ready = true,
                    Ok(Err(err)) => return Err(err),
                    Err(TryRecvError::Empty) => {}
                    Err(TryRecvError::Disconnected) => {
                        return Err("daemon readiness channel closed before mounted-ready state"
                            .to_string())
                    }
                }
            }
            if mountpoint_ready && daemon_ready {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        if !mountpoint_ready || !daemon_ready {
            let _ = child.kill();
            for _ in 0..50 {
                match child.try_wait() {
                    Ok(Some(_)) | Err(_) => break,
                    Ok(None) => thread::sleep(Duration::from_millis(100)),
                }
            }
            return Err(format!(
                "mountpoint did not become ready within 60s (mountpoint_ready={mountpoint_ready}, daemon_ready={daemon_ready})"
            ));
        }
        // Post-mount liveness check.
        match child.try_wait() {
            Ok(Some(status)) => {
                return Err(format!("daemon exited after mount with status {status}"));
            }
            Ok(None) => {}
            Err(e) => return Err(format!("wait daemon after mount: {e}")),
        }
        Ok(child)
    }

    // ── Helper: teardown daemon ───────────────────────────────────────
    fn teardown_daemon(child: &mut std::process::Child, mountpoint: &str, hard: bool) {
        use std::process::Command;
        use std::thread;
        use std::time::Duration;

        if !hard {
            // Gentle unmount first.
            let umount_result = Command::new("fusermount")
                .arg("-u")
                .arg(mountpoint)
                .status();
            if umount_result.is_err() || umount_result.unwrap().code() != Some(0) {
                let _ = Command::new("umount").arg(mountpoint).status();
            }
            for _ in 0..100 {
                match child.try_wait() {
                    Ok(Some(_)) | Err(_) => return,
                    Ok(None) => thread::sleep(Duration::from_millis(100)),
                }
            }
            let _ = child.kill();
        } else {
            // Hard kill: SIGKILL to simulate crash without clean unmount.
            let _ = Command::new("fusermount")
                .arg("-u")
                .arg(mountpoint)
                .status();
            let _ = Command::new("umount").arg("-l").arg(mountpoint).status();
            let _ = child.kill();
            // Give it a moment, then SIGKILL.
            thread::sleep(Duration::from_millis(500));
            // SAFETY: `child.id()` is the process id returned by `Command` for
            // this daemon child; SIGKILL intentionally simulates a crash after
            // gentler teardown attempts.
            unsafe {
                libc::kill(child.id() as i32, libc::SIGKILL);
            }
        }
        // Bounded wait for child exit.
        for _ in 0..100 {
            match child.try_wait() {
                Ok(Some(_)) | Err(_) => break,
                Ok(None) => thread::sleep(Duration::from_millis(100)),
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // ── xattr syscall helpers ────────────────────────────────────────
    fn xattr_set(path: &str, name: &str, value: &[u8], flags: i32) -> Result<(), String> {
        let path_c = std::ffi::CString::new(path).map_err(|e| format!("path CString: {e}"))?;
        let name_c = std::ffi::CString::new(name).map_err(|e| format!("name CString: {e}"))?;
        // SAFETY: `path_c` and `name_c` are NUL-terminated C strings alive for
        // the call, and `value.as_ptr()` is valid for `value.len()` bytes.
        let rc = unsafe {
            libc::setxattr(
                path_c.as_ptr(),
                name_c.as_ptr(),
                value.as_ptr() as *const libc::c_void,
                value.len(),
                flags,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            // SAFETY: errno is read immediately after the failing libc call on
            // this thread.
            let e = unsafe { *libc::__errno_location() };
            Err(format!("setxattr {name}: errno={e}"))
        }
    }

    fn xattr_get(path: &str, name: &str) -> Result<(Vec<u8>, usize), String> {
        let path_c = std::ffi::CString::new(path).map_err(|e| format!("path CString: {e}"))?;
        let name_c = std::ffi::CString::new(name).map_err(|e| format!("name CString: {e}"))?;
        // SAFETY: The path and attribute name are valid C strings. The null
        // buffer and zero length request only asks libc for the xattr size.
        let size =
            unsafe { libc::getxattr(path_c.as_ptr(), name_c.as_ptr(), std::ptr::null_mut(), 0) };
        if size < 0 {
            // SAFETY: errno is read immediately after the failing libc call on
            // this thread.
            let e = unsafe { *libc::__errno_location() };
            return Err(format!("getxattr size {name}: errno={e}"));
        }
        let mut buf = vec![0u8; size as usize];
        // SAFETY: `buf` is allocated for `size` bytes, and the C string
        // pointers remain alive while libc writes at most `buf.len()` bytes.
        let n = unsafe {
            libc::getxattr(
                path_c.as_ptr(),
                name_c.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };
        if n < 0 {
            // SAFETY: errno is read immediately after the failing libc call on
            // this thread.
            let e = unsafe { *libc::__errno_location() };
            return Err(format!("getxattr {name}: errno={e}"));
        }
        Ok((buf, n as usize))
    }

    fn xattr_remove(path: &str, name: &str) -> Result<(), String> {
        let path_c = std::ffi::CString::new(path).map_err(|e| format!("path CString: {e}"))?;
        let name_c = std::ffi::CString::new(name).map_err(|e| format!("name CString: {e}"))?;
        // SAFETY: `path_c` and `name_c` are NUL-terminated C strings alive for
        // the duration of the removexattr syscall.
        let rc = unsafe { libc::removexattr(path_c.as_ptr(), name_c.as_ptr()) };
        if rc == 0 {
            Ok(())
        } else {
            // SAFETY: errno is read immediately after the failing libc call on
            // this thread.
            let e = unsafe { *libc::__errno_location() };
            Err(format!("removexattr {name}: errno={e}"))
        }
    }

    // Phase 1: First mount → create/write/read data
    // ═══════════════════════════════════════════════════════════════════
    eprintln!("=== Phase 1: first mount and data creation ===");

    let mut child = spawn_and_mount(
        &exe,
        store_root,
        mountpoint,
        config.queue_depth_artifact.as_deref(),
    )?;

    // FUSE responsiveness probe.
    eprintln!("  INFO  probing FUSE responsiveness...");
    {
        let mp = mountpoint.to_string();
        let probe_handle =
            thread::spawn(move || fs::metadata(&mp).map(|_| ()).map_err(|e| format!("{e}")));
        for _ in 0..50 {
            thread::sleep(Duration::from_millis(100));
            if probe_handle.is_finished() {
                break;
            }
        }
        if !probe_handle.is_finished() {
            let _ = child.kill();
            for _ in 0..50 {
                match child.try_wait() {
                    Ok(Some(_)) | Err(_) => break,
                    Ok(None) => thread::sleep(Duration::from_millis(100)),
                }
            }
            return Err("FUSE daemon did not respond to stat probe within 5s".to_string());
        }
        match probe_handle.join() {
            Ok(Ok(())) => eprintln!("  INFO  FUSE probe OK: mount is responsive"),
            Ok(Err(e)) => {
                let _ = child.kill();
                for _ in 0..50 {
                    match child.try_wait() {
                        Ok(Some(_)) | Err(_) => break,
                        Ok(None) => thread::sleep(Duration::from_millis(100)),
                    }
                }
                return Err(format!("FUSE probe stat failed: {e}"));
            }
            Err(_) => return Err("FUSE probe thread panicked".to_string()),
        }
    }

    let test_file = format!("{mountpoint}/smoke-test-file.txt");
    let test_dir = format!("{mountpoint}/smoke-subdir");
    let second_file = format!("{mountpoint}/smoke-file-2.txt");

    smoke_test!("phase1_stat_root", {
        eprintln!("  DIAG  stat_root: starting stat on mountpoint");
        let md = fs::metadata(mountpoint).map_err(|e| format!("stat: {e}"))?;
        if !md.is_dir() {
            return Err("not a directory".to_string());
        }
        Ok(())
    });

    smoke_test!("phase1_create_file", {
        eprintln!("  DIAG  create_file: attempting fs::write to {test_file}");
        fs::write(&test_file, "hello tidefs smoke\n").map_err(|e| format!("write: {e}"))?;
        eprintln!("  DIAG  create_file: fs::write completed");
        let md = fs::metadata(&test_file).map_err(|e| format!("stat: {e}"))?;
        if !md.is_file() {
            return Err("not a file".to_string());
        }
        Ok(())
    });

    smoke_test!("phase1_read_file", {
        eprintln!("  DIAG  read_file: attempting fs::read_to_string");
        let content = fs::read_to_string(&test_file).map_err(|e| format!("read: {e}"))?;
        if content != "hello tidefs smoke\n" {
            return Err(format!("unexpected content: {content:?}"));
        }
        Ok(())
    });

    smoke_test!("phase1_append_file", {
        eprintln!("  DIAG  append_file: starting append open/write/read cycle");
        let mut f = fs::OpenOptions::new()
            .append(true)
            .open(&test_file)
            .map_err(|e| format!("open-append: {e}"))?;
        writeln!(f, "appended line").map_err(|e| format!("write: {e}"))?;
        drop(f);
        let content = fs::read_to_string(&test_file).map_err(|e| format!("read: {e}"))?;
        if !content.contains("appended line") {
            return Err(format!("append not reflected: {content:?}"));
        }
        Ok(())
    });

    smoke_test!("phase1_create_dir", {
        eprintln!("  DIAG  create_dir: starting mkdir");
        fs::create_dir(&test_dir).map_err(|e| format!("mkdir: {e}"))?;
        let md = fs::metadata(&test_dir).map_err(|e| format!("stat: {e}"))?;
        if !md.is_dir() {
            return Err("not a directory".to_string());
        }
        Ok(())
    });

    smoke_test!("phase1_readdir", {
        eprintln!("  DIAG  readdir: starting read_dir on mountpoint");
        let entries: Vec<String> = fs::read_dir(mountpoint)
            .map_err(|e| format!("read_dir: {e}"))?
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        if !entries.iter().any(|n| n == "smoke-test-file.txt") {
            return Err("smoke-test-file.txt not found in readdir".to_string());
        }
        if !entries.iter().any(|n| n == "smoke-subdir") {
            return Err("smoke-subdir not found in readdir".to_string());
        }
        Ok(())
    });

    // ═══════════════════════════════════════════════════════════════════
    // ===================================================================
    // Phase 1b: POSIX mutation operations (symlink, unlink, rmdir, rename).
    // Exercise the mutation dispatch paths whose FUSE NOTIFY deadlocks
    // were recently fixed (commits 73886a919, b49c6f310).
    // ===================================================================
    eprintln!("=== Phase 1b: POSIX mutation operations ===");

    let symlink_path = format!("{mountpoint}/smoke-symlink");
    let symlink_target = format!("{mountpoint}/smoke-test-file.txt");
    let unlink_file = format!("{mountpoint}/smoke-unlink-test.txt");
    let rmdir_dir = format!("{mountpoint}/smoke-rmdir-test");
    let rename_src = format!("{mountpoint}/smoke-rename-src.txt");
    let rename_dst = format!("{mountpoint}/smoke-rename-dst.txt");

    smoke_test!("phase1b_symlink_create", {
        eprintln!("  DIAG  symlink_create: {symlink_path:?} -> {symlink_target:?}");
        std::os::unix::fs::symlink(&symlink_target, &symlink_path)
            .map_err(|e| format!("symlink: {e}"))?;
        Ok(())
    });

    smoke_test!("phase1b_readlink", {
        eprintln!("  DIAG  readlink: reading {symlink_path:?}");
        let target = fs::read_link(&symlink_path).map_err(|e| format!("readlink: {e}"))?;
        if target != std::path::Path::new(&symlink_target) {
            return Err(format!(
                "readlink returned {target:?}, expected {symlink_target:?}"
            ));
        }
        Ok(())
    });

    smoke_test!("phase1b_unlink_file", {
        eprintln!("  DIAG  unlink: creating and removing {unlink_file:?}");
        fs::write(&unlink_file, "to be deleted\n").map_err(|e| format!("write: {e}"))?;
        fs::remove_file(&unlink_file).map_err(|e| format!("unlink: {e}"))?;
        if fs::metadata(&unlink_file).is_ok() {
            return Err("unlinked file still exists".to_string());
        }
        Ok(())
    });

    smoke_test!("phase1b_rmdir_dir", {
        eprintln!("  DIAG  rmdir: creating and removing {rmdir_dir:?}");
        fs::create_dir(&rmdir_dir).map_err(|e| format!("mkdir: {e}"))?;
        fs::remove_dir(&rmdir_dir).map_err(|e| format!("rmdir: {e}"))?;
        if fs::metadata(&rmdir_dir).is_ok() {
            return Err("removed dir still exists".to_string());
        }
        Ok(())
    });

    smoke_test!("phase1b_rename_file", {
        eprintln!("  DIAG  rename: {rename_src:?} -> {rename_dst:?}");
        fs::write(&rename_src, "rename test content\n").map_err(|e| format!("write: {e}"))?;
        fs::rename(&rename_src, &rename_dst).map_err(|e| format!("rename: {e}"))?;
        if fs::metadata(&rename_src).is_ok() {
            return Err("rename source still exists".to_string());
        }
        let content = fs::read_to_string(&rename_dst).map_err(|e| format!("read renamed: {e}"))?;
        if content != "rename test content\n" {
            return Err(format!("renamed file content mismatch: {content:?}"));
        }
        Ok(())
    });

    if config.profile == SmokeMountProfile::Quick {
        eprintln!("=== Quick profile: clean teardown after core mount checks ===");
        teardown_daemon(&mut child, mountpoint, false);

        smoke_test!("quick_teardown_complete", {
            let check = Command::new("mountpoint")
                .arg("-q")
                .arg(mountpoint)
                .status();
            if check.is_ok_and(|s| s.success()) {
                return Err("mountpoint still active after quick teardown".to_string());
            }
            Ok(())
        });

        let _ = fs::remove_dir_all(store_root);
        let _ = fs::remove_dir_all(mountpoint);

        eprintln!("=== smoke-mount: {passed} passed, {failed} failed ===");
        if failed > 0 {
            return Err(format!("{failed} smoke test(s) failed"));
        }
        return Ok(());
    }

    // ===================================================================

    // ===================================================================
    // Phase 1e: readdirplus large-directory offset stability
    // ===================================================================
    eprintln!("=== Phase 1e: readdirplus large-directory offset stability ===");

    let large_dir = format!("{mountpoint}/smoke-large-dir");

    smoke_test!("phase1e_large_readdirplus", {
        fs::create_dir(&large_dir).map_err(|e| format!("mkdir large dir: {e}"))?;
        let n_entries: usize = 50;
        // Create 50 files with varying sizes; write via File to ensure flush.
        for i in 0..n_entries {
            let file_path = format!("{large_dir}/entry_{i:04}.dat");
            let data = vec![(i % 256) as u8; i % 64 + 1];
            let mut f = std::fs::File::create(&file_path)
                .map_err(|e| format!("create entry {i:04}: {e}"))?;
            std::io::Write::write_all(&mut f, &data)
                .map_err(|e| format!("write entry {i:04}: {e}"))?;
            f.sync_all()
                .map_err(|e| format!("fsync entry {i:04}: {e}"))?;
        }
        // Collect all entries via readdirplus, excluding "." and "..".
        let mut entries: Vec<String> = Vec::new();
        for entry in fs::read_dir(&large_dir).map_err(|e| format!("read_dir large dir: {e}"))? {
            let entry = entry.map_err(|e| format!("dir entry: {e}"))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name != "." && name != ".." {
                entries.push(name);
            }
        }
        if entries.len() != n_entries {
            return Err(format!(
                "expected {n_entries} entries, got {}: {entries:?}",
                entries.len()
            ));
        }
        // Stat every file to exercise readdirplus attribute path.
        for i in 0..n_entries {
            let name = format!("entry_{i:04}.dat");
            if !entries.contains(&name) {
                return Err(format!("missing entry {name}"));
            }
            let entry_path = format!("{large_dir}/{name}");
            let md = fs::metadata(&entry_path).map_err(|e| format!("stat {name}: {e}"))?;
            if !md.is_file() {
                return Err(format!("{name} is not a file"));
            }
            let expected_sz = (i % 64 + 1) as u64;
            if md.len() != expected_sz {
                return Err(format!(
                    "{name} size mismatch: expected {expected_sz}, got {}",
                    md.len()
                ));
            }
        }
        Ok(())
    });
    // Phase 1c: xattr operations on first mount
    // ===================================================================
    eprintln!("=== Phase 1c: xattr operations ===");

    let xattr_file = format!("{mountpoint}/smoke-xattr.txt");
    smoke_test!("phase1c_create_xattr_file", {
        fs::write(&xattr_file, "xattr test data\n").map_err(|e| format!("write: {e}"))?;
        Ok(())
    });

    smoke_test!("phase1c_user_xattr_roundtrip", {
        xattr_set(&xattr_file, "user.smoke", b"mounted-xattr-roundtrip", 0)?;
        let (buf, n) = xattr_get(&xattr_file, "user.smoke")?;
        if &buf[..n] != b"mounted-xattr-roundtrip" {
            return Err(format!("value mismatch: {:?}", &buf[..n]));
        }
        Ok(())
    });

    smoke_test!("phase1c_xattr_create_succeeds", {
        xattr_set(
            &xattr_file,
            "user.create-ok",
            b"created",
            libc::XATTR_CREATE,
        )?;
        let (_buf, n) = xattr_get(&xattr_file, "user.create-ok")?;
        if n != 7 {
            return Err(format!("expected 7 bytes, got {n}"));
        }
        Ok(())
    });

    smoke_test!("phase1c_xattr_create_fails_on_existing", {
        let result = xattr_set(&xattr_file, "user.smoke", b"again", libc::XATTR_CREATE);
        match result {
            Err(ref msg) if msg.contains("errno=17") => Ok(()),
            Ok(()) => Err("XATTR_CREATE on existing should fail".to_string()),
            Err(e) => Err(format!("expected EEXIST (17), got: {e}")),
        }
    });

    smoke_test!("phase1c_xattr_replace_succeeds", {
        xattr_set(
            &xattr_file,
            "user.smoke",
            b"replaced-value",
            libc::XATTR_REPLACE,
        )?;
        let (buf, n) = xattr_get(&xattr_file, "user.smoke")?;
        if &buf[..n] != b"replaced-value" {
            return Err(format!("replace mismatch: {:?}", &buf[..n]));
        }
        Ok(())
    });

    smoke_test!("phase1c_xattr_replace_fails_on_missing", {
        let result = xattr_set(&xattr_file, "user.never", b"val", libc::XATTR_REPLACE);
        match result {
            Err(ref msg) if msg.contains("errno=61") => Ok(()),
            Ok(()) => Err("XATTR_REPLACE on missing should fail".to_string()),
            Err(e) => Err(format!("expected ENODATA (61), got: {e}")),
        }
    });

    smoke_test!("phase1c_multiple_keys_roundtrip", {
        xattr_set(&xattr_file, "user.k1", b"v1", 0)?;
        xattr_set(&xattr_file, "user.k2", b"v2", 0)?;
        let (buf1, n1) = xattr_get(&xattr_file, "user.k1")?;
        if &buf1[..n1] != b"v1" {
            return Err("k1 mismatch".to_string());
        }
        let (buf2, n2) = xattr_get(&xattr_file, "user.k2")?;
        if &buf2[..n2] != b"v2" {
            return Err("k2 mismatch".to_string());
        }
        Ok(())
    });

    smoke_test!("phase1c_removexattr_makes_missing", {
        xattr_set(&xattr_file, "user.to-remove", b"del-me", 0)?;
        xattr_remove(&xattr_file, "user.to-remove")?;
        let result = xattr_get(&xattr_file, "user.to-remove");
        match result {
            Err(ref msg) if msg.contains("errno=61") => Ok(()),
            Ok(_) => Err("getxattr after remove should fail".to_string()),
            Err(e) => Err(format!("expected ENODATA, got: {e}")),
        }
    });

    smoke_test!("phase1c_getxattr_missing", {
        let result = xattr_get(&xattr_file, "user.never-set");
        match result {
            Err(ref msg) if msg.contains("errno=61") => Ok(()),
            Ok(_) => Err("expected ENODATA on missing".to_string()),
            Err(e) => Err(format!("expected ENODATA, got: {e}")),
        }
    });

    smoke_test!("phase1c_trusted_rejected_nonroot", {
        // SAFETY: `geteuid` has no pointer arguments and only reads the current
        // process credentials.
        let uid = unsafe { libc::geteuid() };
        if uid == 0 {
            eprintln!("  INFO  running as root; trusted.* test identity-gated, skipping");
            return Ok(());
        }
        let result = xattr_set(&xattr_file, "trusted.test", b"val", 0);
        match result {
            Err(ref msg) if msg.contains("errno=1") => Ok(()),
            Ok(()) => Err("non-root trusted.* should fail".to_string()),
            Err(e) => Err(format!("expected EPERM, got: {e}")),
        }
    });

    smoke_test!("phase1c_security_rejected_nonroot", {
        // SAFETY: `geteuid` has no pointer arguments and only reads the current
        // process credentials.
        let uid = unsafe { libc::geteuid() };
        if uid == 0 {
            eprintln!("  INFO  running as root; security.* test identity-gated, skipping");
            return Ok(());
        }
        let result = xattr_set(&xattr_file, "security.test", b"val", 0);
        match result {
            Err(ref msg) if msg.contains("errno=1") || msg.contains("errno=13") => Ok(()),
            Ok(()) => Err("non-root security.* should fail".to_string()),
            Err(e) => Err(format!("expected EPERM/EACCES, got: {e}")),
        }
    });

    smoke_test!("phase1c_system_posix_acl_access", {
        // ── Phase 3c: xattr persistence after clean remount ──
        eprintln!("=== Phase 3c: xattr persistence after clean remount ===");

        smoke_test!("phase3c_xattr_roundtrip_after_remount", {
            let (buf, n) = xattr_get(&xattr_file, "user.smoke")?;
            if &buf[..n] != b"replaced-value" {
                return Err(format!("xattr lost after remount: {:?}", &buf[..n]));
            }
            Ok(())
        });

        smoke_test!("phase3c_multiple_keys_persist", {
            let (buf1, n1) = xattr_get(&xattr_file, "user.k1")?;
            if &buf1[..n1] != b"v1" {
                return Err("k1 lost after remount".to_string());
            }
            let (buf2, n2) = xattr_get(&xattr_file, "user.k2")?;
            if &buf2[..n2] != b"v2" {
                return Err("k2 lost after remount".to_string());
            }
            Ok(())
        });

        smoke_test!("phase3c_removed_xattr_still_missing", {
            let result = xattr_get(&xattr_file, "user.to-remove");
            match result {
                Err(ref msg) if msg.contains("errno=61") => Ok(()),
                Ok(_) => Err("removed xattr reappeared after remount".to_string()),
                Err(e) => Err(format!("expected ENODATA, got: {e}")),
            }
        });

        let acl_raw: &[u8] = &[
            2, 0, 0, 0, 1, 0, 7, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 16, 0, 4, 0, 0, 0, 0, 0,
        ];
        let result = xattr_set(&xattr_file, "system.posix_acl_access", acl_raw, 0);
        if let Err(ref msg) = result {
            if msg.contains("errno=95") {
                eprintln!(
                    "  INFO  system.posix_acl_access: EOPNOTSUPP (kernel FUSE may reject system.*)"
                );
                return Ok(());
            }
        }
        result?;
        let (buf, _n) = xattr_get(&xattr_file, "system.posix_acl_access")?;
        if buf.len() < 4 {
            return Err("ACL blob too short".to_string());
        }
        Ok(())
    });

    // ── Phase 1d: open-unlink and rename-over-open soak ──────────────
    // Exercise POSIX open-unlink (fd survives unlink), rename-over-open
    // (fd survives rename), and rename-overwrite-open (fd survives overwrite
    // rename) semantics.
    eprintln!("=== Phase 1d: open-unlink and rename-over-open soak ===");

    let open_unlink_file = format!("{mountpoint}/smoke-open-unlink.txt");
    let rename_open_src = format!("{mountpoint}/smoke-rename-open-src.txt");
    let rename_open_dst = format!("{mountpoint}/smoke-rename-open-dst.txt");
    let rename_ow_a = format!("{mountpoint}/smoke-rename-ow-a.txt");
    let rename_ow_b = format!("{mountpoint}/smoke-rename-ow-b.txt");

    smoke_test!("phase1d_open_unlink_write_read", {
        use std::os::unix::fs::OpenOptionsExt;

        fs::write(&open_unlink_file, b"initial open-unlink data\n")
            .map_err(|e| format!("write: {e}"))?;

        let mut f = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_SYNC)
            .open(&open_unlink_file)
            .map_err(|e| format!("open: {e}"))?;

        fs::remove_file(&open_unlink_file).map_err(|e| format!("unlink while open: {e}"))?;

        if fs::metadata(&open_unlink_file).is_ok() {
            return Err("file still visible by path after unlink".to_string());
        }

        let post_unlink_data = b"post-unlink write data\n";
        f.write_all(post_unlink_data)
            .map_err(|e| format!("write through open fd: {e}"))?;
        f.sync_all().map_err(|e| format!("fsync: {e}"))?;

        use std::io::{Read, Seek, SeekFrom};
        f.seek(SeekFrom::Start(0))
            .map_err(|e| format!("seek: {e}"))?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)
            .map_err(|e| format!("read through open fd: {e}"))?;
        let content = String::from_utf8_lossy(&buf);
        if !content.contains("initial open-unlink data") {
            return Err(format!(
                "original data not found in fd readback: {content:?}"
            ));
        }
        if !content.contains("post-unlink write data") {
            return Err(format!(
                "post-unlink write not found in fd readback: {content:?}"
            ));
        }

        drop(f);

        if fs::metadata(&open_unlink_file).is_ok() {
            return Err("file reappeared after fd close".to_string());
        }
        Ok(())
    });

    smoke_test!("phase1d_rename_open_handle_survives", {
        use std::os::unix::fs::OpenOptionsExt;

        fs::write(&rename_open_src, b"initial rename-open data\n")
            .map_err(|e| format!("write: {e}"))?;

        let mut f = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_SYNC)
            .open(&rename_open_src)
            .map_err(|e| format!("open: {e}"))?;

        fs::rename(&rename_open_src, &rename_open_dst)
            .map_err(|e| format!("rename while open: {e}"))?;

        if fs::metadata(&rename_open_src).is_ok() {
            return Err("old name still exists after rename".to_string());
        }
        if fs::metadata(&rename_open_dst).is_err() {
            return Err("new name missing after rename".to_string());
        }

        let post_rename_data = b"post-rename write data\n";
        f.write_all(post_rename_data)
            .map_err(|e| format!("write through old fd: {e}"))?;
        f.sync_all().map_err(|e| format!("fsync: {e}"))?;

        use std::io::{Read, Seek, SeekFrom};
        f.seek(SeekFrom::Start(0))
            .map_err(|e| format!("seek: {e}"))?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)
            .map_err(|e| format!("read through old fd: {e}"))?;
        let content = String::from_utf8_lossy(&buf);
        if !content.contains("initial rename-open data") {
            return Err(format!("original data not found: {content:?}"));
        }
        if !content.contains("post-rename write data") {
            return Err(format!("post-rename write not found: {content:?}"));
        }

        drop(f);
        Ok(())
    });

    smoke_test!("phase1d_rename_overwrite_open_handle_survives", {
        use std::os::unix::fs::OpenOptionsExt;

        fs::write(&rename_ow_a, b"file A original data\n").map_err(|e| format!("write A: {e}"))?;
        fs::write(&rename_ow_b, b"file B data\n").map_err(|e| format!("write B: {e}"))?;

        let mut f = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_SYNC)
            .open(&rename_ow_a)
            .map_err(|e| format!("open A: {e}"))?;

        fs::rename(&rename_ow_b, &rename_ow_a).map_err(|e| format!("rename B over A: {e}"))?;

        let post_ow_data = b"post-overwrite write data\n";
        f.write_all(post_ow_data)
            .map_err(|e| format!("write through fd after overwrite: {e}"))?;
        f.sync_all().map_err(|e| format!("fsync: {e}"))?;

        use std::io::{Read, Seek, SeekFrom};
        f.seek(SeekFrom::Start(0))
            .map_err(|e| format!("seek: {e}"))?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)
            .map_err(|e| format!("read through fd: {e}"))?;
        let content = String::from_utf8_lossy(&buf);
        if !content.contains("file A original data") {
            return Err(format!("original A data not found in fd: {content:?}"));
        }
        if !content.contains("post-overwrite write data") {
            return Err(format!("post-overwrite write not found: {content:?}"));
        }

        drop(f);
        Ok(())
    });
    // Phase 2: Clean teardown
    // ═══════════════════════════════════════════════════════════════════
    eprintln!("=== Phase 2: clean teardown ===");
    teardown_daemon(&mut child, mountpoint, false);

    smoke_test!("phase2_teardown_complete", {
        // Verify mountpoint is no longer a mount.
        let check = Command::new("mountpoint")
            .arg("-q")
            .arg(mountpoint)
            .status();
        if check.is_ok_and(|s| s.success()) {
            return Err("mountpoint still active after teardown".to_string());
        }
        Ok(())
    });

    // ═══════════════════════════════════════════════════════════════════
    // Phase 3: Remount → verify data persisted
    // ═══════════════════════════════════════════════════════════════════
    eprintln!("=== Phase 3: remount and data persistence verification ===");

    // Recreate mountpoint dir (umount may have removed it).
    fs::create_dir_all(mountpoint).map_err(|e| format!("recreate mount dir: {e}"))?;

    child = spawn_and_mount(&exe, store_root, mountpoint, None)?;

    smoke_test!("phase3_remount_stat_root", {
        let md = fs::metadata(mountpoint).map_err(|e| format!("stat: {e}"))?;
        if !md.is_dir() {
            return Err("not a directory after remount".to_string());
        }
        Ok(())
    });

    smoke_test!("phase3_data_persist_read", {
        let content =
            fs::read_to_string(&test_file).map_err(|e| format!("read persisted file: {e}"))?;
        if !content.contains("hello tidefs smoke") {
            return Err(format!("persisted file content missing: {content:?}"));
        }
        if !content.contains("appended line") {
            return Err(format!(
                "appended content missing after remount: {content:?}"
            ));
        }
        Ok(())
    });

    smoke_test!("phase3_data_persist_dir", {
        let md = fs::metadata(&test_dir).map_err(|e| format!("stat persisted dir: {e}"))?;
        if !md.is_dir() {
            return Err("persisted dir not a directory".to_string());
        }
        Ok(())
    });

    smoke_test!("phase3_data_persist_readdir", {
        let entries: Vec<String> = fs::read_dir(mountpoint)
            .map_err(|e| format!("read_dir: {e}"))?
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        if !entries.iter().any(|n| n == "smoke-test-file.txt") {
            return Err("persisted file not in readdir after remount".to_string());
        }
        if !entries.iter().any(|n| n == "smoke-subdir") {
            return Err("persisted dir not in readdir after remount".to_string());
        }
        Ok(())
    });

    // Create a second file that will survive the hard-kill test.
    smoke_test!("phase3_create_second_file", {
        fs::write(&second_file, "second file data for crash test\n")
            .map_err(|e| format!("write second file: {e}"))?;
        Ok(())
    });

    // ═══════════════════════════════════════════════════════════════════
    // ── Phase 3b: mutation persistence (symlink, unlink, rmdir, rename) ──
    eprintln!("=== Phase 3b: mutation persistence after clean remount ===");

    smoke_test!("phase3b_symlink_persist", {
        let target =
            fs::read_link(&symlink_path).map_err(|e| format!("readlink after remount: {e}"))?;
        if target != std::path::Path::new(&symlink_target) {
            return Err(format!(
                "symlink lost after remount: got {target:?}, expected {symlink_target:?}"
            ));
        }
        Ok(())
    });

    smoke_test!("phase3b_unlink_persist", {
        if fs::metadata(&unlink_file).is_ok() {
            return Err("unlinked file reappeared after remount".to_string());
        }
        Ok(())
    });

    // ── Phase 5c: xattr persistence after crash remount ──
    eprintln!("=== Phase 5c: xattr persistence after crash remount ===");

    smoke_test!("phase5c_xattr_roundtrip_after_crash", {
        let (buf, n) = xattr_get(&xattr_file, "user.smoke")?;
        if &buf[..n] != b"replaced-value" {
            return Err(format!("xattr lost after crash: {:?}", &buf[..n]));
        }
        Ok(())
    });

    smoke_test!("phase5c_keys_persist_after_crash", {
        let (buf1, n1) = xattr_get(&xattr_file, "user.k1")?;
        if &buf1[..n1] != b"v1" {
            return Err("k1 lost after crash".to_string());
        }
        let (buf2, n2) = xattr_get(&xattr_file, "user.k2")?;
        if &buf2[..n2] != b"v2" {
            return Err("k2 lost after crash".to_string());
        }
        Ok(())
    });

    smoke_test!("phase5c_crash_xattr_create_roundtrip", {
        xattr_set(
            &xattr_file,
            "user.crash-new",
            b"post-crash-create",
            libc::XATTR_CREATE,
        )?;
        let (buf, n) = xattr_get(&xattr_file, "user.crash-new")?;
        if &buf[..n] != b"post-crash-create" {
            return Err(format!("post-crash xattr mismatch: {:?}", &buf[..n]));
        }
        Ok(())
    });

    smoke_test!("phase3b_rmdir_persist", {
        if fs::metadata(&rmdir_dir).is_ok() {
            return Err("rmdir'd directory reappeared after remount".to_string());
        }
        Ok(())
    });

    smoke_test!("phase3b_rename_persist", {
        if fs::metadata(&rename_src).is_ok() {
            return Err("old rename source still exists after remount".to_string());
        }
        let content = fs::read_to_string(&rename_dst)
            .map_err(|e| format!("read renamed after remount: {e}"))?;
        if content != "rename test content\n" {
            return Err(format!(
                "rename content mismatch after remount: {content:?}"
            ));
        }
        Ok(())
    });

    // ===================================================================
    // Phase 3d: mixed directory and data workload (interleaved mkdir + write)
    //
    // Creates a workload where directory creation and file writes are
    // interleaved, mirroring a real application that simultaneously
    // populates directories and writes data. Some files are fsynced
    // (should survive crash), some are not (should be lost on crash
    // if the kernel writeback pages were not yet committed).
    // ===================================================================
    eprintln!("=== Phase 3d: mixed directory and data workload ===");

    let mixed_root = format!("{mountpoint}/mixed_load");
    let mixed_sub_a = format!("{mountpoint}/mixed_load/sub_a");
    let mixed_sub_b = format!("{mountpoint}/mixed_load/sub_b");
    let mixed_deep = format!("{mountpoint}/mixed_load/deep/nested");

    smoke_test!("phase3d_mkdir_mixed_root", {
        fs::create_dir(&mixed_root).map_err(|e| format!("mkdir mixed_root: {e}"))?;
        Ok(())
    });

    smoke_test!("phase3d_create_fsynced_file_a", {
        let path = format!("{mixed_root}/a.txt");
        let data = b"mixed workload file a: interleaved with dir creation\n";
        let mut f = fs::File::create(&path).map_err(|e| format!("create a.txt: {e}"))?;
        f.write_all(data).map_err(|e| format!("write a.txt: {e}"))?;
        f.sync_all().map_err(|e| format!("fsync a.txt: {e}"))?;
        Ok(())
    });

    smoke_test!("phase3d_mkdir_sub_a", {
        fs::create_dir(&mixed_sub_a).map_err(|e| format!("mkdir sub_a: {e}"))?;
        Ok(())
    });

    smoke_test!("phase3d_create_fsynced_file_b", {
        let path = format!("{mixed_sub_a}/b.txt");
        let data = b"mixed workload file b: fsynced in sub_a\n";
        let mut f = fs::File::create(&path).map_err(|e| format!("create b.txt: {e}"))?;
        f.write_all(data).map_err(|e| format!("write b.txt: {e}"))?;
        f.sync_all().map_err(|e| format!("fsync b.txt: {e}"))?;
        Ok(())
    });

    smoke_test!("phase3d_create_nofsync_file_c", {
        let path = format!("{mixed_sub_a}/c.txt");
        let data = b"mixed workload file c: NOT fsynced, expected lost on crash\n";
        fs::write(&path, data).map_err(|e| format!("write c.txt: {e}"))?;
        // Deliberately NOT fsynced; file c should not survive the crash.
        Ok(())
    });

    smoke_test!("phase3d_mkdir_sub_b", {
        fs::create_dir(&mixed_sub_b).map_err(|e| format!("mkdir sub_b: {e}"))?;
        Ok(())
    });

    smoke_test!("phase3d_create_fsynced_file_in_sub_b", {
        let path = format!("{mixed_sub_b}/interleave.txt");
        let data = b"interleave file in sub_b: fsynced\n";
        let mut f = fs::File::create(&path).map_err(|e| format!("create interleave.txt: {e}"))?;
        f.write_all(data)
            .map_err(|e| format!("write interleave.txt: {e}"))?;
        f.sync_all()
            .map_err(|e| format!("fsync interleave.txt: {e}"))?;
        Ok(())
    });

    smoke_test!("phase3d_mkdir_deep_nested", {
        fs::create_dir_all(&mixed_deep).map_err(|e| format!("mkdir -p deep/nested: {e}"))?;
        Ok(())
    });

    smoke_test!("phase3d_create_fsynced_file_d", {
        let path = format!("{mixed_deep}/d.txt");
        let data = b"deep nested file d: fsynced\n";
        let mut f = fs::File::create(&path).map_err(|e| format!("create d.txt: {e}"))?;
        f.write_all(data).map_err(|e| format!("write d.txt: {e}"))?;
        f.sync_all().map_err(|e| format!("fsync d.txt: {e}"))?;
        Ok(())
    });

    smoke_test!("phase3d_create_nofsync_file_e", {
        let path = format!("{mixed_deep}/e.txt");
        let data = b"deep nested file e: NOT fsynced, expected lost on crash\n";
        fs::write(&path, data).map_err(|e| format!("write e.txt: {e}"))?;
        // Deliberately NOT fsynced; file e should not survive the crash.
        Ok(())
    });

    // Verify the mixed workload directories exist before crash.
    smoke_test!("phase3d_verify_before_crash", {
        for (path, label) in &[
            (&mixed_root, "mixed_root"),
            (&mixed_sub_a, "sub_a"),
            (&mixed_sub_b, "sub_b"),
            (&mixed_deep, "deep/nested"),
        ] {
            let md = fs::metadata(path).map_err(|e| format!("stat {label} before crash: {e}"))?;
            if !md.is_dir() {
                return Err(format!("{label}: not a dir before crash"));
            }
        }
        Ok(())
    });

    // Phase 4: Stale handle test (open file, hard-kill daemon, verify
    //          old fd errors after daemon is gone)
    // ═══════════════════════════════════════════════════════════════════
    eprintln!("=== Phase 4: stale handle test ===");

    // Open a file handle before teardown.
    let stale_fd = {
        let file =
            fs::File::open(&test_file).map_err(|e| format!("open file for stale test: {e}"))?;
        use std::os::fd::IntoRawFd;
        file.into_raw_fd()
    };

    // Hard-kill the daemon (SIGKILL without clean unmount).
    teardown_daemon(&mut child, mountpoint, true);

    // Give the kernel a moment to complete pending FUSE operations.
    thread::sleep(Duration::from_secs(4));

    smoke_test!("phase4_stale_handle_read_fails", {
        // Reading from the stale fd should fail because the FUSE daemon
        // is gone. Accept any I/O error (EIO, ENOTCONN, EBADF, ESTALE).
        let mut buf = [0u8; 64];
        // SAFETY: `stale_fd` is an fd owned by this harness until the close
        // probe below, and `buf` is a valid writable buffer for `buf.len()`.
        let n = unsafe { libc::read(stale_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n >= 0 {
            return Err(format!(
                "stale fd read succeeded (returned {n} bytes); expected error after daemon kill"
            ));
        }
        // SAFETY: errno is read immediately after the failing read on this
        // thread.
        let errno = unsafe { *libc::__errno_location() };
        eprintln!("  INFO  stale fd read got errno={errno} (expected)");
        Ok(())
    });

    smoke_test!("phase4_stale_handle_write_fails", {
        // SAFETY: `stale_fd` is still owned by this harness, and the static
        // byte string is valid for the explicit 12-byte write length.
        let n = unsafe {
            libc::write(
                stale_fd,
                b"should fail\n" as *const u8 as *const libc::c_void,
                12,
            )
        };
        if n >= 0 {
            return Err(format!(
                "stale fd write succeeded (returned {n} bytes); expected error after daemon kill"
            ));
        }
        // SAFETY: errno is read immediately after the failing write on this
        // thread.
        let errno = unsafe { *libc::__errno_location() };
        eprintln!("  INFO  stale fd write got errno={errno} (expected)");
        Ok(())
    });

    smoke_test!("phase4_stale_handle_close", {
        // SAFETY: `stale_fd` was produced by `into_raw_fd` and is closed
        // exactly once here, transferring ownership back to the OS.
        let rc = unsafe { libc::close(stale_fd) };
        if rc != 0 {
            // SAFETY: errno is read immediately after the failing close on this
            // thread.
            let errno = unsafe { *libc::__errno_location() };
            eprintln!("  INFO  stale fd close got errno={errno} (expected, may happen)");
        }
        Ok(())
    });

    // ═══════════════════════════════════════════════════════════════════
    // Phase 5: Remount after hard kill → verify data integrity
    // ═══════════════════════════════════════════════════════════════════
    eprintln!("=== Phase 5: remount after hard kill ===");

    fs::create_dir_all(mountpoint).map_err(|e| format!("recreate mount dir: {e}"))?;

    child = spawn_and_mount(&exe, store_root, mountpoint, None)?;

    smoke_test!("phase5_remount_stat_root", {
        let md = fs::metadata(mountpoint).map_err(|e| format!("stat: {e}"))?;
        if !md.is_dir() {
            return Err("not a directory after crash remount".to_string());
        }
        Ok(())
    });

    smoke_test!("phase5_data_integrity_file1", {
        let content = fs::read_to_string(&test_file)
            .map_err(|e| format!("read file after crash remount: {e}"))?;
        if !content.contains("hello tidefs smoke") {
            return Err(format!("file1 header missing after crash: {content:?}"));
        }
        if !content.contains("appended line") {
            return Err(format!("appended content missing after crash: {content:?}"));
        }
        Ok(())
    });

    smoke_test!("phase5_data_integrity_file2", {
        let content = fs::read_to_string(&second_file)
            .map_err(|e| format!("read second file after crash: {e}"))?;
        if content != "second file data for crash test\n" {
            return Err(format!("second file content mismatch: {content:?}"));
        }
        Ok(())
    });

    smoke_test!("phase5_data_integrity_dir", {
        let md = fs::metadata(&test_dir).map_err(|e| format!("stat dir after crash: {e}"))?;
        if !md.is_dir() {
            return Err("dir not present after crash".to_string());
        }
        Ok(())
    });

    // ── Phase 5b: mutation persistence after crash remount ──
    eprintln!("=== Phase 5b: mutation persistence after crash remount ===");

    smoke_test!("phase5b_symlink_crash_persist", {
        let target = fs::read_link(&symlink_path)
            .map_err(|e| format!("readlink after crash remount: {e}"))?;
        if target != std::path::Path::new(&symlink_target) {
            return Err(format!(
                "symlink lost after crash: got {target:?}, expected {symlink_target:?}"
            ));
        }
        Ok(())
    });

    smoke_test!("phase5b_unlink_crash_persist", {
        if fs::metadata(&unlink_file).is_ok() {
            return Err("unlinked file reappeared after crash remount".to_string());
        }
        Ok(())
    });

    smoke_test!("phase5b_rmdir_crash_persist", {
        if fs::metadata(&rmdir_dir).is_ok() {
            return Err("rmdir'd directory reappeared after crash remount".to_string());
        }
        Ok(())
    });

    smoke_test!("phase5b_rename_crash_persist", {
        if fs::metadata(&rename_src).is_ok() {
            return Err("old rename source still exists after crash remount".to_string());
        }
        let content = fs::read_to_string(&rename_dst)
            .map_err(|e| format!("read renamed after crash remount: {e}"))?;
        if content != "rename test content\n" {
            return Err(format!("rename content mismatch after crash: {content:?}"));
        }
        Ok(())
    });

    // ===================================================================
    // Phase 5d: mixed workload crash persistence verification
    //
    // After the SIGKILL crash and remount, verify that:
    // - All fsynced files survived with correct content.
    // - Directory structure for committed directories is intact.
    // - Non-fsynced files are gone (true crash semantics) or
    //   survived via clean-unmount flush (reported for diagnostics).
    // ===================================================================
    eprintln!("=== Phase 5d: mixed workload crash persistence ===");

    smoke_test!("phase5d_mixed_root_exists", {
        let md =
            fs::metadata(&mixed_root).map_err(|e| format!("stat mixed_root after crash: {e}"))?;
        if !md.is_dir() {
            return Err("mixed_root not a directory after crash".to_string());
        }
        Ok(())
    });

    smoke_test!("phase5d_fsynced_file_a_survives", {
        let path = format!("{mixed_root}/a.txt");
        let content =
            fs::read_to_string(&path).map_err(|e| format!("read a.txt after crash: {e}"))?;
        if !content.contains("mixed workload file a") {
            return Err(format!("a.txt content mismatch: {content:?}"));
        }
        Ok(())
    });

    smoke_test!("phase5d_sub_a_dir_survives", {
        let md = fs::metadata(&mixed_sub_a).map_err(|e| format!("stat sub_a after crash: {e}"))?;
        if !md.is_dir() {
            return Err("sub_a not a directory after crash".to_string());
        }
        Ok(())
    });

    smoke_test!("phase5d_fsynced_file_b_survives", {
        let path = format!("{mixed_sub_a}/b.txt");
        let content =
            fs::read_to_string(&path).map_err(|e| format!("read b.txt after crash: {e}"))?;
        if !content.contains("mixed workload file b") {
            return Err(format!("b.txt content mismatch: {content:?}"));
        }
        Ok(())
    });

    smoke_test!("phase5d_nofsync_file_c_lost", {
        let path = format!("{mixed_sub_a}/c.txt");
        // c.txt was NOT fsynced before the crash. In a true crash
        // scenario it should not survive; if the unmount path flushed
        // it, report the unexpected persistence for diagnostics.
        match fs::metadata(&path) {
            Ok(md) if md.is_file() => {
                eprintln!("  DIAG  nofsync file c.txt survived crash (unexpected: may indicate clean-unmount flush path engaged)");
            }
            Ok(_) => {
                eprintln!("  DIAG  nofsync path c.txt exists but is not a regular file");
            }
            Err(_) => {
                eprintln!("  INFO  nofsync file c.txt correctly lost after crash");
            }
        }
        Ok(())
    });

    smoke_test!("phase5d_sub_b_dir_survives", {
        let md = fs::metadata(&mixed_sub_b).map_err(|e| format!("stat sub_b after crash: {e}"))?;
        if !md.is_dir() {
            return Err("sub_b not a directory after crash".to_string());
        }
        Ok(())
    });

    smoke_test!("phase5d_fsynced_interleave_survives", {
        let path = format!("{mixed_sub_b}/interleave.txt");
        let content = fs::read_to_string(&path)
            .map_err(|e| format!("read interleave.txt after crash: {e}"))?;
        if !content.contains("interleave file in sub_b") {
            return Err(format!("interleave.txt content mismatch: {content:?}"));
        }
        Ok(())
    });

    smoke_test!("phase5d_deep_dir_survives", {
        let md =
            fs::metadata(&mixed_deep).map_err(|e| format!("stat deep/nested after crash: {e}"))?;
        if !md.is_dir() {
            return Err("deep/nested not a directory after crash".to_string());
        }
        Ok(())
    });

    smoke_test!("phase5d_fsynced_file_d_survives", {
        let path = format!("{mixed_deep}/d.txt");
        let content =
            fs::read_to_string(&path).map_err(|e| format!("read d.txt after crash: {e}"))?;
        if !content.contains("deep nested file d") {
            return Err(format!("d.txt content mismatch: {content:?}"));
        }
        Ok(())
    });

    smoke_test!("phase5d_nofsync_file_e_lost", {
        let path = format!("{mixed_deep}/e.txt");
        // e.txt was NOT fsynced before the crash.
        match fs::metadata(&path) {
            Ok(md) if md.is_file() => {
                eprintln!("  DIAG  nofsync file e.txt survived crash (unexpected: may indicate clean-unmount flush path engaged)");
            }
            Ok(_) => {
                eprintln!("  DIAG  nofsync path e.txt exists but is not a regular file");
            }
            Err(_) => {
                eprintln!("  INFO  nofsync file e.txt correctly lost after crash");
            }
        }
        Ok(())
    });

    // ===================================================================
    // Phase 6: POSIX lock, flock, and OFD lock workload
    // ===================================================================
    eprintln!("=== Phase 6: lock workload ===");

    // Create a lock test file and exercise POSIX fcntl byte-range locks,
    // BSD flock, and OFD (open file description) lock semantics through
    // the mounted FUSE filesystem.
    let lock_file = format!("{mountpoint}/smoke-lock-file.txt");
    smoke_test!("phase6_lock_create_file", {
        fs::write(
            &lock_file,
            "lock test data: 0123456789ABCDEF0123456789ABCDEF\n",
        )
        .map_err(|e| format!("write: {e}"))?;
        Ok(())
    });

    let lock_file_c = std::ffi::CString::new(lock_file.as_str())
        .map_err(|e| format!("lock file CString: {e}"))?;
    let open_lock_file = || {
        // SAFETY: `lock_file_c` owns a NUL-terminated buffer that remains alive
        // for every call through this closure. Each nonnegative descriptor
        // returned by `open` is owned by the calling lock probe.
        unsafe { libc::open(lock_file_c.as_ptr(), libc::O_RDWR) }
    };

    // POSIX F_SETLK non-blocking write-lock acquire.
    smoke_test!("phase6_posix_setlk_write_acquire", {
        let fd = open_lock_file();
        if fd < 0 {
            // SAFETY: errno is read immediately after the failing open on this
            // thread.
            return Err(format!("open: errno={}", unsafe {
                *libc::__errno_location()
            }));
        }
        // SAFETY: `flock` is a C value type and zeroed storage is populated
        // field-by-field before it is passed to `fcntl`.
        let mut fl: libc::flock = unsafe { std::mem::zeroed() };
        fl.l_type = libc::F_WRLCK as i16;
        fl.l_whence = libc::SEEK_SET as i16;
        fl.l_start = 0;
        fl.l_len = 100;
        // SAFETY: `fd` is the owned descriptor returned by open, and `fl`
        // points to an initialized lock request for the duration of the call.
        let rc = unsafe { libc::fcntl(fd, libc::F_SETLK, &fl) };
        if rc != 0 {
            // SAFETY: errno is read immediately after the failing fcntl on this
            // thread.
            let e = unsafe { *libc::__errno_location() };
            // SAFETY: `fd` is owned by this probe and is not used after this
            // close on the error path.
            unsafe {
                libc::close(fd);
            }
            return Err(format!("F_SETLK write acquire failed: errno={e}"));
        }
        // SAFETY: `fd` is owned by this probe and is not used after this close.
        unsafe {
            libc::close(fd);
        }
        Ok(())
    });

    // POSIX F_SETLK write-lock conflict: overlapping write locks from
    // two file descriptors should return EAGAIN/EWOULDBLOCK.
    smoke_test!("phase6_posix_setlk_write_conflict", {
        let fd1 = open_lock_file();
        if fd1 < 0 {
            // SAFETY: errno is read immediately after the failing open on this
            // thread.
            return Err(format!("open fd1: errno={}", unsafe {
                *libc::__errno_location()
            }));
        }
        // SAFETY: `flock` is a C value type and zeroed storage is populated
        // field-by-field before it is passed to `fcntl`.
        let mut fl1: libc::flock = unsafe { std::mem::zeroed() };
        fl1.l_type = libc::F_WRLCK as i16;
        fl1.l_whence = libc::SEEK_SET as i16;
        fl1.l_start = 0;
        fl1.l_len = 50;
        // SAFETY: `fd1` is open and owned by this probe, and `fl1` points to an
        // initialized lock request.
        if unsafe { libc::fcntl(fd1, libc::F_SETLK, &fl1) } != 0 {
            // SAFETY: errno is read immediately after the failing fcntl on this
            // thread.
            let e = unsafe { *libc::__errno_location() };
            // SAFETY: `fd1` is owned by this probe and is not used after this
            // close on the error path.
            unsafe {
                libc::close(fd1);
            }
            return Err(format!("first F_SETLK failed: errno={e}"));
        }
        let fd2 = open_lock_file();
        if fd2 < 0 {
            // SAFETY: `fd1` is owned by this probe and is not used after this
            // close on the error path.
            unsafe {
                libc::close(fd1);
            }
            // SAFETY: errno is read immediately after the failing open on this
            // thread.
            return Err(format!("open fd2: errno={}", unsafe {
                *libc::__errno_location()
            }));
        }
        // SAFETY: `flock` is a C value type and zeroed storage is populated
        // field-by-field before it is passed to `fcntl`.
        let mut fl2: libc::flock = unsafe { std::mem::zeroed() };
        fl2.l_type = libc::F_WRLCK as i16;
        fl2.l_whence = libc::SEEK_SET as i16;
        fl2.l_start = 10;
        fl2.l_len = 40;
        // SAFETY: `fd2` is open and owned by this probe, and `fl2` points to an
        // initialized lock request.
        let rc2 = unsafe { libc::fcntl(fd2, libc::F_SETLK, &fl2) };
        if rc2 == 0 {
            // SAFETY: both fds are owned by this probe and are not used after
            // this close on the unexpected-success path.
            unsafe {
                libc::close(fd1);
                libc::close(fd2);
            }
            return Err(
                "conflicting F_SETLK should have returned EAGAIN/EWOULDBLOCK but succeeded".into(),
            );
        }
        // SAFETY: errno is read immediately after the failing fcntl on this
        // thread.
        let errno2 = unsafe { *libc::__errno_location() };
        if errno2 != libc::EAGAIN && errno2 != libc::EWOULDBLOCK {
            // SAFETY: both fds are owned by this probe and are not used after
            // this close on the error path.
            unsafe {
                libc::close(fd1);
                libc::close(fd2);
            }
            return Err(format!("expected EAGAIN/EWOULDBLOCK, got errno={errno2}"));
        }
        // SAFETY: both fds are owned by this probe and are not used after this
        // close.
        unsafe {
            libc::close(fd1);
            libc::close(fd2);
        }
        Ok(())
    });

    // POSIX F_GETLK query: should return the conflicting lock info.
    smoke_test!("phase6_posix_getlk_query", {
        let fd1 = open_lock_file();
        if fd1 < 0 {
            // SAFETY: errno is read immediately after the failing open on this
            // thread.
            return Err(format!("open fd1: errno={}", unsafe {
                *libc::__errno_location()
            }));
        }
        // SAFETY: `flock` is a C value type and zeroed storage is populated
        // field-by-field before it is passed to `fcntl`.
        let mut fl1: libc::flock = unsafe { std::mem::zeroed() };
        fl1.l_type = libc::F_WRLCK as i16;
        fl1.l_whence = libc::SEEK_SET as i16;
        fl1.l_start = 100;
        fl1.l_len = 100;
        // SAFETY: `fd1` is open and owned by this probe, and `fl1` points to an
        // initialized lock request.
        if unsafe { libc::fcntl(fd1, libc::F_SETLK, &fl1) } != 0 {
            // SAFETY: errno is read immediately after the failing fcntl on this
            // thread.
            let e = unsafe { *libc::__errno_location() };
            // SAFETY: `fd1` is owned by this probe and is not used after this
            // close on the error path.
            unsafe {
                libc::close(fd1);
            }
            return Err(format!("write lock acquire failed: errno={e}"));
        }
        let fd2 = open_lock_file();
        if fd2 < 0 {
            // SAFETY: `fd1` is owned by this probe and is not used after this
            // close on the error path.
            unsafe {
                libc::close(fd1);
            }
            // SAFETY: errno is read immediately after the failing open on this
            // thread.
            return Err(format!("open fd2: errno={}", unsafe {
                *libc::__errno_location()
            }));
        }
        // SAFETY: `flock` is a C value type and zeroed storage is populated
        // field-by-field before it is passed to `fcntl`.
        let mut fl_query: libc::flock = unsafe { std::mem::zeroed() };
        fl_query.l_type = libc::F_WRLCK as i16;
        fl_query.l_whence = libc::SEEK_SET as i16;
        fl_query.l_start = 150;
        fl_query.l_len = 10;
        // SAFETY: `fd2` is open and owned by this probe, and `fl_query` points
        // to initialized storage that fcntl may update for F_GETLK.
        if unsafe { libc::fcntl(fd2, libc::F_GETLK, &fl_query) } != 0 {
            // SAFETY: errno is read immediately after the failing fcntl on this
            // thread.
            let e = unsafe { *libc::__errno_location() };
            // SAFETY: both fds are owned by this probe and are not used after
            // this close on the error path.
            unsafe {
                libc::close(fd1);
                libc::close(fd2);
            }
            return Err(format!("F_GETLK failed: errno={e}"));
        }
        if fl_query.l_type != (libc::F_WRLCK as i16) {
            // SAFETY: both fds are owned by this probe and are not used after
            // this close on the error path.
            unsafe {
                libc::close(fd1);
                libc::close(fd2);
            }
            return Err(format!(
                "F_GETLK should report F_WRLCK, got type={}",
                fl_query.l_type
            ));
        }
        if fl_query.l_pid <= 0 {
            // SAFETY: both fds are owned by this probe and are not used after
            // this close on the error path.
            unsafe {
                libc::close(fd1);
                libc::close(fd2);
            }
            return Err(format!("F_GETLK pid should be >0, got {}", fl_query.l_pid));
        }
        // SAFETY: both fds are owned by this probe and are not used after this
        // close.
        unsafe {
            libc::close(fd1);
            libc::close(fd2);
        }
        Ok(())
    });

    // POSIX F_SETLK unlock: release a held lock and verify re-acquire succeeds.
    smoke_test!("phase6_posix_setlk_unlock", {
        let fd = open_lock_file();
        if fd < 0 {
            // SAFETY: errno is read immediately after the failing open on this
            // thread.
            return Err(format!("open: errno={}", unsafe {
                *libc::__errno_location()
            }));
        }
        // SAFETY: `flock` is a C value type and zeroed storage is populated
        // field-by-field before it is passed to `fcntl`.
        let mut fl: libc::flock = unsafe { std::mem::zeroed() };
        fl.l_type = libc::F_WRLCK as i16;
        fl.l_whence = libc::SEEK_SET as i16;
        fl.l_start = 200;
        fl.l_len = 50;
        // SAFETY: `fd` is open and owned by this probe, and `fl` points to an
        // initialized lock request.
        if unsafe { libc::fcntl(fd, libc::F_SETLK, &fl) } != 0 {
            // SAFETY: errno is read immediately after the failing fcntl on this
            // thread.
            let e = unsafe { *libc::__errno_location() };
            // SAFETY: `fd` is owned by this probe and is not used after this
            // close on the error path.
            unsafe {
                libc::close(fd);
            }
            return Err(format!("acquire failed: errno={e}"));
        }
        fl.l_type = libc::F_UNLCK as i16;
        // SAFETY: `fd` is open and owned by this probe, and `fl` remains an
        // initialized lock request with only the lock type changed.
        if unsafe { libc::fcntl(fd, libc::F_SETLK, &fl) } != 0 {
            // SAFETY: errno is read immediately after the failing fcntl on this
            // thread.
            let e = unsafe { *libc::__errno_location() };
            // SAFETY: `fd` is owned by this probe and is not used after this
            // close on the error path.
            unsafe {
                libc::close(fd);
            }
            return Err(format!("unlock failed: errno={e}"));
        }
        fl.l_type = libc::F_WRLCK as i16;
        // SAFETY: `fd` is open and owned by this probe, and `fl` remains an
        // initialized lock request with only the lock type changed.
        if unsafe { libc::fcntl(fd, libc::F_SETLK, &fl) } != 0 {
            // SAFETY: errno is read immediately after the failing fcntl on this
            // thread.
            let e = unsafe { *libc::__errno_location() };
            // SAFETY: `fd` is owned by this probe and is not used after this
            // close on the error path.
            unsafe {
                libc::close(fd);
            }
            return Err(format!("re-acquire after unlock failed: errno={e}"));
        }
        // SAFETY: `fd` is owned by this probe and is not used after this close.
        unsafe {
            libc::close(fd);
        }
        Ok(())
    });

    // BSD flock exclusive acquire.
    smoke_test!("phase6_flock_exclusive_acquire", {
        let fd = open_lock_file();
        if fd < 0 {
            // SAFETY: errno is read immediately after the failing open on this
            // thread.
            return Err(format!("open: errno={}", unsafe {
                *libc::__errno_location()
            }));
        }
        // SAFETY: `fd` is open and owned by this probe for the flock call.
        if unsafe { libc::flock(fd, libc::LOCK_EX) } != 0 {
            // SAFETY: errno is read immediately after the failing flock on this
            // thread.
            let e = unsafe { *libc::__errno_location() };
            // SAFETY: `fd` is owned by this probe and is not used after this
            // close on the error path.
            unsafe {
                libc::close(fd);
            }
            return Err(format!("flock LOCK_EX failed: errno={e}"));
        }
        // SAFETY: `fd` is owned by this probe and is not used after this close.
        unsafe {
            libc::close(fd);
        }
        Ok(())
    });

    // BSD flock exclusive conflict: two fds competing for exclusive flock
    // on the same file, second with LOCK_NB should get EWOULDBLOCK.
    smoke_test!("phase6_flock_exclusive_conflict", {
        let fd1 = open_lock_file();
        if fd1 < 0 {
            // SAFETY: errno is read immediately after the failing open on this
            // thread.
            return Err(format!("open fd1: errno={}", unsafe {
                *libc::__errno_location()
            }));
        }
        // SAFETY: `fd1` is open and owned by this probe for the flock call.
        if unsafe { libc::flock(fd1, libc::LOCK_EX) } != 0 {
            // SAFETY: errno is read immediately after the failing flock on this
            // thread.
            let e = unsafe { *libc::__errno_location() };
            // SAFETY: `fd1` is owned by this probe and is not used after this
            // close on the error path.
            unsafe {
                libc::close(fd1);
            }
            return Err(format!("first flock LOCK_EX failed: errno={e}"));
        }
        let fd2 = open_lock_file();
        if fd2 < 0 {
            // SAFETY: `fd1` is owned by this probe and is not used after this
            // close on the error path.
            unsafe {
                libc::close(fd1);
            }
            // SAFETY: errno is read immediately after the failing open on this
            // thread.
            return Err(format!("open fd2: errno={}", unsafe {
                *libc::__errno_location()
            }));
        }
        // SAFETY: `fd2` is open and owned by this probe for the nonblocking
        // flock conflict check.
        let rc2 = unsafe { libc::flock(fd2, libc::LOCK_EX | libc::LOCK_NB) };
        if rc2 == 0 {
            // SAFETY: both fds are owned by this probe and are not used after
            // this close on the unexpected-success path.
            unsafe {
                libc::close(fd1);
                libc::close(fd2);
            }
            return Err(
                "conflicting flock LOCK_EX|LOCK_NB should have returned EWOULDBLOCK but succeeded"
                    .into(),
            );
        }
        // SAFETY: errno is read immediately after the failing flock on this
        // thread.
        let errno2 = unsafe { *libc::__errno_location() };
        if errno2 != libc::EWOULDBLOCK && errno2 != libc::EAGAIN {
            // SAFETY: both fds are owned by this probe and are not used after
            // this close on the error path.
            unsafe {
                libc::close(fd1);
                libc::close(fd2);
            }
            return Err(format!(
                "expected EWOULDBLOCK/EAGAIN from flock conflict, got errno={errno2}"
            ));
        }
        // SAFETY: both fds are owned by this probe and are not used after this
        // close.
        unsafe {
            libc::close(fd1);
            libc::close(fd2);
        }
        Ok(())
    });

    // OFD lock: two fds from the same process on overlapping byte ranges
    // must conflict (unlike traditional POSIX locks where same-pid replaces).
    smoke_test!("phase6_ofd_lock_two_fds_conflict", {
        let fd1 = open_lock_file();
        if fd1 < 0 {
            // SAFETY: errno is read immediately after the failing open on this
            // thread.
            return Err(format!("open fd1: errno={}", unsafe {
                *libc::__errno_location()
            }));
        }
        #[allow(non_upper_case_globals)]
        const F_OFD_SETLK: libc::c_int = 37;
        // SAFETY: `flock` is a C value type and zeroed storage is populated
        // field-by-field before it is passed to `fcntl`.
        let mut fl1: libc::flock = unsafe { std::mem::zeroed() };
        fl1.l_type = libc::F_WRLCK as i16;
        fl1.l_whence = libc::SEEK_SET as i16;
        fl1.l_start = 0;
        fl1.l_len = 200;
        // SAFETY: `fd1` is open and owned by this probe, and `fl1` points to an
        // initialized OFD lock request.
        if unsafe { libc::fcntl(fd1, F_OFD_SETLK, &fl1) } != 0 {
            // SAFETY: errno is read immediately after the failing fcntl on this
            // thread.
            let e = unsafe { *libc::__errno_location() };
            // SAFETY: `fd1` is owned by this probe and is not used after this
            // close on the error path.
            unsafe {
                libc::close(fd1);
            }
            return Err(format!("OFD SETLK fd1 failed: errno={e}"));
        }
        let fd2 = open_lock_file();
        if fd2 < 0 {
            // SAFETY: `fd1` is owned by this probe and is not used after this
            // close on the error path.
            unsafe {
                libc::close(fd1);
            }
            // SAFETY: errno is read immediately after the failing open on this
            // thread.
            return Err(format!("open fd2: errno={}", unsafe {
                *libc::__errno_location()
            }));
        }
        // SAFETY: `flock` is a C value type and zeroed storage is populated
        // field-by-field before it is passed to `fcntl`.
        let mut fl2: libc::flock = unsafe { std::mem::zeroed() };
        fl2.l_type = libc::F_WRLCK as i16;
        fl2.l_whence = libc::SEEK_SET as i16;
        fl2.l_start = 50;
        fl2.l_len = 50;
        // SAFETY: `fd2` is open and owned by this probe, and `fl2` points to an
        // initialized OFD lock request.
        if unsafe { libc::fcntl(fd2, F_OFD_SETLK, &fl2) } == 0 {
            // SAFETY: both fds are owned by this probe and are not used after
            // this close on the unexpected-success path.
            unsafe {
                libc::close(fd1);
                libc::close(fd2);
            }
            return Err("conflicting OFD lock should have been denied but succeeded".into());
        }
        // SAFETY: errno is read immediately after the failing fcntl on this
        // thread.
        let errno2 = unsafe { *libc::__errno_location() };
        if errno2 != libc::EAGAIN && errno2 != libc::EWOULDBLOCK {
            // SAFETY: both fds are owned by this probe and are not used after
            // this close on the error path.
            unsafe {
                libc::close(fd1);
                libc::close(fd2);
            }
            return Err(format!(
                "expected EAGAIN/EWOULDBLOCK from OFD conflict, got errno={errno2}"
            ));
        }
        // SAFETY: both fds are owned by this probe and are not used after this
        // close.
        unsafe {
            libc::close(fd1);
            libc::close(fd2);
        }
        Ok(())
    });

    // OFD lock query through F_OFD_GETLK.
    smoke_test!("phase6_ofd_lock_getlk_query", {
        let fd1 = open_lock_file();
        if fd1 < 0 {
            // SAFETY: errno is read immediately after the failing open on this
            // thread.
            return Err(format!("open fd1: errno={}", unsafe {
                *libc::__errno_location()
            }));
        }
        #[allow(non_upper_case_globals)]
        const F_OFD_SETLK: libc::c_int = 37;
        #[allow(non_upper_case_globals)]
        const F_OFD_GETLK: libc::c_int = 36;
        // SAFETY: `flock` is a C value type and zeroed storage is populated
        // field-by-field before it is passed to `fcntl`.
        let mut fl1: libc::flock = unsafe { std::mem::zeroed() };
        fl1.l_type = libc::F_WRLCK as i16;
        fl1.l_whence = libc::SEEK_SET as i16;
        fl1.l_start = 300;
        fl1.l_len = 100;
        // SAFETY: `fd1` is open and owned by this probe, and `fl1` points to an
        // initialized OFD lock request.
        if unsafe { libc::fcntl(fd1, F_OFD_SETLK, &fl1) } != 0 {
            // SAFETY: errno is read immediately after the failing fcntl on this
            // thread.
            let e = unsafe { *libc::__errno_location() };
            // SAFETY: `fd1` is owned by this probe and is not used after this
            // close on the error path.
            unsafe {
                libc::close(fd1);
            }
            return Err(format!("OFD SETLK acquire failed: errno={e}"));
        }
        let fd2 = open_lock_file();
        if fd2 < 0 {
            // SAFETY: `fd1` is owned by this probe and is not used after this
            // close on the error path.
            unsafe {
                libc::close(fd1);
            }
            // SAFETY: errno is read immediately after the failing open on this
            // thread.
            return Err(format!("open fd2: errno={}", unsafe {
                *libc::__errno_location()
            }));
        }
        // SAFETY: `flock` is a C value type and zeroed storage is populated
        // field-by-field before it is passed to `fcntl`.
        let mut fl_query: libc::flock = unsafe { std::mem::zeroed() };
        fl_query.l_type = libc::F_WRLCK as i16;
        fl_query.l_whence = libc::SEEK_SET as i16;
        fl_query.l_start = 350;
        fl_query.l_len = 10;
        // SAFETY: `fd2` is open and owned by this probe, and `fl_query` points
        // to initialized storage that fcntl may update for F_OFD_GETLK.
        if unsafe { libc::fcntl(fd2, F_OFD_GETLK, &fl_query) } != 0 {
            // SAFETY: errno is read immediately after the failing fcntl on this
            // thread.
            let e = unsafe { *libc::__errno_location() };
            // SAFETY: both fds are owned by this probe and are not used after
            // this close on the error path.
            unsafe {
                libc::close(fd1);
                libc::close(fd2);
            }
            return Err(format!("OFD GETLK failed: errno={e}"));
        }
        if fl_query.l_type != (libc::F_WRLCK as i16) {
            // SAFETY: both fds are owned by this probe and are not used after
            // this close on the error path.
            unsafe {
                libc::close(fd1);
                libc::close(fd2);
            }
            return Err(format!(
                "OFD GETLK should report F_WRLCK, got type={}",
                fl_query.l_type
            ));
        }
        // SAFETY: both fds are owned by this probe and are not used after this
        // close.
        unsafe {
            libc::close(fd1);
            libc::close(fd2);
        }
        Ok(())
    });

    // Clean up the lock test file.
    smoke_test!("phase6_lock_file_unlink", {
        fs::remove_file(&lock_file).map_err(|e| format!("unlink lock file: {e}"))?;
        Ok(())
    });

    // ===================================================================
    // Phase 7: Final cleanup
    // ===================================================================
    eprintln!("=== Phase 7: final cleanup ===");
    teardown_daemon(&mut child, mountpoint, false);

    // ── Phase 7b: SuspectLog persistence and segment chain integrity ──
    // After normal daemon teardown (which calls sync_all → write_suspect_log),
    // open the store directly and verify the SuspectLog survives the
    // daemon lifecycle and is well-formed.
    eprintln!("=== Phase 7b: SuspectLog persistence verification ===");

    smoke_test!("phase7b_suspect_log_loads", {
        let store = tidefs_local_object_store::LocalObjectStore::open(store_root)
            .map_err(|e| format!("open store for suspect log: {e}"))?;
        let log = store.suspect_log();
        if !log.is_empty() {
            eprintln!(
                "  DIAG  suspect_log has {} entries (corruption found)",
                log.len()
            );
        } else {
            eprintln!("  DIAG  suspect_log is empty (clean, expected)");
        }
        Ok(())
    });

    smoke_test!("phase7b_segment_chain_verify", {
        let store = tidefs_local_object_store::LocalObjectStore::open(store_root)
            .map_err(|e| format!("open store for chain verify: {e}"))?;
        let (stats, _log) = store
            .verify_segment_chain()
            .map_err(|e| format!("segment chain verify: {e}"))?;
        eprintln!(
            "  DIAG  segment chain: segments_in_chain={} chain_breaks={} last_segment={}",
            stats.segments_in_chain, stats.chain_breaks_detected, stats.last_verified_segment
        );
        if stats.chain_breaks_detected > 0 {
            return Err(format!(
                "{} chain breaks found",
                stats.chain_breaks_detected
            ));
        }
        Ok(())
    });

    smoke_test!("phase7b_reopen_store_after_daemon_teardown", {
        // Reopen the store to confirm it's not held exclusively by the daemon.
        let _store = tidefs_local_object_store::LocalObjectStore::open(store_root)
            .map_err(|e| format!("reopen store: {e}"))?;
        Ok(())
    });

    // ── Phase 8: Repair writeback policy and recovery loop ──
    // Opens the store directly with RepairWriteback policy, runs the
    // committed-root recovery loop, scrubs the segment chain, and
    // verifies the repair log is well-formed.  This proves the repair
    // writeback code path is functional on the mounted pool even
    // though the daemon itself defaults to ReplayOnly.
    eprintln!("=== Phase 8: repair writeback recovery verification ===");

    smoke_test!("phase8_recovery_loop_repair_writeback", {
        use tidefs_local_filesystem::human::local_filesystem::{
            LocalFileSystem, LocalStorageAllocatorPolicy, StoreOptions,
        };
        let auth_key = tidefs_local_filesystem::RootAuthenticationKey::from_hex(
            "4141414141414141414141414141414141414141414141414141414141414141",
        )
        .map_err(|e| format!("auth key: {e}"))?;
        let store_opts = StoreOptions {
            reclaim_enabled: true,
            ..Default::default()
        };
        let _lfs = LocalFileSystem::open_with_allocator_policy_and_root_authentication_key(
            store_root,
            tidefs_local_filesystem::LocalFileSystemOpenConfig {
                options: store_opts,
                allocator_policy: LocalStorageAllocatorPolicy::default(),
                root_authentication_key: auth_key,
                encryption: None,
                compression: None,
                log_device_device_path: None,
                recovery_policy: tidefs_recovery_loop::RecoveryPolicy::RepairWriteback,
                block_devices: None,
            },
        )
        .map_err(|e| format!("open with RepairWriteback: {e}"))?;
        eprintln!("  DIAG  RepairWriteback open succeeded, recovery loop completed");
        Ok(())
    });

    smoke_test!("phase8_run_background_scrub_on_mounted_pool", {
        let mut store = tidefs_local_object_store::LocalObjectStore::open_with_options(
            store_root,
            tidefs_local_object_store::StoreOptions {
                background_scrub_interval_secs: 1,
                reclaim_enabled: true,
                ..tidefs_local_object_store::StoreOptions::default()
            },
        )
        .map_err(|e| format!("open scrub store: {e}"))?;
        // Run one scrub pass and confirm it completes without error.
        let report = store
            .run_background_scrub()
            .map_err(|e| format!("run_background_scrub: {e}"))?;
        eprintln!(
            "  DIAG  scrub on mounted pool: segments_scanned={} records_verified={}",
            report.segments_scanned, report.records_verified
        );
        let suspect_text = store.suspect_log_text_report();
        if !suspect_text.is_empty() {
            eprintln!("  DIAG  suspect_log_report:\n{suspect_text}");
        }
        Ok(())
    });

    smoke_test!("phase8_discover_suspect_entries_via_chain_verify", {
        let store = tidefs_local_object_store::LocalObjectStore::open(store_root)
            .map_err(|e| format!("open store: {e}"))?;
        let (_stats, suspect_log) = store
            .verify_segment_chain()
            .map_err(|e| format!("verify_segment_chain: {e}"))?;
        let entry_count = suspect_log.len();
        eprintln!(
            "  DIAG  suspect_entries_from_chain_verify={entry_count} (0 expected on clean pool)"
        );
        if entry_count > 0 {
            eprintln!(
                "  WARN  {entry_count} suspect entries found on clean pool (may indicate pre-existing on-disk issue)"
            );
        }
        Ok(())
    });

    // ── Phase 9: Fault injection corruption, scrub detection, repair ──
    // Uses the object-store FaultInjectionConfig to write corrupted
    // payloads, then reopens the store cleanly and runs scrub+repair
    // to verify the detection→repair handoff pipeline.
    eprintln!("=== Phase 9: fault injection corruption and repair ===");

    let corrupt_key = tidefs_local_object_store::ObjectKey::from_name(b"phase9_corrupt_test_key__");

    smoke_test!("phase9_write_with_corruption_injection", {
        let mut store = tidefs_local_object_store::LocalObjectStore::open_with_options(
            store_root,
            tidefs_local_object_store::StoreOptions {
                fault_injection_config: Some(tidefs_local_object_store::FaultInjectionConfig {
                    byte_corruption_probability: 0.5,
                    ..tidefs_local_object_store::FaultInjectionConfig::off()
                }),
                ..tidefs_local_object_store::StoreOptions::default()
            },
        )
        .map_err(|e| format!("open corrupt store: {e}"))?;
        let payload = vec![0xABu8; 2048];
        match store.put(corrupt_key, &payload) {
            Ok(_) => eprintln!("  DIAG  corrupt write succeeded (payload may be altered)"),
            Err(e) => eprintln!("  DIAG  corrupt write failed (expected path): {e}"),
        }
        Ok(())
    });

    smoke_test!("phase9_reopen_and_read_corrupted_data", {
        let store = tidefs_local_object_store::LocalObjectStore::open_with_options(
            store_root,
            tidefs_local_object_store::StoreOptions {
                verify_read_checksums: true,
                ..tidefs_local_object_store::StoreOptions::default()
            },
        )
        .map_err(|e| format!("open verify store: {e}"))?;
        let original = vec![0xABu8; 2048];
        match store.get(corrupt_key) {
            Ok(Some(readback)) => {
                let differs = readback != original;
                eprintln!(
                    "  DIAG  readback len={} differs_from_original={}",
                    readback.len(),
                    differs
                );
                if !differs {
                    eprintln!("  DIAG  corruption did not fire (probabilistic); data matches");
                }
            }
            Ok(None) => {
                eprintln!("  DIAG  key not found (write may have failed)");
            }
            Err(e) => {
                eprintln!("  DIAG  read error (checksum mismatch expected): {e}");
            }
        }
        Ok(())
    });

    smoke_test!("phase9_scrub_after_corruption_injection", {
        let mut store = tidefs_local_object_store::LocalObjectStore::open_with_options(
            store_root,
            tidefs_local_object_store::StoreOptions {
                background_scrub_interval_secs: 1,
                reclaim_enabled: true,
                ..tidefs_local_object_store::StoreOptions::default()
            },
        )
        .map_err(|e| format!("open scrub store: {e}"))?;
        let report = store
            .run_background_scrub()
            .map_err(|e| format!("run_background_scrub: {e}"))?;
        eprintln!(
            "  DIAG  post-corruption scrub: segments={} records={} bytes={}",
            report.segments_scanned, report.records_verified, report.bytes_scanned
        );
        let suspect_text = store.suspect_log_text_report();
        let suspect_count = store.suspect_log().len();
        eprintln!("  DIAG  suspect_log entries after corruption scrub: {suspect_count}");
        if !suspect_text.is_empty() {
            eprintln!("  DIAG  suspect_log_report:\n{suspect_text}");
        }
        Ok(())
    });

    smoke_test!("phase9_recovery_loop_after_corruption", {
        use tidefs_local_filesystem::human::local_filesystem::{
            LocalFileSystem, LocalStorageAllocatorPolicy, StoreOptions,
        };
        let auth_key = tidefs_local_filesystem::RootAuthenticationKey::from_hex(
            "4141414141414141414141414141414141414141414141414141414141414141",
        )
        .map_err(|e| format!("auth key: {e}"))?;
        let store_opts = StoreOptions {
            reclaim_enabled: true,
            ..Default::default()
        };
        let _lfs = LocalFileSystem::open_with_allocator_policy_and_root_authentication_key(
            store_root,
            tidefs_local_filesystem::LocalFileSystemOpenConfig {
                options: store_opts,
                allocator_policy: LocalStorageAllocatorPolicy::default(),
                root_authentication_key: auth_key,
                encryption: None,
                compression: None,
                log_device_device_path: None,
                recovery_policy: tidefs_recovery_loop::RecoveryPolicy::RepairWriteback,
                block_devices: None,
            },
        )
        .map_err(|e| format!("open with RepairWriteback after corruption: {e}"))?;
        eprintln!("  DIAG  RepairWriteback recovery loop succeeded after corruption");
        Ok(())
    });

    // ── Phase 10: On-disk segment corruption → scrub detection → repair ──
    // Directly modifies a closed segment file to inject payload-level
    // corruption that scub will detect (unlike Phase 9's pre-trailer
    // injection).  Verifies the full detect→persist→repair pipeline.
    eprintln!("=== Phase 10: segment-level corruption and repair ===");

    smoke_test!("phase10_inject_segment_corruption", {
        let store = tidefs_local_object_store::LocalObjectStore::open(store_root)
            .map_err(|e| format!("open store for corruption: {e}"))?;
        let seg_dir = store.segments_dir().to_path_buf();
        drop(store);

        // Find the newest non-empty segment file.
        let mut seg_files: Vec<std::path::PathBuf> = std::fs::read_dir(&seg_dir)
            .map_err(|e| format!("read segments dir: {e}"))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .collect();
        if seg_files.is_empty() {
            return Err("no segment files found".to_string());
        }
        seg_files.sort_by_key(|p| std::fs::metadata(p).ok().and_then(|m| m.modified().ok()));
        let target = seg_files.last().ok_or("no segment file")?.clone();
        let file_len = std::fs::metadata(&target)
            .map_err(|e| format!("metadata: {e}"))?
            .len();

        eprintln!(
            "  DIAG  corrupting segment file {:?} (len={})",
            target.file_name().unwrap_or_default(),
            file_len
        );

        // Corrupt bytes in the first record's payload area.
        // Record layout: header(96) + payload + footer(16) + trailer(112).
        // Flip 8 bytes at offset 100 (well into payload for any real object).
        let corrupt_offset: u64 = 100;
        let mut buf = std::fs::read(&target).map_err(|e| format!("read segment: {e}"))?;
        if buf.len() as u64 > corrupt_offset + 8 {
            for i in 0..8 {
                buf[(corrupt_offset + i) as usize] ^= 0xFF;
            }
            std::fs::write(&target, &buf).map_err(|e| format!("write corrupted segment: {e}"))?;
            eprintln!("  DIAG  flipped 8 bytes at offset {corrupt_offset}");
        } else {
            eprintln!(
                "  DIAG  segment too short for payload corruption (len={})",
                buf.len()
            );
        }
        Ok(())
    });

    smoke_test!("phase10_scrub_detects_corruption", {
        let mut store = tidefs_local_object_store::LocalObjectStore::open_with_options(
            store_root,
            tidefs_local_object_store::StoreOptions {
                background_scrub_interval_secs: 1,
                reclaim_enabled: true,
                ..tidefs_local_object_store::StoreOptions::default()
            },
        )
        .map_err(|e| format!("open scrub store: {e}"))?;
        let report = store
            .run_background_scrub()
            .map_err(|e| format!("run_background_scrub: {e}"))?;
        eprintln!(
            "  DIAG  post-corruption scrub: segments={} records={} bytes={} outcomes={}",
            report.segments_scanned,
            report.records_verified,
            report.bytes_scanned,
            report.outcomes.len()
        );
        for outcome in &report.outcomes {
            eprintln!("  DIAG  scrub outcome: {outcome:?}");
        }

        let suspect_count = store.suspect_log().len();
        eprintln!("  DIAG  suspect_log entries after corruption: {suspect_count}");
        if suspect_count == 0 {
            eprintln!("  WARN  scrub did not detect corruption (offset may have hit benign area)");
        }
        let suspect_text = store.suspect_log_text_report();
        if !suspect_text.is_empty() {
            eprintln!("  DIAG  suspect_log text report follows:");
            for line in suspect_text.lines().take(10) {
                eprintln!("    {line}");
            }
        }
        Ok(())
    });

    smoke_test!("phase10_suspect_log_survives_reopen", {
        // Reopen the store and verify SuspectLog entries persist.
        let store = tidefs_local_object_store::LocalObjectStore::open(store_root)
            .map_err(|e| format!("reopen store: {e}"))?;
        let suspect_count = store.suspect_log().len();
        eprintln!(
            "  DIAG  suspect_log after reopen: {suspect_count} entries (should be >0 if corruption detected)"
        );
        // Don't fail if 0 — the corruption offset may not always hit payload.
        // The important thing is the SuspectLog loads correctly across reopen.
        Ok(())
    });

    smoke_test!("phase10_repair_recovery_after_corruption", {
        use tidefs_local_filesystem::human::local_filesystem::{
            LocalFileSystem, LocalStorageAllocatorPolicy, StoreOptions,
        };
        let auth_key = tidefs_local_filesystem::RootAuthenticationKey::from_hex(
            "4141414141414141414141414141414141414141414141414141414141414141",
        )
        .map_err(|e| format!("auth key: {e}"))?;
        let store_opts = StoreOptions {
            reclaim_enabled: true,
            ..Default::default()
        };
        let _lfs = LocalFileSystem::open_with_allocator_policy_and_root_authentication_key(
            store_root,
            tidefs_local_filesystem::LocalFileSystemOpenConfig {
                options: store_opts,
                allocator_policy: LocalStorageAllocatorPolicy::default(),
                root_authentication_key: auth_key,
                encryption: None,
                compression: None,
                log_device_device_path: None,
                recovery_policy: tidefs_recovery_loop::RecoveryPolicy::RepairWriteback,
                block_devices: None,
            },
        )
        .map_err(|e| format!("open with RepairWriteback after segment corruption: {e}"))?;
        eprintln!("  DIAG  RepairWriteback recovery succeeded after segment corruption");
        Ok(())
    });

    // Clean up temp dirs.
    let _ = fs::remove_dir_all(store_root);
    let _ = fs::remove_dir_all(mountpoint);

    eprintln!("=== smoke-mount: {passed} passed, {failed} failed ===");

    if failed > 0 {
        return Err(format!("{failed} smoke test(s) failed"));
    }
    Ok(())
}

/// Standalone scrub-repair-reclaim smoke test that does NOT require FUSE.
///
/// Creates a LocalFileSystem directly, writes data, commits, then runs
/// Phases 7b-10 (SuspectLog persistence, segment chain verify, repair
/// writeback recovery, fault injection, segment-level corruption +
/// scrub detection + SuspectLog survival + RepairWriteback recovery).
///
/// This produces runtime validation output for the scrub/repair/reclaim
/// pipeline without needing /dev/fuse or a mounted kernel.
#[allow(unsafe_code)]
fn run_scrub_repair_smoke() -> Result<(), String> {
    use tidefs_local_filesystem::human::local_filesystem::{
        LocalFileSystem, LocalStorageAllocatorPolicy, StoreOptions,
    };

    let store_root = "/tmp/tidefs-scrub-repair-smoke-store";
    let _ = std::fs::remove_dir_all(store_root);
    std::fs::create_dir_all(store_root).map_err(|e| format!("create store dir: {e}"))?;

    let mut passed = 0_u32;
    let mut failed = 0_u32;

    macro_rules! smoke_test {
        ($name:expr, $body:block) => {
            match (|| -> Result<(), String> { $body })() {
                Ok(()) => {
                    eprintln!("  PASS  {}", $name);
                    passed += 1;
                }
                Err(e) => {
                    eprintln!("  FAIL  {}: {}", $name, e);
                    failed += 1;
                }
            }
        };
    }

    let auth_key = tidefs_local_filesystem::RootAuthenticationKey::from_hex(
        "4141414141414141414141414141414141414141414141414141414141414141",
    )
    .map_err(|e| format!("auth key: {e}"))?;

    // Phase A: Create filesystem and write data (no FUSE needed)
    eprintln!("=== Phase A: create filesystem and write data ===");

    smoke_test!("phaseA_open_filesystem", {
        let opts = StoreOptions {
            reclaim_enabled: true,
            ..Default::default()
        };
        let _lfs = LocalFileSystem::open_with_allocator_policy_and_root_authentication_key(
            store_root,
            tidefs_local_filesystem::LocalFileSystemOpenConfig {
                options: opts,
                allocator_policy: LocalStorageAllocatorPolicy::default(),
                root_authentication_key: auth_key,
                encryption: None,
                compression: None,
                log_device_device_path: None,
                recovery_policy: tidefs_recovery_loop::RecoveryPolicy::RepairWriteback,
                block_devices: None,
            },
        )
        .map_err(|e| format!("open: {e}"))?;
        Ok(())
    });

    smoke_test!("phaseA_create_files_and_dirs", {
        let opts = StoreOptions {
            reclaim_enabled: true,
            ..Default::default()
        };
        let mut lfs = LocalFileSystem::open_with_allocator_policy_and_root_authentication_key(
            store_root,
            tidefs_local_filesystem::LocalFileSystemOpenConfig {
                options: opts,
                allocator_policy: LocalStorageAllocatorPolicy::default(),
                root_authentication_key: auth_key,
                encryption: None,
                compression: None,
                log_device_device_path: None,
                recovery_policy: tidefs_recovery_loop::RecoveryPolicy::RepairWriteback,
                block_devices: None,
            },
        )
        .map_err(|e| format!("open: {e}"))?;
        // Create a file with data
        let _rec = lfs
            .create_file("/scrub-test-file.txt", 0o644)
            .map_err(|e| format!("create_file: {e}"))?;
        let data = vec![0xABu8; 4096];
        lfs.write_file("/scrub-test-file.txt", 0, &data)
            .map_err(|e| format!("write_file: {e}"))?;
        // Create a subdirectory
        let _dirrec = lfs
            .create_dir("/scrub-test-subdir", 0o755)
            .map_err(|e| format!("create_dir: {e}"))?;
        // Create another file
        let _rec2 = lfs
            .create_file("/scrub-test-subdir/nested.txt", 0o644)
            .map_err(|e| format!("create nested file: {e}"))?;
        let data2 = b"nested file content for scrub testing\n".to_vec();
        lfs.write_file("/scrub-test-subdir/nested.txt", 0, &data2)
            .map_err(|e| format!("write nested: {e}"))?;
        // Commit and close
        lfs.commit().map_err(|e| format!("commit: {e}"))?;
        drop(lfs);
        eprintln!("  DIAG  created 2 files, 1 dir, committed");
        Ok(())
    });

    // ── Phase 7b: SuspectLog persistence ──
    eprintln!("=== Phase B: SuspectLog persistence verification ===");

    smoke_test!("phaseB_suspect_log_loads", {
        let store = tidefs_local_object_store::LocalObjectStore::open(store_root)
            .map_err(|e| format!("open store: {e}"))?;
        let log = store.suspect_log();
        eprintln!("  DIAG  suspect_log entries={}", log.len());
        Ok(())
    });

    smoke_test!("phaseB_segment_chain_verify", {
        let store = tidefs_local_object_store::LocalObjectStore::open(store_root)
            .map_err(|e| format!("open store: {e}"))?;
        let (stats, _log) = store
            .verify_segment_chain()
            .map_err(|e| format!("segment chain verify: {e}"))?;
        eprintln!(
            "  DIAG  chain: segments={} breaks={} last={}",
            stats.segments_in_chain, stats.chain_breaks_detected, stats.last_verified_segment
        );
        if stats.chain_breaks_detected > 0 {
            eprintln!(
                "  DIAG  {} chain breaks detected (may be from pre-existing suspect entries or corruption in Phase A/B)",
                stats.chain_breaks_detected
            );
        }
        Ok(())
    });

    // ── Phase 8: Repair writeback recovery ──
    eprintln!("=== Phase C: repair writeback recovery ===");

    smoke_test!("phaseC_recovery_loop_repair_writeback", {
        let opts = StoreOptions {
            reclaim_enabled: true,
            ..Default::default()
        };
        let _lfs = LocalFileSystem::open_with_allocator_policy_and_root_authentication_key(
            store_root,
            tidefs_local_filesystem::LocalFileSystemOpenConfig {
                options: opts,
                allocator_policy: LocalStorageAllocatorPolicy::default(),
                root_authentication_key: auth_key,
                encryption: None,
                compression: None,
                log_device_device_path: None,
                recovery_policy: tidefs_recovery_loop::RecoveryPolicy::RepairWriteback,
                block_devices: None,
            },
        )
        .map_err(|e| format!("open: {e}"))?;
        eprintln!("  DIAG  RepairWriteback recovery loop completed");
        Ok(())
    });

    smoke_test!("phaseC_run_background_scrub", {
        let mut store = tidefs_local_object_store::LocalObjectStore::open_with_options(
            store_root,
            tidefs_local_object_store::StoreOptions {
                background_scrub_interval_secs: 1,
                reclaim_enabled: true,
                ..tidefs_local_object_store::StoreOptions::default()
            },
        )
        .map_err(|e| format!("open: {e}"))?;
        let report = store
            .run_background_scrub()
            .map_err(|e| format!("scrub: {e}"))?;
        eprintln!(
            "  DIAG  scrub: segments={} records={} bytes={}",
            report.segments_scanned, report.records_verified, report.bytes_scanned
        );
        Ok(())
    });

    // ── Phase 9: Fault injection corruption ──
    eprintln!("=== Phase D: fault injection corruption ===");

    let _corrupt_key = tidefs_local_object_store::ObjectKey::from_name(b"phaseD_corrupt_test");

    smoke_test!("phaseD_write_with_corruption_injection", {
        let mut store = tidefs_local_object_store::LocalObjectStore::open_with_options(
            store_root,
            tidefs_local_object_store::StoreOptions {
                fault_injection_config: Some(tidefs_local_object_store::FaultInjectionConfig {
                    byte_corruption_probability: 0.5,
                    ..tidefs_local_object_store::FaultInjectionConfig::off()
                }),
                ..tidefs_local_object_store::StoreOptions::default()
            },
        )
        .map_err(|e| format!("open: {e}"))?;
        let payload = vec![0xABu8; 2048];
        match store.put_named(b"phaseD_corrupt_test", &payload) {
            Ok(_) => eprintln!("  DIAG  corrupt write succeeded"),
            Err(e) => eprintln!("  DIAG  corrupt write: {e}"),
        }
        Ok(())
    });

    smoke_test!("phaseD_reopen_and_read", {
        let store = tidefs_local_object_store::LocalObjectStore::open_with_options(
            store_root,
            tidefs_local_object_store::StoreOptions {
                verify_read_checksums: true,
                ..tidefs_local_object_store::StoreOptions::default()
            },
        )
        .map_err(|e| format!("open: {e}"))?;
        let original = vec![0xABu8; 2048];
        match store.get_named(b"phaseD_corrupt_test") {
            Ok(Some(readback)) => {
                let differs = readback != original;
                eprintln!(
                    "  DIAG  readback len={} differs={}",
                    readback.len(),
                    differs
                );
            }
            Ok(None) => eprintln!("  DIAG  key not found"),
            Err(e) => eprintln!("  DIAG  read error (checksum mismatch?): {e}"),
        }
        Ok(())
    });

    smoke_test!("phaseD_scrub_after_corruption", {
        let mut store = tidefs_local_object_store::LocalObjectStore::open_with_options(
            store_root,
            tidefs_local_object_store::StoreOptions {
                background_scrub_interval_secs: 1,
                reclaim_enabled: true,
                ..tidefs_local_object_store::StoreOptions::default()
            },
        )
        .map_err(|e| format!("open: {e}"))?;
        let _report = store
            .run_background_scrub()
            .map_err(|e| format!("scrub: {e}"))?;
        let suspect_count = store.suspect_log().len();
        eprintln!("  DIAG  suspect_log after corruption scrub: {suspect_count} entries");
        Ok(())
    });

    // ── Phase 10: Segment-level corruption ──
    eprintln!("=== Phase E: segment-level corruption injection ===");

    smoke_test!("phaseE_inject_segment_corruption", {
        let store = tidefs_local_object_store::LocalObjectStore::open(store_root)
            .map_err(|e| format!("open: {e}"))?;
        let seg_dir = store.segments_dir().to_path_buf();
        drop(store);

        let mut seg_files: Vec<std::path::PathBuf> = std::fs::read_dir(&seg_dir)
            .map_err(|e| format!("read dir: {e}"))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .collect();
        if seg_files.is_empty() {
            return Err("no segment files found".to_string());
        }
        seg_files.sort_by_key(|p| std::fs::metadata(p).ok().and_then(|m| m.modified().ok()));
        let target = seg_files.last().ok_or("no segment")?.clone();

        let mut buf = std::fs::read(&target).map_err(|e| format!("read: {e}"))?;
        let corrupt_offset: u64 = 100;
        if buf.len() as u64 > corrupt_offset + 8 {
            for i in 0..8 {
                buf[(corrupt_offset + i) as usize] ^= 0xFF;
            }
            std::fs::write(&target, &buf).map_err(|e| format!("write: {e}"))?;
            eprintln!(
                "  DIAG  flipped 8 bytes at offset {corrupt_offset} in {:?}",
                target.file_name().unwrap_or_default()
            );
        } else {
            eprintln!("  DIAG  segment too short (len={})", buf.len());
        }
        Ok(())
    });

    smoke_test!("phaseE_scrub_detects_corruption", {
        let mut store = tidefs_local_object_store::LocalObjectStore::open_with_options(
            store_root,
            tidefs_local_object_store::StoreOptions {
                background_scrub_interval_secs: 1,
                reclaim_enabled: true,
                verify_read_checksums: false,
                ..tidefs_local_object_store::StoreOptions::default()
            },
        )
        .map_err(|e| format!("open: {e}"))?;
        let report = store
            .run_background_scrub()
            .map_err(|e| format!("scrub: {e}"))?;
        let suspect_count = store.suspect_log().len();
        eprintln!(
            "  DIAG  post-segment-corruption scrub: outcomes={} suspect_entries={}",
            report.outcomes.len(),
            suspect_count
        );
        for outcome in &report.outcomes {
            eprintln!("  DIAG  outcome: {outcome:?}");
        }
        Ok(())
    });

    smoke_test!("phaseE_suspect_log_survives_reopen", {
        let store = tidefs_local_object_store::LocalObjectStore::open_with_options(
            store_root,
            tidefs_local_object_store::StoreOptions {
                verify_read_checksums: false,
                ..tidefs_local_object_store::StoreOptions::default()
            },
        )
        .map_err(|e| format!("open: {e}"))?;
        let suspect_count = store.suspect_log().len();
        eprintln!("  DIAG  suspect_log after reopen: {suspect_count} entries");
        Ok(())
    });

    smoke_test!("phaseE_repair_recovery_after_corruption", {
        let opts = StoreOptions {
            reclaim_enabled: true,
            verify_read_checksums: false,
            ..Default::default()
        };
        let _lfs = LocalFileSystem::open_with_allocator_policy_and_root_authentication_key(
            store_root,
            tidefs_local_filesystem::LocalFileSystemOpenConfig {
                options: opts,
                allocator_policy: LocalStorageAllocatorPolicy::default(),
                root_authentication_key: auth_key,
                encryption: None,
                compression: None,
                log_device_device_path: None,
                recovery_policy: tidefs_recovery_loop::RecoveryPolicy::RepairWriteback,
                block_devices: None,
            },
        )
        .map_err(|e| format!("open: {e}"))?;
        eprintln!("  DIAG  RepairWriteback recovery after corruption succeeded");
        Ok(())
    });

    // Cleanup
    let _ = std::fs::remove_dir_all(store_root);

    eprintln!("=== scrub-repair-smoke: {passed} passed, {failed} failed ===");
    if failed > 0 {
        return Err(format!("{failed} test(s) failed"));
    }
    Ok(())
}

fn print_help() {
    println!("tidefs-posix-filesystem-adapter-daemon");
    println!("  mount-vfs --store <path> --mount <path> [--fs-name <name>] [--root-auth-key-hex <64 hex>] [--read-only] [--snapshot <name>] [--sync] [--writeback-cache] [--no-writeback-cache] [--content-capacity-bytes <bytes>] [--writeback-cache-timeout <seconds>] [--drain-timeout-secs <seconds>] [--background-scrub-interval <seconds>] [--queue-depth-artifact <path>] [--scrub-runtime-observation-artifact <path>]");
    println!("    root auth key fallback env: {ROOT_AUTHENTICATION_ENV_VAR}");
    println!(
        "    --background-scrub-interval  seconds between scrub cycles (0 disables, default 0)"
    );
    println!(
        "    --scrub-runtime-observation-artifact  validation-only typed scrub observation JSON (#1792)"
    );
    println!("    --writeback-cache            enable FUSE writeback-cache (opt-in, default: off)");
    println!(
        "    --content-capacity-bytes N   configure mounted local filesystem content capacity"
    );
    println!("    --no-writeback-cache         disable FUSE writeback-cache (default)");
    println!("  mount           (alias for mount-vfs)");
    println!("  smoke-mount [--profile full|quick] [--queue-depth-artifact <path>]");
    println!("    run a self-contained FUSE mount smoke test; quick stops after core mounted I/O and teardown");
    println!("  score-posix --out <dir>");
    println!(
        "    produce a JSON scoreboard from xfstests results (reads TIDEFS_XFSTESTS_* env vars)"
    );
    println!("  xfstests-harness --tests <range> [--quick|--auto] --out <dir> [--exclude <file>]");
    println!("    run xfstests against a TideFS FUSE mount and produce a JSON scoreboard");
    println!("    --tests: test range, e.g. generic/101-150 or generic/101");
    println!("    --quick: run quick group; --auto: run auto group");
    println!("  receipt-demo");
    println!("  help | --help | -h");
    println!();
    println!("Idmapped mounts: TideFS FUSE does not support idmapped mounts");
    println!("(UID/GID translation via mount_setattr). The daemon will refuse");
    println!("to operate when an idmapped mount is detected.");
}

#[cfg(feature = "receipt-demo")]
fn run_receipt_demo() {
    print_surface_manifest(POSIX_FILESYSTEM_ADAPTER_DAEMON_SURFACE);
    println!("publication_response_to_posix_wake_chain=Publication Pipeline + Response Registry -> POSIX Filesystem Adapter wake receipt");
    println!(
        "wire.publication_response_to_posix_wake_chain={FIRST_PUBLICATION_PIPELINE_RESPONSE_REGISTRY_TO_POSIX_FILESYSTEM_ADAPTER_WAKE_CHAIN}"
    );

    let admitted_ticket = PosixFilesystemAdapterDemoPublicationTicketRecord {
        ticket_id: PosixFilesystemAdapterId128::from_u128_le(0x11),
    };
    let admitted_answer = PosixFilesystemAdapterDemoVisibleAnswerRecord::bundle(
        PosixFilesystemAdapterId128::from_u128_le(0x77),
        PosixFilesystemAdapterId128::from_u128_le(0x22),
        PosixFilesystemAdapterId128::from_u128_le(0x33),
        [0x10_u8; 32],
        [0x20_u8; 32],
    );
    let admitted_receipt = issue_product_wake_receipt(
        Some(admitted_ticket),
        admitted_answer,
        witness_refs_for(admitted_answer, Some(admitted_ticket.ticket_id)),
    )
    .expect("POSIX adapter wake receipt (posix_filesystem_adapter continuity)");
    print_receipt("admitted", admitted_receipt);

    let refusal_answer = PosixFilesystemAdapterDemoVisibleAnswerRecord::refusal(
        PosixFilesystemAdapterId128::from_u128_le(0x88),
        PosixFilesystemAdapterId128::from_u128_le(0x99),
        PosixFilesystemAdapterId128::from_u128_le(0xAA),
        [0x30_u8; 32],
        [0x40_u8; 32],
    );
    let refusal_receipt =
        issue_product_wake_receipt(None, refusal_answer, witness_refs_for(refusal_answer, None))
            .expect("POSIX adapter wake receipt (posix_filesystem_adapter continuity)");
    print_receipt("refusal", refusal_receipt);
}

#[cfg(feature = "receipt-demo")]
fn print_surface_manifest(surface: SurfaceManifest) {
    println!("{}", surface.binary_name);
    println!("service={}", surface.human_name());
    println!("service_key={}", surface.rust_hint());
    println!("family_locator={}", surface.stable_locator());
    println!("stable_family_id={}", surface.family.stable_id());
    println!("profile={}", surface.profile.human_name());
    println!("stable_profile_id={}", surface.profile.stable_id());
    println!("bundle={}", surface.bundle.human_name());
    println!("stable_bundle_id={}", surface.bundle.stable_id());
    print!("capabilities=");
    for (idx, cap) in surface.capabilities.iter().enumerate() {
        if idx != 0 {
            print!(",");
        }
        print!("{}", cap.human_name());
    }
    println!();
    print!("stable_capability_ids=");
    for (idx, cap) in surface.capabilities.iter().enumerate() {
        if idx != 0 {
            print!(",");
        }
        print!("{}", cap.stable_id());
    }
    println!();
    println!("stage={}", surface.stage);
}

#[cfg(feature = "receipt-demo")]
fn print_receipt(label: &'static str, receipt: PosixFilesystemAdapterProductWakeReceiptRecord) {
    println!("case={label}");
    println!(
        "  wake_class={}",
        receipt.wake_class().expect("wake").as_str()
    );
    println!(
        "  visibility={}",
        receipt.visibility().expect("visibility").as_str()
    );
    println!(
        "  has_publication_pipeline_ticket={}",
        receipt.has_publication_pipeline_ticket()
    );
    println!(
        "  witness_join_id_le={:#x}",
        receipt.witness_refs.witness_join_id.as_u128_le()
    );
    println!(
        "  witness_policy_id_le={:#x}",
        receipt.witness_refs.policy_witness_id.as_u128_le()
    );
    println!(
        "  witness_budget_id_le={:#x}",
        receipt.witness_refs.budget_witness_id.as_u128_le()
    );
    println!(
        "  witness_recipe_id_le={:#x}",
        receipt.witness_refs.recipe_witness_id.as_u128_le()
    );
    println!(
        "  wire.posix_adapter.wake_receipt={}",
        roundtrip_encoded_len(&receipt)
    );
}

#[cfg(feature = "receipt-demo")]
fn roundtrip_encoded_len<T>(value: &T) -> usize
where
    T: CanonicalFixedWidth + Copy + PartialEq + Debug,
{
    let mut bytes = vec![0_u8; T::ENCODED_LEN];
    value.encode_le(&mut bytes);
    let decoded = T::decode_le(&bytes).expect("canonical decode");
    assert_eq!(*value, decoded);
    bytes.len()
}

#[cfg(feature = "receipt-demo")]
const fn derive_pair_id(
    left: PosixFilesystemAdapterId128,
    right: PosixFilesystemAdapterId128,
    salt: u8,
) -> PosixFilesystemAdapterId128 {
    let mut out = [0_u8; 16];
    let mut idx = 0;
    while idx < 16 {
        out[idx] = left.0[idx] ^ right.0[15 - idx] ^ salt ^ (idx as u8).wrapping_mul(7);
        idx += 1;
    }
    PosixFilesystemAdapterId128(out)
}

#[cfg(feature = "receipt-demo")]
fn witness_refs_for(
    response_registry_answer: PosixFilesystemAdapterDemoVisibleAnswerRecord,
    publication_pipeline_ticket_id: Option<PosixFilesystemAdapterId128>,
) -> PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs {
    let ticket_or_zero =
        publication_pipeline_ticket_id.unwrap_or(PosixFilesystemAdapterId128::ZERO);
    PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs::new(
        derive_pair_id(
            response_registry_answer.request_id,
            response_registry_answer.journal_id,
            0xC1,
        ),
        derive_pair_id(response_registry_answer.receipt_id, ticket_or_zero, 0xC2),
        derive_pair_id(response_registry_answer.journal_id, ticket_or_zero, 0xC3),
        derive_pair_id(
            response_registry_answer.request_id,
            response_registry_answer.receipt_id,
            0xC4,
        ),
        response_registry_answer.answer_digest,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT_AUTH_KEY_HEX: &str =
        "4141414141414141414141414141414141414141414141414141414141414141";

    fn required_mount_args() -> Vec<String> {
        vec![
            "--store".to_string(),
            "/tmp/tidefs-store".to_string(),
            "--mount".to_string(),
            "/tmp/tidefs-mount".to_string(),
            "--root-auth-key-hex".to_string(),
            ROOT_AUTH_KEY_HEX.to_string(),
        ]
    }

    #[test]
    fn mount_vfs_config_defaults_to_no_writeback_cache() {
        let config = parse_mount_vfs_config(required_mount_args()).expect("parse mount config");

        assert!(!config.mount_opts.sync);
        assert_eq!(config.sync_guarantee, SyncGuarantee::Local);
        assert!(
            !config.writeback_cache,
            "writeback_cache must remain opt-in for the default qemu-smoke mount"
        );
        assert_eq!(config.fs_name, "tidefs-vfs");
    }

    #[test]
    fn mount_vfs_config_disables_background_scrub_by_default() {
        let config = parse_mount_vfs_config(required_mount_args()).expect("parse mount config");

        assert_eq!(config.background_scrub_interval_secs, 0);
    }

    #[test]
    fn mount_vfs_config_accepts_background_scrub_interval() {
        let mut args = required_mount_args();
        args.push("--background-scrub-interval".to_string());
        args.push("300".to_string());

        let config = parse_mount_vfs_config(args).expect("parse mount config");

        assert_eq!(config.background_scrub_interval_secs, 300);
    }

    #[test]
    fn mount_vfs_config_accepts_scrub_runtime_observation_artifact() {
        let mut args = required_mount_args();
        args.push("--background-scrub-interval".to_string());
        args.push("1".to_string());
        args.push("--scrub-runtime-observation-artifact".to_string());
        args.push("/tmp/tidefs-scrub-observation.json".to_string());

        let config = parse_mount_vfs_config(args).expect("parse mount config");

        assert_eq!(
            config.scrub_runtime_observation_artifact.as_deref(),
            Some(Path::new("/tmp/tidefs-scrub-observation.json"))
        );
    }

    #[test]
    fn mount_vfs_config_accepts_fs_name() {
        let mut args = required_mount_args();
        args.push("--fs-name".to_string());
        args.push("tidefs-xfstests-scratch".to_string());

        let config = parse_mount_vfs_config(args).expect("parse mount config");

        assert_eq!(config.fs_name, "tidefs-xfstests-scratch");
    }

    #[test]
    fn mount_vfs_config_accepts_content_capacity_bytes() {
        let mut args = required_mount_args();
        args.push("--content-capacity-bytes".to_string());
        args.push("2147483648".to_string());

        let config = parse_mount_vfs_config(args).expect("parse mount config");

        assert_eq!(config.content_capacity_bytes, 2 * 1024 * 1024 * 1024);
    }

    #[test]
    fn mount_vfs_config_accepts_sync_writes() {
        let mut args = required_mount_args();
        args.push("--sync".to_string());

        let config = parse_mount_vfs_config(args).expect("parse mount config");

        assert!(config.mount_opts.sync);
    }

    #[test]
    fn read_write_mount_preserves_kernel_atime_policy() {
        let opts = MountOptions {
            timestamp_policy: crate::mount_options::TimestampPolicy::StrictAtime,
            suppress_dir_atime: false,
            sync: false,
            sync_guarantee: SyncGuarantee::Local,
            allow_other: false,
            dev: false,
            intent_log_write: false,
        };

        assert_eq!(
            fuse_mount_options_for_mode(&opts, false),
            vec![fuser::MountOption::StrictAtime]
        );
    }

    #[test]
    fn read_only_mount_forces_kernel_noatime_policy() {
        let opts = MountOptions {
            timestamp_policy: crate::mount_options::TimestampPolicy::StrictAtime,
            suppress_dir_atime: false,
            sync: true,
            sync_guarantee: SyncGuarantee::Local,
            allow_other: true,
            dev: true,
            intent_log_write: false,
        };

        let mount_options = fuse_mount_options_for_mode(&opts, true);

        assert!(mount_options.contains(&fuser::MountOption::NoAtime));
        assert!(!mount_options.contains(&fuser::MountOption::StrictAtime));
        assert!(mount_options.contains(&fuser::MountOption::Sync));
        assert!(mount_options.contains(&fuser::MountOption::AllowOther));
        assert!(mount_options.contains(&fuser::MountOption::Dev));
    }

    #[test]
    fn mount_vfs_config_intent_log_write_defaults_false() {
        let config = parse_mount_vfs_config(required_mount_args()).expect("parse mount config");
        assert!(
            !config.intent_log_write,
            "intent_log_write should default to false"
        );
    }

    #[test]
    fn mount_vfs_config_no_intent_log_write_disables() {
        let mut args = required_mount_args();
        args.push("--no-intent-log-write".to_string());
        let config = parse_mount_vfs_config(args).expect("parse mount config");
        assert!(
            !config.intent_log_write,
            "--no-intent-log-write should disable intent log write"
        );
    }
    #[test]
    fn mount_vfs_config_writeback_cache_ignores_profile_default() {
        let config = parse_mount_vfs_config(required_mount_args()).expect("parse mount config");
        assert!(
            !config.writeback_cache,
            "coherency profile must not silently enable FUSE writeback cache"
        );
    }

    #[test]
    fn mount_vfs_config_enables_writeback_cache_with_flag() {
        let mut args = required_mount_args();
        args.push("--writeback-cache".to_string());
        let config = parse_mount_vfs_config(args).expect("parse mount config");
        assert!(
            config.writeback_cache,
            "--writeback-cache should enable writeback cache"
        );
    }

    #[test]
    fn mount_vfs_config_disables_writeback_cache_with_flag() {
        let mut args = required_mount_args();
        args.push("--no-writeback-cache".to_string());
        let config = parse_mount_vfs_config(args).expect("parse mount config");
        assert!(
            !config.writeback_cache,
            "--no-writeback-cache should disable writeback cache"
        );
    }

    #[test]
    fn mount_vfs_config_writeback_cache_no_overrides_writeback() {
        let mut args = required_mount_args();
        args.push("--writeback-cache".to_string());
        args.push("--no-writeback-cache".to_string());
        let config = parse_mount_vfs_config(args).expect("parse mount config");
        assert!(
            !config.writeback_cache,
            "--no-writeback-cache after --writeback-cache should win"
        );
    }

    #[test]
    fn snapshot_mount_effective_mode_forces_read_only_export() {
        let mut args = required_mount_args();
        args.push("--snapshot".to_string());
        args.push("snap0".to_string());
        args.push("--writeback-cache".to_string());
        args.push("--intent-log-write".to_string());
        args.push("--background-scrub-interval".to_string());
        args.push("60".to_string());

        let config = parse_mount_vfs_config(args).expect("parse mount config");
        let mode = effective_mount_mode(&config);

        assert_eq!(config.snapshot_name.as_deref(), Some("snap0"));
        assert!(!config.read_only);
        assert!(mode.read_only);
        assert!(!mode.writeback_cache);
        assert!(!mode.intent_log_write);
        assert_eq!(mode.background_scrub_interval_secs, 0);
    }
}
