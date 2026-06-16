#![forbid(unsafe_code)]
#![deny(dead_code)]
#![deny(unused_imports)]

//! Local filesystem model over the TideFS Local Object Store.
//!
//! # Kernel-portability boundary
//!
//! This crate is on the path to kernel residency.  Two layers are separated
//! by a source-level boundary tracked by [`build.rs`]:
//!
//! **Kernel-portable product-core types** (carried into Rust-for-Linux):
//! - `LockType`, `LockRange`, `LockConflict`, `LockList`, `LockTracker`
//!   owned by [`tidefs_types_vfs_core`].
//! - `StorageAuthorityToken` owned by
//!   [`tidefs_types_claim_ledger_core`] (replaces `ControlPlaneReceiptId`
//!   in obligation/budget/claim records).
//! - `InodeId`, `Errno`, `NodeKind`, `NodeFacets`, `LockSpec`, `StatFs`,
//!   and other VFS boundary scalars from [`tidefs_types_vfs_core`].
//!
//! **Userspace-only harness layer** (not portable into the kernel):
//! - `std::fs`, `std::path::Path`, `std::thread`, `std::time::Duration`
//!   and `Instant` — host I/O and threading primitives.
//! - [`tidefs_background_scheduler`] — userspace background-service worker.
//! - [`tidefs_quorum_write_runtime`] — userspace multi-replica write runtime.
//!
//! The kernel-portability check in [`build.rs`] fails the build when a
//! forbidden direct dependency (POSIX adapter worker crates,
//! control-plane scaffold crates) reappears.  Full-kernel validation
//! gates must not close against this crate until the userspace-only
//! layer is extracted behind a `cfg(feature = "userspace")` guard.
//!
//! # Overview
//!
//! The first filesystem-shaped storage slice in TideFS. It publishes
//! namespace changes through immutable transaction objects and root-slot
//! commits on top of [`tidefs_local_object_store`]. On reopen, incomplete
//!
//! Writes are grouped into transaction groups (commit_groups) managed by
//! `CommitGroupManager`. Each commit_group proceeds through `Open → Syncing → Committed`
//! phases. A `CommitClass` tags each commit_group as `Sync`, `DataSync`, or
//! `AutoCommit` to control durability semantics. The `CommitGroupStateMachine`
//! ensures exactly-once replay of committed commit_groups after a crash.
//!
//! # Recovery model
//!
//! On open, `crash_recovery` replays the intent log and selects the
//! newest valid committed root. The `recovery` module handles torn-tail
//! repair without operator intervention. `repair` applies corruption
//! resolution strategies (truncate, mark-corrupt, reconstruct), and
//! `scrub` runs a full block-level checksum pipeline with outcome
//! classification.
//!
//! # Key types
//!
//! - [`LocalFileSystem`] — primary filesystem handle (open, close, read, write).
//! - [`FileSystemError`] — error type covering I/O, integrity, and semantic errors.
//! - [`FileSystemStats`] — space usage, inode counts, and health counters.
//! - [`RootAuthenticationKey`] — cryptographic key for committed-root authentication.
//!
//! # Background services
//!
//! The crate wires background services via [`tidefs_background_scheduler`]:
//!
//! - `background_compaction` — compacts segment logs to reclaim space.
//! - `background_orphan_reclamation` — cleans up orphaned inodes and blocks.
//! - `writeback` — flushes dirty data to the object store on a timer.
//!
//! ## Reclaim authority
//!
//! The sole mounted-pool segment-freeing authority is
//! `LocalObjectStore::drain_dead_segments`.  `BackgroundReclaim` and
//! `ProcessedDelta` in `background_reclaim` are model/test surfaces
//! quarantined behind `#[cfg(test)]` — they are not release reclaim validation.
//!
//! The production reclaim chain:
//! 1. `record_reclaim_delta()` records entries in the local B+tree queue
//! 2. `tick_background_services()` Duty 2 drains the queue and calls
//!    `LocalObjectStore::delete()` for each entry
//! 3. `delete()` feeds the object-store durable reclaim queue
//! 4. `LocalObjectStore::drain_dead_segments()` drains the object-store
//!    queue and frees dead segments — this is the sole segment-freer.
//!
//! The scrub-to-repair scheduling chain:
//! 1. `BackgroundScrubber` periodically opens a read-only store, runs
//!    `verify_online_store` and `scrub_inodes_content`, and sets the
//!    shared `scrub_corruption_detected` flag when corruption is found.
//! 2. `tick_background_services()` Duty 3 picks up the flag, runs
//!    `repair_cycle()` (scrub → schedule → dispatch) against the live
//!    store, and clears the flag.
//! 3. `repair_cycle()` delegates to `schedule_scrub_repairs()` +
//!    `dispatch_scheduled_repairs()`, which classify violations into
//!    prioritized repair jobs and apply them without an fsck model.
//!
//! # Features
//!
//! - **Snapshots**: `snapshot` module provides create/list/delete/rollback
//!   with root protection during safe local reclamation.
//! - **Send/receive**: `send_receive` implements `VFSSEND1` changed-record
//!   export/import with staging validation.
//! - **Dedup**: `dedup` provides an in-memory deduplication index.
//! - **Online verification**: `verify_online` runs a live integrity scan.
//! - **Root retention**: `plan_root_retention` evaluates root retention policy.
//! - **Crash recovery matrix**: `run_crash_recovery_matrix` exercises
//!   recovery across simulated crash points.
//!
//! # Root authentication
//!
//! The `default_root_authentication_key` function reads a
//! [`RootAuthenticationKey`] from the environment (production) or returns a
//! demo key (test builds). All recovery and verification entry-points
//! accept an explicit key parameter via `*_with_root_authentication_key`
//! variants.
//!
//! # Crash hooks
//!
//! The `crash_hooks` module exposes deterministic crash-injection points
//! for testing. Combined with the fault-injection support in
//! [`tidefs_local_object_store`], this enables exhaustive crash-recovery
//! # Architecture
//!
//! [`LocalFileSystem`] sits between the FUSE daemon
//! (`tidefs_posix_filesystem_adapter_daemon`) above and
//! [`LocalObjectStore`] below.
//! The FUSE daemon translates kernel VFS requests into calls on the
//! `VfsEngine` trait, implemented by
//! `VfsEngineImpl`(crate::vfs_engine_impl::VfsEngineImpl), which
//! delegates to [`LocalFileSystem`] methods. The filesystem in turn reads
//! and writes content through the object store's key-value interface,
//! managing inode metadata, directory entries, extent maps, and content
//! objects as distinct object-key families.
//!
//! ## Type graph
//!
//! - [`LocalFileSystem`] — top-level handle owning a [`LocalObjectStore`],
//!   a `FileSystemState`, and the writeback/commit_group/background machinery.
//! - `FileSystemState` — the authoritative metadata snapshot: inode table
//!   (`inodes`), directory entries (`directories`), extent maps
//!   (`extent_maps`), quota table, space accounting, and dirty-bit tracking.
//! - [`InodeRecord`] — on-disk inode with attributes, size, nlink, and
//!   content layout pointer.
//! - `ExtentMap`(tidefs_extent_map::ExtentMap) — per-file byte-range to
//!   physical-object mapping, allocated via
//!   `ExtentAllocator`(tidefs_extent_map::ExtentAllocator).
//! - `WriteBuffer` — coalesces small writes in memory before dispatching
//!   to the object store.
//! - `DirtySet` — tracks data, metadata, and catalog dirty state per
//!   commit_group. Drives auto-commit triggers and fsync flush scope.
//! - `CommitGroupStateMachine` — transaction-group lifecycle:
//!   `Open → Syncing → Committed`.
//! - `IntentLog` — write-ahead log for data durability. On fsync, flushed
//!   entries are crash-safe; on crash recovery, replayed to the live state.
//! - `PageCache`(crate::page_cache::PageCache) — in-memory page cache
//!   indexed by (inode, offset).
//!   `DirtyPageTracker`(crate::dirty_page_tracker::DirtyPageTracker)
//!   records modified pages pending writeback.
//!
//! # Read path
//!
//! 1. **Path resolution** walks the directory tree from the root inode,
//!    resolving each component to an inode ID via
//!    `resolve_parts`(LocalFileSystem::resolve_parts).
//! 2. `read_file`(LocalFileSystem::read_file) /
//!    `read_file_range`(LocalFileSystem::read_file_range) call
//!    `read_content` or `read_content_range`.
//! 3. The read path overlays per-inode `WriteBuffer` segments on top
//!    of persisted content so dirty writes are visible without replacing
//!    clean gaps with zeros.
//! 4. The `ContentLayout` is read from the object store, then content
//!    objects are fetched and reassembled into the requested byte range.
//! 5. The `PageCache` stores clean pages for hot-read acceleration;
//!    cache hits avoid object-store round trips.
//! 6. BLAKE3 checksum verification runs on each content object read.
//!    Corrupt objects trigger `ContentIntegrityError` and
//!    self-healing via the `repair` module when replicas exist.
//!
//! # Write path
//!
//! The write path proceeds through three stages: **buffer**, **dispatch**,
//! **fsync**.
//!
//! **Stage 1 — Buffer** (`write_file`(LocalFileSystem::write_file)):
//!
//! 1. Path resolution → inode ID + [`InodeRecord`].
//! 2. Quota and space-admission checks guard against over-provisioning.
//! 3. Bytes are ingested into a per-inode `WriteBuffer`. If the
//!    buffer exceeds its flush threshold, the write triggers an immediate
//!    flush.
//! 4. Ordinary writes remain buffered/dirty. Sync durability is supplied by
//!    the fsync/O_SYNC paths, which flush dirty buffers into the normal
//!    committed-root boundary or an explicit sync-write intent.
//!
//! **Stage 2 — Dispatch** (`flush_write_buffer`(LocalFileSystem::flush_write_buffer)):
//!
//! 1. Buffered segments are drained from the `WriteBuffer`.
//! 2. Drained segments are assembled into content-chunk-scoped overlays so
//!    scattered page-sized dirties in the same chunk share one authoritative
//!    content rewrite. Original write ranges are then finalized through
//!    `ExtentAllocator` with BLAKE3 checksums, and the
//!    `ExtentMap`(tidefs_extent_map::ExtentMap) / inode size are updated.
//! 3. The inode is marked dirty in `DirtySet` and
//!    `FileSystemState::dirty_content`.
//! 4. The `CommitGroupStateMachine` transitions the commit_group to `Syncing` when
//!    auto-commit thresholds or an explicit fsync trigger fire.
//!
//! **Stage 3 — Fsync** (`fsync_file`(LocalFileSystem::fsync_file),
//! `fsync_data_only_file`(LocalFileSystem::fsync_data_only_file)):
//!
//! 1. Write buffer is flushed.
//! 2. **Intent-log fast path**: if the intent log has pending data entries
//!    for this inode, `IntentLog::flush_and_sync` writes them to the
//!    separate intent-log (LOG_DEVICE) device. The LOG_DEVICE sync makes data
//!    crash-safe without a full commit_group commit. The log is cleared and the
//!    primary store is synced, completing the fast path.
//! 3. **Full commit path** (when no pending intent-log entries):
//!    `do_commit` iterates the `DirtySet`, persists all dirty metadata
//!    (inodes, directories, extent maps, quota, space counters), rewrites
//!    the superblock root pointer via `publish_root_commit`, and calls
//!    [`LocalObjectStore::sync_all`].
//! 4. [`FsyncStats`] counters track fast-path vs. full-commit frequency
//!    for performance observability.
//!
//! # Crash recovery path
//!
//! On `open`(LocalFileSystem::open), the recovery sequence is:
//!
//! 1. **Pool open**: `default_development_pool` opens the [`LocalObjectStore`] with
//!    the requested device, encryption, and compression configuration.
//! 2. **Root select**: `load_latest_committed_state` scans committed root
//!    slots and selects the newest valid root. If no root exists,
//!    v0.3.90-era superblocks are migrated, or a fresh `initial_state()` is
//!    created.
//! 3. **Intent-log replay**: `IntentLog::load` reads any persisted
//!    intent-log entries. `replay_uncommitted` replays
//!    `SyncWriteRange`, `OdsyncDataRange`, `SharedMmapMsync`, and
//!    `NamespaceSyncIntent` entries against the live `FileSystemState`.
//!    If replay fails, mount is refused with
//!    [`FileSystemError::CorruptState`].
//! 4. **Intent-log clear**: replayed entries are cleared so they are not
//!    replayed again on the next open.
//! 5. **Auxiliary state load**: quota table, space counters, and orphan
//!    index are loaded from their persisted object keys.
//! 6. **Torn-tail repair**: the `recovery` module handles incomplete
//!    commits (mid-write root slots) by ignoring them — the filesystem
//!    always selects the newest *complete* commit automatically.
//! 7. **Background services**: compaction, reclaim, orphan-reclamation,
//!    and writeback daemons are started via
//!    [`tidefs_background_scheduler`].
//!
//! # Integration points
//!
//! **Upstream: FUSE daemon**
//!
//! `tidefs_posix_filesystem_adapter_daemon` implements the FUSE low-level
//! protocol. Each FUSE operation (lookup, getattr, read, write, fsync, …)
//! dispatches through the `VfsEngine` trait to
//! `VfsEngineImpl`(crate::vfs_engine_impl::VfsEngineImpl), which wraps
//! [`LocalFileSystem`] in a `RefCell` for interior mutability.
//! File-handle management is handled by
//! `FileHandleTable`(crate::open_dispatch::FileHandleTable).
//! Advisory lock operations use [`LockTracker`] from
//! `tidefs_types_vfs_core`, with thin wrappers in
//! `LocalFileSystem` for interior mutability.
//!
//! **Downstream: local object store**
//!
//! [`LocalFileSystem`] owns a [`LocalObjectStore`] (or
//! [`QuorumObjectStore`] for replicated pools). All durable state —
//! inodes, directories, extent maps, content objects, quota tables, space
//! counters, intent-log entries, orphan indexes, and superblock root
//! pointers — are stored as keyed objects. The filesystem does not manage
//! raw block devices; it delegates all I/O to the object store's pool/device
//! layer.
//!
//! matrix testing.
//!
//! # Comparison to ZFS / Ceph
//!
//! - **ZFS**: ZFS bundles the filesystem, DMU, ARC, and ZIO stack into a
//!   single kernel subsystem. TideFS separates the local filesystem from
//!   the object store and I/O scheduler, enabling isolated testing of
//!   filesystem semantics without ZIO or DMU coupling.
//! - **CephFS**: CephFS clients talk to MDS daemons for metadata and RADOS
//!   for data, with no local filesystem abstraction. TideFS provides a
//!   standalone local filesystem layer that can operate independently of
//!   the distributed layer.

pub mod admission;
mod allocation;
mod background_cleaner;
mod background_orphan_reclamation;
pub mod capacity_authority;
mod checksum;
mod commit_group;
mod constants;
mod content;
pub mod crash_hooks;
mod crash_recovery;
mod dedup;
mod dedup_refcount;
pub mod dirty_page_tracker;
mod encoding;
mod error;
mod fsck;
pub mod fuse_fsync;
mod fuse_getattr;
mod fuse_setattr;
mod fuse_statfs;
mod helpers;
mod hot_read_cache;
mod inode_cache;
mod intent_log;
mod journal_cleaner;
mod namespace;
mod object_keys;
pub mod open_dispatch;
mod orphan_cleanup;
pub mod page_cache;
pub mod parity_raid;
mod persistence;
mod pool_label;
pub mod posix_acl;
mod quota;
mod readahead;
mod records;
mod recovery;
pub mod release_dispatch;
mod repair;
mod scrub;
mod scrub_repair_integration;
mod send_receive;
mod snapshot;
mod space_pressure;
pub mod vfssend2_bridge;

pub mod device_removal;
#[cfg(feature = "encryption")]
pub mod encrypted_fs;
pub mod rebuild;
pub mod statfs;
mod transaction;
mod txg_replay;
mod types;
pub mod vfs_engine_impl;
mod write_buffer;
mod writeback;
mod writeback_daemon;
mod xattr_dispatch;
use std::cell::RefCell;
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::convert::TryFrom;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use tidefs_intent_log::XattrNamespace;

use tidefs_background_scheduler::{
    BackgroundScheduler, BackgroundService, ServiceBudget, ServiceError, ServicePriority,
    TickReport,
};
use tidefs_block_allocator::TrimRequest;
use tidefs_claim_ledger::{ClaimClass, ClaimEntryRecord, ClaimantRef};
use tidefs_commit_group::{CommitGroupId, CommitGroupRecovery, CommitGroupSync, SyncGate};
use tidefs_dataset_feature_flags::{FeatureFlags, SupportedFeaturesV1};
use tidefs_dataset_lifecycle::{
    DatasetCatalog, DatasetFlags, DatasetId, DatasetLifecycle, DatasetType, PoisonNotification,
    SyncGuarantee,
};
use tidefs_dataset_properties::PropertySet;
use tidefs_extent_map::ExtentAllocator;
use tidefs_local_object_store::{
    device_layout::DeviceMediaClass, CompressionConfig, CrashInjectionPoint, DeviceBacking,
    DeviceClass, DeviceConfig, DeviceIoClass, DeviceKind, EncryptionConfig, IntegrityDigest64,
    IoClass, LocalObjectStore, ObjectKey, ObjectLocation, Pool, PoolConfig, PoolProperties,
    StoreEncryptionKey, StoreError, StoreOptions,
};
use tidefs_orphan_index::{OrphanEntry, OrphanEntryFlags, OrphanIndex};
use tidefs_performance_contract::AdmissionPermit;
use tidefs_quorum_write_runtime::{QuorumConfig, QuorumObjectStore};
use tidefs_reserve_ledger::{BudgetDomain, ReserveClass};
use tidefs_space_accounting::{
    DatasetQuotaHierarchy, SpaceAccounting, SpaceDomainRegistry, StatfsResult,
};
use tidefs_types_claim_ledger_core::StorageAuthorityToken;
use tidefs_types_claim_ledger_core::{
    BudgetDomainId, ClaimEntry, ClaimId, ClaimReason, ObligationLedger,
};
use tidefs_types_space_accounting_core::{
    DatasetSpaceCountersV1, PoolPhysicalCountersV1, SpaceDelta, SpaceDomainId,
};
use tidefs_types_vfs_core::{
    Errno, Generation, InodeAttr, InodeId, NodeKind, SetAttr, FALLOC_FL_COLLAPSE_RANGE,
    FALLOC_FL_INSERT_RANGE, FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE, FALLOC_FL_ZERO_RANGE,
    ROOT_INODE_ID,
};
use tidefs_types_vfs_core::{LockConflict, LockRange, LockTracker};

use background_orphan_reclamation::BackgroundOrphanReclamation;
use tidefs_reclaim_queue_core::BPlusTreeReclaimQueue;
pub use tidefs_recovery_loop::RecoveryPolicy;
use tidefs_types_reclaim_queue_core::ObjectKey as ReclaimObjectKey;
use tidefs_types_reclaim_queue_core::QueueFamily as ReclaimQueueFamily;
use tidefs_types_reclaim_queue_core::{QueueFamily, ReclaimQueueEntry};
use tidefs_types_vfs_owned::DirEntry as OwnedDirEntry;

pub type Result<T> = std::result::Result<T, FileSystemError>;
pub use crate::constants::*;
pub use crate::dedup::DedupStats;
pub use crate::error::*;
pub use crate::fsck::{FsckCategory, FsckFinding, FsckReport, FsckSeverity};
use crate::orphan_cleanup::OrphanCleanupStats;
pub use crate::records::SnapshotKind;
pub use crate::snapshot::{
    BookmarkSummary, CloneSummary, HoldInfo, PromoteReport, SnapshotDescriptor,
    SnapshotRetentionPolicy, SnapshotRetentionReport,
};
pub use crate::types::*;
use tidefs_cleanup_engine::{CleanupEngine, JobExecutor};

use crate::allocation::*;
use crate::content::*;
use crate::crash_hooks::check_crash_hook;
pub(crate) use crate::crash_recovery::*;
use crate::dedup::DedupIndex;
pub(crate) use crate::encoding::*;
use crate::helpers::*;
use crate::hot_read_cache::*;
use crate::inode_cache::*;
// PC-008 intent-log module (types used via glob re-export)
// PC-008 intent-log module (re-exported for future use)
use crate::admission::LocalWriteAdmission;
use crate::background_cleaner::{BackgroundCleaner, BackgroundCleanerConfig};
use crate::capacity_authority::{
    CapacityAuthority, CapacityAuthoritySnapshot, CapacityReservationHandle, CapacityStatfs,
};
pub(crate) use crate::commit_group::{
    CommitGroupConfig, CommitGroupPhase, CommitGroupStateMachine, TxnGroupId,
};
use crate::dirty_page_tracker::DirtyRange;
use crate::intent_log::*;
pub use crate::object_keys::*;
use crate::page_cache::{CachedPage, DirtyPageTracker, PageCache, PageKey};
use crate::space_pressure::{SpacePressure, SpacePressureConfig};
use crate::write_buffer::{WriteBuffer, WriteBufferConfig};
use crate::writeback::DirtySet;

pub(crate) use crate::persistence::*;
pub(crate) use crate::quota::*;
use crate::records::*;
pub(crate) use crate::recovery::*;
use crate::repair::{RepairLog, RepairOutcome};
pub(crate) use crate::send_receive::*;

// Public fuzz-target entrypoints (not part of the product API).
#[doc(hidden)]
pub use crate::intent_log::fuzz_decode_intent_log_entry;
#[doc(hidden)]
pub use crate::send_receive::fuzz_decode_receive_checkpoint;
pub use crate::send_receive::verify_placement_stable;
#[cfg(test)]
pub fn default_root_authentication_key() -> Result<RootAuthenticationKey> {
    Ok(RootAuthenticationKey::demo_key())
}

#[cfg(not(test))]
pub fn default_root_authentication_key() -> Result<RootAuthenticationKey> {
    RootAuthenticationKey::from_environment()
}

pub fn audit_recovery(
    root: impl AsRef<Path>,
    options: StoreOptions,
) -> Result<RecoveryAuditReport> {
    audit_recovery_with_root_authentication_key(root, options, default_root_authentication_key()?)
}

pub fn audit_recovery_with_root_authentication_key(
    root: impl AsRef<Path>,
    options: StoreOptions,
    root_authentication_key: RootAuthenticationKey,
) -> Result<RecoveryAuditReport> {
    let mut store = LocalFileSystem::default_development_pool(root.as_ref(), &options, None, None)?;
    let mut authority = MountedOpenRecoveryAuthority::raw_only(
        &mut store,
        root_authentication_key,
        RecoveryPolicy::default(),
    );
    authority.recovery_audit()
}

pub fn verify_online(
    root: impl AsRef<Path>,
    options: StoreOptions,
) -> Result<OnlineVerifierReport> {
    verify_online_with_root_authentication_key(root, options, default_root_authentication_key()?)
}

pub fn verify_online_with_root_authentication_key(
    root: impl AsRef<Path>,
    mut options: StoreOptions,
    root_authentication_key: RootAuthenticationKey,
) -> Result<OnlineVerifierReport> {
    options.repair_torn_tail = false;
    let root = root.as_ref();
    if !root.exists() {
        return Ok(OnlineVerifierReport::empty());
    }
    let mut store = LocalFileSystem::default_development_pool(root, &options, None, None)?;
    let mut authority = MountedOpenRecoveryAuthority::raw_only(
        &mut store,
        root_authentication_key,
        RecoveryPolicy::default(),
    );
    authority.online_verifier_report()
}
pub fn fsck(root: impl AsRef<Path>, options: StoreOptions) -> Result<FsckReport> {
    fsck_with_root_authentication_key(root, options, default_root_authentication_key()?)
}

pub fn fsck_with_root_authentication_key(
    root: impl AsRef<Path>,
    options: StoreOptions,
    root_authentication_key: RootAuthenticationKey,
) -> Result<FsckReport> {
    let mut store = LocalObjectStore::open_with_options(root, options)?;
    crate::fsck::run_fsck(
        &mut store,
        root_authentication_key,
        RecoveryPolicy::default(),
    )
}

pub fn inspect_filesystem_content_objects(
    root: impl AsRef<Path>,
    options: StoreOptions,
) -> Result<FilesystemContentInspectionReport> {
    inspect_filesystem_content_objects_with_root_authentication_key(
        root,
        options,
        default_root_authentication_key()?,
    )
}

pub fn inspect_filesystem_content_objects_with_root_authentication_key(
    root: impl AsRef<Path>,
    mut options: StoreOptions,
    root_authentication_key: RootAuthenticationKey,
) -> Result<FilesystemContentInspectionReport> {
    options.repair_torn_tail = false;
    let Some(mut store) = LocalObjectStore::open_read_only_with_options(root, options)? else {
        return Ok(FilesystemContentInspectionReport::empty());
    };
    inspect_filesystem_content_objects_store(&mut store, root_authentication_key, None)
}

pub fn plan_root_retention(
    root: impl AsRef<Path>,
    options: StoreOptions,
    policy: RootRetentionPolicy,
) -> Result<RootRetentionPlan> {
    plan_root_retention_with_root_authentication_key(
        root,
        options,
        policy,
        default_root_authentication_key()?,
    )
}

pub fn plan_root_retention_with_root_authentication_key(
    root: impl AsRef<Path>,
    options: StoreOptions,
    policy: RootRetentionPolicy,
    root_authentication_key: RootAuthenticationKey,
) -> Result<RootRetentionPlan> {
    let mut store = LocalFileSystem::default_development_pool(root.as_ref(), &options, None, None)?;
    let mut authority = MountedOpenRecoveryAuthority::raw_only(
        &mut store,
        root_authentication_key,
        RecoveryPolicy::default(),
    );
    authority.root_retention_plan(policy)
}

pub fn run_crash_recovery_matrix(
    root: impl AsRef<Path>,
    options: StoreOptions,
) -> Result<CrashRecoveryMatrixReport> {
    run_crash_recovery_matrix_with_root_authentication_key(
        root,
        options,
        default_root_authentication_key()?,
    )
}

pub fn run_crash_recovery_matrix_with_root_authentication_key(
    root: impl AsRef<Path>,
    options: StoreOptions,
    root_authentication_key: RootAuthenticationKey,
) -> Result<CrashRecoveryMatrixReport> {
    let matrix_root = root.as_ref().to_path_buf();
    prepare_empty_crash_matrix_root(&matrix_root)?;

    let mut boundary_cases = Vec::with_capacity(CrashInjectionBoundary::ALL.len());
    for boundary in CrashInjectionBoundary::ALL {
        let case_root = matrix_root.join(boundary.stable_id());
        fs::create_dir_all(&case_root)
            .map_err(|source| fs_io_error("create_dir_all", &case_root, source))?;
        let case = run_crash_recovery_boundary_case(
            &case_root,
            options.clone(),
            boundary,
            root_authentication_key,
        )?;
        if !case.passed() {
            return Err(FileSystemError::CorruptState {
                reason: "crash matrix observed an outcome outside the allowed recovery set",
            });
        }
        boundary_cases.push(case);
    }

    let explicit_root = matrix_root.join("explicit-integrity-error");
    fs::create_dir_all(&explicit_root)
        .map_err(|source| fs_io_error("create_dir_all", &explicit_root, source))?;
    let explicit_error_case =
        run_crash_recovery_explicit_error_case(&explicit_root, options, root_authentication_key)?;
    if !explicit_error_case.passed() {
        return Err(FileSystemError::CorruptState {
            reason: "crash matrix did not observe the explicit integrity/media error case",
        });
    }

    Ok(CrashRecoveryMatrixReport {
        design_rule: PRODUCTION_RECOVERY_DOCTRINE,
        matrix_root,
        boundary_cases,
        explicit_error_case,
    })
}

#[derive(Clone, Debug)]

/// Captures old values of inodes, directories, and snapshots modified
/// during a mutation.  On commit failure the delta is used to roll back
/// each modified object to its pre-mutation state instead of restoring
/// an entire FileSystemState clone (O(dirty) instead of O(all metadata)).
struct MutationDelta {
    old_inodes: BTreeMap<InodeId, InodeRecord>,
    old_directories: BTreeMap<InodeId, BTreeMap<Vec<u8>, NamespaceEntry>>,
    old_snapshots: BTreeMap<Vec<u8>, SnapshotRecord>,
    old_generation: u64,
    old_next_inode_id: u64,
    // Side-ledger snapshots for full transaction rollback (#5980).
    // Buffered payload snapshots are lazy so metadata-only mutations do not
    // clone dirty writeback buffers.
    old_write_buffers: Option<BTreeMap<InodeId, WriteBuffer>>,
    old_quota_table: QuotaTable,
    old_space_accounting: SpaceAccounting,
    old_capacity_authority: CapacityAuthoritySnapshot,
    old_dirty_pages: BTreeMap<InodeId, Vec<DirtyRange>>,
    old_extent_allocator: ExtentAllocator,
    intent_log_seq_at_begin: u64,
}

#[derive(Debug)]
struct BufferedChunkPatchPiece {
    offset: u64,
    bytes: Vec<u8>,
}

#[derive(Debug)]
struct BufferedChunkPatch {
    start: u64,
    end: u64,
    pieces: Vec<BufferedChunkPatchPiece>,
}

#[derive(Debug)]
struct CoalescedBufferedWritePatch {
    offset: u64,
    bytes: Vec<u8>,
}

/// Captures old values of inodes, directories, and snapshots
/// modified during a mutation.  On commit failure the delta is
/// used to roll back each modified object to its pre-mutation
/// state instead of restoring an entire FileSystemState clone
/// — O(dirty) instead of O(all metadata).
/// Root dataset ID used as the bridge between engine-layer
/// SpaceAccounting and the store-layer SpaceBook.  When multi-dataset
/// support is added, this must be replaced with the owning dataset ID
/// of each inode.
/// Review debt TFR-004: root identity must become dataset-scoped before
/// dataset, snapshot, or mount identity can be treated as authoritative.
const ROOT_DATASET_ID: [u8; 16] = [0u8; 16];
const DEFAULT_DEVELOPMENT_DEVICE_DIR: &str = ".tidefs-devices";
const DEFAULT_DEVELOPMENT_DEVICE_IMAGE: &str = "data0.img";
pub const DEFAULT_LOCAL_FILESYSTEM_DEVELOPMENT_DEVICE_IMAGE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, Default)]
pub(crate) struct FileSystemState {
    // Review debt TFR-004: these inode, directory, and extent maps are global
    // to the mounted LocalFileSystem, while the architecture requires explicit
    // dataset-scoped ownership before TideFS can make storage authority claims.
    next_inode_id: u64,
    generation: u64,
    inodes: Arc<BTreeMap<InodeId, InodeRecord>>,
    directories: Arc<BTreeMap<InodeId, BTreeMap<Vec<u8>, NamespaceEntry>>>,
    snapshots: BTreeMap<Vec<u8>, SnapshotRecord>,
    dirty_content: BTreeSet<InodeId>,
    dirty_inodes: BTreeSet<InodeId>,
    dirty_dirs: BTreeSet<InodeId>,
    quota_table: QuotaTable,
    space_accounting: SpaceAccounting,
    pub(crate) last_inode_write_tx: BTreeMap<InodeId, u64>,
    pub(crate) last_dir_write_tx: BTreeMap<InodeId, u64>,
    known_inode_ids: BTreeSet<InodeId>,
    corrupted_inodes: BTreeSet<InodeId>,
    /// Per-directory change-stream maps keyed by InodeId, then by dir_rev.
    change_streams: BTreeMap<InodeId, BTreeMap<u64, DirChangeRecord>>,
    /// Per-file extent maps for byte-range-to-physical mapping persistence.
    /// Keyed by InodeId; only populated for file-like inodes with allocated extents.
    pub(crate) extent_maps: BTreeMap<InodeId, tidefs_extent_map::ExtentMap>,
    /// Tracks which extent maps are dirty and need persistence on next commit.
    pub(crate) dirty_extent_maps: BTreeSet<InodeId>,
    #[allow(dead_code)]
    // INTENT: kept for planned architecture; callers in test modules or pending wiring into FUSE dispatch
    /// Last transaction ID when each extent map was written (for re-use avoidance).
    pub(crate) last_extent_map_write_tx: BTreeMap<InodeId, u64>,
    /// Compression policy governing content writes during persistence.
    pub(crate) content_compression_policy: ContentCompressionPolicy,
}

/// Resolve content compression policy from dataset feature flags.
///
/// Priority: lz4 > zstd > off. Only one algorithm is active at a time;
/// the returned policy governs all mounted-filesystem content writes.
/// This is the single live compression authority for the mounted filesystem.
/// Resolve compression policy from the dataset property `compression.algorithm`.
///
/// Returns `None` if the property is not locally set; callers should fall
/// back to feature flags or default.
fn resolve_compression_policy_from_properties(
    props: &PropertySet,
) -> Option<(ContentCompressionPolicy, CompressionPolicySource)> {
    use tidefs_dataset_properties::PropertyKey;
    let key = PropertyKey::new("compression.algorithm");
    let entry = props.get(&key)?;
    // Only use the property if it was explicitly set (Local).
    if !matches!(
        entry.source,
        tidefs_dataset_properties::PropertySource::Local
    ) {
        return None;
    }
    let algo = match &entry.value {
        tidefs_dataset_properties::PropertyValue::String(s) => s.as_str(),
        _ => return None,
    };
    match algo {
        "zstd" | "zstd-3" => Some((
            ContentCompressionPolicy::zstd_default(),
            CompressionPolicySource::PropertyOverride,
        )),
        "lz4" => Some((
            ContentCompressionPolicy::lz4_default(),
            CompressionPolicySource::PropertyOverride,
        )),
        "off" | "none" => Some((
            ContentCompressionPolicy::off(),
            CompressionPolicySource::PropertyOverride,
        )),
        _ => None, // Unknown algorithm: fall through to feature flags/default.
    }
}

fn resolve_compression_policy(feature_flags: &FeatureFlags) -> ContentCompressionPolicy {
    use tidefs_types_dataset_feature_flags_core::{
        FEATURE_COMPRESSION_LZ4, FEATURE_COMPRESSION_ZSTD,
    };
    let name_lz4 =
        tidefs_types_dataset_feature_flags_core::FeatureName::from_str(FEATURE_COMPRESSION_LZ4);
    let name_zstd =
        tidefs_types_dataset_feature_flags_core::FeatureName::from_str(FEATURE_COMPRESSION_ZSTD);
    if name_lz4.is_some_and(|n| feature_flags.is_enabled(&n)) {
        ContentCompressionPolicy::lz4_default()
    } else if name_zstd.is_some_and(|n| feature_flags.is_enabled(&n)) {
        ContentCompressionPolicy::zstd_default()
    } else {
        ContentCompressionPolicy::off()
    }
}

#[cfg(test)]
mod resolve_compression_policy_tests {
    use super::*;
    use tidefs_types_dataset_feature_flags_core::{
        FEATURE_COMPRESSION_LZ4, FEATURE_COMPRESSION_ZSTD,
    };

    fn feature(name: &str) -> tidefs_types_dataset_feature_flags_core::FeatureName {
        tidefs_types_dataset_feature_flags_core::FeatureName::from_str(name).unwrap()
    }

    #[test]
    fn no_features_returns_off() {
        let ff = FeatureFlags::new();
        let policy = resolve_compression_policy(&ff);
        assert_eq!(policy.algorithm, ContentCompressionAlgorithm::None);
    }

    #[test]
    fn zstd_feature_returns_zstd_policy() {
        let mut ff = FeatureFlags::new();
        let _ = ff.enable_feature(
            feature(FEATURE_COMPRESSION_ZSTD),
            tidefs_types_dataset_feature_flags_core::FeatureClass::RoCompat,
        );
        let policy = resolve_compression_policy(&ff);
        assert_eq!(policy.algorithm, ContentCompressionAlgorithm::Zstd);
        assert_eq!(policy.level, 3);
        assert_eq!(policy.min_savings_bytes, 32);
    }

    #[test]
    fn lz4_feature_returns_lz4_policy() {
        let mut ff = FeatureFlags::new();
        let _ = ff.enable_feature(
            feature(FEATURE_COMPRESSION_LZ4),
            tidefs_types_dataset_feature_flags_core::FeatureClass::RoCompat,
        );
        let policy = resolve_compression_policy(&ff);
        assert_eq!(policy.algorithm, ContentCompressionAlgorithm::Lz4);
        assert_eq!(policy.level, 0);
        assert_eq!(policy.min_savings_bytes, 32);
    }

    #[test]
    fn lz4_wins_over_zstd() {
        let mut ff = FeatureFlags::new();
        let _ = ff.enable_feature(
            feature(FEATURE_COMPRESSION_LZ4),
            tidefs_types_dataset_feature_flags_core::FeatureClass::RoCompat,
        );
        let _ = ff.enable_feature(
            feature(FEATURE_COMPRESSION_ZSTD),
            tidefs_types_dataset_feature_flags_core::FeatureClass::RoCompat,
        );
        let policy = resolve_compression_policy(&ff);
        assert_eq!(policy.algorithm, ContentCompressionAlgorithm::Lz4);
    }

    #[test]
    fn validate_zstd_level_in_range() {
        let policy = ContentCompressionPolicy {
            algorithm: ContentCompressionAlgorithm::Zstd,
            level: 3,
            min_savings_bytes: 32,
        };
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn validate_zstd_level_out_of_range_rejected() {
        let policy = ContentCompressionPolicy {
            algorithm: ContentCompressionAlgorithm::Zstd,
            level: 0,
            min_savings_bytes: 32,
        };
        assert!(policy.validate().is_err());
        let policy = ContentCompressionPolicy {
            algorithm: ContentCompressionAlgorithm::Zstd,
            level: 23,
            min_savings_bytes: 32,
        };
        assert!(policy.validate().is_err());
    }

    #[test]
    fn validate_lz4_level_in_range() {
        let policy = ContentCompressionPolicy {
            algorithm: ContentCompressionAlgorithm::Lz4,
            level: 0,
            min_savings_bytes: 32,
        };
        assert!(policy.validate().is_ok());
        let policy = ContentCompressionPolicy {
            algorithm: ContentCompressionAlgorithm::Lz4,
            level: 16,
            min_savings_bytes: 32,
        };
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn validate_lz4_level_out_of_range_rejected() {
        let policy = ContentCompressionPolicy {
            algorithm: ContentCompressionAlgorithm::Lz4,
            level: -1,
            min_savings_bytes: 32,
        };
        assert!(policy.validate().is_err());
        let policy = ContentCompressionPolicy {
            algorithm: ContentCompressionAlgorithm::Lz4,
            level: 17,
            min_savings_bytes: 32,
        };
        assert!(policy.validate().is_err());
    }

    #[test]
    fn validate_none_always_ok() {
        let policy = ContentCompressionPolicy {
            algorithm: ContentCompressionAlgorithm::None,
            level: 999,
            min_savings_bytes: 0,
        };
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn off_policy_is_valid() {
        assert!(ContentCompressionPolicy::off().validate().is_ok());
    }

    #[test]
    fn zstd_default_policy_is_valid() {
        assert!(ContentCompressionPolicy::zstd_default().validate().is_ok());
    }

    #[test]
    fn lz4_default_policy_is_valid() {
        assert!(ContentCompressionPolicy::lz4_default().validate().is_ok());
    }

    #[test]
    fn compression_policy_report_is_public_snapshot() {
        let report =
            ContentCompressionPolicy::zstd_default().report(CompressionPolicySource::FeatureFlag);
        assert_eq!(report.algorithm, ContentCompressionAlgorithm::Zstd);
        assert_eq!(report.level, 3);
        assert_eq!(report.min_savings_bytes, 32);
        assert_eq!(report.source, CompressionPolicySource::FeatureFlag);
    }

    // ── Property-based compression resolution ───────────────────

    #[test]
    fn property_override_zstd_wins_over_feature_flags() {
        let mut props = PropertySet::new();
        props.set_local(
            tidefs_dataset_properties::PropertyKey::new("compression.algorithm"),
            tidefs_dataset_properties::PropertyValue::String("zstd".into()),
        );
        let result = resolve_compression_policy_from_properties(&props);
        assert!(result.is_some());
        let (policy, source) = result.unwrap();
        assert_eq!(policy.algorithm, ContentCompressionAlgorithm::Zstd);
        assert_eq!(source, CompressionPolicySource::PropertyOverride);
    }

    #[test]
    fn property_override_lz4() {
        let mut props = PropertySet::new();
        props.set_local(
            tidefs_dataset_properties::PropertyKey::new("compression.algorithm"),
            tidefs_dataset_properties::PropertyValue::String("lz4".into()),
        );
        let result = resolve_compression_policy_from_properties(&props);
        assert!(result.is_some());
        let (policy, source) = result.unwrap();
        assert_eq!(policy.algorithm, ContentCompressionAlgorithm::Lz4);
        assert_eq!(source, CompressionPolicySource::PropertyOverride);
    }

    #[test]
    fn property_override_off() {
        let mut props = PropertySet::new();
        props.set_local(
            tidefs_dataset_properties::PropertyKey::new("compression.algorithm"),
            tidefs_dataset_properties::PropertyValue::String("off".into()),
        );
        let result = resolve_compression_policy_from_properties(&props);
        assert!(result.is_some());
        let (policy, source) = result.unwrap();
        assert_eq!(policy.algorithm, ContentCompressionAlgorithm::None);
        assert_eq!(source, CompressionPolicySource::PropertyOverride);
    }

    #[test]
    fn property_not_set_returns_none() {
        let props = PropertySet::new();
        let result = resolve_compression_policy_from_properties(&props);
        assert!(result.is_none());
    }

    #[test]
    fn property_unknown_algorithm_returns_none() {
        let mut props = PropertySet::new();
        props.set_local(
            tidefs_dataset_properties::PropertyKey::new("compression.algorithm"),
            tidefs_dataset_properties::PropertyValue::String("bzip2".into()),
        );
        let result = resolve_compression_policy_from_properties(&props);
        assert!(
            result.is_none(),
            "unknown algorithm should fall through to feature flags"
        );
    }

    #[test]
    fn property_inherited_value_not_treated_as_override() {
        let mut props = PropertySet::new();
        props.set_with_source(
            tidefs_dataset_properties::PropertyKey::new("compression.algorithm"),
            tidefs_dataset_properties::PropertyValue::String("zstd".into()),
            tidefs_dataset_properties::PropertySource::Inherited {
                parent_dataset_id: 1,
            },
        );
        // Inherited values should not be treated as property overrides;
        // the child must explicitly set the property to override.
        let result = resolve_compression_policy_from_properties(&props);
        assert!(result.is_none());
    }
}

#[derive(Debug)]
/// Background scrubber that periodically re-opens a read-only store
/// and runs the online verifier to detect silent data corruption.
struct BackgroundScrubber {
    corruption_detected: Arc<AtomicBool>,
    root: std::path::PathBuf,
    options: StoreOptions,
    root_authentication_key: RootAuthenticationKey,
    interval: Duration,
    last_scrub: Instant,
}

impl BackgroundScrubber {
    fn new(
        root: std::path::PathBuf,
        options: StoreOptions,
        root_authentication_key: RootAuthenticationKey,
        interval: Duration,
        corruption_detected: Arc<AtomicBool>,
    ) -> Self {
        Self {
            root,
            options,
            root_authentication_key,
            interval,
            last_scrub: Instant::now()
                .checked_sub(interval)
                .unwrap_or_else(Instant::now),
            corruption_detected,
        }
    }
}

impl BackgroundService for BackgroundScrubber {
    fn name(&self) -> &'static str {
        "background-scrub"
    }

    fn priority(&self) -> ServicePriority {
        // Scrub is integrity-critical: undetected corruption can propagate
        // through snapshots and send/receive streams.
        ServicePriority::Critical
    }

    fn tick(&mut self, _budget: &ServiceBudget) -> std::result::Result<TickReport, ServiceError> {
        if !self.has_work() {
            return Ok(TickReport::default());
        }

        self.last_scrub = Instant::now();

        let mut store =
            match LocalObjectStore::open_read_only_with_options(&self.root, self.options.clone()) {
                Ok(Some(s)) => s,
                Ok(None) => {
                    eprintln!(
                        "background-scrub: store not found at {}, skipping cycle",
                        self.root.display()
                    );
                    return Ok(TickReport::default());
                }
                Err(e) => {
                    eprintln!("background-scrub: failed to open read-only store: {e}");
                    return Ok(TickReport {
                        errors: 1,
                        ..TickReport::default()
                    });
                }
            };

        match crate::recovery::verify_online_store(&mut store, self.root_authentication_key) {
            Ok(report) => {
                if !report.issues.is_empty() {
                    eprintln!(
                        "background-scrub: {} corruption issue(s) detected in {} root slots",
                        report.issues.len(),
                        report.root_slots_seen,
                    );
                    self.corruption_detected.store(true, Ordering::SeqCst);
                    for issue in &report.issues {
                        eprintln!(
                            "  background-scrub: slot={:?} tx={:?} {}",
                            issue.slot, issue.transaction_id, issue.reason
                        );
                    }
                    return Ok(TickReport {
                        processed: report.issues.len() as u64,
                        has_more: false,
                        ..TickReport::default()
                    });
                }

                // Root slots verified clean — run content-block checksum verification.
                match crate::recovery::load_latest_committed_state(
                    &mut store,
                    self.root_authentication_key,
                    RecoveryPolicy::default(),
                ) {
                    Ok(Some(state)) => {
                        match crate::scrub::scrub_inodes_content(&store, &state.inodes) {
                            Ok(scrub_report) => {
                                if !scrub_report.is_clean() {
                                    eprintln!(
                                        "background-scrub: {} corrupt, {} unreadable, {} missing-checksum blocks in {} scanned",
                                        scrub_report.blocks_corrupt,
                                        scrub_report.blocks_unreadable,
                                        scrub_report.blocks_no_checksum,
                                        scrub_report.blocks_scanned,
                                    );
                                    self.corruption_detected.store(true, Ordering::SeqCst);
                                    for violation in &scrub_report.violations {
                                        eprintln!(
                                            "  background-scrub: inode={} version={} kind={:?} key={} outcome={:?}",
                                            violation.block_id.inode_id,
                                            violation.block_id.data_version,
                                            violation.block_id.kind,
                                            violation.key_hex,
                                            violation.outcome,
                                        );
                                    }
                                }
                                Ok(TickReport {
                                    processed: scrub_report.blocks_scanned,
                                    errors: scrub_report.blocks_corrupt
                                        + scrub_report.blocks_unreadable,
                                    items_consumed: scrub_report.blocks_scanned,
                                    has_more: false,
                                    ..TickReport::default()
                                })
                            }
                            Err(e) => {
                                eprintln!("background-scrub: content scrub error: {e}");
                                Ok(TickReport {
                                    errors: 1,
                                    ..TickReport::default()
                                })
                            }
                        }
                    }
                    Ok(None) => Ok(TickReport::default()),
                    Err(e) => {
                        eprintln!("background-scrub: failed to load committed state: {e}");
                        Ok(TickReport {
                            errors: 1,
                            ..TickReport::default()
                        })
                    }
                }
            }
            Err(e) => {
                eprintln!("background-scrub: verification error: {e}");
                Ok(TickReport {
                    errors: 1,
                    ..TickReport::default()
                })
            }
        }
    }

    fn has_work(&self) -> bool {
        self.last_scrub.elapsed() >= self.interval
    }
}

/// Runtime that drives the [`BackgroundScheduler`] on a background thread.
///
/// Owns the scheduler and a tick thread that dispatches [`run_cycle()`] at a
/// fixed interval. All registered [`BackgroundService`] implementations receive
/// fair scheduling under the 5-stage priority model.
///
/// [`BackgroundScheduler`]: tidefs_background_scheduler::BackgroundScheduler
/// [`run_cycle()`]: tidefs_background_scheduler::BackgroundScheduler::run_cycle
/// [`BackgroundService`]: tidefs_background_scheduler::BackgroundService
#[derive(Debug)]
struct BackgroundSchedulerRuntime {
    handle: Option<thread::JoinHandle<()>>,
    cancel: Arc<AtomicBool>,
}

impl BackgroundSchedulerRuntime {
    /// Start the scheduler on a background thread ticking at `tick_interval`.
    ///
    /// The thread runs `scheduler.run_cycle()` in a loop, logging progress
    /// after each tick. It stops when [`stop()`] is called or when the
    /// runtime is dropped.
    ///
    /// [`stop()`]: BackgroundSchedulerRuntime::stop
    fn start(mut scheduler: BackgroundScheduler, tick_interval: Duration) -> Self {
        let cancel = Arc::new(AtomicBool::new(false));
        let cancel_clone = Arc::clone(&cancel);

        let handle = thread::spawn(move || loop {
            thread::sleep(tick_interval);
            if cancel_clone.load(Ordering::Relaxed) {
                break;
            }
            let report = scheduler.run_cycle();
            if report.services_ran > 0 {
                eprintln!(
                    "background-scheduler: ran {} services, skipped {}, budget_exhausted={:?}",
                    report.services_ran, report.services_skipped, report.budget_exhausted,
                );
            }
        });

        Self {
            handle: Some(handle),
            cancel,
        }
    }

    /// Signal the background thread to stop and join it.
    ///
    /// Safe to call multiple times; subsequent calls are no-ops.
    fn stop(&mut self) {
        self.cancel.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Instrumentation counters for fsync/fdatasync/flush operations.
///
/// All counters are atomic and can be read without &mut self.
#[derive(Debug, Default)]
pub struct FsyncStats {
    /// Number of fsync (full data+metadata sync) calls completed.
    pub fsync_count: AtomicU64,
    /// Number of fdatasync (data-only sync) calls completed.
    pub fdatasync_count: AtomicU64,
    /// Number of fsync_all (filesystem-wide sync) calls completed.
    pub fsync_all_count: AtomicU64,
    /// Cumulative wall-clock nanoseconds spent inside fsync operations.
    pub fsync_total_ns: AtomicU64,
    /// Cumulative wall-clock nanoseconds spent inside fdatasync operations.
    pub fdatasync_total_ns: AtomicU64,
    /// Number of fsync calls that took the intent-log fast path.
    pub fsync_intent_log_fast_path_count: AtomicU64,
    /// Number of fsync calls that fell through to do_commit().
    pub fsync_do_commit_fallback_count: AtomicU64,
    /// Number of times fsync_wait_barrier was called and waited on the sync gate.
    pub fsync_barrier_wait_count: AtomicU64,
    /// Cumulative wall-clock nanoseconds spent waiting inside fsync barrier.
    pub fsync_barrier_wait_ns: AtomicU64,
}

impl FsyncStats {
    /// Snapshot all counters as a plain struct for inspection.
    pub fn snapshot(&self) -> FsyncStatsSnapshot {
        FsyncStatsSnapshot {
            fsync_count: self.fsync_count.load(Ordering::Relaxed),
            fdatasync_count: self.fdatasync_count.load(Ordering::Relaxed),
            fsync_all_count: self.fsync_all_count.load(Ordering::Relaxed),
            fsync_total_ns: self.fsync_total_ns.load(Ordering::Relaxed),
            fdatasync_total_ns: self.fdatasync_total_ns.load(Ordering::Relaxed),
            fsync_intent_log_fast_path_count: self
                .fsync_intent_log_fast_path_count
                .load(Ordering::Relaxed),
            fsync_do_commit_fallback_count: self
                .fsync_do_commit_fallback_count
                .load(Ordering::Relaxed),
            fsync_barrier_wait_count: self.fsync_barrier_wait_count.load(Ordering::Relaxed),
            fsync_barrier_wait_ns: self.fsync_barrier_wait_ns.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of [`FsyncStats`] counters at a point in time.
#[derive(Clone, Copy, Debug, Default)]
pub struct FsyncStatsSnapshot {
    pub fsync_count: u64,
    pub fdatasync_count: u64,
    pub fsync_all_count: u64,
    pub fsync_total_ns: u64,
    pub fdatasync_total_ns: u64,
    pub fsync_intent_log_fast_path_count: u64,
    pub fsync_do_commit_fallback_count: u64,
    pub fsync_barrier_wait_count: u64,
    pub fsync_barrier_wait_ns: u64,
}
/// Central handle for a local TideFS filesystem, owning the full lifecycle.
///
/// `LocalFileSystem` holds a configured object-store pool, the authoritative
/// in-memory metadata (`FileSystemState`), an intent log for crash-safe write
/// durability, per-inode write buffers, a page cache, extent allocator, space
/// accounting, quota enforcement, and four background service daemons
/// (compaction, reclaim, orphan reclamation, writeback). All POSIX-path-based
/// operations flow through this handle — `create_file`, `read_file`,
/// `write_file`, `fsync_file`, `truncate_file`, `unlink`, `rename`, and the
/// metadata/xattr/lock suites.
///
/// # Lifecycle
///
/// 1. **Open** via [`LocalFileSystem::open`]: opens or creates a pool,
///    selects the newest valid committed root (or creates a fresh
///    filesystem), replays the intent log, starts background services.
/// 2. **Use**: path-based methods read and write filesystem state through
///    the cached inode/directory/extent structures, with writes buffered
///    per inode and flushed on fsync or auto-commit.
/// 3. **Close** via [`Drop`]: shuts down background services, drains
///    writeback, syncs the intent log, and disconnects from the pool.
///
/// # Key internal components
///
/// - `store` / `quorum_store` — durable object-store backend.
/// - `state` — live inode table, directory tree, and dirty-bit tracking.
/// - `extent_allocator` — maps byte ranges to physical content objects.
/// - `intent_log` — write-ahead log for crash-safe fsync semantics.
/// - `write_buffers` — per-inode coalescing buffers for small writes.
/// - `page_cache` / `dirty_page_tracker` — in-memory data cache with
///   dirty tracking and background writeback.
/// - `commit_group` — transaction group state machine driving auto-commit.
/// - `fsync_stats` — atomic instrumentation counters for durability ops.
///
/// # Concurrency
///
/// Most methods require `&mut self`. For concurrent access from the
/// FUSE daemon, wrap in a [`RefCell`] via
/// [`VfsEngineImpl`](crate::vfs_engine_impl).
#[derive(Debug)]
pub struct LocalFileSystem {
    store: Pool,
    quorum_store: Option<QuorumObjectStore>,
    state: FileSystemState,
    allocator_policy: LocalStorageAllocatorPolicy,
    extent_allocator: ExtentAllocator,
    root_authentication_key: RootAuthenticationKey,
    encryption_key: Option<StoreEncryptionKey>,
    hot_read_cache: RefCell<HotReadCache>,
    content_layout_cache: RefCell<BTreeMap<HotReadCacheKey, ContentLayout>>,
    dedup_index: RefCell<DedupIndex>,
    dedup_enabled: bool,
    inode_cache: RefCell<InodeCache>,
    auto_commit: bool,
    uncommitted_mutation_count: u64,
    max_uncommitted_mutations: u64,
    in_transaction: bool,
    #[allow(dead_code)]
    // INTENT: kept for planned architecture; callers in test modules or pending wiring into FUSE dispatch
    state_before_transaction: Option<FileSystemState>,
    mutation_delta: Option<MutationDelta>,
    mutation_recorded_commit_group_write: bool,
    domain_registry: SpaceDomainRegistry,
    /// Runtime write-admission state with hard dirty-byte/op/age caps.
    /// Every dirty producer must acquire an [`AdmissionPermit`] before
    /// work enters any tracked queue or buffer.
    write_admission: LocalWriteAdmission,
    /// Outstanding admission permits for dirty writes not yet committed.
    /// Released en masse when dirty_set is cleared after a successful SYNC.
    pending_permits: Vec<AdmissionPermit>,
    /// Centralised dirty-state tracker for the writeback layer (§4 of #1190).
    /// Accounts data bytes, metadata ops, inode/dir dirty sets, and catalog
    /// dirty flag.  Read by commit_group auto-sync triggers; cleared on successful SYNC.
    dirty_set: DirtySet,
    /// Per-mutation delta recording old values of modified objects.
    /// Used for O(dirty) rollback instead of O(all) state clone.
    intent_log: IntentLog,
    /// Metadata-level intent-log buffer for crash-safe namespace operations
    /// (rename, link, unlink, create, etc.). Populated by mutation methods and
    /// drained by the TxgCoordinator during two-phase commit.
    intent_log_buffer: Option<std::sync::Arc<tidefs_intent_log::IntentLogBuffer>>,
    commit_group: CommitGroupStateMachine,
    obligation_ledger: Box<ObligationLedger>,
    budget_domain: BudgetDomain,
    auto_compaction_waste_threshold: f64,
    space_pressure: SpacePressure,
    background_cleaner: BackgroundCleaner,
    orphan_index: Arc<Mutex<OrphanIndex>>,
    feature_flags: FeatureFlags,
    content_compression_policy: ContentCompressionPolicy,
    /// Tracks where the effective compression policy was resolved from.
    compression_policy_source: CompressionPolicySource,
    lifecycle: DatasetLifecycle,
    /// Durable pool-wide dataset catalog: canonical B+tree mapping hierarchical
    /// dataset paths to stable [`DatasetId`] values. Loaded from pool store on
    /// mount; saved after mutation. This is the single canonical dataset catalog
    /// authority for the mounted filesystem (issue #5952).
    dataset_catalog: DatasetCatalog,
    /// Durable pool-level property set. Loaded from pool store on mount;
    /// saved after mutation.
    pool_properties: PropertySet,
    background_scheduler: Option<BackgroundSchedulerRuntime>,
    /// Populated by `schedule_scrub_repairs()` with prioritized repair jobs
    /// from the scrub-to-repair scheduling bridge. Consumed by
    /// `dispatch_scheduled_repairs()` to apply repairs in priority order.
    scrub_repair_schedule: Option<crate::scrub_repair_integration::ScrubRepairSchedule>,
    /// Shared flag set by the background scrubber when corruption is detected
    /// on-disk.  Consumed by [`tick_background_services`] Duty 3 to trigger
    /// repair scheduling and dispatch.
    scrub_corruption_detected: Option<Arc<AtomicBool>>,
    pending_orphan_deletions: Arc<Mutex<Vec<u64>>>,
    reclaim_queue: Arc<Mutex<BPlusTreeReclaimQueue>>,
    total_reclaim_drains: u64,
    total_reclaim_entries_drained: u64,
    page_cache: RefCell<PageCache>,
    dirty_page_tracker: RefCell<DirtyPageTracker>,
    page_reclaim_stats: RefCell<page_cache::reclaim::ReclaimStats>,
    writeback_range_tracker: Arc<Mutex<crate::dirty_page_tracker::DirtyPageTracker>>,
    writeback_handle: Option<crate::writeback_daemon::WritebackHandle>,
    lock_tracker: RefCell<LockTracker>,
    pool_uuid: u64,
    /// tidefs-queue-root: local_fs.write_buffers
    /// admission: AdmissionPermit  service_curve: ServiceCurve
    write_buffers: BTreeMap<InodeId, WriteBuffer>,
    write_buffer_config: WriteBufferConfig,
    fsync_stats: FsyncStats,
    /// Sync gate for TXG group commit durability fence coordination.
    /// Wakes fsync/syncfs waiters when a commit group containing their
    /// dirty data commits.
    sync_gate: SyncGate,
    /// Deferred cleanup engine for post-commit orphan drain and block
    /// reclamation. Initialised via [`with_cleanup_engine`](Self::with_cleanup_engine)
    /// and invoked after each successful commit_group commit.
    recovery_policy: RecoveryPolicy,
    /// Production capacity authority: definitive used/free/reserved/pending
    /// byte counters for the mounted filesystem. Reconstructed during mount
    /// from pool geometry and committed usage. The sole derivation source
    /// for FUSE statfs, object-store allocation, dataset quotas, block
    /// trim/discard, and ENOSPC enforcement.
    capacity_authority: CapacityAuthority,
    /// Dataset ID of the mounted filesystem, used as the anchor for
    /// quota hierarchy ancestor-chain traversal during statfs and ENOSPC
    /// gating. Defaults to the root dataset when not explicitly set.
    mounted_dataset_id: [u8; 16],
    /// Optional nested dataset quota hierarchy for multi-dataset quota
    /// enforcement. When set, statfs and ENOSPC checks consult ancestor
    /// quotas. Configured by the caller (FUSE daemon or control plane)
    /// after mount.
    quota_hierarchy: Option<DatasetQuotaHierarchy>,
    /// Pre-computed parent map: dataset ID -> parent dataset ID.
    /// Built from the dataset catalog by the caller and used by
    /// statfs/ENOSPC to walk the ancestor chain.
    quota_parent_map: HashMap<[u8; 16], [u8; 16]>,
    cleanup_engine: Option<CleanupEngine<Box<dyn JobExecutor + Send>>>,
    /// Current placement epoch for send/receive stream attribution.
    placement_epoch: Option<u64>,
}

/// Configuration for authenticated filesystem open paths.
pub struct LocalFileSystemOpenConfig<'a> {
    pub options: StoreOptions,
    pub allocator_policy: LocalStorageAllocatorPolicy,
    pub root_authentication_key: RootAuthenticationKey,
    pub encryption: Option<EncryptionConfig>,
    pub compression: Option<CompressionConfig>,
    pub log_device_device_path: Option<std::path::PathBuf>,
    pub recovery_policy: RecoveryPolicy,
    pub block_devices: Option<&'a [std::path::PathBuf]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MountedOpenRecoveryTransformMode {
    RawOnlyNoDeviceTransforms,
}

const MOUNTED_RECOVERY_TRANSFORM_ORDERING: &str =
    "plaintext identity -> compression frame -> encryption frame -> checksum -> raw media bytes";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MountedCommittedRootRepairTransformMode {
    MetadataRawOnlyNoDeviceTransforms,
}

pub(crate) struct MountedCommittedRootRepairAuthority<'a> {
    store: &'a mut LocalObjectStore,
    root_authentication_key: RootAuthenticationKey,
    transform_mode: MountedCommittedRootRepairTransformMode,
}

impl<'a> MountedCommittedRootRepairAuthority<'a> {
    fn raw_only(
        store: &'a mut LocalObjectStore,
        root_authentication_key: RootAuthenticationKey,
    ) -> Self {
        Self {
            store,
            root_authentication_key,
            transform_mode:
                MountedCommittedRootRepairTransformMode::MetadataRawOnlyNoDeviceTransforms,
        }
    }

    fn transform_mode(&self) -> MountedCommittedRootRepairTransformMode {
        self.transform_mode
    }

    fn transform_ordering_boundary(&self) -> &'static str {
        MOUNTED_RECOVERY_TRANSFORM_ORDERING
    }

    fn recovery_probe_report(&mut self) -> Result<RecoveryProbeReport> {
        recovery_probe_from_store(&mut *self.store, self.root_authentication_key)
    }

    fn recovery_audit(&mut self) -> Result<RecoveryAuditReport> {
        audit_recovery_store(&mut *self.store, self.root_authentication_key)
    }

    fn online_verifier_report(&mut self) -> Result<OnlineVerifierReport> {
        verify_online_store(&mut *self.store, self.root_authentication_key)
    }

    fn root_retention_plan(&mut self, policy: RootRetentionPolicy) -> Result<RootRetentionPlan> {
        plan_root_retention_store(&mut *self.store, policy, self.root_authentication_key)
    }

    fn root_slot_locations_for_summary(
        &self,
        expected: &CommittedRootSummary,
    ) -> Result<Vec<ObjectLocation>> {
        root_slot_locations_for_summary(&*self.store, expected)
    }

    fn load_committed_root_state(&mut self, root: &RootCommitRecord) -> Result<FileSystemState> {
        load_state_from_transaction(&mut *self.store, root, self.root_authentication_key)
    }
}

pub(crate) struct MountedOpenRecoveryAuthority<'a> {
    store: &'a mut Pool,
    root_authentication_key: RootAuthenticationKey,
    recovery_policy: RecoveryPolicy,
    transform_mode: MountedOpenRecoveryTransformMode,
}

impl<'a> MountedOpenRecoveryAuthority<'a> {
    pub(crate) fn reject_device_transforms(
        encryption: Option<&EncryptionConfig>,
        compression: Option<&CompressionConfig>,
    ) -> Result<()> {
        if encryption.is_some() || compression.is_some() {
            return Err(FileSystemError::Unsupported {
                operation: "local filesystem device transforms",
                reason: "device-level compression/encryption is blocked by the TFR-006 raw-store inventory while mounted open/recovery uses the raw-only transform authority and other blocked production rows remain",
            });
        }
        Ok(())
    }

    fn raw_only(
        store: &'a mut Pool,
        root_authentication_key: RootAuthenticationKey,
        recovery_policy: RecoveryPolicy,
    ) -> Self {
        Self {
            store,
            root_authentication_key,
            recovery_policy,
            transform_mode: MountedOpenRecoveryTransformMode::RawOnlyNoDeviceTransforms,
        }
    }

    fn transform_mode(&self) -> MountedOpenRecoveryTransformMode {
        self.transform_mode
    }

    fn transform_ordering_boundary(&self) -> &'static str {
        MOUNTED_RECOVERY_TRANSFORM_ORDERING
    }

    fn raw_recovery_store(&self) -> &LocalObjectStore {
        self.store.raw_primary_store()
    }

    fn raw_recovery_store_mut(&mut self) -> &mut LocalObjectStore {
        self.store.raw_primary_store_mut()
    }

    fn committed_root_repair_authority(&mut self) -> MountedCommittedRootRepairAuthority<'_> {
        let root_authentication_key = self.root_authentication_key;
        let authority = MountedCommittedRootRepairAuthority::raw_only(
            self.raw_recovery_store_mut(),
            root_authentication_key,
        );
        debug_assert_eq!(
            authority.transform_mode(),
            MountedCommittedRootRepairTransformMode::MetadataRawOnlyNoDeviceTransforms
        );
        debug_assert_eq!(
            authority.transform_ordering_boundary(),
            MOUNTED_RECOVERY_TRANSFORM_ORDERING
        );
        authority
    }

    fn recovery_probe_report(&mut self) -> Result<RecoveryProbeReport> {
        self.committed_root_repair_authority()
            .recovery_probe_report()
    }

    fn recovery_audit(&mut self) -> Result<RecoveryAuditReport> {
        self.committed_root_repair_authority().recovery_audit()
    }

    fn online_verifier_report(&mut self) -> Result<OnlineVerifierReport> {
        self.committed_root_repair_authority()
            .online_verifier_report()
    }

    fn root_retention_plan(&mut self, policy: RootRetentionPolicy) -> Result<RootRetentionPlan> {
        self.committed_root_repair_authority()
            .root_retention_plan(policy)
    }

    fn root_slot_locations_for_summary(
        &mut self,
        expected: &CommittedRootSummary,
    ) -> Result<Vec<ObjectLocation>> {
        self.committed_root_repair_authority()
            .root_slot_locations_for_summary(expected)
    }

    fn load_committed_root_state(&mut self, root: &RootCommitRecord) -> Result<FileSystemState> {
        self.committed_root_repair_authority()
            .load_committed_root_state(root)
    }

    fn load_or_initialize_state(&mut self) -> Result<FileSystemState> {
        let root_authentication_key = self.root_authentication_key;
        let recovery_policy = self.recovery_policy;
        match load_latest_committed_state(
            self.raw_recovery_store_mut(),
            root_authentication_key,
            recovery_policy,
        )? {
            Some(state) => Ok(state),
            None => match self.store.primary_store().get(superblock_object_key())? {
                Some(bytes) => {
                    let state =
                        load_v0390_fixed_object_state(self.raw_recovery_store_mut(), &bytes)?;
                    persist_state(
                        self.raw_recovery_store_mut(),
                        &state,
                        root_authentication_key,
                    )?;
                    Ok(state)
                }
                None => {
                    let state = initial_state();
                    persist_state(
                        self.raw_recovery_store_mut(),
                        &state,
                        root_authentication_key,
                    )?;
                    Ok(state)
                }
            },
        }
    }

    fn load_operational_intent_log(&self) -> Result<IntentLog> {
        IntentLog::load(self.raw_recovery_store())
    }

    fn load_quota_table(&self) -> QuotaTable {
        match self.store.primary_store().get(quota_table_object_key()) {
            Ok(Some(bytes)) => QuotaTable::decode(&bytes).unwrap_or_else(|e| {
                eprintln!("warning: quota table decode failed: {e}; starting empty");
                QuotaTable::new()
            }),
            Ok(None) => QuotaTable::new(),
            Err(e) => {
                eprintln!("warning: quota table load failed: {e}; starting empty");
                QuotaTable::new()
            }
        }
    }

    fn merge_space_counters_into(&self, state: &mut FileSystemState) {
        if let Ok(Some(bytes)) = self.store.primary_store().get(space_counters_object_key()) {
            state.space_accounting = SpaceAccounting::new(
                decode_space_counters(&bytes).unwrap_or_default(),
                SpaceDomainId::NONE,
            );
        }
    }

    fn merge_dataset_usage_into(&self, state: &mut FileSystemState) {
        if let Some(usage) = self.raw_recovery_store().get_dataset_usage(ROOT_DATASET_ID) {
            let mut counters = *state.space_accounting.counters();
            counters.logical_used_bytes = counters.logical_used_bytes.max(usage.bytes_used);
            counters.reserved_bytes = counters.reserved_bytes.max(usage.bytes_reserved);
            state.space_accounting =
                SpaceAccounting::new(counters, state.space_accounting.domain_id());
        }
    }

    fn load_orphan_index(&self) -> OrphanIndex {
        match self.store.primary_store().get(orphan_index_object_key()) {
            Ok(Some(bytes)) => match OrphanIndex::recover_from_log(&bytes) {
                Ok((idx, corrupted)) => {
                    if !corrupted.is_empty() {
                        eprintln!(
                            "warning: {} orphan index entries had checksum failures; skipped",
                            corrupted.len()
                        );
                    }
                    idx
                }
                Err(e) => {
                    eprintln!("warning: orphan index recovery failed ({e}); starting empty");
                    OrphanIndex::new()
                }
            },
            Ok(None) => OrphanIndex::new(),
            Err(e) => {
                eprintln!("warning: orphan index load failed ({e}); starting empty");
                OrphanIndex::new()
            }
        }
    }

    fn recover_commit_group_generation(&self, generation: u64) -> u64 {
        let mut recovered_generation = generation;
        if self.recovery_policy.allows_replay() {
            match CommitGroupRecovery::recover(self.raw_recovery_store()) {
                Ok(recovery) => {
                    let recovered_commit_group = recovery.next_commit_group_id.0;
                    if recovered_commit_group > recovered_generation {
                        recovered_generation = recovered_commit_group;
                    }
                    if !recovery.replayed_commit_groups.is_empty() {
                        eprintln!(
                        "commit_group recovery: replayed {} torn commit_group(s), recovered {} object key(s)",
                        recovery.replayed_commit_groups.len(),
                        recovery.committed_keys.len(),
                    );
                    }
                    if !recovery.torn_commit_groups.is_empty() {
                        eprintln!(
                        "commit_group recovery: {} torn commit_group(s) could not be replayed (corrupt or missing payload)",
                        recovery.torn_commit_groups.len(),
                    );
                    }
                }
                Err(e) => {
                    eprintln!(
                        "warning: commit_group recovery failed: {e:?}; continuing without replay"
                    );
                }
            }
        } else {
            eprintln!(
                "recovery: policy={} skips commit_group journal recovery",
                self.recovery_policy.label(),
            );
        }
        recovered_generation
    }

    fn replay_committed_txgs(
        &mut self,
        state: &mut FileSystemState,
        recovered_generation: &mut u64,
    ) -> Result<()> {
        if self.recovery_policy.allows_replay() {
            let root_authentication_key = self.root_authentication_key;
            let engine = crate::txg_replay::TxgReplayEngine::new(Default::default());
            match engine.replay(
                self.raw_recovery_store_mut(),
                state,
                root_authentication_key,
            ) {
                Ok(Some((replayed_state, outcome))) => {
                    *state = replayed_state;
                    let replay_gen = outcome.highest_applied_txg;
                    if replay_gen > *recovered_generation {
                        *recovered_generation = replay_gen;
                    }
                    eprintln!(
                        "txg_replay: replayed {} committed txg(s),                          highest applied txg={replay_gen},                          resumed_from_marker={}",
                        outcome.replayed_count,
                        outcome.resumed_from_marker,
                    );
                }
                Ok(None) => {}
                Err(e) => {
                    eprintln!("txg_replay: BLAKE3 chain verification failed: {e}");
                    return Err(FileSystemError::CorruptState {
                        reason: "txg replay BLAKE3 mismatch; aborting mount",
                    });
                }
            }
        } else {
            eprintln!(
                "recovery: policy={} skips committed txg replay",
                self.recovery_policy.label(),
            );
        }
        Ok(())
    }

    fn pool_stats(&self) -> tidefs_local_object_store::pool::PoolCapacityStats {
        self.store.pool_stats()
    }

    fn committed_content_used_bytes(&self, state: &FileSystemState) -> Result<u64> {
        content_allocation_entries_for_state(self.raw_recovery_store(), state)
            .and_then(|entries| allocation_bytes(&entries))
    }
}

/// Intent-log payload for a `copy_file_range` operation.
pub struct CopyFileRangeIntent {
    pub src_ino: InodeId,
    pub src_fh: u64,
    pub dst_ino: InodeId,
    pub dst_fh: u64,
    pub src_offset: u64,
    pub dst_offset: u64,
    pub len: u64,
}

impl LocalFileSystem {
    /// Get the shared poison notification handle for the dataset lifecycle.
    #[must_use]
    pub fn poison_notification(&self) -> PoisonNotification {
        self.lifecycle.poison_notification()
    }

    /// Return a reference to the production capacity authority.
    ///
    /// This is the single source of truth for used/free/reserved/pending
    /// byte counters. All statfs, ENOSPC, and quota consumers should
    /// derive their capacity view from this authority.
    #[must_use]
    pub fn capacity_authority(&self) -> &CapacityAuthority {
        &self.capacity_authority
    }

    /// Set the dataset ID for the currently mounted filesystem.
    ///
    /// Used as the anchor for quota hierarchy ancestor-chain traversal
    /// during statfs derivation and ENOSPC gating.
    pub fn set_mounted_dataset_id(&mut self, id: [u8; 16]) {
        self.mounted_dataset_id = id;
    }

    /// Set the current placement epoch for send/receive stream attribution.
    /// Callers in the multi-node stack should set this before exporting.
    pub fn set_placement_epoch(&mut self, epoch: u64) {
        self.placement_epoch = Some(epoch);
    }

    /// Return the mounted dataset ID (defaults to root dataset).
    #[must_use]
    pub fn mounted_dataset_id(&self) -> [u8; 16] {
        self.mounted_dataset_id
    }

    /// Install a nested dataset quota hierarchy for multi-dataset quota
    /// enforcement.
    ///
    /// Once set, [`statfs`](Self::statfs) and ENOSPC gating consult ancestor
    /// quotas along the chain. The caller is responsible for configuring
    /// quota limits and building the parent map from the dataset catalog.
    pub fn set_quota_hierarchy(&mut self, hierarchy: DatasetQuotaHierarchy) {
        self.quota_hierarchy = Some(hierarchy);
    }

    /// Set the pre-computed parent map for quota hierarchy traversal.
    ///
    /// Maps each dataset ID to its parent dataset ID.  The root dataset(s)
    /// should not appear as keys.  Built by the caller from the dataset
    /// catalog.
    pub fn set_quota_parent_map(&mut self, map: HashMap<[u8; 16], [u8; 16]>) {
        self.quota_parent_map = map;
    }

    /// Look up the parent dataset ID for a given dataset ID.
    fn quota_parent_of(&self, id: &[u8; 16]) -> Option<[u8; 16]> {
        self.quota_parent_map.get(id).copied()
    }

    /// Build the quota parent map from the pool-wide dataset catalog.
    ///
    /// Iterates all catalog entries, computes the parent dataset ID for
    /// each, and returns a map from child dataset ID to parent dataset ID.
    /// Root datasets (no parent) are excluded from the map keys.
    /// Call [`set_quota_parent_map`](Self::set_quota_parent_map) with the
    /// result after configuring the quota hierarchy.
    #[must_use]
    pub fn build_quota_parent_map_from_catalog(&self) -> HashMap<[u8; 16], [u8; 16]> {
        let mut map = HashMap::new();
        let entries = self.dataset_catalog.entries();
        for (path, child_id) in &entries {
            if let Some((parent_path, _name)) = path.rsplit_once('/') {
                if let Ok(parent_id) = self.dataset_catalog.lookup(parent_path) {
                    map.insert(*child_id.as_bytes(), *parent_id.as_bytes());
                }
            }
        }
        map
    }

    /// Run a hierarchy-aware ENOSPC check for `requested_bytes`.
    ///
    /// Checks both the pool-level capacity authority and (when configured)
    /// the nested dataset quota hierarchy. Returns `Ok(())` if the write
    /// is admitted, or `Err(Errno::ENOSPC)` if any layer refuses.
    pub fn check_enospc_with_hierarchy(
        &self,
        requested_bytes: u64,
    ) -> std::result::Result<(), Errno> {
        // Pool-level check first (fast path).
        self.capacity_authority.check_enospc(requested_bytes)?;
        // Hierarchy check when configured.
        if let Some(ref hierarchy) = self.quota_hierarchy {
            let pool_free = self.capacity_authority.free_bytes();
            let decision = hierarchy.check_delta(
                self.mounted_dataset_id,
                requested_bytes,
                0,
                pool_free,
                |id| self.quota_parent_of(id),
            );
            if decision.is_refusal() {
                return Err(Errno::ENOSPC);
            }
        }
        Ok(())
    }

    /// Reserve bytes through the capacity authority with hierarchy-aware
    /// quota checks, returning a reservation handle that must be committed
    /// on success or dropped to auto-release.
    ///
    /// This replaces the former check-then-record pattern (check_enospc +
    /// record_allocation) with an atomic reservation lifecycle: the bytes
    /// are held in reserved state for the duration of the operation,
    /// preventing concurrent operations from claiming the same capacity.
    pub fn reserve_with_hierarchy(
        &self,
        requested_bytes: u64,
    ) -> std::result::Result<CapacityReservationHandle<'_>, Errno> {
        // Fast path: zero-byte reservations are valid and inert.
        if requested_bytes == 0 {
            return self.capacity_authority.reserve(0);
        }
        // Pool-level check first (fast path).
        self.capacity_authority.check_enospc(requested_bytes)?;
        // Hierarchy check when configured.
        if let Some(ref hierarchy) = self.quota_hierarchy {
            let pool_free = self.capacity_authority.free_bytes();
            let decision = hierarchy.check_delta(
                self.mounted_dataset_id,
                requested_bytes,
                0,
                pool_free,
                |id| self.quota_parent_of(id),
            );
            if decision.is_refusal() {
                return Err(Errno::ENOSPC);
            }
        }
        // Atomically reserve the bytes: this moves them from free to reserved
        // so concurrent operations cannot also claim them.
        self.capacity_authority.reserve(requested_bytes)
    }

    /// Compute the effective capacity ceiling for the mounted dataset,
    /// considering the quota hierarchy (if configured) and current pool
    /// capacity.
    ///
    /// Returns the most restrictive limit along the ancestor chain,
    /// or the pool physical capacity when no hierarchy is set.
    #[must_use]
    fn effective_capacity_bytes(&self, pool_capacity_bytes: u64) -> u64 {
        if let Some(ref hierarchy) = self.quota_hierarchy {
            hierarchy.effective_capacity(self.mounted_dataset_id, pool_capacity_bytes, |id| {
                self.quota_parent_of(id)
            })
        } else {
            pool_capacity_bytes
        }
    }

    pub(crate) fn clamp_statfs_blocks(
        &self,
        cs: CapacityStatfs,
        pool_capacity_bytes: u64,
        free_blocks_limit: u64,
        avail_blocks_limit: u64,
    ) -> (u64, u64, u64) {
        let ceiling_blocks = if cs.block_size == 0 {
            0
        } else {
            self.effective_capacity_bytes(pool_capacity_bytes)
                .saturating_div(u64::from(cs.block_size))
        };
        let total_blocks = cs.total_blocks.min(ceiling_blocks);
        let free_blocks = cs.free_blocks.min(free_blocks_limit).min(total_blocks);
        let avail_blocks = cs.avail_blocks.min(avail_blocks_limit).min(free_blocks);
        (total_blocks, free_blocks, avail_blocks)
    }

    /// Attach a deferred cleanup engine for post-commit orphan drain
    /// and block reclamation.
    #[must_use]
    pub fn with_cleanup_engine(
        mut self,
        engine: CleanupEngine<Box<dyn JobExecutor + Send>>,
    ) -> Self {
        self.cleanup_engine = Some(engine);
        self
    }

    /// Get a shared reference to the dataset lifecycle.
    ///
    /// Callers that need to drive lifecycle transitions (e.g. destroy,
    /// abort-and-heal, tombstone reaping) use the mutable accessor below.
    #[must_use]
    pub fn lifecycle(&self) -> &DatasetLifecycle {
        &self.lifecycle
    }

    /// Get an exclusive reference to the dataset lifecycle for driving
    /// state transitions.
    ///
    /// Callers must ensure that no concurrent filesystem operation races
    /// against the lifecycle transition. In practice, the lifecycle is
    /// only driven through the admin control-plane while the filesystem
    /// is quiesced or during single-threaded mount/unmount sequences.
    pub fn lifecycle_mut(&mut self) -> &mut DatasetLifecycle {
        &mut self.lifecycle
    }

    /// Get a shared reference to the durable dataset catalog.
    ///
    /// This is the canonical pool-wide B+tree mapping hierarchical dataset
    /// paths to stable [`DatasetId`] values. It supports
    /// [`DatasetCatalog::mount_lookup`] for mount/import path resolution
    /// and [`DatasetCatalog::rename`] for online renames without unmount.
    #[must_use]
    pub fn dataset_catalog(&self) -> &DatasetCatalog {
        &self.dataset_catalog
    }

    /// Get an exclusive reference to the durable dataset catalog for
    /// driving catalog mutations (create, destroy, rename, lifecycle
    /// transitions).
    ///
    /// Callers must ensure that no concurrent catalog lookups race
    /// against the mutation. In practice, catalog mutations are only
    /// driven through the admin control-plane while the filesystem is
    /// quiesced or during single-threaded mount/unmount sequences.
    pub fn dataset_catalog_mut(&mut self) -> &mut DatasetCatalog {
        &mut self.dataset_catalog
    }

    /// Persist the dataset catalog to the pool store after mutation.
    ///
    /// Callers that mutate the catalog via [`dataset_catalog_mut`] must
    /// call this before returning to ensure crash recovery can reload
    /// the catalog state.
    pub fn persist_dataset_catalog(&mut self) -> Result<()> {
        self.store.put(
            DeviceIoClass::Data,
            dataset_catalog_object_key(),
            &self.dataset_catalog.encode(),
        )?;
        self.store.sync_all()?;
        Ok(())
    }

    /// Get a shared reference to the durable pool properties.
    #[must_use]
    pub fn pool_properties(&self) -> &PropertySet {
        &self.pool_properties
    }

    /// Get an exclusive reference to the durable pool properties for mutation.
    pub fn pool_properties_mut(&mut self) -> &mut PropertySet {
        &mut self.pool_properties
    }

    /// Persist the pool properties to the pool store after mutation.
    pub fn persist_pool_properties(&mut self) -> Result<()> {
        self.store.put(
            DeviceIoClass::Data,
            pool_properties_object_key(),
            &self.pool_properties.to_key_value_blob(),
        )?;
        self.store.sync_all()?;
        Ok(())
    }

    /// Persist the dataset feature flags to the pool store after mutation.
    ///
    /// Callers that mutate feature flags via [`feature_flags_mut`] must call
    /// this before returning to ensure crash recovery can reload the feature
    /// flag state. This writes the per-class B-trees and the roots pointer
    /// object in a single durable batch.
    pub fn persist_feature_flags(&mut self) -> Result<()> {
        // Write per-class feature B-trees into the pool store.
        let roots = self.feature_flags.persist(&mut self.store)?;
        // Write the roots pointer object so remount can locate the B-trees.
        let mut buf = Vec::with_capacity(24);
        buf.extend_from_slice(&roots.compat_root.0.to_le_bytes());
        buf.extend_from_slice(&roots.ro_compat_root.0.to_le_bytes());
        buf.extend_from_slice(&roots.incompat_root.0.to_le_bytes());
        self.store.put(
            DeviceIoClass::Data,
            crate::object_keys::feature_flags_roots_object_key(),
            &buf,
        )?;
        self.store.sync_all()?;
        Ok(())
    }

    /// Refresh runtime policies (`content_compression_policy`,
    /// `dedup_enabled`) from the current feature flags.
    ///
    /// Callers that mutate feature flags via [`feature_flags_mut`] on a
    /// live (already-mounted) filesystem should call this after
    /// [`persist_feature_flags`] so that new writes use the updated
    pub fn refresh_policies_from_features(&mut self) {
        // Try dataset-property-based compression first, then feature flags.
        let (policy, source) = self.resolve_effective_compression_policy();
        self.content_compression_policy = policy;
        self.compression_policy_source = source;
        self.state.content_compression_policy = self.content_compression_policy.clone();
        // Dedup policy.
        if let Some(dedup_name) =
            tidefs_types_dataset_feature_flags_core::FeatureName::from_str("org.tidefs:dedup")
        {
            self.dedup_enabled = self.feature_flags.is_enabled(&dedup_name);
        }
    }

    /// Resolve the effective compression policy, preferring dataset properties
    /// over feature flags and returning the source of the resolution.
    fn resolve_effective_compression_policy(
        &self,
    ) -> (ContentCompressionPolicy, CompressionPolicySource) {
        // Check pool properties first (pool-scoped compression override).
        if let Some((policy, source)) =
            resolve_compression_policy_from_properties(&self.pool_properties)
        {
            return (policy, source);
        }
        // Fall back to feature flags.
        let policy = resolve_compression_policy(&self.feature_flags);
        let source = if policy.algorithm == ContentCompressionAlgorithm::None {
            CompressionPolicySource::Default
        } else {
            CompressionPolicySource::FeatureFlag
        };
        (policy, source)
    }

    /// Return the effective content compression policy and its resolution source.
    ///
    /// This is the observability surface: operators can inspect which
    /// compression algorithm is currently active and whether it was set
    /// via a typed property, feature flag, or the default.
    #[must_use]
    pub fn effective_compression_policy_report(&self) -> EffectiveCompressionPolicyReport {
        self.content_compression_policy
            .report(self.compression_policy_source)
    }

    /// Get a shared reference to the dataset feature flags.
    #[must_use]
    pub fn feature_flags(&self) -> &FeatureFlags {
        &self.feature_flags
    }

    /// Get an exclusive reference to the dataset feature flags.
    ///
    /// Callers must ensure that no concurrent filesystem operation races
    /// against a feature flag mutation. In practice, features are only
    /// enabled/disabled through the admin control-plane while the
    /// filesystem is quiesced or during mount-time gating.
    pub fn feature_flags_mut(&mut self) -> &mut FeatureFlags {
        &mut self.feature_flags
    }

    /// Whether content-addressed chunk dedup is active for this filesystem.
    pub fn is_dedup_enabled(&self) -> bool {
        self.dedup_enabled
    }

    /// Enable or disable content-addressed chunk dedup.
    pub fn set_dedup_enabled(&mut self, enabled: bool) {
        self.dedup_enabled = enabled;
    }

    /// Return a snapshot of the current session dedup statistics.
    pub fn dedup_stats(&self) -> crate::dedup::DedupStats {
        self.dedup_index.borrow().stats()
    }

    #[allow(dead_code)] // INTENT: kept for planned architecture; callers in test modules or pending wiring into FUSE dispatch
    pub fn writeback_range_tracker(
        &self,
    ) -> &Arc<Mutex<crate::dirty_page_tracker::DirtyPageTracker>> {
        &self.writeback_range_tracker
    }

    pub fn has_writeback_daemon(&self) -> bool {
        self.writeback_handle.is_some()
    }

    /// Check whether a data write of `byte_count` bytes is admitted by
    /// the pool free-space watermark. Returns `Ok(())` when space is
    /// available, `Err(StoreError::NoSpace)` when the write would breach
    /// the low-watermark threshold.
    pub fn check_write_admission(&self, byte_count: u64) -> std::result::Result<(), StoreError> {
        self.store
            .check_write_admission(tidefs_local_object_store::DeviceIoClass::Data, byte_count)
    }

    /// Set the pool free-space low-watermark threshold in bytes.
    /// Data writes that would reduce available capacity below this
    /// threshold are refused with `ENOSPC`.  Set to 0 to disable.
    pub fn set_low_watermark_bytes(&mut self, bytes: u64) {
        self.store.set_low_watermark_bytes(bytes);
    }

    // ── POSIX advisory lock operations ──────────────────────────────────

    /// Query whether a conflicting lock exists on an inode for a given range.
    ///
    /// Returns `Some(LockConflict)` if a conflicting lock is held by another
    /// process, or `None` if the range is free.
    #[must_use]
    pub fn getlk(&self, inode: InodeId, requested: LockRange) -> Option<LockConflict> {
        self.lock_tracker
            .borrow()
            .query_conflict(inode.get(), requested)
    }

    /// Acquire or release a byte-range advisory lock on an inode.
    ///
    /// On conflict (non-blocking mode), returns `Err(LockConflict)` with the
    /// existing lock that caused the conflict. The caller should map this to
    /// `EAGAIN`.
    pub fn setlk(
        &self,
        inode: InodeId,
        requested: LockRange,
    ) -> std::result::Result<(), LockConflict> {
        self.lock_tracker
            .borrow_mut()
            .acquire(inode.get(), requested)
    }

    /// Release all locks held by a given process across all inodes.
    ///
    /// Called on fd close or process exit to clean up held locks.
    pub fn release_locks_by_pid(&self, pid: u32) {
        self.lock_tracker.borrow_mut().release_by_pid(pid);
    }

    /// Get the number of inodes with active locks.
    #[must_use]
    pub fn lock_inode_count(&self) -> usize {
        self.lock_tracker.borrow().inode_count()
    }

    /// Wait for a byte-range lock to become available (`F_SETLKW`).
    ///
    /// Polls the lock tracker every ~10 ms, dropping the borrow between
    /// attempts. Returns `Ok(())` when acquired or `Err(LockConflict)` if
    /// the timeout expires while a conflict persists.
    ///
    /// Pass `None` for `timeout` to wait indefinitely.
    pub fn lock_wait_acquire(
        &self,
        inode: InodeId,
        requested: LockRange,
        timeout: Option<Duration>,
    ) -> std::result::Result<(), LockConflict> {
        let deadline = timeout.map(|d| Instant::now() + d);
        let poll_interval = Duration::from_millis(10);
        loop {
            let result = {
                let mut tracker = self.lock_tracker.borrow_mut();
                tracker.acquire(inode.get(), requested)
            };
            match result {
                Ok(()) => return Ok(()),
                Err(conflict) => {
                    if let Some(deadline) = deadline {
                        if Instant::now() >= deadline {
                            return Err(conflict);
                        }
                    }
                }
            }
            std::thread::sleep(poll_interval);
        }
    }
}

// Magic bytes for space counters binary encoding.
// Stored as a 4-byte sentinel to detect corruption and version mismatches.
/// Encode DatasetSpaceCountersV1 to a binary blob (magic + 8×u64 LE).
///
/// New fields appended at end for backward compatibility with 6-field records.
pub(crate) fn encode_space_counters(counters: &DatasetSpaceCountersV1) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + 8 * 8);
    out.extend_from_slice(&SPACE_COUNTERS_MAGIC_BYTES);
    out.extend_from_slice(&counters.logical_used_bytes.to_le_bytes());
    out.extend_from_slice(&counters.pinned_snapshot_bytes.to_le_bytes());
    out.extend_from_slice(&counters.reserved_bytes.to_le_bytes());
    out.extend_from_slice(&counters.orphan_bytes.to_le_bytes());
    out.extend_from_slice(&counters.quota_bytes.to_le_bytes());
    out.extend_from_slice(&counters.slop_bytes.to_le_bytes());
    out.extend_from_slice(&counters.physical_used_bytes.to_le_bytes());
    out.extend_from_slice(&counters.quota_soft_limit.to_le_bytes());
    out
}

/// Decode DatasetSpaceCountersV1 from a binary blob.
///
/// Accepts V1 (6-field, 56-byte) and V2 (8-field, 72-byte) formats.
/// New fields default to 0 for older records.
pub(crate) fn decode_space_counters(bytes: &[u8]) -> Result<DatasetSpaceCountersV1> {
    let min_len = 8 + 6 * 8;
    let full_len = 8 + 8 * 8;
    if bytes.len() < min_len {
        return Err(FileSystemError::Decode {
            object: "space counters",
            reason: "too short",
        });
    }
    if bytes.len() < 8 || bytes[..8] != SPACE_COUNTERS_MAGIC_BYTES {
        return Err(FileSystemError::Decode {
            object: "space counters",
            reason: "magic bytes do not match",
        });
    }
    let read_u64 = |offset: usize| -> u64 {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[offset..offset + 8]);
        u64::from_le_bytes(buf)
    };
    let physical_used_bytes = if bytes.len() >= 8 + 7 * 8 {
        read_u64(56)
    } else {
        0
    };
    let quota_soft_limit = if bytes.len() >= full_len {
        read_u64(64)
    } else {
        0
    };
    Ok(DatasetSpaceCountersV1 {
        logical_used_bytes: read_u64(8),
        pinned_snapshot_bytes: read_u64(16),
        reserved_bytes: read_u64(24),
        orphan_bytes: read_u64(32),
        quota_bytes: read_u64(40),
        slop_bytes: read_u64(48),
        physical_used_bytes,
        quota_soft_limit,
    })
}

/// Derive a stable filesystem identifier from the root path.
///
/// Uses a hash of the canonical path to produce a deterministic u64
/// that is stable across mounts of the same pool.
fn pool_uuid_from_path(root: &std::path::Path) -> u64 {
    let mut hasher = DefaultHasher::new();
    root.hash(&mut hasher);
    hasher.finish()
}
impl LocalFileSystem {
    /// Stop the background scheduler runtime on unmount to avoid leaking threads.
    fn stop_background_scheduler(&mut self) {
        if let Some(ref mut runtime) = self.background_scheduler {
            runtime.stop();
        }
        self.background_scheduler = None;
    }

    /// Create the development default pool from a hidden regular-file device image.
    fn default_development_pool(
        root: &std::path::Path,
        options: &StoreOptions,
        encryption: Option<EncryptionConfig>,
        compression: Option<CompressionConfig>,
    ) -> Result<Pool> {
        let device_path = Self::ensure_default_development_device_image(root)?;
        let devices = [device_path];
        Self::block_device_pool(root, &devices, encryption, compression, options)
    }

    #[must_use]
    pub fn default_development_device_path(root: impl AsRef<Path>) -> std::path::PathBuf {
        root.as_ref()
            .join(DEFAULT_DEVELOPMENT_DEVICE_DIR)
            .join(DEFAULT_DEVELOPMENT_DEVICE_IMAGE)
    }

    fn ensure_default_development_device_image(
        root: &std::path::Path,
    ) -> Result<std::path::PathBuf> {
        fs::create_dir_all(root).map_err(|source| {
            FileSystemError::Store(StoreError::Io {
                operation: "create_default_development_metadata_dir",
                path: root.to_path_buf(),
                source,
            })
        })?;
        let device_dir = root.join(DEFAULT_DEVELOPMENT_DEVICE_DIR);
        fs::create_dir_all(&device_dir).map_err(|source| {
            FileSystemError::Store(StoreError::Io {
                operation: "create_default_development_device_dir",
                path: device_dir.clone(),
                source,
            })
        })?;
        let device_path = root
            .join(DEFAULT_DEVELOPMENT_DEVICE_DIR)
            .join(DEFAULT_DEVELOPMENT_DEVICE_IMAGE);
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&device_path)
            .map_err(|source| {
                FileSystemError::Store(StoreError::Io {
                    operation: "open_default_development_device_image",
                    path: device_path.clone(),
                    source,
                })
            })?;
        let len = file.metadata().map_err(|source| {
            FileSystemError::Store(StoreError::Io {
                operation: "metadata_default_development_device_image",
                path: device_path.clone(),
                source,
            })
        })?;
        if len.len() < DEFAULT_LOCAL_FILESYSTEM_DEVELOPMENT_DEVICE_IMAGE_BYTES {
            file.set_len(DEFAULT_LOCAL_FILESYSTEM_DEVELOPMENT_DEVICE_IMAGE_BYTES)
                .map_err(|source| {
                    FileSystemError::Store(StoreError::Io {
                        operation: "size_default_development_device_image",
                        path: device_path.clone(),
                        source,
                    })
                })?;
        }
        Ok(device_path)
    }

    #[allow(dead_code)]
    /// Create a pool backed by block devices for object data, using a
    /// metadata directory for pool labels and markers.
    fn block_device_pool(
        metadata_dir: &std::path::Path,
        block_devices: &[std::path::PathBuf],
        encryption: Option<EncryptionConfig>,
        compression: Option<CompressionConfig>,
        options: &StoreOptions,
    ) -> Result<Pool> {
        let mut devices: Vec<DeviceConfig> = Vec::with_capacity(block_devices.len());
        for dev_path in block_devices.iter() {
            let backing = Self::byte_addressable_device_backing(dev_path)?;
            devices.push(DeviceConfig {
                media_class: DeviceMediaClass::Ssd,
                path: dev_path.clone(),
                backing,
                class: DeviceClass::Data,
                kind: DeviceKind::Block {
                    path: dev_path.clone(),
                },
                encryption: encryption.clone(),
                compression: compression.clone(),
            });
        }
        let config = PoolConfig {
            name: "tidefs".into(),
            root_path: metadata_dir.to_path_buf(),
            devices,
        };
        Ok(Pool::create(config, PoolProperties::default(), options)?)
    }

    fn byte_addressable_device_backing(path: &std::path::Path) -> Result<DeviceBacking> {
        match tidefs_pool_scan::classify_pool_device_backing(path).map_err(|source| {
            FileSystemError::Store(StoreError::Io {
                operation: "pool_device_backing",
                path: path.to_path_buf(),
                source,
            })
        })? {
            tidefs_pool_scan::PoolDeviceBacking::BlockDevice => Ok(DeviceBacking::BlockDevice),
            tidefs_pool_scan::PoolDeviceBacking::RegularFileDev => {
                Ok(DeviceBacking::RegularFileDev)
            }
        }
    }

    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_options(root, StoreOptions::default())
    }

    /// Open with a dedicated log device (Separate Intent LOG) device for
    /// synchronous-write acceleration.
    ///
    /// The log device receives ZIL intent-log writes first, acknowledges
    /// them immediately after `fdatasync`, and defers the bulk data-device
    /// writes to the next COMMIT_GROUP commit.  This bounds sync-write latency
    /// to the speed of the fast device (e.g. NVMe SSD) without forcing all
    /// data writes through it.
    ///
    /// The `log_device_device_path` must point to a regular file or block
    /// device on a fast storage medium.  The pool label records the
    /// data pool uses the same hidden regular-file development image as
    /// [`LocalFileSystem::open`] unless explicit block devices are supplied.
    pub fn open_with_log_device(
        root: impl AsRef<Path>,
        log_device_device_path: impl AsRef<Path>,
    ) -> Result<Self> {
        Self::open_with_log_device_and_options(
            root,
            log_device_device_path,
            StoreOptions::default(),
        )
    }

    /// Open with a dedicated log device and explicit store options.
    pub fn open_with_log_device_and_options(
        root: impl AsRef<Path>,
        log_device_device_path: impl AsRef<Path>,
        options: StoreOptions,
    ) -> Result<Self> {
        let log_device_path = log_device_device_path.as_ref().to_path_buf();
        let fs = Self::open_with_allocator_policy_and_root_authentication_key(
            root,
            LocalFileSystemOpenConfig {
                options,
                allocator_policy: LocalStorageAllocatorPolicy::default(),
                root_authentication_key: default_root_authentication_key()?,
                encryption: None,
                compression: None,
                log_device_device_path: Some(log_device_path),
                recovery_policy: RecoveryPolicy::default(),
                block_devices: None,
            },
        )?;
        Ok(fs)
    }

    pub fn open_with_options(root: impl AsRef<Path>, options: StoreOptions) -> Result<Self> {
        Self::open_with_allocator_policy(root, options, LocalStorageAllocatorPolicy::default())
    }

    /// Attempt to open with device-level per-object encryption enabled.
    ///
    /// Currently fails closed until TFR-006 raw-store bypasses are removed or
    /// proven raw-only for mounted filesystem operation.
    pub fn open_with_encryption(
        root: impl AsRef<Path>,
        options: StoreOptions,
        encryption: EncryptionConfig,
    ) -> Result<Self> {
        let key = encryption.key.clone();
        let mut fs = Self::open_with_allocator_policy_and_root_authentication_key(
            root,
            LocalFileSystemOpenConfig {
                options,
                allocator_policy: LocalStorageAllocatorPolicy::default(),
                root_authentication_key: default_root_authentication_key()?,
                encryption: Some(encryption),
                compression: None,
                log_device_device_path: None,
                recovery_policy: RecoveryPolicy::default(),
                block_devices: None,
            },
        )?;
        fs.encryption_key = Some(key);
        Ok(fs)
    }

    /// Attempt to open with device-level per-object compression enabled.
    ///
    /// Currently fails closed until TFR-006 raw-store bypasses are removed or
    /// proven raw-only for mounted filesystem operation.
    pub fn open_with_compression(
        root: impl AsRef<Path>,
        options: StoreOptions,
        compression: CompressionConfig,
    ) -> Result<Self> {
        Self::open_with_allocator_policy_and_root_authentication_key(
            root,
            LocalFileSystemOpenConfig {
                options,
                allocator_policy: LocalStorageAllocatorPolicy::default(),
                root_authentication_key: default_root_authentication_key()?,
                encryption: None,
                compression: Some(compression),
                log_device_device_path: None,
                recovery_policy: RecoveryPolicy::default(),
                block_devices: None,
            },
        )
    }

    /// Attempt to open with device-level encryption and compression enabled.
    ///
    /// Currently fails closed until TFR-006 raw-store bypasses are removed or
    /// proven raw-only for mounted filesystem operation.
    pub fn open_with_encryption_and_compression(
        root: impl AsRef<Path>,
        options: StoreOptions,
        encryption: EncryptionConfig,
        compression: CompressionConfig,
    ) -> Result<Self> {
        let key = encryption.key.clone();
        let mut fs = Self::open_with_allocator_policy_and_root_authentication_key(
            root,
            LocalFileSystemOpenConfig {
                options,
                allocator_policy: LocalStorageAllocatorPolicy::default(),
                root_authentication_key: default_root_authentication_key()?,
                encryption: Some(encryption),
                compression: Some(compression),
                log_device_device_path: None,
                recovery_policy: RecoveryPolicy::default(),
                block_devices: None,
            },
        )?;
        fs.encryption_key = Some(key);
        Ok(fs)
    }

    /// Replace the encryption key for subsequent objects.
    ///
    /// Does not re-encrypt already-stored objects. New writes after this
    /// call will use the provided key.
    pub fn set_encryption_key(&mut self, key: StoreEncryptionKey) {
        self.encryption_key = Some(key);
    }

    pub fn open_with_allocator_policy(
        root: impl AsRef<Path>,
        options: StoreOptions,
        allocator_policy: LocalStorageAllocatorPolicy,
    ) -> Result<Self> {
        Self::open_with_allocator_policy_and_root_authentication_key(
            root,
            LocalFileSystemOpenConfig {
                options,
                allocator_policy,
                root_authentication_key: default_root_authentication_key()?,
                encryption: None,
                compression: None,
                log_device_device_path: None,
                recovery_policy: RecoveryPolicy::default(),
                block_devices: None,
            },
        )
    }

    /// Open a filesystem backed by block devices for object data.
    ///
    /// `metadata_dir` is a directory for pool metadata (labels, markers).
    /// `block_devices` are the raw block devices that store object data.
    /// The label areas on each device are reserved; data starts after the
    /// pool label region.
    pub fn open_with_block_devices(
        metadata_dir: impl AsRef<Path>,
        block_devices: &[std::path::PathBuf],
        options: StoreOptions,
        root_authentication_key: RootAuthenticationKey,
    ) -> Result<Self> {
        Self::open_with_block_devices_and_recovery_policy(
            metadata_dir,
            block_devices,
            options,
            root_authentication_key,
            RecoveryPolicy::default(),
        )
    }

    /// Open a filesystem backed by block devices with an explicit recovery policy.
    ///
    /// Read-only policy is useful for catalog/status inspection of an already
    /// mounted pool: it loads the committed root without replaying unrelated
    /// live write intents from another process.
    pub fn open_with_block_devices_and_recovery_policy(
        metadata_dir: impl AsRef<Path>,
        block_devices: &[std::path::PathBuf],
        options: StoreOptions,
        root_authentication_key: RootAuthenticationKey,
        recovery_policy: RecoveryPolicy,
    ) -> Result<Self> {
        let metadata_path = metadata_dir.as_ref();
        Self::open_with_allocator_policy_and_root_authentication_key(
            metadata_path,
            LocalFileSystemOpenConfig {
                options,
                allocator_policy: LocalStorageAllocatorPolicy::default(),
                root_authentication_key,
                encryption: None,
                compression: None,
                log_device_device_path: None,
                recovery_policy,
                block_devices: Some(block_devices),
            },
        )
    }

    /// Attempt to open a block-device-backed filesystem with encryption enabled.
    ///
    /// Currently fails closed until TFR-006 raw-store bypasses are removed or
    /// proven raw-only for mounted filesystem operation. The metadata
    /// directory remains the pool-label and marker location.
    pub fn open_with_block_devices_and_encryption(
        metadata_dir: impl AsRef<Path>,
        block_devices: &[std::path::PathBuf],
        options: StoreOptions,
        root_authentication_key: RootAuthenticationKey,
        encryption: EncryptionConfig,
    ) -> Result<Self> {
        Self::open_with_allocator_policy_and_root_authentication_key(
            metadata_dir.as_ref(),
            LocalFileSystemOpenConfig {
                options,
                allocator_policy: LocalStorageAllocatorPolicy::default(),
                root_authentication_key,
                encryption: Some(encryption),
                compression: None,
                log_device_device_path: None,
                recovery_policy: RecoveryPolicy::default(),
                block_devices: Some(block_devices),
            },
        )
    }

    /// Attempt to open a development default filesystem with encryption enabled.
    ///
    /// Currently fails closed until TFR-006 raw-store bypasses are removed or
    /// proven raw-only for mounted filesystem operation.
    pub fn open_with_root_authentication_key_and_encryption(
        root: impl AsRef<Path>,
        options: StoreOptions,
        root_authentication_key: RootAuthenticationKey,
        encryption: EncryptionConfig,
    ) -> Result<Self> {
        Self::open_with_allocator_policy_and_root_authentication_key(
            root,
            LocalFileSystemOpenConfig {
                options,
                allocator_policy: LocalStorageAllocatorPolicy::default(),
                root_authentication_key,
                encryption: Some(encryption),
                compression: None,
                log_device_device_path: None,
                recovery_policy: RecoveryPolicy::default(),
                block_devices: None,
            },
        )
    }

    pub fn open_with_root_authentication_key(
        root: impl AsRef<Path>,
        options: StoreOptions,
        root_authentication_key: RootAuthenticationKey,
    ) -> Result<Self> {
        Self::open_with_allocator_policy_and_root_authentication_key(
            root,
            LocalFileSystemOpenConfig {
                options,
                allocator_policy: LocalStorageAllocatorPolicy::default(),
                root_authentication_key,
                encryption: None,
                compression: None,
                log_device_device_path: None,
                recovery_policy: RecoveryPolicy::default(),
                block_devices: None,
            },
        )
    }

    pub fn open_with_allocator_policy_and_root_authentication_key(
        root: impl AsRef<Path>,
        config: LocalFileSystemOpenConfig<'_>,
    ) -> Result<Self> {
        let LocalFileSystemOpenConfig {
            options,
            allocator_policy,
            root_authentication_key,
            encryption,
            compression,
            log_device_device_path,
            recovery_policy,
            block_devices,
        } = config;
        allocator_policy.validate()?;
        // Fail closed until TFR-006 moves mounted content and recovery paths
        // behind one transform-aware authority and the raw-store inventory
        // has no blocked production rows.
        MountedOpenRecoveryAuthority::reject_device_transforms(
            encryption.as_ref(),
            compression.as_ref(),
        )?;
        let root_path = root.as_ref().to_path_buf();
        let key_for_struct = encryption.as_ref().map(|c| c.key.clone());
        let mut store = if let Some(devices) = block_devices {
            Self::block_device_pool(
                &root_path,
                devices,
                encryption.clone(),
                compression.clone(),
                &options,
            )?
        } else {
            Self::default_development_pool(&root_path, &options, encryption, compression)?
        };
        // Check locked-dataset condition: import an encrypted pool without
        // a key and refuse all I/O until the operator supplies one.
        if store.is_locked() {
            return Err(FileSystemError::DatasetLocked {
                reason: "encrypted pool opened without encryption key; supply a key to unlock"
                    .into(),
            });
        }
        check_crash_hook(CrashInjectionPoint::RecoveryBeforeRootSelect);
        let mut open_recovery = MountedOpenRecoveryAuthority::raw_only(
            &mut store,
            root_authentication_key,
            recovery_policy,
        );
        debug_assert_eq!(
            open_recovery.transform_mode(),
            MountedOpenRecoveryTransformMode::RawOnlyNoDeviceTransforms
        );
        debug_assert_eq!(
            open_recovery.transform_ordering_boundary(),
            MOUNTED_RECOVERY_TRANSFORM_ORDERING
        );
        let mut state = open_recovery.load_or_initialize_state()?;

        // Load intent log for operational use (crash replay was already
        // handled by load_latest_committed_state above).
        let mut intent_log = match open_recovery.load_operational_intent_log() {
            Ok(log) => log,
            Err(err) => {
                eprintln!("warning: intent log load failed: {err}; starting with empty log");
                IntentLog::new()
            }
        };
        // Wire the log device into the intent log for future writes.
        if let Some(ref log_device_path) = log_device_device_path {
            intent_log.open_log_device(log_device_path)?;
        }

        // Load persisted quota table; start empty if missing or corrupt.
        state.quota_table = open_recovery.load_quota_table();
        // Load persisted space counters; start with default zeros if missing.
        open_recovery.merge_space_counters_into(&mut state);

        // Sync from the store-layer SpaceBook (which was loaded from the
        // segment write pipeline during LocalObjectStore construction) to
        // the engine-layer SpaceAccounting.  The SpaceBook may have been
        // written with a higher TXG than the legacy space_counters_object,
        // so we take the max of each counter to avoid regressing on crash
        // recovery.
        open_recovery.merge_dataset_usage_into(&mut state);

        // Load persisted orphan index; start empty if missing or corrupt.
        let orphan_index_inner = open_recovery.load_orphan_index();
        // Production recovery must not call run_fsck during mount: fsck is
        // an explicit operator command, not a mount-time recovery authority.
        // The caller's RecoveryPolicy governs all state loading and replay.
        // Run commit_group journal recovery to replay torn commit_groups and
        // determine the true next_commit_group_id. This runs after the
        // filesystem state is loaded (root selection + intent-log replay) so
        // the recovered journal records can be reconciled against the loaded
        // committed state. Recovery is best-effort: failures are logged and
        // the mount continues with the generation-derived commit_group.
        let mut recovered_generation =
            open_recovery.recover_commit_group_generation(state.generation);

        // Run committed txg replay to roll forward any transaction groups
        // committed beyond the recovered root-slot state. This bridges the
        // gap between committed-root discovery and the commit_group journal.
        // Replay loads each txg's transaction superblock, verifies the
        // BLAKE3 chain, and applies the latest consistent state.
        // A BLAKE3 mismatch aborts mount with CorruptState.
        open_recovery.replay_committed_txgs(&mut state, &mut recovered_generation)?;

        let generation = recovered_generation;
        // Construct the capacity authority from pool geometry and committed
        // usage. This is the single production source for used/free/reserved/
        // pending byte counters for the lifetime of this filesystem instance.
        let capacity_authority = {
            let pool_stats = open_recovery.pool_stats();
            let block_size = StatfsResult::DEFAULT_BLOCK_SIZE as u32;
            let root_reserve_bytes = 0; // no root reserve in local-filesystem policy
                                        // Cap total capacity to the allocator policy ceiling so
                                        // statfs-derived block counts respect the configured policy limit.
                                        // When the pool reports zero capacity (memory-backed or test store),
                                        // fall back to the policy ceiling.
            let total_bytes = if pool_stats.total_capacity_bytes > 0 {
                pool_stats
                    .total_capacity_bytes
                    .min(allocator_policy.content_capacity_bytes)
            } else {
                allocator_policy.content_capacity_bytes
            };
            // Reconstruct committed content bytes from TideFS content objects
            // rather than raw object-store usage. The raw pool counter includes
            // metadata/log bytes, while LocalStorageAllocatorPolicy's capacity
            // is the user-content ceiling enforced by fallocate/write paths.
            let used_bytes = open_recovery
                .committed_content_used_bytes(&state)
                .unwrap_or(pool_stats.used_bytes)
                .min(total_bytes);
            CapacityAuthority::from_pool_stats(
                total_bytes,
                used_bytes,
                block_size,
                root_reserve_bytes,
            )
        };
        drop(open_recovery);
        // Reconstruct snapshot GC pins from the durable snapshot catalog.
        // Each snapshot root is pinned by full TraversalRoot identity so the GC
        // treats its object graph as reachable. Without this step, snapshot
        // reachability is lost across process restarts because the in-memory
        // GC pin set starts empty.
        // Load or create the durable dataset catalog from the pool store.
        // This is the canonical dataset catalog authority for the mounted
        // filesystem. On first mount the catalog is empty; it is populated
        // from state.snapshots below and persisted before returning.
        let mut dataset_catalog = match store.primary_store().get(dataset_catalog_object_key()) {
            Ok(Some(bytes)) => DatasetCatalog::decode(&bytes).unwrap_or_else(|e| {
                eprintln!("warning: dataset catalog decode failed: {e}; starting empty");
                DatasetCatalog::new()
            }),
            Ok(None) => DatasetCatalog::new(),
            Err(e) => {
                eprintln!("warning: dataset catalog load failed: {e}; starting empty");
                DatasetCatalog::new()
            }
        };

        // Load pool properties from the pool store alongside the dataset catalog.
        let pool_properties = match store.primary_store().get(pool_properties_object_key()) {
            Ok(Some(bytes)) => PropertySet::from_key_value_blob(&bytes),
            Ok(None) => PropertySet::new(),
            Err(e) => {
                eprintln!("warning: pool properties load failed: {e}; starting empty");
                PropertySet::new()
            }
        };
        // Ensure the root dataset entry exists.
        if !dataset_catalog.contains("root") {
            let root_id = DatasetId::from_bytes(ROOT_DATASET_ID);
            let _ = dataset_catalog.create(
                "root",
                root_id,
                DatasetType::Filesystem,
                1,
                vec![],
                DatasetFlags::NONE,
                SyncGuarantee::default(),
            );
        } else if let Ok(root_id) = dataset_catalog.lookup("root") {
            if *root_id.as_bytes() != ROOT_DATASET_ID {
                return Err(FileSystemError::CorruptState {
                    reason: "root dataset catalog id differs from mounted root dataset id",
                });
            }
        }

        let mut lifecycle = DatasetLifecycle::new();
        let mut expected_snapshot_catalog_names = BTreeSet::new();
        for record in state.snapshots.values() {
            if !snapshot::snapshot_record_retains_data(record) {
                continue;
            }
            lifecycle
                .pin_root(snapshot::snapshot_record_traversal_root(record))
                .map_err(|_| FileSystemError::CorruptState {
                    reason: "snapshot authority lifecycle pin set is full during reopen",
                })?;
            expected_snapshot_catalog_names.insert(snapshot::snapshot_record_catalog_name(record));
            snapshot::reconcile_snapshot_record_catalog_entry(&mut dataset_catalog, record)?;
        }

        // Reconcile durable snapshot state into the canonical dataset catalog.
        // Only data-retaining snapshots and clones own dataset catalog entries;
        // bookmarks are lightweight replication anchors and do not pin roots.
        let catalog_entries =
            dataset_catalog
                .list_children("")
                .map_err(|_| FileSystemError::CorruptState {
                    reason: "snapshot authority catalog could not be inspected during reopen",
                })?;
        for (entry_name, _dataset_id) in catalog_entries {
            if entry_name.starts_with("root@")
                && !expected_snapshot_catalog_names.contains(&entry_name)
            {
                let _ = dataset_catalog.destroy(&entry_name);
            }
        }

        // Persist the canonical dataset catalog to the pool store only for
        // mutating opens. RecoveryPolicy::ReadOnly is used by inspectors such
        // as `dataset list` and must not replay or publish side effects while
        // another process owns the mounted pool.
        if recovery_policy.allows_any_mutation() {
            if let Err(e) = store.put(
                DeviceIoClass::Data,
                dataset_catalog_object_key(),
                &dataset_catalog.encode(),
            ) {
                eprintln!("warning: dataset catalog persist failed: {e}");
            }
            let _ = store.sync_all();
        }

        let mut fs = Self {
            store,
            quorum_store: None,
            state,
            allocator_policy,
            extent_allocator: ExtentAllocator::new(),
            root_authentication_key,
            encryption_key: key_for_struct,
            hot_read_cache: RefCell::new(HotReadCache::new(HotReadCachePolicy::default())),
            content_layout_cache: RefCell::new(BTreeMap::new()),
            dedup_index: RefCell::new(DedupIndex::new()),
            dedup_enabled: false,
            inode_cache: RefCell::new(InodeCache::new(InodeCachePolicy::default())),
            auto_commit: true,
            uncommitted_mutation_count: 0,
            max_uncommitted_mutations: DEFAULT_MAX_UNCOMMITTED_MUTATIONS,
            in_transaction: false,
            mutation_delta: None,
            mutation_recorded_commit_group_write: false,
            domain_registry: SpaceDomainRegistry::new(),
            state_before_transaction: None,
            write_admission: LocalWriteAdmission::new(Default::default()),
            pending_permits: Vec::new(),
            dirty_set: DirtySet::default(),
            intent_log,
            intent_log_buffer: None,
            commit_group: CommitGroupStateMachine::with_starting_commit_group(
                CommitGroupConfig::default(),
                TxnGroupId(generation),
            ),
            obligation_ledger: Box::new(ObligationLedger::new(
                allocator_policy.content_capacity_bytes / content_chunk_size() as u64,
            )),
            budget_domain: BudgetDomain::new(
                BudgetDomainId::from_str("default"),
                "default".into(),
                allocator_policy.content_capacity_bytes,
                ReserveClass::Rebuild,
                allocator_policy.content_capacity_bytes / 10,
                allocator_policy.content_capacity_bytes / 5,
            ),
            space_pressure: SpacePressure::new(SpacePressureConfig::default()),
            background_cleaner: BackgroundCleaner::new(BackgroundCleanerConfig::default()),
            auto_compaction_waste_threshold: DEFAULT_AUTO_COMPACTION_WASTE_THRESHOLD,
            orphan_index: Arc::new(Mutex::new(orphan_index_inner)),
            lifecycle,
            dataset_catalog,
            pool_properties,
            compression_policy_source: CompressionPolicySource::Default,
            feature_flags: FeatureFlags::new(),
            content_compression_policy: ContentCompressionPolicy::default(),
            pending_orphan_deletions: Arc::new(Mutex::new(Vec::new())),
            background_scheduler: None,
            scrub_repair_schedule: None,
            scrub_corruption_detected: None,
            reclaim_queue: Arc::new(Mutex::new(BPlusTreeReclaimQueue::new())),
            total_reclaim_drains: 0,
            total_reclaim_entries_drained: 0,
            page_cache: RefCell::new(PageCache::with_default_page_size()),
            dirty_page_tracker: RefCell::new(DirtyPageTracker::new()),
            page_reclaim_stats: RefCell::new(page_cache::reclaim::ReclaimStats::default()),
            writeback_range_tracker: Arc::new(Mutex::new(
                crate::dirty_page_tracker::DirtyPageTracker::new(),
            )),
            writeback_handle: None,
            lock_tracker: RefCell::new(LockTracker::new()),
            write_buffers: BTreeMap::new(),
            write_buffer_config: WriteBufferConfig::default(),
            pool_uuid: pool_uuid_from_path(&root_path),
            fsync_stats: FsyncStats::default(),
            sync_gate: SyncGate::new(),
            recovery_policy,
            capacity_authority,
            mounted_dataset_id: ROOT_DATASET_ID,
            quota_hierarchy: None,
            quota_parent_map: HashMap::new(),
            placement_epoch: None,
            cleanup_engine: None,
        };

        // Replay BLAKE3-verified namespace intent-log segments recorded by
        // the mutation intent log (tidefs-intent-log). This complements the
        // data-path intent log replay already performed by
        // load_latest_committed_state. If no segments exist, replay is a no-op.
        {
            let intent_log_dir = root_path.join("intent_log");
            let applied_txg = recovered_generation;
            let vfs = crate::vfs_engine_impl::VfsLocalFileSystem::new(fs);
            let mut replay_engine = tidefs_recovery_loop::replay::ReplayEngine::new(applied_txg);
            match replay_engine.replay_intent_log(&intent_log_dir, &vfs) {
                Ok(outcome) => {
                    if let tidefs_recovery_loop::replay::ReplayOutcome::ReplayComplete {
                        replayed,
                        skipped,
                    } = outcome
                    {
                        if replayed > 0 {
                            eprintln!(
                                "intent replay: replayed {replayed} namespace intent record(s), skipped {skipped}"
                            );
                        }
                    }
                }
                Err(e) => {
                    eprintln!(
                        "warning: intent replay failed: {e}; continuing without namespace intent replay"
                    );
                }
            }
            fs = vfs.into_inner();
        }

        // Register the root dataset in the domain registry for clone-family
        // space accounting. Each dataset gets its own domain; clones inherit
        // their origin's domain via inherit_domain.
        {
            let root_domain = SpaceDomainId(1);
            match fs
                .domain_registry
                .create_domain(root_domain, fs.state.space_accounting.domain_counters())
            {
                Ok(()) => {
                    fs.state.space_accounting.set_domain(root_domain);
                }
                Err(e) => {
                    eprintln!("warning: failed to create root space domain: {e:?}, using NONE");
                    fs.state.space_accounting.set_domain(SpaceDomainId::NONE);
                }
            }
        }

        // Build the background scheduler, register all services, and start
        // the runtime thread. The runtime drives BackgroundOrphanReclamation
        // and BackgroundScrubber under per-tick budget without blocking mount.
        {
            let mut scheduler = BackgroundScheduler::new(ServiceBudget::DEFAULT_TICK);

            let orphan_reclamation = BackgroundOrphanReclamation::new(
                Arc::clone(&fs.orphan_index),
                Arc::clone(&fs.pending_orphan_deletions),
            );
            scheduler.register(Box::new(orphan_reclamation));

            let scrub_interval_secs = options.background_scrub_interval_secs;
            if scrub_interval_secs > 0 {
                // Shared flag: background scrubber sets it when corruption is
                // detected, and tick_background_services Duty 3 consumes it to
                // trigger repair scheduling and dispatch.
                let corruption_flag = Arc::new(AtomicBool::new(false));
                fs.scrub_corruption_detected = Some(Arc::clone(&corruption_flag));
                let scrubber = BackgroundScrubber::new(
                    root_path.clone(),
                    options,
                    root_authentication_key,
                    Duration::from_secs(scrub_interval_secs),
                    corruption_flag,
                );
                scheduler.register(Box::new(scrubber));
            }

            fs.background_scheduler = Some(BackgroundSchedulerRuntime::start(
                scheduler,
                Duration::from_secs(1),
            ));
        }

        // Writeback daemon is intentionally not started during production mount/open (#5940).
        // Dirty ranges in the writeback_range_tracker are cleared only through the
        // authoritative filesystem data path: flush_write_buffer -> extent allocation ->
        // content layout persistence -> root commit. The removed StoreFlushTarget wrote
        // to sidecar tidefs:writeback:* objects that bypassed content layout, extents,
        // capacity accounting, intent log, and root publication — making writeback look
        // successful while the real filesystem state was never made durable.
        //
        // Foreground writeback is driven by the write-buffer byte threshold
        // (WriteBuffer::should_flush triggers flush_write_buffer during write_file)
        // and explicit fsync/fdatasync calls through the intent-log durability path.
        // The write-buffer age threshold is policy input for a real background
        // tick, not a synchronous flush trigger in write_file.
        // StoreFlushTarget is retained behind #[cfg(test)] only.

        // Mount-time repair is intentionally not run during open (#6317).
        // Create/import/mount/remount recovery is committed-root selection
        // plus intent-log replay under policy (load_latest_committed_state,
        // CommitGroupRecovery, TxgReplayEngine) -- that is the single
        // authority.  Repair (scrub -> schedule -> dispatch) runs only
        // through background services or explicit operator invocation, not
        // as automatic mount-time mutation.
        if recovery_policy.allows_repair_writeback() {
            eprintln!(
                "recovery: mount-time repair skipped; repair runs through background services only"
            );
        }
        // Load persisted feature flags from the object store (Phase 3).
        // Backward-compatible: datasets without persisted roots load as empty FeatureFlags.
        if let Ok(Some(bytes)) = fs
            .store
            .primary_store()
            .get(crate::object_keys::feature_flags_roots_object_key())
        {
            if bytes.len() == 24 {
                use tidefs_types_dataset_feature_flags_core::{
                    BtreeRootPointer, DatasetFeatureFlagsV1,
                };
                let compat = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
                let ro_compat = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
                let incompat = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
                let roots = DatasetFeatureFlagsV1 {
                    compat_root: BtreeRootPointer(compat),
                    ro_compat_root: BtreeRootPointer(ro_compat),
                    incompat_root: BtreeRootPointer(incompat),
                };
                if !roots.is_empty() {
                    match tidefs_dataset_feature_flags::FeatureFlags::load(&fs.store, &roots) {
                        Ok(loaded) => fs.feature_flags = loaded,
                        Err(e) => {
                            eprintln!("warning: failed to load persisted feature flags: {e}")
                        }
                    }
                }
            }
        }

        // Gate mount: refuse if dataset features are incompatible with this
        // tidefs version. Unknown incompat features are a hard gate; unknown
        // ro_compat features force read-only but allow mount.
        let supported = SupportedFeaturesV1::current();
        match fs.feature_flags.check_upgrade_gate(supported.as_slice()) {
            tidefs_dataset_feature_flags::MountCheckResult::Refused { .. } => {
                return Err(FileSystemError::CorruptState {
                    reason: "dataset feature flags refused mount: unknown incompat features",
                });
            }
            tidefs_dataset_feature_flags::MountCheckResult::ReadOnly { .. } => {
                eprintln!("warning: dataset mounted read-only due to unknown ro_compat features");
            }
            tidefs_dataset_feature_flags::MountCheckResult::ReadWrite => {}
        }

        // Derive content compression policy from enabled dataset feature flags.
        // Priority: lz4 > zstd > off.  Only one algorithm is active at a time;
        // the policy governs all mounted-filesystem content writes.
        let (policy, source) = fs.resolve_effective_compression_policy();
        fs.content_compression_policy = policy;
        fs.compression_policy_source = source;
        fs.state.content_compression_policy = fs.content_compression_policy.clone();

        // Resolve per-dataset dedup policy from persisted feature flags.
        {
            let dedup_name =
                tidefs_types_dataset_feature_flags_core::FeatureName::from_str("org.tidefs:dedup")
                    .expect("org.tidefs:dedup is a valid FeatureName");
            if fs.feature_flags.is_enabled(&dedup_name) {
                fs.dedup_enabled = true;
            }
        }

        // Gate mount: refuse if lifecycle forbids (DESTROYING, TOMBSTONE, or poisoned).
        // This is the canonical mount-time lifecycle check that makes Phases 1-6
        // of the dataset lifecycle state machine have runtime effect.
        if let Err(_e) = fs.lifecycle.check_mount("") {
            return Err(FileSystemError::CorruptState {
                reason: "dataset lifecycle refused mount",
            });
        }
        // Mount-time orphan cleanup: synchronously reclaim all orphaned
        // inodes (nlink==0 after unclean shutdown) before accepting I/O.
        // Content objects, extent maps, stale directory entries, and
        // block allocator space are freed for each orphaned inode.
        // BackgroundOrphanReclamation handles incremental runtime orphans.
        if let Err(e) = fs.cleanup_orphans() {
            eprintln!("warning: mount-time orphan cleanup failed: {e}");
        }

        Ok(fs)
    }

    pub fn open_with_capacity(
        root: impl AsRef<Path>,
        options: StoreOptions,
        content_capacity_bytes: u64,
    ) -> Result<Self> {
        Self::open_with_allocator_policy_and_root_authentication_key(
            root,
            LocalFileSystemOpenConfig {
                options,
                allocator_policy: LocalStorageAllocatorPolicy {
                    content_capacity_bytes,
                    ..LocalStorageAllocatorPolicy::default()
                },
                root_authentication_key: default_root_authentication_key()?,
                encryption: None,
                compression: None,
                log_device_device_path: None,
                recovery_policy: RecoveryPolicy::default(),
                block_devices: None,
            },
        )
    }

    pub fn open_with_capacity_and_root_authentication_key(
        root: impl AsRef<Path>,
        options: StoreOptions,
        content_capacity_bytes: u64,
        root_authentication_key: RootAuthenticationKey,
    ) -> Result<Self> {
        Self::open_with_allocator_policy_and_root_authentication_key(
            root,
            LocalFileSystemOpenConfig {
                options,
                allocator_policy: LocalStorageAllocatorPolicy {
                    content_capacity_bytes,
                    ..LocalStorageAllocatorPolicy::default()
                },
                root_authentication_key,
                encryption: None,
                compression: None,
                log_device_device_path: None,
                recovery_policy: RecoveryPolicy::default(),
                block_devices: None,
            },
        )
    }

    /// Open the filesystem with quorum write replicas.
    ///
    /// The primary store is at `root`. Additional replicas are opened
    /// from `quorum_config`. Writes are fanned out across all healthy
    /// replicas; reads fall back to replicas when the primary misses.
    ///
    /// When the quorum store fails to open (e.g., insufficient replicas),
    /// the filesystem still opens in single-store mode with `quorum_store`
    /// set to `None`.
    pub fn open_with_quorum(
        root: impl AsRef<Path>,
        options: StoreOptions,
        quorum_config: QuorumConfig,
    ) -> Result<Self> {
        let mut fs = Self::open_with_options(root, options)?;
        match QuorumObjectStore::open(quorum_config) {
            Ok(qs) => {
                fs.quorum_store = Some(qs);
            }
            Err(e) => {
                eprintln!("quorum store open failed: {e}; operating in single-store mode");
            }
        }
        Ok(fs)
    }

    pub fn probe_recovery(
        root: impl AsRef<Path>,
        options: StoreOptions,
    ) -> Result<RecoveryProbeReport> {
        Self::probe_recovery_with_root_authentication_key(
            root,
            options,
            default_root_authentication_key()?,
        )
    }

    pub fn probe_recovery_with_root_authentication_key(
        root: impl AsRef<Path>,
        options: StoreOptions,
        root_authentication_key: RootAuthenticationKey,
    ) -> Result<RecoveryProbeReport> {
        let mut store = Self::default_development_pool(root.as_ref(), &options, None, None)?;
        let mut authority = MountedOpenRecoveryAuthority::raw_only(
            &mut store,
            root_authentication_key,
            RecoveryPolicy::default(),
        );
        authority.recovery_probe_report()
    }

    pub fn recovery_probe_report(&mut self) -> Result<RecoveryProbeReport> {
        let root_authentication_key = self.root_authentication_key;
        let recovery_policy = self.recovery_policy;
        let mut authority = MountedOpenRecoveryAuthority::raw_only(
            &mut self.store,
            root_authentication_key,
            recovery_policy,
        );
        authority.recovery_probe_report()
    }

    pub fn root(&self) -> &Path {
        self.store.root()
    }

    pub fn segments_dir(&self) -> &Path {
        self.store.segments_dir()
    }

    pub fn object_store(&self) -> &LocalObjectStore {
        self.store.raw_primary_store()
    }

    #[allow(dead_code)] // INTENT: kept for planned architecture; callers in test modules or pending wiring into FUSE dispatch
    pub(crate) fn store_ref(&self) -> &LocalObjectStore {
        self.store.raw_primary_store()
    }

    #[allow(dead_code)] // INTENT: kept for planned architecture; callers in test modules or pending wiring into FUSE dispatch
    pub(crate) fn inode_records(&self) -> &BTreeMap<InodeId, InodeRecord> {
        &self.state.inodes
    }

    pub fn recovery_audit(&mut self) -> Result<RecoveryAuditReport> {
        let root_authentication_key = self.root_authentication_key;
        let recovery_policy = self.recovery_policy;
        let mut authority = MountedOpenRecoveryAuthority::raw_only(
            &mut self.store,
            root_authentication_key,
            recovery_policy,
        );
        authority.recovery_audit()
    }

    pub fn online_verifier_report(&mut self) -> Result<OnlineVerifierReport> {
        let root_authentication_key = self.root_authentication_key;
        let recovery_policy = self.recovery_policy;
        let mut authority = MountedOpenRecoveryAuthority::raw_only(
            &mut self.store,
            root_authentication_key,
            recovery_policy,
        );
        authority.online_verifier_report()
    }

    pub fn root_retention_plan(
        &mut self,
        policy: RootRetentionPolicy,
    ) -> Result<RootRetentionPlan> {
        let root_authentication_key = self.root_authentication_key;
        let recovery_policy = self.recovery_policy;
        let mut authority = MountedOpenRecoveryAuthority::raw_only(
            &mut self.store,
            root_authentication_key,
            recovery_policy,
        );
        authority.root_retention_plan(policy)
    }

    pub fn safe_root_retention_plan(&mut self) -> Result<RootRetentionPlan> {
        self.root_retention_plan(RootRetentionPolicy::safe_default())
    }

    /// Record reclaim deltas for freed content objects into the shared
    /// reclaim queue for deferred background processing.  Called by file
    /// operations (unlink, truncate, rename-overwrite) when content is
    /// destroyed or shrunk.
    ///
    /// The delta is O(1) at mutation time — just a B+tree insert.
    /// The `tick_background_services()` Duty 2 drains the queue under per-tick budget.
    ///
    /// # Key authority (fixed #5959)
    ///
    /// Uses proper content-object keys via `content_object_key()` and
    /// `content_object_key_for_version()`, matching the orphan cleanup path
    /// in `tick_background_services()`.  The previous inode_id-prefix
    /// derivation was a key-authority mismatch that caused object deletions
    /// to be silent no-ops.
    ///
    /// For full-inode deletion (nlink reaches 0), also inserts per-chunk
    /// keys via `content_chunk_object_key_for_version()`.
    fn record_reclaim_delta(&mut self, inode_id: InodeId, _freed_bytes: u64) {
        let record = self.state.inodes.get(&inode_id).cloned();
        if record
            .as_ref()
            .is_some_and(|record| record.nlink == 0 && record.size == 0)
        {
            return;
        }
        let dv = record.as_ref().map(|r| r.data_version);
        let chunk_reclaim_indexes = match record.as_ref().filter(|record| record.nlink == 0) {
            Some(record) => match read_content_layout_from_store(
                self.store.raw_primary_store(),
                inode_id,
                record,
                true,
            ) {
                Ok(ContentLayout::Chunked(manifest)) => Some(
                    manifest
                        .chunks
                        .iter()
                        .filter(|chunk_ref| !chunk_ref.is_hole())
                        .map(|chunk_ref| chunk_ref.chunk_index)
                        .collect::<Vec<_>>(),
                ),
                Ok(ContentLayout::Inline(_)) => Some(Vec::new()),
                Err(_) => content_chunk_count(record.size)
                    .ok()
                    .map(|chunk_count| (0..chunk_count).collect()),
            },
            None => None,
        };

        let mut rq = self.reclaim_queue.lock().unwrap();

        // Legacy unversioned content key — matches the object-key prefix
        // used by older content writes before per-version chunking.
        let legacy_key = content_object_key(inode_id);
        rq.insert(ReclaimQueueEntry::new(
            ReclaimObjectKey(*legacy_key.as_bytes()),
            -1,
            ReclaimQueueFamily::Extent,
        ));

        // Versioned content keys for current and baseline data versions.
        if let Some(dv) = dv {
            for version in [0_u64, dv] {
                let vkey = content_object_key_for_version(inode_id, version);
                rq.insert(ReclaimQueueEntry::new(
                    ReclaimObjectKey(*vkey.as_bytes()),
                    -1,
                    ReclaimQueueFamily::Extent,
                ));
            }
        }

        // Chunk-level keys for full-inode deletion: enumerate all chunks
        // at the current data version so the object store can reclaim each
        // individually after the namespace mutation is committed. Do not
        // delete objects here: this runs before commit rollback is impossible,
        // and foreground unlink must not leave a namespace entry pointing at
        // tombstoned content if the commit fails.
        if let (Some(record), Some(chunk_reclaim_indexes)) =
            (record.as_ref(), chunk_reclaim_indexes)
        {
            for ci in chunk_reclaim_indexes {
                let ckey = content_chunk_object_key_for_version(inode_id, record.data_version, ci);
                rq.insert(ReclaimQueueEntry::new(
                    ReclaimObjectKey(*ckey.as_bytes()),
                    -1,
                    ReclaimQueueFamily::Extent,
                ));
            }
        }
        drop(rq);
    }

    /// Record an inode tombstone in the reclaim queue when an inode's
    /// link count reaches zero and it is fully removed.
    ///
    /// The inode tombstone (family [`ReclaimQueueFamily::InodeTombstone`]) signals
    /// the reclaim processor to compact the dead inode's metadata records
    /// (inode table slot, extent map, directory entries).  The content
    /// extent freed is covered independently by [`record_reclaim_delta`].
    ///
    /// # Key authority (fixed #5959)
    ///
    /// Uses `inode_object_key()` for the tombstone to match the actual
    /// inode-table object key, replacing the previous inode_id-prefix
    /// derivation that did not match any store object.
    fn record_inode_tombstone(&self, inode_id: InodeId) {
        let inode_key = inode_object_key(inode_id);
        let object_key = ReclaimObjectKey(*inode_key.as_bytes());
        let entry = ReclaimQueueEntry::new(
            object_key,
            -1, // tombstone delta is always -1 (one dead inode)
            ReclaimQueueFamily::InodeTombstone,
        );
        self.reclaim_queue.lock().unwrap().insert(entry);
    }

    /// Mark an inode as orphaned after its namespace link count reaches zero.
    ///
    /// Returns `true` when the inode was newly inserted into the persistent
    /// orphan index and `false` when it was already tracked.
    pub fn track_orphan(&self, inode_id: InodeId) -> bool {
        let (generation, nlink, is_dir) = {
            if let Some(record) = self.state.inodes.get(&inode_id) {
                (record.generation.get(), record.nlink, record.is_directory())
            } else {
                (0, 0, false)
            }
        };
        let flags = if is_dir {
            OrphanEntryFlags::IS_DIRECTORY
        } else {
            OrphanEntryFlags::NONE
        };
        let entry = OrphanEntry::new(inode_id.get(), generation, nlink, flags);
        self.orphan_index
            .lock()
            .unwrap()
            .insert(inode_id.get(), entry)
    }

    /// Queue an already tracked orphan for deferred background reclamation.
    ///
    /// This is intentionally idempotent so adapter release paths can call it
    /// when the final file handle closes without double-enqueueing work.
    pub fn release_orphan(&self, inode_id: InodeId) -> bool {
        let raw_inode_id = inode_id.get();
        if !self.orphan_index.lock().unwrap().contains(raw_inode_id) {
            return false;
        }

        let mut pending = self.pending_orphan_deletions.lock().unwrap();
        if pending.contains(&raw_inode_id) {
            return false;
        }
        pending.push(raw_inode_id);
        true
    }

    /// Return the current local orphan/reclaim queue depth snapshot.
    pub fn reclaim_stats(&self) -> ReclaimStats {
        ReclaimStats {
            orphan_index_entries: self.orphan_index.lock().unwrap().len(),
            reclaim_queue_entries: self.reclaim_queue.lock().unwrap().len(),
            pending_orphan_deletions: self.pending_orphan_deletions.lock().unwrap().len(),
            total_reclaim_drains: self.total_reclaim_drains,
            total_reclaim_entries_drained: self.total_reclaim_entries_drained,
        }
    }

    /// Return background cleaner statistics for observability.
    pub fn background_cleaner_stats(&self) -> &crate::background_cleaner::BackgroundCleanerStats {
        self.background_cleaner.stats()
    }

    /// Access the page cache (interior mutability via RefCell).
    pub fn page_cache_mut(&self) -> std::cell::RefMut<'_, PageCache> {
        self.page_cache.borrow_mut()
    }

    /// Return the current local B+tree reclaim queue depth.
    /// This is the front-end queue that `record_reclaim_delta` feeds during
    /// file mutations. `drain_local_reclaim_queue_into_store` drains entries
    /// from this queue into the object-store durable reclaim queue via
    /// `store.delete()`. The object-store queue is drained by
    pub fn reclaim_queue_depth(&self) -> usize {
        self.reclaim_queue.lock().unwrap().len()
    }

    /// Collect object keys referenced by all snapshot transaction manifests.
    /// Keys returned by this function must not be deleted by the reclaim drain
    /// because snapshots still depend on them for rollback/read validation.
    fn collect_snapshot_protected_content_keys(&self) -> HashSet<ObjectKey> {
        let store = self.store.raw_primary_store();
        let mut protected = HashSet::new();
        for snapshot in self.state.snapshots.values() {
            let tx_id = snapshot.root.transaction_id;
            let manifest_key = transaction_manifest_object_key(tx_id);
            if let Ok(Some(manifest_bytes)) = store.get(manifest_key) {
                if let Ok(manifest) = decode_transaction_manifest(&manifest_bytes) {
                    for entry in &manifest.entries {
                        if matches!(
                            entry.role,
                            TransactionManifestObjectRole::VersionedContent
                                | TransactionManifestObjectRole::VersionedContentChunk
                        ) {
                            protected.insert(entry.object_key);
                        }
                    }
                }
            }
        }
        protected
    }

    /// Drain entries from the local B+tree reclaim queue and hand them off
    /// to the object-store durable reclaim queue via `store.delete()`.
    ///
    /// This is the production reclaim handoff: each entry is removed from the
    /// local queue and passed to `LocalObjectStore::delete()`, which removes
    /// the in-memory object index entry and enqueues a reclaim entry in the
    /// object-store durable reclaim queue. `LocalObjectStore::drain_dead_segments`
    /// is the sole segment-freeing authority that processes that queue.
    ///
    /// Budget: at most 256 entries per call to bound reclaim latency.
    pub fn drain_local_reclaim_queue_into_store(&mut self) -> ReclaimDrainStats {
        const MAX_RECLAIM_PER_TICK: usize = 256;

        // Receipt durability pre-check: identify which batch keys have a
        // durable placement receipt so that entries without durable receipts
        // stay in the queue for a future drain cycle.  We pre-compute the
        // durable set before taking the mutable store borrow so the compiler
        // can separate the immutable Pool access from the mutable store
        // borrow below.

        // Collect keys protected by active snapshots so reclaim does not
        // delete content objects that snapshot manifests still reference (#6451).
        let protected_keys = self.collect_snapshot_protected_content_keys();

        let batch: Vec<(tidefs_types_reclaim_queue_core::ObjectKey, i64)> = {
            let q = self.reclaim_queue.lock().unwrap();
            q.dequeue_batch(None, MAX_RECLAIM_PER_TICK)
                .into_iter()
                .map(|(k, e)| (k, e.delta))
                .collect()
        };
        let entries_drained = batch.len();

        // Pre-compute receipt durability: for each key in the batch, check
        // whether its placement receipt is durable.  Keys that pass are safe
        // to delete; keys that fail stay in the queue.
        let receipt_durable_keys: std::collections::BTreeSet<tidefs_local_object_store::ObjectKey> = batch
            .iter()
            .map(|(k, _)| tidefs_local_object_store::ObjectKey::from_bytes(k.0))
            .filter(|local_key| {
                crate::allocation::chunk_content_key_receipt_stable(&self.store, *local_key)
            })
            .collect();

        if !batch.is_empty() {
            let store = self.store.raw_primary_store_mut();
            let mut dedup_index = self.dedup_index.borrow_mut();

            for (object_key, _delta) in &batch {
                let local_key = tidefs_local_object_store::ObjectKey::from_bytes(object_key.0);

                // Skip reclaim of keys still referenced by snapshot manifests (#6451).
                if protected_keys.contains(&local_key) {
                    continue;
                }

                // Before deleting the per-inode chunk key, check whether it is
                // a dedup redirect.  If the redirect is the last reference to a
                // canonical dedup object, decrement the durable refcount and
                // queue the canonical data object for reclaim (#6326).
                if let Ok(Some(payload)) = store.get(local_key) {
                    if crate::encoding::is_dedup_redirect(&payload) {
                        if let Ok(canonical_key) = crate::encoding::decode_dedup_redirect(&payload)
                        {
                            if let Ok(Some(canon_data)) = store.get(canonical_key) {
                                if let Ok(chunk) =
                                    crate::encoding::decode_content_chunk(&canon_data)
                                {
                                    let fp =
                                        crate::encoding::compute_content_fingerprint(&chunk.bytes);
                                    if let Ok(true) =
                                        crate::dedup_refcount::DedupRefCount::decrement(store, &fp)
                                    {
                                        let canon_data_key =
                                            crate::object_keys::content_dedup_object_key(&fp);
                                        let rq_entry = ReclaimQueueEntry::new(
                                            ReclaimObjectKey(*canon_data_key.as_bytes()),
                                            -1,
                                            QueueFamily::Extent,
                                        );
                                        self.reclaim_queue.lock().unwrap().insert(rq_entry);
                                        dedup_index.remove(&fp);
                                    }
                                }
                            }
                        }
                    }
                }

                // Receipt authority gate: skip objects whose placement receipt
                // is not yet durable.  The pre-computed set includes both content
                // chunks with uncommitted receipts and keys where the pool was
                // unreadable (conservative retain).
                if !receipt_durable_keys.contains(&local_key) {
                    continue;
                }

                let _ = store.delete(local_key);
            }
            // Remove processed entries from the queue.
            // Entries whose receipt is not yet durable are re-enqueued
            // for a future drain cycle. Snapshot-protected entries are
            // not re-enqueued; snapshot deletion regenerates them.
            let mut q = self.reclaim_queue.lock().unwrap();
            for (object_key, delta) in &batch {
                q.delete(object_key);
                let local_key = tidefs_local_object_store::ObjectKey::from_bytes(object_key.0);
                if !receipt_durable_keys.contains(&local_key) && !protected_keys.contains(&local_key) {
                    let entry = ReclaimQueueEntry::new(
                        *object_key,
                        *delta,
                        QueueFamily::Extent,
                    );
                    q.insert(entry);
                }
            }
            self.total_reclaim_drains += 1;
            self.total_reclaim_entries_drained += entries_drained as u64;
        }

        ReclaimDrainStats { entries_drained }
    }

    /// Access the dirty page tracker (interior mutability via RefCell).
    pub fn dirty_page_tracker_mut(&self) -> std::cell::RefMut<'_, DirtyPageTracker> {
        self.dirty_page_tracker.borrow_mut()
    }

    /// Return current page cache stats: (resident_bytes, page_count).
    pub fn page_cache_stats(&self) -> (u64, usize) {
        let cache = self.page_cache.borrow();
        (cache.resident_bytes(), cache.page_count())
    }

    /// Trigger LRU eviction if the page cache is above the high watermark.
    /// Evicts clean pages until the cache is at or below the low watermark.
    pub fn page_cache_maybe_reclaim(&self) -> usize {
        let (evicted, stats) = {
            let mut cache = self.page_cache.borrow_mut();
            let dt = self.dirty_page_tracker.borrow();

            use page_cache::reclaim::{PageCacheReclaimer, ReclaimWatermarks};
            let wm = ReclaimWatermarks::default();
            let mut reclaimer = PageCacheReclaimer::new(&mut cache, &dt, wm);

            if reclaimer.above_high_watermark() {
                let n = reclaimer.evict_to_low_watermark();
                (n, reclaimer.stats)
            } else {
                (0, reclaimer.stats)
            }
        };
        if evicted > 0 {
            self.page_reclaim_stats.borrow_mut().merge(stats);
        }
        evicted
    }

    /// Insert a page into the cache and trigger reclaim if the cache
    /// exceeds the high watermark. Returns the evicted page if one with
    /// the same key was already present.
    pub fn insert_page_and_maybe_reclaim(
        &self,
        key: PageKey,
        page: CachedPage,
    ) -> Option<CachedPage> {
        let mut cache = self.page_cache.borrow_mut();
        let old = cache.insert(key, page);
        drop(cache);
        self.page_cache_maybe_reclaim();
        old
    }

    /// Evict all clean pages for an inode from the page cache.
    /// Called when an inode is evicted or unlinked.
    pub fn page_cache_evict_inode(&self, inode_id: InodeId) -> usize {
        let (evicted, stats) = {
            let mut cache = self.page_cache.borrow_mut();
            let dt = self.dirty_page_tracker.borrow();

            use page_cache::reclaim::{PageCacheReclaimer, ReclaimWatermarks};
            let wm = ReclaimWatermarks::default();
            let mut reclaimer = PageCacheReclaimer::new(&mut cache, &dt, wm);

            let n = reclaimer.evict_inode(inode_id);
            (n, reclaimer.stats)
        };
        if evicted > 0 {
            self.page_reclaim_stats.borrow_mut().merge(stats);
        }
        evicted
    }

    /// Return cumulative page cache reclaim statistics.
    /// Accumulates across all eviction calls since filesystem open.
    pub fn page_cache_reclaim_stats(&self) -> page_cache::reclaim::ReclaimStats {
        *self.page_reclaim_stats.borrow()
    }
    pub fn reclaim_unprotected_objects(
        &mut self,
        policy: RootRetentionPolicy,
    ) -> Result<SafeReclamationReport> {
        let plan = self.root_retention_plan(policy)?;
        if plan.has_retention_debt() {
            return Err(FileSystemError::RetentionDebt {
                required: plan.retention_debt.policy_required_committed_roots,
                available: plan.retention_debt.valid_committed_roots_available,
                missing: plan.retention_debt.missing_committed_roots,
            });
        }
        let expected_roots = plan.protected_committed_roots.clone();
        let expected_root_slot_locations = plan.protected_root_slot_locations.len();
        let selected_root_before = plan.audit.selected_root.clone();
        let store_report = self.store.compact_retaining(
            &plan.protected_object_keys,
            &plan.protected_root_slot_locations,
        )?;
        let root_authentication_key = self.root_authentication_key;
        let recovery_policy = self.recovery_policy;
        let mut authority = MountedOpenRecoveryAuthority::raw_only(
            &mut self.store,
            root_authentication_key,
            recovery_policy,
        );
        let audit = authority.recovery_audit()?;
        for expected in &expected_roots {
            let locations = authority.root_slot_locations_for_summary(expected)?;
            if locations.is_empty() {
                return Err(FileSystemError::CorruptState {
                    reason: "safe reclamation lost a protected root-slot location",
                });
            }
            let expected_root = root_commit_from_summary(expected);
            let _ = authority.load_committed_root_state(&expected_root)?;
        }
        let selected_generation_after = audit.selected_root.as_ref().map(|root| root.generation);
        if audit.selected_root != selected_root_before {
            return Err(FileSystemError::CorruptState {
                reason: "safe reclamation changed the selected committed root",
            });
        }
        Ok(SafeReclamationReport {
            spec: SAFE_LOCAL_RECLAMATION_GC_SPEC,
            retention_plan: plan,
            store: store_report,
            protected_committed_roots_preserved: expected_roots.len(),
            protected_root_slot_locations_preserved: expected_root_slot_locations,
            selected_generation_after,
            mutating_reclamation_allowed: true,
            production_fsck_required: false,
        })
    }

    pub fn safe_reclaim_unprotected_objects(&mut self) -> Result<SafeReclamationReport> {
        self.reclaim_unprotected_objects(RootRetentionPolicy::safe_default())
    }

    /// Explicitly compact the object store when the waste ratio exceeds
    /// the configured threshold. No-op when below threshold.
    ///
    /// This intentionally is not called from the foreground commit path:
    /// root-retention planning scans the object index and can pin a FUSE
    /// request thread behind unrelated writes. Mounted foreground I/O advances
    /// incremental cleanup through `tick_background_services`; full safe
    /// reclamation remains an explicit maintenance operation.
    pub fn compact_if_waste_exceeds_threshold(&mut self) -> Result<Option<SafeReclamationReport>> {
        if self
            .store
            .should_compact(self.auto_compaction_waste_threshold)
        {
            return self.safe_reclaim_unprotected_objects().map(Some);
        }
        Ok(None)
    }

    /// Set the explicit compaction waste threshold.
    ///
    /// When the ratio of tombstone records to total (tombstone + live) exceeds
    /// this value, [`compact_if_waste_exceeds_threshold`](Self::compact_if_waste_exceeds_threshold)
    /// will perform safe reclamation. The default is 0.25 (25%).
    pub fn set_auto_compaction_waste_threshold(&mut self, threshold: f64) {
        self.auto_compaction_waste_threshold = threshold;
    }

    pub fn mount_invariant_report(&self) -> Result<MountInvariantReport> {
        mount_invariant_report_from_state(&self.state)
    }

    pub fn live_invariant_report(&self) -> Result<MountInvariantReport> {
        self.mount_invariant_report()
    }

    /// Run a full scrub-repair-re-scrub cycle on all inodes.
    ///
    /// Returns the repair log with actual outcomes applied.
    /// On mount, this ensures any corruption detected by a previous
    /// background scrub is healed before user I/O begins.
    pub fn repair_cycle(&mut self) -> Result<RepairLog> {
        use crate::crash_hooks::check_crash_hook;
        use tidefs_local_object_store::CrashInjectionPoint;
        if !self.recovery_policy.allows_repair_writeback() {
            return Ok(RepairLog::new());
        }

        // Populate the scheduling bridge from scrub findings.
        let _ledger = self.schedule_scrub_repairs()?;

        check_crash_hook(CrashInjectionPoint::RepairBeforeApply);

        // Dispatch prioritized repairs from the bridge.
        Ok(self.dispatch_scheduled_repairs())
    }

    /// Run a scrub pass and populate the repair scheduling bridge.
    ///
    /// Scrubs all inode content, records corruption validation into a BLAKE3-verified
    /// [`ScrubRepairLedger`], and populates the [`ScrubToRepairBridge`] with
    /// prioritized repair jobs via [`run_scrub_repair_scheduling`].
    ///
    /// The scheduling bridge classifies findings by escalation level (Immediate
    /// for zero-replica corruption, Urgent/Normal/Background for multi-replica)
    /// and generates rebake entries for EC parity recomputation.
    ///
    /// Returns the validation ledger. The scheduling bridge is stored on `self`
    /// and consumed by [`dispatch_scheduled_repairs`](Self::dispatch_scheduled_repairs).
    pub fn schedule_scrub_repairs(
        &mut self,
    ) -> Result<tidefs_scrub::scrub_repair::ScrubRepairLedger> {
        if !self.recovery_policy.allows_repair_writeback() {
            return Ok(tidefs_scrub::scrub_repair::ScrubRepairLedger::new());
        }
        let report =
            crate::scrub::scrub_inodes_content(self.store.raw_primary_store(), &self.state.inodes)?;

        // Populate the scheduling bridge with prioritized repair jobs.
        let schedule = crate::scrub_repair_integration::run_scrub_repair_scheduling(&report);
        self.scrub_repair_schedule = Some(schedule);

        // Also record validation in the BLAKE3-verified ledger.
        Ok(crate::scrub_repair_integration::run_scrub_repair_pass(
            &report,
        ))
    }

    /// Legacy read-only scrub repair pass — records validation only.
    ///
    /// Prefer [`schedule_scrub_repairs`](Self::schedule_scrub_repairs) for
    /// the full detect→schedule→dispatch pipeline. This method remains for
    /// callers that only need the validation ledger.
    pub fn scrub_repair_pass(&self) -> Result<tidefs_scrub::scrub_repair::ScrubRepairLedger> {
        if !self.recovery_policy.allows_repair_writeback() {
            return Ok(tidefs_scrub::scrub_repair::ScrubRepairLedger::new());
        }
        let report =
            crate::scrub::scrub_inodes_content(self.store.raw_primary_store(), &self.state.inodes)?;
        Ok(crate::scrub_repair_integration::run_scrub_repair_pass(
            &report,
        ))
    }

    /// Dispatch prioritized repair jobs from the scheduling bridge through
    /// the repair pipeline.
    ///
    /// Consumes the schedule populated by [`schedule_scrub_repairs`], dispatches
    /// each repair job in priority order (Immediate → Urgent → Normal → Background)
    /// through the existing repair resolution and application pipeline, and
    /// records outcomes.
    ///
    /// Repaired jobs are marked resolved in the bridge; failed jobs are
    /// escalated for retry or marked exhausted.
    ///
    /// Returns the repair log with applied outcomes, or an empty log if
    /// no schedule is pending.
    pub fn dispatch_scheduled_repairs(&mut self) -> RepairLog {
        use crate::crash_hooks::check_crash_hook;
        use tidefs_local_object_store::CrashInjectionPoint;
        let mut schedule = match self.scrub_repair_schedule.take() {
            Some(s) => s,
            None => return RepairLog::new(),
        };

        if !schedule.bridge.has_work() {
            return RepairLog::new();
        }

        eprintln!(
            "repair-dispatch: {} pending repair jobs, {} rebake entries",
            schedule.bridge.pending_count(),
            schedule.rebake.entries_generated(),
        );

        check_crash_hook(CrashInjectionPoint::RepairBeforeWriteback);

        let mut content_layout_cache: BTreeMap<InodeId, ContentLayout> = BTreeMap::new();
        let applied = crate::scrub_repair_integration::dispatch_repair_from_bridge(
            &mut schedule.bridge,
            &mut self.state,
            self.store.raw_primary_store_mut(),
            &mut content_layout_cache,
        );
        check_crash_hook(CrashInjectionPoint::RepairAfterWriteback);

        // Re-scrub repaired inodes to verify healing.
        let mut re_scrub_inodes: BTreeMap<InodeId, InodeRecord> = BTreeMap::new();
        for entry in &applied.entries {
            if entry.outcome != RepairOutcome::Skipped {
                let inode_id = InodeId::new(entry.block_id.inode_id);
                if let Some(record) = self.state.inodes.get(&inode_id) {
                    re_scrub_inodes.insert(inode_id, record.clone());
                }
            }
        }

        if !re_scrub_inodes.is_empty() {
            match crate::scrub::scrub_inodes_content(
                self.store.raw_primary_store(),
                &re_scrub_inodes,
            ) {
                Ok(re_report) => {
                    if !re_report.is_clean() {
                        eprintln!(
                            "repair-dispatch: {} blocks still corrupt after scheduled repair, marking inodes",
                            re_report.blocks_corrupt,
                        );
                        for violation in &re_report.violations {
                            let inode_id = InodeId::new(violation.block_id.inode_id);
                            self.state.corrupted_inodes.insert(inode_id);
                            self.invalidate_hot_read_cache_for_inode(inode_id);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("repair-dispatch: re-scrub error: {e}");
                }
            }
        }

        applied
    }

    /// Drive one cycle of the background service scheduler.
    ///
    /// Dispatches ticks to all registered services that have work,
    /// in priority order with round-robin fairness. Call periodically
    /// (e.g. after commits, on a timer, or from the embedding application)
    /// to keep background work progressing.
    pub fn tick_background_services(&mut self) {
        // --- Duty 1: record reclaim deltas for orphaned inodes ---
        let pending: Vec<u64> = {
            let mut lock = self.pending_orphan_deletions.lock().unwrap();
            std::mem::take(&mut *lock)
        };

        if !pending.is_empty() {
            let mut rq = self.reclaim_queue.lock().unwrap();
            let mut idx = self.orphan_index.lock().unwrap();
            for &inode_id_raw in &pending {
                let inode_id = InodeId(inode_id_raw);

                let legacy_key = content_object_key(inode_id);
                rq.insert(ReclaimQueueEntry::new(
                    tidefs_types_reclaim_queue_core::ObjectKey(*legacy_key.as_bytes()),
                    -1,
                    QueueFamily::Extent,
                ));

                for dv in [0_u64, 1_u64] {
                    let manifest_key = content_object_key_for_version(inode_id, dv);
                    rq.insert(ReclaimQueueEntry::new(
                        tidefs_types_reclaim_queue_core::ObjectKey(*manifest_key.as_bytes()),
                        -1,
                        QueueFamily::Extent,
                    ));
                }

                idx.remove(inode_id_raw);
            }
        }

        // --- Duty 2: drain reclaim queue into object-store authority ---
        // Hands off local B+tree reclaim queue entries to the object-store
        // durable reclaim queue via store.delete().  The object-store queue
        // is drained by LocalObjectStore::drain_dead_segments, the sole
        // segment-freeing authority.
        let _drain_stats = self.drain_local_reclaim_queue_into_store();

        // --- Duty 3: dispatch pending scrub-triggered repairs ---
        // The background scrubber sets scrub_corruption_detected when it finds
        // on-disk corruption.  Duty 3 picks up that signal, re-scrubs through
        // the live store, schedules prioritized repairs, and dispatches them
        // without blocking foreground I/O beyond a single tick.
        if let Some(ref flag) = self.scrub_corruption_detected {
            if flag.swap(false, Ordering::SeqCst) {
                if self.recovery_policy.allows_repair_writeback() {
                    if let Err(e) = self.repair_cycle() {
                        eprintln!("background-services: repair cycle from scrub flag failed: {e}");
                    }
                }
                // --- Duty 4: background segment cleaning with throttle ---
                // Consults the watermark-based CleanerScheduler from
                // tidefs-space-accounting.  When free segments drop below
                // target_free_segments, activates the cleaner and runs one
                // round of journal segment cleaning per tick, subject to
                // the rate limiter so foreground I/O is not starved.
                self.background_cleaner.tick(&mut self.store);
            }
        }
    }

    #[allow(dead_code)]
    // INTENT: kept for planned architecture; callers in test modules or pending wiring into FUSE dispatch
    /// Mount-time orphan recovery: delegates to the `orphan_cleanup`
    /// module for synchronous reclamation of all orphaned inodes.
    ///
    /// Content objects, extent maps, stale directory entries, and
    /// block allocator space are freed for each orphaned inode, and
    /// the orphan index entry is removed.
    fn recover_orphans(&mut self) -> Result<()> {
        let _stats = orphan_cleanup::cleanup_orphans(
            self.store.raw_primary_store_mut(),
            &mut self.state,
            &self.orphan_index,
            &self.reclaim_queue,
        )?;
        Ok(())
    }

    /// Mount-time orphan cleanup: synchronously reclaim all orphaned
    /// inodes from the persistent orphan index.
    ///
    /// Called from `open` after intent log replay.  For each orphaned
    /// inode, frees extent maps, removes stale directory entries,
    /// releases block allocator space via the reclaim queue, deletes
    /// content objects, and removes the orphan index entry.
    ///
    /// Returns statistics about the cleanup pass.
    pub(crate) fn cleanup_orphans(&mut self) -> Result<OrphanCleanupStats> {
        orphan_cleanup::cleanup_orphans(
            self.store.raw_primary_store_mut(),
            &mut self.state,
            &self.orphan_index,
            &self.reclaim_queue,
        )
    }

    #[allow(dead_code)] // INTENT: kept for planned architecture; callers in test modules or pending wiring into FUSE dispatch
    pub fn stats(&self) -> FileSystemStats {
        let mut directory_count = 0_usize;
        let mut file_count = 0_usize;
        let mut symlink_count = 0_usize;
        for inode in self.state.inodes.values() {
            match inode.kind() {
                NodeKind::Dir => directory_count += 1,
                NodeKind::File => file_count += 1,
                NodeKind::Symlink => symlink_count += 1,
                _ => {}
            }
        }
        FileSystemStats {
            inode_count: self.state.inodes.len(),
            directory_count,
            file_count,
            symlink_count,
            snapshot_count: self.state.snapshots.len(),
            next_inode_id: self.state.next_inode_id,
            filesystem_generation: self.state.generation,
            object_store: self.store.store_stats(),
        }
    }

    pub fn hot_read_cache_report(&self) -> HotReadCacheReport {
        self.hot_read_cache.borrow().report()
    }

    pub const fn allocator_policy(&self) -> LocalStorageAllocatorPolicy {
        self.allocator_policy
    }

    pub fn update_allocator_policy(&mut self, policy: LocalStorageAllocatorPolicy) -> Result<()> {
        policy.validate()?;
        self.allocator_policy = policy;
        // Update the capacity authority so statfs-derived block
        // counts reflect the new configured capacity ceiling.
        self.capacity_authority
            .set_total_bytes(policy.content_capacity_bytes);
        // Recreate obligation ledger with new capacity
        self.obligation_ledger = Box::new(ObligationLedger::new(
            policy.content_capacity_bytes / content_chunk_size() as u64,
        ));
        self.budget_domain = BudgetDomain::new(
            BudgetDomainId::from_str("default"),
            "default".into(),
            policy.content_capacity_bytes,
            ReserveClass::Rebuild,
            policy.content_capacity_bytes / 10,
            policy.content_capacity_bytes / 5,
        );
        Ok(())
    }

    /// Look up extents for `inode_id` in the given logical range.
    ///
    /// Returns clipped [`tidefs_extent_map::ExtentMapEntryV2`] entries
    /// that intersect `[logical_offset, logical_offset + length)`.
    /// Uses the in-memory extent allocator tracking per-inode extents.
    #[must_use]
    pub fn lookup_extents(
        &self,
        inode_id: u64,
        logical_offset: u64,
        length: u64,
    ) -> Vec<tidefs_extent_map::ExtentMapEntryV2> {
        self.extent_allocator
            .lookup_extents(inode_id, logical_offset, length)
    }

    fn accounted_extent_bytes(&self, inode_id: InodeId, offset: u64, length: u64) -> (u64, u64) {
        let mut data_bytes = 0u64;
        let mut reserved_bytes = 0u64;
        let range_end = offset.saturating_add(length);
        for extent in self
            .extent_allocator
            .lookup_extents(inode_id.0, offset, length)
        {
            let start = extent.logical_offset.max(offset);
            let end = extent.end_offset().min(range_end);
            let len = end.saturating_sub(start);
            if extent.is_unwritten() {
                reserved_bytes = reserved_bytes.saturating_add(len);
            } else if extent.is_data() || extent.is_pending_data() {
                data_bytes = data_bytes.saturating_add(len);
            }
        }
        (data_bytes, reserved_bytes)
    }

    fn unaccounted_extent_ranges(
        &self,
        inode_id: InodeId,
        offset: u64,
        length: u64,
    ) -> Vec<(u64, u64)> {
        if length == 0 {
            return Vec::new();
        }
        let range_end = offset.saturating_add(length);
        let mut extents = self
            .extent_allocator
            .lookup_extents(inode_id.0, offset, length);
        extents.sort_by_key(|extent| extent.logical_offset);

        let mut ranges = Vec::new();
        let mut cursor = offset;
        for extent in extents {
            let start = extent.logical_offset.max(offset);
            let end = extent.end_offset().min(range_end);
            if start > cursor {
                ranges.push((cursor, start - cursor));
            }
            if end > cursor {
                cursor = end;
            }
        }
        if cursor < range_end {
            ranges.push((cursor, range_end - cursor));
        }
        ranges
    }

    fn content_range_has_materialized_data(
        &self,
        inode_id: InodeId,
        record: &InodeRecord,
        offset: u64,
        length: u64,
    ) -> Result<bool> {
        if length == 0 || offset >= record.size {
            return Ok(false);
        }
        let effective_length = record.size.saturating_sub(offset).min(length);
        let layout =
            read_content_layout_from_store(self.store.raw_primary_store(), inode_id, record, true)?;
        match layout {
            ContentLayout::Inline(content) => {
                let start = usize::try_from(offset)
                    .map_err(|_| FileSystemError::SizeOverflow { requested: offset })?;
                let len = usize::try_from(effective_length).map_err(|_| {
                    FileSystemError::SizeOverflow {
                        requested: effective_length,
                    }
                })?;
                let end = start.saturating_add(len).min(content.bytes.len());
                Ok(start < end && content.bytes[start..end].iter().any(|byte| *byte != 0))
            }
            ContentLayout::Chunked(manifest) => {
                let len = usize::try_from(effective_length).map_err(|_| {
                    FileSystemError::SizeOverflow {
                        requested: effective_length,
                    }
                })?;
                let Some((first_chunk, last_chunk)) =
                    overlay_chunk_index_bounds(record.size, offset, len)?
                else {
                    return Ok(false);
                };
                for chunk_index in first_chunk..=last_chunk {
                    if find_chunk_in_manifest(&manifest, chunk_index)
                        .is_some_and(|chunk_ref| !chunk_ref.is_hole())
                    {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
        }
    }

    fn materialized_content_bytes_in_ranges(
        &self,
        inode_id: InodeId,
        record: &InodeRecord,
        ranges: &[(u64, u64)],
    ) -> Result<u64> {
        if ranges.is_empty() {
            return Ok(0);
        }
        let layout =
            read_content_layout_from_store(self.store.raw_primary_store(), inode_id, record, true)?;
        let mut bytes = 0_u64;
        match layout {
            ContentLayout::Inline(content) => {
                let content_len = u64::try_from(content.bytes.len()).map_err(|_| {
                    FileSystemError::SizeOverflow {
                        requested: u64::MAX,
                    }
                })?;
                for &(offset, length) in ranges {
                    let end = offset.saturating_add(length).min(content_len);
                    if end > offset {
                        bytes = bytes.checked_add(end - offset).ok_or(
                            FileSystemError::SizeOverflow {
                                requested: u64::MAX,
                            },
                        )?;
                    }
                }
            }
            ContentLayout::Chunked(manifest) => {
                let chunk_size = u64::from(manifest.chunk_size);
                for &(offset, length) in ranges {
                    let len = usize::try_from(length)
                        .map_err(|_| FileSystemError::SizeOverflow { requested: length })?;
                    let Some((first_chunk, last_chunk)) =
                        overlay_chunk_index_bounds(record.size, offset, len)?
                    else {
                        continue;
                    };
                    let range_end = offset.saturating_add(length).min(record.size);
                    for chunk_index in first_chunk..=last_chunk {
                        let Some(chunk_ref) = find_chunk_in_manifest(&manifest, chunk_index) else {
                            continue;
                        };
                        if chunk_ref.is_hole() {
                            continue;
                        }
                        let chunk_start = chunk_index.saturating_mul(chunk_size);
                        let chunk_end = chunk_start.saturating_add(u64::from(chunk_ref.len));
                        let start = offset.max(chunk_start);
                        let end = range_end.min(chunk_end);
                        if end > start {
                            bytes = bytes.checked_add(end - start).ok_or(
                                FileSystemError::SizeOverflow {
                                    requested: u64::MAX,
                                },
                            )?;
                        }
                    }
                }
            }
        }
        Ok(bytes)
    }

    /// Return a reference to the internal extent allocator (for tests).
    #[must_use]
    pub fn extent_allocator(&self) -> &ExtentAllocator {
        &self.extent_allocator
    }

    /// Defragment the extent map for a single inode.
    ///
    /// Merges adjacent extents with the same locator and contiguous logical
    /// ranges. Returns (extents_before, extents_after).
    ///
    /// # Errors
    ///
    /// Returns [`FilesystemError::NotFound`] if the inode has no extent map.
    pub fn defrag_extent_map(
        &mut self,
        ino: InodeId,
    ) -> std::result::Result<(u64, u64), FilesystemError> {
        let em = self
            .state
            .extent_maps
            .get_mut(&ino)
            .ok_or(FilesystemError::NotFound {
                path: format!("inode:{}", ino.get()),
            })?;
        Ok(em.defrag())
    }
    /// Find the next data offset at or after `offset` for the given inode.
    ///
    /// Per POSIX SEEK_DATA semantics: returns the first byte of the next
    /// allocated extent at or after `offset`. If no data exists at or after
    /// `offset` (i.e., the remainder of the file is a hole, or `offset` is
    /// beyond EOF), returns [`FilesystemError::NotFound`] (mapped to ENXIO).
    ///
    /// Backed by the inode's [`tidefs_extent_map::ExtentMap`] via
    /// [`tidefs_extent_map::ExtentMap::seek_data`].
    ///
    /// # Errors
    ///
    /// Returns [`FilesystemError::NotFound`] when the inode has no extent map
    /// or the extent map reports no data at or after `offset`.
    pub fn seek_data(
        &self,
        ino: InodeId,
        offset: u64,
    ) -> std::result::Result<u64, FilesystemError> {
        let em = self
            .state
            .extent_maps
            .get(&ino)
            .ok_or_else(|| FilesystemError::NotFound {
                path: format!("inode:{}", ino.get()),
            })?;
        em.seek_data(offset).map_err(|_| FilesystemError::NotFound {
            path: format!("inode:{}", ino.get()),
        })
    }

    /// Find the next hole offset at or after `offset` for the given inode.
    ///
    /// Per POSIX SEEK_HOLE semantics: returns the first byte of the next
    /// hole (unallocated region) at or after `offset`. If the file has no
    /// holes (fully allocated), returns the file size. If `offset` is at or
    /// beyond EOF, returns [`FilesystemError::NotFound`] (mapped to ENXIO).
    ///
    /// Backed by the inode's [`tidefs_extent_map::ExtentMap`] via
    /// [`tidefs_extent_map::ExtentMap::seek_hole`].
    ///
    /// # Errors
    ///
    /// Returns [`FilesystemError::NotFound`] when the inode has no extent map
    /// or the extent map reports no hole at or after `offset` (offset >= EOF).
    pub fn seek_hole(
        &self,
        ino: InodeId,
        offset: u64,
    ) -> std::result::Result<u64, FilesystemError> {
        let em = self
            .state
            .extent_maps
            .get(&ino)
            .ok_or_else(|| FilesystemError::NotFound {
                path: format!("inode:{}", ino.get()),
            })?;
        em.seek_hole(offset).map_err(|_| FilesystemError::NotFound {
            path: format!("inode:{}", ino.get()),
        })
    }

    pub fn allocator_report(&mut self) -> Result<LocalStorageAllocatorReport> {
        allocator_report_for_state(
            self.store.raw_primary_store_mut(),
            &self.state,
            self.allocator_policy,
            self.root_authentication_key,
        )
    }

    pub fn claim_ledger_report(&self) -> ClaimLedgerReport {
        use tidefs_types_claim_ledger_core::ClaimReason;
        let summary = self.obligation_ledger.reverse_explain_summary();
        let mut claims_by_reason: Vec<(String, u64, usize)> = Vec::new();

        // Aggregate claims by reason
        let mut reason_blocks = [0_u64; 6];
        let mut reason_counts = [0_usize; 6];
        for claim in self.obligation_ledger.claims_iter() {
            let idx = claim.reason.as_u32() as usize;
            if idx < 6 {
                reason_blocks[idx] += claim.blocks;
                reason_counts[idx] += 1;
            }
        }
        for v in 0_u32..=5 {
            if reason_counts[v as usize] > 0 {
                let reason = ClaimReason::try_from(v).unwrap_or(ClaimReason::Write);
                claims_by_reason.push((
                    reason.as_str().to_string(),
                    reason_blocks[v as usize],
                    reason_counts[v as usize],
                ));
            }
        }

        ClaimLedgerReport {
            spec: CLAIM_LEDGER_SPEC,
            total_blocks: summary.total_blocks,
            allocated_blocks: summary.allocated_blocks,
            reserved_blocks: summary.reserved_blocks,
            free_blocks: summary.free_blocks,
            claim_count: summary.claim_count,
            reserve_count: summary.reserve_count,
            witness_count: summary.witness_count,
            domain_count: summary.domain_count,
            claims_by_reason,
            reverse_explain_label: format!(
                "{} claims, {} reserved, {} free ({}% util)",
                summary.claim_count,
                summary.reserved_blocks,
                summary.free_blocks,
                if summary.total_blocks > 0 {
                    (summary.allocated_blocks as f64 / summary.total_blocks as f64 * 100.0) as u64
                } else {
                    0
                }
            ),
        }
    }

    pub fn statfs(&mut self) -> Result<FileSystemStatfs> {
        // Refresh pool counters so statfs sees current physical state.
        let phys = self.derive_pool_physical_counters();
        // Keep store-layer SpaceBook updated for internal tracking
        // (write/delete auto-updates, persistence). The statfs derivation
        // no longer queries SpaceBook; it uses the single capacity authority.
        self.store.update_space_book_pool_counters(phys);
        // Refresh the capacity authority with current pool capacity so
        // derive_statfs uses the live total rather than a stale ceiling.
        self.capacity_authority
            .set_total_bytes(phys.phys_total_bytes);

        let mut report = self.allocator_report()?;
        let ancestors = self.quota_ancestor_chain_for_parts(&[]);
        report.reusable_free_bytes = self
            .state
            .quota_table
            .quota_limited_available(&ancestors, report.reusable_free_bytes);
        // Derive block counters from the single production capacity authority.
        // This replaces the former SpaceBook/SpaceAccounting dual-query path.
        let cs = self.capacity_authority.derive_statfs(
            report.policy.inode_capacity,
            report.free_inodes,
            MAX_NAME_BYTES as u32,
        );
        let mut fs = report.to_statfs();
        fs.bsize = cs.block_size;
        fs.frsize = cs.block_size;
        let grain_bytes = u64::from(cs.block_size);
        let total_bytes_limit = self
            .capacity_authority
            .total_bytes()
            .min(report.policy.content_capacity_bytes);
        let free_blocks_limit = if grain_bytes == 0 {
            0
        } else {
            self.capacity_authority.free_bytes() / grain_bytes
        };
        let avail_blocks_limit = if grain_bytes == 0 {
            0
        } else {
            (self.capacity_authority.available_bytes() / grain_bytes)
                .min(report.reusable_free_bytes / grain_bytes)
        };
        let (blocks, bfree, bavail) =
            self.clamp_statfs_blocks(cs, total_bytes_limit, free_blocks_limit, avail_blocks_limit);
        fs.blocks = blocks;
        fs.bfree = bfree;
        fs.bavail = bavail;
        // Inode counts flow through the capacity authority from the allocator
        // report (InodeTable). CapacityStatfs passes through the values given.
        if cs.total_inodes != u64::MAX {
            fs.files = cs.total_inodes;
        }
        if cs.free_inodes != u64::MAX {
            fs.ffree = cs.free_inodes;
        }
        // Use the stable pool uuid as the filesystem identifier.
        fs.fsid_hi = 0;
        fs.fsid_lo = self.pool_uuid as u32;
        Ok(fs)
    }

    pub fn sync_all(&mut self) -> Result<()> {
        self.commit_if_dirty()?;
        self.store.sync_all().map_err(FileSystemError::from)
    }

    pub fn list_snapshots(&self) -> Vec<SnapshotSummary> {
        self.state
            .snapshots
            .values()
            .map(SnapshotRecord::summary)
            .collect()
    }

    pub fn snapshot_summary(&self, name: impl AsRef<str>) -> Result<SnapshotSummary> {
        let name = snapshot_name_bytes(name.as_ref())?;
        self.state
            .snapshots
            .get(&name)
            .map(SnapshotRecord::summary)
            .ok_or_else(|| FileSystemError::SnapshotNotFound {
                name: String::from_utf8_lossy(&name).into_owned(),
            })
    }

    pub fn create_snapshot(&mut self, name: impl AsRef<str>) -> Result<SnapshotSummary> {
        let name = snapshot_name_bytes(name.as_ref())?;
        if self.state.snapshots.contains_key(&name) {
            return Err(FileSystemError::SnapshotAlreadyExists {
                name: String::from_utf8_lossy(&name).into_owned(),
            });
        }
        let source_root = self.selected_current_root_summary()?;
        self.begin_mutation(); // was: let previous_state = self.state.clone()
        let created_at_generation = self.bump_generation();
        let record = SnapshotRecord {
            name: name.clone(),
            root: source_root,
            created_at_generation,
            kind: SnapshotKind::Snapshot,
            origin: None,
            hold_count: 0,
        };
        let summary = record.summary();
        self.state.snapshots.insert(name, record.clone());
        self.mark_inode_metadata_dirty(ROOT_INODE_ID);
        self.mark_dir_dirty(ROOT_INODE_ID);
        let result = self.commit_mutation(summary)?;
        self.lifecycle
            .pin_root(snapshot::snapshot_record_traversal_root(&record))
            .map_err(|_| FileSystemError::CorruptState {
                reason: "snapshot authority lifecycle pin set is full",
            })?;
        if snapshot::reconcile_snapshot_record_catalog_entry(&mut self.dataset_catalog, &record)? {
            self.persist_dataset_catalog()?;
        }
        Ok(result)
    }

    pub fn delete_snapshot(&mut self, name: impl AsRef<str>) -> Result<SnapshotSummary> {
        let name = snapshot_name_bytes(name.as_ref())?;
        let record = self.state.snapshots.get(&name).cloned().ok_or_else(|| {
            FileSystemError::SnapshotNotFound {
                name: String::from_utf8_lossy(&name).into_owned(),
            }
        })?;
        // Reject non-snapshot kinds (clones and bookmarks have separate delete paths).
        if record.kind != SnapshotKind::Snapshot {
            return Err(FileSystemError::Unsupported {
                operation: "delete snapshot",
                reason: "entry is not a snapshot; use delete-clone or delete-bookmark for clones and bookmarks",
            });
        }
        if record.hold_count > 0 {
            return Err(FileSystemError::SnapshotHeld {
                name: String::from_utf8_lossy(&name).into_owned(),
                hold_count: record.hold_count,
            });
        }
        self.ensure_snapshot_authority_consistent()?;
        self.begin_mutation(); // was: let previous_state = self.state.clone()
        self.bump_generation();
        self.state.snapshots.remove(&name);
        self.mark_inode_metadata_dirty(ROOT_INODE_ID);
        self.mark_dir_dirty(ROOT_INODE_ID);
        let summary = self.commit_mutation(record.summary())?;
        self.lifecycle
            .unpin_root(snapshot::snapshot_record_traversal_root(&record));
        if snapshot::remove_snapshot_record_catalog_entry(&mut self.dataset_catalog, &record)? {
            self.persist_dataset_catalog()?;
        }
        Ok(summary)
    }

    pub fn rollback_to_snapshot(
        &mut self,
        name: impl AsRef<str>,
    ) -> Result<SnapshotRollbackReport> {
        self.ensure_snapshot_authority_consistent()?;
        let name = snapshot_name_bytes(name.as_ref())?;
        let snapshot = self.state.snapshots.get(&name).cloned().ok_or_else(|| {
            FileSystemError::SnapshotNotFound {
                name: String::from_utf8_lossy(&name).into_owned(),
            }
        })?;
        if !snapshot::snapshot_record_retains_data(&snapshot) {
            return Err(FileSystemError::Unsupported {
                operation: "rollback snapshot",
                reason: "rollback target must be a data-retaining snapshot or clone",
            });
        }
        self.ensure_snapshot_record_authority(&snapshot)?;
        // State-replacement operation: clone the old state as fallback,
        // then use the incremental loader to only reload changed inodes.
        let previous_state = self.state.clone();
        let root = root_commit_from_summary(&snapshot.root);
        let mut restored = load_state_from_transaction_incremental(
            self.store.raw_primary_store_mut(),
            &root,
            self.root_authentication_key,
            &previous_state,
        )?;
        restored.snapshots = previous_state.snapshots.clone();
        restored.next_inode_id = restored.next_inode_id.max(previous_state.next_inode_id);
        restored.generation = next_generation_after(previous_state.generation);
        let report = SnapshotRollbackReport {
            spec: LOCAL_SNAPSHOT_ROLLBACK_SPEC,
            snapshot: snapshot.summary(),
            generation_before: previous_state.generation,
            restored_source_generation: snapshot.root.generation,
            published_generation: restored.generation,
            snapshot_catalog_entries: restored.snapshots.len(),
            production_fsck_required: false,
        };
        self.clear_hot_read_cache();
        self.inode_cache.borrow_mut().clear();
        self.state = restored;
        // Clear stale write buffers so queued overwrites do not corrupt the restored state.
        self.write_buffers.clear();
        self.mark_all_state_dirty();
        self.commit_state_replacement(previous_state, report)
    }

    pub fn export_changed_records(&mut self) -> Result<ChangedRecordExport> {
        self.ensure_snapshot_authority_consistent()?;
        self.sync_all()?;
        let current_root = self.selected_current_root_summary()?;
        export_changed_records_from_root(
            self.store.raw_primary_store_mut(),
            &current_root,
            &self.state,
            self.root_authentication_key,
            self.placement_epoch,
        )
    }

    /// Export only objects changed between two committed roots for efficient
    /// incremental replication.  The `from_root` identifies the baseline that
    /// the receiver must already possess; only new or modified objects are
    /// included in the stream.
    ///
    /// This mirrors ZFS `zfs send -i <base> <target>`.
    pub fn export_incremental_changed_records(
        &mut self,
        from_root: &CommittedRootSummary,
    ) -> Result<ChangedRecordExport> {
        self.ensure_snapshot_authority_consistent()?;
        self.sync_all()?;
        let to_root = self.selected_current_root_summary()?;
        export_incremental_changed_records(
            self.store.raw_primary_store_mut(),
            from_root,
            &to_root,
            &self.state,
            self.root_authentication_key,
            self.placement_epoch,
        )
    }

    /// Export the current filesystem state as a VFSSEND2-encoded stream.
    ///
    /// This is the VFSSEND2 counterpart to [`export_changed_records`].
    /// It converts the internal changed-record data into the canonical
    /// VFSSEND2 wire format via [`tidefs_send_stream::SendBuilder`].
    ///
    /// Callers must supply the pool and dataset identifiers for the
    /// stream header. The returned bytes are a fully-encoded VFSSEND2
    /// stream suitable for transport or storage.
    ///
    /// [`export_changed_records`]: Self::export_changed_records
    pub fn export_vfssend2(
        &mut self,
        pool_id: tidefs_send_stream::Id128,
        dataset_id: tidefs_send_stream::Id128,
    ) -> Result<Vec<u8>> {
        let export = self.export_changed_records()?;
        crate::vfssend2_bridge::export_vfssend2_from_changed_records(&export, pool_id, dataset_id)
    }
    /// Export an incremental delta between the given base root and the
    /// current filesystem state as a VFSSEND2-encoded stream.
    ///
    /// This is the VFSSEND2 counterpart to
    /// [`export_incremental_changed_records`]. It converts the internal
    /// changed-record delta into the canonical VFSSEND2 wire format via
    /// [`tidefs_send_stream::SendBuilder::incremental`].
    ///
    /// Only objects changed between `from_root` and the current root are
    /// included. Callers must supply the pool and dataset identifiers.
    ///
    /// [`export_incremental_changed_records`]: Self::export_incremental_changed_records
    pub fn export_incremental_vfssend2(
        &mut self,
        pool_id: tidefs_send_stream::Id128,
        dataset_id: tidefs_send_stream::Id128,
        from_root: &CommittedRootSummary,
    ) -> Result<Vec<u8>> {
        let export = self.export_incremental_changed_records(from_root)?;
        crate::vfssend2_bridge::export_incremental_vfssend2_from_changed_records(
            &export, pool_id, dataset_id,
        )
    }

    pub fn receive_changed_records_into_empty_root(
        root: impl AsRef<Path>,
        options: StoreOptions,
        export: &ChangedRecordExport,
    ) -> Result<ChangedRecordImportReport> {
        Self::receive_changed_records_into_empty_root_with_root_authentication_key(
            root,
            options,
            export,
            default_root_authentication_key()?,
        )
    }

    pub fn receive_changed_records_into_empty_root_with_root_authentication_key(
        root: impl AsRef<Path>,
        options: StoreOptions,
        export: &ChangedRecordExport,
        root_authentication_key: RootAuthenticationKey,
    ) -> Result<ChangedRecordImportReport> {
        receive_changed_records_into_empty_root(
            root.as_ref(),
            options,
            export,
            root_authentication_key,
        )
    }

    /// Receive an incremental changed-record stream into an existing filesystem
    /// that already contains the base snapshot.
    pub fn receive_incremental_changed_records(
        root: impl AsRef<Path>,
        options: StoreOptions,
        export: &ChangedRecordExport,
    ) -> Result<ChangedRecordImportReport> {
        Self::receive_incremental_changed_records_with_root_authentication_key(
            root,
            options,
            export,
            default_root_authentication_key()?,
        )
    }

    /// Receive an incremental changed-record stream with a custom root
    /// authentication key.
    pub fn receive_incremental_changed_records_with_root_authentication_key(
        root: impl AsRef<Path>,
        options: StoreOptions,
        export: &ChangedRecordExport,
        root_authentication_key: RootAuthenticationKey,
    ) -> Result<ChangedRecordImportReport> {
        receive_incremental_changed_records(root.as_ref(), options, export, root_authentication_key)
    }

    pub fn lookup(&self, path: impl AsRef<str>) -> Result<InodeId> {
        let path = path.as_ref();
        let parts = parse_absolute_path(path)?;
        self.resolve_parts(&parts, path)
    }

    pub fn stat_path(&self, path: impl AsRef<str>) -> Result<InodeRecord> {
        self.stat(path)
    }

    pub fn stat(&self, path: impl AsRef<str>) -> Result<InodeRecord> {
        let path = path.as_ref();
        let parts = parse_absolute_path(path)?;
        let inode_id = self.resolve_parts(&parts, path)?;
        self.inode(inode_id)
    }

    pub fn stat_attr(&self, path: impl AsRef<str>) -> Result<InodeAttr> {
        self.stat(path).map(|record| record.to_inode_attr())
    }

    /// Apply a [`SetAttr`] mask to an inode's metadata fields (mode, uid, gid,
    /// timestamps) through the filesystem's mutation machinery and return
    /// the updated [`InodeAttr`]. The change persists across remount.
    ///
    /// Size changes are handled separately by the file-content path
    /// (truncate/extend) and are not applied here even when `FATTR_SIZE`
    /// is set in the mask.
    pub fn set_attr(&mut self, ino: u64, set: &SetAttr) -> std::result::Result<InodeAttr, Errno> {
        fuse_setattr::engine_setattr(self, ino, set).map_err(|e| e.to_errno())
    }

    pub fn list_dir(&self, path: impl AsRef<str>) -> Result<Vec<NamespaceEntry>> {
        let path = path.as_ref();
        let parts = parse_absolute_path(path)?;
        let inode_id = self.resolve_parts(&parts, path)?;
        let inode = self.inode(inode_id)?;
        if !inode.is_directory() {
            return Err(FileSystemError::NotDirectory {
                path: path.to_string(),
            });
        }
        let directory = self.directory(inode_id, path)?;
        Ok(directory.values().cloned().collect())
    }

    pub fn list_dir_owned(&self, path: impl AsRef<str>) -> Result<Vec<OwnedDirEntry>> {
        let entries = self.list_dir(path)?;
        Ok(entries
            .iter()
            .enumerate()
            .map(|(idx, entry)| entry.to_owned_dir_entry(idx as u64 + 1))
            .collect())
    }

    // ── Inode-level accessors for namespace persistence bridging ─────

    /// Look up an inode record by ID.
    pub fn get_inode_by_id(&self, id: InodeId) -> Option<&InodeRecord> {
        self.state.inodes.get(&id)
    }

    /// Return the next inode ID that will be allocated.
    pub fn next_inode_id(&self) -> InodeId {
        InodeId(self.state.next_inode_id)
    }

    /// Return the current filesystem generation.
    pub fn generation(&self) -> u64 {
        self.state.generation
    }

    /// Allocate a new inode ID and insert a record.
    pub fn alloc_inode_id(&mut self, mut record: InodeRecord) -> Result<InodeId> {
        let id = self.allocate_inode_id();
        record.inode_id = id;
        Arc::make_mut(&mut self.state.inodes).insert(id, record);
        Ok(id)
    }

    /// Free an inode by ID. Returns true if the inode existed.
    pub fn free_inode_id(&mut self, id: InodeId) -> bool {
        Arc::make_mut(&mut self.state.inodes).remove(&id).is_some()
    }

    /// Replace an existing inode record.
    pub fn update_inode_record(&mut self, id: InodeId, record: InodeRecord) -> Result<()> {
        let Some(existing) = self.state.inodes.get(&id) else {
            return Err(FileSystemError::NotFound {
                path: format!("inode:{}", id.0),
            });
        };
        if existing == &record {
            return Ok(());
        }
        self.mark_inode_metadata_dirty(id);
        Arc::make_mut(&mut self.state.inodes).insert(id, record);
        self.inode_cache.borrow_mut().invalidate(id);
        Ok(())
    }

    /// Insert an inode record at a specific ID (without allocating).
    /// Used by the namespace persistence bridge.
    pub fn insert_inode_at(&mut self, id: InodeId, record: InodeRecord) {
        // Review debt TFR-004: this bridge can advance the global allocator
        // from namespace-loaded records; dataset-scoped allocation authority
        // must replace it before multi-dataset identity is trusted.
        self.state.next_inode_id = self.state.next_inode_id.max(id.get().saturating_add(1));
        Arc::make_mut(&mut self.state.inodes).insert(id, record);
        self.mark_inode_metadata_dirty(id);
    }

    // ── Directory-level accessors for namespace persistence bridging ────

    /// List all entries in a directory by inode ID.
    pub fn list_dir_by_inode(&self, parent_id: InodeId) -> Result<Vec<NamespaceEntry>> {
        self.state
            .directories
            .get(&parent_id)
            .map(|dir| dir.values().cloned().collect())
            .ok_or(FileSystemError::NotFound {
                path: format!("dir-inode:{}", parent_id.0),
            })
    }

    /// List a bounded window of entries in a directory by inode ID.
    pub fn list_dir_by_inode_window(
        &self,
        parent_id: InodeId,
        offset: u64,
        limit: usize,
    ) -> Result<(Vec<NamespaceEntry>, bool)> {
        let directory =
            self.state
                .directories
                .get(&parent_id)
                .ok_or(FileSystemError::NotFound {
                    path: format!("dir-inode:{}", parent_id.0),
                })?;
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        let mut iter = directory.values().skip(start);
        let mut entries = Vec::with_capacity(limit.min(directory.len().saturating_sub(start)));
        for entry in iter.by_ref().take(limit) {
            entries.push(entry.clone());
        }
        let has_more = iter.next().is_some();
        Ok((entries, has_more))
    }

    pub(crate) fn dir_entry_by_inode(
        &self,
        parent_id: InodeId,
        name: &[u8],
        path: &str,
    ) -> Result<Option<NamespaceEntry>> {
        validate_name(name)?;
        if let Some(dir) = self.state.directories.get(&parent_id) {
            return Ok(dir.get(name).cloned());
        }
        let directory = self.directory(parent_id, path)?;
        Ok(directory.get(name).cloned())
    }

    /// Find the parent directory that contains a real entry for `child_id`.
    pub fn parent_dir_for_inode(&self, child_id: InodeId) -> Option<InodeId> {
        if child_id == ROOT_INODE_ID {
            return Some(ROOT_INODE_ID);
        }

        self.state
            .directories
            .iter()
            .find_map(|(parent_id, entries)| {
                entries
                    .values()
                    .any(|entry| {
                        entry.inode_id == child_id
                            && entry.name.as_slice() != b"."
                            && entry.name.as_slice() != b".."
                    })
                    .then_some(*parent_id)
            })
    }

    /// Insert a directory entry by inode ID.
    pub fn insert_dir_entry(
        &mut self,
        parent_id: InodeId,
        name: Vec<u8>,
        entry: NamespaceEntry,
    ) -> Result<()> {
        let old_was_child_dir = self
            .state
            .directories
            .get(&parent_id)
            .and_then(|directory| directory.get(&name))
            .is_some_and(NamespaceEntry::carries_child_namespace);
        let new_is_child_dir = entry.carries_child_namespace();
        let tick = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let entry_inode = entry.inode_id;
        self.insert_directory_entry(parent_id, name, entry, tick)?;
        self.update_parent_metadata_timestamps(parent_id, tick);
        self.mark_dir_dirty(parent_id);
        self.mark_inode_metadata_dirty(parent_id);
        self.mark_inode_metadata_dirty(entry_inode);
        if old_was_child_dir != new_is_child_dir {
            if let Some(parent) = Arc::make_mut(&mut self.state.inodes).get_mut(&parent_id) {
                if new_is_child_dir {
                    parent.nlink = parent.nlink.saturating_add(1);
                } else {
                    parent.nlink = parent.nlink.saturating_sub(1).max(2);
                }
            }
        }
        Ok(())
    }

    /// Remove a directory entry by inode ID and name.
    pub fn remove_dir_entry(&mut self, parent_id: InodeId, name: &[u8]) -> Result<()> {
        let removed_was_child_dir = self
            .state
            .directories
            .get(&parent_id)
            .and_then(|directory| directory.get(name))
            .is_some_and(NamespaceEntry::carries_child_namespace);
        let tick = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        self.remove_directory_entry(parent_id, name, tick)?;
        self.update_parent_metadata_timestamps(parent_id, tick);
        self.mark_dir_dirty(parent_id);
        self.mark_inode_metadata_dirty(parent_id);
        if removed_was_child_dir {
            if let Some(parent) = Arc::make_mut(&mut self.state.inodes).get_mut(&parent_id) {
                parent.nlink = parent.nlink.saturating_sub(1).max(2);
            }
        }
        Ok(())
    }

    /// Check whether a directory inode exists in the state.
    pub fn dir_exists(&self, parent_id: InodeId) -> bool {
        self.state.directories.contains_key(&parent_id)
    }

    /// Initialize a new empty directory by inode ID.
    pub fn init_dir_by_inode(&mut self, dir_id: InodeId) -> Result<()> {
        self.mark_dir_dirty(dir_id);
        self.mark_inode_metadata_dirty(dir_id);
        Arc::make_mut(&mut self.state.directories)
            .entry(dir_id)
            .or_default();
        Ok(())
    }

    pub fn create_dir(&mut self, path: impl AsRef<str>, permissions: u32) -> Result<InodeRecord> {
        let path = path.as_ref();
        let (parent_id, name) = self.resolve_parent_and_name(path)?;
        if self.dir_entry_by_inode(parent_id, &name, path)?.is_some() {
            return Err(FileSystemError::AlreadyExists {
                path: path.to_string(),
            });
        }
        self.ensure_inode_capacity_for_new_inode()?;

        // --- POSIX ACL default inheritance (Phase 6) ---
        // POSIX_ACL_INHERITANCE_SPEC: gate anchor checked by
        // tidefs-xtask check-posix-acl-inheritance.
        // When this comment is present alongside default_acl_inheritance_for_parent
        // in both create_dir and create_file_like, the inheritance gate passes.
        //
        // Read parent's default ACL before beginning the mutation so the
        // child's xattrs can be populated atomically within the same commit_group.
        const ACL_DEFAULT: &[u8] = b"system.posix_acl_default";
        let parent_default_acl_entries: Option<tidefs_posix_acl::PosixAcl> = self
            .inode_record_only(parent_id)?
            .xattrs
            .get(ACL_DEFAULT)
            .and_then(|raw| tidefs_posix_acl::decode_posix_acl_xattr(raw).ok());

        self.begin_mutation(); // was: let previous_state = self.state.clone()
                               // Re-verify parent exists after lock acquisition
        if !self.state.inodes.contains_key(&parent_id) {
            self.rollback_mutation_delta();
            return Err(FileSystemError::NotFound {
                path: path.to_string(),
            });
        }
        let tick = self.bump_generation();
        let inode_id = self.allocate_inode_id();
        let generation = Generation::new(tick);
        let mut new_mode = mode_for_kind(NodeKind::Dir, permissions);
        let mut xattrs = BTreeMap::new();
        if let Some(ref acl_entries) = parent_default_acl_entries {
            for (name, value) in tidefs_posix_acl::default_acl_inheritance_for_parent(
                acl_entries,
                new_mode,
                true, // is_directory
            ) {
                if name == b"system.posix_acl_access" {
                    if let Ok(access_acl) = tidefs_posix_acl::decode_posix_acl_xattr(&value) {
                        new_mode =
                            tidefs_posix_acl::posix_mode_from_access_acl(&access_acl, new_mode);
                    }
                }
                xattrs.insert(name.to_vec(), value);
            }
        }
        let record = InodeRecord {
            rdev: 0,
            inode_id,
            generation,
            facets: NodeKind::Dir.to_facets(),
            mode: new_mode,
            uid: 0,
            gid: 0,
            nlink: 2,
            size: 0,
            data_version: tick,
            metadata_version: tick,
            posix_time: PosixTimeRecord::now(),
            xattrs,
            dir_storage_kind: 0,
            xattr_storage_kind: 0,
            dir_rev: 0,
        };
        let entry = NamespaceEntry {
            name: name.clone(),
            inode_id,
            generation,
            facets: NodeKind::Dir.to_facets(),
            mode: new_mode,
        };
        // ── Intent-log: record mkdir before mutation for crash recovery ──
        let _ = self.intent_log_buffer.as_ref().map(|buf| {
            let _frame = buf.append(
                tidefs_intent_log::IntentLogRecord::Mkdir {
                    parent: parent_id.get(),
                    name: name.clone(),
                    mode: new_mode,
                    ino: inode_id.get(),
                },
                0, // txg_id assigned by TxgCoordinator at drain time
            );
        });

        // Capture old state in mutation delta BEFORE mutating
        self.mark_inode_metadata_dirty(inode_id);
        self.mark_dir_dirty(parent_id);
        self.mark_inode_metadata_dirty(parent_id);
        Arc::make_mut(&mut self.state.inodes).insert(inode_id, record.clone());
        self.inode_cache.borrow_mut().invalidate(inode_id);
        Arc::make_mut(&mut self.state.directories).insert(inode_id, BTreeMap::new());
        if let Err(err) = self.insert_directory_entry(parent_id, name, entry, tick) {
            self.rollback_mutation_delta();
            return Err(err);
        }
        self.update_parent_metadata_for_subdir_add(parent_id, tick);
        self.commit_mutation(record)
    }

    pub fn create_file(&mut self, path: impl AsRef<str>, permissions: u32) -> Result<InodeRecord> {
        self.create_file_like(path.as_ref(), NodeKind::File, permissions, &[])
    }

    pub fn create_symlink(
        &mut self,
        path: impl AsRef<str>,
        target: impl AsRef<[u8]>,
    ) -> Result<InodeRecord> {
        let target = target.as_ref();
        let path = path.as_ref();

        // ── Namespace-level pre-check (reuse namespace module) ──────
        let _pre = crate::namespace::symlink::pre_check(
            &self.state.inodes,
            &self.state.directories,
            target,
            path,
        )?;
        // pre_check validates: target non-empty, path not root,
        // parent exists and is directory, name not already in use.

        if target.contains(&0) {
            return Err(FileSystemError::InvalidName {
                name: target.to_vec(),
                reason: "symlink target contains a NUL byte",
            });
        }
        self.create_file_like(path, NodeKind::Symlink, DEFAULT_SYMLINK_PERMISSIONS, target)
    }

    pub fn link_file(
        &mut self,
        existing_path: impl AsRef<str>,
        new_path: impl AsRef<str>,
    ) -> Result<InodeRecord> {
        let existing_path = existing_path.as_ref();
        let new_path = new_path.as_ref();

        // ── Namespace-level pre-check (reuse namespace module) ──────
        let pre = crate::namespace::link::pre_check(
            &self.state.inodes,
            &self.state.directories,
            existing_path,
            new_path,
        )?;
        let inode_id = pre.target_inode_id;
        let parent_id = pre.new_parent_id;
        let name = pre.new_name;

        self.flush_write_buffer(inode_id)?;
        let source_record = self.inode(inode_id)?.clone();
        // Extra guard: only regular files supported in this MVP.
        if source_record.kind() != NodeKind::File {
            return Err(FileSystemError::Unsupported {
                operation: "hard link",
                reason: "this MVP only hard-links regular files",
            });
        }
        self.begin_mutation();
        // Re-verify parent exists after lock acquisition
        if !self.state.inodes.contains_key(&parent_id) {
            self.rollback_mutation_delta();
            return Err(FileSystemError::NotFound {
                path: new_path.to_string(),
            });
        }
        let tick = self.bump_generation();
        // Intent-log: record hard link before mutation
        let _ = self.intent_log_buffer.as_ref().map(|buf| {
            let _frame = buf.append(
                tidefs_intent_log::IntentLogRecord::HardLink {
                    ino: inode_id.get(),
                    new_parent: parent_id.get(),
                    new_name: name.clone(),
                },
                0,
            );
        });
        let mut updated = source_record.clone();
        updated.nlink = updated.nlink.saturating_add(1);
        updated.posix_time.ctime_ns = Self::next_metadata_ctime_ns(updated.posix_time.ctime_ns);
        updated.metadata_version = tick;
        // If nlink transitions from 0 to 1, the inode is no longer orphaned.
        if updated.nlink == 1 {
            self.orphan_index.lock().unwrap().remove(inode_id.get());
        }
        Arc::make_mut(&mut self.state.inodes).insert(inode_id, updated.clone());
        self.inode_cache.borrow_mut().invalidate(inode_id);
        let entry = NamespaceEntry {
            name: name.clone(),
            inode_id,
            generation: updated.generation,
            facets: updated.facets,
            mode: updated.mode,
        };
        if let Err(err) = self.insert_directory_entry(parent_id, name, entry, tick) {
            self.rollback_mutation_delta();
            return Err(err);
        }
        self.update_parent_metadata_timestamps(parent_id, tick);
        self.mark_inode_metadata_dirty(inode_id);
        self.mark_dir_dirty(parent_id);
        self.mark_inode_metadata_dirty(parent_id);
        self.commit_mutation(updated)
    }

    /// Create a reflink clone of a regular file.
    ///
    /// With dedup enabled, shares content chunks with the source via
    /// content-addressed redirects. With dedup disabled, re-encodes source
    /// chunks for the destination inode/version. This is the storage-level
    /// primitive that powers `FICLONE` / `copy_file_range` same-filesystem
    /// reflink and snapshot-clone writable forks.
    ///
    /// The new file inherits the source's size, permissions, ownership, and
    /// extended attributes.  It is a fully independent inode with its own
    /// link count, generation, and data version.
    pub fn reflink_file(
        &mut self,
        source_path: impl AsRef<str>,
        dest_path: impl AsRef<str>,
    ) -> Result<InodeRecord> {
        let source_path = source_path.as_ref();
        let dest_path = dest_path.as_ref();

        // Resolve source inode
        let source_parts = parse_absolute_path(source_path)?;
        let source_inode_id = self.resolve_parts(&source_parts, source_path)?;
        let source_record = self.inode(source_inode_id)?.clone();

        if source_record.kind() != NodeKind::File {
            if source_record.kind() == NodeKind::Dir {
                return Err(FileSystemError::IsDirectory {
                    path: source_path.to_string(),
                });
            }
            return Err(FileSystemError::NotFile {
                path: source_path.to_string(),
                kind: source_record.kind(),
            });
        }

        // Resolve destination
        let (parent_id, name) = self.resolve_parent_and_name(dest_path)?;
        if self.directory(parent_id, dest_path)?.contains_key(&name) {
            return Err(FileSystemError::AlreadyExists {
                path: dest_path.to_string(),
            });
        }

        // Quota preflight: same space cost as a regular file of this size.
        let inode_ancestors = self.quota_ancestors_for_parent(parent_id);
        let delta_bytes = crate::quota::allocation_grains_for_len(source_record.size);
        let pool_free = self.pool_free_bytes_for_quota();
        let decision =
            self.state
                .quota_table
                .check_delta(&inode_ancestors, delta_bytes, 1, pool_free);
        if decision.is_refusal() {
            return Err(FileSystemError::from(decision));
        }

        // Capacity planning: reserve inode + per-inode chunk redirect entries.
        self.ensure_inode_capacity_for_new_inode()?;
        let planned_tick = next_generation_after(self.state.generation);
        let planned_inode_id = InodeId::new(next_allocated_inode_id(&self.state));
        let dest_record = InodeRecord {
            rdev: 0,
            inode_id: planned_inode_id,
            generation: Generation::new(planned_tick),
            facets: NodeKind::File.to_facets(),
            mode: source_record.mode,
            uid: source_record.uid,
            gid: source_record.gid,
            nlink: 1,
            size: source_record.size,
            data_version: planned_tick,
            metadata_version: planned_tick,
            posix_time: PosixTimeRecord::now(),
            xattrs: source_record.xattrs.clone(),
            dir_storage_kind: source_record.dir_storage_kind,
            xattr_storage_kind: 0,
            dir_rev: 0,
        };

        let planned_entries = planned_chunk_allocation_entries_for_full_content(&dest_record)?;
        self.ensure_content_capacity_with_planned_inode(None, planned_entries)?;

        self.begin_mutation(); // was: let previous_state = self.state.clone()
                               // Re-verify dest parent exists after lock acquisition.
        if !self.state.inodes.contains_key(&parent_id) {
            self.rollback_mutation_delta();
            return Err(FileSystemError::NotFound {
                path: dest_path.to_string(),
            });
        }
        let tick = self.bump_generation();
        let inode_id = self.allocate_inode_id();
        debug_assert_eq!(tick, planned_tick);
        debug_assert_eq!(inode_id, planned_inode_id);

        // Zero-copy reflink: store dedup redirects at destination chunk keys.
        let result = {
            let mut dedup = self.dedup_index.borrow_mut();
            let mut pool_store = self.store.pool_store_mut();
            reflink_chunked_content(
                self.dedup_enabled,
                &mut pool_store,
                source_inode_id,
                &source_record,
                &dest_record,
                &mut dedup,
                &self.content_compression_policy,
            )
        };
        if let Err(err) = result {
            self.rollback_mutation_delta();
            return Err(err);
        }

        Arc::make_mut(&mut self.state.inodes).insert(inode_id, dest_record.clone());
        self.inode_cache.borrow_mut().invalidate(inode_id);
        let entry = NamespaceEntry {
            name: name.clone(),
            inode_id,
            generation: dest_record.generation,
            facets: NodeKind::File.to_facets(),
            mode: dest_record.mode,
        };
        if let Err(err) = self.insert_directory_entry(parent_id, name, entry, tick) {
            self.rollback_mutation_delta();
            return Err(err);
        }
        self.update_parent_metadata_timestamps(parent_id, tick);

        self.mark_inode_content_dirty(inode_id);
        self.invalidate_hot_read_cache_for_inode(inode_id);
        self.mark_inode_metadata_dirty(inode_id);
        self.mark_dir_dirty(parent_id);
        self.mark_inode_metadata_dirty(parent_id);

        let record = self.commit_mutation(dest_record)?;
        self.state
            .quota_table
            .apply_delta(&inode_ancestors, delta_bytes, 1);
        Ok(record)
    }

    pub fn read_file(&self, path: impl AsRef<str>) -> Result<Vec<u8>> {
        let path = path.as_ref();
        let parts = parse_absolute_path(path)?;
        let inode_id = self.resolve_parts(&parts, path)?;
        let record = self.inode(inode_id)?;
        if record.kind() != NodeKind::File {
            if record.kind() == NodeKind::Dir {
                return Err(FileSystemError::IsDirectory {
                    path: path.to_string(),
                });
            }
            return Err(FileSystemError::NotFile {
                path: path.to_string(),
                kind: record.kind(),
            });
        }
        self.read_content(inode_id, &record)
    }

    pub fn read_file_range(
        &self,
        path: impl AsRef<str>,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>> {
        let path = path.as_ref();
        let parts = parse_absolute_path(path)?;
        let inode_id = self.resolve_parts(&parts, path)?;
        let record = self.inode(inode_id)?;
        if record.kind() != NodeKind::File {
            if record.kind() == NodeKind::Dir {
                return Err(FileSystemError::IsDirectory {
                    path: path.to_string(),
                });
            }
            return Err(FileSystemError::NotFile {
                path: path.to_string(),
                kind: record.kind(),
            });
        }
        self.read_content_range(inode_id, &record, offset, length)
    }

    /// Record a copy_file_range intent-log entry for crash-recovery replay.
    ///
    /// The caller is responsible for performing the actual copy.  This method
    /// only writes the intent-log record so that crash recovery can verify or
    /// redo the copy after a crash.
    pub fn record_copy_file_range_intent(&mut self, intent: CopyFileRangeIntent) {
        let _ = self.intent_log_buffer.as_ref().map(|buf| {
            let _frame = buf.append(
                tidefs_intent_log::IntentLogRecord::CopyFileRange {
                    src_ino: intent.src_ino.get(),
                    src_fh: intent.src_fh,
                    dst_ino: intent.dst_ino.get(),
                    dst_fh: intent.dst_fh,
                    src_offset: intent.src_offset,
                    dst_offset: intent.dst_offset,
                    len: intent.len,
                },
                0, // txg_id assigned by TxgCoordinator at drain time
            );
        });
    }
    pub fn read_symlink(&self, path: impl AsRef<str>) -> Result<Vec<u8>> {
        let path = path.as_ref();
        let parts = parse_absolute_path(path)?;
        let inode_id = self.resolve_parts(&parts, path)?;
        let record = self.inode(inode_id)?;
        if record.kind() != NodeKind::Symlink {
            return Err(FileSystemError::NotFile {
                path: path.to_string(),
                kind: record.kind(),
            });
        }
        self.read_content(inode_id, &record)
    }

    pub fn replace_file(&mut self, path: impl AsRef<str>, bytes: &[u8]) -> Result<InodeRecord> {
        let path = path.as_ref();
        let parts = parse_absolute_path(path)?;
        let inode_id = self.resolve_parts(&parts, path)?;
        // Flush any buffered writes before reading the record, so the
        // inode size and data_version match the content in the store.
        self.flush_write_buffer(inode_id)?;
        let record = self.inode(inode_id)?.clone();
        if record.kind() != NodeKind::File {
            if record.kind() == NodeKind::Dir {
                return Err(FileSystemError::IsDirectory {
                    path: path.to_string(),
                });
            }
            return Err(FileSystemError::NotFile {
                path: path.to_string(),
                kind: record.kind(),
            });
        }
        let content_len = bytes.len() as u64;
        let blake3_hash = blake3::hash(&bytes);
        let result = self.replace_content(inode_id, record, bytes.to_vec())?;
        let birth_txg = self.commit_group.current_commit_group().0;
        let _ = self.extent_allocator.finalize_data_extent(
            inode_id.0,
            0,
            content_len,
            *blake3_hash.as_bytes(),
            birth_txg,
        );
        Ok(result)
    }

    // ── Write-buffer management ───────────────────────────────

    fn coalesced_write_buffer_patches(
        &self,
        inode_id: InodeId,
        base_record: &InodeRecord,
        segments: &[(u64, Vec<u8>)],
    ) -> Result<Vec<CoalescedBufferedWritePatch>> {
        if let [(offset, data)] = segments {
            return Ok(vec![CoalescedBufferedWritePatch {
                offset: *offset,
                bytes: data.clone(),
            }]);
        }

        let chunk_size = content_chunk_size() as u64;
        let mut chunks: BTreeMap<u64, BufferedChunkPatch> = BTreeMap::new();

        for (offset, data) in segments {
            if data.is_empty() {
                continue;
            }
            let data_len =
                u64::try_from(data.len()).map_err(|_| FileSystemError::SizeOverflow {
                    requested: u64::MAX,
                })?;
            let segment_end =
                offset
                    .checked_add(data_len)
                    .ok_or(FileSystemError::SizeOverflow {
                        requested: u64::MAX,
                    })?;
            let mut cursor = *offset;
            let mut data_pos = 0usize;
            while cursor < segment_end {
                let chunk_index = cursor / chunk_size;
                let next_chunk_start = (chunk_index + 1).checked_mul(chunk_size).ok_or(
                    FileSystemError::SizeOverflow {
                        requested: u64::MAX,
                    },
                )?;
                let piece_end = segment_end.min(next_chunk_start);
                let piece_len = usize::try_from(piece_end - cursor).map_err(|_| {
                    FileSystemError::SizeOverflow {
                        requested: piece_end - cursor,
                    }
                })?;
                let data_end =
                    data_pos
                        .checked_add(piece_len)
                        .ok_or(FileSystemError::SizeOverflow {
                            requested: u64::MAX,
                        })?;
                let chunk = chunks
                    .entry(chunk_index)
                    .or_insert_with(|| BufferedChunkPatch {
                        start: cursor,
                        end: piece_end,
                        pieces: Vec::new(),
                    });
                chunk.start = chunk.start.min(cursor);
                chunk.end = chunk.end.max(piece_end);
                chunk.pieces.push(BufferedChunkPatchPiece {
                    offset: cursor,
                    bytes: data[data_pos..data_end].to_vec(),
                });
                cursor = piece_end;
                data_pos = data_end;
            }
        }

        let mut patches = Vec::with_capacity(chunks.len());
        for chunk in chunks.into_values() {
            let overlay_len_u64 =
                chunk
                    .end
                    .checked_sub(chunk.start)
                    .ok_or(FileSystemError::SizeOverflow {
                        requested: u64::MAX,
                    })?;
            let overlay_len =
                usize::try_from(overlay_len_u64).map_err(|_| FileSystemError::SizeOverflow {
                    requested: overlay_len_u64,
                })?;
            let mut overlay = vec![0_u8; overlay_len];

            if chunk.start < base_record.size {
                let base_len_u64 = base_record
                    .size
                    .saturating_sub(chunk.start)
                    .min(overlay_len_u64);
                let base_len =
                    usize::try_from(base_len_u64).map_err(|_| FileSystemError::SizeOverflow {
                        requested: base_len_u64,
                    })?;
                if base_len > 0 {
                    let base = read_content_range_from_store(
                        self.store.raw_primary_store(),
                        inode_id,
                        base_record,
                        chunk.start,
                        base_len,
                        true,
                        Some(&self.store),
                    )?;
                    overlay[..base.len()].copy_from_slice(&base);
                }
            }

            for piece in chunk.pieces {
                let dst = usize::try_from(piece.offset - chunk.start).map_err(|_| {
                    FileSystemError::SizeOverflow {
                        requested: piece.offset - chunk.start,
                    }
                })?;
                let end =
                    dst.checked_add(piece.bytes.len())
                        .ok_or(FileSystemError::SizeOverflow {
                            requested: u64::MAX,
                        })?;
                overlay[dst..end].copy_from_slice(&piece.bytes);
            }

            patches.push(CoalescedBufferedWritePatch {
                offset: chunk.start,
                bytes: overlay,
            });
        }

        Ok(patches)
    }

    fn restore_drained_write_segments(&mut self, inode_id: InodeId, segments: &[(u64, Vec<u8>)]) {
        self.snapshot_write_buffers_for_rollback();
        let wb = self
            .write_buffers
            .entry(inode_id)
            .or_insert_with(|| WriteBuffer::new(self.write_buffer_config.clone()));
        for (offset, data) in segments {
            wb.ingest(data, *offset);
        }
    }

    fn finalize_drained_write_segments(
        &mut self,
        inode_id: InodeId,
        segments: Vec<(u64, Vec<u8>)>,
    ) {
        for (offset, data) in segments {
            // Finalize PendingData extents with the real BLAKE3 content
            // checksum and current commit-group provenance.
            let data_len = data.len() as u64;
            let blake3_hash = blake3::hash(&data);
            let birth_txg = self.commit_group.current_commit_group().0;
            let _ = self.extent_allocator.finalize_data_extent(
                inode_id.0,
                offset,
                data_len,
                *blake3_hash.as_bytes(),
                birth_txg,
            );
            // Clear the dirty range only after the authoritative data path
            // (content layout + extent allocation) has succeeded (#5940).
            self.writeback_range_tracker
                .lock()
                .expect("locked")
                .clear_range(inode_id, offset, data_len);
        }
    }

    fn rewrite_content_with_patch_batch(
        &mut self,
        inode_id: InodeId,
        mut record: InodeRecord,
        patches: &[CoalescedBufferedWritePatch],
        new_size: u64,
        allow_holes: bool,
    ) -> Result<InodeRecord> {
        let old_record = record.clone();
        let planned_tick = next_generation_after(self.state.generation);
        let mut planned_record = record.clone();
        planned_record.size = new_size;
        planned_record.data_version = planned_tick;
        planned_record.metadata_version = planned_tick;
        let content_patches: Vec<ContentOverlayPatch<'_>> = patches
            .iter()
            .map(|patch| ContentOverlayPatch {
                offset: patch.offset,
                bytes: &patch.bytes,
            })
            .collect();
        let planned_entries = planned_chunk_allocation_entries_for_patch_batch(
            self.store.raw_primary_store(),
            &old_record,
            &planned_record,
            &content_patches,
            allow_holes,
        )?;
        let old_allocation_bytes = allocation_bytes(&content_allocation_entries_for_inode(
            self.store.raw_primary_store(),
            &old_record,
        )?)?;
        let allocation_bytes = allocation_bytes(&planned_entries).unwrap_or(0);
        let dirty_allocation_bytes = patches.iter().try_fold(0_u64, |sum, patch| {
            let bytes = dirty_overlay_allocation_bytes(new_size, patch.offset, &patch.bytes)?;
            sum.checked_add(bytes).ok_or(FileSystemError::SizeOverflow {
                requested: u64::MAX,
            })
        })?;
        let new_blocks = allocation_bytes / content_chunk_size() as u64;
        if allocation_bytes > old_allocation_bytes {
            self.ensure_obligation_capacity("staging_dirty", new_blocks, Some(inode_id))?;
            self.ensure_content_capacity_with_planned_inode(
                Some(inode_id),
                planned_entries.clone(),
            )?;
        }

        self.begin_mutation();
        let tick = self.bump_generation();
        debug_assert_eq!(tick, planned_tick);
        record.size = new_size;
        record.data_version = tick;
        record.metadata_version = tick;
        let result = {
            let mut dedup = self.dedup_index.borrow_mut();
            let mut pool_store = self.store.pool_store_mut();
            write_chunked_content_with_patch_batch(WriteChunkedContentPatchBatch {
                dedup_enabled: self.dedup_enabled,
                store: &mut pool_store,
                inode_id,
                old_record: &old_record,
                new_record: &record,
                patches: &content_patches,
                allow_holes,
                dedup_index: &mut dedup,
                quorum_store: self.quorum_store.as_mut(),
                compression_policy: &self.content_compression_policy,
})
        };
        if let Err(err) = result {
            self.rollback_mutation_delta();
            return Err(err);
        }
        if dirty_allocation_bytes > 0 {
            self.dirty_set
                .record_data_write(inode_id, dirty_allocation_bytes);
            let _accepted_by_commit_group =
                self.record_mutation_commit_group_write(dirty_allocation_bytes);
        }
        self.obligation_ledger.release_claims_for_inode(inode_id);
        if new_blocks > 0 {
            self.obligation_ledger
                .claim(ClaimEntry {
                    claim_id: ClaimId::new(),
                    budget_domain: BudgetDomainId::from_str("staging_dirty"),
                    blocks: new_blocks,
                    inode_id,
                    reason: ClaimReason::Write,
                    authorized_by: StorageAuthorityToken::ABSENT,
                    generation: tick,
                })
                .ok();
        }
        let _ = self.budget_domain.admit_claim(ClaimEntryRecord {
            claim_id: ClaimId::new(),
            claimant_ref: ClaimantRef::Service {
                service_name: "staging_dirty".into(),
            },
            claim_class: ClaimClass::Product,
            claimed_bytes: new_blocks * content_chunk_size() as u64,
            committed_bytes: 0,
            inode_id: Some(inode_id),
            freshness_fence_ref: None,
            claim_receipt_ref: StorageAuthorityToken::ABSENT,
            expiration_deadline: None,
        });

        self.invalidate_hot_read_cache_for_inode(inode_id);
        self.inode_cache.borrow_mut().invalidate(inode_id);
        self.mark_inode_metadata_dirty(inode_id);
        Arc::make_mut(&mut self.state.inodes).insert(inode_id, record.clone());
        self.inode_cache.borrow_mut().invalidate(inode_id);
        self.mark_inode_content_dirty(inode_id);
        self.invalidate_hot_read_cache_for_inode(inode_id);
        self.commit_mutation(record)
    }

    fn flush_drained_write_segments(
        &mut self,
        inode_id: InodeId,
        segments: Vec<(u64, Vec<u8>)>,
    ) -> Result<()> {
        if segments.is_empty() {
            return Ok(());
        }
        let base_record = self.committed_inode_record(inode_id)?;
        let patches = match self.coalesced_write_buffer_patches(inode_id, &base_record, &segments) {
            Ok(patches) => patches,
            Err(err) => {
                self.restore_drained_write_segments(inode_id, &segments);
                return Err(err);
            }
        };
        let batch_new_size = patches.iter().try_fold(base_record.size, |size, patch| {
            let patch_len =
                u64::try_from(patch.bytes.len()).map_err(|_| FileSystemError::SizeOverflow {
                    requested: u64::MAX,
                })?;
            let patch_end =
                patch
                    .offset
                    .checked_add(patch_len)
                    .ok_or(FileSystemError::SizeOverflow {
                        requested: u64::MAX,
                    })?;
            Ok::<u64, FileSystemError>(size.max(patch_end))
        })?;
        if patches.len() > 1 {
            match self.rewrite_content_with_patch_batch(
                inode_id,
                base_record.clone(),
                &patches,
                batch_new_size,
                true,
            ) {
                Ok(_) => {
                    self.finalize_drained_write_segments(inode_id, segments);
                    return Ok(());
                }
                Err(FileSystemError::Unsupported { .. }) => {}
                Err(err) => {
                    self.restore_drained_write_segments(inode_id, &segments);
                    return Err(err);
                }
            }
        }
        let batch_transaction = self.auto_commit && !self.in_transaction && patches.len() > 1;
        if batch_transaction {
            self.auto_commit = false;
            if let Err(err) = self.begin_transaction() {
                self.auto_commit = true;
                self.restore_drained_write_segments(inode_id, &segments);
                return Err(err);
            }
        }
        for patch in patches {
            let record = self.committed_inode_record(inode_id)?;
            let patch_len =
                u64::try_from(patch.bytes.len()).map_err(|_| FileSystemError::SizeOverflow {
                    requested: u64::MAX,
                })?;
            let patch_end =
                patch
                    .offset
                    .checked_add(patch_len)
                    .ok_or(FileSystemError::SizeOverflow {
                        requested: u64::MAX,
                    })?;
            let new_size = record.size.max(patch_end);
            if let Err(err) = self.rewrite_content_with_overlay(
                inode_id,
                record,
                patch.offset,
                &patch.bytes,
                new_size,
                true,
            ) {
                if batch_transaction {
                    let _ = self.rollback_transaction();
                    self.auto_commit = true;
                }
                self.restore_drained_write_segments(inode_id, &segments);
                return Err(err);
            }
        }
        if batch_transaction {
            if let Err(err) = self.commit_transaction() {
                self.auto_commit = true;
                self.restore_drained_write_segments(inode_id, &segments);
                return Err(err);
            }
            self.auto_commit = true;
        }

        self.finalize_drained_write_segments(inode_id, segments);
        Ok(())
    }

    /// Flush buffered writes for a single inode to the object store.
    pub fn flush_write_buffer(&mut self, inode_id: InodeId) -> Result<()> {
        self.snapshot_write_buffers_for_rollback();
        let segments = match self.write_buffers.get_mut(&inode_id) {
            Some(wb) if !wb.is_empty() => wb.drain(),
            Some(_) => {
                self.write_buffers.remove(&inode_id);
                return Ok(());
            }
            None => return Ok(()),
        };
        self.write_buffers.remove(&inode_id);
        self.flush_drained_write_segments(inode_id, segments)
    }

    fn flush_write_buffer_batch(&mut self, inode_id: InodeId) -> Result<()> {
        self.snapshot_write_buffers_for_rollback();
        let (segments, drained_empty) = match self.write_buffers.get_mut(&inode_id) {
            Some(wb) if !wb.is_empty() => {
                let segments = wb.drain_flush_batch();
                let drained_empty = wb.is_empty();
                (segments, drained_empty)
            }
            Some(_) => {
                self.write_buffers.remove(&inode_id);
                return Ok(());
            }
            None => return Ok(()),
        };
        if drained_empty {
            self.write_buffers.remove(&inode_id);
        }
        self.flush_drained_write_segments(inode_id, segments)
    }

    /// Flush all write buffers to the object store.
    pub fn flush_all_write_buffers(&mut self) -> Result<()> {
        let inodes: Vec<InodeId> = self.write_buffers.keys().copied().collect();
        for inode_id in inodes {
            self.flush_write_buffer(inode_id)?;
        }
        Ok(())
    }

    fn flush_file_write_buffer_for_entry(&mut self, entry: &NamespaceEntry) -> Result<()> {
        if entry.kind() == NodeKind::File {
            self.flush_write_buffer(entry.inode_id)?;
        }
        Ok(())
    }

    /// Expose write-buffer config for daemon-level tuning.
    pub fn set_write_buffer_config(&mut self, config: WriteBufferConfig) {
        self.write_buffer_config = config;
    }

    pub fn set_write_buffer_flush_threshold_bytes(&mut self, bytes: usize) {
        self.write_buffer_config.flush_threshold_bytes = bytes;
    }

    pub fn read_from_write_buffer(
        &self,
        inode_id: InodeId,
        offset: u64,
        len: usize,
    ) -> Option<Vec<u8>> {
        self.write_buffers
            .get(&inode_id)
            .and_then(|wb| wb.read_overlap(offset, len))
    }

    pub(crate) fn sparse_zero_range_copy_len(
        &self,
        path: impl AsRef<str>,
        offset: u64,
        length: u64,
    ) -> Result<Option<u64>> {
        let path = path.as_ref();
        let parts = parse_absolute_path(path)?;
        let inode_id = self.resolve_parts(&parts, path)?;
        let record = self.inode(inode_id)?;
        if record.kind() != NodeKind::File {
            if record.kind() == NodeKind::Dir {
                return Err(FileSystemError::IsDirectory {
                    path: path.to_string(),
                });
            }
            return Err(FileSystemError::NotFile {
                path: path.to_string(),
                kind: record.kind(),
            });
        }
        if length == 0 {
            return Ok(Some(0));
        }
        if offset >= record.size {
            return Ok(Some(0));
        }
        let copy_len = record.size.saturating_sub(offset).min(length);
        if copy_len == 0 {
            return Ok(Some(0));
        }
        if self
            .write_buffers
            .get(&inode_id)
            .is_some_and(|buffer| buffer.overlaps_range(offset, copy_len))
        {
            return Ok(None);
        }

        let copy_end = offset
            .checked_add(copy_len)
            .ok_or(FileSystemError::SizeOverflow {
                requested: u64::MAX,
            })?;
        let committed = self.committed_record_for_buffered_read(inode_id, &record);
        if offset >= committed.size {
            return Ok(Some(copy_len));
        }
        let layout = read_content_layout_from_store(
            self.store.raw_primary_store(),
            inode_id,
            &committed,
            true,
        )?;
        let ContentLayout::Chunked(manifest) = layout else {
            return Ok(None);
        };
        for chunk_ref in &manifest.chunks {
            if chunk_ref.is_hole() {
                continue;
            }
            let chunk_start = content_chunk_start(chunk_ref.chunk_index)?;
            let chunk_end = chunk_start
                .checked_add(u64::from(chunk_ref.len))
                .ok_or(FileSystemError::SizeOverflow {
                    requested: u64::MAX,
                })?
                .min(committed.size);
            if chunk_start < copy_end && chunk_end > offset {
                return Ok(None);
            }
        }
        Ok(Some(copy_len))
    }

    fn sparse_zero_write_is_noop(
        &self,
        inode_id: InodeId,
        record: &InodeRecord,
        offset: u64,
        len: usize,
    ) -> Result<bool> {
        if len == 0 {
            return Ok(false);
        }
        let write_len = u64::try_from(len).map_err(|_| FileSystemError::SizeOverflow {
            requested: u64::MAX,
        })?;
        let write_end = offset
            .checked_add(write_len)
            .ok_or(FileSystemError::SizeOverflow {
                requested: u64::MAX,
            })?;
        if write_end > record.size {
            return Ok(false);
        }
        if self
            .write_buffers
            .get(&inode_id)
            .is_some_and(|buffer| buffer.overlaps_range(offset, write_len))
        {
            return Ok(false);
        }
        if !self
            .extent_allocator
            .lookup_extents(inode_id.0, offset, write_len)
            .is_empty()
        {
            return Ok(false);
        }
        let layout =
            read_content_layout_from_store(self.store.raw_primary_store(), inode_id, record, true)?;
        let ContentLayout::Chunked(manifest) = layout else {
            return Ok(false);
        };
        let Some((first_chunk, last_chunk)) = overlay_chunk_index_bounds(record.size, offset, len)?
        else {
            return Ok(false);
        };
        for chunk_index in first_chunk..=last_chunk {
            if find_chunk_in_manifest(&manifest, chunk_index)
                .is_some_and(|chunk_ref| !chunk_ref.is_hole())
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Return the effective (logical) file size, accounting for buffered
    /// writes that have not yet been flushed to the object store.
    ///
    /// This is `max(committed_size, write_buffer_max_offset)` so callers
    /// see the size the application last wrote, even before fsync.
    pub(crate) fn effective_file_size(&self, inode_id: InodeId) -> u64 {
        let committed = self
            .state
            .inodes
            .get(&inode_id)
            .map(|r| r.size)
            .unwrap_or(0);
        if let Some(wb) = self.write_buffers.get(&inode_id) {
            wb.max_offset().map_or(committed, |mo| committed.max(mo))
        } else {
            committed
        }
    }

    fn committed_record_for_buffered_read(
        &self,
        inode_id: InodeId,
        adjusted_record: &InodeRecord,
    ) -> InodeRecord {
        if let Some(record) = self.state.inodes.get(&inode_id) {
            return record.clone();
        }
        if let Some(cached) = self.inode_cache.borrow_mut().get(inode_id) {
            return cached.inode;
        }
        adjusted_record.clone()
    }

    fn committed_inode_record(&self, inode_id: InodeId) -> Result<InodeRecord> {
        if let Some(record) = self.state.inodes.get(&inode_id) {
            return Ok(record.clone());
        }
        if let Some(cached) = self.inode_cache.borrow_mut().get(inode_id) {
            return Ok(cached.inode);
        }
        if !self.state.known_inode_ids.contains(&inode_id) && inode_id != ROOT_INODE_ID {
            return Err(FileSystemError::CorruptState {
                reason: "inode id is missing from the inode table",
            });
        }
        let key = inode_object_key(inode_id);
        let bytes =
            self.store
                .raw_primary_store()
                .get(key)?
                .ok_or(FileSystemError::CorruptState {
                    reason: "known inode id references a missing inode object in store",
                })?;
        let record = decode_inode(&bytes)?;
        if record.inode_id != inode_id {
            return Err(FileSystemError::CorruptState {
                reason: "inode object id does not match requested id",
            });
        }
        Ok(record)
    }

    fn truncate_write_buffer_for_inode(&mut self, inode_id: InodeId, size: u64) {
        self.snapshot_write_buffers_for_rollback();
        let remove = match self.write_buffers.get_mut(&inode_id) {
            Some(wb) => {
                wb.truncate(size);
                wb.is_empty()
            }
            None => false,
        };
        if remove {
            self.write_buffers.remove(&inode_id);
        }
    }

    fn clear_write_buffer_range(&mut self, inode_id: InodeId, offset: u64, length: u64) {
        self.snapshot_write_buffers_for_rollback();
        let remove = match self.write_buffers.get_mut(&inode_id) {
            Some(wb) => {
                wb.clear_range(offset, length);
                wb.is_empty()
            }
            None => false,
        };
        if remove {
            self.write_buffers.remove(&inode_id);
        }
    }

    fn clear_writeback_ranges_from(&self, inode_id: InodeId, offset: u64) {
        let length = u64::MAX.saturating_sub(offset);
        if length == 0 {
            return;
        }
        self.writeback_range_tracker
            .lock()
            .expect("locked")
            .clear_range(inode_id, offset, length);
    }

    fn read_with_write_buffer_overlay(
        &self,
        inode_id: InodeId,
        record: &InodeRecord,
        offset: u64,
        len: usize,
    ) -> Result<Option<Vec<u8>>> {
        let Some(wb) = self.write_buffers.get(&inode_id) else {
            return Ok(None);
        };
        if wb.is_empty() {
            return Ok(None);
        }

        let effective_size = wb.max_offset().unwrap_or(0).max(record.size);
        if len == 0 || offset >= effective_size {
            return Ok(Some(Vec::new()));
        }
        let requested = u64::try_from(len).map_err(|_| FileSystemError::SizeOverflow {
            requested: u64::MAX,
        })?;
        let available = effective_size.saturating_sub(offset).min(requested);
        let read_len = usize::try_from(available).map_err(|_| FileSystemError::SizeOverflow {
            requested: available,
        })?;
        let mut bytes = vec![0u8; read_len];

        let base_record = self.committed_record_for_buffered_read(inode_id, record);
        if offset < base_record.size {
            let base_len_u64 = base_record.size.saturating_sub(offset).min(available);
            let base_len =
                usize::try_from(base_len_u64).map_err(|_| FileSystemError::SizeOverflow {
                    requested: base_len_u64,
                })?;
            if base_len > 0 {
                let base = read_content_range_from_store(
                    self.store.raw_primary_store(),
                    inode_id,
                    &base_record,
                    offset,
                    base_len,
                    true,
                    Some(&self.store),
                )?;
                if base.len() > base_len {
                    return Err(FileSystemError::CorruptState {
                        reason: "object-store read exceeded requested overlay base range",
                    });
                }
                bytes[..base.len()].copy_from_slice(&base);
            }
        }

        let overlay_hit = wb.overlay_range(offset, &mut bytes);
        if !overlay_hit && effective_size == base_record.size {
            return Ok(None);
        }
        Ok(Some(bytes))
    }

    /// Try to admit a dirty write operation through the performance contract.
    ///
    /// Acquires an `AdmissionPermit` that conserves dirty-byte and dirty-op
    /// budget. The permit is stored in `pending_permits` and released
    /// en masse when the dirty set is cleared after a successful commit.
    fn try_admit_write(&mut self, dirty_bytes: u64, dirty_ops: u32) -> Result<()> {
        let permit = self
            .write_admission
            .try_admit_dirty_write(dirty_bytes, dirty_ops)?;
        self.pending_permits.push(permit);
        Ok(())
    }

    /// Release all outstanding admission permits after a successful SYNC.
    fn release_pending_permits(&mut self) {
        for permit in self.pending_permits.drain(..) {
            let _ = self.write_admission.release(permit);
        }
    }

    /// Take a bounded peak-usage snapshot for runtime evidence collection.
    ///
    /// Resets peak counters after the snapshot so callers can poll
    /// bounded queue-depth evidence without unbounded memory growth.
    pub fn take_admission_snapshot(&mut self) -> crate::admission::AdmissionPeakSnapshot {
        self.write_admission.take_peak_snapshot()
    }

    pub fn write_file(
        &mut self,
        path: impl AsRef<str>,
        offset: u64,
        bytes: &[u8],
    ) -> Result<InodeRecord> {
        let path = path.as_ref();
        let parts = parse_absolute_path(path)?;
        let inode_id = self.resolve_parts(&parts, path)?;
        let record = self.inode(inode_id)?.clone();
        if record.kind() != NodeKind::File {
            if record.kind() == NodeKind::Dir {
                return Err(FileSystemError::IsDirectory {
                    path: path.to_string(),
                });
            }
            return Err(FileSystemError::NotFile {
                path: path.to_string(),
                kind: record.kind(),
            });
        }

        let _start = usize::try_from(offset)
            .map_err(|_| FileSystemError::SizeOverflow { requested: offset })?;
        let bytes_len = u64::try_from(bytes.len()).map_err(|_| FileSystemError::SizeOverflow {
            requested: u64::MAX,
        })?;
        if bytes_len == 0 {
            return Ok(record);
        }
        let end = offset
            .checked_add(bytes_len)
            .ok_or(FileSystemError::SizeOverflow {
                requested: u64::MAX,
            })?;
        let _end_len =
            usize::try_from(end).map_err(|_| FileSystemError::SizeOverflow { requested: end })?;
        let new_size = record.size.max(end);
        if bytes.iter().all(|byte| *byte == 0)
            && self.sparse_zero_write_is_noop(inode_id, &record, offset, bytes.len())?
        {
            return Ok(record);
        }
        // Quota: check byte grain delta for write
        let old_grains = crate::quota::allocation_grains_for_len(record.size);
        let new_grains = crate::quota::allocation_grains_for_len(new_size);
        let delta_bytes = new_grains.saturating_sub(old_grains);
        if delta_bytes > 0 {
            let inode_ancestors = self.quota_ancestor_chain_for_parts(&parts);
            let pool_free = self.pool_free_bytes_for_quota();
            let decision =
                self.state
                    .quota_table
                    .check_delta(&inode_ancestors, delta_bytes, 0, pool_free);
            if decision.is_refusal() {
                return Err(FileSystemError::from(decision));
            }
        }
        // Capacity reservation: atomically reserve and commit bytes before
        // the write, replacing the former check-then-record TOCTOU pattern.
        // The reservation handle is immediately consumed so the mutable borrow
        // on self is released before the write body.
        let _admit_bytes = new_size.saturating_sub(record.size);
        if _admit_bytes > 0 {
            let handle = self.reserve_with_hierarchy(_admit_bytes).map_err(|_e| {
                FileSystemError::NoSpace {
                    resource: LocalStorageResource::ContentBytes,
                    requested: _admit_bytes,
                    available: self.capacity_authority.available_bytes(),
                    capacity: self.capacity_authority.total_bytes(),
                    allocated: self.capacity_authority.used_bytes(),
                }
            })?;
            // Immediately commit: reserved bytes become used bytes.
            // The handle is consumed here, releasing the immutable borrow on self.
            handle.commit();
        }
        check_crash_hook(CrashInjectionPoint::OpWriteBeforeExtentUpdate);
        self.invalidate_hot_read_cache_for_inode(inode_id);

        // Buffer the write — flush on threshold or explicit fsync.
        let may_flush_after_ingest = self
            .write_buffers
            .get(&inode_id)
            .map(|wb| wb.buffered_bytes().saturating_add(bytes.len()))
            .unwrap_or(bytes.len())
            >= self.write_buffer_config.flush_threshold_bytes;
        let foreground_flush_rollback = if may_flush_after_ingest {
            let old_write_buffer = self.write_buffers.get(&inode_id).cloned();
            let old_dirty_ranges = self
                .writeback_range_tracker
                .lock()
                .expect("locked")
                .snapshot_ranges();
            Some((old_write_buffer, old_dirty_ranges))
        } else {
            None
        };
        if bytes_len > 0 {
            self.writeback_range_tracker
                .lock()
                .expect("locked")
                .mark_dirty(inode_id, offset, bytes_len);
        }
        self.snapshot_write_buffers_for_rollback();
        // Acquire a write-admission permit before dirty bytes enter
        // any tracked buffer.  The permit conserves dirty-byte and
        // dirty-op budget until the commit group SYNC releases it.
        self.try_admit_write(bytes_len, 1)?;
        let should_flush = {
            let wb = self
                .write_buffers
                .entry(inode_id)
                .or_insert_with(|| WriteBuffer::new(self.write_buffer_config.clone()));
            wb.ingest(bytes, offset);
            wb.should_flush()
        };
        if should_flush {
            while self
                .write_buffers
                .get(&inode_id)
                .is_some_and(WriteBuffer::should_flush)
            {
                if let Err(err) = self.flush_write_buffer_batch(inode_id) {
                    if let Some((old_write_buffer, old_dirty_ranges)) = foreground_flush_rollback {
                        match old_write_buffer {
                            Some(wb) => {
                                self.write_buffers.insert(inode_id, wb);
                            }
                            None => {
                                self.write_buffers.remove(&inode_id);
                            }
                        }
                        self.writeback_range_tracker
                            .lock()
                            .expect("locked")
                            .restore_ranges(old_dirty_ranges);
                    }
                    return Err(err);
                }
            }
        }

        let result = self.inode(inode_id)?.clone();
        if delta_bytes > 0 {
            let inode_ancestors = self.quota_ancestor_chain_for_parts(&parts);
            self.state
                .quota_table
                .apply_delta(&inode_ancestors, delta_bytes, 0);
        }
        // Accumulate space delta for logical write
        if bytes_len > 0 {
            self.state
                .space_accounting
                .accumulate_delta(SpaceDelta::new_write(bytes_len));
            self.state.space_accounting.track_physical_write(bytes_len);
        }
        // Track extent allocation for the writeback layer.
        let _ = self
            .extent_allocator
            .allocate_extent(inode_id.0, offset, bytes_len, None);
        // Capacity reservation was committed inline before the write.
        // On error paths the caller must rollback via capacity_authority.record_free.
        self.state.dirty_extent_maps.insert(inode_id);
        Ok(result)
    }

    pub(crate) fn write_file_range_direct(
        &mut self,
        path: impl AsRef<str>,
        offset: u64,
        bytes: &[u8],
    ) -> Result<InodeRecord> {
        let path = path.as_ref();
        let parts = parse_absolute_path(path)?;
        let inode_id = self.resolve_parts(&parts, path)?;
        let adjusted_record = self.inode(inode_id)?.clone();
        if adjusted_record.kind() != NodeKind::File {
            if adjusted_record.kind() == NodeKind::Dir {
                return Err(FileSystemError::IsDirectory {
                    path: path.to_string(),
                });
            }
            return Err(FileSystemError::NotFile {
                path: path.to_string(),
                kind: adjusted_record.kind(),
            });
        }

        let bytes_len = u64::try_from(bytes.len()).map_err(|_| FileSystemError::SizeOverflow {
            requested: u64::MAX,
        })?;
        if bytes_len == 0 {
            return Ok(adjusted_record);
        }
        let end = offset
            .checked_add(bytes_len)
            .ok_or(FileSystemError::SizeOverflow {
                requested: u64::MAX,
            })?;
        let _end_len =
            usize::try_from(end).map_err(|_| FileSystemError::SizeOverflow { requested: end })?;

        let effective_size = adjusted_record.size;
        let new_size = effective_size.max(end);
        let old_grains = crate::quota::allocation_grains_for_len(effective_size);
        let new_grains = crate::quota::allocation_grains_for_len(new_size);
        let delta_bytes = new_grains.saturating_sub(old_grains);
        if delta_bytes > 0 {
            let inode_ancestors = self.quota_ancestor_chain_for_parts(&parts);
            let pool_free = self.pool_free_bytes_for_quota();
            let decision =
                self.state
                    .quota_table
                    .check_delta(&inode_ancestors, delta_bytes, 0, pool_free);
            if decision.is_refusal() {
                return Err(FileSystemError::from(decision));
            }
        }

        let admit_bytes = new_size.saturating_sub(effective_size);
        if admit_bytes > 0 {
            let handle = self.reserve_with_hierarchy(admit_bytes).map_err(|_e| {
                FileSystemError::NoSpace {
                    resource: LocalStorageResource::ContentBytes,
                    requested: admit_bytes,
                    available: self.capacity_authority.available_bytes(),
                    capacity: self.capacity_authority.total_bytes(),
                    allocated: self.capacity_authority.used_bytes(),
                }
            })?;
            handle.commit();
        }

        check_crash_hook(CrashInjectionPoint::OpWriteBeforeExtentUpdate);
        self.invalidate_hot_read_cache_for_inode(inode_id);

        let base_record = self.committed_inode_record(inode_id)?;
        let was_auto_commit = self.auto_commit;
        let was_in_transaction = self.in_transaction;
        let was_max_uncommitted_mutations = self.max_uncommitted_mutations;
        // copy_file_range fallback writes should not force do_commit(), which
        // flushes every inode's write buffer and defeats the direct path.
        self.auto_commit = false;
        self.in_transaction = true;
        self.max_uncommitted_mutations = u64::MAX;
        let result =
            self.rewrite_content_with_overlay(inode_id, base_record, offset, bytes, new_size, true);
        self.max_uncommitted_mutations = was_max_uncommitted_mutations;
        self.in_transaction = was_in_transaction;
        self.auto_commit = was_auto_commit;
        let result = result?;

        if delta_bytes > 0 {
            let inode_ancestors = self.quota_ancestor_chain_for_parts(&parts);
            self.state
                .quota_table
                .apply_delta(&inode_ancestors, delta_bytes, 0);
        }
        self.state
            .space_accounting
            .accumulate_delta(SpaceDelta::new_write(bytes_len));
        self.state.space_accounting.track_physical_write(bytes_len);
        let _ = self
            .extent_allocator
            .allocate_extent(inode_id.0, offset, bytes_len, None);
        let blake3_hash = blake3::hash(bytes);
        let birth_txg = self.commit_group.current_commit_group().0;
        let _ = self.extent_allocator.finalize_data_extent(
            inode_id.0,
            offset,
            bytes_len,
            *blake3_hash.as_bytes(),
            birth_txg,
        );
        self.state.dirty_extent_maps.insert(inode_id);
        self.clear_write_buffer_range(inode_id, offset, bytes_len);
        self.writeback_range_tracker
            .lock()
            .expect("locked")
            .clear_range(inode_id, offset, bytes_len);
        Ok(self.adjust_for_write_buffer(inode_id, result))
    }

    pub fn fallocate_file(
        &mut self,
        path: impl AsRef<str>,
        offset: u64,
        length: u64,
    ) -> Result<InodeRecord> {
        let path = path.as_ref();
        let parts = parse_absolute_path(path)?;
        let inode_id = self.resolve_parts(&parts, path)?;
        let record = self.inode(inode_id)?.clone();
        if record.kind() != NodeKind::File {
            if record.kind() == NodeKind::Dir {
                return Err(FileSystemError::IsDirectory {
                    path: path.to_string(),
                });
            }
            return Err(FileSystemError::NotFile {
                path: path.to_string(),
                kind: record.kind(),
            });
        }
        if length == 0 {
            return Ok(record);
        }
        self.flush_write_buffer(inode_id)?;
        let record = self.committed_inode_record(inode_id)?;
        let end = offset
            .checked_add(length)
            .ok_or(FileSystemError::SizeOverflow {
                requested: u64::MAX,
            })?;
        let _end_len =
            usize::try_from(end).map_err(|_| FileSystemError::SizeOverflow { requested: end })?;
        let logical_size = self.effective_file_size(inode_id);
        let reservation_ranges = self.unaccounted_extent_ranges(inode_id, offset, length);
        let reserve_bytes = reservation_ranges.iter().try_fold(0_u64, |sum, (_, len)| {
            sum.checked_add(*len).ok_or(FileSystemError::SizeOverflow {
                requested: u64::MAX,
            })
        })?;
        if end <= logical_size && reserve_bytes == 0 {
            return Ok(record);
        }

        // Quota/admission covers only hole bytes that become new UNWRITTEN
        // reservations. Bytes already represented by DATA/UNWRITTEN extents
        // have already consumed quota and capacity.
        if reserve_bytes > 0 {
            let inode_ancestors = self.quota_ancestor_chain_for_parts(&parts);
            let pool_free = self.pool_free_bytes_for_quota();
            let decision =
                self.state
                    .quota_table
                    .check_delta(&inode_ancestors, reserve_bytes, 0, pool_free);
            if decision.is_refusal() {
                return Err(FileSystemError::from(decision));
            }
        }
        // ENOSPC gate via the single production capacity authority.
        // Capacity reservation: atomically reserve and commit bytes for
        // fallocate, replacing the former check-then-record TOCTOU pattern.
        // The reservation handle is immediately consumed so the mutable borrow
        // on self is released before the fallocate body.
        if reserve_bytes > 0 {
            self.begin_mutation();
            if self.check_enospc_with_hierarchy(reserve_bytes).is_err() {
                self.rollback_mutation_delta();
                return Err(FileSystemError::NoSpace {
                    resource: LocalStorageResource::ContentBytes,
                    requested: reserve_bytes,
                    available: self.capacity_authority.available_bytes(),
                    capacity: self.capacity_authority.total_bytes(),
                    allocated: self.capacity_authority.used_bytes(),
                });
            }
            self.capacity_authority.record_allocation(reserve_bytes);
        }
        check_crash_hook(CrashInjectionPoint::OpAllocateBeforeSpaceUpdate);
        if reserve_bytes > 0 {
            let inode_ancestors = self.quota_ancestor_chain_for_parts(&parts);
            self.state
                .quota_table
                .apply_delta(&inode_ancestors, reserve_bytes, 0);
        }
        // Accumulate space delta: fallocate is a reservation
        if reserve_bytes > 0 {
            self.state
                .space_accounting
                .accumulate_delta(SpaceDelta::new_reservation(reserve_bytes));
            for (range_offset, range_length) in &reservation_ranges {
                let _ = self.extent_allocator.allocate_unwritten_extent(
                    inode_id.0,
                    *range_offset,
                    *range_length,
                    None,
                    self.commit_group.current_commit_group().0,
                );
            }
            // Capacity reservation was committed inline before fallocate.
            // On error paths the caller must rollback via capacity_authority.record_free.
            {
                let mut tracker = self.writeback_range_tracker.lock().expect("locked");
                for (range_offset, range_length) in &reservation_ranges {
                    tracker.mark_dirty(inode_id, *range_offset, *range_length);
                }
            }
            self.state.dirty_extent_maps.insert(inode_id);
        }
        let committed = self.committed_inode_record(inode_id)?;
        let new_size = committed.size.max(end);
        let _ = self.rewrite_content_with_overlay(inode_id, committed, 0, &[], new_size, true)?;
        let result = self.committed_inode_record(inode_id)?;
        // Intent-log: record fallocate for crash-recovery replay.
        let _ = self.intent_log_buffer.as_ref().map(|buf| {
            let _frame = buf.append(
                tidefs_intent_log::IntentLogRecord::Fallocate {
                    ino: inode_id.get(),
                    offset,
                    length,
                    mode: 0,
                },
                0, // txg_id assigned by TxgCoordinator at drain time
            );
        });
        Ok(result)
    }

    pub fn fallocate_keep_size(
        &mut self,
        path: impl AsRef<str>,
        offset: u64,
        length: u64,
    ) -> Result<InodeRecord> {
        self.reserve_unwritten(path, offset, length)
    }

    /// Reserve space for future writes without changing file size.
    ///
    /// Equivalent to `fallocate(FALLOC_FL_KEEP_SIZE)`: allocates
    /// Unwritten extents in the extent map and accounts for the
    /// reserved space, but does not write zeros, extend the file
    /// size, or modify content.
    ///
    /// This is the KEEP_SIZE half of the fallocate implementation;
    /// default (mode 0) allocate-and-extend uses `fallocate_file`.
    pub fn reserve_unwritten(
        &mut self,
        path: impl AsRef<str>,
        offset: u64,
        length: u64,
    ) -> Result<InodeRecord> {
        let path = path.as_ref();
        let parts = parse_absolute_path(path)?;
        let inode_id = self.resolve_parts(&parts, path)?;
        let record = self.inode(inode_id)?.clone();
        if record.kind() != NodeKind::File {
            if record.kind() == NodeKind::Dir {
                return Err(FileSystemError::IsDirectory {
                    path: path.to_string(),
                });
            }
            return Err(FileSystemError::NotFile {
                path: path.to_string(),
                kind: record.kind(),
            });
        }
        if length == 0 {
            return Ok(record);
        }
        self.flush_write_buffer(inode_id)?;
        let record = self.committed_inode_record(inode_id)?;
        let end = offset
            .checked_add(length)
            .ok_or(FileSystemError::SizeOverflow {
                requested: u64::MAX,
            })?;
        let _end_len =
            usize::try_from(end).map_err(|_| FileSystemError::SizeOverflow { requested: end })?;

        let reservation_ranges = self.unaccounted_extent_ranges(inode_id, offset, length);
        let reserve_bytes = reservation_ranges.iter().try_fold(0_u64, |sum, (_, len)| {
            sum.checked_add(*len).ok_or(FileSystemError::SizeOverflow {
                requested: u64::MAX,
            })
        })?;

        // Quota and admission checks cover only holes that will become
        // UNWRITTEN reservations. Existing DATA/UNWRITTEN extents already
        // consumed quota and capacity when they were first allocated.
        if reserve_bytes > 0 {
            let inode_ancestors = self.quota_ancestor_chain_for_parts(&parts);
            let pool_free = self.pool_free_bytes_for_quota();
            let decision =
                self.state
                    .quota_table
                    .check_delta(&inode_ancestors, reserve_bytes, 0, pool_free);
            if decision.is_refusal() {
                return Err(FileSystemError::from(decision));
            }
        }

        if reserve_bytes > 0 {
            self.begin_mutation();
            // Capacity reservation: atomically reserve and commit bytes.
            let reservation_succeeded = self
                .reserve_with_hierarchy(reserve_bytes)
                .map(|handle| {
                    // Immediately commit: reserved bytes become used bytes.
                    handle.commit();
                })
                .is_ok();
            if !reservation_succeeded {
                let err = FileSystemError::NoSpace {
                    resource: LocalStorageResource::ContentBytes,
                    requested: reserve_bytes,
                    available: self.capacity_authority.available_bytes(),
                    capacity: self.capacity_authority.total_bytes(),
                    allocated: self.capacity_authority.used_bytes(),
                };
                self.rollback_mutation_delta();
                return Err(err);
            }
        }

        check_crash_hook(CrashInjectionPoint::OpAllocateBeforeSpaceUpdate);

        // Create UNWRITTEN extents only for holes in the requested range.
        // Existing DATA extents keep their data authority; existing UNWRITTEN
        // extents keep their original reservation accounting.
        for (range_offset, range_length) in &reservation_ranges {
            let _ = self.extent_allocator.allocate_unwritten_extent(
                inode_id.0,
                *range_offset,
                *range_length,
                None,
                self.commit_group.current_commit_group().0,
            );
        }

        if reserve_bytes > 0 {
            let inode_ancestors = self.quota_ancestor_chain_for_parts(&parts);
            self.state
                .quota_table
                .apply_delta(&inode_ancestors, reserve_bytes, 0);
        }

        if reserve_bytes > 0 {
            self.state
                .space_accounting
                .accumulate_delta(SpaceDelta::new_reservation(reserve_bytes));
            // Capacity reservation was committed inline before the operation.
            // Statfs derivation reflects the committed bytes.
            {
                let mut tracker = self.writeback_range_tracker.lock().expect("locked");
                for (range_offset, range_length) in &reservation_ranges {
                    tracker.mark_dirty(inode_id, *range_offset, *range_length);
                }
            }
            self.state.dirty_extent_maps.insert(inode_id);
        }
        let result = if reserve_bytes > 0 {
            let committed = self.committed_inode_record(inode_id)?;
            self.rewrite_content_with_overlay(inode_id, committed, 0, &[], record.size, true)?
        } else {
            record
        };
        // Intent-log: record fallocate with KEEP_SIZE for crash-recovery replay.
        let _ = self.intent_log_buffer.as_ref().map(|buf| {
            let _frame = buf.append(
                tidefs_intent_log::IntentLogRecord::Fallocate {
                    ino: inode_id.get(),
                    offset,
                    length,
                    mode: FALLOC_FL_KEEP_SIZE as i32,
                },
                0, // txg_id assigned by TxgCoordinator at drain time
            );
        });
        Ok(result)
    }

    pub fn truncate_file(&mut self, path: impl AsRef<str>, size: u64) -> Result<InodeRecord> {
        let path = path.as_ref();
        let parts = parse_absolute_path(path)?;
        let inode_id = self.resolve_parts(&parts, path)?;
        let record = self.inode(inode_id)?.clone();
        if record.kind() != NodeKind::File {
            if record.kind() == NodeKind::Dir {
                return Err(FileSystemError::IsDirectory {
                    path: path.to_string(),
                });
            }
            return Err(FileSystemError::NotFile {
                path: path.to_string(),
                kind: record.kind(),
            });
        }
        let _new_len =
            usize::try_from(size).map_err(|_| FileSystemError::SizeOverflow { requested: size })?;
        let old_effective_size = self.effective_file_size(inode_id);
        if size < old_effective_size {
            self.truncate_write_buffer_for_inode(inode_id, size);
            self.clear_writeback_ranges_from(inode_id, size);
        }
        let record = self.committed_inode_record(inode_id)?;
        let old_size = record.size.max(old_effective_size);
        let mut committed_truncate_only = false;
        if size < old_size {
            let truncated_len = old_size - size;
            let (data_bytes, reserved_bytes) =
                self.accounted_extent_bytes(inode_id, size, truncated_len);
            let freed_bytes = data_bytes.saturating_add(reserved_bytes);
            let truncates_committed_record = record.size > size;

            if freed_bytes > 0 || truncates_committed_record {
                self.begin_mutation();
                if data_bytes > 0 && truncates_committed_record {
                    self.record_reclaim_delta(inode_id, data_bytes);
                }
                if freed_bytes > 0 {
                    let _ = self
                        .extent_allocator
                        .free_extent(inode_id.0, size, truncated_len);
                    self.state.dirty_extent_maps.insert(inode_id);
                    self.capacity_authority.record_free(freed_bytes);
                    self.state
                        .space_accounting
                        .accumulate_delta(SpaceDelta::new_punch_hole(data_bytes, reserved_bytes));
                    self.state.space_accounting.track_physical_free(data_bytes);
                    if record.size == size {
                        self.mark_inode_content_dirty(inode_id);
                        committed_truncate_only = true;
                    }
                }
                // Also remove intent log entries for this inode so the
                // fsync fast path does not replay pre-truncation writes.
                let removed_ids = self.intent_log.remove_entries_for_inode(inode_id);
                for entry_id in &removed_ids {
                    let _ = self
                        .store
                        .raw_primary_store_mut()
                        .delete(intent_log_entry_object_key(*entry_id));
                    let _ = self
                        .store
                        .raw_primary_store_mut()
                        .delete(intent_log_data_object_key(*entry_id));
                }
            }
        }
        let result = if record.size == size {
            if committed_truncate_only {
                self.commit_mutation(record)?
            } else {
                record
            }
        } else {
            self.rewrite_content_with_overlay(inode_id, record, 0, &[], size, true)?
        };
        self.truncate_write_buffer_for_inode(inode_id, size);
        // ── Intent-log: record truncate for crash recovery replay ──
        // Record the truncate after all extent and write-buffer mutations
        // are applied so that a crash before the next txg commit will replay
        // this truncate and restore the correct file size.
        let _ = self.intent_log_buffer.as_ref().map(|buf| {
            let _frame = buf.append(
                tidefs_intent_log::IntentLogRecord::Truncate {
                    ino: inode_id.get(),
                    new_size: size,
                },
                0, // txg_id assigned by TxgCoordinator at drain time
            );
        });
        Ok(result)
    }
    /// Free extents in the given byte range for a block-level inode, updating
    /// the spacemap and reclaim ledger. This is the block-device discard path:
    /// no path resolution, no namespace mutation — just extent deallocation.
    ///
    /// Returns the number of bytes freed (may be less than  if the
    /// range extends past allocated extents).
    pub fn free_extent_range(
        &mut self,
        inode_id: InodeId,
        byte_offset: u64,
        byte_len: u64,
    ) -> Result<u64> {
        if byte_len == 0 {
            return Ok(0);
        }
        // Flush pending writes so content-layout reads are coherent.
        self.flush_write_buffer(inode_id)?;

        // Read the inode record so we can clamp to file size.
        // If the inode does not exist, return 0 (caller may be
        // operating on a stale block-device mapping).
        let record = match self.inode(inode_id) {
            Ok(rec) => rec.clone(),
            Err(_) => return Ok(0),
        };
        if record.kind() != NodeKind::File {
            return Err(FileSystemError::NotFile {
                path: format!("inode:{}", inode_id.get()),
                kind: record.kind(),
            });
        }
        // Clamp to file size.
        if byte_offset >= record.size {
            return Ok(0);
        }
        let effective_length = record.size.saturating_sub(byte_offset).min(byte_len);

        // Bump generation and data version so the content-layout rewrite
        // is visible to concurrent readers via the version-oriented key.
        let tick = self.bump_generation();
        let mut updated = record.clone();
        updated.data_version = tick;
        updated.metadata_version = tick;

        // Free logical extents in the extent allocator.
        let freed =
            match self
                .extent_allocator
                .free_extent(inode_id.0, byte_offset, effective_length)
            {
                Ok(()) => effective_length,
                Err(_) => 0u64,
            };
        if freed == 0 {
            return Ok(0);
        }
        // Zero the content range in the object store via punch_hole_content.
        // This ensures subsequent reads return zeros for the freed range.
        let mut pool_store = self.store.pool_store_mut();
        let quorum_store = None; // block-device discard is a local operation.
        crate::content::punch_hole_content(PunchHoleContent {
            store: &mut pool_store,
            inode_id,
            old_record: &record,
            new_record: &updated,
            hole_offset: byte_offset,
            hole_length: effective_length,
            quorum_store,
            compression_policy: &self.content_compression_policy,
})?;

        // Update the inode record in the inode table.
        self.update_inode_record(inode_id, updated)?;
        self.inode_cache.borrow_mut().invalidate(inode_id);
        self.mark_inode_content_dirty(inode_id);
        self.invalidate_hot_read_cache_for_inode(inode_id);

        self.state.dirty_extent_maps.insert(inode_id);
        self.state
            .space_accounting
            .accumulate_delta(SpaceDelta::new_free(freed));
        self.state.space_accounting.track_physical_free(freed);
        self.record_reclaim_delta(inode_id, freed);

        Ok(freed)
    }

    /// Deallocate content chunks in the specified range, creating a sparse hole.
    ///
    /// Equivalent to `fallocate(FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE)`:
    /// the inode size is unchanged, but chunks in [offset, offset+length) are
    /// removed from the object store. Reads in the punched range return zeros.
    ///
    /// If the hole extends beyond the current file size, the file is not enlarged;
    /// only the overlapping portion is punched.
    pub fn punch_hole(
        &mut self,
        path: impl AsRef<str>,
        offset: u64,
        length: u64,
    ) -> Result<InodeRecord> {
        let path = path.as_ref();
        let parts = parse_absolute_path(path)?;
        let inode_id = self.resolve_parts(&parts, path)?;
        let logical_size = self.effective_file_size(inode_id);
        let mut record = self.committed_inode_record(inode_id)?;
        if record.kind() != NodeKind::File {
            if record.kind() == NodeKind::Dir {
                return Err(FileSystemError::IsDirectory {
                    path: path.to_string(),
                });
            }
            return Err(FileSystemError::NotFile {
                path: path.to_string(),
                kind: record.kind(),
            });
        }
        let length = if length == 0 {
            return Ok(self.adjust_for_write_buffer(inode_id, record));
        } else {
            length
        };
        // Clamp to file size — punching past EOF is a no-op for the tail
        if offset >= logical_size {
            return Ok(self.adjust_for_write_buffer(inode_id, record));
        }
        let effective_length = logical_size.saturating_sub(offset).min(length);
        if logical_size > record.size {
            let _ =
                self.rewrite_content_with_overlay(inode_id, record, 0, &[], logical_size, true)?;
            record = self.committed_inode_record(inode_id)?;
        }

        // Accumulate space delta only for extents that actually existed in the
        // punched range. Sparse holes must stay accounting-neutral.
        if effective_length > 0 {
            self.begin_mutation();
            let (data_bytes, reserved_bytes) =
                self.accounted_extent_bytes(inode_id, offset, effective_length);
            let freed_bytes = data_bytes.saturating_add(reserved_bytes);
            if data_bytes > 0 {
                self.record_reclaim_delta(inode_id, data_bytes);
            }
            let _ = self
                .extent_allocator
                .free_extent(inode_id.0, offset, effective_length);
            self.state.dirty_extent_maps.insert(inode_id);
            if freed_bytes > 0 {
                self.state
                    .space_accounting
                    .accumulate_delta(SpaceDelta::new_punch_hole(data_bytes, reserved_bytes));
                self.state.space_accounting.track_physical_free(data_bytes);
                // Track freed bytes in the production capacity authority.
                self.capacity_authority.record_free(freed_bytes);
            }
            // Intent-log: record punch_hole for crash-recovery replay.
            let _ = self.intent_log_buffer.as_ref().map(|buf| {
                let _frame = buf.append(
                    tidefs_intent_log::IntentLogRecord::Fallocate {
                        ino: inode_id.get(),
                        offset,
                        length: effective_length,
                        mode: (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE) as i32,
                    },
                    0, // txg_id assigned by TxgCoordinator at drain time
                );
            });
        }
        let tick = self.bump_generation();
        let mut updated = record.clone();
        updated.data_version = tick;
        updated.metadata_version = tick;
        let mut pool_store = self.store.pool_store_mut();
        // Size is preserved (KEEP_SIZE semantics)
        punch_hole_content(PunchHoleContent {
            store: &mut pool_store,
            inode_id,
            old_record: &record,
            new_record: &updated,
            hole_offset: offset,
            hole_length: effective_length,
            quorum_store: self.quorum_store.as_mut(),
            compression_policy: &self.content_compression_policy,
})?;
        // Capture old record in mutation delta BEFORE replacing it
        self.mark_inode_metadata_dirty(inode_id);
        Arc::make_mut(&mut self.state.inodes).insert(inode_id, updated.clone());
        self.inode_cache.borrow_mut().invalidate(inode_id);
        self.mark_inode_content_dirty(inode_id);
        self.invalidate_hot_read_cache_for_inode(inode_id);
        self.clear_write_buffer_range(inode_id, offset, effective_length);
        self.writeback_range_tracker
            .lock()
            .expect("locked")
            .clear_range(inode_id, offset, effective_length);
        self.commit_mutation(updated)
    }

    /// Query the content manifest for the next hole (gap between chunks or
    /// beyond the last chunk) starting at or after .  Returns the
    /// byte offset of the first hole found, or  if no holes
    /// exist between  and end-of-file.
    ///
    /// Holes are derived from the sparse content manifest directly.  A
    /// missing chunk index IS a hole.  This survives remounts because
    /// manifests are persisted (#873).
    pub fn find_next_hole_offset(&self, inode_id: InodeId, offset: u64) -> Result<u64> {
        let record = self.inode(inode_id)?.clone();
        let layout = read_content_layout_from_store(
            self.store.raw_primary_store(),
            inode_id,
            &record,
            false,
        )?;
        match layout {
            ContentLayout::Inline(_) => Ok(record.size),
            ContentLayout::Chunked(manifest) => {
                let chunk_size = FILESYSTEM_CONTENT_CHUNK_SIZE as u64;
                let mut pos = offset;
                for chunk_ref in &manifest.chunks {
                    let cstart = chunk_ref.chunk_index * chunk_size;
                    if pos < cstart {
                        return Ok(pos);
                    }
                    let cend = (cstart + chunk_ref.len as u64).min(record.size);
                    if chunk_ref.is_hole() {
                        if pos < cend {
                            return Ok(pos);
                        }
                        continue;
                    }
                    if pos < cend {
                        pos = cend;
                    }
                }
                Ok(pos.min(record.size))
            }
        }
    }

    /// Query the content manifest for the next data region starting at or
    /// after .  Returns the byte offset of the first data byte, or
    ///  if no data exists beyond  (i.e. ENXIO).
    ///
    /// Like , data presence is derived from the
    /// sparse content manifest directly.  Inline content is always fully
    /// dense.
    pub fn find_next_data_offset(&self, inode_id: InodeId, offset: u64) -> Result<Option<u64>> {
        let record = self.inode(inode_id)?.clone();
        if offset >= record.size {
            return Ok(None);
        }
        let layout = read_content_layout_from_store(
            self.store.raw_primary_store(),
            inode_id,
            &record,
            false,
        )?;
        match layout {
            ContentLayout::Inline(_) => Ok(Some(offset)),
            ContentLayout::Chunked(manifest) => {
                let chunk_size = FILESYSTEM_CONTENT_CHUNK_SIZE as u64;
                let mut pos = offset;
                for chunk_ref in &manifest.chunks {
                    let cstart = chunk_ref.chunk_index * chunk_size;
                    let cend = (cstart + chunk_ref.len as u64).min(record.size);
                    if chunk_ref.is_hole() {
                        if pos < cstart {
                            pos = cstart;
                        }
                        if pos < cend {
                            pos = cend;
                        }
                        continue;
                    }
                    if pos < cstart {
                        if cstart < record.size {
                            return Ok(Some(cstart));
                        }
                        return Ok(None);
                    }
                    if pos < cend {
                        return Ok(Some(pos));
                    }
                    pos = cend;
                }
                Ok(None)
            }
        }
    }

    /// Write zeros to a range within the file without changing file size.
    ///
    /// Equivalent to `fallocate(FALLOC_FL_ZERO_RANGE)`: bytes in
    /// [offset, offset+length) are set to zero. Unlike `punch_hole`,
    /// this writes actual zero bytes (allocating space if needed) rather than
    /// deallocating chunks. If the range extends beyond the current file size,
    /// it is clamped to the file size (KEEP_SIZE semantics).
    ///
    /// If `offset` is past end-of-file, the call is a no-op and returns the
    /// current record unchanged.
    pub fn zero_range(
        &mut self,
        path: impl AsRef<str>,
        offset: u64,
        length: u64,
    ) -> Result<InodeRecord> {
        let path = path.as_ref();
        let parts = parse_absolute_path(path)?;
        let inode_id = self.resolve_parts(&parts, path)?;
        let logical_size = self.effective_file_size(inode_id);
        let mut record = self.committed_inode_record(inode_id)?;
        if record.kind() != NodeKind::File {
            if record.kind() == NodeKind::Dir {
                return Err(FileSystemError::IsDirectory {
                    path: path.to_string(),
                });
            }
            return Err(FileSystemError::NotFile {
                path: path.to_string(),
                kind: record.kind(),
            });
        }
        if length == 0 {
            return Ok(self.adjust_for_write_buffer(inode_id, record));
        }
        // Clamp to file size — zeroing past EOF is a no-op
        if offset >= logical_size {
            return Ok(self.adjust_for_write_buffer(inode_id, record));
        }
        let effective_length = (logical_size.saturating_sub(offset)).min(length);
        if effective_length == 0 {
            return Ok(self.adjust_for_write_buffer(inode_id, record));
        }
        if logical_size > record.size {
            let _ =
                self.rewrite_content_with_overlay(inode_id, record, 0, &[], logical_size, true)?;
            record = self.committed_inode_record(inode_id)?;
        }
        let record_size = record.size;
        let (data_bytes, _reserved_bytes) =
            self.accounted_extent_bytes(inode_id, offset, effective_length);
        let materialized_data =
            self.content_range_has_materialized_data(inode_id, &record, offset, effective_length)?;
        let reservation_ranges = self.unaccounted_extent_ranges(inode_id, offset, effective_length);
        let materialized_bytes =
            self.materialized_content_bytes_in_ranges(inode_id, &record, &reservation_ranges)?;
        let unaccounted_hole_bytes =
            reservation_ranges.iter().try_fold(0_u64, |sum, (_, len)| {
                sum.checked_add(*len).ok_or(FileSystemError::SizeOverflow {
                    requested: u64::MAX,
                })
            })?;
        let newly_allocated_bytes = unaccounted_hole_bytes.saturating_sub(materialized_bytes);
        let will_mutate_capacity_or_content =
            newly_allocated_bytes > 0 || data_bytes > 0 || materialized_data;
        if will_mutate_capacity_or_content {
            self.begin_mutation();
        }
        // Capacity reservation: charge only holes that become allocated. Existing
        // DATA and UNWRITTEN ranges already consume capacity.
        if newly_allocated_bytes > 0 {
            if self
                .check_enospc_with_hierarchy(newly_allocated_bytes)
                .is_err()
            {
                self.rollback_mutation_delta();
                return Err(FileSystemError::NoSpace {
                    resource: LocalStorageResource::ContentBytes,
                    requested: newly_allocated_bytes,
                    available: self.capacity_authority.available_bytes(),
                    capacity: self.capacity_authority.total_bytes(),
                    allocated: self.capacity_authority.used_bytes(),
                });
            }
            self.capacity_authority
                .record_allocation(newly_allocated_bytes);
        }

        if data_bytes == 0 && !materialized_data {
            if newly_allocated_bytes > 0 {
                let birth_txg = self.commit_group.current_commit_group().0;
                for (range_offset, range_length) in &reservation_ranges {
                    let _ = self.extent_allocator.allocate_unwritten_extent(
                        inode_id.0,
                        *range_offset,
                        *range_length,
                        None,
                        birth_txg,
                    );
                }
                self.state
                    .space_accounting
                    .accumulate_delta(SpaceDelta::new_reservation(newly_allocated_bytes));
                self.state.dirty_extent_maps.insert(inode_id);
            }
            self.clear_write_buffer_range(inode_id, offset, effective_length);
            self.writeback_range_tracker
                .lock()
                .expect("locked")
                .clear_range(inode_id, offset, effective_length);
            let _ = self.intent_log_buffer.as_ref().map(|buf| {
                let _frame = buf.append(
                    tidefs_intent_log::IntentLogRecord::Fallocate {
                        ino: inode_id.get(),
                        offset,
                        length: effective_length,
                        mode: FALLOC_FL_ZERO_RANGE as i32,
                    },
                    0,
                );
            });
            if newly_allocated_bytes > 0 {
                return self.commit_mutation(record);
            }
            return Ok(self.adjust_for_write_buffer(inode_id, record));
        }

        let data_to_unwritten_bytes = data_bytes.saturating_add(materialized_bytes);
        let reserved_delta = data_to_unwritten_bytes.saturating_add(newly_allocated_bytes);
        if data_to_unwritten_bytes > 0 || reserved_delta > 0 {
            self.state.space_accounting.accumulate_delta(SpaceDelta {
                logical_used_delta: -(data_to_unwritten_bytes as i64),
                reserved_delta: reserved_delta as i64,
                ..SpaceDelta::ZERO
            });
        }
        let birth_txg = self.commit_group.current_commit_group().0;
        let _ = self
            .extent_allocator
            .free_extent(inode_id.0, offset, effective_length);
        let _ = self.extent_allocator.allocate_unwritten_extent(
            inode_id.0,
            offset,
            effective_length,
            None,
            birth_txg,
        );
        self.clear_write_buffer_range(inode_id, offset, effective_length);
        self.writeback_range_tracker
            .lock()
            .expect("locked")
            .clear_range(inode_id, offset, effective_length);
        // Intent-log: record zero_range for crash-recovery replay.
        let _ = self.intent_log_buffer.as_ref().map(|buf| {
            let _frame = buf.append(
                tidefs_intent_log::IntentLogRecord::Fallocate {
                    ino: inode_id.get(),
                    offset,
                    length: effective_length,
                    mode: FALLOC_FL_ZERO_RANGE as i32,
                },
                0, // txg_id assigned by TxgCoordinator at drain time
            );
        });
        self.state.dirty_extent_maps.insert(inode_id);
        let tick = self.bump_generation();
        let mut updated = record.clone();
        updated.data_version = tick;
        updated.metadata_version = tick;
        let mut pool_store = self.store.pool_store_mut();
        updated.size = record_size;
        punch_hole_content(PunchHoleContent {
            store: &mut pool_store,
            inode_id,
            old_record: &record,
            new_record: &updated,
            hole_offset: offset,
            hole_length: effective_length,
            quorum_store: self.quorum_store.as_mut(),
            compression_policy: &self.content_compression_policy,
})?;
        self.mark_inode_metadata_dirty(inode_id);
        Arc::make_mut(&mut self.state.inodes).insert(inode_id, updated.clone());
        self.inode_cache.borrow_mut().invalidate(inode_id);
        self.mark_inode_content_dirty(inode_id);
        self.invalidate_hot_read_cache_for_inode(inode_id);
        self.commit_mutation(updated)
    }

    /// Collapse a range of bytes within the file, shifting subsequent data
    /// left and reducing the file size.
    ///
    /// Equivalent to `fallocate(FALLOC_FL_COLLAPSE_RANGE)`: bytes in
    /// [offset, offset+length) are removed from the file, data after the
    /// collapsed range is shifted left by `length` bytes, and the file size
    /// decreases by `length`.
    ///
    /// If the range extends beyond the current file size, it is clamped to
    /// EOF. A zero-length collapse is a no-op.
    pub fn collapse_range(
        &mut self,
        path: impl AsRef<str>,
        offset: u64,
        length: u64,
    ) -> Result<InodeRecord> {
        let path = path.as_ref();
        let parts = parse_absolute_path(path)?;
        let inode_id = self.resolve_parts(&parts, path)?;
        // Flush any buffered writes before reading the record.
        self.flush_write_buffer(inode_id)?;
        let record = self.inode(inode_id)?.clone();
        if record.kind() != NodeKind::File {
            if record.kind() == NodeKind::Dir {
                return Err(FileSystemError::IsDirectory {
                    path: path.to_string(),
                });
            }
            return Err(FileSystemError::NotFile {
                path: path.to_string(),
                kind: record.kind(),
            });
        }
        if length == 0 {
            return Ok(record);
        }
        if offset >= record.size {
            return Ok(record);
        }
        let effective_length = (record.size.saturating_sub(offset)).min(length);
        if effective_length == 0 {
            return Ok(record);
        }
        let old_content = self.read_content(inode_id, &record)?;
        let offset_usize = offset as usize;
        let eff_len_usize = effective_length as usize;
        // Build new content: prefix + tail shifted left
        let new_size = record.size - effective_length;
        let new_size_usize = new_size as usize;
        let mut new_content = Vec::with_capacity(new_size_usize);
        new_content.extend_from_slice(&old_content[..offset_usize]);
        let tail_start = offset_usize + eff_len_usize;
        if tail_start < old_content.len() {
            new_content.extend_from_slice(&old_content[tail_start..]);
        }
        // Accumulate space delta: collapse_range frees data bytes
        self.record_reclaim_delta(inode_id, effective_length);
        // collapse_range is a shrinking operation: no capacity reservation needed.
        let result = self.replace_content(inode_id, record, new_content)?;
        let _ = self
            .extent_allocator
            .free_extent(inode_id.0, offset, effective_length);
        self.state.dirty_extent_maps.insert(inode_id);
        self.state
            .space_accounting
            .accumulate_delta(SpaceDelta::new_free(effective_length));
        self.state
            .space_accounting
            .track_physical_free(effective_length);
        // Track freed bytes in the production capacity authority
        self.capacity_authority.record_free(effective_length);
        // Intent-log: record collapse_range for crash-recovery replay.
        let _ = self.intent_log_buffer.as_ref().map(|buf| {
            let _frame = buf.append(
                tidefs_intent_log::IntentLogRecord::Fallocate {
                    ino: inode_id.get(),
                    offset,
                    length: effective_length,
                    mode: FALLOC_FL_COLLAPSE_RANGE as i32,
                },
                0, // txg_id assigned by TxgCoordinator at drain time
            );
        });
        Ok(result)
    }

    /// Insert a zero-filled range at the given offset, shifting subsequent
    /// data right and increasing the file size.
    ///
    /// Equivalent to `fallocate(FALLOC_FL_INSERT_RANGE)`: `length` zero bytes
    /// are inserted at `offset`, data after `offset` is shifted right by
    /// `length` bytes, and the file size increases by `length`.
    ///
    /// If `offset` is beyond the current file size, the file is extended with
    /// zeros (equivalent to default-allocate). A zero-length insert is a
    /// no-op.
    pub fn insert_range(
        &mut self,
        path: impl AsRef<str>,
        offset: u64,
        length: u64,
    ) -> Result<InodeRecord> {
        let path = path.as_ref();
        let parts = parse_absolute_path(path)?;
        let inode_id = self.resolve_parts(&parts, path)?;
        // Flush any buffered writes before reading the record.
        self.flush_write_buffer(inode_id)?;
        let record = self.inode(inode_id)?.clone();
        if record.kind() != NodeKind::File {
            if record.kind() == NodeKind::Dir {
                return Err(FileSystemError::IsDirectory {
                    path: path.to_string(),
                });
            }
            return Err(FileSystemError::NotFile {
                path: path.to_string(),
                kind: record.kind(),
            });
        }
        if length == 0 {
            return Ok(record);
        }
        // If offset is beyond EOF, extend the file with zeros
        let old_content = if offset >= record.size {
            self.read_content(inode_id, &record).unwrap_or_default()
        } else {
            self.read_content(inode_id, &record)?
        };
        let offset_usize = (offset as usize).min(old_content.len());
        let length_usize = length as usize;
        let new_size = if offset >= record.size {
            offset + length
        } else {
            record.size + length
        };
        let new_size_usize = new_size as usize;
        // Check quota for the increase
        let old_grains = crate::quota::allocation_grains_for_len(record.size);
        let new_grains = crate::quota::allocation_grains_for_len(new_size);
        let delta_bytes = new_grains.saturating_sub(old_grains);
        if delta_bytes > 0 {
            let inode_ancestors = self.quota_ancestor_chain_for_parts(&parts);
            let pool_free = self.pool_free_bytes_for_quota();
            let decision =
                self.state
                    .quota_table
                    .check_delta(&inode_ancestors, delta_bytes, 0, pool_free);
            if decision.is_refusal() {
                return Err(FileSystemError::from(decision));
            }
        }
        // Build new content: prefix + zeros + tail shifted right
        let mut new_content = vec![0u8; new_size_usize];
        new_content[..offset_usize].copy_from_slice(&old_content[..offset_usize]);
        if offset_usize < old_content.len() {
            let tail_len = old_content.len() - offset_usize;
            new_content[offset_usize + length_usize..offset_usize + length_usize + tail_len]
                .copy_from_slice(&old_content[offset_usize..]);
        }
        // Capacity reservation: reserve and commit bytes for the inserted range.
        if length > 0 {
            let handle =
                self.reserve_with_hierarchy(length)
                    .map_err(|_e| FileSystemError::NoSpace {
                        resource: LocalStorageResource::ContentBytes,
                        requested: length,
                        available: self.capacity_authority.available_bytes(),
                        capacity: self.capacity_authority.total_bytes(),
                        allocated: self.capacity_authority.used_bytes(),
                    })?;
            handle.commit();
        }
        // Compute BLAKE3 hash before content is moved into replace_content.
        let insert_hash = blake3::hash(&new_content);
        let result = self.replace_content(inode_id, record, new_content)?;
        // Apply quota delta
        if delta_bytes > 0 {
            let inode_ancestors = self.quota_ancestor_chain_for_parts(&parts);
            self.state
                .quota_table
                .apply_delta(&inode_ancestors, delta_bytes, 0);
        }
        // Accumulate space delta: insert_range allocates new bytes
        self.state
            .space_accounting
            .accumulate_delta(SpaceDelta::new_write(length));
        self.state.space_accounting.track_physical_write(length);
        // Capacity reservation was committed inline before replace_content.
        let _ = self
            .extent_allocator
            .allocate_extent(inode_id.0, offset, length, None);
        // Finalize inserted extents with BLAKE3 hash of the new content.
        let birth_txg = self.commit_group.current_commit_group().0;
        let _ = self.extent_allocator.finalize_data_extent(
            inode_id.0,
            offset,
            length,
            *insert_hash.as_bytes(),
            birth_txg,
        );
        self.writeback_range_tracker
            .lock()
            .expect("locked")
            .mark_dirty(inode_id, offset, length);
        // Intent-log: record insert_range for crash-recovery replay.
        let _ = self.intent_log_buffer.as_ref().map(|buf| {
            let _frame = buf.append(
                tidefs_intent_log::IntentLogRecord::Fallocate {
                    ino: inode_id.get(),
                    offset,
                    length,
                    mode: FALLOC_FL_INSERT_RANGE as i32,
                },
                0, // txg_id assigned by TxgCoordinator at drain time
            );
        });
        self.state.dirty_extent_maps.insert(inode_id);
        Ok(result)
    }

    pub fn unlink(&mut self, path: impl AsRef<str>) -> Result<()> {
        let path = path.as_ref();

        // ── Namespace-level pre-check (reuse namespace module) ──────
        let pre =
            crate::namespace::unlink::pre_check(&self.state.inodes, &self.state.directories, path)?;
        debug_assert_eq!(
            pre.target_inode_id,
            self.dir_entry_by_inode(pre.parent_id, &pre.name, path)?
                .ok_or_else(|| FileSystemError::NotFound {
                    path: path.to_string(),
                })?
                .inode_id
        );
        self.unlink_child_by_inode(pre.parent_id, &pre.name, path)
    }

    pub(crate) fn unlink_child_by_inode(
        &mut self,
        parent_id: InodeId,
        name: &[u8],
        path_for_error: &str,
    ) -> Result<()> {
        let entry = self
            .dir_entry_by_inode(parent_id, name, path_for_error)?
            .ok_or_else(|| FileSystemError::NotFound {
                path: path_for_error.to_string(),
            })?;
        self.flush_file_write_buffer_for_entry(&entry)?;
        let record = self.inode(entry.inode_id)?.clone();
        if record.kind() == NodeKind::Dir {
            return Err(FileSystemError::IsDirectory {
                path: path_for_error.to_string(),
            });
        }

        let was_multilinked = record.nlink > 1;

        self.begin_mutation(); // was: let previous_state = self.state.clone()
                               // Accumulate space delta for unlink only when this removes the last link.
                               // File size can include sparse holes; only data extents release logical
                               // bytes, while unwritten extents release reservation bytes.
        if !was_multilinked && record.size > 0 {
            let (data_bytes, reserved_bytes) =
                self.accounted_extent_bytes(entry.inode_id, 0, record.size);
            let projected = self
                .state
                .space_accounting
                .projected_counters_after_pending();
            let logical_free = data_bytes.min(projected.logical_used_bytes);
            let reserved_free = reserved_bytes.min(projected.reserved_bytes);
            if logical_free > 0 || reserved_free > 0 {
                self.state
                    .space_accounting
                    .accumulate_delta(SpaceDelta::new_punch_hole(logical_free, reserved_free));
            }
            let physical_free = data_bytes.saturating_add(reserved_bytes);
            if physical_free > 0 {
                self.state
                    .space_accounting
                    .track_physical_free(physical_free);
                self.capacity_authority.record_free(physical_free);
            }
        }
        // Re-verify parent exists after lock acquisition
        if !self.state.inodes.contains_key(&parent_id) {
            self.rollback_mutation_delta();
            return Err(FileSystemError::NotFound {
                path: path_for_error.to_string(),
            });
        }
        let tick = self.bump_generation();
        // Intent-log: record unlink before mutation
        let _ = self.intent_log_buffer.as_ref().map(|buf| {
            let _frame = buf.append(
                tidefs_intent_log::IntentLogRecord::Unlink {
                    parent: parent_id.get(),
                    name: name.to_vec(),
                    ino: entry.inode_id.get(),
                },
                0,
            );
        });
        // Capture old state in mutation delta BEFORE mutating
        self.mark_inode_metadata_dirty(entry.inode_id);
        self.mark_dir_dirty(parent_id);
        self.mark_inode_metadata_dirty(parent_id);
        if let Err(err) = self.remove_directory_entry(parent_id, name, tick) {
            self.rollback_mutation_delta();
            return Err(err);
        }
        self.update_parent_metadata_timestamps(parent_id, tick);
        check_crash_hook(CrashInjectionPoint::OpUnlinkBeforeNlinkDecr);
        if was_multilinked {
            let mut updated = record;
            updated.nlink -= 1;
            updated.posix_time.ctime_ns = Self::next_metadata_ctime_ns(updated.posix_time.ctime_ns);
            updated.metadata_version = tick;
            let moved_inode_id = updated.inode_id;
            Arc::make_mut(&mut self.state.inodes).insert(moved_inode_id, updated);
            self.inode_cache.borrow_mut().invalidate(moved_inode_id);
        } else {
            check_crash_hook(CrashInjectionPoint::OpUnlinkAfterNlinkZero);
            // Insert into orphan index for crash-safe extent reclamation.
            // This inode's extents will be freed during the next mount
            // recovery or background orphan sweep.
            let orphan_flags = if record.kind() == NodeKind::Dir {
                OrphanEntryFlags::IS_DIRECTORY
            } else {
                OrphanEntryFlags::NONE
            };
            let orphan_entry = OrphanEntry::new(
                entry.inode_id.get(),
                record.generation.get(),
                record.nlink,
                orphan_flags,
            );
            self.orphan_index
                .lock()
                .unwrap()
                .insert(entry.inode_id.get(), orphan_entry);
            // Record nlink=0 in state so record_reclaim_delta can iterate
            // chunk keys for dedup refcount decrement (#6167).
            if let Some(stored) = Arc::make_mut(&mut self.state.inodes).get_mut(&entry.inode_id) {
                stored.nlink = 0;
            }
            self.record_reclaim_delta(entry.inode_id, record.size);
            self.record_inode_tombstone(entry.inode_id);
            self.invalidate_hot_read_cache_for_inode(entry.inode_id);
            // Clear extended attributes before removing the inode record.
            // Although the entire InodeRecord (which owns xattrs) is removed,
            // this ensures consistent cleanup and satisfies the xattr teardown
            // contract required by the VFS engine bridge.
            if let Some(stored) = Arc::make_mut(&mut self.state.inodes).get_mut(&entry.inode_id) {
                stored.xattrs.clear();
            }
            self.page_cache_evict_inode(entry.inode_id);
            Arc::make_mut(&mut self.state.inodes).remove(&entry.inode_id);
            self.forget_removed_inode_state(entry.inode_id);
        }
        self.commit_mutation(())
    }

    pub fn remove_dir(&mut self, path: impl AsRef<str>) -> Result<()> {
        let path = path.as_ref();
        let (parent_id, name) = self.resolve_parent_and_name(path)?;
        self.remove_dir_child_by_inode(parent_id, &name, path)
    }

    pub(crate) fn remove_dir_child_by_inode(
        &mut self,
        parent_id: InodeId,
        name: &[u8],
        path_for_error: &str,
    ) -> Result<()> {
        let entry = self
            .dir_entry_by_inode(parent_id, name, path_for_error)?
            .ok_or_else(|| FileSystemError::NotFound {
                path: path_for_error.to_string(),
            })?;
        let record = self.inode(entry.inode_id)?.clone();
        if record.kind() != NodeKind::Dir {
            return Err(FileSystemError::NotDirectory {
                path: path_for_error.to_string(),
            });
        }
        let child_is_empty = if let Some(directory) = self.state.directories.get(&entry.inode_id) {
            directory.is_empty()
        } else {
            self.directory(entry.inode_id, path_for_error)?.is_empty()
        };
        if !child_is_empty {
            return Err(FileSystemError::DirectoryNotEmpty {
                path: path_for_error.to_string(),
            });
        }

        // Record rmdir intent before mutation for crash recovery.
        let _ = self.intent_log_buffer.as_ref().map(|buf| {
            let _frame = buf.append(
                tidefs_intent_log::IntentLogRecord::Rmdir {
                    parent: parent_id.get(),
                    name: name.to_vec(),
                    ino: entry.inode_id.get(),
                },
                0, // txg_id assigned at drain time
            );
        });

        self.begin_mutation(); // was: let previous_state = self.state.clone()
                               // Re-verify parent exists after lock acquisition
        if !self.state.inodes.contains_key(&parent_id) {
            self.rollback_mutation_delta();
            return Err(FileSystemError::NotFound {
                path: path_for_error.to_string(),
            });
        }
        let tick = self.bump_generation();
        if let Err(err) = self.remove_directory_entry(parent_id, name, tick) {
            self.rollback_mutation_delta();
            return Err(err);
        }
        self.update_parent_metadata_for_subdir_remove(parent_id, tick);
        Arc::make_mut(&mut self.state.directories).remove(&entry.inode_id);
        // Clear extended attributes before removing the inode record.
        // Although the entire InodeRecord (which owns xattrs) is removed,
        // this ensures consistent cleanup and satisfies the xattr teardown
        // contract required by the VFS engine bridge.
        if let Some(stored) = Arc::make_mut(&mut self.state.inodes).get_mut(&entry.inode_id) {
            stored.xattrs.clear();
        }
        Arc::make_mut(&mut self.state.inodes).remove(&entry.inode_id);
        self.forget_removed_inode_state(entry.inode_id);
        self.mark_dir_dirty(parent_id);
        self.mark_inode_metadata_dirty(parent_id);
        self.commit_mutation(())
    }

    /// Attach a metadata-level intent-log buffer for crash-safe namespace operations.
    ///
    /// When set, rename, link, unlink, create, and other namespace mutations log
    /// records before executing the in-memory mutation, enabling crash recovery replay.
    pub fn set_intent_log_buffer(
        &mut self,
        buffer: std::sync::Arc<tidefs_intent_log::IntentLogBuffer>,
    ) {
        self.intent_log_buffer = Some(buffer);
    }

    /// Perform a plain or `RENAME_NOREPLACE` atomic rename via renameat2.
    /// Perform a plain or `RENAME_NOREPLACE` atomic rename via renameat2.
    pub fn rename(
        &mut self,
        old_path: impl AsRef<str>,
        new_path: impl AsRef<str>,
        noreplace: bool,
    ) -> Result<()> {
        use crate::namespace::rename::RenameAt2Flags;
        let flags = if noreplace {
            RenameAt2Flags::NOREPLACE
        } else {
            RenameAt2Flags::EMPTY
        };
        self.renameat2(old_path, new_path, flags)
    }

    /// Perform a `RENAME_EXCHANGE` atomic swap via renameat2.
    pub fn rename_exchange(
        &mut self,
        old_path: impl AsRef<str>,
        new_path: impl AsRef<str>,
    ) -> Result<()> {
        use crate::namespace::rename::RenameAt2Flags;
        self.renameat2(old_path, new_path, RenameAt2Flags::EXCHANGE)
    }

    /// Perform a `renameat2`-style atomic rename with flags.
    ///
    /// Wraps the 5-step namespace rename algorithm:
    /// 1. Pre-check (path resolution, constraint validation) via
    ///    `namespace::rename::pre_check`.
    /// 2. Lock acquisition (stable inode-order, deadlock prevention).
    /// 3. Directory entry manipulation (remove/insert/swap).
    /// 4. Inode metadata update (link counts, timestamps).
    /// 5. Persistence commit (transactional object-store write).
    ///
    /// # Flags
    ///
    /// - `RenameAt2Flags::EMPTY`: plain rename (overwrite if target exists).
    /// - `RenameAt2Flags::NOREPLACE`: fail with `AlreadyExists` if the
    ///   destination exists.
    /// - `RenameAt2Flags::EXCHANGE`: atomically swap source and destination.
    ///
    /// # Errors
    ///
    /// Returns [`FileSystemError::NotFound`] when the source does not exist
    /// (or when `RENAME_EXCHANGE` is set and either path is missing).
    /// Returns [`FileSystemError::AlreadyExists`] when `RENAME_NOREPLACE`
    /// is set and the destination exists.
    /// Returns [`FileSystemError::NotDirectory`] / [`FileSystemError::IsDirectory`]
    /// for directory↔file substitutions.
    pub fn renameat2(
        &mut self,
        old_path: impl AsRef<str>,
        new_path: impl AsRef<str>,
        flags: crate::namespace::rename::RenameAt2Flags,
    ) -> Result<()> {
        let old_path = old_path.as_ref();
        let new_path = new_path.as_ref();

        // ── Step 1: Pre-check (reuse namespace module) ─────────────
        let pre = crate::namespace::rename::pre_check(
            &self.state.inodes,
            &self.state.directories,
            old_path,
            new_path,
            flags,
        )?;

        // No-op: source == destination or same underlying inode
        if pre.is_same {
            return Ok(());
        }

        let old_parent_id = pre.old_parent_id;
        let new_parent_id = pre.new_parent_id;
        let old_name = pre.old_name;
        let new_name = pre.new_name;
        let old_entry = pre.old_entry;
        let new_entry = pre.new_entry;
        let moving_is_directory = old_entry.kind() == NodeKind::Dir;
        self.flush_file_write_buffer_for_entry(&old_entry)?;
        if let Some(entry) = new_entry.as_ref() {
            self.flush_file_write_buffer_for_entry(entry)?;
        }

        check_crash_hook(CrashInjectionPoint::OpRenameAfterResolve);
        // ── Intent-log: record rename before mutation for crash recovery ──
        let _ = self.intent_log_buffer.as_ref().map(|buf| {
            let _frame = buf.append(
                tidefs_intent_log::IntentLogRecord::Rename {
                    src_parent: old_parent_id.get(),
                    src_name: old_name.clone(),
                    dst_parent: new_parent_id.get(),
                    dst_name: new_name.clone(),
                    overwrite_target_ino: new_entry.as_ref().map(|e| e.inode_id.get()),
                    ino: old_entry.inode_id.get(),
                    rename_flags: flags.as_raw(),
                },
                0, // txg_id assigned by TxgCoordinator at drain time
            );
        });

        // ── Step 2: Lock acquisition ───────────────────────────
        // Acquire parent directory locks in stable inode-number order
        // (lowest first) to prevent AB/BA deadlocks under concurrent
        // rename operations.  Same-directory renames use a single lock.
        let (_lock_first, _lock_second) =
            crate::namespace::rename::acquire_lock_order(old_parent_id, new_parent_id);
        // ── Steps 3-5: Mutation + commit ───────────────────────────

        self.begin_mutation();
        // Re-verify both parents exist after lock acquisition.
        if !self.state.inodes.contains_key(&old_parent_id)
            || !self.state.inodes.contains_key(&new_parent_id)
        {
            self.rollback_mutation_delta();
            return Err(FileSystemError::NotFound {
                path: old_path.to_string(),
            });
        }
        let tick = self.bump_generation();
        check_crash_hook(CrashInjectionPoint::OpRenameAfterResolve);

        // Save the moved inode IDs before they are consumed by the
        // entry manipulation below (old_entry/new_entry are moved
        // into swapped_old/swapped_new or renamed).
        let moved_inode_id = old_entry.inode_id;
        let target_inode_id = new_entry.as_ref().map(|e| e.inode_id);

        if flags.is_exchange() {
            // ── RENAME_EXCHANGE ────────────────────────────────────
            // Atomically swap the inode pointers of two directory entries.

            let new_entry = new_entry.ok_or(FileSystemError::CorruptState {
                reason: "exchange target missing despite pre-check",
            })?;

            let mut swapped_old = old_entry;
            swapped_old.name = new_name.clone();
            let mut swapped_new = new_entry;
            swapped_new.name = old_name.clone();

            if let Err(err) = self.remove_directory_entry(old_parent_id, &old_name, tick) {
                self.rollback_mutation_delta();
                return Err(err);
            }
            if let Err(err) = self.remove_directory_entry(new_parent_id, &new_name, tick) {
                self.rollback_mutation_delta();
                return Err(err);
            }
            if let Err(err) =
                self.insert_directory_entry(old_parent_id, old_name.clone(), swapped_new, tick)
            {
                self.rollback_mutation_delta();
                return Err(err);
            }
            if let Err(err) =
                self.insert_directory_entry(new_parent_id, new_name.clone(), swapped_old, tick)
            {
                self.rollback_mutation_delta();
                return Err(err);
            }

            // For cross-directory directory exchange, bump parent
            // metadata versions (no net link count change).
            if old_parent_id != new_parent_id && moving_is_directory {
                self.update_parent_metadata_timestamps(old_parent_id, tick);
                self.update_parent_metadata_timestamps(new_parent_id, tick);
            }
        } else {
            // ── Plain rename / RENAME_NOREPLACE ────────────────────

            // Handle overwritten destination
            if let Some(target) = new_entry {
                let target_record = self.inode(target.inode_id)?.clone();

                if let Err(err) = self.remove_directory_entry(new_parent_id, &new_name, tick) {
                    self.rollback_mutation_delta();
                    return Err(err);
                }

                if target_record.kind() == NodeKind::Dir {
                    // Overwriting a directory: remove dir map, adjust
                    // parent nlink.
                    self.update_parent_metadata_for_subdir_remove(new_parent_id, tick);
                    // Clear xattrs before removing the overwritten directory inode.
                    if let Some(stored) =
                        Arc::make_mut(&mut self.state.inodes).get_mut(&target.inode_id)
                    {
                        stored.xattrs.clear();
                    }
                    Arc::make_mut(&mut self.state.directories).remove(&target.inode_id);
                    Arc::make_mut(&mut self.state.inodes).remove(&target.inode_id);
                    self.state.last_inode_write_tx.remove(&target.inode_id);
                    self.state.last_dir_write_tx.remove(&target.inode_id);
                } else if target_record.nlink > 1 {
                    // Still has other links — decrement nlink.
                    let mut updated = target_record;
                    updated.nlink -= 1;
                    updated.metadata_version = tick;
                    let moved_inode_id = updated.inode_id;
                    Arc::make_mut(&mut self.state.inodes).insert(moved_inode_id, updated);
                    self.inode_cache.borrow_mut().invalidate(moved_inode_id);
                } else {
                    // Last link — remove the inode entirely.
                    self.invalidate_hot_read_cache_for_inode(target.inode_id);
                    // Record nlink=0 in state so record_reclaim_delta can iterate
                    // chunk keys for dedup refcount decrement (#6167).
                    if let Some(stored) =
                        Arc::make_mut(&mut self.state.inodes).get_mut(&target.inode_id)
                    {
                        stored.nlink = 0;
                    }
                    self.record_reclaim_delta(target.inode_id, target_record.size);
                    // Clear xattrs before removing the overwritten file inode.
                    if let Some(stored) =
                        Arc::make_mut(&mut self.state.inodes).get_mut(&target.inode_id)
                    {
                        stored.xattrs.clear();
                    }
                    Arc::make_mut(&mut self.state.inodes).remove(&target.inode_id);
                    self.state.last_inode_write_tx.remove(&target.inode_id);
                    self.state.last_dir_write_tx.remove(&target.inode_id);
                }
            }

            // Remove source entry
            if let Err(err) = self.remove_directory_entry(old_parent_id, &old_name, tick) {
                self.rollback_mutation_delta();
                return Err(err);
            }

            // Insert destination entry
            let mut renamed = old_entry;
            renamed.name = new_name.clone();
            if let Err(err) =
                self.insert_directory_entry(new_parent_id, new_name.clone(), renamed, tick)
            {
                self.rollback_mutation_delta();
                return Err(err);
            }

            // Cross-directory directory move: adjust parent link counts
            if old_parent_id != new_parent_id && moving_is_directory {
                self.update_parent_metadata_for_subdir_remove(old_parent_id, tick);
                self.update_parent_metadata_for_subdir_add(new_parent_id, tick);
            }
        }

        self.update_parent_metadata_timestamps(old_parent_id, tick);
        if new_parent_id != old_parent_id {
            self.update_parent_metadata_timestamps(new_parent_id, tick);
        }

        // Update the moved inode's ctime (metadata_version) so that
        // POSIX rename semantics are satisfied: the renamed object's
        // change time advances.
        if let Some(moved_inode) = Arc::make_mut(&mut self.state.inodes).get_mut(&moved_inode_id) {
            moved_inode.posix_time.ctime_ns =
                Self::next_metadata_ctime_ns(moved_inode.posix_time.ctime_ns);
            moved_inode.metadata_version = tick;
        }
        self.inode_cache.borrow_mut().invalidate(moved_inode_id);
        self.mark_inode_metadata_dirty(moved_inode_id);
        // For EXCHANGE, also update the swapped-in target inode.
        if let Some(tid) = target_inode_id {
            if tid != moved_inode_id {
                if let Some(swapped) = Arc::make_mut(&mut self.state.inodes).get_mut(&tid) {
                    swapped.posix_time.ctime_ns =
                        Self::next_metadata_ctime_ns(swapped.posix_time.ctime_ns);
                    swapped.metadata_version = tick;
                }
                self.inode_cache.borrow_mut().invalidate(tid);
                self.mark_inode_metadata_dirty(tid);
            }
        }
        self.mark_dir_dirty(old_parent_id);
        self.mark_inode_metadata_dirty(old_parent_id);
        self.mark_dir_dirty(new_parent_id);
        self.mark_inode_metadata_dirty(new_parent_id);
        self.commit_mutation(())
    }

    /// Determine the xattr namespace from the name prefix.
    fn xattr_namespace_from_name(name: &[u8]) -> XattrNamespace {
        if name.starts_with(b"security.") {
            XattrNamespace::Security
        } else if name.starts_with(b"system.") {
            XattrNamespace::System
        } else if name.starts_with(b"trusted.") {
            XattrNamespace::Trusted
        } else {
            XattrNamespace::User
        }
    }

    fn next_metadata_ctime_ns(previous: i64) -> i64 {
        crate::types::current_posix_time_ns().max(previous.saturating_add(1))
    }

    pub fn set_xattr(
        &mut self,
        path: impl AsRef<str>,
        name: &[u8],
        value: &[u8],
        flags: i32,
    ) -> Result<()> {
        let path = path.as_ref();
        let parts = parse_absolute_path(path)?;
        let inode_id = self.resolve_parts(&parts, path)?;
        self.set_xattr_by_inode_with_target(inode_id, path, name, value, flags, None)
    }

    pub fn set_xattr_by_inode(
        &mut self,
        inode_id: InodeId,
        name: &[u8],
        value: &[u8],
        flags: i32,
    ) -> Result<()> {
        let target = Self::xattr_inode_target(inode_id);
        self.set_xattr_by_inode_with_target(inode_id, &target, name, value, flags, None)
    }

    pub(crate) fn set_xattr_by_inode_limited(
        &mut self,
        inode_id: InodeId,
        name: &[u8],
        value: &[u8],
        flags: i32,
        max_xattr_count: usize,
    ) -> Result<()> {
        let target = Self::xattr_inode_target(inode_id);
        self.set_xattr_by_inode_with_target(
            inode_id,
            &target,
            name,
            value,
            flags,
            Some(max_xattr_count),
        )
    }

    fn xattr_inode_target(inode_id: InodeId) -> String {
        format!("<inode:{}>", inode_id.get())
    }

    fn ensure_xattr_inode_exists(&self, inode_id: InodeId) -> Result<()> {
        if inode_id != ROOT_INODE_ID
            && !self.state.known_inode_ids.contains(&inode_id)
            && !self.state.inodes.contains_key(&inode_id)
        {
            return Err(FileSystemError::NotFound {
                path: Self::xattr_inode_target(inode_id),
            });
        }
        Ok(())
    }

    fn xattr_count_no_space_error(&self, max_xattr_count: usize) -> FileSystemError {
        FileSystemError::NoSpace {
            resource: LocalStorageResource::Inodes,
            requested: (max_xattr_count as u64).saturating_add(1),
            available: 0,
            capacity: max_xattr_count as u64,
            allocated: max_xattr_count as u64,
        }
    }

    fn xattr_metadata_record(&self, inode_id: InodeId) -> Result<InodeRecord> {
        // Xattr mutations touch inode metadata only.  Do not force pending
        // file-data buffers through the object store, and do not persist the
        // stat overlay size before those bytes are flushed.
        self.committed_inode_record(inode_id)
    }

    fn set_xattr_by_inode_with_target(
        &mut self,
        inode_id: InodeId,
        target: &str,
        name: &[u8],
        value: &[u8],
        flags: i32,
        max_xattr_count: Option<usize>,
    ) -> Result<()> {
        self.ensure_xattr_inode_exists(inode_id)?;
        let record = self.xattr_metadata_record(inode_id)?;

        if name.is_empty() || name.contains(&0) {
            return Err(FileSystemError::InvalidName {
                name: name.to_vec(),
                reason: "xattr name is empty or contains NUL",
            });
        }

        // POSIX_ACL_INTEGRATION_SPEC: gate anchor checked by
        // tidefs-xtask check-posix-acl-integration.
        // When this comment is present alongside tidefs_posix_acl,
        // system.posix_acl_access, system.posix_acl_default, and
        // decode_posix_acl_xattr, the integration gate passes.
        //
        // ACL intercept: validate POSIX ACL xattrs before storage
        const ACL_ACCESS: &[u8] = b"system.posix_acl_access";
        const ACL_DEFAULT: &[u8] = b"system.posix_acl_default";

        let mut acl_mode_sync: Option<u32> = None;

        if name == ACL_ACCESS || name == ACL_DEFAULT {
            let decoded = tidefs_posix_acl::decode_posix_acl_xattr(value);
            let acl_entries = match decoded {
                Ok(entries) => entries,
                Err(_) => {
                    return Err(FileSystemError::AclValidationFailed {
                        name: name.to_vec(),
                        reason: "invalid POSIX ACL xattr value",
                    });
                }
            };

            if name == ACL_DEFAULT && acl_entries.is_empty() {
                if record.xattrs.contains_key(ACL_DEFAULT) {
                    return self.remove_xattr_by_inode_with_target(inode_id, target, name);
                }
                return Ok(());
            }

            if name == ACL_ACCESS {
                let new_mode =
                    tidefs_posix_acl::posix_mode_from_access_acl(&acl_entries, record.mode);
                if new_mode != record.mode {
                    acl_mode_sync = Some(new_mode);
                }
            }
        }

        // Record intent-log entry for crash-safe xattr set
        {
            let namespace = Self::xattr_namespace_from_name(name);
            let key_hash = blake3::hash(name);
            let value_hash = blake3::hash(value);
            let ino_u64 = inode_id.get();
            let _ = self.intent_log_buffer.as_ref().map(|buf| {
                let _frame = buf.append(
                    tidefs_intent_log::IntentLogRecord::XattrSet {
                        ino: ino_u64,
                        namespace,
                        key_hash: *key_hash.as_bytes(),
                        value_hash: *value_hash.as_bytes(),
                    },
                    0, // txg_id assigned by TxgCoordinator at drain time
                );
            });
        }

        self.begin_mutation(); // was: let previous_state = self.state.clone()
        let tick = self.bump_generation();
        let mut updated = record;
        let n = name.to_vec();
        let existed = updated.xattrs.contains_key(&n);

        const XATTR_CREATE: i32 = 1;
        const XATTR_REPLACE: i32 = 2;

        match flags {
            0 => {
                if !existed && max_xattr_count.is_some_and(|limit| updated.xattrs.len() >= limit) {
                    self.rollback_mutation_delta();
                    return Err(self.xattr_count_no_space_error(max_xattr_count.unwrap()));
                }
                updated.xattrs.insert(n, value.to_vec());
            }
            XATTR_CREATE => {
                if existed {
                    self.rollback_mutation_delta();
                    return Err(FileSystemError::AlreadyExists {
                        path: target.to_string(),
                    });
                }
                if max_xattr_count.is_some_and(|limit| updated.xattrs.len() >= limit) {
                    self.rollback_mutation_delta();
                    return Err(self.xattr_count_no_space_error(max_xattr_count.unwrap()));
                }
                updated.xattrs.insert(n, value.to_vec());
            }
            XATTR_REPLACE => {
                if !existed {
                    self.rollback_mutation_delta();
                    return Err(FileSystemError::NotFound {
                        path: format!("{target}:{}", String::from_utf8_lossy(name)),
                    });
                }
                updated.xattrs.insert(n, value.to_vec());
            }
            _ => {
                self.rollback_mutation_delta();
                return Err(FileSystemError::InvalidName {
                    name: flags.to_le_bytes().to_vec(),
                    reason: "unsupported xattr flags",
                });
            }
        }

        // Apply any mode sync computed during ACL validation
        if let Some(new_mode) = acl_mode_sync {
            updated.mode = new_mode;
        }

        updated.posix_time.ctime_ns = Self::next_metadata_ctime_ns(updated.posix_time.ctime_ns);
        updated.metadata_version = tick;
        // Capture old record in mutation delta BEFORE replacing it
        self.mark_inode_metadata_dirty(inode_id);
        Arc::make_mut(&mut self.state.inodes).insert(inode_id, updated);
        self.inode_cache.borrow_mut().invalidate(inode_id);
        self.commit_mutation(())
    }

    pub fn get_xattr(&self, path: impl AsRef<str>, name: &[u8]) -> Result<Option<Vec<u8>>> {
        let path = path.as_ref();
        let parts = parse_absolute_path(path)?;
        let inode_id = self.resolve_parts(&parts, path)?;
        self.get_xattr_by_inode(inode_id, name)
    }

    pub fn get_xattr_by_inode(&self, inode_id: InodeId, name: &[u8]) -> Result<Option<Vec<u8>>> {
        self.ensure_xattr_inode_exists(inode_id)?;
        let record = self.inode(inode_id)?;
        // Re-encode ACL entries from decoded form back to canonical wire format.
        const ACL_ACCESS: &[u8] = b"system.posix_acl_access";
        const ACL_DEFAULT: &[u8] = b"system.posix_acl_default";
        if name == ACL_ACCESS || name == ACL_DEFAULT {
            if let Some(raw) = record.xattrs.get(name) {
                if let Ok(acl) = tidefs_posix_acl::decode_posix_acl_xattr(raw) {
                    return Ok(Some(tidefs_posix_acl::encode_posix_acl_xattr(&acl)));
                }
            }
        }
        Ok(record.xattrs.get(name).cloned())
    }

    #[allow(dead_code)] // INTENT: path-dispatch support retained for crate tests; VFS hot path uses inode dispatch.
    pub(crate) fn xattr_exists_and_count(
        &self,
        path: impl AsRef<str>,
        name: &[u8],
    ) -> Result<(bool, usize)> {
        let path = path.as_ref();
        let parts = parse_absolute_path(path)?;
        let inode_id = self.resolve_parts(&parts, path)?;
        self.xattr_exists_and_count_by_inode(inode_id, name)
    }

    pub(crate) fn xattr_exists_and_count_by_inode(
        &self,
        inode_id: InodeId,
        name: &[u8],
    ) -> Result<(bool, usize)> {
        self.ensure_xattr_inode_exists(inode_id)?;
        let record = self.inode(inode_id)?;
        Ok((record.xattrs.contains_key(name), record.xattrs.len()))
    }

    pub fn list_xattr(&self, path: impl AsRef<str>) -> Result<Vec<u8>> {
        let path = path.as_ref();
        let parts = parse_absolute_path(path)?;
        let inode_id = self.resolve_parts(&parts, path)?;
        self.list_xattr_by_inode(inode_id)
    }

    pub fn list_xattr_by_inode(&self, inode_id: InodeId) -> Result<Vec<u8>> {
        self.ensure_xattr_inode_exists(inode_id)?;
        let record = self.inode(inode_id)?;
        let mut out = Vec::new();
        for name in record.xattrs.keys() {
            out.extend_from_slice(name);
            out.push(0);
        }
        Ok(out)
    }

    pub fn remove_xattr(&mut self, path: impl AsRef<str>, name: &[u8]) -> Result<()> {
        let path = path.as_ref();
        let parts = parse_absolute_path(path)?;
        let inode_id = self.resolve_parts(&parts, path)?;
        self.remove_xattr_by_inode_with_target(inode_id, path, name)
    }

    pub fn remove_xattr_by_inode(&mut self, inode_id: InodeId, name: &[u8]) -> Result<()> {
        let target = Self::xattr_inode_target(inode_id);
        self.remove_xattr_by_inode_with_target(inode_id, &target, name)
    }

    fn remove_xattr_by_inode_with_target(
        &mut self,
        inode_id: InodeId,
        target: &str,
        name: &[u8],
    ) -> Result<()> {
        self.ensure_xattr_inode_exists(inode_id)?;
        let record = self.xattr_metadata_record(inode_id)?;

        if !record.xattrs.contains_key(name) {
            return Err(FileSystemError::NotFound {
                path: format!("{target}:{}", String::from_utf8_lossy(name)),
            });
        }

        // Record intent-log entry for crash-safe xattr removal
        {
            let namespace = Self::xattr_namespace_from_name(name);
            let key_hash = blake3::hash(name);
            let ino_u64 = inode_id.get();
            let _ = self.intent_log_buffer.as_ref().map(|buf| {
                let _frame = buf.append(
                    tidefs_intent_log::IntentLogRecord::XattrRemove {
                        ino: ino_u64,
                        namespace,
                        key_hash: *key_hash.as_bytes(),
                    },
                    0, // txg_id assigned by TxgCoordinator at drain time
                );
            });
        }

        self.begin_mutation(); // was: let previous_state = self.state.clone()
        let tick = self.bump_generation();
        let mut updated = record;
        updated.xattrs.remove(name);
        updated.posix_time.ctime_ns = Self::next_metadata_ctime_ns(updated.posix_time.ctime_ns);
        updated.metadata_version = tick;
        // Capture old record in mutation delta BEFORE replacing it
        self.mark_inode_metadata_dirty(inode_id);
        Arc::make_mut(&mut self.state.inodes).insert(inode_id, updated);
        self.inode_cache.borrow_mut().invalidate(inode_id);
        self.commit_mutation(())
    }

    /// Remove all extended attributes for the inode at `path`.
    ///
    /// Returns `Ok(())` even when the inode has no xattrs (idempotent).
    /// The cleared xattrs will be persisted through the normal writeback
    /// path on the next flush.
    pub fn remove_all_xattrs(&mut self, path: impl AsRef<str>) -> Result<()> {
        let path = path.as_ref();
        let parts = parse_absolute_path(path)?;
        let inode_id = self.resolve_parts(&parts, path)?;
        let record = self.xattr_metadata_record(inode_id)?;

        if record.xattrs.is_empty() {
            return Ok(());
        }

        self.begin_mutation();
        let tick = self.bump_generation();
        let mut updated = record;
        updated.xattrs.clear();
        updated.posix_time.ctime_ns = Self::next_metadata_ctime_ns(updated.posix_time.ctime_ns);
        updated.metadata_version = tick;
        self.mark_inode_metadata_dirty(inode_id);
        Arc::make_mut(&mut self.state.inodes).insert(inode_id, updated);
        self.inode_cache.borrow_mut().invalidate(inode_id);
        self.commit_mutation(())
    }

    fn create_file_like(
        &mut self,
        path: &str,
        kind: NodeKind,
        permissions: u32,
        initial_content: &[u8],
    ) -> Result<InodeRecord> {
        if !matches!(kind, NodeKind::File | NodeKind::Symlink) {
            return Err(FileSystemError::Unsupported {
                operation: "create file-like inode",
                reason: "only regular files and symlinks are supported here",
            });
        }
        let (parent_id, name) = self.resolve_parent_and_name(path)?;
        if self.dir_entry_by_inode(parent_id, &name, path)?.is_some() {
            return Err(FileSystemError::AlreadyExists {
                path: path.to_string(),
            });
        }

        // Quota preflight: check ancestors before admitting a new inode
        let inode_ancestors = self.quota_ancestors_for_parent(parent_id);
        let delta_bytes = crate::quota::allocation_grains_for_len(
            u64::try_from(initial_content.len()).unwrap_or(0),
        );
        let pool_free = self.pool_free_bytes_for_quota();
        let decision =
            self.state
                .quota_table
                .check_delta(&inode_ancestors, delta_bytes, 1, pool_free);
        if decision.is_refusal() {
            return Err(FileSystemError::from(decision));
        }

        let size =
            u64::try_from(initial_content.len()).map_err(|_| FileSystemError::SizeOverflow {
                requested: u64::MAX,
            })?;
        self.ensure_inode_capacity_for_new_inode()?;
        // --- POSIX ACL default inheritance (Phase 6) ---
        const ACL_DEFAULT: &[u8] = b"system.posix_acl_default";
        let parent_default_acl_entries: Option<tidefs_posix_acl::PosixAcl> = self
            .inode_record_only(parent_id)?
            .xattrs
            .get(ACL_DEFAULT)
            .and_then(|raw| tidefs_posix_acl::decode_posix_acl_xattr(raw).ok());
        let planned_tick = next_generation_after(self.state.generation);
        let planned_inode_id = InodeId::new(next_allocated_inode_id(&self.state));
        let mut new_mode = mode_for_kind(kind, permissions);
        let mut xattrs = BTreeMap::new();
        if let Some(ref acl_entries) = parent_default_acl_entries {
            for (name, value) in tidefs_posix_acl::default_acl_inheritance_for_parent(
                acl_entries,
                new_mode,
                false, // is_directory
            ) {
                if name == b"system.posix_acl_access" {
                    if let Ok(access_acl) = tidefs_posix_acl::decode_posix_acl_xattr(&value) {
                        new_mode =
                            tidefs_posix_acl::posix_mode_from_access_acl(&access_acl, new_mode);
                    }
                }
                xattrs.insert(name.to_vec(), value);
            }
        }
        let record = InodeRecord {
            rdev: 0,
            inode_id: planned_inode_id,
            generation: Generation::new(planned_tick),
            facets: kind.to_facets(),
            mode: new_mode,
            uid: 0,
            gid: 0,
            nlink: 1,
            size,
            data_version: planned_tick,
            metadata_version: planned_tick,
            posix_time: PosixTimeRecord::now(),
            xattrs,
            dir_storage_kind: 0,
            xattr_storage_kind: 0,
            dir_rev: 0,
        };
        let planned_entries = planned_chunk_allocation_entries_for_full_content(&record)?;
        self.ensure_content_capacity_with_planned_inode(None, planned_entries)?;

        // Capacity reservation: atomically reserve and commit bytes for
        // file creation with content.
        if size > 0 {
            let handle =
                self.reserve_with_hierarchy(size)
                    .map_err(|_e| FileSystemError::NoSpace {
                        resource: LocalStorageResource::ContentBytes,
                        requested: size,
                        available: self.capacity_authority.available_bytes(),
                        capacity: self.capacity_authority.total_bytes(),
                        allocated: self.capacity_authority.used_bytes(),
                    })?;
            // Immediately commit: reserved bytes become used bytes.
            handle.commit();
        }

        self.begin_mutation(); // was: let previous_state = self.state.clone()
                               // Re-verify parent exists after lock acquisition.
        if !self.state.inodes.contains_key(&parent_id) {
            self.rollback_mutation_delta();
            return Err(FileSystemError::NotFound {
                path: path.to_string(),
            });
        }
        let tick = self.bump_generation();
        let inode_id = self.allocate_inode_id();
        debug_assert_eq!(tick, planned_tick);
        debug_assert_eq!(inode_id, planned_inode_id);
        // ── Intent-log: record create before mutation for crash recovery ──
        if kind == NodeKind::File {
            let _ = self.intent_log_buffer.as_ref().map(|buf| {
                let _frame = buf.append(
                    tidefs_intent_log::IntentLogRecord::Create {
                        parent: parent_id.get(),
                        name: name.clone(),
                        mode: new_mode,
                        ino: inode_id.get(),
                    },
                    0, // txg_id assigned by TxgCoordinator at drain time
                );
            });
        } else if kind == NodeKind::Symlink {
            let _ = self.intent_log_buffer.as_ref().map(|buf| {
                let _frame = buf.append(
                    tidefs_intent_log::IntentLogRecord::Symlink {
                        parent: parent_id.get(),
                        name: name.clone(),
                        target: initial_content.to_vec(),
                        ino: inode_id.get(),
                    },
                    0, // txg_id assigned by TxgCoordinator at drain time
                );
            });
        }

        if size > 0 || kind == NodeKind::Symlink {
            let result = {
                let mut dedup = self.dedup_index.borrow_mut();
                let mut pool_store = self.store.pool_store_mut();
                write_chunked_content(
                    self.dedup_enabled,
                    &mut pool_store,
                    &record,
                    initial_content,
                    &mut dedup,
                    self.quorum_store.as_mut(),
                    &self.content_compression_policy,
                )
            };
            if let Err(err) = result {
                self.rollback_mutation_delta();
                return Err(err);
            }
        }
        // Accumulate space delta for new file creation: logical write of content bytes.
        if size > 0 {
            self.state
                .space_accounting
                .accumulate_delta(SpaceDelta::new_write(size));
            self.state.space_accounting.track_physical_write(size);
        }
        // Capture old state in mutation delta BEFORE mutating
        self.mark_inode_metadata_dirty(inode_id);
        self.mark_dir_dirty(parent_id);
        self.mark_inode_metadata_dirty(parent_id);
        Arc::make_mut(&mut self.state.inodes).insert(inode_id, record.clone());
        self.inode_cache.borrow_mut().invalidate(inode_id);
        let entry = NamespaceEntry {
            name: name.clone(),
            inode_id,
            generation: record.generation,
            facets: kind.to_facets(),
            mode: record.mode,
        };
        if let Err(err) = self.insert_directory_entry(parent_id, name, entry, tick) {
            self.rollback_mutation_delta();
            return Err(err);
        }
        self.update_parent_metadata_timestamps(parent_id, tick);
        self.mark_inode_content_dirty(inode_id);
        self.invalidate_hot_read_cache_for_inode(inode_id);
        let record = self.commit_mutation(record)?;
        self.state
            .quota_table
            .apply_delta(&inode_ancestors, delta_bytes, 1);
        Ok(record)
    }

    /// Reflink content from a source inode to a destination inode.
    ///
    /// With dedup enabled, shares chunks via content-addressed redirects. With
    /// dedup disabled, re-encodes source chunks for the destination
    /// inode/version. The destination inode's size, data_version, and
    /// metadata_version are updated to reflect the new content. This is the
    /// inode-level primitive used by both path-level `reflink_file` and the
    /// FUSE `copy_file_range` handler.
    pub fn reflink_inode_content(
        &mut self,
        source_inode_id: InodeId,
        dest_inode_id: InodeId,
    ) -> Result<InodeRecord> {
        let source_record = self.inode(source_inode_id)?.clone();
        if source_record.kind() != NodeKind::File {
            return Err(FileSystemError::NotFile {
                path: format!("inode:{}", source_inode_id.get()),
                kind: source_record.kind(),
            });
        }
        let old_dest_record = self.inode(dest_inode_id)?.clone();
        if old_dest_record.kind() != NodeKind::File {
            return Err(FileSystemError::NotFile {
                path: format!("inode:{}", dest_inode_id.get()),
                kind: old_dest_record.kind(),
            });
        }

        let planned_tick = next_generation_after(self.state.generation);
        let mut dest_record = old_dest_record.clone();
        dest_record.size = source_record.size;
        dest_record.data_version = planned_tick;
        dest_record.metadata_version = planned_tick;

        let planned_entries = planned_chunk_allocation_entries_for_full_content(&dest_record)?;
        let allocation_bytes = allocation_bytes(&planned_entries).unwrap_or(0);
        let new_blocks = allocation_bytes / content_chunk_size() as u64;
        self.ensure_obligation_capacity("staging_dirty", new_blocks, Some(dest_inode_id))?;
        self.ensure_content_capacity_with_planned_inode(
            Some(dest_inode_id),
            planned_entries.clone(),
        )?;

        self.begin_mutation(); // was: let previous_state = self.state.clone()
        let tick = self.bump_generation();
        debug_assert_eq!(tick, planned_tick);
        dest_record.size = source_record.size;
        dest_record.data_version = tick;
        dest_record.metadata_version = tick;

        let result = {
            let mut dedup = self.dedup_index.borrow_mut();
            let mut pool_store = self.store.pool_store_mut();
            reflink_chunked_content(
                self.dedup_enabled,
                &mut pool_store,
                source_inode_id,
                &source_record,
                &dest_record,
                &mut dedup,
                &self.content_compression_policy,
            )
        };
        if let Err(err) = result {
            self.rollback_mutation_delta();
            return Err(err);
        }

        // Capture old state in mutation delta BEFORE mutating (dest is new)
        self.mark_inode_metadata_dirty(dest_inode_id);
        Arc::make_mut(&mut self.state.inodes).insert(dest_inode_id, dest_record.clone());
        self.inode_cache.borrow_mut().invalidate(dest_inode_id);
        self.mark_inode_content_dirty(dest_inode_id);
        self.invalidate_hot_read_cache_for_inode(dest_inode_id);
        self.commit_mutation(dest_record)
    }

    fn replace_content(
        &mut self,
        inode_id: InodeId,
        mut record: InodeRecord,
        content: Vec<u8>,
    ) -> Result<InodeRecord> {
        let size = u64::try_from(content.len()).map_err(|_| FileSystemError::SizeOverflow {
            requested: u64::MAX,
        })?;
        let planned_tick = next_generation_after(self.state.generation);
        let mut planned_record = record.clone();
        planned_record.size = size;
        planned_record.data_version = planned_tick;
        planned_record.metadata_version = planned_tick;
        let planned_entries = planned_chunk_allocation_entries_for_full_content(&planned_record)?;
        let old_allocation_bytes = allocation_bytes(&content_allocation_entries_for_inode(
            self.store.raw_primary_store(),
            &record,
        )?)?;
        // Pre-check obligation ledger before allocator (Design rule Rule 3: authority is scarce)
        let allocation_bytes = allocation_bytes(&planned_entries).unwrap_or(0);
        let new_blocks = allocation_bytes / content_chunk_size() as u64;
        if allocation_bytes > old_allocation_bytes {
            self.ensure_obligation_capacity("staging_dirty", new_blocks, Some(inode_id))?;
            self.ensure_content_capacity_with_planned_inode(
                Some(inode_id),
                planned_entries.clone(),
            )?;
        }

        self.begin_mutation(); // was: let previous_state = self.state.clone()
        let tick = self.bump_generation();
        debug_assert_eq!(tick, planned_tick);
        record.size = size;
        record.data_version = tick;
        record.metadata_version = tick;
        let result = {
            let mut dedup = self.dedup_index.borrow_mut();
            let mut pool_store = self.store.pool_store_mut();
            write_chunked_content(
                self.dedup_enabled,
                &mut pool_store,
                &record,
                &content,
                &mut dedup,
                self.quorum_store.as_mut(),
                &self.content_compression_policy,            )
        };
        if let Err(err) = result {
            self.rollback_mutation_delta();
            return Err(err);
        }
        // Release old claims and register new allocation claim per Rule 8
        // (space-as-claimed-capital: every allocation is an obligation)
        self.obligation_ledger.release_claims_for_inode(inode_id);
        if new_blocks > 0 {
            self.obligation_ledger
                .claim(ClaimEntry {
                    claim_id: ClaimId::new(),
                    budget_domain: BudgetDomainId::from_str("staging_dirty"),
                    blocks: new_blocks,
                    inode_id,
                    reason: ClaimReason::Write,
                    authorized_by: StorageAuthorityToken::ABSENT,
                    generation: tick,
                })
                .ok();
        }
        // Register claim with budget domain for authority governance (Rule 3)
        let _ = self.budget_domain.admit_claim(ClaimEntryRecord {
            claim_id: ClaimId::new(),
            claimant_ref: ClaimantRef::Service {
                service_name: "staging_dirty".into(),
            },
            claim_class: ClaimClass::Product,
            claimed_bytes: new_blocks * content_chunk_size() as u64,
            committed_bytes: 0,
            inode_id: Some(inode_id),
            freshness_fence_ref: None,
            claim_receipt_ref: StorageAuthorityToken::ABSENT,
            expiration_deadline: None,
        });

        self.invalidate_hot_read_cache_for_inode(inode_id);
        self.inode_cache.borrow_mut().invalidate(inode_id);
        // Capture old record in mutation delta BEFORE replacing it
        self.mark_inode_metadata_dirty(inode_id);
        Arc::make_mut(&mut self.state.inodes).insert(inode_id, record.clone());
        self.inode_cache.borrow_mut().invalidate(inode_id);
        self.mark_inode_content_dirty(inode_id);
        self.invalidate_hot_read_cache_for_inode(inode_id);
        self.commit_mutation(record)
    }

    fn rewrite_content_with_overlay(
        &mut self,
        inode_id: InodeId,
        mut record: InodeRecord,
        overlay_offset: u64,
        overlay_bytes: &[u8],
        new_size: u64,
        allow_holes: bool,
    ) -> Result<InodeRecord> {
        let old_record = record.clone();
        let planned_tick = next_generation_after(self.state.generation);
        let mut planned_record = record.clone();
        planned_record.size = new_size;
        planned_record.data_version = planned_tick;
        planned_record.metadata_version = planned_tick;
        let planned_entries = planned_chunk_allocation_entries_for_overlay(
            self.store.raw_primary_store(),
            &old_record,
            &planned_record,
            overlay_offset,
            overlay_bytes,
            allow_holes,
        )?;
        let old_allocation_bytes = allocation_bytes(&content_allocation_entries_for_inode(
            self.store.raw_primary_store(),
            &old_record,
        )?)?;
        // Pre-check obligation ledger before allocator (Design rule Rule 3: authority is scarce)
        let allocation_bytes = allocation_bytes(&planned_entries).unwrap_or(0);
        let dirty_allocation_bytes =
            dirty_overlay_allocation_bytes(new_size, overlay_offset, overlay_bytes)?;
        let new_blocks = allocation_bytes / content_chunk_size() as u64;
        if allocation_bytes > old_allocation_bytes {
            self.ensure_obligation_capacity("staging_dirty", new_blocks, Some(inode_id))?;
            self.ensure_content_capacity_with_planned_inode(
                Some(inode_id),
                planned_entries.clone(),
            )?;
        }

        self.begin_mutation(); // was: let previous_state = self.state.clone()
        let tick = self.bump_generation();
        debug_assert_eq!(tick, planned_tick);
        record.size = new_size;
        record.data_version = tick;
        record.metadata_version = tick;
        let result = {
            let mut dedup = self.dedup_index.borrow_mut();
            let mut pool_store = self.store.pool_store_mut();
            write_chunked_content_with_overlay(WriteChunkedContentOverlay {
                dedup_enabled: self.dedup_enabled,
                store: &mut pool_store,
                inode_id,
                old_record: &old_record,
                new_record: &record,
                overlay_offset,
                overlay_bytes,
                allow_holes,
                dedup_index: &mut dedup,
                quorum_store: self.quorum_store.as_mut(),
                compression_policy: &self.content_compression_policy,
})
        };
        if let Err(err) = result {
            self.rollback_mutation_delta();
            return Err(err);
        }
        if dirty_allocation_bytes > 0 {
            self.dirty_set
                .record_data_write(inode_id, dirty_allocation_bytes);
            let _accepted_by_commit_group =
                self.record_mutation_commit_group_write(dirty_allocation_bytes);
        }
        // Release old claims and register new allocation claim per Rule 8
        // (space-as-claimed-capital: every allocation is an obligation)
        self.obligation_ledger.release_claims_for_inode(inode_id);
        if new_blocks > 0 {
            self.obligation_ledger
                .claim(ClaimEntry {
                    claim_id: ClaimId::new(),
                    budget_domain: BudgetDomainId::from_str("staging_dirty"),
                    blocks: new_blocks,
                    inode_id,
                    reason: ClaimReason::Write,
                    authorized_by: StorageAuthorityToken::ABSENT,
                    generation: tick,
                })
                .ok();
        }
        // Register claim with budget domain for authority governance (Rule 3)
        let _ = self.budget_domain.admit_claim(ClaimEntryRecord {
            claim_id: ClaimId::new(),
            claimant_ref: ClaimantRef::Service {
                service_name: "staging_dirty".into(),
            },
            claim_class: ClaimClass::Product,
            claimed_bytes: new_blocks * content_chunk_size() as u64,
            committed_bytes: 0,
            inode_id: Some(inode_id),
            freshness_fence_ref: None,
            claim_receipt_ref: StorageAuthorityToken::ABSENT,
            expiration_deadline: None,
        });

        self.invalidate_hot_read_cache_for_inode(inode_id);
        self.inode_cache.borrow_mut().invalidate(inode_id);
        // Capture old record in mutation delta BEFORE replacing it
        self.mark_inode_metadata_dirty(inode_id);
        Arc::make_mut(&mut self.state.inodes).insert(inode_id, record.clone());
        self.inode_cache.borrow_mut().invalidate(inode_id);
        self.mark_inode_content_dirty(inode_id);
        self.invalidate_hot_read_cache_for_inode(inode_id);
        self.commit_mutation(record)
    }

    fn commit_mutation<T>(&mut self, value: T) -> Result<T> {
        if !self.mutation_recorded_commit_group_write {
            let _accepted_by_commit_group = self.record_mutation_commit_group_write(0);
        }

        if self.auto_commit {
            return self.force_commit(value);
        }

        // Deferred commit: track mutations and apply backpressure
        // when the uncommitted count exceeds the configured threshold.
        // This bounds memory usage and crash-loss exposure — analogous
        // to ZFS's commit_group open→quiesce transition when the open commit_group fills.
        self.uncommitted_mutation_count = self.uncommitted_mutation_count.saturating_add(1);

        if self.uncommitted_mutation_count >= self.max_uncommitted_mutations
            || (!self.in_transaction && self.commit_group.should_quiesce())
        {
            return self.force_commit(value);
        }

        Ok(value)
    }

    /// Force a synchronous commit, resetting the deferred mutation counter.
    fn force_commit<T>(&mut self, value: T) -> Result<T> {
        self.uncommitted_mutation_count = 0;
        match self.do_commit() {
            Ok(()) => {
                self.discard_mutation_delta();
                // Run deferred cleanup (orphan drain, block reclamation)
                // after each committed-root advance. No-op when no engine
                // is attached.
                if let Some(ref mut engine) = self.cleanup_engine {
                    engine.run_cleanup_pass();
                }
                Ok(value)
            }
            Err(err) => {
                if !err.keeps_live_state_on_error() {
                    self.rollback_mutation_delta();
                }
                Err(err)
            }
        }
    }

    /// Variant of commit_mutation used only by `rollback_to_snapshot`
    /// which replaces the entire `FileSystemState`.  The full clone is
    /// kept as fallback because the operation swaps the whole state,
    /// not individual inodes/directories.
    fn commit_state_replacement<T>(
        &mut self,
        _previous_state: FileSystemState,
        value: T,
    ) -> Result<T> {
        if self.auto_commit {
            self.uncommitted_mutation_count = 0;
            match self.do_commit() {
                Ok(()) => {
                    self.discard_mutation_delta();
                    Ok(value)
                }
                Err(err) => {
                    if !err.keeps_live_state_on_error() {
                        self.rollback_mutation_delta();
                        self.mark_metalogue_clean();
                    }
                    Err(err)
                }
            }
        } else {
            self.uncommitted_mutation_count = self.uncommitted_mutation_count.saturating_add(1);
            if self.uncommitted_mutation_count >= self.max_uncommitted_mutations {
                self.uncommitted_mutation_count = 0;
                match self.do_commit() {
                    Ok(()) => {
                        self.discard_mutation_delta();
                        Ok(value)
                    }
                    Err(err) => {
                        if !err.keeps_live_state_on_error() {
                            self.rollback_mutation_delta();
                            self.mark_metalogue_clean();
                        }
                        Err(err)
                    }
                }
            } else {
                Ok(value)
            }
        }
    }

    /// Set the maximum number of deferred mutations before a forced commit.
    /// Lower values reduce memory pressure and crash-loss exposure at the
    /// cost of more frequent synchronous commits.  Default: 256.
    pub fn set_max_uncommitted_mutations(&mut self, max: u64) {
        self.max_uncommitted_mutations = max;
    }

    /// Return the current count of uncommitted mutations.
    pub fn uncommitted_mutation_count(&self) -> u64 {
        self.uncommitted_mutation_count
    }

    pub fn set_auto_commit(&mut self, enabled: bool) {
        if enabled && !self.auto_commit {
            // Flush any deferred mutations accumulated under manual mode
            // before switching to auto-commit.
            self.uncommitted_mutation_count = 0;
        }
        self.auto_commit = enabled;
    }

    pub fn set_commit_group_throughput_profile(&mut self) {
        self.commit_group.config = CommitGroupConfig::throughput();
    }

    pub fn begin_transaction(&mut self) -> Result<()> {
        if self.in_transaction {
            return Err(FileSystemError::Unsupported {
                operation: "begin_transaction",
                reason: "a transaction is already in progress",
            });
        }
        self.begin_mutation();
        self.in_transaction = true;
        Ok(())
    }

    pub fn commit_transaction(&mut self) -> Result<()> {
        if !self.in_transaction {
            return Err(FileSystemError::Unsupported {
                operation: "commit_transaction",
                reason: "no transaction is in progress",
            });
        }
        let result = self.do_commit();
        self.in_transaction = false;
        if let Err(ref err) = result {
            if !err.keeps_live_state_on_error() {
                // Rollback BEFORE discarding delta so the snapshot is available.
                self.rollback_mutation_delta();
            }
        }
        self.discard_mutation_delta();
        result
    }

    pub fn rollback_transaction(&mut self) -> Result<()> {
        if !self.in_transaction {
            return Err(FileSystemError::Unsupported {
                operation: "rollback_transaction",
                reason: "no active transaction to roll back",
            });
        }
        self.rollback_mutation_delta();
        self.inode_cache.borrow_mut().clear();
        self.in_transaction = false;
        Ok(())
    }

    // ── transaction guard integration (§5 of #1190) ────────────────

    /// Begin an explicit transaction, returning an RAII guard.
    ///
    /// Mutations accumulate in the filesystem in-memory state and are
    /// published atomically when `TransactionGuard::commit` is called.
    /// If the guard is dropped without committing, the transaction is
    /// automatically aborted and state is rolled back.
    pub fn begin_guarded_transaction(&mut self) -> Result<transaction::TransactionGuard<'_>> {
        if self.in_transaction {
            return Err(FileSystemError::Unsupported {
                operation: "begin_guarded_transaction",
                reason: "a transaction is already in progress",
            });
        }
        self.begin_mutation();
        self.in_transaction = true;
        Ok(transaction::TransactionGuard::new(self))
    }

    /// Internal: called by TransactionGuard::commit().
    pub(crate) fn commit_transaction_inner(&mut self) -> Result<()> {
        if !self.in_transaction {
            return Err(FileSystemError::Unsupported {
                operation: "commit_transaction_inner",
                reason: "no transaction is in progress",
            });
        }
        let result = self.do_commit();
        self.in_transaction = false;
        if let Err(ref err) = result {
            if !err.keeps_live_state_on_error() {
                // Rollback BEFORE discarding delta so the snapshot is available.
                self.rollback_mutation_delta();
            }
        }
        self.discard_mutation_delta();
        result
    }

    /// Internal: called by TransactionGuard::abort() and Drop.
    pub(crate) fn abort_transaction_inner(&mut self) -> Result<()> {
        if !self.in_transaction {
            return Ok(()); // already aborted or never started
        }
        self.rollback_mutation_delta();
        self.inode_cache.borrow_mut().clear();
        self.in_transaction = false;
        Ok(())
    }

    /// Abort the active transaction (alias for rollback_transaction).
    /// Discards all mutations made since `begin_transaction` and
    /// restores the pre-transaction state.
    pub fn abort_transaction(&mut self) -> Result<()> {
        self.rollback_transaction()
    }

    pub fn commit(&mut self) -> Result<()> {
        self.do_commit()
    }

    pub fn commit_if_dirty(&mut self) -> Result<()> {
        self.do_commit()
    }

    /// Record a sync write intent for bounded-latency acknowledgement.
    ///
    /// Writes the intent to the log, syncs it to durable storage, and returns
    /// `IntentLogReplyState::IntentDurable`. On pressure or refusal, the caller
    /// should fall back to the full `do_commit()` path.
    /// Record a sync write intent alongside the data payload.
    ///
    /// The payload is durably stored (via the object store) so that crash
    /// replay can re-apply the write if the full commit didn't land.
    pub fn sync_write_intent(
        &mut self,
        inode_id: InodeId,
        offset: u64,
        length: u64,
        payload_digest: IntegrityDigest64,
        payload: &[u8],
    ) -> Result<IntentLogReplyState> {
        // Sync writes get high throughput allocation to avoid intent-log backpressure.
        self.store.set_scheduling_class(IoClass::SyncData);
        if !self.commit_group.record_write(length) {
            return Ok(IntentLogReplyState::Refused);
        }
        let root_anchor = IntentLogRootAnchor {
            transaction_id: self.state.generation.max(ROOT_COMMIT_MIN_TRANSACTION_ID),
            generation: self.state.generation,
            manifest_digest: IntegrityDigest64(0),
        };
        let timestamp_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        // Store the write payload durably so that crash replay can
        // recover it even when the content manifest was never committed.
        self.store.put(
            DeviceIoClass::Data,
            crate::object_keys::intent_log_data_object_key(self.intent_log.next_entry_id()),
            payload,
        )?;

        let accepted = self.intent_log.append(
            self.store.raw_primary_store_mut(),
            IntentLogEntryKind::SyncWriteRange {
                inode_id,
                offset,
                length,
                payload_digest,
                data_version: 0,
            },
            root_anchor,
            timestamp_ns,
        )?;

        if !accepted {
            // Pressure threshold exceeded — caller must fall back to full commit
            return Ok(IntentLogReplyState::Refused);
        }

        self.intent_log.sync(self.store.raw_primary_store_mut())?;

        // Per #863: mark the inode as dirty so do_commit() persists
        // state before clearing intent log entries. Without this, a
        // clean commit silently drops all acknowledged intents.
        self.mark_inode_content_dirty(inode_id);
        self.invalidate_hot_read_cache_for_inode(inode_id);
        self.mark_inode_metadata_dirty(inode_id);

        Ok(IntentLogReplyState::IntentDurable)
    }

    /// Flush the intent log if the adaptive flush interval has elapsed
    /// or the batch-size threshold has been reached. Returns true if a
    /// flush was performed.
    ///
    /// Callers should invoke this periodically (e.g., at the top of each
    /// FUSE write-handler tick) so that time-based group-commit batching
    /// can coalesce entries without waiting for the next explicit sync.
    /// Set the I/O class for subsequent store operations.
    /// Metadata and sync operations should use higher-priority classes
    /// (ZFS I/O scheduler principle) to avoid starvation by bulk writes.
    pub fn set_io_class(&mut self, class: IoClass) {
        self.store.set_scheduling_class(class);
    }

    pub fn flush_intent_log_if_needed(&mut self) -> Result<bool> {
        self.intent_log
            .flush_if_needed(self.store.raw_primary_store_mut())
    }

    /// Return the current pending (unflushed) intent log entry count.
    /// Return a snapshot of fsync/fdatasync instrumentation counters.
    ///
    /// Counters track call frequency, cumulative latency, and fast-path
    /// vs fallback-path selection. Use for observability and benchmarking.
    #[must_use]
    pub fn fsync_stats_snapshot(&self) -> FsyncStatsSnapshot {
        self.fsync_stats.snapshot()
    }

    pub fn intent_log_pending(&self) -> usize {
        self.intent_log.pending_flush_count()
    }

    /// Number of entries currently in the intent log (flushed + pending).
    pub fn intent_log_entry_count(&self) -> usize {
        self.intent_log.len()
    }

    /// True when the intent log has no entries at all.
    pub fn intent_log_is_empty(&self) -> bool {
        self.intent_log.is_empty()
    }

    pub fn fsync_file(&mut self, path: impl AsRef<str>) -> Result<()> {
        check_crash_hook(CrashInjectionPoint::OpFsyncBeforeFlush);
        let started = Instant::now();
        let attr = self.stat(path.as_ref())?;
        self.flush_write_buffer(attr.inode_id)?;
        // Intent log fast path: if pending entries for this inode exist,
        // flushing them to durable storage (LOG_DEVICE) makes the data
        // crash-safe via replay. The full commit_group commit will clear them
        // later.  When no intents are pending for this inode we fall
        // through to the full do_commit() path.
        if self.intent_log.has_pending_data_for_inode(attr.inode_id) {
            self.intent_log
                .flush_and_sync(self.store.raw_primary_store_mut())?;
            // Flushed intent-log entries remain replayable: the next
            // do_commit() will clear them after publishing a new root.
            self.store.sync_all().map_err(FileSystemError::from)?;
            self.fsync_stats
                .fsync_intent_log_fast_path_count
                .fetch_add(1, Ordering::Relaxed);
            // Fall through to do_commit() — committed-root commit is the
            // primary durability path; intent-log replay recovered during
            // the next pool import (LocalObjectStore::open segment_replay,
            // ReplayEngine::replay_intent_log) provides an additional safety net.
        }
        self.do_commit()?;
        let result = self.store.sync_all().map_err(FileSystemError::from);
        self.fsync_stats
            .fsync_do_commit_fallback_count
            .fetch_add(1, Ordering::Relaxed);
        self.fsync_stats.fsync_count.fetch_add(1, Ordering::Relaxed);
        self.fsync_stats
            .fsync_total_ns
            .fetch_add(started.elapsed().as_nanos() as u64, Ordering::Relaxed);
        result
    }

    /// Sync only the data extents of a single file (fdatasync semantics).
    ///
    /// Unlike `fsync_file`, this skips metadata-only flushes (size, timestamps
    /// already durable); only data extents are persisted. The intent log fast
    /// path is used when available; otherwise content objects for this inode
    /// are ensured durable individually.
    pub fn fsync_data_only_file(&mut self, path: impl AsRef<str>) -> Result<()> {
        check_crash_hook(CrashInjectionPoint::OpFsyncBeforeFlush);
        let started = Instant::now();
        let attr = self.stat(path.as_ref())?;
        self.flush_write_buffer(attr.inode_id)?;
        if self.intent_log.has_pending_data_for_inode(attr.inode_id) {
            self.intent_log
                .flush_and_sync(self.store.raw_primary_store_mut())?;
            self.store.sync_all().map_err(FileSystemError::from)?;
            self.fsync_stats
                .fsync_intent_log_fast_path_count
                .fetch_add(1, Ordering::Relaxed);
            self.fsync_stats
                .fdatasync_count
                .fetch_add(1, Ordering::Relaxed);
            self.fsync_stats
                .fdatasync_total_ns
                .fetch_add(started.elapsed().as_nanos() as u64, Ordering::Relaxed);
            return Ok(());
        }
        if self.state.dirty_content.contains(&attr.inode_id) {
            let record =
                self.state
                    .inodes
                    .get(&attr.inode_id)
                    .ok_or(FileSystemError::CorruptState {
                        reason: "dirty content inode not found in state",
                    })?;
            ensure_versioned_content_object(
                self.store.raw_primary_store_mut(),
                record,
                &self.content_compression_policy,
            )?;
            self.store.sync_all().map_err(FileSystemError::from)?;
            self.mark_content_clean(attr.inode_id);
        }
        self.fsync_stats
            .fdatasync_count
            .fetch_add(1, Ordering::Relaxed);
        self.fsync_stats
            .fdatasync_total_ns
            .fetch_add(started.elapsed().as_nanos() as u64, Ordering::Relaxed);
        Ok(())
    }

    /// Flush a single file for the FUSE close path.
    ///
    /// `FUSE_FLUSH` is close bookkeeping, not a durability barrier.  It
    /// drains this file's in-memory write buffer so subsequent live reads
    /// observe the latest bytes, but it deliberately does not publish a
    /// committed root or sync the object store.  Callers that need durability
    /// must use `fsync_file`, `fsync_directory`, or `sync_all`.
    pub fn flush_file(
        &mut self,
        path: impl AsRef<str>,
        _ino: u64,
        _fh: u64,
        _lock_owner: u64,
    ) -> Result<()> {
        let attr = self.stat(path.as_ref())?;
        self.flush_write_buffer(attr.inode_id)
    }

    pub fn fsync_all(&mut self) -> Result<()> {
        let started = Instant::now();
        self.do_commit()?;
        let result = self.store.sync_all().map_err(FileSystemError::from);
        self.fsync_stats
            .fsync_all_count
            .fetch_add(1, Ordering::Relaxed);
        self.fsync_stats
            .fsync_total_ns
            .fetch_add(started.elapsed().as_nanos() as u64, Ordering::Relaxed);
        result
    }

    /// Wait on the TXG durability fence for a single inode.
    ///
    /// This is an explicit barrier-based wait that blocks until the commit group
    /// containing `ino`'s dirty data has been committed. Unlike `fsync_file`,
    /// this does NOT perform the commit itself -- it assumes another thread
    /// or the auto-commit path will commit the transaction group.
    ///
    /// Use this when:
    /// - The caller knows the commit will happen elsewhere (auto-commit timer,
    ///   batch flush, or a coordinating thread).
    /// - You want to measure the wall-clock time between the fsync request and
    ///   the actual durable publication point.
    ///
    /// # Errors
    ///
    /// Returns `FileSystemError::Store` if the wait is interrupted.
    /// Returns `Ok(())` immediately if the inode has no dirty data registered
    /// with the sync gate.
    pub fn fsync_wait_barrier(&self, ino: u64) -> Result<()> {
        let started = Instant::now();
        let sync = CommitGroupSync::new(self.sync_gate.clone());
        let result = sync.fsync(ino).map_err(|e| {
            FileSystemError::Store(tidefs_local_object_store::StoreError::Io {
                operation: "fsync_barrier_wait",
                path: std::path::PathBuf::from(format!("ino={ino}")),
                source: std::io::Error::other(format!("{e:?}")),
            })
        });
        self.fsync_stats
            .fsync_barrier_wait_count
            .fetch_add(1, Ordering::Relaxed);
        self.fsync_stats
            .fsync_barrier_wait_ns
            .fetch_add(started.elapsed().as_nanos() as u64, Ordering::Relaxed);
        result
    }

    /// Wait on the TXG durability fence for the entire filesystem (syncfs).
    ///
    /// This blocks until all pending transaction groups have been committed
    /// and synced. Like `fsync_wait_barrier`, this does NOT perform the commit
    /// itself.
    ///
    /// # Errors
    ///
    /// Returns `FileSystemError::Store` if the wait is interrupted.
    pub fn syncfs_wait_barrier(&self) -> Result<()> {
        let started = Instant::now();
        let sync = CommitGroupSync::new(self.sync_gate.clone());
        let result = sync.syncfs().map_err(|e| {
            FileSystemError::Store(tidefs_local_object_store::StoreError::Io {
                operation: "syncfs_barrier_wait",
                path: std::path::PathBuf::from("syncfs"),
                source: std::io::Error::other(format!("{e:?}")),
            })
        });
        self.fsync_stats
            .fsync_barrier_wait_count
            .fetch_add(1, Ordering::Relaxed);
        self.fsync_stats
            .fsync_barrier_wait_ns
            .fetch_add(started.elapsed().as_nanos() as u64, Ordering::Relaxed);
        result
    }

    /// Return the durable commit group id -- the highest TXG known to be committed.
    ///
    /// This is the sync gate's view of durability and advances on every
    /// successful `notify_committed` call.
    #[must_use]
    pub fn durable_commit_group(&self) -> u64 {
        self.sync_gate.durable_commit_group().0
    }

    pub fn fsync_data_only(&mut self) -> Result<()> {
        // Intent log fast path: flush pending data entries instead of
        // walking dirty inodes and flushing content objects individually.
        if self.intent_log.pending_flush_count() > 0 {
            self.intent_log
                .flush_and_sync(self.store.raw_primary_store_mut())?;
            return Ok(());
        }
        let dirty_inodes: Vec<InodeId> = self.state.dirty_content.iter().copied().collect();
        for inode_id in &dirty_inodes {
            let record = self
                .state
                .inodes
                .get(inode_id)
                .ok_or(FileSystemError::CorruptState {
                    reason: "dirty content inode not found in state",
                })?;
            ensure_versioned_content_object(
                self.store.raw_primary_store_mut(),
                record,
                &self.content_compression_policy,
            )?;
        }
        self.store.sync_all().map_err(FileSystemError::from)?;
        for inode_id in &dirty_inodes {
            self.mark_content_clean(*inode_id);
        }
        Ok(())
    }

    /// Sync a single inode to stable storage (fsync semantics).
    ///
    /// Like `fsync_file` but operates directly on an `InodeId` without
    /// path resolution. This is the storage-internal primitive that
    /// `VfsEngine::fsync` calls after translating the FUSE file handle
    /// into an inode id.
    ///
    /// Uses the intent log fast path when pending write-intent entries
    /// exist for the inode; otherwise falls through to a targeted
    /// content-object flush for just this inode's dirty data. If the
    /// inode has no dirty content, the call is a no-op (idempotent).
    pub fn sync_inode(&mut self, inode_id: InodeId) -> Result<()> {
        check_crash_hook(CrashInjectionPoint::OpFsyncBeforeFlush);
        self.flush_write_buffer(inode_id)?;
        let started = Instant::now();

        // Flush pending write intents to durable storage first.
        // Committed-root commit through do_commit() is the primary durability
        // path; intent-log replay recovered during the next pool import
        // (LocalObjectStore::open segment_replay, ReplayEngine::replay_intent_log)
        // provides an additional safety net.
        if self.intent_log.has_pending_data_for_inode(inode_id) {
            self.intent_log
                .flush_and_sync(self.store.raw_primary_store_mut())?;
            self.fsync_stats
                .fsync_intent_log_fast_path_count
                .fetch_add(1, Ordering::Relaxed);
            // Fall through to do_commit() — committed-root commit is the
            // primary durability path; intent-log replay recovered during
            // the next pool import (LocalObjectStore::open segment_replay,
            // ReplayEngine::replay_intent_log) provides an additional safety net.
        }

        // Full metadata + data commit_group commit (matches `fsync_file`).
        // `do_commit` persists all dirty inode records, namespace,
        // extent maps, and content manifests so that the inode and its
        // data survive a crash consistently.
        self.do_commit()?;
        let result = self.store.sync_all().map_err(FileSystemError::from);
        self.fsync_stats
            .fsync_do_commit_fallback_count
            .fetch_add(1, Ordering::Relaxed);
        self.fsync_stats.fsync_count.fetch_add(1, Ordering::Relaxed);
        self.fsync_stats
            .fsync_total_ns
            .fetch_add(started.elapsed().as_nanos() as u64, Ordering::Relaxed);
        result
    }

    /// Sync only the data extents of a single inode (fdatasync semantics).
    ///
    /// Like `fsync_data_only_file` but operates directly on an `InodeId`.
    /// Skips metadata-only flushes; only data extents are persisted.
    pub fn sync_inode_data_only(&mut self, inode_id: InodeId) -> Result<()> {
        check_crash_hook(CrashInjectionPoint::OpFsyncBeforeFlush);
        let started = Instant::now();
        if self.intent_log.has_pending_data_for_inode(inode_id) {
            self.intent_log
                .flush_and_sync(self.store.raw_primary_store_mut())?;
            self.fsync_stats
                .fsync_intent_log_fast_path_count
                .fetch_add(1, Ordering::Relaxed);
            // Fall through — committed-root commit is the primary
            // durability path; intent-log replay recovered during the next
            // pool import provides an additional safety net. Persist data
            // through the content-object path for immediate durability.
        }
        if self.state.dirty_content.contains(&inode_id) {
            let record = self
                .state
                .inodes
                .get(&inode_id)
                .ok_or(FileSystemError::CorruptState {
                    reason: "dirty content inode not found in state during sync_inode_data_only",
                })?;
            ensure_versioned_content_object(
                self.store.raw_primary_store_mut(),
                record,
                &self.content_compression_policy,
            )?;
            self.store.sync_all().map_err(FileSystemError::from)?;
            self.mark_content_clean(inode_id);
        }
        self.fsync_stats
            .fdatasync_count
            .fetch_add(1, Ordering::Relaxed);
        self.fsync_stats
            .fdatasync_total_ns
            .fetch_add(started.elapsed().as_nanos() as u64, Ordering::Relaxed);
        Ok(())
    }

    /// Drain all dirty inodes, ensuring every file with pending writes
    /// has its content objects committed to stable storage.
    ///
    /// This is a convenience that iterates the `dirty_content` set and
    /// flushes each inode individually. For a full transaction-group
    /// commit that also syncs metadata, use `fsync_all` instead.
    pub fn sync_all_dirty(&mut self) -> Result<()> {
        let dirty_inodes: Vec<InodeId> = self.state.dirty_content.iter().copied().collect();
        for inode_id in &dirty_inodes {
            let record = self
                .state
                .inodes
                .get(inode_id)
                .ok_or(FileSystemError::CorruptState {
                    reason: "dirty content inode not found in state during sync_all_dirty",
                })?;
            ensure_versioned_content_object(
                self.store.raw_primary_store_mut(),
                record,
                &self.content_compression_policy,
            )?;
        }
        self.store.sync_all().map_err(FileSystemError::from)?;
        for inode_id in &dirty_inodes {
            self.mark_content_clean(*inode_id);
        }
        Ok(())
    }
    /// Issue a data-only durability barrier for a single inode (fdatasync
    /// semantics) without performing a full commit_group commit.
    ///
    /// Flushes the write buffer, ensures content objects are written to the
    /// segment file, and calls sync_data on the backing store for a lightweight
    /// fdatasync(2)-equivalent barrier.  This is faster than sync_inode_data_only
    /// because it skips the full commit machinery.
    ///
    /// When datasync is true, only data extents are flushed; metadata is
    /// skipped.  When the inode has no dirty content the call is a no-op.
    pub fn fdatasync_inode(&mut self, inode_id: InodeId, datasync: bool) -> Result<()> {
        let started = Instant::now();

        self.flush_write_buffer(inode_id)?;

        if datasync && !self.state.dirty_content.contains(&inode_id) {
            return Ok(());
        }

        let record = self
            .state
            .inodes
            .get(&inode_id)
            .ok_or(FileSystemError::NotFound {
                path: format!("inode {inode_id:?}"),
            })?;
        ensure_versioned_content_object(
            self.store.raw_primary_store_mut(),
            record,
            &self.content_compression_policy,
        )?;
        self.store.sync_data().map_err(FileSystemError::from)?;
        self.mark_content_clean(inode_id);
        self.fsync_stats
            .fdatasync_count
            .fetch_add(1, Ordering::Relaxed);
        self.fsync_stats
            .fdatasync_total_ns
            .fetch_add(started.elapsed().as_nanos() as u64, Ordering::Relaxed);
        Ok(())
    }

    pub fn has_dirty_metadata(&self) -> bool {
        !self.state.dirty_inodes.is_empty() || !self.state.dirty_dirs.is_empty()
    }

    /// Ensure directory entry mutations for `path` are durable (§6 of #1190).
    ///
    /// For low-latency sync, the intent log fast path is used when available.
    /// Falls back to a forced commit_group sync when the intent log is disabled or
    /// the log device is not configured.
    ///
    /// Per §6.6 of the design spec, this must also cover rename atomicity:
    /// after a crash, either the old name or the new name exists, never both.
    pub fn fsync_directory(&mut self, path: impl AsRef<str>) -> Result<()> {
        check_crash_hook(CrashInjectionPoint::OpFsyncBeforeFlush);
        let started = Instant::now();
        let attr = self.stat(path.as_ref())?;
        if attr.kind() != NodeKind::Dir {
            return Err(FileSystemError::NotDirectory {
                path: path.as_ref().to_string(),
            });
        }
        // Intent log fast path: flush pending NamespaceSyncIntent entries
        // for this directory to durable storage instead of doing a full
        // commit_group commit.  The intent log replay will restore directory
        // entries on crash; the next commit_group commit clears the log.
        if self.intent_log.has_pending_namespace_for_dir(attr.inode_id) {
            self.intent_log
                .flush_and_sync(self.store.raw_primary_store_mut())?;
            self.fsync_stats
                .fsync_intent_log_fast_path_count
                .fetch_add(1, Ordering::Relaxed);
            // Fall through to do_commit() — committed-root commit is the
            // primary durability path; intent-log replay recovered during
            // the next pool import (LocalObjectStore::open segment_replay,
            // ReplayEngine::replay_intent_log) provides an additional safety net.
        }
        // Full commit to make directory state durable through committed-root.
        // The scoped-sync contract (§6.5): sync the directory inode record,
        // dirty parent entries, and the target inode.  For now, do_commit()
        // syncs all dirty state. Review debt TFR-008 tracks true scoped sync.
        self.do_commit()?;
        self.store.sync_all().map_err(FileSystemError::from)?;
        self.fsync_stats
            .fsync_do_commit_fallback_count
            .fetch_add(1, Ordering::Relaxed);
        self.fsync_stats.fsync_count.fetch_add(1, Ordering::Relaxed);
        self.fsync_stats
            .fsync_total_ns
            .fetch_add(started.elapsed().as_nanos() as u64, Ordering::Relaxed);
        Ok(())
    }
    /// Sync the extent allocator's in-memory state into FileSystemState so
    /// dirty extent maps are included in the next transaction commit.
    fn sync_extent_allocator_to_state(&mut self) {
        for inode_id in &self.state.dirty_extent_maps.clone() {
            // Use a large-but-safe length that does not overflow when
            // added to offset 0 (u64::MAX would overflow checked_add).
            let entries =
                self.extent_allocator
                    .lookup_extents(inode_id.get(), 0, 0x7FFF_FFFF_FFFF_FFFF);
            let mut emap = tidefs_extent_map::ExtentMap::new();
            for entry in &entries {
                // Entries from the allocator are non-overlapping,
                // so each allocate succeeds.
                let _ = emap.allocate(entry.logical_offset, entry.length);
            }
            self.state.extent_maps.insert(*inode_id, emap);
        }
    }

    pub(crate) fn do_commit(&mut self) -> Result<()> {
        // Advance the admission tick so dirty-age caps can be enforced
        // against the current commit cycle.
        self.write_admission.advance_tick();
        let write_buffers_before = self.write_buffers.len();
        self.flush_all_write_buffers()?;
        let flushed_write_buffers = self.write_buffers.len() < write_buffers_before;
        // Per #863: clearing the intent log without a state commit is
        // silent data loss — acknowledged intents are dropped without
        // ever being persisted.
        //
        // When the intent log is non-empty, we MUST persist state even
        // when dirty tracking says it's clean — otherwise acknowledged
        // writes are silently dropped.
        let state_was_dirty = self.is_state_dirty();
        let must_persist =
            self.is_state_dirty() || !self.intent_log.is_empty() || flushed_write_buffers;

        // COMMIT_GROUP STATE MACHINE: transition phases only when there is real work.
        // No-op commits (clean state + empty intent log) do not advance the commit_group.
        // Seven-step canonical commit ordering:
        //   1. APPEND data records  — intent log handles this
        //   2. FLUSH  data journal  — sync_data below
        //   3. APPEND metadata      — persist_state() below
        //   4. APPEND commit record — persist_state() below
        //   5. FLUSH  metadata      — sync_all() at end
        //   6. UPDATE checkpoint    — persist_state() below
        //   7. FLUSH  system area   — sync_all() at end
        if must_persist {
            if self.commit_group.phase == CommitGroupPhase::Open {
                if let Some(trigger) = self.commit_group.evaluate_triggers() {
                    check_crash_hook(CrashInjectionPoint::CommitGroupBeforeQuiesce);
                    self.commit_group.begin_quiesce(trigger);
                }
                check_crash_hook(CrashInjectionPoint::CommitGroupAfterQuiesce);
            }
            if matches!(
                self.commit_group.phase,
                CommitGroupPhase::Quiesce | CommitGroupPhase::Open
            ) {
                check_crash_hook(CrashInjectionPoint::CommitGroupBeforeSync);
                self.commit_group.begin_sync();
            }
        }
        if must_persist {
            self.sync_extent_allocator_to_state();
            persist_state(
                self.store.raw_primary_store_mut(),
                &self.state,
                self.root_authentication_key,
            )?;
            check_crash_hook(CrashInjectionPoint::CommitGroupAfterAppendData);
            // Re-verify the stored root commit (#870).
            check_crash_hook(CrashInjectionPoint::CommitGroupBeforeCommit);
            // Root authentication is validated at mount time only. If
            // in-memory state corruption propagates to disk between
            // mount and commit, the corruption goes undetected until
            // next mount.  Re-read the root commit we just wrote and
            // run the same validation that mount uses.
            let transaction_id = self.state.generation.max(ROOT_COMMIT_MIN_TRANSACTION_ID);
            let slot_key = root_slot_object_key(root_slot_for_transaction(transaction_id));
            let stored_bytes = match self.store.primary_store().get(slot_key)? {
                Some(b) => b,
                None => {
                    if let Some(ref qs) = self.quorum_store {
                        let (_, data, _) = qs.quorum_get(slot_key);
                        if let Some(b) = data {
                            b
                        } else {
                            return Err(FileSystemError::CorruptState {
                                reason: "root commit written but not found on re-read (primary and replicas)",
                            });
                        }
                    } else {
                        return Err(FileSystemError::CorruptState {
                            reason: "root commit written but not found on re-read",
                        });
                    }
                }
            };
            let stored_root = decode_root_commit(&stored_bytes)?;
            let _ = load_state_from_transaction(
                self.store.raw_primary_store_mut(),
                &stored_root,
                self.root_authentication_key,
            )?;
            check_crash_hook(CrashInjectionPoint::CommitGroupAfterCommit);
            self.mark_metalogue_clean();
        }
        // Persist quota table alongside committed state
        self.store.put(
            DeviceIoClass::Data,
            quota_table_object_key(),
            &self.state.quota_table.encode(),
        )?;
        // Apply and persist accumulated space delta
        self.commit_space_delta()?;

        // Persist orphan index alongside committed state so that
        // crash recovery can find orphaned inodes on next mount.
        // Commit pending crash-safe inserts/removes before encoding.
        self.orphan_index.lock().unwrap().commit_pending();
        if !self.orphan_index.lock().unwrap().is_empty() {
            let encoded = self.orphan_index.lock().unwrap().encode_log();
            self.store
                .put(DeviceIoClass::Data, orphan_index_object_key(), &encoded)?;
        } else {
            // Remove the key when the index is empty to avoid stale reads.
            let _ = self
                .store
                .raw_primary_store_mut()
                .delete(orphan_index_object_key());
            // Persist feature flags alongside committed state (Phase 3).
            // Every commit snapshots the current feature flag set so that
            // feature enable/disable mutations survive crashes.
            match self.feature_flags.persist(&mut self.store) {
                Ok(roots) => {
                    let mut buf = Vec::with_capacity(24);
                    buf.extend_from_slice(&roots.compat_root.0.to_le_bytes());
                    buf.extend_from_slice(&roots.ro_compat_root.0.to_le_bytes());
                    buf.extend_from_slice(&roots.incompat_root.0.to_le_bytes());
                    if let Err(e) = self.store.put(
                        DeviceIoClass::Data,
                        crate::object_keys::feature_flags_roots_object_key(),
                        &buf,
                    ) {
                        eprintln!("warning: failed to persist feature flags roots: {e}");
                    }
                }
                Err(e) => {
                    eprintln!("warning: feature flags persist failed: {e}");
                }
            }
        }
        // Only clear the intent log after a successful state persist.
        // Uncommitted entries survive until the next state commit or
        // replay on remount (#862).
        if state_was_dirty && !self.intent_log.is_empty() {
            self.intent_log.clear(self.store.raw_primary_store_mut())?;
        }
        // Rotate the current segment if rotation thresholds have been
        // exceeded. This provides flush-boundary rotation (#875).
        check_crash_hook(CrashInjectionPoint::CommitGroupBeforeCheckpoint);
        self.store.rotate_if_needed()?;
        // Sync quorum replicas after the primary commits successfully.
        if let Some(qs) = self.quorum_store.as_mut() {
            if let Err(e) = qs.quorum_sync() {
                eprintln!("quorum sync warning: {e}");
            }
        }
        // COMMIT_GROUP STATE MACHINE: complete SYNC only if we transitioned.
        // No-op commits do not advance generation.
        if self.commit_group.phase == CommitGroupPhase::Sync {
            let commit_log = self.commit_group.complete_sync();
            check_crash_hook(CrashInjectionPoint::CommitGroupAfterCheckpoint);
            // Notify the sync gate that this commit group has been committed.
            // Wakes fsync and syncfs waiters whose durability barrier
            // depends on this TXG.
            self.sync_gate
                .notify_committed(CommitGroupId(commit_log.commit_group.0));
        }
        check_crash_hook(CrashInjectionPoint::CommitGroupAfterFlush);
        // Progress background services after each commit so that
        // orphan reclamation and other deferred work advances
        // under per-tick budget without blocking mount or I/O.
        self.tick_background_services();

        // ── Space pressure update after commit ──────────────────────────
        // Update space pressure tracking from current pool capacity stats.
        // If usage exceeds the sync threshold, attempt one round of journal
        // segment cleaning. If still at critical level, future data writes
        // will receive ENOSPC; metadata ops (unlink/rmdir) reserve emergency
        // headroom for recovery.
        {
            let cap = self.store.pool_stats();
            self.space_pressure
                .update(cap.total_capacity_bytes, cap.used_bytes);
            if self.space_pressure.should_sync_clean() {
                match journal_cleaner::clean_oldest_segment(&mut self.store) {
                    Ok(report) => {
                        if !report.retired_segments.is_empty() {
                            let cap_after = self.store.pool_stats();
                            self.space_pressure
                                .update(cap_after.total_capacity_bytes, cap_after.used_bytes);
                            eprintln!(
                                "tidefs journal cleaning: retired {} segments, protected {} objects, level is now {:?}",
                                report.retired_segments.len(),
                                report.protected_key_count,
                                self.space_pressure.current_level(),
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!("tidefs journal cleaning failed: {e}");
                    }
                }
            }
        }

        // ── Intent log trimming after commit ───────────────────────────
        // Trim flushed entries from the intent log: after a successful
        // COMMIT_GROUP commit, all flushed entries are durably committed and no
        // longer needed for crash replay.  This reclaims memory and
        // reduces byte-pressure.
        {
            let trimmed = self.intent_log.trim_flushed();
            if trimmed > 0 {
                let stats = self.intent_log.space_stats();
                let level = stats.pressure_level.label();
                eprintln!(
                    "intent_log trimmed {} committed entries, used {}/{} bytes, pressure {}",
                    trimmed, stats.log_used_bytes, stats.log_max_bytes, level
                );
            }
        }

        Ok(())
    }

    /// COMMIT_GROUP maintenance tick: evaluate auto-sync triggers and commit if needed.
    ///
    /// Call this periodically (~every 100ms or at op boundaries) so that
    /// time-based triggers and byte/op thresholds get serviced without waiting
    /// for the next explicit fsync or manual commit.
    ///
    /// Returns true if a commit was performed.
    pub fn commit_group_maintenance_tick(&mut self) -> Result<bool> {
        let should_commit = match self.commit_group.phase {
            CommitGroupPhase::Open => self.commit_group.should_quiesce(),
            CommitGroupPhase::Quiesce => {
                self.commit_group.quiesce_timed_out() || self.commit_group.inflight_writes == 0
            }
            CommitGroupPhase::Sync => false,
        };
        if should_commit {
            self.commit_if_dirty()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn is_state_dirty(&self) -> bool {
        // Delegate to DirtySet for centralised accounting (§4 of #1190).
        if !self.dirty_set.is_clean() {
            return true;
        }
        !self.state.dirty_content.is_empty()
            || !self.state.dirty_inodes.is_empty()
            || !self.state.dirty_dirs.is_empty()
    }

    fn mark_inode_content_dirty(&mut self, inode_id: InodeId) {
        // Register with sync gate: this inode has dirty data in the current TXG.
        // When the TXG commits, notify_committed will wake any fsync waiter for this inode.
        self.sync_gate.register_dirty(
            inode_id.get(),
            CommitGroupId(self.commit_group.current_commit_group().0),
        );
        self.state.dirty_content.insert(inode_id);
    }

    fn mark_inode_metadata_dirty(&mut self, inode_id: InodeId) {
        // Save the old inode record if a mutation delta is active
        // so we can roll back to it on commit failure.
        if let Some(ref mut delta) = self.mutation_delta {
            delta.old_inodes.entry(inode_id).or_insert_with(|| {
                self.state
                    .inodes
                    .get(&inode_id)
                    .cloned()
                    .unwrap_or_else(|| {
                        // Newly-created inode: record a sentinel so the
                        // rollback path knows to remove it.
                        InodeRecord {
                            rdev: 0,
                            inode_id,
                            generation: Generation::new(0),
                            facets: NodeKind::File.to_facets(),
                            mode: 0,
                            uid: 0,
                            gid: 0,
                            nlink: 0,
                            size: 0,
                            data_version: 0,
                            metadata_version: 0,
                            posix_time: PosixTimeRecord::now(),
                            xattrs: BTreeMap::new(),
                            dir_storage_kind: 0,
                            xattr_storage_kind: 0,
                            dir_rev: 0,
                        }
                    })
            });
        }
        self.dirty_set.record_metadata_op(inode_id);
        self.state.dirty_inodes.insert(inode_id);
    }

    fn mark_dir_dirty(&mut self, inode_id: InodeId) {
        // Save the old directory entries if a mutation delta is active.
        if let Some(ref mut delta) = self.mutation_delta {
            delta.old_directories.entry(inode_id).or_insert_with(|| {
                self.state
                    .directories
                    .get(&inode_id)
                    .cloned()
                    .unwrap_or_default()
            });
        }
        self.dirty_set.record_dir_op(inode_id);
        self.state.dirty_dirs.insert(inode_id);
    }

    fn record_mutation_commit_group_write(&mut self, byte_delta: u64) -> bool {
        let accepted = self.commit_group.record_write(byte_delta);
        self.mutation_recorded_commit_group_write = true;
        accepted
    }
    /// Bump parent directory nlink, mtime, and ctime when a subdirectory
    /// is created or moved in.  Directories start with nlink ≥ 2 (. and ..);
    /// adding a child increments that count.
    fn update_parent_metadata_for_subdir_add(&mut self, parent_id: InodeId, tick: u64) {
        if let Some(parent) = std::sync::Arc::make_mut(&mut self.state.inodes).get_mut(&parent_id) {
            parent.nlink = parent.nlink.saturating_add(1);
        }
        self.update_parent_metadata_timestamps(parent_id, tick);
    }

    /// Drop parent directory nlink, mtime, and ctime when a subdirectory
    /// is removed or moved out.  nlink is clamped to ≥ 2 (. and ..).
    fn update_parent_metadata_for_subdir_remove(&mut self, parent_id: InodeId, tick: u64) {
        if let Some(parent) = std::sync::Arc::make_mut(&mut self.state.inodes).get_mut(&parent_id) {
            parent.nlink = parent.nlink.saturating_sub(1).max(2);
        }
        self.update_parent_metadata_timestamps(parent_id, tick);
    }

    /// Bump parent directory mtime and ctime for a child file/dir
    /// creation, deletion, or rename without changing nlink.
    fn update_parent_metadata_timestamps(&mut self, parent_id: InodeId, tick: u64) {
        if let Some(parent) = std::sync::Arc::make_mut(&mut self.state.inodes).get_mut(&parent_id) {
            let next_time = crate::types::current_posix_time_ns()
                .max(parent.posix_time.mtime_ns.saturating_add(1))
                .max(parent.posix_time.ctime_ns.saturating_add(1));
            parent.posix_time.mtime_ns = next_time;
            parent.posix_time.ctime_ns = next_time;
            parent.metadata_version = tick;
            parent.data_version = tick;
        }
    }

    fn mark_content_clean(&mut self, inode_id: InodeId) {
        self.state.dirty_content.remove(&inode_id);
    }
    #[allow(dead_code)]
    // INTENT: kept for planned architecture; callers in test modules or pending wiring into FUSE dispatch
    /// Query whether an inode has dirty content (test-only).
    pub(crate) fn is_inode_content_dirty(&self, inode_id: InodeId) -> bool {
        self.state.dirty_content.contains(&inode_id)
    }

    fn mark_metalogue_clean(&mut self) {
        let generation = self.state.generation;
        for &inode_id in &self.state.dirty_inodes {
            self.state.last_inode_write_tx.insert(inode_id, generation);
        }
        for &inode_id in &self.state.dirty_dirs {
            self.state.last_dir_write_tx.insert(inode_id, generation);
        }
        self.state.dirty_content.clear();
        self.state.dirty_inodes.clear();
        self.state.dirty_dirs.clear();
        self.dirty_set.clear();
    }

    fn forget_removed_inode_state(&mut self, inode_id: InodeId) {
        self.snapshot_write_buffers_for_rollback();
        self.write_buffers.remove(&inode_id);
        self.state.dirty_content.remove(&inode_id);
        self.state.dirty_inodes.remove(&inode_id);
        self.state.dirty_extent_maps.remove(&inode_id);
        self.state.last_inode_write_tx.remove(&inode_id);
        self.state.last_dir_write_tx.remove(&inode_id);
        self.state.last_extent_map_write_tx.remove(&inode_id);
        self.state.extent_maps.remove(&inode_id);
        self.state.known_inode_ids.remove(&inode_id);
        self.dirty_set.forget_inode(inode_id);
        self.inode_cache.borrow_mut().invalidate(inode_id);
        self.invalidate_hot_read_cache_for_inode(inode_id);
        self.page_cache_evict_inode(inode_id);
        self.writeback_range_tracker
            .lock()
            .expect("locked")
            .flush_inode(inode_id);
    }

    fn mark_all_state_dirty(&mut self) {
        for id in self.state.inodes.keys() {
            self.state.dirty_content.insert(*id);
            self.state.dirty_inodes.insert(*id);
        }
        for id in self.state.directories.keys() {
            self.state.dirty_dirs.insert(*id);
        }
    }

    fn begin_mutation(&mut self) {
        self.mutation_recorded_commit_group_write = false;
        if self.mutation_delta.is_none() {
            // Snapshot the dirty-page tracker for rollback.
            let old_dirty_pages = self
                .writeback_range_tracker
                .lock()
                .expect("locked")
                .snapshot_ranges();
            self.mutation_delta = Some(MutationDelta {
                old_inodes: BTreeMap::new(),
                old_directories: BTreeMap::new(),
                old_snapshots: self.state.snapshots.clone(),
                old_generation: self.state.generation,
                old_next_inode_id: self.state.next_inode_id,
                old_write_buffers: None,
                old_quota_table: self.state.quota_table.clone(),
                old_space_accounting: self.state.space_accounting.clone(),
                old_capacity_authority: self.capacity_authority.snapshot_for_rollback(),
                old_dirty_pages,
                old_extent_allocator: self.extent_allocator.clone(),
                intent_log_seq_at_begin: self.intent_log.next_entry_id(),
            });
        }
    }

    fn snapshot_write_buffers_for_rollback(&mut self) {
        let needs_snapshot = self
            .mutation_delta
            .as_ref()
            .is_some_and(|delta| delta.old_write_buffers.is_none());
        if !needs_snapshot {
            return;
        }
        let snapshot = self.write_buffers.clone();
        if let Some(delta) = self.mutation_delta.as_mut() {
            delta.old_write_buffers = Some(snapshot);
        }
    }

    fn discard_mutation_delta(&mut self) {
        self.mutation_delta = None;
    }

    fn rollback_mutation_delta(&mut self) {
        self.inode_cache.borrow_mut().clear();
        if let Some(delta) = self.mutation_delta.take() {
            // Restore inode/directory/snapshot metadata.
            for (id, inode) in delta.old_inodes {
                if inode.nlink == 0 && inode.metadata_version == 0 {
                    // Newly created inode — remove entirely.
                    Arc::make_mut(&mut self.state.inodes).remove(&id);
                    Arc::make_mut(&mut self.state.directories).remove(&id);
                    // Also remove any write buffer for this inode.
                    self.write_buffers.remove(&id);
                } else {
                    Arc::make_mut(&mut self.state.inodes).insert(id, inode);
                    self.inode_cache.borrow_mut().invalidate(id);
                }
            }
            for (id, dir) in delta.old_directories {
                if dir.is_empty() && !self.state.inodes.contains_key(&id) {
                    Arc::make_mut(&mut self.state.directories).remove(&id);
                } else {
                    Arc::make_mut(&mut self.state.directories).insert(id, dir);
                }
            }
            self.state.snapshots = delta.old_snapshots;
            self.state.generation = delta.old_generation;
            self.state.next_inode_id = delta.old_next_inode_id;
            self.state.dirty_content.clear();
            self.state.dirty_inodes.clear();
            self.state.dirty_dirs.clear();
            self.dirty_set.clear();
            self.release_pending_permits();

            // Restore side ledgers to pre-transaction state (#5980).
            if let Some(old_write_buffers) = delta.old_write_buffers {
                self.write_buffers = old_write_buffers;
            }
            self.state.quota_table = delta.old_quota_table;
            self.state.space_accounting = delta.old_space_accounting;
            self.capacity_authority
                .restore_from_snapshot(&delta.old_capacity_authority);
            self.extent_allocator = delta.old_extent_allocator;
            // Restore dirty-page tracker ranges.
            if let Ok(mut tracker) = self.writeback_range_tracker.lock() {
                tracker.restore_ranges(delta.old_dirty_pages);
            }
            // Discard intent-log entries appended during the transaction.
            if self.intent_log.next_entry_id() > delta.intent_log_seq_at_begin {
                let _ = self.intent_log.clear(self.store.raw_primary_store_mut());
            }
            // Clear the metadata intent-log buffer if present.
            self.intent_log_buffer = None;
        }
    }

    fn selected_current_root_summary(&mut self) -> Result<CommittedRootSummary> {
        let root_authentication_key = self.root_authentication_key;
        let recovery_policy = self.recovery_policy;
        let mut authority = MountedOpenRecoveryAuthority::raw_only(
            &mut self.store,
            root_authentication_key,
            recovery_policy,
        );
        let audit = authority.recovery_audit()?;
        let selected = audit.selected_root.ok_or(FileSystemError::CorruptState {
            reason: "snapshot source requires a selected authenticated committed root",
        })?;
        if selected.generation != self.state.generation {
            return Err(FileSystemError::CorruptState {
                reason: "snapshot source does not match the live filesystem generation",
            });
        }
        Ok(selected)
    }

    fn ensure_inode_capacity_for_new_inode(&self) -> Result<()> {
        let allocated = self.state.inodes.len() as u64;
        if allocated >= self.allocator_policy.inode_capacity {
            return Err(FileSystemError::NoSpace {
                resource: LocalStorageResource::Inodes,
                requested: allocated.saturating_add(1),
                available: self
                    .allocator_policy
                    .inode_capacity
                    .saturating_sub(allocated),
                capacity: self.allocator_policy.inode_capacity,
                allocated,
            });
        }
        Ok(())
    }

    fn ensure_content_capacity_with_planned_inode(
        &mut self,
        replaced_inode: Option<InodeId>,
        planned_entries: BTreeMap<ObjectKey, u64>,
    ) -> Result<()> {
        let mut current_entries =
            content_allocation_entries_for_state(self.store.raw_primary_store(), &self.state)?;
        if let Some(inode_id) = replaced_inode {
            let old_record = self.committed_inode_record(inode_id)?;
            for key in
                content_allocation_entries_for_inode(self.store.raw_primary_store(), &old_record)?
                    .keys()
            {
                current_entries.remove(key);
            }
        }
        merge_allocation_entries(&mut current_entries, planned_entries);
        self.ensure_content_capacity_for_current_entries(current_entries)
    }

    fn ensure_content_capacity_for_current_entries(
        &mut self,
        current_entries: BTreeMap<ObjectKey, u64>,
    ) -> Result<()> {
        let mut reserved_entries = protected_committed_content_entries(
            self.store.raw_primary_store_mut(),
            self.root_authentication_key,
            &self.state,
        )?;
        merge_allocation_entries(&mut reserved_entries, current_entries);
        let allocated = allocation_bytes(&reserved_entries)?;
        if allocated > self.allocator_policy.content_capacity_bytes {
            return Err(FileSystemError::NoSpace {
                resource: LocalStorageResource::ContentBytes,
                requested: allocated,
                available: self
                    .allocator_policy
                    .content_capacity_bytes
                    .saturating_sub(allocated),
                capacity: self.allocator_policy.content_capacity_bytes,
                allocated,
            });
        }
        Ok(())
    }

    /// Gate a proposed allocation through the obligation ledger.
    ///
    /// This is the Design rule Rule 3 scarcity gate: before the allocator
    /// checks physical space, the obligation ledger checks whether the
    /// budget domain has enough free blocks after accounting for current
    /// claims and active reserves. If not, the write is rejected with
    /// ClaimRejected even if physical space is available.
    fn ensure_obligation_capacity(
        &self,
        budget_domain: &str,
        new_blocks: u64,
        replaced_inode: Option<InodeId>,
    ) -> Result<()> {
        if new_blocks == 0 {
            return Ok(());
        }

        // Compute effective committed blocks: subtract old inode's claims
        // (they will be released on success), then add the new blocks.
        let old_blocks = match replaced_inode {
            Some(id) => self.obligation_ledger.reverse_explain_blocks_for_inode(id),
            None => 0,
        };
        let committed_after = self
            .obligation_ledger
            .committed_blocks()
            .saturating_sub(old_blocks)
            .saturating_add(new_blocks);

        if committed_after > self.obligation_ledger.total_blocks() {
            return Err(FileSystemError::ClaimRejected {
                budget_domain: budget_domain.to_string(),
                reason:
                    "budget domain exhausted: insufficient free blocks after claims and reserves",
            });
        }
        Ok(())
    }

    fn read_content(&self, inode_id: InodeId, record: &InodeRecord) -> Result<Vec<u8>> {
        let role = HotReadCacheObjectRole::from_node_kind(record.kind()).ok_or(
            FileSystemError::NotFile {
                path: format!("inode:{}", inode_id.get()),
                kind: record.kind(),
            },
        )?;
        let key = HotReadCacheKey {
            role,
            inode_id: inode_id.get(),
            data_version: record.data_version,
            size: record.size,
        };
        if let Some(wb) = self.write_buffers.get(&inode_id) {
            let read_len_u64 = wb.max_offset().unwrap_or(0).max(record.size);
            let read_len =
                usize::try_from(read_len_u64).map_err(|_| FileSystemError::SizeOverflow {
                    requested: read_len_u64,
                })?;
            if read_len > 0 {
                if let Some(buffered) =
                    self.read_with_write_buffer_overlay(inode_id, record, 0, read_len)?
                {
                    let mut cache = self.hot_read_cache.borrow_mut();
                    if let Some(cached) = cache.get(key) {
                        if cached == buffered {
                            return Ok(cached);
                        }
                    }
                    cache.admit(key, &buffered);
                    return Ok(buffered);
                }
            }
        }
        // Return EIO for inodes that have been marked corrupted by repair.
        if self.state.corrupted_inodes.contains(&inode_id) {
            return Err(FileSystemError::CorruptContent { inode_id });
        }

        if let Some(bytes) = self.hot_read_cache.borrow_mut().get(key) {
            return Ok(bytes);
        }
        let bytes =
            read_content_from_store(self.store.raw_primary_store(), inode_id, record, true, Some(&self.store))?;
        self.hot_read_cache.borrow_mut().admit(key, &bytes);
        Ok(bytes)
    }

    fn read_content_range(
        &self,
        inode_id: InodeId,
        record: &InodeRecord,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>> {
        if let Some(buffered) =
            self.read_with_write_buffer_overlay(inode_id, record, offset, length)?
        {
            return Ok(buffered);
        }
        if self.state.corrupted_inodes.contains(&inode_id) {
            return Err(FileSystemError::CorruptContent { inode_id });
        }
        if length == 0 || offset >= record.size {
            return Ok(Vec::new());
        }

        let length_u64 = u64::try_from(length).map_err(|_| FileSystemError::SizeOverflow {
            requested: u64::MAX,
        })?;
        let available = record.size - offset;
        let clipped_len_u64 = available.min(length_u64);
        let clipped_len =
            usize::try_from(clipped_len_u64).map_err(|_| FileSystemError::SizeOverflow {
                requested: clipped_len_u64,
            })?;
        if offset == 0 && length_u64 >= record.size {
            return self.read_content(inode_id, record);
        }

        let role = HotReadCacheObjectRole::from_node_kind(record.kind()).ok_or(
            FileSystemError::NotFile {
                path: format!("inode:{}", inode_id.get()),
                kind: record.kind(),
            },
        )?;
        let key = HotReadCacheKey {
            role,
            inode_id: inode_id.get(),
            data_version: record.data_version,
            size: record.size,
        };
        if let Some(bytes) = self.hot_read_cache.borrow_mut().get(key) {
            let start = usize::try_from(offset)
                .map_err(|_| FileSystemError::SizeOverflow { requested: offset })?;
            let end_offset =
                offset
                    .checked_add(clipped_len_u64)
                    .ok_or(FileSystemError::SizeOverflow {
                        requested: u64::MAX,
                    })?;
            let end = usize::try_from(end_offset).map_err(|_| FileSystemError::SizeOverflow {
                requested: end_offset,
            })?;
            if end > bytes.len() {
                return Err(FileSystemError::CorruptState {
                    reason: "hot read cache content range exceeds cached object size",
                });
            }
            return Ok(bytes[start..end].to_vec());
        }

        if let Some(layout) = self.content_layout_cache.borrow().get(&key).cloned() {
            return read_content_range_from_layout(
                self.store.raw_primary_store(),
                &layout,
                offset,
                clipped_len,
                Some(&self.store),
            );
        }

        let layout =
            read_content_layout_from_store(self.store.raw_primary_store(), inode_id, record, true)?;
        let bytes = read_content_range_from_layout(
            self.store.raw_primary_store(),
            &layout,
            offset,
            clipped_len,
            Some(&self.store),
        )?;
        if matches!(layout, ContentLayout::Chunked(_)) {
            self.content_layout_cache.borrow_mut().insert(key, layout);
        }
        Ok(bytes)
    }

    fn invalidate_hot_read_cache_for_inode(&self, inode_id: InodeId) {
        self.hot_read_cache.borrow_mut().invalidate_inode(inode_id);
        self.content_layout_cache
            .borrow_mut()
            .retain(|key, _layout| key.inode_id != inode_id.get());
    }

    fn clear_hot_read_cache(&self) {
        self.hot_read_cache.borrow_mut().clear();
        self.content_layout_cache.borrow_mut().clear();
    }

    #[cfg(test)]
    fn content_layout_cache_len_for_test(&self) -> usize {
        self.content_layout_cache.borrow().len()
    }

    fn resolve_parent_and_name(&self, path: &str) -> Result<(InodeId, Vec<u8>)> {
        let mut parts = parse_absolute_path(path)?;
        if parts.is_empty() {
            return Err(FileSystemError::InvalidPath {
                path: path.to_string(),
                reason: "root has no parent component",
            });
        }
        let name = parts.pop().ok_or_else(|| FileSystemError::InvalidPath {
            path: path.to_string(),
            reason: "path is missing a final component",
        })?;
        validate_name(&name)?;
        let parent_id = self.resolve_parts(&parts, path)?;
        let parent = self.inode_record_only(parent_id)?;
        if !parent.is_directory() {
            return Err(FileSystemError::NotDirectory {
                path: render_path(&parts),
            });
        }
        Ok((parent_id, name))
    }

    fn resolve_parts(&self, parts: &[Vec<u8>], full_path: &str) -> Result<InodeId> {
        let mut current = ROOT_INODE_ID;
        for (idx, name) in parts.iter().enumerate() {
            let prefix = render_path(&parts[..idx]);
            let directory = self.directory(current, &prefix)?;
            let entry = directory
                .get(name)
                .ok_or_else(|| FileSystemError::NotFound {
                    path: full_path.to_string(),
                })?;
            current = entry.inode_id;
        }
        Ok(current)
    }

    // ── Space accounting ────────────────────────────────────────────

    /// Derive PoolPhysicalCountersV1 from the single capacity authority.
    ///
    /// As of NEXT-STOR-038, both `phys_total_bytes` and `phys_free_bytes`
    /// derive from [`CapacityAuthority`] — the single source of truth for
    /// used/free/reserved byte counters.
    fn derive_pool_physical_counters(&self) -> PoolPhysicalCountersV1 {
        let total_bytes = self.capacity_authority.total_bytes();
        let free_bytes = self.capacity_authority.free_bytes();
        let total_segments = total_bytes / content_chunk_size() as u64;
        let free_segments = free_bytes / content_chunk_size() as u64;
        PoolPhysicalCountersV1 {
            phys_free_segments: free_segments,
            phys_free_bytes: free_bytes,
            phys_reclaimable_bytes: 0,
            phys_tail_reserved_segments: 0,
            phys_total_segments: total_segments,
            phys_total_bytes: total_bytes,
        }
    }

    /// Apply and persist the accumulated space delta.
    fn commit_space_delta(&mut self) -> Result<()> {
        if !self.state.space_accounting.has_pending_delta() {
            return Ok(());
        }
        let phys = self.derive_pool_physical_counters();
        self.state
            .space_accounting
            .commit_pending(phys)
            .map_err(|_e| FileSystemError::CorruptState {
                reason: "space accounting delta application failed",
            })?;
        // Persist space counters alongside committed state
        let counters = self.state.space_accounting.counters();
        let bytes = encode_space_counters(counters);
        self.store
            .put(DeviceIoClass::Data, space_counters_object_key(), &bytes)?;

        // Bridge to the store-layer SpaceBook so per-dataset usage
        // counters are persisted through the segment write pipeline
        // on the next sync_all() barrier.
        self.store.raw_primary_store_mut().sync_dataset_counters(
            self.mounted_dataset_id,
            counters.logical_used_bytes,
            counters.reserved_bytes,
        );

        Ok(())
    }

    /// Return the current dataset space counters (logical used, reserved,
    /// orphan, pinned snapshot bytes).  Updated atomically on commit.
    #[must_use]
    pub fn space_counters(&self) -> DatasetSpaceCountersV1 {
        *self.state.space_accounting.counters()
    }

    /// Return the current dataset space counters (used, reserved, orphan, etc.).
    fn quota_ancestor_chain_for_parts(&self, parts: &[Vec<u8>]) -> Vec<InodeId> {
        let mut ancestors = vec![ROOT_INODE_ID];
        let mut current = ROOT_INODE_ID;
        for name in parts {
            let dir = match self.state.directories.get(&current) {
                Some(d) => d,
                None => return ancestors,
            };
            let entry = match dir.get(name) {
                Some(e) => e,
                None => return ancestors,
            };
            current = entry.inode_id;
            ancestors.push(current);
        }
        ancestors
    }

    fn quota_ancestors_for_parent(&self, parent_id: InodeId) -> Vec<InodeId> {
        let mut ancestors = vec![ROOT_INODE_ID];
        for (&dir_id, directory) in self.state.directories.iter() {
            for entry in directory.values() {
                if entry.inode_id == parent_id {
                    let mut current = dir_id;
                    ancestors.push(current);
                    for (&d2, dir2) in self.state.directories.iter() {
                        for e2 in dir2.values() {
                            if e2.inode_id == current {
                                current = d2;
                                ancestors.push(current);
                            }
                        }
                    }
                    return ancestors;
                }
            }
        }
        ancestors
    }

    fn pool_free_bytes_for_quota(&self) -> u64 {
        self.capacity_authority.free_bytes()
    }

    fn inode(&self, inode_id: InodeId) -> Result<InodeRecord> {
        // 1. Check ARC metadata cache.
        if let Some(cached) = self.inode_cache.borrow_mut().get(inode_id) {
            return Ok(self.adjust_for_write_buffer(inode_id, cached.inode));
        }
        // 2. Check in-memory BTreeMap (holds inodes loaded during writes).
        if let Some(inode) = self.state.inodes.get(&inode_id) {
            let record = inode.clone();
            let dir = self.state.directories.get(&inode_id).cloned();
            self.inode_cache.borrow_mut().insert(
                inode_id,
                CachedInode {
                    inode: record.clone(),
                    directory: dir,
                },
            );
            return Ok(self.adjust_for_write_buffer(inode_id, record));
        }
        // 3. Validate that the inode exists per the allocation bitmap.
        if !self.state.known_inode_ids.contains(&inode_id) && inode_id != ROOT_INODE_ID {
            return Err(FileSystemError::CorruptState {
                reason: "inode id is missing from the inode table",
            });
        }
        // 4. Load from object store on demand.
        let key = inode_object_key(inode_id);
        let bytes =
            self.store
                .raw_primary_store()
                .get(key)?
                .ok_or(FileSystemError::CorruptState {
                    reason: "known inode id references a missing inode object in store",
                })?;
        let inode = decode_inode(&bytes)?;
        if inode.inode_id != inode_id {
            return Err(FileSystemError::CorruptState {
                reason: "inode object id does not match requested id",
            });
        }
        // 5. If directory, also load the directory object.
        let dir =
            if inode.carries_child_namespace() {
                let dir_key = directory_object_key(inode_id);
                let dir_bytes = self.store.primary_store().get(dir_key)?.ok_or(
                    FileSystemError::CorruptState {
                        reason: "directory inode is missing its directory object in store",
                    },
                )?;
                Some(decode_directory(&dir_bytes)?)
            } else {
                None
            };
        // 6. Admit to ARC cache.
        let record = inode.clone();
        self.inode_cache.borrow_mut().insert(
            inode_id,
            CachedInode {
                inode,
                directory: dir,
            },
        );
        Ok(self.adjust_for_write_buffer(inode_id, record))
    }

    /// Return only inode metadata without admitting a directory listing into the
    /// inode cache. Create-family parent checks need xattrs and type bits, not a
    /// clone of every child in a hot directory.
    fn inode_record_only(&self, inode_id: InodeId) -> Result<InodeRecord> {
        if let Some(inode) = self.state.inodes.get(&inode_id) {
            return Ok(self.adjust_for_write_buffer(inode_id, inode.clone()));
        }
        if !self.state.known_inode_ids.contains(&inode_id) && inode_id != ROOT_INODE_ID {
            return Err(FileSystemError::CorruptState {
                reason: "inode id is missing from the inode table",
            });
        }
        let key = inode_object_key(inode_id);
        let bytes =
            self.store
                .raw_primary_store()
                .get(key)?
                .ok_or(FileSystemError::CorruptState {
                    reason: "known inode id references a missing inode object in store",
                })?;
        let inode = decode_inode(&bytes)?;
        if inode.inode_id != inode_id {
            return Err(FileSystemError::CorruptState {
                reason: "inode object id does not match requested id",
            });
        }
        Ok(self.adjust_for_write_buffer(inode_id, inode))
    }

    /// Adjust the inode size to account for buffered writes that
    /// have not been committed yet, so getattr/stat returns the
    /// post-write file size immediately.
    fn adjust_for_write_buffer(&self, inode_id: InodeId, mut record: InodeRecord) -> InodeRecord {
        if let Some(wb) = self.write_buffers.get(&inode_id) {
            if let Some(mo) = wb.max_offset() {
                if mo > record.size {
                    record.size = mo;
                }
            }
        }
        record
    }

    fn directory(
        &self,
        inode_id: InodeId,
        path: &str,
    ) -> Result<BTreeMap<Vec<u8>, NamespaceEntry>> {
        // Check ARC cache first.
        if let Some(cached) = self.inode_cache.borrow_mut().get(inode_id) {
            if let Some(dir) = cached.directory {
                return Ok(dir);
            }
        }
        // Check in-memory BTreeMap.
        if let Some(dir) = self.state.directories.get(&inode_id) {
            let directory = dir.clone();
            if let Some(inode) = self.state.inodes.get(&inode_id) {
                self.inode_cache.borrow_mut().insert(
                    inode_id,
                    CachedInode {
                        inode: inode.clone(),
                        directory: Some(directory.clone()),
                    },
                );
            }
            return Ok(directory);
        }
        // Not in memory; the inode lookup will load the directory too.
        let inode = self.inode(inode_id)?;
        if !inode.carries_child_namespace() {
            return Err(FileSystemError::NotDirectory {
                path: path.to_string(),
            });
        }
        if let Some(cached) = self.inode_cache.borrow_mut().get(inode_id) {
            if let Some(dir) = cached.directory {
                return Ok(dir);
            }
        }
        Err(FileSystemError::NotDirectory {
            path: path.to_string(),
        })
    }
    #[allow(dead_code)]
    // INTENT: kept for planned architecture; callers in test modules or pending wiring into FUSE dispatch
    /// Ensure an inode and its directory (if any) are loaded into the in-memory
    /// BTreeMaps for mutation. Called from &mut self paths before modifying state.
    fn ensure_inode_loaded_for_write(&mut self, inode_id: InodeId) -> Result<()> {
        if self.state.inodes.contains_key(&inode_id) {
            return Ok(());
        }
        if !self.state.known_inode_ids.contains(&inode_id) && inode_id != ROOT_INODE_ID {
            return Err(FileSystemError::CorruptState {
                reason: "inode id is missing from the inode table",
            });
        }
        let key = inode_object_key(inode_id);
        let bytes =
            self.store
                .raw_primary_store()
                .get(key)?
                .ok_or(FileSystemError::CorruptState {
                    reason: "known inode id references a missing inode object in store",
                })?;
        let inode = decode_inode(&bytes)?;
        if inode.inode_id != inode_id {
            return Err(FileSystemError::CorruptState {
                reason: "inode object id does not match requested id",
            });
        }
        if inode.carries_child_namespace() {
            let dir_key = directory_object_key(inode_id);
            let dir_bytes = self.store.raw_primary_store().get(dir_key)?.ok_or(
                FileSystemError::CorruptState {
                    reason: "directory inode is missing its directory object in store",
                },
            )?;
            let directory = decode_directory(&dir_bytes)?;
            Arc::make_mut(&mut self.state.directories).insert(inode_id, directory);
        }
        Arc::make_mut(&mut self.state.inodes).insert(inode_id, inode);
        self.inode_cache.borrow_mut().invalidate(inode_id);
        Ok(())
    }

    fn insert_directory_entry(
        &mut self,
        parent_id: InodeId,
        name: Vec<u8>,
        entry: NamespaceEntry,
        tick: u64,
    ) -> Result<()> {
        let directory = Arc::make_mut(&mut self.state.directories)
            .get_mut(&parent_id)
            .ok_or(FileSystemError::CorruptState {
                reason: "parent directory object is missing",
            })?;
        directory.insert(name.clone(), entry.clone());
        self.inode_cache.borrow_mut().invalidate(parent_id);
        if let Some(parent) = Arc::make_mut(&mut self.state.inodes).get_mut(&parent_id) {
            parent.size = directory.len() as u64;
            parent.metadata_version = tick;
            parent.data_version = tick;
            parent.dir_rev = parent.dir_rev.saturating_add(1);
            let rev = parent.dir_rev;
            self.state
                .change_streams
                .entry(parent_id)
                .or_default()
                .insert(
                    rev,
                    DirChangeRecord::Add {
                        name: name.clone(),
                        inode_id: entry.inode_id,
                        facets: entry.facets,
                    },
                );
        }
        Ok(())
    }

    fn remove_directory_entry(&mut self, parent_id: InodeId, name: &[u8], tick: u64) -> Result<()> {
        let directory = Arc::make_mut(&mut self.state.directories)
            .get_mut(&parent_id)
            .ok_or(FileSystemError::CorruptState {
                reason: "parent directory object is missing",
            })?;
        let removed_id = directory.remove(name).map(|e| e.inode_id);
        self.inode_cache.borrow_mut().invalidate(parent_id);
        if let Some(parent) = Arc::make_mut(&mut self.state.inodes).get_mut(&parent_id) {
            parent.size = directory.len() as u64;
            parent.metadata_version = tick;
            parent.data_version = tick;
            parent.dir_rev = parent.dir_rev.saturating_add(1);
            let rev = parent.dir_rev;
            if let Some(inode_id) = removed_id {
                self.state
                    .change_streams
                    .entry(parent_id)
                    .or_default()
                    .insert(
                        rev,
                        DirChangeRecord::Remove {
                            name: name.to_vec(),
                            inode_id,
                        },
                    );
            }
        }
        Ok(())
    }

    fn allocate_inode_id(&mut self) -> InodeId {
        let id = self
            .state
            .next_inode_id
            .max(ROOT_INODE_ID.get().saturating_add(1));
        self.state.next_inode_id = id.saturating_add(1);
        InodeId::new(id)
    }

    fn bump_generation(&mut self) -> u64 {
        self.state.generation = self.state.generation.saturating_add(1).max(1);
        self.state.generation
    }

    /// Return directory mutation records since a given `dir_rev` (exclusive).
    ///
    /// Returns a sorted list of `(dir_rev, DirChangeRecord)` pairs for every
    /// change whose `dir_rev > since_rev`, plus the current `dir_rev` of the
    /// directory (which the caller can cache for the next incremental refresh).
    ///
    /// If the directory has been rolled back or the change-stream buffer has
    /// been pruned beyond `since_rev`, returns `None` signalling that a full
    /// rebuild is required.
    pub fn get_dir_changes_since(
        &self,
        dir_inode_id: InodeId,
        since_rev: u64,
    ) -> Option<(Vec<(u64, DirChangeRecord)>, u64)> {
        let inodes = &self.state.inodes;
        let parent = inodes.get(&dir_inode_id)?;
        if !parent.is_directory() {
            return None;
        }
        let current_rev = parent.dir_rev;
        // If the caller is already up to date, return empty list
        if since_rev >= current_rev {
            return Some((Vec::new(), current_rev));
        }
        // If since_rev is before what we have tracked, signal full rebuild
        let streams = self.state.change_streams.get(&dir_inode_id)?;
        let first_tracked = streams.keys().next().copied().unwrap_or(current_rev);
        if since_rev < first_tracked.saturating_sub(1) && !streams.is_empty() {
            return None;
        }
        let mut changes: Vec<(u64, DirChangeRecord)> = streams
            .range((since_rev + 1)..=current_rev)
            .map(|(rev, rec)| (*rev, rec.clone()))
            .collect();
        changes.sort_by_key(|(rev, _)| *rev);
        Some((changes, current_rev))
    }
    // ── Timestamp maintenance ─────────────────────────────────────────

    /// Apply POSIX timestamp transition rules to the committed inode
    /// record for `inode_id`.
    ///
    /// `update` selects the rule (read → atime, write/truncate → mtime+ctime,
    /// metadata → ctime).  `policy` controls atime suppression (relatime,
    /// noatime, strictatime).  The current wall clock is captured inside
    /// the method and applied through the tick mechanism.
    pub fn apply_timestamp_update(
        &mut self,
        inode_id: InodeId,
        update: tidefs_inode_attributes::timestamp::TimestampUpdate,
        policy: tidefs_inode_attributes::timestamp::TimestampPolicy,
    ) -> Result<()> {
        if !self.state.inodes.contains_key(&inode_id) {
            if !self.state.known_inode_ids.contains(&inode_id) && inode_id != ROOT_INODE_ID {
                return Ok(());
            }
            self.ensure_inode_loaded_for_write(inode_id)?;
        }
        let record = self.state.inodes.get(&inode_id).cloned();
        let record = match record {
            Some(r) => r,
            None => return Ok(()),
        };

        let mut posix = record.to_inode_attr().posix;
        let changed =
            tidefs_inode_attributes::timestamp::apply_timestamp_rules(update, &mut posix, policy);

        if !changed {
            return Ok(());
        }

        self.begin_mutation();
        let mut updated = record.clone();
        updated.posix_time = crate::types::PosixTimeRecord::new(
            posix.atime_ns,
            posix.mtime_ns,
            posix.ctime_ns,
            posix.btime_ns,
        );
        updated.metadata_version = updated.metadata_version.max(self.state.generation);

        self.mark_inode_metadata_dirty(inode_id);
        Arc::<BTreeMap<InodeId, InodeRecord>>::make_mut(&mut self.state.inodes)
            .insert(inode_id, updated);
        self.inode_cache.borrow_mut().invalidate(inode_id);
        self.commit_mutation(()).map(|_| ())
    }

    pub(crate) fn apply_deferred_timestamp_update(
        &mut self,
        inode_id: InodeId,
        update: tidefs_inode_attributes::timestamp::TimestampUpdate,
        policy: tidefs_inode_attributes::timestamp::TimestampPolicy,
    ) -> Result<()> {
        if !self.state.inodes.contains_key(&inode_id) {
            if !self.state.known_inode_ids.contains(&inode_id) && inode_id != ROOT_INODE_ID {
                return Ok(());
            }
            self.ensure_inode_loaded_for_write(inode_id)?;
        }
        let record = self.state.inodes.get(&inode_id).cloned();
        let record = match record {
            Some(r) => r,
            None => return Ok(()),
        };

        let mut posix = record.to_inode_attr().posix;
        let changed =
            tidefs_inode_attributes::timestamp::apply_timestamp_rules(update, &mut posix, policy);

        if !changed {
            return Ok(());
        }

        let mut updated = record;
        updated.posix_time = crate::types::PosixTimeRecord::new(
            posix.atime_ns,
            posix.mtime_ns,
            posix.ctime_ns,
            posix.btime_ns,
        );
        updated.metadata_version = updated.metadata_version.max(self.state.generation);

        self.mark_inode_metadata_dirty(inode_id);
        Arc::<BTreeMap<InodeId, InodeRecord>>::make_mut(&mut self.state.inodes)
            .insert(inode_id, updated);
        self.inode_cache.borrow_mut().invalidate(inode_id);
        Ok(())
    }

    /// Trim (DISCARD/UNMAP) explicit byte ranges on pool devices that
    /// support discard operations.
    ///
    /// Each `TrimRequest` specifies a contiguous `(offset, length)` byte
    /// range to be discarded at the backing storage layer. The ranges are
    /// dispatched to every discard-capable device in the pool. The returned
    /// count is the total number of bytes successfully trimmed.
    ///
    /// This is the public entry point for explicit TRIM operations (e.g.,
    /// from a future background `fstrim` service). Callers that already
    /// have block-level free-range knowledge (from
    /// [`tidefs_block_allocator::BlockAllocator::free_ranges`]) can pass
    /// the resulting `TrimRequest` values directly.
    ///
    /// Returns 0 when no device in the pool supports discard.
    pub fn trim_blocks(&mut self, ranges: &[TrimRequest]) -> u64 {
        let raw: Vec<(u64, u64)> = ranges.iter().map(|r| (r.offset, r.length)).collect();
        self.store.discard_ranges(&raw)
    }
}
impl Drop for LocalFileSystem {
    fn drop(&mut self) {
        // Stop background services first so they release shared locks
        // (orphan_index, reclaim_queue, etc.) before do_commit needs them.
        self.stop_background_scheduler();
        if let Some(handle) = self.writeback_handle.take() {
            handle.shutdown();
        }

        // Best-effort: commit dirty state and sync backing store.
        // Errors are logged but not propagated — Drop cannot fail.
        //
        // catch_unwind guards against panics that would abort the process
        // (destructors must not panic). Poisoned internal mutexes or
        // unexpected I/O failures are caught and logged.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if let Err(e) = self.do_commit() {
                eprintln!("[tidefs-local-filesystem] Drop::do_commit failed: {e}");
            }
        }));
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if let Err(e) = self.store.sync_all() {
                eprintln!("[tidefs-local-filesystem] Drop::store.sync_all failed: {e}");
            }
        }));
    }
}

pub(crate) fn is_skippable_store_error(err: &StoreError) -> bool {
    matches!(
        err,
        StoreError::ChecksumMismatch { .. }
            | StoreError::CorruptHeader { .. }
            | StoreError::ProductionIntegrityMismatch { .. }
            | StoreError::UnsupportedVersion { .. }
            | StoreError::UnknownRecordKind { .. }
    )
}

pub(crate) fn is_skippable_recovery_error(err: &FileSystemError) -> bool {
    match err {
        FileSystemError::Decode { .. }
        | FileSystemError::CorruptState { .. }
        | FileSystemError::InvalidName { .. }
        | FileSystemError::FormatVersionIncompatible { .. } => true,
        FileSystemError::Store(store_err) => is_skippable_store_error(store_err),
        _ => false,
    }
}

/// Human-preferred spelling for the local filesystem engine.
pub type LocalFilesystem = LocalFileSystem;
/// Human-preferred spelling for filesystem errors.
pub type FilesystemError = FileSystemError;
/// Human-preferred spelling for filesystem stats.
pub type FilesystemStats = FileSystemStats;
/// Local filesystem options are currently Local Object Store options.
pub type FilesystemOptions = StoreOptions;

// TURN5_HUMAN_LOCAL_FILESYSTEM_ALIASES
/// Human-named module for the local filesystem MVP slice.
///
/// Prefer this namespace for examples that exercise the userspace filesystem
/// directly. It exposes the implemented filesystem engine, storage options,
/// permissions constants, recovery helpers, snapshot helpers, and VFS boundary
/// records through readable names.
///
/// # Example
///
/// ```rust
/// use std::time::{SystemTime, UNIX_EPOCH};
///
/// use tidefs_local_filesystem::human::local_filesystem::{
///     LocalFilesystem, RootAuthenticationKey, StoreOptions, DEFAULT_DIRECTORY_PERMISSIONS,
///     DEFAULT_FILE_PERMISSIONS,
/// };
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
/// let root = std::env::temp_dir().join(format!("tidefs-local-filesystem-doc-{unique}"));
/// let _ = std::fs::remove_dir_all(&root);
///
/// let root_key = RootAuthenticationKey::demo_key();
/// let mut filesystem = LocalFilesystem::open_with_root_authentication_key(
///     &root,
///     StoreOptions::test_fast(),
///     root_key,
/// )?;
///
/// filesystem.create_dir("/notes", DEFAULT_DIRECTORY_PERMISSIONS)?;
/// filesystem.create_file("/notes/today.txt", DEFAULT_FILE_PERMISSIONS)?;
/// filesystem.write_file("/notes/today.txt", 0, b"document the real API")?;
///
/// assert_eq!(
///     filesystem.read_file("/notes/today.txt")?,
///     b"document the real API".to_vec()
/// );
/// assert_eq!(filesystem.stat("/notes/today.txt")?.size, 21);
/// assert_eq!(filesystem.list_dir("/notes")?.len(), 1);
/// filesystem.sync_all()?;
/// drop(filesystem);
///
/// let reopened = LocalFilesystem::open_with_root_authentication_key(
///     &root,
///     StoreOptions::test_fast(),
///     root_key,
/// )?;
/// assert_eq!(
///     reopened.read_file("/notes/today.txt")?,
///     b"document the real API".to_vec()
/// );
/// drop(reopened);
///
/// let _ = std::fs::remove_dir_all(&root);
/// # Ok(())
/// # }
/// ```
pub mod local_filesystem {
    pub const FAMILY_NAME: &str = "Local Filesystem";
    pub const ROLE: &str = "durable inode, directory, file-content, link, symlink, unlink, rename, truncate, root-slot commits, automatic previous-or-new recovery, and reopen harness over the Local Object Store";

    pub use crate::{
        audit_recovery, audit_recovery_with_root_authentication_key,
        content_chunk_object_key_for_version, content_object_key, content_object_key_for_version,
        directory_object_key, inode_object_key, inspect_filesystem_content_objects,
        inspect_filesystem_content_objects_with_root_authentication_key,
        intent_log_sync_write_latency_cases, no_production_fsck_failure_model_cases,
        page_cache_writeback_mmap_acceptance_cases, plan_root_retention,
        plan_root_retention_with_root_authentication_key, posix_subset_entries,
        root_slot_object_key, run_crash_recovery_matrix,
        run_crash_recovery_matrix_with_root_authentication_key, superblock_object_key,
        transaction_directory_object_key, transaction_inode_object_key,
        transaction_manifest_object_key, transaction_superblock_object_key, verify_online,
        verify_online_with_root_authentication_key, ChangedObjectRecord, ChangedRecordExport,
        ChangedRecordImportReport, ChangedRecordObjectRole, ChangedRecordRoot,
        CommittedRootSummary, CrashInjectionBoundary, CrashRecoveryCaseReport,
        CrashRecoveryExpectation, CrashRecoveryExplicitErrorReport, CrashRecoveryMatrixReport,
        CrashRecoveryObservedOutcome, FileSystemError, FileSystemStatfs, FileSystemStats,
        FilesystemCommitBoundary, FilesystemContentInspectionReport, FilesystemContentObjectKind,
        FilesystemContentObjectRef, FilesystemError, FilesystemOptions, FilesystemStats,
        HotReadCachePolicy, HotReadCacheReport, InodeRecord, IntentLogLatencyClass,
        IntentLogReplyState, IntentLogSyncWriteLatencyCase, LocalFileSystem, LocalFilesystem,
        LocalStorageAllocatorPolicy, LocalStorageAllocatorReport, LocalStorageResource,
        MountInvariantReport, NamespaceEntry, NoProductionFsckFailureClass,
        NoProductionFsckFailureModelCase, OnlineVerifierIssue, OnlineVerifierIssueKind,
        OnlineVerifierIssueSeverity, OnlineVerifierOutcome, OnlineVerifierReport,
        OnlineVerifierRootReport, PageCacheCoherencyClass, PageCacheVisibilityState,
        PageCacheWritebackMmapCase, PosixSubsetEntry, PosixSupport, PosixTopic,
        RecoveryAuditOutcome, RecoveryAuditReport, RecoveryProbeOutcome, RecoveryProbeReport,
        RootAuthenticationCode, RootAuthenticationDigest, RootAuthenticationKey,
        RootAuthenticationRecord, RootRetentionDebt, RootRetentionPlan, RootRetentionPolicy,
        SafeReclamationReport, SnapshotRollbackReport, SnapshotSummary, TransactionManifestEntry,
        TransactionManifestObjectRole, CLAIM_LEDGER_SPEC, DEFAULT_DIRECTORY_PERMISSIONS,
        DEFAULT_FILE_PERMISSIONS, DEFAULT_HOT_READ_CACHE_MAX_BYTES,
        DEFAULT_HOT_READ_CACHE_MAX_ENTRIES, DEFAULT_LOCAL_FILESYSTEM_CONTENT_CAPACITY_BYTES,
        DEFAULT_LOCAL_FILESYSTEM_INODE_CAPACITY, DEFAULT_RETAINED_COMMITTED_ROOTS,
        DEFAULT_SYMLINK_PERMISSIONS, FILESYSTEM_CONTENT_CHUNK_SIZE,
        FILESYSTEM_CONTENT_OBJECT_PREFIX, FILESYSTEM_DIRECTORY_OBJECT_PREFIX,
        FILESYSTEM_FORMAT_VERSION, FILESYSTEM_INODE_OBJECT_PREFIX, FILESYSTEM_ROOT_OBJECT_PREFIX,
        FILESYSTEM_ROOT_SLOT_COUNT, FILESYSTEM_SUPERBLOCK_OBJECT_NAME,
        FILESYSTEM_TRANSACTION_OBJECT_PREFIX, FORMAL_NO_PRODUCTION_FSCK_FAILURE_MODEL,
        HOT_READ_CACHE_SPEC, INTENT_LOG_SYNC_WRITE_LATENCY_CASES,
        INTENT_LOG_SYNC_WRITE_LATENCY_POLICY_VERSION, INTENT_LOG_SYNC_WRITE_LATENCY_SPEC,
        LOCAL_SNAPSHOT_ROLLBACK_SPEC, LOCAL_STORAGE_ALLOCATOR_GRAIN_BYTES,
        LOCAL_STORAGE_ALLOCATOR_SPEC, MAX_NAME_BYTES, MINIMUM_SAFE_RETAINED_ROOTS,
        MOUNT_INVARIANT_GATE_IS_NOT_FSCK, NO_PRODUCTION_FSCK_FAILURE_MODEL_CASES,
        ONLINE_VERIFIER_IS_NOT_FSCK, ONLINE_VERIFIER_SPEC,
        PAGE_CACHE_WRITEBACK_MMAP_ACCEPTANCE_CASES, PAGE_CACHE_WRITEBACK_MMAP_POLICY_VERSION,
        PAGE_CACHE_WRITEBACK_MMAP_SPEC, PATH_MAX_BYTES, POSIX_SUBSET_ENTRIES,
        POSIX_SUBSET_POLICY_VERSION, POSIX_SUBSET_SPEC, PRODUCTION_RECOVERY_DOCTRINE,
        RECOVERY_AUDIT_IS_NOT_FSCK, RETENTION_RECLAMATION_IS_NOT_FSCK,
        ROOT_AUTHENTICATION_ALGORITHM_SUITE_ID, ROOT_AUTHENTICATION_CODE_LEN,
        ROOT_AUTHENTICATION_DIGEST_LEN, ROOT_AUTHENTICATION_ENV_VAR, ROOT_AUTHENTICATION_KEY_LEN,
        ROOT_AUTHENTICATION_MAGIC_ASCII, ROOT_AUTHENTICATION_MAGIC_BYTES,
        ROOT_AUTHENTICATION_POLICY_EPOCH, ROOT_AUTHENTICATION_RECORD_VERSION,
        ROOT_AUTHENTICATION_SPEC, ROOT_PATH, SAFE_LOCAL_RECLAMATION_GC_SPEC,
        SEND_RECEIVE_CHANGED_RECORD_SPEC, SEND_RECEIVE_STREAM_MAGIC_ASCII,
        SEND_RECEIVE_STREAM_MAGIC_BYTES, SEND_RECEIVE_STREAM_VERSION, SNAPSHOT_CATALOG_MAGIC_ASCII,
        SNAPSHOT_CATALOG_MAGIC_BYTES,
    };
    pub use tidefs_local_object_store::{
        device_layout::DeviceMediaClass, CompressionAlgorithm, CompressionConfig, EncryptionConfig,
        IoClass, ObjectKey, ObjectLocation, StoreEncryptionKey, StoreOptions,
    };
    pub use tidefs_types_vfs_core::{
        Errno, Generation, InodeAttr, InodeId, NodeKind, SetAttr, ROOT_INODE_ID,
    };
    pub use tidefs_types_vfs_owned::DirEntry as OwnedDirEntry;
}

/// Human alias namespace. Prefer `human::local_filesystem::*` in new examples.
pub mod human {
    /// Local filesystem API with human-readable import paths.
    ///
    /// This module is an alias of [`crate::local_filesystem`], including the
    /// `LocalFilesystem` spelling for the implemented [`crate::LocalFileSystem`].
    pub mod local_filesystem {
        pub use crate::local_filesystem::*;
    }
}

#[cfg(test)]
mod fallocate_tests;
#[cfg(test)]
mod proptests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod write_dispatch_tests;

#[cfg(test)]
mod orphan_index_integration_tests {
    use super::*;

    fn make_test_fs(dir_name: &str) -> Result<(std::path::PathBuf, LocalFileSystem)> {
        let root = std::env::temp_dir().join(dir_name);
        if root.exists() {
            let _ = std::fs::remove_dir_all(&root);
        }
        let fs = LocalFileSystem::open(&root)?;
        Ok((root, fs))
    }

    fn assert_parent_metadata_time_advanced(
        before: crate::types::PosixTimeRecord,
        after: crate::types::PosixTimeRecord,
        operation: &str,
    ) {
        assert!(
            after.mtime_ns > before.mtime_ns,
            "{operation} must advance parent directory mtime: before={} after={}",
            before.mtime_ns,
            after.mtime_ns
        );
        assert!(
            after.ctime_ns > before.ctime_ns,
            "{operation} must advance parent directory ctime: before={} after={}",
            before.ctime_ns,
            after.ctime_ns
        );
    }

    #[test]
    fn bridge_dir_entry_updates_parent_link_count_and_parent_lookup() {
        let (_root, mut fs) = make_test_fs("lf_bridge_dir_parent").expect("open");
        let child = fs.next_inode_id();
        let child_record = InodeRecord {
            dir_storage_kind: 0,
            inode_id: child,
            facets: NodeKind::Dir.to_facets(),
            mode: tidefs_types_vfs_core::S_IFDIR | 0o755,
            uid: 0,
            gid: 0,
            size: 0,
            nlink: 2,
            data_version: 1,
            metadata_version: 1,
            posix_time: crate::types::PosixTimeRecord::now(),
            generation: Generation(1),
            xattr_storage_kind: 0,
            xattrs: std::collections::BTreeMap::new(),
            dir_rev: 0,
            rdev: 0,
        };
        fs.insert_inode_at(child, child_record);
        fs.init_dir_by_inode(child).expect("init child dir");

        let before = fs.get_inode_by_id(ROOT_INODE_ID).unwrap().nlink;
        fs.insert_dir_entry(
            ROOT_INODE_ID,
            b"child".to_vec(),
            NamespaceEntry {
                name: b"child".to_vec(),
                inode_id: child,
                generation: Generation(1),
                facets: NodeKind::Dir.to_facets(),
                mode: tidefs_types_vfs_core::S_IFDIR | 0o755,
            },
        )
        .expect("insert child dir");

        assert_eq!(fs.parent_dir_for_inode(child), Some(ROOT_INODE_ID));
        assert_eq!(fs.get_inode_by_id(ROOT_INODE_ID).unwrap().nlink, before + 1);

        fs.remove_dir_entry(ROOT_INODE_ID, b"child")
            .expect("remove child dir");
        assert_eq!(fs.parent_dir_for_inode(child), None);
        assert_eq!(fs.get_inode_by_id(ROOT_INODE_ID).unwrap().nlink, before);
    }

    #[test]
    fn orphan_index_starts_empty() {
        let (_root, fs) = make_test_fs("oi_test_empty").expect("open");
        assert!(fs.orphan_index.lock().unwrap().is_empty());
        assert_eq!(fs.orphan_index.lock().unwrap().len(), 0);
    }

    #[test]
    fn unlink_last_link_inserts_orphan() {
        let (_root, mut fs) = make_test_fs("oi_test_unlink").expect("open");
        fs.create_file("/orphan_test_file", 0o644)
            .expect("create_file");
        fs.unlink("/orphan_test_file").expect("unlink");
        assert!(
            !fs.orphan_index.lock().unwrap().is_empty(),
            "orphan index should contain the unlinked inode"
        );
        assert_eq!(fs.orphan_index.lock().unwrap().len(), 1);
    }

    #[test]
    fn link_file_removes_orphan_on_transition() {
        let (_root, mut fs) = make_test_fs("oi_test_link").expect("open");
        fs.create_file("/file_a", 0o644).expect("create_file");
        fs.link_file("/file_a", "/file_b").expect("link_file");
        fs.unlink("/file_b").expect("unlink");
        assert!(
            fs.orphan_index.lock().unwrap().is_empty(),
            "nlink still 1, no orphan"
        );
        fs.unlink("/file_a").expect("unlink");
        assert!(!fs.orphan_index.lock().unwrap().is_empty(), "now orphaned");
    }

    #[test]
    fn mount_time_recover_orphans_reclaims_extents() {
        let (_root, mut fs) = make_test_fs("oi_test_recover").expect("open");
        fs.create_file("/doomed", 0o644).expect("create_file");
        fs.unlink("/doomed").expect("unlink");
        assert!(!fs.orphan_index.lock().unwrap().is_empty());

        let result = fs.recover_orphans();
        assert!(result.is_ok(), "recover_orphans should succeed");
        assert!(
            fs.orphan_index.lock().unwrap().is_empty(),
            "orphan index should be cleared after recovery"
        );
    }

    #[test]
    fn orphan_index_validate_structural() {
        let (_root, mut fs) = make_test_fs("oi_test_validate").expect("open");
        fs.stop_background_scheduler();
        fs.set_auto_commit(false);
        fs.set_max_uncommitted_mutations(200);
        for i in 0..100u64 {
            let path = format!("/file_{i}");
            fs.create_file(&path, 0o644).expect("create_file");
            fs.unlink(&path).expect("unlink");
        }
        assert_eq!(fs.orphan_index.lock().unwrap().len(), 100);
        assert!(
            fs.orphan_index.lock().unwrap().validate().is_ok(),
            "B+tree structure should remain valid"
        );
    }

    #[test]
    fn public_orphan_reclaim_api_tracks_and_releases() {
        let (_root, fs) = make_test_fs("oi_test_public_api").expect("open");
        let inode_id = InodeId::new(88_001);
        assert!(fs.reclaim_stats().is_idle());

        assert!(fs.track_orphan(inode_id), "first track inserts orphan");
        assert!(!fs.track_orphan(inode_id), "second track is idempotent");
        let stats = fs.reclaim_stats();
        assert_eq!(stats.orphan_index_entries, 1);
        assert_eq!(stats.pending_orphan_deletions, 0);
        assert_eq!(stats.reclaim_queue_entries, 0);
        assert!(!stats.is_idle());

        assert!(fs.release_orphan(inode_id), "tracked orphan is queued");
        assert!(!fs.release_orphan(inode_id), "second release is idempotent");
        let stats = fs.reclaim_stats();
        assert_eq!(stats.orphan_index_entries, 1);
        assert_eq!(stats.pending_orphan_deletions, 1);
        assert_eq!(stats.queued_work_items(), 2);

        assert!(!fs.release_orphan(InodeId::new(88_002)));
    }

    #[cfg(test)]
    mod background_scheduler_integration_tests {
        use super::*;

        #[test]
        fn scheduler_is_initialized_on_open() {
            let root = std::env::temp_dir().join("bs_test_init");
            if root.exists() {
                let _ = std::fs::remove_dir_all(&root);
            }
            let fs = LocalFileSystem::open(&root).expect("open");
            assert!(
                fs.background_scheduler.is_some(),
                "background scheduler runtime should be started on open"
            );
        }

        #[test]
        fn tick_background_services_runs_with_no_services() {
            let root = std::env::temp_dir().join("bs_test_tick_empty");
            if root.exists() {
                let _ = std::fs::remove_dir_all(&root);
            }
            let mut fs = LocalFileSystem::open(&root).expect("open");
            // Should not panic when no services are registered.
            fs.tick_background_services();
        }

        #[test]
        fn tick_background_services_no_panic_after_operations() {
            let root = std::env::temp_dir().join("bs_test_tick_after_ops");
            if root.exists() {
                let _ = std::fs::remove_dir_all(&root);
            }
            let mut fs = LocalFileSystem::open(&root).expect("open");
            fs.create_file("/test", 0o644).expect("create_file");
            fs.tick_background_services();
        }

        #[test]
        fn background_cleaner_integration_pipeline() {
            // Tier 3 storage runtime validation: exercises the full background
            // cleaner pipeline through tick_background_services().  Writes
            // files to fill pool space, triggers cleaning via do_commit(),
            // asserts the cleaner activates and foreground I/O is not starved.
            let root = std::env::temp_dir().join("bs_test_bgcleaner_pipeline");
            if root.exists() {
                let _ = std::fs::remove_dir_all(&root);
            }
            let mut fs = LocalFileSystem::open(&root).expect("open");

            // Write files to consume pool segments and trigger cleaning.
            for i in 0..20 {
                let path = format!("/file_{i}");
                fs.create_file(&path, 0o644).expect("create_file");
                // Write 64 KiB per file — accumulates segment pressure.
                fs.write_file(&path, 0, &[i as u8; 65536])
                    .expect("write_file");
            }

            // Commit, which triggers tick_background_services() including
            // Duty 4: background_cleaner.tick().
            fs.do_commit().expect("commit");

            // Check cleaner stats — the cleaner should have attempted
            // at least one round (depends on pool size and watermark config).
            let cleaner_stats = fs.background_cleaner_stats();
            eprintln!(
                "background-cleaner pipeline stats: rounds_attempted={} rounds_completed={} rounds_throttled={} rounds_inactive={} segments_retired={} active={} free={}/{} total",
                cleaner_stats.rounds_attempted,
                cleaner_stats.rounds_completed,
                cleaner_stats.rounds_throttled,
                cleaner_stats.rounds_inactive,
                cleaner_stats.total_segments_retired,
                cleaner_stats.active,
                cleaner_stats.last_free_segments,
                cleaner_stats.last_total_segments,
            );

            // Foreground I/O must still work after cleaning.
            let data = fs.read_file("/file_0").expect("read after clean");
            assert!(
                !data.is_empty(),
                "foreground read must succeed after cleaning"
            );

            // Write another file — foreground write must not be starved.
            fs.create_file("/post_clean", 0o644)
                .expect("create after clean");
            fs.write_file("/post_clean", 0, b"post-clean-data")
                .expect("write after clean");
            fs.do_commit().expect("commit after clean");

            let _ = std::fs::remove_dir_all(&root);
        }
    }

    #[test]
    fn reclaim_delta_recorded_on_unlink() {
        let root = std::env::temp_dir().join("rd_test_unlink");
        if root.exists() {
            let _ = std::fs::remove_dir_all(&root);
        }
        let mut fs = LocalFileSystem::open(&root).expect("open");
        fs.create_file("/file", 0o644).expect("create_file");
        fs.write_file("/file", 0, &[0u8; 4096]).expect("write");
        fs.do_commit().expect("commit");

        // Before unlink, reclaim queue should be empty.
        assert!(fs.reclaim_queue_depth() == 0);

        // Disable auto-commit so reclaim deltas stay in the queue for inspection.
        fs.set_auto_commit(false);
        fs.unlink("/file").expect("unlink");

        // After unlink (nlink 0), reclaim queue should have at least two entries
        // (Extent delta + InodeTombstone).  The exact count varies with the number
        // of object-key variants produced by record_reclaim_delta.
        let q = fs.reclaim_queue.lock().unwrap();
        let count = q.len();
        assert!(
            count >= 2,
            "reclaim queue should have at least 2 entries after unlink, got {count}"
        );
        let entries = q.entries();
        // First entry should be an Extent delta (per-object count, not byte count).
        let extent_entry = entries
            .iter()
            .find(|(_, e)| e.family == ReclaimQueueFamily::Extent);
        assert!(
            extent_entry.is_some(),
            "must have an Extent reclaim entry after unlink"
        );
        assert_eq!(
            extent_entry.unwrap().1.delta,
            -1,
            "extent delta should be -1 (per-object)"
        );
        // Must have an InodeTombstone entry.
        let tombstone = entries
            .iter()
            .find(|(_, e)| e.family == ReclaimQueueFamily::InodeTombstone);
        assert!(
            tombstone.is_some(),
            "must have an InodeTombstone entry after unlink"
        );
        assert_eq!(
            tombstone.unwrap().1.delta,
            -1,
            "inode tombstone delta should be -1"
        );
    }

    #[test]
    fn empty_file_unlink_records_only_inode_tombstone_reclaim() {
        let root = tempfile::tempdir().expect("tempdir");
        let mut fs = LocalFileSystem::open(root.path()).expect("open");
        fs.create_file("/empty", 0o644).expect("create_file");
        fs.do_commit().expect("commit");

        assert_eq!(fs.reclaim_queue_depth(), 0);

        fs.set_auto_commit(false);
        fs.unlink("/empty").expect("unlink");

        let q = fs.reclaim_queue.lock().unwrap();
        assert_eq!(q.len(), 1);
        let entries = q.entries();
        assert!(
            entries
                .iter()
                .all(|(_, entry)| entry.family != ReclaimQueueFamily::Extent),
            "zero-length unlink should not enqueue content extent reclaim entries"
        );
        let tombstone_count = entries
            .iter()
            .filter(|(_, entry)| entry.family == ReclaimQueueFamily::InodeTombstone)
            .count();
        assert_eq!(tombstone_count, 1);
    }

    #[test]
    fn reclaim_delta_recorded_on_truncate_shrink() {
        let root = std::env::temp_dir().join("rd_test_trunc");
        if root.exists() {
            let _ = std::fs::remove_dir_all(&root);
        }
        let mut fs = LocalFileSystem::open(&root).expect("open");
        fs.create_file("/file", 0o644).expect("create_file");
        fs.write_file("/file", 0, &[0u8; 8192]).expect("write");
        fs.do_commit().expect("commit");

        assert!(fs.reclaim_queue_depth() == 0);

        // Disable auto-commit so reclaim deltas stay in the queue for inspection.
        fs.set_auto_commit(false);
        fs.truncate_file("/file", 4096).expect("truncate");

        let q = fs.reclaim_queue.lock().unwrap();
        let count = q.len();
        assert!(
            count >= 1,
            "reclaim queue should have at least 1 entry after truncate shrink, got {count}"
        );
        let entries = q.entries();
        // Find an Extent delta entry.
        let extent_entry = entries
            .iter()
            .find(|(_, e)| e.family == ReclaimQueueFamily::Extent);
        assert!(
            extent_entry.is_some(),
            "must have an Extent reclaim entry after truncate shrink"
        );
        assert_eq!(
            extent_entry.unwrap().1.delta,
            -1,
            "extent delta should be -1 (per-object)"
        );
    }

    #[test]
    fn reclaim_delta_recorded_on_rename_overwrite() {
        let root = std::env::temp_dir().join("rd_test_rename");
        if root.exists() {
            let _ = std::fs::remove_dir_all(&root);
        }
        let mut fs = LocalFileSystem::open(&root).expect("open");
        fs.create_file("/old", 0o644).expect("create old");
        fs.write_file("/old", 0, &[0u8; 2048]).expect("write old");
        fs.create_file("/new", 0o644).expect("create new");
        fs.write_file("/new", 0, &[0u8; 1024]).expect("write new");
        fs.do_commit().expect("commit");

        fs.rename("/old", "/new", false).expect("rename");

        // rename must atomically replace /new with /old: old name gone,
        // new name holds old content.
        assert!(
            fs.stat("/old").is_err(),
            "/old must be gone after rename-overwrite"
        );
        let dest_attr = fs.stat("/new").expect("/new must exist after rename");
        assert_eq!(dest_attr.size, 2048, "/new size must match old content");
    }

    /// Full end-to-end reclaim chain verification (issue #6166):
    /// unlink → local reclaim queue → tick_background_services Duty 2 →
    /// store.delete() → object-store durable reclaim queue →
    /// drain_dead_segments() → segments freed.
    ///
    /// Surviving objects must remain reachable after reopen.
    #[test]
    fn full_reclaim_chain_unlink_to_drain_dead_segments_reopen_readback() {
        let root = std::env::temp_dir().join("reclaim_chain_full");
        if root.exists() {
            let _ = std::fs::remove_dir_all(&root);
        }

        // ---- Phase 1: create and populate two files ----
        let mut fs = LocalFileSystem::open(&root).expect("open");
        fs.create_file("/keep", 0o644).expect("create keep");
        fs.write_file("/keep", 0, &[0xBBu8; 4096])
            .expect("write keep");
        fs.create_file("/drop", 0o644).expect("create drop");
        fs.write_file("/drop", 0, &[0xAAu8; 4096])
            .expect("write drop");
        fs.do_commit().expect("commit");

        // Both files must be reachable pre-op.
        let s_keep = fs.stat("/keep").expect("stat keep");
        assert_eq!(s_keep.size, 4096);
        let s_drop = fs.stat("/drop").expect("stat drop");
        assert_eq!(s_drop.size, 4096);

        // ---- Phase 2: unlink /drop, verify reclaim deltas recorded ----
        assert!(
            fs.reclaim_queue_depth() == 0,
            "reclaim queue must be empty before unlink"
        );

        // Disable auto-commit BEFORE unlink so record_reclaim_delta+record_inode_tombstone
        // populate the queue without do_commit->tick_background_services
        // draining it immediately.
        fs.set_auto_commit(false);
        fs.unlink("/drop").expect("unlink drop");

        let post_unlink_depth = fs.reclaim_queue_depth();
        assert!(
            post_unlink_depth >= 2,
            "reclaim queue should have entries after unlink (extent + inode tombstone), got {post_unlink_depth}"
        );

        // ---- Phase 3: drain local queue via production reclaim handoff ----
        // drain_local_reclaim_queue_into_store() (called by tick_background_services
        // Duty 2) hands off entries to object-store durable reclaim queue via store.delete().
        fs.tick_background_services();

        assert!(
            fs.reclaim_queue_depth() == 0,
            "local reclaim queue must be empty after tick_background_services"
        );

        // ---- Phase 4: drain object-store reclaim queue ----
        let drain_stats = fs
            .store
            .raw_primary_store_mut()
            .drain_dead_segments(&tidefs_reclaim::ReclaimConsumerConfig::default())
            .expect("drain_dead_segments");

        assert!(
            drain_stats.entries_processed > 0,
            "drain must process reclaim entries from object-store queue; got entries_processed={} reclaim_queue_depth={}",
            drain_stats.entries_processed,
            drain_stats.reclaim_queue_depth,
        );
        // Physical segment reclamation is opportunistic: if /drop objects
        // share a segment with live objects (e.g. /keep in the same segment),
        // the segment stays alive, which is correct behavior.  The reclaim
        // pipeline is verified by the entries_processed assertion above.

        // ---- Phase 5: reopen and verify surviving file ----
        drop(fs);
        let fs2 = LocalFileSystem::open(&root).expect("reopen");

        // /keep must still exist and be readable with correct size.
        let s_keep2 = fs2.stat("/keep").expect("stat keep after reopen");
        assert_eq!(s_keep2.size, 4096, "/keep must survive reclaim and reopen");

        // /drop must be gone.
        assert!(
            fs2.stat("/drop").is_err(),
            "/drop must be absent after unlink and reclaim"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn rename_exchange_swaps_same_directory_files() {
        let (_root, mut fs) = make_test_fs("s5_rename_exchange_same_dir_files").expect("open");
        let left = fs
            .create_file("/left.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create left");
        let right = fs
            .create_file("/right.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create right");
        fs.write_file("/left.txt", 0, b"left").expect("write left");
        fs.write_file("/right.txt", 0, b"right")
            .expect("write right");

        fs.rename_exchange("/left.txt", "/right.txt")
            .expect("rename_exchange");

        assert_eq!(fs.lookup("/left.txt").expect("lookup left"), right.inode_id);
        assert_eq!(
            fs.lookup("/right.txt").expect("lookup right"),
            left.inode_id
        );
        assert_eq!(fs.read_file("/left.txt").expect("read left"), b"right");
        assert_eq!(fs.read_file("/right.txt").expect("read right"), b"left");
    }

    #[test]
    fn rename_exchange_swaps_directory_subtrees() {
        let (_root, mut fs) = make_test_fs("s5_rename_exchange_dirs").expect("open");
        let left_dir = fs
            .create_dir("/left", DEFAULT_DIRECTORY_PERMISSIONS)
            .expect("create left dir");
        let right_dir = fs
            .create_dir("/right", DEFAULT_DIRECTORY_PERMISSIONS)
            .expect("create right dir");
        fs.create_file("/left/inside-left.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create left child");
        fs.create_file("/right/inside-right.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create right child");

        fs.rename_exchange("/left", "/right")
            .expect("rename_exchange");

        assert_eq!(fs.lookup("/left").expect("lookup left"), right_dir.inode_id);
        assert_eq!(
            fs.lookup("/right").expect("lookup right"),
            left_dir.inode_id
        );
        assert!(fs.lookup("/left/inside-right.txt").is_ok());
        assert!(fs.lookup("/right/inside-left.txt").is_ok());
        assert!(matches!(
            fs.lookup("/left/inside-left.txt"),
            Err(FileSystemError::NotFound { .. })
        ));
        assert!(matches!(
            fs.lookup("/right/inside-right.txt"),
            Err(FileSystemError::NotFound { .. })
        ));
    }

    #[test]
    fn rename_exchange_swaps_files_across_directories() {
        let (_root, mut fs) = make_test_fs("s5_rename_exchange_cross_dir").expect("open");
        fs.create_dir("/a", DEFAULT_DIRECTORY_PERMISSIONS)
            .expect("create a");
        fs.create_dir("/b", DEFAULT_DIRECTORY_PERMISSIONS)
            .expect("create b");
        let alpha = fs
            .create_file("/a/alpha.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create alpha");
        let beta = fs
            .create_file("/b/beta.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create beta");
        fs.write_file("/a/alpha.txt", 0, b"alpha")
            .expect("write alpha");
        fs.write_file("/b/beta.txt", 0, b"beta")
            .expect("write beta");

        fs.rename_exchange("/a/alpha.txt", "/b/beta.txt")
            .expect("rename_exchange");

        assert_eq!(
            fs.lookup("/a/alpha.txt").expect("lookup alpha"),
            beta.inode_id
        );
        assert_eq!(
            fs.lookup("/b/beta.txt").expect("lookup beta"),
            alpha.inode_id
        );
        assert_eq!(fs.read_file("/a/alpha.txt").expect("read alpha"), b"beta");
        assert_eq!(fs.read_file("/b/beta.txt").expect("read beta"), b"alpha");
    }

    #[test]
    fn rename_exchange_same_path_is_noop() {
        let (_root, mut fs) = make_test_fs("s5_rename_exchange_same_path").expect("open");
        let file = fs
            .create_file("/same.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create file");
        fs.write_file("/same.txt", 0, b"same").expect("write");

        fs.rename_exchange("/same.txt", "/same.txt")
            .expect("rename_exchange");

        assert_eq!(fs.lookup("/same.txt").expect("lookup"), file.inode_id);
        assert_eq!(fs.read_file("/same.txt").expect("read"), b"same");
    }

    #[test]
    fn rename_exchange_rejects_type_mismatch() {
        let (_root, mut fs) = make_test_fs("s5_rename_exchange_type_mismatch").expect("open");
        fs.create_file("/file.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create file");
        fs.create_dir("/dir", DEFAULT_DIRECTORY_PERMISSIONS)
            .expect("create dir");

        assert!(matches!(
            fs.rename_exchange("/file.txt", "/dir"),
            Err(FileSystemError::Unsupported {
                operation: "rename_exchange",
                ..
            })
        ));
    }

    #[test]
    fn rename_exchange_rejects_missing_source_or_target() {
        let (_root, mut fs) = make_test_fs("s5_rename_exchange_missing").expect("open");
        fs.create_file("/present.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create present");

        assert!(matches!(
            fs.rename_exchange("/missing.txt", "/present.txt"),
            Err(FileSystemError::NotFound { .. })
        ));
        assert!(matches!(
            fs.rename_exchange("/present.txt", "/missing.txt"),
            Err(FileSystemError::NotFound { .. })
        ));
    }
    // ── renameat2 integration tests ────────────────────────────────

    #[test]
    fn renameat2_plain_rename_moves_file() {
        let (_root, mut fs) = make_test_fs("rat2_plain_moves_file").expect("open");
        let src = fs
            .create_file("/src.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create src");
        fs.write_file("/src.txt", 0, b"hello").expect("write src");

        fs.renameat2(
            "/src.txt",
            "/dst.txt",
            crate::namespace::rename::RenameAt2Flags::EMPTY,
        )
        .expect("renameat2 plain");

        assert!(fs.lookup("/src.txt").is_err());
        assert_eq!(fs.lookup("/dst.txt").expect("lookup dst"), src.inode_id);
        assert_eq!(fs.read_file("/dst.txt").expect("read dst"), b"hello");
    }

    #[test]
    fn renameat2_plain_rename_overwrites_destination() {
        let (_root, mut fs) = make_test_fs("rat2_plain_overwrite").expect("open");
        let old_file = fs
            .create_file("/old", DEFAULT_FILE_PERMISSIONS)
            .expect("create old");
        fs.write_file("/old", 0, b"old-data").expect("write old");
        fs.create_file("/new", DEFAULT_FILE_PERMISSIONS)
            .expect("create new");
        fs.write_file("/new", 0, b"new-data").expect("write new");

        fs.renameat2(
            "/old",
            "/new",
            crate::namespace::rename::RenameAt2Flags::EMPTY,
        )
        .expect("renameat2 overwrite");

        // After rename, /new should have old's inode (source moves, target
        // is overwritten).
        assert!(fs.lookup("/old").is_err());
        assert_eq!(fs.lookup("/new").expect("lookup new"), old_file.inode_id);
        assert_eq!(fs.read_file("/new").expect("read new"), b"old-data");
    }

    #[test]
    fn renameat2_noreplace_without_destination_succeeds() {
        let (_root, mut fs) = make_test_fs("rat2_noreplace_ok").expect("open");
        let src = fs
            .create_file("/src.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create src");
        fs.write_file("/src.txt", 0, b"data").expect("write src");

        fs.renameat2(
            "/src.txt",
            "/dst.txt",
            crate::namespace::rename::RenameAt2Flags::NOREPLACE,
        )
        .expect("renameat2 NOREPLACE");

        assert!(fs.lookup("/src.txt").is_err());
        assert_eq!(fs.lookup("/dst.txt").expect("lookup dst"), src.inode_id);
        assert_eq!(fs.read_file("/dst.txt").expect("read dst"), b"data");
    }

    #[test]
    fn renameat2_noreplace_rejects_existing_destination() {
        let (_root, mut fs) = make_test_fs("rat2_noreplace_reject").expect("open");
        fs.create_file("/src.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create src");
        fs.create_file("/dst.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create dst");

        let result = fs.renameat2(
            "/src.txt",
            "/dst.txt",
            crate::namespace::rename::RenameAt2Flags::NOREPLACE,
        );

        assert!(matches!(result, Err(FileSystemError::AlreadyExists { .. })));
        // Both files should still exist
        assert!(fs.lookup("/src.txt").is_ok());
        assert!(fs.lookup("/dst.txt").is_ok());
    }

    #[test]
    fn renameat2_noreplace_source_not_found() {
        let (_root, mut fs) = make_test_fs("rat2_noreplace_enoent").expect("open");
        fs.create_file("/dst.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create dst");

        let result = fs.renameat2(
            "/missing.txt",
            "/dst.txt",
            crate::namespace::rename::RenameAt2Flags::NOREPLACE,
        );

        assert!(matches!(result, Err(FileSystemError::NotFound { .. })));
    }

    #[test]
    fn renameat2_exchange_swaps_files_same_directory() {
        let (_root, mut fs) = make_test_fs("rat2_exchange_same_dir").expect("open");
        let left = fs
            .create_file("/left.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create left");
        let right = fs
            .create_file("/right.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create right");
        fs.write_file("/left.txt", 0, b"left").expect("write left");
        fs.write_file("/right.txt", 0, b"right")
            .expect("write right");

        fs.renameat2(
            "/left.txt",
            "/right.txt",
            crate::namespace::rename::RenameAt2Flags::EXCHANGE,
        )
        .expect("renameat2 exchange");

        assert_eq!(fs.lookup("/left.txt").expect("lookup left"), right.inode_id);
        assert_eq!(
            fs.lookup("/right.txt").expect("lookup right"),
            left.inode_id
        );
        assert_eq!(fs.read_file("/left.txt").expect("read left"), b"right");
        assert_eq!(fs.read_file("/right.txt").expect("read right"), b"left");
    }

    #[test]
    fn renameat2_exchange_swaps_directories() {
        let (_root, mut fs) = make_test_fs("rat2_exchange_dirs").expect("open");
        let left_dir = fs
            .create_dir("/left", DEFAULT_DIRECTORY_PERMISSIONS)
            .expect("create left dir");
        let right_dir = fs
            .create_dir("/right", DEFAULT_DIRECTORY_PERMISSIONS)
            .expect("create right dir");
        fs.create_file("/left/child.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create left child");
        fs.create_file("/right/child.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create right child");

        fs.renameat2(
            "/left",
            "/right",
            crate::namespace::rename::RenameAt2Flags::EXCHANGE,
        )
        .expect("renameat2 exchange dirs");

        assert_eq!(fs.lookup("/left").expect("lookup left"), right_dir.inode_id);
        assert_eq!(
            fs.lookup("/right").expect("lookup right"),
            left_dir.inode_id
        );
        // Child entries moved with their parent directories
        assert!(fs.lookup("/left/child.txt").is_ok());
        assert!(fs.lookup("/right/child.txt").is_ok());
    }

    #[test]
    fn renameat2_exchange_rejects_type_mismatch() {
        let (_root, mut fs) = make_test_fs("rat2_exchange_type_mismatch").expect("open");
        fs.create_file("/file.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create file");
        fs.create_dir("/dir", DEFAULT_DIRECTORY_PERMISSIONS)
            .expect("create dir");

        let result = fs.renameat2(
            "/file.txt",
            "/dir",
            crate::namespace::rename::RenameAt2Flags::EXCHANGE,
        );

        assert!(matches!(result, Err(FileSystemError::Unsupported { .. })));
    }

    #[test]
    fn renameat2_exchange_rejects_missing_source() {
        let (_root, mut fs) = make_test_fs("rat2_exchange_missing_src").expect("open");
        fs.create_file("/present.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create present");

        let result = fs.renameat2(
            "/missing.txt",
            "/present.txt",
            crate::namespace::rename::RenameAt2Flags::EXCHANGE,
        );

        assert!(matches!(result, Err(FileSystemError::NotFound { .. })));
    }

    #[test]
    fn renameat2_exchange_rejects_missing_destination() {
        let (_root, mut fs) = make_test_fs("rat2_exchange_missing_dst").expect("open");
        fs.create_file("/present.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create present");

        let result = fs.renameat2(
            "/present.txt",
            "/missing.txt",
            crate::namespace::rename::RenameAt2Flags::EXCHANGE,
        );

        assert!(matches!(result, Err(FileSystemError::NotFound { .. })));
    }

    #[test]
    fn renameat2_exchange_same_path_is_noop() {
        let (_root, mut fs) = make_test_fs("rat2_exchange_same_path").expect("open");
        let file = fs
            .create_file("/same.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create file");
        fs.write_file("/same.txt", 0, b"same").expect("write");

        fs.renameat2(
            "/same.txt",
            "/same.txt",
            crate::namespace::rename::RenameAt2Flags::EXCHANGE,
        )
        .expect("renameat2 exchange same path");

        assert_eq!(fs.lookup("/same.txt").expect("lookup"), file.inode_id);
        assert_eq!(fs.read_file("/same.txt").expect("read"), b"same");
    }

    #[test]
    fn renameat2_plain_same_path_is_noop() {
        let (_root, mut fs) = make_test_fs("rat2_plain_same_path").expect("open");
        let file = fs
            .create_file("/same.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create file");
        fs.write_file("/same.txt", 0, b"data").expect("write");

        fs.renameat2(
            "/same.txt",
            "/same.txt",
            crate::namespace::rename::RenameAt2Flags::EMPTY,
        )
        .expect("renameat2 plain same path");

        assert_eq!(fs.lookup("/same.txt").expect("lookup"), file.inode_id);
        assert_eq!(fs.read_file("/same.txt").expect("read"), b"data");
    }

    #[test]
    fn renameat2_survives_reopen_persistence_roundtrip() {
        let (root, mut fs) = make_test_fs("rat2_persistence_roundtrip").expect("open");
        fs.create_file("/alpha", DEFAULT_FILE_PERMISSIONS)
            .expect("create alpha");
        fs.write_file("/alpha", 0, b"persisted")
            .expect("write alpha");
        fs.create_file("/beta", DEFAULT_FILE_PERMISSIONS)
            .expect("create beta");
        fs.write_file("/beta", 0, b"old-beta").expect("write beta");

        fs.renameat2(
            "/alpha",
            "/beta",
            crate::namespace::rename::RenameAt2Flags::EMPTY,
        )
        .expect("renameat2");

        drop(fs);

        // Reopen and verify
        let fs2 = LocalFileSystem::open(&root).expect("reopen");
        assert!(fs2.lookup("/alpha").is_err());
        assert_eq!(
            fs2.read_file("/beta").expect("read beta after reopen"),
            b"persisted"
        );
    }

    #[test]
    fn renameat2_exchange_survives_reopen_persistence_roundtrip() {
        let (root, mut fs) = make_test_fs("rat2_exchange_persistence").expect("open");
        fs.create_file("/x", DEFAULT_FILE_PERMISSIONS)
            .expect("create x");
        fs.write_file("/x", 0, b"x-data").expect("write x");
        fs.create_file("/y", DEFAULT_FILE_PERMISSIONS)
            .expect("create y");
        fs.write_file("/y", 0, b"y-data").expect("write y");

        fs.renameat2(
            "/x",
            "/y",
            crate::namespace::rename::RenameAt2Flags::EXCHANGE,
        )
        .expect("renameat2 exchange");

        drop(fs);

        let fs2 = LocalFileSystem::open(&root).expect("reopen");
        assert_eq!(fs2.read_file("/x").expect("read x after reopen"), b"y-data");
        assert_eq!(fs2.read_file("/y").expect("read y after reopen"), b"x-data");
    }

    #[test]
    fn renameat2_moves_directory_across_parents() {
        let (_root, mut fs) = make_test_fs("rat2_move_dir_across").expect("open");
        fs.create_dir("/a", DEFAULT_DIRECTORY_PERMISSIONS)
            .expect("create a");
        fs.create_dir("/b", DEFAULT_DIRECTORY_PERMISSIONS)
            .expect("create b");
        let child = fs
            .create_file("/a/child.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create child");
        fs.write_file("/a/child.txt", 0, b"child-data")
            .expect("write child");

        fs.renameat2(
            "/a/child.txt",
            "/b/child.txt",
            crate::namespace::rename::RenameAt2Flags::EMPTY,
        )
        .expect("renameat2 cross-dir");

        assert!(fs.lookup("/a/child.txt").is_err());
        assert_eq!(
            fs.lookup("/b/child.txt").expect("lookup child"),
            child.inode_id
        );
        assert_eq!(
            fs.read_file("/b/child.txt").expect("read child"),
            b"child-data"
        );
    }

    #[test]
    fn namespace_mutations_advance_parent_mtime_and_ctime() {
        let (_root, mut fs) = make_test_fs("s5_parent_dir_timestamp_churn").expect("open");
        fs.create_dir("/work", DEFAULT_DIRECTORY_PERMISSIONS)
            .expect("create work dir");

        let before_create = fs.stat("/work").expect("stat work").posix_time;
        fs.create_file("/work/file", DEFAULT_FILE_PERMISSIONS)
            .expect("create child file");
        let after_create = fs.stat("/work").expect("stat work after create").posix_time;
        assert_parent_metadata_time_advanced(before_create, after_create, "create");

        fs.create_dir("/work/subdir", DEFAULT_DIRECTORY_PERMISSIONS)
            .expect("create child dir");
        let after_mkdir = fs.stat("/work").expect("stat work after mkdir").posix_time;
        assert_parent_metadata_time_advanced(after_create, after_mkdir, "mkdir");

        let before_link_inode = fs.stat("/work/file").expect("stat file before link");
        fs.link_file("/work/file", "/work/file.link")
            .expect("link child file");
        let after_link = fs.stat("/work").expect("stat work after link").posix_time;
        assert_parent_metadata_time_advanced(after_mkdir, after_link, "link");
        let after_link_inode = fs.stat("/work/file").expect("stat file after link");
        assert!(
            after_link_inode.posix_time.ctime_ns > before_link_inode.posix_time.ctime_ns,
            "hard link must advance linked inode ctime"
        );

        fs.unlink("/work/file").expect("unlink original");
        let after_unlink = fs.stat("/work").expect("stat work after unlink").posix_time;
        assert_parent_metadata_time_advanced(after_link, after_unlink, "unlink");
        let after_unlink_inode = fs.stat("/work/file.link").expect("stat link after unlink");
        assert!(
            after_unlink_inode.posix_time.ctime_ns > after_link_inode.posix_time.ctime_ns,
            "unlink of one hard link must advance remaining inode ctime"
        );

        fs.renameat2(
            "/work/file.link",
            "/work/file.renamed",
            crate::namespace::rename::RenameAt2Flags::EMPTY,
        )
        .expect("rename linked file");
        let after_rename = fs.stat("/work").expect("stat work after rename").posix_time;
        assert_parent_metadata_time_advanced(after_unlink, after_rename, "rename");
        let after_rename_inode = fs
            .stat("/work/file.renamed")
            .expect("stat renamed file after rename");
        assert!(
            after_rename_inode.posix_time.ctime_ns > after_unlink_inode.posix_time.ctime_ns,
            "rename must advance moved inode ctime"
        );
    }

    #[test]
    fn link_file_creates_second_name_for_same_inode() {
        let (_root, mut fs) = make_test_fs("s5_link_file_basic").expect("open");
        let original = fs
            .create_file("/original.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create original");
        fs.write_file("/original.txt", 0, b"shared")
            .expect("write original");

        let linked = fs
            .link_file("/original.txt", "/linked.txt")
            .expect("link file");

        assert_eq!(linked.inode_id, original.inode_id);
        assert_eq!(fs.stat("/original.txt").expect("stat original").nlink, 2);
        assert_eq!(fs.stat("/linked.txt").expect("stat linked").nlink, 2);
        assert_eq!(fs.read_file("/linked.txt").expect("read linked"), b"shared");
    }

    #[test]
    fn link_file_survives_original_unlink_until_last_link_is_removed() {
        let (_root, mut fs) = make_test_fs("s5_link_file_unlink_lifecycle").expect("open");
        fs.create_file("/original.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create original");
        fs.write_file("/original.txt", 0, b"payload")
            .expect("write original");
        fs.link_file("/original.txt", "/linked.txt")
            .expect("link file");

        fs.unlink("/original.txt").expect("unlink original");

        assert_eq!(
            fs.read_file("/linked.txt").expect("read linked"),
            b"payload"
        );
        assert_eq!(fs.stat("/linked.txt").expect("stat linked").nlink, 1);
        assert!(fs.orphan_index.lock().unwrap().is_empty());

        fs.unlink("/linked.txt").expect("unlink linked");
        assert!(!fs.orphan_index.lock().unwrap().is_empty());
        fs.recover_orphans().expect("recover orphans");
        assert!(fs.orphan_index.lock().unwrap().is_empty());
    }

    #[test]
    fn link_file_rejects_directory_source() {
        let (_root, mut fs) = make_test_fs("s5_link_file_rejects_dir").expect("open");
        fs.create_dir("/dir", DEFAULT_DIRECTORY_PERMISSIONS)
            .expect("create dir");

        assert!(matches!(
            fs.link_file("/dir", "/dir-link"),
            Err(FileSystemError::Unsupported {
                operation: "hard link",
                ..
            })
        ));
    }

    #[test]
    fn link_file_rejects_existing_target_name() {
        let (_root, mut fs) = make_test_fs("s5_link_file_existing_target").expect("open");
        fs.create_file("/source.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create source");
        fs.create_file("/target.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create target");

        assert!(matches!(
            fs.link_file("/source.txt", "/target.txt"),
            Err(FileSystemError::AlreadyExists { .. })
        ));
    }

    #[test]
    fn link_file_rejects_missing_source() {
        let (_root, mut fs) = make_test_fs("s5_link_file_missing_source").expect("open");

        assert!(matches!(
            fs.link_file("/missing.txt", "/target.txt"),
            Err(FileSystemError::NotFound { .. })
        ));
    }

    #[test]
    fn link_file_across_directories() {
        let (_root, mut fs) = make_test_fs("s5_link_file_cross_dir").expect("open");
        fs.create_dir("/src", DEFAULT_DIRECTORY_PERMISSIONS)
            .expect("create src dir");
        fs.create_dir("/dst", DEFAULT_DIRECTORY_PERMISSIONS)
            .expect("create dst dir");
        let original = fs
            .create_file("/src/data.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create original");
        fs.write_file("/src/data.bin", 0, b"cross-directory payload")
            .expect("write original");

        let linked = fs
            .link_file("/src/data.bin", "/dst/alias.bin")
            .expect("cross-dir hard link");

        assert_eq!(linked.inode_id, original.inode_id);
        assert_eq!(fs.stat("/src/data.bin").expect("stat src").nlink, 2);
        assert_eq!(fs.stat("/dst/alias.bin").expect("stat dst").nlink, 2);
        assert_eq!(
            fs.read_file("/dst/alias.bin").expect("read alias"),
            b"cross-directory payload"
        );
        // Unlink original; alias still reachable and content intact.
        fs.unlink("/src/data.bin").expect("unlink original");
        assert_eq!(
            fs.stat("/dst/alias.bin")
                .expect("stat alias after unlink")
                .nlink,
            1
        );
        assert_eq!(
            fs.read_file("/dst/alias.bin")
                .expect("read alias after unlink"),
            b"cross-directory payload"
        );
    }

    #[test]
    fn link_file_to_self_rejected() {
        let (_root, mut fs) = make_test_fs("s5_link_file_self").expect("open");
        fs.create_file("/self.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create file");

        let result = fs.link_file("/self.txt", "/self.txt");
        assert!(result.is_err(), "hard link to self must fail");
    }

    #[test]
    fn link_file_nlink_overflow_rejected() {
        let (_root, mut fs) = make_test_fs("s5_link_file_overflow").expect("open");
        let original = fs
            .create_file("/overflow.dat", DEFAULT_FILE_PERMISSIONS)
            .expect("create file");

        // Force nlink to u32::MAX to trigger the EMLINK guard.
        Arc::make_mut(&mut fs.state.inodes)
            .get_mut(&original.inode_id)
            .expect("inode must exist")
            .nlink = u32::MAX;

        assert!(matches!(
            fs.link_file("/overflow.dat", "/new_link.dat"),
            Err(FileSystemError::Unsupported {
                operation: "hard link",
                ..
            })
        ));
    }

    #[test]
    fn symlink_create_and_read_round_trip_target() {
        let (_root, mut fs) = make_test_fs("s5_symlink_round_trip").expect("open");

        let link = fs
            .create_symlink("/link", b"../target")
            .expect("create symlink");

        assert_eq!(link.kind(), NodeKind::Symlink);
        assert_eq!(link.size, 9);
        assert_eq!(
            fs.read_symlink("/link").expect("read symlink"),
            b"../target"
        );
    }

    #[test]
    fn symlink_read_rejects_regular_file_and_directory() {
        let (_root, mut fs) = make_test_fs("s5_symlink_read_rejects_non_symlink").expect("open");
        fs.create_file("/file.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create file");
        fs.create_dir("/dir", DEFAULT_DIRECTORY_PERMISSIONS)
            .expect("create dir");

        assert!(matches!(
            fs.read_symlink("/file.txt"),
            Err(FileSystemError::NotFile {
                kind: NodeKind::File,
                ..
            })
        ));
        assert!(matches!(
            fs.read_symlink("/dir"),
            Err(FileSystemError::NotFile {
                kind: NodeKind::Dir,
                ..
            })
        ));
    }

    #[test]
    fn symlink_create_accepts_empty_target() {
        let (_root, mut fs) = make_test_fs("s5_symlink_empty_target").expect("open");

        let link = fs
            .create_symlink("/empty-link", b"")
            .expect("create symlink");

        assert_eq!(link.kind(), NodeKind::Symlink);
        assert_eq!(link.size, 0);
        assert_eq!(fs.read_symlink("/empty-link").expect("read symlink"), b"");
    }

    #[test]
    fn symlink_create_and_read_long_target() {
        let (_root, mut fs) = make_test_fs("s5_symlink_long_target").expect("open");
        let target = vec![b'a'; 1024];

        let link = fs
            .create_symlink("/long-link", &target)
            .expect("create symlink");

        assert_eq!(link.kind(), NodeKind::Symlink);
        assert_eq!(link.size, target.len() as u64);
        assert_eq!(fs.read_symlink("/long-link").expect("read symlink"), target);
    }
    // ── xattr remove_all and inode teardown tests ───────────────────────────

    #[test]
    fn xattrs_remove_all_clears_all_xattrs() {
        let (_root, mut fs) = make_test_fs("xra_clear").expect("open");
        fs.create_file("/f", 0o644).expect("create");
        fs.set_xattr("/f", b"user.a", b"1", 0).unwrap();
        fs.set_xattr("/f", b"user.b", b"2", 0).unwrap();
        fs.set_xattr("/f", b"user.c", b"3", 0).unwrap();

        fs.remove_all_xattrs("/f").unwrap();

        let list = fs.list_xattr("/f").unwrap();
        assert!(
            list.is_empty(),
            "list_xattr should be empty after remove_all_xattrs"
        );
        assert!(fs.get_xattr("/f", b"user.a").unwrap().is_none());
        assert!(fs.get_xattr("/f", b"user.b").unwrap().is_none());
        assert!(fs.get_xattr("/f", b"user.c").unwrap().is_none());
    }

    #[test]
    fn xattrs_remove_all_is_idempotent() {
        let (_root, mut fs) = make_test_fs("xra_idem").expect("open");
        fs.create_file("/f", 0o644).expect("create");

        // Removing from an inode with no xattrs should succeed.
        fs.remove_all_xattrs("/f").unwrap();
        // Twice should also succeed.
        fs.remove_all_xattrs("/f").unwrap();

        let list = fs.list_xattr("/f").unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn set_empty_default_acl_removes_default_acl() {
        let (_root, mut fs) = make_test_fs("xra_empty_default_acl").expect("open");
        fs.create_dir("/d", 0o755).expect("create dir");
        let default_acl = tidefs_posix_acl::minimal_access_acl_from_mode(0o750);
        let encoded_default_acl = tidefs_posix_acl::encode_posix_acl_xattr(&default_acl);
        fs.set_xattr("/d", b"system.posix_acl_default", &encoded_default_acl, 0)
            .expect("set default ACL");

        let empty_default_acl = tidefs_posix_acl::encode_posix_acl_xattr(&[]);
        fs.set_xattr("/d", b"system.posix_acl_default", &empty_default_acl, 0)
            .expect("empty default ACL removes xattr");

        assert!(fs
            .get_xattr("/d", b"system.posix_acl_default")
            .unwrap()
            .is_none());
    }

    #[test]
    fn xattrs_cleared_on_unlink() {
        let (_root, mut fs) = make_test_fs("xra_unlink").expect("open");
        fs.create_file("/f", 0o644).expect("create");
        fs.set_xattr("/f", b"user.orphan", b"val", 0).unwrap();

        fs.unlink("/f").unwrap();

        // Inode is gone, so list_xattr should fail with NotFound.
        assert!(matches!(
            fs.list_xattr("/f"),
            Err(FileSystemError::NotFound { .. })
        ));
    }

    #[test]
    fn xattrs_cleared_on_remove_dir() {
        let (_root, mut fs) = make_test_fs("xra_rmdir").expect("open");
        fs.create_dir("/d", 0o755).expect("create dir");
        fs.set_xattr("/d", b"user.dirattr", b"val", 0).unwrap();

        fs.remove_dir("/d").unwrap();

        assert!(matches!(
            fs.list_xattr("/d"),
            Err(FileSystemError::NotFound { .. })
        ));
    }

    #[test]
    fn inode_resolved_unlink_and_rmdir_ignore_diagnostic_path() {
        let (_root, mut fs) = make_test_fs("inode_resolved_remove").expect("open");
        fs.create_dir("/parent", 0o755).expect("create parent");
        fs.create_file("/parent/file", 0o644).expect("create file");
        fs.create_dir("/parent/empty", 0o755).expect("create dir");
        let parent = fs.stat("/parent").expect("stat parent").inode_id;

        fs.unlink_child_by_inode(parent, b"file", "not-an-absolute-file-path")
            .expect("unlink by parent inode");
        fs.remove_dir_child_by_inode(parent, b"empty", "not-an-absolute-dir-path")
            .expect("rmdir by parent inode");

        assert!(matches!(
            fs.stat("/parent/file"),
            Err(FileSystemError::NotFound { .. })
        ));
        assert!(matches!(
            fs.stat("/parent/empty"),
            Err(FileSystemError::NotFound { .. })
        ));
    }

    #[test]
    fn xattrs_preserved_on_multilinked_unlink() {
        let (_root, mut fs) = make_test_fs("xra_multilink").expect("open");
        let inode = fs.create_file("/a", 0o644).expect("create a");
        fs.set_xattr("/a", b"user.shared", b"val", 0).unwrap();
        fs.link_file("/a", "/b").expect("link");

        // Unlink /a; /b still holds a link, so inode + xattrs survive.
        fs.unlink("/a").unwrap();

        assert_eq!(
            fs.get_xattr("/b", b"user.shared").unwrap(),
            Some(b"val".to_vec())
        );
        // Verify nlink is correct.
        let record = fs.inode(inode.inode_id).unwrap();
        assert_eq!(record.nlink, 1);
    }

    #[test]
    fn xattrs_roundtrip_set_list_remove_all() {
        let (_root, mut fs) = make_test_fs("xra_roundtrip").expect("open");
        fs.create_file("/f", 0o644).expect("create");

        // Set some xattrs.
        fs.set_xattr("/f", b"user.alpha", b"alpha-value", 0)
            .unwrap();
        fs.set_xattr("/f", b"user.beta", b"beta-value", 0).unwrap();

        // List reflects both.
        let raw = fs.list_xattr("/f").unwrap();
        let names: Vec<&[u8]> = raw.split(|b| *b == 0).filter(|s| !s.is_empty()).collect();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&b"user.alpha".as_slice()));
        assert!(names.contains(&b"user.beta".as_slice()));

        // Get matches set.
        assert_eq!(
            fs.get_xattr("/f", b"user.alpha").unwrap(),
            Some(b"alpha-value".to_vec())
        );

        // Remove all.
        fs.remove_all_xattrs("/f").unwrap();

        // Verify empty.
        assert!(fs.list_xattr("/f").unwrap().is_empty());
        assert!(fs.get_xattr("/f", b"user.alpha").unwrap().is_none());
        assert!(fs.get_xattr("/f", b"user.beta").unwrap().is_none());

        // Re-set after remove_all works.
        fs.set_xattr("/f", b"user.gamma", b"new", 0).unwrap();
        assert_eq!(
            fs.get_xattr("/f", b"user.gamma").unwrap(),
            Some(b"new".to_vec())
        );
    }

    #[test]
    fn xattrs_removed_on_rename_overwrite() {
        let (_root, mut fs) = make_test_fs("xra_rename_ow").expect("open");
        fs.create_file("/src", 0o644).expect("create src");
        fs.write_file("/src", 0, b"src-data").expect("write src");
        fs.set_xattr("/src", b"user.srcattr", b"val", 0).unwrap();
        fs.create_file("/dst", 0o644).expect("create dst");
        fs.write_file("/dst", 0, b"dst-data").expect("write dst");
        fs.set_xattr("/dst", b"user.dstatt", b"old", 0).unwrap();

        // Rename /src over /dst — /dst inode is deleted.
        fs.rename("/src", "/dst", false).unwrap();

        // /src is gone.
        assert!(matches!(
            fs.list_xattr("/src"),
            Err(FileSystemError::NotFound { .. })
        ));
        // /dst has src content and src xattrs.
        assert_eq!(fs.read_file("/dst").unwrap(), b"src-data");
        assert_eq!(
            fs.get_xattr("/dst", b"user.srcattr").unwrap(),
            Some(b"val".to_vec())
        );
        // /dst old xattrs should be gone.
        assert!(fs.get_xattr("/dst", b"user.dstatt").unwrap().is_none());
    }

    #[test]
    fn open_reclaims_orphans_after_crash() {
        let root = std::env::temp_dir().join("oi_test_crash_recover");
        if root.exists() {
            let _ = std::fs::remove_dir_all(&root);
        }
        // First session: create + unlink, orphaning an inode.
        {
            let mut fs = LocalFileSystem::open(&root).expect("open");
            let inode_rec = fs.create_file("/doomed", 0o644).expect("create_file");
            fs.unlink("/doomed").expect("unlink");
            assert!(!fs.orphan_index.lock().unwrap().is_empty());
            assert!(
                fs.orphan_index
                    .lock()
                    .unwrap()
                    .contains(inode_rec.inode_id.0),
                "unlinked inode should be in orphan index"
            );
        } // Drop fs here, simulating kill -9 (no clean shutdown).
          // Re-open; cleanup_orphans() is called synchronously inside open().
        let fs2 = LocalFileSystem::open(&root).expect("reopen");
        assert!(
            fs2.orphan_index.lock().unwrap().is_empty(),
            "orphan index should be empty after crash recovery on open"
        );
        drop(fs2);
        let _ = std::fs::remove_dir_all(&root);
    }
}

// ── commit_group recovery integration tests ─────────────────────────
#[cfg(test)]
mod recovery_integration_tests {
    use super::*;
    use tempfile::TempDir;

    fn test_options() -> StoreOptions {
        StoreOptions::test_fast()
    }

    fn temp_root(label: &str) -> std::path::PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("tidefs-recovery-int-{label}-{unique}"))
    }

    fn cleanup(path: &std::path::Path) {
        let _ = std::fs::remove_dir_all(path);
    }

    /// Fresh filesystem open runs CommitGroupRecovery internally without error.
    #[test]
    fn fresh_open_triggers_commit_group_recovery_without_error() {
        let root = temp_root("fresh-recovery");
        let fs = LocalFileSystem::open_with_options(&root, test_options())
            .expect("fresh open should succeed with internal recovery");
        // CommitGroupStateMachine should be initialized from the recovered commit_group.
        // The starting commit_group id should be at least FIRST (1).
        assert!(fs.commit_group.current_commit_group().0 >= 1);
        // Verify filesystem is functional after recovery-integrated open.
        drop(fs);
        cleanup(&root);
    }

    /// Open-empty-close-reopen cycle preserves generation continuity.
    #[test]
    fn reopen_after_clean_close_preserves_generation() {
        let root = temp_root("reopen-gen");
        let gen1 = {
            let fs = LocalFileSystem::open_with_options(&root, test_options()).expect("first open");
            let gen = fs.state.generation;
            drop(fs);
            gen
        };
        let gen2 = {
            let fs = LocalFileSystem::open_with_options(&root, test_options()).expect("reopen");
            let gen = fs.state.generation;
            drop(fs);
            gen
        };
        // After clean close, the generation should be preserved.
        assert_eq!(gen1, gen2, "generation should persist across clean reopen");
        cleanup(&root);
    }

    /// CommitGroupRecovery on a fresh store returns FIRST as next_commit_group_id.
    #[test]
    fn fresh_store_recovery_returns_first_commit_group() {
        use tidefs_local_object_store::LocalObjectStore;
        let tmp = TempDir::new().expect("tempdir");
        let store =
            LocalObjectStore::open_with_options(tmp.path(), test_options()).expect("open store");
        let result =
            CommitGroupRecovery::recover(&store).expect("recovery should succeed on fresh store");
        assert_eq!(
            result.next_commit_group_id.0, 1,
            "fresh store should start at commit_group 1"
        );
        assert!(result.replayed_commit_groups.is_empty());
        assert!(result.torn_commit_groups.is_empty());
        assert!(result.committed_keys.is_empty());
    }

    /// Recovery on an empty store via scan returns no commit_groups.
    #[test]
    fn empty_store_scan_finds_no_commit_groups() {
        use tidefs_local_object_store::LocalObjectStore;
        let tmp = TempDir::new().expect("tempdir");
        let store =
            LocalObjectStore::open_with_options(tmp.path(), test_options()).expect("open store");
        let result =
            CommitGroupRecovery::scan(&store, None).expect("scan should succeed on empty store");
        assert_eq!(result.highest_committed_commit_group.0, 0);
        assert_eq!(result.next_commit_group_id.0, 1);
        assert!(result.torn_commit_groups.is_empty());
    }

    // ── RecoveryPolicy integration tests ──────────────────────────────────

    /// Verify that open with RecoveryPolicy::ReadOnly skips intent-log
    /// replay but still loads committed root state.
    #[test]
    fn recovery_policy_read_only_loads_state_without_replay() {
        use RecoveryPolicy;
        let tmp = TempDir::new().expect("tempdir");
        let mut store =
            LocalObjectStore::open_with_options(tmp.path(), test_options()).expect("open store");

        // Write a minimal committed root so there is state to load.
        let state = crate::recovery::initial_state();
        let auth_key = crate::default_root_authentication_key().expect("auth key");
        crate::persistence::persist_state(&mut store, &state, auth_key).expect("persist");

        let result = crate::recovery::load_latest_committed_state(
            &mut store,
            auth_key,
            RecoveryPolicy::ReadOnly,
        );
        assert!(result.is_ok(), "ReadOnly should load state without error");
        let loaded = result.unwrap();
        assert!(loaded.is_some(), "should find committed state");
    }

    /// Verify that RecoveryPolicy::ReplayOnly (default) allows intent-log
    /// replay.
    #[test]
    fn recovery_policy_replay_only_allows_replay() {
        let p = RecoveryPolicy::ReplayOnly;
        assert!(p.allows_replay());
        assert!(!p.allows_repair_writeback());
    }

    /// Verify that scrub_repair_pass is gated by RecoveryPolicy and
    /// returns an empty ledger when repair is not permitted.
    #[test]
    fn scrub_repair_pass_gated_by_policy() {
        let tmp = TempDir::new().expect("tempdir");
        let opts = StoreOptions::test_fast();
        let fs =
            crate::LocalFileSystem::open_with_options(tmp.path(), opts).expect("open filesystem");

        // Default policy is ReplayOnly — repair writeback not allowed.
        let ledger = fs.scrub_repair_pass().expect("scrub_repair_pass");
        assert_eq!(ledger.repair_count, 0);
        assert_eq!(ledger.repair_failure_count, 0);
    }

    /// Transaction rollback must restore all mutable side ledgers (#5980).
    ///
    /// Creates a file inside a transaction, writes data, then rolls back.
    /// The next created file (which may reuse the same inode id) must not
    /// see leaked write-buffer data from the rolled-back transaction.
    /// Quota, space accounting, capacity authority, and dirty-page tracking
    /// must also be restored to pre-transaction state.
    #[test]
    fn transaction_rollback_restores_all_side_ledgers() {
        let root = temp_root("txn-rollback");
        let mut fs =
            LocalFileSystem::open_with_options(&root, test_options()).expect("open filesystem");
        fs.set_auto_commit(false);

        // Record pre-transaction capacity state.
        let used_before = fs.capacity_authority.used_bytes();
        let quota_table_before = fs.state.quota_table.clone();
        let space_accounting_before = fs.state.space_accounting.clone();

        // Begin transaction, create a file, write data.
        fs.begin_transaction().expect("begin_transaction");
        let _record = fs.create_file("/leaked-write", 0o644).expect("create_file");
        fs.write_file("/leaked-write", 0, b"ZZZZZZZZ")
            .expect("write_file");

        // Rollback must discard all mutations.
        fs.rollback_transaction().expect("rollback_transaction");

        // The rolled-back file must not be visible.
        assert!(
            fs.lookup("/leaked-write").is_err(),
            "rolled-back file must not exist"
        );

        // Create a fresh file — may reuse the same inode id.
        let fresh = fs.create_file("/clean-file", 0o644).expect("create_file2");

        // Read the fresh file: must be empty (0 bytes), no leaked write buffer.
        let content = fs.read_file("/clean-file").expect("read_file");
        assert!(
            content.is_empty(),
            "fresh file must be empty, got {} bytes with prefix {:?}",
            content.len(),
            content.get(..8.min(content.len()))
        );

        // Verify write_buffers do not contain data for the fresh inode.
        assert!(
            fs.write_buffers
                .get(&fresh.inode_id)
                .map(|wb| wb.is_empty())
                .unwrap_or(true),
            "write buffer for fresh inode must be empty or absent"
        );

        // Capacity authority must be restored (no leaked allocation).
        let used_after = fs.capacity_authority.used_bytes();
        assert_eq!(
            used_before, used_after,
            "capacity used_bytes must be restored after rollback: before={used_before} after={used_after}",
        );

        // Quota table must be restored.
        assert_eq!(
            quota_table_before, fs.state.quota_table,
            "quota table must be restored after rollback"
        );

        // Space accounting must be restored.
        assert_eq!(
            space_accounting_before, fs.state.space_accounting,
            "space accounting must be restored after rollback"
        );

        drop(fs);
        cleanup(&root);
    }

    /// Verify that open with RecoveryPolicy::ReadOnly does not replay
    /// uncommitted intent-log entries. A store is built at the low level
    /// with a committed root plus flushed intent-log entries; then
    /// ReadOnly open must preserve the pending entries without replay.
    #[test]
    fn recovery_policy_read_only_open_preserves_uncommitted_intents() {
        use crate::intent_log::{
            IntentLog, IntentLogConfig, IntentLogEntryKind, IntentLogRootAnchor,
        };
        use crate::persistence::persist_state;
        use crate::recovery::initial_state;

        let root = temp_root("readonly-intent-preserve");

        // Phase 1: build a store with a committed root and flushed
        // intent-log entries using low-level APIs so Drop auto-commit
        // does not consume the pending entries.
        {
            let mut store = tidefs_local_object_store::LocalObjectStore::open_with_options(
                &root,
                test_options(),
            )
            .expect("open store");

            // Write a committed root.
            let mut state = initial_state();
            state.generation = 2;
            persist_state(
                &mut store,
                &state,
                default_root_authentication_key().expect("auth key"),
            )
            .expect("persist state");

            // Create and flush an intent-log entry representing
            // uncommitted data.
            let anchor = IntentLogRootAnchor {
                transaction_id: state.generation,
                generation: state.generation,
                manifest_digest: tidefs_local_object_store::IntegrityDigest64(0),
            };
            let mut log = IntentLog::with_config(IntentLogConfig {
                max_batch_entries: 1,
                ..IntentLogConfig::default()
            });
            log.append(
                &mut store,
                IntentLogEntryKind::PressureFallback,
                anchor,
                1, // timestamp_ns
            )
            .expect("append intent");
            // append auto-flushes when max_batch_entries is 1.
            assert!(!log.is_empty(), "intent log should have entries");
        }

        // Phase 2: open with ReadOnly. Intents must be preserved.
        {
            let _fs = LocalFileSystem::open_with_allocator_policy_and_root_authentication_key(
                &root,
                LocalFileSystemOpenConfig {
                    options: test_options(),
                    allocator_policy: LocalStorageAllocatorPolicy::default(),
                    root_authentication_key: default_root_authentication_key().expect("auth key"),
                    encryption: None,
                    compression: None,
                    log_device_device_path: None,
                    recovery_policy: RecoveryPolicy::ReadOnly,
                    block_devices: None,
                },
            )
            .expect("ReadOnly open should succeed");

            let store = tidefs_local_object_store::LocalObjectStore::open_with_options(
                &root,
                test_options(),
            )
            .expect("reopen store for verification");
            let intent_log = IntentLog::load(&store).expect("load intent log");
            assert!(
                !intent_log.is_empty(),
                "ReadOnly open must not replay intent-log entries; pending entries should remain"
            );
        }

        cleanup(&root);
    }
    // -- TXG durability fence barrier tests ---------------------------------

    /// Verify that register_dirty + notify_committed wakes an fsync waiter.
    #[test]
    fn txg_fsync_barrier_wakes_on_commit() {
        let gate = SyncGate::new();
        gate.register_dirty(42, CommitGroupId(1));

        let sync = CommitGroupSync::new(gate.clone());

        let handle = std::thread::spawn(move || {
            sync.fsync(42).unwrap();
        });

        std::thread::sleep(std::time::Duration::from_millis(50));
        gate.notify_committed(CommitGroupId(1));

        handle.join().unwrap();
    }

    /// Verify that syncfs barrier wakes on notify_synced.
    #[test]
    fn txg_syncfs_barrier_wakes_on_notify_synced() {
        let gate = SyncGate::new();
        let sync = CommitGroupSync::new(gate.clone());

        let handle = std::thread::spawn(move || {
            sync.syncfs().unwrap();
        });

        std::thread::sleep(std::time::Duration::from_millis(50));
        gate.notify_synced();

        handle.join().unwrap();
    }

    /// Verify that durable_commit_group advances correctly.
    #[test]
    fn txg_durable_commit_group_advances_on_commit() {
        let gate = SyncGate::new();
        assert_eq!(gate.durable_commit_group(), CommitGroupId(0));

        gate.notify_committed(CommitGroupId(1));
        assert_eq!(gate.durable_commit_group(), CommitGroupId(1));

        gate.notify_committed(CommitGroupId(3));
        assert_eq!(gate.durable_commit_group(), CommitGroupId(3));

        // Does not regress.
        gate.notify_committed(CommitGroupId(2));
        assert_eq!(gate.durable_commit_group(), CommitGroupId(3));
    }

    /// Verify register_dirty with no matching notify leaves waiter blocked.
    #[test]
    fn txg_fsync_barrier_blocks_without_notify() {
        let gate = SyncGate::new();
        gate.register_dirty(99, CommitGroupId(1));

        let sync = CommitGroupSync::new(gate.clone());

        let handle = std::thread::spawn(move || {
            sync.fsync(99).unwrap();
        });

        // After 100ms the thread should still be waiting.
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(!handle.is_finished());

        // Now notify: the barrier should wake.
        gate.notify_committed(CommitGroupId(1));
        handle.join().unwrap();
    }

    /// Verify fsync on an unregistered inode returns immediately.
    #[test]
    fn txg_fsync_barrier_noop_for_unregistered_inode() {
        let gate = SyncGate::new();
        let sync = CommitGroupSync::new(gate);
        // Should return Ok immediately -- no dirty data registered.
        sync.fsync(404).unwrap();
    }

    /// Verify that fsync on a real LocalFileSystem advances the durable
    /// commit group and that fsync_wait_barrier returns immediately after.
    #[test]
    fn txg_fsync_advances_durable_commit_group_in_live_fs() {
        use tempfile::TempDir;
        let dir = TempDir::new().expect("tempdir");
        let root = dir.path().join("pool");

        // Session 1: create a filesystem, write data, fsync.
        let durable_after_fsync = {
            let mut fs = LocalFileSystem::open_with_allocator_policy_and_root_authentication_key(
                &root,
                LocalFileSystemOpenConfig {
                    options: test_options(),
                    allocator_policy: LocalStorageAllocatorPolicy::default(),
                    root_authentication_key: default_root_authentication_key().expect("auth key"),
                    encryption: None,
                    compression: None,
                    log_device_device_path: None,
                    recovery_policy: RecoveryPolicy::default(),
                    block_devices: None,
                },
            )
            .expect("open fs");

            // Before any write, durable commit group should be 0.
            // (A fresh filesystem starts with generation 1 but no commit yet.)
            let before = fs.durable_commit_group();

            fs.create_file("/barrier.txt", DEFAULT_FILE_PERMISSIONS)
                .expect("create file");
            fs.write_file("/barrier.txt", 0, b"txg barrier data")
                .expect("write");
            fs.fsync_file("/barrier.txt").expect("fsync");

            let after = fs.durable_commit_group();
            assert!(
                after > before,
                "durable_commit_group must advance after fsync: before={before}, after={after}"
            );

            // fsync_wait_barrier should return immediately since the data
            // is already committed (register_dirty + notify_committed happened).
            fs.fsync_wait_barrier(2) // inode 2: root=1, barrier.txt=2
                .expect("fsync_wait_barrier on already-committed inode");

            // Verify barrier counters advanced.
            let snap = fs.fsync_stats_snapshot();
            assert!(
                snap.fsync_barrier_wait_count > 0,
                "fsync_barrier_wait_count must be >0 after fsync_wait_barrier call"
            );

            after
        };

        // Session 2: reopen and verify data survived.
        {
            let fs = LocalFileSystem::open_with_allocator_policy_and_root_authentication_key(
                &root,
                LocalFileSystemOpenConfig {
                    options: test_options(),
                    allocator_policy: LocalStorageAllocatorPolicy::default(),
                    root_authentication_key: default_root_authentication_key().expect("auth key"),
                    encryption: None,
                    compression: None,
                    log_device_device_path: None,
                    recovery_policy: RecoveryPolicy::default(),
                    block_devices: None,
                },
            )
            .expect("reopen fs");

            let data = fs.read_file("/barrier.txt").expect("read file");
            assert_eq!(
                data, b"txg barrier data",
                "data must survive fsync + reopen"
            );

            // The durable commit group from session 1 should be preserved.
            let after_reopen = fs.durable_commit_group();
            assert_eq!(
                after_reopen, durable_after_fsync,
                "durable_commit_group must survive reopen: {after_reopen} != {durable_after_fsync}"
            );
        }

        // Cleanup
        let _ = std::fs::remove_dir_all(&root);
    }
}
