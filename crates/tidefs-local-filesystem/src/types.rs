use std::collections::BTreeMap;
use std::env;
use std::path::PathBuf;

use std::fmt;

use tidefs_local_object_store::{
    IntegrityDigest64, ObjectKey, ObjectLocation, StoreRetentionCompactionReport, StoreStats,
};
use tidefs_types_vfs_core::{
    Generation, InodeAttr, InodeFlags, InodeId, NodeFacets, NodeKind, PosixAttrs, S_IFBLK, S_IFCHR,
    S_IFIFO, S_IFLNK, S_IFMT, S_IFSOCK,
};
use tidefs_types_vfs_owned::DirEntry as OwnedDirEntry;

use crate::constants::*;
use crate::decode_changed_record_export;
use crate::encode_changed_record_export;
use crate::error::FileSystemError;
use crate::Result;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PosixSupport {
    IncludedInCurrentUserspaceImpl,
    IncludedAfterCurrentUserspaceImpl,
    BlockedBeforeUsefulImpl,
    DeferredAfterCurrentImpl,
    ExplicitlyUnsupported,
}

impl PosixSupport {
    pub const fn stable_id(self) -> &'static str {
        match self {
            Self::IncludedInCurrentUserspaceImpl => "included-in-current-userspace-implementation",
            Self::IncludedAfterCurrentUserspaceImpl => {
                "included-after-current-userspace-implementation"
            }
            Self::BlockedBeforeUsefulImpl => "blocked-before-useful-implementation",
            Self::DeferredAfterCurrentImpl => "deferred-after-current-implementation",
            Self::ExplicitlyUnsupported => "explicitly-unsupported",
        }
    }

    pub const fn human_name(self) -> &'static str {
        match self {
            Self::IncludedInCurrentUserspaceImpl => "included in first FUSE implementation",
            Self::IncludedAfterCurrentUserspaceImpl => {
                "included in the current userspace implementation"
            }
            Self::BlockedBeforeUsefulImpl => "blocked before useful implementation",
            Self::DeferredAfterCurrentImpl => "deferred after current implementation",
            Self::ExplicitlyUnsupported => "explicitly unsupported",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PosixTopic {
    LookupGetattr,
    Readdir,
    CreateOpenRelease,
    ReadWriteTruncate,
    MkdirRmdir,
    LinkUnlink,
    Rename,
    SymlinkReadlink,
    FsyncDurability,
    OpenHandleLifetime,
    StatfsCapacity,
    MetadataMutation,
    ExtendedAttributes,
    FileLocking,
    SpaceManagement,
    MmapCoherency,
    SparseDiscovery,
    SpecialInodes,
}

impl PosixTopic {
    pub const fn stable_id(self) -> &'static str {
        match self {
            Self::LookupGetattr => "posix.lookup_getattr",
            Self::Readdir => "posix.readdir",
            Self::CreateOpenRelease => "posix.create_open_release",
            Self::ReadWriteTruncate => "posix.read_write_truncate",
            Self::MkdirRmdir => "posix.mkdir_rmdir",
            Self::LinkUnlink => "posix.link_unlink",
            Self::Rename => "posix.rename",
            Self::SymlinkReadlink => "posix.symlink_readlink",
            Self::FsyncDurability => "posix.fsync_durability",
            Self::OpenHandleLifetime => "posix.open_handle_lifetime",
            Self::StatfsCapacity => "posix.statfs_capacity",
            Self::MetadataMutation => "posix.metadata_mutation",
            Self::ExtendedAttributes => "posix.extended_attributes",
            Self::FileLocking => "posix.file_locking",
            Self::SpaceManagement => "posix.space_management",
            Self::MmapCoherency => "posix.mmap_coherency",
            Self::SparseDiscovery => "posix.sparse_discovery",
            Self::SpecialInodes => "posix.special_inodes",
        }
    }

    pub const fn human_name(self) -> &'static str {
        match self {
            Self::LookupGetattr => "lookup and getattr",
            Self::Readdir => "directory reads",
            Self::CreateOpenRelease => "create, open, and release",
            Self::ReadWriteTruncate => "read, write, and truncate",
            Self::MkdirRmdir => "mkdir and empty rmdir",
            Self::LinkUnlink => "hard link and unlink",
            Self::Rename => "rename",
            Self::SymlinkReadlink => "symlink and readlink",
            Self::FsyncDurability => "fsync and directory fsync durability",
            Self::OpenHandleLifetime => "open-handle lifetime semantics",
            Self::StatfsCapacity => "statfs capacity reporting",
            Self::MetadataMutation => "metadata mutation",
            Self::ExtendedAttributes => "xattrs and ACLs",
            Self::FileLocking => "file locks",
            Self::SpaceManagement => "space management syscalls",
            Self::MmapCoherency => "mmap coherency",
            Self::SparseDiscovery => "sparse file discovery",
            Self::SpecialInodes => "special inode creation",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PosixSubsetEntry {
    pub topic: PosixTopic,
    pub operation: &'static str,
    pub support: PosixSupport,
    pub errno: &'static str,
    pub rule: &'static str,
}

pub const POSIX_SUBSET_ENTRIES: &[PosixSubsetEntry] = &[
    PosixSubsetEntry {
        topic: PosixTopic::LookupGetattr,
        operation: "lookup/getattr",
        support: PosixSupport::IncludedInCurrentUserspaceImpl,
        errno: "ENOENT/EIO",
        rule: "Path lookup and inode attribute rendering are required and map to existing namespace and InodeAttr source surfaces.",
    },
    PosixSubsetEntry {
        topic: PosixTopic::Readdir,
        operation: "opendir/readdir/releasedir",
        support: PosixSupport::IncludedInCurrentUserspaceImpl,
        errno: "ENOENT/ENOTDIR/EIO",
        rule: "Directory listing is required for the first useful userspace implementation and must expose stable names without mutating namespace truth.",
    },
    PosixSubsetEntry {
        topic: PosixTopic::CreateOpenRelease,
        operation: "create/open/release",
        support: PosixSupport::IncludedInCurrentUserspaceImpl,
        errno: "EEXIST/ENOENT/EISDIR/EIO",
        rule: "Regular-file creation and simple open/release are included, but durable open-handle lifetime semantics remain separately blocked.",
    },
    PosixSubsetEntry {
        topic: PosixTopic::ReadWriteTruncate,
        operation: "read/write/truncate",
        support: PosixSupport::IncludedInCurrentUserspaceImpl,
        errno: "ENOENT/EISDIR/EIO",
        rule: "Byte reads, sparse writes, append-by-offset, and size truncation are included over the OW-101 chunked content layout.",
    },
    PosixSubsetEntry {
        topic: PosixTopic::MkdirRmdir,
        operation: "mkdir/rmdir-empty",
        support: PosixSupport::IncludedInCurrentUserspaceImpl,
        errno: "EEXIST/ENOENT/ENOTEMPTY/ENOTDIR/EIO",
        rule: "Directory creation and empty-directory removal are included; non-empty removal must return an explicit error.",
    },
    PosixSubsetEntry {
        topic: PosixTopic::LinkUnlink,
        operation: "link/unlink",
        support: PosixSupport::IncludedInCurrentUserspaceImpl,
        errno: "ENOENT/EISDIR/EIO",
        rule: "Hard links and closed-path unlink are included in the current userspace implementation; OW-106 adds unlink-while-open handle retention as a separate included row.",
    },
    PosixSubsetEntry {
        topic: PosixTopic::Rename,
        operation: "rename",
        support: PosixSupport::IncludedInCurrentUserspaceImpl,
        errno: "ENOENT/ENOTDIR/EISDIR/ENOTEMPTY/EINVAL/EIO",
        rule: "Rename is included; OW-106 adds replacement semantics as a separate included row while renameat2 flags remain rejected.",
    },
    PosixSubsetEntry {
        topic: PosixTopic::SymlinkReadlink,
        operation: "symlink/readlink",
        support: PosixSupport::IncludedInCurrentUserspaceImpl,
        errno: "EEXIST/ENOENT/EINVAL/EIO",
        rule: "Symbolic link creation and target reads are included for byte-preserving local namespace behavior.",
    },
    PosixSubsetEntry {
        topic: PosixTopic::FsyncDurability,
        operation: "fsync-file",
        support: PosixSupport::IncludedAfterCurrentUserspaceImpl,
        errno: "EIO",
        rule: "OW-106 binds file fsync success to the root-slot publication and Local Object Store sync boundary.",
    },
    PosixSubsetEntry {
        topic: PosixTopic::FsyncDurability,
        operation: "fsync-directory",
        support: PosixSupport::IncludedAfterCurrentUserspaceImpl,
        errno: "EIO",
        rule: "OW-106 maps directory fsync to the same committed namespace root-slot and Local Object Store sync boundary.",
    },
    PosixSubsetEntry {
        topic: PosixTopic::OpenHandleLifetime,
        operation: "unlink-while-open",
        support: PosixSupport::IncludedAfterCurrentUserspaceImpl,
        errno: "ENOENT/EISDIR/EIO",
        rule: "OW-106 preserves last-link regular-file content in FUSE session open-handle state until the final release.",
    },
    PosixSubsetEntry {
        topic: PosixTopic::Rename,
        operation: "rename-over-target",
        support: PosixSupport::IncludedAfterCurrentUserspaceImpl,
        errno: "ENOENT/ENOTDIR/EISDIR/ENOTEMPTY/EINVAL/EIO",
        rule: "OW-106 commits replacement rename atomically in the local filesystem and preserves replaced open regular-file handles in FUSE session state.",
    },
    PosixSubsetEntry {
        topic: PosixTopic::StatfsCapacity,
        operation: "statfs",
        support: PosixSupport::IncludedAfterCurrentUserspaceImpl,
        errno: "EIO",
        rule: "OW-102 maps statfs to the finite local storage allocator report; free blocks exclude content still protected by committed fallback roots.",
    },
    PosixSubsetEntry {
        topic: PosixTopic::MetadataMutation,
        operation: "chmod/chown/utimens",
        support: PosixSupport::IncludedAfterCurrentUserspaceImpl,
        errno: "ENOENT",
        rule: "PC-001M stores ownership and mode mutations in FUSE session metadata; these are visible through getattr within the session but are not persisted across remounts.",
    },
    PosixSubsetEntry {
        topic: PosixTopic::ExtendedAttributes,
        operation: "xattr/acl",
        support: PosixSupport::IncludedAfterCurrentUserspaceImpl,
        errno: "ENODATA/EINVAL/EPERM/EOPNOTSUPP",
        rule: "setxattr/getxattr/listxattr/removexattr wired (PC-006, v0.418). POSIX ACL access/default xattrs are validated and stored through tidefs_posix_acl; unsupported namespaces and structurally invalid ACL payloads still fail explicitly.",
    },
    PosixSubsetEntry {
        topic: PosixTopic::FileLocking,
        operation: "flock/posix-locks",
        support: PosixSupport::IncludedAfterCurrentUserspaceImpl,
        errno: "EOPNOTSUPP",
        rule: "getlk/setlk handlers wired (PC-007, v0.419) and exercised through mounted byte-range lock coverage (#2931). getlk reports tracked conflicts, non-blocking locks update LockTracker, shared read locks coexist, overlapping write locks conflict, adjacent ranges remain independent, and close/flush releases PID-owned ranges. Blocking/cancelable setlkw semantics remain Review debt TFR-008.",
    },
    PosixSubsetEntry {
        topic: PosixTopic::SpaceManagement,
        operation: "fallocate",
        support: PosixSupport::IncludedAfterCurrentUserspaceImpl,
        errno: "ENOSPC/EOPNOTSUPP",
        rule: "OW-102 includes fallocate mode 0 as allocator-admitted zero extension over the chunked content layout; unsupported mode flags still return EOPNOTSUPP.",
    },
    PosixSubsetEntry {
        topic: PosixTopic::MmapCoherency,
        operation: "mmap-coherency",
        support: PosixSupport::DeferredAfterCurrentImpl,
        errno: "EOPNOTSUPP",
        rule: "OW-204 specifies page-cache/writeback/mmap law, but live mmap coherency remains deferred until runtime implementation and live mmap tests exist.",
    },
    PosixSubsetEntry {
        topic: PosixTopic::SparseDiscovery,
        operation: "lseek: SEEK_SET/SEEK_END/SEEK_DATA/SEEK_HOLE",
        support: PosixSupport::IncludedAfterCurrentUserspaceImpl,
        errno: "EINVAL/ENXIO/EOPNOTSUPP",
        rule: "PC-004B includes extent-map-backed FUSE lseek answers: SEEK_SET and SEEK_END report valid offsets, SEEK_DATA and SEEK_HOLE are derived from VfsEngine::data_ranges sparse intervals, offsets at or beyond EOF return ENXIO, and SEEK_CUR remains EOPNOTSUPP until current-offset authority exists.",
    },
    PosixSubsetEntry {
        topic: PosixTopic::SparseDiscovery,
        operation: "fiemap",
        support: PosixSupport::IncludedAfterCurrentUserspaceImpl,
        errno: "EINVAL/EIO/EOPNOTSUPP",
        rule: "FS_IOC_FIEMAP is included in the current userspace implementation because VfsEngine::data_ranges now exposes extent-map-backed sparse intervals without inventing dense-file layout truth.",
    },
    PosixSubsetEntry {
        topic: PosixTopic::SpecialInodes,
        operation: "mknod-device/fifo/socket",
        support: PosixSupport::ExplicitlyUnsupported,
        errno: "EOPNOTSUPP",
        rule: "Device nodes, FIFOs, and socket inode creation are explicitly unsupported in the current userspace implementation.",
    },
];

pub const fn posix_subset_entries() -> &'static [PosixSubsetEntry] {
    POSIX_SUBSET_ENTRIES
}

pub const PAGE_CACHE_WRITEBACK_MMAP_SPEC: &str = "TideFS storage item 204 page-cache/writeback/mmap integration: buffered writes, shared mmap, private mmap, direct uncached paths, invalidation, and fsync durability are specified as anchor-bound non-authoritative page-cache states with explicit dirty epochs, writeback batches, and invalidation intents";
pub const PAGE_CACHE_WRITEBACK_MMAP_POLICY_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PageCacheCoherencyClass {
    BufferedCached,
    SharedMmapWriteback,
    PrivateMmapCow,
    DirectUncached,
    ExecReadonly,
    InvalidateTransition,
}

impl PageCacheCoherencyClass {
    pub const fn stable_id(self) -> &'static str {
        match self {
            Self::BufferedCached => "cache_coherency_0.buffered_cached",
            Self::SharedMmapWriteback => "cache_coherency_1.shared_mmap_writeback",
            Self::PrivateMmapCow => "cache_coherency_2.private_mmap_cow",
            Self::DirectUncached => "cache_coherency_3.direct_uncached",
            Self::ExecReadonly => "cache_coherency_4.exec_readonly",
            Self::InvalidateTransition => "cache_coherency_5.invalidate_transition",
        }
    }

    pub const fn human_name(self) -> &'static str {
        match self {
            Self::BufferedCached => "buffered cached",
            Self::SharedMmapWriteback => "shared mmap writeback",
            Self::PrivateMmapCow => "private mmap copy-on-write",
            Self::DirectUncached => "direct uncached",
            Self::ExecReadonly => "exec readonly",
            Self::InvalidateTransition => "invalidate transition",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PageCacheVisibilityState {
    CleanVisible,
    DirtyPrivate,
    DirtyShared,
    WritebackPending,
    InvalidateWait,
    Poisoned,
}

impl PageCacheVisibilityState {
    pub const fn stable_id(self) -> &'static str {
        match self {
            Self::CleanVisible => "vis.clean_visible",
            Self::DirtyPrivate => "vis.dirty_private",
            Self::DirtyShared => "vis.dirty_shared",
            Self::WritebackPending => "vis.writeback_pending",
            Self::InvalidateWait => "vis.invalidate_wait",
            Self::Poisoned => "vis.poisoned",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageCacheWritebackMmapCase {
    pub operation: &'static str,
    pub coherency_class: PageCacheCoherencyClass,
    pub visibility_state: PageCacheVisibilityState,
    pub requires_anchor: bool,
    pub requires_dirty_epoch: bool,
    pub requires_writeback_batch: bool,
    pub requires_invalidate_intent: bool,
    pub requires_durable_fsync_boundary: bool,
    pub rule: &'static str,
}

pub const PAGE_CACHE_WRITEBACK_MMAP_ACCEPTANCE_CASES: &[PageCacheWritebackMmapCase] = &[
    PageCacheWritebackMmapCase {
        operation: "buffered-writeback",
        coherency_class: PageCacheCoherencyClass::BufferedCached,
        visibility_state: PageCacheVisibilityState::DirtyShared,
        requires_anchor: true,
        requires_dirty_epoch: true,
        requires_writeback_batch: true,
        requires_invalidate_intent: false,
        requires_durable_fsync_boundary: false,
        rule: "Buffered writes join dirty epochs and sealed writeback batches before returning clean; page-cache bytes remain a non-authoritative mirror.",
    },
    PageCacheWritebackMmapCase {
        operation: "shared-mmap-msync",
        coherency_class: PageCacheCoherencyClass::SharedMmapWriteback,
        visibility_state: PageCacheVisibilityState::DirtyShared,
        requires_anchor: true,
        requires_dirty_epoch: true,
        requires_writeback_batch: true,
        requires_invalidate_intent: false,
        requires_durable_fsync_boundary: true,
        rule: "Shared writable mmap dirties join the same dirty epoch and writeback law as buffered writes; MS_SYNC waits for the durability boundary required by charter policy.",
    },
    PageCacheWritebackMmapCase {
        operation: "private-mmap-cow",
        coherency_class: PageCacheCoherencyClass::PrivateMmapCow,
        visibility_state: PageCacheVisibilityState::DirtyPrivate,
        requires_anchor: true,
        requires_dirty_epoch: false,
        requires_writeback_batch: false,
        requires_invalidate_intent: false,
        requires_durable_fsync_boundary: false,
        rule: "Private writable mappings may dirty private copy-on-write bytes but do not create publication-visible dirty epochs or shared durability claims.",
    },
    PageCacheWritebackMmapCase {
        operation: "truncate-invalidate",
        coherency_class: PageCacheCoherencyClass::InvalidateTransition,
        visibility_state: PageCacheVisibilityState::InvalidateWait,
        requires_anchor: true,
        requires_dirty_epoch: false,
        requires_writeback_batch: false,
        requires_invalidate_intent: true,
        requires_durable_fsync_boundary: false,
        rule: "Truncate, punch, collapse, insert, resize, and cutover issue explicit invalidate intents before new faults can observe shifted truth, so stale page-cache state cannot become authority.",
    },
    PageCacheWritebackMmapCase {
        operation: "direct-write-reconcile",
        coherency_class: PageCacheCoherencyClass::DirectUncached,
        visibility_state: PageCacheVisibilityState::InvalidateWait,
        requires_anchor: true,
        requires_dirty_epoch: false,
        requires_writeback_batch: true,
        requires_invalidate_intent: true,
        requires_durable_fsync_boundary: false,
        rule: "Direct writes first drain overlapping dirty cached windows and invalidate overlapping clean cached windows; bypassing cache does not bypass authority.",
    },
    PageCacheWritebackMmapCase {
        operation: "fsync-durability",
        coherency_class: PageCacheCoherencyClass::BufferedCached,
        visibility_state: PageCacheVisibilityState::WritebackPending,
        requires_anchor: true,
        requires_dirty_epoch: true,
        requires_writeback_batch: true,
        requires_invalidate_intent: false,
        requires_durable_fsync_boundary: true,
        rule: "fsync, fdatasync, O_SYNC, and synchronous mmap durability wait for storage writeback plus publication or storage-commit receipts, not merely clean page-cache state.",
    },
    PageCacheWritebackMmapCase {
        operation: "exec-readonly-populate",
        coherency_class: PageCacheCoherencyClass::ExecReadonly,
        visibility_state: PageCacheVisibilityState::CleanVisible,
        requires_anchor: true,
        requires_dirty_epoch: false,
        requires_writeback_batch: false,
        requires_invalidate_intent: false,
        requires_durable_fsync_boundary: false,
        rule: "Executable and readonly mappings may share clean populate windows but still carry anchor context and remain non-authoritative cache visibility.",
    },
];

pub const fn page_cache_writeback_mmap_acceptance_cases() -> &'static [PageCacheWritebackMmapCase] {
    PAGE_CACHE_WRITEBACK_MMAP_ACCEPTANCE_CASES
}

pub const INTENT_LOG_SYNC_WRITE_LATENCY_SPEC: &str = "publishing checklist item PC-008 intent-log analogue: sync writes, O_DSYNC ranges, fsync drains, and synchronous mmap writes must either complete through existing durable publication or record a replayable intent receipt under an explicit latency budget before reporting bounded sync completion";
pub const INTENT_LOG_SYNC_WRITE_LATENCY_POLICY_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntentLogLatencyClass {
    SyncWriteRange,
    OdsyncDataRange,
    FsyncDirtyDrain,
    SharedMmapSync,
    NamespaceSyncIntent,
    PressureFallback,
    CrashReplayReconcile,
}

impl IntentLogLatencyClass {
    pub const fn stable_id(self) -> &'static str {
        match self {
            Self::SyncWriteRange => "intent_latency_0.sync_write_range",
            Self::OdsyncDataRange => "intent_latency_1.odsync_data_range",
            Self::FsyncDirtyDrain => "intent_latency_2.fsync_dirty_drain",
            Self::SharedMmapSync => "intent_latency_3.shared_mmap_sync",
            Self::NamespaceSyncIntent => "intent_latency_4.namespace_sync_intent",
            Self::PressureFallback => "intent_latency_5.pressure_fallback",
            Self::CrashReplayReconcile => "intent_latency_6.crash_replay_reconcile",
        }
    }

    pub const fn human_name(self) -> &'static str {
        match self {
            Self::SyncWriteRange => "sync write range",
            Self::OdsyncDataRange => "O_DSYNC data range",
            Self::FsyncDirtyDrain => "fsync dirty drain",
            Self::SharedMmapSync => "shared mmap sync",
            Self::NamespaceSyncIntent => "namespace sync intent",
            Self::PressureFallback => "pressure fallback",
            Self::CrashReplayReconcile => "crash replay reconcile",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntentLogReplyState {
    NoIntentNeeded,
    IntentOpen,
    IntentSealed,
    IntentDurable,
    PublicationPending,
    ReplyEligible,
    Refused,
    ReplayOnly,
}

impl IntentLogReplyState {
    pub const fn stable_id(self) -> &'static str {
        match self {
            Self::NoIntentNeeded => "intent_state.no_intent_needed",
            Self::IntentOpen => "intent_state.intent_open",
            Self::IntentSealed => "intent_state.intent_sealed",
            Self::IntentDurable => "intent_state.intent_durable",
            Self::PublicationPending => "intent_state.publication_pending",
            Self::ReplyEligible => "intent_state.reply_eligible",
            Self::Refused => "intent_state.refused",
            Self::ReplayOnly => "intent_state.replay_only",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IntentLogSyncWriteLatencyCase {
    pub operation: &'static str,
    pub latency_class: IntentLogLatencyClass,
    pub reply_state: IntentLogReplyState,
    pub requires_replayable_intent: bool,
    pub requires_payload_digest: bool,
    pub requires_metadata_delta: bool,
    pub requires_latency_budget: bool,
    pub may_fallback_to_full_commit: bool,
    pub reply_rule: &'static str,
}

pub const INTENT_LOG_SYNC_WRITE_LATENCY_CASES: &[IntentLogSyncWriteLatencyCase] = &[
    IntentLogSyncWriteLatencyCase {
        operation: "sync-write-range",
        latency_class: IntentLogLatencyClass::SyncWriteRange,
        reply_state: IntentLogReplyState::ReplyEligible,
        requires_replayable_intent: true,
        requires_payload_digest: true,
        requires_metadata_delta: true,
        requires_latency_budget: true,
        may_fallback_to_full_commit: true,
        reply_rule: "A bounded sync write reply is legal only after the range payload digest, file-size delta, inode version delta, and target root anchor are sealed in a durable replayable intent or after the full normal commit completes.",
    },
    IntentLogSyncWriteLatencyCase {
        operation: "odsync-data-range",
        latency_class: IntentLogLatencyClass::OdsyncDataRange,
        reply_state: IntentLogReplyState::ReplyEligible,
        requires_replayable_intent: true,
        requires_payload_digest: true,
        requires_metadata_delta: false,
        requires_latency_budget: true,
        may_fallback_to_full_commit: true,
        reply_rule: "O_DSYNC may omit unrelated metadata from the fast intent, but the data range, extent/chunk identities, payload digest, and file-size-affecting metadata must be replayable before success.",
    },
    IntentLogSyncWriteLatencyCase {
        operation: "fsync-dirty-drain",
        latency_class: IntentLogLatencyClass::FsyncDirtyDrain,
        reply_state: IntentLogReplyState::PublicationPending,
        requires_replayable_intent: true,
        requires_payload_digest: true,
        requires_metadata_delta: true,
        requires_latency_budget: false,
        may_fallback_to_full_commit: true,
        reply_rule: "fsync drains all dirty windows and sealed intents for the file into the normal root-slot publication boundary before reporting durable completion.",
    },
    IntentLogSyncWriteLatencyCase {
        operation: "shared-mmap-msync-sync",
        latency_class: IntentLogLatencyClass::SharedMmapSync,
        reply_state: IntentLogReplyState::ReplyEligible,
        requires_replayable_intent: true,
        requires_payload_digest: true,
        requires_metadata_delta: false,
        requires_latency_budget: true,
        may_fallback_to_full_commit: true,
        reply_rule: "MS_SYNC for shared writable mappings uses the same replayable range intent law as buffered sync writes, and cannot report bounded completion from clean page-cache state alone.",
    },
    IntentLogSyncWriteLatencyCase {
        operation: "namespace-sync-intent",
        latency_class: IntentLogLatencyClass::NamespaceSyncIntent,
        reply_state: IntentLogReplyState::IntentDurable,
        requires_replayable_intent: true,
        requires_payload_digest: false,
        requires_metadata_delta: true,
        requires_latency_budget: true,
        may_fallback_to_full_commit: true,
        reply_rule: "A low-latency namespace intent must name parent directories, affected inode ids, link-count deltas, and conflict guards before it can substitute for a full immediate namespace commit.",
    },
    IntentLogSyncWriteLatencyCase {
        operation: "pressure-fallback",
        latency_class: IntentLogLatencyClass::PressureFallback,
        reply_state: IntentLogReplyState::Refused,
        requires_replayable_intent: false,
        requires_payload_digest: false,
        requires_metadata_delta: false,
        requires_latency_budget: true,
        may_fallback_to_full_commit: true,
        reply_rule: "If the intent reserve, dirty-window reserve, or latency budget is exhausted, the system must refuse the bounded-latency path or complete the full commit before success; it must not pretend the fast path passed.",
    },
    IntentLogSyncWriteLatencyCase {
        operation: "crash-replay-reconcile",
        latency_class: IntentLogLatencyClass::CrashReplayReconcile,
        reply_state: IntentLogReplyState::ReplayOnly,
        requires_replayable_intent: true,
        requires_payload_digest: true,
        requires_metadata_delta: true,
        requires_latency_budget: false,
        may_fallback_to_full_commit: false,
        reply_rule: "After a crash, each durable intent must either replay exactly once into a normal committed root or be rejected as an explicit integrity/media error; Partial mounted truth is forbidden.",
    },
];

pub const fn intent_log_sync_write_latency_cases() -> &'static [IntentLogSyncWriteLatencyCase] {
    INTENT_LOG_SYNC_WRITE_LATENCY_CASES
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilesystemCommitBoundary {
    TransactionObjectsWritten,
    TransactionObjectsSynced,
    RootCommitWritten,
    RootCommitSynced,
}

impl FilesystemCommitBoundary {
    pub const fn human_name(self) -> &'static str {
        match self {
            Self::TransactionObjectsWritten => {
                "transaction objects written before transaction sync"
            }
            Self::TransactionObjectsSynced => {
                "transaction objects synced before root commit publication"
            }
            Self::RootCommitWritten => "root commit written before root commit sync",
            Self::RootCommitSynced => "root commit synced and durable boundary reached",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CrashInjectionBoundary {
    NoCrash,
    BeforeContentObjects,
    AfterContentObjects,
    AfterTransactionInodes,
    AfterTransactionDirectories,
    AfterTransactionSuperblock,
    AfterTransactionObjectsSynced,
    AfterMalformedRootCommit,
    AfterRootCommitMissingTransaction,
    AfterRootCommitWritten,
    AfterRootCommitSynced,
}

impl CrashInjectionBoundary {
    pub const ALL: [Self; 11] = [
        Self::NoCrash,
        Self::BeforeContentObjects,
        Self::AfterContentObjects,
        Self::AfterTransactionInodes,
        Self::AfterTransactionDirectories,
        Self::AfterTransactionSuperblock,
        Self::AfterTransactionObjectsSynced,
        Self::AfterMalformedRootCommit,
        Self::AfterRootCommitMissingTransaction,
        Self::AfterRootCommitWritten,
        Self::AfterRootCommitSynced,
    ];

    pub const fn human_name(self) -> &'static str {
        match self {
            Self::NoCrash => "no crash",
            Self::BeforeContentObjects => "before content objects",
            Self::AfterContentObjects => "after content objects",
            Self::AfterTransactionInodes => "after transaction inode objects",
            Self::AfterTransactionDirectories => "after transaction directory objects",
            Self::AfterTransactionSuperblock => "after transaction superblock",
            Self::AfterTransactionObjectsSynced => "after transaction object sync",
            Self::AfterMalformedRootCommit => "after malformed root-slot candidate",
            Self::AfterRootCommitMissingTransaction => {
                "after root-slot candidate references missing transaction objects"
            }
            Self::AfterRootCommitWritten => "after root-slot commit write before sync",
            Self::AfterRootCommitSynced => "after root-slot commit sync",
        }
    }

    pub const fn stable_id(self) -> &'static str {
        match self {
            Self::NoCrash => "no-crash",
            Self::BeforeContentObjects => "before-content-objects",
            Self::AfterContentObjects => "after-content-objects",
            Self::AfterTransactionInodes => "after-transaction-inodes",
            Self::AfterTransactionDirectories => "after-transaction-directories",
            Self::AfterTransactionSuperblock => "after-transaction-superblock",
            Self::AfterTransactionObjectsSynced => "after-transaction-objects-synced",
            Self::AfterMalformedRootCommit => "after-malformed-root-commit",
            Self::AfterRootCommitMissingTransaction => "after-root-commit-missing-transaction",
            Self::AfterRootCommitWritten => "after-root-commit-written",
            Self::AfterRootCommitSynced => "after-root-commit-synced",
        }
    }

    pub const fn expected_recovery(self) -> CrashRecoveryExpectation {
        match self {
            Self::NoCrash | Self::AfterRootCommitSynced => {
                CrashRecoveryExpectation::NewCommittedRoot
            }
            Self::AfterRootCommitWritten => CrashRecoveryExpectation::OldOrNewCommittedRoot,
            Self::BeforeContentObjects
            | Self::AfterContentObjects
            | Self::AfterTransactionInodes
            | Self::AfterTransactionDirectories
            | Self::AfterTransactionSuperblock
            | Self::AfterTransactionObjectsSynced
            | Self::AfterMalformedRootCommit
            | Self::AfterRootCommitMissingTransaction => CrashRecoveryExpectation::OldCommittedRoot,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CrashRecoveryObservedOutcome {
    PreviousCommittedRoot,
    NewCommittedRoot,
    ExplicitIntegrityOrMediaError,
}

impl CrashRecoveryObservedOutcome {
    pub const fn human_name(self) -> &'static str {
        match self {
            Self::PreviousCommittedRoot => "previous committed root",
            Self::NewCommittedRoot => "new committed root",
            Self::ExplicitIntegrityOrMediaError => "explicit integrity/media error",
        }
    }

    pub const fn satisfies(self, expectation: CrashRecoveryExpectation) -> bool {
        match expectation {
            CrashRecoveryExpectation::OldCommittedRoot => {
                matches!(self, Self::PreviousCommittedRoot)
            }
            CrashRecoveryExpectation::NewCommittedRoot => matches!(self, Self::NewCommittedRoot),
            CrashRecoveryExpectation::OldOrNewCommittedRoot => {
                matches!(self, Self::PreviousCommittedRoot | Self::NewCommittedRoot)
            }
            CrashRecoveryExpectation::ExplicitIntegrityOrMediaError => {
                matches!(self, Self::ExplicitIntegrityOrMediaError)
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrashRecoveryCaseReport {
    pub boundary: CrashInjectionBoundary,
    pub expected: CrashRecoveryExpectation,
    pub observed: CrashRecoveryObservedOutcome,
    pub stable_generation: u64,
    pub candidate_generation: u64,
    pub selected_generation: Option<u64>,
    pub object_store_repaired_tail_bytes: u64,
    pub production_fsck_required: bool,
}

impl CrashRecoveryCaseReport {
    pub const fn passed(&self) -> bool {
        self.observed.satisfies(self.expected) && !self.production_fsck_required
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrashRecoveryExplicitErrorReport {
    pub observed: CrashRecoveryObservedOutcome,
    pub root_slot_records_seen: u64,
    pub valid_committed_roots_seen: u64,
    pub production_fsck_required: bool,
}

impl CrashRecoveryExplicitErrorReport {
    pub const fn passed(&self) -> bool {
        self.observed
            .satisfies(CrashRecoveryExpectation::ExplicitIntegrityOrMediaError)
            && self.root_slot_records_seen == FILESYSTEM_ROOT_SLOT_COUNT
            && self.valid_committed_roots_seen == 0
            && !self.production_fsck_required
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrashRecoveryMatrixReport {
    pub design_rule: &'static str,
    pub matrix_root: PathBuf,
    pub boundary_cases: Vec<CrashRecoveryCaseReport>,
    pub explicit_error_case: CrashRecoveryExplicitErrorReport,
}

impl CrashRecoveryMatrixReport {
    pub fn cases_executed(&self) -> usize {
        self.boundary_cases.len() + 1
    }

    pub fn passed(&self) -> bool {
        self.boundary_cases
            .iter()
            .all(CrashRecoveryCaseReport::passed)
            && self.explicit_error_case.passed()
    }

    pub fn previous_root_cases(&self) -> usize {
        self.boundary_cases
            .iter()
            .filter(|case| case.observed == CrashRecoveryObservedOutcome::PreviousCommittedRoot)
            .count()
    }

    pub fn new_root_cases(&self) -> usize {
        self.boundary_cases
            .iter()
            .filter(|case| case.observed == CrashRecoveryObservedOutcome::NewCommittedRoot)
            .count()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CrashRecoveryExpectation {
    OldCommittedRoot,
    NewCommittedRoot,
    OldOrNewCommittedRoot,
    ExplicitIntegrityOrMediaError,
}

impl CrashRecoveryExpectation {
    pub const fn human_name(self) -> &'static str {
        match self {
            Self::OldCommittedRoot => "previous committed root",
            Self::NewCommittedRoot => "new committed root",
            Self::OldOrNewCommittedRoot => "previous or new committed root",
            Self::ExplicitIntegrityOrMediaError => "explicit integrity/media error",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NoProductionFsckFailureClass {
    CleanDurableCommit,
    SyncSemantics,
    WriteReordering,
    TornFinalAppend,
    LostUnsyncedWrite,
    RootCandidateMediaCorruption,
    AllRootSlotsInvalid,
    ExplicitStorageError,
}

impl NoProductionFsckFailureClass {
    pub const fn human_name(self) -> &'static str {
        match self {
            Self::CleanDurableCommit => "clean durable commit",
            Self::SyncSemantics => "sync semantics",
            Self::WriteReordering => "write reordering",
            Self::TornFinalAppend => "torn writes",
            Self::LostUnsyncedWrite => "lost writes",
            Self::RootCandidateMediaCorruption => "media corruption",
            Self::AllRootSlotsInvalid => "all root slots invalid",
            Self::ExplicitStorageError => "explicit-error behavior",
        }
    }

    pub const fn stable_id(self) -> &'static str {
        match self {
            Self::CleanDurableCommit => "clean-durable-commit",
            Self::SyncSemantics => "sync-semantics",
            Self::WriteReordering => "write-reordering",
            Self::TornFinalAppend => "torn-writes",
            Self::LostUnsyncedWrite => "lost-writes",
            Self::RootCandidateMediaCorruption => "media-corruption",
            Self::AllRootSlotsInvalid => "all-root-slots-invalid",
            Self::ExplicitStorageError => "explicit-error-behavior",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NoProductionFsckFailureModelCase {
    pub failure_class: NoProductionFsckFailureClass,
    pub model_rule: &'static str,
    pub expected_recovery: CrashRecoveryExpectation,
    pub covered_by: &'static str,
    pub production_fsck_required: bool,
}

impl NoProductionFsckFailureModelCase {
    pub const fn admits_only_allowed_outcomes(self) -> bool {
        !self.production_fsck_required
    }
}

pub const NO_PRODUCTION_FSCK_FAILURE_MODEL_CASES: &[NoProductionFsckFailureModelCase] = &[
    NoProductionFsckFailureModelCase {
        failure_class: NoProductionFsckFailureClass::CleanDurableCommit,
        model_rule: "a completed root-slot sync is the durable publication point",
        expected_recovery: CrashRecoveryExpectation::NewCommittedRoot,
        covered_by: "CrashInjectionBoundary::AfterRootCommitSynced",
        production_fsck_required: false,
    },
    NoProductionFsckFailureModelCase {
        failure_class: NoProductionFsckFailureClass::SyncSemantics,
        model_rule: "sync semantics make transaction-object sync a staging durability boundary and root-slot sync the publication boundary",
        expected_recovery: CrashRecoveryExpectation::OldOrNewCommittedRoot,
        covered_by: "FilesystemCommitBoundary::{TransactionObjectsSynced,RootCommitWritten,RootCommitSynced}",
        production_fsck_required: false,
    },
    NoProductionFsckFailureModelCase {
        failure_class: NoProductionFsckFailureClass::WriteReordering,
        model_rule: "write reordering may expose transaction objects, root candidates, both, or neither; recovery validates references before selecting truth",
        expected_recovery: CrashRecoveryExpectation::OldOrNewCommittedRoot,
        covered_by: "CrashInjectionBoundary::{AfterTransactionObjectsSynced,AfterRootCommitMissingTransaction,AfterRootCommitWritten}",
        production_fsck_required: false,
    },
    NoProductionFsckFailureModelCase {
        failure_class: NoProductionFsckFailureClass::TornFinalAppend,
        model_rule: "torn writes at the final object-store append tail are replay-truncated automatically when repair_torn_tail is enabled",
        expected_recovery: CrashRecoveryExpectation::OldCommittedRoot,
        covered_by: "truncated_tail_is_repaired_without_losing_committed_record",
        production_fsck_required: false,
    },
    NoProductionFsckFailureModelCase {
        failure_class: NoProductionFsckFailureClass::LostUnsyncedWrite,
        model_rule: "lost writes that were not durably synced may erase staging objects or a pre-sync root candidate but cannot create partial mounted truth",
        expected_recovery: CrashRecoveryExpectation::OldOrNewCommittedRoot,
        covered_by: "CrashInjectionBoundary::{BeforeContentObjects,AfterRootCommitWritten}",
        production_fsck_required: false,
    },
    NoProductionFsckFailureModelCase {
        failure_class: NoProductionFsckFailureClass::RootCandidateMediaCorruption,
        model_rule: "media corruption in a newer root candidate, transaction manifest, transaction object, or mount invariant skips that candidate when an older valid committed root exists",
        expected_recovery: CrashRecoveryExpectation::OldCommittedRoot,
        covered_by: "invalid_newer_root_slot_is_skipped_without_operator_repair",
        production_fsck_required: false,
    },
    NoProductionFsckFailureModelCase {
        failure_class: NoProductionFsckFailureClass::AllRootSlotsInvalid,
        model_rule: "if root-slot records exist but every candidate is invalid, recovery reports an explicit integrity/media error instead of guessing a repair",
        expected_recovery: CrashRecoveryExpectation::ExplicitIntegrityOrMediaError,
        covered_by: "all_root_slots_invalid_reports_explicit_integrity_error_without_fsck",
        production_fsck_required: false,
    },
    NoProductionFsckFailureModelCase {
        failure_class: NoProductionFsckFailureClass::ExplicitStorageError,
        model_rule: "explicit-error behavior propagates object-store I/O, checksum, unsupported-version, and non-final-segment corruption errors as errors, not repair prompts",
        expected_recovery: CrashRecoveryExpectation::ExplicitIntegrityOrMediaError,
        covered_by: "checksum_mismatch_rejects_replay and non-final segment corruption checks",
        production_fsck_required: false,
    },
];

pub const fn no_production_fsck_failure_model_cases() -> &'static [NoProductionFsckFailureModelCase]
{
    NO_PRODUCTION_FSCK_FAILURE_MODEL_CASES
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalStorageResource {
    ContentBytes,
    Inodes,
}

impl LocalStorageResource {
    pub const fn human_name(self) -> &'static str {
        match self {
            Self::ContentBytes => "content bytes",
            Self::Inodes => "inodes",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalStorageAllocatorPolicy {
    pub content_capacity_bytes: u64,
    pub inode_capacity: u64,
}

impl LocalStorageAllocatorPolicy {
    pub const fn new(content_capacity_bytes: u64, inode_capacity: u64) -> Self {
        Self {
            content_capacity_bytes,
            inode_capacity,
        }
    }

    pub const fn default_coherency() -> Self {
        Self {
            content_capacity_bytes: DEFAULT_LOCAL_FILESYSTEM_CONTENT_CAPACITY_BYTES,
            inode_capacity: DEFAULT_LOCAL_FILESYSTEM_INODE_CAPACITY,
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.content_capacity_bytes == 0 {
            return Err(FileSystemError::Unsupported {
                operation: "allocator policy",
                reason: "content capacity must be non-zero",
            });
        }
        if self.inode_capacity < 1 {
            return Err(FileSystemError::Unsupported {
                operation: "allocator policy",
                reason: "inode capacity must include at least the root inode",
            });
        }
        Ok(())
    }

    pub fn resize(&self, content_capacity_bytes: u64, inode_capacity: u64) -> Result<Self> {
        let resized = Self {
            content_capacity_bytes,
            inode_capacity,
        };
        resized.validate()?;
        Ok(resized)
    }
}

impl Default for LocalStorageAllocatorPolicy {
    fn default() -> Self {
        Self::default_coherency()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalStorageAllocatorReport {
    pub spec: &'static str,
    pub policy: LocalStorageAllocatorPolicy,
    pub grain_bytes: u64,
    pub current_namespace_allocated_bytes: u64,
    pub protected_committed_root_allocated_bytes: u64,
    pub protected_committed_roots: u64,
    pub unique_current_content_objects: u64,
    pub unique_protected_content_objects: u64,
    pub allocator_reserved_bytes: u64,
    pub pending_free_bytes: u64,
    pub reusable_free_bytes: u64,
    pub inode_count: u64,
    pub free_inodes: u64,
    pub enospc_enforced: bool,
    pub statfs_capacity_reporting: bool,
    pub production_fsck_required: bool,
}

impl LocalStorageAllocatorReport {
    pub fn to_statfs(self) -> FileSystemStatfs {
        let blocks = self.policy.content_capacity_bytes / self.grain_bytes;
        let bfree = self.reusable_free_bytes / self.grain_bytes;
        FileSystemStatfs {
            blocks,
            bfree,
            bavail: bfree,
            files: self.policy.inode_capacity,
            ffree: self.free_inodes,
            bsize: content_chunk_size() as u64 as u32,
            namelen: MAX_NAME_BYTES as u32,
            frsize: content_chunk_size() as u64 as u32,
            fsid_hi: 0,
            fsid_lo: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileSystemStatfs {
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub bsize: u32,
    pub namelen: u32,
    pub frsize: u32,
    pub fsid_hi: u32,
    pub fsid_lo: u32,
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub struct RootAuthenticationDigest([u8; ROOT_AUTHENTICATION_DIGEST_LEN]);

impl RootAuthenticationDigest {
    pub const ZERO: Self = Self([0_u8; ROOT_AUTHENTICATION_DIGEST_LEN]);

    pub const fn from_bytes32(bytes: [u8; ROOT_AUTHENTICATION_DIGEST_LEN]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes32(self) -> [u8; ROOT_AUTHENTICATION_DIGEST_LEN] {
        self.0
    }

    pub const fn is_zero(self) -> bool {
        let mut idx = 0_usize;
        while idx < ROOT_AUTHENTICATION_DIGEST_LEN {
            if self.0[idx] != 0 {
                return false;
            }
            idx += 1;
        }
        true
    }
}

impl fmt::Debug for RootAuthenticationDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RootAuthenticationDigest({self})")
    }
}

impl fmt::Display for RootAuthenticationDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub struct RootAuthenticationCode([u8; ROOT_AUTHENTICATION_CODE_LEN]);

impl RootAuthenticationCode {
    pub const ZERO: Self = Self([0_u8; ROOT_AUTHENTICATION_CODE_LEN]);

    pub const fn from_bytes32(bytes: [u8; ROOT_AUTHENTICATION_CODE_LEN]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes32(self) -> [u8; ROOT_AUTHENTICATION_CODE_LEN] {
        self.0
    }
}

impl fmt::Debug for RootAuthenticationCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RootAuthenticationCode({self})")
    }
}

impl fmt::Display for RootAuthenticationCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Cryptographic key that authenticates committed-root slot summaries.
///
/// Every committed-root publication appends a [`RootAuthenticationRecord`]
/// with a `superblock_digest` and `authentication_code`. The
/// [`RootAuthenticationKey`] is used to verify that record before the
/// filesystem trusts the root snapshot. In production the key is read
/// from the `TIDEFS_ROOT_AUTHENTICATION_KEY` environment variable; test
/// builds use [`RootAuthenticationKey::demo_key`].
///
/// The key itself is a fixed-size 32-byte symmetric secret. It is
/// redacted in [`Debug`] output and never persisted to disk.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RootAuthenticationKey([u8; ROOT_AUTHENTICATION_KEY_LEN]);

impl RootAuthenticationKey {
    pub const fn from_bytes32(bytes: [u8; ROOT_AUTHENTICATION_KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes32(self) -> [u8; ROOT_AUTHENTICATION_KEY_LEN] {
        self.0
    }

    pub fn from_hex(value: &str) -> Result<Self> {
        let trimmed = value.trim();
        if trimmed.len() != ROOT_AUTHENTICATION_KEY_LEN * 2 {
            return Err(FileSystemError::InvalidRootAuthenticationKey {
                reason: "root authentication key must be 64 lowercase or uppercase hex characters",
            });
        }
        let mut bytes = [0_u8; ROOT_AUTHENTICATION_KEY_LEN];
        for (idx, chunk) in trimmed.as_bytes().chunks_exact(2).enumerate() {
            bytes[idx] = (decode_hex_nibble(chunk[0])? << 4) | decode_hex_nibble(chunk[1])?;
        }
        Ok(Self(bytes))
    }

    pub fn from_environment() -> Result<Self> {
        let value = env::var(ROOT_AUTHENTICATION_ENV_VAR).map_err(|_| {
            FileSystemError::MissingRootAuthenticationKey {
                env_var: ROOT_AUTHENTICATION_ENV_VAR,
            }
        })?;
        Self::from_hex(&value)
    }

    pub const fn demo_key() -> Self {
        Self([0x41_u8; ROOT_AUTHENTICATION_KEY_LEN])
    }
}

impl fmt::Debug for RootAuthenticationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RootAuthenticationKey(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootAuthenticationRecord {
    pub record_version: u16,
    pub algorithm_suite_id: u16,
    pub policy_epoch: u64,
    pub superblock_digest: RootAuthenticationDigest,
    pub manifest_digest: RootAuthenticationDigest,
    pub authentication_code: RootAuthenticationCode,
}

fn decode_hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(FileSystemError::InvalidRootAuthenticationKey {
            reason: "root authentication key contains a non-hex character",
        }),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryAuditOutcome {
    EmptyStore,
    SelectedCommittedRoot,
    ExplicitIntegrityOrMediaError,
}

impl RecoveryAuditOutcome {
    pub const fn human_name(self) -> &'static str {
        match self {
            Self::EmptyStore => "empty store with no root-slot commits",
            Self::SelectedCommittedRoot => "selected committed root automatically",
            Self::ExplicitIntegrityOrMediaError => "explicit integrity/media error",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedRootSummary {
    pub slot: u64,
    pub transaction_id: u64,
    pub generation: u64,
    pub next_inode_id: u64,
    pub inode_count: u64,
    pub superblock_checksum: IntegrityDigest64,
    pub has_transaction_manifest: bool,
    pub manifest_checksum: IntegrityDigest64,
    pub manifest_entry_count: u64,
    pub has_root_authentication: bool,
    pub root_authentication_policy_epoch: Option<u64>,
    pub root_authentication_algorithm_suite_id: Option<u16>,
    pub superblock_digest: Option<RootAuthenticationDigest>,
    pub manifest_digest: Option<RootAuthenticationDigest>,
    pub root_authentication_code: Option<RootAuthenticationCode>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotSummary {
    pub name: String,
    pub source_transaction_id: u64,
    pub source_generation: u64,
    pub created_at_generation: u64,
    pub source_root: CommittedRootSummary,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotRollbackReport {
    pub spec: &'static str,
    pub snapshot: SnapshotSummary,
    pub generation_before: u64,
    pub restored_source_generation: u64,
    pub published_generation: u64,
    pub snapshot_catalog_entries: usize,
    pub production_fsck_required: bool,
}

impl SnapshotRollbackReport {
    pub const fn production_recovery_requires_operator_repair(&self) -> bool {
        self.production_fsck_required
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ChangedRecordObjectRole {
    TransactionManifest = 1,
    TransactionSuperblock = 2,
    TransactionInode = 3,
    TransactionDirectory = 4,
    VersionedContent = 5,
    VersionedContentChunk = 6,
    TransactionSnapshotCatalogEntry = 7,
    TransactionExtentMap = 8,
}

impl ChangedRecordObjectRole {
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    pub const fn human_name(self) -> &'static str {
        match self {
            Self::TransactionManifest => "transaction manifest",
            Self::TransactionSuperblock => "transaction superblock",
            Self::TransactionInode => "transaction inode",
            Self::TransactionDirectory => "transaction directory",
            Self::VersionedContent => "versioned file content",
            Self::VersionedContentChunk => "versioned file content chunk",
            Self::TransactionSnapshotCatalogEntry => "transaction snapshot catalog entry",
            Self::TransactionExtentMap => "transaction extent map",
        }
    }

    pub const fn from_manifest_role(role: TransactionManifestObjectRole) -> Self {
        match role {
            TransactionManifestObjectRole::TransactionSuperblock => Self::TransactionSuperblock,
            TransactionManifestObjectRole::TransactionInode => Self::TransactionInode,
            TransactionManifestObjectRole::TransactionDirectory => Self::TransactionDirectory,
            TransactionManifestObjectRole::VersionedContent => Self::VersionedContent,
            TransactionManifestObjectRole::VersionedContentChunk => Self::VersionedContentChunk,
            TransactionManifestObjectRole::TransactionSnapshotCatalogEntry => {
                Self::TransactionSnapshotCatalogEntry
            }
            TransactionManifestObjectRole::TransactionExtentMap => Self::TransactionExtentMap,
        }
    }

    pub const fn to_manifest_role(self) -> Option<TransactionManifestObjectRole> {
        match self {
            Self::TransactionManifest => None,
            Self::TransactionSuperblock => {
                Some(TransactionManifestObjectRole::TransactionSuperblock)
            }
            Self::TransactionInode => Some(TransactionManifestObjectRole::TransactionInode),
            Self::TransactionDirectory => Some(TransactionManifestObjectRole::TransactionDirectory),
            Self::VersionedContent => Some(TransactionManifestObjectRole::VersionedContent),
            Self::VersionedContentChunk => {
                Some(TransactionManifestObjectRole::VersionedContentChunk)
            }
            Self::TransactionSnapshotCatalogEntry => {
                Some(TransactionManifestObjectRole::TransactionSnapshotCatalogEntry)
            }
            Self::TransactionExtentMap => Some(TransactionManifestObjectRole::TransactionExtentMap),
        }
    }
}

/// Decode error for object-role `TryFrom<u16>` — preserves the rejected raw tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalFilesystemDecodeError {
    UnknownObjectRole(u16),
}

impl TryFrom<u16> for ChangedRecordObjectRole {
    type Error = LocalFilesystemDecodeError;

    fn try_from(value: u16) -> std::result::Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::TransactionManifest),
            2 => Ok(Self::TransactionSuperblock),
            3 => Ok(Self::TransactionInode),
            4 => Ok(Self::TransactionDirectory),
            5 => Ok(Self::VersionedContent),
            6 => Ok(Self::VersionedContentChunk),
            7 => Ok(Self::TransactionSnapshotCatalogEntry),
            8 => Ok(Self::TransactionExtentMap),
            _ => Err(LocalFilesystemDecodeError::UnknownObjectRole(value)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangedObjectRecord {
    pub role: ChangedRecordObjectRole,
    pub object_key: ObjectKey,
    pub checksum: IntegrityDigest64,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangedRecordRoot {
    pub source_root: CommittedRootSummary,
    pub records: Vec<ChangedObjectRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangedRecordExport {
    pub spec: &'static str,
    pub stream_version: u16,
    pub current_root: CommittedRootSummary,
    pub roots: Vec<ChangedRecordRoot>,
    pub total_records: u64,
    pub payload_bytes: u64,
    pub production_fsck_required: bool,
    /// Baseline root for incremental deltas; None for full exports.
    pub from_root: Option<CommittedRootSummary>,
    /// True when this export is an incremental delta.
    pub incremental: bool,
    /// Placement epoch at export time; None when placement is not tracked
    /// (backward-compatible with existing callers).
    pub placement_epoch: Option<u64>,
}

impl ChangedRecordExport {
    pub fn encode(&self) -> Vec<u8> {
        encode_changed_record_export(self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        decode_changed_record_export(bytes)
    }

    pub const fn production_recovery_requires_operator_repair(&self) -> bool {
        self.production_fsck_required
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangedRecordImportReport {
    pub spec: &'static str,
    pub target_root: PathBuf,
    pub imported_roots: u64,
    pub imported_records: u64,
    pub imported_payload_bytes: u64,
    pub selected_generation: u64,
    pub selected_transaction_id: u64,
    pub snapshot_catalog_entries: usize,
    pub stream_version: u16,
    pub staging_validated_before_publish: bool,
    pub destination_root_reauthentication: bool,
    pub production_fsck_required: bool,
    /// Placement epoch from the decoded export; None when sender did not track it.
    pub placement_epoch: Option<u64>,
    /// Whether placement was verified stable during import.
    pub placement_verified_stable: bool,
}

impl ChangedRecordImportReport {
    pub const fn production_recovery_requires_operator_repair(&self) -> bool {
        self.production_fsck_required
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryAuditReport {
    pub design_rule: &'static str,
    pub audit_is_not_fsck: &'static str,
    pub root_slots_seen: u64,
    pub root_candidates_seen: u64,
    pub valid_committed_roots: Vec<CommittedRootSummary>,
    pub invalid_root_candidates: u64,
    pub checked_transaction_manifests: u64,
    pub selected_root: Option<CommittedRootSummary>,
    pub outcome: RecoveryAuditOutcome,
    pub production_fsck_required: bool,
}

impl RecoveryAuditReport {
    pub fn empty() -> Self {
        Self {
            design_rule: PRODUCTION_RECOVERY_DOCTRINE,
            audit_is_not_fsck: RECOVERY_AUDIT_IS_NOT_FSCK,
            root_slots_seen: 0,
            root_candidates_seen: 0,
            valid_committed_roots: Vec::new(),
            invalid_root_candidates: 0,
            checked_transaction_manifests: 0,
            selected_root: None,
            outcome: RecoveryAuditOutcome::EmptyStore,
            production_fsck_required: false,
        }
    }

    pub fn mountable_without_operator_repair(&self) -> bool {
        matches!(
            self.outcome,
            RecoveryAuditOutcome::EmptyStore | RecoveryAuditOutcome::SelectedCommittedRoot
        )
    }

    pub const fn production_recovery_requires_operator_repair(&self) -> bool {
        self.production_fsck_required
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OnlineVerifierOutcome {
    EmptyStore,
    Clean,
    IssuesFound,
}

impl OnlineVerifierOutcome {
    pub const fn human_name(self) -> &'static str {
        match self {
            Self::EmptyStore => "empty store with no root-slot commits",
            Self::Clean => "all committed root candidates verified cleanly",
            Self::IssuesFound => "one or more verifier issues found",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OnlineVerifierIssueSeverity {
    Warning,
    Error,
}

impl OnlineVerifierIssueSeverity {
    pub const fn human_name(self) -> &'static str {
        match self {
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OnlineVerifierIssueKind {
    RootSlotRead,
    RootCommitDecode,
    RootCommitIdentity,
    RootCommitValidation,
    SnapshotRootValidation,
}

impl OnlineVerifierIssueKind {
    pub const fn human_name(self) -> &'static str {
        match self {
            Self::RootSlotRead => "root-slot read",
            Self::RootCommitDecode => "root-commit decode",
            Self::RootCommitIdentity => "root-commit identity",
            Self::RootCommitValidation => "root-commit validation",
            Self::SnapshotRootValidation => "snapshot-root validation",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnlineVerifierIssue {
    pub severity: OnlineVerifierIssueSeverity,
    pub kind: OnlineVerifierIssueKind,
    pub slot: Option<u64>,
    pub location: Option<ObjectLocation>,
    pub transaction_id: Option<u64>,
    pub generation: Option<u64>,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnlineVerifierRootReport {
    pub root: CommittedRootSummary,
    pub mount_invariant: MountInvariantReport,
    pub snapshot_catalog_entries: usize,
    pub verified_snapshot_roots: u64,
    pub checked_manifest_entries: u64,
    pub checked_content_objects: u64,
    pub checked_content_chunks: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnlineVerifierReport {
    pub spec: &'static str,
    pub verifier_is_not_fsck: &'static str,
    pub root_slot_count: u64,
    pub root_slots_seen: u64,
    pub root_slot_records_seen: u64,
    pub root_candidates_seen: u64,
    pub verified_committed_roots: Vec<OnlineVerifierRootReport>,
    pub invalid_root_candidates: u64,
    pub checked_transaction_manifests: u64,
    pub checked_content_objects: u64,
    pub checked_content_chunks: u64,
    pub verified_snapshot_roots: u64,
    pub selected_root: Option<CommittedRootSummary>,
    pub issues: Vec<OnlineVerifierIssue>,
    pub outcome: OnlineVerifierOutcome,
    pub mutating_repair_attempted: bool,
    pub production_fsck_required: bool,
}

impl OnlineVerifierReport {
    pub fn empty() -> Self {
        Self {
            spec: ONLINE_VERIFIER_SPEC,
            verifier_is_not_fsck: ONLINE_VERIFIER_IS_NOT_FSCK,
            root_slot_count: FILESYSTEM_ROOT_SLOT_COUNT,
            root_slots_seen: 0,
            root_slot_records_seen: 0,
            root_candidates_seen: 0,
            verified_committed_roots: Vec::new(),
            invalid_root_candidates: 0,
            checked_transaction_manifests: 0,
            checked_content_objects: 0,
            checked_content_chunks: 0,
            verified_snapshot_roots: 0,
            selected_root: None,
            issues: Vec::new(),
            outcome: OnlineVerifierOutcome::EmptyStore,
            mutating_repair_attempted: false,
            production_fsck_required: false,
        }
    }

    pub fn passed(&self) -> bool {
        self.issues
            .iter()
            .all(|issue| issue.severity != OnlineVerifierIssueSeverity::Error)
    }

    pub fn issue_count(&self) -> usize {
        self.issues.len()
    }

    pub const fn mutates_storage(&self) -> bool {
        self.mutating_repair_attempted
    }

    pub const fn production_recovery_requires_operator_repair(&self) -> bool {
        self.production_fsck_required
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilesystemContentObjectKind {
    InlineContent,
    ContentManifest,
    ContentChunk,
}

impl FilesystemContentObjectKind {
    pub const fn human_name(self) -> &'static str {
        match self {
            Self::InlineContent => "inline content",
            Self::ContentManifest => "content manifest",
            Self::ContentChunk => "content chunk",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilesystemContentObjectRef {
    pub kind: FilesystemContentObjectKind,
    pub inode_id: InodeId,
    pub data_version: u64,
    pub chunk_index: Option<u64>,
    pub key: ObjectKey,
    pub expected_logical_len: Option<u64>,
    pub observed_logical_len: Option<u64>,
    pub observed_encoded_len: Option<u64>,
    pub missing: bool,
    pub zero_length_record: bool,
    pub malformed_reason: Option<String>,
    /// True when a non-hole chunk lacks a placement receipt generation.
    pub missing_receipt: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilesystemContentInspectionReport {
    pub selected_root: Option<CommittedRootSummary>,
    pub file_like_inodes: u64,
    pub referenced_objects: Vec<FilesystemContentObjectRef>,
    pub missing_objects: u64,
    pub zero_length_records: u64,
    pub size_mismatches: u64,
    /// Count of non-hole chunk objects lacking placement receipt authority.
    pub missing_receipts: u64,
    pub malformed_records: u64,
    pub mutating_repair_attempted: bool,
}

impl FilesystemContentInspectionReport {
    pub fn empty() -> Self {
        Self {
            selected_root: None,
            file_like_inodes: 0,
            referenced_objects: Vec::new(),
            missing_objects: 0,
            zero_length_records: 0,
            size_mismatches: 0,
            missing_receipts: 0,
            malformed_records: 0,
            mutating_repair_attempted: false,
        }
    }

    pub fn observe(&mut self, reference: FilesystemContentObjectRef) {
        if reference.missing {
            self.missing_objects = self.missing_objects.saturating_add(1);
        }
        if reference.zero_length_record {
            self.zero_length_records = self.zero_length_records.saturating_add(1);
        }
        if reference
            .expected_logical_len
            .zip(reference.observed_logical_len)
            .map(|(expected, observed)| expected != observed)
            .unwrap_or(false)
        {
            self.size_mismatches = self.size_mismatches.saturating_add(1);
        }
        if reference.missing_receipt {
            self.missing_receipts = self.missing_receipts.saturating_add(1);
        }
        if reference.malformed_reason.is_some() {
            self.malformed_records = self.malformed_records.saturating_add(1);
        }
        self.referenced_objects.push(reference);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MountInvariantReport {
    pub design_rule: &'static str,
    pub invariant_gate_is_not_fsck: &'static str,
    pub inode_count: u64,
    pub directory_count: u64,
    pub file_like_count: u64,
    pub directory_entry_count: u64,
    pub hard_link_edge_count: u64,
    pub reachable_inode_count: u64,
    pub checked_link_counts: u64,
    pub production_fsck_required: bool,
}

impl MountInvariantReport {
    pub fn mountable_without_operator_repair(&self) -> bool {
        self.reachable_inode_count == self.inode_count && !self.production_fsck_required
    }

    pub const fn production_recovery_requires_operator_repair(&self) -> bool {
        self.production_fsck_required
    }
}

pub const MINIMUM_SAFE_RETAINED_ROOTS: usize = 2;
pub const DEFAULT_RETAINED_COMMITTED_ROOTS: usize = FILESYSTEM_ROOT_SLOT_COUNT as usize;
pub const RETENTION_RECLAMATION_IS_NOT_FSCK: &str = "retention planning is validation-only and non-mutating; it must not delete fallback roots, guess repairs, or become production fsck";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootRetentionPolicy {
    pub protected_committed_roots: usize,
}

impl RootRetentionPolicy {
    pub const fn safe_default() -> Self {
        Self {
            protected_committed_roots: DEFAULT_RETAINED_COMMITTED_ROOTS,
        }
    }

    pub const fn protect_at_least(protected_committed_roots: usize) -> Self {
        Self {
            protected_committed_roots,
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.protected_committed_roots < MINIMUM_SAFE_RETAINED_ROOTS {
            return Err(FileSystemError::Unsupported {
                operation: "retention planning",
                reason:
                    "policy would protect fewer committed roots than the no-fsck fallback floor",
            });
        }
        Ok(())
    }
}

impl Default for RootRetentionPolicy {
    fn default() -> Self {
        Self::safe_default()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootRetentionDebt {
    pub policy_required_committed_roots: usize,
    pub valid_committed_roots_available: usize,
    pub missing_committed_roots: usize,
}

impl RootRetentionDebt {
    pub const fn is_clear(&self) -> bool {
        self.missing_committed_roots == 0
    }

    pub const fn has_debt(&self) -> bool {
        self.missing_committed_roots > 0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootRetentionPlan {
    pub design_rule: &'static str,
    pub planner_is_not_fsck: &'static str,
    pub policy: RootRetentionPolicy,
    pub audit: RecoveryAuditReport,
    pub retention_debt: RootRetentionDebt,
    pub protected_committed_roots: Vec<CommittedRootSummary>,
    pub protected_object_keys: Vec<ObjectKey>,
    pub protected_root_slot_locations: Vec<ObjectLocation>,
    pub live_object_keys_seen: u64,
    pub reclaimable_live_object_keys: Vec<ObjectKey>,
    pub mutating_reclamation_allowed: bool,
    pub production_fsck_required: bool,
}

impl RootRetentionPlan {
    pub fn protects_fallback_roots_without_operator_repair(&self) -> bool {
        !self.production_fsck_required
            && !self.mutating_reclamation_allowed
            && self.retention_debt.is_clear()
    }

    pub const fn production_recovery_requires_operator_repair(&self) -> bool {
        self.production_fsck_required
    }

    pub const fn mutates_storage(&self) -> bool {
        self.mutating_reclamation_allowed
    }

    pub const fn retention_policy_satisfied(&self) -> bool {
        self.retention_debt.is_clear()
    }

    pub const fn has_retention_debt(&self) -> bool {
        self.retention_debt.has_debt()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SafeReclamationReport {
    pub spec: &'static str,
    pub retention_plan: RootRetentionPlan,
    pub store: StoreRetentionCompactionReport,
    pub protected_committed_roots_preserved: usize,
    pub protected_root_slot_locations_preserved: usize,
    pub selected_generation_after: Option<u64>,
    pub mutating_reclamation_allowed: bool,
    pub production_fsck_required: bool,
}

impl SafeReclamationReport {
    pub const fn retention_policy_satisfied(&self) -> bool {
        self.retention_plan.retention_policy_satisfied()
    }

    pub const fn production_recovery_requires_operator_repair(&self) -> bool {
        self.production_fsck_required
    }

    pub const fn mutates_storage(&self) -> bool {
        self.mutating_reclamation_allowed
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum TransactionManifestObjectRole {
    TransactionSuperblock = 1,
    TransactionInode = 2,
    TransactionDirectory = 3,
    VersionedContent = 4,
    VersionedContentChunk = 5,
    TransactionSnapshotCatalogEntry = 6,
    TransactionExtentMap = 7,
}

impl TransactionManifestObjectRole {
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    pub const fn human_name(self) -> &'static str {
        match self {
            Self::TransactionSuperblock => "transaction superblock",
            Self::TransactionInode => "transaction inode",
            Self::TransactionDirectory => "transaction directory",
            Self::VersionedContent => "versioned file content",
            Self::VersionedContentChunk => "versioned file content chunk",
            Self::TransactionSnapshotCatalogEntry => "transaction snapshot catalog entry",
            Self::TransactionExtentMap => "transaction extent map",
        }
    }
}

impl TryFrom<u16> for TransactionManifestObjectRole {
    type Error = LocalFilesystemDecodeError;

    fn try_from(value: u16) -> std::result::Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::TransactionSuperblock),
            2 => Ok(Self::TransactionInode),
            3 => Ok(Self::TransactionDirectory),
            4 => Ok(Self::VersionedContent),
            5 => Ok(Self::VersionedContentChunk),
            6 => Ok(Self::TransactionSnapshotCatalogEntry),
            7 => Ok(Self::TransactionExtentMap),
            _ => Err(LocalFilesystemDecodeError::UnknownObjectRole(value)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionManifestEntry {
    pub role: TransactionManifestObjectRole,
    pub object_key: ObjectKey,
    pub checksum: IntegrityDigest64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TransactionManifestRecord {
    pub(crate) transaction_id: u64,
    pub(crate) generation: u64,
    pub(crate) entries: Vec<TransactionManifestEntry>,
}

pub(crate) const ROOT_COMMIT_MAGIC: [u8; 8] = *b"VFSROOT1";
pub(crate) const ROOT_COMMIT_RESERVED: u16 = 0;
pub(crate) const ROOT_COMMIT_MIN_TRANSACTION_ID: u64 = 1;
pub(crate) const ROOT_AUTHENTICATION_MAGIC: [u8; 8] = ROOT_AUTHENTICATION_MAGIC_BYTES;
pub(crate) const ROOT_AUTHENTICATION_ROOT_DOMAIN: &[u8] =
    b"tidefs.local-filesystem.root-authentication.root.v1";
pub(crate) const ROOT_AUTHENTICATION_SUPERBLOCK_DOMAIN: &[u8] =
    b"tidefs.local-filesystem.root-authentication.superblock.v1";
pub(crate) const ROOT_AUTHENTICATION_MANIFEST_DOMAIN: &[u8] =
    b"tidefs.local-filesystem.root-authentication.manifest.v1";

pub(crate) const SUPERBLOCK_MAGIC: [u8; 8] = *b"VLFSHEAD";
pub(crate) const INODE_MAGIC: [u8; 8] = *b"VFSINOD1";
pub(crate) const DIRECTORY_MAGIC: [u8; 8] = *b"VFSDIRS1";
pub(crate) const CONTENT_MAGIC: [u8; 8] = *b"VFSDATA1";
pub(crate) const CONTENT_MANIFEST_MAGIC: [u8; 8] = *b"VFSCMAN1";
pub(crate) const CONTENT_MANIFEST_SPARSE_MAGIC: [u8; 8] = *b"VFSCMAN2";
pub(crate) const CONTENT_CHUNK_MAGIC: [u8; 8] = *b"VFSCHNK1";
pub(crate) const TRANSACTION_MANIFEST_MAGIC: [u8; 8] = *b"VLFSPLAN";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ContentCompressionAlgorithm {
    /// Store content chunks without compression.
    None = 0,
    /// Compress eligible content chunks with zstd.
    Zstd = 1,
    /// Compress eligible content chunks with lz4.
    Lz4 = 2,
}

impl ContentCompressionAlgorithm {
    pub(crate) const fn from_u16(value: u16) -> Option<Self> {
        match value {
            0 => Some(Self::None),
            1 => Some(Self::Zstd),
            2 => Some(Self::Lz4),
            _ => None,
        }
    }

    pub(crate) const fn as_u16(self) -> u16 {
        self as u16
    }
}

/// Live compression authority for mounted filesystem content writes.
///
/// Governs which algorithm, level, and savings threshold apply when
/// encoding content chunks. Resolved from dataset feature flags and
/// persisted dataset properties at mount time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ContentCompressionPolicy {
    pub algorithm: ContentCompressionAlgorithm,
    /// Compression level (zstd: 1-22, lz4: 0=fast, ignored for None).
    pub level: i32,
    /// Minimum bytes saved before compressed output replaces uncompressed.
    /// Compressed output must be at least this many bytes smaller than the
    /// original to be stored compressed.
    pub min_savings_bytes: usize,
}

/// Tracks where the effective compression policy was resolved from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompressionPolicySource {
    /// Policy was set explicitly via dataset properties (compression.algorithm).
    PropertyOverride,
    /// Policy was derived from enabled feature flags.
    FeatureFlag,
    /// Policy is the default (compression off).
    Default,
}

/// Public observability snapshot for the active mounted-content compression policy.
///
/// This is intentionally separate from the internal [`ContentCompressionPolicy`]
/// authority so callers can inspect the effective policy without depending on
/// the mutable implementation type used by write encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectiveCompressionPolicyReport {
    /// Compression algorithm currently selected for content writes.
    pub algorithm: ContentCompressionAlgorithm,
    /// Compression level selected for the algorithm.
    pub level: i32,
    /// Minimum byte savings required before compressed output is stored.
    pub min_savings_bytes: usize,
    /// Source that selected this effective policy.
    pub source: CompressionPolicySource,
}

impl Default for ContentCompressionPolicy {
    fn default() -> Self {
        Self {
            algorithm: ContentCompressionAlgorithm::None,
            level: 3,
            min_savings_bytes: 32,
        }
    }
}

impl ContentCompressionPolicy {
    pub(crate) fn report(
        &self,
        source: CompressionPolicySource,
    ) -> EffectiveCompressionPolicyReport {
        EffectiveCompressionPolicyReport {
            algorithm: self.algorithm,
            level: self.level,
            min_savings_bytes: self.min_savings_bytes,
            source,
        }
    }

    pub(crate) fn off() -> Self {
        Self {
            algorithm: ContentCompressionAlgorithm::None,
            level: 3,
            min_savings_bytes: 32,
        }
    }

    pub(crate) fn zstd_default() -> Self {
        Self {
            algorithm: ContentCompressionAlgorithm::Zstd,
            level: 3,
            min_savings_bytes: 32,
        }
    }

    pub(crate) fn lz4_default() -> Self {
        Self {
            algorithm: ContentCompressionAlgorithm::Lz4,
            level: 0,
            min_savings_bytes: 32,
        }
    }

    /// Validate the compression policy parameters are within acceptable ranges.
    ///
    /// Returns `Err` with a static description if the level is outside the
    /// algorithm's valid range.  Used as a production guard in
    /// [`encode_content_chunk`] so misconfigured policies fall back to
    /// uncompressed storage rather than producing invalid data.
    pub(crate) fn validate(&self) -> std::result::Result<(), &'static str> {
        match self.algorithm {
            ContentCompressionAlgorithm::Zstd => {
                if !(1..=22).contains(&self.level) {
                    return Err("zstd level must be in 1..=22");
                }
            }
            ContentCompressionAlgorithm::Lz4 => {
                if !(0..=16).contains(&self.level) {
                    return Err("lz4 level must be in 0..=16");
                }
            }
            ContentCompressionAlgorithm::None => {
                // Level is ignored for None.
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PosixTimeRecord {
    pub atime_ns: i64,
    pub mtime_ns: i64,
    pub ctime_ns: i64,
    pub btime_ns: i64,
}

impl PosixTimeRecord {
    #[must_use]
    pub const fn new(atime_ns: i64, mtime_ns: i64, ctime_ns: i64, btime_ns: i64) -> Self {
        Self {
            atime_ns,
            mtime_ns,
            ctime_ns,
            btime_ns,
        }
    }

    #[must_use]
    pub fn now() -> Self {
        let ns = current_posix_time_ns();
        Self::new(ns, ns, ns, ns)
    }

    /// Create a PosixTimeRecord from the caller-resolved wall-clock
    /// nanosecond value.  This is the named authority boundary for synthetic
    /// inodes and test fixtures that previously used the removed
    /// `from_generation` shortcut.  The `now_ns` argument must be a POSIX
    /// wall-clock timestamp, never a storage version, generation, or object key.
    #[must_use]
    pub fn synthetic(now_ns: i64) -> Self {
        Self::new(now_ns, now_ns, now_ns, now_ns)
    }
}

#[must_use]
pub fn current_posix_time_ns() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos().try_into().unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InodeRecord {
    pub dir_storage_kind: u8,
    pub inode_id: InodeId,
    pub generation: Generation,
    /// Authoritative typed-facet set — primary type identity.
    /// [`Self::kind`] derives the POSIX projection shape from this.
    pub facets: NodeFacets,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub size: u64,
    pub data_version: u64,
    pub metadata_version: u64,
    pub posix_time: PosixTimeRecord,
    pub xattr_storage_kind: u8,
    pub xattrs: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Monotonic directory revision counter bumped on every entry mutation.
    /// Always 0 for non-directory inodes.
    pub dir_rev: u64,
    /// Device number for block/character device nodes (major << 8 | minor).
    /// Zero for regular files, directories, symlinks, FIFOs, and sockets.
    pub rdev: u32,
}

impl InodeRecord {
    /// Authoritative typed facets for this inode.
    ///
    /// Prefer facet predicates (`carries_byte_space`, `carries_child_namespace`)
    /// over matching on `kind` when the intent is about what the inode *can do*.
    #[must_use]
    pub fn facets(&self) -> NodeFacets {
        self.facets
    }

    /// POSIX projection shape derived from authoritative [`Self::facets`].
    ///
    /// Uses [`Self::mode`] bits to recover the original `NodeKind` when facets
    /// alone cannot distinguish (e.g., File vs Symlink share the same facet set).
    #[must_use]
    pub fn kind(&self) -> NodeKind {
        let projected = self.facets.projection_kind();
        if projected == NodeKind::File {
            match self.mode & S_IFMT {
                S_IFLNK => return NodeKind::Symlink,
                S_IFCHR => return NodeKind::CharDev,
                S_IFBLK => return NodeKind::BlockDev,
                S_IFIFO => return NodeKind::Fifo,
                S_IFSOCK => return NodeKind::Socket,
                _ => {}
            }
        }
        projected
    }

    /// True when the inode carries content bytes.
    #[must_use]
    pub fn carries_byte_space(&self) -> bool {
        self.facets().carries_byte_space()
    }

    /// True when the inode harbours child namespace bindings.
    #[must_use]
    pub fn carries_child_namespace(&self) -> bool {
        self.facets().carries_child_namespace()
    }

    /// POSIX projection: is this a file or symlink? (prior-generation, use facets)
    pub fn is_file_like(&self) -> bool {
        self.carries_byte_space() && !self.carries_child_namespace()
    }

    /// POSIX projection: is this a directory? (prior-generation, use facets)
    pub fn is_directory(&self) -> bool {
        self.carries_child_namespace()
    }

    pub fn to_inode_attr(&self) -> InodeAttr {
        InodeAttr {
            inode_id: self.inode_id,
            generation: self.generation,
            kind: self.kind(),
            posix: PosixAttrs {
                mode: self.mode,
                uid: self.uid,
                gid: self.gid,
                nlink: self.nlink,
                rdev: self.rdev,
                atime_ns: self.posix_time.atime_ns,
                mtime_ns: self.posix_time.mtime_ns,
                ctime_ns: self.posix_time.ctime_ns,
                btime_ns: self.posix_time.btime_ns,
                size: self.size,
                blocks_512: self.size.saturating_add(511) / 512,
                blksize: 4096,
            },
            flags: InodeFlags::default(),
            subtree_rev: self.metadata_version,
            dir_rev: self.metadata_version,
        }
    }
}

/// A single directory entry mutation recorded in the per-directory change stream.
///
/// Keys in the change-stream map are  values; values are these records.
/// The change stream enables O(changes) incremental directory view refresh
/// instead of O(size) full rebuilds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DirChangeRecord {
    /// An entry was added or replaced.
    Add {
        name: Vec<u8>,
        inode_id: InodeId,
        facets: NodeFacets,
    },
    /// An entry was removed.
    Remove { name: Vec<u8>, inode_id: InodeId },
    /// An entry was renamed from old_name to new_name.
    Rename {
        old_name: Vec<u8>,
        new_name: Vec<u8>,
        inode_id: InodeId,
        facets: NodeFacets,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceEntry {
    pub name: Vec<u8>,
    pub inode_id: InodeId,
    pub generation: Generation,
    /// Authoritative typed-facet set — primary type identity.
    /// [`Self::kind`] derives the POSIX projection shape from this.
    pub facets: NodeFacets,
    /// POSIX mode bits (S_IFMT + permissions), used by [`Self::kind`] to
    /// recover the original `NodeKind` when facets alone cannot distinguish.
    pub mode: u32,
}

impl NamespaceEntry {
    /// Authoritative typed facets for this namespace entry.
    #[must_use]
    pub fn facets(&self) -> NodeFacets {
        self.facets
    }

    /// POSIX projection shape derived from authoritative [`Self::facets`].
    ///
    /// Uses [`Self::mode`] bits to recover the original `NodeKind` when facets
    /// alone cannot distinguish (e.g., File vs Symlink share the same facet set).
    #[must_use]
    pub fn kind(&self) -> NodeKind {
        let projected = self.facets.projection_kind();
        if projected == NodeKind::File {
            match self.mode & S_IFMT {
                S_IFLNK => return NodeKind::Symlink,
                S_IFCHR => return NodeKind::CharDev,
                S_IFBLK => return NodeKind::BlockDev,
                S_IFIFO => return NodeKind::Fifo,
                S_IFSOCK => return NodeKind::Socket,
                _ => {}
            }
        }
        projected
    }

    /// True when the entry harbours child namespace bindings.
    #[must_use]
    pub fn carries_child_namespace(&self) -> bool {
        self.facets().carries_child_namespace()
    }
    pub fn name_lossy(&self) -> String {
        String::from_utf8_lossy(&self.name).into_owned()
    }

    pub fn to_owned_dir_entry(&self, cookie: u64) -> OwnedDirEntry {
        OwnedDirEntry::new(
            self.name.clone(),
            self.inode_id,
            self.kind(),
            self.generation,
            cookie,
        )
    }
}

/// Aggregate filesystem-wide statistics.
///
/// Reports object counts (inodes, directories, files, symlinks,
/// snapshots), the next available inode id, the filesystem generation
/// number, and the underlying object-store pool statistics via
/// [`StoreStats`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileSystemStats {
    pub inode_count: usize,
    pub directory_count: usize,
    pub file_count: usize,
    pub symlink_count: usize,
    pub snapshot_count: usize,
    pub next_inode_id: u64,
    pub filesystem_generation: u64,
    pub object_store: StoreStats,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReclaimStats {
    pub orphan_index_entries: usize,
    pub reclaim_queue_entries: usize,
    pub pending_orphan_deletions: usize,
    /// Total number of calls to drain_local_reclaim_queue_into_store since mount.
    pub total_reclaim_drains: u64,
    /// Total reclaim entries handed off to the object-store durable reclaim queue since mount.
    pub total_reclaim_entries_drained: u64,
}

impl ReclaimStats {
    #[must_use]
    pub const fn queued_work_items(self) -> usize {
        self.orphan_index_entries + self.reclaim_queue_entries + self.pending_orphan_deletions
    }

    #[must_use]
    pub const fn is_idle(self) -> bool {
        self.queued_work_items() == 0
    }
}

/// Stats returned by `LocalFileSystem::drain_local_reclaim_queue_into_store`.
///
/// Records the handoff from the local-filesystem B+tree reclaim queue
/// into the object-store durable reclaim queue via `store.delete()`. The
/// object-store reclaim queue is drained by `LocalObjectStore::drain_dead_segments`,
/// the sole mounted-pool segment-freeing authority.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReclaimDrainStats {
    /// Number of reclaim entries drained from the local B+tree queue
    /// and handed off to the object-store durable reclaim queue.
    pub entries_drained: usize,
}

impl ReclaimDrainStats {
    /// True when at least one reclaim entry was handed off to the
    /// object-store durable reclaim queue in this drain call.
    #[must_use]
    pub const fn drained_any(&self) -> bool {
        self.entries_drained > 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HotReadCachePolicy {
    pub max_entries: usize,
    pub max_bytes: u64,
}

impl Default for HotReadCachePolicy {
    fn default() -> Self {
        Self {
            max_entries: DEFAULT_HOT_READ_CACHE_MAX_ENTRIES,
            max_bytes: DEFAULT_HOT_READ_CACHE_MAX_BYTES,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HotReadCacheReport {
    pub spec: &'static str,
    pub max_entries: usize,
    pub max_bytes: u64,
    pub hits: u64,
    pub misses: u64,
    pub insertions: u64,
    pub evictions: u64,
    pub invalidations: u64,
    pub admission_bypasses: u64,
    pub resident_entries: usize,
    pub resident_bytes: u64,
    pub admission_rejected_budget: u64,
    pub admission_rejected_reserve: u64,
    pub admission_rejected_dirty_state: u64,
    pub poisoned_on_validate: u64,
}

impl HotReadCacheReport {
    pub const fn is_bounded(&self) -> bool {
        self.resident_entries <= self.max_entries && self.resident_bytes <= self.max_bytes
    }

    pub fn is_non_authoritative(&self) -> bool {
        self.spec == HOT_READ_CACHE_SPEC
    }
}

/// Report on the obligation ledger state.
///
/// Rule 8 requires that every allocation be traceable back to a claim.
/// This report surfaces the ledger state for operator visibility.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimLedgerReport {
    pub spec: &'static str,
    pub total_blocks: u64,
    pub allocated_blocks: u64,
    pub reserved_blocks: u64,
    pub free_blocks: u64,
    pub claim_count: usize,
    pub reserve_count: usize,
    pub witness_count: usize,
    pub domain_count: usize,
    pub claims_by_reason: Vec<(String, u64, usize)>,
    pub reverse_explain_label: String,
}

impl ClaimLedgerReport {
    pub fn is_non_authoritative(&self) -> bool {
        self.spec == CLAIM_LEDGER_SPEC
    }

    pub fn utilization_pct(&self) -> f64 {
        if self.total_blocks == 0 {
            return 0.0;
        }
        (self.allocated_blocks as f64) / (self.total_blocks as f64) * 100.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryProbeOutcome {
    EmptyStore,
    SelectedCommittedRoot,
    ExplicitIntegrityOrMediaError,
}

impl RecoveryProbeOutcome {
    pub const fn human_name(self) -> &'static str {
        match self {
            Self::EmptyStore => "empty store; initial root may be created",
            Self::SelectedCommittedRoot => "selected newest valid committed root",
            Self::ExplicitIntegrityOrMediaError => {
                "explicit integrity/media error; no committed root may be mounted"
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryProbeReport {
    pub design_rule: &'static str,
    pub root_slot_count: u64,
    pub root_slot_records_seen: u64,
    pub root_slot_candidates_seen: u64,
    pub valid_committed_roots_seen: u64,
    pub skipped_root_candidates: u64,
    pub selected_slot: Option<u64>,
    pub selected_transaction_id: Option<u64>,
    pub selected_generation: Option<u64>,
    pub selected_inode_count: Option<u64>,
    pub object_store_repaired_tail_bytes: u64,
    pub outcome: RecoveryProbeOutcome,
}

impl RecoveryProbeReport {
    pub fn empty_with_replay_tail(repaired_tail_bytes: u64) -> Self {
        Self {
            design_rule: PRODUCTION_RECOVERY_DOCTRINE,
            root_slot_count: FILESYSTEM_ROOT_SLOT_COUNT,
            root_slot_records_seen: 0,
            root_slot_candidates_seen: 0,
            valid_committed_roots_seen: 0,
            skipped_root_candidates: 0,
            selected_slot: None,
            selected_transaction_id: None,
            selected_generation: None,
            selected_inode_count: None,
            object_store_repaired_tail_bytes: repaired_tail_bytes,
            outcome: RecoveryProbeOutcome::EmptyStore,
        }
    }

    pub fn mountable_without_operator_repair(&self) -> bool {
        matches!(
            self.outcome,
            RecoveryProbeOutcome::EmptyStore | RecoveryProbeOutcome::SelectedCommittedRoot
        )
    }

    pub const fn production_recovery_requires_operator_repair(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ContentFingerprint([u8; 32]);

impl ContentFingerprint {
    pub const fn from_bytes32(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes32(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Display for ContentFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}
