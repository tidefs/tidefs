// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![deny(dead_code)]
#![deny(unused_imports)]

//! TideFS POSIX Filesystem Adapter Daemon
//!
//! FUSE-backed daemon that mounts a TideFS filesystem via the Linux FUSE
//! kernel interface.  The crate links a [`LocalFileSystem`] store through
//! a [`VfsEngine`] trait implementation and serves every supported FUSE
//! operation to the kernel on behalf of userspace processes.
//!
//! [`LocalFileSystem`]: tidefs_local_filesystem::LocalFileSystem
//! [`VfsEngine`]: tidefs_vfs_engine::VfsEngine
//!
//! # FUSE request lifecycle
//!
//! 1. **Ingress classification**: raw FUSE requests (lookup, getattr,
//!    read, write, …) are parsed and classified by the ingress layer
//!    ([`crate::ingress`]), which extracts the
//!    [`RequestCtx`], validates the handle table, and routes requests to
//!    the appropriate dispatch handler.
//!
//! 2. **Dispatch**: the [`FuseVfsAdapter`] implements [`fuser::Filesystem`]
//!    and dispatches each operation to a type-safe handler.  Namespace
//!    operations (lookup, mkdir, unlink, rename, symlink, …) go through
//!    [`Namespace`]; data-path operations (read, write, fallocate, flush,
//!    fsync) go through the page-cache and extent-map; metadata operations
//!    (getattr, setattr, access) go through the inode table and permission
//!    checker.
//!
//! 3. **Reply**: each handler returns either a success value (packed into
//!    a FUSE reply) or an [`Errno`] error code.  The reply layer
//!    converts these into the appropriate kernel reply message.
//!
//! [`FuseVfsAdapter`]: crate::fuse_vfs_adapter::FuseVfsAdapter
//! [`Namespace`]: tidefs_namespace::Namespace
//! [`RequestCtx`]: tidefs_types_vfs_core::RequestCtx
//! [`Errno`]: tidefs_vfs_engine::Errno
//!
//! # Error taxonomy
//!
//! Every error path in the daemon maps to a POSIX errno before reaching
//! the kernel.  Errors are grouped into five categories by recovery
//! semantics.  See [`doc/ERROR_TAXONOMY.md`] for the full reference.
//!
//! ## 1. Transport errors (FUSE channel)
//!
//! The FUSE session itself can fail during mount or while reading
//! requests from `/dev/fuse`.  These are surfaced in [`run_mount`] as
//! `String` errors and terminate the daemon process.
//!
//! | Condition | Errno | Recovery |
//! |-----------|-------|----------|
//! | `fuser::spawn_mount2` failure | (process exit) | Daemon restart |
//! | `/dev/fuse` read failure (session lost) | (process exit) | Daemon restart |
//!
//! ## 2. Protocol errors (malformed requests)
//!
//! The daemon validates request parameters before dispatching.
//!
//! | Condition | Errno | Recovery |
//! |-----------|-------|----------|
//! | Invalid `offset`/`length` for read/write/copy-range | `EINVAL` | Propagate to client |
//! | Offset+length overflow (checked_add fails) | `EFBIG` | Propagate to client |
//! | Cookie overflow in readdir (cast to i64 fails) | `EOVERFLOW` | Propagate to client |
//! | Cookie value out of i64 range | `ERANGE` | Propagate to client |
//! | Unknown `ioctl` command | `EOPNOTSUPP` | Propagate to client |
//! | Malformed FIEMAP header | `EINVAL` | Propagate to client |
//! | Non-UTF-8 name in namespace operation | `EINVAL` | Propagate to client |
//!
//! ## 3. Filesystem errors (POSIX semantics)
//!
//! These correspond to standard POSIX error conditions.  The
//! `namespace_error_to_errno` function (in [`fuse_vfs_adapter`]) maps
//! [`NamespaceError`] variants:
//!
//! [`NamespaceError`]: tidefs_namespace::NamespaceError
//!
//! | Namespace variant | Errno |
//! |-------------------|-------|
//! | `InodeNotFound` | `ENOENT` |
//! | `AlreadyExists` | `EEXIST` |
//! | `NotEmpty` | `ENOTEMPTY` |
//! | `NotDirectory` | `ENOTDIR` |
//! | `IsDirectory` | `EISDIR` |
//! | `InvalidName` | `EINVAL` |
//! | `TooManySymlinks` | `ELOOP` |
//! | `NotSymlink` | `EINVAL` |
//! | `LinkCountOverflow` | `EMLINK` |
//! | `RenameCycle` | `EINVAL` |
//! | (other) | `EIO` |
//!
//! Additional filesystem-level errors returned directly by the dispatch layer:
//!
//! | Condition | Errno | Recovery |
//! |-----------|-------|----------|
//! | Bad or closed file handle | `EBADF` | Propagate to client |
//! | Handle exists but not writable | `EBADF` | Propagate to client |
//! | Handle exists but inode is not a directory | `ENOTDIR` | Propagate to client |
//! | Handle exists but inode is a directory (write/read on dir) | `EISDIR` | Propagate to client |
//! | Name exceeds `PATH_MAX_BYTES` | `ENAMETOOLONG` | Propagate to client |
//! | Permission denied (access check) | `EACCES` | Propagate to client |
//! | Permission denied (owner/priv check) | `EPERM` | Propagate to client |
//! | Read-only filesystem | `EROFS` | Propagate to client |
//! | Inode no longer valid after lookup | `ESTALE` | Propagate to client |
//! | xattr does not exist on inode | `ENODATA` | Propagate to client |
//! | Seek offset beyond end of file | `ENXIO` | Propagate to client |
//! | Lock conflict / resource busy | `EBUSY` | Propagate to client |
//! | Operation not implemented | `ENOSYS` | Propagate to client |
//!
//! ## 4. Crate-level error enums
//!
//! Several modules define typed error enums with their own `to_errno()` methods:
//!
//! | Error enum | Defined in | Variants / mapping |
//! |------------|-----------|-------------------|
//! | [`WriteError`] | [`fuse_write`] | `BadFileDescriptor→EBADF`, `NotWritable→EBADF`, `NoSpace→ENOSPC`, `IoError→EIO`, `InvalidArgument→EINVAL` |
//! | [`FlushError`] | [`fuse_flush_fsync`] | `BadFileDescriptor→EBADF`, `IoError→EIO`, `NoSpace→ENOSPC`, `Interrupted→EINTR` |
//! | [`FsyncError`] | [`fuse_flush_fsync`] | `BadFileDescriptor→EBADF`, `IoError→EIO`, `NoSpace→ENOSPC`, `Interrupted→EINTR` |
//! | [`ReaddirError`] | [`readdir_dispatch`] | `NotFound→ENOENT`, `NotDirectory→ENOTDIR`, `Io→EIO` |
//! | [`DaemonWriteDispatchError`] | [`write_dispatch`] | `Rejected{errno}→errno`, `Staging→(staging errno)`, `Scheduler(Full)→EAGAIN`, `Scheduler(InvalidRange)→EINVAL`, `Scheduler(OutOfWorkItemIds)→EIO` |
//!
//! [`WriteError`]: crate::fuse_write::WriteError
//! [`FlushError`]: crate::fuse_flush_fsync::FlushError
//! [`FsyncError`]: crate::fuse_flush_fsync::FsyncError
//! [`ReaddirError`]: crate::readdir_dispatch::ReaddirError
//! [`DaemonWriteDispatchError`]: crate::write_dispatch::DaemonWriteDispatchError
//! [`fuse_write`]: crate::fuse_write
//! [`fuse_flush_fsync`]: crate::fuse_flush_fsync
//! [`readdir_dispatch`]: crate::readdir_dispatch
//! [`write_dispatch`]: crate::write_dispatch
//!
//! ## 5. Internal errors (daemon-local faults)
//!
//! | Condition | Errno | Recovery |
//! |-----------|-------|----------|
//! | PageCache writeback or engine flush/fsync failure | `EIO` | Log; propagate to client |
//! | Extent-map allocation exhausted | `ENOSPC` | Propagate to client |
//! | Extent-map corruption or wrong version | `EIO` | Log; propagate to client |
//! | Dirty-extent scheduler full (back-pressure) | `EAGAIN` | Client retries |
//! | Dirty-extent scheduler out of work-item ids | `EIO` | Log; propagate to client |
//! | Dirty-extent scheduler invalid range | `EINVAL` | Propagate to client |
//! | Internal iteration error (corrupt DirIndex) | `EIO` | Log; propagate to client |
//! | Lock conflict (resource busy) | `EBUSY` | Client retries or blocks |
//! | Inode link-count store failure | `ENOLINK` | Log; propagate to client |
//!
//! # Per-operation errno reference
//!
//! The tables below list every errno value each FUSE operation can return,
//! with rationale for each mapping.
//!
//! ## lookup (opcode 1)
//!
//! - `ENOENT` — component not found in namespace
//! - `ENOTDIR` — intermediate component is not a directory
//! - `ENAMETOOLONG` — name exceeds `PATH_MAX_BYTES`
//! - `EACCES` — search permission denied on parent directory
//! - `ESTALE` — ENOENT escalated when attributes are expected after lookup
//! - `EIO` — namespace engine internal error
//!
//! ## getattr (opcode 3)
//!
//! - `ENOENT` — inode not found in table
//! - `EBADF` — file-handle resolution failed (when `FATTR_FH` is set)
//! - `ESTALE` — inode lookup succeeded but attributes unavailable
//! - `EIO` — internal metadata lookup failure
//!
//! ## read (opcode 15)
//!
//! - `EBADF` — handle unknown, closed, or not open for reading
//! - `EISDIR` — handle points to a directory
//! - `EINVAL` — offset or length out of range
//! - `EFBIG` — offset+length exceeds representable range
//! - `ENXIO` — seek position beyond end of file
//! - `EIO` — page-cache read or extent-map lookup failed
//!
//! ## write (opcode 16)
//!
//! - `EBADF` — handle unknown, closed, or not open for writing
//! - `ENOSPC` — extent-map allocation full; no space on device
//! - `EINVAL` — offset or length out of range
//! - `EFBIG` — offset+length exceeds representable range
//! - `EAGAIN` — dirty-extent scheduler backpressure
//! - `EIO` — I/O-level error during cache insertion
//!
//! ## fsync (opcode 26) / fdatasync
//!
//! - `EBADF` — handle unknown or closed
//! - `EIO` — page-cache writeback or engine fsync failed
//! - `ENOSPC` — extent-map commit failed due to no space
//! - `EINTR` — operation interrupted by signal
//!
//! ## flush (opcode 25)
//!
//! - `EBADF` — handle unknown or closed
//! - `EIO` — writeback failed
//! - `ENOSPC` — extent commit failed due to no space
//! - `EINTR` — operation interrupted by signal
//!
//! ## create / mkdir / mknod (opcodes 35, 9, 8)
//!
//! - `ENOENT` — parent inode does not exist
//! - `ENOTDIR` — parent exists but is not a directory
//! - `EEXIST` — name already exists (or O_EXCL conflict)
//! - `ENOSPC` — inode table exhausted
//! - `ENAMETOOLONG` — name exceeds `PATH_MAX_BYTES`
//! - `EACCES` — write permission denied on parent
//! - `EIO` — engine-level insertion failure
//!
//! ## unlink / rmdir (opcodes 10, 11)
//!
//! - `ENOENT` — parent or child inode not found
//! - `ENOTDIR` — intermediate component is not a directory (rmdir)
//! - `ENOTEMPTY` — directory not empty (rmdir)
//! - `EACCES` — write permission denied
//! - `EIO` — engine-level removal failure
//!
//! ## rename (opcode 12)
//!
//! - `ENOENT` — source not found
//! - `ENOTDIR` — source or destination parent is not a directory
//! - `EEXIST` — destination exists and `RENAME_NOREPLACE` is set
//! - `EISDIR` — attempting to rename directory over non-directory or vice versa
//! - `ENOTEMPTY` — destination is a non-empty directory
//! - `EINVAL` — rename would create a cycle
//! - `EIO` — namespace engine error
//!
//! ## readdir / readdirplus (opcodes 28, 44)
//!
//! - `EBADF` — directory handle unknown or closed (opendir)
//! - `ENOTDIR` — handle points to a non-directory inode
//! - `ENOENT` — inode in directory index not found in inode table
//! - `EOVERFLOW` — cookie value exceeds i64 range
//! - `EIO` — internal iteration error (corrupt DirIndex)
//!
//! ## fallocate (opcode 43)
//!
//! - `EBADF` — handle unknown, closed, or pointing to a directory
//! - `EISDIR` — handle points to a directory
//! - `EOPNOTSUPP` — unsupported fallocate mode (`FALLOC_FL_COLLAPSE_RANGE`, etc.)
//! - `EINVAL` — offset/length invalid or overlapping extent
//! - `ENOSPC` — extent-map full or allocator exhausted
//! - `EIO` — internal engine failure
//!
//! ## xattr operations (getxattr, setxattr, listxattr, removexattr)
//!
//! - `ENODATA` — attribute name not found (getxattr, removexattr)
//! - `ENOENT` — inode not found
//! - `ENOSYS` — not yet implemented (most backends currently stub)
//! - `EIO` — engine-level xattr store failure
//!
//! ## Advisory locks (getlk, setlk, setlkw, flock)
//!
//! POSIX advisory byte-range locks (F_SETLK, F_SETLKW, F_GETLK) and BSD
//! flock (LOCK_SH, LOCK_EX, LOCK_UN) are dispatched through the lease-backed
//! [`DaemonLockDispatch`] in-process lock service.  Lock state is held entirely
//! in memory and is not persisted to the backing store.
//!
//! ### Lock recovery after daemon restart
//!
//! TideFS **does not recover** POSIX or BSD flock lock state across daemon
//! restarts.  This is the correct POSIX/FUSE semantics:
//!
//! - When the daemon process exits (crash or graceful shutdown), the kernel
//!   closes the associated FUSE file descriptors, which automatically releases
//!   all kernel-side locks for those open file descriptions.
//!
//! - The new daemon starts with an empty lock table (see
//!   [`DaemonLockDispatch::reset`]).
//!
//! - Client applications holding locks before the crash will receive errors
//!   on subsequent lock operations, just as they would for any other
//!   filesystem where the lock server has restarted.
//!
//! # Module overview
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`fuse_vfs_adapter`] | Main `fuser::Filesystem` impl; ~30 FUSE op handlers |
//! | [`fuse_write`] | Write/write_buf dispatch with page-cache dirty tracking |
//! | [`fuse_read`] | Read dispatch with page-cache look-aside |
//! | [`fuse_flush_fsync`] | Flush/fsync dispatch with writeback and extent commit |
//! | [`fuse_lookup_forget`] | Lookup and forget dispatch |
//! | [`fuse_rename`] | Atomic rename with cross-directory validation |
//! | [`fuse_create_unlink_dispatch`] | Unlink/rmdir with capacity release |
//! | [`readdir_dispatch`] | Readdir/readdirplus with cookie-based pagination |
//! | [`write_dispatch`] | Ingress-classified write staging and dirty scheduling |
//! | [`read_cache`] | In-memory read-ahead cache for hot data |
//! | [`writeback_reclaim`] | Dirty-page writeback and reclaim |
//!
//! [`fuse_vfs_adapter`]: crate::fuse_vfs_adapter
//! [`fuse_write`]: crate::fuse_write
//! [`fuse_read`]: crate::fuse_read
//! [`fuse_flush_fsync`]: crate::fuse_flush_fsync
//! [`fuse_lookup_forget`]: crate::fuse_lookup_forget
//! [`fuse_rename`]: crate::fuse_rename
//! [`fuse_create_unlink_dispatch`]: crate::fuse_create_unlink_dispatch
//! [`readdir_dispatch`]: crate::readdir_dispatch
//! [`write_dispatch`]: crate::write_dispatch
//! [`read_cache`]: crate::read_cache
//! [`writeback_reclaim`]: crate::writeback_reclaim

pub mod observability;
pub mod trace;
// pub mod fuse_preview (deleted)
pub mod coherency_profile;
pub mod dispatch_helpers;
pub mod fsync_handler;
pub mod fuse_create_unlink_dispatch;
pub mod fuse_flush_fsync;
pub mod fuse_lookup_forget;
pub mod fuse_posix_lock;
pub mod fuse_read;
pub mod fuse_rename;
pub mod fuse_vfs_adapter;
pub mod fuse_write;
pub mod handler_prelude;
pub mod live_owner;
pub mod lock_dispatch;
pub mod materialized_cache;
pub mod mmap_coherency;

/// Canonical cache authority model version (docs/cache-authority-model.md).
/// The daemon ReadCache is Derived and superseded by cache-core::PageCache.
/// The FUSE writeback cache is Optional, gated behind --writeback-cache.
pub const DAEMON_CACHE_AUTHORITY_MODEL_VERSION: &str = "v0.420";

pub mod mount_options;
pub mod read_cache;
pub mod readdir_dispatch;
pub mod txg_cycle;
pub mod workload_observer;
pub mod write_dispatch;

pub mod writeback_reclaim;
pub mod xattr_integrity;
pub mod xfstests_harness;

pub mod capacity;
pub mod clustered_mount;
pub mod fusewire;
pub mod ingress;
pub mod maintenance;
pub mod placement_recorder;
pub mod reply;
pub mod runtime;
pub mod scheduler;
pub mod workers_meta;
pub mod workers_ns;
pub mod workers_writeback;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const MOUNT_WRITE_BUFFER_FLUSH_THRESHOLD_BYTES: usize = 64 * 1024 * 1024;
const MOUNT_MAX_UNCOMMITTED_MUTATIONS: u64 = 64 * 1024;

/// Resolve an encryption configuration from a sealed pool key envelope file.
///
/// Uses [`tidefs_local_object_store::encrypt::PoolEncryptionKey::unseal`] to
/// unwrap the pool encryption key from a durable sealed envelope, using a
/// wrapping key derived from the root authentication key. This follows the
/// P9-04 sealed-envelope model: the pool key is never stored in plaintext on
/// disk, in environment variables, or in CLI arguments.
///
/// Returns `None` when the file is missing or the envelope cannot be unsealed
/// (wrong root auth key, corrupt envelope, or tampered file — fail-closed).
/// Returns the [`EncryptionConfig`] with the unsealed key on success.
pub fn resolve_encryption_key_from_envelope(
    envelope_path: &std::path::Path,
    root_auth_key: &tidefs_local_filesystem::RootAuthenticationKey,
) -> Option<tidefs_local_object_store::encrypt::EncryptionConfig> {
    let envelope =
        tidefs_local_object_store::encrypt::SealedPoolKeyEnvelope::read_from_file(envelope_path)?;
    let root_auth_bytes = root_auth_key.as_bytes32();
    let pool_key =
        tidefs_local_object_store::encrypt::PoolEncryptionKey::unseal(&envelope, &root_auth_bytes)?;
    let store_key = pool_key.into_store_key();
    Some(tidefs_local_object_store::encrypt::EncryptionConfig::new(
        store_key,
    ))
}

/// Configuration for `run_mount`: boots a LocalFileSystem and mounts it via FUSE.
#[derive(Debug, Clone)]
pub struct MountConfig {
    /// Optional per-object encryption configuration for the pool.
    /// When set, every object is transparently encrypted with
    /// ChaCha20-Poly1305 AEAD at rest. The encryption key is unsealed
    /// from a durable sealed envelope file via
    /// [`resolve_encryption_key_from_envelope`], using a wrapping key
    /// derived from the root authentication key per P9-04 sealed-envelope
    /// semantics. The pool key is never stored in plaintext on disk,
    /// in environment variables, or in CLI arguments.
    pub encryption: Option<tidefs_local_object_store::encrypt::EncryptionConfig>,
    /// Backing store directory (created if missing).
    pub backing_dir: PathBuf,
    /// FUSE mountpoint directory (created if missing).
    pub mountpoint: PathBuf,
    /// Pool name for a pool-aware mounted owner.
    ///
    /// When present with [`pool_uuid`], the daemon publishes a live-owner
    /// endpoint so `tidefsctl <pool>` commands can talk to this runtime.
    pub pool_name: Option<String>,
    /// Pool UUID for a pool-aware mounted owner.
    pub pool_uuid: Option<[u8; 16]>,
    /// Run in foreground (default true for CLI workflows).
    pub foreground: bool,
    /// Enable debug logging to stderr.
    pub debug: bool,
    /// Enable FUSE writeback cache for mmap support.
    /// When true, FUSE_WRITE_CACHE flagged writes are accepted and
    /// the kernel page cache is used for buffered writes, enabling
    /// mmap(2) and reducing write-amplification for small I/O.
    /// This is the final authority for both the FUSE mount option
    /// (`fuser::MountOption::WritebackCache`) and the adapter's
    /// `writeback_cache_enabled` flag.  It defaults to false until mounted
    /// writeback-cache validation closes the A11 authority gate.
    pub writeback_cache: bool,
    /// Coherency profile for FUSE caching behaviour.
    /// Determines attribute/entry TTLs and invalidation policy. The boolean
    /// [`writeback_cache`] field, not the profile, controls kernel writeback
    /// negotiation and `FUSE_WRITE_CACHE` admission.
    /// Default: Writeback for TTL/invalidation only; kernel writeback remains
    /// opt-in through [`writeback_cache`].
    pub coherency_profile: crate::coherency_profile::CoherencyProfile,
    /// Block devices backing the pool (when set,  is used
    /// only for pool metadata such as labels and markers; all object data
    /// is stored on the block devices).
    pub block_devices: Option<Vec<std::path::PathBuf>>,

    /// Dataset path to resolve through the catalog (default "root").
    /// When None, the root dataset is mounted.
    pub dataset_path: Option<String>,

    /// Authority used to admit the mount as standalone/local or
    /// cluster-lease-authorized.
    pub mount_authority: MountAuthority,
}

/// Mount authority material accepted by the daemon admission boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountAuthority {
    /// Standalone/local mount with no cluster lease material.
    Standalone,
    /// Cluster mount authorized by a validated pool lease token.
    ClusterLease(ClusterMountAuthority),
}

/// Raw mount authority material decoded at the daemon boundary.
#[derive(Debug, Clone, Copy)]
pub enum MountAuthorityWire<'a> {
    Standalone {
        lease_token_bytes: Option<&'a [u8]>,
    },
    ClusterLease {
        expected_pool_guid: [u8; 16],
        lease_token_bytes: Option<&'a [u8]>,
    },
}

/// Validated cluster lease authority for a mounted pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterMountAuthority {
    token: tidefs_cluster::PoolLeaseToken,
}

impl MountAuthority {
    pub fn standalone() -> Self {
        Self::Standalone
    }

    pub fn cluster_lease(
        expected_pool_guid: [u8; 16],
        token: tidefs_cluster::PoolLeaseToken,
    ) -> Result<Self, String> {
        validate_cluster_lease_token(&token, &expected_pool_guid)?;
        Ok(Self::ClusterLease(ClusterMountAuthority { token }))
    }

    pub fn from_wire(wire: MountAuthorityWire<'_>) -> Result<Self, String> {
        match wire {
            MountAuthorityWire::Standalone {
                lease_token_bytes: None,
            } => Ok(Self::standalone()),
            MountAuthorityWire::Standalone {
                lease_token_bytes: Some(_),
            } => Err("standalone mount cannot carry cluster lease token material".to_string()),
            MountAuthorityWire::ClusterLease {
                expected_pool_guid,
                lease_token_bytes,
            } => {
                use bincode::Options;

                let token_bytes = lease_token_bytes.ok_or_else(|| {
                    "cluster mount requested but no cluster lease token provided: \
                     acquire a lease from a live storage-node before mounting"
                        .to_string()
                })?;
                let token: tidefs_cluster::PoolLeaseToken = bincode::DefaultOptions::new()
                    .with_fixint_encoding()
                    .reject_trailing_bytes()
                    .deserialize(token_bytes)
                    .map_err(|e| {
                        format!("cluster mount: corrupt or truncated lease token bytes: {e}")
                    })?;
                Self::cluster_lease(expected_pool_guid, token)
            }
        }
    }

    pub fn is_cluster_authorized(&self) -> bool {
        matches!(self, Self::ClusterLease(_))
    }

    fn validate_for_pool(
        &self,
        pool_uuid: Option<&[u8; 16]>,
    ) -> Result<Option<&tidefs_cluster::PoolLeaseToken>, String> {
        match self {
            Self::Standalone => Ok(None),
            Self::ClusterLease(authority) => {
                let expected_pool_guid = pool_uuid.ok_or_else(|| {
                    "cluster mount: pool UUID is required to validate lease authority".to_string()
                })?;
                validate_cluster_lease_token(&authority.token, expected_pool_guid)?;
                Ok(Some(&authority.token))
            }
        }
    }
}

impl ClusterMountAuthority {
    pub fn token(&self) -> &tidefs_cluster::PoolLeaseToken {
        &self.token
    }
}

fn validate_cluster_lease_token(
    token: &tidefs_cluster::PoolLeaseToken,
    expected_pool_guid: &[u8; 16],
) -> Result<(), String> {
    if token.node_id == 0 {
        return Err("cluster mount: lease token has zero node_id".to_string());
    }
    if token.epoch.0 == 0 {
        return Err("cluster mount: lease token has zero epoch".to_string());
    }
    if token.lease_id == 0 {
        return Err("cluster mount: lease token has zero lease_id".to_string());
    }
    if !token.authorizes_pool(expected_pool_guid) {
        return Err("cluster mount: lease token pool GUID mismatch".to_string());
    }
    Ok(())
}

/// Bootstrap the TideFS FUSE mount lifecycle.
///
/// Creates a `LocalFileSystem` rooted at `config.backing_dir`, wraps it in
/// the `VfsLocalFileSystem` adapter, and mounts a FUSE session at
/// `config.mountpoint`. The calling thread is parked until the process
/// receives SIGINT or SIGTERM; shutdown joins the FUSE session so clean
/// unmount and filesystem teardown finish before the process exits.
///
/// # Errors
///
/// Returns a human-readable string on store-open failure, adapter-init
/// failure, or FUSE mount failure.
pub fn run_mount(config: MountConfig) -> Result<(), String> {
    use std::fs;

    use tidefs_dataset_lifecycle::DatasetId;
    use tidefs_local_filesystem::human::local_filesystem::StoreOptions;
    use tidefs_local_filesystem::vfs_engine_impl::VfsLocalFileSystem;
    use tidefs_local_filesystem::LocalFileSystem;

    let cluster_lease_token = config
        .mount_authority
        .validate_for_pool(config.pool_uuid.as_ref())?;

    fs::create_dir_all(&config.backing_dir)
        .map_err(|e| format!("create backing dir {}: {e}", config.backing_dir.display()))?;
    fs::create_dir_all(&config.mountpoint)
        .map_err(|e| format!("create mountpoint {}: {e}", config.mountpoint.display()))?;

    let root_auth_key = tidefs_local_filesystem::RootAuthenticationKey::from_environment()
        .unwrap_or_else(|_| tidefs_local_filesystem::RootAuthenticationKey::demo_key());

    if config.debug {
        eprintln!(
            "tidefsctl: opening store at {}",
            config.backing_dir.display()
        );
    }

    let mut lfs = if let Some(ref devices) = config.block_devices {
        // Block-device-backed pool: use metadata dir + block devices.
        eprintln!(
            "tidefsctl: opening block-device-backed pool with {} device(s)",
            devices.len()
        );
        if let Some(ref enc) = config.encryption {
            eprintln!("tidefsctl: encryption enabled (key fingerprint not logged)");
            LocalFileSystem::open_with_block_devices_and_encryption(
                &config.backing_dir,
                devices,
                StoreOptions::default(),
                root_auth_key,
                enc.clone(),
            )
        } else {
            LocalFileSystem::open_with_block_devices(
                &config.backing_dir,
                devices,
                StoreOptions::default(),
                root_auth_key,
            )
        }
    } else if let Some(ref enc) = config.encryption {
        eprintln!("tidefsctl: encryption enabled (key fingerprint not logged)");
        LocalFileSystem::open_with_root_authentication_key_and_encryption(
            &config.backing_dir,
            StoreOptions::default(),
            root_auth_key,
            enc.clone(),
        )
    } else {
        LocalFileSystem::open_with_root_authentication_key(
            &config.backing_dir,
            StoreOptions::default(),
            root_auth_key,
        )
    }
    .map_err(|e| format!("open store: {e}"))?;

    // Resolve dataset path through the canonical catalog.
    let dataset_id: Option<DatasetId> = if let Some(ref ds_path) = config.dataset_path {
        match lfs.dataset_catalog().snapshot_lookup(ds_path) {
            Ok(id) => {
                if config.debug {
                    eprintln!("tidefsctl: resolved dataset \"{ds_path}\" -> {id}");
                }
                Some(id)
            }
            Err(e) => {
                return Err(format!("dataset lookup \"{ds_path}\" failed: {e}"));
            }
        }
    } else {
        None
    };

    // Lifecycle gate: refuse mount for non-Active datasets.
    if let Some(ref ds_path) = config.dataset_path {
        let lifecycle_state = lfs
            .dataset_catalog()
            .lifecycle_state(ds_path)
            .map_err(|e| format!("dataset lifecycle check \"{ds_path}\" failed: {e}"))?;
        if lifecycle_state != tidefs_dataset_catalog::LifecycleState::Active {
            return Err(format!(
                "dataset \"{ds_path}\" is in {lifecycle_state} state and cannot be mounted"
            ));
        }
    }
    if let Some(ds_id) = dataset_id {
        lfs.set_mounted_dataset_id(*ds_id.as_bytes());
    }

    lfs.set_write_buffer_flush_threshold_bytes(MOUNT_WRITE_BUFFER_FLUSH_THRESHOLD_BYTES);
    lfs.set_auto_commit(false);
    lfs.set_commit_group_throughput_profile();
    lfs.set_max_uncommitted_mutations(MOUNT_MAX_UNCOMMITTED_MUTATIONS);

    let writeback_tracker = Arc::clone(lfs.writeback_range_tracker());

    // Build the base VfsLocalFileSystem, optionally scoped to a dataset root.
    let mut base_engine = VfsLocalFileSystem::new(lfs);
    // When mounting a non-root dataset, scope path resolution to the
    // dataset directory within the pool so the FUSE mount root exposes
    // only that dataset's contents.
    if let Some(ref ds_path) = config.dataset_path {
        if ds_path != "root" {
            let dataset_fs_path = format!("/{ds_path}");
            if config.debug {
                eprintln!("tidefsctl: dataset mount root: {ds_path} -> {dataset_fs_path}");
            }
            base_engine = base_engine.with_dataset_root(&dataset_fs_path);
        }
    }

    // When cluster-authorized, wrap the engine in a placement-recording layer.
    let vfs_engine: Box<dyn tidefs_vfs_engine::VfsEngineStatFs + Send> =
        if let Some(token) = cluster_lease_token {
            let member_id = token.node_id;
            let epoch = token.epoch.0;
            let cluster_engine = crate::placement_recorder::ClusterPlacementVfsEngine::new(
                base_engine,
                config.backing_dir.clone(),
                member_id,
                epoch,
            );
            Box::new(cluster_engine)
        } else {
            Box::new(base_engine)
        };
    let mut adapter = fuse_vfs_adapter::FuseVfsAdapter::new(vfs_engine)
        .map_err(|e| format!("adapter init: {e:?}"))?
        .with_coherency_profile(config.coherency_profile);

    // Attach the resolved stable DatasetId for lifecycle gating and metrics.
    if let Some(ds_id) = dataset_id {
        adapter = adapter.with_dataset_id(ds_id);
    }

    if config.writeback_cache {
        adapter = adapter
            .with_writeback_cache_enabled()
            .with_writeback_range_tracker(writeback_tracker);
    } else {
        adapter = adapter.with_writeback_cache_disabled();
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    install_signal_handlers(Arc::clone(&shutdown)).map_err(|e| format!("signal handler: {e}"))?;
    let live_owner_engine = adapter.engine_handle();

    let mut options = vec![
        fuser::MountOption::FSName("tidefs".into()),
        fuser::MountOption::NoAtime,
    ];
    if !config.foreground {
        options.push(fuser::MountOption::AllowOther);
    }
    if config.writeback_cache {
        options.push(fuser::MountOption::WritebackCache);
    }

    let session = fuser::spawn_mount2(adapter, &config.mountpoint, &options)
        .map_err(|e| format!("FUSE mount: {e}"))?;

    eprintln!("Mounted TideFS at {}", config.mountpoint.display());

    // Refuse idmapped mounts: TideFS does not support idmapped mount
    // UID/GID translation (#6418, NEXT-FUSE-015).
    check_idmapped_mount(&config.mountpoint)?;
    let live_owner = match (&config.pool_name, config.pool_uuid) {
        (Some(pool_name), Some(pool_uuid)) => {
            let runtime_dir = PathBuf::from("/run/tidefs/pools").join(hex_uuid(&pool_uuid));
            let owner_config = live_owner::LiveOwnerConfig {
                pool_name: pool_name.clone(),
                pool_uuid,
                backing_dir: config.backing_dir.clone(),
                mountpoint: config.mountpoint.clone(),
                runtime_dir,
            };
            Some(live_owner::start_fuse_owner(
                owner_config,
                live_owner_engine,
                Arc::clone(&shutdown),
            )?)
        }
        _ => None,
    };

    if config.debug {
        eprintln!("tidefsctl: FUSE session active, Ctrl-C to stop");
    }

    while !shutdown.load(Ordering::Relaxed) {
        std::thread::park_timeout(std::time::Duration::from_millis(500));
    }

    crate::observability::emit_all_summaries();
    session.join();
    if let Some(ref block_devices) = config.block_devices {
        let lock_dir = PathBuf::from("/run/tidefs/import");
        match tidefs_pool_import::pool_export(block_devices, &lock_dir, false) {
            Ok(()) => {
                if let Some(ref pool_name) = config.pool_name {
                    eprintln!("tidefsctl: pool exported: {pool_name}");
                } else {
                    eprintln!("tidefsctl: block-device pool exported");
                }
            }
            Err(err) => {
                eprintln!("tidefsctl: warning: clean pool export failed during unmount: {err}");
            }
        }
    }
    if let Some(live_owner) = live_owner {
        live_owner.stop();
    }
    eprintln!(
        "tidefsctl: filesystem unmounted from {}",
        config.mountpoint.display()
    );
    Ok(())
}

fn hex_uuid(uuid: &[u8; 16]) -> String {
    uuid.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn install_signal_handlers(shutdown: Arc<AtomicBool>) -> Result<(), String> {
    use std::mem;
    use std::ptr;

    static mut SHUTDOWN_PTR: Option<*const AtomicBool> = None;

    unsafe {
        SHUTDOWN_PTR = Some(Arc::as_ptr(&shutdown));
    }

    extern "C" fn handle(_signum: libc::c_int) {
        unsafe {
            if let Some(ptr) = SHUTDOWN_PTR {
                let flag: &AtomicBool = &*ptr;
                flag.store(true, Ordering::Release);
            }
        }
    }

    let mut sa: libc::sigaction = unsafe { mem::zeroed() };
    sa.sa_sigaction = handle as usize;
    unsafe {
        libc::sigfillset(&mut sa.sa_mask);
    }

    for &signum in &[libc::SIGINT, libc::SIGTERM] {
        let rc = unsafe { libc::sigaction(signum, &sa, ptr::null_mut()) };
        if rc != 0 {
            return Err(format!(
                "sigaction({}) failed: {}",
                signum,
                std::io::Error::last_os_error()
            ));
        }
    }

    Ok(())
}

// ── Safe defrag ioctl wrapper ────────────────────────────────────────────

/// Issue a `TIDEFS_IOC_DEFRAG` ioctl on an open file descriptor belonging
/// to a FUSE mount. Returns `(extents_before, extents_after, reduction_pct,
/// inodes_defragged)` on success.
///
/// # Safety invariants
///
/// This function is safe because:
/// - `fd` is a valid file descriptor (guaranteed by the caller through
///   `AsRawFd` on an open `File`).
/// - `arg` is a correctly-sized stack buffer written and read within a
///   single synchronous call.
/// - `TIDEFS_IOC_DEFRAG` is the only ioctl issued, and it is a FUSE ioctl
///   forwarded to the daemon with no side effects on the fd itself.
pub fn tidefs_defrag_ioctl(
    fd: std::os::unix::io::RawFd,
    ino: u64,
    recursive: bool,
) -> std::io::Result<(u64, u64, u32, u64)> {
    let flags: u64 = if recursive { 1 } else { 0 };

    // 32-byte buffer matching the _IOWR encoding (16B input, 24B output).
    let mut arg = [0u8; 32];
    arg[0..8].copy_from_slice(&ino.to_le_bytes());
    arg[8..16].copy_from_slice(&flags.to_le_bytes());

    let cmd_nr = crate::fusewire::TIDEFS_IOC_DEFRAG;

    // SAFETY: fd is a valid FUSE file descriptor. arg is a correctly-sized
    // stack buffer. This is a FUSE ioctl forwarded to the daemon with no
    // kernel memory safety risk.
    let ret = unsafe { libc::ioctl(fd, cmd_nr as _, &mut arg as *mut _ as *mut libc::c_void) };

    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }

    let before = u64::from_le_bytes(arg[0..8].try_into().unwrap());
    let after = u64::from_le_bytes(arg[8..16].try_into().unwrap());
    let reduction = u32::from_le_bytes(arg[16..20].try_into().unwrap());
    let inodes = u32::from_le_bytes(arg[20..24].try_into().unwrap()) as u64;

    Ok((before, after, reduction, inodes))
}

/// Check whether a FUSE mountpoint has been idmapped externally via
/// `mount_setattr()` (Linux 5.12+).  Idmapped mounts translate UIDs/GIDs
/// transparently before FUSE requests reach the daemon; TideFS does not
/// currently support this translation and must refuse to operate.
///
/// Detection inspects `/proc/self/mountinfo` for the mountpoint and
/// compares the daemon's view of the mount root with the expected FUSE
/// mount source.  A mismatch indicates a bind or idmapped mount that was
/// not created directly by this daemon.
///
/// Returns `Ok(())` when no idmapped mount is detected, or an `Err` with
/// a human-readable refusal message when an external mount modification
/// is found.
///
/// This is a best-effort check: it cannot detect all possible idmapped
/// mount configurations, but it catches the common patterns (bind-mount
/// with remapping, idmapped remount) and provides an explicit refusal
/// contract.
/// Inspect raw mountinfo text for validation of an idmapped mount at
/// `mountpoint`.  Extracted for unit-testability; the production entry
/// point is [`check_idmapped_mount`].
///
/// Returns `Ok(())` when no idmapped mount is detected, or an `Err` with
/// a human-readable refusal message.
fn check_idmapped_mount_from_text(
    mountinfo_text: &str,
    mountpoint: &std::path::Path,
) -> Result<(), String> {
    let mount_str = mountpoint.to_string_lossy();

    // Collect all mount entries where our mountpoint appears as the
    // mount point (field 5 in mountinfo).
    let mut entries_for_mp: Vec<&str> = Vec::new();

    for line in mountinfo_text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // mountinfo format: id parent_id dev root mountpoint opts ... - fstype source ...
        // Minimum 7 fields: id, parent_id, dev, root, mountpoint, opts, sep(-)
        if fields.len() >= 7 && fields[4] == mount_str.as_ref() {
            entries_for_mp.push(line);
        }
    }

    // If no entries found, mountpoint may not be mounted yet (or is in
    // a different namespace).  No refusal — the FUSE session itself
    // would have already failed if the mountpoint wasn't valid.
    if entries_for_mp.is_empty() {
        return Ok(());
    }

    // For a normal FUSE mount, the "root" field (field 3) is "/".
    // A non-"/" root indicates a bind mount or idmapped remount.
    for entry in &entries_for_mp {
        let fields: Vec<&str> = entry.split_whitespace().collect();
        if fields.len() >= 4 && fields[3] != "/" {
            return Err(format!(
                "TideFS does not support idmapped mounts.                  Mount at {} has non-root root-path '{}' in mountinfo,                  indicating a bind or idmapped remount. Mount refused.",
                mountpoint.display(),
                fields[3]
            ));
        }
        // Check for idmap-related options in mount options (field 5)
        // and super options (the field after mount source, following
        // the "-" separator).  An idmap marker in either location
        // indicates an idmapped mount.
        let mount_opts = if fields.len() > 5 { fields[5] } else { "" };

        let super_opts = if fields.len() > 7 {
            if let Some(sep_pos) = fields.iter().position(|&f| f == "-") {
                if fields.len() > sep_pos + 3 {
                    fields[sep_pos + 3]
                } else {
                    ""
                }
            } else {
                ""
            }
        } else {
            ""
        };

        if mount_opts.contains("idmap")
            || mount_opts.contains("idmapped")
            || super_opts.contains("idmap")
            || super_opts.contains("idmapped")
        {
            return Err(
                "TideFS does not support idmapped mounts.                  Mount options indicate an idmapped mount. Mount refused."
                    .to_string(),
            );
        }
    }

    Ok(())
}

/// Check whether a FUSE mountpoint has been idmapped externally via
/// `mount_setattr()` (Linux 5.12+).  Idmapped mounts translate UIDs/GIDs
/// transparently before FUSE requests reach the daemon; TideFS does not
/// currently support this translation and must refuse to operate.
///
/// Detection inspects `/proc/self/mountinfo` for the mountpoint and
/// compares the daemon's view of the mount root with the expected FUSE
/// mount source.  A mismatch indicates a bind or idmapped mount that was
/// not created directly by this daemon.
///
/// Returns `Ok(())` when no idmapped mount is detected, or an `Err` with
/// a human-readable refusal message when an external mount modification
/// is found.
///
/// This is a best-effort check: it cannot detect all possible idmapped
/// mount configurations, but it catches the common patterns (bind-mount
/// with remapping, idmapped remount) and provides an explicit refusal
/// contract.
pub fn check_idmapped_mount(mountpoint: &std::path::Path) -> Result<(), String> {
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo")
        .map_err(|e| format!("cannot read /proc/self/mountinfo: {e}"))?;

    match check_idmapped_mount_from_text(&mountinfo, mountpoint) {
        Ok(()) => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod mount_authority_tests {
    use super::*;
    use tidefs_cluster::{EpochId, PoolLeaseToken, WriteFence};

    const POOL_GUID: [u8; 16] = [0x42; 16];
    const OTHER_POOL_GUID: [u8; 16] = [0x24; 16];

    fn lease_token(node_id: u64, pool_guid: [u8; 16], epoch: u64, lease_id: u64) -> PoolLeaseToken {
        PoolLeaseToken::new(
            node_id,
            pool_guid,
            EpochId(epoch),
            lease_id,
            3,
            WriteFence::new(EpochId(epoch), 9),
            60_000,
        )
    }

    fn token_bytes(token: &PoolLeaseToken) -> Vec<u8> {
        bincode::serialize(token).expect("serialize lease token")
    }

    #[test]
    fn standalone_mount_authority_is_local_only() {
        let authority = MountAuthority::standalone();

        assert!(!authority.is_cluster_authorized());
        assert!(authority.validate_for_pool(None).unwrap().is_none());
    }

    #[test]
    fn standalone_wire_rejects_token_material() {
        let bytes = token_bytes(&lease_token(7, POOL_GUID, 2, 99));
        let err = MountAuthority::from_wire(MountAuthorityWire::Standalone {
            lease_token_bytes: Some(&bytes),
        })
        .unwrap_err();

        assert!(
            err.contains("standalone mount cannot carry cluster lease token material"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn cluster_wire_rejects_missing_token() {
        let err = MountAuthority::from_wire(MountAuthorityWire::ClusterLease {
            expected_pool_guid: POOL_GUID,
            lease_token_bytes: None,
        })
        .unwrap_err();

        assert!(
            err.contains("no cluster lease token provided"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn cluster_wire_rejects_short_token() {
        let bytes = [0xAA, 0xBB, 0xCC];
        let err = MountAuthority::from_wire(MountAuthorityWire::ClusterLease {
            expected_pool_guid: POOL_GUID,
            lease_token_bytes: Some(&bytes),
        })
        .unwrap_err();

        assert!(
            err.contains("corrupt or truncated lease token bytes"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn cluster_wire_rejects_corrupt_token() {
        let mut bytes = token_bytes(&lease_token(7, POOL_GUID, 2, 99));
        bytes.push(0xFF);
        let err = MountAuthority::from_wire(MountAuthorityWire::ClusterLease {
            expected_pool_guid: POOL_GUID,
            lease_token_bytes: Some(&bytes),
        })
        .unwrap_err();

        assert!(
            err.contains("corrupt or truncated lease token bytes"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn cluster_wire_rejects_zero_node_token() {
        let bytes = token_bytes(&lease_token(0, POOL_GUID, 2, 99));
        let err = MountAuthority::from_wire(MountAuthorityWire::ClusterLease {
            expected_pool_guid: POOL_GUID,
            lease_token_bytes: Some(&bytes),
        })
        .unwrap_err();

        assert!(err.contains("zero node_id"), "unexpected error: {err}");
    }

    #[test]
    fn cluster_wire_rejects_pool_mismatch() {
        let bytes = token_bytes(&lease_token(7, OTHER_POOL_GUID, 2, 99));
        let err = MountAuthority::from_wire(MountAuthorityWire::ClusterLease {
            expected_pool_guid: POOL_GUID,
            lease_token_bytes: Some(&bytes),
        })
        .unwrap_err();

        assert!(
            err.contains("pool GUID mismatch"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn cluster_wire_accepts_valid_lease_authority() {
        let token = lease_token(7, POOL_GUID, 2, 99);
        let bytes = token_bytes(&token);
        let authority = MountAuthority::from_wire(MountAuthorityWire::ClusterLease {
            expected_pool_guid: POOL_GUID,
            lease_token_bytes: Some(&bytes),
        })
        .expect("valid token should decode into cluster mount authority");

        let admitted = authority
            .validate_for_pool(Some(&POOL_GUID))
            .expect("authority should validate")
            .expect("cluster authority should return lease token");

        assert!(authority.is_cluster_authorized());
        assert_eq!(admitted.node_id, token.node_id);
        assert_eq!(admitted.epoch, token.epoch);
        assert_eq!(admitted.lease_id, token.lease_id);
    }

    #[test]
    fn cluster_authority_validates_for_mount_pool() {
        let token = lease_token(7, POOL_GUID, 2, 99);
        let authority = MountAuthority::cluster_lease(POOL_GUID, token.clone()).unwrap();
        let admitted = authority
            .validate_for_pool(Some(&POOL_GUID))
            .expect("authority should validate")
            .expect("cluster authority should return lease token");

        assert!(authority.is_cluster_authorized());
        assert_eq!(admitted.node_id, token.node_id);
        assert_eq!(admitted.epoch, token.epoch);
    }
}

// ── Dataset mount_lookup validation tests ────────────────────────────
//
// These tests validate that the mount path correctly resolves dataset paths
// through the canonical `DatasetCatalog::mount_lookup`, gates mounts on
// dataset lifecycle state, and retains the stable `DatasetId` in the
// mounted session.  They exercise the pool store path (create, persist,
// re-open) and the catalog rename/destroy paths.
//
// Validation tier: source/unit (lower-tier; QEMU validation required for
// release-tier FUSE claims).
#[cfg(test)]
mod dataset_mount_lookup_tests {
    use tidefs_dataset_catalog::{
        DatasetFlags, DatasetId, DatasetType, LifecycleState, SyncGuarantee,
    };
    use tidefs_local_filesystem::human::local_filesystem::StoreOptions;
    use tidefs_local_filesystem::{LocalFileSystem, RootAuthenticationKey};

    /// Helper: create a fresh `LocalFileSystem` in a temp directory.
    fn open_temp_fs(dir: &std::path::Path) -> LocalFileSystem {
        std::fs::create_dir_all(dir).unwrap();
        LocalFileSystem::open_with_root_authentication_key(
            dir,
            StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("open LocalFileSystem")
    }

    #[test]
    fn mount_lookup_resolves_root_dataset() {
        let dir = tempfile::tempdir().unwrap();
        let fs = open_temp_fs(dir.path());
        let id = fs.dataset_catalog().mount_lookup("root");
        assert_eq!(
            id.expect("root dataset must resolve"),
            DatasetId::from_bytes([0u8; 16]),
            "root catalog id must match the mounted root dataset id"
        );
    }

    #[test]
    fn mount_lookup_fails_for_nonexistent_dataset() {
        let dir = tempfile::tempdir().unwrap();
        let fs = open_temp_fs(dir.path());
        let id = fs.dataset_catalog().mount_lookup("nonexistent/ds");
        assert!(id.is_err(), "nonexistent dataset must not resolve");
    }

    #[test]
    fn lifecycle_state_is_active_for_root() {
        let dir = tempfile::tempdir().unwrap();
        let fs = open_temp_fs(dir.path());
        let state = fs.dataset_catalog().lifecycle_state("root").unwrap();
        assert_eq!(state, LifecycleState::Active, "root must be Active");
    }

    #[test]
    fn mount_lookup_returns_same_id_after_rename() {
        let dir = tempfile::tempdir().unwrap();
        let mut fs = open_temp_fs(dir.path());

        let ds_id = DatasetId::from_bytes([2u8; 16]);
        fs.dataset_catalog_mut()
            .create(
                "ds1",
                ds_id,
                DatasetType::Filesystem,
                1,
                vec![],
                DatasetFlags::NONE,
                SyncGuarantee::default(),
            )
            .unwrap();
        fs.persist_dataset_catalog().unwrap();

        let id_before = fs.dataset_catalog().mount_lookup("ds1").unwrap();
        assert_eq!(id_before, ds_id);

        // Rename ds1 -> renamed_ds
        fs.dataset_catalog_mut()
            .rename("ds1", "renamed_ds")
            .unwrap();
        fs.persist_dataset_catalog().unwrap();

        // Old path no longer resolves
        assert!(fs.dataset_catalog().mount_lookup("ds1").is_err());

        // New path resolves to same ID
        let id_after = fs.dataset_catalog().mount_lookup("renamed_ds").unwrap();
        assert_eq!(id_after, ds_id, "stable DatasetId preserved after rename");
    }

    #[test]
    fn lifecycle_rejects_mount_for_destroyed_dataset() {
        let dir = tempfile::tempdir().unwrap();
        let mut fs = open_temp_fs(dir.path());

        let ds_id = DatasetId::from_bytes([3u8; 16]);
        fs.dataset_catalog_mut()
            .create(
                "ds3",
                ds_id,
                DatasetType::Filesystem,
                1,
                vec![],
                DatasetFlags::NONE,
                SyncGuarantee::default(),
            )
            .unwrap();
        fs.persist_dataset_catalog().unwrap();

        // Destroy the dataset
        fs.dataset_catalog_mut().destroy("ds3").unwrap();
        fs.persist_dataset_catalog().unwrap();

        // Verify dataset entry is removed (lifecycle_state returns NotFound)
        let state_result = fs.dataset_catalog().lifecycle_state("ds3");
        assert!(
            matches!(
                state_result,
                Err(tidefs_dataset_catalog::CatalogError::NotFound)
            ),
            "destroyed dataset must be removed from catalog"
        );

        // mount_lookup should fail because the catalog removes entries on destroy
        assert!(
            fs.dataset_catalog().mount_lookup("ds3").is_err(),
            "destroyed dataset must not resolve via mount_lookup"
        );
    }
}

#[cfg(test)]
mod idmapped_mount_tests {
    use super::*;
    use std::path::Path;

    /// Normal FUSE mount entry — root is "/", no idmap options.
    const NORMAL_MOUNTINFO: &str =
        "36 35 0:45 / /mnt/tidefs rw,nosuid,nodev,noatime - fuse.tidefs /dev/fuse rw
";

    /// Bind mount of a subdirectory — root is not "/" ("/subdir").
    const BIND_MOUNT_MOUNTINFO: &str =
        "37 35 0:45 /subdir /mnt/tidefs rw,nosuid,nodev,noatime - fuse.tidefs /dev/fuse rw
";

    /// Normal mount with "idmap" in super options.
    const IDMAP_SUPEROPT_MOUNTINFO: &str =
        "36 35 0:45 / /mnt/tidefs rw,nosuid,nodev,noatime - fuse.tidefs /dev/fuse rw,idmap
";

    /// Normal mount with "idmapped" in mount options.
    const IDMAPPED_OPT_MOUNTINFO: &str =
        "36 35 0:45 / /mnt/tidefs rw,idmapped - fuse.tidefs /dev/fuse rw
";

    /// Mountpoint not present at all.
    const EMPTY_MOUNTINFO: &str = "36 35 0:45 / /mnt/other rw,noatime - ext4 /dev/sda1 rw
";

    #[test]
    fn normal_fuse_mount_passes() {
        let mp = Path::new("/mnt/tidefs");
        assert!(
            check_idmapped_mount_from_text(NORMAL_MOUNTINFO, mp).is_ok(),
            "normal FUSE mount must pass idmapped check"
        );
    }

    #[test]
    fn bind_mount_with_non_root_path_is_refused() {
        let mp = Path::new("/mnt/tidefs");
        let err = check_idmapped_mount_from_text(BIND_MOUNT_MOUNTINFO, mp).unwrap_err();
        assert!(
            err.contains("non-root"),
            "bind mount should be refused: {err}"
        );
        assert!(
            err.contains("idmapped"),
            "refusal should mention idmapped: {err}"
        );
    }

    #[test]
    fn idmap_in_super_options_is_refused() {
        let mp = Path::new("/mnt/tidefs");
        let err = check_idmapped_mount_from_text(IDMAP_SUPEROPT_MOUNTINFO, mp).unwrap_err();
        assert!(
            err.contains("idmapped"),
            "idmap superopt should be refused: {err}"
        );
    }

    #[test]
    fn idmapped_in_mount_options_is_refused() {
        let mp = Path::new("/mnt/tidefs");
        let err = check_idmapped_mount_from_text(IDMAPPED_OPT_MOUNTINFO, mp).unwrap_err();
        assert!(
            err.contains("idmapped"),
            "idmapped mount option should be refused: {err}"
        );
    }

    #[test]
    fn missing_mountpoint_is_ok_not_refused() {
        let mp = Path::new("/mnt/tidefs");
        assert!(
            check_idmapped_mount_from_text(EMPTY_MOUNTINFO, mp).is_ok(),
            "missing mountpoint should not cause false positive"
        );
    }

    #[test]
    fn empty_mountinfo_is_ok() {
        let mp = Path::new("/mnt/tidefs");
        assert!(
            check_idmapped_mount_from_text("", mp).is_ok(),
            "empty mountinfo should not cause false positive"
        );
    }

    #[test]
    fn different_mountpoint_is_ignored() {
        // Mountinfo has entries for /mnt/other but we check for /mnt/tidefs
        let mp = Path::new("/mnt/tidefs");
        assert!(
            check_idmapped_mount_from_text(EMPTY_MOUNTINFO, mp).is_ok(),
            "unrelated mountpoint should be ignored"
        );
    }
}

// Re-export the clustered POSIX mount admission boundary so callers can use
// the daemon crate as the mount-runtime API surface.
pub use clustered_mount::{
    ClusteredPosixAuthoritySnapshot, ClusteredPosixMountAdmissionError,
    ClusteredPosixMountRuntime,
};
