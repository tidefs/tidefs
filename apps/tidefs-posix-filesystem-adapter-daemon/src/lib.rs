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
//!    and projects each operation into the mounted [`VfsEngine`]. Adapter
//!    handle, lookup-reference, page-cache, and reply state remains derived
//!    transport state; namespace, inode, metadata, and persistence decisions
//!    stay in the engine.
//!
//! 3. **Reply**: each handler returns either a success value (packed into
//!    a FUSE reply) or an [`Errno`] error code.  The reply layer
//!    converts these into the appropriate kernel reply message.
//!
//! [`FuseVfsAdapter`]: crate::fuse_vfs_adapter::FuseVfsAdapter
//! [`RequestCtx`]: tidefs_types_vfs_core::RequestCtx
//! [`Errno`]: tidefs_vfs_engine::Errno
//!
//! # Error handling ownership
//!
//! Every dispatched failure that reaches the kernel is returned as an
//! [`Errno`]. The mappings are source-owned: ingress validation lives in
//! [`ingress`] and [`fusewire`], operation-specific translation lives in the
//! dispatch modules below, and mounted errno regressions live in
//! `tests/posix_error_regression.rs`.
//!
//! Transport and mount setup failures still surface from [`run_mount`] as
//! process-level errors. Unsupported FUSE capabilities are explicit adapter
//! boundary outcomes, not POSIX-completeness claims; the scoped policy boundary
//! is `docs/FUSE_ADAPTER_CONTRACT_ASSUMPTIONS.md`.
//!
//! Keep per-operation errno tables, validation status, and recovery guidance in
//! source, tests, GitHub issue or PR evidence, and CI artifacts instead of this
//! crate-level overview.
//!
//! [`ingress`]: crate::ingress
//! [`fusewire`]: crate::fusewire
//!
//! # Module overview
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`fuse_vfs_adapter`] | Main `fuser::Filesystem` impl; ~30 FUSE op handlers |
//! | [`fuse_flush_fsync`] | Flush/fsync dispatch with writeback and extent commit |
//! | [`fuse_rename`] | Atomic rename with cross-directory validation |
//! | [`fuse_create_unlink_dispatch`] | Unlink/rmdir with capacity release |
//! | [`readdir_dispatch`] | Readdir/readdirplus with cookie-based pagination |
//! | [`write_dispatch`] | Ingress-classified write staging and dirty scheduling |
//! | [`read_cache`] | In-memory read-ahead cache for hot data |
//! | [`writeback_reclaim`] | Dirty-page writeback and reclaim |
//!
//! [`fuse_vfs_adapter`]: crate::fuse_vfs_adapter
//! [`fuse_flush_fsync`]: crate::fuse_flush_fsync
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
pub mod fuse_create_unlink_dispatch;
pub mod fuse_flush_fsync;
pub mod fuse_posix_lock;
pub mod fuse_rename;
pub mod fuse_vfs_adapter;
pub mod handler_prelude;
pub mod live_owner;
pub mod lock_dispatch;
#[cfg(feature = "workload-telemetry")]
pub mod materialized_cache;
pub mod mmap_coherency;

/// Canonical cache authority model version (docs/cache-authority-model.md).
/// The daemon ReadCache is Derived and remains a separate adapter dispatch
/// path from cache-core::PageCache.
/// The FUSE writeback cache is Optional, gated behind --writeback-cache.
pub const DAEMON_CACHE_AUTHORITY_MODEL_VERSION: &str = "v0.420";

pub mod mount_options;
pub mod read_cache;
pub mod readdir_dispatch;
#[cfg(feature = "workload-telemetry")]
pub mod workload_observer;
pub mod write_dispatch;

pub mod writeback_reclaim;
pub mod xattr_integrity;
pub mod xfstests_harness;

pub mod capacity;
#[cfg(feature = "cluster")]
pub mod clustered_lock_forwarder;
#[cfg(feature = "cluster")]
pub mod clustered_mount;
pub mod fusewire;
pub mod ingress;
pub mod maintenance;
#[cfg(feature = "cluster")]
pub mod placement_recorder;
pub mod reply;
pub mod runtime;
pub mod scheduler;
pub mod workers_meta;
pub mod workers_ns;
pub mod workers_writeback;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
#[cfg(feature = "cluster")]
use std::time::{Duration, Instant};

use tidefs_background_scheduler::{
    BackgroundScheduler, BackgroundService, ServiceBudget, ServiceError, ServicePriority,
    TickReport,
};
use tidefs_dataset_lifecycle::SyncGuarantee;
use tidefs_vfs_engine::{
    LivePoolAdminArg, LivePoolAdminArgs, LivePoolAdminCommand, LivePoolAdminOutput,
    LivePoolAdminRequest, LivePoolAdminResponseBody,
};

const MOUNT_WRITE_BUFFER_FLUSH_THRESHOLD_BYTES: usize = 64 * 1024 * 1024;
const MOUNT_MAX_UNCOMMITTED_MUTATIONS: u64 = 64 * 1024;
const MOUNT_FUSE_INIT_TIMEOUT_SECS: u64 = 5;
#[cfg(feature = "cluster")]
const CLUSTER_LEASE_MIN_RENEWAL_LEAD_MS: u64 = 250;
#[cfg(feature = "cluster")]
const CLUSTER_LEASE_MAX_RENEWAL_LEAD_MS: u64 = 10_000;
// The selected local mount owns its bounded scrub work-per-tick policy.
// Optional observations report this behavior but do not configure it.
const MOUNT_SCRUB_MAX_RECORDS_PER_TICK: u64 = 1;
const MOUNT_SCRUB_MAX_BYTES_PER_TICK: u64 = 1024 * 1024;

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

fn required_root_authentication_key(
    operation: &str,
) -> Result<tidefs_local_filesystem::RootAuthenticationKey, String> {
    tidefs_local_filesystem::RootAuthenticationKey::from_environment().map_err(|err| {
        format!(
            "{operation}: root authentication key is required: {err}; set {} to a 64-hex-character key",
            tidefs_local_filesystem::ROOT_AUTHENTICATION_ENV_VAR
        )
    })
}

#[cfg(test)]
mod root_authentication_tests {
    use std::sync::{Mutex, OnceLock};

    use super::*;

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn with_root_auth_env<T>(value: Option<&str>, run: impl FnOnce() -> T) -> T {
        let _guard = env_lock().lock().unwrap();
        let env_var = tidefs_local_filesystem::ROOT_AUTHENTICATION_ENV_VAR;
        let previous = std::env::var_os(env_var);
        match value {
            Some(value) => std::env::set_var(env_var, value),
            None => std::env::remove_var(env_var),
        }

        let result = run();

        match previous {
            Some(previous) => std::env::set_var(env_var, previous),
            None => std::env::remove_var(env_var),
        }

        result
    }

    #[test]
    fn required_root_authentication_key_rejects_missing_env() {
        with_root_auth_env(None, || {
            let err = required_root_authentication_key("tidefs adapter mount setup").unwrap_err();
            assert!(err.contains(tidefs_local_filesystem::ROOT_AUTHENTICATION_ENV_VAR));
            assert!(err.contains("missing"));
        });
    }

    #[test]
    fn required_root_authentication_key_rejects_malformed_env() {
        with_root_auth_env(Some("not-hex"), || {
            let err = required_root_authentication_key("tidefs adapter mount setup").unwrap_err();
            assert!(err.contains(tidefs_local_filesystem::ROOT_AUTHENTICATION_ENV_VAR));
            assert!(err.contains("invalid"));
        });
    }
}

/// Configuration for `run_mount`: boots a LocalFileSystem and mounts it via FUSE.
#[derive(Debug)]
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
    /// Pool-wide allocation policy reconstructed from the imported labels.
    pub pool_redundancy_policy: tidefs_local_object_store::PoolRedundancyPolicy,
    /// Pool UUID for a pool-aware mounted owner.
    pub pool_uuid: Option<[u8; 16]>,
    /// Run in foreground (default true for CLI workflows).
    pub foreground: bool,
    /// Enable debug logging to stderr.
    pub debug: bool,
    /// Mount the live filesystem through read-only storage, recovery, VFS,
    /// adapter, and kernel FUSE authorities.
    pub read_only: bool,
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

    /// Unique owner of an explicit pool import performed for this mount.
    ///
    /// When present, `run_mount` consumes the owner and performs the matching
    /// export on startup failure or after the FUSE session has joined.
    pub import_owner: Option<tidefs_pool_import::PoolImportOwner>,

    /// Dataset path to resolve through the catalog (default "root").
    /// When None, the root dataset is mounted.
    pub dataset_path: Option<String>,

    /// Optional snapshot name for read-only snapshot-backed mounts.
    /// When set, the mount opens the named snapshot's committed root
    /// instead of the live committed root. The mount is forced read-only,
    /// does not create a live-owner endpoint, and skips writeback, scrub,
    /// reclaim, and intent-log configuration. Mutually exclusive with
    /// cluster mount authority.
    pub snapshot_name: Option<String>,
    /// Authority used to admit the mount as standalone/local or
    /// cluster-lease-authorized.
    pub mount_authority: MountAuthority,

    /// Runtime semantics selected by the canonical `tidefsctl pool mount`
    /// carrier. Focused library validation may additionally set fault and
    /// observation inputs that are deliberately absent from the operator CLI.
    pub runtime: MountRuntimeOptions,
}

/// Focused configuration for the one mounted runtime implementation.
///
/// `tidefsctl pool mount` translates operator options into this single
/// configuration and delegates to [`run_mount`].
#[derive(Debug)]
pub struct MountRuntimeOptions {
    /// Source name reported by the FUSE mount in mount tables.
    pub fs_name: String,
    /// Explicit root-authentication material for validation callers. When
    /// absent, the canonical runtime reads the documented environment variable.
    pub root_authentication_key: Option<tidefs_local_filesystem::RootAuthenticationKey>,
    /// Parsed kernel and adapter mount semantics.
    pub mount_options: mount_options::MountOptions,
    /// Per-dataset write-acknowledgment durability guarantee.
    pub sync_guarantee: SyncGuarantee,
    /// Content capacity admitted by the local storage allocator.
    pub content_capacity_bytes: u64,
    /// Maximum dirty-page age for the FUSE writeback cache.
    pub writeback_cache_timeout_secs: u64,
    /// Grace period for in-flight requests after shutdown admission.
    pub drain_timeout_secs: u64,
    /// Bounded mounted scrub interval; zero disables the service.
    pub background_scrub_interval_secs: u64,
    /// Optional per-object compression configuration.
    pub compression: Option<tidefs_local_object_store::CompressionConfig>,
    /// Enable the mounted dataset's dedup feature.
    pub enable_dedup: bool,
    /// Enable object-store reclaim for the mounted runtime.
    pub enable_reclaim: bool,
    /// Admit repair writeback during recovery.
    pub enable_repair_writeback: bool,
    /// Validation-only byte-corruption injection probability.
    pub fault_inject_corruption: Option<f64>,
    /// Optional validation-only queue-depth artifact path.
    pub queue_depth_artifact: Option<PathBuf>,
}

impl Default for MountRuntimeOptions {
    fn default() -> Self {
        let mut mount_options = mount_options::MountOptions::default();
        // Preserve the selected tidefsctl carrier's existing production
        // default. The transitional daemon wrapper supplies its parsed
        // relatime/atime choice explicitly instead.
        mount_options.timestamp_policy = mount_options::TimestampPolicy::NoAtime;
        Self {
            fs_name: "tidefs".to_string(),
            root_authentication_key: None,
            mount_options,
            sync_guarantee: SyncGuarantee::Local,
            content_capacity_bytes: tidefs_local_filesystem::LocalStorageAllocatorPolicy::default()
                .content_capacity_bytes,
            writeback_cache_timeout_secs: 60,
            drain_timeout_secs: 0,
            background_scrub_interval_secs: 0,
            compression: None,
            enable_dedup: false,
            enable_reclaim: false,
            enable_repair_writeback: false,
            fault_inject_corruption: None,
            queue_depth_artifact: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EffectiveMountMode {
    read_only: bool,
    writeback_cache: bool,
    background_scrub_interval_secs: u64,
}

fn effective_mount_mode(config: &MountConfig) -> EffectiveMountMode {
    let read_only = config.read_only || config.snapshot_name.is_some();
    EffectiveMountMode {
        read_only,
        writeback_cache: config.writeback_cache && !read_only,
        background_scrub_interval_secs: if read_only {
            0
        } else {
            config.runtime.background_scrub_interval_secs
        },
    }
}

#[cfg(test)]
mod effective_mount_mode_tests {
    use super::*;

    fn config(read_only: bool, snapshot_name: Option<&str>, writeback_cache: bool) -> MountConfig {
        MountConfig {
            encryption: None,
            backing_dir: PathBuf::from("/existing/store"),
            mountpoint: PathBuf::from("/mountpoint"),
            pool_name: Some("named-pool".into()),
            pool_redundancy_policy: tidefs_local_object_store::PoolRedundancyPolicy::default(),
            pool_uuid: Some([0x42; 16]),
            foreground: true,
            debug: false,
            read_only,
            writeback_cache,
            coherency_profile: crate::coherency_profile::CoherencyProfile::Writeback,
            block_devices: None,
            import_owner: None,
            dataset_path: Some("root".into()),
            snapshot_name: snapshot_name.map(str::to_string),
            mount_authority: MountAuthority::standalone(),
            runtime: MountRuntimeOptions::default(),
        }
    }

    #[test]
    fn ordinary_read_only_mount_suppresses_writeback() {
        assert_eq!(
            effective_mount_mode(&config(true, None, true)),
            EffectiveMountMode {
                read_only: true,
                writeback_cache: false,
                background_scrub_interval_secs: 0,
            }
        );
    }

    #[test]
    fn snapshot_export_forces_read_only_mode() {
        let mut config = config(false, Some("snap0"), true);
        config.runtime.background_scrub_interval_secs = 60;
        assert_eq!(
            effective_mount_mode(&config),
            EffectiveMountMode {
                read_only: true,
                writeback_cache: false,
                background_scrub_interval_secs: 0,
            }
        );
    }

    #[test]
    fn read_write_mount_preserves_explicit_writeback() {
        assert_eq!(
            effective_mount_mode(&config(false, None, true)),
            EffectiveMountMode {
                read_only: false,
                writeback_cache: true,
                background_scrub_interval_secs: 0,
            }
        );
    }

    #[test]
    fn read_only_kernel_options_force_noatime_without_dropping_other_flags() {
        let options = mount_options::MountOptions {
            timestamp_policy: mount_options::TimestampPolicy::StrictAtime,
            suppress_dir_atime: false,
            sync: true,
            sync_guarantee: SyncGuarantee::Local,
            allow_other: true,
            dev: true,
        };

        let kernel_options = fuse_mount_options_for_mode(&options, true);

        assert!(kernel_options.contains(&fuser::MountOption::NoAtime));
        assert!(!kernel_options.contains(&fuser::MountOption::StrictAtime));
        assert!(kernel_options.contains(&fuser::MountOption::Sync));
        assert!(kernel_options.contains(&fuser::MountOption::AllowOther));
        assert!(kernel_options.contains(&fuser::MountOption::Dev));
    }
}

/// Mount authority material accepted by the daemon admission boundary.
#[derive(Debug)]
pub enum MountAuthority {
    /// Standalone/local mount with no cluster lease material.
    Standalone,
    /// Cluster mount authorized by a validated pool lease token.
    #[cfg(feature = "cluster")]
    ClusterLease(ClusterMountAuthority),
}

/// Raw mount authority material decoded at the daemon boundary.
#[cfg(feature = "cluster")]
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
#[cfg(feature = "cluster")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClusterLeaseGrant {
    /// Opaque authority token carrying owner, epoch, lease, and write fence.
    pub token: tidefs_cluster::PoolLeaseToken,
    /// Conservative process-local deadline measured after transport receipt.
    pub valid_until: Instant,
}

#[cfg(feature = "cluster")]
impl ClusterLeaseGrant {
    fn remaining(&self) -> Duration {
        self.valid_until.saturating_duration_since(Instant::now())
    }
}

/// Live transport session for renewing and releasing one Pool lease.
#[cfg(feature = "cluster")]
pub trait ClusterLeaseSession: std::fmt::Debug + Send {
    fn renew(
        &mut self,
        token: &tidefs_cluster::PoolLeaseToken,
    ) -> Result<ClusterLeaseGrant, String>;

    fn release(&mut self, token: &tidefs_cluster::PoolLeaseToken) -> Result<(), String>;
}

/// Validated authority plus the live session that keeps it renewable.
#[cfg(feature = "cluster")]
pub struct ClusterMountAuthority {
    token: tidefs_cluster::PoolLeaseToken,
    session: Option<Box<dyn ClusterLeaseSession>>,
    mutation_deadline: tidefs_local_filesystem::ExternalMutationDeadline,
    next_renewal: Instant,
    released: bool,
}

#[cfg(feature = "cluster")]
impl std::fmt::Debug for ClusterMountAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClusterMountAuthority")
            .field("token", &self.token)
            .field("has_live_session", &self.session.is_some())
            .field(
                "next_renewal_in",
                &self.next_renewal.saturating_duration_since(Instant::now()),
            )
            .field("released", &self.released)
            .finish()
    }
}

impl MountAuthority {
    pub fn standalone() -> Self {
        Self::Standalone
    }

    #[cfg(feature = "cluster")]
    pub fn cluster_lease(
        expected_pool_guid: [u8; 16],
        token: tidefs_cluster::PoolLeaseToken,
    ) -> Result<Self, String> {
        validate_cluster_lease_token(&token, &expected_pool_guid)?;
        Ok(Self::ClusterLease(ClusterMountAuthority::new(
            ClusterLeaseGrant {
                token,
                valid_until: Instant::now(),
            },
            None,
        )))
    }

    #[cfg(feature = "cluster")]
    pub fn renewable_cluster_lease(
        expected_pool_guid: [u8; 16],
        grant: ClusterLeaseGrant,
        mut session: Box<dyn ClusterLeaseSession>,
    ) -> Result<Self, String> {
        let validation =
            validate_cluster_lease_token(&grant.token, &expected_pool_guid).and_then(|()| {
                if grant.remaining().is_zero() {
                    Err("cluster mount: Pool lease has no remaining local validity".to_string())
                } else {
                    Ok(())
                }
            });
        if let Err(validation_error) = validation {
            return Err(match session.release(&grant.token) {
                Ok(()) => validation_error,
                Err(release_error) => format!(
                    "{validation_error}; additionally failed to release rejected Pool lease: {release_error}"
                ),
            });
        }
        Ok(Self::ClusterLease(ClusterMountAuthority::new(
            grant,
            Some(session),
        )))
    }

    #[cfg(feature = "cluster")]
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
        #[cfg(feature = "cluster")]
        {
            matches!(self, Self::ClusterLease(_))
        }
        #[cfg(not(feature = "cluster"))]
        {
            false
        }
    }

    /// Return the conservative process-local validity of a clustered grant.
    #[cfg(feature = "cluster")]
    pub fn cluster_lease_remaining(&self) -> Option<Duration> {
        match self {
            Self::Standalone => None,
            Self::ClusterLease(authority) => Some(authority.mutation_deadline.remaining()),
        }
    }

    /// Return the exact process-local deadline of a clustered grant.
    #[cfg(feature = "cluster")]
    pub fn cluster_lease_valid_until(&self) -> Option<Instant> {
        match self {
            Self::Standalone => None,
            Self::ClusterLease(authority) => authority.mutation_deadline.valid_until(),
        }
    }

    #[cfg(feature = "cluster")]
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
                if authority.session.is_some() && !authority.mutation_deadline.is_live() {
                    return Err(
                        "cluster mount: Pool lease local validity expired before admission"
                            .to_string(),
                    );
                }
                Ok(Some(&authority.token))
            }
        }
    }

    #[cfg(feature = "cluster")]
    fn external_mutation_deadline(
        &self,
    ) -> Option<tidefs_local_filesystem::ExternalMutationDeadline> {
        match self {
            Self::Standalone => None,
            Self::ClusterLease(authority) => Some(authority.mutation_deadline.clone()),
        }
    }

    #[cfg(feature = "cluster")]
    fn require_renewable_cluster_authority(&self) -> Result<(), String> {
        match self {
            Self::Standalone => Ok(()),
            Self::ClusterLease(authority) if authority.session.is_some() => Ok(()),
            Self::ClusterLease(_) => Err(
                "cluster mount: lease admission has no live renewal session; refusing a one-shot mount authority"
                    .to_string(),
            ),
        }
    }

    #[cfg(feature = "cluster")]
    fn renew_if_due(&mut self) -> Result<(), String> {
        match self {
            Self::Standalone => Ok(()),
            Self::ClusterLease(authority) => authority.renew_if_due(),
        }
    }

    #[cfg(feature = "cluster")]
    fn fence(&self) {
        if let Self::ClusterLease(authority) = self {
            authority.mutation_deadline.fence();
        }
    }

    #[cfg(feature = "cluster")]
    /// Release a retained cluster lease when no mounted carrier can still
    /// mutate the Pool, including admission unwind before FUSE starts.
    pub fn release_unmounted(&mut self) -> Result<(), String> {
        match self {
            Self::Standalone => Ok(()),
            Self::ClusterLease(authority) => authority.release(),
        }
    }
}

#[cfg(feature = "cluster")]
impl ClusterMountAuthority {
    fn new(grant: ClusterLeaseGrant, session: Option<Box<dyn ClusterLeaseSession>>) -> Self {
        let valid_until = grant.valid_until;
        Self {
            mutation_deadline: tidefs_local_filesystem::ExternalMutationDeadline::new_until(
                valid_until,
            ),
            next_renewal: cluster_lease_renewal_at(valid_until),
            token: grant.token,
            session,
            released: false,
        }
    }

    pub fn token(&self) -> &tidefs_cluster::PoolLeaseToken {
        &self.token
    }

    fn renew_if_due(&mut self) -> Result<(), String> {
        if self.released {
            return Err("cluster mount: Pool lease has already been released".to_string());
        }
        if Instant::now() < self.next_renewal {
            return Ok(());
        }
        let session = self.session.as_mut().ok_or_else(|| {
            "cluster mount: Pool lease cannot renew without its live transport session".to_string()
        })?;
        let renewed = session.renew(&self.token)?;
        validate_cluster_lease_token(&renewed.token, &self.token.pool_guid)?;
        if renewed.remaining().is_zero() {
            return Err("cluster mount: renewal has no remaining local validity".to_string());
        }
        if renewed.token.node_id != self.token.node_id
            || renewed.token.epoch != self.token.epoch
            || renewed.token.lease_id != self.token.lease_id
            || renewed.token.slot != self.token.slot
            || renewed.token.write_fence != self.token.write_fence
        {
            return Err(
                "cluster mount: renewal changed Pool owner, lease identity, or write fence"
                    .to_string(),
            );
        }
        if renewed.token.expiration_deadline_ms <= self.token.expiration_deadline_ms {
            return Err(
                "cluster mount: renewal did not advance the Pool lease deadline".to_string(),
            );
        }
        self.mutation_deadline.renew_until(renewed.valid_until);
        if !self.mutation_deadline.is_live() {
            return Err(
                "cluster mount: renewal local validity expired before installation".to_string(),
            );
        }
        self.next_renewal = cluster_lease_renewal_at(renewed.valid_until);
        self.token = renewed.token;
        Ok(())
    }

    fn release(&mut self) -> Result<(), String> {
        if self.released {
            return Ok(());
        }
        let session = self.session.as_mut().ok_or_else(|| {
            "cluster mount: Pool lease cannot release without its live transport session"
                .to_string()
        })?;
        session.release(&self.token)?;
        self.released = true;
        self.mutation_deadline.fence();
        Ok(())
    }
}

#[cfg(feature = "cluster")]
fn cluster_lease_renewal_at(valid_until: Instant) -> Instant {
    let now = Instant::now();
    let valid_for = valid_until.saturating_duration_since(now);
    let remaining_ms = u64::try_from(valid_for.as_millis()).unwrap_or(u64::MAX);
    let lead_ms = (remaining_ms / 3)
        .clamp(
            CLUSTER_LEASE_MIN_RENEWAL_LEAD_MS,
            CLUSTER_LEASE_MAX_RENEWAL_LEAD_MS,
        )
        .min((remaining_ms / 2).max(1));
    now.checked_add(Duration::from_millis(remaining_ms.saturating_sub(lead_ms)))
        .unwrap_or(now)
}

#[cfg(feature = "cluster")]
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
    if token.expiration_deadline_ms == 0 {
        return Err("cluster mount: lease token has zero authority deadline".to_string());
    }
    if !token.authorizes_pool(expected_pool_guid) {
        return Err("cluster mount: lease token pool GUID mismatch".to_string());
    }
    Ok(())
}

#[cfg(feature = "cluster")]
struct ClusterLeaseRenewalWorker {
    authority: Arc<Mutex<MountAuthority>>,
    stop: Arc<AtomicBool>,
    authority_lost: Arc<AtomicBool>,
    authority_loss: Arc<Mutex<Option<String>>>,
    shared_filesystem: tidefs_local_filesystem::vfs_engine_impl::SharedLocalFileSystem,
    shutdown: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

#[cfg(feature = "cluster")]
impl ClusterLeaseRenewalWorker {
    fn start(
        authority: MountAuthority,
        shared_filesystem: tidefs_local_filesystem::vfs_engine_impl::SharedLocalFileSystem,
        shutdown: Arc<AtomicBool>,
    ) -> Self {
        let authority = Arc::new(Mutex::new(authority));
        let stop = Arc::new(AtomicBool::new(false));
        let authority_lost = Arc::new(AtomicBool::new(false));
        let authority_loss = Arc::new(Mutex::new(None));

        let thread_authority = Arc::clone(&authority);
        let thread_stop = Arc::clone(&stop);
        let thread_authority_lost = Arc::clone(&authority_lost);
        let thread_authority_loss = Arc::clone(&authority_loss);
        let thread_filesystem = shared_filesystem.clone();
        let thread_shutdown = Arc::clone(&shutdown);
        let handle = std::thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                let renewal = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    thread_authority
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .renew_if_due()
                }));
                match renewal {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        Self::record_authority_loss(
                            &thread_authority,
                            &thread_filesystem,
                            &thread_shutdown,
                            &thread_authority_lost,
                            &thread_authority_loss,
                            format!(
                                "cluster Pool lease renewal lost; mutations fenced before unmount: {error}"
                            ),
                        );
                        break;
                    }
                    Err(_) => {
                        Self::record_authority_loss(
                            &thread_authority,
                            &thread_filesystem,
                            &thread_shutdown,
                            &thread_authority_lost,
                            &thread_authority_loss,
                            "cluster Pool lease renewal worker panicked; mutations fenced before unmount"
                                .to_string(),
                        );
                        break;
                    }
                }
                std::thread::park_timeout(std::time::Duration::from_millis(100));
            }
        });

        Self {
            authority,
            stop,
            authority_lost,
            authority_loss,
            shared_filesystem,
            shutdown,
            handle: Some(handle),
        }
    }

    fn record_authority_loss(
        authority: &Arc<Mutex<MountAuthority>>,
        shared_filesystem: &tidefs_local_filesystem::vfs_engine_impl::SharedLocalFileSystem,
        shutdown: &Arc<AtomicBool>,
        authority_lost: &Arc<AtomicBool>,
        authority_loss: &Arc<Mutex<Option<String>>>,
        error: String,
    ) {
        authority
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .fence();
        shared_filesystem
            .borrow_mut()
            .fence_external_mutation_authority();
        *authority_loss
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(error);
        authority_lost.store(true, Ordering::Release);
        shutdown.store(true, Ordering::Release);
    }

    fn check_health(&self) {
        if !self.stop.load(Ordering::Acquire)
            && !self.authority_lost.load(Ordering::Acquire)
            && self
                .handle
                .as_ref()
                .is_some_and(std::thread::JoinHandle::is_finished)
        {
            Self::record_authority_loss(
                &self.authority,
                &self.shared_filesystem,
                &self.shutdown,
                &self.authority_lost,
                &self.authority_loss,
                "cluster Pool lease renewal worker stopped unexpectedly; mutations fenced before unmount"
                    .to_string(),
            );
        }
    }

    fn authority_lost(&self) -> bool {
        self.authority_lost.load(Ordering::Acquire)
    }

    fn authority_loss(&self) -> Option<String> {
        self.authority_loss
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn stop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            handle.thread().unpark();
            if handle.join().is_err() {
                Self::record_authority_loss(
                    &self.authority,
                    &self.shared_filesystem,
                    &self.shutdown,
                    &self.authority_lost,
                    &self.authority_loss,
                    "cluster Pool lease renewal worker terminated unexpectedly; mutations fenced before release"
                        .to_string(),
                );
            }
        }
    }

    fn release(&self) -> Result<(), String> {
        self.authority
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .release_unmounted()
    }
}

// A lazily detached FUSE mount can leave a directory entry that races
// `create_dir_all` into `EEXIST`. Admit only the exact, non-symlink directory.
fn prepare_mountpoint_directory(mountpoint: &std::path::Path) -> std::io::Result<()> {
    match std::fs::create_dir_all(mountpoint) {
        Ok(()) => Ok(()),
        Err(create_error) if create_error.kind() == std::io::ErrorKind::AlreadyExists => {
            let Some(entry_name) = mountpoint.file_name() else {
                return Err(create_error);
            };
            let parent = mountpoint
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| std::path::Path::new("."));

            for entry in std::fs::read_dir(parent)? {
                let entry = entry?;
                if entry.file_name().as_os_str() == entry_name {
                    return if entry.file_type()?.is_dir() {
                        Ok(())
                    } else {
                        Err(create_error)
                    };
                }
            }

            Err(create_error)
        }
        Err(error) => Err(error),
    }
}

fn fuse_mount_options_for_mode(
    mount_options: &mount_options::MountOptions,
    read_only: bool,
) -> Vec<fuser::MountOption> {
    let mut effective = mount_options.clone();
    if read_only {
        effective.timestamp_policy = mount_options::TimestampPolicy::NoAtime;
    }
    effective.to_fuse_mount_options()
}

struct MountedBackgroundScrubService {
    store: tidefs_local_object_store::LocalObjectStore,
    next_tick_not_before: std::time::Instant,
}

impl MountedBackgroundScrubService {
    const NAME: &'static str = "mounted-segment-scrub";

    fn open(root: &Path, options: tidefs_local_object_store::StoreOptions) -> Result<Self, String> {
        let store = tidefs_local_object_store::LocalObjectStore::open_with_options(root, options)
            .map_err(|error| format!("open scheduled scrub store: {error}"))?;
        Ok(Self {
            store,
            next_tick_not_before: std::time::Instant::now(),
        })
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
        let max_records = Self::bounded_limit(budget.max_items, MOUNT_SCRUB_MAX_RECORDS_PER_TICK);
        let max_bytes = Self::bounded_limit(budget.max_bytes, MOUNT_SCRUB_MAX_BYTES_PER_TICK);
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

        let work_pending = self.store.background_scrub_pending();

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

fn write_queue_depth_runtime_artifact(
    engine: &live_owner::LiveOwnerEngine,
    path: &Path,
) -> Result<(), String> {
    let mut args = BTreeMap::new();
    args.insert(
        "workload".to_string(),
        LivePoolAdminArg::String("local-mounted-filesystem".to_string()),
    );
    args.insert(
        "mount_adapter".to_string(),
        LivePoolAdminArg::String("fuse".to_string()),
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

/// Removes the validation PID file after a clean shutdown. A SIGKILL leaves
/// it behind so the existing crash harness can identify the interrupted run.
struct PidFileGuard(Option<PathBuf>);

impl PidFileGuard {
    fn from_environment() -> Result<Self, String> {
        let path = std::env::var("TIDEFS_PID_FILE").ok().map(PathBuf::from);
        if let Some(ref path) = path {
            std::fs::write(path, std::process::id().to_string())
                .map_err(|error| format!("write PID file {}: {error}", path.display()))?;
        }
        Ok(Self(path))
    }
}

impl Drop for PidFileGuard {
    fn drop(&mut self) {
        if let Some(ref path) = self.0 {
            let _ = std::fs::remove_file(path);
        }
    }
}

// Resources established before the mount becomes a reachable live owner.
struct StartedMount {
    snapshot_export: bool,
    shutdown: Arc<AtomicBool>,
    session: fuser::BackgroundSession,
    live_owner: Option<live_owner::LiveOwnerHandle>,
    queue_depth_engine: live_owner::LiveOwnerEngine,
    background_scheduler: Option<Arc<Mutex<Option<BackgroundScheduler>>>>,
    mmap_coherency: Arc<mmap_coherency::MmapCoherency>,
    #[cfg(feature = "cluster")]
    shared_filesystem: tidefs_local_filesystem::vfs_engine_impl::SharedLocalFileSystem,
}

fn start_mount(config: &MountConfig) -> Result<StartedMount, String> {
    use std::fs;

    use tidefs_dataset_lifecycle::DatasetId;
    use tidefs_local_filesystem::human::local_filesystem::StoreOptions;
    use tidefs_local_filesystem::vfs_engine_impl::VfsLocalFileSystem;
    use tidefs_local_filesystem::LocalFileSystem;

    let snapshot_export = config.snapshot_name.is_some();
    let effective_mode = effective_mount_mode(config);
    if snapshot_export && config.mount_authority.is_cluster_authorized() {
        return Err(
            "snapshot export mount is not supported with cluster mount authority".to_string(),
        );
    }
    if snapshot_export && config.runtime.queue_depth_artifact.is_some() {
        return Err("queue-depth artifacts are not supported for snapshot export mounts".into());
    }
    #[cfg(feature = "cluster")]
    let cluster_lease_token = config
        .mount_authority
        .validate_for_pool(config.pool_uuid.as_ref())?;
    #[cfg(feature = "cluster")]
    config
        .mount_authority
        .require_renewable_cluster_authority()?;
    if !snapshot_export {
        fs::create_dir_all(&config.backing_dir)
            .map_err(|e| format!("create backing dir {}: {e}", config.backing_dir.display()))?;
    }
    prepare_mountpoint_directory(&config.mountpoint)
        .map_err(|e| format!("create mountpoint {}: {e}", config.mountpoint.display()))?;

    let root_auth_key = match config.runtime.root_authentication_key {
        Some(key) => key,
        None => required_root_authentication_key("tidefs adapter mount setup")?,
    };

    if config.debug {
        if snapshot_export {
            eprintln!(
                "tidefsctl: opening snapshot export `{}` at {}",
                config.snapshot_name.as_deref().unwrap_or("?"),
                config.backing_dir.display()
            );
        } else {
            eprintln!(
                "tidefsctl: opening store at {}",
                config.backing_dir.display()
            );
        }
    }

    let (base_engine, writeback_tracker, dataset_id) = if let Some(ref snapshot_name) =
        config.snapshot_name
    {
        // Snapshot export: open the snapshot's committed root as a
        // read-only namespace with no writeback, scrub, or reclaim.
        use tidefs_local_filesystem::LocalFileSystemOpenConfig;
        use tidefs_local_filesystem::LocalStorageAllocatorPolicy;
        use tidefs_recovery_loop::RecoveryPolicy;

        let open_config = LocalFileSystemOpenConfig {
            options: StoreOptions::default(),
            allocator_policy: LocalStorageAllocatorPolicy {
                content_capacity_bytes: config.runtime.content_capacity_bytes,
                ..LocalStorageAllocatorPolicy::default()
            },
            root_authentication_key: root_auth_key,
            encryption: None,
            compression: config.runtime.compression.clone(),
            log_device_device_path: None,
            recovery_policy: RecoveryPolicy::ReadOnly,
            block_devices: config.block_devices.as_deref(),
        };
        let session =
            LocalFileSystem::open_snapshot_export(&config.backing_dir, snapshot_name, open_config)
                .map_err(|e| format!("open snapshot export `{snapshot_name}`: {e}"))?;
        let summary = session.summary().clone();
        eprintln!(
            "tidefsctl: opened snapshot export `{}` at generation {} root inode {}",
            summary.snapshot.name,
            summary.generation,
            summary.root_inode_id.get()
        );
        let mut engine = session.into_engine();
        engine
            .set_timestamp_policy(tidefs_inode_attributes::timestamp::TimestampPolicy::Noatime)
            .map_err(|e| format!("set snapshot export timestamp policy: {e}"))?;
        engine = engine.with_read_only();
        let dataset_id: Option<DatasetId> = None;
        (engine, None, dataset_id)
    } else {
        use tidefs_local_filesystem::{LocalFileSystemOpenConfig, LocalStorageAllocatorPolicy};
        use tidefs_recovery_loop::RecoveryPolicy;

        if let Some(ref devices) = config.block_devices {
            eprintln!(
                "tidefsctl: opening block-device-backed pool with {} device(s)",
                devices.len()
            );
        }
        if config.encryption.is_some() {
            eprintln!("tidefsctl: encryption enabled (key fingerprint not logged)");
        }
        let recovery_policy = if effective_mode.read_only {
            RecoveryPolicy::ReadOnly
        } else if config.runtime.enable_repair_writeback {
            RecoveryPolicy::RepairWriteback
        } else {
            RecoveryPolicy::default()
        };
        let store_options = StoreOptions {
            background_scrub_interval_secs: effective_mode.background_scrub_interval_secs,
            reclaim_enabled: !effective_mode.read_only && config.runtime.enable_reclaim,
            fault_injection_config: if effective_mode.read_only {
                None
            } else {
                config.runtime.fault_inject_corruption.map(|probability| {
                    tidefs_local_object_store::FaultInjectionConfig {
                        byte_corruption_probability: probability,
                        ..tidefs_local_object_store::FaultInjectionConfig::off()
                    }
                })
            },
            ..StoreOptions::default()
        };
        let selected_dataset_path = config.dataset_path.as_deref().unwrap_or("root");
        let mut lfs = LocalFileSystem::open_named_pool_filesystem_dataset_with_allocator_policy_and_root_authentication_key(
                &config.backing_dir,
                config.pool_name.as_deref().unwrap_or("tidefs"),
                config.pool_redundancy_policy,
                selected_dataset_path,
                LocalFileSystemOpenConfig {
                    options: store_options,
                    allocator_policy: LocalStorageAllocatorPolicy {
                        content_capacity_bytes: config.runtime.content_capacity_bytes,
                        ..LocalStorageAllocatorPolicy::default()
                    },
                    root_authentication_key: root_auth_key,
                    encryption: config.encryption.clone(),
                    compression: config.runtime.compression.clone(),
                    log_device_device_path: None,
                    recovery_policy,
                    block_devices: config.block_devices.as_deref(),
                },
            )
        .map_err(|e| format!("open store: {e}"))?;

        if !effective_mode.read_only && config.runtime.enable_dedup {
            #[cfg(not(feature = "data-policy"))]
            return Err("dedup mount activation requires the data-policy feature".into());

            #[cfg(feature = "data-policy")]
            {
                use tidefs_types_dataset_feature_flags_core::{FeatureClass, FeatureName};

                let dedup_name = "org.tidefs:dedup"
                    .parse::<FeatureName>()
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
        }

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
            if lfs.mounted_dataset_id() != *ds_id.as_bytes() {
                return Err(format!(
                    "mounted dataset identity differs from canonical root for {selected_dataset_path}"
                ));
            }
        }

        let tracker = if effective_mode.read_only {
            None
        } else {
            lfs.set_write_buffer_flush_threshold_bytes(MOUNT_WRITE_BUFFER_FLUSH_THRESHOLD_BYTES)
                .map_err(|e| format!("set mounted write-buffer threshold: {e}"))?;
            lfs.set_auto_commit(false)
                .map_err(|e| format!("set mounted auto-commit policy: {e}"))?;
            lfs.set_commit_group_throughput_profile()
                .map_err(|e| format!("set mounted commit-group profile: {e}"))?;
            lfs.set_max_uncommitted_mutations(MOUNT_MAX_UNCOMMITTED_MUTATIONS)
                .map_err(|e| format!("set mounted mutation threshold: {e}"))?;

            Some(
                lfs.clone_writeback_range_tracker()
                    .map_err(|e| format!("attach mounted writeback tracker: {e}"))?,
            )
        };

        let dataset_sync_guarantee = config.dataset_path.as_deref().unwrap_or("root");
        let sync_guarantee = if config.runtime.sync_guarantee == SyncGuarantee::Local {
            lfs.dataset_catalog()
                .sync_guarantee(dataset_sync_guarantee)
                .unwrap_or(SyncGuarantee::Local)
        } else {
            config.runtime.sync_guarantee
        };

        // The LocalFileSystem already owns the exact typed dataset root.
        let mut engine = VfsLocalFileSystem::new(lfs).with_sync_guarantee(sync_guarantee);
        if effective_mode.read_only {
            engine
                .set_timestamp_policy(tidefs_inode_attributes::timestamp::TimestampPolicy::Noatime)
                .map_err(|e| format!("set read-only timestamp policy: {e}"))?;
            engine = engine.with_read_only();
        } else {
            let timestamp_policy = match config.runtime.mount_options.timestamp_policy {
                mount_options::TimestampPolicy::StrictAtime => {
                    tidefs_inode_attributes::timestamp::TimestampPolicy::Strictatime
                }
                mount_options::TimestampPolicy::RelativeAtime => {
                    tidefs_inode_attributes::timestamp::TimestampPolicy::Relatime
                }
                mount_options::TimestampPolicy::NoAtime => {
                    tidefs_inode_attributes::timestamp::TimestampPolicy::Noatime
                }
            };
            engine
                .set_timestamp_policy(timestamp_policy)
                .map_err(|e| format!("set mounted timestamp policy: {e}"))?;
        }
        (engine, tracker, dataset_id)
    };
    let shared_filesystem = base_engine.shared_filesystem();
    #[cfg(feature = "cluster")]
    if let Some(deadline_ms) = config.mount_authority.external_mutation_deadline() {
        shared_filesystem
            .borrow_mut()
            .install_external_mutation_deadline(deadline_ms)
            .map_err(|error| format!("install clustered mutation deadline: {error}"))?;
    }

    // When cluster-authorized, wrap the engine in a placement-recording layer.
    #[cfg(feature = "cluster")]
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
    #[cfg(not(feature = "cluster"))]
    let vfs_engine: Box<dyn tidefs_vfs_engine::VfsEngineStatFs + Send> = Box::new(base_engine);
    let mut adapter = fuse_vfs_adapter::FuseVfsAdapter::new(vfs_engine)
        .map_err(|e| format!("adapter init: {e:?}"))?
        .with_coherency_profile(config.coherency_profile);

    if !effective_mode.read_only {
        adapter = adapter
            .with_background_scheduler(BackgroundScheduler::new(ServiceBudget::MAINTENANCE_TICK));
    }

    // Attach the resolved stable DatasetId for lifecycle gating and metrics.
    if let Some(ds_id) = dataset_id {
        adapter = adapter.with_dataset_id(ds_id);
    }

    if effective_mode.read_only {
        adapter = adapter.with_writeback_cache_disabled();
    } else if effective_mode.writeback_cache {
        adapter = adapter
            .with_writeback_cache_enabled()
            .with_writeback_cache_timeout(config.runtime.writeback_cache_timeout_secs)
            .with_writeback_range_tracker(
                writeback_tracker.expect("writeback tracker must be present for live mount"),
            );
    } else {
        adapter = adapter.with_writeback_cache_disabled();
    }
    if effective_mode.read_only {
        adapter = adapter.with_read_only();
    }
    if config.runtime.mount_options.sync {
        adapter = adapter.with_force_sync_writes();
    }
    let adapter_timestamp_policy = if effective_mode.read_only {
        mount_options::TimestampPolicy::NoAtime
    } else {
        config.runtime.mount_options.timestamp_policy
    };
    adapter = adapter
        .with_timestamp_policy(adapter_timestamp_policy)
        .with_suppress_dir_atime(config.runtime.mount_options.suppress_dir_atime);
    let shutdown = Arc::new(AtomicBool::new(false));
    install_signal_handlers(Arc::clone(&shutdown)).map_err(|e| format!("signal handler: {e}"))?;
    let live_owner_engine = adapter.engine_handle();
    let dataset_replacement = adapter.dataset_replacement_handle();
    let queue_depth_engine = Arc::clone(&live_owner_engine);
    let notifier_cell = adapter.notifier_cell();
    let mmap_coherency = adapter.mmap_coherency_cell();
    let background_scheduler = if effective_mode.read_only {
        None
    } else {
        let scheduler = adapter.background_scheduler_handle();
        let fuse_demand = Arc::new(AtomicBool::new(false));
        adapter.set_scheduler_preempt_signal(fuse_demand);
        Some(scheduler)
    };
    if effective_mode.background_scrub_interval_secs > 0 {
        let scrub_options = tidefs_local_object_store::StoreOptions {
            background_scrub_interval_secs: effective_mode.background_scrub_interval_secs,
            reclaim_enabled: config.runtime.enable_reclaim,
            ..tidefs_local_object_store::StoreOptions::default()
        };
        let scrub_service = MountedBackgroundScrubService::open(&config.backing_dir, scrub_options);
        match scrub_service {
            Ok(service) => {
                adapter.register_background_service(Box::new(service));
                eprintln!(
                    "background-scrub: scheduled (interval={}s)",
                    effective_mode.background_scrub_interval_secs
                );
            }
            Err(error) => {
                eprintln!("background-scrub: disabled after setup failure: {error}");
            }
        }
    }

    let mut options = vec![
        if effective_mode.read_only {
            fuser::MountOption::RO
        } else {
            fuser::MountOption::RW
        },
        fuser::MountOption::FSName(config.runtime.fs_name.clone()),
    ];
    options.extend(fuse_mount_options_for_mode(
        &config.runtime.mount_options,
        effective_mode.read_only,
    ));
    if !config.foreground && !options.contains(&fuser::MountOption::AllowOther) {
        options.push(fuser::MountOption::AllowOther);
    }
    if effective_mode.writeback_cache {
        options.push(fuser::MountOption::WritebackCache);
    }

    let session = fuser::spawn_mount2(adapter, &config.mountpoint, &options)
        .map_err(|e| format!("FUSE mount: {e}"))?;

    if session.guard.is_finished() {
        return Err(
            "FUSE background session exited during mount; refusing a hung mountpoint".to_string(),
        );
    }
    let initialized = session
        .wait_until_initialized(std::time::Duration::from_secs(MOUNT_FUSE_INIT_TIMEOUT_SECS))
        .map_err(|error| format!("wait for FUSE INIT: {error}"))?;
    if !initialized {
        return Err(format!(
            "FUSE kernel initialization did not complete within {MOUNT_FUSE_INIT_TIMEOUT_SECS}s"
        ));
    }
    if session.guard.is_finished() {
        return Err(
            "FUSE background session exited during kernel initialization; refusing a hung mountpoint"
                .to_string(),
        );
    }
    let notifier = session.notifier();
    *notifier_cell.lock().unwrap() = Some(notifier.clone());
    dataset_replacement.install_kernel_cache_invalidator(notifier);

    let mode = if effective_mode.read_only { "RO" } else { "RW" };
    eprintln!(
        "Mounted TideFS (VFS engine) at {} ({mode})",
        config.mountpoint.display()
    );

    // Refuse idmapped mounts: TideFS does not support idmapped mount
    // UID/GID translation in the current FUSE adapter boundary.
    if let Err(err) = check_idmapped_mount(&config.mountpoint) {
        session.join();
        return Err(err);
    }
    let live_owner = if snapshot_export {
        None
    } else {
        match (&config.pool_name, config.pool_uuid) {
            (Some(pool_name), Some(pool_uuid)) => {
                let runtime_dir = PathBuf::from("/run/tidefs/pools").join(hex_uuid(&pool_uuid));
                let owner_config = live_owner::LiveOwnerConfig {
                    pool_name: pool_name.clone(),
                    pool_uuid,
                    backing_dir: config.backing_dir.clone(),
                    mountpoint: config.mountpoint.clone(),
                    runtime_dir,
                    read_only: effective_mode.read_only,
                };
                let owner = match live_owner::start_fuse_owner(
                    owner_config,
                    Arc::clone(&live_owner_engine),
                    dataset_replacement.clone(),
                    shared_filesystem.clone(),
                    Arc::clone(&shutdown),
                ) {
                    Ok(owner) => owner,
                    Err(err) => {
                        session.join();
                        return Err(err);
                    }
                };
                Some(owner)
            }
            _ => None,
        }
    };

    Ok(StartedMount {
        snapshot_export,
        shutdown,
        session,
        live_owner,
        queue_depth_engine,
        background_scheduler,
        mmap_coherency,
        #[cfg(feature = "cluster")]
        shared_filesystem,
    })
}

/// Bootstrap the TideFS FUSE mount lifecycle.
///
/// Creates a `LocalFileSystem` rooted at `config.backing_dir`, wraps it in
/// the `VfsLocalFileSystem` adapter, and mounts a FUSE session at
/// `config.mountpoint`. The calling thread is parked until the process
/// receives SIGINT or SIGTERM; shutdown joins the FUSE session so clean
/// unmount and filesystem teardown finish before the process exits. An
/// explicit pool import is unwound on startup error and exported after join.
///
/// # Errors
///
/// Returns a human-readable string on store-open, adapter-init, FUSE mount,
/// startup-unwind, or clean-export failure.
pub fn run_mount(mut config: MountConfig) -> Result<(), String> {
    let import_owner = config.import_owner.take();
    let _pid_guard = match PidFileGuard::from_environment() {
        Ok(guard) => guard,
        Err(primary_error) => {
            let mut errors = vec![primary_error];
            if let Some(owner) = import_owner {
                if let Err(error) = owner.export() {
                    errors.push(format!(
                        "failed to unwind imported pool after PID-file admission failure: {error}"
                    ));
                }
            }
            #[cfg(feature = "cluster")]
            if let Err(error) = config.mount_authority.release_unmounted() {
                errors.push(format!(
                    "failed to release Pool lease after PID-file admission failure: {error}"
                ));
            }
            return Err(errors.join("; additionally "));
        }
    };

    let StartedMount {
        snapshot_export,
        shutdown,
        session,
        live_owner,
        queue_depth_engine,
        background_scheduler,
        mmap_coherency,
        #[cfg(feature = "cluster")]
        shared_filesystem,
    } = match start_mount(&config) {
        Ok(started) => started,
        Err(primary_error) => {
            let mut errors = vec![primary_error];
            if let Some(owner) = import_owner {
                match owner.export() {
                    Ok(()) => {
                        eprintln!("tidefsctl: pool import unwound after mount startup failure")
                    }
                    Err(error) => errors.push(format!(
                        "failed to unwind imported pool after mount startup failure: {error}"
                    )),
                }
            }
            #[cfg(feature = "cluster")]
            if let Err(error) = config.mount_authority.release_unmounted() {
                errors.push(format!(
                    "failed to release Pool lease after mount startup failure: {error}"
                ));
            }
            return Err(errors.join("; additionally "));
        }
    };

    if config.debug {
        eprintln!("tidefsctl: FUSE session active, Ctrl-C to stop");
    }

    #[cfg(feature = "cluster")]
    let mut cluster_lease_renewal = config.mount_authority.is_cluster_authorized().then(|| {
        let authority =
            std::mem::replace(&mut config.mount_authority, MountAuthority::standalone());
        ClusterLeaseRenewalWorker::start(
            authority,
            shared_filesystem.clone(),
            Arc::clone(&shutdown),
        )
    });
    while !shutdown.load(Ordering::Relaxed) {
        #[cfg(feature = "cluster")]
        if let Some(worker) = cluster_lease_renewal.as_ref() {
            worker.check_health();
        }
        let report = background_scheduler.as_ref().and_then(|scheduler| {
            let started = std::time::Instant::now();
            let report = scheduler
                .lock()
                .unwrap()
                .as_mut()
                .and_then(|scheduler| scheduler.tick_if_idle());
            if report.is_some() {
                crate::observability::HIST_BG_SCHEDULER.record(started.elapsed());
            }
            report
        });
        if report.is_none() {
            std::thread::park_timeout(std::time::Duration::from_millis(500));
            mmap_coherency.process_tick(16);
        } else {
            std::thread::yield_now();
        }
        if session.guard.is_finished() {
            shutdown.store(true, Ordering::Release);
        }
    }

    #[cfg(feature = "cluster")]
    let authority_lost = cluster_lease_renewal
        .as_ref()
        .is_some_and(ClusterLeaseRenewalWorker::authority_lost);
    #[cfg(not(feature = "cluster"))]
    let authority_lost = false;
    if !authority_lost && config.runtime.drain_timeout_secs > 0 {
        eprintln!(
            "tidefsctl: draining in-flight requests for {}s",
            config.runtime.drain_timeout_secs
        );
        let drain_duration = std::time::Duration::from_secs(config.runtime.drain_timeout_secs);
        #[cfg(feature = "cluster")]
        {
            let started = std::time::Instant::now();
            while started.elapsed() < drain_duration {
                if let Some(worker) = cluster_lease_renewal.as_ref() {
                    worker.check_health();
                    if worker.authority_lost() {
                        break;
                    }
                }
                let remaining = drain_duration.saturating_sub(started.elapsed());
                std::thread::sleep(remaining.min(std::time::Duration::from_millis(100)));
            }
        }
        #[cfg(not(feature = "cluster"))]
        std::thread::sleep(drain_duration);
    }
    if let Some(scheduler) = background_scheduler {
        *scheduler.lock().unwrap() = None;
    }

    crate::observability::emit_all_summaries();
    let carrier_drain_result = live_owner
        .as_ref()
        .map_or(Ok(()), live_owner::LiveOwnerHandle::drain_carriers);
    session.join();
    let artifact_result = match config.runtime.queue_depth_artifact.as_deref() {
        Some(path) => write_queue_depth_runtime_artifact(&queue_depth_engine, path),
        None => Ok(()),
    };
    let export_result = match import_owner {
        Some(owner) => owner
            .export()
            .map_err(|err| format!("clean pool export failed during unmount: {err}")),
        None => Ok(()),
    };
    #[cfg(feature = "cluster")]
    let (authority_loss, lease_release_result) = match cluster_lease_renewal.as_mut() {
        Some(worker) => {
            worker.stop();
            (
                worker.authority_loss(),
                worker.release().map_err(|error| {
                    format!("release clustered Pool lease after unmount: {error}")
                }),
            )
        }
        None => (
            None,
            config
                .mount_authority
                .release_unmounted()
                .map_err(|error| format!("release clustered Pool lease after unmount: {error}")),
        ),
    };
    #[cfg(not(feature = "cluster"))]
    let lease_release_result: Result<(), String> = Ok(());
    #[cfg(not(feature = "cluster"))]
    let authority_loss: Option<String> = None;
    if export_result.is_ok() && !snapshot_export {
        if let Some(ref pool_name) = config.pool_name {
            eprintln!("tidefsctl: pool exported: {pool_name}");
        }
    }
    if snapshot_export {
        eprintln!(
            "tidefsctl: snapshot export unmounted from {}",
            config.mountpoint.display()
        );
    } else {
        eprintln!(
            "tidefsctl: filesystem unmounted from {}",
            config.mountpoint.display()
        );
    }
    let mut shutdown_errors = Vec::new();
    if let Some(error) = authority_loss {
        shutdown_errors.push(error);
    }
    for result in [
        &carrier_drain_result,
        &artifact_result,
        &export_result,
        &lease_release_result,
    ] {
        if let Err(error) = result {
            shutdown_errors.push(error.clone());
        }
    }
    let shutdown_result = if shutdown_errors.is_empty() {
        Ok(())
    } else {
        Err(shutdown_errors.join("; additionally "))
    };
    if let Some(owner) = live_owner.as_ref() {
        owner.complete_export(shutdown_result.clone());
    }
    if let Some(owner) = live_owner {
        owner.stop();
    }
    shutdown_result
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

    // SAFETY: `shutdown` is held alive by the caller for the whole mounted
    // session, and the signal handler only stores through the pointed atomic.
    unsafe {
        SHUTDOWN_PTR = Some(Arc::as_ptr(&shutdown));
    }

    extern "C" fn handle(_signum: libc::c_int) {
        // SAFETY: `SHUTDOWN_PTR` is initialized before installing the handler
        // and points at an `AtomicBool`; the handler performs only an atomic
        // store through that stable pointer.
        unsafe {
            if let Some(ptr) = SHUTDOWN_PTR {
                let flag: &AtomicBool = &*ptr;
                flag.store(true, Ordering::Release);
            }
        }
    }

    // SAFETY: `libc::sigaction` is a plain old data C struct; zeroed storage is
    // a valid starting point before the handler and mask fields are populated.
    let mut sa: libc::sigaction = unsafe { mem::zeroed() };
    sa.sa_sigaction = handle as usize;
    // SAFETY: `sa.sa_mask` is a valid, initialized sigset_t field owned by this
    // stack frame and may be filled by libc before the sigaction call.
    unsafe {
        libc::sigfillset(&mut sa.sa_mask);
    }

    for &signum in &[libc::SIGINT, libc::SIGTERM] {
        // SAFETY: `sa` points to a fully initialized sigaction struct, the old
        // action pointer is null because the previous action is not needed, and
        // `signum` is selected from valid process signal constants.
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
mod standalone_mount_authority_tests {
    use super::*;

    #[test]
    fn standalone_mount_authority_is_local_only() {
        let authority = MountAuthority::standalone();

        assert!(matches!(authority, MountAuthority::Standalone));
        assert!(!authority.is_cluster_authorized());
    }
}

#[cfg(all(test, feature = "cluster"))]
mod cluster_mount_authority_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
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

    fn lease_grant(token: PoolLeaseToken) -> ClusterLeaseGrant {
        ClusterLeaseGrant {
            token,
            valid_until: Instant::now() + Duration::from_secs(60),
        }
    }

    #[derive(Debug)]
    struct MockLeaseSession {
        renewals: Arc<AtomicUsize>,
        releases: Arc<AtomicUsize>,
        fail_renewal: bool,
    }

    impl ClusterLeaseSession for MockLeaseSession {
        fn renew(&mut self, token: &PoolLeaseToken) -> Result<ClusterLeaseGrant, String> {
            self.renewals.fetch_add(1, AtomicOrdering::Relaxed);
            if self.fail_renewal {
                return Err("injected renewal loss".to_string());
            }
            let mut renewed = token.clone();
            renewed.expiration_deadline_ms += 60_000;
            Ok(lease_grant(renewed))
        }

        fn release(&mut self, _token: &PoolLeaseToken) -> Result<(), String> {
            self.releases.fetch_add(1, AtomicOrdering::Relaxed);
            Ok(())
        }
    }

    fn token_bytes(token: &PoolLeaseToken) -> Vec<u8> {
        bincode::serialize(token).expect("serialize lease token")
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
    fn cluster_mount_authority_rejects_zero_authority_deadline() {
        let mut token = lease_token(7, POOL_GUID, 2, 99);
        token.expiration_deadline_ms = 0;

        let error = MountAuthority::cluster_lease(POOL_GUID, token).unwrap_err();

        assert!(
            error.contains("zero authority deadline"),
            "unexpected error: {error}"
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

    #[test]
    fn cluster_mount_authority_renewal_updates_shared_deadline_and_releases() {
        let token = lease_token(7, POOL_GUID, 2, 99);
        let renewals = Arc::new(AtomicUsize::new(0));
        let releases = Arc::new(AtomicUsize::new(0));
        let session = MockLeaseSession {
            renewals: Arc::clone(&renewals),
            releases: Arc::clone(&releases),
            fail_renewal: false,
        };
        let mut authority = MountAuthority::renewable_cluster_lease(
            POOL_GUID,
            lease_grant(token),
            Box::new(session),
        )
        .unwrap();
        let deadline = authority.external_mutation_deadline().unwrap();
        let MountAuthority::ClusterLease(cluster) = &mut authority else {
            unreachable!();
        };
        cluster.next_renewal = Instant::now();

        authority.renew_if_due().unwrap();

        assert_eq!(renewals.load(AtomicOrdering::Relaxed), 1);
        assert!(deadline.is_live());
        authority.release_unmounted().unwrap();
        assert_eq!(releases.load(AtomicOrdering::Relaxed), 1);
        assert!(!deadline.is_live());
    }

    #[test]
    fn cluster_mount_authority_renewal_loss_arms_shared_deadline_fence() {
        let token = lease_token(7, POOL_GUID, 2, 99);
        let session = MockLeaseSession {
            renewals: Arc::new(AtomicUsize::new(0)),
            releases: Arc::new(AtomicUsize::new(0)),
            fail_renewal: true,
        };
        let mut authority = MountAuthority::renewable_cluster_lease(
            POOL_GUID,
            lease_grant(token),
            Box::new(session),
        )
        .unwrap();
        let deadline = authority.external_mutation_deadline().unwrap();
        let MountAuthority::ClusterLease(cluster) = &mut authority else {
            unreachable!();
        };
        cluster.next_renewal = Instant::now();

        let error = authority.renew_if_due().unwrap_err();
        authority.fence();

        assert!(error.contains("injected renewal loss"));
        assert!(!deadline.is_live());
    }

    #[test]
    fn cluster_mount_authority_does_not_restart_an_elapsed_grant_window() {
        let releases = Arc::new(AtomicUsize::new(0));
        let session = MockLeaseSession {
            renewals: Arc::new(AtomicUsize::new(0)),
            releases: Arc::clone(&releases),
            fail_renewal: false,
        };
        let grant = ClusterLeaseGrant {
            token: lease_token(7, POOL_GUID, 2, 99),
            valid_until: Instant::now(),
        };

        let error = MountAuthority::renewable_cluster_lease(POOL_GUID, grant, Box::new(session))
            .unwrap_err();

        assert!(error.contains("no remaining local validity"));
        assert_eq!(releases.load(AtomicOrdering::Relaxed), 1);
    }

    #[test]
    fn cluster_renewal_worker_keeps_authority_live_through_clean_shutdown_drain() {
        let token = lease_token(7, POOL_GUID, 2, 99);
        let renewals = Arc::new(AtomicUsize::new(0));
        let releases = Arc::new(AtomicUsize::new(0));
        let session = MockLeaseSession {
            renewals: Arc::clone(&renewals),
            releases: Arc::clone(&releases),
            fail_renewal: false,
        };
        let mut authority = MountAuthority::renewable_cluster_lease(
            POOL_GUID,
            lease_grant(token),
            Box::new(session),
        )
        .unwrap();
        let deadline = authority.external_mutation_deadline().unwrap();
        let MountAuthority::ClusterLease(cluster) = &mut authority else {
            unreachable!();
        };
        cluster.next_renewal = Instant::now();

        let root = tempfile::tempdir().expect("tempdir");
        let mut filesystem =
            tidefs_local_filesystem::LocalFileSystem::open_with_root_authentication_key(
                root.path(),
                tidefs_local_object_store::StoreOptions::default(),
                tidefs_local_filesystem::RootAuthenticationKey::demo_key(),
            )
            .expect("open filesystem");
        filesystem
            .install_external_mutation_deadline(deadline)
            .expect("install lease deadline");
        let shared_filesystem =
            tidefs_local_filesystem::vfs_engine_impl::SharedLocalFileSystem::new(filesystem);
        let shutdown = Arc::new(AtomicBool::new(true));
        let mut worker =
            ClusterLeaseRenewalWorker::start(authority, shared_filesystem, Arc::clone(&shutdown));

        let started = std::time::Instant::now();
        while renewals.load(AtomicOrdering::Acquire) == 0
            && started.elapsed() < std::time::Duration::from_secs(1)
        {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        assert_eq!(renewals.load(AtomicOrdering::Acquire), 1);
        assert!(!worker.authority_lost());
        worker.stop();
        worker.release().unwrap();
        assert_eq!(releases.load(AtomicOrdering::Acquire), 1);
    }

    #[test]
    fn cluster_mount_authority_refuses_one_shot_runtime_authority() {
        let authority =
            MountAuthority::cluster_lease(POOL_GUID, lease_token(7, POOL_GUID, 2, 99)).unwrap();

        let error = authority.require_renewable_cluster_authority().unwrap_err();

        assert!(error.contains("one-shot"), "unexpected error: {error}");
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
    use tidefs_dataset_catalog::{DatasetFlags, DatasetId, LifecycleState, SyncGuarantee};
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
        fs.create_filesystem_dataset(
            "ds1",
            ds_id,
            vec![],
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();

        let id_before = fs.dataset_catalog().mount_lookup("ds1").unwrap();
        assert_eq!(id_before, ds_id);

        // Rename ds1 -> renamed_ds
        fs.rename_pool_dataset("ds1", "renamed_ds").unwrap();

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
        fs.create_filesystem_dataset(
            "ds3",
            ds_id,
            vec![],
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();

        // Destroy the dataset
        fs.destroy_filesystem_dataset("ds3").unwrap();

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
#[cfg(feature = "cluster")]
pub use clustered_mount::{
    ClusteredPosixAuthoritySnapshot, ClusteredPosixMountAdmissionError, ClusteredPosixMountRuntime,
};
