// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![allow(dead_code, unused)]
//! Pool mount subcommand: import a pool and launch the FUSE daemon.
//!
//! Wires CLI arguments to tidefs-pool-import and the POSIX filesystem
//! adapter daemon so the operator can go from mkfs to mounted filesystem
//! in a single command.

use std::path::PathBuf;
use std::process;

use clap::Args;
#[cfg(feature = "cluster")]
use std::net::SocketAddr;
#[cfg(feature = "cluster")]
use tidefs_cluster::pool_lease_token::PoolLeaseToken;
#[cfg(feature = "cluster")]
use tidefs_cluster::pool_protocol::{
    ClusterPoolLeaseAction, ClusterPoolLeaseRequest, ClusterPoolMessage,
};
use tidefs_encryption;
use tidefs_local_filesystem::RootAuthenticationKey;
#[cfg(feature = "cluster")]
use tidefs_transport::{NodeInfo, SessionId, Transport, TransportAddr};
use tidefs_vfs_engine::LivePoolAdminArg;

/// Runtime semantics for the canonical local pool mount carrier.
///
/// These are mounted-filesystem choices, not alternate storage paths. Fault
/// injection and validation artifact destinations deliberately remain library
/// inputs and are not exposed by `tidefsctl`.
#[derive(Args, Debug)]
pub struct PoolMountRuntimeArgs {
    /// Source name reported for the FUSE mount
    #[arg(long = "fs-name", default_value = "tidefs")]
    pub fs_name: String,

    /// Enable the kernel FUSE writeback cache
    #[arg(long = "writeback-cache")]
    pub writeback_cache: bool,

    /// Comma-separated FUSE semantics (atime, sync, allow_other, dev, ...)
    #[arg(short = 'o', long = "options")]
    pub options: Option<String>,

    /// Acknowledge writes only after the local durability barrier
    #[arg(long = "sync")]
    pub sync: bool,

    /// Mounted filesystem content-capacity limit in bytes
    #[arg(long = "content-capacity-bytes")]
    pub content_capacity_bytes: Option<u64>,

    /// Maximum dirty-page age in seconds
    #[arg(long = "writeback-cache-timeout")]
    pub writeback_cache_timeout_secs: Option<u64>,

    /// Grace period for in-flight requests during shutdown
    #[arg(long = "drain-timeout-secs")]
    pub drain_timeout_secs: Option<u64>,

    /// Interval in seconds between bounded mounted scrub cycles; zero disables
    #[arg(long = "background-scrub-interval")]
    pub background_scrub_interval_secs: Option<u64>,

    /// Cache coherency profile: strict, writeback, nearline, async, or offline
    #[arg(long = "coherency")]
    pub coherency: Option<String>,

    /// Per-object compression algorithm: zstd, lz4, or off
    #[arg(long = "compress-algo")]
    pub compress_algo: Option<String>,

    /// Enable deduplication for the mounted dataset
    #[arg(long = "enable-dedup")]
    pub enable_dedup: bool,

    /// Enable committed-root-safe object reclaim
    #[arg(long = "enable-reclaim")]
    pub enable_reclaim: bool,

    /// Admit repair writeback during recovery
    #[arg(long = "enable-repair-writeback")]
    pub enable_repair_writeback: bool,

    /// Mount a committed snapshot read-only
    #[arg(long = "snapshot")]
    pub snapshot: Option<String>,
}

impl Default for PoolMountRuntimeArgs {
    fn default() -> Self {
        Self {
            fs_name: "tidefs".to_string(),
            writeback_cache: false,
            options: None,
            sync: false,
            content_capacity_bytes: None,
            writeback_cache_timeout_secs: None,
            drain_timeout_secs: None,
            background_scrub_interval_secs: None,
            coherency: None,
            compress_algo: None,
            enable_dedup: false,
            enable_reclaim: false,
            enable_repair_writeback: false,
            snapshot: None,
        }
    }
}

/// `pool mount <pool_name> <mount_point> [--devices <dev>...] [--read-only] [--relatime]`
///
/// When `--devices` is provided, the pool is imported from the raw block
/// devices and mounted through this userspace harness. When `--devices` is
/// absent, `pool_name` identifies an already imported pool and must route
/// through that pool's live runtime owner.
#[derive(Args, Debug)]
pub struct PoolMountArgs {
    /// Pool name (imported-pool identity; not a backing-directory path)
    pub pool_name: String,

    /// FUSE mountpoint directory (created if missing)
    pub mount_point: PathBuf,

    /// Import read-only (skip intent log replay)
    #[arg(long = "read-only", default_value_t = false)]
    pub read_only: bool,

    /// Block devices that make up the pool (import+activate before mount)
    #[arg(short = 'd', long = "devices", num_args = 1..)]
    pub devices: Option<Vec<PathBuf>>,

    /// Use relatime timestamp policy (no atime updates unless older
    /// than mtime/ctime)
    #[arg(long = "relatime", default_value_t = false)]
    pub relatime: bool,

    /// Dataset path to mount (default "root"). Resolved through the dataset catalog.
    #[arg(long = "dataset", default_value = "root")]
    pub dataset: String,

    /// Path to a sealed pool key envelope file (84 bytes, "VEKF" magic).
    /// When set, the pool is opened with per-object encryption using the
    /// key unsealed from this envelope. Fails closed if the envelope is
    /// missing, corrupt, or cannot be unsealed.
    #[arg(long = "encryption-envelope", value_name = "PATH")]
    pub encryption_envelope: Option<PathBuf>,

    /// Passphrase for unwrapping dataset encryption keys from the

    /// pool's keystore. When set, the mount path verifies that the

    /// passphrase (with the given salt) can unwrap at least one sealed

    /// DEK in the KeyStore before proceeding.

    #[arg(long = "encryption-passphrase")]
    pub encryption_passphrase: Option<String>,

    /// Salt for the encryption passphrase (hex-encoded, 32 chars).

    /// Must match the salt used when sealing dataset DEKs.

    #[arg(long = "encryption-salt")]
    pub encryption_salt: Option<String>,

    #[command(flatten)]
    pub runtime: PoolMountRuntimeArgs,

    #[cfg(feature = "cluster")]
    /// Request cluster-authoritative mount. When set, the pool must have
    /// CLUSTER_POOL_INCOMPAT labels and the mount must go through cluster
    /// authority instead of offline local storage.
    #[arg(long = "cluster", default_value_t = false)]
    pub cluster: bool,

    #[cfg(feature = "cluster")]
    /// Transport address of the storage node that grants the Pool lease.
    /// Required when --cluster is set. Format: host:port.
    #[arg(long = "cluster-authority-addr", requires = "cluster")]
    pub cluster_authority_addr: Option<String>,

    #[cfg(feature = "cluster")]
    /// Committed member ID that will own and mount the Pool.
    /// Required when --cluster is set.
    #[arg(long = "cluster-owner-node-id", requires = "cluster")]
    pub cluster_owner_node_id: Option<u64>,

    #[cfg(feature = "cluster")]
    /// Committed member ID of the storage node granting the Pool lease.
    /// Required when --cluster is set.
    #[arg(long = "cluster-authority-node-id", requires = "cluster")]
    pub cluster_authority_node_id: Option<u64>,
}

/// Find device-label files inside a pool backing directory.
///
/// Returns file paths that start with a TideFS pool label magic.
/// Used by pool_import for integrity verification before mounting.
fn find_device_files(backing_dir: &std::path::Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let dir = match std::fs::read_dir(backing_dir) {
        Ok(d) => d,
        Err(_) => return out,
    };
    for entry in dir.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        // Check for pool label magic at offset 0.
        if let Ok(mut f) = std::fs::File::open(&path) {
            use std::io::Read;
            let mut magic = [0u8; 4];
            if f.read_exact(&mut magic).is_ok()
                && magic == tidefs_types_pool_label_core::POOL_LABEL_MAGIC
            {
                out.push(path);
            }
        }
    }
    out
}

#[cfg(feature = "cluster")]
#[derive(Debug)]
struct TransportPoolLeaseSession {
    transport: Transport,
    session_id: SessionId,
    authority_node_id: u64,
    owner_node_id: u64,
    pool_guid: [u8; 16],
    next_request_id: u64,
    lease_valid_until: Option<std::time::Instant>,
}

#[cfg(feature = "cluster")]
impl TransportPoolLeaseSession {
    fn connect(
        owner_node_id: u64,
        authority_node_id: u64,
        authority_addr: SocketAddr,
        pool_guid: [u8; 16],
    ) -> Result<Self, String> {
        let mut transport = Transport::new(owner_node_id);
        transport.add_node(NodeInfo::new(
            authority_node_id,
            vec![TransportAddr::Tcp(authority_addr)],
            0,
        ));
        let session_id = transport
            .connect(authority_node_id)
            .map_err(|error| format!("connect to cluster authority {authority_addr}: {error:?}"))?;
        transport.perform_handshake(session_id).map_err(|error| {
            format!("handshake with cluster authority {authority_addr}: {error:?}")
        })?;
        Ok(Self {
            transport,
            session_id,
            authority_node_id,
            owner_node_id,
            pool_guid,
            next_request_id: 1,
            lease_valid_until: None,
        })
    }

    fn acquire(
        &mut self,
    ) -> Result<tidefs_posix_filesystem_adapter_daemon::ClusterLeaseGrant, String> {
        self.exchange(ClusterPoolLeaseAction::Acquire)?
            .ok_or_else(|| {
                "cluster authority granted acquire without a Pool lease token".to_string()
            })
    }

    fn exchange(
        &mut self,
        action: ClusterPoolLeaseAction,
    ) -> Result<Option<tidefs_posix_filesystem_adapter_daemon::ClusterLeaseGrant>, String> {
        let release_action = matches!(&action, ClusterPoolLeaseAction::Release { .. });
        let request_started = std::time::Instant::now();
        let response_deadline = match &action {
            ClusterPoolLeaseAction::Renew { .. } => self
                .lease_valid_until
                .and_then(|deadline| deadline.checked_sub(std::time::Duration::from_millis(1)))
                .ok_or_else(|| {
                    "cluster Pool lease renewal has no live process-local deadline".to_string()
                })?,
            ClusterPoolLeaseAction::Acquire | ClusterPoolLeaseAction::Release { .. } => {
                request_started
                    .checked_add(std::time::Duration::from_secs(5))
                    .ok_or_else(|| "cluster Pool lease response deadline overflowed".to_string())?
            }
        };
        if response_deadline <= request_started {
            return Err("cluster Pool lease request has no safe response window".to_string());
        }

        let request_id = self.next_request_id;
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .ok_or_else(|| "cluster Pool lease request ID space is exhausted".to_string())?;
        let request = ClusterPoolMessage::LeaseRequest(ClusterPoolLeaseRequest {
            request_id,
            pool_guid: self.pool_guid,
            requesting_node_id: self.owner_node_id,
            action,
        });
        let encoded = request
            .encode()
            .map_err(|error| format!("encode cluster Pool lease request: {error:?}"))?;
        let mut wire = Vec::with_capacity(4 + encoded.len());
        wire.extend_from_slice(b"CP01");
        wire.extend_from_slice(&encoded);
        self.transport
            .send_message(self.session_id, &wire)
            .map_err(|error| format!("send cluster Pool lease request: {error:?}"))?;

        let raw = loop {
            match self.transport.recv_message(self.session_id) {
                Ok(response) => break response,
                Err(tidefs_transport::TransportError::WouldBlock(_)) => {
                    let now = std::time::Instant::now();
                    if now >= response_deadline {
                        return Err(
                            "cluster Pool lease authority did not respond before the safe deadline"
                                .to_string(),
                        );
                    }
                    std::thread::sleep(
                        response_deadline
                            .saturating_duration_since(now)
                            .min(std::time::Duration::from_millis(10)),
                    );
                }
                Err(error) => {
                    return Err(format!("receive cluster Pool lease response: {error:?}"));
                }
            }
        };
        if raw.len() < 4 || &raw[..4] != b"CP01" {
            return Err("cluster Pool lease response has invalid CP01 framing".to_string());
        }
        let response = ClusterPoolMessage::decode(&raw[4..])
            .map_err(|error| format!("decode cluster Pool lease response: {error:?}"))?;
        let ClusterPoolMessage::LeaseResponse(response) = response else {
            return Err(format!(
                "cluster Pool lease request received unexpected response: {response:?}"
            ));
        };
        if response.request_id != request_id {
            return Err(format!(
                "cluster Pool lease response request ID mismatch: expected {request_id}, got {}",
                response.request_id
            ));
        }
        if response.node_id != self.authority_node_id {
            return Err(format!(
                "cluster Pool lease response authority mismatch: expected {}, got {}",
                self.authority_node_id, response.node_id
            ));
        }
        if response.pool_guid != self.pool_guid {
            return Err("cluster Pool lease response Pool GUID mismatch".to_string());
        }
        if !response.success {
            return Err(response
                .error
                .unwrap_or_else(|| "cluster Pool lease request was refused".to_string()));
        }

        let token = response
            .lease_token_bytes
            .map(|bytes| {
                bincode::deserialize::<PoolLeaseToken>(&bytes)
                    .map_err(|error| format!("deserialize cluster Pool lease token: {error}"))
            })
            .transpose()?;
        let mut response_error = if response.error.is_some() {
            Some("successful cluster Pool lease response also carried an error".to_string())
        } else if token.as_ref().is_some_and(|token| {
            token.node_id != self.owner_node_id || token.pool_guid != self.pool_guid
        }) {
            Some("cluster Pool lease token owner or Pool GUID mismatch".to_string())
        } else if release_action {
            if token.is_some()
                || response.lease_expiration_ms.is_some()
                || response.lease_remaining_ms.is_some()
            {
                Some("cluster Pool lease release response carried grant material".to_string())
            } else {
                None
            }
        } else {
            match (
                token.as_ref(),
                response.lease_expiration_ms,
                response.lease_remaining_ms,
            ) {
                (Some(token), Some(authority_deadline), Some(_authority_remaining))
                    if token.expiration_deadline_ms != authority_deadline =>
                {
                    Some(
                        "cluster Pool lease response deadline disagrees with its token".to_string(),
                    )
                }
                (Some(_), Some(authority_deadline), Some(authority_remaining))
                    if authority_remaining == 0 || authority_remaining > authority_deadline =>
                {
                    Some(
                        "cluster Pool lease response carried inconsistent remaining validity"
                            .to_string(),
                    )
                }
                (Some(_), Some(_), Some(_)) => None,
                _ => Some(
                    "cluster Pool lease grant omitted or mismatched token, deadline, and remaining validity"
                        .to_string(),
                ),
            }
        };

        let mut valid_until = None;
        if response_error.is_none() && !release_action {
            let authority_remaining = std::time::Duration::from_millis(
                response
                    .lease_remaining_ms
                    .expect("validated grant remaining validity"),
            );
            let validation_now = std::time::Instant::now();
            let measured_round_trip = validation_now.saturating_duration_since(request_started);
            let safety_margin = measured_round_trip
                .checked_add(std::time::Duration::from_millis(1))
                .unwrap_or(std::time::Duration::MAX);
            match authority_remaining.checked_sub(safety_margin) {
                Some(remaining) if !remaining.is_zero() => {
                    match validation_now.checked_add(remaining) {
                        Some(deadline) => valid_until = Some(deadline),
                        None => {
                            response_error =
                                Some("cluster Pool lease local deadline overflowed".to_string())
                        }
                    }
                }
                _ => {
                    response_error = Some(
                        "cluster Pool lease grant had no safe process-local validity after transport delay"
                            .to_string(),
                    );
                }
            }
        }
        if let Some(error) = response_error {
            if !release_action
                && token.as_ref().is_some_and(|token| {
                    token.node_id == self.owner_node_id && token.pool_guid == self.pool_guid
                })
            {
                let token = token.expect("checked above");
                let cleanup = self.exchange(ClusterPoolLeaseAction::Release { token });
                return Err(match cleanup {
                    Ok(None) => error,
                    Ok(Some(_)) => {
                        format!("{error}; rejected Pool lease cleanup returned another token")
                    }
                    Err(cleanup_error) => {
                        format!("{error}; rejected Pool lease cleanup failed: {cleanup_error}")
                    }
                });
            }
            return Err(error);
        }
        if release_action {
            self.lease_valid_until = None;
            return Ok(None);
        }

        let valid_until = valid_until.expect("validated non-release local deadline");
        self.lease_valid_until = Some(valid_until);
        Ok(Some(
            tidefs_posix_filesystem_adapter_daemon::ClusterLeaseGrant {
                token: token.expect("validated non-release grant token"),
                valid_until,
            },
        ))
    }
}

#[cfg(feature = "cluster")]
impl tidefs_posix_filesystem_adapter_daemon::ClusterLeaseSession for TransportPoolLeaseSession {
    fn renew(
        &mut self,
        token: &PoolLeaseToken,
    ) -> Result<tidefs_posix_filesystem_adapter_daemon::ClusterLeaseGrant, String> {
        self.exchange(ClusterPoolLeaseAction::Renew {
            token: token.clone(),
        })?
        .ok_or_else(|| "cluster authority renewed without returning a Pool lease token".to_string())
    }

    fn release(&mut self, token: &PoolLeaseToken) -> Result<(), String> {
        if self
            .exchange(ClusterPoolLeaseAction::Release {
                token: token.clone(),
            })?
            .is_some()
        {
            return Err("cluster authority returned a token for Pool lease release".to_string());
        }
        Ok(())
    }
}

/// Try to import a pool from device-label files found in the backing
/// directory.
///
/// Returns `Ok(Some(imported))` when device labels exist and import
/// succeeds, `Ok(None)` when no device labels are found (skip import),
/// or an error string when import fails.
fn try_import_pool(
    backing_dir: &std::path::Path,
    lock_dir: &std::path::Path,
    read_only: bool,
    encryption_key: Option<tidefs_encryption::StoreKey>,
) -> Result<Option<tidefs_pool_import::ImportedPool>, String> {
    let device_files = find_device_files(backing_dir);
    if device_files.is_empty() {
        return Ok(None);
    }

    tidefs_pool_import::pool_import(&device_files, lock_dir, read_only, encryption_key, None)
        .map(Some)
        .map_err(|e| e.to_string())
}

fn scan_device_pool_config(
    pool_name: &str,
    devices: &[PathBuf],
    operation: &str,
) -> tidefs_pool_scan::PoolConfig {
    let entries = match tidefs_pool_scan::scan_labels(devices) {
        Ok(entries) => entries,
        Err(err) => {
            eprintln!("tidefsctl pool {operation}: label scan failed for '{pool_name}': {err}");
            process::exit(1);
        }
    };
    let config = match tidefs_pool_scan::PoolAssembler::assemble(&entries, None) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("tidefsctl pool {operation}: pool assembly failed for '{pool_name}': {err}");
            process::exit(1);
        }
    };
    if config.pool_name != pool_name {
        eprintln!(
            "tidefsctl pool {operation}: devices belong to pool '{}', not '{pool_name}'",
            config.pool_name
        );
        process::exit(1);
    }
    config
}

/// Resolve encryption material from a sealed envelope file for pool import.
///
/// Returns:
/// - `import_key`: `Some(StoreKey)` for passing to `pool_import` (label validation + fingerprint)
/// - `mount_config`: `Some(EncryptionConfig)` for passing to `MountConfig`
///
/// Fails process with `eprintln!`+exit when the envelope path is set but unsealing fails.
fn resolve_encryption_for_import(
    envelope_path: &Option<std::path::PathBuf>,
) -> (
    Option<tidefs_encryption::StoreKey>,
    Option<tidefs_local_object_store::encrypt::EncryptionConfig>,
) {
    if let Some(ref path) = envelope_path {
        let root_auth_key = super::root_authentication_key_or_exit("pool mount");
        match tidefs_posix_filesystem_adapter_daemon::resolve_encryption_key_from_envelope(
            path,
            &root_auth_key,
        ) {
            Some(enc_config) => {
                // Convert StoreEncryptionKey -> StoreKey for pool_import
                let store_key = tidefs_encryption::StoreKey::from_bytes(enc_config.key.as_bytes())
                    .expect("StoreEncryptionKey is always 32 bytes");
                (Some(store_key), Some(enc_config))
            }
            None => {
                eprintln!(
                    "tidefsctl pool mount: failed to unseal encryption envelope {}",
                    path.display()
                );
                eprintln!(
                    "tidefsctl pool mount: wrong root auth key, corrupt envelope, or tampered file"
                );
                std::process::exit(1);
            }
        }
    } else {
        (None, None)
    }
}

fn build_mount_runtime(
    args: &PoolMountArgs,
) -> Result<
    (
        tidefs_posix_filesystem_adapter_daemon::MountRuntimeOptions,
        tidefs_posix_filesystem_adapter_daemon::coherency_profile::CoherencyProfile,
    ),
    String,
> {
    let mut runtime = tidefs_posix_filesystem_adapter_daemon::MountRuntimeOptions::default();
    runtime.fs_name = args.runtime.fs_name.clone();
    if let Some(raw) = args.runtime.options.as_deref() {
        runtime.mount_options =
            tidefs_posix_filesystem_adapter_daemon::mount_options::MountOptions::parse(raw)
                .map_err(|error| format!("invalid mount options: {error}"))?;
    }
    if args.relatime {
        runtime.mount_options.timestamp_policy =
            tidefs_posix_filesystem_adapter_daemon::mount_options::TimestampPolicy::RelativeAtime;
    }
    if args.runtime.sync {
        runtime.mount_options.sync = true;
    }
    if let Some(bytes) = args.runtime.content_capacity_bytes {
        if bytes == 0 {
            return Err("--content-capacity-bytes must be greater than zero".to_string());
        }
        runtime.content_capacity_bytes = bytes;
    }
    if let Some(seconds) = args.runtime.writeback_cache_timeout_secs {
        if seconds == 0 {
            return Err("--writeback-cache-timeout must be greater than zero".to_string());
        }
        runtime.writeback_cache_timeout_secs = seconds;
    }
    if let Some(seconds) = args.runtime.drain_timeout_secs {
        runtime.drain_timeout_secs = seconds;
    }
    if let Some(seconds) = args.runtime.background_scrub_interval_secs {
        runtime.background_scrub_interval_secs = seconds;
    }
    runtime.enable_dedup = args.runtime.enable_dedup;
    runtime.enable_reclaim = args.runtime.enable_reclaim;
    runtime.enable_repair_writeback = args.runtime.enable_repair_writeback;
    if let Some(raw) = args.runtime.compress_algo.as_deref() {
        let algorithm = match raw.to_ascii_lowercase().as_str() {
            "zstd" => tidefs_local_object_store::CompressionAlgorithm::Zstd,
            "lz4" => tidefs_local_object_store::CompressionAlgorithm::Lz4,
            "off" | "none" => tidefs_local_object_store::CompressionAlgorithm::Uncompressed,
            _ => {
                return Err(format!(
                    "unknown compression algorithm `{raw}`; expected zstd, lz4, or off"
                ));
            }
        };
        runtime.compression = Some(tidefs_local_object_store::CompressionConfig {
            algorithm,
            level: if algorithm == tidefs_local_object_store::CompressionAlgorithm::Lz4 {
                0
            } else {
                3
            },
            min_compress_bytes: 0,
        });
    }
    let coherency_profile = args
        .runtime
        .coherency
        .as_deref()
        .map(str::parse)
        .transpose()
        .map_err(|error: String| format!("invalid coherency profile: {error}"))?
        .unwrap_or_default();
    Ok((runtime, coherency_profile))
}

/// Handle `tidefsctl pool mount`.
///
/// 1. Import explicit `--devices` when starting a not-yet-imported pool.
/// 2. Launch the FUSE daemon on the runtime metadata directory.
/// 3. Route already-imported pools through the live runtime owner.
pub fn handle_mount(args: PoolMountArgs) {
    let mountpoint = args.mount_point.clone();
    let lock_dir = std::path::PathBuf::from("/run/tidefs/import");
    let live_args = super::live_owner::live_admin_args([
        (
            "mountpoint",
            LivePoolAdminArg::String(mountpoint.display().to_string()),
        ),
        ("read_only", LivePoolAdminArg::Bool(args.read_only)),
        ("relatime", LivePoolAdminArg::Bool(args.relatime)),
        ("dataset", LivePoolAdminArg::String(args.dataset.clone())),
    ]);

    #[cfg(feature = "cluster")]
    // Cluster mount parameter validation: when --cluster is set,
    // refuse missing or invalid parameters before any pool work.
    if args.cluster {
        if args.cluster_authority_addr.is_none() {
            eprintln!("tidefsctl pool mount: --cluster requires --cluster-authority-addr");
            process::exit(1);
        }
        if args.cluster_owner_node_id.is_none() || args.cluster_owner_node_id == Some(0) {
            eprintln!("tidefsctl pool mount: --cluster requires --cluster-owner-node-id (nonzero)");
            process::exit(1);
        }
        if args.cluster_authority_node_id.is_none() || args.cluster_authority_node_id == Some(0) {
            eprintln!(
                "tidefsctl pool mount: --cluster requires --cluster-authority-node-id (nonzero)"
            );
            process::exit(1);
        }
    }

    let devices = match args.devices.as_ref() {
        Some(devices) => devices,
        None => {
            super::live_owner::route_with_args("pool", "mount", &args.pool_name, live_args.clone())
        }
    };
    let existing_config = scan_device_pool_config(&args.pool_name, devices, "mount");
    // Route a reachable owner. Otherwise import exclusion, not cached owner
    // metadata or an ACTIVE label, decides whether this process may own mount.
    super::live_owner::route_reachable_owner_for_uuid_with_args(
        "pool",
        "mount",
        &args.pool_name,
        existing_config.pool_uuid,
        live_args.clone(),
    );

    // Complete all CLI preflight before activating labels or acquiring the
    // import exclusion. The unique import owner is created only immediately
    // before `run_mount` takes responsibility for it.
    let (import_encryption_key, encryption_config) =
        resolve_encryption_for_import(&args.encryption_envelope);
    check_encryption_consistency(&existing_config, &args.encryption_envelope);

    let backing_dir =
        std::path::PathBuf::from("/run/tidefs/pools").join(hex_uuid(&existing_config.pool_uuid));
    std::fs::create_dir_all(&backing_dir).unwrap_or_else(|e| {
        eprintln!("tidefsctl pool mount: cannot create pool runtime dir: {e}");
        process::exit(1);
    });
    let owner_pool_uuid = Some(existing_config.pool_uuid);

    // --- Encryption passphrase verification ---

    // When --encryption-passphrase and --encryption-salt are provided,

    // verify the passphrase can unwrap at least one sealed DEK from the

    // pool's KeyStore before proceeding with mount.

    if let (Some(ref passphrase), Some(ref salt_hex)) =
        (&args.encryption_passphrase, &args.encryption_salt)
    {
        match verify_encryption_passphrase(&backing_dir, passphrase, salt_hex) {
            Ok(datasets_found) => {
                if datasets_found > 0 {
                    println!("encryption: passphrase verified ({datasets_found} dataset(s) with sealed DEKs)");
                } else {
                    println!(
                        "encryption: passphrase accepted but no sealed DEKs found in keystore"
                    );
                }
            }

            Err(e) => {
                eprintln!("tidefsctl pool mount: encryption passphrase verification failed: {e}");

                eprintln!(
                    "tidefsctl pool mount: refusing to mount with invalid encryption credentials"
                );

                process::exit(1);
            }
        }
    }

    // Validate every remaining fallible operator option before acquiring a
    // Pool lease or importing the Pool, so no early-exit path can strand
    // either authority.
    let (runtime, coherency_profile) = build_mount_runtime(&args).unwrap_or_else(|error| {
        eprintln!("tidefsctl pool mount: {error}");
        process::exit(1);
    });

    // --- FUSE daemon launch ---
    let mut mount_options = Vec::new();
    if args.relatime {
        mount_options.push("relatime".to_string());
    }
    if args.read_only {
        mount_options.push("read-only".to_string());
    }

    println!("mounting pool at {}", mountpoint.display(),);
    if !mount_options.is_empty() {
        println!("  options: {}", mount_options.join(","));
    }
    // Cluster label validation and lease acquisition.
    #[cfg(feature = "cluster")]
    let mut mount_authority = if args.cluster {
        match validate_cluster_pool_labels(&backing_dir, &args.devices) {
            Ok(()) => {
                println!("cluster: pool labels confirmed CLUSTER_POOL_INCOMPAT");
            }
            Err(msg) => {
                eprintln!("tidefsctl pool mount: cluster label validation failed: {msg}");
                eprintln!(
                    "tidefsctl pool mount: refusing to mount without valid cluster authority"
                );
                process::exit(1);
            }
        }

        // Acquire pool GUID from the first device label.
        let pool_guid = match read_pool_guid(&backing_dir, &args.devices) {
            Ok(guid) => guid,
            Err(msg) => {
                eprintln!("tidefsctl pool mount: cannot read pool GUID: {msg}");
                process::exit(1);
            }
        };

        let authority_addr = args.cluster_authority_addr.as_ref().unwrap();
        let owner_node_id = args.cluster_owner_node_id.unwrap();
        let authority_node_id = args.cluster_authority_node_id.unwrap();

        println!(
            "cluster: owner node {} requesting Pool lease from authority node {} at {} for pool {:02x?}...",
            owner_node_id,
            authority_node_id,
            authority_addr,
            &pool_guid[..4]
        );

        let addr: SocketAddr = authority_addr.parse().unwrap_or_else(|error| {
            eprintln!(
                "tidefsctl pool mount: invalid --cluster-authority-addr '{authority_addr}': {error}"
            );
            process::exit(1);
        });
        let mut lease_session =
            TransportPoolLeaseSession::connect(owner_node_id, authority_node_id, addr, pool_guid)
                .unwrap_or_else(|error| {
                    eprintln!("tidefsctl pool mount: {error}");
                    process::exit(1);
                });
        let grant = lease_session.acquire().unwrap_or_else(|error| {
            eprintln!("tidefsctl pool mount: Pool lease acquire failed: {error}");
            process::exit(1);
        });
        let token = grant.token.clone();
        if token.node_id != owner_node_id || token.pool_guid != pool_guid {
            let release_error =
                tidefs_posix_filesystem_adapter_daemon::ClusterLeaseSession::release(
                    &mut lease_session,
                    &token,
                )
                .err();
            eprintln!(
                "tidefsctl pool mount: authority returned a Pool lease for the wrong owner or Pool{}",
                release_error
                    .map(|error| format!("; release also failed: {error}"))
                    .unwrap_or_default()
            );
            process::exit(1);
        }

        let mut authority =
            tidefs_posix_filesystem_adapter_daemon::MountAuthority::renewable_cluster_lease(
                pool_guid,
                grant,
                Box::new(lease_session),
            )
            .unwrap_or_else(|error| {
                eprintln!("tidefsctl pool mount: {error}");
                process::exit(1);
            });

        println!(
            "cluster: lease granted (node={}, epoch={}, lease_id={}, local_valid_for_ms={})",
            token.node_id,
            token.epoch.0,
            token.lease_id,
            authority
                .cluster_lease_remaining()
                .unwrap_or_default()
                .as_millis()
        );

        // Validate cluster ownership via import_pool_clustered.
        let device_paths: Vec<std::path::PathBuf> = args
            .devices
            .clone()
            .unwrap_or_else(|| find_device_files(&backing_dir));
        match tidefs_local_object_store::pool_importer::PoolImporter::import_pool_clustered(
            &device_paths,
            Some(pool_guid),
            Some(token.clone()),
            authority.cluster_lease_valid_until(),
        ) {
            Ok(candidate) => {
                println!(
                    "cluster: pool import authorized (pool={}, devices={})",
                    candidate.pool_name,
                    candidate.devices.len()
                );
            }
            Err(error) => {
                let release_error = authority.release_unmounted().err();
                eprintln!(
                    "tidefsctl pool mount: cluster pool import validation failed: {error}{}",
                    release_error
                        .map(|error| format!("; Pool lease release also failed: {error}"))
                        .unwrap_or_default()
                );
                process::exit(1);
            }
        }
        authority
    } else {
        tidefs_posix_filesystem_adapter_daemon::MountAuthority::standalone()
    };
    #[cfg(not(feature = "cluster"))]
    let mount_authority = tidefs_posix_filesystem_adapter_daemon::MountAuthority::standalone();

    let import_owner = match tidefs_pool_import::pool_import_owned(
        devices,
        &lock_dir,
        args.read_only,
        import_encryption_key,
    ) {
        Ok(owner) => owner,
        Err(tidefs_pool_import::ImportError::AlreadyImported { pool_uuid }) => {
            #[cfg(feature = "cluster")]
            if let Err(error) = mount_authority.release_unmounted() {
                eprintln!(
                    "tidefsctl pool mount: failed to release Pool lease before routing to existing owner: {error}"
                );
                process::exit(1);
            }
            super::live_owner::route_imported_with_format_and_args(
                "pool",
                "mount",
                &args.pool_name,
                pool_uuid,
                false,
                live_args,
            )
        }
        Err(err) => {
            #[cfg(feature = "cluster")]
            if let Err(error) = mount_authority.release_unmounted() {
                eprintln!(
                    "tidefsctl pool mount: pool import failed: {err}; Pool lease release also failed: {error}"
                );
                process::exit(1);
            }
            eprintln!("tidefsctl pool mount: pool import failed: {err}");
            process::exit(1);
        }
    };
    #[cfg(feature = "cluster")]
    if args.cluster && import_owner.imported().config.pool_uuid != existing_config.pool_uuid {
        let imported_pool_uuid = import_owner.imported().config.pool_uuid;
        let export_error = import_owner.export().err();
        let release_error = mount_authority.release_unmounted().err();
        eprintln!(
            "tidefsctl pool mount: imported Pool GUID {} differs from cluster-authorized Pool GUID {}{}{}",
            hex_uuid(&imported_pool_uuid),
            hex_uuid(&existing_config.pool_uuid),
            export_error
                .map(|error| format!("; Pool export also failed: {error}"))
                .unwrap_or_default(),
            release_error
                .map(|error| format!("; Pool lease release also failed: {error}"))
                .unwrap_or_default(),
        );
        process::exit(1);
    }
    let imported = import_owner.imported();
    let cfg = &imported.config;
    let stats = &imported.stats;
    println!("pool \"{}\" imported", cfg.pool_name);
    println!("  pool uuid:   {}", hex_uuid(&cfg.pool_uuid));
    println!("  state:       {}", cfg.state);
    println!("  devices:     {}", cfg.device_count);
    println!("  import time: {} ms", stats.import_time_ms);
    if stats.encrypted {
        println!("  encrypted:   yes");
        if let Some(ref fp) = stats.key_fingerprint {
            println!("  key fp:      {fp}");
        }
    }
    if stats.read_only {
        println!("  read-only:   yes");
    }

    let config = tidefs_posix_filesystem_adapter_daemon::MountConfig {
        backing_dir,
        mountpoint,
        pool_name: Some(args.pool_name.clone()),
        pool_redundancy_policy: tidefs_local_object_store::PoolRedundancyPolicy::from_label_policy(
            cfg.redundancy_policy,
        ),
        pool_uuid: owner_pool_uuid,
        foreground: true,
        debug: false,
        read_only: args.read_only,
        writeback_cache: args.runtime.writeback_cache,
        coherency_profile,
        block_devices: args.devices.clone(),
        import_owner: Some(import_owner),
        dataset_path: Some(args.dataset.clone()),
        encryption: encryption_config,
        snapshot_name: args.runtime.snapshot.clone(),
        mount_authority,
        runtime,
    };

    if let Err(err) = tidefs_posix_filesystem_adapter_daemon::run_mount(config) {
        eprintln!("tidefsctl pool mount: {err}");
        process::exit(1);
    }
}

/// Check encryption consistency between pool label and operator request.
///
/// When the pool label declares encryption (ENCRYPTION_INCOMPAT feature bit),
/// the operator must provide a valid sealed envelope; plaintext opens of
/// encrypted pools fail closed. When the pool is plaintext and the operator
/// requests encryption, this warns but continues (plaintext pool + encryption
/// key is accepted for upward migration).
fn check_encryption_consistency(cfg: &tidefs_pool_scan::PoolConfig, envelope: &Option<PathBuf>) {
    let pool_is_encrypted =
        (cfg.feature_flags & tidefs_types_pool_label_core::features::ENCRYPTION_INCOMPAT) != 0;
    if pool_is_encrypted && envelope.is_none() {
        eprintln!(
            "tidefsctl pool mount: pool '{}' is encrypted but no --encryption-envelope provided",
            cfg.pool_name
        );
        eprintln!("tidefsctl pool mount: refusing to open encrypted pool in plaintext mode");
        process::exit(1);
    }
    if pool_is_encrypted {
        println!("  encryption:   yes");
    }
}

/// Format a 16-byte UUID as a hex string.
fn hex_uuid(uuid: &[u8; 16]) -> String {
    uuid.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}
/// Verify that an encryption passphrase can unwrap at least one sealed DEK
/// from the pool's KeyStore.
///
/// Opens the KeyStore at `backing_dir`, derives the PoolWrappingKey from
/// `passphrase` + decoded `salt_hex`, and attempts to unwrap the first
/// sealed DEK found. Returns the number of datasets found (0 if keystore
/// is empty). Fails if the passphrase cannot unwrap any DEK.
fn verify_encryption_passphrase(
    backing_dir: &std::path::Path,

    passphrase: &str,

    salt_hex: &str,
) -> Result<usize, String> {
    use tidefs_encryption::key_hierarchy::{PoolWrappingKey, SALT_LEN};

    use tidefs_encryption::key_manager::{KeyManager, KeyStore};

    use tidefs_local_object_store::StoreOptions;

    // Decode the salt from hex.

    let salt = hex_decode_salt(salt_hex)?;

    // Derive the wrapping key.

    let wk = PoolWrappingKey::derive(passphrase, &salt)
        .map_err(|e| format!("failed to derive wrapping key: {e}"))?;

    // Open the KeyStore.

    let ks = KeyStore::open_with_options(backing_dir, StoreOptions::default(), salt)
        .map_err(|e| format!("failed to open keystore: {e}"))?;

    let datasets = ks
        .list_datasets()
        .map_err(|e| format!("failed to list keystore datasets: {e}"))?;

    if datasets.is_empty() {
        return Ok(0);
    }

    // Verify at least the first dataset can be unwrapped.

    let first = &datasets[0];

    let sealed = ks
        .load_sealed_dek(first)
        .map_err(|e| format!("failed to load sealed DEK for '{first}': {e}"))?
        .ok_or_else(|| format!("dataset '{first}' listed but has no sealed DEK"))?;

    KeyManager::unseal_dek(&sealed, &wk).map_err(|_| {
        format!("passphrase cannot unwrap DEK for '{first}' (wrong passphrase or salt)")
    })?;

    Ok(datasets.len())
}
/// Decode a hex-encoded salt string into a `[u8; SALT_LEN]`.
fn hex_decode_salt(hex: &str) -> Result<[u8; tidefs_encryption::key_hierarchy::SALT_LEN], String> {
    use tidefs_encryption::key_hierarchy::SALT_LEN;

    let hex = hex.trim();

    if hex.len() != SALT_LEN * 2 {
        return Err(format!(
            "expected {} hex chars ({} bytes), got {}",
            SALT_LEN * 2,
            SALT_LEN,
            hex.len()
        ));
    }

    let mut salt = [0u8; SALT_LEN];

    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        if i >= SALT_LEN {
            break;
        }

        if chunk.len() != 2 {
            return Err("odd number of hex characters".to_string());
        }

        let byte_str =
            std::str::from_utf8(chunk).map_err(|_| "invalid UTF-8 in hex string".to_string())?;

        let byte = u8::from_str_radix(byte_str, 16)
            .map_err(|e| format!("invalid hex byte at position {}: {e}", i * 2))?;

        salt[i] = byte;
    }

    Ok(salt)
}

/// Read the pool GUID from the first device label file.
///
/// Used during cluster mount to correlate the lease request with the
/// correct pool on the storage-node.
#[cfg(feature = "cluster")]
fn read_pool_guid(
    backing_dir: &std::path::Path,
    devices: &Option<Vec<std::path::PathBuf>>,
) -> Result<[u8; 16], String> {
    use std::io::Read;

    let device_paths: Vec<std::path::PathBuf> = if let Some(ref devs) = devices {
        devs.clone()
    } else {
        find_device_files(backing_dir)
    };

    let dev = device_paths
        .first()
        .ok_or_else(|| "no device label files found".to_string())?;

    let mut f = std::fs::File::open(dev)
        .map_err(|e| format!("cannot open label at {}: {e}", dev.display()))?;
    let mut buf = vec![0u8; tidefs_types_pool_label_core::POOL_LABEL_SIZE];
    f.read_exact(&mut buf)
        .map_err(|e| format!("cannot read label at {}: {e}", dev.display()))?;

    let decoded = tidefs_types_pool_label_core::decode_label(&buf)
        .map_err(|e| format!("cannot decode label at {}: {e}", dev.display()))?;

    Ok(decoded.pool_guid)
}

/// Validate that all pool device labels carry CLUSTER_POOL_INCOMPAT.
///
/// Scans device-label files in the backing directory or the provided
/// device paths. Returns Ok(()) when all labels are clustered, or Err
/// with a message when labels are missing, not clustered, or unreadable.
#[cfg(feature = "cluster")]
fn validate_cluster_pool_labels(
    backing_dir: &std::path::Path,
    devices: &Option<Vec<std::path::PathBuf>>,
) -> Result<(), String> {
    use std::io::Read;

    let device_paths: Vec<std::path::PathBuf> = if let Some(ref devs) = devices {
        devs.clone()
    } else {
        find_device_files(backing_dir)
    };

    if device_paths.is_empty() {
        return Err(
            "no pool device-label files found; cluster mount requires devices with CLUSTER_POOL_INCOMPAT labels"
                .to_string(),
        );
    }

    for dev in &device_paths {
        let mut f = std::fs::File::open(dev)
            .map_err(|e| format!("cannot open label at {}: {e}", dev.display()))?;
        let mut buf = vec![0u8; tidefs_types_pool_label_core::POOL_LABEL_SIZE];
        f.read_exact(&mut buf)
            .map_err(|e| format!("cannot read label at {}: {e}", dev.display()))?;

        let decoded = tidefs_types_pool_label_core::decode_label(&buf)
            .map_err(|e| format!("cannot decode label at {}: {e}", dev.display()))?;

        if !decoded.is_clustered() {
            return Err(format!(
                "device {} has a non-clustered pool label; cluster mount requires \
                 CLUSTER_POOL_INCOMPAT (bit 9) in features_incompat on every device",
                dev.display()
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tidefs_types_pool_label_core::{
        encode_label, seal_label, PoolLabelV1, POOL_LABEL_V1_EXT_WIRE_SIZE,
    };

    /// Write a valid TideFS pool label into a file, padded to
    /// POOL_LABEL_SIZE so read_label_bytes works.
    fn write_test_label(path: &std::path::Path, pool_name: &str) {
        let label = PoolLabelV1::new([0xAAu8; 16], [0x01u8; 16], pool_name);
        let sealed = seal_label(label).unwrap();
        let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        encode_label(&sealed, &mut buf).unwrap();
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(&buf).unwrap();
        // Pad to POOL_LABEL_SIZE so pool_import's read_label_bytes works.
        let padding =
            vec![0u8; tidefs_types_pool_label_core::POOL_LABEL_SIZE - POOL_LABEL_V1_EXT_WIRE_SIZE];
        f.write_all(&padding).unwrap();
        f.flush().unwrap();
    }

    // ── Struct binding tests ───────────────────────────────────────

    #[test]
    fn runtime_defaults_match_cli_fs_name() {
        assert_eq!(PoolMountRuntimeArgs::default().fs_name, "tidefs");
    }

    #[test]
    fn mount_args_bind_expected_fields() {
        let args = PoolMountArgs {
            dataset: "root".into(),
            encryption_envelope: None,
            encryption_passphrase: None,
            encryption_salt: None,
            runtime: PoolMountRuntimeArgs::default(),
            #[cfg(feature = "cluster")]
            cluster: false,
            #[cfg(feature = "cluster")]
            cluster_authority_addr: None,
            #[cfg(feature = "cluster")]
            cluster_owner_node_id: None,
            #[cfg(feature = "cluster")]
            cluster_authority_node_id: None,
            pool_name: "testpool".into(),
            mount_point: PathBuf::from("/mnt/tidefs"),
            read_only: false,
            devices: None,
            relatime: false,
        };
        assert_eq!(args.pool_name, "testpool");
        assert_eq!(args.mount_point, PathBuf::from("/mnt/tidefs"));
        assert!(!args.read_only);
        assert!(!args.relatime);
    }

    #[test]
    fn mount_args_read_only_flag() {
        let args = PoolMountArgs {
            pool_name: "ropool".into(),
            mount_point: PathBuf::from("/mnt/ro"),
            read_only: true,
            devices: None,
            relatime: false,
            encryption_envelope: None,
            encryption_passphrase: None,
            encryption_salt: None,
            runtime: PoolMountRuntimeArgs::default(),
            dataset: "root".into(),
            #[cfg(feature = "cluster")]
            cluster: false,
            #[cfg(feature = "cluster")]
            cluster_authority_addr: None,
            #[cfg(feature = "cluster")]
            cluster_owner_node_id: None,
            #[cfg(feature = "cluster")]
            cluster_authority_node_id: None,
        };
        assert!(args.read_only);
    }

    #[test]
    fn mount_args_relatime_flag() {
        let args = PoolMountArgs {
            pool_name: "relpool".into(),
            mount_point: PathBuf::from("/mnt/rel"),
            read_only: false,
            devices: None,
            relatime: true,
            dataset: "root".into(),
            encryption_envelope: None,
            encryption_passphrase: None,
            encryption_salt: None,
            runtime: PoolMountRuntimeArgs::default(),
            #[cfg(feature = "cluster")]
            cluster: false,
            #[cfg(feature = "cluster")]
            cluster_authority_addr: None,
            #[cfg(feature = "cluster")]
            cluster_owner_node_id: None,
            #[cfg(feature = "cluster")]
            cluster_authority_node_id: None,
        };
        assert!(args.relatime);
    }

    #[test]
    fn mount_args_all_options() {
        let args = PoolMountArgs {
            pool_name: "full".into(),
            mount_point: PathBuf::from("/mnt/full"),
            read_only: true,
            devices: None,
            relatime: true,
            dataset: "root".into(),
            encryption_envelope: None,
            encryption_passphrase: None,
            encryption_salt: None,
            runtime: PoolMountRuntimeArgs::default(),
            #[cfg(feature = "cluster")]
            cluster: false,
            #[cfg(feature = "cluster")]
            cluster_authority_addr: None,
            #[cfg(feature = "cluster")]
            cluster_owner_node_id: None,
            #[cfg(feature = "cluster")]
            cluster_authority_node_id: None,
        };
        assert_eq!(args.pool_name, "full");
        assert_eq!(args.mount_point, PathBuf::from("/mnt/full"));
        assert!(args.read_only);
        assert!(args.relatime);
    }

    // ── find_device_files tests ────────────────────────────────────

    #[test]
    fn find_device_files_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let files = find_device_files(dir.path());
        assert!(files.is_empty());
    }

    #[test]
    fn find_device_files_skips_non_label_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("data.bin"), b"not a label").unwrap();
        let files = find_device_files(dir.path());
        assert!(files.is_empty());
    }

    #[test]
    fn find_device_files_detects_label_magic() {
        let dir = tempfile::tempdir().unwrap();
        let label_path = dir.path().join("device0");
        // Write POOL_LABEL_MAGIC at offset 0 plus enough bytes for read_exact.
        let mut buf = vec![0u8; 512];
        buf[..4].copy_from_slice(&tidefs_types_pool_label_core::POOL_LABEL_MAGIC);
        std::fs::write(&label_path, &buf).unwrap();
        let files = find_device_files(dir.path());
        assert_eq!(files.len(), 1);
        assert_eq!(files[0], label_path);
    }

    // ── try_import_pool integration tests ──────────────────────────

    /// Helper: create a lock directory inside the given temp dir.
    fn lock_dir_for(dir: &tempfile::TempDir) -> std::path::PathBuf {
        let p = dir.path().join("locks");
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// No device labels → import is skipped (Ok(None)).
    #[test]
    fn try_import_pool_empty_dir_skips_import() {
        let dir = tempfile::tempdir().unwrap();
        let lock_dir = lock_dir_for(&dir);
        let result = try_import_pool(dir.path(), &lock_dir, false, None).unwrap();
        assert!(result.is_none(), "empty dir should skip import");
    }

    /// Non-label files are ignored → import skipped.
    #[test]
    fn try_import_pool_non_label_files_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let lock_dir = lock_dir_for(&dir);
        std::fs::write(dir.path().join("random.bin"), b"just some data").unwrap();
        let result = try_import_pool(dir.path(), &lock_dir, false, None).unwrap();
        assert!(result.is_none());
    }

    /// Valid pool label file → import succeeds, pool name matches.
    #[test]
    fn try_import_pool_valid_label_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let lock_dir = lock_dir_for(&dir);
        let dev_path = dir.path().join("device0");
        write_test_label(&dev_path, "import_test_pool");

        let result = try_import_pool(dir.path(), &lock_dir, false, None).unwrap();
        assert!(result.is_some(), "valid label should import");
        let imported = result.unwrap();
        assert_eq!(imported.config.pool_name, "import_test_pool");
        assert_eq!(imported.config.device_count, 1);
        assert!(imported.stats.superblock_verified);
        assert!(!imported.stats.read_only);
    }

    /// Valid label with read-only → import succeeds, read_only flag set.
    #[test]
    fn try_import_pool_read_only_flag_passed_through() {
        let dir = tempfile::tempdir().unwrap();
        let lock_dir = lock_dir_for(&dir);
        let dev_path = dir.path().join("device0");
        write_test_label(&dev_path, "ro_test_pool");

        let result = try_import_pool(dir.path(), &lock_dir, true, None).unwrap();
        assert!(result.is_some());
        let imported = result.unwrap();
        assert!(imported.stats.read_only);
    }

    /// Corrupt device file (magic bytes but no valid label) →
    /// import fails with an error.
    #[test]
    fn try_import_pool_corrupt_label_fails() {
        let dir = tempfile::tempdir().unwrap();
        let lock_dir = lock_dir_for(&dir);
        let dev_path = dir.path().join("device0");
        // Write magic bytes but no valid label structure beyond that.
        let mut buf = vec![0u8; 512];
        buf[..4].copy_from_slice(&tidefs_types_pool_label_core::POOL_LABEL_MAGIC);
        std::fs::write(&dev_path, &buf).unwrap();

        let result = try_import_pool(dir.path(), &lock_dir, false, None);
        assert!(result.is_err(), "corrupt label should fail import");
    }

    /// Nonexistent directory → find_device_files returns empty, import
    /// skipped (does not panic).
    #[test]
    fn try_import_pool_nonexistent_dir_skips() {
        let lock_dir = tempfile::tempdir().unwrap();
        let result = try_import_pool(
            std::path::Path::new("/tmp/tidefs_nonexistent_test_dir_12345"),
            lock_dir.path(),
            false,
            None,
        )
        .unwrap();
        assert!(result.is_none());
    }

    // ── hex_uuid tests ─────────────────────────────────────────────

    #[test]
    fn hex_uuid_format() {
        let uuid = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        assert_eq!(hex_uuid(&uuid), "00112233445566778899aabbccddeeff");
    }

    // -- export-reimport round-trip test --

    /// Create a pool, import, export, re-import, and verify identity preserved.
    #[test]
    fn export_reimport_preserves_pool_identity() {
        let dir = tempfile::tempdir().unwrap();
        let dev_path = dir.path().join("device0");
        write_test_label(&dev_path, "roundtrip_pool");
        let lock_dir = lock_dir_for(&dir);

        // First import.
        let imported1 = try_import_pool(dir.path(), &lock_dir, false, None)
            .unwrap()
            .expect("first import should succeed");
        assert_eq!(imported1.config.pool_name, "roundtrip_pool");
        let guid1 = imported1.config.pool_uuid;
        let dev_count1 = imported1.config.device_count;

        // Export the pool.
        tidefs_pool_import::pool_export(&[dev_path.clone()], &lock_dir, false)
            .expect("export should succeed");

        // Verify the label shows Exported.
        let mut f = std::fs::File::open(&dev_path).unwrap();
        let mut buf = vec![0u8; tidefs_types_pool_label_core::POOL_LABEL_SIZE];
        std::io::Read::read_exact(&mut f, &mut buf).unwrap();
        let label = tidefs_types_pool_label_core::decode_label(&buf).unwrap();
        assert_eq!(
            label.pool_state,
            tidefs_types_pool_label_core::PoolState::Exported,
            "label should be Exported after export"
        );

        // Re-import.
        let imported2 = try_import_pool(dir.path(), &lock_dir, false, None)
            .unwrap()
            .expect("re-import should succeed");
        assert_eq!(imported2.config.pool_uuid, guid1, "pool UUID preserved");
        assert_eq!(
            imported2.config.device_count, dev_count1,
            "device count preserved"
        );
        assert_eq!(
            imported2.config.pool_name, "roundtrip_pool",
            "pool name preserved"
        );
        // Verify the on-disk label was activated (import writes Active).
        let mut f = std::fs::File::open(&dev_path).unwrap();
        let mut buf = vec![0u8; tidefs_types_pool_label_core::POOL_LABEL_SIZE];
        std::io::Read::read_exact(&mut f, &mut buf).unwrap();
        let label = tidefs_types_pool_label_core::decode_label(&buf).unwrap();
        assert_eq!(
            label.pool_state,
            tidefs_types_pool_label_core::PoolState::Active,
            "on-disk label should be Active after re-import"
        );
    }

    #[test]
    fn hex_uuid_all_zeros() {
        assert_eq!(hex_uuid(&[0u8; 16]), "00000000000000000000000000000000");
    }

    // ── Encryption passphrase verification tests ───────────────────

    /// Full product-path integration: seal DEK in keystore, verify passphrase,
    /// rotate key, verify new passphrase, reject wrong passphrase.

    #[test]

    fn encryption_passphrase_verify_seal_then_rotate() {
        use tidefs_encryption::key_hierarchy::{DatasetDEK, PoolWrappingKey};

        use tidefs_encryption::key_manager::{KeyManager, KeyRotation, KeyStore};

        use tidefs_local_object_store::StoreOptions;

        let dir = tempfile::TempDir::new().unwrap();

        let pool_path = dir.path();

        // Phase 1: Create keystore and seal a DEK.

        let old_salt = PoolWrappingKey::generate_salt();

        let old_wk = PoolWrappingKey::derive("initial passphrase", &old_salt).unwrap();

        let dek = DatasetDEK::generate();

        let sealed = KeyManager::seal_dek(&dek, &old_wk, "mydataset", 1).unwrap();

        let old_salt_hex: String = old_salt.iter().map(|b| format!("{b:02x}")).collect();

        {
            let store_opts = StoreOptions::test_fast();

            let mut ks = KeyStore::open_with_options(pool_path, store_opts, old_salt).unwrap();

            ks.store_sealed_dek(&sealed).unwrap();
        }

        // Phase 2: Verify passphrase pre-mount check.

        let result = verify_encryption_passphrase(pool_path, "initial passphrase", &old_salt_hex);

        assert!(
            result.is_ok(),
            "correct passphrase should verify: {:?}",
            result.err()
        );

        assert_eq!(result.unwrap(), 1);

        // Phase 3: Wrong passphrase fails pre-mount check.

        let bad_result = verify_encryption_passphrase(pool_path, "wrong passphrase", &old_salt_hex);

        assert!(
            bad_result.is_err(),
            "wrong passphrase should fail verification"
        );

        // Phase 4: Rotate the key.

        let new_salt = PoolWrappingKey::generate_salt();

        let new_salt_hex: String = new_salt.iter().map(|b| format!("{b:02x}")).collect();

        {
            let store_opts = StoreOptions::test_fast();

            let mut ks = KeyStore::open_with_options(pool_path, store_opts, old_salt).unwrap();

            KeyRotation::rekey_wrapping_key(
                "initial passphrase",
                "rotated passphrase",
                &new_salt,
                &mut ks,
            )
            .unwrap();
        }

        // Phase 5: Old passphrase now fails verification.

        let old_result =
            verify_encryption_passphrase(pool_path, "initial passphrase", &old_salt_hex);

        assert!(
            old_result.is_err(),
            "old passphrase should fail after rotation"
        );

        // Phase 6: New passphrase (with new salt) passes verification.

        let new_result =
            verify_encryption_passphrase(pool_path, "rotated passphrase", &new_salt_hex);

        assert!(
            new_result.is_ok(),
            "new passphrase should verify after rotation: {:?}",
            new_result.err()
        );

        assert_eq!(new_result.unwrap(), 1);
    }

    /// Empty keystore: passphrase verification returns Ok(0).

    #[test]

    fn encryption_passphrase_verify_empty_keystore() {
        use tidefs_encryption::key_hierarchy::PoolWrappingKey;

        use tidefs_local_object_store::StoreOptions;

        let dir = tempfile::TempDir::new().unwrap();

        let pool_path = dir.path();

        let salt = PoolWrappingKey::generate_salt();

        let salt_hex: String = salt.iter().map(|b| format!("{b:02x}")).collect();

        // Create an empty keystore (no datasets sealed).

        {
            let store_opts = StoreOptions::test_fast();

            let _ks = tidefs_encryption::key_manager::KeyStore::open_with_options(
                pool_path, store_opts, salt,
            )
            .unwrap();
        }

        let result = verify_encryption_passphrase(pool_path, "any passphrase", &salt_hex);

        assert!(result.is_ok());

        assert_eq!(
            result.unwrap(),
            0,
            "empty keystore should return 0 datasets"
        );
    }

    /// hex_decode_salt roundtrip.

    #[test]

    fn hex_decode_salt_roundtrip() {
        use tidefs_encryption::key_hierarchy::PoolWrappingKey;

        let salt = PoolWrappingKey::generate_salt();

        let hex: String = salt.iter().map(|b| format!("{b:02x}")).collect();

        let decoded = hex_decode_salt(&hex).unwrap();

        assert_eq!(salt, decoded);
    }

    /// hex_decode_salt rejects bad input.

    #[test]

    fn hex_decode_salt_rejects_bad_input() {
        assert!(hex_decode_salt("").is_err());

        assert!(hex_decode_salt("too-short").is_err());

        assert!(hex_decode_salt(&"g".repeat(32)).is_err());

        assert!(hex_decode_salt(&"a".repeat(33)).is_err());
    }
}
