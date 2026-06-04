#![allow(dead_code, unused)]
//! Pool mount subcommand: import a pool and launch the FUSE daemon.
//!
//! Wires CLI arguments to tidefs-pool-import and the POSIX filesystem
//! adapter daemon so the operator can go from mkfs to mounted filesystem
//! in a single command.

use std::path::PathBuf;
use std::process;

use clap::Args;
use std::net::SocketAddr;
use tidefs_cluster::pool_lease_token::PoolLeaseToken;
use tidefs_cluster::pool_protocol::{ClusterPoolLeaseRequest, ClusterPoolMessage};
use tidefs_encryption;
use tidefs_local_filesystem::RootAuthenticationKey;
use tidefs_transport::{NodeInfo, Transport, TransportAddr};
use tidefs_types_pool_label_core::features;

/// `pool mount [<pool_name>] <mount_point> [--devices <dev>...] [--read-only] [--relatime]`
///
/// When `--devices` is provided, the pool is imported from the raw block
/// devices.  When `--devices` is absent, `pool_name` is resolved as a
/// backing-directory path (compatibility mode for directory-backed pools).
#[derive(Args, Debug)]
pub struct PoolMountArgs {
    /// Pool name (optional when --devices is used; resolved as
    /// backing-directory path when --devices is absent)
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

    /// Request cluster-authoritative mount. When set, the pool must have
    /// CLUSTER_POOL_INCOMPAT labels and the mount must go through cluster
    /// authority instead of a local backing-directory path.
    #[arg(long = "cluster", default_value_t = false)]
    pub cluster: bool,

    /// Cluster storage-node address for lease acquisition and authority.
    /// Required when --cluster is set. Format: host:port.
    #[arg(long = "cluster-node-addr")]
    pub cluster_node_addr: Option<String>,

    /// Node identifier for this cluster client (nonzero).
    /// Required when --cluster is set.
    #[arg(long = "cluster-node-id")]
    pub cluster_node_id: Option<u64>,
}

/// Resolve a pool name to a backing-directory path.
///
/// For local filesystem pools the pool name is the path to the
/// backing store directory.  Future multi-node pools will use a
/// pool registry.
fn resolve_backing_dir(pool_name: &str) -> PathBuf {
    PathBuf::from(pool_name)
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
        let root_auth_key = tidefs_local_filesystem::RootAuthenticationKey::from_environment()
            .unwrap_or_else(|_| tidefs_local_filesystem::RootAuthenticationKey::demo_key());
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

/// Handle `tidefsctl pool mount`.
///
/// 1. Resolve pool_name → backing directory.
/// 2. Scan backing directory for device-label files; if found, run
///    pool-import for integrity verification and intent-log replay.
/// 3. Launch the FUSE daemon on the backing directory.
pub fn handle_mount(args: PoolMountArgs) {
    let mountpoint = args.mount_point.clone();
    let lock_dir = std::path::PathBuf::from("/run/tidefs/import");

    // Cluster mount parameter validation: when --cluster is set,
    // refuse missing or invalid parameters before any pool work.
    if args.cluster {
        if args.cluster_node_addr.is_none() {
            eprintln!("tidefsctl pool mount: --cluster requires --cluster-node-addr");
            process::exit(1);
        }
        if args.cluster_node_id.is_none() || args.cluster_node_id.unwrap() == 0 {
            eprintln!("tidefsctl pool mount: --cluster requires --cluster-node-id (nonzero)");
            process::exit(1);
        }
    }

    // Determine the backing directory: --devices path or pool_name-as-directory.
    let backing_dir = if let Some(ref devices) = args.devices {
        // Block-device path: import from raw devices, then use a
        // runtime-managed backing directory keyed by pool UUID.
        // Resolve encryption key before import for label validation + fingerprint.
        let (import_encryption_key, encryption_config) =
            resolve_encryption_for_import(&args.encryption_envelope);
        let imported = match tidefs_pool_import::pool_import(
            devices,
            &lock_dir,
            args.read_only,
            import_encryption_key,
            None,
        ) {
            Ok(imp) => imp,
            Err(err) => {
                eprintln!("tidefsctl pool mount: pool import failed: {err}");
                process::exit(1);
            }
        };
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
        check_encryption_consistency(cfg, &args.encryption_envelope);

        // Use a runtime directory keyed by pool UUID as the backing store.
        let pool_dir = std::path::PathBuf::from("/run/tidefs/pools").join(hex_uuid(&cfg.pool_uuid));
        std::fs::create_dir_all(&pool_dir).unwrap_or_else(|e| {
            eprintln!("tidefsctl pool mount: cannot create pool runtime dir: {e}");
            process::exit(1);
        });
        pool_dir
    } else {
        // Compatibility mode: pool name as backing-directory path.
        let dir = resolve_backing_dir(&args.pool_name);
        // Resolve encryption before import.
        let (import_enc_key, encryption_config) =
            resolve_encryption_for_import(&args.encryption_envelope);
        match try_import_pool(&dir, &lock_dir, args.read_only, import_enc_key) {
            Ok(Some(imported)) => {
                let cfg = &imported.config;
                let stats = &imported.stats;
                println!("pool \"{}\" imported", cfg.pool_name);
                println!("  pool uuid:   {}", hex_uuid(&cfg.pool_uuid));
                println!("  state:       {}", cfg.state);
                println!("  devices:     {}", cfg.device_count);
                println!("  import time: {} ms", stats.import_time_ms);
                if stats.encrypted {
                    println!("  encrypted:   yes");
                }
                if stats.read_only {
                    println!("  read-only:   yes");
                }
                check_encryption_consistency(cfg, &args.encryption_envelope);
            }
            Ok(None) => {
                println!(
                    "pool \"{}\": no device labels found in {} -- skipping import",
                    args.pool_name,
                    dir.display(),
                );
            }
            Err(err) => {
                eprintln!("tidefsctl pool mount: pool import failed: {err}");
                process::exit(1);
            }
        }
        dir
    };

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
    let encryption_config = if let Some(ref envelope_path) = args.encryption_envelope {
        // Resolve root auth key for envelope unwrapping.
        let root_auth_key = tidefs_local_filesystem::RootAuthenticationKey::from_environment()
            .unwrap_or_else(|_| tidefs_local_filesystem::RootAuthenticationKey::demo_key());
        match tidefs_posix_filesystem_adapter_daemon::resolve_encryption_key_from_envelope(
            envelope_path,
            &root_auth_key,
        ) {
            Some(config) => Some(config),
            None => {
                eprintln!(
                    "tidefsctl pool mount: failed to unseal encryption envelope {}",
                    envelope_path.display()
                );
                eprintln!(
                    "tidefsctl pool mount: wrong root auth key, corrupt envelope, or tampered file"
                );
                process::exit(1);
            }
        }
    } else {
        None
    };

    // Cluster label validation and lease acquisition.
    let cluster_lease_token_bytes: Option<Vec<u8>> = if args.cluster {
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

        let node_addr = args.cluster_node_addr.as_ref().unwrap();
        let node_id = args.cluster_node_id.unwrap();

        println!(
            "cluster: requesting pool lease from {} for pool {:02x?}...",
            node_addr,
            &pool_guid[..4]
        );

        // Acquire lease through a transport session instead of raw TCP.
        // The raw-TCP ClusterLeaseClient path is incompatible with the
        // server's transport handshake. Using a proper transport session
        // ensures the lease request reaches the CP01 dispatch handler.
        let addr: SocketAddr = node_addr.parse().unwrap_or_else(|e| {
            eprintln!(
                "tidefsctl pool mount: invalid cluster-node-addr '{}': {e}",
                node_addr
            );
            process::exit(1);
        });
        let operator_client_id = node_id.wrapping_add(10_000);
        let mut transport = Transport::new(operator_client_id);
        transport.add_node(NodeInfo::new(node_id, vec![TransportAddr::Tcp(addr)], 0));
        let sid = transport.connect(node_id).unwrap_or_else(|e| {
            eprintln!(
                "tidefsctl pool mount: connect to cluster node {}: {e:?}",
                node_addr
            );
            process::exit(1);
        });
        transport.perform_handshake(sid).unwrap_or_else(|e| {
            eprintln!(
                "tidefsctl pool mount: handshake with cluster node {}: {e:?}",
                node_addr
            );
            process::exit(1);
        });

        // Build and send CP01-framed LeaseRequest.
        let lease_req = ClusterPoolMessage::LeaseRequest(ClusterPoolLeaseRequest {
            request_id: 1,
            pool_guid,
            requesting_node_id: operator_client_id,
        });
        let req_encoded = lease_req.encode().unwrap_or_else(|e| {
            eprintln!("tidefsctl pool mount: encode lease request: {e:?}");
            process::exit(1);
        });
        let mut wire = Vec::with_capacity(4 + req_encoded.len());
        wire.extend_from_slice(b"CP01");
        wire.extend_from_slice(&req_encoded);
        transport.send_message(sid, &wire).unwrap_or_else(|e| {
            eprintln!("tidefsctl pool mount: send lease request: {e:?}");
            process::exit(1);
        });

        // Receive and decode CP01-framed LeaseResponse.
        let raw = loop {
            match transport.recv_message(sid) {
                Ok(r) => break r,
                Err(tidefs_transport::TransportError::WouldBlock(_)) => {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    continue;
                }
                Err(e) => {
                    eprintln!("tidefsctl pool mount: recv lease response: {e:?}");
                    process::exit(1);
                }
            }
        };
        if raw.len() < 4 || &raw[..4] != b"CP01" {
            eprintln!("tidefsctl pool mount: invalid lease response framing");
            process::exit(1);
        }
        let resp = ClusterPoolMessage::decode(&raw[4..]).unwrap_or_else(|e| {
            eprintln!("tidefsctl pool mount: decode lease response: {e:?}");
            process::exit(1);
        });
        let token: PoolLeaseToken = match resp {
            ClusterPoolMessage::LeaseResponse(lease_resp) => {
                if !lease_resp.success {
                    eprintln!(
                        "tidefsctl pool mount: lease refused: {:?}",
                        lease_resp.error
                    );
                    process::exit(1);
                }
                let token_bytes = lease_resp.lease_token_bytes.unwrap_or_else(|| {
                    eprintln!("tidefsctl pool mount: lease granted but no token bytes");
                    process::exit(1);
                });
                bincode::deserialize(&token_bytes).unwrap_or_else(|e| {
                    eprintln!("tidefsctl pool mount: deserialize lease token: {e}");
                    process::exit(1);
                })
            }
            other => {
                eprintln!("tidefsctl pool mount: unexpected lease response: {other:?}");
                process::exit(1);
            }
        };

        println!(
            "cluster: lease granted (node={}, epoch={}, lease_id={}, expires_ms={})",
            token.node_id, token.epoch.0, token.lease_id, token.expiration_deadline_ms
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
        ) {
            Ok(candidate) => {
                println!(
                    "cluster: pool import authorized (pool={}, devices={})",
                    candidate.pool_name,
                    candidate.devices.len()
                );
            }
            Err(e) => {
                eprintln!("tidefsctl pool mount: cluster pool import validation failed: {e}");
                eprintln!(
                    "tidefsctl pool mount: the lease token may not authorize this pool,                              or the pool labels may be stale"
                );
                process::exit(1);
            }
        }

        let token_bytes = bincode::serialize(&token).unwrap_or_default();
        if token_bytes.is_empty() {
            eprintln!("tidefsctl pool mount: failed to serialize lease token");
            process::exit(1);
        }
        Some(token_bytes)
    } else {
        None
    };

    let config = tidefs_posix_filesystem_adapter_daemon::MountConfig {
        backing_dir,
        mountpoint,
        foreground: true,
        debug: false,
        writeback_cache: false,
        coherency_profile:
            tidefs_posix_filesystem_adapter_daemon::coherency_profile::CoherencyProfile::Writeback,
        block_devices: args.devices.clone(),
        dataset_path: Some(args.dataset.clone()),
        encryption: encryption_config,
        cluster_authorized: args.cluster,
        cluster_lease_token_bytes,
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
    fn mount_args_bind_expected_fields() {
        let args = PoolMountArgs {
            dataset: "root".into(),
            encryption_envelope: None,
            encryption_passphrase: None,
            encryption_salt: None,
            cluster: false,
            cluster_node_addr: None,
            cluster_node_id: None,
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
            dataset: "root".into(),
            cluster: false,
            cluster_node_addr: None,
            cluster_node_id: None,
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
            cluster: false,
            cluster_node_addr: None,
            cluster_node_id: None,
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
            cluster: false,
            cluster_node_addr: None,
            cluster_node_id: None,
        };
        assert_eq!(args.pool_name, "full");
        assert_eq!(args.mount_point, PathBuf::from("/mnt/full"));
        assert!(args.read_only);
        assert!(args.relatime);
    }

    // ── resolve_backing_dir tests ──────────────────────────────────

    #[test]
    fn resolve_backing_dir_uses_pool_name() {
        let dir = resolve_backing_dir("/tmp/mypool");
        assert_eq!(dir, PathBuf::from("/tmp/mypool"));
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
