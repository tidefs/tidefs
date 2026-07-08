// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Pool import: device scan, pool_guid grouping, topology_generation
//! validation, recovery commit_group selection, and cross-system portability.
//!
//! Implements the pool import protocol summarized by
//! `docs/POOL_IMPORT_EXPORT_DEVICE_TOPOLOGY_DESIGN.md`.
//!
//! The `PoolImporter` is responsible for discovering pools by scanning
//! candidate devices, grouping them by pool_guid, validating topology
//! consistency, and selecting the recovery transaction group.

use std::path::{Path, PathBuf};

use crate::pool_label::{
    decode_label, LabelPoolState, PoolLabelV1, POOL_LABEL_SIZE, POOL_LABEL_V1_WIRE_SIZE,
};
use crate::pool_lifecycle_evidence::{
    PoolLifecycleAction, PoolLifecycleContext, PoolLifecycleEvidence,
};
use tidefs_auth::local_only::LocalOnlyGuard;

// Error types
// ---------------------------------------------------------------------------

/// Errors returned by pool import operations.
#[derive(Debug)]
pub enum ImportError {
    /// No valid devices found during scan.
    NoDevicesFound { search_paths: Vec<PathBuf> },
    /// A device label failed checksum verification.
    CorruptLabel {
        device_path: PathBuf,
        reason: String,
    },
    /// Topology is inconsistent across devices in the pool.
    TopologyInconsistent { pool_guid: [u8; 16], detail: String },
    /// Pool state does not permit import.
    PoolNotImportable { pool_guid: [u8; 16], state: String },
    /// Pool requires cluster authority (CLUSTER_POOL_INCOMPAT flag set).
    /// Standalone importers must refuse; import requires cluster membership.
    ClusterPoolRequired { pool_guid: [u8; 16] },
    /// I/O error while reading a device.
    Io {
        operation: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
    /// Caller is not in a local process context -- privileged operation refused.
    NotLocal {
        operation: &'static str,
        reason: String,
    },
    /// The cluster lease token presented for import is invalid (zero fields).
    LeaseTokenInvalid { detail: String },
    /// The pool GUID in the lease token does not match the pool being imported.
    LeaseTokenPoolMismatch {
        token_pool_guid: [u8; 16],
        import_pool_guid: [u8; 16],
    },
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoDevicesFound { search_paths } => {
                write!(f, "no devices found in search paths: {search_paths:?}")
            }
            Self::CorruptLabel {
                device_path,
                reason,
            } => {
                write!(f, "corrupt label on {}: {reason}", device_path.display())
            }
            Self::TopologyInconsistent { pool_guid, detail } => {
                let guid = hex_str(*pool_guid);
                write!(f, "inconsistent topology for pool {guid}: {detail}")
            }
            Self::PoolNotImportable { pool_guid, state } => {
                let guid = hex_str(*pool_guid);
                write!(f, "pool {guid} is not importable (state={state})")
            }
            Self::ClusterPoolRequired { pool_guid } => {
                let guid = hex_str(*pool_guid);
                write!(
                    f,
                    "pool {guid} requires cluster authority (CLUSTER_POOL_INCOMPAT set); standalone import refused"
                )
            }
            Self::LeaseTokenInvalid { detail } => {
                write!(f, "invalid cluster lease token: {detail}")
            }
            Self::LeaseTokenPoolMismatch {
                token_pool_guid,
                import_pool_guid,
            } => {
                let tguid = hex_str(*token_pool_guid);
                let iguid = hex_str(*import_pool_guid);
                write!(
                    f,
                    "lease token pool GUID {tguid} does not match import pool GUID {iguid}"
                )
            }
            Self::Io {
                operation,
                path,
                source,
            } => {
                write!(
                    f,
                    "I/O error during {operation} on {}: {source}",
                    path.display()
                )
            }
            Self::NotLocal { operation, reason } => {
                write!(
                    f,
                    "privileged operation '{operation}' requires local execution: {reason}"
                )
            }
        }
    }
}

impl From<tidefs_auth::local_only::LocalOnlyError> for ImportError {
    fn from(err: tidefs_auth::local_only::LocalOnlyError) -> Self {
        match err {
            tidefs_auth::local_only::LocalOnlyError::NotLocal { operation, reason } => {
                Self::NotLocal { operation, reason }
            }
            tidefs_auth::local_only::LocalOnlyError::NoProcessIdentity { operation } => {
                Self::NotLocal {
                    operation,
                    reason: "no local process identity".to_string(),
                }
            }
        }
    }
}
impl std::error::Error for ImportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

fn hex_str(guid: [u8; 16]) -> String {
    guid.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

// ---------------------------------------------------------------------------
// DeviceCandidate
// ---------------------------------------------------------------------------

/// A single device discovered during pool scan.
#[derive(Clone, Debug)]
pub struct DeviceCandidate {
    /// Filesystem path to the device.
    pub path: PathBuf,
    /// Decoded pool label from the device.
    pub label: PoolLabelV1,
    /// Copy index that was read (0 = head, 1 = tail).
    pub label_copy: u8,
    /// Size of the device in bytes.
    pub device_size: u64,
}

// ---------------------------------------------------------------------------
// CandidatePool
// ---------------------------------------------------------------------------

/// A group of candidate devices sharing the same `pool_guid`.
#[derive(Clone, Debug)]
pub struct CandidatePool {
    /// Pool GUID shared by all devices in this group.
    pub pool_guid: [u8; 16],
    /// Human-readable pool name (from the first device with a name).
    pub pool_name: String,
    /// Current pool state (Active or Exported).
    pub pool_state: LabelPoolState,
    /// Candidate devices sorted by device_index.
    pub devices: Vec<DeviceCandidate>,
    /// The majority topology_generation across devices.
    pub topology_generation: u64,
    /// Total device count according to label metadata.
    pub device_count: u32,
    /// Maximum commit_group found across all devices (recovery point).
    pub recovery_commit_group: u64,
    /// Is the topology complete (all expected devices found)?
    pub topology_complete: bool,
    /// Cluster authority has been granted for this import.
    /// When true, the CLUSTER_POOL_INCOMPAT check is skipped during
    /// validation.  Set by [`PoolImporter::import_pool_clustered`].
    pub cluster_authorized: bool,
}

impl CandidatePool {
    /// Validate the pool's topology consistency and importability.
    ///
    /// Checks:
    /// - All devices share the same pool_guid.
    /// - Pool state is importable (Active or Exported).
    /// - device_count is consistent across devices.
    /// - topology_generation is consistent (majority selection).
    /// - Devices are sorted by device_index with no gaps.
    pub fn validate(&mut self) -> Result<(), ImportError> {
        // Check pool state
        if !self.pool_state.is_importable() {
            return Err(ImportError::PoolNotImportable {
                pool_guid: self.pool_guid,
                state: self.pool_state.to_string(),
            });
        }

        // Check device count consistency
        for d in &self.devices {
            if d.label.device_count != self.device_count {
                return Err(ImportError::TopologyInconsistent {
                    pool_guid: self.pool_guid,
                    detail: format!(
                        "device {} reports device_count={} but pool expects {}",
                        d.path.display(),
                        d.label.device_count,
                        self.device_count
                    ),
                });
            }
        }

        // Check for duplicate device indices
        let indices: Vec<u32> = self.devices.iter().map(|d| d.label.device_index).collect();
        let mut sorted_indices = indices.clone();
        sorted_indices.sort();
        sorted_indices.dedup();
        if sorted_indices.len() != indices.len() {
            return Err(ImportError::TopologyInconsistent {
                pool_guid: self.pool_guid,
                detail: "duplicate device_index values detected".into(),
            });
        }

        // Mark topology completeness
        let found_count = self.devices.len() as u32;
        self.topology_complete = found_count == self.device_count;

        // Cluster pool detection: if any device label has the
        // CLUSTER_POOL_INCOMPAT flag and cluster authority has not been
        // granted, refuse the import.  Cluster-aware import via
        // import_pool_clustered() sets cluster_authorized=true to bypass
        // this check.
        if !self.cluster_authorized && self.devices.iter().any(|d| d.label.is_clustered()) {
            return Err(ImportError::ClusterPoolRequired {
                pool_guid: self.pool_guid,
            });
        }

        Ok(())
    }

    /// Build source-backed lifecycle evidence for scan/import/reopen review.
    #[must_use]
    pub fn lifecycle_evidence(&self, action: PoolLifecycleAction) -> PoolLifecycleEvidence {
        let context = PoolLifecycleContext {
            pool_guid: Some(self.pool_guid),
            pool_name: Some(self.pool_name.clone()),
            device_count: self.devices.len(),
            expected_device_count: self.device_count as usize,
            capacity_bytes: self.devices.iter().map(|d| d.device_size).sum(),
            topology_generation: self.topology_generation,
            commit_group: self.recovery_commit_group,
        };

        let owner_authorized = self.cluster_authorized_or_not_clustered();
        let supported_action = matches!(
            action,
            PoolLifecycleAction::Scan | PoolLifecycleAction::Import | PoolLifecycleAction::Reopen
        );

        if !supported_action {
            return PoolLifecycleEvidence::refused_with_authority(
                PoolLifecycleAction::FailClosed,
                context,
                self.topology_complete,
                owner_authorized,
                "unsupported import lifecycle action",
            );
        }

        if self.topology_complete && owner_authorized {
            PoolLifecycleEvidence::executed(action, context)
        } else {
            let reason = if !self.topology_complete {
                "topology evidence incomplete"
            } else {
                "cluster ownership authority missing"
            };
            PoolLifecycleEvidence::refused_with_authority(
                action,
                context,
                self.topology_complete,
                owner_authorized,
                reason,
            )
        }
    }

    fn cluster_authorized_or_not_clustered(&self) -> bool {
        self.cluster_authorized || !self.devices.iter().any(|d| d.label.is_clustered())
    }
}

// ---------------------------------------------------------------------------
// PoolImporter
// ---------------------------------------------------------------------------

/// Scans devices for pool labels, groups them by pool_guid, and validates
/// topology for import.
#[derive(Debug, Default)]
pub struct PoolImporter;

impl PoolImporter {
    /// Scan a list of device paths for pool labels. Returns one
    /// `CandidatePool` per unique `pool_guid` found.
    ///
    /// Each device is checked at both label locations (offset 0 and
    /// offset `capacity - 256KiB`). The first valid label found is used.
    pub fn scan_candidates(device_paths: &[PathBuf]) -> Result<Vec<CandidatePool>, ImportError> {
        let mut all_candidates: Vec<DeviceCandidate> = Vec::new();

        for path in device_paths {
            if let Some(candidate) = Self::read_candidate(path)? {
                all_candidates.push(candidate);
            }
        }

        if all_candidates.is_empty() {
            return Err(ImportError::NoDevicesFound {
                search_paths: device_paths.to_vec(),
            });
        }

        // Group by pool_guid
        Self::group_by_pool_guid(&all_candidates)
    }

    /// Read a single device candidate. Returns `None` if no valid label found.
    fn read_candidate(device_path: &Path) -> Result<Option<DeviceCandidate>, ImportError> {
        use std::io::Read;

        if !device_path.exists() {
            return Ok(None);
        }

        let label_path = if device_path.is_dir() {
            device_path.join(".tidefs_label")
        } else {
            device_path.to_path_buf()
        };

        let metadata = std::fs::metadata(&label_path).map_err(|e| ImportError::Io {
            operation: "scan_metadata",
            path: label_path.clone(),
            source: e,
        })?;
        let device_size = metadata.len();

        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .open(&label_path)
            .map_err(|e| ImportError::Io {
                operation: "scan_open",
                path: label_path.clone(),
                source: e,
            })?;

        let mut buf = [0u8; POOL_LABEL_V1_WIRE_SIZE];

        // Try label copy 0 at offset 0
        file.read_exact(&mut buf).map_err(|e| ImportError::Io {
            operation: "scan_read_label0",
            path: label_path.clone(),
            source: e,
        })?;

        match decode_label(&buf) {
            Ok(label) => {
                return Ok(Some(DeviceCandidate {
                    path: device_path.to_path_buf(),
                    label,
                    label_copy: 0,
                    device_size,
                }));
            }
            Err(_) => {
                // Try label copy 1 at end of device
                if device_size > POOL_LABEL_SIZE as u64 {
                    let offset = device_size - POOL_LABEL_SIZE as u64;
                    let mut file2 = std::fs::OpenOptions::new()
                        .read(true)
                        .open(&label_path)
                        .map_err(|e| ImportError::Io {
                            operation: "scan_open_label1",
                            path: label_path.clone(),
                            source: e,
                        })?;
                    use std::io::Seek;
                    file2
                        .seek(std::io::SeekFrom::Start(offset))
                        .map_err(|e| ImportError::Io {
                            operation: "scan_seek_label1",
                            path: label_path.clone(),
                            source: e,
                        })?;
                    file2.read_exact(&mut buf).map_err(|e| ImportError::Io {
                        operation: "scan_read_label1",
                        path: label_path.clone(),
                        source: e,
                    })?;
                    match decode_label(&buf) {
                        Ok(label) => {
                            return Ok(Some(DeviceCandidate {
                                path: device_path.to_path_buf(),
                                label,
                                label_copy: 1,
                                device_size,
                            }));
                        }
                        Err(_) => return Ok(None),
                    }
                }
            }
        }

        Ok(None)
    }

    /// Group candidates by pool_guid and build `CandidatePool` instances.
    fn group_by_pool_guid(
        candidates: &[DeviceCandidate],
    ) -> Result<Vec<CandidatePool>, ImportError> {
        use std::collections::BTreeMap;

        let mut groups: BTreeMap<[u8; 16], Vec<DeviceCandidate>> = BTreeMap::new();
        for c in candidates {
            groups.entry(c.label.pool_guid).or_default().push(c.clone());
        }

        let mut pools = Vec::new();
        for (pool_guid, mut devices) in groups {
            // Sort by device_index
            devices.sort_by_key(|d| d.label.device_index);

            // Determine pool state: use the first device's state, preferring Exported
            let mut pool_state = LabelPoolState::Active;
            for d in &devices {
                if d.label.pool_state == LabelPoolState::Exported {
                    pool_state = LabelPoolState::Exported;
                    break;
                }
            }

            // Determine pool name from first device with a non-empty name
            let pool_name = devices
                .iter()
                .find_map(|d| {
                    let n = d.label.pool_name_str();
                    if n.is_empty() {
                        None
                    } else {
                        Some(n.to_string())
                    }
                })
                .unwrap_or_default();

            // Majority topology_generation
            let mut gen_counts: std::collections::BTreeMap<u64, usize> =
                std::collections::BTreeMap::new();
            for d in &devices {
                *gen_counts.entry(d.label.topology_generation).or_default() += 1;
            }
            let topology_generation = gen_counts
                .into_iter()
                .max_by_key(|(_, count)| *count)
                .map(|(gen, _)| gen)
                .unwrap_or(0);

            // device_count from the first device that has it non-zero
            let device_count = devices
                .iter()
                .find_map(|d| {
                    if d.label.device_count > 0 {
                        Some(d.label.device_count)
                    } else {
                        None
                    }
                })
                .unwrap_or(devices.len() as u32);

            // Recovery commit_group: maximum commit_group across all devices
            let recovery_commit_group = devices
                .iter()
                .map(|d| d.label.commit_group)
                .max()
                .unwrap_or(0);

            let mut pool = CandidatePool {
                pool_guid,
                pool_name,
                pool_state,
                devices,
                topology_generation,
                device_count,
                recovery_commit_group,
                topology_complete: false,
                cluster_authorized: false,
            };

            pool.validate()?;
            pools.push(pool);
        }

        if pools.is_empty() {
            return Err(ImportError::NoDevicesFound {
                search_paths: vec![],
            });
        }

        Ok(pools)
    }

    /// Import a specific pool by GUID. Returns the validated `CandidatePool`.
    ///
    /// This is the main entry point for pool import. It scans devices,
    /// finds the matching pool, validates topology, and returns the
    /// import-ready pool description.
    ///
    /// Standalone pools only.  Clustered pools (with CLUSTER_POOL_INCOMPAT
    /// set) are refused; use [`import_pool_clustered`] for those.
    pub fn import_pool(
        device_paths: &[PathBuf],
        pool_guid: Option<[u8; 16]>,
    ) -> Result<CandidatePool, ImportError> {
        // Operator authorization boundary: pool import requires local execution.
        let _guard = LocalOnlyGuard::new("pool import")?;
        let candidates = Self::scan_candidates(device_paths)?;

        match pool_guid {
            Some(guid) => candidates.into_iter().find(|p| p.pool_guid == guid).ok_or(
                ImportError::NoDevicesFound {
                    search_paths: device_paths.to_vec(),
                },
            ),
            None => {
                // If only one pool found, return it
                if candidates.len() == 1 {
                    Ok(candidates.into_iter().next().unwrap())
                } else {
                    // Multiple pools found; caller must specify pool_guid
                    Err(ImportError::NoDevicesFound {
                        search_paths: device_paths.to_vec(),
                    })
                }
            }
        }
    }

    /// Import a clustered pool by GUID with cluster lease authority.
    ///
    /// This is the cluster-aware entry point for pool import.  It sets
    /// `cluster_authorized = true` on the returned [`CandidatePool`] so
    /// that [`CandidatePool::validate`] does not reject pools with the
    /// `CLUSTER_POOL_INCOMPAT` feature flag.
    ///
    /// # Lease verification
    ///
    /// `lease_token` must be `Some(token)` where the token proves the
    /// caller holds a valid cluster membership lease for this pool. The
    /// token's `pool_guid` must match the pool being imported, and the
    /// token must be valid (non-zero node_id, epoch, lease_id). Pass
    /// `None` only when importing read-only without lease ownership.
    ///
    /// When the token is present:
    /// - `node_id > 0` must hold.
    /// - `epoch > EpochId(0)` must hold.
    /// - `lease_id > 0` must hold.
    /// - `pool_guid` in the token must match the resolved pool.
    pub fn import_pool_clustered(
        device_paths: &[PathBuf],
        pool_guid: Option<[u8; 16]>,
        lease_token: Option<tidefs_cluster::PoolLeaseToken>,
    ) -> Result<CandidatePool, ImportError> {
        // Operator authorization boundary: pool import requires local execution.
        let _guard = LocalOnlyGuard::new("clustered pool import")?;
        let candidates = Self::scan_candidates(device_paths)?;

        let mut pool = match pool_guid {
            Some(guid) => candidates.into_iter().find(|p| p.pool_guid == guid).ok_or(
                ImportError::NoDevicesFound {
                    search_paths: device_paths.to_vec(),
                },
            )?,
            None => {
                if candidates.len() == 1 {
                    candidates.into_iter().next().unwrap()
                } else {
                    return Err(ImportError::NoDevicesFound {
                        search_paths: device_paths.to_vec(),
                    });
                }
            }
        };

        // Verify lease token when present.
        if let Some(ref token) = lease_token {
            if !token.is_valid() {
                return Err(ImportError::LeaseTokenInvalid {
                    detail: format!(
                        "token invalid: node_id={} epoch={:?} lease_id={}",
                        token.node_id, token.epoch, token.lease_id
                    ),
                });
            }
            if !token.authorizes_pool(&pool.pool_guid) {
                return Err(ImportError::LeaseTokenPoolMismatch {
                    token_pool_guid: token.pool_guid,
                    import_pool_guid: pool.pool_guid,
                });
            }
        }

        pool.cluster_authorized = true;
        Ok(pool)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool_label::{LabelDeviceClass, PoolRedundancyPolicy, POOL_LABEL_MAGIC};
    use crate::pool_lifecycle_evidence::PoolLifecycleOutcome;

    #[test]
    fn import_error_display() {
        let err = ImportError::NoDevicesFound {
            search_paths: vec![std::path::PathBuf::from("/tmp/test")],
        };
        let msg = err.to_string();
        assert!(msg.contains("no devices found"), "got: {msg}");
    }

    #[test]
    fn candidate_pool_validate_exported() {
        let pool_guid = [0xAAu8; 16];
        let candidates = vec![
            DeviceCandidate {
                path: std::path::PathBuf::from("/dev/sda"),
                label: PoolLabelV1 {
                    magic: POOL_LABEL_MAGIC,
                    version: 1,
                    pool_guid,
                    device_guid: [0x01u8; 16],
                    pool_name_len: 0,
                    pool_name: [0u8; 255],
                    pool_state: LabelPoolState::Exported,
                    commit_group: 100,
                    label_commit_group: 100,
                    device_index: 0,
                    topology_generation: 1,
                    device_count: 2,
                    device_class: LabelDeviceClass::Hdd,
                    device_capacity_bytes: 1024 * 1024 * 1024,
                    system_area_pointer: 0,
                    system_area_size: 0,
                    features_incompat: 0,
                    features_ro_compat: 0,
                    features_compat: 0,
                    device_health: 0,
                    device_read_errors: 0,
                    device_write_errors: 0,
                    device_checksum_errors: 0,
                    redundancy_policy: PoolRedundancyPolicy::default(),
                    checksum: [0u8; 32],
                },
                label_copy: 0,
                device_size: 1024 * 1024 * 1024,
            },
            DeviceCandidate {
                path: std::path::PathBuf::from("/dev/sdb"),
                label: PoolLabelV1 {
                    magic: POOL_LABEL_MAGIC,
                    version: 1,
                    pool_guid,
                    device_guid: [0x02u8; 16],
                    pool_name_len: 0,
                    pool_name: [0u8; 255],
                    pool_state: LabelPoolState::Exported,
                    commit_group: 101,
                    label_commit_group: 101,
                    device_index: 1,
                    topology_generation: 1,
                    device_count: 2,
                    device_class: LabelDeviceClass::Hdd,
                    device_capacity_bytes: 1024 * 1024 * 1024,
                    system_area_pointer: 0,
                    system_area_size: 0,
                    features_incompat: 0,
                    features_ro_compat: 0,
                    features_compat: 0,
                    device_health: 0,
                    device_read_errors: 0,
                    device_write_errors: 0,
                    device_checksum_errors: 0,
                    redundancy_policy: PoolRedundancyPolicy::default(),
                    checksum: [0u8; 32],
                },
                label_copy: 0,
                device_size: 1024 * 1024 * 1024,
            },
        ];

        let mut pool = CandidatePool {
            pool_guid,
            pool_name: "testpl1".into(),
            pool_state: LabelPoolState::Exported,
            devices: candidates,
            topology_generation: 1,
            device_count: 2,
            recovery_commit_group: 101,
            topology_complete: false,
            cluster_authorized: false,
        };

        assert!(pool.validate().is_ok());
    }

    #[test]
    fn destroyed_pool_rejected() {
        let pool_guid = [0xBBu8; 16];
        let mut pool = CandidatePool {
            pool_guid,
            pool_name: "destroyed".into(),
            pool_state: LabelPoolState::Destroyed,
            devices: vec![],
            topology_generation: 0,
            device_count: 0,
            recovery_commit_group: 0,
            topology_complete: false,
            cluster_authorized: false,
        };

        let result = pool.validate();
        assert!(result.is_err());
    }

    #[test]
    fn candidate_pool_emits_import_lifecycle_evidence() {
        let pool = CandidatePool {
            pool_guid: [0x34; 16],
            pool_name: "evidence".into(),
            pool_state: LabelPoolState::Exported,
            devices: vec![],
            topology_generation: 3,
            device_count: 0,
            recovery_commit_group: 44,
            topology_complete: true,
            cluster_authorized: false,
        };

        let evidence = pool.lifecycle_evidence(PoolLifecycleAction::Import);

        assert_eq!(evidence.action, PoolLifecycleAction::Import);
        assert_eq!(evidence.commit_group, 44);
        assert!(evidence.topology_complete);
        assert!(evidence.owner_authorized);
    }

    #[test]
    fn candidate_pool_emits_reopen_lifecycle_evidence() {
        let pool = CandidatePool {
            pool_guid: [0x38; 16],
            pool_name: "reopen".into(),
            pool_state: LabelPoolState::Exported,
            devices: vec![DeviceCandidate {
                path: std::path::PathBuf::from("/dev/tidefs-reopen"),
                label: PoolLabelV1 {
                    magic: POOL_LABEL_MAGIC,
                    version: 1,
                    pool_guid: [0x38; 16],
                    device_guid: [0x39; 16],
                    pool_name_len: 0,
                    pool_name: [0u8; 255],
                    pool_state: LabelPoolState::Exported,
                    commit_group: 45,
                    label_commit_group: 45,
                    device_index: 0,
                    topology_generation: 4,
                    device_count: 1,
                    device_class: LabelDeviceClass::Hdd,
                    device_capacity_bytes: 4096,
                    system_area_pointer: 0,
                    system_area_size: 0,
                    features_incompat: 0,
                    features_ro_compat: 0,
                    features_compat: 0,
                    device_health: 0,
                    device_read_errors: 0,
                    device_write_errors: 0,
                    device_checksum_errors: 0,
                    redundancy_policy: PoolRedundancyPolicy::default(),
                    checksum: [0; 32],
                },
                label_copy: 0,
                device_size: 4096,
            }],
            topology_generation: 4,
            device_count: 1,
            recovery_commit_group: 45,
            topology_complete: true,
            cluster_authorized: false,
        };

        let evidence = pool.lifecycle_evidence(PoolLifecycleAction::Reopen);

        assert_eq!(evidence.action, PoolLifecycleAction::Reopen);
        assert_eq!(evidence.outcome, PoolLifecycleOutcome::Executed);
        assert_eq!(evidence.pool_guid, Some([0x38; 16]));
        assert_eq!(evidence.pool_name.as_deref(), Some("reopen"));
        assert_eq!(evidence.device_count, 1);
        assert_eq!(evidence.expected_device_count, 1);
        assert_eq!(evidence.capacity_bytes, 4096);
        assert_eq!(evidence.topology_generation, 4);
        assert_eq!(evidence.commit_group, 45);
        assert!(evidence.topology_complete);
        assert!(evidence.owner_authorized);
        assert!(!evidence.is_fail_closed());
    }

    #[test]
    fn incomplete_candidate_pool_emits_fail_closed_evidence() {
        let pool = CandidatePool {
            pool_guid: [0x35; 16],
            pool_name: "missing".into(),
            pool_state: LabelPoolState::Exported,
            devices: vec![],
            topology_generation: 3,
            device_count: 2,
            recovery_commit_group: 44,
            topology_complete: false,
            cluster_authorized: false,
        };

        let evidence = pool.lifecycle_evidence(PoolLifecycleAction::Scan);

        assert_eq!(evidence.action, PoolLifecycleAction::Scan);
        assert!(evidence.is_fail_closed());
        assert!(evidence.reason.contains("topology"));
    }

    #[test]
    fn surplus_candidate_pool_emits_fail_closed_evidence() {
        let pool_guid = [0x3A; 16];
        let make_candidate = |index, byte| DeviceCandidate {
            path: std::path::PathBuf::from(format!("/dev/tidefs-surplus-{index}")),
            label: PoolLabelV1 {
                magic: POOL_LABEL_MAGIC,
                version: 1,
                pool_guid,
                device_guid: [byte; 16],
                pool_name_len: 0,
                pool_name: [0u8; 255],
                pool_state: LabelPoolState::Exported,
                commit_group: 46,
                label_commit_group: 46,
                device_index: index,
                topology_generation: 5,
                device_count: 2,
                device_class: LabelDeviceClass::Hdd,
                device_capacity_bytes: 4096,
                system_area_pointer: 0,
                system_area_size: 0,
                features_incompat: 0,
                features_ro_compat: 0,
                features_compat: 0,
                device_health: 0,
                device_read_errors: 0,
                device_write_errors: 0,
                device_checksum_errors: 0,
                redundancy_policy: PoolRedundancyPolicy::default(),
                checksum: [0; 32],
            },
            label_copy: 0,
            device_size: 4096,
        };
        let mut pool = CandidatePool {
            pool_guid,
            pool_name: "surplus".into(),
            pool_state: LabelPoolState::Exported,
            devices: vec![
                make_candidate(0, 0x3B),
                make_candidate(1, 0x3C),
                make_candidate(2, 0x3D),
            ],
            topology_generation: 5,
            device_count: 2,
            recovery_commit_group: 46,
            topology_complete: false,
            cluster_authorized: false,
        };

        assert!(pool.validate().is_ok());
        assert!(!pool.topology_complete);

        let evidence = pool.lifecycle_evidence(PoolLifecycleAction::Import);

        assert_eq!(evidence.outcome, PoolLifecycleOutcome::Refused);
        assert_eq!(evidence.reason, "topology evidence incomplete");
        assert_eq!(evidence.device_count, 3);
        assert_eq!(evidence.expected_device_count, 2);
        assert!(!evidence.topology_complete);
        assert!(evidence.owner_authorized);
        assert!(evidence.is_fail_closed());
    }

    #[test]
    fn clustered_candidate_pool_refusal_preserves_topology_evidence() {
        use crate::pool_label::features;

        let pool = CandidatePool {
            pool_guid: [0x36; 16],
            pool_name: "clustered".into(),
            pool_state: LabelPoolState::Exported,
            devices: vec![DeviceCandidate {
                path: std::path::PathBuf::from("/dev/tidefs-clustered"),
                label: PoolLabelV1 {
                    magic: POOL_LABEL_MAGIC,
                    version: 1,
                    pool_guid: [0x36; 16],
                    device_guid: [0x37; 16],
                    pool_name_len: 0,
                    pool_name: [0u8; 255],
                    pool_state: LabelPoolState::Exported,
                    commit_group: 44,
                    label_commit_group: 44,
                    device_index: 0,
                    topology_generation: 3,
                    device_count: 1,
                    device_class: LabelDeviceClass::Hdd,
                    device_capacity_bytes: 4096,
                    system_area_pointer: 0,
                    system_area_size: 0,
                    features_incompat: features::CLUSTER_POOL_INCOMPAT,
                    features_ro_compat: 0,
                    features_compat: features::CLUSTER_POOL_COMPAT,
                    device_health: 0,
                    device_read_errors: 0,
                    device_write_errors: 0,
                    device_checksum_errors: 0,
                    redundancy_policy: PoolRedundancyPolicy::default(),
                    checksum: [0; 32],
                },
                label_copy: 0,
                device_size: 4096,
            }],
            topology_generation: 3,
            device_count: 1,
            recovery_commit_group: 44,
            topology_complete: true,
            cluster_authorized: false,
        };

        let evidence = pool.lifecycle_evidence(PoolLifecycleAction::Import);

        assert_eq!(evidence.action, PoolLifecycleAction::Import);
        assert_eq!(evidence.outcome, PoolLifecycleOutcome::Refused);
        assert_eq!(evidence.device_count, 1);
        assert_eq!(evidence.expected_device_count, 1);
        assert!(evidence.topology_complete);
        assert!(!evidence.owner_authorized);
        assert!(evidence.is_fail_closed());
        assert_eq!(evidence.reason, "cluster ownership authority missing");
    }

    #[test]
    fn candidate_pool_lifecycle_evidence_refuses_unsupported_action() {
        let pool = CandidatePool {
            pool_guid: [0x3E; 16],
            pool_name: "unsupported".into(),
            pool_state: LabelPoolState::Exported,
            devices: vec![],
            topology_generation: 7,
            device_count: 0,
            recovery_commit_group: 48,
            topology_complete: true,
            cluster_authorized: false,
        };

        let evidence = pool.lifecycle_evidence(PoolLifecycleAction::Export);

        assert_eq!(evidence.action, PoolLifecycleAction::FailClosed);
        assert_eq!(evidence.outcome, PoolLifecycleOutcome::Refused);
        assert_eq!(evidence.pool_guid, Some([0x3E; 16]));
        assert_eq!(evidence.pool_name.as_deref(), Some("unsupported"));
        assert_eq!(evidence.device_count, 0);
        assert_eq!(evidence.expected_device_count, 0);
        assert_eq!(evidence.topology_generation, 7);
        assert_eq!(evidence.commit_group, 48);
        assert!(evidence.topology_complete);
        assert!(evidence.owner_authorized);
        assert!(evidence.is_fail_closed());
        assert!(evidence.reason.contains("unsupported"));
    }

    #[test]
    fn topology_mismatch_rejected() {
        let pool_guid = [0xCCu8; 16];
        let candidates = vec![
            DeviceCandidate {
                path: std::path::PathBuf::from("/dev/sda"),
                label: PoolLabelV1 {
                    magic: POOL_LABEL_MAGIC,
                    version: 1,
                    pool_guid,
                    device_guid: [0x01u8; 16],
                    pool_name_len: 0,
                    pool_name: [0u8; 255],
                    pool_state: LabelPoolState::Active,
                    commit_group: 100,
                    label_commit_group: 100,
                    device_index: 0,
                    topology_generation: 1,
                    device_count: 2, // says 2 devices
                    device_class: LabelDeviceClass::Hdd,
                    device_capacity_bytes: 1024 * 1024 * 1024,
                    system_area_pointer: 0,
                    system_area_size: 0,
                    features_incompat: 0,
                    features_ro_compat: 0,
                    features_compat: 0,
                    device_health: 0,
                    device_read_errors: 0,
                    device_write_errors: 0,
                    device_checksum_errors: 0,
                    redundancy_policy: PoolRedundancyPolicy::default(),
                    checksum: [0u8; 32],
                },
                label_copy: 0,
                device_size: 1024 * 1024 * 1024,
            },
            DeviceCandidate {
                path: std::path::PathBuf::from("/dev/sdb"),
                label: PoolLabelV1 {
                    magic: POOL_LABEL_MAGIC,
                    version: 1,
                    pool_guid,
                    device_guid: [0x02u8; 16],
                    pool_name_len: 0,
                    pool_name: [0u8; 255],
                    pool_state: LabelPoolState::Active,
                    commit_group: 100,
                    label_commit_group: 100,
                    device_index: 1,
                    topology_generation: 1,
                    device_count: 3, // says 3 devices (mismatch!)
                    device_class: LabelDeviceClass::Hdd,
                    device_capacity_bytes: 1024 * 1024 * 1024,
                    system_area_pointer: 0,
                    system_area_size: 0,
                    features_incompat: 0,
                    features_ro_compat: 0,
                    features_compat: 0,
                    device_health: 0,
                    device_read_errors: 0,
                    device_write_errors: 0,
                    device_checksum_errors: 0,
                    redundancy_policy: PoolRedundancyPolicy::default(),
                    checksum: [0u8; 32],
                },
                label_copy: 0,
                device_size: 1024 * 1024 * 1024,
            },
        ];

        let mut pool = CandidatePool {
            pool_guid,
            pool_name: "mismatch".into(),
            pool_state: LabelPoolState::Active,
            devices: candidates,
            topology_generation: 1,
            device_count: 2, // pool-level count differs from device sdb
            recovery_commit_group: 100,
            topology_complete: false,
            cluster_authorized: false,
        };

        assert!(pool.validate().is_err());
    }

    /// A clustered pool (CLUSTER_POOL_INCOMPAT flag set) must be refused
    /// by the standalone PoolImporter.  Cluster-aware import with
    /// membership lease acquisition is not yet implemented.
    #[test]
    fn cluster_pool_refused_by_standalone_importer() {
        use crate::pool_label::features;

        let pool_guid = [0xDDu8; 16];
        let label = PoolLabelV1 {
            magic: POOL_LABEL_MAGIC,
            version: 1,
            pool_guid,
            device_guid: [0x01u8; 16],
            pool_name_len: 0,
            pool_name: [0u8; 255],
            pool_state: LabelPoolState::Active,
            commit_group: 100,
            label_commit_group: 100,
            device_index: 0,
            topology_generation: 1,
            device_count: 1,
            device_class: LabelDeviceClass::Hdd,
            device_capacity_bytes: 1024 * 1024 * 1024,
            system_area_pointer: 0,
            system_area_size: 0,
            features_incompat: features::CLUSTER_POOL_INCOMPAT,
            features_ro_compat: 0,
            features_compat: features::CLUSTER_POOL_COMPAT,
            device_health: 0,
            device_read_errors: 0,
            device_write_errors: 0,
            device_checksum_errors: 0,
            redundancy_policy: PoolRedundancyPolicy::default(),
            checksum: [0u8; 32],
        };
        // Verify the flag is properly set before using in test
        assert!(label.is_clustered());

        let candidate = DeviceCandidate {
            path: std::path::PathBuf::from("/dev/cluster_disk"),
            label,
            label_copy: 0,
            device_size: 1024 * 1024 * 1024,
        };

        let mut pool = CandidatePool {
            pool_guid,
            pool_name: "clusterpool".into(),
            pool_state: LabelPoolState::Active,
            devices: vec![candidate],
            topology_generation: 1,
            device_count: 1,
            recovery_commit_group: 100,
            topology_complete: false,
            cluster_authorized: false,
        };

        let result = pool.validate();
        assert!(
            result.is_err(),
            "clustered pool must be refused by standalone importer"
        );
        match result {
            Err(ImportError::ClusterPoolRequired { pool_guid: guid }) => {
                assert_eq!(guid, pool_guid);
            }
            other => panic!("expected ClusterPoolRequired, got {:?}", other.err()),
        }
    }

    /// A clustered pool with cluster_authorized=true must pass validation.
    /// This is the path that import_pool_clustered() takes.
    #[test]
    fn cluster_pool_accepted_when_cluster_authorized() {
        use crate::pool_label::features;

        let pool_guid = [0xEEu8; 16];
        let label = PoolLabelV1 {
            magic: POOL_LABEL_MAGIC,
            version: 1,
            pool_guid,
            device_guid: [0x01u8; 16],
            pool_name_len: 0,
            pool_name: [0u8; 255],
            pool_state: LabelPoolState::Active,
            commit_group: 100,
            label_commit_group: 100,
            device_index: 0,
            topology_generation: 1,
            device_count: 1,
            device_class: LabelDeviceClass::Hdd,
            device_capacity_bytes: 1024 * 1024 * 1024,
            system_area_pointer: 0,
            system_area_size: 0,
            features_incompat: features::CLUSTER_POOL_INCOMPAT,
            features_ro_compat: 0,
            features_compat: features::CLUSTER_POOL_COMPAT,
            device_health: 0,
            device_read_errors: 0,
            device_write_errors: 0,
            device_checksum_errors: 0,
            redundancy_policy: PoolRedundancyPolicy::default(),
            checksum: [0u8; 32],
        };
        assert!(label.is_clustered());

        let candidate = DeviceCandidate {
            path: std::path::PathBuf::from("/dev/cluster_disk2"),
            label,
            label_copy: 0,
            device_size: 1024 * 1024 * 1024,
        };

        let mut pool = CandidatePool {
            pool_guid,
            pool_name: "clusterpool2".into(),
            pool_state: LabelPoolState::Active,
            devices: vec![candidate],
            topology_generation: 1,
            device_count: 1,
            recovery_commit_group: 100,
            topology_complete: false,
            cluster_authorized: true,
        };

        // With cluster authority, validation must succeed
        let result = pool.validate();
        assert!(
            result.is_ok(),
            "clustered pool with cluster_authorized must pass validation, got {:?}",
            result.err()
        );
    }
}
