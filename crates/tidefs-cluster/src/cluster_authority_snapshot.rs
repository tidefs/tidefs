//! Typed operator-truth snapshot and boot-time authority discovery.
//!
//! [`ClusterAuthoritySnapshot`] exposes the current cluster authority state
//! in a plain-data form suitable for operator inspection, structured logging,
//! and decision gating (e.g. refusing connections when quorum is absent).
//!
//! [`ClusterAuthorityBootstrapper`] ties the on-disk
//! [`ClusterAuthorityStore`](crate::cluster_authority_store) to a single
//! discovery call: given a set of pool device paths, it scans for the
//! latest valid authority record and returns a snapshot (or a refusal reason
//! when no valid authority is found).

use std::collections::{BTreeMap, BTreeSet};
/// Encode a byte slice as a hex string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
use std::path::Path;

use crate::cluster_authority_record::ClusterAuthorityRecord;
use crate::cluster_authority_store::{scan_authority_from_devices, AuthorityStoreError};

// ── ClusterAuthoritySnapshot ───────────────────────────────────────

/// A frozen, operator-inspectable picture of the current cluster authority
/// state as persisted on pool devices.
///
/// Every field is a plain value; the snapshot does not carry any mutable
/// runtime state or lease-token secrets.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ClusterAuthoritySnapshot {
    /// Pool GUID this authority governs.
    pub pool_guid: [u8; 16],
    /// Current membership epoch.
    pub membership_epoch: u64,
    /// Set of voting member node IDs.
    pub voter_set: BTreeSet<u64>,
    /// Set of learner member node IDs.
    pub learner_set: BTreeSet<u64>,
    /// Set of fenced node IDs.
    pub fenced_nodes: BTreeSet<u64>,
    /// Node ID of the current import owner (0 if none).
    pub import_owner: u64,
    /// Current placement-map epoch.
    pub placement_map_epoch: u64,
    /// BLAKE3-256 digest of the current placement map.
    pub placement_map_digest: String, // hex-encoded for readability
    /// Last committed authority transition receipt ID.
    pub last_authority_receipt: u64,
    /// Pool topology generation.
    pub topology_generation: u64,
    /// Transaction group at which this record was committed.
    pub committed_txg: u64,
    /// Monotonic authority record sequence number.
    pub sequence: u64,
    /// Whether the cluster is formed (non-empty voter set).
    pub cluster_formed: bool,
    /// Quorum size (floor(N/2) + 1 of voters).
    pub quorum_size: usize,
    /// Authority record self-digest (hex-encoded).
    pub authority_digest: String,
}

impl ClusterAuthoritySnapshot {
    /// Derive a snapshot from a validated [`ClusterAuthorityRecord`].
    pub fn from_record(record: &ClusterAuthorityRecord) -> Self {
        Self {
            pool_guid: record.pool_guid,
            membership_epoch: record.membership_epoch.0,
            voter_set: record.voter_set.clone(),
            learner_set: record.learner_set.clone(),
            fenced_nodes: record.fenced_nodes.clone(),
            import_owner: record.import_owner,
            placement_map_epoch: record.placement_map_epoch,
            placement_map_digest: hex_encode(&record.placement_map_digest),
            last_authority_receipt: record.last_authority_receipt,
            topology_generation: record.topology_generation,
            committed_txg: record.committed_txg,
            sequence: record.sequence,
            cluster_formed: record.is_cluster_formed(),
            quorum_size: record.quorum_size(),
            authority_digest: hex_encode(&record.self_digest),
        }
    }

    /// Returns true if the snapshot indicates a valid, formed cluster
    /// with at least one voter.
    pub fn is_operational(&self) -> bool {
        self.cluster_formed && !self.voter_set.is_empty()
    }

    /// Returns true if `node_id` is a current voter.
    pub fn is_voter(&self, node_id: u64) -> bool {
        self.voter_set.contains(&node_id)
    }

    /// Returns true if `node_id` is a current learner.
    pub fn is_learner(&self, node_id: u64) -> bool {
        self.learner_set.contains(&node_id)
    }

    /// Returns true if `node_id` is fenced.
    pub fn is_fenced(&self, node_id: u64) -> bool {
        self.fenced_nodes.contains(&node_id)
    }

    /// Produce a human-readable one-line summary for operator output.
    pub fn summary(&self) -> String {
        format!(
            "authority seq={} epoch={} voters={} learners={} fenced={} import_owner={} map_epoch={} quorum={} txg={}",
            self.sequence,
            self.membership_epoch,
            self.voter_set.len(),
            self.learner_set.len(),
            self.fenced_nodes.len(),
            self.import_owner,
            self.placement_map_epoch,
            self.quorum_size,
            self.committed_txg,
        )
    }
}

// ── ClusterAuthorityBootstrapper ───────────────────────────────────

/// Boot-time cluster authority discovery.
///
/// Given a set of pool device paths, scans each device for persisted
/// authority records, selects the newest valid record, and returns a
/// [`ClusterAuthoritySnapshot`]. Failures are reported per-device so
/// operators can diagnose partial device corruption.
#[derive(Debug)]
pub struct ClusterAuthorityBootstrapper;

/// Outcome of a boot-time authority scan.
#[derive(Clone, Debug)]
pub enum BootAuthorityOutcome {
    /// A valid authority record was found; the cluster state is
    /// represented by the snapshot.
    Discovered {
        snapshot: ClusterAuthoritySnapshot,
        /// Per-device scan results for operator visibility.
        per_device: BTreeMap<String, DeviceAuthorityStatus>,
    },
    /// No valid authority was found on any device.
    /// The pool is either fresh (no cluster formed yet) or all
    /// devices are missing/corrupt.
    NoAuthority {
        /// Per-device status.
        per_device: BTreeMap<String, DeviceAuthorityStatus>,
    },
}

/// Per-device authority scan status for operator diagnostics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeviceAuthorityStatus {
    /// A valid authority record was found.
    Valid { sequence: u64, txg: u64, epoch: u64 },
    /// No authority region exists on this device (fresh pool or
    /// standalone pool).
    NoRecord,
    /// The authority region is present but corrupt or invalid.
    Corrupt { error: String },
    /// An I/O error occurred reading the device.
    IoError { error: String },
}

impl ClusterAuthorityBootstrapper {
    /// Scan the given pool device paths and discover the current cluster
    /// authority state.
    ///
    /// This is the primary entry point for boot-time authority discovery.
    /// It calls [`scan_authority_from_devices`] and converts the raw
    /// results into a typed [`BootAuthorityOutcome`].
    pub fn discover(device_paths: &[impl AsRef<Path>]) -> BootAuthorityOutcome {
        let (best, per_device) = match scan_authority_from_devices(device_paths) {
            Ok(result) => result,
            Err(_e) => {
                // Fatal error during scan — report all devices as corrupt/io-error.
                let mut statuses = BTreeMap::new();
                for path in device_paths {
                    statuses.insert(
                        path.as_ref().display().to_string(),
                        DeviceAuthorityStatus::Corrupt {
                            error: "fatal scan error".into(),
                        },
                    );
                }
                return BootAuthorityOutcome::NoAuthority {
                    per_device: statuses,
                };
            }
        };

        let per_device: BTreeMap<String, DeviceAuthorityStatus> = per_device
            .into_iter()
            .map(|(path, result)| {
                let status = match result {
                    Ok(Some(rec)) => DeviceAuthorityStatus::Valid {
                        sequence: rec.sequence,
                        txg: rec.committed_txg,
                        epoch: rec.membership_epoch.0,
                    },
                    Ok(None) => DeviceAuthorityStatus::NoRecord,
                    Err(e) => {
                        if matches!(e, AuthorityStoreError::Io(_)) {
                            DeviceAuthorityStatus::IoError {
                                error: e.to_string(),
                            }
                        } else {
                            DeviceAuthorityStatus::Corrupt {
                                error: e.to_string(),
                            }
                        }
                    }
                };
                (path, status)
            })
            .collect();

        match best {
            Some(record) => BootAuthorityOutcome::Discovered {
                snapshot: ClusterAuthoritySnapshot::from_record(&record),
                per_device,
            },
            None => BootAuthorityOutcome::NoAuthority { per_device },
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster_authority_record::ClusterAuthorityRecord;
    use crate::cluster_authority_store::{
        write_authority_chain_to_device, CLUSTER_AUTHORITY_REGION_OFFSET,
    };
    use std::collections::BTreeSet;
    use std::io::Write;

    fn voters(ids: &[u64]) -> BTreeSet<u64> {
        ids.iter().copied().collect()
    }

    fn make_genesis() -> ClusterAuthorityRecord {
        ClusterAuthorityRecord::genesis(
            [0xAB; 16],
            voters(&[1, 2, 3]),
            BTreeSet::new(),
            1,
            [0xCD; 32],
            5,
        )
    }

    // ── Snapshot from record ────────────────────────────────────

    #[test]
    fn snapshot_from_record_preserves_fields() {
        let rec = make_genesis();
        let snap = ClusterAuthoritySnapshot::from_record(&rec);

        assert_eq!(snap.pool_guid, [0xAB; 16]);
        assert_eq!(snap.membership_epoch, 1);
        assert_eq!(snap.voter_set, voters(&[1, 2, 3]));
        assert_eq!(snap.learner_set, BTreeSet::new());
        assert_eq!(snap.fenced_nodes, BTreeSet::new());
        assert_eq!(snap.import_owner, 1);
        assert_eq!(snap.placement_map_epoch, 0);
        assert_eq!(snap.topology_generation, 5);
        assert_eq!(snap.sequence, 0);
        assert!(snap.cluster_formed);
        assert_eq!(snap.quorum_size, 2);
        assert!(snap.is_operational());
        assert!(snap.is_voter(1));
        assert!(snap.is_voter(2));
        assert!(snap.is_voter(3));
        assert!(!snap.is_voter(99));
        assert!(!snap.is_fenced(1));
    }

    #[test]
    fn snapshot_is_not_operational_for_empty_cluster() {
        let rec = ClusterAuthorityRecord::genesis(
            [0xAB; 16],
            BTreeSet::new(),
            BTreeSet::new(),
            0,
            [0u8; 32],
            0,
        );
        let snap = ClusterAuthoritySnapshot::from_record(&rec);
        assert!(!snap.cluster_formed);
        assert!(!snap.is_operational());
        assert_eq!(snap.quorum_size, 0);
    }

    #[test]
    fn snapshot_summary_contains_key_fields() {
        let snap = ClusterAuthoritySnapshot::from_record(&make_genesis());
        let s = snap.summary();
        assert!(s.contains("seq=0"));
        assert!(s.contains("voters=3"));
        assert!(s.contains("import_owner=1"));
        assert!(s.contains("quorum=2"));
    }

    // ── Bootstrapper with temp files ────────────────────────────

    #[test]
    fn bootstrapper_discovers_authority() {
        let r0 = make_genesis();
        let r1 = r0
            .successor()
            .membership_epoch(tidefs_membership_epoch::EpochId(2))
            .voter_set(voters(&[1, 2, 3, 4]))
            .build();

        let dir = tempfile::TempDir::new().unwrap();
        let dev_path = dir.path().join("dev1");

        {
            let mut f = std::fs::File::create(&dev_path).unwrap();
            f.write_all(&vec![0u8; CLUSTER_AUTHORITY_REGION_OFFSET as usize])
                .unwrap();
            write_authority_chain_to_device(&mut f, &[r0.clone(), r1.clone()]).unwrap();
        }

        let outcome = ClusterAuthorityBootstrapper::discover(&[&dev_path]);
        match outcome {
            BootAuthorityOutcome::Discovered {
                snapshot,
                per_device,
            } => {
                assert_eq!(snapshot.membership_epoch, 2);
                assert_eq!(snapshot.voter_set, voters(&[1, 2, 3, 4]));
                assert_eq!(snapshot.sequence, 1);
                assert_eq!(per_device.len(), 1);
                match per_device.get(&dev_path.display().to_string()) {
                    Some(DeviceAuthorityStatus::Valid { sequence, .. }) => {
                        assert_eq!(*sequence, 1);
                    }
                    other => panic!("expected Valid, got {:?}", other),
                }
            }
            other => panic!("expected Discovered, got {:?}", other),
        }
    }

    #[test]
    fn bootstrapper_returns_no_authority_for_empty_device() {
        let dir = tempfile::TempDir::new().unwrap();
        let dev_path = dir.path().join("dev1");
        std::fs::File::create(&dev_path).unwrap(); // zero-length file

        let outcome = ClusterAuthorityBootstrapper::discover(&[&dev_path]);
        match outcome {
            BootAuthorityOutcome::NoAuthority { per_device } => {
                assert_eq!(per_device.len(), 1);
                match per_device.get(&dev_path.display().to_string()) {
                    Some(DeviceAuthorityStatus::NoRecord) => {}
                    other => panic!("expected NoRecord, got {:?}", other),
                }
            }
            other => panic!("expected NoAuthority, got {:?}", other),
        }
    }

    // ── DeviceAuthorityStatus display/debug ─────────────────────

    #[test]
    fn device_status_variants_are_constructible() {
        let valid = DeviceAuthorityStatus::Valid {
            sequence: 3,
            txg: 42,
            epoch: 7,
        };
        assert_eq!(
            format!("{:?}", valid),
            "Valid { sequence: 3, txg: 42, epoch: 7 }"
        );

        let no_rec = DeviceAuthorityStatus::NoRecord;
        assert_eq!(format!("{:?}", no_rec), "NoRecord");

        let corrupt = DeviceAuthorityStatus::Corrupt {
            error: "bad magic".into(),
        };
        assert!(format!("{:?}", corrupt).contains("bad magic"));

        let io_err = DeviceAuthorityStatus::IoError {
            error: "permission denied".into(),
        };
        assert!(format!("{:?}", io_err).contains("permission denied"));
    }

    #[test]
    fn bootstrapper_handles_multiple_devices() {
        let r0 = make_genesis();
        let r1 = r0
            .successor()
            .membership_epoch(tidefs_membership_epoch::EpochId(2))
            .build();

        let dir = tempfile::TempDir::new().unwrap();
        let dev1 = dir.path().join("dev1");
        let dev2 = dir.path().join("dev2");
        let dev3 = dir.path().join("dev3");

        // dev1: full chain (genesis + successor)
        {
            let mut f = std::fs::File::create(&dev1).unwrap();
            f.write_all(&vec![0u8; CLUSTER_AUTHORITY_REGION_OFFSET as usize])
                .unwrap();
            write_authority_chain_to_device(&mut f, &[r0.clone(), r1.clone()]).unwrap();
        }
        // dev2: genesis only
        {
            let mut f = std::fs::File::create(&dev2).unwrap();
            f.write_all(&vec![0u8; CLUSTER_AUTHORITY_REGION_OFFSET as usize])
                .unwrap();
            write_authority_chain_to_device(&mut f, &[r0.clone()]).unwrap();
        }
        // dev3: empty (fresh)
        std::fs::File::create(&dev3).unwrap();

        let outcome = ClusterAuthorityBootstrapper::discover(&[&dev1, &dev2, &dev3]);
        match outcome {
            BootAuthorityOutcome::Discovered {
                snapshot,
                per_device,
            } => {
                // Should pick the best (dev1 with seq=1)
                assert_eq!(snapshot.sequence, 1);
                assert_eq!(snapshot.membership_epoch, 2);
                assert_eq!(per_device.len(), 3);

                // dev1: Valid with seq=1
                match per_device.get(&dev1.display().to_string()) {
                    Some(DeviceAuthorityStatus::Valid { sequence, .. }) => {
                        assert_eq!(*sequence, 1);
                    }
                    o => panic!("dev1: expected Valid, got {:?}", o),
                }
                // dev2: Valid with seq=0
                match per_device.get(&dev2.display().to_string()) {
                    Some(DeviceAuthorityStatus::Valid { sequence, .. }) => {
                        assert_eq!(*sequence, 0);
                    }
                    o => panic!("dev2: expected Valid, got {:?}", o),
                }
                // dev3: NoRecord
                match per_device.get(&dev3.display().to_string()) {
                    Some(DeviceAuthorityStatus::NoRecord) => {}
                    o => panic!("dev3: expected NoRecord, got {:?}", o),
                }
            }
            other => panic!("expected Discovered, got {:?}", other),
        }
    }

    #[test]
    fn snapshot_serialization_roundtrip() {
        let snap = ClusterAuthoritySnapshot::from_record(&make_genesis());
        let json = serde_json::to_string(&snap).unwrap();
        let restored: ClusterAuthoritySnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, restored);
    }

    #[test]
    fn snapshot_fenced_detection() {
        let rec = make_genesis();
        let succ = rec.successor().fenced_nodes(voters(&[2])).build();
        let snap = ClusterAuthoritySnapshot::from_record(&succ);
        assert!(snap.is_fenced(2));
        assert!(!snap.is_fenced(1));
        assert!(!snap.is_fenced(3));
    }

    #[test]
    fn snapshot_learner_detection() {
        use std::collections::BTreeSet;
        let learners: BTreeSet<u64> = [10, 11].iter().copied().collect();
        let rec = ClusterAuthorityRecord::genesis(
            [0xAB; 16],
            voters(&[1, 2]),
            learners.clone(),
            1,
            [0u8; 32],
            0,
        );
        let snap = ClusterAuthoritySnapshot::from_record(&rec);
        assert!(snap.is_learner(10));
        assert!(snap.is_learner(11));
        assert!(!snap.is_learner(1));
    }
}
