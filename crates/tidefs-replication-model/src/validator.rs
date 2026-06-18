// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Layout validation engine.
//!
//! The [`LayoutValidator`] checks whether a set of concrete placement entries
//! (each tagged with device/node/rack identity) satisfies a given
//! [`ReplicationIntent`]. It detects collision violations where two replicas
//! or shards land in the same failure domain, violating the required
//! separation.

use std::collections::HashSet;

use crate::failure_domain::FailureDomain;
use crate::intent::ReplicationIntent;

// ---------------------------------------------------------------------------
// PlacementEntry
// ---------------------------------------------------------------------------

/// A single placement entry with failure-domain identity tags.
///
/// Each entry maps a shard/replica index to concrete device, node, and rack
/// identifiers. The [`LayoutValidator`] compares these against the intent's
/// required failure-domain separation level.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlacementEntry {
    /// Shard or replica index within the layout (0-based).
    pub shard_index: u16,
    /// Device identifier.
    pub device_id: u64,
    /// Node identifier.
    pub node_id: u64,
    /// Rack identifier.
    pub rack_id: u64,
}

impl PlacementEntry {
    /// Construct a new placement entry.
    #[must_use]
    pub const fn new(shard_index: u16, device_id: u64, node_id: u64, rack_id: u64) -> Self {
        Self {
            shard_index,
            device_id,
            node_id,
            rack_id,
        }
    }

    /// Return the failure-domain identifier for the given domain level.
    #[must_use]
    pub const fn domain_id(&self, domain: FailureDomain) -> u64 {
        match domain {
            FailureDomain::Device => self.device_id,
            FailureDomain::Node => self.node_id,
            FailureDomain::Rack => self.rack_id,
            FailureDomain::Datacenter => {
                // Datacenter-level: rack_id serves as the finest available
                // sub-datacenter tag. Real implementations should use a
                // dedicated datacenter_id field; for now, rack_id proxies.
                self.rack_id
            }
        }
    }
}

// ---------------------------------------------------------------------------
// LayoutValidationError
// ---------------------------------------------------------------------------

/// Errors returned by [`LayoutValidator::validate`].
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LayoutValidationError {
    /// Not enough placement entries to satisfy the intent.
    #[error("insufficient placement entries: need {required} for {intent}, got {actual}")]
    InsufficientEntries {
        /// Human-readable intent description.
        intent: String,
        /// Required minimum number of entries.
        required: u8,
        /// Actual number of entries provided.
        actual: usize,
    },

    /// Two or more entries share the same failure domain, violating the
    /// required separation level.
    #[error("domain collision at {domain:?}: shards {indices:?} share {domain} {colliding_id}")]
    DomainCollision {
        /// The domain level where the collision was detected.
        domain: FailureDomain,
        /// The domain identifier that collided.
        colliding_id: u64,
        /// Indices of the entries that collided.
        indices: Vec<u16>,
    },
}

// ---------------------------------------------------------------------------
// LayoutValidator
// ---------------------------------------------------------------------------

/// Validates placement entries against a replication intent.
///
/// The validator enforces:
/// - Sufficient entry count to satisfy the intent's target spread.
/// - No two entries share the same failure-domain identifier at the level
///   specified by the intent.
///
/// # Examples
///
/// ```
/// use tidefs_replication_model::{
///     ReplicationIntent, FailureDomain, LayoutValidator, PlacementEntry,
/// };
///
/// let intent = ReplicationIntent::new_mirror(3, FailureDomain::Node).unwrap();
///
/// // Three replicas on three distinct nodes
/// let placements = vec![
///     PlacementEntry::new(0, 1, 10, 100),
///     PlacementEntry::new(1, 2, 20, 200),
///     PlacementEntry::new(2, 3, 30, 300),
/// ];
/// assert!(LayoutValidator::validate(&intent, &placements).is_ok());
///
/// // Two replicas on the same node — collision
/// let bad = vec![
///     PlacementEntry::new(0, 1, 10, 100),
///     PlacementEntry::new(1, 2, 10, 200), // same node_id=10
/// ];
/// assert!(LayoutValidator::validate(&intent, &bad).is_err());
/// ```
pub struct LayoutValidator;

impl LayoutValidator {
    /// Validate that `placements` satisfy the given `intent`.
    ///
    /// Returns `Ok(())` on success, or a [`LayoutValidationError`] describing
    /// the first violation found.
    pub fn validate(
        intent: &ReplicationIntent,
        placements: &[PlacementEntry],
    ) -> Result<(), LayoutValidationError> {
        let required = intent.total_targets() as usize;
        let actual = placements.len();

        if actual < required {
            return Err(LayoutValidationError::InsufficientEntries {
                intent: intent.to_string(),
                required: intent.total_targets(),
                actual,
            });
        }

        let domain = intent.failure_domain();

        // Check for collisions at the required failure-domain level.
        // We only need to check the first `required` entries since extra
        // entries beyond the required count don't invalidate the separation
        // of the required ones — but they still must not collide.
        let mut seen: HashSet<u64> = HashSet::with_capacity(actual);

        for entry in placements {
            let id = entry.domain_id(domain);
            if !seen.insert(id) {
                // Find all entries with this colliding id
                let indices: Vec<u16> = placements
                    .iter()
                    .filter(|e| e.domain_id(domain) == id)
                    .map(|e| e.shard_index)
                    .collect();

                return Err(LayoutValidationError::DomainCollision {
                    domain,
                    colliding_id: id,
                    indices,
                });
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(shard: u16, device: u64, node: u64, rack: u64) -> PlacementEntry {
        PlacementEntry::new(shard, device, node, rack)
    }

    // ---------- Mirror validation ----------

    #[test]
    fn mirror_2_device_pass() {
        let intent = ReplicationIntent::new_mirror(2, FailureDomain::Device).unwrap();
        let placements = vec![
            make_entry(0, 1, 10, 100),
            make_entry(1, 2, 10, 100), // same node/rack OK for device-level
        ];
        assert!(LayoutValidator::validate(&intent, &placements).is_ok());
    }

    #[test]
    fn mirror_2_device_collision() {
        let intent = ReplicationIntent::new_mirror(2, FailureDomain::Device).unwrap();
        let placements = vec![
            make_entry(0, 1, 10, 100),
            make_entry(1, 1, 20, 200), // same device_id=1
        ];
        let err = LayoutValidator::validate(&intent, &placements).unwrap_err();
        assert!(matches!(err, LayoutValidationError::DomainCollision { .. }));
    }

    #[test]
    fn mirror_3_node_pass() {
        let intent = ReplicationIntent::new_mirror(3, FailureDomain::Node).unwrap();
        let placements = vec![
            make_entry(0, 1, 10, 100),
            make_entry(1, 2, 20, 200),
            make_entry(2, 3, 30, 300),
        ];
        assert!(LayoutValidator::validate(&intent, &placements).is_ok());
    }

    #[test]
    fn mirror_3_node_collision() {
        let intent = ReplicationIntent::new_mirror(3, FailureDomain::Node).unwrap();
        // Entries 1 and 2 share node_id=20
        let placements = vec![
            make_entry(0, 1, 10, 100),
            make_entry(1, 2, 20, 200),
            make_entry(2, 3, 20, 300),
        ];
        let err = LayoutValidator::validate(&intent, &placements).unwrap_err();
        match err {
            LayoutValidationError::DomainCollision {
                domain,
                colliding_id,
                indices,
            } => {
                assert_eq!(domain, FailureDomain::Node);
                assert_eq!(colliding_id, 20);
                assert_eq!(indices.len(), 2);
            }
            _ => panic!("expected DomainCollision"),
        }
    }

    // ---------- Erasure-coded validation ----------

    #[test]
    fn ec_4_2_rack_pass() {
        let intent = ReplicationIntent::new_erasure_coded(4, 2, FailureDomain::Rack).unwrap();
        let placements = vec![
            make_entry(0, 1, 10, 100),
            make_entry(1, 2, 20, 200),
            make_entry(2, 3, 30, 300),
            make_entry(3, 4, 40, 400),
            make_entry(4, 5, 50, 500),
            make_entry(5, 6, 60, 600),
        ];
        assert!(LayoutValidator::validate(&intent, &placements).is_ok());
    }

    #[test]
    fn ec_4_2_rack_collision() {
        let intent = ReplicationIntent::new_erasure_coded(4, 2, FailureDomain::Rack).unwrap();
        // Shards 0 and 3 share rack_id=100
        let placements = vec![
            make_entry(0, 1, 10, 100),
            make_entry(1, 2, 20, 200),
            make_entry(2, 3, 30, 300),
            make_entry(3, 4, 40, 100), // collision on rack=100
            make_entry(4, 5, 50, 500),
            make_entry(5, 6, 60, 600),
        ];
        let err = LayoutValidator::validate(&intent, &placements).unwrap_err();
        assert!(matches!(
            err,
            LayoutValidationError::DomainCollision {
                domain: FailureDomain::Rack,
                ..
            }
        ));
    }

    #[test]
    fn ec_insufficient_entries() {
        let intent = ReplicationIntent::new_erasure_coded(4, 2, FailureDomain::Rack).unwrap();
        let placements = vec![
            make_entry(0, 1, 10, 100),
            make_entry(1, 2, 20, 200),
            make_entry(2, 3, 30, 300),
        ]; // only 3, need 6
        let err = LayoutValidator::validate(&intent, &placements).unwrap_err();
        assert!(matches!(
            err,
            LayoutValidationError::InsufficientEntries {
                required: 6,
                actual: 3,
                ..
            }
        ));
    }

    #[test]
    fn mirror_insufficient_entries() {
        let intent = ReplicationIntent::new_mirror(3, FailureDomain::Node).unwrap();
        let placements = vec![make_entry(0, 1, 10, 100)]; // only 1, need 3
        let err = LayoutValidator::validate(&intent, &placements).unwrap_err();
        assert!(matches!(
            err,
            LayoutValidationError::InsufficientEntries {
                required: 3,
                actual: 1,
                ..
            }
        ));
    }

    // ---------- Shard distribution enforcement ----------

    #[test]
    fn ec_shard_distribution_all_unique_devices() {
        // For a 4+2 EC layout, all 6 shards should be on distinct devices.
        let intent = ReplicationIntent::new_erasure_coded(4, 2, FailureDomain::Device).unwrap();
        let placements: Vec<_> = (0..6)
            .map(|i| make_entry(i, u64::from(i) + 1, 10, 100))
            .collect();
        assert!(LayoutValidator::validate(&intent, &placements).is_ok());
    }

    #[test]
    fn ec_shard_distribution_device_collision() {
        let intent = ReplicationIntent::new_erasure_coded(4, 2, FailureDomain::Device).unwrap();
        let mut placements: Vec<_> = (0..6)
            .map(|i| make_entry(i, u64::from(i) + 1, 10, 100))
            .collect();
        // Force shard 2 onto same device as shard 0
        placements[2] = make_entry(2, 1, 10, 100);
        let err = LayoutValidator::validate(&intent, &placements).unwrap_err();
        assert!(matches!(
            err,
            LayoutValidationError::DomainCollision {
                domain: FailureDomain::Device,
                ..
            }
        ));
    }

    // ---------- Mixed domains ----------

    #[test]
    fn node_separation_allows_same_rack() {
        // Node-level separation: same rack is fine as long as nodes differ.
        let intent = ReplicationIntent::new_mirror(3, FailureDomain::Node).unwrap();
        let placements = vec![
            make_entry(0, 1, 10, 100),
            make_entry(1, 2, 20, 100), // same rack, different node — OK
            make_entry(2, 3, 30, 100), // same rack, different node — OK
        ];
        assert!(LayoutValidator::validate(&intent, &placements).is_ok());
    }

    #[test]
    fn rack_separation_rejects_same_rack() {
        // Rack-level separation: different nodes on same rack is a collision.
        let intent = ReplicationIntent::new_mirror(3, FailureDomain::Rack).unwrap();
        let placements = vec![
            make_entry(0, 1, 10, 100),
            make_entry(1, 2, 20, 100), // same rack — collision!
            make_entry(2, 3, 30, 300),
        ];
        let err = LayoutValidator::validate(&intent, &placements).unwrap_err();
        assert!(matches!(
            err,
            LayoutValidationError::DomainCollision {
                domain: FailureDomain::Rack,
                ..
            }
        ));
    }

    // ---------- Mirror-1 (no redundancy) ----------

    #[test]
    fn mirror_1_pass() {
        let intent = ReplicationIntent::new_mirror(1, FailureDomain::Device).unwrap();
        let placements = vec![make_entry(0, 1, 10, 100)];
        assert!(LayoutValidator::validate(&intent, &placements).is_ok());
    }

    #[test]
    fn mirror_1_insufficient() {
        let intent = ReplicationIntent::new_mirror(1, FailureDomain::Device).unwrap();
        let placements: Vec<PlacementEntry> = vec![];
        let err = LayoutValidator::validate(&intent, &placements).unwrap_err();
        assert!(matches!(
            err,
            LayoutValidationError::InsufficientEntries {
                required: 1,
                actual: 0,
                ..
            }
        ));
    }

    // ---------- Serde round-trips for error ----------

    #[test]
    fn error_display_insufficient() {
        let err = LayoutValidationError::InsufficientEntries {
            intent: "mirror(copies=3, domain=node)".to_string(),
            required: 3,
            actual: 1,
        };
        let msg = err.to_string();
        assert!(msg.contains("insufficient"));
        assert!(msg.contains("3"));
        assert!(msg.contains("1"));
    }

    #[test]
    fn error_display_collision() {
        let err = LayoutValidationError::DomainCollision {
            domain: FailureDomain::Node,
            colliding_id: 10,
            indices: vec![0, 2],
        };
        let msg = err.to_string();
        assert!(msg.contains("collision"));
        assert!(msg.contains("Node"));
        assert!(msg.contains("10"));
    }
}
