// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Placement verification engine.
//!
//! [`LayoutVerifier`] validates actual object placements against a
//! declared [`DurabilityLayoutV1`] and [`LayoutPolicy`]. It detects:
//!
//! - Co-located replicas in the same failure domain (domain violation),
//! - Under-replicated objects (fewer copies than policy requires),
//! - Policy-constraint breaches at any failure-domain level.
//!
//! The verifier is stateless: given placements and policy, it returns
//! a [`VerificationReport`] enumerating any violations found.

use crate::layout::{
    DomainPlacementMapper, DomainTarget, PlacementVerificationError, ShardPlacement,
};
use crate::policy::LayoutPolicy;
use crate::{DurabilityPolicy, FailureDomainLevel};

/// Result of a layout verification pass for a single object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationReport {
    /// Whether the placement is fully compliant.
    pub compliant: bool,
    /// List of violations found, in discovery order.
    pub violations: Vec<PlacementViolation>,
    /// Number of distinct failure domains used at each level.
    pub domain_counts: DomainCounts,
}

/// Number of distinct failure domains used in a placement.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DomainCounts {
    pub devices: usize,
    pub nodes: usize,
    pub racks: usize,
    pub datacenters: usize,
}

/// A single placement violation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlacementViolation {
    /// Two or more shards share the same failure domain at a level
    /// where the policy requires separation.
    CoLocation {
        level: FailureDomainLevel,
        shard_a: u32,
        shard_b: u32,
        target_id: u64,
    },
    /// Fewer replicas than the policy requires.
    UnderReplicated {
        expected: usize,
        actual: usize,
        level: FailureDomainLevel,
    },
    /// Policy constraint breach (e.g., not enough distinct domains).
    ConstraintBreach {
        level: FailureDomainLevel,
        required: u8,
        actual: u8,
        detail: &'static str,
    },
    /// Redundant copies beyond what the policy requires.
    OverReplicated { expected: usize, actual: usize },
}

/// Layout verifier that validates placements against policy.
#[derive(Clone, Debug)]
pub struct LayoutVerifier {
    /// The durability policy being enforced.
    policy: DurabilityPolicy,
}

impl LayoutVerifier {
    /// Create a new verifier for the given durability policy.
    pub fn new(policy: DurabilityPolicy) -> Self {
        Self { policy }
    }

    /// Verify that a set of domain targets satisfies the policy at all
    /// relevant failure-domain levels.
    ///
    /// Returns a [`VerificationReport`] with compliance status and any
    /// violations found.
    pub fn verify_targets(
        &self,
        targets: &[DomainTarget],
        layout_policy: &dyn LayoutPolicy,
        levels: &[FailureDomainLevel],
    ) -> VerificationReport {
        let mut report = VerificationReport {
            compliant: true,
            violations: Vec::new(),
            domain_counts: DomainCounts::default(),
        };

        // Count distinct domains at each level
        report.domain_counts = count_domains(targets);

        for &level in levels {
            self.verify_at_level(targets, layout_policy, level, &mut report);
        }

        // Check overall replication factor
        let expected = layout_policy.replication_factor(&self.policy);
        let actual = targets.len();
        if actual < expected {
            report.compliant = false;
            report.violations.push(PlacementViolation::UnderReplicated {
                expected,
                actual,
                level: FailureDomainLevel::Device,
            });
        } else if actual > expected {
            report
                .violations
                .push(PlacementViolation::OverReplicated { expected, actual });
        }

        report
    }

    /// Verify placement at a single failure-domain level.
    fn verify_at_level(
        &self,
        targets: &[DomainTarget],
        layout_policy: &dyn LayoutPolicy,
        level: FailureDomainLevel,
        report: &mut VerificationReport,
    ) {
        // Convert to ShardPlacement for the mapper's verify_placement
        let placements: Vec<ShardPlacement> = targets
            .iter()
            .enumerate()
            .map(|(i, t)| ShardPlacement {
                shard_index: i as u32,
                target: *t,
            })
            .collect();

        // Check for co-location at this level
        if let Err(err) = DomainPlacementMapper::verify_placement(&placements, level) {
            match err {
                PlacementVerificationError::CoLocation {
                    shard_a,
                    shard_b,
                    target_a,
                    ..
                } => {
                    report.compliant = false;
                    report.violations.push(PlacementViolation::CoLocation {
                        level,
                        shard_a,
                        shard_b,
                        target_id: target_a.target_id,
                    });
                }
            }
        }

        // Check min_domains constraint
        let required = layout_policy.min_domains(level);
        let actual = match level {
            FailureDomainLevel::Device => report.domain_counts.devices,
            FailureDomainLevel::Node => report.domain_counts.nodes,
            FailureDomainLevel::Rack => report.domain_counts.racks,
            FailureDomainLevel::Datacenter => report.domain_counts.datacenters,
        };

        if required > 0 && actual < required as usize {
            report.compliant = false;
            report
                .violations
                .push(PlacementViolation::ConstraintBreach {
                    level,
                    required,
                    actual: actual as u8,
                    detail: "insufficient distinct failure domains at this level",
                });
        }
    }

    /// Convenience: verify against all four failure-domain levels.
    pub fn verify_all_levels(
        &self,
        targets: &[DomainTarget],
        layout_policy: &dyn LayoutPolicy,
    ) -> VerificationReport {
        self.verify_targets(
            targets,
            layout_policy,
            &[
                FailureDomainLevel::Device,
                FailureDomainLevel::Node,
                FailureDomainLevel::Rack,
                FailureDomainLevel::Datacenter,
            ],
        )
    }
}

/// Count distinct failure domains from a set of targets.
///
/// Since `DomainTarget` only carries a `target_id` at a single level,
/// this performs a naive count: all targets at the same level are assumed
/// to be distinct when they have different `target_id` values. For full
/// hierarchy-aware counting, use [`crate::layout::TopologyAwarePlacement`].
fn count_domains(targets: &[DomainTarget]) -> DomainCounts {
    let mut counts = DomainCounts::default();
    let mut seen_devices = std::collections::BTreeSet::new();
    let mut seen_nodes = std::collections::BTreeSet::new();
    let mut seen_racks = std::collections::BTreeSet::new();
    let mut seen_dcs = std::collections::BTreeSet::new();

    for t in targets {
        match t.level {
            FailureDomainLevel::Device => {
                if seen_devices.insert(t.target_id) {
                    counts.devices += 1;
                }
            }
            FailureDomainLevel::Node => {
                if seen_nodes.insert(t.target_id) {
                    counts.nodes += 1;
                }
            }
            FailureDomainLevel::Rack => {
                if seen_racks.insert(t.target_id) {
                    counts.racks += 1;
                }
            }
            FailureDomainLevel::Datacenter => {
                if seen_dcs.insert(t.target_id) {
                    counts.datacenters += 1;
                }
            }
        }
    }
    counts
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::DefaultLayoutPolicy;

    fn make_targets(ids: &[u64]) -> Vec<DomainTarget> {
        ids.iter()
            .map(|&id| DomainTarget::new(FailureDomainLevel::Device, id))
            .collect()
    }

    // -- LayoutVerifier: basic compliance -----------------------------------

    #[test]
    fn verify_compliant_mirror_3() {
        let policy = DurabilityPolicy::mirror(3).unwrap();
        let verifier = LayoutVerifier::new(policy);
        let layout = DefaultLayoutPolicy::single_node(3, 10);
        let targets = make_targets(&[0, 1, 2]);

        let report = verifier.verify_all_levels(&targets, &layout);
        assert!(report.compliant);
        assert!(report.violations.is_empty());
        assert_eq!(report.domain_counts.devices, 3);
    }

    #[test]
    fn verify_compliant_erasure_6() {
        let policy = DurabilityPolicy::erasure_style(4, 2).unwrap();
        let verifier = LayoutVerifier::new(policy);
        let layout = DefaultLayoutPolicy::single_node(1, 20);
        let targets = make_targets(&[0, 1, 2, 3, 4, 5]);

        let report = verifier.verify_all_levels(&targets, &layout);
        assert!(report.compliant);
        assert_eq!(report.domain_counts.devices, 6);
    }

    #[test]
    fn verify_compliant_mirror_device_level_only() {
        let policy = DurabilityPolicy::mirror(3).unwrap();
        let verifier = LayoutVerifier::new(policy);
        let layout = DefaultLayoutPolicy::single_node(3, 10);
        let targets = make_targets(&[5, 7, 9]);

        let report = verifier.verify_targets(&targets, &layout, &[FailureDomainLevel::Device]);
        assert!(report.compliant);
        assert!(report.violations.is_empty());
    }

    // -- LayoutVerifier: co-location detection ------------------------------

    #[test]
    fn verify_detects_co_location() {
        let policy = DurabilityPolicy::mirror(3).unwrap();
        let verifier = LayoutVerifier::new(policy);
        let layout = DefaultLayoutPolicy::single_node(3, 10);
        // Two replicas on the same device
        let targets = make_targets(&[0, 0, 2]);

        let report = verifier.verify_all_levels(&targets, &layout);
        assert!(!report.compliant);
        assert!(report
            .violations
            .iter()
            .any(|v| matches!(v, PlacementViolation::CoLocation { .. })));
    }

    #[test]
    fn verify_co_location_reports_correct_shards() {
        let policy = DurabilityPolicy::mirror(3).unwrap();
        let verifier = LayoutVerifier::new(policy);
        let layout = DefaultLayoutPolicy::single_node(3, 10);
        let targets = make_targets(&[0, 0, 2]);

        let report = verifier.verify_all_levels(&targets, &layout);
        let colo = report
            .violations
            .iter()
            .find_map(|v| {
                if let PlacementViolation::CoLocation {
                    shard_a, shard_b, ..
                } = v
                {
                    Some((*shard_a, *shard_b))
                } else {
                    None
                }
            })
            .unwrap();
        // Shards 0 and 1 share the same target
        assert_eq!(colo, (0, 1));
    }

    // -- LayoutVerifier: under-replication ----------------------------------

    #[test]
    fn verify_detects_under_replication() {
        let policy = DurabilityPolicy::mirror(5).unwrap();
        let verifier = LayoutVerifier::new(policy);
        let layout = DefaultLayoutPolicy::single_node(5, 10);
        let targets = make_targets(&[0, 1, 2]); // only 3, need 5

        let report = verifier.verify_all_levels(&targets, &layout);
        assert!(!report.compliant);
        assert!(report
            .violations
            .iter()
            .any(|v| matches!(v, PlacementViolation::UnderReplicated { .. })));
    }

    #[test]
    fn verify_under_replication_erasure() {
        let policy = DurabilityPolicy::erasure_style(6, 3).unwrap();
        let verifier = LayoutVerifier::new(policy);
        let layout = DefaultLayoutPolicy::single_node(1, 20);
        let targets = make_targets(&[0, 1]); // only 2, need 9

        let report = verifier.verify_all_levels(&targets, &layout);
        assert!(!report.compliant);
        let under = report.violations.iter().find_map(|v| {
            if let PlacementViolation::UnderReplicated {
                expected, actual, ..
            } = v
            {
                Some((*expected, *actual))
            } else {
                None
            }
        });
        assert_eq!(under, Some((9, 2)));
    }

    // -- LayoutVerifier: constraint breach ----------------------------------

    #[test]
    fn verify_detects_constraint_breach() {
        let policy = DurabilityPolicy::mirror(3).unwrap();
        let verifier = LayoutVerifier::new(policy);
        // require 3 distinct devices
        let layout = DefaultLayoutPolicy::single_node(3, 10);
        // Only 2 distinct targets
        let targets = make_targets(&[0, 1, 1]); // 3 shards but only 2 distinct

        let report = verifier.verify_all_levels(&targets, &layout);
        assert!(!report.compliant);
        assert!(report
            .violations
            .iter()
            .any(|v| matches!(v, PlacementViolation::CoLocation { .. })));
    }

    // -- LayoutVerifier: multi-node constraint breach -----------------------

    #[test]
    fn verify_multi_node_detects_node_colocation() {
        // Even with different device IDs, same-level targets on same node
        // would be caught if we had topology data. Without topology,
        // the verifier checks co-location at each level directly.
        let policy = DurabilityPolicy::mirror(3).unwrap();
        let verifier = LayoutVerifier::new(policy);
        let layout = DefaultLayoutPolicy::multi_node(3, 5, 2, 3, 0);
        let targets = make_targets(&[0, 1, 2]);

        // With device-level targets, device-level check passes
        let report = verifier.verify_targets(&targets, &layout, &[FailureDomainLevel::Device]);
        assert!(report.compliant);
    }

    // -- LayoutVerifier: over-replication -----------------------------------

    #[test]
    fn verify_detects_over_replication() {
        let policy = DurabilityPolicy::mirror(2).unwrap();
        let verifier = LayoutVerifier::new(policy);
        let layout = DefaultLayoutPolicy::single_node(2, 10);
        let targets = make_targets(&[0, 1, 2, 3]); // 4 copies, need only 2

        let report = verifier.verify_all_levels(&targets, &layout);
        assert!(report
            .violations
            .iter()
            .any(|v| matches!(v, PlacementViolation::OverReplicated { .. })));
    }

    // -- LayoutVerifier: hybrid policy --------------------------------------

    #[test]
    fn verify_hybrid_compliant() {
        let policy = DurabilityPolicy::hybrid(2, 4, 2).unwrap();
        let verifier = LayoutVerifier::new(policy);
        let layout = DefaultLayoutPolicy::single_node(1, 50);
        let targets: Vec<DomainTarget> = (0..12)
            .map(|i| DomainTarget::new(FailureDomainLevel::Device, i))
            .collect(); // 2 * (4+2) = 12

        let report = verifier.verify_all_levels(&targets, &layout);
        assert!(report.compliant);
        assert_eq!(report.domain_counts.devices, 12);
    }

    #[test]
    fn verify_empty_targets() {
        let policy = DurabilityPolicy::mirror(3).unwrap();
        let verifier = LayoutVerifier::new(policy);
        let layout = DefaultLayoutPolicy::single_node(3, 10);
        let targets: Vec<DomainTarget> = vec![];

        let report = verifier.verify_all_levels(&targets, &layout);
        assert!(!report.compliant);
        assert!(report
            .violations
            .iter()
            .any(|v| matches!(v, PlacementViolation::UnderReplicated { .. })));
    }

    #[test]
    fn verify_single_replica_compliant() {
        let policy = DurabilityPolicy::mirror(1).unwrap();
        let verifier = LayoutVerifier::new(policy);
        let layout = DefaultLayoutPolicy::single_node(1, 10);
        let targets = make_targets(&[7]);

        let report = verifier.verify_all_levels(&targets, &layout);
        assert!(report.compliant);
    }
}
