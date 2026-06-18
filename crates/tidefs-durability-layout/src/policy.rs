// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Layout policy trait and default implementation.
//!
//! The [`LayoutPolicy`] trait defines the contract for mapping objects
//! to failure-domain targets, selecting copy counts, enforcing
//! failure-domain separation constraints, and determining rebuild-trigger
//! thresholds. [`DefaultLayoutPolicy`] provides a concrete
//! single-policy implementation suitable for both single-node and
//! multi-node operation.
//!
//! ## Design
//!
//! Policies are stateless query objects: given an object identifier,
//! a set of available domain targets, and a durability policy, the
//! layout policy returns which targets should receive copies/shards.
//! The policy is consulted during writes, rebuild/backfill scheduling,
//! and placement verification.

use crate::layout::{
    DomainPlacementMapper, DomainTarget, PlacementVerificationError, ShardPlacement,
};
use crate::{DurabilityPolicy, FailureDomainLevel};

/// Rebuild trigger that specifies when a placement violation demands
/// corrective data movement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RebuildTrigger {
    /// Rebuild only when durability falls below the configured minimum.
    BelowMinimumDomains,
    /// Rebuild when any replica is lost, even if durability is intact.
    OnAnyReplicaLoss,
    /// Never auto-rebuild (manual operator action required).
    ManualOnly,
}

/// Trait for layout policies that map objects to failure-domain targets.
///
/// Implementations decide how many copies to place, which targets to use,
/// and whether a given placement satisfies the policy's constraints.
pub trait LayoutPolicy {
    /// Return the minimum number of distinct failure domains required
    /// at the given `level`. For example, a mirror-3 policy with
    /// `min_domains(FailureDomainLevel::Node) == 3` requires all three
    /// replicas to land on different nodes.
    fn min_domains(&self, level: FailureDomainLevel) -> u8;

    /// Return the replication factor (total shard count) required by
    /// this policy for a given `base_policy`.
    fn replication_factor(&self, base_policy: &DurabilityPolicy) -> usize;

    /// Select domain targets for an object.
    ///
    /// Given an object identifier, a set of available targets, and a
    /// durability policy, returns the ordered list of domain targets
    /// for each shard. Implementations must be deterministic: same
    /// inputs always produce the same output.
    fn select_targets(
        &self,
        object_id: &[u8],
        available_targets: &[DomainTarget],
        policy: &DurabilityPolicy,
        domain_level: FailureDomainLevel,
    ) -> Result<Vec<DomainTarget>, LayoutPolicyError>;

    /// Validate that a set of target assignments satisfies this policy.
    ///
    /// Returns `Ok(())` if the assignments are policy-compliant.
    /// Returns `Err` with diagnostic information on violation.
    fn validate_assignments(
        &self,
        assignments: &[(u32, DomainTarget)],
        _policy: &DurabilityPolicy,
        level: FailureDomainLevel,
    ) -> Result<(), PlacementVerificationError> {
        let placements: Vec<ShardPlacement> = assignments
            .iter()
            .map(|(idx, target)| ShardPlacement {
                shard_index: *idx,
                target: *target,
            })
            .collect();

        // Verify no co-location at the given level
        DomainPlacementMapper::verify_placement(&placements, level)
    }

    fn rebuild_trigger(&self) -> RebuildTrigger;

    /// Return the maximum number of concurrent device failures this
    /// policy tolerates before data loss becomes possible.
    fn tolerated_failures(&self, policy: &DurabilityPolicy) -> u32;

    /// Return `true` if the given policy requires placement beyond a
    /// single failure domain (i.e., multi-node/multi-device).
    fn is_multi_domain(&self) -> bool;
}

/// Errors returned by layout policy operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayoutPolicyError {
    /// Not enough domain targets available to satisfy the policy.
    InsufficientTargets {
        required: usize,
        available: usize,
        level: FailureDomainLevel,
    },
    /// The requested policy is incompatible with the current layout.
    IncompatiblePolicy { reason: &'static str },
    /// A domain-level constraint is violated.
    DomainConstraintViolation {
        level: FailureDomainLevel,
        detail: &'static str,
    },
}

/// Default layout policy with configurable replication and domain constraints.
///
/// Suitable for both single-node (all copies on distinct devices within one
/// node) and multi-node (copies spread across nodes/racks/datacenters)
/// deployments.
#[derive(Clone, Debug)]
pub struct DefaultLayoutPolicy {
    /// Minimum number of distinct failure domains of each level.
    min_device_domains: u8,
    min_node_domains: u8,
    min_rack_domains: u8,
    min_datacenter_domains: u8,
    /// Rebuild trigger threshold.
    rebuild: RebuildTrigger,
    /// Placement mapper for deterministic target selection.
    mapper: DomainPlacementMapper,
}

impl DefaultLayoutPolicy {
    /// Create a new default layout policy targeting a specific number of
    /// domains at each level.
    ///
    /// # Arguments
    ///
    /// - `min_device_domains`: minimum distinct devices for placement.
    /// - `min_node_domains`: minimum distinct nodes (0 = no node separation).
    /// - `min_rack_domains`: minimum distinct racks (0 = no rack separation).
    /// - `min_datacenter_domains`: minimum distinct datacenters (0 = none).
    /// - `rebuild`: rebuild trigger threshold.
    /// - `targets`: available domain targets for deterministic placement.
    ///
    /// # Panics
    ///
    /// Panics if `min_device_domains` is 0 (at least one device is required).
    pub fn new(
        min_device_domains: u8,
        min_node_domains: u8,
        min_rack_domains: u8,
        min_datacenter_domains: u8,
        rebuild: RebuildTrigger,
        targets: Vec<DomainTarget>,
    ) -> Self {
        assert!(
            min_device_domains > 0,
            "at least one device domain is required"
        );
        Self {
            min_device_domains,
            min_node_domains,
            min_rack_domains,
            min_datacenter_domains,
            rebuild,
            mapper: DomainPlacementMapper::new(targets),
        }
    }

    /// Single-node convenience constructor: all copies on distinct devices
    /// within the same node. No node/rack/datacenter separation required.
    pub fn single_node(copies: u8, devices: u64) -> Self {
        let targets: Vec<DomainTarget> = (0..devices)
            .map(|i| DomainTarget::new(FailureDomainLevel::Device, i))
            .collect();
        Self::new(
            copies,
            0, // no node separation
            0, // no rack separation
            0, // no datacenter separation
            RebuildTrigger::OnAnyReplicaLoss,
            targets,
        )
    }

    /// Multi-node convenience constructor: copies spread across distinct
    /// nodes, with optional rack/datacenter separation.
    pub fn multi_node(
        copies: u8,
        node_count: u64,
        devices_per_node: u64,
        min_nodes: u8,
        min_racks: u8,
    ) -> Self {
        let total_devices = node_count * devices_per_node;
        let targets: Vec<DomainTarget> = (0..total_devices)
            .map(|i| DomainTarget::new(FailureDomainLevel::Device, i))
            .collect();
        Self::new(
            copies,
            min_nodes,
            min_racks,
            0, // datacenter separation optional
            RebuildTrigger::BelowMinimumDomains,
            targets,
        )
    }

    /// Return the placement mapper for direct use.
    pub fn mapper(&self) -> &DomainPlacementMapper {
        &self.mapper
    }

    /// Return the minimum device domains.
    pub fn min_device_domains(&self) -> u8 {
        self.min_device_domains
    }

    /// Return the minimum node domains.
    pub fn min_node_domains(&self) -> u8 {
        self.min_node_domains
    }
}

impl LayoutPolicy for DefaultLayoutPolicy {
    fn min_domains(&self, level: FailureDomainLevel) -> u8 {
        match level {
            FailureDomainLevel::Device => self.min_device_domains,
            FailureDomainLevel::Node => self.min_node_domains,
            FailureDomainLevel::Rack => self.min_rack_domains,
            FailureDomainLevel::Datacenter => self.min_datacenter_domains,
        }
    }

    fn replication_factor(&self, base_policy: &DurabilityPolicy) -> usize {
        base_policy.total_shards()
    }

    fn select_targets(
        &self,
        object_id: &[u8],
        available_targets: &[DomainTarget],
        policy: &DurabilityPolicy,
        domain_level: FailureDomainLevel,
    ) -> Result<Vec<DomainTarget>, LayoutPolicyError> {
        let required = self.replication_factor(policy);
        if required > available_targets.len() {
            return Err(LayoutPolicyError::InsufficientTargets {
                required,
                available: available_targets.len(),
                level: domain_level,
            });
        }

        // Use the placement mapper with the available targets
        let mapper = DomainPlacementMapper::new(available_targets.to_vec());
        let placements = mapper.place_object(object_id, policy, domain_level);
        Ok(placements.into_iter().map(|p| p.target).collect())
    }

    fn validate_assignments(
        &self,
        assignments: &[(u32, DomainTarget)],
        _policy: &DurabilityPolicy,
        level: FailureDomainLevel,
    ) -> Result<(), PlacementVerificationError> {
        let placements: Vec<ShardPlacement> = assignments
            .iter()
            .map(|(idx, target)| ShardPlacement {
                shard_index: *idx,
                target: *target,
            })
            .collect();

        // Verify no co-location at the given level
        DomainPlacementMapper::verify_placement(&placements, level)
    }

    fn rebuild_trigger(&self) -> RebuildTrigger {
        self.rebuild
    }

    fn tolerated_failures(&self, policy: &DurabilityPolicy) -> u32 {
        match policy {
            DurabilityPolicy::Mirror { copies } => (*copies as u32).saturating_sub(1),
            DurabilityPolicy::ErasureStyle { parity_shards, .. } => *parity_shards as u32,
            DurabilityPolicy::Hybrid {
                mirror_copies,
                parity_shards,
                ..
            } => ((*mirror_copies as u32).saturating_sub(1)) + (*parity_shards as u32),
        }
    }

    fn is_multi_domain(&self) -> bool {
        self.min_node_domains > 0 || self.min_rack_domains > 0 || self.min_datacenter_domains > 0
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FailureDomainLevel;

    // -- DefaultLayoutPolicy: min_domains -----------------------------------

    #[test]
    fn default_policy_min_domains_device() {
        let policy = DefaultLayoutPolicy::single_node(3, 10);
        assert_eq!(policy.min_domains(FailureDomainLevel::Device), 3);
        assert_eq!(policy.min_domains(FailureDomainLevel::Node), 0);
        assert_eq!(policy.min_domains(FailureDomainLevel::Rack), 0);
        assert_eq!(policy.min_domains(FailureDomainLevel::Datacenter), 0);
    }

    #[test]
    fn default_policy_min_domains_multi_node() {
        let policy = DefaultLayoutPolicy::multi_node(3, 5, 2, 3, 2);
        assert_eq!(policy.min_domains(FailureDomainLevel::Device), 3);
        assert_eq!(policy.min_domains(FailureDomainLevel::Node), 3);
        assert_eq!(policy.min_domains(FailureDomainLevel::Rack), 2);
        assert_eq!(policy.min_domains(FailureDomainLevel::Datacenter), 0);
    }

    // -- DefaultLayoutPolicy: replication_factor ----------------------------

    #[test]
    fn replication_factor_mirror() {
        let policy = DefaultLayoutPolicy::single_node(3, 10);
        assert_eq!(
            policy.replication_factor(&DurabilityPolicy::mirror(3).unwrap()),
            3
        );
        assert_eq!(
            policy.replication_factor(&DurabilityPolicy::mirror(5).unwrap()),
            5
        );
    }

    #[test]
    fn replication_factor_erasure() {
        let policy = DefaultLayoutPolicy::single_node(1, 20);
        assert_eq!(
            policy.replication_factor(&DurabilityPolicy::erasure_style(8, 3).unwrap()),
            11
        );
    }

    #[test]
    fn replication_factor_hybrid() {
        let policy = DefaultLayoutPolicy::single_node(1, 50);
        assert_eq!(
            policy.replication_factor(&DurabilityPolicy::hybrid(2, 4, 2).unwrap()),
            12
        );
    }

    // -- DefaultLayoutPolicy: select_targets --------------------------------

    #[test]
    fn select_targets_mirror_deterministic() {
        let policy = DefaultLayoutPolicy::single_node(3, 10);
        let available: Vec<DomainTarget> = (0..10)
            .map(|i| DomainTarget::new(FailureDomainLevel::Device, i))
            .collect();
        let mirror = DurabilityPolicy::mirror(3).unwrap();

        let t1 = policy
            .select_targets(b"obj", &available, &mirror, FailureDomainLevel::Device)
            .unwrap();
        let t2 = policy
            .select_targets(b"obj", &available, &mirror, FailureDomainLevel::Device)
            .unwrap();
        assert_eq!(t1, t2, "deterministic selection");
        assert_eq!(t1.len(), 3);
    }

    #[test]
    fn select_targets_insufficient() {
        let policy = DefaultLayoutPolicy::single_node(5, 3);
        let available: Vec<DomainTarget> = (0..3)
            .map(|i| DomainTarget::new(FailureDomainLevel::Device, i))
            .collect();
        let mirror = DurabilityPolicy::mirror(5).unwrap();

        let result = policy.select_targets(b"obj", &available, &mirror, FailureDomainLevel::Device);
        assert!(result.is_err());
        match result.unwrap_err() {
            LayoutPolicyError::InsufficientTargets {
                required,
                available,
                ..
            } => {
                assert_eq!(required, 5);
                assert_eq!(available, 3);
            }
            _ => panic!("wrong error variant"),
        }
    }

    #[test]
    fn select_targets_different_objects_different_targets() {
        let policy = DefaultLayoutPolicy::single_node(3, 10);
        let available: Vec<DomainTarget> = (0..10)
            .map(|i| DomainTarget::new(FailureDomainLevel::Device, i))
            .collect();
        let mirror = DurabilityPolicy::mirror(3).unwrap();

        let t1 = policy
            .select_targets(b"obj-a", &available, &mirror, FailureDomainLevel::Device)
            .unwrap();
        let t2 = policy
            .select_targets(b"obj-b", &available, &mirror, FailureDomainLevel::Device)
            .unwrap();
        // Different objects should generally select different target sets
        let any_diff = t1.iter().zip(&t2).any(|(a, b)| a.target_id != b.target_id);
        assert!(any_diff);
    }

    #[test]
    fn select_targets_erasure_style() {
        let policy = DefaultLayoutPolicy::single_node(1, 20);
        let available: Vec<DomainTarget> = (0..20)
            .map(|i| DomainTarget::new(FailureDomainLevel::Device, i))
            .collect();
        let erasure = DurabilityPolicy::erasure_style(4, 2).unwrap();

        let targets = policy
            .select_targets(
                b"erasure-obj",
                &available,
                &erasure,
                FailureDomainLevel::Device,
            )
            .unwrap();
        assert_eq!(targets.len(), 6);
    }

    // -- DefaultLayoutPolicy: validate_assignments --------------------------

    #[test]
    fn validate_assignments_passes() {
        let policy = DefaultLayoutPolicy::single_node(3, 10);
        let mirror = DurabilityPolicy::mirror(3).unwrap();
        let assignments: Vec<(u32, DomainTarget)> = vec![
            (0, DomainTarget::new(FailureDomainLevel::Device, 0)),
            (1, DomainTarget::new(FailureDomainLevel::Device, 1)),
            (2, DomainTarget::new(FailureDomainLevel::Device, 2)),
        ];

        assert!(policy
            .validate_assignments(&assignments, &mirror, FailureDomainLevel::Device)
            .is_ok());
    }

    #[test]
    fn validate_assignments_detects_co_location() {
        let policy = DefaultLayoutPolicy::single_node(3, 10);
        let mirror = DurabilityPolicy::mirror(3).unwrap();
        let assignments: Vec<(u32, DomainTarget)> = vec![
            (0, DomainTarget::new(FailureDomainLevel::Device, 0)),
            (1, DomainTarget::new(FailureDomainLevel::Device, 0)), // same device!
            (2, DomainTarget::new(FailureDomainLevel::Device, 2)),
        ];

        let result = policy.validate_assignments(&assignments, &mirror, FailureDomainLevel::Device);
        assert!(result.is_err());
    }

    // -- DefaultLayoutPolicy: tolerated_failures ----------------------------

    #[test]
    fn tolerated_failures_mirror_3() {
        let policy = DefaultLayoutPolicy::single_node(3, 10);
        assert_eq!(
            policy.tolerated_failures(&DurabilityPolicy::mirror(3).unwrap()),
            2
        );
    }

    #[test]
    fn tolerated_failures_mirror_1() {
        let policy = DefaultLayoutPolicy::single_node(1, 10);
        assert_eq!(
            policy.tolerated_failures(&DurabilityPolicy::mirror(1).unwrap()),
            0
        );
    }

    #[test]
    fn tolerated_failures_erasure_8_3() {
        let policy = DefaultLayoutPolicy::single_node(1, 20);
        assert_eq!(
            policy.tolerated_failures(&DurabilityPolicy::erasure_style(8, 3).unwrap()),
            3
        );
    }

    #[test]
    fn tolerated_failures_hybrid_2_4_2() {
        let policy = DefaultLayoutPolicy::single_node(1, 50);
        // (2-1) + 2 = 3
        assert_eq!(
            policy.tolerated_failures(&DurabilityPolicy::hybrid(2, 4, 2).unwrap()),
            3
        );
    }

    // -- DefaultLayoutPolicy: rebuild_trigger -------------------------------

    #[test]
    fn rebuild_trigger_single_node_is_any_loss() {
        let policy = DefaultLayoutPolicy::single_node(3, 10);
        assert_eq!(policy.rebuild_trigger(), RebuildTrigger::OnAnyReplicaLoss);
    }

    #[test]
    fn rebuild_trigger_multi_node_is_below_minimum() {
        let policy = DefaultLayoutPolicy::multi_node(3, 5, 2, 3, 2);
        assert_eq!(
            policy.rebuild_trigger(),
            RebuildTrigger::BelowMinimumDomains
        );
    }

    // -- DefaultLayoutPolicy: is_multi_domain -------------------------------

    #[test]
    fn is_multi_domain_single_node_false() {
        let policy = DefaultLayoutPolicy::single_node(3, 10);
        assert!(!policy.is_multi_domain());
    }

    #[test]
    fn is_multi_domain_multi_node_true() {
        let policy = DefaultLayoutPolicy::multi_node(3, 5, 2, 3, 2);
        assert!(policy.is_multi_domain());
    }

    #[test]
    fn is_multi_domain_node_only_true() {
        let policy = DefaultLayoutPolicy::multi_node(3, 5, 2, 3, 0);
        assert!(policy.is_multi_domain());
    }
}
