//! Placement constraint satisfaction engine.
//!
//! This module defines the constraint model that bridges durability layout
//! configuration and failure-domain topology to concrete placement decisions.
//!
//! ## Design
//!
//! [`PlacementConstraint`] formalizes the requirements derived from a
//! [`DurabilityLayoutV1`] and [`FailureDomainV1`]:
//!
//! - Shard count from the layout policy (copies for mirror, k+m for erasure).
//! - Failure-domain anti-affinity level (Device, Node, Rack, Datacenter).
//! - BLAKE3-verified constraint digest for tamper-proof seal/verify.
//!
//! [`ConstraintSatisfaction`] validates whether a given device pool can
//! satisfy these constraints, checking eligibility, domain count, and
//! strict-separation feasibility before any planner runs.

use std::collections::{BTreeMap, BTreeSet};

use tidefs_durability_layout::{
    DurabilityLayoutV1, DurabilityPolicy, FailureDomainLevel, FailureDomainV1,
};

use crate::DeviceHealthCapacity;

/// Domain-separated context string for BLAKE3 constraint digest derivation.
const CONSTRAINT_DIGEST_CONTEXT: &str = "TideFS PlacementConstraint v1";

/// A placement constraint that encodes shard count and failure-domain
/// anti-affinity requirements derived from a durability layout and failure
/// domain descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementConstraint {
    /// Number of shards (replicas or data+parity chunks) required.
    pub required_shards: usize,
    /// The failure-domain level at which anti-affinity is enforced.
    pub domain_level: FailureDomainLevel,
    /// The durability policy backing this constraint.
    pub policy: DurabilityPolicy,
    /// BLAKE3-derived constraint digest for tamper-proof verification.
    digest: [u8; 32],
}

impl PlacementConstraint {
    /// Create a constraint from a durability layout and failure domain
    /// descriptor, with a BLAKE3-derived integrity digest.
    pub fn new(layout: &DurabilityLayoutV1, failure_domain: &FailureDomainV1) -> Self {
        let required_shards = layout.policy.total_shards();
        let domain_level = failure_domain.level;
        let policy = layout.policy;

        let digest = Self::compute_digest(required_shards, domain_level, &policy);

        Self {
            required_shards,
            domain_level,
            policy,
            digest,
        }
    }

    /// Verify that the constraint's parameters have not been modified
    /// since construction.
    #[must_use]
    pub fn verify(&self) -> bool {
        let expected = Self::compute_digest(self.required_shards, self.domain_level, &self.policy);
        constant_time_eq(&self.digest, &expected)
    }

    /// Whether this is a mirror (replication) constraint.
    #[must_use]
    pub fn is_mirror(&self) -> bool {
        matches!(self.policy, DurabilityPolicy::Mirror { .. })
    }

    /// Whether this is an erasure-coding constraint.
    #[must_use]
    pub fn is_erasure(&self) -> bool {
        matches!(self.policy, DurabilityPolicy::ErasureStyle { .. })
    }

    /// Number of data shards (for erasure: k; for mirror: copies).
    #[must_use]
    pub fn data_shards(&self) -> usize {
        match &self.policy {
            DurabilityPolicy::Mirror { copies } => *copies as usize,
            DurabilityPolicy::ErasureStyle { data_shards, .. } => *data_shards as usize,
            DurabilityPolicy::Hybrid { data_shards, .. } => *data_shards as usize,
        }
    }

    /// Number of parity shards (0 for mirror; m for erasure k+m).
    #[must_use]
    pub fn parity_shards(&self) -> usize {
        self.required_shards.saturating_sub(self.data_shards())
    }

    /// Compute a BLAKE3-derived digest from constraint parameters.
    fn compute_digest(
        required_shards: usize,
        domain_level: FailureDomainLevel,
        policy: &DurabilityPolicy,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(CONSTRAINT_DIGEST_CONTEXT);
        hasher.update(&(required_shards as u64).to_le_bytes());
        hasher.update(&[domain_level as u8]);
        let discriminant: u8 = match policy {
            DurabilityPolicy::Mirror { .. } => 0,
            DurabilityPolicy::ErasureStyle { .. } => 1,
            DurabilityPolicy::Hybrid { .. } => 2,
        };
        hasher.update(&[discriminant]);
        hasher.finalize().into()
    }
}

// ---------------------------------------------------------------------------
// Constraint satisfaction checking
// ---------------------------------------------------------------------------

/// Result of checking whether a device set satisfies placement constraints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstraintSatisfaction {
    /// Whether any placement is possible (strict or degraded).
    pub satisfiable: bool,
    /// Number of healthy, non-full devices available.
    pub eligible_devices: usize,
    /// Number of distinct failure domains among eligible devices.
    pub distinct_domains: usize,
    /// Whether strict failure-domain separation is possible.
    pub strict_separation_possible: bool,
    /// If unsatisfiable, the reason why.
    pub failure_reason: Option<ConstraintFailureReason>,
}

/// Why a constraint cannot be satisfied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstraintFailureReason {
    /// Not enough eligible devices.
    NotEnoughDevices { required: usize, available: usize },
    /// Not enough distinct failure domains for any placement.
    NotEnoughDomains { required: usize, available: usize },
    /// No healthy devices in the pool.
    NoHealthyDevices,
    /// Healthy devices exist but all are full.
    AllDevicesFull,
}

/// Check whether a device set satisfies placement constraints.
pub fn check_satisfaction(
    constraint: &PlacementConstraint,
    devices: &[DeviceHealthCapacity],
) -> ConstraintSatisfaction {
    let eligible: Vec<&DeviceHealthCapacity> = devices.iter().filter(|d| d.can_accept()).collect();

    if eligible.is_empty() {
        let reason = if devices.iter().any(|d| d.healthy) {
            ConstraintFailureReason::AllDevicesFull
        } else {
            ConstraintFailureReason::NoHealthyDevices
        };
        return ConstraintSatisfaction {
            satisfiable: false,
            eligible_devices: 0,
            distinct_domains: 0,
            strict_separation_possible: false,
            failure_reason: Some(reason),
        };
    }

    let domains: BTreeSet<u64> = eligible
        .iter()
        .map(|d| d.failure_domain_key(constraint.domain_level))
        .collect();
    let domain_count = domains.len();
    let device_count = eligible.len();

    let has_enough_devices = device_count >= constraint.required_shards;
    let strict_possible = domain_count >= constraint.required_shards;

    if !has_enough_devices {
        ConstraintSatisfaction {
            satisfiable: false,
            eligible_devices: device_count,
            distinct_domains: domain_count,
            strict_separation_possible: false,
            failure_reason: Some(ConstraintFailureReason::NotEnoughDevices {
                required: constraint.required_shards,
                available: device_count,
            }),
        }
    } else {
        ConstraintSatisfaction {
            satisfiable: true,
            eligible_devices: device_count,
            distinct_domains: domain_count,
            strict_separation_possible: strict_possible,
            failure_reason: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Domain grouping helpers
// ---------------------------------------------------------------------------

/// Group eligible devices by their failure-domain key at the constraint's
/// domain level.
pub fn group_by_domain<'a>(
    constraint: &PlacementConstraint,
    devices: &'a [DeviceHealthCapacity],
) -> BTreeMap<u64, Vec<&'a DeviceHealthCapacity>> {
    let mut map: BTreeMap<u64, Vec<&'a DeviceHealthCapacity>> = BTreeMap::new();
    for d in devices {
        if !d.can_accept() {
            continue;
        }
        let key = d.failure_domain_key(constraint.domain_level);
        map.entry(key).or_default().push(d);
    }
    map
}

/// Domain groups sorted by device count (fewest first).
pub fn sorted_domain_groups<'a>(
    constraint: &PlacementConstraint,
    devices: &'a [DeviceHealthCapacity],
) -> Vec<(u64, Vec<&'a DeviceHealthCapacity>)> {
    let mut groups: Vec<_> = group_by_domain(constraint, devices).into_iter().collect();
    groups.sort_by_key(|(_, devs)| devs.len());
    groups
}

/// Count distinct failure domains among eligible devices.
pub fn count_distinct_domains(
    constraint: &PlacementConstraint,
    devices: &[DeviceHealthCapacity],
) -> usize {
    let keys: BTreeSet<u64> = devices
        .iter()
        .filter(|d| d.can_accept())
        .map(|d| d.failure_domain_key(constraint.domain_level))
        .collect();
    keys.len()
}

/// Collect the set of failure-domain keys occupied by a given list of
/// device targets.
pub fn domain_keys_for_targets(
    constraint: &PlacementConstraint,
    devices: &[DeviceHealthCapacity],
    targets: &[u64],
) -> BTreeSet<u64> {
    targets
        .iter()
        .filter_map(|device_id| devices.iter().find(|d| d.device_id == *device_id))
        .map(|d| d.failure_domain_key(constraint.domain_level))
        .collect()
}

// ---------------------------------------------------------------------------
// BLAKE3-verified assignment sealing
// ---------------------------------------------------------------------------

/// Context for BLAKE3 keyed sealing of placement assignments.
const ASSIGNMENT_SEAL_CONTEXT: &str = "TideFS PlacementAssignment v1";

/// Produce a BLAKE3-derived seal over a constraint and its device targets.
pub fn seal_assignment(
    constraint: &PlacementConstraint,
    object_id: u64,
    placement_key: u64,
    deterministic_seed: u64,
    device_targets: &[u64],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(ASSIGNMENT_SEAL_CONTEXT);
    hasher.update(&constraint.digest);
    hasher.update(&object_id.to_le_bytes());
    hasher.update(&placement_key.to_le_bytes());
    hasher.update(&deterministic_seed.to_le_bytes());
    for &device_id in device_targets {
        hasher.update(&device_id.to_le_bytes());
    }
    hasher.finalize().into()
}

/// Verify a seal against the expected inputs.
#[must_use]
pub fn verify_assignment(
    constraint: &PlacementConstraint,
    object_id: u64,
    placement_key: u64,
    deterministic_seed: u64,
    device_targets: &[u64],
    seal: &[u8; 32],
) -> bool {
    let expected = seal_assignment(
        constraint,
        object_id,
        placement_key,
        deterministic_seed,
        device_targets,
    );
    constant_time_eq(&expected, seal)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Constant-time byte comparison for digest/seal verification.
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut acc: u8 = 0;
    for i in 0..32 {
        acc |= a[i] ^ b[i];
    }
    acc == 0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_durability_layout::{DurabilityLayoutV1, FailureDomainLevel, FailureDomainV1};

    // -- Helpers ------------------------------------------------------------

    fn device(id: u64, node: u64, rack: u64, total_gb: u64) -> DeviceHealthCapacity {
        DeviceHealthCapacity::new(id, node, rack, total_gb * 1024 * 1024 * 1024)
    }

    fn device_unhealthy(id: u64, node: u64, rack: u64, total_gb: u64) -> DeviceHealthCapacity {
        let mut d = DeviceHealthCapacity::new(id, node, rack, total_gb * 1024 * 1024 * 1024);
        d.healthy = false;
        d
    }

    fn device_full(id: u64, node: u64, rack: u64, total_gb: u64) -> DeviceHealthCapacity {
        let mut d = DeviceHealthCapacity::new(id, node, rack, total_gb * 1024 * 1024 * 1024);
        d.used_bytes = d.total_bytes;
        d
    }

    fn mirror_layout(copies: u8) -> DurabilityLayoutV1 {
        DurabilityLayoutV1::mirror(copies).unwrap()
    }

    fn erasure_layout(k: u8, m: u8) -> DurabilityLayoutV1 {
        DurabilityLayoutV1::erasure(k, m).unwrap()
    }

    fn device_fd() -> FailureDomainV1 {
        FailureDomainV1::new(FailureDomainLevel::Device, 64).unwrap()
    }

    fn node_fd() -> FailureDomainV1 {
        FailureDomainV1::new(FailureDomainLevel::Node, 64).unwrap()
    }

    fn rack_fd() -> FailureDomainV1 {
        FailureDomainV1::new(FailureDomainLevel::Rack, 64).unwrap()
    }

    // -- PlacementConstraint construction / verify --------------------------

    #[test]
    fn constraint_mirror_3_node_level() {
        let layout = mirror_layout(3);
        let fd = node_fd();
        let c = PlacementConstraint::new(&layout, &fd);
        assert_eq!(c.required_shards, 3);
        assert_eq!(c.domain_level, FailureDomainLevel::Node);
        assert!(c.is_mirror());
        assert!(!c.is_erasure());
        assert_eq!(c.data_shards(), 3);
        assert_eq!(c.parity_shards(), 0);
        assert!(c.verify());
    }

    #[test]
    fn constraint_erasure_4_2_rack_level() {
        let layout = erasure_layout(4, 2);
        let fd = rack_fd();
        let c = PlacementConstraint::new(&layout, &fd);
        assert_eq!(c.required_shards, 6);
        assert_eq!(c.domain_level, FailureDomainLevel::Rack);
        assert!(!c.is_mirror());
        assert!(c.is_erasure());
        assert_eq!(c.data_shards(), 4);
        assert_eq!(c.parity_shards(), 2);
        assert!(c.verify());
    }

    #[test]
    fn constraint_verify_detects_tampering() {
        let layout = mirror_layout(2);
        let fd = node_fd();
        let mut c = PlacementConstraint::new(&layout, &fd);
        assert!(c.verify());
        c.required_shards = 99;
        assert!(!c.verify());
    }

    #[test]
    fn constraint_digest_differs_for_different_layouts() {
        let fd = node_fd();
        let c1 = PlacementConstraint::new(&mirror_layout(3), &fd);
        let c2 = PlacementConstraint::new(&mirror_layout(2), &fd);
        assert_ne!(c1.digest, c2.digest);
    }

    #[test]
    fn constraint_digest_differs_for_different_domain_levels() {
        let layout = mirror_layout(3);
        let c1 = PlacementConstraint::new(&layout, &node_fd());
        let c2 = PlacementConstraint::new(&layout, &rack_fd());
        assert_ne!(c1.digest, c2.digest);
    }

    #[test]
    fn constraint_digest_differs_mirror_vs_erasure_same_shard_count() {
        let fd = node_fd();
        let c_mirror = PlacementConstraint::new(&mirror_layout(6), &fd);
        let c_erasure = PlacementConstraint::new(&erasure_layout(4, 2), &fd);
        assert_ne!(c_mirror.digest, c_erasure.digest);
    }

    // -- check_satisfaction: success cases ---------------------------------

    #[test]
    fn satisfaction_mirror_2_three_devices_three_nodes_strict() {
        let c = PlacementConstraint::new(&mirror_layout(2), &node_fd());
        let devices = vec![
            device(1, 10, 100, 100),
            device(2, 20, 200, 100),
            device(3, 30, 300, 100),
        ];
        let sat = check_satisfaction(&c, &devices);
        assert!(sat.satisfiable);
        assert_eq!(sat.eligible_devices, 3);
        assert_eq!(sat.distinct_domains, 3);
        assert!(sat.strict_separation_possible);
        assert!(sat.failure_reason.is_none());
    }

    #[test]
    fn satisfaction_erasure_4_2_strict() {
        let c = PlacementConstraint::new(&erasure_layout(4, 2), &node_fd());
        let devices: Vec<_> = (0..8).map(|i| device(i, i, i / 2, 100)).collect();
        let sat = check_satisfaction(&c, &devices);
        assert!(sat.satisfiable);
        assert_eq!(sat.eligible_devices, 8);
        assert_eq!(sat.distinct_domains, 8);
        assert!(sat.strict_separation_possible);
    }

    #[test]
    fn satisfaction_degraded_when_fewer_domains_than_shards() {
        let c = PlacementConstraint::new(&mirror_layout(3), &node_fd());
        let devices = vec![
            device(1, 10, 100, 100),
            device(2, 10, 100, 100),
            device(3, 20, 200, 100),
        ];
        let sat = check_satisfaction(&c, &devices);
        assert!(sat.satisfiable);
        assert_eq!(sat.eligible_devices, 3);
        assert_eq!(sat.distinct_domains, 2);
        assert!(!sat.strict_separation_possible);
        assert!(sat.failure_reason.is_none());
    }

    #[test]
    fn satisfaction_rack_level_with_mixed_topology() {
        let c = PlacementConstraint::new(&mirror_layout(3), &rack_fd());
        let devices = vec![
            device(1, 10, 100, 100),
            device(2, 20, 200, 100),
            device(3, 30, 300, 100),
            device(4, 40, 400, 100),
        ];
        let sat = check_satisfaction(&c, &devices);
        assert!(sat.satisfiable);
        assert_eq!(sat.distinct_domains, 4);
        assert!(sat.strict_separation_possible);
    }

    // -- check_satisfaction: failure cases ---------------------------------

    #[test]
    fn satisfaction_not_enough_devices() {
        let c = PlacementConstraint::new(&mirror_layout(3), &node_fd());
        let devices = vec![device(1, 10, 100, 100), device(2, 20, 200, 100)];
        let sat = check_satisfaction(&c, &devices);
        assert!(!sat.satisfiable);
        assert!(matches!(
            sat.failure_reason,
            Some(ConstraintFailureReason::NotEnoughDevices {
                required: 3,
                available: 2
            })
        ));
    }

    #[test]
    fn satisfaction_no_healthy_devices() {
        let c = PlacementConstraint::new(&mirror_layout(1), &node_fd());
        let devices = vec![device_unhealthy(1, 10, 100, 100)];
        let sat = check_satisfaction(&c, &devices);
        assert!(!sat.satisfiable);
        assert!(matches!(
            sat.failure_reason,
            Some(ConstraintFailureReason::NoHealthyDevices)
        ));
    }

    #[test]
    fn satisfaction_all_devices_full() {
        let c = PlacementConstraint::new(&mirror_layout(1), &node_fd());
        let devices = vec![device_full(1, 10, 100, 100)];
        let sat = check_satisfaction(&c, &devices);
        assert!(!sat.satisfiable);
        assert!(matches!(
            sat.failure_reason,
            Some(ConstraintFailureReason::AllDevicesFull)
        ));
    }

    #[test]
    fn satisfaction_mixed_healthy_unhealthy_excludes_unhealthy() {
        let c = PlacementConstraint::new(&mirror_layout(2), &node_fd());
        let devices = vec![
            device_unhealthy(1, 10, 100, 100),
            device(2, 20, 200, 100),
            device(3, 30, 300, 100),
        ];
        let sat = check_satisfaction(&c, &devices);
        assert!(sat.satisfiable);
        assert_eq!(sat.eligible_devices, 2);
        assert_eq!(sat.distinct_domains, 2);
    }

    // -- Domain grouping ---------------------------------------------------

    #[test]
    fn group_by_domain_node_level_groups_by_node() {
        let c = PlacementConstraint::new(&mirror_layout(2), &node_fd());
        let devices = vec![
            device(1, 10, 100, 100),
            device(2, 10, 100, 100),
            device(3, 20, 200, 100),
        ];
        let groups = group_by_domain(&c, &devices);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[&10].len(), 2);
        assert_eq!(groups[&20].len(), 1);
    }

    #[test]
    fn group_by_domain_rack_level_groups_by_rack() {
        let c = PlacementConstraint::new(&mirror_layout(2), &rack_fd());
        let devices = vec![
            device(1, 10, 100, 100),
            device(2, 20, 100, 100),
            device(3, 30, 200, 100),
        ];
        let groups = group_by_domain(&c, &devices);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[&100].len(), 2);
        assert_eq!(groups[&200].len(), 1);
    }

    #[test]
    fn group_by_domain_excludes_unhealthy_and_full() {
        let c = PlacementConstraint::new(&mirror_layout(2), &node_fd());
        let devices = vec![
            device_unhealthy(1, 10, 100, 100),
            device_full(2, 20, 200, 100),
            device(3, 30, 300, 100),
        ];
        let groups = group_by_domain(&c, &devices);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[&30].len(), 1);
    }

    #[test]
    fn sorted_domain_groups_fewest_first() {
        let c = PlacementConstraint::new(&mirror_layout(2), &node_fd());
        let devices = vec![
            device(1, 10, 100, 100),
            device(2, 10, 100, 100),
            device(3, 10, 100, 100),
            device(4, 20, 200, 100),
        ];
        let sorted = sorted_domain_groups(&c, &devices);
        assert_eq!(sorted.len(), 2);
        assert_eq!(sorted[0].0, 20);
        assert_eq!(sorted[1].0, 10);
    }

    #[test]
    fn count_distinct_domains_device_level_each_device_own_domain() {
        let c = PlacementConstraint::new(&mirror_layout(2), &device_fd());
        let devices = vec![
            device(1, 10, 100, 100),
            device(2, 10, 100, 100),
            device(3, 10, 100, 100),
        ];
        assert_eq!(count_distinct_domains(&c, &devices), 3);
    }

    #[test]
    fn count_distinct_domains_node_level_collapses_same_node() {
        let c = PlacementConstraint::new(&mirror_layout(2), &node_fd());
        let devices = vec![
            device(1, 10, 100, 100),
            device(2, 10, 100, 100),
            device(3, 20, 200, 100),
        ];
        assert_eq!(count_distinct_domains(&c, &devices), 2);
    }

    #[test]
    fn domain_keys_for_targets_returns_correct_keys() {
        let c = PlacementConstraint::new(&mirror_layout(2), &node_fd());
        let devices = vec![
            device(1, 10, 100, 100),
            device(2, 20, 200, 100),
            device(3, 30, 300, 100),
        ];
        let keys = domain_keys_for_targets(&c, &devices, &[1, 3]);
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&10));
        assert!(keys.contains(&30));
        assert!(!keys.contains(&20));
    }

    // -- BLAKE3 assignment seal/verify -------------------------------------

    #[test]
    fn seal_and_verify_roundtrip() {
        let c = PlacementConstraint::new(&mirror_layout(3), &node_fd());
        let targets = vec![1, 2, 3];
        let seal = seal_assignment(&c, 42, 7, 0, &targets);
        assert!(verify_assignment(&c, 42, 7, 0, &targets, &seal));
    }

    #[test]
    fn verify_rejects_tampered_targets() {
        let c = PlacementConstraint::new(&mirror_layout(3), &node_fd());
        let targets = vec![1, 2, 3];
        let seal = seal_assignment(&c, 42, 7, 0, &targets);
        assert!(!verify_assignment(&c, 42, 7, 0, &[1, 2, 4], &seal));
    }

    #[test]
    fn verify_rejects_tampered_object_id() {
        let c = PlacementConstraint::new(&mirror_layout(3), &node_fd());
        let targets = vec![1, 2, 3];
        let seal = seal_assignment(&c, 42, 7, 0, &targets);
        assert!(!verify_assignment(&c, 43, 7, 0, &targets, &seal));
    }

    #[test]
    fn verify_rejects_different_constraint() {
        let c1 = PlacementConstraint::new(&mirror_layout(3), &node_fd());
        let c2 = PlacementConstraint::new(&mirror_layout(2), &node_fd());
        let targets = vec![1, 2, 3];
        let seal = seal_assignment(&c1, 42, 7, 0, &targets);
        assert!(!verify_assignment(&c2, 42, 7, 0, &targets, &seal));
    }

    #[test]
    fn seal_deterministic() {
        let c = PlacementConstraint::new(&mirror_layout(3), &node_fd());
        let targets = vec![1, 2, 3];
        let s1 = seal_assignment(&c, 42, 7, 0, &targets);
        let s2 = seal_assignment(&c, 42, 7, 0, &targets);
        assert_eq!(s1, s2);
    }

    #[test]
    fn seal_differs_for_different_targets() {
        let c = PlacementConstraint::new(&mirror_layout(3), &node_fd());
        let s1 = seal_assignment(&c, 42, 7, 0, &[1, 2, 3]);
        let s2 = seal_assignment(&c, 42, 7, 0, &[4, 5, 6]);
        assert_ne!(s1, s2);
    }

    // -- Edge cases --------------------------------------------------------

    #[test]
    fn constraint_zero_devices() {
        let c = PlacementConstraint::new(&mirror_layout(1), &node_fd());
        let sat = check_satisfaction(&c, &[]);
        assert!(!sat.satisfiable);
        assert_eq!(sat.eligible_devices, 0);
        assert!(matches!(
            sat.failure_reason,
            Some(ConstraintFailureReason::NoHealthyDevices)
        ));
    }

    #[test]
    fn constraint_exact_fit_devices() {
        let c = PlacementConstraint::new(&mirror_layout(3), &node_fd());
        let devices = vec![
            device(1, 10, 100, 100),
            device(2, 20, 200, 100),
            device(3, 30, 300, 100),
        ];
        let sat = check_satisfaction(&c, &devices);
        assert!(sat.satisfiable);
        assert!(sat.strict_separation_possible);
    }

    #[test]
    fn constraint_erasure_8_3_large_topology() {
        let c = PlacementConstraint::new(&erasure_layout(8, 3), &rack_fd());
        let devices: Vec<_> = (0..20).map(|i| device(i, i % 10, i, 100)).collect();
        let sat = check_satisfaction(&c, &devices);
        assert!(sat.satisfiable);
        assert_eq!(c.required_shards, 11);
        assert!(sat.strict_separation_possible);
        assert_eq!(sat.distinct_domains, 20);
    }

    #[test]
    fn constraint_all_same_domain() {
        let c = PlacementConstraint::new(&mirror_layout(3), &node_fd());
        let devices = vec![
            device(1, 10, 100, 100),
            device(2, 10, 100, 100),
            device(3, 10, 100, 100),
        ];
        let sat = check_satisfaction(&c, &devices);
        assert!(sat.satisfiable);
        assert_eq!(sat.distinct_domains, 1);
        assert!(!sat.strict_separation_possible);
    }
}
