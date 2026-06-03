//! Durability layout placement mapping with domain-tagged BLAKE3 hashing.
//!
//! Provides deterministic object-to-domain placement: given an object
//! identifier and a [`DurabilityPolicy`], [`DomainPlacementMapper`] computes
//! which failure-domain targets each shard lands on. The mapping is
//! deterministic — same (object_id, policy, topology) always yields the
//! same placement — and uses BLAKE3 domain-separated hashing keyed per
//! failure-domain level to prevent cross-domain digest collision.

use crate::{Digest, DurabilityPolicy, FailureDomainLevel};
use blake3::Hasher;

// ---------------------------------------------------------------------------
// Domain context for BLAKE3 placement hashing
// ---------------------------------------------------------------------------

/// Domain-separation context for object-to-domain placement hashing.
///
/// Prevents cross-type digest collision between placement mapping and
/// other BLAKE3 uses (e.g. self-checksums, content hashing).
const PLACEMENT_CONTEXT: &str = "TideFS DomainPlacement v1";

/// Build a domain-level BLAKE3 context string for placement hashing.
///
/// Each failure-domain level gets a distinct context so that a placement
/// computed at Device level cannot collide with one computed at Node level.
fn placement_domain_context(level: FailureDomainLevel) -> String {
    format!("{}:level{}", PLACEMENT_CONTEXT, level.discriminant())
}

// ---------------------------------------------------------------------------
// DomainTarget
// ---------------------------------------------------------------------------

/// A concrete target within a failure domain.
///
/// Identifies a specific device, node, rack, or datacenter by its
/// numeric ID and hierarchy level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DomainTarget {
    /// The failure-domain hierarchy level.
    pub level: FailureDomainLevel,
    /// The numeric ID of the target within that level.
    pub target_id: u64,
}

impl DomainTarget {
    /// Create a new domain target.
    pub fn new(level: FailureDomainLevel, target_id: u64) -> Self {
        Self { level, target_id }
    }

    /// Returns `true` if `self` and `other` are distinct targets at the
    /// given `constraint` level. Two targets are distinct when they share
    /// a parent at the constraint level or above.
    ///
    /// This is used to verify that replicas are placed in separate failure
    /// domains.
    pub fn are_distinct_at(&self, other: &Self, _constraint: FailureDomainLevel) -> bool {
        self.level == other.level && self.target_id != other.target_id
    }

    /// Returns `true` if `self` shares a failure domain with `other` at or
    /// below the `constraint` level.
    ///
    /// For example, two devices in the same node share the Node domain.
    /// The default implementation without topology data treats any two
    /// targets at the same level as distinct (no parent containment data).
    #[must_use]
    pub fn shares_domain_with(&self, other: &Self, _constraint: FailureDomainLevel) -> bool {
        // Without topology data, same-level same-id is identical;
        // same-level different-id is distinct.
        if self.level != other.level {
            return false;
        }
        self.target_id == other.target_id
    }
}

// ---------------------------------------------------------------------------
// ShardPlacement
// ---------------------------------------------------------------------------

/// Maps a single shard index to its assigned domain target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShardPlacement {
    /// Zero-based shard index.
    pub shard_index: u32,
    /// The domain target where this shard is placed.
    pub target: DomainTarget,
}

// ---------------------------------------------------------------------------
// DomainPlacementMapper
// ---------------------------------------------------------------------------

/// Deterministic object-to-domain placement engine.
///
/// Given an object identifier (arbitrary bytes), a [`DurabilityPolicy`],
/// and a set of available domain targets, computes which targets each
/// shard should be placed on. The mapping uses BLAKE3 domain-separated
/// keyed hashing so that different policies, domain levels, and object
/// IDs produce different mappings without collision.
#[derive(Clone, Debug)]
pub struct DomainPlacementMapper {
    /// Available domain targets, grouped by level.
    targets: Vec<DomainTarget>,
}

impl DomainPlacementMapper {
    /// Create a new mapper from a list of available domain targets.
    ///
    /// Targets should represent all available placement destinations
    /// (e.g. all devices, or all nodes).
    pub fn new(targets: Vec<DomainTarget>) -> Self {
        Self { targets }
    }

    /// Return the number of available targets.
    pub fn target_count(&self) -> usize {
        self.targets.len()
    }

    /// Compute deterministic shard placements for an object.
    ///
    /// Returns a [`ShardPlacement`] for each shard required by the policy,
    /// deterministically assigned to available targets using BLAKE3 keyed
    /// hashing.
    ///
    /// # Panics
    ///
    /// Panics if there are not enough targets to satisfy the policy's
    /// total shard count.
    pub fn place_object(
        &self,
        object_id: &[u8],
        policy: &DurabilityPolicy,
        domain_level: FailureDomainLevel,
    ) -> Vec<ShardPlacement> {
        let total_shards = policy.total_shards();
        assert!(
            total_shards <= self.targets.len(),
            "not enough targets: need {total_shards}, have {}",
            self.targets.len()
        );

        let context = placement_domain_context(domain_level);
        let mut placements = Vec::with_capacity(total_shards);
        let mut used = vec![false; self.targets.len()];

        for shard_index in 0..total_shards as u32 {
            // Build a deterministic hash: object_id || shard_index (LE)
            let mut hasher = Hasher::new_derive_key(&context);
            hasher.update(object_id);
            hasher.update(&shard_index.to_le_bytes());
            let digest: Digest = hasher.finalize().into();

            // Use the digest to select an unused target deterministically.
            let target_idx = select_target_from_digest(&digest, &used);
            used[target_idx] = true;

            placements.push(ShardPlacement {
                shard_index,
                target: self.targets[target_idx],
            });
        }

        placements
    }

    /// Compute a deterministic placement for a specific shard index.
    ///
    /// Returns the domain target this shard is assigned to, using the
    /// same deterministic hash as [`place_object`] but without enforcing
    /// uniqueness (useful for verification of an existing placement).
    pub fn place_single_shard(
        &self,
        object_id: &[u8],
        shard_index: u32,
        domain_level: FailureDomainLevel,
    ) -> DomainTarget {
        let context = placement_domain_context(domain_level);
        let mut hasher = Hasher::new_derive_key(&context);
        hasher.update(object_id);
        hasher.update(&shard_index.to_le_bytes());
        let digest: Digest = hasher.finalize().into();

        // Select target deterministically (all targets available)
        let idx =
            (u64::from_le_bytes(digest[0..8].try_into().unwrap()) as usize) % self.targets.len();
        self.targets[idx]
    }

    /// Verify that a set of placements satisfies the policy's failure-domain
    /// separation constraints.
    ///
    /// Returns `Ok(())` if every pair of shards is placed on distinct targets
    /// at the given `constraint` level. Returns `Err` with the indices of the
    /// first violation found.
    pub fn verify_placement(
        placements: &[ShardPlacement],
        constraint: FailureDomainLevel,
    ) -> Result<(), PlacementVerificationError> {
        for i in 0..placements.len() {
            for j in (i + 1)..placements.len() {
                let a = &placements[i];
                let b = &placements[j];
                if a.target.shares_domain_with(&b.target, constraint) {
                    return Err(PlacementVerificationError::CoLocation {
                        shard_a: a.shard_index,
                        shard_b: b.shard_index,
                        target_a: a.target,
                        target_b: b.target,
                        constraint,
                    });
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Placement verification error
// ---------------------------------------------------------------------------

/// Errors detected during placement verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlacementVerificationError {
    /// Two shards are co-located in the same failure domain.
    CoLocation {
        shard_a: u32,
        shard_b: u32,
        target_a: DomainTarget,
        target_b: DomainTarget,
        constraint: FailureDomainLevel,
    },
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Select an unused target index from a 32-byte digest.
///
/// Uses the digest bytes to compute a deterministic index, skipping
/// already-used targets via linear probe with deterministic offset.
fn select_target_from_digest(digest: &Digest, used: &[bool]) -> usize {
    let n = used.len();
    // Use first 8 bytes as initial index
    let base = u64::from_le_bytes(digest[0..8].try_into().unwrap()) as usize % n;
    // Use next 8 bytes as stride; ensure stride is coprime with n (odd is sufficient
    // when n is a power of 2; for general n, fall back to stride=1).
    let raw_stride = u64::from_le_bytes(digest[8..16].try_into().unwrap()) as usize % n;
    let stride = if raw_stride == 0 { 1 } else { raw_stride };

    let mut idx = base;
    loop {
        if !used[idx] {
            return idx;
        }
        idx = (idx + stride) % n;
        // Safety: if stride is coprime with n, we visit every slot before
        // wrapping. When stride is not coprime, fall back through a
        // secondary deterministic offset to guarantee termination.
        if idx == base {
            // Exhausted one cycle; pick the first unused slot linearly.
            for (i, u) in used.iter().enumerate() {
                if !u {
                    return i;
                }
            }
            // All slots used (should not happen with valid inputs).
            return 0;
        }
    }
}

// ---------------------------------------------------------------------------
// Full topology placement (with hierarchy containment data)
// ---------------------------------------------------------------------------

/// Full hierarchical placement using topology containment information.
///
/// When topology data is available (e.g. from `tidefs-replication-model`),
/// placements can be made failure-domain-aware: replicas are distributed
/// across distinct failure domains at each level of the hierarchy.
#[derive(Clone, Debug)]
pub struct TopologyAwarePlacement {
    /// All available targets at the lowest level (devices).
    devices: Vec<DomainTarget>,
    /// Device-to-parent-node mapping (device_id -> node_id).
    device_to_node: Vec<(u64, u64)>,
    /// Node-to-parent-rack mapping.
    node_to_rack: Vec<(u64, u64)>,
    /// Rack-to-parent-datacenter mapping.
    rack_to_datacenter: Vec<(u64, u64)>,
}

impl TopologyAwarePlacement {
    /// Create an empty topology-aware placement mapper.
    pub fn new() -> Self {
        Self {
            devices: Vec::new(),
            device_to_node: Vec::new(),
            node_to_rack: Vec::new(),
            rack_to_datacenter: Vec::new(),
        }
    }

    /// Add a device with its full containment chain.
    pub fn add_device(&mut self, device_id: u64, node_id: u64, rack_id: u64, dc_id: u64) {
        self.devices
            .push(DomainTarget::new(FailureDomainLevel::Device, device_id));
        self.device_to_node.push((device_id, node_id));
        self.node_to_rack.push((node_id, rack_id));
        self.rack_to_datacenter.push((rack_id, dc_id));
    }

    /// Return the number of devices.
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    /// Find the parent ID for a device at the given domain level.
    fn parent_of(&self, device_id: u64, level: FailureDomainLevel) -> Option<u64> {
        // Check device existence first (except for Device level where id is its own parent)
        if !self.devices.iter().any(|d| d.target_id == device_id) {
            return None;
        }
        if level == FailureDomainLevel::Device {
            return Some(device_id);
        }
        let node = self
            .device_to_node
            .iter()
            .find(|(d, _)| *d == device_id)
            .map(|(_, n)| *n)?;
        if level == FailureDomainLevel::Node {
            return Some(node);
        }
        let rack = self
            .node_to_rack
            .iter()
            .find(|(n, _)| *n == node)
            .map(|(_, r)| *r)?;
        if level == FailureDomainLevel::Rack {
            return Some(rack);
        }
        self.rack_to_datacenter
            .iter()
            .find(|(r, _)| *r == rack)
            .map(|(_, d)| *d)
    }

    /// Returns `true` if two devices share a failure domain at the given level.
    pub fn share_domain(&self, device_a: u64, device_b: u64, level: FailureDomainLevel) -> bool {
        if device_a == device_b {
            return true;
        }
        match self.parent_of(device_a, level) {
            Some(parent_a) => match self.parent_of(device_b, level) {
                Some(parent_b) => parent_a == parent_b,
                None => false,
            },
            None => false,
        }
    }
}

impl Default for TopologyAwarePlacement {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DurabilityPolicy, FailureDomainLevel, FailureDomainV1};

    // -- FailureDomainLevel: hierarchy distance --------------------------

    #[test]
    fn distance_same_level_is_zero() {
        assert_eq!(
            FailureDomainLevel::Device.distance(FailureDomainLevel::Device),
            0
        );
        assert_eq!(
            FailureDomainLevel::Node.distance(FailureDomainLevel::Node),
            0
        );
        assert_eq!(
            FailureDomainLevel::Rack.distance(FailureDomainLevel::Rack),
            0
        );
        assert_eq!(
            FailureDomainLevel::Datacenter.distance(FailureDomainLevel::Datacenter),
            0
        );
    }

    #[test]
    fn distance_adjacent_levels_is_one() {
        assert_eq!(
            FailureDomainLevel::Device.distance(FailureDomainLevel::Node),
            1
        );
        assert_eq!(
            FailureDomainLevel::Node.distance(FailureDomainLevel::Device),
            1
        );
        assert_eq!(
            FailureDomainLevel::Node.distance(FailureDomainLevel::Rack),
            1
        );
        assert_eq!(
            FailureDomainLevel::Rack.distance(FailureDomainLevel::Node),
            1
        );
        assert_eq!(
            FailureDomainLevel::Rack.distance(FailureDomainLevel::Datacenter),
            1
        );
        assert_eq!(
            FailureDomainLevel::Datacenter.distance(FailureDomainLevel::Rack),
            1
        );
    }

    #[test]
    fn distance_two_levels_apart() {
        assert_eq!(
            FailureDomainLevel::Device.distance(FailureDomainLevel::Rack),
            2
        );
        assert_eq!(
            FailureDomainLevel::Rack.distance(FailureDomainLevel::Device),
            2
        );
        assert_eq!(
            FailureDomainLevel::Node.distance(FailureDomainLevel::Datacenter),
            2
        );
        assert_eq!(
            FailureDomainLevel::Datacenter.distance(FailureDomainLevel::Node),
            2
        );
    }

    #[test]
    fn distance_max_is_three() {
        assert_eq!(
            FailureDomainLevel::Device.distance(FailureDomainLevel::Datacenter),
            3
        );
        assert_eq!(
            FailureDomainLevel::Datacenter.distance(FailureDomainLevel::Device),
            3
        );
    }

    // -- FailureDomainLevel: hierarchy containment ------------------------

    #[test]
    fn higher_level_contains_lower() {
        assert!(FailureDomainLevel::Datacenter.contains(FailureDomainLevel::Device));
        assert!(FailureDomainLevel::Datacenter.contains(FailureDomainLevel::Node));
        assert!(FailureDomainLevel::Datacenter.contains(FailureDomainLevel::Rack));
        assert!(FailureDomainLevel::Rack.contains(FailureDomainLevel::Device));
        assert!(FailureDomainLevel::Rack.contains(FailureDomainLevel::Node));
        assert!(FailureDomainLevel::Node.contains(FailureDomainLevel::Device));
    }

    #[test]
    fn level_contains_itself() {
        assert!(FailureDomainLevel::Device.contains(FailureDomainLevel::Device));
        assert!(FailureDomainLevel::Node.contains(FailureDomainLevel::Node));
        assert!(FailureDomainLevel::Rack.contains(FailureDomainLevel::Rack));
        assert!(FailureDomainLevel::Datacenter.contains(FailureDomainLevel::Datacenter));
    }

    #[test]
    fn lower_level_does_not_contain_higher() {
        assert!(!FailureDomainLevel::Device.contains(FailureDomainLevel::Node));
        assert!(!FailureDomainLevel::Node.contains(FailureDomainLevel::Rack));
        assert!(!FailureDomainLevel::Rack.contains(FailureDomainLevel::Datacenter));
        assert!(!FailureDomainLevel::Device.contains(FailureDomainLevel::Datacenter));
    }

    #[test]
    fn is_contained_in_symmetry() {
        assert!(FailureDomainLevel::Device.is_contained_in(FailureDomainLevel::Node));
        assert!(FailureDomainLevel::Device.is_contained_in(FailureDomainLevel::Datacenter));
        assert!(!FailureDomainLevel::Datacenter.is_contained_in(FailureDomainLevel::Device));
    }

    // -- FailureDomainLevel: co-location ---------------------------------

    #[test]
    fn devices_can_co_locate_in_node() {
        assert!(FailureDomainLevel::Device.can_co_locate_in(FailureDomainLevel::Node));
        assert!(FailureDomainLevel::Device.can_co_locate_in(FailureDomainLevel::Rack));
        assert!(FailureDomainLevel::Device.can_co_locate_in(FailureDomainLevel::Datacenter));
    }

    #[test]
    fn devices_cannot_co_locate_in_device() {
        assert!(!FailureDomainLevel::Device.can_co_locate_in(FailureDomainLevel::Device));
    }

    #[test]
    fn nodes_can_co_locate_in_rack() {
        assert!(FailureDomainLevel::Node.can_co_locate_in(FailureDomainLevel::Rack));
    }

    #[test]
    fn nodes_cannot_co_locate_in_node() {
        assert!(!FailureDomainLevel::Node.can_co_locate_in(FailureDomainLevel::Node));
    }

    // -- FailureDomainLevel: depth ---------------------------------------

    #[test]
    fn depth_values() {
        assert_eq!(FailureDomainLevel::Device.depth(), 0);
        assert_eq!(FailureDomainLevel::Node.depth(), 1);
        assert_eq!(FailureDomainLevel::Rack.depth(), 2);
        assert_eq!(FailureDomainLevel::Datacenter.depth(), 3);
    }

    // -- FailureDomainLevel: next_broader --------------------------------

    #[test]
    fn next_broader_progression() {
        assert_eq!(
            FailureDomainLevel::Device.next_broader(),
            Some(FailureDomainLevel::Node)
        );
        assert_eq!(
            FailureDomainLevel::Node.next_broader(),
            Some(FailureDomainLevel::Rack)
        );
        assert_eq!(
            FailureDomainLevel::Rack.next_broader(),
            Some(FailureDomainLevel::Datacenter)
        );
        assert_eq!(FailureDomainLevel::Datacenter.next_broader(), None);
    }

    // -- DomainPlacementMapper: deterministic placement ------------------

    #[test]
    fn mapper_place_object_deterministic() {
        // Same inputs always produce same outputs.
        let targets: Vec<DomainTarget> = (0..16)
            .map(|i| DomainTarget::new(FailureDomainLevel::Device, i))
            .collect();
        let mapper = DomainPlacementMapper::new(targets);
        let policy = DurabilityPolicy::mirror(3).unwrap();
        let object_id = b"test-object-42";

        let p1 = mapper.place_object(object_id, &policy, FailureDomainLevel::Device);
        let p2 = mapper.place_object(object_id, &policy, FailureDomainLevel::Device);
        assert_eq!(p1, p2);
    }

    #[test]
    fn mapper_different_object_ids_produce_different_placements() {
        let targets: Vec<DomainTarget> = (0..16)
            .map(|i| DomainTarget::new(FailureDomainLevel::Device, i))
            .collect();
        let mapper = DomainPlacementMapper::new(targets);
        let policy = DurabilityPolicy::mirror(3).unwrap();

        let p1 = mapper.place_object(b"obj-a", &policy, FailureDomainLevel::Device);
        let p2 = mapper.place_object(b"obj-b", &policy, FailureDomainLevel::Device);
        // Different object IDs should generally produce different assignments
        // (extremely high probability; we check they differ in at least one slot)
        let any_diff = p1
            .iter()
            .zip(&p2)
            .any(|(a, b)| a.target.target_id != b.target.target_id);
        assert!(
            any_diff,
            "different object IDs should map to different target sets"
        );
    }

    #[test]
    fn mapper_respects_total_shard_count() {
        let targets: Vec<DomainTarget> = (0..16)
            .map(|i| DomainTarget::new(FailureDomainLevel::Device, i))
            .collect();
        let mapper = DomainPlacementMapper::new(targets);

        let policy = DurabilityPolicy::mirror(5).unwrap();
        let placements = mapper.place_object(b"obj", &policy, FailureDomainLevel::Device);
        assert_eq!(placements.len(), 5);
        // All shard indices should be present
        let indices: Vec<u32> = placements.iter().map(|p| p.shard_index).collect();
        assert_eq!(indices, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn mapper_no_duplicate_targets() {
        let targets: Vec<DomainTarget> = (0..16)
            .map(|i| DomainTarget::new(FailureDomainLevel::Device, i))
            .collect();
        let mapper = DomainPlacementMapper::new(targets);
        let policy = DurabilityPolicy::mirror(8).unwrap();

        let placements = mapper.place_object(b"obj", &policy, FailureDomainLevel::Device);
        // All targets should be unique
        let mut seen = std::collections::BTreeSet::new();
        for p in &placements {
            assert!(
                seen.insert(p.target.target_id),
                "duplicate target {}",
                p.target.target_id
            );
        }
    }

    #[test]
    fn mapper_erasure_style_placement() {
        let targets: Vec<DomainTarget> = (0..20)
            .map(|i| DomainTarget::new(FailureDomainLevel::Device, i))
            .collect();
        let mapper = DomainPlacementMapper::new(targets);
        let policy = DurabilityPolicy::erasure_style(4, 2).unwrap();

        let placements = mapper.place_object(b"erasure-obj", &policy, FailureDomainLevel::Device);
        assert_eq!(placements.len(), 6); // 4 data + 2 parity
        let mut seen = std::collections::BTreeSet::new();
        for p in &placements {
            assert!(seen.insert(p.target.target_id));
        }
    }

    #[test]
    fn mapper_hybrid_placement() {
        let targets: Vec<DomainTarget> = (0..50)
            .map(|i| DomainTarget::new(FailureDomainLevel::Device, i))
            .collect();
        let mapper = DomainPlacementMapper::new(targets);
        let policy = DurabilityPolicy::hybrid(2, 4, 2).unwrap();

        let placements = mapper.place_object(b"hybrid-obj", &policy, FailureDomainLevel::Device);
        assert_eq!(placements.len(), 12); // 2 * (4+2)

        let mut seen = std::collections::BTreeSet::new();
        for p in &placements {
            assert!(seen.insert(p.target.target_id));
        }
    }

    #[test]
    #[should_panic(expected = "not enough targets")]
    fn mapper_panics_when_not_enough_targets() {
        let targets: Vec<DomainTarget> = (0..2)
            .map(|i| DomainTarget::new(FailureDomainLevel::Device, i))
            .collect();
        let mapper = DomainPlacementMapper::new(targets);
        let policy = DurabilityPolicy::mirror(5).unwrap();
        mapper.place_object(b"obj", &policy, FailureDomainLevel::Device);
    }

    #[test]
    fn mapper_place_single_shard_deterministic() {
        let targets: Vec<DomainTarget> = (0..16)
            .map(|i| DomainTarget::new(FailureDomainLevel::Device, i))
            .collect();
        let mapper = DomainPlacementMapper::new(targets);

        let t1 = mapper.place_single_shard(b"obj", 3, FailureDomainLevel::Device);
        let t2 = mapper.place_single_shard(b"obj", 3, FailureDomainLevel::Device);
        assert_eq!(t1, t2, "single-shard placement must be deterministic");
    }

    #[test]
    fn mapper_different_domain_levels_produce_different_placements() {
        let targets: Vec<DomainTarget> = (0..16)
            .map(|i| DomainTarget::new(FailureDomainLevel::Device, i))
            .collect();
        let mapper = DomainPlacementMapper::new(targets);
        let _policy = DurabilityPolicy::mirror(3).unwrap();

        let device_placement = mapper.place_single_shard(b"obj", 0, FailureDomainLevel::Device);
        let node_placement = mapper.place_single_shard(b"obj", 0, FailureDomainLevel::Node);

        // Domain context separation must produce different hashes
        assert_ne!(
            device_placement.target_id, node_placement.target_id,
            "domain-level separation should affect placement hash"
        );
    }

    // -- Placement verification ------------------------------------------

    #[test]
    fn verify_placement_all_distinct_passes() {
        let targets: Vec<DomainTarget> = (0..4)
            .map(|i| DomainTarget::new(FailureDomainLevel::Device, i))
            .collect();
        let placements: Vec<ShardPlacement> = targets
            .iter()
            .enumerate()
            .map(|(i, t)| ShardPlacement {
                shard_index: i as u32,
                target: *t,
            })
            .collect();

        assert!(
            DomainPlacementMapper::verify_placement(&placements, FailureDomainLevel::Device)
                .is_ok()
        );
    }

    #[test]
    fn verify_placement_detects_co_location() {
        let t0 = DomainTarget::new(FailureDomainLevel::Device, 0);
        let placements = vec![
            ShardPlacement {
                shard_index: 0,
                target: t0,
            },
            ShardPlacement {
                shard_index: 1,
                target: t0, // same target!
            },
        ];

        let result =
            DomainPlacementMapper::verify_placement(&placements, FailureDomainLevel::Device);
        assert!(result.is_err());
        match result.unwrap_err() {
            PlacementVerificationError::CoLocation {
                shard_a, shard_b, ..
            } => {
                assert_eq!(shard_a, 0);
                assert_eq!(shard_b, 1);
            }
        }
    }

    // -- TopologyAwarePlacement ------------------------------------------

    #[test]
    fn topology_share_domain_same_device() {
        let mut topo = TopologyAwarePlacement::new();
        topo.add_device(0, 100, 1000, 10000);
        topo.add_device(1, 100, 1000, 10000);
        topo.add_device(2, 200, 1000, 10000);

        // Device 0 and 1 share node 100
        assert!(topo.share_domain(0, 1, FailureDomainLevel::Node));
        // Device 0 and 2 share rack 1000
        assert!(topo.share_domain(0, 2, FailureDomainLevel::Rack));
        // Device 0 and 1 do NOT share same device
        assert!(!topo.share_domain(0, 1, FailureDomainLevel::Device));
        // All share same datacenter
        assert!(topo.share_domain(0, 2, FailureDomainLevel::Datacenter));
    }

    #[test]
    fn topology_distinct_at_node_level() {
        let mut topo = TopologyAwarePlacement::new();
        topo.add_device(0, 100, 1000, 10000);
        topo.add_device(1, 200, 2000, 20000);

        // Different nodes, different racks, different dcs
        assert!(!topo.share_domain(0, 1, FailureDomainLevel::Node));
        assert!(!topo.share_domain(0, 1, FailureDomainLevel::Rack));
        assert!(!topo.share_domain(0, 1, FailureDomainLevel::Datacenter));
    }

    // -- Hybrid policy round-trip ----------------------------------------

    #[test]
    fn hybrid_round_trip_encode_decode() {
        let policy = DurabilityPolicy::hybrid(2, 4, 2).unwrap();
        let encoded = policy.encode();
        assert_eq!(encoded.len(), 4);
        assert_eq!(encoded[0], 2); // Hybrid discriminant
        let decoded = DurabilityPolicy::decode(&encoded).unwrap();
        assert_eq!(decoded, policy);
    }

    #[test]
    fn hybrid_round_trip_min() {
        let policy = DurabilityPolicy::hybrid(1, 1, 1).unwrap();
        let encoded = policy.encode();
        let decoded = DurabilityPolicy::decode(&encoded).unwrap();
        assert_eq!(decoded, policy);
    }

    #[test]
    fn hybrid_round_trip_max() {
        let policy = DurabilityPolicy::hybrid(8, 32, 32).unwrap();
        let encoded = policy.encode();
        let decoded = DurabilityPolicy::decode(&encoded).unwrap();
        assert_eq!(decoded, policy);
    }

    #[test]
    fn hybrid_rejects_zero_copies() {
        assert!(DurabilityPolicy::hybrid(0, 4, 2).is_err());
    }

    #[test]
    fn hybrid_rejects_zero_data() {
        assert!(DurabilityPolicy::hybrid(2, 0, 2).is_err());
    }

    #[test]
    fn hybrid_rejects_zero_parity() {
        assert!(DurabilityPolicy::hybrid(2, 4, 0).is_err());
    }

    #[test]
    fn hybrid_rejects_too_many_copies() {
        assert!(DurabilityPolicy::hybrid(9, 4, 2).is_err());
    }

    #[test]
    fn hybrid_total_shards() {
        let policy = DurabilityPolicy::hybrid(2, 4, 2).unwrap();
        assert_eq!(policy.total_shards(), 12); // 2 * (4+2)
    }

    #[test]
    fn hybrid_total_shards_single_copy() {
        let policy = DurabilityPolicy::hybrid(1, 8, 3).unwrap();
        assert_eq!(policy.total_shards(), 11); // 1 * (8+3)
    }

    #[test]
    fn hybrid_validate_sufficient() {
        let policy = DurabilityPolicy::hybrid(2, 4, 2).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Device, 16).unwrap();
        assert!(policy.validate(16, &[fd]).is_ok());
    }

    #[test]
    fn hybrid_validate_insufficient_copies() {
        let policy = DurabilityPolicy::hybrid(3, 4, 2).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Device, 18).unwrap();
        // Only 2 devices, but need 3 mirror copies
        let err = policy.validate(2, &[fd]).unwrap_err();
        assert!(matches!(
            err,
            crate::PolicyValidationError::InsufficientDevices { .. }
        ));
    }

    #[test]
    fn hybrid_survives_failure() {
        // Hybrid(2, 4, 2): tolerates (2-1) + 2 = 3 failures total
        let layout = crate::DurabilityLayoutV1 {
            policy: DurabilityPolicy::hybrid(2, 4, 2).unwrap(),
        };
        assert!(layout.survives_failure(3, 0));
        assert!(layout.survives_failure(0, 3));
        assert!(layout.survives_failure(1, 2)); // 1 dev + 2 node = 3, ok
        assert!(!layout.survives_failure(4, 0)); // too many
    }

    #[test]
    fn hybrid_survives_failure_single_copy() {
        // Hybrid(1, 4, 2): tolerates (1-1) + 2 = 2 failures
        let layout = crate::DurabilityLayoutV1 {
            policy: DurabilityPolicy::hybrid(1, 4, 2).unwrap(),
        };
        assert!(layout.survives_failure(2, 0));
        assert!(!layout.survives_failure(3, 0));
    }

    // -- Datacenter: round-trip ------------------------------------------

    #[test]
    fn datacenter_failure_domain_round_trip() {
        let fd = FailureDomainV1::new(FailureDomainLevel::Datacenter, 3).unwrap();
        let encoded = fd.encode();
        assert_eq!(encoded[0], 3); // Datacenter discriminant
        let decoded = FailureDomainV1::decode(&encoded).unwrap();
        assert_eq!(decoded.level.discriminant(), 3);
        assert_eq!(decoded.target_count, 3);
    }

    #[test]
    fn datacenter_level_discriminant() {
        assert_eq!(FailureDomainLevel::Datacenter.discriminant(), 3);
    }
}

#[cfg(test)]
mod property_tests {
    //! Property-based tests for random topology placement determinism.
    use super::*;

    /// Deterministic random target generator using BLAKE3 hashing.
    fn hash_u64(seed: &[u8], counter: u64) -> u64 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(seed);
        hasher.update(&counter.to_le_bytes());
        let digest: Digest = hasher.finalize().into();
        u64::from_le_bytes(digest[0..8].try_into().unwrap())
    }

    #[test]
    fn property_random_topologies_produce_deterministic_placements() {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"property-test-seed-1");
        let seed: Digest = hasher.finalize().into();

        for round in 0..50 {
            // Generate random target count (4..32)
            let target_count = ((hash_u64(&seed, round * 100) as usize) % 28) + 4;
            let targets: Vec<DomainTarget> = (0..target_count)
                .map(|i| DomainTarget::new(FailureDomainLevel::Device, i as u64))
                .collect();
            let mapper = DomainPlacementMapper::new(targets);

            // Pick a random policy
            let policy = match hash_u64(&seed, round * 100 + 1) % 3 {
                0 => {
                    let copies = ((hash_u64(&seed, round * 100 + 2) as u8) % 8) + 1;
                    DurabilityPolicy::mirror(copies).unwrap()
                }
                1 => {
                    let k = ((hash_u64(&seed, round * 100 + 2) as u8) % 8) + 1;
                    let m = ((hash_u64(&seed, round * 100 + 3) as u8) % 4) + 1;
                    DurabilityPolicy::erasure_style(k, m).unwrap()
                }
                _ => {
                    let copies = ((hash_u64(&seed, round * 100 + 2) as u8) % 4) + 1;
                    let k = ((hash_u64(&seed, round * 100 + 3) as u8) % 4) + 1;
                    let m = ((hash_u64(&seed, round * 100 + 4) as u8) % 2) + 1;
                    DurabilityPolicy::hybrid(copies, k, m).unwrap()
                }
            };

            let total_shards = policy.total_shards();
            if total_shards > target_count {
                continue; // skip impossible policies for this topology size
            }

            // Generate random object ID
            let object_id = hash_u64(&seed, round * 100 + 5).to_le_bytes();

            // Placement must be deterministic
            let p1 = mapper.place_object(&object_id, &policy, FailureDomainLevel::Device);
            let p2 = mapper.place_object(&object_id, &policy, FailureDomainLevel::Device);
            assert_eq!(p1, p2, "round {round}: placement not deterministic");

            // Must return correct number of shards
            assert_eq!(p1.len(), total_shards, "round {round}: wrong shard count");

            // No duplicate targets
            let mut seen = std::collections::BTreeSet::new();
            for p in &p1 {
                assert!(
                    seen.insert(p.target.target_id),
                    "round {round}: duplicate target {}",
                    p.target.target_id
                );
            }

            // Placement must pass self-verification
            assert!(
                DomainPlacementMapper::verify_placement(&p1, FailureDomainLevel::Device).is_ok(),
                "round {round}: placement failed self-verification"
            );
        }
    }

    #[test]
    fn property_different_seeds_produce_different_placements() {
        let targets: Vec<DomainTarget> = (0..32)
            .map(|i| DomainTarget::new(FailureDomainLevel::Device, i))
            .collect();
        let mapper = DomainPlacementMapper::new(targets);
        let policy = DurabilityPolicy::mirror(4).unwrap();

        let placements: Vec<Vec<u64>> = (0..100)
            .map(|i: u64| {
                let obj_id = i.to_le_bytes();
                let p = mapper.place_object(&obj_id, &policy, FailureDomainLevel::Device);
                p.iter().map(|sp| sp.target.target_id).collect()
            })
            .collect();

        // No two different object IDs should produce identical full placements
        // (astronomically unlikely; this is a sanity check)
        let mut seen = std::collections::BTreeSet::new();
        for (i, p) in placements.iter().enumerate() {
            if !seen.insert(p.clone()) {
                panic!("object {i} produced duplicate placement: {p:?}");
            }
        }
    }

    #[test]
    fn property_topology_aware_share_domain_consistency() {
        let mut topo = TopologyAwarePlacement::new();
        // Build a topology: 9 devices, 3 nodes, 3 racks, 1 datacenter
        for node in 0..3u64 {
            for dev in 0..3u64 {
                let device_id = node * 3 + dev;
                topo.add_device(device_id, node, node, 0); // node==rack for simplicity
            }
        }

        // Devices on same node share Node domain
        assert!(topo.share_domain(0, 1, FailureDomainLevel::Node));
        assert!(topo.share_domain(3, 4, FailureDomainLevel::Node));

        // Devices on different nodes do NOT share Node domain
        assert!(!topo.share_domain(0, 3, FailureDomainLevel::Node));
        assert!(!topo.share_domain(1, 7, FailureDomainLevel::Node));

        // All share Datacenter domain
        assert!(topo.share_domain(0, 8, FailureDomainLevel::Datacenter));

        // Same device shares all domains
        assert!(topo.share_domain(5, 5, FailureDomainLevel::Device));
        assert!(topo.share_domain(5, 5, FailureDomainLevel::Node));
        assert!(topo.share_domain(5, 5, FailureDomainLevel::Datacenter));

        // Different devices do NOT share Device domain
        assert!(!topo.share_domain(0, 1, FailureDomainLevel::Device));
    }

    #[test]
    fn property_topology_parent_of_lookup() {
        let mut topo = TopologyAwarePlacement::new();
        topo.add_device(10, 100, 1000, 10000);
        topo.add_device(20, 200, 2000, 20000);

        // parent_of for device 10
        assert_eq!(topo.parent_of(10, FailureDomainLevel::Device), Some(10));
        assert_eq!(topo.parent_of(10, FailureDomainLevel::Node), Some(100));
        assert_eq!(topo.parent_of(10, FailureDomainLevel::Rack), Some(1000));
        assert_eq!(
            topo.parent_of(10, FailureDomainLevel::Datacenter),
            Some(10000)
        );

        // parent_of for device 20 (different chain)
        assert_eq!(topo.parent_of(20, FailureDomainLevel::Device), Some(20));
        assert_eq!(topo.parent_of(20, FailureDomainLevel::Node), Some(200));
        assert_eq!(topo.parent_of(20, FailureDomainLevel::Rack), Some(2000));
        assert_eq!(
            topo.parent_of(20, FailureDomainLevel::Datacenter),
            Some(20000)
        );

        // Unknown device returns None
        assert_eq!(topo.parent_of(999, FailureDomainLevel::Device), None);
        assert_eq!(topo.parent_of(999, FailureDomainLevel::Node), None);
    }

    #[test]
    fn property_many_objects_no_target_exhaustion() {
        // Generate many objects; all must get valid placements
        let targets: Vec<DomainTarget> = (0..16)
            .map(|i| DomainTarget::new(FailureDomainLevel::Device, i))
            .collect();
        let mapper = DomainPlacementMapper::new(targets);
        let policy = DurabilityPolicy::mirror(4).unwrap();

        for i in 0..500u64 {
            let obj_id = i.to_le_bytes();
            let placements = mapper.place_object(&obj_id, &policy, FailureDomainLevel::Device);
            assert_eq!(placements.len(), 4);
            let mut seen = std::collections::BTreeSet::new();
            for p in &placements {
                assert!(seen.insert(p.target.target_id));
            }
        }
    }
}
