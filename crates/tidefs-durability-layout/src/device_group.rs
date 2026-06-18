// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Deterministic device-group assignment across failure domains.
//!
//! [`DeviceGroupMapper`] produces ordered, failure-domain-separated device
//! groups for an object, using BLAKE3 domain-separated hashing for
//! determinism. Each group contains the set of (shard, device) assignments
//! that land within a single failure domain at the required separation
//! level, and every group occupies a distinct failure domain.

use crate::failure_domain_tree::FailureDomainTree;
use crate::{Digest, DurabilityPolicy, FailureDomainLevel};
use std::collections::{BTreeMap, BTreeSet};

/// Domain-separation context for device-group placement hashing.
const DEVICE_GROUP_CONTEXT: &str = "TideFS DeviceGroupMapping v1";

/// Build the per-level context string.
fn group_domain_context(level: FailureDomainLevel) -> String {
    format!("{}:level{}", DEVICE_GROUP_CONTEXT, level.discriminant())
}

// ---------------------------------------------------------------------------
// DeviceGroupAssignment
// ---------------------------------------------------------------------------

/// A single device-group assignment: shard indices mapped to device IDs,
/// all within the same failure domain at the separation level.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceGroupAssignment {
    /// The failure-domain identifier at the separation level.
    pub domain_id: u64,
    /// The separation level used for this assignment.
    pub separation_level: FailureDomainLevel,
    /// Ordered list of (shard_index, device_id) within this group.
    pub assignments: Vec<(u32, u64)>,
}

// ---------------------------------------------------------------------------
// DeviceGroupMapper
// ---------------------------------------------------------------------------

/// Deterministic object-to-device-group placement engine.
///
/// Given a [`FailureDomainTree`] and a [`DurabilityPolicy`], maps object
/// identifiers to ordered lists of device groups. Each group resides in
/// a distinct failure domain at the specified separation level, ensuring
/// that no two groups share a failure domain at that level or below.
///
/// The mapping is deterministic: same (object_id, tree, policy, level)
/// always produces the same groups.
#[derive(Clone, Debug)]
pub struct DeviceGroupMapper {
    /// The failure-domain tree.
    tree: FailureDomainTree,
    /// The durability policy.
    policy: DurabilityPolicy,
}

impl DeviceGroupMapper {
    /// Create a new mapper.
    pub fn new(tree: FailureDomainTree, policy: DurabilityPolicy) -> Self {
        Self { tree, policy }
    }

    /// Return the total number of devices available.
    pub fn device_count(&self) -> usize {
        self.tree.device_count()
    }

    /// Return a reference to the failure-domain tree.
    pub fn tree(&self) -> &FailureDomainTree {
        &self.tree
    }

    /// Return a reference to the durability policy.
    pub fn policy(&self) -> &DurabilityPolicy {
        &self.policy
    }

    /// Map an object to device groups across distinct failure domains.
    ///
    /// Returns an ordered list of [`DeviceGroupAssignment`]s, one per
    /// failure domain used. Each group's assignments are spread across
    /// devices within that single failure domain. Groups are sorted by
    /// `domain_id` for deterministic output.
    ///
    /// At Device-level separation, each domain contains exactly one
    /// device, so the shard count dictates the required domain count.
    /// At higher levels (Node, Rack, Datacenter), shards are spread
    /// across available domains and distributed across devices within
    /// each domain.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceGroupError::InsufficientDomains`] if there are not
    /// enough distinct failure domains or devices to satisfy the policy.
    pub fn map_object(
        &self,
        object_id: &[u8],
        separation_level: FailureDomainLevel,
    ) -> Result<Vec<DeviceGroupAssignment>, DeviceGroupError> {
        let total_shards = self.policy.total_shards();

        // Get available domain IDs at the separation level
        let domain_ids = self.domain_ids_with_devices(separation_level);

        if domain_ids.is_empty() {
            return Err(DeviceGroupError::NoAvailableDomains {
                level: separation_level,
            });
        }

        // Determine how many domains to use.
        // At Device level, each domain is a single device, so we need
        // as many domains as shards. At higher levels, shards can share
        // a domain and be spread across devices within it.
        let needed_domains = match separation_level {
            FailureDomainLevel::Device => total_shards,
            _ => {
                let policy_domains = self.ideal_domain_count();
                policy_domains.min(domain_ids.len()).max(1)
            }
        };

        if needed_domains > domain_ids.len() {
            return Err(DeviceGroupError::InsufficientDomains {
                required: needed_domains,
                available: domain_ids.len(),
                level: separation_level,
            });
        }

        // Verify total device capacity across selected domains is sufficient
        let total_devices: usize = domain_ids
            .iter()
            .map(|&did| self.tree.devices_in_domain(separation_level, did).len())
            .sum();
        if total_shards > total_devices {
            return Err(DeviceGroupError::InsufficientDomains {
                required: total_shards,
                available: total_devices,
                level: separation_level,
            });
        }

        // Deterministically select domains
        let context = group_domain_context(separation_level);
        let selected_domains =
            self.select_domains(object_id, &domain_ids, needed_domains, &context);

        // Distribute shards across the selected domains
        self.distribute_shards(
            object_id,
            &selected_domains,
            separation_level,
            total_shards,
            &context,
        )
    }

    /// Return the policy's ideal number of distinct failure domains.
    fn ideal_domain_count(&self) -> usize {
        match &self.policy {
            DurabilityPolicy::Mirror { copies } => *copies as usize,
            DurabilityPolicy::ErasureStyle {
                data_shards,
                parity_shards,
            } => (*data_shards + *parity_shards) as usize,
            DurabilityPolicy::Hybrid {
                mirror_copies,
                data_shards,
                parity_shards,
            } => (*mirror_copies as usize).max((*data_shards + *parity_shards) as usize),
        }
    }

    /// List all domain IDs at `level` that contain at least one device.
    fn domain_ids_with_devices(&self, level: FailureDomainLevel) -> Vec<u64> {
        let all_ids = self.tree.domain_ids(level);
        all_ids
            .into_iter()
            .filter(|&id| !self.tree.devices_in_domain(level, id).is_empty())
            .collect()
    }

    /// Deterministically select `count` domains from `available`.
    fn select_domains(
        &self,
        object_id: &[u8],
        available: &[u64],
        count: usize,
        context: &str,
    ) -> Vec<u64> {
        if count >= available.len() {
            return available.to_vec();
        }

        // Sort available deterministically
        let mut sorted: Vec<u64> = available.to_vec();
        sorted.sort();

        let mut selected = Vec::with_capacity(count);
        let mut used = vec![false; sorted.len()];

        for slot in 0..count {
            let mut hasher = blake3::Hasher::new_derive_key(context);
            hasher.update(object_id);
            hasher.update(b"domain_select");
            hasher.update(&(slot as u32).to_le_bytes());
            let digest: Digest = hasher.finalize().into();

            let base = u64::from_le_bytes(digest[0..8].try_into().unwrap()) as usize % sorted.len();
            let stride = (u64::from_le_bytes(digest[8..16].try_into().unwrap()) as usize
                % sorted.len())
            .max(1);

            let mut idx = base;
            loop {
                if !used[idx] {
                    used[idx] = true;
                    selected.push(sorted[idx]);
                    break;
                }
                idx = (idx + stride) % sorted.len();
            }
        }

        selected
    }

    /// Distribute shards across the selected domains.
    fn distribute_shards(
        &self,
        object_id: &[u8],
        domains: &[u64],
        separation_level: FailureDomainLevel,
        total_shards: usize,
        context: &str,
    ) -> Result<Vec<DeviceGroupAssignment>, DeviceGroupError> {
        let mut groups: BTreeMap<u64, Vec<(u32, u64)>> = BTreeMap::new();
        for &domain_id in domains {
            groups.insert(domain_id, Vec::new());
        }

        // Deterministic round-robin offset from the object_id hash
        let mut start_hasher = blake3::Hasher::new_derive_key(context);
        start_hasher.update(object_id);
        start_hasher.update(b"round_robin_start");
        let start_d: Digest = start_hasher.finalize().into();
        let start_offset =
            u64::from_le_bytes(start_d[0..8].try_into().unwrap()) as usize % domains.len();

        // Distribute shards round-robin across domains
        for shard_idx in 0..total_shards as u32 {
            let domain_offset = (start_offset + shard_idx as usize) % domains.len();
            let domain_id = domains[domain_offset];

            let devices = self.tree.devices_in_domain(separation_level, domain_id);
            if devices.is_empty() {
                return Err(DeviceGroupError::DomainEmpty {
                    domain_id,
                    level: separation_level,
                });
            }

            // Deterministic device selection within domain
            let mut dev_hasher = blake3::Hasher::new_derive_key(context);
            dev_hasher.update(object_id);
            dev_hasher.update(b"shard_to_device");
            dev_hasher.update(&shard_idx.to_le_bytes());
            dev_hasher.update(&domain_id.to_le_bytes());
            let dev_d: Digest = dev_hasher.finalize().into();
            let device_offset =
                u64::from_le_bytes(dev_d[0..8].try_into().unwrap()) as usize % devices.len();
            let device_id = devices[device_offset];

            // Avoid duplicate device in the same group
            let group = groups.get(&domain_id).unwrap();
            let used_in_group: Vec<u64> = group.iter().map(|(_, did)| *did).collect();
            let final_device = if used_in_group.contains(&device_id) {
                match devices.iter().find(|&&did| !used_in_group.contains(&did)) {
                    Some(&did) => did,
                    None => {
                        return Err(DeviceGroupError::DeviceCoLocation {
                            device_id,
                            domain_id,
                        })
                    }
                }
            } else {
                device_id
            };
            groups
                .get_mut(&domain_id)
                .unwrap()
                .push((shard_idx, final_device));
        }

        let result: Vec<DeviceGroupAssignment> = groups
            .into_iter()
            .filter(|(_, assignments)| !assignments.is_empty())
            .map(|(domain_id, assignments)| DeviceGroupAssignment {
                domain_id,
                separation_level,
                assignments,
            })
            .collect();

        Ok(result)
    }

    /// Verify that an object's group assignments satisfy failure-domain
    /// separation constraints.
    pub fn verify_groups(groups: &[DeviceGroupAssignment]) -> Result<(), DeviceGroupError> {
        let mut seen_domains = BTreeSet::new();
        for group in groups {
            if !seen_domains.insert(group.domain_id) {
                return Err(DeviceGroupError::DomainCoLocation {
                    domain_id: group.domain_id,
                    level: group.separation_level,
                });
            }
            let mut seen_devices = BTreeSet::new();
            for &(_, device_id) in &group.assignments {
                if !seen_devices.insert(device_id) {
                    return Err(DeviceGroupError::DeviceCoLocation {
                        device_id,
                        domain_id: group.domain_id,
                    });
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// DeviceGroupError
// ---------------------------------------------------------------------------

/// Errors returned by device-group mapping operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceGroupError {
    /// Not enough distinct failure domains to satisfy the policy.
    InsufficientDomains {
        required: usize,
        available: usize,
        level: FailureDomainLevel,
    },
    /// No failure domains available at the requested level.
    NoAvailableDomains { level: FailureDomainLevel },
    /// A domain that was selected for placement has no devices.
    DomainEmpty {
        domain_id: u64,
        level: FailureDomainLevel,
    },
    /// Two groups share the same failure domain (violation).
    DomainCoLocation {
        domain_id: u64,
        level: FailureDomainLevel,
    },
    /// Two shards within a group are assigned to the same device.
    DeviceCoLocation { device_id: u64, domain_id: u64 },
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::failure_domain_tree::FailureDomainEntry;

    fn make_tree_2x2x2() -> FailureDomainTree {
        let mut entries = Vec::new();
        for dc in 0..2u64 {
            for rack in 0..2u64 {
                for node in 0..2u64 {
                    for dev in 0..2u64 {
                        let device_id = dc * 1000 + rack * 100 + node * 10 + dev;
                        let node_id = dc * 100 + rack * 10 + node;
                        let rack_id = dc * 10 + rack;
                        entries.push(FailureDomainEntry::new(device_id, node_id, rack_id, dc));
                    }
                }
            }
        }
        FailureDomainTree::from_entries(&entries).unwrap()
    }

    // -- Construction -------------------------------------------------------

    #[test]
    fn mapper_new() {
        let tree = make_tree_2x2x2();
        let policy = DurabilityPolicy::mirror(3).unwrap();
        let mapper = DeviceGroupMapper::new(tree, policy);
        assert_eq!(mapper.device_count(), 16);
    }

    // -- Mirror: device-level separation ------------------------------------

    #[test]
    fn map_object_mirror_device_separation() {
        let tree = make_tree_2x2x2();
        let policy = DurabilityPolicy::mirror(3).unwrap();
        let mapper = DeviceGroupMapper::new(tree, policy);

        let groups = mapper
            .map_object(b"test-obj-1", FailureDomainLevel::Device)
            .unwrap();

        assert_eq!(groups.len(), 3);
        let shard_indices: BTreeSet<u32> = groups
            .iter()
            .flat_map(|g| g.assignments.iter().map(|a| a.0))
            .collect();
        assert_eq!(shard_indices, [0, 1, 2].iter().copied().collect());
        DeviceGroupMapper::verify_groups(&groups).unwrap();
    }

    #[test]
    fn map_object_mirror_deterministic() {
        let tree = make_tree_2x2x2();
        let policy = DurabilityPolicy::mirror(3).unwrap();
        let mapper = DeviceGroupMapper::new(tree, policy);

        let g1 = mapper
            .map_object(b"obj", FailureDomainLevel::Device)
            .unwrap();
        let g2 = mapper
            .map_object(b"obj", FailureDomainLevel::Device)
            .unwrap();
        assert_eq!(g1, g2);
    }

    #[test]
    fn map_object_different_ids_different_groups() {
        let tree = make_tree_2x2x2();
        let policy = DurabilityPolicy::mirror(3).unwrap();
        let mapper = DeviceGroupMapper::new(tree, policy);

        let g1 = mapper
            .map_object(b"obj-a", FailureDomainLevel::Device)
            .unwrap();
        let g2 = mapper
            .map_object(b"obj-b", FailureDomainLevel::Device)
            .unwrap();
        let same = g1.iter().zip(&g2).all(|(a, b)| a.domain_id == b.domain_id);
        assert!(
            !same,
            "different object IDs should generally produce different groupings"
        );
    }

    // -- Mirror: node-level separation --------------------------------------

    #[test]
    fn map_object_mirror_node_separation() {
        let tree = make_tree_2x2x2();
        let policy = DurabilityPolicy::mirror(2).unwrap();
        let mapper = DeviceGroupMapper::new(tree, policy);

        let groups = mapper
            .map_object(b"node-obj", FailureDomainLevel::Node)
            .unwrap();

        assert_eq!(groups.len(), 2);
        DeviceGroupMapper::verify_groups(&groups).unwrap();
        for g in &groups {
            assert_eq!(g.separation_level, FailureDomainLevel::Node);
        }
    }

    #[test]
    fn map_object_mirror_node_separation_distinct() {
        let tree = make_tree_2x2x2();
        let policy = DurabilityPolicy::mirror(3).unwrap();
        let mapper = DeviceGroupMapper::new(tree, policy);

        let groups = mapper
            .map_object(b"node-obj-2", FailureDomainLevel::Node)
            .unwrap();

        let domain_ids: BTreeSet<u64> = groups.iter().map(|g| g.domain_id).collect();
        assert_eq!(domain_ids.len(), groups.len());
    }

    // -- Mirror: rack-level separation --------------------------------------

    #[test]
    fn map_object_mirror_rack_separation() {
        let tree = make_tree_2x2x2();
        let policy = DurabilityPolicy::mirror(2).unwrap();
        let mapper = DeviceGroupMapper::new(tree, policy);

        let groups = mapper
            .map_object(b"rack-obj", FailureDomainLevel::Rack)
            .unwrap();

        assert_eq!(groups.len(), 2);
        DeviceGroupMapper::verify_groups(&groups).unwrap();
    }

    // -- Mirror: datacenter-level separation --------------------------------

    #[test]
    fn map_object_mirror_dc_separation() {
        let tree = make_tree_2x2x2();
        let policy = DurabilityPolicy::mirror(2).unwrap();
        let mapper = DeviceGroupMapper::new(tree, policy);

        let groups = mapper
            .map_object(b"dc-obj", FailureDomainLevel::Datacenter)
            .unwrap();

        assert_eq!(groups.len(), 2);
        DeviceGroupMapper::verify_groups(&groups).unwrap();
    }

    // -- Insufficient domains -----------------------------------------------

    #[test]
    fn insufficient_domains_error() {
        let mut entries = Vec::new();
        for dev in 0..4u64 {
            entries.push(FailureDomainEntry::new(dev, dev, dev, 0));
        }
        let tree = FailureDomainTree::from_entries(&entries).unwrap();
        let policy = DurabilityPolicy::mirror(5).unwrap();
        let mapper = DeviceGroupMapper::new(tree, policy);

        let err = mapper
            .map_object(b"obj", FailureDomainLevel::Device)
            .unwrap_err();
        match err {
            DeviceGroupError::InsufficientDomains {
                required,
                available,
                ..
            } => {
                assert_eq!(required, 5);
                assert_eq!(available, 4);
            }
            _ => panic!("wrong error: {err:?}"),
        }
    }

    // -- Erasure-style mapping ----------------------------------------------

    #[test]
    fn map_object_erasure_device_separation() {
        let tree = make_tree_2x2x2();
        let policy = DurabilityPolicy::erasure_style(4, 2).unwrap();
        let mapper = DeviceGroupMapper::new(tree, policy);

        let groups = mapper
            .map_object(b"erasure-obj", FailureDomainLevel::Device)
            .unwrap();

        let total_assignments: usize = groups.iter().map(|g| g.assignments.len()).sum();
        assert_eq!(total_assignments, 6);
        DeviceGroupMapper::verify_groups(&groups).unwrap();
    }

    #[test]
    fn map_object_erasure_node_separation() {
        let tree = make_tree_2x2x2();
        let policy = DurabilityPolicy::erasure_style(4, 2).unwrap();
        let mapper = DeviceGroupMapper::new(tree, policy);

        let groups = mapper
            .map_object(b"erasure-node", FailureDomainLevel::Node)
            .unwrap();

        let total_assignments: usize = groups.iter().map(|g| g.assignments.len()).sum();
        assert_eq!(total_assignments, 6);
        DeviceGroupMapper::verify_groups(&groups).unwrap();
    }

    // -- Hybrid mapping -----------------------------------------------------

    #[test]
    fn map_object_hybrid_device_separation() {
        let tree = make_tree_2x2x2();
        let policy = DurabilityPolicy::hybrid(2, 4, 2).unwrap();
        let mapper = DeviceGroupMapper::new(tree, policy);

        let groups = mapper
            .map_object(b"hybrid-obj", FailureDomainLevel::Device)
            .unwrap();

        let total_assignments: usize = groups.iter().map(|g| g.assignments.len()).sum();
        assert_eq!(total_assignments, 12);
        DeviceGroupMapper::verify_groups(&groups).unwrap();
    }

    // -- Verify groups ------------------------------------------------------

    #[test]
    fn verify_groups_rejects_duplicate_domain() {
        let tree = make_tree_2x2x2();
        let policy = DurabilityPolicy::mirror(3).unwrap();
        let mapper = DeviceGroupMapper::new(tree, policy);

        let groups = mapper
            .map_object(b"obj", FailureDomainLevel::Device)
            .unwrap();

        let mut corrupted = groups.clone();
        corrupted[1] = DeviceGroupAssignment {
            domain_id: corrupted[0].domain_id,
            separation_level: corrupted[0].separation_level,
            assignments: corrupted[1].assignments.clone(),
        };

        let err = DeviceGroupMapper::verify_groups(&corrupted).unwrap_err();
        assert!(matches!(err, DeviceGroupError::DomainCoLocation { .. }));
    }

    #[test]
    fn verify_groups_rejects_duplicate_device_in_group() {
        let tree = make_tree_2x2x2();
        let policy = DurabilityPolicy::mirror(2).unwrap();
        let mapper = DeviceGroupMapper::new(tree, policy);

        let groups = mapper
            .map_object(b"obj", FailureDomainLevel::Device)
            .unwrap();

        let mut corrupted = groups.clone();
        if !corrupted.is_empty() {
            let dev = corrupted[0].assignments[0].1;
            corrupted[0].assignments.push((99, dev));
        }

        let err = DeviceGroupMapper::verify_groups(&corrupted).unwrap_err();
        assert!(matches!(err, DeviceGroupError::DeviceCoLocation { .. }));
    }

    // -- No available domains -----------------------------------------------

    #[test]
    fn no_available_domains_empty_tree() {
        let tree = FailureDomainTree::from_entries(&[]).unwrap();
        let policy = DurabilityPolicy::mirror(1).unwrap();
        let mapper = DeviceGroupMapper::new(tree, policy);

        let err = mapper
            .map_object(b"obj", FailureDomainLevel::Node)
            .unwrap_err();
        assert!(matches!(err, DeviceGroupError::NoAvailableDomains { .. }));
    }

    // -- Distribution fairness ----------------------------------------------

    #[test]
    fn shards_distributed_across_groups() {
        let entries = vec![
            FailureDomainEntry::new(0, 1, 1, 1),
            FailureDomainEntry::new(1, 1, 1, 1),
            FailureDomainEntry::new(2, 2, 2, 2),
            FailureDomainEntry::new(3, 2, 2, 2),
        ];
        let tree = FailureDomainTree::from_entries(&entries).unwrap();
        let policy = DurabilityPolicy::mirror(4).unwrap();
        let mapper = DeviceGroupMapper::new(tree, policy);

        let groups = mapper
            .map_object(b"fair-obj", FailureDomainLevel::Node)
            .unwrap();

        assert_eq!(groups.len(), 2);
        let total: usize = groups.iter().map(|g| g.assignments.len()).sum();
        assert_eq!(total, 4);
    }

    #[test]
    fn domain_ids_with_devices_filters_empty() {
        let tree = make_tree_2x2x2();
        let policy = DurabilityPolicy::mirror(1).unwrap();
        let mapper = DeviceGroupMapper::new(tree, policy);

        let device_ids = mapper.tree().domain_ids(FailureDomainLevel::Device);
        assert_eq!(device_ids.len(), 16);

        let node_ids = mapper.tree().domain_ids(FailureDomainLevel::Node);
        assert_eq!(node_ids.len(), 8);
    }
}
