//! Failure-domain tree with BLAKE3-sealed integrity verification.
//!
//! A [`FailureDomainTree`] encodes the full device→node→rack→datacenter
//! hierarchy as a deterministic tree structure. It is the single source
//! of truth for topology-aware placement: given the tree, the placement
//! engine can determine whether two devices share a failure domain at
//! any level.
//!
//! The tree is serialized deterministically via sorted pre-order traversal
//! and sealed with a BLAKE3 content hash, enabling offline integrity
//! verification of the layout configuration.

use crate::{Digest, FailureDomainLevel};
use std::collections::{BTreeMap, BTreeSet};

/// Domain-separation context for FailureDomainTree BLAKE3 hashing.
const FDTREE_CONTEXT: &str = "TideFS FailureDomainTree v1";

// ---------------------------------------------------------------------------
// FailureDomainEntry: one record in a flat device list
// ---------------------------------------------------------------------------

/// A single device entry in a flat topology description.
///
/// When building a [`FailureDomainTree`] from a flat list, each device
/// is annotated with its ancestry chain: which node, rack, and datacenter
/// it belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FailureDomainEntry {
    /// Device identifier.
    pub device_id: u64,
    /// Node (host/server) identifier.
    pub node_id: u64,
    /// Rack identifier.
    pub rack_id: u64,
    /// Datacenter (availability zone) identifier.
    pub datacenter_id: u64,
}

impl FailureDomainEntry {
    /// Create a new entry.
    pub fn new(device_id: u64, node_id: u64, rack_id: u64, datacenter_id: u64) -> Self {
        Self {
            device_id,
            node_id,
            rack_id,
            datacenter_id,
        }
    }

    /// Return the parent ID at the given hierarchy level.
    pub fn parent_at(&self, level: FailureDomainLevel) -> Option<u64> {
        match level {
            FailureDomainLevel::Device => Some(self.device_id),
            FailureDomainLevel::Node => Some(self.node_id),
            FailureDomainLevel::Rack => Some(self.rack_id),
            FailureDomainLevel::Datacenter => Some(self.datacenter_id),
        }
    }
}

// ---------------------------------------------------------------------------
// FailureDomainTreeNode: a single node in the tree
// ---------------------------------------------------------------------------

/// A node in the failure-domain tree.
///
/// Leaf nodes represent individual devices; internal nodes represent
/// higher-level failure domains (node, rack, datacenter). Each node
/// carries a domain level, an identifier, and optional children.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailureDomainTreeNode {
    /// The hierarchy level of this node.
    pub level: FailureDomainLevel,
    /// The numeric identifier within that level.
    pub id: u64,
    /// Child nodes (empty for leaf devices).
    pub children: Vec<FailureDomainTreeNode>,
    /// Devices contained in the subtree rooted here.
    device_count: usize,
}

impl FailureDomainTreeNode {
    /// Create a device leaf node.
    fn device_leaf(id: u64) -> Self {
        Self {
            level: FailureDomainLevel::Device,
            id,
            children: Vec::new(),
            device_count: 1,
        }
    }

    /// Create an internal domain node.
    fn domain_node(level: FailureDomainLevel, id: u64, children: Vec<Self>) -> Self {
        let device_count: usize = children.iter().map(|c| c.device_count).sum();
        Self {
            level,
            id,
            children,
            device_count,
        }
    }

    /// Return the total number of devices in this subtree.
    pub fn device_count(&self) -> usize {
        self.device_count
    }

    /// Return true if this node represents a device (leaf).
    pub fn is_device(&self) -> bool {
        self.level == FailureDomainLevel::Device
    }
}

// ---------------------------------------------------------------------------
// FailureDomainTree
// ---------------------------------------------------------------------------

/// TideFS failure-domain tree encoding the full device hierarchy.
///
/// Constructed from a flat list of [`FailureDomainEntry`] records, the
/// tree arranges devices into a multi-level hierarchy: devices grouped
/// under nodes, nodes under racks, racks under datacenters. A synthetic
/// root (level Datacenter, id `u64::MAX`) sits at the top.
///
/// The tree is serialized deterministically by sorted traversal, and a
/// BLAKE3 content hash seals the configuration for offline integrity
/// verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailureDomainTree {
    /// Synthetic root containing all datacenter subtrees.
    root: FailureDomainTreeNode,
    /// BLAKE3 content hash of the deterministic serialization.
    content_hash: Digest,
}

impl FailureDomainTree {
    /// Build a failure-domain tree from a flat list of device entries.
    ///
    /// Entries are sorted by (datacenter, rack, node, device) for
    /// determinism. Devices with duplicate IDs are rejected.
    ///
    /// # Errors
    ///
    /// Returns [`FailureDomainTreeError::DuplicateDevice`] if two entries
    /// share the same `device_id`.
    pub fn from_entries(entries: &[FailureDomainEntry]) -> Result<Self, FailureDomainTreeError> {
        // Check for duplicate device IDs
        let mut seen_devices = BTreeSet::new();
        for entry in entries {
            if !seen_devices.insert(entry.device_id) {
                return Err(FailureDomainTreeError::DuplicateDevice {
                    device_id: entry.device_id,
                });
            }
        }

        // Sort deterministically
        let mut sorted: Vec<&FailureDomainEntry> = entries.iter().collect();
        sorted.sort_by_key(|e| (e.datacenter_id, e.rack_id, e.node_id, e.device_id));

        // Build the tree bottom-up
        let root = Self::build_tree(&sorted);

        // Serialize and compute BLAKE3 hash
        let serialized = Self::serialize_node(&root);
        let mut hasher = blake3::Hasher::new_derive_key(FDTREE_CONTEXT);
        hasher.update(&serialized);
        let content_hash: Digest = hasher.finalize().into();

        Ok(Self { root, content_hash })
    }

    /// Return the BLAKE3 content hash of this tree.
    pub fn content_hash(&self) -> &Digest {
        &self.content_hash
    }

    /// Verify the tree's integrity against an expected hash.
    pub fn verify_hash(&self, expected: &Digest) -> Result<(), FailureDomainTreeError> {
        if self.content_hash == *expected {
            Ok(())
        } else {
            Err(FailureDomainTreeError::HashMismatch)
        }
    }

    /// Return the root node (synthetic, contains all datacenters).
    pub fn root(&self) -> &FailureDomainTreeNode {
        &self.root
    }

    /// Return the total number of devices in the tree.
    pub fn device_count(&self) -> usize {
        self.root.device_count
    }

    /// Check whether two devices share a failure domain at the given level.
    ///
    /// Returns `true` if both devices have the same ancestor at `level`.
    /// Returns `false` if either device is not found or their ancestors differ.
    pub fn share_domain(&self, device_a: u64, device_b: u64, level: FailureDomainLevel) -> bool {
        let parent_a = self.parent_of(device_a, level);
        let parent_b = self.parent_of(device_b, level);
        match (parent_a, parent_b) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        }
    }

    /// Find the ancestor ID for a device at the given level.
    pub fn parent_of(&self, device_id: u64, level: FailureDomainLevel) -> Option<u64> {
        let path = self.device_path(device_id)?;
        match level {
            FailureDomainLevel::Device => path.device,
            FailureDomainLevel::Node => path.node,
            FailureDomainLevel::Rack => path.rack,
            FailureDomainLevel::Datacenter => path.dc,
        }
    }

    /// Return the full ancestry path for a device.
    fn device_path(&self, device_id: u64) -> Option<DevicePath> {
        fn find_in_node(
            node: &FailureDomainTreeNode,
            target: u64,
            ancestors: &mut Vec<u64>,
        ) -> bool {
            if node.is_device() {
                return node.id == target;
            }
            ancestors.push(node.id);
            for child in &node.children {
                if find_in_node(child, target, ancestors) {
                    return true;
                }
            }
            ancestors.pop();
            false
        }

        let mut ancestors = Vec::new();
        if !find_in_node(&self.root, device_id, &mut ancestors) {
            return None;
        }

        // ancestors is [root_id, dc_id, rack_id, node_id]; skip root (index 0)
        let dc = ancestors.get(1).copied();
        let rack = ancestors.get(2).copied();
        let node = ancestors.get(3).copied();

        Some(DevicePath {
            device: Some(device_id),
            node,
            rack,
            dc,
        })
    }

    /// Collect all device IDs in the subtree rooted at the given domain.
    ///
    /// Returns the list of device IDs in stable sorted order.
    pub fn devices_in_domain(&self, level: FailureDomainLevel, domain_id: u64) -> Vec<u64> {
        fn collect_in(
            node: &FailureDomainTreeNode,
            level: FailureDomainLevel,
            target_id: u64,
            found: &mut bool,
            out: &mut Vec<u64>,
        ) {
            if *found {
                if node.is_device() {
                    out.push(node.id);
                } else {
                    for child in &node.children {
                        collect_in(child, level, target_id, found, out);
                    }
                }
                return;
            }
            if node.level == level && node.id == target_id {
                *found = true;
                // Collect all devices below this node
                collect_leaves(node, out);
                return;
            }
            for child in &node.children {
                collect_in(child, level, target_id, found, out);
                if *found {
                    return;
                }
            }
        }

        fn collect_leaves(node: &FailureDomainTreeNode, out: &mut Vec<u64>) {
            if node.is_device() {
                out.push(node.id);
            } else {
                for child in &node.children {
                    collect_leaves(child, out);
                }
            }
        }

        let mut result = Vec::new();
        let mut found = false;
        collect_in(&self.root, level, domain_id, &mut found, &mut result);
        result.sort();
        result
    }

    /// List all domain IDs at the given hierarchy level.
    pub fn domain_ids(&self, level: FailureDomainLevel) -> Vec<u64> {
        let mut ids = BTreeSet::new();
        fn collect_ids(
            node: &FailureDomainTreeNode,
            level: FailureDomainLevel,
            ids: &mut BTreeSet<u64>,
        ) {
            if node.level == level && node.id != u64::MAX {
                ids.insert(node.id);
            }
            for child in &node.children {
                collect_ids(child, level, ids);
            }
        }
        collect_ids(&self.root, level, &mut ids);
        ids.into_iter().collect()
    }

    /// Serialize the tree to a deterministic byte vector.
    ///
    /// Format (per node, recursive depth-first pre-order sorted by ID):
    /// - 1 byte: level discriminant
    /// - 8 bytes: node ID (little-endian u64)
    /// - 4 bytes: child count (little-endian u32)
    /// - children follow immediately
    pub fn serialize(&self) -> Vec<u8> {
        Self::serialize_node(&self.root)
    }

    /// Deserialize a tree from bytes and verify its BLAKE3 hash.
    ///
    /// Returns the reconstructed tree if the hash matches. The content
    /// hash is verified before the tree is fully parsed, so corrupted
    /// trees are rejected early.
    pub fn deserialize_verified(
        buf: &[u8],
        expected_hash: &Digest,
    ) -> Result<Self, FailureDomainTreeError> {
        // Verify hash first
        let mut hasher = blake3::Hasher::new_derive_key(FDTREE_CONTEXT);
        hasher.update(buf);
        let actual: Digest = hasher.finalize().into();
        if actual != *expected_hash {
            return Err(FailureDomainTreeError::HashMismatch);
        }

        let (root, consumed) = Self::deserialize_node(buf)?;
        if consumed != buf.len() {
            return Err(FailureDomainTreeError::TrailingBytes {
                consumed,
                total: buf.len(),
            });
        }

        Ok(Self {
            root,
            content_hash: actual,
        })
    }

    // -- private helpers ----------------------------------------------------

    fn build_tree(sorted: &[&FailureDomainEntry]) -> FailureDomainTreeNode {
        if sorted.is_empty() {
            return FailureDomainTreeNode::domain_node(
                FailureDomainLevel::Datacenter,
                u64::MAX,
                Vec::new(),
            );
        }

        // Group by datacenter
        let mut dc_groups: BTreeMap<u64, Vec<&FailureDomainEntry>> = BTreeMap::new();
        for entry in sorted {
            dc_groups
                .entry(entry.datacenter_id)
                .or_default()
                .push(*entry);
        }

        let mut dc_children = Vec::new();
        for (&dc_id, dc_entries) in &dc_groups {
            // Group by rack
            let mut rack_groups: BTreeMap<u64, Vec<&FailureDomainEntry>> = BTreeMap::new();
            for entry in dc_entries {
                rack_groups.entry(entry.rack_id).or_default().push(*entry);
            }

            let mut rack_children = Vec::new();
            for (&rack_id, rack_entries) in &rack_groups {
                // Group by node
                let mut node_groups: BTreeMap<u64, Vec<&FailureDomainEntry>> = BTreeMap::new();
                for entry in rack_entries {
                    node_groups.entry(entry.node_id).or_default().push(*entry);
                }

                let mut node_children = Vec::new();
                for (&node_id, node_entries) in &node_groups {
                    let device_children: Vec<FailureDomainTreeNode> = node_entries
                        .iter()
                        .map(|e| FailureDomainTreeNode::device_leaf(e.device_id))
                        .collect();
                    node_children.push(FailureDomainTreeNode::domain_node(
                        FailureDomainLevel::Node,
                        node_id,
                        device_children,
                    ));
                }

                rack_children.push(FailureDomainTreeNode::domain_node(
                    FailureDomainLevel::Rack,
                    rack_id,
                    node_children,
                ));
            }

            dc_children.push(FailureDomainTreeNode::domain_node(
                FailureDomainLevel::Datacenter,
                dc_id,
                rack_children,
            ));
        }

        FailureDomainTreeNode::domain_node(FailureDomainLevel::Datacenter, u64::MAX, dc_children)
    }

    fn serialize_node(node: &FailureDomainTreeNode) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(node.level.discriminant());
        buf.extend_from_slice(&node.id.to_le_bytes());
        let child_count = node.children.len() as u32;
        buf.extend_from_slice(&child_count.to_le_bytes());
        for child in &node.children {
            buf.extend_from_slice(&Self::serialize_node(child));
        }
        buf
    }

    fn deserialize_node(
        buf: &[u8],
    ) -> Result<(FailureDomainTreeNode, usize), FailureDomainTreeError> {
        if buf.len() < 13 {
            return Err(FailureDomainTreeError::TruncatedInput);
        }

        let level_disc = buf[0];
        let level = FailureDomainLevel::from_u8(level_disc)
            .ok_or(FailureDomainTreeError::UnknownLevel { byte: level_disc })?;
        let id = u64::from_le_bytes(buf[1..9].try_into().unwrap());
        let child_count = u32::from_le_bytes(buf[9..13].try_into().unwrap()) as usize;

        let mut offset = 13;
        let mut children = Vec::with_capacity(child_count);
        for _ in 0..child_count {
            let (child, consumed) = Self::deserialize_node(&buf[offset..])?;
            children.push(child);
            offset += consumed;
        }

        let node = if children.is_empty() && level == FailureDomainLevel::Device {
            FailureDomainTreeNode::device_leaf(id)
        } else {
            FailureDomainTreeNode::domain_node(level, id, children)
        };

        Ok((node, offset))
    }
}

// ---------------------------------------------------------------------------
// DevicePath: ancestry chain
// ---------------------------------------------------------------------------

struct DevicePath {
    device: Option<u64>,
    node: Option<u64>,
    rack: Option<u64>,
    dc: Option<u64>,
}

// ---------------------------------------------------------------------------
// FailureDomainTreeError
// ---------------------------------------------------------------------------

/// Errors returned by failure-domain tree operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureDomainTreeError {
    /// A device ID appears in more than one entry.
    DuplicateDevice { device_id: u64 },
    /// The BLAKE3 content hash does not match the expected value.
    HashMismatch,
    /// Input buffer is too short for deserialization.
    TruncatedInput,
    /// Unknown failure-domain level discriminant in serialized data.
    UnknownLevel { byte: u8 },
    /// Extra bytes remain after deserializing the tree.
    TrailingBytes { consumed: usize, total: usize },
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DIGEST_SIZE;

    // -- Construction -------------------------------------------------------

    #[test]
    fn empty_tree() {
        let tree = FailureDomainTree::from_entries(&[]).unwrap();
        assert_eq!(tree.device_count(), 0);
        assert!(tree.root().children.is_empty());
    }

    #[test]
    fn single_device_tree() {
        let entries = [FailureDomainEntry::new(0, 10, 100, 1000)];
        let tree = FailureDomainTree::from_entries(&entries).unwrap();
        assert_eq!(tree.device_count(), 1);
        assert_eq!(tree.parent_of(0, FailureDomainLevel::Device), Some(0));
        assert_eq!(tree.parent_of(0, FailureDomainLevel::Node), Some(10));
        assert_eq!(tree.parent_of(0, FailureDomainLevel::Rack), Some(100));
        assert_eq!(
            tree.parent_of(0, FailureDomainLevel::Datacenter),
            Some(1000)
        );
    }

    #[test]
    fn two_devices_same_node() {
        let entries = [
            FailureDomainEntry::new(0, 10, 100, 1000),
            FailureDomainEntry::new(1, 10, 100, 1000),
        ];
        let tree = FailureDomainTree::from_entries(&entries).unwrap();
        assert_eq!(tree.device_count(), 2);
        assert!(tree.share_domain(0, 1, FailureDomainLevel::Node));
        assert!(tree.share_domain(0, 1, FailureDomainLevel::Rack));
        assert!(tree.share_domain(0, 1, FailureDomainLevel::Datacenter));
        assert!(!tree.share_domain(0, 1, FailureDomainLevel::Device));
    }

    #[test]
    fn two_devices_different_nodes_same_rack() {
        let entries = [
            FailureDomainEntry::new(0, 10, 100, 1000),
            FailureDomainEntry::new(1, 20, 100, 1000),
        ];
        let tree = FailureDomainTree::from_entries(&entries).unwrap();
        assert!(!tree.share_domain(0, 1, FailureDomainLevel::Node));
        assert!(tree.share_domain(0, 1, FailureDomainLevel::Rack));
        assert!(tree.share_domain(0, 1, FailureDomainLevel::Datacenter));
    }

    #[test]
    fn two_devices_different_racks_same_dc() {
        let entries = [
            FailureDomainEntry::new(0, 10, 100, 1000),
            FailureDomainEntry::new(1, 20, 200, 1000),
        ];
        let tree = FailureDomainTree::from_entries(&entries).unwrap();
        assert!(!tree.share_domain(0, 1, FailureDomainLevel::Rack));
        assert!(tree.share_domain(0, 1, FailureDomainLevel::Datacenter));
    }

    #[test]
    fn two_devices_different_dc() {
        let entries = [
            FailureDomainEntry::new(0, 10, 100, 1000),
            FailureDomainEntry::new(1, 20, 200, 2000),
        ];
        let tree = FailureDomainTree::from_entries(&entries).unwrap();
        assert!(!tree.share_domain(0, 1, FailureDomainLevel::Datacenter));
    }

    #[test]
    fn duplicate_device_rejected() {
        let entries = [
            FailureDomainEntry::new(5, 10, 100, 1000),
            FailureDomainEntry::new(5, 20, 200, 2000),
        ];
        let err = FailureDomainTree::from_entries(&entries).unwrap_err();
        assert_eq!(
            err,
            FailureDomainTreeError::DuplicateDevice { device_id: 5 }
        );
    }

    // -- Determinism --------------------------------------------------------

    #[test]
    fn same_entries_produce_same_hash() {
        let entries = [
            FailureDomainEntry::new(0, 10, 100, 1000),
            FailureDomainEntry::new(1, 10, 100, 1000),
            FailureDomainEntry::new(2, 20, 200, 2000),
        ];
        let t1 = FailureDomainTree::from_entries(&entries).unwrap();
        let t2 = FailureDomainTree::from_entries(&entries).unwrap();
        assert_eq!(t1, t2);
        assert_eq!(t1.content_hash(), t2.content_hash());
    }

    #[test]
    fn different_entries_produce_different_hash() {
        let e1 = [FailureDomainEntry::new(0, 10, 100, 1000)];
        let e2 = [FailureDomainEntry::new(1, 20, 200, 2000)];
        let t1 = FailureDomainTree::from_entries(&e1).unwrap();
        let t2 = FailureDomainTree::from_entries(&e2).unwrap();
        assert_ne!(t1.content_hash(), t2.content_hash());
    }

    #[test]
    fn unsorted_vs_sorted_same_hash() {
        let unsorted = [
            FailureDomainEntry::new(2, 20, 200, 2000),
            FailureDomainEntry::new(0, 10, 100, 1000),
            FailureDomainEntry::new(1, 10, 100, 1000),
        ];
        let sorted = [
            FailureDomainEntry::new(0, 10, 100, 1000),
            FailureDomainEntry::new(1, 10, 100, 1000),
            FailureDomainEntry::new(2, 20, 200, 2000),
        ];
        let t1 = FailureDomainTree::from_entries(&unsorted).unwrap();
        let t2 = FailureDomainTree::from_entries(&sorted).unwrap();
        assert_eq!(t1.content_hash(), t2.content_hash());
    }

    // -- Serialization round-trip -------------------------------------------

    #[test]
    fn serialize_deserialize_round_trip() {
        let entries = [
            FailureDomainEntry::new(0, 10, 100, 1000),
            FailureDomainEntry::new(1, 10, 100, 1000),
            FailureDomainEntry::new(2, 20, 200, 2000),
        ];
        let tree = FailureDomainTree::from_entries(&entries).unwrap();
        let hash = *tree.content_hash();
        let serialized = tree.serialize();

        let deserialized = FailureDomainTree::deserialize_verified(&serialized, &hash).unwrap();
        assert_eq!(deserialized, tree);
    }

    #[test]
    fn deserialize_wrong_hash_rejected() {
        let entries = [FailureDomainEntry::new(0, 10, 100, 1000)];
        let tree = FailureDomainTree::from_entries(&entries).unwrap();
        let serialized = tree.serialize();
        let wrong_hash = [0u8; DIGEST_SIZE];
        let err = FailureDomainTree::deserialize_verified(&serialized, &wrong_hash).unwrap_err();
        assert_eq!(err, FailureDomainTreeError::HashMismatch);
    }

    #[test]
    fn hash_verify_accepts_correct() {
        let entries = [FailureDomainEntry::new(0, 10, 100, 1000)];
        let tree = FailureDomainTree::from_entries(&entries).unwrap();
        assert!(tree.verify_hash(tree.content_hash()).is_ok());
    }

    #[test]
    fn hash_verify_rejects_wrong() {
        let entries = [FailureDomainEntry::new(0, 10, 100, 1000)];
        let tree = FailureDomainTree::from_entries(&entries).unwrap();
        assert!(tree.verify_hash(&[0xFF; DIGEST_SIZE]).is_err());
    }

    // -- Domain queries -----------------------------------------------------

    #[test]
    fn devices_in_domain() {
        let entries = [
            FailureDomainEntry::new(0, 10, 100, 1000),
            FailureDomainEntry::new(1, 10, 100, 1000),
            FailureDomainEntry::new(2, 20, 100, 1000),
        ];
        let tree = FailureDomainTree::from_entries(&entries).unwrap();
        let devs = tree.devices_in_domain(FailureDomainLevel::Node, 10);
        assert_eq!(devs, vec![0, 1]);
    }

    #[test]
    fn domain_ids_at_levels() {
        let entries = [
            FailureDomainEntry::new(0, 10, 100, 1000),
            FailureDomainEntry::new(1, 20, 200, 2000),
        ];
        let tree = FailureDomainTree::from_entries(&entries).unwrap();
        assert_eq!(tree.domain_ids(FailureDomainLevel::Device), vec![0, 1]);
        assert_eq!(tree.domain_ids(FailureDomainLevel::Node), vec![10, 20]);
        assert_eq!(tree.domain_ids(FailureDomainLevel::Rack), vec![100, 200]);
        assert_eq!(
            tree.domain_ids(FailureDomainLevel::Datacenter),
            vec![1000, 2000]
        );
    }

    // -- Edge cases ---------------------------------------------------------

    #[test]
    fn parent_of_unknown_device_none() {
        let entries = [FailureDomainEntry::new(0, 10, 100, 1000)];
        let tree = FailureDomainTree::from_entries(&entries).unwrap();
        assert_eq!(tree.parent_of(999, FailureDomainLevel::Node), None);
    }

    #[test]
    fn share_domain_unknown_device_false() {
        let entries = [FailureDomainEntry::new(0, 10, 100, 1000)];
        let tree = FailureDomainTree::from_entries(&entries).unwrap();
        assert!(!tree.share_domain(0, 999, FailureDomainLevel::Node));
    }

    #[test]
    fn three_devices_two_dcs() {
        let entries = [
            FailureDomainEntry::new(0, 10, 100, 1000),
            FailureDomainEntry::new(1, 20, 200, 1000),
            FailureDomainEntry::new(2, 30, 300, 2000),
        ];
        let tree = FailureDomainTree::from_entries(&entries).unwrap();
        assert_eq!(tree.device_count(), 3);
        assert!(tree.share_domain(0, 1, FailureDomainLevel::Datacenter));
        assert!(!tree.share_domain(0, 2, FailureDomainLevel::Datacenter));
    }

    #[test]
    fn multi_device_multi_level_tree() {
        // 2 dcs, 2 racks each, 2 nodes each, 2 devices each = 16 devices
        let mut entries = Vec::new();
        for dc in 0..2u64 {
            for rack in 0..2u64 {
                for node in 0..2u64 {
                    for dev in 0..2u64 {
                        entries.push(FailureDomainEntry::new(
                            dc * 1000 + rack * 100 + node * 10 + dev,
                            dc * 100 + rack * 10 + node,
                            dc * 10 + rack,
                            dc,
                        ));
                    }
                }
            }
        }
        let tree = FailureDomainTree::from_entries(&entries).unwrap();
        assert_eq!(tree.device_count(), 16);
        // 2 dcs (+ synthetic root has MAX id, not counted in domain_ids)
        assert_eq!(tree.domain_ids(FailureDomainLevel::Datacenter).len(), 2);
    }
}
