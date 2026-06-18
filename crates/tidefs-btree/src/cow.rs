// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Crash-safe copy-on-write B+tree operations.
//!
//! Every mutation first serializes the new child nodes into persistent
//! storage before writing the parent. This ensures that a crash never
//! leaves a partially-updated tree: either all new nodes are reachable
//! from the root pointer, or none are.
//!
//! ## COW protocol
//!
//! 1. Serialize the new leaf/internal node body via the [`BtreeSerde`] trait.
//! 2. Compute the BLAKE3 keyed checksum over the body.
//! 3. Write the header + body to the [`NodeStore`] (allocating a new
//!    [`NodeId`]).
//! 4. Only after all children are persisted, write the parent node and
//!    finally update the root pointer in an atomic step.
//!
//! ## Integration
//!
//! The [`CowBPlusTree`] wraps the in-memory [`BPlusTree`] from the
//! parent crate. Mutations are performed on the in-memory tree, then
//! flushed to the [`NodeStore`] with COW semantics. The in-memory
//! tree remains the read path; the persistent nodes are the
//! durability path.

use crate::node::{
    compute_checksum, verify_checksum, ChecksumError, DomainTag, NodeHeader, NODE_MAGIC,
};
use crate::{BPlusTree, BTreeNode, NodeId};
use alloc::vec::Vec;
use core::fmt;

// ---------------------------------------------------------------------------
// BtreeSerde trait
// ---------------------------------------------------------------------------

/// Serialization trait for B+tree keys and values.
///
/// Implementations encode keys and values as length-prefixed byte
/// sequences in the persistent node body format.
pub trait BtreeSerde<K, V> {
    /// Serialize a key into `buf` as a length-prefixed entry:
    /// `key_len: u16 LE`, then `key` bytes.
    fn serialize_key(key: &K, buf: &mut Vec<u8>);

    /// Serialize a value into `buf` as a length-prefixed entry:
    /// `val_len: u16 LE`, then `val` bytes.
    fn serialize_value(val: &V, buf: &mut Vec<u8>);
}

// ---------------------------------------------------------------------------
// Built-in serde impls for common types
// ---------------------------------------------------------------------------

/// Serde for fixed-size `u64` keys and `u64` values.
pub struct U64Serde;

impl BtreeSerde<u64, u64> for U64Serde {
    fn serialize_key(key: &u64, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&8u16.to_le_bytes());
        buf.extend_from_slice(&key.to_le_bytes());
    }
    fn serialize_value(val: &u64, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&8u16.to_le_bytes());
        buf.extend_from_slice(&val.to_le_bytes());
    }
}

/// Serde for `u64` keys and `alloc::string::String` values.
pub struct U64StringSerde;

impl BtreeSerde<u64, alloc::string::String> for U64StringSerde {
    fn serialize_key(key: &u64, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&8u16.to_le_bytes());
        buf.extend_from_slice(&key.to_le_bytes());
    }
    fn serialize_value(val: &alloc::string::String, buf: &mut Vec<u8>) {
        let bytes = val.as_bytes();
        let len = bytes.len();
        assert!(len <= u16::MAX as usize, "value too long");
        buf.extend_from_slice(&(len as u16).to_le_bytes());
        buf.extend_from_slice(bytes);
    }
}

// ---------------------------------------------------------------------------
// NodeStore trait
// ---------------------------------------------------------------------------

/// Trait for persistent storage of B+tree nodes.
///
/// Implementations write to segment files, raw devices, or in-memory
/// buffers. The [`NodeStore`] is responsible for atomic durability;
/// `CowBPlusTree` calls `write_node` in child-before-parent order to
/// guarantee crash consistency.
pub trait NodeStore {
    /// Persist `header` + `body` and return the stable [`NodeId`].
    ///
    /// The implementer must ensure the write is durable (fdatasync or
    /// equivalent) before returning.
    fn write_node(&mut self, header: &NodeHeader, body: &[u8]) -> NodeId;

    /// Read back a previously-written node.
    ///
    /// Returns `(header, body)` on success, or an error.
    fn read_node(&self, node_id: NodeId) -> Result<(NodeHeader, Vec<u8>), NodeStoreError>;
}

// ---------------------------------------------------------------------------
// NodeStoreError
// ---------------------------------------------------------------------------

/// Errors from [`NodeStore`] operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodeStoreError {
    /// The requested [`NodeId`] was not found.
    NotFound(NodeId),
    /// The stored checksum does not match the body.
    Checksum(ChecksumError),
    /// The magic bytes do not match [`NODE_MAGIC`].
    BadMagic { got: [u8; 4] },
    /// I/O or storage-layer error.
    Io(alloc::string::String),
}

impl fmt::Display for NodeStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(id) => write!(f, "node {id} not found"),
            Self::Checksum(e) => write!(f, "checksum error: {e}"),
            Self::BadMagic { got } => {
                write!(f, "bad magic: {got:02x?}, expected {NODE_MAGIC:02x?}")
            }
            Self::Io(s) => write!(f, "I/O error: {s}"),
        }
    }
}

// ---------------------------------------------------------------------------
// CowBPlusTree
// ---------------------------------------------------------------------------

/// A persistent B+tree with crash-safe copy-on-write semantics.
///
/// Wraps the in-memory [`BPlusTree`] and flushes dirty nodes to a
/// [`NodeStore`] in child-before-parent order. The root [`NodeId`]
/// is the single atomic pointer that makes a new tree version
/// reachable.
///
/// # Type parameters
///
/// * `K: Ord + Clone` — key type.
/// * `V: Clone` — value type.
/// * `MAX_LEAF` — max entries per leaf (default 45).
/// * `MAX_INTERNAL` — max children per internal node (default 45).
#[derive(Clone, Debug)]
pub struct CowBPlusTree<
    K: Ord + Clone,
    V: Clone,
    const MAX_LEAF: usize = 45,
    const MAX_INTERNAL: usize = 45,
> {
    /// In-memory tree; all reads go here.
    tree: BPlusTree<K, V, MAX_LEAF, MAX_INTERNAL>,
    /// Root [`NodeId`] in persistent storage, or `None` when empty.
    root_id: Option<NodeId>,
}

impl<K: Ord + Clone, V: Clone, const MAX_LEAF: usize, const MAX_INTERNAL: usize>
    CowBPlusTree<K, V, MAX_LEAF, MAX_INTERNAL>
{
    /// Create an empty `CowBPlusTree`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tree: BPlusTree::new(),
            root_id: None,
        }
    }

    /// Return a reference to the underlying in-memory tree.
    #[must_use]
    pub fn tree(&self) -> &BPlusTree<K, V, MAX_LEAF, MAX_INTERNAL> {
        &self.tree
    }

    /// Return a mutable reference to the underlying in-memory tree.
    pub fn tree_mut(&mut self) -> &mut BPlusTree<K, V, MAX_LEAF, MAX_INTERNAL> {
        &mut self.tree
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tree.len()
    }

    /// Returns `true` when empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }

    /// The current root [`NodeId`] in persistent storage.
    #[must_use]
    pub fn root_id(&self) -> Option<NodeId> {
        self.root_id
    }

    // ------------------------------------------------------------------
    // COW flush
    // ------------------------------------------------------------------

    /// Flush the in-memory tree to `store` with copy-on-write semantics.
    ///
    /// Uses `serde` to serialize keys and values into the persistent
    /// node body format. Returns the new root [`NodeId`] and a list of
    /// all node IDs written. The caller should update the
    /// committed-root pointer atomically after this returns
    /// successfully.
    pub fn cow_flush<S: BtreeSerde<K, V>>(
        &mut self,
        store: &mut dyn NodeStore,
        serde: &S,
    ) -> Result<(NodeId, Vec<NodeId>), CowFlushError> {
        if self.tree.is_empty() {
            return Err(CowFlushError::EmptyTree);
        }
        let mut written = Vec::new();
        let root_id = self.flush_node(&self.tree.root, store, serde, &mut written)?;
        self.root_id = Some(root_id);
        Ok((root_id, written))
    }

    #[allow(clippy::only_used_in_recursion)]
    /// Recursively flush a node. Children are flushed before parents.
    fn flush_node<S: BtreeSerde<K, V>>(
        &self,
        node: &BTreeNode<K, V>,
        store: &mut dyn NodeStore,
        _serde: &S,
        written: &mut Vec<NodeId>,
    ) -> Result<NodeId, CowFlushError> {
        match node {
            BTreeNode::Leaf(entries, _) => {
                let mut body = Vec::new();
                for (k, v) in entries {
                    S::serialize_key(k, &mut body);
                    S::serialize_value(v, &mut body);
                }
                let tag = DomainTag::LeafNode;
                let checksum = compute_checksum(tag, &body);
                let header = NodeHeader {
                    magic: NODE_MAGIC,
                    checksum,
                    domain_tag: tag.discriminant(),
                    reserved: [0; 3],
                    count: entries.len() as u32,
                    body_len: body.len() as u32,
                };
                let node_id = store.write_node(&header, &body);
                written.push(node_id);
                Ok(node_id)
            }
            BTreeNode::Internal { keys, children, .. } => {
                // Flush children first (COW: children before parent).
                let child_ids: Vec<NodeId> = children
                    .iter()
                    .map(|child| self.flush_node(child, store, _serde, written))
                    .collect::<Result<_, _>>()?;
                let mut body = Vec::new();
                // child_count: u32 LE
                body.extend_from_slice(&(child_ids.len() as u32).to_le_bytes());
                // child node IDs
                for cid in &child_ids {
                    body.extend_from_slice(&cid.0.to_le_bytes());
                }
                // keys
                for k in keys {
                    S::serialize_key(k, &mut body);
                }
                let tag = DomainTag::InternalNode;
                let checksum = compute_checksum(tag, &body);
                let header = NodeHeader {
                    magic: NODE_MAGIC,
                    checksum,
                    domain_tag: tag.discriminant(),
                    reserved: [0; 3],
                    count: children.len() as u32,
                    body_len: body.len() as u32,
                };
                let node_id = store.write_node(&header, &body);
                written.push(node_id);
                Ok(node_id)
            }
        }
    }

    /// Verify the integrity of a persisted node by re-reading and
    /// checking its BLAKE3 checksum.
    pub fn verify_node(
        store: &dyn NodeStore,
        node_id: NodeId,
    ) -> Result<(NodeHeader, Vec<u8>), NodeStoreError> {
        let (header, body) = store.read_node(node_id)?;
        if !header.is_valid_magic() {
            return Err(NodeStoreError::BadMagic { got: header.magic });
        }
        verify_checksum(&header, &body).map_err(NodeStoreError::Checksum)?;
        Ok((header, body))
    }
}

impl<K: Ord + Clone, V: Clone, const MAX_LEAF: usize, const MAX_INTERNAL: usize> Default
    for CowBPlusTree<K, V, MAX_LEAF, MAX_INTERNAL>
{
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CowFlushError
// ---------------------------------------------------------------------------

/// Error from [`CowBPlusTree::cow_flush`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CowFlushError {
    /// Attempted to flush an empty tree.
    EmptyTree,
}

impl fmt::Display for CowFlushError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyTree => f.write_str("cannot flush an empty B+tree"),
        }
    }
}

// ---------------------------------------------------------------------------
// In-memory NodeStore for testing
// ---------------------------------------------------------------------------

/// An in-memory [`NodeStore`] backed by a `Vec` of `(NodeHeader, Vec<u8>)`.
///
/// Useful for testing COW semantics without a real storage backend.
#[derive(Clone, Debug, Default)]
pub struct MemNodeStore {
    nodes: Vec<(NodeHeader, Vec<u8>)>,
}

impl NodeStore for MemNodeStore {
    fn write_node(&mut self, header: &NodeHeader, body: &[u8]) -> NodeId {
        let id = NodeId((self.nodes.len() + 1) as u64);
        self.nodes.push((*header, body.to_vec()));
        id
    }

    fn read_node(&self, node_id: NodeId) -> Result<(NodeHeader, Vec<u8>), NodeStoreError> {
        let idx = node_id.0 as usize;
        if idx == 0 || idx > self.nodes.len() {
            return Err(NodeStoreError::NotFound(node_id));
        }
        let (header, body) = &self.nodes[idx - 1];
        Ok((*header, body.clone()))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::string::{String, ToString};

    type TestCowTree = CowBPlusTree<u64, String, 4, 4>;

    fn build_tree(entries: &[(u64, &str)]) -> TestCowTree {
        let mut cow = TestCowTree::new();
        for (k, v) in entries {
            cow.tree_mut().insert(*k, v.to_string());
        }
        cow
    }

    fn verify_all(store: &dyn NodeStore, written: &[NodeId]) {
        for &nid in written {
            let result = CowBPlusTree::<u64, String, 4, 4>::verify_node(store, nid);
            assert!(result.is_ok(), "node {nid} should verify: {result:?}");
        }
    }

    // ── basic COW flush ─────────────────────────────────────────────

    #[test]
    fn cow_flush_single_leaf() {
        let mut cow = build_tree(&[(1, "a"), (2, "b"), (3, "c")]);
        let mut store = MemNodeStore::default();
        let (root_id, written) = cow.cow_flush(&mut store, &U64StringSerde).unwrap();
        assert!(!written.is_empty());
        assert_eq!(root_id, *written.last().unwrap());
        assert_eq!(cow.root_id(), Some(root_id));

        let (header, _body) =
            CowBPlusTree::<u64, String, 4, 4>::verify_node(&store, root_id).unwrap();
        assert_eq!(header.domain_tag(), Some(DomainTag::LeafNode));
        assert_eq!(header.count, 3);
    }

    #[test]
    fn cow_flush_multi_leaf_internal_root() {
        let mut cow = build_tree(&[
            (1, "a"),
            (2, "b"),
            (3, "c"),
            (4, "d"),
            (5, "e"),
            (6, "f"),
            (7, "g"),
            (8, "h"),
            (9, "i"),
        ]);
        let mut store = MemNodeStore::default();
        let (root_id, written) = cow.cow_flush(&mut store, &U64StringSerde).unwrap();
        assert!(
            written.len() > 1,
            "multi-leaf tree should write multiple nodes"
        );
        assert_eq!(cow.root_id(), Some(root_id));

        let (header, _body) =
            CowBPlusTree::<u64, String, 4, 4>::verify_node(&store, root_id).unwrap();
        assert_eq!(header.domain_tag(), Some(DomainTag::InternalNode));
        verify_all(&store, &written);
    }

    #[test]
    fn cow_flush_empty_tree_errors() {
        let mut cow: TestCowTree = TestCowTree::new();
        let mut store = MemNodeStore::default();
        assert!(matches!(
            cow.cow_flush(&mut store, &U64StringSerde),
            Err(CowFlushError::EmptyTree)
        ));
    }

    // ── COW crash window ────────────────────────────────────────────

    #[test]
    fn cow_children_flushed_before_parent() {
        let mut cow = build_tree(&[
            (1, "a"),
            (2, "b"),
            (3, "c"),
            (4, "d"),
            (5, "e"),
            (6, "f"),
            (7, "g"),
        ]);
        let mut store = MemNodeStore::default();
        let (_root_id, written) = cow.cow_flush(&mut store, &U64StringSerde).unwrap();

        let leaves: Vec<_> = written
            .iter()
            .filter(|&&nid| {
                let (h, _) = store.read_node(nid).unwrap();
                h.domain_tag() == Some(DomainTag::LeafNode)
            })
            .collect();
        let internals: Vec<_> = written
            .iter()
            .filter(|&&nid| {
                let (h, _) = store.read_node(nid).unwrap();
                h.domain_tag() == Some(DomainTag::InternalNode)
            })
            .collect();

        if let Some(root) = internals.last() {
            for leaf in &leaves {
                let root_pos = written.iter().position(|&x| x == **root).unwrap();
                let leaf_pos = written.iter().position(|&x| x == **leaf).unwrap();
                assert!(
                    leaf_pos < root_pos,
                    "leaf {leaf} (pos {leaf_pos}) must be written before root {root} (pos {root_pos})"
                );
            }
        }
    }

    #[test]
    fn cow_partial_write_doesnt_corrupt() {
        let mut cow = build_tree(&[(1, "a"), (2, "b"), (3, "c")]);
        let mut store = MemNodeStore::default();
        let (root1, _) = cow.cow_flush(&mut store, &U64StringSerde).unwrap();

        cow.tree_mut().insert(4, "d".into());
        let (root2, _) = cow.cow_flush(&mut store, &U64StringSerde).unwrap();

        assert!(CowBPlusTree::<u64, String, 4, 4>::verify_node(&store, root1).is_ok());
        assert!(CowBPlusTree::<u64, String, 4, 4>::verify_node(&store, root2).is_ok());
        assert_ne!(root1, root2);
    }

    // ── Checksum verification ───────────────────────────────────────

    #[test]
    fn persisted_node_passes_checksum_verification() {
        let mut cow = build_tree(&[(10, "x"), (20, "y")]);
        let mut store = MemNodeStore::default();
        let (root_id, _) = cow.cow_flush(&mut store, &U64StringSerde).unwrap();

        let (header, body) = store.read_node(root_id).unwrap();
        assert!(verify_checksum(&header, &body).is_ok());
    }

    #[test]
    fn tampered_body_fails_checksum() {
        let mut cow = build_tree(&[(10, "x")]);
        let mut store = MemNodeStore::default();
        let (root_id, _) = cow.cow_flush(&mut store, &U64StringSerde).unwrap();

        let (header, mut body) = store.read_node(root_id).unwrap();
        if !body.is_empty() {
            body[0] ^= 0xFF;
        }
        assert!(verify_checksum(&header, &body).is_err());
    }

    #[test]
    fn tampered_checksum_field_detected() {
        let mut cow = build_tree(&[(10, "x")]);
        let mut store = MemNodeStore::default();
        let (root_id, _) = cow.cow_flush(&mut store, &U64StringSerde).unwrap();

        let (mut header, body) = store.read_node(root_id).unwrap();
        header.checksum[0] ^= 0xFF;
        assert!(verify_checksum(&header, &body).is_err());
    }

    #[test]
    fn leaf_and_internal_nodes_have_different_checksums_with_same_body() {
        let body = b"test body";
        let cs_leaf = compute_checksum(DomainTag::LeafNode, body);
        let cs_int = compute_checksum(DomainTag::InternalNode, body);
        assert_ne!(cs_leaf, cs_int);
    }

    #[test]
    fn verify_nonexistent_node_errors() {
        let store = MemNodeStore::default();
        assert!(matches!(
            CowBPlusTree::<u64, String, 4, 4>::verify_node(&store, NodeId(999)),
            Err(NodeStoreError::NotFound(NodeId(999)))
        ));
    }

    // ── Large tree COW flush ────────────────────────────────────────

    #[test]
    fn cow_flush_large_tree() {
        let mut cow: CowBPlusTree<u64, u64, 8, 8> = CowBPlusTree::new();
        for i in 0..100u64 {
            cow.tree_mut().insert(i, i * 10);
        }
        let mut store = MemNodeStore::default();
        let (root_id, written) = cow.cow_flush(&mut store, &U64Serde).unwrap();

        assert!(written.len() > 2, "large tree should produce many nodes");
        assert_eq!(cow.root_id(), Some(root_id));
        verify_all(&store, &written);
    }

    // ── Insert-delete COW cycle ─────────────────────────────────────

    #[test]
    fn cow_insert_delete_cycle() {
        let mut cow: CowBPlusTree<u64, u64, 4, 4> = CowBPlusTree::new();
        for i in 0..20u64 {
            cow.tree_mut().insert(i, i * 100);
        }
        let mut store = MemNodeStore::default();
        let (root1, _) = cow.cow_flush(&mut store, &U64Serde).unwrap();
        assert_eq!(cow.len(), 20);

        for i in 0..10u64 {
            cow.tree_mut().delete(&i);
        }
        let (root2, _) = cow.cow_flush(&mut store, &U64Serde).unwrap();
        assert_eq!(cow.len(), 10);
        assert_ne!(root1, root2);

        assert!(CowBPlusTree::<u64, u64, 4, 4>::verify_node(&store, root1).is_ok());
        assert!(CowBPlusTree::<u64, u64, 4, 4>::verify_node(&store, root2).is_ok());
    }

    // ── Default impl ────────────────────────────────────────────────

    #[test]
    fn default_is_empty() {
        let cow: TestCowTree = TestCowTree::default();
        assert!(cow.is_empty());
        assert_eq!(cow.len(), 0);
        assert!(cow.root_id().is_none());
    }

    // ── NodeStoreError Display ──────────────────────────────────────

    #[test]
    fn nodestore_error_display() {
        let e = NodeStoreError::NotFound(NodeId(42));
        assert!(format!("{e}").contains("42"));

        let e = NodeStoreError::BadMagic { got: *b"DEAD" };
        assert!(format!("{e}").contains("44"));

        let e = NodeStoreError::Io("disk full".into());
        assert!(format!("{e}").contains("disk full"));
    }

    // ── CowFlushError Display ───────────────────────────────────────

    #[test]
    fn cow_flush_error_display() {
        let e = CowFlushError::EmptyTree;
        assert!(!format!("{e}").is_empty());
    }
}
