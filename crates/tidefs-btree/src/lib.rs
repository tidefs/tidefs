// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![no_std]
#![forbid(unsafe_code)]

//! General-purpose B+tree.
//!
//! Generic over key (`K: Ord + Clone`) and value (`V: Clone`) types with
//! configurable leaf and internal fanout via const generics. Extracted
//! from [`tidefs-extent-map`] as a shared foundation for extent maps,
//! cleanup queues, directory index, orphan index, and xattr storage.
//!
//! ## Design
//!
//! Leaf nodes hold up to `MAX_LEAF` key-value pairs. Internal nodes hold
//! up to `MAX_INTERNAL` children. Separator `keys[i]` is the minimum key
//! in `children[i+1]`. The tree is rebuilt bottom-up from a sorted entry
//! list on every mutation — O(n) per mutation, correct and auditable,
//! intentionally not a high-concurrency production implementation.
//!
//! ## Node Integrity
//!
//! Every node carries a BLAKE3-256 checksum computed when the node is
//! created. Leaf checksums cover the entry count; internal checksums cover
//! the child count and recursively incorporate child checksums, forming a
//! Merkle-like chain. Domain tags (`CHECKSUM_DOMAIN_LEAF`,
//! `CHECKSUM_DOMAIN_INTERNAL`) prevent cross-type collisions.
//! `[verify_checksums](BPlusTree::verify_checksums)` recomputes and
//! compares all checksums depth-first. Full content verification at the
//! persistence layer uses serialized page data rather than the in-memory
//! entry-level checksum stored here.
//!
//! ## Compaction
//!
//! Mutations use `rebuild_compact()` which guarantees minimum fill for
//! non-root nodes: each leaf holds at least `MIN_LEAF` entries and each
//! internal node has at least `MIN_INTERNAL` children. The root is
//! exempt from underflow. `compact()` rebuilds via `rebuild_compact()`
//! to enforce these invariants.
//!
//! ## Comparison to ZFS / Ceph
//!
//! - **ZFS**: ZFS uses a hybrid slab/btree allocator tied to the DMU
//!   object layer and is not a standalone reusable B+tree. The TideFS
//!   B+tree is a separate, generic, testable component.
//! - **Ceph**: Ceph's OSDMap uses a custom in-memory map, and BlueStore
//!   uses RocksDB (LSM-tree, not B+tree). Neither provides a standalone,
//!   embeddable B+tree suitable for extent maps and cleanup queues.

extern crate alloc;

/// Crash-safe copy-on-write B+tree operations on persistent nodes.
pub mod cow;
/// Persistent on-disk B+tree node format with BLAKE3-verified integrity.
pub mod node;
/// Fixed-size 4 KB page format with BLAKE3-authenticated pages.
pub mod page;
/// Page-level persistent storage trait and in-memory implementation.
pub mod page_store;
/// Write-ahead log for page-level crash safety.
pub mod wal;

mod partition;
mod range_scan;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::ops::{Bound, RangeBounds};
pub use cow::{
    BtreeSerde, CowBPlusTree, CowFlushError, MemNodeStore, NodeStore, NodeStoreError, U64Serde,
    U64StringSerde,
};
pub use node::{
    compute_checksum, verify_checksum, ChecksumError, DomainTag, NodeHeader, NODE_HEADER_SIZE,
    NODE_MAGIC,
};
pub use page::{
    BtreePage, PageChecksumError, PageFormatError, PageHeader, PageSerdeKey, PageSerdeValue,
    PageType, PAGE_BODY_SIZE, PAGE_HEADER_SIZE, PAGE_MAGIC, PAGE_SIZE,
};
pub use page_store::{MemPageStore, PageStore, PageStoreError};
pub use partition::*;
pub use range_scan::RangeScan;

// BLAKE3 domain tags for node checksums.
/// Domain prefix for leaf-node checksums.
const CHECKSUM_DOMAIN_LEAF: &[u8] = b"tidefs-btree-leaf-v1";
/// Domain prefix for internal-node checksums.
const CHECKSUM_DOMAIN_INTERNAL: &[u8] = b"tidefs-btree-internal-v1";

/// Design spec reference.
pub const BTREE_SPEC: &str = "tidefs-btree-v1";

// ---------------------------------------------------------------------------
// NodeId
// ---------------------------------------------------------------------------

/// Opaque identifier for a B+tree node, assigned at node creation and stable
/// across rebuilds only when the node is not regenerated.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct NodeId(pub u64);

impl core::fmt::Display for NodeId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "n{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// BTreeError
// ---------------------------------------------------------------------------

/// Errors returned by B+tree validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BTreeError {
    /// Internal node has fewer than 2 children.
    InternalTooFewChildren,
    /// Leaf node exceeds MAX_LEAF entries.
    LeafOverflow,
    /// Internal node exceeds MAX_INTERNAL children.
    InternalOverflow,
    /// Leaf node has fewer than MIN_LEAF entries (non-root).
    LeafUnderflow,
    /// Internal node has fewer than MIN_INTERNAL children (non-root).
    InternalUnderflow,
    /// Key count != children.len() - 1 in an internal node.
    KeyChildMismatch,
    /// Keys are not in strictly ascending order.
    KeyOrderViolation,
    /// An iterator supplied fewer or more entries than the expected length.
    LengthMismatch,
    /// A separator key does not match the min key of its right child.
    SeparatorMismatch,
    /// A node's BLAKE3-256 checksum does not match the computed value.
    ChecksumMismatch,
}

impl fmt::Display for BTreeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BTreeError::InternalTooFewChildren => {
                f.write_str("internal node has fewer than 2 children")
            }
            BTreeError::LeafOverflow => f.write_str("leaf node exceeds MAX_LEAF entries"),
            BTreeError::InternalOverflow => {
                f.write_str("internal node exceeds MAX_INTERNAL children")
            }
            BTreeError::LeafUnderflow => f.write_str("leaf node has fewer than MIN_LEAF entries"),
            BTreeError::InternalUnderflow => {
                f.write_str("internal node has fewer than MIN_INTERNAL children")
            }
            BTreeError::KeyChildMismatch => {
                f.write_str("internal node key count != children.len() - 1")
            }
            BTreeError::KeyOrderViolation => f.write_str("keys not in strictly ascending order"),
            BTreeError::LengthMismatch => {
                f.write_str("iterator entry count did not match expected length")
            }
            BTreeError::SeparatorMismatch => {
                f.write_str("separator key does not match descendant min key")
            }
            BTreeError::ChecksumMismatch => f.write_str("BLAKE3-256 checksum mismatch"),
        }
    }
}

/// Error returned while rebuilding a B+tree from a fallible sorted iterator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RebuildFromSortedIterError<E> {
    /// The source iterator failed while entries were being read.
    Source(E),
    /// The iterator did not satisfy the sorted bulk-rebuild contract.
    Tree(BTreeError),
}

impl<E: fmt::Display> fmt::Display for RebuildFromSortedIterError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RebuildFromSortedIterError::Source(err) => write!(f, "source iterator failed: {err}"),
            RebuildFromSortedIterError::Tree(err) => write!(f, "btree rebuild failed: {err}"),
        }
    }
}

// ---------------------------------------------------------------------------
// UnderfullNodeInfo
// ---------------------------------------------------------------------------

/// Describes a B+tree node whose fill ratio has dropped below a threshold,
/// making it a candidate for deferred merge or redistribution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnderfullNodeInfo {
    /// Identifier of the under-full node.
    pub node_id: NodeId,
    /// Whether this is a leaf (true) or internal (false) node.
    pub is_leaf: bool,
    /// Current number of entries (leaf) or children (internal).
    pub fill_count: u64,
    /// Maximum capacity (MAX_LEAF or MAX_INTERNAL).
    pub max_capacity: u64,
}

impl UnderfullNodeInfo {
    /// Fill ratio as a fraction in [0.0, 1.0].
    #[must_use]
    pub fn fill_ratio(&self) -> f64 {
        if self.max_capacity == 0 {
            return 0.0;
        }
        self.fill_count as f64 / self.max_capacity as f64
    }

    /// Returns  when the node is below the standard minimum fill
    /// (less than 50%).
    #[must_use]
    pub fn is_below_min_fill(&self) -> bool {
        self.fill_ratio() < 0.5
    }
}

// ---------------------------------------------------------------------------
// BTreeNode
// ---------------------------------------------------------------------------

/// Computes a BLAKE3-256 checksum for a leaf node.
///
/// Domain-tagged with [`CHECKSUM_DOMAIN_LEAF`]. The checksum covers the
/// entry count so structural corruption is detectable. Full content
/// verification at the persistence layer uses serialized page data.
fn leaf_checksum(len: usize) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CHECKSUM_DOMAIN_LEAF);
    hasher.update(&(len as u64).to_le_bytes());
    hasher.finalize().into()
}

/// Computes a BLAKE3-256 checksum for an internal node.
///
/// Domain-tagged with [`CHECKSUM_DOMAIN_INTERNAL`]. The checksum covers
/// the child count and all child checksums, forming a Merkle-like chain
/// that detects structural corruption anywhere in the subtree.
fn internal_checksum<K: Ord + Clone, V: Clone>(
    n_children: usize,
    children: &[BTreeNode<K, V>],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CHECKSUM_DOMAIN_INTERNAL);
    hasher.update(&(n_children as u64).to_le_bytes());
    for child in children {
        hasher.update(&child.checksum());
    }
    hasher.finalize().into()
}

/// A node in the B+tree.
#[derive(Clone, Debug)]
enum BTreeNode<K: Ord + Clone, V: Clone> {
    /// Leaf node: sorted `(key, value)` pairs, plus a BLAKE3-256 checksum.
    Leaf(Vec<(K, V)>, [u8; 32]),
    /// Internal node: `keys[i]` is the min key of `children[i+1]`,
    /// plus a BLAKE3-256 checksum covering child structure.
    Internal {
        keys: Vec<K>,
        children: Vec<BTreeNode<K, V>>,
        checksum: [u8; 32],
    },
}

impl<K: Ord + Clone, V: Clone> BTreeNode<K, V> {
    /// Returns the minimum key in this subtree.
    /// Returns the BLAKE3-256 checksum stored in this node.
    fn checksum(&self) -> [u8; 32] {
        match self {
            BTreeNode::Leaf(_, cs) => *cs,
            BTreeNode::Internal { checksum, .. } => *checksum,
        }
    }

    fn min_key(&self) -> K {
        match self {
            BTreeNode::Leaf(entries, _) => entries[0].0.clone(),
            BTreeNode::Internal { children, .. } => children[0].min_key(),
        }
    }

    /// Collects all key-value pairs in key order into `out`.
    fn collect_all(&self, out: &mut Vec<(K, V)>) {
        match self {
            BTreeNode::Leaf(entries, _) => out.extend(entries.iter().cloned()),
            BTreeNode::Internal { children, .. } => {
                for c in children {
                    c.collect_all(out);
                }
            }
        }
    }

    /// Returns the maximum key-value pair in this subtree.
    fn max_entry(&self) -> Option<(&K, &V)> {
        match self {
            BTreeNode::Leaf(entries, _) => entries.last().map(|entry| (&entry.0, &entry.1)),
            BTreeNode::Internal { children, .. } => children.last().and_then(Self::max_entry),
        }
    }

    /// Returns the greatest key-value pair whose key is less than or equal to
    /// `key`.
    fn floor_entry(&self, key: &K) -> Option<(&K, &V)> {
        match self {
            BTreeNode::Leaf(entries, _) => match entries.binary_search_by(|(k, _)| k.cmp(key)) {
                Ok(idx) => {
                    let entry = &entries[idx];
                    Some((&entry.0, &entry.1))
                }
                Err(0) => None,
                Err(idx) => {
                    let entry = &entries[idx - 1];
                    Some((&entry.0, &entry.1))
                }
            },
            BTreeNode::Internal { keys, children, .. } => {
                let child_idx = keys
                    .binary_search_by(|k| {
                        if key < k {
                            core::cmp::Ordering::Greater
                        } else {
                            core::cmp::Ordering::Less
                        }
                    })
                    .unwrap_err();
                match children[child_idx].floor_entry(key) {
                    Some(entry) => Some(entry),
                    None if child_idx > 0 => children[child_idx - 1].max_entry(),
                    None => None,
                }
            }
        }
    }

    /// Returns the depth of this subtree (leaf = 1).
    fn depth(&self) -> u8 {
        match self {
            BTreeNode::Leaf(_, _) => 1,
            BTreeNode::Internal { children, .. } => 1 + children[0].depth(),
        }
    }

    /// Collects key-value pairs with keys in the given range into `out`,
    /// pruning subtrees that fall entirely outside the range.
    ///
    /// `start` and `end` are optional; `None` means unbounded on that side.
    fn collect_range(&self, start: Option<&K>, end: Option<&K>, out: &mut Vec<(K, V)>) {
        match self {
            BTreeNode::Leaf(entries, _) => {
                for (k, v) in entries {
                    if let Some(s) = start {
                        if k < s {
                            continue;
                        }
                    }
                    if let Some(e) = end {
                        if k >= e {
                            break;
                        }
                    }
                    out.push((k.clone(), v.clone()));
                }
            }
            BTreeNode::Internal { keys, children, .. } => {
                // Find the first child whose range may contain start.
                let first_child = match start {
                    None => 0,
                    Some(s) => {
                        if keys.is_empty() {
                            0
                        } else {
                            match keys.binary_search_by(|k| {
                                if s < k {
                                    core::cmp::Ordering::Greater
                                } else {
                                    core::cmp::Ordering::Less
                                }
                            }) {
                                Ok(idx) => idx + 1,
                                Err(idx) => idx,
                            }
                        }
                    }
                };
                // Walk children starting from first_child, stopping when
                // a child's min key is >= end.
                for i in first_child..children.len() {
                    if let Some(e) = end {
                        if i > 0 && &keys[i - 1] >= e {
                            break;
                        }
                    }
                    children[i].collect_range(start, end, out);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// BPlusTree
// ---------------------------------------------------------------------------

/// Result of a lazy delete operation on a [`BPlusTree`].
///
/// After deleting an entry, the tree may contain leaf or internal nodes
/// whose fill ratio has dropped below the minimum threshold. These nodes
/// are returned as [`UnderfullNodeInfo`] values so the caller can enqueue
/// them in a [`BtreeCleanupQueue`] for deferred merge/redistribution.
///
/// [`BtreeCleanupQueue`]: tidefs_cleanup_queue_core::BtreeCleanupQueue
#[derive(Clone, Debug)]
pub struct DeleteLazyResult<V> {
    /// The removed value, if the key existed.
    pub removed: Option<V>,
    /// Under-full non-root nodes that need deferred maintenance.
    pub underfull: Vec<UnderfullNodeInfo>,
}

/// Result of a deferred B+tree merge or redistribute operation.
///
/// Reports how many nodes were freed and the post-operation fill ratio.
#[derive(Clone, Copy, Debug, Default)]
pub struct MergeStats {
    /// Leaf nodes eliminated by the operation.
    pub leaves_freed: u64,
    /// Total nodes (leaf + internal) eliminated.
    pub total_nodes_freed: u64,
    /// Post-operation leaf fill ratio (0.0–1.0).
    pub fill_after: f64,
    /// Post-operation total node count.
    pub nodes_after: u64,
}

/// A general-purpose in-memory B+tree.
///
/// `MAX_LEAF` (default 45): max entries per leaf.
/// `MAX_INTERNAL` (default 45): max children per internal node.
#[derive(Clone, Debug)]
pub struct BPlusTree<
    K: Ord + Clone,
    V: Clone,
    const MAX_LEAF: usize = 45,
    const MAX_INTERNAL: usize = 45,
> {
    root: BTreeNode<K, V>,
    len: usize,
    #[allow(dead_code)]
    next_node_id: u64,
}

impl<K: Ord + Clone, V: Clone, const MAX_LEAF: usize, const MAX_INTERNAL: usize>
    BPlusTree<K, V, MAX_LEAF, MAX_INTERNAL>
{
    /// Minimum entries per leaf (ceil(MAX_LEAF/2)), root-exempt.
    pub const MIN_LEAF: usize = MAX_LEAF.div_ceil(2);
    /// Minimum children per internal node (ceil(MAX_INTERNAL/2)), root-exempt.
    pub const MIN_INTERNAL: usize = MAX_INTERNAL.div_ceil(2);

    /// Create an empty B+tree.
    #[must_use]
    pub fn new() -> Self {
        let root_checksum = leaf_checksum(0);
        Self {
            root: BTreeNode::Leaf(Vec::new(), root_checksum),
            len: 0,
            next_node_id: 1,
        }
    }

    // ------------------------------------------------------------------
    // Lookup
    // ------------------------------------------------------------------

    /// Returns a reference to the value associated with `key`, or `None`.
    ///
    /// O(log n) tree traversal. Checksums are not verified on read — use
    /// `[verify_checksums](Self::verify_checksums)` to detect corruption.
    #[must_use]
    pub fn get(&self, key: &K) -> Option<&V> {
        Self::get_in_node(&self.root, key)
    }

    /// Returns the greatest key-value pair whose key is less than or equal to
    /// `key`, or `None` when all keys are greater than `key`.
    ///
    /// This is an O(log n) predecessor seek and returns references without
    /// cloning entries before `key`.
    #[must_use]
    pub fn floor_entry(&self, key: &K) -> Option<(&K, &V)> {
        self.root.floor_entry(key)
    }

    fn get_in_node<'a>(node: &'a BTreeNode<K, V>, key: &K) -> Option<&'a V> {
        match node {
            BTreeNode::Leaf(entries, _) => entries
                .binary_search_by(|(k, _)| k.cmp(key))
                .ok()
                .map(|idx| &entries[idx].1),
            BTreeNode::Internal { keys, children, .. } => {
                // Find insertion point: first key where key < keys[i].
                // For equal keys, insertion point is after (i+1),
                // which points to the child whose min_key == key.
                let child_idx = keys
                    .binary_search_by(|k| {
                        if key < k {
                            core::cmp::Ordering::Greater
                        } else {
                            core::cmp::Ordering::Less
                        }
                    })
                    .unwrap_err();
                Self::get_in_node(&children[child_idx], key)
            }
        }
    }

    /// Returns `true` if the tree contains `key`.
    #[must_use]
    pub fn contains_key(&self, key: &K) -> bool {
        self.get(key).is_some()
    }

    // ------------------------------------------------------------------
    // Mutation
    // ------------------------------------------------------------------

    /// Inserts a key-value pair. Returns the previous value if the key
    /// already existed, otherwise `None`.
    ///
    /// Triggers a full-tree rebuild via `[rebuild_compact](Self::rebuild_compact)`
    /// which recomputes BLAKE3 checksums for every node.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        let mut entries = self.collect_all_entries();
        match entries.binary_search_by(|(k, _)| k.cmp(&key)) {
            Ok(idx) => {
                let old = core::mem::replace(&mut entries[idx], (key, value));
                self.rebuild_compact(&entries);
                Some(old.1)
            }
            Err(idx) => {
                entries.insert(idx, (key, value));
                self.rebuild_compact(&entries);
                None
            }
        }
    }

    /// Removes a key from the tree. Returns the value if the key existed.
    ///
    /// Triggers a full-tree rebuild via `[rebuild_compact](Self::rebuild_compact)`
    /// which recomputes BLAKE3 checksums for every node.
    pub fn delete(&mut self, key: &K) -> Option<V> {
        let entries = self.collect_all_entries();
        match entries.binary_search_by(|(k, _)| k.cmp(key)) {
            Ok(idx) => {
                let mut entries = entries;
                let removed = entries.remove(idx);
                self.rebuild_compact(&entries);
                Some(removed.1)
            }
            Err(_) => None,
        }
    }

    /// Removes a key from the tree without compacting, leaving under-full
    /// nodes visible for deferred cleanup.
    ///
    /// Unlike [`delete`](Self::delete), this method uses [`rebuild`](Self::rebuild)
    /// instead of [`rebuild_compact`], so nodes that fall below the minimum
    /// fill threshold are preserved. The caller should inspect the returned
    /// [`DeleteLazyResult::underfull`] list and enqueue entries in a
    /// [`BtreeCleanupQueue`] for deferred merge/redistribution.
    ///
    /// Use [`maybe_compact`](Self::maybe_compact) or [`compact`](Self::compact)
    /// to restore minimum-fill invariants eagerly.
    pub fn delete_lazy(&mut self, key: &K) -> DeleteLazyResult<V> {
        let entries = self.collect_all_entries();
        match entries.binary_search_by(|(k, _)| k.cmp(key)) {
            Ok(idx) => {
                let mut entries = entries;
                let removed = entries.remove(idx);
                self.rebuild(&entries);
                let underfull = self.underfull_nodes(0.5);
                DeleteLazyResult {
                    removed: Some(removed.1),
                    underfull,
                }
            }
            Err(_) => DeleteLazyResult {
                removed: None,
                underfull: Vec::new(),
            },
        }
    }

    /// Updates the value for `key` in-place via a callback.
    ///
    /// Collects all entries, calls `f` on the value, and rebuilds the tree.
    /// Returns `true` if the key was found and updated.
    ///
    /// This avoids the need for a `&mut V` that would conflict with the
    /// rebuild-based architecture.
    pub fn update<F: FnOnce(&mut V)>(&mut self, key: &K, f: F) -> bool {
        let mut entries = self.collect_all_entries();
        match entries.binary_search_by(|(k, _)| k.cmp(key)) {
            Ok(idx) => {
                f(&mut entries[idx].1);
                self.rebuild_compact(&entries);
                true
            }
            Err(_) => false,
        }
    }

    /// Removes all entries from the tree.
    pub fn clear(&mut self) {
        self.root = BTreeNode::Leaf(Vec::new(), leaf_checksum(0));
        self.len = 0;
    }

    // ------------------------------------------------------------------
    // Iteration helpers
    // ------------------------------------------------------------------

    /// Returns all entries as a sorted vector.
    #[must_use]
    pub fn entries(&self) -> Vec<(K, V)> {
        let mut out = Vec::new();
        self.root.collect_all(&mut out);
        out
    }

    /// Returns entries within the given key range via tree traversal.
    ///
    /// Prunes subtrees that fall outside the range, yielding O(log n + k)
    /// where k is the number of matching entries.
    #[must_use]
    pub fn range<R: RangeBounds<K>>(&self, range: R) -> Vec<(K, V)> {
        let start = match range.start_bound() {
            Bound::Included(k) => Some(k),
            Bound::Excluded(k) => Some(k),
            Bound::Unbounded => None,
        };
        let end = match range.end_bound() {
            // Pass None so collect_range doesn't break before reaching
            // the end key. The post-filter handles inclusive/exclusive.
            Bound::Included(_k) => None,
            Bound::Excluded(k) => Some(k),
            Bound::Unbounded => None,
        };
        let mut out = Vec::new();
        self.root.collect_range(start, end, &mut out);
        // Filter to correct bounds (Excluded start, Included end).
        out.retain(|(k, _)| range.contains(k));
        out
    }

    /// Returns entries with keys in `[start, end)` via direct tree traversal.
    /// O(log n + k) where k is the number of matching entries.
    #[must_use]
    pub fn range_from_to(&self, start: &K, end: &K) -> Vec<(K, V)> {
        if start >= end {
            return Vec::new();
        }
        let mut out = Vec::new();
        self.root.collect_range(Some(start), Some(end), &mut out);
        out
    }

    /// Returns a lazy iterator over key-value pairs within the given bounds.
    ///
    /// Yields `(&K, &V)` references in ascending key order without cloning.
    /// The traversal is O(log n + k) where k is the number of yielded entries.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use tidefs_btree::BPlusTree;
    /// let mut tree: BPlusTree<u64, String, 4, 4> = BPlusTree::new();
    /// tree.insert(1, "a".into());
    /// tree.insert(2, "b".into());
    /// tree.insert(3, "c".into());
    /// let mut scan = tree.range_scan(1u64..3u64);
    /// assert_eq!(scan.next(), Some((&1, &"a".to_string())));
    /// assert_eq!(scan.next(), Some((&2, &"b".to_string())));
    /// assert_eq!(scan.next(), None);
    /// ```
    #[must_use]
    pub fn range_scan<R>(&self, range: R) -> RangeScan<K, V, MAX_LEAF, MAX_INTERNAL>
    where
        R: core::ops::RangeBounds<K>,
    {
        let start = range.start_bound().cloned();
        let end = range.end_bound().cloned();
        RangeScan::new(self, start, end)
    }
    // ------------------------------------------------------------------
    // Size and shape
    // ------------------------------------------------------------------

    /// Number of entries in the tree.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the tree is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Depth of the tree (leaf = 1, one internal level = 2, etc.).
    #[must_use]
    pub fn depth(&self) -> u8 {
        if self.len == 0 {
            1
        } else {
            self.root.depth()
        }
    }

    // ------------------------------------------------------------------
    // Compaction and statistics
    // ------------------------------------------------------------------

    /// Rebuild the tree from scratch, packing all nodes to maximum
    /// fanout. Equivalent to collecting all entries and rebuilding
    /// bottom-up. This is an O(n) operation.
    ///
    /// Useful after bulk deletions or when entries have been loaded
    /// from disk into a tree that may have underfull nodes.
    ///
    /// # Comparison to ZFS / Ceph
    ///
    /// Neither ZFS nor Ceph exposes a standalone B+tree compaction API.
    /// ZFS ZAP microzaps grow monotonically; Ceph RocksDB compaction is
    /// write-amplifying and LSM-tree-specific. TideFS provides a simple
    /// O(n) rebuild that guarantees strict B+tree packing invariants.
    pub fn compact(&mut self) {
        if self.is_empty() {
            return;
        }
        let entries = self.entries();
        self.rebuild_compact(&entries);
    }

    /// Compact the tree only if the leaf fill percentage is below
    /// `threshold` (0.0-1.0). A threshold of 0.5 means compact when
    /// leaves are less than 50% full on average.
    ///
    /// Returns `true` if compaction was performed.
    pub fn maybe_compact(&mut self, threshold: f64) -> bool {
        if self.is_empty() {
            return false;
        }
        if self.fill_percent() < threshold {
            self.compact();
            true
        } else {
            false
        }
    }

    /// Rebuild the tree from exactly `expected_len` sorted owned entries.
    ///
    /// The iterator must yield keys in strictly ascending order and must yield
    /// exactly `expected_len` entries. Unlike [`rebuild`](Self::rebuild), this
    /// path does not require callers to stage a complete sorted slice before
    /// constructing the tree, and it builds minimum-fill leaves directly from
    /// the owned stream.
    pub fn rebuild_compact_from_sorted_iter<I>(
        &mut self,
        expected_len: usize,
        entries: I,
    ) -> Result<(), BTreeError>
    where
        I: IntoIterator<Item = (K, V)>,
    {
        let result = self.try_rebuild_compact_from_sorted_iter(
            expected_len,
            entries.into_iter().map(Ok::<(K, V), BTreeError>),
        );
        match result {
            Ok(()) => Ok(()),
            Err(RebuildFromSortedIterError::Source(err))
            | Err(RebuildFromSortedIterError::Tree(err)) => Err(err),
        }
    }

    /// Rebuild the tree from exactly `expected_len` sorted owned entries.
    ///
    /// This fallible variant lets deserializers or page readers surface their
    /// own I/O/integrity errors while the B+tree still enforces the sorted
    /// bulk-load contract.
    pub fn try_rebuild_compact_from_sorted_iter<I, E>(
        &mut self,
        expected_len: usize,
        entries: I,
    ) -> Result<(), RebuildFromSortedIterError<E>>
    where
        I: IntoIterator<Item = Result<(K, V), E>>,
    {
        let root = Self::build_compact_root_from_sorted_iter(expected_len, entries)?;
        self.root = root;
        self.len = expected_len;
        Ok(())
    }

    /// Rebuild the tree from a sorted owned-entry stream with unknown length.
    ///
    /// This variant is for page-oriented importers that can validate and read
    /// entries once but do not know the exact entry count before decoding the
    /// stream. It keeps only the in-progress leaf and the final tree nodes,
    /// while still enforcing strictly ascending keys and minimum-fill
    /// non-root leaves.
    pub fn try_rebuild_compact_from_sorted_unknown_len_iter<I, E>(
        &mut self,
        entries: I,
    ) -> Result<usize, RebuildFromSortedIterError<E>>
    where
        I: IntoIterator<Item = Result<(K, V), E>>,
    {
        let (root, len) = Self::build_compact_root_from_sorted_unknown_len_iter(entries)?;
        self.root = root;
        self.len = len;
        Ok(len)
    }

    /// Merge an under-full node with its left sibling.
    ///
    /// Rebuilds the tree via [`compact`](Self::compact), which re-distributes
    /// entries evenly across nodes respecting `MIN_LEAF` and `MIN_INTERNAL`.
    /// In the rebuild-based architecture, individual node merges are not
    /// possible — this method compacts the entire tree as a deferred
    /// maintenance operation.
    ///
    /// Returns the number of leaf and internal nodes eliminated by the merge
    /// (i.e., the reduction in total node count).
    ///
    /// The `_info` parameter is accepted for API completeness; all under-full
    /// nodes are resolved by the full-tree compaction.
    pub fn merge_left(&mut self, _info: &UnderfullNodeInfo) -> MergeStats {
        self.merge_impl()
    }

    /// Merge an under-full node with its right sibling.
    ///
    /// Equivalent to [`merge_left`](Self::merge_left); see its documentation.
    pub fn merge_right(&mut self, _info: &UnderfullNodeInfo) -> MergeStats {
        self.merge_impl()
    }

    /// Redistribute entries/children from a richer sibling to an under-full
    /// node.
    ///
    /// Equivalent to [`merge_left`](Self::merge_left); see its documentation.
    pub fn redistribute(&mut self, _info: &UnderfullNodeInfo) -> MergeStats {
        self.merge_impl()
    }

    /// Common implementation for merge and redistribute operations.
    fn merge_impl(&mut self) -> MergeStats {
        let before_leaves = self.leaf_count();
        let before_nodes = self.node_count();
        self.compact();
        let after_leaves = self.leaf_count();
        let after_nodes = self.node_count();
        MergeStats {
            leaves_freed: before_leaves.saturating_sub(after_leaves) as u64,
            total_nodes_freed: before_nodes.saturating_sub(after_nodes) as u64,
            fill_after: self.fill_percent(),
            nodes_after: after_nodes as u64,
        }
    }

    /// Number of leaf nodes in the tree.
    #[must_use]
    pub fn leaf_count(&self) -> usize {
        Self::count_leaves(&self.root)
    }

    fn count_leaves(node: &BTreeNode<K, V>) -> usize {
        match node {
            BTreeNode::Leaf(_, _) => 1,
            BTreeNode::Internal { children, .. } => {
                children.iter().map(|c| Self::count_leaves(c)).sum()
            }
        }
    }

    /// Number of internal (non-leaf) nodes in the tree.
    #[must_use]
    pub fn internal_count(&self) -> usize {
        if self.is_empty() {
            return 0;
        }
        Self::count_internals(&self.root)
    }

    fn count_internals(node: &BTreeNode<K, V>) -> usize {
        match node {
            BTreeNode::Leaf(_, _) => 0,
            BTreeNode::Internal { children, .. } => {
                1 + children
                    .iter()
                    .map(|c| Self::count_internals(c))
                    .sum::<usize>()
            }
        }
    }

    /// Total number of nodes (leaves + internals).
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.leaf_count() + self.internal_count()
    }

    /// Verify BLAKE3-256 checksums on every node in the tree.
    ///
    /// Walks the tree depth-first, recomputing each node's checksum and
    /// comparing against the stored value. Returns `Ok(())` when all
    /// nodes match, or `Err(BTreeError::ChecksumMismatch)` with the
    /// first mismatched node.
    ///
    /// This is a structural integrity check — it verifies that the node
    /// count and child checksum chain are intact.
    pub fn verify_checksums(&self) -> Result<(), BTreeError> {
        Self::verify_node_checksums(&self.root)
    }

    fn verify_node_checksums(node: &BTreeNode<K, V>) -> Result<(), BTreeError> {
        match node {
            BTreeNode::Leaf(entries, checksum) => {
                let expected = leaf_checksum(entries.len());
                if *checksum != expected {
                    return Err(BTreeError::ChecksumMismatch);
                }
                Ok(())
            }
            BTreeNode::Internal {
                children, checksum, ..
            } => {
                let expected = internal_checksum(children.len(), children);
                if *checksum != expected {
                    return Err(BTreeError::ChecksumMismatch);
                }
                for child in children {
                    Self::verify_node_checksums(child)?;
                }
                Ok(())
            }
        }
    }

    /// Average leaf fill percentage as 0.0-1.0.
    ///
    /// Computed as `entries / (leaf_count * MAX_LEAF)`. Returns 1.0
    /// if the tree is empty (no leaves means nothing to fill).
    ///
    /// A tree with 5 entries, 2 leaves, and MAX_LEAF=8 has fill
    /// `5 / (2 * 8) = 0.3125`. After compaction, this would become
    /// `5 / (1 * 8) = 0.625`.
    #[must_use]
    pub fn fill_percent(&self) -> f64 {
        if self.is_empty() {
            return 1.0;
        }
        let leaves = self.leaf_count();
        self.len as f64 / (leaves as f64 * MAX_LEAF as f64)
    }

    /// Returns information about nodes whose fill ratio is below
    ///  (0.0–1.0). The root is exempt.
    ///
    /// Each returned entry identifies a node that may need deferred
    /// merge/redistribution via the btree cleanup queue.
    #[must_use]
    pub fn underfull_nodes(&self, threshold: f64) -> Vec<UnderfullNodeInfo> {
        let mut out = Vec::new();
        if self.len == 0 {
            return out;
        }
        Self::collect_underfull(&self.root, threshold, true, &mut out);
        out
    }

    fn collect_underfull(
        node: &BTreeNode<K, V>,
        threshold: f64,
        is_root: bool,
        out: &mut Vec<UnderfullNodeInfo>,
    ) {
        match node {
            BTreeNode::Leaf(entries, _) => {
                let fill = entries.len() as f64 / MAX_LEAF as f64;
                if !is_root && fill < threshold {
                    out.push(UnderfullNodeInfo {
                        node_id: NodeId(0), // populated by caller if needed
                        is_leaf: true,
                        fill_count: entries.len() as u64,
                        max_capacity: MAX_LEAF as u64,
                    });
                }
            }
            BTreeNode::Internal { children, .. } => {
                for child in children {
                    Self::collect_underfull(child, threshold, false, out);
                }
            }
        }
    }
    // ------------------------------------------------------------------
    // Validation
    // ------------------------------------------------------------------

    /// Validates the B+tree invariants.
    ///
    /// Checks:
    /// - Leaf nodes do not exceed `MAX_LEAF` entries.
    /// - Internal nodes have 2..=MAX_INTERNAL children.
    /// - Internal node key count == children.len() - 1.
    /// - Keys within nodes are strictly ascending.
    /// - Separator keys match descendant min keys.
    /// - BLAKE3-256 checksums match for every node.
    pub fn validate(&self) -> Result<(), BTreeError> {
        if self.len == 0 {
            // Empty tree: root must be an empty leaf.
            match &self.root {
                BTreeNode::Leaf(entries, _) if entries.is_empty() => {
                    // Also verify checksum
                    let expected = leaf_checksum(0);
                    if self.root.checksum() != expected {
                        return Err(BTreeError::ChecksumMismatch);
                    }
                    Ok(())
                }
                _ => Err(BTreeError::KeyChildMismatch),
            }
        } else {
            Self::validate_node(&self.root, true)?;
            Self::verify_node_checksums(&self.root)
        }
    }

    fn validate_node(node: &BTreeNode<K, V>, is_root: bool) -> Result<(), BTreeError> {
        match node {
            BTreeNode::Leaf(entries, _) => {
                if entries.len() > MAX_LEAF {
                    return Err(BTreeError::LeafOverflow);
                }
                if !is_root && entries.len() < Self::MIN_LEAF {
                    return Err(BTreeError::LeafUnderflow);
                }
                for w in entries.windows(2) {
                    if w[0].0 >= w[1].0 {
                        return Err(BTreeError::KeyOrderViolation);
                    }
                }
                Ok(())
            }
            BTreeNode::Internal { keys, children, .. } => {
                if children.len() < 2 {
                    return Err(BTreeError::InternalTooFewChildren);
                }
                if children.len() > MAX_INTERNAL {
                    return Err(BTreeError::InternalOverflow);
                }
                if !is_root && children.len() < Self::MIN_INTERNAL {
                    return Err(BTreeError::InternalUnderflow);
                }
                if keys.len() != children.len() - 1 {
                    return Err(BTreeError::KeyChildMismatch);
                }
                // Check separator keys match child min keys.
                for (i, key) in keys.iter().enumerate() {
                    let child_min = children[i + 1].min_key();
                    if key != &child_min {
                        return Err(BTreeError::SeparatorMismatch);
                    }
                }
                // Check separator keys are sorted.
                for w in keys.windows(2) {
                    if w[0] >= w[1] {
                        return Err(BTreeError::KeyOrderViolation);
                    }
                }
                // Recurse.
                for child in children {
                    Self::validate_node(child, false)?;
                }
                Ok(())
            }
        }
    }

    // ------------------------------------------------------------------
    // Private rebuild
    // ------------------------------------------------------------------

    fn collect_all_entries(&self) -> Vec<(K, V)> {
        let mut entries = Vec::new();
        self.root.collect_all(&mut entries);
        entries
    }

    /// Rebuild the tree with minimum-fill guarantees via redistribution.
    ///
    /// Every non-root leaf holds at least `MIN_LEAF` entries; every
    /// non-root internal node has at least `MIN_INTERNAL` children.
    /// The root is exempt from underflow.
    fn rebuild_compact(&mut self, entries: &[(K, V)]) {
        self.len = entries.len();

        if entries.is_empty() {
            self.root = BTreeNode::Leaf(Vec::new(), leaf_checksum(0));
            return;
        }

        let mut current = Self::build_compact_leaves(entries);
        while current.len() > 1 {
            current = Self::build_compact_internal_level(current);
        }

        self.root = current.into_iter().next().unwrap();
    }

    /// Build leaf nodes with even distribution guaranteeing MIN_LEAF fill.
    fn build_compact_leaves(entries: &[(K, V)]) -> Vec<BTreeNode<K, V>> {
        let n = entries.len();
        if n <= MAX_LEAF {
            return vec![BTreeNode::Leaf(
                entries.to_vec(),
                leaf_checksum(entries.len()),
            )];
        }

        let mut num_leaves = n.div_ceil(MAX_LEAF);
        while num_leaves > 1 && n.div_ceil(num_leaves) < Self::MIN_LEAF {
            num_leaves -= 1;
        }

        let base = n / num_leaves;
        let remainder = n % num_leaves;
        let mut leaves = Vec::with_capacity(num_leaves);
        let mut offset = 0;

        for i in 0..num_leaves {
            let size = if i < remainder { base + 1 } else { base };
            leaves.push(BTreeNode::Leaf(
                entries[offset..offset + size].to_vec(),
                leaf_checksum(size),
            ));
            offset += size;
        }

        leaves
    }

    /// Build the next internal level with even child distribution.
    fn build_compact_internal_level(children: Vec<BTreeNode<K, V>>) -> Vec<BTreeNode<K, V>> {
        let n = children.len();
        if n <= MAX_INTERNAL {
            if n == 1 {
                return children;
            }
            let keys: Vec<K> = children.iter().skip(1).map(|c| c.min_key()).collect();
            let cs = internal_checksum(children.len(), &children);
            return vec![BTreeNode::Internal {
                keys,
                children,
                checksum: cs,
            }];
        }

        let mut num_internals = n.div_ceil(MAX_INTERNAL);
        while num_internals > 1 && n.div_ceil(num_internals) < Self::MIN_INTERNAL {
            num_internals -= 1;
        }

        let base = n / num_internals;
        let remainder = n % num_internals;
        let mut nodes = Vec::with_capacity(num_internals);
        let mut offset = 0;

        for i in 0..num_internals {
            let size = if i < remainder { base + 1 } else { base };
            if size == 1 {
                nodes.push(children[offset].clone());
            } else {
                let chunk = &children[offset..offset + size];
                let keys: Vec<K> = chunk.iter().skip(1).map(|c| c.min_key()).collect();
                let cs = internal_checksum(chunk.len(), chunk);
                nodes.push(BTreeNode::Internal {
                    keys,
                    children: chunk.to_vec(),
                    checksum: cs,
                });
            }
            offset += size;
        }

        nodes
    }

    fn build_compact_internal_level_from_nodes(
        children: Vec<BTreeNode<K, V>>,
    ) -> Vec<BTreeNode<K, V>> {
        let n = children.len();
        if n <= MAX_INTERNAL {
            if n == 1 {
                return children;
            }
            let keys: Vec<K> = children.iter().skip(1).map(|c| c.min_key()).collect();
            let cs = internal_checksum(children.len(), &children);
            return vec![BTreeNode::Internal {
                keys,
                children,
                checksum: cs,
            }];
        }

        let mut num_internals = n.div_ceil(MAX_INTERNAL);
        while num_internals > 1 && n.div_ceil(num_internals) < Self::MIN_INTERNAL {
            num_internals -= 1;
        }

        let base = n / num_internals;
        let remainder = n % num_internals;
        let mut nodes = Vec::with_capacity(num_internals);
        let mut iter = children.into_iter();

        for i in 0..num_internals {
            let size = if i < remainder { base + 1 } else { base };
            let mut group = Vec::with_capacity(size);
            for _ in 0..size {
                group.push(iter.next().expect("partition sizes consume all children"));
            }
            if group.len() == 1 {
                nodes.push(group.pop().unwrap());
            } else {
                let keys: Vec<K> = group.iter().skip(1).map(|c| c.min_key()).collect();
                let cs = internal_checksum(group.len(), &group);
                nodes.push(BTreeNode::Internal {
                    keys,
                    children: group,
                    checksum: cs,
                });
            }
        }

        nodes
    }

    fn build_compact_root_from_sorted_iter<I, E>(
        expected_len: usize,
        entries: I,
    ) -> Result<BTreeNode<K, V>, RebuildFromSortedIterError<E>>
    where
        I: IntoIterator<Item = Result<(K, V), E>>,
    {
        let mut iter = entries.into_iter();
        if expected_len == 0 {
            return match iter.next() {
                None => Ok(BTreeNode::Leaf(Vec::new(), leaf_checksum(0))),
                Some(Ok(_)) => Err(RebuildFromSortedIterError::Tree(BTreeError::LengthMismatch)),
                Some(Err(err)) => Err(RebuildFromSortedIterError::Source(err)),
            };
        }

        let mut num_leaves = expected_len.div_ceil(MAX_LEAF);
        while num_leaves > 1 && expected_len.div_ceil(num_leaves) < Self::MIN_LEAF {
            num_leaves -= 1;
        }

        let base = expected_len / num_leaves;
        let remainder = expected_len % num_leaves;
        let mut leaves = Vec::with_capacity(num_leaves);
        let mut previous_key: Option<K> = None;

        for i in 0..num_leaves {
            let size = if i < remainder { base + 1 } else { base };
            let mut leaf_entries = Vec::with_capacity(size);
            for _ in 0..size {
                let (key, value) = match iter.next() {
                    Some(Ok(entry)) => entry,
                    Some(Err(err)) => return Err(RebuildFromSortedIterError::Source(err)),
                    None => {
                        return Err(RebuildFromSortedIterError::Tree(BTreeError::LengthMismatch));
                    }
                };
                if let Some(prev) = &previous_key {
                    if prev >= &key {
                        return Err(RebuildFromSortedIterError::Tree(
                            BTreeError::KeyOrderViolation,
                        ));
                    }
                }
                previous_key = Some(key.clone());
                leaf_entries.push((key, value));
            }
            leaves.push(BTreeNode::Leaf(leaf_entries, leaf_checksum(size)));
        }

        match iter.next() {
            None => {}
            Some(Ok(_)) => {
                return Err(RebuildFromSortedIterError::Tree(BTreeError::LengthMismatch));
            }
            Some(Err(err)) => return Err(RebuildFromSortedIterError::Source(err)),
        }

        let mut current = leaves;
        while current.len() > 1 {
            current = Self::build_compact_internal_level_from_nodes(current);
        }

        Ok(current.into_iter().next().unwrap())
    }

    fn build_compact_root_from_sorted_unknown_len_iter<I, E>(
        entries: I,
    ) -> Result<(BTreeNode<K, V>, usize), RebuildFromSortedIterError<E>>
    where
        I: IntoIterator<Item = Result<(K, V), E>>,
    {
        let mut leaves: Vec<BTreeNode<K, V>> = Vec::new();
        let mut leaf_entries: Vec<(K, V)> = Vec::with_capacity(MAX_LEAF);
        let mut previous_key: Option<K> = None;
        let mut actual_len = 0usize;

        for entry in entries {
            let (key, value) = entry.map_err(RebuildFromSortedIterError::Source)?;
            if let Some(prev) = &previous_key {
                if prev >= &key {
                    return Err(RebuildFromSortedIterError::Tree(
                        BTreeError::KeyOrderViolation,
                    ));
                }
            }
            previous_key = Some(key.clone());
            leaf_entries.push((key, value));
            actual_len = actual_len
                .checked_add(1)
                .ok_or(RebuildFromSortedIterError::Tree(BTreeError::LengthMismatch))?;

            if leaf_entries.len() == MAX_LEAF {
                let full_leaf = core::mem::replace(&mut leaf_entries, Vec::with_capacity(MAX_LEAF));
                leaves.push(BTreeNode::Leaf(full_leaf, leaf_checksum(MAX_LEAF)));
            }
        }

        if actual_len == 0 {
            return Ok((BTreeNode::Leaf(Vec::new(), leaf_checksum(0)), 0));
        }

        if !leaf_entries.is_empty() {
            if leaves.is_empty() || leaf_entries.len() >= Self::MIN_LEAF {
                let size = leaf_entries.len();
                leaves.push(BTreeNode::Leaf(leaf_entries, leaf_checksum(size)));
            } else {
                let previous = leaves
                    .pop()
                    .expect("a short final leaf can be rebalanced only with a previous leaf");
                let mut previous_entries = match previous {
                    BTreeNode::Leaf(entries, _) => entries,
                    BTreeNode::Internal { .. } => {
                        unreachable!("streamed leaf build only stores leaf nodes before internals")
                    }
                };
                previous_entries.extend(leaf_entries);

                let left_len = previous_entries.len() / 2;
                let right_entries = previous_entries.split_off(left_len);
                let right_len = right_entries.len();
                leaves.push(BTreeNode::Leaf(previous_entries, leaf_checksum(left_len)));
                leaves.push(BTreeNode::Leaf(right_entries, leaf_checksum(right_len)));
            }
        }

        let mut current = leaves;
        while current.len() > 1 {
            current = Self::build_compact_internal_level_from_nodes(current);
        }

        Ok((current.into_iter().next().unwrap(), actual_len))
    }

    /// Rebuild the B+tree from a sorted, non-empty entry list.
    /// Rebuild the tree from a sorted `(key, value)` slice.
    ///
    /// The slice must be sorted by key in ascending order. Uses a single-pass
    /// bottom-up construction (O(n)).
    ///
    /// # Panics
    ///
    /// Panics if entries are not sorted by key; this is not checked.
    #[doc(hidden)]
    pub fn rebuild(&mut self, entries: &[(K, V)]) {
        self.len = entries.len();

        if entries.is_empty() {
            self.root = BTreeNode::Leaf(Vec::new(), leaf_checksum(0));
            return;
        }

        // Build leaf pages.
        let mut leaf_nodes: Vec<BTreeNode<K, V>> = Vec::new();
        for chunk in entries.chunks(MAX_LEAF) {
            leaf_nodes.push(BTreeNode::Leaf(chunk.to_vec(), leaf_checksum(chunk.len())));
        }

        // Build internal levels bottom-up.
        let mut current = leaf_nodes;
        while current.len() > 1 {
            let mut next: Vec<BTreeNode<K, V>> = Vec::new();
            for chunk in current.chunks(MAX_INTERNAL) {
                if chunk.len() == 1 {
                    next.push(chunk[0].clone());
                } else {
                    let keys: Vec<K> = chunk.iter().skip(1).map(|c| c.min_key()).collect();
                    let cs = internal_checksum(chunk.len(), chunk);
                    next.push(BTreeNode::Internal {
                        keys,
                        children: chunk.to_vec(),
                        checksum: cs,
                    });
                }
            }
            current = next;
        }

        self.root = current.into_iter().next().unwrap();
    }
}

impl<K: Ord + Clone, V: Clone, const MAX_LEAF: usize, const MAX_INTERNAL: usize> Default
    for BPlusTree<K, V, MAX_LEAF, MAX_INTERNAL>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<
        K: Ord + Clone + fmt::Debug,
        V: Clone + fmt::Debug,
        const MAX_LEAF: usize,
        const MAX_INTERNAL: usize,
    > fmt::Display for BPlusTree<K, V, MAX_LEAF, MAX_INTERNAL>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BPlusTree(len={} depth={} max_leaf={} max_internal={})",
            self.len,
            self.depth(),
            MAX_LEAF,
            MAX_INTERNAL
        )
    }
}

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// PersistentBTree
// ---------------------------------------------------------------------------

/// A B+tree backed by persistent page storage and a write-ahead log.
///
/// Wraps the in-memory [`BPlusTree`] and synchronizes mutations to
/// durable storage through the [`PageStore`] trait with WAL crash
/// safety provided by [`crate::wal::WalWriter`].
///
/// # Lifecycle
///
/// 1. Create with [`PersistentBTree::new`] for a fresh tree.
/// 2. Mutate through the inner tree: `insert`, `delete`, etc.
/// 3. Call [`flush_to_store`] to serialize all nodes to pages and
///    write them to the [`PageStore`]. After a successful flush,
///    the WAL is cleared (checkpoint).
/// 4. On recovery: replay the WAL to obtain the latest page images,
///    then rebuild the in-memory tree from those pages.
///
/// [`flush_to_store`]: PersistentBTree::flush_to_store
#[derive(Clone, Debug)]
pub struct PersistentBTree<
    K: Ord + Clone,
    V: Clone,
    const MAX_LEAF: usize = 45,
    const MAX_INTERNAL: usize = 45,
> {
    /// In-memory tree; all reads go here.
    tree: BPlusTree<K, V, MAX_LEAF, MAX_INTERNAL>,
    /// Write-ahead log for crash-safe mutation recording.
    wal: crate::wal::WalWriter,
    /// Monotonic page identifier counter.
    next_page_id: u32,
}

impl<K: Ord + Clone, V: Clone, const MAX_LEAF: usize, const MAX_INTERNAL: usize>
    PersistentBTree<K, V, MAX_LEAF, MAX_INTERNAL>
{
    /// Create an empty persistent tree with a fresh WAL starting at
    /// generation 0.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tree: BPlusTree::new(),
            wal: crate::wal::WalWriter::new(0),
            next_page_id: 0,
        }
    }

    /// Create with an existing WAL (e.g. after recovery).
    #[must_use]
    pub fn with_wal(wal: crate::wal::WalWriter, next_page_id: u32) -> Self {
        Self {
            tree: BPlusTree::new(),
            wal,
            next_page_id,
        }
    }

    /// Recover a persistent tree from WAL data.
    ///
    /// Replays the WAL entries, decodes recovered pages back into
    /// key-value pairs, rebuilds the in-memory B+tree, and creates
    /// a fresh WAL writer starting after the last recovered generation.
    ///
    /// Returns `Ok(PersistentBTree)` on success or an error if the WAL
    /// data is corrupt or truncated.
    pub fn from_wal_replay(wal_data: &[u8]) -> Result<Self, FromWalError>
    where
        K: crate::page::PageSerdeKey,
        V: crate::page::PageSerdeValue,
    {
        let (pages, max_gen) = crate::wal::replay_wal(wal_data).map_err(FromWalError::WalError)?;

        let mut tree = BPlusTree::new();
        let mut max_page_id: u32 = 0;

        for (page_id, page) in &pages {
            let header = crate::page::read_header(page);
            let body = crate::page::page_body(page);

            // Verify page integrity before decoding.
            if !header.is_valid_magic() {
                return Err(FromWalError::PageValidation(PageChecksumError::BadMagic {
                    got: header.magic,
                }));
            }
            crate::page::verify_page_checksum(&header, body)
                .map_err(FromWalError::PageValidation)?;

            match header.page_type() {
                Some(PageType::Leaf) => {
                    let entries =
                        crate::page::decode_leaf_body(body).map_err(FromWalError::PageFormat)?;
                    for (kbytes, vbytes) in &entries {
                        let key =
                            K::deserialize_from_slice(kbytes).ok_or(FromWalError::Deserialize)?;
                        let val =
                            V::deserialize_from_slice(vbytes).ok_or(FromWalError::Deserialize)?;
                        tree.insert(key, val);
                    }
                }
                Some(PageType::Internal) => {
                    // Internal pages only hold routing keys and child pointers;
                    // all user data lives in leaf pages. Skip for reconstruction
                    // since we rebuild the tree from leaf entries only.
                }
                Some(PageType::Free) | None => {
                    // Skip free or unknown page types.
                }
            }

            if *page_id > max_page_id {
                max_page_id = *page_id;
            }
        }

        let next_gen = if pages.is_empty() {
            0
        } else {
            max_gen.wrapping_add(1)
        };
        let wal = crate::wal::WalWriter::new(next_gen);

        Ok(Self {
            tree,
            wal,
            next_page_id: max_page_id.wrapping_add(1),
        })
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

    /// Look up a key.
    #[must_use]
    pub fn get(&self, key: &K) -> Option<&V> {
        self.tree.get(key)
    }

    /// Check whether a key exists.
    #[must_use]
    pub fn contains_key(&self, key: &K) -> bool {
        self.tree.contains_key(key)
    }

    /// Insert a key-value pair. Returns the previous value if any.
    ///
    /// After insertion, a WAL entry is appended recording the changed
    /// pages. The caller should periodically call [`flush_to_store`]
    /// to persist the tree and checkpoint the WAL.
    pub fn insert(&mut self, key: K, value: V) -> Option<V>
    where
        K: crate::page::PageSerdeKey,
        V: crate::page::PageSerdeValue,
    {
        let prev = self.tree.insert(key, value);
        // Record the mutation in the WAL for crash safety.
        self.append_tree_to_wal();
        prev
    }

    /// Delete a key. Returns the removed value if found.
    pub fn delete(&mut self, key: &K) -> Option<V>
    where
        K: crate::page::PageSerdeKey,
        V: crate::page::PageSerdeValue,
    {
        let prev = self.tree.delete(key);
        if prev.is_some() {
            self.append_tree_to_wal();
        }
        prev
    }

    /// Reference to the WAL writer.
    #[must_use]
    pub fn wal(&self) -> &crate::wal::WalWriter {
        &self.wal
    }

    /// Mutable reference to the WAL writer.
    pub fn wal_mut(&mut self) -> &mut crate::wal::WalWriter {
        &mut self.wal
    }

    /// Current WAL generation number (one past the last assigned).
    #[must_use]
    pub fn next_wal_generation(&self) -> u32 {
        self.wal.next_generation()
    }

    /// Serialize the entire tree into pages and write them to `store`.
    ///
    /// Uses the page body encoding helpers from [`crate::page`] to
    /// serialize leaf and internal nodes. Each node becomes one
    /// [`BtreePage`] with a BLAKE3-authenticated [`PageHeader`].
    ///
    /// After a successful flush the WAL is cleared (checkpoint).
    ///
    /// Returns the list of page IDs written.
    pub fn flush_to_store(
        &mut self,
        store: &mut dyn PageStore,
    ) -> Result<Vec<u32>, PersistentBTreeError>
    where
        K: crate::page::PageSerdeKey,
        V: crate::page::PageSerdeValue,
    {
        if self.tree.is_empty() {
            return Ok(Vec::new());
        }
        let mut page_ids = Vec::new();
        self.flush_node(&self.tree.root.clone(), store, &mut page_ids)?;
        // Checkpoint: clear the WAL now that pages are durable.
        self.wal.clear();
        Ok(page_ids)
    }

    /// Recursively flush a node into pages.
    fn flush_node(
        &mut self,
        node: &BTreeNode<K, V>,
        store: &mut dyn PageStore,
        page_ids: &mut Vec<u32>,
    ) -> Result<u32, PersistentBTreeError>
    where
        K: crate::page::PageSerdeKey,
        V: crate::page::PageSerdeValue,
    {
        match node {
            BTreeNode::Leaf(entries, _) => {
                let page_id = self.alloc_page_id();
                let mut body = [0u8; PAGE_BODY_SIZE];
                // Serialize keys and values, holding the owned buffers.
                let typed: Vec<(Vec<u8>, Vec<u8>)> = entries
                    .iter()
                    .map(|(k, v)| (K::serialize_to_vec(k), V::serialize_to_vec(v)))
                    .collect();
                let slices: Vec<(&[u8], &[u8])> = typed
                    .iter()
                    .map(|(k, v)| (k.as_slice(), v.as_slice()))
                    .collect();
                let written = crate::page::encode_leaf_body(&slices, &mut body);

                let mut header = PageHeader::new(PageType::Leaf, self.wal.next_generation());
                let mut page = crate::page::blank_page();
                page[PAGE_HEADER_SIZE..PAGE_HEADER_SIZE + written]
                    .copy_from_slice(&body[..written]);
                let pt = PageType::Leaf;
                header.checksum =
                    crate::page::compute_page_checksum(pt, crate::page::page_body(&page));
                crate::page::write_header(&mut page, &header);

                store.write_page(page_id, &page)?;
                page_ids.push(page_id);
                Ok(page_id)
            }
            BTreeNode::Internal { keys, children, .. } => {
                // Flush children first (COW: children before parent).
                let child_ids: Vec<u32> = children
                    .iter()
                    .map(|child| self.flush_node(child, store, page_ids))
                    .collect::<Result<_, _>>()?;

                let page_id = self.alloc_page_id();
                let child_u64: Vec<u64> = child_ids.iter().map(|&id| id as u64).collect();
                // Serialize keys, holding owned buffers.
                let key_bufs: Vec<Vec<u8>> = keys.iter().map(|k| K::serialize_to_vec(k)).collect();
                let key_slices: Vec<&[u8]> = key_bufs.iter().map(|v| v.as_slice()).collect();

                let mut body = [0u8; PAGE_BODY_SIZE];
                let written = crate::page::encode_internal_body(&child_u64, &key_slices, &mut body);

                let mut header = PageHeader::new(PageType::Internal, self.wal.next_generation());
                let mut page = crate::page::blank_page();
                page[PAGE_HEADER_SIZE..PAGE_HEADER_SIZE + written]
                    .copy_from_slice(&body[..written]);
                let pt = PageType::Internal;
                header.checksum =
                    crate::page::compute_page_checksum(pt, crate::page::page_body(&page));
                crate::page::write_header(&mut page, &header);

                store.write_page(page_id, &page)?;
                page_ids.push(page_id);
                Ok(page_id)
            }
        }
    }

    /// Append the entire tree state to the WAL as page entries.
    ///
    /// Each node is serialized into a page, and a WAL entry records
    /// the page image. This provides crash safety: if a crash occurs
    /// before the next `flush_to_store`, the WAL can be replayed to
    /// recover the tree state.
    fn append_tree_to_wal(&mut self)
    where
        K: crate::page::PageSerdeKey,
        V: crate::page::PageSerdeValue,
    {
        if self.tree.is_empty() {
            return;
        }
        let mut pid = self.next_page_id;
        self.append_node_to_wal(&self.tree.root.clone(), &mut pid);
    }

    fn append_node_to_wal(&mut self, node: &BTreeNode<K, V>, next_pid: &mut u32)
    where
        K: crate::page::PageSerdeKey,
        V: crate::page::PageSerdeValue,
    {
        match node {
            BTreeNode::Leaf(entries, _) => {
                let page_id = *next_pid;
                *next_pid += 1;
                let gen = self.wal.next_generation();
                let mut body = [0u8; PAGE_BODY_SIZE];
                let typed: Vec<(Vec<u8>, Vec<u8>)> = entries
                    .iter()
                    .map(|(k, v)| (K::serialize_to_vec(k), V::serialize_to_vec(v)))
                    .collect();
                let slices: Vec<(&[u8], &[u8])> = typed
                    .iter()
                    .map(|(k, v)| (k.as_slice(), v.as_slice()))
                    .collect();
                let written = crate::page::encode_leaf_body(&slices, &mut body);

                let mut page = crate::page::blank_page();
                page[PAGE_HEADER_SIZE..PAGE_HEADER_SIZE + written]
                    .copy_from_slice(&body[..written]);
                // Seal the page with a BLAKE3-authenticated header.
                let mut header = crate::page::PageHeader::new(PageType::Leaf, gen);
                let pt = PageType::Leaf;
                header.checksum =
                    crate::page::compute_page_checksum(pt, crate::page::page_body(&page));
                crate::page::write_header(&mut page, &header);
                self.wal.append_write(page_id, &page);
            }
            BTreeNode::Internal { keys, children, .. } => {
                let page_id = *next_pid;
                *next_pid += 1;

                // Children first
                let mut child_ids = Vec::with_capacity(children.len());
                for child in children {
                    let cid = *next_pid;
                    child_ids.push(cid as u64);
                    self.append_node_to_wal(child, next_pid);
                }

                // Now this internal node
                let gen = self.wal.next_generation();
                let key_bufs: Vec<Vec<u8>> = keys.iter().map(|k| K::serialize_to_vec(k)).collect();
                let key_slices: Vec<&[u8]> = key_bufs.iter().map(|v| v.as_slice()).collect();

                let mut body = [0u8; PAGE_BODY_SIZE];
                let written = crate::page::encode_internal_body(&child_ids, &key_slices, &mut body);

                let mut page = crate::page::blank_page();
                page[PAGE_HEADER_SIZE..PAGE_HEADER_SIZE + written]
                    .copy_from_slice(&body[..written]);
                // Seal the page with a BLAKE3-authenticated header.
                let mut header = crate::page::PageHeader::new(PageType::Internal, gen);
                let pt = PageType::Internal;
                header.checksum =
                    crate::page::compute_page_checksum(pt, crate::page::page_body(&page));
                crate::page::write_header(&mut page, &header);
                self.wal.append_write(page_id, &page);
            }
        }
    }

    fn alloc_page_id(&mut self) -> u32 {
        let id = self.next_page_id;
        self.next_page_id += 1;
        id
    }
}

impl<K: Ord + Clone, V: Clone, const MAX_LEAF: usize, const MAX_INTERNAL: usize> Default
    for PersistentBTree<K, V, MAX_LEAF, MAX_INTERNAL>
{
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PersistentBTreeError
// ---------------------------------------------------------------------------

/// Error from [`PersistentBTree`] persistence operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PersistentBTreeError {
    /// Error from the underlying [`PageStore`].
    Store(PageStoreError),
    /// Attempted to flush an empty tree.
    EmptyTree,
}

// ---------------------------------------------------------------------------
// FromWalError
// ---------------------------------------------------------------------------

/// Error returned by [`PersistentBTree::from_wal_replay`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FromWalError {
    /// The WAL data is corrupt.
    WalError(crate::wal::WalError),
    /// A page failed BLAKE3 checksum verification.
    PageValidation(PageChecksumError),
    /// A page body could not be decoded.
    PageFormat(PageFormatError),
    /// A key or value could not be deserialized from bytes.
    Deserialize,
}

impl From<PageStoreError> for PersistentBTreeError {
    fn from(e: PageStoreError) -> Self {
        Self::Store(e)
    }
}

impl fmt::Display for PersistentBTreeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(e) => write!(f, "page store error: {e}"),
            Self::EmptyTree => f.write_str("cannot flush an empty persistent B+tree"),
        }
    }
}

impl fmt::Display for FromWalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WalError(e) => write!(f, "WAL error: {e}"),
            Self::PageValidation(e) => write!(f, "page validation error: {e}"),
            Self::PageFormat(e) => write!(f, "page format error: {e}"),
            Self::Deserialize => f.write_str("failed to deserialize key or value"),
        }
    }
}

// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::string::String;
    use alloc::string::ToString;
    use alloc::vec;

    // Use small fanout to force splits easily.
    type TestTree = BPlusTree<u64, String, 4, 4>;

    fn make_tree(pairs: &[(u64, &str)]) -> TestTree {
        let mut t = TestTree::new();
        for (k, v) in pairs {
            t.insert(*k, v.to_string());
        }
        t
    }

    // ── empty ────────────────────────────────────────────────────────

    #[test]
    fn new_is_empty() {
        let t = TestTree::new();
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
        assert_eq!(t.depth(), 1);
        assert!(t.validate().is_ok());
    }

    #[test]
    fn empty_get_none() {
        let t = TestTree::new();
        assert!(t.get(&1).is_none());
        assert!(!t.contains_key(&1));
    }

    #[test]
    fn empty_delete_none() {
        let mut t = TestTree::new();
        assert!(t.delete(&1).is_none());
    }

    #[test]
    fn empty_range() {
        let t = TestTree::new();
        assert!(t.range(0..10).is_empty());
    }

    // ── insert / get ─────────────────────────────────────────────────

    #[test]
    fn insert_single() {
        let mut t = TestTree::new();
        assert!(t.insert(10, "a".into()).is_none());
        assert_eq!(t.len(), 1);
        assert_eq!(t.get(&10).unwrap(), "a");
    }

    #[test]
    fn insert_replace() {
        let mut t = TestTree::new();
        t.insert(10, "a".into());
        let old = t.insert(10, "b".into());
        assert_eq!(old.unwrap(), "a");
        assert_eq!(t.len(), 1);
        assert_eq!(t.get(&10).unwrap(), "b");
    }

    #[test]
    fn insert_many_ordered() {
        let mut t = TestTree::new();
        for i in 0..10u64 {
            t.insert(i, i.to_string());
        }
        assert_eq!(t.len(), 10);
        for i in 0..10u64 {
            assert_eq!(t.get(&i).unwrap(), &i.to_string());
        }
        assert!(t.validate().is_ok());
    }

    #[test]
    fn insert_many_reverse() {
        let mut t = TestTree::new();
        for i in (0..10u64).rev() {
            t.insert(i, i.to_string());
        }
        assert_eq!(t.len(), 10);
        assert!(t.validate().is_ok());
        // Verify all findable
        for i in 0..10u64 {
            assert_eq!(t.get(&i).unwrap(), &i.to_string());
        }
    }

    // ── delete ───────────────────────────────────────────────────────

    #[test]
    fn delete_middle() {
        let mut t = make_tree(&[(1, "a"), (2, "b"), (3, "c")]);
        assert_eq!(t.delete(&2).unwrap(), "b");
        assert_eq!(t.len(), 2);
        assert!(t.get(&2).is_none());
        assert!(t.validate().is_ok());
    }

    #[test]
    fn delete_first() {
        let mut t = make_tree(&[(1, "a"), (2, "b"), (3, "c")]);
        t.delete(&1).unwrap();
        assert_eq!(t.len(), 2);
        assert!(t.get(&1).is_none());
        assert!(t.validate().is_ok());
    }

    #[test]
    fn delete_last() {
        let mut t = make_tree(&[(1, "a"), (2, "b"), (3, "c")]);
        t.delete(&3).unwrap();
        assert_eq!(t.len(), 2);
        assert!(t.get(&3).is_none());
        assert!(t.validate().is_ok());
    }

    #[test]
    fn delete_all_to_empty() {
        let mut t = make_tree(&[(1, "a"), (2, "b"), (3, "c")]);
        t.delete(&1).unwrap();
        t.delete(&2).unwrap();
        t.delete(&3).unwrap();
        assert!(t.is_empty());
        assert!(t.validate().is_ok());
    }

    #[test]
    fn delete_nonexistent() {
        let mut t = make_tree(&[(1, "a")]);
        assert!(t.delete(&99).is_none());
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn delete_redistributes_deep_internal_children_and_preserves_range_cursor() {
        let mut t = TestTree::new();
        for i in 0..25u64 {
            t.insert(i, i.to_string());
        }
        assert_eq!(t.depth(), 3);
        assert_eq!(t.leaf_count(), 7);
        assert_eq!(t.internal_count(), 3);

        assert_eq!(t.delete(&12).unwrap(), "12");

        assert_eq!(t.len(), 24);
        assert_eq!(t.depth(), 3);
        assert_eq!(t.leaf_count(), 6);
        assert_eq!(t.internal_count(), 3);
        assert!(t.validate().is_ok());
        assert!(t.get(&12).is_none());
        assert_eq!(
            t.range(10..16)
                .into_iter()
                .map(|(key, _)| key)
                .collect::<alloc::vec::Vec<_>>(),
            vec![10, 11, 13, 14, 15]
        );
        for i in 0..25u64 {
            if i != 12 {
                assert_eq!(t.get(&i).unwrap(), &i.to_string());
            }
        }
    }

    #[test]
    fn delete_leaf_underflow_merges_to_single_leaf_and_keeps_remaining_findable() {
        let mut t = TestTree::new();
        for i in 0..5u64 {
            t.insert(i, i.to_string());
        }
        assert_eq!(t.depth(), 2);
        assert_eq!(t.leaf_count(), 2);
        assert_eq!(t.internal_count(), 1);

        assert_eq!(t.delete(&0).unwrap(), "0");

        assert_eq!(t.len(), 4);
        assert_eq!(t.depth(), 1);
        assert_eq!(t.leaf_count(), 1);
        assert_eq!(t.internal_count(), 0);
        assert!(t.validate().is_ok());
        assert_eq!(
            t.range(..)
                .into_iter()
                .map(|(key, _)| key)
                .collect::<alloc::vec::Vec<_>>(),
            vec![1, 2, 3, 4]
        );
        for i in 1..5u64 {
            assert_eq!(t.get(&i).unwrap(), &i.to_string());
        }
    }

    #[test]
    fn delete_internal_separator_rebuilds_promoted_separator_without_stale_lookup() {
        let mut t = TestTree::new();
        for i in 0..9u64 {
            t.insert(i, i.to_string());
        }
        match &t.root {
            BTreeNode::Internal { keys, children, .. } => {
                assert_eq!(keys, &vec![3, 6]);
                assert_eq!(children.len(), 3);
            }
            BTreeNode::Leaf(..) => panic!("expected internal root before delete"),
        }

        assert_eq!(t.delete(&3).unwrap(), "3");

        assert!(t.get(&3).is_none());
        assert_eq!(t.get(&5).unwrap(), "5");
        assert!(t.validate().is_ok());
        match &t.root {
            BTreeNode::Internal { keys, children, .. } => {
                assert_eq!(keys, &vec![5]);
                assert_eq!(children.len(), 2);
            }
            BTreeNode::Leaf(..) => panic!("expected internal root after delete"),
        }
        assert_eq!(
            t.range(..)
                .into_iter()
                .map(|(key, _)| key)
                .collect::<alloc::vec::Vec<_>>(),
            vec![0, 1, 2, 4, 5, 6, 7, 8]
        );
    }

    // ── clear ────────────────────────────────────────────────────────

    #[test]
    fn update_existing() {
        let mut t = TestTree::new();
        t.insert(10, "a".into());
        assert!(t.update(&10, |v| *v = "updated".into()));
        assert_eq!(t.get(&10).unwrap(), "updated");
        assert_eq!(t.len(), 1);
        assert!(t.validate().is_ok());
    }

    #[test]
    fn update_nonexistent() {
        let mut t = TestTree::new();
        t.insert(10, "a".into());
        assert!(!t.update(&99, |v| *v = "should_not".into()));
        assert_eq!(t.len(), 1);
        assert_eq!(t.get(&10).unwrap(), "a");
    }

    #[test]
    fn update_preserves_order() {
        let mut t = make_tree(&[(1, "a"), (2, "b"), (3, "c")]);
        assert!(t.update(&2, |v| *v = "beta".into()));
        assert_eq!(
            t.entries(),
            vec![(1, "a".into()), (2, "beta".into()), (3, "c".into())]
        );
        assert!(t.validate().is_ok());
    }

    #[test]
    fn update_on_large_tree() {
        let mut t = TestTree::new();
        for i in 0..20u64 {
            t.insert(i, i.to_string());
        }
        // Update middle entry
        assert!(t.update(&10, |v| *v = "ten".into()));
        assert_eq!(t.get(&10).unwrap(), "ten");
        assert_eq!(t.len(), 20);
        assert!(t.validate().is_ok());
        // Other entries unchanged
        assert_eq!(t.get(&5).unwrap(), "5");
        assert_eq!(t.get(&15).unwrap(), "15");
    }

    // ── clear ────────────────────────────────────────────────────────

    #[test]
    fn clear_empties() {
        let mut t = make_tree(&[(1, "a"), (2, "b")]);
        t.clear();
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
        assert!(t.validate().is_ok());
    }

    // ── range ────────────────────────────────────────────────────────

    #[test]
    fn range_full_unbounded() {
        let t = make_tree(&[(1, "a"), (2, "b"), (3, "c")]);
        assert_eq!(t.range(..).len(), 3);
    }

    #[test]
    fn range_bounded() {
        let t = make_tree(&[(1, "a"), (2, "b"), (3, "c"), (4, "d"), (5, "e")]);
        let r = t.range(2..4);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].0, 2);
        assert_eq!(r[1].0, 3);
    }

    #[test]
    fn range_from() {
        let t = make_tree(&[(1, "a"), (2, "b"), (3, "c")]);
        assert_eq!(t.range(2..).len(), 2);
    }

    #[test]
    fn range_to() {
        let t = make_tree(&[(1, "a"), (2, "b"), (3, "c")]);
        assert_eq!(t.range(..3).len(), 2);
    }

    #[test]
    fn range_empty_result() {
        let t = make_tree(&[(1, "a"), (2, "b")]);
        assert!(t.range(10..20).is_empty());
    }

    #[test]
    fn range_from_to() {
        let t = make_tree(&[(1, "a"), (2, "b"), (3, "c"), (4, "d")]);
        let r = t.range_from_to(&2, &4);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].0, 2);
        assert_eq!(r[1].0, 3);
    }

    // ── floor_entry ──────────────────────────────────────────────────

    #[test]
    fn floor_entry_empty_tree() {
        let t: TestTree = TestTree::new();
        assert_eq!(t.floor_entry(&10), None);
    }

    #[test]
    fn floor_entry_leaf_boundaries() {
        let t = make_tree(&[(10, "a"), (20, "b"), (30, "c")]);

        assert_eq!(t.floor_entry(&5), None);

        let exact = t.floor_entry(&20).unwrap();
        assert_eq!((*exact.0, exact.1.as_str()), (20, "b"));

        let between = t.floor_entry(&25).unwrap();
        assert_eq!((*between.0, between.1.as_str()), (20, "b"));

        let after_last = t.floor_entry(&99).unwrap();
        assert_eq!((*after_last.0, after_last.1.as_str()), (30, "c"));
    }

    #[test]
    fn floor_entry_multi_level_tree() {
        let mut t = TestTree::new();
        for i in 1..=100u64 {
            t.insert(i * 10, i.to_string());
        }
        assert!(t.depth() >= 3, "expected multi-level tree");

        let before_first = t.floor_entry(&9);
        assert_eq!(before_first, None);

        let between = t.floor_entry(&555).unwrap();
        assert_eq!((*between.0, between.1.as_str()), (550, "55"));

        let exact_separator_or_leaf_min = t.floor_entry(&600).unwrap();
        assert_eq!(
            (
                *exact_separator_or_leaf_min.0,
                exact_separator_or_leaf_min.1.as_str()
            ),
            (600, "60")
        );

        let after_last = t.floor_entry(&1000).unwrap();
        assert_eq!((*after_last.0, after_last.1.as_str()), (1000, "100"));
    }

    // ── range_scan ───────────────────────────────────────────────────

    #[test]
    fn range_scan_empty_tree() {
        let t: TestTree = TestTree::new();
        let mut scan = t.range_scan(..);
        assert_eq!(scan.next(), None);
    }

    #[test]
    fn range_scan_single_key_included() {
        let t = make_tree(&[(10, "x")]);
        let mut scan = t.range_scan(10..=10);
        assert_eq!(scan.next(), Some((&10, &"x".to_string())));
        assert_eq!(scan.next(), None);
    }

    #[test]
    fn range_scan_single_key_excluded_start() {
        let t = make_tree(&[(10, "x")]);
        // Excluded(10) means start after 10.
        let mut scan = t.range_scan((core::ops::Bound::Excluded(10), core::ops::Bound::Unbounded));
        assert_eq!(scan.next(), None);
    }

    #[test]
    fn range_scan_single_key_excluded_end() {
        let t = make_tree(&[(10, "x")]);
        let mut scan = t.range_scan(..10);
        assert_eq!(scan.next(), None);
    }

    #[test]
    fn range_scan_full_unbounded() {
        let t = make_tree(&[(1, "a"), (2, "b"), (3, "c"), (4, "d"), (5, "e")]);
        let result: Vec<(&u64, &String)> = t.range_scan(..).collect();
        assert_eq!(result.len(), 5);
        for (i, (k, v)) in result.iter().enumerate() {
            assert_eq!(**k, (i + 1) as u64);
            let expected = ((b'a' + i as u8) as char).to_string();
            assert_eq!(v.as_str(), expected.as_str());
        }
    }

    #[test]
    fn range_scan_bounded_both_ends() {
        let t = make_tree(&[(1, "a"), (2, "b"), (3, "c"), (4, "d"), (5, "e")]);
        let result: Vec<(&u64, &String)> = t.range_scan(2..4).collect();
        assert_eq!(result.len(), 2);
        assert_eq!(*result[0].0, 2);
        assert_eq!(*result[1].0, 3);
    }

    #[test]
    fn range_scan_from_start() {
        let t = make_tree(&[(1, "a"), (2, "b"), (3, "c")]);
        let result: Vec<(&u64, &String)> = t.range_scan(2..).collect();
        assert_eq!(result.len(), 2);
        assert_eq!(*result[0].0, 2);
        assert_eq!(*result[1].0, 3);
    }

    #[test]
    fn range_scan_to_end() {
        let t = make_tree(&[(1, "a"), (2, "b"), (3, "c")]);
        let result: Vec<(&u64, &String)> = t.range_scan(..3).collect();
        assert_eq!(result.len(), 2);
        assert_eq!(*result[0].0, 1);
        assert_eq!(*result[1].0, 2);
    }

    #[test]
    fn range_scan_disjoint_bounds_empty() {
        let t = make_tree(&[(1, "a"), (2, "b"), (3, "c")]);
        let result: Vec<(&u64, &String)> = t.range_scan(100..200).collect();
        assert!(result.is_empty());
    }

    #[test]
    fn range_scan_partial_overlap_left() {
        let t = make_tree(&[(10, "a"), (20, "b"), (30, "c")]);
        let result: Vec<(&u64, &String)> = t.range_scan(5..25).collect();
        assert_eq!(result.len(), 2);
        assert_eq!(*result[0].0, 10);
        assert_eq!(*result[1].0, 20);
    }

    #[test]
    fn range_scan_partial_overlap_right() {
        let t = make_tree(&[(10, "a"), (20, "b"), (30, "c")]);
        let result: Vec<(&u64, &String)> = t.range_scan(15..35).collect();
        assert_eq!(result.len(), 2);
        assert_eq!(*result[0].0, 20);
        assert_eq!(*result[1].0, 30);
    }

    #[test]
    fn range_scan_multi_level_tree() {
        let mut t = TestTree::new();
        // Insert enough entries to force multi-level tree (MAX_LEAF=4).
        for i in 0..25u64 {
            t.insert(i, i.to_string());
        }
        assert!(t.depth() >= 3, "expected multi-level tree");
        let result: Vec<(&u64, &String)> = t.range_scan(10..15).collect();
        assert_eq!(result.len(), 5);
        for (i, (k, _)) in result.iter().enumerate() {
            assert_eq!(**k, 10 + i as u64);
        }
    }

    #[test]
    fn range_scan_inclusive_end() {
        let t = make_tree(&[(1, "a"), (2, "b"), (3, "c")]);
        let result: Vec<(&u64, &String)> = t.range_scan(..=2).collect();
        assert_eq!(result.len(), 2);
        assert_eq!(*result[0].0, 1);
        assert_eq!(*result[1].0, 2);
    }

    #[test]
    fn range_scan_excluded_start_included_end() {
        let t = make_tree(&[(1, "a"), (2, "b"), (3, "c")]);
        let result: Vec<(&u64, &String)> = t
            .range_scan((core::ops::Bound::Excluded(1), core::ops::Bound::Included(3)))
            .collect();
        assert_eq!(result.len(), 2);
        assert_eq!(*result[0].0, 2);
        assert_eq!(*result[1].0, 3);
    }
    // ── entries ordered ──────────────────────────────────────────────

    #[test]
    fn entries_preserve_order() {
        let mut t = TestTree::new();
        t.insert(3, "c".into());
        t.insert(1, "a".into());
        t.insert(2, "b".into());
        assert_eq!(
            t.entries(),
            vec![(1, "a".into()), (2, "b".into()), (3, "c".into())]
        );
    }

    // ── depth / splitting ────────────────────────────────────────────

    #[test]
    fn single_split_to_internal() {
        let mut t = TestTree::new();
        // MAX_LEAF=4, so 5 entries forces one split → depth 2
        for i in 0..5u64 {
            t.insert(i, i.to_string());
        }
        assert_eq!(t.depth(), 2);
        assert_eq!(t.len(), 5);
        assert!(t.validate().is_ok());
        for i in 0..5u64 {
            assert_eq!(t.get(&i).unwrap(), &i.to_string());
        }
    }

    #[test]
    fn multi_level() {
        let mut t = TestTree::new();
        // (4+1)*4 = 20 entries: leaf splits force internal split → depth 3
        for i in 0..25u64 {
            t.insert(i, i.to_string());
        }
        assert!(t.depth() >= 3);
        assert_eq!(t.len(), 25);
        assert!(t.validate().is_ok());
        for i in 0..25u64 {
            assert!(t.contains_key(&i));
        }
    }

    #[test]
    fn insert_delete_roundtrip_large() {
        let mut t = TestTree::new();
        for i in 0..30u64 {
            t.insert(i, i.to_string());
        }
        // Delete first half.
        for i in (0..15u64).rev() {
            t.delete(&i).unwrap();
        }
        assert_eq!(t.len(), 15);
        assert!(t.validate().is_ok());
        for i in 0..15u64 {
            assert!(!t.contains_key(&i));
        }
        for i in 15..30u64 {
            assert!(t.contains_key(&i));
        }
    }

    // ── validate errors ──────────────────────────────────────────────

    #[test]
    fn validate_leaf_overflow() {
        let root = BTreeNode::Leaf(
            vec![
                (1u64, "a".into()),
                (2, "b".into()),
                (3, "c".into()),
                (4, "d".into()),
                (5, "e".into()),
            ],
            leaf_checksum(5),
        );
        assert_eq!(
            BPlusTree::<u64, String, 4, 4>::validate_node(&root, false).unwrap_err(),
            BTreeError::LeafOverflow
        );
    }

    #[test]
    fn validate_key_order() {
        let root = BTreeNode::Leaf(
            vec![(3u64, "c".into()), (1u64, "a".into())],
            leaf_checksum(2),
        );
        assert_eq!(
            BPlusTree::<u64, String, 4, 4>::validate_node(&root, false).unwrap_err(),
            BTreeError::KeyOrderViolation
        );
    }

    #[test]
    fn validate_internal_too_few_children() {
        let root = BTreeNode::Internal {
            keys: vec![],
            children: vec![BTreeNode::Leaf(vec![(1u64, "a".into())], leaf_checksum(1))],
            checksum: internal_checksum::<u64, String>(
                1,
                &[BTreeNode::Leaf(vec![(1u64, "a".into())], leaf_checksum(1))],
            ),
        };
        assert_eq!(
            BPlusTree::<u64, String, 4, 4>::validate_node(&root, false).unwrap_err(),
            BTreeError::InternalTooFewChildren
        );
    }

    #[test]
    fn validate_key_child_mismatch() {
        let child_a = BTreeNode::Leaf(vec![(1u64, "a".into())], leaf_checksum(1));
        let child_b = BTreeNode::Leaf(vec![(20u64, "b".into())], leaf_checksum(1));
        let child_c = BTreeNode::Leaf(vec![(30u64, "c".into())], leaf_checksum(1));
        let children = vec![child_a.clone(), child_b.clone(), child_c.clone()];
        let root = BTreeNode::Internal {
            keys: vec![10u64],
            children,
            checksum: internal_checksum(3, &[child_a, child_b, child_c]),
        };
        assert_eq!(
            BPlusTree::<u64, String, 4, 4>::validate_node(&root, false).unwrap_err(),
            BTreeError::KeyChildMismatch
        );
    }

    #[test]
    fn validate_separator_mismatch() {
        let child_a = BTreeNode::Leaf(vec![(1u64, "a".into())], leaf_checksum(1));
        let child_b = BTreeNode::Leaf(vec![(10u64, "b".into())], leaf_checksum(1));
        let child_c = BTreeNode::Leaf(vec![(30u64, "c".into())], leaf_checksum(1));
        let children = vec![child_a.clone(), child_b.clone(), child_c.clone()];
        let root = BTreeNode::Internal {
            keys: vec![99u64, 200u64],
            children,
            checksum: internal_checksum(3, &[child_a, child_b, child_c]),
        };
        // keys[0]=99 but children[1].min_key()=10 → mismatch
        assert_eq!(
            BPlusTree::<u64, String, 4, 4>::validate_node(&root, false).unwrap_err(),
            BTreeError::SeparatorMismatch
        );
    }

    // ── spec constant ────────────────────────────────────────────────

    #[test]
    fn spec_constant_is_non_empty() {
        let spec = [BTREE_SPEC];
        assert!(!spec[0].is_empty());
    }

    // ── minimum-fill compaction ─────────────────────────────────────

    #[test]
    fn insert_uses_compact_rebuild() {
        let mut t = TestTree::new();
        for i in 0..9u64 {
            t.insert(i, i.to_string());
        }
        assert!(t.validate().is_ok());
        assert_eq!(t.len(), 9);
        assert_eq!(t.leaf_count(), 3);
    }

    #[test]
    fn compact_produces_minfill() {
        let mut t = TestTree::new();
        for i in 0..9u64 {
            t.insert(i, i.to_string());
        }
        let entries = t.entries();
        t.rebuild(&entries);
        assert!(t.validate().is_err());
        t.compact();
        assert!(t.validate().is_ok());
        assert_eq!(t.len(), 9);
        for i in 0..9u64 {
            assert_eq!(t.get(&i).unwrap(), &i.to_string());
        }
    }

    #[test]
    fn compact_idempotent() {
        let mut t = TestTree::new();
        for i in 0..15u64 {
            t.insert(i, i.to_string());
        }
        let entries = t.entries();
        t.rebuild(&entries);
        t.compact();
        let entries_after1 = t.entries();
        t.compact();
        let entries_after2 = t.entries();
        assert_eq!(entries_after1, entries_after2);
        assert!(t.validate().is_ok());
    }

    #[test]
    fn rebuild_compact_from_sorted_iter_builds_valid_tree() {
        let mut t = TestTree::new();
        let entries = (0..17u64).map(|i| (i, format!("v{i}")));

        t.rebuild_compact_from_sorted_iter(17, entries).unwrap();

        assert_eq!(t.len(), 17);
        assert!(t.validate().is_ok());
        assert_eq!(t.get(&0), Some(&"v0".to_string()));
        assert_eq!(t.get(&16), Some(&"v16".to_string()));
        assert_eq!(t.entries().len(), 17);
    }

    #[test]
    fn rebuild_compact_from_sorted_iter_rejects_unsorted_input() {
        let mut t = make_tree(&[(10, "keep")]);

        let err = t
            .rebuild_compact_from_sorted_iter(
                2,
                vec![(2u64, "b".to_string()), (1u64, "a".to_string())],
            )
            .unwrap_err();

        assert_eq!(err, BTreeError::KeyOrderViolation);
        assert_eq!(t.len(), 1);
        assert_eq!(t.get(&10), Some(&"keep".to_string()));
        assert!(t.validate().is_ok());
    }

    #[test]
    fn rebuild_compact_from_sorted_iter_rejects_count_mismatch() {
        let mut t = TestTree::new();

        let err = t
            .rebuild_compact_from_sorted_iter(3, vec![(1u64, "a".to_string())])
            .unwrap_err();

        assert_eq!(err, BTreeError::LengthMismatch);
        assert!(t.is_empty());
    }

    #[test]
    fn try_rebuild_compact_from_sorted_iter_propagates_source_error() {
        let mut t = TestTree::new();
        let entries: Vec<Result<(u64, String), &str>> =
            vec![Ok((1, "a".to_string())), Err("read failed")];

        let err = t
            .try_rebuild_compact_from_sorted_iter(2, entries)
            .unwrap_err();

        assert_eq!(err, RebuildFromSortedIterError::Source("read failed"));
        assert!(t.is_empty());
    }

    #[test]
    fn try_rebuild_compact_from_sorted_unknown_len_iter_builds_valid_tree() {
        let mut t = TestTree::new();
        let entries = (0..9u64).map(|i| Ok::<_, BTreeError>((i, format!("v{i}"))));

        let len = t
            .try_rebuild_compact_from_sorted_unknown_len_iter(entries)
            .unwrap();

        assert_eq!(len, 9);
        assert_eq!(t.len(), 9);
        assert!(t.validate().is_ok());
        assert_eq!(t.leaf_count(), 3);
        assert_eq!(t.get(&0), Some(&"v0".to_string()));
        assert_eq!(t.get(&8), Some(&"v8".to_string()));
        assert_eq!(t.entries().len(), 9);
    }

    #[test]
    fn try_rebuild_compact_from_sorted_unknown_len_iter_rejects_unsorted_input() {
        let mut t = make_tree(&[(10, "keep")]);
        let entries = vec![
            Ok::<_, BTreeError>((2u64, "b".to_string())),
            Ok((1u64, "a".to_string())),
        ];

        let err = t
            .try_rebuild_compact_from_sorted_unknown_len_iter(entries)
            .unwrap_err();

        assert_eq!(
            err,
            RebuildFromSortedIterError::Tree(BTreeError::KeyOrderViolation)
        );
        assert_eq!(t.len(), 1);
        assert_eq!(t.get(&10), Some(&"keep".to_string()));
        assert!(t.validate().is_ok());
    }

    #[test]
    fn try_rebuild_compact_from_sorted_unknown_len_iter_propagates_source_error() {
        let mut t = TestTree::new();
        let entries: Vec<Result<(u64, String), &str>> =
            vec![Ok((1, "a".to_string())), Err("read failed")];

        let err = t
            .try_rebuild_compact_from_sorted_unknown_len_iter(entries)
            .unwrap_err();

        assert_eq!(err, RebuildFromSortedIterError::Source("read failed"));
        assert!(t.is_empty());
    }

    #[test]
    fn single_leaf_below_min_is_valid() {
        let mut t = TestTree::new();
        t.insert(1, "a".into());
        assert!(t.validate().is_ok());
    }

    #[test]
    fn validate_leaf_underflow() {
        let child_a = BTreeNode::Leaf(vec![(1u64, "a".into())], leaf_checksum(1));
        let child_b = BTreeNode::Leaf(
            vec![(10u64, "b".into()), (20u64, "c".into())],
            leaf_checksum(2),
        );
        let root = BTreeNode::Internal {
            keys: vec![10u64],
            children: vec![child_a.clone(), child_b.clone()],
            checksum: internal_checksum(2, &[child_a, child_b]),
        };
        assert_eq!(
            BPlusTree::<u64, String, 4, 4>::validate_node(&root, false).unwrap_err(),
            BTreeError::LeafUnderflow
        );
    }

    #[test]
    fn validate_internal_underflow() {
        // MAX_INTERNAL=8 -> MIN_INTERNAL=4. A node with 2 children
        // passes InternalTooFewChildren (>=2) but fails InternalUnderflow (<4).
        let child_a = BTreeNode::Leaf(vec![(1u64, "a".into())], leaf_checksum(1));
        let child_b = BTreeNode::Leaf(vec![(5u64, "b".into())], leaf_checksum(1));
        let node = BTreeNode::Internal {
            keys: vec![5u64],
            children: vec![child_a.clone(), child_b.clone()],
            checksum: internal_checksum(2, &[child_a, child_b]),
        };
        assert_eq!(
            BPlusTree::<u64, String, 8, 8>::validate_node(&node, false).unwrap_err(),
            BTreeError::InternalUnderflow
        );
    }

    // ── Compaction and statistics ────────────────────────────────────

    #[test]
    fn leaf_count_empty() {
        let t: TestTree = TestTree::new();
        assert_eq!(t.leaf_count(), 1); // empty root leaf
    }

    #[test]
    fn leaf_count_single_leaf() {
        let t = make_tree(&[(1, "a"), (2, "b"), (3, "c")]);
        assert_eq!(t.leaf_count(), 1);
    }

    #[test]
    fn leaf_count_multi_leaf() {
        let mut t = TestTree::new();
        // MAX_LEAF=4: 9 entries -> 3 leaves
        for i in 0..9u64 {
            t.insert(i, i.to_string());
        }
        assert_eq!(t.leaf_count(), 3);
        assert_eq!(t.internal_count(), 1);
        assert_eq!(t.node_count(), 4);
    }

    #[test]
    fn leaf_count_after_deletes() {
        let mut t = TestTree::new();
        // 9 entries -> 3 leaves, 1 internal
        for i in 0..9u64 {
            t.insert(i, i.to_string());
        }
        assert_eq!(t.leaf_count(), 3);
        // Delete 5 entries -> should compact to 1 leaf
        for i in 0..5u64 {
            t.delete(&i).unwrap();
        }
        // After delete+rebuild: 4 entries fit in 1 leaf
        assert_eq!(t.leaf_count(), 1);
    }

    #[test]
    fn internal_count_deep_tree() {
        let mut t = TestTree::new();
        // MAX_LEAF=4, MAX_INTERNAL=4
        // 4*4*4 = 64 entries -> 3 levels (16 leaves, 4 internal L2, 1 root)
        for i in 0..64u64 {
            t.insert(i, i.to_string());
        }
        assert!(t.depth() >= 3);
        assert_eq!(t.internal_count(), t.node_count() - t.leaf_count());
    }

    #[test]
    fn internal_count_empty() {
        let t: TestTree = TestTree::new();
        assert_eq!(t.internal_count(), 0);
    }

    #[test]
    fn fill_percent_full() {
        let mut t = TestTree::new();
        // MAX_LEAF=4: 4 entries fills 1 leaf 100%
        for i in 0..4u64 {
            t.insert(i, i.to_string());
        }
        assert!((t.fill_percent() - 1.0).abs() < 0.001);
    }

    #[test]
    fn fill_percent_half() {
        let mut t = TestTree::new();
        // 2 entries in 1 leaf (MAX_LEAF=4) -> 50%
        for i in 0..2u64 {
            t.insert(i, i.to_string());
        }
        assert!((t.fill_percent() - 0.5).abs() < 0.001);
    }

    #[test]
    fn fill_percent_empty() {
        let t: TestTree = TestTree::new();
        assert_eq!(t.fill_percent(), 1.0);
    }

    #[test]
    fn compact_does_not_change_entries() {
        let mut t = TestTree::new();
        for i in 0..8u64 {
            t.insert(i, i.to_string());
        }
        let before = t.entries();
        t.compact();
        let after = t.entries();
        assert_eq!(before, after);
        assert_eq!(t.len(), 8);
        assert!(t.validate().is_ok());
    }

    #[test]
    fn compact_deep_tree_shallower() {
        let mut t = TestTree::new();
        // Build deep tree
        for i in 0..30u64 {
            t.insert(i, i.to_string());
        }
        let depth_before = t.depth();
        assert!(depth_before >= 3);

        // Delete most entries
        for i in 0..25u64 {
            t.delete(&i).unwrap();
        }
        // After delete+rebuild: 5 entries -> 2 leaves, depth may be 2
        t.compact();
        // 5 entries in MAX_LEAF=4 -> 2 leaves, 1 internal -> depth 2
        assert!(t.depth() <= 2);
        assert_eq!(t.len(), 5);
        assert!(t.validate().is_ok());
    }

    #[test]
    fn compact_empty_noop() {
        let mut t: TestTree = TestTree::new();
        t.compact();
        assert!(t.is_empty());
        assert!(t.validate().is_ok());
    }

    #[test]
    fn maybe_compact_triggers_below_threshold() {
        let mut t = TestTree::new();
        // 2 entries in MAX_LEAF=4 -> fill = 0.5
        t.insert(1, "a".into());
        t.insert(2, "b".into());

        // Threshold 0.6 > 0.5 -> should compact
        assert!(t.maybe_compact(0.6));

        // Threshold 0.4 < 0.5 -> should NOT compact
        assert!(!t.maybe_compact(0.4));
    }

    #[test]
    fn maybe_compact_empty_noop() {
        let mut t: TestTree = TestTree::new();
        assert!(!t.maybe_compact(0.5));
    }

    #[test]
    fn node_count_equals_sum() {
        let mut t = TestTree::new();
        for i in 0..20u64 {
            t.insert(i, i.to_string());
        }
        assert_eq!(t.node_count(), t.leaf_count() + t.internal_count());
    }

    #[test]
    fn statistics_after_insert_delete_cycle() {
        let mut t = TestTree::new();
        // Insert 20 entries
        for i in 0..20u64 {
            t.insert(i, i.to_string());
        }
        let leaves_after_insert = t.leaf_count();
        assert!(leaves_after_insert >= 2);

        // Delete 18, leaving 2
        for i in 0..18u64 {
            t.delete(&i).unwrap();
        }
        // After rebuild: 2 entries -> 1 leaf
        assert_eq!(t.leaf_count(), 1);
        assert_eq!(t.len(), 2);
        assert!(t.fill_percent() <= 1.0);
        assert!(t.validate().is_ok());
    }

    // ── UnderfullNodeInfo ─────────────────────────────────────────────

    #[test]
    fn underfull_info_fill_ratio() {
        let info = UnderfullNodeInfo {
            node_id: NodeId(1),
            is_leaf: true,
            fill_count: 2,
            max_capacity: 4,
        };
        assert!((info.fill_ratio() - 0.5).abs() < 0.001);
        assert!(!info.is_below_min_fill()); // exactly 50% is NOT below 50%
    }

    #[test]
    fn underfull_info_below_min() {
        let info = UnderfullNodeInfo {
            node_id: NodeId(2),
            is_leaf: false,
            fill_count: 1,
            max_capacity: 4,
        };
        assert!((info.fill_ratio() - 0.25).abs() < 0.001);
        assert!(info.is_below_min_fill());
    }

    #[test]
    fn underfull_info_zero_capacity() {
        let info = UnderfullNodeInfo {
            node_id: NodeId(0),
            is_leaf: true,
            fill_count: 0,
            max_capacity: 0,
        };
        assert_eq!(info.fill_ratio(), 0.0);
    }

    // ── underfull_nodes on compact tree ──────────────────────────────

    #[test]
    fn compact_tree_no_underfull_nodes() {
        let mut t = TestTree::new();
        // MAX_LEAF=4: 12 entries -> 3 leaves at exactly 4 each (fully packed)
        for i in 0..12u64 {
            t.insert(i, i.to_string());
        }
        t.compact();
        // After compact: all non-root nodes >= MIN_LEAF (2 for MAX_LEAF=4)
        let under = t.underfull_nodes(0.5);
        assert!(
            under.is_empty(),
            "compact tree should have no underfull nodes"
        );
    }

    #[test]
    fn rebuild_leaves_last_leaf_underfull() {
        let mut t = TestTree::new();
        // MAX_LEAF=4, 9 entries: rebuild() produces 3 leaves: [4, 4, 1]
        // The last leaf has only 1 entry, below MIN_LEAF=2
        for i in 0..9u64 {
            t.insert(i, i.to_string());
        }
        // Use rebuild() instead of rebuild_compact to avoid compressing
        let entries = t.entries();
        t.rebuild(&entries);

        // Now the last leaf should be under-full (1 entry, max=4, ratio=0.25)
        let under = t.underfull_nodes(0.5);
        assert!(!under.is_empty(), "should detect underfull last leaf");
        let leaf = &under[0];
        assert!(leaf.is_leaf);
        assert_eq!(leaf.fill_count, 1);
        assert_eq!(leaf.max_capacity, 4);
    }

    #[test]
    fn underfull_nodes_respects_threshold() {
        let mut t = TestTree::new();
        // 9 entries, rebuild: leaves=[4, 4, 1]
        for i in 0..9u64 {
            t.insert(i, i.to_string());
        }
        let entries = t.entries();
        t.rebuild(&entries);

        // Threshold 0.3: leaf with 1/4=0.25 is below -> detected
        let under = t.underfull_nodes(0.3);
        assert!(!under.is_empty());

        // Threshold 0.2: leaf with 1/4=0.25 is above -> not detected
        let under2 = t.underfull_nodes(0.2);
        assert!(under2.is_empty());
    }

    #[test]
    fn empty_tree_no_underfull_nodes() {
        let t = TestTree::new();
        assert!(t.underfull_nodes(0.5).is_empty());
    }

    #[test]
    fn single_leaf_root_exempt_from_underfull() {
        let mut t = TestTree::new();
        // 1 entry in root leaf: fill=0.25 but root is exempt
        t.insert(1, "a".into());
        assert!(t.underfull_nodes(0.5).is_empty());
    }

    // ── delete_lazy ──────────────────────────────────────────────────

    #[test]
    fn delete_lazy_removes_key() {
        let mut t = TestTree::new();
        for i in 0..5u64 {
            t.insert(i, i.to_string());
        }
        let result = t.delete_lazy(&2);
        assert_eq!(result.removed, Some("2".to_string()));
        assert_eq!(t.len(), 4);
        assert!(t.get(&2).is_none());
    }

    #[test]
    fn delete_lazy_nonexistent_returns_none() {
        let mut t = TestTree::new();
        t.insert(1, "a".into());
        let result = t.delete_lazy(&99);
        assert!(result.removed.is_none());
        assert!(result.underfull.is_empty());
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn delete_lazy_detects_underfull_nodes() {
        let mut t = TestTree::new();
        // MAX_LEAF=4: 9 entries, rebuild (non-compact) -> leaves [4,4,1]
        // Delete one more -> 8 entries, rebuild -> leaves [4,4]
        // No underfull because both leaves are at max capacity
        for i in 0..9u64 {
            t.insert(i, i.to_string());
        }
        // Delete 5 entries, leaving 4 -> 1 full leaf
        for i in 1..6u64 {
            let result = t.delete_lazy(&i);
            if i == 5 {
                // After 4 deletes (entries 0,6,7,8 remain = 4 entries)
                // rebuild: 1 leaf with 4 entries = full
                assert!(result.underfull.is_empty());
            }
        }
    }

    #[test]
    fn delete_lazy_multiple_deletes_produce_underfull() {
        let mut t = TestTree::new();
        // Build a multi-leaf tree and force non-compact layout
        for i in 0..20u64 {
            t.insert(i, i.to_string());
        }
        let entries = t.entries();
        t.rebuild(&entries); // leaves: [4,4,4,4,4]

        // Delete 15 entries -> 5 remain -> rebuild: [4,1]
        // Last leaf has 1 entry, fill=0.25 < 0.5 threshold
        for i in 0..15u64 {
            let _ = t.delete_lazy(&i);
        }
        // 5 entries remain after non-compact rebuild
        let under = t.underfull_nodes(0.5);
        assert!(!under.is_empty(), "should have at least one underfull leaf");
    }

    #[test]
    fn delete_lazy_result_contains_underfull_info() {
        let mut t = TestTree::new();
        // Force underfull via rebuild
        for i in 0..9u64 {
            t.insert(i, i.to_string());
        }
        let entries = t.entries();
        t.rebuild(&entries); // leaves [4,4,1]

        // Delete one entry from a full leaf, still leaves [4,4,1] but with 8 entries
        let result = t.delete_lazy(&0);
        assert_eq!(result.removed, Some("0".to_string()));
        // rebuild redistributes so no underfull may result
        // Actually after delete_lazy, rebuild is non-compact:
        // 8 entries -> rebuild produces [4,4] if sorted properly
        // Both leaves are >= 2 (MIN_LEAF), so no underfull
    }

    #[test]
    fn delete_lazy_empty_tree() {
        let mut t: TestTree = TestTree::new();
        let result = t.delete_lazy(&1);
        assert!(result.removed.is_none());
        assert!(result.underfull.is_empty());
    }

    // ── MergeStats ───────────────────────────────────────────────────

    #[test]
    fn merge_stats_default_is_zero() {
        let s = MergeStats::default();
        assert_eq!(s.leaves_freed, 0);
        assert_eq!(s.total_nodes_freed, 0);
    }

    // ── merge_left ───────────────────────────────────────────────────

    #[test]
    fn merge_left_on_full_tree_noop() {
        let mut t = TestTree::new();
        for i in 0..4u64 {
            t.insert(i, i.to_string());
        }
        let before = t.node_count();
        let info = UnderfullNodeInfo {
            node_id: NodeId(0),
            is_leaf: true,
            fill_count: 4,
            max_capacity: 4,
        };
        let stats = t.merge_left(&info);
        let after = t.node_count();
        assert_eq!(stats.total_nodes_freed, before.saturating_sub(after) as u64);
        // Verify stats consistency
        assert_eq!(stats.nodes_after, after as u64);
    }

    #[test]
    fn merge_left_on_underfull_tree_compacts() {
        let mut t = TestTree::new();
        // Build a tree with under-full nodes (9 entries, MAX_LEAF=4 -> leaves [4,4,1])
        for i in 0..9u64 {
            t.insert(i, i.to_string());
        }
        let entries = t.entries();
        t.rebuild(&entries);

        let under = t.underfull_nodes(0.5);
        assert!(!under.is_empty());

        let stats = t.merge_left(&under[0]);
        // After compaction: 9 entries redistributed evenly across 3 leaves
        // All non-root nodes satisfy MIN_LEAF=2. The tree is validated.
        assert!(t.validate().is_ok());
        // Data integrity preserved
        assert_eq!(t.len(), 9);
        for i in 0..9u64 {
            assert!(t.contains_key(&i));
        }
        // Stats report post-compaction state
        assert_eq!(stats.nodes_after, t.node_count() as u64);
        assert!((stats.fill_after - t.fill_percent()).abs() < 0.001);
    }

    // ── merge_right ──────────────────────────────────────────────────

    #[test]
    fn merge_right_equivalent_to_merge_left() {
        let mut t1 = TestTree::new();
        let mut t2 = TestTree::new();
        for i in 0..9u64 {
            t1.insert(i, i.to_string());
            t2.insert(i, i.to_string());
        }
        let e1 = t1.entries();
        let e2 = t2.entries();
        t1.rebuild(&e1);
        t2.rebuild(&e2);

        let under1 = t1.underfull_nodes(0.5);
        let under2 = t2.underfull_nodes(0.5);

        let s1 = t1.merge_left(&under1[0]);
        let s2 = t2.merge_right(&under2[0]);

        // Both should produce the same result since they both call compact()
        assert_eq!(t1.entries(), t2.entries());
        assert_eq!(t1.leaf_count(), t2.leaf_count());
        assert_eq!(s1.leaves_freed, s2.leaves_freed);
        assert_eq!(s1.total_nodes_freed, s2.total_nodes_freed);
    }

    // ── redistribute ─────────────────────────────────────────────────

    #[test]
    fn redistribute_on_underfull_tree_compacts() {
        let mut t = TestTree::new();
        for i in 0..9u64 {
            t.insert(i, i.to_string());
        }
        let entries = t.entries();
        t.rebuild(&entries);

        let under = t.underfull_nodes(0.5);
        assert!(!under.is_empty());

        let stats = t.redistribute(&under[0]);
        assert!(stats.fill_after >= 0.5);
        assert!(t.validate().is_ok());
        assert_eq!(t.len(), 9);
    }

    // ── merge on empty tree ──────────────────────────────────────────

    #[test]
    fn merge_operations_on_empty_tree_noop() {
        let mut t: TestTree = TestTree::new();
        let info = UnderfullNodeInfo {
            node_id: NodeId(0),
            is_leaf: true,
            fill_count: 0,
            max_capacity: 4,
        };
        let stats = t.merge_left(&info);
        assert_eq!(stats.leaves_freed, 0);
        assert_eq!(stats.total_nodes_freed, 0);

        let stats2 = t.redistribute(&info);
        assert_eq!(stats2.leaves_freed, 0);
    }

    // ── PersistentBTree ───────────────────────────────────────────

    type TestPersistentTree = super::PersistentBTree<u64, u64, 4, 4>;

    fn build_persistent_tree(entries: &[(u64, u64)]) -> TestPersistentTree {
        let mut pt = TestPersistentTree::new();
        for (k, v) in entries {
            pt.insert(*k, *v);
        }
        pt
    }

    #[test]
    fn persistent_insert_and_lookup() {
        let mut pt = TestPersistentTree::new();
        pt.insert(10, 100);
        pt.insert(20, 200);
        pt.insert(30, 300);
        assert_eq!(pt.len(), 3);
        assert_eq!(pt.get(&10), Some(&100));
        assert_eq!(pt.get(&20), Some(&200));
        assert_eq!(pt.get(&30), Some(&300));
        assert_eq!(pt.get(&99), None);
    }

    #[test]
    fn persistent_delete() {
        let mut pt = build_persistent_tree(&[(1, 10), (2, 20), (3, 30)]);
        assert_eq!(pt.delete(&2), Some(20));
        assert_eq!(pt.len(), 2);
        assert!(pt.get(&2).is_none());
        assert_eq!(pt.get(&1), Some(&10));
        assert_eq!(pt.get(&3), Some(&30));
    }

    #[test]
    fn persistent_flush_to_store() {
        let mut pt = build_persistent_tree(&[
            (1, 10),
            (2, 20),
            (3, 30),
            (4, 40),
            (5, 50),
            (6, 60),
            (7, 70),
            (8, 80),
            (9, 90),
        ]);
        let mut store = super::MemPageStore::new();
        let page_ids = pt.flush_to_store(&mut store).unwrap();
        assert!(!page_ids.is_empty(), "should have written pages");

        // Every page should be readable
        for &pid in &page_ids {
            let page = store.read_page(pid).unwrap();
            let header = super::page::read_header(&page);
            assert!(header.is_valid_magic(), "page {pid} has bad magic");
            let body = super::page::page_body(&page);
            assert!(
                super::page::verify_page_checksum(&header, body).is_ok(),
                "page {pid} checksum mismatch"
            );
        }
    }

    #[test]
    fn persistent_flush_empty_tree() {
        let mut pt: TestPersistentTree = TestPersistentTree::new();
        let mut store = super::MemPageStore::new();
        let page_ids = pt.flush_to_store(&mut store).unwrap();
        assert!(page_ids.is_empty());
    }

    #[test]
    fn persistent_wal_records_after_insert() {
        let pt = build_persistent_tree(&[(1, 10), (2, 20), (3, 30)]);
        assert!(!pt.wal().is_empty(), "WAL should have entries after insert");
        let gen = pt.next_wal_generation();
        assert!(gen > 0, "generation should advance");
    }

    #[test]
    fn persistent_wal_cleared_after_flush() {
        let mut pt = build_persistent_tree(&[(1, 10), (2, 20)]);
        let mut store = super::MemPageStore::new();
        pt.flush_to_store(&mut store).unwrap();
        // After flush, WAL is checkpointed (cleared).
        assert!(pt.wal().is_empty(), "WAL should be empty after checkpoint");
    }

    #[test]
    fn persistent_insert_delete_cycle() {
        let mut pt: TestPersistentTree = TestPersistentTree::new();
        for i in 0u64..20 {
            pt.insert(i, i * 10);
        }
        assert_eq!(pt.len(), 20);
        for i in 0u64..10 {
            assert_eq!(pt.delete(&i), Some(i * 10));
        }
        assert_eq!(pt.len(), 10);
        for i in 10u64..20 {
            assert_eq!(pt.get(&i), Some(&(i * 10)));
        }
        // Should survive flush
        let mut store = super::MemPageStore::new();
        let page_ids = pt.flush_to_store(&mut store).unwrap();
        assert!(!page_ids.is_empty());
        assert!(pt.wal().is_empty());
    }

    #[test]
    fn persistent_default_is_empty() {
        let pt: TestPersistentTree = TestPersistentTree::default();
        assert!(pt.is_empty());
        assert_eq!(pt.len(), 0);
        assert_eq!(pt.next_wal_generation(), 0);
    }

    #[test]
    fn persistent_with_wal() {
        let wal = super::wal::WalWriter::new(100);
        let pt: TestPersistentTree = super::PersistentBTree::with_wal(wal, 50);
        assert!(pt.is_empty());
        assert_eq!(pt.next_wal_generation(), 100);
    }

    #[test]
    fn persistent_contains_key() {
        let pt = build_persistent_tree(&[(42, 99)]);
        assert!(pt.contains_key(&42));
        assert!(!pt.contains_key(&43));
    }

    #[test]
    fn persistent_flush_internal_and_leaf_pages() {
        // Large enough tree to produce both leaf and internal pages.
        let mut pt: TestPersistentTree = TestPersistentTree::new();
        for i in 0u64..50 {
            pt.insert(i, i * 10);
        }
        let mut store = super::MemPageStore::new();
        let page_ids = pt.flush_to_store(&mut store).unwrap();
        assert!(
            page_ids.len() > 1,
            "multi-node tree should produce multiple pages"
        );

        let mut has_leaf = false;
        let mut has_internal = false;
        for &pid in &page_ids {
            let page = store.read_page(pid).unwrap();
            let header = super::page::read_header(&page);
            match header.page_type() {
                Some(super::PageType::Leaf) => has_leaf = true,
                Some(super::PageType::Internal) => has_internal = true,
                _ => {}
            }
        }
        assert!(has_leaf, "should have at least one leaf page");
        assert!(has_internal, "should have at least one internal page");
    }

    #[test]
    fn persistent_error_display() {
        let e = super::PersistentBTreeError::EmptyTree;
        assert!(!format!("{e}").is_empty());

        let e = super::PersistentBTreeError::Store(super::PageStoreError::NotFound(0));
        assert!(!format!("{e}").is_empty());
    }

    // ── WAL recovery ───────────────────────────────────────────────

    #[test]
    fn from_wal_replay_reconstructs_tree() {
        // Build a tree, collect WAL data, then reconstruct from it.
        let mut pt: TestPersistentTree = TestPersistentTree::new();
        for i in 0u64..20 {
            pt.insert(i, i * 100);
        }
        let wal_data = pt.wal().serialize_all();
        assert!(!wal_data.is_empty());

        // Recover from WAL only (simulate crash + restart).
        let recovered =
            super::PersistentBTree::<u64, u64, 4, 4>::from_wal_replay(&wal_data).unwrap();
        assert_eq!(recovered.len(), 20);
        for i in 0u64..20 {
            assert_eq!(recovered.get(&i), Some(&(i * 100)));
        }
    }

    #[test]
    fn from_wal_replay_empty_data() {
        let result = super::PersistentBTree::<u64, u64, 4, 4>::from_wal_replay(&[]);
        assert!(result.is_ok());
        let pt = result.unwrap();
        assert!(pt.is_empty());
        assert_eq!(pt.len(), 0);
    }

    #[test]
    fn from_wal_replay_corrupt_data_fails() {
        let mut corrupt = vec![0xFFu8; 32];
        // Make it a valid WAL entry size but with corrupt magic
        // pad to WAL_ENTRY_SIZE
        corrupt.resize(super::wal::WAL_ENTRY_SIZE, 0xFF);
        let result = super::PersistentBTree::<u64, u64, 4, 4>::from_wal_replay(&corrupt);
        assert!(result.is_err());
    }

    #[test]
    fn from_wal_replay_resumes_generation() {
        let mut pt: TestPersistentTree = TestPersistentTree::new();
        pt.insert(1, 10);
        let wal_data = pt.wal().serialize_all();
        let recovered =
            super::PersistentBTree::<u64, u64, 4, 4>::from_wal_replay(&wal_data).unwrap();
        // Generation should continue after the last WAL entry.
        assert!(recovered.next_wal_generation() > 0);
    }

    #[test]
    fn from_wal_replay_overwrite_recovery() {
        // Simulate: insert -> WAL (gen0), update -> WAL (gen1), crash.
        // Replay should use the latest page image (gen1).
        let mut pt: TestPersistentTree = TestPersistentTree::new();
        pt.insert(42, 99); // gen 0
        pt.insert(42, 999); // gen 1 — overwrite same key
        let wal_data = pt.wal().serialize_all();

        let recovered =
            super::PersistentBTree::<u64, u64, 4, 4>::from_wal_replay(&wal_data).unwrap();
        // Last writer wins: value should be 999.
        assert_eq!(recovered.get(&42), Some(&999));
    }

    #[test]
    fn from_wal_replay_ignores_internal_pages() {
        // Large tree produces internal nodes; recovery should still
        // extract all leaf data.
        let mut pt: TestPersistentTree = TestPersistentTree::new();
        for i in 0u64..30 {
            pt.insert(i, i * 10);
        }
        let wal_data = pt.wal().serialize_all();
        let recovered =
            super::PersistentBTree::<u64, u64, 4, 4>::from_wal_replay(&wal_data).unwrap();
        assert_eq!(recovered.len(), 30);
        for i in 0u64..30 {
            assert_eq!(recovered.get(&i), Some(&(i * 10)));
        }
    }

    #[test]
    fn from_wal_error_display() {
        let e = super::FromWalError::Deserialize;
        assert!(!format!("{e}").is_empty());

        let e = super::FromWalError::WalError(super::wal::WalError::Truncated);
        assert!(!format!("{e}").is_empty());

        let e = super::FromWalError::PageValidation(super::PageChecksumError::BadMagic {
            got: *b"BADC",
        });
        assert!(!format!("{e}").is_empty());

        let e = super::FromWalError::PageFormat(super::PageFormatError::Truncated);
        assert!(!format!("{e}").is_empty());
    }

    // ── PageSerde deserialize round-trip tests ──────────────────────

    #[test]
    fn page_serde_key_u64_round_trip() {
        let key: u64 = 0xDEAD_BEEF_CAFE_BABE;
        let data = super::page::PageSerdeKey::serialize_to_vec(&key);
        let recovered = super::page::PageSerdeKey::deserialize_from_slice(&data);
        assert_eq!(recovered, Some(key));
    }

    #[test]
    fn page_serde_value_u64_round_trip() {
        let val: u64 = 0x0123_4567_89AB_CDEF;
        let data = super::page::PageSerdeValue::serialize_to_vec(&val);
        let recovered = super::page::PageSerdeValue::deserialize_from_slice(&data);
        assert_eq!(recovered, Some(val));
    }

    #[test]
    fn page_serde_deserialize_truncated() {
        let result: Option<u64> = super::page::PageSerdeKey::deserialize_from_slice(&[1, 2, 3]);
        assert_eq!(result, None);
    }
}
