// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Lazy range-scan iterator over a B+tree.
//!
//! `RangeScan` yields `(&K, &V)` pairs in ascending key order within
//! caller-specified bounds using a stack-based depth-first left-to-right
//! traversal. It avoids cloning keys and values for read-only scans.

use alloc::vec::Vec;
use core::ops::Bound;

use crate::{BPlusTree, BTreeNode};

/// A lazy iterator over key-value pairs in a B+tree within a key range.
///
/// Created by [`BPlusTree::range_scan`]. Yields `(&K, &V)` in ascending
/// key order. The traversal is O(log n + k) where k is the number of
/// yielded entries.
pub struct RangeScan<
    'a,
    K: Ord + Clone,
    V: Clone,
    const MAX_LEAF: usize = 45,
    const MAX_INTERNAL: usize = 45,
> {
    start: Bound<K>,
    end: Bound<K>,
    /// Ancestor stack. Each frame is `(internal_node, next_child_index)`.
    /// `next_child_index` tracks which child we are currently in.
    stack: Vec<(&'a BTreeNode<K, V>, usize)>,
    /// Current leaf slice and entry position, or `None` between leaves.
    leaf: Option<(&'a [(K, V)], usize)>,
    exhausted: bool,
}

impl<'a, K: Ord + Clone, V: Clone, const MAX_LEAF: usize, const MAX_INTERNAL: usize>
    RangeScan<'a, K, V, MAX_LEAF, MAX_INTERNAL>
{
    pub(crate) fn new(
        tree: &'a BPlusTree<K, V, MAX_LEAF, MAX_INTERNAL>,
        start: Bound<K>,
        end: Bound<K>,
    ) -> Self {
        let mut scan = Self {
            start,
            end,
            stack: Vec::new(),
            leaf: None,
            exhausted: tree.is_empty(),
        };

        if !scan.exhausted {
            scan.init_walk(&tree.root);
        }

        scan
    }

    /// Walk from `node` down to the leaf covering the start key, pushing
    /// ancestor frames onto `self.stack`.
    fn init_walk(&mut self, mut node: &'a BTreeNode<K, V>) {
        loop {
            match node {
                BTreeNode::Leaf(entries, _) => {
                    let pos = self.start_idx(entries);
                    self.leaf = Some((entries.as_slice(), pos));
                    return;
                }
                BTreeNode::Internal { keys, children, .. } => {
                    let child_idx = self.first_child(keys);
                    self.stack.push((node, child_idx));
                    node = &children[child_idx];
                }
            }
        }
    }

    /// Index of the first child that may contain the start key.
    fn first_child(&self, keys: &[K]) -> usize {
        match &self.start {
            Bound::Unbounded => 0,
            Bound::Included(k) | Bound::Excluded(k) => {
                match keys.binary_search_by(|sep| sep.cmp(k)) {
                    Ok(idx) => idx + 1,
                    Err(idx) => idx,
                }
            }
        }
    }

    /// Binary-search `entries` for the first entry satisfying the start bound.
    fn start_idx(&self, entries: &[(K, V)]) -> usize {
        match &self.start {
            Bound::Unbounded => 0,
            Bound::Included(k) => entries
                .binary_search_by(|(key, _)| key.cmp(k))
                .unwrap_or_else(|idx| idx),
            Bound::Excluded(k) => match entries.binary_search_by(|(key, _)| key.cmp(k)) {
                Ok(idx) => idx + 1,
                Err(idx) => idx,
            },
        }
    }

    fn before_end(&self, key: &K) -> bool {
        match &self.end {
            Bound::Unbounded => true,
            Bound::Included(e) => key <= e,
            Bound::Excluded(e) => key < e,
        }
    }

    /// Walk left from `node` to its deepest-left leaf, pushing ancestors.
    fn walk_left(&mut self, mut node: &'a BTreeNode<K, V>) {
        loop {
            match node {
                BTreeNode::Leaf(entries, _) => {
                    self.leaf = Some((entries.as_slice(), 0));
                    return;
                }
                BTreeNode::Internal { children, .. } => {
                    self.stack.push((node, 0));
                    node = &children[0];
                }
            }
        }
    }

    /// Advance to the next leaf using the ancestor stack.
    fn next_leaf(&mut self) -> bool {
        while let Some((parent, child_idx)) = self.stack.pop() {
            let next = child_idx + 1;
            if let BTreeNode::Internal { children, .. } = parent {
                if next < children.len() {
                    self.stack.push((parent, next));
                    self.walk_left(&children[next]);
                    return true;
                }
            }
        }
        false
    }
}

impl<'a, K: Ord + Clone, V: Clone, const MAX_LEAF: usize, const MAX_INTERNAL: usize> Iterator
    for RangeScan<'a, K, V, MAX_LEAF, MAX_INTERNAL>
{
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        if self.exhausted {
            return None;
        }

        loop {
            if let Some((entries, pos)) = self.leaf {
                if pos < entries.len() {
                    let (key, val) = &entries[pos];
                    if !self.before_end(key) {
                        self.exhausted = true;
                        return None;
                    }
                    self.leaf = Some((entries, pos + 1));
                    return Some((key, val));
                }
                self.leaf = None; // exhausted this leaf
            }

            if !self.next_leaf() {
                self.exhausted = true;
                return None;
            }
        }
    }
}
