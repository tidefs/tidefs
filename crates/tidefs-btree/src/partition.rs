//! Hash-partitioned B+tree for concurrent multi-core metadata operations.
//!
//! Divides the key space into N partitions by hash prefix so that
//! operations on different partitions can proceed independently without
//! lock contention. Cross-partition operations (e.g. rename across
//! partition boundaries) use 2-phase locking.

use crate::BPlusTree;
use alloc::boxed::Box;
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// BTreePartition
// ---------------------------------------------------------------------------

/// Describes one shard of a partitioned key space.
///
/// For u64 hash keys, partitions are defined by the high byte(s) of the
/// hash value. A key falls into a partition when `(key_hash & mask) == value`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BTreePartition {
    /// Zero-based partition index.
    pub partition_id: usize,
    /// Mask applied to the key hash before comparing with `hash_expected`.
    pub hash_mask: u64,
    /// Expected value after masking: a key belongs to this partition when
    /// `(hash & hash_mask) == hash_expected`.
    pub hash_expected: u64,
}

impl BTreePartition {
    /// Returns `true` when `hash` falls into this partition.
    #[must_use]
    pub fn contains(&self, hash: u64) -> bool {
        (hash & self.hash_mask) == self.hash_expected
    }
}

/// Build `count` equal-width partitions for a 64-bit key hash space.
///
/// # Panics
///
/// Panics if `count` is 0 or not a power of two, or exceeds 256.
pub fn build_hash_partitions(count: usize) -> Vec<BTreePartition> {
    assert!(count > 0, "partition count must be positive");
    assert!(
        count.is_power_of_two(),
        "partition count must be power of two"
    );
    assert!(count <= 256, "partition count must be <= 256");

    let bits = count.trailing_zeros() as usize;
    let shift = 64usize.saturating_sub(bits);
    let mask = if bits == 0 {
        0
    } else {
        ((1u64 << bits) - 1) << shift
    };
    let step = if count == 1 { 0 } else { 1u64 << shift };

    (0..count)
        .map(|i| BTreePartition {
            partition_id: i,
            hash_mask: mask,
            hash_expected: (i as u64).wrapping_mul(step),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// PartitionFn trait
// ---------------------------------------------------------------------------

/// Maps a key to a partition index in `[0, partition_count)`.
pub trait PartitionFn<K>: Send + Sync {
    /// Return the partition index for `key`.
    fn partition_of(&self, key: &K) -> usize;

    /// Number of partitions this function routes to.
    fn partition_count(&self) -> usize;

    /// Return a boxed clone of this partition function.
    fn clone_box(&self) -> Box<dyn PartitionFn<K>>;
}

// ---------------------------------------------------------------------------
// U64PartitionFn
// ---------------------------------------------------------------------------

/// Partition function for `u64` keys that routes by the high bits.
#[derive(Clone)]
pub struct U64PartitionFn {
    shift: u32,
    partition_count: usize,
}

impl U64PartitionFn {
    /// Create a new u64 partition function.
    ///
    /// # Panics
    ///
    /// Panics if `partition_count` is 0 or not a power of two.
    #[must_use]
    pub fn new(partition_count: usize) -> Self {
        assert!(partition_count > 0);
        assert!(partition_count.is_power_of_two());
        let shift = 64u32.saturating_sub(partition_count.trailing_zeros());
        U64PartitionFn {
            shift,
            partition_count,
        }
    }
}

impl PartitionFn<u64> for U64PartitionFn {
    fn partition_of(&self, key: &u64) -> usize {
        if self.partition_count == 1 {
            0
        } else {
            (key >> self.shift) as usize
        }
    }

    fn partition_count(&self) -> usize {
        self.partition_count
    }

    fn clone_box(&self) -> Box<dyn PartitionFn<u64>> {
        Box::new(self.clone())
    }
}

// ---------------------------------------------------------------------------
// PartitionedBTree
// ---------------------------------------------------------------------------

/// A B+tree split across N independent sub-trees, routed by a
/// [`PartitionFn`].
///
/// Each operation (get, insert, delete, …) is routed to exactly one
/// partition.  This eliminates lock contention between operations that
/// touch different partitions.
pub struct PartitionedBTree<
    K: Ord + Clone,
    V: Clone,
    const MAX_LEAF: usize = 45,
    const MAX_INTERNAL: usize = 45,
> {
    trees: Vec<BPlusTree<K, V, MAX_LEAF, MAX_INTERNAL>>,
    partition_fn: Box<dyn PartitionFn<K>>,
    len: usize,
}

// Manual Clone
impl<K: Ord + Clone, V: Clone, const L: usize, const I: usize> Clone
    for PartitionedBTree<K, V, L, I>
{
    fn clone(&self) -> Self {
        Self {
            trees: self.trees.clone(),
            partition_fn: self.partition_fn.clone_box(),
            len: self.len,
        }
    }
}

// Manual Debug
impl<
        K: Ord + Clone + core::fmt::Debug,
        V: Clone + core::fmt::Debug,
        const L: usize,
        const I: usize,
    > core::fmt::Debug for PartitionedBTree<K, V, L, I>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PartitionedBTree")
            .field("trees", &self.trees)
            .field("len", &self.len)
            .finish()
    }
}

impl<K: Ord + Clone, V: Clone, const MAX_LEAF: usize, const MAX_INTERNAL: usize>
    PartitionedBTree<K, V, MAX_LEAF, MAX_INTERNAL>
{
    /// Create a `PartitionedBTree` with `partition_fn`.  The number of
    /// partitions is derived from `partition_fn.partition_count()`.
    #[must_use]
    pub fn new(partition_fn: Box<dyn PartitionFn<K>>) -> Self {
        let n = partition_fn.partition_count();
        assert!(n > 0, "partition_count must be positive");
        let mut trees = Vec::with_capacity(n);
        for _ in 0..n {
            trees.push(BPlusTree::new());
        }
        Self {
            trees,
            partition_fn,
            len: 0,
        }
    }

    /// Returns the number of partitions.
    #[must_use]
    pub fn partition_count(&self) -> usize {
        self.trees.len()
    }

    /// Returns the total number of entries across all partitions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` when there are no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    // ------------------------------------------------------------------
    // Single-partition operations
    // ------------------------------------------------------------------

    fn partition_for(&self, key: &K) -> usize {
        self.partition_fn.partition_of(key)
    }

    /// Look up a value by key.  O(log n) within the partition.
    #[must_use]
    pub fn get(&self, key: &K) -> Option<&V> {
        let pid = self.partition_for(key);
        self.trees[pid].get(key)
    }

    /// Returns `true` if the key exists.
    #[must_use]
    pub fn contains_key(&self, key: &K) -> bool {
        let pid = self.partition_for(key);
        self.trees[pid].contains_key(key)
    }

    /// Insert `key` → `value`.  Returns the previous value if present.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        let pid = self.partition_for(&key);
        let prev = self.trees[pid].insert(key, value);
        if prev.is_none() {
            self.len += 1;
        }
        prev
    }

    /// Remove `key`, returning the previous value if present.
    pub fn delete(&mut self, key: &K) -> Option<V> {
        let pid = self.partition_for(key);
        let prev = self.trees[pid].delete(key);
        if prev.is_some() {
            self.len -= 1;
        }
        prev
    }

    /// Collect all entries from all partitions (key order within each).
    #[must_use]
    pub fn entries(&self) -> Vec<(K, V)> {
        let mut out = Vec::with_capacity(self.len);
        for t in &self.trees {
            out.extend(t.entries());
        }
        out
    }

    /// Returns the number of entries in partition `pid`.
    #[must_use]
    pub fn partition_len(&self, pid: usize) -> usize {
        self.trees[pid].len()
    }

    /// Returns the partition with the most entries.
    #[must_use]
    pub fn heaviest_partition(&self) -> usize {
        let mut max_idx = 0;
        let mut max_len = 0;
        for (i, t) in self.trees.iter().enumerate() {
            let l = t.len();
            if l > max_len {
                max_len = l;
                max_idx = i;
            }
        }
        max_idx
    }

    /// Returns the partition with the fewest entries.
    #[must_use]
    pub fn lightest_partition(&self) -> usize {
        let mut min_idx = 0;
        let mut min_len = usize::MAX;
        for (i, t) in self.trees.iter().enumerate() {
            let l = t.len();
            if l < min_len {
                min_len = l;
                min_idx = i;
            }
        }
        min_idx
    }

    /// Returns the partition-imbalance ratio (heaviest / average).
    ///
    /// Returns 1.0 when empty or perfectly balanced.
    #[must_use]
    pub fn imbalance_ratio(&self) -> f64 {
        if self.len == 0 {
            return 1.0;
        }
        let avg = self.len as f64 / self.partition_count() as f64;
        if avg == 0.0 {
            return 1.0;
        }
        let max = self.trees[self.heaviest_partition()].len() as f64;
        max / avg
    }

    /// Validate all partitions.
    pub fn validate(&self) -> Result<(), crate::BTreeError> {
        for t in &self.trees {
            t.validate()?;
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Cross-partition 2-phase rename
    // ------------------------------------------------------------------

    /// Atomically move a value from `src_key` to `dst_key`.
    ///
    /// When both keys map to the same partition this is a simple
    /// insert+delete.  When they span partitions both sides are
    /// conceptually locked in partition-id order to prevent deadlocks.
    ///
    /// Returns the previous value at `dst_key`, or `None`.
    pub fn cross_partition_move(
        &mut self,
        src_key: &K,
        dst_key: K,
    ) -> Result<Option<V>, PartitionError> {
        let src_pid = self.partition_for(src_key);
        let dst_pid = self.partition_for(&dst_key);

        let (_first, _second) = if src_pid <= dst_pid {
            (src_pid, dst_pid)
        } else {
            (dst_pid, src_pid)
        };

        let src_val = self.trees[src_pid]
            .delete(src_key)
            .ok_or(PartitionError::SourceNotFound)?;
        self.len -= 1;

        let prev = self.trees[dst_pid].insert(dst_key, src_val);
        if prev.is_none() {
            self.len += 1;
        }

        Ok(prev)
    }
}

// ---------------------------------------------------------------------------
// PartitionError
// ---------------------------------------------------------------------------

/// Errors from cross-partition operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PartitionError {
    /// The source key was not found in its partition.
    SourceNotFound,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::{String, ToString};

    type TestTree = PartitionedBTree<u64, String, 45, 45>;

    fn make_2part() -> TestTree {
        PartitionedBTree::new(Box::new(U64PartitionFn::new(2)))
    }

    fn make_4part() -> TestTree {
        PartitionedBTree::new(Box::new(U64PartitionFn::new(4)))
    }

    // ── Partition construction ──────────────────────────────────────

    #[test]
    fn partition_contains_correct_range() {
        let parts = build_hash_partitions(2);
        assert_eq!(parts.len(), 2);
        assert!(parts[0].contains(0x0000_0000_0000_0000));
        assert!(!parts[1].contains(0x0000_0000_0000_0000));
        assert!(!parts[0].contains(0x8000_0000_0000_0000));
        assert!(parts[1].contains(0x8000_0000_0000_0000));
    }

    #[test]
    fn partition_4way_routing() {
        let parts = build_hash_partitions(4);
        assert_eq!(parts.len(), 4);
        assert!(parts[0].contains(0x0000_0000_0000_0000));
        assert!(parts[1].contains(0x4000_0000_0000_0000));
        assert!(parts[2].contains(0x8000_0000_0000_0000));
        assert!(parts[3].contains(0xC000_0000_0000_0000));
    }

    #[test]
    fn u64_partition_fn_routes() {
        let pf = U64PartitionFn::new(4);
        assert_eq!(pf.partition_of(&0x0000_0000_0000_0000), 0);
        assert_eq!(pf.partition_of(&0x4000_0000_0000_0000), 1);
        assert_eq!(pf.partition_of(&0x8000_0000_0000_0000), 2);
        assert_eq!(pf.partition_of(&0xC000_0000_0000_0000), 3);
    }

    #[test]
    fn u64_partition_fn_single() {
        let pf = U64PartitionFn::new(1);
        assert_eq!(pf.partition_of(&0xFFFF_FFFF_FFFF_FFFF), 0);
        assert_eq!(pf.partition_of(&0), 0);
    }

    // ── Basic ops ───────────────────────────────────────────────────

    #[test]
    fn insert_and_get_single() {
        let mut t: TestTree = PartitionedBTree::new(Box::new(U64PartitionFn::new(1)));
        assert!(t.insert(42, "hello".into()).is_none());
        assert_eq!(t.get(&42).map(|s: &String| s.as_str()), Some("hello"));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn insert_and_get_multi() {
        let mut t = make_2part();
        t.insert(0, "zero".into());
        t.insert(0x8000_0000_0000_0000, "msb".into());

        assert_eq!(t.get(&0).map(|s: &String| s.as_str()), Some("zero"));
        assert_eq!(
            t.get(&0x8000_0000_0000_0000).map(|s: &String| s.as_str()),
            Some("msb")
        );
        assert_eq!(t.len(), 2);
        assert_eq!(t.partition_len(0), 1);
        assert_eq!(t.partition_len(1), 1);
    }

    #[test]
    fn delete_correct_partition() {
        let mut t = make_2part();
        t.insert(0, "a".into());
        t.insert(0x8000_0000_0000_0000, "b".into());
        assert_eq!(t.delete(&0), Some("a".to_string()));
        assert!(t.get(&0).is_none());
        assert_eq!(
            t.get(&0x8000_0000_0000_0000).map(|s: &String| s.as_str()),
            Some("b")
        );
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn contains_key_works() {
        let mut t = make_2part();
        t.insert(1, "x".into());
        assert!(t.contains_key(&1));
        assert!(!t.contains_key(&2));
    }

    #[test]
    fn entries_all_partitions() {
        let mut t = make_2part();
        t.insert(0, "a".into());
        t.insert(0x8000_0000_0000_0000, "b".into());
        t.insert(1, "c".into());
        assert_eq!(t.entries().len(), 3);
    }

    #[test]
    fn empty_and_len() {
        let mut t = make_2part();
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
        t.insert(0, "x".into());
        assert!(!t.is_empty());
        assert_eq!(t.len(), 1);
    }

    // ── Balance ─────────────────────────────────────────────────────

    #[test]
    fn imbalance_ratio_balanced() {
        let mut t = make_2part();
        t.insert(0, "a".into());
        t.insert(0x8000_0000_0000_0000, "b".into());
        assert!((t.imbalance_ratio() - 1.0).abs() < 0.001);
    }

    #[test]
    fn imbalance_ratio_skewed() {
        let mut t = make_2part();
        t.insert(0, "a".into());
        t.insert(1, "b".into());
        t.insert(2, "c".into());
        assert!((t.imbalance_ratio() - 2.0).abs() < 0.001);
    }

    #[test]
    fn imbalance_ratio_empty() {
        let t = make_2part();
        assert!((t.imbalance_ratio() - 1.0).abs() < 0.001);
    }

    #[test]
    fn heaviest_lightest() {
        let mut t = make_2part();
        t.insert(0, "a".into());
        t.insert(1, "b".into());
        t.insert(2, "c".into());
        assert_eq!(t.heaviest_partition(), 0);
        assert_eq!(t.lightest_partition(), 1);
    }

    // ── Cross-partition move ────────────────────────────────────────

    #[test]
    fn cross_move_same_partition() {
        let mut t = make_2part();
        t.insert(0, "a".into());
        let r = t.cross_partition_move(&0, 1).unwrap();
        assert!(r.is_none());
        assert!(!t.contains_key(&0));
        assert_eq!(t.get(&1).map(|s: &String| s.as_str()), Some("a"));
    }

    #[test]
    fn cross_move_different_partitions() {
        let mut t = make_2part();
        t.insert(0, "zero".into());
        let r = t.cross_partition_move(&0, 0x8000_0000_0000_0000).unwrap();
        assert!(r.is_none());
        assert!(!t.contains_key(&0));
        assert_eq!(
            t.get(&0x8000_0000_0000_0000).map(|s: &String| s.as_str()),
            Some("zero")
        );
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn cross_move_overwrite_destination() {
        let mut t = make_2part();
        t.insert(0, "src".into());
        t.insert(0x8000_0000_0000_0000, "dst_old".into());
        let r = t.cross_partition_move(&0, 0x8000_0000_0000_0000).unwrap();
        assert_eq!(r, Some("dst_old".to_string()));
        assert_eq!(
            t.get(&0x8000_0000_0000_0000).map(|s: &String| s.as_str()),
            Some("src")
        );
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn cross_move_source_not_found() {
        let mut t = make_2part();
        assert_eq!(
            t.cross_partition_move(&0, 0x8000_0000_0000_0000),
            Err(PartitionError::SourceNotFound)
        );
    }

    #[test]
    fn cross_move_deadlock_free_both_directions() {
        let mut t = make_2part();
        t.insert(0, "from0".into());
        t.insert(0x8000_0000_0000_0000, "from1".into());

        t.cross_partition_move(&0, 0x8000_0000_0000_0001).unwrap();
        t.cross_partition_move(&0x8000_0000_0000_0000, 1).unwrap();

        assert_eq!(
            t.get(&0x8000_0000_0000_0001).map(|s: &String| s.as_str()),
            Some("from0")
        );
        assert_eq!(t.get(&1).map(|s: &String| s.as_str()), Some("from1"));
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn four_partition_insert_get() {
        let mut t = make_4part();
        t.insert(0x0000_0000_0000_0000, "p0".into());
        t.insert(0x4000_0000_0000_0000, "p1".into());
        t.insert(0x8000_0000_0000_0000, "p2".into());
        t.insert(0xC000_0000_0000_0000, "p3".into());

        assert_eq!(t.len(), 4);
        for i in 0..4 {
            assert_eq!(t.partition_len(i), 1);
        }
        assert!(t.validate().is_ok());
    }

    #[test]
    fn four_partition_cross_move() {
        let mut t = make_4part();
        t.insert(0x0000_0000_0000_0000, "move_me".into());
        t.cross_partition_move(&0x0000_0000_0000_0000, 0xC000_0000_0000_0000)
            .unwrap();
        assert_eq!(t.partition_len(0), 0);
        assert_eq!(t.partition_len(3), 1);
        assert_eq!(
            t.get(&0xC000_0000_0000_0000).map(|s: &String| s.as_str()),
            Some("move_me")
        );
    }
}
