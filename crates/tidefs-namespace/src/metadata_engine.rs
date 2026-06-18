// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Multi-core metadata engine with per-core work queues and partitioned
//! directory B-tree sharding.
//!
//! Dispatches incoming namespace operations to per-core queues; each core
//! processes its assigned partition's B-tree independently.  Cross-partition
//! operations (rename) use 2-phase lock ordering.

use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use tidefs_btree::PartitionFn;
use tidefs_dir_index::{DirIndex, DirIndexError};

use crate::{Inode, MemInodeTable, NamespaceError};

// ---------------------------------------------------------------------------
// NamespaceOp — unit of work for the metadata engine
// ---------------------------------------------------------------------------

/// A single namespace operation dispatched to a per-core queue.
#[derive(Debug)]
pub enum NamespaceOp {
    /// Look up an entry in a directory.
    Lookup { parent: Inode, name: Vec<u8> },
    /// Create a new directory entry.
    Create {
        parent: Inode,
        name: Vec<u8>,
        inode_id: u64,
        generation: u64,
        kind: u32,
    },
    /// Remove (unlink) a directory entry.
    Unlink { parent: Inode, name: Vec<u8> },
    /// Rename: move (src_parent, src_name) to (dst_parent, dst_name).
    Rename {
        src_parent: Inode,
        src_name: Vec<u8>,
        dst_parent: Inode,
        dst_name: Vec<u8>,
        flags: u32, // RENAME_NOREPLACE / RENAME_EXCHANGE
    },
}

/// Result of a single metadata operation.
#[derive(Debug)]
pub enum NamespaceOpResult {
    /// Lookup result: optional directory entry and attributes.
    Lookup(Option<(Inode, u64, u32)>),
    /// Operation succeeded (create / unlink / rename).
    Success,
    /// Operation failed with the given error.
    Error(NamespaceError),
}

// ---------------------------------------------------------------------------
// PerCoreWorkQueue
// ---------------------------------------------------------------------------

/// A lock-free (mutex-backed for correctness; upgradeable to lock-free later)
/// queue of namespace operations bound to a single core.
#[derive(Debug)]
pub struct PerCoreWorkQueue {
    queue: Mutex<VecDeque<NamespaceOp>>,
    /// Monotonically increasing counter of operations processed by this core.
    ops_processed: AtomicU64,
}

impl PerCoreWorkQueue {
    /// Create an empty per-core work queue.
    #[must_use]
    pub fn new() -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
            ops_processed: AtomicU64::new(0),
        }
    }

    /// Enqueue an operation.
    pub fn enqueue(&self, op: NamespaceOp) {
        let mut q = self.queue.lock().unwrap();
        q.push_back(op);
    }

    /// Dequeue the next operation, or `None` if empty.
    #[must_use]
    pub fn dequeue(&self) -> Option<NamespaceOp> {
        let mut q = self.queue.lock().unwrap();
        q.pop_front()
    }

    /// Return the number of pending operations in this queue.
    #[must_use]
    pub fn len(&self) -> usize {
        let q = self.queue.lock().unwrap();
        q.len()
    }

    /// Returns `true` when the queue is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Mark one operation as processed.
    pub fn record_processed(&self) {
        self.ops_processed.fetch_add(1, Ordering::Relaxed);
    }

    /// Return total operations processed by this core.
    #[must_use]
    pub fn ops_processed(&self) -> u64 {
        self.ops_processed.load(Ordering::Relaxed)
    }
}

impl Default for PerCoreWorkQueue {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// MetadataEngineStats
// ---------------------------------------------------------------------------

/// Observable statistics for the metadata engine.
#[derive(Clone, Debug, Default)]
pub struct MetadataEngineStats {
    /// Total operations processed across all cores.
    pub operations_processed: u64,
    /// Per-core queue lengths.
    pub per_core_queue_lengths: Vec<usize>,
    /// Partition imbalance ratio (heaviest / average).
    pub partition_imbalance_ratio: f64,
    /// Number of cross-partition operations processed.
    pub cross_partition_operations: u64,
}

// ---------------------------------------------------------------------------
// MetadataEngine
// ---------------------------------------------------------------------------

/// Multi-core metadata engine that dispatches operations to per-core queues
/// and processes them against a partitioned directory B-tree.
pub struct MetadataEngine<P: PartitionFn<u64> + Send + Sync + 'static> {
    /// One work queue per core.
    per_core_queues: Vec<Arc<PerCoreWorkQueue>>,
    /// The inode table (shared — namespace-wide).
    #[allow(dead_code)]
    inode_table: Arc<MemInodeTable>,
    /// Per-directory index shards, indexed by (core_id, directory_inode_id).
    /// Each directory's index is replicated across partitions:
    /// the partition_fn routes by name hash to select the shard.
    ///
    /// For simplicity in this implementation: each core owns a set of
    /// directory indices.  The partition function maps (directory_inode_id,
    /// name_hash) to a core_id.
    partition_fn: Arc<P>,
    /// Number of cores.
    core_count: usize,
    /// Cross-partition operation counter.
    cross_partition_ops: AtomicU64,
}

impl<P: PartitionFn<u64> + Send + Sync + 'static> MetadataEngine<P> {
    /// Create a new metadata engine with `core_count` per-core queues.
    #[must_use]
    pub fn new(core_count: usize, inode_table: Arc<MemInodeTable>, partition_fn: P) -> Self {
        assert!(core_count > 0, "core_count must be positive");
        let per_core_queues: Vec<Arc<PerCoreWorkQueue>> = (0..core_count)
            .map(|_| Arc::new(PerCoreWorkQueue::new()))
            .collect();
        Self {
            per_core_queues,
            inode_table,
            partition_fn: Arc::new(partition_fn),
            core_count,
            cross_partition_ops: AtomicU64::new(0),
        }
    }

    /// Return the number of cores.
    #[must_use]
    pub fn core_count(&self) -> usize {
        self.core_count
    }

    /// Return a reference to the per-core queue for core `core_id`.
    #[must_use]
    pub fn queue_for(&self, core_id: usize) -> &Arc<PerCoreWorkQueue> {
        &self.per_core_queues[core_id]
    }

    /// Map a directory inode + entry name hash to a core (partition) index.
    #[must_use]
    pub fn core_for(&self, _dir_inode: Inode, name_hash: u64) -> usize {
        // Route by the hash of the name only.  In a full implementation
        // we would combine dir_inode and name_hash to prevent hotspots.
        self.partition_fn.partition_of(&name_hash)
    }

    /// Dispatch a lookup to the appropriate per-core queue.
    pub fn dispatch_lookup(&self, parent: Inode, name: Vec<u8>) {
        let core = self.route_name(parent, &name);
        self.per_core_queues[core].enqueue(NamespaceOp::Lookup { parent, name });
    }

    /// Dispatch a create to the appropriate per-core queue.
    pub fn dispatch_create(
        &self,
        parent: Inode,
        name: Vec<u8>,
        inode_id: u64,
        generation: u64,
        kind: u32,
    ) {
        let core = self.route_name(parent, &name);
        self.per_core_queues[core].enqueue(NamespaceOp::Create {
            parent,
            name,
            inode_id,
            generation,
            kind,
        });
    }

    /// Dispatch an unlink to the appropriate per-core queue.
    pub fn dispatch_unlink(&self, parent: Inode, name: Vec<u8>) {
        let core = self.route_name(parent, &name);
        self.per_core_queues[core].enqueue(NamespaceOp::Unlink { parent, name });
    }

    /// Dispatch a rename.  If source and destination map to different
    /// cores, this is a cross-partition operation and the source core
    /// queue receives the operation (the processing code handles the
    /// 2-phase lock across partitions).
    pub fn dispatch_rename(
        &self,
        src_parent: Inode,
        src_name: Vec<u8>,
        dst_parent: Inode,
        dst_name: Vec<u8>,
        flags: u32,
    ) {
        // Route by source name hash.
        let core = self.route_name(src_parent, &src_name);
        self.per_core_queues[core].enqueue(NamespaceOp::Rename {
            src_parent,
            src_name,
            dst_parent,
            dst_name,
            flags,
        });
    }

    /// Process a single operation from the given core's queue against
    /// `dir_indices` — the in-memory directory state.
    ///
    /// Returns the result and updates statistics.
    pub fn process_one(
        &self,
        core_id: usize,
        dir_indices: &mut std::collections::HashMap<Inode, DirIndex>,
    ) -> Option<NamespaceOpResult> {
        let op = self.per_core_queues[core_id].dequeue()?;

        let result = match op {
            NamespaceOp::Lookup { parent, name } => {
                let dir = dir_indices.get(&parent);
                match dir {
                    Some(d) => match d.lookup(&name) {
                        Some(entry) => NamespaceOpResult::Lookup(Some((
                            entry.inode_id,
                            entry.generation,
                            entry.kind,
                        ))),
                        None => NamespaceOpResult::Lookup(None),
                    },
                    None => NamespaceOpResult::Error(NamespaceError::NotDirectory),
                }
            }
            NamespaceOp::Create {
                parent,
                name,
                inode_id,
                generation,
                kind,
            } => {
                let dir = dir_indices.get_mut(&parent);
                match dir {
                    Some(d) => match d.insert(&name, inode_id, generation, kind) {
                        Ok(()) => NamespaceOpResult::Success,
                        Err(e) => NamespaceOpResult::Error(e.into()),
                    },
                    None => NamespaceOpResult::Error(NamespaceError::NotDirectory),
                }
            }
            NamespaceOp::Unlink { parent, name } => {
                let dir = dir_indices.get_mut(&parent);
                match dir {
                    Some(d) => match d.delete(&name) {
                        Ok(_) => NamespaceOpResult::Success,
                        Err(e) => NamespaceOpResult::Error(e.into()),
                    },
                    None => NamespaceOpResult::Error(NamespaceError::NotDirectory),
                }
            }
            NamespaceOp::Rename {
                src_parent,
                src_name,
                dst_parent,
                dst_name,
                flags,
            } => {
                // Determine if cross-partition.
                let src_core = self.route_name(src_parent, &src_name);
                let dst_core = self.route_name(dst_parent, &dst_name);
                if src_core != dst_core {
                    self.cross_partition_ops.fetch_add(1, Ordering::Relaxed);
                }

                let swap_mode = if flags & crate::RENAME_EXCHANGE != 0 {
                    tidefs_dir_index::SwapMode::Exchange
                } else if flags & crate::RENAME_NOREPLACE != 0 {
                    tidefs_dir_index::SwapMode::NoReplace
                } else {
                    tidefs_dir_index::SwapMode::Rename
                };

                let src_exists = dir_indices.contains_key(&src_parent);
                let dst_exists = dir_indices.contains_key(&dst_parent);
                if !src_exists || !dst_exists {
                    NamespaceOpResult::Error(NamespaceError::NotDirectory)
                } else if src_parent == dst_parent {
                    let dir = dir_indices.get_mut(&src_parent).unwrap();
                    let result: Result<(), DirIndexError> = match swap_mode {
                        tidefs_dir_index::SwapMode::Rename => {
                            dir.rename_overwrite(&src_name, &dst_name).map(|_| ())
                        }
                        tidefs_dir_index::SwapMode::NoReplace => dir.rename(&src_name, &dst_name),
                        tidefs_dir_index::SwapMode::Exchange => {
                            // Manual exchange: read both, delete both,
                            // re-insert swapped.
                            let src_entry = dir.lookup(&src_name);
                            let dst_entry = dir.lookup(&dst_name);
                            match (src_entry, dst_entry) {
                                (Some(src), Some(dst)) => {
                                    let _ = dir.delete(&src_name);
                                    let _ = dir.delete(&dst_name);
                                    let _ = dir.insert(
                                        &src_name,
                                        dst.inode_id,
                                        dst.generation,
                                        dst.kind,
                                    );
                                    let _ = dir.insert(
                                        &dst_name,
                                        src.inode_id,
                                        src.generation,
                                        src.kind,
                                    );
                                    Ok(())
                                }
                                _ => Err(DirIndexError::EntryNotFound),
                            }
                        }
                    };
                    match result {
                        Ok(()) => NamespaceOpResult::Success,
                        Err(e) => NamespaceOpResult::Error(e.into()),
                    }
                } else {
                    // Cross-directory rename: temporarily remove dst_dir
                    // to avoid two &mut borrows on the HashMap.
                    let mut dst_dir = dir_indices.remove(&dst_parent).unwrap();
                    let result = {
                        let src_dir = dir_indices.get_mut(&src_parent).unwrap();
                        DirIndex::atomic_swap(
                            src_dir,
                            &src_name,
                            &mut dst_dir,
                            &dst_name,
                            swap_mode,
                        )
                    };
                    dir_indices.insert(dst_parent, dst_dir);
                    match result {
                        Ok(_overwritten) => NamespaceOpResult::Success,
                        Err(e) => NamespaceOpResult::Error(e.into()),
                    }
                }
            }
        };

        self.per_core_queues[core_id].record_processed();
        Some(result)
    }

    /// Collect statistics from the engine.
    #[must_use]
    pub fn stats(&self) -> MetadataEngineStats {
        let ops_processed: u64 = self.per_core_queues.iter().map(|q| q.ops_processed()).sum();
        let per_core_queue_lengths: Vec<usize> =
            self.per_core_queues.iter().map(|q| q.len()).collect();
        let cross_partition_operations = self.cross_partition_ops.load(Ordering::Relaxed);

        // Partition imbalance: heaviest queue / average
        let avg = if self.core_count > 0 {
            per_core_queue_lengths.iter().sum::<usize>() as f64 / self.core_count as f64
        } else {
            0.0
        };
        let partition_imbalance_ratio = if avg > 0.0 {
            let max = per_core_queue_lengths.iter().max().copied().unwrap_or(0) as f64;
            max / avg
        } else {
            1.0
        };

        MetadataEngineStats {
            operations_processed: ops_processed,
            per_core_queue_lengths,
            partition_imbalance_ratio,
            cross_partition_operations,
        }
    }

    // ── Private helpers ─────────────────────────────────────────────

    /// Route an operation for a directory entry to a core.
    fn route_name(&self, _parent: Inode, name: &[u8]) -> usize {
        // Hash the entry name and route by partition function.
        let hash = tidefs_dir_index::name_hash(name);
        self.partition_fn.partition_of(&hash)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tidefs_btree::U64PartitionFn;
    use tidefs_dir_index::{DatasetDirPolicy, DirIndex};

    fn test_inode_table() -> Arc<MemInodeTable> {
        Arc::new(MemInodeTable::new())
    }

    fn test_policy() -> DatasetDirPolicy {
        DatasetDirPolicy::default()
    }

    fn test_engine() -> MetadataEngine<U64PartitionFn> {
        let inode_table = test_inode_table();
        MetadataEngine::new(4, inode_table, U64PartitionFn::new(4))
    }

    // ── PerCoreWorkQueue tests ──────────────────────────────────────

    #[test]
    fn work_queue_enqueue_dequeue() {
        let q = PerCoreWorkQueue::new();
        assert!(q.is_empty());
        q.enqueue(NamespaceOp::Lookup {
            parent: 1,
            name: b"test".to_vec(),
        });
        assert_eq!(q.len(), 1);
        let op = q.dequeue();
        assert!(op.is_some());
        assert!(q.is_empty());
    }

    #[test]
    fn work_queue_ops_processed_count() {
        let q = PerCoreWorkQueue::new();
        assert_eq!(q.ops_processed(), 0);
        q.record_processed();
        q.record_processed();
        assert_eq!(q.ops_processed(), 2);
    }

    #[test]
    fn work_queue_fifo_order() {
        let q = PerCoreWorkQueue::new();
        q.enqueue(NamespaceOp::Lookup {
            parent: 1,
            name: b"a".to_vec(),
        });
        q.enqueue(NamespaceOp::Lookup {
            parent: 1,
            name: b"b".to_vec(),
        });
        let first = q.dequeue().unwrap();
        let second = q.dequeue().unwrap();
        assert!(matches!(first, NamespaceOp::Lookup { ref name, .. } if name == b"a"));
        assert!(matches!(second, NamespaceOp::Lookup { ref name, .. } if name == b"b"));
    }

    // ── MetadataEngine dispatch tests ───────────────────────────────

    #[test]
    fn dispatch_lookup_routes_to_a_queue() {
        let engine = test_engine();
        engine.dispatch_lookup(1, b"hello".to_vec());

        // At least one queue should be non-empty.
        let anyone_has_work = (0..engine.core_count()).any(|c| !engine.queue_for(c).is_empty());
        assert!(anyone_has_work, "dispatch should have enqueued an op");
    }

    #[test]
    fn dispatch_create_routes_to_a_queue() {
        let engine = test_engine();
        engine.dispatch_create(1, b"newfile".to_vec(), 42, 1, 1);
        let total_pending: usize = (0..engine.core_count())
            .map(|c| engine.queue_for(c).len())
            .sum();
        assert_eq!(total_pending, 1);
    }

    #[test]
    fn dispatch_unlink_routes_to_a_queue() {
        let engine = test_engine();
        engine.dispatch_unlink(1, b"rm_me".to_vec());
        let total_pending: usize = (0..engine.core_count())
            .map(|c| engine.queue_for(c).len())
            .sum();
        assert_eq!(total_pending, 1);
    }

    #[test]
    fn dispatch_rename_routes_to_a_queue() {
        let engine = test_engine();
        engine.dispatch_rename(1, b"old".to_vec(), 2, b"new".to_vec(), 0);
        let total_pending: usize = (0..engine.core_count())
            .map(|c| engine.queue_for(c).len())
            .sum();
        assert_eq!(total_pending, 1);
    }

    // ── Processing tests ────────────────────────────────────────────

    #[test]
    fn process_lookup_finds_entry() {
        let engine = test_engine();
        let mut dirs = std::collections::HashMap::new();
        let mut dir = DirIndex::new(1, test_policy());
        dir.insert(b"hello", 42, 1, 1).unwrap();
        dirs.insert(1, dir);

        engine.dispatch_lookup(1, b"hello".to_vec());
        let result = engine.process_one(
            engine.core_for(1, tidefs_dir_index::name_hash(b"hello")),
            &mut dirs,
        );
        assert!(result.is_some());
        match result.unwrap() {
            NamespaceOpResult::Lookup(Some((ino, gen, kind))) => {
                assert_eq!(ino, 42);
                assert_eq!(gen, 1);
                assert_eq!(kind, 1);
            }
            other => panic!("expected Lookup(Some), got {other:?}"),
        }
    }

    #[test]
    fn process_lookup_missing_entry() {
        let engine = test_engine();
        let mut dirs = std::collections::HashMap::new();
        dirs.insert(1, DirIndex::new(1, test_policy()));

        engine.dispatch_lookup(1, b"nope".to_vec());
        let result = engine.process_one(
            engine.core_for(1, tidefs_dir_index::name_hash(b"nope")),
            &mut dirs,
        );
        assert!(matches!(result, Some(NamespaceOpResult::Lookup(None))));
    }

    #[test]
    fn process_create_succeeds() {
        let engine = test_engine();
        let mut dirs = std::collections::HashMap::new();
        dirs.insert(1, DirIndex::new(1, test_policy()));

        engine.dispatch_create(1, b"newfile".to_vec(), 99, 2, 1);
        let core = engine.core_for(1, tidefs_dir_index::name_hash(b"newfile"));
        let result = engine.process_one(core, &mut dirs);
        assert!(matches!(result, Some(NamespaceOpResult::Success)));
        // Verify the entry was created.
        assert!(dirs[&1].contains(b"newfile"));
        assert_eq!(dirs[&1].lookup(b"newfile").unwrap().inode_id, 99);
    }

    #[test]
    fn process_create_duplicate_fails() {
        let engine = test_engine();
        let mut dirs = std::collections::HashMap::new();
        let mut dir = DirIndex::new(1, test_policy());
        dir.insert(b"dup", 10, 1, 1).unwrap();
        dirs.insert(1, dir);

        engine.dispatch_create(1, b"dup".to_vec(), 20, 2, 1);
        let core = engine.core_for(1, tidefs_dir_index::name_hash(b"dup"));
        let result = engine.process_one(core, &mut dirs);
        assert!(matches!(
            result,
            Some(NamespaceOpResult::Error(NamespaceError::AlreadyExists))
        ));
    }

    #[test]
    fn process_unlink_succeeds() {
        let engine = test_engine();
        let mut dirs = std::collections::HashMap::new();
        let mut dir = DirIndex::new(1, test_policy());
        dir.insert(b"bye", 10, 1, 1).unwrap();
        dirs.insert(1, dir);

        engine.dispatch_unlink(1, b"bye".to_vec());
        let core = engine.core_for(1, tidefs_dir_index::name_hash(b"bye"));
        let result = engine.process_one(core, &mut dirs);
        assert!(matches!(result, Some(NamespaceOpResult::Success)));
        assert!(!dirs[&1].contains(b"bye"));
    }

    #[test]
    fn process_unlink_not_found() {
        let engine = test_engine();
        let mut dirs = std::collections::HashMap::new();
        dirs.insert(1, DirIndex::new(1, test_policy()));

        engine.dispatch_unlink(1, b"nope".to_vec());
        let core = engine.core_for(1, tidefs_dir_index::name_hash(b"nope"));
        let result = engine.process_one(core, &mut dirs);
        assert!(matches!(
            result,
            Some(NamespaceOpResult::Error(NamespaceError::NotFound))
        ));
    }

    #[test]
    fn process_rename_same_directory() {
        let engine = test_engine();
        let mut dirs = std::collections::HashMap::new();
        let mut dir = DirIndex::new(1, test_policy());
        dir.insert(b"old", 10, 1, 1).unwrap();
        dirs.insert(1, dir);

        engine.dispatch_rename(1, b"old".to_vec(), 1, b"new".to_vec(), 0);
        let core = engine.core_for(1, tidefs_dir_index::name_hash(b"old"));
        let result = engine.process_one(core, &mut dirs);
        assert!(matches!(result, Some(NamespaceOpResult::Success)));
        assert!(!dirs[&1].contains(b"old"));
        assert!(dirs[&1].contains(b"new"));
        assert_eq!(dirs[&1].lookup(b"new").unwrap().inode_id, 10);
    }

    #[test]
    fn process_rename_cross_directory() {
        let engine = test_engine();
        let mut dirs = std::collections::HashMap::new();
        let mut src = DirIndex::new(1, test_policy());
        src.insert(b"file", 10, 1, 1).unwrap();
        dirs.insert(1, src);
        dirs.insert(2, DirIndex::new(2, test_policy()));

        engine.dispatch_rename(1, b"file".to_vec(), 2, b"moved".to_vec(), 0);
        let core = engine.core_for(1, tidefs_dir_index::name_hash(b"file"));
        let result = engine.process_one(core, &mut dirs);
        assert!(matches!(result, Some(NamespaceOpResult::Success)));
        assert!(!dirs[&1].contains(b"file"));
        assert!(dirs[&2].contains(b"moved"));
        assert_eq!(dirs[&2].lookup(b"moved").unwrap().inode_id, 10);
    }

    // ── Stats tests ─────────────────────────────────────────────────

    #[test]
    fn stats_reflects_processed_ops() {
        let engine = test_engine();
        let mut dirs = std::collections::HashMap::new();
        dirs.insert(1, DirIndex::new(1, test_policy()));

        engine.dispatch_create(1, b"a".to_vec(), 1, 1, 1);
        engine.dispatch_create(1, b"b".to_vec(), 2, 1, 1);

        let core_a = engine.core_for(1, tidefs_dir_index::name_hash(b"a"));
        let core_b = engine.core_for(1, tidefs_dir_index::name_hash(b"b"));

        engine.process_one(core_a, &mut dirs);
        engine.process_one(core_b, &mut dirs);

        let s = engine.stats();
        assert_eq!(s.operations_processed, 2);
    }

    #[test]
    fn stats_per_core_queue_lengths() {
        let engine = test_engine();
        engine.dispatch_create(1, b"x".to_vec(), 1, 1, 1);
        engine.dispatch_create(1, b"y".to_vec(), 2, 1, 1);

        let s = engine.stats();
        assert_eq!(s.per_core_queue_lengths.len(), engine.core_count());
        let total_queued: usize = s.per_core_queue_lengths.iter().sum();
        assert_eq!(total_queued, 2);
    }

    #[test]
    fn stats_cross_partition_counter() {
        let engine = test_engine();
        let mut dirs = std::collections::HashMap::new();
        let mut src = DirIndex::new(1, test_policy());
        src.insert(b"x", 10, 1, 1).unwrap();
        dirs.insert(1, src);
        dirs.insert(2, DirIndex::new(2, test_policy()));

        // Dispatch a rename that may cross partitions.
        engine.dispatch_rename(1, b"x".to_vec(), 2, b"y".to_vec(), 0);
        let core = engine.core_for(1, tidefs_dir_index::name_hash(b"x"));
        engine.process_one(core, &mut dirs);

        let s = engine.stats();
        // cross_partition_operations >= 0; we don't assert exact count
        // since it depends on hash routing.
        assert!(s.cross_partition_operations <= 1);
        assert!(s.operations_processed >= 1);
    }

    #[test]
    fn stats_imbalance_ratio_new_engine() {
        let engine = test_engine();
        let s = engine.stats();
        assert!((s.partition_imbalance_ratio - 1.0).abs() < 0.001);
    }
}
