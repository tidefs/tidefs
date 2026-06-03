//! FUSE `forget` / `batch_forget` handler helpers.
//!
//! Provides:
//! - [`ForgetBatch`]: collector for deferred `(ino, nlookup)` pairs.
//! - [`process_forget_one`]: kernel-reference-count decrement for a single
//!   `FUSE_FORGET` (opcode 2) message.
//! - [`process_forget_batch`]: bulk decrement for a `FUSE_BATCH_FORGET`
//!   (opcode 42) message (feature-gated on `abi-7-16`).
//! - [`drain_forget_batch`]: drain all deferred entries during session
//!   teardown.
//!
//! # FUSE protocol semantics
//!
//! - `FUSE_FORGET` (opcode 2): The kernel sends a single `(ino, nlookup)`
//!   pair indicating that `nlookup` kernel-side references to `ino` have
//!   been dropped.  The filesystem should decrement its own reference
//!   count accordingly.  When the count reaches zero the inode is
//!   eligible for reclamation (e.g. orphan-index check for unlinked
//!   files).
//!
//! - `FUSE_BATCH_FORGET` (opcode 42, FUSE protocol 7.16+): The kernel
//!   sends multiple `fuse_forget_one` entries in a single message for
//!   performance.  Semantics are identical to individual `FUSE_FORGET`
//!   messages.
//!
//! # Usage
//!
//! ```rust,ignore
//! use fuser::forget;
//!
//! let mut batch = forget::ForgetBatch::new();
//! batch.push(ino, nlookup);
//! let zero_inos = forget::drain_forget_batch(&mut batch, |ino, n| {
//!     // decrement inode-table refcount; return true when zero
//!     inode_table.decr_kernel_refs(ino, n)
//! });
//! ```

#[cfg(feature = "abi-7-16")]
use crate::fuse_forget_one;

// ---------------------------------------------------------------------------
// ForgetBatch
// ---------------------------------------------------------------------------

/// Collector for deferred `(ino, nlookup)` pairs.
///
/// The kernel may send `FUSE_FORGET` messages at any time during a FUSE
/// session.  A `ForgetBatch` allows the filesystem to collect these
/// entries and process them in bulk (e.g. on `BATCH_FORGET` or during
/// `DESTROY` teardown).
///
/// Each entry is a `(u64, u64)` pair: `(inode_number, nlookup)` where
/// `nlookup` is the number of kernel-side lookups being released.
#[derive(Clone, Debug, Default)]
pub struct ForgetBatch {
    entries: Vec<(u64, u64)>,
}

impl ForgetBatch {
    /// Create an empty forget batch.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Create a batch with pre-allocated capacity.
    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            entries: Vec::with_capacity(cap),
        }
    }

    /// Push a single `(ino, nlookup)` pair into the batch.
    ///
    /// The `nlookup` value should be the kernel's lookup count for this
    /// forget operation.  A value of 0 is valid and is a no-op (the
    /// kernel is signaling no active references to release).
    pub fn push(&mut self, ino: u64, nlookup: u64) {
        self.entries.push((ino, nlookup));
    }

    /// Returns the number of deferred entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the batch is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Drain all entries, returning them as a `Vec<(u64, u64)>`.
    ///
    /// After draining, the batch is empty and can be reused.
    pub fn drain(&mut self) -> Vec<(u64, u64)> {
        std::mem::take(&mut self.entries)
    }
}

// ---------------------------------------------------------------------------
// process_forget_one — single FUSE_FORGET (opcode 2)
// ---------------------------------------------------------------------------

/// Process a single `FUSE_FORGET` message.
///
/// Calls `decrement(ino, nlookup)` which should perform the actual
/// reference-count decrement in the inode table.
///
/// Returns `true` if the kernel reference count for `ino` reached zero
/// (making the inode eligible for reclamation), or `false` if references
/// remain.
///
/// # Notes
///
/// - `nlookup == 0` is valid: the kernel signals no lookups to drop.
///   The callback should handle this gracefully (typically a no-op).
/// - The callback is responsible for any side effects when the count
///   reaches zero (e.g. orphan-index check for unlinked files).
#[inline]
pub fn process_forget_one(
    ino: u64,
    nlookup: u64,
    decrement: impl FnOnce(u64, u64) -> bool,
) -> bool {
    decrement(ino, nlookup)
}

// ---------------------------------------------------------------------------
// process_forget_batch — FUSE_BATCH_FORGET (opcode 42)
// ---------------------------------------------------------------------------

/// Process a `FUSE_BATCH_FORGET` message (FUSE protocol 7.16+).
///
/// Calls `decrement(ino, nlookup)` for each entry in `nodes`.
///
/// Returns a `Vec<u64>` of inode numbers whose kernel reference count
/// reached zero after the decrement.  Entries are in the order they
/// appear in `nodes`; duplicates are possible if multiple forget entries
/// for the same inode both reach zero.
#[cfg(feature = "abi-7-16")]
pub fn process_forget_batch(
    nodes: &[fuse_forget_one],
    mut decrement: impl FnMut(u64, u64) -> bool,
) -> Vec<u64> {
    let mut zero_inos = Vec::new();
    for node in nodes {
        if decrement(node.nodeid, node.nlookup) {
            zero_inos.push(node.nodeid);
        }
    }
    zero_inos
}

// ---------------------------------------------------------------------------
// drain_forget_batch — session teardown
// ---------------------------------------------------------------------------

/// Drain all entries from a [`ForgetBatch`], calling `decrement(ino, nlookup)`
/// for each.
///
/// Returns a `Vec<u64>` of inode numbers whose kernel reference count
/// reached zero after the decrement.
///
/// After draining, the batch is empty and can be reused.
///
/// # Typical use
///
/// Called during `FUSE_DESTROY` (opcode 38) session teardown to process
/// any remaining deferred forget entries before shutting down.
pub fn drain_forget_batch(
    batch: &mut ForgetBatch,
    mut decrement: impl FnMut(u64, u64) -> bool,
) -> Vec<u64> {
    let entries = batch.drain();
    let mut zero_inos = Vec::new();
    for (ino, nlookup) in entries {
        if decrement(ino, nlookup) {
            zero_inos.push(ino);
        }
    }
    zero_inos
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- ForgetBatch construction ------------------------------------------

    #[test]
    fn forget_batch_new_is_empty() {
        let batch = ForgetBatch::new();
        assert!(batch.is_empty());
        assert_eq!(batch.len(), 0);
    }

    #[test]
    fn forget_batch_default_is_empty() {
        let batch = ForgetBatch::default();
        assert!(batch.is_empty());
    }

    #[test]
    fn forget_batch_with_capacity() {
        let batch = ForgetBatch::with_capacity(64);
        assert!(batch.is_empty());
        assert!(batch.entries.capacity() >= 64);
    }

    #[test]
    fn forget_batch_push_and_len() {
        let mut batch = ForgetBatch::new();
        batch.push(42, 3);
        assert!(!batch.is_empty());
        assert_eq!(batch.len(), 1);
        batch.push(7, 1);
        assert_eq!(batch.len(), 2);
    }

    #[test]
    fn forget_batch_push_zero_nlookup() {
        let mut batch = ForgetBatch::new();
        batch.push(10, 0); // valid: kernel signals no lookups to drop
        assert_eq!(batch.len(), 1);
    }

    #[test]
    fn forget_batch_push_max_values() {
        let mut batch = ForgetBatch::new();
        batch.push(u64::MAX, u64::MAX);
        assert_eq!(batch.len(), 1);
    }

    // -- ForgetBatch drain -------------------------------------------------

    #[test]
    fn forget_batch_drain_returns_entries() {
        let mut batch = ForgetBatch::new();
        batch.push(1, 2);
        batch.push(3, 4);
        let drained = batch.drain();
        assert_eq!(drained, vec![(1, 2), (3, 4)]);
        assert!(batch.is_empty());
    }

    #[test]
    fn forget_batch_drain_empty_returns_empty() {
        let mut batch = ForgetBatch::new();
        let drained = batch.drain();
        assert!(drained.is_empty());
    }

    #[test]
    fn forget_batch_drain_then_reuse() {
        let mut batch = ForgetBatch::new();
        batch.push(5, 1);
        let _ = batch.drain();
        assert!(batch.is_empty());
        // Reuse after drain
        batch.push(6, 2);
        assert_eq!(batch.len(), 1);
    }

    #[test]
    fn forget_batch_clone_independent() {
        let mut a = ForgetBatch::new();
        a.push(1, 1);
        let b = a.clone();
        a.push(2, 2);
        assert_eq!(a.len(), 2);
        assert_eq!(b.len(), 1);
    }

    #[test]
    fn forget_batch_debug_nonempty() {
        let mut batch = ForgetBatch::new();
        batch.push(10, 20);
        let s = format!("{batch:?}");
        assert!(s.contains("10"));
        assert!(s.contains("20"));
    }

    // -- process_forget_one ------------------------------------------------

    #[test]
    fn process_forget_one_nominal_decrement() {
        let result = process_forget_one(42, 3, |ino, nlookup| {
            assert_eq!(ino, 42);
            assert_eq!(nlookup, 3);
            true
        });
        assert!(result);
    }

    #[test]
    fn process_forget_one_nonzero_remaining() {
        let mut count: u64 = 5;
        let result = process_forget_one(1, 2, |_, n| {
            count = count.saturating_sub(n);
            count == 0
        });
        assert!(!result);
        assert_eq!(count, 3);
    }

    #[test]
    fn process_forget_one_exact_to_zero() {
        let mut count: u64 = 5;
        let result = process_forget_one(1, 5, |_, n| {
            count = count.saturating_sub(n);
            count == 0
        });
        assert!(result);
        assert_eq!(count, 0);
    }

    #[test]
    fn process_forget_one_zero_nlookup() {
        let mut called = false;
        let result = process_forget_one(99, 0, |ino, nlookup| {
            called = true;
            assert_eq!(ino, 99);
            assert_eq!(nlookup, 0);
            false
        });
        assert!(called);
        assert!(!result);
    }

    #[test]
    fn process_forget_one_max_values() {
        let result = process_forget_one(u64::MAX, u64::MAX, |_, _| true);
        assert!(result);
    }

    #[test]
    fn process_forget_one_closure_moves_owned_data() {
        let captured = String::from("test");
        let result = process_forget_one(1, 1, |_, _| {
            let _len = captured.len();
            true
        });
        assert!(result);
    }

    // -- process_forget_batch (abi-7-16) -----------------------------------

    #[cfg(feature = "abi-7-16")]
    #[test]
    fn process_forget_batch_multiple_entries() {
        let nodes = vec![
            fuse_forget_one {
                nodeid: 10,
                nlookup: 1,
            },
            fuse_forget_one {
                nodeid: 20,
                nlookup: 2,
            },
            fuse_forget_one {
                nodeid: 30,
                nlookup: 1,
            },
        ];
        let mut counts = std::collections::HashMap::new();
        counts.insert(10u64, 1u64);
        counts.insert(20u64, 2u64);
        counts.insert(30u64, 2u64);

        let zero_inos = process_forget_batch(&nodes, |ino, n| {
            let c = counts.get_mut(&ino).unwrap();
            *c = c.saturating_sub(n);
            *c == 0
        });
        assert_eq!(zero_inos, vec![10, 20]);
    }

    #[cfg(feature = "abi-7-16")]
    #[test]
    fn process_forget_batch_empty_nodes() {
        let zero_inos = process_forget_batch(&[], |_, _| unreachable!());
        assert!(zero_inos.is_empty());
    }

    #[cfg(feature = "abi-7-16")]
    #[test]
    fn process_forget_batch_all_zero_nlookup() {
        let nodes = vec![
            fuse_forget_one {
                nodeid: 1,
                nlookup: 0,
            },
            fuse_forget_one {
                nodeid: 2,
                nlookup: 0,
            },
        ];
        let zero_inos = process_forget_batch(&nodes, |_, _| false);
        assert!(zero_inos.is_empty());
    }

    #[cfg(feature = "abi-7-16")]
    #[test]
    fn process_forget_batch_single_entry() {
        let nodes = vec![fuse_forget_one {
            nodeid: 99,
            nlookup: 1,
        }];
        let mut count: u64 = 1;
        let zero_inos = process_forget_batch(&nodes, |_, n| {
            count = count.saturating_sub(n);
            count == 0
        });
        assert_eq!(zero_inos, vec![99]);
    }

    // -- drain_forget_batch -------------------------------------------------

    #[test]
    fn drain_forget_batch_processes_all_entries() {
        let mut batch = ForgetBatch::new();
        batch.push(100, 1);
        batch.push(200, 3);
        batch.push(300, 2);

        let mut counts = std::collections::HashMap::new();
        counts.insert(100u64, 1u64);
        counts.insert(200u64, 3u64);
        counts.insert(300u64, 5u64);

        let zero_inos = drain_forget_batch(&mut batch, |ino, n| {
            let c = counts.get_mut(&ino).unwrap();
            *c = c.saturating_sub(n);
            *c == 0
        });
        assert_eq!(zero_inos, vec![100, 200]);
        assert!(batch.is_empty());
    }

    #[test]
    fn drain_forget_batch_empty_batch() {
        let mut batch = ForgetBatch::new();
        let zero_inos = drain_forget_batch(&mut batch, |_, _| unreachable!());
        assert!(zero_inos.is_empty());
    }

    #[test]
    fn drain_forget_batch_single_entry_zero_nlookup() {
        let mut batch = ForgetBatch::new();
        batch.push(50, 0);
        let zero_inos = drain_forget_batch(&mut batch, |_, _| false);
        assert!(zero_inos.is_empty());
        assert!(batch.is_empty());
    }

    #[test]
    fn drain_forget_batch_preserves_order() {
        let mut batch = ForgetBatch::new();
        batch.push(1, 1);
        batch.push(2, 1);
        batch.push(3, 1);

        let mut order = Vec::new();
        let _ = drain_forget_batch(&mut batch, |ino, _| {
            order.push(ino);
            true
        });
        assert_eq!(order, vec![1, 2, 3]);
    }

    #[test]
    fn drain_forget_batch_large_batch() {
        let mut batch = ForgetBatch::with_capacity(1024);
        for i in 0..1024u64 {
            batch.push(i, 1);
        }
        let zero_inos = drain_forget_batch(&mut batch, |_, _| true);
        assert_eq!(zero_inos.len(), 1024);
        assert!(batch.is_empty());
    }

    // -- Integration: batch -> drain round-trip ----------------------------

    #[test]
    fn batch_collect_then_drain() {
        let mut batch = ForgetBatch::new();
        batch.push(10, 2);
        batch.push(20, 1);
        batch.push(10, 1);

        let mut refs = std::collections::HashMap::new();
        refs.insert(10u64, 3u64);
        refs.insert(20u64, 1u64);

        let zero_inos = drain_forget_batch(&mut batch, |ino, n| {
            let c = refs.get_mut(&ino).unwrap();
            *c = c.saturating_sub(n);
            *c == 0
        });
        assert_eq!(zero_inos, vec![20, 10]);
    }
}
