#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! GC-safe pinned traversal root set for dataset destroy (§6 of
//! [`docs/DATASET_LIFECYCLE_DESIGN.md`]).
//!
//! Implements Phase 4 of the dataset lifecycle design: a const-generic
//! bounded set of [`TraversalRoot`] records that act as GC barriers during
//! DESTROYING. The GC treats pinned roots as additional reachability roots,
//! preventing premature reclamation of blocks still referenced by the
//! destroy worker.
//!
//! ## Pin model
//!
//! Pins are keyed by the full [`TraversalRoot`] identity (root type +
//! block pointer). Multiple services may pin the same exact root
//! concurrently via reference counting; the root remains GC-protected
//! until all pins on that specific root are released.
//!
//! Distinct snapshot roots (same [`TraversalRootType::SnapshotCatalog`]
//! but different block pointers) occupy separate slots and do not
//! collapse.  Deleting one snapshot unpins only that snapshot's root,
//! leaving other snapshots' object graphs protected.
//!
//! ## Thread safety
//!
//! `GcPinSet` is a plain data structure. For concurrent access from
//! the destroy worker and GC, wrap it in `Arc<RwLock<GcPinSet<N>>>`.
//!
//! ## Comparison to ZFS / Ceph
//!
//! - **ZFS**: Destroy (`zfs destroy`) is immediate — there is no
//!   intermediate GC barrier because the destroy blocks commit_group commit.
//!   No incremental, budgeted, resumable destroy exists.
//! - **Ceph**: Pool deletion is a monitor flag; no explicit root
//!   pinning protocol.
//! - **TideFS**: Pinned traversal roots decouple the destroy worker's
//!   progress from the GC's reclamation decisions. Each pinned root
//!   is a GC barrier; as the worker completes a root, it is unpinned,
//!   and the GC naturally reclaims the now-unreachable blocks.
//!
//! [`docs/DATASET_LIFECYCLE_DESIGN.md`]:
//!     https://forgejo/forgeadmin/tidefs/docs/DATASET_LIFECYCLE_DESIGN.md
//! [`TraversalRoot`]: tidefs_types_dataset_lifecycle_core::TraversalRoot

use core::fmt;

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use tidefs_types_dataset_lifecycle_core::{DestroyJobRecordV1, TraversalRoot, TraversalRootType};

// ---------------------------------------------------------------------------
// GcPinError — pin/unpin outcome
// ---------------------------------------------------------------------------

/// Errors from pin and unpin operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GcPinError {
    /// The pin set is at capacity and cannot accept another root.
    Full { capacity: usize },
    /// The requested root is not currently pinned (pin_count is 0).
    NotFound { root_type: TraversalRootType },
}

impl fmt::Display for GcPinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GcPinError::Full { capacity } => {
                write!(f, "GC pin set full (capacity: {capacity})")
            }
            GcPinError::NotFound { root_type } => {
                write!(f, "traversal root {root_type:?} not found in GC pin set")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PinSlot — single slot with reference count
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PinSlot {
    root: TraversalRoot,
    /// Number of active pins on this root (≥ 1 while the slot exists).
    pin_count: u32,
}

// ---------------------------------------------------------------------------
// GcPinValidation — simulated GC mark-set check result
// ---------------------------------------------------------------------------

/// Result of validating a GC mark set against the pinned roots.
///
/// Used in testing to verify that the GC correctly treats pinned
/// roots as reachability barriers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcPinValidation {
    /// Total number of occupied slots (distinct roots pinned).
    pub pinned_total: usize,
    /// Total number of active pins across all slots.
    pub pin_count_total: usize,
    /// Roots that are both pinned and present in the reachable set.
    pub reachable_from_pins: usize,
    /// Roots that are pinned but NOT in the reachable set
    /// (indicates GC incorrectly reclaimed pinned blocks).
    pub unreachable_pinned: usize,
    /// Roots that are in the reachable set but NOT pinned
    /// (indicates a potential GC leak — orphaned blocks not yet reclaimed).
    pub leaked: usize,
    /// Whether the validation passed (no unreachable pinned roots).
    pub passed: bool,
}

impl GcPinValidation {
    #[must_use]
    pub fn new(
        pinned_total: usize,
        pin_count_total: usize,
        reachable_from_pins: usize,
        unreachable_pinned: usize,
        leaked: usize,
    ) -> Self {
        GcPinValidation {
            pinned_total,
            pin_count_total,
            reachable_from_pins,
            unreachable_pinned,
            leaked,
            passed: unreachable_pinned == 0 && leaked == 0,
        }
    }
}

impl fmt::Display for GcPinValidation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GC pin validation: {} slots, {} total pins, {} reachable, {} unreachable, {} leaked — {}",
            self.pinned_total,
            self.pin_count_total,
            self.reachable_from_pins,
            self.unreachable_pinned,
            self.leaked,
            if self.passed { "PASS" } else { "FAIL" }
        )
    }
}

// ---------------------------------------------------------------------------
// GcPinSet — bounded, const-generic pinned root registry
// ---------------------------------------------------------------------------

/// A bounded set of GC-pinned [`TraversalRoot`] records with
/// reference-counted pinning.
///
/// `N` is the compile-time capacity. Use
/// [`MAX_TRAVERSAL_ROOTS`](tidefs_types_dataset_lifecycle_core::MAX_TRAVERSAL_ROOTS)
/// for datasets (6 root types) or a smaller value for testing.
///
/// # GC barrier contract
///
/// Any block reachable from a root in this set MUST NOT be reclaimed by
/// the GC, even if no live dataset reference exists.
///
/// # Identity-based pinning
///
/// Pins are keyed by the full [`TraversalRoot`] identity: root type AND
/// block pointer. Two snapshots with the same [`TraversalRootType`] but
/// different block pointers occupy separate slots. Deleting one snapshot
/// releases only that snapshot's pin, leaving other snapshots protected.
///
/// # Reference-counted pinning
///
/// Multiple background services may pin the same exact root concurrently.
/// Each [`pin()`](GcPinSet::pin) call increments the reference count;
/// each [`unpin()`](GcPinSet::unpin) call decrements it. The root is
/// removed from the barrier set only when the count reaches zero.
/// [`force_unpin()`](GcPinSet::force_unpin) removes a root regardless of
/// count, useful for lifecycle cleanup (abort, tombstone).
///
/// # Crash recovery
///
/// On recovery from crash during DESTROYING, call
/// [`repin_from_destroy_job()`](GcPinSet::repin_from_destroy_job)
/// to restore the pin set from the persisted
/// [`DestroyJobRecordV1`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GcPinSet<const N: usize> {
    slots: [Option<PinSlot>; N],
    count: usize,
}

impl<const N: usize> Default for GcPinSet<N> {
    fn default() -> Self {
        GcPinSet {
            slots: [None; N],
            count: 0,
        }
    }
}

impl<const N: usize> GcPinSet<N> {
    /// Create an empty pin set.
    #[must_use]
    pub fn new() -> Self {
        GcPinSet::default()
    }

    /// Number of distinct root slots currently occupied.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Total number of active pins across all roots.
    #[must_use]
    pub fn total_pins(&self) -> usize {
        let mut n: usize = 0;
        for i in 0..self.count {
            if let Some(ref slot) = self.slots[i] {
                n += slot.pin_count as usize;
            }
        }
        n
    }

    /// Whether the pin set has no occupied slots.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Whether the pin set is at maximum slot capacity.
    #[must_use]
    pub const fn is_full(&self) -> bool {
        self.count >= N
    }

    /// Maximum number of distinct root slots.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Number of distinct roots of the given [`TraversalRootType`]
    /// currently pinned.
    #[must_use]
    pub fn count_by_type(&self, root_type: TraversalRootType) -> usize {
        self.slots[..self.count]
            .iter()
            .filter(|s| {
                s.as_ref()
                    .is_some_and(|slot| slot.root.root_type == root_type)
            })
            .count()
    }

    /// Iterate over the pinned roots.
    pub fn pinned_roots(&self) -> impl Iterator<Item = &TraversalRoot> {
        self.slots[..self.count]
            .iter()
            .filter_map(|s| s.as_ref().map(|slot| &slot.root))
    }

    /// Number of pins on the given exact root (matched by full identity).
    ///
    /// Returns 0 if the root is not currently pinned.
    #[must_use]
    pub fn pin_count(&self, root: TraversalRoot) -> u32 {
        self.slots
            .iter()
            .take(self.count)
            .find_map(|s| {
                s.as_ref()
                    .filter(|slot| slot.root == root)
                    .map(|slot| slot.pin_count)
            })
            .unwrap_or(0)
    }

    /// Total number of pins across all roots of the given type.
    #[must_use]
    pub fn pin_count_by_type(&self, root_type: TraversalRootType) -> u32 {
        self.slots[..self.count]
            .iter()
            .filter_map(|s| {
                s.as_ref()
                    .filter(|slot| slot.root.root_type == root_type)
                    .map(|slot| slot.pin_count)
            })
            .sum()
    }

    /// Pin a traversal root, adding it to the GC barrier set.
    ///
    /// If the same root (full identity match) is already present,
    /// the pin count is incremented. Otherwise a new slot is allocated.
    ///
    /// # Errors
    /// - [`GcPinError::Full`] if a new slot is needed and the set is at
    ///   capacity.
    pub fn pin(&mut self, root: TraversalRoot) -> Result<(), GcPinError> {
        // Check for existing slot with same full root identity.
        for i in 0..self.count {
            if let Some(ref mut slot) = self.slots[i] {
                if slot.root == root {
                    slot.pin_count = slot.pin_count.saturating_add(1);
                    return Ok(());
                }
            }
        }
        // New distinct root — need an empty slot.
        if self.count >= N {
            return Err(GcPinError::Full { capacity: N });
        }
        self.slots[self.count] = Some(PinSlot { root, pin_count: 1 });
        self.count += 1;
        Ok(())
    }

    /// Release one pin on an exact traversal root (matched by full identity).
    ///
    /// Decrements the reference count by 1. If the count reaches zero,
    /// the slot is removed and the root is no longer GC-protected.
    ///
    /// # Errors
    /// - [`GcPinError::NotFound`] if no slot matches the full root identity.
    pub fn unpin(&mut self, root: TraversalRoot) -> Result<(), GcPinError> {
        let pos = self.slots[..self.count]
            .iter()
            .position(|s| s.as_ref().is_some_and(|slot| slot.root == root));

        match pos {
            Some(idx) => {
                let remove = {
                    let slot = self.slots[idx].as_mut().unwrap();
                    slot.pin_count = slot.pin_count.saturating_sub(1);
                    slot.pin_count == 0
                };
                if remove {
                    for i in idx..self.count.saturating_sub(1) {
                        self.slots[i] = self.slots[i + 1].take();
                    }
                    self.slots[self.count - 1] = None;
                    self.count -= 1;
                }
                Ok(())
            }
            None => Err(GcPinError::NotFound {
                root_type: root.root_type,
            }),
        }
    }

    /// Release one pin from the first root matching the given type
    /// (convenience wrapper for single-root-per-type scenarios).
    ///
    /// Prefer [`unpin()`](GcPinSet::unpin) with the full root when the
    /// specific root identity is known.
    ///
    /// # Errors
    /// - [`GcPinError::NotFound`] if no root with the given type is pinned.
    pub fn unpin_by_type(&mut self, root_type: TraversalRootType) -> Result<(), GcPinError> {
        let pos = self.slots[..self.count].iter().position(|s| {
            s.as_ref()
                .is_some_and(|slot| slot.root.root_type == root_type)
        });

        match pos {
            Some(idx) => {
                let remove = {
                    let slot = self.slots[idx].as_mut().unwrap();
                    slot.pin_count = slot.pin_count.saturating_sub(1);
                    slot.pin_count == 0
                };
                if remove {
                    for i in idx..self.count.saturating_sub(1) {
                        self.slots[i] = self.slots[i + 1].take();
                    }
                    self.slots[self.count - 1] = None;
                    self.count -= 1;
                }
                Ok(())
            }
            None => Err(GcPinError::NotFound { root_type }),
        }
    }

    /// Force-remove an exact root from the pin set regardless of
    /// reference count.
    ///
    /// Used for lifecycle cleanup (abort, tombstone transition)
    /// where all pins on a root should be dropped at once.
    ///
    /// # Errors
    /// - [`GcPinError::NotFound`] if no slot matches the full root identity.
    pub fn force_unpin(&mut self, root: TraversalRoot) -> Result<(), GcPinError> {
        let pos = self.slots[..self.count]
            .iter()
            .position(|s| s.as_ref().is_some_and(|slot| slot.root == root));

        match pos {
            Some(idx) => {
                for i in idx..self.count.saturating_sub(1) {
                    self.slots[i] = self.slots[i + 1].take();
                }
                self.slots[self.count - 1] = None;
                self.count -= 1;
                Ok(())
            }
            None => Err(GcPinError::NotFound {
                root_type: root.root_type,
            }),
        }
    }

    /// Force-remove all roots of the given type regardless of reference
    /// count (convenience wrapper for single-root-per-type scenarios).
    ///
    /// Prefer [`force_unpin()`](GcPinSet::force_unpin) with the full root
    /// when the specific root identity is known.
    ///
    /// # Errors
    /// - [`GcPinError::NotFound`] if no root with the given type is present.
    pub fn force_unpin_by_type(&mut self, root_type: TraversalRootType) -> Result<(), GcPinError> {
        let pos = self.slots[..self.count].iter().position(|s| {
            s.as_ref()
                .is_some_and(|slot| slot.root.root_type == root_type)
        });

        match pos {
            Some(idx) => {
                for i in idx..self.count.saturating_sub(1) {
                    self.slots[i] = self.slots[i + 1].take();
                }
                self.slots[self.count - 1] = None;
                self.count -= 1;
                Ok(())
            }
            None => Err(GcPinError::NotFound { root_type }),
        }
    }

    /// Check whether an exact root has any active pins.
    #[must_use]
    pub fn is_pinned(&self, root: TraversalRoot) -> bool {
        self.slots.iter().take(self.count).any(|s| {
            s.as_ref()
                .is_some_and(|slot| slot.root == root && slot.pin_count > 0)
        })
    }

    /// Check whether any root of the given type has active pins.
    #[must_use]
    pub fn is_pinned_by_type(&self, root_type: TraversalRootType) -> bool {
        self.slots.iter().take(self.count).any(|s| {
            s.as_ref()
                .is_some_and(|slot| slot.root.root_type == root_type && slot.pin_count > 0)
        })
    }

    /// Repopulate the pin set from a persisted [`DestroyJobRecordV1`].
    pub fn repin_from_destroy_job(&mut self, job: &DestroyJobRecordV1) {
        self.slots = [None; N];
        self.count = 0;

        for root in job.valid_roots().iter().flatten() {
            if self.count >= N {
                break;
            }
            self.slots[self.count] = Some(PinSlot {
                root: *root,
                pin_count: 1,
            });
            self.count += 1;
        }
    }

    // -- GC mark-set validation (for testing) --

    /// Validate that the GC correctly treats pinned roots as reachability
    /// barriers.
    ///
    /// Compares by full [`TraversalRoot`] identity (not just root type).
    #[must_use]
    pub fn validate_mark_set(&self, reachable: &[TraversalRoot]) -> GcPinValidation {
        let pinned_total = self.count;
        let pin_count_total = self.total_pins();
        let mut reachable_from_pins = 0usize;
        let mut unreachable_pinned = 0usize;
        let mut leaked = 0usize;

        for i in 0..self.count {
            if let Some(ref slot) = self.slots[i] {
                let found = reachable.contains(&slot.root);
                if found {
                    reachable_from_pins += 1;
                } else {
                    unreachable_pinned += 1;
                }
            }
        }

        for reachable_root in reachable {
            let is_pinned = self
                .slots
                .iter()
                .take(self.count)
                .any(|s| s.as_ref().is_some_and(|slot| slot.root == *reachable_root));
            if !is_pinned {
                leaked += 1;
            }
        }

        GcPinValidation::new(
            pinned_total,
            pin_count_total,
            reachable_from_pins,
            unreachable_pinned,
            leaked,
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_types_dataset_lifecycle_core::BlockPointer;

    fn make_root(root_type: TraversalRootType, bp: u64) -> TraversalRoot {
        TraversalRoot::new(root_type, BlockPointer(bp), 100)
    }

    fn make_all_roots() -> [TraversalRoot; 6] {
        [
            make_root(TraversalRootType::InodeTable, 1),
            make_root(TraversalRootType::ExtentMap, 2),
            make_root(TraversalRootType::DirectoryIndex, 3),
            make_root(TraversalRootType::XattrStore, 4),
            make_root(TraversalRootType::SnapshotCatalog, 5),
            make_root(TraversalRootType::FeatureFlags, 6),
        ]
    }

    #[test]
    fn new_empty() {
        let set = GcPinSet::<6>::new();
        assert_eq!(set.count(), 0);
        assert!(set.is_empty());
        assert!(!set.is_full());
        assert_eq!(set.capacity(), 6);
        assert_eq!(set.total_pins(), 0);
    }

    #[test]
    fn default_is_empty() {
        let set = GcPinSet::<4>::default();
        assert!(set.is_empty());
        assert_eq!(set.count(), 0);
    }

    #[test]
    fn pin_single_root() {
        let mut set = GcPinSet::<6>::new();
        let root = make_root(TraversalRootType::InodeTable, 10);
        set.pin(root).unwrap();
        assert_eq!(set.count(), 1);
        assert_eq!(set.total_pins(), 1);
        assert_eq!(set.pin_count(root), 1);
        assert!(set.is_pinned(root));
        assert!(!set.is_pinned(make_root(TraversalRootType::ExtentMap, 20)));
        assert!(set.is_pinned_by_type(TraversalRootType::InodeTable));
        assert!(!set.is_pinned_by_type(TraversalRootType::ExtentMap));
    }

    #[test]
    fn pin_same_root_increments_count() {
        let mut set = GcPinSet::<6>::new();
        let root = make_root(TraversalRootType::InodeTable, 10);
        set.pin(root).unwrap();
        set.pin(root).unwrap();
        assert_eq!(set.count(), 1);
        assert_eq!(set.total_pins(), 2);
        assert_eq!(set.pin_count(root), 2);
        assert!(set.is_pinned(root));
    }

    #[test]
    fn pin_same_type_different_block_pointer_uses_separate_slots() {
        let mut set = GcPinSet::<6>::new();
        let r1 = make_root(TraversalRootType::SnapshotCatalog, 100);
        let r2 = make_root(TraversalRootType::SnapshotCatalog, 200);
        set.pin(r1).unwrap();
        set.pin(r2).unwrap();
        // Two distinct slots — not collapsed because block pointers differ.
        assert_eq!(set.count(), 2);
        assert_eq!(set.total_pins(), 2);
        assert_eq!(set.pin_count(r1), 1);
        assert_eq!(set.pin_count(r2), 1);
        assert_eq!(set.pin_count_by_type(TraversalRootType::SnapshotCatalog), 2);
        assert_eq!(set.count_by_type(TraversalRootType::SnapshotCatalog), 2);
    }

    #[test]
    fn pin_multiple_distinct_types() {
        let mut set = GcPinSet::<6>::new();
        let roots = make_all_roots();
        for root in &roots {
            set.pin(*root).unwrap();
        }
        assert_eq!(set.count(), 6);
        assert_eq!(set.total_pins(), 6);
        assert!(set.is_full());
        for root in &roots {
            assert!(set.is_pinned(*root));
        }
    }

    #[test]
    fn pin_mixed_ref_counts() {
        let mut set = GcPinSet::<6>::new();
        let r1 = make_root(TraversalRootType::InodeTable, 1);
        set.pin(r1).unwrap();
        set.pin(r1).unwrap();
        set.pin(r1).unwrap();
        let r2 = make_root(TraversalRootType::ExtentMap, 10);
        set.pin(r2).unwrap();
        let s1 = make_root(TraversalRootType::SnapshotCatalog, 20);
        let s2 = make_root(TraversalRootType::SnapshotCatalog, 30);
        set.pin(s1).unwrap();
        set.pin(s2).unwrap();
        assert_eq!(set.count(), 4);
        assert_eq!(set.total_pins(), 6);
        assert_eq!(set.pin_count(r1), 3);
        assert_eq!(set.pin_count(r2), 1);
        assert_eq!(set.pin_count(s1), 1);
        assert_eq!(set.pin_count(s2), 1);
        assert_eq!(set.pin_count_by_type(TraversalRootType::SnapshotCatalog), 2);
        assert_eq!(
            set.pin_count(make_root(TraversalRootType::DirectoryIndex, 99)),
            0
        );
    }

    #[test]
    fn pin_at_capacity_different_root_rejected() {
        let mut set = GcPinSet::<2>::new();
        set.pin(make_root(TraversalRootType::InodeTable, 1))
            .unwrap();
        set.pin(make_root(TraversalRootType::ExtentMap, 2)).unwrap();
        let err = set
            .pin(make_root(TraversalRootType::DirectoryIndex, 3))
            .unwrap_err();
        assert_eq!(err, GcPinError::Full { capacity: 2 });
    }

    #[test]
    fn pin_at_capacity_same_root_succeeds() {
        let mut set = GcPinSet::<2>::new();
        let r1 = make_root(TraversalRootType::InodeTable, 1);
        set.pin(r1).unwrap();
        set.pin(make_root(TraversalRootType::ExtentMap, 2)).unwrap();
        set.pin(r1).unwrap();
        assert_eq!(set.count(), 2);
        assert_eq!(set.total_pins(), 3);
        assert_eq!(set.pin_count(r1), 2);
    }

    #[test]
    fn unpin_decrements_count() {
        let mut set = GcPinSet::<6>::new();
        let root = make_root(TraversalRootType::InodeTable, 1);
        set.pin(root).unwrap();
        set.pin(root).unwrap();
        assert_eq!(set.total_pins(), 2);
        set.unpin(root).unwrap();
        assert_eq!(set.total_pins(), 1);
        assert_eq!(set.pin_count(root), 1);
        assert!(set.is_pinned(root));
        assert_eq!(set.count(), 1);
    }

    #[test]
    fn unpin_last_removes_slot() {
        let mut set = GcPinSet::<6>::new();
        let root = make_root(TraversalRootType::InodeTable, 1);
        set.pin(root).unwrap();
        set.unpin(root).unwrap();
        assert!(set.is_empty());
        assert_eq!(set.count(), 0);
        assert_eq!(set.total_pins(), 0);
        assert!(!set.is_pinned(root));
    }

    #[test]
    fn unpin_not_found() {
        let mut set = GcPinSet::<6>::new();
        let r1 = make_root(TraversalRootType::InodeTable, 1);
        set.pin(r1).unwrap();
        let err = set
            .unpin(make_root(TraversalRootType::InodeTable, 999))
            .unwrap_err();
        assert_eq!(
            err,
            GcPinError::NotFound {
                root_type: TraversalRootType::InodeTable
            }
        );
    }

    #[test]
    fn unpin_wrong_type_not_found() {
        let mut set = GcPinSet::<6>::new();
        set.pin(make_root(TraversalRootType::InodeTable, 1))
            .unwrap();
        let err = set
            .unpin(make_root(TraversalRootType::ExtentMap, 99))
            .unwrap_err();
        assert_eq!(
            err,
            GcPinError::NotFound {
                root_type: TraversalRootType::ExtentMap
            }
        );
    }

    #[test]
    fn unpin_deletes_correct_snapshot_root() {
        let mut set = GcPinSet::<6>::new();
        let s1 = make_root(TraversalRootType::SnapshotCatalog, 100);
        let s2 = make_root(TraversalRootType::SnapshotCatalog, 200);
        set.pin(s1).unwrap();
        set.pin(s2).unwrap();
        assert_eq!(set.count(), 2);

        // Unpin s2 — s1 must remain.
        set.unpin(s2).unwrap();
        assert_eq!(set.count(), 1);
        assert!(set.is_pinned(s1));
        assert!(!set.is_pinned(s2));
        assert_eq!(set.pin_count(s1), 1);
        assert!(set.is_pinned_by_type(TraversalRootType::SnapshotCatalog));
        assert_eq!(set.pin_count_by_type(TraversalRootType::SnapshotCatalog), 1);
    }

    #[test]
    fn unpin_by_type_decrements_first_match() {
        let mut set = GcPinSet::<6>::new();
        let s1 = make_root(TraversalRootType::SnapshotCatalog, 100);
        let s2 = make_root(TraversalRootType::SnapshotCatalog, 200);
        set.pin(s1).unwrap();
        set.pin(s2).unwrap();
        set.unpin_by_type(TraversalRootType::SnapshotCatalog)
            .unwrap();
        // Unpinned the first match (s1), one remains.
        assert_eq!(set.count(), 1);
        assert!(!set.is_pinned(s1));
        assert!(set.is_pinned(s2));
    }

    #[test]
    fn unpin_by_type_not_found() {
        let mut set = GcPinSet::<6>::new();
        let err = set
            .unpin_by_type(TraversalRootType::InodeTable)
            .unwrap_err();
        assert_eq!(
            err,
            GcPinError::NotFound {
                root_type: TraversalRootType::InodeTable
            }
        );
    }

    #[test]
    fn force_unpin_when_multiple_refs() {
        let mut set = GcPinSet::<6>::new();
        let root = make_root(TraversalRootType::InodeTable, 1);
        set.pin(root).unwrap();
        set.pin(root).unwrap();
        set.pin(root).unwrap();
        assert_eq!(set.pin_count(root), 3);
        set.force_unpin(root).unwrap();
        assert_eq!(set.count(), 0);
        assert!(!set.is_pinned(root));
    }

    #[test]
    fn force_unpin_not_found() {
        let mut set = GcPinSet::<6>::new();
        let err = set
            .force_unpin(make_root(TraversalRootType::InodeTable, 1))
            .unwrap_err();
        assert_eq!(
            err,
            GcPinError::NotFound {
                root_type: TraversalRootType::InodeTable
            }
        );
    }

    #[test]
    fn force_unpin_by_type_removes_first_match() {
        let mut set = GcPinSet::<6>::new();
        let s1 = make_root(TraversalRootType::SnapshotCatalog, 100);
        let s2 = make_root(TraversalRootType::SnapshotCatalog, 200);
        set.pin(s1).unwrap();
        set.pin(s2).unwrap();
        set.pin(s1).unwrap(); // refcount s1 → 2
        set.force_unpin_by_type(TraversalRootType::SnapshotCatalog)
            .unwrap();
        // First snapshot slot removed; second remains.
        assert_eq!(set.count(), 1);
        assert!(!set.is_pinned(s1));
        assert!(set.is_pinned(s2));
    }

    #[test]
    fn force_unpin_by_type_not_found() {
        let mut set = GcPinSet::<6>::new();
        let err = set
            .force_unpin_by_type(TraversalRootType::InodeTable)
            .unwrap_err();
        assert_eq!(
            err,
            GcPinError::NotFound {
                root_type: TraversalRootType::InodeTable
            }
        );
    }

    #[test]
    fn is_pinned_edge_cases() {
        let mut set = GcPinSet::<6>::new();
        let root = make_root(TraversalRootType::InodeTable, 1);
        assert!(!set.is_pinned(root));
        set.pin(root).unwrap();
        assert!(set.is_pinned(root));
        assert!(!set.is_pinned(make_root(TraversalRootType::ExtentMap, 99)));
        set.unpin(root).unwrap();
        assert!(!set.is_pinned(root));
    }

    #[test]
    fn repin_from_destroy_job_basic() {
        let roots = [
            make_root(TraversalRootType::InodeTable, 10),
            make_root(TraversalRootType::ExtentMap, 20),
            make_root(TraversalRootType::DirectoryIndex, 30),
        ];
        let job = DestroyJobRecordV1::new(1, 100, Default::default(), &roots, 300).unwrap();
        let mut set = GcPinSet::<6>::new();
        set.repin_from_destroy_job(&job);
        assert_eq!(set.count(), 3);
        assert_eq!(set.total_pins(), 3);
        assert!(set.is_pinned(make_root(TraversalRootType::InodeTable, 10)));
    }

    #[test]
    fn repin_clears_existing_pins() {
        let mut set = GcPinSet::<6>::new();
        let xattr = make_root(TraversalRootType::XattrStore, 99);
        set.pin(xattr).unwrap();
        set.pin(xattr).unwrap();
        assert_eq!(set.total_pins(), 2);
        let roots = [make_root(TraversalRootType::InodeTable, 1)];
        let job = DestroyJobRecordV1::new(1, 100, Default::default(), &roots, 100).unwrap();
        set.repin_from_destroy_job(&job);
        assert_eq!(set.count(), 1);
        assert_eq!(set.total_pins(), 1);
        assert!(set.is_pinned(make_root(TraversalRootType::InodeTable, 1)));
    }

    #[test]
    fn gc_validation_all_reachable() {
        let mut set = GcPinSet::<6>::new();
        let roots = make_all_roots();
        for root in &roots {
            set.pin(*root).unwrap();
        }
        let validation = set.validate_mark_set(&roots);
        assert!(validation.passed);
        assert_eq!(validation.pinned_total, 6);
        assert_eq!(validation.pin_count_total, 6);
        assert_eq!(validation.reachable_from_pins, 6);
    }

    #[test]
    fn gc_validation_unreachable_pinned() {
        let mut set = GcPinSet::<6>::new();
        let r1 = make_root(TraversalRootType::InodeTable, 1);
        let r2 = make_root(TraversalRootType::ExtentMap, 2);
        set.pin(r1).unwrap();
        set.pin(r2).unwrap();
        let reachable = [r1];
        let validation = set.validate_mark_set(&reachable);
        assert!(!validation.passed);
        assert_eq!(validation.unreachable_pinned, 1);
    }

    #[test]
    fn gc_validation_empty() {
        let set = GcPinSet::<6>::new();
        let validation = set.validate_mark_set(&[]);
        assert!(validation.passed);
    }

    #[test]
    fn gc_validation_identity_match() {
        // Two snapshots with same type, different block pointers.
        // If the reachable set has one, the other should be unreachable.
        let mut set = GcPinSet::<6>::new();
        let s1 = make_root(TraversalRootType::SnapshotCatalog, 100);
        let s2 = make_root(TraversalRootType::SnapshotCatalog, 200);
        set.pin(s1).unwrap();
        set.pin(s2).unwrap();
        let reachable = [s1];
        let validation = set.validate_mark_set(&reachable);
        assert!(!validation.passed);
        assert_eq!(validation.unreachable_pinned, 1);
        assert_eq!(validation.reachable_from_pins, 1);
    }

    #[test]
    fn clone_preserves_state() {
        let mut set = GcPinSet::<6>::new();
        let root = make_root(TraversalRootType::InodeTable, 1);
        set.pin(root).unwrap();
        set.pin(root).unwrap();
        let cloned = set.clone();
        assert_eq!(cloned.count(), 1);
        assert_eq!(cloned.total_pins(), 2);
        assert_eq!(cloned.pin_count(root), 2);
    }

    #[test]
    fn full_lifecycle_with_ref_counts() {
        let mut set = GcPinSet::<6>::new();
        let r1 = make_root(TraversalRootType::InodeTable, 1);
        let r2 = make_root(TraversalRootType::ExtentMap, 2);
        for _ in 0..3 {
            set.pin(r1).unwrap();
        }
        for _ in 0..2 {
            set.pin(r2).unwrap();
        }
        assert_eq!(set.count(), 2);
        assert_eq!(set.total_pins(), 5);
        set.unpin(r1).unwrap();
        set.unpin(r1).unwrap();
        assert_eq!(set.count(), 2);
        assert_eq!(set.pin_count(r1), 1);
        set.unpin(r1).unwrap();
        assert_eq!(set.count(), 1);
        set.force_unpin(r2).unwrap();
        assert!(set.is_empty());
    }

    #[test]
    fn const_generic_capacity_0() {
        let mut set = GcPinSet::<0>::new();
        assert!(set.is_empty());
        assert!(set.is_full());
        let err = set
            .pin(make_root(TraversalRootType::InodeTable, 1))
            .unwrap_err();
        assert_eq!(err, GcPinError::Full { capacity: 0 });
    }

    #[test]
    fn error_display_nonempty() {
        let errors = [
            GcPinError::Full { capacity: 6 },
            GcPinError::NotFound {
                root_type: TraversalRootType::InodeTable,
            },
        ];
        for e in &errors {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn validation_display_nonempty() {
        let v = GcPinValidation::new(6, 8, 4, 2, 1);
        let s = v.to_string();
        assert!(s.contains("FAIL"));
        assert!(s.contains("6 slots"));
        assert!(s.contains("8 total pins"));
    }

    #[test]
    fn count_by_type_empty() {
        let set = GcPinSet::<6>::new();
        assert_eq!(set.count_by_type(TraversalRootType::SnapshotCatalog), 0);
    }

    #[test]
    fn count_by_type_multiple() {
        let mut set = GcPinSet::<6>::new();
        set.pin(make_root(TraversalRootType::SnapshotCatalog, 1))
            .unwrap();
        set.pin(make_root(TraversalRootType::SnapshotCatalog, 2))
            .unwrap();
        set.pin(make_root(TraversalRootType::InodeTable, 3))
            .unwrap();
        assert_eq!(set.count_by_type(TraversalRootType::SnapshotCatalog), 2);
        assert_eq!(set.count_by_type(TraversalRootType::InodeTable), 1);
    }
}
