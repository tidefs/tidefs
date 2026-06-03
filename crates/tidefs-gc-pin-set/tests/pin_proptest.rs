// Property-based tests for tidefs-gc-pin-set.
// Uses proptest to verify invariants under random operation sequences.
// Updated for ref-counted pinning: pin() increments count on the same exact root.

use proptest::prelude::*;
use tidefs_gc_pin_set::{GcPinError, GcPinSet};
use tidefs_types_dataset_lifecycle_core::{BlockPointer, TraversalRoot, TraversalRootType};

const ALL_TYPES: [TraversalRootType; 6] = [
    TraversalRootType::InodeTable,
    TraversalRootType::ExtentMap,
    TraversalRootType::DirectoryIndex,
    TraversalRootType::XattrStore,
    TraversalRootType::SnapshotCatalog,
    TraversalRootType::FeatureFlags,
];

fn make_root(rt: TraversalRootType, bp: u64) -> TraversalRoot {
    TraversalRoot::new(rt, BlockPointer(bp), (bp % 1000) + 1)
}

fn root_type_strategy() -> impl Strategy<Value = TraversalRootType> {
    (0..6u8).prop_map(|i| ALL_TYPES[i as usize])
}

#[derive(Clone, Debug)]
enum Op {
    Pin { rt: TraversalRootType, bp: u64 },
    Unpin { rt: TraversalRootType, bp: u64 },
}

fn op_strategy(capacity: usize) -> impl Strategy<Value = Vec<Op>> {
    let op = (root_type_strategy(), 0..100u64).prop_flat_map(move |(rt, bp)| {
        prop_oneof![
            (Just(rt), Just(bp)).prop_map(|(rt, bp)| Op::Pin { rt, bp }),
            (Just(rt), Just(bp)).prop_map(|(rt, bp)| Op::Unpin { rt, bp }),
        ]
    });
    proptest::collection::vec(op, 0..(capacity * 3 + 10))
}

fn model_pos(model: &[(TraversalRoot, u32)], root: TraversalRoot) -> Option<usize> {
    model.iter().position(|(pinned, _)| *pinned == root)
}

proptest! {
    // -----------------------------------------------------------------------
    // Ref-counted pin model: pin() increments count for the same exact root.
    // -----------------------------------------------------------------------
    #[test]
    fn refcount_matches_ops(ops in op_strategy(6)) {
        let mut set = GcPinSet::<6>::new();
        let mut model: Vec<(TraversalRoot, u32)> = Vec::new();

        for op in &ops {
            match *op {
                Op::Pin { rt, bp } => {
                    let root = make_root(rt, bp);
                    let pos = model_pos(&model, root);
                    let already_full = model.len() >= 6 && pos.is_none();
                    let result = set.pin(root);

                    if already_full {
                        prop_assert_eq!(result, Err(GcPinError::Full { capacity: 6 }));
                    } else {
                        prop_assert!(result.is_ok());
                        if let Some(idx) = pos {
                            model[idx].1 = model[idx].1.saturating_add(1);
                        } else {
                            model.push((root, 1));
                        }
                    }
                }
                Op::Unpin { rt, bp } => {
                    let root = make_root(rt, bp);
                    if let Some(idx) = model_pos(&model, root) {
                        prop_assert!(set.unpin(root).is_ok());
                        model[idx].1 -= 1;
                        if model[idx].1 == 0 {
                            model.remove(idx);
                        }
                    } else {
                        prop_assert_eq!(
                            set.unpin(root),
                            Err(GcPinError::NotFound { root_type: rt })
                        );
                    }
                }
            }
            prop_assert!(model.len() <= 6);
            prop_assert_eq!(set.count(), model.len());
            for &(root, count) in &model {
                prop_assert_eq!(set.pin_count(root), count);
                prop_assert!(set.is_pinned(root));
            }
            for root in set.pinned_roots() {
                prop_assert!(model.iter().any(|(expected, _)| expected == root));
            }
        }
    }

    // -----------------------------------------------------------------------
    #[test]
    fn count_never_exceeds_capacity_n4(ops in op_strategy(4)) {
        let mut set = GcPinSet::<4>::new();
        for op in &ops {
            match *op {
                Op::Pin { rt, bp } => { let _ = set.pin(make_root(rt, bp)); }
                Op::Unpin { rt, bp } => { let _ = set.unpin(make_root(rt, bp)); }
            }
            prop_assert!(set.count() <= 4);
        }
    }

    // -----------------------------------------------------------------------
    #[test]
    fn is_pinned_agrees_with_tracker(ops in op_strategy(6)) {
        let mut set = GcPinSet::<6>::new();
        let mut model: Vec<(TraversalRoot, u32)> = Vec::new();

        for op in &ops {
            match *op {
                Op::Pin { rt, bp } => {
                    let root = make_root(rt, bp);
                    if model.len() < 6 || model_pos(&model, root).is_some() {
                        let _ = set.pin(root);
                        if let Some(idx) = model_pos(&model, root) {
                            model[idx].1 = model[idx].1.saturating_add(1);
                        } else {
                            model.push((root, 1));
                        }
                    }
                }
                Op::Unpin { rt, bp } => {
                    let root = make_root(rt, bp);
                    if let Some(idx) = model_pos(&model, root) {
                        let _ = set.unpin(root);
                        model[idx].1 -= 1;
                        if model[idx].1 == 0 {
                            model.remove(idx);
                        }
                    }
                }
            }
            for &(root, count) in &model {
                prop_assert_eq!(set.is_pinned(root), count > 0);
            }
            for root in set.pinned_roots() {
                prop_assert!(model.iter().any(|(expected, _)| expected == root));
            }
        }
    }

    // -----------------------------------------------------------------------
    // No duplicate slots: each exact root appears at most once.
    // -----------------------------------------------------------------------
    #[test]
    fn no_duplicate_roots_in_set(ops in op_strategy(6)) {
        let mut set = GcPinSet::<6>::new();
        for op in &ops {
            match *op {
                Op::Pin { rt, bp } => { let _ = set.pin(make_root(rt, bp)); }
                Op::Unpin { rt, bp } => { let _ = set.unpin(make_root(rt, bp)); }
            }
        }
        let mut seen = Vec::new();
        for root in set.pinned_roots() {
            prop_assert!(!seen.contains(root), "duplicate slot for {root:?}");
            seen.push(*root);
        }
    }

    // -----------------------------------------------------------------------
    #[test]
    fn validation_correctness(
        selected in proptest::collection::vec(root_type_strategy(), 0..7)
    ) {
        let mut set = GcPinSet::<6>::new();
        let mut reachable: Vec<TraversalRoot> = Vec::new();

        for (i, &rt) in selected.iter().enumerate() {
            let root = make_root(rt, i as u64);
            if set.pin(root).is_ok() {
                reachable.push(root);
            }
        }

        let validation = set.validate_mark_set(&reachable);
        let pinned_roots: Vec<TraversalRoot> = set.pinned_roots().copied().collect();
        let mut reachable_pinned = 0usize;
        for pinned in &pinned_roots {
            if reachable.iter().any(|r| r == pinned) {
                reachable_pinned += 1;
            }
        }
        prop_assert_eq!(validation.reachable_from_pins, reachable_pinned);
        prop_assert_eq!(
            validation.unreachable_pinned,
            set.count() - reachable_pinned
        );
        prop_assert_eq!(validation.pinned_total, set.count());
    }
}

// ---------------------------------------------------------------------------
// Deterministic edge cases
// ---------------------------------------------------------------------------

#[test]
fn deterministic_cycle_never_panics() {
    let mut set = GcPinSet::<6>::new();
    let roots: Vec<TraversalRoot> = ALL_TYPES
        .iter()
        .enumerate()
        .map(|(i, &rt)| make_root(rt, (i + 1) as u64))
        .collect();

    for root in &roots {
        set.pin(*root).unwrap();
    }
    assert_eq!(set.count(), 6);
    assert!(set.is_full());

    for root in roots.iter().rev() {
        set.unpin(*root).unwrap();
    }
    assert!(set.is_empty());
}

#[test]
fn rapid_pin_unpin_same_type() {
    let mut set = GcPinSet::<6>::new();
    let rt = TraversalRootType::InodeTable;
    for i in 0..1000 {
        let root = make_root(rt, i);
        set.pin(root).unwrap();
        assert!(set.is_pinned(root));
        set.unpin(root).unwrap();
        assert!(!set.is_pinned(root));
    }
    assert!(set.is_empty());
}

#[test]
fn rapid_multi_pin_same_type() {
    let mut set = GcPinSet::<6>::new();
    let rt = TraversalRootType::InodeTable;
    let root = make_root(rt, 1);
    // Pin 5 times, then unpin 5 times.
    for _ in 0..5 {
        set.pin(root).unwrap();
    }
    assert_eq!(set.count(), 1);
    assert_eq!(set.total_pins(), 5);
    assert_eq!(set.pin_count(root), 5);

    for _ in 0..5 {
        set.unpin(root).unwrap();
    }
    assert!(set.is_empty());
    assert_eq!(set.total_pins(), 0);
}
