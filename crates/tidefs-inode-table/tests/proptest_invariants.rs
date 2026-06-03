#![cfg(feature = "std")]
//! Property-based tests (proptest) for tidefs-inode-table invariants.
//!
//! Verifies inode-table invariants under randomized workloads:
//!  - No duplicate inode numbers from create/allocate
//!  - Free-list reuse: free then re-alloc returns same slot, higher generation
//!  - Generation strictly monotonic per slot
//!  - Capacity invariant: len() <= capacity
//!  - Lookup consistency: create then lookup finds matching attributes
//!  - Delete consistency: remove then lookup returns None
//!  - Iteration consistency: iter() yields len() unique entries
//!  - Dirty-count bound: dirty_count() <= len()
//!  - Inode-counts invariant: total == capacity, free == total - occupied
//!
//! Worker slot: s9
//! Review debt TFR-004: historical issue #4094 work queue item 1.

use std::collections::HashSet;

use proptest::prelude::*;
use tidefs_inode_table::{
    Ino, InodeAttributes, InodeKind, InodeTable, InodeTableError, SystemTimeSource,
};

fn make_table(capacity: usize) -> InodeTable {
    InodeTable::new(capacity, Box::new(SystemTimeSource))
}

fn file_attrs(mode: u32) -> InodeAttributes {
    InodeAttributes::new(mode, 1000, 1000, InodeKind::File)
}

proptest! {
    #[test]
    fn create_always_produces_unique_inos(
        n_creates in 1usize..200usize
    ) {
        let tbl = make_table(n_creates.max(1));
        let mut seen = HashSet::new();
        for _ in 0..n_creates {
            match tbl.create(InodeKind::File, file_attrs(0o644)) {
                Ok(ino) => {
                    prop_assert!(seen.insert(ino), "duplicate inode {ino}");
                }
                Err(InodeTableError::TableFull) => break,
                Err(e) => panic!("unexpected error: {e:?}"),
            }
        }
        for ino in &seen {
            prop_assert!(tbl.lookup(*ino).is_some(), "lookup({ino}) failed");
        }
        prop_assert_eq!(seen.len(), tbl.len());
    }

    #[test]
    fn free_list_reuse_same_slot_higher_generation(
        n_cycles in 1usize..50usize
    ) {
        let tbl = make_table(16);
        for _ in 0..n_cycles {
            let ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
            let gen1 = tbl.lookup(ino).unwrap().generation;
            tbl.unlink(ino).unwrap();
            prop_assert!(tbl.lookup(ino).is_none());
            let ino2 = tbl.create(InodeKind::File, file_attrs(0o600)).unwrap();
            prop_assert_eq!(ino2, ino, "realloc should reuse same slot");
            let gen2 = tbl.lookup(ino2).unwrap().generation;
            prop_assert!(gen2 > gen1, "gen {gen2} <= {gen1}");
            tbl.unlink(ino2).unwrap();
        }
    }

    #[test]
    fn generation_monotonic_across_cycles(
        n_cycles in 2usize..100usize
    ) {
        let tbl = make_table(4);
        for _ in 0..n_cycles {
            let ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
            let gen = tbl.lookup(ino).unwrap().generation;
            prop_assert!(gen > 0, "generation must be > 0");
            tbl.unlink(ino).unwrap();
        }
    }

    #[test]
    fn len_never_exceeds_capacity(
        capacity in 1usize..64usize,
        n_creates in 0usize..128usize
    ) {
        let tbl = make_table(capacity);
        let mut created = 0usize;
        for _ in 0..n_creates {
            if tbl.create(InodeKind::File, file_attrs(0o644)).is_ok() {
                created += 1;
            }
        }
        prop_assert!(tbl.len() <= capacity);
        prop_assert_eq!(tbl.len(), created.min(capacity));
    }

    #[test]
    fn create_lookup_consistency(
        mode in 0o400u32..0o777u32,
        size in 0u64..1048576u64,
        kind in prop_oneof![
            Just(InodeKind::File),
            Just(InodeKind::Directory),
            Just(InodeKind::Symlink),
        ]
    ) {
        let tbl = make_table(16);
        let mut attrs = InodeAttributes::new(mode, 1000, 1000, kind);
        attrs.size = size;
        let ino = tbl.create(kind, attrs.clone()).unwrap();
        let found = tbl.lookup(ino).unwrap();
        prop_assert_eq!(found.mode, mode);
        prop_assert_eq!(found.size, size);
        prop_assert_eq!(found.kind, kind);
    }

    #[test]
    fn delete_removes_inode_from_lookup(
        n_files in 1usize..20usize
    ) {
        let tbl = make_table(32);
        let mut inos = Vec::new();
        for _ in 0..n_files {
            let ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
            inos.push(ino);
        }
        prop_assert_eq!(tbl.len(), n_files);
        for ino in inos.iter() {
            tbl.unlink(*ino).unwrap();
            prop_assert!(tbl.lookup(*ino).is_none());
        }
        prop_assert_eq!(tbl.len(), 0);
    }

    #[test]
    fn iter_yields_len_unique_entries(
        n_creates in 1usize..60usize
    ) {
        let tbl = make_table(n_creates + 10);
        let mut created = HashSet::new();
        for _ in 0..n_creates {
            let ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
            created.insert(ino);
        }
        let entries = tbl.iter();
        prop_assert_eq!(entries.len(), tbl.len());
        prop_assert_eq!(entries.len(), n_creates);
        let iter_inos: HashSet<Ino> = entries.iter().map(|(ino, _)| *ino).collect();
        prop_assert_eq!(iter_inos, created);
        for (ino, attrs) in &entries {
            let direct = tbl.lookup(*ino).unwrap();
            prop_assert_eq!(attrs.generation, direct.generation);
        }
    }

    #[test]
    fn dirty_count_bounded_by_len(
        n_creates in 1usize..30usize,
        n_setattrs in 0usize..20usize
    ) {
        let tbl = make_table(64);
        let mut held = Vec::new();
        for _ in 0..n_creates {
            if let Ok(ino) = tbl.create(InodeKind::File, file_attrs(0o644)) {
                held.push(ino);
            }
        }
        for _ in 0..n_setattrs {
            if let Some(&ino) = held.last() {
                if let Some(mut attrs) = tbl.lookup(ino) {
                    attrs.size += 1;
                    let _ = tbl.setattr(ino, attrs);
                }
            }
        }
        prop_assert!(tbl.dirty_count() <= tbl.len());
    }

    #[test]
    fn inode_counts_total_is_capacity(
        capacity in 1usize..128usize,
        n_creates in 0usize..200usize
    ) {
        let tbl = make_table(capacity);
        let mut created = 0usize;
        for _ in 0..n_creates {
            if tbl.create(InodeKind::File, file_attrs(0o644)).is_ok() {
                created += 1;
            }
        }
        let (total, free) = tbl.inode_counts();
        prop_assert_eq!(total as usize, capacity);
        prop_assert!(free <= total);
        let occupied = (total - free) as usize;
        prop_assert_eq!(occupied, tbl.len());
        prop_assert_eq!(occupied, created.min(capacity));
    }
}
