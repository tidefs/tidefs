#![cfg(feature = "std")]
//! Integration tests for inode-table edge cases and boundaries.
//!
//! Covers sentinel semantics (Ino::ROOT, Ino::NONE), reserved-slot rejection,
//! extreme capacity values, attribute field boundary values (zero, max,
//! near-max), generation-wrapping cross-checks, full-vs-empty iteration,
//! InodeKind predicates, and timestamp boundaries.
//!
//! Uses the public [`InodeTable`] API with [`SystemTimeSource`].

use std::time::Duration;
use tidefs_inode_table::{
    Ino, InodeAttributes, InodeKind, InodeTable, InodeTableError, SystemTimeSource,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_table(capacity: usize) -> InodeTable {
    InodeTable::new(capacity, Box::new(SystemTimeSource))
}

fn file_attrs(mode: u32) -> InodeAttributes {
    InodeAttributes::new(mode, 1000, 1000, InodeKind::File)
}

fn dir_attrs(mode: u32) -> InodeAttributes {
    InodeAttributes::new(mode, 0, 0, InodeKind::Directory)
}

// 1. Ino::NONE reserved slot — cannot allocate, cannot look up

#[test]
fn ino_none_cannot_be_looked_up() {
    let tbl = make_table(16);
    // Slot 0 is reserved; lookup(Ino::NONE) returns None
    assert!(tbl.lookup(Ino::NONE).is_none());
    assert!(tbl.getattr(Ino::NONE).is_none());

    // validate_generation on Ino::NONE fails
    assert_eq!(
        tbl.validate_generation(Ino::NONE, 1),
        Err(InodeTableError::InodeNotFound)
    );
}

#[test]
fn ino_none_cannot_be_operated_on() {
    let tbl = make_table(16);

    // setattr on Ino::NONE must fail
    assert_eq!(
        tbl.setattr(Ino::NONE, file_attrs(0o644)),
        Err(InodeTableError::InodeNotFound)
    );

    // link/unlink on Ino::NONE must fail
    assert_eq!(tbl.link(Ino::NONE), Err(InodeTableError::InodeNotFound));
    assert_eq!(tbl.unlink(Ino::NONE), Err(InodeTableError::InodeNotFound));

    // remove/delete on Ino::NONE must fail
    assert_eq!(tbl.remove(Ino::NONE), Err(InodeTableError::InodeNotFound));
    assert_eq!(tbl.delete(Ino::NONE), Err(InodeTableError::InodeNotFound));
}

#[test]
fn ino_none_never_returned_by_create() {
    let tbl = make_table(16);
    for _ in 0..5 {
        let ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
        assert_ne!(ino, Ino::NONE);
        assert_ne!(ino.0, 0);
    }
}

// 2. Ino::ROOT semantics

#[test]
fn ino_root_is_constant_one() {
    assert_eq!(Ino::ROOT, Ino(1));
    assert_eq!(Ino::ROOT.0, 1);
}

#[test]
fn first_allocation_is_root() {
    let tbl = make_table(16);
    let ino = tbl.create(InodeKind::Directory, dir_attrs(0o755)).unwrap();
    assert_eq!(ino, Ino::ROOT);
}

#[test]
fn root_inode_not_special_after_free() {
    let tbl = make_table(16);

    // Allocate root
    let ino = tbl.create(InodeKind::Directory, dir_attrs(0o755)).unwrap();
    assert_eq!(ino, Ino::ROOT);

    // Free root: unlink (nlink 1->0) then delete
    tbl.unlink(ino).unwrap();
    tbl.delete(ino).unwrap();
    assert!(tbl.lookup(ino).is_none());

    // Next allocation reuses slot 1
    let reused = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    assert_eq!(reused.0, 1, "slot 1 should be reused after root freed");
    assert_ne!(
        tbl.lookup(reused).unwrap().generation,
        tbl.lookup(reused).unwrap().generation.saturating_sub(1)
    );
}

// 3. Extreme capacity values

#[test]
fn capacity_one_allows_single_inode() {
    let tbl = make_table(1);
    let ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    assert_eq!(ino, Ino::ROOT);
    assert_eq!(tbl.len(), 1);

    assert_eq!(
        tbl.create(InodeKind::File, file_attrs(0o644)),
        Err(InodeTableError::TableFull)
    );
}

#[test]
fn capacity_one_free_then_realloc() {
    let tbl = make_table(1);
    let ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    tbl.unlink(ino).unwrap(); // file auto-remove

    // Re-allocate the only slot
    let reused = tbl.create(InodeKind::Directory, dir_attrs(0o755)).unwrap();
    assert_eq!(reused.0, 1);
    assert_eq!(tbl.len(), 1);
}

#[test]
fn capacity_large_does_not_panic() {
    let tbl = make_table(100_000);
    assert_eq!(tbl.capacity(), 100_000);

    // Create a few inodes to ensure the table works at this size
    let ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    assert!(tbl.lookup(ino).is_some());
}

#[test]
fn capacity_prime_numbers() {
    // Test that non-power-of-2 capacities work correctly
    for cap in [3, 7, 13, 31, 127, 999, 10_007] {
        let tbl = make_table(cap);
        assert_eq!(tbl.capacity(), cap);
        for _ in 0..cap {
            tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
        }
        assert_eq!(tbl.len(), cap);
        assert_eq!(
            tbl.create(InodeKind::File, file_attrs(0o644)),
            Err(InodeTableError::TableFull)
        );
    }
}

// 3b. Zero capacity clamps to minimum (zero-inode table)
// ---------------------------------------------------------------------------

#[test]
fn capacity_zero_clamps_to_minimum_one() {
    // Passing capacity=0 is clamped to 1 internally (capacity.max(1)).
    let tbl = make_table(0);
    assert_eq!(tbl.capacity(), 1); // 0 clamped to minimum
    assert_eq!(tbl.len(), 0);
    assert!(tbl.is_empty());
    assert_eq!(tbl.inode_counts(), (1, 1)); // 1 slot, 0 used → 1 free

    // One allocation succeeds (due to clamped capacity)
    let ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    assert_eq!(ino, Ino::ROOT);
    assert_eq!(tbl.len(), 1);
    assert_eq!(tbl.inode_counts(), (1, 0)); // 1 slot, 1 used → 0 free

    // Second allocation fails: table is now full
    assert_eq!(
        tbl.create(InodeKind::File, file_attrs(0o755)),
        Err(InodeTableError::TableFull)
    );

    // Iteration on a single-slot table after alloc
    let entries = tbl.iter();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, ino);

    // Lookup on the allocated inode succeeds
    assert!(tbl.lookup(ino).is_some());
    // Lookup on Ino::NONE returns None
    assert!(tbl.lookup(Ino::NONE).is_none());

    // Validation with wrong generation fails
    assert_eq!(
        tbl.validate_generation(ino, 0),
        Err(InodeTableError::GenerationMismatch)
    );

    // Dirty count reflects the creation
    assert_eq!(tbl.dirty_count(), 1);
}

// 4. Attribute field boundary values

#[test]
fn attribute_zero_values_roundtrip() {
    let tbl = make_table(16);
    let ino = tbl.create(InodeKind::File, file_attrs(0)).unwrap();
    let stored = tbl.lookup(ino).unwrap();
    assert_eq!(stored.mode, 0);
    assert_eq!(stored.uid, 1000); // from helper
    assert_eq!(stored.gid, 1000);
    assert_eq!(stored.size, 0);
    assert_eq!(stored.blocks, 0);

    // Explicitly set all fields to zero
    let all_zero = InodeAttributes {
        mode: 0,
        uid: 0,
        gid: 0,
        size: 0,
        blocks: 0,
        atime: Duration::ZERO,
        mtime: Duration::ZERO,
        ctime: Duration::ZERO,
        nlink: 1, // setattr preserves generation but nlink=1 is legal
        generation: 0,
        kind: InodeKind::File,
        xattrs: std::collections::BTreeMap::new(),
        dirty_bits: 0,
        mutation_gen: 0,
    };
    tbl.setattr(ino, all_zero.clone()).unwrap();
    let reloaded = tbl.lookup(ino).unwrap();
    assert_eq!(reloaded.mode, 0);
    assert_eq!(reloaded.uid, 0);
    assert_eq!(reloaded.gid, 0);
    assert_eq!(reloaded.size, 0);
    assert_eq!(reloaded.blocks, 0);
    assert_eq!(reloaded.atime, Duration::ZERO);
    assert_eq!(reloaded.mtime, Duration::ZERO);
    assert_eq!(reloaded.ctime, Duration::ZERO);
    assert_eq!(reloaded.nlink, 1);
}

#[test]
fn attribute_max_values_roundtrip() {
    let tbl = make_table(16);
    let ino = tbl.create(InodeKind::File, file_attrs(0)).unwrap();

    let maxed = InodeAttributes {
        mode: u32::MAX,
        uid: u32::MAX,
        gid: u32::MAX,
        size: u64::MAX,
        blocks: u64::MAX,
        atime: Duration::new(u64::MAX, 999_999_999),
        mtime: Duration::new(u64::MAX, 999_999_999),
        ctime: Duration::new(u64::MAX, 999_999_999),
        nlink: u32::MAX,
        generation: 0,
        kind: InodeKind::Symlink,
        xattrs: std::collections::BTreeMap::new(),
        dirty_bits: 0,
        mutation_gen: 0,
    };
    tbl.setattr(ino, maxed.clone()).unwrap();
    let reloaded = tbl.lookup(ino).unwrap();
    assert_eq!(reloaded.mode, u32::MAX);
    assert_eq!(reloaded.uid, u32::MAX);
    assert_eq!(reloaded.gid, u32::MAX);
    assert_eq!(reloaded.size, u64::MAX);
    assert_eq!(reloaded.blocks, u64::MAX);
    assert_eq!(reloaded.atime, Duration::new(u64::MAX, 999_999_999));
    assert_eq!(reloaded.mtime, Duration::new(u64::MAX, 999_999_999));
    assert_eq!(reloaded.ctime, Duration::new(u64::MAX, 999_999_999));
    assert_eq!(reloaded.nlink, u32::MAX);
    assert_eq!(reloaded.kind, InodeKind::Symlink);
}

#[test]
fn attribute_nlink_zero_is_valid_for_directories() {
    let tbl = make_table(16);
    let ino = tbl.create(InodeKind::Directory, dir_attrs(0o755)).unwrap();

    tbl.unlink(ino).unwrap(); // nlink 1->0
    let attrs = tbl.lookup(ino).unwrap();
    assert_eq!(attrs.nlink, 0, "directory nlink can be 0");
    assert_eq!(attrs.kind, InodeKind::Directory);
}

#[test]
fn attribute_blocks_independent_of_size() {
    let tbl = make_table(16);
    let ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();

    let mut attrs = tbl.lookup(ino).unwrap();
    attrs.size = 1;
    attrs.blocks = 1_000_000;
    tbl.setattr(ino, attrs).unwrap();

    let stored = tbl.lookup(ino).unwrap();
    assert_eq!(stored.size, 1);
    assert_eq!(
        stored.blocks, 1_000_000,
        "blocks field is independent of size"
    );
}

// 5. Timestamp boundary behavior

#[test]
fn timestamps_are_set_on_create() {
    let tbl = make_table(16);
    let ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    let attrs = tbl.lookup(ino).unwrap();

    assert!(attrs.atime > Duration::ZERO, "atime should be set");
    assert!(attrs.mtime > Duration::ZERO, "mtime should be set");
    assert!(attrs.ctime > Duration::ZERO, "ctime should be set");
    assert_eq!(
        attrs.atime, attrs.mtime,
        "on create, atime and mtime should match"
    );
    assert_eq!(
        attrs.mtime, attrs.ctime,
        "on create, mtime and ctime should match"
    );
}

#[test]
fn timestamps_can_be_overwritten_via_setattr() {
    let tbl = make_table(16);
    let ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();

    let t1 = Duration::new(100, 0);
    let t2 = Duration::new(200, 0);
    let t3 = Duration::new(300, 0);

    let mut attrs = tbl.lookup(ino).unwrap();
    attrs.atime = t1;
    attrs.mtime = t2;
    attrs.ctime = t3;
    tbl.setattr(ino, attrs).unwrap();

    let stored = tbl.lookup(ino).unwrap();
    assert_eq!(stored.atime, t1);
    assert_eq!(stored.mtime, t2);
    assert_eq!(stored.ctime, t3);
}

#[test]
fn timestamps_can_be_zero() {
    let tbl = make_table(16);
    let ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();

    let mut attrs = tbl.lookup(ino).unwrap();
    attrs.atime = Duration::ZERO;
    attrs.mtime = Duration::ZERO;
    attrs.ctime = Duration::ZERO;
    tbl.setattr(ino, attrs).unwrap();

    let stored = tbl.lookup(ino).unwrap();
    assert_eq!(stored.atime, Duration::ZERO);
    assert_eq!(stored.mtime, Duration::ZERO);
    assert_eq!(stored.ctime, Duration::ZERO);
}

// 6. InodeKind predicate cross-check

#[test]
fn inode_kind_predicates_match_created_kind() {
    let tbl = make_table(16);

    let f_ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    let d_ino = tbl.create(InodeKind::Directory, dir_attrs(0o755)).unwrap();
    let s_ino = tbl
        .create(
            InodeKind::Symlink,
            InodeAttributes::new(0o777, 1000, 1000, InodeKind::Symlink),
        )
        .unwrap();

    let f = tbl.lookup(f_ino).unwrap();
    let d = tbl.lookup(d_ino).unwrap();
    let s = tbl.lookup(s_ino).unwrap();

    assert!(f.kind.is_file());
    assert!(!f.kind.is_dir());
    assert!(!f.kind.is_symlink());

    assert!(!d.kind.is_file());
    assert!(d.kind.is_dir());
    assert!(!d.kind.is_symlink());

    assert!(!s.kind.is_file());
    assert!(!s.kind.is_dir());
    assert!(s.kind.is_symlink());
}

// 7. Full vs empty iteration

#[test]
fn iter_on_full_table_returns_all_inodes() {
    let cap = 16;
    let tbl = make_table(cap);
    let mut created = Vec::new();

    for _ in 0..cap {
        created.push(tbl.create(InodeKind::File, file_attrs(0o644)).unwrap());
    }

    let snapshot = tbl.iter();
    assert_eq!(snapshot.len(), cap);
    assert_eq!(tbl.len(), cap);
    assert_eq!(tbl.count(), cap);

    // Every created inode appears exactly once
    let mut found = std::collections::HashSet::new();
    for (ino, _) in &snapshot {
        assert!(found.insert(ino.0), "duplicate ino in iter: {ino:?}");
        assert!(created.contains(ino));
    }
}

#[test]
fn iter_on_empty_table_returns_empty() {
    let tbl = make_table(16);
    assert!(tbl.iter().is_empty());
    assert_eq!(tbl.len(), 0);
    assert_eq!(tbl.count(), 0);
    assert!(tbl.is_empty());
}

#[test]
fn iter_on_partially_filled_table() {
    let tbl = make_table(64);

    // Create inos 1..20, delete 5..10
    let mut live = Vec::new();
    for _ in 0..20 {
        let ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
        live.push(ino);
    }

    for ino in live.iter().take(10).skip(5) {
        tbl.unlink(*ino).unwrap(); // file auto-remove
    }

    let snapshot = tbl.iter();
    assert_eq!(snapshot.len(), tbl.len());

    // Each live inode should appear exactly once
    let mut iter_inos: Vec<u64> = snapshot.iter().map(|(ino, _)| ino.0).collect();
    iter_inos.sort();
    let mut expected: Vec<u64> = (1..21).filter(|x| *x < 6 || *x >= 11).collect();
    expected.sort();
    assert_eq!(iter_inos, expected);
}

// 8. Generation field behavior at boundaries

#[test]
fn generation_starts_at_one_not_zero() {
    let tbl = make_table(16);
    let ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    assert!(
        tbl.lookup(ino).unwrap().generation >= 1,
        "generation should start at 1, not 0"
    );
}

#[test]
fn generation_is_monotonic() {
    let tbl = make_table(64);
    let mut last_gen = 0u64;

    for i in 0..5 {
        let ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
        let gen = tbl.lookup(ino).unwrap().generation;
        assert!(
            gen > last_gen,
            "generation not monotonic at iter {i}: {gen} <= {last_gen}"
        );
        last_gen = gen;
    }
}

#[test]
fn generation_zero_never_matches_live_inode() {
    let tbl = make_table(16);
    let ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    let real_gen = tbl.lookup(ino).unwrap().generation;
    assert!(real_gen > 0);

    // validate_generation with gen=0 must fail
    assert_eq!(
        tbl.validate_generation(ino, 0),
        Err(InodeTableError::GenerationMismatch)
    );

    // setattr_if_generation with gen=0 must fail
    assert_eq!(
        tbl.setattr_if_generation(ino, 0, file_attrs(0o755)),
        Err(InodeTableError::GenerationMismatch)
    );
}
#[test]
fn setattr_stores_generation_verbatim_including_zero() {
    let tbl = make_table(16);
    let ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();

    // setattr writes attributes verbatim — including generation=0.
    // The _if_generation variants preserve generation, plain setattr does not.
    let mut attrs = tbl.lookup(ino).unwrap();
    attrs.generation = 0;
    tbl.setattr(ino, attrs).unwrap();

    let stored = tbl.lookup(ino).unwrap();
    assert_eq!(
        stored.generation, 0,
        "plain setattr stores generation=0 verbatim"
    );
}

#[test]
fn inode_number_type_alias_works() {
    let ino: tidefs_inode_table::InodeNumber = Ino(42);
    assert_eq!(ino.0, 42);
}

// 10. Table operations on maximum-constrained table

#[test]
fn len_never_exceeds_capacity() {
    for cap in [1, 2, 3, 5, 10, 20] {
        let tbl = make_table(cap);
        for _ in 0..cap {
            tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
        }
        assert_eq!(tbl.len(), cap);
        assert!(!tbl.is_empty());

        // One more should fail
        assert_eq!(
            tbl.create(InodeKind::File, file_attrs(0o644)),
            Err(InodeTableError::TableFull)
        );
    }
}

#[test]
fn dirty_count_never_exceeds_len_or_capacity() {
    let cap = 32;
    let tbl = make_table(cap);

    for i in 0..cap {
        tbl.create(
            InodeKind::File,
            InodeAttributes::new(0o644, i as u32, 0, InodeKind::File),
        )
        .unwrap();
    }

    let dirty = tbl.dirty_count();
    let live = tbl.len();
    assert!(
        dirty <= live,
        "dirty_count {dirty} should not exceed len {live}"
    );
    assert!(
        dirty <= cap,
        "dirty_count {dirty} should not exceed capacity {cap}"
    );
}

#[test]
fn count_equals_len() {
    let tbl = make_table(32);
    assert_eq!(tbl.count(), tbl.len());

    tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    assert_eq!(tbl.count(), tbl.len());
    assert_eq!(tbl.count(), 1);

    for _ in 0..5 {
        tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    }
    assert_eq!(tbl.count(), tbl.len());
    assert_eq!(tbl.count(), 6);
}

// 11. Quick successive create+free on slot 0 (reserved) edge

#[test]
fn reserved_slot_zero_never_interferes() {
    let tbl = make_table(5);

    // Fill completely
    let mut inos = Vec::new();
    for _ in 0..5 {
        inos.push(tbl.create(InodeKind::File, file_attrs(0o644)).unwrap());
    }

    // None should be Ino(0)
    for ino in &inos {
        assert_ne!(ino.0, 0, "reserved slot 0 should never be returned");
    }
}

// 12. setattr_if_generation with stale generation on freed slot

#[test]
fn setattr_if_generation_fails_after_free_and_reuse() {
    let tbl = make_table(16);
    let ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    let old_gen = tbl.lookup(ino).unwrap().generation;

    // Free and reuse the slot
    tbl.unlink(ino).unwrap(); // file auto-remove
    let _reused = tbl.create(InodeKind::Directory, dir_attrs(0o755)).unwrap();

    // Old generation must be rejected
    assert_eq!(
        tbl.setattr_if_generation(ino, old_gen, file_attrs(0o755)),
        Err(InodeTableError::GenerationMismatch)
    );
}

// 13. Stress: rapid fill/empty cycles on small table

#[test]
fn rapid_fill_empty_cycles_small_table() {
    let cap = 4;
    let tbl = make_table(cap);

    for _cycle in 0..25 {
        // Fill
        let mut inos = Vec::new();
        for _ in 0..cap {
            inos.push(tbl.create(InodeKind::File, file_attrs(0o644)).unwrap());
        }
        assert_eq!(tbl.len(), cap);

        // Empty: unlink all (files auto-remove)
        for ino in &inos {
            tbl.unlink(*ino).unwrap();
        }
        assert_eq!(tbl.len(), 0);
        assert!(tbl.is_empty());
    }
}
