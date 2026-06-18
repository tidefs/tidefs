// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
// concurrent_readers.rs — Integration tests for multiple independent iterators
// operating on cloned DirIndex instances. Each clone has its own cursor state.
// Since DirIndex derives Clone, multiple readers can iterate independently
// from the same starting state.

use tidefs_dir_index::{DatasetDirPolicy, DirCookie, DirIndex, DirIterator, DirStorageKind};

fn test_policy() -> DatasetDirPolicy {
    DatasetDirPolicy {
        dir_micro_max_entries: 6,
        dir_micro_max_name_bytes: 512,
        dir_btree_downshift_entries: 3,
        dir_btree_downshift_name_bytes: 128,
    }
}

// ---------------------------------------------------------------------------
// Two cloned iterators with independent cursors
// ---------------------------------------------------------------------------

#[test]
fn two_iterators_independent_cursors() {
    let mut idx = DirIndex::new(1, test_policy());
    for i in 0..6u64 {
        let name = format!("ind_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    assert_eq!(idx.representation(), DirStorageKind::MICRO_LIST);

    let mut reader_a = idx.clone();
    let mut reader_b = idx.clone();

    // Reader A: start iterating
    let a1 = reader_a.next_entry().unwrap();
    assert_eq!(a1.name, b"ind_00");

    let a2 = reader_a.next_entry().unwrap();
    assert_eq!(a2.name, b"ind_01");

    // Reader B: independent, starts from beginning
    let b1 = reader_b.next_entry().unwrap();
    assert_eq!(b1.name, b"ind_00");

    // Reader A continues independently
    let a3 = reader_a.next_entry().unwrap();
    assert_eq!(a3.name, b"ind_02");

    // Reader B continues
    let b2 = reader_b.next_entry().unwrap();
    assert_eq!(b2.name, b"ind_01");

    // Reader A cursor != Reader B cursor
    assert_ne!(reader_a.current_cursor(), reader_b.current_cursor());
}

#[test]
fn two_iterators_one_exhausted_one_not() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"a", 1, 0, 1).unwrap();
    idx.insert(b"b", 2, 0, 1).unwrap();
    idx.insert(b"c", 3, 0, 1).unwrap();

    let mut reader_a = idx.clone();
    let mut reader_b = idx.clone();

    // Reader A exhausts
    while reader_a.next_entry().is_some() {}
    assert!(reader_a.next_entry().is_none());

    // Reader B still has entries
    assert!(reader_b.next_entry().is_some());
    assert!(reader_b.next_entry().is_some());
    assert!(reader_b.next_entry().is_some());
    assert!(reader_b.next_entry().is_none());
}

#[test]
fn two_iterators_different_reset_points() {
    let mut idx = DirIndex::new(1, test_policy());
    for i in 0..6u64 {
        let name = format!("res_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }

    let mut reader_a = idx.clone();
    let mut reader_b = idx.clone();

    // Both start, then A resets midway
    let _ = reader_a.next_entry().unwrap(); // res_00
    let _ = reader_a.next_entry().unwrap(); // res_01

    let _ = reader_b.next_entry().unwrap(); // res_00
    let _ = reader_b.next_entry().unwrap(); // res_01
    let _ = reader_b.next_entry().unwrap(); // res_02

    reader_a.reset_cursor();
    let a_restart = reader_a.next_entry().unwrap();
    assert_eq!(a_restart.name, b"res_00");

    // Reader B still has entries after reset of A
    let b_next = reader_b.next_entry().unwrap();
    assert_eq!(b_next.name, b"res_03");
}

#[test]
fn two_iterators_seek_to_different_positions() {
    let mut idx = DirIndex::new(1, test_policy());
    for i in 0..6u64 {
        let name = format!("seek_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }

    let mut reader_a = idx.clone();
    let mut reader_b = idx.clone();

    // Reader A: iterate to position 2, save cursor
    reader_a.next_entry().unwrap();
    reader_a.next_entry().unwrap();
    let saved_a = reader_a.current_cursor();

    // Reader B: iterate to position 4, save cursor
    for _ in 0..4 {
        reader_b.next_entry().unwrap();
    }
    let saved_b = reader_b.current_cursor();

    // Seek both and verify independent positions
    reader_a.seek_to_cursor(saved_a);
    reader_b.seek_to_cursor(saved_b);

    let a_next = reader_a.next_entry().unwrap();
    assert_eq!(a_next.name, b"seek_02");

    let b_next = reader_b.next_entry().unwrap();
    assert_eq!(b_next.name, b"seek_04");
}

// ---------------------------------------------------------------------------
// B-tree cloned iterators
// ---------------------------------------------------------------------------

#[test]
fn two_btree_iterators_independent() {
    let mut idx = DirIndex::new(1, test_policy());
    for i in 0..10u64 {
        let name = format!("bt_{i:03}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    assert_eq!(idx.representation(), DirStorageKind::BTREE);

    let mut reader_a = idx.clone();
    let mut reader_b = idx.clone();

    // A iterates halfway
    for _ in 0..5 {
        reader_a.next_entry().unwrap();
    }
    // B iterates fully
    let mut b_count = 0;
    while reader_b.next_entry().is_some() {
        b_count += 1;
    }
    assert_eq!(b_count, 10);

    // A still has 5 left
    let mut a_count = 0;
    while reader_a.next_entry().is_some() {
        a_count += 1;
    }
    assert_eq!(a_count, 5);
}

// ---------------------------------------------------------------------------
// Three concurrent readers
// ---------------------------------------------------------------------------

#[test]
fn three_iterators_staggered() {
    let mut idx = DirIndex::new(1, test_policy());
    for i in 0..10u64 {
        let name = format!("tri_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }

    let mut r1 = idx.clone();
    let mut r2 = idx.clone();
    let mut r3 = idx.clone();

    // r1: 3 entries
    for _ in 0..3 {
        r1.next_entry().unwrap();
    }
    // r2: 7 entries
    for _ in 0..7 {
        r2.next_entry().unwrap();
    }
    // r3: 1 entry
    r3.next_entry().unwrap();

    let e = r1.next_entry().unwrap();
    assert_eq!(e.name, b"tri_03");

    let e = r2.next_entry().unwrap();
    assert_eq!(e.name, b"tri_07");

    let e = r3.next_entry().unwrap();
    assert_eq!(e.name, b"tri_01");
}

// ---------------------------------------------------------------------------
// Clone mid-iteration and continue on both original and clone
// ---------------------------------------------------------------------------

#[test]
fn clone_mid_iteration_divergent_paths() {
    let mut idx = DirIndex::new(1, test_policy());
    for i in 0..6u64 {
        let name = format!("div_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }

    // Start iterating on idx itself
    idx.reset_cursor();
    let _ = idx.next_entry().unwrap(); // div_00
    let _ = idx.next_entry().unwrap(); // div_01

    // Clone mid-iteration
    let mut clone = idx.clone();

    // Original continues
    let o_next = idx.next_entry().unwrap();
    assert_eq!(o_next.name, b"div_02");

    // Clone also continues from same cursor position
    let c_next = clone.next_entry().unwrap();
    assert_eq!(c_next.name, b"div_02");

    // Both finish independently
    let mut o_remaining = Vec::new();
    while let Some(e) = idx.next_entry() {
        o_remaining.push(e.name);
    }
    let mut c_remaining = Vec::new();
    while let Some(e) = clone.next_entry() {
        c_remaining.push(e.name);
    }

    assert_eq!(o_remaining, c_remaining);
    assert_eq!(o_remaining.len(), 3); // div_03, div_04, div_05
}

// ---------------------------------------------------------------------------
// Reader isolation: mutations on original don't affect clones
// ---------------------------------------------------------------------------

#[test]
fn clone_before_mutation_isolated() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"a", 1, 0, 1).unwrap();
    idx.insert(b"b", 2, 0, 1).unwrap();
    idx.insert(b"c", 3, 0, 1).unwrap();

    let mut reader = idx.clone();

    // Mutate original
    idx.insert(b"d", 4, 0, 1).unwrap();
    idx.delete(b"b").unwrap();
    idx.replace(b"a", 99, 9, 9);

    // Reader cloned before mutations, should see original state
    let entries: Vec<Vec<u8>> = (0..)
        .map(|_| reader.next_entry())
        .take_while(|e| e.is_some())
        .map(|e| e.unwrap().name)
        .collect();

    assert_eq!(entries, vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
}

#[test]
fn clone_after_mutation_sees_mutated_state() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"a", 1, 0, 1).unwrap();
    idx.insert(b"b", 2, 0, 1).unwrap();

    // Mutate
    idx.insert(b"c", 3, 0, 1).unwrap();
    idx.delete(b"a").unwrap();

    let mut reader = idx.clone();
    let entries: Vec<Vec<u8>> = (0..)
        .map(|_| reader.next_entry())
        .take_while(|e| e.is_some())
        .map(|e| e.unwrap().name)
        .collect();

    assert_eq!(entries, vec![b"b".to_vec(), b"c".to_vec()]);
}

// ---------------------------------------------------------------------------
// Clone during B-tree representation
// ---------------------------------------------------------------------------

#[test]
fn clone_btree_iterator_independent_from_original() {
    let mut idx = DirIndex::new(1, test_policy());
    for i in 0..10u64 {
        let name = format!("btclone_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }
    assert_eq!(idx.representation(), DirStorageKind::BTREE);

    // Iterate halfway on original
    idx.reset_cursor();
    for _ in 0..5 {
        idx.next_entry().unwrap();
    }

    // Clone
    let mut reader = idx.clone();

    // Finish original
    let mut o_count = 0usize;
    while idx.next_entry().is_some() {
        o_count += 1;
    }
    assert_eq!(o_count, 5);

    // Reader independently finishes from halfway
    let mut r_count = 0usize;
    while reader.next_entry().is_some() {
        r_count += 1;
    }
    assert_eq!(r_count, 5);
}

// ---------------------------------------------------------------------------
// Multiple clones from same source all behave identically
// ---------------------------------------------------------------------------

#[test]
fn many_clones_identical_behavior() {
    let mut idx = DirIndex::new(1, test_policy());
    for i in 0..5u64 {
        let name = format!("many_{i:02}");
        idx.insert(name.as_bytes(), i, 0, 1).unwrap();
    }

    let clones: Vec<DirIndex> = (0..10).map(|_| idx.clone()).collect();

    for mut c in clones {
        c.reset_cursor();
        let e0 = c.next_entry().unwrap();
        assert_eq!(e0.name, b"many_00");

        let e1 = c.next_entry().unwrap();
        assert_eq!(e1.name, b"many_01");

        c.seek_to_cursor(DirCookie::START);
        let e0_again = c.next_entry().unwrap();
        assert_eq!(e0_again.name, b"many_00");

        // Exhaust
        while c.next_entry().is_some() {}
    }
}

// ---------------------------------------------------------------------------
// to_bytes/from_bytes preserves iterator state independence
// ---------------------------------------------------------------------------

#[test]
fn from_bytes_creates_independent_iterator() {
    let mut idx = DirIndex::new(1, test_policy());
    idx.insert(b"aaa", 1, 0, 1).unwrap();
    idx.insert(b"bbb", 2, 0, 1).unwrap();
    idx.insert(b"ccc", 3, 0, 1).unwrap();

    let bytes = idx.to_bytes();

    let mut r1 = DirIndex::from_bytes(&bytes, test_policy()).unwrap();
    let mut r2 = DirIndex::from_bytes(&bytes, test_policy()).unwrap();

    // r1 starts iterating
    let r1_first = r1.next_entry().unwrap();
    assert_eq!(r1_first.name, b"aaa");

    // r2 still at start
    assert_eq!(r2.current_cursor(), DirCookie::START);
    let r2_first = r2.next_entry().unwrap();
    assert_eq!(r2_first.name, b"aaa");

    // r1 continues
    let r1_second = r1.next_entry().unwrap();
    assert_eq!(r1_second.name, b"bbb");

    // r2 independently continues
    let r2_second = r2.next_entry().unwrap();
    assert_eq!(r2_second.name, b"bbb");
}
