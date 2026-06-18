// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
// naming_edge_cases.rs — Edge-case tests for directory entry naming.
//
// Coverage rationale:
//   The dir-index accepts arbitrary byte sequences as entry names.
//   FUSE passes names from the kernel, which are null-terminated C strings
//   on the wire but may contain arbitrary bytes within the name length.
//   These tests validate:
//
//   (1) Maximum-length name (255 bytes per POSIX NAME_MAX) is accepted,
//       stored, and retrievable.
//   (2) Names with embedded null bytes (\x00) — the dir-index should
//       treat null bytes as data, not terminators, since name_len is
//       explicitly stored.  The FUSE dispatch layer is responsible for
//       rejecting null-byte names before they reach the dir-index.
//   (3) Unicode normalization: NFC and NFD forms of the same grapheme
//       cluster are treated as distinct names (byte-level comparison,
//       no Unicode normalization).
//   (4) Empty-string name insertion is accepted (dir-index does not
//       validate names; the FUSE dispatch layer does).
//   (5) Name with all-zero bytes.
//   (6) Name with high-bit bytes (0x80-0xFF).
//   (7) Name starting/ending with whitespace or control characters.
//   (8) Names differing only in case are treated as distinct.
//   (9) Mixed ASCII / non-ASCII names sort correctly.
//  (10) Single-byte name.
//  (11) Name that differs only by a trailing byte.
//  (12) Delete and re-insert of edge-case names.
//  (13) Hash-bucket correctness in BTree mode.
//  (14) Unicode boundary codepoints (replacement char, max codepoint).

use tidefs_dir_index::{DatasetDirPolicy, DirIndex, DirIterator, DirStorageKind};

fn test_policy() -> DatasetDirPolicy {
    DatasetDirPolicy {
        dir_micro_max_entries: 6,
        dir_micro_max_name_bytes: 512,
        dir_btree_downshift_entries: 3,
        dir_btree_downshift_name_bytes: 128,
    }
}

// (1) Maximum-length name (255 bytes)

#[test]
fn max_length_name_255_bytes() {
    let mut dir = DirIndex::new(1, test_policy());

    let name: Vec<u8> = (0..255u8).map(|b| b'A' + (b % 26)).collect();
    assert_eq!(name.len(), 255);

    dir.insert(&name, 42, 1, 0).unwrap();
    assert!(dir.contains(&name));
    let e = dir.lookup(&name).unwrap();
    assert_eq!(e.inode_id, 42);
    assert_eq!(e.name_len, 255);
    assert_eq!(e.name, name);
}

// (2) Name with embedded null bytes

#[test]
fn name_with_embedded_null_bytes_stored_verbatim() {
    let mut dir = DirIndex::new(1, test_policy());

    let name: Vec<u8> = vec![b'A', 0x00, b'B', 0x00, b'C'];
    dir.insert(&name, 100, 2, 1).unwrap();
    assert!(dir.contains(&name));

    let e = dir.lookup(&name).unwrap();
    assert_eq!(e.inode_id, 100);
    assert_eq!(e.name, name);

    // Lookup with truncated name (at first null) should NOT match
    let truncated: &[u8] = b"A";
    assert!(!dir.contains(truncated));
}

#[test]
fn name_all_null_bytes() {
    let mut dir = DirIndex::new(1, test_policy());

    let name: Vec<u8> = vec![0x00; 4];
    dir.insert(&name, 200, 0, 1).unwrap();
    assert!(dir.contains(&name));
    assert_eq!(dir.lookup(&name).unwrap().inode_id, 200);

    // Empty (zero-length) should NOT match
    assert!(!dir.contains(b""));
}

// (3) Unicode normalization: NFC vs NFD are distinct

#[test]
fn nfc_and_nfd_are_distinct_names() {
    let mut dir = DirIndex::new(1, test_policy());

    // 'e' with acute: NFC (single codepoint U+00E9) vs NFD (e + combining acute U+0301)
    let nfc: Vec<u8> = "\u{00E9}".as_bytes().to_vec();
    let nfd: Vec<u8> = "e\u{0301}".as_bytes().to_vec();

    assert_ne!(nfc, nfd, "NFC and NFD byte representations differ");

    dir.insert(&nfc, 1, 0, 1).unwrap();
    dir.insert(&nfd, 2, 0, 1).unwrap();

    assert_eq!(dir.len(), 2);
    assert_eq!(dir.lookup(&nfc).unwrap().inode_id, 1);
    assert_eq!(dir.lookup(&nfd).unwrap().inode_id, 2);
}

#[test]
fn unicode_multi_codepoint_names() {
    let mut dir = DirIndex::new(1, test_policy());

    let names: &[&[u8]] = &[
        "hello\u{4E16}\u{754C}".as_bytes(),            // hello + CJK
        "\u{1F30D}.txt".as_bytes(),                    // globe emoji U+1F30D
        "caf\u{00E9}".as_bytes(),                      // cafe with acute e
        "\u{03B3}\u{03B5}\u{03B9}\u{03B1}".as_bytes(), // Greek
        "\u{043F}\u{0440}\u{0438}\u{0432}\u{0435}\u{0442}".as_bytes(), // Cyrillic
        "\u{FFFD}".as_bytes(),                         // Replacement character
    ];

    for (i, name) in names.iter().enumerate() {
        dir.insert(name, i as u64, 0, 1).unwrap();
    }
    assert_eq!(dir.len(), names.len());

    for (i, name) in names.iter().enumerate() {
        let e = dir.lookup(name).unwrap();
        assert_eq!(e.inode_id, i as u64);
    }
}

// (4) Empty-string name

#[test]
fn empty_name_insert_accepted() {
    let mut dir = DirIndex::new(1, test_policy());
    let result = dir.insert(b"", 1, 0, 1);
    assert!(
        result.is_ok(),
        "empty name insert behaviour (may change if validation is added)"
    );
    assert!(dir.contains(b""));
}

// (5) Names with high-bit bytes (0x80-0xFF)

#[test]
fn names_with_high_bit_bytes() {
    let mut dir = DirIndex::new(1, test_policy());

    let name1: Vec<u8> = vec![0x80, 0x81, 0x82];
    let name2: Vec<u8> = vec![0xFE, 0xFF];
    let name3: Vec<u8> = vec![0x80];
    let name4: Vec<u8> = vec![0xFF, 0x00, 0xFF];
    let name5: Vec<u8> = vec![0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0];

    let names: &[&[u8]] = &[&name1, &name2, &name3, &name4, &name5];
    for (i, name) in names.iter().enumerate() {
        dir.insert(name, i as u64, 0, 1).unwrap();
    }
    assert_eq!(dir.len(), names.len());

    for (i, name) in names.iter().enumerate() {
        let e = dir.lookup(name).unwrap();
        assert_eq!(e.inode_id, i as u64);
    }
}

// (6) Names with whitespace and control characters

#[test]
fn names_with_whitespace_and_control_chars() {
    let mut dir = DirIndex::new(1, test_policy());

    let names: &[&[u8]] = &[
        b" leading_space",
        b"trailing_space ",
        b"\t\ttabbed",
        b"new\nline",
        b"carriage\rreturn",
        b"\x01\x02\x03",
        b" ",
        b"\t",
        b"mix ed\twhitespace\nchars",
    ];

    for (i, name) in names.iter().enumerate() {
        dir.insert(name, i as u64, 0, 1).unwrap();
    }
    assert_eq!(dir.len(), names.len());

    for (i, name) in names.iter().enumerate() {
        let e = dir.lookup(name).unwrap();
        assert_eq!(e.inode_id, i as u64);
    }
}

// (7) Case-sensitive names are distinct

#[test]
fn case_differences_are_distinct() {
    let mut dir = DirIndex::new(1, test_policy());

    dir.insert(b"File.txt", 1, 0, 1).unwrap();
    dir.insert(b"file.txt", 2, 0, 1).unwrap();
    dir.insert(b"FILE.TXT", 3, 0, 1).unwrap();

    assert_eq!(dir.len(), 3);
    assert_eq!(dir.lookup(b"File.txt").unwrap().inode_id, 1);
    assert_eq!(dir.lookup(b"file.txt").unwrap().inode_id, 2);
    assert_eq!(dir.lookup(b"FILE.TXT").unwrap().inode_id, 3);
}

// (8) Mixed ASCII / non-ASCII names sort order

#[test]
fn mixed_ascii_nonascii_iteration_order() {
    let mut dir = DirIndex::new(1, test_policy());

    // Insert in intentionally unsorted order
    dir.insert(b"zebra", 1, 0, 1).unwrap();
    dir.insert(b"alpha", 2, 0, 1).unwrap();
    dir.insert("\u{00E9}clair".as_bytes(), 3, 0, 1).unwrap();
    dir.insert(b"apple", 4, 0, 1).unwrap();
    dir.insert(b"ALPHA", 5, 0, 1).unwrap();
    dir.insert(b"0_start", 6, 0, 1).unwrap();

    let mut names: Vec<Vec<u8>> = Vec::new();
    while let Some(entry) = dir.next_entry() {
        names.push(entry.name);
    }
    assert_eq!(names.len(), 6);

    for w in names.windows(2) {
        assert!(w[0] <= w[1], "unsorted: {:?} > {:?}", w[0], w[1]);
    }

    // '0' < 'A' < 'a' < 'z' < high-bit bytes
    assert_eq!(names[0], b"0_start");
    assert_eq!(names[1], b"ALPHA");
    assert_eq!(names[2], b"alpha");
    assert_eq!(names[3], b"apple");
    assert_eq!(names[4], b"zebra");
    // e-acute starts with 0xC3, which sorts after 'z' (0x7A)
    assert_eq!(names[5], "\u{00E9}clair".as_bytes());
}

// (9) Single-byte name

#[test]
fn single_byte_name() {
    let mut dir = DirIndex::new(1, test_policy());

    dir.insert(b"a", 1, 0, 1).unwrap();
    dir.insert(b"A", 2, 0, 1).unwrap();
    dir.insert(b"\x00", 3, 0, 1).unwrap();
    dir.insert(b"\xFF", 4, 0, 1).unwrap();

    assert_eq!(dir.len(), 4);
    assert_eq!(dir.lookup(b"a").unwrap().inode_id, 1);
    assert_eq!(dir.lookup(b"A").unwrap().inode_id, 2);
    assert_eq!(dir.lookup(b"\x00").unwrap().inode_id, 3);
    assert_eq!(dir.lookup(b"\xFF").unwrap().inode_id, 4);
}

// (10) Names differing only by trailing byte

#[test]
fn names_diff_by_trailing_byte() {
    let mut dir = DirIndex::new(1, test_policy());

    dir.insert(b"file", 1, 0, 1).unwrap();
    dir.insert(b"file\x00", 2, 0, 1).unwrap();
    dir.insert(b"file\x01", 3, 0, 1).unwrap();
    dir.insert(b"file\xFF", 4, 0, 1).unwrap();

    assert_eq!(dir.len(), 4);
    assert_eq!(dir.lookup(b"file").unwrap().inode_id, 1);
    assert_eq!(dir.lookup(b"file\x00").unwrap().inode_id, 2);
    assert_eq!(dir.lookup(b"file\x01").unwrap().inode_id, 3);
    assert_eq!(dir.lookup(b"file\xFF").unwrap().inode_id, 4);
}

// (11) Delete and re-insert edge-case names

#[test]
fn delete_and_reinsert_edge_names() {
    let mut dir = DirIndex::new(1, test_policy());

    let evil_name: Vec<u8> = vec![0x00, 0xFF, 0x00, b'H', 0x00];

    dir.insert(&evil_name, 99, 1, 1).unwrap();
    assert!(dir.contains(&evil_name));

    dir.delete(&evil_name).unwrap();
    assert!(!dir.contains(&evil_name));
    assert_eq!(dir.len(), 0);

    dir.insert(&evil_name, 100, 2, 1).unwrap();
    let e = dir.lookup(&evil_name).unwrap();
    assert_eq!(e.inode_id, 100);
    assert_eq!(e.generation, 2);
}

// (12) Max-length name in BTree representation

#[test]
fn max_length_name_in_btree() {
    let mut dir = DirIndex::new(1, test_policy());

    let max_name: Vec<u8> = (0..255u8).map(|b| b'A' + (b % 26)).collect();

    // Force BTree by inserting enough entries
    for i in 0..10u64 {
        let pad = format!("pad_{i:03}").into_bytes();
        dir.insert(&pad, i, 0, 1).unwrap();
    }
    assert_eq!(dir.representation(), DirStorageKind::BTREE);

    dir.insert(&max_name, 42, 1, 0).unwrap();

    let e = dir.lookup(&max_name).unwrap();
    assert_eq!(e.inode_id, 42);
    assert_eq!(e.name_len, 255);
    assert_eq!(e.name, max_name);

    // Iterate and find it
    let mut found = false;
    while let Some(entry) = dir.next_entry() {
        if entry.name == max_name {
            found = true;
            assert_eq!(entry.inode_id, 42);
        }
    }
    assert!(found, "max-length name not found in BTree iteration");
}

// (13) Hash-bucket correctness in BTree mode
//
// FNV-1a is not collision-resistant.  The BTree bucket handles
// collisions via per-bucket entry vectors and full-name verification.
// NOTE: current BTree insert is O(n) per operation (collect+rebuild),
// so we test at a modest scale.  Full collision-stress testing at
// 100K+ scale depends on extent-map V3 multi-level BTree work.

#[test]
fn btree_hash_bucket_correctness() {
    let mut dir = DirIndex::new(1, test_policy());

    // Force BTree mode
    for i in 0..10u64 {
        let pad = format!("bt_pad_{i:03}").into_bytes();
        dir.insert(&pad, i, 0, 1).unwrap();
    }
    assert_eq!(dir.representation(), DirStorageKind::BTREE);

    // Insert entries that exercise per-bucket vectors
    let tricky_names: &[&[u8]] = &[
        b"file",
        b"file\x00",
        b"file\x01",
        b"file\xFF",
        b"file\x00\x00",
        b"file\xFF\xFF",
    ];
    for (i, name) in tricky_names.iter().enumerate() {
        dir.insert(name, 100 + i as u64, 0, 1).unwrap();
    }

    // All should be independently retrievable
    for (i, name) in tricky_names.iter().enumerate() {
        let e = dir.lookup(name).expect("should exist");
        assert_eq!(e.inode_id, 100 + i as u64);
    }
    assert_eq!(dir.len(), 10 + tricky_names.len());
}

// (14) Unicode boundary codepoints

#[test]
fn unicode_boundary_codepoints() {
    let mut dir = DirIndex::new(1, test_policy());

    // U+FFFD (replacement character)
    let replacement: Vec<u8> = "\u{FFFD}".as_bytes().to_vec();
    dir.insert(&replacement, 1, 0, 1).unwrap();

    // Lone surrogate half (invalid UTF-8 but valid byte sequence)
    let lone_surrogate: Vec<u8> = vec![0xED, 0xA0, 0x80];
    dir.insert(&lone_surrogate, 2, 0, 1).unwrap();

    // U+10FFFF (maximum codepoint, encoded as 4-byte UTF-8)
    let max_codepoint: Vec<u8> = "\u{10FFFF}".as_bytes().to_vec();
    dir.insert(&max_codepoint, 3, 0, 1).unwrap();

    assert_eq!(dir.len(), 3);
    assert_eq!(dir.lookup(&replacement).unwrap().inode_id, 1);
    assert_eq!(dir.lookup(&lone_surrogate).unwrap().inode_id, 2);
    assert_eq!(dir.lookup(&max_codepoint).unwrap().inode_id, 3);
}
