// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Edge case validation tests.
//!
//! Exercises boundary conditions, error paths, and unusual inputs:
//! - zero/max timestamps (Unix epoch, far future)
//! - negative-size rejection via size field validation
//! - link-count overflow and underflow
//! - nlink=0 semantics
//! - concurrent attribute reads from multiple threads
//! - zero-initialized attributes

use std::sync::Arc;
use std::thread;

use tidefs_inode_attributes::{AttrError, InodeAttributeStore, MemInodeAttributeStore, SetAttr};
use tidefs_types_vfs_core::{
    InodeAttr, InodeFlags, InodeId, NodeKind, PosixAttrs, FATTR_ATIME, FATTR_CTIME, FATTR_MODE,
    FATTR_MTIME, FATTR_SIZE, S_IFREG,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn dummy_attrs(ino: u64) -> InodeAttr {
    InodeAttr {
        inode_id: InodeId(ino),
        generation: tidefs_types_vfs_core::Generation(1),
        kind: NodeKind::File,
        posix: PosixAttrs::new(
            S_IFREG | 0o644,
            1000,
            100,
            1,
            0,
            1_000_000_000,
            2_000_000_000,
            3_000_000_000,
            0,
            4096,
            8,
            4096,
        ),
        flags: InodeFlags::none(),
        subtree_rev: 0,
        dir_rev: 0,
    }
}

// ---------------------------------------------------------------------------
// Zero timestamps (Unix epoch)
// ---------------------------------------------------------------------------

#[test]
fn zero_atime_set_and_retrieved() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let mut set = SetAttr::new();
    set.valid = FATTR_ATIME;
    set.atime_ns = 0;
    let updated = store.setattr(1, &set).unwrap();
    assert_eq!(updated.posix.atime_ns, 0);

    let read = store.getattr(1).unwrap();
    assert_eq!(read.posix.atime_ns, 0);
}

#[test]
fn zero_mtime_set_and_retrieved() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let mut set = SetAttr::new();
    set.valid = FATTR_MTIME;
    set.mtime_ns = 0;
    let updated = store.setattr(1, &set).unwrap();
    assert_eq!(updated.posix.mtime_ns, 0);

    let read = store.getattr(1).unwrap();
    assert_eq!(read.posix.mtime_ns, 0);
}

#[test]
fn zero_ctime_set_and_retrieved() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let mut set = SetAttr::new();
    set.valid = FATTR_CTIME;
    set.ctime_ns = 0;
    let updated = store.setattr(1, &set).unwrap();
    assert_eq!(updated.posix.ctime_ns, 0);

    let read = store.getattr(1).unwrap();
    assert_eq!(read.posix.ctime_ns, 0);
}

// ---------------------------------------------------------------------------
// Maximum i64 timestamps
// ---------------------------------------------------------------------------

#[test]
fn max_i64_atime_set_and_retrieved() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let ts = i64::MAX;
    let mut set = SetAttr::new();
    set.valid = FATTR_ATIME;
    set.atime_ns = ts;
    let updated = store.setattr(1, &set).unwrap();
    assert_eq!(updated.posix.atime_ns, ts);

    let read = store.getattr(1).unwrap();
    assert_eq!(read.posix.atime_ns, ts);
}

#[test]
fn max_i64_mtime_set_and_retrieved() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let ts = i64::MAX;
    let mut set = SetAttr::new();
    set.valid = FATTR_MTIME;
    set.mtime_ns = ts;
    let updated = store.setattr(1, &set).unwrap();
    assert_eq!(updated.posix.mtime_ns, ts);

    let read = store.getattr(1).unwrap();
    assert_eq!(read.posix.mtime_ns, ts);
}

// ---------------------------------------------------------------------------
// Size edge cases
// ---------------------------------------------------------------------------

#[test]
fn size_zero_blocks_512_zero() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let mut set = SetAttr::new();
    set.valid = FATTR_SIZE;
    set.size = 0;
    let updated = store.setattr(1, &set).unwrap();
    assert_eq!(updated.posix.size, 0);
    assert_eq!(updated.posix.blocks_512, 0);
}

#[test]
fn size_under_512_blocks_one() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let mut set = SetAttr::new();
    set.valid = FATTR_SIZE;
    set.size = 1;
    let updated = store.setattr(1, &set).unwrap();
    assert_eq!(updated.posix.size, 1);
    assert_eq!(updated.posix.blocks_512, 1);
}

#[test]
fn size_exactly_512_blocks_one() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let mut set = SetAttr::new();
    set.valid = FATTR_SIZE;
    set.size = 512;
    let updated = store.setattr(1, &set).unwrap();
    assert_eq!(updated.posix.size, 512);
    assert_eq!(updated.posix.blocks_512, 1);
}

#[test]
fn size_513_blocks_two() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let mut set = SetAttr::new();
    set.valid = FATTR_SIZE;
    set.size = 513;
    let updated = store.setattr(1, &set).unwrap();
    assert_eq!(updated.posix.size, 513);
    assert_eq!(updated.posix.blocks_512, 2);
}

#[test]
fn size_max_u64() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let mut set = SetAttr::new();
    set.valid = FATTR_SIZE;
    set.size = u64::MAX;
    let updated = store.setattr(1, &set).unwrap();
    assert_eq!(updated.posix.size, u64::MAX);
    assert!(updated.posix.blocks_512 > 0);
}

// ---------------------------------------------------------------------------
// Link-count overflow and underflow
// ---------------------------------------------------------------------------

#[test]
fn drop_link_on_zero_nlink_returns_link_underflow() {
    let store = MemInodeAttributeStore::new();
    let mut a = dummy_attrs(1);
    a.posix.nlink = 0;
    store.insert(1, a);
    assert_eq!(store.drop_link(1), Err(AttrError::LinkUnderflow));
}

#[test]
fn drop_link_on_nonexistent_inode() {
    let store = MemInodeAttributeStore::new();
    assert_eq!(store.drop_link(999), Err(AttrError::InoNotFound));
}

#[test]
fn bump_link_on_nonexistent_inode() {
    let store = MemInodeAttributeStore::new();
    assert_eq!(store.bump_link(999), Err(AttrError::InoNotFound));
}

#[test]
fn bump_link_from_zero_reaches_one() {
    let store = MemInodeAttributeStore::new();
    let mut a = dummy_attrs(1);
    a.posix.nlink = 0;
    store.insert(1, a);
    assert_eq!(store.bump_link(1).unwrap(), 1);
    assert_eq!(store.getattr(1).unwrap().posix.nlink, 1);
}

#[test]
fn bump_link_high_value_does_not_panic() {
    let store = MemInodeAttributeStore::new();
    let mut a = dummy_attrs(1);
    a.posix.nlink = u32::MAX - 1;
    store.insert(1, a);
    // bump_link checks LINK_MAX (65000); MAX-1 exceeds it.
    let result = store.bump_link(1);
    assert_eq!(result, Err(AttrError::LinkOverflow));
}

// ---------------------------------------------------------------------------
// nlink=0 semantics (ino has zero links but still exists)
// ---------------------------------------------------------------------------

#[test]
fn nlink_zero_inode_can_still_get_attributes() {
    let store = MemInodeAttributeStore::new();
    let mut a = dummy_attrs(1);
    a.posix.nlink = 0;
    store.insert(1, a);
    let attr = store.getattr(1).unwrap();
    assert_eq!(attr.posix.nlink, 0);
}

#[test]
fn nlink_zero_inode_can_still_set_attributes() {
    let store = MemInodeAttributeStore::new();
    let mut a = dummy_attrs(1);
    a.posix.nlink = 0;
    store.insert(1, a);

    let mut set = SetAttr::new();
    set.valid = FATTR_SIZE;
    set.size = 100;
    let updated = store.setattr(1, &set).unwrap();
    assert_eq!(updated.posix.size, 100);
    assert_eq!(updated.posix.nlink, 0);
}

// ---------------------------------------------------------------------------
// Concurrent reads: independent attribute reads don't interfere
// ---------------------------------------------------------------------------

#[test]
fn concurrent_reads_all_see_same_attribute_state() {
    let store = Arc::new(MemInodeAttributeStore::new());
    store.insert(1, dummy_attrs(1));

    let reader_count = 8;
    let barrier = Arc::new(std::sync::Barrier::new(reader_count));
    let mut handles = Vec::new();

    for _ in 0..reader_count {
        let s = Arc::clone(&store);
        let b = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            b.wait();
            let attr = s.getattr(1).unwrap();
            attr.posix.nlink == 1 && attr.posix.uid == 1000 && attr.posix.gid == 100
        }));
    }

    for h in handles {
        assert!(
            h.join().unwrap(),
            "all concurrent readers saw consistent state"
        );
    }
}

#[test]
fn concurrent_reads_during_write_see_either_old_or_new_state() {
    let store = Arc::new(MemInodeAttributeStore::new());
    store.insert(1, dummy_attrs(1));

    let barrier = Arc::new(std::sync::Barrier::new(6));
    let writer_go = Arc::new(std::sync::Barrier::new(2));

    // Writer thread
    let s_w = Arc::clone(&store);
    let wg = Arc::clone(&writer_go);
    let handle_w = thread::spawn(move || {
        wg.wait(); // Wait for signal
        let mut set = SetAttr::new();
        set.valid = FATTR_MODE;
        set.mode = 0o700;
        s_w.setattr(1, &set).unwrap();
    });

    // Reader threads
    let mut read_handles = Vec::new();
    for _ in 0..6 {
        let s = Arc::clone(&store);
        let b = Arc::clone(&barrier);
        read_handles.push(thread::spawn(move || {
            b.wait();
            // Read multiple times to try to catch both states
            let mut modes = Vec::new();
            for _ in 0..100 {
                modes.push(s.getattr(1).unwrap().posix.mode & !S_IFREG);
            }
            modes
        }));
    }

    // Signal writer
    writer_go.wait();

    for h in read_handles {
        let modes = h.join().unwrap();
        // Every read should see either the original mode or the updated mode
        for m in modes {
            assert!(
                m == 0o644 || m == 0o700,
                "concurrent read saw torn write: mode=0o{m:o}"
            );
        }
    }

    handle_w.join().unwrap();

    // After write completes, all reads should see the updated value
    let final_mode = store.getattr(1).unwrap().posix.mode & !S_IFREG;
    assert_eq!(final_mode, 0o700);
}

// ---------------------------------------------------------------------------
// Error code mapping
// ---------------------------------------------------------------------------

#[test]
fn attr_error_display_and_debug() {
    assert_eq!(format!("{}", AttrError::InoNotFound), "inode not found");
    assert_eq!(
        format!("{}", AttrError::LinkUnderflow),
        "link count underflow"
    );
}

#[test]
fn attr_error_raw_os_error() {
    assert_eq!(AttrError::InoNotFound.raw_os_error(), libc::ENOENT);
    assert_eq!(AttrError::LinkUnderflow.raw_os_error(), libc::ENOLINK);
}

// ---------------------------------------------------------------------------
// MemInodeAttributeStore insert / remove / len
// ---------------------------------------------------------------------------

#[test]
fn mem_store_insert_then_get() {
    let store = MemInodeAttributeStore::new();
    store.insert(42, dummy_attrs(42));
    let a = store.getattr(42).unwrap();
    assert_eq!(a.inode_id, InodeId(42));
    assert_eq!(a.posix.uid, 1000);
}

#[test]
fn mem_store_insert_overwrites() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let mut a2 = dummy_attrs(1);
    a2.posix.uid = 999;
    store.insert(1, a2);

    let a = store.getattr(1).unwrap();
    assert_eq!(a.posix.uid, 999);
}

#[test]
fn mem_store_remove_returns_attrs() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));
    let removed = store.remove(1);
    assert!(removed.is_some());
    assert_eq!(removed.unwrap().inode_id, InodeId(1));
    assert!(store.getattr(1).is_err());
}

#[test]
fn mem_store_remove_nonexistent_returns_none() {
    let store = MemInodeAttributeStore::new();
    assert!(store.remove(42).is_none());
}

#[test]
fn mem_store_len_tracks_inserts_and_removes() {
    let store = MemInodeAttributeStore::new();
    assert_eq!(store.len(), 0);
    assert!(store.is_empty());

    store.insert(1, dummy_attrs(1));
    assert_eq!(store.len(), 1);
    assert!(!store.is_empty());

    store.insert(2, dummy_attrs(2));
    assert_eq!(store.len(), 2);

    store.remove(1);
    assert_eq!(store.len(), 1);

    store.remove(2);
    assert_eq!(store.len(), 0);
    assert!(store.is_empty());
}

// ---------------------------------------------------------------------------
// InodeFlags round-trip (immutable, append_only, noatime, nodump)
// ---------------------------------------------------------------------------

#[test]
fn flags_roundtrip_immutable() {
    let store = MemInodeAttributeStore::new();
    let mut a = dummy_attrs(1);
    a.flags = InodeFlags::new(true, false, false, false);
    store.insert(1, a);

    let read = store.getattr(1).unwrap();
    assert!(read.flags.immutable);
    assert!(!read.flags.append_only);
}

#[test]
fn flags_roundtrip_append_only() {
    let store = MemInodeAttributeStore::new();
    let mut a = dummy_attrs(1);
    a.flags = InodeFlags::new(false, true, false, false);
    store.insert(1, a);

    let read = store.getattr(1).unwrap();
    assert!(!read.flags.immutable);
    assert!(read.flags.append_only);
}

#[test]
fn flags_all_set_roundtrip() {
    let store = MemInodeAttributeStore::new();
    let mut a = dummy_attrs(1);
    a.flags = InodeFlags::new(true, true, true, true);
    store.insert(1, a);

    let read = store.getattr(1).unwrap();
    assert!(read.flags.immutable);
    assert!(read.flags.append_only);
    assert!(read.flags.noatime);
    assert!(read.flags.nodump);
}

#[test]
fn flags_none_roundtrip() {
    let store = MemInodeAttributeStore::new();
    store.insert(1, dummy_attrs(1));

    let read = store.getattr(1).unwrap();
    assert!(!read.flags.immutable);
    assert!(!read.flags.append_only);
    assert!(!read.flags.noatime);
    assert!(!read.flags.nodump);
}

// ---------------------------------------------------------------------------
// Concurrent insert/read stress
// ---------------------------------------------------------------------------

#[test]
fn concurrent_insert_and_read_independent_inodes() {
    let store = Arc::new(MemInodeAttributeStore::new());

    // Pre-insert inodes 1-4
    for i in 1..=4u64 {
        store.insert(i, dummy_attrs(i));
    }

    let barrier = Arc::new(std::sync::Barrier::new(4));
    let mut handles = Vec::new();

    // Two readers, two writers
    for t in 0..4 {
        let s = Arc::clone(&store);
        let b = Arc::clone(&barrier);
        if t < 2 {
            // Reader
            handles.push(thread::spawn(move || {
                b.wait();
                for _ in 0..50 {
                    for i in 1..=4u64 {
                        let a = s.getattr(i).unwrap();
                        assert_eq!(a.inode_id, InodeId(i));
                    }
                }
            }));
        } else {
            // Writer (insert new inodes)
            handles.push(thread::spawn(move || {
                b.wait();
                for i in 100..150u64 {
                    s.insert(i, dummy_attrs(i));
                }
            }));
        }
    }

    for h in handles {
        h.join().unwrap();
    }

    // All inodes should still be readable
    for i in 1..=4u64 {
        assert!(store.getattr(i).is_ok(), "inode {i} should exist");
    }
    for i in 100..150u64 {
        assert!(store.getattr(i).is_ok(), "inode {i} should exist");
    }
}
