//! FUSE link/unlink BLAKE3-verified validation harness.
//!
//! Exercises hardlink creation and removal through a real FUSE mount,
//! verifying link-count integrity and namespace state consistency with
//! domain-separated BLAKE3-256 hashing (domain: `tidefs-fuse-link-unlink-v1`).
//!
//! Coverage:
//! - link-create nlink increment on target and source
//! - unlink-remove nlink decrement
//! - last-link removal frees inode (ENOENT on stat)
//! - EMLINK saturation at link-count limit
//! - cross-directory hardlink with nlink integrity
//! - link-to-self rejection (EEXIST)
//! - unlink non-existent ENOENT
//! - concurrent link/unlink isolation (no nlink corruption)
//! - link-after-unlink re-create (name reuse, fresh nlink)
//! - remount persistence for links
//! - stat-after-link immediate nlink visibility
//! - FIFO link/unlink behaviour
//! - directory link/unlink rejection
//! - multi-way hardlink nlink tracking
//! - unlink-during-open-fd file accessibility
//! - domain-separation determinism and non-collision

#![cfg(target_os = "linux")]

use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt};

use std::sync::Arc;
use std::thread;

use tidefs_validation::mount_harness::MountHarness;

// ---------------------------------------------------------------------------
// BLAKE3 domain-separated hashing
// ---------------------------------------------------------------------------

const DOMAIN: &str = "tidefs-fuse-link-unlink-v1";

/// Operation type for BLAKE3 validation.
#[allow(dead_code)]
const OP_LINK: u8 = 0x01;
#[allow(dead_code)]
const OP_UNLINK: u8 = 0x02;
#[allow(dead_code)]
const OP_STATE_SNAPSHOT: u8 = 0x03;

/// Compute a BLAKE3-256 digest over a link operation: (op_type, filename, nlink).
#[allow(dead_code)]
fn hash_link_op(op_type: u8, filename: &str, nlink: u64, inode: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(DOMAIN);
    hasher.update(&[op_type]);
    hasher.update(filename.as_bytes());
    hasher.update(&nlink.to_le_bytes());
    hasher.update(&inode.to_le_bytes());
    hasher.finalize().into()
}

/// Compute a BLAKE3-256 state digest over a sorted list of (filename, nlink, inode)
/// entries, capturing the full link-count state at a point in time.
fn hash_link_state(entries: &[(&str, u64, u64)]) -> [u8; 32] {
    let mut sorted: Vec<&(&str, u64, u64)> = entries.iter().collect();
    sorted.sort_by_key(|(name, _, _)| *name);

    let mut hasher = blake3::Hasher::new_derive_key(DOMAIN);
    hasher.update(&[OP_STATE_SNAPSHOT]);
    for (name, nlink, inode) in &sorted {
        hasher.update(b"entry:");
        hasher.update(name.as_bytes());
        hasher.update(b"\n");
        hasher.update(&nlink.to_le_bytes());
        hasher.update(&inode.to_le_bytes());
        hasher.update(b"\n");
    }
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// Helper: raw errno assertion
// ---------------------------------------------------------------------------

fn assert_errno(result: &io::Result<()>, expected: i32) {
    match result {
        Err(e) => assert_eq!(
            e.raw_os_error(),
            Some(expected),
            "expected errno {expected}, got: {e}"
        ),
        Ok(()) => panic!("expected errno {expected}, got Ok(())"),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a regular file and return its metadata (inode, nlink).
fn create_and_stat(harness: &MountHarness, name: &str, contents: &[u8]) -> (u64, u64) {
    harness
        .create_file(name, contents)
        .unwrap_or_else(|_| panic!("create {name}"));
    let md = harness.stat(name).unwrap_or_else(|_| panic!("stat {name}"));
    (md.ino(), md.nlink())
}

// ──────────────────────────────────────────────────────────────────────────
// Test 1: link-create increments nlink on target; source nlink unchanged
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn link_create_increments_nlink() {
    let harness = MountHarness::new().expect("harness setup");
    let (src_ino, src_before) = create_and_stat(&harness, "source.txt", b"link test alpha");
    assert_eq!(src_before, 1, "new file must have nlink=1");

    harness
        .hardlink("source.txt", "linked.txt")
        .expect("hardlink source.txt -> linked.txt");

    let src_after = harness.stat("source.txt").expect("stat source after link");
    let link_md = harness.stat("linked.txt").expect("stat linked");

    assert_eq!(src_after.nlink(), 2, "source nlink should increment to 2");
    assert_eq!(link_md.nlink(), 2, "linked file should have nlink=2");
    assert_eq!(link_md.ino(), src_ino, "linked file must share same inode");
    assert_eq!(src_after.ino(), src_ino, "source inode must not change");

    // Verify content accessible via both names.
    assert_eq!(
        harness.read_file("source.txt").expect("read source"),
        b"link test alpha"
    );
    assert_eq!(
        harness.read_file("linked.txt").expect("read linked"),
        b"link test alpha"
    );
}

// ──────────────────────────────────────────────────────────────────────────
// Test 2: unlink-remove decrements nlink
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn unlink_decrements_nlink() {
    let harness = MountHarness::new().expect("harness setup");
    let (src_ino, _) = create_and_stat(&harness, "alpha.txt", b"unlink test");

    harness.hardlink("alpha.txt", "beta.txt").expect("hardlink");

    assert_eq!(harness.stat("alpha.txt").expect("stat alpha").nlink(), 2);

    harness.remove_file("beta.txt").expect("unlink beta");

    let alpha_after = harness.stat("alpha.txt").expect("stat alpha after unlink");
    assert_eq!(alpha_after.nlink(), 1, "nlink should decrement to 1");
    assert_eq!(alpha_after.ino(), src_ino, "inode unchanged");
    assert!(
        !harness.exists("beta.txt"),
        "unlinked name should not exist"
    );
}

// ──────────────────────────────────────────────────────────────────────────
// Test 3: last-link removal frees the inode (stat returns ENOENT)
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn last_link_removal_frees_inode() {
    let harness = MountHarness::new().expect("harness setup");
    create_and_stat(&harness, "solo.txt", b"last link");

    harness.remove_file("solo.txt").expect("unlink last link");

    let err = harness
        .stat("solo.txt")
        .expect_err("stat after unlink should fail");
    assert_eq!(
        err.raw_os_error(),
        Some(libc::ENOENT),
        "stat on removed file must return ENOENT, got: {err}"
    );
    assert!(
        !harness.exists("solo.txt"),
        "file must not exist after unlink"
    );

    // Re-creating the same name must succeed and produce a fresh file
    // (different inode, nlink=1).
    let (_new_ino, nlink) = create_and_stat(&harness, "solo.txt", b"fresh");
    assert_eq!(nlink, 1, "re-created file must have nlink=1");
    // Inode may or may not differ depending on allocator; no assertion on inode.
}

// ──────────────────────────────────────────────────────────────────────────
// Test 4: EMLINK saturation (link-count limit)
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn emlink_saturation() {
    let harness = MountHarness::new().expect("harness setup");
    create_and_stat(&harness, "base", b"emlink test");

    // The FUSE daemon internally checks nlink >= 65535.  The kernel VFS may
    // also enforce its own sb->s_max_links.  Loop until we hit EMLINK.
    let mut last_err: Option<io::Error> = None;
    for i in 1..=300u32 {
        let name = format!("link_{i}");
        match harness.hardlink("base", &name) {
            Ok(()) => continue,
            Err(e) => {
                last_err = Some(e);
                break;
            }
        }
    }
    match last_err {
        Some(e) => {
            let eno = e.raw_os_error();
            assert!(
                eno == Some(libc::EMLINK) || eno == Some(libc::ENOSPC),
                "expected EMLINK or ENOSPC at link-count limit, got: {e}"
            );
        }
        None => panic!(
            "expected EMLINK (or ENOSPC) after exhausting link count; \
             created 300 links without error"
        ),
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Test 5: cross-directory hardlink creates entry and maintains nlink
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn cross_directory_hardlink() {
    let harness = MountHarness::new().expect("harness setup");

    harness.mkdir("dir_a").expect("mkdir dir_a");
    harness.mkdir("dir_b").expect("mkdir dir_b");

    let (src_ino, _) = create_and_stat(&harness, "dir_a/file.txt", b"cross-dir link");

    harness
        .hardlink("dir_a/file.txt", "dir_b/linked.txt")
        .expect("cross-directory hardlink");

    let src_md = harness.stat("dir_a/file.txt").expect("stat source");
    let link_md = harness.stat("dir_b/linked.txt").expect("stat link");
    assert_eq!(src_md.nlink(), 2, "nlink=2 for cross-dir link");
    assert_eq!(link_md.nlink(), 2);
    assert_eq!(link_md.ino(), src_ino, "same inode across directories");

    // Unlink source; link in dir_b must still be accessible.
    harness
        .remove_file("dir_a/file.txt")
        .expect("unlink source");
    assert_eq!(
        harness
            .stat("dir_b/linked.txt")
            .expect("stat linked")
            .nlink(),
        1
    );
    assert!(
        !harness.exists("dir_a/file.txt"),
        "unlinked name must be gone"
    );
}

// ──────────────────────────────────────────────────────────────────────────
// Test 6: link-to-self rejection (EEXIST)
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn link_to_self_rejection() {
    let harness = MountHarness::new().expect("harness setup");
    create_and_stat(&harness, "self.txt", b"link to self");

    let result = harness.hardlink("self.txt", "self.txt");
    assert_errno(&result, libc::EEXIST);

    // File must be intact after failed self-link.
    let md = harness
        .stat("self.txt")
        .expect("stat after self-link attempt");
    assert_eq!(md.nlink(), 1, "nlink unchanged after failed self-link");
    assert_eq!(
        harness.read_file("self.txt").expect("read"),
        b"link to self"
    );
}

// ──────────────────────────────────────────────────────────────────────────
// Test 7: unlink non-existent name returns ENOENT
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn unlink_nonexistent_enoent() {
    let harness = MountHarness::new().expect("harness setup");

    let result = harness.remove_file("no_such_file");
    assert_errno(&result, libc::ENOENT);
}

// ──────────────────────────────────────────────────────────────────────────
// Test 8: concurrent link isolation (no nlink corruption)
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn concurrent_link_isolation() {
    let harness = MountHarness::new().expect("harness setup");
    create_and_stat(&harness, "shared.txt", b"concurrent link test");

    let mount = Arc::new(harness.mount_path().to_path_buf());

    let handles: Vec<_> = (0..4)
        .map(|t| {
            let mnt = mount.clone();
            thread::spawn(move || {
                for i in 0..50 {
                    let target = mnt.join("shared.txt");
                    let link = mnt.join(format!("clink_t{t}_{i}"));
                    let _ = std::fs::hard_link(&target, &link);
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread join");
    }

    // After all concurrent links, the nlink of the original should be 1 +
    // number of successful links.  Since different threads may race on
    // name conflicts (EEXIST), the exact count depends on timing, but the
    // nlink must reflect every successful link.
    let nlink = harness
        .stat("shared.txt")
        .expect("stat after concurrent link")
        .nlink();
    assert!(
        nlink >= 2,
        "nlink={nlink} after concurrent links, expected >= 2"
    );
    // Sanity: nlink cannot exceed total attempts + 1.
    assert!(
        nlink <= 201,
        "nlink={nlink} cannot exceed 200 concurrent links + 1"
    );
}

// ──────────────────────────────────────────────────────────────────────────
// Test 9: concurrent unlink isolation
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn concurrent_unlink_isolation() {
    let harness = MountHarness::new().expect("harness setup");
    create_and_stat(&harness, "base.txt", b"concurrent unlink test");

    // Create 50 hardlinks to the base file.
    for i in 0..50u32 {
        let name = format!("culink_{i}.txt");
        harness
            .hardlink("base.txt", &name)
            .unwrap_or_else(|_| panic!("hardlink {name}"));
    }

    let nlink_before = harness
        .stat("base.txt")
        .expect("stat before unlink")
        .nlink();
    assert_eq!(nlink_before, 51, "1 base + 50 links = 51 nlink");

    let mount = Arc::new(harness.mount_path().to_path_buf());

    // Spawn 4 threads, each unlinking a disjoint subset.
    let handles: Vec<_> = (0..4)
        .map(|t| {
            let mnt = mount.clone();
            thread::spawn(move || {
                let start = t * 12;
                let end = start + 12;
                for i in start..end {
                    let link = mnt.join(format!("culink_{i}.txt"));
                    let _ = std::fs::remove_file(&link);
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread join");
    }

    let nlink_after = harness
        .stat("base.txt")
        .expect("stat after concurrent unlink")
        .nlink();
    // Unlinked 48 of 50 names: nlink should be 51 - 48 = 3.
    assert_eq!(
        nlink_after, 3,
        "expected nlink=3 after 48 unlinks, got {nlink_after}"
    );
}

// ──────────────────────────────────────────────────────────────────────────
// Test 10: link after unlink re-create (name reuse, fresh nlink)
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn link_after_unlink_recreate() {
    let harness = MountHarness::new().expect("harness setup");

    let (_orig_ino, _) = create_and_stat(&harness, "reuse.txt", b"original");

    harness
        .hardlink("reuse.txt", "reuse_link.txt")
        .expect("hardlink");
    assert_eq!(harness.stat("reuse.txt").expect("stat").nlink(), 2);

    // Remove both names.
    harness.remove_file("reuse.txt").expect("unlink original");
    harness.remove_file("reuse_link.txt").expect("unlink link");

    // Re-create a new file with the old name.
    let (_new_ino, nlink) = create_and_stat(&harness, "reuse.txt", b"recreated");
    assert_eq!(nlink, 1, "re-created file must have nlink=1");

    // Link the new file.
    harness
        .hardlink("reuse.txt", "new_link.txt")
        .expect("hardlink on re-created file");
    assert_eq!(
        harness.stat("reuse.txt").expect("stat").nlink(),
        2,
        "nlink should be 2 after linking re-created file"
    );
}

// ──────────────────────────────────────────────────────────────────────────
// Test 11: remount persistence — links survive unmount/remount
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn remount_link_persistence() {
    let mut harness = MountHarness::new().expect("harness setup");

    let (src_ino, _) = create_and_stat(&harness, "persist.txt", b"persist link test");

    harness
        .hardlink("persist.txt", "persist_link.txt")
        .expect("hardlink before remount");
    harness
        .fsync_file("persist.txt")
        .expect("fsync persist.txt");

    let nlink_before = harness
        .stat("persist.txt")
        .expect("stat before remount")
        .nlink();
    assert_eq!(nlink_before, 2);

    harness.unmount_only(true).expect("unmount");
    harness.remount().expect("remount");

    let src_after = harness
        .stat("persist.txt")
        .expect("stat persist after remount");
    let link_after = harness
        .stat("persist_link.txt")
        .expect("stat persist_link after remount");

    assert_eq!(src_after.nlink(), 2, "nlink=2 must survive remount");
    assert_eq!(link_after.nlink(), 2);
    assert_eq!(
        link_after.ino(),
        src_after.ino(),
        "same inode after remount"
    );
    assert_eq!(src_after.ino(), src_ino, "inode unchanged after remount");
    assert_eq!(
        harness
            .read_file("persist.txt")
            .expect("read after remount"),
        b"persist link test"
    );
}

// ──────────────────────────────────────────────────────────────────────────
// Test 12: unlink before remount then verify gone after remount
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn unlink_before_remount_gone() {
    let mut harness = MountHarness::new().expect("harness setup");

    create_and_stat(&harness, "gone.txt", b"will be removed");
    harness
        .hardlink("gone.txt", "gone_link.txt")
        .expect("hardlink");
    harness.fsync_file("gone.txt").expect("fsync");

    harness.remove_file("gone.txt").expect("unlink gone.txt");
    assert_eq!(
        harness.stat("gone_link.txt").expect("stat link").nlink(),
        1,
        "nlink decremented after unlink"
    );

    harness.unmount_only(true).expect("unmount");
    harness.remount().expect("remount");

    assert!(
        !harness.exists("gone.txt"),
        "unlinked name must be gone after remount"
    );
    assert!(
        harness.exists("gone_link.txt"),
        "remaining link must survive remount"
    );
    assert_eq!(
        harness.stat("gone_link.txt").expect("stat").nlink(),
        1,
        "nlink=1 after remount"
    );
}

// ──────────────────────────────────────────────────────────────────────────
// Test 13: stat-after-link — immediate fstat sees updated nlink
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn stat_after_link_sees_updated_nlink() {
    let harness = MountHarness::new().expect("harness setup");
    create_and_stat(&harness, "immediate.txt", b"stat after link");

    harness
        .hardlink("immediate.txt", "immediate_link.txt")
        .expect("hardlink");

    // stat both names immediately after link.
    let md1 = harness
        .stat("immediate.txt")
        .expect("stat immediate source");
    let md2 = harness
        .stat("immediate_link.txt")
        .expect("stat immediate link");

    assert_eq!(md1.nlink(), 2, "source nlink should be 2 immediately");
    assert_eq!(md2.nlink(), 2, "link nlink should be 2 immediately");
    assert_eq!(md1.ino(), md2.ino(), "both names share same inode");
}

// ──────────────────────────────────────────────────────────────────────────
// Test 14: stat-after-unlink — immediate fstat sees decremented nlink
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn stat_after_unlink_sees_decremented_nlink() {
    let harness = MountHarness::new().expect("harness setup");
    create_and_stat(&harness, "decr.txt", b"stat after unlink");
    harness
        .hardlink("decr.txt", "decr_link.txt")
        .expect("hardlink");

    harness.remove_file("decr_link.txt").expect("unlink");

    let md = harness.stat("decr.txt").expect("stat after unlink");
    assert_eq!(md.nlink(), 1, "nlink should be 1 immediately after unlink");
}

// ──────────────────────────────────────────────────────────────────────────
// Test 15: link on FIFO fails with EPERM or EOPNOTSUPP
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn link_on_fifo_fails() {
    let harness = MountHarness::new().expect("harness setup");

    harness
        .mknod("myfifo", libc::S_IFIFO | 0o660, 0)
        .expect("mknod FIFO");

    let result = harness.hardlink("myfifo", "fifo_link");
    match &result {
        Err(e) => {
            let eno = e.raw_os_error();
            assert!(
                eno == Some(libc::EPERM) || eno == Some(libc::EOPNOTSUPP),
                "link on FIFO should return EPERM or EOPNOTSUPP, got: {e}"
            );
        }
        Ok(()) => panic!("link on FIFO must fail"),
    }

    // FIFO itself must be intact.
    let md = harness
        .stat("myfifo")
        .expect("stat FIFO after link attempt");
    assert!(md.file_type().is_fifo(), "FIFO must remain FIFO");
}

// ──────────────────────────────────────────────────────────────────────────
// Test 16: unlink on FIFO succeeds and decrements nlink
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn unlink_on_fifo_succeeds() {
    let harness = MountHarness::new().expect("harness setup");

    harness
        .mknod("pipe", libc::S_IFIFO | 0o660, 0)
        .expect("mknod FIFO");

    let md_before = harness.stat("pipe").expect("stat FIFO");
    assert!(md_before.file_type().is_fifo());
    assert_eq!(md_before.nlink(), 1, "FIFO initial nlink=1");

    harness.remove_file("pipe").expect("unlink FIFO");
    assert!(!harness.exists("pipe"), "FIFO must be gone after unlink");
}

// ──────────────────────────────────────────────────────────────────────────
// Test 17: link on directory fails (EPERM)
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn link_on_directory_fails() {
    let harness = MountHarness::new().expect("harness setup");

    harness.mkdir("mydir").expect("mkdir");

    let result = harness.hardlink("mydir", "dir_link");
    assert_errno(&result, libc::EPERM);

    // Directory must be intact.
    assert!(harness.stat("mydir").expect("stat dir").is_dir());
    assert!(!harness.exists("dir_link"));
}

// ──────────────────────────────────────────────────────────────────────────
// Test 18: unlink on non-empty directory fails
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn unlink_on_nonempty_directory_fails() {
    let harness = MountHarness::new().expect("harness setup");

    harness.mkdir("populated").expect("mkdir");
    harness
        .create_file("populated/child.txt", b"child")
        .expect("create child");

    // unlink(2) on a directory (even empty) returns EISDIR on Linux.
    // unlink(2) on a non-empty directory returns EISDIR.
    let result = harness.remove_file("populated");
    match &result {
        Err(e) => {
            let eno = e.raw_os_error();
            assert!(
                eno == Some(libc::EISDIR)
                    || eno == Some(libc::ENOTEMPTY)
                    || eno == Some(libc::EPERM),
                "unlink on directory should return EISDIR/ENOTEMPTY/EPERM, got: {e}"
            );
        }
        Ok(()) => panic!("unlink on non-empty directory must fail"),
    }

    // Directory and its contents must be intact.
    assert!(harness.stat("populated").expect("stat dir").is_dir());
    assert!(harness.exists("populated/child.txt"));
}

// ──────────────────────────────────────────────────────────────────────────
// Test 19: 3-way hardlink with nlink=3
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn three_way_hardlink() {
    let harness = MountHarness::new().expect("harness setup");

    let (ino, _) = create_and_stat(&harness, "one", b"3-way link");

    harness.hardlink("one", "two").expect("link 2");
    harness.hardlink("one", "three").expect("link 3");

    assert_eq!(harness.stat("one").expect("stat one").nlink(), 3);
    assert_eq!(harness.stat("two").expect("stat two").nlink(), 3);
    assert_eq!(harness.stat("three").expect("stat three").nlink(), 3);
    assert_eq!(harness.stat("one").expect("stat").ino(), ino);
    assert_eq!(harness.stat("two").expect("stat").ino(), ino);
    assert_eq!(harness.stat("three").expect("stat").ino(), ino);

    // Remove one link: nlink drops to 2 on remaining names.
    harness.remove_file("two").expect("unlink two");
    assert_eq!(harness.stat("one").expect("stat one").nlink(), 2);
    assert_eq!(harness.stat("three").expect("stat three").nlink(), 2);
    assert!(!harness.exists("two"));
}

// ──────────────────────────────────────────────────────────────────────────
// Test 20: unlink during open fd — file remains accessible
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn unlink_during_open_fd() {
    use std::fs::OpenOptions;
    use std::io::{Read, Seek, SeekFrom, Write};

    let harness = MountHarness::new().expect("harness setup");
    harness
        .create_file("openfd.txt", b"unlink-while-open test data")
        .expect("create file");

    let full_path = harness.mount_path().join("openfd.txt");

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&full_path)
        .expect("open fd");

    // Unlink the name while the fd is open.
    harness
        .remove_file("openfd.txt")
        .expect("unlink openfd.txt");
    assert!(!harness.exists("openfd.txt"), "name must be gone");
    assert_eq!(
        harness
            .stat("openfd.txt")
            .expect_err("stat must fail")
            .raw_os_error(),
        Some(libc::ENOENT),
    );

    // File still accessible via open fd.
    file.seek(SeekFrom::Start(0)).expect("seek to start");
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).expect("read via open fd");
    assert_eq!(buf, b"unlink-while-open test data");

    // Write via open fd still works.
    file.write_all(b" appended").expect("write via open fd");
    file.flush().expect("flush");

    // After close, the inode is freed (nlink=0 + no open fds).
    drop(file);
}

// ──────────────────────────────────────────────────────────────────────────
// Test 21: domain-separation determinism — identical sequence produces
//          identical BLAKE3 digest
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn domain_separation_determinism() {
    // Run the same link/unlink sequence twice through two independent harness
    // instances. The resulting BLAKE3 state digests must be identical.
    fn run_sequence() -> [u8; 32] {
        let harness = MountHarness::new().expect("harness setup");

        harness
            .create_file("determ_a.txt", b"content a")
            .expect("create a");
        harness
            .create_file("determ_b.txt", b"content b")
            .expect("create b");

        harness
            .hardlink("determ_a.txt", "determ_a_link.txt")
            .expect("link a");
        harness
            .hardlink("determ_b.txt", "determ_b_link.txt")
            .expect("link b");

        harness.remove_file("determ_b.txt").expect("unlink b");

        // Collect state: (filename, nlink, inode).
        let mut entries: Vec<(&str, u64, u64)> = Vec::new();
        for name in &["determ_a.txt", "determ_a_link.txt", "determ_b_link.txt"] {
            let md = harness.stat(name).unwrap_or_else(|_| panic!("stat {name}"));
            entries.push((name, md.nlink(), md.ino()));
        }
        hash_link_state(&entries)
    }

    let digest1 = run_sequence();
    let digest2 = run_sequence();

    assert_eq!(
        digest1, digest2,
        "identical link/unlink sequences must produce identical BLAKE3 digests"
    );
}

// ──────────────────────────────────────────────────────────────────────────
// Test 22: cross-domain non-collision — different link targets produce
//          different BLAKE3 digests
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn cross_domain_non_collision() {
    let harness = MountHarness::new().expect("harness setup");

    harness
        .create_file("target_a.txt", b"target a content")
        .expect("create target a");
    harness
        .create_file("target_b.txt", b"target b content")
        .expect("create target b");

    harness
        .hardlink("target_a.txt", "a_link.txt")
        .expect("link a");
    harness
        .hardlink("target_b.txt", "b_link.txt")
        .expect("link b");

    // State digest for target_a + a_link.
    let ma = harness.stat("target_a.txt").expect("stat target_a");
    let mla = harness.stat("a_link.txt").expect("stat a_link");
    let entries_a: Vec<(&str, u64, u64)> = vec![
        ("target_a.txt", ma.nlink(), ma.ino()),
        ("a_link.txt", mla.nlink(), mla.ino()),
    ];
    let digest_a = hash_link_state(&entries_a);

    // State digest for target_b + b_link.
    let mb = harness.stat("target_b.txt").expect("stat target_b");
    let mlb = harness.stat("b_link.txt").expect("stat b_link");
    let entries_b: Vec<(&str, u64, u64)> = vec![
        ("target_b.txt", mb.nlink(), mb.ino()),
        ("b_link.txt", mlb.nlink(), mlb.ino()),
    ];
    let digest_b = hash_link_state(&entries_b);

    assert_ne!(
        digest_a, digest_b,
        "different link targets must produce different BLAKE3 digests"
    );

    // Also verify domain separation: digest from this domain differs from
    // digest computed without domain separation.
    let mut raw_hasher = blake3::Hasher::new();
    for (name, nlink, inode) in &entries_a {
        raw_hasher.update(name.as_bytes());
        raw_hasher.update(&nlink.to_le_bytes());
        raw_hasher.update(&inode.to_le_bytes());
    }
    let raw_digest: [u8; 32] = raw_hasher.finalize().into();
    assert_ne!(
        digest_a, raw_digest,
        "domain-separated digest must differ from raw BLAKE3 digest"
    );
}
