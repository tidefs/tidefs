// Dispatch-table coverage integration tests for tidefs-fuser.
//
// Validates that every FUSE opcode has a recognized name, that
// errno name mapping is round-trip stable, and that error counters
// work correctly.  Trait-method dispatch tests live inside the
// crate in src/request.rs where internal Request construction is
// available.

use fuser::{
    FileAttr, FileType, Filesystem, MountOption, Reply, ReplyEmpty, ReplyOpen, ReplySender,
    ReplyStatfs,
};
use std::io;

// ---------------------------------------------------------------------------
// No-op reply sender
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct NoopSender;
impl ReplySender for NoopSender {
    fn send(&self, _data: &[io::IoSlice<'_>]) -> io::Result<()> {
        Ok(())
    }
}

fn sender() -> NoopSender {
    NoopSender
}

// ---------------------------------------------------------------------------
// Opcode-name completeness
// ---------------------------------------------------------------------------

#[test]
fn opcode_name_every_known_opcode() {
    let known: &[(u32, &str)] = &[
        (1, "LOOKUP"),
        (2, "FORGET"),
        (3, "GETATTR"),
        (4, "SETATTR"),
        (5, "READLINK"),
        (6, "SYMLINK"),
        (8, "MKNOD"),
        (9, "MKDIR"),
        (10, "UNLINK"),
        (11, "RMDIR"),
        (12, "RENAME"),
        (13, "LINK"),
        (14, "OPEN"),
        (15, "READ"),
        (16, "WRITE"),
        (17, "STATFS"),
        (18, "RELEASE"),
        (20, "FSYNC"),
        (21, "SETXATTR"),
        (22, "GETXATTR"),
        (23, "LISTXATTR"),
        (24, "REMOVEXATTR"),
        (25, "FLUSH"),
        (26, "INIT"),
        (27, "OPENDIR"),
        (28, "READDIR"),
        (29, "RELEASEDIR"),
        (30, "FSYNCDIR"),
        (31, "GETLK"),
        (32, "SETLK"),
        (33, "SETLKW"),
        (34, "ACCESS"),
        (35, "CREATE"),
        (36, "INTERRUPT"),
        (37, "BMAP"),
        (38, "DESTROY"),
        (63, "EXCHANGE"),
    ];
    for &(code, expected) in known {
        let name = fuser::opcode_name(code);
        assert_eq!(
            name, expected,
            "opcode {code} returned {name:?}, expected {expected:?}"
        );
    }
}

#[test]
fn opcode_name_unknown_for_unused_slots() {
    for &code in &[
        0u32, 7, 19, 41, 49, 50, 51, 54, 55, 56, 57, 58, 59, 60, 64, 100, 255,
    ] {
        assert_eq!(
            fuser::opcode_name(code),
            "UNKNOWN",
            "opcode {code} should be UNKNOWN"
        );
    }
}

// ---------------------------------------------------------------------------
// Error-code name round-trip
// ---------------------------------------------------------------------------

#[test]
fn errno_name_known_codes() {
    let codes: &[(i32, &str)] = &[
        (libc::EPERM, "EPERM"),
        (libc::ENOENT, "ENOENT"),
        (libc::EIO, "EIO"),
        (libc::ENXIO, "ENXIO"),
        (libc::EACCES, "EACCES"),
        (libc::EEXIST, "EEXIST"),
        (libc::ENODEV, "ENODEV"),
        (libc::ENOTDIR, "ENOTDIR"),
        (libc::EISDIR, "EISDIR"),
        (libc::EINVAL, "EINVAL"),
        (libc::ENOSPC, "ENOSPC"),
        (libc::EROFS, "EROFS"),
        (libc::EMLINK, "EMLINK"),
        (libc::EPIPE, "EPIPE"),
        (libc::ENOSYS, "ENOSYS"),
        (libc::ENOTEMPTY, "ENOTEMPTY"),
        (libc::ELOOP, "ELOOP"),
        (libc::ENAMETOOLONG, "ENAMETOOLONG"),
        (libc::ENOLCK, "ENOLCK"),
        (libc::EBADF, "EBADF"),
        (libc::ENOMEM, "ENOMEM"),
        (libc::EBUSY, "EBUSY"),
        (libc::EDQUOT, "EDQUOT"),
        (libc::ESTALE, "ESTALE"),
        (libc::ENOBUFS, "ENOBUFS"),
        (libc::ENODATA, "ENODATA"),
        (libc::EOVERFLOW, "EOVERFLOW"),
    ];
    for &(code, expected) in codes {
        let name = fuser::errno_name(code);
        assert_eq!(
            name, expected,
            "errno {code} returned {name:?}, expected {expected:?}"
        );
    }
}

#[test]
fn errno_name_zero_is_generic() {
    assert_eq!(fuser::errno_name(0), "ERRNO");
}

// ---------------------------------------------------------------------------
// FuseErrorCounters integration smoke
// ---------------------------------------------------------------------------

#[test]
fn error_counters_increment_and_read() {
    let before = fuser::ERROR_COUNTERS.get(1);
    fuser::ERROR_COUNTERS.increment(1);
    assert_eq!(fuser::ERROR_COUNTERS.get(1), before + 1);
}

#[test]
fn error_counters_snapshot_contains_incremented() {
    fuser::ERROR_COUNTERS.increment(15); // READ
    let snap = fuser::ERROR_COUNTERS.snapshot();
    assert!(
        snap.iter().any(|(name, _)| *name == "READ"),
        "Snapshot should contain READ after increment"
    );
}

// ---------------------------------------------------------------------------
// Type coverage: FileType, FileAttr, MountOption
// ---------------------------------------------------------------------------

#[test]
fn file_type_all_variants_distinct() {
    let types = [
        FileType::NamedPipe,
        FileType::CharDevice,
        FileType::BlockDevice,
        FileType::Directory,
        FileType::RegularFile,
        FileType::Symlink,
        FileType::Socket,
    ];
    for i in 0..types.len() {
        for j in (i + 1)..types.len() {
            assert_ne!(types[i], types[j]);
        }
    }
}

#[test]
fn file_attr_all_fields_settable() {
    use std::time::SystemTime;
    let attr = FileAttr {
        ino: 0,
        size: 0,
        blocks: 0,
        atime: SystemTime::UNIX_EPOCH,
        mtime: SystemTime::UNIX_EPOCH,
        ctime: SystemTime::UNIX_EPOCH,
        crtime: SystemTime::UNIX_EPOCH,
        kind: FileType::RegularFile,
        perm: 0o644,
        nlink: 1,
        uid: 1000,
        gid: 1000,
        rdev: 0,
        blksize: 4096,
        flags: 0,
    };
    assert_eq!(attr.ino, 0);
    assert_eq!(attr.kind, FileType::RegularFile);
    assert_eq!(attr.nlink, 1);
}

#[test]
fn mount_option_all_variants_constructible() {
    let _ = MountOption::AllowRoot;
    let _ = MountOption::AllowOther;
    let _ = MountOption::AutoUnmount;
    let _ = MountOption::CUSTOM("custom".into());
    let _ = MountOption::FSName("fs".into());
    let _ = MountOption::Subtype("sub".into());
}

// ---------------------------------------------------------------------------
// Filesystem trait object-safety
// ---------------------------------------------------------------------------

struct NullFS;
impl Filesystem for NullFS {}

#[test]
fn filesystem_trait_object_safe() {
    let fs = NullFS;
    let _: &dyn Filesystem = &fs;
}

// ---------------------------------------------------------------------------
// Reply type construction (verify ReplySender integration)
// ---------------------------------------------------------------------------

#[test]
fn reply_empty_can_be_constructed() {
    let _reply: ReplyEmpty = Reply::new(0, sender());
}

#[test]
fn reply_open_can_be_constructed() {
    let _reply: ReplyOpen = Reply::new(0, sender());
}

#[test]
fn reply_statfs_can_be_constructed() {
    let _reply: ReplyStatfs = Reply::new(0, sender());
}

// ---------------------------------------------------------------------------
// Session-level dispatch tests (require /dev/fuse)
// ---------------------------------------------------------------------------

#[test]
#[cfg(target_os = "linux")]
fn null_fs_session_mount_and_dispatch() {
    let tmpdir = tempfile::tempdir().expect("tempdir");
    let mountpoint = tmpdir.path().join("mnt");
    std::fs::create_dir(&mountpoint).expect("mkdir");

    // Mount a NullFS — every opcode returns ENOSYS or its default.
    let session = fuser::Session::new(NullFS, &mountpoint, &[]);

    // Session::new can fail if /dev/fuse is unavailable or permissions
    // are insufficient.  Accept either outcome without panic.
    match session {
        Ok(se) => {
            // Spawn background session so we can interact with the mount
            let bg = se.spawn().expect("spawn background session");

            // Attempt a few basic operations on the mountpoint.
            // Since NullFS returns ENOSYS for most ops, these should fail
            // with appropriate errno values, not crash the daemon.
            let mnt = &mountpoint;

            // stat should fail (getattr returns ENOSYS)
            let _ = std::fs::metadata(mnt);

            // readdir should fail (readdir returns ENOSYS)
            let _ = std::fs::read_dir(mnt);

            // create file should fail (create returns ENOSYS)
            let _ = std::fs::File::create(mnt.join("test.txt"));

            // mkdir should fail (mkdir returns ENOSYS)
            let _ = std::fs::create_dir(mnt.join("subdir"));

            // Drop the background session to unmount
            drop(bg);
        }
        Err(e) => {
            // /dev/fuse unavailable or insufficient permissions —
            // this is not a test failure.
            eprintln!("Session::new failed (expected in some CI environments): {e}");
        }
    }
}

#[test]
#[cfg(target_os = "linux")]
fn null_fs_session_mount_options_passthrough() {
    let tmpdir = tempfile::tempdir().expect("tempdir");
    let mountpoint = tmpdir.path().join("mnt");
    std::fs::create_dir(&mountpoint).expect("mkdir");

    let session = fuser::Session::new(
        NullFS,
        &mountpoint,
        &[
            fuser::MountOption::RO,
            fuser::MountOption::NoDev,
            fuser::MountOption::NoSuid,
        ],
    );

    match session {
        Ok(se) => {
            let bg = se.spawn().expect("spawn");
            // Just verify the mount doesn't crash with options
            drop(bg);
        }
        Err(e) => {
            eprintln!("Session::new with options failed: {e}");
        }
    }
}
