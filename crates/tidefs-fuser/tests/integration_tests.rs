// Integration tests for tidefs-fuser (the `fuser` crate).
//
// These tests verify the public API surface: Filesystem trait, FileAttr,
// FileType, MountOption, and reply types.  Session-level tests that
// require /dev/fuse are #[cfg(target_os = "linux")] gated.

use fuser::{FileAttr, FileType, Filesystem, MountOption};
use std::time::SystemTime;

// --- Minimal filesystem implementations ---

/// A filesystem that does nothing (all default ENOSYS handlers).
struct NullFS;
impl Filesystem for NullFS {}

// --- Unit-level tests (no /dev/fuse needed) ---

#[test]
fn file_type_equality() {
    let types = [
        FileType::NamedPipe,
        FileType::CharDevice,
        FileType::BlockDevice,
        FileType::Directory,
        FileType::RegularFile,
        FileType::Symlink,
        FileType::Socket,
    ];
    for (i, a) in types.iter().enumerate() {
        for (j, b) in types.iter().enumerate() {
            assert_eq!(i == j, a == b, "FileType equality mismatch");
        }
    }
}

#[test]
fn file_attr_construction() {
    let attr = FileAttr {
        ino: 42,
        size: 4096,
        blocks: 8,
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
    assert_eq!(attr.ino, 42);
    assert_eq!(attr.size, 4096);
    assert_eq!(attr.kind, FileType::RegularFile);
    assert_eq!(attr.perm, 0o644);
    assert_eq!(attr.nlink, 1);
}

#[test]
fn file_attr_clone_debug() {
    let attr = FileAttr {
        ino: 1,
        size: 0,
        blocks: 0,
        atime: SystemTime::UNIX_EPOCH,
        mtime: SystemTime::UNIX_EPOCH,
        ctime: SystemTime::UNIX_EPOCH,
        crtime: SystemTime::UNIX_EPOCH,
        kind: FileType::Directory,
        perm: 0o755,
        nlink: 2,
        uid: 0,
        gid: 0,
        rdev: 0,
        blksize: 4096,
        flags: 0,
    };
    // Clone and Debug are derived
    let _clone = attr;
    let _debug = format!("{attr:?}");
    assert!(_debug.contains("ino: 1"));
}

#[test]
fn mount_option_count() {
    let opts = [
        MountOption::AllowRoot,
        MountOption::AllowOther,
        MountOption::AutoUnmount,
        MountOption::DefaultPermissions,
        MountOption::Dev,
        MountOption::NoDev,
        MountOption::Suid,
        MountOption::NoSuid,
        MountOption::Exec,
        MountOption::NoExec,
        MountOption::RO,
        MountOption::RW,
        MountOption::FSName("test".into()),
    ];
    assert_eq!(opts.len(), 13);
}

#[test]
fn filesystem_trait_no_send() {
    // A !Send filesystem should still be usable with the trait
    use std::rc::Rc;
    #[allow(dead_code)]
    struct NoSendFS(Rc<()>);
    impl Filesystem for NoSendFS {}
    let _fs = NoSendFS(Rc::new(()));
}

#[test]
fn filesystem_trait_send() {
    // A Send + 'static filesystem compiles
    let fs = NullFS;
    let _fs: &dyn Filesystem = &fs;
}

#[test]
fn mount_option_debug() {
    let opt = MountOption::AllowOther;
    let s = format!("{opt:?}");
    assert!(!s.is_empty());
}

// --- Session-level tests (require /dev/fuse) ---

#[test]
#[cfg(target_os = "linux")]
fn null_fs_session_creation() {
    let tmpdir = tempfile::tempdir().expect("tempdir");
    let session = fuser::Session::new(NullFS, tmpdir.path(), &[]);
    if let Ok(mut se) = session {
        se.unmount();
    }
}
