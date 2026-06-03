// FUSE directory operation integration tests for the `fuser` crate.
//
// Validates mkdir, rmdir, and readdir/readdirplus through a live FUSE mount
// against an in-memory filesystem, exercising POSIX error semantics
// (ENOENT, ENOTEMPTY, EEXIST, ENOTDIR).  All session tests require
// /dev/fuse and are gated behind #[cfg(target_os = "linux")].

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::sync::Mutex;
use std::time::Duration;

use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyDirectory, ReplyDirectoryPlus,
    ReplyEmpty, ReplyEntry, ReplyOpen, Request, FUSE_ROOT_ID,
};

// ---------------------------------------------------------------------------
// In-memory filesystem for directory operation tests
// ---------------------------------------------------------------------------

type Ino = u64;

#[derive(Clone, Debug)]
struct Inode {
    ino: Ino,
    kind: FileType,
    perm: u16,
    nlink: u32,
    /// Directory entries: name bytes -> (child ino, FileType).
    /// Only meaningful when kind == Directory.
    entries: BTreeMap<Vec<u8>, (Ino, FileType)>,
}

impl Inode {
    fn dir(ino: Ino, parent_ino: Ino, perm: u16) -> Self {
        let mut entries = BTreeMap::new();
        entries.insert(b".".to_vec(), (ino, FileType::Directory));
        entries.insert(b"..".to_vec(), (parent_ino, FileType::Directory));
        Inode {
            ino,
            kind: FileType::Directory,
            perm,
            nlink: 2,
            entries,
        }
    }

    fn file(ino: Ino, perm: u16) -> Self {
        Inode {
            ino,
            kind: FileType::RegularFile,
            perm,
            nlink: 1,
            entries: BTreeMap::new(),
        }
    }

    fn to_attr(&self) -> FileAttr {
        FileAttr {
            ino: self.ino,
            size: 0,
            blocks: 0,
            atime: std::time::UNIX_EPOCH,
            mtime: std::time::UNIX_EPOCH,
            ctime: std::time::UNIX_EPOCH,
            crtime: std::time::UNIX_EPOCH,
            kind: self.kind,
            perm: self.perm,
            nlink: self.nlink,
            uid: 0,
            gid: 0,
            rdev: 0,
            blksize: 512,
            flags: 0,
        }
    }
}

struct DirTestFS {
    inodes: Mutex<BTreeMap<Ino, Inode>>,
    next_ino: Mutex<Ino>,
}

impl DirTestFS {
    fn new() -> Self {
        let root = Inode::dir(FUSE_ROOT_ID, FUSE_ROOT_ID, 0o755);
        let mut inodes = BTreeMap::new();
        inodes.insert(FUSE_ROOT_ID, root);
        DirTestFS {
            inodes: Mutex::new(inodes),
            next_ino: Mutex::new(FUSE_ROOT_ID + 1),
        }
    }

    fn alloc_ino(&self) -> Ino {
        let mut next = self.next_ino.lock().unwrap();
        let ino = *next;
        *next += 1;
        ino
    }

    fn get_ino(&self, ino: Ino) -> Option<Inode> {
        self.inodes.lock().unwrap().get(&ino).cloned()
    }

    /// Look up a child entry by name within a parent directory.
    fn resolve(&self, parent: Ino, name: &OsStr) -> Option<(Ino, FileType)> {
        let inodes = self.inodes.lock().unwrap();
        inodes.get(&parent)?.entries.get(name.as_bytes()).copied()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<Ino, Inode>> {
        self.inodes.lock().unwrap()
    }
}

// ---------------------------------------------------------------------------
// Filesystem trait
// ---------------------------------------------------------------------------

impl Filesystem for DirTestFS {
    fn lookup(&mut self, _req: &Request, parent: Ino, name: &OsStr, reply: ReplyEntry) {
        match self.resolve(parent, name) {
            Some((ino, _kind)) => match self.get_ino(ino) {
                Some(inode) => reply.entry(&Duration::ZERO, &inode.to_attr(), 0),
                None => reply.error(libc::ENOENT),
            },
            None => reply.error(libc::ENOENT),
        }
    }

    fn getattr(&mut self, _req: &Request, ino: Ino, reply: ReplyAttr) {
        match self.get_ino(ino) {
            Some(inode) => reply.attr(&Duration::ZERO, &inode.to_attr()),
            None => reply.error(libc::ENOENT),
        }
    }

    fn mkdir(
        &mut self,
        _req: &Request,
        parent: Ino,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let mut inodes = self.lock();

        let parent_inode = match inodes.get(&parent) {
            Some(p) if p.kind == FileType::Directory => p.clone(),
            Some(_) => {
                reply.error(libc::ENOTDIR);
                return;
            }
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        if parent_inode.entries.contains_key(name.as_bytes()) {
            reply.error(libc::EEXIST);
            return;
        }

        let ino = self.alloc_ino();
        let child = Inode::dir(ino, parent, (mode & 0o777) as u16);

        if let Some(p) = inodes.get_mut(&parent) {
            p.nlink += 1;
            p.entries
                .insert(name.as_bytes().to_vec(), (ino, FileType::Directory));
        }

        let attr = child.to_attr();
        inodes.insert(ino, child);
        drop(inodes);
        reply.entry(&Duration::ZERO, &attr, 0);
    }

    fn rmdir(&mut self, _req: &Request, parent: Ino, name: &OsStr, reply: ReplyEmpty) {
        let mut inodes = self.lock();

        let (child_ino, child_kind) = match inodes.get(&parent) {
            Some(p) if p.kind == FileType::Directory => match p.entries.get(name.as_bytes()) {
                Some(e) => *e,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            },
            Some(_) => {
                reply.error(libc::ENOTDIR);
                return;
            }
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        if child_kind != FileType::Directory {
            reply.error(libc::ENOTDIR);
            return;
        }

        let child = match inodes.get(&child_ino) {
            Some(c) => c.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        if child.entries.len() > 2 {
            reply.error(libc::ENOTEMPTY);
            return;
        }

        inodes.remove(&child_ino);
        if let Some(p) = inodes.get_mut(&parent) {
            p.nlink -= 1;
            p.entries.remove(name.as_bytes());
        }

        reply.ok();
    }

    fn unlink(&mut self, _req: &Request, parent: Ino, name: &OsStr, reply: ReplyEmpty) {
        let mut inodes = self.lock();

        let child_ino = match inodes.get(&parent) {
            Some(p) => match p.entries.get(name.as_bytes()) {
                Some((ino, _)) => *ino,
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            },
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        inodes.remove(&child_ino);
        if let Some(p) = inodes.get_mut(&parent) {
            p.entries.remove(name.as_bytes());
        }

        reply.ok();
    }

    fn create(
        &mut self,
        _req: &Request,
        parent: Ino,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let mut inodes = self.lock();

        match inodes.get(&parent) {
            Some(p) if p.kind == FileType::Directory => {}
            Some(_) => {
                reply.error(libc::ENOTDIR);
                return;
            }
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        }

        if inodes
            .get(&parent)
            .unwrap()
            .entries
            .contains_key(name.as_bytes())
        {
            reply.error(libc::EEXIST);
            return;
        }

        let ino = self.alloc_ino();
        let child = Inode::file(ino, (mode & 0o777) as u16);
        let attr = child.to_attr();

        if let Some(p) = inodes.get_mut(&parent) {
            p.entries
                .insert(name.as_bytes().to_vec(), (ino, FileType::RegularFile));
        }
        inodes.insert(ino, child);

        reply.created(&Duration::ZERO, &attr, 0, 0, 0);
    }

    fn opendir(&mut self, _req: &Request, _ino: Ino, _flags: i32, reply: ReplyOpen) {
        reply.opened(0, 0);
    }

    fn readdir(
        &mut self,
        _req: &Request,
        ino: Ino,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let inodes = self.lock();
        let dir = match inodes.get(&ino) {
            Some(d) if d.kind == FileType::Directory => d,
            Some(_) => {
                reply.error(libc::ENOTDIR);
                return;
            }
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let entries: Vec<_> = dir.entries.iter().collect();
        for (i, (name, (child_ino, child_kind))) in entries.iter().enumerate().skip(offset as usize)
        {
            if reply.add(
                *child_ino,
                (i + 1) as i64,
                *child_kind,
                OsStr::from_bytes(name),
            ) {
                break;
            }
        }
        reply.ok();
    }

    fn readdirplus(
        &mut self,
        _req: &Request,
        ino: Ino,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectoryPlus,
    ) {
        let inodes = self.lock();
        let dir = match inodes.get(&ino) {
            Some(d) if d.kind == FileType::Directory => d,
            Some(_) => {
                reply.error(libc::ENOTDIR);
                return;
            }
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let entries: Vec<_> = dir.entries.iter().collect();
        for (i, (name, (child_ino, child_kind))) in entries.iter().enumerate().skip(offset as usize)
        {
            let attr = inodes
                .get(child_ino)
                .map(|c| c.to_attr())
                .unwrap_or(FileAttr {
                    ino: *child_ino,
                    size: 0,
                    blocks: 0,
                    atime: std::time::UNIX_EPOCH,
                    mtime: std::time::UNIX_EPOCH,
                    ctime: std::time::UNIX_EPOCH,
                    crtime: std::time::UNIX_EPOCH,
                    kind: *child_kind,
                    perm: 0,
                    nlink: 0,
                    uid: 0,
                    gid: 0,
                    rdev: 0,
                    blksize: 512,
                    flags: 0,
                });
            if reply.add(
                *child_ino,
                (i + 1) as i64,
                OsStr::from_bytes(name),
                &Duration::ZERO,
                &attr,
                0,
            ) {
                break;
            }
        }
        reply.ok();
    }

    fn releasedir(&mut self, _req: &Request, _ino: Ino, _fh: u64, _flags: i32, reply: ReplyEmpty) {
        reply.ok();
    }
}

// ---------------------------------------------------------------------------
// Mount helper
// ---------------------------------------------------------------------------

/// Returns (mountpoint_path, BackgroundSession).  Drop the session to unmount.
fn mount(label: &str) -> (std::path::PathBuf, fuser::BackgroundSession) {
    let tmpdir = tempfile::tempdir().expect("tempdir");
    if !std::path::Path::new("/dev/fuse").exists() {
        eprintln!("SKIP: /dev/fuse not available");
        std::process::exit(0);
    }

    let mnt = tmpdir.path().join(label);
    std::fs::create_dir(&mnt).expect("mkdir mountpoint");
    let se = fuser::spawn_mount2(DirTestFS::new(), &mnt, &[]).expect("spawn_mount2");
    std::thread::sleep(std::time::Duration::from_millis(50));
    (mnt, se)
}

// ---------------------------------------------------------------------------
// mkdir tests
// ---------------------------------------------------------------------------

#[test]
#[cfg(target_os = "linux")]
fn mkdir_creates_dir_with_correct_mode() {
    let (mnt, _bg) = mount("mkdir-mode");
    let d = mnt.join("sub");
    std::fs::create_dir(&d).expect("mkdir");
    let meta = d.symlink_metadata().expect("stat");
    assert!(meta.is_dir());
    assert_eq!(meta.nlink(), 2, "new dir nlink must be 2");
    let mode = meta.permissions().mode();
    assert_eq!(mode & libc::S_IFMT, libc::S_IFDIR);
}

#[test]
#[cfg(target_os = "linux")]
fn mkdir_duplicate_returns_eexist() {
    let (mnt, _bg) = mount("mkdir-eexist");
    std::fs::create_dir(mnt.join("d")).expect("first mkdir");
    let e = std::fs::create_dir(mnt.join("d")).unwrap_err();
    assert_eq!(e.raw_os_error(), Some(libc::EEXIST), "got {e:?}");
}

#[test]
#[cfg(target_os = "linux")]
fn mkdir_parent_missing_returns_enoent() {
    let (mnt, _bg) = mount("mkdir-enoent");
    let e = std::fs::create_dir(mnt.join("nope").join("child")).unwrap_err();
    assert_eq!(e.raw_os_error(), Some(libc::ENOENT), "got {e:?}");
}

#[test]
#[cfg(target_os = "linux")]
fn mkdir_through_file_returns_enotdir() {
    let (mnt, _bg) = mount("mkdir-enotdir");
    std::fs::File::create(mnt.join("f")).expect("create file");
    let e = std::fs::create_dir(mnt.join("f").join("sub")).unwrap_err();
    assert_eq!(e.raw_os_error(), Some(libc::ENOTDIR), "got {e:?}");
}

// ---------------------------------------------------------------------------
// rmdir tests
// ---------------------------------------------------------------------------

#[test]
#[cfg(target_os = "linux")]
fn rmdir_empty_succeeds() {
    let (mnt, _bg) = mount("rmdir-ok");
    std::fs::create_dir(mnt.join("sub")).expect("mkdir");
    assert!(mnt.join("sub").exists());
    std::fs::remove_dir(mnt.join("sub")).expect("rmdir");
    assert!(!mnt.join("sub").exists());
}

#[test]
#[cfg(target_os = "linux")]
fn rmdir_nonempty_returns_enotempty() {
    let (mnt, _bg) = mount("rmdir-notempty");
    std::fs::create_dir(mnt.join("sub")).expect("mkdir");
    std::fs::File::create(mnt.join("sub").join("f")).expect("create file");
    let e = std::fs::remove_dir(mnt.join("sub")).unwrap_err();
    assert_eq!(e.raw_os_error(), Some(libc::ENOTEMPTY), "got {e:?}");
}

#[test]
#[cfg(target_os = "linux")]
fn rmdir_nonexistent_returns_enoent() {
    let (mnt, _bg) = mount("rmdir-enoent");
    let e = std::fs::remove_dir(mnt.join("nope")).unwrap_err();
    assert_eq!(e.raw_os_error(), Some(libc::ENOENT), "got {e:?}");
}

#[test]
#[cfg(target_os = "linux")]
fn rmdir_on_file_returns_enotdir() {
    let (mnt, _bg) = mount("rmdir-enotdir");
    std::fs::File::create(mnt.join("f")).expect("create file");
    let e = std::fs::remove_dir(mnt.join("f")).unwrap_err();
    assert_eq!(e.raw_os_error(), Some(libc::ENOTDIR), "got {e:?}");
}

#[test]
#[cfg(target_os = "linux")]
fn rmdir_decrements_parent_nlink() {
    let (mnt, _bg) = mount("rmdir-nlink");
    let before = mnt.symlink_metadata().expect("stat root").nlink();
    std::fs::create_dir(mnt.join("sub")).expect("mkdir");
    let after_mkdir = mnt
        .symlink_metadata()
        .expect("stat root after mkdir")
        .nlink();
    assert_eq!(after_mkdir, before + 1, "nlink must increase after mkdir");
    std::fs::remove_dir(mnt.join("sub")).expect("rmdir");
    let after_rmdir = mnt
        .symlink_metadata()
        .expect("stat root after rmdir")
        .nlink();
    assert_eq!(
        after_rmdir, before,
        "nlink must return to original after rmdir"
    );
}

// ---------------------------------------------------------------------------
// readdir / readdirplus tests
// ---------------------------------------------------------------------------

#[test]
#[cfg(target_os = "linux")]
fn readdir_empty_dir() {
    let (mnt, _bg) = mount("readdir-empty");
    std::fs::create_dir(mnt.join("sub")).expect("mkdir");
    let names: Vec<String> = std::fs::read_dir(mnt.join("sub"))
        .expect("read_dir")
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    assert!(
        names.is_empty(),
        "empty dir must have 0 entries, got {:?}",
        names
    );
}

#[test]
#[cfg(target_os = "linux")]
fn readdir_dir_with_children() {
    let (mnt, _bg) = mount("readdir-children");
    std::fs::create_dir(mnt.join("sub")).expect("mkdir");
    std::fs::File::create(mnt.join("sub").join("a.txt")).expect("create");
    std::fs::File::create(mnt.join("sub").join("b.txt")).expect("create");
    std::fs::create_dir(mnt.join("sub").join("nested")).expect("mkdir nested");
    let names: Vec<String> = std::fs::read_dir(mnt.join("sub"))
        .expect("read_dir")
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    assert_eq!(names.len(), 3, "expected 3 children, got {names:?}");
    assert!(names.contains(&"a.txt".to_string()));
    assert!(names.contains(&"b.txt".to_string()));
    assert!(names.contains(&"nested".to_string()));
}

#[test]
#[cfg(target_os = "linux")]
fn readdir_on_file_returns_enotdir() {
    let (mnt, _bg) = mount("readdir-enotdir");
    std::fs::File::create(mnt.join("f")).expect("create file");
    let e = std::fs::read_dir(mnt.join("f")).unwrap_err();
    assert_eq!(e.raw_os_error(), Some(libc::ENOTDIR), "got {e:?}");
}

#[test]
#[cfg(target_os = "linux")]
fn readdirplus_dir_with_children() {
    let (mnt, _bg) = mount("readdirplus");
    std::fs::create_dir(mnt.join("sub")).expect("mkdir");
    std::fs::File::create(mnt.join("sub").join("f1")).expect("create");
    std::fs::create_dir(mnt.join("sub").join("d1")).expect("mkdir");
    let entries: Vec<(String, bool)> = std::fs::read_dir(mnt.join("sub"))
        .expect("read_dir")
        .map(|e| {
            let e = e.unwrap();
            (
                e.file_name().to_string_lossy().to_string(),
                e.file_type().unwrap().is_dir(),
            )
        })
        .collect();
    assert_eq!(entries.len(), 2);
    assert!(entries.iter().any(|(n, d)| n == "f1" && !d));
    assert!(entries.iter().any(|(n, d)| n == "d1" && *d));
}

// ---------------------------------------------------------------------------
// Combined cycle test
// ---------------------------------------------------------------------------

#[test]
#[cfg(target_os = "linux")]
fn combined_mkdir_create_readdir_unlink_rmdir() {
    let (mnt, _bg) = mount("combined");

    // mkdir
    std::fs::create_dir(mnt.join("d")).expect("mkdir");
    assert!(mnt.join("d").exists());
    let meta = mnt.join("d").symlink_metadata().expect("stat");
    assert!(meta.is_dir());
    assert_eq!(meta.nlink(), 2);

    // create file
    std::fs::File::create(mnt.join("d").join("f")).expect("create");
    assert!(mnt.join("d").join("f").exists());

    // readdir
    let names: Vec<String> = std::fs::read_dir(mnt.join("d"))
        .expect("read_dir")
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    assert_eq!(names, vec!["f"], "expected ['f'], got {names:?}");

    // unlink
    std::fs::remove_file(mnt.join("d").join("f")).expect("unlink");
    assert!(!mnt.join("d").join("f").exists());

    // readdir after unlink
    let names: Vec<String> = std::fs::read_dir(mnt.join("d"))
        .expect("read_dir after unlink")
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    assert!(
        names.is_empty(),
        "expected empty after unlink, got {:?}",
        names
    );

    // rmdir
    std::fs::remove_dir(mnt.join("d")).expect("rmdir");
    assert!(!mnt.join("d").exists());
}

// ---------------------------------------------------------------------------
// readdir consistency
// ---------------------------------------------------------------------------

#[test]
#[cfg(target_os = "linux")]
fn readdir_entry_ordering_is_stable() {
    let (mnt, _bg) = mount("readdir-stable");
    std::fs::create_dir(mnt.join("d")).expect("mkdir");
    std::fs::File::create(mnt.join("d").join("a")).expect("create a");
    std::fs::File::create(mnt.join("d").join("b")).expect("create b");
    std::fs::File::create(mnt.join("d").join("c")).expect("create c");

    let read_names = || -> Vec<String> {
        std::fs::read_dir(mnt.join("d"))
            .expect("read_dir")
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect()
    };

    let first = read_names();
    for _ in 0..5 {
        assert_eq!(read_names(), first, "readdir ordering must be stable");
    }
}
