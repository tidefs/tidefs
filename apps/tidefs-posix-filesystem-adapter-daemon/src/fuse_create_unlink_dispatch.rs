// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! FUSE create/mkdir/rmdir/unlink batch dispatch routing through
//! [`VfsEngine`].
//!
//! This module provides batch-processing entry points that accept
//! multiple same-type FUSE requests and route each through the
//! canonical [`tidefs_vfs_engine::VfsEngine`] trait.  The caller
//! (typically [`crate::fuse_vfs_adapter::FuseVfsAdapter`]) is
//! responsible for translating raw FUSE request buffers into the
//! typed batch-request structs defined here.
//!
//! # Design
//!
//! Each batch function iterates over its request slice and calls
//! the corresponding engine method for each entry, collecting
//! per-entry results.  Batch-level rollback on partial failure is
//! NOT implemented here; the caller may decide whether to unwind
//! based on the result vector.

#[cfg_attr(not(test), allow(unused_imports))]
use tidefs_types_vfs_core::{EngineFileHandle, FileHandleId, InodeAttr, InodeId, RequestCtx};
use tidefs_vfs_engine::{Errno, VfsEngine, O_EXCL};

// ── Batch request types ────────────────────────────────────────────────

/// A single FUSE `create` (S_IFREG / O_CREAT) request within a batch.
#[derive(Clone, Debug)]
pub struct CreateBatchRequest<'a> {
    /// Parent directory inode.
    pub parent: InodeId,
    /// File name (raw bytes, kernel-encoded).
    pub name: &'a [u8],
    /// File mode (permission bits; S_IFREG is implied).
    pub mode: u32,
    /// Open flags (O_RDWR, O_EXCL, O_TRUNC, etc.).
    pub flags: u32,
    /// Request context (uid, gid, pid, umask).
    pub ctx: RequestCtx,
}

/// A single FUSE `mkdir` request within a batch.
#[derive(Clone, Debug)]
pub struct MkdirBatchRequest<'a> {
    /// Parent directory inode.
    pub parent: InodeId,
    /// Directory name (raw bytes).
    pub name: &'a [u8],
    /// Directory mode (permission bits; S_IFDIR is implied).
    pub mode: u32,
    /// Request context.
    pub ctx: RequestCtx,
}

/// A single FUSE `unlink` request within a batch.
#[derive(Clone, Debug)]
pub struct UnlinkBatchRequest<'a> {
    /// Parent directory inode.
    pub parent: InodeId,
    /// Entry name to remove.
    pub name: &'a [u8],
    /// Request context.
    pub ctx: RequestCtx,
}

/// A single FUSE `rmdir` request within a batch.
#[derive(Clone, Debug)]
pub struct RmdirBatchRequest<'a> {
    /// Parent directory inode.
    pub parent: InodeId,
    /// Subdirectory name to remove.
    pub name: &'a [u8],
    /// Request context.
    pub ctx: RequestCtx,
}
/// A single FUSE `link` (hard link) request within a batch.
#[derive(Clone, Debug)]
pub struct LinkBatchRequest<'a> {
    /// Source inode to create a hard link to.
    pub target: InodeId,
    /// New parent directory inode.
    pub new_parent: InodeId,
    /// New entry name (raw bytes).
    pub new_name: &'a [u8],
    /// Request context.
    pub ctx: RequestCtx,
}

/// A single FUSE `symlink` request within a batch.
#[derive(Clone, Debug)]
pub struct SymlinkBatchRequest<'a> {
    /// Parent directory inode.
    pub parent: InodeId,
    /// Symlink entry name (raw bytes).
    pub name: &'a [u8],
    /// Symlink target path (raw bytes).
    pub target: &'a [u8],
    /// Request context.
    pub ctx: RequestCtx,
}

// ── Batch dispatch functions ───────────────────────────────────────────

/// Dispatch a batch of `create` requests through `engine`.
///
/// Returns one result per request in input order.
pub fn dispatch_create_batch(
    engine: &dyn VfsEngine,
    requests: &[CreateBatchRequest<'_>],
) -> Vec<Result<(InodeAttr, EngineFileHandle), Errno>> {
    requests
        .iter()
        .map(|r| {
            if r.flags & O_EXCL != 0 {
                engine.create_excl(r.parent, r.name, r.mode, r.flags, &r.ctx)
            } else {
                engine.create(r.parent, r.name, r.mode, r.flags, &r.ctx)
            }
        })
        .collect()
}

/// Dispatch a batch of `mkdir` requests through `engine`.
pub fn dispatch_mkdir_batch(
    engine: &dyn VfsEngine,
    requests: &[MkdirBatchRequest<'_>],
) -> Vec<Result<InodeAttr, Errno>> {
    requests
        .iter()
        .map(|r| engine.mkdir(r.parent, r.name, r.mode, &r.ctx))
        .collect()
}

/// Dispatch a batch of `unlink` requests through `engine`.
pub fn dispatch_unlink_batch(
    engine: &dyn VfsEngine,
    requests: &[UnlinkBatchRequest<'_>],
) -> Vec<Result<(), Errno>> {
    requests
        .iter()
        .map(|r| engine.unlink(r.parent, r.name, &r.ctx))
        .collect()
}

/// Dispatch a batch of `rmdir` requests through `engine`.
pub fn dispatch_rmdir_batch(
    engine: &dyn VfsEngine,
    requests: &[RmdirBatchRequest<'_>],
) -> Vec<Result<(), Errno>> {
    requests
        .iter()
        .map(|r| engine.rmdir(r.parent, r.name, &r.ctx))
        .collect()
}
/// Dispatch a batch of `link` requests through `engine`.
///
/// Returns one `InodeAttr` result per request in input order.
pub fn dispatch_link_batch(
    engine: &dyn VfsEngine,
    requests: &[LinkBatchRequest<'_>],
) -> Vec<Result<InodeAttr, Errno>> {
    requests
        .iter()
        .map(|r| engine.link(r.target, r.new_parent, r.new_name, &r.ctx))
        .collect()
}

/// Dispatch a batch of `symlink` requests through `engine`.
///
/// Returns one `InodeAttr` result per request in input order.
pub fn dispatch_symlink_batch(
    engine: &dyn VfsEngine,
    requests: &[SymlinkBatchRequest<'_>],
) -> Vec<Result<InodeAttr, Errno>> {
    requests
        .iter()
        .map(|r| engine.symlink(r.parent, r.name, r.target, &r.ctx))
        .collect()
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use tidefs_types_vfs_core::{
        DirEntry, EngineDirHandle, Generation, InodeFlags, NodeKind, PosixAttrs, StatFs,
    };
    use tidefs_vfs_engine::VfsEngineStatFs;

    type DirectoryEntries = Vec<(Vec<u8>, u64)>;
    type DirectoryMap = Mutex<HashMap<u64, DirectoryEntries>>;

    // ── Mock engine ──────────────────────────────────────────────────

    /// Minimal in-memory engine for testing create/mkdir/unlink/rmdir
    /// batch dispatch.  Tracks an inode counter, directory entries,
    /// and per-inode attributes.
    struct MockEngine {
        next_ino: Mutex<u64>,
        attrs: Mutex<HashMap<u64, InodeAttr>>,
        /// parent_ino -> [(name, child_ino)]
        dirs: DirectoryMap,
    }

    impl MockEngine {
        fn new() -> Self {
            let mut attrs = HashMap::new();
            // Pre-populate root inode (ino 1).
            attrs.insert(
                1,
                InodeAttr::new(
                    InodeId::new(1),
                    Generation::new(0),
                    NodeKind::Dir,
                    PosixAttrs::new(
                        0o40755, // directory, rwxr-xr-x
                        1000, 1000, 2,   // nlink (self + parent's "..")
                        0,   // rdev
                        0,   // atime_ns
                        0,   // mtime_ns
                        0,   // ctime_ns
                        0,   // btime_ns
                        0,   // size
                        0,   // blocks_512
                        512, // blksize
                    ),
                    InodeFlags::none(),
                    0, // subtree_rev
                    0, // dir_rev
                ),
            );
            let mut dirs = HashMap::new();
            dirs.insert(1u64, Vec::new());
            Self {
                next_ino: Mutex::new(2),
                attrs: Mutex::new(attrs),
                dirs: Mutex::new(dirs),
            }
        }

        fn alloc_ino(&self) -> u64 {
            let mut n = self.next_ino.lock().unwrap();
            let ino = *n;
            *n += 1;
            ino
        }

        fn lookup_ino(&self, parent: u64, name: &[u8]) -> Option<u64> {
            let dirs = self.dirs.lock().unwrap();
            dirs.get(&parent)
                .and_then(|entries| entries.iter().find(|(n, _)| n.as_slice() == name))
                .map(|(_, ino)| *ino)
        }
    }

    impl VfsEngine for MockEngine {
        fn get_root_inode(&self, _ctx: &RequestCtx) -> Result<InodeId, Errno> {
            Ok(InodeId::new(1))
        }

        fn lookup(
            &self,
            parent: InodeId,
            name: &[u8],
            _ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            let child_ino = self.lookup_ino(parent.get(), name).ok_or(Errno::ENOENT)?;
            let attrs = self.attrs.lock().unwrap();
            attrs.get(&child_ino).copied().ok_or(Errno::ENOENT)
        }

        fn getattr(
            &self,
            inode: InodeId,
            _handle: Option<&EngineFileHandle>,
            _ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            self.attrs
                .lock()
                .unwrap()
                .get(&inode.get())
                .copied()
                .ok_or(Errno::ENOENT)
        }

        fn mkdir(
            &self,
            parent: InodeId,
            name: &[u8],
            mode: u32,
            _ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            if name.is_empty() {
                return Err(Errno::EINVAL);
            }
            let parent_ino = parent.get();
            {
                let attrs = self.attrs.lock().unwrap();
                if !attrs.contains_key(&parent_ino) {
                    return Err(Errno::ENOENT);
                }
                // If the parent exists but is not a directory, return ENOTDIR.
                if let Some(parent_attr) = attrs.get(&parent_ino) {
                    if parent_attr.kind != NodeKind::Dir {
                        return Err(Errno::ENOTDIR);
                    }
                }
            }
            {
                let dirs = self.dirs.lock().unwrap();
                if let Some(entries) = dirs.get(&parent_ino) {
                    if entries.iter().any(|(n, _)| n.as_slice() == name) {
                        return Err(Errno::EEXIST);
                    }
                }
            }
            let ino = self.alloc_ino();
            let dir_mode = 0o40000 | (mode & 0o777);
            let attr = InodeAttr::new(
                InodeId::new(ino),
                Generation::new(ino),
                NodeKind::Dir,
                PosixAttrs::new(
                    dir_mode, 1000, 1000, 2, // nlink: self + parent's ".."
                    0, 0, 0, 0, 0,   // btime
                    0,   // size
                    0,   // blocks_512
                    512, // blksize
                ),
                InodeFlags::none(),
                0,
                0,
            );
            self.attrs.lock().unwrap().insert(ino, attr);
            self.dirs
                .lock()
                .unwrap()
                .entry(parent_ino)
                .or_default()
                .push((name.to_vec(), ino));
            // Initialize empty dir for the new directory.
            self.dirs.lock().unwrap().entry(ino).or_default();
            Ok(attr)
        }

        fn create(
            &self,
            parent: InodeId,
            name: &[u8],
            mode: u32,
            _flags: u32,
            _ctx: &RequestCtx,
        ) -> Result<(InodeAttr, EngineFileHandle), Errno> {
            if name.is_empty() {
                return Err(Errno::EINVAL);
            }
            let parent_ino = parent.get();
            {
                let attrs = self.attrs.lock().unwrap();
                if !attrs.contains_key(&parent_ino) {
                    return Err(Errno::ENOENT);
                }
            }
            {
                let dirs = self.dirs.lock().unwrap();
                if let Some(entries) = dirs.get(&parent_ino) {
                    if entries.iter().any(|(n, _)| n.as_slice() == name) {
                        return Err(Errno::EEXIST);
                    }
                }
            }
            let ino = self.alloc_ino();
            let file_mode = 0o100000 | (mode & 0o7777); // S_IFREG | perms
            let attr = InodeAttr::new(
                InodeId::new(ino),
                Generation::new(ino),
                NodeKind::File,
                PosixAttrs::new(
                    file_mode, 1000, 1000, 1,   // nlink
                    0,   // rdev
                    0,   // atime_ns
                    0,   // mtime_ns
                    0,   // ctime_ns
                    0,   // btime_ns
                    0,   // size
                    0,   // blocks_512
                    512, // blksize
                ),
                InodeFlags::none(),
                0,
                0,
            );
            self.attrs.lock().unwrap().insert(ino, attr);
            self.dirs
                .lock()
                .unwrap()
                .entry(parent_ino)
                .or_default()
                .push((name.to_vec(), ino));

            let fh = EngineFileHandle::new(
                InodeId::new(ino),
                0, // open_flags
                FileHandleId::new(ino),
                0, // lock_owner
            );
            Ok((attr, fh))
        }

        fn unlink(&self, parent: InodeId, name: &[u8], _ctx: &RequestCtx) -> Result<(), Errno> {
            if name.is_empty() {
                return Err(Errno::EINVAL);
            }
            let parent_ino = parent.get();
            let child_ino = self.lookup_ino(parent_ino, name).ok_or(Errno::ENOENT)?;
            // unlink of a directory returns EISDIR.
            {
                let attrs = self.attrs.lock().unwrap();
                if let Some(a) = attrs.get(&child_ino) {
                    if a.kind == NodeKind::Dir {
                        return Err(Errno::EISDIR);
                    }
                }
            }
            // Remove entry from parent directory.
            {
                let mut dirs = self.dirs.lock().unwrap();
                if let Some(entries) = dirs.get_mut(&parent_ino) {
                    entries.retain(|(n, _)| n.as_slice() != name);
                }
            }
            // Decrement nlink; remove inode if nlink reaches 0.
            {
                let mut attrs = self.attrs.lock().unwrap();
                if let Some(a) = attrs.get_mut(&child_ino) {
                    a.posix.nlink = a.posix.nlink.saturating_sub(1);
                    if a.posix.nlink == 0 {
                        attrs.remove(&child_ino);
                    }
                }
            }
            Ok(())
        }

        fn rmdir(&self, parent: InodeId, name: &[u8], _ctx: &RequestCtx) -> Result<(), Errno> {
            if name.is_empty() {
                return Err(Errno::EINVAL);
            }
            let parent_ino = parent.get();
            {
                let attrs = self.attrs.lock().unwrap();
                if !attrs.contains_key(&parent_ino) {
                    return Err(Errno::ENOENT);
                }
            }
            let child_ino = self.lookup_ino(parent_ino, name).ok_or(Errno::ENOENT)?;
            // Check child is a directory.
            {
                let attrs = self.attrs.lock().unwrap();
                let child = attrs.get(&child_ino).ok_or(Errno::ENOENT)?;
                if child.kind != NodeKind::Dir {
                    return Err(Errno::ENOTDIR);
                }
            }
            // Check child directory is empty.
            {
                let dirs = self.dirs.lock().unwrap();
                if let Some(entries) = dirs.get(&child_ino) {
                    if !entries.is_empty() {
                        return Err(Errno::ENOTEMPTY);
                    }
                }
            }
            // Remove entry from parent.
            {
                let mut dirs = self.dirs.lock().unwrap();
                if let Some(entries) = dirs.get_mut(&parent_ino) {
                    entries.retain(|(n, _)| n.as_slice() != name);
                }
                dirs.remove(&child_ino);
            }
            // Remove child inode.
            self.attrs.lock().unwrap().remove(&child_ino);
            Ok(())
        }

        fn tmpfile(
            &self,
            _parent: InodeId,
            _mode: u32,
            _flags: u32,
            _ctx: &RequestCtx,
        ) -> Result<(InodeAttr, EngineFileHandle), Errno> {
            Err(Errno::ENOSYS)
        }

        fn setattr(
            &self,
            _inode: InodeId,
            _attr: &tidefs_vfs_engine::SetAttr,
            _handle: Option<&EngineFileHandle>,
            _ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }

        fn rename(
            &self,
            _old_parent: InodeId,
            _old_name: &[u8],
            _new_parent: InodeId,
            _new_name: &[u8],
            _flags: u32,
            _ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }

        fn link(
            &self,
            target: InodeId,
            new_parent: InodeId,
            new_name: &[u8],
            _ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            if new_name.is_empty() {
                return Err(Errno::EINVAL);
            }
            let target_ino = target.get();
            let new_parent_ino = new_parent.get();
            {
                let attrs = self.attrs.lock().unwrap();
                let target_attr = attrs.get(&target_ino).ok_or(Errno::ENOENT)?;
                if target_attr.kind == NodeKind::Dir {
                    return Err(Errno::EPERM);
                }
                if target_attr.posix.nlink >= 65_535 {
                    return Err(Errno::EMLINK);
                }
            }
            {
                let attrs = self.attrs.lock().unwrap();
                if !attrs.contains_key(&new_parent_ino) {
                    return Err(Errno::ENOENT);
                }
            }
            {
                let dirs = self.dirs.lock().unwrap();
                if let Some(entries) = dirs.get(&new_parent_ino) {
                    if entries.iter().any(|(n, _)| n.as_slice() == new_name) {
                        return Err(Errno::EEXIST);
                    }
                }
            }
            self.dirs
                .lock()
                .unwrap()
                .entry(new_parent_ino)
                .or_default()
                .push((new_name.to_vec(), target_ino));
            let attr = {
                let mut attrs = self.attrs.lock().unwrap();
                let a = attrs.get_mut(&target_ino).unwrap();
                a.posix.nlink = a.posix.nlink.saturating_add(1);
                *a
            };
            Ok(attr)
        }

        fn symlink(
            &self,
            _parent: InodeId,
            _name: &[u8],
            _target: &[u8],
            _ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }

        fn readlink(&self, _inode: InodeId, _ctx: &RequestCtx) -> Result<Vec<u8>, Errno> {
            Err(Errno::ENOSYS)
        }

        fn mknod(
            &self,
            _parent: InodeId,
            _name: &[u8],
            _mode: u32,
            _rdev: u32,
            _ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }

        fn open(
            &self,
            _inode: InodeId,
            _flags: u32,
            _ctx: &RequestCtx,
        ) -> Result<EngineFileHandle, Errno> {
            Err(Errno::ENOSYS)
        }

        fn release(&self, _fh: &EngineFileHandle) -> Result<(), Errno> {
            Ok(())
        }

        fn read(
            &self,
            _fh: &EngineFileHandle,
            _offset: u64,
            _size: u32,
            _ctx: &RequestCtx,
        ) -> Result<Vec<u8>, Errno> {
            Err(Errno::ENOSYS)
        }

        fn write(
            &self,
            _fh: &EngineFileHandle,
            _offset: u64,
            _data: &[u8],
            _ctx: &RequestCtx,
        ) -> Result<u32, Errno> {
            Err(Errno::ENOSYS)
        }

        fn flush(&self, _fh: &EngineFileHandle, _ctx: &RequestCtx) -> Result<(), Errno> {
            Ok(())
        }

        fn fsync(
            &self,
            _fh: &EngineFileHandle,
            _datasync: bool,
            _ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            Ok(())
        }

        fn fallocate(
            &self,
            _fh: &EngineFileHandle,
            _mode: u32,
            _offset: u64,
            _length: u64,
            _ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            Err(Errno::EOPNOTSUPP)
        }

        fn opendir(&self, _inode: InodeId, _ctx: &RequestCtx) -> Result<EngineDirHandle, Errno> {
            Err(Errno::ENOSYS)
        }

        fn releasedir(&self, _dh: &EngineDirHandle) -> Result<(), Errno> {
            Ok(())
        }

        fn readdir(
            &self,
            _dh: &EngineDirHandle,
            _offset: u64,
            _ctx: &RequestCtx,
        ) -> Result<(Vec<DirEntry>, bool), Errno> {
            Err(Errno::ENOSYS)
        }

        fn fsyncdir(
            &self,
            _dh: &EngineDirHandle,
            _datasync: bool,
            _ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            Ok(())
        }

        fn getxattr(
            &self,
            _inode: InodeId,
            _name: &[u8],
            _ctx: &RequestCtx,
        ) -> Result<Vec<u8>, Errno> {
            Err(Errno::ENODATA)
        }

        fn setxattr(
            &self,
            _inode: InodeId,
            _name: &[u8],
            _value: &[u8],
            _flags: u32,
            _ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }

        fn listxattr(&self, _inode: InodeId, _ctx: &RequestCtx) -> Result<Vec<u8>, Errno> {
            Err(Errno::ENODATA)
        }

        fn removexattr(
            &self,
            _inode: InodeId,
            _name: &[u8],
            _ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            Err(Errno::ENODATA)
        }

        fn getlk(
            &self,
            _inode: tidefs_types_vfs_core::InodeId,
            _lock: &tidefs_types_vfs_core::LockSpec,
            _ctx: &tidefs_types_vfs_core::RequestCtx,
        ) -> std::result::Result<
            std::option::Option<tidefs_types_vfs_core::LockSpec>,
            tidefs_types_vfs_core::Errno,
        > {
            Err(tidefs_types_vfs_core::Errno::ENOSYS)
        }

        fn setlk(
            &self,
            _inode: tidefs_types_vfs_core::InodeId,
            _lock: &tidefs_types_vfs_core::LockSpec,
            _ctx: &tidefs_types_vfs_core::RequestCtx,
        ) -> std::result::Result<(), tidefs_types_vfs_core::Errno> {
            Err(tidefs_types_vfs_core::Errno::ENOSYS)
        }
    }

    impl VfsEngineStatFs for MockEngine {
        fn statfs(&self, _ctx: &RequestCtx) -> Result<StatFs, Errno> {
            Err(Errno::ENOSYS)
        }
    }

    fn test_ctx() -> RequestCtx {
        RequestCtx::new(1000, 1000, 42, 0o022, Vec::new())
    }

    // ── dispatch_create_batch tests ──────────────────────────────────

    #[test]
    fn create_single_file_in_empty_directory() {
        let engine = MockEngine::new();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        let requests = [CreateBatchRequest {
            parent: root,
            name: b"hello.txt",
            mode: 0o644,
            flags: 0,
            ctx: ctx.clone(),
        }];

        let results = dispatch_create_batch(&engine, &requests);
        assert_eq!(results.len(), 1);

        let (attr, fh) = &results[0].as_ref().expect("create should succeed");

        // st_mode: S_IFREG | 0644 = 0o100644 = 33188
        assert_eq!(
            attr.posix.mode, 0o100644,
            "file mode should be S_IFREG|0644"
        );
        assert_eq!(attr.kind, NodeKind::File, "node kind should be File");
        assert_eq!(attr.posix.nlink, 1, "new file should have nlink=1");

        // File handle is valid.
        assert!(fh.fh_id.0 > 0);

        // Lookup via engine should find it.
        let looked_up = engine
            .lookup(root, b"hello.txt", &ctx)
            .expect("lookup after create");
        assert_eq!(looked_up.posix.mode, 0o100644);
        assert_eq!(looked_up.posix.nlink, 1);
    }

    #[test]
    fn create_multiple_files_in_single_batch() {
        let engine = MockEngine::new();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        let requests = [
            CreateBatchRequest {
                parent: root,
                name: b"a.txt",
                mode: 0o644,
                flags: 0,
                ctx: ctx.clone(),
            },
            CreateBatchRequest {
                parent: root,
                name: b"b.txt",
                mode: 0o600,
                flags: 0,
                ctx: ctx.clone(),
            },
        ];

        let results = dispatch_create_batch(&engine, &requests);
        assert_eq!(results.len(), 2);

        let (a_attr, _) = results[0].as_ref().expect("create a.txt");
        let (b_attr, _) = results[1].as_ref().expect("create b.txt");

        assert_ne!(a_attr.inode_id, b_attr.inode_id, "different inodes");
        assert_eq!(a_attr.posix.mode, 0o100644);
        assert_eq!(b_attr.posix.mode, 0o100600);
    }

    #[test]
    fn create_duplicate_name_returns_eexist() {
        let engine = MockEngine::new();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        let r1 = [CreateBatchRequest {
            parent: root,
            name: b"dup.txt",
            mode: 0o644,
            flags: 0,
            ctx: ctx.clone(),
        }];
        let _ = dispatch_create_batch(&engine, &r1);

        let r2 = [CreateBatchRequest {
            parent: root,
            name: b"dup.txt",
            mode: 0o755,
            flags: 0,
            ctx: ctx.clone(),
        }];
        let results = dispatch_create_batch(&engine, &r2);
        assert_eq!(results[0].as_ref().unwrap_err().0, libc::EEXIST as u16);
    }

    #[test]
    fn create_missing_parent_returns_enoent() {
        let engine = MockEngine::new();
        let ctx = test_ctx();
        let nonexistent = InodeId::new(999);

        let requests = [CreateBatchRequest {
            parent: nonexistent,
            name: b"orphan.txt",
            mode: 0o644,
            flags: 0,
            ctx: ctx.clone(),
        }];

        let results = dispatch_create_batch(&engine, &requests);
        assert_eq!(results[0].as_ref().unwrap_err().0, libc::ENOENT as u16);
    }

    #[test]
    fn mkdir_single_directory() {
        let engine = MockEngine::new();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        let requests = [MkdirBatchRequest {
            parent: root,
            name: b"subdir",
            mode: 0o755,
            ctx: ctx.clone(),
        }];

        let results = dispatch_mkdir_batch(&engine, &requests);
        assert_eq!(results.len(), 1);

        let attr = results[0].as_ref().expect("mkdir should succeed");
        assert_eq!(attr.kind, NodeKind::Dir);
        assert_eq!(attr.posix.nlink, 2, "new dir must have nlink=2");
        assert_eq!(attr.posix.mode & 0o170000, 0o40000, "S_IFDIR bit set");
        assert_eq!(attr.posix.mode & 0o777, 0o755, "permissions preserved");

        let looked_up = engine
            .lookup(root, b"subdir", &ctx)
            .expect("lookup after mkdir");
        assert_eq!(looked_up.kind, NodeKind::Dir);
    }

    #[test]
    fn mkdir_duplicate_name_returns_eexist() {
        let engine = MockEngine::new();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        let r1 = [MkdirBatchRequest {
            parent: root,
            name: b"dupdir",
            mode: 0o755,
            ctx: ctx.clone(),
        }];
        let _ = dispatch_mkdir_batch(&engine, &r1);

        let r2 = [MkdirBatchRequest {
            parent: root,
            name: b"dupdir",
            mode: 0o700,
            ctx: ctx.clone(),
        }];
        let results = dispatch_mkdir_batch(&engine, &r2);
        assert_eq!(results[0].as_ref().unwrap_err().0, libc::EEXIST as u16);
    }

    #[test]
    fn mkdir_missing_parent_returns_enoent() {
        let engine = MockEngine::new();
        let ctx = test_ctx();
        let nonexistent = InodeId::new(999);

        let requests = [MkdirBatchRequest {
            parent: nonexistent,
            name: b"orphan",
            mode: 0o755,
            ctx: ctx.clone(),
        }];

        let results = dispatch_mkdir_batch(&engine, &requests);
        assert_eq!(results[0].as_ref().unwrap_err().0, libc::ENOENT as u16);
    }

    #[test]
    fn unlink_removes_file_and_inode() {
        let engine = MockEngine::new();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        let cr = [CreateBatchRequest {
            parent: root,
            name: b"victim.txt",
            mode: 0o644,
            flags: 0,
            ctx: ctx.clone(),
        }];
        let create_results = dispatch_create_batch(&engine, &cr);
        let (created, _) = create_results[0].as_ref().expect("create");

        assert!(engine.lookup(root, b"victim.txt", &ctx).is_ok());

        let ur = [UnlinkBatchRequest {
            parent: root,
            name: b"victim.txt",
            ctx: ctx.clone(),
        }];
        let results = dispatch_unlink_batch(&engine, &ur);
        assert!(results[0].is_ok());

        assert!(engine.lookup(root, b"victim.txt", &ctx).is_err());
        assert!(engine.getattr(created.inode_id, None, &ctx).is_err());
    }

    #[test]
    fn unlink_nonexistent_returns_enoent() {
        let engine = MockEngine::new();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        let requests = [UnlinkBatchRequest {
            parent: root,
            name: b"ghost",
            ctx: ctx.clone(),
        }];

        let results = dispatch_unlink_batch(&engine, &requests);
        assert_eq!(results[0].as_ref().unwrap_err().0, libc::ENOENT as u16);
    }

    #[test]
    fn rmdir_removes_empty_directory() {
        let engine = MockEngine::new();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        let mr = [MkdirBatchRequest {
            parent: root,
            name: b"emptydir",
            mode: 0o755,
            ctx: ctx.clone(),
        }];
        let mkdir_results = dispatch_mkdir_batch(&engine, &mr);
        let created = mkdir_results[0].as_ref().expect("mkdir");

        assert!(engine.lookup(root, b"emptydir", &ctx).is_ok());

        let rr = [RmdirBatchRequest {
            parent: root,
            name: b"emptydir",
            ctx: ctx.clone(),
        }];
        let results = dispatch_rmdir_batch(&engine, &rr);
        assert!(results[0].is_ok());

        assert!(engine.lookup(root, b"emptydir", &ctx).is_err());
        assert!(engine.getattr(created.inode_id, None, &ctx).is_err());
    }

    #[test]
    fn rmdir_nonexistent_returns_enoent() {
        let engine = MockEngine::new();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        let requests = [RmdirBatchRequest {
            parent: root,
            name: b"nodir",
            ctx: ctx.clone(),
        }];

        let results = dispatch_rmdir_batch(&engine, &requests);
        assert_eq!(results[0].as_ref().unwrap_err().0, libc::ENOENT as u16);
    }

    #[test]
    fn rmdir_nonempty_returns_enotempty() {
        let engine = MockEngine::new();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        let mr = [MkdirBatchRequest {
            parent: root,
            name: b"parentdir",
            mode: 0o755,
            ctx: ctx.clone(),
        }];
        let mkdir_results = dispatch_mkdir_batch(&engine, &mr);
        let parent_attr = mkdir_results[0].as_ref().expect("mkdir");

        let cr = [CreateBatchRequest {
            parent: parent_attr.inode_id,
            name: b"child.txt",
            mode: 0o644,
            flags: 0,
            ctx: ctx.clone(),
        }];
        let _ = dispatch_create_batch(&engine, &cr);

        let rr = [RmdirBatchRequest {
            parent: root,
            name: b"parentdir",
            ctx: ctx.clone(),
        }];
        let results = dispatch_rmdir_batch(&engine, &rr);
        assert_eq!(results[0].as_ref().unwrap_err().0, libc::ENOTEMPTY as u16);
    }
    // ── Edge-case and error-path tests ──────────────────────────────────

    #[test]
    fn create_zero_length_name_returns_einval() {
        let engine = MockEngine::new();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        let requests = [CreateBatchRequest {
            parent: root,
            name: b"",
            mode: 0o644,
            flags: 0,
            ctx: ctx.clone(),
        }];

        let results = dispatch_create_batch(&engine, &requests);
        assert_eq!(results[0].as_ref().unwrap_err().0, libc::EINVAL as u16);
    }

    #[test]
    fn create_empty_batch_returns_empty_vec() {
        let engine = MockEngine::new();
        let results = dispatch_create_batch(&engine, &[]);
        assert!(results.is_empty());
    }

    #[test]
    fn mkdir_zero_length_name_returns_einval() {
        let engine = MockEngine::new();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        let requests = [MkdirBatchRequest {
            parent: root,
            name: b"",
            mode: 0o755,
            ctx: ctx.clone(),
        }];

        let results = dispatch_mkdir_batch(&engine, &requests);
        assert_eq!(results[0].as_ref().unwrap_err().0, libc::EINVAL as u16);
    }

    #[test]
    fn mkdir_in_file_parent_returns_enotdir() {
        let engine = MockEngine::new();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        // Create a regular file to use as a parent.
        let cr = [CreateBatchRequest {
            parent: root,
            name: b"regular_file",
            mode: 0o644,
            flags: 0,
            ctx: ctx.clone(),
        }];
        let create_results = dispatch_create_batch(&engine, &cr);
        let (file_attr, _) = create_results[0].as_ref().expect("create regular file");

        // Attempt mkdir using the regular file as parent.
        let requests = [MkdirBatchRequest {
            parent: file_attr.inode_id,
            name: b"subdir",
            mode: 0o755,
            ctx: ctx.clone(),
        }];

        let results = dispatch_mkdir_batch(&engine, &requests);
        assert_eq!(results[0].as_ref().unwrap_err().0, libc::ENOTDIR as u16);
    }

    #[test]
    fn mkdir_empty_batch_returns_empty_vec() {
        let engine = MockEngine::new();
        let results = dispatch_mkdir_batch(&engine, &[]);
        assert!(results.is_empty());
    }

    #[test]
    fn unlink_zero_length_name_returns_einval() {
        let engine = MockEngine::new();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        let requests = [UnlinkBatchRequest {
            parent: root,
            name: b"",
            ctx: ctx.clone(),
        }];

        let results = dispatch_unlink_batch(&engine, &requests);
        assert_eq!(results[0].as_ref().unwrap_err().0, libc::EINVAL as u16);
    }

    #[test]
    fn unlink_directory_returns_eisdir() {
        let engine = MockEngine::new();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        // Create a subdirectory.
        let mr = [MkdirBatchRequest {
            parent: root,
            name: b"adir",
            mode: 0o755,
            ctx: ctx.clone(),
        }];
        let _ = dispatch_mkdir_batch(&engine, &mr);

        // Attempt unlink on the directory (should fail with EISDIR).
        let requests = [UnlinkBatchRequest {
            parent: root,
            name: b"adir",
            ctx: ctx.clone(),
        }];

        let results = dispatch_unlink_batch(&engine, &requests);
        assert_eq!(results[0].as_ref().unwrap_err().0, libc::EISDIR as u16);
    }

    #[test]
    fn unlink_empty_batch_returns_empty_vec() {
        let engine = MockEngine::new();
        let results = dispatch_unlink_batch(&engine, &[]);
        assert!(results.is_empty());
    }

    #[test]
    fn rmdir_zero_length_name_returns_einval() {
        let engine = MockEngine::new();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        let requests = [RmdirBatchRequest {
            parent: root,
            name: b"",
            ctx: ctx.clone(),
        }];

        let results = dispatch_rmdir_batch(&engine, &requests);
        assert_eq!(results[0].as_ref().unwrap_err().0, libc::EINVAL as u16);
    }

    #[test]
    fn rmdir_file_returns_enotdir() {
        let engine = MockEngine::new();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        // Create a regular file.
        let cr = [CreateBatchRequest {
            parent: root,
            name: b"somefile",
            mode: 0o644,
            flags: 0,
            ctx: ctx.clone(),
        }];
        let _ = dispatch_create_batch(&engine, &cr);

        // Attempt rmdir on a regular file.
        let requests = [RmdirBatchRequest {
            parent: root,
            name: b"somefile",
            ctx: ctx.clone(),
        }];

        let results = dispatch_rmdir_batch(&engine, &requests);
        assert_eq!(results[0].as_ref().unwrap_err().0, libc::ENOTDIR as u16);
    }

    #[test]
    fn rmdir_empty_batch_returns_empty_vec() {
        let engine = MockEngine::new();
        let results = dispatch_rmdir_batch(&engine, &[]);
        assert!(results.is_empty());
    }

    #[test]
    fn batch_partial_failure_mixed_valid_invalid() {
        let engine = MockEngine::new();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        // First request valid, second has an empty name (invalid).
        let requests = [
            CreateBatchRequest {
                parent: root,
                name: b"valid.txt",
                mode: 0o644,
                flags: 0,
                ctx: ctx.clone(),
            },
            CreateBatchRequest {
                parent: root,
                name: b"",
                mode: 0o600,
                flags: 0,
                ctx: ctx.clone(),
            },
        ];

        let results = dispatch_create_batch(&engine, &requests);
        assert_eq!(results.len(), 2);
        // First entry must succeed.
        assert!(results[0].is_ok(), "valid entry should succeed");
        // Second entry must fail with EINVAL.
        assert_eq!(
            results[1].as_ref().unwrap_err().0,
            libc::EINVAL as u16,
            "invalid entry should be EINVAL"
        );
        // The valid file should still exist.
        assert!(engine.lookup(root, b"valid.txt", &ctx).is_ok());
    }

    // ── dispatch_link_batch tests ─────────────────────────────────────

    #[test]
    fn link_creates_hard_link_and_increments_nlink() {
        let engine = MockEngine::new();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        // Create a source file.
        let cr = [CreateBatchRequest {
            parent: root,
            name: b"source.txt",
            mode: 0o644,
            flags: 0,
            ctx: ctx.clone(),
        }];
        let create_results = dispatch_create_batch(&engine, &cr);
        let (source_attr, _) = create_results[0].as_ref().expect("create source");

        assert_eq!(source_attr.posix.nlink, 1, "new file nlink=1");

        // Link source to new name.
        let lr = [LinkBatchRequest {
            target: source_attr.inode_id,
            new_parent: root,
            new_name: b"alias.txt",
            ctx: ctx.clone(),
        }];
        let link_results = dispatch_link_batch(&engine, &lr);
        let linked_attr = link_results[0].as_ref().expect("link should succeed");

        // Same inode, nlink=2.
        assert_eq!(linked_attr.inode_id, source_attr.inode_id);
        assert_eq!(linked_attr.posix.nlink, 2);

        // Both lookups find the same inode.
        let looked_src = engine
            .lookup(root, b"source.txt", &ctx)
            .expect("lookup source");
        let looked_alias = engine
            .lookup(root, b"alias.txt", &ctx)
            .expect("lookup alias");
        assert_eq!(looked_src.inode_id, source_attr.inode_id);
        assert_eq!(looked_alias.inode_id, source_attr.inode_id);
    }

    #[test]
    fn link_directory_returns_eperm() {
        let engine = MockEngine::new();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        // Create a directory.
        let mr = [MkdirBatchRequest {
            parent: root,
            name: b"subdir",
            mode: 0o755,
            ctx: ctx.clone(),
        }];
        let mkdir_results = dispatch_mkdir_batch(&engine, &mr);
        let dir_attr = mkdir_results[0].as_ref().expect("mkdir");

        // Attempt to link the directory.
        let lr = [LinkBatchRequest {
            target: dir_attr.inode_id,
            new_parent: root,
            new_name: b"dir_link",
            ctx: ctx.clone(),
        }];
        let results = dispatch_link_batch(&engine, &lr);
        assert_eq!(results[0].as_ref().unwrap_err().0, libc::EPERM as u16);
    }

    #[test]
    fn link_to_existing_name_returns_eexist() {
        let engine = MockEngine::new();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        // Create source and existing target.
        let cr = [CreateBatchRequest {
            parent: root,
            name: b"source.txt",
            mode: 0o644,
            flags: 0,
            ctx: ctx.clone(),
        }];
        let create_results = dispatch_create_batch(&engine, &cr);
        let (source_attr, _) = create_results[0].as_ref().expect("create source");

        let cr2 = [CreateBatchRequest {
            parent: root,
            name: b"existing.txt",
            mode: 0o644,
            flags: 0,
            ctx: ctx.clone(),
        }];
        let _ = dispatch_create_batch(&engine, &cr2);

        // Attempt to link source to existing name.
        let lr = [LinkBatchRequest {
            target: source_attr.inode_id,
            new_parent: root,
            new_name: b"existing.txt",
            ctx: ctx.clone(),
        }];
        let results = dispatch_link_batch(&engine, &lr);
        assert_eq!(results[0].as_ref().unwrap_err().0, libc::EEXIST as u16);
    }

    #[test]
    fn link_nonexistent_target_returns_enoent() {
        let engine = MockEngine::new();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        let lr = [LinkBatchRequest {
            target: InodeId::new(9999),
            new_parent: root,
            new_name: b"orphan.txt",
            ctx: ctx.clone(),
        }];
        let results = dispatch_link_batch(&engine, &lr);
        assert_eq!(results[0].as_ref().unwrap_err().0, libc::ENOENT as u16);
    }

    #[test]
    fn link_nonexistent_parent_returns_enoent() {
        let engine = MockEngine::new();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        // Create source file.
        let cr = [CreateBatchRequest {
            parent: root,
            name: b"source.txt",
            mode: 0o644,
            flags: 0,
            ctx: ctx.clone(),
        }];
        let create_results = dispatch_create_batch(&engine, &cr);
        let (source_attr, _) = create_results[0].as_ref().expect("create");

        // Link into nonexistent parent.
        let lr = [LinkBatchRequest {
            target: source_attr.inode_id,
            new_parent: InodeId::new(9999),
            new_name: b"ghost.txt",
            ctx: ctx.clone(),
        }];
        let results = dispatch_link_batch(&engine, &lr);
        assert_eq!(results[0].as_ref().unwrap_err().0, libc::ENOENT as u16);
    }

    #[test]
    fn link_zero_length_name_returns_einval() {
        let engine = MockEngine::new();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        // Create source file.
        let cr = [CreateBatchRequest {
            parent: root,
            name: b"source.txt",
            mode: 0o644,
            flags: 0,
            ctx: ctx.clone(),
        }];
        let create_results = dispatch_create_batch(&engine, &cr);
        let (source_attr, _) = create_results[0].as_ref().expect("create");

        let lr = [LinkBatchRequest {
            target: source_attr.inode_id,
            new_parent: root,
            new_name: b"",
            ctx: ctx.clone(),
        }];
        let results = dispatch_link_batch(&engine, &lr);
        assert_eq!(results[0].as_ref().unwrap_err().0, libc::EINVAL as u16);
    }

    #[test]
    fn unlink_one_hard_link_preserves_other_and_nlink() {
        let engine = MockEngine::new();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        // Create source file and link it.
        let cr = [CreateBatchRequest {
            parent: root,
            name: b"source.txt",
            mode: 0o644,
            flags: 0,
            ctx: ctx.clone(),
        }];
        let create_results = dispatch_create_batch(&engine, &cr);
        let (source_attr, _) = create_results[0].as_ref().expect("create");

        let lr = [LinkBatchRequest {
            target: source_attr.inode_id,
            new_parent: root,
            new_name: b"alias.txt",
            ctx: ctx.clone(),
        }];
        let link_results = dispatch_link_batch(&engine, &lr);
        let linked = link_results[0].as_ref().expect("link");
        assert_eq!(linked.posix.nlink, 2);

        // Unlink the original name.
        let ur = [UnlinkBatchRequest {
            parent: root,
            name: b"source.txt",
            ctx: ctx.clone(),
        }];
        dispatch_unlink_batch(&engine, &ur);

        // Alias still accessible, nlink=1.
        let attr = engine
            .getattr(source_attr.inode_id, None, &ctx)
            .expect("getattr");
        assert_eq!(attr.posix.nlink, 1);
        assert!(engine.lookup(root, b"alias.txt", &ctx).is_ok());
        assert!(engine.lookup(root, b"source.txt", &ctx).is_err());
    }

    #[test]
    fn link_cross_directory() {
        let engine = MockEngine::new();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        // Create source file in root.
        let cr = [CreateBatchRequest {
            parent: root,
            name: b"source.txt",
            mode: 0o644,
            flags: 0,
            ctx: ctx.clone(),
        }];
        let create_results = dispatch_create_batch(&engine, &cr);
        let (source_attr, _) = create_results[0].as_ref().expect("create");

        // Create subdirectory.
        let mr = [MkdirBatchRequest {
            parent: root,
            name: b"subdir",
            mode: 0o755,
            ctx: ctx.clone(),
        }];
        let mkdir_results = dispatch_mkdir_batch(&engine, &mr);
        let subdir_attr = mkdir_results[0].as_ref().expect("mkdir");

        // Link source into subdirectory.
        let lr = [LinkBatchRequest {
            target: source_attr.inode_id,
            new_parent: subdir_attr.inode_id,
            new_name: b"cross.txt",
            ctx: ctx.clone(),
        }];
        let link_results = dispatch_link_batch(&engine, &lr);
        let linked = link_results[0].as_ref().expect("cross-dir link");

        assert_eq!(linked.inode_id, source_attr.inode_id);
        assert_eq!(linked.posix.nlink, 2);

        // Lookup in subdirectory finds it.
        let looked = engine
            .lookup(subdir_attr.inode_id, b"cross.txt", &ctx)
            .expect("lookup in subdir");
        assert_eq!(looked.inode_id, source_attr.inode_id);
    }

    #[test]
    fn link_multiple_aliases_increment_nlink_correctly() {
        let engine = MockEngine::new();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        // Create source file.
        let cr = [CreateBatchRequest {
            parent: root,
            name: b"orig.txt",
            mode: 0o644,
            flags: 0,
            ctx: ctx.clone(),
        }];
        let create_results = dispatch_create_batch(&engine, &cr);
        let (source_attr, _) = create_results[0].as_ref().expect("create");
        assert_eq!(source_attr.posix.nlink, 1);

        // Create 3 links.
        for i in 1..=3u32 {
            let name = format!("link{i}.txt");
            let lr = [LinkBatchRequest {
                target: source_attr.inode_id,
                new_parent: root,
                new_name: name.as_bytes(),
                ctx: ctx.clone(),
            }];
            let results = dispatch_link_batch(&engine, &lr);
            let attr = results[0].as_ref().unwrap_or_else(|_| panic!("link {i}"));
            assert_eq!(attr.posix.nlink, 1 + i);
        }

        let final_attr = engine
            .getattr(source_attr.inode_id, None, &ctx)
            .expect("getattr");
        assert_eq!(final_attr.posix.nlink, 4);
    }

    #[test]
    fn link_empty_batch_returns_empty_vec() {
        let engine = MockEngine::new();
        let results = dispatch_link_batch(&engine, &[]);
        assert!(results.is_empty());
    }
}

// ── Parent directory timestamp tests using real VfsLocalFileSystem ─────

#[cfg(test)]
mod parent_timestamp_dispatch_tests {
    use super::*;
    use tidefs_local_filesystem::{
        human::local_filesystem::StoreOptions, vfs_engine_impl::VfsLocalFileSystem,
        LocalFileSystem, RootAuthenticationKey,
    };
    use tidefs_types_vfs_core::RequestCtx;

    fn test_engine() -> (tempfile::TempDir, Box<dyn VfsEngine + Send>) {
        let tmp = tempfile::tempdir().expect("tempdir for dispatch timestamp tests");
        let lfs = LocalFileSystem::open_with_root_authentication_key(
            tmp.path(),
            StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("open local filesystem");
        let engine = Box::new(VfsLocalFileSystem::new(lfs));
        (tmp, engine)
    }

    fn test_ctx() -> RequestCtx {
        RequestCtx {
            uid: 0,
            gid: 0,
            pid: 0,
            umask: 0,
            groups: vec![0],
        }
    }

    fn get_timestamps(engine: &dyn VfsEngine, ino: InodeId, ctx: &RequestCtx) -> (i64, i64) {
        let attr = engine.getattr(ino, None, ctx).expect("getattr");
        (attr.posix.mtime_ns, attr.posix.ctime_ns)
    }

    #[test]
    fn dispatch_mkdir_updates_parent_timestamps() {
        let (_tmp, engine) = test_engine();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        let (mtime_before, ctime_before) = get_timestamps(engine.as_ref(), root, &ctx);
        std::thread::sleep(std::time::Duration::from_millis(1));

        let requests = [MkdirBatchRequest {
            parent: root,
            name: b"dispatch_dir",
            mode: 0o755,
            ctx: ctx.clone(),
        }];
        let results = dispatch_mkdir_batch(engine.as_ref(), &requests);
        assert!(results[0].is_ok());

        let (mtime_after, ctime_after) = get_timestamps(engine.as_ref(), root, &ctx);
        assert!(mtime_after > mtime_before, "parent mtime must advance");
        assert!(ctime_after > ctime_before, "parent ctime must advance");
    }

    #[test]
    fn dispatch_create_updates_parent_timestamps() {
        let (_tmp, engine) = test_engine();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        let (mtime_before, ctime_before) = get_timestamps(engine.as_ref(), root, &ctx);
        std::thread::sleep(std::time::Duration::from_millis(1));

        let requests = [CreateBatchRequest {
            parent: root,
            name: b"dispatch_file",
            mode: 0o644,
            flags: 0,
            ctx: ctx.clone(),
        }];
        let results = dispatch_create_batch(engine.as_ref(), &requests);
        assert!(results[0].is_ok());

        let (mtime_after, ctime_after) = get_timestamps(engine.as_ref(), root, &ctx);
        assert!(mtime_after > mtime_before, "parent mtime must advance");
        assert!(ctime_after > ctime_before, "parent ctime must advance");
    }

    #[test]
    fn dispatch_unlink_updates_parent_timestamps() {
        let (_tmp, engine) = test_engine();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        // Create file first via dispatch.
        let cr = [CreateBatchRequest {
            parent: root,
            name: b"to_unlink",
            mode: 0o644,
            flags: 0,
            ctx: ctx.clone(),
        }];
        let create_results = dispatch_create_batch(engine.as_ref(), &cr);
        let (_, fh) = create_results[0].as_ref().unwrap();
        // Release the file handle so unlink can proceed.
        engine.release(fh).expect("release handle");

        let (mtime_before, ctime_before) = get_timestamps(engine.as_ref(), root, &ctx);
        std::thread::sleep(std::time::Duration::from_millis(1));

        let ur = [UnlinkBatchRequest {
            parent: root,
            name: b"to_unlink",
            ctx: ctx.clone(),
        }];
        let results = dispatch_unlink_batch(engine.as_ref(), &ur);
        assert!(results[0].is_ok());

        let (mtime_after, ctime_after) = get_timestamps(engine.as_ref(), root, &ctx);
        assert!(mtime_after > mtime_before, "parent mtime must advance");
        assert!(ctime_after > ctime_before, "parent ctime must advance");
    }

    #[test]
    fn dispatch_rmdir_updates_parent_timestamps() {
        let (_tmp, engine) = test_engine();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        // Create empty directory first.
        let mr = [MkdirBatchRequest {
            parent: root,
            name: b"to_rmdir",
            mode: 0o755,
            ctx: ctx.clone(),
        }];
        dispatch_mkdir_batch(engine.as_ref(), &mr);

        let (mtime_before, ctime_before) = get_timestamps(engine.as_ref(), root, &ctx);
        std::thread::sleep(std::time::Duration::from_millis(1));

        let rr = [RmdirBatchRequest {
            parent: root,
            name: b"to_rmdir",
            ctx: ctx.clone(),
        }];
        let results = dispatch_rmdir_batch(engine.as_ref(), &rr);
        assert!(results[0].is_ok());

        let (mtime_after, ctime_after) = get_timestamps(engine.as_ref(), root, &ctx);
        assert!(mtime_after > mtime_before, "parent mtime must advance");
        assert!(ctime_after > ctime_before, "parent ctime must advance");
    }

    #[test]
    fn dispatch_link_updates_new_parent_timestamps() {
        let (_tmp, engine) = test_engine();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        // Create source file and subdirectory.
        let cr = [CreateBatchRequest {
            parent: root,
            name: b"link_src",
            mode: 0o644,
            flags: 0,
            ctx: ctx.clone(),
        }];
        let create_results = dispatch_create_batch(engine.as_ref(), &cr);
        let (src_attr, src_fh) = create_results[0].as_ref().unwrap();
        engine.release(src_fh).expect("release source handle");

        let mr = [MkdirBatchRequest {
            parent: root,
            name: b"link_dir",
            mode: 0o755,
            ctx: ctx.clone(),
        }];
        let mkdir_results = dispatch_mkdir_batch(engine.as_ref(), &mr);
        let dir_attr = mkdir_results[0].as_ref().unwrap();

        let (mtime_before, ctime_before) = get_timestamps(engine.as_ref(), dir_attr.inode_id, &ctx);
        std::thread::sleep(std::time::Duration::from_millis(1));

        let lr = [LinkBatchRequest {
            target: src_attr.inode_id,
            new_parent: dir_attr.inode_id,
            new_name: b"linked",
            ctx: ctx.clone(),
        }];
        let results = dispatch_link_batch(engine.as_ref(), &lr);
        assert!(results[0].is_ok());

        let (mtime_after, ctime_after) = get_timestamps(engine.as_ref(), dir_attr.inode_id, &ctx);
        assert!(mtime_after > mtime_before, "new parent mtime must advance");
        assert!(ctime_after > ctime_before, "new parent ctime must advance");
    }

    #[test]
    fn dispatch_symlink_updates_parent_timestamps() {
        let (_tmp, engine) = test_engine();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        let (mtime_before, ctime_before) = get_timestamps(engine.as_ref(), root, &ctx);
        std::thread::sleep(std::time::Duration::from_millis(1));

        let sr = [SymlinkBatchRequest {
            parent: root,
            name: b"dispatch_sym",
            target: b"/some/target",
            ctx: ctx.clone(),
        }];
        let results = dispatch_symlink_batch(engine.as_ref(), &sr);
        assert!(results[0].is_ok());

        let (mtime_after, ctime_after) = get_timestamps(engine.as_ref(), root, &ctx);
        assert!(mtime_after > mtime_before, "parent mtime must advance");
        assert!(ctime_after > ctime_before, "parent ctime must advance");
    }
}
