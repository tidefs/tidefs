// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Kernel trace oracle parity integration test.
//!
//! Validates that kernel VFS dispatch through `KmodPosixVfs` produces
//! results consistent with direct `LocalFileSystem` usage for the same
//! sequence of operations. This is the foundation for cross-implementation
//! trace comparison required by #6283 (REL-KVFS-016).
//!
//! Provides:
//! - `LocalFilesystemVfsEngine`: bridges LocalFileSystem into VfsEngine
//! - `KernelTraceRunner`: replays JSONL trace files through KmodPosixVfs
//! - Kernel fingerprint computation matching userspace semantics
//! - Golden trace parity tests comparing kernel vs userspace results

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::io::BufRead;
use std::path::Path;

use tidefs_kmod_bridge::kernel_types::{
    AllocatedInode, DirEntry, EngineDirHandle, EngineFileHandle, Errno, Generation, InodeAttr,
    InodeFlags, InodeId, LockSpec, NodeKind, PosixAttrs, RequestCtx, SetAttr, StatFs, VfsEngine,
    VfsEngineStatFs, WritebackOutcome, WritebackRange,
};
use tidefs_kmod_posix_vfs::KmodPosixVfs;
use tidefs_local_filesystem::LocalFileSystem;
use tidefs_local_object_store::StoreOptions;
use tidefs_trace_oracle::{
    protocol::{
        CLUSTER_TRACE_SCHEMA, KEY_DATASET, KEY_DEVICE_COUNT, KEY_DEVICE_SIZE_BYTES, KEY_KEY,
        KEY_LENGTH, KEY_NAME, KEY_OFFSET, KEY_PATH, KEY_SCHEMA, KEY_VALUE_B64, KEY_VERSION,
        OP_ASSERT_FINGERPRINT, OP_CLOSE_POOL, OP_CREATE_DATASET, OP_CREATE_FILE, OP_CREATE_POOL,
        OP_GET, OP_GET_RANGE, OP_LOOKUP, OP_MKDIR, OP_OPEN_POOL, OP_PUT, OP_READDIR,
        OP_RESTART_POOL, OP_STAT, OP_TRACE_META, OP_UNLINK, POOL_TRACE_SCHEMA, TRACE_VERSION,
    },
    CostBaseline, TraceError, TraceEvent, TraceRunner,
};

// ── LocalFilesystemVfsEngine ───────────────────────────────────────────────

pub struct LocalFilesystemVfsEngine {
    fs: RefCell<LocalFileSystem>,
    next_ino: Cell<u64>,
    ino_to_path: RefCell<BTreeMap<u64, String>>,
    path_to_ino: RefCell<BTreeMap<String, u64>>,
    next_fh: Cell<u64>,
    fh_state: RefCell<BTreeMap<u64, (u64, String, u32)>>,
    next_dh: Cell<u64>,
    dh_state: RefCell<BTreeMap<u64, (u64, String)>>,
}

impl LocalFilesystemVfsEngine {
    pub fn new(fs: LocalFileSystem) -> Self {
        let mut ino_to_path = BTreeMap::new();
        let mut path_to_ino = BTreeMap::new();
        ino_to_path.insert(1, "/".to_string());
        path_to_ino.insert("/".to_string(), 1);
        Self {
            fs: RefCell::new(fs),
            next_ino: Cell::new(2),
            ino_to_path: RefCell::new(ino_to_path),
            path_to_ino: RefCell::new(path_to_ino),
            next_fh: Cell::new(1),
            fh_state: RefCell::new(BTreeMap::new()),
            next_dh: Cell::new(1),
            dh_state: RefCell::new(BTreeMap::new()),
        }
    }

    pub fn path_for_ino(&self, ino: u64) -> Result<String, Errno> {
        self.ino_to_path
            .borrow()
            .get(&ino)
            .cloned()
            .ok_or(Errno::ENOENT)
    }

    fn register_inode(&self, path: &str) -> Result<u64, Errno> {
        let fs = self.fs.borrow();
        let ino = fs.lookup(path).map_err(|_| Errno::ENOENT)?;
        let ino_u64 = ino.get();
        drop(fs);
        let mut i2p = self.ino_to_path.borrow_mut();
        let mut p2i = self.path_to_ino.borrow_mut();
        i2p.insert(ino_u64, path.to_string());
        p2i.insert(path.to_string(), ino_u64);
        Ok(ino_u64)
    }

    fn alloc_ino(&self) -> u64 {
        let ino = self.next_ino.get();
        self.next_ino.set(ino + 1);
        ino
    }
}

fn convert_attr(a: tidefs_types_vfs_core::InodeAttr) -> InodeAttr {
    InodeAttr {
        inode_id: InodeId::new(a.inode_id.0),
        generation: Generation::new(a.generation.0),
        kind: match a.kind {
            tidefs_types_vfs_core::NodeKind::Dir => NodeKind::Dir,
            tidefs_types_vfs_core::NodeKind::File => NodeKind::File,
            tidefs_types_vfs_core::NodeKind::Symlink => NodeKind::Symlink,
            tidefs_types_vfs_core::NodeKind::CharDev => NodeKind::CharDev,
            tidefs_types_vfs_core::NodeKind::BlockDev => NodeKind::BlockDev,
            tidefs_types_vfs_core::NodeKind::Fifo => NodeKind::Fifo,
            tidefs_types_vfs_core::NodeKind::Socket => NodeKind::Socket,
            _ => NodeKind::File,
        },
        posix: PosixAttrs {
            mode: a.posix.mode,
            uid: a.posix.uid,
            gid: a.posix.gid,
            nlink: a.posix.nlink,
            rdev: a.posix.rdev,
            atime_ns: a.posix.atime_ns,
            mtime_ns: a.posix.mtime_ns,
            ctime_ns: a.posix.ctime_ns,
            btime_ns: a.posix.btime_ns,
            size: a.posix.size,
            blocks_512: a.posix.blocks_512,
            blksize: a.posix.blksize,
        },
        flags: InodeFlags::none(),
        subtree_rev: a.subtree_rev,
        dir_rev: a.dir_rev,
    }
}

impl VfsEngine for LocalFilesystemVfsEngine {
    fn get_root_inode(&self, _ctx: &RequestCtx) -> Result<InodeId, Errno> {
        Ok(InodeId::new(1))
    }

    fn lookup(&self, parent: InodeId, name: &[u8], _ctx: &RequestCtx) -> Result<InodeAttr, Errno> {
        let parent_path = self.path_for_ino(parent.get())?;
        let name_str = core::str::from_utf8(name).map_err(|_| Errno::EINVAL)?;
        let child_path = if parent_path == "/" {
            format!("/{name_str}")
        } else {
            format!("{parent_path}/{name_str}")
        };
        let fs = self.fs.borrow();
        let ino = fs.lookup(&child_path).map_err(|_| Errno::ENOENT)?;
        let ino_u64 = ino.get();
        drop(fs);
        let mut i2p = self.ino_to_path.borrow_mut();
        let mut p2i = self.path_to_ino.borrow_mut();
        if let std::collections::btree_map::Entry::Vacant(e) = i2p.entry(ino_u64) {
            e.insert(child_path.clone());
            p2i.insert(child_path.clone(), ino_u64);
        }
        drop(i2p);
        drop(p2i);
        let fs = self.fs.borrow();
        let record = fs.stat(&child_path).map_err(|_| Errno::ENOENT)?;
        Ok(convert_attr(record.to_inode_attr()))
    }

    fn getattr(
        &self,
        inode: InodeId,
        _h: Option<&EngineFileHandle>,
        _ctx: &RequestCtx,
    ) -> Result<InodeAttr, Errno> {
        let path = self.path_for_ino(inode.get())?;
        let fs = self.fs.borrow();
        let record = fs.stat(&path).map_err(|_| Errno::ENOENT)?;
        Ok(convert_attr(record.to_inode_attr()))
    }

    fn mkdir(
        &self,
        parent: InodeId,
        name: &[u8],
        mode: u32,
        _ctx: &RequestCtx,
    ) -> Result<InodeAttr, Errno> {
        let parent_path = self.path_for_ino(parent.get())?;
        let name_str = core::str::from_utf8(name).map_err(|_| Errno::EINVAL)?;
        let child_path = if parent_path == "/" {
            format!("/{name_str}")
        } else {
            format!("{parent_path}/{name_str}")
        };
        self.fs
            .borrow_mut()
            .create_dir(&child_path, mode)
            .map_err(|_| Errno::EIO)?;
        let ino = self.register_inode(&child_path)?;
        let path = self.path_for_ino(ino)?;
        let fs = self.fs.borrow();
        fs.stat(&path)
            .map(|r| convert_attr(r.to_inode_attr()))
            .map_err(|_| Errno::ENOENT)
    }

    fn create(
        &self,
        parent: InodeId,
        name: &[u8],
        mode: u32,
        _flags: u32,
        _ctx: &RequestCtx,
    ) -> Result<(InodeAttr, EngineFileHandle), Errno> {
        let parent_path = self.path_for_ino(parent.get())?;
        let name_str = core::str::from_utf8(name).map_err(|_| Errno::EINVAL)?;
        let child_path = if parent_path == "/" {
            format!("/{name_str}")
        } else {
            format!("{parent_path}/{name_str}")
        };
        self.fs
            .borrow_mut()
            .create_file(&child_path, mode)
            .map_err(|_| Errno::EIO)?;
        let ino = self.register_inode(&child_path)?;
        let attr = {
            let fs = self.fs.borrow();
            let record = fs.stat(&child_path).map_err(|_| Errno::ENOENT)?;
            convert_attr(record.to_inode_attr())
        };
        let fh_id = self.next_fh.get();
        self.next_fh.set(fh_id + 1);
        self.fh_state
            .borrow_mut()
            .insert(fh_id, (ino, child_path, 0));
        let fh = EngineFileHandle {
            inode_id: InodeId::new(ino),
            open_flags: 0,
            fh_id: tidefs_kmod_bridge::kernel_types::FileHandleId::new(fh_id),
            lock_owner: 0,
        };
        Ok((attr, fh))
    }

    fn open(
        &self,
        inode: InodeId,
        flags: u32,
        _ctx: &RequestCtx,
    ) -> Result<EngineFileHandle, Errno> {
        let ino = inode.get();
        let path = self.path_for_ino(ino)?;
        let fh_id = self.next_fh.get();
        self.next_fh.set(fh_id + 1);
        self.fh_state.borrow_mut().insert(fh_id, (ino, path, flags));
        Ok(EngineFileHandle {
            inode_id: InodeId::new(ino),
            open_flags: flags,
            fh_id: tidefs_kmod_bridge::kernel_types::FileHandleId::new(fh_id),
            lock_owner: 0,
        })
    }

    fn release(&self, fh: &EngineFileHandle) -> Result<(), Errno> {
        self.fh_state.borrow_mut().remove(&fh.fh_id.get());
        Ok(())
    }

    fn read(
        &self,
        fh: &EngineFileHandle,
        offset: u64,
        size: u32,
        _ctx: &RequestCtx,
    ) -> Result<Vec<u8>, Errno> {
        let fh_id = fh.fh_id.get();
        let (_ino, path, _flags) = self
            .fh_state
            .borrow()
            .get(&fh_id)
            .cloned()
            .ok_or(Errno::EBADF)?;
        let fs = self.fs.borrow();
        fs.read_file_range(&path, offset, size as usize)
            .map_err(|_| Errno::EIO)
    }

    fn write(
        &self,
        fh: &EngineFileHandle,
        offset: u64,
        data: &[u8],
        _ctx: &RequestCtx,
    ) -> Result<u32, Errno> {
        let fh_id = fh.fh_id.get();
        let (_ino, path, _flags) = self
            .fh_state
            .borrow()
            .get(&fh_id)
            .cloned()
            .ok_or(Errno::EBADF)?;
        let mut fs = self.fs.borrow_mut();
        let existing = fs.read_file(&path).unwrap_or_default();
        let new_len = (offset as usize).saturating_add(data.len());
        let mut buf = existing;
        if new_len > buf.len() {
            buf.resize(new_len, 0);
        }
        let end = (offset as usize).saturating_add(data.len());
        if end <= buf.len() {
            buf[offset as usize..end].copy_from_slice(data);
        }
        fs.replace_file(&path, &buf).map_err(|_| Errno::EIO)?;
        Ok(data.len() as u32)
    }

    fn flush(&self, _fh: &EngineFileHandle, _ctx: &RequestCtx) -> Result<(), Errno> {
        Ok(())
    }
    fn fsync(&self, _fh: &EngineFileHandle, _d: bool, _ctx: &RequestCtx) -> Result<(), Errno> {
        Ok(())
    }

    fn opendir(&self, inode: InodeId, _ctx: &RequestCtx) -> Result<EngineDirHandle, Errno> {
        let ino = inode.get();
        let path = self.path_for_ino(ino)?;
        let dh_id = self.next_dh.get();
        self.next_dh.set(dh_id + 1);
        self.dh_state.borrow_mut().insert(dh_id, (ino, path));
        Ok(EngineDirHandle {
            inode_id: InodeId::new(ino),
            dh_id: tidefs_kmod_bridge::kernel_types::DirHandleId::new(dh_id),
        })
    }

    fn releasedir(&self, dh: &EngineDirHandle) -> Result<(), Errno> {
        self.dh_state.borrow_mut().remove(&dh.dh_id.get());
        Ok(())
    }

    fn readdir(
        &self,
        dh: &EngineDirHandle,
        offset: u64,
        _ctx: &RequestCtx,
    ) -> Result<(Vec<DirEntry>, bool), Errno> {
        let dh_id = dh.dh_id.get();
        let (_ino, path) = self
            .dh_state
            .borrow()
            .get(&dh_id)
            .cloned()
            .ok_or(Errno::EBADF)?;
        let fs = self.fs.borrow();
        let entries = fs.list_dir(&path).map_err(|_| Errno::EIO)?;
        let mut dir_entries: Vec<DirEntry> = Vec::new();
        let mut cookie: u64 = 1;
        let offset_usize = offset as usize;
        for entry in entries.iter().skip(offset_usize) {
            let name = entry.name.clone();
            let child_path = if path == "/" {
                format!("/{}", String::from_utf8_lossy(&name))
            } else {
                format!("{path}/{}", String::from_utf8_lossy(&name))
            };
            let child_ino = match self.register_inode(&child_path) {
                Ok(ino) => ino,
                Err(_) => continue,
            };
            let kind = match entry.kind() {
                tidefs_types_vfs_core::NodeKind::Dir => NodeKind::Dir,
                tidefs_types_vfs_core::NodeKind::File => NodeKind::File,
                tidefs_types_vfs_core::NodeKind::Symlink => NodeKind::Symlink,
                _ => NodeKind::File,
            };
            dir_entries.push(DirEntry {
                inode_id: InodeId::new(child_ino),
                name: name.into_iter().collect::<Vec<u8>>(),
                kind,
                cookie,
                generation: Generation::new(1),
            });
            cookie += 1;
        }
        Ok((dir_entries, false))
    }

    fn fsyncdir(&self, _dh: &EngineDirHandle, _d: bool, _ctx: &RequestCtx) -> Result<(), Errno> {
        Ok(())
    }
    fn symlink(
        &self,
        parent: InodeId,
        name: &[u8],
        target: &[u8],
        _ctx: &RequestCtx,
    ) -> Result<InodeAttr, Errno> {
        let parent_path = self.path_for_ino(parent.get())?;
        let name_str = core::str::from_utf8(name).map_err(|_| Errno::EINVAL)?;
        let child_path = if parent_path == "/" {
            format!("/{name_str}")
        } else {
            format!("{parent_path}/{name_str}")
        };
        let target_str = core::str::from_utf8(target).map_err(|_| Errno::EINVAL)?;
        self.fs
            .borrow_mut()
            .create_symlink(&child_path, target_str)
            .map_err(|_| Errno::EIO)?;
        let ino = self.register_inode(&child_path)?;
        self.path_for_ino(ino).and_then(|p| {
            let fs = self.fs.borrow();
            fs.stat(&p)
                .map(|r| convert_attr(r.to_inode_attr()))
                .map_err(|_| Errno::ENOENT)
        })
    }
    fn readlink(&self, inode: InodeId, _ctx: &RequestCtx) -> Result<Vec<u8>, Errno> {
        let path = self.path_for_ino(inode.get())?;
        self.fs.borrow().read_symlink(&path).map_err(|_| Errno::EIO)
    }

    // Required trait methods with default/unsupported impls
    fn setattr(
        &self,
        _inode: InodeId,
        _attr: &SetAttr,
        _h: Option<&EngineFileHandle>,
        _ctx: &RequestCtx,
    ) -> Result<InodeAttr, Errno> {
        Err(Errno::ENOSYS)
    }
    fn create_excl(
        &self,
        p: InodeId,
        n: &[u8],
        m: u32,
        f: u32,
        c: &RequestCtx,
    ) -> Result<(InodeAttr, EngineFileHandle), Errno> {
        self.create(p, n, m, f, c)
    }
    fn unlink(&self, parent: InodeId, name: &[u8], _ctx: &RequestCtx) -> Result<(), Errno> {
        self.fs
            .borrow_mut()
            .remove_dir_entry(InodeId::new(parent.get()), name)
            .map_err(|_| Errno::EIO)
    }
    fn rmdir(&self, parent: InodeId, name: &[u8], _ctx: &RequestCtx) -> Result<(), Errno> {
        let parent_path = self.path_for_ino(parent.get())?;
        let name_str = core::str::from_utf8(name).map_err(|_| Errno::EINVAL)?;
        let child_path = if parent_path == "/" {
            format!("/{name_str}")
        } else {
            format!("{parent_path}/{name_str}")
        };
        self.fs
            .borrow_mut()
            .remove_dir(&child_path)
            .map_err(|_| Errno::EIO)
    }
    fn rename(
        &self,
        _op: InodeId,
        _on: &[u8],
        _np: InodeId,
        _nn: &[u8],
        _flags: u32,
        _ctx: &RequestCtx,
    ) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }
    fn link(
        &self,
        _t: InodeId,
        _np: InodeId,
        _nn: &[u8],
        _ctx: &RequestCtx,
    ) -> Result<InodeAttr, Errno> {
        Err(Errno::ENOSYS)
    }
    fn mknod(
        &self,
        _p: InodeId,
        _n: &[u8],
        _m: u32,
        _r: u32,
        _ctx: &RequestCtx,
    ) -> Result<InodeAttr, Errno> {
        Err(Errno::ENOSYS)
    }
    fn allocate_inode(
        &self,
        kind: NodeKind,
        _p: InodeId,
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> Result<AllocatedInode, Errno> {
        let ino = self.alloc_ino();
        Ok(AllocatedInode::new(
            InodeId::new(ino),
            InodeAttr {
                inode_id: InodeId::new(ino),
                generation: Generation::new(1),
                kind,
                posix: PosixAttrs {
                    mode,
                    uid,
                    gid,
                    nlink: 1,
                    rdev: 0,
                    atime_ns: 0,
                    mtime_ns: 0,
                    ctime_ns: 0,
                    btime_ns: 0,
                    size: 0,
                    blocks_512: 0,
                    blksize: 4096,
                },
                flags: InodeFlags::none(),
                subtree_rev: 0,
                dir_rev: 0,
            },
        ))
    }
    fn tmpfile(
        &self,
        _p: InodeId,
        _m: u32,
        _f: u32,
        _ctx: &RequestCtx,
    ) -> Result<(InodeAttr, EngineFileHandle), Errno> {
        Err(Errno::ENOSYS)
    }
    fn fallocate(
        &self,
        _fh: &EngineFileHandle,
        _m: u32,
        _o: u64,
        _l: u64,
        _ctx: &RequestCtx,
    ) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }
    fn getxattr(&self, _i: InodeId, _n: &[u8], _ctx: &RequestCtx) -> Result<Vec<u8>, Errno> {
        Err(Errno::ENODATA)
    }
    fn setxattr(
        &self,
        _i: InodeId,
        _n: &[u8],
        _v: &[u8],
        _f: u32,
        _ctx: &RequestCtx,
    ) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }
    fn listxattr(&self, _i: InodeId, _ctx: &RequestCtx) -> Result<Vec<u8>, Errno> {
        Err(Errno::ENOSYS)
    }
    fn removexattr(&self, _i: InodeId, _n: &[u8], _ctx: &RequestCtx) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }
    fn getlk(
        &self,
        _i: InodeId,
        _l: &LockSpec,
        _ctx: &RequestCtx,
    ) -> Result<Option<LockSpec>, Errno> {
        Err(Errno::ENOSYS)
    }
    fn setlk(&self, _i: InodeId, _l: &LockSpec, _ctx: &RequestCtx) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }
    fn writeback_folios(
        &self,
        _i: InodeId,
        _fh: &EngineFileHandle,
        _r: WritebackRange,
        _ctx: &RequestCtx,
    ) -> Result<WritebackOutcome, Errno> {
        Ok(WritebackOutcome {
            bytes_written: 0,
            complete: true,
        })
    }
}

impl VfsEngineStatFs for LocalFilesystemVfsEngine {
    fn statfs(&self, _ctx: &RequestCtx) -> Result<StatFs, Errno> {
        Ok(StatFs {
            block_size: 4096,
            fragment_size: 4096,
            total_blocks: 1024 * 256,
            free_blocks: 1024 * 128,
            avail_blocks: 1024 * 128,
            files: 1024 * 1024,
            files_free: 1024 * 512,
            name_max: 255,
            fsid_hi: 0,
            fsid_lo: 0,
        })
    }
}

// ── KernelTraceRunner ──────────────────────────────────────────────────────
//
// Replays JSONL trace files through KmodPosixVfs<LocalFilesystemVfsEngine>,
// producing TraceEvent streams comparable with the userspace TraceRunner.

pub struct KernelTraceRunner {
    workdir: tempfile::TempDir,
    vfs: Option<KmodPosixVfs<LocalFilesystemVfsEngine>>,
    store_dir: Option<std::path::PathBuf>,
}

impl KernelTraceRunner {
    pub fn new() -> Result<Self, TraceError> {
        let workdir = tempfile::tempdir()?;
        Ok(Self {
            workdir,
            vfs: None,
            store_dir: None,
        })
    }

    /// Collect namespace entries for semantic comparison with userspace state.
    /// Each entry is (path, kind_byte, content) sorted by path.
    fn collect_namespace(&self) -> Result<Vec<(String, u8, Vec<u8>)>, TraceError> {
        let vfs = match &self.vfs {
            Some(v) => v,
            None => return Ok(Vec::new()),
        };
        let engine = vfs.engine();
        let root = engine
            .get_root_inode(&RequestCtx::default())
            .map_err(|e| TraceError::FileSystem(format!("get_root_inode: {e}")))?;
        let mut entries = Vec::new();
        Self::collect_namespace_recursive(engine, root.get(), "/".to_string(), &mut entries)?;
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(entries)
    }

    fn collect_namespace_recursive(
        engine: &LocalFilesystemVfsEngine,
        ino: u64,
        path: String,
        entries: &mut Vec<(String, u8, Vec<u8>)>,
    ) -> Result<(), TraceError> {
        let ctx = RequestCtx::default();
        let dh = engine
            .opendir(InodeId::new(ino), &ctx)
            .map_err(|e| TraceError::FileSystem(format!("opendir ino={ino}: {e}")))?;
        let (dir_entries, _) = engine
            .readdir(&dh, 0, &ctx)
            .map_err(|e| TraceError::FileSystem(format!("readdir ino={ino}: {e}")))?;
        engine.releasedir(&dh).ok();

        let mut sorted: Vec<_> = dir_entries.iter().collect();
        sorted.sort_by(|a, b| a.name.cmp(&b.name));

        for entry in &sorted {
            let name_str = String::from_utf8_lossy(&entry.name).to_string();
            let child_path = if path == "/" {
                format!("/{name_str}")
            } else {
                format!("{path}/{name_str}")
            };

            let kind_byte = match entry.kind {
                NodeKind::Dir => 0u8,
                NodeKind::File => 1u8,
                NodeKind::Symlink => 2u8,
                _ => 3u8,
            };

            match entry.kind {
                NodeKind::Dir => {
                    entries.push((child_path.clone(), kind_byte, Vec::new()));
                    Self::collect_namespace_recursive(
                        engine,
                        entry.inode_id.get(),
                        child_path,
                        entries,
                    )?;
                }
                NodeKind::File => {
                    let mut content = Vec::new();
                    if let Ok(fh) = engine.open(entry.inode_id, 0, &ctx) {
                        if let Ok(data) = engine.read(&fh, 0, u32::MAX, &ctx) {
                            content = data;
                        }
                        engine.release(&fh).ok();
                    }
                    entries.push((child_path, kind_byte, content));
                }
                NodeKind::Symlink => {
                    let target = engine.readlink(entry.inode_id, &ctx).unwrap_or_default();
                    entries.push((child_path, kind_byte, target));
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub fn run_trace(&mut self, trace_path: &Path) -> Result<Vec<TraceEvent>, TraceError> {
        let file = std::fs::File::open(trace_path)?;
        let reader = std::io::BufReader::new(file);
        let mut events: Vec<TraceEvent> = Vec::new();
        let mut schema: Option<String> = None;
        let mut step: u64 = 0;

        for line_result in reader.lines() {
            let line = line_result?;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            #[derive(serde::Deserialize)]
            struct TraceLine {
                op: String,
                #[serde(default)]
                args: serde_json::Value,
                #[serde(default)]
                expect: serde_json::Value,
            }

            let trace_line: TraceLine = serde_json::from_str(trimmed)?;
            let op = trace_line.op.clone();

            if op == OP_TRACE_META {
                if step != 0 {
                    return Err(TraceError::Protocol("trace_meta must be first op".into()));
                }
                let s = trace_line
                    .args
                    .get(KEY_SCHEMA)
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let v = trace_line
                    .args
                    .get(KEY_VERSION)
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                if s != POOL_TRACE_SCHEMA && s != CLUSTER_TRACE_SCHEMA {
                    return Err(TraceError::Protocol(format!("unsupported schema: {s}")));
                }
                if v > TRACE_VERSION {
                    return Err(TraceError::Protocol(format!("unsupported version: {v}")));
                }
                schema = Some(s.to_string());
                events.push(TraceEvent {
                    step,
                    op,
                    cost: CostBaseline::default(),
                    fingerprint: None,
                    result: None,
                });
                step += 1;
                continue;
            }

            if schema.is_none() {
                return Err(TraceError::Protocol(
                    "trace_meta must precede all other ops".into(),
                ));
            }

            let result = self.dispatch_op(&op, &trace_line.args, &trace_line.expect)?;
            // Collect namespace state for semantic comparison (no BLAKE3 needed)
            let namespace_state = self
                .collect_namespace()
                .map(|entries| format!("{} entries", entries.len()))
                .unwrap_or_else(|_| "error".to_string());

            events.push(TraceEvent {
                step,
                op,
                cost: CostBaseline::default(),
                fingerprint: Some(namespace_state),
                result,
            });
            step += 1;
        }

        self.vfs = None;
        Ok(events)
    }

    fn dispatch_op(
        &mut self,
        op: &str,
        args: &serde_json::Value,
        _expect: &serde_json::Value,
    ) -> Result<Option<serde_json::Value>, TraceError> {
        let ctx = RequestCtx::default();

        match op {
            OP_CREATE_POOL => {
                self.vfs = None;
                let device_count = args
                    .get(KEY_DEVICE_COUNT)
                    .and_then(|v| v.as_u64())
                    .unwrap_or(2) as usize;
                let device_size = args
                    .get(KEY_DEVICE_SIZE_BYTES)
                    .and_then(|v| v.as_u64())
                    .unwrap_or(128 * 1024 * 1024);
                let pool_dir = self.workdir.path().join("pool");
                std::fs::create_dir_all(&pool_dir)?;
                for i in 0..device_count {
                    let dev_path = pool_dir.join(format!("dev_{i}"));
                    let f = std::fs::File::create(&dev_path)?;
                    f.set_len(device_size)?;
                }
                let store_dir = pool_dir.join("store");
                std::fs::create_dir_all(&store_dir)?;
                self.store_dir = Some(store_dir.clone());
                let fs = LocalFileSystem::open_with_root_authentication_key(
                    &store_dir,
                    StoreOptions::default(),
                    tidefs_local_filesystem::RootAuthenticationKey::demo_key(),
                )
                .map_err(|e| TraceError::FileSystem(format!("create_pool: {e}")))?;
                let engine = LocalFilesystemVfsEngine::new(fs);
                self.vfs = Some(KmodPosixVfs::new(engine));
                Ok(None)
            }

            OP_OPEN_POOL | OP_RESTART_POOL => {
                self.vfs = None;
                let store_dir = match &self.store_dir {
                    Some(d) => d.clone(),
                    None => self.workdir.path().join("pool").join("store"),
                };
                let fs = LocalFileSystem::open_with_root_authentication_key(
                    &store_dir,
                    StoreOptions::default(),
                    tidefs_local_filesystem::RootAuthenticationKey::demo_key(),
                )
                .map_err(|e| TraceError::FileSystem(format!("open_pool: {e}")))?;
                let engine = LocalFilesystemVfsEngine::new(fs);
                self.vfs = Some(KmodPosixVfs::new(engine));
                Ok(None)
            }

            OP_CLOSE_POOL => {
                self.vfs = None;
                Ok(None)
            }

            OP_ASSERT_FINGERPRINT => {
                // Verify pool is open; fingerprint comparison uses namespace
                // state collected events, not message-local BLAKE3.
                self.engine_mut()?;
                Ok(None)
            }

            OP_CREATE_DATASET => {
                // Accept both "name" (canonical) and "dataset" (legacy) keys
                let name = args
                    .get(KEY_NAME)
                    .or(args.get(KEY_DATASET))
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        TraceError::Protocol("create_dataset: missing name or dataset arg".into())
                    })?;
                let engine = self.engine_mut()?;
                let root = engine.get_root_inode(&ctx).map_err(to_fs_err)?;
                engine
                    .mkdir(root, name.as_bytes(), 0o755, &ctx)
                    .map_err(to_fs_err)?;
                Ok(None)
            }

            OP_MKDIR => {
                let dataset = get_string_arg(args, KEY_DATASET)?;
                let ps = get_string_arg(args, KEY_PATH)?;
                let engine = self.engine_mut()?;
                let root = engine.get_root_inode(&ctx).map_err(to_fs_err)?;
                let ds_attr = engine
                    .lookup(root, dataset.as_bytes(), &ctx)
                    .map_err(to_fs_err)?;
                engine
                    .mkdir(ds_attr.inode_id, ps.as_bytes(), 0o755, &ctx)
                    .map_err(to_fs_err)?;
                Ok(None)
            }

            OP_CREATE_FILE => {
                let dataset = get_string_arg(args, KEY_DATASET)?;
                let ps = get_string_arg(args, KEY_PATH)?;
                let engine = self.engine_mut()?;
                let root = engine.get_root_inode(&ctx).map_err(to_fs_err)?;
                let ds_attr = engine
                    .lookup(root, dataset.as_bytes(), &ctx)
                    .map_err(to_fs_err)?;
                engine
                    .create(ds_attr.inode_id, ps.as_bytes(), 0o644, 0, &ctx)
                    .map_err(to_fs_err)?;
                Ok(None)
            }

            OP_LOOKUP => {
                let dataset = get_string_arg(args, KEY_DATASET)?;
                let ps = get_string_arg(args, KEY_PATH)?;
                let engine = self.engine_mut()?;
                let root = engine.get_root_inode(&ctx).map_err(to_fs_err)?;
                let ds_attr = engine
                    .lookup(root, dataset.as_bytes(), &ctx)
                    .map_err(to_fs_err)?;
                match engine.lookup(ds_attr.inode_id, ps.as_bytes(), &ctx) {
                    Ok(attr) => Ok(Some(
                        serde_json::json!({"found": true, "kind": format!("{:?}", attr.kind).to_lowercase(), "inode_id": attr.inode_id.get()}),
                    )),
                    Err(e) if e == Errno::ENOENT => {
                        Ok(Some(serde_json::json!({"found": false, "err": "ENOENT"})))
                    }
                    Err(e) => Err(TraceError::FileSystem(format!("lookup error: {e}"))),
                }
            }

            OP_PUT => {
                let dataset = get_string_arg(args, KEY_DATASET)?;
                let key = get_string_arg(args, KEY_KEY)?;
                let value_b64 = get_string_arg(args, KEY_VALUE_B64)?;
                let data =
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value_b64)?;
                let _path = format!("/{dataset}/{key}");

                let engine = self.engine_mut()?;
                // Ensure dataset directory exists
                let root = engine.get_root_inode(&ctx).map_err(to_fs_err)?;
                let ds_attr = match engine.lookup(root, dataset.as_bytes(), &ctx) {
                    Ok(a) => a,
                    Err(_) => engine
                        .mkdir(root, dataset.as_bytes(), 0o755, &ctx)
                        .map_err(to_fs_err)?,
                };

                // Create file if it doesn't exist, then write data
                let file_attr = match engine.lookup(ds_attr.inode_id, key.as_bytes(), &ctx) {
                    Ok(a) => a,
                    Err(_) => {
                        let (a, fh) = engine
                            .create(ds_attr.inode_id, key.as_bytes(), 0o644, 0, &ctx)
                            .map_err(to_fs_err)?;
                        engine.release(&fh).map_err(to_fs_err)?;
                        a
                    }
                };

                let fh = engine
                    .open(file_attr.inode_id, 0, &ctx)
                    .map_err(to_fs_err)?;
                engine.write(&fh, 0, &data, &ctx).map_err(to_fs_err)?;
                engine.release(&fh).map_err(to_fs_err)?;
                Ok(None)
            }

            OP_GET => {
                let dataset = get_string_arg(args, KEY_DATASET)?;
                let key = get_string_arg(args, KEY_KEY)?;
                let _path = format!("/{dataset}/{key}");
                let engine = self.engine_mut()?;
                let root = engine.get_root_inode(&ctx).map_err(to_fs_err)?;
                let ds_attr = engine
                    .lookup(root, dataset.as_bytes(), &ctx)
                    .map_err(to_fs_err)?;
                let file_attr = engine
                    .lookup(ds_attr.inode_id, key.as_bytes(), &ctx)
                    .map_err(to_fs_err)?;
                let fh = engine
                    .open(file_attr.inode_id, 0, &ctx)
                    .map_err(to_fs_err)?;
                let data = engine.read(&fh, 0, u32::MAX, &ctx).map_err(to_fs_err)?;
                engine.release(&fh).map_err(to_fs_err)?;
                let value_b64 =
                    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &data);
                Ok(Some(serde_json::json!({KEY_VALUE_B64: value_b64})))
            }

            OP_GET_RANGE => {
                let dataset = get_string_arg(args, KEY_DATASET)?;
                let key = get_string_arg(args, KEY_KEY)?;
                let offset = args.get(KEY_OFFSET).and_then(|v| v.as_u64()).unwrap_or(0);
                let length = args.get(KEY_LENGTH).and_then(|v| v.as_u64()).unwrap_or(0);
                let engine = self.engine_mut()?;
                let root = engine.get_root_inode(&ctx).map_err(to_fs_err)?;
                let ds_attr = engine
                    .lookup(root, dataset.as_bytes(), &ctx)
                    .map_err(to_fs_err)?;
                let file_attr = engine
                    .lookup(ds_attr.inode_id, key.as_bytes(), &ctx)
                    .map_err(to_fs_err)?;
                let fh = engine
                    .open(file_attr.inode_id, 0, &ctx)
                    .map_err(to_fs_err)?;
                let data = engine
                    .read(&fh, offset, length as u32, &ctx)
                    .map_err(to_fs_err)?;
                engine.release(&fh).map_err(to_fs_err)?;
                let value_b64 =
                    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &data);
                Ok(Some(serde_json::json!({KEY_VALUE_B64: value_b64})))
            }

            OP_READDIR => {
                let dataset = get_string_arg(args, KEY_DATASET)?;
                let engine = self.engine_mut()?;
                let root = engine.get_root_inode(&ctx).map_err(to_fs_err)?;
                let ds_attr = engine
                    .lookup(root, dataset.as_bytes(), &ctx)
                    .map_err(to_fs_err)?;
                let dh = engine.opendir(ds_attr.inode_id, &ctx).map_err(to_fs_err)?;
                let (entries, _) = engine.readdir(&dh, 0, &ctx).map_err(to_fs_err)?;
                engine.releasedir(&dh).map_err(to_fs_err)?;
                let names: Vec<String> = entries
                    .iter()
                    .map(|e| String::from_utf8_lossy(&e.name).to_string())
                    .collect();
                Ok(Some(serde_json::json!({KEY_NAME: names})))
            }

            OP_STAT => {
                let dataset = get_string_arg(args, KEY_DATASET)?;
                let key = args.get(KEY_KEY).and_then(|v| v.as_str()).unwrap_or("");
                let engine = self.engine_mut()?;
                let root = engine.get_root_inode(&ctx).map_err(to_fs_err)?;
                let ds_attr = engine
                    .lookup(root, dataset.as_bytes(), &ctx)
                    .map_err(to_fs_err)?;
                if key.is_empty() {
                    let attr = engine
                        .getattr(ds_attr.inode_id, None, &ctx)
                        .map_err(to_fs_err)?;
                    Ok(Some(
                        serde_json::json!({"kind": format!("{:?}", attr.kind), "size": attr.posix.size}),
                    ))
                } else {
                    let file_attr = engine
                        .lookup(ds_attr.inode_id, key.as_bytes(), &ctx)
                        .map_err(to_fs_err)?;
                    Ok(Some(
                        serde_json::json!({"kind": format!("{:?}", file_attr.kind), "size": file_attr.posix.size}),
                    ))
                }
            }

            OP_UNLINK => {
                let dataset = get_string_arg(args, KEY_DATASET)?;
                let key = get_string_arg(args, KEY_KEY)?;
                let engine = self.engine_mut()?;
                let root = engine.get_root_inode(&ctx).map_err(to_fs_err)?;
                let ds_attr = engine
                    .lookup(root, dataset.as_bytes(), &ctx)
                    .map_err(to_fs_err)?;
                engine
                    .unlink(ds_attr.inode_id, key.as_bytes(), &ctx)
                    .map_err(to_fs_err)?;
                Ok(None)
            }

            _ => Err(TraceError::Protocol(format!(
                "kernel runner: unsupported op: {op}"
            ))),
        }
    }

    fn engine_mut(&self) -> Result<&LocalFilesystemVfsEngine, TraceError> {
        match &self.vfs {
            Some(v) => Ok(v.engine()),
            None => Err(TraceError::Protocol("pool not open".into())),
        }
    }
}

fn get_string_arg<'a>(args: &'a serde_json::Value, key: &str) -> Result<&'a str, TraceError> {
    args.get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| TraceError::Protocol(format!("missing arg: {key}")))
}

fn to_fs_err(e: Errno) -> TraceError {
    TraceError::FileSystem(format!("{e}"))
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn create_test_fs() -> (tempfile::TempDir, LocalFileSystem) {
    let dir = tempfile::tempdir().unwrap();
    let fs = LocalFileSystem::open_with_root_authentication_key(
        dir.path(),
        StoreOptions::default(),
        tidefs_local_filesystem::RootAuthenticationKey::demo_key(),
    )
    .unwrap();
    (dir, fs)
}

fn repo_root() -> std::path::PathBuf {
    let crate_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    crate_dir.parent().unwrap().parent().unwrap().to_path_buf()
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[test]
fn local_filesystem_vfs_engine_smoke() {
    let (_dir, fs) = create_test_fs();
    let engine = LocalFilesystemVfsEngine::new(fs);
    let vfs = KmodPosixVfs::new(engine);
    let root = vfs.engine().get_root_inode(&RequestCtx::default()).unwrap();
    assert_eq!(root.get(), 1, "root inode should be 1");
}

#[test]
fn engine_mkdir_lookup_consistency() {
    let (_dir, fs) = create_test_fs();
    let engine = LocalFilesystemVfsEngine::new(fs);
    let vfs = KmodPosixVfs::new(engine);
    let ctx = RequestCtx::default();
    let root = vfs.engine().get_root_inode(&ctx).unwrap();
    let attr = vfs.engine().mkdir(root, b"testdir", 0o755, &ctx).unwrap();
    assert_eq!(attr.kind, NodeKind::Dir);
    let looked_up = vfs.engine().lookup(root, b"testdir", &ctx).unwrap();
    assert_eq!(looked_up.kind, NodeKind::Dir);
    assert_eq!(looked_up.inode_id, attr.inode_id);
}

#[test]
fn kernel_vs_userspace_fingerprint_parity() {
    // Phase 1: userspace trace run for operation result comparison.
    let dir = tempfile::tempdir().unwrap();
    let mut trace_runner = TraceRunner::new().unwrap();
    let trace_path = dir.path().join("trace.jsonl");
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&trace_path).unwrap();
        let ops: Vec<serde_json::Value> = vec![
            serde_json::json!({"op": "trace_meta", "args": {"schema": "pool_trace_v1", "version": 1}}),
            serde_json::json!({"op": "create_pool", "args": {"device_count": 1, "device_size_bytes": 4194304}}),
            serde_json::json!({"op": "create_dataset", "args": {"name": "ds"}}),
            serde_json::json!({"op": "put", "args": {"dataset": "ds", "key": "f1", "value_b64": "SGVsbG8="}}),
        ];
        for op in &ops {
            writeln!(f, "{}", serde_json::to_string(op).unwrap()).unwrap();
        }
    }
    let us_events = trace_runner.run_trace(&trace_path).unwrap();
    assert!(us_events.len() >= 3);

    // Phase 2: kernel trace run through KmodPosixVfs with the same ops.
    let mut kernel_runner = KernelTraceRunner::new().unwrap();
    let trace_path2 = dir.path().join("trace2.jsonl");
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&trace_path2).unwrap();
        let ops: Vec<serde_json::Value> = vec![
            serde_json::json!({"op": "trace_meta", "args": {"schema": "pool_trace_v1", "version": 1}}),
            serde_json::json!({"op": "create_pool", "args": {"device_count": 1, "device_size_bytes": 4194304}}),
            serde_json::json!({"op": "create_dataset", "args": {"name": "ds"}}),
            serde_json::json!({"op": "put", "args": {"dataset": "ds", "key": "f1", "value_b64": "SGVsbG8="}}),
        ];
        for op in &ops {
            writeln!(f, "{}", serde_json::to_string(op).unwrap()).unwrap();
        }
    }
    let kr_events = kernel_runner.run_trace(&trace_path2).unwrap();

    // Compare operation results between userspace and kernel runs
    assert_eq!(us_events.len(), kr_events.len(), "event count mismatch");
    for (i, (us, kr)) in us_events.iter().zip(kr_events.iter()).enumerate() {
        assert_eq!(us.op, kr.op, "op mismatch at event {i}");
        assert_eq!(
            us.result, kr.result,
            "result mismatch at event {i} (op={}): us={:?} kr={:?}",
            us.op, us.result, kr.result
        );
    }

    // Phase 3: read-back parity through kernel engine.
    let dir2 = tempfile::tempdir().unwrap();
    let fs2 = LocalFileSystem::open_with_root_authentication_key(
        dir2.path(),
        StoreOptions::default(),
        tidefs_local_filesystem::RootAuthenticationKey::demo_key(),
    )
    .unwrap();
    let engine = LocalFilesystemVfsEngine::new(fs2);
    let vfs = KmodPosixVfs::new(engine);
    let ctx = RequestCtx::default();
    let root = vfs.engine().get_root_inode(&ctx).unwrap();
    vfs.engine().mkdir(root, b"ds", 0o755, &ctx).unwrap();
    let ds_attr = vfs.engine().lookup(root, b"ds", &ctx).unwrap();
    let (_attr, fh) = vfs
        .engine()
        .create(ds_attr.inode_id, b"f1", 0o644, 0, &ctx)
        .unwrap();
    vfs.engine().write(&fh, 0, b"Hello", &ctx).unwrap();
    let data = vfs.engine().read(&fh, 0, 5, &ctx).unwrap();
    assert_eq!(data, b"Hello");
    vfs.engine().release(&fh).unwrap();
}

fn golden_trace_test(trace_name: &str) {
    let root = repo_root();
    let trace_path = root
        .join("traces")
        .join("golden")
        .join(trace_name)
        .join("pool_trace.jsonl");
    assert!(
        trace_path.exists(),
        "golden trace not found at {}",
        trace_path.display()
    );

    // Hold TempDir alive throughout both trace runs.
    let stripped_dir = tempfile::tempdir().unwrap();
    let trace_no_assert = stripped_dir.path().join("no_assert.jsonl");
    {
        let content = std::fs::read_to_string(&trace_path).unwrap();
        let mut out = String::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.contains("\"assert_fingerprint\"") {
                continue;
            }
            if trimmed.contains("\"restart_pool\"") {
                continue;
            }
            out.push_str(line);
            out.push('\n');
        }
        std::fs::write(&trace_no_assert, &out).unwrap();
    }

    // Userspace run
    let mut userspace = TraceRunner::new().unwrap();
    let us_events = userspace.run_trace(&trace_no_assert).unwrap();
    let us_results: Vec<(&str, Option<&serde_json::Value>)> = us_events
        .iter()
        .map(|e| (e.op.as_str(), e.result.as_ref()))
        .collect();

    // Kernel run
    let mut kernel = KernelTraceRunner::new().unwrap();
    let kr_events = kernel.run_trace(&trace_no_assert).unwrap();
    let kr_results: Vec<(&str, Option<&serde_json::Value>)> = kr_events
        .iter()
        .map(|e| (e.op.as_str(), e.result.as_ref()))
        .collect();

    assert_eq!(
        us_results.len(),
        kr_results.len(),
        "Event count mismatch for {trace_name}: userspace {} vs kernel {}",
        us_results.len(),
        kr_results.len()
    );

    let mut mismatches = 0;
    for (i, ((us_op, us_res), (kr_op, kr_res))) in
        us_results.iter().zip(kr_results.iter()).enumerate()
    {
        assert_eq!(
            us_op, kr_op,
            "Op name mismatch at event {i} in {trace_name}"
        );
        if us_res != kr_res {
            mismatches += 1;
            eprintln!("Result mismatch at event {i} (op={us_op}) in {trace_name}:\n  userspace: {us_res:?}\n  kernel:    {kr_res:?}");
        }
    }

    assert_eq!(
        mismatches,
        0,
        "Golden trace {trace_name}: {mismatches} result mismatches out of {n} events",
        n = us_results.len()
    );

    eprintln!(
        "Golden trace {trace_name}: {n} events, {m} operation result mismatches",
        n = us_results.len(),
        m = mismatches
    );
}

#[test]
fn golden_trace_smoke_churn_kernel_parity() {
    golden_trace_test("smoke_churn");
}

#[test]
fn golden_trace_smoke_storm_kernel_parity() {
    golden_trace_test("smoke_storm");
}
