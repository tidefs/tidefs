// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! VfsEngine contract test suite: validates trait invariants independent of
//! any specific implementation.
//!
//! Every test function accepts a factory (`fn() -> Box<dyn VfsEngine>`) so
//! the entire suite can be run against any VfsEngine implementation.
//!
//! Gated on `feature = "fuse"`.

use std::cell::RefCell;
use std::collections::HashMap;

use tidefs_vfs_engine::{
    DirEntry, EngineDirHandle, EngineFileHandle, Errno, Generation, InodeAttr, InodeFlags, InodeId,
    LockSpec, NodeKind, PosixAttrs, RequestCtx, SetAttr, StatFs, VfsEngine, VfsEngineStatFs,
    FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE, FALLOC_FL_ZERO_RANGE, FATTR_GID, FATTR_MODE,
    FATTR_MTIME, FATTR_MTIME_NOW, FATTR_SIZE, FATTR_UID, RENAME_EXCHANGE, RENAME_NOREPLACE,
    ROOT_INODE_ID, S_IFDIR, S_IFIFO, S_IFLNK, S_IFMT, S_IFREG, XATTR_CREATE, XATTR_REPLACE,
};

// ── Factory type ────────────────────────────────────────────────────────────

/// A factory that creates a fresh VfsEngine instance.
///
/// Each test calls this to get a new engine, ensuring test isolation.
pub type VfsEngineFactory = fn() -> Box<dyn VfsEngine>;

// ── In-memory test engine ─────────────────────────────────────────────────

type InodeData = (InodeAttr, Vec<u8>, HashMap<Vec<u8>, Vec<u8>>);

struct ContractFileState {
    next_inode: u64,
    next_fh: u64,
    next_dh: u64,
    entries: HashMap<(InodeId, Vec<u8>), InodeId>,
    inodes: HashMap<InodeId, InodeData>,
    handles: HashMap<u64, (InodeId, u32)>,
    dir_handles: HashMap<u64, InodeId>,
}

/// A minimal in-memory VfsEngine suitable for contract testing.
///
/// Provides deterministic, self-contained behavior for all 30 VfsEngine
/// operations. Not intended for production use; exists solely to exercise
/// the trait contract.
pub struct ContractTestEngine {
    state: RefCell<ContractFileState>,
}

impl ContractTestEngine {
    /// Create a new engine with an empty root directory.
    pub fn new() -> Self {
        let root_attr = InodeAttr::new(
            ROOT_INODE_ID,
            Generation::new(1),
            NodeKind::Dir,
            PosixAttrs::new(S_IFDIR | 0o755, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 4096),
            InodeFlags::none(),
            0,
            0,
        );
        let mut inodes = HashMap::new();
        inodes.insert(ROOT_INODE_ID, (root_attr, Vec::new(), HashMap::new()));
        Self {
            state: RefCell::new(ContractFileState {
                next_inode: ROOT_INODE_ID.get() + 1,
                next_fh: 1,
                next_dh: 1,
                entries: HashMap::new(),
                inodes,
                handles: HashMap::new(),
                dir_handles: HashMap::new(),
            }),
        }
    }

    fn entry_key(parent: InodeId, name: &[u8]) -> (InodeId, Vec<u8>) {
        (parent, name.to_vec())
    }

    fn ensure_dir(state: &ContractFileState, inode: InodeId) -> Result<(), Errno> {
        match state.inodes.get(&inode) {
            Some((attr, _, _)) if attr.kind == NodeKind::Dir => Ok(()),
            Some(_) => Err(Errno::ENOTDIR),
            None => Err(Errno::ENOENT),
        }
    }

    fn dir_is_empty(state: &ContractFileState, inode: InodeId) -> bool {
        !state.entries.keys().any(|(parent, _)| *parent == inode)
    }

    fn next_timestamp(attr: &InodeAttr) -> u64 {
        attr.posix
            .atime_ns
            .max(attr.posix.mtime_ns)
            .max(attr.posix.ctime_ns)
            .saturating_add(1)
    }

    fn blocks(size: u64) -> u64 {
        size.saturating_add(511) / 512
    }

    fn set_size(attr: &mut InodeAttr, size: u64) {
        attr.posix.size = size;
        attr.posix.blocks_512 = Self::blocks(size);
    }
}

impl VfsEngine for ContractTestEngine {
    fn get_root_inode(&self, _ctx: &RequestCtx) -> Result<InodeId, Errno> {
        Ok(ROOT_INODE_ID)
    }

    fn lookup(&self, parent: InodeId, name: &[u8], _ctx: &RequestCtx) -> Result<InodeAttr, Errno> {
        let state = self.state.borrow();
        Self::ensure_dir(&state, parent)?;
        let key = Self::entry_key(parent, name);
        let inode_id = state.entries.get(&key).copied().ok_or(Errno::ENOENT)?;
        state
            .inodes
            .get(&inode_id)
            .map(|(attr, _, _)| *attr)
            .ok_or(Errno::ENOENT)
    }

    fn getattr(
        &self,
        inode: InodeId,
        handle: Option<&EngineFileHandle>,
        _ctx: &RequestCtx,
    ) -> Result<InodeAttr, Errno> {
        let state = self.state.borrow();
        if let Some(fh) = handle {
            let live = state.handles.get(&fh.fh_id.get()).ok_or(Errno::EBADF)?;
            if live.0 != fh.inode_id {
                return Err(Errno::EBADF);
            }
        }
        state
            .inodes
            .get(&inode)
            .map(|(attr, _, _)| *attr)
            .ok_or(Errno::ENOENT)
    }

    fn setattr(
        &self,
        inode: InodeId,
        attr: &SetAttr,
        handle: Option<&EngineFileHandle>,
        _ctx: &RequestCtx,
    ) -> Result<InodeAttr, Errno> {
        let mut state = self.state.borrow_mut();
        if let Some(fh) = handle {
            let live = state.handles.get(&fh.fh_id.get()).ok_or(Errno::EBADF)?;
            if live.0 != fh.inode_id {
                return Err(Errno::EBADF);
            }
        }

        let now = state
            .inodes
            .get(&inode)
            .map(|(a, _, _)| Self::next_timestamp(a))
            .ok_or(Errno::ENOENT)?;
        let (stored, data, _) = state.inodes.get_mut(&inode).ok_or(Errno::ENOENT)?;
        let mut changed = false;

        if attr.valid & FATTR_MODE != 0 {
            stored.posix.mode = (stored.posix.mode & S_IFMT) | (attr.mode & !S_IFMT);
            changed = true;
        }
        if attr.valid & FATTR_UID != 0 {
            stored.posix.uid = attr.uid;
            changed = true;
        }
        if attr.valid & FATTR_GID != 0 {
            stored.posix.gid = attr.gid;
            changed = true;
        }
        if attr.valid & FATTR_SIZE != 0 {
            let new_len = usize::try_from(attr.size).map_err(|_| Errno::EFBIG)?;
            data.resize(new_len, 0);
            Self::set_size(stored, attr.size);
            changed = true;
        }
        if attr.valid & FATTR_MTIME != 0 {
            stored.posix.mtime_ns = attr.mtime_ns;
            changed = true;
        }
        if attr.valid & FATTR_MTIME_NOW != 0 {
            stored.posix.mtime_ns = now;
            changed = true;
        }

        if changed {
            stored.posix.ctime_ns = now;
            stored.subtree_rev = stored.subtree_rev.saturating_add(1);
        }

        Ok(*stored)
    }

    fn mkdir(
        &self,
        parent: InodeId,
        name: &[u8],
        mode: u32,
        ctx: &RequestCtx,
    ) -> Result<InodeAttr, Errno> {
        let mut state = self.state.borrow_mut();
        Self::ensure_dir(&state, parent)?;
        let key = Self::entry_key(parent, name);
        if state.entries.contains_key(&key) {
            return Err(Errno::EEXIST);
        }

        let inode_id = InodeId::new(state.next_inode);
        state.next_inode += 1;
        let attr = InodeAttr::new(
            inode_id,
            Generation::new(1),
            NodeKind::Dir,
            PosixAttrs::new(
                S_IFDIR | (mode & !S_IFMT),
                ctx.uid,
                ctx.gid,
                2,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                4096,
            ),
            InodeFlags::none(),
            0,
            0,
        );
        state
            .inodes
            .insert(inode_id, (attr, Vec::new(), HashMap::new()));
        state.entries.insert(key, inode_id);
        Ok(attr)
    }

    fn create(
        &self,
        parent: InodeId,
        name: &[u8],
        mode: u32,
        flags: u32,
        ctx: &RequestCtx,
    ) -> Result<(InodeAttr, EngineFileHandle), Errno> {
        let mut state = self.state.borrow_mut();
        Self::ensure_dir(&state, parent)?;
        let key = Self::entry_key(parent, name);
        if state.entries.contains_key(&key) {
            return Err(Errno::EEXIST);
        }

        let inode_id = InodeId::new(state.next_inode);
        state.next_inode += 1;
        let attr = InodeAttr::new(
            inode_id,
            Generation::new(1),
            NodeKind::File,
            PosixAttrs::new(
                S_IFREG | (mode & !S_IFMT),
                ctx.uid,
                ctx.gid,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                4096,
            ),
            InodeFlags::none(),
            0,
            0,
        );
        state
            .inodes
            .insert(inode_id, (attr, Vec::new(), HashMap::new()));
        state.entries.insert(key, inode_id);

        let fh_id = state.next_fh;
        state.next_fh += 1;
        let fh = EngineFileHandle::new(
            inode_id,
            flags,
            tidefs_vfs_engine::FileHandleId::new(fh_id),
            0,
        );
        state.handles.insert(fh_id, (inode_id, flags));
        Ok((attr, fh))
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

    fn unlink(&self, parent: InodeId, name: &[u8], _ctx: &RequestCtx) -> Result<(), Errno> {
        let mut state = self.state.borrow_mut();
        Self::ensure_dir(&state, parent)?;
        let key = Self::entry_key(parent, name);
        let inode_id = state.entries.remove(&key).ok_or(Errno::ENOENT)?;
        match state.inodes.get(&inode_id) {
            Some((attr, _, _)) if attr.kind == NodeKind::Dir => {
                state.entries.insert(key, inode_id);
                return Err(Errno::EPERM);
            }
            Some(_) => {
                let (attr, _, _) = state.inodes.get_mut(&inode_id).unwrap();
                attr.posix.nlink = attr.posix.nlink.saturating_sub(1);
                if attr.posix.nlink == 0 {
                    state.inodes.remove(&inode_id);
                }
            }
            None => return Err(Errno::ENOENT),
        }
        Ok(())
    }

    fn rmdir(&self, parent: InodeId, name: &[u8], _ctx: &RequestCtx) -> Result<(), Errno> {
        let mut state = self.state.borrow_mut();
        Self::ensure_dir(&state, parent)?;
        let key = Self::entry_key(parent, name);
        let inode_id = state.entries.get(&key).copied().ok_or(Errno::ENOENT)?;
        let attr = state
            .inodes
            .get(&inode_id)
            .map(|(a, _, _)| *a)
            .ok_or(Errno::ENOENT)?;
        if attr.kind != NodeKind::Dir {
            return Err(Errno::ENOTDIR);
        }
        if !Self::dir_is_empty(&state, inode_id) {
            return Err(Errno::ENOTEMPTY);
        }
        state.entries.remove(&key);
        state.inodes.remove(&inode_id);
        Ok(())
    }

    fn rename(
        &self,
        old_parent: InodeId,
        old_name: &[u8],
        new_parent: InodeId,
        new_name: &[u8],
        flags: u32,
        _ctx: &RequestCtx,
    ) -> Result<(), Errno> {
        let mut state = self.state.borrow_mut();
        Self::ensure_dir(&state, old_parent)?;
        Self::ensure_dir(&state, new_parent)?;

        let old_key = Self::entry_key(old_parent, old_name);
        let new_key = Self::entry_key(new_parent, new_name);
        let old_inode = state.entries.get(&old_key).copied().ok_or(Errno::ENOENT)?;
        if old_key == new_key {
            return Ok(());
        }

        if flags & RENAME_EXCHANGE != 0 {
            let new_inode = state.entries.get(&new_key).copied().ok_or(Errno::ENOENT)?;
            state.entries.insert(old_key, new_inode);
            state.entries.insert(new_key, old_inode);
            return Ok(());
        }

        if flags & RENAME_NOREPLACE != 0 && state.entries.contains_key(&new_key) {
            return Err(Errno::EEXIST);
        }

        if let Some(new_inode) = state.entries.remove(&new_key) {
            let old_kind = state
                .inodes
                .get(&old_inode)
                .map(|(a, _, _)| a.kind)
                .ok_or(Errno::ENOENT)?;
            let new_kind = state
                .inodes
                .get(&new_inode)
                .map(|(a, _, _)| a.kind)
                .ok_or(Errno::ENOENT)?;
            match (old_kind, new_kind) {
                (NodeKind::Dir, NodeKind::Dir) => {
                    if !Self::dir_is_empty(&state, new_inode) {
                        return Err(Errno::ENOTEMPTY);
                    }
                }
                (NodeKind::Dir, _) => return Err(Errno::ENOTDIR),
                (_, NodeKind::Dir) => return Err(Errno::EISDIR),
                _ => {}
            }
            state.inodes.remove(&new_inode);
        }

        state.entries.remove(&old_key);
        state.entries.insert(new_key, old_inode);
        Ok(())
    }

    fn link(
        &self,
        target: InodeId,
        new_parent: InodeId,
        new_name: &[u8],
        _ctx: &RequestCtx,
    ) -> Result<InodeAttr, Errno> {
        let mut state = self.state.borrow_mut();
        Self::ensure_dir(&state, new_parent)?;
        let new_key = Self::entry_key(new_parent, new_name);
        if state.entries.contains_key(&new_key) {
            return Err(Errno::EEXIST);
        }

        let target_kind = state
            .inodes
            .get(&target)
            .map(|(a, _, _)| a.kind)
            .ok_or(Errno::ENOENT)?;
        if target_kind == NodeKind::Dir {
            return Err(Errno::EPERM);
        }

        {
            let (attr, _, _) = state.inodes.get_mut(&target).ok_or(Errno::ENOENT)?;
            attr.posix.nlink = attr.posix.nlink.saturating_add(1);
        }
        state.entries.insert(new_key, target);
        let (attr, _, _) = state.inodes.get(&target).ok_or(Errno::ENOENT)?;
        Ok(*attr)
    }

    fn symlink(
        &self,
        parent: InodeId,
        name: &[u8],
        target: &[u8],
        ctx: &RequestCtx,
    ) -> Result<InodeAttr, Errno> {
        let mut state = self.state.borrow_mut();
        Self::ensure_dir(&state, parent)?;
        let key = Self::entry_key(parent, name);
        if state.entries.contains_key(&key) {
            return Err(Errno::EEXIST);
        }

        let inode_id = InodeId::new(state.next_inode);
        state.next_inode += 1;
        let attr = InodeAttr::new(
            inode_id,
            Generation::new(1),
            NodeKind::Symlink,
            PosixAttrs::new(
                S_IFLNK | 0o777,
                ctx.uid,
                ctx.gid,
                1,
                0,
                0,
                0,
                0,
                0,
                target.len() as u64,
                0,
                4096,
            ),
            InodeFlags::none(),
            0,
            0,
        );
        state
            .inodes
            .insert(inode_id, (attr, target.to_vec(), HashMap::new()));
        state.entries.insert(key, inode_id);
        Ok(attr)
    }

    fn readlink(&self, inode: InodeId, _ctx: &RequestCtx) -> Result<Vec<u8>, Errno> {
        let state = self.state.borrow();
        let (attr, target, _) = state.inodes.get(&inode).ok_or(Errno::ENOENT)?;
        if attr.kind != NodeKind::Symlink {
            return Err(Errno::EINVAL);
        }
        Ok(target.clone())
    }

    fn mknod(
        &self,
        parent: InodeId,
        name: &[u8],
        mode: u32,
        _rdev: u32,
        ctx: &RequestCtx,
    ) -> Result<InodeAttr, Errno> {
        if mode & S_IFMT != S_IFIFO {
            return Err(Errno::EOPNOTSUPP);
        }
        let mut state = self.state.borrow_mut();
        Self::ensure_dir(&state, parent)?;
        let key = Self::entry_key(parent, name);
        if state.entries.contains_key(&key) {
            return Err(Errno::EEXIST);
        }

        let inode_id = InodeId::new(state.next_inode);
        state.next_inode += 1;
        let attr = InodeAttr::new(
            inode_id,
            Generation::new(1),
            NodeKind::Fifo,
            PosixAttrs::new(
                S_IFIFO | ((mode & 0o7777) & !ctx.umask),
                ctx.uid,
                ctx.gid,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                4096,
            ),
            InodeFlags::none(),
            0,
            0,
        );
        state
            .inodes
            .insert(inode_id, (attr, Vec::new(), HashMap::new()));
        state.entries.insert(key, inode_id);
        Ok(attr)
    }

    fn open(
        &self,
        inode: InodeId,
        flags: u32,
        _ctx: &RequestCtx,
    ) -> Result<EngineFileHandle, Errno> {
        let mut state = self.state.borrow_mut();
        let (attr, data, _) = state.inodes.get_mut(&inode).ok_or(Errno::ENOENT)?;
        if attr.kind == NodeKind::Dir {
            return Err(Errno::EISDIR);
        }
        if flags & 0o1000 != 0 {
            // O_TRUNC
            data.clear();
            Self::set_size(attr, 0);
        }
        let fh_id = state.next_fh;
        state.next_fh += 1;
        let fh =
            EngineFileHandle::new(inode, flags, tidefs_vfs_engine::FileHandleId::new(fh_id), 0);
        state.handles.insert(fh_id, (inode, flags));
        Ok(fh)
    }

    fn release(&self, fh: &EngineFileHandle) -> Result<(), Errno> {
        let mut state = self.state.borrow_mut();
        let live = state.handles.get(&fh.fh_id.get()).ok_or(Errno::EBADF)?;
        if live.0 != fh.inode_id {
            return Err(Errno::EBADF);
        }
        state.handles.remove(&fh.fh_id.get());
        Ok(())
    }

    fn read(
        &self,
        fh: &EngineFileHandle,
        offset: u64,
        size: u32,
        _ctx: &RequestCtx,
    ) -> Result<Vec<u8>, Errno> {
        let state = self.state.borrow();
        let live = state.handles.get(&fh.fh_id.get()).ok_or(Errno::EBADF)?;
        if live.0 != fh.inode_id {
            return Err(Errno::EBADF);
        }
        if live.1 & 0o3 == 0o1 {
            return Err(Errno::EBADF);
        } // write-only
        let (_, data, _) = state.inodes.get(&live.0).ok_or(Errno::ENOENT)?;
        let off = usize::try_from(offset).map_err(|_| Errno::EINVAL)?;
        if off >= data.len() {
            return Ok(Vec::new());
        }
        let end = data.len().min(off.saturating_add(size as usize));
        Ok(data[off..end].to_vec())
    }

    fn write(
        &self,
        fh: &EngineFileHandle,
        offset: u64,
        data: &[u8],
        _ctx: &RequestCtx,
    ) -> Result<u32, Errno> {
        let mut state = self.state.borrow_mut();
        let live = state.handles.get(&fh.fh_id.get()).ok_or(Errno::EBADF)?;
        if live.0 != fh.inode_id {
            return Err(Errno::EBADF);
        }
        if live.1 & 0o3 == 0 {
            return Err(Errno::EBADF);
        } // read-only
        let inode_id = live.0;

        let off = usize::try_from(offset).map_err(|_| Errno::EINVAL)?;
        let end = off.checked_add(data.len()).ok_or(Errno::EINVAL)?;
        let written = u32::try_from(data.len()).map_err(|_| Errno::EINVAL)?;

        let (attr, stored, _) = state.inodes.get_mut(&inode_id).ok_or(Errno::ENOENT)?;
        if stored.len() < end {
            stored.resize(end, 0);
        }
        stored[off..end].copy_from_slice(data);
        Self::set_size(attr, stored.len() as u64);
        Ok(written)
    }

    fn flush(&self, fh: &EngineFileHandle, _ctx: &RequestCtx) -> Result<(), Errno> {
        let state = self.state.borrow();
        let live = state.handles.get(&fh.fh_id.get()).ok_or(Errno::EBADF)?;
        if live.0 != fh.inode_id {
            return Err(Errno::EBADF);
        }
        Ok(())
    }

    fn fsync(
        &self,
        fh: &EngineFileHandle,
        _datasync: bool,
        _ctx: &RequestCtx,
    ) -> Result<(), Errno> {
        let state = self.state.borrow();
        let live = state.handles.get(&fh.fh_id.get()).ok_or(Errno::EBADF)?;
        if live.0 != fh.inode_id {
            return Err(Errno::EBADF);
        }
        Ok(())
    }

    fn fallocate(
        &self,
        fh: &EngineFileHandle,
        mode: u32,
        offset: u64,
        length: u64,
        _ctx: &RequestCtx,
    ) -> Result<(), Errno> {
        let mut state = self.state.borrow_mut();
        let live = state.handles.get(&fh.fh_id.get()).ok_or(Errno::EBADF)?;
        if live.0 != fh.inode_id {
            return Err(Errno::EBADF);
        }
        let inode_id = live.0;

        let end = offset.checked_add(length).ok_or(Errno::EINVAL)?;
        let off = usize::try_from(offset).map_err(|_| Errno::EINVAL)?;
        let end_us = usize::try_from(end).map_err(|_| Errno::EINVAL)?;
        let (attr, stored, _) = state.inodes.get_mut(&inode_id).ok_or(Errno::ENOENT)?;

        if mode & FALLOC_FL_PUNCH_HOLE != 0 {
            let zero_end = stored.len().min(end_us);
            if off < zero_end {
                stored[off..zero_end].fill(0);
            }
            return Ok(());
        }

        if mode & FALLOC_FL_ZERO_RANGE != 0 {
            let zero_end = if mode & FALLOC_FL_KEEP_SIZE != 0 {
                stored.len().min(end_us)
            } else {
                if stored.len() < end_us {
                    stored.resize(end_us, 0);
                }
                end_us
            };
            if off < zero_end {
                stored[off..zero_end].fill(0);
            }
            if mode & FALLOC_FL_KEEP_SIZE == 0 {
                Self::set_size(attr, stored.len() as u64);
            }
            return Ok(());
        }

        // default: allocate
        if mode & FALLOC_FL_KEEP_SIZE == 0 {
            if stored.len() < end_us {
                stored.resize(end_us, 0);
                Self::set_size(attr, stored.len() as u64);
            }
        }
        Ok(())
    }

    fn opendir(&self, inode: InodeId, _ctx: &RequestCtx) -> Result<EngineDirHandle, Errno> {
        let mut state = self.state.borrow_mut();
        Self::ensure_dir(&state, inode)?;
        let dh_id = state.next_dh;
        state.next_dh += 1;
        let dh = EngineDirHandle::new(inode, tidefs_vfs_engine::DirHandleId::new(dh_id));
        state.dir_handles.insert(dh_id, inode);
        Ok(dh)
    }

    fn releasedir(&self, dh: &EngineDirHandle) -> Result<(), Errno> {
        let mut state = self.state.borrow_mut();
        let live = state.dir_handles.get(&dh.dh_id.get()).ok_or(Errno::EBADF)?;
        if *live != dh.inode_id {
            return Err(Errno::EBADF);
        }
        state.dir_handles.remove(&dh.dh_id.get());
        Ok(())
    }

    fn readdir(
        &self,
        dh: &EngineDirHandle,
        offset: u64,
        _ctx: &RequestCtx,
    ) -> Result<(Vec<DirEntry>, bool), Errno> {
        let state = self.state.borrow();
        let inode_id = state
            .dir_handles
            .get(&dh.dh_id.get())
            .copied()
            .ok_or(Errno::EBADF)?;
        if inode_id != dh.inode_id {
            return Err(Errno::EBADF);
        }
        Self::ensure_dir(&state, inode_id)?;

        let mut entries: Vec<DirEntry> = state
            .entries
            .iter()
            .filter_map(|((parent, name), child)| {
                if *parent != inode_id {
                    return None;
                }
                let (attr, _, _) = state.inodes.get(child)?;
                Some(DirEntry::new(
                    name.clone(),
                    *child,
                    attr.kind,
                    attr.generation,
                    0,
                ))
            })
            .collect();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        for (i, e) in entries.iter_mut().enumerate() {
            e.cookie = i as u64 + 1;
        }

        let start = usize::try_from(offset).map_err(|_| Errno::EINVAL)?;
        if start >= entries.len() {
            return Ok((Vec::new(), false));
        }
        let batch_size = 8;
        let end = entries.len().min(start.saturating_add(batch_size));
        Ok((entries[start..end].to_vec(), end < entries.len()))
    }

    fn fsyncdir(
        &self,
        dh: &EngineDirHandle,
        _datasync: bool,
        _ctx: &RequestCtx,
    ) -> Result<(), Errno> {
        let state = self.state.borrow();
        let live = state.dir_handles.get(&dh.dh_id.get()).ok_or(Errno::EBADF)?;
        if *live != dh.inode_id {
            return Err(Errno::EBADF);
        }
        Ok(())
    }

    fn getxattr(&self, inode: InodeId, name: &[u8], _ctx: &RequestCtx) -> Result<Vec<u8>, Errno> {
        let state = self.state.borrow();
        let (_, _, xattrs) = state.inodes.get(&inode).ok_or(Errno::ENOENT)?;
        xattrs.get(name).cloned().ok_or(Errno::ENODATA)
    }

    fn setxattr(
        &self,
        inode: InodeId,
        name: &[u8],
        value: &[u8],
        flags: u32,
        _ctx: &RequestCtx,
    ) -> Result<(), Errno> {
        let mut state = self.state.borrow_mut();
        let (attr, _, xattrs) = state.inodes.get_mut(&inode).ok_or(Errno::ENOENT)?;
        let exists = xattrs.contains_key(name);
        if flags & XATTR_CREATE != 0 && exists {
            return Err(Errno::EEXIST);
        }
        if flags & XATTR_REPLACE != 0 && !exists {
            return Err(Errno::ENODATA);
        }
        xattrs.insert(name.to_vec(), value.to_vec());
        attr.posix.ctime_ns = Self::next_timestamp(attr);
        attr.subtree_rev = attr.subtree_rev.saturating_add(1);
        Ok(())
    }

    fn listxattr(&self, inode: InodeId, _ctx: &RequestCtx) -> Result<Vec<u8>, Errno> {
        let state = self.state.borrow();
        let (_, _, xattrs) = state.inodes.get(&inode).ok_or(Errno::ENOENT)?;
        let mut names: Vec<&Vec<u8>> = xattrs.keys().collect();
        names.sort();
        let mut encoded = Vec::new();
        for name in names {
            encoded.extend_from_slice(name);
            encoded.push(0);
        }
        Ok(encoded)
    }

    fn removexattr(&self, inode: InodeId, name: &[u8], _ctx: &RequestCtx) -> Result<(), Errno> {
        let mut state = self.state.borrow_mut();
        let (attr, _, xattrs) = state.inodes.get_mut(&inode).ok_or(Errno::ENOENT)?;
        if xattrs.remove(name).is_none() {
            return Err(Errno::ENODATA);
        }
        attr.posix.ctime_ns = Self::next_timestamp(attr);
        attr.subtree_rev = attr.subtree_rev.saturating_add(1);
        Ok(())
    }

    fn getlk(
        &self,
        _inode: InodeId,
        _lock: &LockSpec,
        _ctx: &RequestCtx,
    ) -> Result<Option<LockSpec>, Errno> {
        Err(Errno::ENOSYS)
    }

    fn setlk(&self, _inode: InodeId, _lock: &LockSpec, _ctx: &RequestCtx) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }
}

// ── Factory implementations ─────────────────────────────────────────────────

/// Returns a fresh `ContractTestEngine` as a trait object.
pub fn factory_contract_test_engine() -> Box<dyn VfsEngine> {
    Box::new(ContractTestEngine::new())
}

/// Returns a `ContractTestEngine` as a statfs-capable trait object.
pub fn factory_contract_statfs() -> Box<dyn VfsEngineStatFs> {
    struct StatFsEngine(ContractTestEngine);
    impl VfsEngine for StatFsEngine {
        fn get_root_inode(&self, ctx: &RequestCtx) -> Result<InodeId, Errno> {
            self.0.get_root_inode(ctx)
        }
        fn lookup(
            &self,
            parent: InodeId,
            name: &[u8],
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            self.0.lookup(parent, name, ctx)
        }
        fn getattr(
            &self,
            inode: InodeId,
            handle: Option<&EngineFileHandle>,
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            self.0.getattr(inode, handle, ctx)
        }
        fn setattr(
            &self,
            inode: InodeId,
            attr: &SetAttr,
            handle: Option<&EngineFileHandle>,
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            self.0.setattr(inode, attr, handle, ctx)
        }
        fn mkdir(
            &self,
            parent: InodeId,
            name: &[u8],
            mode: u32,
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            self.0.mkdir(parent, name, mode, ctx)
        }
        fn create(
            &self,
            parent: InodeId,
            name: &[u8],
            mode: u32,
            flags: u32,
            ctx: &RequestCtx,
        ) -> Result<(InodeAttr, EngineFileHandle), Errno> {
            self.0.create(parent, name, mode, flags, ctx)
        }
        fn tmpfile(
            &self,
            parent: InodeId,
            mode: u32,
            flags: u32,
            ctx: &RequestCtx,
        ) -> Result<(InodeAttr, EngineFileHandle), Errno> {
            self.0.tmpfile(parent, mode, flags, ctx)
        }
        fn unlink(&self, parent: InodeId, name: &[u8], ctx: &RequestCtx) -> Result<(), Errno> {
            self.0.unlink(parent, name, ctx)
        }
        fn rmdir(&self, parent: InodeId, name: &[u8], ctx: &RequestCtx) -> Result<(), Errno> {
            self.0.rmdir(parent, name, ctx)
        }
        fn rename(
            &self,
            old_p: InodeId,
            old_n: &[u8],
            new_p: InodeId,
            new_n: &[u8],
            flags: u32,
            ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            self.0.rename(old_p, old_n, new_p, new_n, flags, ctx)
        }
        fn link(
            &self,
            target: InodeId,
            new_p: InodeId,
            new_n: &[u8],
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            self.0.link(target, new_p, new_n, ctx)
        }
        fn symlink(
            &self,
            parent: InodeId,
            name: &[u8],
            target: &[u8],
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            self.0.symlink(parent, name, target, ctx)
        }
        fn readlink(&self, inode: InodeId, ctx: &RequestCtx) -> Result<Vec<u8>, Errno> {
            self.0.readlink(inode, ctx)
        }
        fn mknod(
            &self,
            parent: InodeId,
            name: &[u8],
            mode: u32,
            rdev: u32,
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            self.0.mknod(parent, name, mode, rdev, ctx)
        }
        fn open(
            &self,
            inode: InodeId,
            flags: u32,
            ctx: &RequestCtx,
        ) -> Result<EngineFileHandle, Errno> {
            self.0.open(inode, flags, ctx)
        }
        fn release(&self, fh: &EngineFileHandle) -> Result<(), Errno> {
            self.0.release(fh)
        }
        fn read(
            &self,
            fh: &EngineFileHandle,
            offset: u64,
            size: u32,
            ctx: &RequestCtx,
        ) -> Result<Vec<u8>, Errno> {
            self.0.read(fh, offset, size, ctx)
        }
        fn write(
            &self,
            fh: &EngineFileHandle,
            offset: u64,
            data: &[u8],
            ctx: &RequestCtx,
        ) -> Result<u32, Errno> {
            self.0.write(fh, offset, data, ctx)
        }
        fn flush(&self, fh: &EngineFileHandle, ctx: &RequestCtx) -> Result<(), Errno> {
            self.0.flush(fh, ctx)
        }
        fn fsync(
            &self,
            fh: &EngineFileHandle,
            datasync: bool,
            ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            self.0.fsync(fh, datasync, ctx)
        }
        fn fallocate(
            &self,
            fh: &EngineFileHandle,
            mode: u32,
            offset: u64,
            length: u64,
            ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            self.0.fallocate(fh, mode, offset, length, ctx)
        }
        fn opendir(&self, inode: InodeId, ctx: &RequestCtx) -> Result<EngineDirHandle, Errno> {
            self.0.opendir(inode, ctx)
        }
        fn releasedir(&self, dh: &EngineDirHandle) -> Result<(), Errno> {
            self.0.releasedir(dh)
        }
        fn readdir(
            &self,
            dh: &EngineDirHandle,
            offset: u64,
            ctx: &RequestCtx,
        ) -> Result<(Vec<DirEntry>, bool), Errno> {
            self.0.readdir(dh, offset, ctx)
        }
        fn fsyncdir(
            &self,
            dh: &EngineDirHandle,
            datasync: bool,
            ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            self.0.fsyncdir(dh, datasync, ctx)
        }
        fn getxattr(
            &self,
            inode: InodeId,
            name: &[u8],
            ctx: &RequestCtx,
        ) -> Result<Vec<u8>, Errno> {
            self.0.getxattr(inode, name, ctx)
        }
        fn setxattr(
            &self,
            inode: InodeId,
            name: &[u8],
            value: &[u8],
            flags: u32,
            ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            self.0.setxattr(inode, name, value, flags, ctx)
        }
        fn listxattr(&self, inode: InodeId, ctx: &RequestCtx) -> Result<Vec<u8>, Errno> {
            self.0.listxattr(inode, ctx)
        }
        fn removexattr(&self, inode: InodeId, name: &[u8], ctx: &RequestCtx) -> Result<(), Errno> {
            self.0.removexattr(inode, name, ctx)
        }
        fn getlk(
            &self,
            inode: InodeId,
            lock: &LockSpec,
            ctx: &RequestCtx,
        ) -> Result<Option<LockSpec>, Errno> {
            self.0.getlk(inode, lock, ctx)
        }
        fn setlk(&self, inode: InodeId, lock: &LockSpec, ctx: &RequestCtx) -> Result<(), Errno> {
            self.0.setlk(inode, lock, ctx)
        }
    }
    impl VfsEngineStatFs for StatFsEngine {
        fn statfs(&self, _ctx: &RequestCtx) -> Result<StatFs, Errno> {
            Ok(StatFs {
                block_size: 4096,
                fragment_size: 4096,
                total_blocks: 1000,
                free_blocks: 900,
                avail_blocks: 800,
                files: 100,
                files_free: 80,
                ..Default::default()
            })
        }
    }
    Box::new(StatFsEngine(ContractTestEngine::new()))
}

// ── Helpers ─────────────────────────────────────────────────────────────────

// Helper functions for contract tests
#[allow(dead_code)]
#[allow(dead_code)]
fn ctx() -> RequestCtx {
    RequestCtx {
        uid: 1000,
        gid: 1000,
        pid: 42,
        umask: 0o022,
        groups: vec![1000],
    }
}

#[allow(dead_code)]
fn create_file(engine: &dyn VfsEngine, name: &[u8], flags: u32) -> (InodeAttr, EngineFileHandle) {
    let root = engine.get_root_inode(&ctx()).expect("root");
    engine
        .create(root, name, 0o644, flags, &ctx())
        .expect("create")
}

#[allow(dead_code)]
fn create_dir(engine: &dyn VfsEngine, parent: InodeId, name: &[u8]) -> InodeAttr {
    engine.mkdir(parent, name, 0o755, &ctx()).expect("mkdir")
}

// ── Category 1: Open / Create / Remove round-trip ──────────────────────────

#[test]
fn contract_create_then_lookup_returns_same_inode() {
    let engine = factory_contract_test_engine();
    let root = engine.get_root_inode(&ctx()).unwrap();
    let (attr, _fh) = engine.create(root, b"alice", 0o644, 0, &ctx()).unwrap();
    assert_eq!(attr.kind, NodeKind::File);

    let looked_up = engine.lookup(root, b"alice", &ctx()).unwrap();
    assert_eq!(looked_up.inode_id, attr.inode_id);
    assert_eq!(looked_up.kind, NodeKind::File);
}

#[test]
fn contract_remove_then_lookup_returns_enoent() {
    let engine = factory_contract_test_engine();
    let root = engine.get_root_inode(&ctx()).unwrap();
    engine.create(root, b"temp", 0o644, 0, &ctx()).unwrap();
    engine.unlink(root, b"temp", &ctx()).unwrap();
    assert_eq!(engine.lookup(root, b"temp", &ctx()), Err(Errno::ENOENT));
}

#[test]
fn contract_create_existing_name_returns_eexist() {
    let engine = factory_contract_test_engine();
    let root = engine.get_root_inode(&ctx()).unwrap();
    engine.create(root, b"dup", 0o644, 0, &ctx()).unwrap();
    assert_eq!(
        engine.create(root, b"dup", 0o644, 0, &ctx()).unwrap_err(),
        Errno::EEXIST
    );
}

#[test]
fn contract_lookup_nonexistent_returns_enoent() {
    let engine = factory_contract_test_engine();
    let root = engine.get_root_inode(&ctx()).unwrap();
    assert_eq!(engine.lookup(root, b"nope", &ctx()), Err(Errno::ENOENT));
}

// ── Category 2: Read / Write consistency ───────────────────────────────────

#[test]
fn contract_write_then_read_returns_written_data() {
    let engine = factory_contract_test_engine();
    let (_attr, fh) = create_file(&*engine, b"rw.txt", 0o2); // O_RDWR
    let written = engine.write(&fh, 0, b"hello world", &ctx()).unwrap();
    assert_eq!(written, 11);

    let data = engine.read(&fh, 0, 11, &ctx()).unwrap();
    assert_eq!(data, b"hello world");
}

#[test]
fn contract_read_at_offset_returns_slice() {
    let engine = factory_contract_test_engine();
    let (_attr, fh) = create_file(&*engine, b"off.txt", 0o2);
    engine.write(&fh, 0, b"abcdefghij", &ctx()).unwrap();

    assert_eq!(engine.read(&fh, 3, 4, &ctx()).unwrap(), b"defg");
    assert_eq!(engine.read(&fh, 8, 4, &ctx()).unwrap(), b"ij");
}

#[test]
fn contract_read_past_eof_returns_empty() {
    let engine = factory_contract_test_engine();
    let (_attr, fh) = create_file(&*engine, b"eof.txt", 0o2);
    engine.write(&fh, 0, b"abc", &ctx()).unwrap();
    assert_eq!(engine.read(&fh, 100, 10, &ctx()).unwrap(), b"");
}

#[test]
fn contract_write_expands_file_size() {
    let engine = factory_contract_test_engine();
    let (attr, fh) = create_file(&*engine, b"expand.txt", 0o2);
    engine.write(&fh, 0, b"data", &ctx()).unwrap();

    let updated = engine.getattr(attr.inode_id, None, &ctx()).unwrap();
    assert_eq!(updated.posix.size, 4);
}

#[test]
fn contract_read_zero_size_returns_empty() {
    let engine = factory_contract_test_engine();
    let (_attr, fh) = create_file(&*engine, b"zero.txt", 0o2);
    assert_eq!(engine.read(&fh, 0, 0, &ctx()).unwrap(), b"");
}

#[test]
fn contract_write_zero_size_noop() {
    let engine = factory_contract_test_engine();
    let (attr, fh) = create_file(&*engine, b"noop.txt", 0o2);
    let written = engine.write(&fh, 0, b"", &ctx()).unwrap();
    assert_eq!(written, 0);
    let updated = engine.getattr(attr.inode_id, None, &ctx()).unwrap();
    assert_eq!(updated.posix.size, 0);
}

#[test]
fn contract_write_at_offset_creates_sparse_file() {
    let engine = factory_contract_test_engine();
    let (_attr, fh) = create_file(&*engine, b"sparse.txt", 0o2);
    engine.write(&fh, 10, b"end", &ctx()).unwrap();

    // bytes 0..10 should be zero-filled
    let head = engine.read(&fh, 0, 5, &ctx()).unwrap();
    assert_eq!(head, vec![0u8; 5]);
    let tail = engine.read(&fh, 10, 3, &ctx()).unwrap();
    assert_eq!(tail, b"end");
}

// ── Category 3: Directory operations ───────────────────────────────────────

#[test]
fn contract_mkdir_creates_directory() {
    let engine = factory_contract_test_engine();
    let root = engine.get_root_inode(&ctx()).unwrap();
    let dir_attr = create_dir(&*engine, root, b"subdir");
    assert_eq!(dir_attr.kind, NodeKind::Dir);

    let looked_up = engine.lookup(root, b"subdir", &ctx()).unwrap();
    assert_eq!(looked_up.inode_id, dir_attr.inode_id);
    assert_eq!(looked_up.kind, NodeKind::Dir);
}

#[test]
fn contract_mkdir_existing_returns_eexist() {
    let engine = factory_contract_test_engine();
    let root = engine.get_root_inode(&ctx()).unwrap();
    create_dir(&*engine, root, b"subdir");
    assert_eq!(
        engine.mkdir(root, b"subdir", 0o755, &ctx()).unwrap_err(),
        Errno::EEXIST
    );
}

#[test]
fn contract_readdir_lists_entries() {
    let engine = factory_contract_test_engine();
    let root = engine.get_root_inode(&ctx()).unwrap();
    let (af, _) = engine.create(root, b"alpha", 0o644, 0, &ctx()).unwrap();
    let (_bf, _) = engine.create(root, b"beta", 0o644, 0, &ctx()).unwrap();
    let df = create_dir(&*engine, root, b"gamma");

    let dh = engine.opendir(root, &ctx()).unwrap();
    let (entries, has_more) = engine.readdir(&dh, 0, &ctx()).unwrap();
    engine.releasedir(&dh).unwrap();

    assert!(!has_more); // all entries in one batch for small dir
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].name, b"alpha"); // sorted
    assert_eq!(entries[0].inode_id, af.inode_id);
    assert_eq!(entries[1].name, b"beta");
    assert_eq!(entries[2].name, b"gamma");
    assert_eq!(entries[2].inode_id, df.inode_id);
}

#[test]
fn contract_readdir_empty_directory_returns_empty() {
    let engine = factory_contract_test_engine();
    let root = engine.get_root_inode(&ctx()).unwrap();
    let subdir = create_dir(&*engine, root, b"empty");
    let dh = engine.opendir(subdir.inode_id, &ctx()).unwrap();
    let (entries, has_more) = engine.readdir(&dh, 0, &ctx()).unwrap();
    engine.releasedir(&dh).unwrap();
    assert!(entries.is_empty());
    assert!(!has_more);
}

#[test]
fn contract_opendir_nonexistent_returns_enoent() {
    let engine = factory_contract_test_engine();
    assert_eq!(
        engine.opendir(InodeId::new(99999), &ctx()).unwrap_err(),
        Errno::ENOENT
    );
}

#[test]
fn contract_opendir_on_file_returns_enotdir() {
    let engine = factory_contract_test_engine();
    let (attr, _fh) = create_file(&*engine, b"notadir", 0);
    assert_eq!(
        engine.opendir(attr.inode_id, &ctx()).unwrap_err(),
        Errno::ENOTDIR
    );
}

// ── Category 4: Rename ─────────────────────────────────────────────────────

#[test]
fn contract_rename_within_directory() {
    let engine = factory_contract_test_engine();
    let root = engine.get_root_inode(&ctx()).unwrap();
    let (attr, _fh) = engine.create(root, b"old", 0o644, 0, &ctx()).unwrap();
    engine
        .rename(root, b"old", root, b"new", 0, &ctx())
        .unwrap();

    assert_eq!(engine.lookup(root, b"old", &ctx()), Err(Errno::ENOENT));
    let new_attr = engine.lookup(root, b"new", &ctx()).unwrap();
    assert_eq!(new_attr.inode_id, attr.inode_id);
}

#[test]
fn contract_rename_overwrites_existing_file() {
    let engine = factory_contract_test_engine();
    let root = engine.get_root_inode(&ctx()).unwrap();
    let (src_attr, src_fh) = engine.create(root, b"src", 0o644, 0o2, &ctx()).unwrap();
    engine.write(&src_fh, 0, b"source data", &ctx()).unwrap();
    let (dst_attr, _dst_fh) = engine.create(root, b"dst", 0o644, 0, &ctx()).unwrap();

    engine
        .rename(root, b"src", root, b"dst", 0, &ctx())
        .unwrap();

    // old dst should be removed, src data should be at "dst"
    let looked_up = engine.lookup(root, b"dst", &ctx()).unwrap();
    assert_eq!(looked_up.inode_id, src_attr.inode_id);
    assert_ne!(looked_up.inode_id, dst_attr.inode_id);

    let re_fh = engine.open(looked_up.inode_id, 0, &ctx()).unwrap();
    let data = engine.read(&re_fh, 0, 11, &ctx()).unwrap();
    assert_eq!(data, b"source data");
    engine.release(&re_fh).unwrap();
}

#[test]
fn contract_rename_across_directories() {
    let engine = factory_contract_test_engine();
    let root = engine.get_root_inode(&ctx()).unwrap();
    let dir_a = create_dir(&*engine, root, b"a");
    let dir_b = create_dir(&*engine, root, b"b");
    let (file_attr, _fh) = engine
        .create(dir_a.inode_id, b"file", 0o644, 0, &ctx())
        .unwrap();

    engine
        .rename(dir_a.inode_id, b"file", dir_b.inode_id, b"moved", 0, &ctx())
        .unwrap();

    let looked_up = engine.lookup(dir_b.inode_id, b"moved", &ctx()).unwrap();
    assert_eq!(looked_up.inode_id, file_attr.inode_id);
    assert_eq!(
        engine.lookup(dir_a.inode_id, b"file", &ctx()),
        Err(Errno::ENOENT)
    );
}

#[test]
fn contract_rename_noreplace_fails_when_target_exists() {
    let engine = factory_contract_test_engine();
    let root = engine.get_root_inode(&ctx()).unwrap();
    engine.create(root, b"original", 0o644, 0, &ctx()).unwrap();
    engine.create(root, b"existing", 0o644, 0, &ctx()).unwrap();
    assert_eq!(
        engine
            .rename(
                root,
                b"original",
                root,
                b"existing",
                RENAME_NOREPLACE,
                &ctx()
            )
            .unwrap_err(),
        Errno::EEXIST
    );
}

#[test]
fn contract_rename_exchange_swaps_entries() {
    let engine = factory_contract_test_engine();
    let root = engine.get_root_inode(&ctx()).unwrap();
    let (left_attr, left_fh) = engine.create(root, b"left", 0o644, 0o2, &ctx()).unwrap();
    engine.write(&left_fh, 0, b"LEFT", &ctx()).unwrap();
    let (right_attr, right_fh) = engine.create(root, b"right", 0o644, 0o2, &ctx()).unwrap();
    engine.write(&right_fh, 0, b"RIGHT", &ctx()).unwrap();

    engine
        .rename(root, b"left", root, b"right", RENAME_EXCHANGE, &ctx())
        .unwrap();

    // Names are swapped, inodes follow
    let left_now = engine.lookup(root, b"left", &ctx()).unwrap();
    let right_now = engine.lookup(root, b"right", &ctx()).unwrap();
    assert_eq!(left_now.inode_id, right_attr.inode_id);
    assert_eq!(right_now.inode_id, left_attr.inode_id);

    // Data verification
    let lfh = engine.open(left_now.inode_id, 0, &ctx()).unwrap();
    let rfh = engine.open(right_now.inode_id, 0, &ctx()).unwrap();
    assert_eq!(engine.read(&lfh, 0, 5, &ctx()).unwrap(), b"RIGHT");
    assert_eq!(engine.read(&rfh, 0, 4, &ctx()).unwrap(), b"LEFT");
    engine.release(&lfh).unwrap();
    engine.release(&rfh).unwrap();
}

#[test]
fn contract_rename_file_over_dir_returns_eisdir() {
    let engine = factory_contract_test_engine();
    let root = engine.get_root_inode(&ctx()).unwrap();
    engine.create(root, b"file", 0o644, 0, &ctx()).unwrap();
    create_dir(&*engine, root, b"empty_dir");
    // POSIX: cannot replace a directory with a non-directory
    assert_eq!(
        engine
            .rename(root, b"file", root, b"empty_dir", 0, &ctx())
            .unwrap_err(),
        Errno::EISDIR
    );
}

#[test]
fn contract_rename_nonempty_dir_over_file_fails() {
    let engine = factory_contract_test_engine();
    let root = engine.get_root_inode(&ctx()).unwrap();
    engine.create(root, b"file", 0o644, 0, &ctx()).unwrap();
    let dir = create_dir(&*engine, root, b"nonempty");
    engine
        .create(dir.inode_id, b"child", 0o644, 0, &ctx())
        .unwrap();
    assert!(engine
        .rename(root, b"nonempty", root, b"file", 0, &ctx())
        .is_err());
}

// ── Category 5: Getattr / Setattr round-trip ───────────────────────────────

#[test]
fn contract_setattr_size_then_getattr() {
    let engine = factory_contract_test_engine();
    let (attr, fh) = create_file(&*engine, b"size.txt", 0o2);
    engine.write(&fh, 0, b"0123456789", &ctx()).unwrap();

    let mut sa = SetAttr::new();
    sa.valid = FATTR_SIZE;
    sa.size = 5;
    let updated = engine
        .setattr(attr.inode_id, &sa, Some(&fh), &ctx())
        .unwrap();
    assert_eq!(updated.posix.size, 5);

    let re_read = engine.getattr(attr.inode_id, None, &ctx()).unwrap();
    assert_eq!(re_read.posix.size, 5);
}

#[test]
fn contract_setattr_size_to_zero() {
    let engine = factory_contract_test_engine();
    let (attr, fh) = create_file(&*engine, b"trunc.txt", 0o2);
    engine.write(&fh, 0, b"some data", &ctx()).unwrap();

    let mut sa = SetAttr::new();
    sa.valid = FATTR_SIZE;
    sa.size = 0;
    let updated = engine
        .setattr(attr.inode_id, &sa, Some(&fh), &ctx())
        .unwrap();
    assert_eq!(updated.posix.size, 0);

    let data = engine.read(&fh, 0, 10, &ctx()).unwrap();
    assert_eq!(data, b"");
}

#[test]
fn contract_setattr_mode() {
    let engine = factory_contract_test_engine();
    let (attr, _fh) = create_file(&*engine, b"mode.txt", 0);
    let mut sa = SetAttr::new();
    sa.valid = FATTR_MODE;
    sa.mode = 0o600;
    let updated = engine.setattr(attr.inode_id, &sa, None, &ctx()).unwrap();
    assert_eq!(updated.posix.mode & !S_IFMT, 0o600);
    assert_eq!(updated.posix.mode & S_IFMT, S_IFREG);
}

#[test]
fn contract_setattr_nonexistent_returns_enoent() {
    let engine = factory_contract_test_engine();
    let mut sa = SetAttr::new();
    sa.valid = FATTR_SIZE;
    sa.size = 100;
    assert_eq!(
        engine
            .setattr(InodeId::new(99999), &sa, None, &ctx())
            .unwrap_err(),
        Errno::ENOENT
    );
}

#[test]
fn contract_getattr_nonexistent_returns_enoent() {
    let engine = factory_contract_test_engine();
    assert_eq!(
        engine
            .getattr(InodeId::new(99999), None, &ctx())
            .unwrap_err(),
        Errno::ENOENT
    );
}

// ── Category 6: Fallocate ──────────────────────────────────────────────────

#[test]
fn contract_fallocate_allocates_space() {
    let engine = factory_contract_test_engine();
    let (attr, fh) = create_file(&*engine, b"alloc.bin", 0o2);
    engine.fallocate(&fh, 0, 0, 4096, &ctx()).unwrap();

    let updated = engine.getattr(attr.inode_id, None, &ctx()).unwrap();
    assert_eq!(updated.posix.size, 4096);

    let data = engine.read(&fh, 0, 4, &ctx()).unwrap();
    assert_eq!(data, vec![0u8; 4]); // zero-filled
}

#[test]
fn contract_fallocate_punch_hole_zeroes_data() {
    let engine = factory_contract_test_engine();
    let (_attr, fh) = create_file(&*engine, b"hole.bin", 0o2);
    engine.write(&fh, 0, b"HELLO_WORLD", &ctx()).unwrap();

    engine
        .fallocate(
            &fh,
            FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
            0,
            5,
            &ctx(),
        )
        .unwrap();

    let data = engine.read(&fh, 0, 11, &ctx()).unwrap();
    assert_eq!(&data[0..5], b"\0\0\0\0\0");
    assert_eq!(&data[5..11], b"_WORLD");
}

#[test]
fn contract_fallocate_zero_range() {
    let engine = factory_contract_test_engine();
    let (_attr, fh) = create_file(&*engine, b"zero.bin", 0o2);
    engine.write(&fh, 0, b"DATA_HERE", &ctx()).unwrap();

    engine
        .fallocate(&fh, FALLOC_FL_ZERO_RANGE, 0, 4, &ctx())
        .unwrap();

    let data = engine.read(&fh, 0, 9, &ctx()).unwrap();
    assert_eq!(&data[0..4], b"\0\0\0\0");
    assert_eq!(&data[4..9], b"_HERE");
}

#[test]
fn contract_fallocate_overflow_offset_returns_einval() {
    let engine = factory_contract_test_engine();
    let (_attr, fh) = create_file(&*engine, b"overflow.bin", 0o2);
    assert_eq!(
        engine.fallocate(&fh, 0, u64::MAX, 1, &ctx()).unwrap_err(),
        Errno::EINVAL
    );
}

// ── Category 7: Unlink / Rmdir ─────────────────────────────────────────────

#[test]
fn contract_rmdir_removes_empty_directory() {
    let engine = factory_contract_test_engine();
    let root = engine.get_root_inode(&ctx()).unwrap();
    let _dir = create_dir(&*engine, root, b"toremove");
    engine.rmdir(root, b"toremove", &ctx()).unwrap();
    assert_eq!(engine.lookup(root, b"toremove", &ctx()), Err(Errno::ENOENT));
}

#[test]
fn contract_rmdir_nonempty_returns_enotempty() {
    let engine = factory_contract_test_engine();
    let root = engine.get_root_inode(&ctx()).unwrap();
    let dir = create_dir(&*engine, root, b"parent");
    engine
        .create(dir.inode_id, b"child", 0o644, 0, &ctx())
        .unwrap();
    assert_eq!(
        engine.rmdir(root, b"parent", &ctx()).unwrap_err(),
        Errno::ENOTEMPTY
    );
}

#[test]
fn contract_rmdir_on_file_returns_enotdir() {
    let engine = factory_contract_test_engine();
    let root = engine.get_root_inode(&ctx()).unwrap();
    let (_attr, _fh) = create_file(&*engine, b"notadir", 0);
    assert_eq!(
        engine.rmdir(root, b"notadir", &ctx()).unwrap_err(),
        Errno::ENOTDIR
    );
}

#[test]
fn contract_unlink_file_then_recreate() {
    let engine = factory_contract_test_engine();
    let root = engine.get_root_inode(&ctx()).unwrap();
    let (old_attr, _fh) = create_file(&*engine, b"recreate.txt", 0);
    engine.unlink(root, b"recreate.txt", &ctx()).unwrap();

    let (new_attr, _fh2) = engine
        .create(root, b"recreate.txt", 0o644, 0, &ctx())
        .unwrap();
    assert_ne!(new_attr.inode_id, old_attr.inode_id); // fresh inode
}

#[test]
fn contract_unlink_nonexistent_returns_enoent() {
    let engine = factory_contract_test_engine();
    let root = engine.get_root_inode(&ctx()).unwrap();
    assert_eq!(
        engine.unlink(root, b"nope", &ctx()).unwrap_err(),
        Errno::ENOENT
    );
}

// ── Category 8: Link ───────────────────────────────────────────────────────

#[test]
fn contract_link_creates_second_name() {
    let engine = factory_contract_test_engine();
    let root = engine.get_root_inode(&ctx()).unwrap();
    let (attr, fh) = create_file(&*engine, b"original", 0o2);
    engine.write(&fh, 0, b"shared", &ctx()).unwrap();

    let link_attr = engine.link(attr.inode_id, root, b"alias", &ctx()).unwrap();
    assert_eq!(link_attr.inode_id, attr.inode_id);
    assert_eq!(link_attr.posix.nlink, 2);

    // Read through alias
    let alias_fh = engine.open(link_attr.inode_id, 0, &ctx()).unwrap();
    let data = engine.read(&alias_fh, 0, 6, &ctx()).unwrap();
    assert_eq!(data, b"shared");
    engine.release(&alias_fh).unwrap();
}

#[test]
fn contract_link_directory_returns_eperm() {
    let engine = factory_contract_test_engine();
    let root = engine.get_root_inode(&ctx()).unwrap();
    let dir = create_dir(&*engine, root, b"dir");
    assert_eq!(
        engine
            .link(dir.inode_id, root, b"dir_alias", &ctx())
            .unwrap_err(),
        Errno::EPERM
    );
}

// ── Category 9: Symlink / Readlink ─────────────────────────────────────────

#[test]
fn contract_symlink_then_readlink_roundtrip() {
    let engine = factory_contract_test_engine();
    let root = engine.get_root_inode(&ctx()).unwrap();
    let sl_attr = engine
        .symlink(root, b"link", b"/target/path", &ctx())
        .unwrap();
    assert_eq!(sl_attr.kind, NodeKind::Symlink);

    let target = engine.readlink(sl_attr.inode_id, &ctx()).unwrap();
    assert_eq!(target, b"/target/path");
}

#[test]
fn contract_readlink_on_file_returns_einval() {
    let engine = factory_contract_test_engine();
    let (attr, _fh) = create_file(&*engine, b"notalink", 0);
    assert_eq!(
        engine.readlink(attr.inode_id, &ctx()).unwrap_err(),
        Errno::EINVAL
    );
}

// ── Category 10: Mknod ─────────────────────────────────────────────────────

#[test]
fn contract_mknod_fifo_creates_named_pipe() {
    let engine = factory_contract_test_engine();
    let root = engine.get_root_inode(&ctx()).unwrap();
    let attr = engine
        .mknod(root, b"pipe", S_IFIFO | 0o644, 0, &ctx())
        .unwrap();
    assert_eq!(attr.kind, NodeKind::Fifo);
}

// ── Category 11: Flush / Fsync ─────────────────────────────────────────────

#[test]
fn contract_flush_on_valid_handle_succeeds() {
    let engine = factory_contract_test_engine();
    let (_attr, fh) = create_file(&*engine, b"flush.txt", 0o2);
    engine.write(&fh, 0, b"data", &ctx()).unwrap();
    engine.flush(&fh, &ctx()).unwrap();
}

#[test]
fn contract_fsync_on_valid_handle_succeeds() {
    let engine = factory_contract_test_engine();
    let (_attr, fh) = create_file(&*engine, b"fsync.txt", 0o2);
    engine.write(&fh, 0, b"data", &ctx()).unwrap();
    engine.fsync(&fh, true, &ctx()).unwrap();
    engine.fsync(&fh, false, &ctx()).unwrap();
}

#[test]
fn contract_flush_invalid_handle_returns_ebadf() {
    let engine = factory_contract_test_engine();
    let (attr, _fh) = create_file(&*engine, b"bad.txt", 0o2);
    let bogus = EngineFileHandle::new(
        attr.inode_id,
        0o2,
        tidefs_vfs_engine::FileHandleId::new(99999),
        0,
    );
    assert_eq!(engine.flush(&bogus, &ctx()), Err(Errno::EBADF));
}

// ── Category 12: Xattr ────────────────────────────────────────────────────

#[test]
fn contract_setxattr_then_getxattr_roundtrip() {
    let engine = factory_contract_test_engine();
    let (attr, _fh) = create_file(&*engine, b"x.txt", 0);
    engine
        .setxattr(attr.inode_id, b"user.key", b"my-value", 0, &ctx())
        .unwrap();

    let value = engine.getxattr(attr.inode_id, b"user.key", &ctx()).unwrap();
    assert_eq!(value, b"my-value");
}

#[test]
fn contract_getxattr_missing_returns_enodata() {
    let engine = factory_contract_test_engine();
    let (attr, _fh) = create_file(&*engine, b"nox.txt", 0);
    assert_eq!(
        engine
            .getxattr(attr.inode_id, b"user.missing", &ctx())
            .unwrap_err(),
        Errno::ENODATA
    );
}

#[test]
fn contract_setxattr_create_flag_fails_when_exists() {
    let engine = factory_contract_test_engine();
    let (attr, _fh) = create_file(&*engine, b"cx.txt", 0);
    engine
        .setxattr(attr.inode_id, b"user.k", b"v1", 0, &ctx())
        .unwrap();
    assert_eq!(
        engine
            .setxattr(attr.inode_id, b"user.k", b"v2", XATTR_CREATE, &ctx())
            .unwrap_err(),
        Errno::EEXIST
    );
}

#[test]
fn contract_setxattr_replace_flag_fails_when_missing() {
    let engine = factory_contract_test_engine();
    let (attr, _fh) = create_file(&*engine, b"rx.txt", 0);
    assert_eq!(
        engine
            .setxattr(attr.inode_id, b"user.k", b"v", XATTR_REPLACE, &ctx())
            .unwrap_err(),
        Errno::ENODATA
    );
}

#[test]
fn contract_listxattr_returns_names() {
    let engine = factory_contract_test_engine();
    let (attr, _fh) = create_file(&*engine, b"list.txt", 0);
    engine
        .setxattr(attr.inode_id, b"user.a", b"1", 0, &ctx())
        .unwrap();
    engine
        .setxattr(attr.inode_id, b"user.b", b"2", 0, &ctx())
        .unwrap();

    let list = engine.listxattr(attr.inode_id, &ctx()).unwrap();
    let mut parts: Vec<&[u8]> = list.split(|b| *b == 0).filter(|s| !s.is_empty()).collect();
    parts.sort();
    assert_eq!(parts, vec![b"user.a".as_slice(), b"user.b".as_slice()]);
}

#[test]
fn contract_removexattr_deletes_attribute() {
    let engine = factory_contract_test_engine();
    let (attr, _fh) = create_file(&*engine, b"rm.txt", 0);
    engine
        .setxattr(attr.inode_id, b"user.key", b"val", 0, &ctx())
        .unwrap();
    engine
        .removexattr(attr.inode_id, b"user.key", &ctx())
        .unwrap();
    assert_eq!(
        engine
            .getxattr(attr.inode_id, b"user.key", &ctx())
            .unwrap_err(),
        Errno::ENODATA
    );
}

#[test]
fn contract_removexattr_missing_returns_enodata() {
    let engine = factory_contract_test_engine();
    let (attr, _fh) = create_file(&*engine, b"rmm.txt", 0);
    assert_eq!(
        engine
            .removexattr(attr.inode_id, b"user.nope", &ctx())
            .unwrap_err(),
        Errno::ENODATA
    );
}

// ── Category 13: Integration round-trips ───────────────────────────────────

#[test]
fn contract_integration_create_write_fsync_reopen_read() {
    let engine = factory_contract_test_engine();
    let root = engine.get_root_inode(&ctx()).unwrap();
    let (attr, fh) = engine
        .create(root, b"lifecycle.txt", 0o644, 0o2, &ctx())
        .unwrap();
    engine.write(&fh, 0, b"persistent data", &ctx()).unwrap();
    engine.fsync(&fh, false, &ctx()).unwrap();
    engine.release(&fh).unwrap();

    // Re-open and verify
    let reopened = engine.open(attr.inode_id, 0, &ctx()).unwrap();
    let data = engine.read(&reopened, 0, 15, &ctx()).unwrap();
    assert_eq!(data, b"persistent data");
    engine.release(&reopened).unwrap();
}

#[test]
fn contract_integration_create_dir_create_file_iterate() {
    let engine = factory_contract_test_engine();
    let root = engine.get_root_inode(&ctx()).unwrap();
    let dir = create_dir(&*engine, root, b"project");
    let (f1, _) = engine
        .create(dir.inode_id, b"README.md", 0o644, 0, &ctx())
        .unwrap();
    let (f2, _) = engine
        .create(dir.inode_id, b"main.rs", 0o644, 0, &ctx())
        .unwrap();

    let dh = engine.opendir(dir.inode_id, &ctx()).unwrap();
    let (entries, has_more) = engine.readdir(&dh, 0, &ctx()).unwrap();
    engine.releasedir(&dh).unwrap();

    assert!(!has_more);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name, b"README.md");
    assert_eq!(entries[0].inode_id, f1.inode_id);
    assert_eq!(entries[1].name, b"main.rs");
    assert_eq!(entries[1].inode_id, f2.inode_id);
}

#[test]
fn contract_integration_link_then_stat_both() {
    let engine = factory_contract_test_engine();
    let root = engine.get_root_inode(&ctx()).unwrap();
    let (attr, _fh) = create_file(&*engine, b"original", 0o2);
    let link_attr = engine
        .link(attr.inode_id, root, b"hardlink", &ctx())
        .unwrap();

    assert_eq!(link_attr.inode_id, attr.inode_id);
    let orig_stat = engine.getattr(attr.inode_id, None, &ctx()).unwrap();
    let link_stat = engine.getattr(link_attr.inode_id, None, &ctx()).unwrap();
    assert_eq!(orig_stat.inode_id, link_stat.inode_id);
    assert_eq!(orig_stat.posix.nlink, 2);
    assert_eq!(link_stat.posix.nlink, 2);
}

#[test]
fn contract_integration_write_punch_hole_read() {
    let engine = factory_contract_test_engine();
    let (_attr, fh) = create_file(&*engine, b"punch.txt", 0o2);
    engine.write(&fh, 0, b"ABCDEFGHIJ", &ctx()).unwrap();

    engine
        .fallocate(
            &fh,
            FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
            2,
            4,
            &ctx(),
        )
        .unwrap();

    let data = engine.read(&fh, 0, 10, &ctx()).unwrap();
    assert_eq!(&data[0..2], b"AB");
    assert_eq!(&data[2..6], b"\0\0\0\0");
    assert_eq!(&data[6..10], b"GHIJ");
}

#[test]
fn contract_integration_rename_overwrite_then_verify() {
    let engine = factory_contract_test_engine();
    let root = engine.get_root_inode(&ctx()).unwrap();
    let (src_attr, src_fh) = engine.create(root, b"src", 0o644, 0o2, &ctx()).unwrap();
    engine.write(&src_fh, 0, b"SRC_DATA", &ctx()).unwrap();
    let (_dst_attr, dst_fh) = engine.create(root, b"dst", 0o644, 0o2, &ctx()).unwrap();
    engine.write(&dst_fh, 0, b"OLD_DST", &ctx()).unwrap();

    engine
        .rename(root, b"src", root, b"dst", 0, &ctx())
        .unwrap();

    // "dst" now has src data
    let dst_after = engine.lookup(root, b"dst", &ctx()).unwrap();
    assert_eq!(dst_after.inode_id, src_attr.inode_id);
    let reopened = engine.open(dst_after.inode_id, 0, &ctx()).unwrap();
    assert_eq!(engine.read(&reopened, 0, 8, &ctx()).unwrap(), b"SRC_DATA");
    engine.release(&reopened).unwrap();
    // "src" is gone
    assert_eq!(engine.lookup(root, b"src", &ctx()), Err(Errno::ENOENT));
}

// ── Category 14: Error-path coverage ──────────────────────────────────────

#[test]
fn contract_error_enoent_lookup_nonexistent() {
    let engine = factory_contract_test_engine();
    let root = engine.get_root_inode(&ctx()).unwrap();
    assert_eq!(engine.lookup(root, b"ghost", &ctx()), Err(Errno::ENOENT));
}

#[test]
fn contract_error_enoent_read_nonexistent_inode() {
    let engine = factory_contract_test_engine();
    let ghost_fh = EngineFileHandle::new(
        InodeId::new(99999),
        0o2,
        tidefs_vfs_engine::FileHandleId::new(1),
        0,
    );
    // The handle isn't registered, so we get EBADF before ENOENT
    assert_eq!(engine.read(&ghost_fh, 0, 10, &ctx()), Err(Errno::EBADF));
}

#[test]
fn contract_error_enotdir_operations_on_file() {
    let engine = factory_contract_test_engine();
    let (attr, _fh) = create_file(&*engine, b"file.txt", 0);
    // opendir on a file
    assert_eq!(engine.opendir(attr.inode_id, &ctx()), Err(Errno::ENOTDIR));
    // lookup not-a-dir
    assert_eq!(
        engine.lookup(attr.inode_id, b"anything", &ctx()),
        Err(Errno::ENOTDIR)
    );
}

#[test]
fn contract_error_eisdir_open_on_directory() {
    let engine = factory_contract_test_engine();
    let root = engine.get_root_inode(&ctx()).unwrap();
    let dir = create_dir(&*engine, root, b"adir");
    assert_eq!(engine.open(dir.inode_id, 0, &ctx()), Err(Errno::EISDIR));
}

#[test]
fn contract_error_ebadf_read_write_only_handle() {
    let engine = factory_contract_test_engine();
    let (_attr, fh) = create_file(&*engine, b"wo.txt", 0o1); // O_WRONLY
    assert_eq!(engine.read(&fh, 0, 10, &ctx()), Err(Errno::EBADF));
}

#[test]
fn contract_error_ebadf_write_read_only_handle() {
    let engine = factory_contract_test_engine();
    let (_attr, fh) = create_file(&*engine, b"ro.txt", 0); // O_RDONLY
    assert_eq!(engine.write(&fh, 0, b"data", &ctx()), Err(Errno::EBADF));
}

#[test]
fn contract_error_ebadf_operations_on_released_handle() {
    let engine = factory_contract_test_engine();
    let (_attr, fh) = create_file(&*engine, b"rel.txt", 0o2);
    engine.release(&fh).unwrap();
    assert_eq!(engine.read(&fh, 0, 1, &ctx()), Err(Errno::EBADF));
    assert_eq!(engine.write(&fh, 0, b"x", &ctx()), Err(Errno::EBADF));
}

#[test]
fn contract_read_max_offset_returns_empty() {
    let engine = factory_contract_test_engine();
    let (_attr, fh) = create_file(&*engine, b"bigoff.txt", 0o2);
    // Reading at max offset on an empty file: offset > file size, returns empty
    let result = engine.read(&fh, u64::MAX, 1, &ctx()).unwrap();
    assert!(result.is_empty());
}

// ── Category 15: StatFs ────────────────────────────────────────────────────

#[test]
fn contract_statfs_returns_valid_stats() {
    let engine = factory_contract_statfs();
    let stats = engine.statfs(&ctx()).unwrap();
    assert!(stats.block_size > 0);
    assert!(stats.total_blocks > 0);
    assert!(stats.free_blocks <= stats.total_blocks);
    assert!(stats.avail_blocks <= stats.free_blocks);
    assert!(stats.files > 0);
}

// ── Local filesystem fixture (requires local-filesystem feature) ────────────

#[cfg(feature = "fuse")]
#[allow(dead_code)]
mod local_fs_fixture {
    use super::*;
    use tidefs_local_filesystem::{vfs_engine_impl::VfsLocalFileSystem, LocalFileSystem};

    /// Fixture that owns the temp directory and the VfsEngine adapter.
    pub struct LocalFsFixture {
        _dir: tempfile::TempDir,
        engine: VfsLocalFileSystem,
    }

    impl LocalFsFixture {
        pub fn new() -> Self {
            let dir = tempfile::TempDir::new().expect("tempdir for local-fs contract tests");
            let root_path = dir.path().to_str().unwrap().to_string();
            std::env::set_var("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64));
            let fs = LocalFileSystem::open(&root_path).expect("open LocalFileSystem");
            let engine = VfsLocalFileSystem::new(fs);
            Self { _dir: dir, engine }
        }
    }

    impl VfsEngine for LocalFsFixture {
        fn get_root_inode(&self, ctx: &RequestCtx) -> Result<InodeId, Errno> {
            self.engine.get_root_inode(ctx)
        }
        fn lookup(
            &self,
            parent: InodeId,
            name: &[u8],
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            self.engine.lookup(parent, name, ctx)
        }
        fn getattr(
            &self,
            inode: InodeId,
            handle: Option<&EngineFileHandle>,
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            self.engine.getattr(inode, handle, ctx)
        }
        fn setattr(
            &self,
            inode: InodeId,
            attr: &SetAttr,
            handle: Option<&EngineFileHandle>,
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            self.engine.setattr(inode, attr, handle, ctx)
        }
        fn mkdir(
            &self,
            parent: InodeId,
            name: &[u8],
            mode: u32,
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            self.engine.mkdir(parent, name, mode, ctx)
        }
        fn create(
            &self,
            parent: InodeId,
            name: &[u8],
            mode: u32,
            flags: u32,
            ctx: &RequestCtx,
        ) -> Result<(InodeAttr, EngineFileHandle), Errno> {
            self.engine.create(parent, name, mode, flags, ctx)
        }
        fn tmpfile(
            &self,
            parent: InodeId,
            mode: u32,
            flags: u32,
            ctx: &RequestCtx,
        ) -> Result<(InodeAttr, EngineFileHandle), Errno> {
            self.engine.tmpfile(parent, mode, flags, ctx)
        }
        fn unlink(&self, parent: InodeId, name: &[u8], ctx: &RequestCtx) -> Result<(), Errno> {
            self.engine.unlink(parent, name, ctx)
        }
        fn rmdir(&self, parent: InodeId, name: &[u8], ctx: &RequestCtx) -> Result<(), Errno> {
            self.engine.rmdir(parent, name, ctx)
        }
        fn rename(
            &self,
            old_p: InodeId,
            old_n: &[u8],
            new_p: InodeId,
            new_n: &[u8],
            flags: u32,
            ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            self.engine.rename(old_p, old_n, new_p, new_n, flags, ctx)
        }
        fn link(
            &self,
            target: InodeId,
            new_p: InodeId,
            new_n: &[u8],
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            self.engine.link(target, new_p, new_n, ctx)
        }
        fn symlink(
            &self,
            parent: InodeId,
            name: &[u8],
            target: &[u8],
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            self.engine.symlink(parent, name, target, ctx)
        }
        fn readlink(&self, inode: InodeId, ctx: &RequestCtx) -> Result<Vec<u8>, Errno> {
            self.engine.readlink(inode, ctx)
        }
        fn mknod(
            &self,
            parent: InodeId,
            name: &[u8],
            mode: u32,
            rdev: u32,
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            self.engine.mknod(parent, name, mode, rdev, ctx)
        }
        fn open(
            &self,
            inode: InodeId,
            flags: u32,
            ctx: &RequestCtx,
        ) -> Result<EngineFileHandle, Errno> {
            self.engine.open(inode, flags, ctx)
        }
        fn release(&self, fh: &EngineFileHandle) -> Result<(), Errno> {
            self.engine.release(fh)
        }
        fn read(
            &self,
            fh: &EngineFileHandle,
            offset: u64,
            size: u32,
            ctx: &RequestCtx,
        ) -> Result<Vec<u8>, Errno> {
            self.engine.read(fh, offset, size, ctx)
        }
        fn write(
            &self,
            fh: &EngineFileHandle,
            offset: u64,
            data: &[u8],
            ctx: &RequestCtx,
        ) -> Result<u32, Errno> {
            self.engine.write(fh, offset, data, ctx)
        }
        fn flush(&self, fh: &EngineFileHandle, ctx: &RequestCtx) -> Result<(), Errno> {
            self.engine.flush(fh, ctx)
        }
        fn fsync(
            &self,
            fh: &EngineFileHandle,
            datasync: bool,
            ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            self.engine.fsync(fh, datasync, ctx)
        }
        fn fallocate(
            &self,
            fh: &EngineFileHandle,
            mode: u32,
            offset: u64,
            length: u64,
            ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            self.engine.fallocate(fh, mode, offset, length, ctx)
        }
        fn opendir(&self, inode: InodeId, ctx: &RequestCtx) -> Result<EngineDirHandle, Errno> {
            self.engine.opendir(inode, ctx)
        }
        fn releasedir(&self, dh: &EngineDirHandle) -> Result<(), Errno> {
            self.engine.releasedir(dh)
        }
        fn readdir(
            &self,
            dh: &EngineDirHandle,
            offset: u64,
            ctx: &RequestCtx,
        ) -> Result<(Vec<DirEntry>, bool), Errno> {
            self.engine.readdir(dh, offset, ctx)
        }
        fn fsyncdir(
            &self,
            dh: &EngineDirHandle,
            datasync: bool,
            ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            self.engine.fsyncdir(dh, datasync, ctx)
        }
        fn getxattr(
            &self,
            inode: InodeId,
            name: &[u8],
            ctx: &RequestCtx,
        ) -> Result<Vec<u8>, Errno> {
            self.engine.getxattr(inode, name, ctx)
        }
        fn setxattr(
            &self,
            inode: InodeId,
            name: &[u8],
            value: &[u8],
            flags: u32,
            ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            self.engine.setxattr(inode, name, value, flags, ctx)
        }
        fn listxattr(&self, inode: InodeId, ctx: &RequestCtx) -> Result<Vec<u8>, Errno> {
            self.engine.listxattr(inode, ctx)
        }
        fn removexattr(&self, inode: InodeId, name: &[u8], ctx: &RequestCtx) -> Result<(), Errno> {
            self.engine.removexattr(inode, name, ctx)
        }
        fn getlk(
            &self,
            inode: InodeId,
            lock: &LockSpec,
            ctx: &RequestCtx,
        ) -> Result<Option<LockSpec>, Errno> {
            self.engine.getlk(inode, lock, ctx)
        }
        fn setlk(&self, inode: InodeId, lock: &LockSpec, ctx: &RequestCtx) -> Result<(), Errno> {
            self.engine.setlk(inode, lock, ctx)
        }
    }

    /// Returns a fresh `LocalFsFixture` as a trait object.
    pub fn factory_local_filesystem() -> Box<dyn VfsEngine> {
        Box::new(LocalFsFixture::new())
    }
}

// ── Contract test runners for local-filesystem ──────────────────────────────

#[cfg(feature = "fuse")]
mod local_fs_contract_tests {
    use super::*;
    use local_fs_fixture::factory_local_filesystem;

    #[allow(dead_code)]
    fn make() -> Box<dyn VfsEngine> {
        factory_local_filesystem()
    }

    #[allow(dead_code)]
    fn ctx() -> RequestCtx {
        RequestCtx {
            uid: 1000,
            gid: 1000,
            pid: 42,
            umask: 0o022,
            groups: vec![1000],
        }
    }

    // ── Core round-trip ────────────────────────────────────────────────

    #[test]
    fn local_fs_create_lookup_unlink() {
        let engine = make();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine.create(root, b"hello", 0o644, 0o2, &ctx()).unwrap();
        assert_eq!(attr.kind, NodeKind::File);

        let looked = engine.lookup(root, b"hello", &ctx()).unwrap();
        assert_eq!(looked.inode_id, attr.inode_id);

        engine.unlink(root, b"hello", &ctx()).unwrap();
        assert_eq!(engine.lookup(root, b"hello", &ctx()), Err(Errno::ENOENT));
    }

    #[test]
    fn local_fs_write_read_consistency() {
        let engine = make();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, fh) = engine
            .create(root, b"data.bin", 0o644, 0o2, &ctx())
            .unwrap();

        let n = engine.write(&fh, 0, b"hello local fs", &ctx()).unwrap();
        assert_eq!(n, 14);
        let data = engine.read(&fh, 0, 14, &ctx()).unwrap();
        assert_eq!(data, b"hello local fs");

        // Offset read
        let part = engine.read(&fh, 6, 5, &ctx()).unwrap();
        assert_eq!(part, b"local");

        engine.release(&fh).unwrap();

        // Re-open and verify persistence
        let reopened = engine.open(attr.inode_id, 0, &ctx()).unwrap();
        let persisted = engine.read(&reopened, 0, 14, &ctx()).unwrap();
        assert_eq!(persisted, b"hello local fs");
        engine.release(&reopened).unwrap();
    }

    #[test]
    fn local_fs_mkdir_readdir() {
        let engine = make();
        let root = engine.get_root_inode(&ctx()).unwrap();

        let dir = engine.mkdir(root, b"sub", 0o755, &ctx()).unwrap();
        assert_eq!(dir.kind, NodeKind::Dir);

        engine
            .create(dir.inode_id, b"a.txt", 0o644, 0, &ctx())
            .unwrap();
        engine
            .create(dir.inode_id, b"b.txt", 0o644, 0, &ctx())
            .unwrap();

        let dh = engine.opendir(dir.inode_id, &ctx()).unwrap();
        let (entries, more) = engine.readdir(&dh, 0, &ctx()).unwrap();
        engine.releasedir(&dh).unwrap();

        assert!(!more);
        assert_eq!(entries.len(), 2);
        let names: Vec<&[u8]> = entries.iter().map(|e| e.name.as_slice()).collect();
        assert!(names.contains(&b"a.txt".as_slice()));
        assert!(names.contains(&b"b.txt".as_slice()));
    }

    #[test]
    fn local_fs_rename_within_dir() {
        let engine = make();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine.create(root, b"old", 0o644, 0o2, &ctx()).unwrap();
        engine
            .rename(root, b"old", root, b"new", 0, &ctx())
            .unwrap();

        assert_eq!(engine.lookup(root, b"old", &ctx()), Err(Errno::ENOENT));
        let new_attr = engine.lookup(root, b"new", &ctx()).unwrap();
        assert_eq!(new_attr.inode_id, attr.inode_id);
    }

    #[test]
    fn local_fs_setattr_size() {
        let engine = make();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, fh) = engine
            .create(root, b"size.txt", 0o644, 0o2, &ctx())
            .unwrap();
        engine.write(&fh, 0, b"0123456789", &ctx()).unwrap();

        let mut sa = SetAttr::new();
        sa.valid = FATTR_SIZE;
        sa.size = 5;
        let updated = engine
            .setattr(attr.inode_id, &sa, Some(&fh), &ctx())
            .unwrap();
        assert_eq!(updated.posix.size, 5);

        let data = engine.read(&fh, 0, 10, &ctx()).unwrap();
        assert_eq!(data, b"01234");
    }

    #[test]
    fn local_fs_fallocate_zero_range() {
        let engine = make();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"zero.bin", 0o644, 0o2, &ctx())
            .unwrap();
        engine.write(&fh, 0, b"DATA_HERE", &ctx()).unwrap();

        engine
            .fallocate(&fh, FALLOC_FL_ZERO_RANGE, 0, 4, &ctx())
            .unwrap();
        let data = engine.read(&fh, 0, 9, &ctx()).unwrap();
        assert_eq!(&data[0..4], b"\0\0\0\0");
        assert_eq!(&data[4..9], b"_HERE");
    }

    #[test]
    fn local_fs_fallocate_punch_hole() {
        let engine = make();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"hole.bin", 0o644, 0o2, &ctx())
            .unwrap();
        engine.write(&fh, 0, b"ABCDEFGH", &ctx()).unwrap();

        engine
            .fallocate(
                &fh,
                FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                2,
                4,
                &ctx(),
            )
            .unwrap();
        let data = engine.read(&fh, 0, 8, &ctx()).unwrap();
        assert_eq!(&data[0..2], b"AB");
        assert_eq!(&data[2..6], b"\0\0\0\0");
        assert_eq!(&data[6..8], b"GH");
    }

    #[test]
    fn local_fs_rmdir_enotempty() {
        let engine = make();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let dir = engine.mkdir(root, b"parent", 0o755, &ctx()).unwrap();
        engine
            .create(dir.inode_id, b"child", 0o644, 0, &ctx())
            .unwrap();
        assert_eq!(
            engine.rmdir(root, b"parent", &ctx()).unwrap_err(),
            Errno::ENOTEMPTY
        );
    }

    #[test]
    fn local_fs_flush_fsync() {
        let engine = make();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"sync.txt", 0o644, 0o2, &ctx())
            .unwrap();
        engine.write(&fh, 0, b"data", &ctx()).unwrap();
        engine.flush(&fh, &ctx()).unwrap();
        engine.fsync(&fh, false, &ctx()).unwrap();
        engine.fsync(&fh, true, &ctx()).unwrap();
    }

    #[test]
    fn local_fs_xattr_roundtrip() {
        let engine = make();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine
            .create(root, b"xattr.txt", 0o644, 0o2, &ctx())
            .unwrap();

        engine
            .setxattr(attr.inode_id, b"user.key", b"val", 0, &ctx())
            .unwrap();
        let val = engine.getxattr(attr.inode_id, b"user.key", &ctx()).unwrap();
        assert_eq!(val, b"val");

        engine
            .removexattr(attr.inode_id, b"user.key", &ctx())
            .unwrap();
        assert_eq!(
            engine
                .getxattr(attr.inode_id, b"user.key", &ctx())
                .unwrap_err(),
            Errno::ENODATA
        );
    }

    #[test]
    fn local_fs_integration_create_write_fsync_reopen() {
        let engine = make();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, fh) = engine
            .create(root, b"lifecycle.txt", 0o644, 0o2, &ctx())
            .unwrap();
        engine.write(&fh, 0, b"persistent", &ctx()).unwrap();
        engine.fsync(&fh, false, &ctx()).unwrap();
        engine.release(&fh).unwrap();

        let reopened = engine.open(attr.inode_id, 0, &ctx()).unwrap();
        let data = engine.read(&reopened, 0, 10, &ctx()).unwrap();
        assert_eq!(data, b"persistent");
        engine.release(&reopened).unwrap();
    }

    #[test]
    fn local_fs_error_enotdir_on_file() {
        let engine = make();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine.create(root, b"file.txt", 0o644, 0, &ctx()).unwrap();
        assert_eq!(engine.opendir(attr.inode_id, &ctx()), Err(Errno::ENOTDIR));
    }

    #[test]
    fn local_fs_error_eisdir_on_dir() {
        let engine = make();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let dir = engine.mkdir(root, b"adir", 0o755, &ctx()).unwrap();
        assert_eq!(engine.open(dir.inode_id, 0, &ctx()), Err(Errno::EISDIR));
    }

    #[test]
    fn local_fs_error_eexist_on_dup_create() {
        let engine = make();
        let root = engine.get_root_inode(&ctx()).unwrap();
        engine.create(root, b"dup", 0o644, 0, &ctx()).unwrap();
        assert_eq!(
            engine.create(root, b"dup", 0o644, 0, &ctx()).unwrap_err(),
            Errno::EEXIST
        );
    }
}
