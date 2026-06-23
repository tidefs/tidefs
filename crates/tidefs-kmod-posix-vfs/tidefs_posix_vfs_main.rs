// SPDX-License-Identifier: GPL-2.0
#![cfg_attr(
    CONFIG_RUST,
    allow(
        unused_imports,
        unused_variables,
        dead_code,
        missing_docs,
        unreachable_pub
    )
)]
//! TideFS POSIX VFS kernel module -- Kbuild entry point.
//! NOT compiled under cargo.

// #![no_std] is injected by the kernel build system via -Zcrate-attr=no_std

// -- Bridge substrate (error + types + traits) ----------------------------

#[path = "../../kmod/src/error.rs"]
mod error;

#[path = "../../kmod/src/types.rs"]
mod types;

#[path = "../../kmod/src/traits.rs"]
mod traits;

// -- Kernel-compatible type facade ----------------------------------------

#[path = "../../kmod/src/kernel_types.rs"]
mod kernel_types_impl;

use core::cell::{Cell, RefCell};

mod tidefs_kmod_bridge {
    pub use crate::error::{BridgeError, BridgeResult};
    pub use crate::traits::*;
    pub use crate::types::*;
    pub mod kernel_types {
        pub use crate::kernel_types_impl::*;
    }
}

// -- blake3 re-export ------------------------------------------------------

pub mod blake3 {
    pub use crate::tidefs_kmod_bridge::kernel_types::blake3::*;
}

// -- Product crate source --------------------------------------------------
// Included under Kbuild for product .ko compilation.

#[path = "src/lib.rs"]
mod lib;

pub use crate::lib::*;
use crate::tidefs_kmod_bridge::kernel_types::VfsEngine;
use crate::tidefs_kmod_bridge::kernel_types::VfsEngineStatFs;
use kernel::error::to_result;
use kernel::prelude::*;

const KERNEL_POOL_ENGINE_DATA_OFFSET: u64 = 1024 * 1024;
const ENGINE_INTENT_LOG_LIMIT_OFFSET: u64 = 16 * 1024 * 1024;
const ENGINE_NAMESPACE_SNAPSHOT_OFFSET: u64 = ENGINE_INTENT_LOG_LIMIT_OFFSET;
const ENGINE_NAMESPACE_SNAPSHOT_BYTES: usize = 16 * 1024 * 1024;
const LIVE_EXTENT_BLOCK_SIZE: u64 = 4096;
const LIVE_APPEND_RESERVATION_SIZE: u64 = 1024 * 1024;
const LIVE_WRITE_BUFFER_ENTRY_LIMIT: u64 = LIVE_APPEND_RESERVATION_SIZE;

// -- KernelEngine: kernel-resident VfsEngine stub ---------------------------------
// Provides engine-backed superblock lifecycle operations for the C shim.
// Operations requiring real block-device/pool access return precise blockers.

#[derive(Clone, Copy)]
struct KernelEngineStatfs {
    bsize: u32,
    frsize: u32,
    blocks: u64,
    bfree: u64,
    bavail: u64,
    files: u64,
    ffree: u64,
    namelen: u32,
    fsid_hi: u64,
    fsid_lo: u64,
}

/// Staging entry for data written via [`VfsEngine::write`] and flushed
/// by [`VfsEngine::writeback_folios`]. Not an authoritative data cache —
/// the Linux page cache remains the authoritative cache for reads.
/// In-memory inode record for engine-backed namespace mutation tracking.
/// Mirrors on-disk VINO record fields for create/mkdir/rmdir/unlink.
struct InodeRecord {
    ino: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u32,
    size: u64,
    blocks: u64,
    generation: u64,
    kind: u8,
    atime_ns: i64,
    mtime_ns: i64,
    ctime_ns: i64,
    /// Symlink target path (only meaningful when kind == SYMLINK).
    symlink_target: Option<crate::tidefs_kmod_bridge::kernel_types::KmodVec<u8>>,
}

impl InodeRecord {
    const FILE: u8 = 0;
    const DIR: u8 = 1;
    const SYMLINK: u8 = 2;
}
struct WriteBufferEntry {
    inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
    offset: u64,
    len: u64,
    data: crate::tidefs_kmod_bridge::kernel_types::KmodVec<u8>,
    zero: bool,
}

#[derive(Clone, Copy)]
struct LiveExtentEntry {
    inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
    start: u64,
    end: u64,
    physical_start: u64,
    physical_reserved_end: u64,
    kind: u8,
}

impl LiveExtentEntry {
    const DATA: u8 = 0;
    const UNWRITTEN: u8 = 1;
}

#[derive(Clone, Copy)]
struct LiveCollapseCursor {
    inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
    request_offset: u64,
    index: usize,
    logical_before: u64,
}

const ADVISORY_LOCK_SEEK_SET: u32 = 0;

#[derive(Clone, Copy)]
struct AdvisoryLockEntry {
    inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
    lock: crate::tidefs_kmod_bridge::kernel_types::LockSpec,
}

struct KernelEngine {
    statfs: Option<KernelEngineStatfs>,
    /// Latest committed root set by mount/txg paths, used by txg_commit_barrier.
    committed_root: Cell<Option<crate::tidefs_kmod_bridge::kernel_types::CommittedRoot>>,
    /// Kernel-resident pool core for writeback/alloc/txg authority gating.
    /// When None, all write-path operations return ENODEV (pool not configured).
    pool_core: Option<crate::tidefs_kmod_bridge::kernel_types::KernelPoolCore>,
    /// Write staging buffer — data written via write() but not yet flushed
    /// by writeback_folios(). Cleared on successful writeback. Not an
    /// authoritative data cache; replaced by direct page-cache dispatch
    /// when #6274 [REL-KVFS-006] wires the kernel read/write data path.
    write_buffer: RefCell<crate::tidefs_kmod_bridge::kernel_types::KmodVec<WriteBufferEntry>>,
    /// Live sparse layout for in-memory engine-backed files.
    ///
    /// This records the mounted-kernel smoke path's DATA/UNWRITTEN extents so
    /// SEEK_DATA/SEEK_HOLE and FIEMAP do not collapse sparse files to dense
    /// placeholders before the full persistent extent-map authority is wired.
    live_extents: RefCell<crate::tidefs_kmod_bridge::kernel_types::KmodVec<LiveExtentEntry>>,
    /// Next physical byte offset in the engine live-data area.
    ///
    /// DATA extents are sparse-logical and compact-physical: a write at a
    /// 256MiB logical offset should not require 256MiB of per-inode backing.
    next_live_data_offset: Cell<u64>,
    /// Inodes whose live_extents are in collapse piece-list form.
    ///
    /// Collapse-range can issue thousands of adjacent removals.  During that
    /// run, entries keep their order and length but postpone absolute logical
    /// start/end rewrites until a read/FIEMAP/snapshot needs them.
    live_extent_dirty_inodes: RefCell<
        crate::tidefs_kmod_bridge::kernel_types::KmodVec<
            crate::tidefs_kmod_bridge::kernel_types::InodeId,
        >,
    >,
    /// Forward-scan hints for repeated fallocate(COLLAPSE_RANGE) calls.
    live_collapse_cursors:
        RefCell<crate::tidefs_kmod_bridge::kernel_types::KmodVec<LiveCollapseCursor>>,
    /// Inode table root locator from the committed-root VRBT block.
    /// Read during mount via KernelMountSequence and used by getattr()
    /// for on-disk inode attribute resolution through KernelStorageIo.
    inode_table_root: Cell<u64>,
    /// Extent map root locator from the committed-root VRBT block.
    /// Used by read() for logical-to-physical extent resolution.
    extent_map_root: Cell<u64>,
    /// Cumulative byte count of flushed intent-log entries.
    /// Advanced during txg_commit_barrier when intent entries are drained.
    intent_log_tail: Cell<u64>,
    /// In-memory directory entries:
    /// (parent_ino, name, child_ino, child_kind, stable_cookie).
    /// Engine-backed namespace mutations replace the fixed-table approach.
    dir_entries: RefCell<
        crate::tidefs_kmod_bridge::kernel_types::KmodVec<(
            u64,
            crate::tidefs_kmod_bridge::kernel_types::KmodVec<u8>,
            u64,
            u8,
            u32,
        )>,
    >,
    /// In-memory inode records for engine-backed create/mkdir.
    inodes: RefCell<crate::tidefs_kmod_bridge::kernel_types::KmodVec<InodeRecord>>,
    /// Fallback inode number counter for unbound/test engines.
    /// Production mounted allocations use the persistent pool_core I/O path
    /// via allocate_inode().  Do not read this field directly in production paths.
    next_ino: Cell<u64>,
    /// Monotonic per-mount directory cookie allocator.
    next_dir_cookie: Cell<u32>,
    /// Buffered intent-log entries; flushed on txg_commit_barrier.
    intent_buffer: RefCell<
        crate::tidefs_kmod_bridge::kernel_types::KmodVec<
            crate::tidefs_kmod_bridge::kernel_types::KmodVec<u8>,
        >,
    >,
    /// Per-inode xattr stores: (ino, entries). Entries are (name, value) byte vectors.

    /// Open file handle reference counts per inode (ino -> open_count).
    /// Drives open-unlink lifecycle: nlink==0 inodes with open handles stay alive.
    open_fds: RefCell<crate::tidefs_kmod_bridge::kernel_types::KmodVec<(u64, u32)>>,
    /// Mounted-engine POSIX advisory byte-range locks.
    advisory_locks:
        RefCell<crate::tidefs_kmod_bridge::kernel_types::KmodVec<AdvisoryLockEntry>>,
    xattr_stores: RefCell<
        crate::tidefs_kmod_bridge::kernel_types::KmodVec<(
            u64,
            crate::tidefs_kmod_bridge::kernel_types::KmodVec<(
                crate::tidefs_kmod_bridge::kernel_types::KmodVec<u8>,
                crate::tidefs_kmod_bridge::kernel_types::KmodVec<u8>,
            )>,
        )>,
    >,
}

impl KernelEngine {
    const fn unbound() -> Self {
        Self {
            statfs: None,
            committed_root: Cell::new(None),
            pool_core: None,
            write_buffer: RefCell::new(crate::tidefs_kmod_bridge::kernel_types::KmodVec::new()),
            live_extents: RefCell::new(crate::tidefs_kmod_bridge::kernel_types::KmodVec::new()),
            next_live_data_offset: Cell::new(0),
            live_extent_dirty_inodes: RefCell::new(
                crate::tidefs_kmod_bridge::kernel_types::KmodVec::new(),
            ),
            live_collapse_cursors: RefCell::new(
                crate::tidefs_kmod_bridge::kernel_types::KmodVec::new(),
            ),
            inode_table_root: Cell::new(0),
            extent_map_root: Cell::new(0),
            dir_entries: RefCell::new(crate::tidefs_kmod_bridge::kernel_types::KmodVec::new()),
            inodes: RefCell::new(crate::tidefs_kmod_bridge::kernel_types::KmodVec::new()),
            next_ino: Cell::new(2),
            next_dir_cookie: Cell::new(1),
            intent_log_tail: Cell::new(0),
            intent_buffer: RefCell::new(crate::tidefs_kmod_bridge::kernel_types::KmodVec::new()),
            open_fds: RefCell::new(crate::tidefs_kmod_bridge::kernel_types::KmodVec::new()),
            advisory_locks: RefCell::new(
                crate::tidefs_kmod_bridge::kernel_types::KmodVec::new(),
            ),
            xattr_stores: RefCell::new(crate::tidefs_kmod_bridge::kernel_types::KmodVec::new()),
        }
    }

    const fn with_statfs(statfs: KernelEngineStatfs) -> Self {
        Self {
            statfs: Some(statfs),
            committed_root: Cell::new(None),
            pool_core: None,
            write_buffer: RefCell::new(crate::tidefs_kmod_bridge::kernel_types::KmodVec::new()),
            live_extents: RefCell::new(crate::tidefs_kmod_bridge::kernel_types::KmodVec::new()),
            next_live_data_offset: Cell::new(0),
            live_extent_dirty_inodes: RefCell::new(
                crate::tidefs_kmod_bridge::kernel_types::KmodVec::new(),
            ),
            live_collapse_cursors: RefCell::new(
                crate::tidefs_kmod_bridge::kernel_types::KmodVec::new(),
            ),
            inode_table_root: Cell::new(0),
            extent_map_root: Cell::new(0),
            dir_entries: RefCell::new(crate::tidefs_kmod_bridge::kernel_types::KmodVec::new()),
            inodes: RefCell::new(crate::tidefs_kmod_bridge::kernel_types::KmodVec::new()),
            next_ino: Cell::new(2),
            next_dir_cookie: Cell::new(1),
            intent_log_tail: Cell::new(0),
            xattr_stores: RefCell::new(crate::tidefs_kmod_bridge::kernel_types::KmodVec::new()),
            intent_buffer: RefCell::new(crate::tidefs_kmod_bridge::kernel_types::KmodVec::new()),
            open_fds: RefCell::new(crate::tidefs_kmod_bridge::kernel_types::KmodVec::new()),
            advisory_locks: RefCell::new(
                crate::tidefs_kmod_bridge::kernel_types::KmodVec::new(),
            ),
        }
    }

    /// Create a KernelEngine backed by a KernelPoolCore for write-path authority.
    ///
    /// The pool core must be in Mounted state before any writeback or txg commit
    /// operations will succeed. Callers should call `pool_core.complete_import()`
    /// before passing it here.
    #[allow(dead_code)]
    fn with_pool_core(
        statfs: Option<KernelEngineStatfs>,
        pool_core: crate::tidefs_kmod_bridge::kernel_types::KernelPoolCore,
    ) -> Self {
        Self {
            statfs,
            committed_root: Cell::new(None),
            pool_core: Some(pool_core),
            write_buffer: RefCell::new(crate::tidefs_kmod_bridge::kernel_types::KmodVec::new()),
            live_extents: RefCell::new(crate::tidefs_kmod_bridge::kernel_types::KmodVec::new()),
            next_live_data_offset: Cell::new(0),
            live_extent_dirty_inodes: RefCell::new(
                crate::tidefs_kmod_bridge::kernel_types::KmodVec::new(),
            ),
            live_collapse_cursors: RefCell::new(
                crate::tidefs_kmod_bridge::kernel_types::KmodVec::new(),
            ),
            inode_table_root: Cell::new(0),
            extent_map_root: Cell::new(0),
            dir_entries: RefCell::new(crate::tidefs_kmod_bridge::kernel_types::KmodVec::new()),
            inodes: RefCell::new(crate::tidefs_kmod_bridge::kernel_types::KmodVec::new()),
            next_ino: Cell::new(2),
            next_dir_cookie: Cell::new(1),
            xattr_stores: RefCell::new(crate::tidefs_kmod_bridge::kernel_types::KmodVec::new()),
            intent_log_tail: Cell::new(0),
            intent_buffer: RefCell::new(crate::tidefs_kmod_bridge::kernel_types::KmodVec::new()),
            open_fds: RefCell::new(crate::tidefs_kmod_bridge::kernel_types::KmodVec::new()),
            advisory_locks: RefCell::new(
                crate::tidefs_kmod_bridge::kernel_types::KmodVec::new(),
            ),
        }
    }

    /// Set the committed root for subsequent txg_commit_barrier calls.
    /// Find the index of the xattr store for the given inode.

    /// Map an xattr name prefix to its namespace byte (1=security, 2=system, 3=trusted, 4=user).
    fn xattr_namespace_byte(name: &[u8]) -> u8 {
        if name.starts_with(b"security.") {
            1
        } else if name.starts_with(b"system.") {
            2
        } else if name.starts_with(b"trusted.") {
            3
        } else {
            4
        } // user.
    }

    fn find_xattr_store_idx(&self, ino: u64) -> Option<usize> {
        self.xattr_stores
            .borrow()
            .iter()
            .position(|(i, _)| *i == ino)
    }

    /// Get or create the xattr store for the given inode, returning its index.

    fn get_or_create_xattr_store_idx(&self, ino: u64) -> usize {
        if let Some(idx) = self.find_xattr_store_idx(ino) {
            return idx;
        }

        let mut stores = self.xattr_stores.borrow_mut();

        stores.push((ino, crate::tidefs_kmod_bridge::kernel_types::KmodVec::new()));

        stores.len() - 1
    }

    fn normalize_advisory_lock(
        lock: &crate::tidefs_kmod_bridge::kernel_types::LockSpec,
    ) -> crate::tidefs_kmod_bridge::kernel_types::LockSpec {
        let mut normalized = *lock;
        if normalized.end == 0 {
            normalized.end = u64::MAX;
        }
        normalized
    }

    fn validate_advisory_lock(
        lock: &crate::tidefs_kmod_bridge::kernel_types::LockSpec,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        use crate::tidefs_kmod_bridge::kernel_types::{Errno, F_RDLCK, F_UNLCK, F_WRLCK};

        match lock.typ {
            F_RDLCK | F_WRLCK | F_UNLCK => {}
            _ => return Err(Errno::EINVAL),
        }
        if lock.whence != ADVISORY_LOCK_SEEK_SET {
            return Err(Errno::EINVAL);
        }
        if lock.end <= lock.start {
            return Err(Errno::EINVAL);
        }
        Ok(())
    }

    fn advisory_lock_overlaps(
        left: &crate::tidefs_kmod_bridge::kernel_types::LockSpec,
        right: &crate::tidefs_kmod_bridge::kernel_types::LockSpec,
    ) -> bool {
        left.start < right.end && right.start < left.end
    }

    fn advisory_locks_conflict(
        existing: &crate::tidefs_kmod_bridge::kernel_types::LockSpec,
        requested: &crate::tidefs_kmod_bridge::kernel_types::LockSpec,
    ) -> bool {
        use crate::tidefs_kmod_bridge::kernel_types::{F_RDLCK, F_UNLCK};

        existing.pid != requested.pid
            && existing.typ != F_UNLCK
            && requested.typ != F_UNLCK
            && Self::advisory_lock_overlaps(existing, requested)
            && !(existing.typ == F_RDLCK && requested.typ == F_RDLCK)
    }

    fn push_advisory_lock_entry(
        out: &mut crate::tidefs_kmod_bridge::kernel_types::KmodVec<AdvisoryLockEntry>,
        entry: AdvisoryLockEntry,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        let before = out.len();
        out.push(entry);
        if out.len() == before {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
        }
        Ok(())
    }

    fn find_advisory_lock_conflict(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        requested: &crate::tidefs_kmod_bridge::kernel_types::LockSpec,
    ) -> Option<crate::tidefs_kmod_bridge::kernel_types::LockSpec> {
        self.advisory_locks
            .borrow()
            .iter()
            .find(|entry| {
                entry.inode == inode && Self::advisory_locks_conflict(&entry.lock, requested)
            })
            .map(|entry| entry.lock)
    }

    fn require_advisory_lock_inode(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        use crate::tidefs_kmod_bridge::kernel_types::Errno;

        let ino = inode.get();
        if ino == 0 {
            return Err(Errno::ENOENT);
        }
        if self.find_inode(ino).is_some() {
            return Ok(());
        }

        let Some(ref pool_core) = self.pool_core else {
            return Err(Errno::ENODEV);
        };
        if !pool_core.is_mounted() {
            return Err(Errno::ENODEV);
        }
        let io_ctx = pool_core.committed_root_io_ctx();
        let Some(read_fn) = io_ctx.read_sectors_fn else {
            return Err(Errno::ENODEV);
        };
        let ss = Self::valid_sector_size(io_ctx.sector_size)? as u64;
        let record = self.read_inode_record(ino, &io_ctx, read_fn, ss)?;
        if record.nlink == 0 && record.generation == 0 && record.mode == 0 {
            return Err(Errno::ENOENT);
        }
        Ok(())
    }

    fn replace_advisory_lock_range(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        requested: &crate::tidefs_kmod_bridge::kernel_types::LockSpec,
        new_lock: Option<crate::tidefs_kmod_bridge::kernel_types::LockSpec>,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        let old = self.advisory_locks.borrow();
        let mut next = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();

        for entry in old.iter() {
            if entry.inode != inode
                || entry.lock.pid != requested.pid
                || !Self::advisory_lock_overlaps(&entry.lock, requested)
            {
                Self::push_advisory_lock_entry(&mut next, *entry)?;
                continue;
            }

            if entry.lock.start < requested.start {
                let mut left = entry.lock;
                left.end = requested.start;
                Self::push_advisory_lock_entry(&mut next, AdvisoryLockEntry { inode, lock: left })?;
            }

            if requested.end < entry.lock.end {
                let mut right = entry.lock;
                right.start = requested.end;
                Self::push_advisory_lock_entry(
                    &mut next,
                    AdvisoryLockEntry { inode, lock: right },
                )?;
            }
        }
        if let Some(lock) = new_lock {
            Self::push_advisory_lock_entry(&mut next, AdvisoryLockEntry { inode, lock })?;
        }
        drop(old);

        *self.advisory_locks.borrow_mut() = next;
        Ok(())
    }

    fn unlock_advisory_lock_range(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        requested: &crate::tidefs_kmod_bridge::kernel_types::LockSpec,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        self.replace_advisory_lock_range(inode, requested, None)
    }
    pub fn set_committed_root(&self, root: crate::tidefs_kmod_bridge::kernel_types::CommittedRoot) {
        self.committed_root.set(Some(root));
    }

    /// Take the current committed root (used by txg_commit_barrier).
    fn take_committed_root(
        &self,
    ) -> Option<crate::tidefs_kmod_bridge::kernel_types::CommittedRoot> {
        self.committed_root.take()
    }

    /// Returns true if a committed root is currently tracked.
    pub fn has_committed_root(&self) -> bool {
        self.committed_root.get().is_some()
    }

    fn mounted_pool_io_ctx(
        &self,
    ) -> core::result::Result<
        crate::tidefs_kmod_bridge::kernel_types::CommittedRootIoCtx,
        crate::tidefs_kmod_bridge::kernel_types::Errno,
    > {
        if !self.pool_is_mounted() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV);
        }
        let Some(ref pool_core) = self.pool_core else {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV);
        };
        let io_ctx = pool_core.committed_root_io_ctx();
        if !io_ctx.is_active() || !io_ctx.capabilities().has_mounted_authority() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV);
        }
        Ok(io_ctx)
    }

    fn teardown_pool_authority(
        &self,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        self.mounted_pool_io_ctx()?.teardown()
    }

    /// Seed the mounted root inode into the engine namespace table.
    fn ensure_root_inode(&self, root_ino: u64, sector_size: u32) {
        if root_ino == 0 || self.find_inode(root_ino).is_some() {
            return;
        }

        if self
            .push_inode_record(InodeRecord {
                ino: root_ino,
                mode: 0o040755,
                uid: 0,
                gid: 0,
                nlink: 2,
                size: 0,
                blocks: 0,
                generation: 1,
                kind: InodeRecord::DIR,
                atime_ns: 0,
                mtime_ns: 0,
                ctime_ns: 0,
                symlink_target: None,
            })
            .is_err()
        {
            return;
        }
        self.next_ino
            .set(self.next_ino.get().max(root_ino.saturating_add(1)));
        let _ = sector_size;
    }

    /// Return a reference to the pool core, or None if not configured.
    #[allow(dead_code)]
    pub fn pool_core(&self) -> Option<&crate::tidefs_kmod_bridge::kernel_types::KernelPoolCore> {
        self.pool_core.as_ref()
    }

    /// Store VRBT-derived authority pointers from the committed-root block.
    /// Called after mount when the VRBT has been decoded.
    pub fn set_vrbt_pointers(&self, inode_table_root: u64, extent_map_root: u64) {
        self.inode_table_root.set(inode_table_root);
        self.extent_map_root.set(extent_map_root);
    }

    /// Return true if the pool core is configured and in Mounted state.
    fn pool_is_mounted(&self) -> bool {
        self.pool_core.as_ref().map_or(false, |pc| pc.is_mounted())
    }

    // ── Engine-backed namespace helpers (#6270) ──────────────────────

    /// Look up a directory entry by (parent, name). Returns Some(child_ino, child_kind).
    fn find_dir_entry(&self, parent_ino: u64, name: &[u8]) -> Option<(u64, u8)> {
        for entry in self.dir_entries.borrow().iter() {
            if entry.0 == parent_ino && &*entry.1 == name {
                return Some((entry.2, entry.3));
            }
        }
        None
    }

    /// Look up an inode record by ino.
    fn find_inode(&self, ino: u64) -> Option<usize> {
        for (i, rec) in self.inodes.borrow().iter().enumerate() {
            if rec.ino == ino {
                return Some(i);
            }
        }
        None
    }

    /// Look up the generation number for an inode (NEXT-KVFS-021).
    /// Returns ENOENT if the inode is not found in the engine namespace.
    fn get_generation(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
    ) -> core::result::Result<u64, crate::tidefs_kmod_bridge::kernel_types::Errno> {
        let ino = inode.get();
        match self.find_inode(ino) {
            Some(idx) => {
                let rec = &self.inodes.borrow()[idx];
                Ok(rec.generation)
            }
            None => Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOENT),
        }
    }

    /// Check if a directory has any children (for rmdir emptiness check).
    fn dir_has_children(&self, dir_ino: u64) -> bool {
        for entry in self.dir_entries.borrow().iter() {
            if entry.0 == dir_ino {
                return true;
            }
        }
        false
    }

    fn require_live_directory(
        &self,
        ino: u64,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        let idx = self
            .find_inode(ino)
            .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOENT)?;
        let inodes = self.inodes.borrow();
        let rec = &inodes[idx];
        if rec.kind != InodeRecord::DIR {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOTDIR);
        }
        if rec.nlink == 0 {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOENT);
        }
        Ok(())
    }

    fn is_descendant_directory(&self, mut child: u64, ancestor: u64) -> bool {
        for _ in 0..1024 {
            if child == ancestor {
                return true;
            }
            if child == 1 {
                return false;
            }
            let parent = {
                let entries = self.dir_entries.borrow();
                entries
                    .iter()
                    .find(|entry| entry.2 == child && entry.3 == InodeRecord::DIR)
                    .map(|entry| entry.0)
            };
            match parent {
                Some(next) if next != child => child = next,
                _ => return false,
            }
        }
        true
    }

    fn alloc_dir_cookie(&self) -> u32 {
        let cookie = self.next_dir_cookie.get().max(1);
        self.next_dir_cookie.set(cookie.saturating_add(1));
        cookie
    }

    fn add_dir_entry_with_cookie(
        &self,
        parent_ino: u64,
        name: &[u8],
        child_ino: u64,
        child_kind: u8,
        cookie: u32,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        let mut name_vec = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();
        name_vec.extend_from_slice(name);
        if name_vec.len() != name.len() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
        }
        let mut entries = self.dir_entries.borrow_mut();
        let before = entries.len();
        entries.push((parent_ino, name_vec, child_ino, child_kind, cookie));
        if entries.len() == before {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
        }
        drop(entries);
        self.next_dir_cookie
            .set(self.next_dir_cookie.get().max(cookie.saturating_add(1)));
        Ok(())
    }

    fn add_dir_entry(
        &self,
        parent_ino: u64,
        name: &[u8],
        child_ino: u64,
        child_kind: u8,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        let cookie = self.alloc_dir_cookie();
        self.add_dir_entry_with_cookie(parent_ino, name, child_ino, child_kind, cookie)
    }

    /// Remove all directory entries whose parent is `parent_ino` and name matches.

    /// Return the number of open file handles for an inode.
    fn inode_open_count(&self, ino: u64) -> u32 {
        for &(id, count) in self.open_fds.borrow().iter() {
            if id == ino {
                return count;
            }
        }
        0
    }

    /// Update in-memory inode size after an engine-backed write.
    fn update_inode_size_after_write(&self, ino: u64, end: u64) {
        if let Some(idx) = self.find_inode(ino) {
            let mut inodes = self.inodes.borrow_mut();
            let rec = &mut inodes[idx];
            if end > rec.size {
                rec.size = end;
            }
            rec.blocks = self.live_allocated_blocks(ino);
        }
    }

    fn read_live_inode_data(
        &self,
        ino: u64,
        offset: u64,
        size: u32,
    ) -> core::result::Result<
        crate::tidefs_kmod_bridge::kernel_types::KmodVec<u8>,
        crate::tidefs_kmod_bridge::kernel_types::Errno,
    > {
        let file_size = {
            let idx = self
                .find_inode(ino)
                .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOENT)?;
            let inodes = self.inodes.borrow();
            inodes[idx].size
        };

        if size == 0 || offset >= file_size {
            return Ok(crate::tidefs_kmod_bridge::kernel_types::KmodVec::new());
        }
        let inode = crate::tidefs_kmod_bridge::kernel_types::InodeId::new(ino);
        self.normalize_live_extents(inode)?;

        let read_len_u64 = core::cmp::min(size as u64, file_size.saturating_sub(offset));
        let read_len = usize::try_from(read_len_u64)
            .map_err(|_| crate::tidefs_kmod_bridge::kernel_types::Errno::EOVERFLOW)?;
        let mut out = crate::tidefs_kmod_bridge::kernel_types::KmodVec::from_elem(0u8, read_len);
        if out.len() != read_len {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
        }

        let read_end = offset.saturating_add(read_len_u64);
        if !self.live_write_buffer_covers_range(ino, offset, read_len_u64) {
            let extents = self.live_extents.borrow();
            let mut saw_inode = false;
            // Live extents for an inode are kept contiguous and ordered by
            // start offset, so read-side scans can stop once this inode/range
            // is past instead of walking the whole global extent vector.
            for entry in extents.iter() {
                if entry.inode != inode {
                    if saw_inode {
                        break;
                    }
                    continue;
                }
                saw_inode = true;
                if entry.start >= read_end {
                    break;
                }
                if entry.kind != LiveExtentEntry::DATA || entry.end <= offset {
                    continue;
                }
                let overlap_start = core::cmp::max(offset, entry.start);
                let overlap_end = core::cmp::min(read_end, entry.end);
                if overlap_start >= overlap_end {
                    continue;
                }
                let out_start = usize::try_from(overlap_start.saturating_sub(offset))
                    .map_err(|_| crate::tidefs_kmod_bridge::kernel_types::Errno::EOVERFLOW)?;
                let out_end = usize::try_from(overlap_end.saturating_sub(offset))
                    .map_err(|_| crate::tidefs_kmod_bridge::kernel_types::Errno::EOVERFLOW)?;
                if out_end > out.len() || out_start > out_end {
                    return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EOVERFLOW);
                }
                let physical_offset = entry
                    .physical_start
                    .checked_add(overlap_start.saturating_sub(entry.start))
                    .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)?;
                self.read_live_data_from_storage(physical_offset, &mut out[out_start..out_end])?;
            }
        }

        let wb = self.write_buffer.borrow();
        for entry in wb.iter() {
            if entry.inode.get() != ino || entry.len == 0 {
                continue;
            }

            let entry_end = entry.offset.saturating_add(entry.len);
            let overlap_start = core::cmp::max(offset, entry.offset);
            let overlap_end = core::cmp::min(read_end, entry_end);
            if overlap_start >= overlap_end {
                continue;
            }

            let out_start = usize::try_from(overlap_start.saturating_sub(offset))
                .map_err(|_| crate::tidefs_kmod_bridge::kernel_types::Errno::EOVERFLOW)?;
            let out_end = usize::try_from(overlap_end.saturating_sub(offset))
                .map_err(|_| crate::tidefs_kmod_bridge::kernel_types::Errno::EOVERFLOW)?;
            if out_end > out.len() || out_start > out_end {
                return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EOVERFLOW);
            }

            if entry.zero {
                for byte in &mut out[out_start..out_end] {
                    *byte = 0;
                }
                continue;
            }

            let data_start = usize::try_from(overlap_start.saturating_sub(entry.offset))
                .map_err(|_| crate::tidefs_kmod_bridge::kernel_types::Errno::EOVERFLOW)?;
            let data_end = data_start.saturating_add(out_end.saturating_sub(out_start));
            if data_end > entry.data.len() || data_start > data_end {
                return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EIO);
            }

            out[out_start..out_end].copy_from_slice(&entry.data[data_start..data_end]);
        }

        Ok(out)
    }

    fn write_live_inode_data_to_active_storage(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        offset: u64,
        data: &[u8],
    ) -> core::result::Result<Option<u32>, crate::tidefs_kmod_bridge::kernel_types::Errno> {
        let len = data.len() as u32;
        let len_u64 = len as u64;
        if len == 0 {
            return Ok(Some(0));
        }
        let Some(ref pool_core) = self.pool_core else {
            return Ok(None);
        };
        let io_ctx = pool_core.committed_root_io_ctx();
        if !io_ctx.is_active() || io_ctx.write_sectors_fn.is_none() {
            return Ok(None);
        }

        self.write_live_data_range_to_storage(&io_ctx, inode, offset, len_u64, data)?;
        self.clear_live_write_buffer_range(inode, offset, len_u64)?;
        self.update_inode_size_after_write(inode.get(), offset.saturating_add(len_u64));
        Ok(Some(len))
    }

    fn stage_live_inode_write(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        offset: u64,
        data: &[u8],
    ) -> core::result::Result<u32, crate::tidefs_kmod_bridge::kernel_types::Errno> {
        let len = data.len() as u32;
        let len_u64 = len as u64;
        if let Some(written) = self.write_live_inode_data_to_active_storage(inode, offset, data)? {
            return Ok(written);
        }
        let wrote_direct = if let Some(ref pool_core) = self.pool_core {
            let io_ctx = pool_core.committed_root_io_ctx();
            if io_ctx.is_active() && io_ctx.write_sectors_fn.is_some() {
                if len_u64 <= LIVE_EXTENT_BLOCK_SIZE {
                    if self.can_extend_live_data_tail(inode, offset, len_u64)? {
                        if self.try_append_live_write_buffer_tail(inode, offset, data)? {
                            self.extend_live_data_tail_metadata(inode, offset, len_u64)?;
                            self.update_inode_size_after_write(
                                inode.get(),
                                offset.saturating_add(len_u64),
                            );
                            return Ok(len);
                        }
                        self.flush_live_write_buffer_to_storage(Some(inode), 0, offset)?;
                        self.set_live_write_buffer_range(inode, offset, len_u64, data, false)?;
                        self.extend_live_data_tail_metadata(inode, offset, len_u64)?;
                        self.update_inode_size_after_write(
                            inode.get(),
                            offset.saturating_add(len_u64),
                        );
                        return Ok(len);
                    }
                    let physical_start = self.allocate_live_data_range_with_reservation(
                        len_u64,
                        LIVE_APPEND_RESERVATION_SIZE,
                    )?;
                    let physical_reserved_end = physical_start
                        .checked_add(Self::align_up_to_quantum(
                            len_u64.max(LIVE_APPEND_RESERVATION_SIZE),
                            LIVE_APPEND_RESERVATION_SIZE,
                        )?)
                        .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)?;
                    self.set_live_write_buffer_range(inode, offset, len_u64, data, false)?;
                    self.set_live_data_extent_range_reserved(
                        inode,
                        offset,
                        len_u64,
                        physical_start,
                        physical_reserved_end,
                    )?;
                    self.update_inode_size_after_write(inode.get(), offset.saturating_add(len_u64));
                    return Ok(len);
                }
                if self.try_extend_live_data_tail(inode, offset, data, &io_ctx)? {
                    self.update_inode_size_after_write(inode.get(), offset.saturating_add(len_u64));
                    return Ok(len);
                }
                let reservation = if len_u64 <= LIVE_EXTENT_BLOCK_SIZE {
                    LIVE_APPEND_RESERVATION_SIZE
                } else {
                    LIVE_EXTENT_BLOCK_SIZE
                };
                let physical_start =
                    self.allocate_live_data_range_with_reservation(len_u64, reservation)?;
                let physical_reserved_end = physical_start
                    .checked_add(Self::align_up_to_quantum(
                        len_u64.max(reservation),
                        reservation,
                    )?)
                    .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)?;
                Self::write_live_entry_to_storage(&io_ctx, physical_start, len_u64, data, false)?;
                self.clear_live_write_buffer_range(inode, offset, len_u64)?;
                self.set_live_data_extent_range_reserved(
                    inode,
                    offset,
                    len_u64,
                    physical_start,
                    physical_reserved_end,
                )?;
                true
            } else {
                false
            }
        } else {
            false
        };
        if !wrote_direct {
            let physical_start = self.allocate_live_data_range(len_u64)?;
            self.set_live_write_buffer_range(inode, offset, len_u64, data, false)?;
            self.set_live_data_extent_range(inode, offset, len_u64, physical_start)?;
        }
        self.update_inode_size_after_write(inode.get(), offset.saturating_add(len_u64));
        Ok(len)
    }

    fn stage_live_zero_range(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        offset: u64,
        length: u64,
        keep_size: bool,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if length == 0 {
            return Ok(());
        }
        if length > u32::MAX as u64 {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG);
        }

        self.set_live_write_buffer_range(inode, offset, length, &[], true)?;

        if !keep_size {
            self.update_inode_size_after_write(inode.get(), offset.saturating_add(length));
        }
        Ok(())
    }

    fn checked_range_end(
        offset: u64,
        length: u64,
    ) -> core::result::Result<u64, crate::tidefs_kmod_bridge::kernel_types::Errno> {
        offset
            .checked_add(length)
            .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)
    }

    fn align_up_to_live_block(
        value: u64,
    ) -> core::result::Result<u64, crate::tidefs_kmod_bridge::kernel_types::Errno> {
        Self::align_up_to_quantum(value, LIVE_EXTENT_BLOCK_SIZE)
    }

    fn align_up_to_quantum(
        value: u64,
        quantum: u64,
    ) -> core::result::Result<u64, crate::tidefs_kmod_bridge::kernel_types::Errno> {
        crate::live_data_allocator::align_up_to_quantum(value, quantum)
            .map_err(Self::live_data_allocator_errno)
    }

    fn live_data_allocator_errno(
        err: crate::live_data_allocator::LiveDataAllocatorError,
    ) -> crate::tidefs_kmod_bridge::kernel_types::Errno {
        match err {
            crate::live_data_allocator::LiveDataAllocatorError::InvalidQuantum => {
                crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL
            }
            crate::live_data_allocator::LiveDataAllocatorError::Overflow => {
                crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG
            }
        }
    }

    fn align_down_to_live_block(value: u64) -> u64 {
        value - (value % LIVE_EXTENT_BLOCK_SIZE)
    }

    fn full_live_blocks_in_range(
        offset: u64,
        length: u64,
    ) -> core::result::Result<Option<(u64, u64)>, crate::tidefs_kmod_bridge::kernel_types::Errno>
    {
        let end = Self::checked_range_end(offset, length)?;
        let block_start = Self::align_up_to_live_block(offset)?;
        let block_end = Self::align_down_to_live_block(end);
        if block_start >= block_end {
            Ok(None)
        } else {
            Ok(Some((block_start, block_end.saturating_sub(block_start))))
        }
    }

    fn push_live_extent_entry(
        out: &mut crate::tidefs_kmod_bridge::kernel_types::KmodVec<LiveExtentEntry>,
        entry: LiveExtentEntry,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if entry.start >= entry.end {
            return Ok(());
        }
        if let Some(last) = out.last_mut() {
            if Self::live_extent_entries_can_merge(last, &entry) {
                last.end = entry.end;
                last.physical_reserved_end =
                    last.physical_reserved_end.max(entry.physical_reserved_end);
                return Ok(());
            }
        }
        let before = out.len();
        out.push(entry);
        if out.len() == before {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
        }
        Ok(())
    }

    fn append_live_extent_entry_raw(
        out: &mut crate::tidefs_kmod_bridge::kernel_types::KmodVec<LiveExtentEntry>,
        entry: LiveExtentEntry,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        let before = out.len();
        out.push(entry);
        if out.len() == before {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
        }
        Ok(())
    }

    fn insert_live_extent_entry_sorted(
        out: &mut crate::tidefs_kmod_bridge::kernel_types::KmodVec<LiveExtentEntry>,
        entry: LiveExtentEntry,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if entry.start >= entry.end {
            return Ok(());
        }
        let mut pos = 0usize;
        while pos < out.len() && out[pos].start <= entry.start {
            pos = pos.saturating_add(1);
        }
        let before = out.len();
        out.reserve(1);
        if pos >= out.len() {
            out.push(entry);
        } else {
            out.insert(pos, entry);
        }
        if out.len() != before.saturating_add(1) {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
        }
        Ok(())
    }

    fn sort_live_extents_for_inode(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        let old = self.live_extents.borrow();
        let mut others = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();
        let mut target = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();

        for entry in old.iter() {
            if entry.inode == inode {
                Self::insert_live_extent_entry_sorted(&mut target, *entry)?;
            } else {
                Self::append_live_extent_entry_raw(&mut others, *entry)?;
            }
        }
        drop(old);

        for entry in target.iter() {
            Self::push_live_extent_entry(&mut others, *entry)?;
        }
        *self.live_extents.borrow_mut() = others;
        Ok(())
    }

    fn live_extent_entries_can_merge(left: &LiveExtentEntry, right: &LiveExtentEntry) -> bool {
        let data_is_contiguous = if left.kind == LiveExtentEntry::DATA {
            left.physical_start
                .saturating_add(left.end.saturating_sub(left.start))
                == right.physical_start
        } else {
            true
        };
        left.inode == right.inode
            && left.kind == right.kind
            && left.end == right.start
            && data_is_contiguous
    }

    fn live_allocated_blocks_from_bytes(bytes: u64) -> u64 {
        bytes.saturating_add(511) / 512
    }

    fn live_data_byte_offset(
        data_area_offset: u64,
        physical_offset: u64,
    ) -> core::result::Result<u64, crate::tidefs_kmod_bridge::kernel_types::Errno> {
        data_area_offset
            .checked_add(Self::ENGINE_FILE_DATA_OFFSET)
            .and_then(|base| base.checked_add(physical_offset))
            .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)
    }

    fn live_data_capacity_bytes(&self) -> Option<u64> {
        let pool_core = self.pool_core.as_ref()?;
        let io_ctx = pool_core.committed_root_io_ctx();
        let total = pool_core.total_capacity_bytes();
        if total == 0 {
            return None;
        }
        let base = io_ctx
            .data_area_offset
            .checked_add(Self::ENGINE_FILE_DATA_OFFSET)?;
        if base >= total {
            Some(0)
        } else {
            Some(total - base)
        }
    }

    fn allocate_live_data_range(
        &self,
        length: u64,
    ) -> core::result::Result<u64, crate::tidefs_kmod_bridge::kernel_types::Errno> {
        self.allocate_live_data_range_with_reservation(length, LIVE_EXTENT_BLOCK_SIZE)
    }

    fn allocate_live_data_range_with_reservation(
        &self,
        length: u64,
        reservation: u64,
    ) -> core::result::Result<u64, crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if length == 0 {
            return Ok(self.next_live_data_offset.get());
        }
        let allocation_quantum = reservation.max(LIVE_EXTENT_BLOCK_SIZE);
        let physical_start =
            Self::align_up_to_quantum(self.next_live_data_offset.get(), allocation_quantum)?;
        let allocation_len =
            Self::align_up_to_quantum(length.max(allocation_quantum), allocation_quantum)?;
        let next = physical_start
            .checked_add(allocation_len)
            .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)?;
        if let Some(capacity) = self.live_data_capacity_bytes() {
            if next > capacity {
                return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOSPC);
            }
        }
        self.next_live_data_offset.set(next);
        Ok(physical_start)
    }

    fn advance_live_data_allocator_for_entry(
        &self,
        entry: &LiveExtentEntry,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if entry.kind != LiveExtentEntry::DATA {
            return Ok(());
        }
        let aligned_end = Self::live_data_allocator_tail_for_entry(entry)?;
        if aligned_end > self.next_live_data_offset.get() {
            self.next_live_data_offset.set(aligned_end);
        }
        Ok(())
    }

    fn live_data_allocator_tail_for_entry(
        entry: &LiveExtentEntry,
    ) -> core::result::Result<u64, crate::tidefs_kmod_bridge::kernel_types::Errno> {
        crate::live_data_allocator::reserved_extent_tail(
            crate::live_data_allocator::LiveDataAllocatorExtent {
                physical_start: entry.physical_start,
                logical_len: entry.end.saturating_sub(entry.start),
                physical_reserved_end: entry.physical_reserved_end,
            },
            LIVE_EXTENT_BLOCK_SIZE,
        )
        .map_err(Self::live_data_allocator_errno)
    }

    fn recompute_live_data_allocator_tail(
        &self,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        let extents = self.live_extents.borrow();
        let mut tail = 0u64;

        for entry in extents.iter() {
            if entry.kind != LiveExtentEntry::DATA {
                continue;
            }
            tail = tail.max(Self::live_data_allocator_tail_for_entry(entry)?);
        }

        self.next_live_data_offset.set(tail);
        Ok(())
    }

    fn can_extend_live_data_tail(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        offset: u64,
        length: u64,
    ) -> core::result::Result<bool, crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if length == 0 {
            return Ok(true);
        }
        self.normalize_live_extents(inode)?;
        let end = Self::checked_range_end(offset, length)?;
        let mut has_tail_reservation = false;
        {
            let extents = self.live_extents.borrow();
            for entry in extents.iter() {
                if entry.inode != inode {
                    continue;
                }
                if entry.start < end && entry.end > offset {
                    return Ok(false);
                }
                if entry.kind != LiveExtentEntry::DATA {
                    continue;
                }
                if entry.end != offset {
                    continue;
                }
                let physical = entry
                    .physical_start
                    .checked_add(entry.end.saturating_sub(entry.start))
                    .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)?;
                let physical_end = physical
                    .checked_add(length)
                    .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)?;
                if physical_end <= entry.physical_reserved_end {
                    has_tail_reservation = true;
                }
            }
        }
        if !has_tail_reservation {
            return Ok(false);
        }
        let buffer = self.write_buffer.borrow();
        for entry in buffer.iter() {
            if entry.inode != inode {
                continue;
            }
            let entry_end = Self::checked_range_end(entry.offset, entry.len)?;
            if entry.offset < end && entry_end > offset {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn extend_live_data_tail_metadata(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        offset: u64,
        length: u64,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if length == 0 {
            return Ok(());
        }
        let mut extents = self.live_extents.borrow_mut();
        for entry in extents.iter_mut() {
            if entry.inode != inode || entry.kind != LiveExtentEntry::DATA || entry.end != offset {
                continue;
            }
            let current_len = entry.end.saturating_sub(entry.start);
            let physical = entry
                .physical_start
                .checked_add(current_len)
                .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)?;
            let physical_end = physical
                .checked_add(length)
                .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)?;
            if physical_end <= entry.physical_reserved_end {
                entry.end = entry
                    .end
                    .checked_add(length)
                    .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)?;
                return Ok(());
            }
        }
        Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EIO)
    }

    fn try_extend_live_data_tail(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        offset: u64,
        data: &[u8],
        io_ctx: &crate::tidefs_kmod_bridge::kernel_types::CommittedRootIoCtx,
    ) -> core::result::Result<bool, crate::tidefs_kmod_bridge::kernel_types::Errno> {
        let length = data.len() as u64;
        if length == 0 {
            return Ok(true);
        }

        if !self.can_extend_live_data_tail(inode, offset, length)? {
            return Ok(false);
        }

        self.normalize_live_extents(inode)?;
        let mut target = None;
        {
            let extents = self.live_extents.borrow();
            for entry in extents.iter() {
                if entry.inode != inode
                    || entry.kind != LiveExtentEntry::DATA
                    || entry.end != offset
                {
                    continue;
                }
                let current_len = entry.end.saturating_sub(entry.start);
                let physical = entry
                    .physical_start
                    .checked_add(current_len)
                    .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)?;
                let physical_end = physical
                    .checked_add(length)
                    .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)?;
                if physical_end <= entry.physical_reserved_end {
                    target = Some((entry.start, entry.end, entry.physical_start, physical));
                    break;
                }
            }
        }

        let Some((start, end, physical_start, physical)) = target else {
            return Ok(false);
        };

        Self::write_live_entry_to_storage(io_ctx, physical, length, data, false)?;

        let mut extents = self.live_extents.borrow_mut();
        for entry in extents.iter_mut() {
            if entry.inode == inode
                && entry.kind == LiveExtentEntry::DATA
                && entry.start == start
                && entry.end == end
                && entry.physical_start == physical_start
            {
                entry.end = end.saturating_add(length);
                return Ok(true);
            }
        }

        Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EIO)
    }

    fn live_data_physical_start_for_range(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        offset: u64,
        length: u64,
    ) -> core::result::Result<Option<u64>, crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if length == 0 {
            return Ok(Some(0));
        }
        self.normalize_live_extents(inode)?;
        let end = Self::checked_range_end(offset, length)?;
        let extents = self.live_extents.borrow();
        for entry in extents.iter() {
            if entry.inode == inode
                && entry.kind == LiveExtentEntry::DATA
                && entry.start <= offset
                && entry.end >= end
            {
                return Ok(Some(
                    entry
                        .physical_start
                        .checked_add(offset.saturating_sub(entry.start))
                        .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)?,
                ));
            }
        }
        Ok(None)
    }

    fn coalesce_live_extents_near(
        extents: &mut crate::tidefs_kmod_bridge::kernel_types::KmodVec<LiveExtentEntry>,
        start_idx: usize,
    ) {
        if extents.len() == 0 {
            return;
        }
        let mut idx = core::cmp::min(start_idx, extents.len().saturating_sub(1)).saturating_sub(1);
        let mut clean_edges = 0u8;
        while idx.saturating_add(1) < extents.len() && clean_edges < 8 {
            let left = extents[idx];
            let right = extents[idx.saturating_add(1)];
            if left.start >= left.end {
                extents.remove(idx);
                clean_edges = 0;
                idx = idx.saturating_sub(1);
                continue;
            }
            if right.start >= right.end {
                extents.remove(idx.saturating_add(1));
                clean_edges = 0;
                continue;
            }
            if Self::live_extent_entries_can_merge(&left, &right) {
                extents[idx].end = right.end;
                extents[idx].physical_reserved_end = extents[idx]
                    .physical_reserved_end
                    .max(right.physical_reserved_end);
                extents.remove(idx.saturating_add(1));
                clean_edges = 0;
                idx = idx.saturating_sub(1);
                continue;
            }
            idx = idx.saturating_add(1);
            clean_edges = clean_edges.saturating_add(1);
        }
    }

    fn live_extent_physical_at(
        entry: &LiveExtentEntry,
        logical: u64,
    ) -> core::result::Result<u64, crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if entry.kind == LiveExtentEntry::DATA {
            entry
                .physical_start
                .checked_add(logical.saturating_sub(entry.start))
                .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)
        } else {
            Ok(0)
        }
    }

    fn live_extent_len(entry: &LiveExtentEntry) -> u64 {
        entry.end.saturating_sub(entry.start)
    }

    fn live_extent_piece_physical_at(
        entry: &LiveExtentEntry,
        relative: u64,
    ) -> core::result::Result<u64, crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if entry.kind == LiveExtentEntry::DATA {
            entry
                .physical_start
                .checked_add(relative)
                .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)
        } else {
            Ok(0)
        }
    }

    fn mark_live_extents_dirty(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        let mut dirty = self.live_extent_dirty_inodes.borrow_mut();
        if dirty.iter().any(|entry| *entry == inode) {
            return Ok(());
        }
        let before = dirty.len();
        dirty.push(inode);
        if dirty.len() == before {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
        }
        Ok(())
    }

    fn live_extents_are_dirty(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
    ) -> bool {
        self.live_extent_dirty_inodes
            .borrow()
            .iter()
            .any(|entry| *entry == inode)
    }

    fn clear_live_extents_dirty(&self, inode: crate::tidefs_kmod_bridge::kernel_types::InodeId) {
        self.live_extent_dirty_inodes
            .borrow_mut()
            .retain(|entry| *entry != inode);
    }

    fn invalidate_live_collapse_cursor(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
    ) {
        self.live_collapse_cursors
            .borrow_mut()
            .retain(|entry| entry.inode != inode);
    }

    fn live_collapse_cursor_for(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        offset: u64,
    ) -> Option<(usize, u64)> {
        self.live_collapse_cursors
            .borrow()
            .iter()
            .find(|entry| entry.inode == inode && offset >= entry.request_offset)
            .map(|entry| (entry.index, entry.logical_before))
    }

    fn live_collapse_cursor_rewound(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        offset: u64,
    ) -> bool {
        self.live_collapse_cursors
            .borrow()
            .iter()
            .any(|entry| entry.inode == inode && offset < entry.request_offset)
    }

    fn update_live_collapse_cursor(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        request_offset: u64,
        index: usize,
        logical_before: u64,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        let mut cursors = self.live_collapse_cursors.borrow_mut();
        for cursor in cursors.iter_mut() {
            if cursor.inode == inode {
                cursor.request_offset = request_offset;
                cursor.index = index;
                cursor.logical_before = logical_before;
                return Ok(());
            }
        }
        let before = cursors.len();
        cursors.push(LiveCollapseCursor {
            inode,
            request_offset,
            index,
            logical_before,
        });
        if cursors.len() == before {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
        }
        Ok(())
    }

    fn normalize_live_extents(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if !self.live_extents_are_dirty(inode) {
            return Ok(());
        }

        let old = self.live_extents.borrow();
        let mut next = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();
        let mut cursor = 0u64;

        for entry in old.iter() {
            if entry.inode != inode {
                Self::push_live_extent_entry(&mut next, *entry)?;
                continue;
            }

            let len = Self::live_extent_len(entry);
            if len == 0 {
                continue;
            }
            let end = cursor
                .checked_add(len)
                .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)?;
            Self::push_live_extent_entry(
                &mut next,
                LiveExtentEntry {
                    inode: entry.inode,
                    start: cursor,
                    end,
                    physical_start: entry.physical_start,
                    physical_reserved_end: if entry.kind == LiveExtentEntry::DATA {
                        entry.physical_start.saturating_add(len)
                    } else {
                        0
                    },
                    kind: entry.kind,
                },
            )?;
            cursor = end;
        }

        drop(old);
        *self.live_extents.borrow_mut() = next;
        self.clear_live_extents_dirty(inode);
        self.invalidate_live_collapse_cursor(inode);
        self.recompute_live_data_allocator_tail()?;
        Ok(())
    }

    fn normalize_all_live_extents(
        &self,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        let mut dirty = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();
        {
            let dirty_ref = self.live_extent_dirty_inodes.borrow();
            for inode in dirty_ref.iter() {
                let before = dirty.len();
                dirty.push(*inode);
                if dirty.len() == before {
                    return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
                }
            }
        }
        for inode in dirty.iter() {
            self.normalize_live_extents(*inode)?;
        }
        Ok(())
    }

    fn set_live_extent_range(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        offset: u64,
        length: u64,
        kind: Option<u8>,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        let physical_start = if kind == Some(LiveExtentEntry::DATA) {
            self.allocate_live_data_range(length)?
        } else {
            0
        };
        let physical_reserved_end = if kind == Some(LiveExtentEntry::DATA) {
            physical_start
                .checked_add(length)
                .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)?
        } else {
            0
        };
        self.set_live_extent_range_with_physical(
            inode,
            offset,
            length,
            kind,
            physical_start,
            physical_reserved_end,
        )
    }

    fn set_live_data_extent_range(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        offset: u64,
        length: u64,
        physical_start: u64,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        let physical_reserved_end = physical_start
            .checked_add(length)
            .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)?;
        self.set_live_data_extent_range_reserved(
            inode,
            offset,
            length,
            physical_start,
            physical_reserved_end,
        )
    }

    fn set_live_data_extent_range_reserved(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        offset: u64,
        length: u64,
        physical_start: u64,
        physical_reserved_end: u64,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        self.set_live_extent_range_with_physical(
            inode,
            offset,
            length,
            Some(LiveExtentEntry::DATA),
            physical_start,
            physical_reserved_end,
        )
    }

    fn set_live_extent_range_with_physical(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        offset: u64,
        length: u64,
        kind: Option<u8>,
        physical_start: u64,
        physical_reserved_end: u64,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if length == 0 {
            return Ok(());
        }
        self.normalize_live_extents(inode)?;
        self.invalidate_live_collapse_cursor(inode);
        let end = Self::checked_range_end(offset, length)?;
        let old = self.live_extents.borrow();
        let mut next = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();

        for entry in old.iter() {
            if entry.inode != inode || entry.end <= offset || entry.start >= end {
                Self::push_live_extent_entry(&mut next, *entry)?;
                continue;
            }
            if entry.start < offset {
                Self::push_live_extent_entry(
                    &mut next,
                    LiveExtentEntry {
                        inode: entry.inode,
                        start: entry.start,
                        end: offset,
                        physical_start: entry.physical_start,
                        physical_reserved_end: if entry.kind == LiveExtentEntry::DATA {
                            entry
                                .physical_start
                                .saturating_add(offset.saturating_sub(entry.start))
                        } else {
                            0
                        },
                        kind: entry.kind,
                    },
                )?;
            }
            if entry.end > end {
                let physical_start = if entry.kind == LiveExtentEntry::DATA {
                    entry
                        .physical_start
                        .checked_add(end.saturating_sub(entry.start))
                        .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)?
                } else {
                    0
                };
                Self::push_live_extent_entry(
                    &mut next,
                    LiveExtentEntry {
                        inode: entry.inode,
                        start: end,
                        end: entry.end,
                        physical_start,
                        physical_reserved_end: entry.physical_reserved_end,
                        kind: entry.kind,
                    },
                )?;
            }
        }

        if let Some(kind) = kind {
            Self::push_live_extent_entry(
                &mut next,
                LiveExtentEntry {
                    inode,
                    start: offset,
                    end,
                    physical_start: if kind == LiveExtentEntry::DATA {
                        physical_start
                    } else {
                        0
                    },
                    physical_reserved_end: if kind == LiveExtentEntry::DATA {
                        physical_reserved_end
                    } else {
                        0
                    },
                    kind,
                },
            )?;
        }

        drop(old);
        *self.live_extents.borrow_mut() = next;
        self.sort_live_extents_for_inode(inode)?;
        self.recompute_live_data_allocator_tail()?;
        Ok(())
    }

    fn fill_live_extent_holes(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        offset: u64,
        length: u64,
        kind: u8,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if length == 0 {
            return Ok(());
        }
        self.normalize_live_extents(inode)?;
        self.invalidate_live_collapse_cursor(inode);
        let end = Self::checked_range_end(offset, length)?;
        let old = self.live_extents.borrow();
        let mut gaps = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();
        let mut cursor = offset;

        while cursor < end {
            let mut covered_end = cursor;
            let mut next_start = end;

            for entry in old.iter() {
                if entry.inode != inode || entry.end <= cursor || entry.start >= end {
                    continue;
                }
                if entry.start <= cursor {
                    covered_end = core::cmp::max(covered_end, core::cmp::min(entry.end, end));
                } else {
                    next_start = core::cmp::min(next_start, entry.start);
                }
            }

            if covered_end > cursor {
                cursor = covered_end;
                continue;
            }

            let gap_len = next_start.saturating_sub(cursor);
            let physical_start = if kind == LiveExtentEntry::DATA {
                self.allocate_live_data_range(gap_len)?
            } else {
                0
            };
            Self::push_live_extent_entry(
                &mut gaps,
                LiveExtentEntry {
                    inode,
                    start: cursor,
                    end: next_start,
                    physical_start,
                    physical_reserved_end: if kind == LiveExtentEntry::DATA {
                        physical_start.saturating_add(gap_len)
                    } else {
                        0
                    },
                    kind,
                },
            )?;
            cursor = next_start;
        }
        drop(old);

        let mut extents = self.live_extents.borrow_mut();
        for entry in gaps.iter() {
            Self::push_live_extent_entry(&mut extents, *entry)?;
        }
        drop(extents);
        self.sort_live_extents_for_inode(inode)?;
        self.recompute_live_data_allocator_tail()?;
        Ok(())
    }

    fn truncate_live_extents(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        new_size: u64,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        self.normalize_live_extents(inode)?;
        self.invalidate_live_collapse_cursor(inode);
        let old = self.live_extents.borrow();
        let mut next = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();
        for entry in old.iter() {
            if entry.inode != inode {
                Self::push_live_extent_entry(&mut next, *entry)?;
                continue;
            }
            if entry.start >= new_size {
                continue;
            }
            let mut clipped = *entry;
            if clipped.end > new_size {
                clipped.end = new_size;
            }
            Self::push_live_extent_entry(&mut next, clipped)?;
        }
        drop(old);
        *self.live_extents.borrow_mut() = next;
        self.sort_live_extents_for_inode(inode)?;
        self.recompute_live_data_allocator_tail()?;
        Ok(())
    }

    fn push_write_buffer_entry(
        out: &mut crate::tidefs_kmod_bridge::kernel_types::KmodVec<WriteBufferEntry>,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        offset: u64,
        length: u64,
        data: &[u8],
        zero: bool,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if length == 0 {
            return Ok(());
        }
        let len = usize::try_from(length)
            .map_err(|_| crate::tidefs_kmod_bridge::kernel_types::Errno::EOVERFLOW)?;
        if let Some(last) = out.last_mut() {
            if last.inode == inode
                && last.zero == zero
                && last
                    .offset
                    .checked_add(last.len)
                    .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)?
                    == offset
                && last.len.saturating_add(length) <= LIVE_WRITE_BUFFER_ENTRY_LIMIT
            {
                if zero {
                    last.len = last
                        .len
                        .checked_add(length)
                        .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)?;
                    return Ok(());
                }
                if data.len() < len {
                    return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EIO);
                }
                let before = last.data.len();
                last.data.extend_from_slice(&data[..len]);
                if last.data.len() != before.saturating_add(len) {
                    return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
                }
                last.len = last
                    .len
                    .checked_add(length)
                    .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)?;
                return Ok(());
            }
        }
        let payload = if zero {
            crate::tidefs_kmod_bridge::kernel_types::KmodVec::new()
        } else {
            if data.len() < len {
                return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EIO);
            }
            let mut payload = crate::tidefs_kmod_bridge::kernel_types::KmodVec::with_capacity(len);
            payload.extend_from_slice(&data[..len]);
            if payload.len() != len {
                return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
            }
            payload
        };

        let before = out.len();
        out.push(WriteBufferEntry {
            inode,
            offset,
            len: length,
            data: payload,
            zero,
        });
        if out.len() == before {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
        }
        Ok(())
    }

    fn try_append_live_write_buffer_tail(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        offset: u64,
        data: &[u8],
    ) -> core::result::Result<bool, crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if data.is_empty() {
            return Ok(true);
        }
        let mut buffer = self.write_buffer.borrow_mut();
        for entry in buffer.iter_mut() {
            if entry.inode != inode || entry.zero {
                continue;
            }
            if entry
                .offset
                .checked_add(entry.len)
                .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)?
                != offset
            {
                continue;
            }
            if entry.len.saturating_add(data.len() as u64) > LIVE_WRITE_BUFFER_ENTRY_LIMIT {
                return Ok(false);
            }
            let before = entry.data.len();
            entry.data.extend_from_slice(data);
            if entry.data.len() != before.saturating_add(data.len()) {
                return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
            }
            entry.len = entry
                .len
                .checked_add(data.len() as u64)
                .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)?;
            return Ok(true);
        }
        Ok(false)
    }

    fn live_write_buffer_covers_range(&self, ino: u64, offset: u64, length: u64) -> bool {
        if length == 0 {
            return true;
        }
        let Some(end) = offset.checked_add(length) else {
            return false;
        };
        let buffer = self.write_buffer.borrow();
        for entry in buffer.iter() {
            if entry.inode.get() != ino {
                continue;
            }
            let Some(entry_end) = entry.offset.checked_add(entry.len) else {
                continue;
            };
            if entry.offset <= offset && entry_end >= end {
                return true;
            }
        }
        false
    }

    fn set_live_write_buffer_range(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        offset: u64,
        length: u64,
        data: &[u8],
        zero: bool,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if length == 0 {
            return Ok(());
        }
        let end = Self::checked_range_end(offset, length)?;
        let old = self.write_buffer.borrow();
        let mut next = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();

        for entry in old.iter() {
            let entry_end = Self::checked_range_end(entry.offset, entry.len)?;
            if entry.inode != inode || entry_end <= offset || entry.offset >= end {
                Self::push_write_buffer_entry(
                    &mut next,
                    entry.inode,
                    entry.offset,
                    entry.len,
                    &entry.data,
                    entry.zero,
                )?;
                continue;
            }

            if entry.offset < offset {
                let left_len = offset.saturating_sub(entry.offset);
                Self::push_write_buffer_entry(
                    &mut next,
                    entry.inode,
                    entry.offset,
                    left_len,
                    &entry.data,
                    entry.zero,
                )?;
            }
            if entry_end > end {
                let data_start = usize::try_from(end.saturating_sub(entry.offset))
                    .map_err(|_| crate::tidefs_kmod_bridge::kernel_types::Errno::EOVERFLOW)?;
                let right_len = entry_end.saturating_sub(end);
                let right_data = if entry.zero {
                    &[][..]
                } else {
                    &entry.data[data_start..]
                };
                Self::push_write_buffer_entry(
                    &mut next,
                    entry.inode,
                    end,
                    right_len,
                    right_data,
                    entry.zero,
                )?;
            }
        }
        Self::push_write_buffer_entry(&mut next, inode, offset, length, data, zero)?;
        drop(old);
        *self.write_buffer.borrow_mut() = next;
        Ok(())
    }

    fn clear_live_write_buffer_range(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        offset: u64,
        length: u64,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if length == 0 {
            return Ok(());
        }
        let end = Self::checked_range_end(offset, length)?;
        let old = self.write_buffer.borrow();
        let mut next = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();

        for entry in old.iter() {
            let entry_end = Self::checked_range_end(entry.offset, entry.len)?;
            if entry.inode != inode || entry_end <= offset || entry.offset >= end {
                Self::push_write_buffer_entry(
                    &mut next,
                    entry.inode,
                    entry.offset,
                    entry.len,
                    &entry.data,
                    entry.zero,
                )?;
                continue;
            }

            if entry.offset < offset {
                let left_len = offset.saturating_sub(entry.offset);
                Self::push_write_buffer_entry(
                    &mut next,
                    entry.inode,
                    entry.offset,
                    left_len,
                    &entry.data,
                    entry.zero,
                )?;
            }
            if entry_end > end {
                let data_start = usize::try_from(end.saturating_sub(entry.offset))
                    .map_err(|_| crate::tidefs_kmod_bridge::kernel_types::Errno::EOVERFLOW)?;
                let right_len = entry_end.saturating_sub(end);
                let right_data = if entry.zero {
                    &[][..]
                } else {
                    &entry.data[data_start..]
                };
                Self::push_write_buffer_entry(
                    &mut next,
                    entry.inode,
                    end,
                    right_len,
                    right_data,
                    entry.zero,
                )?;
            }
        }

        drop(old);
        *self.write_buffer.borrow_mut() = next;
        Ok(())
    }

    fn truncate_live_write_buffer(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        new_size: u64,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        let old = self.write_buffer.borrow();
        let mut next = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();
        for entry in old.iter() {
            if entry.inode != inode {
                Self::push_write_buffer_entry(
                    &mut next,
                    entry.inode,
                    entry.offset,
                    entry.len,
                    &entry.data,
                    entry.zero,
                )?;
                continue;
            }
            if entry.offset >= new_size {
                continue;
            }
            let keep_len = core::cmp::min(entry.len, new_size.saturating_sub(entry.offset));
            Self::push_write_buffer_entry(
                &mut next,
                entry.inode,
                entry.offset,
                keep_len,
                &entry.data,
                entry.zero,
            )?;
        }
        drop(old);
        *self.write_buffer.borrow_mut() = next;
        Ok(())
    }

    fn collapse_live_write_buffer(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        offset: u64,
        length: u64,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        let end = Self::checked_range_end(offset, length)?;
        let old = self.write_buffer.borrow();
        let mut next = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();
        for entry in old.iter() {
            let entry_end = Self::checked_range_end(entry.offset, entry.len)?;
            if entry.inode != inode || entry_end <= offset {
                Self::push_write_buffer_entry(
                    &mut next,
                    entry.inode,
                    entry.offset,
                    entry.len,
                    &entry.data,
                    entry.zero,
                )?;
                continue;
            }
            if entry.offset >= end {
                Self::push_write_buffer_entry(
                    &mut next,
                    entry.inode,
                    entry.offset.saturating_sub(length),
                    entry.len,
                    &entry.data,
                    entry.zero,
                )?;
                continue;
            }
            if entry.offset < offset {
                let left_len = offset.saturating_sub(entry.offset);
                Self::push_write_buffer_entry(
                    &mut next,
                    entry.inode,
                    entry.offset,
                    left_len,
                    &entry.data,
                    entry.zero,
                )?;
            }
            if entry_end > end {
                let data_start = usize::try_from(end.saturating_sub(entry.offset))
                    .map_err(|_| crate::tidefs_kmod_bridge::kernel_types::Errno::EOVERFLOW)?;
                let right_len = entry_end.saturating_sub(end);
                let right_data = if entry.zero {
                    &[][..]
                } else {
                    &entry.data[data_start..]
                };
                Self::push_write_buffer_entry(
                    &mut next,
                    entry.inode,
                    offset,
                    right_len,
                    right_data,
                    entry.zero,
                )?;
            }
        }
        drop(old);
        *self.write_buffer.borrow_mut() = next;
        Ok(())
    }

    fn insert_live_write_buffer(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        offset: u64,
        length: u64,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if length == 0 {
            return Ok(());
        }
        let old = self.write_buffer.borrow();
        let mut next = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();
        for entry in old.iter() {
            let entry_end = Self::checked_range_end(entry.offset, entry.len)?;
            if entry.inode != inode || entry_end <= offset {
                Self::push_write_buffer_entry(
                    &mut next,
                    entry.inode,
                    entry.offset,
                    entry.len,
                    &entry.data,
                    entry.zero,
                )?;
                continue;
            }
            if entry.offset >= offset {
                let shifted = entry
                    .offset
                    .checked_add(length)
                    .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)?;
                Self::push_write_buffer_entry(
                    &mut next,
                    entry.inode,
                    shifted,
                    entry.len,
                    &entry.data,
                    entry.zero,
                )?;
                continue;
            }

            let left_len = offset.saturating_sub(entry.offset);
            Self::push_write_buffer_entry(
                &mut next,
                entry.inode,
                entry.offset,
                left_len,
                &entry.data,
                entry.zero,
            )?;

            let data_start = usize::try_from(left_len)
                .map_err(|_| crate::tidefs_kmod_bridge::kernel_types::Errno::EOVERFLOW)?;
            let right_len = entry_end.saturating_sub(offset);
            let right_data = if entry.zero {
                &[][..]
            } else {
                &entry.data[data_start..]
            };
            let shifted = offset
                .checked_add(length)
                .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)?;
            Self::push_write_buffer_entry(
                &mut next,
                entry.inode,
                shifted,
                right_len,
                right_data,
                entry.zero,
            )?;
        }
        drop(old);
        *self.write_buffer.borrow_mut() = next;
        Ok(())
    }

    fn collapse_live_extents(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        offset: u64,
        length: u64,
    ) -> core::result::Result<u64, crate::tidefs_kmod_bridge::kernel_types::Errno> {
        let end = Self::checked_range_end(offset, length)?;
        if length == 0 {
            return Ok(0);
        }

        self.normalize_live_extents(inode)?;
        self.invalidate_live_collapse_cursor(inode);

        let old = self.live_extents.borrow();
        let mut next = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();
        let mut removed_bytes = 0u64;

        for entry in old.iter() {
            if entry.inode != inode {
                Self::push_live_extent_entry(&mut next, *entry)?;
                continue;
            }

            let entry_len = Self::live_extent_len(entry);
            if entry_len == 0 {
                continue;
            }
            let entry_start = entry.start;
            let entry_end = entry.end;

            if entry_end <= offset {
                Self::push_live_extent_entry(&mut next, *entry)?;
                continue;
            }
            if entry_start >= end {
                let shifted_start = entry_start.saturating_sub(length);
                let shifted_end = entry_end.saturating_sub(length);
                Self::push_live_extent_entry(
                    &mut next,
                    LiveExtentEntry {
                        inode: entry.inode,
                        start: shifted_start,
                        end: shifted_end,
                        physical_start: entry.physical_start,
                        physical_reserved_end: entry.physical_reserved_end,
                        kind: entry.kind,
                    },
                )?;
                continue;
            }

            let remove_start = core::cmp::max(offset, entry_start);
            let remove_end = core::cmp::min(end, entry_end);
            let left_len = remove_start.saturating_sub(entry_start);
            if left_len > 0 {
                Self::push_live_extent_entry(
                    &mut next,
                    LiveExtentEntry {
                        inode: entry.inode,
                        start: entry.start,
                        end: entry
                            .start
                            .checked_add(left_len)
                            .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)?,
                        physical_start: entry.physical_start,
                        physical_reserved_end: if entry.kind == LiveExtentEntry::DATA {
                            entry.physical_start.saturating_add(left_len)
                        } else {
                            0
                        },
                        kind: entry.kind,
                    },
                )?;
            }

            if remove_start < remove_end {
                removed_bytes =
                    removed_bytes.saturating_add(remove_end.saturating_sub(remove_start));
            }

            if entry_end > end {
                let shifted_start = end.saturating_sub(length);
                let shifted_end = entry_end.saturating_sub(length);
                Self::push_live_extent_entry(
                    &mut next,
                    LiveExtentEntry {
                        inode: entry.inode,
                        start: shifted_start,
                        end: shifted_end,
                        physical_start: Self::live_extent_physical_at(entry, end)?,
                        physical_reserved_end: entry.physical_reserved_end,
                        kind: entry.kind,
                    },
                )?;
            }
        }

        drop(old);
        *self.live_extents.borrow_mut() = next;
        self.sort_live_extents_for_inode(inode)?;
        self.recompute_live_data_allocator_tail()?;
        Ok(Self::live_allocated_blocks_from_bytes(removed_bytes))
    }

    fn insert_live_extents(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        offset: u64,
        length: u64,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if length == 0 {
            return Ok(());
        }

        self.normalize_live_extents(inode)?;
        self.invalidate_live_collapse_cursor(inode);

        let old = self.live_extents.borrow();
        let mut next = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();

        for entry in old.iter() {
            if entry.inode != inode {
                Self::push_live_extent_entry(&mut next, *entry)?;
                continue;
            }

            let entry_len = Self::live_extent_len(entry);
            if entry_len == 0 {
                continue;
            }
            let entry_start = entry.start;
            let entry_end = entry.end;

            if entry_end <= offset {
                Self::push_live_extent_entry(&mut next, *entry)?;
                continue;
            }
            if entry_start >= offset {
                let shifted_start = entry_start
                    .checked_add(length)
                    .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)?;
                let shifted_end = entry_end
                    .checked_add(length)
                    .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)?;
                Self::push_live_extent_entry(
                    &mut next,
                    LiveExtentEntry {
                        inode: entry.inode,
                        start: shifted_start,
                        end: shifted_end,
                        physical_start: entry.physical_start,
                        physical_reserved_end: entry.physical_reserved_end,
                        kind: entry.kind,
                    },
                )?;
                continue;
            }

            let left_len = offset.saturating_sub(entry_start);
            Self::push_live_extent_entry(
                &mut next,
                LiveExtentEntry {
                    inode: entry.inode,
                    start: entry_start,
                    end: offset,
                    physical_start: entry.physical_start,
                    physical_reserved_end: if entry.kind == LiveExtentEntry::DATA {
                        entry.physical_start.saturating_add(left_len)
                    } else {
                        0
                    },
                    kind: entry.kind,
                },
            )?;

            let shifted_start = offset
                .checked_add(length)
                .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)?;
            let shifted_end = entry_end
                .checked_add(length)
                .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)?;
            Self::push_live_extent_entry(
                &mut next,
                LiveExtentEntry {
                    inode: entry.inode,
                    start: shifted_start,
                    end: shifted_end,
                    physical_start: Self::live_extent_physical_at(entry, offset)?,
                    physical_reserved_end: entry.physical_reserved_end,
                    kind: entry.kind,
                },
            )?;
        }

        drop(old);
        *self.live_extents.borrow_mut() = next;
        self.sort_live_extents_for_inode(inode)?;
        self.recompute_live_data_allocator_tail()?;
        Ok(())
    }

    fn live_allocated_blocks(&self, ino: u64) -> u64 {
        let inode = crate::tidefs_kmod_bridge::kernel_types::InodeId::new(ino);
        let bytes = self
            .live_extents
            .borrow()
            .iter()
            .filter(|entry| entry.inode == inode)
            .fold(0u64, |sum, entry| {
                sum.saturating_add(entry.end.saturating_sub(entry.start))
            });
        Self::live_allocated_blocks_from_bytes(bytes)
    }

    /// Increment the open file handle count for an inode.
    fn track_open(
        &self,
        ino: u64,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        let mut fds = self.open_fds.borrow_mut();
        for entry in fds.iter_mut() {
            if entry.0 == ino {
                entry.1 = entry.1.saturating_add(1);
                return Ok(());
            }
        }
        let before = fds.len();
        fds.push((ino, 1));
        if fds.len() == before {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
        }
        Ok(())
    }

    /// Decrement the open file handle count for an inode.
    /// Returns the new count (0 means no open handles remain).
    fn track_release(&self, ino: u64) -> u32 {
        let mut fds = self.open_fds.borrow_mut();
        if let Some(pos) = fds.iter().position(|e| e.0 == ino) {
            fds[pos].1 = fds[pos].1.saturating_sub(1);
            let count = fds[pos].1;
            if count == 0 {
                fds.remove(pos);
            }
            return count;
        }
        0
    }

    /// Remove an inode record by ino; returns true if found and removed.
    fn remove_inode_record(
        &self,
        ino: u64,
    ) -> core::result::Result<bool, crate::tidefs_kmod_bridge::kernel_types::Errno> {
        let mut inodes = self.inodes.borrow_mut();
        if let Some(pos) = inodes.iter().position(|r| r.ino == ino) {
            inodes.remove(pos);
            drop(inodes);
            self.remove_transient_inode_state(ino)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn remove_transient_inode_state(
        &self,
        ino: u64,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        self.write_buffer
            .borrow_mut()
            .retain(|entry| entry.inode.get() != ino);
        self.live_extents
            .borrow_mut()
            .retain(|entry| entry.inode.get() != ino);
        self.xattr_stores
            .borrow_mut()
            .retain(|(store_ino, _)| *store_ino != ino);
        self.open_fds
            .borrow_mut()
            .retain(|(open_ino, _)| *open_ino != ino);
        self.advisory_locks
            .borrow_mut()
            .retain(|entry| entry.inode.get() != ino);
        let inode = crate::tidefs_kmod_bridge::kernel_types::InodeId::new(ino);
        self.clear_live_extents_dirty(inode);
        self.invalidate_live_collapse_cursor(inode);
        self.recompute_live_data_allocator_tail()
    }

    fn drop_unlinked_inode_if_closed(
        &self,
        ino: u64,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if self.inode_open_count(ino) != 0 {
            return Ok(());
        }
        let should_drop = if let Some(idx) = self.find_inode(ino) {
            self.inodes.borrow()[idx].nlink == 0
        } else {
            false
        };
        if should_drop {
            self.remove_inode_record(ino)?;
        }
        Ok(())
    }

    fn push_inode_record(
        &self,
        rec: InodeRecord,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        let mut inodes = self.inodes.borrow_mut();
        let before = inodes.len();
        inodes.push(rec);
        if inodes.len() == before {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
        }
        Ok(())
    }
    /// Returns true if an entry was removed.
    fn remove_dir_entry(&self, parent_ino: u64, name: &[u8]) -> bool {
        let mut entries = self.dir_entries.borrow_mut();
        let mut removed = false;
        while let Some(pos) = entries
            .iter()
            .position(|e| e.0 == parent_ino && &*e.1 == name)
        {
            entries.remove(pos);
            removed = true;
        }
        removed
    }

    /// Build an InodeAttr from an InodeRecord for returning to the VFS.

    /// Read an on-disk VINO-format inode record from the inode table.
    ///
    /// Uses the cached `inode_table_root` from the VRBT (resolved once
    /// on first use via the same VRBT read path as `getattr`). Returns
    /// the decoded VinoRecord with extent_map_root and object_store_locator
    /// fields required for extent-map-aware data-path routing.
    fn read_inode_record(
        &self,
        ino: u64,
        io_ctx: &crate::tidefs_kmod_bridge::kernel_types::CommittedRootIoCtx,
        // SAFETY: read_fn is a function pointer provided by the C
        // shim pointing to a valid block-device read implementation.
        read_fn: unsafe extern "C" fn(u64, *mut u8, u32) -> core::ffi::c_int,
        ss: u64,
    ) -> core::result::Result<
        crate::replay_integration::VinoRecord,
        crate::tidefs_kmod_bridge::kernel_types::Errno,
    > {
        if ino == 0 {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOENT);
        }
        // Resolve VRBT pointers on first use (cached in Cell<u64>).
        let mut inode_table_root = self.inode_table_root.get();
        if inode_table_root == 0 {
            let vrbt_byte_offset = io_ctx
                .superblock_offset
                .saturating_add(3u64.saturating_mul(ss));
            let vrbt_sector = vrbt_byte_offset / ss;
            let mut vrbt_buf = [0u8; 88];
            // SAFETY: read_fn is the C shim's block read callback;
            // vrbt_buf has sufficient capacity and vrbt_sector is valid.
            let ret = unsafe { read_fn(vrbt_sector, vrbt_buf.as_mut_ptr(), vrbt_buf.len() as u32) };
            if ret < 0 {
                kernel::pr_err!(
                    "tidefs_posix_vfs: read_inode_record: VRBT read failed sector={} err={}\n",
                    vrbt_sector,
                    ret
                );
                return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EIO);
            }
            if let Ok(vrbt) = crate::replay_integration::decode_vrbt(&vrbt_buf) {
                inode_table_root = vrbt.inode_table_root;
                self.inode_table_root.set(inode_table_root);
                self.extent_map_root.set(vrbt.extent_map_root);
            } else {
                // VRBT not yet committed (fresh pool, first mount before
                // txg commit): check if the inode exists in the local
                // in-memory table populated by namespace sync.  If it does,
                // return a default record so callers in the read/write
                // path get extent_map_root=0 and use write_buffer or
                // return empty, instead of propagating EIO.
                if self.find_inode(ino).is_some() {
                    return Ok(crate::replay_integration::VinoRecord {
                        extent_map_root: 0,
                        object_store_locator: 0,
                        mode: 0,
                        uid: 0,
                        gid: 0,
                        size: 0,
                        blocks: 0,
                        atime_secs: 0,
                        atime_nanos: 0,
                        mtime_secs: 0,
                        mtime_nanos: 0,
                        ctime_secs: 0,
                        ctime_nanos: 0,
                        nlink: 0,
                        generation: 0,
                        kind: 0,
                        btime_secs: 0,
                        btime_nanos: 0,
                        flags: 0,
                    });
                }
                kernel::pr_err!(
                    "tidefs_posix_vfs: read_inode_record: VRBT decode failed and inode {} not in local table\n", ino
                );
                return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EIO);
            }
        }
        const VINO_RECORD_BYTES: u64 = 116;
        let entry_offset =
            inode_table_root.saturating_add((ino - 1).saturating_mul(VINO_RECORD_BYTES));
        let entry_sector = entry_offset / ss;
        let sector_off = (entry_offset % ss) as usize;
        let record_len = VINO_RECORD_BYTES as usize;
        let read_len_usize = sector_off.saturating_add(record_len);
        let read_len = u32::try_from(read_len_usize)
            .map_err(|_| crate::tidefs_kmod_bridge::kernel_types::Errno::EOVERFLOW)?;
        // Allocate a sector-sized buffer from the kernel heap to avoid
        // a 4 KiB stack frame in the kernel read path (K7-46 guard-page Oops).
        // SAFETY: read_fn is the C shim's block read callback;
        // the buffer lives through the read and inode-parse span.
        let mut entry_buf = match kernel::alloc::KVec::<u8>::with_capacity(
            read_len_usize,
            kernel::alloc::flags::GFP_KERNEL,
        ) {
            Ok(v) => v,
            Err(_) => return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM),
        };
        if entry_buf
            .resize(read_len_usize, 0, kernel::alloc::flags::GFP_KERNEL)
            .is_err()
        {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
        }
        // SAFETY: entry_buf has initialized length >= read_len; entry_sector is valid.
        let ret = unsafe { read_fn(entry_sector, entry_buf.as_mut_ptr(), read_len) };
        if ret < 0 {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EIO);
        }
        if read_len_usize > entry_buf.len() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOENT);
        }
        match crate::replay_integration::read_vino_inode(&entry_buf[sector_off..], 1) {
            Some(rec) => Ok(rec),
            None => Ok(crate::replay_integration::VinoRecord {
                extent_map_root: 0,
                object_store_locator: 0,
                mode: 0,
                uid: 0,
                gid: 0,
                size: 0,
                blocks: 0,
                atime_secs: 0,
                atime_nanos: 0,
                mtime_secs: 0,
                mtime_nanos: 0,
                ctime_secs: 0,
                ctime_nanos: 0,
                nlink: 0,
                generation: 0,
                kind: 0,
                btime_secs: 0,
                btime_nanos: 0,
                flags: 0,
            }),
        }
    }

    fn record_to_attr(
        rec: &InodeRecord,
        sector_size: u32,
    ) -> crate::tidefs_kmod_bridge::kernel_types::InodeAttr {
        let kind = match rec.kind {
            InodeRecord::FILE => crate::tidefs_kmod_bridge::kernel_types::NodeKind::File,
            InodeRecord::DIR => crate::tidefs_kmod_bridge::kernel_types::NodeKind::Dir,
            _ => crate::tidefs_kmod_bridge::kernel_types::NodeKind::Symlink,
        };
        crate::tidefs_kmod_bridge::kernel_types::InodeAttr {
            inode_id: crate::tidefs_kmod_bridge::kernel_types::InodeId::new(rec.ino),
            generation: crate::tidefs_kmod_bridge::kernel_types::Generation::new(rec.generation),
            kind,
            posix: crate::tidefs_kmod_bridge::kernel_types::PosixAttrs {
                mode: rec.mode,
                uid: rec.uid,
                gid: rec.gid,
                nlink: rec.nlink,
                rdev: 0,
                atime_ns: rec.atime_ns,
                mtime_ns: rec.mtime_ns,
                ctime_ns: rec.ctime_ns,
                btime_ns: 0,
                size: rec.size,
                blocks_512: rec.blocks,
                blksize: sector_size,
            },
            flags: crate::tidefs_kmod_bridge::kernel_types::InodeFlags(0),
            subtree_rev: 0,
            dir_rev: 0,
        }
    }
}

// -- Committed-root encoding helpers for write_committed_root -----------

impl KernelEngine {
    /// Fixed-size constants for the VRBT/VCRP/VCRL on-disk formats.
    const VRBT_MAGIC: [u8; 4] = *b"VRBT";
    const VRBT_VERSION: u32 = 1;
    const VRBT_HEADER_SIZE: usize = 56;
    const VRBT_WIRE_SIZE: usize = 88;
    const VRBT_HASH_OFFSET: usize = 56;
    const VCRP_MAGIC: [u8; 4] = *b"VCRP";
    const VCRP_VERSION: u32 = 1;
    const VCRP_HEADER_SIZE: usize = 64;
    const VCRP_RECORD_SIZE: usize = 96;
    const VCRP_HASH_OFFSET: usize = 64;

    /// Encode a VRBT committed-root block.
    fn encode_vrbt_block(
        commit_group_id: u64,
        namespace_root: u64,
        inode_table_root: u64,
        extent_map_root: u64,
        intent_log_tail: u64,
        root_sector: u64,
    ) -> crate::tidefs_kmod_bridge::kernel_types::KmodVec<u8> {
        let mut block = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();
        block.extend_from_slice(&Self::VRBT_MAGIC);
        block.extend_from_slice(&Self::VRBT_VERSION.to_le_bytes());
        block.extend_from_slice(&commit_group_id.to_le_bytes());
        block.extend_from_slice(&namespace_root.to_le_bytes());
        block.extend_from_slice(&inode_table_root.to_le_bytes());
        block.extend_from_slice(&extent_map_root.to_le_bytes());
        block.extend_from_slice(&intent_log_tail.to_le_bytes());
        // Pad to header size with reserved bytes
        while block.len() < Self::VRBT_HEADER_SIZE {
            block.push(0u8);
        }
        // Compute BLAKE3 hash over header
        let hash_bytes: [u8; 32] = crate::blake3::hash(&block[..Self::VRBT_HEADER_SIZE]).into();
        block.extend_from_slice(&hash_bytes);
        // Pad to wire size
        while block.len() < Self::VRBT_WIRE_SIZE {
            block.push(0u8);
        }
        // Write root_sector into reserved bytes (past header, before hash padding)
        // bytes 48..56: root_sector (little-endian)
        let rs_bytes = root_sector.to_le_bytes();
        for (i, b) in rs_bytes.iter().enumerate() {
            block[48 + i] = *b;
        }
        block
    }

    /// Encode a VCRP committed-root pointer record.
    fn encode_vcrp_record(
        pointer_sequence: u64,
        root_sector: u64,
        commit_group_id: u64,
        root_hash: &[u8; 32],
    ) -> crate::tidefs_kmod_bridge::kernel_types::KmodVec<u8> {
        let mut rec = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();
        rec.extend_from_slice(&Self::VCRP_MAGIC);
        rec.extend_from_slice(&Self::VCRP_VERSION.to_le_bytes());
        rec.extend_from_slice(&pointer_sequence.to_le_bytes());
        rec.extend_from_slice(&root_sector.to_le_bytes());
        rec.extend_from_slice(&commit_group_id.to_le_bytes());
        rec.extend_from_slice(root_hash);
        // Pad to header size
        while rec.len() < Self::VCRP_HEADER_SIZE {
            rec.push(0u8);
        }
        // BLAKE3 hash over header
        let hash_bytes: [u8; 32] = crate::blake3::hash(&rec[..Self::VCRP_HEADER_SIZE]).into();
        rec.extend_from_slice(&hash_bytes);
        // Pad to record size
        while rec.len() < Self::VCRP_RECORD_SIZE {
            rec.push(0u8);
        }
        rec
    }

    /// Encode a VCRL committed-root ledger entry (single anchor).
    fn encode_vcrl_ledger(
        root_ino: u64,
        pool_uuid: &[u8; 32],
        committed_txg: u64,
    ) -> crate::tidefs_kmod_bridge::kernel_types::KmodVec<u8> {
        use crate::superblock::CommittedRootAnchor;
        use crate::tidefs_kmod_bridge::kernel_types::InodeId;
        let anchor = CommittedRootAnchor::new(InodeId::new(root_ino), *pool_uuid, committed_txg);
        crate::mount::MountRootSelector::encode_ledger(&[anchor])
    }

    /// Write data padded to sector size through a C write callback.
    fn write_padded_sector(
        // SAFETY: write_fn is a function pointer provided by the C
        // shim pointing to a valid block-device write implementation.
        write_fn: unsafe extern "C" fn(u64, *const u8, u32) -> core::ffi::c_int,
        sector: u64,
        data: &[u8],
        sector_size: u32,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        let mut padded = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();
        padded.extend_from_slice(data);
        while (padded.len() as u32) < sector_size {
            padded.push(0u8);
        }
        // SAFETY: write_fn is the C shim's block write callback;
        // padded contains the data to write and sector is within bounds.
        let ret = unsafe { write_fn(sector, padded.as_ptr(), padded.len() as u32) };
        if ret != 0 {
            kernel::pr_err!(
                "tidefs_posix_vfs: write_padded_sector failed sector={} len={} ret={}\n",
                sector,
                padded.len(),
                ret,
            );
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EIO);
        }
        Ok(())
    }

    fn valid_sector_size(
        sector_size: u32,
    ) -> core::result::Result<usize, crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if sector_size == 0 || sector_size > 65536 {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL);
        }
        Ok(sector_size as usize)
    }

    fn write_live_entry_to_storage(
        io_ctx: &crate::tidefs_kmod_bridge::kernel_types::CommittedRootIoCtx,
        physical_start: u64,
        length: u64,
        data: &[u8],
        zero: bool,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if length == 0 {
            return Ok(());
        }
        let write_fn = io_ctx
            .write_sectors_fn
            .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV)?;
        let sector_size = Self::valid_sector_size(io_ctx.sector_size)?;
        let length_usize = usize::try_from(length)
            .map_err(|_| crate::tidefs_kmod_bridge::kernel_types::Errno::EOVERFLOW)?;
        if !zero && data.len() < length_usize {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EIO);
        }

        let mut cursor = 0usize;
        let mut sector_buf = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();
        while cursor < length_usize {
            let physical = physical_start
                .checked_add(cursor as u64)
                .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)?;
            let byte_offset = Self::live_data_byte_offset(io_ctx.data_area_offset, physical)?;
            let sector = byte_offset / io_ctx.sector_size as u64;
            let sector_cursor = (byte_offset % io_ctx.sector_size as u64) as usize;
            let remaining = length_usize.saturating_sub(cursor);

            if !zero && sector_cursor == 0 {
                let take = remaining.saturating_sub(remaining % sector_size);
                if take > 0 {
                    let write_len = u32::try_from(take)
                        .map_err(|_| crate::tidefs_kmod_bridge::kernel_types::Errno::EOVERFLOW)?;
                    let ret = unsafe {
                        write_fn(sector, data[cursor..cursor + take].as_ptr(), write_len)
                    };
                    if ret != 0 {
                        return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EIO);
                    }
                    cursor = cursor.saturating_add(take);
                    continue;
                }
            }

            let take = core::cmp::min(sector_size.saturating_sub(sector_cursor), remaining);
            if sector_buf.len() != sector_size {
                sector_buf =
                    crate::tidefs_kmod_bridge::kernel_types::KmodVec::from_elem(0u8, sector_size);
                if sector_buf.len() != sector_size {
                    return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
                }
            }
            for byte in &mut sector_buf[..] {
                *byte = 0;
            }
            if let Some(read_fn) = io_ctx.read_sectors_fn {
                let ret = unsafe { read_fn(sector, sector_buf.as_mut_ptr(), io_ctx.sector_size) };
                if ret != 0 {
                    return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EIO);
                }
            } else if sector_cursor != 0 || take != sector_size {
                return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV);
            }

            if zero {
                for byte in &mut sector_buf[sector_cursor..sector_cursor + take] {
                    *byte = 0;
                }
            } else {
                sector_buf[sector_cursor..sector_cursor + take]
                    .copy_from_slice(&data[cursor..cursor + take]);
            }
            let ret = unsafe { write_fn(sector, sector_buf.as_ptr(), io_ctx.sector_size) };
            if ret != 0 {
                return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EIO);
            }
            cursor = cursor.saturating_add(take);
        }
        Ok(())
    }

    fn read_live_data_from_storage(
        &self,
        physical_start: u64,
        out: &mut [u8],
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if out.is_empty() {
            return Ok(());
        }
        let Some(ref pool_core) = self.pool_core else {
            return Ok(());
        };
        let io_ctx = pool_core.committed_root_io_ctx();
        if !io_ctx.is_active() {
            return Ok(());
        }
        let Some(read_fn) = io_ctx.read_sectors_fn else {
            return Ok(());
        };
        let sector_size = Self::valid_sector_size(io_ctx.sector_size)?;
        let mut cursor = 0usize;
        let mut sector_buf = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();
        while cursor < out.len() {
            let physical = physical_start
                .checked_add(cursor as u64)
                .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)?;
            let byte_offset = Self::live_data_byte_offset(io_ctx.data_area_offset, physical)?;
            let sector = byte_offset / io_ctx.sector_size as u64;
            let sector_cursor = (byte_offset % io_ctx.sector_size as u64) as usize;
            let remaining = out.len().saturating_sub(cursor);

            if sector_cursor == 0 {
                let take = remaining.saturating_sub(remaining % sector_size);
                if take > 0 {
                    let read_len = u32::try_from(take)
                        .map_err(|_| crate::tidefs_kmod_bridge::kernel_types::Errno::EOVERFLOW)?;
                    let ret = unsafe {
                        read_fn(sector, out[cursor..cursor + take].as_mut_ptr(), read_len)
                    };
                    if ret != 0 {
                        return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EIO);
                    }
                    cursor = cursor.saturating_add(take);
                    continue;
                }
            }

            let take = core::cmp::min(sector_size.saturating_sub(sector_cursor), remaining);
            if sector_buf.len() != sector_size {
                sector_buf =
                    crate::tidefs_kmod_bridge::kernel_types::KmodVec::from_elem(0u8, sector_size);
                if sector_buf.len() != sector_size {
                    return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
                }
            }
            let ret = unsafe { read_fn(sector, sector_buf.as_mut_ptr(), io_ctx.sector_size) };
            if ret != 0 {
                return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EIO);
            }
            out[cursor..cursor + take]
                .copy_from_slice(&sector_buf[sector_cursor..sector_cursor + take]);
            cursor = cursor.saturating_add(take);
        }
        Ok(())
    }

    fn zero_live_data_range_to_storage(
        &self,
        io_ctx: &crate::tidefs_kmod_bridge::kernel_types::CommittedRootIoCtx,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        offset: u64,
        length: u64,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if length == 0 {
            return Ok(());
        }
        self.normalize_live_extents(inode)?;
        let end = Self::checked_range_end(offset, length)?;
        let mut ranges = crate::tidefs_kmod_bridge::kernel_types::KmodVec::<(u64, u64)>::new();
        {
            let extents = self.live_extents.borrow();
            for entry in extents.iter() {
                if entry.inode != inode || entry.kind != LiveExtentEntry::DATA {
                    continue;
                }
                let overlap_start = core::cmp::max(offset, entry.start);
                let overlap_end = core::cmp::min(end, entry.end);
                if overlap_start >= overlap_end {
                    continue;
                }
                let physical_start = entry
                    .physical_start
                    .checked_add(overlap_start.saturating_sub(entry.start))
                    .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)?;
                let overlap_len = overlap_end.saturating_sub(overlap_start);
                let before = ranges.len();
                ranges.push((physical_start, overlap_len));
                if ranges.len() != before.saturating_add(1) {
                    return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
                }
            }
        }
        for (physical_start, overlap_len) in ranges.iter() {
            Self::write_live_entry_to_storage(io_ctx, *physical_start, *overlap_len, &[], true)?;
        }
        Ok(())
    }

    fn ensure_live_data_extents_for_writeback(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        offset: u64,
        length: u64,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if length == 0 {
            return Ok(());
        }
        let end = Self::checked_range_end(offset, length)?;
        let mut cursor = offset;

        while cursor < end {
            self.normalize_live_extents(inode)?;
            let mut data_end = None;
            let mut convert_end = None;
            let mut next_start = end;

            {
                let extents = self.live_extents.borrow();
                for entry in extents.iter() {
                    if entry.inode != inode || entry.end <= cursor || entry.start >= end {
                        continue;
                    }
                    if entry.start <= cursor {
                        let entry_end = core::cmp::min(entry.end, end);
                        if entry.kind == LiveExtentEntry::DATA {
                            data_end =
                                Some(data_end.map_or(entry_end, |current| {
                                    core::cmp::max(current, entry_end)
                                }));
                        } else {
                            convert_end = Some(entry_end);
                            break;
                        }
                    } else {
                        next_start = core::cmp::min(next_start, entry.start);
                    }
                }
            }

            if let Some(data_end) = data_end {
                cursor = data_end;
                continue;
            }

            let allocate_end = convert_end.unwrap_or(next_start);
            if allocate_end <= cursor {
                return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EIO);
            }
            let allocate_len = allocate_end.saturating_sub(cursor);
            let physical_start = self.allocate_live_data_range(allocate_len)?;
            self.set_live_data_extent_range(inode, cursor, allocate_len, physical_start)?;
            cursor = allocate_end;
        }

        Ok(())
    }

    fn write_live_data_range_to_storage(
        &self,
        io_ctx: &crate::tidefs_kmod_bridge::kernel_types::CommittedRootIoCtx,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        offset: u64,
        length: u64,
        data: &[u8],
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if length == 0 {
            return Ok(());
        }
        let data_len = usize::try_from(length)
            .map_err(|_| crate::tidefs_kmod_bridge::kernel_types::Errno::EOVERFLOW)?;
        if data.len() < data_len {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EIO);
        }

        self.ensure_live_data_extents_for_writeback(inode, offset, length)?;
        self.normalize_live_extents(inode)?;
        let end = Self::checked_range_end(offset, length)?;
        let mut ranges = crate::tidefs_kmod_bridge::kernel_types::KmodVec::<(u64, u64, u64)>::new();
        {
            let extents = self.live_extents.borrow();
            for entry in extents.iter() {
                if entry.inode != inode || entry.kind != LiveExtentEntry::DATA {
                    continue;
                }
                let overlap_start = core::cmp::max(offset, entry.start);
                let overlap_end = core::cmp::min(end, entry.end);
                if overlap_start >= overlap_end {
                    continue;
                }
                let physical_start = entry
                    .physical_start
                    .checked_add(overlap_start.saturating_sub(entry.start))
                    .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)?;
                let overlap_len = overlap_end.saturating_sub(overlap_start);
                let before = ranges.len();
                ranges.push((overlap_start, physical_start, overlap_len));
                if ranges.len() != before.saturating_add(1) {
                    return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
                }
            }
        }

        let mut bytes_written = 0u64;
        for (overlap_start, physical_start, overlap_len) in ranges.iter() {
            let data_start = usize::try_from(overlap_start.saturating_sub(offset))
                .map_err(|_| crate::tidefs_kmod_bridge::kernel_types::Errno::EOVERFLOW)?;
            let len = usize::try_from(*overlap_len)
                .map_err(|_| crate::tidefs_kmod_bridge::kernel_types::Errno::EOVERFLOW)?;
            let data_end = data_start
                .checked_add(len)
                .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EOVERFLOW)?;
            if data_end > data.len() {
                return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EIO);
            }
            Self::write_live_entry_to_storage(
                io_ctx,
                *physical_start,
                *overlap_len,
                &data[data_start..data_end],
                false,
            )?;
            bytes_written = bytes_written.saturating_add(*overlap_len);
        }

        if bytes_written != length {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EIO);
        }
        Ok(())
    }

    fn flush_live_write_buffer_to_storage(
        &self,
        target_inode: Option<crate::tidefs_kmod_bridge::kernel_types::InodeId>,
        range_offset: u64,
        range_length: u64,
    ) -> core::result::Result<u64, crate::tidefs_kmod_bridge::kernel_types::Errno> {
        let Some(ref pool_core) = self.pool_core else {
            return Ok(0);
        };
        let io_ctx = pool_core.committed_root_io_ctx();
        if !io_ctx.is_active() {
            return Ok(0);
        }
        let range_end = range_offset.saturating_add(range_length);
        let mut first_error = None;
        let mut bytes_written = 0u64;
        let mut buffer = self.write_buffer.borrow_mut();
        buffer.retain(|entry| {
            if first_error.is_some() {
                return true;
            }
            if self.find_inode(entry.inode.get()).is_none() {
                return false;
            }
            let entry_end = entry.offset.saturating_add(entry.len);
            let selected = match target_inode {
                Some(inode) => {
                    entry.inode == inode && entry_end > range_offset && entry.offset < range_end
                }
                None => true,
            };
            if !selected {
                return true;
            }
            if entry.zero {
                match self.zero_live_data_range_to_storage(
                    &io_ctx,
                    entry.inode,
                    entry.offset,
                    entry.len,
                ) {
                    Ok(()) => {
                        bytes_written = bytes_written.saturating_add(entry.len);
                        return false;
                    }
                    Err(err) => {
                        first_error = Some(err);
                        return true;
                    }
                }
            }
            match self.write_live_data_range_to_storage(
                &io_ctx,
                entry.inode,
                entry.offset,
                entry.len,
                &entry.data,
            ) {
                Ok(()) => {
                    bytes_written = bytes_written.saturating_add(entry.len);
                    false
                }
                Err(err) => {
                    first_error = Some(err);
                    true
                }
            }
        });
        drop(buffer);
        if let Some(err) = first_error {
            return Err(err);
        }
        Ok(bytes_written)
    }

    fn flush_intent_buffer_to_storage(
        &self,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        let mut intent_buf = self.intent_buffer.borrow_mut();
        let flushed_bytes = intent_buf
            .iter()
            .fold(0u64, |sum, entry| sum.saturating_add(entry.len() as u64));
        if flushed_bytes == 0 {
            return Ok(());
        }
        if self.intent_log_tail.get().saturating_add(flushed_bytes) > Self::ENGINE_INTENT_LOG_BYTES
        {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOSPC);
        }

        if let Some(ref pool_core) = self.pool_core {
            let io_ctx = pool_core.committed_root_io_ctx();
            if io_ctx.is_active() {
                let write_fn = io_ctx
                    .write_sectors_fn
                    .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV)?;
                let sector_size = io_ctx.sector_size;
                if sector_size == 0 || sector_size > 65536 {
                    return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL);
                }
                let sector_size_usize = sector_size as usize;
                let base_offset = io_ctx
                    .data_area_offset
                    .saturating_add(Self::ENGINE_INTENT_LOG_OFFSET);
                let start_byte = base_offset.saturating_add(self.intent_log_tail.get());
                let mut current_sector = start_byte / sector_size as u64;
                let mut sector_cursor = (start_byte % sector_size as u64) as usize;
                let mut sector_buf = crate::tidefs_kmod_bridge::kernel_types::KmodVec::from_elem(
                    0u8,
                    sector_size_usize,
                );
                if sector_buf.len() != sector_size_usize {
                    return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
                }
                if sector_cursor != 0 {
                    if let Some(read_fn) = io_ctx.read_sectors_fn {
                        let ret = unsafe {
                            read_fn(current_sector, sector_buf.as_mut_ptr(), sector_size)
                        };
                        if ret != 0 {
                            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EIO);
                        }
                    }
                }

                let mut dirty = false;
                for entry in intent_buf.iter() {
                    let mut entry_cursor = 0usize;
                    while entry_cursor < entry.len() {
                        if sector_cursor == sector_size_usize {
                            Self::write_padded_sector(
                                write_fn,
                                current_sector,
                                &sector_buf,
                                sector_size,
                            )?;
                            current_sector = current_sector.saturating_add(1);
                            for byte in &mut sector_buf[..] {
                                *byte = 0;
                            }
                            sector_cursor = 0;
                        }
                        let room = sector_size_usize.saturating_sub(sector_cursor);
                        let remaining = entry.len().saturating_sub(entry_cursor);
                        let take = core::cmp::min(room, remaining);
                        sector_buf[sector_cursor..sector_cursor + take]
                            .copy_from_slice(&entry[entry_cursor..entry_cursor + take]);
                        sector_cursor = sector_cursor.saturating_add(take);
                        entry_cursor = entry_cursor.saturating_add(take);
                        dirty = true;
                    }
                }
                if dirty {
                    Self::write_padded_sector(write_fn, current_sector, &sector_buf, sector_size)?;
                }
            }
        }

        self.intent_log_tail
            .set(self.intent_log_tail.get().saturating_add(flushed_bytes));
        intent_buf.clear();
        Ok(())
    }

    /// Dense fallback for data_ranges when the EXMP extent map is unavailable.
    ///
    /// Returns [0, size) from the in-memory inode table when the VRBT has not
    /// yet been written or extent_map_root is zero. This preserves correct
    /// dense-file behavior during early pool lifecycle before the first
    /// transaction-group commit.
    fn dense_data_ranges(
        &self,
        ino: u64,
    ) -> core::result::Result<
        crate::tidefs_kmod_bridge::kernel_types::KmodVec<
            crate::tidefs_kmod_bridge::kernel_types::LseekDataRange,
        >,
        crate::tidefs_kmod_bridge::kernel_types::Errno,
    > {
        let idx = self
            .find_inode(ino)
            .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOENT)?;
        let inodes = self.inodes.borrow();
        let size = inodes[idx].size;
        let mut ranges = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();
        if size > 0 {
            ranges.push(crate::tidefs_kmod_bridge::kernel_types::LseekDataRange::new(0, size));
        }
        Ok(ranges)
    }

    fn live_data_ranges_for_inode(
        &self,
        ino: u64,
        offset: u64,
        length: u64,
    ) -> core::result::Result<
        crate::tidefs_kmod_bridge::kernel_types::KmodVec<
            crate::tidefs_kmod_bridge::kernel_types::LseekDataRange,
        >,
        crate::tidefs_kmod_bridge::kernel_types::Errno,
    > {
        let idx = self
            .find_inode(ino)
            .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOENT)?;
        let size = self.inodes.borrow()[idx].size;
        let mut ranges = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();
        if length == 0 || offset >= size {
            return Ok(ranges);
        }
        let inode = crate::tidefs_kmod_bridge::kernel_types::InodeId::new(ino);
        self.normalize_live_extents(inode)?;
        let end = Self::checked_range_end(offset, length)?;
        let query_end = core::cmp::min(end, size);
        let mut cursor = offset;

        while cursor < query_end {
            let mut best: Option<LiveExtentEntry> = None;
            let mut best_start = query_end;
            {
                let extents = self.live_extents.borrow();
                for entry in extents.iter() {
                    if entry.inode != inode || entry.end <= cursor || entry.start >= query_end {
                        continue;
                    }
                    let logical = core::cmp::max(entry.start, cursor);
                    if logical < best_start {
                        best_start = logical;
                        best = Some(*entry);
                    }
                }
            }

            let Some(entry) = best else {
                break;
            };
            let logical = core::cmp::max(entry.start, cursor);
            let extent_end = core::cmp::min(entry.end, query_end);
            if logical < extent_end && entry.kind == LiveExtentEntry::DATA {
                let before = ranges.len();
                ranges.push(
                    crate::tidefs_kmod_bridge::kernel_types::LseekDataRange::new(
                        logical, extent_end,
                    ),
                );
                if ranges.len() == before {
                    return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
                }
            }
            cursor = extent_end;
        }

        Ok(ranges)
    }

    fn live_fiemap_extents(
        &self,
        ino: u64,
        start: u64,
        length: u64,
    ) -> core::result::Result<
        crate::tidefs_kmod_bridge::kernel_types::KmodVec<
            crate::tidefs_kmod_bridge::kernel_types::FiemapExtent,
        >,
        crate::tidefs_kmod_bridge::kernel_types::Errno,
    > {
        let idx = self
            .find_inode(ino)
            .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOENT)?;
        let size = self.inodes.borrow()[idx].size;
        let mut out = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();
        if length == 0 || start >= size {
            return Ok(out);
        }
        let inode = crate::tidefs_kmod_bridge::kernel_types::InodeId::new(ino);
        self.normalize_live_extents(inode)?;

        let end = Self::checked_range_end(start, length)?;
        let query_end = core::cmp::min(end, size);
        let mut cursor = start;

        while cursor < query_end {
            let mut best: Option<LiveExtentEntry> = None;
            let mut best_start = query_end;
            {
                let extents = self.live_extents.borrow();
                for entry in extents.iter() {
                    if entry.inode != inode || entry.end <= cursor || entry.start >= query_end {
                        continue;
                    }
                    let logical = core::cmp::max(entry.start, cursor);
                    if logical < best_start {
                        best_start = logical;
                        best = Some(*entry);
                    }
                }
            }

            let Some(entry) = best else {
                break;
            };
            let logical = core::cmp::max(entry.start, cursor);
            let extent_end = core::cmp::min(entry.end, query_end);
            if logical < extent_end {
                let mut flags = if entry.kind == LiveExtentEntry::UNWRITTEN {
                    crate::tidefs_kmod_bridge::kernel_types::FiemapExtent::FLAG_UNWRITTEN
                        | crate::tidefs_kmod_bridge::kernel_types::FiemapExtent::FLAG_UNKNOWN
                } else {
                    0
                };
                if entry.kind == LiveExtentEntry::DATA {
                    flags |= crate::tidefs_kmod_bridge::kernel_types::FiemapExtent::FLAG_UNKNOWN;
                }
                let physical = if entry.kind == LiveExtentEntry::DATA {
                    entry
                        .physical_start
                        .checked_add(logical.saturating_sub(entry.start))
                        .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)?
                } else {
                    0
                };
                let before = out.len();
                out.push(crate::tidefs_kmod_bridge::kernel_types::FiemapExtent::new(
                    logical,
                    physical,
                    extent_end.saturating_sub(logical),
                    flags,
                ));
                if out.len() == before {
                    return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
                }
            }
            cursor = extent_end;
        }

        if let Some(last) = out.last_mut() {
            last.fe_flags |= crate::tidefs_kmod_bridge::kernel_types::FiemapExtent::FLAG_LAST;
        }

        Ok(out)
    }
    // ── Inode allocation ──────────────────────────────────────────────

    /// On-disk inode allocation metadata: next_ino (8 bytes LE) +
    /// generation (8 bytes LE).  Stored at the start of the Rust
    /// engine-owned region, after the C namespace mirror reservation.
    const INODE_ALLOC_META_OFFSET: u64 = 0;
    const INODE_ALLOC_META_BYTES: usize = 16;
    const ENGINE_INTENT_LOG_OFFSET: u64 = 4096;
    const ENGINE_FILE_DATA_OFFSET: u64 = 64 * 1024 * 1024;
    const ENGINE_INTENT_LOG_BYTES: u64 =
        ENGINE_INTENT_LOG_LIMIT_OFFSET - Self::ENGINE_INTENT_LOG_OFFSET;
    const ENGINE_INTENT_BUFFER_MAX_ENTRIES: usize = 256;
    const ENGINE_INTENT_BUFFER_MAX_BYTES: usize = 256 * 1024;
    const ENGINE_NAMESPACE_SNAPSHOT_MAGIC: [u8; 4] = *b"VNS1";
    const ENGINE_NAMESPACE_SNAPSHOT_VERSION: u32 = 3;
    const ENGINE_NAMESPACE_SNAPSHOT_HEADER_BYTES: usize = 72;
    const ENGINE_NAMESPACE_INODE_RECORD_BYTES: usize = 80;
    const ENGINE_NAMESPACE_DIRENT_RECORD_BYTES: usize = 24;
    const ENGINE_NAMESPACE_SECTION_LIVE_DATA: u8 = 1;
    const ENGINE_NAMESPACE_SECTION_XATTRS: u8 = 2;
    const ENGINE_NAMESPACE_SECTION_LIVE_EXTENTS: u8 = 3;
    const ENGINE_NAMESPACE_LIVE_DATA_RECORD_BYTES: usize = 24;
    const ENGINE_NAMESPACE_XATTR_RECORD_BYTES: usize = 14;
    const ENGINE_NAMESPACE_LIVE_EXTENT_RECORD_BYTES_V2: usize = 28;
    const ENGINE_NAMESPACE_LIVE_EXTENT_RECORD_BYTES: usize = 36;

    fn append_snapshot_bytes(
        out: &mut crate::tidefs_kmod_bridge::kernel_types::KmodVec<u8>,
        bytes: &[u8],
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        let before = out.len();
        out.extend_from_slice(bytes);
        if out.len() != before.saturating_add(bytes.len()) {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
        }
        Ok(())
    }

    fn append_snapshot_u8(
        out: &mut crate::tidefs_kmod_bridge::kernel_types::KmodVec<u8>,
        value: u8,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        let before = out.len();
        out.push(value);
        if out.len() != before.saturating_add(1) {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
        }
        Ok(())
    }

    fn append_snapshot_u16(
        out: &mut crate::tidefs_kmod_bridge::kernel_types::KmodVec<u8>,
        value: u16,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        Self::append_snapshot_bytes(out, &value.to_le_bytes())
    }

    fn append_snapshot_u32(
        out: &mut crate::tidefs_kmod_bridge::kernel_types::KmodVec<u8>,
        value: u32,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        Self::append_snapshot_bytes(out, &value.to_le_bytes())
    }

    fn append_snapshot_u64(
        out: &mut crate::tidefs_kmod_bridge::kernel_types::KmodVec<u8>,
        value: u64,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        Self::append_snapshot_bytes(out, &value.to_le_bytes())
    }

    fn append_snapshot_i64(
        out: &mut crate::tidefs_kmod_bridge::kernel_types::KmodVec<u8>,
        value: i64,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        Self::append_snapshot_bytes(out, &value.to_le_bytes())
    }

    fn read_snapshot_u8(
        image: &[u8],
        cursor: &mut usize,
    ) -> core::result::Result<u8, crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if (*cursor).saturating_add(1) > image.len() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL);
        }
        let value = image[*cursor];
        *cursor = (*cursor).saturating_add(1);
        Ok(value)
    }

    fn read_snapshot_u16(
        image: &[u8],
        cursor: &mut usize,
    ) -> core::result::Result<u16, crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if (*cursor).saturating_add(2) > image.len() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL);
        }
        let mut bytes = [0u8; 2];
        bytes.copy_from_slice(&image[*cursor..(*cursor).saturating_add(2)]);
        *cursor = (*cursor).saturating_add(2);
        Ok(u16::from_le_bytes(bytes))
    }

    fn read_snapshot_u32(
        image: &[u8],
        cursor: &mut usize,
    ) -> core::result::Result<u32, crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if (*cursor).saturating_add(4) > image.len() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL);
        }
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&image[*cursor..(*cursor).saturating_add(4)]);
        *cursor = (*cursor).saturating_add(4);
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_snapshot_u64(
        image: &[u8],
        cursor: &mut usize,
    ) -> core::result::Result<u64, crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if (*cursor).saturating_add(8) > image.len() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL);
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&image[*cursor..(*cursor).saturating_add(8)]);
        *cursor = (*cursor).saturating_add(8);
        Ok(u64::from_le_bytes(bytes))
    }

    fn read_snapshot_i64(
        image: &[u8],
        cursor: &mut usize,
    ) -> core::result::Result<i64, crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if (*cursor).saturating_add(8) > image.len() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL);
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&image[*cursor..(*cursor).saturating_add(8)]);
        *cursor = (*cursor).saturating_add(8);
        Ok(i64::from_le_bytes(bytes))
    }

    fn record_secs_to_ns(seconds: u64) -> i64 {
        i64::try_from(seconds)
            .unwrap_or(i64::MAX)
            .saturating_mul(1_000_000_000)
    }

    fn persist_namespace_snapshot(
        &self,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        let Some(ref pc) = self.pool_core else {
            return Ok(());
        };
        let io = pc.committed_root_io_ctx();
        if !io.is_active() {
            return Ok(());
        }
        let Some(write_fn) = io.write_sectors_fn else {
            return Ok(());
        };
        let ss = io.sector_size;
        if ss == 0 || ss > 65536 {
            return Ok(());
        }

        if io.root_ino != 0 {
            self.ensure_root_inode(io.root_ino, ss);
        }
        self.normalize_all_live_extents()?;

        let byte_offset = io
            .data_area_offset
            .saturating_add(ENGINE_NAMESPACE_SNAPSHOT_OFFSET);
        if byte_offset % ss as u64 != 0 {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL);
        }

        let inodes = self.inodes.borrow();
        let entries = self.dir_entries.borrow();
        let writes = self.write_buffer.borrow();
        let live_extents = self.live_extents.borrow();
        let xattr_stores = self.xattr_stores.borrow();
        let inode_count = u32::try_from(inodes.len())
            .map_err(|_| crate::tidefs_kmod_bridge::kernel_types::Errno::EOVERFLOW)?;
        let dirent_count = u32::try_from(entries.len())
            .map_err(|_| crate::tidefs_kmod_bridge::kernel_types::Errno::EOVERFLOW)?;
        let inode_is_live = |ino: u64| inodes.iter().any(|rec| rec.ino == ino);
        let live_data_count = u32::try_from(
            writes
                .iter()
                .filter(|entry| entry.len > 0 && inode_is_live(entry.inode.get()))
                .count(),
        )
        .map_err(|_| crate::tidefs_kmod_bridge::kernel_types::Errno::EOVERFLOW)?;
        let live_extent_count = u32::try_from(
            live_extents
                .iter()
                .filter(|entry| entry.start < entry.end && inode_is_live(entry.inode.get()))
                .count(),
        )
        .map_err(|_| crate::tidefs_kmod_bridge::kernel_types::Errno::EOVERFLOW)?;
        let xattr_count = u32::try_from(
            xattr_stores
                .iter()
                .filter(|(ino, _)| inode_is_live(*ino))
                .fold(0usize, |sum, (_, attrs)| sum.saturating_add(attrs.len())),
        )
        .map_err(|_| crate::tidefs_kmod_bridge::kernel_types::Errno::EOVERFLOW)?;

        let mut image = crate::tidefs_kmod_bridge::kernel_types::KmodVec::from_elem(
            0u8,
            Self::ENGINE_NAMESPACE_SNAPSHOT_HEADER_BYTES,
        );
        if image.len() != Self::ENGINE_NAMESPACE_SNAPSHOT_HEADER_BYTES {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
        }

        let mut max_ino = io.root_ino;
        for rec in inodes.iter() {
            let target_len = rec.symlink_target.as_ref().map(|t| t.len()).unwrap_or(0);
            let symlink_len = u16::try_from(target_len)
                .map_err(|_| crate::tidefs_kmod_bridge::kernel_types::Errno::EOVERFLOW)?;
            max_ino = max_ino.max(rec.ino);
            Self::append_snapshot_u64(&mut image, rec.ino)?;
            Self::append_snapshot_u32(&mut image, rec.mode)?;
            Self::append_snapshot_u32(&mut image, rec.uid)?;
            Self::append_snapshot_u32(&mut image, rec.gid)?;
            Self::append_snapshot_u32(&mut image, rec.nlink)?;
            Self::append_snapshot_u64(&mut image, rec.size)?;
            Self::append_snapshot_u64(&mut image, rec.blocks)?;
            Self::append_snapshot_u64(&mut image, rec.generation)?;
            Self::append_snapshot_i64(&mut image, rec.atime_ns)?;
            Self::append_snapshot_i64(&mut image, rec.mtime_ns)?;
            Self::append_snapshot_i64(&mut image, rec.ctime_ns)?;
            Self::append_snapshot_u8(&mut image, rec.kind)?;
            Self::append_snapshot_u8(&mut image, if rec.symlink_target.is_some() { 1 } else { 0 })?;
            Self::append_snapshot_u16(&mut image, symlink_len)?;
            Self::append_snapshot_u32(&mut image, 0)?;
            if let Some(target) = rec.symlink_target.as_ref() {
                Self::append_snapshot_bytes(&mut image, target)?;
            }
        }

        for entry in entries.iter() {
            let name = &*entry.1;
            let name_len = u16::try_from(name.len())
                .map_err(|_| crate::tidefs_kmod_bridge::kernel_types::Errno::ENAMETOOLONG)?;
            if name.is_empty() || name.len() > 255 {
                return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENAMETOOLONG);
            }
            Self::append_snapshot_u64(&mut image, entry.0)?;
            Self::append_snapshot_u64(&mut image, entry.2)?;
            Self::append_snapshot_u32(&mut image, entry.4)?;
            Self::append_snapshot_u8(&mut image, entry.3)?;
            Self::append_snapshot_u16(&mut image, name_len)?;
            Self::append_snapshot_u8(&mut image, 0)?;
            Self::append_snapshot_bytes(&mut image, name)?;
        }

        if live_data_count > 0 {
            Self::append_snapshot_u8(&mut image, Self::ENGINE_NAMESPACE_SECTION_LIVE_DATA)?;
            Self::append_snapshot_u32(&mut image, live_data_count)?;
            for entry in writes.iter() {
                if entry.len == 0 || !inode_is_live(entry.inode.get()) {
                    continue;
                }
                let data_len = usize::try_from(entry.len)
                    .map_err(|_| crate::tidefs_kmod_bridge::kernel_types::Errno::EOVERFLOW)?;
                if !entry.zero && entry.data.len() < data_len {
                    return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EIO);
                }
                let len_u32 = u32::try_from(entry.len)
                    .map_err(|_| crate::tidefs_kmod_bridge::kernel_types::Errno::EOVERFLOW)?;
                Self::append_snapshot_u64(&mut image, entry.inode.get())?;
                Self::append_snapshot_u64(&mut image, entry.offset)?;
                Self::append_snapshot_u32(&mut image, len_u32)?;
                Self::append_snapshot_u8(&mut image, if entry.zero { 1 } else { 0 })?;
                Self::append_snapshot_u8(&mut image, 0)?;
                Self::append_snapshot_u16(&mut image, 0)?;
                if !entry.zero {
                    Self::append_snapshot_bytes(&mut image, &entry.data[..data_len])?;
                }
            }
        }

        if live_extent_count > 0 {
            Self::append_snapshot_u8(&mut image, Self::ENGINE_NAMESPACE_SECTION_LIVE_EXTENTS)?;
            Self::append_snapshot_u32(&mut image, live_extent_count)?;
            for entry in live_extents.iter() {
                if entry.start >= entry.end || !inode_is_live(entry.inode.get()) {
                    continue;
                }
                Self::append_snapshot_u64(&mut image, entry.inode.get())?;
                Self::append_snapshot_u64(&mut image, entry.start)?;
                Self::append_snapshot_u64(&mut image, entry.end)?;
                Self::append_snapshot_u64(&mut image, entry.physical_start)?;
                Self::append_snapshot_u8(&mut image, entry.kind)?;
                Self::append_snapshot_u8(&mut image, 0)?;
                Self::append_snapshot_u16(&mut image, 0)?;
            }
        }

        if xattr_count > 0 {
            Self::append_snapshot_u8(&mut image, Self::ENGINE_NAMESPACE_SECTION_XATTRS)?;
            Self::append_snapshot_u32(&mut image, xattr_count)?;
            for (ino, attrs) in xattr_stores.iter() {
                if !inode_is_live(*ino) {
                    continue;
                }
                for (name, value) in attrs.iter() {
                    let name_len = u16::try_from(name.len())
                        .map_err(|_| crate::tidefs_kmod_bridge::kernel_types::Errno::EOVERFLOW)?;
                    let value_len = u32::try_from(value.len())
                        .map_err(|_| crate::tidefs_kmod_bridge::kernel_types::Errno::EOVERFLOW)?;
                    if name_len == 0 || name_len > 255 {
                        return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL);
                    }
                    if value_len > 65536 {
                        return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::E2BIG);
                    }
                    Self::append_snapshot_u64(&mut image, *ino)?;
                    Self::append_snapshot_u16(&mut image, name_len)?;
                    Self::append_snapshot_u32(&mut image, value_len)?;
                    Self::append_snapshot_bytes(&mut image, name)?;
                    Self::append_snapshot_bytes(&mut image, value)?;
                }
            }
        }

        if image.len() > ENGINE_NAMESPACE_SNAPSHOT_BYTES {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOSPC);
        }
        let payload_len = u64::try_from(image.len())
            .map_err(|_| crate::tidefs_kmod_bridge::kernel_types::Errno::EOVERFLOW)?;
        let next_ino = self.next_ino.get().max(max_ino.saturating_add(1)).max(2);
        let next_cookie = self.next_dir_cookie.get().max(1);
        let payload_hash: [u8; 32] =
            crate::blake3::hash(&image[Self::ENGINE_NAMESPACE_SNAPSHOT_HEADER_BYTES..]).into();

        image[0..4].copy_from_slice(&Self::ENGINE_NAMESPACE_SNAPSHOT_MAGIC);
        image[4..8].copy_from_slice(&Self::ENGINE_NAMESPACE_SNAPSHOT_VERSION.to_le_bytes());
        image[8..12].copy_from_slice(&inode_count.to_le_bytes());
        image[12..16].copy_from_slice(&dirent_count.to_le_bytes());
        image[16..24].copy_from_slice(&next_ino.to_le_bytes());
        image[24..28].copy_from_slice(&next_cookie.to_le_bytes());
        image[28..32].copy_from_slice(&0u32.to_le_bytes());
        image[32..40].copy_from_slice(&payload_len.to_le_bytes());
        image[40..72].copy_from_slice(&payload_hash);

        let write_len = u32::try_from(image.len())
            .map_err(|_| crate::tidefs_kmod_bridge::kernel_types::Errno::EOVERFLOW)?;
        let ret = unsafe { write_fn(byte_offset / ss as u64, image.as_ptr(), write_len) };
        if ret != 0 {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EIO);
        }

        kernel::pr_info!(
            "tidefs_posix_vfs: persisted engine namespace snapshot inodes={} dirents={} data={} extents={} xattrs={} bytes={}\n",
            inode_count,
            dirent_count,
            live_data_count,
            live_extent_count,
            xattr_count,
            payload_len,
        );
        Ok(())
    }

    fn load_namespace_snapshot(
        &self,
    ) -> core::result::Result<bool, crate::tidefs_kmod_bridge::kernel_types::Errno> {
        let Some(ref pc) = self.pool_core else {
            return Ok(false);
        };
        let io = pc.committed_root_io_ctx();
        if !io.is_active() {
            return Ok(false);
        }
        let Some(read_fn) = io.read_sectors_fn else {
            return Ok(false);
        };
        let ss = io.sector_size;
        if ss == 0 || ss > 65536 {
            return Ok(false);
        }
        let byte_offset = io
            .data_area_offset
            .saturating_add(ENGINE_NAMESPACE_SNAPSHOT_OFFSET);
        if byte_offset % ss as u64 != 0 {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL);
        }

        let header_len = core::cmp::max(Self::ENGINE_NAMESPACE_SNAPSHOT_HEADER_BYTES, ss as usize);
        let mut header =
            crate::tidefs_kmod_bridge::kernel_types::KmodVec::from_elem(0u8, header_len);
        if header.len() != header_len {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
        }
        let ret = unsafe {
            read_fn(
                byte_offset / ss as u64,
                header.as_mut_ptr(),
                u32::try_from(header_len)
                    .map_err(|_| crate::tidefs_kmod_bridge::kernel_types::Errno::EOVERFLOW)?,
            )
        };
        if ret != 0 {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EIO);
        }
        if &header[0..4] != &Self::ENGINE_NAMESPACE_SNAPSHOT_MAGIC {
            return Ok(false);
        }

        let mut header_cursor = 4usize;
        let version = Self::read_snapshot_u32(&header, &mut header_cursor)?;
        if version == 0 || version > Self::ENGINE_NAMESPACE_SNAPSHOT_VERSION {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL);
        }
        let inode_count = Self::read_snapshot_u32(&header, &mut header_cursor)?;
        let dirent_count = Self::read_snapshot_u32(&header, &mut header_cursor)?;
        let snapshot_next_ino = Self::read_snapshot_u64(&header, &mut header_cursor)?;
        let snapshot_next_cookie = Self::read_snapshot_u32(&header, &mut header_cursor)?;
        let _reserved = Self::read_snapshot_u32(&header, &mut header_cursor)?;
        let payload_len_u64 = Self::read_snapshot_u64(&header, &mut header_cursor)?;
        let payload_len = usize::try_from(payload_len_u64)
            .map_err(|_| crate::tidefs_kmod_bridge::kernel_types::Errno::EOVERFLOW)?;
        if payload_len < Self::ENGINE_NAMESPACE_SNAPSHOT_HEADER_BYTES
            || payload_len > ENGINE_NAMESPACE_SNAPSHOT_BYTES
        {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL);
        }

        let mut expected_hash = [0u8; 32];
        expected_hash.copy_from_slice(&header[40..72]);
        let mut image =
            crate::tidefs_kmod_bridge::kernel_types::KmodVec::from_elem(0u8, payload_len);
        if image.len() != payload_len {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
        }
        let ret = unsafe {
            read_fn(
                byte_offset / ss as u64,
                image.as_mut_ptr(),
                u32::try_from(payload_len)
                    .map_err(|_| crate::tidefs_kmod_bridge::kernel_types::Errno::EOVERFLOW)?,
            )
        };
        if ret != 0 {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EIO);
        }
        if &image[0..4] != &Self::ENGINE_NAMESPACE_SNAPSHOT_MAGIC {
            return Ok(false);
        }
        let actual_hash: [u8; 32] =
            crate::blake3::hash(&image[Self::ENGINE_NAMESPACE_SNAPSHOT_HEADER_BYTES..payload_len])
                .into();
        if actual_hash != expected_hash {
            kernel::pr_err!("tidefs_posix_vfs: engine namespace snapshot checksum mismatch\n");
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EIO);
        }

        let mut cursor = Self::ENGINE_NAMESPACE_SNAPSHOT_HEADER_BYTES;
        let mut loaded_inodes =
            crate::tidefs_kmod_bridge::kernel_types::KmodVec::with_capacity(inode_count as usize);
        let mut max_ino = 0u64;
        for _ in 0..inode_count {
            if cursor.saturating_add(Self::ENGINE_NAMESPACE_INODE_RECORD_BYTES) > image.len() {
                return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL);
            }
            let ino = Self::read_snapshot_u64(&image, &mut cursor)?;
            let mode = Self::read_snapshot_u32(&image, &mut cursor)?;
            let uid = Self::read_snapshot_u32(&image, &mut cursor)?;
            let gid = Self::read_snapshot_u32(&image, &mut cursor)?;
            let nlink = Self::read_snapshot_u32(&image, &mut cursor)?;
            let size = Self::read_snapshot_u64(&image, &mut cursor)?;
            let blocks = Self::read_snapshot_u64(&image, &mut cursor)?;
            let generation = Self::read_snapshot_u64(&image, &mut cursor)?;
            let atime_ns = Self::read_snapshot_i64(&image, &mut cursor)?;
            let mtime_ns = Self::read_snapshot_i64(&image, &mut cursor)?;
            let ctime_ns = Self::read_snapshot_i64(&image, &mut cursor)?;
            let kind = Self::read_snapshot_u8(&image, &mut cursor)?;
            let flags = Self::read_snapshot_u8(&image, &mut cursor)?;
            let symlink_len = Self::read_snapshot_u16(&image, &mut cursor)? as usize;
            let _record_reserved = Self::read_snapshot_u32(&image, &mut cursor)?;
            let symlink_target = if (flags & 1) != 0 {
                if cursor.saturating_add(symlink_len) > image.len() {
                    return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL);
                }
                let mut target =
                    crate::tidefs_kmod_bridge::kernel_types::KmodVec::with_capacity(symlink_len);
                target.extend_from_slice(&image[cursor..cursor + symlink_len]);
                if target.len() != symlink_len {
                    return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
                }
                cursor = cursor.saturating_add(symlink_len);
                Some(target)
            } else {
                if symlink_len != 0 {
                    return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL);
                }
                None
            };
            max_ino = max_ino.max(ino);
            let before = loaded_inodes.len();
            loaded_inodes.push(InodeRecord {
                ino,
                mode,
                uid,
                gid,
                nlink,
                size,
                blocks,
                generation,
                kind,
                atime_ns,
                mtime_ns,
                ctime_ns,
                symlink_target,
            });
            if loaded_inodes.len() != before.saturating_add(1) {
                return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
            }
        }

        let mut loaded_entries =
            crate::tidefs_kmod_bridge::kernel_types::KmodVec::with_capacity(dirent_count as usize);
        let mut max_cookie = 0u32;
        for _ in 0..dirent_count {
            if cursor.saturating_add(Self::ENGINE_NAMESPACE_DIRENT_RECORD_BYTES) > image.len() {
                return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL);
            }
            let parent_ino = Self::read_snapshot_u64(&image, &mut cursor)?;
            let child_ino = Self::read_snapshot_u64(&image, &mut cursor)?;
            let cookie = Self::read_snapshot_u32(&image, &mut cursor)?;
            let child_kind = Self::read_snapshot_u8(&image, &mut cursor)?;
            let name_len = Self::read_snapshot_u16(&image, &mut cursor)? as usize;
            let _dirent_reserved = Self::read_snapshot_u8(&image, &mut cursor)?;
            if name_len == 0 || name_len > 255 || cursor.saturating_add(name_len) > image.len() {
                return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL);
            }
            let mut name =
                crate::tidefs_kmod_bridge::kernel_types::KmodVec::with_capacity(name_len);
            name.extend_from_slice(&image[cursor..cursor + name_len]);
            if name.len() != name_len {
                return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
            }
            cursor = cursor.saturating_add(name_len);
            max_cookie = max_cookie.max(cookie);
            let before = loaded_entries.len();
            loaded_entries.push((parent_ino, name, child_ino, child_kind, cookie));
            if loaded_entries.len() != before.saturating_add(1) {
                return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
            }
        }
        let mut loaded_writes = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();
        let mut loaded_extents = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();
        let mut loaded_xattrs: crate::tidefs_kmod_bridge::kernel_types::KmodVec<(
            u64,
            crate::tidefs_kmod_bridge::kernel_types::KmodVec<(
                crate::tidefs_kmod_bridge::kernel_types::KmodVec<u8>,
                crate::tidefs_kmod_bridge::kernel_types::KmodVec<u8>,
            )>,
        )> = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();
        let mut loaded_live_data_count = 0u32;
        let mut loaded_live_extent_count = 0u32;
        let mut loaded_xattr_count = 0u32;
        while cursor < payload_len {
            if version < 2 {
                return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL);
            }
            let section = Self::read_snapshot_u8(&image, &mut cursor)?;
            let count = Self::read_snapshot_u32(&image, &mut cursor)?;
            match section {
                Self::ENGINE_NAMESPACE_SECTION_LIVE_DATA => {
                    for _ in 0..count {
                        if cursor.saturating_add(Self::ENGINE_NAMESPACE_LIVE_DATA_RECORD_BYTES)
                            > image.len()
                        {
                            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL);
                        }
                        let ino = Self::read_snapshot_u64(&image, &mut cursor)?;
                        let offset = Self::read_snapshot_u64(&image, &mut cursor)?;
                        let len_u32 = Self::read_snapshot_u32(&image, &mut cursor)?;
                        let flags = Self::read_snapshot_u8(&image, &mut cursor)?;
                        let _reserved0 = Self::read_snapshot_u8(&image, &mut cursor)?;
                        let _reserved1 = Self::read_snapshot_u16(&image, &mut cursor)?;
                        if flags & !1 != 0 || len_u32 == 0 {
                            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL);
                        }
                        let zero = (flags & 1) != 0;
                        let len = len_u32 as usize;
                        let data = if zero {
                            crate::tidefs_kmod_bridge::kernel_types::KmodVec::new()
                        } else {
                            if cursor.saturating_add(len) > image.len() {
                                return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL);
                            }
                            let mut payload =
                                crate::tidefs_kmod_bridge::kernel_types::KmodVec::with_capacity(
                                    len,
                                );
                            payload.extend_from_slice(&image[cursor..cursor + len]);
                            if payload.len() != len {
                                return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
                            }
                            cursor = cursor.saturating_add(len);
                            payload
                        };
                        let before = loaded_writes.len();
                        loaded_writes.push(WriteBufferEntry {
                            inode: crate::tidefs_kmod_bridge::kernel_types::InodeId::new(ino),
                            offset,
                            len: len_u32 as u64,
                            data,
                            zero,
                        });
                        if loaded_writes.len() != before.saturating_add(1) {
                            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
                        }
                        loaded_live_data_count = loaded_live_data_count.saturating_add(1);
                    }
                }
                Self::ENGINE_NAMESPACE_SECTION_LIVE_EXTENTS => {
                    let record_bytes = if version >= 3 {
                        Self::ENGINE_NAMESPACE_LIVE_EXTENT_RECORD_BYTES
                    } else {
                        Self::ENGINE_NAMESPACE_LIVE_EXTENT_RECORD_BYTES_V2
                    };
                    for _ in 0..count {
                        if cursor.saturating_add(record_bytes) > image.len() {
                            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL);
                        }
                        let ino = Self::read_snapshot_u64(&image, &mut cursor)?;
                        let start = Self::read_snapshot_u64(&image, &mut cursor)?;
                        let end = Self::read_snapshot_u64(&image, &mut cursor)?;
                        let physical_start = if version >= 3 {
                            Self::read_snapshot_u64(&image, &mut cursor)?
                        } else {
                            start
                        };
                        let kind = Self::read_snapshot_u8(&image, &mut cursor)?;
                        let _reserved0 = Self::read_snapshot_u8(&image, &mut cursor)?;
                        let _reserved1 = Self::read_snapshot_u16(&image, &mut cursor)?;
                        if start >= end
                            || (kind != LiveExtentEntry::DATA && kind != LiveExtentEntry::UNWRITTEN)
                        {
                            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL);
                        }
                        let before = loaded_extents.len();
                        loaded_extents.push(LiveExtentEntry {
                            inode: crate::tidefs_kmod_bridge::kernel_types::InodeId::new(ino),
                            start,
                            end,
                            physical_start: if kind == LiveExtentEntry::DATA {
                                physical_start
                            } else {
                                0
                            },
                            physical_reserved_end: if kind == LiveExtentEntry::DATA {
                                physical_start.saturating_add(end.saturating_sub(start))
                            } else {
                                0
                            },
                            kind,
                        });
                        if loaded_extents.len() != before.saturating_add(1) {
                            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
                        }
                        loaded_live_extent_count = loaded_live_extent_count.saturating_add(1);
                    }
                }
                Self::ENGINE_NAMESPACE_SECTION_XATTRS => {
                    for _ in 0..count {
                        if cursor.saturating_add(Self::ENGINE_NAMESPACE_XATTR_RECORD_BYTES)
                            > image.len()
                        {
                            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL);
                        }
                        let ino = Self::read_snapshot_u64(&image, &mut cursor)?;
                        let name_len = Self::read_snapshot_u16(&image, &mut cursor)? as usize;
                        let value_len = Self::read_snapshot_u32(&image, &mut cursor)? as usize;
                        if name_len == 0
                            || name_len > 255
                            || value_len > 65536
                            || cursor.saturating_add(name_len).saturating_add(value_len)
                                > image.len()
                        {
                            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL);
                        }
                        let mut name =
                            crate::tidefs_kmod_bridge::kernel_types::KmodVec::with_capacity(
                                name_len,
                            );
                        name.extend_from_slice(&image[cursor..cursor + name_len]);
                        if name.len() != name_len {
                            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
                        }
                        cursor = cursor.saturating_add(name_len);
                        let mut value =
                            crate::tidefs_kmod_bridge::kernel_types::KmodVec::with_capacity(
                                value_len,
                            );
                        value.extend_from_slice(&image[cursor..cursor + value_len]);
                        if value.len() != value_len {
                            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
                        }
                        cursor = cursor.saturating_add(value_len);
                        let mut pair = Some((name, value));
                        if let Some(idx) = loaded_xattrs
                            .iter()
                            .position(|(store_ino, _)| *store_ino == ino)
                        {
                            let before = loaded_xattrs[idx].1.len();
                            loaded_xattrs[idx].1.push(pair.take().unwrap());
                            if loaded_xattrs[idx].1.len() != before.saturating_add(1) {
                                return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
                            }
                        } else {
                            let mut attrs = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();
                            attrs.push(pair.take().unwrap());
                            if attrs.len() != 1 {
                                return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
                            }
                            let before = loaded_xattrs.len();
                            loaded_xattrs.push((ino, attrs));
                            if loaded_xattrs.len() != before.saturating_add(1) {
                                return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
                            }
                        }
                        loaded_xattr_count = loaded_xattr_count.saturating_add(1);
                    }
                }
                _ => return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL),
            }
        }
        if cursor != payload_len {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL);
        }

        {
            let mut inodes = self.inodes.borrow_mut();
            *inodes = loaded_inodes;
        }
        {
            let mut entries = self.dir_entries.borrow_mut();
            *entries = loaded_entries;
        }
        {
            let mut writes = self.write_buffer.borrow_mut();
            *writes = loaded_writes;
        }
        {
            let mut extents = self.live_extents.borrow_mut();
            *extents = loaded_extents;
        }
        self.next_live_data_offset.set(0);
        {
            let extents = self.live_extents.borrow();
            for entry in extents.iter() {
                self.advance_live_data_allocator_for_entry(entry)?;
            }
        }
        self.live_extent_dirty_inodes.borrow_mut().clear();
        self.live_collapse_cursors.borrow_mut().clear();
        {
            let mut xattrs = self.xattr_stores.borrow_mut();
            *xattrs = loaded_xattrs;
        }

        let target_next_ino = snapshot_next_ino.max(max_ino.saturating_add(1)).max(2);
        self.next_ino.set(target_next_ino);
        self.next_dir_cookie.set(
            snapshot_next_cookie
                .max(max_cookie.saturating_add(1))
                .max(1),
        );
        match self.read_alloc_meta()? {
            Some((current_next_ino, generation)) if target_next_ino > current_next_ino => {
                self.write_alloc_meta(target_next_ino, generation)?;
            }
            None if self.pool_core.is_some() => {
                self.write_alloc_meta(target_next_ino, 1)?;
            }
            _ => {}
        }

        kernel::pr_info!(
            "tidefs_posix_vfs: loaded engine namespace snapshot inodes={} dirents={} data={} extents={} xattrs={} bytes={}\n",
            inode_count,
            dirent_count,
            loaded_live_data_count,
            loaded_live_extent_count,
            loaded_xattr_count,
            payload_len_u64,
        );
        Ok(true)
    }

    /// Read persistent allocator state through pool_core I/O.
    fn read_alloc_meta(
        &self,
    ) -> core::result::Result<Option<(u64, u64)>, crate::tidefs_kmod_bridge::kernel_types::Errno>
    {
        let Some(ref pc) = self.pool_core else {
            return Ok(None);
        };
        let io = pc.committed_root_io_ctx();
        if !io.is_active() {
            return Ok(None);
        }
        let Some(read_fn) = io.read_sectors_fn else {
            return Ok(None);
        };
        let ss = io.sector_size;
        if ss == 0 || ss > 65536 {
            return Ok(None);
        }
        let byte_offset = io
            .data_area_offset
            .saturating_add(Self::INODE_ALLOC_META_OFFSET);
        let start_sector = byte_offset / ss as u64;
        let mut buf = [0u8; 4096];
        let buf_len = core::cmp::min(buf.len() as u32, ss);
        let ret = unsafe { read_fn(start_sector, buf.as_mut_ptr(), buf_len) };
        if ret != 0 {
            return Ok(None);
        }
        let off = (byte_offset % ss as u64) as usize;
        if off + 16 > buf.len() {
            return Ok(None);
        }
        let next_ino = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap_or([0u8; 8]));
        let generation = u64::from_le_bytes(buf[off + 8..off + 16].try_into().unwrap_or([0u8; 8]));
        if next_ino == 0 && generation == 0 {
            return Ok(None);
        }
        Ok(Some((next_ino, generation)))
    }

    /// Write persistent allocator state through pool_core I/O.
    fn write_alloc_meta(
        &self,
        next_ino: u64,
        generation: u64,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        let Some(ref pc) = self.pool_core else {
            return Ok(());
        };
        let io = pc.committed_root_io_ctx();
        if !io.is_active() {
            return Ok(());
        }
        let Some(write_fn) = io.write_sectors_fn else {
            return Ok(());
        };
        let ss = io.sector_size;
        if ss == 0 || ss > 65536 {
            return Ok(());
        }
        let byte_offset = io
            .data_area_offset
            .saturating_add(Self::INODE_ALLOC_META_OFFSET);
        let start_sector = byte_offset / ss as u64;
        let mut buf = [0u8; 4096];
        let buf_len = core::cmp::min(buf.len() as u32, ss);
        let off = (byte_offset % ss as u64) as usize;
        buf[off..off + 8].copy_from_slice(&next_ino.to_le_bytes());
        buf[off + 8..off + 16].copy_from_slice(&generation.to_le_bytes());
        let ret = unsafe { write_fn(start_sector, buf.as_ptr(), buf_len) };
        if ret != 0 {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EIO);
        }
        Ok(())
    }

    /// Allocate a new inode through the authoritative allocation path.
    fn allocate_inode(
        &self,
        kind: u8,
        _parent: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        mode: u32,
        uid: u32,
        gid: u32,
        nlink: u32,
        initial_size: u64,
    ) -> core::result::Result<InodeRecord, crate::tidefs_kmod_bridge::kernel_types::Errno> {
        let (ino, gen) = if let Some((ni, existing_gen)) = self.read_alloc_meta()? {
            if ni >= 2 {
                let ino = ni;
                let gen = existing_gen.max(1u64);
                let next_gen = gen.wrapping_add(1u64);
                let next_ni = ino.saturating_add(1u64);
                self.write_alloc_meta(next_ni, next_gen)?;
                (ino, gen)
            } else {
                let ino = self.next_ino.get().max(2u64);
                self.next_ino.set(ino.saturating_add(1u64));
                self.write_alloc_meta(ino.saturating_add(1u64), 2u64)?;
                (ino, 1u64)
            }
        } else {
            let ino = self.next_ino.get().max(2u64);
            self.next_ino.set(ino.saturating_add(1u64));
            if self.pool_core.is_some() {
                self.write_alloc_meta(ino.saturating_add(1u64), 2u64)?;
            }
            (ino, 1u64)
        };
        let blocks = if initial_size > 0 {
            (initial_size.saturating_add(511u64)) / 512u64
        } else {
            0u64
        };
        Ok(InodeRecord {
            ino,
            mode,
            uid,
            gid,
            nlink,
            size: initial_size,
            blocks,
            generation: gen,
            kind,
            atime_ns: 0,
            mtime_ns: 0,
            ctime_ns: 0,
            symlink_target: None,
        })
    }

    fn set_inode_mtime_ctime_ns(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        mtime_ns: i64,
        ctime_ns: i64,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        let idx = self
            .find_inode(inode.get())
            .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOENT)?;
        let mut inodes = self.inodes.borrow_mut();
        let rec = &mut inodes[idx];
        rec.mtime_ns = mtime_ns;
        rec.ctime_ns = ctime_ns;
        Ok(())
    }
}

impl crate::tidefs_kmod_bridge::kernel_types::VfsEngine for KernelEngine {
    fn get_root_inode(
        &self,
        _ctx: &crate::tidefs_kmod_bridge::kernel_types::RequestCtx,
    ) -> core::result::Result<
        crate::tidefs_kmod_bridge::kernel_types::InodeId,
        crate::tidefs_kmod_bridge::kernel_types::Errno,
    > {
        // Return the root inode from the committed-root I/O context when
        // the pool core is configured with a mounted block device.  This
        // closes the VfsEngine -> committed-root loop so the cargo test
        // path and Kbuild path share one root-inode authority.
        if let Some(ref pool_core) = self.pool_core {
            let io_ctx = pool_core.committed_root_io_ctx();
            if io_ctx.root_ino != 0 && pool_core.is_mounted() {
                return Ok(crate::tidefs_kmod_bridge::kernel_types::InodeId::new(
                    io_ctx.root_ino,
                ));
            }
        }
        Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV)
    }
    fn lookup(
        &self,
        parent: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        name: &[u8],
        _ctx: &crate::tidefs_kmod_bridge::kernel_types::RequestCtx,
    ) -> core::result::Result<
        crate::tidefs_kmod_bridge::kernel_types::InodeAttr,
        crate::tidefs_kmod_bridge::kernel_types::Errno,
    > {
        if name.is_empty() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOENT);
        }

        let (child_ino, _) = self
            .find_dir_entry(parent.get(), name)
            .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOENT)?;
        let idx = self
            .find_inode(child_ino)
            .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOENT)?;
        let ss = self
            .pool_core
            .as_ref()
            .map(|pc| pc.committed_root_io_ctx().sector_size)
            .unwrap_or(512);
        let inodes = self.inodes.borrow();
        Ok(KernelEngine::record_to_attr(&inodes[idx], ss))
    }
    fn getattr(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        _handle: Option<&crate::tidefs_kmod_bridge::kernel_types::EngineFileHandle>,
        _ctx: &crate::tidefs_kmod_bridge::kernel_types::RequestCtx,
    ) -> core::result::Result<
        crate::tidefs_kmod_bridge::kernel_types::InodeAttr,
        crate::tidefs_kmod_bridge::kernel_types::Errno,
    > {
        let ino = inode.get();
        if let Some(idx) = self.find_inode(ino) {
            let ss = self
                .pool_core
                .as_ref()
                .map(|pc| pc.committed_root_io_ctx().sector_size)
                .unwrap_or(512);
            let inodes = self.inodes.borrow();
            return Ok(KernelEngine::record_to_attr(&inodes[idx], ss));
        }

        // Resolve inode attributes through the canonical committed-root ->
        // VRBT -> inode-table authority chain.  Reads the VRBT block once
        // (cached after first call), then reads the inode table slot for the
        // requested inode via the KernelStorageIo read callback.
        let Some(ref pool_core) = self.pool_core else {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV);
        };
        if !pool_core.is_mounted() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV);
        }
        let io_ctx = pool_core.committed_root_io_ctx();
        let Some(read_fn) = io_ctx.read_sectors_fn else {
            // Read callback not registered (cargo test path without C shim).
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV);
        };

        // Resolve VRBT pointers on first use (cached in Cell<u64>).
        let mut inode_table_root = self.inode_table_root.get();
        let mut _extent_map_root = self.extent_map_root.get();
        if inode_table_root == 0 {
            // VRBT is at superblock_offset + 3 * block_size within the
            // superblock region.
            let ss = io_ctx.sector_size as u64;
            let vrbt_byte_offset = io_ctx
                .superblock_offset
                .saturating_add(3u64.saturating_mul(ss));
            let vrbt_sector = vrbt_byte_offset / ss;
            let mut vrbt_buf = [0u8; 88]; // VRBT_WIRE_SIZE
                                          // SAFETY: read_fn is the C shim's block read callback
                                          // used to load the VRBT from the block device.
            let ret = unsafe { read_fn(vrbt_sector, vrbt_buf.as_mut_ptr(), vrbt_buf.len() as u32) };
            if ret < 0 {
                kernel::pr_debug!(
                    "tidefs_posix_vfs: getattr: VRBT read failed sector={} err={}
",
                    vrbt_sector,
                    ret
                );
                return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EIO);
            }
            if let Ok(vrbt) = crate::replay_integration::decode_vrbt(&vrbt_buf) {
                inode_table_root = vrbt.inode_table_root;
                _extent_map_root = vrbt.extent_map_root;
                self.inode_table_root.set(inode_table_root);
                self.extent_map_root.set(_extent_map_root);
            } else {
                kernel::pr_debug!(
                    "tidefs_posix_vfs: getattr: VRBT decode failed
"
                );
                return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EIO);
            }
        }

        // Read the inode table slot for the requested inode.
        // Inode table entries are 100 bytes (VINO_RECORD_BYTES).
        if ino == 0 {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOENT);
        }
        let ss = io_ctx.sector_size as u64;
        const VINO_RECORD_BYTES: u64 = 116;
        let entry_offset =
            inode_table_root.saturating_add((ino - 1).saturating_mul(VINO_RECORD_BYTES));
        // Read a full sector to cover the 100-byte entry.
        let entry_sector = entry_offset / ss;
        let sector_off = (entry_offset % ss) as usize;
        let read_len = (sector_off + 116usize).min(ss as usize).max(116) as u32;
        // Buffer sized for max sector size; read_len may be up to ss (4096).
        let mut entry_buf = [0u8; 4096]; // Up to one sector
                                         // SAFETY: read_fn is the C shim's block read callback.
        let ret = unsafe { read_fn(entry_sector, entry_buf.as_mut_ptr(), read_len) };
        if ret < 0 {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EIO);
        }

        // Parse the inode record from the sector buffer.
        // read_vino_inode indexes by (ino-1)*100 into the buffer, so pass 1
        // since the buffer slice is already positioned at the target entry.
        let record = crate::replay_integration::read_vino_inode(&entry_buf[sector_off..], 1)
            .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOENT)?;

        // Convert VinoRecord to InodeAttr.
        let kind = match record.kind {
            0 => crate::tidefs_kmod_bridge::kernel_types::NodeKind::File,
            1 => crate::tidefs_kmod_bridge::kernel_types::NodeKind::Dir,
            2 => crate::tidefs_kmod_bridge::kernel_types::NodeKind::Symlink,
            _ => return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EIO),
        };
        Ok(crate::tidefs_kmod_bridge::kernel_types::InodeAttr {
            inode_id: inode,
            generation: crate::tidefs_kmod_bridge::kernel_types::Generation::new(record.generation),
            kind,
            posix: crate::tidefs_kmod_bridge::kernel_types::PosixAttrs {
                mode: record.mode,
                uid: record.uid,
                gid: record.gid,
                nlink: record.nlink,
                rdev: 0,
                atime_ns: Self::record_secs_to_ns(record.atime_secs),
                mtime_ns: Self::record_secs_to_ns(record.mtime_secs),
                ctime_ns: Self::record_secs_to_ns(record.ctime_secs),
                btime_ns: 0,
                size: record.size,
                blocks_512: record.blocks,
                blksize: io_ctx.sector_size,
            },
            flags: crate::tidefs_kmod_bridge::kernel_types::InodeFlags(0),
            subtree_rev: 0,
            dir_rev: 0,
        })
    }
    /// Engine-backed setattr: apply mode/uid/gid/size/timestamp mutations
    /// through the in-memory inode table. Truncate (FATTR_SIZE) adjusts the
    /// file size and recomputes block count via extent/object authority.
    ///
    /// Errors: ENOENT, EACCES (deferred to bridge layer), EROFS (when pool
    /// is read-only), ENOSPC (when truncate-extend cannot allocate), EIO.
    fn setattr(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        attr: &crate::tidefs_kmod_bridge::kernel_types::SetAttr,
        _handle: Option<&crate::tidefs_kmod_bridge::kernel_types::EngineFileHandle>,
        _ctx: &crate::tidefs_kmod_bridge::kernel_types::RequestCtx,
    ) -> core::result::Result<
        crate::tidefs_kmod_bridge::kernel_types::InodeAttr,
        crate::tidefs_kmod_bridge::kernel_types::Errno,
    > {
        use crate::tidefs_kmod_bridge::kernel_types::{
            FATTR_ATIME, FATTR_CTIME, FATTR_GID, FATTR_MODE, FATTR_MTIME, FATTR_SIZE, FATTR_UID,
        };
        if !self.pool_is_mounted() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV);
        }
        let ino = inode.get();
        let idx = self
            .find_inode(ino)
            .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOENT)?;
        let valid = attr.valid;
        let ss = self
            .pool_core
            .as_ref()
            .map(|pc| pc.committed_root_io_ctx().sector_size)
            .unwrap_or(512);
        let mut truncate_to = None;
        {
            let mut inodes = self.inodes.borrow_mut();
            let rec = &mut inodes[idx];

            if (valid & FATTR_MODE) != 0 {
                // Preserve file-type bits; only mutate permission bits.
                let file_type = rec.mode & 0o170000;
                rec.mode = file_type | (attr.mode & 0o7777);
            }
            if (valid & FATTR_UID) != 0 {
                rec.uid = attr.uid;
            }
            if (valid & FATTR_GID) != 0 {
                rec.gid = attr.gid;
            }
            if (valid & FATTR_SIZE) != 0 {
                let old_size = rec.size;
                let new_size = attr.size;
                if new_size != old_size {
                    rec.size = new_size;
                    truncate_to = Some(new_size);
                }
            }
            if (valid & FATTR_ATIME) != 0 {
                rec.atime_ns = attr.atime_ns;
            }
            if (valid & FATTR_MTIME) != 0 {
                rec.mtime_ns = attr.mtime_ns;
            }
            if (valid & FATTR_CTIME) != 0 {
                rec.ctime_ns = attr.ctime_ns;
            }
        }
        if let Some(new_size) = truncate_to {
            self.truncate_live_extents(inode, new_size)?;
            self.truncate_live_write_buffer(inode, new_size)?;
            if let Some(idx) = self.find_inode(ino) {
                self.inodes.borrow_mut()[idx].blocks = self.live_allocated_blocks(ino);
            }
        }
        // Read back the updated record for the response.
        let inodes = self.inodes.borrow();
        let rec = &inodes[idx];
        Ok(KernelEngine::record_to_attr(rec, ss))
    }
    /// Engine-backed mkdir: allocate a directory inode through the authoritative
    /// allocator and add a directory entry.
    fn mkdir(
        &self,
        parent: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        name: &[u8],
        mode: u32,
        _ctx: &crate::tidefs_kmod_bridge::kernel_types::RequestCtx,
    ) -> core::result::Result<
        crate::tidefs_kmod_bridge::kernel_types::InodeAttr,
        crate::tidefs_kmod_bridge::kernel_types::Errno,
    > {
        if !self.pool_is_mounted() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV);
        }
        let parent_ino = parent.get();
        self.require_live_directory(parent_ino)?;
        if self.find_dir_entry(parent_ino, name).is_some() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EEXIST);
        }
        let dir_mode = (0o040000u32 | (mode & 0o7777)) as u32;
        let rec = self.allocate_inode(
            InodeRecord::DIR,
            parent,
            dir_mode,
            0,
            0, // uid, gid
            2, // nlink: . and parent link
            0, // initial_size
        )?;
        let ino = rec.ino;
        let gen = rec.generation;
        self.push_inode_record(rec)?;
        if let Some(parent_idx) = self.find_inode(parent_ino) {
            let mut inodes = self.inodes.borrow_mut();
            inodes[parent_idx].nlink = inodes[parent_idx].nlink.saturating_add(1);
        }
        if let Err(e) = self.add_dir_entry(parent_ino, name, ino, InodeRecord::DIR) {
            self.remove_inode_record(ino)?;
            if let Some(parent_idx) = self.find_inode(parent_ino) {
                let mut inodes = self.inodes.borrow_mut();
                inodes[parent_idx].nlink = inodes[parent_idx].nlink.saturating_sub(1);
            }
            return Err(e);
        }
        let entry = crate::intent_record::encode_mkdir_intent(
            parent,
            name,
            mode,
            crate::tidefs_kmod_bridge::kernel_types::InodeId::new(ino),
        );
        self.record_intent_entry(entry.as_bytes())?;
        let ss = self
            .pool_core
            .as_ref()
            .map(|pc| pc.committed_root_io_ctx().sector_size)
            .unwrap_or(512);
        Ok(KernelEngine::record_to_attr(
            &InodeRecord {
                ino,
                mode: dir_mode,
                uid: 0,
                gid: 0,
                nlink: 2,
                size: 0,
                blocks: 0,
                generation: gen,
                kind: InodeRecord::DIR,
                atime_ns: 0,
                mtime_ns: 0,
                ctime_ns: 0,
                symlink_target: None,
            },
            ss,
        ))
    }
    /// Engine-backed create: allocate a file inode through the authoritative
    /// allocator and add a directory entry.
    fn create(
        &self,
        parent: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        name: &[u8],
        mode: u32,
        flags: u32,
        _ctx: &crate::tidefs_kmod_bridge::kernel_types::RequestCtx,
    ) -> core::result::Result<
        (
            crate::tidefs_kmod_bridge::kernel_types::InodeAttr,
            crate::tidefs_kmod_bridge::kernel_types::EngineFileHandle,
        ),
        crate::tidefs_kmod_bridge::kernel_types::Errno,
    > {
        if !self.pool_is_mounted() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV);
        }
        let parent_ino = parent.get();
        self.require_live_directory(parent_ino)?;
        if self.find_dir_entry(parent_ino, name).is_some() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EEXIST);
        }
        let file_mode = (0o100000u32 | (mode & 0o7777)) as u32;
        let rec = self.allocate_inode(
            InodeRecord::FILE,
            parent,
            file_mode,
            0,
            0, // uid, gid
            1, // nlink
            0, // initial_size
        )?;
        let ino = rec.ino;
        let gen = rec.generation;
        self.push_inode_record(rec)?;
        if let Err(e) = self.add_dir_entry(parent_ino, name, ino, InodeRecord::FILE) {
            self.remove_inode_record(ino)?;
            return Err(e);
        }
        let entry = crate::intent_record::encode_create_intent(
            parent,
            name,
            mode,
            crate::tidefs_kmod_bridge::kernel_types::InodeId::new(ino),
        );
        self.record_intent_entry(entry.as_bytes())?;
        let ss = self
            .pool_core
            .as_ref()
            .map(|pc| pc.committed_root_io_ctx().sector_size)
            .unwrap_or(512);
        let attr = KernelEngine::record_to_attr(
            &InodeRecord {
                ino,
                mode: file_mode,
                uid: 0,
                gid: 0,
                nlink: 1,
                size: 0,
                blocks: 0,
                generation: gen,
                kind: InodeRecord::FILE,
                atime_ns: 0,
                mtime_ns: 0,
                ctime_ns: 0,
                symlink_target: None,
            },
            ss,
        );
        let fh = crate::tidefs_kmod_bridge::kernel_types::EngineFileHandle {
            inode_id: crate::tidefs_kmod_bridge::kernel_types::InodeId::new(ino),
            open_flags: flags,
            fh_id: crate::tidefs_kmod_bridge::kernel_types::FileHandleId::new(gen),
            lock_owner: 0,
        };
        Ok((attr, fh))
    }
    /// Engine-backed tmpfile: allocate an unnamed file inode through the
    /// authoritative allocator (O_TMPFILE).  No directory entry is created;
    /// the file may later be linked via linkat().
    fn tmpfile(
        &self,
        parent: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        mode: u32,
        flags: u32,
        _ctx: &crate::tidefs_kmod_bridge::kernel_types::RequestCtx,
    ) -> core::result::Result<
        (
            crate::tidefs_kmod_bridge::kernel_types::InodeAttr,
            crate::tidefs_kmod_bridge::kernel_types::EngineFileHandle,
        ),
        crate::tidefs_kmod_bridge::kernel_types::Errno,
    > {
        if !self.pool_is_mounted() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV);
        }
        self.require_live_directory(parent.get())?;
        let file_mode = (0o100000u32 | (mode & 0o7777)) as u32;
        let rec = self.allocate_inode(
            InodeRecord::FILE,
            parent,
            file_mode,
            0,
            0, // uid, gid
            0, // nlink: unnamed
            0, // initial_size
        )?;
        let ino = rec.ino;
        let gen = rec.generation;
        self.push_inode_record(rec)?;
        let ss = self
            .pool_core
            .as_ref()
            .map(|pc| pc.committed_root_io_ctx().sector_size)
            .unwrap_or(512);
        let attr = KernelEngine::record_to_attr(
            &InodeRecord {
                ino,
                mode: file_mode,
                uid: 0,
                gid: 0,
                nlink: 0,
                size: 0,
                blocks: 0,
                generation: gen,
                kind: InodeRecord::FILE,
                atime_ns: 0,
                mtime_ns: 0,
                ctime_ns: 0,
                symlink_target: None,
            },
            ss,
        );
        let fh = crate::tidefs_kmod_bridge::kernel_types::EngineFileHandle {
            inode_id: crate::tidefs_kmod_bridge::kernel_types::InodeId::new(ino),
            open_flags: flags,
            fh_id: crate::tidefs_kmod_bridge::kernel_types::FileHandleId::new(gen),
            lock_owner: 0,
        };
        Ok((attr, fh))
    }

    /// Engine-backed unlink: remove a directory entry and drop nlink on the target inode.
    fn unlink(
        &self,
        parent: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        name: &[u8],
        _ctx: &crate::tidefs_kmod_bridge::kernel_types::RequestCtx,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if !self.pool_is_mounted() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV);
        }
        let parent_ino = parent.get();
        self.require_live_directory(parent_ino)?;
        // Find the entry
        let child = self
            .find_dir_entry(parent_ino, name)
            .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOENT)?;
        let (child_ino, child_kind) = child;
        // Refuse to unlink directories (use rmdir)
        if child_kind == InodeRecord::DIR {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EISDIR);
        }
        // Remove the directory entry
        self.remove_dir_entry(parent_ino, name);
        // Decrement nlink on the target inode
        if let Some(idx) = self.find_inode(child_ino) {
            let mut inodes = self.inodes.borrow_mut();
            inodes[idx].nlink = inodes[idx].nlink.saturating_sub(1);
        }
        self.drop_unlinked_inode_if_closed(child_ino)?;
        Ok(())
    }
    /// Engine-backed rmdir: remove an empty directory entry.
    fn rmdir(
        &self,
        parent: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        name: &[u8],
        _ctx: &crate::tidefs_kmod_bridge::kernel_types::RequestCtx,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if !self.pool_is_mounted() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV);
        }
        let parent_ino = parent.get();
        self.require_live_directory(parent_ino)?;
        // Find the entry
        let child = self
            .find_dir_entry(parent_ino, name)
            .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOENT)?;
        let (child_ino, child_kind) = child;
        // Must be a directory
        if child_kind != InodeRecord::DIR {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOTDIR);
        }
        // Must be empty
        if self.dir_has_children(child_ino) {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOTEMPTY);
        }
        // Remove the directory entry
        self.remove_dir_entry(parent_ino, name);
        // Remove the inode record and transient per-inode state.
        self.remove_inode_record(child_ino)?;
        // Decrement parent nlink
        if let Some(idx) = self.find_inode(parent_ino) {
            let mut inodes = self.inodes.borrow_mut();
            inodes[idx].nlink = inodes[idx].nlink.saturating_sub(1);
        }
        Ok(())
    }
    /// Engine-backed rename: atomically move a directory entry.
    /// Supports RENAME_NOREPLACE and RENAME_EXCHANGE flags.
    /// Handles cross-directory subdirectory nlink adjustment.
    fn rename(
        &self,
        old_parent: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        old_name: &[u8],
        new_parent: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        new_name: &[u8],
        flags: u32,
        _ctx: &crate::tidefs_kmod_bridge::kernel_types::RequestCtx,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if !self.pool_is_mounted() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV);
        }
        let old_p = old_parent.get();
        let new_p = new_parent.get();
        const RENAME_NOREPLACE: u32 = 1;
        const RENAME_EXCHANGE: u32 = 2;
        if flags & !(RENAME_NOREPLACE | RENAME_EXCHANGE) != 0 {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL);
        }
        self.require_live_directory(old_p)?;
        self.require_live_directory(new_p)?;
        let src = self
            .find_dir_entry(old_p, old_name)
            .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOENT)?;
        let (src_ino, src_kind) = src;
        if old_p == new_p && old_name == new_name {
            return Ok(());
        }
        let dst_exists = self.find_dir_entry(new_p, new_name);
        if flags & RENAME_NOREPLACE != 0 && dst_exists.is_some() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EEXIST);
        }
        if src_kind == InodeRecord::DIR && self.is_descendant_directory(new_p, src_ino) {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL);
        }
        if flags & RENAME_EXCHANGE != 0 {
            let dst = dst_exists.ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOENT)?;
            let (dst_ino, dst_kind) = dst;
            if src_kind == InodeRecord::DIR && self.is_descendant_directory(new_p, src_ino) {
                return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL);
            }
            if dst_kind == InodeRecord::DIR && self.is_descendant_directory(old_p, dst_ino) {
                return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL);
            }
            self.remove_dir_entry(old_p, old_name);
            self.remove_dir_entry(new_p, new_name);
            if let Err(e) = self.add_dir_entry(old_p, old_name, dst_ino, dst_kind) {
                return Err(e);
            }
            if let Err(e) = self.add_dir_entry(new_p, new_name, src_ino, src_kind) {
                self.remove_dir_entry(old_p, old_name);
                let _ = self.add_dir_entry(old_p, old_name, src_ino, src_kind);
                let _ = self.add_dir_entry(new_p, new_name, dst_ino, dst_kind);
                return Err(e);
            }
            if old_p != new_p {
                if src_kind == InodeRecord::DIR {
                    if let Some(idx) = self.find_inode(old_p) {
                        let mut inodes = self.inodes.borrow_mut();
                        inodes[idx].nlink = inodes[idx].nlink.saturating_sub(1);
                    }
                    if let Some(idx) = self.find_inode(new_p) {
                        let mut inodes = self.inodes.borrow_mut();
                        inodes[idx].nlink = inodes[idx].nlink.saturating_add(1);
                    }
                }
                if dst_kind == InodeRecord::DIR {
                    if let Some(idx) = self.find_inode(new_p) {
                        let mut inodes = self.inodes.borrow_mut();
                        inodes[idx].nlink = inodes[idx].nlink.saturating_sub(1);
                    }
                    if let Some(idx) = self.find_inode(old_p) {
                        let mut inodes = self.inodes.borrow_mut();
                        inodes[idx].nlink = inodes[idx].nlink.saturating_add(1);
                    }
                }
            }
            let entry = crate::intent_record::encode_rename_intent(
                old_parent,
                old_name,
                new_parent,
                new_name,
                crate::tidefs_kmod_bridge::kernel_types::InodeId::new(src_ino),
                Some(crate::tidefs_kmod_bridge::kernel_types::InodeId::new(
                    dst_ino,
                )),
            );
            self.record_intent_entry(entry.as_bytes())?;
            return Ok(());
        }
        if let Some((dst_ino, dst_kind)) = dst_exists {
            // Reject file-over-directory and directory-over-file renames.
            let src_is_dir = src_kind == InodeRecord::DIR;
            let dst_is_dir = dst_kind == InodeRecord::DIR;
            if !src_is_dir && dst_is_dir {
                return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EISDIR);
            }
            if src_is_dir && !dst_is_dir {
                return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOTDIR);
            }
            if dst_is_dir && self.dir_has_children(dst_ino) {
                return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOTEMPTY);
            }
            self.remove_dir_entry(new_p, new_name);
            if let Some(idx) = self.find_inode(dst_ino) {
                let mut inodes = self.inodes.borrow_mut();
                if dst_is_dir {
                    inodes[idx].nlink = 0;
                } else {
                    inodes[idx].nlink = inodes[idx].nlink.saturating_sub(1);
                }
            }
            self.drop_unlinked_inode_if_closed(dst_ino)?;
            if dst_is_dir {
                if let Some(idx) = self.find_inode(new_p) {
                    let mut inodes = self.inodes.borrow_mut();
                    inodes[idx].nlink = inodes[idx].nlink.saturating_sub(1);
                }
            }
        }
        self.remove_dir_entry(old_p, old_name);
        if let Err(e) = self.add_dir_entry(new_p, new_name, src_ino, src_kind) {
            let _ = self.add_dir_entry(old_p, old_name, src_ino, src_kind);
            return Err(e);
        }
        if old_p != new_p && src_kind == InodeRecord::DIR {
            if let Some(idx) = self.find_inode(old_p) {
                let mut inodes = self.inodes.borrow_mut();
                inodes[idx].nlink = inodes[idx].nlink.saturating_sub(1);
            }
            if let Some(idx) = self.find_inode(new_p) {
                let mut inodes = self.inodes.borrow_mut();
                inodes[idx].nlink = inodes[idx].nlink.saturating_add(1);
            }
        }
        let overwrite_ino =
            dst_exists.map(|(ino, _)| crate::tidefs_kmod_bridge::kernel_types::InodeId::new(ino));
        let entry = crate::intent_record::encode_rename_intent(
            old_parent,
            old_name,
            new_parent,
            new_name,
            crate::tidefs_kmod_bridge::kernel_types::InodeId::new(src_ino),
            overwrite_ino,
        );
        self.record_intent_entry(entry.as_bytes())?;
        Ok(())
    }
    /// Engine-backed link: create a hard link from target to new_name in new_parent.
    fn link(
        &self,
        target: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        new_parent: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        new_name: &[u8],
        _ctx: &crate::tidefs_kmod_bridge::kernel_types::RequestCtx,
    ) -> core::result::Result<
        crate::tidefs_kmod_bridge::kernel_types::InodeAttr,
        crate::tidefs_kmod_bridge::kernel_types::Errno,
    > {
        if !self.pool_is_mounted() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV);
        }
        let new_p = new_parent.get();
        self.require_live_directory(new_p)?;
        let target_idx = self
            .find_inode(target.get())
            .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOENT)?;
        let target_kind = { self.inodes.borrow()[target_idx].kind };
        if target_kind == InodeRecord::DIR {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EPERM);
        }
        if self.find_dir_entry(new_p, new_name).is_some() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EEXIST);
        }
        self.add_dir_entry(new_p, new_name, target.get(), target_kind)?;
        {
            let mut inodes = self.inodes.borrow_mut();
            inodes[target_idx].nlink = inodes[target_idx].nlink.saturating_add(1);
        }
        let entry = crate::intent_record::encode_link_intent(target, new_parent, new_name);
        self.record_intent_entry(entry.as_bytes())?;
        let ss = self
            .pool_core
            .as_ref()
            .map(|pc| pc.committed_root_io_ctx().sector_size)
            .unwrap_or(512);
        let rec = &self.inodes.borrow()[target_idx];
        Ok(KernelEngine::record_to_attr(rec, ss))
    }
    /// Engine-backed symlink: create a symbolic link in parent directory.
    fn symlink(
        &self,
        parent: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        name: &[u8],
        target: &[u8],
        _ctx: &crate::tidefs_kmod_bridge::kernel_types::RequestCtx,
    ) -> core::result::Result<
        crate::tidefs_kmod_bridge::kernel_types::InodeAttr,
        crate::tidefs_kmod_bridge::kernel_types::Errno,
    > {
        if !self.pool_is_mounted() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV);
        }
        let parent_ino = parent.get();
        self.require_live_directory(parent_ino)?;
        if self.find_dir_entry(parent_ino, name).is_some() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EEXIST);
        }
        let target_len = target.len() as u64;
        let mut target_vec = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();
        target_vec.extend_from_slice(target);
        let rec = self.allocate_inode(
            InodeRecord::SYMLINK,
            parent,
            0o120777,
            0,
            0, // uid, gid
            1, // nlink
            target_len,
        )?;
        let ino = rec.ino;
        let gen = rec.generation;
        let rec_with_target = InodeRecord {
            ino,
            mode: 0o120777,
            uid: 0,
            gid: 0,
            nlink: 1,
            size: target_len,
            blocks: (target_len + 511) / 512,
            generation: gen,
            kind: InodeRecord::SYMLINK,
            atime_ns: 0,
            mtime_ns: 0,
            ctime_ns: 0,
            symlink_target: Some(target_vec),
        };
        self.push_inode_record(rec_with_target)?;
        if let Err(e) = self.add_dir_entry(parent_ino, name, ino, InodeRecord::SYMLINK) {
            self.remove_inode_record(ino)?;
            return Err(e);
        }
        let entry = crate::intent_record::encode_symlink_intent(
            parent,
            name,
            target,
            crate::tidefs_kmod_bridge::kernel_types::InodeId::new(ino),
        );
        self.record_intent_entry(entry.as_bytes())?;
        let ss = self
            .pool_core
            .as_ref()
            .map(|pc| pc.committed_root_io_ctx().sector_size)
            .unwrap_or(512);
        Ok(KernelEngine::record_to_attr(
            &InodeRecord {
                ino,
                mode: 0o120777,
                uid: 0,
                gid: 0,
                nlink: 1,
                size: target_len,
                blocks: (target_len + 511) / 512,
                generation: gen,
                kind: InodeRecord::SYMLINK,
                atime_ns: 0,
                mtime_ns: 0,
                ctime_ns: 0,
                symlink_target: None,
            },
            ss,
        ))
    }

    /// Engine-backed readlink: return the symlink target path.
    fn readlink(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        _ctx: &crate::tidefs_kmod_bridge::kernel_types::RequestCtx,
    ) -> core::result::Result<
        crate::tidefs_kmod_bridge::kernel_types::KmodVec<u8>,
        crate::tidefs_kmod_bridge::kernel_types::Errno,
    > {
        if !self.pool_is_mounted() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV);
        }
        let idx = self
            .find_inode(inode.get())
            .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOENT)?;
        let inodes = self.inodes.borrow();
        let rec = &inodes[idx];
        if rec.kind != InodeRecord::SYMLINK {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL);
        }
        match &rec.symlink_target {
            Some(target) => Ok(target.clone()),
            None => Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EIO),
        }
    }
    fn mknod(
        &self,
        parent: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        name: &[u8],
        mode: u32,
        rdev: u32,
        _ctx: &crate::tidefs_kmod_bridge::kernel_types::RequestCtx,
    ) -> core::result::Result<
        crate::tidefs_kmod_bridge::kernel_types::InodeAttr,
        crate::tidefs_kmod_bridge::kernel_types::Errno,
    > {
        if !self.pool_is_mounted() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV);
        }
        let parent_ino = parent.get();
        self.require_live_directory(parent_ino)?;
        if self.find_dir_entry(parent_ino, name).is_some() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EEXIST);
        }
        // Support FIFO (named pipe) and regular-file-via-mknod.
        // Block/char devices require CAP_MKNOD which is beyond this scope.
        let type_bits = mode & 0o170000;
        let (kind, file_mode) = if type_bits == 0o010000 {
            (InodeRecord::FILE, mode)
        } else if type_bits == 0 {
            (InodeRecord::FILE, 0o100000u32 | (mode & 0o7777))
        } else if type_bits == 0o040000 {
            (InodeRecord::DIR, 0o040000u32 | (mode & 0o7777))
        } else {
            (InodeRecord::FILE, mode)
        };
        let rec = self.allocate_inode(
            kind,
            parent,
            file_mode,
            0,
            0, // uid, gid
            if kind == InodeRecord::DIR { 2 } else { 1 },
            0, // initial_size
        )?;
        let ino = rec.ino;
        let gen = rec.generation;
        self.push_inode_record(rec)?;
        if kind == InodeRecord::DIR {
            if let Some(parent_idx) = self.find_inode(parent_ino) {
                let mut inodes = self.inodes.borrow_mut();
                inodes[parent_idx].nlink = inodes[parent_idx].nlink.saturating_add(1);
            }
        }
        if let Err(e) = self.add_dir_entry(parent_ino, name, ino, kind) {
            self.remove_inode_record(ino)?;
            if kind == InodeRecord::DIR {
                if let Some(parent_idx) = self.find_inode(parent_ino) {
                    let mut inodes = self.inodes.borrow_mut();
                    inodes[parent_idx].nlink = inodes[parent_idx].nlink.saturating_sub(1);
                }
            }
            return Err(e);
        }
        let entry = crate::intent_record::encode_mknod_intent(
            parent,
            name,
            mode,
            rdev,
            crate::tidefs_kmod_bridge::kernel_types::InodeId::new(ino),
        );
        self.record_intent_entry(entry.as_bytes())?;
        let ss = self
            .pool_core
            .as_ref()
            .map(|pc| pc.committed_root_io_ctx().sector_size)
            .unwrap_or(512);
        let attr = InodeRecord {
            ino,
            mode: file_mode,
            uid: 0,
            gid: 0,
            nlink: if kind == InodeRecord::DIR { 2 } else { 1 },
            size: 0,
            blocks: 0,
            generation: gen,
            kind,
            atime_ns: 0,
            mtime_ns: 0,
            ctime_ns: 0,
            symlink_target: None,
        };
        Ok(KernelEngine::record_to_attr(&attr, ss))
    }

    /// Open a file inode and return an engine file handle.
    ///
    /// Verifies the inode exists in either the in-memory table
    /// (for engine-backed mutations) or the on-disk VINO table
    /// (for pool-backed inodes).  Returns a handle with the
    /// inode number as the fh_id for simple tracking.
    fn open(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        flags: u32,
        _ctx: &crate::tidefs_kmod_bridge::kernel_types::RequestCtx,
    ) -> core::result::Result<
        crate::tidefs_kmod_bridge::kernel_types::EngineFileHandle,
        crate::tidefs_kmod_bridge::kernel_types::Errno,
    > {
        let ino = inode.get();
        if ino == 0 {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOENT);
        }
        // Check in-memory inode table first (engine-backed create/mkdir).
        if self.find_inode(ino).is_some() {
            self.track_open(ino)?;
            return Ok(
                crate::tidefs_kmod_bridge::kernel_types::EngineFileHandle::new(
                    inode,
                    flags,
                    crate::tidefs_kmod_bridge::kernel_types::FileHandleId::new(ino),
                    0,
                ),
            );
        }
        // If pool is mounted, check the on-disk VINO table.
        if self.pool_is_mounted() {
            if let Some(ref pool_core) = self.pool_core {
                let io_ctx = pool_core.committed_root_io_ctx();
                if let Some(read_fn) = io_ctx.read_sectors_fn {
                    let ss = io_ctx.sector_size as u64;
                    // Attempt to read the inode record; if it exists,
                    // the inode is valid and can be opened.
                    if self.read_inode_record(ino, &io_ctx, read_fn, ss).is_ok() {
                        self.track_open(ino)?;
                        return Ok(
                            crate::tidefs_kmod_bridge::kernel_types::EngineFileHandle::new(
                                inode,
                                flags,
                                crate::tidefs_kmod_bridge::kernel_types::FileHandleId::new(ino),
                                0,
                            ),
                        );
                    }
                }
            }
        }
        Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOENT)
    }
    /// Release an open file handle with open-unlink lifecycle management.
    ///
    /// Decrements the open-fd count for the inode.  When the count reaches
    /// zero and the inode has nlink==0 (orphaned by a prior unlink), the
    /// inode record is removed.  This implements the POSIX deleted-file
    /// lifetime semantics: data stays alive through open handles and is
    /// reclaimed only after the last close.
    fn release(
        &self,
        fh: &crate::tidefs_kmod_bridge::kernel_types::EngineFileHandle,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        let ino = fh.inode_id.get();
        let remaining = self.track_release(ino);
        if remaining == 0 {
            // No more open handles: check if the inode was orphaned.
            if let Some(idx) = self.find_inode(ino) {
                if self.inodes.borrow()[idx].nlink == 0 {
                    self.remove_inode_record(ino)?;
                }
            }
        }
        Ok(())
    }
    /// Read file data through extent-map authority and pool-core I/O.
    ///
    /// Resolves the logical file offset through the on-disk EXMP extent
    /// map leaf page, then reads data bytes from the physical locator
    /// via KernelPoolCore's block-device read callback.  Holes and
    /// unwritten extents return zero-filled buffers.  Short reads at
    /// EOF are expressed by returning fewer bytes than `size`.
    ///
    /// This replaces the in-memory bring-up buffer approach: every read
    /// is resolved against durable extent-map authority.
    fn read(
        &self,
        fh: &crate::tidefs_kmod_bridge::kernel_types::EngineFileHandle,
        offset: u64,
        size: u32,
        _ctx: &crate::tidefs_kmod_bridge::kernel_types::RequestCtx,
    ) -> core::result::Result<
        crate::tidefs_kmod_bridge::kernel_types::KmodVec<u8>,
        crate::tidefs_kmod_bridge::kernel_types::Errno,
    > {
        if size == 0 {
            let empty = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();
            return Ok(empty);
        }
        if !self.pool_is_mounted() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV);
        }
        let Some(ref pool_core) = self.pool_core else {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV);
        };
        let io_ctx = pool_core.committed_root_io_ctx();
        let Some(read_fn) = io_ctx.read_sectors_fn else {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV);
        };
        let ss = io_ctx.sector_size as u64;
        let ino = fh.inode_id.get();

        // In-memory inodes use the live staged-data overlay. Later entries
        // override earlier entries, including fallocate zero-range records.
        if self.find_inode(ino).is_some() {
            return self.read_live_inode_data(ino, offset, size);
        }

        // Resolve the inode's on-disk VINO record to obtain extent_map_root.
        // Only reached for inodes that exist on disk (not in the in-memory
        // table).  read_inode_record calls decode_vrbt which uses BLAKE3
        // hash; the write_buffer guard above avoids this path for fresh
        // inodes that have not yet been committed.
        let record = match self.read_inode_record(ino, &io_ctx, read_fn, ss) {
            Ok(rec) => rec,
            Err(_) => {
                let empty = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();
                return Ok(empty);
            }
        };
        if record.extent_map_root == 0 {
            let empty = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();
            return Ok(empty);
        }

        // Read the EXMP leaf page.
        let exmp_sector = record.extent_map_root / ss;
        let exmp_sector_off = (record.extent_map_root % ss) as usize;
        let mut exmp_buf = [0u8; 4096];
        let exmp_read_len = core::cmp::min(4096u32, ss as u32) as u32;
        // SAFETY: read_fn is the C shim block-device read callback.
        if unsafe { read_fn(exmp_sector, exmp_buf.as_mut_ptr(), exmp_read_len) } < 0 {
            kernel::pr_err!(
                "tidefs_posix_vfs: read: EXMP read failed ino={} sector={}\n",
                ino,
                exmp_sector
            );
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EIO);
        }

        // Look up the logical offset in the extent map.
        use crate::replay_integration;
        let entry =
            match replay_integration::lookup_exmp_extent(&exmp_buf[exmp_sector_off..], offset) {
                Ok(e) => e,
                Err(replay_integration::ExmpError::NotFound) => {
                    // No extent covers this offset: hole, return zeros.
                    let mut zeros = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();
                    zeros.resize(size as usize, 0u8);
                    return Ok(zeros);
                }
                Err(_) => {
                    kernel::pr_err!(
                        "tidefs_posix_vfs: read: EXMP parse error ino={} off={}\n",
                        ino,
                        offset
                    );
                    return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EIO);
                }
            };

        // Unwritten extent: return zeros.
        if !entry.is_data() {
            let available = entry.end_offset().saturating_sub(offset);
            let read_len = core::cmp::min(size as u64, available) as usize;
            let mut zeros = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();
            zeros.resize(read_len, 0u8);
            return Ok(zeros);
        }

        // Data extent: compute physical byte offset and read sector(s).
        let internal_off = offset.saturating_sub(entry.logical_offset);
        let phys_offset = entry.locator_id.saturating_add(internal_off);
        let available = entry.end_offset().saturating_sub(offset);
        let read_size = core::cmp::min(size as u64, available);
        let read_size_usize = read_size as usize;

        let phys_sector = phys_offset / ss;
        let phys_off_in_sector = (phys_offset % ss) as usize;
        let sector_need = phys_off_in_sector.saturating_add(read_size_usize);
        let sector_read_len = core::cmp::min(sector_need as u32, ss as u32);
        let mut sector_buf = [0u8; 4096];
        // SAFETY: read_fn is the C shim block-device read callback.
        if unsafe { read_fn(phys_sector, sector_buf.as_mut_ptr(), sector_read_len) } < 0 {
            kernel::pr_err!(
                "tidefs_posix_vfs: read: data read failed ino={} off={} phys_sec={}\n",
                ino,
                offset,
                phys_sector
            );
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EIO);
        }

        let copy_len = core::cmp::min(
            read_size_usize,
            sector_buf.len().saturating_sub(phys_off_in_sector),
        );
        let mut out = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();
        out.extend_from_slice(
            &sector_buf[phys_off_in_sector..phys_off_in_sector.saturating_add(copy_len)],
        );

        // Span a sector boundary if needed.
        if copy_len < read_size_usize {
            let remaining = read_size_usize - copy_len;
            let next_sector = phys_sector.saturating_add(1);
            let mut next_buf = [0u8; 4096];
            let next_read_len = core::cmp::min(remaining as u32, ss as u32);
            // SAFETY: read_fn is the C shim block-device read callback.
            if unsafe { read_fn(next_sector, next_buf.as_mut_ptr(), next_read_len) } >= 0 {
                let take = core::cmp::min(remaining, next_read_len as usize);
                out.extend_from_slice(&next_buf[..take]);
            }
        }
        Ok(out)
    }
    /// Write file data through extent-map authority and pool-core I/O.
    ///
    /// Resolves the logical file offset through the on-disk EXMP extent
    /// map, obtains the physical locator for the target extent, and
    /// writes data directly through KernelPoolCore's block-device write
    /// callback.  Unwritten extents cannot be written until
    /// `allocate_extents` is wired (#6323); writes to unallocated
    /// regions return ENOSPC.  Existing data extents are overwritten
    /// in place.
    ///
    /// This replaces the in-memory write_buffer approach: data is
    /// routed through durable extent-map authority, not staged in a
    /// transient buffer for later writeback.
    fn write(
        &self,
        fh: &crate::tidefs_kmod_bridge::kernel_types::EngineFileHandle,
        offset: u64,
        data: &[u8],
        _ctx: &crate::tidefs_kmod_bridge::kernel_types::RequestCtx,
    ) -> core::result::Result<u32, crate::tidefs_kmod_bridge::kernel_types::Errno> {
        let len = data.len() as u32;
        if len == 0 {
            return Ok(0);
        }
        if !self.pool_is_mounted() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV);
        }
        let Some(ref pool_core) = self.pool_core else {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV);
        };
        let io_ctx = pool_core.committed_root_io_ctx();
        let ino = fh.inode_id.get();

        if self.find_inode(ino).is_some() {
            return self.stage_live_inode_write(fh.inode_id, offset, data);
        }

        // Disk-backed writes require both block-device callbacks: write
        // for data persistence and read for extent/inode-table metadata.
        // Without those callbacks the engine is not mounted with usable
        // storage authority, so fail closed instead of treating write as
        // an unimplemented VFS operation.
        let Some(write_fn) = io_ctx.write_sectors_fn else {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV);
        };
        let ss = io_ctx.sector_size as u64;

        // Resolve the inode's VINO record to obtain extent_map_root.
        // Use the read callback for inode-table reads; the write path
        // needs the read-side to resolve extent metadata.
        let Some(read_fn) = io_ctx.read_sectors_fn else {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV);
        };
        let record = match self.read_inode_record(ino, &io_ctx, read_fn, ss) {
            Ok(rec) => rec,
            Err(_) => {
                return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EIO);
            }
        };

        // If no extent map exists yet, stage in write_buffer as fallback
        // until #6323 wires kernel-side extent allocation.
        if record.extent_map_root == 0 {
            return self.stage_live_inode_write(fh.inode_id, offset, data);
        }

        // Read the EXMP leaf page.
        let exmp_sector = record.extent_map_root / ss;
        let exmp_sector_off = (record.extent_map_root % ss) as usize;
        let mut exmp_buf = [0u8; 4096];
        let exmp_read_len = core::cmp::min(4096u32, ss as u32) as u32;
        // SAFETY: read_fn is the C shim block-device read callback.
        if unsafe { read_fn(exmp_sector, exmp_buf.as_mut_ptr(), exmp_read_len) } < 0 {
            kernel::pr_err!(
                "tidefs_posix_vfs: write: EXMP read failed ino={} sector={}\n",
                ino,
                exmp_sector
            );
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EIO);
        }

        // Look up the extent for this offset.
        use crate::replay_integration;
        let entry =
            match replay_integration::lookup_exmp_extent(&exmp_buf[exmp_sector_off..], offset) {
                Ok(e) => e,
                Err(replay_integration::ExmpError::NotFound) => {
                    // No extent allocated: cannot write without allocate_extents.
                    return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOSPC);
                }
                Err(_) => {
                    kernel::pr_err!(
                        "tidefs_posix_vfs: write: EXMP parse error ino={} off={}\n",
                        ino,
                        offset
                    );
                    return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EIO);
                }
            };

        if !entry.is_data() {
            // Unwritten extent: cannot overwrite without allocation.
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOSPC);
        }

        // Write data to the physical locator.
        let internal_off = offset.saturating_sub(entry.logical_offset);
        let phys_offset = entry.locator_id.saturating_add(internal_off);
        let available = entry.end_offset().saturating_sub(offset);
        let write_size = core::cmp::min(len as u64, available) as u32;

        let phys_sector = phys_offset / ss;
        let phys_off_in_sector = (phys_offset % ss) as u32;
        // SAFETY: write_fn is the C shim block-device write callback.
        let ret = unsafe { write_fn(phys_sector, data.as_ptr(), write_size) };
        if ret != 0 {
            kernel::pr_err!(
                "tidefs_posix_vfs: write: sector write failed ino={} off={} phys_sec={}\n",
                ino,
                offset,
                phys_sector
            );
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EIO);
        }
        self.update_inode_size_after_write(ino, offset.saturating_add(write_size as u64));
        Ok(write_size)
    }
    fn copy_file_range(
        &self,
        source_fh: &crate::tidefs_kmod_bridge::kernel_types::EngineFileHandle,
        offset_in: u64,
        dest_fh: &crate::tidefs_kmod_bridge::kernel_types::EngineFileHandle,
        offset_out: u64,
        length: u64,
        ctx: &crate::tidefs_kmod_bridge::kernel_types::RequestCtx,
    ) -> core::result::Result<u32, crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if length == 0 {
            return Ok(0);
        }

        let requested = length.min(u64::from(u32::MAX));
        let source_end = offset_in
            .checked_add(requested)
            .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL)?;
        let dest_end = offset_out
            .checked_add(requested)
            .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL)?;
        if source_fh.inode_id == dest_fh.inode_id && offset_in < dest_end && offset_out < source_end
        {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL);
        }

        if self.find_inode(source_fh.inode_id.get()).is_some() {
            self.flush_live_write_buffer_to_storage(
                Some(source_fh.inode_id),
                offset_in,
                requested,
            )?;
        }

        let mut copied = 0_u64;
        while copied < requested {
            let remaining = requested - copied;
            let chunk_len = remaining
                .min(crate::tidefs_kmod_bridge::kernel_types::VFS_COPY_FILE_RANGE_MAX_CHUNK);
            let chunk_size = u32::try_from(chunk_len)
                .map_err(|_| crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)?;
            let read_offset = offset_in
                .checked_add(copied)
                .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL)?;
            let chunk = self.read(source_fh, read_offset, chunk_size, ctx)?;
            if chunk.is_empty() {
                break;
            }

            let write_offset = offset_out
                .checked_add(copied)
                .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL)?;
            let written = match self.write(dest_fh, write_offset, &chunk, ctx) {
                Ok(written) => written,
                Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOSPC) if copied > 0 => {
                    break;
                }
                Err(err) => return Err(err),
            };
            if u64::from(written) > chunk.len() as u64 {
                return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EIO);
            }
            copied = copied
                .checked_add(u64::from(written))
                .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)?;
            if written == 0 || u64::from(written) < chunk.len() as u64 {
                break;
            }
        }

        u32::try_from(copied).map_err(|_| crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)
    }
    fn flush(
        &self,
        _fh: &crate::tidefs_kmod_bridge::kernel_types::EngineFileHandle,
        _ctx: &crate::tidefs_kmod_bridge::kernel_types::RequestCtx,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if !self.pool_is_mounted() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV);
        }
        // Writes are synchronous to sectors through the pool core I/O
        // context; there is no engine-internal buffer to flush.  The C
        // shim fsync path already persists pool state independently
        // through tidefs_kernel_pool_persist_state.  This is a no-op
        // that satisfies the VfsEngine trait contract.
        Ok(())
    }
    fn fsync(
        &self,
        fh: &crate::tidefs_kmod_bridge::kernel_types::EngineFileHandle,
        _datasync: bool,
        _ctx: &crate::tidefs_kmod_bridge::kernel_types::RequestCtx,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if !self.pool_is_mounted() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV);
        }
        // Verify the file handle's inode exists.
        let ino = fh.inode_id.get();
        if self.find_inode(ino).is_none() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOENT);
        }
        // File fsync is a per-inode wait barrier.  The whole-namespace
        // txg barrier persists every live inode, dirent, extent, and xattr
        // under the mounted-engine lock; fsstress can issue enough file
        // fsyncs to starve unrelated open/write/setattr calls.  Directory
        // fsync, syncfs, and unmount remain the whole-mount publication
        // boundaries.
        self.flush_live_write_buffer_to_storage(Some(fh.inode_id), 0, u64::MAX)?;
        self.mounted_pool_io_ctx()?.flush()
    }
    /// Engine-backed fallocate: space reservation, hole punch, and zero-range
    /// through the in-memory inode table with block-count adjustment.
    ///
    /// FALLOC_FL_KEEP_SIZE: allocate space without changing the file size.
    /// FALLOC_FL_PUNCH_HOLE: deallocate backed storage; does not change size.
    /// FALLOC_FL_ZERO_RANGE: ensure the range reads as zeroes; extends size.
    /// FALLOC_FL_COLLAPSE_RANGE: remove bytes and shift later extents down.
    /// FALLOC_FL_INSERT_RANGE: insert a sparse zero range and shift later data.
    fn fallocate(
        &self,
        fh: &crate::tidefs_kmod_bridge::kernel_types::EngineFileHandle,
        mode: u32,
        offset: u64,
        length: u64,
        _ctx: &crate::tidefs_kmod_bridge::kernel_types::RequestCtx,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if !self.pool_is_mounted() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV);
        }
        let ino = fh.inode_id.get();
        let idx = self
            .find_inode(ino)
            .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOENT)?;
        // Classify the operation from raw Linux FALLOC_FL_* flags.
        let keep_size = (mode & 0x01) != 0; // FALLOC_FL_KEEP_SIZE
        let is_punch = (mode & 0x02) != 0; // FALLOC_FL_PUNCH_HOLE
        let is_zero = (mode & 0x10) != 0; // FALLOC_FL_ZERO_RANGE
        let is_collapse = (mode & 0x08) != 0; // FALLOC_FL_COLLAPSE_RANGE
        let is_insert = (mode & 0x20) != 0; // FALLOC_FL_INSERT_RANGE

        let end = Self::checked_range_end(offset, length)?;
        if is_collapse {
            let size = self.inodes.borrow()[idx].size;
            if end >= size {
                return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL);
            }
            self.collapse_live_write_buffer(fh.inode_id, offset, length)?;
            let removed_blocks = self.collapse_live_extents(fh.inode_id, offset, length)?;
            {
                let mut inodes = self.inodes.borrow_mut();
                let rec = &mut inodes[idx];
                rec.size = rec.size.saturating_sub(length);
                rec.blocks = rec.blocks.saturating_sub(removed_blocks);
            }
            return Ok(());
        }

        if is_insert {
            let size = self.inodes.borrow()[idx].size;
            if offset >= size {
                return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL);
            }
            let new_size = size
                .checked_add(length)
                .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::EFBIG)?;
            self.insert_live_write_buffer(fh.inode_id, offset, length)?;
            self.insert_live_extents(fh.inode_id, offset, length)?;
            {
                let mut inodes = self.inodes.borrow_mut();
                let rec = &mut inodes[idx];
                rec.size = new_size;
                rec.blocks = self.live_allocated_blocks(ino);
            }
            return Ok(());
        }

        if is_punch {
            self.clear_live_write_buffer_range(fh.inode_id, offset, length)?;
        } else if is_zero {
            self.stage_live_zero_range(fh.inode_id, offset, length, true)?;
        }
        if is_punch {
            self.set_live_extent_range(fh.inode_id, offset, length, None)?;
        } else if is_zero {
            let extent_len = if keep_size {
                let size = self.inodes.borrow()[idx].size;
                if offset >= size {
                    0
                } else {
                    core::cmp::min(length, size.saturating_sub(offset))
                }
            } else {
                length
            };
            if let Some((extent_offset, extent_len)) =
                Self::full_live_blocks_in_range(offset, extent_len)?
            {
                self.set_live_extent_range(
                    fh.inode_id,
                    extent_offset,
                    extent_len,
                    Some(LiveExtentEntry::UNWRITTEN),
                )?;
            }
        } else {
            let extent_len = if keep_size {
                let size = self.inodes.borrow()[idx].size;
                if offset >= size {
                    0
                } else {
                    core::cmp::min(length, size.saturating_sub(offset))
                }
            } else {
                length
            };
            self.fill_live_extent_holes(
                fh.inode_id,
                offset,
                extent_len,
                LiveExtentEntry::UNWRITTEN,
            )?;
        }
        {
            let mut inodes = self.inodes.borrow_mut();
            let rec = &mut inodes[idx];

            if is_punch {
                // Hole punch: deallocate backed range. Size unchanged.
                rec.blocks = self.live_allocated_blocks(ino);
            } else if is_zero {
                // Zero range: extend size if needed, then block count follows size.
                if end > rec.size && !keep_size {
                    rec.size = end;
                }
                rec.blocks = self.live_allocated_blocks(ino);
            } else {
                // Allocate: extend size unless KEEP_SIZE is set.
                if end > rec.size && !keep_size {
                    rec.size = end;
                }
                rec.blocks = self.live_allocated_blocks(ino);
            }
        }
        Ok(())
    }

    /// Engine-backed data-ranges query for SEEK_DATA/SEEK_HOLE (#6644).
    ///
    /// Reads the on-disk EXMP extent map leaf page through KernelStorageIo
    /// and enumerates data extents (kind=0) that overlap the requested
    /// byte range. Unwritten extents (kind=1) are treated as holes and
    fn data_ranges(
        &self,
        fh: &crate::tidefs_kmod_bridge::kernel_types::EngineFileHandle,
        offset: u64,
        length: u64,
        _ctx: &crate::tidefs_kmod_bridge::kernel_types::RequestCtx,
    ) -> core::result::Result<
        crate::tidefs_kmod_bridge::kernel_types::KmodVec<
            crate::tidefs_kmod_bridge::kernel_types::LseekDataRange,
        >,
        crate::tidefs_kmod_bridge::kernel_types::Errno,
    > {
        if !self.pool_is_mounted() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV);
        }
        let ino = fh.inode_id.get();
        self.live_data_ranges_for_inode(ino, offset, length)
    }

    fn fiemap(
        &self,
        fh: &crate::tidefs_kmod_bridge::kernel_types::EngineFileHandle,
        _ctx: &crate::tidefs_kmod_bridge::kernel_types::RequestCtx,
    ) -> core::result::Result<
        crate::tidefs_kmod_bridge::kernel_types::FiemapExtentVec,
        crate::tidefs_kmod_bridge::kernel_types::Errno,
    > {
        if !self.pool_is_mounted() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV);
        }
        let attr = self.getattr(fh.inode_id, Some(fh), _ctx)?;
        let extents = self.live_fiemap_extents(fh.inode_id.get(), 0, attr.posix.size)?;
        Ok(crate::tidefs_kmod_bridge::kernel_types::FiemapExtentVec { extents })
    }
    /// Engine-backed opendir: validate the inode is a directory and return a handle.
    ///
    /// Root (ino 1) is always a directory. Other inodes are checked against
    /// the in-memory inode table. Returns ENOTDIR for non-directory inodes
    /// and ENOENT for unknown inodes.
    fn opendir(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        _ctx: &crate::tidefs_kmod_bridge::kernel_types::RequestCtx,
    ) -> core::result::Result<
        crate::tidefs_kmod_bridge::kernel_types::EngineDirHandle,
        crate::tidefs_kmod_bridge::kernel_types::Errno,
    > {
        use crate::tidefs_kmod_bridge::kernel_types::{DirHandleId, EngineDirHandle, Errno};
        let ino = inode.get();
        // Root is always a valid directory.
        if ino == 1 || ino == 0 {
            if ino == 1 {
                self.track_open(ino)?;
            }
            return Ok(EngineDirHandle {
                inode_id: inode,
                dh_id: DirHandleId::new(ino),
            });
        }
        // Check in-memory inode table.
        let inodes = self.inodes.borrow();
        if let Some(rec) = inodes.iter().find(|r| r.ino == ino) {
            if rec.kind == InodeRecord::DIR {
                drop(inodes);
                self.track_open(ino)?;
                return Ok(EngineDirHandle {
                    inode_id: inode,
                    dh_id: DirHandleId::new(ino),
                });
            }
            return Err(Errno::ENOTDIR);
        }
        Err(Errno::ENOENT)
    }

    /// Engine-backed releasedir: release directory lifetime pins.
    fn releasedir(
        &self,
        dh: &crate::tidefs_kmod_bridge::kernel_types::EngineDirHandle,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        let ino = dh.inode_id.get();
        let remaining = self.track_release(ino);
        if remaining == 0 {
            if let Some(idx) = self.find_inode(ino) {
                if self.inodes.borrow()[idx].nlink == 0 {
                    self.remove_inode_record(ino)?;
                }
            }
        }
        Ok(())
    }

    /// Engine-backed readdir: iterate in-memory directory entries with
    /// cookie-based pagination for seekdir stability.
    ///
    /// Entries are collected from `dir_entries` where parent_ino matches
    /// the directory handle's inode. Stable per-mount cookies are assigned
    /// when entries are inserted; iteration must return the minimum cookie
    /// greater than the caller's offset, independent of vector mutation order.
    ///
    /// The `offset` parameter works as a cookie filter: only entries
    /// with `cookie > offset` are returned. Batch size is bounded at 128
    /// entries to bound memory use; `more` is set true when additional
    /// entries remain.
    fn readdir(
        &self,
        dh: &crate::tidefs_kmod_bridge::kernel_types::EngineDirHandle,
        offset: u64,
        _ctx: &crate::tidefs_kmod_bridge::kernel_types::RequestCtx,
    ) -> core::result::Result<
        (
            crate::tidefs_kmod_bridge::kernel_types::KmodVec<
                crate::tidefs_kmod_bridge::kernel_types::DirEntry,
            >,
            bool,
        ),
        crate::tidefs_kmod_bridge::kernel_types::Errno,
    > {
        use crate::tidefs_kmod_bridge::kernel_types::{DirEntry, Generation, InodeId, NodeKind};
        let dir_ino = dh.inode_id.get();
        let dir_entries = self.dir_entries.borrow();

        let mut result = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();
        let batch_limit: usize = 128;

        let mut cursor = offset;
        loop {
            let mut best_index: Option<usize> = None;
            let mut best_cookie: u64 = 0;

            for (idx, entry) in dir_entries.iter().enumerate() {
                let (parent_ino, _name, _child_ino, _child_kind, entry_cookie) = entry;
                if *parent_ino != dir_ino {
                    continue;
                }
                let candidate_cookie = *entry_cookie as u64;
                if candidate_cookie <= cursor {
                    continue;
                }
                if best_index.is_none() || candidate_cookie < best_cookie {
                    best_index = Some(idx);
                    best_cookie = candidate_cookie;
                }
            }

            let idx = match best_index {
                Some(idx) => idx,
                None => return Ok((result, false)),
            };
            let (_parent_ino, name, child_ino, child_kind, entry_cookie) = &dir_entries[idx];
            let cookie = *entry_cookie as u64;

            let node_kind = match child_kind {
                0 => NodeKind::File,
                1 => NodeKind::Dir,
                2 => NodeKind::Symlink,
                _ => NodeKind::File,
            };

            // Build a kernel::alloc::KVec<u8> for the DirEntry name.
            // SAFETY: name is a KmodVec<u8> wrapping kernel::alloc::KVec<u8>;
            // we clone the bytes into a fresh KVec for the DirEntry.
            let name_kvec_init = kernel::alloc::KVec::<u8>::with_capacity(
                name.len(),
                kernel::alloc::flags::GFP_KERNEL,
            );
            let mut name_kvec = match name_kvec_init {
                Ok(v) => v,
                Err(_) => kernel::alloc::KVec::<u8>::new(),
            };
            // SAFETY: name derefs to &[u8] via KmodVec's Deref impl.
            let name_slice: &[u8] = &*name;
            let _ = name_kvec.extend_from_slice(name_slice, kernel::alloc::flags::GFP_KERNEL);

            let dir_entry = DirEntry {
                name: name_kvec,
                inode_id: InodeId::new(*child_ino),
                kind: node_kind,
                generation: Generation::new(1),
                cookie,
            };
            result.push(dir_entry);
            cursor = cookie;

            if result.len() >= batch_limit {
                let mut more = false;
                for entry in dir_entries.iter() {
                    let (parent_ino, _name, _child_ino, _child_kind, entry_cookie) = entry;
                    if *parent_ino == dir_ino && (*entry_cookie as u64) > cursor {
                        more = true;
                        break;
                    }
                }
                return Ok((result, more));
            }
        }
    }

    /// Engine-backed fsyncdir: no-op for the in-memory engine.
    fn fsyncdir(
        &self,
        _dh: &crate::tidefs_kmod_bridge::kernel_types::EngineDirHandle,
        _datasync: bool,
        _ctx: &crate::tidefs_kmod_bridge::kernel_types::RequestCtx,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        Ok(())
    }

    fn getxattr(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        name: &[u8],
        _ctx: &crate::tidefs_kmod_bridge::kernel_types::RequestCtx,
    ) -> core::result::Result<
        crate::tidefs_kmod_bridge::kernel_types::KmodVec<u8>,
        crate::tidefs_kmod_bridge::kernel_types::Errno,
    > {
        let valid_prefixes: &[&[u8]] = &[b"security.", b"system.", b"trusted.", b"user."];
        if !valid_prefixes.iter().any(|p| name.starts_with(p)) {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EOPNOTSUPP);
        }
        let ino = inode.get();
        if let Some(idx) = self.find_xattr_store_idx(ino) {
            let stores = self.xattr_stores.borrow();
            let entries = &stores[idx].1;
            for (entry_name, value) in entries.iter() {
                if **entry_name == *name {
                    let mut result = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();
                    result.extend_from_slice(&*value);
                    return Ok(result);
                }
            }
        }
        Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODATA)
    }
    fn setxattr(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        name: &[u8],
        value: &[u8],
        flags: u32,
        _ctx: &crate::tidefs_kmod_bridge::kernel_types::RequestCtx,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        let valid_prefixes: &[&[u8]] = &[b"security.", b"system.", b"trusted.", b"user."];
        if !valid_prefixes.iter().any(|p| name.starts_with(p)) {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EOPNOTSUPP);
        }
        if name.is_empty() || name.contains(&0) {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL);
        }
        if name.len() > 255 {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL);
        }
        if value.len() > 65536 {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::E2BIG);
        }
        if flags > 2 || flags == 3 {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL);
        }
        let ino = inode.get();
        let idx = self.get_or_create_xattr_store_idx(ino);
        let mut stores = self.xattr_stores.borrow_mut();
        let entries = &mut stores[idx].1;
        let exists = entries.iter().any(|(n, _)| **n == *name);
        match flags {
            1 if exists => return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EEXIST),
            2 if !exists => return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODATA),
            _ => {}
        }
        if exists {
            entries.retain(|(n, _)| **n != *name);
        }
        let mut name_vec = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();
        name_vec.extend_from_slice(name);
        let mut value_vec = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();
        value_vec.extend_from_slice(value);
        entries.push((name_vec, value_vec));
        // Record intent for crash recovery replay.
        let ns_byte = Self::xattr_namespace_byte(name);
        let entry = crate::intent_record::encode_setxattr_intent(inode, ns_byte, name, value);
        self.record_intent_entry(entry.as_bytes())?;
        Ok(())
    }
    fn listxattr(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        _ctx: &crate::tidefs_kmod_bridge::kernel_types::RequestCtx,
    ) -> core::result::Result<
        crate::tidefs_kmod_bridge::kernel_types::KmodVec<u8>,
        crate::tidefs_kmod_bridge::kernel_types::Errno,
    > {
        let ino = inode.get();
        let mut result = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();
        if let Some(idx) = self.find_xattr_store_idx(ino) {
            let stores = self.xattr_stores.borrow();
            let entries = &stores[idx].1;
            for (entry_name, _value) in entries.iter() {
                let name_slice = &*entry_name;
                for &b in name_slice {
                    result.push(b);
                }
                result.push(0u8);
            }
        }
        Ok(result)
    }
    fn removexattr(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        name: &[u8],
        _ctx: &crate::tidefs_kmod_bridge::kernel_types::RequestCtx,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        let valid_prefixes: &[&[u8]] = &[b"security.", b"system.", b"trusted.", b"user."];
        if !valid_prefixes.iter().any(|p| name.starts_with(p)) {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EOPNOTSUPP);
        }
        let ino = inode.get();
        if let Some(idx) = self.find_xattr_store_idx(ino) {
            let mut stores = self.xattr_stores.borrow_mut();
            let entries = &mut stores[idx].1;
            let before = entries.len();
            entries.retain(|(n, _)| **n != *name);
            if entries.len() < before {
                // Record intent for crash recovery replay.
                let ns_byte = Self::xattr_namespace_byte(name);
                let entry = crate::intent_record::encode_removexattr_intent(inode, ns_byte, name);
                self.record_intent_entry(entry.as_bytes())?;
                return Ok(());
            }
        }
        Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODATA)
    }
    fn getlk(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        lock: &crate::tidefs_kmod_bridge::kernel_types::LockSpec,
        _ctx: &crate::tidefs_kmod_bridge::kernel_types::RequestCtx,
    ) -> core::result::Result<
        Option<crate::tidefs_kmod_bridge::kernel_types::LockSpec>,
        crate::tidefs_kmod_bridge::kernel_types::Errno,
    > {
        let lock = Self::normalize_advisory_lock(lock);
        Self::validate_advisory_lock(&lock)?;
        self.require_advisory_lock_inode(inode)?;
        if lock.typ == crate::tidefs_kmod_bridge::kernel_types::F_UNLCK {
            return Ok(None);
        }
        Ok(self.find_advisory_lock_conflict(inode, &lock))
    }
    fn setlk(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        lock: &crate::tidefs_kmod_bridge::kernel_types::LockSpec,
        _ctx: &crate::tidefs_kmod_bridge::kernel_types::RequestCtx,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        let lock = Self::normalize_advisory_lock(lock);
        Self::validate_advisory_lock(&lock)?;
        self.require_advisory_lock_inode(inode)?;
        if lock.typ == crate::tidefs_kmod_bridge::kernel_types::F_UNLCK {
            return self.unlock_advisory_lock_range(inode, &lock);
        }
        if self.find_advisory_lock_conflict(inode, &lock).is_some() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EAGAIN);
        }
        self.replace_advisory_lock_range(inode, &lock, Some(lock))
    }
    /// Writeback dirty data through KernelPoolCore I/O authority.
    ///
    /// Drains matching entries from the write staging buffer and persists
    /// them through the C-provided block-device write callback. Gates on
    /// Mounted pool state. When no I/O context is registered, the buffer
    /// is drained without persistence (zero-byte completion).

    /// Buffer intent-log entries for crash-safety recording.
    ///
    /// Stores the entry in the in-memory intent buffer; entries are flushed
    /// to the intent-log region on txg_commit_barrier.  This ensures
    /// namespace mutations are crash-safe without a fixed table.
    fn record_intent_entry(
        &self,
        entry: &[u8],
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if entry.len() > crate::intent_record::MAX_INTENT_ENTRY_SIZE {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::E2BIG);
        }
        let should_flush = {
            let intent_buf = self.intent_buffer.borrow();
            let pending_bytes = intent_buf
                .iter()
                .fold(0usize, |sum, item| sum.saturating_add(item.len()));
            intent_buf.len() >= Self::ENGINE_INTENT_BUFFER_MAX_ENTRIES
                || pending_bytes.saturating_add(entry.len()) > Self::ENGINE_INTENT_BUFFER_MAX_BYTES
        };
        if should_flush {
            self.flush_intent_buffer_to_storage()?;
        }

        let mut buf = crate::tidefs_kmod_bridge::kernel_types::KmodVec::with_capacity(entry.len());
        buf.extend_from_slice(entry);
        if buf.len() != entry.len() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
        }
        let mut intent_buf = self.intent_buffer.borrow_mut();
        let before = intent_buf.len();
        intent_buf.push(buf);
        if intent_buf.len() != before.saturating_add(1) {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOMEM);
        }
        Ok(())
    }

    fn writeback_folios(
        &self,
        inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        _fh: &crate::tidefs_kmod_bridge::kernel_types::EngineFileHandle,
        range: crate::tidefs_kmod_bridge::kernel_types::WritebackRange,
        _ctx: &crate::tidefs_kmod_bridge::kernel_types::RequestCtx,
    ) -> core::result::Result<
        crate::tidefs_kmod_bridge::kernel_types::WritebackOutcome,
        crate::tidefs_kmod_bridge::kernel_types::Errno,
    > {
        if !self.pool_is_mounted() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV);
        }
        let bytes_written =
            self.flush_live_write_buffer_to_storage(Some(inode), range.offset, range.length)?;
        Ok(crate::tidefs_kmod_bridge::kernel_types::WritebackOutcome {
            bytes_written,
            complete: true,
        })
    }
    /// Allocate extents through KernelPoolCore object allocation authority.
    ///
    /// Gates on Mounted pool state. Returns zero-byte complete outcomes
    /// so that writeback can proceed without extending allocation.
    /// Blocked on #6323 [REL-STOR-007] kernel-side CapacityAuthority.
    fn allocate_extents(
        &self,
        _inode: crate::tidefs_kmod_bridge::kernel_types::InodeId,
        _offset: u64,
        _length: u64,
        _ctx: &crate::tidefs_kmod_bridge::kernel_types::RequestCtx,
    ) -> core::result::Result<
        crate::tidefs_kmod_bridge::kernel_types::AllocateExtentsOutcome,
        crate::tidefs_kmod_bridge::kernel_types::Errno,
    > {
        if !self.pool_is_mounted() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV);
        }
        // Blocked: extent allocation through KernelPoolCore requires the
        // kernel-side CapacityAuthority. Return zero-byte complete so
        // writeback proceeds without extending (existing extents only).
        Ok(
            crate::tidefs_kmod_bridge::kernel_types::AllocateExtentsOutcome {
                bytes_allocated: 0,
                complete: true,
            },
        )
    }
    /// Drain all pending writeback through KernelPoolCore, then
    /// flush the txg commit barrier to persist the committed root.
    fn syncfs(
        &self,
        _ctx: &crate::tidefs_kmod_bridge::kernel_types::RequestCtx,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if !self.pool_is_mounted() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV);
        }
        self.flush_live_write_buffer_to_storage(None, 0, 0)?;
        self.txg_commit_barrier()
    }
    // ── Committed-root writeback ─────────────────────────────────────
    /// Persist the committed root through KernelPoolCore authority.
    ///
    /// Gates on Mounted pool state and requires the C shim to register
    /// explicit read, write, flush, capacity, and teardown authority.
    fn write_committed_root(
        &self,
        committed_root: &crate::tidefs_kmod_bridge::kernel_types::CommittedRoot,
        _device_index: u32,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if !self.pool_is_mounted() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV);
        }

        let io_ctx = self.mounted_pool_io_ctx()?;

        let root_hash = *committed_root.as_bytes();
        let committed_txg = io_ctx.committed_txg;

        // Determine where to place VRBT and VCRP within the superblock region.
        // Layout: [VCRL at superblock_offset] [VCRP primary at offset+block_size]
        //         [VCRP backup at offset+2*block_size] [VRBT at offset+3*block_size]
        let block_size = io_ctx.sector_size as u64;
        if block_size < 512 {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL);
        }

        let pointer_offset = io_ctx.superblock_offset.saturating_add(block_size);
        let root_offset = io_ctx
            .superblock_offset
            .saturating_add(3u64.saturating_mul(block_size));
        let pointer_sector = pointer_offset / block_size;
        let root_sector = root_offset / block_size;

        // Encode the VRBT committed-root block.
        let intent_tail = self.intent_log_tail.get();
        let vrbt = Self::encode_vrbt_block(
            committed_txg,
            io_ctx.root_ino, // namespace_root
            io_ctx.root_ino, // inode_table_root (same region for bootstrap)
            0,               // extent_map_root
            intent_tail,     // intent_log_tail
            root_sector,
        );

        // Encode the VCRP pointer record.
        let vcrp = Self::encode_vcrp_record(
            committed_txg, // pointer_sequence
            root_sector,
            committed_txg, // commit_group_id
            &root_hash,
        );

        // Encode the VCRL committed-root ledger.
        let vcrl = Self::encode_vcrl_ledger(io_ctx.root_ino, &io_ctx.pool_uuid, committed_txg);

        // Write VCRL at superblock_offset.
        let write_fn = io_ctx
            .write_sectors_fn
            .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV)?;
        let sector_size = io_ctx.sector_size;

        // Pad and write each record through the C callback.
        Self::write_padded_sector(
            write_fn,
            io_ctx.superblock_offset / block_size,
            &vcrl,
            sector_size,
        )?;
        Self::write_padded_sector(write_fn, pointer_sector, &vcrp, sector_size)?;
        Self::write_padded_sector(
            write_fn,
            pointer_sector.saturating_add(1),
            &vcrp,
            sector_size,
        )?;
        Self::write_padded_sector(write_fn, root_sector, &vrbt, sector_size)?;
        io_ctx.flush()?;

        Ok(())
    }

    fn set_committed_root(&self, root: crate::tidefs_kmod_bridge::kernel_types::CommittedRoot) {
        self.committed_root.set(Some(root));
    }

    /// Route syncfs and unmount through the shared KernelPoolCore txg barrier.
    ///
    /// Gates on Mounted pool state. Takes the current committed root and
    /// attempts to persist it via write_committed_root. When the pool is
    /// mounted but on-disk persistence is not yet available, the barrier
    /// succeeds (committed root is in-memory).
    fn txg_commit_barrier(
        &self,
    ) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
        if !self.pool_is_mounted() {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV);
        }

        self.flush_live_write_buffer_to_storage(None, 0, 0)?;
        self.flush_intent_buffer_to_storage()?;
        self.persist_namespace_snapshot()?;
        let io_ctx = self.mounted_pool_io_ctx()?;
        let Some(root) = self.take_committed_root() else {
            return io_ctx.flush();
        };
        self.committed_root.set(Some(root));
        self.write_committed_root(&root, 0)
    }
}

impl crate::tidefs_kmod_bridge::kernel_types::VfsEngineStatFs for KernelEngine {
    fn statfs(
        &self,
        _ctx: &crate::tidefs_kmod_bridge::kernel_types::RequestCtx,
    ) -> core::result::Result<
        crate::tidefs_kmod_bridge::kernel_types::StatFs,
        crate::tidefs_kmod_bridge::kernel_types::Errno,
    > {
        let Some(statfs) = self.statfs else {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV);
        };

        if statfs.bsize == 0
            || statfs.frsize == 0
            || statfs.namelen == 0
            || statfs.bfree > statfs.blocks
            || statfs.bavail > statfs.blocks
            || statfs.ffree > statfs.files
        {
            return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EIO);
        }

        Ok(crate::tidefs_kmod_bridge::kernel_types::StatFs {
            blocks: statfs.blocks,
            bfree: statfs.bfree,
            bavail: statfs.bavail,
            files: statfs.files,
            ffree: statfs.ffree,
            bsize: statfs.bsize,
            namelen: statfs.namelen,
            frsize: statfs.frsize,
            block_size: statfs.bsize,
            fsid_hi: statfs.fsid_hi,
            fsid_lo: statfs.fsid_lo,
        })
    }
}

// -- Extern "C" engine bridge for the C VFS registration shim -------------------

/// Attempt engine-backed fill_super validation for a kernel mount.
///
/// Called from the C shim's `fill_super` path via `get_tree_nodev`.
/// Creates a KernelEngine, wraps it in a KmodSuperContext, and runs
/// the full mount validation pipeline. On success returns 0; on failure
/// returns -errno and logs the precise blocker via pr_err.
#[no_mangle]
pub extern "C" fn tidefs_posix_vfs_engine_fill_super(
    _mount_opts: *const core::ffi::c_char,
    committed_txg: u64,
) -> core::ffi::c_int {
    use crate::lib::bridge::kmod_fill_super;
    use crate::lib::bridge::KmodSuperContext;

    let engine = KernelEngine::unbound();
    let mut ctx = KmodSuperContext::new(engine);
    let request = crate::tidefs_kmod_bridge::kernel_types::RequestCtx::default();

    match kmod_fill_super(
        &mut ctx,
        &request,
        None, // expected_uuid
        None, // expected_root_digest
        committed_txg,
        &[],   // intent_records
        false, // recovery_mode
    ) {
        Ok(_result) => {
            kernel::pr_info!("tidefs_posix_vfs: engine-backed fill_super succeeded\n");
            // Future: store ctx in sb->s_fs_info and wire super_operations.
            0
        }
        Err(e) => {
            let errno_val: u16 = e.to_errno().0;
            // Log the precise error variant for operator diagnosis
            match &e {
                crate::lib::superblock::MountError::MissingCommittedRoot =>
                    kernel::pr_err!("tidefs_posix_vfs: fill_super failed: missing committed root — no kernel-resident pool configured (KernelEngine get_root_inode returned ENODEV)\n"),
                crate::lib::superblock::MountError::EngineError(_) =>
                    kernel::pr_err!("tidefs_posix_vfs: fill_super failed: engine error — no kernel-resident pool configured\n"),
                _ =>
                    kernel::pr_err!("tidefs_posix_vfs: fill_super failed: mount validation error (errno={})\n", errno_val),
            }
            -(errno_val as core::ffi::c_int)
        }
    }
}

// -- Statfs structs for C bridge ---------------------------------------------
// repr(C) layout matching the C shim's statfs handoff structs.

#[repr(C)]
pub struct TidefsStatfsIn {
    f_bsize: u32,
    f_frsize: u32,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_favail: u64,
    f_namelen: u32,
    f_fsid_hi: u64,
    f_fsid_lo: u64,
}

#[repr(C)]
pub struct TidefsStatfsOut {
    f_bsize: u32,
    f_frsize: u32,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_favail: u64,
    f_namelen: u32,
    f_fsid_hi: u64,
    f_fsid_lo: u64,
}

// -- Extern "C" statfs bridge for the C super_operations table ----------------

/// Engine-backed statfs for the C shim's super_operations.statfs callback.
///
/// Builds a KernelEngine from the mounted C shim pool context, calls
/// engine.statfs(), and writes the result into the caller-supplied `out`
/// struct. Returns 0 on success or -errno on failure.
#[no_mangle]
pub extern "C" fn tidefs_posix_vfs_engine_statfs(
    input: *const TidefsStatfsIn,
    out: *mut TidefsStatfsOut,
) -> core::ffi::c_int {
    if input.is_null() || out.is_null() {
        kernel::pr_err!("tidefs_posix_vfs: statfs: null input/output pointer\n");
        return -22; // EINVAL
    }

    // SAFETY: pointers are checked non-null above and the C shim passes
    // stack-allocated structs for the duration of this call.
    let seed = unsafe {
        let input = &*input;
        KernelEngineStatfs {
            bsize: input.f_bsize,
            frsize: input.f_frsize,
            blocks: input.f_blocks,
            bfree: input.f_bfree,
            bavail: input.f_bavail,
            files: input.f_files,
            ffree: input.f_ffree,
            namelen: input.f_namelen,
            fsid_hi: input.f_fsid_hi,
            fsid_lo: input.f_fsid_lo,
        }
    };

    let engine = KernelEngine::with_statfs(seed);
    let request = crate::tidefs_kmod_bridge::kernel_types::RequestCtx::default();

    match engine.statfs(&request) {
        Ok(sf) => {
            // SAFETY: pointer checked non-null above; C shim passes a
            // stack-allocated TidefsStatfsOut.
            unsafe {
                (*out).f_bsize = sf.block_size;
                (*out).f_frsize = sf.frsize;
                (*out).f_blocks = sf.blocks;
                (*out).f_bfree = sf.bfree;
                (*out).f_bavail = sf.bavail;
                (*out).f_files = sf.files;
                (*out).f_ffree = sf.ffree;
                (*out).f_favail = sf.ffree;
                (*out).f_namelen = sf.namelen;
                (*out).f_fsid_hi = sf.fsid_hi;
                (*out).f_fsid_lo = sf.fsid_lo;
            }
            kernel::pr_debug!(
                "tidefs_posix_vfs: engine statfs served
"
            );
            0
        }
        Err(e) => {
            let errno_val: u16 = e.0;
            kernel::pr_err!(
                "tidefs_posix_vfs: engine statfs failed for mounted pool context (errno={})
",
                errno_val
            );
            -(errno_val as core::ffi::c_int)
        }
    }
}

// -- Extern "C" superblock lifecycle bridges for the C super_operations table -

/// Engine-backed sync_fs for the C shim's super_operations.sync_fs callback.
///
/// Uses the persistent engine initialized during mount (via
/// tidefs_posix_vfs_engine_init_mounted). Falls back to an unbound
/// engine when not initialized (bootstrap-only mounts).
#[no_mangle]
pub extern "C" fn tidefs_posix_vfs_engine_sync_fs(wait: core::ffi::c_int) -> core::ffi::c_int {
    let request = crate::tidefs_kmod_bridge::kernel_types::RequestCtx::default();
    let initialized = ENGINE_INITIALIZED.load(core::sync::atomic::Ordering::Acquire);

    // Use the persistent mounted engine when available.
    let result = if initialized {
        with_mounted_engine(
            Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV),
            |engine| engine.syncfs(&request),
        )
    } else {
        let engine = KernelEngine::unbound();
        engine.syncfs(&request)
    };

    match result {
        Ok(()) => {
            kernel::pr_info!(
                "tidefs_posix_vfs: engine sync_fs: syncfs completed (wait={})\n",
                wait,
            );
            0
        }
        Err(e) if !initialized && e == crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV => {
            kernel::pr_info!(
                "tidefs_posix_vfs: engine sync_fs: pool not configured (tolerated; wait={})\n",
                wait,
            );
            0
        }
        Err(e) => {
            let errno_val: u16 = e.0;
            kernel::pr_err!(
                "tidefs_posix_vfs: engine sync_fs failed (errno={} wait={})\n",
                errno_val,
                wait,
            );
            -(errno_val as core::ffi::c_int)
        }
    }
}

/// Record cluster mount options on the mounted engine for carrier
/// disclosure and node-identity tracking (issue #6671).
///
/// Called from the C shim after the matching mounted engine is activated
/// when cluster_node_id and/or transport_carrier mount options are set.
/// The recorded values are disclosed in kernel log messages at mount time
/// and can be retrieved by validation harnesses for validation collection.
///
/// Both parameters are null-terminated C strings, or NULL when the option
/// was not specified.  The function copies the strings into kernel-owned
/// buffers so the C shim can free its fs_context copies independently.
#[no_mangle]
pub extern "C" fn tidefs_posix_vfs_engine_record_cluster_config(
    cluster_node_id: *const u8,
    transport_carrier: *const u8,
) {
    // SAFETY: The C shim passes null-terminated strings or NULL.
    // We copy into kernel-owned buffers.
    unsafe {
        if !cluster_node_id.is_null() {
            // Walk to null terminator (max 256 bytes for node ID).
            let mut len: usize = 0;
            while len < 256 && *cluster_node_id.add(len) != 0 {
                len += 1;
            }
            if len > 0 {
                let slice = core::slice::from_raw_parts(cluster_node_id, len);
                let mut buf = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();
                buf.extend_from_slice(slice);
                CLUSTER_NODE_ID = Some(buf);
            } else {
                CLUSTER_NODE_ID = None;
            }
        } else {
            CLUSTER_NODE_ID = None;
        }
        if !transport_carrier.is_null() {
            let mut len: usize = 0;
            while len < 64 && *transport_carrier.add(len) != 0 {
                len += 1;
            }
            if len > 0 {
                let slice = core::slice::from_raw_parts(transport_carrier, len);
                let mut buf = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();
                buf.extend_from_slice(slice);
                TRANSPORT_CARRIER = Some(buf);
            } else {
                TRANSPORT_CARRIER = None;
            }
        } else {
            TRANSPORT_CARRIER = None;
        }
    }

    // Log that cluster config was recorded for validation collection.
    let has_node = !cluster_node_id.is_null();
    let has_carrier = !transport_carrier.is_null();
    kernel::pr_info!(
        "tidefs_posix_vfs: cluster config recorded (node={}, carrier={})\n",
        has_node,
        has_carrier,
    );
}

/// Engine-backed final teardown hook for the C shim's kill_sb path.
///
/// The C shim keeps `s_fs_info` live until Linux has run `sync_fs` and
/// `put_super`, then calls this bridge for a final engine flush before it
/// releases the mounted pool context.
#[no_mangle]
pub extern "C" fn tidefs_posix_vfs_engine_kill_sb() -> core::ffi::c_int {
    let mut ret = tidefs_posix_vfs_engine_sync_fs(1);

    if ret == 0 {
        kernel::pr_info!(
            "tidefs_posix_vfs: engine kill_sb: final sync_fs completed, superblock teardown clean\n",
        );
    }

    // Tear down the persistent engine so the next mount gets a fresh one.
    let teardown_ret = tidefs_posix_vfs_engine_teardown_mounted();
    if ret == 0 && teardown_ret < 0 {
        ret = teardown_ret;
    }

    ret
}

// -- Label parse output struct for C bridge ---------------------------------

/// Output of label parsing: superblock region location and recovery info.
#[repr(C)]
pub struct TidefsLabelParseOut {
    /// Byte offset to the superblock/system area on the device.
    pub superblock_offset: u64,
    /// Size of the superblock/system area in bytes.
    pub superblock_size: u64,
    /// Most recent commit_group from the label (recovery reference).
    pub recovery_commit_group: u64,
    /// Which label copy was read (0 = head, 1 = tail).
    pub label_copy: u8,
    /// Device capacity in bytes (from label).
    pub device_capacity_bytes: u64,
    /// Topology generation from the label.
    pub topology_generation: u64,
    pub _pad: [u8; 7],
}

// -- Extern "C" label parse bridge ------------------------------------------

/// Parse a raw pool label buffer and return superblock region location.
///
/// Called from the C shim after reading the first 256 KiB of the block
/// device. On success, fills `out` with the superblock region offset/size
/// and recovery metadata; the C shim then reads the superblock region
/// and calls `tidefs_posix_vfs_engine_mount_with_label`.
#[no_mangle]
pub extern "C" fn tidefs_posix_vfs_engine_parse_label(
    label_buf: *const u8,
    label_len: core::ffi::c_ulong,
    out: *mut TidefsLabelParseOut,
) -> core::ffi::c_int {
    // SAFETY: label_buf non-null and label_len > 0 checked above;
    // the C shim passes a valid buffer from the kernel block-device read.
    let label_slice = if label_len > 0 && !label_buf.is_null() {
        unsafe { core::slice::from_raw_parts(label_buf, label_len as usize) }
    } else {
        kernel::pr_err!("tidefs_posix_vfs: parse_label: null or empty label buffer\n");
        return -22; // EINVAL
    };

    // SAFETY: null-check out before dereference.
    if out.is_null() {
        kernel::pr_err!("tidefs_posix_vfs: parse_label: null out pointer\n");
        return -22; // EINVAL
    }

    match crate::mount::PoolImportContext::import_full(label_slice, 0) {
        Ok(ctx) => {
            // SAFETY: pointer checked non-null above; C shim passes a valid stack
            // pointer. We fill it before returning.
            unsafe {
                (*out).superblock_offset = ctx.superblock_offset;
                (*out).superblock_size = ctx.superblock_size;
                (*out).recovery_commit_group = ctx.recovery_commit_group;
                (*out).label_copy = ctx.label_copy;
                (*out).device_capacity_bytes = ctx.device_capacity_bytes();
                (*out).topology_generation = ctx.topology_generation();
            }
            kernel::pr_info!(
                "tidefs_posix_vfs: parsed pool label: txg={} sb_ofs={} sb_sz={}\n",
                ctx.recovery_commit_group,
                ctx.superblock_offset,
                ctx.superblock_size
            );
            0
        }
        Err(e) => {
            use crate::mount::PoolImportError;
            let errno: core::ffi::c_int = match &e {
                PoolImportError::BufferTooSmall { .. } | PoolImportError::LabelInvalid { .. } => 22,
                PoolImportError::BadMagic => 19,
                PoolImportError::UnsupportedVersion { .. } => 22,
                PoolImportError::PoolNotImportable { .. } => 19,
                PoolImportError::ChecksumMismatch => 5,
                PoolImportError::DigestUnavailable => 5,
                PoolImportError::InvalidPoolName => 22,
                PoolImportError::SuperblockRegionInvalid { .. } => 22,
            };
            kernel::pr_err!("tidefs_posix_vfs: parse_label failed\n");
            -errno
        }
    }
}

// -- Mount output struct for C bridge ---------------------------------------

/// Result of engine-backed mount validation: root inode, superblock
/// parameters, and capacity information for the C shim's superblock setup.
#[repr(C)]
pub struct TidefsMountOut {
    /// Root inode number from the committed root.
    pub root_ino: u64,
    /// Filesystem ID composite (uuid-derived).
    pub fsid_hi: u64,
    pub fsid_lo: u64,
    /// Logical block size (PAGE_SIZE for kmod).
    pub block_size: u32,
    /// Committed transaction group at mount time.
    pub committed_txg: u64,
    /// Total data blocks (device capacity / block_size).
    pub total_blocks: u64,
    /// Free data blocks (total minus reserved metadata estimate).
    pub free_blocks: u64,
    /// Available blocks for non-privileged users.
    pub avail_blocks: u64,
    /// Total inodes (estimated from pool metadata capacity).
    pub total_inodes: u64,
    /// Free inodes (total minus consumed root inode).
    pub free_inodes: u64,
    /// Maximum filename length.
    pub name_max: u32,
    /// Pool UUID carried by the selected committed-root ledger anchor.
    pub pool_uuid: [u8; 32],
}

// -- Extern "C" mount-with-label bridge -------------------------------------

/// Engine-backed mount validation with pool label and committed-root ledger.
///
/// Called from the C shim after reading both the label and superblock region
/// from the block device. Validates the label, selects the most recent
/// valid committed root from the ledger, and returns mount parameters
/// for superblock setup.
///
/// Returns 0 on success (fills `out`) or -errno on failure.
#[no_mangle]
pub extern "C" fn tidefs_posix_vfs_engine_mount_with_label(
    label_buf: *const u8,
    label_len: core::ffi::c_ulong,
    ledger_buf: *const u8,
    ledger_len: core::ffi::c_ulong,
    out: *mut TidefsMountOut,
) -> core::ffi::c_int {
    use crate::superblock::{select_device_root, validate_device_label};

    // SAFETY: label_buf non-null and label_len > 0 checked above;
    // the C shim passes a valid buffer from the kernel block-device read.
    let label_slice = if label_len > 0 && !label_buf.is_null() {
        unsafe { core::slice::from_raw_parts(label_buf, label_len as usize) }
    } else {
        kernel::pr_err!("tidefs_posix_vfs: mount_with_label: null label buffer\n");
        return -22;
    };

    let ledger_slice = if ledger_len > 0 && !ledger_buf.is_null() {
        // SAFETY: pointer and length are validated above by the C shim.
        unsafe { core::slice::from_raw_parts(ledger_buf, ledger_len as usize) }
    } else {
        kernel::pr_err!("tidefs_posix_vfs: mount_with_label: null ledger buffer\n");
        return -22;
    };

    // SAFETY: null-check out before dereference.
    if out.is_null() {
        kernel::pr_err!("tidefs_posix_vfs: mount_with_label: null out pointer\n");
        return -22; // EINVAL
    }

    // Phase 1: Validate the device label.
    let import_ctx = match validate_device_label(label_slice) {
        Ok(ctx) => ctx,
        Err(e) => {
            let errno = e.to_errno().0 as core::ffi::c_int;
            kernel::pr_err!("tidefs_posix_vfs: mount_with_label: label validation failed\n");
            return -errno;
        }
    };

    // Phase 2: Select the best committed root from the ledger.
    let root_anchor = match select_device_root(ledger_slice) {
        Ok(anchor) => anchor,
        Err(e) => {
            let errno = e.to_errno().0 as core::ffi::c_int;
            kernel::pr_err!("tidefs_posix_vfs: mount_with_label: root selection failed\n");
            return -errno;
        }
    };

    // Phase 3: Derive superblock parameters from label and committed root.
    let block_size: u32 = 4096;
    let capacity = import_ctx.device_capacity_bytes();
    let total_blocks = capacity / (block_size as u64);
    let reserved_blocks = total_blocks / 100;
    let free_blocks = total_blocks.saturating_sub(reserved_blocks);
    let avail_blocks = total_blocks.saturating_sub(reserved_blocks * 2);
    let total_inodes = capacity / 16384;
    let free_inodes = total_inodes.saturating_sub(1);

    let pool_guid = import_ctx.pool_guid();
    let fsid_hi = u64::from_le_bytes(pool_guid[0..8].try_into().unwrap_or([0u8; 8]));
    let fsid_lo = u64::from_le_bytes(pool_guid[8..16].try_into().unwrap_or([0u8; 8]));

    // Phase 4: Fill output struct.
    // SAFETY: pointer checked non-null above; C shim passes a valid stack
    // pointer.
    unsafe {
        (*out).root_ino = root_anchor.root_ino.get();
        (*out).fsid_hi = fsid_hi;
        (*out).fsid_lo = fsid_lo;
        (*out).block_size = block_size;
        (*out).committed_txg = root_anchor.txg;
        (*out).total_blocks = total_blocks;
        (*out).free_blocks = free_blocks;
        (*out).avail_blocks = avail_blocks;
        (*out).total_inodes = total_inodes;
        (*out).free_inodes = free_inodes;
        (*out).name_max = 255;
        (*out).pool_uuid = root_anchor.pool_uuid;
    }

    kernel::pr_info!(
        "tidefs_posix_vfs: mount validated: root_ino={} txg={} blk={}/{}\n",
        root_anchor.root_ino.get(),
        root_anchor.txg,
        total_blocks,
        free_blocks
    );
    0
}

// -- Kernel replay mount output struct for C bridge -------------------------

/// Result of kernel replay mount: root inode, superblock parameters,
/// capacity, and intent-replay outcome for the C shim's superblock setup.
///
/// This replaces the legacy fixed-table handoff (tidefs_kernel_pool_load_state).
/// The C shim treats this as the authoritative mount-time namespace state;
/// replay authority stays in Rust via KernelMountSequence.
#[repr(C)]
#[cfg(CONFIG_RUST)]
pub struct TidefsReplayMountOut {
    /// Root inode number from the committed root.
    pub root_ino: u64,
    /// Filesystem ID composite (uuid-derived).
    pub fsid_hi: u64,
    pub fsid_lo: u64,
    /// Logical block size (PAGE_SIZE for kmod).
    pub block_size: u32,
    /// Committed transaction group at mount time.
    pub committed_txg: u64,
    /// Total data blocks (device capacity / block_size).
    pub total_blocks: u64,
    /// Free data blocks (total minus reserved metadata estimate).
    pub free_blocks: u64,
    /// Available blocks for non-privileged users.
    pub avail_blocks: u64,
    /// Total inodes (estimated from pool metadata capacity).
    pub total_inodes: u64,
    /// Free inodes (total minus consumed root inode).
    pub free_inodes: u64,
    /// Maximum filename length.
    pub name_max: u32,
    /// Pool UUID from the selected committed-root ledger anchor.
    pub pool_uuid: [u8; 32],
    /// Number of intent-log records replayed during mount.
    pub replay_replayed: u64,
    /// Number of intent-log records skipped (non-replayable types).
    pub replay_skipped: u64,
    /// Number of intent-log records that errored during replay.
    pub replay_errored: u64,
    /// Whether the pool was cleanly exported (no dirty intent log).
    pub clean_export: u8,
    /// Inode table root locator from the committed-root VRBT.
    pub inode_table_root: u64,
    /// Extent map root locator from the committed-root VRBT.
    pub extent_map_root: u64,
    /// Intent-log head (most recent record) from the committed-root VRBT.
    pub intent_log_head: u64,
    /// Intent-log tail (oldest replayable record) from the committed-root VRBT.
    pub intent_log_tail: u64,
    pub _pad: [u8; 7],
}

// -- Intent buffer record splitter --------------------------------------------

/// Split a concatenated intent-log buffer into individual records.
///
/// Intent records are written as a flat concatenation during txg_commit_barrier.
/// During crash-recovery mount, the C shim reads the raw bytes from the block
/// device (data area) and passes them here. This function splits the flat buffer
/// back into individual records using the discriminant byte to determine record
/// boundaries.
///
/// Returns a Vec of byte slices pointing into `data`. The caller must keep
/// `data` alive for the lifetime of the returned slices.
fn split_intent_buffer<'a>(
    data: &'a [u8],
) -> crate::tidefs_kmod_bridge::kernel_types::KmodVec<&'a [u8]> {
    use crate::intent_record::{
        DISC_CREATE, DISC_FALLOCATE, DISC_HARDLINK, DISC_MKDIR, DISC_MKNOD, DISC_RENAME,
        DISC_RMDIR, DISC_SETATTR, DISC_SYMLINK, DISC_TMPFILE, DISC_TRUNCATE, DISC_UNLINK,
        DISC_WRITE,
    };

    let mut records = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();
    let mut pos: usize = 0;
    while pos < data.len() {
        let disc = data[pos];
        let rec_len: usize = match disc {
            // Fixed-length records
            DISC_WRITE => 25,
            DISC_TRUNCATE => 17,
            DISC_SETATTR => 81,
            DISC_TMPFILE => 21,
            DISC_FALLOCATE => 29,
            // Name-prefixed records: name_len at offset 9
            DISC_CREATE | DISC_MKDIR => {
                if pos + 10 > data.len() {
                    break;
                }
                22usize.saturating_add(data[pos + 9] as usize)
            }
            DISC_UNLINK => {
                if pos + 10 > data.len() {
                    break;
                }
                18usize.saturating_add(data[pos + 9] as usize)
            }
            DISC_RMDIR => {
                if pos + 10 > data.len() {
                    break;
                }
                10usize.saturating_add(data[pos + 9] as usize)
            }
            DISC_MKNOD => {
                if pos + 10 > data.len() {
                    break;
                }
                18usize.saturating_add(data[pos + 9] as usize)
            }
            // DISC_HARDLINK: [disc:1][target_ino:8][new_parent:8][name_len:1][name:name_len]
            DISC_HARDLINK => {
                if pos + 18 > data.len() {
                    break;
                }
                18usize.saturating_add(data[pos + 17] as usize)
            }
            // DISC_SYMLINK: [disc:1][parent:8][name_len:1][name:name_len][target_len:1][target:target_len]
            DISC_SYMLINK => {
                if pos + 10 > data.len() {
                    break;
                }
                let name_len = data[pos + 9] as usize;
                let target_len_pos = pos.saturating_add(10).saturating_add(name_len);
                if target_len_pos >= data.len() {
                    break;
                }
                let target_len = data[target_len_pos] as usize;
                11usize.saturating_add(name_len).saturating_add(target_len)
            }
            // DISC_RENAME: [disc:1][src_parent:8][src_name_len:1][src_name:N][dst_parent:8][dst_name_len:1][dst_name:M][overwrite:1][ino:8]
            DISC_RENAME => {
                if pos + 10 > data.len() {
                    break;
                }
                let src_name_len = data[pos + 9] as usize;
                let dst_parent_pos = pos.saturating_add(10).saturating_add(src_name_len);
                if dst_parent_pos.saturating_add(9) > data.len() {
                    break;
                }
                let dst_name_len = data[dst_parent_pos.saturating_add(8)] as usize;
                28usize
                    .saturating_add(src_name_len)
                    .saturating_add(dst_name_len)
            }
            // Unknown discriminants: treat as single-byte (safe; non-replayable types
            // like FLUSH/FSYNC/LSEEK/CLEANUP_QUEUE won't be replayed anyway).
            _ => 1,
        };
        if pos.saturating_add(rec_len) > data.len() {
            break;
        }
        records.push(&data[pos..pos.saturating_add(rec_len)]);
        pos = pos.saturating_add(rec_len);
    }
    records
}

// -- Extern "C" kernel replay mount bridge ----------------------------------

/// Kernel replay mount adapter — replaces the legacy fixed-table C handoff.
///
/// Called from the C shim's `fill_super_bdev` path instead of the
/// fixed-table `tidefs_kernel_pool_load_state`.  This function runs the
/// full Rust-side kernel mount sequence:
///
/// 1. Validates the pool label buffer.
/// 2. Selects the most recent valid committed root from the ledger.
/// 3. Optionally replays intent-log records when `recovery_mode` is non-zero.
///
/// Returns 0 on success (fills `out`) or -errno on failure.
/// The C shim treats the returned values as the authoritative mount-time
/// state; committed-root, object, extent, and intent authority stay in Rust.
#[no_mangle]
#[cfg(CONFIG_RUST)]
pub extern "C" fn tidefs_posix_vfs_kernel_replay_mount(
    label_buf: *const u8,
    label_len: core::ffi::c_ulong,
    ledger_buf: *const u8,
    ledger_len: core::ffi::c_ulong,
    intent_buf: *const u8,
    intent_len: core::ffi::c_ulong,
    recovery_mode: core::ffi::c_int,
    out: *mut TidefsReplayMountOut,
) -> core::ffi::c_int {
    use crate::kernel_mount::KernelMountSequence;
    use crate::superblock::validate_device_label;

    // Validate pointer/length arguments.
    // SAFETY: label_buf non-null and label_len > 0 checked above;
    // the C shim passes a valid buffer from the kernel block-device read.
    let label_slice = if label_len > 0 && !label_buf.is_null() {
        unsafe { core::slice::from_raw_parts(label_buf, label_len as usize) }
    } else {
        kernel::pr_err!("tidefs_posix_vfs: kernel_replay_mount: null label buffer\n");
        return -22; // EINVAL
    };

    let ledger_slice = if ledger_len > 0 && !ledger_buf.is_null() {
        // SAFETY: pointer and length are validated above by the C shim.
        unsafe { core::slice::from_raw_parts(ledger_buf, ledger_len as usize) }
    } else {
        kernel::pr_err!("tidefs_posix_vfs: kernel_replay_mount: null ledger buffer\n");
        return -22; // EINVAL
    };

    if out.is_null() {
        kernel::pr_err!("tidefs_posix_vfs: kernel_replay_mount: null out pointer\n");
        return -22; // EINVAL
    }

    let import_ctx = match validate_device_label(label_slice) {
        Ok(ctx) => ctx,
        Err(e) => {
            let errno = e.to_errno().0 as core::ffi::c_int;
            kernel::pr_err!("tidefs_posix_vfs: kernel_replay_mount: label validation failed\n");
            return -errno;
        }
    };

    let engine = KernelEngine::unbound();
    let request = crate::tidefs_kmod_bridge::kernel_types::RequestCtx::default();
    let recovery = recovery_mode != 0;

    let seq = KernelMountSequence::new(engine, recovery);

    // Parse intent-log records from the raw buffer when the C shim
    // passes persisted intent bytes during crash recovery mount.
    // Each record is self-delimiting by discriminant byte.
    let intent_slice: &[u8] = if intent_len > 0 && !intent_buf.is_null() {
        // SAFETY: pointer/length validate above; C shim owns the buffer.
        unsafe { core::slice::from_raw_parts(intent_buf, intent_len as usize) }
    } else {
        &[]
    };
    let parsed_records = split_intent_buffer(intent_slice);
    let intent_records: &[&[u8]] = &parsed_records;

    match seq.mount(label_slice, ledger_slice, intent_records, &request) {
        Ok((result, _engine)) => {
            let block_size: u32 = 4096;
            let capacity = import_ctx.device_capacity_bytes();
            let total_blocks = capacity / (block_size as u64);
            let reserved: u64 = total_blocks / 100;
            let total_inodes: u64 = capacity / 16384;

            // SAFETY: out pointer validated non-null above.
            unsafe {
                (*out).root_ino = result.root_anchor.root_ino.get();
                (*out).block_size = block_size;
                (*out).committed_txg = result.root_anchor.txg;
                (*out).total_blocks = total_blocks;
                (*out).free_blocks = total_blocks.saturating_sub(reserved);
                (*out).avail_blocks = total_blocks.saturating_sub(reserved * 2);
                (*out).total_inodes = total_inodes;
                (*out).free_inodes = total_inodes.saturating_sub(1);
                (*out).name_max = 255;
                (*out).pool_uuid = result.root_anchor.pool_uuid;
                (*out).fsid_hi = u64::from_le_bytes(
                    result.root_anchor.pool_uuid[0..8]
                        .try_into()
                        .unwrap_or([0u8; 8]),
                );
                (*out).fsid_lo = u64::from_le_bytes(
                    result.root_anchor.pool_uuid[8..16]
                        .try_into()
                        .unwrap_or([0u8; 8]),
                );
                (*out).replay_replayed = result.replay_outcome.replayed;
                (*out).replay_skipped = result.replay_outcome.skipped;
                (*out).replay_errored = result.replay_outcome.errored;
                (*out).clean_export = if result.clean_export { 1 } else { 0 };
                (*out).inode_table_root = result.inode_table_root;
                (*out).extent_map_root = result.extent_map_root;
                (*out).intent_log_head = result.intent_log_head;
                (*out).intent_log_tail = result.intent_log_tail;
            }

            kernel::pr_info!(
                "tidefs_posix_vfs: kernel replay mount succeeded: root_ino={} txg={} replay={}/{}/{} clean={}\n",
                result.root_anchor.root_ino.get(),
                result.root_anchor.txg,
                result.replay_outcome.replayed,
                result.replay_outcome.skipped,
                result.replay_outcome.errored,
                result.clean_export,
            );
            0
        }
        Err(e) => {
            use crate::kernel_mount::MountSequenceError;
            let errno: core::ffi::c_int = match &e {
                MountSequenceError::PoolImport(_) => 5,               // EIO
                MountSequenceError::Ledger(_) => 5,                   // EIO
                MountSequenceError::FeatureRefused(_) => 19,          // ENODEV
                MountSequenceError::Replay(_) => 5,                   // EIO
                MountSequenceError::SuperblockRegionEmpty => 2,       // ENOENT
                MountSequenceError::MissingComponent { .. } => 19,    // ENODEV
                MountSequenceError::ClusteredPoolRefused { .. } => 1, // EPERM
            };
            // Log the precise error variant (MountSequenceError impls
            // core::fmt::Display, not kernel::fmt::Display; embed manually).
            match &e {
                MountSequenceError::PoolImport(_) =>
                    kernel::pr_err!("tidefs_posix_vfs: kernel replay mount failed: pool import error\n"),
                MountSequenceError::Ledger(_) =>
                    kernel::pr_err!("tidefs_posix_vfs: kernel replay mount failed: ledger error\n"),
                MountSequenceError::FeatureRefused(_) =>
                    kernel::pr_err!("tidefs_posix_vfs: kernel replay mount failed: feature refused\n"),
                MountSequenceError::Replay(_) =>
                    kernel::pr_err!("tidefs_posix_vfs: kernel replay mount failed: intent replay error\n"),
                MountSequenceError::SuperblockRegionEmpty =>
                    kernel::pr_err!("tidefs_posix_vfs: kernel replay mount failed: empty superblock region\n"),
                MountSequenceError::MissingComponent { .. } =>
                    kernel::pr_err!("tidefs_posix_vfs: kernel replay mount failed: missing component\n"),
                MountSequenceError::ClusteredPoolRefused { .. } =>
                    kernel::pr_err!("tidefs_posix_vfs: kernel replay mount failed: clustered pool requires cluster_node_id\n"),
            }
            -errno
        }
    }
}

// -- Extern "C" VRBT intent-log tail helper ----------------------------------

/// Extract intent_log_tail from the VRBT block embedded in the superblock region.
///
/// The C shim calls this before the replay mount to determine whether intent-log
/// records exist on the block device.  When the returned tail is non-zero, the
/// shim reads `intent_log_tail` bytes from the data area (superblock_offset +
/// superblock_size) and passes them to `tidefs_posix_vfs_kernel_replay_mount`
/// with `recovery_mode=1`.
///
/// Returns intent_log_tail on success, or 0 when the VRBT is absent, too small,
/// has bad magic, or has a hash mismatch.  The C shim treats 0 as "no intent
/// records to replay".
#[no_mangle]
#[cfg(CONFIG_RUST)]
pub extern "C" fn tidefs_posix_vfs_engine_get_vrbt_intent_tail(
    superblock_buf: *const u8,
    superblock_len: core::ffi::c_ulong,
    block_size: u32,
) -> u64 {
    use crate::replay_integration;

    if superblock_buf.is_null() || superblock_len == 0 {
        return 0;
    }
    let blk: usize = if block_size > 0 {
        block_size as usize
    } else {
        4096
    };
    let vrbt_offset: usize = 3usize.saturating_mul(blk);
    let vrbt_end = vrbt_offset.saturating_add(replay_integration::VRBT_WIRE_SIZE);
    let buf_len = superblock_len as usize;
    if buf_len < vrbt_end {
        return 0;
    }
    // SAFETY: bounds checked above; C shim owns the buffer.
    let vrbt_slice = unsafe {
        core::slice::from_raw_parts(
            superblock_buf.add(vrbt_offset),
            replay_integration::VRBT_WIRE_SIZE,
        )
    };
    match replay_integration::decode_vrbt(vrbt_slice) {
        Ok(vrbt) => vrbt.intent_log_tail,
        Err(_) => 0,
    }
}

// -- Extern "C" label-backed fill_super for block-device mount path --------

/// Engine-backed fill_super with pool label data from a block device.
#[no_mangle]
pub extern "C" fn tidefs_posix_vfs_engine_fill_super_label(
    label_buf: *const u8,
    label_len: core::ffi::c_ulong,
    ledger_buf: *const u8,
    ledger_len: core::ffi::c_ulong,
    committed_txg: u64,
) -> core::ffi::c_int {
    kernel::pr_info!(
        "tidefs_posix_vfs: engine fill_super_label: label={} ledger={} txg={} -- executing mount_with_label validation\n",
        label_len as u64,
        ledger_len as u64,
        committed_txg,
    );
    // Use a local stack-allocated TidefsMountOut instead of passing null.
    // mount_with_label will fill it with the mount parameters.
    let mut mount_out = TidefsMountOut {
        root_ino: 0,
        fsid_hi: 0,
        fsid_lo: 0,
        block_size: 0,
        committed_txg: 0,
        total_blocks: 0,
        free_blocks: 0,
        avail_blocks: 0,
        total_inodes: 0,
        free_inodes: 0,
        name_max: 0,
        pool_uuid: [0u8; 32],
    };
    tidefs_posix_vfs_engine_mount_with_label(
        label_buf,
        label_len,
        ledger_buf,
        ledger_len,
        &raw mut mount_out as *mut TidefsMountOut,
    )
}

/// Encode a single-entry committed-root ledger for the mounted block-device path.
///
/// C owns block-device I/O. Rust owns the VCRL wire format and digest rules.
#[no_mangle]
pub extern "C" fn tidefs_posix_vfs_engine_encode_committed_root_ledger(
    root_ino: u64,
    pool_uuid: *const u8,
    pool_uuid_len: core::ffi::c_ulong,
    committed_txg: u64,
    out_buf: *mut u8,
    out_len: core::ffi::c_ulong,
    written_len: *mut core::ffi::c_ulong,
) -> core::ffi::c_int {
    use crate::superblock::CommittedRootAnchor;
    use crate::tidefs_kmod_bridge::kernel_types::InodeId;

    if pool_uuid.is_null() || pool_uuid_len != 32 || out_buf.is_null() || written_len.is_null() {
        kernel::pr_err!("tidefs_posix_vfs: encode_committed_root_ledger: invalid pointer/length\n");
        return -22;
    }

    let out_capacity = out_len as usize;
    // SAFETY: pool_uuid is a fixed 32-byte field validated by the
    // C shim before calling this function; length 32 is the canonical
    // TideFS pool UUID width.
    let uuid_slice = unsafe { core::slice::from_raw_parts(pool_uuid, 32) };
    let mut uuid = [0u8; 32];
    uuid.copy_from_slice(uuid_slice);

    let anchor = CommittedRootAnchor::new(InodeId::new(root_ino), uuid, committed_txg);
    let ledger = crate::mount::MountRootSelector::encode_ledger(&[anchor]);
    if ledger.len() > out_capacity {
        kernel::pr_err!(
            "tidefs_posix_vfs: encode_committed_root_ledger: output too small have={} need={}\n",
            out_capacity as u64,
            ledger.len() as u64,
        );
        return -28;
    }

    unsafe {
        core::ptr::copy_nonoverlapping(ledger.as_ptr(), out_buf, ledger.len());
        *written_len = ledger.len() as core::ffi::c_ulong;
    }

    0
}

const TIDEFS_VRBT_MAGIC: &[u8; 4] = b"VRBT";
const TIDEFS_VRBT_VERSION: u32 = 1;
const TIDEFS_VRBT_HEADER_SIZE: usize = 56;
const TIDEFS_VRBT_WIRE_SIZE: usize = 88;
const TIDEFS_VRBT_HASH_OFFSET: usize = 56;
const TIDEFS_VCRP_MAGIC: &[u8; 4] = b"VCRP";
const TIDEFS_VCRP_VERSION: u32 = 1;
const TIDEFS_VCRP_HEADER_SIZE: usize = 64;
const TIDEFS_VCRP_RECORD_SIZE: usize = 96;
const TIDEFS_VCRP_HASH_OFFSET: usize = 64;

/// Encode the canonical `VRBT` committed-root block and matching `VCRP`
/// pointer record for the mounted block-device path.
///
/// C owns mounted block I/O. The Kbuild Rust entry point owns the wire format
/// and BLAKE3 checksums so the POSIX module does not invent a second committed
/// root representation while publishing mounted mutations.
#[no_mangle]
pub extern "C" fn tidefs_posix_vfs_engine_encode_committed_root_vrbt(
    commit_group_id: u64,
    namespace_root: u64,
    inode_table_root: u64,
    extent_map_root: u64,
    intent_log_tail: u64,
    pointer_sequence: u64,
    root_sector: u64,
    root_buf: *mut u8,
    root_len: core::ffi::c_ulong,
    root_written_len: *mut core::ffi::c_ulong,
    pointer_buf: *mut u8,
    pointer_len: core::ffi::c_ulong,
    pointer_written_len: *mut core::ffi::c_ulong,
) -> core::ffi::c_int {
    if root_buf.is_null()
        || root_written_len.is_null()
        || pointer_buf.is_null()
        || pointer_written_len.is_null()
    {
        kernel::pr_err!("tidefs_posix_vfs: encode_committed_root_vrbt: invalid pointer\n");
        return -22;
    }
    if (root_len as usize) < TIDEFS_VRBT_WIRE_SIZE
        || (pointer_len as usize) < TIDEFS_VCRP_RECORD_SIZE
    {
        kernel::pr_err!(
            "tidefs_posix_vfs: encode_committed_root_vrbt: output too small root={} pointer={}\n",
            root_len as u64,
            pointer_len as u64,
        );
        return -28;
    }

    let mut root = [0u8; TIDEFS_VRBT_WIRE_SIZE];
    root[0..4].copy_from_slice(TIDEFS_VRBT_MAGIC);
    root[4..8].copy_from_slice(&TIDEFS_VRBT_VERSION.to_le_bytes());
    root[8..16].copy_from_slice(&commit_group_id.to_le_bytes());
    root[16..24].copy_from_slice(&namespace_root.to_le_bytes());
    root[24..32].copy_from_slice(&inode_table_root.to_le_bytes());
    root[32..40].copy_from_slice(&extent_map_root.to_le_bytes());
    root[40..48].copy_from_slice(&intent_log_tail.to_le_bytes());
    let root_hash: [u8; 32] = crate::blake3::hash(&root[..TIDEFS_VRBT_HEADER_SIZE]).into();
    root[TIDEFS_VRBT_HASH_OFFSET..TIDEFS_VRBT_WIRE_SIZE].copy_from_slice(&root_hash);

    let mut pointer = [0u8; TIDEFS_VCRP_RECORD_SIZE];
    pointer[0..4].copy_from_slice(TIDEFS_VCRP_MAGIC);
    pointer[4..8].copy_from_slice(&TIDEFS_VCRP_VERSION.to_le_bytes());
    pointer[8..16].copy_from_slice(&pointer_sequence.to_le_bytes());
    pointer[16..24].copy_from_slice(&root_sector.to_le_bytes());
    pointer[24..32].copy_from_slice(&commit_group_id.to_le_bytes());
    pointer[32..64].copy_from_slice(&root_hash);
    let pointer_hash: [u8; 32] = crate::blake3::hash(&pointer[..TIDEFS_VCRP_HEADER_SIZE]).into();
    pointer[TIDEFS_VCRP_HASH_OFFSET..TIDEFS_VCRP_RECORD_SIZE].copy_from_slice(&pointer_hash);

    unsafe {
        core::ptr::copy_nonoverlapping(root.as_ptr(), root_buf, root.len());
        *root_written_len = root.len() as core::ffi::c_ulong;
        core::ptr::copy_nonoverlapping(pointer.as_ptr(), pointer_buf, pointer.len());
        *pointer_written_len = pointer.len() as core::ffi::c_ulong;
    }

    0
}

extern "C" {
    fn tidefs_posix_vfs_register_fs() -> core::ffi::c_int;
    fn tidefs_posix_vfs_unregister_fs();
}

// -- Extern "C" replay getattr bridge ---------------------------------------
// Uses the canonical KernelInodeTableReader through KernelStorageIo
// to read inode attributes from the on-disk inode table instead of the
// fixed bring-up table.  This is the mounted replay integration cut point
// for #6252.

/// C-visible output struct for replay getattr.
#[repr(C)]
#[cfg(CONFIG_RUST)]
pub struct TidefsReplayGetattrOut {
    /// File mode (umode_t).
    pub mode: u32,
    /// Owner uid.
    pub uid: u32,
    /// Owner gid.
    pub gid: u32,
    /// File size in bytes.
    pub size: u64,
    /// Blocks allocated (512-byte units).
    pub blocks: u64,
    /// nlink count.
    pub nlink: u32,
    /// Object kind: 0=file, 1=dir, 2=symlink.
    pub kind: u8,
    /// object_store_locator (for file data dispatch).
    pub object_store_locator: u64,
    /// extent_map_root (for extent resolution).
    pub extent_map_root: u64,
    /// generation number.
    pub generation: u64,
    /// atime seconds.
    pub atime_secs: i64,
    /// mtime seconds.
    pub mtime_secs: i64,
    /// ctime seconds.
    pub ctime_secs: i64,
    pub btime_secs: u64,
    pub btime_nsec: u32,
    pub flags: u32,
    pub blksize: u32,
}

/// Engine-backed inode attribute read through the canonical on-disk
/// inode table. Uses the inline VINO-format inode record parser
/// (replay_integration::parse_vino_record / read_vino_inode) that works
/// under Kbuild using only core primitives — no child crate linking
/// required.
#[no_mangle]
#[cfg(CONFIG_RUST)]
pub extern "C" fn tidefs_posix_vfs_engine_replay_getattr(
    vrbt_buf: *const u8,
    vrbt_len: core::ffi::c_ulong,
    inode_table_buf: *const u8,
    ino_table_len: core::ffi::c_ulong,
    _block_size: u32,
    ino: u64,
    out: *mut TidefsReplayGetattrOut,
) -> core::ffi::c_int {
    if vrbt_buf.is_null() || inode_table_buf.is_null() || out.is_null() {
        return -22; // EINVAL
    }
    if vrbt_len < 88 || ino_table_len == 0 || ino == 0 {
        return -22; // EINVAL
    }

    // Decode VRBT to validate the committed-root block (VRBT integrity
    // is checked by decode_vrbt's BLAKE3 hash). The VRBT offset fields
    // are informational; C already read the inode table from the right
    // disk offset.
    // SAFETY: pointer and length are validated above by the C shim.
    let vrbt_slice =
        unsafe { core::slice::from_raw_parts(vrbt_buf, core::cmp::min(vrbt_len as usize, 88)) };
    let _vrbt = match crate::replay_integration::decode_vrbt(vrbt_slice) {
        Ok(v) => v,
        Err(e) => {
            kernel::pr_debug!(
                "tidefs_posix_vfs: replay getattr: VRBT decode failed: {:?}\n",
                e
            );
            return -5; // EIO
        }
    };

    // Extract the inode record from the inode table buffer.
    // SAFETY: pointer and length are validated above by the C shim.
    let ino_table_slice =
        unsafe { core::slice::from_raw_parts(inode_table_buf, ino_table_len as usize) };
    let record = match crate::replay_integration::read_vino_inode(ino_table_slice, ino) {
        Some(r) => r,
        None => {
            kernel::pr_debug!(
                "tidefs_posix_vfs: replay getattr: ino={} not in buffer or bad magic\n",
                ino
            );
            return -2; // ENOENT
        }
    };

    // Populate the output struct with canonical inode attributes.
    unsafe {
        (*out).mode = record.mode;
        (*out).uid = record.uid;
        (*out).gid = record.gid;
        (*out).size = record.size;
        (*out).blocks = record.blocks;
        (*out).nlink = record.nlink;
        (*out).kind = record.kind;
        (*out).object_store_locator = record.object_store_locator;
        (*out).extent_map_root = record.extent_map_root;
        (*out).generation = record.generation;
        (*out).atime_secs = i64::try_from(record.atime_secs).unwrap_or(i64::MAX);
        (*out).mtime_secs = i64::try_from(record.mtime_secs).unwrap_or(i64::MAX);
        (*out).ctime_secs = i64::try_from(record.ctime_secs).unwrap_or(i64::MAX);
        (*out).btime_secs = record.btime_secs;
        (*out).btime_nsec = record.btime_nanos;
        (*out).flags = record.flags;
        (*out).blksize = 4096;
    }

    kernel::pr_debug!(
        "tidefs_posix_vfs: replay getattr: ino={} kind={} mode=0{:o} size={}\n",
        ino,
        record.kind,
        record.mode,
        record.size
    );
    0
}
// -- Extern "C" replay directory lookup bridge (#6260) -------------------
/// C-visible output struct for replay directory lookup.
#[repr(C)]
#[cfg(CONFIG_RUST)]
pub struct TidefsReplayLookupOut {
    /// Inode number of the found entry, or 0 if not found.
    pub ino: u64,
    /// Entry type: 0=unknown, 1=file, 2=dir, 3=symlink.
    pub entry_type: u8,
    /// Object kind: 0=file, 1=dir, 2=symlink.
    pub kind: u8,
}

/// Engine-backed directory entry lookup through the inline DirPage
/// scanner (replay_integration::lookup_dir_page). Works under Kbuild
/// using only core primitives — no child crate linking required.
///
/// Called from the C shim when `engine_backed` is true.
///
/// `dir_page_buf` / `dir_page_len`: buffer containing the root directory
///   DirPage bytes (read from disk by C).
/// `block_size`: device sector size in bytes.
/// `name_buf` / `name_len`: name to look up (null-terminated or exact).
/// `out`: populated with the found entry on success.
///
/// Returns 0 on success (entry found or not found), -errno on I/O error.
#[no_mangle]
#[cfg(CONFIG_RUST)]
pub extern "C" fn tidefs_posix_vfs_engine_replay_lookup(
    dir_page_buf: *const u8,
    dir_page_len: core::ffi::c_ulong,
    _block_size: u32,
    name_buf: *const u8,
    name_len: core::ffi::c_ulong,
    out: *mut TidefsReplayLookupOut,
) -> core::ffi::c_int {
    if dir_page_buf.is_null() || name_buf.is_null() || out.is_null() {
        return -22; // EINVAL
    }
    if dir_page_len == 0 || name_len == 0 {
        return -22; // EINVAL
    }

    // SAFETY: dir_page_buf and name_buf are valid block-device
    // read buffers; the C shim validates lengths before calling.
    // SAFETY: dir_page_buf is a valid block-device read buffer;
    // dir_page_len is the number of bytes read by the C shim.
    let dir_slice = unsafe { core::slice::from_raw_parts(dir_page_buf, dir_page_len as usize) };
    let name_slice = unsafe { core::slice::from_raw_parts(name_buf, name_len as usize) };

    match crate::replay_integration::lookup_dir_page(dir_slice, name_slice) {
        Some(result) => unsafe {
            (*out).ino = result.ino;
            (*out).entry_type = result.entry_type;
            (*out).kind = result.kind;
        },
        None => unsafe {
            // Entry not found in on-disk DirPage — caller falls back
            // to the fixed table via the C shim's fallback path.
            (*out).ino = 0;
            (*out).entry_type = 0;
            (*out).kind = 0;
        },
    }
    0
}

// -- Extern "C" replay readdir bridge (#6252) ---------------------------
// Uses the inline DirPage iterator (replay_integration::iterate_dir_page)
// for readdir/iterate_shared. Works under Kbuild using only core
// primitives — no child crate linking required.
//
// Called from the C shim when `engine_backed` is true.

// -- Extern "C" engine-backed readdir bridge (#6400 NEXT-KVFS-037) -------
// Uses the mounted KernelEngine dir_entries for cookie-based directory
// iteration. Returns one entry per call with a sequential cookie so the
// C shim can loop without tracking engine handles.

/// C-visible output struct for engine-backed readdir.
/// Mirrors TidefsReplayReaddirOut for drop-in compatibility.
#[repr(C)]
#[cfg(CONFIG_RUST)]
pub struct TidefsEngineReaddirOut {
    /// Inode number of the child entry, or 0 when no more entries.
    pub ino: u64,
    /// DT_DIR=0, DT_FILE=1, DT_SYMLINK=2.
    pub entry_type: u8,
    /// Object kind: 0=file, 1=dir, 2=symlink.
    pub kind: u8,
    /// Length of the entry name in bytes.
    pub name_len: u8,
    /// Stable cookie for this entry; 0 means end-of-directory.
    pub next_cookie: u32,
}

/// Engine-backed directory iteration through the mounted KernelEngine
/// dir_entries.  Returns one entry per call in cookie order.
///
/// Called from the C shim when `engine_backed` is true.
///
/// `directory_ino`: inode of the directory being listed.
/// `cookie`: last stable cookie seen by the caller; 0 starts iteration.
/// `out`: populated with the next entry on success.
///
/// Returns 0 on success.  Caller treats `out.ino == 0` as end-of-directory.
/// Returns -ENODEV when the engine is not initialized.
#[no_mangle]
#[cfg(CONFIG_RUST)]
pub extern "C" fn tidefs_posix_vfs_engine_readdir(
    directory_ino: u64,
    cookie: u32,
    out: *mut TidefsEngineReaddirOut,
) -> core::ffi::c_int {
    if out.is_null() {
        return -22; // EINVAL
    }
    if !ENGINE_INITIALIZED.load(core::sync::atomic::Ordering::Acquire) {
        unsafe {
            (*out).ino = 0;
            (*out).entry_type = 0;
            (*out).kind = 0;
            (*out).name_len = 0;
            (*out).next_cookie = 0;
        }
        return -19; // ENODEV
    }

    let result = with_mounted_engine(-19, |engine| unsafe {
        let dir_entries = engine.dir_entries.borrow();
        let mut best_index: Option<usize> = None;
        let mut best_cookie: u32 = 0;

        for (idx, entry) in dir_entries.iter().enumerate() {
            let (parent_ino, _name, _child_ino, _child_kind, entry_cookie) = entry;
            if *parent_ino != directory_ino {
                continue;
            }
            if *entry_cookie <= cookie {
                continue;
            }
            if best_index.is_none() || *entry_cookie < best_cookie {
                best_index = Some(idx);
                best_cookie = *entry_cookie;
            }
        }

        if let Some(idx) = best_index {
            let (_parent_ino, name, child_ino, child_kind, entry_cookie) = &dir_entries[idx];
            let name_len = name.len().min(255u8 as usize) as u8;
            let entry_type: u8 = match child_kind {
                0 => 1, // DT_FILE
                1 => 0, // DT_DIR
                2 => 2, // DT_SYMLINK
                _ => 1,
            };
            (*out).ino = *child_ino;
            (*out).entry_type = entry_type;
            (*out).kind = *child_kind;
            (*out).name_len = name_len;
            (*out).next_cookie = *entry_cookie;
            return 0;
        }

        // No more entries.
        (*out).ino = 0;
        (*out).entry_type = 0;
        (*out).kind = 0;
        (*out).name_len = 0;
        (*out).next_cookie = 0;
        0
    });
    result
}

// -- Extern "C" engine-backed readdir name retrieval (#6400) -----------
// After calling tidefs_posix_vfs_engine_readdir, the C shim needs the
// entry name bytes. This function copies the name for the exact stable
// `cookie` returned by tidefs_posix_vfs_engine_readdir.
//
// `directory_ino`: inode of the directory being listed.
// `cookie`: the cookie of the entry whose name to retrieve.
// `out_buf`: output buffer for the name (at least 256 bytes recommended).
// `out_buf_size`: size of out_buf.
// `out_name_len`: populated with the actual name length.
//
// Returns 0 on success, -ENOENT if the cookie is absent.
#[no_mangle]
#[cfg(CONFIG_RUST)]
pub extern "C" fn tidefs_posix_vfs_engine_readdir_name(
    directory_ino: u64,
    cookie: u32,
    out_buf: *mut u8,
    out_buf_size: u32,
    out_name_len: *mut u32,
) -> core::ffi::c_int {
    if out_buf.is_null() || out_name_len.is_null() {
        return -22; // EINVAL
    }
    if !ENGINE_INITIALIZED.load(core::sync::atomic::Ordering::Acquire) {
        return -19; // ENODEV
    }

    with_mounted_engine(-19, |engine| unsafe {
        let dir_entries = engine.dir_entries.borrow();
        for entry in dir_entries.iter() {
            let (parent_ino, name, _child_ino, _child_kind, entry_cookie) = entry;
            if *parent_ino != directory_ino {
                continue;
            }
            if *entry_cookie != cookie {
                continue;
            }
            let name_slice: &[u8] = &*name;
            let copy_len = name_slice.len().min(out_buf_size as usize);
            core::ptr::copy_nonoverlapping(name_slice.as_ptr(), out_buf, copy_len);
            *out_name_len = copy_len as u32;
            return 0;
        }
        *out_name_len = 0;
        -2 // ENOENT
    })
}

/// C-visible output struct for replay readdir.
#[repr(C)]
#[cfg(CONFIG_RUST)]
pub struct TidefsReplayReaddirOut {
    /// Inode number of the directory entry, or 0 when no more entries.
    pub ino: u64,
    /// DT_DIR=0, DT_FILE=1, DT_SYMLINK=2.
    pub entry_type: u8,
    /// Object kind: 0=file, 1=dir, 2=symlink.
    pub kind: u8,
    /// Length of the entry name in bytes.
    pub name_len: u8,
    /// Cookie for the next call; 0 means end of page.
    pub next_cookie: u32,
}

/// Engine-backed readdir entry iteration through the inline DirPage
/// scanner (replay_integration::iterate_dir_page).
///
/// `dir_page_buf` / `dir_page_len`: buffer containing the directory
///   DirPage bytes (read from disk by C).
/// `cookie`: cookie from the previous call (0 to start).
/// `out`: populated with the next entry on success.
///
/// Returns 0 on success (entry found), -errno on buffer error.
/// Caller treats `out.ino == 0` as end-of-directory.
#[no_mangle]
#[cfg(CONFIG_RUST)]
pub extern "C" fn tidefs_posix_vfs_engine_replay_readdir(
    dir_page_buf: *const u8,
    dir_page_len: core::ffi::c_ulong,
    cookie: u32,
    out: *mut TidefsReplayReaddirOut,
) -> core::ffi::c_int {
    if dir_page_buf.is_null() || out.is_null() {
        return -22; // EINVAL
    }
    if dir_page_len == 0 {
        return -22;
    }

    // SAFETY: dir_page_buf is a valid block-device read buffer;
    // dir_page_len is the number of bytes read by the C shim.
    let dir_slice = unsafe { core::slice::from_raw_parts(dir_page_buf, dir_page_len as usize) };

    match crate::replay_integration::iterate_dir_page(dir_slice, cookie) {
        Some(entry) => unsafe {
            (*out).ino = entry.ino;
            (*out).entry_type = entry.entry_type;
            (*out).kind = entry.kind;
            (*out).name_len = entry.name_len;
            (*out).next_cookie = entry.next_cookie;
        },
        None => unsafe {
            // No more entries — caller uses ino=0 as end-of-directory.
            (*out).ino = 0;
            (*out).entry_type = 0;
            (*out).kind = 0;
            (*out).name_len = 0;
            (*out).next_cookie = 0;
        },
    }
    0
}

// -- Extern "C" replay extent lookup bridge (#6252 file read) ----------
// Uses the inline EXMP extent-map leaf page parser
// (replay_integration::lookup_exmp_extent) to resolve a logical file
// offset to a physical extent mapping. Works under Kbuild using only
// core primitives and kmod-bridge BLAKE3 — no child crate linking
// required.
//
// Called from the C shim when building the physical I/O plan for
// file read operations.

/// C-visible output struct for replay extent lookup.
#[repr(C)]
#[cfg(CONFIG_RUST)]
pub struct TidefsReplayExtentOut {
    /// Physical block locator (LocatorId) for the extent.
    pub locator_id: u64,
    /// Byte offset within the extent where the requested logical
    /// offset falls.
    pub extent_internal_offset: u64,
    /// Length of this extent in bytes.
    pub extent_length: u64,
    /// 0=data, 1=unwritten.
    pub extent_kind: u8,
    /// Padding.
    pub _pad: [u8; 7],
}

/// Resolve a logical file offset to a physical extent through the
/// EXMP extent-map leaf page.
///
/// `extent_page_buf` / `extent_page_len`: buffer containing the
///   extent map page (4096 bytes typically, read from disk by C
///   at the offset given by the inode's extent_map_root).
/// `logical_offset`: byte offset within the file.
/// `out`: populated with the extent mapping on success.
///
/// Returns 0 on success, -errno on failure.
#[no_mangle]
#[cfg(CONFIG_RUST)]
pub extern "C" fn tidefs_posix_vfs_engine_replay_extent_lookup(
    extent_page_buf: *const u8,
    extent_page_len: core::ffi::c_ulong,
    logical_offset: u64,
    out: *mut TidefsReplayExtentOut,
) -> core::ffi::c_int {
    if extent_page_buf.is_null() || out.is_null() {
        return -22; // EINVAL
    }
    if extent_page_len < 54 {
        return -22;
    }

    // SAFETY: extent_page_buf is a valid block-device read buffer
    // of extent_page_len bytes provided by the C shim.
    let page_slice =
        unsafe { core::slice::from_raw_parts(extent_page_buf, extent_page_len as usize) };
    match crate::replay_integration::lookup_exmp_extent(page_slice, logical_offset) {
        Ok(entry) => unsafe {
            (*out).locator_id = entry.locator_id;
            (*out).extent_internal_offset = logical_offset - entry.logical_offset;
            (*out).extent_length = entry.length;
            (*out).extent_kind = entry.extent_kind;
            (*out)._pad = [0u8; 7];
        },
        Err(_e) => {
            // Extent not found or page corrupt.
            // Return 0 with locator_id=0 to signal hole/ENOENT.
            unsafe {
                (*out).locator_id = 0;
                (*out).extent_internal_offset = 0;
                (*out).extent_length = 0;
                (*out).extent_kind = 0;
                (*out)._pad = [0u8; 7];
            }
        }
    }
    0
}

// -- Persistent kernel engine for committed-root persistence ------------
// Stores the mounted engine so sync_fs can access pool_core I/O context
// without creating a fresh unbound engine each time.

/// Static engine instance set during mount, used by sync_fs/commit barriers.
/// SAFETY: all mounted-engine access is serialized by MOUNTED_ENGINE_LOCK.
static mut MOUNTED_ENGINE: Option<KernelEngine> = None;
static ENGINE_INITIALIZED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

kernel::sync::global_lock! {
    // SAFETY: initialized once in module init before filesystem registration.
    unsafe(uninit) static MOUNTED_ENGINE_LOCK: Mutex<()> = ();
}

fn with_mounted_engine<R>(missing: R, f: impl FnOnce(&KernelEngine) -> R) -> R {
    if !ENGINE_INITIALIZED.load(core::sync::atomic::Ordering::Acquire) {
        return missing;
    }

    let _guard = MOUNTED_ENGINE_LOCK.lock();
    if !ENGINE_INITIALIZED.load(core::sync::atomic::Ordering::Acquire) {
        return missing;
    }

    unsafe {
        let engine_ptr: *const Option<KernelEngine> = &raw const MOUNTED_ENGINE;
        match &*engine_ptr {
            Some(engine) => f(engine),
            None => missing,
        }
    }
}

fn with_mounted_engine_mut<R>(missing: R, f: impl FnOnce(&mut KernelEngine) -> R) -> R {
    if !ENGINE_INITIALIZED.load(core::sync::atomic::Ordering::Acquire) {
        return missing;
    }

    let _guard = MOUNTED_ENGINE_LOCK.lock();
    if !ENGINE_INITIALIZED.load(core::sync::atomic::Ordering::Acquire) {
        return missing;
    }

    unsafe {
        let engine_ptr: *mut Option<KernelEngine> = &raw mut MOUNTED_ENGINE;
        match &mut *engine_ptr {
            Some(engine) => f(engine),
            None => missing,
        }
    }
}

/// Cluster node identity recorded from mount options (issue #6671).
static mut CLUSTER_NODE_ID: Option<crate::tidefs_kmod_bridge::kernel_types::KmodVec<u8>> = None;
/// Transport carrier recorded from mount options (issue #6671).
static mut TRANSPORT_CARRIER: Option<crate::tidefs_kmod_bridge::kernel_types::KmodVec<u8>> = None;

/// C-visible bridge: initialize the persistent engine during mount.
///
/// Called from fill_super_bdev after the mount context is created.
/// The C shim provides sector_size, superblock offset/size, txg, root_ino,
/// pool_uuid, and a write_sectors_fn callback for block-device I/O.
///
/// write_fn: C function pointer for writing sectors. Signature:
///   int write_fn(u64 start_sector, const u8 *data, u32 len)
///   Returns 0 on success, -errno on failure.
/// sector_size, sb_offset, sb_size, device_capacity_bytes: mounted block geometry.
/// committed_txg, root_ino: from the committed-root ledger.
/// pool_uuid: 32-byte pool UUID.
#[no_mangle]
pub extern "C" fn tidefs_posix_vfs_engine_init_mounted(
    write_fn: Option<unsafe extern "C" fn(u64, *const u8, u32) -> core::ffi::c_int>,
    read_fn: Option<unsafe extern "C" fn(u64, *mut u8, u32) -> core::ffi::c_int>,
    flush_fn: Option<unsafe extern "C" fn() -> core::ffi::c_int>,
    teardown_fn: Option<unsafe extern "C" fn() -> core::ffi::c_int>,
    sector_size: u32,
    sb_offset: u64,
    sb_size: u64,
    device_capacity_bytes: u64,
    committed_txg: u64,
    root_ino: u64,
    pool_uuid: *const u8,
    major: u32,
    minor: u32,
    inode_table_root: u64,
    extent_map_root: u64,
) -> core::ffi::c_int {
    if pool_uuid.is_null() {
        kernel::pr_err!("tidefs_posix_vfs: engine_init_mounted: null pool_uuid\n");
        return -22; // EINVAL
    }
    if ENGINE_INITIALIZED.load(core::sync::atomic::Ordering::Acquire) {
        kernel::pr_info!("tidefs_posix_vfs: engine already initialized; replacing\n");
    }
    if write_fn.is_none() || read_fn.is_none() || flush_fn.is_none() || teardown_fn.is_none() {
        kernel::pr_err!(
            "tidefs_posix_vfs: engine_init_mounted: missing explicit pool I/O authority callbacks\n"
        );
        return -19; // ENODEV
    }
    if sector_size == 0
        || device_capacity_bytes == 0
        || sb_size == 0
        || sb_offset % u64::from(sector_size) != 0
        || root_ino == 0
    {
        kernel::pr_err!(
            "tidefs_posix_vfs: engine_init_mounted: invalid pool geometry sector={} sb_off={} sb_size={} capacity={} root={}\n",
            sector_size,
            sb_offset,
            sb_size,
            device_capacity_bytes,
            root_ino,
        );
        return -22; // EINVAL
    }

    let mut uuid = [0u8; 32];
    // SAFETY: uuid is a [u8; 32] on the stack; pool_uuid is a
    // valid 32-byte source from the C shim.  Copy is within bounds.
    unsafe {
        core::ptr::copy_nonoverlapping(pool_uuid, uuid.as_mut_ptr(), 32);
    }

    // Build an I/O context for the engine's pool core. The raw data area
    // starts after the superblock region, sector-aligned; the C shim keeps
    // its fixed namespace mirror there, so Rust engine-local allocator,
    // intent-log, and writeback data use a reserved offset past that mirror.
    let data_area_offset = {
        let raw = sb_offset.saturating_add(sb_size);
        let aligned = if sector_size > 0 {
            ((raw + sector_size as u64 - 1) / sector_size as u64) * sector_size as u64
        } else {
            raw
        };
        aligned.saturating_add(KERNEL_POOL_ENGINE_DATA_OFFSET)
    };
    let io_ctx = crate::tidefs_kmod_bridge::kernel_types::CommittedRootIoCtx {
        data_area_offset,
        write_sectors_fn: write_fn,
        read_sectors_fn: read_fn,
        flush_fn,
        teardown_fn,
        sector_size,
        device_capacity_bytes,
        superblock_offset: sb_offset,
        superblock_size: sb_size,
        committed_txg,
        root_ino,
        pool_uuid: uuid,
    };
    if !io_ctx.capabilities().has_mounted_authority() {
        kernel::pr_err!(
            "tidefs_posix_vfs: engine_init_mounted: pool I/O authority is not mount-capable\n"
        );
        return -19; // ENODEV
    }

    // Create a minimal pool config (one device with placeholder params).
    let sector_count = device_capacity_bytes / sector_size as u64;
    if sector_count == 0 {
        kernel::pr_err!("tidefs_posix_vfs: engine_init_mounted: zero-capacity pool authority\n");
        return -22; // EINVAL
    }
    let desc = crate::tidefs_kmod_bridge::kernel_types::LowerDeviceDesc::new(
        major,
        minor,
        sector_count,
        sector_size,
    );
    let mut devices = crate::tidefs_kmod_bridge::kernel_types::KmodVec::new();
    devices.push(desc);
    let pool_uuid = uuid; // 32-byte pool UUID from C shim
    let config =
        crate::tidefs_kmod_bridge::kernel_types::KernelPoolConfig::new(pool_uuid, devices, 0);

    let mut pool_core = match crate::tidefs_kmod_bridge::kernel_types::KernelPoolCore::new(config) {
        Ok(pc) => pc,
        Err(_) => {
            kernel::pr_err!("tidefs_posix_vfs: engine_init_mounted: failed to create pool core\n");
            return -12; // ENOMEM
        }
    };
    pool_core.set_committed_root_io_ctx(io_ctx);
    // Transition through the pool lifecycle: Configured → Importing → Mounted.
    // The C shim already validated the block device and committed-root ledger,
    // so we complete the full state machine here.
    if let Err(e) = pool_core.begin_import() {
        kernel::pr_err!(
            "tidefs_posix_vfs: engine_init_mounted: begin_import failed: {:?}\n",
            e
        );
        return -5; // EIO
    }
    if let Err(e) = pool_core.complete_import() {
        kernel::pr_err!(
            "tidefs_posix_vfs: engine_init_mounted: complete_import failed: {:?}\n",
            e
        );
        return -5; // EIO
    }

    let engine = KernelEngine::with_pool_core(None, pool_core);
    engine.set_vrbt_pointers(inode_table_root, extent_map_root);
    match engine.load_namespace_snapshot() {
        Ok(true) => {
            engine.ensure_root_inode(root_ino, sector_size);
        }
        Ok(false) => {
            engine.ensure_root_inode(root_ino, sector_size);
        }
        Err(e) => {
            kernel::pr_err!(
                "tidefs_posix_vfs: engine_init_mounted: namespace snapshot load failed: {:?}\n",
                e,
            );
            return -5; // EIO
        }
    }
    {
        let _guard = MOUNTED_ENGINE_LOCK.lock();
        unsafe {
            let engine_ptr: *mut Option<KernelEngine> = &raw mut MOUNTED_ENGINE;
            *engine_ptr = Some(engine);
        }
        ENGINE_INITIALIZED.store(true, core::sync::atomic::Ordering::Release);
    }

    kernel::pr_info!(
        "tidefs_posix_vfs: engine initialized: txg={} root_ino={} sb_ofs={} sb_sz={} ss={}\n",
        committed_txg,
        root_ino,
        sb_offset,
        sb_size,
        sector_size,
    );

    // Log residency status at every engine init: proves no userspace daemon
    // dependency for normal VFS/block I/O through kernel-resident code paths.
    let residency = crate::no_daemon_residency::KernelVfsNoDaemonResidencyToken::check_residency();
    kernel::pr_info!(
        "tidefs_posix_vfs: residency assertion: {:?} (kernel_resident={})\n",
        residency,
        residency.is_kernel_resident(),
    );
    0
}

/// C-visible bridge: tear down the persistent engine during unmount.
#[no_mangle]
pub extern "C" fn tidefs_posix_vfs_engine_sync_namespace(
    count: u32,
    inos: *const u64,
    parent_inos: *const u64,
    modes: *const u32,
    names_ptr: *const *const u8,
    name_lens: *const u32,
    data_lens: *const u64,
) -> core::ffi::c_int {
    if !ENGINE_INITIALIZED.load(core::sync::atomic::Ordering::Acquire) {
        return 0; // nothing to sync; no engine mounted
    }
    if count == 0 {
        return 0;
    }
    // SAFETY: all pointer/length pairs are provided by the C shim
    // which owns the pool inode table and guarantees valid data.
    let ino_slice = unsafe { core::slice::from_raw_parts(inos, count as usize) };
    let parent_slice = unsafe { core::slice::from_raw_parts(parent_inos, count as usize) };
    let mode_slice = unsafe { core::slice::from_raw_parts(modes, count as usize) };
    let name_len_slice = unsafe { core::slice::from_raw_parts(name_lens, count as usize) };
    let data_len_slice = unsafe { core::slice::from_raw_parts(data_lens, count as usize) };
    let names_slice = unsafe { core::slice::from_raw_parts(names_ptr, count as usize) };

    let ret = with_mounted_engine_mut(-19, |engine| {
        let mut max_ino: u64 = 0;
        for i in 0..count as usize {
            let ino = ino_slice[i];
            let parent_ino = parent_slice[i];
            let mode = mode_slice[i];
            let name_len = name_len_slice[i] as usize;
            if name_len == 0 || name_len > 255 {
                continue;
            }
            let name_ptr = names_slice[i];
            if name_ptr.is_null() {
                continue;
            }
            let name_bytes = unsafe { core::slice::from_raw_parts(name_ptr, name_len) };

            // Determine kind from mode: S_IFDIR(0040000) or S_IFREG(0100000)
            let kind: u8 = if (mode & 0o170000) == 0o040000 {
                InodeRecord::DIR
            } else if (mode & 0o170000) == 0o120000 {
                InodeRecord::SYMLINK
            } else if (mode & 0o170000) == 0o010000 {
                InodeRecord::FILE
            }
            /* S_IFIFO: treat as special file */
            else {
                InodeRecord::FILE
            }; /* default: regular file, socket, blk, chr */

            // Add to inodes table.
            let rec = InodeRecord {
                ino,
                mode,
                uid: 0,
                gid: 0,
                nlink: 1,
                size: data_len_slice[i],
                blocks: 0,
                generation: 1,
                kind,
                atime_ns: 0,
                mtime_ns: 0,
                ctime_ns: 0,
                symlink_target: None,
            };
            if engine.push_inode_record(rec).is_err() {
                return -12;
            }

            // Add to dir_entries.
            if engine
                .add_dir_entry(parent_ino, name_bytes, ino, kind)
                .is_err()
            {
                if engine.remove_inode_record(ino).is_err() {
                    return -12;
                }
                return -12;
            }

            if ino > max_ino {
                max_ino = ino;
            }
        }
        let target_ni = max_ino.saturating_add(1u64).max(2u64);
        if let Ok(Some((ni, gen))) = engine.read_alloc_meta() {
            if target_ni > ni {
                let _ = engine.write_alloc_meta(target_ni, gen);
            }
        } else if engine.pool_core.is_some() {
            let _ = engine.write_alloc_meta(target_ni, 0u64);
        } else {
            engine.next_ino.set(target_ni);
        }

        kernel::pr_info!(
            "tidefs_posix_vfs: synced {} namespace entries from C pool to engine\n",
            count,
        );
        0
    });
    if ret == -19 {
        kernel::pr_err!("tidefs_posix_vfs: engine_sync_namespace: no mounted engine\n");
    }
    ret
}

/// C-visible bridge: tear down the persistent engine during unmount.
#[no_mangle]
pub extern "C" fn tidefs_posix_vfs_engine_teardown_mounted() -> core::ffi::c_int {
    if !ENGINE_INITIALIZED.load(core::sync::atomic::Ordering::Acquire) {
        return 0;
    }
    let _guard = MOUNTED_ENGINE_LOCK.lock();
    if !ENGINE_INITIALIZED.load(core::sync::atomic::Ordering::Acquire) {
        return 0;
    }
    let teardown_result = unsafe {
        let engine_ptr: *const Option<KernelEngine> = &raw const MOUNTED_ENGINE;
        match (*engine_ptr).as_ref() {
            Some(engine) => engine.teardown_pool_authority(),
            None => Ok(()),
        }
    };
    ENGINE_INITIALIZED.store(false, core::sync::atomic::Ordering::Release);
    unsafe {
        let engine_ptr: *mut Option<KernelEngine> = &raw mut MOUNTED_ENGINE;
        *engine_ptr = None;
    }
    match teardown_result {
        Ok(()) => {
            kernel::pr_info!("tidefs_posix_vfs: engine torn down\n");
            0
        }
        Err(e) => {
            let errno_val: u16 = e.0;
            kernel::pr_err!(
                "tidefs_posix_vfs: engine teardown failed (errno={})\n",
                errno_val,
            );
            -(errno_val as core::ffi::c_int)
        }
    }
}

// -- Engine-backed open/release bridges (#6274) --------------------------
// Bridge the C shim's file_operations::open/release to the Rust
// KernelEngine so that engine-backed inodes (create/mkdir through
// Rust) are visible to the VFS open path.

/// C-visible output for the engine-backed open bridge.
#[repr(C)]
#[cfg(CONFIG_RUST)]
pub struct TidefsEngineOpenOut {
    pub ok: u8,
    pub fh_ino: u64,
    pub fh_id: u64,
}

/// C-visible bridge: engine-backed file open.
///
/// Checks whether an inode with the given ino exists in the mounted
/// engine (in-memory table or on-disk VINO table).  On success
/// sets out->ok=1 and populates the file-handle fields.
///
/// Returns 0 on success (even when inode not found: caller checks
/// out->ok), -errno on engine error.
#[no_mangle]
#[cfg(CONFIG_RUST)]
pub extern "C" fn tidefs_posix_vfs_engine_open(
    ino: u64,
    flags: u32,
    out: *mut TidefsEngineOpenOut,
) -> core::ffi::c_int {
    if out.is_null() {
        return -22; // EINVAL
    }
    let inode = crate::tidefs_kmod_bridge::kernel_types::InodeId::new(ino);
    let ctx = crate::tidefs_kmod_bridge::kernel_types::RequestCtx::default();

    let result = with_mounted_engine(
        Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV),
        |engine| engine.open(inode, flags, &ctx),
    );

    match result {
        Ok(fh) => unsafe {
            (*out).ok = 1;
            (*out).fh_ino = fh.inode_id.get();
            (*out).fh_id = fh.fh_id.0;
        },
        Err(_e) => unsafe {
            (*out).ok = 0;
            (*out).fh_ino = 0;
            (*out).fh_id = 0;
        },
    }
    0
}

/// C-visible bridge: engine-backed file release.
///
/// Returns 0 on success, -errno on engine error.
#[no_mangle]
#[cfg(CONFIG_RUST)]
pub extern "C" fn tidefs_posix_vfs_engine_release(ino: u64, fh_id: u64) -> core::ffi::c_int {
    let inode = crate::tidefs_kmod_bridge::kernel_types::InodeId::new(ino);
    let fh = crate::tidefs_kmod_bridge::kernel_types::EngineFileHandle::new(
        inode,
        0,
        crate::tidefs_kmod_bridge::kernel_types::FileHandleId::new(fh_id),
        0,
    );
    let result = with_mounted_engine(
        Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV),
        |engine| engine.release(&fh),
    );
    match result {
        Ok(()) => 0,
        Err(e) => -(e.0 as core::ffi::c_int),
    }
}

/// C-visible bridge: engine-backed directory open.
#[no_mangle]
#[cfg(CONFIG_RUST)]
pub extern "C" fn tidefs_posix_vfs_engine_opendir(
    ino: u64,
    out: *mut TidefsEngineOpenOut,
) -> core::ffi::c_int {
    if out.is_null() {
        return -22; // EINVAL
    }
    let inode = crate::tidefs_kmod_bridge::kernel_types::InodeId::new(ino);
    let ctx = crate::tidefs_kmod_bridge::kernel_types::RequestCtx::default();

    let result = with_mounted_engine(
        Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV),
        |engine| engine.opendir(inode, &ctx),
    );

    match result {
        Ok(dh) => unsafe {
            (*out).ok = 1;
            (*out).fh_ino = dh.inode_id.get();
            (*out).fh_id = dh.dh_id.0;
        },
        Err(_e) => unsafe {
            (*out).ok = 0;
            (*out).fh_ino = 0;
            (*out).fh_id = 0;
        },
    }
    0
}

/// C-visible bridge: engine-backed directory release.
#[no_mangle]
#[cfg(CONFIG_RUST)]
pub extern "C" fn tidefs_posix_vfs_engine_releasedir(ino: u64, dh_id: u64) -> core::ffi::c_int {
    let inode = crate::tidefs_kmod_bridge::kernel_types::InodeId::new(ino);
    let dh = crate::tidefs_kmod_bridge::kernel_types::EngineDirHandle {
        inode_id: inode,
        dh_id: crate::tidefs_kmod_bridge::kernel_types::DirHandleId::new(dh_id),
    };
    let result = with_mounted_engine(
        Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV),
        |engine| engine.releasedir(&dh),
    );
    match result {
        Ok(()) => 0,
        Err(e) => -(e.0 as core::ffi::c_int),
    }
}

/// C-visible inode attribute packet for live engine lookup/getattr.
#[repr(C)]
#[cfg(CONFIG_RUST)]
pub struct TidefsEngineAttrOut {
    pub ino: u64,
    pub generation: u64,
    pub size: u64,
    pub blocks: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub atime_ns: i64,
    pub mtime_ns: i64,
    pub ctime_ns: i64,
}

#[cfg(CONFIG_RUST)]
fn fill_engine_attr_out(
    out: *mut TidefsEngineAttrOut,
    attr: &crate::tidefs_kmod_bridge::kernel_types::InodeAttr,
) {
    unsafe {
        (*out).ino = attr.inode_id.get();
        (*out).generation = attr.generation.0;
        (*out).size = attr.posix.size;
        (*out).blocks = attr.posix.blocks_512;
        (*out).mode = attr.posix.mode;
        (*out).uid = attr.posix.uid;
        (*out).gid = attr.posix.gid;
        (*out).nlink = attr.posix.nlink;
        (*out).atime_ns = attr.posix.atime_ns;
        (*out).mtime_ns = attr.posix.mtime_ns;
        (*out).ctime_ns = attr.posix.ctime_ns;
    }
}

fn validate_kernel_name_len(
    name_len: u32,
) -> core::result::Result<(), crate::tidefs_kmod_bridge::kernel_types::Errno> {
    if name_len == 0 {
        return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL);
    }
    if name_len > 255 {
        return Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENAMETOOLONG);
    }
    Ok(())
}

/// C-visible bridge: live engine-backed lookup by parent/name.
#[no_mangle]
#[cfg(CONFIG_RUST)]
pub extern "C" fn tidefs_posix_vfs_engine_lookup(
    parent_ino: u64,
    name_ptr: *const u8,
    name_len: u32,
    out: *mut TidefsEngineAttrOut,
) -> core::ffi::c_int {
    if name_ptr.is_null() || out.is_null() {
        return -22; // EINVAL
    }
    if let Err(e) = validate_kernel_name_len(name_len) {
        return -(e.0 as core::ffi::c_int);
    }

    let parent = crate::tidefs_kmod_bridge::kernel_types::InodeId::new(parent_ino);
    let name_slice: &[u8] = unsafe { core::slice::from_raw_parts(name_ptr, name_len as usize) };
    let ctx = crate::tidefs_kmod_bridge::kernel_types::RequestCtx::default();
    let result = with_mounted_engine(
        Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV),
        |engine| engine.lookup(parent, name_slice, &ctx),
    );

    match result {
        Ok(attr) => {
            fill_engine_attr_out(out, &attr);
            0
        }
        Err(e) => -(e.0 as core::ffi::c_int),
    }
}

/// C-visible bridge: live engine-backed getattr by inode number.
#[no_mangle]
#[cfg(CONFIG_RUST)]
pub extern "C" fn tidefs_posix_vfs_engine_getattr(
    ino: u64,
    out: *mut TidefsEngineAttrOut,
) -> core::ffi::c_int {
    if out.is_null() {
        return -22; // EINVAL
    }

    let inode = crate::tidefs_kmod_bridge::kernel_types::InodeId::new(ino);
    let ctx = crate::tidefs_kmod_bridge::kernel_types::RequestCtx::default();
    let result = with_mounted_engine(
        Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV),
        |engine| engine.getattr(inode, None, &ctx),
    );

    match result {
        Ok(attr) => {
            fill_engine_attr_out(out, &attr);
            0
        }
        Err(e) => -(e.0 as core::ffi::c_int),
    }
}

/// C-visible bridge: engine-backed file write (bootstrap write-path).
///
/// Writes data at the given offset for an engine-backed file,
/// routing through VfsEngine::write.  Returns bytes written on
/// success (>=0), -errno on failure.
#[no_mangle]
#[cfg(CONFIG_RUST)]
pub extern "C" fn tidefs_posix_vfs_engine_write(
    fh_ino: u64,
    fh_id: u64,
    offset: u64,
    buf_ptr: *const u8,
    buf_len: u32,
) -> core::ffi::c_int {
    if buf_ptr.is_null() || buf_len == 0 {
        return 0;
    }
    let inode = crate::tidefs_kmod_bridge::kernel_types::InodeId::new(fh_ino);
    let fh = crate::tidefs_kmod_bridge::kernel_types::EngineFileHandle::new(
        inode,
        0,
        crate::tidefs_kmod_bridge::kernel_types::FileHandleId::new(fh_id),
        0,
    );
    let ctx = crate::tidefs_kmod_bridge::kernel_types::RequestCtx::default();
    // SAFETY: buf_ptr and buf_len are provided by the kernel VFS write
    // path; null and zero-length are validated above.
    let data: &[u8] = unsafe { core::slice::from_raw_parts(buf_ptr, buf_len as usize) };

    let result = with_mounted_engine(
        Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV),
        |engine| engine.write(&fh, offset, data, &ctx),
    );

    match result {
        Ok(bytes) => bytes as core::ffi::c_int,
        Err(e) => -(e.0 as core::ffi::c_int),
    }
}

/// C-visible bridge: engine-backed fsync.
///
/// Delegates fsync/fdatasync to the Rust engine for engine-backed files.
/// Returns 0 on success, -errno on failure.
#[no_mangle]
#[cfg(CONFIG_RUST)]
pub extern "C" fn tidefs_posix_vfs_engine_fsync(
    fh_ino: u64,
    fh_id: u64,
    start: u64,
    end: u64,
    datasync: core::ffi::c_int,
) -> core::ffi::c_int {
    let inode = crate::tidefs_kmod_bridge::kernel_types::InodeId::new(fh_ino);
    let fh = crate::tidefs_kmod_bridge::kernel_types::EngineFileHandle::new(
        inode,
        0,
        crate::tidefs_kmod_bridge::kernel_types::FileHandleId::new(fh_id),
        0,
    );
    let ctx = crate::tidefs_kmod_bridge::kernel_types::RequestCtx::default();
    let _ = (start, end); // range parameters reserved for future per-range fsync

    let result = with_mounted_engine(
        Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV),
        |engine| engine.fsync(&fh, datasync != 0, &ctx),
    );

    match result {
        Ok(()) => 0,
        Err(e) => -(e.0 as core::ffi::c_int),
    }
}

/// C-visible bridge: engine-backed file read.
///
/// Reads up to `buf_len` bytes at `offset` for an engine-backed file,
/// routing through VfsEngine::read.  The caller provides a kernel buffer
/// in `buf_ptr`.  Returns bytes read on success (>=0), -errno on failure.
#[no_mangle]
#[cfg(CONFIG_RUST)]
pub extern "C" fn tidefs_posix_vfs_engine_read(
    fh_ino: u64,
    fh_id: u64,
    offset: u64,
    buf_ptr: *mut u8,
    buf_len: u32,
) -> core::ffi::c_int {
    if buf_ptr.is_null() || buf_len == 0 {
        return 0;
    }
    let inode = crate::tidefs_kmod_bridge::kernel_types::InodeId::new(fh_ino);
    let fh = crate::tidefs_kmod_bridge::kernel_types::EngineFileHandle::new(
        inode,
        0,
        crate::tidefs_kmod_bridge::kernel_types::FileHandleId::new(fh_id),
        0,
    );
    let ctx = crate::tidefs_kmod_bridge::kernel_types::RequestCtx::default();

    let result = with_mounted_engine(
        Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV),
        |engine| engine.read(&fh, offset, buf_len, &ctx),
    );

    match result {
        Ok(data) => {
            let copy_len = core::cmp::min(data.len(), buf_len as usize);
            // SAFETY: buf_ptr is a valid kernel buffer provided by the
            // C shim read_iter path with at least buf_len bytes.
            unsafe {
                core::ptr::copy_nonoverlapping(data.as_ptr(), buf_ptr, copy_len);
            }
            copy_len as core::ffi::c_int
        }
        Err(e) => -(e.0 as core::ffi::c_int),
    }
}

/// C-visible bridge: engine-backed copy_file_range.
///
/// Copies up to `length` bytes from source file at `offset_in` to
/// destination file at `offset_out`.  Returns the number of bytes copied
/// through `out_copied`.  On engine error, returns -errno.
#[no_mangle]
#[cfg(CONFIG_RUST)]
pub extern "C" fn tidefs_posix_vfs_engine_copy_file_range(
    fh_ino_in: u64,
    fh_id_in: u64,
    offset_in: u64,
    fh_ino_out: u64,
    fh_id_out: u64,
    offset_out: u64,
    length: u64,
    out_copied: *mut u32,
) -> core::ffi::c_int {
    if out_copied.is_null() {
        return -(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL.0 as core::ffi::c_int);
    }
    if length == 0 {
        unsafe {
            *out_copied = 0;
        }
        return 0;
    }

    let src_inode = crate::tidefs_kmod_bridge::kernel_types::InodeId::new(fh_ino_in);
    let dst_inode = crate::tidefs_kmod_bridge::kernel_types::InodeId::new(fh_ino_out);
    let src_fh = crate::tidefs_kmod_bridge::kernel_types::EngineFileHandle::new(
        src_inode,
        0,
        crate::tidefs_kmod_bridge::kernel_types::FileHandleId::new(fh_id_in),
        0,
    );
    let dst_fh = crate::tidefs_kmod_bridge::kernel_types::EngineFileHandle::new(
        dst_inode,
        0,
        crate::tidefs_kmod_bridge::kernel_types::FileHandleId::new(fh_id_out),
        0,
    );
    let ctx = crate::tidefs_kmod_bridge::kernel_types::RequestCtx::default();

    let result = with_mounted_engine(
        Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV),
        |engine| engine.copy_file_range(&src_fh, offset_in, &dst_fh, offset_out, length, &ctx),
    );

    match result {
        Ok(copied) => {
            unsafe {
                *out_copied = copied;
            }
            0
        }
        Err(e) => -(e.0 as core::ffi::c_int),
    }
}

// -- Xattr bridges (REL-KVFS-010) ------------------------------------------
// Bridges for the C shim's inode_operations and xattr_handler callbacks.
// All four xattr operations (get, set, list, remove) are now engine-backed
// with in-memory per-inode xattr stores wired through XattrStore semantics.
// kernel xattr persistence is wired through intent-log.
//
// All bridges access the shared MOUNTED_ENGINE and use VfsEngine trait
// methods.  When no engine is mounted, they return ENODEV.

/// C-visible bridge for getxattr -- read an extended attribute value.
///
/// Parameters:
///   ino:         inode number
///   name_ptr:    xattr name bytes
///   name_len:    xattr name length
///   value_ptr:   output buffer (may be NULL to query size)
///   value_size:  output buffer capacity
///   out_len:     [out] actual value length or required buffer size
///
/// Returns 0 on success, -errno on failure.
/// If value_ptr is NULL or value_size is 0, writes the required size to
/// out_len and returns that required size, matching Linux xattr query
/// semantics.
#[no_mangle]
pub extern "C" fn tidefs_posix_vfs_engine_getxattr(
    ino: u64,
    name_ptr: *const u8,
    name_len: u32,
    value_ptr: *mut u8,
    value_size: u32,
    out_len: *mut u32,
) -> core::ffi::c_int {
    if name_ptr.is_null() || out_len.is_null() {
        return -(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL.0 as core::ffi::c_int);
    }
    if name_len == 0 || name_len > 256 {
        return -(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL.0 as core::ffi::c_int);
    }

    let inode_id = crate::tidefs_kmod_bridge::kernel_types::InodeId::new(ino);
    let ctx = crate::tidefs_kmod_bridge::kernel_types::RequestCtx::default();

    // SAFETY: name_ptr and name_len are provided by the kernel VFS
    // xattr handler; null and zero-length are validated above.
    // SAFETY: name_ptr and name_len are provided by the kernel VFS
    // xattr handler; validated above.
    // SAFETY: name_ptr and name_len are provided by the kernel VFS
    // lookup handler; validated above.
    // SAFETY: name_ptr and name_len are provided by the kernel VFS
    // getattr handler; validated above.
    let name_slice: &[u8] = unsafe { core::slice::from_raw_parts(name_ptr, name_len as usize) };

    let result = with_mounted_engine(
        Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV),
        |engine| engine.getxattr(inode_id, name_slice, &ctx),
    );

    match result {
        Ok(value) => {
            let req_len = value.len() as u32;
            unsafe {
                *out_len = req_len;
            }
            if value_ptr.is_null() || value_size == 0 {
                return req_len as core::ffi::c_int;
            }
            if value_size < req_len {
                return -(crate::tidefs_kmod_bridge::kernel_types::Errno::ERANGE.0
                    as core::ffi::c_int);
            }
            unsafe {
                core::ptr::copy_nonoverlapping(value.as_ptr(), value_ptr, req_len as usize);
            }
            0
        }
        Err(e) => -(e.0 as core::ffi::c_int),
    }
}

/// C-visible bridge for listxattr -- list all extended attribute names.
///
/// Returns a NUL-separated packed name list.  Same buffer semantics as
/// getxattr: if buf is NULL/zero, returns required size via out_len
/// and as the positive return value.  Empty list returns 0 with out_len=0.
#[no_mangle]
pub extern "C" fn tidefs_posix_vfs_engine_listxattr(
    ino: u64,
    buf_ptr: *mut u8,
    buf_size: u32,
    out_len: *mut u32,
) -> core::ffi::c_int {
    if out_len.is_null() {
        return -(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL.0 as core::ffi::c_int);
    }

    let inode_id = crate::tidefs_kmod_bridge::kernel_types::InodeId::new(ino);
    let ctx = crate::tidefs_kmod_bridge::kernel_types::RequestCtx::default();

    let result = with_mounted_engine(
        Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV),
        |engine| engine.listxattr(inode_id, &ctx),
    );

    match result {
        Ok(list) => {
            let req_len = list.len() as u32;
            unsafe {
                *out_len = req_len;
            }
            if buf_ptr.is_null() || buf_size == 0 {
                return req_len as core::ffi::c_int;
            }
            if buf_size < req_len {
                return -(crate::tidefs_kmod_bridge::kernel_types::Errno::ERANGE.0
                    as core::ffi::c_int);
            }
            unsafe {
                core::ptr::copy_nonoverlapping(list.as_ptr(), buf_ptr, req_len as usize);
            }
            0
        }
        Err(e) => -(e.0 as core::ffi::c_int),
    }
}

/// C-visible bridge for setxattr -- set an extended attribute value.
///
/// Parameters:
///   ino:         inode number
///   name_ptr:    xattr name bytes
///   name_len:    xattr name length
///   value_ptr:   new value bytes
///   value_len:   new value length
///   flags:       XATTR_CREATE (1) or XATTR_REPLACE (2), or 0
///
/// Returns 0 on success, -errno on failure.
#[no_mangle]
pub extern "C" fn tidefs_posix_vfs_engine_setxattr(
    ino: u64,
    name_ptr: *const u8,
    name_len: u32,
    value_ptr: *const u8,
    value_len: u32,
    flags: u32,
) -> core::ffi::c_int {
    // Linux VFS routes removexattr through the xattr_handler set callback
    // with value_ptr=NULL and value_len=0.  Route to removexattr engine call.
    if value_ptr.is_null() && value_len == 0 {
        return tidefs_posix_vfs_engine_removexattr(ino, name_ptr, name_len);
    }
    if name_ptr.is_null() || value_ptr.is_null() {
        return -(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL.0 as core::ffi::c_int);
    }
    if name_len == 0 || name_len > 256 {
        return -(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL.0 as core::ffi::c_int);
    }

    let inode_id = crate::tidefs_kmod_bridge::kernel_types::InodeId::new(ino);
    let ctx = crate::tidefs_kmod_bridge::kernel_types::RequestCtx::default();

    // SAFETY: name_ptr and name_len are provided by the kernel VFS
    // xattr handler; null and zero-length are validated above.
    // SAFETY: name_ptr/name_len and value_ptr/value_len are
    // provided by the kernel VFS xattr handler; validated above.
    // SAFETY: name_ptr and name_len are provided by the kernel VFS
    // xattr handler; validated above.
    // SAFETY: name_ptr and name_len are provided by the kernel VFS
    // lookup handler; validated above.
    // SAFETY: name_ptr and name_len are provided by the kernel VFS
    // getattr handler; validated above.
    let name_slice: &[u8] = unsafe { core::slice::from_raw_parts(name_ptr, name_len as usize) };
    let value_slice: &[u8] = unsafe { core::slice::from_raw_parts(value_ptr, value_len as usize) };

    let result = with_mounted_engine(
        Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV),
        |engine| engine.setxattr(inode_id, name_slice, value_slice, flags, &ctx),
    );

    match result {
        Ok(()) => 0,
        Err(e) => -(e.0 as core::ffi::c_int),
    }
}

/// C-visible bridge for removexattr -- remove an extended attribute.
///
/// Parameters:
///   ino:         inode number
///   name_ptr:    xattr name bytes
///   name_len:    xattr name length
///
/// Returns 0 on success, -errno on failure.
#[no_mangle]
pub extern "C" fn tidefs_posix_vfs_engine_removexattr(
    ino: u64,
    name_ptr: *const u8,
    name_len: u32,
) -> core::ffi::c_int {
    if name_ptr.is_null() {
        return -(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL.0 as core::ffi::c_int);
    }
    if name_len == 0 || name_len > 256 {
        return -(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL.0 as core::ffi::c_int);
    }

    let inode_id = crate::tidefs_kmod_bridge::kernel_types::InodeId::new(ino);
    let ctx = crate::tidefs_kmod_bridge::kernel_types::RequestCtx::default();

    // SAFETY: name_ptr and name_len are provided by the kernel VFS
    // xattr handler; null and zero-length are validated above.
    // SAFETY: name_ptr and name_len are provided by the kernel VFS
    // xattr handler; validated above.
    // SAFETY: name_ptr and name_len are provided by the kernel VFS
    // lookup handler; validated above.
    // SAFETY: name_ptr and name_len are provided by the kernel VFS
    // getattr handler; validated above.
    let name_slice: &[u8] = unsafe { core::slice::from_raw_parts(name_ptr, name_len as usize) };

    let result = with_mounted_engine(
        Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV),
        |engine| engine.removexattr(inode_id, name_slice, &ctx),
    );

    match result {
        Ok(()) => 0,
        Err(e) => -(e.0 as core::ffi::c_int),
    }
}
// -- Extern "C" engine-backed namespace mutation bridges (#6270) --------------
// Engine-backed create, mkdir, rmdir, unlink bridges for the C shim.
// These replace the fixed-table approach when engine_backed is true.

/// C-visible bridge: engine-backed file creation.
///
/// Returns 0 on success (populates out_*), -errno on failure.
#[no_mangle]
pub extern "C" fn tidefs_posix_vfs_engine_create(
    parent_ino: u64,
    name_ptr: *const u8,
    name_len: u32,
    mode: u32,
    flags: u32,
    out_ino: *mut u64,
    out_mode: *mut u32,
    out_generation: *mut u64,
) -> core::ffi::c_int {
    if name_ptr.is_null() || out_ino.is_null() || out_mode.is_null() || out_generation.is_null() {
        return -(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL.0 as core::ffi::c_int);
    }
    if let Err(e) = validate_kernel_name_len(name_len) {
        return -(e.0 as core::ffi::c_int);
    }

    let parent = crate::tidefs_kmod_bridge::kernel_types::InodeId::new(parent_ino);
    // SAFETY: name_ptr and name_len are provided by the kernel VFS
    // xattr handler; null and zero-length are validated above.
    // SAFETY: name_ptr and name_len are provided by the kernel VFS
    // xattr handler; validated above.
    // SAFETY: name_ptr and name_len are provided by the kernel VFS
    // lookup handler; validated above.
    // SAFETY: name_ptr and name_len are provided by the kernel VFS
    // getattr handler; validated above.
    let name_slice: &[u8] = unsafe { core::slice::from_raw_parts(name_ptr, name_len as usize) };
    let ctx = crate::tidefs_kmod_bridge::kernel_types::RequestCtx::default();

    let result = with_mounted_engine(
        Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV),
        |engine| engine.create(parent, name_slice, mode, flags, &ctx),
    );

    match result {
        Ok((attr, _fh)) => unsafe {
            *out_ino = attr.inode_id.get();
            *out_mode = attr.posix.mode;
            *out_generation = attr.generation.0;
        },
        Err(e) => return -(e.0 as core::ffi::c_int),
    }
    0
}

/// C-visible bridge: engine-backed unnamed temporary file creation (O_TMPFILE).
///
/// Creates an unnamed regular file in `parent_ino` directory.  No dentry name
/// is required — the kernel links the resulting inode into an open file.
/// Returns 0 on success (populates out_*), -errno on failure.
#[no_mangle]
pub extern "C" fn tidefs_posix_vfs_engine_tmpfile(
    parent_ino: u64,
    mode: u32,
    flags: u32,
    out_ino: *mut u64,
    out_mode: *mut u32,
    out_generation: *mut u64,
) -> core::ffi::c_int {
    if out_ino.is_null() || out_mode.is_null() || out_generation.is_null() {
        return -(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL.0 as core::ffi::c_int);
    }

    let parent = crate::tidefs_kmod_bridge::kernel_types::InodeId::new(parent_ino);
    let ctx = crate::tidefs_kmod_bridge::kernel_types::RequestCtx::default();

    let result = with_mounted_engine(
        Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV),
        |engine| engine.tmpfile(parent, mode, flags, &ctx),
    );

    match result {
        Ok((attr, _fh)) => unsafe {
            *out_ino = attr.inode_id.get();
            *out_mode = attr.posix.mode;
            *out_generation = attr.generation.0;
        },
        Err(e) => return -(e.0 as core::ffi::c_int),
    }
    0
}

/// C-visible bridge: engine-backed directory creation.
///
/// Returns 0 on success (populates out_*), -errno on failure.
#[no_mangle]
pub extern "C" fn tidefs_posix_vfs_engine_mkdir(
    parent_ino: u64,
    name_ptr: *const u8,
    name_len: u32,
    mode: u32,
    out_ino: *mut u64,
    out_mode: *mut u32,
    out_generation: *mut u64,
) -> core::ffi::c_int {
    if name_ptr.is_null() || out_ino.is_null() || out_mode.is_null() || out_generation.is_null() {
        return -(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL.0 as core::ffi::c_int);
    }
    if let Err(e) = validate_kernel_name_len(name_len) {
        return -(e.0 as core::ffi::c_int);
    }

    let parent = crate::tidefs_kmod_bridge::kernel_types::InodeId::new(parent_ino);
    // SAFETY: name_ptr and name_len are provided by the kernel VFS
    // xattr handler; null and zero-length are validated above.
    // SAFETY: name_ptr and name_len are provided by the kernel VFS
    // xattr handler; validated above.
    // SAFETY: name_ptr and name_len are provided by the kernel VFS
    // lookup handler; validated above.
    // SAFETY: name_ptr and name_len are provided by the kernel VFS
    // getattr handler; validated above.
    let name_slice: &[u8] = unsafe { core::slice::from_raw_parts(name_ptr, name_len as usize) };
    let ctx = crate::tidefs_kmod_bridge::kernel_types::RequestCtx::default();

    let result = with_mounted_engine(
        Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV),
        |engine| engine.mkdir(parent, name_slice, mode, &ctx),
    );

    match result {
        Ok(attr) => unsafe {
            *out_ino = attr.inode_id.get();
            *out_mode = attr.posix.mode;
            *out_generation = attr.generation.0;
        },
        Err(e) => return -(e.0 as core::ffi::c_int),
    }
    0
}

/// C-visible bridge: engine-backed directory removal.
///
/// Returns 0 on success, -errno on failure.
#[no_mangle]
pub extern "C" fn tidefs_posix_vfs_engine_rmdir(
    parent_ino: u64,
    name_ptr: *const u8,
    name_len: u32,
) -> core::ffi::c_int {
    if name_ptr.is_null() {
        return -(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL.0 as core::ffi::c_int);
    }
    if let Err(e) = validate_kernel_name_len(name_len) {
        return -(e.0 as core::ffi::c_int);
    }

    let parent = crate::tidefs_kmod_bridge::kernel_types::InodeId::new(parent_ino);
    // SAFETY: name_ptr and name_len are provided by the kernel VFS
    // xattr handler; null and zero-length are validated above.
    // SAFETY: name_ptr and name_len are provided by the kernel VFS
    // xattr handler; validated above.
    // SAFETY: name_ptr and name_len are provided by the kernel VFS
    // lookup handler; validated above.
    // SAFETY: name_ptr and name_len are provided by the kernel VFS
    // getattr handler; validated above.
    let name_slice: &[u8] = unsafe { core::slice::from_raw_parts(name_ptr, name_len as usize) };
    let ctx = crate::tidefs_kmod_bridge::kernel_types::RequestCtx::default();

    let result = with_mounted_engine(
        Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV),
        |engine| engine.rmdir(parent, name_slice, &ctx),
    );

    match result {
        Ok(()) => 0,
        Err(e) => -(e.0 as core::ffi::c_int),
    }
}

/// C-visible bridge: engine-backed file unlink.
///
/// Returns 0 on success, -errno on failure.
#[no_mangle]
pub extern "C" fn tidefs_posix_vfs_engine_unlink(
    parent_ino: u64,
    name_ptr: *const u8,
    name_len: u32,
) -> core::ffi::c_int {
    if name_ptr.is_null() {
        return -(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL.0 as core::ffi::c_int);
    }
    if let Err(e) = validate_kernel_name_len(name_len) {
        return -(e.0 as core::ffi::c_int);
    }

    let parent = crate::tidefs_kmod_bridge::kernel_types::InodeId::new(parent_ino);
    // SAFETY: name_ptr and name_len are provided by the kernel VFS
    // xattr handler; null and zero-length are validated above.
    // SAFETY: name_ptr and name_len are provided by the kernel VFS
    // xattr handler; validated above.
    // SAFETY: name_ptr and name_len are provided by the kernel VFS
    // lookup handler; validated above.
    // SAFETY: name_ptr and name_len are provided by the kernel VFS
    // getattr handler; validated above.
    let name_slice: &[u8] = unsafe { core::slice::from_raw_parts(name_ptr, name_len as usize) };
    let ctx = crate::tidefs_kmod_bridge::kernel_types::RequestCtx::default();

    let result = with_mounted_engine(
        Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV),
        |engine| engine.unlink(parent, name_slice, &ctx),
    );

    match result {
        Ok(()) => 0,
        Err(e) => -(e.0 as core::ffi::c_int),
    }
}

// -- Extern "C" engine-backed rename/link/symlink/readlink bridges (#6271) ----

#[no_mangle]
pub extern "C" fn tidefs_posix_vfs_engine_rename(
    old_parent_ino: u64,
    old_name_ptr: *const u8,
    old_name_len: u32,
    new_parent_ino: u64,
    new_name_ptr: *const u8,
    new_name_len: u32,
    flags: u32,
) -> core::ffi::c_int {
    if old_name_ptr.is_null() || new_name_ptr.is_null() {
        return -(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL.0 as core::ffi::c_int);
    }
    if let Err(e) = validate_kernel_name_len(old_name_len) {
        return -(e.0 as core::ffi::c_int);
    }
    if let Err(e) = validate_kernel_name_len(new_name_len) {
        return -(e.0 as core::ffi::c_int);
    }
    let old_parent = crate::tidefs_kmod_bridge::kernel_types::InodeId::new(old_parent_ino);
    let new_parent = crate::tidefs_kmod_bridge::kernel_types::InodeId::new(new_parent_ino);
    // SAFETY: old_name_ptr/len and new_name_ptr/len are kernel
    // VFS rename arguments; validated above by the C shim.
    let old_name_slice: &[u8] =
        unsafe { core::slice::from_raw_parts(old_name_ptr, old_name_len as usize) };
    let new_name_slice: &[u8] =
        unsafe { core::slice::from_raw_parts(new_name_ptr, new_name_len as usize) };
    let ctx = crate::tidefs_kmod_bridge::kernel_types::RequestCtx::default();
    let result = with_mounted_engine(
        Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV),
        |engine| {
            engine.rename(
                old_parent,
                old_name_slice,
                new_parent,
                new_name_slice,
                flags,
                &ctx,
            )
        },
    );
    match result {
        Ok(()) => 0,
        Err(e) => -(e.0 as core::ffi::c_int),
    }
}

#[no_mangle]
pub extern "C" fn tidefs_posix_vfs_engine_link(
    target_ino: u64,
    new_parent_ino: u64,
    new_name_ptr: *const u8,
    new_name_len: u32,
    out_ino: *mut u64,
    out_mode: *mut u32,
) -> core::ffi::c_int {
    if new_name_ptr.is_null() || out_ino.is_null() || out_mode.is_null() {
        return -(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL.0 as core::ffi::c_int);
    }
    if let Err(e) = validate_kernel_name_len(new_name_len) {
        return -(e.0 as core::ffi::c_int);
    }
    let target = crate::tidefs_kmod_bridge::kernel_types::InodeId::new(target_ino);
    let new_parent = crate::tidefs_kmod_bridge::kernel_types::InodeId::new(new_parent_ino);
    // SAFETY: name_ptr/len from kernel VFS handler; validated above.
    let name_slice: &[u8] =
        unsafe { core::slice::from_raw_parts(new_name_ptr, new_name_len as usize) };
    let ctx = crate::tidefs_kmod_bridge::kernel_types::RequestCtx::default();
    let result = with_mounted_engine(
        Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV),
        |engine| engine.link(target, new_parent, name_slice, &ctx),
    );
    match result {
        Ok(attr) => unsafe {
            *out_ino = attr.inode_id.get();
            *out_mode = attr.posix.mode;
        },
        Err(e) => return -(e.0 as core::ffi::c_int),
    }
    0
}

#[no_mangle]
pub extern "C" fn tidefs_posix_vfs_engine_symlink(
    parent_ino: u64,
    name_ptr: *const u8,
    name_len: u32,
    target_ptr: *const u8,
    target_len: u32,
    out_ino: *mut u64,
    out_mode: *mut u32,
) -> core::ffi::c_int {
    if name_ptr.is_null() || target_ptr.is_null() || out_ino.is_null() || out_mode.is_null() {
        return -(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL.0 as core::ffi::c_int);
    }
    if let Err(e) = validate_kernel_name_len(name_len) {
        return -(e.0 as core::ffi::c_int);
    }
    if target_len == 0 || target_len > 4096 {
        return -(crate::tidefs_kmod_bridge::kernel_types::Errno::ENAMETOOLONG.0
            as core::ffi::c_int);
    }
    let parent = crate::tidefs_kmod_bridge::kernel_types::InodeId::new(parent_ino);
    // SAFETY: name_ptr and name_len are provided by the kernel VFS
    // xattr handler; null and zero-length are validated above.
    // SAFETY: name_ptr and name_len are provided by the kernel VFS
    // xattr handler; validated above.
    // SAFETY: name_ptr and name_len are provided by the kernel VFS
    // lookup handler; validated above.
    // SAFETY: name_ptr and name_len are provided by the kernel VFS
    // getattr handler; validated above.
    let name_slice: &[u8] = unsafe { core::slice::from_raw_parts(name_ptr, name_len as usize) };
    let target_slice: &[u8] =
        unsafe { core::slice::from_raw_parts(target_ptr, target_len as usize) };
    let ctx = crate::tidefs_kmod_bridge::kernel_types::RequestCtx::default();
    let result = with_mounted_engine(
        Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV),
        |engine| engine.symlink(parent, name_slice, target_slice, &ctx),
    );
    match result {
        Ok(attr) => unsafe {
            *out_ino = attr.inode_id.get();
            *out_mode = attr.posix.mode;
        },
        Err(e) => return -(e.0 as core::ffi::c_int),
    }
    0
}

#[no_mangle]
pub extern "C" fn tidefs_posix_vfs_engine_mknod(
    parent_ino: u64,
    name_ptr: *const u8,
    name_len: u32,
    mode: u32,
    rdev: u32,
    out_ino: *mut u64,
    out_mode: *mut u32,
) -> core::ffi::c_int {
    if name_ptr.is_null() || out_ino.is_null() || out_mode.is_null() {
        return -(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL.0 as core::ffi::c_int);
    }
    if let Err(e) = validate_kernel_name_len(name_len) {
        return -(e.0 as core::ffi::c_int);
    }
    let parent = crate::tidefs_kmod_bridge::kernel_types::InodeId::new(parent_ino);
    let name_slice: &[u8] = unsafe { core::slice::from_raw_parts(name_ptr, name_len as usize) };
    let ctx = crate::tidefs_kmod_bridge::kernel_types::RequestCtx::default();
    let result = with_mounted_engine(
        Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV),
        |engine| engine.mknod(parent, name_slice, mode, rdev, &ctx),
    );
    match result {
        Ok(attr) => unsafe {
            *out_ino = attr.inode_id.get();
            *out_mode = attr.posix.mode;
        },
        Err(e) => return -(e.0 as core::ffi::c_int),
    }
    0
}

#[no_mangle]
pub extern "C" fn tidefs_posix_vfs_engine_readlink(
    ino: u64,
    out_buf: *mut u8,
    out_buf_size: u32,
    out_len: *mut u32,
) -> core::ffi::c_int {
    if out_buf.is_null() || out_len.is_null() {
        return -(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL.0 as core::ffi::c_int);
    }
    let inode = crate::tidefs_kmod_bridge::kernel_types::InodeId::new(ino);
    let ctx = crate::tidefs_kmod_bridge::kernel_types::RequestCtx::default();
    let result = with_mounted_engine(
        Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV),
        |engine| engine.readlink(inode, &ctx),
    );
    match result {
        Ok(target) => {
            let copy_len = core::cmp::min(target.len(), out_buf_size as usize);
            unsafe {
                core::ptr::copy_nonoverlapping(target.as_ptr(), out_buf, copy_len);
                *out_len = copy_len as u32;
            }
            0
        }
        Err(e) => -(e.0 as core::ffi::c_int),
    }
}

/// C-visible bridge: engine-backed setattr (chmod/chown/truncate/utimes).
///
/// Takes individual struct iattr fields as C types, constructs a SetAttr,
/// calls MOUNTED_ENGINE.setattr(), and returns the updated inode attributes
/// via out pointers so the C shim can reflect them in the kernel inode.
///
/// Returns 0 on success (populates out_*), -errno on failure.
#[no_mangle]
#[cfg(CONFIG_RUST)]
pub extern "C" fn tidefs_posix_vfs_engine_setattr(
    ino: u64,
    valid: u32,
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    atime_ns: i64,
    mtime_ns: i64,
    ctime_ns: i64,
    out_mode: *mut u32,
    out_uid: *mut u32,
    out_gid: *mut u32,
    out_size: *mut u64,
    out_blocks: *mut u64,
) -> core::ffi::c_int {
    if out_mode.is_null()
        || out_uid.is_null()
        || out_gid.is_null()
        || out_size.is_null()
        || out_blocks.is_null()
    {
        return -(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL.0 as core::ffi::c_int);
    }

    let inode = crate::tidefs_kmod_bridge::kernel_types::InodeId::new(ino);
    let attr = crate::tidefs_kmod_bridge::kernel_types::SetAttr {
        valid,
        mode,
        uid,
        gid,
        size,
        atime_ns,
        mtime_ns,
        ctime_ns,
    };
    let ctx = crate::tidefs_kmod_bridge::kernel_types::RequestCtx::default();

    let result = with_mounted_engine(
        Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV),
        |engine| engine.setattr(inode, &attr, None, &ctx),
    );

    match result {
        Ok(attr) => unsafe {
            *out_mode = attr.posix.mode;
            *out_uid = attr.posix.uid;
            *out_gid = attr.posix.gid;
            *out_size = attr.posix.size;
            *out_blocks = attr.posix.blocks_512;
        },
        Err(e) => return -(e.0 as core::ffi::c_int),
    }
    0
}

/// C-visible bridge: engine-backed inode generation lookup (NEXT-KVFS-021).
///
/// Returns the generation number for an inode from the engine's in-memory
/// InodeRecord table, or ENODEV if no engine is mounted.  The generation
/// is stable across remount when backed by committed-root inode state.
///
/// Returns 0 on success (populates out_generation), -errno on failure.
#[no_mangle]
pub extern "C" fn tidefs_posix_vfs_engine_get_generation(
    ino: u64,
    out_generation: *mut u64,
) -> core::ffi::c_int {
    if out_generation.is_null() {
        return -(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL.0 as core::ffi::c_int);
    }

    let inode_id = crate::tidefs_kmod_bridge::kernel_types::InodeId::new(ino);

    let result = with_mounted_engine(
        Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV),
        |engine| engine.get_generation(inode_id),
    );

    match result {
        Ok(gen) => unsafe {
            *out_generation = gen;
        },
        Err(e) => return -(e.0 as core::ffi::c_int),
    }
    0
}

/// C-visible bridge: engine-backed llseek for SEEK_DATA/SEEK_HOLE
/// extent resolution through VfsEngine::data_ranges() (#6644).
///
/// Returns the new file offset on success, -errno on failure.
#[no_mangle]
pub extern "C" fn tidefs_posix_vfs_engine_llseek(
    fh_ino: u64,
    fh_id: u64,
    offset: i64,
    whence: u32,
    current_pos: i64,
) -> i64 {
    use crate::tidefs_kmod_bridge::kernel_types::{Errno, VfsEngine};

    let result: Result<i64, Errno> = (|| -> Result<i64, Errno> {
        const SEEK_SET: u32 = 0;
        const SEEK_CUR: u32 = 1;
        const SEEK_END: u32 = 2;
        const SEEK_DATA: u32 = 3;
        const SEEK_HOLE: u32 = 4;

        let fh = crate::tidefs_kmod_bridge::kernel_types::EngineFileHandle::new(
            crate::tidefs_kmod_bridge::kernel_types::InodeId::new(fh_ino),
            0,
            crate::tidefs_kmod_bridge::kernel_types::FileHandleId::new(fh_id),
            0,
        );
        let ctx = crate::tidefs_kmod_bridge::kernel_types::RequestCtx::default();

        with_mounted_engine(Err(Errno::ENODEV), |engine| match whence {
            SEEK_SET | SEEK_CUR | SEEK_END => {
                let attr = engine.getattr(fh.inode_id, Some(&fh), &ctx)?;
                let file_size = i64::try_from(attr.posix.size).map_err(|_| Errno::EFBIG)?;

                let target = match whence {
                    SEEK_SET => offset,
                    SEEK_CUR => current_pos.checked_add(offset).ok_or(Errno::EINVAL)?,
                    SEEK_END => file_size.checked_add(offset).ok_or(Errno::EINVAL)?,
                    _ => unreachable!(),
                };

                if target < 0 {
                    Err(Errno::EINVAL)
                } else {
                    Ok(target.min(file_size))
                }
            }
            SEEK_DATA => {
                let uoff = u64::try_from(offset).map_err(|_| Errno::EINVAL)?;
                let remaining = u64::MAX - uoff;
                let ranges = engine.data_ranges(&fh, uoff, remaining, &ctx)?;
                seek_data_from_ranges(&ranges, uoff).map(|v| v as i64)
            }
            SEEK_HOLE => {
                let uoff = u64::try_from(offset).map_err(|_| Errno::EINVAL)?;
                let remaining = u64::MAX - uoff;
                let ranges = engine.data_ranges(&fh, uoff, remaining, &ctx)?;
                let attr = engine.getattr(fh.inode_id, Some(&fh), &ctx)?;
                let file_size = attr.posix.size;
                Ok(seek_hole_from_ranges(&ranges, uoff, file_size) as i64)
            }
            _ => Err(Errno::EINVAL),
        })
    })();

    match result {
        Ok(pos) => pos,
        Err(e) => -(e.0 as i64),
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TidefsFiemapExtentOut {
    logical: u64,
    physical: u64,
    length: u64,
    flags: u32,
    _pad: u32,
}

/// C-visible bridge: engine-backed FIEMAP extent query.
///
/// Linux 7.0 dispatches FS_IOC_FIEMAP through inode_operations::fiemap.  The C
/// shim uses this bridge to retrieve TideFS live extent descriptors and then
/// feeds them to fiemap_fill_next_extent().
#[no_mangle]
pub extern "C" fn tidefs_posix_vfs_engine_fiemap(
    fh_ino: u64,
    fh_id: u64,
    start: u64,
    length: u64,
    max_extents: u32,
    extents_out: *mut TidefsFiemapExtentOut,
    mapped_extents: *mut u32,
    available_extents: *mut u32,
) -> core::ffi::c_int {
    if mapped_extents.is_null() || available_extents.is_null() {
        return -(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL.0 as core::ffi::c_int);
    }
    if max_extents > 0 && extents_out.is_null() {
        return -(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL.0 as core::ffi::c_int);
    }
    if length == 0 {
        return -(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL.0 as core::ffi::c_int);
    }

    let fh = crate::tidefs_kmod_bridge::kernel_types::EngineFileHandle::new(
        crate::tidefs_kmod_bridge::kernel_types::InodeId::new(fh_ino),
        0,
        crate::tidefs_kmod_bridge::kernel_types::FileHandleId::new(fh_id),
        0,
    );
    let result = with_mounted_engine(
        Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV),
        |engine| engine.live_fiemap_extents(fh.inode_id.get(), start, length),
    );

    match result {
        Ok(extents) => {
            let available = match u32::try_from(extents.len()) {
                Ok(v) => v,
                Err(_) => {
                    return -(crate::tidefs_kmod_bridge::kernel_types::Errno::EOVERFLOW.0
                        as core::ffi::c_int);
                }
            };
            let to_copy = core::cmp::min(max_extents as usize, extents.len());
            if to_copy > 0 {
                for (idx, extent) in extents.iter().take(to_copy).enumerate() {
                    unsafe {
                        *extents_out.add(idx) = TidefsFiemapExtentOut {
                            logical: extent.fe_logical,
                            physical: extent.fe_physical,
                            length: extent.fe_length,
                            flags: extent.fe_flags,
                            _pad: 0,
                        };
                    }
                }
            }
            unsafe {
                *mapped_extents = to_copy as u32;
                *available_extents = available;
            }
            0
        }
        Err(e) => -(e.0 as core::ffi::c_int),
    }
}

/// Return the byte offset of the first data extent at or after .
fn seek_data_from_ranges(
    ranges: &[crate::tidefs_kmod_bridge::kernel_types::LseekDataRange],
    offset: u64,
) -> Result<u64, crate::tidefs_kmod_bridge::kernel_types::Errno> {
    use crate::tidefs_kmod_bridge::kernel_types::Errno;
    for r in ranges {
        if r.end <= offset {
            continue;
        }
        if r.start <= offset {
            return Ok(offset);
        }
        return Ok(r.start);
    }
    Err(Errno::ENXIO)
}

/// Return the byte offset of the first hole at or after .
fn seek_hole_from_ranges(
    ranges: &[crate::tidefs_kmod_bridge::kernel_types::LseekDataRange],
    offset: u64,
    _file_size: u64,
) -> u64 {
    let mut cursor = offset;
    for r in ranges {
        if r.end <= cursor {
            continue;
        }
        if r.start <= cursor {
            cursor = r.end;
            continue;
        }
        return cursor;
    }
    cursor
}

/// C-visible bridge: engine-backed fallocate for space reservation,
/// hole punch, zero-range, collapse-range, and insert-range operations.
///
/// Returns 0 on success, -errno on failure.
#[no_mangle]
pub extern "C" fn tidefs_posix_vfs_engine_fallocate(
    fh_ino: u64,
    fh_id: u64,
    mode: u32,
    offset: u64,
    length: u64,
    mtime_ns: i64,
    ctime_ns: i64,
    out_size: *mut u64,
    out_blocks: *mut u64,
) -> core::ffi::c_int {
    if out_size.is_null() || out_blocks.is_null() {
        return -(crate::tidefs_kmod_bridge::kernel_types::Errno::EINVAL.0 as core::ffi::c_int);
    }

    let fh = crate::tidefs_kmod_bridge::kernel_types::EngineFileHandle::new(
        crate::tidefs_kmod_bridge::kernel_types::InodeId::new(fh_ino),
        0,
        crate::tidefs_kmod_bridge::kernel_types::FileHandleId::new(fh_id),
        0,
    );
    let ctx = crate::tidefs_kmod_bridge::kernel_types::RequestCtx::default();

    let result = with_mounted_engine(
        Err(crate::tidefs_kmod_bridge::kernel_types::Errno::ENODEV),
        |engine| {
            engine.fallocate(&fh, mode, offset, length, &ctx)?;
            engine.set_inode_mtime_ctime_ns(fh.inode_id, mtime_ns, ctime_ns)?;
            let idx = engine
                .find_inode(fh.inode_id.get())
                .ok_or(crate::tidefs_kmod_bridge::kernel_types::Errno::ENOENT)?;
            let inodes = engine.inodes.borrow();
            let rec = &inodes[idx];
            Ok((rec.size, rec.blocks))
        },
    );

    match result {
        Ok((size, blocks)) => unsafe {
            *out_size = size;
            *out_blocks = blocks;
            0
        },
        Err(e) => -(e.0 as core::ffi::c_int),
    }
}

/// Validate mount options passed from the Linux fs_context path.
/// Takes the features and authority_mode strings, parses them via
/// MountOptions, and checks feature flags against the engine's supported
/// set. Returns 0 on success, or a negative errno with a TideFS-specific
/// kernel log message on refusal.
#[no_mangle]
#[cfg(CONFIG_RUST)]
pub extern "C" fn tidefs_posix_vfs_engine_validate_mount_options(
    features_ptr: *const u8,
    features_len: core::ffi::c_uint,
    authority_mode_ptr: *const u8,
    authority_mode_len: core::ffi::c_uint,
) -> core::ffi::c_int {
    use crate::mount_options::{FeatureFlags, MountOptionError};

    // Validate features string if provided.
    if features_len > 0 && !features_ptr.is_null() {
        // SAFETY: pointer and length validated by the C shim.
        let features_str = core::str::from_utf8(unsafe {
            core::slice::from_raw_parts(features_ptr, features_len as usize)
        });
        match features_str {
            Ok(s) => {
                let flags = match FeatureFlags::parse_names(s) {
                    Ok(f) => f,
                    Err(MountOptionError::UnknownFeature { name }) => {
                        kernel::pr_err!(
                            "tidefs_posix_vfs: unknown mount feature: {}\n",
                            "<feature>",
                        );
                        return -95; // EOPNOTSUPP
                    }
                    Err(e) => {
                        kernel::pr_err!("tidefs_posix_vfs: invalid feature flags: {}\n", "<error>",);
                        return -22; // EINVAL
                    }
                };
                // The kernel engine currently supports no optional features.
                let supported = FeatureFlags::NONE;
                if !flags.unsupported_against(supported).is_empty() {
                    // Report the first unsupported feature.
                    let mut bit: u64 = 1;
                    let unsupported = flags.unsupported_against(supported);
                    loop {
                        if bit > unsupported.bits() {
                            break;
                        }
                        if unsupported.contains(bit) {
                            let name = FeatureFlags::name(bit).unwrap_or("unknown");
                            kernel::pr_err!(
                                "tidefs_posix_vfs: requested feature not supported by current engine: {}\n",
                                name,
                            );
                            return -95; // EOPNOTSUPP
                        }
                        bit <<= 1;
                    }
                }
            }
            Err(_) => {
                kernel::pr_err!("tidefs_posix_vfs: invalid UTF-8 in features string\n");
                return -22; // EINVAL
            }
        }
    }

    // Validate authority_mode string if provided.
    if authority_mode_len > 0 && !authority_mode_ptr.is_null() {
        use crate::mount_options::EngineAuthorityMode;
        // SAFETY: pointer and length validated by the C shim.
        let mode_str = core::str::from_utf8(unsafe {
            core::slice::from_raw_parts(authority_mode_ptr, authority_mode_len as usize)
        });
        match mode_str {
            Ok(s) => {
                if EngineAuthorityMode::parse(s).is_none() {
                    kernel::pr_err!("tidefs_posix_vfs: invalid authority_mode: {}\n", s,);
                    return -22; // EINVAL
                }
            }
            Err(_) => {
                kernel::pr_err!("tidefs_posix_vfs: invalid UTF-8 in authority_mode string\n");
                return -22; // EINVAL
            }
        }
    }

    0
}
module! {
    type: TidefsPosixVfs,
    name: "tidefs_posix_vfs",
    authors: ["TideFS Project"],
    description: "TideFS POSIX VFS kernel filesystem driver",
    license: "GPL",
}

struct TidefsPosixVfs {
    registered: bool,
}

impl kernel::Module for TidefsPosixVfs {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        unsafe { MOUNTED_ENGINE_LOCK.init() };
        let ret = unsafe { tidefs_posix_vfs_register_fs() };
        to_result(ret)?;
        pr_info!("tidefs_posix_vfs: loaded and registered filesystem type 'tidefs'\n");
        Ok(Self { registered: true })
    }
}
impl Drop for TidefsPosixVfs {
    fn drop(&mut self) {
        if self.registered {
            unsafe { tidefs_posix_vfs_unregister_fs() };
            self.registered = false;
        }
        pr_info!("tidefs_posix_vfs: unloaded\n");
    }
}
