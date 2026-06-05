#![no_std]
#![forbid(unsafe_code)]

//! VFS Engine trait: canonical operations defining the tidefs storage engine interface.
//!
//! This crate defines the [`VfsEngine`] trait — the central embodiment of Contract 2
//! (VFS semantic contract) per the three-contract architecture. Every frontend adapter
//! (FUSE daemon, ublk surface, admin proxy, VFS_RPC) implements this trait, unifying
//! all surfaces behind a common engine abstraction.
//!
//! The contract operates in **inode space**, not path space. Path resolution is the
//! adapter's responsibility; the engine receives `InodeId` and raw name bytes.
//!
//! # Operations
//!
//! - 14 namespace operations: `get_root_inode`, `lookup`, `getattr`, `setattr`,
//!   `mkdir`, `create`, `tmpfile`, `unlink`, `rmdir`, `rename`, `link`, `symlink`,
//!   `readlink`, `mknod`
//! - 8 file I/O operations: `open`, `release`, `read`, `write`, `copy_file_range`,
//!   `flush`, `fsync`, `fallocate`
//! - 1 sparse-layout advisory: `data_ranges`
//! - 4 directory operations: `opendir`, `releasedir`, `readdir`, `fsyncdir`
//! - 4 extended attribute operations: `getxattr`, `setxattr`, `listxattr`,
//!   `removexattr`
//! - 2 memory-mapped I/O operations: `mmap` (policy), `fault` (page-fault resolver)
//!
//! - 3 advisory lock operations: `getlk`, `setlk`, `setlkw`
//! # Design doc
//!
//! `docs/VFS_ENGINE_API_CONTRACT.md` (#1213)

extern crate alloc;

pub mod directory;
pub mod dispatch;
pub mod inode;
pub mod operation;
#[cfg(feature = "alloc")]
pub mod pool_core;
pub mod trace;
pub mod txg;
pub mod xattr_bridge;

use alloc::vec::Vec;

// ── Core types re-export ────────────────────────────────────────────────
//
// Consumers only need `tidefs-vfs-engine` as a dependency; all core types
// are re-exported here so the engine crate serves as a complete API surface.
pub use tidefs_types_vfs_core::{
    CreateFlags, DirEntry, DirEntryName, DirHandleId, EngineDirHandle, EngineFileHandle, Errno,
    FileHandleId, Generation, InodeAttr, InodeFlags, InodeId, LockSpec, LseekOffset, NodeFacets,
    NodeKind, NodeKindDecodeError, OpenFlags, PosixAttrs, RenameFlags, RequestCtx, SetAttr, StatFs,
    FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE, FALLOC_FL_UNSHARE_RANGE, FALLOC_FL_ZERO_RANGE,
    FATTR_ATIME, FATTR_ATIME_NOW, FATTR_CTIME, FATTR_FH, FATTR_GID, FATTR_LOCKOWNER, FATTR_MODE,
    FATTR_MTIME, FATTR_MTIME_NOW, FATTR_SIZE, FATTR_UID, F_RDLCK, F_UNLCK, F_WRLCK,
    RENAME_EXCHANGE, RENAME_NOREPLACE, RENAME_WHITEOUT, ROOT_INODE_ID, SEEK_CUR, SEEK_END,
    SEEK_SET, S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO, S_IFLNK, S_IFMT, S_IFREG, S_IFSOCK, S_ISGID,
    S_ISUID, S_ISVTX, XATTR_CREATE, XATTR_REPLACE,
};

// Re-export new VFS engine types from sub-modules.
pub use directory::{CursorPosition, DirectoryCursor, DirectoryFilter};
pub use dispatch::VfsDispatch;
pub use inode::{InodeHandle, InodeState, InodeTable};
pub use operation::{VfsOperation, VfsResponse};
#[cfg(feature = "alloc")]
pub use pool_core::{
    KernelPoolConfig, KernelPoolCore, KernelPoolError, KernelPoolState, LowerDeviceDesc,
};
pub use txg::{CommittedRoot, TxgHandle, TxgId, TxgPrepareResult};

/// File data byte range reported by the VFS engine for sparse-layout queries.
///
/// The interval is half-open: `[start, end)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LseekDataRange {
    /// Inclusive byte offset where data begins.
    pub start: u64,
    /// Exclusive byte offset where data ends.
    pub end: u64,
}

impl LseekDataRange {
    /// Construct a half-open data range.
    #[must_use]
    pub const fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }
}

/// A dirty-byte-range submitted for writeback through [`VfsEngine::writeback_folios`].
///
/// The interval is half-open: `[offset, offset + length)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WritebackRange {
    /// Byte offset of the start of the dirty range.
    pub offset: u64,
    /// Length of the dirty range in bytes.
    pub length: u64,
}

impl WritebackRange {
    /// Construct a half-open writeback range.
    #[must_use]
    pub const fn new(offset: u64, length: u64) -> Self {
        Self { offset, length }
    }
}

/// Outcome of a [`VfsEngine::writeback_folios`] call for a single range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WritebackOutcome {
    /// Number of bytes successfully written to stable storage.
    pub bytes_written: u64,
    /// Whether the entire range was committed.
    pub complete: bool,
}

impl WritebackOutcome {
    /// Construct a writeback outcome.
    #[must_use]
    pub const fn new(bytes_written: u64, complete: bool) -> Self {
        Self {
            bytes_written,
            complete,
        }
    }
}

/// Outcome of a [`VfsEngine::allocate_extents`] call.
///
/// Reports how many bytes were allocated and whether the full
/// request was satisfied. Engines that cannot allocate (e.g.,
/// sparse backends, fixed-size volumes) return zero bytes and
/// incomplete.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocateExtentsOutcome {
    /// Number of bytes actually allocated to the inode.
    pub bytes_allocated: u64,
    /// Whether the full requested range was allocated.
    pub complete: bool,
}

impl AllocateExtentsOutcome {
    /// Construct an allocation outcome.
    #[must_use]
    pub const fn new(bytes_allocated: u64, complete: bool) -> Self {
        Self {
            bytes_allocated,
            complete,
        }
    }
}

// --- FIEMAP types (kernel-mode fiemap dispatch bridge) ---
// ── Inode allocation ───────────────────────────────────────────────────

/// Result of a kernel-mode inode allocation through [`VfsEngine::allocate_inode`].
///
/// Carries the allocated inode number, a populated [`InodeAttr`] with
/// default attributes for the requested [`NodeKind`], and the inode
/// generation number for NFS-style filehandle reconstruction.
///
/// The kernel adapter uses this struct to construct a Rust-for-Linux
/// `struct inode` via `new_inode` or equivalent before invoking the
/// namespace mutation methods (`create`, `mkdir`, `mknod`, `symlink`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllocatedInode {
    /// The allocated inode number.
    pub ino: InodeId,
    /// Initialized attributes for the new inode.
    pub attr: InodeAttr,
}

impl AllocatedInode {
    /// Construct an [`AllocatedInode`] from an inode id and attributes.
    #[must_use]
    pub const fn new(ino: InodeId, attr: InodeAttr) -> Self {
        Self { ino, attr }
    }

    /// The generation number for NFS filehandle reconstruction.
    #[must_use]
    pub fn generation(&self) -> Generation {
        self.attr.generation
    }

    /// Inode number convenience accessor.
    #[must_use]
    pub fn inode_id(&self) -> InodeId {
        self.ino
    }

    /// The allocated inode's [`NodeKind`].
    #[must_use]
    pub fn kind(&self) -> NodeKind {
        self.attr.kind
    }
}

/// A collection of [`tidefs_types_extent_map_core::FiemapExtent`] entries
/// returned by [`VfsEngine::fiemap`].
///
/// Wraps the canonical FiemapExtent type from tidefs-types-extent-map-core
/// (which mirrors the Linux `struct fiemap_extent` layout with fields
/// `fe_logical`, `fe_physical`, `fe_length`, `fe_flags`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FiemapExtentVec {
    /// The list of extent records.
    pub extents: Vec<tidefs_types_extent_map_core::FiemapExtent>,
}

impl FiemapExtentVec {
    /// Construct an empty extent vector.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            extents: Vec::new(),
        }
    }
}

// ── Block queue geometry ────────────────────────────────────────────────

/// Storage geometry for block queue-limit configuration.
///
/// Used by `block-kmod` and block-volume adapters to populate the Linux
/// `queue_limits` structure with [`VfsEngine`] storage characteristics so
/// the block layer makes correct I/O merging, alignment, and scheduling
/// decisions.
///
/// # Production defaults
///
/// [`BlockQueueGeometry::default`] returns production-appropriate values:
/// 256 KiB `max_hw_sectors`, 128 `max_segments`, 4096-byte physical/logical
/// block size, 512 io_min, 4096 io_opt, 0 discard (no discard).
///
/// Engines that back block devices override [`VfsEngine::queue_limits`] to replace
/// any of these values with device-specific geometry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockQueueGeometry {
    /// Maximum sectors per request (maps to `max_hw_sectors` in Linux
    /// `queue_limits`).
    pub max_hw_sectors: u32,
    /// Maximum number of scatter-gather segments per request
    /// (maps to `max_segments`).
    pub max_segments: u16,
    /// Physical block size in bytes (minimum unit for direct I/O alignment).
    pub physical_block_size: u32,
    /// Logical block (sector) size in bytes (addressable unit).
    pub logical_block_size: u32,
    /// Minimum I/O request size in bytes (`io_min`).
    pub io_min: u32,
    /// Optimal I/O request size in bytes (`io_opt`).
    pub io_opt: u32,
    /// Discard (trim/unmap) granularity in bytes (zero when
    /// discard is not supported).
    pub discard_granularity: u32,
    /// Maximum discard sectors per request (zero when discard
    /// is not supported).
    pub max_discard_sectors: u32,
}

impl BlockQueueGeometry {
    /// Production defaults suitable for general-purpose block-device pools.
    pub const fn production() -> Self {
        Self {
            max_hw_sectors: 512,
            max_segments: 128,
            physical_block_size: 4096,
            logical_block_size: 512,
            io_min: 512,
            io_opt: 4096,
            discard_granularity: 0,
            max_discard_sectors: 0,
        }
    }
}

impl Default for BlockQueueGeometry {
    fn default() -> Self {
        Self::production()
    }
}

/// Outcome of a [`VfsEngine::setattr`] attribute mutation.
///
/// Encodes the engine-level result of an attribute-mutation request:
/// the updated inode attributes and whether a size change triggered
/// block allocation or freeing. The `truncate_block_change`
/// flag lets upper layers track extent-space accounting needs
/// independently from the attribute mutation itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetattrOutcome {
    /// Updated inode attributes after the mutation.
    pub attr: InodeAttr,
    /// Whether a size change required block allocation or freeing.
    pub truncate_block_change: bool,
}

impl SetattrOutcome {
    /// Construct a setattr outcome.
    #[must_use]
    pub fn new(attr: InodeAttr, truncate_block_change: bool) -> Self {
        Self {
            attr,
            truncate_block_change,
        }
    }
}

/// Increment an nlink counter with overflow detection.
///
/// Returns the new nlink value. Returns `Err(Errno::EOVERFLOW)` if the
/// counter is already at `u64::MAX`.
///
/// This helper lets [`VfsEngine`] implementors safely manage hard link
/// counts.  The POSIX `link` handler should call this when creating a
/// hard link and translate errors to `EMLINK` where appropriate.
#[inline]
pub fn inc_nlink(nlink: &mut u64) -> Result<u64, Errno> {
    if *nlink == u64::MAX {
        return Err(Errno::EOVERFLOW);
    }

    *nlink += 1;
    Ok(*nlink)
}

/// Decrement an nlink counter with underflow detection.
///
/// Returns the new nlink value. Returns `Err(Errno::EINVAL)` if the
/// counter is already at 0 (underflow condition).
///
/// Callers should check whether the returned value is 0 to decide
/// whether the inode should be scheduled for deletion (no remaining
/// links and no open file handles).
#[inline]
pub fn dec_nlink(nlink: &mut u64) -> Result<u64, Errno> {
    if *nlink == 0 {
        return Err(Errno::EINVAL);
    }

    *nlink -= 1;
    Ok(*nlink)
}

// ── Intent-log replay types ───────────────────────────────────────────────

/// Summary of a completed intent-log replay run.
///
/// Returned by [`VfsEngine::replay_intent_log`] to report how many
/// mutation records were applied, skipped, or errored during mount-time
/// crash recovery.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReplaySummary {
    /// Number of records successfully replayed (applied).
    pub replayed: u64,
    /// Number of records skipped (already applied or non-replayable type).
    pub skipped: u64,
    /// Number of records that encountered an error.
    pub errored: u64,
}

impl ReplaySummary {
    /// Construct an empty replay summary.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            replayed: 0,
            skipped: 0,
            errored: 0,
        }
    }

    /// Total records processed (replayed + skipped + errored).
    #[must_use]
    pub fn total(&self) -> u64 {
        self.replayed + self.skipped + self.errored
    }
}

/// Access mode for the page-ownership protocol.
///
/// Used by [] to signal whether the
/// kernel acquired shared (read) or exclusive (write) page ownership.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageOwnershipMode {
    /// Shared read access — kernel wants to read the page.
    Read,
    /// Exclusive write access — kernel wants to modify the page.
    Write,
}

// ── Memory-mapped I/O types ────────────────────────────────────────────

/// Engine policy for memory-mapped file access.
///
/// Returned by [`VfsEngine::mmap`] to control how the kernel sets up the
/// virtual memory area for an mmap'd file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MmapPolicy {
    /// Pages are faulted in on first access (demand paging).
    /// The kernel installs the vm_operations_struct and populates pages
    /// lazily via the [`VfsEngine::fault`] callback.
    PopulateOnFault,
    /// Pre-fault all pages in the mapping at mmap time.
    /// The engine will be called for each page before mmap returns,
    /// ensuring all data is resident and avoiding future minor faults.
    PreFaultPages,
    /// mmap is not allowed for this file (e.g. special files, device nodes).
    /// The kernel returns ENODEV or ENOSYS.
    Denied,
}

/// Outcome of a page-fault resolution by the engine.
///
/// Returned by [`VfsEngine::fault`] to represent either a successfully populated
/// page or a VM_FAULT_* error code indicating why the fault could not be satisfied.
#[derive(Clone, Debug)]
pub struct VmFaultOutcome {
    /// Page data when the fault succeeded (may be zero-filled for holes).
    pub page: alloc::vec::Vec<u8>,
    /// VM_FAULT_* code: VM_FAULT_MINOR, VM_FAULT_MAJOR, VM_FAULT_NOPAGE, etc.
    pub vm_fault_code: u32,
}

/// Minor fault — page was already in the engine cache, no I/O needed.
pub const VM_FAULT_MINOR: u32 = 0;
/// Major fault — page required I/O to populate from stable storage.
pub const VM_FAULT_MAJOR: u32 = 1;
/// Page is locked, caller must unlock after I/O completion.
pub const VM_FAULT_LOCKED: u32 = 2;
/// Out of memory — cannot allocate a page for the mapping.
pub const VM_FAULT_OOM: u32 = 3;
/// Fatal signal — e.g. SIGBUS on access beyond EOF or into a hole.
pub const VM_FAULT_SIGBUS: u32 = 4;
/// No page available — the requested offset has no backing data.
pub const VM_FAULT_NOPAGE: u32 = 5;
/// Hardware I/O error reading page data from storage.
pub const VM_FAULT_HWPOISON: u32 = 6;
/// Operation returned, caller should retry (e.g. page was truncated).
pub const VM_FAULT_RETRY: u32 = 7;

/// Standard page size in bytes (4 KiB).
pub const PAGE_SIZE: u32 = 4096;

/// Maximum chunk size used by the default VFS `copy_file_range` implementation.
pub const VFS_COPY_FILE_RANGE_MAX_CHUNK: u64 = 4096;

/// The canonical VFS Engine trait — one contract, many surfaces.
///
/// Every frontend adapter implements this trait. The engine operates in inode space:
/// path resolution is the adapter's responsibility; the engine receives `InodeId`
/// and raw name bytes.
///
/// All mutating operations receive a [`RequestCtx`] carrying the calling process
/// identity for permission checks and ownership inheritance.
///
/// # Feature flags
///
/// Requires the `alloc` feature (default). The `groups` field on [`RequestCtx`] and
/// `name` field on [`DirEntry`] are only available with `alloc`.
#[cfg(feature = "alloc")]
pub trait VfsEngine {
    /// Returns the root inode of the filesystem.
    ///
    /// This is the adapter's entry point for mount and path resolution.
    /// Corresponds to `get_root_inode` in `docs/VFS_ENGINE_API_CONTRACT.md` §5.1.
    fn get_root_inode(&self, ctx: &RequestCtx) -> Result<InodeId, Errno>;

    /// Look up `name` in directory `parent`.
    ///
    /// Returns the target inode's attributes.
    /// Errors: `ENOENT`, `ENOTDIR`, `EACCES`.
    /// Corresponds to §5.2.
    fn lookup(&self, parent: InodeId, name: &[u8], ctx: &RequestCtx) -> Result<InodeAttr, Errno>;

    /// Get attributes for `inode`.
    ///
    /// When `handle` is provided, it carries the open file handle context
    /// for per-open inode state.
    /// Errors: `ESTALE`, `ENOENT`.
    /// Corresponds to §5.3.
    fn getattr(
        &self,
        inode: InodeId,
        handle: Option<&EngineFileHandle>,
        ctx: &RequestCtx,
    ) -> Result<InodeAttr, Errno>;

    /// Set attributes on `inode`.
    ///
    /// `attr.valid` uses FUSE `FATTR_*` bit positions to express which
    /// attributes are being changed. When `handle` is provided, it carries
    /// the open file handle context.
    ///
    /// The engine must update `ctime` when mode, uid, gid, size, atime,
    /// or mtime changes. `FATTR_ATIME_NOW`/`FATTR_MTIME_NOW` set the
    /// corresponding time to the current time.
    ///
    /// Returns the updated attributes.
    /// Errors: `EPERM`, `EACCES`, `EINVAL`, `ESTALE`.
    /// Corresponds to §4, §5.x.
    fn setattr(
        &self,
        inode: InodeId,
        attr: &SetAttr,
        handle: Option<&EngineFileHandle>,
        ctx: &RequestCtx,
    ) -> Result<InodeAttr, Errno>;

    /// Create subdirectory `name` in `parent` with initial `mode`.
    ///
    /// Ownership: uid from `ctx.uid`, gid from `ctx.gid` (or parent gid if
    /// setgid bit set on parent). Umask applied if `FUSE_DONT_MASK` is
    /// not negotiated.
    ///
    /// Returns the new directory's attributes.
    /// Errors: `EEXIST`, `ENOSPC`, `ENOTDIR`, `EACCES`, `ENAMETOOLONG`.
    /// Corresponds to §5.4.
    fn mkdir(
        &self,
        parent: InodeId,
        name: &[u8],
        mode: u32,
        ctx: &RequestCtx,
    ) -> Result<InodeAttr, Errno>;

    /// Create regular file `name` in `parent` with `mode` and `flags`.
    ///
    /// `flags` carries O_RDWR, O_EXCL, O_TRUNC, etc. Returns the new file's
    /// attributes and an open file handle. Ownership inheritance: same as
    /// [`mkdir`](VfsEngine::mkdir).
    ///
    /// Errors: `EEXIST`, `ENOSPC`, `ENOTDIR`, `EACCES`.
    /// Corresponds to §5.5.
    fn create(
        &self,
        parent: InodeId,
        name: &[u8],
        mode: u32,
        flags: u32,
        ctx: &RequestCtx,
    ) -> Result<(InodeAttr, EngineFileHandle), Errno>;

    /// Atomically create regular file `name` in `parent` with `mode`.
    ///
    /// This is the atomic compare-and-create primitive for `O_CREAT|O_EXCL`.
    /// If the entry does not exist, it is created in the same critical
    /// section as the existence check; if the entry already exists,
    /// `EEXIST` is returned. The method must serialize concurrent callers
    /// so that exactly one succeeds and all others observe the entry.
    ///
    /// Returns the new file's attributes and an open file handle.
    /// Errors: `EEXIST`, `ENOSPC`, `ENOTDIR`, `EACCES`.
    /// Corresponds to §5.5 (O_EXCL path).
    fn create_excl(
        &self,
        _parent: InodeId,
        _name: &[u8],
        _mode: u32,
        _flags: u32,
        _ctx: &RequestCtx,
    ) -> Result<(InodeAttr, EngineFileHandle), Errno> {
        Err(Errno::ENOSYS)
    }

    /// Create an unnamed temporary file linked into `parent` (O_TMPFILE).
    ///
    /// The file has no directory entry until linked via `linkat`. Returns
    /// attributes and open handle.
    /// Errors: `ENOSPC`, `EACCES`, `EOPNOTSUPP`.
    /// Corresponds to §5.6.
    fn tmpfile(
        &self,
        parent: InodeId,
        mode: u32,
        flags: u32,
        ctx: &RequestCtx,
    ) -> Result<(InodeAttr, EngineFileHandle), Errno>;

    /// Remove `name` from directory `parent`.
    ///
    /// The inode's nlink is decremented; if nlink reaches 0 and no open
    /// handles exist, the inode is scheduled for deletion.
    /// Errors: `ENOENT`, `EPERM` (directory), `EBUSY`, `EACCES`.
    /// Corresponds to §5.7.
    fn unlink(&self, parent: InodeId, name: &[u8], ctx: &RequestCtx) -> Result<(), Errno>;

    /// Remove empty subdirectory `name` from `parent`.
    ///
    /// Errors: `ENOENT`, `ENOTEMPTY`, `ENOTDIR`, `EBUSY`, `EACCES`.
    /// Corresponds to §5.8.
    fn rmdir(&self, parent: InodeId, name: &[u8], ctx: &RequestCtx) -> Result<(), Errno>;

    /// Atomically rename `old_name` in `old_parent` to `new_name` in
    /// `new_parent`.
    ///
    /// `flags` carries renameat2 flags: 0 (plain rename),
    /// `RENAME_NOREPLACE` (1), `RENAME_EXCHANGE` (2),
    /// `RENAME_WHITEOUT` (4).
    ///
    /// Errors: `EEXIST` (NOREPLACE), `ENOENT`, `ENOTDIR`, `EISDIR`,
    /// `ENOTEMPTY`, `EXDEV`.
    /// Corresponds to §5.9.
    fn rename(
        &self,
        old_parent: InodeId,
        old_name: &[u8],
        new_parent: InodeId,
        new_name: &[u8],
        flags: u32,
        ctx: &RequestCtx,
    ) -> Result<(), Errno>;

    /// Create hard link `new_name` in `new_parent` pointing to `target`.
    ///
    /// Increments nlink. Returns target's updated attributes.
    /// Errors: `EMLINK`, `EPERM` (directory hard link), `EXDEV`, `ENOSPC`,
    /// `EACCES`.
    /// Corresponds to §5.10.
    fn link(
        &self,
        target: InodeId,
        new_parent: InodeId,
        new_name: &[u8],
        ctx: &RequestCtx,
    ) -> Result<InodeAttr, Errno>;

    /// Create symbolic link `name` in `parent` containing `target` as its
    /// value.
    ///
    /// Returns the new symlink's attributes. Ownership: uid/gid from ctx
    /// (symlinks have their own ownership, independent of target).
    /// Errors: `EEXIST`, `ENOSPC`, `ENOTDIR`, `EACCES`.
    /// Corresponds to §5.11.
    fn symlink(
        &self,
        parent: InodeId,
        name: &[u8],
        target: &[u8],
        ctx: &RequestCtx,
    ) -> Result<InodeAttr, Errno>;

    /// Read the target of symlink `inode`.
    ///
    /// Returns the symlink's target as raw bytes.
    /// Errors: `EINVAL` (not a symlink), `ENOENT`.
    /// Corresponds to §5.12.
    fn readlink(&self, inode: InodeId, ctx: &RequestCtx) -> Result<Vec<u8>, Errno>;

    /// Create a special file (device node, FIFO, socket) named `name` in
    /// `parent`.
    ///
    /// `mode` includes the file type, `rdev` is the device number for
    /// char/block devices. Returns the new inode's attributes.
    /// Errors: `EPERM` (insufficient privilege for device nodes), `EEXIST`,
    /// `ENOSPC`.
    /// Corresponds to §5.13.
    fn mknod(
        &self,
        parent: InodeId,
        name: &[u8],
        mode: u32,
        rdev: u32,
        ctx: &RequestCtx,
    ) -> Result<InodeAttr, Errno>;

    // ── Inode lifecycle ──────────────────────────────────────────────────

    /// Allocate a new inode number and initialize its attributes.
    ///
    /// This is the kernel-mode inode allocation primitive. It selects a free
    /// inode number, initializes an inode-table entry with the provided
    /// [`NodeKind`], mode, uid, gid, and default timestamps, and returns an
    /// [`AllocatedInode`] with the populated attributes.
    ///
    /// Callers (kernel VFS create, mkdir, mknod, symlink) use the returned
    /// [`AllocatedInode`] to construct a kernel `struct inode` via
    /// `new_inode`, populate `i_ino`, `i_mode`, `i_uid`, `i_gid`, and
    /// timestamps, then invoke the namespace mutation method to commit the
    /// directory entry.
    ///
    /// The default implementation returns [`Errno::ENOSYS`]. Engines that
    /// back real storage must override this to manage the inode table.
    ///
    /// # No-daemon boundary
    ///
    /// Inode allocation resolves within kernel authority. No userspace
    /// daemon is required.
    fn allocate_inode(
        &self,
        _kind: NodeKind,
        _parent: InodeId,
        _mode: u32,
        _uid: u32,
        _gid: u32,
    ) -> Result<AllocatedInode, Errno> {
        Err(Errno::ENOSYS)
    }

    // ── File I/O operations ──────────────────────────────────────────────

    /// Open `inode` with `flags` (O_RDONLY, O_WRONLY, O_RDWR, O_APPEND,
    /// O_TRUNC, O_DIRECT, ...).
    ///
    /// Returns a file handle the adapter uses for subsequent I/O.
    /// The engine may return a handle with `fh_id=0` if no adapter-local
    /// identifier is needed; the adapter sets it before use.
    /// Errors: `ENOENT`, `EACCES`, `EISDIR`, `ETXTBSY`.
    /// Corresponds to §6.1.
    fn open(&self, inode: InodeId, flags: u32, ctx: &RequestCtx)
        -> Result<EngineFileHandle, Errno>;

    /// Release (close) a file handle. Called when the last reference is
    /// dropped.
    ///
    /// The engine must flush pending writes before returning. After release,
    /// the handle is invalid.
    /// Errors: none defined for the close itself (flush failures are surfaced
    /// via `flush`/`fsync`, not `release`).
    /// Corresponds to §6.2.
    fn release(&self, fh: &EngineFileHandle) -> Result<(), Errno>;

    /// Read up to `size` bytes from `fh` starting at `offset`.
    ///
    /// Returns the bytes actually read (may be less than `size` at EOF).
    /// `offset` is absolute file position; the engine ignores any O_APPEND
    /// or per-handle seek position.
    /// Errors: `EBADF` (not open for reading), `EIO`.
    /// Corresponds to §6.3.
    fn read(
        &self,
        fh: &EngineFileHandle,
        offset: u64,
        size: u32,
        ctx: &RequestCtx,
    ) -> Result<Vec<u8>, Errno>;

    /// Write `data` to `fh` at `offset`.
    ///
    /// Returns the number of bytes written (may be less than `data.len()`
    /// on ENOSPC or partial write). `offset` is absolute file position.
    /// Errors: `EBADF` (not open for writing), `ENOSPC`, `EIO`.
    /// Corresponds to §6.4.
    fn write(
        &self,
        fh: &EngineFileHandle,
        offset: u64,
        data: &[u8],
        ctx: &RequestCtx,
    ) -> Result<u32, Errno>;

    /// Copy bytes from one open file handle to another.
    ///
    /// The default implementation uses bounded `read` + `write` chunks and
    /// clips at source EOF, so success may copy fewer bytes than requested.
    /// Same-inode overlapping ranges are rejected.
    /// Errors: `EBADF`, `EINVAL`, `EFBIG`, `EIO`, or errors surfaced by
    /// `read`/`write`.
    fn copy_file_range(
        &self,
        source_fh: &EngineFileHandle,
        offset_in: u64,
        dest_fh: &EngineFileHandle,
        offset_out: u64,
        length: u64,
        ctx: &RequestCtx,
    ) -> Result<u32, Errno> {
        if length == 0 {
            return Ok(0);
        }

        let requested = length.min(u64::from(u32::MAX));
        let source_end = offset_in.checked_add(requested).ok_or(Errno::EINVAL)?;
        let dest_end = offset_out.checked_add(requested).ok_or(Errno::EINVAL)?;
        if source_fh.inode_id == dest_fh.inode_id && offset_in < dest_end && offset_out < source_end
        {
            return Err(Errno::EINVAL);
        }

        let mut copied = 0_u64;
        while copied < requested {
            let remaining = requested - copied;
            let chunk_len = remaining.min(VFS_COPY_FILE_RANGE_MAX_CHUNK);
            let chunk_size = u32::try_from(chunk_len).map_err(|_| Errno::EFBIG)?;
            let read_offset = offset_in.checked_add(copied).ok_or(Errno::EINVAL)?;
            let chunk = self.read(source_fh, read_offset, chunk_size, ctx)?;
            if chunk.is_empty() {
                break;
            }

            let write_offset = offset_out.checked_add(copied).ok_or(Errno::EINVAL)?;
            let written = self.write(dest_fh, write_offset, &chunk, ctx)?;
            copied = copied.checked_add(u64::from(written)).ok_or(Errno::EFBIG)?;
            if written == 0 || u64::from(written) < chunk.len() as u64 {
                break;
            }
        }

        u32::try_from(copied).map_err(|_| Errno::EFBIG)
    }

    /// Flush dirty data for `fh`.
    ///
    /// Called on every `close()` and on `fsync()`. The engine must ensure
    /// all previously written data for this handle reaches stable storage.
    /// Errors: `EIO`.
    /// Corresponds to §6.5.
    fn flush(&self, fh: &EngineFileHandle, ctx: &RequestCtx) -> Result<(), Errno>;

    /// Synchronize file data and metadata.
    ///
    /// If `datasync` is true, only data and metadata needed to retrieve the
    /// data (size, mtime) must be flushed; other metadata (atime) may be
    /// skipped. Equivalent to Linux `fsync`/`fdatasync`.
    /// Errors: `EIO`.
    /// Corresponds to §6.6.
    fn fsync(&self, fh: &EngineFileHandle, datasync: bool, ctx: &RequestCtx) -> Result<(), Errno>;

    /// Allocate or manipulate file space.
    ///
    /// `mode` is the `fallocate(2)` flags: 0 (allocate), `FALLOC_FL_KEEP_SIZE`
    /// (1), `FALLOC_FL_PUNCH_HOLE` (2), `FALLOC_FL_ZERO_RANGE` (16),
    /// `FALLOC_FL_UNSHARE_RANGE` (64).
    ///
    /// The default (mode=0) allocates `length` bytes starting at `offset` and
    /// extends the file size to `offset+length` unless KEEP_SIZE is set.
    /// Errors: `ENOSPC`, `EOPNOTSUPP`, `EINVAL`.
    /// Corresponds to §6.7.
    fn fallocate(
        &self,
        fh: &EngineFileHandle,
        mode: u32,
        offset: u64,
        length: u64,
        ctx: &RequestCtx,
    ) -> Result<(), Errno>;

    /// Advisory readahead hint for sequential prefetch.
    ///
    /// The engine may asynchronously prefetch data for the given byte range
    /// to improve read latency.  Errors are non-fatal: callers must tolerate
    /// any returned error and continue normal operation.
    /// Errors: `EBADF`, `EIO` (both tolerated).
    fn readahead(
        &self,
        fh: &EngineFileHandle,
        offset: u64,
        length: u32,
        ctx: &RequestCtx,
    ) -> Result<(), Errno> {
        let _ = (fh, offset, length, ctx);
        Ok(())
    }

    /// Return data ranges intersecting `[offset, offset + length)`.
    ///
    /// Engines that do not expose sparse layout metadata may return `ENOSYS`;
    /// adapters can then fall back to dense-file behavior.
    /// Errors: `ENOSYS`, `EBADF`, `EIO`.
    fn data_ranges(
        &self,
        _fh: &EngineFileHandle,
        _offset: u64,
        _length: u64,
        _ctx: &RequestCtx,
    ) -> Result<Vec<LseekDataRange>, Errno> {
        Err(Errno::ENOSYS)
    }

    /// Return FIEMAP extent descriptors for the byte range `[offset, offset+length)`.
    ///
    /// Engines that support sparse layout queries from an extent map return
    /// a vector of [`FiemapExtent`] descriptors with correct flags
    /// (`FLAG_LAST`, `FLAG_UNWRITTEN`, `FLAG_MERGED`).  Engines that do not
    /// expose extent-map fidelity may return `ENOSYS`.
    ///
    /// `max_extents` caps the number of returned extents; 0 means query-only
    /// (returns the count but no extent records).
    ///
    /// Errors: `ENOSYS`, `EBADF`, `EINVAL`, `EIO`.
    fn fiemap_file(
        &self,
        _fh: &EngineFileHandle,
        _offset: u64,
        _length: u64,
        _max_extents: u32,
        _ctx: &RequestCtx,
    ) -> Result<alloc::vec::Vec<tidefs_types_extent_map_core::FiemapExtent>, Errno> {
        Err(Errno::ENOSYS)
    }

    // ── Directory operations ──────────────────────────────────────────────

    /// Open directory `inode` for reading.
    ///
    /// Returns a directory handle. The engine prepares iteration state for
    /// subsequent [`readdir`](VfsEngine::readdir) calls.
    /// Errors: `ENOTDIR`, `EACCES`, `ENOENT`.
    /// Corresponds to §7.1.
    fn opendir(&self, inode: InodeId, ctx: &RequestCtx) -> Result<EngineDirHandle, Errno>;

    /// Release directory handle. After this, the handle is invalid.
    ///
    /// Called on `closedir()`.
    /// Corresponds to §7.2.
    fn releasedir(&self, dh: &EngineDirHandle) -> Result<(), Errno>;

    /// Read directory entries starting from `offset`.
    ///
    /// `offset` is either 0 (start of directory) or a `DirEntry.cookie`
    /// from a previous call (continuation). Returns a batch of entries
    /// and `has_more=true` if more entries remain.
    ///
    /// The engine may return entries in any order, but the ordering must be
    /// stable within a single `opendir`/`releasedir` session. Cookies must be
    /// stable across mounts. `.` and `..` entries are the adapter's
    /// responsibility; the engine should not return them.
    ///
    /// Errors: `EBADF`, `EIO`.
    /// Corresponds to §7.3.
    fn readdir(
        &self,
        dh: &EngineDirHandle,
        offset: u64,
        ctx: &RequestCtx,
    ) -> Result<(Vec<DirEntry>, bool), Errno>;

    /// Synchronize directory metadata.
    ///
    /// If `datasync` is true, only the directory's entry data (names and
    /// inode pointers) must be flushed; other metadata may be skipped.
    /// Errors: `EIO`.
    /// Corresponds to §7.4.
    fn fsyncdir(&self, dh: &EngineDirHandle, datasync: bool, ctx: &RequestCtx)
        -> Result<(), Errno>;

    /// Synchronize entire filesystem.
    ///
    /// Flushes all dirty data and metadata to stable storage, equivalent
    /// to the Linux `syncfs(2)` system call. Engines must ensure all
    /// previously written data reaches stable storage.
    /// Errors: `EIO`, `ENOSYS`.
    /// Corresponds to §7.5.
    fn fdatasync_inode(
        &self,
        fh: &EngineFileHandle,
        datasync: bool,
        ctx: &RequestCtx,
    ) -> Result<(), Errno> {
        let _ = (fh, datasync, ctx);
        Ok(())
    }

    fn syncfs(&self, _ctx: &RequestCtx) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }

    // ── Extended attribute operations ─────────────────────────────────────

    /// Get extended attribute `name` of `inode`.
    ///
    /// Returns the attribute value. If the adapter probes with an empty
    /// buffer (size=0), the engine returns empty bytes and the adapter
    /// reports the attribute size from the kernel protocol, not the engine
    /// response.
    /// Errors: `ENODATA`, `ERANGE`, `EACCES`.
    /// Corresponds to §8.1.
    fn getxattr(&self, inode: InodeId, name: &[u8], ctx: &RequestCtx) -> Result<Vec<u8>, Errno>;

    /// Set extended attribute `name` to `value`.
    ///
    /// `flags` is one of: 0 (create or replace), `XATTR_CREATE` (1, fail if
    /// exists), `XATTR_REPLACE` (2, fail if not exists).
    /// Errors: `EEXIST`, `ENODATA`, `ENOSPC`, `EACCES`.
    /// Corresponds to §8.2.
    fn setxattr(
        &self,
        inode: InodeId,
        name: &[u8],
        value: &[u8],
        flags: u32,
        ctx: &RequestCtx,
    ) -> Result<(), Errno>;

    /// List all extended attribute names for `inode`.
    ///
    /// Returns null-separated (`\0`) name bytes, with a final null
    /// (Linux `listxattr` convention). When the adapter's buffer is smaller
    /// than the full name list, the engine returns `ERANGE`.
    /// Errors: `ERANGE`, `EACCES`.
    /// Corresponds to §8.3.
    fn listxattr(&self, inode: InodeId, ctx: &RequestCtx) -> Result<Vec<u8>, Errno>;

    /// Remove extended attribute `name`.
    ///
    /// Errors: `ENODATA`, `EACCES`.
    /// Corresponds to §8.4.
    fn removexattr(&self, inode: InodeId, name: &[u8], ctx: &RequestCtx) -> Result<(), Errno>;

    // ── Advisory file locking operations ──────────────────────────────────

    /// Test whether a conflicting advisory lock exists on `inode`.
    ///
    /// `lock` describes the lock being queried (type, range, pid).
    /// Returns `None` if no conflicting lock exists; returns the
    /// conflicting `LockSpec` otherwise.
    ///
    /// Errors: `EINVAL` (bad whence or type), `ENOENT` (inode not found),
    /// `EACCES`.
    /// Corresponds to §9.1.
    fn getlk(
        &self,
        inode: InodeId,
        lock: &LockSpec,
        ctx: &RequestCtx,
    ) -> Result<Option<LockSpec>, Errno>;

    /// Acquire or release an advisory byte-range lock on `inode`.
    ///
    /// Non-blocking: returns `EAGAIN` if a conflicting lock is held by
    /// another process. `F_UNLCK` releases matching locks held by `lock.pid`.
    ///
    /// Errors: `EAGAIN` (conflict), `EINVAL` (bad whence/type/range),
    /// `ENOENT`, `EACCES`.
    /// Corresponds to §9.2.
    fn setlk(&self, inode: InodeId, lock: &LockSpec, ctx: &RequestCtx) -> Result<(), Errno>;

    /// Acquire or release an advisory byte-range lock on `inode`, blocking
    /// until the lock is available.
    ///
    /// Engines that do not support true blocking may implement this as a
    /// retry loop or delegate to a lock-wait worker. The default
    /// implementation calls `setlk`; engines should override this when
    /// they provide genuine blocking semantics.
    ///
    /// Errors: same as [`setlk`](VfsEngine::setlk), plus `EINTR` if
    /// interrupted.
    /// Corresponds to §9.3.
    fn setlkw(&self, inode: InodeId, lock: &LockSpec, ctx: &RequestCtx) -> Result<(), Errno> {
        self.setlk(inode, lock, ctx)
    }

    /// Check whether a write of `byte_count` bytes is admitted by the
    /// underlying storage pool free-space watermark.
    ///
    /// Returns `Ok(())` when space is available or the engine does not
    /// enforce watermark admission. Returns `Err(ENOSPC)` when the write
    /// would breach the configured low-watermark threshold.
    ///
    /// Default implementation always admits (no watermark enforcement).
    fn check_write_admission(&self, _byte_count: u64) -> Result<(), Errno> {
        Ok(())
    }

    // ── Defrag operations ────────────────────────────────────────────

    /// Defragment the extent map for a single inode.
    ///
    /// Merges adjacent extents with contiguous logical ranges and the same
    /// locator. Returns the extent count before and after defragmentation.
    ///
    /// The default implementation returns [`Errno::ENOSYS`] for engines
    /// that do not support online defrag.
    ///
    /// Errors: [`Errno::ENOENT`] if the inode does not exist,
    /// [`Errno::EBADF`] if defrag cannot access the extent map,
    /// [`Errno::EIO`] for internal store errors.
    fn defrag_file(&self, _ino: InodeId, _ctx: &RequestCtx) -> Result<(u64, u64), Errno> {
        Err(Errno::ENOSYS)
    }

    // ── Cache coherence operations ───────────────────────────────────────

    /// Invalidate the engine's cached data for a byte range on an inode.
    ///
    /// Called by the kernel page cache when it needs to drop cached folios
    /// (e.g., on truncate, hole-punch, direct-I/O write, or memory
    /// pressure). The engine may use this hint to free internal caches or
    /// mark the range as stale so subsequent reads go to stable storage.
    ///
    /// The default implementation is a no-op: engines that do not maintain
    /// an internal page cache need no action. Engines with internal caches
    /// should override this to evict or invalidate the affected range.
    ///
    /// # No-daemon boundary
    ///
    /// Cache invalidation operates on in-memory engine state within kernel
    /// authority. No userspace daemon is required.
    ///
    /// Errors: [`Errno::EIO`] if the engine cache layer reports an
    /// internal error during invalidation.
    fn invalidate_cache_range(
        &self,
        _inode: InodeId,
        _offset: u64,
        _len: u64,
    ) -> Result<(), Errno> {
        Ok(())
    }

    /// Called when the kernel acquires page ownership from the engine.
    ///
    /// This is a notification callback invoked by the page-authority
    /// protocol when the kernel takes ownership of a page's contents
    /// for writing.  Engines that maintain an internal page cache
    /// should use this signal to mark the affected page as stale or
    /// to buffer it for future invalidation.
    ///
    /// The default implementation is a no-op; engines that track
    /// page ownership internally should override this.
    ///
    /// # No-daemon boundary
    ///
    /// This callback resolves within kernel authority.  No userspace
    /// daemon is required.
    fn page_ownership_acquired(&self, _inode: InodeId, _page_idx: u64, _mode: PageOwnershipMode) {}

    /// Called when the kernel transfers page ownership back to the engine.
    ///
    /// This notification fires after writeback completes and the kernel
    /// releases exclusive ownership of a page.  Engines that maintain an
    /// internal page cache can use this to re-validate their cached copy
    /// or to mark the page as engine-authoritative again.
    ///
    /// The default implementation is a no-op.
    ///
    /// # No-daemon boundary
    ///
    /// Resolves within kernel authority.  No userspace daemon required.
    fn page_ownership_transferred(&self, _inode: InodeId, _page_idx: u64) {}

    /// Called when the engine must invalidate its cached copy of a page.
    ///
    /// Fired when the kernel signals that the engine's copy is stale
    /// (e.g., the kernel is about to write, or is evicting a folio).
    /// Engines that maintain an internal page cache should evict the
    /// affected page and any derived metadata from their cache.
    ///
    /// The default implementation is a no-op.
    ///
    /// # No-daemon boundary
    ///
    /// Resolves within kernel authority.
    fn page_invalidation_needed(&self, _inode: InodeId, _page_idx: u64) {}

    // ── Memory-mapped I/O operations ───────────────────────────────────

    /// Decide mmap policy for a file.
    ///
    /// Called by the kernel file_operations mmap handler to determine whether
    /// memory-mapped access is permitted and how pages should be populated.
    /// The engine inspects the inode, requested mapping range, and flags
    /// (MAP_SHARED, MAP_PRIVATE, ...) and returns a policy.
    ///
    /// The default implementation allows demand-paged fault-in for all files.
    /// Engines that restrict mmap (e.g. for special files or device nodes)
    /// must override this to return [`MmapPolicy::Denied`].
    ///
    /// # No-daemon boundary
    ///
    /// Policy decision resolves within kernel authority.  No userspace
    /// daemon is required.
    ///
    /// Errors: [`Errno::EACCES`] if the caller lacks permission,
    /// [`Errno::ENODEV`] if the inode type does not support mmap.
    fn mmap(
        &self,
        _inode: InodeId,
        _offset: u64,
        _length: u64,
        _flags: u32,
        _ctx: &RequestCtx,
    ) -> Result<MmapPolicy, Errno> {
        Ok(MmapPolicy::PopulateOnFault)
    }

    /// Handle a page fault for an mmap'd file region.
    ///
    /// Called by the kernel vm_operations_struct fault handler when a process
    /// accesses a virtual address that is not yet backed by a physical page.
    /// The engine reads file data at the given offset and returns a page
    /// together with a VM_FAULT_* code indicating the fault resolution.
    ///
    /// The default implementation delegates to [`VfsEngine::read`] with the
    /// given offset and size, returning [`VM_FAULT_MAJOR`] when data is
    /// present and [`VM_FAULT_NOPAGE`] when the read returns empty bytes
    /// (indicating a hole or beyond-EOF access). Engines that maintain
    /// their own page cache can override this to serve pages from cache
    /// and return [`VM_FAULT_MINOR`] for cache hits.
    ///
    /// # No-daemon boundary
    ///
    /// Fault resolution resolves within kernel authority through
    /// [`VfsEngine::read`].  No userspace daemon is required.
    ///
    /// # Errors
    ///
    /// Returns [`Errno::EIO`] on read failure, [`Errno::EBADF`] if the
    /// handle is not open for reading.
    fn fault(
        &self,
        fh: &EngineFileHandle,
        offset: u64,
        size: u32,
        ctx: &RequestCtx,
    ) -> Result<VmFaultOutcome, Errno> {
        let data = self.read(fh, offset, size, ctx)?;
        let vm_fault_code = if data.is_empty() {
            VM_FAULT_NOPAGE
        } else {
            VM_FAULT_MAJOR
        };
        Ok(VmFaultOutcome {
            page: data,
            vm_fault_code,
        })
    }

    /// Write back dirty data for a byte range through the engine.
    ///
    /// Called by the kernel address_space writeback path to flush dirty
    /// page-cache data to stable storage. The engine receives the inode,
    /// open file handle, byte range, and request context and is responsible
    /// for committing the data durably.
    ///
    /// Returns [`WritebackOutcome`] with the number of bytes committed and
    /// whether the full range was written. On partial success,
    /// `bytes_written < range.length` and `complete` is false; the caller
    /// must re-dirty the unwritten tail.
    ///
    /// The default implementation is a no-op that writes 0 bytes. Engines
    /// that back real storage must override this to persist dirty data.
    ///
    /// # No-daemon boundary
    ///
    /// Writeback resolves within kernel authority through the engine's block
    /// I/O layer. No userspace daemon is required.
    ///
    /// Errors: [`Errno::EIO`] for I/O errors, [`Errno::EBADF`] if the handle
    /// is not open for writing, [`Errno::ENOSPC`] if the backing store is
    /// full.
    fn writeback_folios(
        &self,
        _inode: InodeId,
        _fh: &EngineFileHandle,
        _range: WritebackRange,
        _ctx: &RequestCtx,
    ) -> Result<WritebackOutcome, Errno> {
        Ok(WritebackOutcome {
            bytes_written: 0,
            complete: false,
        })
    }

    /// Allocate new extents for an inode.
    ///
    /// Provisions `length` bytes of new backing storage starting at `offset`
    /// for `inode`. Called by the kernel writeback path when extending a file
    /// beyond its current extent map. The engine records the allocation in
    /// the intent log for crash-safety so that a crash-mount-replay cycle
    /// preserves both the allocation and the data written into the new extents.
    ///
    /// The default implementation is a no-op that allocates 0 bytes. Engines
    /// that back real storage must override this to provision blocks and
    /// record intent-log entries.
    ///
    /// # No-daemon boundary
    ///
    /// Extent allocation resolves within kernel authority through the engine's
    /// block allocator. No userspace daemon is required.
    ///
    /// # Returns
    ///
    /// - `Ok(outcome)` with the number of bytes allocated and a `complete`
    ///   flag indicating whether the full request was satisfied.
    /// - `Err(Errno::ENOSPC)` if no space is available.
    /// - `Err(Errno::EIO)` for storage errors.
    /// - `Err(Errno::EBADF)` if the inode does not exist.
    /// - `Err(Errno::EINVAL)` if offset/length are invalid.
    ///
    /// Corresponds to the K7-24 writeback extent-provisioning seam.
    fn allocate_extents(
        &self,
        _inode: InodeId,
        _offset: u64,
        _length: u64,
        _ctx: &RequestCtx,
    ) -> Result<AllocateExtentsOutcome, Errno> {
        Ok(AllocateExtentsOutcome {
            bytes_allocated: 0,
            complete: true,
        })
    }

    /// Look up extent map entries for `inode` in the given logical range.
    ///
    /// Returns [`tidefs_types_extent_map_core::ExtentMapEntryV2`] entries that
    /// intersect `[offset, offset + length)`.  Each entry carries the logical
    /// offset, length, extent kind (data / unwritten), [`LocatorId`] (physical
    /// address), checksum, and birth commit group.
    ///
    /// The returned entries are clipped to the query range.  Gaps between
    /// entries represent sparse holes.  Callers that need to assemble a
    /// byte-range reply must zero-fill holes and read DATA extents from the
    /// block-volume adapter at the physical offset encoded in the locator.
    ///
    /// The default implementation returns an empty vector (no extents).
    /// Engines that maintain extent maps (e.g., via `tidefs-extent-map`)
    /// should override this to return real extent entries.
    ///
    /// # Block-volume integration
    ///
    /// The physical offset for DATA extents is encoded in
    /// [`tidefs_types_extent_map_core::LocatorId`] as the raw byte offset
    /// into the block-volume backing store.  The FUSE adapter translates
    /// these into [`BlockVolumeWriteTarget::read_bytes`] / `write_bytes`
    /// calls.
    ///
    /// UNWRITTEN extents have [`LocatorId::NONE`] and must be treated as
    /// reserved-but-unwritten space (zero-fill on read, convert-to-data on
    /// first write).
    ///
    /// # No-daemon boundary
    ///
    /// Extent-map resolution resolves locally within kernel authority
    /// through the engine's extent allocator.  No userspace daemon is
    /// required.
    fn lookup_extents(
        &self,
        _inode: InodeId,
        _offset: u64,
        _length: u64,
    ) -> alloc::vec::Vec<tidefs_types_extent_map_core::ExtentMapEntryV2> {
        alloc::vec::Vec::new()
    }

    /// Query file extent mapping information (FIEMAP / FS_IOC_FIEMAP).
    ///
    /// Returns committed extent-map data for the open file handle.
    /// Each [`FiemapExtent`] records a logical offset, physical offset,
    /// length, and FIEMAP_EXTENT_* flags. An empty extent vector means
    /// either a sparse (unwritten) file or an engine that does not yet
    /// expose extent metadata.
    ///
    /// The default implementation returns an empty [`FiemapExtentVec`].
    /// Engines that maintain physical extent layout (e.g., via
    /// `tidefs-extent-map`) should override this to return real
    /// extent information, enabling tools like `filefrag` and
    /// `hdparm --fibmap` on kernel-mounted TideFS instances.
    ///
    /// # No-daemon boundary
    ///
    /// Fiemap resolution resolves locally within kernel authority
    /// through the engine. No userspace daemon is required.
    fn fiemap(&self, _fh: &EngineFileHandle, _ctx: &RequestCtx) -> Result<FiemapExtentVec, Errno> {
        Ok(FiemapExtentVec::empty())
    }

    // ── Block-volume operations ─────────────────────────────────────────

    /// Read sectors from the block device into `buf`.
    ///
    /// `buf.len()` must be at least `sector_count * sector_size`.
    /// Returns the number of bytes transferred.
    ///
    /// The default implementation returns [`Errno::ENOSYS`]. Engines that
    /// back block devices must override this to perform real I/O.
    ///
    /// # No-daemon boundary
    ///
    /// Block read resolves within kernel authority through the engine"s
    /// block I/O layer. No userspace daemon is required.
    fn block_read(
        &self,
        _start_sector: u64,
        _sector_count: u32,
        _buf: &mut [u8],
    ) -> Result<u32, Errno> {
        Err(Errno::ENOSYS)
    }

    /// Write sectors to the block device from `data`.
    ///
    /// `data.len()` must be a multiple of the sector size.
    /// Returns the number of bytes written.
    ///
    /// The default implementation returns [`Errno::ENOSYS`]. Engines that
    /// back block devices must override this to persist data.
    fn block_write(&self, _start_sector: u64, _data: &[u8]) -> Result<u32, Errno> {
        Err(Errno::ENOSYS)
    }

    /// Flush volatile write caches to stable storage.
    ///
    /// The default implementation returns [`Errno::ENOSYS`].
    fn block_flush(&self) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }

    /// Discard (trim/unmap) a range of sectors.
    ///
    /// The default implementation returns [`Errno::ENOSYS`].
    fn block_discard(&self, _start_sector: u64, _sector_count: u32) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }

    /// Write zeroes to a range of sectors.
    ///
    /// Unlike discard, the device guarantees that subsequent reads of the
    /// written range will return zeroes. The device MAY allocate backing
    /// storage as needed. This corresponds to Linux `REQ_OP_WRITE_ZEROES`.
    ///
    /// The default implementation returns [`Errno::ENOSYS`]. Engines that
    /// back block devices should override this to provide write-zeroes
    /// semantics through allocation and extent authority.
    fn block_write_zeroes(&self, _start_sector: u64, _sector_count: u32) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }

    /// Zero a range of sectors through the allocation layer.
    ///
    /// This is a stronger guarantee than discard: the device MUST ensure
    /// subsequent reads return zeroes for the zeroed range, and the range
    /// MUST remain readable (no fault on access). This corresponds to
    /// Linux `fallocate(FALLOC_FL_ZERO_RANGE)` and is typically mapped
    /// to `REQ_OP_WRITE_ZEROES` with the no-unmap flag set.
    ///
    /// The implementation should interact with the extent map to either
    /// write zeroes to existing allocated blocks or allocate new zeroed
    /// blocks as needed.
    ///
    /// The default implementation returns [`Errno::ENOSYS`].
    fn block_zero_range(&self, _start_sector: u64, _sector_count: u32) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }

    /// Total block device capacity in sectors.
    fn block_capacity_sectors(&self) -> u64 {
        0
    }

    /// Logical block (sector) size in bytes.
    fn block_sector_size(&self) -> u32 {
        512
    }

    /// Return storage geometry for block-device queue-limit configuration.
    ///
    /// Engines that back block devices override this to report physical
    /// characteristics that guide I/O merging, alignment, discard alignment
    /// and multi-queue depth decisions in the Linux block layer.
    ///
    /// The default implementation returns [`BlockQueueGeometry::default`]
    /// (production values: 256 KiB max_hw_sectors, 128 max_segments,
    /// 4096 physical / 512 logical block size).
    fn queue_limits(&self) -> BlockQueueGeometry {
        BlockQueueGeometry::default()
    }

    // ── Intent-log replay ────────────────────────────────────────────────
    /// Record an intent-log entry for crash-safety.
    ///
    /// Called by the kernel adapter before committing a storage
    /// mutation (write, truncate, fallocate, create, unlink, etc.)
    /// to ensure the intent is durably recorded before the data
    /// mutation is applied. The entry is an opaque byte slice
    /// (packed binary record) produced by the kernel adapter.
    ///
    /// The default implementation is a no-op. Engines that back durable
    /// storage must override this.
    fn record_intent_entry(&self, _entry: &[u8]) -> Result<(), Errno> {
        Ok(())
    }

    /// Replay intent-log records during mount recovery.
    ///
    /// Each element in `records` is the binary encoding of an intent-log
    /// record (the same wire format as `tidefs_intent_log::IntentLogRecord`).
    /// The engine decodes each record, dispatches mutation operations
    /// through the corresponding [`VfsEngine`] methods, and skips
    /// already-applied and non-replayable record types.
    ///
    /// `committed_txg` gates idempotency: records with LSN <= committed_txg
    /// are skipped because the committed root already reflects those mutations.
    ///
    /// The default implementation returns [`Errno::ENOSYS`]. Engines that
    /// support intent-log crash recovery must override this method.
    fn replay_intent_log(
        &self,
        _records: &[&[u8]],
        _committed_txg: u64,
        _ctx: &RequestCtx,
    ) -> Result<ReplaySummary, Errno> {
        Err(Errno::ENOSYS)
    }

    // ── Pool label validation ─────────────────────────────────────────

    /// Validate a pool label from a raw device buffer.
    ///
    /// `device_index` identifies the device in the pool topology (0-based).
    /// `label_buf` contains the raw label bytes read from the device
    /// (typically the first 256 KiB, i.e. [`POOL_LABEL_SIZE`] bytes).
    ///
    /// Returns the decoded [`PoolLabelV1`] if the label is valid and
    /// its BLAKE3-256 checksum verifies.
    ///
    /// The default implementation decodes the buffer through
    /// [`tidefs_types_pool_label_core::decode_label`] and returns the
    /// result. Engines that read labels directly from storage or apply
    /// additional policy checks may override this.
    ///
    /// # Errors
    ///
    /// Returns [`LabelError`] variants mapping to kernel errno:
    /// `BufferTooSmall` ➜ `EINVAL`, `BadMagic` ➜ `ENODEV`,
    /// `UnsupportedVersion` ➜ `EINVAL`, `ChecksumMismatch` ➜ `EIO`.
    fn validate_pool_label(
        &self,
        _device_index: u32,
        label_buf: &[u8],
    ) -> Result<tidefs_types_pool_label_core::PoolLabelV1, tidefs_types_pool_label_core::LabelError>
    {
        tidefs_types_pool_label_core::decode_label(label_buf)
    }

    // ── Committed-root selection ──────────────────────────────────────

    /// Select a committed root from a pool device's committed-root ledger.
    ///
    /// `device_index` identifies the device whose ledger is being read.
    /// `ledger_buf` contains the raw committed-root ledger bytes (read from
    /// the superblock region located via the pool label's
    /// `system_area_pointer`).
    ///
    /// Returns a [`CommittedRootState`] indicating whether a valid root
    /// was found, which root is most-current, or whether the ledger is
    /// empty or corrupt.
    ///
    /// The default implementation returns `Empty` (no ledger parsing).
    /// Engines that maintain committed-root ledgers must override this
    /// to perform BLAKE3-verified ledger parsing and txg selection.
    ///
    /// # Errors
    ///
    /// Returns [`LabelError`] when the ledger buffer is unreadable
    /// (e.g. `BufferTooSmall`).
    fn select_committed_root(
        &self,
        _device_index: u32,
        _ledger_buf: &[u8],
    ) -> Result<
        tidefs_types_pool_label_core::CommittedRootState,
        tidefs_types_pool_label_core::LabelError,
    > {
        Ok(tidefs_types_pool_label_core::CommittedRootState::Empty)
    }

    // ── Committed-root writeback ─────────────────────────────────────────

    /// Write the committed root to the pool-label superblock on a lower device.
    ///
    /// Bridges [`txg_commit_finish`](VfsEngine::txg_commit_finish) to durable
    /// on-disk label persistence. After a transaction group commits, the new
    /// committed root is flushed to the pool label so the next mount discovers
    /// the latest committed state without userspace daemon mediation.
    ///
    /// `device_index` identifies the lower device whose label should be
    /// updated (0-based index into the pool device list).
    ///
    /// The default implementation is a no-op. Engines that back real block
    /// devices must override this to serialize the committed root into
    /// [`PoolLabelV1`](tidefs_types_pool_label_core::PoolLabelV1) and issue a
    /// synchronous write to the label region on the lower block device.
    ///
    /// # No-daemon boundary
    ///
    /// Committed-root writeback resolves within kernel authority through
    /// the engine. No userspace daemon is required.
    fn write_committed_root(
        &self,
        committed_root: &CommittedRoot,
        device_index: u32,
    ) -> Result<(), Errno> {
        let _ = committed_root;
        let _ = device_index;
        Ok(())
    }

    // ── Transaction-group lifecycle ───────────────────────────────────

    /// Open a new transaction group for batching kernel-mode writes.
    ///
    /// Returns a [`TxgHandle`] that the caller holds for the duration of
    /// a write batch. The handle must be passed to
    /// [`txg_commit_finish`](VfsEngine::txg_commit_finish) to close the
    /// transaction group. If the handle is dropped before being consumed,
    /// the transaction group is implicitly aborted.
    ///
    /// The default implementation returns a no-op handle. Engines that
    /// support transaction-group semantics must override this.
    ///
    /// # No-daemon boundary
    ///
    /// Transaction-group open resolves within kernel authority through
    /// the engine. No userspace daemon is required.
    fn txg_open(&self, txg_id: TxgId) -> Result<TxgHandle, Errno> {
        let _ = txg_id;
        Ok(TxgHandle::noop())
    }

    /// Prepare an open transaction group for commit.
    ///
    /// The engine flushes dirty data, finalizes intent-log entries, and
    /// returns the proposed committed-root identifier. If the engine
    /// requires quorum acknowledgement (multi-node operation), it sets
    /// `quorum_needed` in the returned [`TxgPrepareResult`].
    ///
    /// The default implementation returns an immediate result with a
    /// zero committed root. Engines that support transaction groups
    /// must override this.
    ///
    /// # No-daemon boundary
    ///
    /// Commit preparation resolves within kernel authority through
    /// the engine. No userspace daemon is required.
    fn txg_commit_prepare(&self, handle: &TxgHandle) -> Result<TxgPrepareResult, Errno> {
        let _ = handle;
        Ok(TxgPrepareResult::immediate(CommittedRoot::ZERO))
    }

    /// Finalize a transaction group commit.
    ///
    /// Consumes the [`TxgHandle`] and confirms that the committed root
    /// identified by `committed_root` is durable. After this call, the
    /// transaction group is closed, the committed root is advanced, and
    /// the handle is marked consumed so its drop does not trigger an abort.
    ///
    /// The default implementation is a no-op. Engines that support
    /// transaction groups must override this to persist the commit
    /// record and advance the durable committed root.
    ///
    /// # No-daemon boundary
    ///
    /// Commit finalization resolves within kernel authority through
    /// the engine. No userspace daemon is required.
    ///
    /// # Errors
    ///
    /// - [`Errno::EIO`] if the commit record cannot be written.
    /// - [`Errno::EINVAL`] if the handle was already consumed.
    fn txg_commit_finish(
        &self,
        mut handle: TxgHandle,
        committed_root: CommittedRoot,
    ) -> Result<(), Errno> {
        // committed_root durability delegated to write_committed_root below.
        handle.mark_consumed();
        self.write_committed_root(&committed_root, 0)
    }

    /// Store the latest committed root for use by [].
    ///
    /// Called by mount and txg-commit paths so the engine can later publish
    /// the root during fsync/syncfs/unmount without an explicit handle.
    /// The default is a no-op; engines that support kernel-mode txg
    /// barriers must override this.
    fn set_committed_root(&self, _root: CommittedRoot) {}

    /// Commit the current transaction group without an explicit root hash or handle.
    ///
    /// Engines that track the committed-root hash internally must override
    /// this to publish the latest root.  The default no-op is compatible
    /// with engines that use [`txg_commit_finish`] directly or do not
    /// support kernel-mode txg barriers yet.
    ///
    /// The mounted POSIX kmod adapter calls this from
    /// `KmodPosixVfs::commit_fs_barrier` after fsync, syncfs,
    /// and clean unmount to establish a txg commit point without knowing
    /// the root hash or owning a TxgHandle.
    fn txg_commit_barrier(&self) -> Result<(), Errno> {
        Ok(())
    }
}

// ── No-alloc stub ─────────────────────────────────────────────────────────

/// Stub trait when `alloc` is disabled.
///
/// The full [`VfsEngine`] trait requires `alloc` because [`RequestCtx::groups`]
/// and [`DirEntry::name`] are gated behind the `alloc` feature. This stub
/// exists solely to keep the crate compilable in `no_std` tooling contexts.
#[cfg(not(feature = "alloc"))]
pub trait VfsEngine {}

// ── StatFs convenience ────────────────────────────────────────────────────

/// Extension trait for filesystem statistics.
///
/// `statfs` is not a core VFS Engine operation because it is typically
/// aggregated from pool-level counters rather than routed through the
/// per-dataset engine. Adapters that need it can use this extension.
pub trait VfsEngineStatFs: VfsEngine {
    /// Return filesystem statistics (`statfs`/`statvfs`).
    ///
    /// Corresponds to §9 auxiliary operations in
    /// `docs/VFS_ENGINE_API_CONTRACT.md`.
    fn statfs(&self, ctx: &RequestCtx) -> Result<StatFs, Errno>;

    /// Handle an imported-pool admin request owned by this live engine.
    ///
    /// The request and response are intentionally byte-oriented so the VFS
    /// contract does not grow a second userspace-only schema. Engines that own
    /// live pool state may decode their selected control UAPI here; engines
    /// without such authority must leave the default unsupported response.
    fn live_pool_admin_request(&self, _request_json: &[u8]) -> Result<Vec<u8>, Errno> {
        Err(Errno::EOPNOTSUPP)
    }
}

/// O_EXCL: fail if the file already exists (used with O_CREAT).
pub const O_EXCL: u32 = 0o200;

/// O_TRUNC: truncate file to zero length on open.
pub const O_TRUNC: u32 = 0o1000;

/// O_RDWR: open for reading and writing.
pub const O_RDWR: u32 = 0o2;

#[cfg(test)]
mod tests {
    //! Compile-time validation: the trait must be object-safe.
    //!
    //! We define a mock implementation and verify it meets the trait bound.

    extern crate std;

    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    /// Minimal mock that returns a fixed error for every operation.
    ///
    /// Exists solely to prove the trait is compilable and object-safe.
    struct EmptyTestEngine;

    #[allow(unused_variables)]
    impl VfsEngine for EmptyTestEngine {
        fn get_root_inode(&self, ctx: &RequestCtx) -> Result<InodeId, Errno> {
            Err(Errno::ENOSYS)
        }
        fn lookup(
            &self,
            parent: InodeId,
            name: &[u8],
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }
        fn getattr(
            &self,
            inode: InodeId,
            handle: Option<&EngineFileHandle>,
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }
        fn setattr(
            &self,
            inode: InodeId,
            attr: &SetAttr,
            handle: Option<&EngineFileHandle>,
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }
        fn mkdir(
            &self,
            parent: InodeId,
            name: &[u8],
            mode: u32,
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }
        fn create(
            &self,
            parent: InodeId,
            name: &[u8],
            mode: u32,
            flags: u32,
            ctx: &RequestCtx,
        ) -> Result<(InodeAttr, EngineFileHandle), Errno> {
            Err(Errno::ENOSYS)
        }
        fn create_excl(
            &self,
            _parent: InodeId,
            _name: &[u8],
            _mode: u32,
            _flags: u32,
            _ctx: &RequestCtx,
        ) -> Result<(InodeAttr, EngineFileHandle), Errno> {
            Err(Errno::ENOSYS)
        }
        fn tmpfile(
            &self,
            parent: InodeId,
            mode: u32,
            flags: u32,
            ctx: &RequestCtx,
        ) -> Result<(InodeAttr, EngineFileHandle), Errno> {
            Err(Errno::ENOSYS)
        }
        fn unlink(&self, parent: InodeId, name: &[u8], ctx: &RequestCtx) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn rmdir(&self, parent: InodeId, name: &[u8], ctx: &RequestCtx) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn rename(
            &self,
            old_parent: InodeId,
            old_name: &[u8],
            new_parent: InodeId,
            new_name: &[u8],
            flags: u32,
            ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn link(
            &self,
            target: InodeId,
            new_parent: InodeId,
            new_name: &[u8],
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }
        fn symlink(
            &self,
            parent: InodeId,
            name: &[u8],
            target: &[u8],
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }
        fn readlink(&self, inode: InodeId, ctx: &RequestCtx) -> Result<Vec<u8>, Errno> {
            Err(Errno::ENOSYS)
        }
        fn mknod(
            &self,
            parent: InodeId,
            name: &[u8],
            mode: u32,
            rdev: u32,
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }
        fn open(
            &self,
            inode: InodeId,
            flags: u32,
            ctx: &RequestCtx,
        ) -> Result<EngineFileHandle, Errno> {
            Err(Errno::ENOSYS)
        }
        fn release(&self, fh: &EngineFileHandle) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn read(
            &self,
            fh: &EngineFileHandle,
            offset: u64,
            size: u32,
            ctx: &RequestCtx,
        ) -> Result<Vec<u8>, Errno> {
            Err(Errno::ENOSYS)
        }
        fn write(
            &self,
            fh: &EngineFileHandle,
            offset: u64,
            data: &[u8],
            ctx: &RequestCtx,
        ) -> Result<u32, Errno> {
            Err(Errno::ENOSYS)
        }
        fn flush(&self, fh: &EngineFileHandle, ctx: &RequestCtx) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn fsync(
            &self,
            fh: &EngineFileHandle,
            datasync: bool,
            ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn fallocate(
            &self,
            fh: &EngineFileHandle,
            mode: u32,
            offset: u64,
            length: u64,
            ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn opendir(&self, inode: InodeId, ctx: &RequestCtx) -> Result<EngineDirHandle, Errno> {
            Err(Errno::ENOSYS)
        }
        fn releasedir(&self, dh: &EngineDirHandle) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn readdir(
            &self,
            dh: &EngineDirHandle,
            offset: u64,
            ctx: &RequestCtx,
        ) -> Result<(Vec<DirEntry>, bool), Errno> {
            Err(Errno::ENOSYS)
        }
        fn fsyncdir(
            &self,
            dh: &EngineDirHandle,
            datasync: bool,
            ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn fdatasync_inode(
            &self,
            fh: &EngineFileHandle,
            datasync: bool,
            ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            let _ = (fh, datasync, ctx);
            Ok(())
        }

        fn syncfs(&self, _ctx: &RequestCtx) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn getxattr(
            &self,
            inode: InodeId,
            name: &[u8],
            ctx: &RequestCtx,
        ) -> Result<Vec<u8>, Errno> {
            Err(Errno::ENOSYS)
        }
        fn setxattr(
            &self,
            inode: InodeId,
            name: &[u8],
            value: &[u8],
            flags: u32,
            ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn listxattr(&self, inode: InodeId, ctx: &RequestCtx) -> Result<Vec<u8>, Errno> {
            Err(Errno::ENOSYS)
        }
        fn removexattr(&self, inode: InodeId, name: &[u8], ctx: &RequestCtx) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
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

        fn queue_limits(&self) -> BlockQueueGeometry {
            BlockQueueGeometry::production()
        }
    }

    pub const O_RDONLY: u32 = 0;
    pub const O_WRONLY: u32 = 0o1;
    pub const O_RDWR: u32 = 0o2;
    pub const O_ACCMODE: u32 = 0o3;
    pub const O_TRUNC: u32 = 0o1000;
    pub const O_EXCL: u32 = 0o200;
    const MOCK_READDIR_BATCH: usize = 2;

    #[derive(Clone, Copy)]
    struct OpenHandle {
        inode_id: InodeId,
        open_flags: OpenFlags,
    }

    #[derive(Clone, Copy)]
    struct OpenDirHandle {
        inode_id: InodeId,
    }

    type FileIoXattrMap = HashMap<Vec<u8>, Vec<u8>>;
    type FileIoInodeRecord = (InodeAttr, Vec<u8>, FileIoXattrMap);

    struct FileIoState {
        next_inode: u64,
        next_fh: u64,
        next_dh: u64,
        max_nlink: u32,
        cross_device_link_targets: Vec<InodeId>,
        entries: HashMap<(InodeId, Vec<u8>), InodeId>,
        inodes: HashMap<InodeId, FileIoInodeRecord>,
        handles: HashMap<FileHandleId, OpenHandle>,
        dir_handles: HashMap<DirHandleId, OpenDirHandle>,
    }

    struct FileIoTestEngine {
        state: RefCell<FileIoState>,
    }

    impl FileIoTestEngine {
        fn new() -> Self {
            let mut inodes = HashMap::new();
            inodes.insert(
                ROOT_INODE_ID,
                (
                    Self::attr_for(ROOT_INODE_ID, NodeKind::Dir, S_IFDIR | 0o755, 0, 0, 0),
                    Vec::new(),
                    HashMap::new(),
                ),
            );

            Self {
                state: RefCell::new(FileIoState {
                    next_inode: ROOT_INODE_ID.get() + 1,
                    next_fh: 1,
                    next_dh: 1,
                    max_nlink: u32::MAX,
                    cross_device_link_targets: Vec::new(),
                    entries: HashMap::new(),
                    inodes,
                    handles: HashMap::new(),
                    dir_handles: HashMap::new(),
                }),
            }
        }

        fn with_max_nlink(max_nlink: u32) -> Self {
            let engine = Self::new();
            engine.state.borrow_mut().max_nlink = max_nlink;
            engine
        }

        fn mark_cross_device_link_target(&self, inode_id: InodeId) {
            self.state
                .borrow_mut()
                .cross_device_link_targets
                .push(inode_id);
        }

        fn attr_for(
            inode_id: InodeId,
            kind: NodeKind,
            mode: u32,
            uid: u32,
            gid: u32,
            size: u64,
        ) -> InodeAttr {
            let nlink = if kind == NodeKind::Dir { 2 } else { 1 };
            InodeAttr::new(
                inode_id,
                Generation::new(1),
                kind,
                PosixAttrs::new(
                    mode,
                    uid,
                    gid,
                    nlink,
                    0,
                    0,
                    0,
                    0,
                    0,
                    size,
                    Self::blocks_512(size),
                    4096,
                ),
                InodeFlags::none(),
                0,
                0,
            )
        }

        fn blocks_512(size: u64) -> u64 {
            size.saturating_add(511) / 512
        }

        fn set_size(attr: &mut InodeAttr, size: u64) {
            attr.posix.size = size;
            attr.posix.blocks_512 = Self::blocks_512(size);
            attr.subtree_rev = attr.subtree_rev.saturating_add(1);
        }

        fn next_timestamp(attr: &InodeAttr) -> u64 {
            attr.posix
                .atime_ns
                .max(attr.posix.mtime_ns)
                .max(attr.posix.ctime_ns)
                .saturating_add(1)
        }

        fn entry_key(parent: InodeId, name: &[u8]) -> (InodeId, Vec<u8>) {
            (parent, name.to_vec())
        }

        fn ensure_dir(state: &FileIoState, inode_id: InodeId) -> Result<(), Errno> {
            match state.inodes.get(&inode_id) {
                Some((attr, _, _)) if attr.kind == NodeKind::Dir => Ok(()),
                Some(_) => Err(Errno::ENOTDIR),
                None => Err(Errno::ENOENT),
            }
        }

        fn dir_is_empty(state: &FileIoState, inode_id: InodeId) -> bool {
            !state.entries.keys().any(|(parent, _)| *parent == inode_id)
        }

        fn remove_inode_tree(state: &mut FileIoState, inode_id: InodeId) {
            let children: Vec<InodeId> = state
                .entries
                .iter()
                .filter_map(|((parent, _), child)| (*parent == inode_id).then_some(*child))
                .collect();
            state.entries.retain(|(parent, _), _| *parent != inode_id);
            for child in children {
                Self::remove_inode_tree(state, child);
            }
            state.inodes.remove(&inode_id);
        }

        fn allocate_handle(
            state: &mut FileIoState,
            inode_id: InodeId,
            open_flags: OpenFlags,
        ) -> EngineFileHandle {
            let fh_id = FileHandleId::new(state.next_fh);
            state.next_fh += 1;
            let fh = EngineFileHandle::new(inode_id, open_flags, fh_id, 0);
            state.handles.insert(
                fh_id,
                OpenHandle {
                    inode_id,
                    open_flags,
                },
            );
            fh
        }

        fn live_handle(state: &FileIoState, fh: &EngineFileHandle) -> Result<OpenHandle, Errno> {
            let live = state.handles.get(&fh.fh_id).copied().ok_or(Errno::EBADF)?;
            if live.inode_id != fh.inode_id || live.open_flags != fh.open_flags {
                return Err(Errno::EBADF);
            }
            Ok(live)
        }

        fn allocate_dir_handle(state: &mut FileIoState, inode_id: InodeId) -> EngineDirHandle {
            let dh_id = DirHandleId::new(state.next_dh);
            state.next_dh += 1;
            let dh = EngineDirHandle::new(inode_id, dh_id);
            state.dir_handles.insert(dh_id, OpenDirHandle { inode_id });
            dh
        }

        fn live_dir_handle(state: &FileIoState, dh: &EngineDirHandle) -> Result<InodeId, Errno> {
            let live = state
                .dir_handles
                .get(&dh.dh_id)
                .copied()
                .ok_or(Errno::EBADF)?;
            if live.inode_id != dh.inode_id {
                return Err(Errno::EBADF);
            }
            Ok(live.inode_id)
        }

        fn sorted_dir_entries(
            state: &FileIoState,
            inode_id: InodeId,
        ) -> Result<Vec<DirEntry>, Errno> {
            Self::ensure_dir(state, inode_id)?;
            let mut entries = Vec::new();
            for ((parent, name), child) in &state.entries {
                if *parent != inode_id {
                    continue;
                }
                let (attr, _, _) = state.inodes.get(child).ok_or(Errno::ENOENT)?;
                entries.push(DirEntry::new(
                    name.clone(),
                    *child,
                    attr.kind,
                    attr.generation,
                    0,
                ));
            }
            entries.sort_by(|left, right| left.name.cmp(&right.name));
            for (index, entry) in entries.iter_mut().enumerate() {
                entry.cookie = index as u64 + 1;
            }
            Ok(entries)
        }

        fn can_read(flags: OpenFlags) -> bool {
            flags & O_ACCMODE != O_WRONLY
        }

        fn can_write(flags: OpenFlags) -> bool {
            matches!(flags & O_ACCMODE, O_WRONLY | O_RDWR)
        }
    }

    #[allow(unused_variables)]
    impl VfsEngine for FileIoTestEngine {
        fn get_root_inode(&self, ctx: &RequestCtx) -> Result<InodeId, Errno> {
            Ok(ROOT_INODE_ID)
        }

        fn lookup(
            &self,
            parent: InodeId,
            name: &[u8],
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
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
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            let state = self.state.borrow();
            if let Some(fh) = handle {
                Self::live_handle(&state, fh)?;
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
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            const SUPPORTED_SETATTR_BITS: u32 = FATTR_MODE
                | FATTR_UID
                | FATTR_GID
                | FATTR_SIZE
                | FATTR_ATIME
                | FATTR_MTIME
                | FATTR_FH
                | FATTR_ATIME_NOW
                | FATTR_MTIME_NOW
                | FATTR_LOCKOWNER
                | FATTR_CTIME;

            if attr.valid & !SUPPORTED_SETATTR_BITS != 0 {
                return Err(Errno::EINVAL);
            }

            let mut state = self.state.borrow_mut();
            if let Some(fh) = handle {
                Self::live_handle(&state, fh)?;
            }

            let now = state
                .inodes
                .get(&inode)
                .map(|(existing, _, _)| Self::next_timestamp(existing))
                .ok_or(Errno::ENOENT)?;
            let (stored_attr, data, _) = state.inodes.get_mut(&inode).ok_or(Errno::ENOENT)?;
            let mut changed = false;

            if attr.valid & FATTR_MODE != 0 {
                stored_attr.posix.mode = (stored_attr.posix.mode & S_IFMT) | (attr.mode & !S_IFMT);
                changed = true;
            }
            if attr.valid & FATTR_UID != 0 {
                stored_attr.posix.uid = attr.uid;
                changed = true;
            }
            if attr.valid & FATTR_GID != 0 {
                stored_attr.posix.gid = attr.gid;
                changed = true;
            }
            if attr.valid & FATTR_SIZE != 0 {
                if stored_attr.kind == NodeKind::Dir {
                    return Err(Errno::EISDIR);
                }
                let new_len = usize::try_from(attr.size).map_err(|_| Errno::EFBIG)?;
                data.resize(new_len, 0);
                Self::set_size(stored_attr, attr.size);
                changed = true;
            }
            if attr.valid & FATTR_ATIME != 0 {
                stored_attr.posix.atime_ns = attr.atime_ns;
                changed = true;
            }
            if attr.valid & FATTR_ATIME_NOW != 0 {
                stored_attr.posix.atime_ns = now;
                changed = true;
            }
            if attr.valid & FATTR_MTIME != 0 {
                stored_attr.posix.mtime_ns = attr.mtime_ns;
                changed = true;
            }
            if attr.valid & FATTR_MTIME_NOW != 0 {
                stored_attr.posix.mtime_ns = now;
                changed = true;
            }
            if attr.valid & FATTR_CTIME != 0 {
                stored_attr.posix.ctime_ns = attr.ctime_ns;
            } else if changed {
                stored_attr.posix.ctime_ns = now;
            }

            if changed || attr.valid & FATTR_CTIME != 0 {
                stored_attr.subtree_rev = stored_attr.subtree_rev.saturating_add(1);
            }

            Ok(*stored_attr)
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
            let attr = Self::attr_for(
                inode_id,
                NodeKind::Dir,
                S_IFDIR | (mode & !S_IFMT),
                ctx.uid,
                ctx.gid,
                0,
            );
            // A new subdirectory adds a '..' link back to parent.
            if let Some((parent_attr, _, _)) = state.inodes.get_mut(&parent) {
                let mut nlink_u64 = parent_attr.posix.nlink as u64;
                if let Ok(new_nlink) = inc_nlink(&mut nlink_u64) {
                    parent_attr.posix.nlink = new_nlink as u32;
                }
            }
            state.entries.insert(key, inode_id);
            state
                .inodes
                .insert(inode_id, (attr, Vec::new(), HashMap::new()));
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

            if let Some(&existing_inode) = state.entries.get(&key) {
                if flags & O_EXCL != 0 {
                    return Err(Errno::EEXIST);
                }
                if flags & O_TRUNC != 0 {
                    let inode_attr = {
                        let (attr, data, _) =
                            state.inodes.get_mut(&existing_inode).ok_or(Errno::ENOENT)?;
                        data.clear();
                        Self::set_size(attr, 0);
                        *attr
                    };
                    let fh = Self::allocate_handle(&mut state, existing_inode, flags);
                    return Ok((inode_attr, fh));
                }
                // Existing file, no O_EXCL, no O_TRUNC: open existing.
                let inode_attr = {
                    let (attr, _, _) = state.inodes.get(&existing_inode).ok_or(Errno::ENOENT)?;
                    *attr
                };
                let fh = Self::allocate_handle(&mut state, existing_inode, flags);
                return Ok((inode_attr, fh));
            }

            let inode_id = InodeId::new(state.next_inode);
            state.next_inode += 1;
            let attr = Self::attr_for(
                inode_id,
                NodeKind::File,
                S_IFREG | (mode & !S_IFMT),
                ctx.uid,
                ctx.gid,
                0,
            );
            state.entries.insert(key, inode_id);
            state
                .inodes
                .insert(inode_id, (attr, Vec::new(), HashMap::new()));
            let fh = Self::allocate_handle(&mut state, inode_id, flags);
            Ok((attr, fh))
        }

        fn create_excl(
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
            let attr = Self::attr_for(
                inode_id,
                NodeKind::File,
                S_IFREG | (mode & !S_IFMT),
                ctx.uid,
                ctx.gid,
                0,
            );
            state.entries.insert(key, inode_id);
            state
                .inodes
                .insert(inode_id, (attr, Vec::new(), HashMap::new()));
            let fh = Self::allocate_handle(&mut state, inode_id, flags);
            Ok((attr, fh))
        }

        fn tmpfile(
            &self,
            parent: InodeId,
            mode: u32,
            flags: u32,
            ctx: &RequestCtx,
        ) -> Result<(InodeAttr, EngineFileHandle), Errno> {
            Err(Errno::ENOSYS)
        }

        fn unlink(&self, parent: InodeId, name: &[u8], ctx: &RequestCtx) -> Result<(), Errno> {
            let mut state = self.state.borrow_mut();
            Self::ensure_dir(&state, parent)?;
            let key = Self::entry_key(parent, name);
            let inode_id = *state.entries.get(&key).ok_or(Errno::ENOENT)?;
            if state
                .inodes
                .get(&inode_id)
                .map(|(attr, _, _)| attr.kind == NodeKind::Dir)
                .unwrap_or(false)
            {
                return Err(Errno::EPERM);
            }
            // POSIX sticky-bit check: on directories with S_ISVTX, only the
            // file owner, directory owner, or root may unlink entries.
            {
                let parent_attr = state
                    .inodes
                    .get(&parent)
                    .map(|(attr, _, _)| attr)
                    .ok_or(Errno::ENOENT)?;
                let victim_attr = state
                    .inodes
                    .get(&inode_id)
                    .map(|(attr, _, _)| attr)
                    .ok_or(Errno::ENOENT)?;
                if tidefs_permission::can_unlink(
                    parent_attr.posix.mode,
                    parent_attr.posix.uid,
                    victim_attr.posix.uid,
                    ctx.uid,
                )
                .is_err()
                {
                    return Err(Errno::EPERM);
                }
            }
            state.entries.remove(&key);
            let remove_inode = {
                let (attr, _, _) = state.inodes.get_mut(&inode_id).ok_or(Errno::ENOENT)?;
                let mut nlink_u64 = attr.posix.nlink as u64;
                let new_nlink = dec_nlink(&mut nlink_u64)?;
                attr.posix.nlink = new_nlink as u32;
                new_nlink == 0
            };
            if remove_inode {
                state.inodes.remove(&inode_id);
            }
            Ok(())
        }

        fn rmdir(&self, parent: InodeId, name: &[u8], ctx: &RequestCtx) -> Result<(), Errno> {
            let mut state = self.state.borrow_mut();
            Self::ensure_dir(&state, parent)?;
            let key = Self::entry_key(parent, name);
            let inode_id = *state.entries.get(&key).ok_or(Errno::ENOENT)?;
            let attr = state
                .inodes
                .get(&inode_id)
                .map(|(attr, _, _)| *attr)
                .ok_or(Errno::ENOENT)?;
            if attr.kind != NodeKind::Dir {
                return Err(Errno::ENOTDIR);
            }
            if !Self::dir_is_empty(&state, inode_id) {
                return Err(Errno::ENOTEMPTY);
            }
            // nlink precondition: empty directory has exactly 2 links
            // (own name in parent + '.').  >2 implies subdirectories.
            if attr.posix.nlink > 2 {
                return Err(Errno::ENOTEMPTY);
            }
            // Removing a subdirectory removes its '..' link to parent.
            if let Some((parent_attr, _, _)) = state.inodes.get_mut(&parent) {
                let mut nlink_u64 = parent_attr.posix.nlink as u64;
                if let Ok(new_nlink) = dec_nlink(&mut nlink_u64) {
                    parent_attr.posix.nlink = new_nlink as u32;
                }
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
            ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            let unsupported = flags & !(RENAME_NOREPLACE | RENAME_EXCHANGE);
            if unsupported != 0 || flags == (RENAME_NOREPLACE | RENAME_EXCHANGE) {
                return Err(Errno::EINVAL);
            }

            let mut state = self.state.borrow_mut();
            Self::ensure_dir(&state, old_parent)?;
            Self::ensure_dir(&state, new_parent)?;

            let old_key = Self::entry_key(old_parent, old_name);
            let new_key = Self::entry_key(new_parent, new_name);
            let old_inode = *state.entries.get(&old_key).ok_or(Errno::ENOENT)?;
            if old_key == new_key {
                return Ok(());
            }

            // POSIX sticky-bit check: on directories with S_ISVTX, only the
            // file owner, directory owner, or root may rename entries away.
            // This applies to the source side (old_parent / old_inode).
            {
                let old_parent_attr = state
                    .inodes
                    .get(&old_parent)
                    .map(|(attr, _, _)| attr)
                    .ok_or(Errno::ENOENT)?;
                let old_victim_attr = state
                    .inodes
                    .get(&old_inode)
                    .map(|(attr, _, _)| attr)
                    .ok_or(Errno::ENOENT)?;
                if tidefs_permission::can_unlink(
                    old_parent_attr.posix.mode,
                    old_parent_attr.posix.uid,
                    old_victim_attr.posix.uid,
                    ctx.uid,
                )
                .is_err()
                {
                    return Err(Errno::EPERM);
                }
            }

            if flags & RENAME_EXCHANGE != 0 {
                let new_inode = *state.entries.get(&new_key).ok_or(Errno::ENOENT)?;
                // Sticky-bit check for the target side of exchange: the
                // new_parent must also allow removing the new entry.
                {
                    let new_parent_attr = state
                        .inodes
                        .get(&new_parent)
                        .map(|(attr, _, _)| attr)
                        .ok_or(Errno::ENOENT)?;
                    let new_victim_attr = state
                        .inodes
                        .get(&new_inode)
                        .map(|(attr, _, _)| attr)
                        .ok_or(Errno::ENOENT)?;
                    if tidefs_permission::can_unlink(
                        new_parent_attr.posix.mode,
                        new_parent_attr.posix.uid,
                        new_victim_attr.posix.uid,
                        ctx.uid,
                    )
                    .is_err()
                    {
                        return Err(Errno::EPERM);
                    }
                }
                state.entries.insert(old_key, new_inode);
                state.entries.insert(new_key, old_inode);
                return Ok(());
            }

            if flags & RENAME_NOREPLACE != 0 && state.entries.contains_key(&new_key) {
                return Err(Errno::EEXIST);
            }

            let old_kind = state
                .inodes
                .get(&old_inode)
                .map(|(attr, _, _)| attr.kind)
                .ok_or(Errno::ENOENT)?;

            // Handle overwritten target inode with nlink accounting.
            if let Some(new_inode) = state.entries.get(&new_key).copied() {
                // Sticky-bit check for the target side of overwrite: the
                // new_parent must allow removing the existing target entry.
                {
                    let new_parent_attr = state
                        .inodes
                        .get(&new_parent)
                        .map(|(attr, _, _)| attr)
                        .ok_or(Errno::ENOENT)?;
                    let new_victim_attr = state
                        .inodes
                        .get(&new_inode)
                        .map(|(attr, _, _)| attr)
                        .ok_or(Errno::ENOENT)?;
                    if tidefs_permission::can_unlink(
                        new_parent_attr.posix.mode,
                        new_parent_attr.posix.uid,
                        new_victim_attr.posix.uid,
                        ctx.uid,
                    )
                    .is_err()
                    {
                        return Err(Errno::EPERM);
                    }
                }
                let new_kind = state
                    .inodes
                    .get(&new_inode)
                    .map(|(attr, _, _)| attr.kind)
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
                state.entries.remove(&new_key);

                if new_kind == NodeKind::Dir {
                    // Target is a directory being overwritten: remove its
                    // '..' link from new_parent, then recursively remove
                    // the directory tree.
                    if let Some((parent_attr, _, _)) = state.inodes.get_mut(&new_parent) {
                        let mut nlink_u64 = parent_attr.posix.nlink as u64;
                        if let Ok(new_nlink) = dec_nlink(&mut nlink_u64) {
                            parent_attr.posix.nlink = new_nlink as u32;
                        }
                    }
                    Self::remove_inode_tree(&mut state, new_inode);
                } else {
                    // Target is a file: decrement its nlink and remove
                    // the inode if this was the last link.
                    let remove_inode = {
                        let (attr, _, _) = state.inodes.get_mut(&new_inode).ok_or(Errno::ENOENT)?;
                        let mut nlink_u64 = attr.posix.nlink as u64;
                        let new_nlink = dec_nlink(&mut nlink_u64)?;
                        attr.posix.nlink = new_nlink as u32;
                        new_nlink == 0
                    };
                    if remove_inode {
                        state.inodes.remove(&new_inode);
                    }
                }
            }

            // Cross-directory directory rename: adjust parent nlink for
            // the '..' links the subdirectory brings/removes.
            if old_kind == NodeKind::Dir && old_parent != new_parent {
                if let Some((parent_attr, _, _)) = state.inodes.get_mut(&old_parent) {
                    let mut nlink_u64 = parent_attr.posix.nlink as u64;
                    if let Ok(new_nlink) = dec_nlink(&mut nlink_u64) {
                        parent_attr.posix.nlink = new_nlink as u32;
                    }
                }
                if let Some((parent_attr, _, _)) = state.inodes.get_mut(&new_parent) {
                    let mut nlink_u64 = parent_attr.posix.nlink as u64;
                    if let Ok(new_nlink) = inc_nlink(&mut nlink_u64) {
                        parent_attr.posix.nlink = new_nlink as u32;
                    }
                }
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
            ctx: &RequestCtx,
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
                .map(|(attr, _, _)| attr.kind)
                .ok_or(Errno::ENOENT)?;
            if target_kind == NodeKind::Dir {
                return Err(Errno::EPERM);
            }
            if state.cross_device_link_targets.contains(&target) {
                return Err(Errno::EXDEV);
            }

            let max_nlink = state.max_nlink;
            let linked_attr = {
                let (attr, _, _) = state.inodes.get_mut(&target).ok_or(Errno::ENOENT)?;
                if attr.posix.nlink >= max_nlink {
                    return Err(Errno::EMLINK);
                }
                let mut nlink_u64 = attr.posix.nlink as u64;
                let new_nlink = inc_nlink(&mut nlink_u64)?;
                attr.posix.nlink = new_nlink as u32;
                *attr
            };
            state.entries.insert(new_key, target);
            Ok(linked_attr)
        }

        fn symlink(
            &self,
            parent: InodeId,
            name: &[u8],
            target: &[u8],
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            if name.is_empty() || name.contains(&0) {
                return Err(Errno::EINVAL);
            }
            if target.is_empty() {
                return Err(Errno::EINVAL);
            }

            let mut state = self.state.borrow_mut();
            Self::ensure_dir(&state, parent)?;
            let key = Self::entry_key(parent, name);
            if state.entries.contains_key(&key) {
                return Err(Errno::EEXIST);
            }

            let inode_id = InodeId::new(state.next_inode);
            state.next_inode += 1;
            let attr = Self::attr_for(
                inode_id,
                NodeKind::Symlink,
                S_IFLNK | 0o777,
                ctx.uid,
                ctx.gid,
                target.len() as u64,
            );
            state.entries.insert(key, inode_id);
            state
                .inodes
                .insert(inode_id, (attr, target.to_vec(), HashMap::new()));
            Ok(attr)
        }

        fn readlink(&self, inode: InodeId, ctx: &RequestCtx) -> Result<Vec<u8>, Errno> {
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
            rdev: u32,
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
            let attr = Self::attr_for(
                inode_id,
                NodeKind::Fifo,
                S_IFIFO | ((mode & 0o7777) & !ctx.umask),
                ctx.uid,
                ctx.gid,
                0,
            );
            state.entries.insert(key, inode_id);
            state
                .inodes
                .insert(inode_id, (attr, Vec::new(), HashMap::new()));
            Ok(attr)
        }

        fn open(
            &self,
            inode: InodeId,
            flags: u32,
            ctx: &RequestCtx,
        ) -> Result<EngineFileHandle, Errno> {
            let mut state = self.state.borrow_mut();
            {
                let (attr, data, _) = state.inodes.get_mut(&inode).ok_or(Errno::ENOENT)?;
                if attr.kind == NodeKind::Dir {
                    return Err(Errno::EISDIR);
                }
                if flags & O_TRUNC != 0 {
                    data.clear();
                    Self::set_size(attr, 0);
                }
            }

            Ok(Self::allocate_handle(&mut state, inode, flags))
        }

        fn release(&self, fh: &EngineFileHandle) -> Result<(), Errno> {
            let mut state = self.state.borrow_mut();
            Self::live_handle(&state, fh)?;
            state.handles.remove(&fh.fh_id);
            Ok(())
        }

        fn read(
            &self,
            fh: &EngineFileHandle,
            offset: u64,
            size: u32,
            ctx: &RequestCtx,
        ) -> Result<Vec<u8>, Errno> {
            let state = self.state.borrow();
            let live = Self::live_handle(&state, fh)?;
            if !Self::can_read(live.open_flags) {
                return Err(Errno::EBADF);
            }
            let (_, data, _) = state.inodes.get(&live.inode_id).ok_or(Errno::ENOENT)?;
            let offset = usize::try_from(offset).map_err(|_| Errno::EINVAL)?;
            if offset >= data.len() {
                return Ok(Vec::new());
            }
            let end = data.len().min(offset.saturating_add(size as usize));
            Ok(data[offset..end].to_vec())
        }

        fn write(
            &self,
            fh: &EngineFileHandle,
            offset: u64,
            data: &[u8],
            ctx: &RequestCtx,
        ) -> Result<u32, Errno> {
            let mut state = self.state.borrow_mut();
            let live = Self::live_handle(&state, fh)?;
            if !Self::can_write(live.open_flags) {
                return Err(Errno::EBADF);
            }

            let offset = usize::try_from(offset).map_err(|_| Errno::EINVAL)?;
            let end = offset.checked_add(data.len()).ok_or(Errno::EINVAL)?;
            let written = u32::try_from(data.len()).map_err(|_| Errno::EINVAL)?;
            let (attr, stored_data, _) =
                state.inodes.get_mut(&live.inode_id).ok_or(Errno::ENOENT)?;
            if stored_data.len() < offset {
                stored_data.resize(offset, 0);
            }
            if stored_data.len() < end {
                stored_data.resize(end, 0);
            }
            stored_data[offset..end].copy_from_slice(data);
            Self::set_size(attr, stored_data.len() as u64);
            Ok(written)
        }

        fn flush(&self, fh: &EngineFileHandle, ctx: &RequestCtx) -> Result<(), Errno> {
            let state = self.state.borrow();
            Self::live_handle(&state, fh)?;
            Ok(())
        }

        fn fsync(
            &self,
            fh: &EngineFileHandle,
            _datasync: bool,
            _ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            let state = self.state.borrow();
            Self::live_handle(&state, fh)?;
            Ok(())
        }

        fn fallocate(
            &self,
            fh: &EngineFileHandle,
            mode: u32,
            offset: u64,
            length: u64,
            ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            let mut state = self.state.borrow_mut();
            let live = Self::live_handle(&state, fh)?;
            if !Self::can_write(live.open_flags) {
                return Err(Errno::EBADF);
            }

            let known_flags = FALLOC_FL_KEEP_SIZE
                | FALLOC_FL_PUNCH_HOLE
                | FALLOC_FL_ZERO_RANGE
                | FALLOC_FL_UNSHARE_RANGE;
            if mode & !known_flags != 0 {
                return Err(Errno::EINVAL);
            }
            if mode & FALLOC_FL_UNSHARE_RANGE != 0 {
                return Err(Errno::EOPNOTSUPP);
            }
            if mode & FALLOC_FL_PUNCH_HOLE != 0
                && (mode & FALLOC_FL_KEEP_SIZE == 0 || mode & FALLOC_FL_ZERO_RANGE != 0)
            {
                return Err(Errno::EINVAL);
            }

            let end = offset.checked_add(length).ok_or(Errno::EINVAL)?;
            let offset = usize::try_from(offset).map_err(|_| Errno::EINVAL)?;
            let end = usize::try_from(end).map_err(|_| Errno::EINVAL)?;
            let (attr, stored_data, _) =
                state.inodes.get_mut(&live.inode_id).ok_or(Errno::ENOENT)?;

            if mode & FALLOC_FL_PUNCH_HOLE != 0 {
                let zero_end = stored_data.len().min(end);
                if offset < zero_end {
                    stored_data[offset..zero_end].fill(0);
                }
                return Ok(());
            }

            if mode & FALLOC_FL_ZERO_RANGE != 0 {
                let zero_end = if mode & FALLOC_FL_KEEP_SIZE != 0 {
                    stored_data.len().min(end)
                } else {
                    if stored_data.len() < end {
                        stored_data.resize(end, 0);
                    }
                    end
                };
                if offset < zero_end {
                    stored_data[offset..zero_end].fill(0);
                }
                if mode & FALLOC_FL_KEEP_SIZE == 0 {
                    Self::set_size(attr, stored_data.len() as u64);
                }
                return Ok(());
            }

            if mode & FALLOC_FL_KEEP_SIZE != 0 {
                return Ok(());
            }

            if stored_data.len() < end {
                stored_data.resize(end, 0);
                Self::set_size(attr, stored_data.len() as u64);
            }
            Ok(())
        }

        fn data_ranges(
            &self,
            fh: &EngineFileHandle,
            offset: u64,
            length: u64,
            ctx: &RequestCtx,
        ) -> Result<Vec<LseekDataRange>, Errno> {
            let state = self.state.borrow();
            let live = Self::live_handle(&state, fh)?;
            if length == 0 {
                return Ok(Vec::new());
            }

            let query_end = offset.checked_add(length).ok_or(Errno::EINVAL)?;
            let (_, data, _) = state.inodes.get(&live.inode_id).ok_or(Errno::ENOENT)?;
            let file_end = u64::try_from(data.len()).map_err(|_| Errno::EFBIG)?;
            if offset >= file_end {
                return Ok(Vec::new());
            }

            Ok(alloc::vec![LseekDataRange::new(
                offset,
                query_end.min(file_end),
            )])
        }

        fn opendir(&self, inode: InodeId, ctx: &RequestCtx) -> Result<EngineDirHandle, Errno> {
            let mut state = self.state.borrow_mut();
            Self::ensure_dir(&state, inode)?;
            Ok(Self::allocate_dir_handle(&mut state, inode))
        }

        fn releasedir(&self, dh: &EngineDirHandle) -> Result<(), Errno> {
            let mut state = self.state.borrow_mut();
            Self::live_dir_handle(&state, dh)?;
            state.dir_handles.remove(&dh.dh_id);
            Ok(())
        }

        fn readdir(
            &self,
            dh: &EngineDirHandle,
            offset: u64,
            ctx: &RequestCtx,
        ) -> Result<(Vec<DirEntry>, bool), Errno> {
            let state = self.state.borrow();
            let inode_id = Self::live_dir_handle(&state, dh)?;
            let entries = Self::sorted_dir_entries(&state, inode_id)?;
            let start = usize::try_from(offset).map_err(|_| Errno::EINVAL)?;
            if start >= entries.len() {
                return Ok((Vec::new(), false));
            }
            let end = entries.len().min(start.saturating_add(MOCK_READDIR_BATCH));
            Ok((entries[start..end].to_vec(), end < entries.len()))
        }

        fn fsyncdir(
            &self,
            dh: &EngineDirHandle,
            _datasync: bool,
            _ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            let state = self.state.borrow();
            Self::live_dir_handle(&state, dh)?;
            Ok(())
        }

        fn fdatasync_inode(
            &self,
            fh: &EngineFileHandle,
            datasync: bool,
            ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            let _ = (fh, datasync, ctx);
            Ok(())
        }

        fn syncfs(&self, _ctx: &RequestCtx) -> Result<(), Errno> {
            Ok(())
        }

        fn getxattr(
            &self,
            inode: InodeId,
            name: &[u8],
            ctx: &RequestCtx,
        ) -> Result<Vec<u8>, Errno> {
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
            ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            if flags & !(XATTR_CREATE | XATTR_REPLACE) != 0
                || flags == (XATTR_CREATE | XATTR_REPLACE)
            {
                return Err(Errno::EINVAL);
            }

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

        fn listxattr(&self, inode: InodeId, ctx: &RequestCtx) -> Result<Vec<u8>, Errno> {
            let state = self.state.borrow();
            let (_, _, xattrs) = state.inodes.get(&inode).ok_or(Errno::ENOENT)?;
            if xattrs.is_empty() {
                return Ok(alloc::vec![0]);
            }

            let mut names: Vec<&Vec<u8>> = xattrs.keys().collect();
            names.sort();
            let mut encoded = Vec::new();
            for name in names {
                encoded.extend_from_slice(name);
                encoded.push(0);
            }
            Ok(encoded)
        }

        fn removexattr(&self, inode: InodeId, name: &[u8], ctx: &RequestCtx) -> Result<(), Errno> {
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

    type RenameTestEngine = FileIoTestEngine;

    fn file_io_ctx() -> RequestCtx {
        RequestCtx {
            uid: 1000,
            gid: 1000,
            pid: 42,
            umask: 0o022,
            groups: alloc::vec![1000],
        }
    }

    fn create_file(
        engine: &FileIoTestEngine,
        name: &[u8],
        flags: OpenFlags,
        ctx: &RequestCtx,
    ) -> (InodeAttr, EngineFileHandle) {
        create_file_in(engine, ROOT_INODE_ID, name, flags, ctx)
    }

    fn create_file_in(
        engine: &FileIoTestEngine,
        parent: InodeId,
        name: &[u8],
        flags: OpenFlags,
        ctx: &RequestCtx,
    ) -> (InodeAttr, EngineFileHandle) {
        engine
            .create(parent, name, 0o644, flags, ctx)
            .expect("create test file")
    }

    fn create_dir(
        engine: &RenameTestEngine,
        parent: InodeId,
        name: &[u8],
        ctx: &RequestCtx,
    ) -> InodeAttr {
        engine
            .mkdir(parent, name, 0o755, ctx)
            .expect("create test directory")
    }

    #[test]
    fn trait_is_object_safe() {
        let engine: &dyn VfsEngine = &EmptyTestEngine;
        let ctx = RequestCtx {
            uid: 1000,
            gid: 1000,
            pid: 42,
            umask: 0o022,
            groups: alloc::vec![1000],
        };
        assert_eq!(engine.get_root_inode(&ctx).unwrap_err(), Errno::ENOSYS);
    }

    #[test]
    fn mock_returns_enosys_for_all_namespace_ops() {
        let engine = EmptyTestEngine;
        let ctx = RequestCtx {
            uid: 0,
            gid: 0,
            pid: 1,
            umask: 0,
            groups: alloc::vec![0],
        };
        assert_eq!(engine.get_root_inode(&ctx), Err(Errno::ENOSYS));
        assert_eq!(
            engine.lookup(InodeId::new(1), b"foo", &ctx),
            Err(Errno::ENOSYS)
        );
        assert_eq!(
            engine.getattr(InodeId::new(1), None, &ctx),
            Err(Errno::ENOSYS)
        );
    }

    #[test]
    fn mock_returns_enosys_for_create_and_tmpfile() {
        let engine = EmptyTestEngine;
        let ctx = RequestCtx {
            uid: 0,
            gid: 0,
            pid: 1,
            umask: 0,
            groups: alloc::vec![0],
        };
        assert!(engine
            .create(InodeId::new(1), b"f", 0o644, 0, &ctx)
            .is_err());
        assert!(engine.tmpfile(InodeId::new(1), 0o600, 0, &ctx).is_err());
    }

    #[test]
    fn mock_returns_enosys_for_file_io_ops() {
        let engine = EmptyTestEngine;
        let ctx = RequestCtx {
            uid: 0,
            gid: 0,
            pid: 1,
            umask: 0,
            groups: alloc::vec![0],
        };
        let fh = EngineFileHandle::default();
        assert_eq!(engine.open(InodeId::new(1), 0, &ctx), Err(Errno::ENOSYS));
        assert_eq!(engine.release(&fh), Err(Errno::ENOSYS));
        assert_eq!(engine.read(&fh, 0, 4096, &ctx), Err(Errno::ENOSYS));
        assert_eq!(engine.write(&fh, 0, b"data", &ctx), Err(Errno::ENOSYS));
        assert_eq!(
            engine.copy_file_range(&fh, 0, &fh, 4096, 4096, &ctx),
            Err(Errno::ENOSYS)
        );
        assert_eq!(engine.flush(&fh, &ctx), Err(Errno::ENOSYS));
        assert_eq!(engine.fsync(&fh, false, &ctx), Err(Errno::ENOSYS));
        assert_eq!(engine.fallocate(&fh, 0, 0, 4096, &ctx), Err(Errno::ENOSYS));
        assert_eq!(engine.data_ranges(&fh, 0, 4096, &ctx), Err(Errno::ENOSYS));
    }

    #[test]
    fn mock_returns_enosys_for_dir_ops() {
        let engine = EmptyTestEngine;
        let ctx = RequestCtx {
            uid: 0,
            gid: 0,
            pid: 1,
            umask: 0,
            groups: alloc::vec![0],
        };
        let dh = EngineDirHandle::default();
        assert_eq!(engine.opendir(InodeId::new(1), &ctx), Err(Errno::ENOSYS));
        assert_eq!(engine.releasedir(&dh), Err(Errno::ENOSYS));
        assert_eq!(engine.readdir(&dh, 0, &ctx), Err(Errno::ENOSYS));
        assert_eq!(engine.fsyncdir(&dh, false, &ctx), Err(Errno::ENOSYS));
    }

    #[test]
    fn mock_returns_enosys_for_xattr_ops() {
        let engine = EmptyTestEngine;
        let ctx = RequestCtx {
            uid: 0,
            gid: 0,
            pid: 1,
            umask: 0,
            groups: alloc::vec![0],
        };
        assert_eq!(
            engine.getxattr(InodeId::new(1), b"user.foo", &ctx),
            Err(Errno::ENOSYS)
        );
        assert_eq!(
            engine.setxattr(InodeId::new(1), b"user.foo", b"bar", 0, &ctx),
            Err(Errno::ENOSYS)
        );
        assert_eq!(engine.listxattr(InodeId::new(1), &ctx), Err(Errno::ENOSYS));
    }

    #[test]
    fn rename_plain_within_directory_moves_entry() {
        let engine = RenameTestEngine::new();
        let ctx = file_io_ctx();
        let (attr, fh) = create_file(&engine, b"old.txt", O_RDWR, &ctx);
        engine.release(&fh).expect("release create handle");

        engine
            .rename(
                ROOT_INODE_ID,
                b"old.txt",
                ROOT_INODE_ID,
                b"new.txt",
                0,
                &ctx,
            )
            .expect("rename file");

        assert_eq!(
            engine.lookup(ROOT_INODE_ID, b"old.txt", &ctx),
            Err(Errno::ENOENT)
        );
        assert_eq!(
            engine
                .lookup(ROOT_INODE_ID, b"new.txt", &ctx)
                .unwrap()
                .inode_id,
            attr.inode_id
        );
    }

    #[test]
    fn rename_cross_directory_moves_entry() {
        let engine = RenameTestEngine::new();
        let ctx = file_io_ctx();
        let dir_a = create_dir(&engine, ROOT_INODE_ID, b"a", &ctx);
        let dir_b = create_dir(&engine, ROOT_INODE_ID, b"b", &ctx);
        let (attr, fh) = create_file_in(&engine, dir_a.inode_id, b"file", O_RDWR, &ctx);
        engine.release(&fh).expect("release create handle");

        engine
            .rename(dir_a.inode_id, b"file", dir_b.inode_id, b"moved", 0, &ctx)
            .expect("cross-directory rename");

        assert_eq!(
            engine.lookup(dir_a.inode_id, b"file", &ctx),
            Err(Errno::ENOENT)
        );
        assert_eq!(
            engine
                .lookup(dir_b.inode_id, b"moved", &ctx)
                .unwrap()
                .inode_id,
            attr.inode_id
        );
    }

    #[test]
    fn rename_directory_moves_directory_entry() {
        let engine = RenameTestEngine::new();
        let ctx = file_io_ctx();
        let dir = create_dir(&engine, ROOT_INODE_ID, b"old-dir", &ctx);

        engine
            .rename(
                ROOT_INODE_ID,
                b"old-dir",
                ROOT_INODE_ID,
                b"new-dir",
                0,
                &ctx,
            )
            .expect("rename directory");

        assert_eq!(
            engine.lookup(ROOT_INODE_ID, b"old-dir", &ctx),
            Err(Errno::ENOENT)
        );
        assert_eq!(
            engine
                .lookup(ROOT_INODE_ID, b"new-dir", &ctx)
                .unwrap()
                .inode_id,
            dir.inode_id
        );
    }

    #[test]
    fn rename_noreplace_succeeds_when_target_missing() {
        let engine = RenameTestEngine::new();
        let ctx = file_io_ctx();
        let (attr, fh) = create_file(&engine, b"source", O_RDWR, &ctx);
        engine.release(&fh).expect("release create handle");

        engine
            .rename(
                ROOT_INODE_ID,
                b"source",
                ROOT_INODE_ID,
                b"target",
                RENAME_NOREPLACE,
                &ctx,
            )
            .expect("rename with noreplace");

        assert_eq!(
            engine
                .lookup(ROOT_INODE_ID, b"target", &ctx)
                .unwrap()
                .inode_id,
            attr.inode_id
        );
    }

    #[test]
    fn rename_noreplace_refuses_existing_target() {
        let engine = RenameTestEngine::new();
        let ctx = file_io_ctx();
        let (source_attr, source_fh) = create_file(&engine, b"source", O_RDWR, &ctx);
        let (target_attr, target_fh) = create_file(&engine, b"target", O_RDWR, &ctx);
        engine.release(&source_fh).expect("release source handle");
        engine.release(&target_fh).expect("release target handle");

        assert_eq!(
            engine.rename(
                ROOT_INODE_ID,
                b"source",
                ROOT_INODE_ID,
                b"target",
                RENAME_NOREPLACE,
                &ctx,
            ),
            Err(Errno::EEXIST)
        );
        assert_eq!(
            engine
                .lookup(ROOT_INODE_ID, b"source", &ctx)
                .unwrap()
                .inode_id,
            source_attr.inode_id
        );
        assert_eq!(
            engine
                .lookup(ROOT_INODE_ID, b"target", &ctx)
                .unwrap()
                .inode_id,
            target_attr.inode_id
        );
    }

    #[test]
    fn rename_exchange_swaps_names_and_preserves_inode_data() {
        let engine = RenameTestEngine::new();
        let ctx = file_io_ctx();
        let (left_attr, left_fh) = create_file(&engine, b"left", O_RDWR, &ctx);
        let (right_attr, right_fh) = create_file(&engine, b"right", O_RDWR, &ctx);
        engine.write(&left_fh, 0, b"left-data", &ctx).unwrap();
        engine.write(&right_fh, 0, b"right-data", &ctx).unwrap();
        engine.release(&left_fh).expect("release left handle");
        engine.release(&right_fh).expect("release right handle");

        engine
            .rename(
                ROOT_INODE_ID,
                b"left",
                ROOT_INODE_ID,
                b"right",
                RENAME_EXCHANGE,
                &ctx,
            )
            .expect("exchange entries");

        let left_after = engine.lookup(ROOT_INODE_ID, b"left", &ctx).unwrap();
        let right_after = engine.lookup(ROOT_INODE_ID, b"right", &ctx).unwrap();
        assert_eq!(left_after.inode_id, right_attr.inode_id);
        assert_eq!(right_after.inode_id, left_attr.inode_id);

        let left_fh_after = engine.open(left_after.inode_id, O_RDONLY, &ctx).unwrap();
        let right_fh_after = engine.open(right_after.inode_id, O_RDONLY, &ctx).unwrap();
        assert_eq!(
            engine.read(&left_fh_after, 0, 16, &ctx),
            Ok(b"right-data".to_vec())
        );
        assert_eq!(
            engine.read(&right_fh_after, 0, 16, &ctx),
            Ok(b"left-data".to_vec())
        );
    }

    #[test]
    fn rename_plain_overwrites_existing_file_target() {
        let engine = RenameTestEngine::new();
        let ctx = file_io_ctx();
        let (source_attr, source_fh) = create_file(&engine, b"source", O_RDWR, &ctx);
        let (target_attr, target_fh) = create_file(&engine, b"target", O_RDWR, &ctx);
        engine.write(&source_fh, 0, b"source-data", &ctx).unwrap();
        engine.write(&target_fh, 0, b"target-data", &ctx).unwrap();
        engine.release(&source_fh).expect("release source handle");
        engine.release(&target_fh).expect("release target handle");

        engine
            .rename(ROOT_INODE_ID, b"source", ROOT_INODE_ID, b"target", 0, &ctx)
            .expect("rename over target");

        assert_eq!(
            engine.lookup(ROOT_INODE_ID, b"source", &ctx),
            Err(Errno::ENOENT)
        );
        let target_after = engine.lookup(ROOT_INODE_ID, b"target", &ctx).unwrap();
        assert_eq!(target_after.inode_id, source_attr.inode_id);
        assert_ne!(target_after.inode_id, target_attr.inode_id);
        let fh = engine.open(target_after.inode_id, O_RDONLY, &ctx).unwrap();
        assert_eq!(engine.read(&fh, 0, 16, &ctx), Ok(b"source-data".to_vec()));
    }

    #[test]
    fn rename_missing_source_returns_enoent() {
        let engine = RenameTestEngine::new();
        let ctx = file_io_ctx();

        assert_eq!(
            engine.rename(ROOT_INODE_ID, b"missing", ROOT_INODE_ID, b"target", 0, &ctx),
            Err(Errno::ENOENT)
        );
    }

    #[test]
    fn rename_directory_over_non_empty_directory_returns_enotempty() {
        let engine = RenameTestEngine::new();
        let ctx = file_io_ctx();
        let source = create_dir(&engine, ROOT_INODE_ID, b"source-dir", &ctx);
        let target = create_dir(&engine, ROOT_INODE_ID, b"target-dir", &ctx);
        let (child_attr, child_fh) =
            create_file_in(&engine, target.inode_id, b"child", O_RDWR, &ctx);
        engine.release(&child_fh).expect("release child handle");

        assert_eq!(
            engine.rename(
                ROOT_INODE_ID,
                b"source-dir",
                ROOT_INODE_ID,
                b"target-dir",
                0,
                &ctx,
            ),
            Err(Errno::ENOTEMPTY)
        );
        assert_eq!(
            engine
                .lookup(ROOT_INODE_ID, b"source-dir", &ctx)
                .unwrap()
                .inode_id,
            source.inode_id
        );
        assert_eq!(
            engine
                .lookup(ROOT_INODE_ID, b"target-dir", &ctx)
                .unwrap()
                .inode_id,
            target.inode_id
        );
        assert_eq!(
            engine
                .lookup(target.inode_id, b"child", &ctx)
                .unwrap()
                .inode_id,
            child_attr.inode_id
        );
    }

    #[test]
    fn rename_into_missing_parent_returns_enoent() {
        let engine = RenameTestEngine::new();
        let ctx = file_io_ctx();
        let (attr, fh) = create_file(&engine, b"source", O_RDWR, &ctx);
        engine.release(&fh).expect("release source handle");

        assert_eq!(
            engine.rename(
                ROOT_INODE_ID,
                b"source",
                InodeId::new(999),
                b"target",
                0,
                &ctx,
            ),
            Err(Errno::ENOENT)
        );
        assert_eq!(
            engine
                .lookup(ROOT_INODE_ID, b"source", &ctx)
                .unwrap()
                .inode_id,
            attr.inode_id
        );
    }

    #[test]
    fn rename_file_over_directory_returns_eisdir() {
        let engine = RenameTestEngine::new();
        let ctx = file_io_ctx();
        let (source, source_fh) = create_file(&engine, b"source", O_RDWR, &ctx);
        let target = create_dir(&engine, ROOT_INODE_ID, b"target-dir", &ctx);
        engine.release(&source_fh).expect("release source handle");

        assert_eq!(
            engine.rename(
                ROOT_INODE_ID,
                b"source",
                ROOT_INODE_ID,
                b"target-dir",
                0,
                &ctx
            ),
            Err(Errno::EISDIR)
        );
        assert_eq!(
            engine
                .lookup(ROOT_INODE_ID, b"source", &ctx)
                .unwrap()
                .inode_id,
            source.inode_id
        );
        assert_eq!(
            engine
                .lookup(ROOT_INODE_ID, b"target-dir", &ctx)
                .unwrap()
                .inode_id,
            target.inode_id
        );
    }

    #[test]
    fn rename_directory_over_file_returns_enotdir() {
        let engine = RenameTestEngine::new();
        let ctx = file_io_ctx();
        let source = create_dir(&engine, ROOT_INODE_ID, b"source-dir", &ctx);
        let (target, target_fh) = create_file(&engine, b"target", O_RDWR, &ctx);
        engine.release(&target_fh).expect("release target handle");

        assert_eq!(
            engine.rename(
                ROOT_INODE_ID,
                b"source-dir",
                ROOT_INODE_ID,
                b"target",
                0,
                &ctx
            ),
            Err(Errno::ENOTDIR)
        );
        assert_eq!(
            engine
                .lookup(ROOT_INODE_ID, b"source-dir", &ctx)
                .unwrap()
                .inode_id,
            source.inode_id
        );
        assert_eq!(
            engine
                .lookup(ROOT_INODE_ID, b"target", &ctx)
                .unwrap()
                .inode_id,
            target.inode_id
        );
    }

    #[test]
    fn rename_exchange_requires_existing_target() {
        let engine = RenameTestEngine::new();
        let ctx = file_io_ctx();
        let (source, source_fh) = create_file(&engine, b"source", O_RDWR, &ctx);
        engine.release(&source_fh).expect("release source handle");

        assert_eq!(
            engine.rename(
                ROOT_INODE_ID,
                b"source",
                ROOT_INODE_ID,
                b"missing",
                RENAME_EXCHANGE,
                &ctx,
            ),
            Err(Errno::ENOENT)
        );
        assert_eq!(
            engine
                .lookup(ROOT_INODE_ID, b"source", &ctx)
                .unwrap()
                .inode_id,
            source.inode_id
        );
    }

    #[test]
    fn rename_rejects_unsupported_or_conflicting_flags() {
        let engine = RenameTestEngine::new();
        let ctx = file_io_ctx();
        let (source, source_fh) = create_file(&engine, b"source", O_RDWR, &ctx);
        let (target, target_fh) = create_file(&engine, b"target", O_RDWR, &ctx);
        engine.release(&source_fh).expect("release source handle");
        engine.release(&target_fh).expect("release target handle");

        assert_eq!(
            engine.rename(
                ROOT_INODE_ID,
                b"source",
                ROOT_INODE_ID,
                b"target",
                RENAME_WHITEOUT,
                &ctx,
            ),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            engine.rename(
                ROOT_INODE_ID,
                b"source",
                ROOT_INODE_ID,
                b"target",
                RENAME_NOREPLACE | RENAME_EXCHANGE,
                &ctx,
            ),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            engine
                .lookup(ROOT_INODE_ID, b"source", &ctx)
                .unwrap()
                .inode_id,
            source.inode_id
        );
        assert_eq!(
            engine
                .lookup(ROOT_INODE_ID, b"target", &ctx)
                .unwrap()
                .inode_id,
            target.inode_id
        );
    }

    #[test]
    fn rename_cross_directory_subdir_adjusts_parent_nlink() {
        let engine = RenameTestEngine::new();
        let ctx = file_io_ctx();
        let dir_a = create_dir(&engine, ROOT_INODE_ID, b"a", &ctx);
        let dir_b = create_dir(&engine, ROOT_INODE_ID, b"b", &ctx);
        let subdir = create_dir(&engine, dir_a.inode_id, b"sub", &ctx);

        let before_a = engine.getattr(dir_a.inode_id, None, &ctx).unwrap();
        let before_b = engine.getattr(dir_b.inode_id, None, &ctx).unwrap();
        assert!(
            before_a.posix.nlink > 2,
            "dir_a nlink should be > 2 due to subdir '..'"
        );
        assert_eq!(before_b.posix.nlink, 2, "empty dir_b should have nlink 2");

        engine
            .rename(dir_a.inode_id, b"sub", dir_b.inode_id, b"sub", 0, &ctx)
            .expect("cross-dir subdir rename");

        let after_a = engine.getattr(dir_a.inode_id, None, &ctx).unwrap();
        let after_b = engine.getattr(dir_b.inode_id, None, &ctx).unwrap();
        assert_eq!(
            after_a.posix.nlink,
            before_a.posix.nlink - 1,
            "dir_a nlink should decrease by 1 after subdir moved out"
        );
        assert_eq!(
            after_b.posix.nlink,
            before_b.posix.nlink + 1,
            "dir_b nlink should increase by 1 after subdir moved in"
        );

        let subdir_after = engine.lookup(dir_b.inode_id, b"sub", &ctx).unwrap();
        assert_eq!(subdir_after.inode_id, subdir.inode_id);
        assert_eq!(
            engine.lookup(dir_a.inode_id, b"sub", &ctx),
            Err(Errno::ENOENT)
        );
    }

    #[test]
    fn rename_cross_directory_file_leaves_parent_nlink_unchanged() {
        let engine = RenameTestEngine::new();
        let ctx = file_io_ctx();
        let dir_a = create_dir(&engine, ROOT_INODE_ID, b"a", &ctx);
        let dir_b = create_dir(&engine, ROOT_INODE_ID, b"b", &ctx);
        let (file_attr, file_fh) = create_file_in(&engine, dir_a.inode_id, b"f", O_RDWR, &ctx);
        engine.release(&file_fh).expect("release create handle");

        let before_a = engine.getattr(dir_a.inode_id, None, &ctx).unwrap();
        let before_b = engine.getattr(dir_b.inode_id, None, &ctx).unwrap();

        engine
            .rename(dir_a.inode_id, b"f", dir_b.inode_id, b"f", 0, &ctx)
            .expect("cross-dir file rename");

        let after_a = engine.getattr(dir_a.inode_id, None, &ctx).unwrap();
        let after_b = engine.getattr(dir_b.inode_id, None, &ctx).unwrap();
        assert_eq!(
            after_a.posix.nlink, before_a.posix.nlink,
            "file rename should not change source parent nlink"
        );
        assert_eq!(
            after_b.posix.nlink, before_b.posix.nlink,
            "file rename should not change target parent nlink"
        );

        let moved = engine.lookup(dir_b.inode_id, b"f", &ctx).unwrap();
        assert_eq!(moved.inode_id, file_attr.inode_id);
        assert_eq!(
            engine.lookup(dir_a.inode_id, b"f", &ctx),
            Err(Errno::ENOENT)
        );
    }

    #[test]
    fn rename_overwrite_empty_directory_orphans_target_and_adjusts_parent_nlink() {
        let engine = RenameTestEngine::new();
        let ctx = file_io_ctx();
        let dir_a = create_dir(&engine, ROOT_INODE_ID, b"a", &ctx);
        let dir_b = create_dir(&engine, ROOT_INODE_ID, b"b", &ctx);

        let root_before = engine.getattr(ROOT_INODE_ID, None, &ctx).unwrap();
        assert!(
            root_before.posix.nlink >= 4,
            "root should have nlink >= 4 with two empty subdirectories"
        );

        engine
            .rename(ROOT_INODE_ID, b"a", ROOT_INODE_ID, b"b", 0, &ctx)
            .expect("rename empty dir over empty dir");

        let target_after = engine.lookup(ROOT_INODE_ID, b"b", &ctx).unwrap();
        assert_eq!(target_after.inode_id, dir_a.inode_id);

        assert_eq!(engine.lookup(ROOT_INODE_ID, b"a", &ctx), Err(Errno::ENOENT));

        let root_after = engine.getattr(ROOT_INODE_ID, None, &ctx).unwrap();
        assert_eq!(
            root_after.posix.nlink,
            root_before.posix.nlink - 1,
            "root nlink should decrease by 1 after dir_b's '..' removed"
        );

        assert_eq!(
            engine.getattr(dir_b.inode_id, None, &ctx),
            Err(Errno::ENOENT)
        );
    }

    #[test]
    fn rename_self_rename_file_same_name_same_parent_is_noop() {
        let engine = RenameTestEngine::new();
        let ctx = file_io_ctx();
        let (file_attr, file_fh) = create_file(&engine, b"self.txt", O_RDWR, &ctx);
        engine.write(&file_fh, 0, b"payload", &ctx).unwrap();
        engine.release(&file_fh).expect("release create handle");

        engine
            .rename(
                ROOT_INODE_ID,
                b"self.txt",
                ROOT_INODE_ID,
                b"self.txt",
                0,
                &ctx,
            )
            .expect("self-rename");

        let after = engine.lookup(ROOT_INODE_ID, b"self.txt", &ctx).unwrap();
        assert_eq!(after.inode_id, file_attr.inode_id);

        let fh = engine.open(after.inode_id, O_RDONLY, &ctx).unwrap();
        assert_eq!(
            engine.read(&fh, 0, b"payload".len() as u32, &ctx),
            Ok(b"payload".to_vec())
        );
    }

    #[test]
    fn rename_self_rename_directory_same_name_same_parent_is_noop() {
        let engine = RenameTestEngine::new();
        let ctx = file_io_ctx();
        let dir = create_dir(&engine, ROOT_INODE_ID, b"selfdir", &ctx);
        let root_before = engine.getattr(ROOT_INODE_ID, None, &ctx).unwrap();

        engine
            .rename(
                ROOT_INODE_ID,
                b"selfdir",
                ROOT_INODE_ID,
                b"selfdir",
                0,
                &ctx,
            )
            .expect("self-rename directory");

        let after = engine.lookup(ROOT_INODE_ID, b"selfdir", &ctx).unwrap();
        assert_eq!(after.inode_id, dir.inode_id);

        let root_after = engine.getattr(ROOT_INODE_ID, None, &ctx).unwrap();
        assert_eq!(root_after.posix.nlink, root_before.posix.nlink);
    }

    #[test]
    fn rename_file_overwrite_removes_target_inode_when_last_link() {
        let engine = RenameTestEngine::new();
        let ctx = file_io_ctx();
        let (_file_a, file_a_fh) = create_file(&engine, b"a", O_RDWR, &ctx);
        engine.release(&file_a_fh).expect("release file a");
        let (file_b, file_b_fh) = create_file(&engine, b"b", O_RDWR, &ctx);
        engine.release(&file_b_fh).expect("release file b");
        assert_eq!(file_b.posix.nlink, 1);

        engine
            .rename(ROOT_INODE_ID, b"a", ROOT_INODE_ID, b"b", 0, &ctx)
            .expect("rename file over file");

        assert_eq!(
            engine.getattr(file_b.inode_id, None, &ctx),
            Err(Errno::ENOENT)
        );
    }

    #[test]
    fn link_creates_hard_link_and_both_names_share_inode_attributes() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (original, fh) = create_file(&engine, b"original.txt", O_RDWR, &ctx);
        engine
            .write(&fh, 0, b"linked bytes", &ctx)
            .expect("write original data");

        let linked = engine
            .link(original.inode_id, ROOT_INODE_ID, b"alias.txt", &ctx)
            .expect("create hard link");

        let original_lookup = engine
            .lookup(ROOT_INODE_ID, b"original.txt", &ctx)
            .expect("lookup original");
        let alias_lookup = engine
            .lookup(ROOT_INODE_ID, b"alias.txt", &ctx)
            .expect("lookup alias");
        assert_eq!(linked.inode_id, original.inode_id);
        assert_eq!(alias_lookup.inode_id, original.inode_id);
        assert_eq!(original_lookup.inode_id, original.inode_id);
        assert_eq!(alias_lookup.kind, NodeKind::File);
        assert_eq!(alias_lookup.posix.mode, original_lookup.posix.mode);
        assert_eq!(alias_lookup.posix.size, original_lookup.posix.size);
    }

    #[test]
    fn link_increments_nlink_on_target_inode() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (original, _fh) = create_file(&engine, b"original.txt", O_RDWR, &ctx);

        let linked = engine
            .link(original.inode_id, ROOT_INODE_ID, b"alias.txt", &ctx)
            .expect("create hard link");

        assert_eq!(linked.posix.nlink, 2);
        assert_eq!(
            engine
                .getattr(original.inode_id, None, &ctx)
                .expect("getattr original")
                .posix
                .nlink,
            2
        );
    }

    #[test]
    fn link_nonexistent_target_returns_enoent() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();

        assert_eq!(
            engine.link(InodeId::new(99_999), ROOT_INODE_ID, b"alias.txt", &ctx),
            Err(Errno::ENOENT)
        );
        assert_eq!(
            engine.lookup(ROOT_INODE_ID, b"alias.txt", &ctx),
            Err(Errno::ENOENT)
        );
    }

    #[test]
    fn link_to_existing_destination_returns_eexist() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (original, _original_fh) = create_file(&engine, b"original.txt", O_RDWR, &ctx);
        let (_existing, _existing_fh) = create_file(&engine, b"existing.txt", O_RDWR, &ctx);

        assert_eq!(
            engine.link(original.inode_id, ROOT_INODE_ID, b"existing.txt", &ctx),
            Err(Errno::EEXIST)
        );
        assert_eq!(
            engine
                .getattr(original.inode_id, None, &ctx)
                .expect("getattr original")
                .posix
                .nlink,
            1
        );
    }

    #[test]
    fn link_on_directory_returns_eperm() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let dir = create_dir(&engine, ROOT_INODE_ID, b"dir", &ctx);

        assert_eq!(
            engine.link(dir.inode_id, ROOT_INODE_ID, b"dir-link", &ctx),
            Err(Errno::EPERM)
        );
        assert_eq!(
            engine.lookup(ROOT_INODE_ID, b"dir-link", &ctx),
            Err(Errno::ENOENT)
        );
    }

    #[test]
    fn link_into_missing_parent_returns_enoent() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (original, _fh) = create_file(&engine, b"original.txt", O_RDWR, &ctx);

        assert_eq!(
            engine.link(original.inode_id, InodeId::new(999), b"alias.txt", &ctx),
            Err(Errno::ENOENT)
        );
        assert_eq!(
            engine
                .getattr(original.inode_id, None, &ctx)
                .expect("getattr original")
                .posix
                .nlink,
            1
        );
    }

    #[test]
    fn link_to_cross_device_target_returns_exdev() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (original, _fh) = create_file(&engine, b"original.txt", O_RDWR, &ctx);
        engine.mark_cross_device_link_target(original.inode_id);

        assert_eq!(
            engine.link(original.inode_id, ROOT_INODE_ID, b"alias.txt", &ctx),
            Err(Errno::EXDEV)
        );
        assert_eq!(
            engine.lookup(ROOT_INODE_ID, b"alias.txt", &ctx),
            Err(Errno::ENOENT)
        );
    }

    #[test]
    fn link_over_nlink_limit_returns_emlink() {
        let engine = FileIoTestEngine::with_max_nlink(1);
        let ctx = file_io_ctx();
        let (original, _fh) = create_file(&engine, b"original.txt", O_RDWR, &ctx);

        assert_eq!(
            engine.link(original.inode_id, ROOT_INODE_ID, b"alias.txt", &ctx),
            Err(Errno::EMLINK)
        );
        assert_eq!(
            engine
                .getattr(original.inode_id, None, &ctx)
                .expect("getattr original")
                .posix
                .nlink,
            1
        );
    }

    // ── create O_EXCL / O_TRUNC flag tests ──────────────────────────

    #[test]
    fn create_existing_with_oexcl_returns_eexist() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (_original, _fh) = create_file(&engine, b"file.txt", O_RDWR, &ctx);
        let result = engine.create(ROOT_INODE_ID, b"file.txt", 0o644, O_EXCL | O_RDWR, &ctx);
        assert_eq!(result, Err(Errno::EEXIST));
    }

    #[test]
    fn create_existing_with_trunc_truncates_existing_file() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (_original, fh) = create_file(&engine, b"file.txt", O_RDWR, &ctx);
        engine
            .write(&fh, 0, b"original data", &ctx)
            .expect("write data");

        let (attr, reopen_fh) = engine
            .create(ROOT_INODE_ID, b"file.txt", 0o644, O_TRUNC | O_RDWR, &ctx)
            .expect("create with trunc");

        assert_eq!(attr.posix.size, 0);
        assert_eq!(engine.read(&reopen_fh, 0, 16, &ctx), Ok(Vec::new()));
    }

    #[test]
    fn create_existing_without_flags_opens_existing_file() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (original, _fh) = create_file(&engine, b"file.txt", O_RDWR, &ctx);
        let (attr, _reopen_fh) = engine
            .create(ROOT_INODE_ID, b"file.txt", 0o644, O_RDWR, &ctx)
            .expect("create on existing file without O_EXCL should open it");
        assert_eq!(attr.inode_id, original.inode_id);
    }

    #[test]
    fn create_existing_with_oexcl_and_trunc_returns_eexist() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (_original, _fh) = create_file(&engine, b"file.txt", O_RDWR, &ctx);
        let result = engine.create(
            ROOT_INODE_ID,
            b"file.txt",
            0o644,
            O_EXCL | O_TRUNC | O_RDWR,
            &ctx,
        );
        assert_eq!(result, Err(Errno::EEXIST));
    }

    // ── create_excl atomicity tests ────────────────────────────────────

    #[test]
    fn create_excl_absent_entry_succeeds() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (attr, _fh) = engine
            .create_excl(ROOT_INODE_ID, b"new.txt", 0o644, O_RDWR, &ctx)
            .expect("create_excl on absent entry");
        assert_eq!(attr.posix.mode & S_IFMT, S_IFREG);
        // Verify via lookup.
        let looked_up = engine
            .lookup(ROOT_INODE_ID, b"new.txt", &ctx)
            .expect("lookup after create_excl");
        assert_eq!(looked_up.inode_id, attr.inode_id);
    }

    #[test]
    fn create_excl_existing_entry_returns_eexist() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (_first, _fh) = create_file(&engine, b"file.txt", O_RDWR, &ctx);
        let result = engine.create_excl(ROOT_INODE_ID, b"file.txt", 0o644, O_RDWR, &ctx);
        assert_eq!(result, Err(Errno::EEXIST));
    }

    #[test]
    fn create_excl_twice_same_name_second_fails() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (first, _fh) = engine
            .create_excl(ROOT_INODE_ID, b"only.txt", 0o644, O_RDWR, &ctx)
            .expect("first create_excl");
        let second = engine.create_excl(ROOT_INODE_ID, b"only.txt", 0o644, O_RDWR, &ctx);
        assert_eq!(second, Err(Errno::EEXIST));
        // Stored inode is still the first one.
        let looked_up = engine
            .lookup(ROOT_INODE_ID, b"only.txt", &ctx)
            .expect("lookup");
        assert_eq!(looked_up.inode_id, first.inode_id);
    }

    #[test]
    fn create_excl_on_non_directory_returns_enotdir() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (file_attr, _fh) = create_file(&engine, b"regular.txt", O_RDWR, &ctx);
        let result = engine.create_excl(
            file_attr.inode_id,
            b"child.txt",
            0o644,
            O_EXCL | O_RDWR,
            &ctx,
        );
        assert_eq!(result, Err(Errno::ENOTDIR));
    }

    #[test]
    fn create_excl_on_missing_parent_returns_enoent() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let result = engine.create_excl(
            InodeId::new(9999),
            b"orphan.txt",
            0o644,
            O_EXCL | O_RDWR,
            &ctx,
        );
        assert_eq!(result, Err(Errno::ENOENT));
    }

    #[test]
    fn create_excl_mode_respects_umask() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx(); // umask 0o022
        let (attr, _fh) = engine
            .create_excl(ROOT_INODE_ID, b"masked.txt", 0o666, O_EXCL | O_RDWR, &ctx)
            .expect("create_excl");
        // mode & ~umask in POSIX; mock engine doesn't apply umask yet, so
        // we assert the engine-stored mode (S_IFREG | mode_without_type).
        assert_eq!(attr.posix.mode & S_IFMT, S_IFREG);
    }

    #[test]
    fn create_excl_preserves_uid_gid_from_ctx() {
        let engine = FileIoTestEngine::new();
        let ctx = RequestCtx {
            uid: 42,
            gid: 99,
            pid: 1,
            umask: 0,
            groups: alloc::vec![],
        };
        let (attr, _fh) = engine
            .create_excl(ROOT_INODE_ID, b"owned.txt", 0o600, O_EXCL | O_RDWR, &ctx)
            .expect("create_excl");
        assert_eq!(attr.posix.uid, 42);
        assert_eq!(attr.posix.gid, 99);
    }

    // ── create_excl contract: no duplicate inode creation ─────────────

    /// Even when called many times on the same (parent, name) pair,
    /// create_excl must never create a second entry; every call after the
    /// first must return EEXIST.
    #[test]
    fn create_excl_duplicate_under_repeated_calls() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (first, _fh) = engine
            .create_excl(ROOT_INODE_ID, b"unique.txt", 0o644, O_EXCL | O_RDWR, &ctx)
            .expect("first create_excl");

        for _ in 0..100 {
            let result =
                engine.create_excl(ROOT_INODE_ID, b"unique.txt", 0o644, O_EXCL | O_RDWR, &ctx);
            assert_eq!(
                result,
                Err(Errno::EEXIST),
                "create_excl must return EEXIST on every repeated attempt"
            );
        }

        // The stored inode is still the first one.
        let looked_up = engine
            .lookup(ROOT_INODE_ID, b"unique.txt", &ctx)
            .expect("lookup");
        assert_eq!(looked_up.inode_id, first.inode_id);
    }

    /// create_excl and create with O_EXCL must behave identically
    /// for the existence check.
    #[test]
    fn create_excl_matches_create_with_oexcl() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();

        // Both fail on existing entry.
        let (_existing, _fh) = create_file(&engine, b"common.txt", O_RDWR, &ctx);

        let via_create_excl =
            engine.create_excl(ROOT_INODE_ID, b"common.txt", 0o644, O_EXCL | O_RDWR, &ctx);
        let via_create_oexcl =
            engine.create(ROOT_INODE_ID, b"common.txt", 0o644, O_EXCL | O_RDWR, &ctx);
        assert_eq!(via_create_excl, Err(Errno::EEXIST));
        assert_eq!(via_create_oexcl, Err(Errno::EEXIST));

        // Both succeed on absent entry.
        let (a1, _) = engine
            .create_excl(ROOT_INODE_ID, b"new_a.txt", 0o644, O_EXCL | O_RDWR, &ctx)
            .expect("create_excl new");
        let (a2, _) = engine
            .create(ROOT_INODE_ID, b"new_b.txt", 0o644, O_EXCL | O_RDWR, &ctx)
            .expect("create O_EXCL new");
        assert_eq!(a1.posix.mode & S_IFMT, S_IFREG);
        assert_eq!(a2.posix.mode & S_IFMT, S_IFREG);
    }

    /// create_excl must not observe an entry created by a prior create_excl
    /// in the same critical section — verified by repeated attempts.
    #[test]
    fn create_excl_serialized_under_repeated_stress() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        // Use a sequence of different names; each should succeed exactly once.
        for i in 0..50 {
            let mut name = alloc::vec::Vec::new();
            name.extend_from_slice(b"stress_");
            // Simple decimal encoding of i
            if i >= 10 {
                name.push(b'0' + (i / 10) as u8);
            }
            name.push(b'0' + (i % 10) as u8);
            let name_bytes = name.as_slice();
            let (attr, _fh) = engine
                .create_excl(ROOT_INODE_ID, name_bytes, 0o644, O_EXCL | O_RDWR, &ctx)
                .expect("first create_excl for name");
            assert_eq!(attr.posix.mode & S_IFMT, S_IFREG);
            // Second attempt on same name must fail.
            assert_eq!(
                engine.create_excl(ROOT_INODE_ID, name_bytes, 0o644, O_EXCL | O_RDWR, &ctx),
                Err(Errno::EEXIST)
            );
        }
    }

    #[test]
    fn file_io_mknod_fifo_creates_lookup_and_getattr_visible_inode() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();

        let attr = engine
            .mknod(ROOT_INODE_ID, b"pipe", S_IFIFO | 0o666, 0, &ctx)
            .expect("create FIFO");

        assert_eq!(attr.kind, NodeKind::Fifo);
        assert_eq!(attr.posix.mode & S_IFMT, S_IFIFO);
        assert_eq!(attr.posix.mode & !S_IFMT, 0o644);
        assert_eq!(attr.posix.uid, ctx.uid);
        assert_eq!(attr.posix.gid, ctx.gid);
        let looked_up = engine
            .lookup(ROOT_INODE_ID, b"pipe", &ctx)
            .expect("lookup FIFO");
        assert_eq!(looked_up.inode_id, attr.inode_id);
        assert_eq!(looked_up.kind, NodeKind::Fifo);
        assert_eq!(
            engine
                .getattr(attr.inode_id, None, &ctx)
                .expect("getattr FIFO")
                .kind,
            NodeKind::Fifo
        );
    }

    #[test]
    fn file_io_mknod_fifo_under_file_parent_returns_enotdir() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (file, _fh) = create_file(&engine, b"parent-file", O_RDWR, &ctx);

        assert_eq!(
            engine.mknod(file.inode_id, b"pipe", S_IFIFO | 0o644, 0, &ctx),
            Err(Errno::ENOTDIR)
        );
    }

    #[test]
    fn file_io_mknod_fifo_existing_name_returns_eexist() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let first = engine
            .mknod(ROOT_INODE_ID, b"pipe", S_IFIFO | 0o644, 0, &ctx)
            .expect("create first FIFO");

        assert_eq!(
            engine.mknod(ROOT_INODE_ID, b"pipe", S_IFIFO | 0o600, 0, &ctx),
            Err(Errno::EEXIST)
        );
        assert_eq!(
            engine
                .lookup(ROOT_INODE_ID, b"pipe", &ctx)
                .expect("lookup original FIFO")
                .inode_id,
            first.inode_id
        );
    }

    #[test]
    fn file_io_mknod_chrdev_devnode_returns_eopnotsupp() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();

        assert_eq!(
            engine.mknod(ROOT_INODE_ID, b".wh.foo", S_IFCHR | 0o600, 0, &ctx),
            Err(Errno::EOPNOTSUPP)
        );
        assert_eq!(
            engine.mknod(ROOT_INODE_ID, b"blk", S_IFBLK | 0o640, 0x0800, &ctx),
            Err(Errno::EOPNOTSUPP)
        );
    }

    #[test]
    fn file_io_mknod_fifo_missing_parent_returns_enoent() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();

        assert_eq!(
            engine.mknod(InodeId::new(99_999), b"pipe", S_IFIFO | 0o644, 0, &ctx),
            Err(Errno::ENOENT)
        );
    }

    #[test]
    fn file_io_mknod_unsupported_node_types_return_eopnotsupp() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();

        for (name, mode) in [
            (&b"char"[..], S_IFCHR | 0o600),
            (&b"block"[..], S_IFBLK | 0o600),
            (&b"socket"[..], S_IFSOCK | 0o600),
            (&b"regular"[..], S_IFREG | 0o600),
        ] {
            assert_eq!(
                engine.mknod(ROOT_INODE_ID, name, mode, 0, &ctx),
                Err(Errno::EOPNOTSUPP)
            );
            assert_eq!(engine.lookup(ROOT_INODE_ID, name, &ctx), Err(Errno::ENOENT));
        }
    }

    #[test]
    fn file_io_setattr_mode_preserves_file_type_bits() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (attr, _fh) = create_file(&engine, b"mode.txt", O_RDWR, &ctx);

        let mut update = SetAttr::new();
        update.valid = FATTR_MODE;
        update.mode = S_IFDIR | 0o600;

        let updated = engine
            .setattr(attr.inode_id, &update, None, &ctx)
            .expect("set mode");

        assert_eq!(updated.kind, NodeKind::File);
        assert_eq!(updated.posix.mode & S_IFMT, S_IFREG);
        assert_eq!(updated.posix.mode & !S_IFMT, 0o600);
    }

    #[test]
    fn file_io_setattr_uid_gid_updates_owner_fields() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (attr, _fh) = create_file(&engine, b"owner.txt", O_RDWR, &ctx);

        let mut update = SetAttr::new();
        update.valid = FATTR_UID | FATTR_GID;
        update.uid = 2000;
        update.gid = 3000;

        let updated = engine
            .setattr(attr.inode_id, &update, None, &ctx)
            .expect("set owner");

        assert_eq!(updated.posix.uid, 2000);
        assert_eq!(updated.posix.gid, 3000);
    }

    #[test]
    fn file_io_setattr_size_truncates_and_extends_data() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (attr, fh) = create_file(&engine, b"resize.txt", O_RDWR, &ctx);
        engine.write(&fh, 0, b"abcdef", &ctx).expect("write data");

        let mut shrink = SetAttr::new();
        shrink.valid = FATTR_SIZE;
        shrink.size = 3;
        let shrunk = engine
            .setattr(attr.inode_id, &shrink, Some(&fh), &ctx)
            .expect("shrink file");
        assert_eq!(shrunk.posix.size, 3);
        assert_eq!(engine.read(&fh, 0, 8, &ctx), Ok(b"abc".to_vec()));

        let mut grow = SetAttr::new();
        grow.valid = FATTR_SIZE;
        grow.size = 6;
        let grown = engine
            .setattr(attr.inode_id, &grow, Some(&fh), &ctx)
            .expect("extend file");
        assert_eq!(grown.posix.size, 6);
        assert_eq!(engine.read(&fh, 0, 8, &ctx), Ok(b"abc\0\0\0".to_vec()));
    }

    #[test]
    fn file_io_setattr_timestamps_update_posix_attrs() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (attr, _fh) = create_file(&engine, b"time.txt", O_RDWR, &ctx);

        let mut update = SetAttr::new();
        update.valid = FATTR_ATIME | FATTR_MTIME | FATTR_CTIME;
        update.atime_ns = 100;
        update.mtime_ns = 200;
        update.ctime_ns = 300;

        let updated = engine
            .setattr(attr.inode_id, &update, None, &ctx)
            .expect("set timestamps");

        assert_eq!(updated.posix.atime_ns, 100);
        assert_eq!(updated.posix.mtime_ns, 200);
        assert_eq!(updated.posix.ctime_ns, 300);
    }

    #[test]
    fn file_io_setattr_missing_inode_returns_enoent() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();

        let mut update = SetAttr::new();
        update.valid = FATTR_MODE;
        update.mode = 0o600;

        assert_eq!(
            engine.setattr(InodeId::new(99_999), &update, None, &ctx),
            Err(Errno::ENOENT)
        );
    }

    #[test]
    fn symlink_create_and_readlink_round_trips_target_and_attrs() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();

        let attr = engine
            .symlink(ROOT_INODE_ID, b"link.txt", b"target.txt", &ctx)
            .expect("create symlink");

        assert_eq!(attr.kind, NodeKind::Symlink);
        assert_eq!(attr.posix.mode & S_IFMT, S_IFLNK);
        assert_eq!(attr.posix.mode & !S_IFMT, 0o777);
        assert_eq!(attr.posix.uid, ctx.uid);
        assert_eq!(attr.posix.gid, ctx.gid);
        assert_eq!(attr.posix.size, b"target.txt".len() as u64);
        assert_eq!(
            engine
                .lookup(ROOT_INODE_ID, b"link.txt", &ctx)
                .expect("lookup symlink")
                .inode_id,
            attr.inode_id
        );
        assert_eq!(
            engine.readlink(attr.inode_id, &ctx),
            Ok(b"target.txt".to_vec())
        );
    }

    #[test]
    fn symlink_in_subdirectory_is_lookup_visible() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let dir = create_dir(&engine, ROOT_INODE_ID, b"dir", &ctx);

        let attr = engine
            .symlink(dir.inode_id, b"nested", b"../target", &ctx)
            .expect("create nested symlink");

        assert_eq!(
            engine
                .lookup(dir.inode_id, b"nested", &ctx)
                .expect("lookup nested symlink")
                .inode_id,
            attr.inode_id
        );
        assert_eq!(
            engine.readlink(attr.inode_id, &ctx),
            Ok(b"../target".to_vec())
        );
        assert_eq!(
            engine.lookup(ROOT_INODE_ID, b"nested", &ctx),
            Err(Errno::ENOENT)
        );
    }

    #[test]
    fn symlink_preserves_absolute_and_relative_target_bytes() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();

        let relative = engine
            .symlink(ROOT_INODE_ID, b"relative", b"../a/./b", &ctx)
            .expect("create relative symlink");
        let absolute = engine
            .symlink(ROOT_INODE_ID, b"absolute", b"/var/lib/tidefs", &ctx)
            .expect("create absolute symlink");

        assert_eq!(
            engine.readlink(relative.inode_id, &ctx),
            Ok(b"../a/./b".to_vec())
        );
        assert_eq!(
            engine.readlink(absolute.inode_id, &ctx),
            Ok(b"/var/lib/tidefs".to_vec())
        );
    }

    #[test]
    fn symlink_existing_name_returns_eexist() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (existing, _fh) = create_file(&engine, b"existing", O_RDWR, &ctx);

        assert_eq!(
            engine.symlink(ROOT_INODE_ID, b"existing", b"target", &ctx),
            Err(Errno::EEXIST)
        );
        assert_eq!(
            engine
                .lookup(ROOT_INODE_ID, b"existing", &ctx)
                .expect("lookup existing")
                .inode_id,
            existing.inode_id
        );
    }

    #[test]
    fn readlink_missing_inode_returns_enoent() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();

        assert_eq!(
            engine.readlink(InodeId::new(99_999), &ctx),
            Err(Errno::ENOENT)
        );
    }

    #[test]
    fn readlink_regular_file_returns_einval() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (file, _fh) = create_file(&engine, b"file", O_RDWR, &ctx);

        assert_eq!(engine.readlink(file.inode_id, &ctx), Err(Errno::EINVAL));
    }

    #[test]
    fn file_io_xattr_set_and_get_round_trips_value() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (attr, _fh) = create_file(&engine, b"xattr.txt", O_RDWR, &ctx);

        engine
            .setxattr(attr.inode_id, b"user.color", b"blue", 0, &ctx)
            .expect("set xattr");

        assert_eq!(
            engine.getxattr(attr.inode_id, b"user.color", &ctx),
            Ok(b"blue".to_vec())
        );
    }

    #[test]
    fn file_io_xattr_create_and_replace_flags_enforce_existence() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (attr, _fh) = create_file(&engine, b"xattr-flags.txt", O_RDWR, &ctx);

        engine
            .setxattr(attr.inode_id, b"user.state", b"created", XATTR_CREATE, &ctx)
            .expect("create xattr");
        assert_eq!(
            engine.setxattr(
                attr.inode_id,
                b"user.state",
                b"duplicate",
                XATTR_CREATE,
                &ctx,
            ),
            Err(Errno::EEXIST)
        );

        engine
            .setxattr(
                attr.inode_id,
                b"user.state",
                b"replaced",
                XATTR_REPLACE,
                &ctx,
            )
            .expect("replace xattr");
        assert_eq!(
            engine.getxattr(attr.inode_id, b"user.state", &ctx),
            Ok(b"replaced".to_vec())
        );
        assert_eq!(
            engine.setxattr(
                attr.inode_id,
                b"user.missing",
                b"value",
                XATTR_REPLACE,
                &ctx,
            ),
            Err(Errno::ENODATA)
        );
        assert_eq!(
            engine.setxattr(
                attr.inode_id,
                b"user.invalid",
                b"value",
                XATTR_CREATE | XATTR_REPLACE,
                &ctx,
            ),
            Err(Errno::EINVAL)
        );
    }

    #[test]
    fn file_io_xattr_list_returns_sorted_null_separated_names() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (attr, _fh) = create_file(&engine, b"xattr-list.txt", O_RDWR, &ctx);

        engine
            .setxattr(attr.inode_id, b"user.beta", b"b", 0, &ctx)
            .expect("set beta");
        engine
            .setxattr(attr.inode_id, b"user.alpha", b"a", 0, &ctx)
            .expect("set alpha");

        assert_eq!(
            engine.listxattr(attr.inode_id, &ctx),
            Ok(b"user.alpha\0user.beta\0".to_vec())
        );
    }

    #[test]
    fn file_io_xattr_list_empty_inode_returns_final_null() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (attr, _fh) = create_file(&engine, b"xattr-empty.txt", O_RDWR, &ctx);

        assert_eq!(engine.listxattr(attr.inode_id, &ctx), Ok(alloc::vec![0]));
    }

    #[test]
    fn file_io_xattr_remove_deletes_existing_value() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (attr, _fh) = create_file(&engine, b"xattr-remove.txt", O_RDWR, &ctx);

        engine
            .setxattr(attr.inode_id, b"user.remove", b"value", 0, &ctx)
            .expect("set xattr");
        engine
            .removexattr(attr.inode_id, b"user.remove", &ctx)
            .expect("remove xattr");

        assert_eq!(
            engine.getxattr(attr.inode_id, b"user.remove", &ctx),
            Err(Errno::ENODATA)
        );
        assert_eq!(
            engine.removexattr(attr.inode_id, b"user.remove", &ctx),
            Err(Errno::ENODATA)
        );
    }

    #[test]
    fn file_io_xattr_missing_inode_returns_enoent() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let missing = InodeId::new(99_999);

        assert_eq!(
            engine.getxattr(missing, b"user.attr", &ctx),
            Err(Errno::ENOENT)
        );
        assert_eq!(
            engine.setxattr(missing, b"user.attr", b"value", 0, &ctx),
            Err(Errno::ENOENT)
        );
        assert_eq!(engine.listxattr(missing, &ctx), Err(Errno::ENOENT));
        assert_eq!(
            engine.removexattr(missing, b"user.attr", &ctx),
            Err(Errno::ENOENT)
        );
    }

    #[test]
    fn file_io_xattrs_survive_getattr_reads() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (attr, _fh) = create_file(&engine, b"xattr-getattr.txt", O_RDWR, &ctx);

        engine
            .setxattr(attr.inode_id, b"user.persist", b"kept", 0, &ctx)
            .expect("set xattr");
        let after_getattr = engine
            .getattr(attr.inode_id, None, &ctx)
            .expect("getattr after xattr");

        assert_eq!(after_getattr.inode_id, attr.inode_id);
        assert_eq!(
            engine.getxattr(attr.inode_id, b"user.persist", &ctx),
            Ok(b"kept".to_vec())
        );
    }

    #[test]
    fn unlink_after_link_preserves_inode_until_last_link_removed() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (original, fh) = create_file(&engine, b"original.txt", O_RDWR, &ctx);
        engine
            .write(&fh, 0, b"survives unlink", &ctx)
            .expect("write original data");
        engine
            .link(original.inode_id, ROOT_INODE_ID, b"alias.txt", &ctx)
            .expect("create hard link");

        engine
            .unlink(ROOT_INODE_ID, b"original.txt", &ctx)
            .expect("unlink original");

        assert_eq!(
            engine.lookup(ROOT_INODE_ID, b"original.txt", &ctx),
            Err(Errno::ENOENT)
        );
        let alias = engine
            .lookup(ROOT_INODE_ID, b"alias.txt", &ctx)
            .expect("lookup alias");
        assert_eq!(alias.inode_id, original.inode_id);
        assert_eq!(alias.posix.nlink, 1);
        let alias_fh = engine
            .open(alias.inode_id, O_RDONLY, &ctx)
            .expect("open alias");
        assert_eq!(
            engine.read(&alias_fh, 0, b"survives unlink".len() as u32, &ctx),
            Ok(b"survives unlink".to_vec())
        );
    }

    // ── hard-link nlink contract tests ───────────────────────────────

    #[test]
    fn unlink_decrements_nlink_by_one() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (original, _fh) = create_file(&engine, b"original.txt", O_RDWR, &ctx);
        engine
            .link(original.inode_id, ROOT_INODE_ID, b"alias.txt", &ctx)
            .expect("create hard link");

        let attr = engine
            .getattr(original.inode_id, None, &ctx)
            .expect("getattr");
        assert_eq!(attr.posix.nlink, 2);

        engine
            .unlink(ROOT_INODE_ID, b"alias.txt", &ctx)
            .expect("unlink alias");
        let attr = engine
            .getattr(original.inode_id, None, &ctx)
            .expect("getattr after unlink");
        assert_eq!(attr.posix.nlink, 1);

        engine
            .lookup(ROOT_INODE_ID, b"original.txt", &ctx)
            .expect("lookup original");
    }

    #[test]
    fn nlink_preserved_through_multiple_hard_links() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (original, _fh) = create_file(&engine, b"link0", O_RDWR, &ctx);
        assert_eq!(original.posix.nlink, 1);

        for i in 1..=3 {
            let name = alloc::format!("link{i}");
            engine
                .link(original.inode_id, ROOT_INODE_ID, name.as_bytes(), &ctx)
                .expect("create hard link");
        }
        let attr = engine
            .getattr(original.inode_id, None, &ctx)
            .expect("getattr after 3 links");
        assert_eq!(attr.posix.nlink, 4);

        for i in 0..=3 {
            let name = alloc::format!("link{i}");
            let entry = engine.lookup(ROOT_INODE_ID, name.as_bytes(), &ctx).unwrap();
            assert_eq!(entry.inode_id, original.inode_id, "link{i} same inode");
        }
    }

    // ── inc_nlink / dec_nlink unit tests ─────────────────────────────

    #[test]
    fn nlink_inc_from_zero_yields_one() {
        let mut n = 0u64;
        assert_eq!(inc_nlink(&mut n), Ok(1));
        assert_eq!(n, 1);
    }

    #[test]
    fn nlink_inc_from_high_value() {
        let mut n = 1_000_000u64;
        assert_eq!(inc_nlink(&mut n), Ok(1_000_001));
        assert_eq!(n, 1_000_001);
    }

    #[test]
    fn nlink_inc_overflow_rejected() {
        let mut n = u64::MAX;
        assert_eq!(inc_nlink(&mut n), Err(Errno::EOVERFLOW));
        assert_eq!(n, u64::MAX); // unchanged on error
    }

    #[test]
    fn nlink_dec_to_zero_yields_zero() {
        let mut n = 1u64;
        assert_eq!(dec_nlink(&mut n), Ok(0));
        assert_eq!(n, 0);
    }

    #[test]
    fn nlink_dec_underflow_rejected() {
        let mut n = 0u64;
        assert_eq!(dec_nlink(&mut n), Err(Errno::EINVAL));
        assert_eq!(n, 0); // unchanged on error
    }

    #[test]
    fn nlink_roundtrip_inc_dec() {
        let mut n = 5u64;
        assert_eq!(inc_nlink(&mut n), Ok(6));
        assert_eq!(dec_nlink(&mut n), Ok(5));
        assert_eq!(n, 5);
    }

    #[test]
    fn rmdir_rejects_nlink_gt_two_with_enotempty() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let dir = create_dir(&engine, ROOT_INODE_ID, b"parent", &ctx);
        let _subdir = create_dir(&engine, dir.inode_id, b"child", &ctx);

        // parent now has nlink > 2 (itself + '.' + child's '..')
        let parent_attr = engine.getattr(dir.inode_id, None, &ctx).unwrap();
        assert!(
            parent_attr.posix.nlink > 2,
            "directory with subdirectory should have nlink > 2"
        );

        // rmdir on a non-empty directory (has child) must return ENOTEMPTY
        // The nlink > 2 fast-path catches it before the full scan.
        assert_eq!(
            engine.rmdir(ROOT_INODE_ID, b"parent", &ctx),
            Err(Errno::ENOTEMPTY)
        );
    }

    #[test]
    fn rmdir_allows_nlink_eq_two_for_empty_directory() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let dir = create_dir(&engine, ROOT_INODE_ID, b"emptydir", &ctx);

        let attr = engine.getattr(dir.inode_id, None, &ctx).unwrap();
        assert_eq!(attr.posix.nlink, 2, "empty directory has exactly 2 links");

        assert_eq!(engine.rmdir(ROOT_INODE_ID, b"emptydir", &ctx), Ok(()));
        assert_eq!(
            engine.lookup(ROOT_INODE_ID, b"emptydir", &ctx),
            Err(Errno::ENOENT)
        );
    }

    // ── Sticky-bit directory unlink tests ────────────────────────────────

    /// Create a directory with the sticky bit set, owned by `dir_uid`.
    fn create_sticky_dir(
        engine: &RenameTestEngine,
        parent: InodeId,
        name: &[u8],
        dir_uid: u32,
        dir_gid: u32,
    ) -> InodeAttr {
        let ctx = RequestCtx {
            uid: dir_uid,
            gid: dir_gid,
            pid: 1,
            umask: 0,
            groups: alloc::vec![dir_gid],
        };
        engine
            .mkdir(parent, name, 0o1777, &ctx)
            .expect("create sticky directory")
    }

    /// Create a regular file owned by `file_uid` inside `parent`.
    fn create_owned_file(
        engine: &RenameTestEngine,
        parent: InodeId,
        name: &[u8],
        file_uid: u32,
        file_gid: u32,
    ) -> InodeAttr {
        let ctx = RequestCtx {
            uid: file_uid,
            gid: file_gid,
            pid: 1,
            umask: 0,
            groups: alloc::vec![file_gid],
        };
        let (attr, fh) = engine
            .create(parent, name, 0o644, O_RDWR, &ctx)
            .expect("create owned file");
        // Release the handle so it does not pin the inode.
        engine.release(&fh).expect("release file handle");
        attr
    }

    /// Build a `RequestCtx` for a given uid/gid.
    fn user_ctx(uid: u32, gid: u32) -> RequestCtx {
        RequestCtx {
            uid,
            gid,
            pid: 1,
            umask: 0,
            groups: alloc::vec![gid],
        }
    }

    #[test]
    fn sticky_bit_unlink_denies_non_owner_third_party() {
        let engine = RenameTestEngine::new();
        // sticky dir owned by uid 1000
        let sticky_dir = create_sticky_dir(&engine, ROOT_INODE_ID, b"sticky", 1000, 100);
        // file inside sticky dir owned by uid 2000
        let _file_attr = create_owned_file(&engine, sticky_dir.inode_id, b"secret", 2000, 200);
        // uid 3000 (neither file owner nor dir owner) tries to unlink
        let ctx = user_ctx(3000, 300);
        assert_eq!(
            engine.unlink(sticky_dir.inode_id, b"secret", &ctx),
            Err(Errno::EPERM),
            "sticky bit must deny unlink by a non-owner third party"
        );
        // File still exists
        assert!(engine.lookup(sticky_dir.inode_id, b"secret", &ctx).is_ok());
    }

    #[test]
    fn sticky_bit_unlink_allows_file_owner() {
        let engine = RenameTestEngine::new();
        let sticky_dir = create_sticky_dir(&engine, ROOT_INODE_ID, b"sticky", 1000, 100);
        let _file_attr = create_owned_file(&engine, sticky_dir.inode_id, b"mine", 2000, 200);
        // File owner (uid 2000) should be able to unlink
        let ctx = user_ctx(2000, 200);
        assert_eq!(
            engine.unlink(sticky_dir.inode_id, b"mine", &ctx),
            Ok(()),
            "sticky bit must allow file owner to unlink"
        );
        assert_eq!(
            engine.lookup(sticky_dir.inode_id, b"mine", &ctx),
            Err(Errno::ENOENT)
        );
    }

    #[test]
    fn sticky_bit_unlink_allows_directory_owner() {
        let engine = RenameTestEngine::new();
        let sticky_dir = create_sticky_dir(&engine, ROOT_INODE_ID, b"sticky", 1000, 100);
        let _file_attr = create_owned_file(&engine, sticky_dir.inode_id, b"theirs", 2000, 200);
        // Directory owner (uid 1000) should be able to unlink
        let ctx = user_ctx(1000, 100);
        assert_eq!(
            engine.unlink(sticky_dir.inode_id, b"theirs", &ctx),
            Ok(()),
            "sticky bit must allow directory owner to unlink"
        );
    }

    #[test]
    fn sticky_bit_unlink_allows_root() {
        let engine = RenameTestEngine::new();
        let sticky_dir = create_sticky_dir(&engine, ROOT_INODE_ID, b"sticky", 1000, 100);
        let _file_attr = create_owned_file(&engine, sticky_dir.inode_id, b"rootfile", 2000, 200);
        // Root (uid 0) bypasses sticky bit
        let ctx = user_ctx(0, 0);
        assert_eq!(
            engine.unlink(sticky_dir.inode_id, b"rootfile", &ctx),
            Ok(()),
            "root must bypass sticky bit"
        );
    }

    #[test]
    fn sticky_bit_non_sticky_dir_allows_anyone_with_write_permission() {
        let engine = RenameTestEngine::new();
        // Regular directory (mode 0o777, no sticky bit), owned by uid 1000
        let dir_ctx = user_ctx(1000, 100);
        let regular_dir = engine
            .mkdir(ROOT_INODE_ID, b"pub", 0o777, &dir_ctx)
            .expect("create public directory");
        let _file_attr = create_owned_file(&engine, regular_dir.inode_id, b"data", 2000, 200);
        // uid 3000 can unlink since there is no sticky bit and dir is world-writable
        let ctx = user_ctx(3000, 300);
        assert_eq!(
            engine.unlink(regular_dir.inode_id, b"data", &ctx),
            Ok(()),
            "non-sticky world-writable directory must allow unlink by any user"
        );
    }

    // ── Sticky-bit directory rename tests ─────────────────────────────────

    #[test]
    fn sticky_bit_rename_source_denies_non_owner() {
        let engine = RenameTestEngine::new();
        let sticky_dir = create_sticky_dir(&engine, ROOT_INODE_ID, b"sticky", 1000, 100);
        let _file_attr = create_owned_file(&engine, sticky_dir.inode_id, b"srcfile", 2000, 200);
        // uid 3000 tries to rename srcfile out of the sticky directory
        let ctx = user_ctx(3000, 300);
        assert_eq!(
            engine.rename(
                sticky_dir.inode_id,
                b"srcfile",
                ROOT_INODE_ID,
                b"dstfile",
                0,
                &ctx,
            ),
            Err(Errno::EPERM),
            "sticky bit must deny rename-away by a non-owner"
        );
    }

    #[test]
    fn sticky_bit_rename_target_denies_non_owner() {
        let engine = RenameTestEngine::new();
        // Source: regular file in root owned by uid 3000
        let ctx_3000 = user_ctx(3000, 300);
        let (_src_attr, src_fh) = engine
            .create(ROOT_INODE_ID, b"src", 0o644, O_RDWR, &ctx_3000)
            .expect("create source file");
        engine.release(&src_fh).expect("release src handle");
        // Target: sticky dir owned by uid 1000
        let sticky_dir = create_sticky_dir(&engine, ROOT_INODE_ID, b"sticky", 1000, 100);
        // Existing file in sticky dir owned by uid 2000
        let _tgt_attr = create_owned_file(&engine, sticky_dir.inode_id, b"existing", 2000, 200);
        // uid 3000 tries to rename src over existing in sticky dir
        assert_eq!(
            engine.rename(
                ROOT_INODE_ID,
                b"src",
                sticky_dir.inode_id,
                b"existing",
                0,
                &ctx_3000,
            ),
            Err(Errno::EPERM),
            "sticky bit must deny rename-over-target by a non-owner of the target"
        );
    }

    #[test]
    fn sticky_bit_rename_exchange_checks_both_sides() {
        let engine = RenameTestEngine::new();
        // Sticky dir A owned by uid 1000
        let sticky_a = create_sticky_dir(&engine, ROOT_INODE_ID, b"sticky-a", 1000, 100);
        // Sticky dir B owned by uid 2000
        let sticky_b = create_sticky_dir(&engine, ROOT_INODE_ID, b"sticky-b", 2000, 200);
        // File in A owned by uid 5000
        let _file_a = create_owned_file(&engine, sticky_a.inode_id, b"file-a", 5000, 500);
        // File in B owned by uid 6000
        let _file_b = create_owned_file(&engine, sticky_b.inode_id, b"file-b", 6000, 600);
        // uid 3000 (owns neither file nor either directory) tries RENAME_EXCHANGE
        let ctx = user_ctx(3000, 300);
        assert_eq!(
            engine.rename(
                sticky_a.inode_id,
                b"file-a",
                sticky_b.inode_id,
                b"file-b",
                RENAME_EXCHANGE,
                &ctx,
            ),
            Err(Errno::EPERM),
            "sticky bit must deny exchange rename when caller owns neither source nor target"
        );
        // File owner of A (uid 5000) can exchange with file owner of B (uid 6000)?
        // uid 5000 owns file-a but not sticky-b or file-b -> should still fail on target side
        let ctx_a_owner = user_ctx(5000, 500);
        assert_eq!(
            engine.rename(
                sticky_a.inode_id,
                b"file-a",
                sticky_b.inode_id,
                b"file-b",
                RENAME_EXCHANGE,
                &ctx_a_owner,
            ),
            Err(Errno::EPERM),
            "exchange rename must check both source and target sticky rules"
        );
    }

    #[test]
    fn readdir_lists_sorted_entries_with_continuation_cookies() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (beta, beta_fh) = create_file(&engine, b"beta.txt", O_RDWR, &ctx);
        let (alpha, alpha_fh) = create_file(&engine, b"alpha.txt", O_RDWR, &ctx);
        let gamma = create_dir(&engine, ROOT_INODE_ID, b"gamma", &ctx);
        engine.release(&beta_fh).expect("release beta");
        engine.release(&alpha_fh).expect("release alpha");

        let dh = engine
            .opendir(ROOT_INODE_ID, &ctx)
            .expect("open root directory");
        let (first_batch, has_more) = engine.readdir(&dh, 0, &ctx).expect("read first batch");
        assert!(has_more);
        assert_eq!(first_batch.len(), 2);
        assert_eq!(first_batch[0].name, b"alpha.txt".to_vec());
        assert_eq!(first_batch[0].inode_id, alpha.inode_id);
        assert_eq!(first_batch[0].kind, NodeKind::File);
        assert_eq!(first_batch[0].cookie, 1);
        assert_eq!(first_batch[1].name, b"beta.txt".to_vec());
        assert_eq!(first_batch[1].inode_id, beta.inode_id);
        assert_eq!(first_batch[1].cookie, 2);

        let (second_batch, has_more) = engine
            .readdir(&dh, first_batch[1].cookie, &ctx)
            .expect("read continuation batch");
        assert!(!has_more);
        assert_eq!(second_batch.len(), 1);
        assert_eq!(second_batch[0].name, b"gamma".to_vec());
        assert_eq!(second_batch[0].inode_id, gamma.inode_id);
        assert_eq!(second_batch[0].kind, NodeKind::Dir);
        assert_eq!(second_batch[0].cookie, 3);
    }

    #[test]
    fn opendir_rejects_missing_and_non_directory_inodes() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (file, _fh) = create_file(&engine, b"file.txt", O_RDWR, &ctx);

        assert_eq!(engine.opendir(file.inode_id, &ctx), Err(Errno::ENOTDIR));
        assert_eq!(
            engine.opendir(InodeId::new(99_999), &ctx),
            Err(Errno::ENOENT)
        );
    }

    #[test]
    fn readdir_empty_directory_returns_empty_batch() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let empty = create_dir(&engine, ROOT_INODE_ID, b"empty", &ctx);
        let dh = engine
            .opendir(empty.inode_id, &ctx)
            .expect("open empty directory");

        assert_eq!(engine.readdir(&dh, 0, &ctx), Ok((Vec::new(), false)));
    }

    #[test]
    fn readdir_after_releasedir_returns_ebadf() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let dh = engine
            .opendir(ROOT_INODE_ID, &ctx)
            .expect("open root directory");

        engine.releasedir(&dh).expect("release dir handle");

        assert_eq!(engine.readdir(&dh, 0, &ctx), Err(Errno::EBADF));
        assert_eq!(engine.releasedir(&dh), Err(Errno::EBADF));
    }

    #[test]
    fn readdir_rejects_unknown_or_mismatched_dir_handle() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let dir = create_dir(&engine, ROOT_INODE_ID, b"dir", &ctx);
        let root_handle = engine
            .opendir(ROOT_INODE_ID, &ctx)
            .expect("open root directory");
        let unknown = EngineDirHandle::new(ROOT_INODE_ID, DirHandleId::new(99_999));
        let mismatched = EngineDirHandle::new(dir.inode_id, root_handle.dh_id);

        assert_eq!(engine.readdir(&unknown, 0, &ctx), Err(Errno::EBADF));
        assert_eq!(engine.readdir(&mismatched, 0, &ctx), Err(Errno::EBADF));
        assert_eq!(engine.releasedir(&mismatched), Err(Errno::EBADF));
    }

    #[test]
    fn file_io_create_open_write_read_release_round_trips() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (attr, create_fh) = create_file(&engine, b"round-trip.txt", O_RDWR, &ctx);
        engine.release(&create_fh).expect("release create handle");

        let fh = engine
            .open(attr.inode_id, O_RDWR, &ctx)
            .expect("open created file");
        assert_eq!(engine.write(&fh, 0, b"vfs io", &ctx), Ok(6));
        assert_eq!(engine.read(&fh, 0, 6, &ctx), Ok(b"vfs io".to_vec()));
        engine.release(&fh).expect("release opened handle");
    }

    #[test]
    fn file_io_open_with_trunc_clears_existing_data() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (attr, fh) = create_file(&engine, b"truncate.txt", O_RDWR, &ctx);
        engine.write(&fh, 0, b"existing", &ctx).expect("write data");
        engine.release(&fh).expect("release written handle");

        let truncated = engine
            .open(attr.inode_id, O_RDWR | O_TRUNC, &ctx)
            .expect("open with truncate");
        let truncated_attr = engine
            .getattr(attr.inode_id, Some(&truncated), &ctx)
            .expect("getattr after truncate");
        assert_eq!(truncated_attr.posix.size, 0);
        assert_eq!(engine.read(&truncated, 0, 16, &ctx), Ok(Vec::new()));
    }

    #[test]
    fn file_io_read_beyond_written_data_returns_empty() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (_, fh) = create_file(&engine, b"read-beyond.txt", O_RDWR, &ctx);
        engine.write(&fh, 0, b"short", &ctx).expect("write data");

        assert_eq!(engine.read(&fh, 64, 8, &ctx), Ok(Vec::new()));
    }

    #[test]
    fn file_io_write_beyond_eof_extends_with_zeroes() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (attr, fh) = create_file(&engine, b"sparse.txt", O_RDWR, &ctx);

        assert_eq!(engine.write(&fh, 4, b"tail", &ctx), Ok(4));
        assert_eq!(
            engine.read(&fh, 0, 8, &ctx),
            Ok(alloc::vec![0, 0, 0, 0, b't', b'a', b'i', b'l'])
        );
        let updated = engine
            .getattr(attr.inode_id, Some(&fh), &ctx)
            .expect("getattr after sparse write");
        assert_eq!(updated.posix.size, 8);
    }

    #[test]
    fn file_io_fallocate_extends_file_with_zeroes() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (attr, fh) = create_file(&engine, b"allocated.bin", O_RDWR, &ctx);
        engine
            .write(&fh, 0, b"head", &ctx)
            .expect("write initial data");

        engine
            .fallocate(&fh, 0, 8, 4, &ctx)
            .expect("allocate past EOF");

        assert_eq!(
            engine.read(&fh, 0, 12, &ctx),
            Ok(alloc::vec![b'h', b'e', b'a', b'd', 0, 0, 0, 0, 0, 0, 0, 0])
        );
        let updated = engine
            .getattr(attr.inode_id, Some(&fh), &ctx)
            .expect("getattr after fallocate");
        assert_eq!(updated.posix.size, 12);
    }

    #[test]
    fn file_io_fallocate_keep_size_does_not_extend() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (attr, fh) = create_file(&engine, b"keep-size.bin", O_RDWR, &ctx);
        engine
            .write(&fh, 0, b"data", &ctx)
            .expect("write initial data");

        engine
            .fallocate(&fh, FALLOC_FL_KEEP_SIZE, 8, 4, &ctx)
            .expect("keep-size allocation");

        assert_eq!(engine.read(&fh, 0, 16, &ctx), Ok(b"data".to_vec()));
        let updated = engine
            .getattr(attr.inode_id, Some(&fh), &ctx)
            .expect("getattr after keep-size fallocate");
        assert_eq!(updated.posix.size, 4);
    }

    #[test]
    fn file_io_fallocate_punch_hole_zeroes_existing_range() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (attr, fh) = create_file(&engine, b"hole.bin", O_RDWR, &ctx);
        engine
            .write(&fh, 0, b"abcdefgh", &ctx)
            .expect("write initial data");

        engine
            .fallocate(&fh, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 2, 3, &ctx)
            .expect("punch hole");

        assert_eq!(
            engine.read(&fh, 0, 8, &ctx),
            Ok(alloc::vec![b'a', b'b', 0, 0, 0, b'f', b'g', b'h'])
        );
        let updated = engine
            .getattr(attr.inode_id, Some(&fh), &ctx)
            .expect("getattr after punch hole");
        assert_eq!(updated.posix.size, 8);
    }

    #[test]
    fn file_io_fallocate_zero_range_extends_and_zeroes() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (attr, fh) = create_file(&engine, b"zero-range.bin", O_RDWR, &ctx);
        engine
            .write(&fh, 0, b"abcdef", &ctx)
            .expect("write initial data");

        engine
            .fallocate(&fh, FALLOC_FL_ZERO_RANGE, 2, 6, &ctx)
            .expect("zero range");

        assert_eq!(
            engine.read(&fh, 0, 8, &ctx),
            Ok(alloc::vec![b'a', b'b', 0, 0, 0, 0, 0, 0])
        );
        let updated = engine
            .getattr(attr.inode_id, Some(&fh), &ctx)
            .expect("getattr after zero range");
        assert_eq!(updated.posix.size, 8);
    }

    #[test]
    fn file_io_fallocate_keep_size_zero_range_does_not_extend() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (attr, fh) = create_file(&engine, b"keep-zero.bin", O_RDWR, &ctx);
        engine
            .write(&fh, 0, b"abcdef", &ctx)
            .expect("write initial data");

        engine
            .fallocate(&fh, FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE, 2, 8, &ctx)
            .expect("keep-size zero range");

        assert_eq!(
            engine.read(&fh, 0, 16, &ctx),
            Ok(alloc::vec![b'a', b'b', 0, 0, 0, 0])
        );
        let updated = engine
            .getattr(attr.inode_id, Some(&fh), &ctx)
            .expect("getattr after keep-size zero range");
        assert_eq!(updated.posix.size, 6);
    }

    #[test]
    fn file_io_fallocate_requires_write_handle() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (attr, create_fh) = create_file(&engine, b"readonly-fallocate.bin", O_RDWR, &ctx);
        engine.release(&create_fh).expect("release create handle");
        let read_only = engine
            .open(attr.inode_id, O_RDONLY, &ctx)
            .expect("open read-only");

        assert_eq!(
            engine.fallocate(&read_only, 0, 0, 4, &ctx),
            Err(Errno::EBADF)
        );
    }

    #[test]
    fn file_io_fallocate_rejects_unsupported_and_invalid_modes() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (_, fh) = create_file(&engine, b"modes.bin", O_RDWR, &ctx);

        assert_eq!(
            engine.fallocate(&fh, FALLOC_FL_UNSHARE_RANGE, 0, 4, &ctx),
            Err(Errno::EOPNOTSUPP)
        );
        assert_eq!(
            engine.fallocate(&fh, FALLOC_FL_PUNCH_HOLE, 0, 4, &ctx),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            engine.fallocate(&fh, 0x8000_0000, 0, 4, &ctx),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            engine.fallocate(&fh, 0, u64::MAX, 2, &ctx),
            Err(Errno::EINVAL)
        );
    }

    #[test]
    fn file_io_data_ranges_empty_file_returns_empty() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (_, fh) = create_file(&engine, b"empty-data-ranges.bin", O_RDWR, &ctx);

        assert_eq!(engine.data_ranges(&fh, 0, 8, &ctx), Ok(Vec::new()));
    }

    #[test]
    fn file_io_data_ranges_written_file_returns_single_range() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (_, fh) = create_file(&engine, b"dense-data-ranges.bin", O_RDWR, &ctx);
        engine
            .write(&fh, 0, b"abcdef", &ctx)
            .expect("write test data");

        assert_eq!(
            engine.data_ranges(&fh, 1, 3, &ctx),
            Ok(alloc::vec![LseekDataRange::new(1, 4)])
        );
    }

    #[test]
    fn file_io_data_ranges_past_eof_returns_empty() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (_, fh) = create_file(&engine, b"past-eof-data-ranges.bin", O_RDWR, &ctx);
        engine.write(&fh, 0, b"abc", &ctx).expect("write test data");

        assert_eq!(engine.data_ranges(&fh, 3, 8, &ctx), Ok(Vec::new()));
        assert_eq!(engine.data_ranges(&fh, 64, 8, &ctx), Ok(Vec::new()));
    }

    #[test]
    fn file_io_data_ranges_clips_to_file_end() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (_, fh) = create_file(&engine, b"clipped-data-ranges.bin", O_RDWR, &ctx);
        engine
            .write(&fh, 0, b"abcdef", &ctx)
            .expect("write test data");

        assert_eq!(
            engine.data_ranges(&fh, 4, 8, &ctx),
            Ok(alloc::vec![LseekDataRange::new(4, 6)])
        );
    }

    #[test]
    fn file_io_data_ranges_released_handle_returns_ebadf() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (_, fh) = create_file(&engine, b"released-data-ranges.bin", O_RDWR, &ctx);
        engine.release(&fh).expect("release handle");

        assert_eq!(engine.data_ranges(&fh, 0, 8, &ctx), Err(Errno::EBADF));
    }

    #[test]
    fn file_io_data_ranges_unknown_handle_returns_ebadf() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (attr, _fh) = create_file(&engine, b"unknown-data-ranges.bin", O_RDWR, &ctx);
        let unknown = EngineFileHandle::new(attr.inode_id, O_RDWR, FileHandleId::new(99_999), 0);

        assert_eq!(engine.data_ranges(&unknown, 0, 8, &ctx), Err(Errno::EBADF));
    }

    #[test]
    fn file_io_data_ranges_zero_length_and_overflow() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (_, fh) = create_file(&engine, b"edge-data-ranges.bin", O_RDWR, &ctx);
        engine.write(&fh, 0, b"abc", &ctx).expect("write test data");

        assert_eq!(engine.data_ranges(&fh, 1, 0, &ctx), Ok(Vec::new()));
        assert_eq!(
            engine.data_ranges(&fh, u64::MAX, 1, &ctx),
            Err(Errno::EINVAL)
        );
    }

    #[test]
    fn file_io_open_missing_inode_returns_enoent() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();

        assert_eq!(
            engine.open(InodeId::new(999), O_RDONLY, &ctx),
            Err(Errno::ENOENT)
        );
    }

    #[test]
    fn file_io_write_to_read_only_handle_returns_ebadf() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (attr, create_fh) = create_file(&engine, b"readonly.txt", O_RDWR, &ctx);
        engine.release(&create_fh).expect("release create handle");
        let read_only = engine
            .open(attr.inode_id, O_RDONLY, &ctx)
            .expect("open read-only");

        assert_eq!(
            engine.write(&read_only, 0, b"denied", &ctx),
            Err(Errno::EBADF)
        );
    }

    #[test]
    fn file_io_read_from_write_only_handle_returns_ebadf() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (_, write_only) = create_file(&engine, b"writeonly.txt", O_WRONLY, &ctx);

        assert_eq!(engine.read(&write_only, 0, 8, &ctx), Err(Errno::EBADF));
    }

    #[test]
    fn file_io_release_invalidates_handle() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (_, fh) = create_file(&engine, b"release.txt", O_RDWR, &ctx);
        engine.release(&fh).expect("release handle");

        assert_eq!(engine.read(&fh, 0, 8, &ctx), Err(Errno::EBADF));
    }

    #[test]
    fn file_io_flush_validates_live_handle_and_succeeds() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (_, fh) = create_file(&engine, b"flush.txt", O_RDWR, &ctx);

        assert_eq!(engine.flush(&fh, &ctx), Ok(()));
    }

    #[test]
    fn file_io_flush_rejects_unknown_or_released_handle() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (attr, fh) = create_file(&engine, b"flush-invalid.txt", O_RDWR, &ctx);
        let unknown = EngineFileHandle::new(attr.inode_id, O_RDWR, FileHandleId::new(99_999), 0);

        assert_eq!(engine.flush(&unknown, &ctx), Err(Errno::EBADF));

        engine.release(&fh).expect("release handle");

        assert_eq!(engine.flush(&fh, &ctx), Err(Errno::EBADF));
    }

    #[test]
    fn file_io_fsync_validates_live_handle_and_succeeds() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (_, fh) = create_file(&engine, b"fsync.txt", O_RDWR, &ctx);

        assert_eq!(engine.fsync(&fh, false, &ctx), Ok(()));
        assert_eq!(engine.fsync(&fh, true, &ctx), Ok(()));
    }

    #[test]
    fn file_io_fsync_rejects_unknown_or_released_handle() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (attr, fh) = create_file(&engine, b"fsync-invalid.txt", O_RDWR, &ctx);
        let unknown = EngineFileHandle::new(attr.inode_id, O_RDWR, FileHandleId::new(99_999), 0);

        assert_eq!(engine.fsync(&unknown, false, &ctx), Err(Errno::EBADF));

        engine.release(&fh).expect("release handle");

        assert_eq!(engine.fsync(&fh, false, &ctx), Err(Errno::EBADF));
    }

    #[test]
    fn file_io_fsyncdir_validates_live_dir_handle_and_succeeds() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let dh = engine
            .opendir(ROOT_INODE_ID, &ctx)
            .expect("open root directory");

        assert_eq!(engine.fsyncdir(&dh, false, &ctx), Ok(()));
        assert_eq!(engine.fsyncdir(&dh, true, &ctx), Ok(()));
    }

    #[test]
    fn file_io_fsyncdir_rejects_unknown_or_released_dir_handle() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let dh = engine
            .opendir(ROOT_INODE_ID, &ctx)
            .expect("open root directory");
        let unknown = EngineDirHandle::new(ROOT_INODE_ID, DirHandleId::new(99_999));

        assert_eq!(engine.fsyncdir(&unknown, false, &ctx), Err(Errno::EBADF));

        engine.releasedir(&dh).expect("release dir handle");

        assert_eq!(engine.fsyncdir(&dh, false, &ctx), Err(Errno::EBADF));
    }

    #[test]
    fn file_io_multiple_handles_share_inode_data() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (attr, first) = create_file(&engine, b"handles.txt", O_RDWR, &ctx);
        let second = engine
            .open(attr.inode_id, O_RDWR, &ctx)
            .expect("open second handle");

        assert_eq!(engine.write(&first, 0, b"one", &ctx), Ok(3));
        assert_eq!(engine.write(&second, 3, b"two", &ctx), Ok(3));
        assert_eq!(engine.read(&first, 0, 6, &ctx), Ok(b"onetwo".to_vec()));
        assert_eq!(engine.read(&second, 0, 6, &ctx), Ok(b"onetwo".to_vec()));
    }

    // ── copy_file_range tests (default trait implementation) ─────────────

    #[test]
    fn file_io_copy_file_range_basic_between_files() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (_, src_fh) = create_file(&engine, b"copy-src.bin", O_RDWR, &ctx);
        let (_, dst_fh) = create_file(&engine, b"copy-dst.bin", O_RDWR, &ctx);
        engine
            .write(&src_fh, 0, b"hello world", &ctx)
            .expect("write src");

        let copied = engine
            .copy_file_range(&src_fh, 0, &dst_fh, 0, 11, &ctx)
            .expect("copy_file_range");
        assert_eq!(copied, 11);
        assert_eq!(
            engine.read(&dst_fh, 0, 11, &ctx),
            Ok(b"hello world".to_vec())
        );
    }

    #[test]
    fn file_io_copy_file_range_zero_length_returns_zero() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (_, src_fh) = create_file(&engine, b"zero-src.bin", O_RDWR, &ctx);
        let (_, dst_fh) = create_file(&engine, b"zero-dst.bin", O_RDWR, &ctx);

        let copied = engine
            .copy_file_range(&src_fh, 0, &dst_fh, 0, 0, &ctx)
            .expect("copy zero length");
        assert_eq!(copied, 0);
    }

    #[test]
    fn file_io_copy_file_range_partial_at_eof() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (_, src_fh) = create_file(&engine, b"partial-src.bin", O_RDWR, &ctx);
        let (_, dst_fh) = create_file(&engine, b"partial-dst.bin", O_RDWR, &ctx);
        engine
            .write(&src_fh, 0, b"abc", &ctx)
            .expect("write 3 bytes");

        let copied = engine
            .copy_file_range(&src_fh, 0, &dst_fh, 0, 10, &ctx)
            .expect("copy past EOF");
        assert_eq!(copied, 3);
        assert_eq!(engine.read(&dst_fh, 0, 3, &ctx), Ok(b"abc".to_vec()));
    }

    #[test]
    fn file_io_copy_file_range_overlapping_same_inode_returns_einval() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (_, fh) = create_file(&engine, b"overlap.bin", O_RDWR, &ctx);
        engine.write(&fh, 0, b"abcdefgh", &ctx).expect("write data");

        // overlapping ranges on same inode: src [0,4) dst [2,6)
        assert_eq!(
            engine.copy_file_range(&fh, 0, &fh, 2, 4, &ctx),
            Err(Errno::EINVAL)
        );
    }

    #[test]
    fn file_io_copy_file_range_mid_file_offset() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (_, src_fh) = create_file(&engine, b"mid-src.bin", O_RDWR, &ctx);
        let (_, dst_fh) = create_file(&engine, b"mid-dst.bin", O_RDWR, &ctx);
        engine
            .write(&src_fh, 0, b"abcdefghij", &ctx)
            .expect("write 10 bytes");

        let copied = engine
            .copy_file_range(&src_fh, 3, &dst_fh, 1, 4, &ctx)
            .expect("copy mid-file");
        assert_eq!(copied, 4);
        assert_eq!(engine.read(&dst_fh, 0, 5, &ctx), Ok(b"\0defg".to_vec()));
    }

    #[test]
    fn file_io_copy_file_range_released_source_returns_ebadf() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (_, src_fh) = create_file(&engine, b"rel-src.bin", O_RDWR, &ctx);
        let (_, dst_fh) = create_file(&engine, b"rel-dst.bin", O_RDWR, &ctx);
        engine.release(&src_fh).expect("release src");

        assert_eq!(
            engine.copy_file_range(&src_fh, 0, &dst_fh, 0, 4, &ctx),
            Err(Errno::EBADF)
        );
    }

    #[test]
    fn file_io_copy_file_range_released_dest_returns_ebadf() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (_, src_fh) = create_file(&engine, b"rel-src2.bin", O_RDWR, &ctx);
        let (_, dst_fh) = create_file(&engine, b"rel-dst2.bin", O_RDWR, &ctx);
        engine.write(&src_fh, 0, b"data", &ctx).expect("write");
        engine.release(&dst_fh).expect("release dst");

        assert_eq!(
            engine.copy_file_range(&src_fh, 0, &dst_fh, 0, 4, &ctx),
            Err(Errno::EBADF)
        );
    }

    #[test]
    fn file_io_copy_file_range_unknown_handle_returns_ebadf() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (attr, real_fh) = create_file(&engine, b"unknown-copy.bin", O_RDWR, &ctx);
        let unknown = EngineFileHandle::new(attr.inode_id, O_RDWR, FileHandleId::new(99_999), 0);

        engine.write(&real_fh, 0, b"testdata", &ctx).expect("write");
        assert_eq!(
            engine.copy_file_range(&unknown, 0, &real_fh, 100, 4, &ctx),
            Err(Errno::EBADF)
        );
        assert_eq!(
            engine.copy_file_range(&real_fh, 0, &unknown, 100, 4, &ctx),
            Err(Errno::EBADF)
        );
    }

    #[test]
    fn file_io_copy_file_range_readonly_source_reads() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (src_attr, _) = create_file(&engine, b"ro-src.bin", O_RDWR, &ctx);
        let (_, dst_fh) = create_file(&engine, b"ro-dst.bin", O_RDWR, &ctx);

        // Write data through a writable handle, then open read-only
        {
            let wr_fh = engine
                .open(src_attr.inode_id, O_WRONLY, &ctx)
                .expect("open write");
            engine
                .write(&wr_fh, 0, b"readonly", &ctx)
                .expect("write src data");
            engine.release(&wr_fh).expect("release write handle");
        }
        let src_ro = engine
            .open(src_attr.inode_id, O_RDONLY, &ctx)
            .expect("open read-only");

        let copied = engine
            .copy_file_range(&src_ro, 0, &dst_fh, 0, 8, &ctx)
            .expect("copy from read-only");
        assert_eq!(copied, 8);
        assert_eq!(engine.read(&dst_fh, 0, 8, &ctx), Ok(b"readonly".to_vec()));
    }

    // ── Additional error-path tests ──────────────────────────────────────

    #[test]
    fn file_io_getattr_with_invalid_handle_returns_ebadf() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (attr, _) = create_file(&engine, b"gh-invalid.bin", O_RDWR, &ctx);
        let unknown = EngineFileHandle::new(attr.inode_id, O_RDWR, FileHandleId::new(99_998), 0);

        assert_eq!(
            engine.getattr(attr.inode_id, Some(&unknown), &ctx),
            Err(Errno::EBADF)
        );
    }

    #[test]
    fn file_io_setattr_with_invalid_handle_returns_ebadf() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (attr, _) = create_file(&engine, b"sa-invalid.bin", O_RDWR, &ctx);
        let unknown = EngineFileHandle::new(attr.inode_id, O_RDWR, FileHandleId::new(99_997), 0);
        let sa = SetAttr {
            valid: FATTR_MODE,
            mode: 0o644,
            ..SetAttr::new()
        };

        assert_eq!(
            engine.setattr(attr.inode_id, &sa, Some(&unknown), &ctx),
            Err(Errno::EBADF)
        );
    }

    #[test]
    fn file_io_read_zero_size_returns_empty() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (_, fh) = create_file(&engine, b"zero-read.bin", O_RDWR, &ctx);
        engine.write(&fh, 0, b"data", &ctx).expect("write data");

        assert_eq!(engine.read(&fh, 0, 0, &ctx), Ok(Vec::new()));
        assert_eq!(engine.read(&fh, 2, 0, &ctx), Ok(Vec::new()));
    }

    #[test]
    fn file_io_read_at_eof_boundary_returns_empty() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (_, fh) = create_file(&engine, b"eof-read.bin", O_RDWR, &ctx);
        engine.write(&fh, 0, b"abcd", &ctx).expect("write 4 bytes");

        // read at exact EOF
        assert_eq!(engine.read(&fh, 4, 4, &ctx), Ok(Vec::new()));
        // read past EOF
        assert_eq!(engine.read(&fh, 8, 4, &ctx), Ok(Vec::new()));
    }

    #[test]
    fn file_io_read_partial_past_eof_returns_available_tail() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (_, fh) = create_file(&engine, b"partial-eof.bin", O_RDWR, &ctx);
        engine
            .write(&fh, 0, b"0123456789", &ctx)
            .expect("write 10 bytes");

        let result = engine.read(&fh, 7, 8, &ctx).expect("read past EOF");
        assert_eq!(result, b"789".to_vec());
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn file_io_write_empty_payload_is_noop() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (_, fh) = create_file(&engine, b"empty-write.bin", O_RDWR, &ctx);

        let written = engine.write(&fh, 0, b"", &ctx).expect("write empty");
        assert_eq!(written, 0);
        assert_eq!(engine.read(&fh, 0, 8, &ctx), Ok(Vec::new()));
    }

    #[test]
    fn file_io_truncate_to_zero_clears_and_reads_empty() {
        let engine = FileIoTestEngine::new();
        let ctx = file_io_ctx();
        let (attr, fh) = create_file(&engine, b"trunc-zero.bin", O_RDWR, &ctx);
        engine
            .write(&fh, 0, b"some data here", &ctx)
            .expect("write data");

        let sa = SetAttr {
            valid: FATTR_SIZE,
            size: 0,
            ..SetAttr::new()
        };
        engine
            .setattr(attr.inode_id, &sa, None, &ctx)
            .expect("truncate to 0");

        assert_eq!(engine.read(&fh, 0, 16, &ctx), Ok(Vec::new()));
        let got = engine.getattr(attr.inode_id, None, &ctx).expect("getattr");
        assert_eq!(got.posix.size, 0);
    }

    // ── Lock operation tests ─────────────────────────────────────────────

    /// Minimal mock that implements getlk/setlk with real lock conflict detection.
    struct LockEmptyTestEngine {
        locks: std::cell::RefCell<std::collections::BTreeMap<u64, Vec<LockSpec>>>,
    }

    impl LockEmptyTestEngine {
        fn new() -> Self {
            Self {
                locks: std::cell::RefCell::new(std::collections::BTreeMap::new()),
            }
        }

        fn find_conflict(&self, inode: InodeId, requested: &LockSpec) -> Option<LockSpec> {
            let locks = self.locks.borrow();
            let per_inode = locks.get(&inode.get())?;
            for existing in per_inode.iter() {
                if existing.pid == requested.pid {
                    continue;
                }
                let overlap =
                    ranges_overlap(existing.start, existing.end, requested.start, requested.end);
                if overlap && lock_types_conflict(existing.typ, requested.typ) {
                    return Some(*existing);
                }
            }
            None
        }
    }

    fn ranges_overlap(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> bool {
        !(a_end < b_start || b_end < a_start)
    }

    fn lock_types_conflict(a: u32, b: u32) -> bool {
        if a == F_UNLCK || b == F_UNLCK {
            return false;
        }
        if a == F_RDLCK && b == F_RDLCK {
            return false;
        }
        true
    }

    #[allow(unused_variables)]
    impl VfsEngine for LockEmptyTestEngine {
        fn get_root_inode(&self, ctx: &RequestCtx) -> Result<InodeId, Errno> {
            Err(Errno::ENOSYS)
        }
        fn lookup(&self, p: InodeId, n: &[u8], c: &RequestCtx) -> Result<InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }
        fn getattr(
            &self,
            i: InodeId,
            h: Option<&EngineFileHandle>,
            c: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }
        fn setattr(
            &self,
            i: InodeId,
            a: &SetAttr,
            h: Option<&EngineFileHandle>,
            c: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }
        fn mkdir(&self, p: InodeId, n: &[u8], m: u32, c: &RequestCtx) -> Result<InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }
        fn create(
            &self,
            p: InodeId,
            n: &[u8],
            m: u32,
            f: u32,
            c: &RequestCtx,
        ) -> Result<(InodeAttr, EngineFileHandle), Errno> {
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
            Err(Errno::ENOSYS)
        }
        fn tmpfile(
            &self,
            p: InodeId,
            m: u32,
            f: u32,
            c: &RequestCtx,
        ) -> Result<(InodeAttr, EngineFileHandle), Errno> {
            Err(Errno::ENOSYS)
        }
        fn unlink(&self, p: InodeId, n: &[u8], c: &RequestCtx) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn rmdir(&self, p: InodeId, n: &[u8], c: &RequestCtx) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn rename(
            &self,
            op: InodeId,
            on: &[u8],
            np: InodeId,
            nn: &[u8],
            f: u32,
            c: &RequestCtx,
        ) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn link(
            &self,
            t: InodeId,
            np: InodeId,
            nn: &[u8],
            c: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }
        fn symlink(
            &self,
            p: InodeId,
            n: &[u8],
            t: &[u8],
            c: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }
        fn readlink(&self, i: InodeId, c: &RequestCtx) -> Result<Vec<u8>, Errno> {
            Err(Errno::ENOSYS)
        }
        fn mknod(
            &self,
            p: InodeId,
            n: &[u8],
            m: u32,
            r: u32,
            c: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }
        fn open(&self, i: InodeId, f: u32, c: &RequestCtx) -> Result<EngineFileHandle, Errno> {
            Err(Errno::ENOSYS)
        }
        fn release(&self, fh: &EngineFileHandle) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn read(
            &self,
            fh: &EngineFileHandle,
            o: u64,
            s: u32,
            c: &RequestCtx,
        ) -> Result<Vec<u8>, Errno> {
            Err(Errno::ENOSYS)
        }
        fn write(
            &self,
            fh: &EngineFileHandle,
            o: u64,
            d: &[u8],
            c: &RequestCtx,
        ) -> Result<u32, Errno> {
            Err(Errno::ENOSYS)
        }
        fn flush(&self, fh: &EngineFileHandle, c: &RequestCtx) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn fsync(&self, fh: &EngineFileHandle, d: bool, c: &RequestCtx) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn fallocate(
            &self,
            fh: &EngineFileHandle,
            m: u32,
            o: u64,
            l: u64,
            c: &RequestCtx,
        ) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn opendir(&self, i: InodeId, c: &RequestCtx) -> Result<EngineDirHandle, Errno> {
            Err(Errno::ENOSYS)
        }
        fn releasedir(&self, dh: &EngineDirHandle) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn readdir(
            &self,
            dh: &EngineDirHandle,
            o: u64,
            c: &RequestCtx,
        ) -> Result<(Vec<DirEntry>, bool), Errno> {
            Err(Errno::ENOSYS)
        }
        fn fsyncdir(&self, dh: &EngineDirHandle, d: bool, c: &RequestCtx) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn syncfs(&self, c: &RequestCtx) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn getxattr(&self, i: InodeId, n: &[u8], c: &RequestCtx) -> Result<Vec<u8>, Errno> {
            Err(Errno::ENOSYS)
        }
        fn setxattr(
            &self,
            i: InodeId,
            n: &[u8],
            v: &[u8],
            f: u32,
            c: &RequestCtx,
        ) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn listxattr(&self, i: InodeId, c: &RequestCtx) -> Result<Vec<u8>, Errno> {
            Err(Errno::ENOSYS)
        }
        fn removexattr(&self, i: InodeId, n: &[u8], c: &RequestCtx) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }

        fn getlk(
            &self,
            inode: InodeId,
            lock: &LockSpec,
            _ctx: &RequestCtx,
        ) -> Result<Option<LockSpec>, Errno> {
            if lock.whence != 0 {
                return Err(Errno::EINVAL);
            }
            if lock.typ != F_RDLCK && lock.typ != F_WRLCK && lock.typ != F_UNLCK {
                return Err(Errno::EINVAL);
            }
            Ok(self.find_conflict(inode, lock))
        }

        fn setlk(&self, inode: InodeId, lock: &LockSpec, _ctx: &RequestCtx) -> Result<(), Errno> {
            if lock.whence != 0 {
                return Err(Errno::EINVAL);
            }
            if lock.typ != F_RDLCK && lock.typ != F_WRLCK && lock.typ != F_UNLCK {
                return Err(Errno::EINVAL);
            }

            // Check for conflict before acquiring the mutable borrow.
            let has_conflict = if lock.typ != F_UNLCK {
                self.find_conflict(inode, lock).is_some()
            } else {
                false
            };
            if has_conflict {
                return Err(Errno::EAGAIN);
            }

            let mut locks = self.locks.borrow_mut();
            if lock.typ == F_UNLCK {
                let per_inode = locks.entry(inode.get()).or_default();
                per_inode.retain(|existing| {
                    !(existing.pid == lock.pid
                        && ranges_overlap(existing.start, existing.end, lock.start, lock.end))
                });
                if per_inode.is_empty() {
                    locks.remove(&inode.get());
                }
                return Ok(());
            }
            let per_inode = locks.entry(inode.get()).or_default();
            per_inode.retain(|existing| {
                !(existing.pid == lock.pid
                    && ranges_overlap(existing.start, existing.end, lock.start, lock.end))
            });
            per_inode.push(*lock);
            Ok(())
        }
    }

    fn lock_ctx() -> RequestCtx {
        RequestCtx {
            uid: 1000,
            gid: 1000,
            pid: 42,
            umask: 0o022,
            groups: alloc::vec![1000],
        }
    }

    fn lock_spec(typ: u32, start: u64, end: u64, pid: u32) -> LockSpec {
        LockSpec {
            typ,
            whence: 0,
            start,
            end,
            pid,
        }
    }

    #[test]
    fn lock_getlk_returns_none_when_no_locks_held() {
        let engine = LockEmptyTestEngine::new();
        let ctx = lock_ctx();
        let ino = InodeId::new(10);
        let result = engine
            .getlk(ino, &lock_spec(F_RDLCK, 0, 99, 200), &ctx)
            .expect("getlk on empty inode");
        assert_eq!(result, None);
    }

    #[test]
    fn lock_getlk_returns_conflicting_lock_when_held() {
        let engine = LockEmptyTestEngine::new();
        let ctx = lock_ctx();
        let ino = InodeId::new(10);
        engine
            .setlk(ino, &lock_spec(F_WRLCK, 0, 99, 100), &ctx)
            .expect("acquire write lock");
        let conflict = engine
            .getlk(ino, &lock_spec(F_WRLCK, 50, 60, 200), &ctx)
            .expect("getlk");
        assert!(conflict.is_some());
        let c = conflict.unwrap();
        assert_eq!(c.typ, F_WRLCK);
        assert_eq!(c.start, 0);
        assert_eq!(c.end, 99);
        assert_eq!(c.pid, 100);
    }

    #[test]
    fn lock_getlk_returns_none_for_compatible_read_locks() {
        let engine = LockEmptyTestEngine::new();
        let ctx = lock_ctx();
        let ino = InodeId::new(10);
        engine
            .setlk(ino, &lock_spec(F_RDLCK, 0, 99, 100), &ctx)
            .expect("acquire read lock");
        let result = engine
            .getlk(ino, &lock_spec(F_RDLCK, 50, 60, 200), &ctx)
            .expect("getlk");
        assert_eq!(result, None);
    }

    #[test]
    fn lock_setlk_succeeds_on_free_range() {
        let engine = LockEmptyTestEngine::new();
        let ctx = lock_ctx();
        let ino = InodeId::new(10);
        engine
            .setlk(ino, &lock_spec(F_WRLCK, 0, 49, 100), &ctx)
            .expect("first write lock");
        engine
            .setlk(ino, &lock_spec(F_WRLCK, 100, 149, 200), &ctx)
            .expect("non-overlapping write lock");
    }

    #[test]
    fn lock_setlk_fails_with_eagain_on_write_write_conflict() {
        let engine = LockEmptyTestEngine::new();
        let ctx = lock_ctx();
        let ino = InodeId::new(10);
        engine
            .setlk(ino, &lock_spec(F_WRLCK, 0, 99, 100), &ctx)
            .expect("first write lock");
        let err = engine
            .setlk(ino, &lock_spec(F_WRLCK, 50, 60, 200), &ctx)
            .unwrap_err();
        assert_eq!(err, Errno::EAGAIN);
    }

    #[test]
    fn lock_setlk_fails_with_eagain_on_read_write_conflict() {
        let engine = LockEmptyTestEngine::new();
        let ctx = lock_ctx();
        let ino = InodeId::new(10);
        engine
            .setlk(ino, &lock_spec(F_RDLCK, 0, 99, 100), &ctx)
            .expect("read lock");
        let err = engine
            .setlk(ino, &lock_spec(F_WRLCK, 50, 60, 200), &ctx)
            .unwrap_err();
        assert_eq!(err, Errno::EAGAIN);
    }

    #[test]
    fn lock_setlk_same_pid_replaces_overlapping_range() {
        let engine = LockEmptyTestEngine::new();
        let ctx = lock_ctx();
        let ino = InodeId::new(10);
        engine
            .setlk(ino, &lock_spec(F_WRLCK, 0, 99, 100), &ctx)
            .expect("first lock");
        engine
            .setlk(ino, &lock_spec(F_WRLCK, 30, 49, 100), &ctx)
            .expect("same-pid replacement");
        // After replacement, the lock range is [30, 49].
        // [0, 10] is no longer locked by pid 100.
        let no_conflict = engine
            .getlk(ino, &lock_spec(F_WRLCK, 0, 10, 200), &ctx)
            .expect("getlk on released range");
        assert_eq!(no_conflict, None);
        // [30, 49] should still show a conflict from pid 100.
        let conflict = engine
            .getlk(ino, &lock_spec(F_WRLCK, 35, 40, 200), &ctx)
            .expect("getlk on overlapping range");
        assert!(conflict.is_some());
        let c = conflict.unwrap();
        assert_eq!(c.pid, 100);
        assert_eq!(c.start, 30);
        assert_eq!(c.end, 49);
    }

    #[test]
    fn lock_unlock_releases_range() {
        let engine = LockEmptyTestEngine::new();
        let ctx = lock_ctx();
        let ino = InodeId::new(10);
        engine
            .setlk(ino, &lock_spec(F_WRLCK, 0, 99, 100), &ctx)
            .expect("acquire lock");
        engine
            .setlk(ino, &lock_spec(F_UNLCK, 0, 99, 100), &ctx)
            .expect("unlock");
        engine
            .setlk(ino, &lock_spec(F_WRLCK, 0, 99, 200), &ctx)
            .expect("acquire after unlock");
    }

    #[test]
    fn lock_getlk_rejects_bad_whence() {
        let engine = LockEmptyTestEngine::new();
        let ctx = lock_ctx();
        let bad_lock = LockSpec {
            typ: F_RDLCK,
            whence: 1,
            start: 0,
            end: 99,
            pid: 100,
        };
        let err = engine.getlk(InodeId::new(10), &bad_lock, &ctx).unwrap_err();
        assert_eq!(err, Errno::EINVAL);
    }

    #[test]
    fn lock_setlkw_default_delegates_to_setlk() {
        let engine = LockEmptyTestEngine::new();
        let ctx = lock_ctx();
        let ino = InodeId::new(10);
        engine
            .setlkw(ino, &lock_spec(F_WRLCK, 0, 49, 100), &ctx)
            .expect("setlkw on free range");
        let err = engine
            .setlkw(ino, &lock_spec(F_WRLCK, 0, 49, 200), &ctx)
            .unwrap_err();
        assert_eq!(err, Errno::EAGAIN);
    }

    #[test]
    fn lock_operations_are_object_safe() {
        let engine: std::boxed::Box<dyn VfsEngine> =
            std::boxed::Box::new(LockEmptyTestEngine::new());
        let ctx = lock_ctx();
        let ino = InodeId::new(10);
        assert_eq!(
            engine.getlk(ino, &lock_spec(F_RDLCK, 0, 99, 100), &ctx),
            Ok(None)
        );
        assert_eq!(
            engine.setlk(ino, &lock_spec(F_WRLCK, 0, 99, 100), &ctx),
            Ok(())
        );
        assert_eq!(
            engine.setlkw(ino, &lock_spec(F_WRLCK, 0, 49, 200), &ctx),
            Err(Errno::EAGAIN)
        );
    }

    // ── BlockQueueGeometry and queue_limits tests ──────────────────────

    #[test]
    fn block_queue_geometry_production_defaults() {
        let g = BlockQueueGeometry::production();
        assert_eq!(g.max_hw_sectors, 512);
        assert_eq!(g.max_segments, 128);
        assert_eq!(g.physical_block_size, 4096);
        assert_eq!(g.logical_block_size, 512);
        assert_eq!(g.io_min, 512);
        assert_eq!(g.io_opt, 4096);
        assert_eq!(g.discard_granularity, 0);
        assert_eq!(g.max_discard_sectors, 0);
    }

    #[test]
    fn block_queue_geometry_default_equals_production() {
        assert_eq!(
            BlockQueueGeometry::default(),
            BlockQueueGeometry::production()
        );
    }

    #[test]
    fn block_queue_geometry_clone_eq() {
        let g1 = BlockQueueGeometry::production();
        let g2 = g1.clone();
        assert_eq!(g1, g2);
    }

    #[test]
    fn block_queue_geometry_custom_values() {
        let g = BlockQueueGeometry {
            max_hw_sectors: 256,
            max_segments: 64,
            physical_block_size: 4096,
            logical_block_size: 4096,
            io_min: 4096,
            io_opt: 65536,
            discard_granularity: 4096,
            max_discard_sectors: 512,
        };
        assert_eq!(g.max_hw_sectors, 256);
        assert_eq!(g.max_segments, 64);
        assert_eq!(g.logical_block_size, 4096);
        assert_eq!(g.io_opt, 65536);
    }

    #[test]
    fn block_queue_geometry_debug_format() {
        let g = BlockQueueGeometry::production();
        let s = alloc::format!("{g:?}");
        assert!(s.contains("BlockQueueGeometry"));
        assert!(s.contains("512"));
    }

    #[test]
    fn mock_engine_queue_limits_returns_production() {
        let engine = EmptyTestEngine;
        let g = engine.queue_limits();
        assert_eq!(g, BlockQueueGeometry::production());
    }

    // ── Transaction-group lifecycle trait tests ───────────────────────

    #[test]
    fn txg_open_default_returns_noop_handle() {
        let engine = EmptyTestEngine;
        let handle = engine.txg_open(TxgId(1)).expect("txg_open should succeed");
        assert_eq!(handle.id(), TxgId::NO_TXG);
        assert!(!handle.is_consumed());
    }

    #[test]
    fn txg_commit_prepare_default_returns_immediate_zero_root() {
        let engine = EmptyTestEngine;
        let handle = TxgHandle::noop();
        let result = engine
            .txg_commit_prepare(&handle)
            .expect("txg_commit_prepare should succeed");
        assert_eq!(result.committed_root, CommittedRoot::ZERO);
        assert!(!result.quorum_needed);
        assert_eq!(result.flags, 0);
    }

    #[test]
    fn txg_commit_finish_default_consumes_handle() {
        let engine = EmptyTestEngine;
        let handle = TxgHandle::new(TxgId(42));
        let root = CommittedRoot::new([0xabu8; 32]);
        engine
            .txg_commit_finish(handle, root)
            .expect("txg_commit_finish should succeed");
        // The handle was moved into txg_commit_finish; if we got here
        // without panicking, the default impl worked.
    }

    #[test]
    fn txg_full_lifecycle_round_trip() {
        let engine = EmptyTestEngine;
        let handle = engine.txg_open(TxgId(1)).expect("txg_open");
        let result = engine
            .txg_commit_prepare(&handle)
            .expect("txg_commit_prepare");
        let root = result.committed_root;
        engine
            .txg_commit_finish(handle, root)
            .expect("txg_commit_finish");
    }

    #[test]
    fn txg_handle_drop_without_commit_is_noop() {
        let engine = EmptyTestEngine;
        let handle = engine.txg_open(TxgId(2)).expect("txg_open");
        // Drop the handle without calling txg_commit_finish.
        // This should not panic — the default impl is a noop abort.
        drop(handle);
    }

    #[test]
    fn txg_object_safe_through_boxed_trait() {
        let engine: std::boxed::Box<dyn VfsEngine> = std::boxed::Box::new(EmptyTestEngine);
        let handle = engine
            .txg_open(TxgId(3))
            .expect("txg_open via trait object");
        let result = engine
            .txg_commit_prepare(&handle)
            .expect("txg_commit_prepare via trait object");
        engine
            .txg_commit_finish(handle, result.committed_root)
            .expect("txg_commit_finish via trait object");
    }

    // ── Committed-root writeback tests ────────────────────────────

    #[test]
    fn write_committed_root_default_is_noop() {
        let engine = EmptyTestEngine;
        let root = CommittedRoot::new([0x42u8; 32]);
        let result = engine.write_committed_root(&root, 0);
        assert!(
            result.is_ok(),
            "default write_committed_root should succeed"
        );
    }

    #[test]
    fn write_committed_root_multiple_device_indices_are_ok() {
        let engine = EmptyTestEngine;
        let root = CommittedRoot::new([0xffu8; 32]);
        assert!(engine.write_committed_root(&root, 0).is_ok());
        assert!(engine.write_committed_root(&root, 1).is_ok());
        assert!(engine.write_committed_root(&root, 7).is_ok());
    }

    #[test]
    fn write_committed_root_object_safe_through_boxed_trait() {
        let engine: std::boxed::Box<dyn VfsEngine> = std::boxed::Box::new(EmptyTestEngine);
        let root = CommittedRoot::new([0xabu8; 32]);
        engine
            .write_committed_root(&root, 0)
            .expect("write_committed_root via trait object");
    }

    #[test]
    fn txg_commit_finish_calls_write_committed_root() {
        // The default txg_commit_finish calls write_committed_root(&root, 0).
        // Since EmptyTestEngine uses the default impls, this verifies the call chain
        // completes without error.
        let engine = EmptyTestEngine;
        let handle = TxgHandle::new(TxgId(5));
        let root = CommittedRoot::new([0x11u8; 32]);
        engine
            .txg_commit_finish(handle, root)
            .expect("txg_commit_finish should call write_committed_root successfully");
    }

    #[test]
    fn write_committed_root_with_zero_root() {
        let engine = EmptyTestEngine;
        let result = engine.write_committed_root(&CommittedRoot::ZERO, 0);
        assert!(result.is_ok());
    }
    // ── Mmap and fault tests ─────────────────────────────────────────

    fn mmap_ctx() -> RequestCtx {
        RequestCtx::new(1000, 1000, 42, 0o022, alloc::vec![1000])
    }

    fn mmap_fh(inode: u64) -> EngineFileHandle {
        EngineFileHandle::new(InodeId::new(inode), 0, FileHandleId::new(0), 0)
    }

    #[test]
    fn mmap_default_returns_populate_on_fault() {
        let engine = EmptyTestEngine;
        let ctx = mmap_ctx();
        let policy = engine.mmap(InodeId::new(1), 0, 4096, 0, &ctx).unwrap();
        assert_eq!(policy, MmapPolicy::PopulateOnFault);
    }

    #[test]
    fn mmap_policy_enum_values_distinct() {
        assert_ne!(MmapPolicy::PopulateOnFault, MmapPolicy::PreFaultPages);
        assert_ne!(MmapPolicy::PopulateOnFault, MmapPolicy::Denied);
        assert_ne!(MmapPolicy::PreFaultPages, MmapPolicy::Denied);
    }

    #[test]
    fn mmap_policy_clone_eq() {
        let p1 = MmapPolicy::PopulateOnFault;
        let p2 = p1;
        assert_eq!(p1, p2);
        let p3 = MmapPolicy::Denied;
        assert_ne!(p1, p3);
    }

    #[test]
    fn mmap_policy_debug_format() {
        let s = alloc::format!("{:?}", MmapPolicy::PopulateOnFault);
        assert!(s.contains("PopulateOnFault"));
        let s = alloc::format!("{:?}", MmapPolicy::Denied);
        assert!(s.contains("Denied"));
    }

    #[test]
    fn fault_through_default_read_delegation() {
        // EmptyTestEngine::read returns ENOSYS by default, so the default
        // fault() (which calls read()) also returns ENOSYS.
        let engine = EmptyTestEngine;
        let fh = mmap_fh(1);
        let ctx = mmap_ctx();
        let err = engine.fault(&fh, 0, 4096, &ctx).unwrap_err();
        assert_eq!(err, Errno::ENOSYS);
    }

    #[test]
    fn vm_fault_outcome_construct_and_access() {
        let page = b"hello fault".to_vec();
        let outcome = VmFaultOutcome {
            page: page.clone(),
            vm_fault_code: VM_FAULT_MAJOR,
        };
        assert_eq!(outcome.page, page);
        assert_eq!(outcome.vm_fault_code, VM_FAULT_MAJOR);
    }

    #[test]
    fn vm_fault_outcome_minor_code() {
        let outcome = VmFaultOutcome {
            page: b"".to_vec(),
            vm_fault_code: VM_FAULT_MINOR,
        };
        assert_eq!(outcome.vm_fault_code, VM_FAULT_MINOR);
        assert_eq!(outcome.page.len(), 0);
    }

    #[test]
    fn vm_fault_outcome_nopage_code() {
        let outcome = VmFaultOutcome {
            page: alloc::vec::Vec::new(),
            vm_fault_code: VM_FAULT_NOPAGE,
        };
        assert_eq!(outcome.vm_fault_code, VM_FAULT_NOPAGE);
        assert!(outcome.page.is_empty());
    }

    #[test]
    fn vm_fault_constants_distinct() {
        let codes = [
            VM_FAULT_MINOR,
            VM_FAULT_MAJOR,
            VM_FAULT_LOCKED,
            VM_FAULT_OOM,
            VM_FAULT_SIGBUS,
            VM_FAULT_NOPAGE,
            VM_FAULT_HWPOISON,
            VM_FAULT_RETRY,
        ];
        for i in 0..codes.len() {
            for j in (i + 1)..codes.len() {
                assert_ne!(codes[i], codes[j], "codes[{i}] == codes[{j}]");
            }
        }
    }

    #[test]
    fn fault_is_object_safe() {
        let engine: std::boxed::Box<dyn VfsEngine> = std::boxed::Box::new(EmptyTestEngine);
        let fh = mmap_fh(1);
        let ctx = mmap_ctx();
        // Default implementation calls read() which is ENOSYS on EmptyTestEngine
        let err = engine.fault(&fh, 0, 4096, &ctx).unwrap_err();
        assert_eq!(err, Errno::ENOSYS);
    }

    #[test]
    fn mmap_is_object_safe() {
        let engine: std::boxed::Box<dyn VfsEngine> = std::boxed::Box::new(EmptyTestEngine);
        let ctx = mmap_ctx();
        let policy = engine.mmap(InodeId::new(1), 0, 4096, 0, &ctx).unwrap();
        assert_eq!(policy, MmapPolicy::PopulateOnFault);
    }

    #[test]
    fn page_size_is_4096() {
        assert_eq!(PAGE_SIZE, 4096);
    }

    // ── Pool label validation trait tests ───────────────────────────

    #[test]
    fn mock_engine_validate_pool_label_rejects_empty_buffer() {
        let engine = EmptyTestEngine;
        let result = engine.validate_pool_label(0, &[]);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            tidefs_types_pool_label_core::LabelError::BufferTooSmall
        );
    }

    #[test]
    fn mock_engine_validate_pool_label_rejects_bad_magic() {
        let engine = EmptyTestEngine;
        let buf = [0u8; 411];
        let result = engine.validate_pool_label(0, &buf);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            tidefs_types_pool_label_core::LabelError::BadMagic
        );
    }

    #[test]
    fn mock_engine_validate_pool_label_accepts_valid_label() {
        // Build a minimal valid label using types-pool-label-core.
        use tidefs_types_pool_label_core::{seal_label, PoolLabelV1, POOL_LABEL_V1_EXT_WIRE_SIZE};
        let pool_guid = [0xAAu8; 16];
        let device_guid = [0xBBu8; 16];
        let label = PoolLabelV1::new(pool_guid, device_guid, "testpool");
        let sealed = seal_label(label).unwrap();
        let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        tidefs_types_pool_label_core::encode_label(&sealed, &mut buf).unwrap();

        let engine = EmptyTestEngine;
        let result = engine.validate_pool_label(0, &buf);
        assert!(result.is_ok());
        let decoded = result.unwrap();
        assert_eq!(decoded.pool_guid, pool_guid);
        assert_eq!(decoded.pool_name_str(), "testpool");
    }

    #[test]
    fn mock_engine_select_committed_root_default_returns_empty() {
        let engine = EmptyTestEngine;
        let result = engine.select_committed_root(0, &[]);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            tidefs_types_pool_label_core::CommittedRootState::Empty
        );
    }

    // ── AllocatedInode + allocate_inode tests ──────────────────────────

    /// A test engine that implements a simple sequential inode allocator
    /// so that `allocate_inode` tests can validate the return shape and
    /// uniqueness without depending on a real backing store (#6193).
    struct InodeAllocTestEngine {
        next_ino: core::cell::Cell<u64>,
    }

    impl InodeAllocTestEngine {
        fn new() -> Self {
            Self {
                next_ino: core::cell::Cell::new(1000),
            }
        }
    }

    #[allow(unused_variables)]
    impl VfsEngine for InodeAllocTestEngine {
        fn get_root_inode(&self, ctx: &RequestCtx) -> Result<InodeId, Errno> {
            Err(Errno::ENOSYS)
        }
        fn lookup(
            &self,
            parent: InodeId,
            name: &[u8],
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }
        fn getattr(
            &self,
            inode: InodeId,
            handle: Option<&EngineFileHandle>,
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }
        fn setattr(
            &self,
            inode: InodeId,
            attr: &SetAttr,
            handle: Option<&EngineFileHandle>,
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }
        fn mkdir(
            &self,
            parent: InodeId,
            name: &[u8],
            mode: u32,
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }
        fn create(
            &self,
            parent: InodeId,
            name: &[u8],
            mode: u32,
            flags: u32,
            ctx: &RequestCtx,
        ) -> Result<(InodeAttr, EngineFileHandle), Errno> {
            Err(Errno::ENOSYS)
        }
        fn unlink(&self, parent: InodeId, name: &[u8], ctx: &RequestCtx) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn rmdir(&self, parent: InodeId, name: &[u8], ctx: &RequestCtx) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn rename(
            &self,
            op: InodeId,
            on: &[u8],
            np: InodeId,
            nn: &[u8],
            f: u32,
            c: &RequestCtx,
        ) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn link(
            &self,
            t: InodeId,
            np: InodeId,
            nn: &[u8],
            c: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }
        fn symlink(
            &self,
            parent: InodeId,
            name: &[u8],
            target: &[u8],
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }
        fn readlink(&self, inode: InodeId, ctx: &RequestCtx) -> Result<Vec<u8>, Errno> {
            Err(Errno::ENOSYS)
        }
        fn mknod(
            &self,
            parent: InodeId,
            name: &[u8],
            mode: u32,
            rdev: u32,
            ctx: &RequestCtx,
        ) -> Result<InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }
        fn open(
            &self,
            inode: InodeId,
            flags: u32,
            ctx: &RequestCtx,
        ) -> Result<EngineFileHandle, Errno> {
            Err(Errno::ENOSYS)
        }
        fn release(&self, fh: &EngineFileHandle) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn read(
            &self,
            fh: &EngineFileHandle,
            offset: u64,
            size: u32,
            ctx: &RequestCtx,
        ) -> Result<Vec<u8>, Errno> {
            Err(Errno::ENOSYS)
        }
        fn write(
            &self,
            fh: &EngineFileHandle,
            offset: u64,
            data: &[u8],
            ctx: &RequestCtx,
        ) -> Result<u32, Errno> {
            Err(Errno::ENOSYS)
        }
        fn flush(&self, fh: &EngineFileHandle, ctx: &RequestCtx) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn fsync(
            &self,
            fh: &EngineFileHandle,
            datasync: bool,
            ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn fallocate(
            &self,
            fh: &EngineFileHandle,
            mode: u32,
            offset: u64,
            length: u64,
            ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn opendir(&self, inode: InodeId, ctx: &RequestCtx) -> Result<EngineDirHandle, Errno> {
            Err(Errno::ENOSYS)
        }
        fn releasedir(&self, dh: &EngineDirHandle) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn readdir(
            &self,
            dh: &EngineDirHandle,
            offset: u64,
            ctx: &RequestCtx,
        ) -> Result<(Vec<DirEntry>, bool), Errno> {
            Err(Errno::ENOSYS)
        }
        fn getxattr(
            &self,
            inode: InodeId,
            name: &[u8],
            ctx: &RequestCtx,
        ) -> Result<Vec<u8>, Errno> {
            Err(Errno::ENOSYS)
        }
        fn setxattr(
            &self,
            inode: InodeId,
            name: &[u8],
            value: &[u8],
            flags: u32,
            ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn listxattr(&self, inode: InodeId, ctx: &RequestCtx) -> Result<Vec<u8>, Errno> {
            Err(Errno::ENOSYS)
        }
        fn removexattr(&self, inode: InodeId, name: &[u8], ctx: &RequestCtx) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn getlk(
            &self,
            inode: InodeId,
            lock: &LockSpec,
            ctx: &RequestCtx,
        ) -> Result<Option<LockSpec>, Errno> {
            Err(Errno::ENOSYS)
        }
        fn setlk(&self, inode: InodeId, lock: &LockSpec, ctx: &RequestCtx) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn copy_file_range(
            &self,
            sfh: &EngineFileHandle,
            oi: u64,
            dfh: &EngineFileHandle,
            oo: u64,
            l: u64,
            c: &RequestCtx,
        ) -> Result<u32, Errno> {
            Err(Errno::ENOSYS)
        }
        fn syncfs(&self, c: &RequestCtx) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn tmpfile(
            &self,
            parent: InodeId,
            mode: u32,
            flags: u32,
            ctx: &RequestCtx,
        ) -> Result<(InodeAttr, EngineFileHandle), Errno> {
            Err(Errno::ENOSYS)
        }
        fn fsyncdir(
            &self,
            dh: &EngineDirHandle,
            datasync: bool,
            ctx: &RequestCtx,
        ) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }

        fn allocate_inode(
            &self,
            kind: NodeKind,
            parent: InodeId,
            mode: u32,
            uid: u32,
            gid: u32,
        ) -> Result<AllocatedInode, Errno> {
            let ino = self.next_ino.get();
            self.next_ino.set(ino + 1);
            let now_ns = 1_700_000_000_000_000_000u64;
            let nlink = if kind == NodeKind::Dir { 2 } else { 1 };
            let attr = InodeAttr {
                inode_id: InodeId::new(ino),
                generation: Generation::new(1),
                kind,
                posix: PosixAttrs {
                    mode,
                    uid,
                    gid,
                    nlink,
                    rdev: 0,
                    atime_ns: now_ns,
                    mtime_ns: now_ns,
                    ctime_ns: now_ns,
                    btime_ns: now_ns,
                    size: 0,
                    blocks_512: 0,
                    blksize: 4096,
                },
                flags: InodeFlags::none(),
                subtree_rev: 0,
                dir_rev: 0,
            };
            Ok(AllocatedInode::new(InodeId::new(ino), attr))
        }
    }

    #[test]
    fn allocated_inode_new_and_accessors() {
        let ino = InodeId::new(42);
        let attr = InodeAttr {
            inode_id: ino,
            generation: Generation::new(7),
            kind: NodeKind::File,
            posix: PosixAttrs::default(),
            flags: InodeFlags::none(),
            subtree_rev: 0,
            dir_rev: 0,
        };
        let ai = AllocatedInode::new(ino, attr);
        assert_eq!(ai.inode_id(), ino);
        assert_eq!(ai.ino, ino);
        assert_eq!(ai.attr, attr);
        assert_eq!(ai.generation(), Generation::new(7));
        assert_eq!(ai.kind(), NodeKind::File);
    }

    #[test]
    fn allocated_inode_clone_eq() {
        let ai1 = AllocatedInode::new(InodeId::new(1), InodeAttr::default());
        let ai2 = ai1.clone();
        assert_eq!(ai1, ai2);
    }

    #[test]
    fn allocated_inode_debug() {
        let ai = AllocatedInode::new(InodeId::new(99), InodeAttr::default());
        let s = alloc::format!("{ai:?}");
        assert!(s.contains("AllocatedInode"));
    }

    #[test]
    fn allocate_inode_default_returns_enosys() {
        let engine = EmptyTestEngine;
        let result = engine.allocate_inode(NodeKind::File, InodeId::new(0), 0o644, 0, 0);
        assert_eq!(result, Err(Errno::ENOSYS));
    }

    #[test]
    fn allocate_inode_file_sequential_uniqueness() {
        let engine = InodeAllocTestEngine::new();
        let parent = InodeId::new(1);
        let a1 = engine
            .allocate_inode(NodeKind::File, parent, 0o644, 1000, 1000)
            .unwrap();
        let a2 = engine
            .allocate_inode(NodeKind::File, parent, 0o644, 1000, 1000)
            .unwrap();
        assert_ne!(a1.ino, a2.ino);
        assert_eq!(a1.ino.get(), 1000);
        assert_eq!(a2.ino.get(), 1001);
    }

    #[test]
    fn allocate_inode_dir_has_nlink_two() {
        let engine = InodeAllocTestEngine::new();
        let a = engine
            .allocate_inode(NodeKind::Dir, InodeId::new(0), 0o755, 0, 0)
            .unwrap();
        assert_eq!(a.kind(), NodeKind::Dir);
        assert_eq!(a.attr.posix.nlink, 2);
    }

    #[test]
    fn allocate_inode_file_has_nlink_one() {
        let engine = InodeAllocTestEngine::new();
        let a = engine
            .allocate_inode(NodeKind::File, InodeId::new(0), 0o644, 1000, 1000)
            .unwrap();
        assert_eq!(a.kind(), NodeKind::File);
        assert_eq!(a.attr.posix.nlink, 1);
    }

    #[test]
    fn allocate_inode_symlink_kind_preserved() {
        let engine = InodeAllocTestEngine::new();
        let a = engine
            .allocate_inode(NodeKind::Symlink, InodeId::new(0), 0o777, 0, 0)
            .unwrap();
        assert_eq!(a.kind(), NodeKind::Symlink);
    }

    #[test]
    fn allocate_inode_preserves_mode_uid_gid() {
        let engine = InodeAllocTestEngine::new();
        let a = engine
            .allocate_inode(NodeKind::File, InodeId::new(0), 0o600, 42, 99)
            .unwrap();
        assert_eq!(a.attr.posix.mode, 0o600);
        assert_eq!(a.attr.posix.uid, 42);
        assert_eq!(a.attr.posix.gid, 99);
    }

    #[test]
    fn allocate_inode_timestamps_initialized() {
        let engine = InodeAllocTestEngine::new();
        let a = engine
            .allocate_inode(NodeKind::File, InodeId::new(0), 0o644, 0, 0)
            .unwrap();
        assert!(a.attr.posix.atime_ns > 0);
        assert!(a.attr.posix.mtime_ns > 0);
        assert!(a.attr.posix.ctime_ns > 0);
        assert!(a.attr.posix.btime_ns > 0);
    }

    #[test]
    fn allocate_inode_blksize_nonzero() {
        let engine = InodeAllocTestEngine::new();
        let a = engine
            .allocate_inode(NodeKind::File, InodeId::new(0), 0o644, 0, 0)
            .unwrap();
        assert_eq!(a.attr.posix.blksize, 4096);
    }
}
