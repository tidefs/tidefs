#![cfg_attr(not(CONFIG_RUST), no_std)]
#![forbid(unsafe_code)]

//! # Safety: callback registration and pointer-lifetime contract
//!
//! This crate implements the Linux VFS kernel callback surface
//! (`file_operations`, `inode_operations`, `super_operations`) for the
//! TideFS kernel module.  Every public dispatch function in this crate is
//! designed to be registered as a kernel C callback via the `module!` macro
//! in the Kbuild environment (K7-02).
//!
//! When registered as kernel callbacks, the following invariants apply:
//!
//! - **ABI match**: The function signature must match the kernel's expected
//!   `struct file_operations` / `struct inode_operations` /
//!   `struct super_operations` layout exactly.  Signature mismatch is
//!   undefined behavior and is caught only at Kbuild link time (not at
//!   Cargo compile time).
//!
//! - **Opaque-pointer lifetime**: Kernel pointers (`super_block *`,
//!   `inode *`, `dentry *`, `file *`, `folio *`) passed into callbacks are
//!   valid only for the callback duration.  The kernel VFS guarantees this
//!   through reference counting and VFS locking.  Any opaque pointer
//!   constructed via `Opaque*::from_ptr()` must cite the specific kernel
//!   guarantee (e.g., `igrab`/`dget` ref count, or VFS lock held) in a
//!   `// SAFETY:` comment.
//!
//! - **Lock discipline**: Lock acquisitions inside callbacks must declare a
//!   `KernelLockClass` variant from the kmod-bridge and respect the
//!   canonical P7-03 lockdep partial order.  Callbacks running in RCU
//!   read-sections or under spinlocks must not sleep.
//!
//! - **No hidden authority**: In full-kernel mode (no FUSE daemon, no ublk
//!   control thread), these callbacks must not require a userspace process
//!   for normal operation.  Authority-gated operations must dispatch through
//!   a kernel-resident path or record a precise blocker.
//!
//! This crate currently uses `#![forbid(unsafe_code)]` because all raw-pointer
//! construction is deferred to the kmod-bridge substrate.  When real Kbuild
//! registration is wired, the `forbid` may relax to
//! `#![deny(unsafe_op_in_unsafe_fn)]` at the registration sites.

//! Mounted-kernel directory lookup and readdir validation belongs in Linux 7.0
//! QEMU validation, not crate-local mock harnesses.
//! TideFS kernel POSIX VFS adapter — clean-read namespace seam (K7-05).
//!
//! This crate implements the first legal kernel seam:
//! `seam.kernel_module_0.posix_filesystem_adapter.namespace_cleanread.s0`
//! (P7-01 §6).
//!
//! It sits at stratum s3 / c7, consuming the kmod-bridge (s2 / c6) and
//! delegating all operations to the canonical [`VfsEngine`] trait. The
//! kernel module is a projection mirror, not a hidden authority.
//!
//! # Scope (in)
//! - mount/super admission via get_root_inode + statfs
//! - lookup with negative dentry tracking
//! - getattr with generation validation
//! - opendir / readdir / releasedir
//! - read (file data read) with offset and size
//! - open / release with handle tracking
//! - readahead hint forwarding with active page-cache population tracking
//! - fadvise (no-op advisory hint) with posix_fadvise(2) compatibility
//! - statx field rendering from InodeAttr
//! - kernel module registration via kmod-bridge traits
//! - permission (inode_permission) access-control check

//!
//! - create (file creation) with inode allocation delegation
//! - create_excl (exclusive file creation, O_EXCL|O_CREAT)
//! - link (hard-link creation) with nlink accounting delegation
//! - mkdir (directory creation) with mode validation and POSIX errno mapping
//! - setattr (truncate, chmod, chown, utimes) with attribute mutation
//! - write (file data write) with offset and data
//! - flush (per-fd dirty-data push) with VfsEngine delegation
//! - update_time (atime/mtime/ctime timestamp updates)
//! - rmdir (directory removal) with name validation
//! - symlink (symbolic link creation) with intent-log crash safety
//! - readlink (symlink target resolution)
//! - mknod (device node, FIFO, socket creation) with rdev
//! - rename (atomic rename with RENAME_NOREPLACE and RENAME_EXCHANGE)
//! - xattr (getxattr, setxattr, listxattr, removexattr) delegation
//! - fallocate (space reservation, hole punch, zero, collapse, insert)
//! - llseek (SEEK_DATA/SEEK_HOLE extent resolution) with VfsEngine::data_ranges() delegation
//! - fsync / fsyncdir (file and directory durability flush)
//! - lock (getlk, setlk) advisory byte-range locking
//! - copy_file_range (server-side copy) delegation -- K7-20
//! - statfs (filesystem statistics: total/free blocks/inodes, block size, name max)
//! - tmpfile (O_TMPFILE unnamed temporary file creation)
//! - syncfs (filesystem-wide synchronization to stable storage)
//! - readdir (directory iteration) with dirent64 kernel-format packing -- K7-23
//! - super_operations (fill_super, kill_sb, statfs) mount lifecycle dispatch
//! - mount_lifecycle state machine with BLAKE3-verified superblock state integrity
//! - C address_space_operations callbacks for mounted read/writeback, plus Rust
//!   source-model dispatch spines for future direct vm_ops/a_ops bridge work
//! - sync_fs (per-superblock writeback flush, C shim + Rust bridge)
//! - show_options (/proc/mounts display, C shim)
//! - umount_begin (async unmount initiation, C shim)
//! # Scope (out)

//! - ACL / ioctl
//! - reflink / remap_file_range (explicit EOPNOTSUPP refusal; see #6646)
//! - freeze / thaw / remount
#[cfg(not(CONFIG_RUST))]
extern crate alloc;
// Under Kbuild, tidefs_kmod_bridge is a module at the crate root.
// Under cargo, it is an extern crate (Cargo.toml dependency).
#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

// Kernel-compatible Vec alias.
// Under cargo: alloc::vec::Vec.  Under Kbuild: wraps kernel::alloc::KVec.
#[allow(unused_imports)]
pub(crate) use tidefs_kmod_bridge::kernel_types::KmodBox as TideBox;
pub(crate) use tidefs_kmod_bridge::kernel_types::KmodString as TideString;
pub(crate) use tidefs_kmod_bridge::kernel_types::KmodVec as TideVec;

pub mod address_space_ops;
pub mod bridge;
pub mod copy_file_range;
pub mod create;
pub mod create_excl;
pub mod dir;
pub mod dir_cursor;
pub mod dir_ops_bridge;
pub mod errno;
pub mod fadvise;
pub mod fallocate;
pub mod file;
pub mod flush;
pub mod fsync;
pub mod getattr;
pub mod inode;
pub mod intent_replay;
#[cfg(not(CONFIG_RUST))]
pub mod kernel_env_model;
pub mod kernel_mount;
pub mod kernel_xattr_bridge;
pub mod link;
pub mod live_data_allocator;
pub mod llseek;
pub mod lock;
pub mod mkdir;
pub mod mknod;
pub mod mmap;
pub mod mount;
pub mod mount_lifecycle;
pub mod mount_options;
pub mod permission;
pub mod read;
pub mod readahead;
pub mod readdir;
pub mod rename;
pub mod replay_integration;
pub mod rmdir;
pub mod setattr;
pub mod statfs;
pub mod statx;
pub mod super_operations;
pub mod superblock;
pub mod symlink;
pub mod syncfs;
pub mod tmpfile;
pub mod unlink;
pub mod write;
pub mod writeback;
pub mod xattr;

pub mod update_time;

pub use create::CreatePlan;
pub use extent_ops::AllocateExtentsPlan;
pub use fallocate::FallocateMode;
pub use fallocate::FallocatePlan;
pub use inode::LookupPlan;
pub use link::LinkPlan;
pub use mkdir::MkdirPlan;
pub use mount_options::EngineAuthorityMode;
pub use mount_options::FeatureFlags;
pub use rename::RenameArgs;
pub use rename::RenamePlan;
pub use rename::{RENAME_EXCHANGE, RENAME_NOREPLACE, RENAME_WHITEOUT};
pub use rmdir::RmdirPlan;
pub use setattr::SetattrPlan;
pub use symlink::SymlinkPlan;
pub use tidefs_kmod_bridge::kernel_types::{WritebackOutcome, WritebackRange};
pub use unlink::UnlinkPlan;

#[cfg(test)]
pub mod test_util;

pub mod blake3_guard;
mod concurrent_stress;
pub mod extent_ops;
pub mod extent_ops_bridge;
pub mod intent_record;
pub mod no_daemon_residency;
pub mod open_release;
pub mod page_authority;

use tidefs_kmod_bridge::kernel_types::VfsEngine;
use tidefs_kmod_bridge::kernel_types::{EngineDirHandle, EngineFileHandle, InodeId};

/// Context for a mounted TideFS kernel filesystem instance.
pub struct KmodPosixVfs<E> {
    engine: E,
    /// Parsed mount options populated during fill_super.
    pub mount_options: mount_options::MountOptions,
    /// Runtime authority-mode disclosure (set after mount).
    pub authority_mode: mount_options::EngineAuthorityMode,
    /// Monotonic generation counter. Incremented on remount.
    generation: u64,
    /// Kernel page-cache statistics tracker for parity validation (K7-06).
    pub page_cache: readahead::KmodPageCacheTracker,
    /// Rust source-model dirty-folio tracker.
    ///
    /// The mounted C shim uses Linux dirty accounting and C `writepages`;
    /// this tracker is not registered as mounted product callback state.
    pub dirty_folio_tracker: writeback::DirtyFolioTracker,
    /// Rust source-model page-cache ownership table.
    ///
    /// The mounted product path does not call this table from C
    /// `vm_operations_struct` or `address_space_operations` callbacks.
    pub page_authority: page_authority::PageAuthorityTable,
    /// Bridge registration handle (None until kmod_init succeeds).
    pub registration: Option<bridge::KmodRegistration>,
    /// Intent-log recorder for kernel-side mutation durability.
    /// Constructed during mount once KernelStorageIo is available;
    /// None when intent recording is disabled or not yet initialized.
    #[cfg(not(CONFIG_RUST))]
    pub intent_recorder: core::cell::RefCell<Option<intent_record::KernelIntentRecorder>>,
}

impl<E> KmodPosixVfs<E> {
    pub fn new(engine: E) -> Self {
        Self {
            engine,
            mount_options: mount_options::MountOptions::default(),
            authority_mode: mount_options::EngineAuthorityMode::Unspecified,
            generation: 0,
            page_cache: readahead::KmodPageCacheTracker::new(),
            dirty_folio_tracker: writeback::DirtyFolioTracker::new(1024),
            page_authority: page_authority::PageAuthorityTable::default_production(),
            registration: None,
            #[cfg(not(CONFIG_RUST))]
            intent_recorder: core::cell::RefCell::new(None),
        }
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Parse and store mount options during fill_super.
    ///
    /// Accepts the comma-separated option string from the kernel VFS
    /// mount(2) system call and stores the parsed configuration.
    pub fn parse_mount_options(
        &mut self,
        option_string: &str,
    ) -> Result<(), mount_options::MountOptionError> {
        let opts = mount_options::MountOptions::parse(option_string)?;
        self.authority_mode = opts.authority_mode;
        self.mount_options = opts;
        Ok(())
    }
}

impl<E: VfsEngine> KmodPosixVfs<E> {
    pub fn engine(&self) -> &E {
        &self.engine
    }

    /// Construct a source-model [`AddressSpaceOps`] dispatch spine.
    ///
    /// Borrows the VfsEngine, page-cache tracker, dirty-folio tracker,
    /// and page-authority table mutably, returning an `AddressSpaceOps`
    /// that can dispatch `read_folio`, `readahead`, and all implemented
    /// operations (`write_begin`, `write_end`, `dirty_folio`,
    /// `writepages`, `writepage`, `page_mkwrite`, `invalidate_folio`).
    /// The returned ops carry mutable borrows on `self.page_cache`,
    /// `self.dirty_folio_tracker`, and `self.page_authority` for source-model
    /// per-operation statistics, writeback tracking, and page-cache ownership
    /// arbitration respectively.
    ///
    /// # Kernel wiring
    ///
    /// During `fill_super`/`inode_init`, the kernel module sets the
    /// address_space_operations vtable on each inode:
    ///
    /// ```c
    /// inode->i_mapping->a_ops = &tidefs_address_space_ops;
    /// ```
    ///
    /// The mounted C shim currently registers its own C vtable and calls
    /// Rust engine bridge exports directly for the callbacks it wires. A
    /// future direct C-to-Rust vtable bridge may delegate each function
    /// pointer to [`AddressSpaceOps`], but the live mounted path must not be
    /// documented as doing that until the bridge is registered.
    ///
    /// This method returns the Rust source-model dispatch spine only. The
    /// mounted C shim's registered vtable is the product authority until a
    /// direct C-to-Rust a_ops bridge is added.
    ///
    /// # No-daemon boundary
    ///
    /// All modeled aops operations resolve locally through VfsEngine. See
    /// [`AddressSpaceOps`] for per-operation daemon-boundary disclosure and
    /// mounted-callback limits.
    pub fn address_space_ops(&mut self) -> crate::address_space_ops::AddressSpaceOps<'_, E> {
        crate::address_space_ops::AddressSpaceOps::new(
            &self.engine,
            &mut self.page_cache,
            &mut self.dirty_folio_tracker,
            &mut self.page_authority,
        )
    }
}

/// A pending negative dentry — lookup failed with ENOENT.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NegativeDentry {
    pub parent: InodeId,
    pub name: crate::TideVec<u8>,
    pub generation: u64,
}

/// Outcome of lookup: either a found inode or a negative dentry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LookupResult {
    Found(tidefs_kmod_bridge::kernel_types::InodeAttr),
    Negative(NegativeDentry),
}

/// State for an open file handle within the kernel adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenFileState {
    pub handle: EngineFileHandle,
    pub inode: InodeId,
    pub flags: u32,
}

/// State for an open directory handle within the kernel adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenDirState {
    pub handle: EngineDirHandle,
    pub inode: InodeId,
}
