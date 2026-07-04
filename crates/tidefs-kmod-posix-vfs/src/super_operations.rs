// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Super_operations dispatch for the kernel VFS adapter.
//!
//! Implements the Linux 7.0 kernel `super_operations` contract:
//! `fill_super`, `kill_sb`, `statfs`, `evict_inode`, and `free_inode`.
//! These bridge the kernel VFS mount lifecycle to VfsEngine initialization,
//! teardown, capacity queries, inode eviction, and slab deallocation; plus
//! `address_space_operations` vtable attachment during inode creation.
//!
//! # Current Status
//!
//! Wired super_operations (C shim, with Rust bridge where applicable):
//! - `show_options` -- mount option display for /proc/mounts, wired in
//!   `tidefs_posix_vfs_show_options` (C shim line 4393); reports
//!   bootstrap/engine-backed, ro/rw, debug, commit_timeout_ms, recovery.
//! - `sync_fs` -- wired in `tidefs_posix_vfs_sync_fs` (C shim line 4073);
//!   bridges to Rust via `tidefs_posix_vfs_engine_sync_fs`.
//! - `umount_begin` -- wired in `tidefs_posix_vfs_umount_begin` (C shim
//!   line 4235); initiates async unmount with lifecycle tracking.
//! - `put_super` -- wired in `tidefs_posix_vfs_put_super` (C shim line 4142).
//!
//! Explicitly deferred:
//! - `shutdown` / `FS_IOC_GOINGDOWN` -- not registered in the C-shim
//!   `super_operations` table. Linux's shutdown callback cannot return an
//!   errno, so registration is withheld until TideFS can quiesce writes,
//!   refuse new mutation, and prove no-work-after-shutdown.
//! - `freeze_fs` / `unfreeze_fs` -- filesystem freeze/thaw not implemented;
//!   the C shim registers callbacks that return EOPNOTSUPP instead of
//!   pretending dirty/writeback state reached a coherent frozen state.
//! - remount reconfiguration -- remount with updated mount options not
//!   implemented; the C shim returns EOPNOTSUPP from the Linux 7.0
//!   `fs_context_operations.reconfigure` hook rather than silently accepting
//!   option changes or ro/rw toggles that TideFS did not apply.
//!
//! # Eviction Lifecycle (REL-KVFS-009)
//!
//! The inode eviction path is wired in the C shim
//! (`tidefs_posix_vfs_evict_inode` / `tidefs_posix_vfs_free_inode`) and
//! completes the dentry/inode lifecycle gap:
//!
//! 1. **open-unlink**: `tidefs_posix_vfs_unlink` removes the directory entry
//!    and calls `clear_nlink(inode)`, marking the inode as deleted (nlink=0).
//! 2. **last close**: When the last file descriptor closes, the kernel
//!    drops its reference. If nlink==0, the VFS calls `evict_inode`.
//! 3. **evict_inode**: Truncates remaining page-cache pages via
//!    `truncate_inode_pages_final`, calls `clear_inode`, and logs the
//!    eviction (tracking orphan evictions separately for open-unlink
//!    lifecycle validation).
//! 4. **free_inode**: Called after eviction completes; currently a no-op
//!    since the module uses the kernel's default slab allocator for
//!    `struct inode` rather than a custom `tidefs_inode_info` wrapper.
//! 5. **umount**: `kill_sb` now reports `evict_inode_calls` and
//!    `evict_orphan_calls` in the lifecycle summary log.
//!

//!
//! # Address Space Operations Wiring
//!
//! During the kernel VFS `fill_super` path, the filesystem must attach the
//! `address_space_operations` vtable to each inode's `i_mapping->a_ops`.
//! This is done in the inode initialization callback (`inode_init` or
//! `alloc_inode`) provided by the kernel module.
//!
//! The wiring pattern in kernel C code:
//!
//! ```c
//! static int tidefs_inode_init(struct inode *inode, void *data) {
//!     inode->i_mapping->a_ops = &tidefs_address_space_ops;
//!     return 0;
//! }
//! ```
//!
//! The `tidefs_address_space_ops` vtable function pointers each delegate
//! to the corresponding method on [`crate::address_space_ops::AddressSpaceOps`]
//! via the kmod-bridge substrate.
//!
//! In the userspace model, [`KmodPosixVfs::address_space_ops`] constructs an
//! [`AddressSpaceOps`] dispatch spine. This is the userspace-model analogue
//! of the kernel inode_init callback: callers constructing an inode should
//! call this method to obtain the aops spine for wiring into the inode's
//! mapping.
#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

use crate::TideString as String;
use crate::TideVec as Vec;

use crate::address_space_ops::AddressSpaceOps;
use crate::superblock::{mount_validate, MountError, MountResult};
use crate::writeback::DirtyFolioTracker;
use crate::KmodPosixVfs;
use tidefs_kmod_bridge::kernel_types::{
    EngineFileHandle, Errno, FileHandleId, InodeId, RequestCtx, StatFs, WritebackRange,
};
use tidefs_kmod_bridge::kernel_types::{VfsEngine, VfsEngineStatFs};

/// Administrative superblock operations tracked by the mounted-kernel policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdministrativeSuperOperation {
    /// Linux `FS_IOC_GOINGDOWN` / `super_operations.shutdown`.
    Shutdown,
    /// Linux filesystem freeze entry point.
    FreezeFs,
    /// Linux filesystem thaw entry point.
    UnfreezeFs,
    /// Linux remount-with-new-options entry point.
    RemountFs,
}

/// How the C shim exposes the operation to Linux VFS today.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdministrativeSuperOperationKernelPath {
    /// The callback is deliberately absent so Linux reports unsupported.
    UnregisteredUnsupported,
    /// A `super_operations` callback is registered only to return a refusal.
    SuperOperationRefusalCallback,
    /// A `fs_context_operations.reconfigure` callback refuses remount.
    FsContextReconfigureRefusal,
}

/// Support status for an administrative superblock operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdministrativeSuperOperationSupport {
    /// The operation is an implemented product capability.
    Supported,
    /// The operation is not a TideFS product capability yet.
    Unsupported,
}

/// Typed status for an administrative superblock operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdministrativeSuperOperationPolicy {
    pub operation: AdministrativeSuperOperation,
    pub support: AdministrativeSuperOperationSupport,
    pub kernel_path: AdministrativeSuperOperationKernelPath,
    pub errno: Errno,
    pub reason: &'static str,
}

impl AdministrativeSuperOperationPolicy {
    const fn unsupported(
        operation: AdministrativeSuperOperation,
        kernel_path: AdministrativeSuperOperationKernelPath,
        reason: &'static str,
    ) -> Self {
        Self {
            operation,
            support: AdministrativeSuperOperationSupport::Unsupported,
            kernel_path,
            errno: Errno::EOPNOTSUPP,
            reason,
        }
    }

    /// Return true when this operation is an implemented product capability.
    pub const fn is_supported(self) -> bool {
        match self.support {
            AdministrativeSuperOperationSupport::Supported => true,
            AdministrativeSuperOperationSupport::Unsupported => false,
        }
    }
}

/// Return the mounted-kernel product policy for an administrative operation.
pub const fn administrative_super_operation_policy(
    operation: AdministrativeSuperOperation,
) -> AdministrativeSuperOperationPolicy {
    match operation {
        AdministrativeSuperOperation::Shutdown => AdministrativeSuperOperationPolicy::unsupported(
            operation,
            AdministrativeSuperOperationKernelPath::UnregisteredUnsupported,
            "FS_IOC_GOINGDOWN is withheld until quiesce and no-new-work shutdown exists",
        ),
        AdministrativeSuperOperation::FreezeFs => AdministrativeSuperOperationPolicy::unsupported(
            operation,
            AdministrativeSuperOperationKernelPath::SuperOperationRefusalCallback,
            "freeze cannot claim coherent dirty/writeback state yet",
        ),
        AdministrativeSuperOperation::UnfreezeFs => {
            AdministrativeSuperOperationPolicy::unsupported(
                operation,
                AdministrativeSuperOperationKernelPath::SuperOperationRefusalCallback,
                "thaw is unsupported because TideFS never enters frozen state",
            )
        }
        AdministrativeSuperOperation::RemountFs => AdministrativeSuperOperationPolicy::unsupported(
            operation,
            AdministrativeSuperOperationKernelPath::FsContextReconfigureRefusal,
            "remount option changes are refused through fs_context reconfigure instead of silently ignored",
        ),
    }
}

/// Refuse an administrative operation through the typed policy status.
pub fn refuse_administrative_super_operation(
    operation: AdministrativeSuperOperation,
) -> Result<(), Errno> {
    Err(administrative_super_operation_policy(operation).errno)
}

/// fill_super: Initialize the kernel VFS superblock from the backing device.
///
/// This is the entry point for the Linux kernel VFS mount path. It:
/// 1. Opens the backing device through VfsEngine
/// 2. Reads and validates the superblock metadata
/// 3. Replays the committed-root with BLAKE3-256 verification
/// 4. Constructs the root inode for the VFS dentry tree
///
/// On success, returns a [`MountResult`] containing the root inode id,
/// validated superblock parameters, and the BLAKE3-committed-root anchor.
///
/// # Safety (kernel callback ABI)
///
/// The kernel VFS guarantees the super_block pointer is valid and exclusive
/// for the call duration.  This function must validate the on-disk superblock
/// before returning success; a corrupted or mismatched superblock must return
/// [`MountError`] rather than mounting a broken filesystem.
pub fn fill_super<E: VfsEngine + VfsEngineStatFs>(
    engine: &E,
    ctx: &RequestCtx,
    expected_uuid: Option<&[u8; 32]>,
    expected_root_digest: Option<&[u8; 32]>,
    committed_txg: u64,
) -> Result<MountResult, MountError> {
    mount_validate(
        engine,
        ctx,
        expected_uuid,
        expected_root_digest,
        committed_txg,
    )
}

/// kill_sb: Teardown the kernel superblock with dirty-state flush.
///
/// Called by the kernel VFS on unmount. When a
/// [`DirtyFolioTracker`] is provided, drains all tracked dirty ranges
/// through [`VfsEngine::writeback_folios`] before calling
/// [`VfsEngine::syncfs`] to complete superblock teardown.  Writeback
/// errors propagate to the caller and prevent a clean teardown from
/// being reported.  The engine is responsible for releasing
/// backing-device resources and marking the superblock clean.
///
/// Unsupported `syncfs` is propagated for mounted filesystems so kernel
/// teardown cannot report clean durability without pool authority.
///
/// # Safety (kernel callback ABI)
///
/// The kernel VFS guarantees no new file operations will be admitted on
/// this superblock.  After `kill_sb` returns, the kernel frees the
/// superblock; this function must not retain references to it.
pub fn kill_sb<E: VfsEngine>(
    engine: &E,
    ctx: &RequestCtx,
    tracker: Option<&mut DirtyFolioTracker>,
) -> Result<(), Errno> {
    if let Some(tracker) = tracker {
        // Build inode list manually: KmodVec does not implement
        // FromIterator, so collect() fails in the kernel build.
        let mut dirty_inodes: Vec<InodeId> = Vec::new();
        for (ino, _) in tracker.iter() {
            dirty_inodes.push(ino);
        }
        for inode in dirty_inodes {
            let ranges = tracker.drain_inode(inode);
            for (idx, range) in ranges.iter().enumerate() {
                let wb_range = WritebackRange::new(range.offset, range.length as u64);
                let fh = EngineFileHandle::new(inode, 0, FileHandleId::default(), 0);
                let outcome = match engine.writeback_folios(inode, &fh, wb_range, ctx) {
                    Ok(outcome) => outcome,
                    Err(err) => {
                        tracker.redirty_unwritten(inode, &ranges, idx, 0)?;
                        return Err(err);
                    }
                };
                if !outcome.complete || outcome.bytes_written < wb_range.length {
                    tracker.redirty_unwritten(inode, &ranges, idx, outcome.bytes_written)?;
                    return Err(Errno::EIO);
                }
            }
        }
    }
    engine.syncfs(ctx)
}

/// statfs: Query filesystem capacity statistics.
///
/// Returns total/free blocks, total/free inodes, block size, maximum
/// filename length, and filesystem id. Equivalent to the Linux `statfs(2)`
/// and `statvfs(2)` system calls, fed through the VfsEngine capacity path.
pub fn statfs<E: VfsEngineStatFs>(engine: &E, ctx: &RequestCtx) -> Result<StatFs, Errno> {
    engine.statfs(ctx)
}

/// inode_init_aops: Construct the AddressSpaceOps dispatch spine for
/// wiring into a new inode's `i_mapping->a_ops`.
///
/// This is the userspace-model analogue of the kernel inode_init callback.
/// During `fill_super`, for each inode created, the kernel module calls
/// this to obtain the `AddressSpaceOps` that will be attached to the
/// inode's address_space mapping.
///
/// # Kernel wiring
///
/// In the real kernel module, the aops vtable is set once in the
/// `inode_init` callback:
///
/// ```c
/// inode->i_mapping->a_ops = &tidefs_address_space_ops;
/// ```
///
/// Each vtable function pointer delegates to the corresponding
/// [`AddressSpaceOps`] method through the kmod-bridge substrate.
///
/// # No-daemon boundary
///
/// All implemented aops operations resolve within kernel authority.
/// See [`AddressSpaceOps`] for per-operation daemon-boundary disclosure.
pub fn inode_init_aops<E: VfsEngine>(kmod: &mut KmodPosixVfs<E>) -> AddressSpaceOps<'_, E> {
    kmod.address_space_ops()
}
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// fill_super_from_device: integrated mount pipeline
// ---------------------------------------------------------------------------

/// Device buffers and policy inputs for [`fill_super_from_device`].
pub struct FillSuperDeviceInput<'a> {
    pub device_label_buf: &'a [u8],
    pub superblock_region_buf: &'a [u8],
    pub intent_records: &'a [&'a [u8]],
    pub recovery_mode: bool,
    pub expected_uuid: Option<&'a [u8; 32]>,
    pub expected_root_digest: Option<&'a [u8; 32]>,
    pub ctx: &'a RequestCtx,
}

/// Execute the full kernel fill_super path from raw device buffers.
///
/// This is the complete kernel `fill_super` equivalent combining:
///
/// 1. Pool label import and validation (PoolImportContext)
/// 2. Committed-root ledger selection (MountRootSelector)
/// 3. Intent-log replay (if recovery mode, via KernelIntentReplay)
/// 4. Superblock mount validation (mount_validate)
///
/// On success, returns the MountResult and the recovered VfsEngine
/// for subsequent normal VFS operations.
///
/// # No-daemon boundary
///
/// All four phases execute entirely in kernel context. No userspace
/// daemon, helper, or upcall is required.
pub fn fill_super_from_device<E: VfsEngine + VfsEngineStatFs>(
    engine: E,
    input: FillSuperDeviceInput<'_>,
) -> Result<(MountResult, E), MountError> {
    use crate::kernel_mount::KernelMountSequence;
    let FillSuperDeviceInput {
        device_label_buf,
        superblock_region_buf,
        intent_records,
        recovery_mode,
        expected_uuid,
        expected_root_digest,
        ctx,
    } = input;

    #[cfg(CONFIG_RUST)]
    use tidefs_kmod_bridge::kernel_types::ByteSliceExt;
    // Phases 1-3: pool import, ledger selection, intent replay.
    let seq = KernelMountSequence::new(engine, recovery_mode);
    let (kmr, engine) = seq
        .mount(device_label_buf, superblock_region_buf, intent_records, ctx)
        .map_err(|e| MountError::SuperblockCorrupted {
            detail: {
                use core::fmt::Write;
                let mut s = String::new();
                let _ = write!(s, "mount sequence error: {e}");
                s
            },
        })?;

    // Phase 4: mount validation against the selected committed root.
    let result = mount_validate(
        &engine,
        ctx,
        expected_uuid,
        expected_root_digest,
        kmr.root_anchor.txg,
    )?;

    Ok((result, engine))
}

// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::superblock::MountError;
    use crate::test_util::MockEngine;
    use crate::TideBox as Box;
    use crate::TideVec as Vec;
    use tidefs_kmod_bridge::kernel_types::{
        EngineFileHandle, FileHandleId, InodeId, StatFs, WritebackOutcome,
    };

    // -- fill_super tests --

    #[test]
    fn administrative_super_operations_are_typed_unsupported() {
        use AdministrativeSuperOperation as Op;
        use AdministrativeSuperOperationKernelPath as KernelPath;
        use AdministrativeSuperOperationSupport as Support;

        let cases = [
            (Op::Shutdown, KernelPath::UnregisteredUnsupported),
            (Op::FreezeFs, KernelPath::SuperOperationRefusalCallback),
            (Op::UnfreezeFs, KernelPath::SuperOperationRefusalCallback),
            (Op::RemountFs, KernelPath::FsContextReconfigureRefusal),
        ];

        for (operation, kernel_path) in cases {
            let policy = administrative_super_operation_policy(operation);
            assert_eq!(policy.operation, operation);
            assert_eq!(policy.support, Support::Unsupported);
            assert_eq!(policy.kernel_path, kernel_path);
            assert_eq!(policy.errno, Errno::EOPNOTSUPP);
            assert!(!policy.reason.is_empty());
            assert!(!policy.is_supported());
            assert_eq!(
                refuse_administrative_super_operation(operation),
                Err(Errno::EOPNOTSUPP)
            );
        }
    }

    #[test]
    fn fill_super_success_delegates_to_mount_validate() {
        let mut engine = MockEngine::new();
        engine.root_ino = InodeId::new(2);
        engine.statfs_fn =
            Box::new(|_| Ok(StatFs::new(4096, 4096, 1000, 500, 500, 100, 50, 255, 1, 2)));
        let ra = MockEngine::dir_attr(2);
        engine.getattr_fn = Box::new(move |ino, _, _| {
            if ino == InodeId::new(2) {
                Ok(ra)
            } else {
                Err(Errno::ENOENT)
            }
        });

        let result = fill_super(&engine, &MockEngine::test_ctx(), None, None, 3);
        assert!(result.is_ok());
        let mr = result.unwrap();
        assert_eq!(mr.root_ino, InodeId::new(2));
        assert!(mr.anchor.verify());
    }

    #[test]
    fn fill_super_fails_missing_committed_root() {
        let mut engine = MockEngine::new();
        engine.root_ino = InodeId::new(1);
        engine.statfs_fn = Box::new(|_| Err(Errno::ENOENT));
        let ra = MockEngine::dir_attr(1);
        engine.getattr_fn = Box::new(move |_, _, _| Ok(ra));

        let result = fill_super(&engine, &MockEngine::test_ctx(), None, None, 0);
        assert!(result.is_err());
        match result.unwrap_err() {
            MountError::EngineError(Errno::ENOENT) => {}
            other => panic!("expected EngineError(ENOENT), got {other:?}"),
        }
    }

    // -- kill_sb tests --

    #[test]
    fn kill_sb_success_when_syncfs_succeeds() {
        let mut engine = MockEngine::new();
        engine.syncfs_fn = Box::new(|_| Ok(()));

        assert_eq!(kill_sb(&engine, &MockEngine::test_ctx(), None), Ok(()));
    }

    #[test]
    fn kill_sb_propagates_unsupported_syncfs() {
        let engine = MockEngine::new();
        // syncfs_fn defaults to ENOSYS
        assert_eq!(
            kill_sb(&engine, &MockEngine::test_ctx(), None),
            Err(Errno::ENOSYS)
        );
    }

    #[test]
    fn kill_sb_propagates_io_error() {
        let mut engine = MockEngine::new();
        engine.syncfs_fn = Box::new(|_| Err(Errno::EIO));

        assert_eq!(
            kill_sb(&engine, &MockEngine::test_ctx(), None),
            Err(Errno::EIO)
        );
    }

    #[test]
    fn kill_sb_writeback_error_keeps_dirty_range_and_skips_syncfs() {
        use alloc::sync::Arc;
        use core::sync::atomic::{AtomicBool, Ordering};

        let mut engine = MockEngine::new();
        let syncfs_called = Arc::new(AtomicBool::new(false));
        let syncfs_seen = Arc::clone(&syncfs_called);
        engine.writeback_folios_fn = Box::new(|_, _, _, _| Err(Errno::EIO));
        engine.syncfs_fn = Box::new(move |_| {
            syncfs_seen.store(true, Ordering::SeqCst);
            Ok(())
        });
        let inode = InodeId::new(9);
        let mut tracker = DirtyFolioTracker::new(8);
        tracker.add(inode, 0, 4096);

        assert_eq!(
            kill_sb(&engine, &MockEngine::test_ctx(), Some(&mut tracker)),
            Err(Errno::EIO)
        );
        assert!(!syncfs_called.load(Ordering::SeqCst));
        let ranges: Vec<_> = tracker.iter().collect();
        assert_eq!(
            ranges,
            Vec::from([(inode, crate::writeback::DirtyRange::new(0, 4096))])
        );
    }

    #[test]
    fn kill_sb_partial_writeback_keeps_tail_and_skips_syncfs() {
        use alloc::sync::Arc;
        use core::sync::atomic::{AtomicBool, Ordering};

        let mut engine = MockEngine::new();
        let syncfs_called = Arc::new(AtomicBool::new(false));
        let syncfs_seen = Arc::clone(&syncfs_called);
        engine.writeback_folios_fn = Box::new(|_, _, _, _| Ok(WritebackOutcome::new(2048, false)));
        engine.syncfs_fn = Box::new(move |_| {
            syncfs_seen.store(true, Ordering::SeqCst);
            Ok(())
        });
        let inode = InodeId::new(10);
        let mut tracker = DirtyFolioTracker::new(8);
        tracker.add(inode, 0, 4096);

        assert_eq!(
            kill_sb(&engine, &MockEngine::test_ctx(), Some(&mut tracker)),
            Err(Errno::EIO)
        );
        assert!(!syncfs_called.load(Ordering::SeqCst));
        let ranges: Vec<_> = tracker.iter().collect();
        assert_eq!(
            ranges,
            Vec::from([(inode, crate::writeback::DirtyRange::new(2048, 2048))])
        );
    }

    // -- statfs tests --

    #[test]
    fn statfs_delegates_to_engine() {
        let mut engine = MockEngine::new();
        engine.statfs_fn = Box::new(|_| {
            Ok(StatFs::new(
                4096, 4096, 500, 250, 250, 100, 50, 255, 0xABCD, 0x1234,
            ))
        });

        let sf = statfs(&engine, &MockEngine::test_ctx()).unwrap();
        assert_eq!(sf.block_size, 4096);
        assert_eq!(sf.total_blocks, 500);
        assert_eq!(sf.name_max, 255);
    }

    // -- inode_init_aops tests --

    #[test]
    fn inode_init_aops_returns_address_space_ops() {
        let mut e = MockEngine::new();
        e.read_fn =
            Box::new(|_, _, _, _| Ok(crate::TideVec::from([b'd', b'a', b't', b'a'].as_slice())));
        let mut kmod = KmodPosixVfs::new(e);
        let mut aops = kmod.address_space_ops();

        let fh = EngineFileHandle::new(InodeId::new(1), 0, FileHandleId(0), 0);
        let data = aops
            .read_folio(&fh, 0, 4096, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(data, b"data");
        assert_eq!(aops.page_cache_stats().populate, 1);
    }

    #[test]
    fn inode_init_aops_readahead_dispatches() {
        let mut e = MockEngine::new();
        e.read_fn = Box::new(|_, _, _, _| Ok(crate::TideVec::from([b'p', b'r', b'e'].as_slice())));
        let mut kmod = KmodPosixVfs::new(e);
        let mut aops = kmod.address_space_ops();

        let fh = EngineFileHandle::new(InodeId::new(1), 0, FileHandleId(0), 0);
        aops.readahead(&fh, 0, 4096, &MockEngine::test_ctx());
        assert_eq!(aops.page_cache_stats().readahead_count, 1);
        assert_eq!(aops.page_cache_stats().prefetch, 1);
    }

    #[test]
    fn inode_init_aops_write_begin_blocked() {
        let e = MockEngine::new();
        let mut kmod = KmodPosixVfs::new(e);
        let aops = kmod.address_space_ops();

        let fh = EngineFileHandle::new(InodeId::new(1), 0, FileHandleId(0), 0);
        assert_eq!(
            aops.write_begin(&fh, 0, 4096, &MockEngine::test_ctx()),
            Err(Errno::ENOSYS)
        );
    }

    #[test]
    fn inode_init_aops_dirty_folio_is_noop() {
        let e = MockEngine::new();
        let mut kmod = KmodPosixVfs::new(e);
        let mut aops = kmod.address_space_ops();

        // Should not panic
        aops.dirty_folio(InodeId::new(1), 0, 4096);
    }

    #[test]
    fn inode_init_aops_invalidate_counts_eviction() {
        let e = MockEngine::new();
        let mut kmod = KmodPosixVfs::new(e);
        let mut aops = kmod.address_space_ops();

        let fh = EngineFileHandle::new(InodeId::new(1), 0, FileHandleId(0), 0);
        let _ = aops.invalidate_folio(InodeId::new(1), &fh, 0, 8192);
        assert_eq!(aops.page_cache_stats().evict, 1);
    }

    #[test]
    fn inode_init_aops_page_mkwrite_registers_dirty() {
        let e = MockEngine::new();
        let mut kmod = KmodPosixVfs::new(e);
        let mut aops = kmod.address_space_ops();

        assert_eq!(
            aops.page_mkwrite(InodeId::new(1), 0, &MockEngine::test_ctx()),
            Ok(())
        );
        // Verify dirty range was registered in the tracker
        let ranges: Vec<_> = kmod.dirty_folio_tracker.iter().collect();
        assert_eq!(ranges.len(), 1);
        assert_eq!(
            ranges[0],
            (InodeId::new(1), crate::writeback::DirtyRange::new(0, 4096))
        );
    }

    // ── fill_super_from_device tests ─────────────────────────────────

    use crate::mount::MountRootSelector;
    use alloc::vec;
    use tidefs_types_pool_label_core::{
        encode_label, seal_label, PoolLabelV1, PoolState, POOL_LABEL_SIZE,
        POOL_LABEL_V1_EXT_WIRE_SIZE,
    }; // Kbuild: use crate::TideVec;

    fn make_label_buf(state: PoolState, commit_group: u64) -> crate::TideVec<u8> {
        let mut label = PoolLabelV1::new([0xAA; 16], [0xBB; 16], "testpool");
        label.pool_state = state;
        label.commit_group = commit_group;
        label.label_commit_group = commit_group;
        label.device_index = 0;
        label.device_count = 1;
        label.topology_generation = 1;
        label.device_capacity_bytes = 1024 * 1024 * 1024;
        label.system_area_pointer = POOL_LABEL_SIZE as u64;
        label.system_area_size = 4096 * 64;
        let label = seal_label(label).unwrap();
        let mut buf = [0u8; POOL_LABEL_V1_EXT_WIRE_SIZE];
        encode_label(&label, &mut buf).unwrap();
        buf.to_vec()
    }

    fn make_anchor(txg: u64, root_ino: u64) -> crate::superblock::CommittedRootAnchor {
        use crate::superblock::CommittedRootAnchor;
        let mut uuid = [0u8; 32];
        uuid[0..16].copy_from_slice(&[0xAA; 16]);
        CommittedRootAnchor::new(InodeId::new(root_ino), uuid, txg)
    }

    fn make_ledger(txg: u64, root_ino: u64) -> crate::TideVec<u8> {
        let anchor = make_anchor(txg, root_ino);
        MountRootSelector::encode_ledger(&[anchor])
    }

    fn make_vrbt(
        committed_txg: u64,
        root_ino: u64,
        inode_table_root: u64,
        extent_map_root: u64,
        intent_log_tail: u64,
    ) -> crate::TideVec<u8> {
        let mut block = vec![0u8; crate::replay_integration::VRBT_WIRE_SIZE];
        block[0..4].copy_from_slice(b"VRBT");
        block[4..8].copy_from_slice(&1u32.to_le_bytes());
        block[8..16].copy_from_slice(&committed_txg.to_le_bytes());
        block[16..24].copy_from_slice(&root_ino.to_le_bytes());
        block[24..32].copy_from_slice(&inode_table_root.to_le_bytes());
        block[32..40].copy_from_slice(&extent_map_root.to_le_bytes());
        block[40..48].copy_from_slice(&intent_log_tail.to_le_bytes());
        let digest: [u8; 32] = blake3::hash(&block[..56]).into();
        block[56..88].copy_from_slice(&digest);
        block
    }

    fn make_superblock_region(txg: u64, root_ino: u64) -> crate::TideVec<u8> {
        let anchor = make_anchor(txg, root_ino);
        let mut region = MountRootSelector::encode_ledger(&[anchor]);
        let vrbt = make_vrbt(txg, root_ino, 4096, 8192, 0);
        region.resize(3 * 4096 + crate::replay_integration::VRBT_WIRE_SIZE, 0);
        region[3 * 4096..3 * 4096 + crate::replay_integration::VRBT_WIRE_SIZE]
            .copy_from_slice(&vrbt);
        region
    }

    fn make_intent_create(parent: u64, name: &[u8], mode: u32, ino: u64) -> crate::TideVec<u8> {
        let mut buf = vec![4u8]; // DISC_CREATE
        buf.extend_from_slice(&parent.to_le_bytes());
        buf.push(name.len().min(255) as u8);
        buf.extend_from_slice(&name[..name.len().min(255)]);
        buf.extend_from_slice(&mode.to_le_bytes());
        buf.extend_from_slice(&ino.to_le_bytes());
        buf
    }

    fn build_fs_engine(root_ino: u64) -> MockEngine {
        let mut e = MockEngine::new();
        e.root_ino = InodeId::new(root_ino);
        let ra = MockEngine::dir_attr(root_ino);
        e.getattr_fn = Box::new(move |ino, _, _| {
            if ino == InodeId::new(root_ino) {
                Ok(ra)
            } else {
                Err(Errno::ENOENT)
            }
        });
        e.statfs_fn = Box::new(|_| {
            Ok(StatFs::new(
                4096, 4096, 1000, 500, 500, 100, 50, 255, 0x12345678, 0x9ABCDEF0,
            ))
        });
        e.create_fn = Box::new(|_, _, _, _, _| {
            Ok((
                tidefs_kmod_bridge::kernel_types::InodeAttr {
                    inode_id: InodeId::new(42),
                    ..Default::default()
                },
                EngineFileHandle::default(),
            ))
        });
        e.unlink_fn = Box::new(|_, _, _| Ok(()));
        e.mkdir_fn = Box::new(|_, _, _, _| {
            Ok(tidefs_kmod_bridge::kernel_types::InodeAttr {
                inode_id: InodeId::new(50),
                ..Default::default()
            })
        });
        e.rmdir_fn = Box::new(|_, _, _| Ok(()));
        e.rename_fn = Box::new(|_, _, _, _, _, _| Ok(()));
        let cap_ino = root_ino;
        e.setattr_fn = Box::new(move |_, _, _, _| {
            Ok(tidefs_kmod_bridge::kernel_types::InodeAttr {
                inode_id: InodeId::new(cap_ino),
                ..Default::default()
            })
        });
        e.syncfs_fn = Box::new(|_| Ok(()));
        e
    }

    #[test]
    fn fill_super_from_device_success_no_recovery() {
        let engine = build_fs_engine(1);
        let label_buf = make_label_buf(PoolState::Active, 7);
        let ledger_buf = make_superblock_region(7, 1);

        let (result, _engine) = fill_super_from_device(
            engine,
            FillSuperDeviceInput {
                device_label_buf: &label_buf,
                superblock_region_buf: &ledger_buf,
                intent_records: &[],
                recovery_mode: false,
                expected_uuid: None,
                expected_root_digest: None,
                ctx: &MockEngine::test_ctx(),
            },
        )
        .unwrap();

        assert_eq!(result.root_ino, InodeId::new(1));
        assert!(result.anchor.verify());
        assert_eq!(result.superblock.block_size, 4096);
    }

    #[test]
    fn fill_super_from_device_with_recovery_replays_intents() {
        let engine = build_fs_engine(1);
        let label_buf = make_label_buf(PoolState::Active, 7);
        let ledger_buf = make_superblock_region(7, 1);
        let intent = make_intent_create(1, b"recovered", 0o644, 42);

        let (result, _engine) = fill_super_from_device(
            engine,
            FillSuperDeviceInput {
                device_label_buf: &label_buf,
                superblock_region_buf: &ledger_buf,
                intent_records: &[&intent],
                recovery_mode: true,
                expected_uuid: None,
                expected_root_digest: None,
                ctx: &MockEngine::test_ctx(),
            },
        )
        .unwrap();

        assert!(result.anchor.verify());
    }

    #[test]
    fn fill_super_from_device_destroyed_pool_rejected() {
        let engine = build_fs_engine(1);
        let label_buf = make_label_buf(PoolState::Destroyed, 7);
        let ledger_buf = make_ledger(7, 1);

        let err = fill_super_from_device(
            engine,
            FillSuperDeviceInput {
                device_label_buf: &label_buf,
                superblock_region_buf: &ledger_buf,
                intent_records: &[],
                recovery_mode: false,
                expected_uuid: None,
                expected_root_digest: None,
                ctx: &MockEngine::test_ctx(),
            },
        )
        .unwrap_err();

        assert!(matches!(err, MountError::SuperblockCorrupted { .. }));
    }

    #[test]
    fn fill_super_from_device_empty_superblock_region_rejected() {
        let engine = build_fs_engine(1);
        let label_buf = make_label_buf(PoolState::Active, 7);

        let err = fill_super_from_device(
            engine,
            FillSuperDeviceInput {
                device_label_buf: &label_buf,
                superblock_region_buf: &[],
                intent_records: &[],
                recovery_mode: false,
                expected_uuid: None,
                expected_root_digest: None,
                ctx: &MockEngine::test_ctx(),
            },
        )
        .unwrap_err();

        assert!(matches!(err, MountError::SuperblockCorrupted { .. }));
    }

    #[test]
    fn fill_super_from_device_returns_engine_for_reuse() {
        let engine = build_fs_engine(1);
        let label_buf = make_label_buf(PoolState::Active, 7);
        let ledger_buf = make_superblock_region(7, 1);

        let (_result, engine) = fill_super_from_device(
            engine,
            FillSuperDeviceInput {
                device_label_buf: &label_buf,
                superblock_region_buf: &ledger_buf,
                intent_records: &[],
                recovery_mode: false,
                expected_uuid: None,
                expected_root_digest: None,
                ctx: &MockEngine::test_ctx(),
            },
        )
        .unwrap();

        // Engine is recovered; can be queried for statfs after mount.
        let sf = statfs(&engine, &MockEngine::test_ctx()).unwrap();
        assert_eq!(sf.block_size, 4096);
    }
}
