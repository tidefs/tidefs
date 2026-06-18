// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Kernel bridge integration for the VFS adapter.
//!
//! Wires the kmod-posix-vfs leaf module (s3 / c7) to the kmod-bridge
//! substrate (s2 / c6, K7-04/#5283). Uses bridge types for error
//! mapping and kernel registration via the bridge trait contracts.
//!
//! The bridge exposes three super_operations dispatch entry points
//! for the Linux 7.0 kernel VFS layer:
//! - `kmod_fill_super` -- superblock initialization
//! - `kmod_kill_sb` -- superblock teardown
//! - `kmod_statfs` -- filesystem capacity query
//!
//! The loaded Linux 7.0 module also wires C-shim `sync_fs`, `put_super`, and
//! `umount_begin` callbacks directly in `tidefs_posix_vfs_shim.c`; those
//! callbacks hold the mounted `s_fs_info` context live through
//! `generic_shutdown_super()`.
//!
//! # Super_operations Dispatch Status
//!
//! Wired (C shim + bridge, per `tidefs_posix_vfs_super_ops`):
//! - `fill_super`, `kill_sb`, `statfs`, `evict_inode`, `write_inode`,
//!   `free_inode`, `put_super`, `sync_fs`, `umount_begin`,
//!   `shutdown`, `show_options`.
//!
//! Explicitly deferred (not in super_ops table):
//! - `freeze_fs`/`unfreeze_fs` -- kernel returns EOPNOTSUPP.
//! - `remount_fs` -- kernel treats MS_REMOUNT as a no-op.
//!
//! # Safety: kernel callback registration contract
//!
//! The functions exported by this module — `kmod_fill_super`, `kmod_kill_sb`,
//! `kmod_statfs`, `kmod_init`, and `kmod_exit` — are designed to be registered
//! as Linux VFS `super_operations` and module init/exit callbacks in the
//! kernel build environment (Kbuild / K7-02).  When registered, the Linux
//! kernel calls these functions with kernel-owned pointers that this crate
//! does not yet consume directly (all kernel-object access is mediated by
//! the kmod-bridge trait contracts).
//!
//! The following invariants must hold when these functions are registered as
//! kernel callbacks:
//!
//! - **ABI match**: The function signature must match the kernel's expected
//!   calling convention for `struct super_operations` or module init/exit.
//!   Signature mismatches are undefined behavior.
//! - **Pointer provenance**: Any opaque kernel pointers (`OpaqueSuperBlock`,
//!   `OpaqueInode`, etc.) arriving via callbacks must be constructed through
//!   `unsafe { Opaque*::from_ptr(ptr) }` in the bridge, with a `// SAFETY:`
//!   comment naming the kernel guarantee that keeps the pointer live.
//! - **Lock discipline**: Any lock acquired inside these callbacks must
//!   declare a `KernelLockClass` variant per the canonical P7-03 lockdep
//!   order, and may not sleep in non-sleepable callback contexts (e.g.,
//!   RCU read sections, spinlock-held regions).
//! - **No userspace authority**: In full-kernel mode, these callbacks must
//!   not require a userspace daemon, FUSE helper, or ublk control thread
//!   for normal operation.  Callbacks that need policy authority must
//!   dispatch through a kernel-resident authority path or record a
//!   precise blocker.
//!
//! This crate currently uses `#![forbid(unsafe_code)]` because all raw-pointer
//! construction is deferred to the bridge substrate.  When real Kbuild
//! registration is wired, the `forbid` may relax to
//! `#![deny(unsafe_op_in_unsafe_fn)]` at the registration sites.

#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

use crate::mount_lifecycle::MountLifecycle;
use crate::superblock::{MountError, MountResult};
use crate::KmodPosixVfs;
use tidefs_kmod_bridge::kernel_types::{Errno, RequestCtx, StatFs};
use tidefs_kmod_bridge::kernel_types::{VfsEngine, VfsEngineStatFs};
use tidefs_kmod_bridge::BridgeError;

/// Registration handle for the kernel filesystem module.
///
/// Wraps a [`FilesystemRegHandle`] from the kmod-bridge. When the handle
/// is active, the "tidefs" filesystem type is registered with the kernel
/// VFS. The handle must be held for the module's lifetime and dropped
/// during module exit to unregister the type.
#[derive(Clone, Copy, Debug)]
pub struct KmodRegistration {
    pub handle: tidefs_kmod_bridge::FilesystemRegHandle,
}

impl Default for KmodRegistration {
    fn default() -> Self {
        Self::new()
    }
}

impl KmodRegistration {
    pub const fn new() -> Self {
        Self {
            handle: tidefs_kmod_bridge::FilesystemRegHandle::NONE,
        }
    }

    /// Whether the filesystem type is currently registered.
    pub fn is_registered(&self) -> bool {
        self.handle.is_active()
    }
}

// ---------------------------------------------------------------------------
// Per-mount superblock context
// ---------------------------------------------------------------------------

/// Per-mount superblock context for a TideFS kernel filesystem instance.
///
/// Wraps a [`MountLifecycle`] that tracks the full mount/unmount lifecycle
/// with BLAKE3-256 verified superblock state integrity. Created by
/// [`kmod_init_super`] from an engine instance and consumed by the kernel
/// VFS super_operations dispatch.
pub struct KmodSuperContext<E> {
    lifecycle: MountLifecycle<E>,
}

impl<E: VfsEngine + VfsEngineStatFs> KmodSuperContext<E> {
    /// Create a new superblock context wrapping the given engine.
    pub fn new(engine: E) -> Self {
        Self {
            lifecycle: MountLifecycle::new(engine),
        }
    }

    /// Create a superblock context from an already-configured KmodPosixVfs.
    ///
    /// This is the preferred constructor when the adapter has been
    /// pre-configured with mount options, page-cache trackers, or
    /// other operational state. Prefer KmodSuperContext::new when
    /// starting from a bare engine.
    pub fn from_vfs(vfs: KmodPosixVfs<E>) -> Self {
        Self {
            lifecycle: MountLifecycle::from_vfs(vfs),
        }
    }

    /// Return a reference to the underlying VfsEngine.
    pub fn engine(&self) -> &E {
        self.lifecycle.engine()
    }

    /// Return the current mount state.
    pub fn is_mounted(&self) -> bool {
        self.lifecycle.is_mounted()
    }

    /// Return the number of successful mounts.
    pub fn mount_count(&self) -> u64 {
        self.lifecycle.mount_count()
    }

    /// Take a BLAKE3-256 verified lifecycle snapshot.
    pub fn snapshot(&self) -> crate::mount_lifecycle::MountLifecycleDigest {
        self.lifecycle.snapshot()
    }
}

impl<E: VfsEngine + VfsEngineStatFs> From<KmodPosixVfs<E>> for KmodSuperContext<E> {
    fn from(vfs: KmodPosixVfs<E>) -> Self {
        Self::from_vfs(vfs)
    }
}

// ---------------------------------------------------------------------------
// Super_operations dispatch entry points
// ---------------------------------------------------------------------------

/// fill_super: Initialize the kernel VFS superblock from the backing device.
///
/// Called by the Linux kernel VFS on mount. Validates the superblock,
/// replays the committed-root with BLAKE3-256 verification, and resolves
/// the root inode. On success, the superblock context transitions to
/// Mounted state.
///
/// Returns [`MountResult`] with root inode id, superblock parameters,
/// and the committed-root anchor.
///
/// # Safety (kernel callback ABI)
///
/// When registered as a `super_operations` callback in the kernel build
/// environment, the caller (Linux VFS) guarantees:
/// - The backing device is open and held across the mount.
/// - No concurrent `fill_super` call for the same superblock.
/// - The kernel super_block pointer (opaque to this crate) is valid for
///   the duration of the call.
///
/// The `expected_uuid` and `expected_root_digest` parameters, when
/// `Some`, are validated against on-disk superblock metadata.  A
/// mismatch returns [`MountError::UuidMismatch`] or
/// [`MountError::RootDigestMismatch`]; the kernel VFS must not proceed
/// with a mismatched mount.
pub fn kmod_fill_super<E: VfsEngine + VfsEngineStatFs>(
    ctx: &mut KmodSuperContext<E>,
    request: &RequestCtx,
    expected_uuid: Option<&[u8; 32]>,
    expected_root_digest: Option<&[u8; 32]>,
    committed_txg: u64,
    intent_records: &[&[u8]],
    recovery_mode: bool,
) -> Result<MountResult, MountError> {
    ctx.lifecycle.mount(
        request,
        expected_uuid,
        expected_root_digest,
        committed_txg,
        intent_records,
        recovery_mode,
    )
}

/// kill_sb: Teardown the kernel superblock with dirty-state flush.
///
/// Called by the Linux kernel VFS on unmount. Flushes all dirty data
/// and metadata via [`VfsEngine::syncfs`] and transitions the superblock
/// context to Unmounted state. Unsupported sync is returned as an error
/// for mounted filesystems that claim pool-backed durability.
///
/// # Safety (kernel callback ABI)
///
/// When registered as a `super_operations` callback:
/// - The kernel VFS guarantees no new file operations will be admitted
///   on this superblock after `kill_sb` is called.
/// - The superblock pointer is valid for the call duration.
/// - After `kill_sb` returns, the kernel will free the superblock; this
///   crate must not hold references to it.
pub fn kmod_kill_sb<E: VfsEngine + VfsEngineStatFs>(
    ctx: &mut KmodSuperContext<E>,
    request: &RequestCtx,
) -> Result<(), Errno> {
    ctx.lifecycle.unmount(request)
}

/// statfs: Query filesystem capacity statistics.
///
/// Called by the Linux kernel VFS for `statfs(2)` / `statvfs(2)`.
/// Returns total/free blocks, total/free inodes, block size, maximum
/// filename length, and filesystem id.
///
/// # Safety (kernel callback ABI)
///
/// When registered as a `super_operations` callback:
/// - The kernel VFS holds a reference to the superblock, keeping it live
///   for the call duration.
/// - This function does not mutate superblock state; it is safe to call
///   concurrently with other read-only super_operations.
/// - Capacity values must be honest: returning fabricated or stale
///   capacity can cause ENOSPC at the VFS layer without a clear error
///   path.
pub fn kmod_statfs<E: VfsEngine + VfsEngineStatFs>(
    ctx: &KmodSuperContext<E>,
    request: &RequestCtx,
) -> Result<StatFs, Errno> {
    crate::super_operations::statfs(ctx.engine(), request)
}

// ---------------------------------------------------------------------------
// Error mapping (unchanged)
// ---------------------------------------------------------------------------

/// Map a kmod-bridge [`BridgeError`] to a VFS [`Errno`].
pub fn bridge_errno(err: &BridgeError) -> Errno {
    use crate::errno::KernelErrno;
    match err {
        BridgeError::DecodeFailed { .. } => KernelErrno::STORAGE_IO,
        BridgeError::AnchorStale { .. } => KernelErrno::STALE_GENERATION,
        BridgeError::MirrorLiftFailed { .. } => KernelErrno::STORAGE_IO,
        BridgeError::AuthorityRefused { .. } => KernelErrno::PERM_NOT_PERMITTED,
        BridgeError::RenderRejected { .. } => KernelErrno::STORAGE_IO,
        BridgeError::ValidationEmitFailed { .. } => KernelErrno::STORAGE_IO,
        BridgeError::PinDrainFailed { .. } => KernelErrno::RESOURCE_BUSY,
        BridgeError::PageWindowFailed { .. } => KernelErrno::STORAGE_IO,
        BridgeError::BioQueueFailed { .. } => KernelErrno::STORAGE_IO,
        BridgeError::SecretLeaseExpired { .. } => KernelErrno::STALE_GENERATION,
        BridgeError::InvalidState { .. } => KernelErrno::STORAGE_IO,
        BridgeError::Unimplemented { .. } => KernelErrno::UNSUPPORTED_OP,
    }
}

/// Kernel module init entry point.
///
/// Registers the "tidefs" filesystem type through the bridge trait
/// contracts. The concrete kernel bindings are supplied by the
/// Linux 7.0 kernel build environment (K7-02).
/// Kernel module init: register the "tidefs" filesystem type.
///
/// Uses the bridge [`FilesystemRegistration`] trait contract in the portable
/// model. The Linux 7.0 product `.ko` registers the real filesystem type
/// through the root-level C VFS shim because this kernel tree does not expose a
/// Rust `kernel::filesystem` registration API.
pub fn kmod_init() -> Result<KmodRegistration, BridgeError> {
    // Userspace model path: sentinel handle represents an active
    // registration without wrapping a real kernel pointer.
    let handle = tidefs_kmod_bridge::FilesystemRegHandle::new_sentinel();
    Ok(KmodRegistration { handle })
}

/// Kernel module cleanup.
/// Kernel module cleanup: unregister the "tidefs" filesystem type.
///
/// Uses the bridge [`FilesystemRegistration`] trait contract in the portable
/// model. The Linux 7.0 product `.ko` unregisters the real filesystem type
/// through the root-level C VFS shim.
pub fn kmod_exit(reg: &KmodRegistration) -> Result<(), BridgeError> {
    if reg.handle.is_active() {
        // Unregistration through the bridge trait contracts.
        // In the kernel build environment, this blocks until all
        // mounted superblocks are torn down.
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::MockEngine;
    use crate::TideBox as Box;
    use tidefs_kmod_bridge::kernel_types::{InodeId, StatFs};

    // ── Error mapping tests ──────────────────────────────────────────

    #[test]
    fn bridge_errno_decode_failed() {
        assert_eq!(
            bridge_errno(&BridgeError::DecodeFailed {
                detail: "bad magic"
            }),
            Errno::EIO
        );
    }

    #[test]
    fn bridge_errno_anchor_stale() {
        assert_eq!(
            bridge_errno(&BridgeError::AnchorStale {
                generation: 1,
                expected: 2
            }),
            Errno::ESTALE
        );
    }

    #[test]
    fn bridge_errno_authority_refused() {
        assert_eq!(
            bridge_errno(&BridgeError::AuthorityRefused {
                reason: "no permission"
            }),
            Errno::EPERM
        );
    }

    #[test]
    fn bridge_errno_pin_drain_failed() {
        assert_eq!(
            bridge_errno(&BridgeError::PinDrainFailed { detail: "busy" }),
            Errno::EBUSY
        );
    }

    #[test]
    fn bridge_errno_unimplemented() {
        assert_eq!(
            bridge_errno(&BridgeError::Unimplemented { feature: "acl" }),
            Errno::EOPNOTSUPP
        );
    }

    #[test]
    fn bridge_errno_secret_lease_expired() {
        assert_eq!(
            bridge_errno(&BridgeError::SecretLeaseExpired { handle_id: 42 }),
            Errno::ESTALE
        );
    }

    #[test]
    fn kmod_init_returns_registered() {
        assert!(kmod_init().unwrap().is_registered());
    }

    #[test]
    fn kmod_exit_succeeds() {
        kmod_exit(&KmodRegistration {
            handle: tidefs_kmod_bridge::FilesystemRegHandle::new_sentinel(),
        })
        .unwrap();
    }

    // ── Super_operations dispatch tests ──────────────────────────────

    fn mount_ready_engine() -> MockEngine {
        let mut e = MockEngine::new();
        e.root_ino = InodeId::new(100);
        e.statfs_fn = Box::new(|_| {
            Ok(StatFs::new(
                4096, 4096, 2000, 1500, 1500, 500, 400, 255, 0xAAAA, 0xBBBB,
            ))
        });
        let ra = MockEngine::dir_attr(100);
        e.getattr_fn = Box::new(move |ino, _, _| {
            if ino == InodeId::new(100) {
                Ok(ra)
            } else {
                Err(Errno::ENOENT)
            }
        });
        e.syncfs_fn = Box::new(|_| Ok(()));
        e
    }

    #[test]
    fn kmod_fill_super_mounts_and_returns_root() {
        let mut ctx = KmodSuperContext::new(mount_ready_engine());
        let result =
            kmod_fill_super(&mut ctx, &MockEngine::test_ctx(), None, None, 1, &[], false).unwrap();
        assert!(ctx.is_mounted());
        assert_eq!(result.root_ino, InodeId::new(100));
        assert!(result.anchor.verify());
    }

    #[test]
    fn kmod_kill_sb_unmounts_and_flushes() {
        let mut ctx = KmodSuperContext::new(mount_ready_engine());
        kmod_fill_super(&mut ctx, &MockEngine::test_ctx(), None, None, 1, &[], false).unwrap();
        assert!(ctx.is_mounted());

        kmod_kill_sb(&mut ctx, &MockEngine::test_ctx()).unwrap();
        assert!(!ctx.is_mounted());
    }

    #[test]
    fn kmod_statfs_returns_capacity() {
        let ctx = KmodSuperContext::new(mount_ready_engine());
        let sf = kmod_statfs(&ctx, &MockEngine::test_ctx()).unwrap();
        assert_eq!(sf.block_size, 4096);
        assert_eq!(sf.total_blocks, 2000);
        assert_eq!(sf.name_max, 255);
    }

    #[test]
    fn kmod_fill_super_fails_on_statfs_error() {
        let fail_engine = mock_engine_statfs_err();
        let mut ctx = KmodSuperContext::new(fail_engine);
        let err = kmod_fill_super(&mut ctx, &MockEngine::test_ctx(), None, None, 1, &[], false)
            .unwrap_err();
        match err {
            MountError::EngineError(Errno::EIO) => {}
            other => panic!("expected EngineError(EIO), got {other:?}"),
        }
        assert!(!ctx.is_mounted());
    }

    fn mock_engine_statfs_err() -> MockEngine {
        let mut e = MockEngine::new();
        e.root_ino = InodeId::new(100);
        e.statfs_fn = Box::new(|_| Err(Errno::EIO));
        let ra = MockEngine::dir_attr(100);
        e.getattr_fn = Box::new(move |_, _, _| Ok(ra));
        e
    }

    #[test]
    fn mount_unmount_remount_cycle_preserves_state() {
        let mut ctx = KmodSuperContext::new(mount_ready_engine());

        // First mount
        let r1 =
            kmod_fill_super(&mut ctx, &MockEngine::test_ctx(), None, None, 7, &[], false).unwrap();
        assert_eq!(ctx.mount_count(), 1);
        let snap1a = ctx.snapshot();

        // Unmount
        kmod_kill_sb(&mut ctx, &MockEngine::test_ctx()).unwrap();
        assert!(!ctx.is_mounted());

        // Remount
        let r2 =
            kmod_fill_super(&mut ctx, &MockEngine::test_ctx(), None, None, 7, &[], false).unwrap();
        assert_eq!(ctx.mount_count(), 2);
        let snap2a = ctx.snapshot();

        assert_eq!(r1.root_ino, r2.root_ino);
        assert_eq!(r1.superblock, r2.superblock);
        assert_eq!(r1.anchor, r2.anchor);
        // mount_count differs (1 vs 2) so full lifecycle digests differ;
        // committed-root digest is preserved
        assert_eq!(snap1a.committed_root_digest, snap2a.committed_root_digest);
    }

    #[test]
    fn snapshot_reflects_mount_state() {
        let mut ctx = KmodSuperContext::new(mount_ready_engine());
        let s0 = ctx.snapshot();
        assert_eq!(s0.mounted, 0);

        kmod_fill_super(&mut ctx, &MockEngine::test_ctx(), None, None, 1, &[], false).unwrap();
        let s1 = ctx.snapshot();
        assert_eq!(s1.mounted, 1);

        kmod_kill_sb(&mut ctx, &MockEngine::test_ctx()).unwrap();
        let s2 = ctx.snapshot();
        assert_eq!(s2.mounted, 0);
    }
}
