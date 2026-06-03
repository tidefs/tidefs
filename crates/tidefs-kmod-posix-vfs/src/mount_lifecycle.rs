//! Mount lifecycle state machine for the kernel VFS adapter.
//!
//! Tracks the mount/unmount lifecycle of a TideFS kernel filesystem
//! instance with BLAKE3-256 verified superblock state integrity.
//! Bridges kernel mount/unmount transitions to VfsEngine initialization
//! and teardown with error propagation.
//!
//! # States
//!
//! ```text
//! Unmounted --fill_super--> Mounted --kill_sb--> Unmounted
//!      ^                                            |
//!      +--------------------------------------------+
//! ```
//!
//! # Super_operations Dispatch Status
//!
//! Wired (C shim): `fill_super`, `kill_sb`, `statfs`, `sync_fs`,
//!   `put_super`, `umount_begin`, `shutdown`, `show_options`,
//!   plus inode-level ops (`evict_inode`, `write_inode`, `free_inode`).
//!
//! Explicitly deferred (not registered in super_ops table):
//! - `remount_fs` -- the kernel VFS treats MS_REMOUNT as a flags-only
//!   no-op (ro/rw toggle); custom mount-option propagation is not supported.
//! - `freeze_fs`/`unfreeze_fs` -- the kernel VFS returns EOPNOTSUPP for
//!   any freeze/thaw request on this superblock.

#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

#[cfg(CONFIG_RUST)]
use crate::blake3;
use crate::intent_replay::replay_intent_records_ref;
use crate::superblock::{mount_validate, MountError, MountResult};
use crate::KmodPosixVfs;
use crate::TideString as String;
use tidefs_kmod_bridge::kernel_types::{CommittedRoot, VfsEngine, VfsEngineStatFs};
use tidefs_kmod_bridge::kernel_types::{Errno, RequestCtx};

// -- BLAKE3 domain separator --

/// Domain separator for mount lifecycle state digests.
const DOMAIN: &str = "tidefs-kmod-mount-lifecycle-v1";

// -- Mount state --

/// The current mount state of a kernel VFS filesystem instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MountState {
    /// Filesystem is not mounted.
    Unmounted,
    /// Filesystem is mounted with the given mount result.
    Mounted(MountResult),
}

impl MountState {
    /// Returns true if the filesystem is currently mounted.
    pub fn is_mounted(&self) -> bool {
        matches!(self, MountState::Mounted(_))
    }
}

// -- Lifecycle digest --

/// Stable snapshot of mount lifecycle state for BLAKE3-256 comparison.
#[derive(Clone, Debug)]
pub struct MountLifecycleDigest {
    /// Mounted flag: 1 if mounted, 0 if unmounted.
    pub mounted: u8,
    /// Root inode id at mount time (0 if unmounted).
    pub root_ino: u64,
    /// Committed transaction group at mount time.
    pub committed_txg: u64,
    /// Superblock magic (first 8 bytes of pool UUID).
    pub magic: [u8; 8],
    /// Superblock logical block size in bytes.
    pub block_size: u32,
    /// Number of completed mounts since boot.
    pub mount_count: u64,
    /// BLAKE3-256 digest of the committed-root anchor.
    pub committed_root_digest: [u8; 32],
}

impl MountLifecycleDigest {
    /// Compute the BLAKE3-256 digest of this lifecycle snapshot.
    pub fn compute(&self) -> blake3::Hash {
        let mut hasher = blake3::Hasher::new_derive_key(DOMAIN);
        hasher.update(&[self.mounted]);
        hasher.update(&self.root_ino.to_le_bytes());
        hasher.update(&self.committed_txg.to_le_bytes());
        hasher.update(&self.magic);
        hasher.update(&self.block_size.to_le_bytes());
        hasher.update(&self.mount_count.to_le_bytes());
        hasher.update(&self.committed_root_digest);
        hasher.finalize()
    }

    /// Compute the raw digest bytes.
    pub fn digest_bytes(&self) -> [u8; 32] {
        self.compute().into()
    }
}

// -- MountLifecycle --

/// Mount lifecycle state machine for a TideFS kernel filesystem instance.
///
/// Wraps a [`KmodPosixVfs`] instance and adds mount/unmount lifecycle
/// tracking with BLAKE3-256 verified superblock state integrity. The
/// lifecycle bridges kernel VFS mount/unmount transitions to VfsEngine
/// initialization and teardown.
pub struct MountLifecycle<E> {
    /// The underlying kernel POSIX VFS adapter.
    vfs: KmodPosixVfs<E>,
    /// Current mount state.
    state: MountState,
    /// Number of successful mount operations since construction.
    mount_count: u64,
    /// Pool UUID (cached from the most recent mount).
    pool_uuid: [u8; 32],
    /// Committed-root digest (cached from the most recent mount).
    committed_root_digest: [u8; 32],
}

impl<E: VfsEngine + VfsEngineStatFs> MountLifecycle<E> {
    /// Create a new mount lifecycle wrapper around a VfsEngine.
    pub fn new(engine: E) -> Self {
        Self {
            vfs: KmodPosixVfs::new(engine),
            state: MountState::Unmounted,
            mount_count: 0,
            pool_uuid: [0u8; 32],
            committed_root_digest: [0u8; 32],
        }
    }

    /// Create a mount lifecycle from an already-configured [`KmodPosixVfs`].
    ///
    /// This is the preferred constructor when the adapter has been
    /// pre-configured with mount options, page-cache trackers, or
    /// other operational state.  Prefer [`MountLifecycle::new`] when
    /// starting from a bare engine.
    ///
    /// The lifecycle begins in [`MountState::Unmounted`]; call
    /// [`MountLifecycle::mount`] to validate the committed root and
    /// transition to mounted state.
    pub fn from_vfs(vfs: KmodPosixVfs<E>) -> Self {
        Self {
            vfs,
            state: MountState::Unmounted,
            mount_count: 0,
            pool_uuid: [0u8; 32],
            committed_root_digest: [0u8; 32],
        }
    }

    /// Execute fill_super: validate the superblock, replay the committed-root,
    /// and transition to Mounted state.
    ///
    /// Returns the [`MountResult`] on success. On failure, the lifecycle
    /// remains in the Unmounted state with no side effects.
    /// Execute fill_super: validate the superblock, replay intent-log records,
    /// and transition to Mounted state.
    ///
    /// When `recovery_mode` is true and `intent_records` is non-empty, the
    /// mount sequence replays intent-log records forward from the committed
    /// root before exposing the root dentry. Replay failure (corrupt log,
    /// engine error) aborts the mount with [`MountError::IntentReplayFailed`].
    ///
    /// If `recovery_mode` is false or `intent_records` is empty, replay is
    /// skipped silently and the namespace reflects the committed-root state
    /// as-is.
    ///
    /// Returns the [`MountResult`] on success. On failure, the lifecycle
    /// remains in the Unmounted state with no side effects.
    pub fn mount(
        &mut self,
        ctx: &RequestCtx,
        expected_uuid: Option<&[u8; 32]>,
        expected_root_digest: Option<&[u8; 32]>,
        committed_txg: u64,
        intent_records: &[&[u8]],
        recovery_mode: bool,
    ) -> Result<MountResult, MountError> {
        if self.state.is_mounted() {
            return Err(MountError::EngineError(Errno::EBUSY));
        }

        // Phase 0: Replay intent-log records before root dentry exposure.
        if recovery_mode && !intent_records.is_empty() {
            replay_intent_records_ref(self.vfs.engine(), intent_records, committed_txg, ctx)
                .map_err(|e| MountError::IntentReplayFailed {
                    detail: {
                        use core::fmt::Write;
                        let mut s = String::new();
                        let _ = write!(s, "intent replay error: {e}");
                        s
                    },
                })?;
        }

        let result = mount_validate(
            self.vfs.engine(),
            ctx,
            expected_uuid,
            expected_root_digest,
            committed_txg,
        )?;

        let mount_result = result.clone();
        self.pool_uuid = result.superblock.uuid;
        self.committed_root_digest = result.anchor.digest;
        self.vfs
            .engine()
            .set_committed_root(CommittedRoot(result.anchor.digest));
        self.mount_count += 1;
        self.vfs.generation += 1;
        self.state = MountState::Mounted(result);

        Ok(mount_result)
    }

    /// Execute kill_sb: flush dirty state and transition to Unmounted.
    ///
    /// Calls [`VfsEngine::syncfs`] to flush all dirty data and metadata
    /// before transitioning. `ENOSYS` from syncfs is treated as success.
    pub fn unmount(&mut self, ctx: &RequestCtx) -> Result<(), Errno> {
        match &self.state {
            MountState::Unmounted => return Ok(()),
            MountState::Mounted(_) => {}
        }

        // Flush dirty state before teardown.
        match self.vfs.engine().syncfs(ctx) {
            Ok(()) | Err(Errno::ENOSYS) => {}
            Err(e) => return Err(e),
        }

        self.state = MountState::Unmounted;
        Ok(())
    }

    /// Return true if the filesystem is currently mounted.
    pub fn is_mounted(&self) -> bool {
        self.state.is_mounted()
    }

    /// Return the current mount state.
    pub fn state(&self) -> &MountState {
        &self.state
    }

    /// Return the number of successful mounts since construction.
    pub fn mount_count(&self) -> u64 {
        self.mount_count
    }

    /// Return a reference to the underlying VfsEngine.
    pub fn engine(&self) -> &E {
        self.vfs.engine()
    }

    /// Return a reference to the wrapped KmodPosixVfs adapter.
    pub fn vfs(&self) -> &KmodPosixVfs<E> {
        &self.vfs
    }

    /// Build a BLAKE3-256 verified lifecycle digest from current state.
    pub fn snapshot(&self) -> MountLifecycleDigest {
        let (root_ino, committed_txg, magic, block_size) = match &self.state {
            MountState::Unmounted => (0u64, 0u64, [0u8; 8], 0u32),
            MountState::Mounted(mr) => (
                mr.root_ino.get(),
                mr.superblock.committed_txg,
                mr.superblock.magic,
                mr.superblock.block_size,
            ),
        };

        MountLifecycleDigest {
            mounted: if self.state.is_mounted() { 1 } else { 0 },
            root_ino,
            committed_txg,
            magic,
            block_size,
            mount_count: self.mount_count,
            committed_root_digest: self.committed_root_digest,
        }
    }

    /// Return the pool UUID from the most recent successful mount.
    pub fn pool_uuid(&self) -> &[u8; 32] {
        &self.pool_uuid
    }
}

impl<E: VfsEngine + VfsEngineStatFs> From<KmodPosixVfs<E>> for MountLifecycle<E> {
    fn from(vfs: KmodPosixVfs<E>) -> Self {
        Self::from_vfs(vfs)
    }
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

    fn mount_ready_engine() -> MockEngine {
        let mut e = MockEngine::new();
        e.root_ino = InodeId::new(10);
        e.statfs_fn = Box::new(|_| {
            Ok(StatFs::new(
                4096, 4096, 1000, 500, 500, 100, 50, 255, 0xDEAD, 0xBEEF,
            ))
        });
        let ra = MockEngine::dir_attr(10);
        e.getattr_fn = Box::new(move |ino, _, _| {
            if ino == InodeId::new(10) {
                Ok(ra)
            } else {
                Err(Errno::ENOENT)
            }
        });
        e.syncfs_fn = Box::new(|_| Ok(()));
        e
    }

    #[test]
    fn new_lifecycle_starts_unmounted() {
        let lc: MountLifecycle<MockEngine> = MountLifecycle::new(MockEngine::new());
        assert!(!lc.is_mounted());
        assert_eq!(lc.mount_count(), 0);
        assert!(matches!(lc.state(), MountState::Unmounted));
    }

    #[test]
    fn mount_transitions_to_mounted() {
        let mut lc = MountLifecycle::new(mount_ready_engine());
        let result = lc
            .mount(&MockEngine::test_ctx(), None, None, 7, &[], false)
            .unwrap();
        assert!(lc.is_mounted());
        assert_eq!(lc.mount_count(), 1);
        assert_eq!(result.root_ino, InodeId::new(10));
        assert!(matches!(lc.state(), MountState::Mounted(_)));
    }

    #[test]
    fn unmount_transitions_to_unmounted() {
        let mut lc = MountLifecycle::new(mount_ready_engine());
        lc.mount(&MockEngine::test_ctx(), None, None, 7, &[], false)
            .unwrap();
        lc.unmount(&MockEngine::test_ctx()).unwrap();
        assert!(!lc.is_mounted());
        assert!(matches!(lc.state(), MountState::Unmounted));
    }

    #[test]
    fn double_mount_is_rejected() {
        let mut lc = MountLifecycle::new(mount_ready_engine());
        lc.mount(&MockEngine::test_ctx(), None, None, 7, &[], false)
            .unwrap();
        let err = lc
            .mount(&MockEngine::test_ctx(), None, None, 7, &[], false)
            .unwrap_err();
        match err {
            MountError::EngineError(Errno::EBUSY) => {}
            other => panic!("expected EBUSY, got {other:?}"),
        }
    }

    #[test]
    fn unmount_when_already_unmounted_is_noop() {
        let mut lc: MountLifecycle<MockEngine> = MountLifecycle::new(MockEngine::new());
        assert_eq!(lc.unmount(&MockEngine::test_ctx()), Ok(()));
    }

    #[test]
    fn mount_unmount_remount_cycle() {
        let mut lc = MountLifecycle::new(mount_ready_engine());

        lc.mount(&MockEngine::test_ctx(), None, None, 7, &[], false)
            .unwrap();
        assert!(lc.is_mounted());
        assert_eq!(lc.mount_count(), 1);

        lc.unmount(&MockEngine::test_ctx()).unwrap();
        assert!(!lc.is_mounted());
        assert_eq!(lc.mount_count(), 1);

        // The MockEngine holds state; remount on same engine works.
        lc.mount(&MockEngine::test_ctx(), None, None, 7, &[], false)
            .unwrap();
        assert!(lc.is_mounted());
        assert_eq!(lc.mount_count(), 2);
    }

    #[test]
    fn snapshot_when_unmounted_is_zeroed() {
        let lc: MountLifecycle<MockEngine> = MountLifecycle::new(MockEngine::new());
        let snap = lc.snapshot();
        assert_eq!(snap.mounted, 0);
        assert_eq!(snap.root_ino, 0);
        assert_eq!(snap.mount_count, 0);
    }

    #[test]
    fn snapshot_when_mounted_reflects_superblock() {
        let mut lc = MountLifecycle::new(mount_ready_engine());
        lc.mount(&MockEngine::test_ctx(), None, None, 7, &[], false)
            .unwrap();
        let snap = lc.snapshot();
        assert_eq!(snap.mounted, 1);
        assert_eq!(snap.root_ino, 10);
        assert_eq!(snap.committed_txg, 7);
        assert_eq!(snap.block_size, 4096);
        assert_eq!(snap.mount_count, 1);
    }

    #[test]
    fn snapshot_digest_changes_on_transition() {
        let mut lc = MountLifecycle::new(mount_ready_engine());
        let d0 = lc.snapshot().compute();

        lc.mount(&MockEngine::test_ctx(), None, None, 7, &[], false)
            .unwrap();
        let d1 = lc.snapshot().compute();
        assert_ne!(d0, d1, "digest must change after mount");

        lc.unmount(&MockEngine::test_ctx()).unwrap();
        let d2 = lc.snapshot().compute();
        assert_ne!(d1, d2, "digest must change after unmount");
    }

    #[test]
    fn mount_failure_leaves_state_unchanged() {
        let mut engine = MockEngine::new();
        engine.root_ino = InodeId::new(10);
        engine.statfs_fn = Box::new(|_| Err(Errno::EIO));
        let ra = MockEngine::dir_attr(10);
        engine.getattr_fn = Box::new(move |_, _, _| Ok(ra));

        let mut lc = MountLifecycle::new(engine);
        assert!(lc
            .mount(&MockEngine::test_ctx(), None, None, 7, &[], false)
            .is_err());
        assert!(!lc.is_mounted());
        assert_eq!(lc.mount_count(), 0);
        let snap = lc.snapshot();
        assert_eq!(snap.mounted, 0);
    }

    #[test]
    fn unmount_propagates_engine_error() {
        let mut fail_engine = MockEngine::new();
        fail_engine.root_ino = InodeId::new(10);
        fail_engine.statfs_fn = Box::new(|_| {
            Ok(StatFs::new(
                4096, 4096, 1000, 500, 500, 100, 50, 255, 0xDEAD, 0xBEEF,
            ))
        });
        let ra = MockEngine::dir_attr(10);
        fail_engine.getattr_fn = Box::new(move |ino, _, _| {
            if ino == InodeId::new(10) {
                Ok(ra)
            } else {
                Err(Errno::ENOENT)
            }
        });
        fail_engine.syncfs_fn = Box::new(|_| Err(Errno::EIO));

        let mut lc = MountLifecycle::new(fail_engine);
        lc.mount(&MockEngine::test_ctx(), None, None, 7, &[], false)
            .unwrap();
        assert_eq!(lc.unmount(&MockEngine::test_ctx()), Err(Errno::EIO));
    }

    #[test]
    fn digest_deterministic_across_identical_lifecycles() {
        for _ in 0..5 {
            let mut lc = MountLifecycle::new(mount_ready_engine());
            lc.mount(&MockEngine::test_ctx(), None, None, 7, &[], false)
                .unwrap();
            let d1 = lc.snapshot().compute();

            let mut lc2 = MountLifecycle::new(mount_ready_engine());
            lc2.mount(&MockEngine::test_ctx(), None, None, 7, &[], false)
                .unwrap();
            let d2 = lc2.snapshot().compute();

            assert_eq!(d1, d2);
        }
    }
}
