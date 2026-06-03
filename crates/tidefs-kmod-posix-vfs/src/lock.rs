//! POSIX advisory lock delegation for the kernel VFS adapter -- K7-19 mutation seam.
//!
//! Provides getlk/setlk byte-range lock delegation and flock whole-file lock
//! dispatch mapping Linux flock(2) operations to the VfsEngine lock interface.

// ── Linux flock(2) operation constants ──────────────────────────────────
#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

pub const LOCK_SH: u32 = 1;
pub const LOCK_EX: u32 = 2;
pub const LOCK_UN: u32 = 8;
pub const LOCK_NB: u32 = 4;

use crate::KmodPosixVfs;
use tidefs_kmod_bridge::kernel_types::VfsEngine;
use tidefs_kmod_bridge::kernel_types::{
    Errno, InodeId, LockSpec, RequestCtx, F_RDLCK, F_UNLCK, F_WRLCK,
};

impl<E: VfsEngine> KmodPosixVfs<E> {
    /// Query whether a conflicting lock exists on the given inode.
    ///
    /// Returns `Ok(None)` when no conflict exists (lock would be granted).
    /// Returns `Ok(Some(conflicting_lock))` when a conflicting lock blocks
    /// the requested lock. Returns `Err(e)` on engine-level failure.
    pub fn getlk(
        &self,
        ino: InodeId,
        lock: &LockSpec,
        ctx: &RequestCtx,
    ) -> Result<Option<LockSpec>, Errno> {
        self.engine.getlk(ino, lock, ctx)
    }

    /// Acquire or release an advisory byte-range lock on the given inode.
    ///
    /// Blocking variant (setlkw) is not separately delegated here; the
    /// VfsEngine trait provides a default setlkw→setlk fallback.
    pub fn setlk(&self, ino: InodeId, lock: &LockSpec, ctx: &RequestCtx) -> Result<(), Errno> {
        self.engine.setlk(ino, lock, ctx)
    }

    /// Apply a flock(2) advisory lock on the given inode.
    ///
    /// `operation` encodes the lock type and flags using Linux flock(2)
    /// constants: `LOCK_SH` (shared), `LOCK_EX` (exclusive), `LOCK_UN`
    /// (unlock), with optional `LOCK_NB` for non-blocking semantics.
    ///
    /// `fd` is the kernel file-descriptor identifier used as the lock
    /// owner. flock locks are fd-associated, not pid-associated; closing
    /// the last fd referencing the open file description releases all
    /// flock locks held through that description.
    ///
    /// # Mapping to VfsEngine
    ///
    /// flock is a whole-file lock: the LockSpec range is `[0, u64::MAX]`.
    /// The lock type maps as LOCK_SH→F_RDLCK, LOCK_EX→F_WRLCK,
    /// LOCK_UN→F_UNLCK. The `fd` value is stored in LockSpec.pid for
    /// per-fd owner tracking.
    ///
    /// # Return values
    ///
    /// - `Ok(())` on success.
    /// - `Err(Errno::EAGAIN)` when `LOCK_NB` is set and the lock cannot be
    ///   immediately acquired (conflict).
    /// - `Err(Errno::EINVAL)` for invalid operation masks.
    /// - Other engine errors propagated as-is.
    pub fn flock(
        &self,
        ino: InodeId,
        operation: u32,
        fd: u64,
        ctx: &RequestCtx,
    ) -> Result<(), Errno> {
        // Extract lock type (low 2 bits) and non-blocking flag.
        let lock_type = operation & 0x3;
        let nonblocking = (operation & LOCK_NB) != 0;

        // Validate lock type: SH(1), EX(2), UN (0=implicit, 8=explicit).
        // LOCK_UN has value 8 (bit 3 set, low bits 0).
        let is_unlock = lock_type == 0
            && (operation & !LOCK_NB) != LOCK_SH
            && (operation & !LOCK_NB) != LOCK_EX;

        let typ = if is_unlock {
            F_UNLCK
        } else if lock_type == LOCK_SH {
            F_RDLCK
        } else if lock_type == LOCK_EX {
            F_WRLCK
        } else {
            return Err(Errno::EINVAL);
        };

        // whole-file range, fd as owner
        let lock_spec = LockSpec::new(typ, 0, 0, u64::MAX, fd as u32);

        if nonblocking {
            self.engine.setlk(ino, &lock_spec, ctx)
        } else if is_unlock {
            // Unlock: always use setlk (non-blocking, release immediately).
            self.engine.setlk(ino, &lock_spec, ctx)
        } else {
            // Blocking shared or exclusive: use setlkw which may block
            // (default delegates to setlk, but engines can override for
            // true blocking behaviour).
            self.engine.setlkw(ino, &lock_spec, ctx)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::MockEngine;
    use crate::TideBox as Box;
    use tidefs_kmod_bridge::kernel_types::{InodeId, LockSpec};

    pub(super) fn test_ctx() -> RequestCtx {
        MockEngine::test_ctx()
    }

    #[test]
    fn getlk_no_conflict() {
        let mut e = MockEngine::new();
        let ino = InodeId::new(42);
        let req = LockSpec::new(0, 0, 0, 4096, 1000);
        e.getlk_fn = Box::new(move |i, l, _| {
            assert_eq!(i, InodeId::new(42));
            assert_eq!(l.start, 0);
            assert_eq!(l.end, 4096);
            Ok(None)
        });
        let result = KmodPosixVfs::new(e).getlk(ino, &req, &test_ctx()).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn getlk_conflict_found() {
        let mut e = MockEngine::new();
        let ino = InodeId::new(7);
        let req = LockSpec::new(1, 0, 2048, 8192, 2000);
        let conflict = LockSpec::new(2, 0, 0, 4096, 1000);
        e.getlk_fn = Box::new(move |_, _, _| Ok(Some(conflict)));
        let result = KmodPosixVfs::new(e).getlk(ino, &req, &test_ctx()).unwrap();
        assert_eq!(result, Some(LockSpec::new(2, 0, 0, 4096, 1000)));
    }

    #[test]
    fn setlk_success() {
        let mut e = MockEngine::new();
        let ino = InodeId::new(99);
        let req = LockSpec::new(1, 0, 0, 65536, 3000);
        e.setlk_fn = Box::new(move |i, l, _| {
            assert_eq!(i, InodeId::new(99));
            assert_eq!(l.typ, 1);
            assert_eq!(l.pid, 3000);
            Ok(())
        });
        KmodPosixVfs::new(e).setlk(ino, &req, &test_ctx()).unwrap();
    }

    #[test]
    fn setlk_eacces_propagates() {
        let mut e = MockEngine::new();
        let ino = InodeId::new(1);
        let req = LockSpec::new(0, 0, 0, 4096, 1000);
        e.setlk_fn = Box::new(|_, _, _| Err(Errno::EACCES));
        let result = KmodPosixVfs::new(e).setlk(ino, &req, &test_ctx());
        assert_eq!(result, Err(Errno::EACCES));
    }

    // ── flock dispatch tests ─────────────────────────────────────────────

    fn flock_ctx() -> RequestCtx {
        test_ctx()
    }

    #[test]
    fn flock_shared_success() {
        let mut e = MockEngine::new();
        let ino = InodeId::new(10);
        let fd = 3u64;
        e.setlk_fn = Box::new(move |i, l, _| {
            assert_eq!(i, InodeId::new(10));
            assert_eq!(l.typ, F_RDLCK);
            assert_eq!(l.start, 0);
            assert_eq!(l.end, u64::MAX);
            assert_eq!(l.pid, fd as u32);
            Ok(())
        });
        KmodPosixVfs::new(e)
            .flock(ino, LOCK_SH, fd, &flock_ctx())
            .expect("flock shared");
    }

    #[test]
    fn flock_exclusive_success() {
        let mut e = MockEngine::new();
        let ino = InodeId::new(20);
        let fd = 5u64;
        e.setlk_fn = Box::new(move |_, l, _| {
            assert_eq!(l.typ, F_WRLCK);
            Ok(())
        });
        KmodPosixVfs::new(e)
            .flock(ino, LOCK_EX, fd, &flock_ctx())
            .expect("flock exclusive");
    }

    #[test]
    fn flock_unlock_success() {
        let mut e = MockEngine::new();
        let ino = InodeId::new(30);
        let fd = 7u64;
        e.setlk_fn = Box::new(move |_, l, _| {
            assert_eq!(l.typ, F_UNLCK);
            Ok(())
        });
        KmodPosixVfs::new(e)
            .flock(ino, LOCK_UN, fd, &flock_ctx())
            .expect("flock unlock");
    }

    #[test]
    fn flock_shared_nonblocking_success() {
        let mut e = MockEngine::new();
        let ino = InodeId::new(40);
        let fd = 9u64;
        e.setlk_fn = Box::new(move |_, l, _| {
            assert_eq!(l.typ, F_RDLCK);
            Ok(())
        });
        KmodPosixVfs::new(e)
            .flock(ino, LOCK_SH | LOCK_NB, fd, &flock_ctx())
            .expect("flock shared nb");
    }

    #[test]
    fn flock_exclusive_nonblocking_eagain() {
        let mut e = MockEngine::new();
        let ino = InodeId::new(50);
        let fd = 11u64;
        e.setlk_fn = Box::new(|_, _, _| Err(Errno::EAGAIN));
        let err = KmodPosixVfs::new(e)
            .flock(ino, LOCK_EX | LOCK_NB, fd, &flock_ctx())
            .unwrap_err();
        assert_eq!(err, Errno::EAGAIN);
    }

    #[test]
    fn flock_blocking_calls_setlkw() {
        let mut e = MockEngine::new();
        let ino = InodeId::new(60);
        let fd = 13u64;
        // Blocking flock without LOCK_NB calls setlkw (which by default
        // delegates to setlk). Verify the lock spec is correct.
        e.setlk_fn = Box::new(move |_, l, _| {
            assert_eq!(l.typ, F_WRLCK);
            assert_eq!(l.pid, fd as u32);
            Ok(())
        });
        KmodPosixVfs::new(e)
            .flock(ino, LOCK_EX, fd, &flock_ctx())
            .expect("flock blocking via setlkw→setlk");
    }

    #[test]
    fn flock_blocking_propagates_error() {
        let mut e = MockEngine::new();
        // Blocking flock without LOCK_NB: the default setlkw→setlk path
        // should propagate the error.
        e.setlk_fn = Box::new(|_, _, _| Err(Errno::EDEADLK));
        let err = KmodPosixVfs::new(e)
            .flock(InodeId::new(61), LOCK_EX, 14, &flock_ctx())
            .unwrap_err();
        assert_eq!(err, Errno::EDEADLK);
    }

    #[test]
    fn flock_invalid_operation_returns_einval() {
        let e = MockEngine::new();
        // Invalid lock type (3 = 0b11, neither SH nor EX nor valid UN).
        let err = KmodPosixVfs::new(e)
            .flock(InodeId::new(70), 3, 15, &flock_ctx())
            .unwrap_err();
        assert_eq!(err, Errno::EINVAL);
    }

    #[test]
    fn flock_invalid_op_7_returns_einval() {
        let e = MockEngine::new();
        // 7 = LOCK_NB (4) | 3 (invalid type bits).
        let err = KmodPosixVfs::new(e)
            .flock(InodeId::new(71), 7, 16, &flock_ctx())
            .unwrap_err();
        assert_eq!(err, Errno::EINVAL);
    }

    #[test]
    fn flock_unlock_with_nb_flag() {
        let mut e = MockEngine::new();
        let ino = InodeId::new(80);
        let fd = 17u64;
        e.setlk_fn = Box::new(move |_, l, _| {
            assert_eq!(l.typ, F_UNLCK);
            Ok(())
        });
        // LOCK_UN | LOCK_NB = 12. Should treat as unlock.
        KmodPosixVfs::new(e)
            .flock(ino, LOCK_UN | LOCK_NB, fd, &flock_ctx())
            .expect("flock unlock with NB");
    }

    #[test]
    fn flock_zero_operation_is_unlock() {
        let mut e = MockEngine::new();
        let ino = InodeId::new(90);
        let fd = 19u64;
        e.setlk_fn = Box::new(move |_, l, _| {
            assert_eq!(l.typ, F_UNLCK);
            Ok(())
        });
        // operation=0: low bits are 0, treated as unlock.
        KmodPosixVfs::new(e)
            .flock(ino, 0, fd, &flock_ctx())
            .expect("flock zero-op as unlock");
    }

    #[test]
    fn flock_unlock_uses_setlk() {
        let mut e = MockEngine::new();
        let ino = InodeId::new(100);
        let fd = 21u64;
        // Unlock without LOCK_NB should dispatch through setlk (never blocks).
        // The closure verifies the lock-spec type is F_UNLCK and then
        // succeeds—if setlkw had incorrectly been called instead, the default
        // delegation would still route through setlk, so we verify the correct
        // LockSpec shape arrives.
        e.setlk_fn = Box::new(move |_, l, _| {
            assert_eq!(l.typ, F_UNLCK);
            assert_eq!(l.pid, fd as u32);
            Ok(())
        });
        KmodPosixVfs::new(e)
            .flock(ino, LOCK_UN, fd, &flock_ctx())
            .expect("flock unlock via setlk");
    }
}
