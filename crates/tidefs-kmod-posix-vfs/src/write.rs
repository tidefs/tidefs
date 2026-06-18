// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! File data write mutation for the kernel VFS adapter -- K7-08 mutation seam.
#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

use crate::intent_record::encode_write_intent;
use crate::open_release;
use crate::KmodPosixVfs;
use tidefs_kmod_bridge::kernel_types::VfsEngine;
use tidefs_kmod_bridge::kernel_types::{Errno, RequestCtx};

impl<E: VfsEngine> KmodPosixVfs<E> {
    /// Write data to a file at the given offset.
    ///
    /// Per-write sync semantics: when the file was opened with O_SYNC or
    /// O_DSYNC, this method implicitly performs an fsync (or fdatasync for
    /// O_DSYNC-only) after the write completes, without bypassing object/txg
    /// authority. The sync goes through [`VfsEngine::fsync`] and the
    /// txg commit barrier, ensuring the write is durable before returning.
    pub fn write(
        &mut self,
        fh: &tidefs_kmod_bridge::kernel_types::EngineFileHandle,
        offset: u64,
        data: &[u8],
        ctx: &RequestCtx,
    ) -> Result<u32, Errno> {
        // Record write-intent so crash recovery can observe and replay
        // this mutation after a power loss. Fail the write if the intent
        // log rejects the entry.
        let entry = encode_write_intent(fh.inode_id, offset, data.len() as u32);
        self.record_mutation_intent(&entry)?;
        let written = self.engine.write(fh, offset, data, ctx)?;

        // Per-write sync semantics: O_SYNC -> full fsync, O_DSYNC -> fdatasync.
        // O_SYNC takes precedence over O_DSYNC per POSIX (O_SYNC includes O_DSYNC).
        let flags = fh.open_flags;
        if open_release::has_osync_flag(flags) {
            self.fsync(fh, false, ctx)?;
        } else if open_release::has_odsync_flag(flags) {
            self.fsync(fh, true, ctx)?;
        }

        Ok(written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::MockEngine;
    use crate::TideBox as Box;
    use tidefs_kmod_bridge::kernel_types::{EngineFileHandle, FileHandleId, InodeId};

    fn fh(ino: u64, id: u64) -> EngineFileHandle {
        EngineFileHandle {
            inode_id: InodeId::new(ino),
            open_flags: 0,
            fh_id: FileHandleId::new(id),
            lock_owner: 0,
        }
    }

    #[test]
    fn write_works() {
        let h = fh(20, 1);
        let _h2 = h;
        let mut e = MockEngine::new();
        e.write_fn = Box::new(move |fh, off, data, _| {
            assert_eq!(fh.inode_id, InodeId::new(20));
            assert_eq!(off, 0);
            assert_eq!(data, b"hello");
            Ok(5)
        });
        let written = KmodPosixVfs::new(e)
            .write(&h, 0, b"hello", &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(written, 5);
    }

    #[test]
    fn write_zero_length() {
        let h = fh(20, 1);
        let mut e = MockEngine::new();
        e.write_fn = Box::new(|_, _, data, _| {
            assert!(data.is_empty());
            Ok(0)
        });
        let written = KmodPosixVfs::new(e)
            .write(&h, 0, b"", &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(written, 0);
    }

    #[test]
    fn write_enospc_propagates() {
        let h = fh(20, 1);
        let mut e = MockEngine::new();
        e.write_fn = Box::new(|_, _, _, _| Err(Errno::ENOSPC));
        assert_eq!(
            KmodPosixVfs::new(e)
                .write(&h, 0, b"data", &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::ENOSPC,
        );
    }

    #[test]
    fn write_eio_propagates() {
        let h = fh(20, 1);
        let mut e = MockEngine::new();
        e.write_fn = Box::new(|_, _, _, _| Err(Errno::EIO));
        assert_eq!(
            KmodPosixVfs::new(e)
                .write(&h, 0, b"data", &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EIO,
        );
    }

    #[test]
    fn write_eacces_propagates() {
        let h = fh(20, 1);
        let mut e = MockEngine::new();
        e.write_fn = Box::new(|_, _, _, _| Err(Errno::EACCES));
        assert_eq!(
            KmodPosixVfs::new(e)
                .write(&h, 0, b"data", &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EACCES,
        );
    }

    #[test]
    fn write_preserves_offset() {
        let h = fh(20, 1);
        let offset: u64 = 4096;
        let mut e = MockEngine::new();
        e.write_fn = Box::new(move |_, off, _, _| {
            assert_eq!(off, offset);
            Ok(16)
        });
        KmodPosixVfs::new(e)
            .write(&h, offset, b"data-at-offset-", &MockEngine::test_ctx())
            .unwrap();
    }

    #[test]
    fn write_sequential() {
        let h = fh(30, 2);
        // Write 10 bytes at offset 0
        let mut e1 = MockEngine::new();
        e1.write_fn = Box::new(|_, _, data, _| Ok(data.len() as u32));
        let w1 = KmodPosixVfs::new(e1)
            .write(&h, 0, b"0123456789", &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(w1, 10);

        // Write 5 bytes at offset 10
        let mut e2 = MockEngine::new();
        e2.write_fn = Box::new(|_, _, data, _| Ok(data.len() as u32));
        let w2 = KmodPosixVfs::new(e2)
            .write(&h, 10, b"abcde", &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(w2, 5);
    }

    fn fh_with_flags(ino: u64, id: u64, flags: u32) -> EngineFileHandle {
        EngineFileHandle {
            inode_id: InodeId::new(ino),
            open_flags: flags,
            fh_id: FileHandleId::new(id),
            lock_owner: 0,
        }
    }

    // -- Per-write O_SYNC semantics tests -------------------------------

    #[test]
    fn write_with_osync_calls_fsync() {
        use alloc::sync::Arc;
        use core::sync::atomic::{AtomicBool, Ordering};
        let flags = open_release::O_SYNC;
        let h = fh_with_flags(50, 10, flags);
        let mut e = MockEngine::new();

        let fsync_called = Arc::new(AtomicBool::new(false));
        let fc = Arc::clone(&fsync_called);

        e.write_fn = Box::new(|_, _, _, _| Ok(5));
        e.fsync_fn = Box::new(move |_, datasync, _| {
            fc.store(true, Ordering::SeqCst);
            assert!(!datasync, "O_SYNC should call full fsync (datasync=false)");
            Ok(())
        });

        let written = KmodPosixVfs::new(e)
            .write(&h, 0, b"hello", &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(written, 5);
        assert!(fsync_called.load(Ordering::SeqCst));
    }

    #[test]
    fn write_with_odsync_calls_fdatasync() {
        use alloc::sync::Arc;
        use core::sync::atomic::{AtomicBool, Ordering};
        let flags = open_release::O_DSYNC;
        let h = fh_with_flags(60, 11, flags);
        let mut e = MockEngine::new();

        let fsync_datasync = Arc::new(AtomicBool::new(false));
        let fd = Arc::clone(&fsync_datasync);

        e.write_fn = Box::new(|_, _, _, _| Ok(3));
        e.fsync_fn = Box::new(move |_, datasync, _| {
            fd.store(datasync, Ordering::SeqCst);
            Ok(())
        });

        KmodPosixVfs::new(e)
            .write(&h, 0, b"abc", &MockEngine::test_ctx())
            .unwrap();
        assert!(
            fsync_datasync.load(Ordering::SeqCst),
            "O_DSYNC should call fdatasync (datasync=true)"
        );
    }

    #[test]
    fn write_without_sync_flags_skips_fsync() {
        use alloc::sync::Arc;
        use core::sync::atomic::{AtomicBool, Ordering};
        let h = fh(70, 12);
        let mut e = MockEngine::new();

        let fsync_called = Arc::new(AtomicBool::new(false));
        let fc = Arc::clone(&fsync_called);

        e.write_fn = Box::new(|_, _, _, _| Ok(4));
        e.fsync_fn = Box::new(move |_, _, _| {
            fc.store(true, Ordering::SeqCst);
            Ok(())
        });

        KmodPosixVfs::new(e)
            .write(&h, 0, b"data", &MockEngine::test_ctx())
            .unwrap();
        assert!(
            !fsync_called.load(Ordering::SeqCst),
            "No sync flags should skip fsync"
        );
    }

    #[test]
    fn write_with_osync_fsync_failure_propagates() {
        let flags = open_release::O_SYNC;
        let h = fh_with_flags(80, 13, flags);
        let mut e = MockEngine::new();

        e.write_fn = Box::new(|_, _, _, _| Ok(5));
        e.fsync_fn = Box::new(|_, _, _| Err(Errno::EIO));

        let err = KmodPosixVfs::new(e)
            .write(&h, 0, b"hello", &MockEngine::test_ctx())
            .unwrap_err();
        assert_eq!(err, Errno::EIO);
    }

    #[test]
    fn write_with_odsync_fdatasync_failure_propagates() {
        let flags = open_release::O_DSYNC;
        let h = fh_with_flags(90, 14, flags);
        let mut e = MockEngine::new();

        e.write_fn = Box::new(|_, _, _, _| Ok(3));
        e.fsync_fn = Box::new(|_, _, _| Err(Errno::EROFS));

        let err = KmodPosixVfs::new(e)
            .write(&h, 0, b"abc", &MockEngine::test_ctx())
            .unwrap_err();
        assert_eq!(err, Errno::EROFS);
    }

    #[test]
    fn write_with_osync_preserves_returned_count() {
        let flags = open_release::O_SYNC;
        let h = fh_with_flags(100, 15, flags);
        let mut e = MockEngine::new();

        e.write_fn = Box::new(|_, _, data, _| Ok(data.len() as u32));
        e.fsync_fn = Box::new(|_, _, _| Ok(()));

        let written = KmodPosixVfs::new(e)
            .write(&h, 0, b"sync-write", &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(written, 10);
    }

    #[test]
    fn write_osync_takes_precedence_over_odsync() {
        use alloc::sync::Arc;
        use core::sync::atomic::{AtomicBool, Ordering};
        // O_SYNC | O_DSYNC: O_SYNC semantics (full fsync) should apply
        let flags = open_release::O_SYNC | open_release::O_DSYNC;
        let h = fh_with_flags(110, 16, flags);
        let mut e = MockEngine::new();

        let datasync_value = Arc::new(AtomicBool::new(true)); // default true to detect if never called
        let dv = Arc::clone(&datasync_value);

        e.write_fn = Box::new(|_, _, _, _| Ok(4));
        e.fsync_fn = Box::new(move |_, datasync, _| {
            dv.store(datasync, Ordering::SeqCst);
            Ok(())
        });

        KmodPosixVfs::new(e)
            .write(&h, 0, b"test", &MockEngine::test_ctx())
            .unwrap();
        assert!(
            !datasync_value.load(Ordering::SeqCst),
            "O_SYNC|O_DSYNC should use O_SYNC semantics (datasync=false)"
        );
    }

    #[test]
    fn write_odirect_without_sync_flags_skips_fsync() {
        use alloc::sync::Arc;
        use core::sync::atomic::{AtomicBool, Ordering};
        // O_DIRECT alone does not imply sync semantics
        let h = fh_with_flags(120, 17, open_release::O_DIRECT);
        let mut e = MockEngine::new();

        let fsync_called = Arc::new(AtomicBool::new(false));
        let fc = Arc::clone(&fsync_called);

        e.write_fn = Box::new(|_, _, _, _| Ok(8));
        e.fsync_fn = Box::new(move |_, _, _| {
            fc.store(true, Ordering::SeqCst);
            Ok(())
        });

        KmodPosixVfs::new(e)
            .write(&h, 0, b"directio", &MockEngine::test_ctx())
            .unwrap();
        assert!(
            !fsync_called.load(Ordering::SeqCst),
            "O_DIRECT alone should not trigger implicit fsync"
        );
    }

    #[test]
    fn write_odirect_with_odsync_calls_fdatasync() {
        use alloc::sync::Arc;
        use core::sync::atomic::{AtomicBool, Ordering};
        let flags = open_release::O_DIRECT | open_release::O_DSYNC;
        let h = fh_with_flags(130, 18, flags);
        let mut e = MockEngine::new();

        let datasync_value = Arc::new(AtomicBool::new(false));
        let dv = Arc::clone(&datasync_value);

        e.write_fn = Box::new(|_, _, _, _| Ok(6));
        e.fsync_fn = Box::new(move |_, datasync, _| {
            dv.store(datasync, Ordering::SeqCst);
            Ok(())
        });

        KmodPosixVfs::new(e)
            .write(&h, 0, b"di+dsy", &MockEngine::test_ctx())
            .unwrap();
        assert!(
            datasync_value.load(Ordering::SeqCst),
            "O_DIRECT|O_DSYNC should trigger fdatasync"
        );
    }
}
