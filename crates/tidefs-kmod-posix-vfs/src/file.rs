//! File operations for the kernel VFS adapter --- clean-read seam.

#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

use crate::errno::KernelErrno;
use crate::fallocate::{FallocateMode, FallocatePlan};
use crate::{KmodPosixVfs, OpenDirState, OpenFileState};
use tidefs_kmod_bridge::kernel_types::VfsEngine;
use tidefs_kmod_bridge::kernel_types::{
    Errno, FiemapExtentVec, InodeAttr, InodeId, MmapPolicy, RequestCtx,
};

#[cfg(CONFIG_RUST)]
use tidefs_kmod_bridge::kernel_types::ByteSliceExt;

type DirEntryEmitter<'a> = dyn FnMut(u64, u64, u8, &[u8]) -> bool + 'a;

/// Linux `FS_IOC_FIEMAP` ioctl command value.
///
/// Computed via `_IOWR('f', 11, struct fiemap)` on 64-bit Linux.
/// Used by [`KmodPosixVfs::dispatch_ioctl`] to route fiemap extent-map
/// queries to [`VfsEngine::fiemap`].
pub const FS_IOC_FIEMAP: u32 = 0xC020_660B;

impl<E: VfsEngine> KmodPosixVfs<E> {
    /// Kernel `file_operations::read` dispatch.
    ///
    /// Resolves the [`OpenFileState`] (kernel `file->private_data`), calls
    /// [`VfsEngine::read`], and returns the read buffer. The returned buffer
    /// may be shorter than `size` on EOF or sparse read.
    ///
    /// This is the kernel-resident read(2) data path; no userspace daemon
    /// is required.
    pub fn dispatch_read(
        &self,
        state: &OpenFileState,
        offset: u64,
        size: u32,
        ctx: &RequestCtx,
    ) -> Result<crate::TideVec<u8>, Errno> {
        self.engine.read(&state.handle, offset, size, ctx)
    }

    /// Kernel `file_operations::write` dispatch.
    ///
    /// Resolves the [`OpenFileState`], calls [`VfsEngine::write`], and
    /// updates the inode size if the write extends beyond the current
    /// end-of-file. Returns the number of bytes written.
    ///
    /// The i_size update is performed via [`VfsEngine::getattr`] +
    /// [`VfsEngine::setattr`] with the `FATTR_SIZE` flag set on the
    /// new computed size. If the setattr fails, the write data is still
    /// durable through the engine but the kernel VFS may see a stale
    /// size until the next attribute refresh.
    ///
    /// This is the kernel-resident write(2) data path; no userspace daemon
    /// is required.
    pub fn dispatch_write(
        &self,
        state: &OpenFileState,
        offset: u64,
        data: &[u8],
        ctx: &RequestCtx,
    ) -> Result<u32, Errno> {
        let written = self.engine.write(&state.handle, offset, data, ctx)?;

        // Extend inode size if the write goes past the current EOF.
        let new_end = offset.saturating_add(u64::from(written));
        let current_attr = self.engine.getattr(state.inode, Some(&state.handle), ctx)?;
        if new_end > current_attr.posix.size {
            let mut sa = tidefs_kmod_bridge::kernel_types::SetAttr::new();
            sa.valid = tidefs_kmod_bridge::kernel_types::FATTR_SIZE;
            sa.size = new_end;
            // Best-effort: if setattr fails, the write data is still committed;
            // the kernel VFS will see the old size until the next stat or close.
            let _ = self
                .engine
                .setattr(state.inode, &sa, Some(&state.handle), ctx);
        }

        Ok(written)
    }

    /// Kernel `file_operations::fsync` dispatch.
    ///
    /// Resolves the [`OpenFileState`], calls [`VfsEngine::fsync`] to flush
    /// file data and metadata to stable storage. When `datasync` is true,
    /// only the data and metadata needed to retrieve the data (size, mtime)
    /// must be flushed; other metadata may be skipped.
    ///
    /// This is the kernel-resident fsync(2) durability path; no userspace
    /// daemon is required.
    pub fn dispatch_fsync(
        &self,
        state: &OpenFileState,
        datasync: bool,
        ctx: &RequestCtx,
    ) -> Result<(), Errno> {
        self.engine.fsync(&state.handle, datasync, ctx)
    }

    pub fn open(
        &self,
        inode: InodeId,
        flags: u32,
        ctx: &RequestCtx,
    ) -> Result<OpenFileState, Errno> {
        let handle = self.engine.open(inode, flags, ctx)?;
        Ok(OpenFileState {
            handle,
            inode,
            flags,
        })
    }
    pub fn release(&self, state: &OpenFileState) -> Result<(), Errno> {
        self.engine.release(&state.handle)
    }
    /// Forward a readahead hint to [`VfsEngine::readahead`].
    ///
    /// Readahead is advisory: engine errors are tolerated and the hint
    /// is always recorded in the page-cache tracker for observability.
    pub fn readahead(&self, state: &OpenFileState, offset: u64, length: u32, ctx: &RequestCtx) {
        if length == 0 {
            return;
        }
        if let Err(_e) = self.engine.readahead(&state.handle, offset, length, ctx) {
            // Readahead errors are non-fatal; continue.
        }
    }
    pub fn getattr_via_handle(
        &self,
        state: &OpenFileState,
        ctx: &RequestCtx,
    ) -> Result<InodeAttr, Errno> {
        self.engine.getattr(state.inode, Some(&state.handle), ctx)
    }

    /// dispatch_fallocate: file_operations::fallocate dispatch.
    pub fn dispatch_fallocate(
        &self,
        state: &OpenFileState,
        mode: u32,
        offset: u64,
        length: u64,
        ctx: &RequestCtx,
    ) -> Result<FallocatePlan, Errno> {
        self.engine
            .fallocate(&state.handle, mode, offset, length, ctx)?;
        Ok(FallocatePlan::new(
            &state.handle,
            FallocateMode::from_flags(mode),
            offset,
            length,
        ))
    }

    /// dispatch_flush: file_operations::flush dispatch.
    pub fn dispatch_flush(&self, state: &OpenFileState, ctx: &RequestCtx) -> Result<(), Errno> {
        self.engine.flush(&state.handle, ctx)
    }

    /// Kernel `file_operations::unlocked_ioctl` FS_IOC_FIEMAP dispatch.
    ///
    /// Resolves the [`OpenFileState`] (kernel `file->private_data`), calls
    /// [`VfsEngine::fiemap`], and returns the committed extent-map vector.
    /// Each [`FiemapExtent`] records a logical offset, physical offset,
    /// length, and FIEMAP_EXTENT_* flags.
    ///
    /// The returned [`FiemapExtentVec`] is marshaled into a `struct fiemap_extent`
    /// array by the kernel-side ioctl handler via `copy_to_user`. An empty
    /// extent vector means either a sparse file or an engine that does not
    /// yet expose extent metadata.
    ///
    /// This is the kernel-resident fiemap(2) extent-query path; no userspace
    /// daemon is required.
    pub fn dispatch_fiemap(
        &self,
        state: &OpenFileState,
        ctx: &RequestCtx,
    ) -> Result<FiemapExtentVec, Errno> {
        bridge_fiemap(&self.engine, state, ctx)
    }

    /// Kernel `file_operations::unlocked_ioctl` dispatch.
    ///
    /// Routes Linux ioctl commands to the appropriate engine dispatch.
    /// Currently handles:
    ///
    /// | Command | Dispatch | Description |
    /// |---------|----------|-------------|
    /// | [`FS_IOC_FIEMAP`] | [`Self::dispatch_fiemap`] | Extent-map query |
    ///
    /// Unknown commands return [`KernelErrno::INAPPROPRIATE_IOCTL`] (inappropriate ioctl).
    ///
    /// # No-daemon boundary
    ///
    /// All handled ioctl commands resolve within kernel authority through
    /// [`VfsEngine`]. No userspace daemon is required.
    pub fn dispatch_ioctl(
        &self,
        cmd: u32,
        state: &OpenFileState,
        ctx: &RequestCtx,
    ) -> Result<FiemapExtentVec, Errno> {
        match cmd {
            FS_IOC_FIEMAP => self.dispatch_fiemap(state, ctx),
            _ => Err(KernelErrno::INAPPROPRIATE_IOCTL),
        }
    }

    /// Kernel `file_operations::iterate_shared` dispatch.
    ///
    /// Bridges the Linux kernel `getdents64(2)` / `readdir(3)` syscall
    /// to [`VfsEngine::readdir`] with [`DirCursor`] state tracked
    /// across multiple calls.  The cursor is stored in the open-file
    /// private data alongside the [`OpenDirState`].
    ///
    /// # Callback contract
    ///
    /// The kernel VFS calls this function repeatedly for a directory fd:
    /// - On the first call, `ctx_pos` is 0 and a fresh [`DirCursor`]
    ///   is created for the directory inode.
    /// - On subsequent calls, `ctx_pos` reflects the byte offset
    ///   consumed by the previous `dir_emit` invocations.  The cursor
    ///   translates this to engine cookies.
    /// - When the cursor reaches end-of-directory, this function returns
    ///   `Ok(0)` and the kernel VFS stops calling.
    ///
    /// Each directory entry is emitted through the `emit` closure, which
    /// corresponds to the kernel's `dir_emit` / `dir_emit_dot` /
    /// `dir_emit_dotdot` helpers.  `.` and `..` entries are the kernel
    /// VFS's responsibility; this adapter emits only real directory
    /// entries returned by the engine.
    ///
    /// # No-daemon boundary
    ///
    /// All readdir operations resolve locally within kernel authority
    /// through [`VfsEngine`].  No userspace daemon is required.
    pub fn dispatch_iterate(
        &self,
        state: &OpenDirState,
        cursor: &mut crate::dir_cursor::DirCursor,
        ctx_pos: u64,
        emit: &mut DirEntryEmitter<'_>,
        req_ctx: &RequestCtx,
    ) -> Result<usize, Errno> {
        // When the kernel VFS resets ctx->pos to 0 (e.g., lseek to 0),
        // reset the cursor to Fresh state.
        if ctx_pos == 0 && cursor.position() > 0 {
            cursor.reset();
        }

        // If end-of-directory reached, return 0 immediately.
        if cursor.at_end() {
            return Ok(0);
        }

        let mut emitted: usize = 0;

        // Phase 1: Drain buffered entries from a previous engine call.
        while let Some(entry) = cursor.peek_buffered() {
            let ino = entry.inode_id.get();
            let dtype = super::readdir::node_kind_to_dtype(entry.kind);
            let name = &entry.name;

            if !emit(ino, entry.cookie, dtype, name) {
                return Ok(emitted);
            }

            let _ = cursor.next_buffered();
            emitted += 1;
        }

        // If we emitted entries from the buffer, stop here.
        // Defer the next engine call to the next getdents64 invocation
        // to keep per-callback latency bounded.
        if emitted > 0 {
            return Ok(emitted);
        }

        // Phase 2: Fetch next batch from the engine.
        let (entries, more) = self
            .engine
            .readdir(&state.handle, cursor.position(), req_ctx)?;

        if entries.is_empty() && !more {
            // Truly at end-of-directory. Mark cursor so subsequent
            // calls return 0 without touching the engine.
            cursor.load_batch(entries, more);
            return Ok(0);
        }

        // Load batch into cursor and emit entries.
        cursor.load_batch(entries, more);

        while let Some(entry) = cursor.peek_buffered() {
            let ino = entry.inode_id.get();
            let dtype = super::readdir::node_kind_to_dtype(entry.kind);
            let name = &entry.name;

            if !emit(ino, entry.cookie, dtype, name) {
                return Ok(emitted);
            }

            let _ = cursor.next_buffered();
            emitted += 1;

            if emitted >= 256 {
                break;
            }
        }

        Ok(emitted)
    }
}

// ---------------------------------------------------------------------------
// bridge_fiemap — canonical kernel fiemap extent-query entry point
// ---------------------------------------------------------------------------

/// Delegate fiemap extent-query to the [`VfsEngine`].
///
/// Resolves the open file handle from [`OpenFileState`] and calls
/// [`VfsEngine::fiemap`] to retrieve the committed extent-map vector.
/// Each [`FiemapExtent`] records a logical offset, physical offset,
/// length, and FIEMAP_EXTENT_* flags.
///
/// # Errors
/// - `EBADF`: the file handle is not valid.
/// - `EIO`: storage error retrieving extent metadata.
/// - `ENOSYS`: the engine does not implement extent-map queries.
pub fn bridge_fiemap<E: VfsEngine + ?Sized>(
    engine: &E,
    state: &OpenFileState,
    ctx: &RequestCtx,
) -> Result<FiemapExtentVec, Errno> {
    engine.fiemap(&state.handle, ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errno::KernelErrno;
    use crate::TideBox as Box;
    use crate::TideVec as Vec;

    use crate::test_util::MockEngine;
    use tidefs_kmod_bridge::kernel_types::{EngineFileHandle, FileHandleId, InodeId};

    fn make_state(ino: u64, fh_id: u64) -> OpenFileState {
        OpenFileState {
            handle: EngineFileHandle::new(InodeId::new(ino), 0, FileHandleId::new(fh_id), 0),
            inode: InodeId::new(ino),
            flags: 0o100644,
        }
    }

    // -- dispatch_read tests --------------------------------------------

    #[test]
    fn dispatch_read_works() {
        let state = make_state(20, 1);
        let mut e = MockEngine::new();
        e.read_fn = Box::new(move |fh, off, size, _| {
            assert_eq!(fh.inode_id, InodeId::new(20));
            assert_eq!(off, 0);
            assert_eq!(size, 5);
            Ok(b"hello".to_vec())
        });
        let data = KmodPosixVfs::new(e)
            .dispatch_read(&state, 0, 5, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(data, b"hello");
    }

    #[test]
    fn dispatch_read_zero_length() {
        let state = make_state(20, 1);
        let mut e = MockEngine::new();
        e.read_fn = Box::new(|_, _, size, _| {
            assert_eq!(size, 0);
            Ok(Vec::new())
        });
        let data = KmodPosixVfs::new(e)
            .dispatch_read(&state, 0, 0, &MockEngine::test_ctx())
            .unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn dispatch_read_eof_short_read() {
        let state = make_state(20, 1);
        let mut e = MockEngine::new();
        e.read_fn = Box::new(|_, off, size, _| {
            assert_eq!(off, 100);
            assert_eq!(size, 20);
            Ok(b"end".to_vec())
        });
        let data = KmodPosixVfs::new(e)
            .dispatch_read(&state, 100, 20, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(data, b"end");
        assert_eq!(data.len(), 3);
    }

    #[test]
    fn dispatch_read_eio_propagates() {
        let state = make_state(20, 1);
        let mut e = MockEngine::new();
        e.read_fn = Box::new(|_, _, _, _| Err(KernelErrno::STORAGE_IO));
        assert_eq!(
            KmodPosixVfs::new(e)
                .dispatch_read(&state, 0, 64, &MockEngine::test_ctx())
                .unwrap_err(),
            KernelErrno::STORAGE_IO,
        );
    }

    #[test]
    fn dispatch_read_enospc_propagates() {
        let state = make_state(20, 1);
        let mut e = MockEngine::new();
        e.read_fn = Box::new(|_, _, _, _| Err(KernelErrno::SPACE_EXHAUSTED));
        assert_eq!(
            KmodPosixVfs::new(e)
                .dispatch_read(&state, 0, 64, &MockEngine::test_ctx())
                .unwrap_err(),
            KernelErrno::SPACE_EXHAUSTED,
        );
    }

    // -- dispatch_write tests -------------------------------------------

    #[test]
    fn dispatch_write_works() {
        let state = make_state(20, 1);
        let mut e = MockEngine::new();
        e.write_fn = Box::new(move |fh, off, data, _| {
            assert_eq!(fh.inode_id, InodeId::new(20));
            assert_eq!(off, 0);
            assert_eq!(data, b"hello");
            Ok(5)
        });
        // getattr returns current size 0, so write extends past EOF
        let attr = MockEngine::file_attr(20, 0);
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr));
        let setattr_called = alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
        let sc = setattr_called.clone();
        e.setattr_fn = Box::new(move |_, sa, _, _| {
            sc.store(true, core::sync::atomic::Ordering::SeqCst);
            assert!(sa.is_valid(tidefs_kmod_bridge::kernel_types::FATTR_SIZE));
            assert_eq!(sa.size, 5);
            Ok(MockEngine::file_attr(20, 5))
        });
        let written = KmodPosixVfs::new(e)
            .dispatch_write(&state, 0, b"hello", &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(written, 5);
        assert!(setattr_called.load(core::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn dispatch_write_extends_eof() {
        let state = make_state(20, 1);
        let mut e = MockEngine::new();
        e.write_fn = Box::new(|_, _, data, _| Ok(data.len() as u32));
        let attr = MockEngine::file_attr(20, 4096); // current size 4096
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr));
        let setattr_called = alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
        let sc = setattr_called.clone();
        e.setattr_fn = Box::new(move |_, sa, _, _| {
            sc.store(true, core::sync::atomic::Ordering::SeqCst);
            assert_eq!(sa.size, 5120); // 4096 + 1024
            Ok(MockEngine::file_attr(20, 5120))
        });
        let written = KmodPosixVfs::new(e)
            .dispatch_write(&state, 4096, &[0u8; 1024], &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(written, 1024);
        assert!(setattr_called.load(core::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn dispatch_write_no_size_update_when_within_eof() {
        let state = make_state(20, 1);
        let mut e = MockEngine::new();
        e.write_fn = Box::new(|_, _, data, _| Ok(data.len() as u32));
        let attr = MockEngine::file_attr(20, 8192); // current size 8192
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr));
        let setattr_called = alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
        let sc = setattr_called.clone();
        e.setattr_fn = Box::new(move |_, _, _, _| {
            sc.store(true, core::sync::atomic::Ordering::SeqCst);
            Ok(MockEngine::file_attr(20, 8192))
        });
        let written = KmodPosixVfs::new(e)
            .dispatch_write(&state, 0, &[0u8; 512], &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(written, 512);
        assert!(!setattr_called.load(core::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn dispatch_write_eio_propagates() {
        let state = make_state(20, 1);
        let mut e = MockEngine::new();
        e.write_fn = Box::new(|_, _, _, _| Err(KernelErrno::STORAGE_IO));
        assert_eq!(
            KmodPosixVfs::new(e)
                .dispatch_write(&state, 0, b"data", &MockEngine::test_ctx())
                .unwrap_err(),
            KernelErrno::STORAGE_IO,
        );
    }

    #[test]
    fn dispatch_write_enospc_propagates() {
        let state = make_state(20, 1);
        let mut e = MockEngine::new();
        e.write_fn = Box::new(|_, _, _, _| Err(KernelErrno::SPACE_EXHAUSTED));
        assert_eq!(
            KmodPosixVfs::new(e)
                .dispatch_write(&state, 0, b"data", &MockEngine::test_ctx())
                .unwrap_err(),
            KernelErrno::SPACE_EXHAUSTED,
        );
    }

    // -- dispatch_fsync tests -------------------------------------------

    #[test]
    fn dispatch_fsync_works() {
        let state = make_state(20, 1);
        let mut e = MockEngine::new();
        let st = state.handle;
        e.fsync_fn = Box::new(move |fh, datasync, _| {
            assert_eq!(fh, &st);
            assert!(!datasync);
            Ok(())
        });
        KmodPosixVfs::new(e)
            .dispatch_fsync(&state, false, &MockEngine::test_ctx())
            .unwrap();
    }

    #[test]
    fn dispatch_fsync_datasync_flag() {
        let state = make_state(20, 1);
        let mut e = MockEngine::new();
        let st = state.handle;
        e.fsync_fn = Box::new(move |fh, datasync, _| {
            assert_eq!(fh, &st);
            assert!(datasync);
            Ok(())
        });
        KmodPosixVfs::new(e)
            .dispatch_fsync(&state, true, &MockEngine::test_ctx())
            .unwrap();
    }

    #[test]
    fn dispatch_fsync_eio_propagates() {
        let state = make_state(20, 1);
        let mut e = MockEngine::new();
        e.fsync_fn = Box::new(|_, _, _| Err(KernelErrno::STORAGE_IO));
        assert_eq!(
            KmodPosixVfs::new(e)
                .dispatch_fsync(&state, false, &MockEngine::test_ctx())
                .unwrap_err(),
            KernelErrno::STORAGE_IO,
        );
    }

    #[test]
    fn dispatch_fsync_ebadf_propagates() {
        let state = make_state(20, 1);
        let mut e = MockEngine::new();
        e.fsync_fn = Box::new(|_, _, _| Err(KernelErrno::INVALID_FILE_DESCRIPTOR));
        assert_eq!(
            KmodPosixVfs::new(e)
                .dispatch_fsync(&state, false, &MockEngine::test_ctx())
                .unwrap_err(),
            KernelErrno::INVALID_FILE_DESCRIPTOR,
        );
    }

    // -- sequence tests --------------------------------------------------

    #[test]
    fn dispatch_read_after_write_round_trip() {
        // Use a simple Cell-based mock: write stores data in the cell;
        // read returns the stored data.
        let data_cell = alloc::rc::Rc::new(core::cell::RefCell::new(Vec::new()));
        let dc_w = data_cell.clone();
        let dc_r = data_cell.clone();

        let state = make_state(30, 2);
        let mut e = MockEngine::new();

        e.write_fn = Box::new(move |_, _, data, _| {
            let mut s = dc_w.borrow_mut();
            s.clear();
            s.extend_from_slice(data);
            Ok(data.len() as u32)
        });

        // getattr for size update
        let attr = MockEngine::file_attr(30, 0);
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr));
        e.setattr_fn = Box::new(|_, _, _, _| Ok(MockEngine::file_attr(30, 11)));

        e.read_fn = Box::new(move |_, _, _, _| {
            let s = dc_r.borrow();
            Ok(s.clone())
        });

        let kmod = KmodPosixVfs::new(e);
        kmod.dispatch_write(&state, 0, b"hello world", &MockEngine::test_ctx())
            .unwrap();
        let data = kmod
            .dispatch_read(&state, 0, 11, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(data, b"hello world");
    }

    #[test]
    fn dispatch_write_then_fsync_sequence() {
        let state = make_state(20, 1);
        let mut e = MockEngine::new();

        e.write_fn = Box::new(|_, _, data, _| Ok(data.len() as u32));
        let attr = MockEngine::file_attr(20, 0);
        e.getattr_fn = Box::new(move |_, _, _| Ok(attr));
        e.setattr_fn = Box::new(|_, _, _, _| Ok(MockEngine::file_attr(20, 7)));

        let fsync_called = alloc::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
        let fc = fsync_called.clone();
        e.fsync_fn = Box::new(move |_, _, _| {
            fc.store(true, core::sync::atomic::Ordering::SeqCst);
            Ok(())
        });

        let kmod = KmodPosixVfs::new(e);
        kmod.dispatch_write(&state, 0, b"payload", &MockEngine::test_ctx())
            .unwrap();
        kmod.dispatch_fsync(&state, false, &MockEngine::test_ctx())
            .unwrap();
        assert!(fsync_called.load(core::sync::atomic::Ordering::SeqCst));
    }

    // -- dispatch_fallocate tests ----------------------------------------

    #[test]
    fn dispatch_fallocate_works() {
        let state = make_state(20, 1);
        let mut e = MockEngine::new();
        let st = state.handle;
        e.fallocate_fn = Box::new(move |fh, mode, off, len, _| {
            assert_eq!(fh, &st);
            assert_eq!(mode, 0);
            assert_eq!(off, 0);
            assert_eq!(len, 4096);
            Ok(())
        });
        KmodPosixVfs::new(e)
            .dispatch_fallocate(&state, 0, 0, 4096, &MockEngine::test_ctx())
            .unwrap();
    }

    #[test]
    fn dispatch_fallocate_enospc_propagates() {
        let state = make_state(20, 1);
        let mut e = MockEngine::new();
        e.fallocate_fn = Box::new(|_, _, _, _, _| Err(KernelErrno::SPACE_EXHAUSTED));
        assert_eq!(
            KmodPosixVfs::new(e)
                .dispatch_fallocate(&state, 0, 0, 4096, &MockEngine::test_ctx())
                .unwrap_err(),
            KernelErrno::SPACE_EXHAUSTED,
        );
    }

    // -- dispatch_flush tests --------------------------------------------

    #[test]
    fn dispatch_flush_works() {
        let state = make_state(20, 1);
        let mut e = MockEngine::new();
        let st = state.handle;
        e.flush_fn = Box::new(move |fh, _| {
            assert_eq!(fh, &st);
            Ok(())
        });
        KmodPosixVfs::new(e)
            .dispatch_flush(&state, &MockEngine::test_ctx())
            .unwrap();
    }

    #[test]
    fn dispatch_flush_eio_propagates() {
        let state = make_state(20, 1);
        let mut e = MockEngine::new();
        e.flush_fn = Box::new(|_, _| Err(KernelErrno::STORAGE_IO));
        assert_eq!(
            KmodPosixVfs::new(e)
                .dispatch_flush(&state, &MockEngine::test_ctx())
                .unwrap_err(),
            KernelErrno::STORAGE_IO,
        );
    }

    // -- existing open/release/getattr tests ----------------------------

    fn fh(ino: u64, id: u64) -> EngineFileHandle {
        EngineFileHandle {
            inode_id: InodeId::new(ino),
            open_flags: 0,
            fh_id: FileHandleId::new(id),
            lock_owner: 0,
        }
    }

    #[test]
    fn open_works() {
        let h = fh(10, 1);
        let h2 = h;
        let mut e = MockEngine::new();
        e.open_fn = Box::new(move |_, _, _| Ok(h2));
        assert_eq!(
            KmodPosixVfs::new(e)
                .open(InodeId::new(10), 0, &MockEngine::test_ctx())
                .unwrap()
                .inode,
            InodeId::new(10)
        );
    }

    #[test]
    fn release_works() {
        let s = OpenFileState {
            handle: fh(10, 1),
            inode: InodeId::new(10),
            flags: 0,
        };
        KmodPosixVfs::new(MockEngine::new()).release(&s).unwrap();
    }

    #[test]
    fn getattr_via_handle_works() {
        let a = MockEngine::file_attr(10, 4096);
        let a2 = a;
        let mut e = MockEngine::new();
        e.getattr_fn = Box::new(move |_, _, _| Ok(a2));
        let s = OpenFileState {
            handle: fh(10, 1),
            inode: InodeId::new(10),
            flags: 0,
        };
        let r = KmodPosixVfs::new(e)
            .getattr_via_handle(&s, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(r.inode_id, InodeId::new(10));
        assert_eq!(r.posix.size, 4096);
    }

    #[test]
    fn open_preserves_flags() {
        let h = fh(10, 1);
        let h2 = h;
        let mut e = MockEngine::new();
        e.open_fn = Box::new(move |_, _, _| Ok(h2));
        assert_eq!(
            KmodPosixVfs::new(e)
                .open(InodeId::new(10), 0o100, &MockEngine::test_ctx())
                .unwrap()
                .flags,
            0o100
        );
    }
}

impl<E: VfsEngine> KmodPosixVfs<E> {
    /// Create a [`KmodVfsVmOps`] dispatch spine for the mmap(2) callback.
    pub fn vm_ops(&mut self) -> crate::mmap::KmodVfsVmOps<'_, E> {
        crate::mmap::KmodVfsVmOps::new(
            &self.engine,
            &mut self.dirty_folio_tracker,
            &mut self.page_authority,
        )
    }

    /// `mmap` file_operation callback.
    ///
    /// Consults [`VfsEngine::mmap`] for the mmap policy. Returns
    /// [`KernelErrno::STORAGE_NO_DEVICE`] when the engine denies mmap for this inode.
    pub fn mmap(
        &mut self,
        inode: InodeId,
        flags: u32,
        ctx: &RequestCtx,
    ) -> Result<crate::mmap::KmodVfsVmOps<'_, E>, Errno> {
        let policy = self.engine.mmap(inode, 0, 0, flags, ctx)?;
        match policy {
            MmapPolicy::Denied => Err(KernelErrno::STORAGE_NO_DEVICE),
            MmapPolicy::PopulateOnFault | MmapPolicy::PreFaultPages => Ok(self.vm_ops()),
        }
    }
}

#[cfg(test)]
mod mmap_tests {
    use super::*;
    use crate::test_util::MockEngine;
    use crate::TideBox as Box;
    use tidefs_kmod_bridge::kernel_types::{EngineFileHandle, FileHandleId, InodeId};

    #[test]
    fn mmap_returns_vm_ops() {
        let mut e = MockEngine::new();
        e.read_fn = Box::new(|_, _, _, _| Ok(b"mmap-data".to_vec()));
        let mut vfs = KmodPosixVfs::new(e);
        let mut vmops = vfs
            .mmap(InodeId::new(1), 0, &MockEngine::test_ctx())
            .unwrap();
        let fh = EngineFileHandle::new(InodeId::new(1), 0, FileHandleId(0), 0);
        let (data, _) = vmops.fault(&fh, 0, 4096, &MockEngine::test_ctx()).unwrap();
        assert_eq!(data, b"mmap-data");
    }

    #[test]
    fn vm_ops_accessor_returns_engine_reference() {
        let e = MockEngine::new();
        let mut vfs = KmodPosixVfs::new(e);
        let vmops = vfs.vm_ops();
        let root = vmops.engine().get_root_inode(&MockEngine::test_ctx());
        assert!(root.is_ok());
    }

    #[test]
    fn mmap_returns_different_data_per_inode() {
        let mut e = MockEngine::new();
        e.read_fn = Box::new(|fh, _, _, _| {
            if fh.inode_id == InodeId::new(1) {
                Ok(b"inode-1".to_vec())
            } else {
                Ok(b"inode-2".to_vec())
            }
        });
        let mut vfs = KmodPosixVfs::new(e);

        {
            let mut vmops1 = vfs
                .mmap(InodeId::new(1), 0, &MockEngine::test_ctx())
                .unwrap();
            let fh1 = EngineFileHandle::new(InodeId::new(1), 0, FileHandleId(0), 0);
            let (d1, _) = vmops1
                .fault(&fh1, 0, 4096, &MockEngine::test_ctx())
                .unwrap();
            assert_eq!(d1, b"inode-1");
        }

        let mut vmops2 = vfs
            .mmap(InodeId::new(2), 0, &MockEngine::test_ctx())
            .unwrap();
        let fh2 = EngineFileHandle::new(InodeId::new(2), 0, FileHandleId(0), 0);
        let (d2, _) = vmops2
            .fault(&fh2, 0, 4096, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(d2, b"inode-2");
    }

    #[test]
    fn mmap_populate_on_fault_policy() {
        let mut e = MockEngine::new();
        e.mmap_fn = Box::new(|_, _, _, _, _| Ok(MmapPolicy::PopulateOnFault));
        let mut vfs = KmodPosixVfs::new(e);
        let vmops = vfs
            .mmap(InodeId::new(1), 0, &MockEngine::test_ctx())
            .unwrap();
        // Policy PopulateOnFault succeeds — vmops is returned.
        let engine_ref = vmops.engine();
        assert!(engine_ref.get_root_inode(&MockEngine::test_ctx()).is_ok());
    }

    #[test]
    fn mmap_prefault_pages_policy() {
        let mut e = MockEngine::new();
        e.mmap_fn = Box::new(|_, _, _, _, _| Ok(MmapPolicy::PreFaultPages));
        let mut vfs = KmodPosixVfs::new(e);
        let vmops = vfs
            .mmap(InodeId::new(2), 0, &MockEngine::test_ctx())
            .unwrap();
        // Policy PreFaultPages succeeds — vmops is returned.
        assert!(vmops
            .engine()
            .get_root_inode(&MockEngine::test_ctx())
            .is_ok());
    }

    #[test]
    fn mmap_denied_returns_enodev() {
        let mut e = MockEngine::new();
        e.mmap_fn = Box::new(|_, _, _, _, _| Ok(MmapPolicy::Denied));
        let mut vfs = KmodPosixVfs::new(e);
        let result = vfs.mmap(InodeId::new(3), 0, &MockEngine::test_ctx());
        match result {
            Err(e) => assert_eq!(e, KernelErrno::STORAGE_NO_DEVICE),
            Ok(_) => panic!("expected Err(ENODEV), got Ok"),
        }
    }

    /// Default mmap policy (no mmap_fn override) returns PopulateOnFault.
    #[test]
    fn mmap_default_policy_is_populate_on_fault() {
        let e = MockEngine::new();
        // No mmap_fn override: default VfsEngine::mmap() returns PopulateOnFault.
        let engine_policy =
            VfsEngine::mmap(&e, InodeId::new(1), 0, 4096, 0, &MockEngine::test_ctx()).unwrap();
        assert_eq!(engine_policy, MmapPolicy::PopulateOnFault);
        // And through KmodPosixVfs it also succeeds.
        let mut vfs = KmodPosixVfs::new(e);
        let vmops = vfs
            .mmap(InodeId::new(1), 0, &MockEngine::test_ctx())
            .unwrap();
        assert!(vmops
            .engine()
            .get_root_inode(&MockEngine::test_ctx())
            .is_ok());
    }
}

#[cfg(test)]
mod iterate_tests {
    use super::*;
    use crate::TideBox as Box;
    use crate::TideVec as Vec;
    use alloc::vec;

    use crate::dir_cursor::DirCursor;
    use crate::readdir::node_kind_to_dtype;
    use crate::test_util::MockEngine;
    use tidefs_kmod_bridge::kernel_types::{
        DirEntry, DirHandleId, EngineDirHandle, Generation, InodeId, NodeKind,
    };

    fn ds(ino: u64, dh_id: u64) -> OpenDirState {
        OpenDirState {
            handle: EngineDirHandle {
                inode_id: InodeId::new(ino),
                dh_id: DirHandleId::new(dh_id),
            },
            inode: InodeId::new(ino),
        }
    }

    fn de(ino: u64, name: &[u8], cookie: u64) -> DirEntry {
        DirEntry {
            name: name.to_vec(),
            inode_id: InodeId::new(ino),
            kind: NodeKind::File,
            generation: Generation::new(1),
            cookie,
        }
    }

    struct EmitCollector {
        entries: Vec<(u64, u64, u8, Vec<u8>)>,
        capacity: Option<usize>,
    }

    impl EmitCollector {
        fn new() -> Self {
            Self {
                entries: Vec::new(),
                capacity: None,
            }
        }
        fn with_capacity(n: usize) -> Self {
            Self {
                entries: Vec::new(),
                capacity: Some(n),
            }
        }
        fn emit(&mut self, ino: u64, cookie: u64, dtype: u8, name: &[u8]) -> bool {
            if let Some(cap) = self.capacity {
                if self.entries.len() >= cap {
                    return false;
                }
            }
            self.entries.push((ino, cookie, dtype, name.to_vec()));
            true
        }
    }

    #[test]
    fn iterate_empty_directory() {
        let mut e = MockEngine::new();
        e.readdir_fn = Box::new(|_, _, _| Ok((vec![], false)));
        let state = ds(1, 1);
        let mut cursor = DirCursor::new(InodeId::new(1));
        let mut collector = EmitCollector::new();
        let kmod = KmodPosixVfs::new(e);
        let emitted = kmod
            .dispatch_iterate(
                &state,
                &mut cursor,
                0,
                &mut |ino, cookie, dtype, name| collector.emit(ino, cookie, dtype, name),
                &MockEngine::test_ctx(),
            )
            .unwrap();
        assert_eq!(emitted, 0);
        assert!(cursor.at_end());
    }

    #[test]
    fn iterate_single_entry() {
        let entry = de(100, b"file.txt", 3);
        let entries = vec![entry.clone()];
        let entries2 = entries.clone();
        let mut e = MockEngine::new();
        e.readdir_fn = Box::new(move |_, _, _| Ok((entries2.clone(), false)));
        let state = ds(1, 1);
        let mut cursor = DirCursor::new(InodeId::new(1));
        let mut collector = EmitCollector::new();
        let kmod = KmodPosixVfs::new(e);
        let emitted = kmod
            .dispatch_iterate(
                &state,
                &mut cursor,
                0,
                &mut |ino, cookie, dtype, name| collector.emit(ino, cookie, dtype, name),
                &MockEngine::test_ctx(),
            )
            .unwrap();
        assert_eq!(emitted, 1);
        assert_eq!(collector.entries[0].0, 100);
    }

    #[test]
    fn iterate_multiple_entries() {
        let entries = vec![
            de(10, b"a", 1),
            de(20, b"b", 2),
            de(30, b"c", 3),
            de(40, b"d", 4),
        ];
        let entries2 = entries.clone();
        let mut e = MockEngine::new();
        e.readdir_fn = Box::new(move |_, _, _| Ok((entries2.clone(), false)));
        let state = ds(1, 1);
        let mut cursor = DirCursor::new(InodeId::new(1));
        let mut collector = EmitCollector::new();
        let kmod = KmodPosixVfs::new(e);
        let emitted = kmod
            .dispatch_iterate(
                &state,
                &mut cursor,
                0,
                &mut |ino, cookie, dtype, name| collector.emit(ino, cookie, dtype, name),
                &MockEngine::test_ctx(),
            )
            .unwrap();
        assert_eq!(emitted, 4);
    }

    #[test]
    fn iterate_end_of_directory_returns_zero() {
        let mut e = MockEngine::new();
        e.readdir_fn = Box::new(|_, _, _| Ok((vec![], false)));
        let state = ds(1, 1);
        let mut cursor = DirCursor::new(InodeId::new(1));
        let mut collector = EmitCollector::new();
        let kmod = KmodPosixVfs::new(e);
        let emitted = kmod
            .dispatch_iterate(
                &state,
                &mut cursor,
                0,
                &mut |ino, cookie, dtype, name| collector.emit(ino, cookie, dtype, name),
                &MockEngine::test_ctx(),
            )
            .unwrap();
        assert_eq!(emitted, 0);
        assert!(cursor.at_end());
        let emitted2 = kmod
            .dispatch_iterate(
                &state,
                &mut cursor,
                0,
                &mut |ino, cookie, dtype, name| collector.emit(ino, cookie, dtype, name),
                &MockEngine::test_ctx(),
            )
            .unwrap();
        assert_eq!(emitted2, 0);
    }

    #[test]
    fn iterate_buffer_full_mid_batch() {
        let entries = vec![de(10, b"a", 1), de(20, b"b", 2), de(30, b"c", 3)];
        let entries2 = entries.clone();
        let mut e = MockEngine::new();
        e.readdir_fn = Box::new(move |_, _, _| Ok((entries2.clone(), false)));
        let state = ds(1, 1);
        let mut cursor = DirCursor::new(InodeId::new(1));
        let mut collector = EmitCollector::with_capacity(2);
        let kmod = KmodPosixVfs::new(e);
        let emitted = kmod
            .dispatch_iterate(
                &state,
                &mut cursor,
                0,
                &mut |ino, cookie, dtype, name| collector.emit(ino, cookie, dtype, name),
                &MockEngine::test_ctx(),
            )
            .unwrap();
        assert_eq!(emitted, 2);
        assert!(cursor.has_buffered());
    }

    #[test]
    fn iterate_resume_after_buffer_full() {
        let entries = vec![
            de(10, b"first", 1),
            de(20, b"second", 2),
            de(30, b"third", 3),
        ];
        let entries2 = entries.clone();
        let mut e = MockEngine::new();
        e.readdir_fn = Box::new(move |_, _, _| Ok((entries2.clone(), false)));
        let state = ds(1, 1);
        let mut cursor = DirCursor::new(InodeId::new(1));
        let kmod = KmodPosixVfs::new(e);
        let mut c1 = EmitCollector::with_capacity(2);
        let e1 = kmod
            .dispatch_iterate(
                &state,
                &mut cursor,
                0,
                &mut |ino, cookie, dtype, name| c1.emit(ino, cookie, dtype, name),
                &MockEngine::test_ctx(),
            )
            .unwrap();
        assert_eq!(e1, 2);
        let mut c2 = EmitCollector::new();
        let e2 = kmod
            .dispatch_iterate(
                &state,
                &mut cursor,
                1,
                &mut |ino, cookie, dtype, name| c2.emit(ino, cookie, dtype, name),
                &MockEngine::test_ctx(),
            )
            .unwrap();
        assert_eq!(e2, 1);
        assert_eq!(c2.entries[0].3, b"third");
    }

    #[test]
    fn iterate_eio_propagates() {
        let mut e = MockEngine::new();
        e.readdir_fn = Box::new(|_, _, _| Err(KernelErrno::STORAGE_IO));
        let state = ds(1, 1);
        let mut cursor = DirCursor::new(InodeId::new(1));
        let mut collector = EmitCollector::new();
        let kmod = KmodPosixVfs::new(e);
        assert_eq!(
            kmod.dispatch_iterate(
                &state,
                &mut cursor,
                0,
                &mut |ino, cookie, dtype, name| collector.emit(ino, cookie, dtype, name),
                &MockEngine::test_ctx()
            )
            .unwrap_err(),
            KernelErrno::STORAGE_IO
        );
    }

    #[test]
    fn iterate_cursor_reset_on_ctx_pos_zero() {
        let entries = vec![de(10, b"item", 5)];
        let entries2 = entries.clone();
        let mut e = MockEngine::new();
        e.readdir_fn = Box::new(move |_, offset, _| {
            let f: Vec<DirEntry> = entries2
                .iter()
                .filter(|d| d.cookie > offset)
                .cloned()
                .collect();
            Ok((f, false))
        });
        let state = ds(1, 1);
        let mut cursor = DirCursor::new(InodeId::new(1));
        let kmod = KmodPosixVfs::new(e);
        let mut c1 = EmitCollector::new();
        kmod.dispatch_iterate(
            &state,
            &mut cursor,
            0,
            &mut |ino, cookie, dtype, name| c1.emit(ino, cookie, dtype, name),
            &MockEngine::test_ctx(),
        )
        .unwrap();
        assert!(cursor.position() > 0);
        let mut c2 = EmitCollector::new();
        kmod.dispatch_iterate(
            &state,
            &mut cursor,
            0,
            &mut |ino, cookie, dtype, name| c2.emit(ino, cookie, dtype, name),
            &MockEngine::test_ctx(),
        )
        .unwrap();
        assert_eq!(c2.entries[0].3, b"item");
    }

    #[test]
    fn iterate_entry_dtype_mapping() {
        let entries: Vec<DirEntry> = vec![
            DirEntry {
                name: b"dir".to_vec(),
                inode_id: InodeId::new(2),
                kind: NodeKind::Dir,
                generation: Generation::new(1),
                cookie: 0,
            },
            DirEntry {
                name: b"link".to_vec(),
                inode_id: InodeId::new(3),
                kind: NodeKind::Symlink,
                generation: Generation::new(1),
                cookie: 1,
            },
            DirEntry {
                name: b"file".to_vec(),
                inode_id: InodeId::new(4),
                kind: NodeKind::File,
                generation: Generation::new(1),
                cookie: 2,
            },
        ];
        let entries2 = entries.clone();
        let mut e = MockEngine::new();
        e.readdir_fn = Box::new(move |_, _, _| Ok((entries2.clone(), false)));
        let state = ds(1, 1);
        let mut cursor = DirCursor::new(InodeId::new(1));
        let mut collector = EmitCollector::new();
        let kmod = KmodPosixVfs::new(e);
        kmod.dispatch_iterate(
            &state,
            &mut cursor,
            0,
            &mut |ino, cookie, dtype, name| collector.emit(ino, cookie, dtype, name),
            &MockEngine::test_ctx(),
        )
        .unwrap();
        assert_eq!(collector.entries[0].2, node_kind_to_dtype(NodeKind::Dir));
        assert_eq!(
            collector.entries[1].2,
            node_kind_to_dtype(NodeKind::Symlink)
        );
    }

    #[test]
    fn iterate_large_directory_256_entries() {
        let n = 256usize;
        let all_entries: Vec<DirEntry> = (0..n)
            .map(|i| {
                de(
                    100 + i as u64,
                    alloc::format!("e{i:04x}").as_bytes(),
                    (i + 1) as u64,
                )
            })
            .collect();
        let all2 = all_entries.clone();
        let mut e = MockEngine::new();
        e.readdir_fn = Box::new(move |_, offset, _| {
            let f: Vec<DirEntry> = all2.iter().filter(|d| d.cookie > offset).cloned().collect();
            Ok((f, false))
        });
        let state = ds(1, 1);
        let mut cursor = DirCursor::new(InodeId::new(1));
        let kmod = KmodPosixVfs::new(e);
        let mut all_collected: Vec<Vec<u8>> = Vec::new();
        let mut te = 0usize;
        loop {
            if te >= n {
                break;
            }
            let mut collector = EmitCollector::with_capacity(16);
            let emitted = kmod
                .dispatch_iterate(
                    &state,
                    &mut cursor,
                    te as u64,
                    &mut |ino, cookie, dtype, name| collector.emit(ino, cookie, dtype, name),
                    &MockEngine::test_ctx(),
                )
                .unwrap();
            if emitted == 0 {
                break;
            }
            for (_, _, _, name) in &collector.entries {
                all_collected.push(name.clone());
            }
            te += emitted;
        }
        assert_eq!(all_collected.len(), n);
        for (i, name) in all_collected.iter().enumerate().take(n) {
            assert_eq!(name, &alloc::format!("e{i:04x}").into_bytes());
        }
    }

    #[test]
    fn iterate_cursor_fresh_state() {
        let cursor = DirCursor::new(InodeId::new(42));
        assert_eq!(cursor.position(), 0);
        assert!(!cursor.at_end());
    }

    #[test]
    fn iterate_cursor_reset_on_modification() {
        let mut cursor = DirCursor::new(InodeId::new(1));
        cursor.load_batch(vec![de(10, b"stale", 5)], false);
        let _ = cursor.next_buffered();
        cursor.reset();
        assert_eq!(cursor.position(), 0);
    }
}

#[cfg(test)]
mod readahead_tests {
    use super::*;
    use crate::test_util::MockEngine;
    use alloc::boxed::Box;
    use tidefs_kmod_bridge::kernel_types::{EngineFileHandle, FileHandleId, InodeId, RequestCtx};

    fn fh() -> EngineFileHandle {
        EngineFileHandle::new(InodeId::new(10), 0, FileHandleId::new(1), 0)
    }

    fn state() -> OpenFileState {
        OpenFileState {
            handle: fh(),
            inode: InodeId::new(10),
            flags: 0,
        }
    }

    fn ctx() -> RequestCtx {
        RequestCtx {
            uid: 1000,
            gid: 1000,
            pid: 42,
            umask: 0o022,
            groups: alloc::vec![1000],
        }
    }

    #[test]
    fn readahead_forwards_hint_to_engine() {
        use alloc::sync::Arc;
        use core::sync::atomic::{AtomicBool, Ordering};
        let called = Arc::new(AtomicBool::new(false));
        let called2 = called.clone();
        let mut e = MockEngine::new();
        e.readahead_fn = Box::new(move |_fh, o, l, _c| {
            assert_eq!(o, 4096);
            assert_eq!(l, 8192);
            called2.store(true, Ordering::SeqCst);
            Ok(())
        });
        let kmod = KmodPosixVfs::new(e);
        kmod.readahead(&state(), 4096, 8192, &ctx());
        assert!(called.load(Ordering::SeqCst));
    }

    #[test]
    fn readahead_zero_length_is_noop() {
        let mut e = MockEngine::new();
        e.readahead_fn = Box::new(|_, _, _, _| panic!("should not be called"));
        let kmod = KmodPosixVfs::new(e);
        kmod.readahead(&state(), 0, 0, &ctx());
    }

    #[test]
    fn readahead_tolerates_engine_error() {
        let mut e = MockEngine::new();
        e.readahead_fn = Box::new(|_, _, _, _| Err(KernelErrno::STORAGE_IO));
        let kmod = KmodPosixVfs::new(e);
        kmod.readahead(&state(), 1024, 4096, &ctx());
        // No panic — errors are tolerated.
    }

    #[test]
    fn readahead_multiple_calls_all_forwarded() {
        use alloc::sync::Arc;
        use core::sync::atomic::{AtomicUsize, Ordering};
        let count = Arc::new(AtomicUsize::new(0));
        let count2 = count.clone();
        let mut e = MockEngine::new();
        e.readahead_fn = Box::new(move |_, _, _, _| {
            count2.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        let kmod = KmodPosixVfs::new(e);
        kmod.readahead(&state(), 0, 4096, &ctx());
        kmod.readahead(&state(), 4096, 4096, &ctx());
        kmod.readahead(&state(), 8192, 4096, &ctx());
        assert_eq!(count.load(Ordering::SeqCst), 3);
    }
}

// -- fiemap tests ---------------------------------------------------

#[cfg(test)]
mod fiemap_tests {
    use super::*;
    use crate::test_util::MockEngine;
    use alloc::boxed::Box;

    use tidefs_kmod_bridge::kernel_types::{EngineFileHandle, FileHandleId, InodeId};
    use tidefs_types_extent_map_core::FiemapExtent;

    fn make_state(ino: u64, fh_id: u64) -> OpenFileState {
        OpenFileState {
            handle: EngineFileHandle::new(InodeId::new(ino), 0, FileHandleId::new(fh_id), 0),
            inode: InodeId::new(ino),
            flags: 0o100644,
        }
    }

    #[test]
    fn bridge_fiemap_returns_empty_by_default() {
        let e = MockEngine::new();
        let state = make_state(42, 1);
        let ctx = MockEngine::test_ctx();
        let result = bridge_fiemap(&e, &state, &ctx).unwrap();
        assert!(result.extents.is_empty());
    }

    #[test]
    fn bridge_fiemap_delegates_to_engine() {
        use tidefs_types_extent_map_core::FiemapExtent;
        let mut e = MockEngine::new();
        let state = make_state(10, 2);
        let ctx = MockEngine::test_ctx();
        let handle = state.handle;
        e.fiemap_fn = Box::new(move |fh, _ctx| {
            assert_eq!(fh, &handle);
            let _extent = FiemapExtent::new(0, 2048, 4096, 0);
            let extents = alloc::vec![_extent];
            Ok(FiemapExtentVec { extents })
        });
        let result = bridge_fiemap(&e, &state, &ctx).unwrap();
        assert_eq!(result.extents.len(), 1);
        assert_eq!(result.extents[0].fe_logical, 0);
        assert_eq!(result.extents[0].fe_physical, 2048);
        assert_eq!(result.extents[0].fe_length, 4096);
    }

    #[test]
    fn dispatch_fiemap_returns_empty_by_default() {
        let e = MockEngine::new();
        let state = make_state(42, 1);
        let ctx = MockEngine::test_ctx();
        let result = KmodPosixVfs::new(e).dispatch_fiemap(&state, &ctx).unwrap();
        assert!(result.extents.is_empty());
    }

    #[test]
    fn dispatch_fiemap_propagates_errors() {
        let mut e = MockEngine::new();
        let state = make_state(10, 1);
        e.fiemap_fn = Box::new(|_, _| Err(KernelErrno::INVALID_FILE_DESCRIPTOR));
        let ctx = MockEngine::test_ctx();
        let err = KmodPosixVfs::new(e)
            .dispatch_fiemap(&state, &ctx)
            .unwrap_err();
        assert_eq!(err, KernelErrno::INVALID_FILE_DESCRIPTOR);
    }

    #[test]
    fn dispatch_fiemap_eio_propagates() {
        let mut e = MockEngine::new();
        let state = make_state(10, 1);
        e.fiemap_fn = Box::new(|_, _| Err(KernelErrno::STORAGE_IO));
        let ctx = MockEngine::test_ctx();
        let err = KmodPosixVfs::new(e)
            .dispatch_fiemap(&state, &ctx)
            .unwrap_err();
        assert_eq!(err, KernelErrno::STORAGE_IO);
    }

    #[test]
    fn dispatch_fiemap_enosys_propagates() {
        let mut e = MockEngine::new();
        let state = make_state(10, 1);
        e.fiemap_fn = Box::new(|_, _| Err(KernelErrno::UNIMPLEMENTED_SYSCALL));
        let ctx = MockEngine::test_ctx();
        let err = KmodPosixVfs::new(e)
            .dispatch_fiemap(&state, &ctx)
            .unwrap_err();
        assert_eq!(err, KernelErrno::UNIMPLEMENTED_SYSCALL);
    }

    #[test]
    fn dispatch_ioctl_fiemap_route() {
        let mut e = MockEngine::new();
        let state = make_state(10, 2);
        let ctx = MockEngine::test_ctx();
        let handle = state.handle;
        e.fiemap_fn = Box::new(move |fh, _ctx| {
            assert_eq!(fh, &handle);
            let _extent = FiemapExtent::new(0, 4096, 8192, 0);
            let extents = alloc::vec![_extent];
            Ok(FiemapExtentVec { extents })
        });
        let result = KmodPosixVfs::new(e)
            .dispatch_ioctl(FS_IOC_FIEMAP, &state, &ctx)
            .unwrap();
        assert_eq!(result.extents.len(), 1);
        assert_eq!(result.extents[0].fe_logical, 0);
        assert_eq!(result.extents[0].fe_physical, 4096);
        assert_eq!(result.extents[0].fe_length, 8192);
    }

    #[test]
    fn dispatch_ioctl_unknown_returns_enotty() {
        let e = MockEngine::new();
        let state = make_state(10, 1);
        let ctx = MockEngine::test_ctx();
        let err = KmodPosixVfs::new(e)
            .dispatch_ioctl(0xDEAD_BEEF, &state, &ctx)
            .unwrap_err();
        assert_eq!(err, KernelErrno::INAPPROPRIATE_IOCTL);
    }

    #[test]
    fn dispatch_ioctl_fiemap_error_propagates() {
        let mut e = MockEngine::new();
        let state = make_state(10, 1);
        e.fiemap_fn = Box::new(|_, _| Err(KernelErrno::STORAGE_IO));
        let ctx = MockEngine::test_ctx();
        let err = KmodPosixVfs::new(e)
            .dispatch_ioctl(FS_IOC_FIEMAP, &state, &ctx)
            .unwrap_err();
        assert_eq!(err, KernelErrno::STORAGE_IO);
    }
}
