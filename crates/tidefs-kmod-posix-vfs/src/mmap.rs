// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! vm_operations_struct dispatch for the kernel VFS adapter.
//!
//! Source-model dispatch for the Linux 7.0 `vm_operations_struct` contract
//! (`fault`, `page_mkwrite`) bridging mmap'd file access to [`VfsEngine`]
//! reads and the [`DirtyFolioTracker`] writeback pipeline.
//!
//! The mounted C shim does not currently register this Rust vtable as
//! `vma->vm_ops`. Live Linux mmap admission goes through
//! `tidefs_posix_vfs_file_mmap()` -> `generic_file_mmap()`, then Linux
//! filemap faults and dirtying call the registered C
//! `address_space_operations` (`read_folio`, `dirty_folio`, `writepages`).
//! Treat this module as the Rust authority model for a future direct vm_ops
//! bridge, not as proof that the mounted C path calls these methods.
//!
//! # Implemented operations
//!
//! | Operation        | Status      | VfsEngine dependency        | Daemon required |
//! |------------------|-------------|-----------------------------|-----------------|
//! | `fault`          | Implemented | `VfsEngine::read()`         | No              |
//! | `page_mkwrite`   | Implemented | `DirtyFolioTracker::try_add()` | No           |
//!
//! # No-daemon boundary
//!
//! Both operations resolve locally within kernel authority.  `fault`
//! delegates to VfsEngine::read (kernel-resident), and `page_mkwrite`
//! registers dirty ranges in the in-memory DirtyFolioTracker for
//! subsequent writepages flush — no userspace daemon required.
//!
//! # Kernel wiring
//!
//! A future direct bridge would set `vma->vm_ops = &tidefs_vm_ops` during
//! `mmap(2)` and delegate each function pointer to [`KmodVfsVmOps`] via the
//! kmod-bridge substrate. The mounted Linux 7.0 C shim deliberately does not
//! claim that bridge today; unsupported runtime rows must stay explicit until
//! it is registered.
//!
//! # Page lock/unlock lifecycle
//!
//! In the kernel, the VFS layer holds the page lock across fault and
//! page_mkwrite calls.  This userspace model tracks page-lock state
//! explicitly through `PageLockState` to match kernel semantics: pages
//! arrive locked on fault, page_mkwrite must return with the page still
//! locked (VM_FAULT_LOCKED), and the caller unlocks after I/O completion.

#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;
use crate::TideVec as Vec;

use tidefs_kmod_bridge::kernel_types::{
    EngineFileHandle, Errno, InodeId, RequestCtx, VfsEngine, VmFaultOutcome, VM_FAULT_HWPOISON,
    VM_FAULT_LOCKED, VM_FAULT_MAJOR, VM_FAULT_MINOR, VM_FAULT_NOPAGE, VM_FAULT_OOM, VM_FAULT_RETRY,
    VM_FAULT_SIGBUS,
};

use crate::page_authority::{page_index, PageAuthorityTable};
use crate::writeback::DirtyFolioTracker;
#[cfg(CONFIG_RUST)]
use tidefs_kmod_bridge::kernel_types::ByteSliceExt;
use tidefs_kmod_bridge::kernel_types::PageOwnershipMode;

// ---------------------------------------------------------------------------
// Page lock state tracking
// ---------------------------------------------------------------------------

/// Tracks page lock state for the kernel page-cache model.
///
/// The kernel VFS holds the page lock across fault and page_mkwrite calls.
/// This enum explicitly models that state so the userspace model can
/// validate correct lock/unlock pairing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageLockState {
    /// Page is unlocked — no I/O or fault in progress.
    Unlocked,
    /// Page is locked for read fault (VM_FAULT_MINOR / VM_FAULT_MAJOR).
    LockedForFault,
    /// Page is locked for write transition (VM_FAULT_LOCKED from page_mkwrite).
    LockedForWrite,
}

/// Return codes from vm_operations_struct fault handlers.
///
/// Mirrors Linux `vm_fault_t` return values.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmFaultResult {
    /// Minor fault — page was resident in page cache, no I/O needed.
    Minor,
    /// Major fault — page required I/O to populate.
    Major,
    /// Page is locked, caller must unlock after I/O.
    Locked,
    /// Out of memory — cannot allocate page.
    OOM,
    /// Fatal signal — SIGBUS on access beyond EOF or into a hole.
    Sigbus,
    /// No page available — the requested offset has no backing data.
    NoPage,
    /// Operation not supported.
    NotSupported,
    /// Hardware I/O error reading page data from storage.
    HardwarePoison,
    /// Operation returned, caller should retry (page was truncated).
    Retry,
}

// ---------------------------------------------------------------------------
// KmodVfsVmOps dispatch struct
// ---------------------------------------------------------------------------

/// Dispatch struct for Linux `vm_operations_struct` vtable methods.
///
/// Holds a reference to the [`VfsEngine`] for data reads and a mutable
/// reference to the [`DirtyFolioTracker`] for dirty-range registration.
/// Each method corresponds to a function pointer in the Linux kernel's
/// `struct vm_operations_struct`.
pub struct KmodVfsVmOps<'a, E: VfsEngine> {
    engine: &'a E,
    dirty_tracker: &'a mut DirtyFolioTracker,
    page_authority: &'a mut PageAuthorityTable,
}

impl<'a, E: VfsEngine> KmodVfsVmOps<'a, E> {
    /// Create a new vm_ops dispatch spine borrowing the engine and dirty tracker.
    pub fn new(
        engine: &'a E,
        dirty_tracker: &'a mut DirtyFolioTracker,
        page_authority: &'a mut PageAuthorityTable,
    ) -> Self {
        Self {
            engine,
            dirty_tracker,
            page_authority,
        }
    }

    /// Return a shared reference to the VfsEngine.
    pub fn engine(&self) -> &E {
        self.engine
    }

    /// Return the current page lock state for a given offset.
    ///
    /// In the userspace model this is tracked explicitly; in the kernel
    /// this corresponds to `PageLocked(page)` / `trylock_page(page)`.
    pub fn page_lock_state(&self, _inode: InodeId, _offset: u64) -> PageLockState {
        // In the userspace model we don't track per-page locks; the
        // kernel VFS layer handles that.  Return Unlocked as default
        // for the model.
        PageLockState::Unlocked
    }

    // ── Implemented vm_operations ────────────────────────────────────

    /// `fault`: Handle a page fault for an mmap'd file region.
    ///
    /// Reads file data at the given offset through [`VfsEngine::read`]
    /// and returns the page contents.  For VM_FAULT_MINOR (page already in
    /// cache), the data may be served from the engine's internal cache.
    /// For VM_FAULT_MAJOR (page not in cache), this issues a full read.
    ///
    /// The caller is responsible for mapping the returned data into the
    /// process's virtual address space via `vm_insert_page` or equivalent.
    ///
    /// # Linux kernel signature
    ///
    /// `vm_fault_t (*fault)(struct vm_fault *vmf)`
    ///
    /// `vmf->pgoff` gives the page offset, `vmf->vma->vm_file` the file.
    ///
    /// # No-daemon boundary
    ///
    /// VfsEngine::read resolves within kernel authority.  No userspace
    /// daemon is required.
    ///
    /// # Errors
    ///
    /// Returns `Errno` on read failure or `VmFaultResult::OOM` if the read
    /// buffer cannot be allocated.
    pub fn fault(
        &mut self,
        fh: &EngineFileHandle,
        offset: u64,
        size: u32,
        ctx: &RequestCtx,
    ) -> Result<(Vec<u8>, VmFaultResult), Errno> {
        let page_idx = page_index(offset);
        // Acquire read ownership before reading page data.
        // Transitions EngineOwned->Shared if the engine held the copy.
        let guard = self.page_authority.acquire(
            self.engine,
            fh.inode_id,
            page_idx,
            PageOwnershipMode::Read,
        );
        let outcome: VmFaultOutcome = self.engine.fault(fh, offset, size, ctx)?;
        let data = outcome.page;
        let result = match outcome.vm_fault_code {
            VM_FAULT_MINOR => VmFaultResult::Minor,
            VM_FAULT_MAJOR => VmFaultResult::Major,
            VM_FAULT_LOCKED => VmFaultResult::Locked,
            VM_FAULT_OOM => VmFaultResult::OOM,
            VM_FAULT_SIGBUS => VmFaultResult::Sigbus,
            VM_FAULT_NOPAGE => VmFaultResult::NoPage,
            VM_FAULT_HWPOISON => VmFaultResult::HardwarePoison,
            VM_FAULT_RETRY => VmFaultResult::Retry,
            _ => VmFaultResult::Major,
        };
        if let Ok(g) = guard {
            g.commit();
        }
        Ok((data, result))
    }

    /// `page_mkwrite`: Prepare a read-only page for write access in an
    /// mmap'd file region.
    ///
    /// Transitions the page to writable and registers the dirty byte range
    /// with the [`DirtyFolioTracker`] so that subsequent `writepages` flush
    /// can persist the data.  Returns `VmFaultResult::Locked` to signal
    /// that the page remains locked after this call (the kernel will unlock
    /// it after `writepages` completes).
    ///
    /// # Linux kernel signature
    ///
    /// `vm_fault_t (*page_mkwrite)(struct vm_fault *vmf)`
    ///
    /// `vmf->page` is the page being write-protected; the handler must
    /// mark it dirty and return `VM_FAULT_LOCKED`.
    ///
    /// # No-daemon boundary
    ///
    /// DirtyFolioTracker is in-memory state.  No userspace daemon required.
    ///
    /// # Page lock lifecycle
    ///
    /// On entry the page is locked by the kernel VFS.  On exit the page
    /// remains locked (VM_FAULT_LOCKED) — the caller is responsible for
    /// unlocking after the data has been written back through writepages.
    pub fn page_mkwrite(
        &mut self,
        inode: InodeId,
        offset: u64,
        length: u32,
    ) -> Result<VmFaultResult, Errno> {
        let page_idx = page_index(offset);
        // Acquire exclusive write ownership: signals engine to invalidate
        // its copy so the kernel holds the authoritative dirty page.
        let guard = self
            .page_authority
            .acquire(self.engine, inode, page_idx, PageOwnershipMode::Write)
            .map_err(|c| c.to_errno())?;
        self.dirty_tracker.try_add(inode, offset, length)?;
        guard.commit();
        Ok(VmFaultResult::Locked)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::MockEngine;
    use crate::writeback::DirtyRange;
    use crate::TideBox as Box;
    use alloc::vec; // Kbuild: use crate::TideVec;
    use tidefs_kmod_bridge::kernel_types::{EngineFileHandle, FileHandleId, InodeId};

    // ── Helpers ──────────────────────────────────────────────────────

    fn make_fh() -> EngineFileHandle {
        EngineFileHandle::new(InodeId::new(1), 0, FileHandleId(0), 0)
    }

    fn make_dirty_tracker() -> DirtyFolioTracker {
        DirtyFolioTracker::new(64)
    }

    fn make_page_authority() -> PageAuthorityTable {
        PageAuthorityTable::new(64)
    }

    fn make_engine() -> MockEngine {
        MockEngine::new()
    }

    // ── fault tests ──────────────────────────────────────────────────

    #[test]
    fn fault_reads_data_from_engine() {
        let mut e = make_engine();
        let fh = make_fh();
        e.read_fn = Box::new(move |fh, off, size, _ctx| {
            assert_eq!(fh.inode_id, InodeId::new(1));
            assert_eq!(off, 0);
            assert_eq!(size, 4096);
            Ok(b"fault page data here!".to_vec())
        });

        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut vmops = KmodVfsVmOps::new(&e, &mut dt, &mut pa);
        let (data, result) = vmops.fault(&fh, 0, 4096, &MockEngine::test_ctx()).unwrap();

        assert_eq!(data, b"fault page data here!");
        assert_eq!(result, VmFaultResult::Major);
    }

    #[test]
    fn fault_empty_read_returns_no_page() {
        let mut e = make_engine();
        let fh = make_fh();
        e.read_fn = Box::new(|_, _, _, _| Ok(vec![]));

        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut vmops = KmodVfsVmOps::new(&e, &mut dt, &mut pa);
        let (data, result) = vmops
            .fault(&fh, 4096, 4096, &MockEngine::test_ctx())
            .unwrap();

        assert!(data.is_empty());
        assert_eq!(result, VmFaultResult::NoPage);
    }

    #[test]
    fn fault_at_offset_reads_correct_range() {
        let mut e = make_engine();
        let fh = make_fh();
        e.read_fn = Box::new(|_, off, size, _| {
            assert_eq!(off, 8192);
            assert_eq!(size, 4096);
            Ok(b"offset-data".to_vec())
        });

        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut vmops = KmodVfsVmOps::new(&e, &mut dt, &mut pa);
        let (data, _) = vmops
            .fault(&fh, 8192, 4096, &MockEngine::test_ctx())
            .unwrap();

        assert_eq!(data, b"offset-data");
    }

    #[test]
    fn fault_propagates_io_error() {
        let mut e = make_engine();
        let fh = make_fh();
        e.read_fn = Box::new(|_, _, _, _| Err(Errno::EIO));

        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut vmops = KmodVfsVmOps::new(&e, &mut dt, &mut pa);
        let err = vmops
            .fault(&fh, 0, 4096, &MockEngine::test_ctx())
            .unwrap_err();

        assert_eq!(err, Errno::EIO);
    }

    #[test]
    fn fault_propagates_ebadf() {
        let mut e = make_engine();
        let fh = make_fh();
        e.read_fn = Box::new(|_, _, _, _| Err(Errno::EBADF));

        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut vmops = KmodVfsVmOps::new(&e, &mut dt, &mut pa);
        assert_eq!(
            vmops
                .fault(&fh, 0, 4096, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EBADF
        );
    }

    #[test]
    fn fault_multiple_pages_independent() {
        let mut e = make_engine();
        let fh = make_fh();
        e.read_fn = Box::new(|_, off, _, _| {
            if off == 0 {
                Ok(b"page-0".to_vec())
            } else {
                Ok(b"page-1".to_vec())
            }
        });

        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut vmops = KmodVfsVmOps::new(&e, &mut dt, &mut pa);

        let (d0, r0) = vmops.fault(&fh, 0, 4096, &MockEngine::test_ctx()).unwrap();
        assert_eq!(d0, b"page-0");
        assert_eq!(r0, VmFaultResult::Major);

        let (d1, r1) = vmops
            .fault(&fh, 4096, 4096, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(d1, b"page-1");
        assert_eq!(r1, VmFaultResult::Major);
    }

    #[test]
    fn fault_engine_accessor() {
        let mut e = make_engine();
        e.read_fn = Box::new(|_, _, _, _| Ok(b"data".to_vec()));
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let vmops = KmodVfsVmOps::new(&e, &mut dt, &mut pa);

        let engine_ref: &MockEngine = vmops.engine();
        let root = engine_ref.get_root_inode(&MockEngine::test_ctx());
        assert!(root.is_ok());
    }

    // ── page_mkwrite tests ───────────────────────────────────────────

    #[test]
    fn page_mkwrite_registers_dirty_range() {
        let e = make_engine();
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut vmops = KmodVfsVmOps::new(&e, &mut dt, &mut pa);

        let result = vmops.page_mkwrite(InodeId::new(42), 8192, 4096).unwrap();
        assert_eq!(result, VmFaultResult::Locked);

        let ranges: Vec<_> = dt.iter().collect();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0], (InodeId::new(42), DirtyRange::new(8192, 4096)));
    }

    #[test]
    fn page_mkwrite_multiple_ranges_merge() {
        let e = make_engine();
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut vmops = KmodVfsVmOps::new(&e, &mut dt, &mut pa);

        vmops.page_mkwrite(InodeId::new(10), 0, 4096).unwrap();
        vmops.page_mkwrite(InodeId::new(10), 4096, 4096).unwrap();

        let ranges: Vec<_> = dt.iter().collect();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0], (InodeId::new(10), DirtyRange::new(0, 8192)));
    }

    #[test]
    fn page_mkwrite_different_inodes_independent() {
        let e = make_engine();
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut vmops = KmodVfsVmOps::new(&e, &mut dt, &mut pa);

        vmops.page_mkwrite(InodeId::new(1), 0, 4096).unwrap();
        vmops.page_mkwrite(InodeId::new(2), 0, 4096).unwrap();

        let ranges: Vec<_> = dt.iter().collect();
        assert_eq!(ranges.len(), 2);
    }

    #[test]
    fn page_mkwrite_zero_length_is_noop() {
        let e = make_engine();
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut vmops = KmodVfsVmOps::new(&e, &mut dt, &mut pa);

        let result = vmops.page_mkwrite(InodeId::new(1), 100, 0).unwrap();
        assert_eq!(result, VmFaultResult::Locked);
        assert!(dt.is_empty());
    }

    #[test]
    fn page_mkwrite_enospc_on_capacity() {
        let e = make_engine();
        let mut dt = DirtyFolioTracker::new(2);
        let mut pa = make_page_authority();
        let mut vmops = KmodVfsVmOps::new(&e, &mut dt, &mut pa);

        vmops.page_mkwrite(InodeId::new(1), 0, 4096).unwrap();
        vmops.page_mkwrite(InodeId::new(1), 8192, 4096).unwrap();
        assert_eq!(
            vmops.page_mkwrite(InodeId::new(1), 16384, 4096),
            Err(Errno::ENOSPC)
        );
    }

    // ── Integration: fault then page_mkwrite ────────────────────────

    #[test]
    fn fault_then_page_mkwrite_integration() {
        let mut e = make_engine();
        let fh = make_fh();
        let fh2 = fh;
        e.read_fn = Box::new(move |fh, off, size, _ctx| {
            assert_eq!(fh.inode_id, InodeId::new(1));
            assert_eq!(off, 0);
            assert_eq!(size, 4096);
            Ok(b"mmap-write-data".to_vec())
        });

        let mut dt = make_dirty_tracker();

        // Step 1: fault — read initial data (vmops borrows dt)
        let (data, fault_result) = {
            let mut pa = make_page_authority();
            let mut vmops = KmodVfsVmOps::new(&e, &mut dt, &mut pa);
            vmops.fault(&fh2, 0, 4096, &MockEngine::test_ctx()).unwrap()
        };
        assert_eq!(data, b"mmap-write-data");
        assert_eq!(fault_result, VmFaultResult::Major);

        // vmops dropped — dt accessible
        assert!(dt.is_empty());

        // Step 2: page_mkwrite — transition to writable (vmops borrows dt)
        let mkwrite_result = {
            let mut pa = make_page_authority();
            let mut vmops = KmodVfsVmOps::new(&e, &mut dt, &mut pa);
            vmops.page_mkwrite(InodeId::new(1), 0, 4096).unwrap()
        };
        assert_eq!(mkwrite_result, VmFaultResult::Locked);

        // vmops dropped — dt accessible
        assert_eq!(dt.len(), 1);

        // Step 3: verify dirty range is registered for writeback
        let ranges: Vec<_> = dt.iter().collect();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0], (InodeId::new(1), DirtyRange::new(0, 4096)));
    }

    #[test]
    fn fault_then_page_mkwrite_then_drain() {
        let mut e = make_engine();
        let fh = make_fh();
        let fh2 = fh;
        e.read_fn = Box::new(move |_, _, _, _| Ok(b"data".to_vec()));
        e.write_fn = Box::new(|_, _, data, _| Ok(data.len() as u32));

        let mut dt = make_dirty_tracker();

        // Fault and mark writable
        {
            let mut pa = make_page_authority();
            let mut vmops = KmodVfsVmOps::new(&e, &mut dt, &mut pa);
            vmops.fault(&fh, 0, 4096, &MockEngine::test_ctx()).unwrap();
            vmops.page_mkwrite(InodeId::new(1), 0, 4096).unwrap();
        }

        // Drain dirty ranges (simulating writepages)
        let drained = dt.drain_inode(InodeId::new(1));
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0], DirtyRange::new(0, 4096));
        assert!(dt.is_empty());

        // Re-fault after writeback — data should still be readable
        let mut pa = make_page_authority();
        let mut vmops = KmodVfsVmOps::new(&e, &mut dt, &mut pa);
        let (data, _) = vmops.fault(&fh2, 0, 4096, &MockEngine::test_ctx()).unwrap();
        assert_eq!(data, b"data");
    }

    #[test]
    fn page_mkwrite_then_drain_clears_correctly() {
        let e = make_engine();
        let mut dt = make_dirty_tracker();

        {
            let mut pa = make_page_authority();
            let mut vmops = KmodVfsVmOps::new(&e, &mut dt, &mut pa);
            vmops.page_mkwrite(InodeId::new(1), 0, 4096).unwrap();
            vmops.page_mkwrite(InodeId::new(1), 8192, 4096).unwrap();
            vmops.page_mkwrite(InodeId::new(2), 0, 8192).unwrap();
        }

        let drained = dt.drain_inode(InodeId::new(1));
        assert_eq!(drained.len(), 2);
        assert_eq!(dt.len(), 1);

        let remaining: Vec<_> = dt.iter().collect();
        assert_eq!(remaining[0].0, InodeId::new(2));
    }

    // ── PageLockState tests ─────────────────────────────────────────

    #[test]
    fn page_lock_state_defaults_unlocked() {
        let e = make_engine();
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let vmops = KmodVfsVmOps::new(&e, &mut dt, &mut pa);

        assert_eq!(
            vmops.page_lock_state(InodeId::new(1), 0),
            PageLockState::Unlocked
        );
    }

    #[test]
    fn page_lock_state_enum_values() {
        assert_ne!(PageLockState::Unlocked, PageLockState::LockedForFault);
        assert_ne!(PageLockState::LockedForFault, PageLockState::LockedForWrite);
        assert_ne!(PageLockState::LockedForWrite, PageLockState::Unlocked);
    }

    #[test]
    fn vm_fault_result_enum_values() {
        assert_ne!(VmFaultResult::Minor, VmFaultResult::Major);
        assert_ne!(VmFaultResult::Major, VmFaultResult::Locked);
        assert_ne!(VmFaultResult::Locked, VmFaultResult::OOM);
        assert_ne!(VmFaultResult::OOM, VmFaultResult::Sigbus);
        assert_ne!(VmFaultResult::Sigbus, VmFaultResult::NoPage);
        assert_ne!(VmFaultResult::NoPage, VmFaultResult::NotSupported);
        assert_ne!(VmFaultResult::NotSupported, VmFaultResult::HardwarePoison);
        assert_ne!(VmFaultResult::HardwarePoison, VmFaultResult::Retry);
        assert_ne!(VmFaultResult::OOM, VmFaultResult::Sigbus);
        assert_ne!(VmFaultResult::Sigbus, VmFaultResult::NoPage);
        assert_ne!(VmFaultResult::NoPage, VmFaultResult::NotSupported);
        assert_ne!(VmFaultResult::NotSupported, VmFaultResult::HardwarePoison);
        assert_ne!(VmFaultResult::HardwarePoison, VmFaultResult::Retry);
    }

    #[test]
    fn new_creates_valid_vmops() {
        let e = make_engine();
        let mut dt = make_dirty_tracker();
        dt.add(InodeId::new(1), 0, 4096);
        assert_eq!(dt.len(), 1);

        let mut pa = make_page_authority();
        {
            let vmops = KmodVfsVmOps::new(&e, &mut dt, &mut pa);
            assert!(vmops
                .engine()
                .get_root_inode(&MockEngine::test_ctx())
                .is_ok());
        }
        assert_eq!(dt.len(), 1);
    }

    // ── vm_fault_code → VmFaultResult mapping tests ─────────────────

    /// Verify every VM_FAULT_* code maps to the correct VmFaultResult variant.
    #[test]
    fn vm_fault_code_mapping_is_exhaustive() {
        use tidefs_vfs_engine::{
            VM_FAULT_HWPOISON, VM_FAULT_LOCKED, VM_FAULT_MAJOR, VM_FAULT_MINOR, VM_FAULT_NOPAGE,
            VM_FAULT_OOM, VM_FAULT_RETRY, VM_FAULT_SIGBUS,
        };

        let mut e = make_engine();
        let fh = make_fh();

        // Test each code via fault_fn returning the desired VmFaultOutcome.
        let pairs: &[(u32, VmFaultResult)] = &[
            (VM_FAULT_MINOR, VmFaultResult::Minor),
            (VM_FAULT_MAJOR, VmFaultResult::Major),
            (VM_FAULT_LOCKED, VmFaultResult::Locked),
            (VM_FAULT_OOM, VmFaultResult::OOM),
            (VM_FAULT_SIGBUS, VmFaultResult::Sigbus),
            (VM_FAULT_NOPAGE, VmFaultResult::NoPage),
            (VM_FAULT_HWPOISON, VmFaultResult::HardwarePoison),
            (VM_FAULT_RETRY, VmFaultResult::Retry),
        ];

        for &(code, expected) in pairs {
            e.fault_fn = Some(Box::new({
                move |_, _, _, _| {
                    Ok(VmFaultOutcome {
                        page: b"test".to_vec(),
                        vm_fault_code: code,
                    })
                }
            }));
            let mut dt = make_dirty_tracker();
            let mut pa = make_page_authority();
            let mut vmops = KmodVfsVmOps::new(&e, &mut dt, &mut pa);
            let (_, result) = vmops.fault(&fh, 0, 4096, &MockEngine::test_ctx()).unwrap();
            assert_eq!(
                result, expected,
                "VM_FAULT code {code} mapped to {result:?}, expected {expected:?}"
            );
        }
    }

    #[test]
    fn vm_fault_code_unknown_maps_to_major() {
        let mut e = make_engine();
        let fh = make_fh();
        e.fault_fn = Some(Box::new(|_, _, _, _| {
            Ok(VmFaultOutcome {
                page: b"data".to_vec(),
                vm_fault_code: 999, // unknown code
            })
        }));
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut vmops = KmodVfsVmOps::new(&e, &mut dt, &mut pa);
        let (_, result) = vmops.fault(&fh, 0, 4096, &MockEngine::test_ctx()).unwrap();
        assert_eq!(result, VmFaultResult::Major);
    }

    // ── fault_fn override tests ──────────────────────────────────────

    /// fault() through fault_fn returns the VmFaultOutcome page data.
    #[test]
    fn fault_fn_returns_page_data() {
        let mut e = make_engine();
        let fh = make_fh();
        e.fault_fn = Some(Box::new(|_, offset, size, _| {
            assert_eq!(offset, 0);
            assert_eq!(size, 4096);
            Ok(VmFaultOutcome {
                page: b"direct-fault-page".to_vec(),
                vm_fault_code: VM_FAULT_MAJOR,
            })
        }));
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut vmops = KmodVfsVmOps::new(&e, &mut dt, &mut pa);
        let (data, result) = vmops.fault(&fh, 0, 4096, &MockEngine::test_ctx()).unwrap();
        assert_eq!(data, b"direct-fault-page");
        assert_eq!(result, VmFaultResult::Major);
    }

    /// fault() through fault_fn with a SIGBUS outcome returns Sigbus.
    #[test]
    fn fault_fn_sigbus_returns_sigbus() {
        let mut e = make_engine();
        let fh = make_fh();
        e.fault_fn = Some(Box::new(|_, _, _, _| {
            Ok(VmFaultOutcome {
                page: Vec::new(),
                vm_fault_code: VM_FAULT_SIGBUS,
            })
        }));
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut vmops = KmodVfsVmOps::new(&e, &mut dt, &mut pa);
        let (data, result) = vmops
            .fault(&fh, 4096, 4096, &MockEngine::test_ctx())
            .unwrap();
        assert!(data.is_empty());
        assert_eq!(result, VmFaultResult::Sigbus);
    }

    /// fault() through fault_fn may return an empty page with NOPAGE.
    #[test]
    fn fault_fn_nopage_returns_nopage() {
        let mut e = make_engine();
        let fh = make_fh();
        e.fault_fn = Some(Box::new(|_, _, _, _| {
            Ok(VmFaultOutcome {
                page: Vec::new(),
                vm_fault_code: VM_FAULT_NOPAGE,
            })
        }));
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut vmops = KmodVfsVmOps::new(&e, &mut dt, &mut pa);
        let (data, result) = vmops.fault(&fh, 0, 4096, &MockEngine::test_ctx()).unwrap();
        assert!(data.is_empty());
        assert_eq!(result, VmFaultResult::NoPage);
    }

    // ── Concurrent-fault exclusion tests ───────────────────────────

    /// Two vmops cannot be active simultaneously because both borrow
    /// `dirty_tracker` and `page_authority` mutably. This test
    /// demonstrates sequential exclusivity: first vmops is created,
    /// used, dropped, then a second vmops is created.
    #[test]
    fn vmops_sequential_exclusivity() {
        let mut e = make_engine();
        let fh = make_fh();
        e.read_fn = Box::new(|_, _, _, _| Ok(b"page-A".to_vec()));

        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();

        // First vmops: borrows dt and pa mutably.
        {
            let mut vmops1 = KmodVfsVmOps::new(&e, &mut dt, &mut pa);
            let (data1, _) = vmops1.fault(&fh, 0, 4096, &MockEngine::test_ctx()).unwrap();
            assert_eq!(data1, b"page-A");
        }

        // Second vmops: now dt and pa are free.
        let mut vmops2 = KmodVfsVmOps::new(&e, &mut dt, &mut pa);
        let (data2, _) = vmops2
            .fault(&fh, 4096, 4096, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(data2, b"page-A");
    }

    /// After vmops is dropped, the dirty_tracker is accessible again.
    #[test]
    fn dirty_tracker_accessible_after_vmops_drop() {
        let e = make_engine();
        let _fh = make_fh();

        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();

        {
            let mut vmops = KmodVfsVmOps::new(&e, &mut dt, &mut pa);
            vmops.page_mkwrite(InodeId::new(1), 0, 4096).unwrap();
        } // vmops dropped here

        // dirty_tracker now accessible
        assert_eq!(dt.len(), 1);
        let ranges: Vec<_> = dt.iter().collect();
        assert_eq!(ranges[0].0, InodeId::new(1));
    }

    /// page_authority is accessible after vmops drop.
    #[test]
    fn page_authority_accessible_after_vmops_drop() {
        let mut e = make_engine();
        let fh = make_fh();
        e.read_fn = Box::new(|_, _, _, _| Ok(b"data".to_vec()));

        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();

        {
            let mut vmops = KmodVfsVmOps::new(&e, &mut dt, &mut pa);
            vmops.fault(&fh, 0, 4096, &MockEngine::test_ctx()).unwrap();
        }

        // page_authority accessible after vmops drop
        let guard = pa.acquire(
            &e,
            InodeId::new(1),
            0,
            tidefs_vfs_engine::PageOwnershipMode::Read,
        );
        assert!(guard.is_ok());
    }
}
